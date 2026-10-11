import json
import time
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from sentinel.app import Settings, create_app
from sentinel.posture import evaluate, attack_paths

@pytest.fixture(scope='session')
def keys():
    k=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    return k,k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()

@pytest.fixture
def lab(tmp_path,keys):
    settings=Settings(database_url='sqlite:///'+str(tmp_path/'test.db'),public_key=keys[1],rate_limit=100)
    app=create_app(settings)
    with TestClient(app) as client:
        yield client,settings,keys[0]
    app.state.engine.dispose()

def headers(lab,actor='alice',tenant='tenant-a',roles=None,changes=None,key=None,algorithm='RS256'):
    now=int(time.time())
    c={'sub':actor,'tenant':tenant,'roles':roles or ['viewer'],'iss':'sentinel-local','aud':'sentinel-api','iat':now,'exp':now+900}
    c.update(changes or {})
    token=jwt.encode(c,key or lab[2],algorithm=algorithm)
    return {'Authorization':'Bearer '+token}

def test_same_tenant_read(lab):
    r=lab[0].get('/payments/pay-a-001',headers=headers(lab)); assert r.status_code==200;assert r.json()['tenant']=='tenant-a'

def test_cross_tenant_read(lab):
    assert lab[0].get('/payments/pay-b-001',headers=headers(lab)).status_code==404

def test_cross_tenant_update(lab):
    assert lab[0].patch('/payments/pay-b-001',json={'status':'cancelled'},headers=headers(lab)).status_code==404
    assert lab[0].get('/payments/pay-b-001',headers=headers(lab,'bob','tenant-b')).json()['status']=='settled'

def test_same_tenant_update(lab):
    r=lab[0].patch('/payments/pay-a-001',json={'status':'settled'},headers=headers(lab));assert r.status_code==200
    assert lab[0].get('/payments/pay-a-001',headers=headers(lab)).json()['status']=='settled'

def test_listing_tenant_isolation(lab):
    assert [x['id'] for x in lab[0].get('/payments',headers=headers(lab)).json()]==['pay-a-001']

@pytest.mark.parametrize('changes',[{'exp':1},{'iss':'wrong'},{'aud':'wrong'},{'iat':int(time.time())+3600},{'tenant':'tenant-c'},{'sub':''}])
def test_invalid_claims(lab,changes):
    assert lab[0].get('/payments/pay-a-001',headers=headers(lab,changes=changes)).status_code==401

def test_missing_token(lab):
    assert lab[0].get('/payments/pay-a-001').status_code==401

def test_forged_signature(lab):
    bad=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    assert lab[0].get('/payments/pay-a-001',headers=headers(lab,key=bad)).status_code==401

def test_algorithm_confusion(lab):
    assert lab[0].get('/payments/pay-a-001',headers=headers(lab,key=bytes(range(32)),algorithm='HS256')).status_code==401

def test_required_expiry(lab):
    c={'sub':'alice','tenant':'tenant-a','roles':['viewer'],'iss':'sentinel-local','aud':'sentinel-api','iat':int(time.time())}
    token=jwt.encode(c,lab[2],algorithm='RS256')
    assert lab[0].get('/payments/pay-a-001',headers={'Authorization':'Bearer '+token}).status_code==401

def test_viewer_cannot_read_incidents(lab):
    assert lab[0].get('/incidents',headers=headers(lab)).status_code==403

def test_detection_evidence_and_tenant_scope(lab):
    for _ in range(3): lab[0].get('/payments/pay-b-001',headers=headers(lab))
    own=lab[0].get('/incidents',headers=headers(lab,'analyst','tenant-a',['analyst'])).json()
    other=lab[0].get('/incidents',headers=headers(lab,'other','tenant-b',['analyst'])).json()
    assert len(own)==1;assert own[0]['rule']=='ACCESS-001';assert len(own[0]['evidence_ids'])==3;assert other==[]

def test_no_alert_for_benign_single_read(lab):
    lab[0].get('/payments/pay-a-001',headers=headers(lab))
    assert lab[0].get('/incidents',headers=headers(lab,'analyst',roles=['analyst'])).json()==[]

def test_repeated_auth_failure(lab):
    for _ in range(5): lab[0].get('/payments/pay-a-001')
    own=lab[0].get('/incidents',headers=headers(lab,'analyst',roles=['analyst'])).json()
    admin=lab[0].get('/incidents',headers=headers(lab,'admin',roles=['admin'])).json()
    assert own==[];assert admin[0]['rule']=='AUTH-001';assert admin[0]['tenant']=='unverified'

def test_rate_limit(lab):
    lab[1].rate_limit=2
    for _ in range(2): assert lab[0].get('/payments/pay-a-001',headers=headers(lab)).status_code==200
    r=lab[0].get('/payments/pay-a-001',headers=headers(lab));assert r.status_code==429;assert r.headers['Retry-After']=='60'

def test_rate_window_recovery(lab):
    lab[1].rate_limit=1;tick=[time.time()];lab[1].clock=lambda:tick[0]
    assert lab[0].get('/payments/pay-a-001',headers=headers(lab)).status_code==200
    assert lab[0].get('/payments/pay-a-001',headers=headers(lab)).status_code==429
    tick[0]+=61
    assert lab[0].get('/payments/pay-a-001',headers=headers(lab)).status_code==200

def test_payload_limit(lab):
    assert lab[0].patch('/payments/pay-a-001',content=b'x'*17000,headers=headers(lab)).status_code==413

def test_input_validation(lab):
    assert lab[0].patch('/payments/pay-a-001',json={'status':'hacked'},headers=headers(lab)).status_code==422

def test_correlation_id_generated_by_server(lab):
    h=headers(lab);h['X-Correlation-ID']='attacker-input'
    r=lab[0].get('/payments/pay-a-001',headers=h)
    assert r.headers['X-Correlation-ID']!='attacker-input';assert len(r.headers['X-Correlation-ID'])==36

def test_no_credentials_in_evidence(lab):
    h=headers(lab);lab[0].get('/payments/pay-a-001',headers=h)
    events=lab[0].get('/events',headers=headers(lab,'analyst',roles=['analyst'])).json()
    serialized=json.dumps(events);assert h['Authorization'].split()[1] not in serialized;assert 'password' not in serialized

def test_incident_update_and_audit(lab):
    for _ in range(3):lab[0].get('/payments/pay-b-001',headers=headers(lab))
    h=headers(lab,'analyst',roles=['analyst']);i=lab[0].get('/incidents',headers=h).json()[0]['id']
    assert lab[0].patch('/incidents/'+i,json={'status':'investigating','notes':'Review session','assignee':'analyst'},headers=h).status_code==200
    assert any(e['kind']=='admin_action' for e in lab[0].get('/events',headers=h).json())

def test_incident_update_tenant_isolation(lab):
    for _ in range(3):lab[0].get('/payments/pay-b-001',headers=headers(lab))
    i=lab[0].get('/incidents',headers=headers(lab,'analyst',roles=['analyst'])).json()[0]['id']
    h=headers(lab,'other','tenant-b',['analyst'])
    assert lab[0].patch('/incidents/'+i,json={'status':'resolved'},headers=h).status_code==404

def test_bulk_read_detection(lab):
    for _ in range(4):lab[0].get('/payments',headers=headers(lab))
    assert any(i['rule']=='EXPORT-001' for i in lab[0].get('/incidents',headers=headers(lab,'analyst',roles=['analyst'])).json())

def test_detection_window(lab):
    tick=[time.time()];lab[1].clock=lambda:tick[0]
    for _ in range(2):lab[0].get('/payments/pay-b-001',headers=headers(lab))
    tick[0]+=61;lab[0].get('/payments/pay-b-001',headers=headers(lab))
    assert lab[0].get('/incidents',headers=headers(lab,'analyst',roles=['analyst'])).json()==[]

def test_posture_and_graph():
    assets=[{'id':'api','public':True,'can_access':['iam']},{'id':'iam','permissions':['*'],'can_access':['db']},{'id':'db','sensitive':True,'encrypted':False}]
    assert len(evaluate(assets))==3;assert attack_paths(assets)[0]['nodes']==['internet','api','iam','db']

def test_graph_cycle_terminates():
    assert attack_paths([{'id':'a','public':True,'can_access':['b']},{'id':'b','can_access':['a']}])==[]

def test_incident_persists_across_app_restart(lab):
    for _ in range(3):lab[0].get('/payments/pay-b-001',headers=headers(lab))
    second=create_app(lab[1])
    with TestClient(second) as client:
        assert client.get('/incidents',headers=headers(lab,'analyst',roles=['analyst'])).json()[0]['rule']=='ACCESS-001'
    second.state.engine.dispose()

def test_redis_failure_fails_closed():
    from sentinel.app import RateLimiter
    from fastapi import HTTPException
    class Offline:
        def eval(self,*args):raise ConnectionError('unavailable')
    limiter=RateLimiter(Settings());limiter.redis=Offline()
    with pytest.raises(HTTPException) as exc:limiter.allowed('tenant-a:alice')
    assert exc.value.status_code==503

def test_unapproved_cors_origin(lab):
    response=lab[0].get('/health',headers={'Origin':'https://untrusted.example'})
    assert 'access-control-allow-origin' not in response.headers

def test_streamed_payload_limit(lab):
    def chunks():
        for _ in range(20):yield b'x'*1000
    response=lab[0].patch('/payments/pay-a-001',content=chunks(),headers=headers(lab))
    assert response.status_code==413
