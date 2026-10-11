"""Capture real FastAPI TestClient responses for a safe static showcase replay."""
import json,sys,time,tempfile,xml.etree.ElementTree as ET
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from sentinel.app import create_app,Settings
from sentinel.posture import evaluate,attack_paths
root=Path(__file__).resolve().parents[1]
k=rsa.generate_private_key(public_exponent=65537,key_size=2048)
pub=k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
def h(actor='alice',tenant='tenant-a',roles=None):
 now=int(time.time());return {'Authorization':'Bearer '+jwt.encode({'sub':actor,'tenant':tenant,'roles':roles or ['viewer'],'iss':'sentinel-local','aud':'sentinel-api','iat':now,'exp':now+900},k,algorithm='RS256')}
scenarios=[]
with tempfile.TemporaryDirectory() as tmp:
 s=Settings(public_key=pub,database_url='sqlite:///'+tmp+'/replay.db',rate_limit=100)
 app=create_app(s)
 with TestClient(app) as client:
  for key,title,requests,auth in [
   ('benign','Authorized payment read',1,h()),
   ('access','Cross-tenant access',3,h()),
   ('auth','Invalid authentication',5,{'Authorization':'Bearer synthetic-invalid'}),
   ('export','Repeated data retrieval',4,h()),
  ]:
   path='/payments' if key=='export' else '/payments/pay-b-001' if key=='access' else '/payments/pay-a-001'
   start=time.perf_counter(); responses=[]
   for _ in range(requests):
    r=client.get(path,headers=auth);responses.append({'status':r.status_code,'body':r.json(),'correlation':r.headers['X-Correlation-ID']})
   scenarios.append({'id':key,'title':title,'method':'GET','path':path,'requests':requests,'responses':responses,'duration_ms':round((time.perf_counter()-start)*1000,2)})
  analyst=h('analyst',roles=['analyst'])
  i=client.get('/incidents',headers=analyst).json()[0]['id']
  start=time.perf_counter();r=client.patch('/incidents/'+i,json={'status':'investigating','assignee':'analyst','notes':'Synthetic evidence review'},headers=analyst)
  scenarios.append({'id':'admin','title':'Audited analyst action','method':'PATCH','path':'/incidents/{incident_id}','requests':1,'responses':[{'status':r.status_code,'body':r.json(),'correlation':r.headers['X-Correlation-ID']}],'duration_ms':round((time.perf_counter()-start)*1000,2)})
  s.rate_limit=2;responses=[];start=time.perf_counter()
  for _ in range(3):
   r=client.get('/payments/pay-a-001',headers=h('noisy-client'));responses.append({'status':r.status_code,'body':r.json(),'correlation':r.headers['X-Correlation-ID']})
  scenarios.append({'id':'rate','title':'Request allowance exceeded','method':'GET','path':'/payments/pay-a-001','requests':3,'responses':responses,'duration_ms':round((time.perf_counter()-start)*1000,2)})
  s.rate_limit=100
  for _ in range(10):client.get('/payments/pay-a-001',headers=h('benign-cohort'))
  admin=h('admin',roles=['admin'])
  incidents=client.get('/incidents',headers=admin).json();events=client.get('/events',headers=admin).json()
  metrics={'seeded_rules_detected':len({i['rule'] for i in incidents}),'seeded_rules_expected':5,'benign_requests':10,'benign_alerts':len([i for i in incidents if i['actor']=='benign-cohort']),'scope':'Single-process TestClient run using SQLite; not a production benchmark or general false-positive estimate.'}
  app.state.engine.dispose()
assets=json.loads((root/'fixtures/cloud-assets.json').read_text())
report={'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'mode':'recorded-local-lab','scenarios':scenarios,'incidents':incidents,'events':events,'metrics':metrics,'assets':assets,'findings':evaluate(assets),'attack_paths':attack_paths(assets)}
report['tests']={'passed':0,'failed':0,'seconds':0}
f=root/'docs/test-results.xml'
if f.exists():
 suite=ET.parse(f).getroot().find('testsuite');report['tests']={'passed':int(suite.attrib['tests'])-int(suite.attrib['failures'])-int(suite.attrib['errors']),'failed':int(suite.attrib['failures'])+int(suite.attrib['errors']),'seconds':float(suite.attrib['time'])}
(root/'dist/assets/replay.json').write_text(json.dumps(report,indent=2));(root/'docs/replay-report.json').write_text(json.dumps(report,indent=2))
print(json.dumps({'tests':report['tests'],'metrics':metrics,'scenarios':len(scenarios)}))
