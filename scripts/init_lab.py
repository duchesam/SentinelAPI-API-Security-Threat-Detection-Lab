from pathlib import Path
import sys,time,json
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"backend"))
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
p=Path('.state');p.mkdir(exist_ok=True)
private=p/'private.pem';public=p/'public.pem'
if not private.exists():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));private.chmod(0o600)
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
if '--tokens' in sys.argv:
    now=int(time.time())
    for actor,tenant,roles in [('alice','tenant-a',['viewer']),('bob','tenant-b',['viewer']),('analyst','tenant-a',['analyst']),('admin','tenant-a',['admin'])]:
        token=jwt.encode({'sub':actor,'tenant':tenant,'roles':roles,'iss':'sentinel-local','aud':'sentinel-api','iat':now,'exp':now+900},private.read_bytes(),algorithm='RS256')
        print(json.dumps({'identity':actor,'expires_in_seconds':900,'access_token':token}))
else: print('Local keys initialized. Use --tokens for short-lived synthetic credentials.')
