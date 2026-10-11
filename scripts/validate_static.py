from html.parser import HTMLParser
from pathlib import Path
import json,zipfile
root=Path(__file__).resolve().parents[1]
class Check(HTMLParser):
 def handle_starttag(self,tag,attrs):
  for key,value in attrs:
   if key in {'href','src'} and value and not value.startswith(('#','http','mailto:')):
    assert (root/'dist'/value).is_file(),f'Missing asset: {value}'
Check().feed((root/'dist/index.html').read_text())
r=json.loads((root/'dist/assets/replay.json').read_text())
assert r['tests']['failed']==0 and r['tests']['passed']>0
assert r['metrics']['seeded_rules_detected']==5
assert r['metrics']['benign_alerts']==0
assert len(r['scenarios'])==6
with zipfile.ZipFile(root/'dist/assets/sentinel-api-source.zip') as z:
 names=z.namelist()
 assert any(n.endswith('backend/sentinel/app.py') for n in names)
 assert not any('/.state/' in n or n.endswith('.pem') or '/.venv/' in n or '/.openai/' in n for n in names)
print('Static references, recorded evidence and source archive validated.')
