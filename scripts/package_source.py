"""Package portable project source without credentials, runtime state or Site identity."""
from pathlib import Path
import zipfile
root=Path(__file__).resolve().parents[1]
out=root/'dist/assets/sentinel-api-source.zip'
skip={'.git','.venv','.state','__pycache__','.pytest_cache','.openai','node_modules'}
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as archive:
 for f in sorted(root.rglob('*')):
  rel=f.relative_to(root)
  if not f.is_file() or any(p in skip for p in rel.parts) or f==out or f.name=='.env':continue
  archive.write(f,'sentinel-api/'+str(rel))
print('Packaged portable source:',out)
