#!/usr/bin/env python3
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / 'samples'
OUT = ROOT / 'artifacts.zip'

def gather():
    files = []
    comp = SAMPLES / 'compiled'
    out = SAMPLES / 'sandbox_output'
    if comp.exists():
        files.extend([p for p in comp.glob('*') if p.is_file()])
    if out.exists():
        files.extend([p for p in out.glob('**/*') if p.is_file()])
    with zipfile.ZipFile(OUT, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            zf.write(f, arcname=str(f.relative_to(SAMPLES)))
    print(f"Wrote {OUT} with {len(files)} files")

if __name__ == '__main__':
    gather()


