"""Expand the compiled source-guest body to exercise every real image page."""
import argparse,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tooling'))
from ext_profile import wrap_raw,encode_profile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('g1a',type=Path);p.add_argument('output',type=Path)
p.add_argument('--bytes',type=int,required=True);p.add_argument('--capacity',type=int)
a=p.parse_args();raw=a.g1a.read_bytes()[512:]
if a.bytes<512+len(raw) or len(raw)>3584:raise SystemExit('guest must fit in first page')
body=bytearray(a.bytes-512);body[:len(raw)]=raw
for offset in range(4096,a.bytes,4096):
    if offset+4>a.bytes:raise SystemExit('last page needs four readable fixture bytes')
    struct.pack_into('>I',body,offset-512,0xfaca0000|offset//4096)
image=wrap_raw(body);profile=encode_profile(image,capacity=a.capacity)
a.output.mkdir(parents=True,exist_ok=True)
(a.output/'IMAGE.BIN').write_bytes(image);(a.output/'EXT.PRF').write_bytes(profile)
print(f'fixture {len(image)} bytes; {(len(image)+4095)//4096} pages')
