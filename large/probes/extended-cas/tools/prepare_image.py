"""Wrap an already source-integrated raw payload; never adapt an arbitrary G1A."""
import argparse,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'tooling'))
from ext_profile import wrap_raw,encode_profile,decode_profile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('raw',type=Path);p.add_argument('out',type=Path)
p.add_argument('--capacity',type=int);p.add_argument('--guest-ram',type=int,default=0)
a=p.parse_args();raw=a.raw.read_bytes();image=wrap_raw(raw)
profile=encode_profile(image,capacity=a.capacity,guest_ram_bytes=a.guest_ram)
a.out.mkdir(parents=True,exist_ok=True)
for name,data in (('IMAGE.BIN',image),('EXT.PRF',profile)):
    path=a.out/name
    if path.exists() and path.read_bytes()!=data:raise SystemExit(f'refusing to overwrite {path}')
    path.write_bytes(data)
report={**decode_profile(profile),'rawSha256':hashlib.sha256(raw).hexdigest(),
        'runtimeIntegrationRequired':True,'hardwareValidated':False}
(a.out/'payload.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps(report))
