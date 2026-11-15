"""Deterministic, exact-version adapter; never guesses address relocations."""
import argparse,hashlib,importlib.util,json,struct
from pathlib import Path
APPROVED='4a9d1c18009d987dc7c8745b7fc099b3c6e8006ebbb2ee5e4b483934be757473'
POOL_PATCHES=[(0x1d14d0,0x88051000,0x88060000),(0x1d14dc,0x88052000,0x88061000),(0x1d14f0,0x88053800,0x88062800)]
def prepare(source,output):
 b=source.read_bytes()
 if hashlib.sha256(b).hexdigest()!=APPROVED:raise ValueError('Unreviewed KhiCAS version; refused')
 tool=Path(__file__).resolve().parents[2]/'native-loader/tools/prepare.py'
 spec=importlib.util.spec_from_file_location('gate_scanner',tool);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 _,report=module.profile(b)
 patches=[(p['offset'],0x80010070,0) for p in report['patches']]+POOL_PATCHES
 patches.sort()
 assert len(patches)==54
 assert sorted(set(p[0]//4096 for p in patches))==[0,465,470,471]
 for off,old,new in patches:
  if struct.unpack_from('>I',b,off)[0]!=old:raise ValueError('Patch preimage mismatch')
 profile=struct.pack('>8s4I32s',b'FXKHP001',1,len(b),len(patches),0x88060000,bytes.fromhex(APPROVED))
 profile+=b''.join(struct.pack('>3I',*p) for p in patches)+bytes((64-len(patches))*12)
 assert len(profile)==824
 output.mkdir(parents=True,exist_ok=True)
 for name,data in [('khicas.bin',b),('khicas.kpf',profile)]:
  p=output/name
  if p.exists() and p.read_bytes()!=data:raise FileExistsError(p)
  p.write_bytes(data)
 log=output/'KLoad.txt'
 if not log.exists():log.write_bytes(b'FXKLOAD1\n'+b' '*(4096-9))
 report.update(adapter='mapped-khicas-v1',hardwareValidated=False,shadowPages=[0,465,470,471],poolPatches=POOL_PATCHES,
   originalArenaBytes=0x29800,adaptedArenaBytes=0x1a800,profileSha256=hashlib.sha256(profile).hexdigest())
 (output/'adapter-report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
 return report
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
 r=prepare(a.source,a.output);print(json.dumps({k:r[k] for k in ['sha256','bytes','shadowPages','adaptedArenaBytes']},indent=2))
