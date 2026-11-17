"""Exercise fail-closed preflight paths without entering third-party code."""
import argparse,json,shutil,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'emulator'))
from runtime_probe import Session
p=argparse.ArgumentParser()
for name in ['loader','bundle','firmware','output']:p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True);results=[]
for case,expected,extra in [
 ('missing-profile','Missing khicas.kpf',[]),
 ('profile-version','Invalid profile',[]),
 ('unreviewed-image','Unreviewed image',[]),
 ('insufficient-heap','Allocation failed',['--heap-bytes','28672']),
 ('unsupported-stack','Unsupported stack',['--memory-profile','default'])]:
 root=(a.output/case).resolve();store=root/'storage/fls0';store.mkdir(parents=True,exist_ok=True)
 for name in ['khicas.bin','khicas.kpf','KLoad.txt']:shutil.copyfile(a.bundle/name,store/name)
 shutil.copyfile(a.loader,store/'KLoad.g1a')
 if case=='missing-profile':(store/'khicas.kpf').rename(store/'missing.kpf')
 if case in ['profile-version','unreviewed-image']:
  path=store/'khicas.kpf';b=bytearray(path.read_bytes());b[11 if case=='profile-version' else 24]^=1;path.write_bytes(b)
 options=['--os-firmware',a.firmware.resolve(),'--memory-profile','probe3',*extra]
 with Session(store/'KLoad.g1a',root,options,cwd=root) as s:
  s.remote.request('c',wait=False);deadline=time.monotonic()+10;confirmed=False
  while time.monotonic()<deadline:
   time.sleep(.1);status=s.command('status');log=(store/'KLoad.txt').read_text()
   if not confirmed and any(c['number']==0x90f for c in s.command('syscalls')['recent']):
    s.command('key',key='EXE',down=True);time.sleep(.15);s.command('key',key='EXE',down=False);confirmed=True
   if expected in log or status['state']!='running':break
  assert expected in log,(case,status,log.strip())
  assert 'TARGET_GETKEY=' not in log,case
  s.command('key',key='EXIT',down=True);time.sleep(.15);s.command('key',key='EXIT',down=False)
  for _ in range(20):
   time.sleep(.1);status=s.command('status')
   if status['state']!='running':break
  assert status['state']=='exited',(case,status)
  results.append({'case':case,'diagnostic':expected,'exited':True})
(a.output/'results.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
