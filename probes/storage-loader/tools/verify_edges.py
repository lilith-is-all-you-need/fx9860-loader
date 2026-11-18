"""Execute the real loader against malformed files and an authored returning guest."""
import argparse,importlib.util,json,shutil,struct,sys,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for name in ('emulator-root','emulator','firmware','loader','output'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();sys.path.insert(0,str(a.emulator_root.resolve()))
from runtime_probe import Session
from prepare import prepare
spec=importlib.util.spec_from_file_location('authored',Path(__file__).resolve().parents[2]/'native-loader/tools/fixtures.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
prepare([m.authored_target(out/'fixture.g1a')],out/'bundle');results=[]
for case in ['return','oom','bad-bin','no-bin','wrong-size','bad-profile','bad-patch','bad-gate','bad-catalog','no-profile','foreign-log','ram-conflict']:
 root=out/case;storage=root/'storage/fls0';storage.mkdir(parents=True)
 for f in (out/'bundle').iterdir():shutil.copyfile(f,storage/f.name)
 shutil.copyfile(a.loader,storage/'FlashLd.g1a')
 image=storage/'fixture.bin';profile=storage/'fixture.fpf'
 if case=='bad-bin':data=bytearray(image.read_bytes());data[-1]^=1;image.write_bytes(data)
 if case=='no-bin':image.unlink()
 if case=='wrong-size':image.write_bytes(image.read_bytes()+b'X')
 if case=='bad-profile':profile.write_bytes(bytes(384))
 if case in ('bad-patch','bad-gate','ram-conflict'):
  data=bytearray(profile.read_bytes())
  if case=='bad-patch':struct.pack_into('>I',data,128,0xffffffff)
  if case=='bad-gate':struct.pack_into('>I',data,128,0x220)
  if case=='ram-conflict':struct.pack_into('>I',data,28,1);struct.pack_into('>II',data,64,0x88050000,0x88070000)
  profile.write_bytes(data)
 if case=='bad-catalog':(storage/'Loader.idx').write_bytes(bytes(204))
 if case=='no-profile':profile.unlink()
 if case=='foreign-log':(storage/'FlashLd.txt').write_bytes(b'keep unrelated data')
 with Session(storage/'FlashLd.g1a',root,['--os-firmware',a.firmware.resolve(),'--memory-profile','probe3','--heap-bytes',1024 if case=='oom' else 40960,'--file-map-stress'],a.emulator.resolve(),cwd=root) as s:
  def key(k):s.command('key',key=k,down=True);time.sleep(.12);s.command('key',key=k,down=False);time.sleep(.3)
  def log():return (storage/'FlashLd.txt').read_text(errors='replace').rstrip()
  def wait(fn):
   end=time.monotonic()+25
   while not fn():
    assert time.monotonic()<end,s.command('status')
    time.sleep(.05)
  s.remote.request('c',wait=False);time.sleep(.4)
  if case!='bad-catalog':key('EXE')
  if case=='return':
   wait(lambda:s.command('status')['state']=='exited')
   assert 'TARGET_RETURNED=0000002A' in log() and 'TARGET_CLEANUP_DONE=' in log(),log()
   assert s.remote.receive()=='W00'
   assert s.remote.read_memory(0x08100004,4)==bytes.fromhex('00000001')
  else:
   time.sleep(1);assert 'READY_ENTRY=' not in log(),log()
   assert s.command('status')['state']=='running'
   key('EXIT');wait(lambda:s.command('status')['state']=='exited')
  if case=='foreign-log':assert (storage/'FlashLd.txt').read_bytes()==b'keep unrelated data'
  results.append({'case':case,'passed':True,'log':log(),'status':s.command('status')});print(case,'PASS',flush=True)
(out/'results.json').write_text(json.dumps({'hardwareValidated':False,'hostWritesTargetMemory':False,'cases':results},indent=2))
