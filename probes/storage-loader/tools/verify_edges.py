"""Execute the real loader against malformed files and an authored returning guest."""
import argparse,importlib.util,json,re,shutil,struct,sys,time
from collections import Counter
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
for case in ['return','oom','bad-bin','no-bin','wrong-size','bad-profile','bad-patch','bad-gate','bad-catalog','no-profile','foreign-log','ram-conflict','ram-retry','ram-adjacent','ram-retry-twice']:
 root=out/case;storage=root/'storage/fls0';storage.mkdir(parents=True)
 for f in (out/'bundle').iterdir():shutil.copyfile(f,storage/f.name)
 shutil.copyfile(a.loader,storage/'FlashLd.g1a')
 image=storage/'fixture.bin';profile=storage/'fixture.fpf'
 if case=='bad-bin':data=bytearray(image.read_bytes());data[-1]^=1;image.write_bytes(data)
 if case=='no-bin':image.unlink()
 if case=='wrong-size':image.write_bytes(image.read_bytes()+b'X')
 if case=='bad-profile':profile.write_bytes(bytes(384))
 if case in ('bad-patch','bad-gate','ram-conflict','ram-retry','ram-adjacent','ram-retry-twice'):
  data=bytearray(profile.read_bytes())
  if case=='bad-patch':struct.pack_into('>I',data,128,0xffffffff)
  if case=='bad-gate':struct.pack_into('>I',data,128,0x220)
  if case.startswith('ram-'):
   # probe3's first user pointer is 0x880502a0. An 8 KiB exclusion leaves
   # enough room only when the rejected candidate's unused suffix is released.
   end={'ram-conflict':0x88070000,'ram-retry':0x880522a0,'ram-adjacent':0x880502a0,'ram-retry-twice':0x880506a0}[case]
   struct.pack_into('>I',data,28,1);struct.pack_into('>II',data,64,0x88050000,end)
   if case=='ram-retry-twice':
    # Put the second exclusion just beyond the first candidate, so shifting
    # past the first exclusion will actually encounter it, at any build size.
    second=0x880502a0+first_request+0x100
    end=second+0xc0
    struct.pack_into('>I',data,28,2);struct.pack_into('>II',data,72,second,end)
  profile.write_bytes(data)
 if case=='bad-catalog':(storage/'Loader.idx').write_bytes(bytes(204))
 if case=='no-profile':profile.unlink()
 if case=='foreign-log':(storage/'FlashLd.txt').write_bytes(b'keep unrelated data')
 heap=1024 if case=='oom' else 49152 if case in ('ram-conflict','ram-retry-twice') else 40960
 options=['--os-firmware',a.firmware.resolve(),'--memory-profile','probe3','--heap-bytes',heap,'--file-map-stress']
 trace=root/'heap.jsonl'
 if case.startswith('ram-') or case=='return':options+=['--trace-syscalls',trace]
 with Session(storage/'FlashLd.g1a',root,options,a.emulator.resolve(),cwd=root) as s:
  def key(k):s.command('key',key=k,down=True);time.sleep(.12);s.command('key',key=k,down=False);time.sleep(.3)
  def log():return (storage/'FlashLd.txt').read_text(errors='replace').rstrip()
  def wait(fn):
   end=time.monotonic()+25
   while not fn():
    assert time.monotonic()<end,s.command('status')
    time.sleep(.05)
  s.remote.request('c',wait=False);time.sleep(.4)
  if case!='bad-catalog':key('EXE')
  if case in ('return','ram-adjacent','ram-retry','ram-retry-twice'):
   wait(lambda:s.command('status')['state']=='exited')
   assert 'TARGET_RETURNED=0000002A' in log() and 'TARGET_CLEANUP_DONE=' in log(),log()
   count=int(re.search(r'RAM_CANDIDATES=([0-9A-F]+)',log())[1],16)
   assert count>={'ram-retry':2,'ram-retry-twice':3}.get(case,1),(case,log())
   if case.startswith('ram-retry'):assert int(re.search(r'CONTEXT_BYTES=([0-9A-F]+)',log())[1],16)>=end
   assert s.remote.receive()=='W00'
   assert s.remote.read_memory(0x08100004,4)==bytes.fromhex('00000001')
  else:
   time.sleep(1);assert 'READY_ENTRY=' not in log(),log()
   assert s.command('status')['state']=='running'
   key('EXIT');wait(lambda:s.command('status')['state']=='exited')
  if case=='ram-conflict':
   assert 'START_FAILED=No fitting OS block' in log() and 'RAM_FIRST=880502A0' in log(),log()
   candidates=int(re.search('RAM_CANDIDATES=([0-9A-F]+)',log())[1],16)
   conflicts=int(re.search('RAM_CONFLICTS=([0-9A-F]+)',log())[1],16)
   assert conflicts==candidates and conflicts>=2,(case,log())
  if trace.is_file():
   calls=[e['call'] for e in map(json.loads,trace.read_text().splitlines()) if e['phase']=='leave']
   if case=='return':first_request=next(c['args'][0] for c in calls if c['number']==0xacd)
   alloc=Counter(c['result'] for c in calls if c['number']==0xacd and c['result'])
   free=Counter(c['args'][0] for c in calls if c['number']==0xacc and c['args'][0])
   assert alloc==free,(case,alloc,free)
   if case=='ram-conflict':assert any(c['number']==0xacd and not c['result'] for c in calls),case
  if case=='foreign-log':assert (storage/'FlashLd.txt').read_bytes()==b'keep unrelated data'
  results.append({'case':case,'passed':True,'log':log(),'status':s.command('status')});print(case,'PASS',flush=True)
(out/'results.json').write_text(json.dumps({'hardwareValidated':False,'hostWritesTargetMemory':False,'cases':results},indent=2))
