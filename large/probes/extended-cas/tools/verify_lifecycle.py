"""Observe real loader binaries across MENU resume and replacement.

No host writes to guest RAM/registers. MENU redraw is an explicit HLE stress
scenario, not a claim that the complete physical OS has been reproduced.
Screens must also be reviewed; the assertions verify control flow/allocations.
"""
import argparse,hashlib,json,shutil,sys,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for key in ('emulator-root','emulator','firmware','bundle','loader','output'):
 p.add_argument('--'+key,type=Path,required=True)
p.add_argument('--kind',choices=('giac','khicas'),required=True)
p.add_argument('--baseline',action='store_true')
a=p.parse_args();sys.path.insert(0,str(a.emulator_root.resolve()))
from runtime_probe import Session
out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
storage=out/'storage/fls0';storage.mkdir(parents=True)
names=['KHICAS.BIN'] if a.kind=='giac' else ['khicas.bin','khicas.kpf','KLoad.txt']
for name in names:shutil.copyfile(a.bundle/name,storage/name)
addin=storage/('KhiMap.g1a' if a.kind=='giac' else 'KLoad.g1a');shutil.copyfile(a.loader,addin)
trace=out/'syscalls.jsonl'
options=['--os-firmware',a.firmware.resolve(),'--memory-profile','probe3','--heap-bytes','40960',
         '--file-map-stress','--menu-vram-stress','--trace-syscalls',trace]
def calls():
 result=[]
 for line in trace.read_text().splitlines():
  try:j=json.loads(line)
  except json.JSONDecodeError:continue # a live trace can end mid-record
  if j['phase']=='leave':result.append(j['call'])
 return result
def allocations():return [c for c in calls() if c['number']==0xacd and c['result']]
def wait(s,predicate,seconds=160):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if predicate():return
  status=s.command('status')
  if status['state'] not in ('running','paused'):raise AssertionError(status)
  time.sleep(.2)
 raise TimeoutError(s.command('status'))
def press(s,key):
 assert s.command('key',key=key,down=True)['ok'];time.sleep(.12)
 assert s.command('key',key=key,down=False)['ok'];time.sleep(.65)
def snap(s,name):
 time.sleep(.15);shutil.copyfile(out/'screen.bmp',out/(name+'.bmp'))
 print(name,s.command('status'),flush=True)
def ready(s,cycle):
 if a.kind=='giac':
  wait(s,lambda:len([c for c in allocations() if c['args'][0]==32768])>=cycle)
  time.sleep(4)
 else:
  wait(s,lambda:'TARGET_GETKEY=' in (storage/'KLoad.txt').read_text())
  time.sleep(1)
with Session(addin,out,options,a.emulator.resolve(),timeout=30,cwd=out) as s:
 s.remote.request('c',wait=False)
 if a.kind=='khicas' and not a.baseline:
  wait(s,lambda:any(c['number']==0x90f for c in s.command('syscalls')['recent']))
  snap(s,'00-start-instructions');press(s,'EXE')
 ready(s,1);snap(s,'01-ready')
 if a.kind=='khicas':press(s,'EXE')
 for key in ('2','PLUS','2','EXE'):press(s,key)
 snap(s,'02-calculation')
 press(s,'MENU');wait(s,lambda:s.command('status')['osMenu'],20)
 snap(s,'03-menu');before=allocations()
 assert s.command('menu-resume')['ok'];time.sleep(.5)
 snap(s,'04-same-icon-no-extra-key')
 assert not s.command('status')['osMenu']
 assert len(allocations())==len(before),'Selecting the icon unexpectedly started another instance'
 assert s.command('status')['pc']=='80010070','Expected the suspended OS key wait'
 press(s,'EXE')
 if a.kind=='giac':ready(s,2)
 snap(s,'05-after-EXE')
 for key in ('3','PLUS','4','EXE'):press(s,key)
 snap(s,'06-second-calculation')
 press(s,'MENU');wait(s,lambda:s.command('status')['osMenu'],20)
 assert s.command('menu-replace')['ok'];wait(s,lambda:s.command('status')['state']=='exited',20)
 allcalls=calls();alloc=allocations();frees=[c['args'][0] for c in allcalls if c['number']==0xacc]
 result={'schemaVersion':1,'kind':a.kind,'baseline':a.baseline,'hardwareValidated':False,
         'hostWritesTargetMemory':False,'menuVramStress':True,'status':s.command('status'),
         'allocations':[{'bytes':c['args'][0],'address':c['result']} for c in alloc],
         'frees':frees,'screenReviewRequired':True,
         'hashes':{q.name:hashlib.sha256(q.read_bytes()).hexdigest() for q in (addin,a.emulator,*[storage/n for n in names])}}
 if a.kind=='giac':
  assert len(alloc)==4,(alloc,frees)
  assert sorted(c['result'] for c in alloc)==sorted(frees)
  assert [c['result'] for c in alloc[:2]]==[c['result'] for c in alloc[2:]],'Heap blocks not reused'
 else:
  log=(storage/'KLoad.txt').read_text()
  assert 'TARGET_CLEANUP_DONE=' in log and 'RUNTIME_FAILED=' not in log
 (out/'result.json').write_text(json.dumps(result,indent=2))
 print('PASS: MENU wait/resume, explicit EXE, second calculation inputs, replacement cleanup',flush=True)
