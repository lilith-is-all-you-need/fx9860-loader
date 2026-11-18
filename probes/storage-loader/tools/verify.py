"""Run real FlashLd files with bounded heap; guest memory is never injected.

Keys are test scenarios, not application-specific logic in the loader.
Screens must be reviewed separately from startup/cleanup assertions.
"""
import argparse,hashlib,json,shutil,sys,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ('emulator-root','emulator','firmware','loader','bundle','output'):p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--heap',type=int,default=40960);p.add_argument('--ids',default='fruit,mines,terold,tergint,amine,wsc')
p.add_argument('--stress',action='store_true');a=p.parse_args()
sys.path.insert(0,str(a.emulator_root.resolve()));from runtime_probe import Session
out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);results=[]
profiles=json.loads((a.bundle/'profiles.json').read_text());loader=a.loader.resolve()
def wait(s,fn,seconds=25):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if fn():return
  if s.command('status')['state'] not in ('running','paused'):
   if fn():return
   raise AssertionError(s.command('status'))
  time.sleep(.05)
 raise TimeoutError(s.command('status'))
def key(s,k,hold=.07,gap=.3):
 s.command('key',key=k,down=True);time.sleep(hold);s.command('key',key=k,down=False);time.sleep(gap)
for ident in a.ids.split(','):
 index=next(i for i,r in enumerate(profiles) if r['id']==ident)
 root=out/ident;storage=root/'storage/fls0';storage.mkdir(parents=True)
 for f in a.bundle.iterdir():
  if f.is_file():shutil.copyfile(f,storage/f.name)
 shutil.copyfile(loader,storage/'FlashLd.g1a')
 options=['--os-firmware',a.firmware.resolve(),'--memory-profile','probe3','--heap-bytes',a.heap,'--trace-syscalls',root/'syscalls.jsonl']
 if a.stress:options+=['--file-map-stress','--menu-vram-stress']
 with Session(storage/'FlashLd.g1a',root,options,a.emulator.resolve(),timeout=30,cwd=root) as s:
  r={'id':ident,'heapBytes':a.heap,'hostWritesTargetMemory':False,'hardwareValidated':False,'assertionsPassed':False,'started':False,'cleanup':False}
  log=lambda:(storage/'FlashLd.txt').read_text(errors='replace').rstrip()
  def snap(name):
   time.sleep(.2);shutil.copyfile(root/'screen.bmp',root/(name+'.bmp'))
  try:
   s.remote.request('c',wait=False)
   wait(s,lambda:any(c['number']==0x247 for c in s.command('syscalls')['recent']))
   for _ in range(index):key(s,'DOWN')
   key(s,'EXE');time.sleep(3);snap('startup')
   assert 'READY_ENTRY=' in log() and 'FAILED' not in log() and 'FAIL_' not in log(),log()
   assert s.command('status')['state']=='running',s.command('status')
   r['started']=True
   if ident=='fruit':
    for keys in [('1','2','3','PLUS','MINUS'),('4','5','6','MULT','DIV'),('7','8','9','DEL'),('0','DP','EXP','NEG','EXE')]*2:
     previous=None
     for k in keys:
      s.command('key',key=k,down=True);time.sleep(.06)
      if previous:s.command('key',key=previous,down=False)
      previous=k
     s.command('key',key=previous,down=False);time.sleep(.25)
   else:
    for k in (('EXE','EXE','SHIFT','RIGHT','DOWN','OPTN') if ident in ('mines','amine') else ('EXE','LEFT','RIGHT')):key(s,k)
   snap('play');r['playStatus']=s.command('status');assert r['playStatus']['state']=='running',r['playStatus']
   if ident=='fruit':key(s,'F6',1)
   key(s,'MENU',1);wait(s,lambda:s.command('status')['osMenu'] or s.command('status')['state']=='exited',10)
   if s.command('status')['osMenu']:
    r['menuEntered']=True
    assert s.command('menu-resume')['ok'];time.sleep(.5);snap('resume');key(s,'EXE',.2)
    r['resumeStatus']=s.command('status')
    if s.command('status')['state']=='running':
     key(s,'MENU',1);wait(s,lambda:s.command('status')['osMenu'] or s.command('status')['state']=='exited',10)
     if s.command('status')['osMenu']:assert s.command('menu-replace')['ok']
   wait(s,lambda:s.command('status')['state']=='exited',15)
   assert 'TARGET_CLEANUP_DONE=' in log() and 'RUNTIME_FAILED=' not in log(),log()
   r['cleanup']=True
   r['assertionsPassed']=True
  except (AssertionError,TimeoutError) as ex:r['failure']=str(ex);snap('failure')
  r.update(status=s.command('status'),log=log(),syscalls=s.command('syscalls'))
  (root/'result.json').write_text(json.dumps(r,indent=2));results.append(r)
  print(ident,'PASS' if r['assertionsPassed'] else 'FAIL',r.get('failure',''),flush=True)
report={'loaderSha256':hashlib.sha256(loader.read_bytes()).hexdigest(),'emulatorSha256':hashlib.sha256(a.emulator.read_bytes()).hexdigest(),
        'heapBytes':a.heap,'stress':a.stress,'cases':results}
(out/'results.json').write_text(json.dumps(report,indent=2))
if not all(r['assertionsPassed'] for r in results):raise SystemExit(1)
