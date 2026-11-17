"""Run target instructions normally; never inject page tables or results."""
from pathlib import Path
import argparse,hashlib,json,shutil,sys,time
p=argparse.ArgumentParser();p.add_argument('--sdk',type=Path,required=True);p.add_argument('--firmware',type=Path,required=True)
p.add_argument('--exe',type=Path,required=True);p.add_argument('--build',type=Path,required=True)
p.add_argument('--mode',choices=['O','M','A'],required=True);p.add_argument('--label',required=True)
p.add_argument('--stress',action='store_true');p.add_argument('--heap',type=int,default=49152);p.add_argument('--timeout',type=int,default=180)
a=p.parse_args();root=Path(__file__).resolve().parents[1];out=root/'evidence'/a.label
out.mkdir(parents=True,exist_ok=False);storage=out/'storage/fls0';storage.mkdir(parents=True)
sys.path.insert(0,str(a.sdk/'probes/emulator'));from runtime_probe import Session
for n in ['Map698.g1a','Map698.bin','Map698.txt']:shutil.copy2(a.build/n,storage/n)
(storage/'Map698.cfg').write_bytes(a.mode.encode()+b'\n')
options=['--os-firmware',a.firmware,'--memory-profile','probe3','--heap-bytes',str(a.heap),'--trace-syscalls',out/'syscalls.jsonl']
if a.stress:options+=['--file-map-stress']
report={'mode':a.mode,'stress':a.stress,'heapBytes':a.heap,'mathKernelExecuted':False,'hostWritesTargetMemory':False,'hashes':{str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in [a.exe,a.firmware,storage/'Map698.g1a',storage/'Map698.bin']}}
start=time.monotonic();last=0
with Session(storage/'Map698.g1a',out,options,executable=a.exe,timeout=30,cwd=out) as s:
 s.remote.request('c',wait=False)
 while time.monotonic()-start<a.timeout:
  time.sleep(.4);state=s.command('status');log=(storage/'Map698.txt').read_text(errors='replace').rstrip()
  if state['state']!='running' or 'PASS=' in log or 'FAILED=' in log:break
  if time.monotonic()-last>15:
   print(json.dumps({'label':a.label,'elapsed':round(time.monotonic()-start),'state':state['state'],'logTail':log[-160:]}),flush=True);last=time.monotonic()
 else:report['timedOut']=True
 time.sleep(.3);report['beforeExit']=s.command('status');report['diagnostics']=s.command('diagnostics')
 report['log']=log;report['passMarker']='PASS=0000082E,0000082E' in log
 if report['passMarker'] and report['beforeExit']['state']=='running':
  if (out/'screen.bmp').exists():shutil.copy2(out/'screen.bmp',out/'pass.bmp')
  s.command('key',key='EXIT',down=True);time.sleep(.15);s.command('key',key='EXIT',down=False)
  deadline=time.monotonic()+5
  while time.monotonic()<deadline and s.command('status')['state']=='running':time.sleep(.1)
 report['final']=s.command('status');report['syscalls']=s.command('syscalls');report['elapsedHostSeconds']=time.monotonic()-start
 if report['final']['state']=='running':s.remote.interrupt()
(out/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps({'label':a.label,'passMarker':report['passMarker'],'state':report['final']['state'],'error':report['final'].get('error'),'elapsed':report['elapsedHostSeconds'],'log':log},ensure_ascii=False),flush=True)
