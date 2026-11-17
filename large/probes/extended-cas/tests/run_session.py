"""Normal loader boot with file-spooled observation/key requests, never target writes.

The caller may atomically create commands/NNNN.json with one of: key, snapshot,
inspect, quit. Inspect pauses and reads registers/memory, then resumes only if
the guest was running. All requests and responses are retained as evidence.
"""
import argparse,hashlib,json,shutil,sys,time,traceback
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--sdk',type=Path,required=True)
p.add_argument('--exe',type=Path,required=True);p.add_argument('--firmware',type=Path,required=True)
p.add_argument('--bundle',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
p.add_argument('--heap',type=int,default=49152);p.add_argument('--seconds',type=int,default=1800)
p.add_argument('--stress',action='store_true');a=p.parse_args()
for name in ['sdk','exe','firmware','bundle','out']:setattr(a,name,getattr(a,name).resolve())
a.out.mkdir(parents=True,exist_ok=False);storage=a.out/'storage/fls0';storage.mkdir(parents=True)
cmds=a.out/'commands';cmds.mkdir();responses=a.out/'responses';responses.mkdir()
for n in ['KhiMap.g1a','KHICAS.BIN']:shutil.copy2(a.bundle/n,storage/n)
sys.path.insert(0,str(a.sdk/'probes/emulator'));from runtime_probe import Session
meta={'hostWritesTargetMemory':False,'heapBytes':a.heap,'stress':a.stress,'hashes':{str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in [a.exe,a.firmware,storage/'KhiMap.g1a',storage/'KHICAS.BIN']}}
(a.out/'inputs.json').write_text(json.dumps(meta,indent=2),encoding='utf8')
opts=['--os-firmware',a.firmware,'--memory-profile','probe3','--heap-bytes',str(a.heap),'--trace-syscalls',a.out/'syscalls.jsonl']
if a.stress:opts+=['--file-map-stress']
done=set();start=time.monotonic();last=0
with Session(storage/'KhiMap.g1a',a.out,opts,executable=a.exe,timeout=30,cwd=a.out) as s:
 s.remote.request('c',wait=False)
 while time.monotonic()-start<a.seconds:
  state=s.command('status')
  for path in sorted(cmds.glob('*.json')):
   if path.name in done:continue
   try:req=json.loads(path.read_text(encoding='utf-8-sig'))
   except (OSError,ValueError):continue
   result={}
   try:
    op=req['op']
    if op=='key':
     result=s.command('key',key=req['key'],down=True);time.sleep(req.get('hold',.13));s.command('key',key=req['key'],down=False);time.sleep(req.get('after',.15))
    elif op=='snapshot':
     result={'status':s.command('status'),'diagnostics':s.command('diagnostics'),'syscalls':s.command('syscalls')}
     if (a.out/'screen.bmp').exists():shutil.copy2(a.out/'screen.bmp',responses/(path.stem+'.bmp'))
    elif op=='inspect':
     running=state['state']=='running'
     if running:s.remote.interrupt()
     # Drain a pending stop packet for natural faults by requesting '?'.
     result={'status':s.command('status')}
     result['registers']={str(i):f'{s.remote.get(i):08x}' for i in range(23)}
     for name,addr,size in req.get('reads',[]):
      try:result[name]=s.remote.read_memory(int(addr,0),size).hex()
      except Exception as e:result[name]=str(e)
     if running:s.remote.request('c',wait=False)
    elif op=='quit':done.add(path.name);break
    else:raise ValueError(op)
   except Exception:result={'error':traceback.format_exc()}
   (responses/path.name).write_text(json.dumps(result,indent=2),encoding='utf8');done.add(path.name)
  else:
   if time.monotonic()-last>15:
    print(json.dumps({'elapsed':round(time.monotonic()-start),'status':state}),flush=True);last=time.monotonic()
   time.sleep(.15);continue
  break
 result={'status':s.command('status'),'diagnostics':s.command('diagnostics'),'syscalls':s.command('syscalls'),'elapsedHostSeconds':time.monotonic()-start}
 (a.out/'result.json').write_text(json.dumps(result,indent=2),encoding='utf8')
print(json.dumps(result),flush=True)
