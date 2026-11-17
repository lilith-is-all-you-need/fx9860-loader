import argparse,json,shutil,sys,time
from pathlib import Path
S=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(S/'probes/emulator'))
from runtime_probe import Session
p=argparse.ArgumentParser(description='Run real KhiCAS via KLoad; no guest RAM/register injection')
for name in ['loader','bundle','firmware','output']:p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--stress',action='store_true');p.add_argument('--keys',default='EXE,2,PLUS,2,EXE,2,POWER,1,0,EXE');p.add_argument('--reuse',action='store_true');p.add_argument('--seconds',type=int,default=150)
a=p.parse_args();a.menu=True
out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
storage=out/'storage/fls0';storage.mkdir(parents=True,exist_ok=True)
for name in ['khicas.bin','khicas.kpf','KLoad.txt']:
 if not a.reuse or not (storage/name).exists():shutil.copyfile(a.bundle/name,storage/name)
shutil.copyfile(a.loader,storage/'KLoad.g1a')
options=['--os-firmware',a.firmware.resolve(),'--memory-profile','probe3','--trace-syscalls',out/'syscalls.jsonl']
if a.stress:options+=['--file-map-stress']
with Session(storage/'KLoad.g1a',out,options,cwd=out,timeout=30) as s:
 s.remote.request('c',wait=False);start=time.monotonic();ready=False;confirmed=False
 while time.monotonic()-start<a.seconds:
  time.sleep(1);status=s.command('status')
  trace=s.command('syscalls').get('recent',[])
  if not confirmed and any(x['number']==0x90f and str(x.get('caller','')).startswith('003') for x in trace):
   s.command('key',key='EXE',down=True);time.sleep(.15);s.command('key',key='EXE',down=False);confirmed=True
  # Waiting at the real target's GetKey, after a durable gateway checkpoint.
  report=(storage/'KLoad.txt').read_text(errors='replace')
  if 'TARGET_GETKEY=' in report:
   ready=True
   if any(x.get('number')==0x90f and str(x.get('caller','')).startswith('A8') and not x.get('completed',True) for x in trace):break
  if status['state']!='running':break
  if int(time.monotonic()-start)%15==0:print(json.dumps({'elapsed':round(time.monotonic()-start),'status':status,'ready':ready}),flush=True)
 print(json.dumps({'phase':'loaded','status':status,'ready':ready,'recent':trace[-5:]}),flush=True)
 (out/'initial-status.json').write_text(json.dumps(status,indent=2))
 if ready and status['state']=='running':
  time.sleep(.5)
  for i,key in enumerate(filter(None,a.keys.split(','))):
   print('key',key,flush=True);s.command('key',key=key,down=True);time.sleep(.15);s.command('key',key=key,down=False);time.sleep(.7)
   if (out/'screen.bmp').exists():shutil.copyfile(out/'screen.bmp',out/f'key-{i}-{key}.bmp')
   if s.command('status')['state']!='running':break
  if a.menu and s.command('status')['state']=='running':
   s.command('key',key='MENU',down=True);time.sleep(.15);s.command('key',key='MENU',down=False);time.sleep(.5)
   print('menu',s.command('status'),flush=True)
   print('replace',s.command('menu-replace'),flush=True);time.sleep(2)
 status=s.command('status')
 if status['state']=='running':s.remote.interrupt()
 if ready and status['state']=='running':
  (out/'ram-pools.json').write_text(json.dumps({'work1':s.remote.read_memory(0x081000dc,4).hex(),'work2':s.remote.read_memory(0x081000e0,4).hex(),'arena':s.remote.read_memory(0x08100038,8).hex()},indent=2))
 (out/'result.json').write_text(json.dumps({'ready':ready,'status':status,'syscalls':s.command('syscalls'),'elapsed':time.monotonic()-start},indent=2))
 print(json.dumps({'final':status,'log':(storage/'KLoad.txt').read_text(errors='replace').rstrip()}),flush=True)

assert ready and status['state']=='exited',status
report=(storage/'KLoad.txt').read_text();assert 'TARGET_CLEANUP_DONE=' in report and 'RUNTIME_FAILED=' not in report
session=storage/'session.xw';assert session.exists() and any(session.read_bytes()),'session file was not written'
print('PASS: target startup, calculation inputs, durable session, menu cleanup')
