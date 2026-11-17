"""Normal directory selection and boot; no debugger memory/register writes."""
import argparse,hashlib,json,shutil,struct,sys,time,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for key in ('emulator-root','emulator','firmware','image','loader','output'):
    p.add_argument('--'+key,type=Path,required=True)
p.add_argument('--capacity',type=int);p.add_argument('--seconds',type=int,default=130)
p.add_argument('--kind',choices=('ext','mapped'),default='ext')
a=p.parse_args()
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tooling'))
from ext_profile import prepare
sys.path.insert(0,str(a.emulator_root.resolve()))
from runtime_probe import Session
original_popen=subprocess.Popen
def hidden_popen(*args,**kw):
    if sys.platform=='win32':
        startup=subprocess.STARTUPINFO();startup.dwFlags|=subprocess.STARTF_USESHOWWINDOW;startup.wShowWindow=0;kw['startupinfo']=startup
    return original_popen(*args,**kw)
subprocess.Popen=hidden_popen
out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
storage=out/'storage/fls0';app=storage/'FXAPPS/GIAC001';app.mkdir(parents=True)
if a.kind=='ext':profile=prepare(a.image,app,capacity=a.capacity)
else:
    shutil.copy2(a.image,app/'IMAGE.BIN');shutil.copy2(a.image.parent/'khicas.kpf',app/'KHICAS.KPF')
    shutil.copy2(a.image.parent/'KLoad.txt',app/'KLOAD.TXT')
    profile={'imageBytes':a.image.stat().st_size,'kind':'mapped'}
meta=bytearray(64);meta[:8]=b'FXAPPM01';struct.pack_into('>4I',meta,8,1,2 if a.kind=='ext' else 3,profile['imageBytes'],0);meta[24:28]=b'Giac';(app/'APP.MET').write_bytes(meta)
addin=storage/('ExtLoad.g1a' if a.kind=='ext' else 'KLoad.g1a');shutil.copy2(a.loader,addin)
trace=out/'syscalls.jsonl'
options=['--os-firmware',a.firmware.resolve(),'--memory-profile','probe3','--heap-bytes','49152','--trace-syscalls',trace]
with Session(addin,out,options,a.emulator.resolve(),timeout=30,cwd=out) as session:
    session.remote.request('c',wait=False)
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        if any(c['number']==0x90f for c in session.command('syscalls')['recent']):break
        time.sleep(.15)
    shutil.copy2(out/'screen.bmp',out/'01-directory.bmp')
    session.command('key',key='EXE',down=True);time.sleep(.12);session.command('key',key='EXE',down=False)
    if a.kind=='mapped':
        time.sleep(.5);session.command('key',key='EXE',down=True);time.sleep(.12);session.command('key',key='EXE',down=False)
    began=time.monotonic()
    while time.monotonic()-began<a.seconds:
        status=session.command('status')
        if status['state']!='running':break
        calls=[]
        if trace.exists():
            for line in trace.read_text().splitlines():
                try:item=json.loads(line)
                except ValueError:continue
                if item['phase']=='leave':calls.append(item['call'])
        ready=any(c['number']==0xacd and c['args'][0]==32768 and c.get('result') for c in calls)
        if a.kind=='mapped':ready='TARGET_GETKEY=' in (app/'KLOAD.TXT').read_text(errors='replace')
        if ready:
            time.sleep(7);break
        time.sleep(.4)
    shutil.copy2(out/'screen.bmp',out/'02-start.bmp')
    result={'profile':profile,'status':session.command('status'),'syscalls':session.command('syscalls'),
            'diagnostics':session.command('diagnostics'),'hostWritesTargetMemory':False,'hardwareValidated':False,
            'inputHashes':{x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in (a.image,a.loader,a.emulator,a.firmware)}}
    if result['status']['state']=='running':
        if a.kind=='mapped':session.command('key',key='EXE',down=True);time.sleep(.12);session.command('key',key='EXE',down=False);time.sleep(.3)
        for key in ('2','PLUS','2','EXE'):
            session.command('key',key=key,down=True);time.sleep(.12);session.command('key',key=key,down=False);time.sleep(.6)
        shutil.copy2(out/'screen.bmp',out/'03-calculation.bmp')
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'profile':profile,'output':str(out)}),flush=True)
