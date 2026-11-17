"""Exercise folder discovery, Full/Fast cache, and cleanup in the real emulator.

External samples/firmware are inputs; this script never writes target RAM.
"""
import argparse,hashlib,json,shutil,struct,sys,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for name in ('emulator-root','emulator','firmware','loader','bundle','output'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args()
for name in vars(a):setattr(a,name,getattr(a,name).resolve())
sys.path.insert(0,str(a.emulator_root));from runtime_probe import Session
a.output.mkdir(parents=True,exist_ok=True)
storage=a.output/'storage/fls0';storage.mkdir(parents=True,exist_ok=True)
shutil.copyfile(a.loader,storage/'FlashLd.g1a')
ids=[('AM123456','amine'),('FR123456','fruit'),('MI123456','mines'),('WS123456','wsc')]
for directory,ident in ids:
    root=storage/'FXAPPS'/directory;root.mkdir(parents=True,exist_ok=True)
    data=(a.bundle/(ident+'.bin')).read_bytes()
    (root/'IMAGE.BIN').write_bytes(data);shutil.copyfile(a.bundle/(ident+'.fpf'),root/'APP.FPF')
    (root/'APP.MET').write_bytes(struct.pack('>8sIIII32s8s',b'FXAPPM01',1,1,len(data),0,ident.encode(),bytes(8)))
    (root/'ICON.BIN').write_bytes(data[0x40:0x84])
    (root/'RUN.LOG').write_bytes(b'FXFLASH1\n'+b' '*(4096-9));(root/'VERIFY.CCH').write_bytes(bytes(4096))
bad=storage/'FXAPPS'/'BAD00000';bad.mkdir(exist_ok=True);(bad/'APP.MET').write_bytes(bytes(64))
extra=storage/'FXAPPS'/'ZZ123456';extra.mkdir(exist_ok=True)
(extra/'APP.MET').write_bytes(struct.pack('>8sIIII32s8s',b'FXAPPM01',1,2,0x280000,0,b'Oversized',bytes(8)))
results=[]
def key(s,k,hold=.08,gap=.22):
    assert s.command('key',key=k,down=True)['ok'];time.sleep(hold);s.command('key',key=k,down=False);time.sleep(gap)
def wait(s,predicate,timeout=30):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if predicate():return
        if s.command('status')['state'] not in ('running','paused'):
            if predicate():return
            raise AssertionError(s.command('status'))
        time.sleep(.05)
    raise TimeoutError(s.command('status'))
def run(name,index=0,fast=False,expected_mode=0,fail=None,stress=False,cleanup=True):
    out=a.output/name;out.mkdir(exist_ok=True)
    path=storage/'FXAPPS'/ids[index][0]/'RUN.LOG'
    # Stale success text must not leak past the new explicit terminator.
    path.write_bytes(b'FXFLASH1\n'+b' '*(3500-9)+b'STALE_OLD_RUN\n'+b' '*(4096-3514))
    def log():return path.read_text(errors='replace').split('\nRUN_END\n',1)[0].rstrip()
    options=['--os-firmware',a.firmware,'--memory-profile','probe3','--heap-bytes',40960,'--trace-syscalls',out/'syscalls.jsonl']
    if stress:options+=['--file-map-stress','--menu-vram-stress']
    r={'case':name,'hardwareValidated':False,'hostWritesTargetMemory':False,'passed':False}
    with Session(storage/'FlashLd.g1a',out,options,a.emulator,timeout=30,cwd=a.output) as s:
        try:
            s.remote.request('c',wait=False)
            wait(s,lambda:any(c['number']==0x90f for c in s.command('syscalls')['recent']))
            time.sleep(.2);shutil.copyfile(out/'screen.bmp',out/'browser.bmp')
            for _ in range(index):key(s,'DOWN')
            if fast:key(s,'F2');key(s,'EXE')
            key(s,'EXE')
            if fail:
                wait(s,lambda:fail in log());assert 'READY_ENTRY=' not in log();key(s,'EXIT')
            else:
                wait(s,lambda:'READY_ENTRY=' in log())
                assert f',{expected_mode:08X}' in log().split('RUN_ID_MODE=')[1].splitlines()[0],log()
                assert 'STALE_OLD_RUN' not in log(),log()
                time.sleep(3)
                if name.startswith('full-') and ids[index][1] in ('amine','mines'):
                    for k in ('EXE','EXE','SHIFT','RIGHT','DOWN','OPTN'):key(s,k)
                shutil.copyfile(out/'screen.bmp',out/'target.bmp')
                assert s.command('status')['state']=='running',s.command('status')
                if cleanup:
                    if ids[index][1]=='fruit':key(s,'F6',1)
                    key(s,'MENU',1)
                    wait(s,lambda:s.command('status')['osMenu'] or s.command('status')['state']=='exited')
                    if s.command('status')['osMenu']:assert s.command('menu-replace')['ok']
                    wait(s,lambda:s.command('status')['state']=='exited')
                    assert 'TARGET_CLEANUP_DONE=' in log() and 'RUNTIME_FAILED=' not in log(),log()
            r['passed']=True
        except (AssertionError,TimeoutError) as e:r['error']=str(e)
        r.update(log=log(),status=s.command('status'))
        if (out/'screen.bmp').exists():shutil.copyfile(out/'screen.bmp',out/'final.bmp')
    results.append(r);(a.output/'results.json').write_text(json.dumps({'cases':results,'loaderSha256':hashlib.sha256(a.loader.read_bytes()).hexdigest()},indent=2))
    print(name,'PASS' if r['passed'] else 'FAIL',r.get('error',''),flush=True)
for i in range(4):run('full-'+ids[i][1],i,stress=True)
run('fast-valid',0,True,1)
root=storage/'FXAPPS'/ids[0][0];cache=root/'VERIFY.CCH'
data=bytearray(cache.read_bytes());data[64]^=1;cache.write_bytes(data)
run('fast-corrupt-cache-falls-back',0,True,0)
cache.write_bytes(bytes(4096));run('fast-empty-cache-falls-back',0,True,0)
image=root/'IMAGE.BIN';original=image.read_bytes();changed=bytearray(original);changed[0x110]^=1;image.write_bytes(changed)
run('full-rejects-same-size-edit',0,False,0,'BIN hash mismatch')
run('fast-documented-same-size-blind-spot',0,True,1)
image.write_bytes(original)
if not all(r['passed'] for r in results):raise SystemExit(1)
