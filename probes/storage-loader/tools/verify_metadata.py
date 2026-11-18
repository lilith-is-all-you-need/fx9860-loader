"""Reject APP.MET/profile size disagreement before allocating the backend."""
import argparse,hashlib,json,shutil,struct,sys,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for name in ('emulator-root','emulator','firmware','loader','bundle','output'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args()
for name in vars(a):setattr(a,name,getattr(a,name).resolve())
sys.path.insert(0,str(a.emulator_root));from runtime_probe import Session
a.output.mkdir(parents=True,exist_ok=True);results=[]
for mismatch in (False,True):
    name='metadata-mismatch' if mismatch else 'metadata-match';out=a.output/name
    folder=out/'storage/fls0/FXAPPS/TEST1234';folder.mkdir(parents=True,exist_ok=True)
    data=(a.bundle/'fixture.bin').read_bytes();(folder/'IMAGE.BIN').write_bytes(data)
    shutil.copyfile(a.bundle/'fixture.fpf',folder/'APP.FPF')
    (folder/'APP.MET').write_bytes(struct.pack('>8sIIII32s8s',b'FXAPPM01',1,1,len(data)+(4 if mismatch else 0),0,b'Fixture',bytes(8)))
    (folder/'RUN.LOG').write_bytes(b'FXFLASH1\n'+b' '*(4096-9))
    loader=out/'storage/fls0/FlashLd.g1a';shutil.copyfile(a.loader,loader)
    with Session(loader,out,['--os-firmware',a.firmware,'--memory-profile','probe3','--heap-bytes',40960],a.emulator,cwd=out) as s:
        def log():return (folder/'RUN.LOG').read_text(errors='replace').split('\nRUN_END\n',1)[0].rstrip()
        def key(k):s.command('key',key=k,down=True);time.sleep(.1);s.command('key',key=k,down=False);time.sleep(.3)
        s.remote.request('c',wait=False);time.sleep(.5);key('EXE')
        expected='START_FAILED=MET/profile size' if mismatch else 'TARGET_RETURNED=0000002A'
        deadline=time.monotonic()+15
        while expected not in log():
            assert time.monotonic()<deadline,(log(),s.command('status'))
            time.sleep(.05)
        if mismatch:
            assert 'READY_ENTRY=' not in log()
            assert not any(c['number']==0xacd for c in s.command('syscalls')['recent'])
            assert s.command('status')['state']=='running'
            key('EXIT')
        while s.command('status')['state']!='exited':
            assert time.monotonic()<deadline,(log(),s.command('status'))
            time.sleep(.05)
        results.append({'case':name,'passed':True,'log':log(),'backendAllocationAttempted':not mismatch})
        print(name,'PASS',flush=True)
(a.output/'results.json').write_text(json.dumps({'hardwareValidated':False,'loaderSha256':hashlib.sha256(a.loader.read_bytes()).hexdigest(),'cases':results},indent=2))
