"""Check that an oversized folder is listed but cannot enter this backend."""
import argparse,json,shutil,sys,time
from pathlib import Path
p=argparse.ArgumentParser()
for n in ('emulator-root','emulator','firmware','storage','output'):p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();sys.path.insert(0,str(a.emulator_root.resolve()));from runtime_probe import Session
out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);storage=a.storage.resolve()
with Session(storage/'FlashLd.g1a',out,['--os-firmware',a.firmware.resolve(),'--memory-profile','probe3','--heap-bytes',40960],a.emulator.resolve(),cwd=storage.parents[1]) as s:
    def key(k):
        s.command('key',key=k,down=True);time.sleep(.1);s.command('key',key=k,down=False);time.sleep(.3)
    s.remote.request('c',wait=False);time.sleep(.5)
    for _ in range(4):key('DOWN')
    shutil.copyfile(out/'screen.bmp',out/'oversized-list.bmp');key('EXE')
    shutil.copyfile(out/'screen.bmp',out/'oversized-blocked.bmp')
    assert s.command('status')['state']=='running'
    assert not any(c['number']==0xacd for c in s.command('syscalls')['recent'])
    key('EXIT');key('EXIT');assert s.command('status')['state']=='exited'
    (out/'result.json').write_text(json.dumps({'passed':True,'hardwareValidated':False,'backendAllocationAttempted':False,'status':s.command('status')},indent=2))
print('oversized-folder-blocked PASS')
