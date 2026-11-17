"""Empty-directory refusal and EXIT, without a legacy package present."""
import argparse,json,sys,shutil,time,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for key in ('emulator-root','emulator','loader','output'):p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();sys.path.insert(0,str(a.emulator_root.resolve()))
from runtime_probe import Session
original_popen=subprocess.Popen
def hidden_popen(*args,**kw):
    if sys.platform=='win32':
        startup=subprocess.STARTUPINFO();startup.dwFlags|=subprocess.STARTF_USESHOWWINDOW;startup.wShowWindow=0;kw['startupinfo']=startup
    return original_popen(*args,**kw)
subprocess.Popen=hidden_popen
out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
storage=out/'storage/fls0';(storage/'FXAPPS').mkdir(parents=True)
addin=storage/'Test.g1a';shutil.copy2(a.loader,addin)
with Session(addin,out,[],a.emulator.resolve(),timeout=30,cwd=out) as session:
    session.remote.request('c',wait=False);deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        calls=session.command('syscalls')
        if any(c['number']==0x90f for c in calls['recent']):break
        time.sleep(.1)
    assert not any(c['number'] in (0xacd,0xffff0001) for c in calls['recent']),calls
    assert session.command('status')['state']=='running'
    shutil.copy2(out/'screen.bmp',out/'empty.bmp')
    session.command('key',key='EXIT',down=True);time.sleep(.12);session.command('key',key='EXIT',down=False)
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        state=session.command('status')
        if state['state']=='exited':break
        time.sleep(.1)
    assert state['state']=='exited',state
    result={'emptyCatalogRefused':True,'noResidentAllocation':True,'exitReturned':True,'hardwareValidated':False}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
