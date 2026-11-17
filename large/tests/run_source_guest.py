"""Exercise a compiled source adapter over variable page counts, observing only."""
import argparse,json,struct,sys,time,subprocess,shutil
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for key in ('emulator-root','emulator','firmware','guest','loader','output'):
    p.add_argument('--'+key,type=Path,required=True)
p.add_argument('--bytes',type=int,default=0x200004);p.add_argument('--capacity',type=int)
a=p.parse_args()
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tooling'))
from ext_profile import wrap_raw,encode_profile,decode_profile
sys.path.insert(0,str(a.emulator_root.resolve()))
from runtime_probe import Session
original_popen=subprocess.Popen
def hidden_popen(*args,**kw):
    if sys.platform=='win32':
        startup=subprocess.STARTUPINFO();startup.dwFlags|=subprocess.STARTF_USESHOWWINDOW;startup.wShowWindow=0;kw['startupinfo']=startup
    return original_popen(*args,**kw)
subprocess.Popen=hidden_popen
out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
storage=out/'storage/fls0';app=storage/'FXAPPS/SOURCE01';app.mkdir(parents=True)
raw=a.guest.read_bytes()[512:]
assert 512+len(raw)<=min(4096,a.bytes)
body=bytearray(a.bytes-512);body[:len(raw)]=raw
for offset in range(4096,a.bytes,4096):struct.pack_into('>I',body,offset-512,0xfaca0000|offset//4096)
image=wrap_raw(body);profile=encode_profile(image,capacity=a.capacity)
(app/'IMAGE.BIN').write_bytes(image);(app/'EXT.PRF').write_bytes(profile)
addin=storage/'ExtLoad.g1a';shutil.copy2(a.loader,addin)
trace=out/'syscalls.jsonl';options=['--os-firmware',a.firmware.resolve(),'--memory-profile','probe3','--heap-bytes','49152','--trace-syscalls',trace]
with Session(addin,out,options,a.emulator.resolve(),timeout=30,cwd=out) as session:
    session.remote.request('c',wait=False)
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        if any(c['number']==0x90f for c in session.command('syscalls')['recent']):break
        time.sleep(.15)
    session.command('key',key='EXE',down=True);time.sleep(.12);session.command('key',key='EXE',down=False)
    deadline=time.monotonic()+160;allocations=[];frees=[]
    while time.monotonic()<deadline:
        state=session.command('status')
        if state['state']!='running':raise AssertionError(state)
        calls=[]
        if trace.exists():
            for line in trace.read_text().splitlines():
                try:item=json.loads(line)
                except ValueError:continue
                if item['phase']=='leave':calls.append(item['call'])
        allocations=[c for c in calls if c['number']==0xacd and c['result']]
        frees=[c for c in calls if c['number']==0xacc]
        if frees:break
        time.sleep(.2)
    assert len(allocations)==1 and len(frees)==1,(allocations,frees)
    context=allocations[0]['result'];assert frees[0]['args'][0]==context
    session.remote.interrupt()
    # Explicit debug layout v1; reads after teardown, never target writes.
    data=session.remote.read_memory(context,468)
    u32=lambda offset:struct.unpack_from('>I',data,offset)[0]
    pages,capacity=u32(52),u32(56)
    spare=session.remote.read_memory(u32(156)+pages*4,(capacity-pages)*4) if capacity>pages else b''
    result={'profile':decode_profile(profile),'stage':u32(204),'phase':u32(208),'status':u32(212),
            'failureStage':u32(220),'payloadRc':u32(228),'refills':u32(188),'highRefills':u32(192),
            'residentBytes':allocations[0]['args'][0],'spareAllZero':not any(spare),
            'allocationReleased':True,'hostWritesTargetMemory':False,'hardwareValidated':False}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    assert (result['stage'],result['phase'],result['status'],result['failureStage'],result['payloadRc'])==(6,1,0xd0000000|pages,0,0),result
    assert result['spareAllZero'] and result['refills']>=pages,result
    if pages>512:assert result['highRefills']>=pages-512,result
    print(json.dumps(result),flush=True)
