"""Run real Loader.g1a file I/O and handoff; never inject target RAM or registers.

GDB is used only for start/pause and observational reads. Third-party originals
stay external. A blocked target is a result, not a compatibility pass.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'emulator'))
from runtime_probe import Session
from prepare import prepare

SEQUENCES = {
    'khicas': ['F1','2','PLUS','2','EXE'],
    'wolf': ['EXE','EXE','UP','RIGHT','UP'],
    'fruit': ['SWIPE0','SWIPE1','SWIPE2','SWIPE3']*2+['F6'],
    'mines': ['EXE','EXE','SHIFT','RIGHT','DOWN','OPTN','F4','F4'],
}

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def wait(s, predicate, seconds=20, allow_paused=False):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if predicate(): return
        st=s.command('status')
        if st['state'] in ('error','exited') or (st['state']=='paused' and not allow_paused):
            if predicate():return
            raise AssertionError(st)
        time.sleep(.02)
    raise TimeoutError(s.command('status'))

def press(s, key, hold=.045, gap=.2):
    assert s.command('key',key=key,down=True)['ok']
    time.sleep(hold)
    assert s.command('key',key=key,down=False)['ok']
    time.sleep(gap)

def gesture(s, row):
    # Fruit's virtual touchpad needs a continuous stroke, not isolated taps.
    keys=[['1','2','3','PLUS','MINUS'],['4','5','6','MULT','DIV'],
          ['7','8','9','DEL'],['0','DP','EXP','NEG','EXE']][row]
    previous=None
    for key in keys:
        assert s.command('key',key=key,down=True)['ok'];time.sleep(.06)
        if previous:s.command('key',key=previous,down=False)
        previous=key
    s.command('key',key=previous,down=False);time.sleep(.3)

def read_log(storage):
    p=storage/'Loader.txt'
    return p.read_text('ascii').rstrip() if p.exists() else ''

from fixtures import authored_target

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--bundle',type=Path,required=True)
    p.add_argument('--emulator',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--section',choices=('all','samples','edges'),default='all')
    p.add_argument('--fault-policy',choices=('reboot','pause'),default='reboot')
    a=p.parse_args()
    root,bundle,exe=a.output.resolve(),a.bundle.resolve(),a.emulator.resolve()
    items=json.loads(a.manifest.read_text('utf8'))
    # Sessions change cwd to isolate Bfile storage; pin caller-relative inputs now.
    for item in items:item['source']=str(Path(item['source']).resolve())
    root.mkdir(parents=True,exist_ok=True)
    results=[]

    def storage_for(name, source=bundle):
        folder=root/name; storage=folder/'storage/fls0'
        storage.mkdir(parents=True,exist_ok=False)
        for src in source.iterdir():
            if src.suffix in ('.bin','.lpf','.idx'): shutil.copy2(src,storage/src.name)
        return folder,storage

    def start(folder, addin, heap=196608, profile='default', label='session'):
        os.chdir(folder)
        s=Session(addin,folder/label,['--memory-profile',profile,'--heap-bytes',heap,
                  '--step-limit','2000000000','--trace-syscalls',folder/(label+'-syscalls.jsonl')],exe,
                  fault_policy=a.fault_policy)
        s.remote.request('c',wait=False)
        wait(s,lambda:s.command('status')['state']=='running',allow_paused=True)
        return s

    def catalog(s,index):
        wait(s,lambda:any(c['number']==0x90f for c in s.command('syscalls')['recent']))
        for _ in range(index):press(s,'DOWN')
        press(s,'EXE')

    def screen(s,folder,label):
        # Pause refreshes the framebuffer without changing guest memory.
        if s.command('status')['state']=='running' and not s.command('status')['osMenu']:
            s.remote.interrupt();shutil.copy2(s.output/'screen.bmp',folder/(label+'.bmp'))
            s.remote.request('c',wait=False)
            wait(s,lambda:s.command('status')['state']=='running',allow_paused=True)
        else:shutil.copy2(s.output/'screen.bmp',folder/(label+'.bmp'))

    def record(s,folder,name,storage,**extra):
        result={'case':name,'status':s.command('status'),'diagnostics':s.command('diagnostics'),
                'syscalls':s.command('syscalls'),'recovery':s.command('recovery'),'log':read_log(storage),**extra}
        (folder/'result.json').write_text(json.dumps(result,indent=2),encoding='utf8')
        results.append(result)
        print(name,result['status']['state'],result['status']['error'],flush=True)
        return result

    for index,item in enumerate(items if a.section!='edges' else []):
        name=item['id']; source=Path(item['source'])
        assert digest(source)==item['expectedSha256']==digest(bundle/(name+'.bin'))
        for mode in ('direct','loader'):
            folder,storage=storage_for(mode+'-'+name)
            with start(folder,source if mode=='direct' else bundle/'Loader.g1a',
                       49152 if name=='khicas' and mode=='direct' else 196608,
                       'khicas' if name=='khicas' and mode=='direct' else 'default') as s:
                if mode=='loader':
                    catalog(s,index)
                    wait(s,lambda:'TARGET_ENTER' in read_log(storage) or 'REJECTED=' in read_log(storage))
                time.sleep(3 if name=='wolf' else .5)
                screen(s,folder,'startup')
                blocked=mode=='loader' and 'REJECTED=' in read_log(storage)
                if not blocked:
                    for i,key in enumerate(SEQUENCES[name]):
                        if s.command('status')['state']!='running':break
                        if key.startswith('SWIPE'):gesture(s,int(key[-1]))
                        else:press(s,key)
                        screen(s,folder,f'key-{i:02}-{key}')
                play=s.command('status')
                # The old SDK games have separate menu/quit tests below.
                if name=='mines' and not blocked:
                    press(s,'MENU');wait(s,lambda:s.command('status')['osMenu'])
                    assert s.command('menu-replace')['ok']
                    wait(s,lambda:s.command('status')['state']=='exited')
                    if mode=='loader':
                        assert 'TARGET_EXIT_GUARD=00000000' in read_log(storage)
                        assert 'CLEANUP=00000000,00000001' in read_log(storage)
                if blocked:
                    assert name=='khicas' and 'REJECTED=Need file mapping' in read_log(storage)
                    press(s,'EXIT');wait(s,lambda:s.command('status')['state']=='exited')
                record(s,folder,mode+'-'+name,storage,playStatus=play,blocked=blocked)
            if mode=='loader' and name=='mines':
                # Fresh Loader invocation with real saved files, and another load/exit.
                with start(folder,bundle/'Loader.g1a',label='reentry') as s:
                    catalog(s,index);wait(s,lambda:'TARGET_ENTER' in read_log(storage))
                    time.sleep(.7);press(s,'EXE');press(s,'MENU')
                    wait(s,lambda:s.command('status')['osMenu']);s.command('menu-replace')
                    wait(s,lambda:s.command('status')['state']=='exited')
                    assert 'CLEANUP=00000000,00000001' in read_log(storage)
                    record(s,folder,'loader-mines-reentry',storage)

    # Startup CRT cleanup is tested equally on original and loaded images.
    for name,keys in ([('wolf',['DOWN','DOWN','EXE']),('fruit',['F6','MENU'])] if a.section!='edges' else []):
        index=next(i for i,x in enumerate(items) if x['id']==name)
        for mode in ('direct','loader'):
            folder,storage=storage_for(mode+'-quit-'+name)
            with start(folder,Path(items[index]['source']) if mode=='direct' else bundle/'Loader.g1a') as s:
                if mode=='loader':catalog(s,index);wait(s,lambda:'TARGET_ENTER' in read_log(storage))
                time.sleep(3)
                for key in keys:
                    if s.command('status')['state']!='running':break
                    press(s,key,hold=.15,gap=.5)
                    if s.command('status')['osMenu']:
                        s.command('menu-replace');time.sleep(.2)
                expected_state='rebooted' if a.fault_policy=='reboot' else 'error'
                wait(s,lambda:s.command('status')['state']==expected_state)
                recovery=s.command('recovery')
                report=json.loads(Path(recovery['report']).read_text('utf8'))
                assert report['kind']==('reset-vector' if name=='wolf' else 'unexpected-fault'),report
                if name=='fruit':assert '0x0218' in report['error'],report
                screen(s,folder,'quit');record(s,folder,mode+'-quit-'+name,storage,
                    rebootCause=report['kind'],faultError=report['error'],assertionsPassed=True)

    own=root/'authored';own.mkdir(exist_ok=True)
    fixture=authored_target(own/'fixture.g1a');prepare([fixture],own/'bundle')
    cases=['return','low-heap','context-oom','image-oom','runner-oom','bad-bin','no-bin','wrong-size',
           'bad-profile','bad-patch','bad-gate','bad-catalog','no-profile','foreign-log','ram-conflict']
    for case in (cases if a.section!='samples' else []):
        folder,storage=storage_for('edge-'+case,own/'bundle')
        file=storage/'fixture.bin';prof=storage/'fixture.lpf';budget=49152
        if case=='low-heap':
            shutil.copy2(bundle/'fruit.bin',file);shutil.copy2(bundle/'fruit.lpf',prof)
        if case=='context-oom':budget=256
        if case=='image-oom':budget=4096
        if case=='runner-oom':budget=16384
        if case=='bad-bin':
            data=bytearray(file.read_bytes());data[-1]^=1;file.write_bytes(data)
        if case=='no-bin':file.unlink()
        if case=='wrong-size':file.write_bytes(file.read_bytes()+b'xx')
        if case=='bad-profile':prof.write_bytes(bytes(384))
        if case in ('bad-patch','bad-gate','ram-conflict'):
            data=bytearray(prof.read_bytes())
            if case=='bad-patch':struct.pack_into('>I',data,128,0xffffffff)
            if case=='bad-gate':struct.pack_into('>I',data,128,0x220)
            if case=='ram-conflict':
                struct.pack_into('>I',data,28,1);struct.pack_into('>II',data,64,0x88040000,0x88070000)
            prof.write_bytes(data)
        if case=='bad-catalog':(storage/'Loader.idx').write_bytes(bytes(204))
        if case=='no-profile':prof.unlink()
        if case=='foreign-log':(storage/'Loader.txt').write_bytes(b'keep this unrelated file')
        with start(folder,bundle/'Loader.g1a',budget) as s:
            if case!='bad-catalog':catalog(s,0)
            else:time.sleep(.2)
            if case=='return':
                wait(s,lambda:'CLEANUP=' in read_log(storage))
                log=read_log(storage)
                assert 'TARGET_RETURN=0000002A,00000000' in log,log
                assert 'TARGET_CALLBACK_RETURNED' in log and 'CLEANUP=00000000,00000000' in log,log
                s.remote.interrupt()
                assert s.remote.read_memory(0x08100004,4)==bytes.fromhex('00000001')
                s.remote.request('c',wait=False)
            else:
                time.sleep(.3)
                assert 'TARGET_ENTER' not in read_log(storage)
            screen(s,folder,'result');press(s,'EXIT')
            wait(s,lambda:s.command('status')['state']=='exited')
            if case=='foreign-log':assert (storage/'Loader.txt').read_bytes()==b'keep this unrelated file'
            record(s,folder,'edge-'+case,storage,assertionsPassed=True)

    report={'hardwareValidated':False,'targetMemoryInjected':False,'faultPolicy':a.fault_policy,
            'loaderSha256':digest(bundle/'Loader.g1a'),'emulatorSha256':digest(exe),'cases':results}
    (root/'verification.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print('Saved',root/'verification.json')

if __name__=='__main__':main()
