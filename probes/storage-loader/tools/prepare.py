"""Generic Flash profiles: same image layout, only classified syscall gates.

No program identity whitelist. Passing these structural checks is an experimental
test candidate, not proof of arbitrary program memory/callback compatibility.
"""
import argparse,hashlib,importlib.util,json,re,struct
from pathlib import Path
spec=importlib.util.spec_from_file_location('flash_gate_scan',Path(__file__).resolve().parents[2]/'native-loader/tools/prepare.py')
scanner=importlib.util.module_from_spec(spec);spec.loader.exec_module(scanner)

def profile(data,forbidden=()):
    packed,report=scanner.profile(data,forbidden)
    if len(data)>2*1024*1024:raise ValueError('Flash mapping requires an image within the OS 2 MiB window')
    if report['unadaptedControlTransfers']:
        raise scanner.ReviewRequired('Direct reset/exit transfer requires a runtime adapter',
                                     {'unadaptedControlTransfers':report['unadaptedControlTransfers'],
                                      'recognizedGateCount':len(report['patches'])})
    packed=bytearray(packed);packed[:8]=b'FXLDF001';struct.pack_into('>I',packed,20,2)
    pages=sorted({p['offset']//4096 for p in report['patches']})
    even=sum(p%2==0 for p in pages);odd=len(pages)-even
    span=2*max(even,odd)*4096
    report.update(backend='flash',strategy='OS file mapping with dynamically selected syscall shadow pages',
                  shadowPages=pages,shadowSpanBytes=span,shadowAlignmentAllowance=4095,
                  cacheColorFromActualAllocation=True,
                  imageCopyBytes=0,programWhitelist=False,
                  warnings=['Original CRT/private RAM, callbacks, timers and direct MMU use still need runtime validation',
                            'Resident/context/allocator/guest memory is additional to the shadow span'])
    return bytes(packed),report

def prepare(items,output):
    output=Path(output)
    if output.exists():raise FileExistsError('Choose a new output directory')
    if not 1<=len(items)<=8:raise ValueError('Catalog size must be 1 through 8')
    identifiers=set();catalog=struct.pack('>8sI',b'FXLDIDX1',len(items));reports=[];pending=[]
    for item in items:
        ident,title=item['id'],item['title']
        if not re.fullmatch('[a-z0-9_]{1,7}',ident) or ident in identifiers or len(title.encode('ascii'))>15:raise ValueError('Invalid or duplicate catalog identity')
        identifiers.add(ident);source=Path(item['source'])
        if not 516<=source.stat().st_size<=2*1024*1024:raise ValueError('G1A size outside Flash window')
        with source.open('rb') as f:data=f.read(2*1024*1024+1)
        if item.get('expectedSha256') and item['expectedSha256']!=hashlib.sha256(data).hexdigest():raise ValueError('Input changed')
        packed,report=profile(data,item.get('forbiddenPhysicalRam',()))
        pending.extend([(ident+'.bin',data),(ident+'.fpf',packed)])
        catalog+=struct.pack('>8s16s',ident.encode(),title.encode());reports.append({'id':ident,'title':title,**report})
    pending.append(('Loader.idx',catalog+bytes(24*(8-len(items)))))
    pending.append(('FlashLd.txt',b'FXFLASH1\n'+b' '*(4096-9)))
    output.mkdir(parents=True)
    for name,content in pending:(output/name).write_bytes(content)
    (output/'profiles.json').write_text(json.dumps(reports,indent=2)+'\n',encoding='utf8')
    return reports

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    a=p.parse_args();items=json.loads(a.manifest.read_text('utf-8-sig'))
    for item in items:item['source']=str(a.manifest.resolve().parent/item['source'])
    print(json.dumps(prepare(items,a.output),indent=2))
