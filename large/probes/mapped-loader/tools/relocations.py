"""Patch only authored resident relocations; never infer pointers from numbers."""
import hashlib
import json
from pathlib import Path
import struct
import sys

def elf(path):
    b=bytearray(path.read_bytes())
    assert b[:6]==b'\x7fELF\x01\x02', 'expected big-endian ELF32'
    shoff=struct.unpack_from('>I',b,32)[0]
    size,count,names=struct.unpack_from('>HHH',b,46)
    sections=[struct.unpack_from('>10I',b,shoff+i*size) for i in range(count)]
    st=sections[names]; strings=b[st[4]:st[4]+st[5]]
    def name(s): return strings[s[0]:].split(b'\0',1)[0].decode()
    return b,sections,{name(s):i for i,s in enumerate(sections)}

def fixups(path):
    b,sections,names=elf(path)
    ri=names['.resident']; r=sections[ri]; low,high=r[3],r[3]+r[5]
    found=[]; relative=0
    for rel in sections:
        if rel[1]!=4 or rel[7]!=ri: continue
        sym=sections[rel[6]]
        for off in range(rel[4],rel[4]+rel[5],12):
            place,info,addend=struct.unpack_from('>IIi',b,off)
            kind=info&255; si=info>>8
            _,value,_,_,_,section=struct.unpack_from('>IIIBBH',b,sym[4]+si*16)
            if kind==0: continue
            if section!=ri: raise ValueError(f'resident references outside section: {place:x}, type={kind}, symbol={value:x}')
            if kind==1:
                stored=struct.unpack_from('>I',b,r[4]+place-low)[0]
                if not low<=stored<high: raise ValueError(f'bad resident pointer {stored:x}')
                found.append(place-low)
            elif kind in (2,3,4,5,6,7,8,9): relative+=1
            else: raise ValueError(f'unsupported resident relocation {kind}')
    f=sections[names['.fixups']]
    found=sorted(set(found))
    if (len(found)+1)*4>f[5]: raise ValueError('relocation table overflow')
    struct.pack_into('>'+str(len(found)+1)+'I',b,f[4],len(found),*found)
    path.write_bytes(b)
    report={'residentAddress':hex(low),'residentBytes':r[5],
            'absoluteFixups':len(found),'relativeReferences':relative,'outsideReferences':0,
            'fixupOffsets':found}
    path.with_suffix('.resident.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k!='fixupOffsets'}))

def fnv(data):
    x=2166136261
    for n in data:x=((x^n)*16777619)&0xffffffff
    return x

def bundle(folder):
    data=(folder/'P2Target.container').read_bytes()
    if len(data)!=16384: raise ValueError(f'payload length {len(data)}, expected 16384')
    (folder/'Probe2.bin').write_bytes(data)
    (folder/'Probe2.cfg').write_text(f'FXPROBE2\nimage_bytes=16384\nimage_fnv={fnv(data):08X}\nloops=8\nhold_ms=480\n',encoding='ascii')
    (folder/'payload-manifest.json').write_text(json.dumps({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
        'fnv32':f'{fnv(data):08X}','imageBase':'00300000','entry':'00300200','ramBase':'08100000',
        'ramBytes':8192,'dataOffset':8192,'dataDestination':'08100004','dataBytes':4},indent=2),encoding='ascii')

if __name__=='__main__':
    if sys.argv[1]=='fixups':fixups(Path(sys.argv[2]))
    elif sys.argv[1]=='bundle':bundle(Path(sys.argv[2]))
    else:raise SystemExit('fixups ELF | bundle BUILD_DIRECTORY')
