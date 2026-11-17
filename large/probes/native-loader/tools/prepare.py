"""Produce exact renamed BINs and bounded profiles for reviewed input versions.

This does not recover arbitrary relocations. Original addresses and CRT remain.
Only positively matched syscall stubs supply gateway literal patch locations.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

BASE=0x300000

def profile(data, forbidden=()):
    if len(data)<516 or len(data)>0x400000 or bytes(x^255 for x in data[:8])!=b'USBPower':
        raise ValueError('not a supported G1A container')
    if any(len(r)!=2 or not 0x80000000<=r[0]<r[1]<0xa0000000 for r in forbidden):
        raise ValueError('invalid forbidden P1 RAM range')
    u16=lambda n:struct.unpack_from('>H',data,n)[0]
    u32=lambda n:struct.unpack_from('>I',data,n)[0]
    gates={}
    # MOV.L @(disp,PC),Rn; MOV.L @(disp,PC),R0; JMP @Rn; NOP.
    # The compiler emits both this shared-pool and per-function-pool form.
    for at in range(512,len(data)-7,2):
        op=u16(at);reg=(op>>8)&15
        if op>>12!=13 or reg in (0,15):continue
        pool=((at+4)&~3)+(op&255)*4
        if pool+4>len(data) or u32(pool)!=0x80010070:continue
        if u16(at+2)>>8==0xd0 and u16(at+4)==(0x402b|(reg<<8)) and u16(at+6)==9:
            number_pool=((at+6)&~3)+(u16(at+2)&255)*4
            if number_pool+4>len(data):continue
            number,kind,size=u32(number_pool),'literal-number tail call',8
        elif u16(at+2)==(0x402b|(reg<<8)) and u16(at+4)==0x60f2:
            number,kind,size=None,'stack-number tail call',6
        elif u16(at+2)==(0x400b|(reg<<8)) and u16(at+4)>>8==0xe0:
            number,kind,size=u16(at+4)&255,'immediate-number call',6
        else:continue
        gates.setdefault(pool,[]).append({'stubOffset':at,'number':number,'form':kind,'instructionHex':data[at:at+size].hex()})
    literals=[n for n in range(512,len(data)-3,4) if u32(n)==0x80010070]
    unclassified=sorted(set(literals)-set(gates))
    if unclassified:raise ValueError('unclassified syscall gate literals: '+str(unclassified))
    if not gates:raise ValueError('no recognized syscall gate; adapter required')
    if len(gates)>64 or len(forbidden)>8:raise ValueError('profile table limit')
    hazards=[]
    for at in range(512,len(data)-5,2):
        op=u16(at);reg=(op>>8)&15
        pool=((at+4)&~3)+(op&255)*4
        if op>>12==13 and pool+4<=len(data) and u16(at+2)==(0x402b|(reg<<8)) and u16(at+4)==9 and u32(pool)==0xa0000000:
            hazards.append({'kind':'direct jump to boot-ROM alias; exit adapter required',
                            'instructionOffset':at,'literalOffset':pool,'destination':0xa0000000})
    digest=hashlib.sha256(data).digest()
    out=struct.pack('>8s6I',b'FXLDP001',1,len(data),BASE+512,1,len(gates),len(forbidden))+digest
    out+=b''.join(struct.pack('>II',*r) for r in forbidden)+bytes(8*(8-len(forbidden)))
    offsets=sorted(gates)
    out+=b''.join(struct.pack('>I',v) for v in offsets)+bytes(4*(64-len(offsets)))
    assert len(out)==384
    return out,{'sha256':digest.hex(),'bytes':len(data),'entry':BASE+512,
                'strategy':'retain original image addresses and full original startup',
                'backend':'pinned RAM image; rejects above 160 KiB before allocation',
                'hardwareValidated':False,'patches':[{'offset':off,'expected':0x80010070,'replacement':'resident syscall gateway','evidence':gates[off]} for off in offsets],
                'forbiddenPhysicalRam':forbidden,'unclassifiedGateLiterals':unclassified,
                'unadaptedControlTransfers':hazards}

def prepare(items, output):
    output.mkdir(parents=True,exist_ok=True)
    if not 1<=len(items)<=8:raise ValueError('catalog size')
    catalog=struct.pack('>8sI',b'FXLDIDX1',len(items));reports=[];pending=[];identifiers=set()
    for item in items:
        ident,title=item['id'],item['title']
        if not re.fullmatch('[a-z0-9_]{1,7}',ident) or len(title.encode('ascii'))>15:raise ValueError('invalid catalog item')
        if ident in identifiers:raise ValueError('duplicate catalog identifier')
        identifiers.add(ident)
        data=Path(item['source']).read_bytes()
        if item.get('expectedSha256')!=hashlib.sha256(data).hexdigest():raise ValueError(f'{ident}: input differs from reviewed version')
        packed,report=profile(data,item.get('forbiddenPhysicalRam',()))
        for ext,content in (('.bin',data),('.lpf',packed)):
            dest=output/(ident+ext)
            if dest.exists() and dest.read_bytes()!=content:raise FileExistsError(dest)
            pending.append((dest,content))
        catalog+=struct.pack('>8s16s',ident.encode(),title.encode())
        reports.append({'id':ident,'title':title,**report})
    catalog+=bytes(24*(8-len(items)))
    assert len(catalog)==204
    # Finish validation of every input before publishing a new catalog.
    for dest,content in pending:dest.write_bytes(content)
    (output/'Loader.idx').write_bytes(catalog)
    (output/'profiles.json').write_text(json.dumps(reports,indent=2),encoding='utf8')
    return reports

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    reports=prepare(json.loads(a.manifest.read_text('utf8')),a.output)
    print(json.dumps([{'id':r['id'],'bytes':r['bytes'],'sha256':r['sha256'],'gatewayPools':len(r['patches'])} for r in reports],indent=2))
