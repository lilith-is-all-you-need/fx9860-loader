"""Verify exported hook-site bytes and record unresolved runtime obligations.

This is an evidence checker, never a binary patch executor or compatibility seal.
"""
import hashlib


def review(image, evidence):
    digest=hashlib.sha256(image).hexdigest()
    if evidence.get('inputSha256')!=digest or evidence.get('imageBytes')!=len(image):
        raise ValueError('Hook evidence belongs to a different image')
    if evidence.get('imageBase')!=0x300000 or evidence.get('entry')!=0x300200:
        raise ValueError('Unexpected evidence address layout')
    sites=evidence.get('exceptionOwnershipSites',[])
    checked=[]
    for site in sites:
        offset=site.get('fileOffset');original=site.get('originalBytes')
        if not isinstance(offset,int) or isinstance(offset,bool) or offset<512 or offset%2 or not isinstance(original,str):
            raise ValueError('Invalid hook instruction location')
        try:raw=bytes.fromhex(original)
        except ValueError as ex:raise ValueError('Invalid hook instruction bytes') from ex
        if not raw or len(raw)%2 or offset+len(raw)>len(image) or image[offset:offset+len(raw)]!=raw:
            raise ValueError('Hook instruction bytes differ from the immutable input')
        if int(site['address'],16)!=0x300000+offset:
            raise ValueError('Hook address does not match file offset')
        checked.append({'fileOffset':offset,'originalBytes':original,'instruction':site['instruction'],
                        'function':site.get('function'),'delaySlotDepth':site.get('delaySlotDepth'),
                        'inDelaySlot':site.get('inDelaySlot')})
    return {'schemaVersion':1,'kind':'exception-hook-review','inputSha256':digest,
            'executableProfile':False,'status':'runtime-adapter-required',
            'evidenceByteChecks':len(checked),'analysisCompleted':evidence.get('analysisComplete') is True,
            'sites':checked,'unresolvedObligations':[
                'Find every VBR writer and exception dispatch path; recovered instructions may be incomplete.',
                'Specify preserved registers, SR/SSR/SPC, stack, delay slots and original-handler forwarding.',
                'Keep the refill entry and page table resident outside guest-overwritten memory.',
                'Own cache/TLB transitions, OS entry/return, timers and interrupt callbacks.',
                'Restore the caller or resume the guest according to the selected MENU policy.',
                'Test unsupported exceptions and teardown on the actual device.'],
            'note':'Exact byte matches validate provenance only. No replacement bytes or executable hook records are generated.'}
