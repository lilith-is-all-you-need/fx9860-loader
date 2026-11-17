from pathlib import Path
import hashlib,json,struct,sys
def make(folder):
 data=bytearray()
 for p in range(698):
  block=bytearray((p*37+i*13+(i>>8))&255 for i in range(4096))
  block[:8]=b'MAP698PG';struct.pack_into('>I',block,8,p)
  block[32:44]=bytes.fromhex('d001000b00090000')+struct.pack('>I',0x69800000|p)
  block[64:76]=bytes.fromhex('d101412b00090000')+struct.pack('>I',0x300000+((p+349)%698)*4096+32)
  data+=block
 data=data[:2857444];folder.mkdir(parents=True,exist_ok=True)
 (folder/'Map698.bin').write_bytes(data)
 (folder/'Map698.cfg').write_bytes(b'M\n')
 (folder/'Map698.txt').write_bytes(b' '*2048)
 (folder/'payload.json').write_text(json.dumps({'bytes':len(data),'pages':698,'lastPageBytes':len(data)%4096,'sha256':hashlib.sha256(data).hexdigest(),'mathKernelExecuted':False},indent=2))
if __name__=='__main__':make(Path(sys.argv[1]))
