"""Authored fixture; independent of the emulator and external games."""
import hashlib
import struct

def authored_target(path):
    data=bytearray(0x254)
    data[:9]=bytes.fromhex('aaacbdaf90889a8d0c')
    data[0x200:0x212]=bytes.fromhex('4f22d407d108410b0009e02a4f26000b0009')
    struct.pack_into('>I',data,0x220,0x300230)
    struct.pack_into('>I',data,0x228,0x300240)
    data[0x230:0x23c]=bytes.fromhex('e001d1022102000b00090009')
    struct.pack_into('>I',data,0x23c,0x08100004)
    data[0x240:0x248]=bytes.fromhex('d102d003412b0009')
    struct.pack_into('>II',data,0x24c,0x80010070,0x494)
    path.write_bytes(data)
    return {'id':'fixture','title':'Return test','source':str(path),
            'expectedSha256':hashlib.sha256(data).hexdigest()}
