"""Boundary and branch-target checks for the authored oversized probe image."""
import struct,tempfile,unittest
from pathlib import Path
from bundle import make

class PayloadTests(unittest.TestCase):
    def test_every_page_and_cross_page_branch(self):
        with tempfile.TemporaryDirectory() as t:
            make(Path(t));b=(Path(t)/'Map698.bin').read_bytes()
            self.assertEqual(len(b),2857444)
            self.assertEqual(len(b)%4096,2532)
            for p in range(698):
                at=p*4096
                self.assertEqual(b[at:at+8],b'MAP698PG')
                self.assertEqual(struct.unpack_from('>I',b,at+8)[0],p)
                self.assertEqual(struct.unpack_from('>I',b,at+40)[0],0x69800000|p)
                dest=struct.unpack_from('>I',b,at+72)[0]-0x300000
                self.assertEqual(dest,((p+349)%698)*4096+32)
                self.assertLess(dest+12,len(b))

if __name__=='__main__':unittest.main(verbosity=2)
