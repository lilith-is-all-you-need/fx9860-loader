"""Profile generation tests use authored machine code, never shipped games."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from prepare import prepare, profile
from fixtures import authored_target

class ProfileTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.item=authored_target(self.root/'source.g1a')
        self.data=Path(self.item['source']).read_bytes()

    def test_exact_bin_and_gate_evidence(self):
        reports=prepare([self.item],self.root/'bundle')
        self.assertEqual((self.root/'bundle/fixture.bin').read_bytes(),self.data)
        self.assertEqual([p['offset'] for p in reports[0]['patches']],[0x24c])
        p=(self.root/'bundle/fixture.lpf').read_bytes()
        self.assertEqual(len(p),384)
        self.assertEqual(p[32:64],hashlib.sha256(self.data).digest())
        self.assertEqual(len((self.root/'bundle/Loader.idx').read_bytes()),204)

    def test_unknown_gate_is_rejected(self):
        data=bytearray(self.data);struct.pack_into('>I',data,0x214,0x80010070)
        with self.assertRaisesRegex(ValueError,'unclassified'):profile(data)

    def test_gate_number_is_not_relocated(self):
        data=bytearray(self.data);struct.pack_into('>I',data,0x250,0x00301234)
        packed,report=profile(data)
        self.assertEqual(len(report['patches']),1)
        self.assertEqual(report['patches'][0]['evidence'][0]['number'],0x00301234)
        self.assertEqual(struct.unpack_from('>I',packed,128)[0],0x24c)

    def test_invalid_identity_or_hash_does_not_publish(self):
        for updates in ({'id':'../bad'},{'expectedSha256':'00'*32}):
            with self.subTest(updates=updates),self.assertRaises(ValueError):
                prepare([{**self.item,**updates}],self.root/'rejected')
            self.assertFalse((self.root/'rejected/Loader.idx').exists())

    def test_conflicting_existing_bin_is_preserved(self):
        out=self.root/'bundle';out.mkdir();p=out/'fixture.bin';p.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):prepare([self.item],out)
        self.assertEqual(p.read_bytes(),b'keep')

    def test_duplicate_ids_do_not_publish(self):
        with self.assertRaises(ValueError):prepare([self.item,self.item],self.root/'duplicate')
        self.assertFalse((self.root/'duplicate/fixture.bin').exists())

    def test_invalid_forbidden_ranges(self):
        for r in ([0x88050000,0x88040000],[0x300000,0x400000],[0x88040000,0xa0000000]):
            with self.subTest(range=r),self.assertRaises(ValueError):profile(self.data,[r])

    def test_direct_boot_jump_requires_adapter(self):
        data=bytearray(self.data)+bytes.fromhex('d001402b00090009a0000000')
        _,report=profile(data)
        self.assertEqual(report['unadaptedControlTransfers'][0]['instructionOffset'],0x254)
        self.assertEqual(report['unadaptedControlTransfers'][0]['destination'],0xa0000000)

if __name__=='__main__':unittest.main(verbosity=2)
