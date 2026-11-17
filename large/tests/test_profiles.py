import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tooling"))
from ext_profile import encode_profile,decode_profile,wrap_raw,inspect_image,prepare
from hook_review import review
from sync_sample_library import sync

class Profiles(unittest.TestCase):
    def image(self,size):
        return wrap_raw(b"\0\x09"*((size-512)//2)+b"\0"*((size-512)%2))
    def test_page_boundaries_and_spare_capacity(self):
        for size in (516,4095,4096,4097,0x1fffff,0x200000,0x200001,2859236,2990000):
            with self.subTest(size=size):
                image=self.image(size);p=decode_profile(encode_profile(image))
                self.assertEqual(len(image),size)
                self.assertEqual(p["pageCount"],(size+4095)//4096)
                self.assertEqual(p["pageCapacity"]%16,0)
                self.assertGreaterEqual(p["pageCapacity"],p["pageCount"])
                self.assertEqual(p["sha256"],hashlib.sha256(image).hexdigest())
    def test_capacity_does_not_expand_valid_image(self):
        image=self.image(4097);p=decode_profile(encode_profile(image,capacity=768))
        self.assertEqual((p["imageBytes"],p["pageCount"],p["pageCapacity"]),(4097,2,768))
        for capacity in (0,1,769):
            with self.assertRaises(ValueError):encode_profile(image,capacity=capacity)
    def test_storage_is_independent_from_page_capacity(self):
        with self.assertRaisesRegex(ValueError,"storage"):
            encode_profile(self.image(3_000_000),capacity=736)
        with self.assertRaisesRegex(ValueError,"window"):
            encode_profile(self.image(768*4096+1))
    def test_unknown_binary_and_false_header_rejected(self):
        for image in (bytes(600),b"G1A"+bytes(1000)):
            with self.assertRaises(ValueError):inspect_image(image)
        image=bytearray(self.image(600));struct.pack_into(">I",image,28,2)
        with self.assertRaises(ValueError):inspect_image(bytes(image))
    def test_profile_rejects_hooks_overflow_and_malformed(self):
        original=encode_profile(self.image(4097))
        for offset,value in ((8,3),(12,0xffffffff),(16,0),(20,0x300201),(24,1),(28,769),(32,2),(36,2),(40,0xffffffff),(44,0xffffffff),(80,1),(124,1)):
            p=bytearray(original);struct.pack_into(">I",p,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):decode_profile(bytes(p))
        for p in (original[:-1],original+b"\0",b"invalid!"+original[8:]):
            with self.assertRaises(ValueError):decode_profile(p)
    def test_prepare_idempotent_no_destructive_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);source=p/"source.bin";source.write_bytes(self.image(4101))
            prepare(source,p/"app");prepare(source,p/"app")
            source.write_bytes(self.image(4102))
            with self.assertRaises(FileExistsError):prepare(source,p/"app")
    def test_profile_only_conflict_does_not_create_partial_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);source=p/"source.bin";source.write_bytes(self.image(4101))
            out=p/"app";out.mkdir();(out/"EXT.PRF").write_bytes(b"existing")
            before={f.name:f.read_bytes() for f in out.iterdir()}
            with self.assertRaises(FileExistsError):prepare(source,out)
            self.assertEqual(before,{f.name:f.read_bytes() for f in out.iterdir()})
    def test_header_lengths_and_sample_snapshots(self):
        self.assertEqual(self.image(600)[:16],b"FXLARGE-PAYLOAD1")
        self.assertEqual(struct.unpack_from(">5I",self.image(600),16),(1,0x300200,88,1,1))
        sync(check=True)

class Hooks(unittest.TestCase):
    def evidence(self,image):
        return {"imageSha256":hashlib.sha256(image).hexdigest(),"architecture":"SuperH4-BE-32",
          "hooks":[{"kind":"vbr-write","fileOffset":512,"virtualAddress":0x300200,
                    "expectedHex":"402e0009","delaySlotIncluded":True,
                    "callingConvention":"SH bank 1, BL=1","registerPreservation":"r0-r7 bank, PR, MACH, MACL, GBR"}],
          "exceptionContract":{k:"explicit reviewer assertion" for k in
             ("vbrOwner","residentHandlerRange","previousHandlerChain","restoreOrder","unwindFailure")}}
    def test_evidence_never_implies_runnable(self):
        image=wrap_raw(bytes.fromhex("402e0009"));e=self.evidence(image)
        result=review(image,e);self.assertFalse(result["runnable"])
        self.assertIn("tlb-handler",result["missingKinds"])
        e["hooks"][0]["expectedHex"]="002b0009"
        with self.assertRaises(ValueError):review(image,e)
    def test_hash_and_exception_contract_are_required(self):
        image=wrap_raw(bytes.fromhex("402e0009"));e=self.evidence(image)
        with self.assertRaises(ValueError):review(image+b"\0",e)
        del e["exceptionContract"]["restoreOrder"]
        with self.assertRaises(ValueError):review(image,e)

if __name__=="__main__":unittest.main()
