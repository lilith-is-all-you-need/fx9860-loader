"""Structural acceptance has no program whitelist; rejected input is not published."""
import importlib.util,json,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from test_loader_suite import suite,fixture

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('flash_prepare',ROOT/'probes/storage-loader/tools/prepare.py')
flash=importlib.util.module_from_spec(spec);spec.loader.exec_module(flash)

class FlashProfiles(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.src=self.root/'new-name.g1a';self.src.write_bytes(fixture())
  self.art=self.root/'artifacts';self.art.mkdir();binary=b'authored loader artifact'
  (self.art/'FlashLd.g1a').write_bytes(binary)
  (self.art/'manifest.json').write_text(json.dumps({'files':{'FlashLd.g1a':suite.sha(binary)}}))

 def test_unknown_hashes_and_names_get_complete_generic_bundle(self):
  for value in [17,83,199]:
   data=fixture();data[-1]=value;self.src.write_bytes(data)
   out=self.root/str(value);r=suite.prepare(self.src,out,artifacts=self.art)
   self.assertEqual((r['status'],r['backend'],r['hardwareValidated']),('candidate','flash',False))
   self.assertIsNone(r['approvedProfile']);self.assertFalse(r['programWhitelist'])
   self.assertEqual((out/'calculator/target.bin').read_bytes(),data)
   pf=(out/'calculator/target.fpf').read_bytes()
   self.assertEqual((pf[:8],len(pf),struct.unpack_from('>I',pf,20)[0]),(b'FXLDF001',384,2))
   self.assertEqual((out/'calculator/FlashLd.txt').stat().st_size,4096)

 def test_ram_rejection_is_not_misreported_as_flash_hardware_evidence(self):
  old=suite.read_json
  def read(path):
   return {'programs':[{'sha256':suite.sha(self.src.read_bytes()),'adapter':'ram-v1','blocked':'old RAM allocation failed','hardwareEvidence':{'firstLaunch':'failed'}}]} if Path(path)==ROOT/'profiles/registry.json' else old(path)
  with patch.object(suite,'read_json',side_effect=read):r=suite.prepare(self.src,self.root/'fresh',artifacts=self.art)
  self.assertEqual(r['status'],'candidate');self.assertNotIn('hardwareEvidence',r)
  self.assertEqual(r['priorBackendEvidence']['adapter'],'ram-v1')

 def test_cache_color_span_comes_from_gate_pages(self):
  data=bytearray(0x5100);data[:8]=fixture()[:8]
  for off in [0x1200,0x2200,0x4200]:
   data[off:off+8]=bytes.fromhex('d103d004412b0009')
   struct.pack_into('>II',data,off+16,0x80010070,0x90f)
  _,r=flash.profile(data)
  self.assertEqual(r['shadowPages'],[1,2,4]);self.assertEqual(r['shadowSpanBytes'],4*4096)
  self.assertEqual(r['shadowAlignmentAllowance'],4095)
  self.assertEqual(r['imageCopyBytes'],0)

 def test_rejected_catalog_does_not_leave_partial_files(self):
  good={'id':'a','title':'A','source':str(self.src)}
  for bad in [{**good,'id':'../bad'},{**good,'expectedSha256':'0'*64},good]:
   out=self.root/'bad'
   with self.assertRaises(ValueError):flash.prepare([good,bad],out)
   self.assertFalse(out.exists())

 def test_direct_reset_cannot_be_automatically_accepted(self):
  data=fixture();data[0x230:0x238]=bytes.fromhex('d101412b00090009')
  struct.pack_into('>I',data,0x238,0xa0000000);self.src.write_bytes(data)
  r=suite.prepare(self.src,self.root/'reset',artifacts=self.art)
  self.assertEqual(r['status'],'needs-review');self.assertFalse((self.root/'reset/calculator').exists())

 def test_wrong_loader_hash_never_publishes(self):
  (self.art/'FlashLd.g1a').write_bytes(b'changed')
  with self.assertRaises(ValueError):suite.prepare(self.src,self.root/'bad',artifacts=self.art)
  self.assertFalse((self.root/'bad').exists())

if __name__=='__main__':unittest.main(verbosity=2)
