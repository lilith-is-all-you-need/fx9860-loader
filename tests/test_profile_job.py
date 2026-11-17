import contextlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('profile_job',ROOT/'tooling/profile_job.py')
job=importlib.util.module_from_spec(spec);spec.loader.exec_module(job)

def image(length=0x260):
    data=bytearray(length);data[:8]=bytes(x^255 for x in b'USBPower')
    data[0x200:0x208]=bytes.fromhex('d103d004412b0009')
    struct.pack_into('>II',data,0x210,0x80010070,0x90f)
    return data

class DesktopJobTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/"测试 O'Brien $sample.g1a";self.source.write_bytes(image())
        self.artifacts=self.root/'artifacts';self.artifacts.mkdir();loader=b'authored launcher fixture'
        (self.artifacts/'FlashLd.g1a').write_bytes(loader)
        (self.artifacts/'manifest.json').write_text(json.dumps({'files':{'FlashLd.g1a':job.suite.sha(loader)}}))

    def generate(self,name='output',**kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return job.generate(self.source,self.root/name,artifacts=self.artifacts,**kwargs)

    def test_complete_bundle_hashes_include_loader_profile_and_image(self):
        r=self.generate();out=self.root/'output'
        self.assertTrue(r['installableCandidate']);self.assertFalse(r['hardwareValidated'])
        self.assertEqual(r['inputName'],self.source.name)
        self.assertEqual((out/'calculator/target.bin').read_bytes(),self.source.read_bytes())
        sums=json.loads((out/'checksums.json').read_text('utf-8'))
        for name in ['calculator/target.bin','calculator/target.fpf','calculator/FlashLd.g1a','paging-plan.json','job-result.json']:
            self.assertEqual(sums[name],job.suite.sha((out/name).read_bytes()))

    def test_513th_page_has_only_one_byte_and_cannot_be_made_runnable(self):
        self.source.write_bytes(image(2097153));r=self.generate()
        p=json.loads((self.root/'output/paging-plan.json').read_text('utf-8'))
        self.assertEqual(p['pageCount'],513);self.assertTrue(p['requiresExtendedRefill'])
        self.assertFalse(p['executableProfile']);self.assertFalse(p['physicalAddressesIncluded'])
        self.assertEqual(p['pages'][-1],{'index':512,'fileOffset':2097152,'virtualAddress':0x500000,'validBytes':1,'outsideOsWindow':True,'sha256':job.suite.sha(b'\0')})
        self.assertFalse(r['installableCandidate']);self.assertFalse((self.root/'output/calculator').exists())

    def test_complete_512_pages_stay_within_window(self):
        self.source.write_bytes(image(2097152));self.generate()
        p=json.loads((self.root/'output/paging-plan.json').read_text('utf-8'))
        self.assertFalse(p['requiresExtendedRefill']);self.assertEqual(p['pages'][-1]['validBytes'],4096)

    def test_missing_deep_dependencies_never_publish_a_calculator_bundle(self):
        r=self.generate(deep=True,ghidra=str(self.root/'absent'),java=str(self.root/'absent-jdk'))
        self.assertEqual(r['status'],'analysis-incomplete');self.assertFalse(r['installableCandidate'])
        self.assertFalse((self.root/'output/calculator').exists())
        self.assertEqual((self.root/'output/original.bin').read_bytes(),self.source.read_bytes())

    def test_headless_success_does_not_bypass_large_runtime_blocker(self):
        self.source.write_bytes(image(2097153))
        with patch.object(job,'ghidra_analyze',return_value={'status':'completed','analysisComplete':True}):r=self.generate(deep=True)
        self.assertEqual(r['status'],'needs-review');self.assertFalse((self.root/'output/calculator').exists())

    def test_partial_analysis_is_not_reported_ready(self):
        with patch.object(job,'ghidra_analyze',return_value={'status':'partial','analysisComplete':False}):r=self.generate(deep=True)
        self.assertEqual(r['status'],'analysis-incomplete');self.assertFalse((self.root/'output/calculator').exists())

    def test_input_change_after_initial_analysis_cannot_change_packaged_bytes(self):
        original=self.source.read_bytes()
        def analyze(*args,**kwargs):
            self.source.write_bytes(b'changed externally')
            return {'status':'completed','analysisComplete':True}
        with patch.object(job,'ghidra_analyze',side_effect=analyze):r=self.generate(deep=True)
        self.assertEqual(r['sha256'],job.suite.sha(original))
        self.assertEqual((self.root/'output/calculator/target.bin').read_bytes(),original)

    def test_existing_result_and_bad_artifact_leave_no_half_bundle(self):
        out=self.root/'output';out.mkdir();(out/'sentinel').write_text('keep')
        with self.assertRaises(FileExistsError):self.generate()
        self.assertEqual((out/'sentinel').read_text(),'keep')
        (self.artifacts/'FlashLd.g1a').write_bytes(b'altered')
        with self.assertRaises(ValueError):self.generate('bad')
        self.assertFalse((self.root/'bad').exists())
        self.assertFalse(list(self.root.glob('.profile-studio-*')))

    def test_invalid_file_and_size_never_publish(self):
        for data in [b'not a G1A',bytearray(4*1024*1024+1)]:
            self.source.write_bytes(data)
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'output').exists())

if __name__=='__main__':unittest.main(verbosity=2)
