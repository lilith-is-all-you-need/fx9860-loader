import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('loader_suite',ROOT/'tooling/loader_suite.py')
suite=importlib.util.module_from_spec(spec);spec.loader.exec_module(suite)

def fixture():
    b=bytearray(0x260);b[:8]=bytes(x^255 for x in b'USBPower')
    b[0x200:0x208]=bytes.fromhex('d103d004412b0009')
    struct.pack_into('>II',b,0x210,0x80010070,0x90f)
    return b

class SuiteTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.src=self.root/'sample.g1a';self.src.write_bytes(fixture())
        self.review={'schemaVersion':1,'sha256':suite.sha(self.src.read_bytes()),'backend':'ram',
                     'memoryReviewed':True,'callbacksReviewed':True,'forbiddenPhysicalRam':[]}

    def test_reviewed_khicas_uses_flash_unless_legacy_adapter_is_requested(self):
        image = self.src.read_bytes()
        registry = {'programs': [{'sha256': suite.sha(image), 'adapter': 'mapped-khicas-v1',
                                  'hardwareEvidence': {'firstLaunch': 'legacy-only'}}]}
        with patch.object(suite, 'read_json', return_value=registry):
            _, auto = suite.analyze(self.src)
            _, flash = suite.analyze(self.src, 'flash')
            _, legacy = suite.analyze(self.src, 'mapped')
        self.assertEqual(auto, flash)
        self.assertEqual((auto['backend'], auto['status']), ('flash', 'candidate'))
        self.assertIsNone(auto['approvedProfile'])
        self.assertNotIn('priorBackendEvidence', auto)
        self.assertEqual((legacy['backend'], legacy['status']), ('mapped', 'candidate'))
        self.assertEqual(legacy['hardwareEvidence']['firstLaunch'], 'legacy-only')

    def test_unknown_small_keeps_image_without_claiming_compatibility(self):
        out=self.root/'out';r=suite.prepare(self.src,out,artifacts=self.root/'missing')
        self.assertEqual(r['status'],'profile-only')
        self.assertEqual((out/'original.bin').read_bytes(),self.src.read_bytes())
        self.assertEqual((out/'calculator/target.bin').read_bytes(),self.src.read_bytes())
        self.assertEqual((out/'calculator/target.fpf').read_bytes()[:8],b'FXLDF001')
        self.assertFalse(r['programWhitelist'])
        self.assertFalse(r['hardwareValidated'])
        self.assertEqual(r['requiredContiguousImageBytes'],0)

    def test_hardware_block_cannot_be_overridden_by_static_review(self):
        profile={'sha256':suite.sha(self.src.read_bytes()),'adapter':'ram-v1',
                 'blocked':'Real device rejected image allocation',
                 'hardwareEvidence':{'firstLaunch':'rejected-before-target'}}
        original=suite.read_json
        def read(path):
            return {'programs':[profile]} if Path(path)==suite.ROOT/'profiles/registry.json' else original(path)
        with patch.object(suite,'read_json',side_effect=read):
            report=suite.prepare(self.src,self.root/'blocked',requested='ram',review=self.review)
        self.assertEqual(report['status'],'needs-review')
        self.assertIn(profile['blocked'],report['blockers'])
        self.assertEqual(report['hardwareEvidence'],profile['hardwareEvidence'])
        self.assertFalse((self.root/'blocked/calculator').exists())

    def test_review_bound_to_bytes_and_backend(self):
        for change in ({'sha256':'0'*64},{'backend':'mapped'},{'memoryReviewed':False}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                suite.prepare(self.src,self.root/'rejected',requested='ram',review={**self.review,**change})
            self.assertFalse((self.root/'rejected').exists())

    def test_complete_candidate_has_paired_files(self):
        artifacts=self.root/'artifacts';artifacts.mkdir();binary=b'authored loader test fixture'
        (artifacts/'Loader.g1a').write_bytes(binary)
        (artifacts/'manifest.json').write_text(json.dumps({'files':{'Loader.g1a':suite.sha(binary)}}))
        r=suite.prepare(self.src,self.root/'ready',requested='ram',review=self.review,artifacts=artifacts)
        self.assertEqual(r['status'],'candidate')
        self.assertEqual((self.root/'ready/calculator/target.bin').read_bytes(),self.src.read_bytes())
        self.assertEqual(len((self.root/'ready/calculator/target.lpf').read_bytes()),384)
        self.assertEqual(len((self.root/'ready/calculator/Loader.idx').read_bytes()),204)

    def test_missing_artifact_is_not_installable(self):
        r=suite.prepare(self.src,self.root/'out',requested='ram',review=self.review,artifacts=self.root/'missing')
        self.assertEqual(r['status'],'profile-only')

    def test_bad_artifact_does_not_publish(self):
        artifacts=self.root/'artifacts';artifacts.mkdir();(artifacts/'Loader.g1a').write_bytes(b'x')
        (artifacts/'manifest.json').write_text('{"files":{"Loader.g1a":"wrong"}}')
        with self.assertRaises(ValueError):suite.prepare(self.src,self.root/'bad',requested='ram',review=self.review,artifacts=artifacts)
        self.assertFalse((self.root/'bad').exists())

    def test_size_boundaries_and_tail_hash(self):
        for size,backend in [(163840,'flash'),(163841,'flash'),(2097152,'flash'),(2097153,'extended'),(2857444,'extended')]:
            with self.subTest(size=size):
                data=fixture()+bytearray(size-len(fixture()));self.src.write_bytes(data)
                _,r=suite.analyze(self.src)
                self.assertEqual(r['backend'],backend)
                self.assertEqual(len(r['pageHashes']),(size+4095)//4096)
                self.assertEqual(r['pageHashes'][-1],suite.sha(data[((size-1)//4096)*4096:]))
                self.assertEqual(r['lastPageBytes'],size%4096 or 4096)

    def test_forced_wrong_backend_and_overwrite_rejected(self):
        with self.assertRaises(ValueError):suite.prepare(self.src,self.root/'bad',requested='extended')
        out=self.root/'keep';out.mkdir();(out/'sentinel').write_text('keep')
        with self.assertRaises(FileExistsError):suite.prepare(self.src,out)
        self.assertEqual((out/'sentinel').read_text(),'keep')

    def test_unrecognized_literals_block_even_reviewed_image(self):
        b=fixture();struct.pack_into('>I',b,0x250,0x80010070);self.src.write_bytes(b)
        r=suite.prepare(self.src,self.root/'out',requested='ram',review={**self.review,'sha256':suite.sha(b)})
        self.assertEqual(r['status'],'needs-review')
        self.assertFalse((self.root/'out/calculator').exists())

    def test_private_payload_requires_exact_registered_runtime(self):
        data=bytearray(2097153);data[:16]=b'KHICAS-MAPPED/1\0';self.src.write_bytes(data)
        with self.assertRaises(ValueError):suite.analyze(self.src)
        profile={'sha256':suite.sha(data),'adapter':'extended-giac-v1','limitations':['hardware pending'],'launcherSha256':suite.sha(b'paired launcher')}
        original=suite.read_json
        def read(path):
            return {'programs':[profile]} if Path(path)==suite.ROOT/'profiles/registry.json' else original(path)
        import ext_profile
        with patch.object(suite,'read_json',side_effect=read), patch.object(ext_profile,'LEGACY_SHA256',suite.sha(data)):
            r=suite.prepare(self.src,self.root/'extended',artifacts=self.root/'missing')
            self.assertEqual(r['status'],'profile-only')
            self.assertEqual((self.root/'extended/calculator/KHICAS.BIN').read_bytes(),data)
            artifacts=self.root/'artifacts';artifacts.mkdir();bad=b'wrong paired launcher'
            (artifacts/'KhiMap.g1a').write_bytes(bad)
            (artifacts/'manifest.json').write_text(json.dumps({'files':{'KhiMap.g1a':suite.sha(bad)}}))
            with self.assertRaisesRegex(ValueError,'reviewed source-integrated'):
                suite.prepare(self.src,self.root/'rejected',artifacts=artifacts)
            self.assertFalse((self.root/'rejected').exists())

if __name__=='__main__':unittest.main(verbosity=2)
