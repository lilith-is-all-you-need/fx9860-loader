import importlib.util
from pathlib import Path
import hashlib
import unittest

spec=importlib.util.spec_from_file_location('hook_review',Path(__file__).resolve().parents[1]/'tooling/hook_review.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

class HookEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.image=bytes(512)+bytes.fromhex('402e0009')
        self.site={'fileOffset':512,'address':'00300200','originalBytes':'402e','instruction':'ldc r0,vbr','delaySlotDepth':0,'inDelaySlot':False}
        self.evidence={'inputSha256':hashlib.sha256(self.image).hexdigest(),'imageBytes':len(self.image),
                       'imageBase':0x300000,'entry':0x300200,'analysisComplete':True,'exceptionOwnershipSites':[self.site]}
    def test_matching_evidence_cannot_authorize_a_hook(self):
        r=mod.review(self.image,self.evidence)
        self.assertEqual(r['evidenceByteChecks'],1);self.assertFalse(r['executableProfile'])
        self.assertEqual(r['status'],'runtime-adapter-required')
    def test_mismatched_image_and_sites_are_rejected(self):
        for field,value in [('inputSha256','0'*64),('imageBytes',999),('imageBase',0x300200)]:
            with self.subTest(field=field),self.assertRaises(ValueError):mod.review(self.image,{**self.evidence,field:value})
        for field,value in [('fileOffset',513),('fileOffset',True),('originalBytes','ffff'),('originalBytes','zz'),('address','00300400')]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                mod.review(self.image,{**self.evidence,'exceptionOwnershipSites':[{**self.site,field:value}]})
