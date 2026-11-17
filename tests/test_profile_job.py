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
        (self.artifacts/'manifest.json').write_text(json.dumps({'schemaVersion':2,'bundleFormat':2,'files':{'FlashLd.g1a':job.suite.sha(loader)}}))

    def generate(self,name='output',**kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return job.generate(self.source,self.root/name,artifacts=self.artifacts,**kwargs)

    def test_complete_bundle_hashes_include_loader_profile_and_image(self):
        r=self.generate(include_loader=True);out=self.root/'output'
        self.assertTrue(r['installableCandidate']);self.assertFalse(r['hardwareValidated'])
        self.assertEqual(r['inputName'],self.source.name)
        app='calculator/FXAPPS/'+r['identity']['calculatorId']
        self.assertEqual((out/app/'IMAGE.BIN').read_bytes(),self.source.read_bytes())
        sums=json.loads((out/'checksums.json').read_text('utf-8'))
        for name in [app+'/IMAGE.BIN',app+'/APP.FPF',app+'/APP.MET','calculator/FlashLd.g1a','paging-plan.json','job-result.json']:
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

    def test_missing_optional_dependencies_preserve_valid_bundle(self):
        r=self.generate(deep=True,ghidra=str(self.root/'absent'),java=str(self.root/'absent-jdk'))
        self.assertEqual(r['status'],'program-ready');self.assertEqual(r['deepAnalysis']['status'],'unavailable')
        self.assertTrue(r['programReady']);self.assertTrue((self.root/'output/calculator').exists())
        self.assertEqual((self.root/'output/original.bin').read_bytes(),self.source.read_bytes())

    def test_headless_success_does_not_bypass_large_runtime_blocker(self):
        self.source.write_bytes(image(2097153))
        with patch.object(job,'ghidra_analyze',return_value={'status':'completed','analysisComplete':True}):r=self.generate(deep=True)
        self.assertEqual(r['status'],'needs-adapter');self.assertFalse((self.root/'output/calculator').exists())

    def test_partial_analysis_is_reported_separately_from_package(self):
        with patch.object(job,'ghidra_analyze',return_value={'status':'partial','analysisComplete':False}):r=self.generate(deep=True)
        self.assertEqual(r['status'],'program-ready');self.assertEqual(r['deepAnalysis']['status'],'partial')
        self.assertTrue((self.root/'output/calculator').exists())

    def test_distinct_blockers_include_offsets_and_actions_in_both_languages(self):
        data=image()
        struct.pack_into('>I',data,0x250,0x80010070)
        self.source.write_bytes(data)
        r=self.generate('unknown')
        d,=r['diagnostics']
        self.assertEqual(d['code'],'unknown-gate-use')
        self.assertIn('0x250',d['reasonZh']);self.assertTrue(d['nextEn'])
        data=image()
        data[0x220:0x226]=bytes.fromhex('d103412b0009')
        struct.pack_into('>I',data,0x230,0xa0000000)
        self.source.write_bytes(data)
        r=self.generate('direct')
        d,=r['diagnostics']
        self.assertEqual(d['code'],'direct-reset-transfer');self.assertIn('0x220',d['reasonEn'])
        self.assertEqual(d['evidence']['transfers'][0]['literalOffset'],0x230)
        self.assertFalse(r['programReady'])
        self.assertIn(d['reasonZh'],(Path(r['output'])/'阅读说明.txt').read_text('utf-8-sig'))
        job.attach_ghidra_refs([d],{'candidateLiteralPools':[{'offset':0x230,'references':[{'from':'00300220'}]}],
                                    'controlFlowSites':[{'fileOffset':0x222,'instruction':'jmp @r1','recoveredTargets':['a0000000']}]})
        self.assertIn('1 条控制流记录',d['reasonZh'])
        self.assertEqual(d['evidence']['ghidraControlFlow'][0]['fileOffset'],0x222)

    def test_signature_inspection_remains_outside_generic_call_profile(self):
        data=image(0x300)
        data[0x240:0x25a]=bytes.fromhex('d70f 4f22 7ff4 0009 6270 4118 622c 4310 7701 8ff9 212b d20b 3120')
        struct.pack_into('>II',data,0x280,0x80010070,0xd2024008)
        self.source.write_bytes(data)
        d,=self.generate()['diagnostics']
        self.assertEqual(d['code'],'rom-signature-read')
        self.assertIn('0x240',d['reasonZh']);self.assertIn('0x280',d['reasonEn'])

    def test_same_root_preserves_basic_and_deep_reports_and_can_retry_failed_analysis(self):
        data=image();struct.pack_into('>I',data,0x250,0x80010070);self.source.write_bytes(data)
        root=self.root/'results'
        def complete(source,directory,*args):
            directory.mkdir()
            pools=[{'offset':0x250,'references':[{'from':'00300208'}]}]
            job.write(directory/'evidence.json',{'inputSha256':job.suite.sha(data),'analysisComplete':True,
                         'imageBase':0x300000,'entry':0x300200,'imageBytes':len(data),'candidateLiteralPools':pools})
            return {'status':'completed'}
        with contextlib.redirect_stdout(io.StringIO()):
            basic=job.generate(self.source,output_root=root)
            again=job.generate(self.source,output_root=root)
            failed=job.generate(self.source,output_root=root,deep=True)
            with patch.object(job,'ghidra_analyze',side_effect=complete) as analyze:
                success=job.generate(self.source,output_root=root,deep=True)
                reused=job.generate(self.source,output_root=root,deep=True)
                self.assertEqual(analyze.call_count,1)
        self.assertTrue(again['reused']);self.assertTrue(reused['reused'])
        self.assertEqual(success['output'],reused['output']);self.assertFalse(success['programReady'])
        self.assertIn('1 条引用',success['diagnostics'][0]['reasonZh'])
        self.assertEqual(failed['output'],basic['output']+'-deep')
        self.assertEqual(success['output'],basic['output']+'-deep-2')

    def test_input_change_after_initial_analysis_cannot_change_packaged_bytes(self):
        original=self.source.read_bytes()
        def analyze(*args,**kwargs):
            self.source.write_bytes(b'changed externally')
            return {'status':'completed','analysisComplete':True}
        with patch.object(job,'ghidra_analyze',side_effect=analyze):r=self.generate(deep=True)
        self.assertEqual(r['sha256'],job.suite.sha(original))
        self.assertEqual((self.root/'output/calculator/FXAPPS'/r['identity']['calculatorId']/'IMAGE.BIN').read_bytes(),original)

    def test_existing_result_and_bad_artifact_leave_no_half_bundle(self):
        out=self.root/'output';out.mkdir();(out/'sentinel').write_text('keep')
        with self.assertRaises(FileExistsError):self.generate()
        self.assertEqual((out/'sentinel').read_text(),'keep')
        (self.artifacts/'FlashLd.g1a').write_bytes(b'altered')
        with self.assertRaises(ValueError):self.generate('bad',include_loader=True)
        self.assertFalse((self.root/'bad').exists())
        self.assertFalse(list(self.root.glob('.profile-studio-*')))

    def test_default_exports_only_program_and_zero_untrusted_cache(self):
        r=self.generate();out=self.root/'output'
        self.assertEqual(r['status'],'program-ready');self.assertTrue(r['programReady'])
        self.assertFalse(r['includesLoader']);self.assertFalse(r['installableCandidate'])
        self.assertFalse((out/'calculator/FlashLd.g1a').exists())
        app=out/'calculator/FXAPPS'/r['identity']['calculatorId']
        self.assertEqual(len((app/'APP.MET').read_bytes()),64)
        self.assertEqual((app/'VERIFY.CCH').read_bytes(),bytes(4096))
        self.assertEqual((app/'IMAGE.BIN').read_bytes(),self.source.read_bytes())

    def test_stable_identity_reuses_verified_result_and_preserves_existing_files(self):
        with contextlib.redirect_stdout(io.StringIO()):
            first=job.generate(self.source,output_root=self.root/'stable')
            second=job.generate(self.source,output_root=self.root/'stable')
        self.assertEqual(first['output'],second['output']);self.assertTrue(second['reused'])
        self.assertIn(first['sha256'][:10],Path(first['output']).name)
        with self.assertRaises(FileExistsError),contextlib.redirect_stdout(io.StringIO()):
            job.generate(self.source,output_root=self.root/'stable',include_loader=True,artifacts=self.artifacts)
        app=Path(first['output'])/'calculator/FXAPPS'/first['identity']['calculatorId']
        (app/'RUN.LOG').write_bytes(b'new device results')
        with self.assertRaises(ValueError),contextlib.redirect_stdout(io.StringIO()):
            job.generate(self.source,output_root=self.root/'stable')
        self.assertEqual((app/'RUN.LOG').read_bytes(),b'new device results')

    def test_moved_result_returns_its_current_directory(self):
        with contextlib.redirect_stdout(io.StringIO()):
            first=job.generate(self.source,output_root=self.root/'stable')
            (self.root/'stable').rename(self.root/'moved')
            second=job.generate(self.source,output_root=self.root/'moved')
        self.assertTrue(second['reused']);self.assertEqual(Path(second['output']).parent,(self.root/'moved').resolve())
        self.assertTrue(Path(second['output']).is_dir());self.assertFalse(Path(first['output']).exists())

    def test_new_blocker_cannot_be_bypassed_by_old_ready_result(self):
        with contextlib.redirect_stdout(io.StringIO()):job.generate(self.source,output_root=self.root/'stable')
        original=job.suite.analyze
        def blocked(*args,**kwargs):
            data,report=original(*args,**kwargs);report['status']='needs-review';report['blockers'].append('new rejection')
            return data,report
        with patch.object(job.suite,'analyze',side_effect=blocked),contextlib.redirect_stdout(io.StringIO()),self.assertRaises(FileExistsError):
            job.generate(self.source,output_root=self.root/'stable')

    def test_empty_checksum_manifest_cannot_hide_missing_profile(self):
        with contextlib.redirect_stdout(io.StringIO()):r=job.generate(self.source,output_root=self.root/'stable')
        output=Path(r['output']);app=output/'calculator/FXAPPS'/r['identity']['calculatorId']
        (app/'APP.FPF').unlink();(output/'checksums.json').write_text('{}')
        with self.assertRaises(ValueError),contextlib.redirect_stdout(io.StringIO()):
            job.generate(self.source,output_root=self.root/'stable')

    def test_modified_profile_cannot_be_reapproved_with_updated_checksum(self):
        with contextlib.redirect_stdout(io.StringIO()):r=job.generate(self.source,output_root=self.root/'stable')
        output=Path(r['output']);name='calculator/FXAPPS/'+r['identity']['calculatorId']+'/APP.FPF'
        profile=bytearray((output/name).read_bytes());profile[-1]=1;(output/name).write_bytes(profile)
        sums=json.loads((output/'checksums.json').read_text(encoding='utf-8'));sums[name]=job.suite.sha(profile)
        (output/'checksums.json').write_text(json.dumps(sums))
        with self.assertRaises(ValueError),contextlib.redirect_stdout(io.StringIO()):
            job.generate(self.source,output_root=self.root/'stable')

    def test_independent_loader_export_needs_no_input_and_checks_manifest(self):
        r=job.bundle_v2.export_loaders(self.root/'loaders',self.artifacts,'flash')
        self.assertEqual(r['status'],'loader-exported')
        self.assertEqual((self.root/'loaders/FlashLd.g1a').read_bytes(),(self.artifacts/'FlashLd.g1a').read_bytes())
        with self.assertRaises(FileExistsError):job.bundle_v2.export_loaders(self.root/'loaders',self.artifacts,'flash')
        (self.artifacts/'FlashLd.g1a').write_bytes(b'tampered')
        with self.assertRaises(ValueError):job.bundle_v2.export_loaders(self.root/'other',self.artifacts,'flash')
        self.assertFalse((self.root/'other').exists())

    def test_legacy_launcher_manifest_cannot_claim_folder_support(self):
        manifest=self.artifacts/'manifest.json'
        data=json.loads(manifest.read_text());data.pop('bundleFormat');manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'predates'):self.generate(include_loader=True)
        self.assertFalse((self.root/'output').exists())

    def test_source_integrated_profiles_follow_actual_size_not_699(self):
        import ext_profile
        for count,tail in [(1,516),(512,4096),(513,1),(699,228),(720,17)]:
            size=(count-1)*4096+tail
            data=ext_profile.wrap_raw(bytes(size-512));self.source.write_bytes(data)
            r=self.generate('source-'+str(count));out=Path(r['output'])
            self.assertEqual(r['status'],'program-ready');self.assertEqual(r['pages'],count)
            app=out/'calculator/FXAPPS'/r['identity']['calculatorId']
            p=ext_profile.decode_profile((app/'EXT.PRF').read_bytes())
            self.assertEqual(p['pageCount'],count);self.assertEqual(p['pageCapacity'],(count+15)//16*16)
            self.assertEqual(p['imageBytes'],size);self.assertEqual(p['sha256'],job.suite.sha(data))
            self.assertFalse(r['hardwareValidated'])

    def test_source_abi_and_budget_rejection_do_not_publish(self):
        import ext_profile
        bad=bytearray(ext_profile.wrap_raw(bytes(4096)));bad[16:20]=struct.pack('>I',99)
        for data in (bad, ext_profile.wrap_raw(bytes(3_000_000-512))):
            self.source.write_bytes(data)
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'output').exists())

    def test_invalid_file_and_size_never_publish(self):
        for data in [b'not a G1A',bytearray(4*1024*1024+1)]:
            self.source.write_bytes(data)
            with self.assertRaises(ValueError):self.generate()
            self.assertFalse((self.root/'output').exists())

if __name__=='__main__':unittest.main(verbosity=2)
