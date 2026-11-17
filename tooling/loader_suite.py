"""Offline G1A analysis and SHA-bound bundle preparation. Python standard library only.

No LLM, network, original-image relocation, or executable profile plugins.
Ordinary images use a generic Flash backend without a program whitelist.
Structural acceptance is not proof of memory coexistence or stability.
All output directories must be new.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tooling'))
RAM_LIMIT = 160 * 1024
OS_LIMIT = 2 * 1024 * 1024
ANALYSIS_LIMIT = 4 * 1024 * 1024


def module(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def analyze(source, requested='auto', review=None):
    source = Path(source)
    # Bound both the allocation and scan work before reading untrusted files.
    size = source.stat().st_size
    if not 516 <= size <= ANALYSIS_LIMIT:
        raise ValueError('G1A must be 516 bytes through 4 MiB for this analyzer')
    with source.open('rb') as stream:
        data = stream.read(ANALYSIS_LIMIT + 1)
    size = len(data)
    if not 516 <= size <= ANALYSIS_LIMIT:
        raise ValueError('Image changed size or exceeds analysis limit')
    digest = sha(data)
    registry = read_json(ROOT / 'profiles/registry.json')
    approved = next((x for x in registry['programs'] if x['sha256'] == digest), None)
    source_runtime = approved and approved.get('adapter') == 'extended-giac-v1'
    source_contract = None
    if data[:16] == b'FXLARGE-PAYLOAD1' or source_runtime:
        from ext_profile import inspect_image, encode_profile
        source_contract = inspect_image(data)
        source_runtime = True
        # Reject impossible table/storage budgets before generating any files.
        encode_profile(data)
    if bytes(x ^ 255 for x in data[:8]) != b'USBPower':
        if not source_runtime:
            raise ValueError('Not a G1A or a registered source-integrated payload')
    backend = ('extended' if source_runtime or size > OS_LIMIT else
               'mapped' if approved and approved.get('adapter') == 'mapped-khicas-v1' else 'flash')
    if requested != 'auto':
        if requested not in ('flash','ram','mapped','extended') or (requested == 'ram' and size > RAM_LIMIT) or (requested in ('flash','mapped') and size > OS_LIMIT) or (requested == 'extended' and size <= OS_LIMIT and not source_runtime) or (source_runtime and requested != 'extended'):
            raise ValueError(f'{size} bytes cannot use {requested}')
        backend = requested
    report = {'schemaVersion': 1, 'inputName': source.name, 'sha256': digest,
              'bytes': size, 'pages': (size + 4095) // 4096,
              'lastPageBytes': size % 4096 or 4096, 'backend': backend,
              'entry': 0x300200, 'imageBase': 0x300000, 'imageUnchanged': True,
              'status': 'needs-review', 'hardwareValidated': False,
              'blockers': [], 'warnings': [], 'approvedProfile': approved,
              'pageHashes': [sha(data[o:o+4096]) for o in range(0, size, 4096)]}
    if source_contract:
        report['sourceRuntimeContract'] = source_contract
    if backend == 'ram':
        report['requiredContiguousImageBytes'] = report['pages'] * 4096 + 8191
        report['warnings'].append('Image allocation excludes the context, resident runner, allocator overhead and guest heap')
    if approved and approved.get('hardwareEvidence'):
        report['priorBackendEvidence'] = {'adapter':approved.get('adapter'), **approved['hardwareEvidence']}
        if backend != 'flash': report['hardwareEvidence'] = approved['hardwareEvidence']
    # These offsets describe bytes in the image. Physical Flash addresses must
    # always be obtained afresh on the calculator, never stored in a PC profile.
    try:
        scanner = module('probes/storage-loader/tools/prepare.py' if backend == 'flash' else 'probes/native-loader/tools/prepare.py', 'fx_gate_scan')
        if not source_runtime:
            _, scan = scanner.profile(data, (review or {}).get('forbiddenPhysicalRam', ()))
            report['staticAnalysis'] = scan
        else:
            report['staticAnalysis'] = {'method': 'source-declared resident API and immutable SHA-256 binding', 'runtimeContract': 'fxlarge-map-api-v1', 'imagePatches': []}
    except ValueError as ex:
        report['blockers'].append(str(ex))
        if hasattr(ex, 'evidence'):
            report['staticAnalysis'] = ex.evidence
    if review is not None:
        required = {'schemaVersion', 'sha256', 'backend', 'memoryReviewed',
                    'callbacksReviewed', 'forbiddenPhysicalRam'}
        if not required <= review.keys() or review['schemaVersion'] != 1:
            raise ValueError('Incomplete review profile')
        if review['sha256'] != digest or review['backend'] != backend:
            raise ValueError('Review profile belongs to a different image/backend')
        if review['memoryReviewed'] is not True or review['callbacksReviewed'] is not True:
            raise ValueError('Memory and callback review must be explicitly completed')
        report['reviewProfile'] = review
    if backend == 'extended':
        if source_runtime:
            report['status'] = 'candidate'
            report['requiredRuntime'] = 'fxlarge-map-api-v1'
            report['historicalAdapterLimitations'] = (approved or {}).get('limitations', [])
            report['warnings'].append('Resident RAM depends on this profile capacity and runtime build; the payload arena is additional. Unsupported OS/callback paths still require source adaptation.')
            report['warnings'].append('The source ABI header is a declaration, not proof that every exception path obeys it; test the actual source-integrated build.')
        else:
            report['blockers'].append('Requires guest-owned page table/refill and runtime integration; OS table has only 512 entries')
            report['requiredRuntime'] = 'extended-vbr-v1 (source integration; experimental)'
            report['warnings'].append('698-page synthetic probe passed simulation; arbitrary oversized G1A runtime integration is still required')
    elif backend == 'flash':
        report['programWhitelist'] = False
        report['requiredContiguousImageBytes'] = 0
        if not report['blockers']:
            report['status'] = 'candidate'
        report['warnings'].extend([
            'Original image layout and CRT are preserved; only syscall gate pages are shadowed in RAM',
            'Actual heap coexistence, custom MMU/VBR, RAM callbacks and direct OS calls require runtime validation',
            'A small image alone does not guarantee compatibility; the calculator checks its actual resident allocation'])
    elif backend == 'mapped':
        if approved and approved.get('adapter') == 'mapped-khicas-v1':
            report['status'] = 'candidate'
            report['warnings'].append('Exact KhiCAS adapter reduces its arena from 166 KiB to 106 KiB; first launch reported working, same-icon MENU resume remains unverified')
        else:
            report['blockers'].append('No reviewed mapped runtime adapter for this SHA-256')
    else:
        scan = report.get('staticAnalysis', {})
        if scan.get('unadaptedControlTransfers'):
            report['blockers'].append('Direct reset/control transfer needs an exit adapter')
        if approved and approved.get('blocked'):
            report['blockers'].append(approved['blocked'])
        if not approved and not review:
            report['blockers'].append('Memory coexistence and callbacks need review; matched literals do not prove compatibility')
        if not report['blockers']:
            report['status'] = 'candidate'
            report['warnings'].append('RAM limit is an upper bound; available contiguous heap may be smaller')
    if report['blockers']:
        report['status'] = 'needs-review'
    report['warnings'].append('Candidate means a runnable test bundle, not a hardware stability guarantee')
    return data, report


def prepare(source, output, requested='auto', review=None, artifacts=None):
    source = Path(source)
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError(f'Use a new output directory: {output}')
    data, report = analyze(source, requested, review)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Analyze and assemble in a sibling staging directory, then publish once.
    # A rejected profile or copy failure cannot leave a half-written catalog.
    with tempfile.TemporaryDirectory(prefix='.fxprepare-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'result'
        stage.mkdir()
        (stage / 'original.bin').write_bytes(data)
        loader = None
        if report['status'] == 'candidate':
            files = stage / 'calculator'
            if report['backend'] != 'flash': files.mkdir()
            if report['backend'] == 'flash':
                known = report['approvedProfile'] or {}
                item = {'id':'target','title':known.get('title',source.stem)[:15].encode('ascii','replace').decode(),
                        'source':str(stage/'original.bin'),'expectedSha256':report['sha256'],
                        'forbiddenPhysicalRam':(review or {}).get('forbiddenPhysicalRam',[])}
                module('probes/storage-loader/tools/prepare.py','fx_flash_prepare').prepare([item],files)
                loader = 'FlashLd.g1a'
            elif report['backend'] == 'ram':
                ident = 'target'
                known = report['approvedProfile'] or {}
                forbidden = (review or known).get('forbiddenPhysicalRam', [])
                item = {'id': ident, 'title': known.get('title', 'Target')[:15],
                        'source': str(stage / 'original.bin'), 'expectedSha256': report['sha256'],
                        'forbiddenPhysicalRam': forbidden}
                module('probes/native-loader/tools/prepare.py', 'fx_ram_prepare').prepare([item], files)
                (files / 'Loader.txt').write_bytes(b'FXLOADER\n' + b' ' * (2048-9))
                loader = 'Loader.g1a'
            elif report['backend'] == 'mapped':
                module('probes/mapped-loader/tools/prepare.py', 'fx_map_prepare').prepare(stage / 'original.bin', files)
                loader = 'KLoad.g1a'
            else:
                (files / 'KHICAS.BIN').write_bytes(data)
                loader = 'KhiMap.g1a'
                write_json(stage / 'runtime-profile.json', report['approvedProfile'])
            binary = Path(artifacts or ROOT / 'loader-artifacts') / loader
            if binary.is_file():
                artifact_manifest = read_json(binary.parent / 'manifest.json')
                expected = artifact_manifest.get('files', {}).get(loader)
                if expected != sha(binary.read_bytes()):
                    raise ValueError('Loader artifact hash does not match its build manifest')
                bound = (report['approvedProfile'] or {}).get('launcherSha256') if report['backend']=='extended' else None
                if bound and expected != bound:
                    raise ValueError('Launcher differs from the reviewed source-integrated build')
                shutil.copyfile(binary, files / loader)
                report['loaderSha256'] = expected
            else:
                report['status'] = 'profile-only'
                report['warnings'].append(f'Build and supply {loader}; this folder is not yet installable')
        write_json(stage / 'analysis.json', report)
        note = ('将 calculator 文件夹中的全部文件复制到计算器存储根目录。\n'
                f'启动 {loader}；FlashLd/Loader 使用 EXE 选择，KLoad 阅读提示后按 EXE，KhiMap 自动加载 BIN。\n'
                'FlashLd 使用通用映射，不保证所有程序；首次实机测试后请回传 FlashLd.txt。请勿重命名 FlashLd.g1a。\n'
                'KhiMap 从 MENU 选回后按 EXE 重新加载；此前计算不会保留。\n'
                'KLoad 的实机直接选回路径仍待验证；需要全新启动时先进入 RUN-MAT 再打开 KLoad。\n'
                'Loader/KLoad 保留结果文件；KhiMap 显示阶段和错误码，当前版本不写文件。\n'
                if report['status'] == 'candidate' else
                '尚未生成可直接测试的完整包。查看 analysis.json 的 blockers 和 warnings。\n')
        (stage / '说明.txt').write_text(note, encoding='utf-8-sig')
        write_json(stage / 'checksums.json', {str(p.relative_to(stage)).replace('\\','/'): sha(p.read_bytes()) for p in stage.rglob('*') if p.is_file()})
        stage.rename(output)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, nargs='?')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--profile', choices=['auto', 'flash', 'ram', 'mapped', 'extended'], default='auto')
    parser.add_argument('--review-profile', type=Path)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--batch', type=Path, help='JSON array of source/output/profile/reviewProfile, paths relative to JSON')
    args = parser.parse_args(argv)
    try:
        if args.batch:
            if args.source or args.output or args.review_profile:
                raise ValueError('Batch mode cannot be combined with single-image arguments')
            rows = read_json(args.batch)
            if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
                raise ValueError('Batch must contain 1 through 256 items')
            reports = []
            for row in rows:
                base = args.batch.resolve().parent
                try:
                    if not isinstance(row, dict):
                        raise ValueError('Each batch item must be an object')
                    r = prepare(base / row['source'], base / row['output'], row.get('profile', 'auto'),
                                read_json(base / row['reviewProfile']) if row.get('reviewProfile') else None, args.artifacts)
                    reports.append({k:r[k] for k in ['inputName','status','backend','sha256','blockers']})
                except (OSError, ValueError, KeyError) as ex:
                    reports.append({'inputName': row.get('source') if isinstance(row, dict) else None, 'status': 'error', 'error': str(ex)})
        else:
            if not args.source or not args.output:
                raise ValueError('source and --output are required')
            r = prepare(args.source, args.output, args.profile, read_json(args.review_profile) if args.review_profile else None, args.artifacts)
            reports = [{k:r[k] for k in ['inputName','status','backend','sha256','blockers']}]
        print(json.dumps(reports, ensure_ascii=False, indent=2))
        return 0 if all(r['status'] == 'candidate' for r in reports) else 2
    except (OSError, ValueError, KeyError) as ex:
        print(json.dumps({'status':'error','error':str(ex)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
