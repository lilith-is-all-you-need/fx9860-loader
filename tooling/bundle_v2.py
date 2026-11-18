"""Immutable per-program calculator folders; no executable profile plugins."""
import hashlib
import json
import re
import shutil
import struct
import tempfile
import unicodedata
from pathlib import Path

FORMAT_VERSION = 2
PAGE = 4096
LOADERS = {'flash': 'FlashLd.g1a', 'mapped': 'KLoad.g1a', 'extended': 'ExtLoad.g1a'}


def identity(name, digest):
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError('Invalid SHA-256 identity')
    stem = unicodedata.normalize('NFKC', Path(name).stem)
    stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', stem).strip(' .')[:48] or 'Addin'
    if stem.upper() in {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1,10)), *(f'LPT{i}' for i in range(1,10))}:
        stem = '_' + stem
    prefix = re.sub('[^A-Za-z0-9]', '', stem).upper()[:2].ljust(2, 'X')
    return {'directoryName': stem + '-' + digest[:10], 'calculatorId': prefix + digest[:6].upper(),
            'displayName': stem, 'sha256': digest}


def metadata(name, kind, size):
    title = name.encode('ascii', 'replace')[:31].ljust(32, b'\0')
    return struct.pack('>8sIIII32s8s', b'FXAPPM01', 1, kind, size, 0, title, bytes(8))


def g1a_icon(data):
    # The G1A header stores 17 rows of 30 pixels, MSB first, at offset 0x4c.
    rows = bytearray(data[0x4c:0x90])
    for last_byte in range(3, len(rows), 4):
        rows[last_byte] &= 0xfc  # Clear the two padding bits at the right edge.
    return bytes(rows)


def artifact(directory, name):
    directory = Path(directory)
    manifest = json.loads((directory/'manifest.json').read_text('utf-8-sig'))
    if manifest.get('schemaVersion') != 2 or manifest.get('bundleFormat') != 2:
        raise ValueError('This Loader set predates folder packages; supply a version-2 build manifest / 此 Loader 不支持新版目录包。')
    expected = manifest.get('files', {}).get(name)
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('Loader build manifest does not contain ' + name)
    source = directory/name
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Loader artifact hash does not match its build manifest: ' + name)
    return data, expected


def prepare(data, report, result, suite, artifacts=None, include_loader=False):
    """Result exists in a private staging directory. Never modifies user files."""
    ident = identity(report['inputName'], report['sha256'])
    report['bundleFormat'] = FORMAT_VERSION
    report['identity'] = ident
    report['includesLoader'] = False
    report['programReady'] = False
    if report['status'] != 'candidate':
        if report['backend'] == 'extended':
            report['status'] = 'needs-adapter'
            report['ghidraRequiredForBinaryAdapter'] = True
        return report
    backend = report['backend']
    if backend == 'ram':
        report['status'] = 'needs-adapter'
        report['blockers'].append('The legacy RAM runner has no folder/caller-state contract. Use the Flash backend for ordinary images.')
        return report
    files = result/'calculator'
    app = files/'FXAPPS'/ident['calculatorId']
    app.mkdir(parents=True)
    (app/'IMAGE.BIN').write_bytes(data)
    (app/'APP.MET').write_bytes(metadata(ident['displayName'], {'flash':1,'extended':2,'mapped':3}[backend], len(data)))
    (app/'ICON.BIN').write_bytes(g1a_icon(data))
    if backend == 'flash':
        profile, _ = suite.module('probes/storage-loader/tools/prepare.py','fx_folder_scan').profile(data, ())
        (app/'APP.FPF').write_bytes(profile)
        (app/'RUN.LOG').write_bytes(b'FXFLASH1' + bytes(4096-8))
        (app/'VERIFY.CCH').write_bytes(bytes(4096))
    elif backend == 'extended':
        import ext_profile
        profile = ext_profile.encode_profile(data)
        (app/'EXT.PRF').write_bytes(profile)
        report['runtimeProfile'] = {'file':'EXT.PRF', 'pageCount':(len(data)+4095)//4096,
                                    'pageCapacity':(((len(data)+4095)//4096+15)//16)*16,
                                    'physicalAddressesIncluded':False}
    elif backend == 'mapped':
        # The exact KhiCAS adapter still supplies its memory ownership/exit patches.
        # Its launcher validates this profile and immutable image independently.
        legacy = result/'mapped-staging'
        suite.module('probes/mapped-loader/tools/prepare.py','fx_mapped_folder').prepare(result/'original.bin', legacy)
        shutil.copyfile(legacy/'khicas.kpf', app/'KHICAS.KPF')
        shutil.copyfile(legacy/'KLoad.txt', app/'KLOAD.TXT')
        shutil.copyfile(legacy/'adapter-report.json', result/'adapter-report.json')
        if legacy.resolve().parent != result.resolve():
            raise ValueError('Unexpected staging directory')
        shutil.rmtree(legacy)
    loader = LOADERS[backend]
    report['requiredLoader'] = loader
    report['programReady'] = True
    report['status'] = 'program-ready'
    report['calculatorDirectory'] = 'FXAPPS/' + ident['calculatorId']
    report['storageFileBytes'] = sum(p.stat().st_size for p in files.rglob('*') if p.is_file())
    if include_loader:
        blob, digest = artifact(artifacts or suite.ROOT/'loader-artifacts', loader)
        (files/loader).write_bytes(blob)
        report['loaderSha256'] = digest
        report['includesLoader'] = True
        report['status'] = 'candidate'
        report['storageFileBytes'] += len(blob)
    report['warnings'].append('Keep the complete FXAPPS subdirectory and the shared Loader filename. Existing device files are not overwritten by this PC tool.')
    return report


def export_loaders(output, artifacts, backend='all'):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError('Loader export requires a new directory / 请使用新的导出目录。')
    keys = list(LOADERS) if backend == 'all' else [backend]
    blobs = [(LOADERS[k], *artifact(artifacts, LOADERS[k])) for k in keys]
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.fxloaders-', dir=output.parent) as temporary:
        stage = Path(temporary)/'loaders'
        stage.mkdir()
        for name, data, digest in blobs:
            (stage/name).write_bytes(data)
        (stage/'checksums.json').write_text(json.dumps({n:d for n,b,d in blobs}, indent=2)+'\n', encoding='utf-8')
        (stage/'README.txt').write_text('Copy the required .g1a to storage root; preserve its filename.\n将需要的 .g1a 复制到存储根目录，保留文件名。\nFlashLd: ordinary folders / 普通程序\nKLoad: reviewed KhiCAS adapter / 已适配 KhiCAS\nExtLoad: source-integrated oversized payloads / 接入运行库的超限程序\n', encoding='utf-8-sig')
        stage.rename(output)
    return {'status':'loader-exported', 'output':str(output), 'loaders':[n for n,b,d in blobs]}
