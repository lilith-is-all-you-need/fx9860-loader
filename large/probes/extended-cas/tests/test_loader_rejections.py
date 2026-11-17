"""Boot isolated negative inputs without modifying the distributable bundle."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


parser = argparse.ArgumentParser(description=__doc__)
for option in ('sdk', 'exe', 'firmware', 'bundle', 'out'):
    parser.add_argument('--' + option, type=Path, required=True)
parser.add_argument('--case', action='append', choices=(
    'missing-bin', 'wrong-length', 'heap-too-small', 'cas-reservation-too-small', 'sha-mismatch'))
parser.add_argument('--timeout', type=float, default=120)
args = parser.parse_args()
for option in ('sdk', 'exe', 'firmware', 'bundle', 'out'):
    setattr(args, option, getattr(args, option).resolve())
sys.path.insert(0, str(args.sdk / 'probes/emulator'))
from runtime_probe import Session

# These sessions run in the background and expose only the normal debugger
# observation interfaces. The script never writes target memory or registers.
original_popen = subprocess.Popen
def hidden_popen(*values, **options):
    if sys.platform == 'win32':
        info = subprocess.STARTUPINFO()
        info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        info.wShowWindow = 0
        options['startupinfo'] = info
    return original_popen(*values, **options)
subprocess.Popen = hidden_popen

args.out.mkdir(parents=True, exist_ok=False)
bundle_hashes = {n: digest(args.bundle / n) for n in ('KhiMap.g1a', 'KHICAS.BIN')}
cases = [('missing-bin', 49152, None, 10),
         ('wrong-length', 49152, b'\0', 11),
         ('heap-too-small', 4096, 'correct', 20),
         ('cas-reservation-too-small', 32768, 'correct', 40),
         ('sha-mismatch', 49152, 'tampered', 14)]
selected = args.case or ['missing-bin', 'wrong-length', 'heap-too-small']
cases = [case for case in cases if case[0] in selected]
reports = []
for name, heap, content, error in cases:
    output = args.out / name
    storage = output / 'storage/fls0'
    storage.mkdir(parents=True)
    shutil.copy2(args.bundle / 'KhiMap.g1a', storage / 'KhiMap.g1a')
    mutation = None
    if content in ('correct', 'tampered'):
        shutil.copy2(args.bundle / 'KHICAS.BIN', storage / 'KHICAS.BIN')
        if content == 'tampered':
            image = bytearray((storage / 'KHICAS.BIN').read_bytes())
            mutation = len(image) // 2
            image[mutation] ^= 1
            (storage / 'KHICAS.BIN').write_bytes(image)
    elif content is not None:
        (storage / 'KHICAS.BIN').write_bytes(content)
    options = ['--os-firmware', args.firmware, '--memory-profile', 'probe3',
               '--heap-bytes', str(heap)]
    began = time.monotonic()
    with Session(storage / 'KhiMap.g1a', output, options,
                 executable=args.exe, timeout=30, cwd=output) as session:
        session.remote.request('c', wait=False)
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            time.sleep(.2)
            status = session.command('status')
            calls = session.command('syscalls')
            if status['state'] != 'running':
                break
            if any('getkey' in x.get('name', '').lower() for x in calls.get('recent', [])):
                break
        time.sleep(.2)
        status = session.command('status')
        calls = session.command('syscalls')
        diagnostic = session.command('diagnostics')
        if (output / 'screen.bmp').is_file():
            shutil.copy2(output / 'screen.bmp', output / 'refusal.bmp')
        summary = {'case': name, 'expectedLoaderError': error,
                   'heapBytes': heap, 'hostWritesTargetMemory': False,
                   'singleByteMutationOffset': mutation,
                   'inputHashes': {str(p): digest(p) for p in storage.iterdir()},
                   'emulatorSha256': digest(args.exe),
                   'firmwareSha256': digest(args.firmware),
                   'status': status, 'diagnostics': diagnostic, 'syscalls': calls,
                   'elapsedHostSeconds': time.monotonic() - began,
                   'scope': 'Firmware-assisted HLE emulator; requires framebuffer review'}
        (output / 'result.json').write_text(json.dumps(summary, indent=2) + '\n')
        reports.append({'case': name, 'expectedLoaderError': error,
                        'status': status, 'syscallCount': calls.get('total'),
                        'framebuffer': str(output / 'refusal.bmp')})
        if status['state'] == 'running':
            session.remote.interrupt()
    print(json.dumps(reports[-1]), flush=True)
assert bundle_hashes == {n: digest(args.bundle / n) for n in bundle_hashes}
(args.out / 'summary.json').write_text(json.dumps({
    'bundleUnchanged': True, 'bundleSha256': bundle_hashes, 'cases': reports,
    'hostWritesTargetMemory': False}, indent=2) + '\n')
