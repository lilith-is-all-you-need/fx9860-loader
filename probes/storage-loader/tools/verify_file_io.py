"""Run the authored I/O guest through two actual launchers on separate empty disks."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

from prepare import prepare

SECTIONS = ('size16', 'seek16', 'read16', 'seekWrite16', 'readback16Close', 'waitExit')


def run(args, label, loader, marker, session_class):
    disk = args.output / label
    storage = disk / 'storage/fls0'
    storage.parent.mkdir(parents=True)
    prepare([dict(source=args.guest, id='io', title='IO check')], storage)
    shutil.copyfile(loader, storage / 'FlashLd.g1a')
    (storage / 'IO.DAT').write_bytes(bytes(256))
    trace = disk / 'calls.jsonl'
    options = ['--memory-profile', 'probe3', '--heap-bytes', 40960,
               '--os-firmware', args.firmware, '--trace-syscalls', trace]
    marks, boundaries = [], []
    with session_class(storage / 'FlashLd.g1a', disk, options, args.emulator, cwd=disk, timeout=15) as session:
        remote = session.remote

        def wait(predicate):
            deadline = time.monotonic() + 20
            while not predicate():
                state = session.command('status')
                if state['state'] in ('error', 'exited') or time.monotonic() >= deadline:
                    if predicate(): return
                    raise RuntimeError((label, state))
                time.sleep(.03)

        def key(name):
            session.command('key', key=name, down=True)
            time.sleep(.12)
            session.command('key', key=name, down=False)

        remote.request('c', wait=False)
        wait(lambda: any(c['number'] in (0x90f, 0x247) for c in session.command('syscalls')['recent']))
        remote.interrupt()
        assert remote.request(f'Z0,{marker:x},2') == 'OK'
        remote.request('c', wait=False)
        key('EXE')
        for phase in range(len(SECTIONS) + 1):
            wait(lambda: session.command('status')['state'] == 'paused')
            remote.receive()
            assert (remote.get(16), remote.get(4)) == (marker, phase)
            marks.append(session.command('status')['cycles'])
            boundaries.append(trace.stat().st_size)
            if phase == len(SECTIONS):
                assert remote.request(f'z0,{marker:x},2') == 'OK'
            else:
                remote.request('s')
            remote.request('c', wait=False)
            if phase == 5:
                wait(lambda: session.command('syscalls')['recent'][-1]['number'] == 0x90f)
                key('EXIT')
        wait(lambda: session.command('status')['state'] == 'exited')

    expected = b''.join(struct.pack('>I', 0x130000+i) for i in range(16)) + bytes(192)
    assert (storage/'IO.DAT').read_bytes() == expected
    log = (storage/'FlashLd.txt').read_bytes().split(b'RUN_END')[0].decode().strip()
    assert 'TARGET_RETURNED=0000002A' in log
    sections = {}
    with trace.open('rb') as stream:
        for i, name in enumerate(SECTIONS):
            stream.seek(boundaries[i])
            rows = stream.read(boundaries[i+1]-boundaries[i]).splitlines()
            calls = Counter(event['call']['name'] for row in rows
                            if (event := json.loads(row))['phase'] == 'leave')
            sections[name] = dict(instructions=marks[i+1]-marks[i], filePageQueries=calls['OS_FileOffsetToAddress_internal'])
    return dict(sha256=hashlib.sha256(loader.read_bytes()).hexdigest(), sections=sections, log=log)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','candidate','guest','elf','nm','firmware','emulator','emulator-root','output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    for name, value in vars(args).items(): setattr(args, name, value.resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(args.emulator_root))
    from runtime_probe import Session
    symbols = subprocess.check_output([args.nm, '-an', args.elf], text=True)
    marker = int(re.search(r'^([\da-fA-F]+) [tT] _io_phase$', symbols, re.M)[1], 16)
    results = {label: run(args, label, getattr(args,label), marker, Session) for label in ('baseline','candidate')}
    (args.output/'results.json').write_text(json.dumps(results, indent=2)+'\n', 'utf8')


if __name__ == '__main__':
    main()
