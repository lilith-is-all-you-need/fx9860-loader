"""Verify the FlashLd browser across an HLE menu handoff using two metadata-only entries."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import time


def key(session, name, hold=0.10):
    assert session.command('key', key=name, down=True)['ok']
    time.sleep(hold)
    assert session.command('key', key=name, down=False)['ok']


def wait(predicate, message):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.04)
    raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('emulator-root', 'emulator', 'loader', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.emulator_root.resolve()))
    from runtime_probe import Session

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    storage = output/'storage/fls0'
    for title in ('First', 'Second'):
        app = storage/'FXAPPS'/title
        app.mkdir(parents=True)
        header = struct.pack('>8sIIII32s8s', b'FXAPPM01', 1, 1, 516, 0, title.encode(), bytes(8))
        (app/'APP.MET').write_bytes(header)
    launcher = storage/'FlashLd.g1a'
    shutil.copyfile(args.loader, launcher)
    frame = output/'screen.bmp'
    options = ['--memory-profile', 'probe3', '--menu-vram-stress']
    with Session(launcher, output, options, args.emulator.resolve(), cwd=output) as session:
        # The EXE that selected this icon can still be pressed on a fresh entry.
        assert session.command('key', key='EXE', down=True)['ok']
        session.remote.request('c', wait=False)
        def waiting_for(number):
            return any(c['number'] == number for c in session.command('syscalls')['recent'])
        wait(lambda: waiting_for(0x24a), 'entry did not check the held key')
        assert session.command('key', key='EXE', down=False)['ok']
        wait(lambda: waiting_for(0x247) and frame.is_file(), 'browser did not start')
        first = frame.read_bytes()
        key(session, 'DOWN')
        wait(lambda: frame.read_bytes() != first, 'selection did not move')
        selected = frame.read_bytes()
        for hold in (0.10, 0.80):
            key(session, 'MENU')
            wait(lambda: session.command('status')['osMenu'], 'MENU did not suspend')
            key(session, 'EXE', hold)
            wait(lambda: not session.command('status')['osMenu'], 'same-icon resume did not finish')
            assert session.command('status')['state'] == 'running'
            assert frame.read_bytes() == selected
        key(session, 'UP')
        wait(lambda: frame.read_bytes() == first, 'navigation after resume failed')
        key(session, 'EXIT')
        wait(lambda: session.command('status')['state'] == 'exited', 'explicit EXIT did not exit')
    print('PASS: cold entry, repeated MENU/EXE, held EXE, preserved selection, explicit EXIT')
    print('SHA-256', hashlib.sha256(launcher.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
