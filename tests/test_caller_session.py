"""Compile/run the C lifecycle contract, including cold-entry recovery and faults."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'sdk/caller-session'


class CallerSessionTests(unittest.TestCase):
    def test_native_lifecycle_contract(self):
        compiler = os.environ.get('CC') or shutil.which('gcc') or shutil.which('clang')
        if not compiler:
            self.skipTest('A host C compiler is required for caller-session contract tests')
        with tempfile.TemporaryDirectory(prefix='fxcs-contract-') as work:
            binary = Path(work) / ('session-test.exe' if os.name == 'nt' else 'session-test')
            build = subprocess.run([compiler, '-std=c99', '-O2', '-Wall', '-Wextra', '-Werror',
                                    '-I', str(ROOT/'include'), str(ROOT/'src/fx_caller_session.c'),
                                    str(ROOT/'tests/session_test.c'), '-o', str(binary)],
                                   text=True, capture_output=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            test = subprocess.run([str(binary)], text=True, capture_output=True, timeout=15)
            self.assertEqual(test.returncode, 0, test.stdout + test.stderr)
            self.assertIn('100 snapshot corruption cases passed', test.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
