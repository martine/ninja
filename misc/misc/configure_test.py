#!/usr/bin/env python3

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


class TestConfigure(unittest.TestCase):
    def run_configure(self, directory, interrupt=False, bootstrap=True, replace_failure=False):
        script = Path(__file__).resolve().parents[1] / 'configure.py'
        if bootstrap or replace_failure:
            command = [sys.executable, '-c', '''
import os
import runpy
import subprocess
import sys

def interrupt(*args, **kwargs):
    raise KeyboardInterrupt

mode = sys.argv.pop(1)
if mode == 'replace':
    os.replace = interrupt
elif mode == 'interrupt':
    subprocess.check_call = interrupt
else:
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0])
    subprocess.check_call = fail
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name='__main__')
''', 'replace' if replace_failure else 'interrupt' if interrupt else 'fail',
                        str(script)]
        else:
            command = [sys.executable, str(script)]
        if bootstrap:
            command.append('--bootstrap')
        command.append('--platform=linux')
        env = dict(os.environ)
        env['CXX'] = 'nonexistent-ninja-bootstrap-compiler'
        return subprocess.run(command, cwd=directory, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_failed_bootstrap_preserves_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / 'build.ninja'
            original = b'# previous complete manifest\n'
            manifest.write_bytes(original)
            result = self.run_configure(directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(manifest.read_bytes(), original)

    def test_failed_bootstrap_does_not_create_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_configure(directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(directory) / 'build.ninja').exists())

    def test_interrupted_bootstrap_preserves_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / 'build.ninja'
            original = b'# previous complete manifest\n'
            manifest.write_bytes(original)
            result = self.run_configure(directory, interrupt=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'KeyboardInterrupt', result.stderr)
            self.assertEqual(manifest.read_bytes(), original)

    def test_interrupted_replace_cleans_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / 'build.ninja'
            original = b'# previous complete manifest\n'
            manifest.write_bytes(original)
            result = self.run_configure(directory, bootstrap=False,
                                        replace_failure=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'KeyboardInterrupt', result.stderr)
            self.assertEqual(manifest.read_bytes(), original)
            self.assertEqual(list(Path(directory).iterdir()), [manifest])

    def test_successful_generation_creates_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_configure(directory, bootstrap=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = Path(directory) / 'build.ninja'
            self.assertIn(b'build all: phony', manifest.read_bytes())
            self.assertEqual(list(Path(directory).iterdir()), [manifest])

    @unittest.skipUnless(os.name == 'posix', 'Requires POSIX symlink support')
    def test_successful_generation_preserves_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target_dir = Path(directory) / 'target'
            target_dir.mkdir()
            target = target_dir / 'manifest'
            target.write_bytes(b'# previous complete manifest\n')
            manifest = Path(directory) / 'build.ninja'
            manifest.symlink_to(Path('target') / 'manifest')
            result = self.run_configure(directory, bootstrap=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(manifest.is_symlink())
            self.assertIn(b'build all: phony', target.read_bytes())
            self.assertEqual(list(target_dir.iterdir()), [target])

    def test_successful_generation_replaces_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / 'build.ninja'
            manifest.write_bytes(b'# previous complete manifest\n')
            manifest.chmod(0o640)
            result = self.run_configure(directory, bootstrap=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b'build all: phony', manifest.read_bytes())
            self.assertEqual(list(Path(directory).iterdir()), [manifest])
            if os.name == 'posix':
                self.assertEqual(stat.S_IMODE(manifest.stat().st_mode), 0o640)


if __name__ == '__main__':
    unittest.main()
