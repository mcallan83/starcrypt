"""Check that the interoperability launcher cannot mistake failures for passes."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from run import run


class RunnerFailureTests(unittest.TestCase):
    def test_expected_rejection_requires_the_expected_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = [sys.executable, '-c', 'raise SystemExit("AuthenticationFailedException")']
            record = run(command, root, 'expected', expected_success=False,
                         expected_error='AuthenticationFailedException')
            self.assertTrue(record['pass'])
            with self.assertRaisesRegex(RuntimeError, 'unexpected reason'):
                run(command, root, 'wrong-error', expected_success=False,
                    expected_error='InvalidPassphraseException')
            summary = json.loads((root / 'summary.json').read_text())
            self.assertFalse(summary['pass'])
            self.assertEqual(summary['status'], 'failed')
            self.assertEqual(len(summary['checks']), 2)
            self.assertFalse(summary['checks'][-1]['pass'])

    def test_unexpected_success_and_geometry_warning_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, 'unexpected exit status'):
                run([sys.executable, '-c', 'pass'], root, 'unexpected-success', expected_success=False)
            with self.assertRaisesRegex(RuntimeError, 'ciphertext geometry'):
                run([sys.executable, '-c', 'print("Invalid cipher text file size")'], root, 'geometry')
            self.assertFalse(json.loads((root / 'summary.json').read_text())['checks'][-1]['pass'])

    def test_timeout_preserves_partial_logs_and_failure_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            timeout = subprocess.TimeoutExpired(['test-only-command'], 600,
                                                output=b'partial stdout\n', stderr=b'partial stderr\n')
            with patch('run.subprocess.run', side_effect=timeout):
                with self.assertRaisesRegex(RuntimeError, 'timed out'):
                    run(['test-only-command'], root, 'timeout')
            log = (root / 'timeout.log').read_text()
            self.assertIn('partial stdout', log)
            self.assertIn('partial stderr', log)
            self.assertIn('TIMED OUT', log)
            summary = json.loads((root / 'summary.json').read_text())
            self.assertEqual(summary['status'], 'failed')
            self.assertEqual(summary['checks'][0]['error'], 'timeout')

class RunnerAdditionalFailureTests(unittest.TestCase):
    def test_launch_failure_is_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch('run.subprocess.run', side_effect=FileNotFoundError('missing-test-tool')):
                with self.assertRaisesRegex(RuntimeError, 'cannot launch command'):
                    run(['missing-test-tool'], root, 'launch-error')
            summary = json.loads((root / 'summary.json').read_text())
            self.assertEqual(summary['status'], 'failed')
            self.assertIsNone(summary['checks'][0]['exit_code'])
            self.assertIn('missing-test-tool', (root / 'launch-error.log').read_text())

    def test_fixture_failure_marks_entire_run_failed(self):
        from run import main
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'results'
            app = root / 'Cryptomator.app'
            mods = app / 'Contents/app/mods'
            mods.mkdir(parents=True)
            (mods / 'cryptofs-test.jar').write_bytes(b'not-used-by-mocked-compiler')
            with patch('sys.argv', ['run.py', '--output', str(output), '--cryptomator-app', str(app)]), \
                 patch('run.jdk_tools', return_value=('test-javac', 'test-java')), \
                 patch('run.shutil.which', return_value='/test/tool'), \
                 patch('run.run', return_value={'name': 'compile-oracle', 'pass': True}), \
                 patch('run.fixture', side_effect=RuntimeError('fixture setup failed')):
                with self.assertRaisesRegex(RuntimeError, 'fixture setup failed'):
                    main()
            summary = json.loads((output / 'summary.json').read_text())
            self.assertFalse(summary['pass'])
            self.assertEqual(summary['status'], 'failed')
            self.assertIn('fixture setup failed', summary['error'])


if __name__ == '__main__':
    unittest.main()
