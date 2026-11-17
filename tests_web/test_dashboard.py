import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import subprocess
import collector
from app import app


class DashboardTests(unittest.TestCase):
    def test_pages(self):
        with app.test_client() as client:
            for path in ['/', '/ssh', '/ufw', '/fail2ban', '/permissions', '/reports', '/tests']:
                with self.subTest(path=path):
                    self.assertEqual(client.get(path).status_code, 200)
            self.assertEqual(client.get('/api/health').json['status'], 'PASS')
            self.assertEqual(len(client.get('/api/tests').json['items']), 8)
            self.assertEqual(client.get('/api/missing').status_code, 404)

    def test_missing_tools_are_unknown(self):
        def missing(*args, **kwargs):
            raise FileNotFoundError('missing tool')
        snapshot = collector.collect_snapshot(collector.SafeCommandRunner(missing))
        self.assertEqual(snapshot['overall'], 'UNKNOWN')
        self.assertTrue(all(c['value'] == 'UNKNOWN' for c in snapshot['cards']))

    def test_inactive_fail2ban_cannot_pass(self):
        def execute(argv, **kwargs):
            text = 'Jail list: sshd' if argv[-1] == 'status' else ''
            if argv[-2:] == ['is-active', 'fail2ban']:
                return subprocess.CompletedProcess(argv, 3, 'inactive', '')
            return subprocess.CompletedProcess(argv, 0, text, '')
        self.assertEqual(collector.collect_snapshot(collector.SafeCommandRunner(execute))['fail2ban']['status'], 'FAIL')

    def test_timeout_bytes_are_serializable(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], 1, output=b'partial', stderr=b'timeout')
        result = collector.SafeCommandRunner(timeout).run('hostname')
        self.assertTrue(result.timed_out)
        self.assertIsInstance(result.stdout, str)

    def test_report_download_and_traversal(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(collector, 'REPORT_DIR', Path(directory)):
            name = 'security_audit_20261110_120000.txt'
            (Path(directory) / name).write_text('audit evidence')
            with app.test_client() as client:
                response = client.get('/api/reports/' + name)
                self.assertEqual(response.data, b'audit evidence')
                response.close()
                self.assertEqual(len(client.get('/api/reports').json['items']), 1)
                self.assertEqual(client.get('/api/reports/passwd').status_code, 404)
            (Path(directory) / name).unlink()
            (Path(directory) / name).symlink_to('/etc/passwd')
            self.assertIsNone(collector.report_path(name))

    def test_command_registry_rejects_input(self):
        with self.assertRaises(KeyError):
            collector.SafeCommandRunner().run('echo unsafe')


if __name__ == '__main__':
    unittest.main()
