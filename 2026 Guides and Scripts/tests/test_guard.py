import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('guard', ROOT/'scripts/linux_guard.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class GuardTests(unittest.TestCase):
    def invoke(self, argv, values, writer=None):
        def write(k, v):
            values[k] = v
        with patch.object(sys, 'argv', ['guard'] + argv), patch.object(g.platform, 'system', return_value='Linux'), patch.object(g, 'read_value', side_effect=lambda k: values[k]), patch.object(g, 'write_value', side_effect=writer or write), patch.object(g.os, 'geteuid', return_value=0), contextlib.redirect_stdout(io.StringIO()):
            g.main()

    def test_preview_is_read_only(self):
        values = dict.fromkeys(g.SETTINGS, '0')
        original = values.copy()
        with tempfile.TemporaryDirectory() as t:
            backup = Path(t)/'before.json'
            self.invoke(['harden', '--backup', str(backup)], values)
            self.assertEqual(values, original)
            self.assertFalse(backup.exists())

    def test_apply_repeat_and_rollback(self):
        values = dict.fromkeys(g.SETTINGS, '0')
        original = values.copy()
        with tempfile.TemporaryDirectory() as t:
            backup = Path(t)/'before.json'
            self.invoke(['harden', '--apply', '--backup', str(backup)], values)
            self.assertEqual(values, g.SETTINGS)
            self.assertEqual(json.loads(backup.read_text()), original)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                self.invoke(['harden', '--apply', '--backup', str(backup)], values)
            self.assertEqual(json.loads(backup.read_text()), original)
            self.invoke(['rollback', '--backup', str(backup)], values)
            self.assertEqual(values, g.SETTINGS)
            self.invoke(['rollback', '--apply', '--backup', str(backup)], values)
            self.assertEqual(values, original)
            self.invoke(['rollback', '--apply', '--backup', str(backup)], values)
            self.assertEqual(values, original)

    def test_partial_failure_restores_previous(self):
        values = dict.fromkeys(g.SETTINGS, '0')
        original = values.copy()
        def writer(k, v):
            if k == 'kernel.dmesg_restrict' and v == '1':
                raise OSError('simulated denied write')
            values[k] = v
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(OSError):
                self.invoke(['harden', '--apply', '--backup', str(Path(t)/'backup')], values, writer)
        self.assertEqual(values, original)

    def test_untrusted_rollback_rejected(self):
        for data in [{'net.ipv4.ip_forward':'0'}, dict.fromkeys(g.SETTINGS, '7'), dict.fromkeys(g.SETTINGS, 1), []]:
            with self.assertRaises(ValueError):
                g.validate_backup(data)

    def test_invalid_cli(self):
        for args in [['harden','--unknown'], ['rollback'], ['assess','--apply'], ['harden','--apply']]:
            with self.subTest(args=args):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    self.invoke(args, dict.fromkeys(g.SETTINGS, '0'))

    def test_no_traffic_configuration_keys(self):
        # Enforce narrow scope: no forwarding/rp_filter/ICMP/service changes.
        self.assertEqual(set(g.SETTINGS), {'kernel.kptr_restrict','kernel.dmesg_restrict','fs.protected_hardlinks','fs.protected_symlinks'})

    def test_topology_guide_coverage(self):
        topology = json.loads((ROOT/'config/topology.json').read_text())
        self.assertEqual(len(topology), 10)
        self.assertEqual(len({h['id'] for h in topology}), 10)
        guides = {p.stem for p in (ROOT/'docs/systems').glob('*.md')}
        self.assertEqual(guides, {h['id'] for h in topology})
        index = (ROOT/'docs/README.md').read_text()
        for host in topology:
            guide = ROOT/'docs/systems'/f"{host['id']}.md"
            self.assertIn(host['name'], guide.read_text())
            self.assertIn(f"systems/{host['id']}.md", index)


if __name__ == '__main__':
    unittest.main()
