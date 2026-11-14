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

    def test_firewall_plan_shape(self):
        text = g.linux_nftables()['linux-hardening.nft']
        self.assertIn('add table inet team_hardening', text)
        self.assertIn('type filter hook input priority 0; policy accept;', text)
        self.assertIn('ct state invalid drop', text)
        self.assertIn('ct state established, related accept', text)
        self.assertIn('tcp dport 22 ip saddr 172.20.240.0/24 accept', text)
        self.assertIn('iifname != "lo" tcp dport 22 drop', text)
        # Never touch ICMP, forwarding or service ports other than SSH mgmt.
        self.assertNotIn('icmp', text.lower())
        self.assertNotIn('ip_forward', text)
        for port in ('80', '443', '8080', '1433', '25', '110', '143', '3389'):
            self.assertNotIn('dport ' + port, text)

    def test_firewall_rollback_removes_added_table(self):
        rb = g.linux_nftables_rollback()['linux-rollback.nft']
        self.assertIn('flush table inet team_hardening', rb)
        self.assertIn('delete table inet team_hardening', rb)
        # Rollback removes exactly the added table; no stale ruleset re-apply.
        self.assertNotIn('add table', rb)

    def test_firewall_host_profile(self):
        text = g.linux_nftables(host_id='kali')['linux-hardening.nft']
        self.assertIn('tcp dport 22 ip saddr 172.17.0.0/24 accept', text)
        # Workstation profile excludes the Kali segment (host-specific policy).
        text_ws = g.linux_nftables(host_id='ubuntu-workstation')['linux-hardening.nft']
        self.assertNotIn('172.17.0.0/24', text_ws)

    def test_firewall_rejects_bad_profiles_and_sources(self):
        for host in ('no-such-host', '2022-ad', 'palo-alto'):
            with self.assertRaises(ValueError):
                g.linux_nftables(host_id=host)
        for sources in ([], ['::/0'], ['172.17.0.0/24; flush ruleset']):
            with self.assertRaises(ValueError):
                g.linux_nftables(sources)

    def test_firewall_cli_writes_file(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t)/'hardening.nft'
            with patch.object(sys, 'argv', ['guard', 'firewall', '--out', str(out)]), \
                 patch.object(g.platform, 'system', return_value='Linux'), \
                 contextlib.redirect_stdout(io.StringIO()):
                g.main()
            self.assertIn('team_hardening', out.read_text())
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_firewall_cli_rejects_apply(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.invoke(['firewall', '--apply'], dict.fromkeys(g.SETTINGS, '0'))

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
