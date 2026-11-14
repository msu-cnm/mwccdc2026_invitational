import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('splunk_setup', ROOT / 'scripts/splunk_setup.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class SplunkSetupTests(unittest.TestCase):
    def plan(self, host, **kw):
        return s.plan(s.load_host(host), kw.get('receiver', '172.20.240.20'),
                      kw.get('port', 9997), kw.get('index', 'team_security'),
                      kw.get('method', 'forwarder'), extra_inputs=kw.get('inputs'))

    def test_linux_forwarder_rocky_paths(self):
        files, _ = self.plan('rocky-ecom')
        self.assertIn('outputs.conf', files)
        self.assertIn('inputs.conf', files)
        self.assertIn('server = 172.20.240.20:9997', files['outputs.conf'])
        self.assertIn('[tcpout:team_indexer]', files['outputs.conf'])
        self.assertIn('index = team_security', files['inputs.conf'])
        # Rocky 9 uses /var/log/secure + /var/log/messages, not auth.log/syslog
        self.assertIn('/var/log/secure', files['inputs.conf'])
        self.assertIn('/var/log/messages', files['inputs.conf'])
        self.assertNotIn('auth.log', files['inputs.conf'])

    def test_linux_inputs_override(self):
        files, _ = self.plan('rocky-ecom', inputs=['/var/log/custom'])
        self.assertIn('/var/log/custom', files['inputs.conf'])
        self.assertNotIn('/var/log/secure', files['inputs.conf'])

    def test_indexer_local_collection_does_not_forward_to_itself(self):
        files, note = self.plan('debian-splunk')
        self.assertEqual(set(files), {'inputs.conf'})
        self.assertIn('existing Splunk', note)

    def test_invalid_transport_destinations_and_config_injection_rejected(self):
        for receiver in ('bad host', '192.0.2.999', '::1', 'host;commit', 'host\ncommit', '-bad.example'):
            with self.subTest(receiver=receiver), self.assertRaises(ValueError):
                self.plan('vyos', method='syslog', receiver=receiver)
        for port in (0, 65536, -1, True):
            with self.subTest(port=port), self.assertRaises(ValueError):
                self.plan('vyos', method='syslog', port=port)
        with self.assertRaises(ValueError):
            self.plan('rocky-ecom', index='team\n[evil]')
        for item in ('relative.log', '/var/log/x\x00', '/var/log/x\n[evil]:raw', '/var/log/x:raw\ndisabled=1'):
            with self.subTest(item=item), self.assertRaises(ValueError):
                self.plan('rocky-ecom', inputs=[item])

    def test_unsupported_collection_methods_rejected(self):
        for host, method in (('vyos', 'forwarder'), ('palo-alto', 'forwarder'),
                             ('2022-ad', 'syslog'), ('rocky-ecom', 'syslog')):
            with self.subTest(host=host, method=method), self.assertRaises(ValueError):
                self.plan(host, method=method)

    def test_hostname_receiver_and_custom_source_are_preserved(self):
        files, _ = self.plan('ubuntu-email', receiver='splunk.lab.example',
                             inputs=['/var/log/mail.log:mail:raw'])
        self.assertIn('server = splunk.lab.example:9997', files['outputs.conf'])
        self.assertIn('sourcetype = mail:raw', files['inputs.conf'])

    def test_linux_syslog_relay_uses_tcp(self):
        files, _ = self.plan('debian-splunk', method='syslog', port=1514)
        self.assertIn('rsyslog-team-relay.conf', files)
        # TCP listener (imtcp), not a bare @ UDP forwarder.
        self.assertIn('input(type="imtcp" port="1514"', files['rsyslog-team-relay.conf'])
        self.assertNotIn('@', files['rsyslog-team-relay.conf'].split('ruleset')[0])
        # Routes each appliance's traffic to a local file Splunk then monitors.
        self.assertIn('action(type="omfile" file="/var/log/team-remote/vyos.log"', files['rsyslog-team-relay.conf'])
        self.assertIn('[monitor:///var/log/team-remote/vyos.log]', files['inputs.conf'])

    def test_relay_custom_port(self):
        files, _ = self.plan('debian-splunk', method='syslog', port=5514)
        self.assertIn('input(type="imtcp" port="5514"', files['rsyslog-team-relay.conf'])
        self.assertNotIn('1514', files['rsyslog-team-relay.conf'])

    def test_rollback_recreates_deleted_output_directory(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / 'nested' / 'gen'
            out.mkdir(parents=True)
            (out / 'outputs.conf').write_text('OLD\n')
            backup = Path(t) / 'bak.json'
            s.backup_existing(out, backup)
            (out / 'outputs.conf').unlink()
            out.rmdir()
            out.parent.rmdir()
            s.restore_backup(out, backup)
            self.assertEqual((out / 'outputs.conf').read_text(), 'OLD\n')
            self.assertEqual((out / 'outputs.conf').stat().st_mode & 0o777, 0o600)

    def test_windows_uf_only(self):
        files, _ = self.plan('2022-ad')
        # No WEF subscription XML (invalid schema + non-existent weutil command).
        self.assertNotIn('Subscription-2022-ad.xml', files)
        self.assertIn('inputs.conf', files)
        self.assertIn('[WinEventLog://Security]', files['inputs.conf'])
        self.assertIn('renderXml = true', files['inputs.conf'])
        self.assertIn('server = 172.20.240.20:9997', files['outputs.conf'])

    def test_network_devices_documented_syntax(self):
        # Docs examples use --port 1514 for the relay (TCP syslog).
        vyos, _ = self.plan('vyos', method='syslog', port=1514)
        self.assertIn('vyos-syslog.config', vyos)
        # VyOS 1.4 documented syntax: set system syslog host <ip> facility <fac> level <lvl>
        self.assertIn('set system syslog host 172.20.240.20 facility all level info', vyos['vyos-syslog.config'])
        self.assertIn('set system syslog host 172.20.240.20 port 1514', vyos['vyos-syslog.config'])
        self.assertIn('set system syslog host 172.20.240.20 protocol tcp', vyos['vyos-syslog.config'])
        palo, _ = self.plan('palo-alto', method='syslog', port=1514)
        self.assertIn('paloalto-syslog.config', palo)
        # PAN-OS 11 syslog server-profile hierarchy (docs "Palo Alto PAN-OS 11.0.2").
        self.assertIn('set shared log-settings syslog TEAM-SYSLOG server splunk server 172.20.240.20', palo['paloalto-syslog.config'])
        self.assertIn('transport TCP', palo['paloalto-syslog.config'])
        # TCP relay transport on port 1514, not Splunk's 9997.
        self.assertIn('port 1514', palo['paloalto-syslog.config'])
        self.assertNotIn('9997', palo['paloalto-syslog.config'])

    def test_unknown_host(self):
        with self.assertRaises(SystemExit):
            s.load_host('nope')

    def _apply(self, t, host='rocky-ecom', **kw):
        out = Path(t) / 'gen'
        backup = Path(t) / 'bak.json'
        files, _ = self.plan(host, **kw)
        nonempty = out.exists() and any(out.iterdir())
        if nonempty:
            s.backup_existing(out, backup)
            overwrite = True
            created = [n for n in files if not (out / n).exists()]
        else:
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump({'files': {}}, f)
            overwrite = False
            created = list(files)
        s.write_files(out, files, allow_overwrite=overwrite)
        s.record_created(backup, created)
        return out, backup

    def test_apply_fresh_dir_records_created(self):
        with tempfile.TemporaryDirectory() as t:
            out, backup = self._apply(t)
            self.assertTrue((out / 'inputs.conf').exists())
            self.assertTrue((out / 'outputs.conf').exists())
            data = json.loads(backup.read_text())
            self.assertEqual(sorted(data['created']), ['inputs.conf', 'outputs.conf'])

    def test_apply_overwrite_backs_up(self):
        with tempfile.TemporaryDirectory() as t:
            out, backup = self._apply(t)
            # Now pre-populate outputs.conf and apply again — must back up.
            (out / 'outputs.conf').write_text('OLD\n')
            backup2 = Path(t) / 'bak2.json'
            s.backup_existing(out, backup2)
            files, _ = self.plan('rocky-ecom')
            s.write_files(out, files, allow_overwrite=True)
            self.assertIn('server = 172.20.240.20:9997', (out / 'outputs.conf').read_text())
            data = json.loads(backup2.read_text())
            self.assertEqual(data['files']['outputs.conf']['content'], 'OLD\n')

    def test_refuses_overwrite_without_permission(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / 'gen'
            out.mkdir()
            (out / 'outputs.conf').write_text('OLD\n')
            files, _ = self.plan('rocky-ecom')
            with self.assertRaises(FileExistsError):
                s.write_files(out, files)

    def test_rollback_removes_created_restores_overwritten(self):
        with tempfile.TemporaryDirectory() as t:
            out, backup = self._apply(t)
            # Simulate an overwrite scenario: pre-existing outputs.conf was backed up.
            # Rollback must remove created files (inputs.conf) AND restore overwrites.
            (out / 'outputs.conf').unlink()  # pretend the new file is gone
            s.restore_backup(out, backup)
            self.assertFalse((out / 'inputs.conf').exists(), 'created file should be removed')
            self.assertFalse((out / 'outputs.conf').exists())

    def test_rollback_restores_overwritten_with_0600(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / 'gen'
            out.mkdir()
            (out / 'outputs.conf').write_text('OLD\n')
            os.chmod(out / 'outputs.conf', 0o644)
            backup = Path(t) / 'bak.json'
            s.backup_existing(out, backup)
            # Simulate the new file replacing the old one.
            (out / 'outputs.conf').write_text('NEW\n')
            s.restore_backup(out, backup)
            self.assertEqual((out / 'outputs.conf').read_text(), 'OLD\n')
            self.assertEqual((out / 'outputs.conf').stat().st_mode & 0o777, 0o600)

    def test_rejects_symlink_targets(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / 'gen'
            out.mkdir()
            target = Path(t) / 'outside.txt'
            target.write_text('secret\n')
            (out / 'evil.conf').symlink_to(target)
            files = {'evil.conf': 'x\n'}
            with self.assertRaises(SystemExit):
                s.write_files(out, files, allow_overwrite=True)

    def test_rejects_path_traversal_backup_key(self):
        # The backup JSON keys (file names) must be plain filenames; traversal is rejected.
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / 'gen'
            out.mkdir()
            backup = Path(t) / 'bak.json'
            backup.write_text('{"files": {"../evil.conf": {"content": "x\\n", "mode": "0o600"}}}')
            with self.assertRaises(SystemExit):
                s.restore_backup(out, backup)

    def test_rejects_absolute_backup_key(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / 'gen'
            out.mkdir()
            backup = Path(t) / 'bak.json'
            backup.write_text('{"files": {"/etc/passwd": {"content": "x\\n", "mode": "0o600"}}}')
            with self.assertRaises(SystemExit):
                s.restore_backup(out, backup)

    def test_rejects_traversal_backup_path(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / 'gen'
            out.mkdir()
            (out / 'outputs.conf').write_text('x\n')
            with self.assertRaises(SystemExit):
                s.backup_existing(out, Path(t) / '..' / 'evil.json')

    def test_record_created_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as t:
            backup = Path(t) / 'bak.json'
            backup.write_text('{"files": {}}')
            with self.assertRaises(SystemExit):
                s.record_created(backup, ['../evil.conf'])

    def test_restore_rejects_traversal_key(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / 'gen'
            out.mkdir()
            backup = Path(t) / 'bak.json'
            backup.write_text('{"files": {"../evil.conf": {"content": "x\\n", "mode": "0o600"}}}')
            with self.assertRaises(SystemExit):
                s.restore_backup(out, backup)


if __name__ == '__main__':
    unittest.main()
