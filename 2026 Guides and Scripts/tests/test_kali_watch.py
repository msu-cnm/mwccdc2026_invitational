"""Offline tests for scripts/kali_watch.py.

All network and subprocess activity is mocked; fixtures use sanitized,
non-routable TEST-NET addresses. No live competition probes are performed.
"""

import copy
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import kali_watch as kw  # noqa: E402


def write_config(raw):
    fh = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
    json.dump(raw, fh)
    fh.close()
    return fh.name


def mock_response(status, final_url, body=b''):
    """opener.open stand-in that supports both call and context-manager use."""
    resp = mock.Mock()
    resp.status = status
    resp.geturl.return_value = final_url
    resp.read.return_value = body
    cm = mock.Mock()
    cm.__enter__ = mock.Mock(return_value=resp)
    cm.__exit__ = mock.Mock(return_value=False)
    return cm


class KaliWatchBase(unittest.TestCase):
    def setUp(self):
        self.raw = {
            'team': None,
            'internal_targets': [
                {'id': 'rocky-ecom', 'ip': '192.0.2.10', 'ports': [80, 443],
                 'service_checks_enabled': False},
                {'id': 'ubuntu-email', 'ip': '192.0.2.15', 'ports': [25, 587],
                 'service_checks_enabled': True},
            ],
            'public_targets': [],
            'http_checks': [],
            'timeouts': {'connect_seconds': 2, 'read_seconds': 3},
            'probe_limits': {'max_parallel': 1, 'delay_ms': 50},
        }

    def load(self, raw):
        path = write_config(raw)
        try:
            return kw.load_config(path)
        finally:
            os.unlink(path)

    def assert_rejected(self, raw):
        with self.assertRaises(SystemExit) as ctx:
            self.load(raw)
        self.assertEqual(ctx.exception.code, 2)


class ConfigValidationTests(KaliWatchBase):
    """Configuration must be rejected (exit 2) before any probe can run."""

    def test_cidr_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw['internal_targets'][0]['ip'] = '192.0.2.0/24'
        self.assert_rejected(raw)

    def test_hostname_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw['internal_targets'][0]['ip'] = 'rocky-ecom.local'
        self.assert_rejected(raw)

    def test_placeholder_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw['internal_targets'][0]['ip'] = '{{TEAM_IP}}'
        self.assert_rejected(raw)

    def test_malformed_port_rejected(self):
        raw = copy.deepcopy(self.raw)
        raw['internal_targets'][0]['ports'] = [80, 'http', 99999]
        self.assert_rejected(raw)

    def test_invalid_team_rejected(self):
        for bad in (0, 21, '7', -3, 2.5, True):
            raw = copy.deepcopy(self.raw)
            raw['team'] = bad
            self.assert_rejected(raw)

    def test_valid_team_accepted(self):
        raw = copy.deepcopy(self.raw)
        raw['team'] = 7
        cfg = self.load(raw)
        self.assertEqual(cfg['team'], 7)

    def test_non_object_config_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            self.load([1, 2, 3])
        self.assertEqual(ctx.exception.code, 2)

    def test_core_infrastructure_excluded_from_targets(self):
        raw = copy.deepcopy(self.raw)
        raw['internal_targets'].append(
            {'id': 'vyos', 'ip': '172.17.0.1', 'ports': [80],
             'service_checks_enabled': True})
        self.assert_rejected(raw)

    def test_public_targets_require_team(self):
        raw = copy.deepcopy(self.raw)
        raw['public_targets'] = [
            {'id': 'rocky-ecom-pub', 'ip': '198.51.100.27', 'ports': [443],
             'service_checks_enabled': False}]
        self.assert_rejected(raw)


class TeamAddressTests(KaliWatchBase):
    def test_public_address_calculation(self):
        hint = kw.public_address_hint(7)
        self.assertEqual(hint['rocky-ecom'], '172.25.27.10')
        self.assertEqual(hint['ubuntu-email'], '172.25.27.15')

    def test_team_boundaries(self):
        self.assertEqual(kw.public_address_hint(1)['2019-mssql'], '172.25.21.120')
        self.assertEqual(kw.public_address_hint(20)['2019-mssql'], '172.25.40.120')

    def test_team_none_has_no_hints(self):
        self.assertIsNone(kw.public_address_hint(None))


class PreviewTests(KaliWatchBase):
    """Plan mode must perform no network or subprocess activity."""

    def test_map_plan_makes_no_calls(self):
        path = write_config(self.raw)
        try:
            with mock.patch.object(kw.subprocess, 'run') as run, \
                 mock.patch.object(kw.socket, 'create_connection') as conn, \
                 mock.patch.object(kw.shutil, 'which', return_value='/usr/bin/nmap'), \
                 mock.patch('sys.stdout', new=mock.Mock()):
                with self.assertRaises(SystemExit) as ctx:
                    kw.main(['map', '--config', path])
                self.assertEqual(ctx.exception.code, 0)
            run.assert_not_called()
            conn.assert_not_called()
        finally:
            os.unlink(path)

    def test_monitor_plan_makes_no_calls(self):
        path = write_config(self.raw)
        try:
            with mock.patch.object(kw.socket, 'create_connection') as conn, \
                 mock.patch('sys.stdout', new=mock.Mock()):
                with self.assertRaises(SystemExit) as ctx:
                    kw.main(['monitor', '--config', path])
                self.assertEqual(ctx.exception.code, 0)
            conn.assert_not_called()
        finally:
            os.unlink(path)

    def test_exposure_plan_makes_no_calls(self):
        path = write_config(self.raw)
        try:
            with mock.patch.object(kw.socket, 'create_connection') as conn, \
                 mock.patch('sys.stdout', new=mock.Mock()):
                with self.assertRaises(SystemExit) as ctx:
                    kw.main(['exposure', '--config', path])
                self.assertEqual(ctx.exception.code, 0)
            conn.assert_not_called()
        finally:
            os.unlink(path)


class NmapCommandTests(KaliWatchBase):
    def test_exact_nmap_arguments(self):
        cfg = self.load(self.raw)
        target = cfg['targets'][0]
        cmd = kw.build_nmap_command(target, cfg)
        self.assertEqual(cmd, ['nmap', '-sT', '-p', '80,443', '-n', '-Pn',
                               '--max-retries', '2', '--host-timeout', '30s',
                               '--max-parallelism', '1', '--scan-delay', '50ms',
                               '--max-rate', '10',
                               '-oX', '-', '192.0.2.10'])
        self.assertNotIn('-sS', cmd)  # unprivileged TCP connect only

    def test_parse_nmap_xml_distinct_states(self):
        xml = '''<?xml version="1.0"?>
        <nmaprun>
          <host><address addr="192.0.2.10" addrtype="ip"/></host>
          <host>
            <address addr="192.0.2.10" addrtype="ip"/>
            <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
            <port protocol="tcp" portid="443"><state state="filtered"/></port>
            <port protocol="tcp" portid="22"><state state="closed"/></port>
          </host>
        </nmaprun>'''
        result = kw.parse_nmap_xml(xml, '192.0.2.10')
        states = {p['port']: p['state'] for p in result['ports']}
        self.assertEqual(states, {80: 'open', 443: 'filtered', 22: 'closed'})
        by_port = {p['port']: p for p in result['ports']}
        self.assertEqual(by_port[80]['service'], 'http')

    def test_parse_nmap_xml_unknown_state(self):
        xml = '''<?xml version="1.0"?><nmaprun>
          <host><address addr="192.0.2.10" addrtype="ip"/>
          <port protocol="tcp" portid="80"><state state="weird"/></port></host>
        </nmaprun>'''
        result = kw.parse_nmap_xml(xml, '192.0.2.10')
        self.assertEqual(result['ports'][0]['state'], 'unknown')

    def test_discovery_failure_is_not_host_absence(self):
        xml = ('<?xml version="1.0"?><nmaprun>'
               '<host><address addr="198.51.100.9" addrtype="ip"/></host>'
               '</nmaprun>')
        with self.assertRaises(ValueError):
            kw.parse_nmap_xml(xml, '192.0.2.10')


class MapCollectionErrorTests(KaliWatchBase):
    def _run_map(self, side_effect=None, which=None):
        cfg = self.load(self.raw)
        with mock.patch.object(kw.shutil, 'which', return_value=which or '/usr/bin/nmap'), \
             mock.patch.object(kw.subprocess, 'run', side_effect=side_effect), \
             mock.patch('sys.stdout', new=mock.Mock()):
            try:
                kw.run_map(cfg)
            except SystemExit as e:
                return e.code
        return None

    def test_missing_nmap_is_collection_error(self):
        with mock.patch.object(kw.shutil, 'which', return_value=None), mock.patch('sys.stdout'):
            with self.assertRaises(SystemExit) as ctx:
                kw.run_map(self.load(self.raw))
        self.assertEqual(ctx.exception.code, 2)

    def test_nmap_timeout_is_collection_error(self):
        import subprocess as sp
        code = self._run_map(side_effect=sp.TimeoutExpired('nmap', 90))
        self.assertEqual(code, 2)

    def test_nmap_nonzero_exit_is_collection_error(self):
        proc = mock.Mock(returncode=1, stdout='<nmaprun/>', stderr='x')
        code = self._run_map(side_effect=lambda *a, **k: proc)
        self.assertEqual(code, 2)

    def test_malformed_xml_is_collection_error(self):
        proc = mock.Mock(returncode=0, stdout='<not-xml', stderr='')
        code = self._run_map(side_effect=lambda *a, **k: proc)
        self.assertEqual(code, 2)


class MonitorTests(KaliWatchBase):
    def test_empty_monitor_is_unknown_not_healthy(self):
        for target in self.raw['internal_targets']:
            target['service_checks_enabled'] = False
        cfg = self.load(self.raw)
        with mock.patch.object(kw, 'tcp_check') as tcp, \
             mock.patch.object(kw, 'http_check') as http, \
             mock.patch('sys.stdout', new=mock.Mock()):
            with self.assertRaises(SystemExit) as ctx:
                kw.run_monitor(cfg)
            self.assertEqual(ctx.exception.code, 2)
            tcp.assert_not_called()
            http.assert_not_called()

    def test_healthy_exit_zero(self):
        cfg = self.load(self.raw)
        with mock.patch.object(kw, 'tcp_check', return_value=('up', 5, None)), \
             mock.patch('sys.stdout', new=mock.Mock()):
            with self.assertRaises(SystemExit) as ctx:
                kw.run_monitor(cfg)
            self.assertEqual(ctx.exception.code, 0)

    def test_unhealthy_exit_one(self):
        cfg = self.load(self.raw)
        with mock.patch.object(kw, 'tcp_check',
                               side_effect=lambda *a, **k: ('down', 9, 'timeout')), \
             mock.patch('sys.stdout', new=mock.Mock()):
            with self.assertRaises(SystemExit) as ctx:
                kw.run_monitor(cfg)
            self.assertEqual(ctx.exception.code, 1)

    def test_collection_error_precedence_exit_two(self):
        cfg = self.load(self.raw)
        with mock.patch.object(kw, 'tcp_check',
                               side_effect=lambda *a, **k: ('error', 9, 'OSError')), \
             mock.patch('sys.stdout', new=mock.Mock()):
            with self.assertRaises(SystemExit) as ctx:
                kw.run_monitor(cfg)
            self.assertEqual(ctx.exception.code, 2)

    def test_repeat_bounded(self):
        cfg = self.load(self.raw)
        calls = []
        with mock.patch.object(kw, 'tcp_check',
                               side_effect=lambda *a, **k: (calls.append(1), ('up', 1, None))[1]), \
             mock.patch.object(kw.time, 'sleep', lambda s: None), \
             mock.patch('sys.stdout', new=mock.Mock()):
            with self.assertRaises(SystemExit) as ctx:
                kw.run_monitor(cfg, repeat=3)
            self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(len(calls), 3 * 2)  # disabled targets are skipped

    def test_repeat_out_of_bounds_rejected(self):
        cfg = self.load(self.raw)
        for bad in (0, 21, 'x'):
            with self.assertRaises(SystemExit) as ctx:
                kw.run_monitor(cfg, repeat=bad)
            self.assertEqual(ctx.exception.code, 2)


class HttpBoundaryTests(KaliWatchBase):
    def test_secret_free_output_no_body(self):
        check = {'url': 'https://192.0.2.10/portal', 'expected_status': 200,
                 'expected_content': None}
        cfg = self.load(self.raw)
        with mock.patch.object(kw, '_open',
                               return_value=mock_response(200, 'https://192.0.2.10/portal', b'token=SECRET')):
            result = kw.http_check(check, cfg)
        out = json.dumps(result)
        self.assertNotIn('SECRET', out)
        self.assertEqual(result['state'], 'ok')
        self.assertFalse(result['redirected'])

    def test_redirect_reported_not_followed(self):
        from urllib import error as urlerr
        check = {'url': 'https://192.0.2.10/', 'expected_status': None,
                 'expected_content': None}
        cfg = self.load(self.raw)
        http_err = urlerr.HTTPError('https://unconfigured.example/', 302, 'Found',
                                    mock.Mock(), None)
        with mock.patch.object(kw, '_open', side_effect=http_err):
            result = kw.http_check(check, cfg)
        self.assertTrue(result['redirected'])
        self.assertEqual(result['state'], 'redirect')
        self.assertIn('note', result)

    def test_tls_context_created_for_https(self):
        check = {'url': 'https://192.0.2.10/', 'expected_status': None,
                 'expected_content': None}
        cfg = self.load(self.raw)
        with mock.patch.object(kw, '_open',
                               return_value=mock_response(200, 'https://192.0.2.10/')) as op:
            kw.http_check(check, cfg)
        _, kwargs = op.call_args
        # context is the 3rd positional arg to _open(req, timeout, context, sni)
        args = op.call_args[0]
        self.assertIsNotNone(args[2])  # TLS verified by default

    def test_http_error_status_captured(self):
        from urllib import error as urlerr
        check = {'url': 'https://192.0.2.10/', 'expected_status': 200,
                 'expected_content': None}
        cfg = self.load(self.raw)
        http_err = urlerr.HTTPError('https://192.0.2.10/', 503, 'Service Unavailable',
                                    mock.Mock(), None)
        with mock.patch.object(kw, '_open', side_effect=http_err):
            result = kw.http_check(check, cfg)
        self.assertEqual(result['state'], 'mismatch')
        self.assertEqual(result['status'], 503)

    def test_connection_error_is_error_state(self):
        import socket as sock_mod
        check = {'url': 'https://192.0.2.10/', 'expected_status': None,
                 'expected_content': None}
        cfg = self.load(self.raw)
        with mock.patch.object(kw, '_open', side_effect=sock_mod.timeout('t')):
            result = kw.http_check(check, cfg)
        self.assertEqual(result['state'], 'error')

    def test_expected_content_mismatch(self):
        check = {'url': 'http://192.0.2.10/', 'expected_status': 200,
                 'expected_content': 'SCORING-PORTAL'}
        cfg = self.load(self.raw)
        with mock.patch.object(kw, '_open',
                               return_value=mock_response(200, 'http://192.0.2.10/', b'other')):
            result = kw.http_check(check, cfg)
        self.assertEqual(result['state'], 'mismatch')


class ScopeRegressionTests(KaliWatchBase):
    def test_public_scope_and_core_rejection(self):
        for team in (1, 20):
            raw = copy.deepcopy(self.raw)
            raw.update(team=team, target_scope='public')
            raw['public_targets'] = [dict(raw['internal_targets'][0],
                id='public', ip=kw.public_address_hint(team)['rocky-ecom'])]
            self.assertEqual(self.load(raw)['targets'][0]['id'], 'public')
            raw['public_targets'][0]['ip'] = '172.31.21.1'
            self.assert_rejected(raw)

    def test_http_scope_rejected_before_any_probe(self):
        for url in ('https://example.com/', 'http://203.0.113.9/',
                    'http://192.0.2.15:99999/', 'http://user:secret@192.0.2.15/'):
            raw = copy.deepcopy(self.raw)
            raw['http_checks'] = [{'url': url}]
            with mock.patch.object(kw.socket, 'create_connection') as conn:
                self.assert_rejected(raw)
                conn.assert_not_called()

    def test_https_sni_connects_to_ip_and_verifies_name(self):
        context = mock.Mock()
        conn = kw._ScopedHTTPSConnection('192.0.2.15', context=context,
                                         server_hostname='mail.example.test')
        sock = mock.Mock()
        def connect(instance):
            self.assertEqual(instance.host, '192.0.2.15')
            instance.sock = sock
        with mock.patch.object(kw.http.client.HTTPConnection, 'connect', connect):
            conn.connect()
        context.wrap_socket.assert_called_once_with(sock, server_hostname='mail.example.test')

    def test_handler_uses_scoped_connection(self):
        handler = kw._ContextSniHandler(context=mock.Mock(), sni_hostname='mail.example.test')
        with mock.patch.object(handler, 'do_open') as op:
            handler.https_open(mock.Mock())
        self.assertIs(op.call_args.args[0], kw._ScopedHTTPSConnection)

    def test_redirect_handler_never_opens_destination(self):
        handler = kw._NoRedirectHandler()
        req = kw.request.Request('http://192.0.2.15/')
        with self.assertRaises(kw.error.HTTPError):
            handler.http_error_302(req, None, 302, 'Found', {'Location': 'http://other/'})

    def test_expected_content_not_in_plan(self):
        cfg = self.load(self.raw)
        cfg['http_checks'] = [{'url': 'http://192.0.2.15/', 'expected_content': 'SECRET'}]
        self.assertNotIn('SECRET', json.dumps(kw.plan_document('monitor', cfg)))


if __name__ == '__main__':
    unittest.main()
