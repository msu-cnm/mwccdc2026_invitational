"""Offline tests for scripts/splunk_poll.py.

All network activity is mocked; fixtures use sanitized TEST-NET addresses and
placeholder credentials only. No live competition probes are performed.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import splunk_poll as sp  # noqa: E402


def make_config(**over):
    cfg = {
        'splunk_url': 'https://192.0.2.20:8089',
        'index': 'team_security',
        'poll_interval': 15,
        'max_evidence_files': 5,
        'evidence_dir': 'inject_evidence',
        'timeout': 15,
        'queries': [
            {'id': 'webshell_markers',
             'query': 'index=team_security "eval(" | head 100'},
        ],
    }
    cfg.update(over)
    return cfg


class ConfigValidationTests(unittest.TestCase):
    def test_valid_config_round_trips(self):
        cfg = sp.validate_config(make_config())
        self.assertEqual(cfg['splunk_url'], 'https://192.0.2.20:8089')
        self.assertEqual(len(cfg['queries']), 1)
        self.assertEqual(cfg['queries'][0]['id'], 'webshell_markers')

    def test_rejects_credentials_in_config(self):
        for key in ('username', 'password', 'token'):
            with self.subTest(key=key):
                with self.assertRaises(SystemExit):
                    sp.validate_config(make_config(**{key: 'x'}))

    def test_rejects_credential_bearing_url(self):
        with self.assertRaises(SystemExit):
            sp.validate_config(make_config(splunk_url='https://user:pw@192.0.2.20:8089'))

    def test_rejects_http_scheme(self):
        with self.assertRaises(SystemExit):
            sp.validate_config(make_config(splunk_url='http://192.0.2.20:8089'))

    def test_rejects_hostname_url(self):
        with self.assertRaises(SystemExit):
            sp.validate_config(make_config(splunk_url='https://splunk.lab.local:8089'))

    def test_rejects_fragment_url(self):
        with self.assertRaises(SystemExit):
            sp.validate_config(make_config(splunk_url='https://192.0.2.20:8089#frag'))

    def test_rejects_bad_index(self):
        with self.assertRaises(SystemExit):
            sp.validate_config(make_config(index='team security'))

    def test_rejects_empty_queries(self):
        with self.assertRaises(SystemExit):
            sp.validate_config(make_config(queries=[]))

    def test_rejects_duplicate_query_ids(self):
        with self.assertRaises(SystemExit):
            sp.validate_config(make_config(queries=[
                {'id': 'a', 'query': 'x'},
                {'id': 'a', 'query': 'y'}]))

    def test_rejects_bad_poll_interval(self):
        for bad in (0, 7200, '15', True):
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    sp.validate_config(make_config(poll_interval=bad))

    def test_rejects_absolute_evidence_dir(self):
        with self.assertRaises(SystemExit):
            sp.validate_config(make_config(evidence_dir='/tmp/evidence'))


class PlanModeTests(unittest.TestCase):
    """--execute not set: prints a plan, performs no network activity."""

    def test_plan_prints_and_does_not_touch_network(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as fh:
            json.dump(make_config(), fh)
            path = fh.name
        buf = io.StringIO()
        with mock.patch.object(sp, '_do_request') as dr:
            with contextlib.redirect_stdout(buf):
                rc = sp.main(['--config', path])
        self.assertEqual(rc, 0)
        dr.assert_not_called()
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload['mode'], 'plan')
        self.assertEqual(payload['status'], 'ok')
        self.assertEqual(len(payload['queries']), 1)

    def test_missing_config_fails(self):
        with self.assertRaises(SystemExit) as ctx:
            sp.main(['--config', '/nonexistent/nope.json'])
        self.assertEqual(ctx.exception.code, 2)


class ExecuteCycleTests(unittest.TestCase):
    """One --execute cycle with a fully mocked REST layer."""

    def _mock_rest(self, rows):
        def fake_request(url, data=None, headers=None, method=None, timeout=15):
            if url.endswith('/services/auth/login'):
                return 200, {}, json.dumps({'sessionKey': 'abc'}).encode()
            if url.endswith('/services/search/jobs') and method == 'POST':
                # Splunk requires POST to create a search job; the search
                # arrives form-encoded in the body.
                self.assertIn(b'search=', data)
                self.assertIn(b'output_mode=json', data)
                self.assertEqual(headers['Authorization'], 'Splunk abc')
                return 200, {}, json.dumps({'sid': 'job1'}).encode()
            if url.endswith('/services/search/jobs/job1?output_mode=json'):
                return 200, {}, json.dumps(
                    {'entry': [{'content': {'dispatchState': 'DONE'}}]}).encode()
            if '/results' in url:
                import csv as _csv, io as _io
                buf = _io.StringIO()
                w = _csv.writer(buf)
                w.writerow(['_time', 'host', 'uri'])
                for r in rows:
                    w.writerow([r['_time'], r['host'], r['uri']])
                return 200, {}, buf.getvalue().encode()
            raise AssertionError('unexpected url %r' % url)
        return fake_request

    def test_cycle_writes_evidence_when_rows_found(self):
        cfg = sp.validate_config(make_config(evidence_dir='ev_test'))
        rows = [{'_time': '1', 'host': 'h1', 'uri': '/x'},
                {'_time': '2', 'host': 'h2', 'uri': '/y'}]
        d = tempfile.mkdtemp()
        old = os.getcwd()
        os.chdir(d)
        try:
            with mock.patch.object(sp, '_do_request', side_effect=self._mock_rest(rows)), \
                 mock.patch.dict(os.environ, {'SPLUNK_USERNAME': 'u', 'SPLUNK_PASSWORD': 'p'}):
                new_total, evidence_file = sp.execute_once(cfg)
            self.assertEqual(new_total, 2)
            self.assertIsNotNone(evidence_file)
            self.assertTrue(evidence_file.exists())
            payload = json.loads(evidence_file.read_text())
            self.assertEqual(len(payload['queries']['webshell_markers']), 2)
        finally:
            os.chdir(old)

    def test_cycle_no_evidence_when_no_rows(self):
        cfg = sp.validate_config(make_config(evidence_dir='ev_test'))
        d = tempfile.mkdtemp()
        old = os.getcwd()
        os.chdir(d)
        try:
            with mock.patch.object(sp, '_do_request', side_effect=self._mock_rest([])), \
                 mock.patch.dict(os.environ, {'SPLUNK_USERNAME': 'u', 'SPLUNK_PASSWORD': 'p'}):
                new_total, evidence_file = sp.execute_once(cfg)
            self.assertEqual(new_total, 0)
            self.assertIsNone(evidence_file)
        finally:
            os.chdir(old)

    def test_consecutive_cycles_only_write_new_rows(self):
        rows = [{'_time': '1', 'host': 'h1', 'uri': '/x'}]
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_config(evidence_dir=directory)
            seen = set()
            with mock.patch.object(sp, '_do_request', side_effect=self._mock_rest(rows)), \
                 mock.patch.dict(os.environ, {'SPLUNK_USERNAME': 'u', 'SPLUNK_PASSWORD': 'p'}):
                first_total, first_file = sp.execute_once(cfg, seen)
                original = first_file.read_bytes()
                second_total, second_file = sp.execute_once(cfg, seen)
            self.assertEqual(first_total, 1)
            self.assertEqual(second_total, 0)
            self.assertIsNone(second_file)
            self.assertEqual(list(first_file.parent.glob('events_*.json')), [first_file])
            self.assertEqual(first_file.read_bytes(), original)

    def test_main_shares_dedup_state_between_cycles(self):
        with tempfile.TemporaryDirectory() as directory:
            from pathlib import Path
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps(make_config()))
            states = []

            def cycle(cfg, seen):
                states.append(seen)
                if len(states) == 1:
                    seen.add('previous-row')
                else:
                    self.assertIn('previous-row', seen)
                return 0, None

            with mock.patch.object(sp, 'execute_once', side_effect=cycle), \
                 mock.patch.object(sp.time, 'sleep'), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(sp.main(['--config', str(path), '--execute', '--max-cycles', '2']), 0)
            self.assertEqual(len(states), 2)
            self.assertIs(states[0], states[1])

    def test_missing_credentials_fails(self):
        cfg = sp.validate_config(make_config())
        env = {k: v for k, v in os.environ.items() if not k.startswith('SPLUNK_')}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(sp, '_do_request') as dr:
            with self.assertRaises(SystemExit) as ctx:
                sp.execute_once(cfg)
        self.assertEqual(ctx.exception.code, 2)

    def test_query_error_recorded_not_fatal(self):
        cfg = sp.validate_config(make_config(evidence_dir='ev_test'))

        def boom(url, data=None, headers=None, method=None, timeout=15):
            if url.endswith('/services/auth/login'):
                return 200, {}, json.dumps({'sessionKey': 'abc'}).encode()
            raise RuntimeError('HTTP 500 from submit')

        with mock.patch.object(sp, '_do_request', side_effect=boom), \
             mock.patch.dict(os.environ, {'SPLUNK_USERNAME': 'u', 'SPLUNK_PASSWORD': 'p'}):
            new_total, evidence_file = sp.execute_once(cfg)
        self.assertEqual(new_total, 0)
        self.assertIsNone(evidence_file)

    def test_login_urlencodes_credentials(self):
        """Special characters in the password must be form-encoded, not raw-interpolated."""
        cfg = sp.validate_config(make_config())
        pw = 'p&ss=w+word'  # contains &, =, + which would break a naive body

        def fake_request(url, data=None, headers=None, method=None, timeout=15):
            self.assertTrue(url.endswith('/services/auth/login'))
            self.assertEqual(method, 'POST')
            self.assertIn(b'output_mode=json', data)
            # The password must arrive percent-encoded, not as raw special chars.
            self.assertIn(b'password=p%26ss%3Dw%2Bword', data)
            return 200, {}, json.dumps({'sessionKey': 'abc'}).encode()

        with mock.patch.object(sp, '_do_request', side_effect=fake_request), \
             mock.patch.dict(os.environ, {'SPLUNK_USERNAME': 'u', 'SPLUNK_PASSWORD': pw}):
            auth = sp.login(cfg)
        self.assertEqual(auth, 'Splunk abc')


class PruneTests(unittest.TestCase):
    def test_prune_keeps_max_files(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            for i in range(8):
                (p / ('events_%02d.json' % i)).write_text('{}')
            sp.prune(p, 5)
            remaining = sorted(x.name for x in p.glob('events_*.json'))
            self.assertEqual(len(remaining), 5)
            # Oldest three removed.
            self.assertNotIn('events_00.json', remaining)
            self.assertIn('events_07.json', remaining)


if __name__ == '__main__':
    unittest.main()
