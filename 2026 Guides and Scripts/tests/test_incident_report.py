"""Offline tests for scripts/incident_report.py.

All network activity is mocked; fixtures use sanitized TEST-NET addresses and
placeholder credentials only. No live competition probes are performed.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import incident_report as ir  # noqa: E402


def make_valid_doc(**over):
    """Build a valid document with optional overrides."""
    doc = {
        'incident_id': 'INC-001',
        'reported_utc': '2024-01-15T10:30:00Z',
        'timeline': [
            {'utc': '2024-01-15T10:00:00Z', 'description': 'Initial detection'},
            {'utc': '2024-01-15T10:30:00Z', 'description': 'Impact observed'},
        ],
        'evidence': [
            {
                'source': 'syslog-server-1',
                'event_id': 'EVT-12345',
                'hash': 'abc123def456789012345678901234567890abcdef12345678901234567890ab',
            },
        ],
        'source_address': '192.0.2.10',
        'destination_address': '192.0.2.20',
        'port': 443,
        'affected_services': ['nginx', 'mysql'],
        'impact': 'Service unavailable due to DDoS attack',
        'containment': 'Blocked source IP at perimeter firewall',
        'recovery': 'Scaled up backend servers and rerouted traffic',
        'scoring_verification': 'Score verified by incident commander',
    }
    doc.update(over)
    return doc


class ValidationTests(unittest.TestCase):
    """Test validate() function."""

    def test_valid_doc_passes_validation(self):
        """A fully valid document should pass validation with empty missing list."""
        doc = {
            'incident_id': 'INC-001',
            'reported_utc': '2024-01-15T10:30:00Z',
            'timeline': [
                {'utc': '2024-01-15T10:00:00Z', 'description': 'Initial detection'},
                {'utc': '2024-01-15T10:30:00Z', 'description': 'Impact observed'},
            ],
            'evidence': [
                {
                    'source': 'syslog-server-1',
                    'event_id': 'EVT-12345',
                    'hash': 'abc123def456789012345678901234567890abcdef12345678901234567890ab',
                },
            ],
            'source_address': '192.0.2.10',
            'destination_address': '192.0.2.20',
            'port': 443,
            'affected_services': ['nginx', 'mysql'],
            'impact': 'Service unavailable due to DDoS attack',
            'containment': 'Blocked source IP at perimeter firewall',
            'recovery': 'Scaled up backend servers and rerouted traffic',
            'scoring_verification': 'Score verified by incident commander',
        }
        missing = ir.validate(doc)
        self.assertEqual(missing, [])

    def test_missing_incident_id(self):
        """Missing incident_id field should be reported."""
        doc = make_valid_doc(incident_id=None)
        missing = ir.validate(doc)
        self.assertIn('missing incident_id', missing)

    def test_missing_reported_utc(self):
        """Empty reported_utc should be reported as missing."""
        doc = make_valid_doc(reported_utc='')
        missing = ir.validate(doc)
        self.assertIn('missing reported_utc', missing)

    def test_empty_timeline(self):
        """Empty timeline should be reported."""
        doc = make_valid_doc(timeline=[])
        missing = ir.validate(doc)
        self.assertIn('timeline is empty', missing)

    def test_missing_evidence(self):
        """Missing evidence field should be reported."""
        doc = make_valid_doc(evidence=None)
        missing = ir.validate(doc)
        self.assertIn('missing evidence', missing)

    def test_empty_evidence(self):
        """Empty evidence list should be reported."""
        doc = make_valid_doc(evidence=[])
        missing = ir.validate(doc)
        self.assertIn('evidence is empty', missing)

    def test_missing_source_address(self):
        """Missing source_address should be reported."""
        doc = make_valid_doc(source_address='')
        missing = ir.validate(doc)
        self.assertIn('missing source_address', missing)

    def test_missing_affected_services(self):
        """Empty affected_services should be reported."""
        doc = make_valid_doc(affected_services=[])
        missing = ir.validate(doc)
        self.assertIn('affected_services is empty', missing)

    def test_missing_impact(self):
        """Missing impact should be reported."""
        doc = make_valid_doc(impact='')
        missing = ir.validate(doc)
        self.assertIn('missing impact', missing)

    def test_rejects_non_object_input(self):
        """A top-level array or string is a validation error, not a crash."""
        for bad in ([1, 2], 'text', 42, None):
            with self.subTest(bad=bad):
                errors = ir.validate(bad)
                self.assertTrue(errors)

    def test_rejects_string_timeline(self):
        """timeline='text' must fail validation instead of crashing render."""
        doc = make_valid_doc(timeline='text')
        errors = ir.validate(doc)
        self.assertTrue(any('timeline' in e for e in errors))

    def test_rejects_list_impact(self):
        """A list-valued impact must fail validation instead of crashing join."""
        doc = make_valid_doc(impact=['a', 'b'])
        errors = ir.validate(doc)
        self.assertIn('missing impact', errors)

    def test_rejects_bad_port_values(self):
        for bad in (0, -1, 70000, '443', True, 443.0, None):
            with self.subTest(bad=bad):
                doc = make_valid_doc(port=bad)
                errors = ir.validate(doc)
                self.assertTrue(any('port' in e for e in errors))

    def test_rejects_bad_entry_schemas(self):
        """Entries with missing/non-text keys must fail validation."""
        cases = [
            make_valid_doc(timeline=[{'utc': '2024-01-15T10:00:00Z'}]),
            make_valid_doc(timeline=[{'utc': '', 'description': 'x'}]),
            make_valid_doc(timeline=['not-an-object']),
            make_valid_doc(evidence=[{'source': 's', 'event_id': 'e'}]),
            make_valid_doc(evidence=['not-an-object']),
            make_valid_doc(affected_services=['nginx', 42]),
            make_valid_doc(affected_services=[]),
        ]
        for doc in cases:
            with self.subTest(doc=doc):
                errors = ir.validate(doc)
                self.assertTrue(errors)

    def test_valid_doc_still_passes(self):
        """The reference document must remain fully valid."""
        self.assertEqual(ir.validate(make_valid_doc()), [])


class RedactionTests(unittest.TestCase):
    """Test redact() and redact_all() functions."""

    def test_redacts_password_value(self):
        """Redact password=value patterns — the value must be masked, key name kept."""
        self.assertEqual(ir.redact('password=hunter2secret'), 'password=[REDACTED]')
        self.assertEqual(ir.redact('PASSWORD=SECRET123'), 'PASSWORD=[REDACTED]')

    def test_redacts_plain_secret_under_secret_key(self):
        """A plain secret under a secret-named key is fully redacted."""
        doc = {'password': 'hunter2secret', 'api_key': 'abc123'}
        redacted = ir.redact_all(doc)
        self.assertEqual(redacted['password'], '[REDACTED]')
        self.assertEqual(redacted['api_key'], '[REDACTED]')

    def test_redacts_long_base64_token(self):
        """Redact high-entropy base64 strings (20+ chars)."""
        token = 'abcdefg1234567890123456'  # 24 chars, base64-like
        self.assertEqual(ir.redact(token), '[REDACTED]')

    def test_preserves_sha256_hash(self):
        """Preserve sha256 hex hashes (64 hex chars)."""
        sha256 = 'a' * 64
        self.assertEqual(ir.redact(sha256), sha256)

    def test_preserves_md5_hash(self):
        """Preserve md5 hex hashes (32 hex chars)."""
        md5 = 'd' * 32
        self.assertEqual(ir.redact(md5), md5)

    def test_preserves_ipv4_address(self):
        """Preserve IPv4 addresses."""
        ip = '192.0.2.10'
        self.assertEqual(ir.redact(ip), ip)

    def test_preserves_url(self):
        """Preserve URLs."""
        url = 'https://example.com/path?query=value'
        self.assertEqual(ir.redact(url), url)

    def test_redacts_20_char_base64_not_hash(self):
        """Redact 20+ char base64 that is not a hash."""
        self.assertEqual(ir.redact('ABCDEFGHIJ1234567890KLMNO'), '[REDACTED]')

    def test_redacts_multiple_secrets_in_one_string(self):
        """Every secret occurrence is redacted, not just the first entropy match."""
        first = 'abcdefg1234567890123456'  # 24 chars
        second = 'ZYXWVUTSRQ9876543210zyx'  # 25 chars, distinct
        value = f'token={first} then api_key={second}'
        redacted = ir.redact(value)
        self.assertNotIn(first, redacted)
        self.assertNotIn(second, redacted)
        self.assertEqual(redacted.count('[REDACTED]'), 2)

    def test_redacts_quoted_multivalue_secret(self):
        """Quoted assignments such as password="two words" are fully masked."""
        value = 'password="two words secret"'
        redacted = ir.redact(value)
        self.assertNotIn('two words', redacted)
        self.assertIn('[REDACTED]', redacted)

    def test_redacts_quoted_secret_among_plain_text(self):
        """A quoted secret later in the string is still fully masked."""
        value = 'login failed for admin: password="hunter two" retry=3'
        redacted = ir.redact(value)
        self.assertNotIn('hunter two', redacted)
        self.assertIn('[REDACTED]', redacted)

    def test_redact_all_recursive(self):
        """Test redact_all recursively processes nested dicts and lists."""
        doc = {
            'incident_id': 'INC-001',
            'reported_utc': '2024-01-15T10:30:00Z',
            'timeline': [
                {'utc': '2024-01-15T10:00:00Z', 'description': 'password=test'},
            ],
            'evidence': [
                {
                    'source': 'syslog-server',
                    'event_id': 'EVT-123',
                    'hash': 'abcdef123456789012345678901234567890abcdef12345678901234567890ab',
                },
            ],
            'source_address': '192.0.2.10',
            'destination_address': '192.0.2.20',
            'port': 443,
            'affected_services': ['nginx'],
            'impact': 'password=secret123',
            'containment': '',
            'recovery': '',
            'scoring_verification': '',
        }
        redacted = ir.redact_all(doc)
        self.assertIn('[REDACTED]', str(redacted['timeline'][0]['description']))
        self.assertIn('[REDACTED]', str(redacted['impact']))


class RenderingTests(unittest.TestCase):
    """Test render_report() function."""

    def test_render_contains_all_sections(self):
        """Rendered report should contain all required section headings."""
        doc = make_valid_doc()
        report = ir.render_report(doc, [])

        self.assertIn('# Incident INC-001', report)
        self.assertIn('## Reported', report)
        self.assertIn('## Timeline', report)
        self.assertIn('## Evidence', report)
        self.assertIn('## Network', report)
        self.assertIn('## Affected services', report)
        self.assertIn('## Impact', report)
        self.assertIn('## Containment', report)
        self.assertIn('## Recovery', report)
        self.assertIn('## Scoring verification', report)

    def test_render_footer_note(self):
        """Rendered report should contain footer note about secret material."""
        doc = make_valid_doc()
        report = ir.render_report(doc, [])

        self.assertIn('approved protected channel', report)
        self.assertIn('formatting aid', report)


class CLITests(unittest.TestCase):
    """Test CLI behavior."""

    def test_cli_exits_with_code_2_on_missing_field(self):
        """CLI should exit with code 2 when validation fails."""
        temp_file = None

        try:
            # Create a temp doc with missing field
            fd, temp_file = tempfile.mkstemp(suffix='.json')
            os.write(fd, json.dumps({
                'incident_id': 'INC-001',
                'reported_utc': '2024-01-15T10:30:00Z',
                'timeline': [],  # Missing required field
                'evidence': [
                    {
                        'source': 'syslog-server',
                        'event_id': 'EVT-123',
                        'hash': 'abc123def456789012345678901234567890abcdef12345678901234567890ab',
                    },
                ],
                'source_address': '192.0.2.10',
                'destination_address': '192.0.2.20',
                'port': 443,
                'affected_services': ['nginx'],
                'impact': 'Service unavailable',
                'containment': 'Blocked at firewall',
                'recovery': 'Scaled up servers',
                'scoring_verification': 'Verified',
            }).encode())
            os.close(fd)

            # Run the CLI with the temp file as input
            old_argv = sys.argv[:]  # Use slice for copy
            sys.argv = ['incident_report.py', '--input', temp_file]

            # Capture stdout and stderr
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()

            try:
                ir.main()
            except SystemExit as e:
                self.assertEqual(e.code, 2)

        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            sys.argv = old_argv
            if temp_file:
                os.unlink(temp_file)

        self.assertIsNotNone(temp_file)


class OutputSafetyTests(unittest.TestCase):
    def test_supported_inline_secrets(self):
        for key in ('private_key', 'sessionkey'):
            with self.subTest(key=key):
                self.assertEqual(ir.redact(f'{key}=shortsecret'), f'{key}=[REDACTED]')

    def test_json_and_write_report_real_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'report.md')
            doc = make_valid_doc(impact='sessionkey=shortsecret private_key=another')
            stdout = io.StringIO()
            with mock.patch.object(sys, 'argv', ['incident_report', '--write', path, '--json']), \
                    mock.patch.object(sys, 'stdin', io.StringIO(json.dumps(doc))), \
                    mock.patch.object(sys, 'stdout', stdout):
                ir.main()
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary['redacted_count'], 2)
            self.assertEqual(summary['output_path'], path)
            with open(path) as stream:
                report = stream.read()
            self.assertNotIn('shortsecret', report)
            self.assertNotIn('another', report)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            ir.write_output(path, 'replacement')
            with open(path + '.bak') as stream:
                self.assertEqual(stream.read(), report)
            self.assertEqual(os.stat(path + '.bak').st_mode & 0o777, 0o600)

    def test_reject_output_and_backup_symlinks(self):
        for suffix in ('', '.bak'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                victim = os.path.join(directory, 'victim')
                path = os.path.join(directory, 'report')
                with open(victim, 'w') as stream:
                    stream.write('keep')
                os.symlink(victim, path + suffix)
                with self.assertRaises(OSError):
                    ir.write_output(path, 'sensitive')
                with open(victim) as stream:
                    self.assertEqual(stream.read(), 'keep')


if __name__ == '__main__':
    unittest.main()
