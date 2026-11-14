"""Offline tests for scripts/iot_query_builder.py; no network activity."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import iot_query_builder as qb  # noqa: E402


class QueryBuilderTests(unittest.TestCase):
    def assert_invalid(self, ioc_type, value):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            with self.assertRaises(SystemExit) as ctx:
                qb.build_queries(ioc_type, value)
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(json.loads(errors.getvalue())['status'], 'invalid_configuration')

    def test_valid_ip(self):
        for value in ('192.0.2.50', '2001:db8::1'):
            with self.subTest(value=value):
                pack = qb.build_queries('ip', value)
                self.assertEqual(len(pack['queries']), 3)
                for query in pack['queries']:
                    self.assertIn(value, query['query'])
                self.assertIn('eventtype=outbound', pack['queries'][2]['query'])

    def test_invalid_ip(self):
        self.assert_invalid('ip', '999.1.2.3')

    def test_valid_domain(self):
        queries = qb.build_queries('domain', 'evil.example')['queries']
        for field in ('host', 'uri', 'dst_domain', 'src_domain'):
            self.assertIn(field + '=', queries[0]['query'])
        self.assertIn('uri="*evil.example*"', queries[1]['query'])
        self.assertIn('query="evil.example"', queries[2]['query'])
        self.assertIn('dns_query="evil.example"', queries[2]['query'])

    def test_invalid_domain(self):
        self.assert_invalid('domain', '-bad-.com')

    def test_valid_hash(self):
        for value in ('a3' * 16, 'B4' * 20, 'c5' * 32):
            with self.subTest(value=value):
                queries = qb.build_queries('hash', value)['queries']
                for field in ('hash', 'file_hash', 'md5', 'sha1', 'sha256', 'filename'):
                    self.assertIn(field + '=', queries[0]['query'])
                self.assertIn('command_line="*' + value + '*"', queries[1]['query'])

    def test_invalid_hash(self):
        for value in ('z' * 32, 'a' * 31):
            with self.subTest(value=value):
                self.assert_invalid('hash', value)

    def test_valid_url(self):
        queries = qb.build_queries('url', 'https://evil.example/payload')['queries']
        for field in ('uri', 'url', 'referrer'):
            self.assertIn(field + '=', queries[0]['query'])
        self.assertIn('(process="certutil.exe" OR process="powershell.exe") command_line=',
                      queries[2]['query'])

    def test_invalid_url(self):
        self.assert_invalid('url', 'evil.example/payload')

    def test_valid_process(self):
        queries = qb.build_queries('process', 'powershell.exe')['queries']
        for field in ('process', 'parent_process', 'command_line'):
            self.assertIn(field + '=', queries[0]['query'])
        self.assertIn('parent_process="powershell.exe"', queries[1]['query'])
        self.assertIn('process="powershell.exe" dst_ip=*', queries[2]['query'])

    def test_invalid_process(self):
        for value in ('', '   ', 'process\nname'):
            with self.subTest(value=value):
                self.assert_invalid('process', value)

    def test_valid_port(self):
        queries = qb.build_queries('port', '4444')['queries']
        self.assertEqual(len(queries), 3)
        for field in ('dst_port', 'src_port', 'port'):
            self.assertIn(field + '="4444"', queries[0]['query'])
        self.assertIn('uri=*', queries[2]['query'])

    def test_invalid_port(self):
        for value in ('0', '99999', 'abc'):
            with self.subTest(value=value):
                self.assert_invalid('port', value)

    def test_custom_index(self):
        pack = qb.build_queries('ip', '192.0.2.50', index='custom_security')
        for query in pack['queries']:
            self.assertIn('index=custom_security ', query['query'])

    def test_custom_time_range(self):
        pack = qb.build_queries('ip', '192.0.2.50', earliest='-2h', latest='-30m')
        for query in pack['queries']:
            self.assertIn('earliest=-2h latest=-30m ', query['query'])
        pack = qb.build_queries('ip', '192.0.2.50', earliest='2026-01-15T10:30:00Z')
        self.assertEqual(pack['time_range']['earliest'], '2026-01-15T10:30:00Z')

    def test_absolute_search_times_use_epoch_with_offset_conversion(self):
        utc = qb.build_queries('ip', '192.0.2.50', earliest='2026-01-15T10:30:00Z')
        offset = qb.build_queries('ip', '192.0.2.50', earliest='2026-01-15T12:30:00+02:00')
        naive = qb.build_queries('ip', '192.0.2.50', earliest='2026-01-15T10:30:00')
        self.assertEqual(utc['queries'], offset['queries'])
        self.assertEqual(utc['queries'], naive['queries'])
        for query in utc['queries']:
            self.assertIn('earliest=1768473000.0 latest=now', query['query'])

    def test_markdown_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'queries.md')
            self.assertEqual(qb.main(['ip', '192.0.2.50', '--output', path]), 0)
            with open(path, encoding='utf-8') as stream:
                content = stream.read()
        self.assertIn('# IOC Query Pack: ip 192.0.2.50', content)
        self.assertIn('**Generated:** ', content)
        self.assertIn('**Time range:** -1h to now', content)
        self.assertEqual(content.count('```spl'), 3)
        for number, query in enumerate(qb.build_queries('ip', '192.0.2.50')['queries'], 1):
            self.assertIn('### %d.' % number, content)
            self.assertIn(query['query'], content)
            self.assertIn(query['description'], content)

    def test_json_output_structure(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(qb.main(['ip', '192.0.2.50']), 0)
        pack = json.loads(stdout.getvalue())
        self.assertEqual(set(pack), {'ioc_type', 'ioc_value', 'index', 'time_range', 'queries'})
        self.assertEqual(pack['ioc_type'], 'ip')
        self.assertEqual(pack['ioc_value'], '192.0.2.50')
        self.assertEqual(pack['index'], 'team_security')
        self.assertEqual(pack['time_range'], {'earliest': '-1h', 'latest': 'now'})
        self.assertIsInstance(pack['queries'], list)
        for query in pack['queries']:
            self.assertEqual(set(query), {'id', 'description', 'query'})

    def test_cli_negative_relative_time(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(qb.main(['port', '4444', '--earliest', '-30m', '--latest', '-2m']), 0)
        self.assertEqual(json.loads(stdout.getvalue())['time_range'],
                         {'earliest': '-30m', 'latest': '-2m'})

    def test_cli_errors_are_json(self):
        for argv in ([], ['invalid', 'value'], ['ip', '192.0.2.50', '--index', 'x | head 1'],
                     ['ip', '192.0.2.50', '--earliest', 'yesterday'],
                     ['ip', '192.0.2.50', '--earliest', '2026-02-30T00:00:00Z']):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(SystemExit) as ctx:
                    qb.main(argv)
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn('error', json.loads(errors.getvalue()))

    def test_output_write_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(SystemExit) as ctx:
                    qb.main(['port', '4444', '--output', directory])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn('error', json.loads(errors.getvalue()))

    def test_quotes_and_backslashes_are_escaped(self):
        pack = qb.build_queries('process', 'C:\\Tools\\a"b.exe')
        self.assertIn('process="C:\\\\Tools\\\\a\\"b.exe"', pack['queries'][0]['query'])


if __name__ == '__main__':
    unittest.main()
