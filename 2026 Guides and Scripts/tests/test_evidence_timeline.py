"""Offline tests for scripts/evidence_timeline.py using temporary evidence files."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import evidence_timeline as et  # noqa: E402


class TimelineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / 'timeline.md'

    def write_events(self, payload, name='evidence.json'):
        path = self.root / name
        path.write_text(json.dumps(payload), encoding='utf-8')
        return path

    def run_main(self, paths, *flags):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = et.main([str(path) for path in paths] +
                         ['--output', str(self.output)] + list(flags))
        return rc, json.loads(buf.getvalue())

    def test_plan_prints_sizes_without_reading_or_writing(self):
        path = self.write_events([{'timestamp': 0}])
        with mock.patch.object(et, 'load_events') as load:
            rc, payload = self.run_main([path])
        self.assertEqual(rc, 0)
        self.assertEqual(payload['mode'], 'plan')
        self.assertEqual(payload['status'], 'ok')
        self.assertEqual(payload['inputs'], [
            {'path': str(path), 'size_bytes': path.stat().st_size}])
        self.assertEqual(payload['output'], str(self.output))
        self.assertFalse(self.output.exists())
        load.assert_not_called()

    def test_execute_writes_timeline(self):
        path = self.write_events({'events': [
            {'timestamp': '2026-01-15T09:12:33Z', 'source': 'splunk_poll',
             'message': 'Marker found'}], 'metadata': {}})
        rc, payload = self.run_main([path], '--execute', '--index', 'team_security')
        self.assertEqual(rc, 0)
        self.assertEqual(payload['event_count'], 1)
        text = self.output.read_text(encoding='utf-8')
        self.assertIn('# Evidence Timeline', text)
        self.assertIn('**Index:** team_security', text)
        self.assertIn('| 1 | 2026-01-15T09:12:33Z | splunk_poll | Marker found |', text)
        self.assertIn('| splunk_poll | 1 | 09:12:33 | 09:12:33 |', text)

    def test_normalization_aliases(self):
        for timestamp, source, message in zip(et.TIME_KEYS, et.SOURCE_KEYS,
                                              et.MESSAGE_KEYS):
            with self.subTest(timestamp=timestamp):
                event = et.normalize_event({timestamp: 0, source: 'sensor',
                                            message: 'observed'}, 'fallback.json')
                self.assertEqual(event['timestamp'], '1970-01-01T00:00:00Z')
                self.assertEqual(event['source'], 'sensor')
                self.assertEqual(event['message'], 'observed')
        self.assertEqual(et.normalize_event({'note': 'note'}, 'x.json')['message'], 'note')
        event = et.normalize_event({'timestamp': 0, 'a': 'one', 'b': 'two',
                                    'number': 4}, 'fallback.json')
        self.assertEqual(event['source'], 'fallback')
        self.assertEqual(event['message'], 'a="one" | b="two" | number=4')

    def test_timestamp_formats_and_missing(self):
        for stamp in ('2026-01-15T09:12:33Z', '2026-01-15T10:12:33+01:00',
                      '2026-01-15T09:12:33', 1768468353, '1768468353'):
            with self.subTest(stamp=stamp):
                self.assertEqual(et.normalize_event({'timestamp': stamp}, 'x.json')
                                 ['timestamp'], '2026-01-15T09:12:33Z')
        self.assertEqual(et.normalize_event({}, 'x.json')['timestamp'], 'UNKNOWN')
        for bad in ('bad', None, True, float('inf')):
            self.assertIsNone(et.parse_timestamp(bad))

    def test_empty_array(self):
        rc, payload = self.run_main([self.write_events([])], '--execute')
        self.assertEqual(rc, 0)
        self.assertEqual(payload['event_count'], 0)
        self.assertIn('**Event count:** 0', self.output.read_text())

    def assert_error(self, path, execute=True):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf), self.assertRaises(SystemExit) as ctx:
            self.run_main([path], *(['--execute'] if execute else []))
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(json.loads(buf.getvalue())['status'], 'error')
        self.assertFalse(self.output.exists())

    def test_invalid_json(self):
        path = self.root / 'invalid.json'
        path.write_text('{broken')
        self.assert_error(path)

    def test_nonexistent_file(self):
        for execute in (False, True):
            self.assert_error(self.root / 'missing.json', execute)

    def test_long_message_truncation(self):
        message = et.normalize_event({'message': 'x' * 201}, 'x')['message']
        self.assertEqual(len(message), 200)
        self.assertTrue(message.endswith('…'))
        self.assertEqual(et.normalize_event({'message': 'x' * 200}, 'x')
                         ['message'], 'x' * 200)

    def test_multiple_files_and_single_event_shape(self):
        first = self.write_events([{'timestamp': 20, 'message': 'later'}], 'first.json')
        second = self.write_events({'timestamp': 10, 'message': 'earlier'}, 'second.json')
        rc, payload = self.run_main([first, second], '--execute', '--json')
        self.assertEqual(rc, 0)
        self.assertEqual(payload['event_count'], 2)
        self.assertEqual(payload['sources'], ['first', 'second'])
        text = self.output.read_text()
        self.assertIn('**Sources:** first.json, second.json', text)
        self.assertLess(text.index('earlier'), text.index('later'))

    def test_json_summary(self):
        path = self.write_events([{'timestamp': 0, 'source': 'sensor'},
                                  {'timestamp': 60, 'source': 'sensor'}])
        rc, payload = self.run_main([path], '--execute', '--json')
        self.assertEqual(rc, 0)
        self.assertEqual(payload['event_count'], 2)
        self.assertEqual(payload['warning_count'], 0)
        self.assertEqual(payload['sources'], ['sensor'])
        self.assertEqual(payload['time_range'], {
            'start': '1970-01-01T00:00:00Z', 'end': '1970-01-01T00:01:00Z'})

    def test_chronological_stable_sort(self):
        first = self.write_events([{'timestamp': 2, 'message': 'tie-first'},
                                   {'timestamp': 1, 'message': 'earliest'},
                                   {'timestamp': 2, 'message': 'tie-second'}])
        second = self.write_events([{'timestamp': 2, 'message': 'tie-third'},
                                    {'message': 'unknown'}], 'second.json')
        rc, payload = self.run_main([first, second], '--execute')
        self.assertEqual(rc, 1)
        text = self.output.read_text()
        positions = [text.index(message) for message in
                     ('earliest', 'tie-first', 'tie-second', 'tie-third', 'unknown')]
        self.assertEqual(positions, sorted(positions))

    def test_warning_count_all_unknown(self):
        path = self.write_events([{}, {'timestamp': 'bad'}, {'timestamp': None}])
        rc, payload = self.run_main([path], '--execute', '--json')
        self.assertEqual(rc, 1)
        self.assertEqual(payload['warning_count'], 3)
        self.assertEqual(payload['time_range'], {'start': None, 'end': None})
        self.assertEqual(self.output.read_text().count('| UNKNOWN |'), 4)

    def test_rejects_invalid_event_shapes(self):
        for payload in (None, 42, [1], {'events': {}}, {'events': [None]}):
            with self.subTest(payload=payload):
                self.assert_error(self.write_events(payload))

    # --- Tool envelope flattening -------------------------------------------

    def test_flattens_splunk_poll_queries_envelope(self):
        """Each query batch row becomes its own event with its own _time."""
        payload = {
            'time_utc': '2024-01-15T10:00:00Z',
            'protocol': 'iot',
            'index': 'main',
            'queries': {
                'q1': [
                    {'_time': 1705312800, 'src_ip': '10.0.0.1', 'message': 'hit A'},
                    {'_time': 1705312900, 'src_ip': '10.0.0.2', 'message': 'hit B'},
                ],
                'q2': {'error': 'job failed'},
            },
        }
        path = self.write_events(payload)
        rc, summary = self.run_main([path], '--execute', '--json')
        self.assertEqual(rc, 0)
        self.assertEqual(summary['event_count'], 3)
        text = self.output.read_text()
        self.assertIn('hit A', text)
        self.assertIn('hit B', text)
        self.assertIn('q1', text)
        self.assertIn('job failed', text)
        # Rows keep their own timestamps, not the envelope time.
        self.assertEqual(summary['time_range']['start'], '2024-01-15T10:00:00Z')
        self.assertEqual(summary['time_range']['end'], '2024-01-15T10:01:40Z')

    def test_flattens_kali_watch_map_envelope(self):
        payload = {
            'protocol': 'iot', 'mode': 'map', 'status': 'ok',
            'time_utc': '2024-01-15T11:00:00Z',
            'results': [{'ip': '192.168.1.10',
                         'ports': [{'port': 22, 'state': 'open'},
                                   {'port': 80, 'state': 'closed'}]}],
        }
        path = self.write_events(payload)
        rc, summary = self.run_main([path], '--execute')
        self.assertEqual(rc, 0)
        self.assertEqual(summary['event_count'], 1)
        text = self.output.read_text()
        self.assertIn('192.168.1.10', text)
        self.assertIn('22/open', text)
        self.assertIn('kali_watch:map', text)

    def test_flattens_kali_watch_exposure_envelope(self):
        payload = {
            'protocol': 'iot', 'mode': 'exposure', 'status': 'ok',
            'time_utc': '2024-01-15T12:00:00Z',
            'findings': [{'target': 't1', 'ip': '192.168.1.10',
                          'port': 8080, 'status': 'observed', 'banner': None}],
        }
        path = self.write_events(payload)
        rc, summary = self.run_main([path], '--execute')
        self.assertEqual(rc, 0)
        self.assertEqual(summary['event_count'], 1)
        text = self.output.read_text()
        self.assertIn('192.168.1.10:8080 observed', text)
        self.assertIn('kali_watch:exposure', text)

    def test_flattens_kali_watch_monitor_envelope(self):
        payload = {
            'protocol': 'iot', 'mode': 'monitor', 'time_utc': '2024-01-15T13:00:00Z',
            'passes': [
                {'time_utc': '2024-01-15T13:00:00Z',
                 'checks': [{'port': 443, 'state': 'up'}]},
                {'time_utc': '2024-01-15T13:05:00Z',
                 'checks': [{'port': 443, 'state': 'down'}]},
            ],
        }
        path = self.write_events(payload)
        rc, summary = self.run_main([path], '--execute')
        self.assertEqual(rc, 0)
        self.assertEqual(summary['event_count'], 2)
        text = self.output.read_text()
        self.assertIn('port=443', text)
        self.assertIn('state="down"', text)

    def test_flattening_mixed_with_plain_event_files(self):
        """Envelope files and plain event arrays merge into one timeline."""
        poll = self.write_events(
            {'time_utc': '2024-01-15T10:00:00Z',
             'queries': {'q1': [{'_time': 1705312800, 'message': 'poll row'}]}},
            name='poll.json')
        plain = self.write_events([{'timestamp': 1705312900, 'source': 'manual',
                                    'message': 'manual note'}], name='plain.json')
        rc, summary = self.run_main([poll, plain], '--execute')
        self.assertEqual(rc, 0)
        self.assertEqual(summary['event_count'], 2)
        text = self.output.read_text()
        self.assertIn('poll row', text)
        self.assertIn('manual note', text)

    def test_markdown_escaping(self):
        self.assertEqual(et.markdown_cell('a|b\nc<d>'), 'a&#124;b c&lt;d&gt;')

    def test_rejects_output_overwriting_input(self):
        path = self.write_events([])
        original = path.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            et.main([str(path), '--output', str(path), '--execute'])
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
