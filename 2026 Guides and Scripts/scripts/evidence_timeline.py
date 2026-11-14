#!/usr/bin/env python3
"""Merge JSON evidence into a chronological Markdown incident timeline.

Usage: python3 scripts/evidence_timeline.py INPUT [INPUT...] [--index NAME]
       [--output evidence_timeline.md] [--execute] [--json]
Without --execute, only a JSON plan with input sizes is printed. Naive ISO
 timestamps are interpreted as UTC; unknown timestamps sort after known ones.
Exit codes: 0 success, 1 timestamp warnings, 2 configuration or file error.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn


TIME_KEYS = ('timestamp', '_time', 'time', 'ts')
SOURCE_KEYS = ('source', 'host', 'src_ip', 'tool')
MESSAGE_KEYS = ('message', 'query', 'result', 'banner', 'note')


def fail(message) -> NoReturn:
    print(json.dumps({'status': 'error', 'error': message}), file=sys.stderr)
    sys.exit(2)


def parse_timestamp(value):
    """Return an aware UTC datetime, or None for an unknown timestamp."""
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, timezone.utc)
        if isinstance(value, str):
            try:
                return datetime.fromtimestamp(float(value), timezone.utc)
            except ValueError:
                stamp = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
                return stamp.replace(tzinfo=stamp.tzinfo or timezone.utc).astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    return None


def format_timestamp(stamp):
    return stamp.isoformat().replace('+00:00', 'Z') if stamp else 'UNKNOWN'


def first_value(event, keys, default=None):
    for key in keys:
        if key in event and event[key] is not None and event[key] != '':
            return event[key]
    return default


def normalize_event(event, filename):
    """Normalize key aliases, retaining a datetime for accurate stable sorting."""
    stamp = None
    for key in TIME_KEYS:
        stamp = parse_timestamp(event.get(key))
        if stamp is not None:
            break
    source = str(first_value(event, SOURCE_KEYS, Path(filename).stem))
    message = first_value(event, MESSAGE_KEYS)
    if message is None:
        message = ' | '.join(f'{key}={json.dumps(value, ensure_ascii=False)}'
                             for key, value in event.items()
                             if key not in TIME_KEYS + SOURCE_KEYS + MESSAGE_KEYS)
    if not isinstance(message, str):
        message = json.dumps(message, ensure_ascii=False)
    if len(message) > 200:
        message = message[:199] + '…'
    return {'timestamp': format_timestamp(stamp), 'source': source,
            'message': message, '_datetime': stamp}


def flatten_envelope(payload):
    """Recognize and flatten known tool output envelopes into a list of event dicts.

    Returns None if the payload does not match any known envelope shape.
    """
    if not isinstance(payload, dict):
        return None

    # splunk_poll: {time_utc, protocol, index, queries: {qid: [rows] | {error}}}
    queries = payload.get('queries')
    if isinstance(queries, dict):
        events = []
        envelope_time = payload.get('time_utc')
        for qid, value in queries.items():
            if isinstance(value, list):
                for row in value:
                    if isinstance(row, dict):
                        event = dict(row)
                        event.setdefault('source', qid)
                        events.append(event)
            elif isinstance(value, dict) and 'error' in value:
                events.append({'_time': envelope_time, 'source': qid,
                               'message': 'error: %s' % value['error']})
        return events

    # kali_watch: {protocol, mode: map|exposure|monitor, ...}
    mode = payload.get('mode')
    if mode in ('map', 'exposure', 'monitor'):
        time_utc = payload.get('time_utc')
        status = payload.get('status', 'unknown')

        if mode == 'monitor':
            events = []
            for p in payload.get('passes', []):
                if not isinstance(p, dict):
                    continue
                for check in p.get('checks', []):
                    if isinstance(check, dict):
                        event = dict(check)
                        event['_time'] = p.get('time_utc') or time_utc
                        event.setdefault('source', 'kali_watch:monitor')
                        event['message'] = ' | '.join(
                            f'{key}={json.dumps(check.get(key), ensure_ascii=False)}'
                            for key in ('target', 'ip', 'port', 'state', 'error'))
                        events.append(event)
            return events

        # map or exposure: one summary event per file
        if mode == 'map':
            results = payload.get('results', [])
            parts = []
            for r in results:
                if not isinstance(r, dict):
                    continue
                ports = ', '.join('%d/%s' % (p.get('port', '?'), p.get('state', '?'))
                                  for p in r.get('ports', []) if isinstance(p, dict))
                parts.append('%s [%s]' % (r.get('ip', '?'), ports))
            detail = '; '.join(parts)
        else:  # exposure
            findings = payload.get('findings', [])
            parts = []
            for f in findings:
                if not isinstance(f, dict):
                    continue
                parts.append('%s:%s %s' % (f.get('ip', '?'), f.get('port', '?'),
                                           f.get('status', '?')))
            detail = '; '.join(parts)

        return [{'_time': time_utc, 'source': 'kali_watch:%s' % mode,
                 'message': '%s: %s' % (status, detail or 'no data')}]

    return None


def load_events(path):
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        fail('Cannot read JSON evidence %s: %s' % (path, exc))
    if isinstance(payload, dict):
        flattened = flatten_envelope(payload)
        if flattened is not None:
            return [normalize_event(e, path) for e in flattened]
        payload = payload['events'] if 'events' in payload else [payload]
    if not isinstance(payload, list) or any(not isinstance(e, dict) for e in payload):
        fail('%s: expected an event object or an array of event objects' % path)
    return [normalize_event(event, path) for event in payload]


def markdown_cell(value):
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('\r', ' ').replace('\n', ' ')


def render_timeline(events, inputs, index=None):
    lines = ['# Evidence Timeline', '',
             '**Generated:** ' + format_timestamp(datetime.now(timezone.utc)),
             '**Sources:** ' + ', '.join(markdown_cell(Path(p).name) for p in inputs)]
    if index is not None:
        lines.append('**Index:** ' + markdown_cell(index))
    lines += ['**Event count:** %d' % len(events), '', '## Chronological events', '',
              '| # | Time (UTC) | Source | Message |',
              '|---|-----------|--------|---------|']
    for number, event in enumerate(events, 1):
        lines.append('| %d | %s | %s | %s |' % (
            number, event['timestamp'], markdown_cell(event['source']),
            markdown_cell(event['message'])))
    lines += ['', '## Summary by source', '',
              '| Source | Events | First seen | Last seen |',
              '|--------|--------|-----------|-----------|']
    for source in sorted({event['source'] for event in events}):
        group = [event for event in events if event['source'] == source]
        known = [event['_datetime'] for event in group if event['_datetime'] is not None]
        first = known[0].strftime('%H:%M:%S') if known else 'UNKNOWN'
        last = known[-1].strftime('%H:%M:%S') if known else 'UNKNOWN'
        lines.append('| %s | %d | %s | %s |' % (markdown_cell(source), len(group), first, last))
    return '\n'.join(lines) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', nargs='+', metavar='INPUT')
    parser.add_argument('--index')
    parser.add_argument('--output', default='evidence_timeline.md')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    paths = [Path(name) for name in args.inputs]
    output = Path(args.output)
    files = []
    for path in paths:
        try:
            if not path.is_file():
                fail('Input is not a file: %s' % path)
            files.append({'path': str(path), 'size_bytes': path.stat().st_size})
            if path.resolve() == output.resolve():
                fail('Output must not overwrite an input file: %s' % path)
        except OSError as exc:
            fail('Cannot inspect %s: %s' % (path, exc))
    if not args.execute:
        print(json.dumps({'mode': 'plan', 'status': 'ok', 'inputs': files,
                          'output': str(output), 'index': args.index}, indent=2))
        return 0
    events = []
    for path in paths:
        events.extend(load_events(path))
    events.sort(key=lambda event: (event['_datetime'] is None,
                                  event['_datetime'] or datetime.max.replace(tzinfo=timezone.utc)))
    warnings = sum(event['_datetime'] is None for event in events)
    try:
        output.write_text(render_timeline(events, paths, args.index), encoding='utf-8')
    except (OSError, ValueError) as exc:
        fail('Cannot write timeline %s: %s' % (output, exc))
    summary = {'mode': 'execute', 'status': 'warnings' if warnings else 'ok',
               'output': str(output), 'event_count': len(events), 'warning_count': warnings}
    if args.json:
        known = [event for event in events if event['_datetime'] is not None]
        summary.update({'time_range': {'start': known[0]['timestamp'] if known else None,
                                       'end': known[-1]['timestamp'] if known else None},
                        'sources': sorted({event['source'] for event in events})})
    print(json.dumps(summary, indent=2))
    return 1 if warnings else 0


if __name__ == '__main__':
    sys.exit(main())
