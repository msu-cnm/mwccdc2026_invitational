#!/usr/bin/env python3
"""Generate offline Splunk IOC query packs as JSON or Markdown."""

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import re
import sys
from typing import NoReturn


IOC_TYPES = ('ip', 'domain', 'hash', 'url', 'process', 'port')


def fail(message) -> NoReturn:
    print(json.dumps({'status': 'invalid_configuration', 'error': message}), file=sys.stderr)
    sys.exit(2)


def validate_ioc(ioc_type, value):
    if ioc_type not in IOC_TYPES:
        fail('unknown IOC type: %s' % ioc_type)
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        fail('IOC value must be a non-empty string without control characters')
    if ioc_type == 'ip':
        try:
            ipaddress.ip_address(value)
        except ValueError:
            fail('invalid IP address')
    elif ioc_type == 'domain':
        if not re.fullmatch(r'[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+', value):
            fail('invalid domain')
    elif ioc_type == 'hash':
        if len(value) not in (32, 40, 64) or not re.fullmatch(r'[a-fA-F0-9]+', value):
            fail('hash must be 32, 40, or 64 hexadecimal characters')
    elif ioc_type == 'url':
        if not value.startswith(('http://', 'https://')):
            fail('URL must start with http:// or https://')
    elif ioc_type == 'port':
        if not re.fullmatch(r'[0-9]{1,5}', value) or not 1 <= int(value) <= 65535:
            fail('port must be an integer from 1 to 65535')
    return value


def validate_time(value):
    if value == 'now' or re.fullmatch(r'[+-]?\d+(?:s|m|h|d|w|mon|q|y)(?:@(?:s|m|h|d|w|mon|q|y))?', value):
        return value
    if re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', value):
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            # SPL earliest/latest accepts epoch seconds. Bare ISO timestamps
            # depend on a matching timeformat and are not portable search terms.
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return str(parsed.timestamp())
        except ValueError:
            pass
    fail('time must be now, relative (e.g. -30m), or ISO 8601')


def quote(value):
    """Quote a Splunk search value without permitting search syntax injection."""
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('*', '\\*') + '"'


def build_queries(ioc_type, ioc_value, index='team_security', earliest='-1h', latest='now'):
    validate_ioc(ioc_type, ioc_value)
    if not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_-]*', index):
        fail('invalid index name')
    search_earliest = validate_time(earliest)
    search_latest = validate_time(latest)
    prefix = 'index=%s earliest=%s latest=%s ' % (index, search_earliest, search_latest)
    exact = quote(ioc_value)
    contains = '"*' + quote(ioc_value)[1:-1] + '*"'

    def fields(names, value=exact):
        return '(' + ' OR '.join('%s=%s' % (name, value) for name in names.split()) + ')'

    common = '_time, host, src_ip, dst_ip, uri, process'
    if ioc_type == 'ip':
        pair = fields('src_ip dst_ip')
        templates = [
            ('any_field', 'Any event referencing this IP in common fields', fields('src_ip dst_ip host src dst'), common),
            ('web_access', 'Web access from or to this IP', pair + ' (uri=* OR user_agent=*)', '_time, src_ip, dst_ip, uri, user_agent, status'),
            ('outbound', 'Outbound connections involving this IP', pair + ' eventtype=outbound', '_time, src_ip, dst_ip, dst_port, process')]
    elif ioc_type == 'domain':
        templates = [
            ('any_field', 'Any event referencing this domain', fields('host uri dst_domain src_domain', contains), common),
            ('web_access', 'Web access referencing this domain', 'uri=' + contains, '_time, host, uri, status'),
            ('dns_lookups', 'DNS lookups for this domain', fields('query dns_query'), '_time, host, query, dns_query, src_ip')]
    elif ioc_type == 'hash':
        templates = [
            ('any_field', 'Any event referencing this file hash', fields('hash file_hash md5 sha1 sha256 filename'), '_time, host, hash, file_hash, md5, sha1, sha256, filename'),
            ('process', 'Processes referencing this hash', fields('process command_line', contains), '_time, host, process, command_line')]
    elif ioc_type == 'url':
        templates = [
            ('any_field', 'Any event referencing this URL', fields('uri url referrer'), common),
            ('web_access', 'Web access referencing this URL', 'uri=' + contains, '_time, src_ip, dst_ip, uri, status'),
            ('download', 'Download commands referencing this URL', '(process="certutil.exe" OR process="powershell.exe") command_line=' + contains, '_time, host, process, command_line')]
    elif ioc_type == 'process':
        templates = [
            ('any_field', 'Any event referencing this process', '(' + 'process=%s OR parent_process=%s OR command_line=%s' % (exact, exact, contains) + ')', '_time, host, process, parent_process, command_line'),
            ('children', 'Children of this process', 'parent_process=' + exact, '_time, host, process, parent_process, command_line'),
            ('network', 'Network activity from this process', 'process=' + exact + ' dst_ip=*', '_time, host, process, src_ip, dst_ip, dst_port')]
    else:
        templates = [
            ('any_field', 'Any event referencing this port', fields('dst_port src_port port'), '_time, host, src_ip, dst_ip, src_port, dst_port, port'),
            ('connections', 'Connections involving this port', fields('dst_port src_port'), '_time, src_ip, dst_ip, src_port, dst_port, process'),
            ('web', 'Web access to this port', 'dst_port=' + exact + ' uri=*', '_time, src_ip, dst_ip, dst_port, uri, status')]
    return {'ioc_type': ioc_type, 'ioc_value': ioc_value, 'index': index,
            'time_range': {'earliest': earliest, 'latest': latest},
            'queries': [{'id': ioc_type + '_' + name, 'description': description,
                         'query': prefix + search + ' | table ' + columns + ' | head 200'}
                        for name, description, search, columns in templates]}


def render_markdown(pack):
    lines = ['# IOC Query Pack: %s %s' % (pack['ioc_type'], pack['ioc_value']), '',
             '**Index:** ' + pack['index'],
             '**Time range:** {earliest} to {latest}'.format(**pack['time_range']),
             '**Generated:** ' + datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
             '', '## Queries', '']
    for number, query in enumerate(pack['queries'], 1):
        title = query['id'][len(pack['ioc_type']) + 1:].replace('_', ' ').capitalize()
        lines.extend(['### %d. %s' % (number, title), '*' + query['description'] + '*',
                      '', '```spl', query['query'], '```', ''])
    return '\n'.join(lines)


class QueryParser(argparse.ArgumentParser):
    def error(self, message):
        fail(message)


def main(argv=None):
    parser = QueryParser(description=__doc__)
    parser.add_argument('ioc_type', choices=IOC_TYPES)
    parser.add_argument('ioc_value')
    parser.add_argument('--index', default='team_security')
    parser.add_argument('--earliest', default='-1h')
    parser.add_argument('--latest', default='now')
    parser.add_argument('--output')
    # argparse otherwise mistakes negative relative times for option names.
    argv = list(sys.argv[1:] if argv is None else argv)
    for pos in range(len(argv) - 2, -1, -1):
        if argv[pos] in ('--earliest', '--latest') and re.fullmatch(r'-\d+\w+(?:@\w+)?', argv[pos + 1]):
            argv[pos:pos + 2] = [argv[pos] + '=' + argv[pos + 1]]
    args = parser.parse_args(argv)
    pack = build_queries(args.ioc_type, args.ioc_value, args.index, args.earliest, args.latest)
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as stream:
                stream.write(render_markdown(pack))
        except (OSError, ValueError) as exc:
            fail('could not write output: %s' % exc)
    else:
        print(json.dumps(pack, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
