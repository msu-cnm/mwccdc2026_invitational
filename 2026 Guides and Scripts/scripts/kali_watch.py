#!/usr/bin/env python3
"""Kali workstation tooling for authorized network mapping, exposure assessment, and service monitoring.

Modes: map (Nmap TCP connect scan), exposure (lightweight service/version detection),
monitor (bounded TCP and optional HTTP(S) checks). Every mode defaults to a readable
plan; --execute performs probes only after complete configuration validation.

Exit codes: 0 = successful plan or healthy completed checks; 1 = unhealthy findings;
2 = invalid configuration or collection error (collection errors take precedence).

Observation only: open ports and version strings are exposure leads, not confirmed
vulnerabilities. TCP success does not establish authenticated scoring success.
"""
import argparse
import http.client
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from typing import NoReturn
from urllib import error, request
from urllib.parse import urlsplit

PROTOCOL = 'kali-watch/1.0'
MAX_REPEAT = 20
TCP_STATES = ('open', 'closed', 'filtered', 'unknown')


def now_utc():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def fail(message) -> NoReturn:
    print(json.dumps({'status': 'invalid_configuration', 'error': message}), file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Configuration validation: exact IPs only; no CIDRs, hostnames, or placeholders.
# ---------------------------------------------------------------------------

IP_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')


def valid_ip(value):
    if not isinstance(value, str) or not IP_RE.match(value):
        return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def is_num(value, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return isinstance(value, int) if integer else True


def validate_target(entry, where, index):
    label = '%s[%d]' % (where, index)
    if not isinstance(entry, dict):
        fail('%s must be an object' % label)
    if set(entry) != {'id', 'ip', 'ports', 'service_checks_enabled'}:
        fail('%s must contain exactly id, ip, ports, service_checks_enabled' % label)
    tid = entry.get('id')
    if not isinstance(tid, str) or not re.match(r'^[A-Za-z0-9._-]+$', tid):
        fail('%s.id must be a simple identifier' % label)
    ip = entry.get('ip')
    if not valid_ip(ip):
        fail('%s.ip must be an exact IPv4 address (no CIDR, hostname, or placeholder): %r' % (label, ip))
    reason = protected_ip(ip)
    if reason:
        fail('%s.ip %s is protected: %s' % (label, ip, reason))
    ports = entry.get('ports')
    if not isinstance(ports, list) or not ports:
        fail('%s.ports must be a nonempty list of integers 1-65535' % label)
    seen = set()
    for port in ports:
        if not is_num(port, integer=True) or not (1 <= port <= 65535):
            fail('%s has invalid port: %r' % (label, port))
        if port in seen:
            fail('%s has duplicate port %d' % (label, port))
        seen.add(port)
    if not isinstance(entry.get('service_checks_enabled'), bool):
        fail('%s.service_checks_enabled must be a boolean' % label)
    return {'id': tid, 'ip': ip, 'ports': sorted(seen),
            'service_checks_enabled': entry['service_checks_enabled']}


def validate_http_check(entry, index):
    label = 'http_checks[%d]' % index
    if not isinstance(entry, dict):
        fail('%s must be an object' % label)
    allowed = {'url', 'expected_status', 'expected_content', 'sni_hostname'}
    if not set(entry) <= allowed or 'url' not in entry:
        fail('%s must contain url and at most expected_status/expected_content/'
             'sni_hostname' % label)
    url = entry['url']
    if not isinstance(url, str):
        fail('%s.url must be a string' % label)
    # Credential-bearing URLs are rejected outright; bodies are never stored.
    if re.match(r'^https?://[^/@]+@', url, re.IGNORECASE):
        fail('%s.url must not contain credentials' % label)
    if '//' not in url:
        fail('%s.url must be an absolute http(s) URL' % label)
    scheme = url.split('://', 1)[0].lower()
    if scheme not in ('http', 'https'):
        fail('%s.url must use the http or https scheme' % label)
    host = url.split('://', 1)[1].split('/', 1)[0]
    if '@' in host:
        fail('%s.url must not contain credentials' % label)
    expected_status = entry.get('expected_status')
    if expected_status is not None and (
            not is_num(expected_status, integer=True) or not (100 <= expected_status <= 599)):
        fail('%s.expected_status must be an integer 100-599' % label)
    expected_content = entry.get('expected_content')
    if expected_content is not None and not isinstance(expected_content, str):
        fail('%s.expected_content must be a string' % label)
    sni_hostname = entry.get('sni_hostname')
    if sni_hostname is not None:
        if not isinstance(sni_hostname, str) or not re.match(
                r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]'
                r'([A-Za-z0-9-]*[A-Za-z0-9])?)*$', sni_hostname):
            fail('%s.sni_hostname must be a hostname string' % label)
    return {'url': url, 'expected_status': expected_status,
            'expected_content': expected_content,
            'sni_hostname': sni_hostname}


PROTECTED_NETS = (
    ('172.17.0.', 'Kali/VyOS internal network (core infrastructure)'),
    ('172.31.', 'Core infrastructure and shared egress'),
    ('172.16.0.', 'Router transit network'),
    ('172.20.240.200', 'Palo Alto management'),
    ('172.20.240.254', 'Palo Alto inside interface'),
)


def protected_ip(ip):
    """Core infrastructure and shared egress must never be scan targets."""
    for prefix, reason in PROTECTED_NETS:
        if ip.startswith(prefix):
            return reason
    return None


def load_config(path):
    try:
        with open(path, 'r') as f:
            raw = json.loads(f.read())
    except (OSError, ValueError) as e:
        fail('cannot read configuration: %s' % type(e).__name__)
    if not isinstance(raw, dict):  # fail() exits; guard for static analysis
        fail('configuration must be a JSON object')
    team = raw.get('team')
    if team is not None and (isinstance(team, bool) or not isinstance(team, int)
                             or not (1 <= team <= 20)):
        fail('team must be null or an integer 1-20; got %r' % (team,))
    for key in ('internal_targets', 'public_targets', 'http_checks'):
        if not isinstance(raw.get(key), list):
            fail('%s must be a list' % key)
    internal = [validate_target(e, 'internal_targets', i)
                for i, e in enumerate(raw.get('internal_targets', []))]
    public = [validate_target(e, 'public_targets', i)
              for i, e in enumerate(raw.get('public_targets', []))]
    if team is None and public:
        fail('public targets require an explicit team number 1-20')
    if team is not None and not internal:
        fail('internal targets must be listed even when using public targets')
    http_checks = [validate_http_check(e, i) for i, e in enumerate(raw.get('http_checks', []))]
    timeouts = raw.get('timeouts')
    if not isinstance(timeouts, dict):
        fail('timeouts must be an object with connect_seconds and read_seconds')
    connect = timeouts.get('connect_seconds')
    read = timeouts.get('read_seconds')
    if not is_num(connect) or not (1 <= connect <= 60) or not is_num(read) or not (1 <= read <= 60):
        fail('timeouts.connect_seconds and timeouts.read_seconds must be numbers in 1-60')
    limits = raw.get('probe_limits')
    if not isinstance(limits, dict):
        fail('probe_limits must be an object with max_parallel and delay_ms')
    parallel = limits.get('max_parallel')
    delay = limits.get('delay_ms')
    if not is_num(parallel, integer=True) or not (1 <= parallel <= 8):
        fail('probe_limits.max_parallel must be an integer 1-8')
    if not is_num(delay, integer=True) or not (0 <= delay <= 60000):
        fail('probe_limits.delay_ms must be an integer 0-60000')
    scope = raw.get('target_scope', 'internal' if not public else None)
    if scope not in ('internal', 'public'):
        fail('target_scope must explicitly select internal or public')
    for target in public:
        if target['ip'] not in public_address_hint(team).values():
            fail('public target must be a fixed server address for the assigned team')
    targets = internal if scope == 'internal' else public
    if not targets:
        fail('selected target scope must not be empty')
    for check in http_checks:
        try:
            parsed = urlsplit(check['url'])
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            if (parsed.username is not None or parsed.password is not None or
                    parsed.fragment or not valid_ip(parsed.hostname) or
                    any(ord(c) <= 32 for c in check['url'])):
                fail('HTTP URL must use an exact scoped IP without credentials or fragments')
            if not any(t['ip'] == parsed.hostname and port in t['ports'] and
                       t['service_checks_enabled'] for t in targets):
                fail('HTTP endpoint must match an enabled target and configured port in selected scope')
        except ValueError:
            fail('invalid HTTP URL or port')
    # One shared validated target list across all modes.
    ids = [t['id'] for t in targets]
    if len(ids) != len(set(ids)):
        fail('target ids must be unique across internal and public targets')
    return {
        'team': team,
        'targets': targets,
        'http_checks': http_checks,
        'timeouts': {'connect_seconds': connect, 'read_seconds': read},
        'probe_limits': {'max_parallel': parallel, 'delay_ms': delay},
    }


def public_address_hint(team):
    if team is None:
        return None
    n = 20 + team
    return {'rocky-ecom': '172.25.%d.10' % n, 'ubuntu-email': '172.25.%d.15' % n,
            'debian-splunk': '172.25.%d.20' % n, '2022-ad': '172.25.%d.100' % n,
            '2019-mssql': '172.25.%d.120' % n}


def plan_document(mode, cfg, execute=False):
    """Readable plan shared by all modes; printed before any probe."""
    doc = {
        'protocol': PROTOCOL,
        'mode': mode,
        'time_utc': now_utc(),
        'host': platform.node(),
        'execute': bool(execute),
        'team': cfg['team'],
        'targets': cfg['targets'],
        'http_checks': [{k: v for k, v in c.items() if k != 'expected_content'}
                        for c in cfg['http_checks']],
        'timeouts': cfg['timeouts'],
        'probe_limits': cfg['probe_limits'],
        'scope_note': (
            'Authorized team hosts only. Never scan other teams, officials, core '
            'infrastructure, shared egress, or Red Team assets. Open ports and '
            'version strings are exposure leads, not confirmed vulnerabilities; '
            'verify with package/build and vendor advisories before acting.'),
    }
    if cfg['team'] is not None:
        doc['public_address_hints'] = public_address_hint(cfg['team'])
    return doc


def print_plan(mode, cfg, execute):
    print(json.dumps(plan_document(mode, cfg, execute), indent=2))


def finish(status_code, payload):
    """Print result JSON and exit with the documented code."""
    print(json.dumps(payload, indent=2))
    sys.exit(status_code)


# ---------------------------------------------------------------------------
# map: external Nmap, unprivileged TCP connect scan, argument list, no shell.
# ---------------------------------------------------------------------------

def build_nmap_command(target, cfg):
    # Unprivileged TCP connect scan (-sT); explicit configured ports only.
    args = ['nmap', '-sT'] + ['-p', ','.join(str(p) for p in target['ports'])]
    args += ['-n', '-Pn',  # no DNS resolution; host up/down is not assumed
             '--max-retries', '2', '--host-timeout', '30s',
             '--max-parallelism', str(cfg['probe_limits']['max_parallel']),
             '--scan-delay', str(cfg['probe_limits']['delay_ms']) + 'ms',
             '--max-rate', '10',
             '-oX', '-']
    args.append(target['ip'])
    return args


def parse_nmap_xml(text, target_ip, configured_ports=None):
    """Parse Nmap XML into distinct open/closed/filtered/unknown states."""
    root = ET.fromstring(text)  # raises on malformed XML (collection error)
    ports = []
    seen = set()
    for host in root.iter('host'):
        addr = host.find('address')
        if addr is None or addr.get('addr') != target_ip:
            continue
        for p in host.iter('port'):
            state = p.find('state')
            name = state.get('state') if state is not None else 'unknown'
            if name not in TCP_STATES:
                name = 'unknown'
            try:
                portid = int(p.get('portid'))
            except (TypeError, ValueError):
                raise ValueError('nmap XML port entry has no valid portid')
            if portid in seen:
                continue
            seen.add(portid)
            entry = {'port': portid, 'protocol': p.get('protocol'),
                     'state': name}
            svc = p.find('service')
            if svc is not None and svc.get('name'):
                entry['service'] = svc.get('name')
            ports.append(entry)
    if root.tag != 'nmaprun' or not any(
            a.get('addr') == target_ip for h in root.iter('host') for a in h.findall('address')):
        raise ValueError('nmap XML missing target host')
    if configured_ports:
        # Nmap may compress closed/filtered ports into extraports summaries.
        missing = set(configured_ports) - seen
        summaries = [e for h in root.iter('host')
                     if any(a.get('addr') == target_ip for a in h.findall('address'))
                     for e in h.iter('extraports')]
        state = 'unknown'
        if len(summaries) == 1 and int(summaries[0].get('count', '0')) == len(missing):
            candidate = summaries[0].get('state')
            state = candidate if candidate in TCP_STATES else 'unknown'
        ports.extend({'port': p, 'protocol': 'tcp', 'state': state} for p in missing)
    ports.sort(key=lambda e: e['port'])
    # Discovery failure is a collection error, never host absence.
    if not ports:
        raise ValueError('nmap XML contained no port entry for %s' % target_ip)
    return {'ip': target_ip, 'ports': ports}


def run_map(cfg):
    """Map mode: one Nmap pass per target; collection errors exit 2."""
    results = []
    errors = []
    nmap_path = shutil.which('nmap')
    if not nmap_path:
        finish(2, {'protocol': PROTOCOL, 'mode': 'map', 'status': 'collection_error',
                   'error': 'nmap binary not found on PATH'})
    for target in cfg['targets']:
        command = build_nmap_command(target, cfg)
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=90)
        except (subprocess.TimeoutExpired, OSError) as e:
            errors.append({'target': target['id'], 'error': type(e).__name__})
            continue
        if proc.returncode != 0:
            errors.append({'target': target['id'],
                           'error': 'nmap exit %d' % proc.returncode})
            continue
        try:
            results.append(parse_nmap_xml(proc.stdout, target['ip'], target['ports']))
        except (ET.ParseError, ValueError) as e:
            errors.append({'target': target['id'], 'error': str(e)})
    if errors:
        finish(2, {'protocol': PROTOCOL, 'mode': 'map',
                   'status': 'collection_error', 'results': results,
                   'errors': errors})
    finish(0, {'protocol': PROTOCOL, 'mode': 'map', 'status': 'ok',
               'results': results,
               'note': ('open/closed/filtered/unknown are distinct observations; '
                        'a failed discovery is not proof the host is absent.')})


# ---------------------------------------------------------------------------
# exposure: lightweight service/version detection on configured targets only.
# ---------------------------------------------------------------------------

def probe_banner(ip, port, timeout):
    """Single bounded TCP connect with a short banner read. No auth, no exploit."""
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        data = b''
        deadline = time.monotonic() + timeout
        try:
            while len(data) < 256:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                chunk = sock.recv(256 - len(data))
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass
        return data.decode('utf-8', 'replace').strip()[:200]
    finally:
        sock.close()


def run_exposure(cfg):
    findings = []
    errors = []
    for target in cfg['targets']:
        if not target['service_checks_enabled']:
            findings.append({'target': target['id'], 'ip': target['ip'],
                             'status': 'skipped',
                             'reason': 'service_checks_enabled is false; enable only after confirming port assignments'})
            continue
        for port in target['ports']:
            try:
                banner = probe_banner(target['ip'], port, cfg['timeouts']['connect_seconds'])
                findings.append({'target': target['id'], 'ip': target['ip'],
                                 'port': port, 'status': 'observed',
                                 'banner': banner or None})
            except (OSError, socket.timeout) as e:
                errors.append({'target': target['id'], 'ip': target['ip'], 'port': port,
                               'error': type(e).__name__})
            time.sleep(cfg['probe_limits']['delay_ms'] / 1000.0)
    if errors:
        finish(2, {'protocol': PROTOCOL, 'mode': 'exposure',
                   'status': 'collection_error', 'findings': findings,
                   'errors': errors})
    finish(0, {'protocol': PROTOCOL, 'mode': 'exposure', 'status': 'ok',
               'findings': findings,
               'note': ('Version strings are investigation leads only. Do not infer '
                        'CVEs or patch status from banners; backported fixes make '
                        'banner claims unreliable. Verify with package/build and '
                        'vendor advisories.')})


# ---------------------------------------------------------------------------
# monitor: bounded TCP checks plus optional HTTP(S); one pass by default.
# ---------------------------------------------------------------------------

def tcp_check(ip, port, timeout):
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            latency_ms = int((time.monotonic() - start) * 1000)
            return 'up', latency_ms, None
    except (socket.timeout, OSError) as e:
        return 'down', int((time.monotonic() - start) * 1000), type(e).__name__


class _NoRedirectHandler(request.HTTPRedirectHandler):
    """Raise HTTPError on any 3xx so the probe never reaches the redirect target."""

    def http_error_301(self, req, fp, code, msg, hdrs):
        raise error.HTTPError(req.full_url, code, msg, hdrs, fp)

    def http_error_302(self, req, fp, code, msg, hdrs):
        raise error.HTTPError(req.full_url, code, msg, hdrs, fp)

    def http_error_303(self, req, fp, code, msg, hdrs):
        raise error.HTTPError(req.full_url, code, msg, hdrs, fp)

    def http_error_307(self, req, fp, code, msg, hdrs):
        raise error.HTTPError(req.full_url, code, msg, hdrs, fp)

    def http_error_308(self, req, fp, code, msg, hdrs):
        raise error.HTTPError(req.full_url, code, msg, hdrs, fp)


class _ScopedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, server_hostname=None, **kwargs):
        self._scoped_hostname = server_hostname
        super().__init__(*args, **kwargs)

    def connect(self):
        # Connect only to the configured IP; the hostname is used solely for
        # TLS SNI and certificate verification, never DNS resolution.
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self._scoped_hostname or self.host)


class _ContextSniHandler(request.HTTPSHandler):
    """HTTPSHandler that carries an explicit SSL context and, optionally, a
    custom SNI hostname for the TLS handshake (required for IP-scoped HTTPS)."""

    def __init__(self, context=None, sni_hostname=None):
        super().__init__(context=context)
        self._sni = sni_hostname

    def https_open(self, req):
        kwargs = {'context': self._context}
        if self._sni:
            kwargs['server_hostname'] = self._sni
        return self.do_open(_ScopedHTTPSConnection, req, **kwargs)

    https_request = request.AbstractHTTPHandler.do_request_


def _build_opener(context=None, sni_hostname=None):
    """Build an opener that never follows redirects and (optionally) uses a
    custom SNI hostname for the TLS handshake."""
    handlers = [request.ProxyHandler({}), _NoRedirectHandler()]
    if context is not None or sni_hostname:
        handlers.append(_ContextSniHandler(context=context, sni_hostname=sni_hostname))
    return request.build_opener(*handlers)


def _open(req, timeout, context, sni_hostname=None):
    """Open an HTTP(S) request: TLS verified by default, no redirects followed.

    When ``sni_hostname`` is given the TLS handshake advertises that name,
    which is required for IP-scoped HTTPS checks whose certificate is issued
    to a virtual-host name rather than the IP address.
    """
    return _build_opener(context=context, sni_hostname=sni_hostname).open(req, timeout=timeout)


def http_check(check, cfg):
    """GET with TLS verified by default; redirects are never followed;
    no credentials in the URL; response body is not stored."""
    url = check['url']
    timeout = cfg['timeouts']['read_seconds']
    sni = check.get('sni_hostname')
    req = request.Request(url, method='GET',
                          headers={'User-Agent': PROTOCOL, 'Accept': '*/*'})
    if sni:
        req.add_header('Host', sni + (':' + str(urlsplit(url).port) if urlsplit(url).port else ''))
    context = None
    if url.lower().startswith('https://'):
        context = ssl.create_default_context()  # certificate verified by default
    start = time.monotonic()
    try:
        with _open(req, timeout, context, sni) as resp:
            body = resp.read(1024)  # bounded read; never stored in output
            latency_ms = int((time.monotonic() - start) * 1000)
            status = resp.status
            final_url = resp.geturl()
    except (error.HTTPError) as e:
        latency_ms = int((time.monotonic() - start) * 1000)
        status = e.code
        final_url = url
        body = b''
    except (error.URLError, ssl.SSLError, socket.timeout, OSError) as e:
        return {'url': url, 'state': 'error',
                'error': type(e).__name__,
                'latency_ms': int((time.monotonic() - start) * 1000)}
    # Never follow redirects to unconfigured destinations: report, do not chase.
    redirected = final_url.rstrip('/') != url.rstrip('/') or (300 <= status < 400)
    state = 'ok'
    if redirected:
        state = 'redirect'
    elif check['expected_status'] is not None and status != check['expected_status']:
        state = 'mismatch'
    elif check['expected_content'] is not None and \
            check['expected_content'] not in body.decode('utf-8', 'replace'):
        state = 'mismatch'
    result = {'url': url, 'state': state, 'status': status,
              'latency_ms': latency_ms, 'redirected': redirected}
    if sni:
        result['sni_hostname'] = sni
    if redirected:
        result['note'] = ('response came from a different destination; the probe '
                          'does not follow redirects outside the configured scope')
    return result


def run_monitor(cfg, repeat=1):
    """Bounded TCP + optional HTTP(S) checks. One pass by default."""
    if not (is_num(repeat, integer=True) and 1 <= repeat <= MAX_REPEAT):
        fail('monitor --repeat must be an integer 1-%d' % MAX_REPEAT)
    passes = []
    for _ in range(repeat):
        checks = []
        errors = []
        for target in cfg['targets']:
            if not target['service_checks_enabled']:
                continue
            for port in target['ports']:
                state, latency_ms, err = tcp_check(
                    target['ip'], port, cfg['timeouts']['connect_seconds'])
                entry = {'target': target['id'], 'ip': target['ip'], 'port': port,
                         'state': state, 'latency_ms': latency_ms}
                if err:
                    entry['error'] = err
                checks.append(entry)
                time.sleep(cfg['probe_limits']['delay_ms'] / 1000.0)
        for check in cfg['http_checks']:
            result = http_check(check, cfg)
            checks.append(result)
        passes.append({'time_utc': now_utc(), 'checks': checks})
    # Aggregate: any down/error is unhealthy; collection errors take precedence.
    all_checks = [c for p in passes for c in p['checks']]
    collection_errors = [c for c in all_checks if c.get('state') == 'error']
    unhealthy = [c for c in all_checks if c.get('state') in ('down', 'mismatch', 'redirect')]
    payload = {'protocol': PROTOCOL, 'mode': 'monitor',
               'time_utc': now_utc(), 'passes': passes,
               'note': ('TCP success does not establish authenticated scoring '
                        'success; run the portal check with intended '
                        'authentication and content to confirm.'),
               'splunk_hint': 'passes contain nested checks; expand both arrays and retain pass time'}
    if not all_checks:
        payload['status'] = 'collection_error'
        payload['note'] = 'No checks ran; enable confirmed targets before execution.'
        finish(2, payload)
    if collection_errors:
        payload['status'] = 'collection_error'
        finish(2, payload)
    if unhealthy:
        payload['status'] = 'unhealthy'
        finish(1, payload)
    payload['status'] = 'healthy'
    finish(0, payload)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='mode', required=True)
    for name, help_text in (
            ('map', 'Nmap TCP connect scan of configured targets (plan by default)'),
            ('exposure', 'lightweight service/version detection (plan by default)'),
            ('monitor', 'bounded TCP and optional HTTP(S) checks (plan by default)')):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument('--config', required=True, help='path to kali-checks JSON')
        sp.add_argument('--execute', action='store_true',
                        help='perform probes after complete configuration validation')
        if name == 'monitor':
            sp.add_argument('--repeat', type=int, default=1,
                            help='number of monitor passes (1-%d)' % MAX_REPEAT)
    a = parser.parse_args(argv)
    if a.mode == 'monitor' and not 1 <= a.repeat <= MAX_REPEAT:
        fail('monitor --repeat must be 1-20')
    cfg = load_config(a.config)
    if not a.execute:
        print_plan(a.mode, cfg, execute=False)
        print(json.dumps({
            'note': ('plan only; no network activity. Re-run with --execute after '
                     'reviewing every target and confirming authorization.')},
            indent=2))
        sys.exit(0)
    if a.mode == 'map':
        run_map(cfg)
    elif a.mode == 'exposure':
        run_exposure(cfg)
    else:
        run_monitor(cfg, repeat=a.repeat)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except (OSError, ValueError) as e:
        fail(str(e))
