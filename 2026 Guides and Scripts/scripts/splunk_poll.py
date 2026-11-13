#!/usr/bin/env python3
"""Poll the Splunk REST API for IOC events during incident response and save a local evidence trail.

Plan-first: by default this prints a readable JSON plan and performs no network
activity. Pass --execute to actually poll; --once runs a single cycle, or pass
--max-cycles N to run a bounded number of cycles (useful for rehearsal).

Credentials are read from the SPLUNK_USERNAME and SPLUNK_PASSWORD environment
variables only. They are never written to disk and never appear in the config
file. The Splunk URL must be an exact scoped IP with no credentials or fragment.

Observation only: results are detection leads, not confirmed findings. A failed
query is recorded as an error in the evidence file; it is not proof of absence.
"""
import argparse
import csv
import io
import ipaddress
import json
import os
import re
import ssl
import sys
import time
from pathlib import Path
from typing import NoReturn
from urllib import error, parse, request

PROTOCOL = 'splunk-poll/1.0'
DEFAULT_TIMEOUT = 15
SPL_MAX_LEN = 4096        # keep each query small and fast


def now_utc():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def fail(message) -> NoReturn:
    print(json.dumps({'status': 'invalid_configuration', 'error': message}), file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Configuration validation. Credentials are never read from the config file.
# ---------------------------------------------------------------------------

IP_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
IDENT_RE = re.compile(r'^[A-Za-z0-9._-]+$')
CRED_KEYS = ('username', 'password', 'token', 'session_key', 'apikey')


def valid_ip(value):
    if not isinstance(value, str) or not IP_RE.match(value):
        return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def validate_config(raw):
    if not isinstance(raw, dict):
        fail('config must be a JSON object')
    for key in CRED_KEYS:
        if key in raw:
            fail('config must not contain %r; credentials come from the environment' % key)

    splunk_url = raw.get('splunk_url')
    if not isinstance(splunk_url, str):
        fail('splunk_url is required (absolute https URL to the Splunk management port)')
    if re.match(r'^https?://[^/@]+@', splunk_url, re.IGNORECASE) or '@' in splunk_url.split('://', 1)[-1]:
        fail('splunk_url must not contain credentials')
    if '#' in splunk_url:
        fail('splunk_url must not contain a fragment')
    if '//' not in splunk_url:
        fail('splunk_url must be an absolute https URL')
    scheme = splunk_url.split('://', 1)[0].lower()
    if scheme != 'https':
        fail('splunk_url must use https (the management port is TLS)')
    hostport = splunk_url.split('://', 1)[1].split('/', 1)[0]
    host, _, port = hostport.partition(':')
    if not IP_RE.match(host):
        fail('splunk_url host must be an exact IPv4 address (no hostname or placeholder): %r' % host)
    if not valid_ip(host):
        fail('splunk_url host is not a valid IPv4 address: %r' % host)
    if port:
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            fail('splunk_url port must be 1-65535: %r' % port)

    index = raw.get('index')
    if not isinstance(index, str) or not IDENT_RE.match(index):
        fail('index must be a simple identifier (e.g. team_security)')

    poll_interval = raw.get('poll_interval', 15)
    if isinstance(poll_interval, bool) or not isinstance(poll_interval, (int, float)) or not (1 <= poll_interval <= 3600):
        fail('poll_interval must be a number of seconds between 1 and 3600')

    max_evidence_files = raw.get('max_evidence_files', 200)
    if isinstance(max_evidence_files, bool) or not isinstance(max_evidence_files, int) or not (1 <= max_evidence_files <= 10000):
        fail('max_evidence_files must be an integer between 1 and 10000')

    evidence_dir = raw.get('evidence_dir', 'inject_evidence')
    if not isinstance(evidence_dir, str) or not evidence_dir:
        fail('evidence_dir must be a nonempty path (relative to the working directory)')
    if os.path.isabs(evidence_dir):
        fail('evidence_dir must be relative to the working directory')

    timeout = raw.get('timeout', DEFAULT_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not (1 <= timeout <= 120):
        fail('timeout must be a number of seconds between 1 and 120')

    queries = raw.get('queries')
    if not isinstance(queries, list) or not queries:
        fail('queries must be a nonempty list of {id, query} objects')
    seen_ids = set()
    norm_queries = []
    for i, q in enumerate(queries):
        label = 'queries[%d]' % i
        if not isinstance(q, dict) or set(q) != {'id', 'query'}:
            fail('%s must contain exactly id and query' % label)
        qid = q.get('id')
        if not isinstance(qid, str) or not IDENT_RE.match(qid):
            fail('%s.id must be a simple identifier' % label)
        if qid in seen_ids:
            fail('%s.id is a duplicate: %r' % (label, qid))
        seen_ids.add(qid)
        spl = q.get('query')
        if not isinstance(spl, str) or not spl.strip():
            fail('%s.query must be a nonempty SPL string' % label)
        if len(spl) > SPL_MAX_LEN:
            fail('%s.query is too long (max %d chars)' % (label, SPL_MAX_LEN))
        norm_queries.append({'id': qid, 'query': spl.strip()})

    return {
        'splunk_url': splunk_url,
        'index': index,
        'poll_interval': poll_interval,
        'max_evidence_files': max_evidence_files,
        'evidence_dir': evidence_dir,
        'timeout': timeout,
        'queries': norm_queries,
    }


# ---------------------------------------------------------------------------
# HTTP layer (stdlib only). urlopen is isolated so tests can mock it.
# ---------------------------------------------------------------------------

def _build_ssl():
    ca = os.environ.get('SPLUNK_CA_BUNDLE')
    if ca:
        return ssl.create_default_context(cafile=ca)
    # Lab self-signed CA: verify against the system trust store by default.
    return ssl.create_default_context()


def _do_request(url, data=None, headers=None, method=None, timeout=DEFAULT_TIMEOUT):
    req = request.Request(url, data=data, method=method or ('POST' if data is not None else 'GET'))
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with request.urlopen(req, timeout=timeout, context=_build_ssl()) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except error.HTTPError as e:
        body = e.read() if hasattr(e, 'read') else b''
        raise RuntimeError('HTTP %s from %s: %s' % (e.code, url, body[:300].decode('utf-8', 'replace')))


def login(cfg):
    user = os.environ.get('SPLUNK_USERNAME')
    pw = os.environ.get('SPLUNK_PASSWORD')
    if not user or not pw:
        fail('SPLUNK_USERNAME and SPLUNK_PASSWORD environment variables are required for --execute')
    body = parse.urlencode({'username': user, 'password': pw, 'output_mode': 'json'}).encode()
    status, headers, data = _do_request(
        cfg['splunk_url'] + '/services/auth/login',
        data=body, method='POST', timeout=cfg['timeout'])
    try:
        payload = json.loads(data.decode('utf-8', 'replace'))
    except ValueError:
        raise RuntimeError('login response was not JSON')
    key = payload.get('sessionKey') or (payload.get('sessionToken') or {}).get('key')
    if not key:
        raise RuntimeError('login response contained no sessionKey')
    return 'Splunk ' + key


def submit_job(cfg, auth, spl):
    url = cfg['splunk_url'] + '/services/search/jobs'
    body = parse.urlencode({'search': spl, 'output_mode': 'json'}).encode()
    status, headers, data = _do_request(url, data=body, headers={'Authorization': auth}, method='POST', timeout=cfg['timeout'])
    try:
        payload = json.loads(data.decode('utf-8', 'replace'))
    except ValueError:
        raise RuntimeError('submit response was not JSON')
    sid = payload.get('sid') or (payload.get('entry') or [{}])[0].get('name')
    if not sid:
        raise RuntimeError('submit response contained no job id')
    return sid


def wait_job(cfg, auth, sid):
    url = cfg['splunk_url'] + '/services/search/jobs/%s?output_mode=json' % parse.quote(sid, safe='')
    deadline = time.monotonic() + cfg['timeout'] * 4
    while True:
        _, _, data = _do_request(url, headers={'Authorization': auth}, method='GET', timeout=cfg['timeout'])
        payload = json.loads(data.decode('utf-8', 'replace'))
        state = (payload.get('entry') or [{}])[0].get('content', {}).get('dispatchState')
        if state == 'DONE':
            return
        if state in ('ERROR', 'FAILED', 'DISCARDING'):
            raise RuntimeError('search job reported %s' % state)
        if time.monotonic() > deadline:
            raise RuntimeError('search job timed out (state=%r)' % state)
        time.sleep(0.5)


def fetch_results(cfg, auth, sid):
    url = cfg['splunk_url'] + '/services/search/jobs/%s/results?count=1000&output_mode=csv' % sid
    _, headers, data = _do_request(url, headers={'Authorization': auth}, method='GET', timeout=cfg['timeout'])
    text = data.decode('utf-8', 'replace')
    if not text.strip():
        return []
    rows = list(csv.reader(io.StringIO(text)))
    if len(rows) < 2:
        return []
    header, body = rows[0], rows[1:]
    return [dict(zip(header, r)) for r in body]


# ---------------------------------------------------------------------------
# Evidence output
# ---------------------------------------------------------------------------

def ensure_dir(path):
    path.mkdir(parents=True, exist_ok=True)


def prune(dirpath, max_files):
    files = sorted(p for p in dirpath.glob('events_*.json'))
    excess = len(files) - max_files
    for old in files[:max(0, excess)]:
        try:
            old.unlink()
        except OSError:
            pass


def row_key(row):
    return json.dumps(row, sort_keys=True, default=str)


def execute_once(cfg, seen=None):
    """Run one poll cycle. Returns (new_rows_by_query, evidence_file_or_None)."""
    auth = login(cfg)
    out_dir = Path(cfg['evidence_dir'])
    ensure_dir(out_dir)

    batch = {}
    new_total = 0
    if seen is None:
        seen = set()
    for q in cfg['queries']:
        try:
            sid = submit_job(cfg, auth, q['query'])
            wait_job(cfg, auth, sid)
            rows = fetch_results(cfg, auth, sid)
        except (RuntimeError, error.URLError, OSError, ValueError) as e:
            batch[q['id']] = {'error': str(e)}
            continue
        fresh = []
        for row in rows:
            key = row_key(row)
            if key not in seen:
                seen.add(key)
                fresh.append(row)
        if fresh:
            batch[q['id']] = fresh
            new_total += len(fresh)

    evidence_file = None
    if new_total:
        ts = now_utc().replace(':', '').replace('-', '')
        evidence_file = out_dir / ('events_%s.json' % ts)
        payload = {'time_utc': now_utc(), 'protocol': PROTOCOL, 'index': cfg['index'], 'queries': batch}
        with open(evidence_file, 'w') as f:
            json.dump(payload, f, indent=2)
        prune(out_dir, cfg['max_evidence_files'])
    return new_total, evidence_file


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(description='Poll Splunk for IOC events and save a local evidence trail.')
    p.add_argument('--config', required=True, help='path to the poll config JSON')
    p.add_argument('--execute', action='store_true', help='actually poll (default is plan-only)')
    p.add_argument('--once', action='store_true', help='with --execute: run a single cycle and exit')
    p.add_argument('--max-cycles', type=int, default=None, help='with --execute: bounded number of cycles')
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        raw = json.loads(Path(args.config).read_text())
    except (OSError, ValueError) as e:
        fail('could not read config %r: %s' % (args.config, e))
    cfg = validate_config(raw)

    if not args.execute:
        print(json.dumps({
            'protocol': PROTOCOL, 'mode': 'plan', 'status': 'ok',
            'splunk_url': cfg['splunk_url'], 'index': cfg['index'],
            'poll_interval': cfg['poll_interval'], 'evidence_dir': cfg['evidence_dir'],
            'max_evidence_files': cfg['max_evidence_files'],
            'queries': [{'id': q['id'], 'query': q['query']} for q in cfg['queries']],
            'note': 'plan only; no network activity. Use --execute (with SPLUNK_USERNAME/SPLUNK_PASSWORD set) to poll.',
        }, indent=2))
        return 0

    if args.max_cycles is not None and args.max_cycles < 1:
        fail('--max-cycles must be >= 1')

    cycles = 1 if args.once else (args.max_cycles or None)
    done = 0
    seen = set()
    try:
        while cycles is None or done < cycles:
            new_total, evidence_file = execute_once(cfg, seen)
            stamp = now_utc()
            if evidence_file:
                print('[%s] %d new row(s) -> %s' % (stamp, new_total, evidence_file))
            else:
                print('[%s] no new events' % stamp)
            done += 1
            if cycles is not None and done >= cycles:
                break
            time.sleep(cfg['poll_interval'])
    except KeyboardInterrupt:
        print('\n[splunk_poll] stopped.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
