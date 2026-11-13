#!/usr/bin/env python3
"""Local assessment and reversible kernel hardening; no network/firewall changes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

# Deliberately exclude forwarding, reverse-path filtering, IPv6, SSH and services.
SETTINGS = {"kernel.kptr_restrict": "2", "kernel.dmesg_restrict": "1",
            "fs.protected_hardlinks": "1", "fs.protected_symlinks": "1"}


def run(args):
    p = subprocess.run(args, text=True, capture_output=True, timeout=15)
    return {"rc": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}


def read_value(key):
    return Path('/proc/sys/' + key.replace('.', '/')).read_text().strip()


def write_value(key, value):
    Path('/proc/sys/' + key.replace('.', '/')).write_text(value + '\n')


def manifest():
    result = {}
    # Hash only: never include configuration contents, process arguments or secrets.
    roots = ['/etc/ssh', '/etc/cron.d', '/etc/systemd/system', '/etc/sudoers.d']
    files = [Path('/etc/passwd'), Path('/etc/group'), Path('/etc/crontab')]
    for root in roots:
        files.extend(Path(root).rglob('*'))
    for p in sorted(set(files)):
        if p.is_symlink():
            result[str(p)] = {'symlink': os.readlink(p)}
        elif p.is_file():
            try:
                result[str(p)] = {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                                  'mode': oct(p.stat().st_mode & 0o7777)}
            except OSError:
                result[str(p)] = {'error': 'unreadable'}
    return result


def assess():
    commands = {'listeners': ['ss', '-lntu'],
                'failed_services': ['systemctl', '--failed', '--no-pager', '--plain'],
                'service_states': ['systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--plain'],
                'disk': ['df', '-P'], 'memory': ['free', '-m']}
    result = {'time_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'host': platform.node(), 'load': os.getloadavg(), 'persistence': manifest()}
    for name, command in commands.items():
        try:
            result[name] = run(command) if shutil.which(command[0]) else {'error': 'command unavailable'}
        except (OSError, subprocess.TimeoutExpired) as e:
            result[name] = {'error': type(e).__name__}
    # Only event metadata, no MESSAGE field that could contain submitted credentials.
    try:
        p = subprocess.run(['journalctl', '--since=-15min', '-n', '500', '-o', 'json', '--no-pager'],
                           capture_output=True, text=True, timeout=15)
        counts = {}
        for line in p.stdout.splitlines():
            row = json.loads(line)
            if row.get('SYSLOG_IDENTIFIER') in ('sshd', 'sudo', 'su', 'login'):
                tag = row['SYSLOG_IDENTIFIER']
                counts[tag] = counts.get(tag, 0) + 1
        result['auth_event_counts_last_15m_capped_500'] = counts
        result['journal_status'] = p.returncode
    except (OSError, ValueError, subprocess.TimeoutExpired):
        result['journal_status'] = 'unavailable'
    return result


def validate_backup(data):
    if not isinstance(data, dict) or set(data) != set(SETTINGS):
        raise ValueError('backup must contain exactly the supported kernel keys')
    if any(not isinstance(v, str) or v not in ('0', '1', '2') for v in data.values()):
        raise ValueError('invalid backup values')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['assess', 'harden', 'rollback'])
    parser.add_argument('--apply', action='store_true', help='explicitly allow changes')
    parser.add_argument('--backup', type=Path, help='new backup file for harden; existing file for rollback')
    a = parser.parse_args()
    if platform.system() != 'Linux':
        parser.error('Linux required')
    if a.action == 'assess':
        if a.apply or a.backup:
            parser.error('assess does not accept --apply or --backup')
        print(json.dumps(assess(), indent=2))
        return
    if a.action == 'rollback' and not a.backup:
        parser.error('rollback requires --backup')
    desired = validate_backup(json.loads(a.backup.read_text())) if a.action == 'rollback' else SETTINGS
    previous = {k: read_value(k) for k in SETTINGS}
    print(json.dumps({'action': a.action, 'apply': a.apply, 'before': previous, 'after': desired}, indent=2))
    if not a.apply:
        return
    if os.geteuid() != 0:
        parser.error('--apply requires root')
    if a.action == 'harden':
        if not a.backup:
            parser.error('harden --apply requires a fresh --backup path')
        # Exclusive creation prevents repeated runs from destroying original values.
        fd = os.open(a.backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(previous, f)
            f.flush()
            os.fsync(f.fileno())
    changed = []
    try:
        for k, v in desired.items():
            write_value(k, v)
            changed.append(k)
            if read_value(k) != v:
                raise RuntimeError('verification failed: ' + k)
    except Exception:
        for k in reversed(changed):
            write_value(k, previous[k])
        raise


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
