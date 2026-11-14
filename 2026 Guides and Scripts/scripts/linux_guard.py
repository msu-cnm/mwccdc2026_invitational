#!/usr/bin/env python3
"""Local assessment, reversible kernel controls and host-specific firewall plans."""
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


TABLE = 'team_hardening'
CHAIN = 'team_input_harden'


def load_host_profile(host_id, config_path=None):
    """Load an explicit host profile; reject unknown or mismatched hosts."""
    import ipaddress
    path = Path(config_path) if config_path else Path(__file__).resolve().parent.parent / 'config' / 'host-firewall.json'
    data = json.loads(path.read_text())
    profile = data.get(host_id)
    if not isinstance(profile, dict) or profile.get('platform') != 'linux':
        raise ValueError('unknown or incompatible firewall host profile: ' + str(host_id))
    sources = profile.get('trusted_ssh_sources')
    if not isinstance(sources, list) or not sources:
        raise ValueError('trusted_ssh_sources must be a nonempty list')
    sources = [str(ipaddress.IPv4Network(c, strict=True)) for c in sources]
    return sources


def linux_nftables(trusted_ssrcs=None, host_id=None):
    """Generate a reviewable nftables hardening add-on for one Linux host.

    Conservative by design: it only drops invalid state and restricts SSH to
    the trusted management/Kali networks for that host. It never rewrites
    existing tables/chains, never changes routes, forwarding or any service
    port other than SSH, and preserves established/related flow so
    already-open sessions keep working.

    Apply with ``nft -c -f`` (syntax check only, does not change state) then
    ``nft -f``, after capturing a full ruleset backup with
    ``nft list ruleset > nftables-backup.nft``. Rollback is the matching
    ``linux-rollback.nft`` file (see ``linux_nftables_rollback``), which
    removes exactly the table this plan added so the SSH restriction is fully
    lifted.
    """
    if trusted_ssrcs is None:
        trusted_ssrcs = load_host_profile(host_id) if host_id else ['172.20.240.0/24', '172.17.0.0/24']
    import ipaddress
    trusted_ssrcs = [str(ipaddress.IPv4Network(c, strict=True)) for c in trusted_ssrcs]
    if not trusted_ssrcs:
        raise ValueError('trusted SSH sources cannot be empty')
    accept_lines = [
        '    iifname != "lo" tcp dport 22 ip saddr %s accept' % cidr
        for cidr in trusted_ssrcs
    ]
    lines = [
        '# Linux hardening add-on (review before applying; back up first)',
        '#   backup:   nft list ruleset > nftables-backup.nft',
        '#   check:    nft -c -f linux-hardening.nft   (syntax check only, does not apply)',
        '#   apply:    nft -f linux-hardening.nft',
        '#   rollback: nft -f linux-rollback.nft       (removes table %s)' % TABLE,
        '#   verify trusted access:   from a host in one of the trusted networks run: ssh <host> (must succeed)',
        '#   verify untrusted denial: from a non-trusted source run: ssh <host> (must be refused/timeout)',
        '',
        'add table inet %s' % TABLE,
        'table inet %s {' % TABLE,
        '  chain %s {' % CHAIN,
        '    type filter hook input priority 0; policy accept;',
        '    ct state invalid drop',
        '    ct state established, related accept',
    ] + accept_lines + [
        '    iifname != "lo" tcp dport 22 drop',
        '  }',
        '}',
        '',
    ]
    return {'linux-hardening.nft': '\n'.join(lines)}


def linux_nftables_rollback():
    """Generate the matching rollback file: it deletes exactly the table this
    plan added, so re-applying a ruleset backup (which would leave the new
    table in place) is not needed and the SSH restriction is fully removed.

    ``flush table`` then ``delete table`` require the table to exist: the
    operator runs this after confirming the table exists (``nft list tables``).
    """
    lines = [
        '# Linux hardening rollback (removes only the team_hardening table)',
        '#   check:    nft -c -f linux-rollback.nft   (syntax check only)',
        '#   apply:    nft -f linux-rollback.nft',
        '',
        'flush table inet %s' % TABLE,
        'delete table inet %s' % TABLE,
        '',
    ]
    return {'linux-rollback.nft': '\n'.join(lines)}


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
    parser.add_argument('action', choices=['assess', 'harden', 'rollback', 'firewall'])
    parser.add_argument('--apply', action='store_true', help='explicitly allow changes')
    parser.add_argument('--backup', type=Path, help='new backup file for harden; existing file for rollback')
    parser.add_argument('--out', type=Path, help='write the generated firewall ruleset to this file (firewall)')
    parser.add_argument('--host', help='topology host id for per-host firewall profiles (firewall)')
    a = parser.parse_args()
    if platform.system() != 'Linux':
        parser.error('Linux required')
    if a.action == 'firewall':
        if a.apply or a.backup:
            parser.error('firewall does not accept --apply or --backup')
        files = linux_nftables(host_id=a.host)
        files.update(linux_nftables_rollback())
        if a.out:
            out_path = Path(a.out)
            if out_path.is_dir() or str(out_path).endswith((os.sep, '/')):
                # Directory: write every generated file into it.
                for name, text in files.items():
                    p = out_path / name
                    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'w') as f:
                        f.write(text)
                    print('Wrote %s' % p)
            else:
                # Single file path (original behaviour): write only the hardening ruleset.
                p = out_path
                fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w') as f:
                    f.write(files['linux-hardening.nft'])
                print('Wrote %s' % p)
        else:
            for name, text in files.items():
                print('=== %s ===' % name)
                print(text)
        return
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
