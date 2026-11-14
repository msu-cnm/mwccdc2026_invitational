#!/usr/bin/env python3
"""Generate concrete Splunk log-collection configuration for a single event host.

Reads the host from config/topology.json and emits platform-appropriate files:
  linux   -> universal-forwarder confs (outputs.conf, inputs.conf), or an
             appliance syslog receiver relay (rsyslog listener + routing + file inputs)
  windows -> local universal-forwarder confs (WinEventLog inputs.conf + outputs.conf)
  network -> device syslog-server config lines (VyOS 1.4 / PAN-OS 11)

The plan subcommand writes nothing: it prints every file and command.
--apply writes the generated files to --out (0600), backing up anything it would
overwrite first; --rollback restores that backup and removes files this apply
created, so it fully reverses the collection change.

This script generates configuration only; it does not install software, open
ports, or change firewall/NAT rules. Applying those changes on an event host
still requires the event change gate and permission under competition rules.
Replace all angle-bracket values with discovered values before use.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY = ROOT / 'config' / 'topology.json'


def load_host(host_id):
    hosts = json.loads(TOPOLOGY.read_text())
    for h in hosts:
        if h['id'] == host_id:
            return h
    raise SystemExit('unknown host %r; valid ids: %s' % (host_id, ', '.join(h['id'] for h in hosts)))


# --- Linux ---------------------------------------------------------------

# Per-host log paths and sourcetypes. Rocky uses secure/messages; Debian/Ubuntu
# use auth.log/syslog. Add service-specific inputs with --input path:sourcetype.
LINUX_INPUTS = {
    'rocky-ecom': [('/var/log/secure', 'linux_auth'), ('/var/log/messages', 'linux_syslog')],
    'ubuntu-email': [('/var/log/auth.log', 'linux_auth'), ('/var/log/syslog', 'linux_syslog')],
    'debian-splunk': [('/var/log/auth.log', 'linux_auth'), ('/var/log/syslog', 'linux_syslog')],
    'ubuntu-workstation': [('/var/log/auth.log', 'linux_auth'), ('/var/log/syslog', 'linux_syslog')],
    'kali': [('/var/log/auth.log', 'linux_auth'), ('/var/log/syslog', 'linux_syslog')],
}


def linux_forwarder(receiver, port, index, inputs):
    # outputs.conf follows docs/splunk-data-sources.md "Linux forwarder".
    outputs = (
        '[tcpout]\n'
        'defaultGroup = team_indexer\n'
        '\n'
        '[tcpout:team_indexer]\n'
        'server = %s:%s\n' % (receiver, port)
    )
    inputs_conf = ''
    for item in inputs:
        if isinstance(item, str):
            # Accept "path" or "path:sourcetype" from --input.
            path, _, sourcetype = item.partition(':')
            sourcetype = sourcetype or 'linux_syslog'
        else:
            path, sourcetype = item
        inputs_conf += (
            '[monitor://%s]\n' % path +
            'disabled = 0\n'
            'index = %s\n' % index +
            'sourcetype = %s\n\n' % sourcetype
        )
    return {'outputs.conf': outputs, 'inputs.conf': inputs_conf}


# Appliance syslog receiver relay on the Debian Splunk host (docs "Appliance relay").
# Maps a sending appliance to its observed source IP and local log file.
RELAY_SOURCES = {
    'palo-alto': ('172.20.240.200', '/var/log/team-remote/palo-alto.log', 'pan_raw'),
    'vyos': ('172.16.0.254', '/var/log/team-remote/vyos.log', 'vyos_syslog'),
}


def linux_rsyslog_relay(index, host, port):
    # Receiver: listen on the selected TCP port, route each appliance's traffic to a file,
    # then read those files with Splunk local inputs. This is the documented
    # appliance relay; it is not a per-host forwarder.
    rsyslog = (
        '# rsyslog appliance relay for Splunk collection on %s\n'
        '# Review before enabling: substitute observed source IPs and confirm no scored\n'
        '# service depends on these facilities. Load imtcp only once.\n'
        'module(load="imtcp")\n'
        'ruleset(name="team_remote") {\n'
    ) % host['id']
    inputs = ''
    for name, (src_ip, log_path, sourcetype) in RELAY_SOURCES.items():
        rsyslog += (
            "  if ($fromhost-ip == '%s') then {\n"
            '    action(type="omfile" file="%s" fileCreateMode="0640")\n'
            '    stop\n'
            '  }\n' % (src_ip, log_path)
        )
        inputs += (
            '[monitor://%s]\n' % log_path +
            'disabled = 0\n'
            'index = %s\n' % index +
            'sourcetype = %s\n' % sourcetype +
            'host = %s\n\n' % name
        )
    rsyslog += '  stop\n}\ninput(type="imtcp" port="%s" ruleset="team_remote")\n' % port
    return {'rsyslog-team-relay.conf': rsyslog, 'inputs.conf': inputs}


# --- Windows -------------------------------------------------------------

def windows_forwarder(receiver, port, index):
    # Local universal-forwarder collection (docs "Windows forwarder"). WEF is a
    # separate collector path and is not generated here; use this local UF path.
    outputs = (
        '[tcpout]\n'
        'defaultGroup = team_indexer\n'
        '\n'
        '[tcpout:team_indexer]\n'
        'server = %s:%s\n' % (receiver, port)
    )
    # Core channels; add Directory Service (DC only), PowerShell/Operational and
    # Defender/Operational where the channel exists and is approved.
    inputs = ''
    for chan in ('Security', 'System', 'Application'):
        inputs += (
            '[WinEventLog://%s]\n' % chan +
            'disabled = 0\n'
            'index = %s\n' % index +
            'renderXml = true\n\n'
        )
    return {'outputs.conf': outputs, 'inputs.conf': inputs}


# --- Network -------------------------------------------------------------

def vyos_syslog(receiver, port):
    # VyOS 1.4 syslog (docs "VyOS 1.4"); retain existing destinations.
    return {'vyos-syslog.config': (
        "# VyOS 1.4: forward syslog to the approved relay over TCP (commit after review)\n"
        "# Preserve existing destinations: show configuration commands | match syslog\n"
        "set system syslog host %s facility all level info\n"
        "set system syslog host %s port %s\n"
        "set system syslog host %s protocol tcp\n"
    ) % (receiver, receiver, port, receiver)}


def paloalto_syslog(receiver, port):
    # PAN-OS 11 syslog server-profile (docs "Palo Alto PAN-OS 11.0.2").
    return {'paloalto-syslog.config': (
        "# PAN-OS 11: syslog server profile to the approved relay over TCP (commit after review)\n"
        "set shared log-settings syslog TEAM-SYSLOG server splunk server %s\n"
        "set shared log-settings syslog TEAM-SYSLOG server splunk transport TCP\n"
        "set shared log-settings syslog TEAM-SYSLOG server splunk port %s\n"
        "set shared log-settings syslog TEAM-SYSLOG server splunk format BSD\n"
        "# Then attach TEAM-SYSLOG to the existing required security rules (Log at Session End)\n"
        "# and add System/Config forwarding in Device > Log Settings. Do not replace the rules.\n"
    ) % (receiver, port)}


def plan(host, receiver, port, index, method, extra_inputs=None):
    if host['platform'] == 'linux':
        if method == 'syslog':
            files = linux_rsyslog_relay(index, host, port)
            note = ('Appliance syslog RELAY on the Splunk host. Enable with:\n'
                    '  sudo install -d -m 0750 /var/log/team-remote\n'
                    '  sudo cp rsyslog-team-relay.conf /etc/rsyslog.d/30-team-remote.conf\n'
                    '  sudo rsyslogd -N1 && sudo systemctl restart rsyslog\n'
                    'then deploy inputs.conf under the Splunk team_collection app and restart it.')
        else:
            inputs = list(LINUX_INPUTS.get(host['id'], []))
            if extra_inputs:
                # --input overrides the per-host defaults when given.
                inputs = list(extra_inputs)
            files = linux_forwarder(receiver, port, index, inputs)
            note = ('Deploy under the forwarder (use its discovered install path):\n'
                    '  sudo mkdir -p /opt/splunkforwarder/etc/apps/team_collection/local\n'
                    '  sudo cp outputs.conf inputs.conf /opt/splunkforwarder/etc/apps/team_collection/local/\n'
                    '  # Follow Step 1 of the Linux guide to discover and verify the unit and owner.\n'
                    '  # Set UNIT to that exact unit in this shell before restarting:\n'
                    '  sudo systemctl restart "${UNIT:?Set UNIT using Step 1 discovery first}"\n'
                    'then verify per docs/splunk-data-sources.md "Linux forwarder" (btool, forward-server, splunkd.log).')
    elif host['platform'] == 'windows':
        files = windows_forwarder(receiver, port, index)
        note = ('Local universal-forwarder collection (elevated PowerShell):\n'
                '  $d = "C:\\Program Files\\SplunkUniversalForwarder\\etc\\apps\\team_collection\\local"\n'
                '  New-Item -ItemType Directory -Force -Path $d | Out-Null\n'
                '  Copy-Item outputs.conf, inputs.conf -Destination $d -Force\n'
                '  Restart-Service SplunkForwarder\n'
                'then verify per docs/splunk-data-sources.md "Windows forwarder". WEF is a separate path and is not generated here.')
    elif host['platform'] == 'network':
        if host['id'] == 'vyos':
            files = vyos_syslog(receiver, port)
        else:
            files = paloalto_syslog(receiver, port)
        note = 'Apply the device syslog config through its normal candidate/commit workflow.'
    else:
        raise SystemExit('unsupported platform %r' % host['platform'])
    return files, note


# --- File handling (hardened) -------------------------------------------

def _safe_name(name):
    # Only plain filenames inside --out; reject absolute paths, traversal and separators.
    if not name or '/' in name or '\\' in name or name in ('.', '..') \
            or re.search(r'[^\w.\-]', name):
        raise SystemExit('unsafe output filename %r (must be a plain filename)' % name)
    return name


def write_files(out_dir, files, allow_overwrite=False):
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        _safe_name(name)
        p = out_dir / name
        if p.is_symlink():
            raise SystemExit('refusing to write through symlink %s' % p)
        if p.exists() and not allow_overwrite:
            raise FileExistsError('refusing to overwrite existing %s (use a fresh --out or review first)' % p)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(p, 0o600)


def backup_existing(out_dir, backup):
    state = {}
    if out_dir.exists():
        for p in out_dir.iterdir():
            if not p.is_file() or p.is_symlink():
                continue
            _safe_name(p.name)
            state[p.name] = {'content': p.read_text(), 'mode': oct(p.stat().st_mode & 0o777)}
    # backup is a user-supplied path (absolute allowed); only reject '..' traversal.
    if '..' in Path(backup).parts:
        raise SystemExit('unsafe backup path %r (.. traversal not allowed)' % backup)
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump({'files': state}, f)


def record_created(backup, created):
    # Store the files this apply created so rollback can remove them.
    data = json.loads(Path(backup).read_text())
    data['created'] = sorted(set(created))
    for name in data['created']:
        _safe_name(name)
    Path(backup).write_text(json.dumps(data))
    os.chmod(backup, 0o600)


def restore_backup(out_dir, backup):
    data = json.loads(Path(backup).read_text())
    files = data.get('files', {})
    created = set(data.get('created', []))
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, entry in files.items():
        _safe_name(name)
        p = out_dir / name
        if p.is_symlink() or p.exists():
            p.unlink()
        p.write_text(entry['content'])
        os.chmod(p, 0o600)
    # Remove files this apply created that are not part of the original state.
    for name in created:
        _safe_name(name)
        if name not in files:
            p = out_dir / name
            if p.exists() and not p.is_symlink():
                p.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('host', help='host id from config/topology.json')
    parser.add_argument('--receiver', required=True, help='discovered Splunk receiver address (no angle brackets)')
    parser.add_argument('--port', type=int, default=None,
                        help='receiver port (default 9997 for forwarders; 1514 for syslog relays)')
    parser.add_argument('--index', default='team_security', help='target index (default team_security)')
    parser.add_argument('--method', choices=['forwarder', 'syslog'], default=None,
                        help='linux collection method: forwarder (per-host UF) or syslog (appliance relay on the Splunk host)')
    parser.add_argument('--input', action='append', default=[], metavar='PATH[:SOURCE_TYPE]',
                        help='Linux monitor inputs (repeatable); when given, overrides the per-host defaults')
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('plan', help='print the generated files and commands; write nothing')
    ap = sub.add_parser('apply', help='write files to --out (backs up anything it would overwrite)')
    ap.add_argument('--out', type=Path, required=True, help='output directory for generated files')
    ap.add_argument('--backup', type=Path, default=None, help='backup path (required if --out has files)')
    rb = sub.add_parser('rollback', help='restore a previous apply from --backup')
    rb.add_argument('--out', type=Path, required=True)
    rb.add_argument('--backup', type=Path, required=True)
    a = parser.parse_args()

    host = load_host(a.host)
    method = a.method or ('syslog' if host['platform'] == 'network' else 'forwarder')
    port = a.port if a.port is not None else (1514 if method == 'syslog' else 9997)

    extra_inputs = []
    for spec in a.input:
        if ':' not in spec:
            extra_inputs.append(spec)  # path only; default sourcetype applied downstream
            continue
        path, stype = spec.split(':', 1)
        extra_inputs.append((path, stype))

    files, note = plan(host, a.receiver, port, a.index, method, extra_inputs)

    if a.action == 'plan':
        print('Host: %s (%s, %s)  receiver=%s:%s  index=%s  method=%s'
              % (host['id'], host['os'], host['platform'], a.receiver, port, a.index, method))
        for name, content in files.items():
            print('\n=== %s ===\n%s' % (name, content.rstrip()))
        print('\nNext steps:\n%s\n' % note)
        return

    if a.action == 'apply':
        if not a.backup:
            parser.error('apply requires a --backup path (it backs up overwrites and records created files for rollback)')
        nonempty = a.out.exists() and any(a.out.iterdir())
        if nonempty:
            backup_existing(a.out, a.backup)
            overwrite = True
            created = [n for n in files if not (a.out / n).exists()]
        else:
            # Fresh dir: record what we create so rollback can remove it.
            _safe_name(a.backup.name)
            fd = os.open(a.backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump({'files': {}}, f)
            overwrite = False
            created = list(files)
        write_files(a.out, files, allow_overwrite=overwrite)
        record_created(a.backup, created)
        print('Wrote %d file(s) to %s\n%s' % (len(files), a.out, note))
        return

    if a.action == 'rollback':
        restore_backup(a.out, a.backup)
        print('Restored %s from backup %s (removed files this apply created)' % (a.out, a.backup))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
