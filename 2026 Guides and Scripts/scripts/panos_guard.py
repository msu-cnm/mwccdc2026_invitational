#!/usr/bin/env python3
"""PAN-OS dedicated MGT permitted-address plan (all management services).

Does not alter transit policy or data-interface management profiles. Requires
console access and a saved, clean candidate baseline for recovery.
"""
import argparse
import json
from pathlib import Path

DEFAULT_TRUSTED_SSH_SOURCES = ['172.20.240.0/24']


def load_host_profile(host_id, config_path=None):
    """Load an explicit host profile; reject unknown or mismatched hosts."""
    import ipaddress
    path = Path(config_path) if config_path else Path(__file__).resolve().parent.parent / 'config' / 'host-firewall.json'
    data = json.loads(path.read_text())
    profile = data.get(host_id)
    if not isinstance(profile, dict) or profile.get('platform') != 'panos':
        raise ValueError('unknown or incompatible firewall host profile: ' + str(host_id))
    sources = profile.get('trusted_ssh_sources')
    if not isinstance(sources, list) or not sources:
        raise ValueError('trusted_ssh_sources must be a nonempty list')
    sources = [str(ipaddress.IPv4Network(c, strict=True)) for c in sources]
    return sources


def plan_commands(trusted_ssrcs=None):
    """Return dedicated management-interface settings and snapshot recovery."""
    if trusted_ssrcs is None:
        trusted_ssrcs = list(DEFAULT_TRUSTED_SSH_SOURCES)
    import ipaddress
    trusted_ssrcs = [str(ipaddress.IPv4Network(c, strict=True)) for c in trusted_ssrcs]
    if not trusted_ssrcs:
        raise ValueError('trusted management networks cannot be empty')
    # Dedicated MGT interface, not transit rulebase. Replace only after backup.
    commit = ['delete deviceconfig system permitted-ip']
    commit += [f'set deviceconfig system permitted-ip {cidr}' for cidr in trusted_ssrcs]
    rollback = ['load config from team-before.xml']
    return commit, rollback


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan'])
    parser.add_argument('--host', help='topology host id for per-host profiles (default: palo-alto)')
    a = parser.parse_args()
    host_id = a.host or 'palo-alto'
    trusted = load_host_profile(host_id)
    commit, rollback = plan_commands(trusted)
    print('# PAN-OS hardening plan for host "%s" (trusted SSH: %s)' % (host_id, ', '.join(trusted)))
    print('#')
    print('# CONSOLE REQUIRED: restriction covers SSH/HTTPS/API on dedicated MGT 172.20.240.200, including IPv6 sources.')
    print('# Does not protect management on dataplane interfaces; inspect their management profiles separately.')
    print('# Start with a clean candidate: show config diff (operational mode), then configure.')
    print('# In configuration mode: show deviceconfig system permitted-ip')
    print('# If permitted-ip is absent, omit the initial delete command.')
    print('# Ensure the actual operator source as seen by MGT is in the trusted list.')
    print('# save config to team-before.xml  (use a unique filename; protect the snapshot)')
    print('# Apply commands below in configuration mode, then:')
    print('#   run show config diff')
    print('#   validate full')
    print('#   commit')
    print('# Wait for successful commit, THEN test fresh trusted SSH/HTTPS and untrusted denial.')
    print('# Test scored transit services. Validation does not activate candidate settings.')
    print('# Recovery from console: load config from team-before.xml; commit; retest.')
    print('# Snapshot restore replaces the whole candidate: coordinate a change freeze.')
    print()
    print('--- COMMIT ---')
    for c in commit:
        print(c)
    print('--- ROLLBACK ---')
    for r in rollback:
        print(r)


if __name__ == '__main__':
    main()
