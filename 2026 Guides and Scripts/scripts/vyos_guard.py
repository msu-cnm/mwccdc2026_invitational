#!/usr/bin/env python3
"""Generate a VyOS 1.4 IPv4 input-filter SSH guard; plan only.

Requires unused input rule 1 and TEAM-HARDEN name. Trusted/non-SSH traffic
returns to existing policy. Only the selected ingress interface is covered.
Use console access, commit-confirm 5, test, confirm, then save.
"""
import argparse
import json
from pathlib import Path

FIREWALL_NAME = 'TEAM-HARDEN'
# Defaults for direct API calls; CLI loads an explicit host profile.
DEFAULT_TRUSTED_SSH_SOURCES = ['172.20.240.0/24', '172.17.0.0/24']
DEFAULT_INTERNAL_IFACE = 'eth2'


def load_host_profile(host_id, config_path=None):
    """Load an explicit host profile; reject unknown or mismatched hosts."""
    import ipaddress
    path = Path(config_path) if config_path else Path(__file__).resolve().parent.parent / 'config' / 'host-firewall.json'
    data = json.loads(path.read_text())
    profile = data.get(host_id)
    if not isinstance(profile, dict) or profile.get('platform') != 'vyos':
        raise ValueError('unknown or incompatible firewall host profile: ' + str(host_id))
    sources = profile.get('trusted_ssh_sources')
    if not isinstance(sources, list) or not sources:
        raise ValueError('trusted_ssh_sources must be a nonempty list')
    sources = [str(ipaddress.IPv4Network(c, strict=True)) for c in sources]
    return sources, profile['internal_interface']


def plan_commands(trusted_ssrcs=None, internal_iface=None):
    """Return native configuration commands and matching removal commands."""
    if trusted_ssrcs is None:
        trusted_ssrcs = list(DEFAULT_TRUSTED_SSH_SOURCES)
    if internal_iface is None:
        internal_iface = DEFAULT_INTERNAL_IFACE
    import ipaddress
    import re
    trusted_ssrcs = [str(ipaddress.IPv4Network(c, strict=True)) for c in trusted_ssrcs]
    if not trusted_ssrcs or len(trusted_ssrcs) > 6:
        raise ValueError('require 1–6 trusted IPv4 networks')
    if not re.fullmatch(r'eth[0-9]+', internal_iface):
        raise ValueError('expected ethernet interface ethN')
    base = 'firewall ipv4 name ' + FIREWALL_NAME
    # Return to existing input policy for trusted/non-SSH traffic; accept would bypass it.
    commit = [f'set {base} default-action return']
    for i, cidr in enumerate(trusted_ssrcs):
        n = 10 + i * 10
        commit += [f'set {base} rule {n} action return',
                   f'set {base} rule {n} source address {cidr}']
    commit += [f'set {base} rule 90 action drop',
               'set firewall ipv4 input filter rule 1 action jump',
               f'set firewall ipv4 input filter rule 1 jump-target {FIREWALL_NAME}',
               f'set firewall ipv4 input filter rule 1 inbound-interface name {internal_iface}',
               'set firewall ipv4 input filter rule 1 protocol tcp',
               'set firewall ipv4 input filter rule 1 destination port 22']
    rollback = ['delete firewall ipv4 input filter rule 1', f'delete {base}']
    return commit, rollback


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan'])
    parser.add_argument('--host', help='topology host id for per-host profiles (default: vyos)')
    a = parser.parse_args()
    host_id = a.host or 'vyos'
    trusted, iface = load_host_profile(host_id)
    commit, rollback = plan_commands(trusted, iface)
    print('# VyOS 1.4 hardening plan for host "%s" (trusted SSH: %s; internal iface: %s)' % (host_id, ', '.join(trusted), iface))
    print('#')
    print('# PRECONDITION: console access; show configuration commands; abort if input filter rule 1 or TEAM-HARDEN exists.')
    print('# Save original config: run show configuration commands; save /config/team-before.boot')
    print('# Apply (native CLI, one line at a time; NOT a shell one-liner):')
    print('#   configure')
    for c in commit:
        print('#   ' + c)
    print('#   show | diff                    # review the pending changes')
    print('#   commit-confirm 5              # rolls back in 5 MINUTES unless explicitly confirmed')
    print('#   confirm                        # after fresh SSH and service tests')
    print('#   save                           # only after confirming connectivity and services')
    print('#')
    print('# Rollback:')
    print('#   configure')
    for r in rollback:
        print('#   ' + r)
    print('#   show | diff')
    print('#   commit-confirm 5')
    print('#   confirm                        # after fresh SSH and service tests')
    print('#   save')
    print()
    print('--- COMMIT ---')
    for c in commit:
        print(c)
    print('--- ROLLBACK ---')
    for r in rollback:
        print(r)


if __name__ == '__main__':
    main()
