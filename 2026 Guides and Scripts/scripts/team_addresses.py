"""Team address resolver for CCDC competition ops toolkit.

Given your team number, prints the concrete IP addresses you will use to reach
your own team's hosts and network devices — both the fixed internal management
addresses (172.20.240.x / 172.16.0.x / 172.17.0.x) and the per-team public pool
(172.25.N.x, where N = 20 + team).

Modes: resolve (pure function computing addresses from the team number).
Exit codes: 0 = success; 2 = invalid team number.

Observation only: addresses are computed from the topology and printed to stdout;
no network activity is performed and no files are written. Verify against your
live configuration before use — the shared-egress .2/29 is the router address,
not an address to assign to workstations.
"""
import argparse
import ipaddress
import json
import sys
from typing import NoReturn


def resolve(team: int) -> dict:
    """Resolve a team number to its concrete network addresses.

    Team numbers 1-20 (inclusive). N = 20 + team (so N is 21-40).

    Raises ValueError if team is not an integer or outside 1-20.
    """
    # Reject booleans and non-integers
    if isinstance(team, bool) or not isinstance(team, int):
        raise ValueError("team must be an integer")

    # Validate range 1-20
    if team < 1 or team > 20:
        raise ValueError("team must be between 1 and 20 (inclusive)")

    n = 20 + team

    # Internal management addresses are FIXED across all teams (per topology.json).
    # Only the public pool varies by team via N.
    hosts = {
        "rocky_ecom": {"internal": "172.20.240.10", "public": f"172.25.{n}.10"},
        "ubuntu_email": {"internal": "172.20.240.15", "public": f"172.25.{n}.15"},
        "debian_splunk": {"internal": "172.20.240.20", "public": f"172.25.{n}.20"},
        "windows_ad": {"internal": "172.20.240.100", "public": f"172.25.{n}.100"},
        "windows_mssql": {"internal": "172.20.240.120", "public": f"172.25.{n}.120"},
    }

    # Network devices (fixed internal interfaces; public egress is per-team).
    devices = {
        "palo_alto": {
            "inside": "172.20.240.254",
            "outside": "172.16.0.1",
            "management": "172.20.240.200",
        },
        "vyos": {
            "external": f"172.31.{n}.2/29",
            "wkst": "172.17.0.1",
            "internal": "172.16.0.254",
        },
    }

    # Validate every address we emit.
    for host in hosts.values():
        for addr in host.values():
            ipaddress.ip_network(addr, strict=False)
    for dev in devices.values():
        for addr in dev.values():
            ipaddress.ip_network(addr, strict=False)

    return {
        "team": team,
        "n": n,
        "public_pool": f"172.25.{n}.0/24",
        "hosts": hosts,
        "devices": devices,
    }


def fail(message) -> NoReturn:
    """Print JSON error to stderr and exit with code 2."""
    print(json.dumps({"status": "invalid_configuration", "error": message}), file=sys.stderr)
    sys.exit(2)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Resolve team number to network addresses")
    parser.add_argument("--team", type=int, required=True,
                        help="Team number (1-20)")
    parser.add_argument("--json", action="store_true",
                        help="Output as pretty JSON")

    args = parser.parse_args()

    try:
        result = resolve(args.team)
    except ValueError as e:
        fail(str(e))
        return

    if args.json:
        print(json.dumps(result, indent=2))
        return

    # Human-readable table output
    print("Team Address Resolver (CCDC Competition Ops Toolkit)")
    print("=" * 60)
    print(f"Team: {result['team']}   N: {result['n']}   Public pool: {result['public_pool']}")
    print()
    print("Hosts (internal = what you SSH into; public = per-team NAT pool)")
    print("-" * 60)
    for name, addrs in result["hosts"].items():
        print(f"{name:<15} internal {addrs['internal']:<16} public {addrs['public']}")
    print()
    print("Network devices")
    print("-" * 60)
    for name, addrs in result["devices"].items():
        parts = "  ".join(f"{k} {v}" for k, v in addrs.items())
        print(f"{name:<15} {parts}")
    print()
    print("Note: addresses are computed from the topology and must be verified")
    print("against your live configuration. The shared-egress .2/29 is the router")
    print("address, not an address to assign to workstations.")


if __name__ == "__main__":
    main()
