"""Offline tests for scripts/team_addresses.py.

All network activity is mocked; fixtures use sanitized addresses and
placeholder values only. No live competition probes are performed.
"""
import argparse
import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import team_addresses as ta  # noqa: E402


class ResolveTests(unittest.TestCase):
    """Test the resolve() function."""

    def test_resolve_team_17(self):
        """Team 17 should produce the exact values from config/topology.json."""
        result = ta.resolve(17)

        self.assertEqual(result["team"], 17)
        self.assertEqual(result["n"], 37)
        self.assertEqual(result["public_pool"], "172.25.37.0/24")
        # Hosts: internal (fixed) and public (per-team via N=37).
        self.assertEqual(result["hosts"]["rocky_ecom"]["internal"], "172.20.240.10")
        self.assertEqual(result["hosts"]["rocky_ecom"]["public"], "172.25.37.10")
        self.assertEqual(result["hosts"]["ubuntu_email"]["internal"], "172.20.240.15")
        self.assertEqual(result["hosts"]["ubuntu_email"]["public"], "172.25.37.15")
        self.assertEqual(result["hosts"]["debian_splunk"]["internal"], "172.20.240.20")
        self.assertEqual(result["hosts"]["debian_splunk"]["public"], "172.25.37.20")
        self.assertEqual(result["hosts"]["windows_ad"]["internal"], "172.20.240.100")
        self.assertEqual(result["hosts"]["windows_ad"]["public"], "172.25.37.100")
        self.assertEqual(result["hosts"]["windows_mssql"]["internal"], "172.20.240.120")
        self.assertEqual(result["hosts"]["windows_mssql"]["public"], "172.25.37.120")
        # Devices: fixed internal interfaces; public egress is per-team.
        self.assertEqual(result["devices"]["palo_alto"]["inside"], "172.20.240.254")
        self.assertEqual(result["devices"]["palo_alto"]["outside"], "172.16.0.1")
        self.assertEqual(result["devices"]["palo_alto"]["management"], "172.20.240.200")
        self.assertEqual(result["devices"]["vyos"]["external"], "172.31.37.2/29")
        self.assertEqual(result["devices"]["vyos"]["wkst"], "172.17.0.1")
        self.assertEqual(result["devices"]["vyos"]["internal"], "172.16.0.254")

    def test_resolve_team_1(self):
        """Team 1 should produce N=21 and consistent per-team public addresses."""
        result = ta.resolve(1)
        self.assertEqual(result["n"], 21)
        self.assertEqual(result["public_pool"], "172.25.21.0/24")
        self.assertEqual(result["hosts"]["rocky_ecom"]["public"], "172.25.21.10")
        self.assertEqual(result["devices"]["vyos"]["external"], "172.31.21.2/29")
        # Internal addresses are fixed regardless of team.
        self.assertEqual(result["hosts"]["rocky_ecom"]["internal"], "172.20.240.10")

    def test_resolve_team_20(self):
        """Team 20 (upper bound) should produce N=40."""
        result = ta.resolve(20)
        self.assertEqual(result["n"], 40)
        self.assertEqual(result["hosts"]["windows_mssql"]["public"], "172.25.40.120")

    def test_resolve_rejects_zero(self):
        with self.assertRaises(ValueError):
            ta.resolve(0)

    def test_resolve_rejects_21(self):
        with self.assertRaises(ValueError):
            ta.resolve(21)

    def test_resolve_rejects_negative(self):
        with self.assertRaises(ValueError):
            ta.resolve(-5)

    def test_resolve_rejects_non_integer(self):
        with self.assertRaises(ValueError):
            ta.resolve("17")

    def test_resolve_rejects_bool(self):
        """Booleans are ints in Python; reject them explicitly."""
        with self.assertRaises(ValueError):
            ta.resolve(True)


class CLITests(unittest.TestCase):
    """Test CLI behavior."""

    def _run_main(self, argv):
        old_argv = sys.argv[:]
        old_stdout = sys.stdout
        sys.argv = argv
        sys.stdout = io.StringIO()
        try:
            ta.main()
            return sys.stdout.getvalue()
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout

    def test_cli_json_output(self):
        output = self._run_main(["team_addresses.py", "--team", "17", "--json"])
        parsed = json.loads(output)
        self.assertEqual(parsed["team"], 17)
        self.assertEqual(parsed["n"], 37)
        self.assertIn("hosts", parsed)
        self.assertIn("devices", parsed)

    def test_cli_human_readable(self):
        output = self._run_main(["team_addresses.py", "--team", "17"])
        self.assertIn("Team: 17", output)
        self.assertIn("N: 37", output)
        self.assertIn("172.25.37.0/24", output)
        self.assertIn("172.20.240.10", output)
        self.assertIn("verified", output)
        self.assertIn("live configuration", output)
        self.assertIn(".2/29", output)

    def test_cli_invalid_team_exits_2(self):
        old_stderr = sys.stderr
        old_stdout = sys.stdout
        sys.stderr = io.StringIO()
        sys.stdout = io.StringIO()
        try:
            with self.assertRaises(SystemExit) as ctx:
                self._run_main(["team_addresses.py", "--team", "25"])
            self.assertEqual(ctx.exception.code, 2)
        finally:
            sys.stderr = old_stderr
            sys.stdout = old_stdout


if __name__ == "__main__":
    unittest.main()
