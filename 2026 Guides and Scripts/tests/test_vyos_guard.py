import importlib.util
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vyos_guard', ROOT/'scripts/vyos_guard.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

class VyosGuardTests(unittest.TestCase):
    def test_existing_policy_continues_for_trusted(self):
        commands, rollback = v.plan_commands(['172.20.240.0/24'], 'eth2')
        self.assertEqual(commands[0], 'set firewall ipv4 name TEAM-HARDEN default-action return')
        text = '\n'.join(commands)
        self.assertIn('rule 10 action return', text)
        self.assertIn('rule 90 action drop', text)
        self.assertIn('input filter rule 1 action jump', text)
        self.assertIn('input filter rule 1 inbound-interface name eth2', text)
        self.assertIn('input filter rule 1 destination port 22', text)
        self.assertNotIn('action accept', text)
        self.assertEqual(rollback, ['delete firewall ipv4 input filter rule 1', 'delete firewall ipv4 name TEAM-HARDEN'])
    def test_rejects_command_injection_and_invalid_prefixes(self):
        for sources, iface in [(['0.0.0.0/33'], 'eth2'), (['::/0'], 'eth2'), ([], 'eth2'), (['172.17.0.0/24'], 'eth2;delete')]:
            with self.assertRaises(ValueError):
                v.plan_commands(sources, iface)
    def test_host_profile(self):
        trusted, iface = v.load_host_profile('vyos')
        self.assertEqual(iface, 'eth2')
        self.assertIn('172.17.0.0/24', trusted)

    def test_unknown_or_wrong_platform_rejected(self):
        for host in ['no-such-host', 'rocky-ecom']:
            with self.assertRaises(ValueError):
                v.load_host_profile(host)
