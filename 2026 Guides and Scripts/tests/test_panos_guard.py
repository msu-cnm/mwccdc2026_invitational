import importlib.util
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('panos_guard', ROOT/'scripts/panos_guard.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class PanosGuardTests(unittest.TestCase):
    def test_mgt_not_transit(self):
        commands, rollback = p.plan_commands(['172.20.240.0/24'])
        self.assertEqual(commands, ['delete deviceconfig system permitted-ip', 'set deviceconfig system permitted-ip 172.20.240.0/24'])
        self.assertEqual(rollback, ['load config from team-before.xml'])
        self.assertNotIn('security', '\n'.join(commands))
    def test_rejects_empty_and_injection(self):
        for sources in [[], ['172.20.240.0/24;commit'], ['::/0']]:
            with self.assertRaises(ValueError):
                p.plan_commands(sources)
    def test_profile(self):
        self.assertEqual(p.load_host_profile('palo-alto'), ['172.20.240.0/24'])

    def test_unknown_or_wrong_platform_rejected(self):
        for host in ['no-such-host', '2022-ad']:
            with self.assertRaises(ValueError):
                p.load_host_profile(host)
