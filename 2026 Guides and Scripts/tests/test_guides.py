"""Documentation structure only: no claim of CVE, command or SPL correctness."""
import json
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'
HEADINGS = (
    'Vulnerabilities and applicability',
    'Patching and recovery',
    'Detection when patching is deferred',
    'Threat hunting',
    'Splunk monitoring',
    'References',
)


def without_fences(text):
    return re.sub(r'^```[^\n]*\n.*?^```\s*$', '', text,
                  flags=re.MULTILINE | re.DOTALL)


class GuideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = json.loads((ROOT / 'config/topology.json').read_text())
        cls.guides = [DOCS / 'systems' / (host['id'] + '.md')
                      for host in cls.inventory]
        cls.shared = DOCS / 'splunk-threat-hunting.md'

    def test_inventory_and_sections(self):
        self.assertEqual(len(self.inventory), 10)
        self.assertEqual(len({h['id'] for h in self.inventory}), 10)
        for guide in self.guides:
            with self.subTest(guide=guide.name):
                text = guide.read_text()
                for heading in HEADINGS:
                    matches = re.findall(
                        r'^## ' + re.escape(heading) + r'\n(.*?)(?=^## |\Z)',
                        text, flags=re.MULTILINE | re.DOTALL)
                    self.assertEqual(len(matches), 1, heading)
                    self.assertTrue(matches[0].strip(), heading)
                    self.assertRegex(matches[0], r'[A-Za-z0-9]')

    def test_machine_spl_shared_link_and_sources(self):
        for guide in self.guides:
            with self.subTest(guide=guide.name):
                text = guide.read_text()
                section = text.split('## Splunk monitoring\n', 1)[1].split('\n## ', 1)[0]
                self.assertRegex(section, r'```spl\n[\s\S]+?\n```')
                self.assertIn('../splunk-threat-hunting.md', section)
                refs = text.split('## References\n', 1)[1]
                self.assertRegex(refs, r'https://[^\s)]+')
                self.assertRegex(refs, r'\b20\d{2}-\d{2}-\d{2}\b')

    def test_shared_inventory_and_navigation(self):
        shared = self.shared.read_text()
        index = (DOCS / 'README.md').read_text()
        self.assertIn('splunk-threat-hunting.md', index)
        for host in self.inventory:
            with self.subTest(host=host['id']):
                self.assertIn('`' + host['id'] + '`', shared)
                self.assertIn('systems/' + host['id'] + '.md', index)
        self.assertIn('test_guides.py', (DOCS / 'validation.md').read_text())

    def test_collection_profiles_and_monitoring_contract(self):
        collection = (DOCS / 'splunk-data-sources.md').read_text()
        hunting = self.shared.read_text()
        query = (DOCS / 'services/splunk-query.md').read_text()
        for host in self.inventory:
            self.assertIn('`' + host['id'] + '`', collection)
        for value in ('--optional-source', '--os-source journal', '-HostId', '-InputPath',
                      'SQLAGENT.OUT', 'kali_watch', 'LINE_BREAKER', 'No self-forwarding'):
            self.assertIn(value, collection)
        for value in ('inputlookup expected_sources.csv', 'isnull(last_seen)',
                      'by host source', 'passes{}', 'pass_time_utc', 'checks{}',
                      'earliest=-24h latest=-2m'):
            self.assertIn(value, hunting)
        self.assertNotIn('index=REPLACE_', hunting)
        for value in ('--cacert', "--user '<user>'", 'latest=-2m', 'team_security',
                      'secret store', 'zero events'):
            self.assertIn(value, query)
        self.assertNotIn('curl -sk', query)

    def test_kali_activation_and_storage_contract(self):
        text = (DOCS / 'kali-operations.md').read_text()
        headings = re.findall(r'^## (.+)$', without_fences(text), re.M)
        self.assertEqual(len(headings), len(set(headings)))
        self.assertNotIn('HTTP checks are **independent**', text)
        self.assertNotIn('https_checks', text)
        for value in ('WATCH_SCOPE=public', "cfg['http_checks'] =", 'umask 077',
                      'install -d -m 0700', 'mktemp', 'mv --', 'SSL_CERT_FILE=',
                      'no UDP or ICMP checks', 'exits 2'):
            self.assertIn(value, text)
        self.assertIn('splunk-data-sources.md#kali-nested-json-result-ingestion', text)

    def test_relative_markdown_link_targets(self):
        # Scope is the documentation changed by this task; ignore fenced examples.
        service_docs = sorted((DOCS / 'services').glob('*.md'))
        paths = self.guides + [self.shared, DOCS / 'README.md', DOCS / 'validation.md'] + service_docs
        for path in paths:
            content = without_fences(path.read_text())
            for target in re.findall(r'\[[^\]\n]+\]\(([^)\n]+)\)', content):
                target = target.strip().split(' "', 1)[0].strip('<>')
                parsed = urlsplit(target)
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                with self.subTest(document=path.name, target=target):
                    resolved = (path.parent / unquote(parsed.path)).resolve()
                    self.assertTrue(resolved.is_relative_to(ROOT), target)
                    self.assertTrue(resolved.exists(), target)


SERVICE_HEADINGS = (
    'Discovery',
    'Setup',
    'Configuration',
    'Monitoring',
    'Backup',
    'Usage and scoring verification',
    'Recovery',
    'References',
)


class ServiceGuideTests(unittest.TestCase):
    """Validate docs/services/*.md structure (excluding README.md)."""

    @classmethod
    def setUpClass(cls):
        svc_dir = DOCS / 'services'
        cls.guides = sorted(svc_dir.glob('*.md'))
        # Exclude the index/README
        cls.guides = [g for g in cls.guides if g.name != 'README.md']

    def test_service_guide_count(self):
        self.assertGreaterEqual(len(self.guides), 8,
                                "Expected at least 8 service guides")

    def test_required_sections(self):
        for guide in self.guides:
            with self.subTest(guide=guide.name):
                text = guide.read_text()
                for heading in SERVICE_HEADINGS:
                    matches = re.findall(
                        r'^## ' + re.escape(heading) + r'\n(.*?)(?=^## |\Z)',
                        text, flags=re.MULTILINE | re.DOTALL)
                    self.assertEqual(len(matches), 1, heading)
                    self.assertTrue(matches[0].strip(), heading)

    def test_references_section_has_link(self):
        """Each guide's References section must contain at least one link."""
        for guide in self.guides:
            with self.subTest(guide=guide.name):
                text = guide.read_text()
                refs = text.split('## References\n', 1)[1]
                # Accept absolute URLs or relative Markdown links
                self.assertRegex(refs, r'(https?://[^\s)]+|\[[^\]]+\]\([^)]+\))',
                                 "References must contain at least one link")

    def test_discovery_mentions_verification(self):
        """Each guide's Discovery section should note the service is unconfirmed."""
        for guide in self.guides:
            with self.subTest(guide=guide.name):
                text = guide.read_text()
                disc = text.split('## Discovery\n', 1)[1].split('\n## ', 1)[0]
                self.assertRegex(disc, r'unconfirm|candidate|verify|not.*confirmed',
                                 'Discovery should note service is a candidate')


if __name__ == '__main__':
    unittest.main()
