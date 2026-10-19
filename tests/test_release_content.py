"""Reviewed source fixtures never exempt credentials or private terms."""
from pathlib import Path
import unittest

from push_guard.guard import scan_text_for_secrets, load_fixture_allow_list, _apply_fixture_allow_list

ROOT = Path(__file__).resolve().parents[1]


class ReleaseContentTests(unittest.TestCase):
    def test_shipping_source_and_readme_pass_reviewed_scan(self):
        paths = sorted((ROOT / 'src/push_guard').glob('*.py'))
        paths.extend([ROOT / 'README.md', ROOT / 'CHANGELOG.md'])
        for path in paths:
            with self.subTest(path=path.name):
                findings = scan_text_for_secrets(path.read_text(), path=path.relative_to(ROOT).as_posix())
                remaining, _ = _apply_fixture_allow_list(findings, load_fixture_allow_list(ROOT))
                self.assertEqual([], remaining)

    def test_reviewed_description_lines_still_block_provider_credentials(self):
        lines = (ROOT / 'src/push_guard/guard.py').read_text().splitlines()
        descriptions = [line for line in lines if any(text in line for text in (
            'untrusted event-to-agent boundary', 'surface is wired near MCP agent context',
            'second-stage payload name'))]
        self.assertEqual(3, len(descriptions))
        credential = 'ghp_' + 'Q' * 36
        for line in descriptions:
            with self.subTest(description=line):
                findings = scan_text_for_secrets(line + ' ' + credential, path='push_guard/guard.py')
                findings, _ = _apply_fixture_allow_list(findings, load_fixture_allow_list(ROOT))
                self.assertTrue(any(hit.rule_id == 'secret.github_token' for hit in findings))
