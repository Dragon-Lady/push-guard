"""Keep shipping source text clean without weakening secret detection."""

from pathlib import Path
import unittest

from push_guard.guard import scan_text_for_secrets


ROOT = Path(__file__).resolve().parents[1]


class ReleaseContentTests(unittest.TestCase):
    def test_shipping_source_and_readme_pass_full_content_scan(self):
        paths = sorted((ROOT / "src" / "push_guard").glob("*.py"))
        paths.extend([ROOT / "README.md", ROOT / "CHANGELOG.md"])
        for path in paths:
            with self.subTest(path=path.name):
                self.assertEqual([], scan_text_for_secrets(
                    path.read_text(encoding="utf-8"),
                    path=path.relative_to(ROOT).as_posix(),
                ))

    def test_reviewed_description_lines_still_block_provider_credentials(self):
        lines = (ROOT / "src/push_guard/guard.py").read_text().splitlines()
        descriptions = [line for line in lines if "push-guard: ignore" in line
                        and any(text in line for text in (
                            "untrusted event-to-agent boundary",
                            "surface is wired near MCP agent context",
                            "second-stage payload name",
                        ))]
        self.assertEqual(3, len(descriptions))
        credential = "ghp_" + "Q" * 36
        for line in descriptions:
            with self.subTest(description=line):
                findings = scan_text_for_secrets(
                    line + " " + credential, path="push_guard/guard.py"
                )
                self.assertTrue(any(hit.rule_id == "secret.github_token"
                                    for hit in findings))
