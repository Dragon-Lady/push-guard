import unittest
from io import StringIO
from pathlib import Path
from subprocess import CalledProcessError, CompletedProcess
from unittest.mock import patch

from push_guard.guard import _resolve_git_root, _scan_diff, main, scan_text_for_secrets


class PushGuardTests(unittest.TestCase):
    def test_detects_github_tokens_without_returning_secret_value(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        findings = scan_text_for_secrets(f"token={secret}", path="example.env")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.github_token", findings[0].rule_id)
        self.assertEqual("example.env", findings[0].path)
        self.assertNotIn(secret, findings[0].evidence)
        self.assertIn("redacted", findings[0].evidence.lower())

    def test_detects_github_fine_grained_token_without_returning_secret_value(self):
        secret = "github_pat_11AAAAAAA0abcdefghijklmnopqrstuvwxyzABCDEFGHI"
        findings = scan_text_for_secrets(secret, path="notes.txt")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.github_fine_grained_token", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_detects_private_key_block_without_returning_body(self):
        text = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "abc123abc123abc123abc123\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        findings = scan_text_for_secrets(text, path="id_key")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.private_key", findings[0].rule_id)
        self.assertNotIn("abc123abc123abc123abc123", findings[0].evidence)

    def test_detects_openai_style_token_without_returning_secret_value(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyzABCDEF"
        findings = scan_text_for_secrets(f"OPENAI_API_KEY={secret}", path=".env")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.openai_token", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_detects_aws_access_key_without_returning_secret_value(self):
        secret = "AKIAABCDEFGHIJKLMNOP"
        findings = scan_text_for_secrets(f"AWS_ACCESS_KEY_ID={secret}", path=".env")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.aws_access_key", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_detects_generic_secret_assignment_without_returning_secret_value(self):
        secret = "superlongsecretvalue1234567890"
        findings = scan_text_for_secrets(f"api_key = '{secret}'", path="config.py")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.generic_assignment", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_ignores_obvious_placeholders(self):
        text = "\n".join(
            [
                "api_key=YOUR_API_KEY_HERE",
                "token=example-token-placeholder",
                "password=changeme",
            ]
        )
        findings = scan_text_for_secrets(text, path="README.md")

        self.assertEqual([], findings)

    def test_specific_token_is_not_hidden_by_placeholder_comment(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        findings = scan_text_for_secrets(
            f'token = "{secret}"  # test this config',
            path="config.py",
        )

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.github_token", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_scan_diff_reports_added_secret_path_and_line(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        diff_text = "\n".join(
            [
                "diff --git a/config.py b/config.py",
                "index 1111111..2222222 100644",
                "--- a/config.py",
                "+++ b/config.py",
                "@@ -10,3 +10,4 @@",
                " context line one",
                " context line two",
                f"+token = '{secret}'",
            ]
        )

        findings = _scan_diff(diff_text)

        self.assertEqual(1, len(findings))
        self.assertEqual("config.py", findings[0].path)
        self.assertEqual(12, findings[0].line)

    def test_resolve_git_root_canonicalizes_nested_repo_path(self):
        nested = Path("C:/Users/tanya/dragoneye")
        root = "C:/Users/tanya"

        with patch(
            "push_guard.guard.subprocess.run",
            return_value=CompletedProcess(
                args=["git"],
                returncode=0,
                stdout=f"{root}\n",
                stderr="",
            ),
        ) as run:
            resolved = _resolve_git_root(nested)

        self.assertEqual(Path(root), resolved)
        run.assert_called_once_with(
            [
                "git",
                "-c",
                f"safe.directory={nested}",
                "-C",
                str(nested),
                "rev-parse",
                "--show-toplevel",
            ],
            check=True,
            text=True,
            stdout=-1,
            stderr=-1,
        )

    def test_resolve_git_root_retries_dubious_ownership_root(self):
        nested = Path("C:/Users/tanya/dragoneye")
        root = Path("C:/Users/tanya")
        dubious = CalledProcessError(
            returncode=128,
            cmd=["git"],
            stderr=(
                "fatal: detected dubious ownership in repository at "
                "'C:/Users/tanya'\n"
            ),
        )

        with patch(
            "push_guard.guard.subprocess.run",
            side_effect=[
                dubious,
                CompletedProcess(
                    args=["git"],
                    returncode=0,
                    stdout=f"{root}\n",
                    stderr="",
                ),
            ],
        ) as run:
            resolved = _resolve_git_root(nested)

        self.assertEqual(root, resolved)
        self.assertEqual(2, run.call_count)
        self.assertIn(f"safe.directory={root}", run.call_args_list[1].args[0])

    def test_main_blocks_and_reports_redacted_findings(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        finding_diff = "\n".join(
            [
                "diff --git a/config.py b/config.py",
                "--- a/config.py",
                "+++ b/config.py",
                "@@ -1,0 +1,1 @@",
                f"+token = '{secret}'",
            ]
        )

        with (
            patch("push_guard.guard._diffs_for_push_ref", return_value=[finding_diff]),
            patch("sys.stdin", StringIO("refs/heads/main abc refs/heads/main def\n")),
            patch("sys.stderr", new_callable=StringIO) as stderr,
        ):
            exit_code = main(["--repo", "."])

        self.assertEqual(1, exit_code)
        output = stderr.getvalue()
        self.assertIn("blocked this push", output)
        self.assertIn("<redacted>", output)
        self.assertNotIn(secret, output)

    def test_main_reports_clean_git_inspection_error_without_traceback(self):
        with (
            patch(
                "push_guard.guard._diffs_for_push_ref",
                side_effect=RuntimeError("git diff failed"),
            ),
            patch("sys.stdin", StringIO("refs/heads/main abc refs/heads/main def\n")),
            patch("sys.stderr", new_callable=StringIO) as stderr,
        ):
            exit_code = main(["--repo", "."])

        self.assertEqual(1, exit_code)
        output = stderr.getvalue()
        self.assertIn("could not inspect this push", output)
        self.assertIn("Blocking push because inspection failed", output)
        self.assertNotIn("Traceback", output)
