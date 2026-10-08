"""Operator-path regressions: real Git objects, isolated homes, no network."""
import contextlib
import io
import os
from pathlib import Path
import shlex
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import push_guard.guard as guard_module
from push_guard.guard import (PushGuardInspectionError, _decode_diff_path,
                              install_pre_push_hook, main, scan_git_push,
                              scan_git_range, scan_text_for_secrets)


class GitInspectionHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        home = self.root / "home"
        home.mkdir()
        self.environment = patch.dict(os.environ, {
            "HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"),
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0", "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_AUTHOR_NAME": "Push Guard Test", "GIT_AUTHOR_EMAIL": "push-guard@example.invalid",
            "GIT_COMMITTER_NAME": "Push Guard Test", "GIT_COMMITTER_EMAIL": "push-guard@example.invalid",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("commit", "--allow-empty", "-qm", "fixture base")
        self.base = self.git("rev-parse", "HEAD")
        self.token = "gh" + "p_" + "A7b9C3d5" * 5

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, path, data):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data, encoding="utf-8")
        self.git("add", "--", path)
        self.git("commit", "-qm", "fixture change")
        return self.git("rev-parse", "HEAD")

    def test_color_always_cannot_hide_content(self):
        self.commit("settings.txt", self.token + "\n")
        self.git("config", "color.ui", "always")
        findings = scan_git_range(self.repo, self.base)
        self.assertIn("secret.github_token", {f.rule_id for f in findings})

    def test_attributes_cannot_hide_plain_text_as_binary(self):
        self.commit(".gitattributes", "settings.txt -diff\n")
        self.commit("settings.txt", self.token + "\n")
        findings = scan_git_range(self.repo, self.base)
        self.assertIn("secret.github_token", {f.rule_id for f in findings})

    def test_noprefix_configuration_cannot_hide_manifest_path(self):
        self.commit("package.json", '{"dependencies":{"lodash":"4.17.23"}}\n')
        self.git("config", "diff.noprefix", "true")
        findings = scan_git_range(self.repo, self.base)
        self.assertIn("workflow.lodash_template_cve_2026_4800_pin", {f.rule_id for f in findings})

    def test_actual_hook_never_executes_textconv(self):
        marker = self.root / "converter-executed"
        helper = self.root / "converter.py"
        helper.write_text("from pathlib import Path\nPath(" + repr(str(marker)) +
                          ").write_text('executed')\nprint('sanitized presentation')\n")
        self.git("config", "diff.fixture.textconv", shlex.join([sys.executable, str(helper)]))
        self.commit(".gitattributes", "settings.txt diff=fixture\n")
        head = self.commit("settings.txt", self.token + "\n")
        hook = install_pre_push_hook(self.repo)
        environment = dict(os.environ)
        # Derive the actual imported package root so the same hook regression
        # exercises either source or the installed wheel, never a guessed tree.
        imported = Path(guard_module.__file__).resolve()
        if os.environ.get("PUSH_GUARD_TEST_INSTALLED") == "1":
            self.assertIn("site-packages", imported.parts)
        environment["PYTHONPATH"] = str(imported.parents[1])
        completed = subprocess.run([str(hook)], cwd=self.repo, text=True,
                                   input=f"refs/heads/main {head} refs/heads/main {self.base}\n",
                                   capture_output=True, env=environment)
        self.assertEqual(1, completed.returncode)
        self.assertIn("secret.github_token", completed.stderr)
        self.assertNotIn(self.token, completed.stdout + completed.stderr)
        self.assertFalse(marker.exists(), "inspection must not execute configured textconv helpers")

    def test_new_remote_does_not_trust_other_remote_tracking_refs(self):
        self.commit("settings.txt", self.token + "\n")
        head = self.commit("README.md", "harmless tip change\n")
        self.git("update-ref", "refs/remotes/private/main", head)
        findings = scan_git_push(self.repo, f"refs/heads/main {head} refs/heads/main {'0' * 40}\n")
        self.assertIn("secret.github_token", {f.rule_id for f in findings})

    def test_filename_credential_is_redacted_in_api_and_cli(self):
        self.commit(self.token + ".txt", self.token + "\n")
        findings = scan_git_range(self.repo, self.base)
        self.assertTrue(findings)
        self.assertNotIn(self.token, repr(findings))
        self.assertEqual("<redacted>", findings[0].path)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["scan", "--repo", str(self.repo), "--base", self.base])
        self.assertEqual(1, code)
        self.assertNotIn(self.token, out.getvalue() + err.getvalue())

    def test_encoded_filename_credential_is_redacted(self):
        encoded = self.token.replace("_", "%5F")
        self.commit(encoded + ".txt", self.token + "\n")
        findings = scan_git_range(self.repo, self.base)
        self.assertEqual("<redacted>", findings[0].path)
        self.assertNotIn(encoded, repr(findings))

    def test_secret_bearing_invalid_ref_error_is_redacted(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["scan", "--repo", str(self.repo), "--base", self.token])
        self.assertEqual(1, code)
        self.assertNotIn(self.token, out.getvalue() + err.getvalue())

    def test_ordinary_filename_is_preserved(self):
        self.commit("ordinary-settings.txt", self.token + "\n")
        findings = scan_git_range(self.repo, self.base)
        self.assertEqual("ordinary-settings.txt", findings[0].path)

    def test_quoted_unicode_and_control_paths_keep_manifest_scoping(self):
        for directory in ("caf\u00e9", "tab\tdir", "new\nline", 'quote"dir'):
            with self.subTest(directory=directory):
                base = self.git("rev-parse", "HEAD")
                path = directory + "/package.json"
                self.commit(path, '{"dependencies":{"lodash":"4.17.23"}}\n')
                findings = scan_git_range(self.repo, base)
                self.assertIn("workflow.lodash_template_cve_2026_4800_pin", {f.rule_id for f in findings})
                self.assertTrue(any(f.path == path for f in findings))

    def test_plus_prefixed_content_cannot_impersonate_diff_header(self):
        self.commit("notes.txt", "++" + self.token + "\n++ b/" + self.token + "\n")
        findings = scan_git_range(self.repo, self.base)
        self.assertEqual(2, sum(f.rule_id == "secret.github_token" for f in findings))

    def test_malformed_quoted_diff_paths_fail_closed(self):
        for path in ('"b/unfinished', '"b/invalid\\x"', '"b/invalid\\777"', 'a/incorrect-prefix'):
            with self.subTest(path=path), self.assertRaises(PushGuardInspectionError):
                _decode_diff_path(path)

    def test_mcp_extras_keep_exact_affected_pin_detection(self):
        rule = "workflow.mcp_oauth_credential_routing_pin"
        for value, path in (("mcp[cli]==1.29.1", "requirements.txt"),
                            ('dependencies = ["mcp[cli,http]==2.0.0a1"]', "pyproject.toml"),
                            ("MCP[ cli, http ]==1.29.1", "requirements.txt")):
            with self.subTest(value=value):
                self.assertIn(rule, {f.rule_id for f in scan_text_for_secrets(value, path)})
        for value, path in (("mcp[cli]==1.30.0", "requirements.txt"),
                            ("mcp[cli]>=1.29.1", "requirements.txt"),
                            ("other-mcp[cli]==1.29.1", "requirements.txt"),
                            ("mcp[cli]==1.29.1", "README.md")):
            with self.subTest(value=value, path=path):
                self.assertNotIn(rule, {f.rule_id for f in scan_text_for_secrets(value, path)})

    def test_phantomsub_npm_v3_keys_are_exact_and_lockfile_scoped(self):
        rule = "workflow.phantomsub_ox_npm_package"
        for key, path in (("node_modules/ourin-baileys", "package-lock.json"),
                          ("node_modules/@nexustechpro/baileys", "npm-shrinkwrap.json"),
                          ("node_modules/host/node_modules/ourin-baileys", "package-lock.json"),
                          ("node_modules/@scope/host/node_modules/@nexustechpro/baileys", "package-lock.json")):
            with self.subTest(key=key, path=path):
                line = '"' + key + '": {"version": "1.2.3"}'
                self.assertIn(rule, {f.rule_id for f in scan_text_for_secrets(line, path)})
        for key, path in (("node_modules/ourin-baileys-extra", "package-lock.json"),
                          ("node_modules/@legitimate/ourin-baileys", "package-lock.json"),
                          ("docs/node_modules/ourin-baileys", "package-lock.json"),
                          ("node_modules/ourin-baileys", "README.md"),
                          ("node_modules/ourin-baileys", "package.json")):
            with self.subTest(key=key, path=path):
                line = '"' + key + '": {"version": "1.2.3"}'
                self.assertNotIn(rule, {f.rule_id for f in scan_text_for_secrets(line, path)})

    def test_cli_escapes_terminal_controls_without_changing_rule_paths(self):
        path = "line\n\x1b[2J\u202edir/package.json"
        self.commit(path, '{"dependencies":{"lodash":"4.17.23"}}\n')
        findings = scan_git_range(self.repo, self.base)
        self.assertTrue(any(f.path == path for f in findings))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["scan", "--repo", str(self.repo), "--base", self.base])
        self.assertEqual(1, code)
        visible = out.getvalue() + err.getvalue()
        self.assertNotIn("\x1b", visible)
        self.assertNotIn("\u202e", visible)
        self.assertIn("line\\x0a\\x1b[2J\\u202edir/package.json", visible)

    def test_parser_error_redacts_credentials_and_controls(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            main(["scan", "--base", "HEAD", "--invalid", self.token + "\x1b[2J"])
        self.assertNotIn(self.token, err.getvalue())
        self.assertNotIn("\x1b", err.getvalue())

    def test_private_path_added_then_deleted_remains_outgoing(self):
        self.commit("archive.kdbx", "private fixture bytes without a token shape\n")
        self.git("rm", "-q", "archive.kdbx")
        self.git("commit", "-qm", "fixture removal")
        head = self.git("rev-parse", "HEAD")
        for findings in (scan_git_range(self.repo, self.base),
                         scan_git_push(self.repo, f"refs/heads/main {head} refs/heads/main {self.base}\n")):
            self.assertTrue(any(f.rule_id == "private_path.match" and f.path == "archive.kdbx" for f in findings))

    def test_private_path_only_in_trusted_base_is_not_rescanned(self):
        self.commit("archive.kdbx", "old remote fixture bytes\n")
        base = self.git("rev-parse", "HEAD")
        self.commit("README.md", "harmless intervening outgoing change\n")
        self.git("rm", "-q", "archive.kdbx")
        self.git("commit", "-qm", "remove old remote private path")
        self.assertEqual([], scan_git_range(self.repo, base))

    def test_private_path_history_keeps_safe_template_exception(self):
        self.commit(".env.example", "ordinary placeholder documentation\n")
        self.git("rm", "-q", ".env.example")
        self.git("commit", "-qm", "remove fixture template")
        self.assertEqual([], scan_git_range(self.repo, self.base))

    def test_private_path_history_applies_local_patterns_and_quoted_paths(self):
        (self.repo / ".push-guard-private-paths").write_text("private-lane/\n")
        path = "private-lane/line\nnotes.txt"
        self.commit(path, "private non-token fixture content\n")
        self.git("rm", "-q", "--", path)
        self.git("commit", "-qm", "remove fixture private path")
        findings = scan_git_range(self.repo, self.base)
        self.assertTrue(any(f.path == path and f.rule_id == "private_path.match" for f in findings))


if __name__ == "__main__":
    unittest.main()
