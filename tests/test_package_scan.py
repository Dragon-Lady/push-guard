import io
import os
import subprocess
import tarfile
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from push_guard.guard import (
    PushGuardInspectionError, _identity_terms, main, scan_git_push,
    scan_git_range,
)
from push_guard.package_scan import scan_distribution


class PackageScanTests(unittest.TestCase):
    def test_account_identity_is_inferred_without_public_name_list(self):
        terms = _identity_terms("lena", "Lena Vale,Room 7", "cedarbox")
        self.assertIn("lena", terms)
        self.assertIn("Lena Vale", terms)
        self.assertIn("Lena", terms)
        self.assertIn("cedarbox", terms)
        self.assertNotIn("runner", _identity_terms("runner", "", "localhost"))

    def test_generic_account_and_host_names_are_not_inferred(self):
        for value in ("abc", "dev", "test", "code", "node", "git", "sample", "vagrant", "ec2-user", "codespace123"):
            with self.subTest(value=value):
                self.assertNotIn(value, _identity_terms(value, "", ""))
        for value in ("DEVICE-ABCD", "MacBook-Pro", "raspberrypi", "desktop-WXYZ"):
            with self.subTest(value=value):
                self.assertEqual([], _identity_terms("", "", value))

    def test_new_refs_scan_only_commits_absent_from_remote_tracking_refs(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            def git(*args):
                return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
            git("init", "-q")
            git("config", "user.name", "Package Test")
            git("config", "user.email", "package-test@example.invalid")
            git("remote", "add", "origin", str(root / "remote.git"))
            git("remote", "add", "private", str(root / "private.git"))
            (root / "REVIEW.md").write_text("Lena was here.\n")
            git("add", ".")
            git("commit", "-qm", "old private line")
            (root / "REVIEW.md").write_text("Neutral text.\n")
            git("add", ".")
            git("commit", "-qm", "scrub")
            clean_sha = git("rev-parse", "HEAD")
            git("tag", "-a", "v1", "-m", "release")
            tag_sha = git("rev-parse", "v1")
            git("tag", "-a", "v2", "-m", "Lena release")
            bad_tag_sha = git("rev-parse", "v2")
            zero = "0" * 40
            git("update-ref", "refs/remotes/private/main", clean_sha)
            with patch("push_guard.guard._local_identity_terms", return_value=["Lena"]), \
                 patch("push_guard.guard.USER_BLOCKED_TERMS", root / "missing"), \
                 patch.dict(os.environ, {"PUSH_GUARD_BLOCKED_TERMS": ""}):
                first = scan_git_push(root, f"refs/heads/main {clean_sha} refs/heads/main {zero}\n", "origin")
                self.assertTrue(any(f.rule_id == "personal.blocked_term" for f in first))
                git("update-ref", "refs/remotes/origin/main", clean_sha)
                for ref, sha in (("refs/heads/release", clean_sha), ("refs/tags/v1", tag_sha)):
                    with self.subTest(ref=ref):
                        self.assertEqual([], scan_git_push(root, f"{ref} {sha} {ref} {zero}\n", "origin"))
                tag_findings = scan_git_push(root, f"refs/tags/v2 {bad_tag_sha} refs/tags/v2 {zero}\n", "origin")
                self.assertTrue(any(f.rule_id == "personal.blocked_term" for f in tag_findings))
                (root / "NEW.md").write_text("Lena appeared again.\n")
                git("add", ".")
                git("commit", "-qm", "new private line")
                new_sha = git("rev-parse", "HEAD")
                later = scan_git_push(root, f"refs/heads/new {new_sha} refs/heads/new {zero}\n", "origin")
                self.assertTrue(any(f.rule_id == "personal.blocked_term" for f in later))

    def test_release_gate_rejects_single_line_list_and_counts_terms(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wheel = root / "demo-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as package:
                package.writestr("demo/README.md", "Clean release text.\n")
            with patch("push_guard.guard.USER_BLOCKED_TERMS", root / "missing"):
                for secret in ("Lena,cedarbox,home", "Lena;cedarbox;home", "Lena cedarbox home"):
                    with self.subTest(separator=secret[4]), patch.dict(os.environ, {"PUSH_GUARD_BLOCKED_TERMS": secret}):
                        self.assertEqual(1, main(["scan-package", "--repo", str(root), "--require-explicit-terms", "--min-terms", "3", str(wheel)]))
                with patch.dict(os.environ, {"PUSH_GUARD_BLOCKED_TERMS": "Lena\ncedarbox\nhome"}):
                    self.assertEqual(0, main(["scan-package", "--repo", str(root), "--require-explicit-terms", "--min-terms", "3", str(wheel)]))

    def test_no_infer_keeps_explicit_private_terms(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wheel = root / "demo-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as package:
                package.writestr("demo/REVIEW.md", "Lena approved this release.\n")
            with patch("push_guard.guard._local_identity_terms", return_value=["Lena"]), \
                 patch("push_guard.guard.USER_BLOCKED_TERMS", root / "missing"), \
                 patch.dict(os.environ, {"PUSH_GUARD_BLOCKED_TERMS": "cedarbox"}):
                self.assertEqual(1, main(["scan-package", "--repo", str(root), str(wheel)]))
                self.assertEqual(0, main(["scan-package", "--repo", str(root), "--no-infer", str(wheel)]))

    def test_wheel_and_sdist_block_name_in_release_note_without_echoing_it(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            content = b"Lena approved this release.\n"
            wheel = root / "demo-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as package:
                package.writestr("demo/REVIEW.md", content)
            sdist = root / "demo-1.0.tar.gz"
            with tarfile.open(sdist, "w:gz") as package:
                item = tarfile.TarInfo("demo-1.0/REVIEW.md")
                item.size = len(content)
                package.addfile(item, io.BytesIO(content))
            with patch.dict(os.environ, {"PUSH_GUARD_BLOCKED_TERMS": "Lena"}), \
                 patch("push_guard.guard.USER_BLOCKED_TERMS", root / "missing"):
                for archive in (wheel, sdist):
                    with self.subTest(archive=archive.name):
                        findings = scan_distribution(
                            archive, root, require_explicit_terms=True
                        )
                        self.assertEqual(
                            ["personal.blocked_term"],
                            [finding.rule_id for finding in findings],
                        )
                        self.assertNotIn("Lena", repr(findings))

    def test_release_gate_fails_closed_without_explicit_terms(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wheel = root / "demo-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as package:
                package.writestr("demo/README.md", "Clean release text.\n")
            with patch.dict(os.environ, {"PUSH_GUARD_BLOCKED_TERMS": ""}), \
                 patch("push_guard.guard.USER_BLOCKED_TERMS", root / "missing"):
                with self.assertRaises(PushGuardInspectionError):
                    scan_distribution(wheel, root, require_explicit_terms=True)

    def test_inferred_account_name_blocks_outgoing_commit_without_private_file(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            def git(*args):
                return subprocess.run(
                    ["git", *args], cwd=root, capture_output=True, text=True,
                    check=True,
                ).stdout.strip()
            git("init", "-q")
            git("config", "user.name", "Package Test")
            git("config", "user.email", "package-test@example.invalid")
            (root / "README.md").write_text("Initial text.\n")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            (root / "REVIEW.md").write_text("Lena approved publication.\n")
            git("add", ".")
            git("commit", "-qm", "release")
            with patch("push_guard.guard._local_identity_terms", return_value=["Lena"]), \
                 patch("push_guard.guard.USER_BLOCKED_TERMS", root / "missing"), \
                 patch.dict(os.environ, {"PUSH_GUARD_BLOCKED_TERMS": ""}):
                findings = scan_git_range(root, base)
            personal = [f for f in findings if f.rule_id == "personal.blocked_term"]
            self.assertEqual(1, len(personal))
            self.assertNotIn("Lena", repr(personal))

    def test_package_path_and_archive_errors_fail_closed(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wheel = root / "demo-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as package:
                package.writestr("../outside.txt", "clean")
            with self.assertRaises(PushGuardInspectionError):
                scan_distribution(wheel, root)
            sdist = root / "demo-1.0.tar.gz"
            with tarfile.open(sdist, "w:gz") as package:
                link = tarfile.TarInfo("demo-1.0/linked-note")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../outside"
                package.addfile(link)
            with self.assertRaises(PushGuardInspectionError):
                scan_distribution(sdist, root)

    def test_private_member_name_is_redacted(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / ".push-guard-private-paths").write_text("private-ledger.txt\n")
            wheel = root / "demo-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as package:
                package.writestr("demo/private-ledger.txt", "clean text\n")
            findings = scan_distribution(wheel, root)
            self.assertIn("private_path.match", [f.rule_id for f in findings])
            self.assertNotIn("private-ledger", repr(findings))

    def test_privacy_only_checks_private_terms_in_fixture_packages(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wheel = root / "demo-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as package:
                package.writestr("demo/tests/test_fixture.py", "token = 'ghp_" + "a" * 30 + "'\n")
            with patch.dict(os.environ, {"PUSH_GUARD_BLOCKED_TERMS": "Lena"}), \
                 patch("push_guard.guard.USER_BLOCKED_TERMS", root / "missing"):
                self.assertEqual([], scan_distribution(wheel, root, privacy_only=True))
                self.assertTrue(scan_distribution(wheel, root, privacy_only=False))

    def test_cli_blocks_artifact_and_redacts_value(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wheel = root / "demo-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as package:
                package.writestr("demo/REVIEW.md", "Lena approved this release.\n")
            stderr = io.StringIO()
            with patch.dict(os.environ, {"PUSH_GUARD_BLOCKED_TERMS": "Lena"}), \
                 patch("push_guard.guard.USER_BLOCKED_TERMS", root / "missing"), \
                 patch("sys.stderr", stderr):
                code = main(["scan-package", "--repo", str(root),
                             "--require-explicit-terms", str(wheel)])
            self.assertEqual(1, code)
            self.assertIn("personal.blocked_term", stderr.getvalue())
            self.assertNotIn("Lena", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
