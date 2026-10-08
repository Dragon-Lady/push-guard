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
    PushGuardInspectionError, _identity_terms, main, scan_git_range,
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
