"""Synthetic provider shapes across public scanning and redacted output paths."""
import io
import json
import subprocess
import zipfile

import pytest

from push_guard import SecretFinding, scan_text_for_secrets
from push_guard.guard import main
from push_guard.sweep import Cleaner, matches


BODY = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY"
CASES = [
    ("google", "secret.google_api_key", "sweep.google_api_key"),
    ("proj", "secret.openai_token", "sweep.openai_extended"),
    ("svcacct", "secret.openai_token", "sweep.openai_extended"),
    ("admin", "secret.openai_token", "sweep.openai_extended"),
    ("ant-api03", "secret.anthropic_token", "secret.anthropic_token"),
    ("ant-admin01", "secret.anthropic_token", "secret.anthropic_token"),
    ("ant-oat01", "secret.anthropic_token", "secret.anthropic_token"),
    ("ant-ort01", "secret.anthropic_token", "secret.anthropic_token"),
]


def canary(kind):
    if kind == "google":
        return "AI" + "za" + (BODY + "_-9")[:35]
    return "s" + "k-" + kind + "-" + BODY + "_" + BODY + "-tail9"


@pytest.mark.parametrize("kind,rule,sweep_rule", CASES)
@pytest.mark.parametrize("context", ["bare", "json", "header", "assignment", "ignore"])
def test_public_api_provider_classification_and_redaction(kind, rule, sweep_rule, context):
    value = canary(kind)
    text = {
        "bare": value,
        "json": json.dumps({"credential": value}),
        "header": "Authorization: Bearer " + value,
        "assignment": "API_KEY=" + value,
        "ignore": value + " # push-guard: ignore",
    }[context]
    findings = scan_text_for_secrets("ordinary line\n" + text)
    assert len(findings) == 1
    assert findings[0].rule_id == rule
    assert findings[0].line == 2
    assert findings[0].evidence == "<redacted>"
    assert BODY not in repr(findings)


@pytest.mark.parametrize("kind,rule,sweep_rule", CASES)
@pytest.mark.parametrize("encoding", ["url", "split"])
def test_encoded_and_split_provider_shapes(kind, rule, sweep_rule, encoding):
    value = canary(kind)
    encoded = value.replace("-", "%2D").replace("_", "%5F")
    if encoding == "split":
        encoded = '"' + value[:8] + '" + "' + value[8:] + '"'
    findings = scan_text_for_secrets(encoded, path=encoded)
    assert [f.rule_id for f in findings] == [rule]
    assert findings[0].path == "<redacted>"
    assert BODY not in repr(findings)


@pytest.mark.parametrize("kind,rule,sweep_rule", CASES)
def test_full_match_redaction_and_metadata(kind, rule, sweep_rule):
    value = canary(kind)
    # Full body equality catches truncated matches and leaked suffixes.
    label = "Google API key" if kind == "google" else "Anthropic" if "ant-" in kind else "OpenAI"
    assert list(matches(value)) == [(1, sweep_rule, label, value)]
    assert Cleaner().text("prefix/" + value + ".txt") == "prefix/<redacted>.txt"
    finding = SecretFinding(rule, value + ".txt", 1, "reason: " + value, "<redacted>")
    assert finding.path == finding.reason == "<redacted>"


@pytest.mark.parametrize("kind,rule,sweep_rule", CASES)
def test_package_cli_blocks_and_redacts_member_name(kind, rule, sweep_rule, tmp_path, capsys):
    value = canary(kind)
    archive = tmp_path / "fixture-1.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr(value + ".txt", value)
    assert main(["scan-package", "--repo", str(tmp_path), "--no-infer", str(archive)]) == 1
    output = capsys.readouterr()
    assert rule in output.err
    assert BODY not in output.out + output.err


@pytest.mark.parametrize("kind,rule,sweep_rule", CASES)
def test_git_cli_blocks_and_redacts_new_provider(kind, rule, sweep_rule, tmp_path, capsys):
    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    git("init", "-q")
    git("config", "user.name", "Dragon Lady")
    git("config", "user.email", "268074749+Dragon-Lady@users.noreply.github.com")
    git("commit", "--allow-empty", "-qm", "fixture base")
    base = git("rev-parse", "HEAD")
    value = canary(kind)
    (tmp_path / (value + ".txt")).write_text(value + "\n")
    git("add", ".")
    git("commit", "-qm", "fixture candidate")
    assert main(["scan", "--repo", str(tmp_path), "--base", base, "--no-infer"]) == 1
    output = capsys.readouterr()
    assert rule in output.err
    assert BODY not in output.out + output.err


@pytest.mark.parametrize("kind,rule,sweep_rule", CASES)
def test_short_prefixes_are_not_provider_keys(kind, rule, sweep_rule):
    assert scan_text_for_secrets("s" + "k-" + kind + "-short") == []


def test_legacy_openai_shape_still_detected():
    value = "s" + "k-" + BODY
    assert [f.rule_id for f in scan_text_for_secrets(value)] == ["secret.openai_token"]
    assert Cleaner().text(value) == "<redacted>"


@pytest.mark.parametrize("prefix", ["identifier", "prefix-", "\u00e9"])
@pytest.mark.parametrize("kind", ["google", "proj", "svcacct", "admin", "ant-api03", "ant-admin01", "ant-oat01", "ant-ort01"])
def test_extended_openai_does_not_match_inside_identifier(prefix, kind):
    value = prefix + canary(kind)
    assert scan_text_for_secrets(value) == []
    assert list(matches(value)) == []


@pytest.mark.parametrize("value", [
    "flask-admin-dashboard-templates-and-static",
    "risk-proj-management-plan-for-the-quarter-2026",
    "desk-admin-workstation_configuration_notes",
    "kiosk-ant-admin01-" + "x" * 32,
    "https://example.com/disk-proj-build_artifacts_2026_10_19/index.html",
    "desk-" + "a" * 32,
])
def test_ordinary_identifiers_are_not_provider_tokens(value):
    assert scan_text_for_secrets(value) == []
    assert list(matches(value)) == []


def test_archive_ignore_marker_cannot_hide_workflow_or_private_term(tmp_path, monkeypatch, capsys):
    marker = "/tmp/" + ".sshu-" + "fixture"
    private = "PrivateCanaryValue"
    archive = tmp_path / "fixture-1.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("fixture.py", marker + " " + private + " # push-guard: ignore")
    monkeypatch.setenv("PUSH_GUARD_BLOCKED_TERMS", private)
    args = ["scan-package", "--repo", str(tmp_path), "--no-infer", str(archive)]
    assert main(args) == 1
    error = capsys.readouterr().err
    assert "workflow.shai_hulud_ssh_tmp" in error
    assert "personal.blocked_term" in error
    assert private not in error
    (tmp_path / ".push-guard-allow").write_text(
        "fixture.py workflow.shai_hulud_ssh_tmp,personal.blocked_term\n")
    assert main(args) == 1
    error = capsys.readouterr().err
    assert "workflow.shai_hulud_ssh_tmp" not in error
    assert "personal.blocked_term" in error
    assert private not in error


def test_pre_push_allow_list_still_blocks_credentials_and_private_terms(tmp_path, monkeypatch, capsys):
    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True,
                              capture_output=True, text=True).stdout.strip()
    git("init", "-q")
    git("config", "user.name", "Dragon Lady")
    git("config", "user.email", "268074749+Dragon-Lady@users.noreply.github.com")
    git("commit", "--allow-empty", "-qm", "base")
    base = git("rev-parse", "HEAD")
    marker = "/tmp/" + ".sshu-" + "fixture"
    (tmp_path / "fixture.py").write_text(marker + " # push-guard: ignore\n")
    (tmp_path / ".push-guard-allow").write_text(
        "fixture.py workflow.shai_hulud_ssh_tmp,personal.blocked_term,secret.openai_token\n")
    git("add", ".")
    git("commit", "-qm", "reviewed fixture")
    base = git("rev-parse", "HEAD")
    (tmp_path / "fixture.py").write_text(marker + " # push-guard: ignore fixture update\n")
    git("add", ".")
    git("commit", "-qm", "fixture change")
    private = "PrivateCanaryValue"
    monkeypatch.setenv("PUSH_GUARD_BLOCKED_TERMS", private)
    for with_secret in (False, True):
        if with_secret:
            (tmp_path / "fixture.py").write_text(marker + " " + private + " " + canary("proj") + " # push-guard: ignore\n")
            git("add", ".")
            git("commit", "-qm", "sensitive fixture")
        head = git("rev-parse", "HEAD")
        monkeypatch.setattr("sys.stdin", io.StringIO(f"refs/heads/main {head} refs/heads/main {base}\n"))
        assert main(["--repo", str(tmp_path), "--no-infer"]) == int(with_secret)
        out = capsys.readouterr()
        assert "allowed 1 reviewed workflow hit(s)" in out.out
        assert private not in out.err and BODY not in out.err
        if with_secret:
            assert "personal.blocked_term" in out.err and "secret.openai_token" in out.err


@pytest.mark.parametrize('kind', [c[0] for c in CASES] + ['legacy'])
@pytest.mark.parametrize('prefix', [r'\n', r'\r', r'\t', 'key_', '%3D', '%3d', '%09', '%0A', '%0d', '%5F'])
def test_serialized_boundaries_detect_and_redact_complete_tokens(kind, prefix):
    from push_guard.guard import SECRET_PATTERNS
    value = 's' + 'k-' + BODY if kind == 'legacy' else canary(kind)
    text = prefix + value
    rule = 'secret.google_api_key' if kind == 'google' else 'secret.anthropic_token' if kind.startswith('ant-') else 'secret.openai_token'
    findings = scan_text_for_secrets(text, path=text)
    assert [f.rule_id for f in findings] == [rule]
    assert all(f.evidence == '<redacted>' and f.path == '<redacted>' for f in findings)
    pattern = next(p for r, p, _, _ in SECRET_PATTERNS if r == rule)
    assert pattern.search(text).group() == value
    assert list(matches(text))[0][-1] == value
    assert BODY not in Cleaner().text(text)


@pytest.mark.parametrize("prefix", ["", "_", r"\n", r"\t", "%3D", "?key=", "X-Goog-Api-Key: "])
def test_google_serialized_boundaries(prefix):
    value = canary("google")
    assert len(value) == 39
    assert [f.rule_id for f in scan_text_for_secrets(prefix + value)] == ["secret.google_api_key"]
    assert value not in Cleaner().text(prefix + value)


@pytest.mark.parametrize("length", [0, 19, 20, 34, 36, 50])
def test_google_key_length_controls(length):
    value = "AI" + "za" + (BODY * 3)[:length]
    assert scan_text_for_secrets(value) == []
    assert list(matches(value)) == []
