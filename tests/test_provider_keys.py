"""Synthetic provider shapes across public scanning and redacted output paths."""
import json
import subprocess
import zipfile

import pytest

from push_guard import SecretFinding, scan_text_for_secrets
from push_guard.guard import main
from push_guard.sweep import Cleaner, matches


BODY = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY"
CASES = [
    ("proj", "secret.openai_token", "sweep.openai_extended"),
    ("svcacct", "secret.openai_token", "sweep.openai_extended"),
    ("admin", "secret.openai_token", "sweep.openai_extended"),
    ("ant-api03", "secret.anthropic_token", "secret.anthropic_token"),
    ("ant-admin01", "secret.anthropic_token", "secret.anthropic_token"),
]


def canary(kind):
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
    assert list(matches(value)) == [(1, sweep_rule, "Anthropic" if "ant-" in kind else "OpenAI", value)]
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
