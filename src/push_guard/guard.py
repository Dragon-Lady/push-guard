from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ZERO_SHA = "0" * 40

PLACEHOLDER_WORDS = {
    "changeme",
    "example",
    "placeholder",
    "replace",
    "sample",
    "test",
    "your",
}

SECRET_PATTERNS = [
    (
        "secret.github_fine_grained_token",
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
        "GitHub fine-grained token pattern",
    ),
    (
        "secret.github_token",
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
        "GitHub token pattern",
    ),
    (
        "secret.openai_token",
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        "OpenAI-style token pattern",
    ),
    (
        "secret.aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "AWS access key pattern",
    ),
    (
        "secret.private_key",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        "Private key block marker",
    ),
]

GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd)\b"
    r"\s*[:=]\s*['\"]?([^'\"\s]{20,})"
)


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    path: str
    line: int
    reason: str
    evidence: str


class PushGuardInspectionError(RuntimeError):
    """Raised when Push Guard cannot inspect Git push content cleanly."""


def scan_text_for_secrets(text: str, path: str = "<text>") -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        findings.extend(_scan_line(line, path, line_number))
    return findings


def scan_git_push(repo: str | Path, stdin_text: str) -> list[SecretFinding]:
    repo_path = Path(repo)
    findings: list[SecretFinding] = []
    for _local_ref, local_sha, _remote_ref, remote_sha in _parse_pre_push(stdin_text):
        if local_sha == ZERO_SHA:
            continue
        diffs = _diffs_for_push_ref(repo_path, local_sha, remote_sha)
        for diff_text in diffs:
            findings.extend(_scan_diff(diff_text))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="push-guard",
        description="Local pre-push secret guard. Blocks likely secret pushes.",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Repository path. Defaults to current directory.",
    )
    args = parser.parse_args(argv)

    stdin_text = sys.stdin.read()
    try:
        findings = scan_git_push(args.repo, stdin_text)
    except RuntimeError as exc:
        print("Push Guard could not inspect this push.", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        print("Blocking push because inspection failed.", file=sys.stderr)
        return 1

    if not findings:
        return 0

    print("Push Guard blocked this push.", file=sys.stderr)
    print("Likely secret material matched. Values are redacted.", file=sys.stderr)
    for finding in findings:
        print(
            f"- {finding.rule_id} at {finding.path}:{finding.line} "
            f"({finding.reason}; {finding.evidence})",
            file=sys.stderr,
        )
    print("Review locally, remove or rotate the secret, then retry.", file=sys.stderr)
    return 1


def _scan_line(line: str, path: str, line_number: int) -> list[SecretFinding]:
    findings: list[SecretFinding] = []

    for rule_id, pattern, reason in SECRET_PATTERNS:
        for match in pattern.finditer(line):
            if _looks_like_placeholder(match.group(0)):
                continue
            findings.append(
                SecretFinding(
                    rule_id=rule_id,
                    path=path,
                    line=line_number,
                    reason=reason,
                    evidence="<redacted>",
                )
            )

    match = GENERIC_ASSIGNMENT.search(line)
    if match and not _looks_like_placeholder(match.group(1)):
        findings.append(
            SecretFinding(
                rule_id="secret.generic_assignment",
                path=path,
                line=line_number,
                reason="High-entropy-looking secret assignment",
                evidence="<redacted>",
            )
        )

    return findings


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(word in lowered for word in PLACEHOLDER_WORDS)


def _parse_pre_push(stdin_text: str) -> list[tuple[str, str, str, str]]:
    refs: list[tuple[str, str, str, str]] = []
    for line in stdin_text.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        refs.append((parts[0], parts[1], parts[2], parts[3]))
    return refs


def _diffs_for_push_ref(repo: Path, local_sha: str, remote_sha: str) -> list[str]:
    if remote_sha == ZERO_SHA:
        commits = _run_git(
            repo,
            ["rev-list", "--reverse", local_sha, "--not", "--remotes"],
        ).splitlines()
        if not commits:
            commits = [local_sha]
        return [
            _run_git(repo, ["show", "--format=", "--unified=0", "--no-ext-diff", commit])
            for commit in commits
        ]

    return [
        _run_git(
            repo,
            [
                "diff",
                "--unified=0",
                "--no-ext-diff",
                "--diff-filter=ACMRT",
                remote_sha,
                local_sha,
            ],
        )
    ]


def _scan_diff(diff_text: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    current_path = "<diff>"
    new_line = 0
    in_hunk = False
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_path = line[6:]
            continue
        if line.startswith("@@"):
            new_line = _parse_hunk_new_line(line)
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            findings.extend(_scan_line(line[1:], current_path, max(new_line, 1)))
            new_line += 1
            continue
        if line.startswith("-") and not line.startswith("---"):
            continue
        if line.startswith("\\ No newline"):
            continue
        new_line += 1
    return findings


def _parse_hunk_new_line(line: str) -> int:
    match = re.search(r"\+(\d+)", line)
    if not match:
        return 0
    return int(match.group(1))


def _run_git(repo: Path, args: list[str]) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        stderr = _first_stderr_line(exc.stderr)
        detail = f": {stderr}" if stderr else ""
        raise PushGuardInspectionError(
            f"git {' '.join(args)} failed with exit {exc.returncode}{detail}"
        ) from exc
    return completed.stdout


def _first_stderr_line(stderr: str | None) -> str:
    if not stderr:
        return ""
    for line in stderr.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""
