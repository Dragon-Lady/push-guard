from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ZERO_SHA = "0" * 40

# Inline allowlist escape hatch. A line containing this marker is skipped by
# every rule. Use it on lines that legitimately carry IOC-shaped strings: this
# detector's own pattern definitions and test fixtures, or a deploy script
# that really does ssh-then-exec. It is explicit and grep-auditable on purpose --
# matching detect-secrets' `# pragma: allowlist secret` philosophy.
IGNORE_MARKER = re.compile(r"push-guard:\s*ignore", re.IGNORECASE)

PLACEHOLDER_WORDS = {
    "changeme",
    "example",
    "placeholder",
    "replace",
    "sample",
    "test",
    "your",
}

# Each entry: (rule_id, pattern, reason, high_confidence)
# high_confidence == True means the match is a provider-specific token *shape*
# (ghp_, github_pat_, sk-, AKIA/ASIA). A value matching one of these is a real
# secret even if it happens to contain a word like "test" or "your", so the
# placeholder filter MUST NOT suppress it. Only low-confidence/structural
# markers honor the placeholder filter.
SECRET_PATTERNS = [
    (
        "secret.github_fine_grained_token",
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
        "GitHub fine-grained token pattern",
        True,
    ),
    (
        "secret.github_token",
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
        "GitHub token pattern",
        True,
    ),
    (
        "secret.openai_token",
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        "OpenAI-style token pattern",
        True,
    ),
    (
        "secret.aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "AWS access key pattern",
        True,
    ),
    (
        "secret.private_key",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        "Private key block marker",
        False,
    ),
]

# Keyword may be embedded in an underscore/dash-delimited identifier so that
# names like AWS_SECRET_ACCESS_KEY or CLIENT_SECRET_TOKEN are matched, not just
# bare `secret=`. The negative lookbehind keeps the keyword on a real boundary
# (start, space, `_`, `-`) instead of matching inside an unrelated word.
GENERIC_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd)"
    r"(?:[_-][A-Za-z0-9]+)*"
    r"\s*[:=]\s*['\"]?([^'\"\s]{20,})"
)

SHAI_HULUD_SSH_PATTERNS = [
    (
        "workflow.shai_hulud_ssh_tmp",
        re.compile(r"/tmp/\.sshu-[A-Za-z0-9_-]*", re.I),
        "Hidden /tmp/.sshu-* SSH propagation artifact",  # push-guard: ignore
    ),
    (
        "workflow.shai_hulud_ai_loader",
        re.compile(r"\bai_(?:setup\.sh|init\.js)\b", re.I),
        "AI-themed Shai-Hulud SSH loader/payload filename",
    ),
    (
        "workflow.ssh_fanout_exec",
        re.compile(r"\b(?:ssh|scp|rsync)\b.*\b(?:bun|node|sh|bash|curl|wget)\b", re.I),  # push-guard: ignore
        "SSH fan-out combined with script/network execution",
    ),
    (
        "workflow.bun_tmp_exec",
        re.compile(r"\bBun\.spawnSync\b.*(?:/tmp/|ai_setup\.sh|ai_init\.js)", re.I),
        "Bun execution paired with temp or AI-themed payload behavior",
    ),
]

HADES_PYPI_PATTERNS = [
    (
        "workflow.hades_pypi_bun_download",
        re.compile(r"oven-sh/bun/releases/download|bun-v\d+\.\d+\.\d+", re.I),  # push-guard: ignore
        "Hades/Miasma PyPI Bun runtime bootstrap marker",
    ),
    (
        "workflow.hades_pypi_bun_sentinel",
        re.compile(r"\.bun_ran\b", re.I),  # push-guard: ignore
        "Hades/Miasma PyPI Bun startup sentinel",
    ),
    (
        "workflow.hades_anthropic_camouflage",
        re.compile(r"api\.anthropic\.com/v1/api", re.I),  # push-guard: ignore
        "Hades/Miasma Anthropic-host camouflage endpoint",
    ),
    (
        "workflow.hades_github_exfil_marker",
        re.compile(
            r"Hades - The End for the Damned|"  # push-guard: ignore
            r"IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully|"  # push-guard: ignore
            r"results/results-[^\"'\s]*\.json|"  # push-guard: ignore
            r"\bformat-results\b|"  # push-guard: ignore
            r"\bRun Copilot\b",  # push-guard: ignore
            re.I,
        ),  # push-guard: ignore
        "Hades/Miasma GitHub or Actions exfiltration marker",
    ),
    (
        "workflow.hades_github_token_monitor",
        re.compile(
            r"gh-token-monitor|GitHub Commit Monitor|"  # push-guard: ignore
            r"gh-token-monitor\.service|com\.github\.token-monitor\.plist",  # push-guard: ignore
            re.I,
        ),  # push-guard: ignore
        "Hades/Miasma GitHub token-monitor persistence marker",
    ),
]


# ---------------------------------------------------------------------------
# Private-path rules.
#
# A second, path-based dimension: block a push that *introduces a file whose
# path* should never leave the machine -- private handoff lanes, agent/team
# notes, credential vaults -- even when the file body holds no secret pattern.
# This is the guard against the failure mode where internal material is staged
# into a repo by mistake (or by a misbehaving automation) and the content
# scanner sees nothing token-shaped to flag.
#
# Defaults below are GENERIC and project-neutral on purpose: no organization,
# person, or codename appears here, so this source stays safe to publish.
# Project-specific patterns (private directory names, internal doc prefixes)
# load from an optional, git-ignored config file at the repo root --
# `.push-guard-private-paths`, one glob per line, `#` for comments. Keep that
# file local so the private names themselves never get committed or pushed.
# Basename-style globs: matched against each file's basename at any depth, so a
# root-level `family_keys.json` and a nested `secrets/family_keys.json` both hit.
PRIVATE_PATH_DEFAULTS = [
    "*.kdbx",
    "*.pem",
    "id_rsa",
    "id_ed25519",
    ".env",
    ".env.*",
    "*_keys.json",
    "credentials.json",
    ".npmrc",
]

# Conventionally-safe, meant-to-be-committed env templates. They contain only
# placeholder values (the real, secret-bearing .env is gitignored), so they must
# NOT be flagged as private even though their names match the ".env.*" pattern
# above. Real .env and environment-specific files (.env.local, .env.prod, ...)
# stay blocked. This closes the .env.example false positive that otherwise
# blocks every push in repos that legitimately commit an example template.
SAFE_ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template", ".env.dist"}

PRIVATE_PATHS_CONFIG = ".push-guard-private-paths"


def load_private_path_patterns(repo: str | Path = ".") -> list[str]:
    """Generic defaults plus any patterns from the local, git-ignored config."""
    patterns = list(PRIVATE_PATH_DEFAULTS)
    try:
        config = Path(repo) / PRIVATE_PATHS_CONFIG
        text = config.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return patterns
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def path_matches_private(path: str, patterns: list[str]) -> str | None:
    """Return the matched pattern, or None. Simplified gitignore-style match.

    - A trailing-slash pattern (`notes/`) matches that directory anywhere in the
      path.
    - A glob pattern (`*MEMORY.md`, `**/*.pem`) is matched against the full
      normalized path and against the basename.
    - A plain token is matched as an exact basename or a path segment.
    """
    normalized = path.replace("\\", "/").lstrip("/")
    basename = normalized.rsplit("/", 1)[-1]
    # Safe env templates are explicitly allowed (placeholders only; real .env is gitignored).
    if basename in SAFE_ENV_TEMPLATES:
        return None
    segments = normalized.split("/")
    for pattern in patterns:
        pat = pattern.replace("\\", "/").strip()
        if not pat:
            continue
        if pat.endswith("/"):
            directory = pat[:-1].lstrip("/")
            if directory and directory in segments[:-1]:
                return pattern
            continue
        if any(ch in pat for ch in "*?["):
            if (
                fnmatch.fnmatch(normalized, pat)
                or fnmatch.fnmatch(normalized, f"*/{pat}")
                or fnmatch.fnmatch(basename, pat)
            ):
                return pattern
            continue
        if pat == basename or pat in segments:
            return pattern
    return None


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
    repo_path = _resolve_git_root(Path(repo))
    private_patterns = load_private_path_patterns(repo_path)
    findings: list[SecretFinding] = []
    seen_path_shas: set[str] = set()
    for _local_ref, local_sha, _remote_ref, remote_sha in _parse_pre_push(stdin_text):
        if local_sha == ZERO_SHA:
            continue
        diffs = _diffs_for_push_ref(repo_path, local_sha, remote_sha)
        for diff_text in diffs:
            findings.extend(_scan_diff(diff_text))
        if local_sha not in seen_path_shas:
            seen_path_shas.add(local_sha)
            findings.extend(
                _scan_tree_for_private_paths(repo_path, local_sha, private_patterns)
            )
    return findings


def _scan_tree_for_private_paths(
    repo: Path, local_sha: str, patterns: list[str]
) -> list[SecretFinding]:
    """Flag any file in the pushed tree whose path is private/internal.

    Uses the tip tree (not the diff) so a private file that should never have
    been tracked is caught on every push until it is removed -- not only on the
    commit that introduced it.
    """
    if not patterns:
        return []
    tree = _run_git(repo, ["ls-tree", "-r", "--name-only", local_sha])
    findings: list[SecretFinding] = []
    for path in tree.splitlines():
        path = path.strip()
        if not path:
            continue
        matched = path_matches_private(path, patterns)
        if matched:
            findings.append(
                SecretFinding(
                    rule_id="private_path.match",
                    path=path,
                    line=0,
                    reason=f"Private/internal path (pattern: {matched})",
                    evidence="<redacted>",
                )
            )
    return findings


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "install":
        return _install_main(argv[1:])
    if argv and argv[0] in {"-h", "--help"}:
        _print_help()
        return 0

    # Backward-compatible pre-push mode. Existing hooks call:
    #   python -m push_guard --repo "$(git rev-parse --show-toplevel)"
    return _pre_push_main(argv)


def _pre_push_main(argv: list[str]) -> int:
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

    has_private_path = any(f.rule_id.startswith("private_path.") for f in findings)
    has_secret = any(not f.rule_id.startswith("private_path.") for f in findings)
    if has_private_path and has_secret:
        kind = "Secret or private material matched."
    elif has_private_path:
        kind = "Private/internal file path matched."
    else:
        kind = "Likely secret material matched."

    print("Push Guard blocked this push.", file=sys.stderr)
    print(f"{kind} Secret values are redacted.", file=sys.stderr)
    for finding in findings:
        line_suffix = f":{finding.line}" if finding.line else ""
        print(
            f"- {finding.rule_id} at {finding.path}{line_suffix} "
            f"({finding.reason}; {finding.evidence})",
            file=sys.stderr,
        )
    print(
        "Review locally: untrack the private file, or remove/rotate the secret, "
        "then retry.",
        file=sys.stderr,
    )
    return 1


def _install_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="push-guard install",
        description="Install Push Guard as this repository's local pre-push hook.",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Repository path. Defaults to current directory.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing Push Guard-managed pre-push hook.",
    )
    parser.add_argument(
        "--allow-home-repo",
        action="store_true",
        help="Allow installing into the user home directory if it is a Git repo.",
    )
    args = parser.parse_args(argv)

    try:
        hook_path = install_pre_push_hook(
            args.repo,
            force=args.force,
            allow_home_repo=args.allow_home_repo,
        )
    except RuntimeError as exc:
        print(f"Push Guard install failed: {exc}", file=sys.stderr)
        return 1

    print(f"Push Guard installed: {hook_path}")
    return 0


def install_pre_push_hook(
    repo: str | Path = ".",
    *,
    force: bool = False,
    allow_home_repo: bool = False,
) -> Path:
    repo_path = _resolve_git_root(Path(repo))
    if not allow_home_repo and repo_path == Path.home():
        raise RuntimeError(
            f"Refusing to install into your home directory Git repo ({repo_path}). "
            "Run from the specific project repo or pass --repo C:\\path\\to\\repo. "
            "Use --allow-home-repo only if you intentionally want this broad hook."
        )
    hook_dir = repo_path / ".git" / "hooks"
    hook_path = hook_dir / "pre-push"
    hook_dir.mkdir(parents=True, exist_ok=True)

    hook_body = _hook_body()
    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8", errors="replace")
        if existing == hook_body:
            return hook_path
        if "push_guard" not in existing and "push-guard" not in existing:
            raise RuntimeError(
                f"{hook_path} already exists. Chain it manually or rerun with --force."
            )
        if not force:
            raise RuntimeError(
                f"{hook_path} already exists. Rerun with --force to refresh it."
            )

    hook_path.write_text(hook_body, encoding="utf-8", newline="\n")
    if os.name != "nt":
        hook_path.chmod(0o755)
    return hook_path


def _hook_body() -> str:
    # Pin the hook to the interpreter running the install so it points at the
    # same environment push_guard is installed in. A bare "python" breaks where
    # only python3 exists (most Linux) or where push_guard lives in a venv that
    # isn't on the hook's PATH. sys.executable is that interpreter; fall back to
    # python3 only if it is somehow unset.
    python = sys.executable or "python3"
    return (
        "#!/bin/sh\n"
        "# Installed by Push Guard. Local only; no network calls.\n"
        f'exec "{python}" -m push_guard --repo "$(git rev-parse --show-toplevel)"\n'
    )


def _print_help() -> None:
    print(
        "usage: push-guard [--repo REPO]\n"
        "       push-guard install [--repo REPO] [--force] [--allow-home-repo]\n\n"
        "Local pre-push secret guard. Run from a Git pre-push hook, or install\n"
        "the hook with `push-guard install`."
    )


def _scan_line(line: str, path: str, line_number: int) -> list[SecretFinding]:
    findings: list[SecretFinding] = []

    # Explicit per-line opt-out. Skip the whole line for every rule.
    if IGNORE_MARKER.search(line):
        return findings

    for rule_id, pattern, reason, high_confidence in SECRET_PATTERNS:
        for match in pattern.finditer(line):
            # High-confidence provider token shapes are never suppressed by a
            # placeholder word — a real ghp_/sk-/AKIA value that merely contains
            # "test" or "your" is still a real secret and must be caught.
            if not high_confidence and _looks_like_placeholder(match.group(0)):
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

    # Only consider the lower-confidence generic-assignment rule when no
    # specific token already matched this line. This avoids double-reporting a
    # single leak (e.g. OPENAI_API_KEY=sk-...) while still catching secrets that
    # only the generic rule can see (e.g. a 40-char AWS *secret* in
    # AWS_SECRET_ACCESS_KEY=..., which has no provider prefix).
    if not findings:
        match = GENERIC_ASSIGNMENT.search(line)
        if match and not _value_is_placeholder(match.group(1)):
            findings.append(
                SecretFinding(
                    rule_id="secret.generic_assignment",
                    path=path,
                    line=line_number,
                    reason="High-entropy-looking secret assignment",
                    evidence="<redacted>",
                )
            )

    findings.extend(_scan_line_for_workflow_compromise(line, path, line_number))
    findings.extend(_scan_line_for_hades_pypi(line, path, line_number))

    return findings


def _scan_line_for_workflow_compromise(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    if not _is_workflow_or_script_path(normalized_path):
        return []

    findings: list[SecretFinding] = []
    for rule_id, pattern, reason in SHAI_HULUD_SSH_PATTERNS:
        if pattern.search(line):
            findings.append(
                SecretFinding(
                    rule_id=rule_id,
                    path=path,
                    line=line_number,
                    reason=reason,
                    evidence="<redacted>",
                )
            )

    if (
        re.search(r"\binfectHost\s*\(", line)
        or re.search(r"\bremote(?:Loader|Payload)Script\b", line)
    ):
        findings.append(
            SecretFinding(
                rule_id="workflow.shai_hulud_ssh_shape",
                path=path,
                line=line_number,
                reason="Shai-Hulud SSH propagation function/variable shape",
                evidence="<redacted>",
            )
        )

    return findings


def _scan_line_for_hades_pypi(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    lowered_path = normalized_path.lower()
    if lowered_path.endswith((".md", ".mdx", ".txt", ".rst")):
        return []

    is_pth = lowered_path.endswith(".pth")
    is_code_or_workflow = is_pth or _is_workflow_or_script_path(normalized_path)
    if not is_code_or_workflow:
        return []

    findings: list[SecretFinding] = []

    if (
        is_pth
        and re.match(r"\s*import(?:\s|;)", line)
        and re.search(
            r"urllib\.request|urlretrieve|subprocess\.run|tempfile\.gettempdir|"
            r"_index\.js|oven-sh/bun/releases/download|\.bun_ran|\bbun\s+run\b",  # push-guard: ignore
            line,
            re.I,
        )
    ):
        findings.append(
            SecretFinding(
                rule_id="workflow.hades_pypi_pth_loader",
                path=path,
                line=line_number,
                reason="Executable .pth startup hook with Hades/Miasma loader behavior",
                evidence="<redacted>",
            )
        )

    for rule_id, pattern, reason in HADES_PYPI_PATTERNS:
        if pattern.search(line):
            findings.append(
                SecretFinding(
                    rule_id=rule_id,
                    path=path,
                    line=line_number,
                    reason=reason,
                    evidence="<redacted>",
                )
            )

    return findings


def _is_workflow_or_script_path(path: str) -> bool:
    lowered = path.lower()
    if lowered.endswith((".md", ".mdx", ".txt", ".rst")):
        return False
    if any(
        marker in lowered
        for marker in (
            "/.github/workflows/",
            ".github/workflows/",
            "/.githooks/",
            ".githooks/",
            "/hooks/",
            "hooks/",
            "/scripts/",
            "scripts/",
            "/bin/",
            "bin/",
            "/tools/",
            "tools/",
            "/ci/",
            "ci/",
        )
    ):
        return True
    return lowered.endswith((".sh", ".bash", ".zsh", ".js", ".cjs", ".mjs", ".ps1", ".py", ".yml", ".yaml"))


def _looks_like_placeholder(value: str) -> bool:
    """Substring check, used only for low-confidence/structural markers."""
    lowered = value.lower()
    return any(word in lowered for word in PLACEHOLDER_WORDS)


def _value_is_placeholder(value: str) -> bool:
    """True only when an assigned value is *dominated* by placeholder text.

    The earlier behaviour skipped any value that merely *contained* a
    placeholder word (e.g. a real secret embedding "test"), which silently let
    secrets through. Now a value counts as a placeholder only when it is an
    obvious dummy shape, stacks two or more placeholder words, or is left with
    almost nothing real after the placeholder words are removed. This biases a
    pre-push seatbelt toward blocking — a verbose dummy may be flagged for
    review, but a real secret with an embedded common word is no longer missed.
    """
    lowered = value.lower()
    # Bracketed dummies (<your-token>, [REDACTED]) or filler runs (xxxxxxxx).
    if re.fullmatch(r"[<\[{(].*[>\]})]", value):
        return True
    if re.fullmatch(r"[x*._\-]{8,}", lowered):
        return True
    present = [word for word in PLACEHOLDER_WORDS if word in lowered]
    if len(present) >= 2:
        return True
    residue = lowered
    for word in present:
        residue = residue.replace(word, "")
    residue = re.sub(r"[^a-z0-9]", "", residue)
    return len(residue) < 8


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


def _resolve_git_root(repo: Path) -> Path:
    try:
        completed = _run_rev_parse_show_toplevel(repo, repo)
    except subprocess.CalledProcessError as exc:
        dubious_root = _parse_dubious_ownership_root(exc.stderr)
        if dubious_root:
            try:
                completed = _run_rev_parse_show_toplevel(repo, dubious_root)
            except subprocess.CalledProcessError as retry_exc:
                raise _git_inspection_error(
                    "git rev-parse --show-toplevel", retry_exc
                ) from retry_exc
        else:
            raise _git_inspection_error("git rev-parse --show-toplevel", exc) from exc

    root = completed.stdout.strip()
    if not root:
        raise PushGuardInspectionError("git rev-parse --show-toplevel returned no path")
    return Path(root)


def _run_rev_parse_show_toplevel(
    repo: Path, safe_directory: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _git_command(repo, ["rev-parse", "--show-toplevel"], safe_directory),
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _git_inspection_error(
    command: str, exc: subprocess.CalledProcessError
) -> PushGuardInspectionError:
    stderr = _first_stderr_line(exc.stderr)
    detail = f": {stderr}" if stderr else ""
    return PushGuardInspectionError(
        f"{command} failed with exit {exc.returncode}{detail}"
    )


def _parse_dubious_ownership_root(stderr: str | None) -> Path | None:
    if not stderr or "dubious ownership" not in stderr:
        return None
    match = re.search(r"repository at '([^']+)'", stderr)
    if not match:
        return None
    return Path(match.group(1))


def _run_git(repo: Path, args: list[str]) -> str:
    try:
        completed = subprocess.run(
            _git_command(repo, args, repo),
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace",
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


def _git_command(repo: Path, args: list[str], safe_directory: Path) -> list[str]:
    return [
        "git",
        "-c",
        f"safe.directory={safe_directory}",
        "-C",
        str(repo),
        *args,
    ]


def _first_stderr_line(stderr: str | None) -> str:
    if not stderr:
        return ""
    for line in stderr.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""
