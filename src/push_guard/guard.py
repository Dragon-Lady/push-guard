from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
import unicodedata
import urllib.parse
from dataclasses import dataclass
from pathlib import Path


ZERO_SHA = "0" * 40

# Inline allowlist escape hatch for non-secret workflow/IOC rules. Provider
# token shapes and generic secret assignments are still scanned on marked
# lines: a comment must not turn a real credential into an allowed value. Use
# this marker only on legitimate detector definitions, safe test structure, or
# a deploy line that really does ssh-then-exec. It stays explicit and
# grep-auditable on purpose.
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
        "secret.gitlab_incoming_email_token",
        re.compile(r"(?<![A-Za-z0-9_])glimt-[A-Za-z0-9_-]{25}(?![A-Za-z0-9_])"),
        "GitLab incoming email token pattern",
        True,
    ),
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
    (
        "workflow.hades_llm_anti_analysis_bait",
        re.compile(
            r"(?:unrestricted\s+mode|safety\s+guidelines|guardrails).{0,120}"
            r"(?:biological|nuclear)\s+weapons?|"
            r"(?:biological|nuclear)\s+weapons?.{0,120}"
            r"(?:unrestricted\s+mode|safety\s+guidelines|guardrails)",
            re.I,
        ),
        "Hades-style LLM refusal-bait marker in executable code",
    ),
    (
        "workflow.llm_refusal_evasion_bait",
        re.compile(
            r"(?:ai\s+(?:security\s+)?scanner|language\s+model|automated\s+scanner|malware\s+scanner)"
            r".{0,160}(?:must\s+refuse|safety\s+(?:guardrail|policy)|classified\s+documents|weapon\s+systems)"
            r".{0,160}(?:stop\s+reading|do\s+not\s+analy[sz]e|no\s+verdict|refuse\s+to\s+continue)",
            re.I,
        ),
        "LLM scanner refusal/null-result bait marker in executable code",
    ),
]

AGENTJACKING_PATTERNS = [
    (
        "workflow.agentjacking_sentry_mcp_config",
        re.compile(r"\bsentry\b.*\bmcp\b|\bmcp\b.*\bsentry\b", re.I),
        "Sentry MCP integration added or changed; review untrusted event-to-agent boundary",
    ),
    (
        "workflow.agentjacking_sentry_resolution_npx",
        re.compile(r"(?:##\s*Resolution|resolution\s*:).{0,160}\bnpx\b|\bnpx\b.{0,160}(?:##\s*Resolution|resolution\s*:)", re.I),
        "Agentjacking-style Sentry resolution text attempts npm execution",
    ),
    (
        "workflow.agentjacking_sentry_ingest_mcp",
        re.compile(r"(?:ingest\.sentry\.io|SENTRY_DSN|sentry_dsn).{0,160}\bmcp\b|\bmcp\b.{0,160}(?:ingest\.sentry\.io|SENTRY_DSN|sentry_dsn)", re.I),
        "Sentry DSN/ingest surface is wired near MCP agent context",
    ),
]

COPILOT_REPROMPT_PATTERNS = [
    (
        "workflow.copilot_reprompt_qparam_exfil",
        re.compile(
            r"(?:copilot\.microsoft\.com|m365\.cloud\.microsoft/chat|microsoft365\.com/chat)"
            r".{0,120}(?:[?&]q=|%3[fF]q%3[dD]|%26q%3[dD])"
            r"(?=.{0,520}(?:send\s+to\s+https?://|fetch\s+https?://|post\s+to\s+https?://|exfiltrate|attacker\s+server))"
            r"(?=.{0,520}(?:recent\s+files|looked\s+at\s+today|where\s+is\s+the\s+user|user\s+location|sharepoint|onedrive))",
            re.I,
        ),
        "Microsoft Copilot q-parameter prompt injection with private-context exfiltration terms",
    ),
]

KNOWN_COMPROMISED_NPM_PACKAGE_PATTERNS = [
    (
        "workflow.dirtyblanket_npm_package",
        re.compile(
            r"(?<![\w@/-])(?:xeprews|express-javascript|express-nodejs|react-nodejs|"
            r"exprdd|exprrdd|exptrdd|exptred|exptredd)(?![\w/-])",
            re.I,
        ),
        "SafeDep-reported DirtyBlanket npm package appears in dependency metadata",
    ),
    (
        "workflow.compromised_npm_package",
        re.compile(r"(?<![\w@/-])(?:atomic-lockfile|ecto-flag-read)(?![\w/-])", re.I),
        "Known compromised npm package appears in dependency metadata",
    ),
    (
        "workflow.july_malicious_npm_package",
        re.compile(
            r"(?<![\w@/-])(?:paperclip2|vps-maintenance(?:-paperclip-adapter)?|polymarket-kit|"
            r"rollup-packages-polyfill-core|rollup-runtime-polyfill-core|swift-parse-stream|"
            r"quirky-token|react-icon-svgs|rollup-plugin-polyfill-connect)(?![\w/-])",
            re.I,
        ),
        "July 2026 malicious npm package appears in dependency metadata",
    ),
    (
        "workflow.july_compromised_npm_version",
        re.compile(
            r"(?:[\"']jscrambler[\"']\s*:\s*[\"'](?:8\.14\.0|8\.16\.0|8\.17\.0|8\.18\.0|8\.20\.0)[\"']|"
            r"[\"']@injectivelabs/[^\"']+[\"']\s*:\s*[\"']1\.20\.21[\"']|"
            r"[\"'](?:paysafe-(?:checkout|vault|js|api|node|cards|fraud|kyc|payments)|neteller|skrill(?:-payments|-sdk)?)[\"']"
            r"\s*:\s*[\"']1\.0\.[0-3][\"'])",
            re.I,
        ),
        "July 2026 compromised npm package version appears in dependency metadata",
    ),
    (
        # August 4, 2026 keyv/cacheable ChainDrop seed carriers only (exact versions).
        # Vendor-verified initial full-worm wave: keyv@6.0.0 + ten jaredwray-family
        # releases. Full inventory is larger (Ox/Wiz); seed set only for push block.
        "workflow.august_keyv_compromised_npm_version",
        re.compile(
            r"(?:[\"']keyv[\"']\s*:\s*[\"']6\.0\.0[\"']|"
            r"[\"']flat-cache[\"']\s*:\s*[\"']6\.1\.24[\"']|"
            r"[\"']file-entry-cache[\"']\s*:\s*[\"']11\.1\.6[\"']|"
            r"[\"']cacheable-request[\"']\s*:\s*[\"']13\.0\.20[\"']|"
            r"[\"']cacheable[\"']\s*:\s*[\"']2\.5\.1[\"']|"
            r"[\"']@cacheable/memory[\"']\s*:\s*[\"']2\.2\.1[\"']|"
            r"[\"']cache-manager[\"']\s*:\s*[\"']7\.2\.10[\"']|"
            r"[\"']@cacheable/node-cache[\"']\s*:\s*[\"']3\.1\.2[\"']|"
            r"[\"']@cacheable/utils[\"']\s*:\s*[\"']2\.5\.1[\"']|"
            r"[\"']@cacheable/net[\"']\s*:\s*[\"']2\.1\.1[\"']|"
            r"[\"']ecto[\"']\s*:\s*[\"']5\.0\.1[\"'])",
            re.I,
        ),
        "August 2026 keyv/cacheable (ChainDrop) compromised npm package version appears in dependency metadata",
    ),
    (
        "workflow.trinitite_compromised_npm_version",
        re.compile(
            r"[\"']@7nohe/openapi-react-query-codegen(?:@|[\"']\s*:\s*[\"'])"  # push-guard: ignore
            r"(?:0\.5\.[45]|1\.6\.[34]|2\.2\.[12]|3\.0\.[34]|"
            r"0\.0\.0-(?:365d4eb738d3146583431948d3ba6e27a32556be|ec7876d6c917dad516ba69bbfafc948b834bf0ab))[\"']",  # push-guard: ignore
            re.I,
        ),
        "Trinitite / Mini Shai-Hulud compromised npm package version appears in dependency metadata",
    ),
    (
        "workflow.manifest_reverse_shell_lifecycle",
        re.compile(
            r"[\"'](?:preinstall|install|postinstall|prepare)[\"']\s*:\s*[\"'][^\"']*"
            r"(?:/dev/tcp/|\bbash\s+-i\b|\bnc\s+(?:-[^\s]+\s+)*-e\b|\bsocat\b[^\"']*\bexec:)",
            re.I,
        ),
        "Package manifest lifecycle script contains a reverse-shell execution shape",
    ),
]

SEPTEMBER_2026_THREAT_PATTERNS = [
    (
        "workflow.aurora_linux_ransomware_hash",
        re.compile(r"a4af136d159a8eb96b54924fa80355ca52874913301300f55af7d67ae97edcfe", re.I),  # push-guard: ignore
        "Aurora Linux/ESXi ransomware SHA-256",
    ),
    (
        "workflow.aurora_ransomware_download",
        re.compile(r"pub-c057b7d0b24944a29e381ce9ea22a2f1\.r2(?:\[\.\]|\.)dev/xu4gid0t8er3\.out", re.I),  # push-guard: ignore
        "Aurora ransomware Cloudflare R2 payload URL",
    ),
    (
        "workflow.aurora_esxi_vm_kill",
        re.compile(r"\besxcli\s+vm\s+process\s+kill\s+--type=force\s+--world-id", re.I),  # push-guard: ignore
        "Aurora-reported ESXi force-kill command shape",
    ),
    (
        "workflow.public_linux_kernel_lpe_poc",
        re.compile(r"NebuSec/CyberMeowfia(?:/[^\s\"']*)?/Linux-CVE-2026-(?:80714|74597|74581|74480|72255|72137|68376|68162|64560|63834|52933|52929|52924|52923|52912|43502|43501|43074|43042|31678|31659|23274)", re.I),  # push-guard: ignore
        "Public September 2026 Linux kernel exploit-pack source in executable or configuration content",
    ),
    (
        "workflow.trinitite_payload_marker",
        re.compile(r"Trinitite:\s*Sponsored by Preview 2 Effects|\b3FWCvzduYZg\.js\b|\bdoubletrinnys-", re.I),  # push-guard: ignore
        "Trinitite / Mini Shai-Hulud payload or exfiltration marker",
    ),
]

TRINITITE_COMMENT_PUBLISH_TRIGGER = re.compile(
    r"github\.event\.comment\.body\s*==\s*[\"']npm publish[\"']", re.I  # push-guard: ignore
)

ATOMIC_ARCH_AUR_PATTERNS = [
    (
        "workflow.atomicarch_aur_atomic_lockfile",
        re.compile(r"(?<![\w@/-])atomic-lockfile(?![\w/-])", re.I),
        "AUR build metadata references malicious atomic-lockfile npm package",
    ),
    (
        "workflow.atomicarch_aur_npm_loader",
        re.compile(r"\b(?:npm\s+(?:install|i|exec|x)|npx)\b.*(?<![\w@/-])atomic-lockfile(?![\w/-])|(?<![\w@/-])atomic-lockfile(?![\w/-]).*\b(?:npm\s+(?:install|i|exec|x)|npx)\b", re.I),
        "AUR build/install script invokes npm while referencing atomic-lockfile",
    ),
]

OTTERCOOKIE_NPM_PATTERNS = [
    (
        "workflow.ottercookie_vercel_c2",
        re.compile(
            r"cloudflare(?:insights|firewall|security)(?:\[\.\]|\.)vercel(?:\[\.\]|\.)app",  # push-guard: ignore
            re.I,
        ),  # push-guard: ignore
        "OtterCookie npm Vercel-hosted C2 domain",
    ),
    (
        "workflow.ottercookie_npm_package",
        re.compile(
            r"\b(?:bjs-lint-builders|bjs-lint-builder|bjs-biginteger|"  # push-guard: ignore
            r"hjs-lint-builders|sjs-builders|sjs-builder|npm-doc-builder)\b",  # push-guard: ignore
            re.I,
        ),  # push-guard: ignore
        "Panther OtterCookie npm package indicator",
    ),
    (
        "workflow.ottercookie_ssh_backdoor_shape",
        re.compile(r"authorized_keys|ufw\s+allow\s+22/tcp|/api/ssh-key", re.I),  # push-guard: ignore
        "OtterCookie SSH key or firewall backdoor behavior",
    ),
]

DPRK_SOCKET_IO_LOADER_PATTERNS = [
    (
        "workflow.dprk_socketio_service_fetch",
        re.compile(r"/api/service", re.I),  # push-guard: ignore
        "DPRK/Famous Chollima-style Socket.IO loader service path",
    ),
    (
        "workflow.dprk_socketio_0001_stage",
        re.compile(r"\b0001\.dat\b", re.I),  # push-guard: ignore
        "DPRK/Famous Chollima-style 0001.dat second-stage payload name",
    ),
    (
        "workflow.dprk_socketio_node_exec",
        re.compile(
            r"\bchild_process\b|\b(?:spawn|spawnSync|exec|execFile|execSync)\s*\(|"
            r"\bprocess\.execPath\b|\bnode\s+[^;&|]*0001\.dat\b",
            re.I,
        ),
        "DPRK/Famous Chollima-style Node execution path near loader code",
    ),
]

ASTRO_CONFIG_C2_PATTERNS = [
    (
        "workflow.astro_config_create_require",
        re.compile(r"\bcreateRequire\s*\(", re.I),
        "Astro config reconstructs CommonJS require",
    ),
    (
        "workflow.astro_config_eval_sink",
        re.compile(r"\b(?:eval|Function)\s*\(", re.I),
        "Astro config contains JavaScript eval/function execution sink",
    ),
    (
        "workflow.astro_config_network_loader",
        re.compile(
            r"\brequire\s*\(\s*['\"](?:node:)?https?['\"]\s*\)|"
            r"\bfrom\s+['\"](?:node:)?https?['\"]|"
            r"\bhttps?\s*\.\s*(?:request|get)\s*\(|"
            r"\bfetch\s*\(",
            re.I,
        ),
        "Astro config contains network loader behavior",
    ),
    (
        "workflow.astro_config_blockchain_c2",
        re.compile(
            r"trongrid|aptoslabs|bsc-dataseed|publicnode|eth_getTransactionByHash|"
            r"Sec-V|TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP",  # push-guard: ignore
            re.I,
        ),
        "Astro config contains blockchain/C2 relay marker",
    ),
]

ASTRO_GITIGNORE_HIDE_FILES = re.compile(
    r"\b(?:branch_structure\.json|temp_auto_push\.bat|temp_interactive_push\.bat)\b",
    re.I,
)

OPENCLAW_FIXED_VERSION = "2026.4.23"
OPENCLAW_VERSION_RE = re.compile(
    r"\bopenclaw\b[^\n\r]{0,80}\b([0-9]{4}\.[0-9]{1,2}\.[0-9]{1,2})\b",
    re.I,
)
OPENCLAW_OPEN_DM_POLICY_RE = re.compile(r"\bdmPolicy[\"']?\s*[:=]\s*[\"']open[\"']", re.I)
OPENCLAW_WILDCARD_ALLOW_RE = re.compile(
    r"\ballowFrom[\"']?\s*[:=][^\n\r]{0,160}[\"']\*[\"']",
    re.I,
)
OPENCLAW_DISABLED_SANDBOX_RE = re.compile(
    r"(?:agents\.defaults\.sandbox\.mode|sandbox[^\n\r]{0,80}\bmode)"
    r"[\"']?\s*[:=]\s*[\"'](?:none|off|host|main|disabled)[\"']",
    re.I,
)
NPM_V12_PREPARE_MIN_VERSION = "11.16.0"
NPM_VERSION_RE = re.compile(r"\bnpm\b[^\n\r0-9]{0,12}([0-9]+\.[0-9]+\.[0-9]+)\b", re.I)
NPM_REMOTE_TARBALL_RE = re.compile(
    r"[\"']https?://[^\"'\s]+(?:\.tgz|\.tar\.gz)(?:[?#][^\"'\s]*)?[\"']",
    re.I,
)
NPM_GIT_DEPENDENCY_RE = re.compile(
    r"[\"'](?:git\+https?|git|github|gitlab|bitbucket):[^\"']+[\"']|github\.com[:/]",
    re.I,
)
NPM_BROAD_ALLOW_RE = re.compile(
    r"^\s*(allow-git|allow-remote|allow-scripts)\s*=\s*(?:true|all|\*)\s*$",
    re.I,
)


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
BLOCKED_TERMS_CONFIG = ".push-guard-blocked-terms"
USER_BLOCKED_TERMS = Path.home() / ".config" / "push-guard" / "blocked-terms"


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


def load_blocked_terms(repo: str | Path = ".") -> list[str]:
    """Local/user word list. Never ships in the published package.

    Repo file ``.push-guard-blocked-terms`` plus optional
    ``~/.config/push-guard/blocked-terms``. One term per line. Used to catch
    personal / house names in a *public* diff without putting those names in
    Push Guard source.
    """
    terms: list[str] = []
    seen: set[str] = set()
    paths = [USER_BLOCKED_TERMS, Path(repo) / BLOCKED_TERMS_CONFIG]
    for config in paths:
        try:
            text = Path(config).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key = line.casefold()
            if key in seen:
                continue
            seen.add(key)
            terms.append(line)
    return terms


def _scan_line_for_blocked_terms(
    line: str, path: str, line_number: int, terms: list[str]
) -> list[SecretFinding]:
    if not terms or IGNORE_MARKER.search(line):
        return []
    findings: list[SecretFinding] = []
    folded = line.casefold()
    for term in terms:
        if len(term) < 3:
            continue
        needle = term.casefold()
        if re.search(r"(?<![A-Za-z0-9_])" + re.escape(needle) + r"(?![A-Za-z0-9_])", folded):
            findings.append(
                SecretFinding(
                    rule_id="personal.blocked_term",
                    path=path,
                    line=line_number,
                    reason="Personal or house term from local blocked-terms list",
                    evidence="<redacted>",
                )
            )
    return findings


def _scan_tree_for_gitignored(repo: Path, local_sha: str) -> list[SecretFinding]:
    """Block tracked files whose paths match the repo ignore rules.

    Uses ``git check-ignore --no-index`` so a force-added personal file still
    fails, even though a normal check-ignore skips tracked paths.
    """
    paths = _tree_paths(repo, local_sha)
    if not paths:
        return []
    try:
        completed = subprocess.run(
            _git_command(
                repo,
                ["check-ignore", "--no-index", "-z", "--stdin"],
                repo,
            ),
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            input="\0".join(paths) + "\0",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise PushGuardInspectionError(
            f"git check-ignore could not run: {exc.__class__.__name__}"
        ) from exc
    if completed.returncode not in (0, 1):
        stderr = _first_stderr_line(completed.stderr)
        detail = f": {stderr}" if stderr else ""
        raise PushGuardInspectionError(
            f"git check-ignore failed with exit {completed.returncode}{detail}"
        )
    findings: list[SecretFinding] = []
    for path in completed.stdout.split("\0"):
        if not path:
            continue
        findings.append(
            SecretFinding(
                rule_id="private_path.gitignored",
                path=path,
                line=0,
                reason="Path is gitignored but present in the pushed tree",
                evidence="<redacted>",
            )
        )
    return findings


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

    def __post_init__(self) -> None:
        # Paths and local rule patterns are untrusted metadata too. A filename
        # can itself contain a matched credential even when evidence is redacted.
        object.__setattr__(self, "path", _redact_metadata(self.path))
        object.__setattr__(self, "reason", _redact_metadata(self.reason))


def _redact_metadata(value: str) -> str:
    """Never return a recognized credential embedded in diagnostic metadata."""
    for variant in [value, *_normalized_secret_shape_variants(value)]:
        if any(pattern.search(variant) for _, pattern, _, _ in SECRET_PATTERNS):
            return "<redacted>"
        match = GENERIC_ASSIGNMENT.search(variant)
        if match and not _value_is_placeholder(match.group(1)):
            return "<redacted>"
    return value


def _display_metadata(value: str) -> str:
    # Preserve exact path data for rule matching/API consumers, but never let a
    # filename or diagnostic control the terminal or forge additional lines.
    value = _redact_metadata(value)
    return "".join(
        (f"\\x{ord(char):02x}" if ord(char) <= 255 else f"\\u{ord(char):04x}")
        if unicodedata.category(char) in {"Cc", "Cf"} else char
        for char in value
    )


class _GuardArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        super().error(_display_metadata(message))


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
        blocked_terms = load_blocked_terms(repo_path)
        for diff_text in diffs:
            findings.extend(_scan_diff(diff_text, blocked_terms=blocked_terms))
        findings.extend(_scan_history_private_paths(repo_path, local_sha, remote_sha, private_patterns))
        if local_sha not in seen_path_shas:
            seen_path_shas.add(local_sha)
            findings.extend(
                _scan_tree_for_private_paths(repo_path, local_sha, private_patterns)
            )
            findings.extend(_scan_tree_for_gitignored(repo_path, local_sha))
    return list(dict.fromkeys(findings))


def scan_git_range(
    repo: str | Path,
    base_ref: str,
    head_ref: str = "HEAD",
) -> list[SecretFinding]:
    """Scan committed changes between two refs without invoking git push."""
    repo_path = _resolve_git_root(Path(repo))
    base_sha = _resolve_commit(repo_path, base_ref)
    head_sha = _resolve_commit(repo_path, head_ref)
    findings: list[SecretFinding] = []
    blocked_terms = load_blocked_terms(repo_path)
    for diff_text in _diffs_for_push_ref(repo_path, head_sha, base_sha):
        findings.extend(_scan_diff(diff_text, blocked_terms=blocked_terms))
    private_patterns = load_private_path_patterns(repo_path)
    findings.extend(_scan_history_private_paths(repo_path, head_sha, base_sha, private_patterns))
    findings.extend(
        _scan_tree_for_private_paths(
            repo_path,
            head_sha,
            private_patterns,
        )
    )
    findings.extend(_scan_tree_for_gitignored(repo_path, head_sha))
    return list(dict.fromkeys(findings))


def _scan_history_private_paths(
    repo: Path, local_sha: str, remote_sha: str, patterns: list[str]
) -> list[SecretFinding]:
    """Private material remains published when an outgoing later commit deletes it."""
    if not patterns:
        return []
    findings: list[SecretFinding] = []
    seen: set[str] = set()
    for commit in _outgoing_commits(repo, local_sha, remote_sha):
        # Inspect added/changed paths, not whole historical trees. Unchanged
        # private paths confined to the trusted base do not expand this range.
        output = _run_git(repo, [
            "diff-tree", "--root", "--no-commit-id", "--name-only", "-z", "-r",
            "--no-ext-diff", "--no-textconv", "--no-renames",
            "--diff-merges=first-parent", "--diff-filter=ACMRT", commit,
        ])
        for path in output.split("\0"):
            if not path or path in seen:
                continue
            seen.add(path)
            matched = path_matches_private(path, patterns)
            if matched:
                findings.append(SecretFinding(
                    "private_path.match", path, 0,
                    f"Private/internal path (pattern: {matched})", "<redacted>",
                ))
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
    findings: list[SecretFinding] = []
    for path in _tree_paths(repo, local_sha):
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
    if argv and argv[0] == "scan":
        return _scan_main(argv[1:])
    if argv and argv[0] in {"-h", "--help"}:
        _print_help()
        return 0

    # Backward-compatible pre-push mode. Existing hooks call:
    #   python -m push_guard --repo "$(git rev-parse --show-toplevel)"
    return _pre_push_main(argv)


def _pre_push_main(argv: list[str]) -> int:
    parser = _GuardArgumentParser(
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
        print(_display_metadata(str(exc)), file=sys.stderr)
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
            f"- {finding.rule_id} at {_display_metadata(finding.path)}{line_suffix} "
            f"({_display_metadata(finding.reason)}; {finding.evidence})",
            file=sys.stderr,
        )
    print(
        "Review locally: untrack the private file, or remove/rotate the secret, "
        "then retry.",
        file=sys.stderr,
    )
    return 1


def _scan_main(argv: list[str]) -> int:
    parser = _GuardArgumentParser(
        prog="push-guard scan",
        description="Scan a committed Git range without attempting a push.",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Repository path. Defaults to current directory.",
    )
    parser.add_argument(
        "--base",
        required=True,
        help="Trusted base ref, such as origin/main.",
    )
    parser.add_argument(
        "--head",
        default="HEAD",
        help="Candidate head ref. Defaults to HEAD.",
    )
    args = parser.parse_args(argv)

    try:
        findings = scan_git_range(args.repo, args.base, args.head)
    except RuntimeError as exc:
        print("Push Guard could not inspect this range.", file=sys.stderr)
        print(_display_metadata(str(exc)), file=sys.stderr)
        print("Blocking publication because inspection failed.", file=sys.stderr)
        return 1

    if not findings:
        print(f"Push Guard found no blocking findings in {_display_metadata(args.base)}..{_display_metadata(args.head)}.")
        return 0

    print("Push Guard blocked this range. Secret values are redacted.", file=sys.stderr)
    for finding in findings:
        line_suffix = f":{finding.line}" if finding.line else ""
        print(
            f"- {finding.rule_id} at {_display_metadata(finding.path)}{line_suffix} "
            f"({_display_metadata(finding.reason)}; {finding.evidence})",
            file=sys.stderr,
        )
    print("Review the reported paths locally before publication.", file=sys.stderr)
    return 1


def _install_main(argv: list[str]) -> int:
    parser = _GuardArgumentParser(
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
        print(f"Push Guard install failed: {_display_metadata(str(exc))}", file=sys.stderr)
        return 1

    print(f"Push Guard installed: {_display_metadata(str(hook_path))}")
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
    configured_hook_path = _run_git(
        repo_path, ["rev-parse", "--git-path", "hooks/pre-push"]
    ).strip()
    if not configured_hook_path:
        raise PushGuardInspectionError(
            "git rev-parse --git-path hooks/pre-push returned no path"
        )
    hook_path = Path(configured_hook_path)
    if not hook_path.is_absolute():
        hook_path = repo_path / hook_path
    hook_dir = hook_path.parent
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
        "       push-guard scan --base REF [--head REF] [--repo REPO]\n"
        "       push-guard install [--repo REPO] [--force] [--allow-home-repo]\n\n"
        "Local secret guard. Scan a committed range, run from a Git pre-push\n"
        "hook, or install the hook with `push-guard install`."
    )


def _scan_line(line: str, path: str, line_number: int) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    skip_workflow_rules = bool(IGNORE_MARKER.search(line))

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

    if not findings:
        findings.extend(
            _scan_normalized_high_confidence_token_shapes(line, path, line_number)
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

    # The explicit marker only suppresses non-secret workflow/IOC rules. It
    # cannot allow a provider token shape or generic secret assignment.
    if skip_workflow_rules:
        return findings

    findings.extend(_scan_line_for_workflow_compromise(line, path, line_number))
    findings.extend(_scan_line_for_hades_pypi(line, path, line_number))
    findings.extend(_scan_line_for_agentjacking(line, path, line_number))
    findings.extend(_scan_line_for_copilot_reprompt(line, path, line_number))
    findings.extend(_scan_line_for_known_compromised_npm(line, path, line_number))
    findings.extend(_scan_line_for_phantomsub_npm(line, path, line_number))
    findings.extend(_scan_line_for_advisory_dependencies(line, path, line_number))
    findings.extend(_scan_line_for_graphalgo_dependencies(line, path, line_number))
    findings.extend(_scan_line_for_september_2026_threats(line, path, line_number))
    findings.extend(_scan_line_for_atomicarch_aur(line, path, line_number))
    findings.extend(_scan_line_for_ottercookie_npm(line, path, line_number))
    findings.extend(_scan_line_for_dprk_socketio_loader(line, path, line_number))
    findings.extend(_scan_line_for_astro_config_c2(line, path, line_number))
    findings.extend(_scan_line_for_openclaw_agent_exposure(line, path, line_number))
    findings.extend(_scan_line_for_npm_v12_readiness(line, path, line_number))

    return findings


def _scan_normalized_high_confidence_token_shapes(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    seen_rules: set[str] = set()

    for variant in _normalized_secret_shape_variants(line):
        for rule_id, pattern, reason, high_confidence in SECRET_PATTERNS:
            if not high_confidence or rule_id in seen_rules:
                continue
            if pattern.search(variant):
                seen_rules.add(rule_id)
                findings.append(
                    SecretFinding(
                        rule_id=rule_id,
                        path=path,
                        line=line_number,
                        reason=f"{reason} in encoded or split text",
                        evidence="<redacted>",
                    )
                )

    return findings


def _normalized_secret_shape_variants(line: str) -> list[str]:
    variants: list[str] = []

    decoded = urllib.parse.unquote(line)
    if decoded != line:
        variants.append(decoded)

    compact = re.sub(r"[\"'`]", "", line)
    compact = re.sub(r"\s*\+\s*", "", compact)
    compact = re.sub(r"\s+", "", compact)
    if compact != line:
        variants.append(compact)

    if decoded != line:
        decoded_compact = re.sub(r"[\"'`]", "", decoded)
        decoded_compact = re.sub(r"\s*\+\s*", "", decoded_compact)
        decoded_compact = re.sub(r"\s+", "", decoded_compact)
        if decoded_compact != decoded and decoded_compact not in variants:
            variants.append(decoded_compact)

    return variants


def _scan_line_for_workflow_compromise(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    if not _is_workflow_or_script_path(normalized_path):
        return []

    findings: list[SecretFinding] = []
    if (
        ".github/workflows/" in normalized_path.lower()
        and re.search(
            r"\buses\s*:\s*[\"']?actions-cool/(?:issues-helper|maintain-one-comment)@v[0-9][\w.-]*\b",
            line,
            re.I,
        )
    ):
        findings.append(
            SecretFinding(
                rule_id="workflow.mini_shai_hulud_hijacked_action_tag",
                path=path,
                line=line_number,
                reason="Workflow uses a reported hijacked actions-cool release tag",
                evidence="<redacted>",
            )
        )

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
    is_agent_instruction = _is_agent_instruction_path(normalized_path)
    if (
        lowered_path.endswith((".md", ".mdx", ".txt", ".rst"))
        and not is_agent_instruction
    ):
        return []

    is_pth = lowered_path.endswith(".pth")
    is_code_or_workflow = (
        is_pth
        or is_agent_instruction
        or _is_workflow_or_script_path(normalized_path)
    )
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


def _scan_line_for_agentjacking(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    if normalized_path.lower().endswith((".md", ".mdx", ".txt", ".rst")):
        return []
    if not (
        _is_workflow_or_script_path(normalized_path)
        or _is_dependency_metadata_path(normalized_path)
        or normalized_path.lower().endswith((".json", ".jsonc", ".toml", ".env"))
    ):
        return []

    findings: list[SecretFinding] = []
    for rule_id, pattern, reason in AGENTJACKING_PATTERNS:
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


def _scan_line_for_copilot_reprompt(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    lowered_path = normalized_path.lower()
    if lowered_path.endswith((".md", ".mdx", ".txt", ".rst")):
        return []
    if not (
        _is_workflow_or_script_path(normalized_path)
        or _is_dependency_metadata_path(normalized_path)
        or lowered_path.endswith((".html", ".htm", ".json", ".jsonc", ".toml", ".env"))
    ):
        return []

    findings: list[SecretFinding] = []
    decoded = urllib.parse.unquote(line)
    candidates = [line]
    if decoded != line:
        candidates.append(decoded)

    for rule_id, pattern, reason in COPILOT_REPROMPT_PATTERNS:
        if any(pattern.search(candidate) for candidate in candidates):
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


def _scan_line_for_known_compromised_npm(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    if not _is_dependency_metadata_path(normalized_path):
        return []

    findings: list[SecretFinding] = []
    for rule_id, pattern, reason in KNOWN_COMPROMISED_NPM_PACKAGE_PATTERNS:
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


PHANTOMSUB_OX_NPM_NAMES = (
    "ourin-baileys", "@nexustechpro/baileys", "@badzz88/baileys",
    "@ostyado/baileys", "levvleys", "@vanzxy/baileys",
    "@yudzxml/baileys", "@chatunity/baileys", "@kelvdra/baileys",
    "neuralwhatsapp", "lilys-baileys", "@fyxzpediaa/baileys",
    "noxleyss", "@xrelly-stack/bails", "alipclutch-baileys",
)


def _scan_line_for_phantomsub_npm(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    if not _is_dependency_metadata_path(path):
        return []
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for package_name in PHANTOMSUB_OX_NPM_NAMES:
        escaped = re.escape(package_name)
        if re.search(rf'["\']{escaped}["\']\s*:', line, re.I) or re.search(
            rf'(?<![\w@.-]){escaped}@(?:npm:)?\d', line, re.I
        ) or (name == "package.json" and re.search(
            rf'["\']name["\']\s*:\s*["\']{escaped}["\']', line, re.I
        )) or (name in {"package-lock.json", "npm-shrinkwrap.json"} and re.search(
            rf'["\'](?:node_modules/(?:@[^/"\']+/)?[^/"\']+/)*node_modules/{escaped}["\']\s*:',
            line, re.I,
        )):
            return [SecretFinding(
                "workflow.phantomsub_ox_npm_package", path, line_number,
                "OX-reported PhantomSub npm package appears in dependency metadata; review WhatsApp account use",
                "<redacted>",
            )]
    return []


def _scan_line_for_advisory_dependencies(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    """Review exact vulnerable pins added to dependency manifests."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if line.lstrip().startswith(("#", "//")):
        return []

    findings: list[SecretFinding] = []
    if name == "package.json":
        for match in re.finditer(
            r'["\'](lodash(?:-amd|-es|\.template)?)["\']\s*:\s*["\'](\d+\.\d+\.\d+)["\']',
            line,
            re.I,
        ):
            package_name, version = match.group(1).lower(), match.group(2)
            upper = "4.18.0" if package_name == "lodash.template" else "4.17.23"
            affected = _compare_dotted_version(version, "4.0.0") >= 0 and (
                _compare_dotted_version(version, upper) < (0 if package_name == "lodash.template" else 1)
            )
            if affected:
                findings.append(SecretFinding(
                    "workflow.lodash_template_cve_2026_4800_pin", path, line_number,
                    "Exact lodash pin is affected by GHSA-r5fr-rjxr-66jc; review _.template imports usage and upgrade to 4.18.0",
                    "<redacted>",
                ))

    if name in {"requirements.txt", "pyproject.toml"}:
        for match in re.finditer(
            r'(?<![\w.-])mcp(?:\[\s*[A-Za-z0-9_.-]+(?:\s*,\s*[A-Za-z0-9_.-]+)*\s*\])?'
            r'\s*==\s*(\d+\.\d+\.\d+(?:a\d+)?)(?=[\s"\'\],;#]|$)',
            line,
            re.I,
        ):
            version = match.group(1)
            base = re.sub(r"a\d+$", "", version)
            prerelease = base != version
            affected = (
                (_compare_dotted_version(base, "1.9.1") > 0 or (base == "1.9.1" and not prerelease))
                and (_compare_dotted_version(base, "1.30.0") < 0 or (base == "1.30.0" and prerelease))
            ) or (
                (_compare_dotted_version(base, "2.0.0") > 0 or (base == "2.0.0" and version != "2.0.0a0"))
                and (_compare_dotted_version(base, "2.2.0") < 0 or (base == "2.2.0" and prerelease))
            )
            if affected:
                findings.append(SecretFinding(
                    "workflow.mcp_oauth_credential_routing_pin", path, line_number,
                    "Exact mcp pin is affected by GHSA-qx49-fqc8-xw99; upgrade and bind issuer for unattended OAuth providers",
                    "<redacted>",
                ))

    return findings


def _scan_line_for_graphalgo_dependencies(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    """Match only the four reported Go/Terraform package identities in manifests."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    stripped = line.lstrip()
    if stripped.startswith(("#", "//")):
        return []

    if name in {"go.mod", "go.sum"} and re.search(
        r"^\s*(?:require\s+)?(?:gocommunity\.io/orderedbtree|gogets\.dev/btreex)\s+v[0-9]",
        line,
    ):
        rule_id = "workflow.graphalgo_go_module"
        reason = "Aikido-reported Graphalgo Go module appears in dependency metadata"
    elif (name.endswith(".tf") or name == ".terraform.lock.hcl") and re.search(
        r'^\s*(?:source\s*=\s*|provider\s+)["\'](?:registry\.terraform\.io/)?(?:gocommunity-io/dockerd|kreuzwenker/docker)["\']',
        line,
    ):
        rule_id = "workflow.graphalgo_terraform_provider"
        reason = "Aikido-reported Graphalgo Terraform provider appears in configuration"
    else:
        return []

    return [SecretFinding(rule_id, path, line_number, reason, "<redacted>")]


def _scan_line_for_september_2026_threats(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    lowered_path = normalized_path.lower()
    if lowered_path.endswith((".md", ".mdx", ".txt", ".rst")):
        return []

    is_reviewable = _is_workflow_or_script_path(normalized_path) or lowered_path.endswith(
        (".json", ".jsonc", ".toml", ".ini", ".conf", ".env", ".lock")
    )
    if not is_reviewable:
        return []

    findings: list[SecretFinding] = []
    for rule_id, pattern, reason in SEPTEMBER_2026_THREAT_PATTERNS:
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
        ".github/workflows/" in lowered_path
        and TRINITITE_COMMENT_PUBLISH_TRIGGER.search(line)
    ):
        findings.append(
            SecretFinding(
                rule_id="workflow.trinitite_comment_publish_trigger",
                path=path,
                line=line_number,
                reason="Comment-triggered npm publish workflow needs a trusted-author gate",
                evidence="<redacted>",
            )
        )

    return findings


def _scan_line_for_atomicarch_aur(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    if not _is_aur_build_metadata_path(normalized_path):
        return []

    findings: list[SecretFinding] = []
    for rule_id, pattern, reason in ATOMIC_ARCH_AUR_PATTERNS:
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


def _scan_line_for_ottercookie_npm(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    lowered_path = normalized_path.lower()
    if lowered_path.endswith((".md", ".mdx", ".txt", ".rst")):
        return []
    if not _is_workflow_or_script_path(normalized_path):
        return []

    findings: list[SecretFinding] = []
    for rule_id, pattern, reason in OTTERCOOKIE_NPM_PATTERNS:
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


def _scan_line_for_dprk_socketio_loader(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    lowered_path = normalized_path.lower()
    if lowered_path.endswith((".md", ".mdx", ".txt", ".rst")):
        return []
    if not (
        _is_workflow_or_script_path(normalized_path)
        or _is_dependency_metadata_path(normalized_path)
        or lowered_path.endswith((".json", ".jsonc", ".env"))
    ):
        return []

    findings: list[SecretFinding] = []
    for rule_id, pattern, reason in DPRK_SOCKET_IO_LOADER_PATTERNS:
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


def _scan_line_for_astro_config_c2(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    lowered_path = normalized_path.lower()
    findings: list[SecretFinding] = []

    if lowered_path.endswith("/.gitignore") or lowered_path == ".gitignore":
        if ASTRO_GITIGNORE_HIDE_FILES.search(line):
            findings.append(
                SecretFinding(
                    rule_id="workflow.gitignore_hidden_pr_tooling",
                    path=path,
                    line=line_number,
                    reason="Gitignore hides PR automation/helper artifact names used in Astro config C2 reporting",
                    evidence="<redacted>",
                )
            )
        return findings

    if not _is_astro_config_path(normalized_path):
        return findings

    for rule_id, pattern, reason in ASTRO_CONFIG_C2_PATTERNS:
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

    if len(line) > 300 and re.search(r"[ \t]{80,}\S", line) and _astro_config_line_has_loader_signal(line):
        findings.append(
            SecretFinding(
                rule_id="workflow.astro_config_hidden_payload_line",
                path=path,
                line=line_number,
                reason="Astro config contains a long horizontally hidden executable-looking payload line",
                evidence="<redacted>",
            )
        )

    return findings


def _is_astro_config_path(path: str) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.startswith("astro.config.") and name.endswith((".js", ".cjs", ".mjs", ".ts", ".mts", ".cts"))


def _astro_config_line_has_loader_signal(line: str) -> bool:
    return bool(
        re.search(
            r"createRequire|eval\s*\(|Function\s*\(|global\s*(?:\.|\[)|"
            r"Buffer\.from|https?\.|\.request\s*\(|\.get\s*\(|fetch\s*\(|"
            r"trongrid|aptoslabs|bsc-dataseed|publicnode",
            line,
            re.I,
        )
    )


def _scan_line_for_openclaw_agent_exposure(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    findings: list[SecretFinding] = []

    if _is_dependency_metadata_path(normalized_path):
        for match in OPENCLAW_VERSION_RE.finditer(line):
            version = match.group(1)
            if _compare_dotted_version(version, OPENCLAW_FIXED_VERSION) < 0:
                findings.append(
                    SecretFinding(
                        rule_id="workflow.openclaw_vulnerable_version",
                        path=path,
                        line=line_number,
                        reason=f"OpenClaw {version} predates the {OPENCLAW_FIXED_VERSION} message-object prompt-boundary fix",
                        evidence="<redacted>",
                    )
                )

    if not _is_openclaw_config_path(normalized_path):
        return findings

    has_open_dm = OPENCLAW_OPEN_DM_POLICY_RE.search(line)
    if has_open_dm and OPENCLAW_WILDCARD_ALLOW_RE.search(line):
        findings.append(
            SecretFinding(
                rule_id="workflow.openclaw_open_dm_wildcard",
                path=path,
                line=line_number,
                reason="OpenClaw config allows public inbound DMs with a wildcard allowlist",
                evidence="<redacted>",
            )
        )

    if has_open_dm and OPENCLAW_DISABLED_SANDBOX_RE.search(line):
        findings.append(
            SecretFinding(
                rule_id="workflow.openclaw_open_dm_unsandboxed",
                path=path,
                line=line_number,
                reason="OpenClaw config combines open inbound DMs with host/main/disabled sandbox mode",
                evidence="<redacted>",
            )
        )

    return findings


def _is_dependency_metadata_path(path: str) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    }


def _is_aur_build_metadata_path(path: str) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    lowered = name.lower()
    return name in {"PKGBUILD", ".SRCINFO"} or lowered.endswith(".install")


def _is_openclaw_config_path(path: str) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in {".crabbox.yaml", ".crabbox.yml"} or bool(
        re.match(r"openclaw\.(?:json|jsonc|ya?ml|toml)$", name, re.I)
    )


def _compare_dotted_version(left: str, right: str) -> int:
    left_parts = [int(part) for part in left.split(".")]
    right_parts = [int(part) for part in right.split(".")]
    length = max(len(left_parts), len(right_parts))
    left_parts.extend([0] * (length - len(left_parts)))
    right_parts.extend([0] * (length - len(right_parts)))
    if left_parts == right_parts:
        return 0
    return -1 if left_parts < right_parts else 1


def _scan_line_for_npm_v12_readiness(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    name = normalized_path.rsplit("/", 1)[-1].lower()
    findings: list[SecretFinding] = []

    if name == ".npmrc":
        match = NPM_BROAD_ALLOW_RE.search(line)
        if match:
            findings.append(
                SecretFinding(
                    rule_id=f"workflow.npm_v12_broad_{match.group(1).replace('-', '_')}",
                    path=path,
                    line=line_number,
                    reason="Repo .npmrc broadly re-enables an npm v12 install-time execution or fetch surface",
                    evidence="<redacted>",
                )
            )
        return findings

    if not _is_dependency_metadata_path(normalized_path):
        return findings

    for match in NPM_VERSION_RE.finditer(line):
        version = match.group(1)
        if _compare_dotted_version(version, NPM_V12_PREPARE_MIN_VERSION) < 0:
            findings.append(
                SecretFinding(
                    rule_id="workflow.npm_v12_old_npm_pin",
                    path=path,
                    line=line_number,
                    reason=f"npm {version} is older than {NPM_V12_PREPARE_MIN_VERSION}, which surfaces npm v12 migration warnings",
                    evidence="<redacted>",
                )
            )

    if NPM_REMOTE_TARBALL_RE.search(line):
        findings.append(
            SecretFinding(
                rule_id="workflow.npm_v12_remote_tarball_dependency",
                path=path,
                line=line_number,
                reason="npm dependency resolves from a remote tarball URL; npm v12 requires explicit --allow-remote approval",
                evidence="<redacted>",
            )
        )

    if NPM_GIT_DEPENDENCY_RE.search(line):
        findings.append(
            SecretFinding(
                rule_id="workflow.npm_v12_git_dependency",
                path=path,
                line=line_number,
                reason="npm dependency resolves from a Git source; npm v12 requires explicit --allow-git approval",
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


def _is_agent_instruction_path(path: str) -> bool:
    """Known repo-local instruction paths that agents may load as commands."""
    normalized = path.replace("\\", "/").lower().lstrip("/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    basename = normalized.rsplit("/", 1)[-1]
    if basename in {".cursorrules", ".windsurfrules"}:
        return True
    if normalized == ".github/copilot-instructions.md":
        return True
    return normalized.startswith(".cursor/rules/")


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
    for line_number, line in enumerate(stdin_text.splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 4:
            raise PushGuardInspectionError(
                f"Malformed pre-push input at line {line_number}"
            )
        local_ref, local_sha, remote_ref, remote_sha = parts
        if not re.fullmatch(r"[0-9a-fA-F]{40}", local_sha) or not re.fullmatch(
            r"[0-9a-fA-F]{40}", remote_sha
        ):
            raise PushGuardInspectionError(
                f"Invalid object ID in pre-push input at line {line_number}"
            )
        refs.append((local_ref, local_sha.lower(), remote_ref, remote_sha.lower()))
    return refs


def _tree_paths(repo: Path, treeish: str) -> list[str]:
    """Return exact Git tree paths without newline/quoting ambiguity."""
    output = _run_git(repo, ["ls-tree", "-r", "-z", "--name-only", treeish])
    return [path for path in output.split("\0") if path]


def _outgoing_commits(repo: Path, local_sha: str, remote_sha: str) -> list[str]:
    if remote_sha == ZERO_SHA:
        # The remote has no trusted base for this ref. Other remote-tracking
        # refs may belong to private repositories and cannot justify excluding
        # objects from a first push to a different destination.
        commits = _run_git(
            repo,
            ["rev-list", "--reverse", local_sha],
        ).splitlines()
        if not commits:
            commits = [local_sha]
    else:
        # Scan every commit object introduced by the update. An endpoint diff
        # misses a secret added in one commit and removed again before HEAD.
        commits = _run_git(
            repo,
            ["rev-list", "--reverse", local_sha, f"^{remote_sha}"],
        ).splitlines()

    return commits


def _diffs_for_push_ref(repo: Path, local_sha: str, remote_sha: str) -> list[str]:
    return [
        _run_git(
            repo,
            [
                "show",
                "--format=",
                "--unified=0",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--text",
                "--src-prefix=a/",
                "--dst-prefix=b/",
                "--diff-merges=first-parent",
                "--diff-filter=ACMRT",
                commit,
            ],
        )
        for commit in _outgoing_commits(repo, local_sha, remote_sha)
    ]


def _scan_diff(
    diff_text: str, *, blocked_terms: list[str] | None = None
) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    current_path = "<diff>"
    new_line = 0
    in_hunk = False
    terms = blocked_terms or []
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current_path = "<diff>"
            in_hunk = False
            continue
        if not in_hunk and line.startswith("+++ "):
            current_path = _decode_diff_path(line[4:])
            continue
        if line.startswith("@@"):
            new_line = _parse_hunk_new_line(line)
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("+"):
            body = line[1:]
            findings.extend(_scan_line(body, current_path, max(new_line, 1)))
            findings.extend(
                _scan_line_for_blocked_terms(body, current_path, max(new_line, 1), terms)
            )
            new_line += 1
            continue
        if line.startswith("-") and not line.startswith("---"):
            continue
        if line.startswith("\\ No newline"):
            continue
        new_line += 1
    return findings


def _decode_diff_path(value: str) -> str:
    """Decode Git's C-quoted UTF-8 path format without evaluating source text."""
    if value.startswith('"'):
        if not value.endswith('"'):
            raise PushGuardInspectionError("Invalid quoted path in Git diff")
        encoded = value[1:-1]
        decoded = bytearray()
        escapes = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}
        index = 0
        while index < len(encoded):
            char = encoded[index]
            if char != "\\":
                decoded.extend(char.encode("utf-8"))
                index += 1
                continue
            index += 1
            if index == len(encoded):
                raise PushGuardInspectionError("Invalid escape in Git diff path")
            char = encoded[index]
            if char in escapes:
                decoded.append(escapes[char])
                index += 1
            elif char in "01234567":
                end = index + 1
                while end < min(index + 3, len(encoded)) and encoded[end] in "01234567":
                    end += 1
                number = int(encoded[index:end], 8)
                if number > 255:
                    raise PushGuardInspectionError("Invalid octal escape in Git diff path")
                decoded.append(number)
                index = end
            else:
                raise PushGuardInspectionError("Invalid escape in Git diff path")
        value = decoded.decode("utf-8", errors="replace")
    if value == "/dev/null":
        return "<deleted>"
    if not value.startswith("b/"):
        raise PushGuardInspectionError("Unexpected path prefix in Git diff")
    return value[2:]


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


def _resolve_commit(repo: Path, ref: str) -> str:
    if not ref or ref.startswith("-") or any(character.isspace() for character in ref):
        raise PushGuardInspectionError(f"Invalid Git ref: {ref!r}")
    sha = _run_git(repo, ["rev-parse", "--verify", f"{ref}^{{commit}}"]).strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
        raise PushGuardInspectionError(f"Git ref did not resolve to a commit: {ref}")
    return sha.lower()


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
