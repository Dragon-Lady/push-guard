"""Local, bounded secrets-on-disk inspection. No Git or other child processes."""
from __future__ import annotations

import argparse
from collections import Counter
import fnmatch
import html
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tomllib
from urllib.parse import unquote

from .sweep_boundary import Budget, BudgetExceeded, MountSkipped, ScanFS
from .guard import GENERIC_ASSIGNMENT, SECRET_PATTERNS, _value_is_placeholder
from .sweep_safety import (MAX_BYTES, SafeError, Store, absolute, bounded_read,
                           directory_fd, fingerprint, write_private)

HISTORY = {'.bash_history', '.zsh_history', '.python_history', '.node_repl_history',
           '.psql_history', '.mysql_history', '.sqlite_history', '.lesshst'}
DOTFILES = {'.bashrc', '.zshrc', '.profile', '.bash_profile', '.npmrc', '.docker/config.json'}
EXPECTED = {'.git-credentials', '.aws/credentials', '.netrc', '.pypirc',
            '.config/gh/hosts.yml', '.config/rclone/rclone.conf', '.codex/auth.json'}
CONFIG_EXT = {'.json', '.toml', '.yaml', '.yml', '.ini', '.conf'}
SKIP_DIRS = {'node_modules', '.venv', 'venv', '.git', '__pycache__', '.tox',
             '.nox', '.mypy_cache', '.pytest_cache', '.ruff_cache', 'Cache',
             'CacheStorage', 'Code Cache', 'GPUCache', 'keyrings', '.gnupg',
             '.ssh', '.mozilla', 'chromium', 'google-chrome', 'BraveSoftware',
             'microsoft-edge', 'firefox', 'vivaldi', 'opera', 'Browser',
             'Local Storage', 'Session Storage', 'IndexedDB', 'Cookies'}
SKIP_SUFFIX = {'.gz', '.bz2', '.xz', '.zip', '.tar', '.7z', '.zst', '.rar',
               '.sqlite', '.sqlite3', '.db', '.vscdb', '.db3', '.sqlite-wal',
               '.sqlite-shm', '.db-wal', '.db-shm', '.vscdb-wal', '.vscdb-shm',
               '.kdbx', '.keyring', '.png', '.jpg', '.jpeg', '.gif', '.pdf',
               '.so', '.exe', '.bin', '.pyc', '.woff', '.woff2', '.mp4', '.mp3'}
PRUNE_DIRS = {'.cargo', '.rustup', '.npm', '.gradle', '.m2', '.yarn', '.pnpm-store'}
PRUNE_PATHS = {'.local/share/Trash', 'snap', 'go/pkg', '.local/share/Steam',
               '.local/share/flatpak', '.var/app', '.local/lib', '.nvm',
               '.cache/uv', '.cache/pip', '.cache/pypoetry', '.cache/huggingface',
               '.cache/torch', '.cache/ms-playwright', '.codex/plugins/cache'}
SKIP_PARTS = SKIP_DIRS | PRUNE_DIRS
PRUNE_PREFIXES = tuple(p + '/' for p in PRUNE_PATHS)
SKIP_ENDINGS = tuple(SKIP_SUFFIX)
MAX_DISCOVERY_SECONDS = 20
MAX_ENTRIES = 250_000
MAX_FILES = 10_000
MAX_FINDINGS = 10_000
MAX_TOTAL = 100 * 1024 * 1024
MAX_SECONDS = 45

# Existing provider definitions are reused without changing the hook's rule set.
EXTRA = [
    ('sweep.openai_extended', re.compile(r'(?<![\w-])sk-(?:proj-|svcacct-)[A-Za-z0-9_-]{20,}'), 'OpenAI'),
    ('sweep.slack_token', re.compile(r'\bxox[abpr]-[A-Za-z0-9-]{10,}'), 'Slack'),
    ('sweep.slack_webhook', re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+'), 'Slack webhook'),
    ('sweep.google_api_key', re.compile(r'\bAIza[A-Za-z0-9_-]{20,}'), 'Google API key'),
    ('sweep.google_access_token', re.compile(r'\bya29\.[A-Za-z0-9_-]{10,}'), 'Google access token'),
    ('sweep.google_refresh_token', re.compile(r'(?<![\w/])1//[A-Za-z0-9_-]{20,}'), 'Google refresh token'),
    ('sweep.npm_token', re.compile(r'\bnpm_[A-Za-z0-9]{16,}'), 'npm'),
    ('sweep.pypi_token', re.compile(r'\bpypi-[A-Za-z0-9_-]{16,}'), 'PyPI'),
    ('sweep.jwt', re.compile(r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'), 'JWT'),
    ('sweep.url_credentials', re.compile(r'https?://[^\s:/<>"\']+:[^\s@<>"\']+@[^\s/<>"\']+'), 'URL credentials'),
]
TYPE_LABELS = {'secret.github_fine_grained_token': 'GitHub', 'secret.github_token': 'GitHub',
               'secret.gitlab_incoming_email_token': 'GitLab', 'secret.openai_token': 'OpenAI',
               'secret.aws_access_key': 'AWS access key', 'secret.private_key': 'Private key'}
RULE_TYPES = {**TYPE_LABELS, **{rule: label for rule, _, label in EXTRA},
              'sweep.generic_assignment': 'Generic assignment',
              'sweep.expected_store_mode': 'Credential store (metadata only)'}
GENERIC_EXTRA = re.compile(r'''(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9]+[_-])*(?:token|key|secret|password|passwd|pwd|apikey)(?:[_-][A-Za-z0-9]+)*[\"']?\s*[:=]\s*[\"']?([^'\"\s]{20,})''')
REFERENCE = re.compile(r'^(?:\$[A-Za-z_]\w*|\$\{[^}]+\}|<[^>]+>)$')
FILLER = re.compile(r'^(?:(?:example|changeme|dummy|placeholder|replace|sample|your|token|secret|key|xxx)|[-_.*\d])+$', re.I)
HINTS = ['Rotate a confirmed credential at its provider.',
         'For shell history: use history -d N in the owning shell, or edit with that shell closed.',
         'Move credentials to a keyring or an environment file with mode 0600.',
         'For repository files, consider adding the path to .gitignore.']


def placeholder(value):
    if not value or REFERENCE.fullmatch(value):
        return True
    # Only obvious filler is suppressed in provider bodies, never a random token
    # merely containing a word such as "test".
    body = re.sub(r'^(?:github_pat_|gh[pousr]_|glimt-|sk-(?:proj-|svcacct-)?|AKIA|ASIA|xox[abpr]-|AIza|ya29\.|1//|npm_|pypi-)', '', value)
    return len(set(body)) <= 1 or bool(FILLER.fullmatch(body))


def entropy(value):
    n = len(value)
    return -sum((v / n) * math.log2(v / n) for v in Counter(value).values()) if n else 0


def matches(text):
    """Yield internal matches only; callers retain no evidence text."""
    complete_keys = set()
    key_header = re.compile(r'-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----')
    for match in key_header.finditer(text):
        lineno = text.count('\n', 0, match.start()) + 1
        complete_keys.add(lineno)
        footer = '-----END ' + match.group(1) + '-----'
        end = text.find(footer, match.end())
        # Incomplete blocks fingerprint the bounded remainder, not the marker.
        value = text[match.start():end + len(footer)] if end >= 0 else text[match.start():]
        yield lineno, 'secret.private_key', 'Private key', value

    patterns = [(r, p, TYPE_LABELS[r]) for r, p, _, _ in SECRET_PATTERNS] + EXTRA
    for lineno, raw in enumerate(text.splitlines(), 1):
        # Also cover escaped provider strings in URLs, without double reporting.
        line = unquote(raw)
        seen = set()
        spans = []
        for rule, pattern, label in patterns:
            for match in pattern.finditer(line):
                value = match.group()
                if rule == 'secret.private_key' and lineno in complete_keys:
                    continue
                if rule != 'secret.private_key' and placeholder(value):
                    continue
                if rule == 'sweep.slack_webhook' and all(placeholder(v) for v in value.split('/services/', 1)[1].split('/')):
                    continue
                if rule == 'sweep.url_credentials':
                    password = value.split('://', 1)[1].rsplit('@', 1)[0].split(':', 1)[1]
                    if placeholder(password) or password.lower() in {'example', 'changeme', 'dummy', 'password', 'pass'}:
                        continue
                # Prefer the complete extended OpenAI shape over its prefix.
                if rule == 'secret.openai_token' and re.match(r'sk-(?:proj-|svcacct-)', value):
                    continue
                identity = (rule, value)
                if identity not in seen:
                    seen.add(identity)
                    spans.append(match.span())
                    yield lineno, rule, label, value
        for match in [*GENERIC_ASSIGNMENT.finditer(line), *GENERIC_EXTRA.finditer(line)]:
            value = match.group(1).rstrip(',;')
            if (any(a <= match.start(1) < b for a, b in spans) or placeholder(value)
                    or _value_is_placeholder(value) or entropy(value) < 3.5):
                continue
            identity = ('sweep.generic_assignment', value)
            if identity not in seen:
                seen.add(identity)
                yield lineno, 'sweep.generic_assignment', 'Generic assignment', value


class Cleaner:
    """Remove discovered values and provider-shaped names from local metadata."""
    def __init__(self):
        self.values = set()
        self._paths = {}

    def text(self, value):
        # A decoded match cannot safely be replaced in its encoded spelling.
        # Keep recoverable secret bytes out of reports, including list-targets.
        if unquote(value) != value:
            return '<redacted encoded path>'
        for _, _, _, secret in matches(value):
            value = value.replace(secret, '<redacted>')
        for secret in sorted(self.values, key=len, reverse=True):
            value = value.replace(secret, '<redacted>')
        return ''.join(c if c >= ' ' and c != '\x7f' else '?' for c in value)

    def clean(self, value):
        if isinstance(value, list):
            return [self.clean(item) for item in value]
        if isinstance(value, dict):
            # Only paths are untrusted. Keep protocol names and fp values intact.
            cleaned = {}
            for key, item in value.items():
                if key == 'path':
                    if item not in self._paths:
                        self._paths[item] = self.text(item)
                    cleaned[key] = self._paths[item]
                else:
                    cleaned[key] = self.clean(item)
            return cleaned
        return value


def home_path(home, value):
    path = absolute(value)
    if not path.is_relative_to(home):
        raise SafeError('all scan paths must be inside HOME')
    return path


def file_info(path, boundary=None):
    if boundary:
        boundary.check_path(path)
    parent = boundary.directory(path.parent) if boundary else directory_fd(path.parent)
    try:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if boundary:
            boundary.check_stat(path, info)
        return info
    finally:
        os.close(parent)


def skipped(path, home):
    rel = path.relative_to(home)
    label = rel.as_posix()
    return (any(part in SKIP_PARTS for part in rel.parts) or
            label in PRUNE_PATHS or label.startswith(PRUNE_PREFIXES) or
            path.name.lower().endswith(SKIP_ENDINGS) or
            path.name.endswith(('-journal', '-wal', '-shm')) or
            path.name in {'Login Data', 'Web Data', 'Cookies', 'History'})


def pattern_match(path, home, patterns):
    if not patterns:
        return False
    rel = path.relative_to(home).as_posix()
    return any(fnmatch.fnmatchcase(rel, p) or fnmatch.fnmatchcase(str(path), p)
               or fnmatch.fnmatchcase(path.name, p) for p in patterns)


def git_membership(path, home, boundary=None):
    """A .git marker establishes possible membership, not tracked/index status."""
    for parent in [path.parent, *path.parent.parents]:
        if not parent.is_relative_to(home):
            break
        try:
            info = file_info(parent / '.git', boundary)
        except (OSError, SafeError):
            continue
        if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode):
            return True
    return False


def discover(home, roots, includes, excludes, log_dirs, omitted, budget=None, boundary=None):
    targets = {}
    notes = Counter()
    visited = 0
    budget = budget or Budget(MAX_SECONDS)
    boundary = boundary or ScanFS(home)
    if boundary.unknown:
        return [], {'mount_metadata_unavailable': 1}

    def consider(path, kind):
        budget.check()
        if (path in omitted or skipped(path, home) or pattern_match(path, home, excludes)):
            return
        try:
            info = file_info(path, boundary)
        except MountSkipped:
            return
        except FileNotFoundError:
            return
        except (OSError, SafeError):
            notes['unreadable_metadata'] += 1
            return
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            notes['non_regular_symlink_or_hardlink'] += 1
            return
        if info.st_size > MAX_BYTES:
            notes['over_10_MB'] += 1
            return
        if path not in targets and len(targets) >= MAX_FILES:
            raise BudgetExceeded('target_budget')
        rel = path.relative_to(home).as_posix()
        store = rel in EXPECTED
        targets[path] = {'path': str(path), 'class': 'expected-store' if store else 'stray',
                         'mode': f'{stat.S_IMODE(info.st_mode):04o}',
                         'source': 'expected-store' if store else kind,
                         'inside_git_repo': git_membership(path, home, boundary), 'tracked': 'unknown',
                         'content_read': not store}

    def walk(root, depth, kind, parent_fd=None):
        nonlocal visited
        budget.check()
        if skipped(root, home) or root in omitted:
            return
        try:
            fd = boundary.directory(root) if parent_fd is None else boundary.child_directory(root, parent_fd)
        except MountSkipped:
            return
        except FileNotFoundError:
            return
        except (OSError, SafeError):
            notes['unreadable_directory'] += 1
            return
        try:
            with os.scandir(fd) as items:
                entries = []
                for entry in items:
                    visited += 1
                    budget.check()
                    if visited > MAX_ENTRIES:
                        raise BudgetExceeded('entry_budget')
                    entries.append(entry.name)
            for name in sorted(entries):
                budget.check()
                path = root / name
                if skipped(path, home) or path in omitted or pattern_match(path, home, excludes):
                    continue
                try:
                    boundary.check_path(path)
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    boundary.check_stat(path, info)
                except MountSkipped:
                    continue
                except (OSError, SafeError):
                    notes['unreadable_metadata'] += 1
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if depth > 0 and (kind != 'env' or name not in {'.cache', 'cache', 'caches'}):
                        walk(path, depth - 1, kind, fd)
                elif stat.S_ISREG(info.st_mode):
                    rel = path.relative_to(home).as_posix()
                    use = (kind == 'config' and path.suffix.lower() in CONFIG_EXT or
                           kind == 'env' and name.startswith('.env') or
                           kind == 'logs' and (name.endswith('.log') or 'logs' in path.parts) or
                           bool(includes) and pattern_match(path, home, includes))
                    if use:
                        consider(path, kind)
        finally:
            os.close(fd)

    try:
        with budget.phase(MAX_DISCOVERY_SECONDS, 'discovery_time_budget'):
            for item in sorted(HISTORY | DOTFILES | EXPECTED):
                consider(home / item, 'history' if item in HISTORY else 'dotfile')
            walk(home / '.config', 4, 'config')
            for root in [home / '.local/state', home / '.cache', home / '.codex', home / '.config/Cursor/logs', *log_dirs]:
                walk(root, 4, 'logs')
            for root in roots:
                walk(root, 6, 'env')
    except BudgetExceeded as exc:
        notes[exc.reason] += 1
    if boundary.seen_skips:
        notes['skipped_mount'] = len(boundary.seen_skips)
    return [targets[p] for p in sorted(targets)], dict(notes)


def is_binary(data):
    # Named databases are never opened. Disguised databases/compressed/binaries
    # are rejected after a bounded header read, without parsing their content.
    return (data.startswith((b'SQLite format 3\x00', b'\x1f\x8b', b'PK\x03\x04',
                             b'\xfd7zXZ\x00', b'BZh', b'\x7fELF', b'%PDF')) or
            b'\x00' in data or any(x < 9 or 13 < x < 32 for x in data[:8192]))


def bounded_scan_read(path, home, boundary=None, budget=None):
    """Read at most 8 KiB before rejecting identifiable non-text content.

    This scanner-only reader deliberately does not change config, key, baseline
    or receipt reading. Named databases are excluded before this function.
    """
    path = home_path(home, path)
    if boundary:
        boundary.check_path(path)
    parent = boundary.directory(path.parent) if boundary else directory_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            if boundary:
                boundary.check_fd(path, fd)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise SafeError('not a single-link regular file; not inspected')
            if before.st_size > MAX_BYTES:
                raise SafeError('over 10 MB; not inspected')
            data = bytearray()
            while len(data) < 8192:
                if budget:
                    budget.check()
                block = os.read(fd, 8192 - len(data))
                if not block:
                    break
                data.extend(block)
                if is_binary(data):
                    break
            if not is_binary(data):
                while len(data) <= MAX_BYTES:
                    if budget:
                        budget.check()
                    block = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
                    if not block:
                        break
                    data.extend(block)
            after = os.fstat(fd)
            if len(data) > MAX_BYTES:
                raise SafeError('over 10 MB; not inspected')
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise SafeError('changed during read; not inspected')
            return bytes(data), before, os.fstat(parent)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def scan(targets, home, store, budget=None, boundary=None):
    results = []
    notes = Counter()
    cleaner = Cleaner()
    total = 0
    budget = budget or Budget(MAX_SECONDS)
    boundary = boundary or ScanFS(home)
    try:
        with budget.phase():
            for target in targets:
                path = Path(target['path'])
                budget.check()
                if target['class'] == 'expected-store':
                    if len(results) >= MAX_FINDINGS:
                        raise BudgetExceeded('finding_budget')
                    mode = int(target['mode'], 8)
                    results.append({**target, 'line': None, 'rule_id': 'sweep.expected_store_mode',
                                    'secret_type': RULE_TYPES['sweep.expected_store_mode'],
                                    'severity': 'warn' if mode & ~0o600 else 'info',
                                    'fp': fingerprint(store.key, 'metadata:' + str(path)),
                                    'fp_kind': 'path', 'value': '<redacted>',
                                    'note': 'mode check only; credential contents not inspected'})
                    continue
                try:
                    if total + file_info(path, boundary).st_size > MAX_TOTAL:
                        raise BudgetExceeded('byte_budget')
                    data, info, _ = bounded_scan_read(path, home, boundary=boundary, budget=budget)
                except MountSkipped:
                    continue
                except SafeError:
                    notes['unreadable_changed_or_unsafe'] += 1
                    continue
                except OSError:
                    notes['unreadable_changed_or_unsafe'] += 1
                    continue
                total += len(data)
                if total > MAX_TOTAL:
                    raise BudgetExceeded('byte_budget')
                if is_binary(data):
                    notes['binary_database_or_compressed'] += 1
                    continue
                try:
                    text = data.decode('utf-8-sig')
                except UnicodeError:
                    notes['not_utf8_text'] += 1
                    continue
                for lineno, rule, label, value in matches(text):
                    budget.check()
                    if len(results) >= MAX_FINDINGS:
                        raise BudgetExceeded('finding_budget')
                    cleaner.values.add(value)
                    results.append({**target, 'mode': f'{stat.S_IMODE(info.st_mode):04o}',
                                    'line': lineno, 'rule_id': rule, 'secret_type': label,
                                    'severity': 'low' if rule == 'sweep.google_access_token' else 'warn',
                                    'fp': fingerprint(store.key, value), 'fp_kind': 'secret',
                                    'value': '<redacted>',
                                    'note': 'short-lived, likely expired; not validated' if rule == 'sweep.google_access_token' else 'live-looking shape; not validated'})
    except BudgetExceeded as exc:
        notes[exc.reason] += 1
    if boundary.seen_skips:
        notes['skipped_mount'] = len(boundary.seen_skips)
    return cleaner.clean(results), dict(notes), cleaner


def load_config(path, home, explicit=False):
    try:
        data, info, _ = bounded_read(absolute(path))
    except FileNotFoundError:
        if explicit:
            raise SafeError('configuration file not found')
        return {}
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
        raise SafeError('configuration must be owned by this user and mode 0600')
    cfg = tomllib.loads(data.decode())
    if not isinstance(cfg, dict):
        raise SafeError('invalid configuration')
    for field in ('roots', 'include', 'exclude', 'log_dirs', 'alert_channels'):
        if field in cfg and (not isinstance(cfg[field], list) or any(not isinstance(x, str) for x in cfg[field])):
            raise SafeError('configuration list has invalid values')
    if any(k in cfg for k in ('alert_slack_webhook', 'alert_ntfy_token', 'alert_smtp_password')):
        raise SafeError('alert secrets must use environment variable names')
    return cfg


def finding_identity(item):
    return tuple(item[field] for field in ('path', 'line', 'rule_id', 'fp', 'mode'))


def baseline_compare(path, findings, store):
    existing = None
    try:
        raw, info, _ = bounded_read(path)
    except FileNotFoundError:
        pass
    else:
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise SafeError('baseline must be owned by this user and mode 0600')
        existing = json.loads(raw)
        if (not isinstance(existing, dict) or existing.get('schema') != 'push-guard-sweep/1'
                or not isinstance(existing.get('findings'), list)):
            raise SafeError('invalid baseline; refused replacement')
        if existing.get('key_id') != fingerprint(store.key, 'push-guard-sweep-key-check'):
            raise SafeError('baseline fingerprint key differs; preserve and restore the original key')
        for item in existing['findings']:
            if not isinstance(item, dict) or any(k not in item for k in ('path', 'line', 'rule_id', 'fp', 'mode')):
                raise SafeError('invalid baseline finding')
    known = {finding_identity(item) for item in existing['findings']} if existing else set()
    new = [item for item in findings if finding_identity(item) not in known]
    document = {'schema': 'push-guard-sweep/1', 'key_id': fingerprint(store.key, 'push-guard-sweep-key-check'),
                'findings': [{k: item[k] for k in ('path', 'line', 'rule_id', 'fp', 'mode')} for item in findings]}
    return new, document


def render(report, fmt):
    if fmt == 'json':
        return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + '\n'
    lines = ['Push Guard Sweep', f"Findings: {len(report.get('findings', []))}; targets: {len(report.get('targets', []))}"]
    if report.get('incomplete'):
        lines.append('Inspection incomplete; retained results are partial.')
    if report.get('list_targets'):
        lines += [f"{item['path']} mode={item['mode']} class={item['class']} content={'read' if item['content_read'] else 'metadata only'} tracked=unknown" for item in report['targets']]
    for item in report.get('findings', []):
        lines.append(f"{item['path']}:{item['line'] or '-'} {item['rule_id']} type={item['secret_type']} class={item['class']} severity={item['severity']} mode={item['mode']} {item['fp']} fp_kind={item['fp_kind']} inside_git_repo={item['inside_git_repo']} tracked=unknown <redacted>; {item['note']}")
    if report.get('skipped'):
        lines.append('Skipped: ' + ', '.join(f'{key}={value}' for key, value in sorted(report['skipped'].items())))
    if report.get('findings'):
        lines.extend(HINTS)
    if report.get('alerts'):
        lines.append('Alerts: ' + json.dumps(report['alerts'], sort_keys=True))
    lines.extend(report.get('notes', []))
    if fmt == 'html':
        return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Push Guard Sweep</title><body><pre>' + html.escape('\n'.join(lines)) + '</pre></body></html>\n'
    if fmt == 'md':
        # HTML-escape raw source metadata and neutralize Markdown link syntax.
        return '# Push Guard Sweep\n\n' + '\n\n'.join(html.escape(line).replace('[', '&#91;').replace(']', '&#93;').replace('`', '&#96;') for line in lines[1:]) + '\n'
    return '\n'.join(lines) + '\n'


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SafeError('invalid sweep arguments; use --help')


def parser():
    p = Parser(prog='push-guard sweep', description=__doc__)
    p.add_argument('command', nargs='?', choices=['scan', 'report', 'print-timer'], default='scan')
    p.add_argument('--roots', nargs='+')
    p.add_argument('--include', action='append', default=[])
    p.add_argument('--exclude', action='append', default=[])
    p.add_argument('--class', dest='classification', choices=['stray', 'expected-store', 'all'], default='all')
    p.add_argument('--format', choices=['text', 'json', 'md', 'html'], default='text')
    p.add_argument('--output')
    p.add_argument('--baseline')
    p.add_argument('--send', action='store_true')
    p.add_argument('--config')
    p.add_argument('--list-targets', action='store_true')
    p.add_argument('--interval', default='7d')
    return p


def timer(interval):
    if not re.fullmatch(r'[1-9][0-9]{0,4}[smhdw]', interval):
        raise SafeError('invalid timer interval')
    return ('# push-guard-sweep.service\n[Unit]\nDescription=Local secrets-on-disk inspection\n'
            '[Service]\nType=oneshot\nUMask=0077\nExecStart=/usr/bin/env push-guard-sweep\n'
            'SuccessExitStatus=1\n\n# push-guard-sweep.timer\n[Unit]\nDescription=Run local sweep periodically\n'
            f'[Timer]\nOnBootSec=5m\nOnUnitActiveSec={interval}\nPersistent=true\n'
            'Unit=push-guard-sweep.service\n[Install]\nWantedBy=timers.target\n')


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        if args.output and args.baseline and absolute(args.output) == absolute(args.baseline):
            raise SafeError('output and baseline must be different files')
        if args.command == 'print-timer':
            if args.send or args.baseline or args.list_targets or args.output:
                raise SafeError('timer printing cannot be combined with scan or write options')
            print(timer(args.interval), end='')
            return 0
        home = absolute(os.environ.get('HOME', str(Path.home())))
        state = absolute(Path(os.environ.get('XDG_STATE_HOME', str(home / '.local/state'))) / 'push-guard-sweep')
        config_root = Path(os.environ.get('XDG_CONFIG_HOME', str(home / '.config')))
        config = absolute(args.config or config_root / 'push-guard-sweep/config.toml')
        if args.list_targets and (args.config or args.baseline or args.send or args.output):
            raise SafeError('list-targets permits no config content reads or writes; use CLI target options')
        budget = Budget(MAX_SECONDS)
        boundary = ScanFS(home)
        unavailable_home = boundary.unknown or boundary.home_remote
        if not args.list_targets and not unavailable_home:
            for destination in (state, config, args.output, args.baseline):
                if destination is not None:
                    path = absolute(destination)
                    if path.is_relative_to(home):
                        boundary.check_path(path)
        cfg = {} if args.list_targets or unavailable_home else load_config(config, home, explicit=bool(args.config))
        roots = [home_path(home, value) for value in (args.roots or cfg.get('roots') or [home])]
        logs = [home_path(home, value) for value in cfg.get('log_dirs', [])]
        excludes = args.exclude + cfg.get('exclude', [])
        includes = args.include + cfg.get('include', [])
        omitted = {state, config}
        for value in (args.output, args.baseline):
            if value:
                omitted.add(absolute(value))
        targets, skipped_counts = discover(home, roots, includes, excludes, logs, omitted, budget, boundary)
        targets = [t for t in targets if args.classification == 'all' or t['class'] == args.classification]
        report = {'findings': [], 'targets': [], 'skipped': skipped_counts, 'list_targets': args.list_targets,
                  'incomplete': False,
                  'notes': ['Git membership is inferred from .git markers; tracked status is unknown.']}
        budget_keys = ('entry_budget', 'time_budget', 'discovery_time_budget', 'target_budget', 'byte_budget', 'finding_budget', 'mount_metadata_unavailable')
        if args.list_targets:
            report['incomplete'] = any(skipped_counts.get(k) for k in budget_keys)
            report['targets'] = Cleaner().clean(targets)
            report['notes'].append('Default discovery and CLI options only; configuration contents were not read.')
            print(render(report, args.format), end='')
            return 2 if report['incomplete'] else 0
        store = None if unavailable_home else Store(state)
        if store is None:
            findings, skipped_reads, cleaner = [], {}, Cleaner()
        else:
            findings, skipped_reads, cleaner = scan(targets, home, store, budget, boundary)
        report['targets'] = cleaner.clean(targets)
        report['skipped'].update(skipped_reads)
        incomplete = unavailable_home or any(report['skipped'].get(k) for k in ('unreadable_metadata', 'unreadable_directory', 'unreadable_changed_or_unsafe', *budget_keys))
        report['incomplete'] = incomplete
        baseline = None
        if args.baseline and store is not None:
            findings, baseline = baseline_compare(absolute(args.baseline), findings, store)
        report['findings'] = findings
        if incomplete:
            report['notes'].append('Inspection incomplete; baseline was not updated.')
        if args.command == 'report':
            report['notes'].append('Fresh local scan; no historical scan results are retained by default.')
        baseline_text = json.dumps(baseline, indent=2, sort_keys=True) + '\n' if baseline is not None else None
        if baseline_text is not None and len(baseline_text.encode()) > MAX_BYTES:
            raise SafeError('baseline size budget exceeded; narrow roots')
        if args.send and store is not None:
            from .sweep_alerts import deliver
            report['alerts'] = deliver(cfg, store, findings)
        rendered = render(report, args.format)
        if args.output:
            write_private(absolute(args.output), rendered)
        if baseline is not None and not incomplete:
            write_private(absolute(args.baseline), baseline_text, replace=True)
        if not args.output:
            print(rendered, end='')
        if report.get('alerts', {}).get('failed') or incomplete:
            return 2
        return 1 if findings else 0
    except SafeError as exc:
        print('Push Guard Sweep: ' + str(exc), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        # Never echo exception strings, source text, CLI values or endpoint URLs.
        print('Push Guard Sweep could not complete safely; check arguments, permissions, budgets and configuration. No secret values are displayed.', file=sys.stderr)
        return 2
