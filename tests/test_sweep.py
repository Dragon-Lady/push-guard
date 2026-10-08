"""Fixture-only checks. Synthetic shapes are assembled at runtime."""
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess

import pytest

from push_guard import guard, sweep, sweep_alerts, sweep_safety

BODY = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY'
AWS_BODY = 'AB12CD34EF56GH78'
TOKENS = {
    'secret.github_token': 'gh' + 'p_' + BODY,
    'secret.github_fine_grained_token': 'github_' + 'pat_' + BODY,
    'secret.gitlab_incoming_email_token': 'gli' + 'mt-' + BODY[:25],
    'secret.openai_token': 's' + 'k-' + BODY,
    'secret.aws_access_key': 'A' + 'KIA' + AWS_BODY,
    'secret.private_key': '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----',
    'sweep.openai_extended': 's' + 'k-proj-' + BODY + '_' + BODY,
    'sweep.slack_token': 'xo' + 'xb-' + BODY,
    'sweep.slack_webhook': 'https://hooks.slack.com/' + 'services/T1A2B3/C4D5E6/' + BODY,
    'sweep.google_api_key': 'AI' + 'za' + BODY,
    'sweep.google_access_token': 'ya' + '29.' + BODY,
    'sweep.google_refresh_token': '1' + '//' + BODY,
    'sweep.npm_token': 'np' + 'm_' + BODY,
    'sweep.pypi_token': 'py' + 'pi-' + BODY,
    'sweep.jwt': 'ey' + 'JhbGciOiJIUzI1NiJ9.' + 'eyJzdWIiOiIxMjM0NTY3ODkwIn0.' + BODY,
    'sweep.url_credentials': 'https://operator:' + BODY + '@example.invalid',
    'sweep.generic_assignment': BODY + 'Z9',
}


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('XDG_STATE_HOME', str(home / '.local/state'))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(home / '.config'))
    return home


def write(home, relative, body, mode=0o600):
    path = home / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(mode)
    return path


def call(capsys, *args):
    code = sweep.main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def snapshot(path):
    info = path.stat()
    return hashlib.sha256(path.read_bytes()).hexdigest(), info.st_size, info.st_mtime_ns, info.st_mode, info.st_ino


@pytest.mark.parametrize('rule', TOKENS)
def test_every_provider_positive(rule, isolated_home, capsys):
    value = TOKENS[rule]
    text = ('API_TOKEN=' if rule == 'sweep.generic_assignment' else '') + value
    write(isolated_home, '.bash_history', text)
    code, out, err = call(capsys, '--format', 'json')
    result = json.loads(out)
    assert code == 1 and not err
    assert rule in {f['rule_id'] for f in result['findings']}
    assert value not in out
    finding = next(f for f in result['findings'] if f['rule_id'] == rule)
    assert finding['line'] == 1 and finding['class'] == 'stray'
    assert finding['fp'].startswith('fp:') and len(finding['fp']) == 19
    assert finding['value'] == '<redacted>'
    assert finding['tracked'] == 'unknown'


@pytest.mark.parametrize('prefix', ['gh' + 'p_', 'github_' + 'pat_', 's' + 'k-', 'A' + 'KIA',
                                   'xo' + 'xb-', 'AI' + 'za', 'ya' + '29.', '1' + '//',
                                   'np' + 'm_', 'py' + 'pi-'])
def test_provider_fillers_negative(prefix, isolated_home, capsys):
    write(isolated_home, '.bash_history', prefix + 'X' * 40)
    code, out, _ = call(capsys, '--format', 'json')
    assert code == 0
    assert json.loads(out)['findings'] == []


@pytest.mark.parametrize('value', ['xxx' * 10, '<replace-with-token>', '${MY_SUPER_SECRET_VARIABLE}',
                                 '$MY_SUPER_SECRET_VARIABLE', 'example' * 8, 'changeme' * 7,
                                 'dummy' * 9, 'A' * 32, 'aabb' * 9])
def test_generic_placeholders_negative(value, isolated_home, capsys):
    write(isolated_home, '.bash_history', 'API_KEY=' + value)
    assert call(capsys, '--format', 'json')[0] == 0


def test_provider_random_body_containing_test_is_not_suppressed(isolated_home, capsys):
    value = 'gh' + 'p_' + BODY + 'test' + BODY
    write(isolated_home, '.bash_history', value + ' # push-guard: ignore')
    code, out, _ = call(capsys, '--format', 'json')
    assert code == 1 and value not in out


@pytest.mark.parametrize('fmt', ['text', 'json', 'md', 'html'])
@pytest.mark.parametrize('command', ['scan', 'report'])
def test_canary_all_commands_formats_and_storage(command, fmt, isolated_home, capsys):
    canary = TOKENS['secret.github_token']
    write(isolated_home, '.bash_history', canary)
    # The same canary in metadata must be redacted too.
    write(isolated_home, canary + '/.env', 'TOKEN=' + canary)
    output = isolated_home / ('report.' + fmt)
    baseline = isolated_home / 'baseline.json'
    code, out, err = call(capsys, command, '--format', fmt, '--output', str(output), '--baseline', str(baseline), '--send')
    assert code == 1 and not out and not err
    assert canary not in output.read_text()
    assert canary not in baseline.read_text()
    state = isolated_home / '.local/state/push-guard-sweep'
    for path in [output, baseline, *state.iterdir()]:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert canary.encode() not in path.read_bytes()
    assert stat.S_IMODE(state.stat().st_mode) == 0o700


def test_list_targets_does_zero_content_reads_or_writes(isolated_home, monkeypatch, capsys):
    canary = TOKENS['secret.github_token']
    write(isolated_home, '.bash_history', canary)
    write(isolated_home, canary + '/.env', canary)
    real_open = os.open
    def no_content_open(path, flags, *args, **kwargs):
        assert flags & os.O_DIRECTORY
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, 'open', no_content_open)
    monkeypatch.setattr(os, 'read', lambda *a: pytest.fail('content read'))
    monkeypatch.setattr(Path, 'read_bytes', lambda *a: pytest.fail('content read'))
    code, out, err = call(capsys, '--list-targets', '--format', 'json')
    assert code == 0 and not err and canary not in out
    assert not (isolated_home / '.local').exists()
    assert len(json.loads(out)['targets']) == 2


def test_expected_store_mode_only_does_not_read_credentials(isolated_home, monkeypatch, capsys):
    path = write(isolated_home, '.netrc', TOKENS['secret.github_token'], 0o644)
    real_read = sweep.bounded_scan_read
    def spy(p, *args, **kwargs):
        assert Path(p) != path
        return real_read(p, *args, **kwargs)
    monkeypatch.setattr(sweep, 'bounded_scan_read', spy)
    code, out, _ = call(capsys, '--format', 'json', '--class', 'expected-store')
    item = json.loads(out)['findings'][0]
    assert code == 1 and item['class'] == 'expected-store' and item['severity'] == 'warn'
    assert item['line'] is None and item['fp_kind'] == 'path'
    assert item['content_read'] is False
    code, out, _ = call(capsys, '--class', 'stray', '--format', 'json')
    assert code == 0 and not json.loads(out)['findings']


def test_expected_private_store_informational(isolated_home, capsys):
    write(isolated_home, '.aws/credentials', TOKENS['secret.aws_access_key'])
    code, out, _ = call(capsys, '--format', 'json')
    assert code == 1 and json.loads(out)['findings'][0]['severity'] == 'info'


def test_git_marker_and_baseline_new_only(isolated_home, capsys):
    (isolated_home / 'repo/.git').mkdir(parents=True)
    path = write(isolated_home, 'repo/.env', TOKENS['secret.github_token'])
    baseline = isolated_home / 'baseline.json'
    code, out, _ = call(capsys, '--baseline', str(baseline), '--format', 'json')
    assert code == 1 and json.loads(out)['findings'][0]['inside_git_repo'] is True
    code, out, _ = call(capsys, '--baseline', str(baseline), '--format', 'json')
    assert code == 0 and not json.loads(out)['findings']
    path.write_text(TOKENS['secret.github_token'] + '\n' + TOKENS['sweep.npm_token'])
    code, out, _ = call(capsys, '--baseline', str(baseline), '--format', 'json')
    assert code == 1 and [f['rule_id'] for f in json.loads(out)['findings']] == ['sweep.npm_token']


def test_readonly_full_fixture_scan(isolated_home, capsys):
    paths = [write(isolated_home, name, TOKENS['secret.github_token']) for name in
             ['.bash_history', '.npmrc', '.env', '.local/state/logs/agent.log', '.cache/logs/run.log', '.config/tool/settings.json']]
    before = {p: snapshot(p) for p in paths}
    assert call(capsys, '--format', 'json')[0] == 1
    assert {p: snapshot(p) for p in paths} == before


def test_no_subprocess_and_no_network_without_send(isolated_home, monkeypatch, capsys):
    write(isolated_home, '.bash_history', TOKENS['secret.github_token'])
    monkeypatch.setattr(socket.socket, 'connect', lambda *a: pytest.fail('network'))
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: pytest.fail('child process'))
    monkeypatch.setattr(os, 'system', lambda *a: pytest.fail('shell'))
    assert guard.main(['sweep', '--format', 'json']) == 1
    assert 'fp:' in capsys.readouterr().out
    assert sweep.main(['--send']) == 1  # default stdout only
    assert 'Push Guard Sweep:' in capsys.readouterr().out


def test_html_and_terminal_path_escaping(isolated_home, capsys):
    write(isolated_home, '<script>alert(1)</script>/new\x1b[31m/.env', TOKENS['secret.github_token'])
    code, out, _ = call(capsys, '--format', 'html')
    assert code == 1
    assert '<script>' not in out and '&lt;script&gt;' in out
    assert '\x1b' not in out


def test_home_boundary_symlinks_hardlinks_fifo_binaries_and_sqlite(isolated_home, tmp_path, capsys, monkeypatch):
    outside = write(tmp_path, 'outside.log', TOKENS['secret.github_token'])
    (isolated_home / '.env-link').symlink_to(outside)
    (isolated_home / 'outside-dir').symlink_to(tmp_path, target_is_directory=True)
    os.link(outside, isolated_home / '.env-hardlink')
    os.mkfifo(isolated_home / '.env-fifo')
    write(isolated_home, '.config/fake.sqlite', TOKENS['secret.github_token'])
    disguised = isolated_home / '.env-binary'
    disguised.write_bytes(b'SQLite format 3\0' + TOKENS['secret.github_token'].encode())
    compressed = isolated_home / '.env-data.gz'
    compressed.write_bytes(TOKENS['secret.github_token'].encode())
    called = []
    real_read = sweep.bounded_scan_read
    def spy(p, *a, **kw):
        called.append(Path(p))
        return real_read(p, *a, **kw)
    monkeypatch.setattr(sweep, 'bounded_scan_read', spy)
    code, out, _ = call(capsys, '--include', '*', '--format', 'json')
    assert code == 0 and not json.loads(out)['findings']
    assert outside not in called and compressed not in called
    assert all(p.name not in {'.env-hardlink', '.env-link', '.env-fifo', 'fake.sqlite'} for p in called)
    assert call(capsys, '--roots', str(tmp_path), '--format', 'json')[0] == 2


def test_browser_and_keyring_paths_always_excluded(isolated_home, capsys):
    for name in ['.config/google-chrome/Default/logs/key.log', '.mozilla/firefox/.env',
                 '.local/share/keyrings/.env', '.cache/chromium/logs/a.log']:
        write(isolated_home, name, TOKENS['secret.github_token'])
    assert call(capsys, '--include', '*', '--format', 'json')[0] == 0


def test_size_limit_and_total_budget(isolated_home, monkeypatch, capsys):
    path = write(isolated_home, '.env-huge', TOKENS['secret.github_token'])
    with path.open('ab') as file:
        file.truncate(sweep.MAX_BYTES + 1)
    code, out, _ = call(capsys, '--format', 'json')
    assert code == 0 and json.loads(out)['skipped']['over_10_MB'] >= 1
    path.unlink()
    write(isolated_home, '.env', TOKENS['secret.github_token'])
    monkeypatch.setattr(sweep, 'MAX_TOTAL', 1)
    assert call(capsys, '--format', 'json')[0] == 2


def test_symlinked_parent_never_opened(isolated_home, tmp_path, capsys):
    outside = tmp_path / 'elsewhere'
    write(outside, 'tool/settings.json', TOKENS['secret.github_token'])
    (isolated_home / '.config').symlink_to(outside, target_is_directory=True)
    assert call(capsys, '--list-targets', '--format', 'json')[0] == 0
    assert call(capsys, '--format', 'json')[0] == 2


def test_private_files_created_at_0600_even_permissive_umask(isolated_home, monkeypatch, capsys):
    write(isolated_home, '.env', TOKENS['secret.github_token'])
    calls = []
    real_open = os.open
    real_mkdir = os.mkdir
    def spy_open(path, flags, mode=0o777, *args, **kwargs):
        if flags & os.O_CREAT:
            calls.append(('file', mode))
        return real_open(path, flags, mode, *args, **kwargs)
    def spy_mkdir(path, mode=0o777, *args, **kwargs):
        calls.append(('directory', mode))
        return real_mkdir(path, mode, *args, **kwargs)
    monkeypatch.setattr(os, 'open', spy_open)
    monkeypatch.setattr(os, 'mkdir', spy_mkdir)
    previous = os.umask(0)
    try:
        assert call(capsys, '--output', str(isolated_home / 'report'), '--baseline', str(isolated_home / 'baseline'))[0] == 1
    finally:
        os.umask(previous)
    assert calls and all(mode == (0o600 if kind == 'file' else 0o700) for kind, mode in calls)


def test_refuse_overwrite_source_or_symlink_output(isolated_home, tmp_path, capsys):
    source = write(isolated_home, '.bash_history', TOKENS['secret.github_token'])
    before = snapshot(source)
    assert call(capsys, '--output', str(source))[0] == 2
    assert snapshot(source) == before
    assert call(capsys, '--baseline', str(source))[0] == 2
    assert snapshot(source) == before
    link = isolated_home / 'report'
    link.symlink_to(source)
    assert call(capsys, '--output', str(link))[0] == 2
    assert snapshot(source) == before


def test_fingerprint_stable_and_keyed_and_replaced_key_refused(isolated_home, capsys):
    token = TOKENS['secret.github_token']
    write(isolated_home, '.env', token)
    baseline = isolated_home / 'baseline'
    _, out, _ = call(capsys, '--baseline', str(baseline), '--format', 'json')
    fp = json.loads(out)['findings'][0]['fp']
    _, out, _ = call(capsys, '--format', 'json')
    assert fp == json.loads(out)['findings'][0]['fp']
    assert fp != 'fp:' + hashlib.sha256(token.encode()).hexdigest()[:16]
    key = isolated_home / '.local/state/push-guard-sweep/fp.key'
    key.write_bytes(os.urandom(32))
    assert call(capsys, '--baseline', str(baseline))[0] == 2


def test_config_and_cli_discovery_excludes(isolated_home, capsys):
    write(isolated_home, 'custom/app.trace', TOKENS['secret.github_token'])
    write(isolated_home, 'custom/private.trace', TOKENS['secret.github_token'])
    config = write(isolated_home, '.config/push-guard-sweep/config.toml',
                   'include = ["*.trace"]\nexclude = ["private.trace"]\n')
    code, out, _ = call(capsys, '--config', str(config), '--format', 'json')
    assert code == 1 and len(json.loads(out)['findings']) == 1
    assert call(capsys, '--list-targets', '--config', str(config))[0] == 2
    config.chmod(0o644)
    assert call(capsys, '--config', str(config))[0] == 2


def test_timer_print_only_and_safe_errors(isolated_home, capsys):
    assert call(capsys, 'print-timer')[0] == 0
    assert not list(isolated_home.iterdir())
    canary = TOKENS['secret.github_token']
    code, out, err = call(capsys, 'print-timer', '--interval', canary)
    assert code == 2 and canary not in out + err
    code, out, err = call(capsys, '--class', canary)
    assert code == 2 and canary not in out + err


def test_alerts_aggregate_only_dedupe_and_failures(isolated_home, monkeypatch, capsys):
    token = TOKENS['secret.github_token']
    write(isolated_home, '.bash_history', token)
    cfg = write(isolated_home, '.config/push-guard-sweep/config.toml',
                'alert_channels = ["slack"]\nalert_slack_webhook_env = "SWEEP_TEST_WEBHOOK"\n')
    monkeypatch.setenv('SWEEP_TEST_WEBHOOK', 'https://hooks.slack.com/' + 'services/T1/C2/' + BODY)
    messages = []
    monkeypatch.setattr(sweep_alerts, 'send_one', lambda channel, cfg, message: messages.append(message))
    assert call(capsys, '--config', str(cfg), '--send')[0] == 1
    assert len(messages) == 1
    assert token not in messages[0] and str(isolated_home) not in messages[0] and '.bash_history' not in messages[0]
    assert 'secret.github_token=1' in messages[0]
    assert messages[0].endswith('run `push-guard-sweep report` locally for details')
    assert call(capsys, '--config', str(cfg), '--send')[0] == 1
    assert len(messages) == 1
    monkeypatch.setenv('SWEEP_TEST_WEBHOOK', 'https://hooks.slack.com/' + 'services/T3/C4/' + BODY)
    def fail(*a):
        raise OSError(token)
    monkeypatch.setattr(sweep_alerts, 'send_one', fail)
    code, out, err = call(capsys, '--config', str(cfg), '--send')
    assert code == 2 and token not in out + err


@pytest.mark.parametrize('url', ['http://example.invalid/a', 'https://operator:password@example.invalid/a',
                               'file:///tmp/secret', 'https://example.invalid/#fragment'])
def test_alert_endpoints_reject_unsafe(url):
    with pytest.raises(sweep_safety.SafeError):
        sweep_alerts.endpoint(url)


def test_alert_timeout_and_no_redirects(monkeypatch):
    calls = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size): calls.append(size)
    class Opener:
        def open(self, request, timeout):
            calls.append(timeout)
            return Response()
    monkeypatch.setattr(sweep_alerts, 'build_opener', lambda handler: Opener())
    sweep_alerts.post('https://example.invalid/alerts', b'aggregate', {})
    assert calls == [5, 1024]
    assert sweep_alerts.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.invalid') is None


def test_complete_private_keys_fingerprint_material_not_marker(isolated_home, capsys):
    begin = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----\n'
    end = '\n-----END ' + 'OPENSSH PRIVATE KEY-----'
    body = BODY * 3
    path = write(isolated_home, '.bash_history', begin + body + end)
    _, out, _ = call(capsys, '--format', 'json')
    first = json.loads(out)['findings']
    assert len(first) == 1 and body not in out
    path.write_text(begin + body[::-1] + end)
    _, out, _ = call(capsys, '--format', 'json')
    second = json.loads(out)['findings']
    assert len(second) == 1 and first[0]['fp'] != second[0]['fp']


def test_partial_scan_does_not_replace_baseline(isolated_home, monkeypatch, capsys):
    path = write(isolated_home, '.env', TOKENS['secret.github_token'])
    baseline = isolated_home / 'baseline'
    assert call(capsys, '--baseline', str(baseline))[0] == 1
    before = snapshot(baseline)
    real_read = sweep.bounded_scan_read
    def broken(p, *a, **kw):
        if Path(p) == path:
            raise OSError('fixture unavailable')
        return real_read(p, *a, **kw)
    monkeypatch.setattr(sweep, 'bounded_scan_read', broken)
    assert call(capsys, '--baseline', str(baseline))[0] == 2
    assert snapshot(baseline) == before


def test_xdg_config_and_state_outside_home_are_tool_owned_not_scan_roots(isolated_home, tmp_path, monkeypatch, capsys):
    config_root = tmp_path / 'xdg-config'
    state_root = tmp_path / 'xdg-state'
    monkeypatch.setenv('XDG_CONFIG_HOME', str(config_root))
    monkeypatch.setenv('XDG_STATE_HOME', str(state_root))
    write(config_root, 'push-guard-sweep/config.toml', 'alert_channels = []\n')
    write(isolated_home, '.env', TOKENS['secret.github_token'])
    assert call(capsys, '--format', 'json')[0] == 1
    assert (state_root / 'push-guard-sweep/fp.key').is_file()


def test_fixture_depth_limits(isolated_home, capsys):
    write(isolated_home, 'a/b/c/d/e/f/g/.env', TOKENS['secret.github_token'])
    write(isolated_home, '.config/a/b/c/d/e/config.json', TOKENS['secret.github_token'])
    assert call(capsys, '--format', 'json')[0] == 0


@pytest.mark.parametrize('list_only', [False, True])
def test_encoded_filename_canary_is_not_recoverable(isolated_home, capsys, list_only):
    token = TOKENS['secret.github_token']
    encoded = token.replace('_', '%5F')
    write(isolated_home, encoded + '/.env', token)
    arguments = ['--format', 'json'] + (['--list-targets'] if list_only else [])
    code, out, err = call(capsys, *arguments)
    assert code == (0 if list_only else 1)
    assert token not in out + err and encoded not in out + err
    assert '<redacted encoded path>' in out


@pytest.mark.parametrize('value', ['gli' + 'mt-' + 'X' * 25, 's' + 'k-proj-' + 'X' * 40,
                                  'https://hooks.slack.com/' + 'services/XXXX/XXXX/XXXX',
                                  'https://operator:dummy@example.invalid',
                                  'ey' + 'Jaaa.bbb.ccc'])
def test_remaining_placeholder_shapes(value, isolated_home, capsys):
    write(isolated_home, '.bash_history', value)
    assert call(capsys, '--format', 'json')[0] == 0


def test_incomplete_private_key_fingerprints_material(isolated_home, capsys):
    header = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----\n'
    source = write(isolated_home, '.bash_history', header + BODY)
    _, out, _ = call(capsys, '--format', 'json')
    before = json.loads(out)['findings'][0]['fp']
    source.write_text(header + BODY[::-1])
    _, out, _ = call(capsys, '--format', 'json')
    assert before != json.loads(out)['findings'][0]['fp']


def test_finding_budget_fails_before_unbounded_output(isolated_home, capsys, monkeypatch):
    write(isolated_home, '.env', TOKENS['secret.github_token'] + '\n' + TOKENS['sweep.npm_token'])
    monkeypatch.setattr(sweep, 'MAX_FINDINGS', 1)
    code, out, err = call(capsys, '--format', 'json')
    report = json.loads(out)
    assert code == 2 and not err and report['incomplete']
    assert report['skipped']['finding_budget'] == 1 and len(report['findings']) == 1


@pytest.mark.parametrize('fmt', ['text', 'json', 'md', 'html'])
def test_list_and_timer_formats_have_no_canary_or_writes(isolated_home, capsys, fmt):
    token = TOKENS['secret.github_token']
    write(isolated_home, token + '/.env', token)
    for args in [('--list-targets', '--format', fmt), ('print-timer', '--format', fmt)]:
        code, out, err = call(capsys, *args)
        assert code == 0 and token not in out + err
    assert not (isolated_home / '.local').exists()


def test_output_and_baseline_cannot_share_destination(isolated_home, capsys):
    path = isolated_home / 'result'
    code, out, err = call(capsys, '--output', str(path), '--baseline', str(path))
    assert code == 2 and not path.exists() and not (isolated_home / '.local').exists()


@pytest.mark.parametrize('header', [b'SQLite format 3\0', b'\x1f\x8b', b'PK\x03\x04',
                                    b'\xfd7zXZ\x00', b'BZh', b'\x7fELF', b'%PDF', b'\x00', b'\x01'])
def test_disguised_binary_header_stops_source_reads_at_8k(isolated_home, capsys, monkeypatch, header):
    import sqlite3
    path = isolated_home / '.env-disguised'
    body = header + b'A' * (2 * 1024 * 1024) + TOKENS['secret.github_token'].encode()
    path.write_bytes(body)
    path.chmod(0o600)
    opened = set()
    sizes = []
    real_open, real_read, real_close = os.open, os.read, os.close
    def spy_open(name, flags, *args, **kwargs):
        fd = real_open(name, flags, *args, **kwargs)
        if str(name) == path.name and not flags & os.O_DIRECTORY:
            opened.add(fd)
        return fd
    def spy_read(fd, limit):
        if fd in opened:
            assert not sizes, 'a second read was attempted after identifiable binary magic'
            assert limit <= 8192
        data = real_read(fd, limit)
        if fd in opened:
            sizes.append(len(data))
        return data
    def spy_close(fd):
        opened.discard(fd)
        return real_close(fd)
    monkeypatch.setattr(os, 'open', spy_open)
    monkeypatch.setattr(os, 'read', spy_read)
    monkeypatch.setattr(os, 'close', spy_close)
    monkeypatch.setattr(sqlite3, 'connect', lambda *a, **k: pytest.fail('SQLite original inspection'))
    code, out, err = call(capsys, '--format', 'json')
    assert code == 0 and not err and sizes == [8192]
    assert json.loads(out)['skipped']['binary_database_or_compressed'] == 1
    assert TOKENS['secret.github_token'] not in out
    assert path.read_bytes() == body


def test_binary_header_change_does_not_truncate_state_reads(isolated_home):
    path = isolated_home / 'state-file'
    payload = b'\0' + b'A' * 20000
    path.write_bytes(payload)
    path.chmod(0o600)
    assert sweep_safety.bounded_read(path)[0] == payload
