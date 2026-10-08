"""Fixture-only acceptance regressions for bounded local discovery."""
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from push_guard import sweep, sweep_boundary as boundary, sweep_safety

BODY = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY'
TOKEN = 'gh' + 'p_' + BODY


@pytest.fixture
def home(tmp_path, monkeypatch):
    path = tmp_path / 'home'
    path.mkdir(mode=0o700)
    monkeypatch.setenv('HOME', str(path))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(path / '.config'))
    monkeypatch.setenv('XDG_STATE_HOME', str(path / '.local/state'))
    return path


def put(home, name, value=TOKEN):
    path = home / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    return path


def run(capsys, *args):
    code = sweep.main(['--format', 'json', *args])
    captured = capsys.readouterr()
    assert not captured.err and TOKEN not in captured.out
    return code, json.loads(captured.out)


def test_entry_exhaustion_returns_partial_and_preserves_baseline(home, monkeypatch, capsys):
    put(home, '.bash_history')
    for i in range(5):
        put(home, f'project-{i}/.env')
    baseline = home / 'baseline'
    assert run(capsys, '--baseline', str(baseline))[0] == 1
    saved = baseline.read_bytes()
    monkeypatch.setattr(sweep, 'MAX_ENTRIES', 2)
    code, report = run(capsys, '--baseline', str(baseline))
    assert code == 2 and report['incomplete']
    assert report['skipped']['entry_budget'] == 1 and report['targets']
    assert baseline.read_bytes() == saved
    code, report = run(capsys, '--list-targets')
    assert code == 2 and report['incomplete'] and report['targets']


def test_target_exhaustion_keeps_bounded_partial_report(home, monkeypatch, capsys):
    put(home, '.bash_history')
    put(home, '.zsh_history')
    monkeypatch.setattr(sweep, 'MAX_FILES', 1)
    code, report = run(capsys)
    assert code == 2 and report['incomplete']
    assert report['skipped']['target_budget'] == 1
    assert len(report['targets']) == len(report['findings']) == 1


def test_byte_exhaustion_keeps_prior_findings(home, monkeypatch, capsys):
    put(home, '.bash_history')
    put(home, '.zsh_history')
    monkeypatch.setattr(sweep, 'MAX_TOTAL', len(TOKEN) + 1)
    code, report = run(capsys)
    assert code == 2 and report['incomplete']
    assert report['skipped']['byte_budget'] == 1 and len(report['findings']) == 1


@pytest.mark.parametrize('fmt', ['text', 'md', 'html'])
def test_partial_status_visible_in_human_formats(home, monkeypatch, capsys, fmt):
    put(home, '.env')
    monkeypatch.setattr(sweep, 'MAX_TOTAL', 1)
    assert sweep.main(['--format', fmt]) == 2
    captured = capsys.readouterr()
    assert 'Inspection incomplete' in captured.out and TOKEN not in captured.out


def test_shared_deadline_covers_discovery_and_scanning(home, monkeypatch):
    put(home, '.bash_history')
    clock = [100.0]
    monkeypatch.setattr(boundary.time, 'monotonic', lambda: clock[0])
    budget = boundary.Budget(45)
    fs = boundary.ScanFS(home)
    targets, notes = sweep.discover(home, [home], [], [], [], set(), budget, fs)
    assert targets and not notes
    clock[0] = 145.0
    store = sweep_safety.Store(home / 'state')
    findings, notes, _ = sweep.scan(targets, home, store, budget, fs)
    assert findings == [] and notes == {'time_budget': 1}


def test_timer_interrupts_slow_match_and_returns_partial(home, monkeypatch, capsys):
    put(home, '.bash_history')
    real = sweep.matches
    def slow(text):
        if text == TOKEN:
            time.sleep(1)
        yield from real(text)
    monkeypatch.setattr(sweep, 'matches', slow)
    monkeypatch.setattr(sweep, 'MAX_SECONDS', 0.1)
    started = time.monotonic()
    code, report = run(capsys)
    assert time.monotonic() - started < 0.8
    assert code == 2 and report['incomplete'] and report['skipped']['time_budget']


def test_timer_interrupts_slow_discovery_and_returns_partial(home, monkeypatch, capsys):
    put(home, '.bash_history')
    real = os.scandir
    def slow(fd):
        time.sleep(1)
        return real(fd)
    monkeypatch.setattr(os, 'scandir', slow)
    monkeypatch.setattr(sweep, 'MAX_SECONDS', 0.1)
    started = time.monotonic()
    code, report = run(capsys)
    assert time.monotonic() - started < 0.8
    assert code == 2 and report['incomplete'] and report['targets']


@pytest.mark.parametrize('name', sorted(sweep.PRUNE_PATHS | sweep.PRUNE_DIRS))
def test_heavy_directories_never_listed_even_if_explicit_root(home, monkeypatch, capsys, name):
    root = home / name
    put(root, '.env')
    real = os.scandir
    def guarded(fd):
        info = os.fstat(fd)
        assert (info.st_dev, info.st_ino) != (root.stat().st_dev, root.stat().st_ino)
        return real(fd)
    monkeypatch.setattr(os, 'scandir', guarded)
    code, report = run(capsys, '--roots', str(root), '--include', '*')
    assert code == 0 and not report['findings']


def test_more_than_old_30000_entry_budget_completes(home, capsys):
    root = home / 'project'
    root.mkdir()
    for index in range(30_050):
        (root / f'item-{index}').touch()
    put(root, '.env')
    code, report = run(capsys)
    assert code == 1 and not report['incomplete'] and len(report['findings']) == 1


@pytest.mark.parametrize('filesystem', ['ext4', 'fuse.rclone', 'nfs', 'cifs'])
@pytest.mark.parametrize('target', ['mounted tree', '.env-mounted-file'])
def test_known_mounts_rejected_before_stat_or_open(home, monkeypatch, capsys, filesystem, target):
    mounted = home / target
    if target.startswith('.env'):
        put(home, target)
    else:
        put(mounted, '.env')
    real_records = boundary.mount_records()
    monkeypatch.setattr(boundary, 'mount_records', lambda: [*real_records, (999999, mounted, filesystem)])
    real_stat, real_open = os.stat, os.open
    def checked_path(path, kwargs):
        if isinstance(path, int):
            return None
        path = Path(path)
        if not path.is_absolute() and kwargs.get('dir_fd') is not None:
            path = Path(os.readlink(f"/proc/self/fd/{kwargs['dir_fd']}")) / path
        return path
    def guarded_stat(path, *args, **kwargs):
        checked = checked_path(path, kwargs)
        assert checked is None or not checked.is_relative_to(mounted)
        return real_stat(path, *args, **kwargs)
    def guarded_open(path, *args, **kwargs):
        checked = checked_path(path, kwargs)
        assert checked is None or not checked.is_relative_to(mounted)
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(os, 'stat', guarded_stat)
    monkeypatch.setattr(os, 'open', guarded_open)
    code, report = run(capsys)
    assert code == 0 and not report['findings'] and report['skipped']['skipped_mount'] == 1


def test_changed_device_is_rejected(home):
    fs = boundary.ScanFS(home)
    with pytest.raises(boundary.MountSkipped):
        fs.check_stat(home / 'mounted', SimpleNamespace(st_dev=fs.device + 1))
    assert fs.seen_skips == {home / 'mounted'}


def test_same_device_bind_replacement_read_never_occurs(home, monkeypatch, capsys):
    path = put(home, '.env')
    source_inode = path.stat().st_ino
    real_id = boundary.fd_mount_id
    real_read = os.read
    def changed_id(fd):
        original = real_id(fd)
        return original + 1 if os.fstat(fd).st_ino == source_inode else original
    def guarded_read(fd, n):
        assert os.fstat(fd).st_ino != source_inode
        return real_read(fd, n)
    monkeypatch.setattr(boundary, 'fd_mount_id', changed_id)
    monkeypatch.setattr(os, 'read', guarded_read)
    code, report = run(capsys)
    assert code == 0 and report['skipped']['skipped_mount'] == 1 and not report['findings']


def test_mountinfo_unavailable_returns_incomplete_without_target_reads(home, monkeypatch, capsys):
    put(home, '.bash_history')
    def unavailable():
        raise PermissionError('fixture')
    def no_read(*args, **kwargs):
        raise AssertionError('target read while mount state unknown')
    monkeypatch.setattr(boundary, 'mount_records', unavailable)
    monkeypatch.setattr(sweep, 'bounded_scan_read', no_read)
    code, report = run(capsys)
    assert code == 2 and report['incomplete'] and not report['targets']
    assert report['skipped']['mount_metadata_unavailable'] == 1


@pytest.mark.parametrize('filesystem', ['fuse.rclone', 'nfs4', 'cifs', 'autofs'])
def test_remote_home_is_never_opened(home, monkeypatch, capsys, filesystem):
    monkeypatch.setattr(boundary, 'mount_records', lambda: [(1, Path('/'), 'ext4'), (2, home, filesystem)])
    def no_directory(*args):
        raise AssertionError('remote HOME opened')
    monkeypatch.setattr(boundary, 'directory_fd', no_directory)
    code, report = run(capsys, '--list-targets')
    assert code == 0 and report['skipped']['skipped_mount'] == 1 and not report['targets']


def test_mountinfo_octal_paths_and_same_device_mounts(monkeypatch):
    import builtins
    import io
    data = b'14 1 8:1 / / rw - ext4 /dev/disk rw\n15 14 8:1 / /home/person/mounted\\040tree rw - ext4 /dev/disk rw\n'
    original = builtins.open
    monkeypatch.setattr(builtins, 'open', lambda p, *a, **k: io.BytesIO(data) if p == '/proc/self/mountinfo' else original(p, *a, **k))
    assert boundary.mount_records()[1] == (15, Path('/home/person/mounted tree'), 'ext4')


def test_remote_home_default_scan_reads_no_config_or_state(home, monkeypatch, capsys):
    monkeypatch.setattr(boundary, 'mount_records', lambda: [(1, Path('/'), 'ext4'), (2, home, 'fuse.rclone')])
    def forbidden(*args, **kwargs):
        raise AssertionError('remote config/state accessed')
    monkeypatch.setattr(sweep, 'load_config', forbidden)
    monkeypatch.setattr(sweep, 'Store', forbidden)
    code, report = run(capsys)
    assert code == 2 and report['incomplete'] and report['skipped']['skipped_mount'] == 1
    assert not (home / '.local').exists()


def test_discovery_timeout_reserves_time_for_already_found_history(home, monkeypatch, capsys):
    put(home, '.bash_history')
    original = os.scandir
    def slow(fd):
        time.sleep(0.5)
        return original(fd)
    monkeypatch.setattr(os, 'scandir', slow)
    monkeypatch.setattr(sweep, 'MAX_DISCOVERY_SECONDS', 0.05)
    monkeypatch.setattr(sweep, 'MAX_SECONDS', 1)
    code, report = run(capsys)
    assert code == 2 and report['incomplete']
    assert report['skipped']['discovery_time_budget'] == 1
    assert len(report['findings']) == 1


def test_same_device_directory_bind_replacement_is_never_listed(home, monkeypatch, capsys):
    folder = home / 'project'
    put(folder, '.env')
    inode = folder.stat().st_ino
    real_id, real_scan = boundary.fd_mount_id, os.scandir
    def changed_id(fd):
        original = real_id(fd)
        return original + 1 if os.fstat(fd).st_ino == inode else original
    def guarded_scan(fd):
        assert os.fstat(fd).st_ino != inode
        return real_scan(fd)
    monkeypatch.setattr(boundary, 'fd_mount_id', changed_id)
    monkeypatch.setattr(os, 'scandir', guarded_scan)
    code, report = run(capsys)
    assert code == 0 and not report['findings'] and report['skipped']['skipped_mount'] == 1


@pytest.mark.parametrize('folder', ['.config', '.local/state'])
def test_tool_state_and_config_do_not_cross_known_home_mounts(home, monkeypatch, capsys, folder):
    records = boundary.mount_records()
    monkeypatch.setattr(boundary, 'mount_records', lambda: [*records, (999999, home / folder, 'fuse.rclone')])
    def forbidden(*args, **kwargs):
        raise AssertionError('mounted config/state accessed')
    monkeypatch.setattr(sweep, 'load_config', forbidden)
    monkeypatch.setattr(sweep, 'Store', forbidden)
    assert sweep.main(['--format', 'json']) == 2
    output = capsys.readouterr()
    assert 'filesystem boundary' in output.err and not output.out
    assert not (home / '.local').exists()
