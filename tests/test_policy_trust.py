"""Candidate content must not grant itself workflow exemptions."""
import io
import subprocess

import pytest
from push_guard.guard import main, load_committed_fixture_allow_list

RULE = 'workflow.shai_hulud_ssh_tmp'
MARKER = '/tmp/' + '.sshu-fixture'


@pytest.fixture
def repo(tmp_path, monkeypatch):
    def git(*args):
        return subprocess.run(['git', '-C', str(tmp_path), *args], check=True,
                              capture_output=True, text=True).stdout.strip()
    git('init', '-q')
    git('config', 'user.name', 'Dragon Lady')
    git('config', 'user.email', '268074749+Dragon-Lady@users.noreply.github.com')
    monkeypatch.setenv('PUSH_GUARD_INFER_IDENTITY', '0')
    return tmp_path, git


@pytest.mark.parametrize('policy_in_base', [False, True])
@pytest.mark.parametrize('commit_policy', [False, True])
def test_candidate_policy_cannot_approve_its_own_hit(repo, monkeypatch, capsys, policy_in_base, commit_policy):
    root, git = repo
    if policy_in_base:
        (root / '.push-guard-allow').write_text('other.py ' + RULE + '\n')
    git('add', '.')
    git('commit', '--allow-empty', '-qm', 'trusted base')
    base = git('rev-parse', 'HEAD')
    (root / 'fixture.py').write_text(MARKER)
    git('add', 'fixture.py')
    git('commit', '-qm', 'candidate content')
    (root / '.push-guard-allow').write_text('fixture.py ' + RULE + '\n')
    if commit_policy:
        git('add', '.')
        git('commit', '-qm', 'candidate exemption')
    head = git('rev-parse', 'HEAD')
    monkeypatch.setattr('sys.stdin', io.StringIO(f'refs/heads/main {head} refs/heads/main {base}\n'))
    assert main(['--repo', str(root), '--no-infer']) == 1
    assert RULE in capsys.readouterr().err
    assert main(['scan', '--repo', str(root), '--base', base, '--no-infer']) == 1
    assert RULE in capsys.readouterr().err


def test_trusted_base_policy_survives_dirty_worktree_and_requires_shared_multiref_trust(repo, monkeypatch, capsys):
    root, git = repo
    git('commit', '--allow-empty', '-qm', 'unapproved base')
    empty = git('rev-parse', 'HEAD')
    (root / '.push-guard-allow').write_text('fixture.py ' + RULE + '\n')
    git('add', '.')
    git('commit', '-qm', 'reviewed policy')
    base = git('rev-parse', 'HEAD')
    (root / 'fixture.py').write_text(MARKER)
    git('add', '.')
    git('commit', '-qm', 'fixture')
    head = git('rev-parse', 'HEAD')
    (root / '.push-guard-allow').write_text('')
    for second_base, expected in [(None, 0), (empty, 1), ('0' * 40, 1)]:
        refs = f'refs/heads/main {head} refs/heads/main {base}\n'
        if second_base is not None:
            refs += f'refs/heads/other {head} refs/heads/other {second_base}\n'
        monkeypatch.setattr('sys.stdin', io.StringIO(refs))
        assert main(['--repo', str(root), '--no-infer']) == expected
        capsys.readouterr()
    assert main(['scan', '--repo', str(root), '--base', base, '--no-infer']) == 0
    # A separately reviewed immutable snapshot can be selected explicitly when
    # auditing a larger historical range. No candidate policy is auto-trusted.
    assert main(['scan', '--repo', str(root), '--base', empty, '--allow-list-ref', base, '--no-infer']) == 0


def test_committed_policy_symlink_is_not_followed(repo):
    root, git = repo
    (root / 'policy-target').write_text('fixture.py ' + RULE + '\n')
    (root / '.push-guard-allow').symlink_to('policy-target')
    git('add', '.')
    git('commit', '-qm', 'symlink policy')
    assert load_committed_fixture_allow_list(root, 'HEAD') == {}
