# Push Guard — project memory

Local-only Git `pre-push` guard. Two threat models in one scanner:
1. **Secret leak** (outbound): GitHub/OpenAI/AWS token shapes, private-key
   blocks, generic long `secret=`/`api_key=` assignments. Redacts all evidence.
2. **Self-propagation worm** (incoming malicious code): `malware.worm_propagation`.

No network, no telemetry. Findings carry only rule id, path, line, reason, and
redacted/category evidence.

## Worm heuristic (added on branch `claude/code-security-review-m1KeN`)

Behavioral, NOT signature-based. Fires only when **>= 2 distinct signal
categories co-occur in one added file** (`WORM_MIN_SIGNALS`, `WORM_SIGNALS` in
`src/push_guard/guard.py`):
`ssh_key_material`, `process_spawn`, `repo_propagation` (enumerate-and-push, not
bare `git push`), `network_exfil` (outbound destination, not just reading env),
`temp_drop`, `hook_install` (package.json lifecycle / husky / `core.hooksPath`;
`.git/hooks/*` is untracked so it never reaches a push diff).

Keyed on behavior so renamed Shai-Hulud variants still match. Prose docs
(`.md/.rst/.txt/...`, `DOC_SUFFIXES`) are skipped so an advisory documenting an
IOC like `/tmp/.sshu-*` is never blocked.

## Enable (run on the real dev machine — NOT in an ephemeral web session)

```sh
pip install -e .            # or: pip install push-guard
python -m push_guard install --repo .          # add --force to refresh
```

## Test / verify

```sh
python -m unittest discover -s tests           # 24 tests, all passing
```

## Optional: server-side PR review (Anthropic's action)

Complements push-guard. Push Guard is a *local pre-push* seatbelt; Anthropic's
`claude-code-security-review` is a *server-side PR* reviewer that posts inline
findings. Use both: local catches it before it leaves the machine, CI catches
what bypassed the hook.

`.github/workflows/security.yml`:

```yaml
name: Security Review
on: pull_request
permissions:
  contents: read
  pull-requests: write          # needed to post inline findings
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2         # diff needs the PR base
      - uses: anthropics/claude-code-security-review@main
        with:
          comment-pr: true
          claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
```

Setup: add repo secret `CLAUDE_API_KEY` (key needs Code tool access).
Default model `claude-opus-4-1-20250805`; supports custom org rules and
excluded dirs. **Caveat: not hardened against prompt injection** — only run on
trusted PRs; enable "Require approval for all external contributors" so a forked
PR can't run it with a malicious diff.

## Open follow-ups

- **Sync gap was the headline finding:** the SSH heuristic previously lived only
  on the Windows editable install (`C:\Users\tanya\push-guard`) and was never in
  git — the branch was identical to `main`. This branch is now the source of
  truth. Diff any local-only tuning against commit `bb714c6` and land it here;
  do not let the local copy drift again.
- **`HereWeGoAgain`** (separate repo, not in this checkout): run its smoke
  fixture (`ai_setup.sh`, `ai_init.js`, `infectHost`, `Bun.spawnSync`) and
  consider porting the same `hook_install` signal. Not reviewable from here.
- **False-positive watch:** a legit deploy doing `process_spawn` +
  `repo_propagation` together would trip the worm rule. Confirm against real
  repos before making it a hard CI block; consider a non-blocking warn tier.
