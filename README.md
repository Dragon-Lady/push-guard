# Push Guard

Push Guard is a local Git `pre-push` guard for likely secret leaks.

It scans the content being pushed, reports likely secret patterns, redacts all
matched values, and exits nonzero so Git blocks the push.

> Built and maintained by Dragon Lady - [github.com/Dragon-Lady](https://github.com/Dragon-Lady) - X: [@answerislove2](https://x.com/answerislove2)

## Website

Public landing page: [push-guard.netlify.app](https://push-guard.netlify.app/)

The static project landing page lives in [`docs/`](docs/) and has no runtime
dependencies, external scripts, analytics, or remote assets. It can be served
with GitHub Pages from the `docs/` directory or deployed to Netlify using the
included `netlify.toml` (no build command; publish directory `docs`).

## Posture

- Local only.
- No network calls.
- No package installs.
- No target file mutation.
- No secret values printed.
- No tokens, keys, secrets, credentials, file contents, repository contents, or
  user data are saved by Push Guard.
- Findings store only rule IDs, file paths, line numbers, reasons, and the
  literal placeholder `<redacted>`.
- Uses the `git` subprocess only to read commit diffs, pushed trees, configured
  hook paths, and ignore metadata.
- No mutation through Git and no other subprocess execution.
- No claim that a repository is clean.

Blocking a push is Git's response to the advisory. Push Guard remains read-only
and does not mutate files. Override is available with `git push --no-verify`
when the matched value is known not to be a secret.

Push Guard does not send data to any service. It does not phone home, collect
telemetry, upload reports, write scan results by default, or retain copies of
matched values.

## Current Signals

- GitHub classic token prefixes: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
- GitHub fine-grained token prefix: `github_pat_`
- OpenAI-style `sk-...` tokens
- AWS access key IDs: `AKIA...` / `ASIA...`
- private key block markers
- generic long `api_key`, `token`, `secret`, or `password` assignments,
  including underscore/dash-delimited names such as `AWS_SECRET_ACCESS_KEY`
- Astro config loader/C2 patterns in `astro.config.*` and related
  `.gitignore` helper-artifact hiding, based on reported config-as-code
  supply-chain abuse
- OpenClaw dependency versions before `2026.4.23` and risky OpenClaw
  open-DM/wildcard/unsandboxed configuration lines
- Agentjacking-style Sentry MCP wiring and fake Sentry resolution text that
  tries to make coding agents run `npx` diagnostics
- known compromised npm package names in dependency metadata, including
  `atomic-lockfile` and `ecto-flag-read`
- July 2026 malicious npm names and exact compromised `jscrambler`, Injective,
  and payment-SDK versions, plus reverse-shell shapes embedded directly in
  package manifest lifecycle scripts
- August 4, 2026 keyv / cacheable (ChainDrop / Shai-Hulud) **exact** seed versions
  only (`keyv@6.0.0` and ten related jaredwray-family releases verified by Snyk,
  StepSecurity, Aikido, Wiz, and JFrog). Does not block all versions of those
  package names; full campaign inventory is larger (Ox / Wiz)
- AtomicArch/IronWorm-style AUR `PKGBUILD`, `.SRCINFO`, or `.install` metadata
  that references `atomic-lockfile` or invokes npm/npx loaders for it
- DPRK/Famous Chollima-style npm loader behavior using Socket.IO,
  `/api/service`, `0001.dat`, and Node execution paths
- model-scanner refusal/null-result bait in executable package diffs, following
  JFrog's Shai-Hulud prompt-injection-vs-scanner writeup
- the same refusal-bait signals in repo-local agent instruction paths reported
  as promptware targets: `.cursorrules`, `.windsurfrules`, `.cursor/rules/`, and
  `.github/copilot-instructions.md`; ordinary Markdown incident notes remain
  excluded
- Microsoft Copilot / AI-assistant `q=` links in executable/web/config diffs
  that combine private-context requests with external exfiltration terms
- npm v12 readiness regressions in pushed npm metadata, including old npm pins,
  Git or remote tarball dependency sources, and broad repo `.npmrc` opt-ins for
  install-time execution or dependency fetching

All evidence is redacted as `<redacted>`.

## Private Path Rules

Some leaks are not token-shaped. A private handoff lane, a team note, or a
credential vault carries no secret *pattern* in its body, yet pushing it is
still a leak. Push Guard also blocks a push when the pushed tree contains a file
whose **path** is private.

It checks the pushed tip tree (not just the diff), so a file that should never
have been tracked is flagged on every push until it is removed -- not only on
the commit that first added it.

Generic defaults are matched by basename at any depth: `*.kdbx`, `*.pem`,
`id_rsa`, `id_ed25519`, `.env`, `.env.*`, `*_keys.json`, `credentials.json`,
`.npmrc`.

Add your own patterns in a local, **git-ignored** file at the repo root named
`.push-guard-private-paths` -- one pattern per line, `#` for comments. Keeping
your private directory and file names in this local file (and out of version
control) means the names themselves are never committed or pushed:

```
# directory anywhere in the tree
internal-handoff/
# basename globs
*_NOTES.md
*INTERNAL*
```

Match rules: a trailing-slash pattern matches that directory anywhere; a glob
(`*`, `?`, `[`) matches the full path and the basename; a plain token matches an
exact basename or path segment.

A file that is **gitignored** but still present in the pushed tree (force-add)
is also blocked (`private_path.gitignored`).

## Personal / house terms (local list)

Token shapes miss a name in a README. Keep a **git-ignored** list of terms:

- repo: `.push-guard-blocked-terms`
- user: `~/.config/push-guard/blocked-terms`

One term per line. Added diff lines are scanned; matches are reported as
`<redacted>`. Those names stay off PyPI and off git. Use
`# push-guard: ignore` on a line that must keep a term.

The marker can suppress local blocked-term and workflow/IOC findings, but it
does **not** suppress provider token shapes or generic secret assignments. A
comment must not turn a credential into an allowed value.

```
# .push-guard-blocked-terms  (gitignored)
house-given-name
seat-nickname
```

## Install

```sh
pip install push-guard
```

## Install A Repo Hook

Install per repository. Do not install globally.

From the specific repository you want to protect:

```sh
cd /path/to/that/repo
push-guard install
```

Or pass the repository path explicitly:

```sh
push-guard install --repo /path/to/that/repo
```

Push Guard refuses to install into your user home directory by default, even if
your home directory is itself a Git repository. Use `--allow-home-repo` only when
you intentionally want one broad hook at the home-repo level.

If a `pre-push` hook already exists, Push Guard refuses to overwrite it. Preserve
and chain existing hooks intentionally, or rerun with `--force` only when you are
refreshing a Push Guard-managed hook. Installation honors Git's configured
`core.hooksPath` as well as the default `.git/hooks` directory.

Manual hook body, for teams that prefer to wire hooks themselves:

```sh
#!/bin/sh
exec python -m push_guard --repo "$(git rev-parse --show-toplevel)"
```

## Run Manually

Cloud workspaces and restricted agents can scan committed work without push
access. Choose the trusted base explicitly:

```sh
push-guard scan --repo . --base origin/main --head HEAD
```

This scans every commit introduced by `base..head`, including content added in
one commit and removed before the head, plus the head tree's private-path rules.
It does not scan uncommitted working-tree changes. Commit locally first, then
run the command. Project-specific `.push-guard-private-paths` rules remain local
unless that ignored file is separately provisioned in the workspace.

The backward-compatible hook mode expects Git `pre-push` input on stdin. Manual
hook dry runs are best done from an actual hook or a test fixture.

```sh
python -m push_guard --repo /path/to/repo
```

## Known Limits

- Pattern-based detection can miss secrets or flag non-secrets.
- Long non-secret identifiers in assignments such as
  `secret = mySuperLongFunctionCallHereWithNoSpaces` can match the generic
  assignment rule.
- If a hook is installed from a Git subdirectory, Git may resolve `--repo` to a
  parent repository root. Push Guard canonicalizes the root before commit and
  private-path inspection; future path-relative features must preserve that
  behavior.
- It blocks likely matches; it does not rotate exposed credentials.
- If a real secret was committed, rotate from a clean context after removing it.
- A local Git hook can be bypassed with `git push --no-verify`; use server-side
  push protection and protected release controls when enforcement is required.
- It should be treated as a seatbelt, not a guarantee.

## Security design sources

- [Git pre-push hook input](https://git-scm.com/docs/githooks#_pre_push) defines
  the exact local/remote ref and object IDs Push Guard validates and scans.
- [Git revision ranges](https://git-scm.com/docs/git-rev-list) define the
  reachable-minus-remote commit set used for outgoing coverage.
- [JFrog's prompt-injection scanner research](https://research.jfrog.com/post/prompt-injection-vs-scanners/)
  supports treating refusal as a failed scan and retaining deterministic
  non-model checks.
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
  recommends immutable full-length action SHAs.
- [PyPI's Trusted Publishing security model](https://docs.pypi.org/trusted-publishers/security-model/)
  recommends a separate, minimal publish job with a protected environment.

## License

Apache-2.0.

## Related read-only tooling

Complementary **read-only** tools in the same security kit:

- **actions-warden** (PyPI, Dragon Lady) — read-only auditor for risky or injected GitHub Actions workflow config under `.github/workflows/`. After token theft, CI injection is a common next step. `pipx install actions-warden` then `actions-warden /path/to/repo`. Does not execute workflows or modify files. https://github.com/Dragon-Lady/actions-warden · https://pypi.org/project/actions-warden/
