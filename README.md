# Push Guard

Push Guard is a local Git `pre-push` guard for likely secret leaks.

It scans the content being pushed, reports likely secret patterns, redacts all
matched values, and exits nonzero so Git blocks the push.

> Built and maintained by Dragon Lady - [github.com/Dragon-Lady](https://github.com/Dragon-Lady) - X: [@answerislove2](https://x.com/answerislove2)

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
- Uses the `git` subprocess only to read commit diffs.
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

All evidence is redacted as `<redacted>`.

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
refreshing a Push Guard-managed hook.

Manual hook body, for teams that prefer to wire hooks themselves:

```sh
#!/bin/sh
exec python -m push_guard --repo "$(git rev-parse --show-toplevel)"
```

## Run Manually

The CLI expects Git `pre-push` input on stdin. Manual dry runs are best done from
an actual hook or a test fixture.

```sh
python -m push_guard --repo /path/to/repo
```

## Known Limits

- Pattern-based detection can miss secrets or flag non-secrets.
- Long non-secret identifiers in assignments such as
  `secret = mySuperLongFunctionCallHereWithNoSpaces` can match the generic
  assignment rule.
- If a hook is installed from a Git subdirectory, Git may resolve `--repo` to a
  parent repository root. This is acceptable for current diff-only scanning, but
  future path-relative features such as allowlists or report output must resolve
  and document the canonical Git root first.
- It blocks likely matches; it does not rotate exposed credentials.
- If a real secret was committed, rotate from a clean context after removing it.
- It should be treated as a seatbelt, not a guarantee.

## License

Apache-2.0.
