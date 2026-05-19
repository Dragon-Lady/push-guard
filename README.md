# Push Guard

Push Guard is a local Git `pre-push` guard for likely secret leaks.

It scans the content being pushed, reports likely secret patterns, redacts all
matched values, and exits nonzero so Git blocks the push.

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
- generic long `api_key`, `token`, `secret`, or `password` assignments

All evidence is redacted as `<redacted>`.

## Install A Repo Hook

Install per repository. Do not install globally.

Create `.git/hooks/pre-push` in the target repository:

```sh
#!/bin/sh
exec python -m push_guard --repo "$(git rev-parse --show-toplevel)"
```

If a `pre-push` hook already exists, preserve and chain it intentionally.

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
- Compound underscored names such as `AWS_SECRET_ACCESS_KEY` are not matched by
  the generic keyword boundary. Prefix-specific rules can still catch known
  token formats such as `AKIA...` / `ASIA...`.
- If a hook is installed from a Git subdirectory, Git may resolve `--repo` to a
  parent repository root. This is acceptable for current diff-only scanning, but
  future path-relative features such as allowlists or report output must resolve
  and document the canonical Git root first.
- It blocks likely matches; it does not rotate exposed credentials.
- If a real secret was committed, rotate from a clean context after removing it.
- It should be treated as a seatbelt, not a guarantee.

## License

Apache-2.0.
