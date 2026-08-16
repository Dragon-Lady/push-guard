# Changelog

## 0.3.4 - 2026-08-16

### Security

- Keep inline workflow/IOC allowlist comments from suppressing real provider
  token shapes or generic secret assignments.
- Fail closed when pre-push input is malformed or Git ignore inspection fails.
- Preserve exact tree paths with NUL-delimited Git plumbing, including unusual
  filenames that contain whitespace or newlines.
- Apply existing refusal-bait detection to the repo-local agent instruction
  paths identified in current promptware research while continuing to exempt
  ordinary Markdown incident notes.
- Resolve hook installation through Git so configured `core.hooksPath` and
  linked-worktree layouts are honored.

### Release engineering

- Add a Python 3.11-3.14 CI matrix.
- Pin GitHub Actions to immutable upstream commit SHAs.
- Test, validate version/tag parity, and build distributions before passing a
  short-lived artifact to a separate PyPI Trusted Publishing job.
