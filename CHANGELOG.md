# Changelog

## 0.3.6 - 2026-09-29

### Security

- Block the nine SafeDep-reported DirtyBlanket npm package names in dependency
  metadata. These fake Express/React packages run a Linux worm at install time.
- Flag release-tag references to the two hijacked `actions-cool` GitHub Actions
  in workflow changes. The tags were still malicious when the actions were
  briefly re-enabled in September; full clean commit pins stay unflagged.
- Block standard GitLab incoming email tokens in pushed text, including
  project email addresses, with redacted findings. GitLab's secret-detection
  pattern uses the `glimt-` prefix and a 25-character body; custom-prefix and
  older formats require separate review.
- Block the four Aikido-reported Graphalgo package identities when they appear
  as Go module requirements or Terraform provider declarations. Keep the
  similarly named legitimate Docker provider clear.

## 0.3.5 - 2026-09-10

### Security

- Block all ten GitHub-reviewed Trinitite / Mini Shai-Hulud malicious releases
  of `@7nohe/openapi-react-query-codegen` in npm dependency metadata.
- Flag Trinitite payload markers and unsafe comment-triggered npm publish
  conditions in executable or workflow changes.
- Flag Aurora Linux/ESXi ransomware hash, R2 download, and VM force-kill
  command shapes in executable or configuration changes.
- Flag public September 2026 Linux kernel exploit-pack sources in executable or
  configuration changes while keeping ordinary incident documentation
  non-blocking.

### Privacy

- Preserve Push Guard's local-only, zero-telemetry posture. Findings remain
  redacted and no user data, file contents, or matched values are retained.

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
