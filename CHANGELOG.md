# Changelog

## 0.4.1 - release pending

- Infer local account and machine identifiers as redacted personal terms for
  push checks, while retaining private lists for other names and details.
- Accept a private terms list through `PUSH_GUARD_BLOCKED_TERMS` for CI.
- Always block Push Guard's own private configuration files if they are tracked.
- Add `scan-package` to inspect built wheel and source archives before upload;
  release jobs can require an explicit private list and fail closed.

## 0.4.0 - 2026-10-08

- Bound discovery and scanning by one 45-second inspection deadline; preserve
  partial reports on budget exhaustion and prune heavy package/cache trees.
- Exclude filesystem and bind mounts using mountinfo, device and descriptor
  mount IDs; report skipped mounts without listing their contents.
- Keep release tests in a separate job from artifact building; make the existing
  hook-reporting test independent of the current checkout.

- Inspect raw Git content with text conversion, external diff helpers, and color
  disabled; do not allow binary attributes or custom prefixes to hide findings.
- Decode Git-quoted paths and distinguish added `++` content from patch headers.
- Inspect complete reachable history for new remote refs instead of excluding
  commits merely because a different remote-tracking ref already contains them.
- For a new release tag sent with its branch in one push, use that branch's
  advertised remote SHA as the tag's scan base; keep the full-history check
  for a tag sent alone, and inspect annotated tag text for secrets.
- Check added/changed private paths throughout outgoing history, including files
  deleted before the tip, while keeping normal trusted-base scope and exceptions.
- Redact recognized credentials in finding paths and diagnostic metadata, and
  escape terminal controls in user-visible metadata.
- Recognize exact affected MCP pins with extras and PhantomSub package identities
  in npm v3 `node_modules` lockfile keys, including nested dependencies.

- Add fixture-verified, opt-in `push-guard sweep` and `push-guard-sweep` disk
  inspection as a separate command alongside the Git inspection hardening above.
- Add HOME-bounded no-follow reads, metadata-only credential-store mode checks,
  keyed fingerprints, private baseline/report output and opt-in aggregate alerts.
- Reject identifiable binary/database/compressed scan targets after at most an
  8 KiB header read, leaving state and config readers unchanged.
- Install a development-only pytest extra in CI and run all existing and new
  tests before a release can publish.
- Keep the existing Python >=3.11 package floor.

## 0.3.7 - 2026-09-30

### Build

- Refresh the PyPA build frontend pinned in the release workflow to 1.6.1,
  incorporating upstream dependency-floor and build fixes.

### Security

- Flag exact affected lodash-family pins for the `_.template` imports-key
  advisory in `package.json`; a version match is an exposure lead.
- Flag exact affected MCP Python SDK pins in requirements and PyProject
  metadata for the OAuth credential-routing advisory. Unattended providers
  also need `issuer=` after upgrading.
- Flag 15 exact npm package names from OX Security's PhantomSub report in
  dependency metadata, without treating nearby lookalike names as matches.

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
