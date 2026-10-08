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

The current Netlify project uses manual deploys. A Git push alone does not
update the public page: publish the contents of `docs/` after each release and
check the live version, social image, and response headers. The `docs/_headers`
file keeps the security headers when deploying that directory directly.

## Posture

- Local, read-only inspection of targets. No telemetry.
- No network by default. Only Sweep's explicit `--send` option enables aggregate
  alerts to configured destinations; the Git guard remains offline.
- No package installs or target-file mutation during scans.
- No matched secret values or source lines printed, logged, or saved.
- Git mode uses the `git` subprocess only to read commit diffs, pushed trees,
  configured hook paths, and ignore metadata. The existing hook entry point is
  preserved, with raw-content and outgoing-history inspection hardened.
- Sweep reads selected files outside Git, inside `$HOME`, and executes no child
  processes, including Git.
- No scan results written by default. Sweep creates one random 32-byte HMAC key
  at `$XDG_STATE_HOME/push-guard-sweep/fp.key` (default
  `~/.local/state/push-guard-sweep/fp.key`) for stable, non-guessable fingerprints.
  This key is the explicit exception to “no data stored by default.” It contains
  no scanned data. The state directory is 0700 and files are created 0600.
- Explicit Sweep `--baseline` and `--output` files contain redacted local metadata;
  `--send` stores keyed deduplication receipts, never alert credentials or secrets.
- No claim that a repository or machine is clean. Matches are review leads,
  not proof that credentials remain valid.

Blocking a push is Git's response to the advisory. Push Guard remains read-only
and does not mutate files. Override is available with `git push --no-verify`
when the matched value is known not to be a secret.

## Sweep: secrets on disk

The `push-guard sweep` command and `push-guard-sweep` alias provide the same local
inspection. They require the existing package's Python 3.11 or newer and have no
additional runtime dependencies. Development tests use the optional `test` extra
(`python -m pip install ".[test]"`, then `PYTHONPATH=src python -m pytest -q`
from the repository root). The 0.4.0 release adds Sweep. CI installs that
development extra and runs the entire pytest suite, including the legacy
unittest cases. Release tests run in a
separate job; that job never supplies distribution artifacts to publishing. The
artifact-build job does not install test dependencies. Sweep does not install
or enable a scheduler.

```sh
push-guard sweep --list-targets
push-guard sweep --roots ~/projects --class stray
push-guard-sweep --format json --output ~/sweep-report.json
push-guard-sweep --baseline ~/sweep-baseline.json
push-guard-sweep report --format html --output ~/sweep-report.html
push-guard-sweep print-timer --interval 7d
```

Every scan also considers the default history, dotfile, configuration and log
locations below. `--roots` changes the `.env*` and custom-include search roots;
use `--exclude` to narrow the other default sets. Repeated `--include GLOB` adds
files within the existing bounded searches, and repeated `--exclude GLOB` removes
paths. Globs match basenames, HOME-relative paths, or absolute paths. Excludes
win; includes cannot override safety exclusions or depth limits. `~` in CLI path
arguments is expanded. Scanned paths must remain inside `$HOME`.

- History: Bash, Zsh, Python, Node, PostgreSQL, MySQL, SQLite shell history and
  `.lesshst`. The SQLite **shell history text** is separate from database files.
- Dotfiles: `.bashrc`, `.zshrc`, `.profile`, `.bash_profile`, `.npmrc`, and
  `.docker/config.json`; selected JSON, TOML, YAML, INI and CONF files under
  `.config` with at most four directory levels below it.
- `.env*` files: under the selected roots (default HOME), at most six directory
  levels. Dependency trees, virtual environments, Git metadata and caches are
  excluded from this search.
- Logs: `.log` files and files within `logs/`, at most four directory levels under
  `.local/state`, `.cache`, `.codex`, `.config/Cursor/logs` and configured
  `log_dirs`.

Known credential stores (`.git-credentials`, `.aws/credentials`, `.netrc`,
`.pypirc`, `.config/gh/hosts.yml`, `.config/rclone/rclone.conf`, `.codex/auth.json`)
are **metadata-only** checks. Their contents are never opened. Each is reported
as `expected-store`, with info severity for private modes or warn severity for
execute/group/other permissions. `line` is null and `fp_kind=path` explicitly
identifies a keyed path fingerprint, not a token fingerprint. Reach Ward owns
credential inventory in these stores. This avoids inventing a secret value or
line number for a mode check. All other matches are classed `stray` and normally
warn; Google access tokens are low severity and marked short-lived, likely
expired. No token is checked against a provider.

Sweep reuses Push Guard's provider definitions and generic-assignment matcher,
adds Slack, Google, npm, PyPI, JWT and credential-bearing URL shapes, and detects
extended OpenAI token shapes. Generic assignments additionally require entropy
of at least 3.5 bits per character. Obvious fillers and variable references are
ignored; a random provider token containing a word such as `test` is still
reported. `# push-guard: ignore` cannot suppress Sweep matches. Complete private
key blocks are fingerprinted in full; incomplete blocks fingerprint the bounded
remainder after their header. No private key material is persisted.

Findings contain local path, line, rule, type, class, severity, mode, `fp:` plus
16 HMAC-SHA256 hex characters, and the literal `<redacted>`. A `.git` directory or
file establishes possible Git membership by metadata only. **Tracked status is
always `unknown`**: Sweep does not execute Git or parse its index. Paths are
redacted when they contain discovered secret values or token shapes; encoded
path labels are conservatively replaced in full. Reports never include source
lines. Hints are printed advice only; Sweep never deletes history, rotates a
credential, edits `.gitignore`, or changes a file's mode.

`--list-targets` does zero scan-target or configuration content reads and creates no fingerprint key or
other files. It uses defaults and CLI target options only, and does not read the
default configuration file. Combining it with `--config`, `--baseline`,
`--output` or `--send` is rejected. It lists intended text reads and explicitly
marks expected stores as metadata-only. Binary content cannot be identified
without reading it, so unnamed binary files can appear in this preview and be
skipped during the scan.

All symlinks, hardlinks, FIFOs, devices, sockets, known browser-profile/keyring
paths, database filenames and compressed/binary extensions are skipped. Directory
components are opened with no-follow descriptors, so a symlinked parent cannot
redirect reads. Text reads are capped at 10 MiB per file; database/compressed
magic, NUL bytes, binary control bytes or invalid UTF-8 cause a skip.
Identifiable binary/database/compressed content is rejected after at most 8 KiB
of header reads; config/state reading is separate and unchanged. A file with
an unexpected binary/database name needs a bounded read to identify its content;
no SQLite library is used. Discovery is bounded to 250,000 directory entries and
10,000 target files and 10,000 findings; baselines are capped at 10 MiB. A run has
a 100 MiB text-read budget and one shared 45-second inspection deadline. Budget
exhaustion returns a partial, incomplete report with exit 2. Slow storage can
still exceed a deadline during an uninterruptible kernel system call.

Exit codes: **0** no findings, **1** findings (including informational store
checks), **2** usage, runtime, incomplete-inspection or alert-delivery error.
Intentional policy skips are summarized separately and do not mean inspection
failed. Missing standard optional source files are normal. Text, JSON, Markdown
and self-contained escaped HTML are available through `--format`.

A first `--baseline FILE` run reports everything and saves fingerprints, paths,
lines, rule IDs and modes. Subsequent runs report only entries absent from the
previous successful scan, then replace that baseline atomically. Changed modes
or lines are new entries. Removed entries are dropped. An incomplete scan never
updates the baseline. Baselines are private, validated files and must use the
same fingerprint key; a missing or changed key requires restoring the original
key before comparing. Output reports never overwrite existing files. All output
and baseline files are 0600 at creation; destination parent directories must
already exist. No source file is repurposed as state.

`report` performs a fresh local scan, because no historical scan results are kept
by default. `print-timer` prints separate systemd user service/timer texts to
stdout and installs nothing. A timer uses the defaults or your saved config;
review and save it yourself after validating the tool on the intended machine.

### Sweep traversal boundaries

Discovery and content scanning share a **45-second inspection deadline**; they
no longer each receive a separate allowance. Discovery receives at most 20
seconds of that shared allowance, reserving time for already-found files. Known
history/config/log roots are considered before broad environment discovery.
The single-threaded CLI also uses
a temporary alarm to interrupt slow pattern matching; embedded calls in other
threads retain cooperative checks. Reporting and writing private results happen
after inspection stops. An uninterruptible kernel I/O stall cannot be given a
hard wall-clock guarantee. Mount avoidance is particularly important for that
reason.

Discovery permits up to 250,000 entries and 10,000 targets. Byte, entry, target,
finding or time exhaustion returns the findings collected so far, marks the
report `incomplete: true`, summarizes the budget reason and exits 2. Human
formats display the incomplete status too. Partial runs never update a baseline.

Heavy package/cache trees are pruned, including `~/.local/share/Trash`, `~/snap`,
`.cargo`, `.rustup`, `.npm`, `.gradle`, `.m2`, `.yarn`, `.pnpm-store`, `~/go/pkg`,
`~/.local/share/Steam`, `~/.local/share/flatpak`, `~/.var/app`, `~/.local/lib` and
`~/.nvm`. Package caches under `~/.cache` (uv, pip, pypoetry, huggingface,
torch, ms-playwright) and `~/.codex/plugins/cache` are also pruned.
Environment discovery also prunes cache directories; bounded log
inspection still considers the configured log roots. Hard safety exclusions
remain in effect even with explicit roots or include patterns.

Sweep reads Linux `/proc/self/mountinfo` and descriptor mount metadata. These are
kernel metadata, not target/configuration contents: `--list-targets` still reads
zero scan-target or configuration content and creates no state. Every mount
point below HOME is excluded **before stat, open or listing**, including file
bind mounts and same-device bind mounts. Opened descriptors are checked again
against HOME's device and kernel mount ID before listing or reading. FUSE,
rclone, NFS, CIFS and autofs HOME filesystems are refused as scan roots; unknown
mount metadata produces an incomplete report without target reads. Exclusions
are counted as `skipped_mount`. There is no override that traverses a mounted
subtree. Config/state/report/baseline paths inside HOME also reject known mounted
subtrees before use. Explicit tool-owned XDG/output paths outside HOME remain
allowed. Checks do not lock the mount namespace against a privileged remount.

Sweep is based on the separately reviewed guard-hardening commit; its only
changes to the existing guard entry point are Sweep dispatch and a help line.
It adds no change to the hook body or outgoing Git inspection.

### Sweep configuration and optional alerts

Config: `$XDG_CONFIG_HOME/push-guard-sweep/config.toml`, default
`~/.config/push-guard-sweep/config.toml`, owned by the current user and mode 0600.
`--config FILE` selects another file. XDG config/state may be outside HOME;
scanned targets may not. An example:

```toml
roots = ["~/projects"]
include = ["*.trace"]
exclude = ["scratch/*"]
log_dirs = ["~/app-logs"]
alert_channels = ["stdout"]
# alert_channels = ["slack"]
# alert_slack_webhook_env = "SWEEP_SLACK_WEBHOOK"
```

Alerting requires `--send`, even with channels configured. Empty channels mean
stdout. Supported channels and Net Ward-compatible keys are:

| Channel | Configuration |
| --- | --- |
| `stdout` | No credentials; aggregate summary in command output |
| `slack` | `alert_slack_webhook_env` names an environment variable |
| `ntfy` | `alert_ntfy_topic`, optional `alert_ntfy_token_env` |
| `email` | `alert_smtp_host`, `alert_smtp_port`, `alert_smtp_security` (`starttls`/`ssl`), `alert_smtp_from`, `alert_email`, optional `alert_smtp_username` and `alert_smtp_password_env` |

Never put webhook URLs, tokens or SMTP passwords in config: only their
**environment variable names**. HTTPS is required except for loopback HTTP;
SMTP encryption is required off loopback. Redirects are rejected. Connections
use a five-second timeout. Failed sends are reported by channel only, without
leaking credential-bearing URLs. Alerts carry only aggregate counts by rule,
class and severity, with no paths, fingerprints, source lines or secret values,
and end with `run push-guard-sweep report locally for details`. Private keyed
receipts suppress repeated matching alerts to the same destination for 24 hours;
a changed destination is eligible again. No real alert destination is configured
by the package.

## Current Signals

- Exact affected lodash-family pins in `package.json` for the
  `_.template` imports-key advisory (GHSA-r5fr-rjxr-66jc). A pin alone does
  not prove an unsafe template call.
- Exact affected `mcp` Python SDK pins in requirements and PyProject
  metadata for GHSA-qx49-fqc8-xw99. HTTP OAuth clients need a fixed SDK;
  unattended providers also need `issuer=` and stored registrations may need
  clearing.
- Fifteen exact OX Security PhantomSub npm package names in dependency
  metadata. A reference is a review lead, not proof of account activity.
- GitHub classic token prefixes: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
- GitHub fine-grained token prefix: `github_pat_`
- GitLab incoming email tokens with the standard `glimt-` prefix and 25-character
  token body. A project email address containing one can enable issue and merge
  request actions as its owner; custom-prefix and older formats are not covered.
- Aikido-reported Graphalgo Go modules and Terraform providers in `go.mod`,
  `go.sum`, `.tf`, and `.terraform.lock.hcl` dependency or provider declarations.
  The legitimate `kreuzwerker/docker` provider is not blocked.
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
  `atomic-lockfile`, `ecto-flag-read`, and the nine DirtyBlanket fake
  Express/React packages reported on September 29
- GitHub workflow references to release tags of the hijacked
  `actions-cool/issues-helper` and `actions-cool/maintain-one-comment` actions
- July 2026 malicious npm names and exact compromised `jscrambler`, Injective,
  and payment-SDK versions, plus reverse-shell shapes embedded directly in
  package manifest lifecycle scripts
- August 4, 2026 keyv / cacheable (ChainDrop / Shai-Hulud) **exact** seed versions
  only (`keyv@6.0.0` and ten related jaredwray-family releases verified by Snyk,
  StepSecurity, Aikido, Wiz, and JFrog). Does not block all versions of those
  package names; full campaign inventory is larger (Ox / Wiz)
- all ten GitHub-reviewed Trinitite / Mini Shai-Hulud malicious releases of
  `@7nohe/openapi-react-query-codegen`, campaign payload markers, and
  comment-triggered npm publish conditions that require a trusted-author gate
- Aurora Linux/ESXi ransomware SHA-256, R2 payload URL, and ESXi VM force-kill
  command shapes in executable or configuration diffs; Cursor installation or
  ordinary use is not treated as an indicator
- NebuSec/CyberMeowfia public exploit-pack sources for the 22 CVEs enumerated
  in the September 2026 oss-security Linux LPE post when they appear in
  executable or configuration diffs; ordinary incident documentation remains
  excluded
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

It checks the pushed tip tree and added/changed private paths in every outgoing
commit. A private file added and then deleted before the tip is still blocked:
its contents remain in the transmitted history. An unchanged private file at
the tip is also flagged on every push until it is removed. Ordinary range scans
do not rescan private paths confined to the trusted remote base.

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
When Git reports a new remote ref with no trusted base, the hook scans all
reachable history. Remote-tracking refs from other destinations never exclude
objects from that first-push inspection.
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

- [SafeDep's DirtyBlanket analysis](https://safedep.io/dirtyblanket-express-impersonation-npm/)
  names the nine fake npm packages and Linux worm persistence paths.
- [Socket's actions-cool report](https://socket.dev/blog/mini-shai-hulud-actions)
  and [SafeDep's downstream infection analysis](https://safedep.io/mini-shai-hulud-reinfection-github-repositories/)
  document the hijacked tags and September 2026 exposure window.
- [GitLab token documentation](https://docs.gitlab.com/security/tokens/) and
  [GitLab's detection pattern](https://gitlab-org.gitlab.io/gitlab/coverage-frontend/lcov-report/app/assets/javascripts/lib/utils/secret_detection_patterns.js.html)
  define the incoming email token format; [Aikido's report](https://www.aikido.dev/blog/gitlab-email-push-to-main)
  explains why a leaked project address matters.
- [Aikido's Graphalgo analysis](https://www.aikido.dev/blog/graphalgo-terraform-go-modules)
  names the two Go modules and two Terraform providers.
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
- [GitHub's reviewed Trinitite malware advisory](https://github.com/advisories/GHSA-rg27-qr39-ch6w)
  provides the affected `@7nohe/openapi-react-query-codegen` versions.
- [JFrog's Trinitite analysis](https://research.jfrog.com/post/shai-hulud-trinitite/)
  documents the payload markers and comment-triggered publishing path.
- [Gambit Security's Aurora report](https://gambit.security/blog-posts/aurora-ransomware-targets-esxi-abuses-cursor-agent-for-exploitation)
  provides the Linux/ESXi ransomware hash and behaviors.
- [Openwall's oss-security post](https://www.openwall.com/lists/oss-security/2026/09/08/1)
  enumerates the September 2026 public Linux kernel exploit batch.

## License

Apache-2.0.

## Related read-only tooling

Complementary **read-only** tools in the same security kit:

- **actions-warden** (PyPI, Dragon Lady) — read-only auditor for risky or injected GitHub Actions workflow config under `.github/workflows/`. After token theft, CI injection is a common next step. `pipx install actions-warden` then `actions-warden /path/to/repo`. Does not execute workflows or modify files. https://github.com/Dragon-Lady/actions-warden · https://pypi.org/project/actions-warden/
