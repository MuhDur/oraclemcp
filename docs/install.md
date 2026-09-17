# Installation, service, and dashboard

This is the detailed installation and operations manual. The front-page README
is deliberately concise; it links here for the complete verified installer,
service, dashboard, offline, and channel contract.

## Install, service, dashboard

One line installs or updates `oraclemcp` on macOS and Linux. It works as pasted
for a human terminal and for a non-interactive agent run:

```sh
curl -fsSL "https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh?$(date +%s)" | bash
```

The hosted script fetch includes a cache buster so stale CDN/proxy copies do not
hide installer updates. This command installs the latest published release; add
`--version X.Y.Z` (or `vX.Y.Z`) to pin a specific release instead. Later
examples that contain `...`, `<pw>`, `<profile>`, or placeholder env values are
templates: replace those placeholders before running them.

The normal command downloads, verifies, and installs into `$HOME/.local` unless
you pass `--prefix`. It requires the SHA-256 digest check, verifies the cosign
blob signature and provenance attestation when cosign is installed, and installs
`oraclemcp` plus the short `om` alias. Missing cosign is a visible
authenticity-unverified posture by default; use `--verify require` when your
environment requires cosign to be present.

In an interactive terminal, the installer then offers a short guided flow:
append the binary directory to `PATH`, run `doctor`, offer zero-config database
discovery from `tnsnames.ora`, print an MCP client snippet, and optionally
install the loopback service. In a pipe, CI job, or agent run, it never prompts,
never scans, and never starts a service; it installs the binary and prints the
exact `PATH` line plus next steps on stderr. Every install finishes with next
steps on stderr: discover databases, run `doctor`, write the starter profile,
and generate MCP client snippets.

### Zero-config onboarding

`oraclemcp setup --discover` finds every database defined in your `tnsnames.ora`
and writes one **read-only** connection profile per net-service — through the
same governed config-ops path (timestamped backup, atomic write, strict
re-validation) used everywhere else. It is **consent-gated**: an interactive run
asks before it scans and again before it writes; a non-interactive run without
`--discover-tns` (or `--yes`) refuses with exit code 2 and scans nothing. It
writes **no secrets to disk** (each profile references an environment variable,
`env:ORACLE_<NAME>_PASSWORD`, that you export yourself), keeps every profile
capped at `READ_ONLY`, and is **idempotent and non-destructive**: existing
profiles and hand edits are preserved, only new databases are added. When no
`tnsnames.ora` is found it falls back to the minimal starter profile so you
still boot. Add
`--json` for a names-only agent report, or `--dry-run` to preview without
writing. Run `oraclemcp doctor` afterwards to see exactly which credentials
remain to be set. Full contract: `docs/tns-discovery-onboarding.md`.

Re-running the same one-liner is the update path. Re-running the same verified
archive is a no-op for identical installed files; re-running with a newer target
updates atomically after backing up the previous binary. A downgrade is refused unless you pass `--force`.

Operator migration notes for the current field-hardening train:
[`docs/oraclemcp-091-field-hardening-notes.md`](oraclemcp-091-field-hardening-notes.md).
Config-migration runbooks introduced in 0.8.0 still apply when upgrading from an
older release:
[`docs/upgrading-to-0.8.0.md`](upgrading-to-0.8.0.md),
[`docs/downgrading-0.8.0-to-0.7.2.md`](downgrading-0.8.0-to-0.7.2.md),
and [`docs/feature-rollout-0.8.0.md`](feature-rollout-0.8.0.md).

Use the dry-run command first when you want a preview: it prints the archive,
verification inputs, files, service plan, client-registration plan, and
installer lock path, then exits before downloading, verifying, writing files, or
touching the service manager. Dry-run exists for review and automation plans;
the normal command above is the install/update command.

### Advanced install paths

Preview the Linux/macOS host plan without changing the machine:

```sh
curl -fsSL "https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh?$(date +%s)" | bash -s -- --dry-run
```

From an installed binary, preview or run the same update path:

```sh
oraclemcp --json self-update --dry-run
oraclemcp self-update --no-service
```

On Windows, download and run the PowerShell installer:

```powershell
iwr -UseBasicParsing https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.ps1 -OutFile install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The Windows installer accepts the same release operations: `-Update` for the
explicit update path, `-NoService` to suppress service prompts, and
`-Verify prefer`, `-Verify require`, or `-Verify checksum-only` for the
verification posture. `prefer` installs after a hard SHA-256 check when cosign
is missing; `require` fails without cosign.

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Update -NoService
```

For air-gapped hosts, stage five inputs: the release archive, its `.sha256`,
`.sigstore.json`, and `.attestation.sigstore.json` siblings, plus a Sigstore
`trusted_root.json` obtained independently on a connected staging host. With a
trusted Cosign v3 installation, refresh that root through Sigstore's TUF
metadata before moving it across the air gap:

```sh
cosign trusted-root create --with-default-services --out sigstore-trusted-root.json
```

Then require authenticity and provenance verification during the offline
install:

```sh
bash install.sh \
  --offline ./oraclemcp-x86_64-unknown-linux-musl.tar.gz \
  --version 0.10.0 \
  --verify require \
  --trusted-root ./sigstore-trusted-root.json
```

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 `
  -Offline .\oraclemcp-x86_64-pc-windows-msvc.zip `
  -Version 0.10.0 `
  -Verify require `
  -TrustedRoot .\sigstore-trusted-root.json
```

The trusted root is trust material, not another self-authenticating release
asset. Provision and protect it separately from the archive bundle. Offline
Cosign verification fails closed when it is absent; `checksum-only` remains an
explicit integrity-only posture.

The release installer does not silently fall back from a missing release archive
to a source build. Use `--source` explicitly when you want `cargo install`
instead of the verified archive path.

On Linux the installer auto-detects the static musl build, which runs everywhere
(including WSL2). The published glibc tarballs are also installable, but only by
explicit request: `--target x86_64-unknown-linux-gnu` (or
`aarch64-unknown-linux-gnu`).

Uninstall is preview-first and idempotent. Service removal remains an explicit
service-manager mutation:

```sh
bash install.sh --uninstall --dry-run
bash install.sh --uninstall --yes
bash install.sh --uninstall --service --yes
```

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall -DryRun
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall -Yes
```

Install the local service only with explicit consent. Keep it on loopback unless
you deliberately configure remote HTTP, and use service-owned client credentials,
OAuth, or mTLS for HTTP MCP clients. For Windows service install, the PowerShell
installer also requires explicit consent.

```sh
oraclemcp --json service install --dry-run --profile db_ro --listen 127.0.0.1:7070 --client-credentials
oraclemcp service install --yes --profile db_ro --listen 127.0.0.1:7070 --client-credentials
oraclemcp --json clients issue --label claude --scope oracle:read
```

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Service -Yes -Profile db_ro
```

Request a listener-bound pairing URL plus a one-time code, open the printed URL,
and paste the code into the form it serves:

```sh
om dashboard
```

The printed URL carries **no secret**, so it is safe in browser history, in a
`Referer`, and in the view of any extension holding `tabs`/`webNavigation`
permission. The one-time code is accepted only from the pairing form's POST body
— never from a URL query or fragment — and the CLI never hands either to a
desktop launcher (where process argv could expose it). The dashboard uses a
one-time loopback pairing ticket bound to the exact live listener instance and
scheme/host/port, then an HttpOnly, SameSite=Strict cookie plus CSRF and
route-scoped action tickets. The cookie is
`Secure` under native TLS or explicit trusted HTTPS termination; the only
non-Secure exception is server-observed loopback HTTP, and remote plaintext
requests never receive privileged browser cookies. Browser
requests do not supply the database Subject: the server derives the Subject from
the authenticated transport principal, session, and lane context. Authenticated
HTTP sessions run on isolated per-principal lanes with their own Oracle
connection, operating level, grants, cancellation, and audit context. Intentional
`--allow-no-auth` HTTP development uses one anonymous lane; stdio remains the
single local client path.

Other release channels come from the same signed archive matrix. These channels
can lag the GitHub release tag, so use the check command first and install only
after it resolves the target version.

```sh
cargo binstall oraclemcp
docker run -i --rm ghcr.io/muhdur/oraclemcp:latest
```

Pending registry-backed channels:

```sh
brew info MuhDur/oraclemcp/oraclemcp
winget search --id MuhDur.oraclemcp --exact
```

After the relevant check resolves the target version, these commands are
copy-pasteable:

```sh
brew install MuhDur/oraclemcp/oraclemcp
winget install --id MuhDur.oraclemcp --exact
```

An npm/npx channel is not offered. Install with the one-line installer above, or
`cargo binstall oraclemcp`, the GHCR Docker image, or the Homebrew/winget
channels once they resolve.
