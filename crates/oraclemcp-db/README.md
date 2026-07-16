# oraclemcp-db

The **canonical shared Oracle foundation** for `oraclemcp`, including its
optional embedded PL/SQL-intelligence engine, per
[ADR-0006](../../docs/adr/0006-oraclemcp-db-canonical-foundation.md). The
standalone `plsql-mcp` server described by that historical ADR is deprecated.

It owns the correctness-critical Oracle layer used by the server and its
optional embedded engine:

- the backend-independent [`OracleConnection`] trait + the thin
  [`oracledb`]-backed `RustOracleConnection`,
- the bounded pure-Rust session pool (`OraclePool`),
- the session-lease primitive,
- the deterministic NUMBER→string / ISO-8601 / NLS-stable serializer,
- and the dictionary / intelligence operations.

Every real `oracledb` driver call is confined to the adapter seam
(`src/connection.rs`,
[ADR-0002](../../docs/adr/0002-driver-adapter-seam.md)). No driver type leaks
into this crate's public API: callers depend only on the `oraclemcp-db` types.

## API stability

Because this surface is published, its public API is treated as a **product**
and follows SemVer once published. It is snapshot-locked in CI so an unintended
breaking change is caught before release:

- **`cargo public-api`** — diffs the rendered public API against a committed
  baseline (`api/<crate>.txt`). Any addition or removal that is not reflected in
  the baseline fails the `api-lock` CI job.
- **`cargo semver-checks`** — an actual SemVer contract: it classifies a diff as
  major / minor / patch and fails when the surface changed in a way the version
  bump does not allow.

The same gate covers the public dependencies used by this crate
(`oraclemcp-error`, `oraclemcp-guard`) alongside the canonical foundation.

The accepted published-spine dependency on `oraclemcp-error` **is part of the
locked surface** (re-exported as `error_envelope`; its `ErrorEnvelope` type
appears in return positions such as `DbError::into_envelope`). It is not
pretended away — a breaking bump to it is a deliberate, snapshot-visible change.
The `oraclemcp-guard` dependency is internal (the pool consumes its validators)
and does not appear in the public surface.

## Refreshing the baseline

When you make an **intended** public-API change, regenerate the baseline in the
same PR so the diff is reviewable:

```bash
# Install the pinned tools (CI installs them via taiki-e/install-action):
cargo install --locked cargo-public-api cargo-semver-checks

# Regenerate the committed baseline for the changed crate(s):
CARGO_TARGET_DIR="$PWD/target" cargo public-api -p oraclemcp-db \
  > crates/oraclemcp-db/api/oraclemcp-db.txt

# Sanity-check the SemVer classification against the last published release:
CARGO_TARGET_DIR="$PWD/target" cargo semver-checks check-release -p oraclemcp-db
```

`cargo public-api` renders the surface under the pinned nightly toolchain (see
`rust-toolchain.toml`); run it with that toolchain so the baseline is stable.

[`OracleConnection`]: https://docs.rs/oraclemcp-db
[`oracledb`]: https://crates.io/crates/oracledb
