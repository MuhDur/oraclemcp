//! TNS discovery and consent-gated onboarding — the config-side contract.
//!
//! This module is the in-code mirror of the design anchor at
//! [`docs/tns-discovery-onboarding.md`](../../../../docs/tns-discovery-onboarding.md).
//! It holds the pieces of the *TNS-onboarding* feature that belong next to the
//! configuration structs they govern:
//!
//! - [`contract`] — the machine-readable **mapping + writer contract**: for
//!   every serde field of [`crate::OracleMcpConfig`] and
//!   [`crate::ConnectionProfile`], whether the annotated writer sets it, sets it
//!   only when known, comments it, points at `oraclemcp.example.toml`, or
//!   handles it structurally. Downstream synthesis (`.5`) and the writer (`.8`)
//!   build on this, and a schema-drift test keeps it honest against the structs.
//! - [`search`] — the pure-`std` **search-path resolver**: enumerates the
//!   candidate directories that may hold a `tnsnames.ora`, in precedence order,
//!   de-duplicated by canonical path, with permission-denied = skip-with-note.
//!
//! The Oracle-Net *parse adapter* (reusing the upstream `TnsnamesReader`) lives
//! in `oraclemcp-db` near the driver seam, not here — this module has no Oracle
//! dependency; it is pure config mapping and pure-`std` filesystem discovery.
//!
//! # Design summary (authoritative detail in the doc)
//!
//! - **Search order** (spec §A): `$TNS_ADMIN`, `$ORACLE_HOME/network/admin`,
//!   `~/.config/oraclemcp/network`, `~`, `/etc`, common Instant Client dirs, the
//!   cwd — first-match-wins but scan-all-for-report, de-duplicated by canonical
//!   path, permission-denied = skip-with-note (never a hard failure).
//! - **Mapping** (spec §B): each net-service → at most one profile; `name`
//!   sanitized from the alias, `connect_string` = alias or normalized EZConnect,
//!   `credential_ref` a placeholder `env:` secret-ref, `max_level` /
//!   `default_level` both set explicitly to `READ_ONLY`.
//! - **Writer** (spec §C): bootable minimum + a commented self-documenting menu;
//!   `deny_unknown_fields` means every uncommented key is a real serde field and
//!   the output round-trips through `OracleMcpConfig::from_toml_str`.
//! - **Consent** (spec §D): never scan without consent, never prompt a non-TTY;
//!   a refusal is a usage/safety block (exit code 2).
//! - **Idempotency** (spec §E): add-only, never clobber; timestamped backup and
//!   verify-before-mutate via config-ops; secrets never written to disk.
//!
//! Nothing here weakens the `AGENTS.md` safety invariant.

pub mod contract;
pub mod search;

pub use contract::{
    CONNECTION_PROFILE_FIELD_DISPOSITIONS, Disposition, FieldDisposition,
    TOP_LEVEL_FIELD_DISPOSITIONS, connection_profile_field_names, top_level_field_names,
};
pub use search::{
    CandidateSource, CandidateStatus, DiscoveryEnv, TnsCandidateDir, resolve_candidate_dirs,
    resolve_candidate_dirs_with,
};
