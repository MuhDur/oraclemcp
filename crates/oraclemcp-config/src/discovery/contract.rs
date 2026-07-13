//! The machine-readable half of the TNS-onboarding **mapping + writer
//! contract** (design spec §B/§C; `docs/tns-discovery-onboarding.md`).
//!
//! This is the shared source of truth the downstream discovery beads build on:
//! the net-service → profile synthesis (`.5`) and the annotated safe-config
//! writer (`.8`) both consume [`CONNECTION_PROFILE_FIELD_DISPOSITIONS`] and
//! [`TOP_LEVEL_FIELD_DISPOSITIONS`] to decide, for every serde field, whether it
//! is written with a value ([`Disposition::Set`]), written only when known
//! ([`Disposition::SetWhenKnown`]), rendered as a commented one-line menu entry
//! ([`Disposition::Commented`]), rendered as a short commented pointer to
//! `oraclemcp.example.toml` ([`Disposition::Pointer`]), or handled structurally
//! ([`Disposition::Structural`], e.g. the `[[profiles]]` array itself).
//!
//! # deny_unknown_fields
//!
//! Both [`crate::OracleMcpConfig`] and [`crate::ConnectionProfile`] are
//! `#[serde(deny_unknown_fields)]`. So every uncommented key the writer emits
//! MUST be a real serde field and NO unknown key may ever appear — a typo'd key
//! becomes a load error the instant an operator uncomments it. The writer output
//! must round-trip through `OracleMcpConfig::from_toml_str`.
//!
//! # Schema-drift guard
//!
//! The [`tests`] module below asserts these tables enumerate EXACTLY the serde
//! fields of the two structs (by serializing a fully-populated instance and
//! comparing key sets), and the fully-populated struct literals it builds fail
//! to compile if a new field is added without being dispositioned here. Together
//! they keep this contract and the config structs from silently diverging.

/// How the annotated writer renders one config field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Written uncommented, with a value (e.g. `max_level = "READ_ONLY"`).
    Set,
    /// Written with a value only when a convention is known for the target,
    /// otherwise rendered commented (e.g. `username`).
    SetWhenKnown,
    /// Present but commented, with a one-line help string using the exact serde
    /// name, so uncommenting yields a valid key.
    Commented,
    /// Rendered as a short commented pointer to `oraclemcp.example.toml` rather
    /// than reproducing the full surface (e.g. `[http]`, `[audit]`).
    Pointer,
    /// Not a scalar key the writer emits directly; handled structurally (e.g.
    /// the `[[profiles]]` array, rendered one block per synthesized service).
    Structural,
}

/// The disposition and one-line help for a single serde field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldDisposition {
    /// The EXACT serde field name (so uncommenting the rendered key is valid).
    pub field: &'static str,
    /// How the writer renders it.
    pub disposition: Disposition,
    /// One-line help string, reconciled in meaning with `oraclemcp.example.toml`.
    pub help: &'static str,
}

/// Top-level [`crate::OracleMcpConfig`] field dispositions (design spec §C.1).
///
/// Enumerates every serde field of `OracleMcpConfig`
/// (`crates/oraclemcp-config/src/lib.rs:83`). The schema-drift test asserts this
/// list matches the struct's serde surface exactly.
pub const TOP_LEVEL_FIELD_DISPOSITIONS: &[FieldDisposition] = &[
    FieldDisposition {
        field: "schema_version",
        disposition: Disposition::Set,
        help: "Config schema version this build understands (= 2); a higher value is rejected.",
    },
    FieldDisposition {
        field: "default_profile",
        disposition: Disposition::Set,
        help: "Profile used when the launcher passes no `serve --profile <name>`; set when unambiguous.",
    },
    FieldDisposition {
        field: "monitor_profile",
        disposition: Disposition::Commented,
        help: "Optional least-privilege profile for fleet-wide DB observability; unset degrades to self-lane/local telemetry.",
    },
    FieldDisposition {
        field: "http",
        disposition: Disposition::Pointer,
        help: "Native Streamable HTTP transport (off by default; stdio-only). See oraclemcp.example.toml [http].",
    },
    FieldDisposition {
        field: "audit",
        disposition: Disposition::Pointer,
        help: "Out-of-band hash-chained audit log. See oraclemcp.example.toml [audit]. key_ref MUST be set before any profile raises max_level above READ_ONLY, or startup fails closed.",
    },
    FieldDisposition {
        field: "profiles",
        disposition: Disposition::Structural,
        help: "The [[profiles]] array; the writer renders one profile block per synthesized net-service.",
    },
];

/// Per-profile [`crate::ConnectionProfile`] field dispositions (design spec §C.2).
///
/// Enumerates every serde field of `ConnectionProfile`
/// (`crates/oraclemcp-config/src/profile.rs`, 30 serde fields).
/// The schema-drift test asserts this list matches the struct's serde surface
/// exactly.
pub const CONNECTION_PROFILE_FIELD_DISPOSITIONS: &[FieldDisposition] = &[
    FieldDisposition {
        field: "name",
        disposition: Disposition::Set,
        help: "Stable identifier the agent connects by; unique, [a-z0-9_].",
    },
    FieldDisposition {
        field: "description",
        disposition: Disposition::Set,
        help: "Friendly description shown in list_profiles; seeded from the net-service alias.",
    },
    FieldDisposition {
        field: "connect_string",
        disposition: Disposition::Set,
        help: "Oracle Net connect identifier: the tnsnames.ora alias, or a normalized EZConnect (host:port/service).",
    },
    FieldDisposition {
        field: "username",
        disposition: Disposition::SetWhenKnown,
        help: "Oracle username; set only when a least-privilege convention is known, else commented (none for wallet / OS-auth / OCI-IAM).",
    },
    FieldDisposition {
        field: "credential_ref",
        disposition: Disposition::Set,
        help: "Placeholder secret-ref for the DB password (env:ORACLE_<NAME>_PASSWORD); use env:/file:/keyring: — never a literal.",
    },
    FieldDisposition {
        field: "login_script",
        disposition: Disposition::Commented,
        help: "Path to an allowlisted `ALTER SESSION …` login script run on lease acquire.",
    },
    FieldDisposition {
        field: "login_statements",
        disposition: Disposition::Commented,
        help: "Inline allowlist-validated `ALTER SESSION SET …` statements run on lease acquire.",
    },
    FieldDisposition {
        field: "trusted_session_statements",
        disposition: Disposition::Commented,
        help: "Trusted local session setup, authored by the profile owner, never accepted from agent tool calls.",
    },
    FieldDisposition {
        field: "call_timeout_seconds",
        disposition: Disposition::Commented,
        help: "Per-round-trip Oracle call timeout, in seconds (default 30 when omitted).",
    },
    FieldDisposition {
        field: "max_query_cost",
        disposition: Disposition::Commented,
        help: "Per-query cooperative cost ceiling for oracle_query; per-call overrides may only lower it.",
    },
    FieldDisposition {
        field: "connect_timeout_seconds",
        disposition: Disposition::Commented,
        help: "Oracle Net transport connect timeout, in seconds (default: the thin driver's 20s).",
    },
    FieldDisposition {
        field: "inactivity_timeout_seconds",
        disposition: Disposition::Commented,
        help: "Per-read inactivity deadline on an established session, in seconds (unset = unbounded reads).",
    },
    FieldDisposition {
        field: "keepalive_minutes",
        disposition: Disposition::Commented,
        help: "Oracle EXPIRE_TIME dead-connection-detection probe interval, in MINUTES (injected as expire_time=N; unset = no DCD probes).",
    },
    FieldDisposition {
        field: "sdu",
        disposition: Disposition::Commented,
        help: "Session Data Unit request size for the thin driver (512..=65535 bytes; negotiated when unset).",
    },
    FieldDisposition {
        field: "max_level",
        disposition: Disposition::Set,
        help: "Per-target operating-level ceiling; set explicitly to READ_ONLY. The immutable cap escalation can never exceed.",
    },
    FieldDisposition {
        field: "default_level",
        disposition: Disposition::Set,
        help: "Level a fresh session starts at; set explicitly to READ_ONLY. Must not exceed max_level.",
    },
    FieldDisposition {
        field: "protected",
        disposition: Disposition::Commented,
        help: "Production profile: pins the ceiling immutable; requires max_level = READ_ONLY and rejects literal: secret refs.",
    },
    FieldDisposition {
        field: "require_signed_tools",
        disposition: Disposition::Commented,
        help: "Require HMAC signatures for operator-defined custom tools on this profile (implied by protected).",
    },
    FieldDisposition {
        field: "read_only_standby",
        disposition: Disposition::Commented,
        help: "Mark target as a read-only Active Data Guard standby: forces READ_ONLY regardless of max_level.",
    },
    FieldDisposition {
        field: "mcp_exposed",
        disposition: Disposition::Commented,
        help: "Per-profile MCP exposure; default exposed (opt-out). Set false to hide this profile from the agent surface.",
    },
    FieldDisposition {
        field: "dashboard_ddl_workbench",
        disposition: Disposition::Commented,
        help: "Browser dashboard DDL/Admin apply opt-in; never raises max_level or bypasses preview/confirm/rollback/audit.",
    },
    FieldDisposition {
        field: "session_identity",
        disposition: Disposition::Commented,
        help: "[profiles.session_identity] end-to-end Oracle session identity (program/machine/module/action/client_identifier/…).",
    },
    FieldDisposition {
        field: "pool",
        disposition: Disposition::Commented,
        help: "[profiles.pool] local client-side connection pool for stateless catalog/metadata reads.",
    },
    FieldDisposition {
        field: "oci",
        disposition: Disposition::Commented,
        help: "[profiles.oci] OCI / Autonomous DB fields (wallet_location, wallet_password_ref, DN matching, SNI, IAM token).",
    },
    FieldDisposition {
        field: "drcp",
        disposition: Disposition::Commented,
        help: "[profiles.drcp] Database Resident Connection Pooling server routing (pooled, connection_class, purity).",
    },
    FieldDisposition {
        field: "proxy_auth",
        disposition: Disposition::Commented,
        help: "[profiles.proxy_auth] thin proxy authentication (proxy_user, target_schema).",
    },
    FieldDisposition {
        field: "app_context",
        disposition: Disposition::Commented,
        help: "[[profiles.app_context]] driver-level application-context triples applied at logon (redacted from diagnostics).",
    },
    FieldDisposition {
        field: "masking",
        disposition: Disposition::Commented,
        help: "[profiles.masking] result egress masking policy; mask_unknown_default must stay true unless complete catalog tagging is configured.",
    },
    FieldDisposition {
        field: "sql_policy",
        disposition: Disposition::Commented,
        help: "[profiles.sql_policy] Arc N admission policy; only deny, level-floor, and static predicate tightening effects are valid.",
    },
    FieldDisposition {
        field: "base",
        disposition: Disposition::Commented,
        help: "Name of a profile to inherit unset fields from (shallow-merge).",
    },
];

/// The serde field names dispositioned for the top-level config, in order.
#[must_use]
pub fn top_level_field_names() -> Vec<&'static str> {
    TOP_LEVEL_FIELD_DISPOSITIONS
        .iter()
        .map(|f| f.field)
        .collect()
}

/// The serde field names dispositioned for a connection profile, in order.
#[must_use]
pub fn connection_profile_field_names() -> Vec<&'static str> {
    CONNECTION_PROFILE_FIELD_DISPOSITIONS
        .iter()
        .map(|f| f.field)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AppContextConfig, AuditConfig, ConnectionProfile, DrcpRoutingConfig, HttpConfig, OciConfig,
        OperatingLevel, OracleMcpConfig, PoolConfig, ProxyAuthConfig, ResultMaskingConfig,
        SessionIdentityConfig, SqlPolicyConfig,
    };
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    /// The exact serde field-name set of a struct, obtained by serializing a
    /// FULLY-POPULATED instance (every `Option` = `Some`, so no
    /// `skip_serializing_if` hides a field) and reading the JSON object keys.
    fn serialized_field_names<T: serde::Serialize>(value: &T) -> BTreeSet<String> {
        let json = serde_json::to_value(value).expect("serialize to serde_json::Value");
        json.as_object()
            .expect("struct serializes to a JSON object")
            .keys()
            .cloned()
            .collect()
    }

    /// A `ConnectionProfile` with EVERY field populated. The explicit struct
    /// literal is itself a compile-time schema-drift guard: adding a field to
    /// `ConnectionProfile` breaks this literal until the field is dispositioned
    /// in [`CONNECTION_PROFILE_FIELD_DISPOSITIONS`].
    fn fully_populated_profile() -> ConnectionProfile {
        ConnectionProfile {
            name: "sample".to_owned(),
            description: Some("sample".to_owned()),
            connect_string: Some("host:1521/svc".to_owned()),
            username: Some("APP_RO".to_owned()),
            credential_ref: Some("env:ORACLE_SAMPLE_PASSWORD".to_owned()),
            login_script: Some(PathBuf::from("/dev/null")),
            login_statements: Some(vec!["ALTER SESSION SET NLS_LANGUAGE = english".to_owned()]),
            trusted_session_statements: Some(vec!["BEGIN NULL; END;".to_owned()]),
            call_timeout_seconds: Some(30),
            max_query_cost: Some(1_000),
            connect_timeout_seconds: Some(20),
            inactivity_timeout_seconds: Some(300),
            keepalive_minutes: Some(10),
            sdu: Some(8192),
            max_level: Some(OperatingLevel::ReadOnly),
            default_level: Some(OperatingLevel::ReadOnly),
            protected: Some(false),
            require_signed_tools: Some(false),
            read_only_standby: Some(false),
            mcp_exposed: Some(true),
            dashboard_ddl_workbench: Some(false),
            session_identity: Some(SessionIdentityConfig::default()),
            pool: Some(PoolConfig::default()),
            oci: Some(OciConfig::default()),
            drcp: Some(DrcpRoutingConfig::default()),
            proxy_auth: Some(ProxyAuthConfig::default()),
            app_context: Some(vec![AppContextConfig::default()]),
            masking: Some(ResultMaskingConfig::default()),
            sql_policy: Some(SqlPolicyConfig {
                version: 1,
                rules: Vec::new(),
            }),
            base: Some("base_profile".to_owned()),
        }
    }

    /// An `OracleMcpConfig` with every serde field present. `http`/`audit`/
    /// `profiles` always serialize; the two `Option`s are `Some` here.
    fn fully_populated_config() -> OracleMcpConfig {
        OracleMcpConfig {
            schema_version: 2,
            default_profile: Some("sample".to_owned()),
            monitor_profile: Some("monitor_ro".to_owned()),
            http: HttpConfig::default(),
            audit: AuditConfig::default(),
            profiles: Vec::new(),
        }
    }

    #[test]
    fn connection_profile_dispositions_cover_every_serde_field() {
        let actual = serialized_field_names(&fully_populated_profile());
        let documented: BTreeSet<String> = connection_profile_field_names()
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            documented,
            actual,
            "CONNECTION_PROFILE_FIELD_DISPOSITIONS must list exactly the serde \
             fields of ConnectionProfile (profile.rs:457-550). Missing from the \
             table: {:?}; listed but not a serde field: {:?}",
            actual.difference(&documented).collect::<Vec<_>>(),
            documented.difference(&actual).collect::<Vec<_>>(),
        );
        // The spec fixes the count at 30.
        assert_eq!(
            CONNECTION_PROFILE_FIELD_DISPOSITIONS.len(),
            30,
            "the design spec fixes ConnectionProfile at 30 serde fields"
        );
    }

    #[test]
    fn top_level_dispositions_cover_every_serde_field() {
        let actual = serialized_field_names(&fully_populated_config());
        let documented: BTreeSet<String> = top_level_field_names()
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            documented,
            actual,
            "TOP_LEVEL_FIELD_DISPOSITIONS must list exactly the serde fields of \
             OracleMcpConfig (lib.rs:83). Missing from the table: {:?}; listed \
             but not a serde field: {:?}",
            actual.difference(&documented).collect::<Vec<_>>(),
            documented.difference(&actual).collect::<Vec<_>>(),
        );
        assert_eq!(
            TOP_LEVEL_FIELD_DISPOSITIONS.len(),
            6,
            "the design spec fixes OracleMcpConfig at 6 serde fields"
        );
    }

    #[test]
    fn dispositions_are_internally_consistent() {
        // No duplicate field names; help strings non-empty; the two READ_ONLY
        // ceiling fields are SET (legible safety cap, never a default).
        for table in [
            CONNECTION_PROFILE_FIELD_DISPOSITIONS,
            TOP_LEVEL_FIELD_DISPOSITIONS,
        ] {
            let names: BTreeSet<&str> = table.iter().map(|f| f.field).collect();
            assert_eq!(names.len(), table.len(), "duplicate serde field in table");
            assert!(
                table.iter().all(|f| !f.help.trim().is_empty()),
                "every field needs a one-line help string"
            );
        }
        for field in ["max_level", "default_level"] {
            let entry = CONNECTION_PROFILE_FIELD_DISPOSITIONS
                .iter()
                .find(|f| f.field == field)
                .expect("ceiling field present");
            assert_eq!(
                entry.disposition,
                Disposition::Set,
                "{field} must be SET explicitly so the READ_ONLY safety ceiling is legible"
            );
        }
    }
}
