//! Named connection profiles (plan §8.4) with `base` inheritance.
//!
//! Inheritable scalar fields are modelled as `Option` so "unset" is
//! distinguishable from "explicitly set to the default" — that distinction is
//! what makes shallow-merge inheritance well-defined. After
//! [`resolve_inheritance`] fills each child from its `base` chain, accessor
//! methods apply the documented defaults (`max_level` / `default_level` default
//! to `READ_ONLY`, §6.6).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use oraclemcp_guard::OperatingLevel;
use serde::{Deserialize, Serialize};

use crate::ConfigError;

/// `r2d2`-style pool settings (plan §10). Concrete with documented defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PoolConfig {
    /// Maximum pooled connections.
    pub max_size: u32,
    /// Minimum idle connections kept warm.
    pub min_idle: u32,
    /// Seconds to wait for a connection before returning `BUSY`.
    pub acquire_timeout_secs: u64,
    /// Per-connection statement-cache size.
    pub statement_cache_size: u32,
}

impl Default for PoolConfig {
    fn default() -> Self {
        // Plan §10: max_size = min(cpu*2+1, 20), min_idle 2, acquire 5s,
        // statement_cache >= 50. The cpu-derived sizing is applied at pool
        // construction; the static default is the documented ceiling.
        PoolConfig {
            max_size: 20,
            min_idle: 2,
            acquire_timeout_secs: 5,
            statement_cache_size: 50,
        }
    }
}

/// OCI / Oracle Cloud (Autonomous DB) connection fields (plan §7.3, §9.1).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OciConfig {
    /// Cloud wallet directory (`cwallet.sso` + `tnsnames.ora`); sets `TNS_ADMIN`.
    pub wallet_location: Option<PathBuf>,
    /// Authenticate with an OCI IAM database token instead of a password.
    pub use_iam_token: bool,
    /// The `~/.oci/config` profile name to use for the IAM token.
    pub iam_config_profile: Option<String>,
}

/// End-to-end Oracle session identity, applied to each physical connection.
///
/// Values here are operator-specific and intentionally profile-driven. They are
/// not exposed through profile metadata because they can identify users,
/// workstations, tools, or tenant conventions.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionIdentityConfig {
    /// Optional Oracle edition for Edition-Based Redefinition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
    /// `DBMS_APPLICATION_INFO` module / `SYS_CONTEXT('USERENV','MODULE')`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// `DBMS_APPLICATION_INFO` action / `SYS_CONTEXT('USERENV','ACTION')`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// `DBMS_SESSION` client identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identifier: Option<String>,
    /// `DBMS_APPLICATION_INFO` client info.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_info: Option<String>,
    /// Driver name shown by Oracle connection-info views where supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_name: Option<String>,
}

/// A single named Oracle connection profile, as written in
/// `~/.config/oraclemcp/profiles.toml`. Inheritable fields are `Option`;
/// [`resolve_inheritance`] merges a `base` chain and the accessors apply
/// defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionProfile {
    /// Stable identifier the agent connects by (e.g. `"prod_ro"`).
    pub name: String,
    /// Friendly description shown in `list_profiles`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Oracle Net connect identifier: EZConnect (`host:port/service`),
    /// EZConnect-Plus (`tcps://…?wallet_location=…`), or a `tnsnames.ora` alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_string: Option<String>,
    /// Oracle username; `None` for wallet / OS-auth / OCI-IAM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Reference to the credential in a secrets backend (e.g.
    /// `"keyring:prod_ro"`). **Never** a literal secret; never surfaced in
    /// `list_profiles` metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    /// Path to a login script (`ALTER SESSION …`) run on lease acquire (§6.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_script: Option<PathBuf>,
    /// Inline login statements (allowlist-validated; §6.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_statements: Option<Vec<String>>,
    /// Trusted local session setup statements, run exactly as configured after
    /// guarded login statements. These are never agent supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_session_statements: Option<Vec<String>>,
    /// Optional per-round-trip Oracle call timeout, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_timeout_seconds: Option<u64>,
    /// The per-target operating-level ceiling (§6.6). Defaults to `READ_ONLY`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_level: Option<OperatingLevel>,
    /// The level a fresh session starts at. Defaults to `READ_ONLY`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_level: Option<OperatingLevel>,
    /// Production profile: the ceiling is pinned and immutable (§6.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<bool>,
    /// Require HMAC signatures for every operator-defined custom tool loaded
    /// with this profile. Protected profiles imply this even when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_signed_tools: Option<bool>,
    /// Force `READ_ONLY` regardless of profile (Active Data Guard standby).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_standby: Option<bool>,
    /// Optional per-connection Oracle session identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_identity: Option<SessionIdentityConfig>,
    /// Pool settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<PoolConfig>,
    /// OCI / cloud fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci: Option<OciConfig>,
    /// Name of a profile to inherit unset fields from (shallow-merge).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
}

impl ConnectionProfile {
    /// The effective operating-level ceiling (defaults to `READ_ONLY`).
    #[must_use]
    pub fn max_level(&self) -> OperatingLevel {
        self.max_level.unwrap_or(OperatingLevel::ReadOnly)
    }

    /// The effective starting level (defaults to `READ_ONLY`).
    #[must_use]
    pub fn default_level(&self) -> OperatingLevel {
        self.default_level.unwrap_or(OperatingLevel::ReadOnly)
    }

    /// Whether this is a `protected` (production) profile.
    #[must_use]
    pub fn protected(&self) -> bool {
        self.protected.unwrap_or(false)
    }

    /// Whether custom tool definitions must be signed for this profile.
    #[must_use]
    pub fn require_signed_tools(&self) -> bool {
        self.protected() || self.require_signed_tools.unwrap_or(false)
    }

    /// Whether this profile is flagged a read-only standby.
    #[must_use]
    pub fn read_only_standby(&self) -> bool {
        self.read_only_standby.unwrap_or(false)
    }

    /// The effective pool settings (defaults applied).
    #[must_use]
    pub fn pool(&self) -> PoolConfig {
        self.pool.clone().unwrap_or_default()
    }

    /// Fill every unset (`None`) field of `self` from `parent` — shallow-merge,
    /// child wins. `name` and `base` are never inherited.
    fn inherit_from(&mut self, parent: &ConnectionProfile) {
        macro_rules! inherit {
            ($($field:ident),* $(,)?) => {$(
                if self.$field.is_none() { self.$field = parent.$field.clone(); }
            )*};
        }
        inherit!(
            description,
            connect_string,
            username,
            credential_ref,
            login_script,
            login_statements,
            trusted_session_statements,
            call_timeout_seconds,
            max_level,
            default_level,
            protected,
            require_signed_tools,
            read_only_standby,
            session_identity,
            pool,
            oci,
        );
    }

    /// Non-sensitive metadata for `list_profiles` self-discovery. Deliberately
    /// omits connection strings, `credential_ref`, and `username` so local
    /// topology and secret references are never materialized into
    /// agent-visible output (plan §8.4).
    #[must_use]
    pub fn metadata(&self) -> ProfileMetadata {
        ProfileMetadata {
            name: self.name.clone(),
            description: self.description.clone(),
            is_default: false,
            call_timeout_seconds: self.call_timeout_seconds,
            max_level: self.max_level(),
            default_level: self.default_level(),
            protected: self.protected(),
            require_signed_tools: self.require_signed_tools(),
            read_only_standby: self.read_only_standby(),
        }
    }
}

/// Non-secret, agent-visible profile metadata (`list_profiles`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProfileMetadata {
    /// Profile name.
    pub name: String,
    /// Description, if any.
    pub description: Option<String>,
    /// Whether this is the configured startup default.
    pub is_default: bool,
    /// Optional per-round-trip Oracle call timeout, in seconds.
    pub call_timeout_seconds: Option<u64>,
    /// The operating-level ceiling.
    pub max_level: OperatingLevel,
    /// The starting operating level.
    pub default_level: OperatingLevel,
    /// Whether the profile is production-protected.
    pub protected: bool,
    /// Whether custom tools for this profile require HMAC signatures.
    pub require_signed_tools: bool,
    /// Whether the profile is a read-only standby.
    pub read_only_standby: bool,
}

/// Resolve `base` inheritance across all profiles, in place. Detects unknown
/// bases, inheritance cycles, and duplicate names. Each profile ends up with
/// its `base` chain merged in (child fields win).
pub fn resolve_inheritance(profiles: &mut [ConnectionProfile]) -> Result<(), ConfigError> {
    // Index by name; reject duplicates.
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    for (i, p) in profiles.iter().enumerate() {
        if index.insert(p.name.clone(), i).is_some() {
            return Err(ConfigError::DuplicateProfile(p.name.clone()));
        }
    }

    // Snapshot the raw (pre-merge) profiles so a child always inherits from the
    // *authored* parent values, independent of resolution order.
    let raw = profiles.to_vec();

    for i in 0..profiles.len() {
        // Walk this profile's base chain from child upward, detecting cycles
        // and unknown bases, collecting ancestors nearest-first.
        let mut chain: Vec<usize> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        seen.insert(raw[i].name.clone());
        let mut current_base = raw[i].base.clone();
        while let Some(base_name) = current_base {
            let &base_idx = index
                .get(&base_name)
                .ok_or_else(|| ConfigError::UnknownBase(raw[i].name.clone(), base_name.clone()))?;
            if !seen.insert(base_name.clone()) {
                return Err(ConfigError::InheritanceCycle(format!(
                    "{} -> {}",
                    raw[i].name, base_name
                )));
            }
            chain.push(base_idx);
            current_base = raw[base_idx].base.clone();
        }
        // Apply ancestors nearest-first; nearer ancestors win over farther ones
        // (and the child, already populated, wins over all — inherit only fills
        // None fields).
        for &ancestor in &chain {
            let parent = raw[ancestor].clone();
            profiles[i].inherit_from(&parent);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str) -> ConnectionProfile {
        ConnectionProfile {
            name: name.to_owned(),
            description: None,
            connect_string: None,
            username: None,
            credential_ref: None,
            login_script: None,
            login_statements: None,
            trusted_session_statements: None,
            call_timeout_seconds: None,
            max_level: None,
            default_level: None,
            protected: None,
            require_signed_tools: None,
            read_only_standby: None,
            session_identity: None,
            pool: None,
            oci: None,
            base: None,
        }
    }

    #[test]
    fn defaults_are_read_only() {
        let prof = p("dev");
        assert_eq!(prof.max_level(), OperatingLevel::ReadOnly);
        assert_eq!(prof.default_level(), OperatingLevel::ReadOnly);
        assert!(!prof.protected());
        assert!(!prof.require_signed_tools());
    }

    #[test]
    fn child_inherits_unset_fields_from_base() {
        let mut base = p("shared");
        base.connect_string = Some("host:1521/svc".to_owned());
        base.max_level = Some(OperatingLevel::ReadWrite);
        base.call_timeout_seconds = Some(30);
        let mut child = p("dev");
        child.base = Some("shared".to_owned());
        let mut profiles = vec![base, child];
        resolve_inheritance(&mut profiles).expect("resolve");
        let dev = &profiles[1];
        assert_eq!(dev.connect_string.as_deref(), Some("host:1521/svc"));
        assert_eq!(dev.max_level(), OperatingLevel::ReadWrite);
        assert_eq!(dev.call_timeout_seconds, Some(30));
    }

    #[test]
    fn child_overrides_base() {
        let mut base = p("shared");
        base.max_level = Some(OperatingLevel::Admin);
        let mut child = p("dev");
        child.base = Some("shared".to_owned());
        child.max_level = Some(OperatingLevel::ReadOnly);
        let mut profiles = vec![base, child];
        resolve_inheritance(&mut profiles).expect("resolve");
        assert_eq!(profiles[1].max_level(), OperatingLevel::ReadOnly);
    }

    #[test]
    fn unknown_base_is_rejected() {
        let mut child = p("dev");
        child.base = Some("nope".to_owned());
        let err = resolve_inheritance(&mut [child]).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownBase(_, _)));
    }

    #[test]
    fn inheritance_cycle_is_detected() {
        let mut a = p("a");
        a.base = Some("b".to_owned());
        let mut b = p("b");
        b.base = Some("a".to_owned());
        let err = resolve_inheritance(&mut [a, b]).unwrap_err();
        assert!(matches!(err, ConfigError::InheritanceCycle(_)));
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let err = resolve_inheritance(&mut [p("dup"), p("dup")]).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateProfile(_)));
    }

    #[test]
    fn metadata_omits_secret_reference() {
        let mut prof = p("prod");
        prof.connect_string = Some("prod:1521/svc".to_owned());
        prof.credential_ref = Some("keyring:prod".to_owned());
        prof.username = Some("svc_acct".to_owned());
        prof.require_signed_tools = Some(true);
        prof.session_identity = Some(SessionIdentityConfig {
            edition: None,
            module: Some("local-client".to_owned()),
            action: None,
            client_identifier: Some("operator".to_owned()),
            client_info: None,
            driver_name: None,
        });
        let meta = prof.metadata();
        let json = serde_json::to_string(&meta).expect("serialize");
        assert!(
            !json.contains("keyring:prod"),
            "credential_ref leaked into metadata"
        );
        assert!(!json.contains("svc_acct"), "username leaked into metadata");
        assert!(
            !json.contains("operator") && !json.contains("local-client"),
            "session identity leaked into metadata"
        );
        assert!(
            !json.contains("prod:1521/svc") && !json.contains("connect_string"),
            "connect string leaked into metadata"
        );
        assert!(
            json.contains("require_signed_tools"),
            "signing policy is safe profile metadata"
        );
    }

    #[test]
    fn child_inherits_session_identity_from_base() {
        let mut base = p("shared");
        base.session_identity = Some(SessionIdentityConfig {
            edition: Some("shared-edition".to_owned()),
            module: Some("shared-client".to_owned()),
            action: Some("inspect".to_owned()),
            client_identifier: Some("agent".to_owned()),
            client_info: None,
            driver_name: Some("shared-driver".to_owned()),
        });
        let mut child = p("dev");
        child.base = Some("shared".to_owned());
        let mut profiles = vec![base, child];
        resolve_inheritance(&mut profiles).expect("resolve");
        let identity = profiles[1]
            .session_identity
            .as_ref()
            .expect("inherited identity");
        assert_eq!(identity.module.as_deref(), Some("shared-client"));
        assert_eq!(identity.edition.as_deref(), Some("shared-edition"));
        assert_eq!(identity.driver_name.as_deref(), Some("shared-driver"));
    }

    #[test]
    fn child_inherits_custom_tool_signing_policy_from_base() {
        let mut base = p("shared");
        base.require_signed_tools = Some(true);
        let mut child = p("dev");
        child.base = Some("shared".to_owned());
        let mut profiles = vec![base, child];
        resolve_inheritance(&mut profiles).expect("resolve");
        assert!(profiles[1].require_signed_tools());
    }

    #[test]
    fn protected_profile_implies_signed_custom_tools() {
        let mut prod = p("prod");
        prod.protected = Some(true);
        assert!(prod.require_signed_tools());
    }
}
