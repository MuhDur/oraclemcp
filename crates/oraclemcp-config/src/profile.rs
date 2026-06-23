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

const APP_CONTEXT_MAX_ENTRIES: usize = 64;
const APP_CONTEXT_MAX_NAMESPACE_CHARS: usize = 128;
const APP_CONTEXT_MAX_KEY_CHARS: usize = 128;
const APP_CONTEXT_MAX_VALUE_CHARS: usize = 4000;
const SDU_MIN_BYTES: u32 = 512;
const SDU_MAX_BYTES: u32 = u16::MAX as u32;
const DRCP_CONNECTION_CLASS_MAX_CHARS: usize = 128;

/// Thin session-pool settings (plan §10). Concrete with documented defaults.
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
        // statement_cache >= 50. This static default is the documented CEILING;
        // the cpu-derived clamp (min(configured, cpu*2+1)) is applied at pool
        // construction by `oraclemcp_db::PoolSettings::resolved` (B4).
        PoolConfig {
            max_size: 20,
            min_idle: 2,
            acquire_timeout_secs: 5,
            statement_cache_size: 50,
        }
    }
}

impl PoolConfig {
    fn validate(&self, profile: &str) -> Result<(), ConfigError> {
        if self.max_size == 0 {
            return Err(ConfigError::InvalidPool {
                profile: profile.to_owned(),
                field: "max_size",
                reason: "must be at least 1",
            });
        }
        if self.min_idle > self.max_size {
            return Err(ConfigError::InvalidPool {
                profile: profile.to_owned(),
                field: "min_idle",
                reason: "must be less than or equal to max_size",
            });
        }
        if self.acquire_timeout_secs == 0 {
            return Err(ConfigError::InvalidPool {
                profile: profile.to_owned(),
                field: "acquire_timeout_secs",
                reason: "must be at least 1",
            });
        }
        Ok(())
    }
}

/// OCI / Oracle Cloud (Autonomous DB) connection fields (plan §7.3, §9.1).
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OciConfig {
    /// Cloud wallet directory (`cwallet.sso` + `tnsnames.ora`) passed to the thin driver.
    pub wallet_location: Option<PathBuf>,
    /// Secret reference for encrypted-wallet passwords; never a literal value.
    pub wallet_password_ref: Option<String>,
    /// Override Oracle server-certificate DN matching (`ssl_server_dn_match`).
    pub ssl_server_dn_match: Option<bool>,
    /// Exact expected server-certificate DN (`ssl_server_cert_dn`).
    pub ssl_server_cert_dn: Option<String>,
    /// Override Oracle TCPS SNI behavior (`use_sni`).
    pub use_sni: Option<bool>,
    /// Authenticate with an OCI IAM database token instead of a password.
    pub use_iam_token: bool,
    /// The `~/.oci/config` profile name to use for the IAM token.
    pub iam_config_profile: Option<String>,
}

impl std::fmt::Debug for OciConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let wallet_location = self.wallet_location.as_ref().map(|_| "<redacted>");
        let wallet_password_ref = self.wallet_password_ref.as_ref().map(|_| "<redacted>");
        let ssl_server_cert_dn = self.ssl_server_cert_dn.as_ref().map(|_| "<redacted>");
        let iam_config_profile = self.iam_config_profile.as_ref().map(|_| "<redacted>");
        f.debug_struct("OciConfig")
            .field("wallet_location", &wallet_location)
            .field("wallet_password_ref", &wallet_password_ref)
            .field("ssl_server_dn_match", &self.ssl_server_dn_match)
            .field("ssl_server_cert_dn", &ssl_server_cert_dn)
            .field("use_sni", &self.use_sni)
            .field("use_iam_token", &self.use_iam_token)
            .field("iam_config_profile", &iam_config_profile)
            .finish()
    }
}

/// Supported thin proxy-authentication settings.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyAuthConfig {
    /// Authenticating account that owns `credential_ref`.
    pub proxy_user: Option<String>,
    /// Target schema/client identity granted `CONNECT THROUGH proxy_user`.
    pub target_schema: Option<String>,
}

impl ProxyAuthConfig {
    /// Trimmed authenticating proxy account, when configured.
    #[must_use]
    pub fn proxy_user(&self) -> Option<&str> {
        self.proxy_user
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// Trimmed target schema/client identity, when configured.
    #[must_use]
    pub fn target_schema(&self) -> Option<&str> {
        self.target_schema
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// Whether both required proxy-auth fields are present and non-empty.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.proxy_user().is_some() && self.target_schema().is_some()
    }
}

impl std::fmt::Debug for ProxyAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proxy_user = self.proxy_user.as_ref().map(|_| "<redacted>");
        let target_schema = self.target_schema.as_ref().map(|_| "<redacted>");
        f.debug_struct("ProxyAuthConfig")
            .field("proxy_user", &proxy_user)
            .field("target_schema", &target_schema)
            .finish()
    }
}

/// DRCP session purity for Oracle Database Resident Connection Pooling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrcpSessionPurity {
    /// Reuse an existing pooled server session when possible.
    #[default]
    Reuse,
    /// Request a fresh pooled server session.
    New,
}

/// Oracle Database Resident Connection Pooling routing settings.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DrcpRoutingConfig {
    /// Request a DRCP pooled server (`SERVER=POOLED`).
    pub pooled: bool,
    /// Optional DRCP connection class (`pool_connection_class`).
    pub connection_class: Option<String>,
    /// Optional DRCP session purity. Defaults to `reuse`.
    pub purity: DrcpSessionPurity,
}

impl DrcpRoutingConfig {
    /// Trimmed DRCP connection class, when configured.
    #[must_use]
    pub fn connection_class(&self) -> Option<&str> {
        self.connection_class
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn validate(&self, profile: &str) -> Result<(), ConfigError> {
        let Some(class) = self.connection_class.as_deref() else {
            return Ok(());
        };
        let class = class.trim();
        if !self.pooled {
            return Err(ConfigError::InvalidDrcp {
                profile: profile.to_owned(),
                field: "connection_class",
                reason: "requires pooled = true",
            });
        }
        if class.is_empty() {
            return Err(ConfigError::InvalidDrcp {
                profile: profile.to_owned(),
                field: "connection_class",
                reason: "must be non-empty when configured",
            });
        }
        if class.chars().count() > DRCP_CONNECTION_CLASS_MAX_CHARS {
            return Err(ConfigError::InvalidDrcp {
                profile: profile.to_owned(),
                field: "connection_class",
                reason: "is too long",
            });
        }
        if !class
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '$'))
        {
            return Err(ConfigError::InvalidDrcp {
                profile: profile.to_owned(),
                field: "connection_class",
                reason: "contains a character that is not safe in an EZConnect query parameter",
            });
        }
        Ok(())
    }
}

impl std::fmt::Debug for DrcpRoutingConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let connection_class = self.connection_class.as_ref().map(|_| "<redacted>");
        f.debug_struct("DrcpRoutingConfig")
            .field("pooled", &self.pooled)
            .field("connection_class", &connection_class)
            .field("purity", &self.purity)
            .finish()
    }
}

/// Driver-level application context applied during Oracle thin authentication.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppContextConfig {
    /// Oracle application context namespace.
    pub namespace: Option<String>,
    /// Oracle application context key/name.
    pub key: Option<String>,
    /// Context value. Treat as sensitive tenant/session material.
    pub value: Option<String>,
}

impl AppContextConfig {
    /// Trimmed namespace, when configured.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// Trimmed key/name, when configured.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// Value as authored. Empty values are allowed but bounded.
    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_deref().unwrap_or("")
    }

    /// Convert to the tuple accepted by the thin driver. Returns `None` if a
    /// required identity field is missing; validated profiles cannot hit that.
    #[must_use]
    pub fn driver_tuple(&self) -> Option<(String, String, String)> {
        Some((
            self.namespace()?.to_owned(),
            self.key()?.to_owned(),
            self.value().to_owned(),
        ))
    }

    pub(crate) fn validate_list(
        profile: &str,
        entries: &[AppContextConfig],
    ) -> Result<(), ConfigError> {
        if entries.len() > APP_CONTEXT_MAX_ENTRIES {
            return Err(ConfigError::InvalidAppContext {
                profile: profile.to_owned(),
                index: entries.len(),
                field: "app_context",
                reason: "exceeds the maximum entry count",
            });
        }
        for (index, entry) in entries.iter().enumerate() {
            entry.validate(profile, index)?;
        }
        Ok(())
    }

    fn validate(&self, profile: &str, index: usize) -> Result<(), ConfigError> {
        validate_present_component(profile, index, "namespace", self.namespace())?;
        validate_present_component(profile, index, "key", self.key())?;
        validate_len(
            profile,
            index,
            "namespace",
            self.namespace(),
            APP_CONTEXT_MAX_NAMESPACE_CHARS,
        )?;
        validate_len(profile, index, "key", self.key(), APP_CONTEXT_MAX_KEY_CHARS)?;
        validate_len(
            profile,
            index,
            "value",
            Some(self.value()),
            APP_CONTEXT_MAX_VALUE_CHARS,
        )
    }
}

fn validate_present_component(
    profile: &str,
    index: usize,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ConfigError> {
    if value.is_some() {
        Ok(())
    } else {
        Err(ConfigError::InvalidAppContext {
            profile: profile.to_owned(),
            index,
            field,
            reason: "must be non-empty",
        })
    }
}

fn validate_len(
    profile: &str,
    index: usize,
    field: &'static str,
    value: Option<&str>,
    max_chars: usize,
) -> Result<(), ConfigError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.chars().count() <= max_chars {
        Ok(())
    } else {
        Err(ConfigError::InvalidAppContext {
            profile: profile.to_owned(),
            index,
            field,
            reason: "is too long",
        })
    }
}

impl std::fmt::Debug for AppContextConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let namespace = self.namespace.as_ref().map(|_| "<redacted>");
        let key = self.key.as_ref().map(|_| "<redacted>");
        let value = self.value.as_ref().map(|_| "<redacted>");
        f.debug_struct("AppContextConfig")
            .field("namespace", &namespace)
            .field("key", &key)
            .field("value", &value)
            .finish()
    }
}

/// End-to-end Oracle session identity, applied to each physical connection.
///
/// Values here are operator-specific and intentionally profile-driven. They are
/// not exposed through profile metadata because they can identify users,
/// workstations, tools, or tenant conventions.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionIdentityConfig {
    /// Optional Oracle edition for Edition-Based Redefinition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
    /// Connect-time client program recorded by Oracle (`V$SESSION.PROGRAM`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// Connect-time client machine recorded by Oracle (`V$SESSION.MACHINE`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// Connect-time operating-system user recorded by Oracle (`V$SESSION.OSUSER`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_user: Option<String>,
    /// Connect-time terminal recorded by Oracle (`V$SESSION.TERMINAL`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<String>,
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

impl std::fmt::Debug for SessionIdentityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |value: &Option<String>| value.as_ref().map(|_| "<redacted>");
        f.debug_struct("SessionIdentityConfig")
            .field("edition", &redact(&self.edition))
            .field("program", &redact(&self.program))
            .field("machine", &redact(&self.machine))
            .field("os_user", &redact(&self.os_user))
            .field("terminal", &redact(&self.terminal))
            .field("module", &redact(&self.module))
            .field("action", &redact(&self.action))
            .field("client_identifier", &redact(&self.client_identifier))
            .field("client_info", &redact(&self.client_info))
            .field("driver_name", &redact(&self.driver_name))
            .finish()
    }
}

/// A single named Oracle connection profile, as written in
/// `~/.config/oraclemcp/profiles.toml`. Inheritable fields are `Option`;
/// [`resolve_inheritance`] merges a `base` chain and the accessors apply
/// defaults.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Optional Session Data Unit request size for the thin driver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdu: Option<u32>,
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
    /// Whether this profile is exposed to the MCP **served** surface (E5
    /// connection-scope isolation). PER-PROFILE OPT-OUT: a profile is exposed to
    /// agents **by default**; set `mcp_exposed = false` to hide it. A hidden
    /// profile is invisible to every agent-facing path — `oracle_list_profiles`,
    /// `oracle_switch_profile`, `oracle_search_objects`, and
    /// `completion/complete` all behave as if it does not exist. The CLI and the
    /// operator (`oraclemcp profiles`, `doctor`, `--profile`) always see and use
    /// every profile regardless of this flag. One profile's setting never affects
    /// another's (there is no global activation). This is a visibility/scoping
    /// convenience, **not** an access control — the real bound on what an exposed
    /// profile can do is `max_level`/`protected`/DB privileges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_exposed: Option<bool>,
    /// Optional per-connection Oracle session identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_identity: Option<SessionIdentityConfig>,
    /// Pool settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<PoolConfig>,
    /// OCI / cloud fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci: Option<OciConfig>,
    /// Optional Oracle DRCP server-routing fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drcp: Option<DrcpRoutingConfig>,
    /// Supported thin proxy-authentication settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_auth: Option<ProxyAuthConfig>,
    /// Driver-level application context triples applied at logon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_context: Option<Vec<AppContextConfig>>,
    /// Name of a profile to inherit unset fields from (shallow-merge).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
}

impl std::fmt::Debug for ConnectionProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |value: &Option<String>| value.as_ref().map(|_| "<redacted>");
        let redact_path = |value: &Option<PathBuf>| value.as_ref().map(|_| "<redacted>");
        let login_statement_count = self.login_statements.as_ref().map(Vec::len);
        let trusted_statement_count = self.trusted_session_statements.as_ref().map(Vec::len);
        let app_context_count = self.app_context.as_ref().map(Vec::len);
        f.debug_struct("ConnectionProfile")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("connect_string", &redact(&self.connect_string))
            .field("username", &redact(&self.username))
            .field("credential_ref", &redact(&self.credential_ref))
            .field("login_script", &redact_path(&self.login_script))
            .field("login_statement_count", &login_statement_count)
            .field("trusted_statement_count", &trusted_statement_count)
            .field("call_timeout_seconds", &self.call_timeout_seconds)
            .field("sdu", &self.sdu)
            .field("max_level", &self.max_level)
            .field("default_level", &self.default_level)
            .field("protected", &self.protected)
            .field("require_signed_tools", &self.require_signed_tools)
            .field("read_only_standby", &self.read_only_standby)
            .field("session_identity", &self.session_identity)
            .field("pool", &self.pool)
            .field("oci", &self.oci)
            .field("drcp", &self.drcp)
            .field("proxy_auth", &self.proxy_auth)
            .field("app_context_count", &app_context_count)
            .field("base", &self.base)
            .finish()
    }
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

    /// Whether this profile is exposed to the MCP served (agent-facing) surface
    /// (E5). Per-profile opt-out: defaults to `true` (exposed); only an explicit
    /// `mcp_exposed = false` hides it from
    /// `oracle_list_profiles`/`oracle_switch_profile`/search/completion. The
    /// CLI/operator still sees every profile regardless of this flag.
    #[must_use]
    pub fn mcp_exposed(&self) -> bool {
        // Per-profile opt-out: exposed by default; only an explicit `= false` hides.
        self.mcp_exposed.unwrap_or(true)
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
            sdu,
            max_level,
            default_level,
            protected,
            require_signed_tools,
            read_only_standby,
            mcp_exposed,
            session_identity,
            pool,
            oci,
            drcp,
            proxy_auth,
            app_context,
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
            pool: self.pool.clone().map(Into::into),
            max_level: self.max_level(),
            default_level: self.default_level(),
            protected: self.protected(),
            require_signed_tools: self.require_signed_tools(),
            read_only_standby: self.read_only_standby(),
            mcp_exposed: self.mcp_exposed(),
        }
    }

    pub(crate) fn validate_thin_routing(&self) -> Result<(), ConfigError> {
        if let Some(sdu) = self.sdu
            && !(SDU_MIN_BYTES..=SDU_MAX_BYTES).contains(&sdu)
        {
            return Err(ConfigError::InvalidSdu {
                profile: self.name.clone(),
                sdu,
                min: SDU_MIN_BYTES,
                max: SDU_MAX_BYTES,
            });
        }
        if let Some(drcp) = &self.drcp {
            drcp.validate(&self.name)?;
        }
        if let Some(pool) = &self.pool {
            pool.validate(&self.name)?;
        }
        Ok(())
    }
}

/// Non-secret profile-pool metadata for `list_profiles`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PoolMetadata {
    /// Active runtime strategy when this profile is selected.
    pub strategy: &'static str,
    /// Maximum stateless read connections in the local client-side pool.
    pub max_size: u32,
    /// Minimum idle stateless read connections kept warm.
    pub min_idle: u32,
    /// Seconds to wait for a stateless read-pool checkout before returning BUSY.
    pub acquire_timeout_secs: u64,
    /// Parsed statement-cache setting. The current thin bridge leaves this to
    /// the driver's built-in cache until a public setter is available.
    pub statement_cache_size: u32,
}

impl From<PoolConfig> for PoolMetadata {
    fn from(value: PoolConfig) -> Self {
        PoolMetadata {
            strategy: "hybrid_pool",
            max_size: value.max_size,
            min_idle: value.min_idle,
            acquire_timeout_secs: value.acquire_timeout_secs,
            statement_cache_size: value.statement_cache_size,
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
    /// Safe local pool metadata when `[profiles.pool]` is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool: Option<PoolMetadata>,
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
    /// Whether the profile is exposed to the MCP served (agent-facing) surface
    /// (E5). The CLI shows this for every profile; the served `oracle_list_profiles`
    /// only ever returns profiles where this is `true`.
    pub mcp_exposed: bool,
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
            sdu: None,
            max_level: None,
            default_level: None,
            protected: None,
            require_signed_tools: None,
            read_only_standby: None,
            mcp_exposed: None,
            session_identity: None,
            pool: None,
            oci: None,
            drcp: None,
            proxy_auth: None,
            app_context: None,
            base: None,
        }
    }

    #[test]
    fn oci_tls_fields_parse_strictly() {
        let cfg = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "tcps"
            connect_string = "tcps://adb.example.com/service"

            [profiles.oci]
            wallet_location = "/wallets/adb"
            wallet_password_ref = "env:WALLET_PASSWORD"
            ssl_server_dn_match = false
            ssl_server_cert_dn = "CN=db.example.com,O=Example,C=US"
            use_sni = true
            "#,
        )
        .expect("valid tls profile");

        let oci = cfg.profiles[0].oci.as_ref().expect("oci fields");
        assert_eq!(
            oci.wallet_location.as_deref(),
            Some(std::path::Path::new("/wallets/adb"))
        );
        assert_eq!(
            oci.wallet_password_ref.as_deref(),
            Some("env:WALLET_PASSWORD")
        );
        assert_eq!(oci.ssl_server_dn_match, Some(false));
        assert_eq!(
            oci.ssl_server_cert_dn.as_deref(),
            Some("CN=db.example.com,O=Example,C=US")
        );
        assert_eq!(oci.use_sni, Some(true));

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "tcps"
            connect_string = "tcps://adb.example.com/service"

            [profiles.oci]
            ssl_server_dn_matc = false
            "#,
        )
        .expect_err("misspelled tls field must be rejected");
        assert!(err.to_string().contains("ssl_server_dn_matc"));
    }

    #[test]
    fn proxy_auth_parse_and_validation_are_strict() {
        let cfg = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "proxy"
            connect_string = "localhost:1521/FREEPDB1"
            credential_ref = "env:PROXY_PASSWORD"

            [profiles.proxy_auth]
            proxy_user = "MCP_PROXY"
            target_schema = "APP_OWNER"
            "#,
        )
        .expect("valid proxy profile");

        let proxy = cfg.profiles[0].proxy_auth.as_ref().expect("proxy auth");
        assert_eq!(proxy.proxy_user(), Some("MCP_PROXY"));
        assert_eq!(proxy.target_schema(), Some("APP_OWNER"));

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "proxy"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.proxy_auth]
            proxy_user = "MCP_PROXY"
            "#,
        )
        .expect_err("target_schema is required");
        assert!(matches!(err, ConfigError::IncompleteProxyAuth(_)));

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "proxy"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.proxy_auth]
            proxy_user_name = "MCP_PROXY"
            target_schema = "APP_OWNER"
            "#,
        )
        .expect_err("misspelled proxy field must be rejected");
        assert!(err.to_string().contains("proxy_user_name"));
    }

    #[test]
    fn proxy_auth_rejects_conflicting_top_level_username() {
        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "proxy"
            connect_string = "localhost:1521/FREEPDB1"
            username = "OTHER_USER"

            [profiles.proxy_auth]
            proxy_user = "MCP_PROXY"
            target_schema = "APP_OWNER"
            "#,
        )
        .expect_err("username and proxy_user disagree");
        assert!(matches!(err, ConfigError::ProxyUsernameMismatch(_)));
        assert!(!err.to_string().contains("OTHER_USER"));
        assert!(!err.to_string().contains("MCP_PROXY"));
    }

    #[test]
    fn drcp_and_sdu_parse_and_validation_are_strict() {
        let cfg = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "routed"
            connect_string = "localhost:1521/FREEPDB1"
            sdu = 32768

            [profiles.drcp]
            pooled = true
            connection_class = "AGENTS_RO"
            purity = "new"
            "#,
        )
        .expect("valid routed profile");

        let profile = &cfg.profiles[0];
        assert_eq!(profile.sdu, Some(32_768));
        let drcp = profile.drcp.as_ref().expect("drcp");
        assert!(drcp.pooled);
        assert_eq!(drcp.connection_class(), Some("AGENTS_RO"));
        assert_eq!(drcp.purity, DrcpSessionPurity::New);

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "bad_sdu"
            connect_string = "localhost:1521/FREEPDB1"
            sdu = 1
            "#,
        )
        .expect_err("sdu below driver range is rejected");
        assert!(matches!(err, ConfigError::InvalidSdu { .. }));

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "bad_drcp"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.drcp]
            connection_class = "AGENTS&wallet_location=/private"
            "#,
        )
        .expect_err("connection_class without pooled=true is rejected");
        assert!(matches!(err, ConfigError::InvalidDrcp { .. }));
        assert!(!err.to_string().contains("AGENTS&wallet_location"));

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "bad_drcp"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.drcp]
            pooled = true
            connection_class = "AGENTS#fragment"
            "#,
        )
        .expect_err("unsafe connection_class character is rejected");
        assert!(matches!(err, ConfigError::InvalidDrcp { .. }));
        assert!(!err.to_string().contains("AGENTS#fragment"));

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "bad_drcp"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.drcp]
            pooled = true
            pool_connection_class = "AGENTS"
            "#,
        )
        .expect_err("misspelled drcp field must be rejected");
        assert!(err.to_string().contains("pool_connection_class"));
    }

    #[test]
    fn pool_parse_validation_defaults_and_metadata_are_strict() {
        let cfg = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "pooled"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.pool]
            max_size = 4
            min_idle = 1
            acquire_timeout_secs = 3
            statement_cache_size = 64
            "#,
        )
        .expect("valid pool profile");

        let pool = cfg.profiles[0].pool.as_ref().expect("pool");
        assert_eq!(pool.max_size, 4);
        assert_eq!(pool.min_idle, 1);
        assert_eq!(pool.acquire_timeout_secs, 3);
        assert_eq!(pool.statement_cache_size, 64);

        let metadata = cfg.profiles[0].metadata().pool.expect("pool metadata");
        assert_eq!(metadata.strategy, "hybrid_pool");
        assert_eq!(metadata.max_size, 4);
        assert_eq!(metadata.min_idle, 1);
        assert_eq!(metadata.acquire_timeout_secs, 3);
        assert_eq!(metadata.statement_cache_size, 64);

        let cfg = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "defaults"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.pool]
            "#,
        )
        .expect("defaulted pool profile");
        let pool = cfg.profiles[0].pool.as_ref().expect("default pool");
        assert_eq!(pool.max_size, 20);
        assert_eq!(pool.min_idle, 2);
        assert_eq!(pool.acquire_timeout_secs, 5);
        assert_eq!(pool.statement_cache_size, 50);

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "bad_pool"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.pool]
            max_size = 0
            "#,
        )
        .expect_err("max_size zero is rejected");
        assert!(matches!(
            err,
            ConfigError::InvalidPool {
                field: "max_size",
                ..
            }
        ));

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "bad_pool"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.pool]
            max_size = 2
            min_idle = 3
            "#,
        )
        .expect_err("min_idle above max_size is rejected");
        assert!(matches!(
            err,
            ConfigError::InvalidPool {
                field: "min_idle",
                ..
            }
        ));

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "bad_pool"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.pool]
            acquire_timeout_secs = 0
            "#,
        )
        .expect_err("zero acquire timeout is rejected");
        assert!(matches!(
            err,
            ConfigError::InvalidPool {
                field: "acquire_timeout_secs",
                ..
            }
        ));

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "bad_pool"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.pool]
            max = 4
            "#,
        )
        .expect_err("misspelled pool field must be rejected");
        assert!(err.to_string().contains("max"));
    }

    #[test]
    fn app_context_parse_validation_and_order_are_strict() {
        let cfg = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "ctx"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles.app_context]]
            namespace = "ORACLEMCP_CTX"
            key = "tenant_id"
            value = "tenant-123"

            [[profiles.app_context]]
            namespace = "ORACLEMCP_CTX"
            key = "request_id"
            value = "req-456"
            "#,
        )
        .expect("valid app context profile");

        let entries = cfg.profiles[0].app_context.as_ref().expect("app context");
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].driver_tuple(),
            Some((
                "ORACLEMCP_CTX".to_owned(),
                "tenant_id".to_owned(),
                "tenant-123".to_owned()
            ))
        );
        assert_eq!(
            entries[1].driver_tuple(),
            Some((
                "ORACLEMCP_CTX".to_owned(),
                "request_id".to_owned(),
                "req-456".to_owned()
            ))
        );

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "ctx"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles.app_context]]
            namespace = " "
            key = "tenant_id"
            value = "tenant-123"
            "#,
        )
        .expect_err("blank namespace is rejected");
        assert!(matches!(err, ConfigError::InvalidAppContext { .. }));
        assert!(!err.to_string().contains("tenant-123"));

        let err = crate::OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "ctx"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles.app_context]]
            namespace = "ORACLEMCP_CTX"
            key_name = "tenant_id"
            value = "tenant-123"
            "#,
        )
        .expect_err("misspelled app-context field must be rejected");
        assert!(err.to_string().contains("key_name"));
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
        prof.sdu = Some(32_768);
        prof.oci = Some(OciConfig {
            wallet_location: Some("/wallets/prod".into()),
            wallet_password_ref: Some("env:WALLET_PASSWORD".to_owned()),
            ssl_server_dn_match: Some(true),
            ssl_server_cert_dn: Some("CN=prod-db".to_owned()),
            use_sni: Some(true),
            use_iam_token: false,
            iam_config_profile: None,
        });
        prof.proxy_auth = Some(ProxyAuthConfig {
            proxy_user: Some("MCP_PROXY".to_owned()),
            target_schema: Some("APP_OWNER".to_owned()),
        });
        prof.drcp = Some(DrcpRoutingConfig {
            pooled: true,
            connection_class: Some("PRIVATE_CLASS".to_owned()),
            purity: DrcpSessionPurity::Reuse,
        });
        prof.app_context = Some(vec![AppContextConfig {
            namespace: Some("ORACLEMCP_CTX".to_owned()),
            key: Some("tenant_id".to_owned()),
            value: Some("tenant-123".to_owned()),
        }]);
        prof.require_signed_tools = Some(true);
        prof.session_identity = Some(SessionIdentityConfig {
            edition: None,
            program: Some("agent-program".to_owned()),
            machine: Some("workstation".to_owned()),
            os_user: Some("operator-os".to_owned()),
            terminal: Some("terminal-1".to_owned()),
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
        assert!(
            !json.contains("WALLET_PASSWORD")
                && !json.contains("/wallets/prod")
                && !json.contains("CN=prod-db"),
            "OCI wallet/TLS material leaked into metadata"
        );
        assert!(!json.contains("svc_acct"), "username leaked into metadata");
        assert!(
            !json.contains("MCP_PROXY") && !json.contains("APP_OWNER"),
            "proxy auth material leaked into metadata"
        );
        assert!(
            !json.contains("PRIVATE_CLASS") && !json.contains("drcp"),
            "DRCP routing material leaked into metadata"
        );
        assert!(
            !json.contains("ORACLEMCP_CTX")
                && !json.contains("tenant_id")
                && !json.contains("tenant-123"),
            "application context leaked into metadata"
        );
        assert!(
            !json.contains("operator")
                && !json.contains("local-client")
                && !json.contains("agent-program")
                && !json.contains("workstation")
                && !json.contains("operator-os")
                && !json.contains("terminal-1"),
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
    fn profile_debug_redacts_connect_wallet_tls_and_identity_values() {
        let mut prof = p("prod");
        prof.connect_string = Some("prod:1521/private_service".to_owned());
        prof.username = Some("svc_acct".to_owned());
        prof.credential_ref = Some("env:DB_PASSWORD".to_owned());
        prof.sdu = Some(32_768);
        prof.login_script = Some("/home/operator/login.sql".into());
        prof.login_statements = Some(vec![
            "ALTER SESSION SET CURRENT_SCHEMA = PRIVATE".to_owned(),
        ]);
        prof.trusted_session_statements =
            Some(vec!["BEGIN DBMS_OUTPUT.ENABLE(500000); END;".to_owned()]);
        prof.oci = Some(OciConfig {
            wallet_location: Some("/wallets/private".into()),
            wallet_password_ref: Some("env:WALLET_PASSWORD".to_owned()),
            ssl_server_dn_match: Some(true),
            ssl_server_cert_dn: Some("CN=private-db,O=Example,C=US".to_owned()),
            use_sni: Some(true),
            use_iam_token: false,
            iam_config_profile: Some("private-oci-profile".to_owned()),
        });
        prof.proxy_auth = Some(ProxyAuthConfig {
            proxy_user: Some("private-proxy-user".to_owned()),
            target_schema: Some("private-target-schema".to_owned()),
        });
        prof.drcp = Some(DrcpRoutingConfig {
            pooled: true,
            connection_class: Some("private-drcp-class".to_owned()),
            purity: DrcpSessionPurity::New,
        });
        prof.app_context = Some(vec![AppContextConfig {
            namespace: Some("private-namespace".to_owned()),
            key: Some("private-key".to_owned()),
            value: Some("private-value".to_owned()),
        }]);
        prof.session_identity = Some(SessionIdentityConfig {
            edition: Some("PRIVATE_EDITION".to_owned()),
            program: Some("private-program".to_owned()),
            machine: Some("private-machine".to_owned()),
            os_user: Some("private-os-user".to_owned()),
            terminal: Some("private-terminal".to_owned()),
            module: Some("private-module".to_owned()),
            action: Some("private-action".to_owned()),
            client_identifier: Some("private-client-id".to_owned()),
            client_info: Some("private-client-info".to_owned()),
            driver_name: Some("private-driver".to_owned()),
        });

        let rendered = format!("{prof:?}");
        for forbidden in [
            "prod:1521/private_service",
            "svc_acct",
            "DB_PASSWORD",
            "/home/operator/login.sql",
            "CURRENT_SCHEMA = PRIVATE",
            "DBMS_OUTPUT",
            "/wallets/private",
            "WALLET_PASSWORD",
            "CN=private-db",
            "private-oci-profile",
            "private-proxy-user",
            "private-target-schema",
            "private-drcp-class",
            "private-namespace",
            "private-key",
            "private-value",
            "PRIVATE_EDITION",
            "private-program",
            "private-machine",
            "private-os-user",
            "private-terminal",
            "private-module",
            "private-action",
            "private-client-id",
            "private-client-info",
            "private-driver",
        ] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
        assert!(rendered.contains("connect_string: Some"));
        assert!(rendered.contains("wallet_location: Some"));
        assert!(rendered.contains("ssl_server_cert_dn: Some"));
        assert!(rendered.contains("proxy_auth: Some"));
        assert!(rendered.contains("drcp: Some"));
        assert!(rendered.contains("app_context_count: Some(1)"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn child_inherits_session_identity_from_base() {
        let mut base = p("shared");
        base.session_identity = Some(SessionIdentityConfig {
            edition: Some("shared-edition".to_owned()),
            program: Some("shared-program".to_owned()),
            machine: Some("shared-machine".to_owned()),
            os_user: Some("shared-os-user".to_owned()),
            terminal: Some("shared-terminal".to_owned()),
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
        assert_eq!(identity.program.as_deref(), Some("shared-program"));
        assert_eq!(identity.machine.as_deref(), Some("shared-machine"));
        assert_eq!(identity.os_user.as_deref(), Some("shared-os-user"));
        assert_eq!(identity.terminal.as_deref(), Some("shared-terminal"));
        assert_eq!(identity.driver_name.as_deref(), Some("shared-driver"));
    }

    #[test]
    fn child_inherits_oci_tls_fields_from_base() {
        let mut base = p("shared");
        base.oci = Some(OciConfig {
            wallet_location: Some("/wallets/shared".into()),
            wallet_password_ref: Some("env:SHARED_WALLET_PASSWORD".to_owned()),
            ssl_server_dn_match: Some(false),
            ssl_server_cert_dn: Some("CN=shared-db".to_owned()),
            use_sni: Some(false),
            use_iam_token: false,
            iam_config_profile: None,
        });
        let mut child = p("dev");
        child.base = Some("shared".to_owned());
        let mut profiles = vec![base, child];
        resolve_inheritance(&mut profiles).expect("resolve");
        let oci = profiles[1].oci.as_ref().expect("inherited oci");
        assert_eq!(
            oci.wallet_location.as_deref(),
            Some(std::path::Path::new("/wallets/shared"))
        );
        assert_eq!(
            oci.wallet_password_ref.as_deref(),
            Some("env:SHARED_WALLET_PASSWORD")
        );
        assert_eq!(oci.ssl_server_dn_match, Some(false));
        assert_eq!(oci.ssl_server_cert_dn.as_deref(), Some("CN=shared-db"));
        assert_eq!(oci.use_sni, Some(false));
    }

    #[test]
    fn child_inherits_proxy_auth_from_base() {
        let mut base = p("shared");
        base.proxy_auth = Some(ProxyAuthConfig {
            proxy_user: Some("SHARED_PROXY".to_owned()),
            target_schema: Some("APP_OWNER".to_owned()),
        });
        let mut child = p("dev");
        child.base = Some("shared".to_owned());
        let mut profiles = vec![base, child];
        resolve_inheritance(&mut profiles).expect("resolve");
        let proxy = profiles[1].proxy_auth.as_ref().expect("inherited proxy");
        assert_eq!(proxy.proxy_user(), Some("SHARED_PROXY"));
        assert_eq!(proxy.target_schema(), Some("APP_OWNER"));
    }

    #[test]
    fn child_inherits_or_replaces_drcp_and_sdu_from_base() {
        let mut base = p("shared");
        base.sdu = Some(32_768);
        base.drcp = Some(DrcpRoutingConfig {
            pooled: true,
            connection_class: Some("SHARED_CLASS".to_owned()),
            purity: DrcpSessionPurity::Reuse,
        });
        let mut inherited = p("inherited");
        inherited.base = Some("shared".to_owned());
        let mut replaced = p("replaced");
        replaced.base = Some("shared".to_owned());
        replaced.sdu = Some(16_384);
        replaced.drcp = Some(DrcpRoutingConfig {
            pooled: false,
            connection_class: None,
            purity: DrcpSessionPurity::New,
        });

        let mut profiles = vec![base, inherited, replaced];
        resolve_inheritance(&mut profiles).expect("resolve");

        assert_eq!(profiles[1].sdu, Some(32_768));
        let inherited_drcp = profiles[1].drcp.as_ref().expect("inherited drcp");
        assert!(inherited_drcp.pooled);
        assert_eq!(inherited_drcp.connection_class(), Some("SHARED_CLASS"));

        assert_eq!(profiles[2].sdu, Some(16_384));
        let replaced_drcp = profiles[2].drcp.as_ref().expect("replaced drcp");
        assert!(!replaced_drcp.pooled);
        assert_eq!(replaced_drcp.connection_class(), None);
        assert_eq!(replaced_drcp.purity, DrcpSessionPurity::New);
    }

    #[test]
    fn child_inherits_or_replaces_app_context_from_base() {
        let mut base = p("shared");
        base.app_context = Some(vec![AppContextConfig {
            namespace: Some("BASE_CTX".to_owned()),
            key: Some("tenant_id".to_owned()),
            value: Some("base-tenant".to_owned()),
        }]);
        let mut inherited = p("inherited");
        inherited.base = Some("shared".to_owned());
        let mut replaced = p("replaced");
        replaced.base = Some("shared".to_owned());
        replaced.app_context = Some(vec![AppContextConfig {
            namespace: Some("CHILD_CTX".to_owned()),
            key: Some("tenant_id".to_owned()),
            value: Some("child-tenant".to_owned()),
        }]);
        let mut cleared = p("cleared");
        cleared.base = Some("shared".to_owned());
        cleared.app_context = Some(Vec::new());

        let mut profiles = vec![base, inherited, replaced, cleared];
        resolve_inheritance(&mut profiles).expect("resolve");

        let inherited_tuple = profiles[1].app_context.as_ref().unwrap()[0]
            .driver_tuple()
            .expect("tuple");
        assert_eq!(inherited_tuple.0, "BASE_CTX");
        assert_eq!(inherited_tuple.2, "base-tenant");

        let replaced_tuple = profiles[2].app_context.as_ref().unwrap()[0]
            .driver_tuple()
            .expect("tuple");
        assert_eq!(replaced_tuple.0, "CHILD_CTX");
        assert_eq!(replaced_tuple.2, "child-tenant");

        assert!(profiles[3].app_context.as_ref().unwrap().is_empty());
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
