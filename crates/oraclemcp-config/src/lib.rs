#![forbid(unsafe_code)]

//! Layered, validated configuration for the `oraclemcp` Oracle MCP server
//! (plan §5.9, §8.4; bead P0-2).
//!
//! One validated, versioned [`OracleMcpConfig`] with strict precedence —
//! built-in defaults < `config.toml` < environment (`ORACLEMCP_*`) < CLI
//! overrides — assembled with [`figment`]. Unknown keys are rejected
//! (`deny_unknown_fields`), validation runs at load (fail fast), and `base`
//! inheritance across connection profiles is resolved with cycle detection.

mod profile;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use oraclemcp_error as error;
pub use oraclemcp_guard::OperatingLevel;
pub use profile::{
    AppContextConfig, ConnectionProfile, DrcpRoutingConfig, DrcpSessionPurity, OciConfig,
    PoolConfig, PoolMetadata, ProfileMetadata, ProxyAuthConfig, SessionIdentityConfig,
    resolve_inheritance,
};

/// The config schema version this build understands. A config declaring a
/// higher version is rejected (forward-incompatible) rather than silently
/// mis-read.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 2;

/// Default environment-variable prefix for config overrides.
pub const ENV_PREFIX: &str = "ORACLEMCP_";
/// Environment variable that points at a specific TOML config file.
///
/// This is a launcher/control variable, not part of the config schema.
pub const CONFIG_PATH_ENV: &str = "ORACLEMCP_CONFIG";

const IGNORED_ENV_KEYS: &[&str] = &[
    "audit_key",
    "config",
    "custom_tools_hmac_key",
    "live_xe",
    "live_xe_contention",
    "log",
    "multi_db_live_xe",
    "phase0_lanes",
    "phase0_probes_per_lane",
    "stdio_token",
    "test_app_context",
    "test_drcp",
    "test_drcp_class",
    "test_dsn",
    "test_dsn_a",
    "test_dsn_b",
    "test_edition",
    "test_password",
    "test_password_a",
    "test_password_b",
    "test_proxy_target_schema",
    "test_proxy_user",
    "test_ssl_server_cert_dn",
    "test_ssl_server_dn_match",
    "test_user",
    "test_user_a",
    "test_user_b",
    "test_use_sni",
    "test_wallet_location",
    "test_wallet_password",
    "tools_dir",
];

fn default_schema_version() -> u32 {
    SUPPORTED_SCHEMA_VERSION
}

/// The validated top-level server configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleMcpConfig {
    /// Config schema version for upgrade migrations.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Optional profile name to use when the launcher does not pass
    /// `serve --profile <name>`. This keeps multi-client MCP config small.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    /// Optional least-privilege profile used for fleet-wide database
    /// observability such as `v$session` and DB evidence. When unset, the
    /// operator surface degrades to self-lane/local telemetry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor_profile: Option<String>,
    /// Native Streamable HTTP transport configuration.
    #[serde(default)]
    pub http: HttpConfig,
    /// Out-of-band, hash-chained, keyed-MAC audit log configuration.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Named connection profiles.
    #[serde(default)]
    pub profiles: Vec<ConnectionProfile>,
}

impl Default for OracleMcpConfig {
    fn default() -> Self {
        OracleMcpConfig {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            default_profile: None,
            monitor_profile: None,
            http: HttpConfig::default(),
            audit: AuditConfig::default(),
            profiles: Vec::new(),
        }
    }
}

/// Out-of-band durable audit configuration (plan §5.13, §6.4; bead A8).
///
/// The audit log is an append-only, hash-chained, HMAC-SHA256-signed JSONL file
/// written out-of-band of the Oracle session. `path` is where it lives;
/// `key_ref` is a secret-ref (mirrors `wallet_password_ref`: `env:VAR`,
/// `file:/path`, `keyring:service/account`, future `vault:...`, or dev-only
/// `literal:`) for the keyed MAC; `key_id` labels the active key for rotation.
/// When unset, the binary picks a safe default path and fails closed at startup
/// if an operating level above ReadOnly is reachable without a configured key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Append-only audit log file path. When `None`, the binary chooses a safe
    /// default under the XDG state home.
    pub path: Option<PathBuf>,
    /// Secret reference for the HMAC signing key
    /// (`env:`/`file:`/`keyring:`/future `vault:`/dev-only `literal:`).
    pub key_ref: Option<String>,
    /// Identifier of the active signing key, recorded in each record so the key
    /// can be rotated while old records keep verifying. Defaults to `default`.
    pub key_id: Option<String>,
    /// Optional shipping of the signed audit chain to an external WORM/SIEM
    /// destination (bead D2). **Off by default** — when `None`, nothing is
    /// forwarded and the auditor uses the local file sink alone.
    pub shipping: Option<AuditShippingConfig>,
}

impl AuditConfig {
    /// The configured key id, or the `"default"` label.
    #[must_use]
    pub fn key_id_or_default(&self) -> &str {
        self.key_id.as_deref().unwrap_or("default")
    }
}

/// Audit-log shipping configuration (bead D2): mirror each signed, durable
/// record to an external write-once-read-many (WORM) store and/or a SIEM
/// endpoint. The local signed chain stays authoritative; shipping is a
/// fail-safe mirror (a forwarding failure never loses the local record).
///
/// At least one destination (`worm_path` or `siem_endpoint`) must be set for the
/// shipping decorator to be installed; an empty config is rejected so a typo'd
/// `[audit.shipping]` table is not silently a no-op.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditShippingConfig {
    /// Append-only WORM mirror file path. Point it at a WORM-mounted volume or
    /// an object-lock bucket's sync directory. The mirror is byte-identical
    /// JSONL, so `oraclemcp audit verify <worm_path>` verifies it under the
    /// signing key.
    pub worm_path: Option<PathBuf>,
    /// SIEM HTTP(S) endpoint that receives one signed record per POST.
    pub siem_endpoint: Option<String>,
    /// SIEM wire format: `json` (default), `cef`, or `syslog`.
    pub siem_format: Option<String>,
    /// Secret reference for an outbound SIEM auth header value
    /// (`env:`/`file:`/`keyring:`/future `vault:`/dev-only `literal:`), e.g. a
    /// Splunk HEC token.
    pub siem_auth_header_ref: Option<String>,
    /// Header name for the SIEM auth value. Defaults to `Authorization`.
    pub siem_auth_header_name: Option<String>,
}

impl AuditShippingConfig {
    /// The configured SIEM format string, or the `"json"` default.
    #[must_use]
    pub fn siem_format_or_default(&self) -> &str {
        self.siem_format.as_deref().unwrap_or("json")
    }

    /// The SIEM auth header name, or the `Authorization` default.
    #[must_use]
    pub fn siem_auth_header_name_or_default(&self) -> &str {
        self.siem_auth_header_name
            .as_deref()
            .unwrap_or("Authorization")
    }

    /// Whether any destination is configured (a WORM path or a SIEM endpoint).
    #[must_use]
    pub fn has_destination(&self) -> bool {
        self.worm_path.is_some() || self.siem_endpoint.is_some()
    }

    /// Validate the shipping config: at least one destination, and SIEM auth
    /// only alongside a SIEM endpoint.
    ///
    /// # Errors
    /// Returns [`ConfigError::InvalidAuditShipping`] when no destination is set
    /// or a SIEM auth ref is given without an endpoint.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.has_destination() {
            return Err(ConfigError::InvalidAuditShipping {
                reason: "set at least one of audit.shipping.worm_path or \
                         audit.shipping.siem_endpoint",
            });
        }
        if self.siem_endpoint.is_none()
            && (self.siem_auth_header_ref.is_some() || self.siem_format.is_some())
        {
            return Err(ConfigError::InvalidAuditShipping {
                reason: "audit.shipping.siem_format / siem_auth_header_ref require \
                         audit.shipping.siem_endpoint",
            });
        }
        Ok(())
    }
}

/// Default idle TTL for stateful Streamable HTTP sessions.
pub const DEFAULT_HTTP_STATEFUL_IDLE_TTL_SECONDS: u64 = 900;

fn default_http_stateful_idle_ttl_seconds() -> u64 {
    DEFAULT_HTTP_STATEFUL_IDLE_TTL_SECONDS
}

/// Native Streamable HTTP transport configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    /// Allowed `Host` authorities beyond loopback.
    pub allowed_hosts: Vec<String>,
    /// Allowed browser `Origin` values beyond loopback origins.
    pub allowed_origins: Vec<String>,
    /// Prefer direct JSON responses for stateless requests.
    pub json_response: bool,
    /// Enable Streamable HTTP stateful session framing.
    pub stateful: bool,
    /// Seconds before an idle stateful session is reaped. The watchdog closes
    /// the owning lane by mailbox; it never touches the Oracle connection from
    /// the HTTP/listener thread. `0` disables idle reaping.
    #[serde(default = "default_http_stateful_idle_ttl_seconds")]
    pub stateful_idle_ttl_seconds: u64,
    /// Optional OAuth 2.1 resource-server protection for `/mcp`.
    pub oauth: Option<HttpOAuthConfig>,
    /// Optional mTLS client registry. Client-CA verification alone proves only
    /// certificate issuance; the leaf fingerprint must be listed here before it
    /// becomes a server-derived principal.
    pub mtls: HttpMtlsConfig,
    /// Optional TLS material for the native HTTPS listener.
    pub tls: Option<HttpTlsConfig>,
    /// Operator-authority policy for `/operator/v1`.
    pub operator: HttpOperatorConfig,
    /// Release gate for the browser Safe SQL Workbench. The workbench remains
    /// disabled unless this is explicitly enabled and the runtime profile
    /// ceiling still admits the requested operation.
    pub dashboard_workbench: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            json_response: false,
            stateful: false,
            stateful_idle_ttl_seconds: DEFAULT_HTTP_STATEFUL_IDLE_TTL_SECONDS,
            oauth: None,
            mtls: HttpMtlsConfig::default(),
            tls: None,
            operator: HttpOperatorConfig::default(),
            dashboard_workbench: false,
        }
    }
}

impl HttpConfig {
    /// Validate the HTTP transport config in isolation.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_non_empty_list("http.allowed_hosts", &self.allowed_hosts)?;
        validate_non_empty_list("http.allowed_origins", &self.allowed_origins)?;
        if let Some(oauth) = &self.oauth {
            oauth.validate()?;
        }
        self.mtls.validate()?;
        if let Some(tls) = &self.tls {
            tls.validate()?;
        }
        self.operator.validate()?;
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

/// Operator-authority policy for the native HTTP operator API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpOperatorConfig {
    /// Allow unauthenticated loopback requests from the local process owner to
    /// act as the single local operator. Authenticated principals still require
    /// an explicit `allowed_subjects` entry.
    #[serde(default = "default_true")]
    pub allow_loopback_owner: bool,
    /// Server-derived principal keys allowed to act as operator, such as
    /// `oauth:<stable-hash>` or `mtls:<certificate-fingerprint>`.
    pub allowed_subjects: Vec<String>,
}

impl Default for HttpOperatorConfig {
    fn default() -> Self {
        Self {
            allow_loopback_owner: true,
            allowed_subjects: Vec::new(),
        }
    }
}

impl HttpOperatorConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        for subject in &self.allowed_subjects {
            let Some((kind, stable_id)) = subject.split_once(':') else {
                return Err(ConfigError::InvalidOperator {
                    field: "http.operator.allowed_subjects",
                    reason: "entries must be server-derived keys like oauth:<stable-id> or mtls:<fingerprint>",
                });
            };
            if kind.trim().is_empty() || stable_id.trim().is_empty() {
                return Err(ConfigError::InvalidOperator {
                    field: "http.operator.allowed_subjects",
                    reason: "entries must have non-empty kind and stable id",
                });
            }
        }
        Ok(())
    }
}

/// mTLS application-identity registry for the native HTTP transport.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpMtlsConfig {
    /// Registered client leaf-certificate fingerprints. Values are SHA-256 over
    /// the DER leaf certificate and may be written as `sha256:<hex>` or `<hex>`.
    /// At runtime they become principal keys `mtls:sha256:<hex>`.
    pub client_fingerprints: Vec<String>,
}

impl HttpMtlsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = BTreeSet::new();
        for fingerprint in &self.client_fingerprints {
            let Some(normalized) = normalize_sha256_fingerprint(fingerprint) else {
                return Err(ConfigError::InvalidHttp {
                    field: "http.mtls.client_fingerprints",
                    reason: "entries must be sha256:<64 lowercase-or-uppercase hex chars>",
                });
            };
            if !seen.insert(normalized) {
                return Err(ConfigError::InvalidHttp {
                    field: "http.mtls.client_fingerprints",
                    reason: "entries must be unique",
                });
            }
        }
        Ok(())
    }
}

/// OAuth 2.1 resource-server configuration for the native HTTP transport.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpOAuthConfig {
    /// Canonical resource/audience identifier expected in JWT `aud`.
    pub resource: Option<String>,
    /// Allowed JWT issuers (`iss`). Empty means invalid config.
    pub allowed_issuers: Vec<String>,
    /// Authorization servers advertised in RFC 9728 metadata.
    pub authorization_servers: Vec<String>,
    /// Scopes that every token must carry before dispatch.
    pub required_scopes: Vec<String>,
    /// Secret reference used by the built-in HS256 verifier.
    pub hs256_secret_ref: Option<String>,
    /// Metadata URL advertised in `WWW-Authenticate`; defaults from resource.
    pub metadata_url: Option<String>,
}

impl HttpOAuthConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_required_string("http.oauth.resource", self.resource.as_deref())?;
        validate_non_empty_list("http.oauth.allowed_issuers", &self.allowed_issuers)?;
        validate_non_empty_list(
            "http.oauth.authorization_servers",
            &self.authorization_servers,
        )?;
        validate_non_empty_list("http.oauth.required_scopes", &self.required_scopes)?;
        validate_required_string(
            "http.oauth.hs256_secret_ref",
            self.hs256_secret_ref.as_deref(),
        )?;
        if let Some(metadata_url) = self.metadata_url.as_deref() {
            validate_required_string("http.oauth.metadata_url", Some(metadata_url))?;
        }
        Ok(())
    }
}

fn normalize_sha256_fingerprint(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    let hex = value.strip_prefix("sha256:").unwrap_or(&value);
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| format!("sha256:{hex}"))
}

/// TLS material paths for native HTTPS serving.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpTlsConfig {
    /// Server certificate chain PEM path.
    pub cert_chain_path: Option<PathBuf>,
    /// Server private key PEM path.
    pub private_key_path: Option<PathBuf>,
    /// Client CA PEM path. When present, mTLS is required.
    pub client_ca_path: Option<PathBuf>,
}

impl HttpTlsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let has_cert = self.cert_chain_path.is_some();
        let has_key = self.private_key_path.is_some();
        if has_cert != has_key {
            return Err(ConfigError::InvalidHttp {
                field: "http.tls",
                reason: "cert_chain_path and private_key_path must be configured together",
            });
        }
        if self.client_ca_path.is_some() && !has_cert {
            return Err(ConfigError::InvalidHttp {
                field: "http.tls.client_ca_path",
                reason: "requires cert_chain_path and private_key_path",
            });
        }
        Ok(())
    }
}

fn validate_required_string(field: &'static str, value: Option<&str>) -> Result<(), ConfigError> {
    match value.map(str::trim) {
        Some(value) if !value.is_empty() => Ok(()),
        _ => Err(ConfigError::InvalidHttp {
            field,
            reason: "must be non-empty",
        }),
    }
}

fn validate_non_empty_list(field: &'static str, values: &[String]) -> Result<(), ConfigError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(ConfigError::InvalidHttp {
            field,
            reason: "entries must be non-empty",
        });
    }
    Ok(())
}

impl OracleMcpConfig {
    /// Return the default config file if one is configured or present.
    ///
    /// Precedence:
    /// 1. `$ORACLEMCP_CONFIG`
    /// 2. `~/.config/oraclemcp/profiles.toml`
    /// 3. `~/.config/oraclemcp/config.toml`
    #[must_use]
    pub fn default_config_path() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os(CONFIG_PATH_ENV).map(PathBuf::from) {
            return Some(path);
        }
        let home = std::env::var_os("HOME").map(PathBuf::from)?;
        [
            home.join(".config").join("oraclemcp").join("profiles.toml"),
            home.join(".config").join("oraclemcp").join("config.toml"),
        ]
        .into_iter()
        .find(|path| path.is_file())
    }

    /// Build the layered [`Figment`] (defaults < `config.toml` < env), without
    /// extracting. Callers (the binary) may `.merge()` CLI overrides last —
    /// CLI has the highest precedence — before calling [`Self::from_figment`].
    #[must_use]
    pub fn figment(config_path: Option<&Path>) -> Figment {
        let mut fig = Figment::from(Serialized::defaults(OracleMcpConfig::default()));
        let discovered_path;
        let path = match config_path {
            Some(path) => Some(path),
            None => {
                discovered_path = Self::default_config_path();
                discovered_path.as_deref()
            }
        };
        if let Some(path) = path {
            fig = fig.merge(Toml::file(path));
        }
        fig.merge(
            Env::prefixed(ENV_PREFIX)
                .split("__")
                .ignore(IGNORED_ENV_KEYS),
        )
    }

    /// Extract and validate from a composed [`Figment`].
    pub fn from_figment(figment: &Figment) -> Result<Self, ConfigError> {
        let cfg: OracleMcpConfig = figment.extract().map_err(ConfigError::from)?;
        cfg.into_validated()
    }

    /// Load from an optional `config.toml` plus the environment (the common
    /// path). Use [`figment`](Self::figment) + [`from_figment`](Self::from_figment)
    /// to also layer CLI overrides.
    pub fn load(config_path: Option<&Path>) -> Result<Self, ConfigError> {
        Self::from_figment(&Self::figment(config_path))
    }

    /// Parse + validate directly from a TOML string (tests / embedding).
    pub fn from_toml_str(toml: &str) -> Result<Self, ConfigError> {
        let figment = Figment::from(Serialized::defaults(OracleMcpConfig::default()))
            .merge(Toml::string(toml));
        Self::from_figment(&figment)
    }

    /// Resolve inheritance and validate, consuming and returning `self`.
    fn into_validated(mut self) -> Result<Self, ConfigError> {
        if self.schema_version > SUPPORTED_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
        self.http.validate()?;
        if let Some(shipping) = self.audit.shipping.as_ref() {
            shipping.validate()?;
        }
        resolve_inheritance(&mut self.profiles)?;
        if let Some(default_profile) = self.default_profile.as_deref()
            && !self.profiles.iter().any(|p| p.name == default_profile)
        {
            return Err(ConfigError::UnknownDefaultProfile(
                default_profile.to_owned(),
            ));
        }
        if let Some(monitor_profile) = self.monitor_profile.as_deref()
            && !self.profiles.iter().any(|p| p.name == monitor_profile)
        {
            return Err(ConfigError::UnknownMonitorProfile(
                monitor_profile.to_owned(),
            ));
        }
        for prof in &self.profiles {
            match prof.connect_string.as_deref() {
                Some(s) if !s.trim().is_empty() => {}
                _ => return Err(ConfigError::MissingConnectString(prof.name.clone())),
            }
            // A protected (production) profile pins its ceiling at READ_ONLY
            // (§6.6); a higher max_level on a protected profile is a config
            // error, caught at load rather than silently weakening the lock.
            if prof.protected() && prof.max_level() != OperatingLevel::ReadOnly {
                return Err(ConfigError::ProtectedNotReadOnly(prof.name.clone()));
            }
            if prof.default_level() > prof.max_level() {
                return Err(ConfigError::DefaultLevelExceedsMax {
                    profile: prof.name.clone(),
                    default_level: prof.default_level(),
                    max_level: prof.max_level(),
                });
            }
            if let Some(proxy) = &prof.proxy_auth {
                let proxy_user = proxy
                    .proxy_user()
                    .ok_or_else(|| ConfigError::IncompleteProxyAuth(prof.name.clone()))?;
                proxy
                    .target_schema()
                    .ok_or_else(|| ConfigError::IncompleteProxyAuth(prof.name.clone()))?;
                if let Some(username) = prof.username.as_deref()
                    && username.trim() != proxy_user
                {
                    return Err(ConfigError::ProxyUsernameMismatch(prof.name.clone()));
                }
            }
            prof.validate_thin_routing()?;
            if let Some(entries) = &prof.app_context {
                AppContextConfig::validate_list(&prof.name, entries)?;
            }
        }
        Ok(self)
    }

    /// Look up a profile by name. This is the **operator/CLI** lookup: it sees
    /// every configured profile regardless of MCP exposure. The agent-facing
    /// served surface must use [`Self::mcp_profile`] instead, which fails closed
    /// on non-`mcp_exposed` profiles (E5).
    #[must_use]
    pub fn profile(&self, name: &str) -> Option<&ConnectionProfile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    /// Look up a profile by name for the MCP **served** surface (E5
    /// connection-scope isolation). Returns `None` — exactly as if the profile
    /// did not exist — for any profile hidden with `mcp_exposed = false`
    /// (per-profile opt-out; profiles are exposed by default). This is the gate
    /// the agent-facing dispatch (`oracle_switch_profile`, `oracle_search_objects`,
    /// `completion/complete`) routes profile lookups through, so a hidden or
    /// guessed name is never switchable, searchable, or completable.
    #[must_use]
    pub fn mcp_profile(&self, name: &str) -> Option<&ConnectionProfile> {
        self.profiles
            .iter()
            .find(|p| p.name == name && p.mcp_exposed())
    }

    /// Whether `name` is a configured profile exposed to the MCP served surface
    /// (E5). A hidden (`mcp_exposed = false`) or unknown name is
    /// indistinguishable: both return `false`.
    #[must_use]
    pub fn is_mcp_exposed(&self, name: &str) -> bool {
        self.mcp_profile(name).is_some()
    }

    /// Non-secret metadata for every profile (`profiles` CLI / operator view).
    /// No secret reference is ever included (plan §8.4). This includes
    /// non-`mcp_exposed` profiles, since the operator is allowed to see the full
    /// topology; the agent-facing surface uses [`Self::list_mcp_profiles`].
    #[must_use]
    pub fn list_profiles(&self) -> Vec<ProfileMetadata> {
        self.profiles
            .iter()
            .map(|profile| {
                let mut metadata = profile.metadata();
                metadata.is_default =
                    self.default_profile.as_deref() == Some(profile.name.as_str());
                metadata
            })
            .collect()
    }

    /// Non-secret metadata for only the MCP-exposed profiles (E5) — every profile
    /// except those hidden with `mcp_exposed = false`. This is what the served
    /// `oracle_list_profiles` tool returns; a hidden profile is omitted entirely
    /// (not redacted): it is invisible to the agent.
    #[must_use]
    pub fn list_mcp_profiles(&self) -> Vec<ProfileMetadata> {
        self.list_profiles()
            .into_iter()
            .filter(|metadata| metadata.mcp_exposed)
            .collect()
    }
}

/// Per-profile action a hot config reload may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReloadProfileAction {
    /// Existing lanes may keep using the profile.
    Retain,
    /// The profile is new and may be used by future lanes.
    Add,
    /// Existing lanes using this profile must drain; new lanes/switches are
    /// refused until they use a fresh compatible profile.
    Drain,
}

/// Why a profile received its reload action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReloadProfileReason {
    /// No effective fields changed.
    Unchanged,
    /// Only compatible local metadata changed.
    CompatibleMetadataChanged,
    /// The profile exists only in the new config.
    NewProfile,
    /// The profile was removed from the new config.
    Removed,
    /// Connection/session/security fields changed and require lane drain.
    IncompatibleChange,
}

/// One profile's reload decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReloadProfileDecision {
    /// Profile name.
    pub profile: String,
    /// Action to apply for active/new lanes.
    pub action: ReloadProfileAction,
    /// Reason for the action.
    pub reason: ReloadProfileReason,
}

/// A validated config-to-config reload plan.
///
/// This plan is deliberately conservative: profile changes that can affect the
/// Oracle connection, session setup, pool, served exposure, or operating-level
/// ceiling drain the profile. Cosmetic discovery metadata may be retained.
/// HTTP/audit/default-profile/monitor-profile changes are not hot-applied by the current
/// service process; callers should reject those reloads and ask for restart
/// rather than silently mutating live state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigReloadPlan {
    /// Whether this config transition may be hot-applied.
    pub hot_reloadable: bool,
    /// Reasons this transition requires a process restart instead of reload.
    pub restart_required: Vec<&'static str>,
    /// Stable profile decisions sorted by profile name.
    pub profiles: Vec<ReloadProfileDecision>,
}

impl ConfigReloadPlan {
    /// Build a reload plan between two already validated config snapshots.
    #[must_use]
    pub fn between(current: &OracleMcpConfig, next: &OracleMcpConfig) -> Self {
        let mut restart_required = Vec::new();
        if current.http != next.http {
            restart_required.push("http transport config changed");
        }
        if current.audit != next.audit {
            restart_required.push("audit config changed");
        }
        if current.default_profile != next.default_profile {
            restart_required.push("default_profile changed");
        }
        if current.monitor_profile != next.monitor_profile {
            restart_required.push("monitor_profile changed");
        }

        let current_profiles = profile_map(current);
        let next_profiles = profile_map(next);
        let names: BTreeSet<_> = current_profiles
            .keys()
            .chain(next_profiles.keys())
            .copied()
            .collect();
        let profiles = names
            .into_iter()
            .map(
                |name| match (current_profiles.get(name), next_profiles.get(name)) {
                    (Some(before), Some(after)) if before == after => ReloadProfileDecision {
                        profile: name.to_owned(),
                        action: ReloadProfileAction::Retain,
                        reason: ReloadProfileReason::Unchanged,
                    },
                    (Some(before), Some(after)) if profile_hot_reload_compatible(before, after) => {
                        ReloadProfileDecision {
                            profile: name.to_owned(),
                            action: ReloadProfileAction::Retain,
                            reason: ReloadProfileReason::CompatibleMetadataChanged,
                        }
                    }
                    (Some(_), Some(_)) => ReloadProfileDecision {
                        profile: name.to_owned(),
                        action: ReloadProfileAction::Drain,
                        reason: ReloadProfileReason::IncompatibleChange,
                    },
                    (Some(_), None) => ReloadProfileDecision {
                        profile: name.to_owned(),
                        action: ReloadProfileAction::Drain,
                        reason: ReloadProfileReason::Removed,
                    },
                    (None, Some(_)) => ReloadProfileDecision {
                        profile: name.to_owned(),
                        action: ReloadProfileAction::Add,
                        reason: ReloadProfileReason::NewProfile,
                    },
                    (None, None) => unreachable!("profile name came from one side"),
                },
            )
            .collect();

        Self {
            hot_reloadable: restart_required.is_empty(),
            restart_required,
            profiles,
        }
    }

    /// Profile names that must be marked draining.
    #[must_use]
    pub fn draining_profiles(&self) -> Vec<String> {
        self.profiles
            .iter()
            .filter(|decision| decision.action == ReloadProfileAction::Drain)
            .map(|decision| decision.profile.clone())
            .collect()
    }
}

fn profile_map(cfg: &OracleMcpConfig) -> BTreeMap<&str, &ConnectionProfile> {
    cfg.profiles
        .iter()
        .map(|profile| (profile.name.as_str(), profile))
        .collect()
}

fn profile_hot_reload_compatible(before: &ConnectionProfile, after: &ConnectionProfile) -> bool {
    before.name == after.name
        && before.connect_string == after.connect_string
        && before.username == after.username
        && before.credential_ref == after.credential_ref
        && before.login_script == after.login_script
        && before.login_statements == after.login_statements
        && before.trusted_session_statements == after.trusted_session_statements
        && before.call_timeout_seconds == after.call_timeout_seconds
        && before.connect_timeout_seconds == after.connect_timeout_seconds
        && before.sdu == after.sdu
        && before.max_level == after.max_level
        && before.default_level == after.default_level
        && before.protected == after.protected
        && before.require_signed_tools == after.require_signed_tools
        && before.read_only_standby == after.read_only_standby
        && before.mcp_exposed == after.mcp_exposed
        && before.dashboard_ddl_workbench == after.dashboard_ddl_workbench
        && before.session_identity == after.session_identity
        && before.pool == after.pool
        && before.oci == after.oci
        && before.drcp == after.drcp
        && before.proxy_auth == after.proxy_auth
        && before.app_context == after.app_context
}

/// Configuration load / validation error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// figment parse / extract failure (unknown keys, type errors, …).
    #[error("config error: {0}")]
    Figment(String),
    /// A profile has no usable `connect_string` after inheritance.
    #[error("connection profile `{0}` is missing a connect_string")]
    MissingConnectString(String),
    /// A profile's `base` names a profile that does not exist.
    #[error("connection profile `{0}` references unknown base `{1}`")]
    UnknownBase(String, String),
    /// A `base` inheritance cycle was detected.
    #[error("connection profile inheritance cycle: {0}")]
    InheritanceCycle(String),
    /// Two profiles share a name.
    #[error("duplicate connection profile name `{0}`")]
    DuplicateProfile(String),
    /// The configured default profile does not exist.
    #[error("default_profile references unknown profile `{0}`")]
    UnknownDefaultProfile(String),
    /// The configured monitor profile does not exist.
    #[error("monitor_profile references unknown profile `{0}`")]
    UnknownMonitorProfile(String),
    /// The config declares a newer schema than this build supports.
    #[error("unsupported config schema_version {found}; this build supports {supported}")]
    UnsupportedSchemaVersion {
        /// The version the config declared.
        found: u32,
        /// The version this build supports.
        supported: u32,
    },
    /// A `protected` profile declared a `max_level` above `READ_ONLY`.
    #[error("protected profile `{0}` must pin max_level = READ_ONLY (§6.6)")]
    ProtectedNotReadOnly(String),
    /// A profile's default operating level is above its immutable ceiling.
    #[error(
        "connection profile `{profile}` has default_level {default_level} above max_level {max_level}"
    )]
    DefaultLevelExceedsMax {
        /// Profile name.
        profile: String,
        /// Configured default level.
        default_level: OperatingLevel,
        /// Configured ceiling.
        max_level: OperatingLevel,
    },
    /// Proxy auth was enabled without both required identities.
    #[error("connection profile `{0}` proxy_auth requires non-empty proxy_user and target_schema")]
    IncompleteProxyAuth(String),
    /// Top-level username conflicts with `proxy_auth.proxy_user`.
    #[error("connection profile `{0}` proxy_auth.proxy_user must match username when both are set")]
    ProxyUsernameMismatch(String),
    /// A profile declared an SDU outside the thin driver's supported range.
    #[error("connection profile `{profile}` has invalid sdu {sdu}; expected {min}..={max}")]
    InvalidSdu {
        /// Profile name.
        profile: String,
        /// Configured SDU value.
        sdu: u32,
        /// Minimum supported SDU.
        min: u32,
        /// Maximum supported SDU.
        max: u32,
    },
    /// A profile declared invalid DRCP routing settings.
    #[error("connection profile `{profile}` has invalid drcp.{field}: {reason}")]
    InvalidDrcp {
        /// Profile name.
        profile: String,
        /// Field name.
        field: &'static str,
        /// Static validation reason.
        reason: &'static str,
    },
    /// A profile declared invalid local client-side pool settings.
    #[error("connection profile `{profile}` has invalid pool.{field}: {reason}")]
    InvalidPool {
        /// Profile name.
        profile: String,
        /// Field name.
        field: &'static str,
        /// Static validation reason.
        reason: &'static str,
    },
    /// Driver-level app-context entry is malformed.
    #[error("connection profile `{profile}` app_context[{index}].{field} {reason}")]
    InvalidAppContext {
        /// Profile name.
        profile: String,
        /// Entry index in the configured list.
        index: usize,
        /// Field name.
        field: &'static str,
        /// Validation failure.
        reason: &'static str,
    },
    /// Native HTTP transport configuration is malformed.
    #[error("invalid {field}: {reason}")]
    InvalidHttp {
        /// Field name.
        field: &'static str,
        /// Validation failure.
        reason: &'static str,
    },
    /// Operator-authority configuration is malformed.
    #[error("invalid {field}: {reason}")]
    InvalidOperator {
        /// Field name.
        field: &'static str,
        /// Validation failure.
        reason: &'static str,
    },
    /// Audit-log shipping configuration is malformed (bead D2).
    #[error("invalid audit.shipping: {reason}")]
    InvalidAuditShipping {
        /// Validation failure.
        reason: &'static str,
    },
}

impl From<figment::Error> for ConfigError {
    fn from(e: figment::Error) -> Self {
        ConfigError::Figment(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_valid_with_default_schema_version() {
        let cfg = OracleMcpConfig::from_toml_str("").expect("empty config loads");
        assert_eq!(cfg.schema_version, SUPPORTED_SCHEMA_VERSION);
        assert_eq!(cfg.http, HttpConfig::default());
        assert!(cfg.profiles.is_empty());
    }

    #[test]
    fn legacy_schema_v1_config_still_loads_after_v2_additive_fields() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            schema_version = 1

            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            "#,
        )
        .expect("schema v1 config loads");

        assert_eq!(cfg.schema_version, 1);
        assert!(!cfg.http.dashboard_workbench);
        assert!(cfg.monitor_profile.is_none());
        assert!(!cfg.profiles[0].dashboard_ddl_workbench());
    }

    #[test]
    fn schema_v2_dashboard_and_monitor_fields_load_and_validate() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            schema_version = 2
            default_profile = "app_ro"
            monitor_profile = "monitor_ro"

            [http]
            dashboard_workbench = true

            [[profiles]]
            name = "app_ro"
            connect_string = "app:1521/svc"
            dashboard_ddl_workbench = true

            [[profiles]]
            name = "monitor_ro"
            connect_string = "monitor:1521/svc"
            mcp_exposed = false
            "#,
        )
        .expect("schema v2 config loads");

        assert_eq!(cfg.schema_version, SUPPORTED_SCHEMA_VERSION);
        assert_eq!(cfg.monitor_profile.as_deref(), Some("monitor_ro"));
        assert!(cfg.http.dashboard_workbench);
        assert!(cfg.profile("app_ro").unwrap().dashboard_ddl_workbench());
    }

    #[test]
    fn unknown_monitor_profile_is_rejected() {
        let err = OracleMcpConfig::from_toml_str(
            r#"
            monitor_profile = "missing"

            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            "#,
        )
        .expect_err("unknown monitor profile rejected");

        assert!(matches!(err, ConfigError::UnknownMonitorProfile(name) if name == "missing"));
    }

    #[test]
    fn http_oauth_config_loads_and_validates() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [http]
            allowed_hosts = ["mcp.example.com"]
            allowed_origins = ["https://app.example.com"]
            json_response = true
            stateful = true
            stateful_idle_ttl_seconds = 60

            [http.oauth]
            resource = "https://mcp.example.com/mcp"
            allowed_issuers = ["https://idp.example.com"]
            authorization_servers = ["https://idp.example.com"]
            required_scopes = ["oracle:read"]
            hs256_secret_ref = "env:ORACLEMCP_OAUTH_HS256_SECRET"
            metadata_url = "https://mcp.example.com/.well-known/oauth-protected-resource"
            "#,
        )
        .expect("http oauth config loads");

        assert_eq!(cfg.http.allowed_hosts, vec!["mcp.example.com"]);
        assert!(cfg.http.stateful);
        assert_eq!(cfg.http.stateful_idle_ttl_seconds, 60);
        let oauth = cfg.http.oauth.expect("oauth config");
        assert_eq!(
            oauth.resource.as_deref(),
            Some("https://mcp.example.com/mcp")
        );
        assert_eq!(oauth.required_scopes, vec!["oracle:read"]);
    }

    #[test]
    fn http_operator_config_loads_and_validates() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [http.operator]
            allow_loopback_owner = false
            allowed_subjects = ["oauth:subject-hash", "mtls:cert-fingerprint"]
            "#,
        )
        .expect("operator config loads");

        assert!(!cfg.http.operator.allow_loopback_owner);
        assert_eq!(
            cfg.http.operator.allowed_subjects,
            vec!["oauth:subject-hash", "mtls:cert-fingerprint"]
        );
    }

    #[test]
    fn malformed_http_operator_subject_is_rejected() {
        let err = OracleMcpConfig::from_toml_str(
            r#"
            [http.operator]
            allowed_subjects = ["not-a-server-derived-key"]
            "#,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ConfigError::InvalidOperator {
                field: "http.operator.allowed_subjects",
                ..
            }
        ));
    }

    #[test]
    fn http_mtls_client_fingerprints_load_and_validate() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [http.mtls]
            client_fingerprints = [
              "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
              "FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100",
            ]
            "#,
        )
        .expect("mTLS client registry loads");

        assert_eq!(
            cfg.http.mtls.client_fingerprints,
            vec![
                "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100",
            ]
        );
    }

    #[test]
    fn malformed_http_mtls_fingerprint_is_rejected() {
        let err = OracleMcpConfig::from_toml_str(
            r#"
            [http.mtls]
            client_fingerprints = ["sha256:not-a-fingerprint"]
            "#,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ConfigError::InvalidHttp {
                field: "http.mtls.client_fingerprints",
                ..
            }
        ));
    }

    #[test]
    fn partial_http_oauth_config_is_rejected() {
        let err = OracleMcpConfig::from_toml_str(
            r#"
            [http.oauth]
            resource = "https://mcp.example.com/mcp"
            allowed_issuers = ["https://idp.example.com"]
            authorization_servers = ["https://idp.example.com"]
            "#,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidHttp {
                field: "http.oauth.hs256_secret_ref",
                ..
            }
        ));
    }

    #[test]
    fn half_configured_http_tls_is_rejected() {
        let err = OracleMcpConfig::from_toml_str(
            r#"
            [http.tls]
            cert_chain_path = "/etc/oraclemcp/server.pem"
            "#,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidHttp {
                field: "http.tls",
                ..
            }
        ));
    }

    #[test]
    fn profile_loads_and_defaults_to_read_only() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            "#,
        )
        .expect("loads");
        let dev = cfg.profile("dev").expect("dev profile");
        assert_eq!(dev.max_level(), OperatingLevel::ReadOnly);
        assert_eq!(dev.default_level(), OperatingLevel::ReadOnly);
        assert!(!dev.protected());
    }

    #[test]
    fn default_profile_must_reference_a_known_profile() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            default_profile = "dev"

            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            "#,
        )
        .expect("loads");
        assert_eq!(cfg.default_profile.as_deref(), Some("dev"));

        let err = OracleMcpConfig::from_toml_str(
            r#"
            default_profile = "missing"

            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::UnknownDefaultProfile(_)));
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        let err = OracleMcpConfig::from_toml_str("nonsense_key = 42").unwrap_err();
        assert!(matches!(err, ConfigError::Figment(_)), "got {err:?}");
    }

    #[test]
    fn unknown_profile_key_is_rejected() {
        let err = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "h:1521/s"
            wide_open = true
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Figment(_)), "got {err:?}");
    }

    #[test]
    fn missing_connect_string_is_rejected() {
        let err = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "dev"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::MissingConnectString(_)));
    }

    #[test]
    fn protected_profile_must_be_read_only() {
        let err = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            protected = true
            max_level = "DDL"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::ProtectedNotReadOnly(_)));
    }

    #[test]
    fn default_level_cannot_exceed_max_level() {
        let err = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "dev:1521/svc"
            max_level = "READ_WRITE"
            default_level = "DDL"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::DefaultLevelExceedsMax { .. }));
    }

    #[test]
    fn newer_schema_version_is_rejected() {
        let err = OracleMcpConfig::from_toml_str("schema_version = 999").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::UnsupportedSchemaVersion { found: 999, .. }
        ));
    }

    #[test]
    fn inheritance_resolves_through_base() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "shared"
            connect_string = "host:1521/svc"
            max_level = "READ_WRITE"

            [[profiles]]
            name = "dev"
            base = "shared"
            "#,
        )
        .expect("loads");
        let dev = cfg.profile("dev").expect("dev");
        assert_eq!(dev.connect_string.as_deref(), Some("host:1521/svc"));
        assert_eq!(dev.max_level(), OperatingLevel::ReadWrite);
    }

    #[test]
    // figment::Jail's closure return type (Result<(), figment::Error>) fixes a
    // large Err variant we cannot shrink; the lint is irrelevant in a test.
    #[allow(clippy::result_large_err)]
    fn env_overrides_toml_with_correct_precedence() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("ORACLEMCP_SCHEMA_VERSION", "1");
            let figment = Figment::from(Serialized::defaults(OracleMcpConfig::default()))
                .merge(Toml::string("schema_version = 1"))
                .merge(Env::prefixed(ENV_PREFIX).split("__"));
            let cfg = OracleMcpConfig::from_figment(&figment).expect("loads");
            assert_eq!(cfg.schema_version, 1);
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn load_discovers_profiles_toml_under_config_home() {
        figment::Jail::expect_with(|jail| {
            jail.create_dir(".config/oraclemcp")?;
            jail.create_file(
                ".config/oraclemcp/profiles.toml",
                r#"
                [[profiles]]
                name = "dev"
                connect_string = "localhost:1521/FREEPDB1"
                "#,
            )?;
            let home = jail.directory().display().to_string();
            jail.set_env("HOME", home);

            let cfg = OracleMcpConfig::load(None).expect("loads discovered profile");

            assert!(cfg.profile("dev").is_some());
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn launcher_env_vars_do_not_become_unknown_config_keys() {
        figment::Jail::expect_with(|jail| {
            let home = jail.directory().display().to_string();
            jail.set_env("HOME", home);
            jail.set_env("ORACLEMCP_LOG", "debug");
            jail.set_env("ORACLEMCP_STDIO_TOKEN", "token-for-stdio");
            jail.set_env("ORACLEMCP_TOOLS_DIR", "/tmp/oraclemcp-tools");
            jail.set_env("ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY", "test-hmac-key");
            jail.set_env("ORACLEMCP_LIVE_XE", "1");
            jail.set_env("ORACLEMCP_LIVE_XE_CONTENTION", "1");
            jail.set_env("ORACLEMCP_MULTI_DB_LIVE_XE", "1");
            jail.set_env("ORACLEMCP_PHASE0_LANES", "4");
            jail.set_env("ORACLEMCP_PHASE0_PROBES_PER_LANE", "2");
            jail.set_env("ORACLEMCP_TEST_DSN", "localhost:1521/FREEPDB1");
            jail.set_env("ORACLEMCP_TEST_USER", "ORACLEMCP_TEST");
            jail.set_env("ORACLEMCP_TEST_PASSWORD", "test-password");
            jail.set_env("ORACLEMCP_TEST_DSN_A", "localhost:1521/FREEPDB1");
            jail.set_env("ORACLEMCP_TEST_USER_A", "ORACLEMCP_TEST_A");
            jail.set_env("ORACLEMCP_TEST_PASSWORD_A", "test-password-a");
            jail.set_env("ORACLEMCP_TEST_DSN_B", "localhost:1523/FREEPDB1");
            jail.set_env("ORACLEMCP_TEST_USER_B", "ORACLEMCP_TEST_B");
            jail.set_env("ORACLEMCP_TEST_PASSWORD_B", "test-password-b");
            jail.set_env("ORACLEMCP_TEST_EDITION", "ORA$BASE");
            jail.set_env("ORACLEMCP_TEST_APP_CONTEXT", "NS:key:value");
            jail.set_env("ORACLEMCP_TEST_DRCP", "1");
            jail.set_env("ORACLEMCP_TEST_DRCP_CLASS", "ORACLEMCP");
            jail.set_env("ORACLEMCP_TEST_WALLET_LOCATION", "/tmp/wallet");
            jail.set_env("ORACLEMCP_TEST_WALLET_PASSWORD", "wallet-password");
            jail.set_env("ORACLEMCP_TEST_SSL_SERVER_DN_MATCH", "true");
            jail.set_env("ORACLEMCP_TEST_SSL_SERVER_CERT_DN", "CN=test");
            jail.set_env("ORACLEMCP_TEST_USE_SNI", "true");
            jail.set_env("ORACLEMCP_TEST_PROXY_USER", "PROXY_USER");
            jail.set_env("ORACLEMCP_TEST_PROXY_TARGET_SCHEMA", "TARGET_SCHEMA");

            let cfg = OracleMcpConfig::load(None).expect("control env vars are ignored");

            assert!(cfg.profiles.is_empty());
            Ok(())
        });
    }

    #[test]
    fn audit_config_loads_and_defaults_empty() {
        let cfg = OracleMcpConfig::from_toml_str("").expect("empty loads");
        assert_eq!(cfg.audit, AuditConfig::default());
        assert!(cfg.audit.path.is_none());
        assert_eq!(cfg.audit.key_id_or_default(), "default");

        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [audit]
            path = "/var/log/oraclemcp/audit.jsonl"
            key_ref = "env:ORACLEMCP_AUDIT_KEY"
            key_id = "2026-q2"
            "#,
        )
        .expect("audit config loads");
        assert_eq!(
            cfg.audit.path.as_deref(),
            Some(Path::new("/var/log/oraclemcp/audit.jsonl"))
        );
        assert_eq!(
            cfg.audit.key_ref.as_deref(),
            Some("env:ORACLEMCP_AUDIT_KEY")
        );
        assert_eq!(cfg.audit.key_id_or_default(), "2026-q2");
    }

    #[test]
    fn audit_shipping_is_off_by_default() {
        let cfg = OracleMcpConfig::from_toml_str("").expect("empty loads");
        assert!(
            cfg.audit.shipping.is_none(),
            "audit shipping is off by default (no [audit.shipping] table)"
        );
    }

    #[test]
    fn audit_shipping_worm_and_siem_load() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [audit]
            key_ref = "env:ORACLEMCP_AUDIT_KEY"

            [audit.shipping]
            worm_path = "/mnt/worm/oraclemcp-audit.jsonl"
            siem_endpoint = "https://siem.example.com/services/collector/raw"
            siem_format = "cef"
            siem_auth_header_ref = "env:SIEM_TOKEN"
            "#,
        )
        .expect("shipping config loads");
        let shipping = cfg.audit.shipping.expect("shipping present");
        assert_eq!(
            shipping.worm_path.as_deref(),
            Some(Path::new("/mnt/worm/oraclemcp-audit.jsonl"))
        );
        assert_eq!(
            shipping.siem_endpoint.as_deref(),
            Some("https://siem.example.com/services/collector/raw")
        );
        assert_eq!(shipping.siem_format_or_default(), "cef");
        assert_eq!(shipping.siem_auth_header_name_or_default(), "Authorization");
        assert!(shipping.has_destination());
        shipping.validate().expect("valid shipping config");
    }

    #[test]
    fn audit_shipping_requires_a_destination() {
        // An empty [audit.shipping] table is a likely typo (a no-op mirror), so
        // it is rejected rather than silently forwarding nothing.
        let err = OracleMcpConfig::from_toml_str(
            r#"
            [audit.shipping]
            "#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidAuditShipping { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn audit_shipping_siem_auth_requires_endpoint() {
        let err = OracleMcpConfig::from_toml_str(
            r#"
            [audit.shipping]
            worm_path = "/mnt/worm/a.jsonl"
            siem_auth_header_ref = "env:SIEM_TOKEN"
            "#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidAuditShipping { .. }),
            "SIEM auth without a SIEM endpoint is rejected, got {err:?}"
        );
    }

    #[test]
    fn unknown_audit_key_is_rejected() {
        let err = OracleMcpConfig::from_toml_str(
            r#"
            [audit]
            secret = "oops"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Figment(_)), "got {err:?}");
    }

    #[test]
    fn list_profiles_excludes_connection_and_credentials() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            default_profile = "prod"

            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            username = "svc_acct"
            credential_ref = "keyring:prod"

            [profiles.oci]
            wallet_password_ref = "file:/run/secrets/prod-wallet-password"
            "#,
        )
        .expect("loads");
        let json = serde_json::to_string(&cfg.list_profiles()).expect("serialize");
        assert!(!json.contains("keyring:prod"));
        assert!(!json.contains("/run/secrets/prod-wallet-password"));
        assert!(!json.contains("svc_acct"));
        assert!(!json.contains("prod:1521/svc"));
        assert!(!json.contains("connect_string"));
        assert!(json.contains("\"is_default\":true"));
    }

    #[test]
    fn mcp_exposure_defaults_open_and_hides_only_explicit_false() {
        // E5 per-profile opt-out: a profile is exposed by default; only an
        // explicit `mcp_exposed = false` hides it from the served surface. The
        // operator-facing list_profiles always sees both.
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "exposed_default"
            connect_string = "internal:1521/svc"

            [[profiles]]
            name = "hidden"
            connect_string = "ro:1521/svc"
            mcp_exposed = false
            "#,
        )
        .expect("loads");

        // Default-open: the unflagged profile is exposed; the `= false` one hidden.
        assert!(cfg.profile("exposed_default").unwrap().mcp_exposed());
        assert!(!cfg.profile("hidden").unwrap().mcp_exposed());
        assert!(cfg.mcp_profile("exposed_default").is_some());
        assert!(cfg.mcp_profile("hidden").is_none());
        assert!(cfg.is_mcp_exposed("exposed_default"));
        assert!(!cfg.is_mcp_exposed("hidden"));

        // A guessed/unknown name is indistinguishable from a hidden one.
        assert!(cfg.mcp_profile("does_not_exist").is_none());
        assert!(!cfg.is_mcp_exposed("does_not_exist"));

        // The served list shows only the exposed profile; the operator/CLI list
        // shows both.
        let served: Vec<String> = cfg
            .list_mcp_profiles()
            .iter()
            .map(|p| p.name.clone())
            .collect();
        assert_eq!(served, vec!["exposed_default".to_owned()]);
        let all: Vec<String> = cfg.list_profiles().iter().map(|p| p.name.clone()).collect();
        assert_eq!(all, vec!["exposed_default".to_owned(), "hidden".to_owned()]);
    }

    #[test]
    fn mcp_exposure_has_no_global_flip() {
        // Regression guard for the old footgun: one profile's setting must NOT
        // change another profile's exposure. With no flags, all are exposed; when
        // one profile sets `= false`, ONLY that one is hidden and the others stay
        // exposed (no global activation / allow-list flip).
        let none_flagged = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "a"
            connect_string = "db:1521/svc"

            [[profiles]]
            name = "b"
            connect_string = "db2:1521/svc"
            "#,
        )
        .expect("loads");
        assert!(none_flagged.is_mcp_exposed("a"));
        assert!(none_flagged.is_mcp_exposed("b"));

        let one_hidden = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "a"
            connect_string = "db:1521/svc"
            mcp_exposed = false

            [[profiles]]
            name = "b"
            connect_string = "db2:1521/svc"
            "#,
        )
        .expect("loads");
        assert!(
            !one_hidden.is_mcp_exposed("a"),
            "explicit false hides only a"
        );
        assert!(
            one_hidden.is_mcp_exposed("b"),
            "b stays exposed — one profile's flag never changes another's"
        );
    }

    #[test]
    fn mcp_exposed_inherits_through_base() {
        // E5: the exposure flag participates in base inheritance like other scalar
        // fields. A base that hides (`= false`) propagates to a child that does
        // not override it; an explicit child `= true` un-hides.
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "hidden_base"
            connect_string = "host:1521/svc"
            mcp_exposed = false

            [[profiles]]
            name = "inherits_hidden"
            base = "hidden_base"

            [[profiles]]
            name = "overrides_exposed"
            base = "hidden_base"
            mcp_exposed = true
            "#,
        )
        .expect("loads");
        assert!(
            cfg.mcp_profile("inherits_hidden").is_none(),
            "child inherits the base's hidden flag"
        );
        assert!(
            cfg.mcp_profile("overrides_exposed").is_some(),
            "child override re-exposes"
        );
    }

    fn reload_decision<'a>(plan: &'a ConfigReloadPlan, profile: &str) -> &'a ReloadProfileDecision {
        plan.profiles
            .iter()
            .find(|decision| decision.profile == profile)
            .unwrap_or_else(|| panic!("missing reload decision for {profile}"))
    }

    #[test]
    fn safe_config_reload_retains_cosmetic_profile_changes() {
        let before = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod_ro"
            description = "old label"
            connect_string = "prod:1521/svc"
            username = "APP"
            credential_ref = "env:APP_PASSWORD"
            "#,
        )
        .expect("before config");
        let after = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod_ro"
            description = "new label"
            connect_string = "prod:1521/svc"
            username = "APP"
            credential_ref = "env:APP_PASSWORD"
            "#,
        )
        .expect("after config");

        let plan = ConfigReloadPlan::between(&before, &after);

        assert!(plan.hot_reloadable);
        assert!(plan.draining_profiles().is_empty());
        let decision = reload_decision(&plan, "prod_ro");
        assert_eq!(decision.action, ReloadProfileAction::Retain);
        assert_eq!(
            decision.reason,
            ReloadProfileReason::CompatibleMetadataChanged
        );
    }

    #[test]
    fn safe_config_reload_drains_removed_or_incompatible_profiles_only() {
        let before = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "kept"
            connect_string = "kept:1521/svc"

            [[profiles]]
            name = "changed"
            connect_string = "old:1521/svc"
            credential_ref = "env:OLD_PASSWORD"

            [[profiles]]
            name = "removed"
            connect_string = "removed:1521/svc"
            "#,
        )
        .expect("before config");
        let after = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "kept"
            connect_string = "kept:1521/svc"

            [[profiles]]
            name = "changed"
            connect_string = "new:1521/svc"
            credential_ref = "env:NEW_PASSWORD"

            [[profiles]]
            name = "added"
            connect_string = "added:1521/svc"
            "#,
        )
        .expect("after config");

        let plan = ConfigReloadPlan::between(&before, &after);

        assert!(plan.hot_reloadable);
        assert_eq!(
            plan.draining_profiles(),
            vec!["changed".to_owned(), "removed".to_owned()]
        );
        assert_eq!(
            reload_decision(&plan, "kept").action,
            ReloadProfileAction::Retain
        );
        assert_eq!(
            reload_decision(&plan, "changed").reason,
            ReloadProfileReason::IncompatibleChange
        );
        assert_eq!(
            reload_decision(&plan, "removed").reason,
            ReloadProfileReason::Removed
        );
        assert_eq!(
            reload_decision(&plan, "added").action,
            ReloadProfileAction::Add
        );
    }

    #[test]
    fn safe_config_reload_drains_profile_exposure_or_ceiling_changes() {
        let before = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "agent_ro"
            connect_string = "ro:1521/svc"
            max_level = "READ_ONLY"
            mcp_exposed = true
            "#,
        )
        .expect("before config");
        let after = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "agent_ro"
            connect_string = "ro:1521/svc"
            max_level = "READ_WRITE"
            mcp_exposed = false
            "#,
        )
        .expect("after config");

        let plan = ConfigReloadPlan::between(&before, &after);

        assert_eq!(
            reload_decision(&plan, "agent_ro").action,
            ReloadProfileAction::Drain
        );
        assert_eq!(plan.draining_profiles(), vec!["agent_ro".to_owned()]);
    }

    #[test]
    fn safe_config_reload_rejects_top_level_hot_mutations() {
        let before = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "dev:1521/svc"
            "#,
        )
        .expect("before config");
        let after = OracleMcpConfig::from_toml_str(
            r#"
            default_profile = "dev"

            [http]
            stateful = true

            [[profiles]]
            name = "dev"
            connect_string = "dev:1521/svc"
            "#,
        )
        .expect("after config");

        let plan = ConfigReloadPlan::between(&before, &after);

        assert!(!plan.hot_reloadable);
        assert_eq!(
            plan.restart_required,
            vec!["http transport config changed", "default_profile changed"]
        );
        assert!(plan.draining_profiles().is_empty());
    }
}
