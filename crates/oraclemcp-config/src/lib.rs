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

use std::path::Path;

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use oraclemcp_error as error;
pub use oraclemcp_guard::OperatingLevel;
pub use profile::{ConnectionProfile, OciConfig, PoolConfig, ProfileMetadata, resolve_inheritance};

/// The config schema version this build understands. A config declaring a
/// higher version is rejected (forward-incompatible) rather than silently
/// mis-read.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Default environment-variable prefix for config overrides.
pub const ENV_PREFIX: &str = "ORACLEMCP_";

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
    /// Named connection profiles.
    #[serde(default)]
    pub profiles: Vec<ConnectionProfile>,
}

impl Default for OracleMcpConfig {
    fn default() -> Self {
        OracleMcpConfig {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            profiles: Vec::new(),
        }
    }
}

impl OracleMcpConfig {
    /// Build the layered [`Figment`] (defaults < `config.toml` < env), without
    /// extracting. Callers (the binary) may `.merge()` CLI overrides last —
    /// CLI has the highest precedence — before calling [`from_figment`].
    #[must_use]
    pub fn figment(config_path: Option<&Path>) -> Figment {
        let mut fig = Figment::from(Serialized::defaults(OracleMcpConfig::default()));
        if let Some(path) = config_path {
            fig = fig.merge(Toml::file(path));
        }
        fig.merge(Env::prefixed(ENV_PREFIX).split("__"))
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
        resolve_inheritance(&mut self.profiles)?;
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
        }
        Ok(self)
    }

    /// Look up a profile by name.
    #[must_use]
    pub fn profile(&self, name: &str) -> Option<&ConnectionProfile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    /// Non-secret metadata for every profile (`list_profiles`). No secret
    /// reference is ever included (plan §8.4).
    #[must_use]
    pub fn list_profiles(&self) -> Vec<ProfileMetadata> {
        self.profiles
            .iter()
            .map(ConnectionProfile::metadata)
            .collect()
    }
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
        assert!(cfg.profiles.is_empty());
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
    fn list_profiles_excludes_credentials() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            username = "svc_acct"
            credential_ref = "keyring:prod"
            "#,
        )
        .expect("loads");
        let json = serde_json::to_string(&cfg.list_profiles()).expect("serialize");
        assert!(!json.contains("keyring:prod"));
        assert!(!json.contains("svc_acct"));
        assert!(json.contains("prod:1521/svc"));
    }
}
