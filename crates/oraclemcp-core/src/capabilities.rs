//! The `oracle_capabilities` report (plan §8.1) — the zero-arg entry point an
//! agent calls first to discover the server's tools, operating level + gates,
//! connection/standby status, feature tiers, and version.
//!
//! Kept serializable as a **standalone document** (no rmcp/session types) so the
//! move to per-request `_meta` in a later MCP spec is cheap (§2.5).

use oraclemcp_db::{CloudStatus, PrivilegeProfile};
use oraclemcp_guard::OperatingLevel;
use serde::{Deserialize, Serialize};

use crate::tools::ToolDescriptor;

/// The MCP spec baseline this server implements (§2.5).
pub const PROTOCOL_VERSION: &str = "2025-11-25";

/// The operating-level view in the capability report (§6.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatingLevelReport {
    /// The session's current level.
    pub current: OperatingLevel,
    /// The per-target ceiling (immutable on a `protected` profile).
    pub max: OperatingLevel,
    /// Whether escalation above `current` requires a human step-up confirmation.
    pub escalation_gated: bool,
    /// Whether the profile is `protected` (production, ceiling pinned).
    pub protected: bool,
    /// RFC-3339 expiry of an active elevation window, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elevation_expires_at: Option<String>,
}

/// Connection / standby / cloud status (§5.8, §9.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionStatus {
    /// Whether a live connection is currently active.
    pub connected: bool,
    /// The active profile name, if connected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Oracle server version, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
    /// Whether the target is a read-only standby (forces READ_ONLY).
    pub read_only_standby: bool,
}

/// Which capability tiers are available (live-DB / engine intelligence).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureTiers {
    /// Whether the Oracle driver is compiled in (live-DB capable).
    pub live_db: bool,
    /// Whether the PL/SQL intelligence engine is available (always true for the
    /// product binary).
    pub engine: bool,
    /// Whether the Streamable HTTP(S) transport is available.
    pub http_transport: bool,
}

/// The full, standalone capability document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitiesReport {
    /// Server name (`oraclemcp`).
    pub server_name: String,
    /// Server semantic version.
    pub server_version: String,
    /// The MCP protocol baseline.
    pub protocol_version: String,
    /// The advertised tool surface.
    pub tools: Vec<ToolDescriptor>,
    /// Operating-level state + gates.
    pub operating_level: OperatingLevelReport,
    /// Transports this build exposes.
    pub transports: Vec<String>,
    /// Connection / standby status.
    pub connection: ConnectionStatus,
    /// Feature tiers.
    pub features: FeatureTiers,
    /// The connected account's probed privilege profile (dictionary tier,
    /// Diagnostics Pack, PL/Scope), once a session exists (§5.11, bead P2-9).
    /// `None` before connect — the agent learns which tiers degrade and why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileges: Option<PrivilegeProfile>,
    /// Cloud / Autonomous DB connectivity status (wallet vs IAM token; §9.1,
    /// bead P1-11). `None` when not a cloud target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<CloudStatus>,
}

impl CapabilitiesReport {
    /// A read-only-default report for the given tool surface and feature flags.
    #[must_use]
    pub fn new(
        server_version: impl Into<String>,
        tools: Vec<ToolDescriptor>,
        max_level: OperatingLevel,
        features: FeatureTiers,
    ) -> Self {
        let mut transports = vec!["stdio".to_owned()];
        if features.http_transport {
            transports.push("http".to_owned());
        }
        CapabilitiesReport {
            server_name: "oraclemcp".to_owned(),
            server_version: server_version.into(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            tools,
            operating_level: OperatingLevelReport {
                current: OperatingLevel::ReadOnly,
                max: max_level,
                escalation_gated: true,
                protected: max_level == OperatingLevel::ReadOnly,
                elevation_expires_at: None,
            },
            transports,
            connection: ConnectionStatus::default(),
            features,
            privileges: None,
            cloud: None,
        }
    }

    /// Attach the probed privilege profile (from [`oraclemcp_db::probe_privileges`]).
    #[must_use]
    pub fn with_privileges(mut self, profile: PrivilegeProfile) -> Self {
        self.privileges = Some(profile);
        self
    }

    /// Attach the cloud / Autonomous DB connectivity status (§9.1, P1-11).
    #[must_use]
    pub fn with_cloud(mut self, cloud: CloudStatus) -> Self {
        self.cloud = Some(cloud);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolTier;

    fn sample_tools() -> Vec<ToolDescriptor> {
        vec![ToolDescriptor {
            name: "oracle_capabilities".to_owned(),
            tier: ToolTier::FoundationStatic,
            summary: "Zero-arg entry point".to_owned(),
        }]
    }

    #[test]
    fn report_shape_is_stable() {
        let report = CapabilitiesReport::new(
            "0.1.0",
            sample_tools(),
            OperatingLevel::ReadOnly,
            FeatureTiers {
                live_db: true,
                engine: true,
                http_transport: false,
            },
        );
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["server_name"], serde_json::json!("oraclemcp"));
        assert_eq!(json["protocol_version"], serde_json::json!("2025-11-25"));
        assert_eq!(
            json["operating_level"]["current"],
            serde_json::json!("READ_ONLY")
        );
        assert_eq!(
            json["operating_level"]["max"],
            serde_json::json!("READ_ONLY")
        );
        assert_eq!(
            json["operating_level"]["protected"],
            serde_json::json!(true)
        );
        assert_eq!(json["transports"], serde_json::json!(["stdio"]));
        assert_eq!(
            json["tools"][0]["name"],
            serde_json::json!("oracle_capabilities")
        );
    }

    #[test]
    fn http_transport_adds_transport_and_unprotects_high_ceiling() {
        let report = CapabilitiesReport::new(
            "0.1.0",
            sample_tools(),
            OperatingLevel::Ddl,
            FeatureTiers {
                live_db: true,
                engine: true,
                http_transport: true,
            },
        );
        assert_eq!(
            report.transports,
            vec!["stdio".to_owned(), "http".to_owned()]
        );
        assert!(!report.operating_level.protected);
        assert_eq!(report.operating_level.max, OperatingLevel::Ddl);
    }

    #[test]
    fn privileges_absent_until_probed_then_surfaced() {
        let base = CapabilitiesReport::new(
            "0.1.0",
            sample_tools(),
            OperatingLevel::ReadOnly,
            FeatureTiers {
                live_db: true,
                engine: true,
                http_transport: false,
            },
        );
        // Pre-connect: omitted from the document entirely.
        assert!(base.privileges.is_none());
        let json = serde_json::to_value(&base).expect("serialize");
        assert!(json.get("privileges").is_none(), "skipped when None");

        // Post-probe: the tier is surfaced so the agent knows what degrades.
        let probed = base.with_privileges(PrivilegeProfile {
            dictionary_tier: oraclemcp_db::DictionaryTier::All,
            diagnostics_pack: false,
            plscope: true,
        });
        let json = serde_json::to_value(&probed).expect("serialize");
        assert_eq!(
            json["privileges"]["dictionary_tier"],
            serde_json::json!("all")
        );
        assert_eq!(json["privileges"]["plscope"], serde_json::json!(true));
        assert_eq!(
            json["privileges"]["diagnostics_pack"],
            serde_json::json!(false)
        );
    }

    #[test]
    fn cloud_status_absent_until_set_then_surfaced() {
        let base = CapabilitiesReport::new(
            "0.1.0",
            sample_tools(),
            OperatingLevel::ReadOnly,
            FeatureTiers {
                live_db: true,
                engine: true,
                http_transport: false,
            },
        );
        assert!(serde_json::to_value(&base).unwrap().get("cloud").is_none());
        let report = base.with_cloud(oraclemcp_db::CloudStatus {
            mode: "wallet".to_owned(),
            autonomous: true,
            wallet_dir: Some("/wallets/adb".to_owned()),
        });
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["cloud"]["mode"], serde_json::json!("wallet"));
        assert_eq!(json["cloud"]["autonomous"], serde_json::json!(true));
    }

    #[test]
    fn report_roundtrips_as_standalone_document() {
        let report = CapabilitiesReport::new(
            "1.2.3",
            sample_tools(),
            OperatingLevel::ReadWrite,
            FeatureTiers {
                live_db: false,
                engine: true,
                http_transport: false,
            },
        );
        let s = serde_json::to_string(&report).expect("serialize");
        let back: CapabilitiesReport = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(report, back);
    }
}
