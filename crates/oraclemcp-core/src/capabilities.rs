//! The `oracle_capabilities` report (plan §8.1) — the zero-arg entry point an
//! agent calls first to discover the server's tools, operating level + gates,
//! connection/standby status, feature tiers, and version.
//!
//! Kept serializable as a **standalone document** (no transport/session types)
//! so the move to per-request `_meta` in a later MCP spec is cheap (§2.5).

use oraclemcp_db::{CloudStatus, PrivilegeProfile, ServerFeatures};
use oraclemcp_guard::OperatingLevel;
use serde::{Deserialize, Serialize};

use crate::tools::ToolDescriptor;

/// The MCP spec baseline this server implements (§2.5); the latest revision
/// it will offer during `initialize` version negotiation.
pub const PROTOCOL_VERSION: &str = "2025-11-25";

/// Every published MCP protocol revision this server accepts during
/// `initialize` version negotiation. Per the MCP lifecycle spec, when the
/// client requests one of these the server MUST respond with the same
/// version; anything else negotiates up to [`PROTOCOL_VERSION`].
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2024-11-05", "2025-03-26", "2025-06-18", PROTOCOL_VERSION];

/// The revision that introduced the `completions` server capability
/// (2025-03-26 changelog: "Added completions capability"). Advertising it to
/// an older-revision client would post-date that client's spec.
pub const COMPLETIONS_CAPABILITY_SINCE: &str = "2025-03-26";

/// The revision that made the `MCP-Protocol-Version` HTTP header mandatory on
/// every post-initialize request (2025-06-18 transport changelog).
pub const HTTP_PROTOCOL_VERSION_HEADER_REQUIRED_SINCE: &str = "2025-06-18";

/// Negotiate the protocol revision for an `initialize` request: echo a
/// supported requested version, otherwise offer the server's latest.
#[must_use]
pub fn negotiate_protocol_version(requested: Option<&str>) -> &'static str {
    requested
        .and_then(|requested| {
            SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .find(|supported| **supported == requested)
        })
        .copied()
        .unwrap_or(PROTOCOL_VERSION)
}

/// Whether a negotiated revision is at least `baseline`. MCP revisions are
/// ISO dates, so lexicographic order IS chronological order.
#[must_use]
pub fn revision_at_least(negotiated: &str, baseline: &str) -> bool {
    negotiated >= baseline
}

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
    /// Live server-capability probe (bead K2): driver-negotiated facts,
    /// best-effort version-derived inferences, and privilege-degradable
    /// edition/partitioning. Additive and observational — it never affects the
    /// fail-closed guard. `None` until a live connection is probed (or when the
    /// backend does not surface it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_features: Option<ServerFeatures>,
}

/// Tool-surface delivery features advertised by the server (bead K10).
///
/// This is the **TOOL-SURFACE** capability block: it describes what the tool
/// surface can do for *result delivery*. It is deliberately distinct from the
/// build [`FeatureTiers`] (which tools/transports are compiled in) and from the
/// connection-level K2 `server_features` probe (what the live Oracle server
/// negotiated). Purely additive and observational — it never affects the
/// fail-closed classifier; streaming/incremental fetch only change how an
/// already-proven read is DELIVERED.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSurfaceFeatures {
    /// `oracle_query` supports **incremental fetch**: a large read returns
    /// bounded pages plus an opaque `cursor`, and resuming with that cursor
    /// yields the next page BYTE-IDENTICAL to a single full fetch. Available on
    /// every transport.
    pub incremental_fetch: bool,
    /// `oracle_query` supports **streaming delivery** (`streaming=true`): the
    /// result is delivered incrementally after the existing read-only guard.
    /// Over HTTP/SSE, scalar/self-contained rowsets emit one `event: row` frame
    /// per row; values that require connection-owned materialization (LOBs,
    /// BFILEs, REF CURSORs) retain the cursor-chunked `event: chunk` fallback.
    /// This flag reflects that SSE transport, so it is `true` only when HTTP is
    /// available. Over stdio, `streaming=true` still returns the ordered chunks
    /// inline; see `incremental_fetch` for the transport-independent contract.
    pub streaming: bool,
}

/// Which build capability tiers are available (Oracle driver / engine intelligence).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureTiers {
    /// Whether this binary was built with the Oracle driver. This is a build
    /// capability, not a claim that any configured database is currently live;
    /// inspect [`CapabilitiesReport::connection`] for observed connection state.
    #[serde(rename = "built_with_live_db")]
    pub live_db: bool,
    /// Whether the PL/SQL intelligence engine is available (always true for the
    /// product binary).
    pub engine: bool,
    /// Whether the Streamable HTTP(S) transport is available.
    pub http_transport: bool,
}

/// One custom-tool definition the server deliberately did not load.
///
/// A skipped definition is never registered or executable. This is an
/// operator-facing availability observation, not an override for the guard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedCustomTool {
    /// Stable tool name when the definition parsed, or a file label otherwise.
    pub name: String,
    /// Redacted, actionable reason the definition was not loaded.
    pub reason: String,
}

/// The full, standalone capability document.
// `Eq` dropped with `ToolDescriptor::input_schema: Option<serde_json::Value>`
// (Value is not Eq); structural `PartialEq` is all this report needs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    /// Tool-surface delivery features (incremental fetch / streaming; bead K10).
    /// The TOOL-SURFACE capability block, distinct from `features` (build tiers)
    /// and `connection.server_features` (the K2 live-server probe).
    pub tool_features: ToolSurfaceFeatures,
    /// The connected account's probed privilege profile (dictionary tier,
    /// Diagnostics Pack, PL/Scope), once a session exists (§5.11, bead P2-9).
    /// `None` before connect — the agent learns which tiers degrade and why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileges: Option<PrivilegeProfile>,
    /// Cloud / Autonomous DB connectivity status (wallet vs IAM token; §9.1,
    /// bead P1-11). `None` when not a cloud target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<CloudStatus>,
    /// Operator-defined custom tools skipped during startup. Each listed entry
    /// is absent from discovery and execution; an empty list means no
    /// configuration-quality definition was skipped.
    #[serde(default)]
    pub skipped_custom_tools: Vec<SkippedCustomTool>,
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
            tool_features: ToolSurfaceFeatures {
                // Incremental fetch (cursor pagination) is transport-independent.
                incremental_fetch: true,
                // Row-by-row SSE streaming rides the HTTP transport; complex
                // values fall back to chunk frames over the same transport.
                streaming: features.http_transport,
            },
            features,
            privileges: None,
            cloud: None,
            skipped_custom_tools: Vec::new(),
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

    /// Attach the custom-tool definitions skipped during startup.
    #[must_use]
    pub fn with_skipped_custom_tools(mut self, skipped: Vec<SkippedCustomTool>) -> Self {
        self.skipped_custom_tools = skipped;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolTier;

    fn sample_tools() -> Vec<ToolDescriptor> {
        vec![ToolDescriptor::new(
            "oracle_capabilities",
            ToolTier::FoundationStatic,
            "Zero-arg entry point",
        )]
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
            json["features"]["built_with_live_db"],
            serde_json::json!(true)
        );
        assert!(json["features"].get("live_db").is_none());
        assert_eq!(
            json["tools"][0]["name"],
            serde_json::json!("oracle_capabilities")
        );
        assert_eq!(json["skipped_custom_tools"], serde_json::json!([]));
    }

    #[test]
    fn skipped_custom_tools_are_visible_without_changing_the_tool_surface() {
        let report = CapabilitiesReport::new(
            "0.1.0",
            sample_tools(),
            OperatingLevel::ReadOnly,
            FeatureTiers {
                live_db: true,
                engine: true,
                http_transport: false,
            },
        )
        .with_skipped_custom_tools(vec![SkippedCustomTool {
            name: "broken.toml".to_owned(),
            reason: "file is malformed".to_owned(),
        }]);
        assert_eq!(
            report.tools,
            sample_tools(),
            "a skip never changes built-ins"
        );
        let json = serde_json::to_value(report).expect("serialize");
        assert_eq!(json["skipped_custom_tools"][0]["name"], "broken.toml");
        assert_eq!(
            json["skipped_custom_tools"][0]["reason"],
            "file is malformed"
        );
    }

    #[test]
    fn tool_surface_features_advertise_incremental_fetch_and_transport_gated_streaming() {
        // K10: the TOOL-SURFACE block advertises incremental fetch (always) and
        // SSE streaming (HTTP transport only), distinct from the build
        // `features` tiers and the K2 connection `server_features` probe.
        let stdio = CapabilitiesReport::new(
            "0.1.0",
            sample_tools(),
            OperatingLevel::ReadOnly,
            FeatureTiers {
                live_db: true,
                engine: true,
                http_transport: false,
            },
        );
        assert!(stdio.tool_features.incremental_fetch);
        assert!(
            !stdio.tool_features.streaming,
            "SSE row/chunk streaming needs the HTTP transport"
        );
        let json = serde_json::to_value(&stdio).expect("serialize");
        assert_eq!(
            json["tool_features"]["incremental_fetch"],
            serde_json::json!(true)
        );
        assert_eq!(json["tool_features"]["streaming"], serde_json::json!(false));

        let http = CapabilitiesReport::new(
            "0.1.0",
            sample_tools(),
            OperatingLevel::ReadOnly,
            FeatureTiers {
                live_db: true,
                engine: true,
                http_transport: true,
            },
        );
        assert!(http.tool_features.incremental_fetch);
        assert!(http.tool_features.streaming, "HTTP exposes SSE streaming");
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
