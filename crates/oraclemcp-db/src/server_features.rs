//! Live server-capability probe surfaced in `oracle_capabilities` (bead K2).
//!
//! This block is **purely additive and observational**: it reports what the
//! thin driver negotiated with the server, a handful of best-effort
//! capability inferences derived from the server version, and — when the
//! account has the privilege — the database edition and whether Partitioning is
//! enabled. It does **not** touch, consult, or relax the fail-closed SQL guard:
//! nothing here decides what statements a session may run.
//!
//! # Three kinds of signal, three degrees of confidence
//!
//! 1. **Driver-negotiated facts** ([`ServerFeatures::sdu`],
//!    [`ServerFeatures::supports_pipelining`], [`ServerFeatures::supports_oob`],
//!    and the [`ServerVersion`] 5-tuple): read straight from the thin
//!    `oracledb` driver's own accessors at the connection seam. These are exact
//!    — they are the values the driver and server actually agreed on at connect
//!    time.
//! 2. **Version-derived inferences** ([`ServerFeatures::supports_vector`], …):
//!    pure version arithmetic over the server major version (see
//!    [`derive_version_capabilities`]). These are **best-effort**: they say "a
//!    server of this generation ships this feature", not "this specific
//!    instance has it licensed/installed/enabled". A `None` version tuple leaves
//!    every derived field `None`.
//! 3. **Dictionary-probed facts** ([`ServerFeatures::edition`],
//!    [`ServerFeatures::partitioning`]): one privilege-degradable dictionary
//!    query. A low-privilege account that cannot read the underlying views
//!    simply omits these two fields; the probe never fails the capabilities
//!    tool.

use serde::{Deserialize, Serialize};

/// AI Vector Search (the native `VECTOR` type + vector indexes/operators) was
/// introduced in **Oracle Database 23ai** (23c). Inferred for major >= 23.
/// Source: Oracle Database AI Vector Search User's Guide, 23ai — "Oracle AI
/// Vector Search is a feature of Oracle Database 23ai".
pub const VECTOR_MIN_MAJOR: u8 = 23;

/// The native SQL/JSON `JSON` data type was introduced in **Oracle Database
/// 21c**. Inferred for major >= 21. (JSON *functions* over `VARCHAR2`/`BLOB`
/// storage predate this — 12.1/12.2 — but the dedicated `JSON` type is 21c.)
/// Source: Oracle Database JSON Developer's Guide, 21c — "Starting with Oracle
/// Database 21c, a dedicated JSON data type … is available".
pub const JSON_MIN_MAJOR: u8 = 21;

/// The native SQL `BOOLEAN` data type (usable in tables and SQL, distinct from
/// the long-standing PL/SQL `BOOLEAN`) was introduced in **Oracle Database
/// 23ai** (23c). Inferred for major >= 23. Source: Oracle Database SQL Language
/// Reference, 23ai — "The BOOLEAN data type … new in Oracle Database 23ai".
pub const BOOLEAN_MIN_MAJOR: u8 = 23;

/// SODA (Simple Oracle Document Access) is version-gated at **Oracle Database
/// 18c** (18.3) for the modern thin drivers. Inferred for major >= 18. Source:
/// python-oracledb / node-oracledb SODA docs — "SODA … requires Oracle Database
/// 18.3 or later". This is a best-effort generation inference; a given 18c+
/// instance still needs the `SODA_APP` role granted to actually use it.
pub const SODA_MIN_MAJOR: u8 = 18;

/// The server database version, decoded from the driver's `AUTH_VERSION_NO`
/// negotiation as a 5-part tuple `(major, minor, patch, port_update,
/// port_patch)`. For an Oracle Database 23ai server this is `23.0.0.0.0`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerVersion {
    /// Major release (e.g. `23` for 23ai, `21` for 21c, `18` for 18c).
    pub major: u8,
    /// Maintenance release number.
    pub minor: u8,
    /// Application-server / fusion-middleware component number (the "patch"
    /// slot of the classic 5-part Oracle version).
    pub patch: u8,
    /// Component-specific update number.
    pub port_update: u8,
    /// Platform-specific patch number.
    pub port_patch: u8,
}

impl ServerVersion {
    /// Construct from the driver's `(major, minor, patch, port_update,
    /// port_patch)` tuple.
    #[must_use]
    pub const fn from_tuple(tuple: (u8, u8, u8, u8, u8)) -> Self {
        let (major, minor, patch, port_update, port_patch) = tuple;
        Self {
            major,
            minor,
            patch,
            port_update,
            port_patch,
        }
    }
}

/// The best-effort, version-derived capability inferences (kind 2 above). Each
/// is a pure function of the server major version; see the `*_MIN_MAJOR`
/// thresholds for the source of each cutoff.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedVersionCapabilities {
    /// AI Vector Search (`VECTOR` type) — inferred for 23ai+.
    pub supports_vector: bool,
    /// Native `JSON` data type — inferred for 21c+.
    pub supports_json: bool,
    /// Native SQL `BOOLEAN` data type — inferred for 23ai+.
    pub supports_boolean: bool,
    /// SODA document store — inferred for 18c+ (best-effort; needs `SODA_APP`).
    pub supports_soda: bool,
}

/// Infer generation-level feature availability from the server major version.
///
/// Pure version arithmetic, **no round-trip** — this is the cheap, high-value
/// core of the probe and is unit-tested exhaustively. The results are
/// best-effort: they describe what a server of this generation ships, not what
/// this specific instance has licensed/installed/enabled.
#[must_use]
pub fn derive_version_capabilities(major: u8) -> DerivedVersionCapabilities {
    DerivedVersionCapabilities {
        supports_vector: major >= VECTOR_MIN_MAJOR,
        supports_json: major >= JSON_MIN_MAJOR,
        supports_boolean: major >= BOOLEAN_MIN_MAJOR,
        supports_soda: major >= SODA_MIN_MAJOR,
    }
}

/// The `server_features` block of the `oracle_capabilities` report.
///
/// Every field is optional and omitted when unknown, so the block is fully
/// additive and degrades gracefully: no version tuple → no version/derived
/// fields; low privilege → no `edition`/`partitioning`. Assembled only for a
/// live connection at the connection seam.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerFeatures {
    /// Driver-negotiated server database version 5-tuple, when the server
    /// reported one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<ServerVersion>,
    /// Negotiated Session Data Unit (SDU) size in bytes, from the driver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdu: Option<usize>,
    /// Whether the server negotiated the END_OF_RESPONSE framing that is the
    /// prerequisite for pipelining (driver-reported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_pipelining: Option<bool>,
    /// Whether the server negotiated out-of-band break support (driver-reported;
    /// this thin driver still uses the in-band break regardless).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_oob: Option<bool>,
    /// Best-effort: native `VECTOR` / AI Vector Search (23ai+). `None` when the
    /// version is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_vector: Option<bool>,
    /// Best-effort: native `JSON` data type (21c+). `None` when the version is
    /// unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_json: Option<bool>,
    /// Best-effort: native SQL `BOOLEAN` data type (23ai+). `None` when the
    /// version is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_boolean: Option<bool>,
    /// Best-effort: SODA document store (18c+). `None` when the version is
    /// unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_soda: Option<bool>,
    /// Database edition / product descriptor (e.g. `Oracle Database 23ai Free`,
    /// `Oracle Database 21c Enterprise Edition`), from the dictionary. Omitted
    /// when the account cannot read the dictionary view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
    /// Whether the Partitioning option is enabled, from `v$option`. Omitted when
    /// the account cannot read the view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partitioning: Option<bool>,
}

impl ServerFeatures {
    /// Assemble the block from a live probe.
    ///
    /// - `version_tuple`: the driver's `server_version_tuple()` (the sole source
    ///   of the version and every derived inference).
    /// - `sdu` / `supports_pipelining` / `supports_oob`: the driver's negotiated
    ///   facts.
    /// - `edition` / `partitioning`: the dictionary-probed values, already
    ///   `None` when the privilege-degradable query returned nothing.
    #[must_use]
    pub fn from_probe(
        version_tuple: Option<(u8, u8, u8, u8, u8)>,
        sdu: usize,
        supports_pipelining: bool,
        supports_oob: bool,
        edition: Option<String>,
        partitioning: Option<bool>,
    ) -> Self {
        let version = version_tuple.map(ServerVersion::from_tuple);
        let derived = version.map(|v| derive_version_capabilities(v.major));
        Self {
            version,
            sdu: Some(sdu),
            supports_pipelining: Some(supports_pipelining),
            supports_oob: Some(supports_oob),
            supports_vector: derived.map(|d| d.supports_vector),
            supports_json: derived.map(|d| d.supports_json),
            supports_boolean: derived.map(|d| d.supports_boolean),
            supports_soda: derived.map(|d| d.supports_soda),
            edition,
            partitioning,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_23ai_gets_vector_boolean_json_soda() {
        let d = derive_version_capabilities(23);
        assert!(d.supports_vector, "23ai has AI Vector Search");
        assert!(d.supports_boolean, "23ai has native SQL BOOLEAN");
        assert!(d.supports_json, "23ai has the JSON type (>= 21c)");
        assert!(d.supports_soda, "23ai has SODA (>= 18c)");
    }

    #[test]
    fn derives_21c_gets_json_soda_but_not_vector_boolean() {
        let d = derive_version_capabilities(21);
        assert!(d.supports_json, "21c introduced the native JSON type");
        assert!(d.supports_soda, "21c has SODA (>= 18c)");
        assert!(!d.supports_vector, "vector is 23ai+, not 21c");
        assert!(!d.supports_boolean, "native SQL BOOLEAN is 23ai+, not 21c");
    }

    #[test]
    fn derives_18c_gets_soda_only() {
        let d = derive_version_capabilities(18);
        assert!(d.supports_soda, "18c is the SODA threshold");
        assert!(!d.supports_json, "native JSON type is 21c+, not 18c");
        assert!(!d.supports_vector);
        assert!(!d.supports_boolean);
    }

    #[test]
    fn derives_19c_gets_soda_only() {
        // 19c is the common long-term-support release: SODA yes, JSON type no.
        let d = derive_version_capabilities(19);
        assert!(d.supports_soda);
        assert!(!d.supports_json);
        assert!(!d.supports_vector);
        assert!(!d.supports_boolean);
    }

    #[test]
    fn derives_12c_gets_nothing() {
        let d = derive_version_capabilities(12);
        assert!(!d.supports_soda, "SODA threshold is 18c");
        assert!(!d.supports_json);
        assert!(!d.supports_vector);
        assert!(!d.supports_boolean);
    }

    #[test]
    fn thresholds_are_monotone_in_major_version() {
        // Every capability, once gained at its threshold, stays true for all
        // higher majors — the inference must never "lose" a feature by upgrade.
        for major in 0u8..=40 {
            let d = derive_version_capabilities(major);
            assert_eq!(d.supports_vector, major >= VECTOR_MIN_MAJOR);
            assert_eq!(d.supports_json, major >= JSON_MIN_MAJOR);
            assert_eq!(d.supports_boolean, major >= BOOLEAN_MIN_MAJOR);
            assert_eq!(d.supports_soda, major >= SODA_MIN_MAJOR);
        }
    }

    #[test]
    fn from_probe_with_23ai_tuple_populates_everything() {
        let f = ServerFeatures::from_probe(
            Some((23, 0, 0, 0, 0)),
            8192,
            true,
            false,
            Some("Oracle Database 23ai Free".to_owned()),
            Some(false),
        );
        assert_eq!(f.version, Some(ServerVersion::from_tuple((23, 0, 0, 0, 0))));
        assert_eq!(f.sdu, Some(8192));
        assert_eq!(f.supports_pipelining, Some(true));
        assert_eq!(f.supports_oob, Some(false));
        assert_eq!(f.supports_vector, Some(true));
        assert_eq!(f.supports_json, Some(true));
        assert_eq!(f.supports_boolean, Some(true));
        assert_eq!(f.supports_soda, Some(true));
        assert_eq!(f.edition.as_deref(), Some("Oracle Database 23ai Free"));
        assert_eq!(f.partitioning, Some(false));
    }

    #[test]
    fn from_probe_with_21c_tuple_infers_json_not_vector() {
        let f = ServerFeatures::from_probe(Some((21, 3, 0, 0, 0)), 8192, true, true, None, None);
        assert_eq!(f.supports_json, Some(true));
        assert_eq!(f.supports_vector, Some(false));
        assert_eq!(f.supports_boolean, Some(false));
        assert_eq!(f.supports_soda, Some(true));
        // Dictionary bits degraded (low privilege) → omitted from JSON.
        let json = serde_json::to_value(&f).expect("serialize");
        assert!(json.get("edition").is_none(), "edition omitted when None");
        assert!(
            json.get("partitioning").is_none(),
            "partitioning omitted when None"
        );
        // Driver + derived facts still present.
        assert_eq!(json["supports_json"], serde_json::json!(true));
        assert_eq!(json["version"]["major"], serde_json::json!(21));
    }

    #[test]
    fn from_probe_with_18c_tuple_infers_soda_only() {
        let f = ServerFeatures::from_probe(Some((18, 0, 0, 0, 0)), 8192, false, false, None, None);
        assert_eq!(f.supports_soda, Some(true));
        assert_eq!(f.supports_json, Some(false));
        assert_eq!(f.supports_vector, Some(false));
        assert_eq!(f.supports_boolean, Some(false));
    }

    #[test]
    fn none_version_tuple_degrades_derived_helpers() {
        // No version negotiated: every version-derived field is None (omitted),
        // but the driver-negotiated facts still report.
        let f = ServerFeatures::from_probe(None, 8192, true, false, None, None);
        assert!(f.version.is_none());
        assert!(f.supports_vector.is_none());
        assert!(f.supports_json.is_none());
        assert!(f.supports_boolean.is_none());
        assert!(f.supports_soda.is_none());
        assert_eq!(f.sdu, Some(8192));
        assert_eq!(f.supports_pipelining, Some(true));

        let json = serde_json::to_value(&f).expect("serialize");
        assert!(json.get("version").is_none(), "version omitted when None");
        assert!(json.get("supports_vector").is_none());
        assert!(json.get("supports_json").is_none());
        assert_eq!(json["sdu"], serde_json::json!(8192));
    }

    #[test]
    fn default_is_empty_and_serializes_to_empty_object() {
        let f = ServerFeatures::default();
        let json = serde_json::to_value(&f).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({}),
            "all fields omitted when unknown"
        );
    }

    #[test]
    fn round_trips_through_json() {
        let f = ServerFeatures::from_probe(
            Some((23, 0, 0, 0, 0)),
            8192,
            true,
            false,
            Some("Oracle Database 23ai Free".to_owned()),
            Some(true),
        );
        let s = serde_json::to_string(&f).expect("serialize");
        let back: ServerFeatures = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(f, back);
    }
}
