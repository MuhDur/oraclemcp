//! Versioned `/operator/v1` protocol contract.
//!
//! The HTTP router serves these shapes directly, and the generated schema/TS
//! artifacts are compared against this module in tests. Keep this file as the
//! Rust source of truth for operator UI contracts.

use std::fmt::Write as _;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// Operator API protocol version served under `/operator/v1`.
pub const OPERATOR_PROTOCOL_VERSION: &str = "operator.v1";
/// Operator API response/event schema version.
pub const OPERATOR_SCHEMA_VERSION: u16 = 1;
/// Redaction policy label for every operator route/event.
pub const OPERATOR_REDACTION_LEVEL: &str = "operator_redacted";
/// Published operator schema artifact path.
pub const OPERATOR_SCHEMA_ARTIFACT: &str = "schemas/operator.schema.json";
/// Generated TypeScript types consumed by the future dashboard SPA.
pub const OPERATOR_TS_ARTIFACT: &str = "ui/generated/operator-v1.ts";
/// Captured UI fixtures validated against this Rust contract.
pub const OPERATOR_UI_FIXTURE_DIR: &str = "tests/fixtures/ui/operator-v1";

/// Static route metadata included in the schema bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorRouteSpec {
    /// HTTP method.
    pub method: &'static str,
    /// Absolute route path.
    pub path: &'static str,
    /// Response/event schema name in the bundle `$defs`.
    pub schema: &'static str,
    /// Whether this route uses Server-Sent Events.
    pub sse: bool,
    /// MCP tool this route maps to, for gated action routes.
    pub mcp_tool: Option<&'static str>,
}

/// The `/operator/v1` route table.
pub const OPERATOR_ROUTE_SPECS: &[OperatorRouteSpec] = &[
    OperatorRouteSpec {
        method: "GET",
        path: "/operator/v1",
        schema: "routeIndexResponse",
        sse: false,
        mcp_tool: None,
    },
    OperatorRouteSpec {
        method: "GET",
        path: "/operator/v1/schema",
        schema: "operatorSchemaBundle",
        sse: false,
        mcp_tool: None,
    },
    OperatorRouteSpec {
        method: "GET",
        path: "/operator/v1/health",
        schema: "healthResponse",
        sse: false,
        mcp_tool: None,
    },
    OperatorRouteSpec {
        method: "GET",
        path: "/operator/v1/metrics",
        schema: "metricsResponse",
        sse: false,
        mcp_tool: None,
    },
    OperatorRouteSpec {
        method: "GET",
        path: "/operator/v1/audit-tail",
        schema: "auditTailResponse",
        sse: false,
        mcp_tool: None,
    },
    OperatorRouteSpec {
        method: "GET",
        path: "/operator/v1/active-lanes",
        schema: "activeLanesResponse",
        sse: false,
        mcp_tool: None,
    },
    OperatorRouteSpec {
        method: "GET",
        path: "/operator/v1/vsession",
        schema: "vsessionResponse",
        sse: false,
        mcp_tool: None,
    },
    OperatorRouteSpec {
        method: "GET",
        path: "/operator/v1/events",
        schema: "operatorEvent",
        sse: true,
        mcp_tool: None,
    },
    OperatorRouteSpec {
        method: "POST",
        path: "/operator/v1/actions/preview",
        schema: "gatedActionResponse",
        sse: false,
        mcp_tool: Some("operator-selected preview tool"),
    },
    OperatorRouteSpec {
        method: "POST",
        path: "/operator/v1/actions/confirm",
        schema: "gatedActionResponse",
        sse: false,
        mcp_tool: Some("operator-selected confirmation tool"),
    },
    OperatorRouteSpec {
        method: "POST",
        path: "/operator/v1/actions/execute",
        schema: "gatedActionResponse",
        sse: false,
        mcp_tool: Some("operator-selected execute tool"),
    },
    OperatorRouteSpec {
        method: "POST",
        path: "/operator/v1/session/set-level",
        schema: "gatedActionResponse",
        sse: false,
        mcp_tool: Some("oracle_set_session_level"),
    },
    OperatorRouteSpec {
        method: "POST",
        path: "/operator/v1/session/switch-profile",
        schema: "gatedActionResponse",
        sse: false,
        mcp_tool: Some("oracle_switch_profile"),
    },
];

/// Hash a server-derived subject/principal key for operator UI display.
#[must_use]
pub fn operator_subject_id_hash(subject_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"oraclemcp.operator.subject.v1\0");
    hasher.update(subject_key.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::from("subject-sha256:");
    for byte in digest {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Build the common operator REST response envelope.
#[must_use]
pub fn operator_response(route: &str, data: Value) -> Value {
    json!({
        "protocol_version": OPERATOR_PROTOCOL_VERSION,
        "schema_version": OPERATOR_SCHEMA_VERSION,
        "route": route,
        "redaction_level": OPERATOR_REDACTION_LEVEL,
        "data": data,
    })
}

/// Build one operator SSE event envelope.
#[must_use]
pub fn operator_event(
    event_seq: u64,
    lane_id: impl AsRef<str>,
    subject_key: impl AsRef<str>,
    event_type: impl AsRef<str>,
    data: Value,
) -> Value {
    let lane_id = lane_id.as_ref();
    let event_type = event_type.as_ref();
    json!({
        "protocol_version": OPERATOR_PROTOCOL_VERSION,
        "schema_version": OPERATOR_SCHEMA_VERSION,
        "event_seq": event_seq,
        "event_id": format!("{lane_id}/{event_seq}"),
        "lane_id": lane_id,
        "subject_id_hash": operator_subject_id_hash(subject_key.as_ref()),
        "redaction_level": OPERATOR_REDACTION_LEVEL,
        "event_type": event_type,
        "data": data,
    })
}

/// Versioned route index response body.
#[must_use]
pub fn operator_route_index() -> Value {
    operator_response(
        "/operator/v1",
        json!({
            "routes": OPERATOR_ROUTE_SPECS.iter().map(route_spec_json).collect::<Vec<_>>(),
        }),
    )
}

fn route_spec_json(spec: &OperatorRouteSpec) -> Value {
    json!({
        "method": spec.method,
        "path": spec.path,
        "schema": spec.schema,
        "sse": spec.sse,
        "mcp_tool": spec.mcp_tool,
    })
}

/// Published JSON schema bundle for `/operator/v1`.
#[must_use]
pub fn operator_schema_bundle() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/MuhDur/oraclemcp/schemas/operator.schema.json",
        "title": "oraclemcp operator v1 protocol",
        "type": "object",
        "x-oraclemcp-protocol-version": OPERATOR_PROTOCOL_VERSION,
        "x-oraclemcp-schema-version": OPERATOR_SCHEMA_VERSION,
        "routes": OPERATOR_ROUTE_SPECS.iter().map(route_spec_json).collect::<Vec<_>>(),
        "$defs": {
            "versionedResponse": {
                "type": "object",
                "additionalProperties": false,
                "required": ["protocol_version", "schema_version", "route", "redaction_level", "data"],
                "properties": {
                    "protocol_version": { "const": OPERATOR_PROTOCOL_VERSION },
                    "schema_version": { "const": OPERATOR_SCHEMA_VERSION },
                    "route": { "type": "string", "pattern": "^/operator/v1" },
                    "redaction_level": { "const": OPERATOR_REDACTION_LEVEL },
                    "data": { "type": "object" }
                }
            },
            "operatorEvent": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "protocol_version",
                    "schema_version",
                    "event_seq",
                    "event_id",
                    "lane_id",
                    "subject_id_hash",
                    "redaction_level",
                    "event_type",
                    "data"
                ],
                "properties": {
                    "protocol_version": { "const": OPERATOR_PROTOCOL_VERSION },
                    "schema_version": { "const": OPERATOR_SCHEMA_VERSION },
                    "event_seq": { "type": "integer", "minimum": 0 },
                    "event_id": { "type": "string", "minLength": 1 },
                    "lane_id": { "type": "string", "minLength": 1 },
                    "subject_id_hash": { "type": "string", "pattern": "^subject-sha256:[0-9a-f]{64}$" },
                    "redaction_level": { "const": OPERATOR_REDACTION_LEVEL },
                    "event_type": { "type": "string", "minLength": 1 },
                    "data": { "type": "object" }
                }
            },
            "routeSpec": {
                "type": "object",
                "additionalProperties": false,
                "required": ["method", "path", "schema", "sse", "mcp_tool"],
                "properties": {
                    "method": { "type": "string", "enum": ["GET", "POST"] },
                    "path": { "type": "string", "pattern": "^/operator/v1" },
                    "schema": { "type": "string", "minLength": 1 },
                    "sse": { "type": "boolean" },
                    "mcp_tool": { "type": ["string", "null"] }
                }
            },
            "routeIndexResponse": { "$ref": "#/$defs/versionedResponse" },
            "healthResponse": { "$ref": "#/$defs/versionedResponse" },
            "metricsResponse": { "$ref": "#/$defs/versionedResponse" },
            "auditTailResponse": { "$ref": "#/$defs/versionedResponse" },
            "activeLanesResponse": { "$ref": "#/$defs/versionedResponse" },
            "vsessionResponse": { "$ref": "#/$defs/versionedResponse" },
            "gatedActionResponse": { "$ref": "#/$defs/versionedResponse" },
            "operatorSchemaBundle": {
                "type": "object",
                "required": ["$schema", "$id", "routes", "$defs"],
                "properties": {
                    "$schema": { "type": "string" },
                    "$id": { "type": "string" },
                    "routes": { "type": "array", "items": { "$ref": "#/$defs/routeSpec" } },
                    "$defs": { "type": "object" }
                }
            }
        }
    })
}

/// Generated TypeScript definitions for the operator UI.
#[must_use]
pub fn operator_typescript_definitions() -> String {
    format!(
        r#"// Generated from crates/oraclemcp-core/src/operator_protocol.rs.
// Do not edit by hand. Run scripts/generate_operator_schema.sh.

export const OPERATOR_PROTOCOL_VERSION = "{protocol_version}" as const;
export const OPERATOR_SCHEMA_VERSION = {schema_version} as const;
export const OPERATOR_REDACTION_LEVEL = "{redaction_level}" as const;

export interface OperatorRouteSpec {{
  method: "GET" | "POST";
  path: string;
  schema: string;
  sse: boolean;
  mcp_tool: string | null;
}}

export interface OperatorResponse<T extends Record<string, unknown> = Record<string, unknown>> {{
  protocol_version: typeof OPERATOR_PROTOCOL_VERSION;
  schema_version: typeof OPERATOR_SCHEMA_VERSION;
  route: string;
  redaction_level: typeof OPERATOR_REDACTION_LEVEL;
  data: T;
}}

export interface OperatorEvent<T extends Record<string, unknown> = Record<string, unknown>> {{
  protocol_version: typeof OPERATOR_PROTOCOL_VERSION;
  schema_version: typeof OPERATOR_SCHEMA_VERSION;
  event_seq: number;
  event_id: string;
  lane_id: string;
  subject_id_hash: string;
  redaction_level: typeof OPERATOR_REDACTION_LEVEL;
  event_type: string;
  data: T;
}}

export interface OperatorLaneSummary {{
  lane_id: string;
  generation: number;
  status: "starting" | "running" | "stopped" | "quarantined";
  subject_id_hash: string;
}}
"#,
        protocol_version = OPERATOR_PROTOCOL_VERSION,
        schema_version = OPERATOR_SCHEMA_VERSION,
        redaction_level = OPERATOR_REDACTION_LEVEL,
    )
}

/// Validate a captured operator UI fixture against the Rust-owned contract.
pub fn validate_operator_fixture(value: &Value) -> Result<(), String> {
    if value.get("event_seq").is_some() {
        validate_operator_event(value)
    } else {
        validate_operator_response(value)
    }
}

/// Validate a versioned operator REST response envelope.
pub fn validate_operator_response(value: &Value) -> Result<(), String> {
    let obj = object(value)?;
    expect_string(obj, "protocol_version", OPERATOR_PROTOCOL_VERSION)?;
    expect_u64(obj, "schema_version", u64::from(OPERATOR_SCHEMA_VERSION))?;
    let route = string_field(obj, "route")?;
    if !route.starts_with("/operator/v1") {
        return Err(format!("route must be under /operator/v1, got {route:?}"));
    }
    expect_string(obj, "redaction_level", OPERATOR_REDACTION_LEVEL)?;
    object(field(obj, "data")?)?;
    Ok(())
}

/// Validate a versioned operator SSE event envelope.
pub fn validate_operator_event(value: &Value) -> Result<(), String> {
    let obj = object(value)?;
    expect_string(obj, "protocol_version", OPERATOR_PROTOCOL_VERSION)?;
    expect_u64(obj, "schema_version", u64::from(OPERATOR_SCHEMA_VERSION))?;
    let seq = field(obj, "event_seq")?
        .as_u64()
        .ok_or_else(|| "event_seq must be a non-negative integer".to_owned())?;
    let event_id = string_field(obj, "event_id")?;
    let lane_id = string_field(obj, "lane_id")?;
    if !event_id.ends_with(&format!("/{seq}")) {
        return Err(format!("event_id {event_id:?} must end with /{seq}"));
    }
    if lane_id.trim().is_empty() {
        return Err("lane_id must be non-empty".to_owned());
    }
    let subject_hash = string_field(obj, "subject_id_hash")?;
    if !subject_hash.starts_with("subject-sha256:")
        || subject_hash.len() != "subject-sha256:".len() + 64
        || !subject_hash["subject-sha256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "subject_id_hash is not a redacted hash: {subject_hash:?}"
        ));
    }
    expect_string(obj, "redaction_level", OPERATOR_REDACTION_LEVEL)?;
    string_field(obj, "event_type")?;
    object(field(obj, "data")?)?;
    Ok(())
}

/// Fixture values generated from the Rust contract for UI validation tests.
#[must_use]
pub fn operator_fixture_values() -> Vec<(&'static str, Value)> {
    vec![
        ("route-index", operator_route_index()),
        (
            "health",
            operator_response(
                "/operator/v1/health",
                json!({
                    "source": "self_lane",
                    "liveness": { "status": "ok", "live": true, "ready": true, "version": "0.4.1" },
                    "readiness": {
                        "status": "ok",
                        "ready": true,
                        "db_reachable": true,
                        "draining": false
                    }
                }),
            ),
        ),
        (
            "active-lanes",
            operator_response(
                "/operator/v1/active-lanes",
                json!({
                    "source": "self_lane",
                    "lanes": [{
                        "lane_id": "http-lane-1",
                        "generation": 1,
                        "status": "running",
                        "subject_id_hash": operator_subject_id_hash("oauth:fixture")
                    }]
                }),
            ),
        ),
        (
            "audit-tail-unavailable",
            operator_response(
                "/operator/v1/audit-tail",
                json!({
                    "source": "unavailable",
                    "reason": "audit tail provider is not configured",
                    "records": []
                }),
            ),
        ),
        (
            "event-snapshot",
            operator_event(
                1,
                "operator",
                "local-owner:fixture",
                "operator.snapshot",
                json!({ "active_lanes": 1 }),
            ),
        ),
        (
            "gated-action",
            operator_response(
                "/operator/v1/actions/preview",
                json!({
                    "mcp_tool": "oracle_preview_sql",
                    "lane_id": "http-lane-1",
                    "status": "forwarded",
                    "mcp_response": { "jsonrpc": "2.0", "id": "operator-v1", "result": {} }
                }),
            ),
        ),
    ]
}

fn object(value: &Value) -> Result<&Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| "expected JSON object".to_owned())
}

fn field<'a>(obj: &'a Map<String, Value>, name: &str) -> Result<&'a Value, String> {
    obj.get(name)
        .ok_or_else(|| format!("missing required field {name:?}"))
}

fn string_field<'a>(obj: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    field(obj, name)?
        .as_str()
        .ok_or_else(|| format!("{name} must be a string"))
}

fn expect_string(obj: &Map<String, Value>, name: &str, expected: &str) -> Result<(), String> {
    let actual = string_field(obj, name)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{name} must be {expected:?}, got {actual:?}"))
    }
}

fn expect_u64(obj: &Map<String, Value>, name: &str, expected: u64) -> Result<(), String> {
    let actual = field(obj, name)?
        .as_u64()
        .ok_or_else(|| format!("{name} must be an integer"))?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{name} must be {expected}, got {actual}"))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn operator_schema_declares_every_route_and_event_contract() {
        let schema = operator_schema_bundle();
        assert_eq!(
            schema["x-oraclemcp-protocol-version"],
            json!(OPERATOR_PROTOCOL_VERSION)
        );
        assert_eq!(
            schema["x-oraclemcp-schema-version"],
            json!(OPERATOR_SCHEMA_VERSION)
        );
        assert_eq!(
            schema["routes"].as_array().expect("routes array").len(),
            OPERATOR_ROUTE_SPECS.len()
        );
        assert!(
            schema["$defs"]["operatorEvent"]["required"]
                .as_array()
                .expect("event required array")
                .iter()
                .any(|field| field == "subject_id_hash")
        );
    }

    #[test]
    fn operator_fixture_examples_validate_against_contract() {
        for (name, fixture) in operator_fixture_values() {
            validate_operator_fixture(&fixture)
                .unwrap_or_else(|err| panic!("{name} fixture violates operator contract: {err}"));
        }
    }

    #[test]
    fn generated_operator_schema_artifacts_match_rust_contract() {
        let root = workspace_root();
        let schema_path = root.join(OPERATOR_SCHEMA_ARTIFACT);
        let ts_path = root.join(OPERATOR_TS_ARTIFACT);
        let fixture_dir = root.join(OPERATOR_UI_FIXTURE_DIR);
        let schema_text =
            render_json(&operator_schema_bundle()).expect("schema bundle renders as JSON");
        let ts_text = operator_typescript_definitions();

        if std::env::var_os("UPDATE_OPERATOR_SCHEMA").is_some() {
            write_artifact(&schema_path, schema_text.as_bytes());
            write_artifact(&ts_path, ts_text.as_bytes());
            fs::create_dir_all(&fixture_dir).expect("create fixture dir");
            for (name, fixture) in operator_fixture_values() {
                let path = fixture_dir.join(format!("{name}.json"));
                write_artifact(
                    &path,
                    render_json(&fixture).expect("fixture renders").as_bytes(),
                );
            }
            return;
        }

        assert_eq!(
            fs::read_to_string(&schema_path).expect("read generated operator schema"),
            schema_text,
            "run scripts/generate_operator_schema.sh and review the diff"
        );
        assert_eq!(
            fs::read_to_string(&ts_path).expect("read generated operator TS"),
            ts_text,
            "run scripts/generate_operator_schema.sh and review the diff"
        );
        for (name, fixture) in operator_fixture_values() {
            let path = fixture_dir.join(format!("{name}.json"));
            let parsed: Value = serde_json::from_str(
                &fs::read_to_string(&path)
                    .unwrap_or_else(|err| panic!("missing UI fixture {}: {err}", path.display())),
            )
            .expect("fixture parses");
            assert_eq!(
                parsed,
                fixture,
                "operator UI fixture {} drifted from Rust contract",
                path.display()
            );
            validate_operator_fixture(&parsed).expect("fixture validates");
        }
    }

    #[test]
    fn ui_fixtures_validate_against_rust_schema() {
        let fixture_dir = workspace_root().join(OPERATOR_UI_FIXTURE_DIR);
        let mut seen = 0;
        for entry in fs::read_dir(&fixture_dir).expect("fixture dir exists") {
            let entry = entry.expect("fixture entry");
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let value: Value =
                serde_json::from_str(&fs::read_to_string(entry.path()).expect("fixture reads"))
                    .expect("fixture parses");
            validate_operator_fixture(&value).unwrap_or_else(|err| {
                panic!("{} violates operator schema: {err}", entry.path().display())
            });
            seen += 1;
        }
        assert!(seen >= 5, "expected captured operator UI fixtures");
    }

    fn render_json(value: &Value) -> serde_json::Result<String> {
        let mut text = serde_json::to_string_pretty(value)?;
        text.push('\n');
        Ok(text)
    }

    fn write_artifact(path: &std::path::Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create artifact parent");
        }
        fs::write(path, bytes).expect("write generated artifact");
    }

    fn workspace_root() -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        loop {
            if dir.join("Cargo.toml").exists() && dir.join("crates").is_dir() {
                return dir;
            }
            assert!(dir.pop(), "could not find workspace root");
        }
    }
}
