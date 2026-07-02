//! Deterministic metadata-cache-key derivation for `oracle_connection_info`.
//!
//! Pure, leaf helpers extracted verbatim from [`super`]: they serialize the
//! stable identity facets of an [`OracleConnectionInfo`] into the JSON view of
//! an [`OracleMetadataCacheKey`]. These functions make no authorization,
//! guard, or classifier decision — the SHA-256 fingerprints exist solely to
//! partition the metadata cache by database/user/schema identity. Only
//! [`metadata_cache_key_json`] is re-exported into the dispatcher namespace;
//! the fingerprint helpers stay private to this module.

use oraclemcp_audit::sha256_hex;
use oraclemcp_db::{
    ORACLE_CELL_STRUCTURED_CONTRACT_VERSION, OracleConnectionInfo, OracleMetadataCacheKey,
};
use serde_json::{Value, json};

pub(super) fn metadata_cache_key_json(
    active_profile: Option<&str>,
    info: &OracleConnectionInfo,
) -> Value {
    let visible_schema = info.current_schema.as_deref().unwrap_or("*");
    let key = OracleMetadataCacheKey::with_serialization_contract_version(
        metadata_db_fingerprint(info),
        active_profile.unwrap_or("<unprofiled>"),
        metadata_user_fingerprint(info),
        metadata_schema_fingerprint(visible_schema),
        ORACLE_CELL_STRUCTURED_CONTRACT_VERSION,
    );
    serde_json::to_value(key).unwrap_or(Value::Null)
}

fn metadata_db_fingerprint(info: &OracleConnectionInfo) -> String {
    let material = json!({
        "backend": &info.backend,
        "db_unique_name": &info.db_unique_name,
        "service_name": &info.service_name,
        "instance_name": &info.instance_name,
        "server_version": &info.server_version,
    });
    format!("db-sha256:{}", sha256_hex(&stable_json_bytes(&material)))
}

fn metadata_user_fingerprint(info: &OracleConnectionInfo) -> String {
    let material = json!({
        "current_schema": &info.current_schema,
        "session_user": &info.session_user,
        "current_user": &info.current_user,
        "proxy_user": &info.proxy_user,
    });
    format!("user-sha256:{}", sha256_hex(&stable_json_bytes(&material)))
}

fn metadata_schema_fingerprint(schema: &str) -> String {
    format!("schema-sha256:{}", sha256_hex(schema.as_bytes()))
}

fn stable_json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_else(|_| b"<json-serialization-failed>".to_vec())
}
