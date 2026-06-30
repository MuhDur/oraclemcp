//! Published schema and golden fixtures for `OracleCell::structured`.
//!
//! This pins the contract added by WP-C: typed structured values are observable
//! JSON, not adapter-private implementation detail. The test intentionally uses
//! synthetic examples so the default suite stays Oracle-free.

use std::collections::BTreeSet;

use oraclemcp_db::{
    ORACLE_CELL_STRUCTURED_CONTRACT_VERSION, OracleCell, OracleMetadataCacheKey, SerializeOptions,
    serialize_cell,
};
use serde_json::{Map, Value, json};

#[path = "../../../tests/golden/support.rs"]
mod golden_support;

const SCHEMA_TEXT: &str = include_str!("../../../schemas/oracle-cell-structured.schema.json");

fn structured_examples() -> Vec<(&'static str, Value)> {
    vec![
        (
            "oracle-cell-structured/array-json-vector-tstz",
            json!({
                "kind": "array",
                "items": [
                    null,
                    {
                        "kind": "json",
                        "value": {
                            "kind": "object",
                            "entries": [
                                {
                                    "key": "wide_number",
                                    "value": {
                                        "kind": "number",
                                        "value": "99999999999999999999999999999999999999"
                                    }
                                },
                                {
                                    "key": "raw",
                                    "value": {
                                        "kind": "raw",
                                        "encoding": "hex",
                                        "data": "deadbeef",
                                        "byte_length": 4
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "kind": "vector",
                        "storage": "sparse",
                        "format": "float64",
                        "num_dimensions": 4,
                        "indices": [0, 3],
                        "values": [1.0, -1.5]
                    },
                    {
                        "kind": "timestamp_tz",
                        "value": "2026-06-29 12:34:56.987654321 -05:30",
                        "year": 2026,
                        "month": 6,
                        "day": 29,
                        "hour": 12,
                        "minute": 34,
                        "second": 56,
                        "nanosecond": 987654321,
                        "offset_minutes": -330
                    }
                ]
            }),
        ),
        (
            "oracle-cell-structured/oson-scalars",
            json!({
                "kind": "json",
                "value": {
                    "kind": "object",
                    "entries": [
                        {
                            "key": "wide_number",
                            "value": {
                                "kind": "number",
                                "value": "1.234567890123456789"
                            }
                        },
                        {
                            "key": "raw",
                            "value": {
                                "kind": "raw",
                                "encoding": "hex",
                                "data": "dead",
                                "byte_length": 2
                            }
                        },
                        {
                            "key": "when",
                            "value": {
                                "kind": "datetime",
                                "value": "2026-06-30 21:24:05.123456789",
                                "year": 2026,
                                "month": 6,
                                "day": 30,
                                "hour": 21,
                                "minute": 24,
                                "second": 5,
                                "nanosecond": 123456789
                            }
                        },
                        {
                            "key": "embedded_vector",
                            "value": {
                                "kind": "vector",
                                "storage": "dense",
                                "format": "int8",
                                "values": [-1, 0, 127]
                            }
                        }
                    ]
                }
            }),
        ),
        (
            "oracle-cell-structured/object-unsupported",
            json!({
                "kind": "unsupported",
                "unsupported": "oracle_object",
                "oracle_value_kind": "Object",
                "schema": "HR",
                "type_name": "ADDRESS_T",
                "packed_byte_length": 4,
                "value": null,
                "warning": "Oracle object/UDT values are not decoded by default"
            }),
        ),
        (
            "oracle-cell-structured/generic-unsupported",
            json!({
                "kind": "unsupported",
                "unsupported": "oracle_value",
                "oracle_value_kind": "Cursor",
                "value": null,
                "warning": "Oracle value kind is not structurally serialized yet"
            }),
        ),
    ]
}

#[test]
fn published_schema_parses_and_declares_structured_variants() {
    let schema: Value = serde_json::from_str(SCHEMA_TEXT).expect("schema parses");
    assert_eq!(
        schema["$schema"],
        json!("https://json-schema.org/draft/2020-12/schema")
    );
    assert_eq!(
        schema["$id"],
        json!("https://github.com/MuhDur/oraclemcp/schemas/oracle-cell-structured.schema.json")
    );
    assert_eq!(
        schema["x-oraclemcp-contract-version"],
        json!(ORACLE_CELL_STRUCTURED_CONTRACT_VERSION)
    );

    let defs = schema["$defs"].as_object().expect("$defs object");
    for required in [
        "sqlArray",
        "jsonWrapper",
        "vectorDense",
        "vectorSparse",
        "osonObject",
        "timestampTz",
        "unsupportedObject",
        "unsupportedOracleValue",
    ] {
        assert!(
            defs.contains_key(required),
            "schema missing $defs/{required}"
        );
    }

    let one_of = defs["structuredCell"]["oneOf"]
        .as_array()
        .expect("structuredCell oneOf array");
    assert!(
        one_of.len() >= 20,
        "structuredCell should cover scalar, JSON, vector, array, and unsupported variants"
    );
}

#[test]
fn serialization_contract_version_present_and_consumed() {
    let cell = OracleCell::structured("JSON", json!({ "kind": "null" }));
    assert_eq!(
        cell.structured_contract_version,
        Some(ORACLE_CELL_STRUCTURED_CONTRACT_VERSION)
    );

    let key = OracleMetadataCacheKey::new("db-sha256:abc", "agent_ro", "APP", "HR");
    assert_eq!(
        key.serialization_contract_version,
        ORACLE_CELL_STRUCTURED_CONTRACT_VERSION
    );

    let bumped = OracleMetadataCacheKey::with_serialization_contract_version(
        "db-sha256:abc",
        "agent_ro",
        "APP",
        "HR",
        ORACLE_CELL_STRUCTURED_CONTRACT_VERSION + 1,
    );
    assert_ne!(
        key, bumped,
        "W7 metadata cache identity must change with the serialization contract"
    );

    let rendered_key = serde_json::to_value(&key).expect("cache key serializes");
    assert_eq!(
        rendered_key["serialization_contract_version"],
        json!(ORACLE_CELL_STRUCTURED_CONTRACT_VERSION)
    );
}

#[test]
fn structured_goldens_match_schema_and_serializer_contract() {
    for (name, value) in structured_examples() {
        validate_structured_value(&value)
            .unwrap_or_else(|err| panic!("{name} violates structured schema contract: {err}"));

        let rendered = serialize_cell(
            &OracleCell::structured("SYNTHETIC", value.clone()),
            &SerializeOptions::default(),
        );
        assert_eq!(rendered, value, "{name} must serialize verbatim");
        golden_support::assert_golden(name, &rendered);
    }
}

#[test]
fn schema_contract_rejects_legacy_silent_flattening_shapes() {
    for bad in [
        json!("QueryValue::Vector(Dense(...))"),
        json!({ "value": "ObjectValue { schema: HR, type_name: ADDRESS_T }" }),
        json!({ "kind": "unsupported", "unsupported": "oracle_object", "value": null }),
    ] {
        assert!(
            validate_structured_value(&bad).is_err(),
            "legacy/silent shape must be rejected: {bad}"
        );
    }
}

fn validate_structured_value(value: &Value) -> Result<(), String> {
    let obj = object(value)?;
    let kind = string_field(obj, "kind")?;
    match kind {
        "array" => validate_array(obj),
        "json" => validate_structured_value(field(obj, "value")?),
        "vector" => validate_vector(obj),
        "object" => validate_object(obj),
        "text" | "string" | "rowid" => {
            string_field(obj, "value")?;
            Ok(())
        }
        "text_raw" => {
            validate_raw_like(obj)?;
            integer_field(obj, "csfrm")?;
            Ok(())
        }
        "raw" => validate_raw_like(obj),
        "number" => {
            string_field(obj, "value")?;
            Ok(())
        }
        "binary_float" | "binary_double" => validate_number_or_string(field(obj, "value")?),
        "boolean" => {
            bool_field(obj, "value")?;
            Ok(())
        }
        "null" => Ok(()),
        "datetime" => validate_datetime(obj, false),
        "timestamp_tz" => validate_datetime(obj, true),
        "interval_ds" => validate_interval_ds(obj),
        "interval_ym" => validate_interval_ym(obj),
        "unsupported" => validate_unsupported(obj),
        other => Err(format!("unknown structured kind {other:?}")),
    }
}

fn validate_array(obj: &Map<String, Value>) -> Result<(), String> {
    for item in array_field(obj, "items")? {
        if !item.is_null() {
            validate_structured_value(item)?;
        }
    }
    Ok(())
}

fn validate_vector(obj: &Map<String, Value>) -> Result<(), String> {
    let storage = string_field(obj, "storage")?;
    let format = string_field(obj, "format")?;
    match format {
        "float32" | "float64" | "int8" | "binary" => {}
        other => return Err(format!("invalid vector format {other:?}")),
    }
    let values = array_field(obj, "values")?;
    for value in values {
        validate_number_or_string(value)?;
    }
    match storage {
        "dense" => Ok(()),
        "sparse" => {
            unsigned_field(obj, "num_dimensions")?;
            let indices = array_field(obj, "indices")?;
            for index in indices {
                if index.as_u64().is_none() {
                    return Err("sparse vector index must be an unsigned integer".to_owned());
                }
            }
            if indices.len() != values.len() {
                return Err(
                    "sparse vector indices and values must have matching lengths".to_owned(),
                );
            }
            Ok(())
        }
        other => Err(format!("invalid vector storage {other:?}")),
    }
}

fn validate_object(obj: &Map<String, Value>) -> Result<(), String> {
    for entry in array_field(obj, "entries")? {
        let entry = object(entry)?;
        string_field(entry, "key")?;
        validate_structured_value(field(entry, "value")?)?;
    }
    Ok(())
}

fn validate_raw_like(obj: &Map<String, Value>) -> Result<(), String> {
    if string_field(obj, "encoding")? != "hex" {
        return Err("raw/text_raw encoding must be hex".to_owned());
    }
    let data = string_field(obj, "data")?;
    if !data.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("raw/text_raw data must be hex".to_owned());
    }
    unsigned_field(obj, "byte_length")?;
    Ok(())
}

fn validate_datetime(obj: &Map<String, Value>, with_tz: bool) -> Result<(), String> {
    string_field(obj, "value")?;
    integer_field(obj, "year")?;
    for field_name in ["month", "day", "hour", "minute", "second", "nanosecond"] {
        unsigned_field(obj, field_name)?;
    }
    if with_tz {
        integer_field(obj, "offset_minutes")?;
    }
    Ok(())
}

fn validate_interval_ds(obj: &Map<String, Value>) -> Result<(), String> {
    string_field(obj, "value")?;
    for field_name in ["days", "hours", "minutes", "seconds", "fseconds"] {
        integer_field(obj, field_name)?;
    }
    Ok(())
}

fn validate_interval_ym(obj: &Map<String, Value>) -> Result<(), String> {
    string_field(obj, "value")?;
    integer_field(obj, "years")?;
    integer_field(obj, "months")?;
    Ok(())
}

fn validate_unsupported(obj: &Map<String, Value>) -> Result<(), String> {
    let unsupported = string_field(obj, "unsupported")?;
    string_field(obj, "oracle_value_kind")?;
    if !field(obj, "value")?.is_null() {
        return Err("unsupported marker value must be null".to_owned());
    }
    string_field(obj, "warning")?;
    match unsupported {
        "oracle_object" => {
            nullable_string_field(obj, "schema")?;
            nullable_string_field(obj, "type_name")?;
            unsigned_field(obj, "packed_byte_length")?;
            Ok(())
        }
        "oracle_value" => Ok(()),
        other => Err(format!("invalid unsupported marker {other:?}")),
    }
}

fn object(value: &Value) -> Result<&Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| "structured value must be a JSON object".to_owned())
}

fn field<'a>(obj: &'a Map<String, Value>, name: &str) -> Result<&'a Value, String> {
    obj.get(name)
        .ok_or_else(|| format!("missing required field {name}"))
}

fn string_field<'a>(obj: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    field(obj, name)?
        .as_str()
        .ok_or_else(|| format!("{name} must be a string"))
}

fn nullable_string_field(obj: &Map<String, Value>, name: &str) -> Result<(), String> {
    let value = field(obj, name)?;
    if value.is_null() || value.as_str().is_some() {
        Ok(())
    } else {
        Err(format!("{name} must be string or null"))
    }
}

fn bool_field(obj: &Map<String, Value>, name: &str) -> Result<bool, String> {
    field(obj, name)?
        .as_bool()
        .ok_or_else(|| format!("{name} must be a boolean"))
}

fn integer_field(obj: &Map<String, Value>, name: &str) -> Result<i64, String> {
    field(obj, name)?
        .as_i64()
        .ok_or_else(|| format!("{name} must be an integer"))
}

fn unsigned_field(obj: &Map<String, Value>, name: &str) -> Result<u64, String> {
    field(obj, name)?
        .as_u64()
        .ok_or_else(|| format!("{name} must be an unsigned integer"))
}

fn array_field<'a>(obj: &'a Map<String, Value>, name: &str) -> Result<&'a Vec<Value>, String> {
    field(obj, name)?
        .as_array()
        .ok_or_else(|| format!("{name} must be an array"))
}

fn validate_number_or_string(value: &Value) -> Result<(), String> {
    if value.is_number() || value.is_string() {
        Ok(())
    } else {
        Err("value must be a JSON number or string".to_owned())
    }
}

#[test]
fn structured_fixture_names_are_unique() {
    let mut names = BTreeSet::new();
    for (name, _) in structured_examples() {
        assert!(names.insert(name), "duplicate fixture name {name}");
    }
}
