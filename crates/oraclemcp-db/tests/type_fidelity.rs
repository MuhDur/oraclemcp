//! Type-fidelity golden tests (plan §5.2, §12; bead T-TYPES / 6.4).
//!
//! A standing artifact pinning the published type table: every Oracle type maps
//! to its documented JSON representation, NUMBER never passes through `f64`,
//! dates are ISO-8601, and the output is NLS-invariant (identical regardless of
//! the driver's locale-dependent input formatting). Pairs with the live
//! type-fidelity test in `live_oracle.rs` (which proves the same against a real
//! Oracle 23ai).

use oraclemcp_db::{OracleCell, SerializeOptions, serialize_cell};
use serde_json::{Value, json};

fn ser(t: &str, v: &str) -> Value {
    serialize_cell(
        &OracleCell::new(t, Some(v.to_owned())),
        &SerializeOptions::default(),
    )
}

#[test]
fn number_is_lossless_string_by_default() {
    // The non-negotiable rule: NUMBER -> JSON string (no f64 truncation).
    assert_eq!(ser("NUMBER", "42"), json!("42"));
    assert_eq!(
        ser("NUMBER", "1234567890123456789"),
        json!("1234567890123456789")
    );
    assert_eq!(
        ser("NUMBER(38,0)", "99999999999999999999999999999999999999"),
        json!("99999999999999999999999999999999999999")
    );
    assert_eq!(ser("NUMBER", "-3.14159"), json!("-3.14159"));
}

#[test]
fn numbers_as_float_opt_in_is_lossy_number() {
    let opts = SerializeOptions {
        numbers_as_float: true,
        ..Default::default()
    };
    let v = serialize_cell(&OracleCell::new("NUMBER", Some("42".to_owned())), &opts);
    assert_eq!(v, json!(42.0));

    let exact = "12345678901234567890123456789012345678";
    let lossless = serialize_cell(
        &OracleCell::new("NUMBER(38,0)", Some(exact.to_owned())),
        &SerializeOptions::default(),
    );
    assert_eq!(lossless, json!(exact));

    let lossy = serialize_cell(
        &OracleCell::new("NUMBER(38,0)", Some(exact.to_owned())),
        &opts,
    );
    assert!(
        lossy.is_number(),
        "opt-in float mode should emit a JSON number"
    );
    assert_ne!(
        lossy.to_string(),
        exact,
        "opt-in float mode must be visibly lossy for 38-digit NUMBER"
    );
}

#[test]
fn float_types() {
    // Native IEEE floats serialize as JSON numbers (f64-safe).
    assert_eq!(ser("BINARY_DOUBLE", "3.5"), json!(3.5));
    assert_eq!(ser("BINARY_FLOAT", "1.25"), json!(1.25));
    // A >15-sig-digit FLOAT stays a string (lossless).
    assert_eq!(
        ser("FLOAT", "12345678901234567890"),
        json!("12345678901234567890")
    );
}

#[test]
fn character_types_are_strings() {
    assert_eq!(ser("VARCHAR2(50)", "hello"), json!("hello"));
    assert_eq!(ser("CHAR(3)", "abc"), json!("abc"));
    assert_eq!(ser("NVARCHAR2(10)", "uni©ode"), json!("uni©ode"));
    assert_eq!(ser("NCHAR(2)", "ab"), json!("ab"));
    assert_eq!(
        ser("ROWID", "AAAR3sAABAAAW8rAAA"),
        json!("AAAR3sAABAAAW8rAAA")
    );
    assert_eq!(
        ser("INTERVAL DAY(2) TO SECOND(6)", "+01 00:00:00.000000"),
        json!("+01 00:00:00.000000")
    );
}

#[test]
fn date_and_timestamp_are_iso_8601() {
    // The driver renders DATE/TIMESTAMP with a space; output is canonical ISO.
    assert_eq!(
        ser("DATE", "2026-06-01 12:00:00"),
        json!("2026-06-01T12:00:00")
    );
    assert_eq!(
        ser("TIMESTAMP(6)", "2026-06-01 12:00:00.123456"),
        json!("2026-06-01T12:00:00.123456")
    );
    assert_eq!(
        ser(
            "TIMESTAMP(6) WITH TIME ZONE",
            "2026-06-01 12:00:00.000000 +00:00"
        ),
        json!("2026-06-01T12:00:00.000000+00:00")
    );
}

#[test]
fn nls_invariance() {
    // Whatever locale-dependent spacing the driver used, the canonical output is
    // identical — the §5.2 NLS-decoupling guarantee.
    let a = ser("DATE", "2026-06-01 12:00:00");
    let b = ser("DATE", "2026-06-01T12:00:00"); // already-ISO input
    assert_eq!(a, b);
    assert_eq!(a, json!("2026-06-01T12:00:00"));
}

#[test]
fn raw_is_hex_text() {
    assert_eq!(ser("RAW(4)", "DEADBEEF"), json!("DEADBEEF"));
}

#[test]
fn blob_binary_is_base64_with_length() {
    let cell = OracleCell::binary("BLOB", vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let v = serialize_cell(&cell, &SerializeOptions::default());
    assert_eq!(v["encoding"], json!("base64"));
    assert_eq!(v["data"], json!("3q2+7w=="));
    assert_eq!(v["byte_length"], json!(4));
    assert_eq!(v["truncated"], json!(false));
}

#[test]
fn clob_truncates_with_flag() {
    let opts = SerializeOptions {
        max_lob_chars: 5,
        ..Default::default()
    };
    let v = serialize_cell(
        &OracleCell::new("CLOB", Some("abcdefghij".to_owned())),
        &opts,
    );
    assert_eq!(v["value"], json!("abcde"));
    assert_eq!(v["truncated"], json!(true));
    assert_eq!(v["char_length"], json!(10));
}

#[test]
fn null_is_json_null_for_every_type() {
    for t in [
        "NUMBER",
        "VARCHAR2(10)",
        "DATE",
        "TIMESTAMP(6)",
        "RAW(4)",
        "CLOB",
        "BLOB",
    ] {
        let v = serialize_cell(&OracleCell::new(t, None), &SerializeOptions::default());
        assert_eq!(v, Value::Null, "NULL {t} should be JSON null");
    }
}

#[test]
fn unsupported_type_emits_explicit_marker_never_silent() {
    let v = ser("SDO_GEOMETRY", "(MDSYS.SDO_GEOMETRY...)");
    assert_eq!(v["unsupported"], json!("SDO_GEOMETRY"));
    assert_eq!(v["value"], Value::Null);
    assert!(
        v["warning"].is_string(),
        "must carry a warning, never a silent best-effort"
    );
}
