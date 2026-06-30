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
fn number_boundary_values_include_negative_scale() {
    assert_eq!(
        ser("NUMBER(38,-2)", "1234567890123456789012345678901234567800"),
        json!("1234567890123456789012345678901234567800")
    );
    assert_eq!(
        ser("NUMBER(38,-2)", "-1234567890123456789012345678901234567800"),
        json!("-1234567890123456789012345678901234567800")
    );
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
fn binary_double_edge_values_are_explicit() {
    assert_eq!(ser("BINARY_DOUBLE", "NaN"), json!("NaN"));
    assert_eq!(ser("BINARY_DOUBLE", "inf"), json!("inf"));
    assert_eq!(ser("BINARY_DOUBLE", "-inf"), json!("-inf"));

    let neg_zero = ser("BINARY_DOUBLE", "-0.0");
    let value = neg_zero
        .as_f64()
        .expect("negative zero should remain a JSON number");
    assert_eq!(value, 0.0);
    assert!(
        value.is_sign_negative(),
        "BINARY_DOUBLE -0.0 must preserve the IEEE sign"
    );
}

#[test]
fn structured_carrier_round_trips_array_json_vector_tstz_shape() {
    let structured = json!({
        "kind": "array",
        "items": [
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
    });

    let rendered = serialize_cell(
        &OracleCell::structured("TABLE OF ANYDATA", structured.clone()),
        &SerializeOptions::default(),
    );
    assert_eq!(rendered, structured);

    let encoded = serde_json::to_string(&rendered).expect("structured cell serializes");
    let decoded: Value = serde_json::from_str(&encoded).expect("structured cell parses");
    assert_eq!(decoded, structured);
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
    assert_eq!(
        ser(
            "TIMESTAMP(9) WITH TIME ZONE",
            "2026-06-29 12:34:56.987654321 -05:30"
        ),
        json!("2026-06-29T12:34:56.987654321-05:30")
    );
    assert_eq!(
        ser(
            "TIMESTAMP(9) WITH TIME ZONE",
            "2026-06-29 23:59:59.123456789 +14:00"
        ),
        json!("2026-06-29T23:59:59.123456789+14:00")
    );
    assert_eq!(
        ser(
            "TIMESTAMP(9) WITH TIME ZONE",
            "2026-06-29 00:00:00.000000001 -14:00"
        ),
        json!("2026-06-29T00:00:00.000000001-14:00")
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
fn blob_base64_boundary_lengths_cover_modulo_classes() {
    for (bytes, expected) in [
        (vec![], ""),
        (vec![1], "AQ=="),
        (vec![1, 2], "AQI="),
        (vec![1, 2, 3], "AQID"),
        (vec![1, 2, 3, 4], "AQIDBA=="),
    ] {
        let v = serialize_cell(
            &OracleCell::binary("BLOB", bytes.clone()),
            &SerializeOptions::default(),
        );
        assert_eq!(v["encoding"], json!("base64"));
        assert_eq!(v["data"], json!(expected));
        assert_eq!(v["byte_length"], json!(bytes.len()));
        assert_eq!(v["truncated"], json!(false));
    }
}

#[test]
fn lob_caps_cover_exact_boundary_and_cap_plus_one() {
    let clob_opts = SerializeOptions {
        max_lob_chars: 5,
        ..Default::default()
    };
    assert_eq!(
        serialize_cell(
            &OracleCell::new("CLOB", Some("abcde".to_owned())),
            &clob_opts
        ),
        json!("abcde")
    );
    let clob_plus_one = serialize_cell(
        &OracleCell::new("CLOB", Some("abcdef".to_owned())),
        &clob_opts,
    );
    assert_eq!(clob_plus_one["value"], json!("abcde"));
    assert_eq!(clob_plus_one["truncated"], json!(true));
    assert_eq!(clob_plus_one["char_length"], json!(6));

    let blob_opts = SerializeOptions {
        max_blob_bytes: 3,
        ..Default::default()
    };
    let exact = serialize_cell(&OracleCell::binary("BLOB", vec![1, 2, 3]), &blob_opts);
    assert_eq!(exact["data"], json!("AQID"));
    assert_eq!(exact["byte_length"], json!(3));
    assert_eq!(exact["truncated"], json!(false));

    let plus_one = serialize_cell(&OracleCell::binary("BLOB", vec![1, 2, 3, 4]), &blob_opts);
    assert_eq!(plus_one["data"], json!("AQID"));
    assert_eq!(plus_one["byte_length"], json!(4));
    assert_eq!(plus_one["truncated"], json!(true));
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
        "BINARY_DOUBLE",
        "VARCHAR2(10)",
        "DATE",
        "TIMESTAMP(6)",
        "TIMESTAMP(9) WITH TIME ZONE",
        "RAW(4)",
        "CLOB",
        "BLOB",
        "INTERVAL YEAR(2) TO MONTH",
        "INTERVAL DAY(2) TO SECOND(9)",
    ] {
        let v = serialize_cell(&OracleCell::new(t, None), &SerializeOptions::default());
        assert_eq!(v, Value::Null, "NULL {t} should be JSON null");
    }
}

#[test]
fn interval_boundary_values_are_text_not_reinterpreted() {
    assert_eq!(
        ser("INTERVAL DAY(2) TO SECOND(9)", "+01 02:03:04.123456789"),
        json!("+01 02:03:04.123456789")
    );
    assert_eq!(ser("INTERVAL YEAR(2) TO MONTH", "-01-11"), json!("-01-11"));
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
