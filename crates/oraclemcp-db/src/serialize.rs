//! The deterministic type-mapping & NLS-canonical serializer (plan §5.2; beads
//! P0-5 / P0-5a..d).
//!
//! Two halves:
//! 1. **Canonical session NLS** ([`canonical_nls_statements`]) — applied at
//!    connect so dates/timestamps come back ISO-8601 and decimals use a period,
//!    regardless of the host `NLS_LANG`/CI locale. The session NLS used to
//!    *interpret* a query is the operator's choice; the *output* is always
//!    canonical.
//! 2. **The value serializer** ([`serialize_cell`]) — the published type table
//!    mapping every Oracle type to a JSON representation, with the
//!    non-negotiable rule that NUMBER (and any numeric with >15 significant
//!    digits) serializes as a JSON **string** by default so a 38-digit NUMBER
//!    never silently truncates through `f64`. `numbers_as_float` opts into
//!    lossy float for callers who accept it.

use serde_json::{Value, json};

use crate::types::{OracleCell, OracleRow};

/// `ALTER SESSION` statements that pin canonical, NLS-decoupled output. Applied
/// once per physical session (at connect / lease acquire).
#[must_use]
pub fn canonical_nls_statements() -> Vec<&'static str> {
    vec![
        "ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY-MM-DD\"T\"HH24:MI:SS'",
        "ALTER SESSION SET NLS_TIMESTAMP_FORMAT = 'YYYY-MM-DD\"T\"HH24:MI:SS.FF6'",
        "ALTER SESSION SET NLS_TIMESTAMP_TZ_FORMAT = 'YYYY-MM-DD\"T\"HH24:MI:SS.FF6TZH:TZM'",
        // Period decimal separator, comma group separator (period decimals).
        "ALTER SESSION SET NLS_NUMERIC_CHARACTERS = '.,'",
    ]
}

/// Options governing serialization.
#[derive(Clone, Copy, Debug)]
pub struct SerializeOptions {
    /// Emit NUMBER as a JSON float (lossy for >15 sig digits) instead of the
    /// default lossless string.
    pub numbers_as_float: bool,
    /// Max characters of a CLOB/text value to inline before truncating.
    pub max_lob_chars: usize,
    /// Max bytes of a BLOB to base64-inline before truncating.
    pub max_blob_bytes: usize,
}

impl Default for SerializeOptions {
    fn default() -> Self {
        SerializeOptions {
            numbers_as_float: false,
            max_lob_chars: 32_768,
            max_blob_bytes: 1_048_576,
        }
    }
}

/// The published JSON-representation class for an Oracle column type (§5.2 type
/// table). The classifier is the single source of truth for "how does this type
/// serialize."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeRepr {
    /// NUMBER / FLOAT / BINARY_FLOAT / BINARY_DOUBLE — numeric.
    Numeric,
    /// VARCHAR2 / CHAR / NVARCHAR2 / NCHAR / ROWID / interval — text.
    Text,
    /// DATE — ISO-8601 date-time string.
    Date,
    /// `TIMESTAMP [WITH [LOCAL] TIME ZONE]` — ISO-8601 string.
    Timestamp,
    /// RAW / LONG RAW — hex (when fetched as text) or base64 (when binary).
    Raw,
    /// BLOB — base64.
    Blob,
    /// CLOB / NCLOB — text (paginated/truncated).
    Clob,
    /// A type we do not serialize yet — emits an explicit unsupported marker,
    /// never a silent best-effort.
    Unsupported,
}

/// Classify an Oracle type name (as rendered by the driver, e.g. `"NUMBER"`,
/// `"VARCHAR2(50)"`, `"TIMESTAMP(6) WITH TIME ZONE"`).
#[must_use]
pub fn classify_type(oracle_type: &str) -> TypeRepr {
    let t = oracle_type.trim().to_ascii_uppercase();
    if t.starts_with("NUMBER")
        || t.starts_with("FLOAT")
        || t.starts_with("BINARY_FLOAT")
        || t.starts_with("BINARY_DOUBLE")
    {
        TypeRepr::Numeric
    } else if t.contains("TIMESTAMP") {
        TypeRepr::Timestamp
    } else if t == "DATE" {
        TypeRepr::Date
    } else if t.starts_with("BLOB") {
        TypeRepr::Blob
    } else if t.starts_with("CLOB") || t.starts_with("NCLOB") {
        TypeRepr::Clob
    } else if t.starts_with("RAW") || t.starts_with("LONG RAW") {
        TypeRepr::Raw
    } else if t.starts_with("VARCHAR")
        || t.starts_with("NVARCHAR")
        || t.starts_with("CHAR")
        || t.starts_with("NCHAR")
        || t.starts_with("LONG")
        || t.starts_with("ROWID")
        || t.starts_with("UROWID")
        || t.contains("INTERVAL")
    {
        TypeRepr::Text
    } else {
        TypeRepr::Unsupported
    }
}

/// Count significant decimal digits in a numeric text (ignoring sign, decimal
/// point, leading zeros, and any exponent marker).
fn significant_digits(text: &str) -> usize {
    let mantissa = text.split(['e', 'E']).next().unwrap_or(text);
    mantissa
        .chars()
        .filter(char::is_ascii_digit)
        .skip_while(|c| *c == '0')
        .filter(char::is_ascii_digit)
        .count()
}

/// Standard-alphabet base64 encoder (std-only; avoids a crate dep).
#[must_use]
pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHA[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHA[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Canonicalize a driver-rendered date/time string to ISO-8601: replace the
/// date↔time separator space with `T`, and close the space before a timezone
/// sign (`... +00:00` → `...+00:00`). Already-ISO text passes through unchanged.
#[must_use]
pub fn canonicalize_datetime(text: &str) -> String {
    let with_t = text.replacen(' ', "T", 1);
    with_t.replace(" +", "+").replace(" -", "-")
}

/// Serialize one cell to its canonical JSON value per the type table.
#[must_use]
pub fn serialize_cell(cell: &OracleCell, opts: &SerializeOptions) -> Value {
    // Binary columns carrying raw bytes always base64 (with a cap).
    if let Some(bytes) = &cell.bytes {
        let truncated = bytes.len() > opts.max_blob_bytes;
        let slice = if truncated {
            &bytes[..opts.max_blob_bytes]
        } else {
            &bytes[..]
        };
        return json!({
            "encoding": "base64",
            "data": base64_encode(slice),
            "byte_length": bytes.len(),
            "truncated": truncated,
        });
    }
    let Some(text) = cell.text() else {
        return Value::Null;
    };
    match classify_type(&cell.oracle_type) {
        TypeRepr::Numeric => {
            let is_number_type = cell
                .oracle_type
                .trim()
                .to_ascii_uppercase()
                .starts_with("NUMBER");
            if opts.numbers_as_float {
                match text.parse::<f64>() {
                    Ok(f) => serde_json::Number::from_f64(f)
                        .map_or_else(|| Value::String(text.to_owned()), Value::Number),
                    Err(_) => Value::String(text.to_owned()),
                }
            } else if is_number_type || significant_digits(text) > 15 {
                // Lossless: NUMBER (and any >15-sig-digit numeric) stays a string.
                Value::String(text.to_owned())
            } else {
                text.parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map_or_else(|| Value::String(text.to_owned()), Value::Number)
            }
        }
        TypeRepr::Date | TypeRepr::Timestamp => {
            // The driver renders DATE/TIMESTAMP client-side as
            // "YYYY-MM-DD HH:MI:SS[.ffffff][ +TZ]" regardless of session NLS, so
            // canonicalize to ISO-8601 here (the only reliable place).
            Value::String(canonicalize_datetime(text))
        }
        TypeRepr::Text | TypeRepr::Raw => Value::String(text.to_owned()),
        TypeRepr::Clob => {
            let truncated = text.chars().count() > opts.max_lob_chars;
            if truncated {
                let s: String = text.chars().take(opts.max_lob_chars).collect();
                json!({ "value": s, "truncated": true, "char_length": text.chars().count() })
            } else {
                Value::String(text.to_owned())
            }
        }
        TypeRepr::Blob => {
            // A BLOB arrived as text (not binary-fetched): mark it so the caller
            // re-fetches in binary mode rather than trusting a lossy rendering.
            json!({ "unsupported": "BLOB-as-text", "value": null, "warning": "BLOB must be fetched in binary mode for base64" })
        }
        TypeRepr::Unsupported => {
            json!({ "unsupported": cell.oracle_type, "value": null, "warning": "type not serialized yet (§5.2)" })
        }
    }
}

/// Serialize a row to a JSON object keyed by (last-wins) column name.
#[must_use]
pub fn serialize_row(row: &OracleRow, opts: &SerializeOptions) -> Value {
    let mut map = serde_json::Map::with_capacity(row.columns.len());
    for (name, cell) in &row.columns {
        map.insert(name.clone(), serialize_cell(cell, opts));
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(t: &str, v: &str) -> OracleCell {
        OracleCell::new(t, Some(v.to_owned()))
    }

    #[test]
    fn number_serializes_as_string_by_default() {
        // The non-negotiable rule: a 19-digit NUMBER must not pass through f64.
        let c = cell("NUMBER", "1234567890123456789");
        assert_eq!(
            serialize_cell(&c, &SerializeOptions::default()),
            json!("1234567890123456789")
        );
        // Even a small NUMBER is a string by default (no silent float).
        assert_eq!(
            serialize_cell(&cell("NUMBER", "42"), &SerializeOptions::default()),
            json!("42")
        );
    }

    #[test]
    fn numbers_as_float_opt_in() {
        let opts = SerializeOptions {
            numbers_as_float: true,
            ..Default::default()
        };
        assert_eq!(serialize_cell(&cell("NUMBER", "42"), &opts), json!(42.0));
    }

    #[test]
    fn binary_double_is_a_number() {
        assert_eq!(
            serialize_cell(&cell("BINARY_DOUBLE", "3.5"), &SerializeOptions::default()),
            json!(3.5)
        );
    }

    #[test]
    fn high_precision_non_number_numeric_stays_string() {
        // >15 significant digits forces string even for a non-NUMBER numeric.
        let c = cell("FLOAT", "12345678901234567890");
        assert_eq!(
            serialize_cell(&c, &SerializeOptions::default()),
            json!("12345678901234567890")
        );
    }

    #[test]
    fn date_and_timestamp_pass_through_iso_text() {
        assert_eq!(
            serialize_cell(
                &cell("DATE", "2026-06-01T12:00:00"),
                &SerializeOptions::default()
            ),
            json!("2026-06-01T12:00:00")
        );
        assert_eq!(
            serialize_cell(
                &cell(
                    "TIMESTAMP(6) WITH TIME ZONE",
                    "2026-06-01T12:00:00.000000+00:00"
                ),
                &SerializeOptions::default()
            ),
            json!("2026-06-01T12:00:00.000000+00:00")
        );
    }

    #[test]
    fn driver_rendered_datetime_canonicalizes_to_iso() {
        // The shape the `oracle` crate actually returns for DATE / TIMESTAMP.
        assert_eq!(
            canonicalize_datetime("2026-06-01 12:00:00"),
            "2026-06-01T12:00:00"
        );
        assert_eq!(
            canonicalize_datetime("2026-06-01 12:00:00.000000 +00:00"),
            "2026-06-01T12:00:00.000000+00:00"
        );
        // Already-ISO passes through.
        assert_eq!(
            canonicalize_datetime("2026-06-01T12:00:00"),
            "2026-06-01T12:00:00"
        );
        assert_eq!(
            serialize_cell(
                &cell("DATE", "2026-06-01 12:00:00"),
                &SerializeOptions::default()
            ),
            json!("2026-06-01T12:00:00")
        );
    }

    #[test]
    fn null_is_json_null() {
        let c = OracleCell::new("VARCHAR2(10)", None);
        assert_eq!(
            serialize_cell(&c, &SerializeOptions::default()),
            Value::Null
        );
    }

    #[test]
    fn blob_bytes_base64_with_length() {
        let c = OracleCell::binary("BLOB", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let v = serialize_cell(&c, &SerializeOptions::default());
        assert_eq!(v["encoding"], json!("base64"));
        assert_eq!(v["data"], json!("3q2+7w==")); // base64 of DEADBEEF
        assert_eq!(v["byte_length"], json!(4));
        assert_eq!(v["truncated"], json!(false));
    }

    #[test]
    fn blob_base64_truncates_at_cap() {
        let opts = SerializeOptions {
            max_blob_bytes: 2,
            ..Default::default()
        };
        let c = OracleCell::binary("BLOB", vec![1, 2, 3, 4, 5]);
        let v = serialize_cell(&c, &opts);
        assert_eq!(v["byte_length"], json!(5));
        assert_eq!(v["truncated"], json!(true));
    }

    #[test]
    fn unsupported_type_emits_explicit_marker() {
        let c = cell("SDO_GEOMETRY", "(whatever)");
        let v = serialize_cell(&c, &SerializeOptions::default());
        assert_eq!(v["unsupported"], json!("SDO_GEOMETRY"));
        assert_eq!(v["value"], Value::Null);
        assert!(v["warning"].is_string());
    }

    #[test]
    fn clob_truncates_at_cap_with_flag() {
        let opts = SerializeOptions {
            max_lob_chars: 4,
            ..Default::default()
        };
        let c = cell("CLOB", "abcdefgh");
        let v = serialize_cell(&c, &opts);
        assert_eq!(v["value"], json!("abcd"));
        assert_eq!(v["truncated"], json!(true));
        assert_eq!(v["char_length"], json!(8));
    }

    #[test]
    fn base64_roundtrip_shapes() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"M"), "TQ==");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"Man"), "TWFu");
    }

    #[test]
    fn canonical_nls_covers_date_timestamp_and_decimal() {
        let stmts = canonical_nls_statements();
        assert!(stmts.iter().any(|s| s.contains("NLS_DATE_FORMAT")));
        assert!(stmts.iter().any(|s| s.contains("NLS_TIMESTAMP_FORMAT")));
        assert!(stmts.iter().any(|s| s.contains("NLS_TIMESTAMP_TZ_FORMAT")));
        assert!(stmts.iter().any(|s| s.contains("NLS_NUMERIC_CHARACTERS")));
    }
}
