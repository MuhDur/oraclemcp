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

use std::collections::HashMap;
use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::masking::{ResultColumnContext, ResultMaskingPolicy};
use crate::types::{ORACLE_CELL_STRUCTURED_CONTRACT_VERSION, OracleCell, OracleRow};

/// A sink that tallies bytes without buffering, so the page byte cap can measure
/// a serialized row in one streaming pass instead of allocating a throwaway
/// `String`. The count equals `Value::to_string().len()` (both use the compact
/// formatter).
struct ByteCounter(usize);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Saturation keeps adversarial accounting fail-closed even on a
        // hypothetical value whose encoded length approaches `usize::MAX`.
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The compact-JSON byte length of `value`, computed without allocating the
/// serialized string. Equal to `value.to_string().len()`.
#[must_use]
pub(crate) fn json_byte_len(value: &Value) -> usize {
    let mut counter = ByteCounter(0);
    // serde_json's `Value` serializer is infallible into an infallible writer.
    let _ = serde_json::to_writer(&mut counter, value);
    counter.0
}

/// The compact-JSON byte length of an object key, including its quotes and any
/// required escaping, without allocating the encoded string.
fn json_string_byte_len(value: &str) -> usize {
    let mut counter = ByteCounter(0);
    let _ = serde_json::to_writer(&mut counter, value);
    counter.0
}

/// Add one compact-JSON payload length to a running byte total without
/// overflowing and only when the resulting total remains within `max_bytes`.
/// `None` means either arithmetic overflow or budget exhaustion; callers treat
/// both identically and fail closed.
pub(crate) fn checked_byte_budget_add(
    total_bytes: usize,
    next_bytes: usize,
    max_bytes: usize,
) -> Option<usize> {
    total_bytes
        .checked_add(next_bytes)
        .filter(|total| *total <= max_bytes)
}

/// Structural allowance for the bounded nested-cursor row-too-large sentinel.
/// `max_nested_cursor_bytes` governs compact row payload only; when row zero is
/// too large, this fixed-size metadata replaces the rows/columns payload and is
/// capped independently so even a 1-byte row budget has a useful typed result.
const NESTED_CURSOR_ERROR_SENTINEL_MAX_BYTES: usize = 512;

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

/// Row, cell, byte, and depth limits for structured Oracle value decoding.
///
/// These caps apply before a driver-side ARRAY/JSON/VECTOR value is expanded
/// into the public [`OracleCell::structured`] JSON payload. When a cap is hit,
/// the serializer emits the existing explicit unsupported marker instead of
/// silently flattening or dumping an unbounded value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructuredDecodeCaps {
    /// Maximum direct entries decoded for one array/object-like structured node.
    pub max_rows: usize,
    /// Maximum structured value nodes decoded across one cell.
    pub max_cells: usize,
    /// Maximum compact JSON bytes decoded for one structured node.
    pub max_bytes: usize,
    /// Maximum recursion depth decoded inside one structured cell. The root is
    /// depth zero.
    pub max_depth: usize,
}

impl StructuredDecodeCaps {
    /// Safe default caps used by `oracle_query` unless the caller opts into
    /// deeper structured decoding.
    pub const DEFAULT: Self = Self {
        max_rows: 1_000,
        max_cells: 10_000,
        max_bytes: 1_048_576,
        max_depth: 8,
    };

    /// Larger non-default caps used when a caller sets `deep_decode=true`.
    pub const DEEP: Self = Self {
        max_rows: 10_000,
        max_cells: 100_000,
        max_bytes: 5 * 1024 * 1024,
        max_depth: 32,
    };

    /// Construct an explicit cap set.
    #[must_use]
    pub const fn new(
        max_rows: usize,
        max_cells: usize,
        max_bytes: usize,
        max_depth: usize,
    ) -> Self {
        Self {
            max_rows,
            max_cells,
            max_bytes,
            max_depth,
        }
    }

    /// Return the larger, non-default deep decode cap set.
    #[must_use]
    pub const fn deep() -> Self {
        Self::DEEP
    }
}

impl Default for StructuredDecodeCaps {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Options governing serialization.
#[derive(Clone, Debug)]
pub struct SerializeOptions {
    /// Emit NUMBER as a JSON float (lossy for >15 sig digits) instead of the
    /// default lossless string.
    pub numbers_as_float: bool,
    /// Max characters of ordinary text/raw columns to inline. `None` means no
    /// per-column text cap beyond the page byte cap.
    pub max_text_chars: Option<usize>,
    /// Max characters of a CLOB/text value to inline before truncating.
    pub max_lob_chars: usize,
    /// Max bytes of a BLOB to base64-inline before truncating.
    pub max_blob_bytes: usize,
    /// Max rows fetched from a nested REF CURSOR / implicit result.
    pub max_nested_cursor_rows: usize,
    /// Max cells fetched from a nested REF CURSOR / implicit result.
    pub max_nested_cursor_cells: usize,
    /// Max compact serialized bytes across row objects in one nested REF CURSOR
    /// / implicit result. Columns and structural metadata are excluded. A first
    /// row that exceeds this budget is replaced by a typed error sentinel of at
    /// most 512 bytes.
    pub max_nested_cursor_bytes: usize,
    /// Max nested cursor depth. A top-level REF CURSOR cell is depth 0.
    pub max_nested_cursor_depth: usize,
    /// Decode caps for structured Oracle ARRAY/JSON/VECTOR cells.
    pub structured_decode_caps: StructuredDecodeCaps,
    /// Optional fail-closed result masking policy applied after cell
    /// serialization and before rows leave the DB layer.
    pub result_masking: Option<ResultMaskingPolicy>,
}

impl Default for SerializeOptions {
    fn default() -> Self {
        SerializeOptions {
            numbers_as_float: false,
            max_text_chars: None,
            max_lob_chars: 32_768,
            max_blob_bytes: 1_048_576,
            max_nested_cursor_rows: 100,
            max_nested_cursor_cells: 1_000,
            max_nested_cursor_bytes: 1_048_576,
            max_nested_cursor_depth: 2,
            structured_decode_caps: StructuredDecodeCaps::DEFAULT,
            result_masking: None,
        }
    }
}

/// Stable cache key for schema/object metadata that embeds serialized Oracle
/// values.
///
/// The dashboard/object explorer cache is intentionally keyed by the database
/// identity, the effective profile/user/schema visibility boundary, and the
/// structured serialization contract version. A future shape bump changes this
/// key even if the database metadata itself is unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OracleMetadataCacheKey {
    /// Stable fingerprint of the database identity.
    pub db_fingerprint: String,
    /// Connection profile whose visibility rules produced the metadata.
    pub profile: String,
    /// Effective Oracle user for the metadata view.
    pub user: String,
    /// Visible schema whose objects are cached.
    pub visible_schema: String,
    /// Structured OracleCell serialization contract version.
    pub serialization_contract_version: u16,
}

impl OracleMetadataCacheKey {
    /// Build a cache key using the current structured serialization contract.
    #[must_use]
    pub fn new(
        db_fingerprint: impl Into<String>,
        profile: impl Into<String>,
        user: impl Into<String>,
        visible_schema: impl Into<String>,
    ) -> Self {
        Self::with_serialization_contract_version(
            db_fingerprint,
            profile,
            user,
            visible_schema,
            ORACLE_CELL_STRUCTURED_CONTRACT_VERSION,
        )
    }

    /// Build a cache key with an explicit contract version.
    ///
    /// This constructor exists for tests and migrations that need to prove a
    /// version bump invalidates cache identity without changing any other
    /// dimension.
    #[must_use]
    pub fn with_serialization_contract_version(
        db_fingerprint: impl Into<String>,
        profile: impl Into<String>,
        user: impl Into<String>,
        visible_schema: impl Into<String>,
        serialization_contract_version: u16,
    ) -> Self {
        OracleMetadataCacheKey {
            db_fingerprint: db_fingerprint.into(),
            profile: profile.into(),
            user: user.into(),
            visible_schema: visible_schema.into(),
            serialization_contract_version,
        }
    }
}

fn capped_text_value(text: &str, cap: Option<usize>, source_length: Option<usize>) -> Value {
    let Some(cap) = cap else {
        return Value::String(text.to_owned());
    };
    let char_length = source_length.unwrap_or_else(|| text.chars().count());
    if char_length > cap {
        let value: String = text.chars().take(cap).collect();
        json!({ "value": value, "truncated": true, "char_length": char_length })
    } else {
        Value::String(text.to_owned())
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

/// Classify a pre-uppercased, pre-trimmed Oracle type name. Callers that already
/// hold the canonical-cased name (the per-column cache) use this to skip the
/// re-uppercase; [`classify_type`] is the trimming/uppercasing front door.
fn classify_uppercased(t: &str) -> TypeRepr {
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

/// Classify an Oracle type name (as rendered by the driver, e.g. `"NUMBER"`,
/// `"VARCHAR2(50)"`, `"TIMESTAMP(6) WITH TIME ZONE"`).
#[must_use]
pub fn classify_type(oracle_type: &str) -> TypeRepr {
    classify_uppercased(&oracle_type.trim().to_ascii_uppercase())
}

/// The constant-per-column classification: the [`TypeRepr`] plus the NUMBER
/// distinction the numeric branch needs, computed once so a page of rows never
/// re-uppercases a column's type per cell.
#[derive(Clone, Copy, Debug)]
struct ColumnRepr {
    repr: TypeRepr,
    is_number_type: bool,
}

impl ColumnRepr {
    fn classify(oracle_type: &str) -> Self {
        let t = oracle_type.trim().to_ascii_uppercase();
        ColumnRepr {
            repr: classify_uppercased(&t),
            is_number_type: t.starts_with("NUMBER"),
        }
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
    // Byte-identical single-pass form of:
    //   text.replacen(' ', "T", 1).replace(" +", "+").replace(" -", "-")
    // The output never grows (each transform is a 1:1 'T' substitution or a
    // space deletion), so one `text.len()`-capacity allocation always suffices —
    // down from the three allocations the chained `replacen`/`replace` made.
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut run_start = 0usize;
    let mut first_space_replaced = false;
    for i in 0..bytes.len() {
        if bytes[i] != b' ' {
            continue;
        }
        if !first_space_replaced {
            // Replace only the first space with the ISO date/time separator 'T'.
            out.push_str(&text[run_start..i]);
            out.push('T');
            run_start = i + 1;
            first_space_replaced = true;
        } else if matches!(bytes.get(i + 1).copied(), Some(b'+') | Some(b'-')) {
            // Close the gap before a timezone sign (" +" → "+", " -" → "-").
            out.push_str(&text[run_start..i]);
            run_start = i + 1;
        }
    }
    out.push_str(&text[run_start..]);
    out
}

/// Serialize one cell to its canonical JSON value per the type table.
#[must_use]
pub fn serialize_cell(cell: &OracleCell, opts: &SerializeOptions) -> Value {
    serialize_cell_classified(cell, ColumnRepr::classify(&cell.oracle_type), opts)
}

/// Serialize a cell whose column classification is already known, so a page of
/// rows classifies each column once instead of once per cell.
fn serialize_cell_classified(cell: &OracleCell, col: ColumnRepr, opts: &SerializeOptions) -> Value {
    if let Some(nested) = &cell.nested_result {
        return serialize_nested_result(nested, opts);
    }
    if let Some(structured) = &cell.structured {
        return structured.clone();
    }
    // Binary columns carrying raw bytes always base64 (with a cap).
    if let Some(bytes) = &cell.bytes {
        let byte_length = cell.source_length.unwrap_or(bytes.len());
        let truncated = byte_length > opts.max_blob_bytes || bytes.len() > opts.max_blob_bytes;
        let slice_len = if truncated {
            bytes.len().min(opts.max_blob_bytes)
        } else {
            bytes.len()
        };
        let slice = &bytes[..slice_len];
        return json!({
            "encoding": "base64",
            "data": base64_encode(slice),
            "byte_length": byte_length,
            "truncated": truncated,
        });
    }
    let Some(text) = cell.text() else {
        return Value::Null;
    };
    match col.repr {
        TypeRepr::Numeric => {
            if opts.numbers_as_float {
                match text.parse::<f64>() {
                    Ok(f) => serde_json::Number::from_f64(f)
                        .map_or_else(|| Value::String(text.to_owned()), Value::Number),
                    Err(_) => Value::String(text.to_owned()),
                }
            } else if col.is_number_type || significant_digits(text) > 15 {
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
        TypeRepr::Text | TypeRepr::Raw => {
            capped_text_value(text, opts.max_text_chars, cell.source_length)
        }
        TypeRepr::Clob => {
            let char_length = cell.source_length.unwrap_or_else(|| text.chars().count());
            if char_length > opts.max_lob_chars {
                let s: String = text.chars().take(opts.max_lob_chars).collect();
                json!({ "value": s, "truncated": true, "char_length": char_length })
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

fn serialize_nested_result(
    nested: &crate::types::OracleNestedResult,
    opts: &SerializeOptions,
) -> Value {
    let column_cache = nested.rows.first().map(PageColumnCache::from_row);
    let mut rows = Vec::with_capacity(nested.rows.len());
    let mut total_bytes = 0usize;
    let mut byte_truncated = false;
    for (row_index, row) in nested.rows.iter().enumerate() {
        let remaining = opts.max_nested_cursor_bytes.saturating_sub(total_bytes);
        let serialized = match &column_cache {
            Some(cache) => cache.serialize_row_with_budget(row, opts, remaining),
            None => PageColumnCache::from_row(row).serialize_row_with_budget(row, opts, remaining),
        };
        let (value, size) = match serialized {
            Ok(serialized) => serialized,
            Err(size) => {
                if rows.is_empty() {
                    let sentinel = json!({
                        "error": {
                            "type": "ROW_TOO_LARGE",
                            "row_index": row_index,
                            "row_bytes": size,
                            "max_row_bytes": opts.max_nested_cursor_bytes,
                            "message": "nested cursor row exceeds the compact row-payload byte budget",
                            "next_step": "select fewer nested columns or lower per-cell text/LOB limits"
                        },
                        "rows": [],
                        "row_count": 0,
                        "fetched_count": nested.fetched_count,
                        "truncated": true,
                    });
                    debug_assert!(
                        json_byte_len(&sentinel) <= NESTED_CURSOR_ERROR_SENTINEL_MAX_BYTES,
                        "nested cursor row-too-large sentinel must remain structurally bounded"
                    );
                    return sentinel;
                }
                byte_truncated = true;
                break;
            }
        };
        let Some(next_total) =
            checked_byte_budget_add(total_bytes, size, opts.max_nested_cursor_bytes)
        else {
            // `serialize_row_with_budget` admitted this row against the exact
            // remaining budget, so only an arithmetic/accounting defect could
            // reach here. Fail closed rather than emitting an oversized page.
            byte_truncated = true;
            break;
        };
        total_bytes = next_total;
        rows.push(value);
    }
    let row_count = rows.len();
    json!({
        "columns": nested.columns,
        "rows": rows,
        "row_count": row_count,
        "fetched_count": nested.fetched_count,
        "truncated": nested.truncated || byte_truncated || row_count < nested.rows.len(),
    })
}

/// Serialize a row to a JSON object keyed by (last-wins) column name.
#[must_use]
pub fn serialize_row(row: &OracleRow, opts: &SerializeOptions) -> Value {
    let mut map = serde_json::Map::with_capacity(row.columns.len());
    for (name, cell) in &row.columns {
        let col = ColumnRepr::classify(&cell.oracle_type);
        map.insert(
            name.clone(),
            serialize_cell_with_optional_mask(name, cell, col, opts),
        );
    }
    Value::Object(map)
}

fn serialize_cell_with_optional_mask(
    name: &str,
    cell: &OracleCell,
    col: ColumnRepr,
    opts: &SerializeOptions,
) -> Value {
    match opts.result_masking.as_ref() {
        Some(policy) => policy.apply_cell(
            &ResultColumnContext::result_column(name, &cell.oracle_type),
            cell,
            || serialize_cell_classified(cell, col, opts),
        ),
        None => serialize_cell_classified(cell, col, opts),
    }
}

/// A reusable per-column classification cache for serializing a whole page: the
/// column classifications are computed once from the first row and reused across
/// every row, avoiding a per-cell re-uppercase of constant column types.
pub(crate) struct PageColumnCache {
    columns: Vec<ColumnRepr>,
}

impl PageColumnCache {
    pub(crate) fn from_row(row: &OracleRow) -> Self {
        PageColumnCache {
            columns: row
                .columns
                .iter()
                .map(|(_, cell)| ColumnRepr::classify(&cell.oracle_type))
                .collect(),
        }
    }

    /// Serialize a row reusing the cached column classifications. A result-set
    /// page has a fixed column descriptor, so the cache is keyed by position; an
    /// index past the cache (a ragged row) classifies fresh rather than panicking.
    pub(crate) fn serialize_row(&self, row: &OracleRow, opts: &SerializeOptions) -> Value {
        let mut map = serde_json::Map::with_capacity(row.columns.len());
        for (idx, (name, cell)) in row.columns.iter().enumerate() {
            let col = self
                .columns
                .get(idx)
                .copied()
                .unwrap_or_else(|| ColumnRepr::classify(&cell.oracle_type));
            map.insert(
                name.clone(),
                serialize_cell_with_optional_mask(name, cell, col, opts),
            );
        }
        Value::Object(map)
    }

    /// Serialize one row while retaining its aggregate JSON object only while
    /// it fits `max_bytes`. Each cell is still serialized independently so its
    /// exact compact length can be counted, but once the object crosses the
    /// budget the already-built aggregate is dropped immediately. This avoids
    /// retaining an unbounded many-column `Value` merely to reject the row.
    ///
    /// The returned `Err` is the exact compact row-object length. Duplicate
    /// column names preserve [`serialize_row`]'s last-wins behavior; if a later
    /// duplicate shrinks an over-budget object back under the cap, the accepted
    /// object is reconstructed to preserve byte-identical ordinary pages.
    pub(crate) fn serialize_row_with_budget(
        &self,
        row: &OracleRow,
        opts: &SerializeOptions,
        max_bytes: usize,
    ) -> Result<(Value, usize), usize> {
        // `{}` is two bytes. Track last-wins value lengths separately from the
        // retained map so counting can continue after the aggregate is dropped.
        let mut total_bytes = 2usize;
        let mut value_sizes: HashMap<&str, usize> = HashMap::with_capacity(row.columns.len());
        let mut retained = Some(serde_json::Map::with_capacity(row.columns.len()));

        for (idx, (name, cell)) in row.columns.iter().enumerate() {
            let col = self
                .columns
                .get(idx)
                .copied()
                .unwrap_or_else(|| ColumnRepr::classify(&cell.oracle_type));
            let value = serialize_cell_with_optional_mask(name, cell, col, opts);
            let value_bytes = json_byte_len(&value);

            let next_total = if let Some(previous_bytes) = value_sizes.get(name.as_str()).copied() {
                total_bytes
                    .checked_sub(previous_bytes)
                    .and_then(|n| n.checked_add(value_bytes))
            } else {
                let comma_bytes = usize::from(!value_sizes.is_empty());
                total_bytes
                    .checked_add(comma_bytes)
                    .and_then(|n| n.checked_add(json_string_byte_len(name)))
                    .and_then(|n| n.checked_add(1)) // `:`
                    .and_then(|n| n.checked_add(value_bytes))
            };
            let Some(next_total) = next_total else {
                // A real compact JSON value cannot exceed the address space,
                // but fail closed if accounting ever reaches that boundary.
                return Err(usize::MAX);
            };
            total_bytes = next_total;
            value_sizes.insert(name.as_str(), value_bytes);

            if total_bytes <= max_bytes {
                if let Some(map) = &mut retained {
                    map.insert(name.clone(), value);
                }
            } else {
                retained = None;
            }
        }

        if total_bytes > max_bytes {
            return Err(total_bytes);
        }

        let value = retained.map_or_else(|| self.serialize_row(row, opts), Value::Object);
        debug_assert_eq!(json_byte_len(&value), total_bytes);
        Ok((value, total_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::OracleNestedResult;

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
    fn canonicalize_datetime_matches_reference_three_pass() {
        // Isomorphism proof (machine-checked): the single-pass canonicalizer must
        // be byte-identical to the original chained `replacen`/`replace` form for
        // every input, including adversarial space/sign layouts and multibyte text.
        fn reference(text: &str) -> String {
            let with_t = text.replacen(' ', "T", 1);
            with_t.replace(" +", "+").replace(" -", "-")
        }
        let corpus = [
            "",
            " ",
            "  ",
            "   ",
            "T",
            "+",
            "-",
            " +",
            " -",
            "  +",
            "  -",
            " -+",
            " +-",
            "a +b",
            "a -b",
            "a  +b",
            "a - b",
            "x  +  -  y",
            "2026-06-01 12:00:00",
            "2026-06-01 12:00:00.000000 +00:00",
            "2026-06-01 12:00:00.000000 -05:30",
            "2026-06-01T12:00:00",
            "2026-06-01T12:00:00.000000+00:00",
            "1999-12-31 23:59:59 +14:00",
            "  2026-01-01  00:00:00  +00:00  ",
            "no-spaces-2026-06-01",
            "héllo 2026 +€",
            "héllo -€ world",
            "a\tb c +d",
            "trailing space ",
            " leading",
        ];
        for input in corpus {
            assert_eq!(
                canonicalize_datetime(input),
                reference(input),
                "single-pass diverged from reference for {input:?}"
            );
        }
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
    fn text_cap_marks_truncated_text_without_changing_default() {
        let c = cell("VARCHAR2", "abcdef");
        assert_eq!(
            serialize_cell(&c, &SerializeOptions::default()),
            json!("abcdef")
        );

        let opts = SerializeOptions {
            max_text_chars: Some(3),
            ..Default::default()
        };
        assert_eq!(
            serialize_cell(&c, &opts),
            json!({ "value": "abc", "truncated": true, "char_length": 6 })
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
    fn structured_carrier_serializes_verbatim() {
        let c = OracleCell::structured(
            "JSON",
            json!({
                "kind": "json",
                "value": {
                    "items": [1, true, null, { "nested": "ok" }]
                }
            }),
        );
        assert_eq!(
            serialize_cell(&c, &SerializeOptions::default()),
            json!({
                "kind": "json",
                "value": {
                    "items": [1, true, null, { "nested": "ok" }]
                }
            })
        );
    }

    #[test]
    fn structured_contract_version_tags_cell_and_cache_key() {
        let cell = OracleCell::structured("JSON", json!({"kind": "null"}));
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
            "a contract bump must invalidate metadata cache identity"
        );
    }

    #[test]
    fn nested_result_serializes_rows_and_counts() {
        let nested = OracleNestedResult {
            columns: vec!["N".to_owned(), "LABEL".to_owned()],
            rows: vec![
                OracleRow {
                    columns: vec![
                        ("N".to_owned(), cell("NUMBER", "1")),
                        ("LABEL".to_owned(), cell("VARCHAR2", "one")),
                    ],
                },
                OracleRow {
                    columns: vec![
                        ("N".to_owned(), cell("NUMBER", "2")),
                        ("LABEL".to_owned(), cell("VARCHAR2", "two")),
                    ],
                },
            ],
            row_count: 2,
            fetched_count: 2,
            truncated: false,
        };
        let rendered = serialize_cell(
            &OracleCell::nested_result("REF CURSOR", nested),
            &SerializeOptions::default(),
        );

        assert_eq!(rendered["columns"], json!(["N", "LABEL"]));
        assert_eq!(rendered["row_count"], json!(2));
        assert_eq!(rendered["fetched_count"], json!(2));
        assert_eq!(rendered["truncated"], json!(false));
        assert_eq!(rendered["rows"][0], json!({ "N": "1", "LABEL": "one" }));
    }

    #[test]
    fn nested_result_byte_cap_marks_truncated() {
        let nested = OracleNestedResult {
            columns: vec!["TEXT".to_owned()],
            rows: vec![
                OracleRow {
                    columns: vec![("TEXT".to_owned(), cell("VARCHAR2", "short"))],
                },
                OracleRow {
                    columns: vec![("TEXT".to_owned(), cell("VARCHAR2", "longer row"))],
                },
            ],
            row_count: 2,
            fetched_count: 2,
            truncated: false,
        };
        let rendered = serialize_cell(
            &OracleCell::nested_result("REF CURSOR", nested),
            &SerializeOptions {
                max_nested_cursor_bytes: 16,
                ..Default::default()
            },
        );

        assert_eq!(rendered["row_count"], json!(1));
        assert_eq!(rendered["fetched_count"], json!(2));
        assert_eq!(rendered["truncated"], json!(true));
    }

    #[test]
    fn nested_result_first_oversized_row_becomes_bounded_typed_error() {
        let nested = OracleNestedResult {
            columns: vec!["TEXT".to_owned()],
            rows: vec![OracleRow {
                columns: vec![("TEXT".to_owned(), cell("VARCHAR2", "secret-row-value"))],
            }],
            row_count: 1,
            fetched_count: 1,
            truncated: false,
        };
        let rendered = serialize_cell(
            &OracleCell::nested_result("REF CURSOR", nested),
            &SerializeOptions {
                max_nested_cursor_bytes: 8,
                ..Default::default()
            },
        );

        assert_eq!(rendered["rows"], json!([]));
        assert_eq!(rendered["row_count"], json!(0));
        assert_eq!(rendered["fetched_count"], json!(1));
        assert_eq!(rendered["truncated"], json!(true));
        assert_eq!(rendered["error"]["type"], json!("ROW_TOO_LARGE"));
        assert_eq!(rendered["error"]["row_index"], json!(0));
        assert_eq!(rendered["error"]["max_row_bytes"], json!(8));
        assert!(
            rendered["error"]["row_bytes"]
                .as_u64()
                .is_some_and(|n| n > 8)
        );
        let encoded = rendered.to_string();
        assert!(
            !encoded.contains("secret-row-value"),
            "raw oversized row leaked"
        );
        assert!(
            encoded.len() <= NESTED_CURSOR_ERROR_SENTINEL_MAX_BYTES,
            "typed nested sentinel exceeded its structural allowance: {} bytes",
            encoded.len()
        );
    }

    #[test]
    fn checked_byte_budget_add_handles_exact_boundary_and_overflow() {
        assert_eq!(checked_byte_budget_add(7, 5, 12), Some(12));
        assert_eq!(checked_byte_budget_add(7, 6, 12), None);
        assert_eq!(checked_byte_budget_add(usize::MAX, 1, usize::MAX), None);
        assert_eq!(
            checked_byte_budget_add(usize::MAX - 1, 1, usize::MAX),
            Some(usize::MAX)
        );
    }

    #[test]
    fn budgeted_row_serializer_is_exact_and_preserves_last_wins_output() {
        let opts = SerializeOptions::default();
        let row = OracleRow {
            columns: vec![
                ("B".to_owned(), cell("VARCHAR2", "first")),
                ("A".to_owned(), cell("NUMBER", "42")),
                ("B".to_owned(), cell("VARCHAR2", "replacement")),
            ],
        };
        let expected = serialize_row(&row, &opts);
        let expected_bytes = json_byte_len(&expected);
        let cache = PageColumnCache::from_row(&row);

        let (actual, actual_bytes) = cache
            .serialize_row_with_budget(&row, &opts, expected_bytes)
            .expect("exact row budget must be admitted");
        assert_eq!(actual, expected);
        assert_eq!(actual_bytes, expected_bytes);
        assert_eq!(
            cache.serialize_row_with_budget(&row, &opts, expected_bytes - 1),
            Err(expected_bytes)
        );
    }

    #[test]
    fn budgeted_row_serializer_counts_many_columns_after_dropping_aggregate() {
        let opts = SerializeOptions::default();
        let row = OracleRow {
            columns: (0..256)
                .map(|idx| (format!("COLUMN_{idx}"), cell("VARCHAR2", &"x".repeat(1024))))
                .collect(),
        };
        let expected_bytes = json_byte_len(&serialize_row(&row, &opts));
        let cache = PageColumnCache::from_row(&row);

        assert_eq!(
            cache.serialize_row_with_budget(&row, &opts, 4096),
            Err(expected_bytes),
            "rejected row still reports exact checked size"
        );
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

    fn sample_values() -> Vec<Value> {
        vec![
            json!({"ID": "0", "NAME": "n0"}),
            json!({"z": 1, "a": "héllo €", "nested": {"b": [1, 2, 3], "c": null}}),
            json!({"value": "ab\"c\\d\ne", "truncated": true, "char_length": 12345}),
            json!("a \"quoted\" \\ string with \t tab"),
            json!(null),
            json!([1.5, "x", false, null]),
            json!({}),
        ]
    }

    #[test]
    fn json_byte_len_matches_to_string_len() {
        // T1: the single-pass byte count must equal the old `to_string().len()`.
        for v in sample_values() {
            assert_eq!(json_byte_len(&v), v.to_string().len(), "value: {v}");
        }
    }

    #[test]
    fn page_cache_serializes_byte_identically_to_per_cell() {
        // T2: classifying each column once and reusing it across rows must give
        // byte-identical JSON to classifying per cell.
        let opts = SerializeOptions::default();
        let rows = vec![
            OracleRow {
                columns: vec![
                    ("ID".to_owned(), cell("NUMBER", "1")),
                    ("WHEN".to_owned(), cell("DATE", "2026-06-01 12:00:00")),
                    ("BODY".to_owned(), cell("CLOB", "abcdef")),
                ],
            },
            OracleRow {
                columns: vec![
                    ("ID".to_owned(), cell("NUMBER", "1234567890123456789")),
                    ("WHEN".to_owned(), cell("DATE", "2026-12-31 23:59:59")),
                    ("BODY".to_owned(), cell("CLOB", "")),
                ],
            },
        ];
        let cache = PageColumnCache::from_row(&rows[0]);
        for row in &rows {
            let per_cell = serialize_row(row, &opts);
            let cached = cache.serialize_row(row, &opts);
            assert_eq!(cached, per_cell);
            assert_eq!(cached.to_string(), per_cell.to_string());
        }
    }

    #[test]
    fn page_cache_handles_mixed_case_and_padded_type_names() {
        // The cache must classify identically regardless of casing/whitespace in
        // the driver-rendered type name.
        let opts = SerializeOptions::default();
        let first = OracleRow {
            columns: vec![("V".to_owned(), cell("  number  ", "9999999999999999999"))],
        };
        let row = OracleRow {
            columns: vec![("V".to_owned(), cell("NuMbEr", "42"))],
        };
        let cache = PageColumnCache::from_row(&first);
        assert_eq!(cache.serialize_row(&row, &opts), serialize_row(&row, &opts));
    }

    #[test]
    fn classify_type_public_signature_unchanged() {
        assert_eq!(classify_type("number"), TypeRepr::Numeric);
        assert_eq!(classify_type("  VARCHAR2(50) "), TypeRepr::Text);
        assert_eq!(
            classify_type("TIMESTAMP(6) WITH TIME ZONE"),
            TypeRepr::Timestamp
        );
        assert_eq!(classify_type("DATE"), TypeRepr::Date);
        assert_eq!(classify_type("SDO_GEOMETRY"), TypeRepr::Unsupported);
    }
}
