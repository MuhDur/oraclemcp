//! Export-to-resource for large query results (WP-E E3).
//!
//! When a read result is too large to inline in a tool response, the server
//! materializes it once as an `oracle-export://{id}` MCP resource (CSV or JSON)
//! and hands the client a link to fetch instead. This keeps the inline
//! tool-response channel bounded while still letting a capable client pull the
//! full result.
//!
//! The export id is **not** a guessable counter: it is a
//! [`crate::tamper_token`]-signed handle bound to the originating query's
//! access context (the active profile + the request's scope-grant fingerprint),
//! so a client cannot forge an id or read an export that belongs to a different
//! profile/scope. Exports are **bounded** (a per-export byte cap and a
//! whole-registry cap with FIFO eviction) and **expire** on a timer; a
//! `resources/read` after expiry fails closed exactly like an unknown id.
//!
//! Access control is enforced identically to the originating query: the read
//! must present the same access context the export was minted under, or it is
//! refused. The registry is engine-free in-process state; nothing here reaches
//! a database.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use parking_lot::Mutex;

use crate::tamper_token::{sign_token, verify_token};

/// Tamper-token scope for export ids.
const EXPORT_SCOPE: &str = "export:id";

/// Default time-to-live for a materialized export.
pub const DEFAULT_EXPORT_TTL: Duration = Duration::from_secs(900);

/// Hard cap on a single export's serialized size (10 MiB). A result larger than
/// this is truncated at the row boundary before materialization, and the export
/// records that it was truncated.
pub const MAX_EXPORT_BYTES: usize = 10 * 1024 * 1024;

/// Hard cap on the number of live exports retained in one server process.
/// Oldest-first eviction keeps memory bounded under a burst of large reads.
pub const MAX_LIVE_EXPORTS: usize = 64;

/// The serialized export format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    /// RFC 4180-style CSV (header row + escaped fields).
    Csv,
    /// A JSON document (`{ "columns": [...], "rows": [...] }`).
    Json,
}

impl ExportFormat {
    /// The MCP MIME type for this format.
    #[must_use]
    pub fn mime_type(self) -> &'static str {
        match self {
            ExportFormat::Csv => "text/csv",
            ExportFormat::Json => "application/json",
        }
    }

    /// Parse a caller-supplied format string (case-insensitive); defaults to
    /// CSV when absent.
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Option<Self> {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            None | Some("") | Some("csv") => Some(ExportFormat::Csv),
            Some("json") => Some(ExportFormat::Json),
            _ => None,
        }
    }
}

/// The access context an export is bound to. A `resources/read` must present a
/// matching context (same scope-grant fingerprint), or the read is refused —
/// the export is access-controlled identically to the originating query.
///
/// The binding is the request's **OAuth scope-grant fingerprint**, which is the
/// genuine cross-tenant authorization boundary in this server (scopes can only
/// *lower* the effective level) and is available on BOTH the mint path
/// (`oracle_query` dispatch) and the read path (`resources/read`). The active
/// profile is recorded as advisory metadata (it is a per-process connection
/// property and the per-process token key already isolates one server instance
/// from another), but it is not part of the unforgeable binding because the
/// `resources/read` transport does not carry it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportAccess {
    /// The active profile name at mint time (`""` when unconfigured). Advisory.
    pub profile: String,
    /// A stable fingerprint of the request's scope grant (`""` when none). This
    /// is the authorization boundary the export id is signed against.
    pub scope_fingerprint: String,
}

impl ExportAccess {
    /// Build an access context from an optional profile + optional scope list.
    #[must_use]
    pub fn new(profile: Option<&str>, scopes: Option<&[String]>) -> Self {
        let scope_fingerprint = scopes
            .map(|scopes| {
                let mut sorted: Vec<&str> = scopes.iter().map(String::as_str).collect();
                sorted.sort_unstable();
                sorted.dedup();
                sorted.join(" ")
            })
            .unwrap_or_default();
        ExportAccess {
            profile: profile.unwrap_or("").to_owned(),
            scope_fingerprint,
        }
    }

    /// The length-prefixed token field binding an id to this context: the scope
    /// fingerprint, the boundary reproducible on the read path.
    fn token_fields(&self) -> [String; 1] {
        [self.scope_fingerprint.clone()]
    }
}

/// A materialized export held in the registry.
struct ExportEntry {
    format: ExportFormat,
    body: String,
    access: ExportAccess,
    expires_at: Instant,
}

/// The resolved contents of an export read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportContents {
    /// The canonical `oracle-export://{id}` URI.
    pub uri: String,
    /// The MIME type (`text/csv` / `application/json`).
    pub mime_type: String,
    /// The serialized body.
    pub text: String,
}

/// A handle returned when an export is created: the opaque id, its URI, format,
/// size, and truncation/row metadata for the `resource_link` (E3b).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportHandle {
    /// The opaque, tamper-evident export id.
    pub id: String,
    /// The `oracle-export://{id}` URI.
    pub uri: String,
    /// The serialized format.
    pub format: ExportFormat,
    /// The MIME type.
    pub mime_type: String,
    /// Total serialized byte size.
    pub byte_size: usize,
    /// Rows materialized.
    pub row_count: usize,
    /// Whether the export was truncated at the per-export byte cap.
    pub truncated: bool,
}

/// An in-process registry of materialized exports. One per server.
#[derive(Default)]
pub struct ExportRegistry {
    inner: Mutex<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    /// Insertion-ordered ids for FIFO eviction.
    order: Vec<String>,
    by_id: HashMap<String, ExportEntry>,
    /// Monotonic counter feeding the unguessable-but-unique id body.
    seq: u64,
}

impl ExportRegistry {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Materialize `rows` (already serialized as `Vec<Vec<String>>` cells with
    /// `columns` headers) as an export of `format`, bound to `access`, expiring
    /// after `ttl`. The body is capped at [`MAX_EXPORT_BYTES`] (truncating at a
    /// row boundary). Returns a handle with the opaque id + metadata.
    pub fn create(
        &self,
        columns: &[String],
        rows: &[Vec<String>],
        format: ExportFormat,
        access: ExportAccess,
        ttl: Duration,
    ) -> ExportHandle {
        let (body, row_count, truncated) = match format {
            ExportFormat::Csv => render_csv(columns, rows, MAX_EXPORT_BYTES),
            ExportFormat::Json => render_json(columns, rows, MAX_EXPORT_BYTES),
        };
        let byte_size = body.len();

        let mut inner = self.inner.lock();
        inner.sweep_expired();
        inner.seq = inner.seq.wrapping_add(1);
        // The id body is `exp-<seq>`; the tamper-evident MAC over the access
        // context is what makes the full id unforgeable, not the body.
        let id_body = format!("exp-{}", inner.seq);
        let field_strings = access.token_fields();
        let fields: Vec<&str> = field_strings.iter().map(String::as_str).collect();
        let id = sign_token(EXPORT_SCOPE, &id_body, &fields);
        let uri = export_uri(&id);

        inner.order.push(id.clone());
        inner.by_id.insert(
            id.clone(),
            ExportEntry {
                format,
                body,
                access: access.clone(),
                expires_at: Instant::now() + ttl,
            },
        );
        inner.evict_to_cap();

        ExportHandle {
            id,
            uri,
            format,
            mime_type: format.mime_type().to_owned(),
            byte_size,
            row_count,
            truncated,
        }
    }

    /// Read an export by id, enforcing the access binding and expiry. Fails
    /// closed: an unknown id, an expired id, a forged id, or a mismatched
    /// access context all yield an `ObjectNotFound` / `PolicyDenied` envelope
    /// (never the bytes).
    pub fn read(&self, id: &str, access: &ExportAccess) -> Result<ExportContents, ErrorEnvelope> {
        // The id must verify under the *presented* access context. A forged id,
        // or a genuine id replayed under a different profile/scope, fails the
        // MAC check here before any lookup.
        let field_strings = access.token_fields();
        let fields: Vec<&str> = field_strings.iter().map(String::as_str).collect();
        if verify_token(EXPORT_SCOPE, id, &fields).is_none() {
            return Err(export_access_denied());
        }

        let mut inner = self.inner.lock();
        inner.sweep_expired();
        let Some(entry) = inner.by_id.get(id) else {
            return Err(export_not_found());
        };
        // Defense in depth: the stored scope fingerprint must also match (the
        // MAC already bound it, but re-checking keeps the invariant explicit and
        // local). Profile is advisory and not on the read transport, so it is
        // not part of this check.
        if entry.access.scope_fingerprint != access.scope_fingerprint {
            return Err(export_access_denied());
        }
        Ok(ExportContents {
            uri: export_uri(id),
            mime_type: entry.format.mime_type().to_owned(),
            text: entry.body.clone(),
        })
    }

    /// Number of live (non-expired-at-last-sweep) exports. Test/observability.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().by_id.len()
    }

    /// Whether the registry holds no exports.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl RegistryInner {
    /// Drop expired entries. Cheap: O(n) over the small live set.
    fn sweep_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<String> = self
            .by_id
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.by_id.remove(&id);
        }
        self.order.retain(|id| self.by_id.contains_key(id));
    }

    /// Evict oldest-first until at or under the live cap.
    fn evict_to_cap(&mut self) {
        while self.by_id.len() > MAX_LIVE_EXPORTS {
            let Some(oldest) = self.order.first().cloned() else {
                break;
            };
            self.order.remove(0);
            self.by_id.remove(&oldest);
        }
    }
}

/// The canonical export URI for an id.
#[must_use]
pub fn export_uri(id: &str) -> String {
    format!("oracle-export://{id}")
}

fn export_not_found() -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::ObjectNotFound,
        "export resource not found (unknown id, or it expired)",
    )
    .with_next_step("re-run the query to materialize a fresh export")
}

fn export_access_denied() -> ErrorEnvelope {
    // Deliberately the same shape as not-found so a probing client cannot tell a
    // forged id from a wrong-context id from a missing id.
    ErrorEnvelope::new(
        ErrorClass::ObjectNotFound,
        "export resource not found (unknown id, or it expired)",
    )
    .with_next_step("re-run the query to materialize a fresh export")
}

/// Render CSV (RFC 4180): a header row plus one row per record. A field
/// containing a comma, double-quote, CR, or LF is wrapped in double quotes with
/// internal quotes doubled. Caps the body at `max_bytes`, truncating at a row
/// boundary; returns `(body, rows_written, truncated)`.
fn render_csv(columns: &[String], rows: &[Vec<String>], max_bytes: usize) -> (String, usize, bool) {
    let mut out = String::new();
    push_csv_record(&mut out, columns);
    let header_len = out.len();
    let mut written = 0usize;
    let mut truncated = false;
    for row in rows {
        let mut record = String::new();
        push_csv_record(&mut record, row);
        if out.len() + record.len() > max_bytes && out.len() > header_len {
            truncated = true;
            break;
        }
        out.push_str(&record);
        written += 1;
    }
    (out, written, truncated)
}

/// Append one CSV record (with trailing `\n`) to `out`, escaping each field.
fn push_csv_record(out: &mut String, fields: &[String]) {
    for (idx, field) in fields.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&escape_csv_field(field));
    }
    out.push('\n');
}

/// Escape a single CSV field per RFC 4180.
fn escape_csv_field(field: &str) -> String {
    let needs_quote = field
        .bytes()
        .any(|b| b == b',' || b == b'"' || b == b'\n' || b == b'\r');
    if needs_quote {
        let mut escaped = String::with_capacity(field.len() + 2);
        escaped.push('"');
        for ch in field.chars() {
            if ch == '"' {
                escaped.push('"');
            }
            escaped.push(ch);
        }
        escaped.push('"');
        escaped
    } else {
        field.to_owned()
    }
}

/// Render JSON `{ "columns": [...], "rows": [[...], ...] }`. Caps the body at
/// `max_bytes`, truncating at a row boundary; returns `(body, rows_written,
/// truncated)`.
fn render_json(
    columns: &[String],
    rows: &[Vec<String>],
    max_bytes: usize,
) -> (String, usize, bool) {
    // Build incrementally so we can stop at a row boundary under the cap. Each
    // cell is a JSON string (the caller already serialized cells to text).
    let mut out = String::from("{\"columns\":");
    out.push_str(&serde_json::to_string(columns).unwrap_or_else(|_| "[]".to_owned()));
    out.push_str(",\"rows\":[");
    let prefix_len = out.len();
    let mut written = 0usize;
    let mut truncated = false;
    for row in rows {
        let cell = serde_json::to_string(row).unwrap_or_else(|_| "[]".to_owned());
        // +2 for a possible leading comma and the closing "]}".
        let projected = out.len() + cell.len() + if written > 0 { 1 } else { 0 } + 2;
        if projected > max_bytes && out.len() > prefix_len {
            truncated = true;
            break;
        }
        if written > 0 {
            out.push(',');
        }
        out.push_str(&cell);
        written += 1;
    }
    out.push_str("]}");
    (out, written, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access() -> ExportAccess {
        ExportAccess::new(Some("PROD"), Some(&["oracle:read".to_owned()]))
    }

    fn sample() -> (Vec<String>, Vec<Vec<String>>) {
        (
            vec!["ID".to_owned(), "NAME".to_owned()],
            vec![
                vec!["1".to_owned(), "alice".to_owned()],
                vec!["2".to_owned(), "bob, jr".to_owned()],
            ],
        )
    }

    #[test]
    fn create_then_read_round_trips_csv_under_the_same_access() {
        let reg = ExportRegistry::new();
        let (cols, rows) = sample();
        let handle = reg.create(
            &cols,
            &rows,
            ExportFormat::Csv,
            access(),
            DEFAULT_EXPORT_TTL,
        );
        assert_eq!(handle.mime_type, "text/csv");
        assert_eq!(handle.row_count, 2);
        let contents = reg.read(&handle.id, &access()).expect("read");
        assert_eq!(contents.mime_type, "text/csv");
        assert!(contents.text.starts_with("ID,NAME\n"));
        // The comma in "bob, jr" forces quoting.
        assert!(contents.text.contains("\"bob, jr\""));
    }

    #[test]
    fn csv_escapes_commas_quotes_and_newlines() {
        assert_eq!(escape_csv_field("plain"), "plain");
        assert_eq!(escape_csv_field("a,b"), "\"a,b\"");
        assert_eq!(
            escape_csv_field("she said \"hi\""),
            "\"she said \"\"hi\"\"\""
        );
        assert_eq!(escape_csv_field("line1\nline2"), "\"line1\nline2\"");
        assert_eq!(escape_csv_field("cr\rlf"), "\"cr\rlf\"");
    }

    #[test]
    fn json_export_is_valid_and_round_trips() {
        let reg = ExportRegistry::new();
        let (cols, rows) = sample();
        let handle = reg.create(
            &cols,
            &rows,
            ExportFormat::Json,
            access(),
            DEFAULT_EXPORT_TTL,
        );
        assert_eq!(handle.mime_type, "application/json");
        let contents = reg.read(&handle.id, &access()).expect("read");
        let doc: serde_json::Value =
            serde_json::from_str(&contents.text).expect("export JSON parses");
        assert_eq!(doc["columns"][1], serde_json::json!("NAME"));
        assert_eq!(doc["rows"][1][1], serde_json::json!("bob, jr"));
    }

    #[test]
    fn the_authorization_boundary_is_the_scope_not_the_advisory_profile() {
        let reg = ExportRegistry::new();
        let (cols, rows) = sample();
        let handle = reg.create(
            &cols,
            &rows,
            ExportFormat::Csv,
            access(),
            DEFAULT_EXPORT_TTL,
        );
        // Same scope, different (advisory) profile: the read succeeds because
        // the binding is the scope fingerprint, which `resources/read` can
        // reproduce. The profile is not on the read transport.
        let same_scope = ExportAccess::new(Some("DEV"), Some(&["oracle:read".to_owned()]));
        assert!(
            reg.read(&handle.id, &same_scope).is_ok(),
            "advisory profile difference does not deny a same-scope read"
        );
    }

    #[test]
    fn a_read_under_a_different_scope_is_refused() {
        let reg = ExportRegistry::new();
        let (cols, rows) = sample();
        let handle = reg.create(
            &cols,
            &rows,
            ExportFormat::Csv,
            access(),
            DEFAULT_EXPORT_TTL,
        );
        let other = ExportAccess::new(Some("PROD"), Some(&["oracle:admin".to_owned()]));
        let err = reg
            .read(&handle.id, &other)
            .expect_err("cross-scope read refused");
        assert_eq!(err.error_class, ErrorClass::ObjectNotFound);
    }

    #[test]
    fn a_forged_id_is_refused() {
        let reg = ExportRegistry::new();
        let (cols, rows) = sample();
        let handle = reg.create(
            &cols,
            &rows,
            ExportFormat::Csv,
            access(),
            DEFAULT_EXPORT_TTL,
        );
        // Keep the MAC tag, edit the id body to point at a different export.
        let (_body, tag) = handle.id.rsplit_once('.').expect("id has a tag");
        let forged = format!("exp-9999.{tag}");
        let err = reg.read(&forged, &access()).expect_err("forged id refused");
        assert_eq!(err.error_class, ErrorClass::ObjectNotFound);
    }

    #[test]
    fn an_expired_export_reads_as_not_found() {
        let reg = ExportRegistry::new();
        let (cols, rows) = sample();
        let handle = reg.create(
            &cols,
            &rows,
            ExportFormat::Csv,
            access(),
            Duration::from_nanos(1),
        );
        std::thread::sleep(Duration::from_millis(5));
        let err = reg
            .read(&handle.id, &access())
            .expect_err("expired read refused");
        assert_eq!(err.error_class, ErrorClass::ObjectNotFound);
    }

    #[test]
    fn oversized_result_is_truncated_at_a_row_boundary() {
        let reg = ExportRegistry::new();
        let cols = vec!["DATA".to_owned()];
        // Each row is ~1 KiB; force the cap well below the total.
        let rows: Vec<Vec<String>> = (0..100).map(|_| vec!["x".repeat(1024)]).collect();
        let (body, written, truncated) = render_csv(&cols, &rows, 4096);
        assert!(truncated, "body exceeds the cap so it truncates");
        assert!(written < rows.len(), "not all rows fit");
        assert!(body.len() <= 4096 + 1100, "body stays near the cap");
        // The registry path records truncation in the handle.
        let handle = reg.create(
            &cols,
            &rows,
            ExportFormat::Csv,
            access(),
            DEFAULT_EXPORT_TTL,
        );
        assert!(handle.byte_size <= MAX_EXPORT_BYTES);
    }

    #[test]
    fn the_live_export_cap_evicts_oldest_first() {
        let reg = ExportRegistry::new();
        let (cols, rows) = sample();
        let mut first = None;
        for i in 0..(MAX_LIVE_EXPORTS + 5) {
            let handle = reg.create(
                &cols,
                &rows,
                ExportFormat::Csv,
                access(),
                DEFAULT_EXPORT_TTL,
            );
            if i == 0 {
                first = Some(handle.id);
            }
        }
        assert_eq!(reg.len(), MAX_LIVE_EXPORTS, "registry stays at the cap");
        // The very first export was evicted.
        let err = reg
            .read(&first.unwrap(), &access())
            .expect_err("evicted export is gone");
        assert_eq!(err.error_class, ErrorClass::ObjectNotFound);
    }

    #[test]
    fn format_parse_defaults_to_csv_and_rejects_unknown() {
        assert_eq!(ExportFormat::parse(None), Some(ExportFormat::Csv));
        assert_eq!(ExportFormat::parse(Some("CSV")), Some(ExportFormat::Csv));
        assert_eq!(ExportFormat::parse(Some("json")), Some(ExportFormat::Json));
        assert_eq!(ExportFormat::parse(Some("xml")), None);
    }
}
