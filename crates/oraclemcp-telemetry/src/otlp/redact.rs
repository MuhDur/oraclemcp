//! Secret redaction for telemetry (D1 / WP-D; AGENTS.md hard requirement).
//!
//! **Load-bearing**: telemetry MUST NEVER emit SQL bind values, passwords,
//! tokens, or wallet secrets. Every attribute key/value and log body that
//! crosses into a `LogsSnapshot`, a metric label, or an OTLP span attribute is
//! filtered through [`Redactor`] first.
//!
//! Two layers of defence:
//!
//! 1. **Key denylist** — an attribute whose key matches a sensitive name
//!    (`password`, `secret`, `token`, `bind`, `wallet`, `authorization`, …) is
//!    DROPPED entirely. The only sensitive-name exceptions are finite, exact,
//!    typed driver counters such as numeric `db.bind_count`.
//! 2. **Value redaction** — for attributes that survive the key check, values
//!    that *look* like a secret (a bearer token, a `key=value` credential, a
//!    long opaque blob) are replaced with `[REDACTED]`. This is a backstop for
//!    free-form fields (e.g. an error message that quoted a connect string).
//!
//! The finite allowlist of benign `db.*` keys contains only the exact semantic
//! fields emitted by this product/driver. An arbitrary `db.*` extension is not
//! implicitly safe, and value-shape redaction still applies after key admission.

/// Sentinel substituted for a redacted value.
pub const REDACTED: &str = "[REDACTED]";

/// Stateless secret-redaction policy. Cheap to clone.
#[derive(Clone, Copy, Debug, Default)]
pub struct Redactor {
    _private: (),
}

impl Redactor {
    /// A redactor with the default oraclemcp policy.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Returns `true` if an attribute with this key must be dropped wholesale.
    ///
    /// Case-insensitive substring match against the sensitive-name denylist.
    /// Exact typed database-counter exceptions remain observable; an arbitrary
    /// extension never inherits trust from the `db.` namespace.
    #[must_use]
    pub fn should_drop_key(&self, key: &str) -> bool {
        let key_lc = key.to_ascii_lowercase();
        // Defense-in-depth: the raw-SQL-text family must NEVER reach telemetry,
        // even though it is `db.*`-prefixed (we emit only the SQL SHA / bind-free
        // subset). Drop it before the `db.*` allowlist so a future accidental
        // emit of db.statement/db.query.text/db.query.parameter.* still can't leak.
        if DB_TEXT_DENY.iter().any(|d| key_lc == *d) || key_lc.starts_with("db.query.parameter") {
            return true;
        }
        let sensitive = SENSITIVE_KEY_FRAGMENTS
            .iter()
            .any(|fragment| key_lc.contains(fragment));
        // `db.bind_count` and `db.bind_rows` are typed numeric metadata emitted
        // by the active oracledb driver, not bind values. They are deliberately
        // exact-listed; arbitrary db.bind*/db.token*/etc. extensions still lose.
        sensitive && !is_known_safe_db_key(&key_lc)
    }

    /// Redact a value that survived the key check, returning the safe value.
    ///
    /// Secret-shape scanning applies to every admitted key. The only opaque
    /// value exempted from the heuristic is a `subject_id_hash` that matches its
    /// exact `subject-sha256:<64 lowercase hex>` domain. Invalid typed database
    /// counters are redacted here and dropped by [`Self::filter`].
    #[must_use]
    pub fn redact_value(&self, key: &str, value: &str) -> String {
        let key_lc = key.to_ascii_lowercase();
        if is_safe_bind_count_key(&key_lc) && value.parse::<u64>().is_err() {
            return REDACTED.to_owned();
        }
        // The subject hash is intentionally a 64-character opaque token, which
        // the generic entropy backstop would otherwise redact. Only bypass that
        // backstop when it has the exact SHA-256 hex domain promised by the key.
        if key.eq_ignore_ascii_case("subject_id_hash") && is_subject_sha256(value) {
            return value.to_owned();
        }
        if value_looks_secret(value) {
            REDACTED.to_owned()
        } else {
            value.to_owned()
        }
    }

    /// Filter a `(key, value)` pair: `None` if the key is denied or an exact
    /// typed counter has an invalid value, otherwise the key with its (possibly
    /// redacted) value. This is the single funnel every attribute should pass
    /// through before export.
    #[must_use]
    pub fn filter<'a>(&self, key: &'a str, value: &str) -> Option<(&'a str, String)> {
        if self.should_drop_key(key) {
            return None;
        }
        let key_lc = key.to_ascii_lowercase();
        if is_safe_bind_count_key(&key_lc) && value.parse::<u64>().is_err() {
            // The exact key exception is for typed driver counts only. A string
            // placed under the same name does not inherit that trust.
            return None;
        }
        Some((key, self.redact_value(key, value)))
    }
}

/// Substrings that mark an attribute key as carrying a secret. Matched
/// case-insensitively. Deliberately broad — a false positive only loses an
/// observability attribute, while a miss leaks a credential.
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "authorization",
    "auth_header",
    "credential",
    "wallet",
    "private_key",
    "privatekey",
    "session_key",
    "bearer",
    "cookie",
    "bind", // SQL bind values are never emitted (oraclemcp invariant)
    "dsn",
    "connect_string",
    "connection_string",
];

/// `db.*` keys that carry raw SQL / bind text and must be dropped regardless of
/// namespace or value. We only ever emit the SQL SHA + bind-free subset, so
/// these never appear — this is a backstop.
const DB_TEXT_DENY: &[&str] = &["db.statement", "db.query.text"];

/// Exact benign database attributes currently emitted by oraclemcp metrics or
/// the pinned oracledb tracing integration. Raw statement/query/parameter text
/// is intentionally absent. Keep this finite when either emitter grows.
fn is_known_safe_db_key(key_lc: &str) -> bool {
    matches!(
        key_lc,
        // Current OTel database semantic-convention fields.
        "db.system.name"
            | "db.namespace"
            | "db.operation.name"
            | "db.response.status_code"
            // Pinned oracledb tracing fields (bounded names/counts/booleans).
            | "db.system"
            | "db.name"
            | "db.operation"
            | "db.arraysize"
            | "db.batch_row_count"
            | "db.batch_row_error_count"
            | "db.batch_rows_affected"
            | "db.bind_count"
            | "db.bind_rows"
            | "db.cache_event"
            | "db.cache_existed"
            | "db.cache_generation"
            | "db.cursor_id"
            | "db.lob_amount"
            | "db.lob_bytes"
            | "db.lob_chunk_bytes"
            | "db.lob_chunk_chars"
            | "db.lob_chunk_units"
            | "db.lob_offset"
            | "db.lob_utf16_boundary_split"
            | "db.pages_fetched"
            | "db.prefetch_inflight_max"
            | "db.rows_fetched"
            | "db.rows_streamed"
    )
}

fn is_safe_bind_count_key(key_lc: &str) -> bool {
    matches!(key_lc, "db.bind_count" | "db.bind_rows")
}

fn is_subject_sha256(value: &str) -> bool {
    let Some(hash) = value.strip_prefix("subject-sha256:") else {
        return false;
    };
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn contains_sensitive_ocid(value: &str) -> bool {
    let value_lc = value.to_ascii_lowercase();
    for prefix in ["ocid1.tenancy.", "ocid1.user.", "ocid1.compartment."] {
        for (start, _) in value_lc.match_indices(prefix) {
            if value_lc[..start]
                .chars()
                .next_back()
                .is_some_and(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                })
            {
                continue;
            }
            let tail = &value_lc[start..];
            let end = tail
                .bytes()
                .position(|byte| {
                    !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-')
                })
                .unwrap_or(tail.len());
            let candidate = tail[..end].trim_end_matches('.');
            let parts = candidate.split('.').collect::<Vec<_>>();
            if parts.len() >= 5
                && parts[0] == "ocid1"
                && matches!(parts[1], "tenancy" | "user" | "compartment")
                && parts[2].starts_with("oc")
                && parts[2][2..].bytes().all(|byte| byte.is_ascii_digit())
                && parts.last().is_some_and(|unique| unique.len() >= 8)
            {
                return true;
            }
        }
    }
    false
}

/// Heuristic: does a free-form value look like a secret?
///
/// Catches the common shapes that show up in logs/error messages:
/// - `Bearer <blob>` / `Basic <blob>` auth values
/// - `password=...`, `secret=...`, `token=...` `k=v` credentials
/// - long opaque high-entropy-ish blobs (≥ 40 chars, no spaces, mixed case/digits)
///
/// It is intentionally conservative about ordinary prose (which contains spaces)
/// to avoid mangling legitimate messages, while still catching credentials.
fn value_looks_secret(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return false;
    }
    let v_lc = v.to_ascii_lowercase();

    // A `Bearer <token>` / `Basic <token>` auth scheme anywhere in the value —
    // not just as a prefix (a log body may quote it mid-sentence).
    for scheme in ["bearer ", "basic "] {
        if let Some(idx) = v_lc.find(scheme) {
            // Only treat it as a credential if a token-ish word follows.
            let rest = v_lc[idx + scheme.len()..].trim_start();
            if rest
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            {
                return true;
            }
        }
    }
    // `something=secret` inline credentials.
    for marker in [
        "password=",
        "passwd=",
        "secret=",
        "token=",
        "apikey=",
        "api_key=",
    ] {
        if v_lc.contains(marker) {
            return true;
        }
    }
    // Global OCI identity/container identifiers frequently appear inside error
    // prose rather than as a dedicated attribute. Treat their validated value
    // shape as sensitive wherever it occurs; resource OCIDs outside this
    // narrow tenancy/user/compartment set remain governed by their own fields.
    if contains_sensitive_ocid(v) {
        return true;
    }
    // Long opaque single-token blob (no whitespace), likely a key/token.
    if v.len() >= 40 && !v.chars().any(char::is_whitespace) {
        let has_alpha = v.chars().any(|c| c.is_ascii_alphabetic());
        let has_other = v.chars().any(|c| {
            c.is_ascii_digit() || c == '+' || c == '/' || c == '=' || c == '_' || c == '-'
        });
        if has_alpha && has_other {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_sensitive_keys() {
        let r = Redactor::new();
        for key in [
            "password",
            "DB_PASSWORD",
            "secret",
            "access_token",
            "authorization",
            "api-key",
            "wallet_pem",
            "bind_0",
            "bind.values",
            "connection_string",
        ] {
            assert!(r.should_drop_key(key), "{key} must be dropped");
            assert!(r.filter(key, "anything").is_none(), "{key} filtered out");
        }
    }

    #[test]
    fn raw_sql_db_keys_are_dropped_despite_db_prefix() {
        // Defense-in-depth: db.statement / db.query.text / db.query.parameter.*
        // carry raw SQL + binds and must be dropped even though `db.` is safe.
        let r = Redactor::new();
        for key in [
            "db.statement",
            "db.query.text",
            "db.query.parameter.0",
            "DB.QUERY.PARAMETER.user_id",
        ] {
            assert!(r.should_drop_key(key), "{key} must be dropped");
            assert!(
                r.filter(key, "SELECT * FROM t WHERE x = 'secret'")
                    .is_none()
            );
        }
        // Exact benign database keys still pass key admission.
        assert!(!r.should_drop_key("db.operation"));
        assert!(!r.should_drop_key("db.system.name"));
    }

    #[test]
    fn sensitive_db_extensions_never_bypass_the_key_denylist() {
        let r = Redactor::new();
        for key in [
            "db.password",
            "DB.PASSWD",
            "db.wallet_secret",
            "db.token",
            "db.authorization",
            "db.credential",
            "db.bind_value",
            "db.dsn",
            "db.connect_string",
            "db.connection_string",
        ] {
            assert!(r.should_drop_key(key), "{key} must be dropped");
            assert!(r.filter(key, "QA34_DB_SECRET_SENTINEL").is_none());
        }
    }

    #[test]
    fn finite_db_allowlist_preserves_benign_driver_metadata_only() {
        let r = Redactor::new();
        for (key, value) in [
            ("db.system.name", "oracle"),
            ("db.namespace", "service"),
            ("db.operation.name", "SELECT"),
            ("db.response.status_code", "942"),
            ("db.bind_count", "2"),
            ("db.bind_rows", "8"),
            ("db.rows_fetched", "40"),
        ] {
            assert_eq!(r.filter(key, value), Some((key, value.to_owned())));
        }

        let (_, value) = r
            .filter("db.vendor.extension", "Bearer QA34_DB_SECRET_SENTINEL")
            .expect("non-sensitive extension key remains observable");
        assert_eq!(value, REDACTED, "unknown db.* values use the backstop");
        assert!(
            r.filter("db.bind_count", "Bearer QA34_DB_SECRET_SENTINEL")
                .is_none(),
            "bind-count exception applies only to typed numeric values"
        );
        assert_eq!(
            r.redact_value("db.bind_count", "QA34_DB_SECRET_SENTINEL"),
            REDACTED,
            "direct value redaction also rejects a non-numeric count"
        );
    }

    #[test]
    fn keeps_ordinary_structured_values_verbatim() {
        let r = Redactor::new();
        for (key, value) in [
            ("tool", "oracle_query"),
            ("profile", "prod"),
            ("operating_level", "read_only"),
            ("row_count", "42"),
            ("ora_code", "942"),
            ("db.system", "oracle"),
            ("db.operation", "SELECT"),
            ("cache_hit", "true"),
        ] {
            assert!(!r.should_drop_key(key), "{key} kept");
            assert_eq!(
                r.filter(key, value),
                Some((key, value.to_owned())),
                "{key} value unchanged"
            );
        }
    }

    #[test]
    fn redacts_secret_looking_values_on_freeform_keys() {
        let r = Redactor::new();
        // A free-form key that is not in the denylist but whose value is a token.
        let (_k, v) = r
            .filter("error_detail", "Bearer abcdef....")
            .expect("kept key");
        assert_eq!(v, REDACTED);

        let (_k, v) = r
            .filter("note", "the connect used password=hunter2 oops")
            .expect("kept");
        assert_eq!(v, REDACTED);

        let (_k, v) = r
            .filter("blob", "AKIA1234567890ABCDEFGHIJ0987654321ZZZZ_extra")
            .expect("kept");
        assert_eq!(v, REDACTED, "long opaque blob redacted");
    }

    #[test]
    fn redacts_sensitive_ocids_embedded_in_prose() {
        let r = Redactor::new();
        for value in [
            "request used tenancy ocid1.tenancy.oc1..aaaaaaaabbbbbbbb, then failed",
            "principal=OCID1.USER.OC1..ABCDEF0123456789",
            "scope (ocid1.compartment.oc1.eu-frankfurt-1.abcdefghijklmnop)",
        ] {
            assert_eq!(
                r.redact_value("message", value),
                REDACTED,
                "sensitive OCID survived: {value}"
            );
        }
    }

    #[test]
    fn ocid_redaction_preserves_approved_non_secret_shapes() {
        let r = Redactor::new();
        for (key, value) in [
            ("message", "ordinary Oracle connectivity prose"),
            (
                "message",
                "accepted sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef evidence",
            ),
            (
                "subject_id_hash",
                "subject-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            (
                "message",
                "resource ocid1.autonomousdatabase.oc1.eu-frankfurt-1.abcdefghijklmnop",
            ),
            ("message", "the token ocid1.tenancy is only a syntax label"),
        ] {
            assert_eq!(
                r.redact_value(key, value),
                value,
                "approved non-secret was over-redacted: {value}"
            );
        }
    }

    #[test]
    fn leaves_ordinary_prose_intact() {
        let r = Redactor::new();
        let (_k, v) = r
            .filter("message", "ORA-00942: table or view does not exist")
            .expect("kept");
        assert_eq!(v, "ORA-00942: table or view does not exist");
    }

    #[test]
    fn secret_shaped_values_are_redacted_even_under_known_keys() {
        let r = Redactor::new();
        for (key, value) in [
            (
                "db.operation",
                "SELECTSELECTSELECTSELECTSELECTSELECTSELECT1",
            ),
            ("db.operation.name", "Bearer QA34_DB_SECRET_SENTINEL"),
            ("db.namespace", "password=QA34_DB_SECRET_SENTINEL"),
        ] {
            let (_, filtered) = r.filter(key, value).expect("key remains observable");
            assert_eq!(filtered, REDACTED, "{key} value must be redacted");
        }
    }

    #[test]
    fn validated_subject_hash_bypasses_only_the_opaque_value_heuristic() {
        let r = Redactor::new();
        let hash = format!("subject-sha256:{}", "0123456789abcdef".repeat(4));
        assert_eq!(
            r.filter("subject_id_hash", &hash),
            Some(("subject_id_hash", hash))
        );
        let (_, invalid) = r
            .filter(
                "subject_id_hash",
                "Bearer QA34_DB_SECRET_SENTINEL_that_is_not_a_sha256_hash",
            )
            .expect("key remains observable");
        assert_eq!(invalid, REDACTED);
    }
}
