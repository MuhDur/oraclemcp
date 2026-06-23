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
//!    DROPPED entirely (key and value), so neither the name nor the value leaks.
//! 2. **Value redaction** — for attributes that survive the key check, values
//!    that *look* like a secret (a bearer token, a `key=value` credential, a
//!    long opaque blob) are replaced with `[REDACTED]`. This is a backstop for
//!    free-form fields (e.g. an error message that quoted a connect string).
//!
//! The allowlist of *known-safe* keys (`tool`, `profile`, `operating_level`,
//! `row_count`, `cache_hit`, `ora_code`, `db.*` semantic-convention keys, …) is
//! passed through verbatim — these are the structured fields the spans/metrics
//! are designed to carry and never hold secrets by construction.

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
    /// Known-safe structured keys are never dropped.
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
        if is_known_safe_key(&key_lc) {
            return false;
        }
        SENSITIVE_KEY_FRAGMENTS
            .iter()
            .any(|fragment| key_lc.contains(fragment))
    }

    /// Redact a value that survived the key check, returning the safe value.
    ///
    /// Known-safe keys pass through unchanged (they are structured, non-secret
    /// by construction). For any other key, a value that pattern-matches a
    /// secret is replaced with [`REDACTED`].
    #[must_use]
    pub fn redact_value(&self, key: &str, value: &str) -> String {
        if is_known_safe_key(&key.to_ascii_lowercase()) {
            return value.to_owned();
        }
        if value_looks_secret(value) {
            REDACTED.to_owned()
        } else {
            value.to_owned()
        }
    }

    /// Filter a `(key, value)` pair: `None` if the key is dropped, otherwise the
    /// key with its (possibly redacted) value. The single funnel every
    /// attribute should pass through before export.
    #[must_use]
    pub fn filter<'a>(&self, key: &'a str, value: &str) -> Option<(&'a str, String)> {
        if self.should_drop_key(key) {
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

/// `db.*` keys that carry raw SQL / bind text and must be dropped even though
/// they share the otherwise-safe `db.` prefix. We only ever emit the SQL SHA +
/// bind-free subset, so these never appear — this is a backstop.
const DB_TEXT_DENY: &[&str] = &["db.statement", "db.query.text"];

/// Structured keys the telemetry layer is designed to carry. Exact match
/// (case-insensitive) OR `db.`-prefixed OTel semantic-convention keys. These are
/// never dropped or value-redacted.
fn is_known_safe_key(key_lc: &str) -> bool {
    if key_lc.starts_with("db.") {
        // OTel db.* semantic conventions: db.system, db.operation, db.namespace,
        // db.response.status_code, etc. NEVER db.statement with binds — we map
        // only the SHA/preview-free subset (see metrics.rs / traces.rs).
        return true;
    }
    matches!(
        key_lc,
        "tool"
            | "tool_name"
            | "profile"
            | "operating_level"
            | "status"
            | "row_count"
            | "rowcount"
            | "cache_hit"
            | "ora_code"
            | "request_id"
            | "target"
            | "service.name"
            | "telemetry.sdk.name"
            | "telemetry.sdk.version"
            | "code"
    )
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
        // The safe db.* subset still passes.
        assert!(!r.should_drop_key("db.operation"));
        assert!(!r.should_drop_key("db.system.name"));
    }

    #[test]
    fn keeps_known_safe_keys_verbatim() {
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
    fn leaves_ordinary_prose_intact() {
        let r = Redactor::new();
        let (_k, v) = r
            .filter("message", "ORA-00942: table or view does not exist")
            .expect("kept");
        assert_eq!(v, "ORA-00942: table or view does not exist");
    }

    #[test]
    fn known_safe_value_not_redacted_even_if_secret_shaped() {
        // A db.* attribute whose value happens to be long is still kept (these
        // are structured, never secrets).
        let r = Redactor::new();
        let (_k, v) = r
            .filter(
                "db.operation",
                "SELECTSELECTSELECTSELECTSELECTSELECTSELECT1",
            )
            .expect("kept");
        assert_eq!(v, "SELECTSELECTSELECTSELECTSELECTSELECTSELECT1");
    }
}
