//! Read-only enforcement layers (plan §6.3) and the session-setting allowlist
//! (§6.5). Three complementary layers protect a read-only session, strongest
//! first:
//!
//! - **(A) DB-privilege ceiling** — a least-privilege Oracle user (operator's
//!   responsibility; see `docs/oraclemcp/least-privilege.md`). The only hard
//!   boundary.
//! - **(B) `SET TRANSACTION READ ONLY`** — issued whenever the session level is
//!   `READ_ONLY`, so a *misclassified* direct DML still raises `ORA-01456`.
//! - **(C) The fail-closed classifier** (P1-1) + the operating-level gate (P0-7).
//!
//! Caveat (carried everywhere): layer B does **not** stop
//! `PRAGMA AUTONOMOUS_TRANSACTION` side-effects fired by triggers/VPD functions
//! (they commit independently, no `ORA-01456`). The classifier's trigger/VPD
//! walk is the defense; on a `protected` profile, layer A is the real boundary.

use crate::levels::OperatingLevel;

/// The statement that makes the current transaction read-only at the engine.
pub const SET_TRANSACTION_READ_ONLY: &str = "SET TRANSACTION READ ONLY";

/// Session-setup statements to apply for a session at `level` on a profile
/// (`protected` = production). At `READ_ONLY` this issues
/// `SET TRANSACTION READ ONLY` (layer B).
///
/// Layering of `SET ROLE` / `ALTER SESSION` (the precise, code-true picture —
/// oracle-clgt.13):
///
/// - **`SET ROLE`** is mapped by the classifier (layer C) to
///   `Destructive` / `OperatingLevel::Admin`, so the operating-level gate
///   ([`crate::levels::SessionLevelState::evaluate`]) never *Allows* it below
///   `ADMIN`: a `READ_ONLY` *or* `READ_WRITE` session is forced to step up to
///   `ADMIN` (and on a profile whose ceiling is below `ADMIN`, it is hard
///   `Blocked`). It is **not** classified `Forbidden`, so an operator who has
///   genuinely provisioned an `ADMIN` ceiling can still run it after step-up.
/// - **`ALTER SESSION SET <param>`** does *not* parse under sqlparser's
///   `OracleDialect`, so in [`crate::classifier`] it falls through the
///   parse-failure branch to `Guarded` / `READ_WRITE` (it requires step-up from
///   a `READ_ONLY` session but is allowed once a session is at `READ_WRITE`).
///   The allowlist below ([`is_allowed_alter_session`]) is **not** consulted on
///   the `classify()` path — it is enforced only on the dedicated `oracle_session`
///   `SetSession` action (`oraclemcp-core::session_tool`), which is the
///   supported way for an agent to change session parameters.
///
/// The hard guarantee that a session cannot enable a write-bearing role
/// post-connect rests on **layer A** (the least-privilege Oracle user, which has
/// no write-bearing role to enable); layers B and C are defense-in-depth that
/// refuse to silently *Allow* the attempt.
#[must_use]
pub fn read_only_setup_statements(level: OperatingLevel) -> Vec<&'static str> {
    if level == OperatingLevel::ReadOnly {
        vec![SET_TRANSACTION_READ_ONLY]
    } else {
        Vec::new()
    }
}

/// The allowlist of `ALTER SESSION SET <param>` parameters an agent may set at
/// `READ_ONLY` (§6.5): session-scoped, non-data-mutating, non-security.
const ALTER_SESSION_ALLOWLIST: &[&str] = &[
    "CURRENT_SCHEMA",
    "NLS_DATE_FORMAT",
    "NLS_TIMESTAMP_FORMAT",
    "NLS_TIMESTAMP_TZ_FORMAT",
    "NLS_NUMERIC_CHARACTERS",
    "NLS_LANGUAGE",
    "NLS_TERRITORY",
    "NLS_SORT",
    "NLS_COMP",
    "TIME_ZONE",
    "OPTIMIZER_MODE",
    "STATISTICS_LEVEL",
    "OPTIMIZER_DYNAMIC_SAMPLING",
];

/// Whether an `ALTER SESSION SET <param> = …` statement targets *only*
/// allowlisted, safe session parameters (§6.5). Oracle accepts multiple
/// space-separated `param = value` pairs in a single `ALTER SESSION SET`, so
/// **every** parameter assigned must be in the allowlist — a single allowlisted
/// prefix must NOT smuggle a trailing `SQL_TRACE = TRUE` / `EVENTS = '10046 …'`
/// past the gate (oracle-ajm2.4). Anything outside the allowlist (e.g. statements
/// that change security/audit/trace context) is rejected. Fail-closed: a
/// statement that cannot be cleanly parsed into known `param = value` pairs, or
/// that assigns zero parameters, is rejected. String-literal-aware so an `=` or
/// whitespace *inside* a quoted value is never mistaken for a parameter name.
/// Case-insensitive.
#[must_use]
pub fn is_allowed_alter_session(stmt: &str) -> bool {
    let upper = stmt.trim().to_ascii_uppercase();
    let Some(rest) = upper.strip_prefix("ALTER SESSION SET ") else {
        return false;
    };
    match alter_session_params(rest) {
        // Every assigned parameter must be allowlisted, and there must be at
        // least one (a statement with no parseable assignment is rejected).
        Some(params) if !params.is_empty() => params
            .iter()
            .all(|p| ALTER_SESSION_ALLOWLIST.contains(&p.as_str())),
        // Unparseable (e.g. unterminated literal, a top-level `=` with no
        // preceding identifier) → fail closed.
        _ => false,
    }
}

/// Parse the post-`ALTER SESSION SET ` remainder into the list of parameter
/// names being assigned. String-literal-aware: a single-quoted value is opaque,
/// so `=`/whitespace inside it never starts a new clause or parameter name.
///
/// The grammar accepted is a whitespace-separated sequence of `IDENT = VALUE`
/// clauses (Oracle's documented `param = value [param = value]...`). The
/// parameter name is the identifier token immediately preceding each top-level
/// `=`. Returns `None` (fail-closed) on anything that does not fit this shape:
/// an unterminated quote, a top-level `=` with no preceding identifier, or a
/// value clause that is not cleanly closed before the next parameter.
fn alter_session_params(rest: &str) -> Option<Vec<String>> {
    // Top-level tokenizer: words, the `=` sign, and opaque single-quoted strings.
    // Doubled `''` inside a literal is a quote escape, not a terminator.
    #[derive(PartialEq)]
    enum Tok {
        Word(String),
        Eq,
        Str,
    }
    let mut toks: Vec<Tok> = Vec::new();
    let mut chars = rest.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '=' => {
                chars.next();
                toks.push(Tok::Eq);
            }
            '\'' => {
                // Opaque string literal: consume until the closing quote,
                // honoring doubled-'' escapes. Unterminated → fail closed.
                chars.next();
                loop {
                    match chars.next() {
                        Some('\'') => {
                            if chars.peek() == Some(&'\'') {
                                chars.next(); // escaped quote, keep scanning
                            } else {
                                break;
                            }
                        }
                        Some(_) => {}
                        None => return None, // unterminated literal
                    }
                }
                toks.push(Tok::Str);
            }
            _ => {
                // A bare word: run of non-whitespace, non-`=`, non-quote chars.
                let mut word = String::new();
                while let Some(&w) = chars.peek() {
                    if w.is_whitespace() || w == '=' || w == '\'' {
                        break;
                    }
                    word.push(w);
                    chars.next();
                }
                toks.push(Tok::Word(word));
            }
        }
    }

    // Walk the token stream as repeated `WORD = (WORD|STR)` clauses; collect the
    // WORD before each `=` as a parameter name. Reject any other shape.
    let mut params: Vec<String> = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        // param name
        let Tok::Word(name) = &toks[i] else {
            return None;
        };
        // `=`
        if toks.get(i + 1) != Some(&Tok::Eq) {
            return None;
        }
        // value: a word or a string literal
        match toks.get(i + 2) {
            Some(Tok::Word(_)) | Some(Tok::Str) => {}
            _ => return None,
        }
        params.push(name.trim().to_owned());
        i += 3;
    }
    Some(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_level_sets_transaction_read_only() {
        assert_eq!(
            read_only_setup_statements(OperatingLevel::ReadOnly),
            vec![SET_TRANSACTION_READ_ONLY]
        );
        assert!(read_only_setup_statements(OperatingLevel::ReadWrite).is_empty());
        assert!(read_only_setup_statements(OperatingLevel::Ddl).is_empty());
    }

    #[test]
    fn alter_session_allowlist_permits_safe_params() {
        assert!(is_allowed_alter_session(
            "ALTER SESSION SET CURRENT_SCHEMA = HR"
        ));
        assert!(is_allowed_alter_session(
            "alter session set nls_date_format='YYYY'"
        ));
        assert!(is_allowed_alter_session(
            "ALTER SESSION SET OPTIMIZER_MODE = ALL_ROWS"
        ));
    }

    #[test]
    fn alter_session_allowlist_rejects_security_and_unknown() {
        // Security/audit context changes are rejected.
        assert!(!is_allowed_alter_session(
            "ALTER SESSION SET CONTAINER = CDB$ROOT"
        ));
        assert!(!is_allowed_alter_session(
            "ALTER SESSION SET SQL_TRACE = TRUE"
        ));
        // SET ROLE is not an ALTER SESSION and is rejected here too.
        assert!(!is_allowed_alter_session("SET ROLE DBA"));
        assert!(!is_allowed_alter_session("DROP TABLE t"));
        assert!(!is_allowed_alter_session(
            "ALTER SESSION SET EVENTS '10046'"
        ));
    }

    #[test]
    fn alter_session_rejects_smuggled_trailing_param() {
        // oracle-ajm2.4: an allowlisted prefix must NOT smuggle a
        // non-allowlisted trailing parameter past the gate. Oracle accepts
        // multiple `param = value` pairs in one ALTER SESSION SET, so EVERY
        // assigned parameter must be allowlisted.
        assert!(
            !is_allowed_alter_session("ALTER SESSION SET CURRENT_SCHEMA=HR SQL_TRACE=TRUE"),
            "trailing SQL_TRACE must not be smuggled past an allowlisted prefix"
        );
        // ... including when the smuggled value is a quoted literal containing
        // spaces and `=` (EVENTS '10046 trace name context forever, level 12').
        assert!(
            !is_allowed_alter_session(
                "ALTER SESSION SET CURRENT_SCHEMA = HR EVENTS = '10046 trace name context forever'"
            ),
            "trailing EVENTS with a spacey/quoted value must be rejected"
        );
        // The order does not matter: a non-allowlisted leading param also fails.
        assert!(!is_allowed_alter_session(
            "ALTER SESSION SET SQL_TRACE = TRUE CURRENT_SCHEMA = HR"
        ));
    }

    #[test]
    fn alter_session_permits_multiple_allowlisted_params() {
        // A genuinely-safe multi-param statement: every assignment is allowlisted.
        assert!(is_allowed_alter_session(
            "ALTER SESSION SET CURRENT_SCHEMA = HR OPTIMIZER_MODE = ALL_ROWS"
        ));
        assert!(is_allowed_alter_session(
            "ALTER SESSION SET NLS_DATE_FORMAT='YYYY-MM-DD' NLS_LANGUAGE = AMERICAN"
        ));
    }

    #[test]
    fn alter_session_fails_closed_on_malformed() {
        // Zero assignments / no `=` → rejected.
        assert!(!is_allowed_alter_session(
            "ALTER SESSION SET CURRENT_SCHEMA"
        ));
        assert!(!is_allowed_alter_session("ALTER SESSION SET "));
        // Unterminated string literal → fail closed.
        assert!(!is_allowed_alter_session(
            "ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY"
        ));
        // A top-level `=` with no preceding parameter name → fail closed.
        assert!(!is_allowed_alter_session("ALTER SESSION SET = HR"));
    }
}
