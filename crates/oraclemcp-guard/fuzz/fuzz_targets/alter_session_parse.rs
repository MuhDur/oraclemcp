#![no_main]
//! Fuzz the `ALTER SESSION SET` allowlist validator (`is_allowed_alter_session`,
//! §6.5 / P1-6). Arbitrary bytes (UTF-8 lossy) fed into the public API must:
//!
//!   1. never panic,
//!   2. be deterministic, and
//!   3. never accept a statement that a canonical, independent parameter scan
//!      would reject — i.e. the validator must not over-accept. Every parameter
//!      assigned by an accepted statement must be allowlisted, and an accepted
//!      statement must assign at least one parameter (fail-closed).
//!
//! Invariant 3 is a differential check: the validator parses the statement one
//! way; this target re-derives the assigned parameter names by an independent
//! quote-aware scan and asserts the validator never clears a statement whose
//! parameter set escapes the allowlist. A divergence here is a real
//! classifier-bug signal (REPORT, do not silently fix).
//!
//! Run: `cargo +nightly fuzz run alter_session_parse` (from crates/oraclemcp-guard).

use libfuzzer_sys::fuzz_target;
use oraclemcp_guard::is_allowed_alter_session;

/// Mirror of `enforcement::ALTER_SESSION_ALLOWLIST` (private to the crate).
/// Kept in sync by hand; if the source allowlist grows, this differential check
/// becomes conservatively stricter (it may flag a newly-allowed param), which
/// surfaces drift rather than hiding it.
const CANON_ALLOWLIST: &[&str] = &[
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
    "PLSQL_WARNINGS",
];

/// Independent, quote-aware re-derivation of the parameter names assigned by an
/// `ALTER SESSION SET <rest>` statement. Deliberately a different shape from the
/// crate's internal tokenizer: this one scans left-to-right, remembering the
/// most recent bare word, and emits that word as a parameter name the moment a
/// top-level `=` is seen — then demands a value token before the next clause.
///
/// Returns `None` (canonical reject) on anything that does not fit the
/// documented `IDENT = VALUE [IDENT = VALUE]...` grammar: an unterminated quote,
/// a top-level `=` with no preceding word, a missing value, or trailing tokens
/// that are not a fresh `IDENT = VALUE` clause.
fn canonical_params(rest: &str) -> Option<Vec<String>> {
    #[derive(PartialEq, Clone)]
    enum Tok {
        Word(String),
        Eq,
        Str,
    }

    let mut toks: Vec<Tok> = Vec::new();
    let mut it = rest.chars().peekable();
    while let Some(&c) = it.peek() {
        if c.is_whitespace() {
            it.next();
        } else if c == '=' {
            it.next();
            toks.push(Tok::Eq);
        } else if c == '\'' {
            it.next();
            loop {
                match it.next() {
                    Some('\'') => {
                        if it.peek() == Some(&'\'') {
                            it.next();
                        } else {
                            break;
                        }
                    }
                    Some(_) => {}
                    None => return None,
                }
            }
            toks.push(Tok::Str);
        } else {
            let mut w = String::new();
            while let Some(&n) = it.peek() {
                if n.is_whitespace() || n == '=' || n == '\'' {
                    break;
                }
                w.push(n);
                it.next();
            }
            toks.push(Tok::Word(w));
        }
    }

    let mut params = Vec::new();
    let mut idx = 0;
    while idx < toks.len() {
        let name = match &toks[idx] {
            Tok::Word(w) => w.clone(),
            _ => return None,
        };
        if toks.get(idx + 1) != Some(&Tok::Eq) {
            return None;
        }
        match toks.get(idx + 2) {
            Some(Tok::Word(_)) | Some(Tok::Str) => {}
            _ => return None,
        }
        params.push(name);
        idx += 3;
    }
    Some(params)
}

fuzz_target!(|data: &[u8]| {
    let sql = String::from_utf8_lossy(data);
    let stmt = sql.as_ref();

    let allowed = is_allowed_alter_session(stmt);

    // Invariant 2: deterministic.
    assert_eq!(
        allowed,
        is_allowed_alter_session(stmt),
        "is_allowed_alter_session must be deterministic"
    );

    if !allowed {
        return;
    }

    // The validator accepted, so the statement must begin with the (case-
    // insensitive) prefix. Re-derive the parameter set independently.
    let upper = stmt.trim().to_ascii_uppercase();
    let rest = upper
        .strip_prefix("ALTER SESSION SET ")
        .expect("accepted statement must carry the ALTER SESSION SET prefix");

    let params =
        canonical_params(rest).expect("accepted statement must parse into canonical param clauses");

    // Invariant 3a: fail-closed — an accepted statement assigns >= 1 parameter.
    assert!(
        !params.is_empty(),
        "validator accepted a statement that assigns zero parameters: {stmt:?}"
    );

    // Invariant 3b: never over-accept — every assigned parameter is allowlisted.
    for p in &params {
        assert!(
            CANON_ALLOWLIST.contains(&p.as_str()),
            "validator accepted non-allowlisted parameter {p:?} in statement {stmt:?}"
        );
    }
});
