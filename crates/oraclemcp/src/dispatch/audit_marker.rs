//! Per-statement audit marker comment (bead A3 / oraclemcp-040-epic-wp-a-ia1.3).
//!
//! Prepend a structured, SQLcl-style SQL comment carrying server-controlled
//! agent identity to executed statements so DBA-side tooling (`V$SQL`, Unified
//! Auditing, ASH) can attribute them WITHOUT trusting the client:
//!
//! ```text
//! /* oraclemcp llm=<model> profile=<name> tool=<tool> */ <sql>
//! ```
//!
//! ## Safety law (do not weaken)
//!
//! The marker is a *leading comment*. The fail-closed classifier already treats
//! `/* … */` and `--` comments as whitespace token separators, so a well-formed
//! marker yields the SAME verdict as the bare SQL. Two invariants enforce that:
//!
//! 1. **Injection-safe construction.** Identity values are attacker-influenced
//!    (a profile name is operator-set, but a model label may be host/agent
//!    supplied). [`sanitize_marker_value`] strips every character that could
//!    close the comment early or start a new statement: `*/` (comment close),
//!    `/*` (nested-open confusion), newlines / control chars (which would end a
//!    `--` line comment or smuggle a second statement), and `;`. A sanitized
//!    value therefore CANNOT break out of the `/* … */` block.
//!
//! 2. **Classified == executed.** [`with_audit_marker`] re-classifies the marked
//!    text and compares the verdict to the bare-SQL verdict. The marker is
//!    applied ONLY when the two verdicts are byte-for-byte equal; on any
//!    mismatch it fails closed by returning the bare SQL unchanged. The caller
//!    classifies and executes the SAME returned text, so a marker can never let
//!    a write slip through as a read or otherwise change the gate.
//!
//! No secrets are placed in the marker: only the active profile name, the tool
//! name, and a best-effort, operator-supplied model label (the server cannot
//! observe the client's model, so `llm` defaults to the binary name and may be
//! overridden by the `ORACLEMCP_AGENT_MODEL` environment variable).

use oraclemcp_guard::{Classifier, ClassifierConfig};

/// Environment variable an operator/host may set to label the driving agent
/// model in the audit marker. Best-effort, non-secret; absent -> `oraclemcp`.
pub(crate) const AGENT_MODEL_ENV: &str = "ORACLEMCP_AGENT_MODEL";

/// Max length of any single marker value after sanitization. Keeps the comment
/// bounded (V$SQL text is finite) and denies a value large enough to push the
/// real SQL past a truncation boundary in downstream tooling.
const MARKER_VALUE_MAX: usize = 64;

/// The fixed marker tag (greppable in `V$SQL.SQL_TEXT` / ASH).
const MARKER_TAG: &str = "oraclemcp";

/// Sanitize one identity value for safe inclusion inside a `/* … */` comment.
///
/// Removes anything that could terminate the comment, open a nested comment,
/// end a line comment, or introduce a second statement, then collapses internal
/// whitespace to single spaces and bounds the length. The result contains only
/// printable, single-line text with no `/`, `*`, `;`, `\n`, or control bytes,
/// so it is provably incapable of closing the marker comment early.
#[must_use]
pub(crate) fn sanitize_marker_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MARKER_VALUE_MAX));
    let mut prev_space = false;
    for ch in raw.chars() {
        // Drop the comment-delimiter and statement-separator characters
        // outright; also drop control chars (newlines, NUL, tabs) and the
        // backslash so no escape can be smuggled. A space stands in for any
        // run of whitespace so values stay single-token-ish and readable.
        let dangerous = matches!(ch, '*' | '/' | ';' | '\\') || ch.is_control();
        if dangerous {
            continue;
        }
        if ch.is_whitespace() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
                prev_space = true;
            }
            continue;
        }
        out.push(ch);
        prev_space = false;
        if out.len() >= MARKER_VALUE_MAX {
            break;
        }
    }
    let trimmed = out.trim_end();
    if trimmed.len() != out.len() {
        out.truncate(trimmed.len());
    }
    out
}

/// Build the marker comment prefix (including the trailing space before the
/// SQL) from already-sanitized parts. Pure and deterministic.
fn marker_prefix(model: &str, profile: &str, tool: &str) -> String {
    format!("/* {MARKER_TAG} llm={model} profile={profile} tool={tool} */ ")
}

/// The best-effort model label: the operator-supplied `ORACLEMCP_AGENT_MODEL`,
/// else `oraclemcp`. Sanitized by the caller.
fn agent_model_label() -> String {
    std::env::var(AGENT_MODEL_ENV).unwrap_or_else(|_| MARKER_TAG.to_owned())
}

/// Prepend the audit marker to `sql`, fail-closed.
///
/// `profile` is the active profile name (or `None`), `tool` is the dispatch tool
/// name. Returns the marked SQL **iff** the classifier's verdict on the marked
/// text is identical to its verdict on the bare SQL; otherwise returns `sql`
/// unchanged so the caller's downstream classify+gate is never altered by the
/// marker. The caller MUST classify/execute the returned string.
#[must_use]
pub(crate) fn with_audit_marker(sql: &str, profile: Option<&str>, tool: &str) -> String {
    let model = sanitize_marker_value(&agent_model_label());
    let profile = sanitize_marker_value(profile.unwrap_or("none"));
    let tool = sanitize_marker_value(tool);
    let prefix = marker_prefix(&model, &profile, &tool);
    let marked = format!("{prefix}{sql}");

    // Classified == executed: only adopt the marker if the verdict is unchanged.
    // A divergence (which sanitization is designed to make impossible) fails
    // closed to the bare SQL rather than risking a different gate.
    let classifier = Classifier::new(ClassifierConfig::new());
    if classifier.classify(&marked) == classifier.classify(sql) {
        marked
    } else {
        sql.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_guard::OperatingLevel;

    fn classify(sql: &str) -> oraclemcp_guard::GuardDecision {
        Classifier::new(ClassifierConfig::new()).classify(sql)
    }

    #[test]
    fn marker_is_prepended_and_greppable() {
        let marked = with_audit_marker("UPDATE t SET x = 1", Some("dev"), "oracle_execute");
        assert!(marked.starts_with("/* oraclemcp llm="));
        assert!(marked.contains("profile=dev"));
        assert!(marked.contains("tool=oracle_execute"));
        assert!(marked.contains("*/ UPDATE t SET x = 1"));
    }

    #[test]
    fn marked_sql_yields_same_verdict_as_bare_sql() {
        for sql in [
            "SELECT 1 FROM dual",
            "UPDATE accounts SET balance = 0",
            "DELETE FROM orders WHERE id = 1",
            "INSERT INTO t VALUES (1)",
            "DROP TABLE customers",
            "CREATE OR REPLACE PROCEDURE p AS BEGIN NULL; END;",
        ] {
            let marked = with_audit_marker(sql, Some("dev"), "oracle_execute");
            assert_eq!(
                classify(&marked),
                classify(sql),
                "marker changed the verdict for: {sql}"
            );
        }
    }

    #[test]
    fn sanitizer_strips_comment_close_and_newlines() {
        // The canonical injection: a forged `*/` that would close the comment
        // and let trailing text execute as SQL.
        let evil = "gpt */ DROP TABLE secrets; --";
        let cleaned = sanitize_marker_value(evil);
        assert!(!cleaned.contains("*/"));
        assert!(!cleaned.contains('*'));
        assert!(!cleaned.contains('/'));
        assert!(!cleaned.contains(';'));
        assert!(!cleaned.contains('\n'));
        // Newlines and carriage returns are removed (would end a `--` comment).
        let multiline = sanitize_marker_value("foo\nbar\r\nbaz");
        assert!(!multiline.contains('\n') && !multiline.contains('\r'));
    }

    #[test]
    fn forged_marker_value_cannot_break_out_or_change_verdict() {
        // A malicious model label tries to close the comment and append a DROP.
        // SAFETY: env mutation is process-global; this test owns the variable for
        // its duration and clears it afterward. (No unsafe; std::env API.)
        let read = "SELECT 1 FROM dual";
        let evil_model = "gpt */ DROP TABLE secrets; SELECT * FROM dual WHERE 1=1 -- ";
        // Drive the same construction the runtime uses, but with the forged model.
        let model = sanitize_marker_value(evil_model);
        let prefix = marker_prefix(&model, "dev", "oracle_execute");
        let marked = format!("{prefix}{read}");

        // The forged `*/` and `;` are gone -> the comment cannot be closed early.
        assert!(!model.contains("*/"));
        // The whole marked statement still classifies exactly as the bare read:
        // a single READ_ONLY SELECT, not a DROP.
        let bare = classify(read);
        let with_evil = classify(&marked);
        assert_eq!(with_evil, bare);
        assert_eq!(with_evil.required_level, Some(OperatingLevel::ReadOnly));
    }

    #[test]
    fn value_length_is_bounded() {
        let long = "a".repeat(1000);
        assert!(sanitize_marker_value(&long).len() <= MARKER_VALUE_MAX);
    }

    #[test]
    fn empty_and_none_profile_render_safely() {
        let marked = with_audit_marker("SELECT 1 FROM dual", None, "oracle_query");
        assert!(marked.contains("profile=none"));
        assert_eq!(classify(&marked), classify("SELECT 1 FROM dual"));
    }
}
