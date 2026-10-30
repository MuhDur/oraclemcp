//! Exact, built-in eligibility for Oracle dictionary views.
//!
//! Eligibility is deliberately not a safety verdict.  A caller must still
//! establish the full view closure before it may treat a relation as read-only.

use sqlparser::dialect::OracleDialect;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

/// Parse an exact owner-qualified proof target, never a wildcard or SQL
/// expression. Unquoted components use Oracle's uppercase dictionary spelling;
/// double-quoted components retain their exact spelling, including dots.
/// The returned identity only establishes eligibility for a separate proof.
#[must_use]
pub fn parse_trusted_proof_target(value: &str) -> Option<Vec<String>> {
    if value.len() > 1024 {
        return None;
    }
    let tokens = Tokenizer::new(&OracleDialect {}, value).tokenize().ok()?;
    let tokens = tokens
        .into_iter()
        .filter(|token| {
            !matches!(
                token,
                Token::Whitespace(Whitespace::Space | Whitespace::Tab | Whitespace::Newline)
            )
        })
        .collect::<Vec<_>>();
    if !matches!(tokens.len(), 3 | 5) {
        return None;
    }
    let mut parts = Vec::new();
    for (index, token) in tokens.into_iter().enumerate() {
        if index % 2 == 1 {
            if token != Token::Period {
                return None;
            }
            continue;
        }
        let Token::Word(word) = token else {
            return None;
        };
        if word.value.is_empty()
            || word.value.len() > 128
            || word
                .value
                .chars()
                .any(|c| c.is_control() || matches!(c, '*' | '%'))
        {
            return None;
        }
        let component = match word.quote_style {
            Some('"') => word.value,
            None if word.value.as_bytes()[0].is_ascii_alphabetic()
                && word
                    .value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'#')) =>
            {
                word.value.to_ascii_uppercase()
            }
            _ => return None,
        };
        parts.push(component);
    }
    Some(parts)
}

/// Returns whether an exact `SYS` dictionary view is eligible for closure
/// proof.
///
/// This list is intentionally limited to the user/all dictionary surface.
/// `DBA_*` views and every application view remain ineligible unless a
/// database-facing consumer supplies a separately configured, exact identity.
#[must_use]
pub fn is_builtin_dictionary_view(owner: &str, name: &str) -> bool {
    owner == "SYS"
        && matches!(
            name,
            "USER_OBJECTS"
                | "ALL_OBJECTS"
                | "USER_TAB_COLUMNS"
                | "ALL_TAB_COLUMNS"
                | "USER_TABLES"
                | "ALL_TABLES"
                | "USER_VIEWS"
                | "ALL_VIEWS"
                | "USER_SEQUENCES"
                | "ALL_SEQUENCES"
                | "USER_ARGUMENTS"
                | "ALL_ARGUMENTS"
                | "USER_SOURCE"
                | "ALL_SOURCE"
                | "USER_CONSTRAINTS"
                | "ALL_CONSTRAINTS"
                | "USER_CONS_COLUMNS"
                | "ALL_CONS_COLUMNS"
                | "USER_INDEXES"
                | "ALL_INDEXES"
                | "USER_IND_COLUMNS"
                | "ALL_IND_COLUMNS"
                | "USER_SYNONYMS"
                | "ALL_SYNONYMS"
                | "USER_DEPENDENCIES"
                | "ALL_DEPENDENCIES"
                | "USER_ERRORS"
                | "ALL_ERRORS"
                | "USER_PROCEDURES"
                | "ALL_PROCEDURES"
                | "USER_TRIGGERS"
                | "ALL_TRIGGERS"
        )
}

#[cfg(test)]
mod tests {
    use super::{is_builtin_dictionary_view, parse_trusted_proof_target};

    #[test]
    fn issue35_dictionary_allowlist_is_exact_sys_only() {
        assert!(is_builtin_dictionary_view("SYS", "USER_OBJECTS"));
        assert!(is_builtin_dictionary_view("SYS", "ALL_TAB_COLUMNS"));
        assert!(is_builtin_dictionary_view("SYS", "USER_SEQUENCES"));
        assert!(!is_builtin_dictionary_view("APP", "USER_OBJECTS"));
        assert!(!is_builtin_dictionary_view("SYS", "DBA_OBJECTS"));
        assert!(!is_builtin_dictionary_view("sys", "USER_OBJECTS"));
        assert!(!is_builtin_dictionary_view("SYS", "user_objects"));
    }

    #[test]
    fn trusted_proof_targets_preserve_exact_oracle_identifier_identity() {
        assert_eq!(
            parse_trusted_proof_target("app.report"),
            Some(vec!["APP".into(), "REPORT".into()])
        );
        assert_eq!(
            parse_trusted_proof_target("APP.PKG.FN"),
            Some(vec!["APP".into(), "PKG".into(), "FN".into()])
        );
        assert_eq!(
            parse_trusted_proof_target("\"Mixed.Owner\".\"view name\""),
            Some(vec!["Mixed.Owner".into(), "view name".into()])
        );
        assert_eq!(
            parse_trusted_proof_target("\"a\"\"b\".V"),
            Some(vec!["a\"b".into(), "V".into()])
        );
    }

    #[test]
    fn trusted_proof_targets_reject_wildcards_links_comments_and_expressions() {
        for candidate in [
            "V",
            "APP.*",
            "APP.%",
            "APP..V",
            "APP.V@DB",
            "APP.V;DELETE FROM T",
            "APP./*comment*/V",
            "APP.\"\"",
            "`APP`.V",
            "APP.FN()",
            "A.B.C.D",
        ] {
            assert!(
                parse_trusted_proof_target(candidate).is_none(),
                "{candidate}"
            );
        }
    }
}
