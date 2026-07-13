//! Exact Oracle Edition-Based Redefinition lifecycle grammar.
//!
//! Oracle editions are a linear staging chain, not a branch graph: a parent
//! edition can have at most one child. This module recognizes only the small
//! lifecycle surface the dispatcher can protect with a dictionary preflight.
//! Any `CREATE EDITION` or `DROP EDITION` spelling outside this grammar is
//! deliberately `Invalid`, so it cannot bypass the one-child guard by reaching
//! Oracle through a different syntax shape.

use sqlparser::dialect::OracleDialect;
use sqlparser::tokenizer::{Token, Tokenizer};

/// One normalized Oracle edition identifier.
///
/// Oracle stores unquoted identifiers uppercase while preserving quoted
/// identifiers. Keeping that distinction here makes the bound dictionary probe
/// exact without ever interpolating caller-controlled text into SQL.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EditionIdentifier(String);

impl EditionIdentifier {
    /// Dictionary spelling for this exact edition name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A lifecycle statement that the dispatcher may execute through its usual
/// classifier, operating-level, confirmation, audit, and transaction controls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditionLifecycleSql {
    /// `CREATE EDITION <child> AS CHILD OF <parent>`.
    CreateChild {
        /// The proposed child edition.
        child: EditionIdentifier,
        /// The sole parent edition whose child slot is being requested.
        parent: EditionIdentifier,
    },
    /// `DROP EDITION <edition> [CASCADE]`, the lifecycle's retire operation.
    Retire {
        /// The old edition being retired.
        edition: EditionIdentifier,
        /// Whether Oracle should retire dependent editioned objects too.
        cascade: bool,
    },
}

/// Result of parsing the narrow edition lifecycle grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditionLifecycleParse {
    /// The statement does not target Oracle editions.
    NotEdition,
    /// The statement is one exact lifecycle operation.
    Parsed(EditionLifecycleSql),
    /// The statement targets editions but is not a supported exact lifecycle
    /// form. The classifier must refuse it rather than letting it bypass the
    /// preflight.
    Invalid,
}

/// Parse the supported, exact Oracle edition lifecycle SQL.
///
/// Comments and whitespace are tokenized away. A single trailing semicolon is
/// accepted for interactive clients; any buried semicolon or trailing token is
/// invalid so this parser never masks a multi-statement request.
#[must_use]
pub fn parse_edition_lifecycle_sql(sql: &str) -> EditionLifecycleParse {
    let mut tokens = match Tokenizer::new(&OracleDialect {}, sql).tokenize() {
        Ok(tokens) => tokens
            .into_iter()
            .filter(|token| !matches!(token, Token::Whitespace(_)))
            .collect::<Vec<_>>(),
        Err(_) => return EditionLifecycleParse::NotEdition,
    };
    let is_edition = matches!(
        (tokens.first(), tokens.get(1)),
        (Some(first), Some(second))
            if word_is(first, "CREATE") && word_is(second, "EDITION")
                || word_is(first, "DROP") && word_is(second, "EDITION")
    );
    if !is_edition {
        return EditionLifecycleParse::NotEdition;
    }

    if matches!(tokens.last(), Some(Token::SemiColon)) {
        let _ = tokens.pop();
    }
    if tokens.iter().any(|token| matches!(token, Token::SemiColon)) {
        return EditionLifecycleParse::Invalid;
    }

    match tokens.as_slice() {
        [create, edition, child, as_kw, child_kw, of_kw, parent]
            if word_is(create, "CREATE")
                && word_is(edition, "EDITION")
                && word_is(as_kw, "AS")
                && word_is(child_kw, "CHILD")
                && word_is(of_kw, "OF") =>
        {
            match (identifier(child), identifier(parent)) {
                (Some(child), Some(parent)) => {
                    EditionLifecycleParse::Parsed(EditionLifecycleSql::CreateChild {
                        child,
                        parent,
                    })
                }
                _ => EditionLifecycleParse::Invalid,
            }
        }
        [drop_kw, edition_kw, edition]
            if word_is(drop_kw, "DROP") && word_is(edition_kw, "EDITION") =>
        {
            identifier(edition).map_or(EditionLifecycleParse::Invalid, |edition| {
                EditionLifecycleParse::Parsed(EditionLifecycleSql::Retire {
                    edition,
                    cascade: false,
                })
            })
        }
        [drop_kw, edition_kw, edition, cascade_kw]
            if word_is(drop_kw, "DROP")
                && word_is(edition_kw, "EDITION")
                && word_is(cascade_kw, "CASCADE") =>
        {
            identifier(edition).map_or(EditionLifecycleParse::Invalid, |edition| {
                EditionLifecycleParse::Parsed(EditionLifecycleSql::Retire {
                    edition,
                    cascade: true,
                })
            })
        }
        _ => EditionLifecycleParse::Invalid,
    }
}

fn word_is(token: &Token, expected: &str) -> bool {
    matches!(token, Token::Word(word) if word.quote_style.is_none() && word.value.eq_ignore_ascii_case(expected))
}

fn identifier(token: &Token) -> Option<EditionIdentifier> {
    let Token::Word(word) = token else {
        return None;
    };
    (!word.value.is_empty()).then(|| {
        EditionIdentifier(if word.quote_style.is_some() {
            word.value.clone()
        } else {
            word.value.to_ascii_uppercase()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_create_child_with_comments_and_quoted_identifiers() {
        let parsed = parse_edition_lifecycle_sql(
            "/* D2 */ CREATE EDITION \"Child v2\" AS /* linear */ CHILD OF base_stage;",
        );
        assert_eq!(
            parsed,
            EditionLifecycleParse::Parsed(EditionLifecycleSql::CreateChild {
                child: EditionIdentifier("Child v2".to_owned()),
                parent: EditionIdentifier("BASE_STAGE".to_owned()),
            })
        );
    }

    #[test]
    fn parses_retire_with_optional_cascade() {
        assert_eq!(
            parse_edition_lifecycle_sql("DROP EDITION retired_stage CASCADE"),
            EditionLifecycleParse::Parsed(EditionLifecycleSql::Retire {
                edition: EditionIdentifier("RETIRED_STAGE".to_owned()),
                cascade: true,
            })
        );
        assert_eq!(
            parse_edition_lifecycle_sql("DROP EDITION retired_stage"),
            EditionLifecycleParse::Parsed(EditionLifecycleSql::Retire {
                edition: EditionIdentifier("RETIRED_STAGE".to_owned()),
                cascade: false,
            })
        );
    }

    #[test]
    fn rejects_alternative_or_stacked_edition_shapes() {
        for sql in [
            "CREATE EDITION child_stage",
            "CREATE EDITION child_stage AS CHILD OF base_stage EXTRA",
            "CREATE EDITION child_stage AS CHILD OF base_stage; DROP EDITION base_stage",
            "DROP EDITION retired_stage PURGE",
        ] {
            assert_eq!(
                parse_edition_lifecycle_sql(sql),
                EditionLifecycleParse::Invalid,
                "{sql}"
            );
        }
        assert_eq!(
            parse_edition_lifecycle_sql("CREATE TABLE edition_log (id NUMBER)"),
            EditionLifecycleParse::NotEdition
        );
    }

    #[test]
    fn every_keyword_of_the_create_child_shape_is_load_bearing() {
        // The tests above vary the ARITY (a missing tail, a trailing token, a
        // stacked statement). They never vary a keyword while keeping the arity,
        // so the match guard that spells the shape out — CREATE EDITION <c> AS
        // CHILD OF <p> — was never actually required to hold: a seven-token
        // statement could reach `Parsed` on its shape alone.
        //
        // This parser IS the edition allow-list (D1). `Parsed` means "a known,
        // supported lifecycle statement"; `Invalid` means refused. So admitting a
        // statement we did not actually recognize is a fail-open, and each keyword
        // must be independently necessary.
        for sql in [
            // One keyword wrong, arity intact — one case per conjunct of the guard.
            "CREATE EDITION child_stage XX CHILD OF base_stage",
            "CREATE EDITION child_stage AS XX OF base_stage",
            "CREATE EDITION child_stage AS CHILD XX base_stage",
            // DROP EDITION also satisfies the `is_edition` pre-check, so a seven
            // token DROP must not be admitted through the CREATE-child arm.
            "DROP EDITION child_stage AS CHILD OF base_stage",
            // A quoted keyword is an identifier, not the keyword it spells.
            "CREATE EDITION child_stage \"AS\" CHILD OF base_stage",
        ] {
            assert_eq!(
                parse_edition_lifecycle_sql(sql),
                EditionLifecycleParse::Invalid,
                "the edition allow-list must refuse a shape it does not recognize: {sql}"
            );
        }
    }

    #[test]
    fn the_parsed_edition_names_are_the_ones_in_the_sql() {
        // The names are not decoration: they are what a staged change is applied
        // INTO. A parser that returned a constant (or an empty string) would still
        // structurally satisfy every assertion above, because those compare the
        // EditionIdentifier value — nothing ever asked it what it says. Ask it.
        let EditionLifecycleParse::Parsed(EditionLifecycleSql::CreateChild { child, parent }) =
            parse_edition_lifecycle_sql("CREATE EDITION app_v2 AS CHILD OF app_v1")
        else {
            panic!("the canonical create-child shape must parse");
        };
        assert_eq!(
            child.as_str(),
            "APP_V2",
            "the child edition is the one named"
        );
        assert_eq!(
            parent.as_str(),
            "APP_V1",
            "and the parent is the one it descends from — targeting the wrong \
             edition is how a staged change lands in the live one"
        );

        let EditionLifecycleParse::Parsed(EditionLifecycleSql::Retire { edition, .. }) =
            parse_edition_lifecycle_sql("DROP EDITION \"Retired v9\"")
        else {
            panic!("the canonical retire shape must parse");
        };
        assert_eq!(
            edition.as_str(),
            "Retired v9",
            "a quoted identifier keeps its case verbatim"
        );
    }
}
