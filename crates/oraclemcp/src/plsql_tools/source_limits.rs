//! Admission limits for the pinned grammar engine, before recursive parsing.
//! The Oracle lexer is iterative; quoted text/comments cannot disguise syntax
//! nesting. These limits protect the serving lane, not prove SQL safety.

use std::io::Read;
use std::path::Path;

use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use sqlparser::dialect::OracleDialect;
use sqlparser::tokenizer::{Token, Tokenizer};

const MAX_SOURCE_BYTES: usize = 64 * 1024;
const MAX_TOKENS: usize = 2048;
const MAX_STATEMENT_TOKENS: usize = 256;
const MAX_NESTING: usize = 32;
const MAX_ROUTINES: usize = 32;
const MAX_PROJECT_FILES: usize = 256;
const MAX_PROJECT_BYTES: usize = 4 * 1024 * 1024;

// Keep in sync with the pinned engine's source-extension contract. Other
// discovered files count toward project discovery but never reach its parser.
const SOURCE_EXTENSIONS: &[&str] = &[
    "sql", "pls", "plsql", "pks", "pkb", "prc", "fnc", "trg", "tps", "tpb", "plb", "bdy", "spec",
    "typ",
];

fn refused(detail: &str) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::InvalidArguments,
        format!("PL/SQL analysis input limit exceeded: {detail}"),
    )
    .with_next_step("reduce source nesting or analyze smaller source files, then retry")
}

pub(super) fn validate_source(source: &str) -> Result<(), ErrorEnvelope> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(refused("source exceeds 65536 UTF-8 bytes"));
    }
    let tokens = Tokenizer::new(&OracleDialect {}, source)
        .tokenize()
        .map_err(|_| {
            ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                "PL/SQL source cannot be tokenized safely before analysis",
            )
            .with_next_step("correct source literals and comments, then retry")
        })?;
    let mut total = 0;
    let mut statement = 0;
    let mut parentheses = 0usize;
    let mut blocks = 0usize;
    let mut routines = 0;
    let mut unary = 0;
    let mut after_end = false;
    for token in tokens {
        if matches!(token, Token::Whitespace(_)) {
            continue;
        }
        total += 1;
        statement += 1;
        if total > MAX_TOKENS {
            return Err(refused("source exceeds 2048 significant tokens"));
        }
        if statement > MAX_STATEMENT_TOKENS {
            return Err(refused("statement exceeds 256 significant tokens"));
        }
        let word = match &token {
            Token::Word(word) if word.quote_style.is_none() => {
                Some(word.value.to_ascii_uppercase())
            }
            _ => None,
        };
        match &token {
            Token::LParen | Token::LBracket | Token::LBrace => parentheses += 1,
            Token::RParen | Token::RBracket | Token::RBrace => {
                parentheses = parentheses.saturating_sub(1)
            }
            Token::SemiColon => statement = 0,
            _ => {}
        }
        match word.as_deref() {
            Some("BEGIN" | "IF" | "LOOP" | "CASE") if !after_end => blocks += 1,
            Some("END") => blocks = blocks.saturating_sub(1),
            Some("PROCEDURE" | "FUNCTION") => routines += 1,
            _ => {}
        }
        if parentheses + blocks > MAX_NESTING {
            return Err(refused("syntax nesting limit is 32"));
        }
        if routines > MAX_ROUTINES {
            return Err(refused("source exceeds 32 routine declarations"));
        }
        unary = if matches!(token, Token::Plus | Token::Minus) || word.as_deref() == Some("NOT") {
            unary + 1
        } else {
            0
        };
        if unary > MAX_NESTING {
            return Err(refused("unary expression nesting limit is 32"));
        }
        after_end = word.as_deref() == Some("END");
    }
    Ok(())
}

pub(super) fn validate_project(project_root: &Path) -> Result<(), ErrorEnvelope> {
    let manifest = plsql_project::ProjectManifest::load(project_root).map_err(|_| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            "cannot load the PL/SQL project manifest",
        )
    })?;
    let files = plsql_project::discover_files(project_root, &manifest).map_err(|_| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            "cannot discover PL/SQL project sources",
        )
    })?;
    let mut count = 0;
    let mut bytes = 0;
    for file in files
        .iter()
        .filter(|file| SOURCE_EXTENSIONS.contains(&file.extension.as_str()))
    {
        count += 1;
        if count > MAX_PROJECT_FILES {
            return Err(refused("project exceeds 256 source files"));
        }
        let input = std::fs::File::open(project_root.join(&file.relative_path)).map_err(|_| {
            ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                "cannot read a PL/SQL project source",
            )
        })?;
        let mut source = String::new();
        input
            .take((MAX_SOURCE_BYTES + 1) as u64)
            .read_to_string(&mut source)
            .map_err(|_| {
                ErrorEnvelope::new(
                    ErrorClass::InvalidArguments,
                    "cannot read a PL/SQL project source as UTF-8",
                )
            })?;
        bytes += source.len();
        if bytes > MAX_PROJECT_BYTES {
            return Err(refused("project exceeds 4194304 source bytes"));
        }
        validate_source(&source)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_blocks_parentheses_and_unary_chains_refuse_before_parser_entry() {
        for source in [
            format!(
                "CREATE PROCEDURE p AS BEGIN {}NULL;{} END;",
                "BEGIN ".repeat(512),
                "END;".repeat(512)
            ),
            format!("BEGIN x := {}1{}; END;", "(".repeat(512), ")".repeat(512)),
            format!(
                "BEGIN IF {}TRUE THEN NULL; END IF; END;",
                "NOT ".repeat(512)
            ),
        ] {
            assert_eq!(
                validate_source(&source).unwrap_err().error_class,
                ErrorClass::InvalidArguments
            );
        }
    }

    #[test]
    fn quoted_keywords_and_comments_do_not_consume_syntax_nesting() {
        validate_source(&format!(
            "CREATE PROCEDURE p AS BEGIN x := '{}'; -- {}\n NULL; END;",
            "BEGIN ".repeat(100),
            "(".repeat(100)
        ))
        .unwrap();
        validate_source("CREATE PROCEDURE p AS BEGIN x := q'[BEGIN 'quoted' ( END)]'; NULL; END;")
            .unwrap();
        validate_source("CREATE PROCEDURE p AS BEGIN IF TRUE THEN NULL; END IF; END;").unwrap();
    }
}
