//! Refusal-to-rewrite corpus records (Arc J; bead oraclemcp-epic-09x-alien-6sj8.14.1).
//!
//! The corpus is read-only exhaust: an append-only, redacted dataset of
//! `(unsafe agent SQL, governed correction)` pairs that is intended to SHIP
//! PUBLICLY. That makes every record a potential disclosure, so the schema is
//! built so that a record carrying a secret cannot exist:
//!
//! * A record can only be constructed through [`CorpusRecord::new`], which runs
//!   every text field through the redaction seam. There is no way to hand-build
//!   one from raw text.
//! * Redaction is an **allowlist**, not a denylist. A SQL statement is reduced to
//!   its *skeleton*: SQL keywords and Oracle-shipped names (`DBMS_SQL`,
//!   `UTL_HTTP`, `DUAL`, …) survive because they are what makes the statement
//!   unsafe and they are public knowledge. Every literal, number, bind, comment,
//!   database link, and *customer* identifier is replaced. A token kind the
//!   redactor does not recognise is replaced too, never passed through.
//! * Redaction is followed by a **postcondition**: the output is re-lexed and
//!   rejected unless every surviving lexeme is a keyword, an allowlisted public
//!   name, or a generated placeholder. Belt and braces — a hole in the redactor
//!   becomes a rejected record, not a leak.
//! * The same validation runs again on [`CorpusRecord::from_jsonl_line`], so a
//!   record that was tampered with on disk is refused at load rather than
//!   trusted because it is already in the file (SEC-1: never trust stored text).
//! * Errors are a closed vocabulary that never echoes the offending text, so the
//!   secret cannot escape through an error message or a log line either.
//!
//! Records dedup by content hash over the *redacted* fields, so the id leaks
//! nothing and two statements that differ only in table names or literal values
//! collapse to a single corpus entry.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlparser::dialect::OracleDialect;
use sqlparser::keywords::Keyword;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

use crate::{Classifier, DangerLevel, GuardDecision};

pub use oraclemcp_error::ReasonCategory;

/// Version of the corpus record schema. Included in the content hash so a schema
/// change cannot silently collide with a record written by an older build.
pub const CORPUS_RECORD_VERSION: u16 = 1;

/// The lexeme a redacted string literal collapses to.
pub const REDACTED_LITERAL: &str = "'?'";
/// The lexeme a redacted number collapses to.
pub const REDACTED_NUMBER: &str = "?";
/// The lexeme a redacted bind variable collapses to.
pub const REDACTED_BIND: &str = ":?";
/// Longest `why` accepted. A long explanation is a place to hide a payload.
pub const MAX_WHY_CHARS: usize = 200;

/// Oracle-shipped names that survive redaction.
///
/// These are public, product-supplied identifiers — the ones that make a
/// statement *interesting* to the corpus (`EXECUTE IMMEDIATE` plus `DBMS_SQL` is
/// the lesson; `EXECUTE IMMEDIATE` plus `id_1` is not). None of them can name a
/// customer object, so keeping them discloses nothing. Anything not on this list
/// is treated as a customer identifier and replaced.
const ORACLE_PUBLIC_NAMES: &[&str] = &[
    "DUAL",
    "SYS",
    "SYSTEM",
    "SYSAUX",
    "PUBLIC",
    "DBMS_SQL",
    "DBMS_SYS_SQL",
    "DBMS_OUTPUT",
    "DBMS_SCHEDULER",
    "DBMS_JOB",
    "DBMS_LOB",
    "DBMS_RANDOM",
    "DBMS_CRYPTO",
    "DBMS_UTILITY",
    "DBMS_PIPE",
    "DBMS_ALERT",
    "DBMS_AQ",
    "DBMS_REDACT",
    "DBMS_RLS",
    "DBMS_METADATA",
    "DBMS_ASSERT",
    "UTL_FILE",
    "UTL_HTTP",
    "UTL_TCP",
    "UTL_SMTP",
    "UTL_INADDR",
    "UTL_RAW",
    "OWA_UTIL",
    "HTP",
    "HTF",
    "XMLTYPE",
    "SYS_CONTEXT",
    "USERENV",
    "SYSDATE",
    "SYSTIMESTAMP",
    "ROWNUM",
    "ROWID",
    "NEXTVAL",
    "CURRVAL",
];

/// Why a candidate record could not be admitted to the corpus.
///
/// Deliberately a closed vocabulary with no payload: an error that quoted the
/// offending text would leak the very secret the record was rejected for, into
/// whatever log or bug report the error lands in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CorpusRedactionError {
    /// The statement does not lex, so the redactor cannot prove what is in it.
    #[error("statement does not lex; refused rather than shipped unredacted")]
    NotLexable,
    /// The statement was empty once redacted.
    #[error("statement is empty")]
    Empty,
    /// A string literal survived redaction.
    #[error("a string literal survived redaction")]
    ResidualLiteral,
    /// A number survived redaction.
    #[error("a number survived redaction")]
    ResidualNumber,
    /// A bind variable survived redaction.
    #[error("a bind variable survived redaction")]
    ResidualBind,
    /// A comment survived redaction. Comments are where secrets hide.
    #[error("a comment survived redaction")]
    ResidualComment,
    /// An identifier that is not an Oracle-shipped name survived redaction.
    #[error("a non-public identifier survived redaction")]
    ResidualIdentifier,
    /// The `why` text is not drawn from the safe prose alphabet.
    #[error("`why` must be short, plain prose: no digits, quotes, binds, or identifiers")]
    UnsafeWhy,
    /// The JSONL line is not a corpus record.
    #[error("malformed corpus record")]
    Malformed,
    /// The record's id does not match its content: it was edited after writing.
    #[error("corpus record id does not match its content (tampered)")]
    IdMismatch,
}

/// Authenticity boundary carried by every refusal-trail record.
///
/// The trail is durable and redacted, but it has no signing key, hash chain, or
/// anchor. Callers must never mistake the record identifier for integrity proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusAuthenticity {
    /// The record is unsigned and not tamper-evident.
    #[default]
    UnsignedNotTamperEvident,
}

/// One redacted refusal-to-rewrite pair, as written to the corpus JSONL.
///
/// Every text field here has already passed the redaction seam. The struct is
/// deliberately constructible only through [`CorpusRecord::new`] and
/// [`CorpusRecord::from_jsonl_line`], both of which redact and then verify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusRecord {
    /// Content hash over the redacted fields. Also the dedup key.
    pub id: String,
    /// The refused statement, reduced to its redacted skeleton.
    pub refused_sql_redacted: String,
    /// The closed-vocabulary reason the guard refused it.
    pub refusal_class: ReasonCategory,
    /// The governed correction, redacted, when the guard could suggest one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_rewrite_redacted: Option<String>,
    /// Short, non-secret prose explaining the refusal.
    pub why: String,
    /// Explicit per-entry authenticity boundary. The fixed default lets older
    /// unsigned records retain their truthful interpretation when read.
    #[serde(default)]
    pub authenticity: CorpusAuthenticity,
}

impl CorpusRecord {
    /// Redact a refusal into a corpus record, or refuse to make one.
    ///
    /// This is the only way a record comes into existence. Both SQL fields are
    /// reduced to their skeleton and then re-lexed to prove nothing survived;
    /// `why` must be plain prose. Any failure returns an error and NO record —
    /// a refusal the corpus cannot represent safely is simply not collected.
    pub fn new(
        refused_sql: &str,
        refusal_class: ReasonCategory,
        suggested_rewrite: Option<&str>,
        why: &str,
    ) -> Result<Self, CorpusRedactionError> {
        let refused_sql_redacted = redact_sql(refused_sql)?;
        let suggested_rewrite_redacted = suggested_rewrite.map(redact_sql).transpose()?;
        let why = safe_why(why)?;
        let id = content_id(
            &refused_sql_redacted,
            refusal_class,
            suggested_rewrite_redacted.as_deref(),
            &why,
        );
        Ok(Self {
            id,
            refused_sql_redacted,
            refusal_class,
            suggested_rewrite_redacted,
            why,
            authenticity: CorpusAuthenticity::UnsignedNotTamperEvident,
        })
    }

    /// Serialize to one JSONL line. Redaction forbids newlines in every field,
    /// so a record is always exactly one line.
    #[must_use]
    pub fn to_jsonl_line(&self) -> String {
        serde_json::to_string(self).expect("a redacted corpus record always serializes")
    }

    /// Parse and RE-VALIDATE a record from the corpus file.
    ///
    /// The stored text is not trusted: it is re-lexed against the same
    /// postcondition as a fresh record, and its id is recomputed. A line that was
    /// hand-edited to smuggle a secret back in — or whose id no longer matches its
    /// content — is refused at load rather than believed because it is on disk.
    pub fn from_jsonl_line(line: &str) -> Result<Self, CorpusRedactionError> {
        let record: Self =
            serde_json::from_str(line).map_err(|_| CorpusRedactionError::Malformed)?;
        validate_redacted_sql(&record.refused_sql_redacted)?;
        if let Some(rewrite) = record.suggested_rewrite_redacted.as_deref() {
            validate_redacted_sql(rewrite)?;
        }
        if safe_why(&record.why)? != record.why {
            return Err(CorpusRedactionError::UnsafeWhy);
        }
        let expected = content_id(
            &record.refused_sql_redacted,
            record.refusal_class,
            record.suggested_rewrite_redacted.as_deref(),
            &record.why,
        );
        if expected != record.id {
            return Err(CorpusRedactionError::IdMismatch);
        }
        Ok(record)
    }
}

/// Deduplicate by content hash, keeping the first occurrence.
///
/// Because the hash is taken over the REDACTED skeleton, two statements that
/// differed only in their table names or literal values are the same corpus
/// lesson and collapse to one record.
#[must_use]
pub fn dedup_by_content(records: Vec<CorpusRecord>) -> Vec<CorpusRecord> {
    let mut seen = BTreeSet::new();
    records
        .into_iter()
        .filter(|record| seen.insert(record.id.clone()))
        .collect()
}

/// Classify raw proposed SQL at the point a rewrite would be applied.
///
/// Corpus records intentionally contain only a redacted SQL skeleton and no
/// verdict. This function therefore accepts neither a [`CorpusRecord`] nor a
/// prior decision: every apply attempt starts from the current classifier.
#[must_use]
pub fn reclassify_rewrite_at_apply(classifier: &Classifier, raw_rewrite: &str) -> GuardDecision {
    classifier.classify(raw_rewrite)
}

/// Whether a raw rewrite is classifier-proven enough to offer or record as
/// governed advice.
///
/// This is deliberately **not** execution authorization. A level-gated
/// statement can be useful advice, but it must pass
/// [`reclassify_rewrite_at_apply`] and the active session-level gate again when
/// a later request tries to execute it. A `Forbidden` candidate is never
/// offered or recorded.
#[must_use]
pub fn classifier_proves_rewrite(classifier: &Classifier, raw_rewrite: &str) -> bool {
    !matches!(
        reclassify_rewrite_at_apply(classifier, raw_rewrite).danger,
        DangerLevel::Forbidden
    )
}

fn content_id(
    refused_sql_redacted: &str,
    refusal_class: ReasonCategory,
    suggested_rewrite_redacted: Option<&str>,
    why: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CORPUS_RECORD_VERSION.to_be_bytes());
    for field in [
        refused_sql_redacted,
        // A closed enum; its Debug is a stable, non-secret discriminant name.
        &format!("{refusal_class:?}"),
        suggested_rewrite_redacted.unwrap_or(""),
        why,
    ] {
        hasher.update([0x1f]);
        hasher.update(field.as_bytes());
    }
    let mut id = String::from("sha256:");
    for byte in hasher.finalize() {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

/// Reduce a statement to its redacted skeleton, then prove the reduction worked.
///
/// The token walk is an allowlist: keywords and Oracle-shipped names pass, and
/// EVERY other token kind — including any literal shape this build of the
/// tokenizer knows that we do not enumerate — collapses to a placeholder. A
/// token we fail to anticipate can therefore only make the output *less*
/// informative, never leakier.
pub fn redact_sql(sql: &str) -> Result<String, CorpusRedactionError> {
    let tokens = Tokenizer::new(&OracleDialect {}, sql)
        .tokenize()
        .map_err(|_| CorpusRedactionError::NotLexable)?;

    let mut out: Vec<String> = Vec::new();
    let mut identifiers: Vec<String> = Vec::new();
    let mut skip_next_word = false;

    for token in tokens {
        match token {
            // Comments are dropped outright: a comment is free-text, and free-text
            // in a refused statement is exactly where a credential shows up.
            Token::Whitespace(
                Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_),
            ) => {}
            Token::Whitespace(_) => {}
            Token::EOF => {}
            Token::Word(word) => {
                if skip_next_word {
                    // The name half of a `:bind`; the bind lexeme is already out.
                    skip_next_word = false;
                    continue;
                }
                let upper = word.value.to_ascii_uppercase();
                if word.quote_style.is_none()
                    && (word.keyword != Keyword::NoKeyword
                        || ORACLE_PUBLIC_NAMES.contains(&upper.as_str()))
                {
                    out.push(upper);
                } else {
                    out.push(placeholder_for(&mut identifiers, &upper));
                }
            }
            Token::Number(..) => {
                if skip_next_word {
                    // A positional bind such as `:1`.
                    skip_next_word = false;
                    continue;
                }
                out.push(REDACTED_NUMBER.to_owned());
            }
            Token::Placeholder(_) => out.push(REDACTED_BIND.to_owned()),
            Token::Colon => {
                out.push(REDACTED_BIND.to_owned());
                skip_next_word = true;
            }
            Token::Comma
            | Token::LParen
            | Token::RParen
            | Token::Period
            | Token::SemiColon
            | Token::Eq
            | Token::Neq
            | Token::Lt
            | Token::Gt
            | Token::LtEq
            | Token::GtEq
            | Token::Plus
            | Token::Minus
            | Token::Mul
            | Token::Div
            | Token::Mod
            | Token::StringConcat
            | Token::DoubleColon
            | Token::Assignment => out.push(token.to_string()),
            // Everything else — every quoted-string flavour, hex/national/raw
            // literals, dollar-quoted bodies, and any exotic token — is treated as
            // a value and collapsed. Fail closed: unknown means redact.
            _ => out.push(REDACTED_LITERAL.to_owned()),
        }
    }

    let redacted = out.join(" ");
    if redacted.trim().is_empty() {
        return Err(CorpusRedactionError::Empty);
    }
    // The postcondition. If the walk above ever grows a hole, this turns it into
    // a rejected record instead of a disclosure.
    validate_redacted_sql(&redacted)?;
    Ok(redacted)
}

/// Stable per-record placeholder for a customer identifier. The mapping is local
/// to one record, so it preserves structure (`a.x = b.x` still joins) while
/// carrying nothing about the real name.
fn placeholder_for(identifiers: &mut Vec<String>, upper: &str) -> String {
    let index = match identifiers.iter().position(|seen| seen == upper) {
        Some(index) => index,
        None => {
            identifiers.push(upper.to_owned());
            identifiers.len() - 1
        }
    };
    format!("id_{}", index + 1)
}

fn is_placeholder_identifier(value: &str) -> bool {
    value
        .strip_prefix("id_")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
}

/// Re-lex a redacted statement and refuse it unless every surviving lexeme is a
/// keyword, an Oracle-shipped name, or a generated placeholder.
///
/// This is what makes the schema's promise checkable rather than aspirational,
/// and it is applied to text read back from disk as well as text we just wrote.
pub fn validate_redacted_sql(sql: &str) -> Result<(), CorpusRedactionError> {
    if sql.contains("--") || sql.contains("/*") {
        // A comment marker means the comment strip did not run, and a comment is
        // free text: the one place a credential is most likely to be sitting.
        return Err(CorpusRedactionError::ResidualComment);
    }
    if sql.contains('@') {
        // A db link (`@PRODDB`) names a real host or service, and an `@` is also
        // how an email address survives a half-done scrub.
        return Err(CorpusRedactionError::ResidualIdentifier);
    }
    let tokens = Tokenizer::new(&OracleDialect {}, sql)
        .tokenize()
        .map_err(|_| CorpusRedactionError::NotLexable)?;

    for token in tokens {
        match token {
            Token::Whitespace(
                Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_),
            ) => {
                return Err(CorpusRedactionError::ResidualComment);
            }
            Token::Whitespace(_) | Token::EOF => {}
            Token::Word(word) => {
                let upper = word.value.to_ascii_uppercase();
                let admissible = word.quote_style.is_none()
                    && (word.keyword != Keyword::NoKeyword
                        || ORACLE_PUBLIC_NAMES.contains(&upper.as_str())
                        || is_placeholder_identifier(&word.value));
                if !admissible {
                    return Err(CorpusRedactionError::ResidualIdentifier);
                }
            }
            // `'?'` is the only literal the corpus may contain.
            Token::SingleQuotedString(value) => {
                if value != "?" {
                    return Err(CorpusRedactionError::ResidualLiteral);
                }
            }
            Token::Number(..) => return Err(CorpusRedactionError::ResidualNumber),
            Token::Placeholder(value) => {
                if value != REDACTED_BIND && value != REDACTED_NUMBER {
                    return Err(CorpusRedactionError::ResidualBind);
                }
            }
            Token::Comma
            | Token::LParen
            | Token::RParen
            | Token::Period
            | Token::SemiColon
            | Token::Eq
            | Token::Neq
            | Token::Lt
            | Token::Gt
            | Token::LtEq
            | Token::GtEq
            | Token::Plus
            | Token::Minus
            | Token::Mul
            | Token::Div
            | Token::Mod
            | Token::StringConcat
            | Token::DoubleColon
            | Token::Colon
            | Token::Assignment => {}
            // Any other token kind in a redacted statement means an unredacted
            // value survived: refuse the record.
            _ => return Err(CorpusRedactionError::ResidualLiteral),
        }
    }
    Ok(())
}

/// `why` is operator/classifier prose, so it is held to a strict alphabet rather
/// than parsed: letters, spaces, and light punctuation only.
///
/// That forbids, by construction, everything a secret needs to be written down —
/// digits (`hunter2`, an account number), quotes, `:` binds, `@` hosts, `=`
/// assignments, `_`/`.` identifier shapes — so a caller cannot smuggle a
/// credential through the one free-text field.
pub fn safe_why(why: &str) -> Result<String, CorpusRedactionError> {
    let trimmed = why.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_WHY_CHARS {
        return Err(CorpusRedactionError::UnsafeWhy);
    }
    let safe = trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphabetic() || matches!(ch, ' ' | ',' | '.' | '-' | '(' | ')'));
    if !safe {
        return Err(CorpusRedactionError::UnsafeWhy);
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_sql_collapses_non_word_literal_flavors_to_placeholder() {
        let hex = redact_sql("SELECT X'414243' FROM dual").expect("hex input is redactable");
        assert!(
            hex.contains("?"),
            "hex payload must be replaced by a redaction placeholder: {hex:?}"
        );
        assert!(
            !hex.contains("414243"),
            "raw hex never reaches disk: {hex:?}"
        );

        let national =
            redact_sql("SELECT N'abc' FROM dual").expect("national string is redactable");
        assert!(
            national.contains("?"),
            "national string must be redacted, not persisted: {national:?}"
        );
        assert!(
            !national.contains("abc"),
            "raw literal text must be replaced: {national:?}"
        );
    }

    #[test]
    fn redact_sql_removes_comments_entirely() {
        let redacted = redact_sql("SELECT id -- user-id: 1234\nFROM dual")
            .expect("commented SQL is still a valid token stream");
        assert!(
            !redacted.contains("--"),
            "comments must never survive redaction output: {redacted:?}"
        );
        assert!(
            !redacted.contains("1234"),
            "commented secrets must never remain in redacted output: {redacted:?}"
        );
        assert_eq!(redacted, "SELECT ID FROM DUAL");
    }

    #[test]
    fn validate_redacted_sql_rejects_non_whitelisted_literal_shapes() {
        assert_eq!(
            validate_redacted_sql("SELECT id_1 FROM id_2 WHERE id_3 = X'414243'"),
            Err(CorpusRedactionError::ResidualLiteral)
        );
        assert_eq!(
            validate_redacted_sql("SELECT id_1 FROM id_2 WHERE id_3 = N'abc'"),
            Err(CorpusRedactionError::ResidualLiteral)
        );
    }

    #[test]
    fn validate_redacted_sql_rejects_comments() {
        assert_eq!(
            validate_redacted_sql("SELECT id_1 FROM id_2 -- blocked\nWHERE id_1 = id_2"),
            Err(CorpusRedactionError::ResidualComment)
        );
        assert_eq!(
            validate_redacted_sql("SELECT id_1 FROM id_2 /* blocked */ WHERE id_1 = id_2"),
            Err(CorpusRedactionError::ResidualComment)
        );
    }

    #[test]
    fn every_record_labels_its_unsigned_authenticity_boundary() {
        let record = CorpusRecord::new(
            "UPDATE app.orders SET state = 'closed'",
            ReasonCategory::RequiresHigherLevel,
            None,
            "the statement needs a higher operating level",
        )
        .expect("refusal record");

        assert_eq!(
            record.authenticity,
            CorpusAuthenticity::UnsignedNotTamperEvident
        );
        assert!(
            record
                .to_jsonl_line()
                .contains(r#""authenticity":"unsigned_not_tamper_evident""#)
        );
    }
}
