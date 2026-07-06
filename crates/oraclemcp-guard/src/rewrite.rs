//! Agent-facing rewrite hints (workstream K: K7). These helpers suggest a
//! safer or more cache-friendly form of a statement. They are **purely
//! observational**: a hint is advice attached to an already-final guard
//! decision and never changes classification, relaxes the fail-closed law, or
//! reaches Oracle. A broken hint can, at worst, produce a less helpful message.
//!
//! [`suggest_parameterized_form`] rewrites inline literals that sit at
//! **bind-safe positions** — the right-hand side of a comparison, a `LIKE`
//! pattern, an `IN (…)` list, a `BETWEEN … AND …` range, or a `VALUES (…)` row
//! — into named binds (`:id`, `:p2`, …). Positions where an Oracle bind is
//! illegal (a table name after `FROM`, a function/type argument such as the
//! length in `VARCHAR2(50)`, a `DEFAULT` in DDL) are left untouched: the scan
//! is an allow-list of known-bindable contexts, so anything it does not
//! recognise is conservatively skipped.

use sqlparser::dialect::OracleDialect;
use sqlparser::keywords::Keyword;
use sqlparser::tokenizer::{Span, Token, Tokenizer};

/// The most literals a single hint will parameterize. Bounds output size and
/// keeps the suggestion readable; statements with more literals still get a
/// (partial) hint for the first `MAX_BINDS`.
const MAX_BINDS: usize = 10;

/// Suggest a parameterized rewrite of `sql`, binding inline literals that sit at
/// bind-safe positions. Returns `None` when the statement does not tokenize or
/// has no bind-safe literal to suggest (nothing actionable to say).
///
/// The returned string is `sql` with the bindable literals replaced in place —
/// every other byte, including comments, whitespace, and quoted identifiers, is
/// preserved exactly.
#[must_use]
pub fn suggest_parameterized_form(sql: &str) -> Option<String> {
    let dialect = OracleDialect {};
    let tokens = Tokenizer::new(&dialect, sql)
        .tokenize_with_location()
        .ok()?;

    let offsets = LineOffsets::new(sql);
    let mut binds = BindNamer::new();
    // Replacements as (byte_start, byte_end, replacement); applied right-to-left
    // so earlier spans keep their byte positions.
    let mut edits: Vec<(usize, usize, String)> = Vec::new();

    // Context carried across significant (non-whitespace/comment) tokens.
    let mut prev_sig: Option<Token> = None;
    // The left-operand identifier of the value-position operator currently in
    // scope, used to name binds after the column they constrain (`id = 42` →
    // `:id`). `None` when the operand is not a simple unquoted identifier.
    let mut operand_name: Option<String> = None;
    let mut paren_stack: Vec<ParenKind> = Vec::new();
    let mut values_active = false;
    let mut between_and_pending = false;

    for tws in &tokens {
        let token = &tws.token;
        if matches!(token, Token::Whitespace(_)) {
            continue;
        }

        // Open/close bind-list contexts. The kind is decided by the token that
        // introduced the parenthesis (IN / VALUES), captured from `prev_sig`.
        match token {
            Token::LParen => {
                let kind = match &prev_sig {
                    Some(Token::Word(w)) if w.keyword == Keyword::IN => ParenKind::InList,
                    Some(Token::Word(w)) if w.keyword == Keyword::VALUES => ParenKind::ValuesList,
                    // A fresh VALUES row: `VALUES (…),(…)` — the comma sits at
                    // the top level between rows.
                    Some(Token::Comma) if values_active && paren_stack.is_empty() => {
                        ParenKind::ValuesList
                    }
                    _ => ParenKind::Other,
                };
                paren_stack.push(kind);
                prev_sig = Some(token.clone());
                continue;
            }
            Token::RParen => {
                paren_stack.pop();
                prev_sig = Some(token.clone());
                continue;
            }
            _ => {}
        }

        // Capture the left operand of a value-position operator so the bind can
        // be named after the column it constrains. The operand is the token
        // *before* this operator (the current `prev_sig`).
        match token {
            Token::Eq
            | Token::DoubleEq
            | Token::Neq
            | Token::Lt
            | Token::Gt
            | Token::LtEq
            | Token::GtEq => operand_name = unquoted_ident(prev_sig.as_ref()),
            Token::Word(w) => match w.keyword {
                Keyword::IN | Keyword::BETWEEN | Keyword::LIKE => {
                    operand_name = unquoted_ident(prev_sig.as_ref());
                }
                // A VALUES row has no single column operand; fall back to `p{n}`.
                Keyword::VALUES => {
                    values_active = true;
                    operand_name = None;
                }
                _ => {}
            },
            _ => {}
        }

        if is_bindable_literal(token) && edits.len() < MAX_BINDS {
            let bindable = match &prev_sig {
                Some(
                    Token::Eq
                    | Token::DoubleEq
                    | Token::Neq
                    | Token::Lt
                    | Token::Gt
                    | Token::LtEq
                    | Token::GtEq,
                ) => true,
                Some(Token::Word(w)) if w.keyword == Keyword::LIKE => true,
                Some(Token::Word(w)) if w.keyword == Keyword::BETWEEN => {
                    between_and_pending = true;
                    true
                }
                Some(Token::Word(w)) if w.keyword == Keyword::AND && between_and_pending => {
                    between_and_pending = false;
                    true
                }
                // Inside an IN-list or a VALUES row (first element after `(`, or
                // any element after a `,`).
                Some(Token::LParen | Token::Comma) => {
                    matches!(
                        paren_stack.last(),
                        Some(ParenKind::InList | ParenKind::ValuesList)
                    )
                }
                _ => false,
            };

            if bindable && let Some((start, end)) = offsets.byte_range(tws.span) {
                let name = binds.next(operand_name.as_deref());
                edits.push((start, end, format!(":{name}")));
            }
        }

        prev_sig = Some(token.clone());
    }

    if edits.is_empty() {
        return None;
    }

    let mut out = sql.to_owned();
    for (start, end, replacement) in edits.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    Some(out)
}

/// The bind-list kind an open parenthesis introduced.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ParenKind {
    /// `col IN ( … )` — elements are bind-safe.
    InList,
    /// `VALUES ( … )` — row elements are bind-safe.
    ValuesList,
    /// Any other parenthesis (function call, type length, sub-expression) —
    /// its contents are NOT assumed bindable.
    Other,
}

/// The value of `token` when it is an unquoted word usable to name a bind. In
/// an operand position (left of a comparison, or before `IN`/`BETWEEN`/`LIKE`)
/// the token is grammatically a column reference, so even words `sqlparser`
/// flags as *non-reserved* keywords (`ID`, `STATUS`, `NAME`, …) are accepted —
/// they are ordinary column names. `None` for quoted identifiers, operators,
/// and literals, which fall back to a positional `p{n}` name.
fn unquoted_ident(token: Option<&Token>) -> Option<String> {
    match token {
        Some(Token::Word(w)) if w.quote_style.is_none() => Some(w.value.clone()),
        _ => None,
    }
}

/// Literals the hint is willing to parameterize (the four the K7 spec names).
fn is_bindable_literal(token: &Token) -> bool {
    matches!(
        token,
        Token::Number(_, _)
            | Token::SingleQuotedString(_)
            | Token::NationalStringLiteral(_)
            | Token::HexStringLiteral(_)
    )
}

/// Allocates unique, valid bind names, preferring the column identifier a
/// literal is compared against and falling back to `p{n}`.
struct BindNamer {
    used: std::collections::HashSet<String>,
    counter: usize,
}

impl BindNamer {
    fn new() -> Self {
        Self {
            used: std::collections::HashSet::new(),
            counter: 0,
        }
    }

    fn next(&mut self, column: Option<&str>) -> String {
        self.counter += 1;
        let base = column
            .map(sanitize_bind_name)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("p{}", self.counter));
        if self.used.insert(base.clone()) {
            return base;
        }
        // Collision (e.g. `a = 1 OR a = 2`): disambiguate with the counter.
        let mut candidate = format!("{base}_{}", self.counter);
        while !self.used.insert(candidate.clone()) {
            self.counter += 1;
            candidate = format!("{base}_{}", self.counter);
        }
        candidate
    }
}

/// Reduce a column identifier to a safe lowercase bind name (`[a-z0-9_]`),
/// so a quoted or oddly-cased column never yields an invalid placeholder.
fn sanitize_bind_name(column: &str) -> String {
    column
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// Maps `sqlparser` line/column [`Span`]s to byte ranges in the source. The
/// tokenizer reports 1-based line/column (columns counted in characters) where
/// the span end is one-past the last character, so `source[start..end]` is
/// exactly the token text. Column→byte conversion walks characters so
/// multibyte input never yields a non-boundary byte index.
struct LineOffsets<'a> {
    source: &'a str,
    /// Byte offset of the first character of each 1-based line.
    line_starts: Vec<usize>,
}

impl<'a> LineOffsets<'a> {
    fn new(source: &'a str) -> Self {
        let mut line_starts = vec![0usize];
        for (idx, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(idx + 1);
            }
        }
        Self {
            source,
            line_starts,
        }
    }

    fn byte_of(&self, line: u64, column: u64) -> Option<usize> {
        let line_idx = usize::try_from(line).ok()?.checked_sub(1)?;
        let col_idx = usize::try_from(column).ok()?.checked_sub(1)?;
        let line_start = *self.line_starts.get(line_idx)?;
        // Advance `col_idx` characters from the line start, counting bytes so
        // the result always lands on a UTF-8 boundary.
        let rest = self.source.get(line_start..)?;
        let mut byte = line_start;
        for (n, (offset, _ch)) in rest.char_indices().enumerate() {
            if n == col_idx {
                byte = line_start + offset;
                return Some(byte);
            }
            byte = line_start + offset;
        }
        // Column one past the final character on the line (span end).
        if col_idx == rest.chars().count() {
            return Some(self.source.len());
        }
        let _ = byte;
        None
    }

    fn byte_range(&self, span: Span) -> Option<(usize, usize)> {
        let start = self.byte_of(span.start.line, span.start.column)?;
        let end = self.byte_of(span.end.line, span.end.column)?;
        if start < end
            && end <= self.source.len()
            && self.source.is_char_boundary(start)
            && self.source.is_char_boundary(end)
        {
            Some((start, end))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_a_where_equality_literal_named_after_the_column() {
        // K7 DoD: `WHERE id = 42` -> suggests `:id`.
        let hint = suggest_parameterized_form("SELECT * FROM orders WHERE id = 42")
            .expect("a bindable literal was present");
        assert_eq!(hint, "SELECT * FROM orders WHERE id = :id");
    }

    #[test]
    fn leaves_a_quoted_identifier_literal_untouched() {
        // K7 DoD: a literal inside a quoted identifier is data-as-identifier and
        // must not be parameterized; and there is nothing else bindable here.
        assert_eq!(suggest_parameterized_form("SELECT \"42\" FROM dual"), None);
        // A quoted identifier next to a real bindable literal: only the literal
        // is rewritten, the quoted identifier is preserved byte-for-byte. Since
        // the operand is a quoted identifier (not a plain column), the bind
        // falls back to a positional name rather than reusing the quoted text.
        let hint =
            suggest_parameterized_form("SELECT \"weird col\" FROM t WHERE \"weird col\" = 7")
                .expect("bindable literal present");
        assert_eq!(
            hint,
            "SELECT \"weird col\" FROM t WHERE \"weird col\" = :p1"
        );
    }

    #[test]
    fn does_not_bind_table_or_type_length_or_default() {
        // FROM target, a type length inside VARCHAR2(50), and a DDL DEFAULT are
        // all positions where an Oracle bind is illegal — none may be rewritten.
        assert_eq!(suggest_parameterized_form("SELECT * FROM t123"), None);
        assert_eq!(
            suggest_parameterized_form("CREATE TABLE t (name VARCHAR2(50) DEFAULT 0)"),
            None
        );
    }

    #[test]
    fn binds_in_list_between_and_string_literals() {
        let hint =
            suggest_parameterized_form("SELECT * FROM t WHERE code IN ('A', 'B') AND qty = 5")
                .expect("bindable literals present");
        assert_eq!(
            hint,
            "SELECT * FROM t WHERE code IN (:code, :code_2) AND qty = :qty"
        );

        let between = suggest_parameterized_form("SELECT * FROM t WHERE d BETWEEN 1 AND 100")
            .expect("bindable range bounds present");
        assert_eq!(between, "SELECT * FROM t WHERE d BETWEEN :d AND :d_2");
    }

    #[test]
    fn binds_values_row_literals_positionally() {
        let hint = suggest_parameterized_form("INSERT INTO t (a, b) VALUES (1, 'x')")
            .expect("bindable VALUES row present");
        assert_eq!(hint, "INSERT INTO t (a, b) VALUES (:p1, :p2)");
    }

    #[test]
    fn caps_the_number_of_binds() {
        let mut sql = String::from("SELECT * FROM t WHERE ");
        for i in 0..15 {
            if i > 0 {
                sql.push_str(" OR ");
            }
            sql.push_str(&format!("c{i} = {i}"));
        }
        let hint = suggest_parameterized_form(&sql).expect("many bindable literals");
        assert_eq!(hint.matches(':').count(), MAX_BINDS);
    }

    #[test]
    fn returns_none_for_no_literals_or_unparseable() {
        assert_eq!(suggest_parameterized_form("SELECT * FROM dual"), None);
        // An unterminated literal fails to tokenize -> no hint (fail-quiet; the
        // guard still refuses it elsewhere).
        assert_eq!(suggest_parameterized_form("SELECT 'unterminated"), None);
    }

    #[test]
    fn preserves_multiline_and_comment_bytes() {
        let sql = "SELECT *\n  FROM t -- note\n  WHERE id = 9";
        let hint = suggest_parameterized_form(sql).expect("bindable literal present");
        assert_eq!(hint, "SELECT *\n  FROM t -- note\n  WHERE id = :id");
    }
}
