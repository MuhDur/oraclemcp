use std::borrow::Cow;

use sqlparser::dialect::OracleDialect;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

/// Return whether every token in `between` is ordinary layout whitespace.
///
/// Comments deliberately do not count: the parser-only grammar bridge is
/// intentionally narrower than arbitrary Oracle expression spelling. A
/// lookalike with comments remains unparseable and therefore fail-closed.
fn ordinary_whitespace(between: &[Token]) -> bool {
    between.iter().all(|token| {
        matches!(
            token,
            Token::Whitespace(Whitespace::Space | Whitespace::Newline | Whitespace::Tab)
        )
    })
}

fn bare_word_is(token: &Token, expected: &str) -> bool {
    matches!(
        token,
        Token::Word(word)
            if word.quote_style.is_none() && word.value.eq_ignore_ascii_case(expected)
    )
}

fn oracle_simple_identifier(token: &Token) -> Option<&str> {
    let Token::Word(word) = token else {
        return None;
    };
    if word.quote_style.is_some() || word.value.len() > 30 {
        return None;
    }
    let (first, rest) = word.value.as_bytes().split_first()?;
    if !first.is_ascii_alphabetic()
        || !rest
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'#'))
    {
        return None;
    }
    Some(&word.value)
}

fn positional_bind_number(token: &Token) -> Option<&str> {
    let Token::Number(number, _) = token else {
        return None;
    };
    let (first, rest) = number.as_bytes().split_first()?;
    if *first == b'0' || !first.is_ascii_digit() || !rest.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(number)
}

/// `sqlparser`'s Oracle dialect does not yet parse Oracle 23ai's
/// `VECTOR_EMBEDDING(model USING :bind)` grammar. This recognizes only the
/// builtin's unqualified, identifier-and-positional-bind form and presents an
/// equivalent comma-argument form to the parser. Tokenizing first means a
/// schema-qualified, quoted, literal, or comment-spelled lookalike cannot be
/// promoted by a text match; everything outside the narrow shape remains
/// unparseable and therefore fail-closed.
pub(super) fn normalize_vector_embedding_for_parser(sql: &str) -> Cow<'_, str> {
    let Ok(tokens) = Tokenizer::new(&OracleDialect {}, sql).tokenize() else {
        return Cow::Borrowed(sql);
    };
    let significant: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| (!matches!(token, Token::Whitespace(_))).then_some(index))
        .collect();
    let mut rewrites = Vec::new();

    for (position, &function_index) in significant.iter().enumerate() {
        if !bare_word_is(&tokens[function_index], "VECTOR_EMBEDDING")
            || (position > 0 && matches!(tokens[significant[position - 1]], Token::Period))
        {
            continue;
        }
        let Some(&lparen_index) = significant.get(position + 1) else {
            continue;
        };
        let Some(&model_index) = significant.get(position + 2) else {
            continue;
        };
        let Some(&using_index) = significant.get(position + 3) else {
            continue;
        };
        let Some(&colon_index) = significant.get(position + 4) else {
            continue;
        };
        let Some(&bind_index) = significant.get(position + 5) else {
            continue;
        };
        let Some(&rparen_index) = significant.get(position + 6) else {
            continue;
        };

        let Some(model) = oracle_simple_identifier(&tokens[model_index]) else {
            continue;
        };
        let Some(bind) = positional_bind_number(&tokens[bind_index]) else {
            continue;
        };
        if !matches!(tokens[lparen_index], Token::LParen)
            || !bare_word_is(&tokens[using_index], "USING")
            || !matches!(tokens[colon_index], Token::Colon)
            || !matches!(tokens[rparen_index], Token::RParen)
            || !ordinary_whitespace(&tokens[function_index + 1..lparen_index])
            || !ordinary_whitespace(&tokens[lparen_index + 1..model_index])
            || tokens[model_index + 1..using_index].is_empty()
            || !ordinary_whitespace(&tokens[model_index + 1..using_index])
            || !ordinary_whitespace(&tokens[using_index + 1..colon_index])
            || colon_index + 1 != bind_index
            || !ordinary_whitespace(&tokens[bind_index + 1..rparen_index])
        {
            continue;
        }
        rewrites.push((function_index, rparen_index, model, bind));
    }

    if rewrites.is_empty() {
        return Cow::Borrowed(sql);
    }

    let mut normalized = String::with_capacity(sql.len());
    let mut cursor = 0;
    for (start, end, model, bind) in rewrites {
        normalized.extend(tokens[cursor..start].iter().map(ToString::to_string));
        normalized.push_str("VECTOR_EMBEDDING(");
        normalized.push_str(model);
        normalized.push_str(", :");
        normalized.push_str(bind);
        normalized.push(')');
        cursor = end + 1;
    }
    normalized.extend(tokens[cursor..].iter().map(ToString::to_string));
    Cow::Owned(normalized)
}
