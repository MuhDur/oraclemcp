//! HTTP request-target parsing.
//!
//! Splits a request target into its path, raw query string, and decoded
//! `(name, value)` query pairs, with `application/x-www-form-urlencoded`
//! percent-decoding. Pure string parsing extracted verbatim from the transport
//! surface (behavior-identical).

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RequestTargetError {
    InvalidPercentEncoding,
    InvalidUtf8,
}

impl fmt::Display for RequestTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPercentEncoding => "invalid percent-encoding",
            Self::InvalidUtf8 => "decoded form data is not UTF-8",
        })
    }
}

impl std::error::Error for RequestTargetError {}

type ParsedRequestTarget = (String, Option<String>, Vec<(String, String)>);

pub(super) fn split_request_target(target: &str) -> ParsedRequestTarget {
    try_split_request_target(target).unwrap_or_else(|_| {
        let (path, query_string) = target
            .split_once('?')
            .map_or((target, None), |(path, query)| {
                (path, Some(query.to_owned()))
            });
        (path.to_owned(), query_string, Vec::new())
    })
}

pub(super) fn validate_request_target(target: &str) -> Result<(), RequestTargetError> {
    try_split_request_target(target).map(drop)
}

pub(super) fn try_split_request_target(
    target: &str,
) -> Result<ParsedRequestTarget, RequestTargetError> {
    let (path, query_string) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| {
            (path, Some(query.to_owned()))
        });
    let query = query_string
        .as_deref()
        .map(parse_query_string)
        .transpose()?
        .unwrap_or_default();
    Ok((path.to_owned(), query_string, query))
}

pub(super) fn try_parse_form_urlencoded(
    body: &str,
) -> Result<Vec<(String, String)>, RequestTargetError> {
    parse_query_string(body)
}

pub(super) fn validate_form_urlencoded(body: &[u8]) -> Result<(), RequestTargetError> {
    let body = std::str::from_utf8(body).map_err(|_| RequestTargetError::InvalidUtf8)?;
    try_parse_form_urlencoded(body).map(drop)
}

fn parse_query_string(query: &str) -> Result<Vec<(String, String)>, RequestTargetError> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            Ok((percent_decode_query(name)?, percent_decode_query(value)?))
        })
        .collect()
}

fn percent_decode_query(input: &str) -> Result<String, RequestTargetError> {
    fn hex(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let (Some(&hi), Some(&lo)) = (bytes.get(i + 1), bytes.get(i + 2)) else {
                    return Err(RequestTargetError::InvalidPercentEncoding);
                };
                let (Some(hi), Some(lo)) = (hex(hi), hex(lo)) else {
                    return Err(RequestTargetError::InvalidPercentEncoding);
                };
                out.push((hi << 4) | lo);
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| RequestTargetError::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_percent_encoded_query_and_form_values_decode() {
        let (_, _, query) = try_split_request_target("/mcp?name=Jos%C3%A9&path=a%2Fb")
            .expect("valid UTF-8 percent encoding");
        assert_eq!(
            query,
            vec![
                ("name".to_owned(), "Jos\u{e9}".to_owned()),
                ("path".to_owned(), "a/b".to_owned()),
            ]
        );
        validate_form_urlencoded(b"code=one%2Btwo+three").expect("valid form body");
    }

    #[test]
    fn malformed_percent_encoding_is_typed() {
        for value in ["%", "%0", "%GG", "%0G", "%G0"] {
            assert_eq!(
                validate_request_target(&format!("/mcp?value={value}")),
                Err(RequestTargetError::InvalidPercentEncoding)
            );
            assert_eq!(
                validate_form_urlencoded(format!("value={value}").as_bytes()),
                Err(RequestTargetError::InvalidPercentEncoding)
            );
        }
    }

    #[test]
    fn invalid_decoded_utf8_is_typed() {
        assert_eq!(
            validate_request_target("/mcp?value=%FF"),
            Err(RequestTargetError::InvalidUtf8)
        );
        assert_eq!(
            validate_form_urlencoded(b"value=%C3%28"),
            Err(RequestTargetError::InvalidUtf8)
        );
        assert_eq!(
            validate_form_urlencoded(b"value=\xff"),
            Err(RequestTargetError::InvalidUtf8)
        );
    }
}
