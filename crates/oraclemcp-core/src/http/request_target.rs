//! HTTP request-target parsing.
//!
//! Splits a request target into its path, raw query string, and decoded
//! `(name, value)` query pairs, with `application/x-www-form-urlencoded`
//! percent-decoding. Pure string parsing extracted verbatim from the transport
//! surface (behavior-identical).

pub(super) fn split_request_target(
    target: &str,
) -> (String, Option<String>, Vec<(String, String)>) {
    let (path, query_string) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| {
            (path, Some(query.to_owned()))
        });
    let query = query_string
        .as_deref()
        .map(parse_query_string)
        .unwrap_or_default();
    (path.to_owned(), query_string, query)
}

/// Decode an `application/x-www-form-urlencoded` request body. Bodies and query
/// strings share one grammar, so they share one parser.
pub(super) fn parse_form_urlencoded(body: &str) -> Vec<(String, String)> {
    parse_query_string(body)
}

fn parse_query_string(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            (percent_decode_query(name), percent_decode_query(value))
        })
        .collect()
}

fn percent_decode_query(input: &str) -> String {
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
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
