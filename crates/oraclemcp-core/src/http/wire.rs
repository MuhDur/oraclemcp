//! HTTP/1.1 request reading and response writing over a byte stream.
//!
//! `read_http_request` parses a request-line + headers + bounded body from a
//! blocking reader; `write_http_response` serializes an `HttpResponse` back to
//! the socket, defaulting `content-length` and `connection: close`. Extracted
//! verbatim from the transport surface (behavior-identical).

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use super::request_target::{validate_form_urlencoded, validate_request_target};
use super::{HttpRequest, HttpResponse, MAX_BODY_BYTES, MAX_HEADER_BYTES, reason_phrase};

pub(super) trait DeadlineRead: Read {
    fn set_ingress_read_timeout(&mut self, timeout: Duration) -> std::io::Result<()>;
}

#[derive(Debug)]
struct HttpParseError {
    status: u16,
    message: &'static str,
}

impl std::fmt::Display for HttpParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for HttpParseError {}

pub(super) fn parse_error_status(error: &std::io::Error) -> Option<u16> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<HttpParseError>())
        .map(|error| error.status)
}

pub(super) fn read_http_request(
    stream: &mut impl DeadlineRead,
    header_timeout: Duration,
    body_timeout: Duration,
) -> std::io::Result<Option<HttpRequest>> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 8192];
    let header_deadline = Instant::now() + header_timeout;
    let header_end = loop {
        let n = read_before_deadline(stream, &mut chunk, header_deadline, "HTTP header")?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(invalid_data("incomplete HTTP request"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_header_end(&buf) {
            if end
                .checked_add(4)
                .is_none_or(|header_bytes| header_bytes > MAX_HEADER_BYTES)
            {
                return Err(parse_error(
                    431,
                    "HTTP headers exceed native transport limit",
                ));
            }
            break end;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(parse_error(
                431,
                "HTTP headers exceed native transport limit",
            ));
        }
    };

    let header_text = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| invalid_data("HTTP headers are not UTF-8"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request line"))?;
    let mut request_parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (
        request_parts.next(),
        request_parts.next(),
        request_parts.next(),
        request_parts.next(),
    ) else {
        return Err(invalid_data("malformed HTTP request line"));
    };
    if !is_http_token(method) {
        return Err(invalid_data("invalid HTTP method"));
    }
    if target.is_empty() || !target.bytes().all(|byte| matches!(byte, 0x21..=0x7e)) {
        return Err(invalid_data("invalid HTTP target"));
    }
    validate_request_target(target)
        .map_err(|_| invalid_data("invalid HTTP request-target encoding"))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(invalid_data("unsupported HTTP version"));
    }

    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid_data("malformed HTTP header"));
        };
        if !is_http_token(name) {
            return Err(invalid_data("invalid HTTP header name"));
        }
        if value
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(invalid_data("invalid HTTP header value"));
        }
        headers.push((name.to_owned(), value.trim_matches([' ', '\t']).to_owned()));
    }
    if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(invalid_data("Transfer-Encoding is not supported"));
    }
    let mut content_lengths = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str());
    let content_length = match (content_lengths.next(), content_lengths.next()) {
        (None, None) => 0,
        (Some(value), None)
            if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value
                .parse::<usize>()
                .map_err(|_| invalid_data("invalid Content-Length"))?
        }
        (Some(_), Some(_)) => {
            return Err(invalid_data("duplicate Content-Length is not supported"));
        }
        _ => return Err(invalid_data("invalid Content-Length")),
    };
    if content_length > MAX_BODY_BYTES {
        return Err(parse_error(413, "HTTP body exceeds native transport limit"));
    }
    let mut request = HttpRequest::new(method, target, headers, Vec::new());
    let body_start = header_end + 4;
    request.body.extend_from_slice(&buf[body_start..]);
    let body_deadline = Instant::now() + body_timeout;
    while request.body.len() < content_length {
        let n = read_before_deadline(stream, &mut chunk, body_deadline, "HTTP body")?;
        if n == 0 {
            return Err(invalid_data("incomplete HTTP body"));
        }
        request.body.extend_from_slice(&chunk[..n]);
    }
    request.body.truncate(content_length);
    if request
        .header("content-type")
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
    {
        validate_form_urlencoded(&request.body)
            .map_err(|_| invalid_data("invalid form body encoding"))?;
    }
    Ok(Some(request))
}

fn read_before_deadline(
    stream: &mut impl DeadlineRead,
    buf: &mut [u8],
    deadline: Instant,
    phase: &'static str,
) -> std::io::Result<usize> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| phase_timed_out(phase))?;
    stream.set_ingress_read_timeout(remaining)?;
    stream.read(buf).map_err(|error| {
        if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            phase_timed_out(phase)
        } else {
            error
        }
    })
}

fn phase_timed_out(phase: &'static str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{phase} absolute deadline exceeded"),
    )
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn invalid_data(message: &'static str) -> std::io::Error {
    parse_error(400, message)
}

fn parse_error(status: u16, message: &'static str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        HttpParseError { status, message },
    )
}

pub(super) fn write_http_response(
    stream: &mut impl Write,
    response: &HttpResponse,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason_phrase(response.status)
    )?;
    let mut has_content_length = false;
    let mut has_connection = false;
    for (name, value) in &response.headers {
        if name.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        if name.eq_ignore_ascii_case("connection") {
            has_connection = true;
        }
        write!(stream, "{name}: {value}\r\n")?;
    }
    if !has_content_length {
        write!(stream, "content-length: {}\r\n", response.body.len())?;
    }
    if !has_connection {
        write!(stream, "connection: close\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(&response.body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct ScheduledReader {
        chunks: VecDeque<(Duration, Vec<u8>)>,
        timeout: Option<Duration>,
    }

    impl ScheduledReader {
        fn new(chunks: impl IntoIterator<Item = (Duration, Vec<u8>)>) -> Self {
            Self {
                chunks: chunks.into_iter().collect(),
                timeout: None,
            }
        }
    }

    impl Read for ScheduledReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some((delay, bytes)) = self.chunks.pop_front() else {
                return Ok(0);
            };
            if let Some(timeout) = self.timeout
                && delay >= timeout
            {
                std::thread::sleep(timeout);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "scheduled read exceeded timeout",
                ));
            }
            std::thread::sleep(delay);
            let count = bytes.len().min(buf.len());
            buf[..count].copy_from_slice(&bytes[..count]);
            if count < bytes.len() {
                self.chunks
                    .push_front((Duration::ZERO, bytes[count..].to_vec()));
            }
            Ok(count)
        }
    }

    impl DeadlineRead for ScheduledReader {
        fn set_ingress_read_timeout(&mut self, timeout: Duration) -> std::io::Result<()> {
            self.timeout = Some(timeout);
            Ok(())
        }
    }

    fn parse_request(raw: impl Into<Vec<u8>>) -> std::io::Result<HttpRequest> {
        let mut reader = ScheduledReader::new([(Duration::ZERO, raw.into())]);
        read_http_request(&mut reader, Duration::from_secs(1), Duration::from_secs(1))?
            .ok_or_else(|| std::io::Error::other("request unexpectedly absent"))
    }

    fn assert_bad_request(raw: &[u8]) {
        let error = parse_request(raw.to_vec()).expect_err("request must fail closed");
        assert_eq!(parse_error_status(&error), Some(400), "{error}");
    }

    #[test]
    fn trickled_header_cannot_reset_the_absolute_deadline() {
        let chunks = b"GET / HTTP/1.1\r\n"
            .iter()
            .map(|byte| (Duration::from_millis(4), vec![*byte]));
        let mut reader = ScheduledReader::new(chunks);
        let started = Instant::now();
        let error = read_http_request(
            &mut reader,
            Duration::from_millis(15),
            Duration::from_secs(1),
        )
        .expect_err("an incomplete trickled header must time out absolutely");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn trickled_body_gets_a_separate_absolute_deadline() {
        let mut chunks = vec![(
            Duration::ZERO,
            b"POST / HTTP/1.1\r\ncontent-length: 8\r\n\r\n".to_vec(),
        )];
        chunks.extend(
            b"12345678"
                .iter()
                .map(|byte| (Duration::from_millis(4), vec![*byte])),
        );
        let mut reader = ScheduledReader::new(chunks);
        let error = read_http_request(
            &mut reader,
            Duration::from_secs(1),
            Duration::from_millis(15),
        )
        .expect_err("an incomplete trickled body must time out absolutely");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("HTTP body"));
    }

    #[test]
    fn complete_request_at_body_limit_succeeds_within_budgets() {
        let body = vec![b'x'; MAX_BODY_BYTES];
        let mut request =
            format!("POST / HTTP/1.1\r\ncontent-length: {}\r\n\r\n", body.len()).into_bytes();
        request.extend_from_slice(&body);
        let mut reader = ScheduledReader::new([(Duration::ZERO, request)]);
        let parsed = read_http_request(&mut reader, Duration::from_secs(1), Duration::from_secs(1))
            .expect("bounded request parses")
            .expect("request is present");
        assert_eq!(parsed.body.len(), MAX_BODY_BYTES);
    }

    #[test]
    fn header_terminator_cannot_bypass_the_header_byte_cap() {
        let mut request = b"GET / HTTP/1.1\r\nx-fill: ".to_vec();
        request.resize(MAX_HEADER_BYTES + 1, b'x');
        request.extend_from_slice(b"\r\n\r\n");
        let mut reader = ScheduledReader::new([(Duration::ZERO, request)]);
        let error = read_http_request(&mut reader, Duration::from_secs(1), Duration::from_secs(1))
            .expect_err("header bytes beyond the cap must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(parse_error_status(&error), Some(431));
        assert!(error.to_string().contains("headers exceed"));
    }

    #[test]
    fn declared_body_over_limit_is_typed_without_reading_body() {
        let request = format!(
            "POST / HTTP/1.1\r\ncontent-length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let mut reader = ScheduledReader::new([(Duration::ZERO, request.into_bytes())]);
        let error = read_http_request(&mut reader, Duration::from_secs(1), Duration::from_secs(1))
            .expect_err("declared oversized body must fail from headers alone");
        assert_eq!(parse_error_status(&error), Some(413));
    }

    #[test]
    fn malformed_content_length_remains_bad_request() {
        let mut reader = ScheduledReader::new([(
            Duration::ZERO,
            b"POST / HTTP/1.1\r\ncontent-length: nope\r\n\r\n".to_vec(),
        )]);
        let error = read_http_request(&mut reader, Duration::from_secs(1), Duration::from_secs(1))
            .expect_err("malformed content length must fail");
        assert_eq!(parse_error_status(&error), Some(400));
    }

    #[test]
    fn transfer_encoding_is_rejected_before_body_parsing() {
        for request in [
            b"POST / HTTP/1.1\r\nhost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nhost: localhost\r\ntRaNsFeR-EnCoDiNg: identity\r\ncontent-length: 0\r\n\r\n".as_slice(),
        ] {
            assert_bad_request(request);
        }
    }

    #[test]
    fn every_duplicate_content_length_is_rejected() {
        for request in [
            b"POST / HTTP/1.1\r\ncontent-length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\ncontent-length: 1\r\nContent-Length: 0\r\n\r\nx".as_slice(),
            b"POST / HTTP/1.1\r\nContent-Length: 0\r\ncontent-length: 1\r\n\r\nx".as_slice(),
        ] {
            assert_bad_request(request);
        }
    }

    #[test]
    fn request_line_requires_exactly_three_valid_fields() {
        for request in [
            b"GET / HTTP/1.1 junk\r\n\r\n".as_slice(),
            b"GET  / HTTP/1.1\r\n\r\n".as_slice(),
            b"GET\t/ HTTP/1.1\r\n\r\n".as_slice(),
            b"G(ET / HTTP/1.1\r\n\r\n".as_slice(),
            b"GET /bad\tpath HTTP/1.1\r\n\r\n".as_slice(),
        ] {
            assert_bad_request(request);
        }
        let request = parse_request(b"M-SEARCH * HTTP/1.1\r\nx-valid:\t value \t\r\n\r\n".to_vec())
            .expect("valid token grammar and optional header whitespace parse");
        assert_eq!(request.method, "M-SEARCH");
        assert_eq!(request.header("x-valid"), Some("value"));
    }

    #[test]
    fn malformed_header_names_and_control_values_are_rejected() {
        for request in [
            b"GET / HTTP/1.1\r\nContent-Length : 0\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\n: empty-name\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nbad(name: value\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nx-value: before\0after\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nx-value: before\x7fafter\r\n\r\n".as_slice(),
        ] {
            assert_bad_request(request);
        }
    }

    #[test]
    fn content_length_uses_the_decimal_digit_grammar() {
        for value in ["", "+1", "-1", "1, 1", "0x10"] {
            let request = format!("POST / HTTP/1.1\r\ncontent-length: {value}\r\n\r\n");
            assert_bad_request(request.as_bytes());
        }
    }

    #[test]
    fn malformed_query_and_form_encoding_are_bad_requests() {
        for target in ["/mcp?value=%", "/mcp?value=%GG", "/mcp?value=%FF"] {
            let request = format!("GET {target} HTTP/1.1\r\n\r\n");
            assert_bad_request(request.as_bytes());
        }

        for body in [
            b"code=%".as_slice(),
            b"code=%GG".as_slice(),
            b"code=%FF".as_slice(),
        ] {
            let mut request = format!(
                "POST /dashboard/pair HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            request.extend_from_slice(body);
            assert_bad_request(&request);
        }
    }

    #[test]
    fn complete_header_at_the_exact_byte_cap_succeeds() {
        let mut request = b"GET / HTTP/1.1\r\nx-fill: ".to_vec();
        request.resize(MAX_HEADER_BYTES - 4, b'x');
        request.extend_from_slice(b"\r\n\r\n");
        assert_eq!(request.len(), MAX_HEADER_BYTES);
        let mut reader = ScheduledReader::new([(Duration::ZERO, request)]);
        let parsed = read_http_request(&mut reader, Duration::from_secs(1), Duration::from_secs(1))
            .expect("header at exact cap parses")
            .expect("request is present");
        assert_eq!(parsed.method, "GET");
    }
}
