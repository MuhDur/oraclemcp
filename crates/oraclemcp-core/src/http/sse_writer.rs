//! Server-Sent Events frame writers and HTTP/1.1 chunked-transfer helpers.
//!
//! `write_sse_event` serializes a single SSE frame into an in-memory buffer;
//! the `write_chunked_*`/`write_streaming_sse_headers`/`write_final_chunk`
//! helpers stream those frames over a live socket using `transfer-encoding:
//! chunked`. Extracted verbatim from the transport surface (behavior-identical).

use std::io::Write;

use serde_json::Value;

use super::reason_phrase;

pub(super) fn write_sse_event(
    body: &mut Vec<u8>,
    event: Option<&str>,
    id: Option<&str>,
    retry: Option<u64>,
    data: Option<&Value>,
) {
    if let Some(event) = event {
        body.extend_from_slice(format!("event: {event}\n").as_bytes());
    }
    if let Some(id) = id {
        body.extend_from_slice(format!("id: {id}\n").as_bytes());
    }
    if let Some(retry) = retry {
        body.extend_from_slice(format!("retry: {retry}\n").as_bytes());
    }
    if let Some(data) = data {
        if data.is_null() {
            body.extend_from_slice(b"data:\n");
        } else {
            body.extend_from_slice(b"data: ");
            body.extend_from_slice(
                serde_json::to_string(data)
                    .expect("SSE event data serializes")
                    .as_bytes(),
            );
            body.push(b'\n');
        }
    }
    body.push(b'\n');
}

/// K10: frame a streaming `oracle_query` result's ordered page `chunks` as
/// individual SSE `event: chunk` frames into `body`. This is the streaming
/// ASSEMBLY: the caller writes the authoritative JSON-RPC response frame AFTER
/// these, so a streaming-aware client renders chunks progressively while a
/// plain MCP client still consumes the final result. Each frame's `id` is
/// `chunk/<seq>` (monotonic, resumable) and its `data` is the chunk object
/// (rows + re-sealed `next_cursor`). Returns the number of chunk frames written.
pub(super) fn write_query_stream_chunks(body: &mut Vec<u8>, chunks: &[Value]) -> usize {
    for (i, chunk) in chunks.iter().enumerate() {
        let seq = chunk.get("seq").and_then(Value::as_u64).unwrap_or(i as u64);
        let id = format!("chunk/{seq}");
        write_sse_event(body, Some("chunk"), Some(&id), None, Some(chunk));
    }
    chunks.len()
}

pub(super) fn write_streaming_sse_headers(stream: &mut impl Write) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 {}\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\ntransfer-encoding: chunked\r\nconnection: close\r\nx-accel-buffering: no\r\n\r\n",
        reason_phrase(200)
    )?;
    stream.flush()
}

pub(super) fn write_chunked_sse_event(
    stream: &mut impl Write,
    event: Option<&str>,
    id: Option<&str>,
    retry: Option<u64>,
    data: Option<&Value>,
) -> std::io::Result<()> {
    let mut body = Vec::new();
    write_sse_event(&mut body, event, id, retry, data);
    write_chunked_bytes(stream, &body)
}

pub(super) fn write_chunked_sse_comment(
    stream: &mut impl Write,
    comment: &str,
) -> std::io::Result<()> {
    let mut body = Vec::with_capacity(comment.len().saturating_add(4));
    body.extend_from_slice(b": ");
    body.extend_from_slice(comment.as_bytes());
    body.extend_from_slice(b"\n\n");
    write_chunked_bytes(stream, &body)
}

fn write_chunked_bytes(stream: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    write!(stream, "{:x}\r\n", bytes.len())?;
    stream.write_all(bytes)?;
    stream.write_all(b"\r\n")?;
    stream.flush()
}

pub(super) fn write_final_chunk(stream: &mut impl Write) -> std::io::Result<()> {
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()
}
