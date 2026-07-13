fn streaming_query_response() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 7,
        "result": {
            "structuredContent": {
                "streaming": true,
                "columns": ["ID", "NAME"],
                "chunk_count": 2,
                "row_count": 3,
                "truncated": false,
                "next_cursor": Value::Null,
                "chunks": [
                    { "seq": 0, "rows": [{"ID": "1", "NAME": "a"}, {"ID": "2", "NAME": "b"}],
                      "row_count": 2, "total_bytes": 40, "next_cursor": "sealed-cursor-0", "last": false },
                    { "seq": 1, "rows": [{"ID": "3", "NAME": "c"}],
                      "row_count": 1, "total_bytes": 20, "next_cursor": Value::Null, "last": true }
                ]
            }
        }
    })
}

#[test]
fn streaming_query_chunks_detects_only_streaming_results() {
    // A streaming oracle_query result exposes its ordered chunks.
    let streaming = streaming_query_response();
    let chunks = streaming_query_chunks(&streaming).expect("streaming result has chunks");
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0]["seq"], json!(0));

    // A plain (non-streaming) tool result is never treated as streaming.
    let inline = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": { "structuredContent": { "columns": ["ID"], "rows": [], "row_count": 0 } }
    });
    assert!(streaming_query_chunks(&inline).is_none());

    // A streaming flag without a chunks array degrades to None (no framing).
    let no_chunks = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": { "structuredContent": { "streaming": true } }
    });
    assert!(streaming_query_chunks(&no_chunks).is_none());

    // An error response (no result) is never streaming.
    let err = json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "x" } });
    assert!(streaming_query_chunks(&err).is_none());
}

#[test]
fn write_query_stream_chunks_frames_each_chunk_as_an_sse_event() {
    let streaming = streaming_query_response();
    let chunks = streaming_query_chunks(&streaming).expect("chunks");
    let mut body = Vec::new();
    let framed = write_query_stream_chunks(&mut body, chunks);
    assert_eq!(framed, 2, "one SSE frame per chunk");
    let text = String::from_utf8(body).expect("utf8 SSE body");
    // The low-level writer cannot promise replay, so it emits no fake ids.
    assert_eq!(text.matches("event: chunk\n").count(), 2);
    assert!(!text.contains("id:"));
    // The chunk rows ride in the frame data (progressive delivery).
    assert!(text.contains("\"NAME\":\"a\""));
    assert!(text.contains("\"NAME\":\"c\""));
    // The re-sealed cursor of a non-final chunk is carried for resume.
    assert!(text.contains("sealed-cursor-0"));
}

#[test]
fn tool_stream_response_frames_each_row_before_final_result() {
    let result_store = Arc::new(HttpResultStore::new());
    result_store.ensure_session("session-test");
    result_store.ensure_session("other-session");
    let (frames_tx, frames_rx) = mpsc::channel(4);
    let permit = frames_tx.try_reserve().expect("reserve first row frame");
    permit
        .try_send(ToolStreamFrame::Row {
            seq: 0,
            row: json!({ "ID": "1", "NAME": "a" }),
        })
        .expect("send first row frame");
    let permit = frames_tx.try_reserve().expect("reserve second row frame");
    permit
        .try_send(ToolStreamFrame::Row {
            seq: 1,
            row: json!({ "ID": "2", "NAME": "b" }),
        })
        .expect("send second row frame");
    drop(frames_tx);

    let (reply_tx, reply_rx) = oneshot::channel();
    reply_tx
        .send_blocking(Outcome::Ok(json!({
            "streaming": true,
            "streaming_mode": "rows",
            "columns": ["ID", "NAME"],
            "row_count": 2,
            "truncated": false,
            "next_cursor": Value::Null
        })))
        .expect("send final streaming outcome");
    let response = HttpToolStream::new(
        test_server(),
        Some(Arc::clone(&result_store)),
        HttpToolStreamBinding {
            session_id: "session-test".to_owned(),
            principal_key: "principal-test".to_owned(),
        },
        json!(7),
        frames_rx,
        reply_rx.into(),
        HttpToolStreamNotifications {
            initial: Vec::new(),
            request_owner: None,
            progress_token: None,
        },
    )
    .into_buffered_response();
    assert_eq!(response.status, 200);
    let text = String::from_utf8(response.body).expect("utf8 SSE body");
    assert_eq!(
        text.matches("event: row\n").count(),
        2,
        "one row SSE frame per produced row"
    );
    assert!(text.contains("\"streaming_mode\":\"rows\""));

    let retained = result_store
        .events_after("session-test", None, false)
        .expect("stream replay remains available");
    assert_eq!(retained.len(), 3, "two rows and one final response");
    assert_eq!(retained[0].event, Some("row"));
    assert_eq!(retained[1].event, Some("row"));
    assert_eq!(retained[2].event, None);
    assert!(retained[0].id.starts_with("1/"));
    assert!(retained[1].id.starts_with("2/"));
    assert!(retained[2].id.starts_with("3/"));
    for event in &retained {
        assert!(text.contains(&format!("id: {}\n", event.id)));
    }

    let resumed = result_store
        .events_after("session-test", Some(&retained[0].id), false)
        .expect("the exact emitted row id is resumable");
    assert_eq!(resumed, retained[1..]);
    let wrong_session = result_store
        .events_after("other-session", Some(&retained[0].id), false)
        .expect_err("an emitted id cannot cross MCP session scope");
    assert_eq!(wrong_session.status, 400);
    let body: Value = serde_json::from_slice(&wrong_session.body).expect("scope error JSON");
    assert_eq!(
        body["error"],
        serde_json::json!("stream_cursor_scope_mismatch")
    );

    let first_row = text.find("event: row\n").expect("row frame present");
    let final_response = text
        .find("\"jsonrpc\":\"2.0\"")
        .expect("final JSON-RPC response present");
    assert!(
        first_row < final_response,
        "row frames stream before the final authoritative response"
    );
}

#[test]
fn sse_response_emits_chunk_frames_before_the_authoritative_result() {
    // End-to-end SSE assembly: a streaming query response frames each page as
    // its own `event: chunk` SSE event, THEN the authoritative response frame —
    // a plain client still reads the final result; a streaming-aware client
    // renders chunks progressively.
    let result_store = Arc::new(HttpResultStore::new());
    result_store.ensure_session("chunk-session");
    let cfg = HttpTransportConfig {
        stateful: true,
        result_store: Some(Arc::clone(&result_store)),
        ..Default::default()
    };
    let request = post(&init_body()).with_peer_loopback(true);
    let response = sse_response(
        &cfg,
        &request,
        Some("tools/call"),
        streaming_query_response(),
        Some("chunk-session".to_owned()),
        "principal-test",
        SseResponseEvents {
            response_event_id: None,
            notifications: &[],
        },
    );
    assert_eq!(response.status, 200);
    let text = String::from_utf8(response.body).expect("utf8 SSE body");
    assert_eq!(
        text.matches("event: chunk\n").count(),
        2,
        "two page chunks framed as SSE events"
    );
    let retained = result_store
        .events_after("chunk-session", None, false)
        .expect("chunk replay remains available");
    assert_eq!(retained.len(), 3, "two chunks and the final response");
    assert_eq!(retained[0].event, Some("chunk"));
    assert_eq!(retained[1].event, Some("chunk"));
    assert_eq!(retained[2].event, None);
    let first_chunk = text
        .find(&format!("id: {}\n", retained[0].id))
        .expect("first resumable chunk frame");
    let response_frame = text
        .find(&format!("id: {}\n", retained[2].id))
        .expect("authoritative response frame");
    assert!(
        first_chunk < response_frame,
        "chunks stream before the final result"
    );

    // A NON-streaming response is unchanged: no chunk frames, just the result.
    let inline = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": { "structuredContent": { "columns": ["ID"], "rows": [], "row_count": 0 } }
    });
    let plain = sse_response(
        &cfg,
        &request,
        Some("tools/call"),
        inline,
        None,
        "principal-test",
        SseResponseEvents {
            response_event_id: Some("1/0"),
            notifications: &[],
        },
    );
    let plain_text = String::from_utf8(plain.body).expect("utf8");
    assert!(
        !plain_text.contains("event: chunk\n"),
        "no chunk frames for inline reads"
    );
}
