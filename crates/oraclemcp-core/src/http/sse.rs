//! The Streamable HTTP SSE surface: replay streams, tool streams, and the
//! `text/event-stream` responses the MCP transport writes.
//!
//! [`HttpSseStream`] is the GET replay stream — it re-emits the buffered events a
//! reconnecting client missed and then keeps the connection open with keepalive
//! comments. [`HttpToolStream`] is the POST tool stream: it pumps K10 row/chunk
//! frames out of a running dispatch as `event: row` / `event: chunk` frames ahead
//! of the authoritative response frame, retaining each one in the result store so
//! the same bytes can be replayed later. [`sse_response`] and
//! [`buffered_sse_response`] build the one-shot SSE bodies, and the stream-cursor
//! helpers ([`parse_stream_cursor`], [`validate_stream_cursor_binding`],
//! [`events_after_sequence`]) are the resume path the result store gates on.
//!
//! Extracted verbatim from `http/mod.rs` (behavior-identical). Nothing here was
//! relaxed in the move: a cursor that cannot be parsed is a 400, a cursor bound to
//! another MCP session is a 400 scope mismatch, a cursor older than the retained
//! ring is a 410 (or an explicit gap event when the client asked to resume by
//! `Last-Event-ID`), and a stream only ever runs while it holds its admission
//! permit. The SSE subscriber capacity gate, the keepalive interval, and the row
//! channel bound stay in `mod.rs`, where they are read by the route handlers.
//!
//! The glob import mirrors the inline test module: this code moved out of
//! `mod.rs` and resolves every name in exactly the environment it was written in,
//! so the extraction cannot silently rebind a type.
use super::*;

pub(super) fn stream_event_sequence(id: &str) -> Option<u64> {
    id.split('/').next()?.parse().ok()
}

pub(super) fn parse_stream_cursor(cursor: Option<&str>) -> Result<u64, HttpResponse> {
    match cursor {
        Some(cursor) if !cursor.trim().is_empty() => {
            stream_event_sequence(cursor).ok_or_else(|| {
                json_response(
                    400,
                    &json!({
                        "error": "invalid_stream_cursor",
                        "message": "cursor must be the exact Streamable HTTP event id emitted for this MCP session",
                    }),
                )
            })
        }
        _ => Ok(0),
    }
}

pub(super) fn validate_stream_cursor_binding(
    cursor: Option<&str>,
    sequence: u64,
    expected_binding: &str,
) -> Result<(), HttpResponse> {
    let Some(cursor) = cursor.filter(|cursor| !cursor.trim().is_empty()) else {
        return Ok(());
    };
    let binding = cursor.split_once('/').map(|(_, binding)| binding);
    if binding.is_none() || (sequence == 0 && binding == Some("0")) {
        return Ok(());
    }
    if binding == Some(expected_binding) {
        return Ok(());
    }
    Err(json_response(
        400,
        &json!({
            "error": "stream_cursor_scope_mismatch",
            "message": "the Streamable HTTP event id belongs to a different MCP session",
            "next_step": "resume with an event id emitted for this MCP session, or omit Last-Event-ID to start at the retained head",
        }),
    ))
}

pub(super) fn events_after_sequence(
    events: &[HttpBufferedEvent],
    dropped_through_sequence: u64,
    after_seq: u64,
    cursor: Option<&str>,
    gap_on_expired_cursor: bool,
    cursor_binding: &str,
) -> Result<Vec<HttpBufferedEvent>, HttpResponse> {
    let oldest_retained_sequence = events
        .first()
        .and_then(|event| stream_event_sequence(&event.id));
    let cursor_expired = after_seq < dropped_through_sequence
        || oldest_retained_sequence.is_some_and(|oldest| after_seq < oldest.saturating_sub(1));
    if cursor_expired {
        let oldest_event_id = events.first().map_or_else(
            || {
                format!(
                    "{}/{cursor_binding}",
                    dropped_through_sequence.saturating_add(1)
                )
            },
            |event| event.id.clone(),
        );
        if !gap_on_expired_cursor {
            return Err(json_response(
                410,
                &json!({
                    "error": "stream_cursor_expired",
                    "message": "requested Streamable HTTP cursor is older than the retained event buffer",
                    "cursor": cursor.unwrap_or(""),
                    "oldest_event_id": oldest_event_id,
                    "dropped_through_event_id": format!("{dropped_through_sequence}/{cursor_binding}"),
                    "next_step": "restart the MCP session; the missing event range is no longer available for replay",
                }),
            ));
        }
        let mut resumed = Vec::with_capacity(events.len().saturating_add(1));
        resumed.push(HttpBufferedEvent::gap(
            format!("{dropped_through_sequence}/{cursor_binding}"),
            cursor,
            &oldest_event_id,
        ));
        resumed.extend(events.iter().cloned());
        return Ok(resumed);
    }
    Ok(events
        .iter()
        .filter(|event| stream_event_sequence(&event.id).is_some_and(|seq| seq > after_seq))
        .cloned()
        .collect())
}

pub(super) struct HttpSseStream {
    store: Arc<HttpResultStore>,
    session_id: String,
    after_seq: u64,
    initial_events: Vec<HttpBufferedEvent>,
    _permit: AdmissionPermit,
}

impl HttpSseStream {
    pub(super) fn new(
        store: Arc<HttpResultStore>,
        session_id: String,
        after_seq: u64,
        initial_events: Vec<HttpBufferedEvent>,
        permit: AdmissionPermit,
    ) -> Self {
        Self {
            store,
            session_id,
            after_seq,
            initial_events,
            _permit: permit,
        }
    }

    pub(super) fn into_buffered_response(self) -> HttpResponse {
        buffered_sse_response(&self.initial_events)
    }

    pub(super) fn write_to(
        mut self,
        stream: &mut impl Write,
        include_hsts: bool,
    ) -> std::io::Result<()> {
        write_streaming_sse_headers(stream, include_hsts)?;
        write_chunked_sse_event(stream, None, Some("0/0"), Some(3000), Some(&Value::Null))?;
        let initial_events = std::mem::take(&mut self.initial_events);
        for event in initial_events {
            self.write_buffered_event(stream, &event)?;
        }
        loop {
            match self.store.wait_events_after(
                &self.session_id,
                self.after_seq,
                SSE_KEEPALIVE_INTERVAL,
            ) {
                HttpResultWait::Events(events) => {
                    for event in events {
                        self.write_buffered_event(stream, &event)?;
                    }
                }
                HttpResultWait::Timeout => write_chunked_sse_comment(stream, "keepalive")?,
                HttpResultWait::Closed => break,
            }
        }
        write_final_chunk(stream)
    }

    fn write_buffered_event(
        &mut self,
        stream: &mut impl Write,
        event: &HttpBufferedEvent,
    ) -> std::io::Result<()> {
        write_chunked_sse_event(
            stream,
            event.event,
            Some(&event.id),
            None,
            Some(&event.data),
        )?;
        if let Some(seq) = stream_event_sequence(&event.id) {
            self.after_seq = self.after_seq.max(seq);
        }
        Ok(())
    }
}

pub(super) struct HttpToolStream {
    server: OracleMcpServer,
    result_store: Option<Arc<HttpResultStore>>,
    session_id: String,
    _principal_key: String,
    request_id: Value,
    frames_rx: mpsc::Receiver<ToolStreamFrame>,
    reply_rx: DispatchReplyReceiver,
    initial_notifications: Vec<HttpBufferedEvent>,
    notification_request_owner: Option<String>,
    progress_token: Option<Value>,
}

pub(super) struct HttpToolStreamBinding {
    pub(super) session_id: String,
    pub(super) principal_key: String,
}

pub(super) struct HttpToolStreamNotifications {
    pub(super) initial: Vec<HttpBufferedEvent>,
    pub(super) request_owner: Option<String>,
    pub(super) progress_token: Option<Value>,
}

impl HttpToolStream {
    pub(super) fn new(
        server: OracleMcpServer,
        result_store: Option<Arc<HttpResultStore>>,
        binding: HttpToolStreamBinding,
        request_id: Value,
        frames_rx: mpsc::Receiver<ToolStreamFrame>,
        reply_rx: DispatchReplyReceiver,
        notifications: HttpToolStreamNotifications,
    ) -> Self {
        Self {
            server,
            result_store,
            session_id: binding.session_id,
            _principal_key: binding.principal_key,
            request_id,
            frames_rx,
            reply_rx,
            initial_notifications: notifications.initial,
            notification_request_owner: notifications.request_owner,
            progress_token: notifications.progress_token,
        }
    }

    pub(super) fn into_buffered_response(mut self) -> HttpResponse {
        let mut body = Vec::new();
        write_sse_event(&mut body, None, Some("0/0"), Some(3000), Some(&Value::Null));
        for notification in &self.initial_notifications {
            write_tool_stream_event_buffered(&mut body, notification);
        }
        let response = crate::lane::block_on_lane_bridge(async {
            let cx = Cx::current().expect("block_on installs a request Cx");
            while let Ok(frame) = self.frames_rx.recv(&cx).await {
                let event = self.retain_frame(frame);
                write_tool_stream_event_buffered(&mut body, &event);
            }
            self.final_response(&cx).await
        });
        for notification in self.finish_notifications() {
            write_tool_stream_event_buffered(&mut body, &notification);
        }
        let response_event_id = self.append_final_response(&response);
        write_sse_event(
            &mut body,
            None,
            response_event_id.as_deref(),
            None,
            Some(&response),
        );
        HttpResponse {
            status: 200,
            headers: vec![
                ("content-type".to_owned(), "text/event-stream".to_owned()),
                ("cache-control".to_owned(), "no-cache".to_owned()),
            ],
            body,
        }
    }

    pub(super) fn write_to(
        mut self,
        stream: &mut impl Write,
        include_hsts: bool,
    ) -> std::io::Result<()> {
        write_streaming_sse_headers(stream, include_hsts)?;
        write_chunked_sse_event(stream, None, Some("0/0"), Some(3000), Some(&Value::Null))?;
        for notification in &self.initial_notifications {
            write_tool_stream_event_chunked(stream, notification)?;
        }
        let response = crate::lane::block_on_lane_bridge(async {
            let cx = Cx::current().expect("block_on installs a request Cx");
            loop {
                match self.frames_rx.recv(&cx).await {
                    Ok(frame) => {
                        let event = self.retain_frame(frame);
                        write_tool_stream_event_chunked(stream, &event)?;
                    }
                    Err(mpsc::RecvError::Disconnected) => break,
                    Err(mpsc::RecvError::Cancelled) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "stream frame receive cancelled",
                        ));
                    }
                    Err(mpsc::RecvError::Empty) => continue,
                }
            }
            Ok::<Value, std::io::Error>(self.final_response(&cx).await)
        })?;
        for notification in self.finish_notifications() {
            write_tool_stream_event_chunked(stream, &notification)?;
        }
        let response_event_id = self.append_final_response(&response);
        write_chunked_sse_event(
            stream,
            None,
            response_event_id.as_deref(),
            None,
            Some(&response),
        )?;
        write_final_chunk(stream)
    }

    async fn final_response(&mut self, cx: &Cx) -> Value {
        match self.reply_rx.recv(cx).await {
            Ok(outcome) => self
                .server
                .jsonrpc_tool_response_from_outcome(self.request_id.clone(), outcome),
            Err(_) => self.server.jsonrpc_tool_response_from_outcome(
                self.request_id.clone(),
                Outcome::Err(ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "streaming dispatch lane stopped before final reply",
                )),
            ),
        }
    }

    fn append_final_response(&self, response: &Value) -> Option<String> {
        self.result_store
            .as_ref()
            .and_then(|store| store.append_response_if_session(&self.session_id, response.clone()))
    }

    fn finish_notifications(&self) -> Vec<HttpBufferedEvent> {
        let (Some(request_owner), Some(progress_token)) = (
            self.notification_request_owner.as_deref(),
            self.progress_token.as_ref(),
        ) else {
            return Vec::new();
        };
        self.server.notifications().enqueue_progress(
            request_owner,
            progress_token,
            1.0,
            Some(1.0),
            Some("oracle_query completed"),
        );
        retain_server_notifications(
            self.result_store.as_deref(),
            Some(&self.session_id),
            self.server.drain_server_notifications(request_owner),
        )
    }

    fn retain_frame(&self, frame: ToolStreamFrame) -> HttpBufferedEvent {
        let (event_name, data) = tool_stream_frame_data(frame);
        let id = self
            .result_store
            .as_ref()
            .and_then(|store| {
                store.append_event_if_session(&self.session_id, Some(event_name), data.clone())
            })
            .unwrap_or_default();
        HttpBufferedEvent::named(id, event_name, data)
    }
}

fn tool_stream_frame_data(frame: ToolStreamFrame) -> (&'static str, Value) {
    match frame {
        ToolStreamFrame::Row { seq, row } => ("row", json!({ "seq": seq, "row": row })),
        ToolStreamFrame::Chunk { chunk, .. } => ("chunk", chunk),
    }
}

fn write_tool_stream_event_buffered(body: &mut Vec<u8>, event: &HttpBufferedEvent) {
    write_sse_event(
        body,
        event.event,
        (!event.id.is_empty()).then_some(event.id.as_str()),
        None,
        Some(&event.data),
    );
}

fn write_tool_stream_event_chunked(
    stream: &mut impl Write,
    event: &HttpBufferedEvent,
) -> std::io::Result<()> {
    write_chunked_sse_event(
        stream,
        event.event,
        (!event.id.is_empty()).then_some(event.id.as_str()),
        None,
        Some(&event.data),
    )
}

pub(super) fn buffered_sse_response(events: &[HttpBufferedEvent]) -> HttpResponse {
    let mut body = Vec::new();
    write_sse_event(&mut body, None, Some("0/0"), Some(3000), Some(&Value::Null));
    for event in events {
        write_sse_event(
            &mut body,
            event.event,
            Some(&event.id),
            None,
            Some(&event.data),
        );
    }
    HttpResponse {
        status: 200,
        headers: vec![
            ("content-type".to_owned(), "text/event-stream".to_owned()),
            ("cache-control".to_owned(), "no-cache".to_owned()),
        ],
        body,
    }
}

/// K10: if `response` is a streaming `oracle_query` tool result, borrow its
/// ordered page `chunks` for SSE chunk-frame emission. `None` for every other
/// response, so the standard single-frame SSE path is untouched.
pub(super) fn streaming_query_chunks(response: &Value) -> Option<&Vec<Value>> {
    let structured = response.get("result")?.get("structuredContent")?;
    if structured.get("streaming").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    structured.get("chunks").and_then(Value::as_array)
}

pub(super) fn append_nonstreaming_response_if_session(
    store: &HttpResultStore,
    session_id: &str,
    response: &Value,
) -> Option<String> {
    streaming_query_chunks(response)
        .is_none()
        .then(|| store.append_response_if_session(session_id, response.clone()))
        .flatten()
}

pub(super) fn retain_server_notifications(
    store: Option<&HttpResultStore>,
    session_id: Option<&str>,
    notifications: Vec<Value>,
) -> Vec<HttpBufferedEvent> {
    notifications
        .into_iter()
        .map(|notification| {
            let id = session_id
                .zip(store)
                .and_then(|(session_id, store)| {
                    store.append_response_if_session(session_id, notification.clone())
                })
                .unwrap_or_default();
            HttpBufferedEvent::data(id, notification)
        })
        .collect()
}

pub(super) struct SseResponseEvents<'a> {
    pub(super) response_event_id: Option<&'a str>,
    pub(super) notifications: &'a [HttpBufferedEvent],
}

pub(super) fn sse_response(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    method: Option<&str>,
    response: Value,
    initialized_session_id: Option<String>,
    principal_key: &str,
    events: SseResponseEvents<'_>,
) -> HttpResponse {
    let mut body = Vec::new();
    // A method string alone does not establish an MCP session. The negotiated
    // revision must come from a successful JSON-RPC initialize result; parse,
    // validation, lifecycle, and dispatch errors never allocate state.
    let negotiated_version = if method == Some("initialize") && response.get("error").is_none() {
        response
            .get("result")
            .and_then(|result| result.get("protocolVersion"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    } else {
        None
    };
    let session_id = if method == Some("initialize") {
        write_sse_event(&mut body, None, Some("0"), Some(3000), Some(&Value::Null));
        write_sse_event(&mut body, None, None, None, Some(&response));
        negotiated_version
            .as_ref()
            .map(|_| initialized_session_id.unwrap_or_else(new_session_id))
    } else {
        write_sse_event(&mut body, None, Some("0/0"), Some(3000), Some(&Value::Null));
        for notification in events.notifications {
            write_sse_event(
                &mut body,
                None,
                (!notification.id.is_empty()).then_some(notification.id.as_str()),
                None,
                Some(&notification.data),
            );
        }
        // K10: a streaming `oracle_query` result carries an ordered page
        // `chunks` array. Emit each chunk as its own `event: chunk` SSE frame
        // BEFORE the authoritative response frame, so a streaming-aware client
        // renders pages progressively while a plain client still reads the final
        // result. Purely additive — every non-streaming response is unchanged.
        let chunks = streaming_query_chunks(&response).cloned();
        let retained_chunks = chunks.as_ref().map(|chunks| {
            chunks
                .iter()
                .cloned()
                .map(|chunk| {
                    let id = initialized_session_id
                        .as_deref()
                        .zip(config.result_store.as_deref())
                        .and_then(|(session_id, store)| {
                            store.append_event_if_session(session_id, Some("chunk"), chunk.clone())
                        })
                        .unwrap_or_default();
                    HttpBufferedEvent::named(id, "chunk", chunk)
                })
                .collect::<Vec<_>>()
        });
        if let Some(chunks) = retained_chunks.as_ref() {
            for chunk in chunks {
                write_tool_stream_event_buffered(&mut body, chunk);
            }
        }
        let retained_response_event_id = if chunks.is_some() {
            initialized_session_id
                .as_deref()
                .zip(config.result_store.as_deref())
                .and_then(|(session_id, store)| {
                    store.append_response_if_session(session_id, response.clone())
                })
        } else {
            None
        };
        write_sse_event(
            &mut body,
            None,
            retained_response_event_id
                .as_deref()
                .or(events.response_event_id),
            None,
            Some(&response),
        );
        None
    };
    let mut headers = vec![
        ("content-type".to_owned(), "text/event-stream".to_owned()),
        ("cache-control".to_owned(), "no-cache".to_owned()),
    ];
    if let Some(session_id) = session_id {
        if let Some(store) = &config.session_store {
            let negotiated_version = negotiated_version
                .as_deref()
                .expect("session id is minted only for a negotiated initialize result");
            if let Err(rejection) = store.insert_with_result_store(
                session_id.clone(),
                principal_key.to_owned(),
                negotiated_version.to_owned(),
                config.stateful_idle_ttl,
                config.result_store.as_deref(),
            ) {
                return stateful_session_capacity_response(rejection, principal_key);
            }
        }
        headers.push(("mcp-session-id".to_owned(), session_id.clone()));
        let cookie_policy = PrivilegedCookiePolicy::for_request(config, request);
        if cookie_policy != PrivilegedCookiePolicy::Suppress {
            headers.push((
                "set-cookie".to_owned(),
                stateful_session_cookie_header(&session_id, cookie_policy.secure()),
            ));
        }
    }
    HttpResponse {
        status: 200,
        headers,
        body,
    }
}
