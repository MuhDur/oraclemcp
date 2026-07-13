//! The transport's in-memory session and result stores.
//!
//! [`HttpSessionStore`] is the stateful-mode session table: it mints and
//! validates `mcp-session-id`, binds each session to its server-derived
//! principal, enforces the global and per-principal session caps, and reaps idle
//! sessions. [`HttpResultStore`] is the replay buffer behind Streamable HTTP GET:
//! it retains a bounded ring of POST responses and server notifications per
//! session so a reconnecting client can resume by `cursor` / `Last-Event-ID`,
//! and returns a typed refusal rather than silently replaying a truncated suffix
//! when a cursor has aged out of the ring.
//!
//! Extracted verbatim from `http/mod.rs` (behavior-identical). Both stores are
//! in-memory by construction — no database, and no file is opened here. The
//! files-first persistence (change proposals, source snapshots, the audit tail)
//! lives in its own crate modules and is reached from the operator route
//! handlers, not from this module.
//!
//! Every bound is a fail-closed cap and moved unchanged: the global and
//! per-principal stateful-session ceilings with their `retry_after_ms`, and the
//! four buffered-event ceilings (per-session event count, per-event bytes,
//! per-session bytes, and the global byte budget) that keep one client from
//! consuming the whole transport's replay memory.
//!
//! The glob import mirrors the inline test module: this code moved out of
//! `mod.rs` and resolves every name in exactly the environment it was written
//! in, so the extraction cannot silently rebind a type.
use super::*;

const DEFAULT_MAX_STATEFUL_SESSIONS_GLOBAL: usize = 1_024;
const DEFAULT_MAX_STATEFUL_SESSIONS_PER_PRINCIPAL: usize = 32;
pub(super) const STATEFUL_SESSION_RETRY_AFTER_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug)]
pub(super) struct HttpSessionLimits {
    pub(super) max_global: usize,
    pub(super) max_per_principal: usize,
}

impl Default for HttpSessionLimits {
    fn default() -> Self {
        Self {
            max_global: DEFAULT_MAX_STATEFUL_SESSIONS_GLOBAL,
            max_per_principal: DEFAULT_MAX_STATEFUL_SESSIONS_PER_PRINCIPAL,
        }
    }
}

#[derive(Debug)]
pub(super) struct HttpSessionCapacityRejection {
    pub(super) scope: &'static str,
    pub(super) active_global: usize,
    pub(super) active_for_principal: usize,
    pub(super) limits: HttpSessionLimits,
}

/// Shared stateful Streamable HTTP session-id registry.
#[derive(Debug)]
pub struct HttpSessionStore {
    state: Mutex<HttpSessionStoreState>,
    limits: HttpSessionLimits,
}

#[derive(Debug, Default)]
struct HttpSessionStoreState {
    owners: HashMap<String, HttpSessionEntry>,
    principal_counts: HashMap<String, usize>,
    expirations: BTreeMap<Instant, HashSet<String>>,
}

#[derive(Debug)]
struct HttpSessionEntry {
    principal_key: String,
    idle_ttl: Duration,
    expires_at: Option<Instant>,
    /// The protocol revision negotiated by this session's `initialize` (bead
    /// oraclemcp-s693). Drives the post-init `MCP-Protocol-Version` header
    /// requirement for sessions that negotiated >= 2025-06-18.
    protocol_version: String,
}

impl Default for HttpSessionStore {
    fn default() -> Self {
        Self {
            state: Mutex::new(HttpSessionStoreState::default()),
            limits: HttpSessionLimits::default(),
        }
    }
}

impl HttpSessionStore {
    #[cfg(test)]
    pub(super) fn with_limits_for_test(max_global: usize, max_per_principal: usize) -> Self {
        Self {
            state: Mutex::new(HttpSessionStoreState::default()),
            limits: HttpSessionLimits {
                max_global,
                max_per_principal,
            },
        }
    }

    #[cfg(test)]
    pub(super) fn insert(&self, id: String, principal_key: String, protocol_version: String) {
        self.insert_with_result_store(
            id,
            principal_key,
            protocol_version,
            Duration::from_secs(DEFAULT_STATEFUL_IDLE_TTL_SECONDS),
            None,
        )
        .expect("test session insert stays within default capacity");
    }

    pub(super) fn insert_with_result_store(
        &self,
        id: String,
        principal_key: String,
        protocol_version: String,
        idle_ttl: Duration,
        result_store: Option<&HttpResultStore>,
    ) -> Result<(), HttpSessionCapacityRejection> {
        let mut state = self.state.lock();
        let active_global = state.owners.len();
        let active_for_principal = state
            .principal_counts
            .get(&principal_key)
            .copied()
            .unwrap_or(0);
        if state.owners.contains_key(&id) {
            return Err(HttpSessionCapacityRejection {
                scope: "stateful_session_id_collision",
                active_global,
                active_for_principal,
                limits: self.limits,
            });
        }
        if active_global >= self.limits.max_global {
            return Err(HttpSessionCapacityRejection {
                scope: "stateful_sessions_global",
                active_global,
                active_for_principal,
                limits: self.limits,
            });
        }
        if active_for_principal >= self.limits.max_per_principal {
            return Err(HttpSessionCapacityRejection {
                scope: "stateful_sessions_principal",
                active_global,
                active_for_principal,
                limits: self.limits,
            });
        }

        // Lock ordering is session registry, then result registry everywhere a
        // coordinated operation needs both. Neither entry becomes observable
        // until both maps contain it.
        let mut result_state = result_store.map(|store| store.state.lock());
        if let Some(result_state) = result_state.as_mut() {
            result_state
                .sessions
                .entry(id.clone())
                .or_insert_with(|| HttpResultSession::new(&id));
        }
        let now = Instant::now();
        let expires_at = (!idle_ttl.is_zero()).then(|| now.checked_add(idle_ttl).unwrap_or(now));
        state.owners.insert(
            id.clone(),
            HttpSessionEntry {
                principal_key: principal_key.clone(),
                idle_ttl,
                expires_at,
                protocol_version,
            },
        );
        *state.principal_counts.entry(principal_key).or_default() += 1;
        if let Some(expires_at) = expires_at {
            state.expirations.entry(expires_at).or_default().insert(id);
        }
        Ok(())
    }

    pub(super) fn principal_for(&self, id: &str) -> Option<String> {
        let mut state = self.state.lock();
        let (principal_key, old_expiry, new_expiry) = {
            let entry = state.owners.get_mut(id)?;
            let now = Instant::now();
            let old_expiry = entry.expires_at;
            let new_expiry =
                (!entry.idle_ttl.is_zero()).then(|| now.checked_add(entry.idle_ttl).unwrap_or(now));
            entry.expires_at = new_expiry;
            (entry.principal_key.clone(), old_expiry, new_expiry)
        };
        unschedule_session_expiry(&mut state, id, old_expiry);
        if let Some(new_expiry) = new_expiry {
            state
                .expirations
                .entry(new_expiry)
                .or_default()
                .insert(id.to_owned());
        }
        Some(principal_key)
    }

    /// The protocol revision the session negotiated at `initialize`.
    pub(super) fn protocol_version_for(&self, id: &str) -> Option<String> {
        self.state
            .lock()
            .owners
            .get(id)
            .map(|entry| entry.protocol_version.clone())
    }

    pub(super) fn remove(&self, id: &str) -> bool {
        let mut state = self.state.lock();
        remove_session_entry(&mut state, id).is_some()
    }

    pub(super) fn remove_principal(&self, principal_key: &str) -> Vec<String> {
        let mut state = self.state.lock();
        let session_ids = state
            .owners
            .iter()
            .filter(|(_, entry)| entry.principal_key == principal_key)
            .map(|(session_id, _)| session_id.clone())
            .collect::<Vec<_>>();
        for session_id in &session_ids {
            remove_session_entry(&mut state, session_id);
        }
        session_ids
    }

    pub(super) fn session_ids(&self) -> Vec<String> {
        self.state.lock().owners.keys().cloned().collect()
    }

    pub(super) fn reap_idle(&self, idle_ttl: Duration) -> Vec<(String, String)> {
        if idle_ttl.is_zero() {
            return Vec::new();
        }
        self.reap_idle_at(idle_ttl, Instant::now())
    }

    fn reap_idle_at(&self, _idle_ttl: Duration, now: Instant) -> Vec<(String, String)> {
        let mut state = self.state.lock();
        let mut expired = Vec::new();
        while state
            .expirations
            .first_key_value()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            let Some((deadline, session_ids)) = state.expirations.pop_first() else {
                break;
            };
            for session_id in session_ids {
                if state
                    .owners
                    .get(&session_id)
                    .is_some_and(|entry| entry.expires_at == Some(deadline))
                    && let Some(entry) = remove_session_entry(&mut state, &session_id)
                {
                    expired.push((session_id, entry.principal_key));
                }
            }
        }
        expired
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.state.lock().owners.len()
    }

    pub(super) fn close_all(&self) {
        let mut state = self.state.lock();
        state.owners.clear();
        state.principal_counts.clear();
        state.expirations.clear();
    }

    #[cfg(test)]
    pub(super) fn force_idle_for_test(&self, id: &str, idle_for: Duration) {
        let mut state = self.state.lock();
        let old_expiry = state.owners.get(id).and_then(|entry| entry.expires_at);
        unschedule_session_expiry(&mut state, id, old_expiry);
        if let Some(entry) = state.owners.get_mut(id) {
            let now = Instant::now();
            let last_seen = now.checked_sub(idle_for).unwrap_or(now);
            entry.expires_at = (!entry.idle_ttl.is_zero())
                .then(|| last_seen.checked_add(entry.idle_ttl).unwrap_or(last_seen));
            if let Some(expires_at) = entry.expires_at {
                state
                    .expirations
                    .entry(expires_at)
                    .or_default()
                    .insert(id.to_owned());
            }
        }
    }
}

fn unschedule_session_expiry(
    state: &mut HttpSessionStoreState,
    id: &str,
    expires_at: Option<Instant>,
) {
    let Some(expires_at) = expires_at else {
        return;
    };
    let remove_bucket = state
        .expirations
        .get_mut(&expires_at)
        .is_some_and(|session_ids| {
            session_ids.remove(id);
            session_ids.is_empty()
        });
    if remove_bucket {
        state.expirations.remove(&expires_at);
    }
}

fn remove_session_entry(state: &mut HttpSessionStoreState, id: &str) -> Option<HttpSessionEntry> {
    let entry = state.owners.remove(id)?;
    unschedule_session_expiry(state, id, entry.expires_at);
    if let Some(count) = state.principal_counts.get_mut(&entry.principal_key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            state.principal_counts.remove(&entry.principal_key);
        }
    }
    Some(entry)
}

pub(super) const MAX_BUFFERED_MCP_EVENTS_PER_SESSION: usize = 128;
const MAX_BUFFERED_MCP_EVENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_BUFFERED_MCP_BYTES_PER_SESSION: usize = 16 * 1024 * 1024;
const MAX_BUFFERED_MCP_BYTES_GLOBAL: usize = 64 * 1024 * 1024;

/// Stateful Streamable HTTP result buffer.
///
/// POST still returns a response for compatible clients, but every stateful
/// JSON-RPC response is also retained here under the MCP session id. GET can
/// then replay responses after a cursor, which is the substrate later streaming
/// and disconnect/resume work builds on.
#[derive(Debug, Default)]
pub struct HttpResultStore {
    state: Mutex<HttpResultStoreState>,
    changed: Condvar,
    limits: HttpResultStoreLimits,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct HttpResultStoreLimits {
    pub(super) max_events_per_session: usize,
    pub(super) max_event_bytes: usize,
    pub(super) max_session_bytes: usize,
    pub(super) max_global_bytes: usize,
}

impl Default for HttpResultStoreLimits {
    fn default() -> Self {
        Self {
            max_events_per_session: MAX_BUFFERED_MCP_EVENTS_PER_SESSION,
            max_event_bytes: MAX_BUFFERED_MCP_EVENT_BYTES,
            max_session_bytes: MAX_BUFFERED_MCP_BYTES_PER_SESSION,
            max_global_bytes: MAX_BUFFERED_MCP_BYTES_GLOBAL,
        }
    }
}

#[derive(Debug, Default)]
struct HttpResultStoreState {
    sessions: HashMap<String, HttpResultSession>,
    retained_bytes: usize,
    next_completion_ordinal: u64,
}

#[derive(Debug)]
struct HttpResultSession {
    events: Vec<HttpRetainedEvent>,
    retained_bytes: usize,
    next_sequence: u64,
    dropped_through_sequence: u64,
    cursor_binding: String,
}

#[derive(Debug)]
struct HttpRetainedEvent {
    event: HttpBufferedEvent,
    retained_bytes: usize,
    completion_ordinal: u64,
}

impl HttpResultSession {
    fn new(session_id: &str) -> Self {
        Self {
            events: Vec::new(),
            retained_bytes: 0,
            next_sequence: 0,
            dropped_through_sequence: 0,
            cursor_binding: sha256_hex(session_id.as_bytes())[..32].to_owned(),
        }
    }

    fn evict_oldest(&mut self) -> Option<usize> {
        if self.events.is_empty() {
            return None;
        }
        let evicted = self.events.remove(0);
        if let Some(sequence) = stream_event_sequence(&evicted.event.id) {
            self.dropped_through_sequence = self.dropped_through_sequence.max(sequence);
        }
        self.retained_bytes = self.retained_bytes.saturating_sub(evicted.retained_bytes);
        Some(evicted.retained_bytes)
    }

    fn buffered_events(&self) -> Vec<HttpBufferedEvent> {
        self.events
            .iter()
            .map(|event| event.event.clone())
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HttpBufferedEvent {
    pub(super) id: String,
    pub(super) event: Option<&'static str>,
    pub(super) data: Arc<Value>,
}

impl HttpBufferedEvent {
    pub(super) fn data(id: String, data: Value) -> Self {
        Self {
            id,
            event: None,
            data: Arc::new(data),
        }
    }

    pub(super) fn named(id: String, event: &'static str, data: Value) -> Self {
        Self {
            id,
            event: Some(event),
            data: Arc::new(data),
        }
    }

    pub(super) fn gap(id: String, requested_cursor: Option<&str>, oldest_event_id: &str) -> Self {
        Self {
            id,
            event: Some("stream-gap"),
            data: Arc::new(json!({
                "type": "stream_gap",
                "message": "one or more Streamable HTTP events were dropped before this resume point",
                "requested_last_event_id": requested_cursor.unwrap_or(""),
                "oldest_event_id": oldest_event_id,
                "next_step": "continue from the retained events in this stream; restart the MCP session if the missing range is required",
            })),
        }
    }

    fn oversized(id: String, response_bytes: usize, max_replay_event_bytes: usize) -> Self {
        Self {
            id,
            event: Some("stream-gap"),
            data: Arc::new(json!({
                "type": "stream_gap",
                "reason": "response_too_large_for_replay",
                "message": "the MCP response was delivered to the original POST caller but exceeded the replay entry byte budget and was not retained",
                "response_bytes": response_bytes,
                "max_replay_event_bytes": max_replay_event_bytes,
                "next_step": "repeat the request if the response is still required; use a bounded export for large durable result delivery",
            })),
        }
    }

    fn retained_bytes(&self) -> usize {
        let data_bytes = serde_json::to_vec(self.data.as_ref())
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX);
        self.id
            .len()
            .saturating_add(self.event.map(str::len).unwrap_or_default())
            .saturating_add(data_bytes)
            .saturating_add(32)
    }
}

impl HttpResultStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(super) fn with_limits_for_test(limits: HttpResultStoreLimits) -> Self {
        Self {
            state: Mutex::new(HttpResultStoreState::default()),
            changed: Condvar::new(),
            limits,
        }
    }

    #[cfg(test)]
    pub(super) fn ensure_session(&self, session_id: &str) {
        self.state
            .lock()
            .sessions
            .entry(session_id.to_owned())
            .or_insert_with(|| HttpResultSession::new(session_id));
    }

    #[cfg(test)]
    pub(super) fn session_count(&self) -> usize {
        self.state.lock().sessions.len()
    }

    pub(super) fn append_event_if_session(
        &self,
        session_id: &str,
        event_name: Option<&'static str>,
        data: Value,
    ) -> Option<String> {
        let mut state = self.state.lock();
        if !state.sessions.contains_key(session_id) {
            return None;
        }
        let completion_ordinal = state.next_completion_ordinal;
        state.next_completion_ordinal = state.next_completion_ordinal.saturating_add(1);
        let (next_seq, cursor_binding) = {
            let session = state
                .sessions
                .get_mut(session_id)
                .expect("session presence was checked under the same store lock");
            session.next_sequence = session.next_sequence.saturating_add(1);
            (session.next_sequence, session.cursor_binding.clone())
        };
        let id = format!("{next_seq}/{cursor_binding}");
        let event = match event_name {
            Some(event_name) => HttpBufferedEvent::named(id.clone(), event_name, data),
            None => HttpBufferedEvent::data(id.clone(), data),
        };
        let response_bytes = event.retained_bytes();
        let event = if response_bytes > self.limits.max_event_bytes {
            HttpBufferedEvent::oversized(id.clone(), response_bytes, self.limits.max_event_bytes)
        } else {
            event
        };
        let retained_bytes = event.retained_bytes();
        let session_evicted_bytes = {
            let session = state
                .sessions
                .get_mut(session_id)
                .expect("replay session was inserted under the same store lock");
            session.retained_bytes = session.retained_bytes.saturating_add(retained_bytes);
            session.events.push(HttpRetainedEvent {
                event: event.clone(),
                retained_bytes,
                completion_ordinal,
            });

            let mut evicted_bytes = 0usize;
            while session.events.len() > self.limits.max_events_per_session
                || session.retained_bytes > self.limits.max_session_bytes
            {
                let Some(evicted) = session.evict_oldest() else {
                    break;
                };
                evicted_bytes = evicted_bytes.saturating_add(evicted);
            }
            evicted_bytes
        };
        state.retained_bytes = state
            .retained_bytes
            .saturating_add(retained_bytes)
            .saturating_sub(session_evicted_bytes);
        while state.retained_bytes > self.limits.max_global_bytes {
            let oldest_session = state
                .sessions
                .iter()
                .filter_map(|(session_id, session)| {
                    session
                        .events
                        .first()
                        .map(|event| (session_id.clone(), event.completion_ordinal))
                })
                .min_by_key(|(_, ordinal)| *ordinal)
                .map(|(session_id, _)| session_id);
            let Some(oldest_session) = oldest_session else {
                break;
            };
            let session = state
                .sessions
                .get_mut(&oldest_session)
                .expect("selected replay session remains present under the store lock");
            let evicted_bytes = session
                .evict_oldest()
                .expect("selected replay session has an oldest event");
            state.retained_bytes = state.retained_bytes.saturating_sub(evicted_bytes);
        }
        drop(state);
        self.changed.notify_all();
        Some(id)
    }

    pub(super) fn append_response_if_session(
        &self,
        session_id: &str,
        data: Value,
    ) -> Option<String> {
        self.append_event_if_session(session_id, None, data)
    }

    #[cfg(test)]
    pub(super) fn append_response(&self, session_id: &str, data: Value) -> String {
        self.ensure_session(session_id);
        self.append_response_if_session(session_id, data)
            .expect("test replay session was ensured")
    }

    pub(super) fn events_after(
        &self,
        session_id: &str,
        cursor: Option<&str>,
        gap_on_expired_cursor: bool,
    ) -> Result<Vec<HttpBufferedEvent>, HttpResponse> {
        let after_seq = parse_stream_cursor(cursor)?;
        let state = self.state.lock();
        let Some(session) = state.sessions.get(session_id) else {
            return Ok(Vec::new());
        };
        validate_stream_cursor_binding(cursor, after_seq, &session.cursor_binding)?;
        let events = session.buffered_events();
        events_after_sequence(
            &events,
            session.dropped_through_sequence,
            after_seq,
            cursor,
            gap_on_expired_cursor,
            &session.cursor_binding,
        )
    }

    pub(super) fn wait_events_after(
        &self,
        session_id: &str,
        after_seq: u64,
        timeout: Duration,
    ) -> HttpResultWait {
        let mut state = self.state.lock();
        loop {
            let Some(session) = state.sessions.get(session_id) else {
                return HttpResultWait::Closed;
            };
            let events = session.buffered_events();
            let cursor = format!("{after_seq}/0");
            match events_after_sequence(
                &events,
                session.dropped_through_sequence,
                after_seq,
                Some(&cursor),
                true,
                &session.cursor_binding,
            ) {
                Ok(events) if !events.is_empty() => return HttpResultWait::Events(events),
                Ok(_) => {}
                Err(_) => return HttpResultWait::Closed,
            }
            let wait = self.changed.wait_for(&mut state, timeout);
            if wait.timed_out() {
                return HttpResultWait::Timeout;
            }
        }
    }

    pub(super) fn remove_session(&self, session_id: &str) {
        let mut state = self.state.lock();
        let removed = state.sessions.remove(session_id);
        if let Some(session) = &removed {
            state.retained_bytes = state.retained_bytes.saturating_sub(session.retained_bytes);
        }
        drop(state);
        if removed.is_some() {
            self.changed.notify_all();
        }
    }

    pub(super) fn close_all(&self) {
        let mut state = self.state.lock();
        if !state.sessions.is_empty() {
            state.sessions.clear();
            state.retained_bytes = 0;
            drop(state);
            self.changed.notify_all();
        }
    }

    #[cfg(test)]
    pub(super) fn retained_bytes_for_test(&self) -> (usize, Vec<(String, usize)>) {
        let state = self.state.lock();
        let mut sessions = state
            .sessions
            .iter()
            .map(|(session_id, session)| (session_id.clone(), session.retained_bytes))
            .collect::<Vec<_>>();
        sessions.sort_by(|a, b| a.0.cmp(&b.0));
        (state.retained_bytes, sessions)
    }
}

pub(super) enum HttpResultWait {
    Events(Vec<HttpBufferedEvent>),
    Closed,
    Timeout,
}
