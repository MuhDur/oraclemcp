//! Server-initiated MCP notifications (WP-E E6): `notifications/progress` for
//! long-running operations and `notifications/tools/list_changed` for changes
//! to the served tool set.
//!
//! Two MCP notifications are server-initiated and so need an out-of-band queue
//! the transport drains, mirroring the `resources/updated` machinery in
//! [`crate::subscriptions`]:
//!
//! - **`notifications/progress`** — emitted only when the client supplied a
//!   `progressToken` (in the originating request's `params._meta.progressToken`,
//!   per the MCP spec). A long operation enqueues one or more progress updates
//!   bound to that token; the transport flushes them on the next write. Without
//!   a token, no progress is emitted (the spec makes progress opt-in).
//! - **`notifications/tools/list_changed`** — emitted when the *served* tool set
//!   changes (E6 + E5/A9): e.g. an `oracle_switch_profile` moves to a profile
//!   whose custom-tool catalog or operating ceiling changes which tools are
//!   advertised. The server advertises `tools.listChanged: true` and the client
//!   re-fetches `tools/list` on this signal.
//!
//! The hub holds fully-formed JSON-RPC notification objects (no `id`), so the
//! transport flush loop is a thin drain — identical in spirit to
//! [`crate::subscriptions::SubscriptionHub::drain_pending`].

use std::collections::{HashMap, VecDeque};

use parking_lot::Mutex;
use serde_json::{Value, json};

/// Per-owner bounded queues of server-initiated JSON-RPC notification objects
/// (E6). The transport drains one owner after handling each request and writes
/// each object on the same outbound channel.
///
/// The queue is bounded both per owner and in aggregate so clients that never
/// read cannot grow either one queue or the owner map without limit. One noisy
/// owner first evicts its own advisory progress. A previously unrepresented
/// owner may displace progress from the largest foreign producer, preventing
/// one producer from monopolizing every slot. Control signals are never
/// displaced.
pub struct NotificationHub {
    state: Mutex<NotificationState>,
    capacity: usize,
}

#[derive(Default)]
struct NotificationState {
    pending: HashMap<String, VecDeque<PendingNotification>>,
    pending_count: usize,
    tool_catalogs: HashMap<String, Value>,
    dropped: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NotificationKind {
    Progress,
    ToolsListChanged,
}

struct PendingNotification {
    kind: NotificationKind,
    value: Value,
}

/// Stable notification/session owner for the single stdio client.
pub const STDIO_NOTIFICATION_OWNER: &str = "stdio";

/// Default cap on queued, undrained notifications.
const DEFAULT_NOTIFICATION_CAPACITY: usize = 1024;

impl Default for NotificationHub {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationHub {
    /// A new, empty hub with the default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_NOTIFICATION_CAPACITY)
    }

    /// A new, empty hub with an explicit capacity (mostly for tests).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        NotificationHub {
            state: Mutex::new(NotificationState::default()),
            capacity: capacity.max(1),
        }
    }

    /// Push a fully-formed JSON-RPC notification object into one owner's queue.
    /// Duplicate catalog-change signals coalesce. When that queue is full,
    /// advisory progress is discarded before the catalog-change signal.
    fn push(&self, request_owner: &str, kind: NotificationKind, notification: Value) {
        let mut state = self.state.lock();
        if kind == NotificationKind::ToolsListChanged
            && state.pending.get(request_owner).is_some_and(|queue| {
                queue
                    .iter()
                    .any(|pending| pending.kind == NotificationKind::ToolsListChanged)
            })
        {
            return;
        }

        let owner_is_full = state
            .pending
            .get(request_owner)
            .is_some_and(|queue| queue.len() >= self.capacity);
        if owner_is_full && !drop_owner_progress(&mut state, request_owner) {
            state.dropped = state.dropped.saturating_add(1);
            return;
        }

        if state.pending_count >= self.capacity {
            let made_room = drop_owner_progress(&mut state, request_owner)
                || drop_largest_foreign_progress(&mut state, request_owner);
            if !made_room {
                state.dropped = state.dropped.saturating_add(1);
                return;
            }
        }

        state
            .pending
            .entry(request_owner.to_owned())
            .or_default()
            .push_back(PendingNotification {
                kind,
                value: notification,
            });
        state.pending_count += 1;
    }

    /// Enqueue a `notifications/progress` for `progress_token` (E6). MCP carries
    /// the float-or-int `progress`, an optional `total`, and an optional
    /// human-readable `message`. The caller only enqueues when a token was
    /// supplied; this method does not itself decide whether progress is enabled.
    pub fn enqueue_progress(
        &self,
        request_owner: &str,
        progress_token: &Value,
        progress: f64,
        total: Option<f64>,
        message: Option<&str>,
    ) {
        let mut params = json!({
            "progressToken": progress_token,
            "progress": progress,
        });
        if let (Value::Object(map), Some(total)) = (&mut params, total) {
            map.insert("total".to_owned(), json!(total));
        }
        if let (Value::Object(map), Some(message)) = (&mut params, message) {
            map.insert("message".to_owned(), Value::String(message.to_owned()));
        }
        self.push(
            request_owner,
            NotificationKind::Progress,
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": params,
            }),
        );
    }

    /// Enqueue a `notifications/tools/list_changed` (E6). Idempotent for the
    /// client (it re-fetches `tools/list`), so duplicates are harmless; callers
    /// typically enqueue exactly one after a change to the served tool set.
    pub fn enqueue_tools_list_changed(&self, request_owner: &str) {
        self.push(
            request_owner,
            NotificationKind::ToolsListChanged,
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed",
            }),
        );
    }

    /// Drain queued notification objects (the transport writes each one). A
    /// one-shot drain like the subscription hub's.
    #[must_use]
    pub fn drain(&self, request_owner: &str) -> Vec<Value> {
        let mut state = self.state.lock();
        let pending = state.pending.remove(request_owner).unwrap_or_default();
        state.pending_count = state.pending_count.saturating_sub(pending.len());
        pending
            .into_iter()
            .map(|notification| notification.value)
            .collect()
    }

    /// Whether `request_owner` has anything queued (introspection/tests).
    #[must_use]
    pub fn is_empty(&self, request_owner: &str) -> bool {
        !self
            .state
            .lock()
            .pending
            .get(request_owner)
            .is_some_and(|pending| !pending.is_empty())
    }

    /// Observe the exact served tool catalog for one MCP session. The first
    /// observation seeds the session snapshot. A later difference queues one
    /// `tools/list_changed` on the request stream that observed the change.
    pub fn observe_tool_catalog(&self, session_owner: &str, request_owner: &str, catalog: Value) {
        let changed = {
            let mut state = self.state.lock();
            match state
                .tool_catalogs
                .insert(session_owner.to_owned(), catalog.clone())
            {
                Some(previous) => previous != catalog,
                None => false,
            }
        };
        if changed {
            self.enqueue_tools_list_changed(request_owner);
        }
    }

    /// Forget catalog state for a closed MCP session.
    pub fn forget_session(&self, session_owner: &str) {
        self.state.lock().tool_catalogs.remove(session_owner);
    }

    /// Number of globally evicted notifications. Saturation is observable
    /// without exposing owners, principals, or progress tokens.
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.state.lock().dropped
    }
}

fn drop_owner_progress(state: &mut NotificationState, request_owner: &str) -> bool {
    let Some(queue) = state.pending.get_mut(request_owner) else {
        return false;
    };
    let Some(index) = queue
        .iter()
        .position(|pending| pending.kind == NotificationKind::Progress)
    else {
        return false;
    };
    queue.remove(index);
    state.pending_count = state.pending_count.saturating_sub(1);
    state.dropped = state.dropped.saturating_add(1);
    if queue.is_empty() {
        state.pending.remove(request_owner);
    }
    true
}

fn drop_largest_foreign_progress(state: &mut NotificationState, request_owner: &str) -> bool {
    let candidate = state
        .pending
        .iter()
        .filter_map(|(owner, queue)| {
            let progress_count = queue
                .iter()
                .filter(|pending| pending.kind == NotificationKind::Progress)
                .count();
            (owner.as_str() != request_owner && progress_count > 0)
                .then_some((owner, progress_count))
        })
        .max_by(|(owner_a, count_a), (owner_b, count_b)| {
            count_a.cmp(count_b).then_with(|| owner_b.cmp(owner_a))
        })
        .map(|(owner, _)| owner.clone());
    candidate.is_some_and(|owner| drop_owner_progress(state, &owner))
}

/// Extract the MCP `progressToken` from a request's `params._meta`, if present
/// (E6). MCP places it at `params._meta.progressToken`; its value is an opaque
/// string or integer the server echoes back in every `notifications/progress`.
/// Returns `None` when absent (progress is then disabled for that call).
#[must_use]
pub fn progress_token_from_params(params: Option<&Value>) -> Option<Value> {
    params
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get("progressToken"))
        .cloned()
        .filter(|token| token.is_string() || token.is_number())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_notification_carries_token_progress_total_and_message() {
        let hub = NotificationHub::new();
        let token = json!("op-1");
        hub.enqueue_progress("a", &token, 0.5, Some(1.0), Some("halfway"));
        let drained = hub.drain("a");
        assert_eq!(drained.len(), 1);
        let n = &drained[0];
        assert_eq!(n["jsonrpc"], json!("2.0"));
        assert_eq!(n["method"], json!("notifications/progress"));
        assert!(n.get("id").is_none(), "a notification has no id");
        assert_eq!(n["params"]["progressToken"], json!("op-1"));
        assert_eq!(n["params"]["progress"], json!(0.5));
        assert_eq!(n["params"]["total"], json!(1.0));
        assert_eq!(n["params"]["message"], json!("halfway"));
        // Drain is one-shot.
        assert!(hub.drain("a").is_empty());
    }

    #[test]
    fn progress_omits_absent_total_and_message() {
        let hub = NotificationHub::new();
        hub.enqueue_progress("a", &json!(7), 3.0, None, None);
        let drained = hub.drain("a");
        assert_eq!(drained[0]["params"]["progressToken"], json!(7));
        assert_eq!(drained[0]["params"]["progress"], json!(3.0));
        assert!(drained[0]["params"].get("total").is_none());
        assert!(drained[0]["params"].get("message").is_none());
    }

    #[test]
    fn tools_list_changed_is_a_paramless_notification() {
        let hub = NotificationHub::new();
        hub.enqueue_tools_list_changed("a");
        let drained = hub.drain("a");
        assert_eq!(drained.len(), 1);
        assert_eq!(
            drained[0]["method"],
            json!("notifications/tools/list_changed")
        );
        assert!(drained[0].get("id").is_none());
        assert!(drained[0].get("params").is_none());
    }

    #[test]
    fn the_queue_is_bounded_and_drops_oldest_when_full() {
        let hub = NotificationHub::with_capacity(2);
        hub.enqueue_progress("a", &json!("t"), 1.0, None, None);
        hub.enqueue_progress("a", &json!("t"), 2.0, None, None);
        hub.enqueue_progress("a", &json!("t"), 3.0, None, None);
        let drained = hub.drain("a");
        assert_eq!(drained.len(), 2, "capacity is enforced");
        // The oldest (progress 1.0) was dropped; 2.0 and 3.0 remain in order.
        assert_eq!(drained[0]["params"]["progress"], json!(2.0));
        assert_eq!(drained[1]["params"]["progress"], json!(3.0));
        assert_eq!(hub.dropped_count(), 1);
    }

    #[test]
    fn one_owners_progress_flood_cannot_evict_another_owners_event() {
        let hub = NotificationHub::with_capacity(2);
        hub.enqueue_tools_list_changed("owner-b");
        for progress in 0..16 {
            hub.enqueue_progress("owner-a", &json!("a"), progress.into(), None, None);
        }

        let owner_b = hub.drain("owner-b");
        assert_eq!(owner_b.len(), 1);
        assert_eq!(
            owner_b[0]["method"],
            json!("notifications/tools/list_changed")
        );
        let owner_a = hub.drain("owner-a");
        assert_eq!(owner_a.len(), 1, "the aggregate capacity is also enforced");
        assert_eq!(owner_a[0]["params"]["progress"], json!(15.0));
    }

    #[test]
    fn new_owner_progress_displaces_a_progress_monopolist() {
        let hub = NotificationHub::with_capacity(3);
        for progress in 1..=3 {
            hub.enqueue_progress("owner-a", &json!("a"), progress.into(), None, None);
        }

        hub.enqueue_progress("owner-b", &json!("b"), 1.0, None, None);

        let owner_a = hub.drain("owner-a");
        let owner_b = hub.drain("owner-b");
        assert_eq!(owner_a.len(), 2);
        assert_eq!(owner_b.len(), 1, "a new owner receives one progress slot");
        assert_eq!(owner_b[0]["params"]["progressToken"], json!("b"));
        assert_eq!(hub.dropped_count(), 1);
    }

    #[test]
    fn abandoned_request_owners_cannot_exceed_the_aggregate_capacity() {
        let hub = NotificationHub::with_capacity(3);
        for owner in 0..100 {
            hub.enqueue_progress(&format!("owner-{owner}"), &json!(owner), 0.0, None, None);
        }

        let state = hub.state.lock();
        assert_eq!(state.pending_count, 3);
        assert_eq!(state.pending.len(), 3);
        assert!(state.pending.values().all(|queue| !queue.is_empty()));
        assert_eq!(state.dropped, 97);
    }

    #[test]
    fn catalog_change_is_coalesced_and_protected_from_progress_pressure() {
        let hub = NotificationHub::with_capacity(2);
        hub.enqueue_progress("a", &json!("t"), 1.0, None, None);
        hub.enqueue_tools_list_changed("a");
        hub.enqueue_tools_list_changed("a");
        hub.enqueue_progress("a", &json!("t"), 2.0, None, None);
        hub.enqueue_progress("a", &json!("t"), 3.0, None, None);

        let drained = hub.drain("a");
        assert_eq!(drained.len(), 2);
        assert_eq!(
            drained
                .iter()
                .filter(|value| value["method"] == "notifications/tools/list_changed")
                .count(),
            1,
            "catalog changes coalesce and survive progress eviction"
        );
        assert_eq!(
            drained
                .iter()
                .filter(|value| value["method"] == "notifications/progress")
                .count(),
            1
        );
    }

    #[test]
    fn request_owners_cannot_cross_drain() {
        let hub = NotificationHub::new();
        hub.enqueue_progress("a", &json!("token-a"), 0.0, None, None);
        hub.enqueue_progress("b", &json!("token-b"), 0.0, None, None);
        let a = hub.drain("a");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0]["params"]["progressToken"], json!("token-a"));
        assert!(!hub.is_empty("b"));
        let b = hub.drain("b");
        assert_eq!(b[0]["params"]["progressToken"], json!("token-b"));
    }

    #[test]
    fn catalog_observation_is_session_scoped_and_change_only() {
        let hub = NotificationHub::new();
        hub.observe_tool_catalog("session-a", "request-a1", json!(["read"]));
        hub.observe_tool_catalog("session-b", "request-b1", json!(["read"]));
        assert!(hub.drain("request-a1").is_empty());
        assert!(hub.drain("request-b1").is_empty());

        hub.observe_tool_catalog("session-a", "request-a2", json!(["read", "write"]));
        assert_eq!(hub.drain("request-a2").len(), 1);
        assert!(hub.drain("request-b1").is_empty());

        hub.observe_tool_catalog("session-a", "request-a3", json!(["read", "write"]));
        assert!(hub.drain("request-a3").is_empty());
        hub.forget_session("session-a");
        hub.observe_tool_catalog("session-a", "request-a4", json!(["read"]));
        assert!(hub.drain("request-a4").is_empty());
    }

    #[test]
    fn progress_token_is_extracted_only_from_meta() {
        assert_eq!(
            progress_token_from_params(Some(&json!({ "_meta": { "progressToken": "abc" } }))),
            Some(json!("abc"))
        );
        assert_eq!(
            progress_token_from_params(Some(&json!({ "_meta": { "progressToken": 42 } }))),
            Some(json!(42))
        );
        // Absent / wrong shape => None (progress disabled).
        assert!(progress_token_from_params(Some(&json!({}))).is_none());
        assert!(progress_token_from_params(None).is_none());
        assert!(
            progress_token_from_params(Some(&json!({ "_meta": { "progressToken": [1] } })))
                .is_none()
        );
    }
}
