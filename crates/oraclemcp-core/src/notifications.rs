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

use std::collections::VecDeque;

use parking_lot::Mutex;
use serde_json::{Value, json};

/// A bounded queue of server-initiated JSON-RPC notification objects (E6). The
/// transport drains it after handling each request and writes each object on the
/// same outbound channel.
///
/// The queue is bounded so a client that never reads cannot make the server
/// accumulate unbounded progress notifications; once full, the oldest pending
/// notification is dropped (progress is advisory — losing an intermediate tick
/// is acceptable, and `tools/list_changed` is idempotent so a coalesced drop is
/// harmless).
pub struct NotificationHub {
    pending: Mutex<VecDeque<Value>>,
    capacity: usize,
}

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
            pending: Mutex::new(VecDeque::new()),
            capacity: capacity.max(1),
        }
    }

    /// Push a fully-formed JSON-RPC notification object, dropping the oldest
    /// when the queue is full (advisory delivery; see the type docs).
    fn push(&self, notification: Value) {
        let mut pending = self.pending.lock();
        while pending.len() >= self.capacity {
            pending.pop_front();
        }
        pending.push_back(notification);
    }

    /// Enqueue a `notifications/progress` for `progress_token` (E6). MCP carries
    /// the float-or-int `progress`, an optional `total`, and an optional
    /// human-readable `message`. The caller only enqueues when a token was
    /// supplied; this method does not itself decide whether progress is enabled.
    pub fn enqueue_progress(
        &self,
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
        self.push(json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": params,
        }));
    }

    /// Enqueue a `notifications/tools/list_changed` (E6). Idempotent for the
    /// client (it re-fetches `tools/list`), so duplicates are harmless; callers
    /// typically enqueue exactly one after a change to the served tool set.
    pub fn enqueue_tools_list_changed(&self) {
        self.push(json!({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
        }));
    }

    /// Drain queued notification objects (the transport writes each one). A
    /// one-shot drain like the subscription hub's.
    #[must_use]
    pub fn drain(&self) -> Vec<Value> {
        let mut pending = self.pending.lock();
        pending.drain(..).collect()
    }

    /// Whether anything is queued (introspection/tests).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.lock().is_empty()
    }
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
        hub.enqueue_progress(&token, 0.5, Some(1.0), Some("halfway"));
        let drained = hub.drain();
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
        assert!(hub.drain().is_empty());
    }

    #[test]
    fn progress_omits_absent_total_and_message() {
        let hub = NotificationHub::new();
        hub.enqueue_progress(&json!(7), 3.0, None, None);
        let drained = hub.drain();
        assert_eq!(drained[0]["params"]["progressToken"], json!(7));
        assert_eq!(drained[0]["params"]["progress"], json!(3.0));
        assert!(drained[0]["params"].get("total").is_none());
        assert!(drained[0]["params"].get("message").is_none());
    }

    #[test]
    fn tools_list_changed_is_a_paramless_notification() {
        let hub = NotificationHub::new();
        hub.enqueue_tools_list_changed();
        let drained = hub.drain();
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
        hub.enqueue_progress(&json!("t"), 1.0, None, None);
        hub.enqueue_progress(&json!("t"), 2.0, None, None);
        hub.enqueue_progress(&json!("t"), 3.0, None, None);
        let drained = hub.drain();
        assert_eq!(drained.len(), 2, "capacity is enforced");
        // The oldest (progress 1.0) was dropped; 2.0 and 3.0 remain in order.
        assert_eq!(drained[0]["params"]["progress"], json!(2.0));
        assert_eq!(drained[1]["params"]["progress"], json!(3.0));
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
