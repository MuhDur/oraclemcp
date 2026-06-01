//! MCP resource subscriptions (plan §8.5; bead P3-6 / oracle-qmwz.4.6,
//! sub-feature 2). `resources/subscribe` lets a client watch an `oracle://`
//! resource; the server emits `resources/updated` to its subscribers when the
//! resource changes (e.g. a DDL change via `DBMS_CHANGE_NOTIFICATION`). A
//! thread-safe registry of which client subscribes to which URI.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Per-URI subscriber registry. Cheap, in-process; one per server.
#[derive(Default)]
pub struct SubscriptionRegistry {
    by_uri: Mutex<HashMap<String, HashSet<String>>>,
}

impl SubscriptionRegistry {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe `client` to `uri`. Idempotent.
    pub fn subscribe(&self, client: &str, uri: &str) {
        self.by_uri
            .lock()
            .expect("poisoned")
            .entry(uri.to_owned())
            .or_default()
            .insert(client.to_owned());
    }

    /// Unsubscribe `client` from `uri`. Idempotent; drops the URI entry when its
    /// last subscriber leaves.
    pub fn unsubscribe(&self, client: &str, uri: &str) {
        let mut map = self.by_uri.lock().expect("poisoned");
        if let Some(set) = map.get_mut(uri) {
            set.remove(client);
            if set.is_empty() {
                map.remove(uri);
            }
        }
    }

    /// Drop all of `client`'s subscriptions (on disconnect).
    pub fn unsubscribe_all(&self, client: &str) {
        let mut map = self.by_uri.lock().expect("poisoned");
        map.retain(|_, set| {
            set.remove(client);
            !set.is_empty()
        });
    }

    /// The clients to notify for `uri` (sorted, deduped).
    #[must_use]
    pub fn subscribers_of(&self, uri: &str) -> Vec<String> {
        let map = self.by_uri.lock().expect("poisoned");
        let mut out: Vec<String> = map
            .get(uri)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        out.sort();
        out
    }

    /// Whether `client` is subscribed to `uri`.
    #[must_use]
    pub fn is_subscribed(&self, client: &str, uri: &str) -> bool {
        self.by_uri
            .lock()
            .expect("poisoned")
            .get(uri)
            .is_some_and(|s| s.contains(client))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "oracle://object/HR/PACKAGE/EMP_API";

    #[test]
    fn subscribe_then_notify_lists_subscribers() {
        let r = SubscriptionRegistry::new();
        r.subscribe("agent-a", URI);
        r.subscribe("agent-b", URI);
        r.subscribe("agent-a", URI); // idempotent
        assert_eq!(
            r.subscribers_of(URI),
            vec!["agent-a".to_owned(), "agent-b".to_owned()]
        );
        assert!(r.is_subscribed("agent-a", URI));
    }

    #[test]
    fn unsubscribe_removes_the_client_and_prunes_empty_uris() {
        let r = SubscriptionRegistry::new();
        r.subscribe("agent-a", URI);
        r.unsubscribe("agent-a", URI);
        assert!(!r.is_subscribed("agent-a", URI));
        assert!(r.subscribers_of(URI).is_empty());
    }

    #[test]
    fn unsubscribe_all_clears_a_disconnected_client() {
        let r = SubscriptionRegistry::new();
        r.subscribe("agent-a", URI);
        r.subscribe("agent-a", "oracle://capabilities");
        r.subscribe("agent-b", URI);
        r.unsubscribe_all("agent-a");
        assert_eq!(r.subscribers_of(URI), vec!["agent-b".to_owned()]);
        assert!(r.subscribers_of("oracle://capabilities").is_empty());
    }

    #[test]
    fn unknown_uri_has_no_subscribers() {
        let r = SubscriptionRegistry::new();
        assert!(r.subscribers_of("oracle://nope").is_empty());
    }
}
