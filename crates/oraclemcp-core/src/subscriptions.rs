//! MCP resource subscriptions (plan §8.5; bead P3-6 / oracle-qmwz.4.6,
//! sub-feature 2; WP-E E1). `resources/subscribe` lets a client watch an
//! `oracle://` resource; the server emits `resources/updated` to its
//! subscribers when the resource changes.
//!
//! **The change-detection fork (E1).** Oracle can push DDL/data changes via
//! `DBMS_CHANGE_NOTIFICATION` (DCN), but that requires the `CHANGE NOTIFICATION`
//! privilege, an open callback port, and driver support the thin line does not
//! have. So this server's *served* change source is a **polling fallback**: a
//! [`PollingSource`] the operator wires re-reads a resource's fingerprint on a
//! cadence and reports a change. The DCN path is a documented future source
//! ([`SubscribeSource::ChangeNotification`]) that is not wired here.
//!
//! **Capability gating (E1, hard requirement).** `resources.subscribe` is
//! advertised in the `initialize` capabilities **only** when a working change
//! source has been confirmed ([`SubscriptionHub::with_source`]). With no source
//! ([`SubscriptionHub::unsupported`], the default), `subscribe` is NOT
//! advertised and a `resources/subscribe` call fails — we never advertise a
//! subscription we cannot honor.

use std::collections::{HashMap, HashSet, VecDeque};
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

    /// Every URI with at least one subscriber (sorted). Used by the polling
    /// hub to know which resources to fingerprint.
    #[must_use]
    pub fn subscribed_uris(&self) -> Vec<String> {
        let map = self.by_uri.lock().expect("poisoned");
        let mut out: Vec<String> = map.keys().cloned().collect();
        out.sort();
        out
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

/// A polling change source (E1 fallback). The hub calls [`PollingSource::poll`]
/// for each subscribed URI to learn its current fingerprint; when the
/// fingerprint differs from the last one the hub saw, the resource is reported
/// changed and a `resources/updated` is emitted to its subscribers. The
/// fingerprint is opaque (e.g. a `LAST_DDL_TIME` hash, a row-count + checksum);
/// the hub only compares for inequality.
///
/// `poll` returns `None` when the source cannot fingerprint a URI (e.g. an
/// ephemeral resource), in which case the hub reports no change.
pub trait PollingSource: Send + Sync {
    /// The current opaque fingerprint of `uri`, or `None` if not pollable.
    fn poll(&self, uri: &str) -> Option<String>;
}

/// The confirmed change-detection source backing `resources/subscribe` (E1).
/// The capability is advertised iff this is not [`SubscribeSource::Unsupported`].
pub enum SubscribeSource {
    /// No working source — `resources/subscribe` is unsupported and unadvertised.
    Unsupported,
    /// The polling fallback: re-read resource fingerprints on a cadence.
    Polling(Box<dyn PollingSource>),
    /// Reserved for a future Oracle `DBMS_CHANGE_NOTIFICATION`-backed source.
    /// Not wired in the thin line; present so the gate has a named DCN arm.
    #[allow(dead_code)]
    ChangeNotification,
}

impl SubscribeSource {
    /// Whether this source supports subscriptions (and so the capability may be
    /// advertised).
    #[must_use]
    pub fn is_supported(&self) -> bool {
        !matches!(self, SubscribeSource::Unsupported)
    }
}

/// The subscription hub: the per-URI subscriber [`SubscriptionRegistry`], the
/// confirmed change source (the capability gate), the last-seen fingerprints
/// for the polling fallback, and a queue of pending `resources/updated`
/// notifications the transport drains.
pub struct SubscriptionHub {
    registry: SubscriptionRegistry,
    source: SubscribeSource,
    fingerprints: Mutex<HashMap<String, String>>,
    pending: Mutex<VecDeque<String>>,
}

impl Default for SubscriptionHub {
    fn default() -> Self {
        Self::unsupported()
    }
}

impl SubscriptionHub {
    /// A hub with NO change source: `resources/subscribe` is unsupported and the
    /// capability is not advertised (E1 fail-closed default).
    #[must_use]
    pub fn unsupported() -> Self {
        SubscriptionHub {
            registry: SubscriptionRegistry::new(),
            source: SubscribeSource::Unsupported,
            fingerprints: Mutex::new(HashMap::new()),
            pending: Mutex::new(VecDeque::new()),
        }
    }

    /// A hub backed by a confirmed change `source`. When the source supports
    /// subscriptions, the capability is advertised and `resources/subscribe`
    /// works.
    #[must_use]
    pub fn with_source(source: SubscribeSource) -> Self {
        SubscriptionHub {
            registry: SubscriptionRegistry::new(),
            source,
            fingerprints: Mutex::new(HashMap::new()),
            pending: Mutex::new(VecDeque::new()),
        }
    }

    /// Whether subscriptions are supported (the capability gate).
    #[must_use]
    pub fn supports_subscriptions(&self) -> bool {
        self.source.is_supported()
    }

    /// Subscribe `client` to `uri`. Seeds the baseline fingerprint from the
    /// polling source so the first change (not the first poll) fires an update.
    /// Returns `false` when subscriptions are unsupported (the caller maps that
    /// to a method/feature error).
    pub fn subscribe(&self, client: &str, uri: &str) -> bool {
        if !self.supports_subscriptions() {
            return false;
        }
        self.registry.subscribe(client, uri);
        if let SubscribeSource::Polling(source) = &self.source
            && let Some(fp) = source.poll(uri)
        {
            self.fingerprints
                .lock()
                .expect("poisoned")
                .insert(uri.to_owned(), fp);
        }
        true
    }

    /// Unsubscribe `client` from `uri`.
    pub fn unsubscribe(&self, client: &str, uri: &str) {
        self.registry.unsubscribe(client, uri);
    }

    /// Drop all of `client`'s subscriptions (on disconnect).
    pub fn unsubscribe_all(&self, client: &str) {
        self.registry.unsubscribe_all(client);
    }

    /// Poll every subscribed URI through the polling source; for each whose
    /// fingerprint changed, enqueue a `resources/updated` and return the changed
    /// URIs. A no-op (returns empty) when the source is not polling.
    pub fn poll_for_changes(&self) -> Vec<String> {
        let SubscribeSource::Polling(source) = &self.source else {
            return Vec::new();
        };
        let uris = self.registry.subscribed_uris();
        let mut changed = Vec::new();
        let mut fingerprints = self.fingerprints.lock().expect("poisoned");
        for uri in uris {
            let Some(current) = source.poll(&uri) else {
                continue;
            };
            let prior = fingerprints.get(&uri).cloned();
            if prior.as_ref() != Some(&current) {
                fingerprints.insert(uri.clone(), current);
                // Only an actual change (we had a prior fingerprint that
                // differs) fires; the very first observation just seeds.
                if prior.is_some() {
                    changed.push(uri);
                }
            }
        }
        drop(fingerprints);
        let mut pending = self.pending.lock().expect("poisoned");
        for uri in &changed {
            pending.push_back(uri.clone());
        }
        changed
    }

    /// Directly mark `uri` changed (used when an out-of-band signal — e.g. a
    /// DDL the server itself just applied — is known without polling). Enqueues
    /// a `resources/updated` for its subscribers.
    pub fn mark_changed(&self, uri: &str) {
        if self.registry.subscribers_of(uri).is_empty() {
            return;
        }
        self.pending
            .lock()
            .expect("poisoned")
            .push_back(uri.to_owned());
    }

    /// Drain queued `resources/updated` URIs (the transport turns each into a
    /// `notifications/resources/updated` JSON-RPC notification).
    pub fn drain_pending(&self) -> Vec<String> {
        let mut pending = self.pending.lock().expect("poisoned");
        pending.drain(..).collect()
    }

    /// The subscriber registry (for introspection/tests).
    #[must_use]
    pub fn registry(&self) -> &SubscriptionRegistry {
        &self.registry
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

    /// A scripted polling source whose fingerprint advances on demand, so a
    /// test can model "the watched resource changed" without a database.
    struct ScriptedSource {
        fingerprints: Mutex<HashMap<String, String>>,
    }
    impl ScriptedSource {
        fn new() -> Self {
            Self {
                fingerprints: Mutex::new(HashMap::new()),
            }
        }
        fn set(&self, uri: &str, fp: &str) {
            self.fingerprints
                .lock()
                .unwrap()
                .insert(uri.to_owned(), fp.to_owned());
        }
    }
    impl PollingSource for ScriptedSource {
        fn poll(&self, uri: &str) -> Option<String> {
            self.fingerprints.lock().unwrap().get(uri).cloned()
        }
    }

    #[test]
    fn an_unsupported_hub_does_not_advertise_or_accept_subscriptions() {
        // E1 hard requirement: with no confirmed source, the capability is off
        // and subscribe is refused.
        let hub = SubscriptionHub::unsupported();
        assert!(!hub.supports_subscriptions());
        assert!(
            !hub.subscribe("agent-a", URI),
            "subscribe refused with no source"
        );
        assert!(hub.registry().subscribers_of(URI).is_empty());
    }

    #[test]
    fn the_polling_fallback_fires_updates_only_on_an_actual_change() {
        // E1: the polling-fallback path (no DBMS_CHANGE_NOTIFICATION).
        let source = std::sync::Arc::new(ScriptedSource::new());
        source.set(URI, "fp-v1");
        let hub = SubscriptionHub::with_source(SubscribeSource::Polling(Box::new(
            PollingSourceArc(source.clone()),
        )));
        assert!(hub.supports_subscriptions());
        assert!(hub.subscribe("agent-a", URI));

        // No change yet: a poll fires nothing (the baseline was seeded on
        // subscribe).
        assert!(hub.poll_for_changes().is_empty());
        assert!(hub.drain_pending().is_empty());

        // The resource changes: the next poll detects it and enqueues an update.
        source.set(URI, "fp-v2");
        assert_eq!(hub.poll_for_changes(), vec![URI.to_owned()]);
        assert_eq!(hub.drain_pending(), vec![URI.to_owned()]);

        // Draining is one-shot.
        assert!(hub.drain_pending().is_empty());

        // A second change fires again.
        source.set(URI, "fp-v3");
        assert_eq!(hub.poll_for_changes(), vec![URI.to_owned()]);
    }

    #[test]
    fn mark_changed_only_enqueues_for_subscribed_uris() {
        let source = std::sync::Arc::new(ScriptedSource::new());
        source.set(URI, "fp");
        let hub = SubscriptionHub::with_source(SubscribeSource::Polling(Box::new(
            PollingSourceArc(source),
        )));
        // No subscriber yet: mark is a no-op.
        hub.mark_changed(URI);
        assert!(hub.drain_pending().is_empty());
        // After subscribing, an out-of-band mark enqueues an update.
        hub.subscribe("agent-a", URI);
        hub.mark_changed(URI);
        assert_eq!(hub.drain_pending(), vec![URI.to_owned()]);
    }

    /// Adapter so a test can share one `ScriptedSource` between the hub and the
    /// test body (the hub takes ownership of a `Box<dyn PollingSource>`).
    struct PollingSourceArc(std::sync::Arc<ScriptedSource>);
    impl PollingSource for PollingSourceArc {
        fn poll(&self, uri: &str) -> Option<String> {
            self.0.poll(uri)
        }
    }
}
