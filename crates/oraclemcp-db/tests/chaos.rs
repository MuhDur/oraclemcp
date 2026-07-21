//! Chaos tests — credential rotation mid-flight must refresh rather than fail.

use oraclemcp_db::{IamToken, IamTokenSource, OciError, ensure_fresh_token};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct OneShotTokenSource {
    calls: Arc<AtomicUsize>,
}
impl IamTokenSource for OneShotTokenSource {
    fn fetch(&self) -> Result<IamToken, OciError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(IamToken {
            token: "rotated".to_owned(),
            expires_at_unix: 10_000,
        })
    }
}

#[test]
fn credential_rotation_mid_flight_refreshes_without_failure() {
    // An IAM database token nearing expiry mid-session is proactively refreshed
    // (not allowed to fail an in-flight call).
    let calls = Arc::new(AtomicUsize::new(0));
    let src = OneShotTokenSource {
        calls: Arc::clone(&calls),
    };
    let stale = IamToken {
        token: "old".to_owned(),
        expires_at_unix: 1000,
    };

    // now is within the 60s skew of expiry -> rotate.
    let fresh = ensure_fresh_token(Some(&stale), &src, 950, 60).expect("rotation succeeds");
    assert_eq!(fresh.token, "rotated");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "rotated exactly once mid-flight"
    );

    // A token with ample headroom is reused (no needless rotation).
    let reused = ensure_fresh_token(Some(&fresh), &src, 1000, 60).expect("reuse");
    assert_eq!(reused.token, "rotated");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "no extra fetch when fresh");
}
