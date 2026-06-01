//! Vault **dynamic** Oracle credentials + zero-downtime rotation (plan §7.4;
//! bead P3-2 / oracle-qmwz.4.2). Beyond the static Vault backend (P2-5): Vault's
//! database secrets engine issues short-lived per-session credentials with a
//! lease; the server renews the lease before it expires and, when renewal is no
//! longer possible (max-TTL reached or revoked), rotates to a freshly-issued
//! credential.
//!
//! **Zero-downtime:** this layer only *decides* when to renew/rotate and supplies
//! the new credential — it never closes a connection. In-flight work finishes on
//! its existing session; new sessions pick up the new credential (the pool
//! drains + reconnects). The Vault client is injected ([`DynamicSecretsSource`])
//! so this logic is engine/transport-free and unit-testable on an injected clock.

use crate::secrets::{Secret, SecretError};

/// A dynamic Oracle credential leased from Vault, with its renewal/expiry
/// deadlines (Unix seconds) precomputed by the source.
#[derive(Debug)]
pub struct DynamicCredential {
    /// The leased username.
    pub username: String,
    /// The leased password (zeroized on drop).
    pub password: Secret,
    /// The Vault lease id (used to renew).
    pub lease_id: String,
    /// When to start renewing (typically ~2/3 of the lease TTL).
    pub renew_after_unix: i64,
    /// When the lease expires (renewal must happen before this).
    pub expire_at_unix: i64,
}

impl DynamicCredential {
    /// The action due at `now_unix`.
    #[must_use]
    pub fn action_due(&self, now_unix: i64) -> NextAction {
        if now_unix < self.renew_after_unix {
            NextAction::Reuse
        } else if now_unix < self.expire_at_unix {
            NextAction::Renew
        } else {
            NextAction::Reissue
        }
    }
}

/// What the rotator should do with the current credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextAction {
    /// Still fresh — keep using it.
    Reuse,
    /// In the renewal window — extend the lease.
    Renew,
    /// Past expiry — issue a brand-new credential.
    Reissue,
}

/// The outcome of a rotation cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationOutcome {
    /// The current credential was kept (no Vault call).
    Reused,
    /// The lease was renewed (same underlying credential, extended).
    Renewed,
    /// A fresh credential was issued (the lease could not be renewed).
    Rotated,
}

/// The decision from a rotation cycle: the outcome and, when it changed, the new
/// credential to install for *new* connections (`None` = keep the current one).
#[derive(Debug)]
pub struct RotationDecision {
    /// What happened.
    pub outcome: RotationOutcome,
    /// The new credential to install (`None` when `Reused`).
    pub new_credential: Option<DynamicCredential>,
}

/// The Vault database-secrets client (issue + renew). Injected at the edge.
pub trait DynamicSecretsSource {
    /// Issue a brand-new dynamic credential.
    fn issue(&self) -> Result<DynamicCredential, SecretError>;
    /// Renew the lease `lease_id`, returning the extended credential.
    fn renew(&self, lease_id: &str) -> Result<DynamicCredential, SecretError>;
}

/// Run one rotation cycle for `current` at `now_unix`. Renews before expiry; if
/// renewal fails (revoked / max-TTL), rotates to a fresh credential. Never fails
/// in-flight work: on `Reuse`/`Renew`/`Rotate` it always yields a usable
/// credential decision (only an issue failure with no current credential errors).
pub fn rotate_if_due(
    current: &DynamicCredential,
    source: &dyn DynamicSecretsSource,
    now_unix: i64,
) -> Result<RotationDecision, SecretError> {
    match current.action_due(now_unix) {
        NextAction::Reuse => Ok(RotationDecision {
            outcome: RotationOutcome::Reused,
            new_credential: None,
        }),
        NextAction::Renew => match source.renew(&current.lease_id) {
            Ok(renewed) => Ok(RotationDecision {
                outcome: RotationOutcome::Renewed,
                new_credential: Some(renewed),
            }),
            // Renewal failed (max-TTL / revoked) — rotate to a fresh credential
            // rather than failing; existing connections keep working until drained.
            Err(_) => {
                let fresh = source.issue()?;
                Ok(RotationDecision {
                    outcome: RotationOutcome::Rotated,
                    new_credential: Some(fresh),
                })
            }
        },
        NextAction::Reissue => {
            let fresh = source.issue()?;
            Ok(RotationDecision {
                outcome: RotationOutcome::Rotated,
                new_credential: Some(fresh),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct MockVault {
        issues: Cell<u32>,
        renews: Cell<u32>,
        renew_ok: bool,
    }
    impl MockVault {
        fn new(renew_ok: bool) -> Self {
            MockVault {
                issues: Cell::new(0),
                renews: Cell::new(0),
                renew_ok,
            }
        }
    }
    impl DynamicSecretsSource for MockVault {
        fn issue(&self) -> Result<DynamicCredential, SecretError> {
            self.issues.set(self.issues.get() + 1);
            Ok(DynamicCredential {
                username: "v_user_new".to_owned(),
                password: Secret::new("fresh-pw"),
                lease_id: "lease-new".to_owned(),
                renew_after_unix: 2000,
                expire_at_unix: 3000,
            })
        }
        fn renew(&self, _lease_id: &str) -> Result<DynamicCredential, SecretError> {
            self.renews.set(self.renews.get() + 1);
            if self.renew_ok {
                Ok(DynamicCredential {
                    username: "v_user".to_owned(),
                    password: Secret::new("renewed-pw"),
                    lease_id: "lease-1".to_owned(),
                    renew_after_unix: 1666,
                    expire_at_unix: 2000,
                })
            } else {
                Err(SecretError::NotFound(
                    "lease at max TTL / revoked".to_owned(),
                ))
            }
        }
    }

    fn cred() -> DynamicCredential {
        DynamicCredential {
            username: "v_user".to_owned(),
            password: Secret::new("pw"),
            lease_id: "lease-1".to_owned(),
            renew_after_unix: 1000,
            expire_at_unix: 1500,
        }
    }

    #[test]
    fn action_due_transitions() {
        let c = cred();
        assert_eq!(c.action_due(500), NextAction::Reuse);
        assert_eq!(c.action_due(1000), NextAction::Renew);
        assert_eq!(c.action_due(1499), NextAction::Renew);
        assert_eq!(c.action_due(1500), NextAction::Reissue);
    }

    #[test]
    fn fresh_credential_is_reused_without_a_vault_call() {
        let vault = MockVault::new(true);
        let d = rotate_if_due(&cred(), &vault, 500).expect("ok");
        assert_eq!(d.outcome, RotationOutcome::Reused);
        assert!(d.new_credential.is_none());
        assert_eq!(vault.issues.get(), 0);
        assert_eq!(vault.renews.get(), 0);
    }

    #[test]
    fn renewal_window_renews_the_lease() {
        let vault = MockVault::new(true);
        let d = rotate_if_due(&cred(), &vault, 1100).expect("ok");
        assert_eq!(d.outcome, RotationOutcome::Renewed);
        let new = d.new_credential.expect("renewed cred");
        assert_eq!(new.password.expose(), "renewed-pw");
        assert_eq!(vault.renews.get(), 1);
        assert_eq!(vault.issues.get(), 0);
    }

    #[test]
    fn failed_renewal_rotates_to_a_fresh_credential() {
        // Renew fails (max TTL) -> rotate, never fail in-flight work.
        let vault = MockVault::new(false);
        let d = rotate_if_due(&cred(), &vault, 1100).expect("ok");
        assert_eq!(d.outcome, RotationOutcome::Rotated);
        let new = d.new_credential.expect("fresh cred");
        assert_eq!(new.username, "v_user_new");
        assert_eq!(vault.renews.get(), 1);
        assert_eq!(vault.issues.get(), 1);
    }

    #[test]
    fn expired_lease_reissues() {
        let vault = MockVault::new(true);
        let d = rotate_if_due(&cred(), &vault, 2000).expect("ok");
        assert_eq!(d.outcome, RotationOutcome::Rotated);
        assert!(d.new_credential.is_some());
        assert_eq!(vault.issues.get(), 1);
        assert_eq!(
            vault.renews.get(),
            0,
            "expired lease is reissued, not renewed"
        );
    }
}
