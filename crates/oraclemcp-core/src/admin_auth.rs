//! WebAuthn admin authentication (plan §7.6; bead P3-6 / oracle-qmwz.4.6,
//! sub-feature 4, OPTIONAL). Gates **server administration** (config/operator
//! actions) behind a FIDO2/WebAuthn credential — distinct from the **agent
//! step-up gate**, which stays in-band (§5.10) and is NOT replaced by this.
//!
//! This module owns the admin POLICY: an allowlist of registered credential ids
//! and the challenge→assertion binding. The cryptographic assertion verification
//! (FIDO2 signature over the challenge) plugs in via [`AdminAssertionVerifier`]
//! so the heavy WebAuthn crypto lives at the edge and the policy is unit-tested.

/// Verifies a WebAuthn assertion: the `assertion` signs `challenge` under the
/// public key bound to `credential_id`. Implemented at the edge (e.g. webauthn-rs).
pub trait AdminAssertionVerifier {
    /// Whether the assertion is cryptographically valid for the credential + challenge.
    fn verify(&self, credential_id: &str, challenge: &str, assertion: &[u8]) -> bool;
}

/// The admin auth policy: which credential ids may administer the server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdminAuthPolicy {
    /// Allowlisted WebAuthn credential ids (registered admin authenticators).
    pub allowed_credentials: Vec<String>,
}

/// Why admin authentication failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AdminAuthError {
    /// The credential id is not on the admin allowlist.
    #[error("admin credential is not registered")]
    UnknownCredential,
    /// The WebAuthn assertion did not verify against the challenge.
    #[error("admin assertion rejected")]
    AssertionRejected,
}

impl AdminAuthPolicy {
    /// Whether `credential_id` is a registered admin credential.
    #[must_use]
    pub fn is_registered(&self, credential_id: &str) -> bool {
        self.allowed_credentials.iter().any(|c| c == credential_id)
    }

    /// Authenticate an admin: the credential MUST be allowlisted AND the
    /// assertion MUST verify against `challenge`. Fail-closed on either.
    pub fn authenticate(
        &self,
        credential_id: &str,
        challenge: &str,
        assertion: &[u8],
        verifier: &dyn AdminAssertionVerifier,
    ) -> Result<(), AdminAuthError> {
        if !self.is_registered(credential_id) {
            return Err(AdminAuthError::UnknownCredential);
        }
        if !verifier.verify(credential_id, challenge, assertion) {
            return Err(AdminAuthError::AssertionRejected);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accepts the assertion only when it equals `b"good"` (a stand-in for a
    /// valid FIDO2 signature over the challenge).
    struct StubVerifier;
    impl AdminAssertionVerifier for StubVerifier {
        fn verify(&self, _credential_id: &str, _challenge: &str, assertion: &[u8]) -> bool {
            assertion == b"good"
        }
    }

    fn policy() -> AdminAuthPolicy {
        AdminAuthPolicy {
            allowed_credentials: vec!["cred-admin-1".to_owned()],
        }
    }

    #[test]
    fn registered_credential_with_valid_assertion_authenticates() {
        assert!(
            policy()
                .authenticate("cred-admin-1", "chal-xyz", b"good", &StubVerifier)
                .is_ok()
        );
    }

    #[test]
    fn unregistered_credential_is_denied_before_crypto() {
        assert_eq!(
            policy().authenticate("cred-evil", "chal-xyz", b"good", &StubVerifier),
            Err(AdminAuthError::UnknownCredential)
        );
    }

    #[test]
    fn registered_but_bad_assertion_is_rejected() {
        assert_eq!(
            policy().authenticate("cred-admin-1", "chal-xyz", b"forged", &StubVerifier),
            Err(AdminAuthError::AssertionRejected)
        );
    }

    #[test]
    fn empty_policy_registers_no_one() {
        let p = AdminAuthPolicy::default();
        assert!(!p.is_registered("anyone"));
        assert_eq!(
            p.authenticate("anyone", "c", b"good", &StubVerifier),
            Err(AdminAuthError::UnknownCredential)
        );
    }
}
