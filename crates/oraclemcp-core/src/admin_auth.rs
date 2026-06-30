//! WebAuthn admin authentication (plan §7.6; bead P3-6 / oracle-qmwz.4.6,
//! sub-feature 4, OPTIONAL). Gates **server administration** (config/operator
//! actions) behind a FIDO2/WebAuthn credential — distinct from the **agent
//! step-up gate**, which stays in-band (§5.10) and is NOT replaced by this.
//!
//! This module owns the admin POLICY: an allowlist of registered credential ids
//! and the challenge→assertion binding. The cryptographic assertion verification
//! (FIDO2 signature over the challenge) plugs in via [`AdminAssertionVerifier`]
//! so the heavy WebAuthn crypto lives at the edge and the policy is unit-tested.

use oraclemcp_audit::AuditSubject;

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

/// Binary operator-authority policy for the HTTP operator API.
///
/// D17 deliberately keeps this above ordinary MCP subjects: a request is an
/// operator only when the server can derive that authority from local ownership
/// or from an explicit config allow-list. Tool arguments never participate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorAuthorityPolicy {
    /// Permit the local process owner on loopback requests when no authenticated
    /// principal is present. This is the single-operator local default.
    pub allow_loopback_owner: bool,
    /// Stable subject recorded for the local loopback owner in audit entries.
    pub local_owner_stable_id: String,
    /// Explicit server-derived principal keys allowed to act as operator, e.g.
    /// `oauth:<stable-hash>` or `mtls:<certificate-fingerprint>`.
    pub allowed_subjects: Vec<String>,
}

impl Default for OperatorAuthorityPolicy {
    fn default() -> Self {
        Self {
            allow_loopback_owner: true,
            local_owner_stable_id: "process-owner".to_owned(),
            allowed_subjects: Vec::new(),
        }
    }
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

impl OperatorAuthorityPolicy {
    /// Resolve the operator audit subject for this request when the request is
    /// authorized. Returns `None` when the request is only a regular scoped
    /// principal or a non-loopback unauthenticated caller.
    #[must_use]
    pub fn authorize(
        &self,
        principal_key: Option<&str>,
        peer_is_loopback: bool,
    ) -> Option<AuditSubject> {
        if let Some(principal_key) = principal_key {
            return self
                .allowed_subjects
                .iter()
                .any(|allowed| allowed == principal_key)
                .then(|| audit_subject_from_principal_key(principal_key));
        }
        (self.allow_loopback_owner && peer_is_loopback).then(|| {
            AuditSubject::new("local-owner", self.local_owner_stable_id.clone())
                .with_authn_method("loopback")
        })
    }
}

/// Convert a server-derived principal key into the structured audit Subject.
#[must_use]
pub fn audit_subject_from_principal_key(principal_key: &str) -> AuditSubject {
    if principal_key == "anonymous-http" {
        return AuditSubject::new("anonymous-http", "server-derived").with_authn_method("none");
    }
    let (kind, stable_id) = principal_key
        .split_once(':')
        .filter(|(kind, stable_id)| !kind.is_empty() && !stable_id.is_empty())
        .unwrap_or(("principal", principal_key));
    let authn_method = match kind {
        "oauth" => "oauth",
        "mtls" | "cert" => "mtls",
        "process" => "process",
        _ => "server",
    };
    AuditSubject::new(kind, stable_id).with_authn_method(authn_method)
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

    #[test]
    fn operator_policy_allows_only_configured_subjects_or_loopback_owner() {
        let policy = OperatorAuthorityPolicy {
            allow_loopback_owner: true,
            local_owner_stable_id: "alice".to_owned(),
            allowed_subjects: vec!["oauth:subject-hash".to_owned()],
        };

        let subject = policy
            .authorize(Some("oauth:subject-hash"), false)
            .expect("explicit subject is operator");
        assert_eq!(
            subject,
            AuditSubject::new("oauth", "subject-hash").with_authn_method("oauth")
        );
        assert!(
            policy
                .authorize(Some("oauth:regular-subject"), true)
                .is_none(),
            "a scoped principal on loopback is not operator unless allow-listed"
        );

        let local = policy
            .authorize(None, true)
            .expect("loopback owner is the local default");
        assert_eq!(
            local,
            AuditSubject::new("local-owner", "alice").with_authn_method("loopback")
        );
        assert!(
            policy.authorize(None, false).is_none(),
            "non-loopback anonymous caller is never the local owner"
        );
    }
}
