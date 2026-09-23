//! The signed, client-visible reference to a scoped grant.
//!
//! The client only ever holds `sgr1.<grant id>.<tag>`. The tag is a full
//! HMAC-SHA256 under the caller's per-process key over a domain that differs
//! from every other token in the server (in particular the execute-confirmation
//! token, scope `grant:execute`, which uses the tamper-token domain and a
//! 16-hex tag), bound to the grant id, the minting lane binding and the scope
//! digest. So a reference cannot be replayed from another session, lane,
//! subject or generation, after a key rotation, against a grant whose scope
//! digest differs, or as — or in place of — an execute token.

use std::fmt;

use oraclemcp_audit::{ct_eq, hmac_sha256};

use crate::exec_grant::ExecGrantBinding;

use super::{Canonical, hex};

/// The token scope of a scoped-grant reference. Distinct from the execute
/// confirmation token's `grant:execute`.
pub const SCOPED_GRANT_TOKEN_SCOPE: &str = "grant:scoped";

const REF_DOMAIN: &[u8] = b"omcp/scoped-grant/ref/v1";
const REF_PREFIX: &str = "sgr1";
const TAG_HEX_LEN: usize = 64;

/// A signed reference handed to the client in place of the raw grant id.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedGrantRef(String);

fn ref_mac(
    key: &[u8; 32],
    grant_id: &str,
    binding: &ExecGrantBinding,
    scope_digest: &[u8; 32],
) -> [u8; 32] {
    let mut message = Canonical::default();
    message
        .bytes(REF_DOMAIN)
        .str(SCOPED_GRANT_TOKEN_SCOPE)
        .str(grant_id)
        .str(&binding.session_id)
        .str(&binding.lane_id)
        .str(&binding.subject_id)
        .u64(binding.generation)
        .bytes(scope_digest);
    hmac_sha256(key, message.as_slice())
}

impl SignedGrantRef {
    /// Sign `grant_id` for `binding` and `scope_digest` under `key`.
    #[must_use]
    pub fn sign(
        key: &[u8; 32],
        grant_id: &str,
        binding: &ExecGrantBinding,
        scope_digest: &[u8; 32],
    ) -> Self {
        let tag = hex(&ref_mac(key, grant_id, binding, scope_digest));
        SignedGrantRef(format!("{REF_PREFIX}.{grant_id}.{tag}"))
    }

    /// Wrap a client-presented token for verification.
    #[must_use]
    pub fn from_client(token: impl Into<String>) -> Self {
        SignedGrantRef(token.into())
    }

    /// The token text to hand to the client.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Verify under `key` for the presenting `binding`, and the scope digest the
    /// server holds for the referenced grant. Returns the raw grant id.
    /// Fails closed on any malformed token, wrong prefix, wrong tag width or
    /// MAC mismatch; the compare is constant-time.
    #[must_use]
    pub fn verify(
        &self,
        key: &[u8; 32],
        binding: &ExecGrantBinding,
        scope_digest: &[u8; 32],
    ) -> Option<String> {
        let grant_id = self.grant_id_unverified()?;
        let (_, tag) = self.0.rsplit_once('.')?;
        let expected = hex(&ref_mac(key, grant_id, binding, scope_digest));
        ct_eq(expected.as_bytes(), tag.as_bytes()).then(|| grant_id.to_owned())
    }

    /// The grant id the token *claims*, so the server can find the grant (and
    /// its scope digest) before calling [`Self::verify`]. Never trust it
    /// without verifying.
    #[must_use]
    pub fn grant_id_unverified(&self) -> Option<&str> {
        let rest = self.0.strip_prefix(REF_PREFIX)?.strip_prefix('.')?;
        let (grant_id, tag) = rest.rsplit_once('.')?;
        let well_formed = !grant_id.is_empty()
            && !grant_id.contains('.')
            && tag.len() == TAG_HEX_LEN
            && tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        well_formed.then_some(grant_id)
    }
}

impl fmt::Debug for SignedGrantRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SignedGrantRef").field(&self.0).finish()
    }
}
