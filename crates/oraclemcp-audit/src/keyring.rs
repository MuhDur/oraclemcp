//! Validated active-signing plus historical-verification audit keys.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::SigningKey;

/// A validated audit keyring with exactly one active signer.
///
/// Historical keys can authenticate existing records and an old head anchor,
/// but are never selected for new signatures. Key identifiers and key material
/// are unique so a rotation transition cannot be interpreted two ways.
#[derive(Clone)]
pub struct AuditKeyring {
    active: SigningKey,
    keys: Vec<SigningKey>,
}

impl AuditKeyring {
    /// Build a keyring from one active signer and historical verification keys.
    ///
    /// # Errors
    /// Rejects unsafe/empty identifiers, duplicate identifiers, and the same
    /// secret material assigned to multiple identifiers.
    pub fn new(
        active: SigningKey,
        historical: impl IntoIterator<Item = SigningKey>,
    ) -> Result<Self, AuditKeyringError> {
        validate_key_id(active.key_id())?;
        let mut ids = BTreeSet::new();
        ids.insert(active.key_id().to_owned());
        let mut keys = vec![active.clone()];
        for key in historical {
            validate_key_id(key.key_id())?;
            if !ids.insert(key.key_id().to_owned()) {
                return Err(AuditKeyringError::DuplicateKeyId(key.key_id().to_owned()));
            }
            if let Some(existing) = keys.iter().find(|existing| existing.same_material(&key)) {
                return Err(AuditKeyringError::DuplicateKeyMaterial {
                    first_id: existing.key_id().to_owned(),
                    second_id: key.key_id().to_owned(),
                });
            }
            keys.push(key);
        }
        Ok(Self { active, keys })
    }

    /// Build the common single-key keyring.
    #[must_use]
    pub fn single(active: SigningKey) -> Self {
        Self {
            keys: vec![active.clone()],
            active,
        }
    }

    /// The only key allowed to sign new records and anchors.
    #[must_use]
    pub fn active(&self) -> &SigningKey {
        &self.active
    }

    /// Every configured key, active first, for full-chain verification.
    #[must_use]
    pub fn verification_keys(&self) -> &[SigningKey] {
        &self.keys
    }

    /// Select a key by its authenticated wire identifier.
    #[must_use]
    pub fn key(&self, key_id: &str) -> Option<&SigningKey> {
        self.keys.iter().find(|key| key.key_id() == key_id)
    }

    /// Whether the keyring explicitly authorizes a transition from a
    /// historical anchor to the active signer.
    #[must_use]
    pub fn is_historical(&self, key_id: &str) -> bool {
        key_id != self.active.key_id() && self.key(key_id).is_some()
    }
}

impl std::fmt::Debug for AuditKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<_> = self.keys.iter().map(SigningKey::key_id).collect();
        f.debug_struct("AuditKeyring")
            .field("active_key_id", &self.active.key_id())
            .field("verification_key_ids", &ids)
            .field("key_material", &"***redacted***")
            .finish()
    }
}

/// Audit keyring construction failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditKeyringError {
    /// A key identifier is empty or outside the bounded safe ASCII alphabet.
    #[error("invalid audit key id")]
    InvalidKeyId,
    /// Two configured keys share one identifier.
    #[error("duplicate audit key id {0:?}")]
    DuplicateKeyId(String),
    /// The same secret bytes were ambiguously assigned to two identifiers.
    #[error("audit key material is reused under ids {first_id:?} and {second_id:?}")]
    DuplicateKeyMaterial {
        /// First identifier.
        first_id: String,
        /// Conflicting identifier.
        second_id: String,
    },
}

fn validate_key_id(key_id: &str) -> Result<(), AuditKeyringError> {
    if key_id.is_empty()
        || key_id.len() > 128
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AuditKeyringError::InvalidKeyId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str, byte: u8) -> SigningKey {
        SigningKey::new(id, vec![byte; 32]).expect("valid key")
    }

    #[test]
    fn active_is_first_and_historical_keys_are_selectable() {
        let ring = AuditKeyring::new(key("new", 1), [key("old-1", 2), key("old-2", 3)])
            .expect("valid keyring");
        assert_eq!(ring.active().key_id(), "new");
        assert_eq!(
            ring.verification_keys()
                .iter()
                .map(SigningKey::key_id)
                .collect::<Vec<_>>(),
            vec!["new", "old-1", "old-2"]
        );
        assert!(ring.is_historical("old-1"));
        assert!(!ring.is_historical("new"));
    }

    #[test]
    fn ambiguous_ids_and_material_are_rejected() {
        assert!(matches!(
            AuditKeyring::new(key("new", 1), [key("new", 2)]),
            Err(AuditKeyringError::DuplicateKeyId(id)) if id == "new"
        ));
        assert!(matches!(
            AuditKeyring::new(key("new", 1), [key("old", 1)]),
            Err(AuditKeyringError::DuplicateKeyMaterial { .. })
        ));
        assert!(matches!(
            SigningKey::new("", vec![1; 32]),
            Err(crate::SigningKeyError::InvalidKeyId)
        ));
    }

    #[test]
    fn debug_never_contains_key_material() {
        let sentinel = b"QA37_KEY_MATERIAL_MUST_STAY_HIDDEN";
        let ring = AuditKeyring::new(
            SigningKey::new("active", sentinel.to_vec()).expect("valid key"),
            [],
        )
        .expect("valid ring");
        let debug = format!("{ring:?}");
        assert!(!debug.contains(std::str::from_utf8(sentinel).unwrap()));
        assert!(debug.contains("***redacted***"));
    }
}
