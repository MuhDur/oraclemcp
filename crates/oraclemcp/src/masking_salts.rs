//! Private, durable state for result-masking token salts.
//!
//! A masking config's `salt_ref` is a public, auditable identifier; the HMAC
//! material lives only in this XDG state file. Serving refuses before opening a
//! connection when a configured tokenization rule lacks one exact active record.

use std::fmt;
use std::fs;
use std::path::Path;

use oraclemcp_core::{FileStore, StoreId};
use oraclemcp_db::ProfileMaskingSalt;
use serde::Deserialize;

const STATE_FILE_ID: &str = "masking-salts";
const STATE_FILE_EXTENSION: &str = "json";
const STATE_KIND: &str = "oraclemcp.masking_salts.v1";
const MAX_STATE_BYTES: u64 = 128 * 1024;
const MAX_SALT_RECORDS: usize = 256;

/// Reasons the active tokenization salt cannot be safely loaded.
///
/// Deliberately contains no profile, salt id, path, or raw material: callers
/// can report this failure without turning an unavailable secret source into an
/// egress side channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaskingSaltLoadError {
    /// The private XDG state root or state file could not be read.
    StateUnavailable,
    /// The state file is a symlink, non-regular file, or otherwise unsafe.
    UnsafeState,
    /// The state file is malformed, unsupported, or exceeds its bounded size.
    InvalidState,
    /// No single active state record exactly matches the profile and salt id.
    ActiveSaltUnavailable,
    /// The selected state record contains invalid base64url or insufficient key material.
    InvalidSaltMaterial,
}

impl fmt::Display for MaskingSaltLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::StateUnavailable => "masking salt state is unavailable",
            Self::UnsafeState => "masking salt state is unsafe",
            Self::InvalidState => "masking salt state is invalid",
            Self::ActiveSaltUnavailable => "configured active masking salt is unavailable",
            Self::InvalidSaltMaterial => "configured masking salt material is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MaskingSaltLoadError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaskingSaltState {
    kind: String,
    salts: Vec<MaskingSaltRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaskingSaltRecord {
    profile: String,
    salt_id: String,
    created_at: String,
    salt_b64: String,
    status: MaskingSaltStatus,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MaskingSaltStatus {
    Active,
    Retired,
}

/// Load the one active state-file salt for a configured profile tokenization
/// policy. The returned value carries the non-secret configured `salt_ref` as
/// its certificate/audit `salt_id`.
///
/// # Errors
///
/// Returns a generic, non-secret-bearing error when state is unavailable,
/// malformed, unsafe, or does not contain one exact active record.
pub fn load_active_profile_masking_salt(
    profile: &str,
    salt_ref: &str,
) -> Result<ProfileMaskingSalt, MaskingSaltLoadError> {
    let store = FileStore::open_default().map_err(|_| MaskingSaltLoadError::StateUnavailable)?;
    load_active_profile_masking_salt_from_store(&store, profile, salt_ref)
}

fn load_active_profile_masking_salt_from_store(
    store: &FileStore,
    profile: &str,
    salt_ref: &str,
) -> Result<ProfileMaskingSalt, MaskingSaltLoadError> {
    let path = state_path(store)?;
    let bytes = read_private_state_file(&path)?;
    let state: MaskingSaltState =
        serde_json::from_slice(&bytes).map_err(|_| MaskingSaltLoadError::InvalidState)?;
    if state.kind != STATE_KIND || state.salts.len() > MAX_SALT_RECORDS {
        return Err(MaskingSaltLoadError::InvalidState);
    }

    let mut matches = state.salts.iter().filter(|record| {
        record.status == MaskingSaltStatus::Active
            && record.profile == profile
            && record.salt_id == salt_ref
    });
    let Some(record) = matches.next() else {
        return Err(MaskingSaltLoadError::ActiveSaltUnavailable);
    };
    if matches.next().is_some() || record.created_at.trim().is_empty() {
        return Err(MaskingSaltLoadError::InvalidState);
    }

    let bytes = decode_base64url_no_pad(&record.salt_b64)
        .ok_or(MaskingSaltLoadError::InvalidSaltMaterial)?;
    ProfileMaskingSalt::new(salt_ref, bytes).map_err(|_| MaskingSaltLoadError::InvalidSaltMaterial)
}

fn decode_base64url_no_pad(value: &str) -> Option<Vec<u8>> {
    let input = value.as_bytes();
    if input.is_empty() || input.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    for chunk in input.chunks(4) {
        let a = base64url_value(*chunk.first()?)?;
        let b = base64url_value(*chunk.get(1)?)?;
        let c = match chunk.get(2).copied() {
            Some(byte) => Some(base64url_value(byte)?),
            None => None,
        };
        let d = match chunk.get(3).copied() {
            Some(byte) => Some(base64url_value(byte)?),
            None => None,
        };
        let word = (u32::from(a) << 18)
            | (u32::from(b) << 12)
            | (u32::from(c.unwrap_or(0)) << 6)
            | u32::from(d.unwrap_or(0));
        out.push((word >> 16) as u8);
        if c.is_some() {
            out.push((word >> 8) as u8);
        } else if b & 0x0f != 0 {
            return None;
        }
        if d.is_some() {
            out.push(word as u8);
        } else if let Some(c) = c
            && c & 0x03 != 0
        {
            return None;
        }
    }
    Some(out)
}

fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
fn base64url_no_pad(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let word = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((word >> 18) & 63) as usize] as char);
        out.push(ALPHA[((word >> 12) & 63) as usize] as char);
        if chunk.len() >= 2 {
            out.push(ALPHA[((word >> 6) & 63) as usize] as char);
        }
        if chunk.len() == 3 {
            out.push(ALPHA[(word & 63) as usize] as char);
        }
    }
    out
}

fn state_path(store: &FileStore) -> Result<std::path::PathBuf, MaskingSaltLoadError> {
    let id = StoreId::from_safe_segment(STATE_FILE_ID)
        .map_err(|_| MaskingSaltLoadError::InvalidState)?;
    store
        .root_path_for(&id, STATE_FILE_EXTENSION)
        .map_err(|_| MaskingSaltLoadError::InvalidState)
}

fn read_private_state_file(path: &Path) -> Result<Vec<u8>, MaskingSaltLoadError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            MaskingSaltLoadError::ActiveSaltUnavailable
        } else {
            MaskingSaltLoadError::StateUnavailable
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(MaskingSaltLoadError::UnsafeState);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(MaskingSaltLoadError::UnsafeState);
        }
    }
    if metadata.len() > MAX_STATE_BYTES {
        return Err(MaskingSaltLoadError::InvalidState);
    }
    fs::read(path).map_err(|_| MaskingSaltLoadError::StateUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    fn write_state(
        store: &FileStore,
        owner: &oraclemcp_core::ServiceOwner,
        value: serde_json::Value,
    ) {
        let id = StoreId::from_safe_segment(STATE_FILE_ID).expect("fixed state file id");
        let bytes = serde_json::to_vec(&value).expect("serialize state fixture");
        store
            .write_root_atomic(owner, &id, STATE_FILE_EXTENSION, &bytes)
            .expect("write private salt state");
    }

    #[test]
    fn active_profile_salt_loads_with_its_non_secret_configured_id() {
        let root = tempfile::tempdir().expect("temporary state root");
        let store = FileStore::open(root.path()).expect("open private state root");
        let owner = store
            .acquire_service_owner("masking-salt-test")
            .expect("own temporary state root");
        let material = base64url_no_pad(&[7_u8; 32]);
        write_state(
            &store,
            &owner,
            json!({
                "kind": STATE_KIND,
                "salts": [{
                    "profile": "prod",
                    "salt_id": "profile:prod:masking:v1",
                    "created_at": "2026-07-13T00:00:00Z",
                    "salt_b64": material,
                    "status": "active"
                }]
            }),
        );

        let salt =
            load_active_profile_masking_salt_from_store(&store, "prod", "profile:prod:masking:v1")
                .expect("matching active state salt");
        assert_eq!(salt.salt_id(), "profile:prod:masking:v1");
        assert!(!format!("{salt:?}").contains(&material));
    }

    #[test]
    fn absent_retired_or_ambiguous_state_never_selects_a_salt() {
        let root = tempfile::tempdir().expect("temporary state root");
        let store = FileStore::open(root.path()).expect("open private state root");
        let owner = store
            .acquire_service_owner("masking-salt-test")
            .expect("own temporary state root");
        let material = base64url_no_pad(&[9_u8; 32]);
        write_state(
            &store,
            &owner,
            json!({
                "kind": STATE_KIND,
                "salts": [{
                    "profile": "prod",
                    "salt_id": "profile:prod:masking:v1",
                    "created_at": "2026-07-13T00:00:00Z",
                    "salt_b64": material,
                    "status": "retired"
                }]
            }),
        );
        assert_eq!(
            load_active_profile_masking_salt_from_store(&store, "prod", "profile:prod:masking:v1"),
            Err(MaskingSaltLoadError::ActiveSaltUnavailable)
        );

        let material = base64url_no_pad(&[10_u8; 32]);
        write_state(
            &store,
            &owner,
            json!({
                "kind": STATE_KIND,
                "salts": [
                    {
                        "profile": "prod",
                        "salt_id": "profile:prod:masking:v1",
                        "created_at": "2026-07-13T00:00:00Z",
                        "salt_b64": material,
                        "status": "active"
                    },
                    {
                        "profile": "prod",
                        "salt_id": "profile:prod:masking:v1",
                        "created_at": "2026-07-13T00:00:01Z",
                        "salt_b64": material,
                        "status": "active"
                    }
                ]
            }),
        );
        assert_eq!(
            load_active_profile_masking_salt_from_store(&store, "prod", "profile:prod:masking:v1"),
            Err(MaskingSaltLoadError::InvalidState)
        );
    }

    #[test]
    fn malformed_or_short_material_is_rejected_without_exposing_it() {
        let root = tempfile::tempdir().expect("temporary state root");
        let store = FileStore::open(root.path()).expect("open private state root");
        let owner = store
            .acquire_service_owner("masking-salt-test")
            .expect("own temporary state root");
        let sentinel = "MASKING_SALT_MUST_NOT_ESCAPE";
        write_state(
            &store,
            &owner,
            json!({
                "kind": STATE_KIND,
                "salts": [{
                    "profile": "prod",
                    "salt_id": "profile:prod:masking:v1",
                    "created_at": "2026-07-13T00:00:00Z",
                    "salt_b64": sentinel,
                    "status": "active"
                }]
            }),
        );
        let error =
            load_active_profile_masking_salt_from_store(&store, "prod", "profile:prod:masking:v1")
                .expect_err("invalid base64 must fail closed");
        assert_eq!(error, MaskingSaltLoadError::InvalidSaltMaterial);
        assert!(!error.to_string().contains(sentinel));
    }
}
