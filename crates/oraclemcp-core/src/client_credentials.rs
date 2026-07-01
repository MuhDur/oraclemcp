//! Service-owned per-client HTTP credential store.
//!
//! These are oraclemcp access credentials for MCP clients, not Oracle database
//! credentials. Tokens are high-entropy opaque bearer values, shown once by the
//! caller that issues them, and persisted only as salted hashes in
//! `$XDG_STATE_HOME/oraclemcp/clients.json`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_auth::Secret;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::file_store::{FileStore, FileStoreError, ServiceLock, StoreId};
use crate::operator_protocol::operator_subject_id_hash;

const CLIENTS_ID: &str = "clients";
const CLIENTS_EXTENSION: &str = "json";
const CLIENT_CREDENTIAL_SCHEMA_VERSION: u16 = 1;
const CLIENT_ID_RANDOM_BYTES: usize = 16;
const TOKEN_RANDOM_BYTES: usize = 32;
const HASH_SALT_BYTES: usize = 16;
const TOKEN_PREFIX: &str = "ocmcp_";
const HASH_DOMAIN: &[u8] = b"oraclemcp.client-credential.v1\0";
const PRINCIPAL_DOMAIN: &[u8] = b"oraclemcp.client-principal.v1\0";
const MAX_LABEL_LEN: usize = 128;
const MAX_SCOPE_LEN: usize = 128;
const MAX_SCOPES: usize = 32;

/// Errors from the per-client credential store.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientCredentialError {
    /// The underlying service file-store failed.
    #[error("client credential store error: {0}")]
    Store(#[from] FileStoreError),
    /// Serialization failed before an atomic write could be issued.
    #[error("client credential serialization error: {0}")]
    Serialization(String),
    /// The persisted clients file could not be parsed or validated.
    #[error("client credential parse error: {0}")]
    Parse(String),
    /// The request carried an invalid label, scope, or id.
    #[error("invalid client credential request: {0}")]
    InvalidRequest(String),
    /// A client id was not present in the store.
    #[error("unknown client credential: {0}")]
    UnknownClient(String),
    /// The presented bearer credential did not verify.
    #[error("client credential authentication failed")]
    AuthenticationFailed,
    /// The client credential has been revoked.
    #[error("client credential is revoked: {0}")]
    Revoked(String),
    /// The OS random source failed.
    #[error("random source failed: {0}")]
    Random(String),
}

/// Request to issue a new per-client credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientCredentialIssueRequest {
    /// Human label shown in operator views.
    pub label: String,
    /// Granted OAuth-style scopes. These later lower the profile ceiling in the
    /// same way validated OAuth scopes do.
    pub scopes: Vec<String>,
}

impl ClientCredentialIssueRequest {
    /// Build a request with normalized validation deferred to the store.
    #[must_use]
    pub fn new(label: impl Into<String>, scopes: Vec<String>) -> Self {
        Self {
            label: label.into(),
            scopes,
        }
    }
}

/// One-time issuance result. `bearer` redacts in `Debug` and must not be stored
/// outside the caller's one-time handoff path.
pub struct IssuedClientCredential {
    /// Public client id.
    pub client_id: String,
    /// Stable principal key used for session ownership and audit subject
    /// derivation.
    pub principal_key: String,
    /// One-time opaque bearer token.
    pub bearer: Secret,
    /// Redacted operator view after issuance.
    pub view: ClientCredentialView,
}

impl std::fmt::Debug for IssuedClientCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedClientCredential")
            .field("client_id", &self.client_id)
            .field("principal_key", &self.principal_key)
            .field("bearer", &self.bearer)
            .field("view", &self.view)
            .finish()
    }
}

/// Authentication facts for a valid bearer token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedClientCredential {
    /// Public client id.
    pub client_id: String,
    /// Stable server-derived principal key.
    pub principal_key: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Current credential generation. Rotate/revoke increments it so a caller
    /// can force stale lane/grant cleanup.
    pub generation: u64,
}

/// Lifecycle facts returned by rotate/revoke. Callers use `principal_key` to
/// close active lanes for that client, which in turn rolls back and revokes
/// in-memory grants through the existing dispatch close path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientCredentialLifecycle {
    /// Public client id.
    pub client_id: String,
    /// Principal whose lanes must be torn down.
    pub principal_key: String,
    /// New generation after the lifecycle mutation.
    pub generation: u64,
}

/// Public credential status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientCredentialStatus {
    /// Credential can authenticate.
    Active,
    /// Credential has been revoked and cannot authenticate.
    Revoked,
}

/// Redacted operator/listing view. It intentionally contains no bearer token,
/// token prefix, salt, or hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCredentialView {
    /// Public client id.
    pub client_id: String,
    /// Human label shown in operator views.
    pub label: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Active/revoked status.
    pub status: ClientCredentialStatus,
    /// Hash of the stable principal key for display.
    pub subject_id_hash: String,
    /// Monotonic credential generation.
    pub generation: u64,
    /// Creation timestamp.
    pub created_at: String,
    /// Last successful bearer validation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    /// Last source address reported by the transport on successful validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_source_addr: Option<String>,
    /// Last rotation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<String>,
    /// Revocation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientCredentialFile {
    schema_version: u16,
    clients: Vec<ClientCredentialRecord>,
}

impl Default for ClientCredentialFile {
    fn default() -> Self {
        Self {
            schema_version: CLIENT_CREDENTIAL_SCHEMA_VERSION,
            clients: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientCredentialRecord {
    client_id: String,
    label: String,
    scopes: Vec<String>,
    credential_hash: String,
    credential_salt: String,
    generation: u64,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_used_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_source_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_at: Option<String>,
}

impl ClientCredentialRecord {
    fn view(&self) -> ClientCredentialView {
        let principal_key = principal_key_for_client_id(&self.client_id);
        ClientCredentialView {
            client_id: self.client_id.clone(),
            label: self.label.clone(),
            scopes: self.scopes.clone(),
            status: if self.revoked_at.is_some() {
                ClientCredentialStatus::Revoked
            } else {
                ClientCredentialStatus::Active
            },
            subject_id_hash: operator_subject_id_hash(&principal_key),
            generation: self.generation,
            created_at: self.created_at.clone(),
            last_used_at: self.last_used_at.clone(),
            last_source_addr: self.last_source_addr.clone(),
            rotated_at: self.rotated_at.clone(),
            revoked_at: self.revoked_at.clone(),
        }
    }

    fn lifecycle(&self) -> ClientCredentialLifecycle {
        ClientCredentialLifecycle {
            client_id: self.client_id.clone(),
            principal_key: principal_key_for_client_id(&self.client_id),
            generation: self.generation,
        }
    }
}

/// Service-owned per-client credential store.
pub struct ClientCredentialStore {
    store: FileStore,
    lock: ServiceLock,
    id: StoreId,
    path: PathBuf,
    file: Mutex<ClientCredentialFile>,
}

impl ClientCredentialStore {
    /// Open the default `$XDG_STATE_HOME/oraclemcp/clients.json` store.
    pub fn open_default() -> Result<Self, ClientCredentialError> {
        Self::open(FileStore::default_state_dir()?)
    }

    /// Open a store rooted at `root`, creating `clients.json` when absent.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ClientCredentialError> {
        let store = FileStore::open(root)?;
        let lock = store.acquire_service_lock("client-credentials")?;
        let id = StoreId::from_safe_segment(CLIENTS_ID)?;
        let path = store.root_path_for(&id, CLIENTS_EXTENSION)?;
        if !path.exists() {
            persist_file(&store, &lock, &id, &ClientCredentialFile::default())?;
        }
        let file = load_file(&path)?;
        Ok(Self {
            store,
            lock,
            id,
            path,
            file: Mutex::new(file),
        })
    }

    /// Canonical `clients.json` path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Issue a new client credential and persist only its salted hash.
    pub fn issue(
        &self,
        request: ClientCredentialIssueRequest,
    ) -> Result<IssuedClientCredential, ClientCredentialError> {
        let label = normalize_label(&request.label)?;
        let scopes = normalize_scopes(request.scopes)?;
        let mut file = self.file.lock();
        let (client_id, bearer) = loop {
            let client_id = generate_client_id()?;
            if file.clients.iter().all(|c| c.client_id != client_id) {
                let bearer = generate_bearer(&client_id)?;
                break (client_id, bearer);
            }
        };
        let salt = random_hex(HASH_SALT_BYTES)?;
        let record = ClientCredentialRecord {
            credential_hash: credential_hash(&salt, &bearer),
            credential_salt: salt,
            client_id: client_id.clone(),
            label,
            scopes,
            generation: 1,
            created_at: unix_timestamp(),
            last_used_at: None,
            last_source_addr: None,
            rotated_at: None,
            revoked_at: None,
        };
        let view = record.view();
        let principal_key = principal_key_for_client_id(&client_id);
        file.clients.push(record);
        sort_clients(&mut file.clients);
        self.persist_locked(&file)?;
        Ok(IssuedClientCredential {
            client_id,
            principal_key,
            bearer: Secret::new(bearer),
            view,
        })
    }

    /// Return redacted client metadata.
    pub fn list(&self) -> Vec<ClientCredentialView> {
        self.file.lock().clients.iter().map(|c| c.view()).collect()
    }

    /// Validate a bearer token and update last-use metadata.
    pub fn authenticate_bearer(
        &self,
        bearer: &str,
        source_addr: Option<&str>,
    ) -> Result<AuthenticatedClientCredential, ClientCredentialError> {
        let client_id = parse_bearer_client_id(bearer)?;
        let mut file = self.file.lock();
        let Some(record) = file.clients.iter_mut().find(|c| c.client_id == client_id) else {
            return Err(ClientCredentialError::AuthenticationFailed);
        };
        if record.revoked_at.is_some() {
            return Err(ClientCredentialError::Revoked(record.client_id.clone()));
        }
        if !credential_matches(&record.credential_salt, &record.credential_hash, bearer) {
            return Err(ClientCredentialError::AuthenticationFailed);
        }
        record.last_used_at = Some(unix_timestamp());
        record.last_source_addr = source_addr
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let authenticated = AuthenticatedClientCredential {
            client_id: record.client_id.clone(),
            principal_key: principal_key_for_client_id(&record.client_id),
            scopes: record.scopes.clone(),
            generation: record.generation,
        };
        self.persist_locked(&file)?;
        Ok(authenticated)
    }

    /// Rotate a client's bearer token. The old token fails immediately; callers
    /// must close sessions for the returned principal.
    pub fn rotate(
        &self,
        client_id: &str,
    ) -> Result<(IssuedClientCredential, ClientCredentialLifecycle), ClientCredentialError> {
        validate_client_id(client_id)?;
        let mut file = self.file.lock();
        let Some(record) = file.clients.iter_mut().find(|c| c.client_id == client_id) else {
            return Err(ClientCredentialError::UnknownClient(client_id.to_owned()));
        };
        if record.revoked_at.is_some() {
            return Err(ClientCredentialError::Revoked(record.client_id.clone()));
        }
        let bearer = generate_bearer(&record.client_id)?;
        let salt = random_hex(HASH_SALT_BYTES)?;
        record.credential_hash = credential_hash(&salt, &bearer);
        record.credential_salt = salt;
        record.generation = record.generation.saturating_add(1);
        record.rotated_at = Some(unix_timestamp());
        record.last_used_at = None;
        record.last_source_addr = None;
        let issued = IssuedClientCredential {
            client_id: record.client_id.clone(),
            principal_key: principal_key_for_client_id(&record.client_id),
            bearer: Secret::new(bearer),
            view: record.view(),
        };
        let lifecycle = record.lifecycle();
        self.persist_locked(&file)?;
        Ok((issued, lifecycle))
    }

    /// Revoke a client. The mutation is idempotent and returns the principal
    /// whose lanes should be closed.
    pub fn revoke(
        &self,
        client_id: &str,
    ) -> Result<ClientCredentialLifecycle, ClientCredentialError> {
        validate_client_id(client_id)?;
        let mut file = self.file.lock();
        let Some(record) = file.clients.iter_mut().find(|c| c.client_id == client_id) else {
            return Err(ClientCredentialError::UnknownClient(client_id.to_owned()));
        };
        if record.revoked_at.is_none() {
            record.revoked_at = Some(unix_timestamp());
            record.generation = record.generation.saturating_add(1);
            record.last_used_at = None;
            record.last_source_addr = None;
            let lifecycle = record.lifecycle();
            self.persist_locked(&file)?;
            return Ok(lifecycle);
        }
        Ok(record.lifecycle())
    }

    fn persist_locked(&self, file: &ClientCredentialFile) -> Result<(), ClientCredentialError> {
        persist_file(&self.store, &self.lock, &self.id, file)
    }
}

/// Whether `bearer` has the service-owned per-client token prefix.
#[must_use]
pub fn looks_like_client_bearer(bearer: &str) -> bool {
    bearer.trim_start().starts_with(TOKEN_PREFIX)
}

fn load_file(path: &Path) -> Result<ClientCredentialFile, ClientCredentialError> {
    let bytes = fs::read(path)
        .map_err(|e| ClientCredentialError::Store(FileStoreError::Io(e.to_string())))?;
    let file: ClientCredentialFile =
        serde_json::from_slice(&bytes).map_err(|e| ClientCredentialError::Parse(e.to_string()))?;
    validate_file(file)
}

fn validate_file(
    mut file: ClientCredentialFile,
) -> Result<ClientCredentialFile, ClientCredentialError> {
    if file.schema_version != CLIENT_CREDENTIAL_SCHEMA_VERSION {
        return Err(ClientCredentialError::Parse(format!(
            "unsupported schema_version {}",
            file.schema_version
        )));
    }
    let mut seen = BTreeSet::new();
    for client in &mut file.clients {
        validate_client_id(&client.client_id)?;
        client.label = normalize_label(&client.label)?;
        client.scopes = normalize_scopes(std::mem::take(&mut client.scopes))?;
        if !seen.insert(client.client_id.clone()) {
            return Err(ClientCredentialError::Parse(format!(
                "duplicate client_id {}",
                client.client_id
            )));
        }
        if !client.credential_hash.starts_with("sha256:") || client.credential_salt.len() != 32 {
            return Err(ClientCredentialError::Parse(format!(
                "invalid credential hash material for {}",
                client.client_id
            )));
        }
    }
    sort_clients(&mut file.clients);
    Ok(file)
}

fn persist_file(
    store: &FileStore,
    lock: &ServiceLock,
    id: &StoreId,
    file: &ClientCredentialFile,
) -> Result<(), ClientCredentialError> {
    let mut bytes = serde_json::to_vec_pretty(file)
        .map_err(|e| ClientCredentialError::Serialization(e.to_string()))?;
    bytes.push(b'\n');
    store.write_root_atomic(lock, id, CLIENTS_EXTENSION, &bytes)?;
    Ok(())
}

fn sort_clients(clients: &mut [ClientCredentialRecord]) {
    clients.sort_by(|a, b| a.client_id.cmp(&b.client_id));
}

fn normalize_label(label: &str) -> Result<String, ClientCredentialError> {
    let label = label.trim();
    if label.is_empty() {
        return Err(ClientCredentialError::InvalidRequest(
            "label must not be empty".to_owned(),
        ));
    }
    if label.len() > MAX_LABEL_LEN || label.chars().any(char::is_control) {
        return Err(ClientCredentialError::InvalidRequest(
            "label must be printable and at most 128 bytes".to_owned(),
        ));
    }
    Ok(label.to_owned())
}

fn normalize_scopes(scopes: Vec<String>) -> Result<Vec<String>, ClientCredentialError> {
    let mut out = BTreeSet::new();
    for scope in scopes {
        let scope = scope.trim();
        if scope.is_empty()
            || scope.len() > MAX_SCOPE_LEN
            || scope.chars().any(char::is_whitespace)
            || scope.chars().any(char::is_control)
        {
            return Err(ClientCredentialError::InvalidRequest(
                "scopes must be non-empty printable tokens without whitespace".to_owned(),
            ));
        }
        out.insert(scope.to_owned());
    }
    if out.is_empty() || out.len() > MAX_SCOPES {
        return Err(ClientCredentialError::InvalidRequest(format!(
            "scope count must be between 1 and {MAX_SCOPES}"
        )));
    }
    Ok(out.into_iter().collect())
}

fn validate_client_id(client_id: &str) -> Result<(), ClientCredentialError> {
    if !client_id.starts_with("client-")
        || client_id.len() != "client-".len() + CLIENT_ID_RANDOM_BYTES * 2
        || !client_id["client-".len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(ClientCredentialError::InvalidRequest(
            "client_id must be a generated client-<hex> id".to_owned(),
        ));
    }
    Ok(())
}

fn generate_client_id() -> Result<String, ClientCredentialError> {
    Ok(format!("client-{}", random_hex(CLIENT_ID_RANDOM_BYTES)?))
}

fn generate_bearer(client_id: &str) -> Result<String, ClientCredentialError> {
    Ok(format!(
        "{TOKEN_PREFIX}{client_id}_{}",
        random_hex(TOKEN_RANDOM_BYTES)?
    ))
}

fn parse_bearer_client_id(bearer: &str) -> Result<&str, ClientCredentialError> {
    let Some(rest) = bearer.strip_prefix(TOKEN_PREFIX) else {
        return Err(ClientCredentialError::AuthenticationFailed);
    };
    let Some((client_id, token_hex)) = rest.rsplit_once('_') else {
        return Err(ClientCredentialError::AuthenticationFailed);
    };
    if token_hex.len() != TOKEN_RANDOM_BYTES * 2
        || !token_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(ClientCredentialError::AuthenticationFailed);
    }
    validate_client_id(client_id).map_err(|_| ClientCredentialError::AuthenticationFailed)?;
    Ok(client_id)
}

fn principal_key_for_client_id(client_id: &str) -> String {
    let mut material = Vec::with_capacity(PRINCIPAL_DOMAIN.len() + client_id.len());
    material.extend_from_slice(PRINCIPAL_DOMAIN);
    material.extend_from_slice(client_id.as_bytes());
    format!("client:{}", oraclemcp_audit::sha256_hex(&material))
}

fn credential_hash(salt_hex: &str, bearer: &str) -> String {
    let mut material = Vec::with_capacity(HASH_DOMAIN.len() + salt_hex.len() + bearer.len());
    material.extend_from_slice(HASH_DOMAIN);
    material.extend_from_slice(salt_hex.as_bytes());
    material.extend_from_slice(b"\0");
    material.extend_from_slice(bearer.as_bytes());
    oraclemcp_audit::sha256_hex(&material)
}

fn credential_matches(salt_hex: &str, expected_hash: &str, bearer: &str) -> bool {
    constant_time_eq(
        credential_hash(salt_hex, bearer).as_bytes(),
        expected_hash.as_bytes(),
    )
}

fn random_hex(bytes: usize) -> Result<String, ClientCredentialError> {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).map_err(|e| ClientCredentialError::Random(e.to_string()))?;
    Ok(hex_lower(&buf))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let max = a.len().max(b.len());
    for i in 0..max {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

fn unix_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn test_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/client-credential-tests")
            .join(format!("{name}-{}-{stamp}", std::process::id()))
    }

    fn issue_read_client(store: &ClientCredentialStore) -> IssuedClientCredential {
        store
            .issue(ClientCredentialIssueRequest::new(
                "Claude Desktop",
                vec!["oracle:read".to_owned(), "oracle:read".to_owned()],
            ))
            .expect("issue client")
    }

    #[test]
    fn clients_json_is_private_and_never_contains_issued_bearer() {
        let store = ClientCredentialStore::open(test_root("private-redacted")).expect("store");
        let issued = issue_read_client(&store);
        assert_eq!(
            store.path(),
            store.store.root().join("clients.json").as_path()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                fs::metadata(store.store.root())
                    .expect("root metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(store.path())
                    .expect("clients metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let bearer = issued.bearer.expose().to_owned();
        let json = fs::read_to_string(store.path()).expect("read clients json");
        assert!(
            !json.contains(&bearer),
            "bearer token must not be persisted"
        );
        assert!(
            !serde_json::to_string(&store.list())
                .expect("list json")
                .contains(&bearer),
            "redacted list view must not contain bearer token"
        );
        assert!(
            !format!("{issued:?}").contains(&bearer),
            "Debug must redact bearer token"
        );
        assert!(json.contains("credential_hash"));
        assert!(json.contains("credential_salt"));
    }

    #[test]
    fn authenticate_rotate_and_revoke_update_lifecycle_without_storing_secret() {
        let store = ClientCredentialStore::open(test_root("lifecycle")).expect("store");
        let issued = issue_read_client(&store);
        let bearer = issued.bearer.expose().to_owned();
        let auth = store
            .authenticate_bearer(&bearer, Some("127.0.0.1:49152"))
            .expect("bearer authenticates");
        assert_eq!(auth.client_id, issued.client_id);
        assert_eq!(auth.principal_key, issued.principal_key);
        assert_eq!(auth.scopes, vec!["oracle:read"]);
        assert_eq!(auth.generation, 1);
        let used_view = store.list().remove(0);
        assert_eq!(
            used_view.last_source_addr.as_deref(),
            Some("127.0.0.1:49152")
        );
        assert!(used_view.last_used_at.is_some());

        assert!(matches!(
            store.authenticate_bearer("ocmcp_client-deadbeef_deadbeef", None),
            Err(ClientCredentialError::AuthenticationFailed)
        ));

        let (rotated, rotate_lifecycle) = store.rotate(&issued.client_id).expect("rotate");
        assert_eq!(rotate_lifecycle.client_id, issued.client_id);
        assert_eq!(rotate_lifecycle.principal_key, issued.principal_key);
        assert_eq!(rotate_lifecycle.generation, 2);
        assert!(matches!(
            store.authenticate_bearer(&bearer, None),
            Err(ClientCredentialError::AuthenticationFailed)
        ));
        let rotated_bearer = rotated.bearer.expose().to_owned();
        assert!(
            store
                .authenticate_bearer(&rotated_bearer, None)
                .expect("rotated bearer authenticates")
                .generation
                >= 2
        );

        let revoke_lifecycle = store.revoke(&issued.client_id).expect("revoke");
        assert_eq!(revoke_lifecycle.principal_key, issued.principal_key);
        assert_eq!(revoke_lifecycle.generation, 3);
        assert!(matches!(
            store.authenticate_bearer(&rotated_bearer, None),
            Err(ClientCredentialError::Revoked(_))
        ));
        let view = store.list().remove(0);
        assert_eq!(view.status, ClientCredentialStatus::Revoked);
        assert!(view.revoked_at.is_some());
        assert!(view.subject_id_hash.starts_with("subject-sha256:"));
    }

    #[test]
    fn lock_is_single_writer_and_records_survive_reopen() {
        let root = test_root("reopen");
        let client_id;
        let bearer;
        {
            let store = ClientCredentialStore::open(&root).expect("store");
            let issued = issue_read_client(&store);
            client_id = issued.client_id.clone();
            bearer = issued.bearer.expose().to_owned();
            assert!(
                matches!(
                    ClientCredentialStore::open(&root),
                    Err(ClientCredentialError::Store(FileStoreError::Locked))
                ),
                "a second writer must not acquire the service lock"
            );
        }

        let reopened = ClientCredentialStore::open(&root).expect("reopen");
        let auth = reopened
            .authenticate_bearer(&bearer, None)
            .expect("persisted bearer hash validates");
        assert_eq!(auth.client_id, client_id);
    }
}
