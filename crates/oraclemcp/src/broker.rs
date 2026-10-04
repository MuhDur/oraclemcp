//! Local broker attachment. The service-owner capability remains held for the
//! listener lifetime; each accepted stream is a separate MCP session.

use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use interprocess::TryClone;
#[cfg(unix)]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{
    Listener, ListenerNonblockingMode, ListenerOptions, Name, Stream, prelude::*,
};
use oraclemcp_auth::{SecretResolver, SystemSecretResolver, resolve_secret_with};
use oraclemcp_config::{OracleMcpConfig, read_sensitive_file};
use oraclemcp_core::file_store::{FileStoreError, StoreId};
use oraclemcp_core::{FileStore, ServiceOwner};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ATTACH_LIMIT: usize = 16 * 1024;
const ATTACH_TIMEOUT: Duration = Duration::from_secs(5);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Internal process hosting the automatically attached local broker.
#[derive(clap::Args, Debug)]
pub struct BrokerArgs {
    #[arg(long)]
    pub allow_no_auth: bool,
    #[arg(long)]
    pub strict_custom_tools: bool,
}

/// Compatibility identity checked before any MCP frame reaches a dispatcher.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerIdentity {
    pub version: String,
    pub generation: String,
    credentials: String,
}

impl std::fmt::Debug for BrokerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerIdentity")
            .field("version", &self.version)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl BrokerIdentity {
    /// Profile selection and init-token policy are session-local. Configuration,
    /// custom-tool policy and resolved database credentials bind the service.
    pub fn from_config(config: &OracleMcpConfig, auth_policy: &str) -> Result<Self, ErrorEnvelope> {
        Self::from_config_with(config, auth_policy, &SystemSecretResolver)
    }

    fn from_config_with(
        config: &OracleMcpConfig,
        auth_policy: &str,
        resolver: &dyn SecretResolver,
    ) -> Result<Self, ErrorEnvelope> {
        let mut hash = Sha256::new();
        hash.update(serde_json::to_vec(config).map_err(internal)?);
        hash.update(auth_policy.as_bytes());
        let mut credentials = Sha256::new();
        for profile in &config.profiles {
            let iam_references: Vec<String> = profile
                .oci
                .as_ref()
                .filter(|oci| oci.use_iam_token)
                .map_or_else(Vec::new, |oci| {
                    let mut references = Vec::new();
                    if oci
                        .token_file
                        .as_deref()
                        .map(str::trim)
                        .is_none_or(str::is_empty)
                        && oci.token_exec.as_ref().is_none_or(Vec::is_empty)
                    {
                        references.push(format!(
                            "env:{}",
                            oci.token_env
                                .as_deref()
                                .map(str::trim)
                                .filter(|name| !name.is_empty())
                                .unwrap_or(oraclemcp_core::IAM_TOKEN_ENV)
                        ));
                    }
                    if let Some(name) = oci
                        .token_key_env
                        .as_deref()
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                    {
                        references.push(format!("env:{name}"));
                    }
                    references
                });
            for reference in [
                profile.credential_ref.as_deref(),
                profile
                    .oci
                    .as_ref()
                    .and_then(|oci| oci.wallet_password_ref.as_deref()),
            ]
            .into_iter()
            .flatten()
            .chain(iam_references.iter().map(String::as_str))
            {
                credentials.update((reference.len() as u64).to_be_bytes());
                credentials.update(reference.as_bytes());
                match resolve_secret_with(reference, profile.protected(), resolver) {
                    Ok(secret) => {
                        credentials.update([1]);
                        credentials.update((secret.expose().len() as u64).to_be_bytes());
                        credentials.update(secret.expose().as_bytes());
                    }
                    Err(_) => credentials.update([0]),
                }
            }
        }
        Ok(Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            generation: hex_digest(&hash.finalize()),
            credentials: hex_digest(&credentials.finalize()),
        })
    }

    pub fn require_match(&self, proxy: &Self) -> Result<(), ErrorEnvelope> {
        if self.version == proxy.version && self.generation == proxy.generation {
            if self.credentials != proxy.credentials {
                return Err(ErrorEnvelope::new(
                    ErrorClass::PolicyDenied,
                    "ORACLEMCP_BROKER_CREDENTIAL_MISMATCH: this client's resolved database credentials differ from the broker's; supply the correct credentials in this client's environment",
                ));
            }
            return Ok(());
        }
        Err(ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            format!(
                "ORACLEMCP_BROKER_VERSION_MISMATCH: proxy version={} config={}; broker version={} config={}; stop the older broker or use the same binary and configuration",
                proxy.version, proxy.generation, self.version, self.generation,
            ),
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Locator {
    endpoint: String,
    pid: u32,
}

/// Proxy-selected metadata on the owner-only IPC channel. Session authentication
/// remains local to this client; credential compatibility is checked before MCP.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachRequest {
    pub identity: BrokerIdentity,
    pub profile: Option<String>,
    pub client_info: serde_json::Value,
    pub auth: oraclemcp_core::StdioAuthPolicy,
    pub http: Option<serde_json::Value>,
}

impl std::fmt::Debug for AttachRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachRequest")
            .field("identity", &self.identity)
            .field("profile", &self.profile)
            .field("http", &self.http.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachReply {
    session_id: String,
    broker_pid: u32,
    error: Option<ErrorEnvelope>,
}

/// Identity recorded from OS peer credentials, never a client assertion.
#[derive(Clone)]
pub struct PeerSession {
    pub session_id: String,
    pub peer_identity: String,
    pub client_info: serde_json::Value,
    pub profile: Option<String>,
    pub auth: oraclemcp_core::StdioAuthPolicy,
    pub http: Option<serde_json::Value>,
}

impl std::fmt::Debug for PeerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerSession")
            .field("session_id", &self.session_id)
            .field("peer_identity", &self.peer_identity)
            .field("profile", &self.profile)
            .field("http", &self.http.is_some())
            .finish_non_exhaustive()
    }
}

pub struct AttachedStream {
    pub reader: BufReader<Stream>,
    pub writer: Stream,
    pub session_id: String,
    pub broker_pid: u32,
}

/// An exclusive listener and its process-wide service-state capability.
pub struct BrokerListener {
    listener: Listener,
    owner: ServiceOwner,
    identity: BrokerIdentity,
    activity: Arc<Mutex<BrokerActivity>>,
    #[cfg(target_os = "linux")]
    _endpoint_directory: Option<std::fs::File>,
}

struct BrokerActivity {
    active: usize,
    idle_since: Instant,
}

impl BrokerActivity {
    fn is_idle_for(&self, now: Instant, timeout: Duration) -> bool {
        self.active == 0 && now.saturating_duration_since(self.idle_since) >= timeout
    }
}

struct ActiveSession(Arc<Mutex<BrokerActivity>>);

impl ActiveSession {
    fn new(activity: Arc<Mutex<BrokerActivity>>) -> Self {
        activity.lock().expect("broker activity lock").active += 1;
        Self(activity)
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        let mut activity = self.0.lock().expect("broker activity lock");
        activity.active -= 1;
        if activity.active == 0 {
            activity.idle_since = Instant::now();
        }
    }
}

fn internal(error: impl std::fmt::Display) -> ErrorEnvelope {
    ErrorEnvelope::new(ErrorClass::Internal, error.to_string())
}

fn transient(error: impl std::fmt::Display) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::Transient,
        format!("ORACLEMCP_BROKER_UNREACHABLE: {error}"),
    )
}

fn random_id() -> Result<String, ErrorEnvelope> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(internal)?;
    Ok(hex_digest(&bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn locator_path(store: &FileStore) -> Result<PathBuf, ErrorEnvelope> {
    store
        .root_path_for(
            &StoreId::from_safe_segment("broker").map_err(internal)?,
            "json",
        )
        .map_err(internal)
}

fn endpoint_name(endpoint: &str) -> io::Result<Name<'_>> {
    #[cfg(unix)]
    {
        endpoint.to_fs_name::<GenericFilePath>()
    }
    #[cfg(windows)]
    {
        endpoint.to_ns_name::<GenericNamespaced>()
    }
}

fn connect_endpoint(endpoint: &str) -> io::Result<Stream> {
    #[cfg(unix)]
    {
        interprocess::local_socket::ConnectOptions::new()
            .name(endpoint_name(endpoint)?)
            .wait_mode(interprocess::ConnectWaitMode::Timeout(ATTACH_TIMEOUT))
            .connect_sync()
    }
    #[cfg(windows)]
    {
        use interprocess::os::windows::named_pipe::{
            DuplexPipeStream, local_socket::Stream as PipeSocket, pipe_mode::Bytes,
        };
        // The local-socket wrapper currently ignores its connection wait mode
        // on Windows. Use the bounded safe pipe constructor, then retain the
        // common local-socket interface and its kernel peer-identity checks.
        let path = format!(r"\\.\pipe\{endpoint}");
        let pipe = DuplexPipeStream::<Bytes>::connect_by_path_with_wait_mode(
            path.as_str(),
            interprocess::ConnectWaitMode::Timeout(ATTACH_TIMEOUT),
        )?;
        let handle: std::os::windows::io::OwnedHandle = pipe
            .try_into()
            .map_err(|_| io::Error::other("unexpected shared broker pipe handle"))?;
        let socket = PipeSocket::try_from(handle)
            .map_err(|_| io::Error::other("broker named-pipe handle conversion failed"))?;
        Ok(Stream::from(socket))
    }
}

fn read_json_line<T: serde::de::DeserializeOwned>(
    reader: &mut impl Read,
) -> Result<T, ErrorEnvelope> {
    let mut bytes = Vec::new();
    while bytes.len() <= ATTACH_LIMIT {
        let mut byte = [0];
        if reader.read(&mut byte).map_err(transient)? == 0 {
            return Err(transient("broker closed an incomplete handshake frame"));
        }
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if bytes.len() > ATTACH_LIMIT || bytes.last() != Some(&b'\n') {
        return Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            "invalid or oversized broker attachment frame",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("invalid broker attachment: {e}"),
        )
    })
}

// Windows named pipes do not implement socket timeouts. Poll nonblocking I/O
// against one absolute deadline on every platform; partial frames cannot reset it.
struct DeadlineIo<T> {
    inner: T,
    deadline: Instant,
}

impl<T> DeadlineIo<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            deadline: Instant::now() + ATTACH_TIMEOUT,
        }
    }

    fn retry(&self, error: &io::Error) -> io::Result<()> {
        if error.kind() != io::ErrorKind::WouldBlock {
            return Err(io::Error::new(error.kind(), error.to_string()));
        }
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker handshake deadline exceeded",
            ));
        }
        std::thread::sleep(Duration::from_millis(2));
        Ok(())
    }

    fn check_deadline(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker handshake deadline exceeded",
            ));
        }
        Ok(())
    }
}

impl<T: Read> Read for DeadlineIo<T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            self.check_deadline()?;
            match self.inner.read(bytes) {
                // interprocess downgrades Windows ERROR_NO_DATA to EOF even
                // in PIPE_NOWAIT mode. During the bounded handshake an empty
                // read must wait for data; actual EOF times out as TRANSIENT.
                #[cfg(windows)]
                Ok(0) if !bytes.is_empty() => self.retry(&io::ErrorKind::WouldBlock.into())?,
                Err(error) => self.retry(&error)?,
                result => return result,
            }
        }
    }
}

impl<T: Write> Write for DeadlineIo<T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            self.check_deadline()?;
            match self.inner.write(bytes) {
                Ok(0) if !bytes.is_empty() => self.retry(&io::ErrorKind::WouldBlock.into())?,
                Err(error) => self.retry(&error)?,
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        loop {
            self.check_deadline()?;
            match self.inner.flush() {
                Err(error) => self.retry(&error)?,
                result => return result,
            }
        }
    }
}

fn write_json_line(writer: &mut impl Write, value: &impl Serialize) -> Result<(), ErrorEnvelope> {
    serde_json::to_writer(&mut *writer, value).map_err(transient)?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(transient)
}

impl BrokerListener {
    /// Acquire the existing service lock before publishing a fresh endpoint.
    /// Competing spawns lose the lock and attach to the winner; stale endpoints
    /// cannot win a new election and are never reused by a replacement broker.
    pub fn bind(store: &FileStore, identity: BrokerIdentity) -> Result<Self, ErrorEnvelope> {
        let owner = store.acquire_service_owner("broker").map_err(|e| match e {
            FileStoreError::Locked => ErrorEnvelope::new(
                ErrorClass::Transient,
                format!("ORACLEMCP_BROKER_OWNER_LOCKED: {e}"),
            ),
            other => internal(other),
        })?;
        let nonce = random_id()?;
        #[cfg(unix)]
        let endpoint = store
            .root()
            .join(format!("b-{}.sock", &nonce[..16]))
            .to_string_lossy()
            .into_owned();
        #[cfg(target_os = "linux")]
        let (endpoint, endpoint_directory) = {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::MetadataExt;
            if endpoint.len() >= 108 {
                let descriptor = rustix::fs::open(
                    store.root(),
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(internal)?;
                let directory = std::fs::File::from(descriptor);
                let held = directory.metadata().map_err(internal)?;
                let expected = std::fs::metadata(store.root()).map_err(internal)?;
                if (held.dev(), held.ino()) != (expected.dev(), expected.ino()) {
                    return Err(internal(
                        "broker state directory changed before socket bind",
                    ));
                }
                // The socket still lives in the 0700 state root. This short
                // kernel alias avoids sockaddr_un's 108-byte path limit.
                (
                    format!(
                        "/proc/{}/fd/{}/b-{}.sock",
                        std::process::id(),
                        directory.as_raw_fd(),
                        &nonce[..16]
                    ),
                    Some(directory),
                )
            } else {
                (endpoint, None)
            }
        };
        #[cfg(windows)]
        let endpoint = format!(
            "oraclemcp-{}-{}",
            hex_digest(&Sha256::digest(store.root().to_string_lossy().as_bytes())),
            nonce
        );
        let options = ListenerOptions::new()
            .name(endpoint_name(&endpoint).map_err(internal)?)
            .nonblocking(ListenerNonblockingMode::Accept);
        #[cfg(target_os = "linux")]
        let options = {
            use interprocess::os::unix::local_socket::ListenerOptionsExt;
            options.mode(0o600)
        };
        #[cfg(windows)]
        let options = {
            use interprocess::os::windows::{
                local_socket::ListenerOptionsExt, security_descriptor::SecurityDescriptor,
            };
            let descriptor =
                widestring::U16CString::from_str("D:P(A;;GA;;;OW)").map_err(internal)?;
            options.security_descriptor(
                SecurityDescriptor::deserialize(&descriptor).map_err(internal)?,
            )
        };
        let listener = options.create_sync().map_err(internal)?;
        // Darwin does not support setting the mode before bind. The verified
        // 0700 state directory protects the socket until chmod completes.
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))
                .map_err(internal)?;
        }
        let locator = Locator {
            endpoint,
            pid: std::process::id(),
        };
        store
            .write_root_atomic(
                &owner,
                &StoreId::from_safe_segment("broker").map_err(internal)?,
                "json",
                &serde_json::to_vec(&locator).map_err(internal)?,
            )
            .map_err(internal)?;
        Ok(Self {
            listener,
            owner,
            identity,
            activity: Arc::new(Mutex::new(BrokerActivity {
                active: 0,
                idle_since: Instant::now(),
            })),
            #[cfg(target_os = "linux")]
            _endpoint_directory: endpoint_directory,
        })
    }

    pub fn owner(&self) -> ServiceOwner {
        self.owner.clone()
    }

    /// Each connection runs on its own transport thread and receives an independent
    /// server. Callback completion releases the session even after panic.
    pub fn serve<F>(&self, idle_timeout: Duration, serve_session: F) -> Result<(), ErrorEnvelope>
    where
        F: Fn(BufReader<Stream>, Stream, PeerSession) -> Result<(), ErrorEnvelope>
            + Send
            + Sync
            + 'static,
    {
        let serve_session = Arc::new(serve_session);
        self.activity
            .lock()
            .expect("broker activity lock")
            .idle_since = Instant::now();
        loop {
            match self.listener.accept() {
                Ok(stream) => {
                    let active = ActiveSession::new(Arc::clone(&self.activity));
                    let callback = Arc::clone(&serve_session);
                    let identity = self.identity.clone();
                    std::thread::spawn(move || {
                        let _active = active;
                        let result = accept_session(stream, &identity)
                            .and_then(|(reader, writer, peer)| callback(reader, writer, peer));
                        if let Err(error) = result {
                            tracing::warn!(error = %error.message, "broker session ended with an error");
                        }
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if self
                        .activity
                        .lock()
                        .expect("broker activity lock")
                        .is_idle_for(Instant::now(), idle_timeout)
                    {
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(internal(e)),
            }
        }
    }
}

fn accept_session(
    stream: Stream,
    identity: &BrokerIdentity,
) -> Result<(BufReader<Stream>, Stream, PeerSession), ErrorEnvelope> {
    stream.set_nonblocking(true).map_err(internal)?;
    let creds = stream.peer_creds().map_err(internal)?;
    #[cfg(unix)]
    let peer_identity = format!(
        "uid:{}",
        creds
            .euid()
            .ok_or_else(|| internal("missing kernel peer uid"))?
    );
    #[cfg(windows)]
    let peer_identity = format!(
        "pid:{}",
        creds
            .pid()
            .ok_or_else(|| internal("missing kernel pipe client pid"))?
    );
    let mut writer = stream.try_clone().map_err(internal)?;
    writer.set_nonblocking(true).map_err(internal)?;
    let mut reader = BufReader::new(stream);
    let request: AttachRequest = read_json_line(&mut DeadlineIo::new(&mut reader))?;
    if let Err(error) = identity.require_match(&request.identity) {
        write_json_line(
            &mut DeadlineIo::new(&mut writer),
            &AttachReply {
                session_id: String::new(),
                broker_pid: std::process::id(),
                error: Some(error.clone()),
            },
        )?;
        return Err(error);
    }
    let session_id = random_id()?;
    write_json_line(
        &mut DeadlineIo::new(&mut writer),
        &AttachReply {
            session_id: session_id.clone(),
            broker_pid: std::process::id(),
            error: None,
        },
    )?;
    reader.get_ref().set_nonblocking(false).map_err(internal)?;
    writer.set_nonblocking(false).map_err(internal)?;
    Ok((
        reader,
        writer,
        PeerSession {
            session_id,
            peer_identity,
            client_info: request.client_info,
            profile: request.profile,
            auth: request.auth,
            http: request.http,
        },
    ))
}

/// Attach to a live broker. No request is executed before compatibility matches.
pub fn attach(store: &FileStore, request: &AttachRequest) -> Result<AttachedStream, ErrorEnvelope> {
    let locator: Locator = serde_json::from_slice(
        &read_sensitive_file(&locator_path(store)?, ATTACH_LIMIT).map_err(transient)?,
    )
    .map_err(transient)?;
    #[cfg(unix)]
    if !endpoint_is_in_root(store, &locator)? {
        return Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            "broker endpoint is outside the verified state root",
        ));
    }
    let stream = connect_endpoint(&locator.endpoint).map_err(transient)?;
    let credentials = stream.peer_creds().map_err(transient)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner_uid = std::fs::metadata(store.root()).map_err(internal)?.uid();
        if credentials.euid() != Some(owner_uid) {
            return Err(ErrorEnvelope::new(
                ErrorClass::PolicyDenied,
                "broker peer uid differs from the state-root owner",
            ));
        }
    }
    #[cfg(any(target_os = "linux", windows))]
    if credentials.pid().map(i64::from) != Some(i64::from(locator.pid)) {
        return Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "broker kernel peer pid differs from the locator",
        ));
    }
    stream.set_nonblocking(true).map_err(transient)?;
    let mut writer = stream.try_clone().map_err(transient)?;
    writer.set_nonblocking(true).map_err(transient)?;
    let mut reader = BufReader::new(stream);
    write_json_line(&mut DeadlineIo::new(&mut writer), request)?;
    let reply: AttachReply = read_json_line(&mut DeadlineIo::new(&mut reader))?;
    if let Some(error) = reply.error {
        return Err(error);
    }
    if reply.broker_pid != locator.pid || reply.session_id.is_empty() {
        return Err(ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "broker locator and attachment identity disagree",
        ));
    }
    reader.get_ref().set_nonblocking(false).map_err(transient)?;
    writer.set_nonblocking(false).map_err(transient)?;
    Ok(AttachedStream {
        reader,
        writer,
        session_id: reply.session_id,
        broker_pid: reply.broker_pid,
    })
}

/// Restore only MCP initialization after broker loss. Statements and previous
/// session state are never replayed. A replacement must authenticate the cached
/// initialize request again before receiving the next client request.
pub fn reinitialize(
    connection: &mut AttachedStream,
    initialize: &[u8],
) -> Result<(), ErrorEnvelope> {
    connection
        .reader
        .get_ref()
        .set_nonblocking(true)
        .map_err(transient)?;
    connection.writer.set_nonblocking(true).map_err(transient)?;
    let request: serde_json::Value = serde_json::from_slice(initialize).map_err(transient)?;
    let result = (|| {
        let mut writer = DeadlineIo::new(&mut connection.writer);
        writer
            .write_all(initialize)
            .and_then(|()| writer.flush())
            .map_err(transient)?;
        let response: serde_json::Value =
            read_json_line(&mut DeadlineIo::new(&mut connection.reader))?;
        if response.get("error").is_some() {
            return Err(ErrorEnvelope::new(
                ErrorClass::PolicyDenied,
                "replacement broker refused the original initialize authentication",
            ));
        }
        if response.get("id") != request.get("id") || response.get("result").is_none() {
            return Err(transient(
                "replacement broker returned an invalid initialize response",
            ));
        }
        writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .and_then(|()| writer.flush())
            .map_err(transient)
    })();
    connection
        .reader
        .get_ref()
        .set_nonblocking(false)
        .map_err(transient)?;
    connection
        .writer
        .set_nonblocking(false)
        .map_err(transient)?;
    result
}

#[cfg(unix)]
fn endpoint_is_in_root(store: &FileStore, locator: &Locator) -> Result<bool, ErrorEnvelope> {
    let path = PathBuf::from(&locator.endpoint);
    if path.parent() == Some(store.root()) {
        return Ok(true);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let prefix = PathBuf::from(format!("/proc/{}/fd", locator.pid));
        let Some(parent) = path.parent() else {
            return Ok(false);
        };
        if parent.parent() != Some(prefix.as_path())
            || !parent.file_name().is_some_and(|fd| {
                fd.to_string_lossy()
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
            })
        {
            return Ok(false);
        }
        let target = std::fs::metadata(parent).map_err(transient)?;
        let root = std::fs::metadata(store.root()).map_err(internal)?;
        Ok((target.dev(), target.ino()) == (root.dev(), root.ino()))
    }
    #[cfg(not(target_os = "linux"))]
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::sync::mpsc;

    fn identity() -> BrokerIdentity {
        BrokerIdentity {
            version: "test-build".into(),
            generation: "test-config".into(),
            credentials: "test-credentials".into(),
        }
    }
    fn request() -> AttachRequest {
        AttachRequest {
            identity: identity(),
            profile: Some("synthetic".into()),
            client_info: serde_json::json!({"name":"test","version":"1"}),
            auth: oraclemcp_core::StdioAuthPolicy::Disabled,
            http: None,
        }
    }

    #[test]
    fn broker_mismatch_names_both_binary_and_configuration_generations() {
        let mut proxy = identity();
        proxy.version = "older-build".into();
        proxy.generation = "older-config".into();
        let e = identity().require_match(&proxy).unwrap_err();
        assert_eq!(e.error_class, ErrorClass::RuntimeStateRequired);
        for value in ["test-build", "test-config", "older-build", "older-config"] {
            assert!(e.message.contains(value));
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn broker_long_state_root_uses_verified_directory_handle_without_relocation() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FileStore::open(temporary.path().join("long-state-root".repeat(12))).unwrap();
        let broker = BrokerListener::bind(&store, identity()).unwrap();
        let locator: Locator =
            serde_json::from_slice(&std::fs::read(locator_path(&store).unwrap()).unwrap()).unwrap();
        assert!(
            locator
                .endpoint
                .starts_with(&format!("/proc/{}/fd/", std::process::id()))
        );
        assert!(endpoint_is_in_root(&store, &locator).unwrap());
        let listener = std::thread::spawn(move || {
            broker
                .serve(Duration::from_millis(150), |_reader, _writer, _peer| Ok(()))
                .unwrap()
        });
        let _client = attach(&store, &request()).unwrap();
        listener.join().unwrap();
    }

    #[test]
    fn broker_ipc_mismatch_refuses_before_dispatch_and_keeps_listener_usable() {
        let root = tempfile::tempdir().unwrap();
        let store = FileStore::open(root.path()).unwrap();
        let broker = BrokerListener::bind(&store, identity()).unwrap();
        let dispatched = Arc::new(AtomicUsize::new(0));
        let observed = dispatched.clone();
        let worker = std::thread::spawn(move || {
            broker
                .serve(
                    Duration::from_millis(150),
                    move |_reader, _writer, _peer| {
                        observed.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .unwrap()
        });
        let mut mismatched = request();
        mismatched.identity.version = "incompatible-binary".into();
        let error = match attach(&store, &mismatched) {
            Err(error) => error,
            Ok(_) => panic!("incompatible proxy attached"),
        };
        assert_eq!(error.error_class, ErrorClass::RuntimeStateRequired);
        assert!(
            error.message.contains("incompatible-binary") && error.message.contains("test-build")
        );
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        let _compatible = attach(&store, &request()).unwrap();
        worker.join().unwrap();
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn broker_credentials_bind_values_instead_of_environment_reference_names() {
        let mut config = OracleMcpConfig::default();
        config.profiles.push(
            serde_json::from_value(serde_json::json!({
                "name":"synthetic", "credential_ref":"env:SYNTHETIC_PASSWORD"
            }))
            .unwrap(),
        );
        let resolved = |value: Option<&'static str>| {
            let resolver = oraclemcp_auth::EnvLookupSecretResolver::new(move |_name: &str| {
                value.map(str::to_owned)
            });
            BrokerIdentity::from_config_with(&config, "same-policy", &resolver).unwrap()
        };
        let broker = resolved(Some("synthetic-correct-password"));
        assert!(
            broker
                .require_match(&resolved(Some("synthetic-correct-password")))
                .is_ok()
        );
        for proxy in [resolved(Some("synthetic-wrong-password")), resolved(None)] {
            assert_eq!(proxy.generation, broker.generation);
            let error = broker.require_match(&proxy).unwrap_err();
            assert_eq!(error.error_class, ErrorClass::PolicyDenied);
            assert!(
                error
                    .message
                    .contains("ORACLEMCP_BROKER_CREDENTIAL_MISMATCH")
            );
            assert!(!error.message.contains("synthetic-wrong-password"));
        }
        let debug = format!("{broker:?}");
        assert!(!debug.contains(&broker.credentials));
    }

    #[test]
    fn broker_ipc_credential_mismatch_refuses_before_dispatch() {
        let root = tempfile::tempdir().unwrap();
        let store = FileStore::open(root.path()).unwrap();
        let broker = BrokerListener::bind(&store, identity()).unwrap();
        let dispatched = Arc::new(AtomicUsize::new(0));
        let observed = dispatched.clone();
        let worker = std::thread::spawn(move || {
            broker
                .serve(
                    Duration::from_millis(150),
                    move |_reader, _writer, _peer| {
                        observed.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .unwrap()
        });
        let mut wrong = request();
        wrong.identity.credentials = "different-credential-values".into();
        let error = match attach(&store, &wrong) {
            Err(error) => error,
            Ok(_) => panic!("wrong credentials attached"),
        };
        assert_eq!(error.error_class, ErrorClass::PolicyDenied);
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        let _correct = attach(&store, &request()).unwrap();
        worker.join().unwrap();
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn broker_credentials_bind_wallet_and_iam_environment_values() {
        for profile in [
            serde_json::json!({"name":"synthetic","oci":{"wallet_password_ref":"env:WALLET_PASSWORD"}}),
            serde_json::json!({"name":"synthetic","oci":{"use_iam_token":true,"token_env":"IAM_TOKEN"}}),
            serde_json::json!({"name":"synthetic","oci":{"use_iam_token":true,"token_file":"synthetic-token-file","token_key_env":"IAM_PRIVATE_KEY"}}),
        ] {
            let mut config = OracleMcpConfig::default();
            config
                .profiles
                .push(serde_json::from_value(profile).unwrap());
            let identity = |value: Option<&'static str>| {
                let resolver = oraclemcp_auth::EnvLookupSecretResolver::new(move |_name: &str| {
                    value.map(str::to_owned)
                });
                BrokerIdentity::from_config_with(&config, "same-policy", &resolver).unwrap()
            };
            let broker = identity(Some("synthetic-correct-secret"));
            assert!(
                broker
                    .require_match(&identity(Some("synthetic-correct-secret")))
                    .is_ok()
            );
            for client in [identity(None), identity(Some("synthetic-wrong-secret"))] {
                assert_eq!(
                    broker.require_match(&client).unwrap_err().error_class,
                    ErrorClass::PolicyDenied
                );
            }
        }
    }

    #[test]
    fn broker_configuration_identity_includes_policy_and_profile_selection() {
        let mut config = OracleMcpConfig::default();
        let original = BrokerIdentity::from_config(&config, "policy-a").unwrap();
        assert_eq!(
            original,
            BrokerIdentity::from_config(&config, "policy-a").unwrap()
        );
        assert_ne!(
            original,
            BrokerIdentity::from_config(&config, "policy-b").unwrap()
        );
        config.default_profile = Some("changed-profile".to_owned());
        assert_ne!(
            original,
            BrokerIdentity::from_config(&config, "policy-a").unwrap()
        );
    }

    #[test]
    fn broker_rejects_oversized_attachment_before_dispatch() {
        let mut reader = BufReader::new(std::io::Cursor::new(vec![b'x'; ATTACH_LIMIT + 1]));
        let error = read_json_line::<AttachRequest>(&mut reader).unwrap_err();
        assert_eq!(error.error_class, ErrorClass::InvalidArguments);
    }

    #[test]
    fn handshake_deadline_bounds_partial_frames_and_would_block() {
        struct Blocked;
        impl Read for Blocked {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
        let mut blocked = DeadlineIo {
            inner: Blocked,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        assert_eq!(
            blocked.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        let mut partial = DeadlineIo {
            inner: io::Cursor::new(b"{\"frame\":"),
            deadline: Instant::now(),
        };
        let error = read_json_line::<serde_json::Value>(&mut partial).unwrap_err();
        assert_eq!(error.error_class, ErrorClass::Transient);
        let error = read_json_line::<AttachReply>(&mut io::Cursor::new([])).unwrap_err();
        assert_eq!(error.error_class, ErrorClass::Transient);
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Ok(0)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut full = DeadlineIo {
            inner: Full,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        assert_eq!(
            full.write_all(b"frame").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    #[cfg(windows)]
    fn named_pipe_nowait_empty_read_obeys_handshake_deadline() {
        let mut empty = DeadlineIo {
            inner: io::Cursor::new([]),
            deadline: Instant::now() + Duration::from_millis(10),
        };
        assert_eq!(
            empty.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn broker_reinitializes_only_handshake_and_rejects_unrelated_reply() {
        for correct_id in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let store = FileStore::open(root.path()).unwrap();
            let broker = BrokerListener::bind(&store, identity()).unwrap();
            let worker = std::thread::spawn(move || {
                broker.serve(Duration::from_millis(150), move |mut reader, mut writer, _| {
                    let initialize: serde_json::Value = read_json_line(&mut reader)?;
                    assert_eq!(initialize["method"], "initialize");
                    write_json_line(&mut writer, &serde_json::json!({"jsonrpc":"2.0", "id":if correct_id {7} else {8},"result":{}}))?;
                    if correct_id {
                        let notification: serde_json::Value = read_json_line(&mut reader)?;
                        assert_eq!(notification["method"], "notifications/initialized");
                    }
                    Ok(())
                }).unwrap();
            });
            let mut connection = attach(&store, &request()).unwrap();
            let restored = reinitialize(
                &mut connection,
                b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"initialize\"}\n",
            );
            if correct_id {
                restored.unwrap();
            } else {
                assert_eq!(restored.unwrap_err().error_class, ErrorClass::Transient);
            }
            drop(connection);
            worker.join().unwrap();
        }
    }

    #[test]
    fn active_session_prevents_idle_exit_and_disconnect_starts_timeout() {
        let root = tempfile::tempdir().unwrap();
        let store = FileStore::open(root.path()).unwrap();
        let broker = BrokerListener::bind(&store, identity()).unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            broker
                .serve(Duration::from_millis(150), move |mut reader, _, _| {
                    accepted_tx.send(()).unwrap();
                    let mut line = String::new();
                    reader.read_line(&mut line).map_err(internal)?;
                    Ok(())
                })
                .unwrap();
            drop(broker);
            finished_tx.send(Instant::now()).unwrap();
        });
        let client = attach(&store, &request()).unwrap();
        accepted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            finished_rx
                .recv_timeout(Duration::from_millis(350))
                .is_err(),
            "an active client must keep the broker alive beyond its idle timeout"
        );
        assert!(store.acquire_service_owner("competing-broker").is_err());
        let disconnect_started = Instant::now();
        drop(client);
        let exited_at = finished_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            exited_at.saturating_duration_since(disconnect_started) >= Duration::from_millis(150),
            "disconnect must start the full idle timeout, regardless of caller scheduling"
        );
        worker.join().unwrap();
        assert!(store.acquire_service_owner("replacement-broker").is_ok());
    }

    #[test]
    fn last_session_close_resets_stale_idle_clock_without_a_listener_poll() {
        let timeout = Duration::from_millis(150);
        let activity = Arc::new(Mutex::new(BrokerActivity {
            active: 0,
            idle_since: Instant::now() - Duration::from_secs(5),
        }));
        let first = ActiveSession::new(Arc::clone(&activity));
        let last = ActiveSession::new(Arc::clone(&activity));
        drop(first);
        assert!(
            !activity
                .lock()
                .expect("broker activity lock")
                .is_idle_for(Instant::now(), timeout)
        );
        let close_started = Instant::now();
        drop(last);
        let state = activity.lock().expect("broker activity lock");
        assert!(
            state.idle_since >= close_started,
            "record actual final close time"
        );
        assert!(!state.is_idle_for(state.idle_since + timeout / 2, timeout));
        assert!(state.is_idle_for(state.idle_since + timeout, timeout));
    }

    #[test]
    fn broker_real_ipc_five_clients_share_one_owner_with_distinct_sessions() {
        let root = tempfile::tempdir().unwrap();
        let store = FileStore::open(root.path()).unwrap();
        let broker = BrokerListener::bind(&store, identity()).unwrap();
        assert!(BrokerListener::bind(&store, identity()).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let locator: Locator =
                serde_json::from_slice(&std::fs::read(locator_path(&store).unwrap()).unwrap())
                    .unwrap();
            assert_eq!(
                std::fs::metadata(locator.endpoint)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let (seen_tx, seen_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            broker
                .serve(
                    Duration::from_millis(150),
                    move |mut reader, mut writer, peer| {
                        seen_tx.send((peer.session_id, peer.peer_identity)).unwrap();
                        let mut line = String::new();
                        reader.read_line(&mut line).map_err(internal)?;
                        writer.write_all(line.as_bytes()).map_err(internal)
                    },
                )
                .unwrap()
        });
        let mut clients = Vec::new();
        for _ in 0..5 {
            clients.push(attach(&store, &request()).unwrap());
        }
        let mut sessions = std::collections::HashSet::new();
        for client in &mut clients {
            assert!(sessions.insert(client.session_id.clone()));
            client.writer.write_all(b"real-ipc-echo\n").unwrap();
            let mut line = String::new();
            client.reader.read_line(&mut line).unwrap();
            assert_eq!(line, "real-ipc-echo\n");
        }
        for _ in 0..5 {
            let (_, peer) = seen_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(peer.starts_with(if cfg!(unix) { "uid:" } else { "pid:" }));
        }
        drop(clients);
        worker.join().unwrap();
        assert!(store.acquire_service_owner("next-broker").is_ok());
    }
}
