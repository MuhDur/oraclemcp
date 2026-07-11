//! Secrets backends (plan §6.5; bead P2-5). Credentials are referenced by a
//! scheme-prefixed `credential_ref` (never stored in the profile or surfaced in
//! metadata) and resolved here to a zeroizing [`Secret`]:
//!
//! - `env:VAR` — an environment variable (dev / container injection).
//! - `file:/path/to/secret` — a local secret file (one trailing line ending is stripped).
//! - `keyring:account` or `keyring:service/account` — the OS keyring.
//! - `vault:mount/path#field` — HashiCorp Vault / OpenBao KV v2 via AppRole
//!   (production; the HTTP client is feature-gated for deploy — see notes).
//! - `literal:...` — an inline value (**dev only**; default-denied under a
//!   `protected` production profile).
//!
//! End-to-end zeroize discipline: [`Secret`] wipes on drop and redacts in
//! `Debug`/logs.

use std::fs;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use command_group::{CommandGroup, GroupChild};
use thiserror::Error;
use wait_timeout::ChildExt;
use zeroize::Zeroizing;

const DEFAULT_KEYRING_SERVICE: &str = "oraclemcp";
const KEYRING_COMMAND_ENV: &str = "ORACLEMCP_KEYRING_COMMAND";
/// End-to-end wall deadline for a keyring helper process and its pipe readers.
const KEYRING_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum bytes accepted independently from keyring stdout and stderr.
const KEYRING_OUTPUT_CAP: usize = 64 * 1024;

/// A secret value that zeroes its memory on drop and never prints its contents.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wrap a secret string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Secret(Zeroizing::new(value.into()))
    }

    /// Expose the secret for use at the FFI / connect boundary. Keep the borrow
    /// as short-lived as possible.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***redacted***)")
    }
}

/// Secret-resolution failures.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretError {
    /// The secret reference had no recognized `scheme:` prefix.
    #[error("malformed secret reference (expected scheme:locator)")]
    Malformed(String),
    /// The referenced secret could not be found / read.
    #[error("secret not found for secret reference")]
    NotFound(String),
    /// A plaintext `literal:` ref was used under a production profile.
    #[error("plaintext literal credential is forbidden on a protected profile")]
    PlaintextForbidden,
    /// A backend returned bytes that were not UTF-8 text.
    #[error("secret backend `{0}` returned invalid utf-8")]
    InvalidUtf8(String),
    /// A backend command/service failed.
    #[error("secret backend `{0}` failed")]
    BackendFailure(String),
    /// A backend command and its descendants exceeded their wall deadline.
    #[error("secret backend `{0}` timed out")]
    BackendTimedOut(String),
    /// A backend command produced more output than the bounded integration
    /// protocol permits.
    #[error("secret backend `{0}` produced too much output")]
    BackendOutputTooLarge(String),
    /// The scheme needs a backend not compiled into this build.
    #[error("secrets backend not available for scheme `{0}` (feature-gated)")]
    BackendUnavailable(String),
}

/// A parsed secret reference.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretRef {
    /// The scheme (`env` / `file` / `keyring` / `vault` / `literal`).
    pub scheme: String,
    /// The scheme-specific locator.
    pub locator: String,
}

impl std::fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRef")
            .field("scheme", &self.scheme)
            .field("locator", &"<redacted>")
            .finish()
    }
}

impl SecretRef {
    /// Parse `scheme:locator`.
    pub fn parse(credential_ref: &str) -> Result<Self, SecretError> {
        match credential_ref.split_once(':') {
            Some((scheme, locator)) if !scheme.is_empty() && !locator.is_empty() => Ok(SecretRef {
                scheme: scheme.to_owned(),
                locator: locator.to_owned(),
            }),
            _ => Err(SecretError::Malformed(credential_ref.to_owned())),
        }
    }
}

/// Pluggable secret-reference resolver. Production uses [`SystemSecretResolver`];
/// tests and embedders can inject an implementation that maps the same parsed
/// references to a different backend without changing config parsing.
pub trait SecretResolver: Send + Sync {
    /// Resolve a parsed, already-policy-checked reference to a secret value.
    fn resolve(&self, reference: &SecretRef) -> Result<Secret, SecretError>;
}

/// Production resolver for local process environment, local files, and OS
/// keyring access. `vault:` remains fail-closed until a production Vault client
/// is compiled in and injected behind this seam.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSecretResolver;

impl SecretResolver for SystemSecretResolver {
    fn resolve(&self, reference: &SecretRef) -> Result<Secret, SecretError> {
        match reference.scheme.as_str() {
            "env" => std::env::var(&reference.locator)
                .ok()
                .map(Secret::new)
                .ok_or_else(|| SecretError::NotFound(reference.scheme.clone())),
            "file" => resolve_file_secret(&reference.locator),
            "keyring" => resolve_keyring_secret(&reference.locator),
            "literal" => Ok(Secret::new(reference.locator.clone())),
            // Vault / OpenBao KV v2 via AppRole — the async HTTP client (vaultrs)
            // is wired at deploy behind the `vault` feature; absent it, this is
            // explicit BackendUnavailable rather than a silent fallback to env.
            "vault" => Err(SecretError::BackendUnavailable("vault".to_owned())),
            other => Err(SecretError::BackendUnavailable(other.to_owned())),
        }
    }
}

/// Resolver with an injected environment lookup. File and keyring resolution are
/// still the system implementations; only `env:` is replaced. This preserves
/// deterministic tests without weakening the production resolver.
#[derive(Clone, Debug)]
pub struct EnvLookupSecretResolver<E> {
    env_lookup: E,
}

impl<E> EnvLookupSecretResolver<E> {
    /// Build a resolver whose `env:` scheme is backed by `env_lookup`.
    #[must_use]
    pub fn new(env_lookup: E) -> Self {
        EnvLookupSecretResolver { env_lookup }
    }
}

impl<E> SecretResolver for EnvLookupSecretResolver<E>
where
    E: for<'a> Fn(&'a str) -> Option<String> + Send + Sync,
{
    fn resolve(&self, reference: &SecretRef) -> Result<Secret, SecretError> {
        match reference.scheme.as_str() {
            "env" => (self.env_lookup)(&reference.locator)
                .map(Secret::new)
                .ok_or_else(|| SecretError::NotFound(reference.scheme.clone())),
            "file" => resolve_file_secret(&reference.locator),
            "keyring" => resolve_keyring_secret(&reference.locator),
            "literal" => Ok(Secret::new(reference.locator.clone())),
            "vault" => Err(SecretError::BackendUnavailable("vault".to_owned())),
            other => Err(SecretError::BackendUnavailable(other.to_owned())),
        }
    }
}

/// Resolve a `credential_ref` to a [`Secret`] with an injected resolver.
pub fn resolve_secret_with(
    credential_ref: &str,
    protected: bool,
    resolver: &dyn SecretResolver,
) -> Result<Secret, SecretError> {
    let parsed = SecretRef::parse(credential_ref)?;
    if parsed.scheme == "literal" && protected {
        return Err(SecretError::PlaintextForbidden);
    }
    resolver.resolve(&parsed)
}

/// Resolve a secret with an injected `env:` lookup and the system file/keyring
/// backends. This preserves the original helper shape for callers that only
/// need deterministic environment injection; use [`resolve_secret_with`] when
/// replacing the whole resolver.
pub fn resolve_secret(
    credential_ref: &str,
    protected: bool,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Result<Secret, SecretError> {
    let parsed = SecretRef::parse(credential_ref)?;
    if parsed.scheme == "literal" && protected {
        return Err(SecretError::PlaintextForbidden);
    }
    match parsed.scheme.as_str() {
        "env" => env_lookup(&parsed.locator)
            .map(Secret::new)
            .ok_or_else(|| SecretError::NotFound(parsed.scheme.clone())),
        "file" => resolve_file_secret(&parsed.locator),
        "keyring" => resolve_keyring_secret(&parsed.locator),
        "literal" => Ok(Secret::new(parsed.locator)),
        "vault" => Err(SecretError::BackendUnavailable("vault".to_owned())),
        other => Err(SecretError::BackendUnavailable(other.to_owned())),
    }
}

fn resolve_file_secret(locator: &str) -> Result<Secret, SecretError> {
    let contents =
        fs::read_to_string(locator).map_err(|_| SecretError::NotFound("file".to_owned()))?;
    Ok(Secret::new(strip_one_trailing_line_ending(contents)))
}

fn strip_one_trailing_line_ending(mut value: String) -> String {
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') || value.ends_with('\r') {
        value.truncate(value.len() - 1);
    }
    value
}

fn resolve_keyring_secret(locator: &str) -> Result<Secret, SecretError> {
    let (service, account) = parse_keyring_locator(locator)?;
    if let Ok(command) = std::env::var(KEYRING_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return run_keyring_command(&command, &[service, account]);
    }

    platform_keyring_secret(service, account)
}

fn parse_keyring_locator(locator: &str) -> Result<(&str, &str), SecretError> {
    let (service, account) = locator
        .split_once('/')
        .unwrap_or((DEFAULT_KEYRING_SERVICE, locator));
    if service.is_empty() || account.is_empty() {
        Err(SecretError::Malformed("keyring".to_owned()))
    } else {
        Ok((service, account))
    }
}

fn containment_unit_is_absent(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
    ) {
        return true;
    }
    // Unix killpg(2) reports ESRCH when the direct child was already reaped and
    // its process group has no surviving descendants. `std::io` currently
    // classifies that errno as Uncategorized, so retain the stable POSIX value.
    #[cfg(unix)]
    if error.raw_os_error() == Some(3) {
        return true;
    }
    false
}

struct CappedRead {
    bytes: Zeroizing<Vec<u8>>,
    truncated: bool,
    failed: bool,
}

fn read_capped(mut reader: impl Read, retain: bool) -> CappedRead {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut seen = 0_usize;
    let mut chunk = [0_u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => {
                return CappedRead {
                    bytes,
                    truncated: seen > KEYRING_OUTPUT_CAP,
                    failed: false,
                };
            }
            Ok(read) => {
                seen = seen.saturating_add(read);
                if retain && bytes.len() < KEYRING_OUTPUT_CAP {
                    let room = KEYRING_OUTPUT_CAP - bytes.len();
                    bytes.extend_from_slice(&chunk[..room.min(read)]);
                }
            }
            Err(_) => {
                return CappedRead {
                    bytes,
                    truncated: seen > KEYRING_OUTPUT_CAP,
                    failed: true,
                };
            }
        }
    }
}

fn receive_before<T>(
    receiver: &Receiver<T>,
    started: Instant,
    timeout: Duration,
) -> Result<T, RecvTimeoutError> {
    let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
        return Err(RecvTimeoutError::Timeout);
    };
    receiver.recv_timeout(remaining)
}

/// A keyring helper process tree held in one OS containment unit.
///
/// SAFETY: `group_spawn` creates a fresh POSIX process group on Unix and a Job
/// Object on Windows. Every post-spawn exit terminates that complete unit,
/// including successful direct-parent exits, so descendants cannot retain
/// pipes or outlive secret resolution. The direct child is always reaped and
/// `Drop` is the unwind fallback.
struct KeyringProcessTree {
    child: GroupChild,
}

impl KeyringProcessTree {
    fn spawn(command: &str, args: &[&str]) -> std::io::Result<Self> {
        let mut process = Command::new(command);
        process
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        process
            .group_spawn()
            .map(|child| KeyringProcessTree { child })
    }

    fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.inner().stdout.take()
    }

    fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.inner().stderr.take()
    }

    fn wait_direct(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.inner().wait_timeout(timeout)
    }

    fn terminate_and_reap(&mut self) -> bool {
        let kill_ok = match self.child.kill() {
            Ok(()) => true,
            Err(error) => containment_unit_is_absent(&error),
        };
        let wait_ok = self.child.inner().wait().is_ok();
        kill_ok && wait_ok
    }
}

impl Drop for KeyringProcessTree {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.inner().wait();
    }
}

struct KeyringReaders {
    stdout: JoinHandle<()>,
    stderr: JoinHandle<()>,
    stdout_rx: Receiver<CappedRead>,
    stderr_rx: Receiver<CappedRead>,
}

impl KeyringReaders {
    fn spawn(child: &mut KeyringProcessTree) -> std::io::Result<Self> {
        let stdout = child.take_stdout();
        let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
        let stdout_worker = std::thread::Builder::new()
            .name("keyring-stdout".to_owned())
            .spawn(move || {
                let output = stdout.map_or(
                    CappedRead {
                        bytes: Zeroizing::new(Vec::new()),
                        truncated: false,
                        failed: true,
                    },
                    |pipe| read_capped(pipe, true),
                );
                let _ = stdout_tx.send(output);
            })?;

        let stderr = child.take_stderr();
        let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
        let stderr_worker = match std::thread::Builder::new()
            .name("keyring-stderr".to_owned())
            .spawn(move || {
                let output = stderr.map_or(
                    CappedRead {
                        bytes: Zeroizing::new(Vec::new()),
                        truncated: false,
                        failed: true,
                    },
                    |pipe| read_capped(pipe, false),
                );
                let _ = stderr_tx.send(output);
            }) {
            Ok(worker) => worker,
            Err(error) => {
                drop(stdout_worker);
                return Err(error);
            }
        };

        Ok(KeyringReaders {
            stdout: stdout_worker,
            stderr: stderr_worker,
            stdout_rx,
            stderr_rx,
        })
    }

    fn collect(
        self,
        started: Instant,
        timeout: Duration,
    ) -> Result<(CappedRead, CappedRead), RecvTimeoutError> {
        let stdout = receive_before(&self.stdout_rx, started, timeout);
        let stderr = receive_before(&self.stderr_rx, started, timeout);
        // Receipt proves blocking I/O is complete. Dropping rather than joining
        // keeps the same end-to-end deadline while each thread returns from its
        // already-finished closure.
        drop(self.stdout);
        drop(self.stderr);
        Ok((stdout?, stderr?))
    }
}

/// Run a keyring helper under the local-command safety boundary.
///
/// The helper is invoked directly with literal argv (never through a shell),
/// stdin is closed, and one [`KEYRING_COMMAND_TIMEOUT`] deadline covers the
/// direct process plus both pipe readers. The complete POSIX process group or
/// Windows Job Object is terminated on every exit, including direct-child
/// success. Stdout and stderr are independently limited to
/// [`KEYRING_OUTPUT_CAP`]; retained stdout is zeroized, stderr is discarded, and
/// no helper-controlled bytes or command path enter an error.
fn run_keyring_command(command: &str, args: &[&str]) -> Result<Secret, SecretError> {
    run_keyring_command_with_timeout(command, args, KEYRING_COMMAND_TIMEOUT)
}

fn run_keyring_command_with_timeout(
    command: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Secret, SecretError> {
    let started = Instant::now();
    let mut child = KeyringProcessTree::spawn(command, args).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SecretError::BackendUnavailable("keyring".to_owned())
        } else {
            SecretError::BackendFailure("keyring".to_owned())
        }
    })?;
    let readers = match KeyringReaders::spawn(&mut child) {
        Ok(readers) => readers,
        Err(_) => {
            let _ = child.terminate_and_reap();
            return Err(SecretError::BackendFailure("keyring".to_owned()));
        }
    };

    let remaining = timeout
        .checked_sub(started.elapsed())
        .unwrap_or(Duration::ZERO);
    let status = child.wait_direct(remaining);
    let cleanup_succeeded = child.terminate_and_reap();
    let output = readers.collect(started, timeout);

    if !cleanup_succeeded {
        return Err(SecretError::BackendFailure("keyring".to_owned()));
    }
    let status = match status {
        Ok(Some(status)) => status,
        Ok(None) => return Err(SecretError::BackendTimedOut("keyring".to_owned())),
        Err(_) => return Err(SecretError::BackendFailure("keyring".to_owned())),
    };
    let (stdout, stderr) = match output {
        Ok(output) => output,
        Err(RecvTimeoutError::Timeout) => {
            return Err(SecretError::BackendTimedOut("keyring".to_owned()));
        }
        Err(RecvTimeoutError::Disconnected) => {
            return Err(SecretError::BackendFailure("keyring".to_owned()));
        }
    };
    if stdout.failed || stderr.failed {
        return Err(SecretError::BackendFailure("keyring".to_owned()));
    }
    if !status.success() {
        return Err(SecretError::NotFound("keyring".to_owned()));
    }
    if stdout.truncated || stderr.truncated {
        return Err(SecretError::BackendOutputTooLarge("keyring".to_owned()));
    }
    let value = std::str::from_utf8(&stdout.bytes)
        .map_err(|_| SecretError::InvalidUtf8("keyring".to_owned()))?;
    let value = strip_one_trailing_line_ending(value.to_owned());
    if value.is_empty() {
        Err(SecretError::NotFound("keyring".to_owned()))
    } else {
        Ok(Secret::new(value))
    }
}

#[cfg(target_os = "macos")]
fn platform_keyring_secret(service: &str, account: &str) -> Result<Secret, SecretError> {
    run_keyring_command(
        "/usr/bin/security",
        &["find-generic-password", "-w", "-s", service, "-a", account],
    )
}

#[cfg(target_os = "linux")]
fn platform_keyring_secret(service: &str, account: &str) -> Result<Secret, SecretError> {
    run_keyring_command(
        "secret-tool",
        &["lookup", "service", service, "account", account],
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_keyring_secret(_service: &str, _account: &str) -> Result<Secret, SecretError> {
    Err(SecretError::BackendUnavailable("keyring".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env<'a>(
        map: &'a HashMap<&'static str, &'static str>,
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| map.get(k).map(|v| (*v).to_owned())
    }

    fn empty_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn parses_scheme_and_locator() {
        let r = SecretRef::parse("env:DB_PASSWORD").unwrap();
        assert_eq!(r.scheme, "env");
        assert_eq!(r.locator, "DB_PASSWORD");
        assert!(SecretRef::parse("noscheme").is_err());
        assert!(SecretRef::parse("env:").is_err());
    }

    #[test]
    fn env_scheme_resolves_from_injected_lookup() {
        let mut m = HashMap::new();
        m.insert("DB_PASSWORD", "tiger");
        let s = resolve_secret("env:DB_PASSWORD", true, env(&m)).expect("resolve");
        assert_eq!(s.expose(), "tiger");
        let resolver = EnvLookupSecretResolver::new(env(&m));
        assert_eq!(
            resolve_secret_with("env:DB_PASSWORD", true, &resolver)
                .expect("resolve via seam")
                .expose(),
            "tiger"
        );
        // Missing var -> NotFound.
        assert!(matches!(
            resolve_secret_with("env:NOPE", false, &resolver),
            Err(SecretError::NotFound(_))
        ));
    }

    #[test]
    fn file_scheme_resolves_from_secret_file_and_strips_one_line_ending() {
        let path = std::env::temp_dir().join(format!(
            "oraclemcp-secret-test-{}-file.txt",
            std::process::id()
        ));
        std::fs::write(&path, "file-secret\n").expect("write secret fixture");
        let reference = format!("file:{}", path.display());
        let resolver = EnvLookupSecretResolver::new(empty_env);
        let s = resolve_secret_with(&reference, true, &resolver).expect("resolve file");
        assert_eq!(s.expose(), "file-secret");
    }

    #[test]
    fn keyring_scheme_is_available_through_the_resolver_seam() {
        struct MockResolver;
        impl SecretResolver for MockResolver {
            fn resolve(&self, reference: &SecretRef) -> Result<Secret, SecretError> {
                match reference.scheme.as_str() {
                    "keyring" => {
                        let (service, account) = parse_keyring_locator(&reference.locator)?;
                        Ok(Secret::new(format!("{service}/{account}-secret")))
                    }
                    other => Err(SecretError::BackendUnavailable(other.to_owned())),
                }
            }
        }

        let s = resolve_secret_with("keyring:prod/ro", true, &MockResolver).expect("keyring");
        assert_eq!(s.expose(), "prod/ro-secret");
        assert_eq!(
            parse_keyring_locator("solo").expect("default service"),
            (DEFAULT_KEYRING_SERVICE, "solo")
        );
    }

    #[test]
    fn literal_is_denied_under_protected_profile() {
        let m = HashMap::new();
        let resolver = EnvLookupSecretResolver::new(env(&m));
        assert!(matches!(
            resolve_secret_with("literal:hunter2", true, &resolver),
            Err(SecretError::PlaintextForbidden)
        ));
        // Allowed in dev (non-protected).
        assert_eq!(
            resolve_secret_with("literal:hunter2", false, &resolver)
                .unwrap()
                .expose(),
            "hunter2"
        );
    }

    #[test]
    fn vault_scheme_is_explicit_backend_unavailable_without_the_feature() {
        let m = HashMap::new();
        let resolver = EnvLookupSecretResolver::new(env(&m));
        assert!(matches!(
            resolve_secret_with("vault:secret/oracle#password", true, &resolver),
            Err(SecretError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "Secret(***redacted***)");
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    #[test]
    fn secret_ref_debug_redacts_locator() {
        let r = SecretRef::parse("file:/private/path/secret.txt").expect("parse");
        let rendered = format!("{r:?}");
        assert!(rendered.contains("file"));
        assert!(!rendered.contains("/private/path/secret.txt"));
    }

    #[cfg(unix)]
    fn run_test_keyring_helper(
        script: &str,
        timeout: Duration,
    ) -> (Result<Secret, SecretError>, Duration) {
        let started = Instant::now();
        let result = run_keyring_command_with_timeout("/bin/sh", &["-c", script], timeout);
        (result, started.elapsed())
    }

    #[cfg(unix)]
    #[test]
    fn keyring_helper_stdin_is_closed_and_normal_results_are_preserved() {
        let (secret, elapsed) = run_test_keyring_helper(
            "cat >/dev/null; printf 'finite-secret\\r\\n'",
            Duration::from_secs(2),
        );
        assert_eq!(
            secret.expect("closed stdin reaches EOF").expose(),
            "finite-secret"
        );
        assert!(elapsed < Duration::from_secs(1), "elapsed {elapsed:?}");

        assert!(matches!(
            run_test_keyring_helper("exit 0", Duration::from_secs(2)).0,
            Err(SecretError::NotFound(ref backend)) if backend == "keyring"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn keyring_helper_that_never_finishes_is_deadline_bounded() {
        let (result, elapsed) = run_test_keyring_helper("sleep 30", Duration::from_millis(100));
        assert!(matches!(
            result,
            Err(SecretError::BackendTimedOut(ref backend)) if backend == "keyring"
        ));
        assert!(elapsed < Duration::from_secs(2), "elapsed {elapsed:?}");
    }

    #[cfg(unix)]
    fn assert_process_gone(pid: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if !Command::new("kill")
                .args(["-0", pid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("probe descendant")
                .success()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("keyring descendant {pid} survived process-tree cleanup");
    }

    #[cfg(unix)]
    fn assert_inherited_pipe_is_bounded(script: &str) {
        let (result, elapsed) = run_test_keyring_helper(script, Duration::from_millis(250));
        assert!(elapsed < Duration::from_secs(1), "elapsed {elapsed:?}");
        let secret = result.expect("successful parent returns its finite secret");
        let pid = secret
            .expose()
            .split('.')
            .next()
            .expect("PID secret segment");
        assert!(pid.bytes().all(|byte| byte.is_ascii_digit()));
        assert_process_gone(pid);
    }

    #[cfg(unix)]
    #[test]
    fn keyring_successful_parent_with_inherited_stdout_is_deadline_bounded() {
        for _ in 0..5 {
            assert_inherited_pipe_is_bounded(
                "sleep 30 2>/dev/null & printf '%s.finite-secret\\n' \"$!\"",
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn keyring_successful_parent_with_inherited_stderr_is_deadline_bounded() {
        for _ in 0..5 {
            assert_inherited_pipe_is_bounded(
                "sleep 30 >/dev/null & printf '%s.finite-secret\\n' \"$!\"",
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn keyring_helper_caps_stdout_and_stderr_independently() {
        let stdout_script = format!("head -c {} /dev/zero | tr '\\0' x", KEYRING_OUTPUT_CAP + 1);
        assert!(matches!(
            run_test_keyring_helper(&stdout_script, Duration::from_secs(5)).0,
            Err(SecretError::BackendOutputTooLarge(ref backend)) if backend == "keyring"
        ));

        let stderr_script = format!(
            "head -c {} /dev/zero | tr '\\0' s >&2; printf 'finite-secret\\n'",
            KEYRING_OUTPUT_CAP + 1
        );
        assert!(matches!(
            run_test_keyring_helper(&stderr_script, Duration::from_secs(5)).0,
            Err(SecretError::BackendOutputTooLarge(ref backend)) if backend == "keyring"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn keyring_helper_nonzero_invalid_utf8_and_spawn_errors_are_typed_and_redacted() {
        let stdout_secret = "QA12_STDOUT_SECRET";
        let stderr_secret = "QA12_STDERR_SECRET";
        let script = format!("printf '{stdout_secret}'; printf '{stderr_secret}' >&2; exit 17");
        let error = run_test_keyring_helper(&script, Duration::from_secs(2))
            .0
            .expect_err("nonzero helper must fail");
        let rendered = format!("{error:?} {error}");
        assert!(matches!(error, SecretError::NotFound(_)));
        assert!(
            !rendered.contains(stdout_secret),
            "stdout leaked: {rendered}"
        );
        assert!(
            !rendered.contains(stderr_secret),
            "stderr leaked: {rendered}"
        );

        assert!(matches!(
            run_test_keyring_helper("printf '\\377'", Duration::from_secs(2)).0,
            Err(SecretError::InvalidUtf8(ref backend)) if backend == "keyring"
        ));

        let secret_path = "/nonexistent/QA12-secret-helper-path";
        let spawn_error = run_keyring_command(secret_path, &[]).expect_err("spawn must fail");
        let rendered = format!("{spawn_error:?} {spawn_error}");
        assert!(matches!(spawn_error, SecretError::BackendUnavailable(_)));
        assert!(!rendered.contains(secret_path), "path leaked: {rendered}");
    }

    #[cfg(target_os = "linux")]
    fn process_with_marker_exists(marker: &str) -> bool {
        std::fs::read_dir("/proc")
            .expect("read /proc")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
            })
            .filter_map(|entry| std::fs::read(entry.path().join("cmdline")).ok())
            .any(|cmdline| String::from_utf8_lossy(&cmdline).contains(marker))
    }

    #[cfg(target_os = "linux")]
    fn keyring_worker_count() -> usize {
        std::fs::read_dir("/proc/self/task")
            .expect("read task directory")
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_to_string(entry.path().join("comm")).ok())
            .filter(|name| name.starts_with("keyring-"))
            .count()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repeated_keyring_timeouts_leave_no_descendants_or_reader_workers() {
        let workers_before = keyring_worker_count();
        for iteration in 0..10 {
            let marker = format!("qa12-keyring-timeout-{}-{iteration}", std::process::id());
            let script = format!("sh -c 'sleep 30' {marker} & wait");
            let (result, elapsed) = run_test_keyring_helper(&script, Duration::from_millis(50));
            assert!(matches!(result, Err(SecretError::BackendTimedOut(_))));
            assert!(elapsed < Duration::from_secs(2), "elapsed {elapsed:?}");

            let deadline = Instant::now() + Duration::from_secs(2);
            while process_with_marker_exists(&marker) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                !process_with_marker_exists(&marker),
                "descendant survived cleanup: {marker}"
            );
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        while keyring_worker_count() > workers_before && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            keyring_worker_count() <= workers_before,
            "reader workers accumulated across retries"
        );
    }
}
