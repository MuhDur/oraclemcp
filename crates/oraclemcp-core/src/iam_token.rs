//! Server-side OCI IAM database-token resolution (beads B2.2a / B2.2b): the three
//! server token sources — an **environment variable**, a **token file**, and a
//! **command** (`token_exec`) — that feed a pre-fetched JWT database token into
//! [`OracleConnectOptions::iam_token`](oraclemcp_db::OracleConnectOptions), which
//! the B2 adapter then hands to the driver via `with_access_token` (TCPS-enforced;
//! a token on a plaintext transport is refused).
//!
//! Discipline (mirrors [`oraclemcp_auth::secrets`]): a token is an **external
//! ref**. This module holds only the *reference* (an env-var NAME, a file PATH, or
//! a command **arg-array**) on its types; the token **value** is resolved
//! transiently at connect time and is never persisted, rendered, logged, or placed
//! in an error message. Every source **re-resolves on every
//! [`ServerIamTokenSource::get_token`]** — the env/file is re-read and the command
//! is re-run — so a rotated token is picked up without a restart. An empty,
//! missing, or malformed token is a typed, fail-closed error — never a silent
//! empty token.
//!
//! Source selection is **mutually exclusive** (bead B2.2b): at most one of
//! `token_exec`, `token_file`, `token_env` may be configured; configuring more
//! than one is a fail-closed [`IamTokenError::AmbiguousSource`], and none falls
//! back to the built-in [`IAM_TOKEN_ENV`].
//!
//! ## `token_exec` hardening (SECURITY-CRITICAL — it spawns a subprocess)
//!
//! The command is an **arg-array** run directly via
//! [`std::process::Command`] — `Command::new(argv[0]).args(argv[1..])`. There is
//! **NO shell**: shell metacharacters (`;`, `$(…)`, backticks, `|`) in any element
//! are inert literal argv, never interpreted. Every fetch is bounded and
//! fail-closed:
//! - one **5-second end-to-end wall-clock timeout** ([`EXEC_TIMEOUT`]) over both
//!   process execution and output collection — the whole helper process tree is
//!   killed and the direct child reaped (no zombie or inherited-pipe hang);
//! - stdout is read behind a **64 KiB cap** ([`EXEC_OUTPUT_CAP`]) — larger output
//!   fails closed and is never buffered unbounded;
//! - the trimmed token must match the **base64url/JWT charset** (`[A-Za-z0-9_.=-]`)
//!   — null bytes, spaces, control chars, or invalid UTF-8 fail closed;
//! - a **non-zero exit** or **empty stdout** fails closed;
//! - every refusal is logged with its *reason* — never the token or the stdout
//!   bytes.
//!
//! The richer proactive-refresh seam (`oraclemcp_db::IamTokenSource` /
//! `ensure_fresh_token`, for a future OCI-SDK source) is unchanged; these simple
//! sources use the static [`with_access_token`] path and re-read on each connect,
//! so a separate skew-based refresher is unnecessary for them.
//!
//! [`with_access_token`]: https://docs.rs/oracledb

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[cfg(test)]
use std::{
    cell::Cell,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use command_group::{CommandGroup, GroupChild};
use oraclemcp_config::{ConnectionProfile, OciConfig};
use oraclemcp_db::OracleConnectOptions;
use thiserror::Error;
use wait_timeout::ChildExt;

/// Wall-clock deadline for a single `token_exec` fetch. A command still running at
/// this point is killed and reaped, and the fetch fails closed — a hanging token
/// fetcher can never wedge the connect path.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(5);

/// Hard cap on the bytes read from a `token_exec` command's stdout. Output beyond
/// this fails closed rather than being buffered unbounded (a flood defense).
pub const EXEC_OUTPUT_CAP: usize = 64 * 1024;

/// The built-in environment variable checked for an IAM database token when a
/// profile enables `use_iam_token` without naming its own `token_env`.
pub const IAM_TOKEN_ENV: &str = "ORACLEMCP_IAM_TOKEN";

/// Seconds-before-expiry at which the JWT `exp` is considered "near expiry" for
/// the doctor diagnostic (5 minutes).
pub const IAM_TOKEN_EXPIRY_WARN_SECS: i64 = 300;

/// IAM database-token resolution failures. Fail-closed and **token-free**: no
/// variant carries the token value, so an error may be logged or surfaced
/// without leaking the credential.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum IamTokenError {
    /// The named environment variable is not set.
    #[error("IAM token environment variable `{0}` is not set")]
    EnvMissing(String),
    /// The token file could not be read (missing / unreadable).
    #[error("IAM token file `{0}` could not be read")]
    FileUnreadable(String),
    /// The resolved source produced an empty token (whitespace-only or empty).
    #[error("resolved IAM token from {0} is empty")]
    Empty(&'static str),
    /// A token is configured on a transport that is not provably TLS/TCPS. A
    /// database access token must never travel in clear text, so we fail closed
    /// before the token reaches the driver.
    #[error(
        "OCI IAM database-token auth requires a TLS (TCPS) transport; use a tcps:// connect \
         string or a connect descriptor whose selected address uses PROTOCOL=TCPS"
    )]
    NonTcpsTransport,
    /// The configured Oracle Net target could not be resolved and parsed far
    /// enough to prove the selected endpoint's transport before token I/O.
    #[error("OCI IAM database-token auth requires a resolvable Oracle Net TCPS endpoint")]
    TransportUnresolved,
    /// More than one of `token_env` / `token_file` / `token_exec` is configured.
    /// The sources are mutually exclusive so an operator's intent is never
    /// silently disambiguated — a profile with two sources fails closed.
    #[error(
        "ambiguous IAM token source: configure at most one of token_env, token_file, or token_exec"
    )]
    AmbiguousSource,
    /// `token_exec` is configured but its arg-array is empty (no `argv[0]`).
    #[error("IAM token_exec command is empty (argv[0] program is required)")]
    ExecEmptyCommand,
    /// The `token_exec` program could not be spawned (or could not be waited on).
    /// Carries the program name (`argv[0]`) only — a config reference, never the
    /// token.
    #[error("IAM token_exec program `{0}` could not be spawned")]
    ExecSpawnFailed(String),
    /// The `token_exec` process tree or its output collection did not finish
    /// within [`EXEC_TIMEOUT`]. The whole tree was killed and the direct child
    /// reaped; the fetch fails closed. Carries the deadline (seconds) only.
    #[error("IAM token_exec command timed out after {0}s and was killed")]
    ExecTimedOut(u64),
    /// The `token_exec` command exited with a non-zero status (or was terminated by
    /// a signal — `None` code). Carries the exit code only, never any output.
    #[error("IAM token_exec command exited with a non-zero status ({0:?})")]
    ExecNonZeroExit(Option<i32>),
    /// The `token_exec` command wrote more than [`EXEC_OUTPUT_CAP`] bytes to stdout.
    /// We fail closed rather than buffer unbounded. No output bytes are carried.
    #[error("IAM token_exec produced more than {EXEC_OUTPUT_CAP} bytes of output")]
    ExecOutputTooLarge,
    /// The `token_exec` output (after trimming) is not a valid base64url/JWT token
    /// (`[A-Za-z0-9_.=-]`): it held control chars, whitespace, null bytes, or was
    /// not valid UTF-8. No output bytes are carried.
    #[error("IAM token_exec output is not a valid base64url token")]
    ExecBadCharset,
    /// Both `token_key_file` and `token_key_env` are configured. They are
    /// mutually exclusive so an operator's intent is never silently disambiguated.
    #[error(
        "ambiguous IAM token key source: configure at most one of token_key_file or token_key_env"
    )]
    AmbiguousKeySource,
    /// The IAM token proof-of-possession private-key file could not be read
    /// (missing / unreadable). Carries the path reference only, never the key.
    #[error("IAM token key file `{0}` could not be read")]
    KeyFileUnreadable(String),
    /// The environment variable named by `token_key_env` is not set. Carries the
    /// variable name only, never the key.
    #[error("IAM token key environment variable `{0}` is not set")]
    KeyEnvMissing(String),
    /// The resolved proof-of-possession private key is empty (whitespace-only).
    #[error("resolved IAM token key from {0} is empty")]
    KeyEmpty(&'static str),
}

/// A simple server-side IAM database-token source: an environment variable, a
/// token file, or a command (`token_exec`). Each variant holds only the
/// *reference* — never the token value — and re-resolves on every
/// [`Self::get_token`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerIamTokenSource {
    /// Read the token from an environment variable. `None` uses the built-in
    /// [`IAM_TOKEN_ENV`]; `Some(name)` uses the profile's `token_env` variable.
    Env {
        /// The environment-variable name, or `None` for [`IAM_TOKEN_ENV`].
        var: Option<String>,
    },
    /// Read the token from a file, re-read on every fetch.
    File {
        /// The token file path.
        path: PathBuf,
    },
    /// Run a command to fetch the token from its stdout, re-run on every fetch.
    /// `argv[0]` is the program and the rest are literal arguments — it is run
    /// **directly, never through a shell**, so shell metacharacters in any element
    /// are inert literal data. The fetch is bounded by [`EXEC_TIMEOUT`] and
    /// [`EXEC_OUTPUT_CAP`] and fails closed on timeout / non-zero exit / oversized
    /// or non-base64url output.
    Exec {
        /// The command arg-array: `argv[0]` is the program, the rest are args.
        argv: Vec<String>,
    },
}

impl ServerIamTokenSource {
    /// The source implied by a profile's `[profiles.oci]` config, when
    /// `use_iam_token` is set. The three explicit sources — `token_exec`,
    /// `token_file`, `token_env` — are **mutually exclusive**: configuring more
    /// than one is a fail-closed [`IamTokenError::AmbiguousSource`] so an
    /// operator's intent is never silently disambiguated. With exactly one
    /// configured, that source is used; with none, the built-in [`IAM_TOKEN_ENV`]
    /// variable is read. An empty ref (empty string / empty arg-array) counts as
    /// unset, mirroring the env/file handling. Returns `Ok(None)` when the profile
    /// does not use IAM-token auth.
    pub fn from_oci(oci: &OciConfig) -> Result<Option<Self>, IamTokenError> {
        if !oci.use_iam_token {
            return Ok(None);
        }
        // Gather the explicitly-configured sources; an empty ref is treated as
        // unset (mirrors B2.2a's empty-string handling).
        let exec = oci
            .token_exec
            .as_ref()
            .filter(|argv| !argv.is_empty())
            .map(|argv| ServerIamTokenSource::Exec { argv: argv.clone() });
        let file = oci
            .token_file
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| ServerIamTokenSource::File {
                path: PathBuf::from(p),
            });
        let env = oci
            .token_env
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| ServerIamTokenSource::Env {
                var: Some(v.to_owned()),
            });

        let mut configured = [exec, file, env].into_iter().flatten();
        let first = configured.next();
        if configured.next().is_some() {
            // Two or more explicit sources: refuse rather than pick one.
            tracing::warn!(
                reason = "ambiguous-source",
                "IAM token source resolution failed closed"
            );
            return Err(IamTokenError::AmbiguousSource);
        }
        Ok(Some(
            first.unwrap_or(ServerIamTokenSource::Env { var: None }),
        ))
    }

    /// Resolve the token now, reading the env/file **fresh** on every call so a
    /// rotated token is picked up without a restart. Trims surrounding
    /// whitespace/newlines; an empty or missing token is a typed, fail-closed
    /// error. The returned string is the raw token — keep the borrow short-lived
    /// and never log it.
    pub fn get_token(&self) -> Result<String, IamTokenError> {
        self.get_token_with(|name| std::env::var(name).ok())
    }

    /// [`Self::get_token`] with an injected environment lookup (deterministic
    /// tests). File resolution still reads the real filesystem.
    pub fn get_token_with(
        &self,
        env_lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<String, IamTokenError> {
        match self {
            ServerIamTokenSource::Env { var } => {
                let name = var.as_deref().unwrap_or(IAM_TOKEN_ENV);
                let raw =
                    env_lookup(name).ok_or_else(|| IamTokenError::EnvMissing(name.to_owned()))?;
                non_empty(raw.trim(), "env")
            }
            ServerIamTokenSource::File { path } => {
                // Re-read on every call: a rotated token file is picked up with
                // no caching across calls.
                let raw = std::fs::read_to_string(path)
                    .map_err(|_| IamTokenError::FileUnreadable(path.display().to_string()))?;
                non_empty(raw.trim(), "file")
            }
            ServerIamTokenSource::Exec { argv } => {
                // Re-run on every call: a fresh token is fetched from the command's
                // stdout with no caching across calls.
                run_token_exec(argv)
            }
        }
    }
}

fn non_empty(trimmed: &str, source: &'static str) -> Result<String, IamTokenError> {
    if trimmed.is_empty() {
        Err(IamTokenError::Empty(source))
    } else {
        Ok(trimmed.to_owned())
    }
}

/// Whether `s` is a non-empty base64url/JWT token: every byte is in
/// `[A-Za-z0-9_.=-]`. This rejects null bytes, spaces, control characters, and
/// (because the caller checks UTF-8 first) any non-ASCII byte.
fn is_base64url_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'='))
}

/// Read a child pipe with a hard [`EXEC_OUTPUT_CAP`] byte cap. Returns the first
/// (up to) `EXEC_OUTPUT_CAP` bytes plus a `truncated` flag set when the child
/// produced more. The reader keeps draining past the cap (discarding) so a child
/// with a *finite* oversized output can still exit — it is never wedged on a full
/// pipe — while the retained buffer is bounded, so memory can never grow
/// unbounded even for an infinite producer.
fn read_capped(mut reader: impl Read) -> (Vec<u8>, bool) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buffer.len() < EXEC_OUTPUT_CAP {
                    let room = EXEC_OUTPUT_CAP - buffer.len();
                    let take = room.min(n);
                    buffer.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (buffer, truncated)
}

/// A `token_exec` process tree held in an OS containment unit.
///
/// SAFETY: every spawned helper is a fresh POSIX process group on Unix and a
/// Job Object on Windows. All exits from the credential path terminate that
/// entire unit, not just the direct child. The `Drop` fallback preserves that
/// invariant during unwinding as well.
struct TokenExecProcessTree {
    child: GroupChild,
}

impl TokenExecProcessTree {
    fn spawn(program: &str, args: &[String]) -> std::io::Result<Self> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
            .group_spawn()
            .map(|child| TokenExecProcessTree { child })
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

    fn terminate_and_reap(&mut self) {
        // `kill` deliberately targets the containment unit even when the direct
        // child has already exited. That is the successful-parent/lingering-
        // descendant case that caused QA9.
        let _ = self.child.kill();
        let _ = self.child.inner().wait();
    }
}

impl Drop for TokenExecProcessTree {
    fn drop(&mut self) {
        self.terminate_and_reap();
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

fn drop_reader<T>(reader: JoinHandle<T>) {
    // A reader sends only after reaching EOF, so receipt proves its blocking
    // work is over. Dropping instead of joining keeps the wall deadline strict:
    // the thread has no more I/O and exits immediately after its one send.
    drop(reader);
}

#[cfg(test)]
static ACTIVE_TOKEN_EXEC_READER_WORKERS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
static TOKEN_EXEC_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
thread_local! {
    static TOKEN_EXEC_TEST_LOCK_HELD: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
struct TokenExecTestLockFlag<'a>(&'a Cell<bool>);

#[cfg(test)]
impl Drop for TokenExecTestLockFlag<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

#[cfg(test)]
fn with_token_exec_test_lock<R>(f: impl FnOnce() -> R) -> R {
    TOKEN_EXEC_TEST_LOCK_HELD.with(|held| {
        if held.get() {
            return f();
        }
        let _guard = TOKEN_EXEC_TEST_LOCK
            .lock()
            .expect("token_exec test lock poisoned");
        held.set(true);
        let _flag = TokenExecTestLockFlag(held);
        f()
    })
}

#[cfg(test)]
fn active_token_exec_reader_workers() -> usize {
    ACTIVE_TOKEN_EXEC_READER_WORKERS.load(Ordering::SeqCst)
}

#[cfg(test)]
struct ActiveTokenExecReaderGuard;

#[cfg(test)]
impl Drop for ActiveTokenExecReaderGuard {
    fn drop(&mut self) {
        ACTIVE_TOKEN_EXEC_READER_WORKERS.fetch_sub(1, Ordering::SeqCst);
    }
}

fn spawn_token_exec_reader<F>(f: F) -> JoinHandle<()>
where
    F: FnOnce() + Send + 'static,
{
    #[cfg(test)]
    {
        ACTIVE_TOKEN_EXEC_READER_WORKERS.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let _active_reader = ActiveTokenExecReaderGuard;
            f();
        })
    }

    #[cfg(not(test))]
    {
        std::thread::spawn(f)
    }
}

/// Run a `token_exec` arg-array and return the fetched token, fully hardened.
///
/// The command is spawned **directly** — `Command::new(argv[0]).args(argv[1..])`,
/// no shell — so metacharacters in any element are literal argv. stdin is closed
/// ([`Stdio::null`]) so a fetcher never blocks reading input. stdout is drained on
/// a dedicated thread behind [`EXEC_OUTPUT_CAP`]; stderr is drained+discarded on
/// its own thread so a chatty child cannot deadlock on a full stderr pipe. A
/// One [`EXEC_TIMEOUT`] wall-clock deadline covers execution and pipe collection.
/// The helper runs in its own POSIX process group / Windows Job Object, which is
/// terminated on every exit so descendants cannot retain pipes or survive a
/// retry. The direct child is reaped, and every fail-closed path logs its *reason*
/// without the token or the stdout bytes.
///
/// This runs in the **synchronous** connect path (`inject_iam_token` →
/// `resolve_profile_options_with`), so it uses `std::thread` + `wait_timeout` and
/// introduces **no** `block_on`, `tokio::spawn`, or async-runtime dependency — the
/// concurrency-audit contract stays green.
fn run_token_exec(argv: &[String]) -> Result<String, IamTokenError> {
    run_token_exec_with_timeout(argv, EXEC_TIMEOUT)
}

fn run_token_exec_with_timeout(
    argv: &[String],
    timeout: Duration,
) -> Result<String, IamTokenError> {
    #[cfg(test)]
    {
        with_token_exec_test_lock(|| run_token_exec_with_timeout_inner(argv, timeout))
    }

    #[cfg(not(test))]
    {
        run_token_exec_with_timeout_inner(argv, timeout)
    }
}

fn run_token_exec_with_timeout_inner(
    argv: &[String],
    timeout: Duration,
) -> Result<String, IamTokenError> {
    let (program, args) = argv.split_first().ok_or(IamTokenError::ExecEmptyCommand)?;
    let started = Instant::now();

    // Arg-array spawn: NO shell. `program` + `args` are passed as literal argv, so
    // `;`, `$(…)`, backticks, and `|` in any element are inert data, never
    // interpreted. stdin is closed so the fetcher cannot hang waiting for input.
    let mut child = match TokenExecProcessTree::spawn(program, args) {
        Ok(child) => child,
        Err(_) => {
            tracing::warn!(reason = "spawn-failed", "IAM token_exec failed closed");
            return Err(IamTokenError::ExecSpawnFailed(program.clone()));
        }
    };

    // Drain stdout on its own thread (capped) and stderr on its own thread
    // (discarded, capped) so neither pipe can fill and wedge us while we wait.
    let stdout = child.take_stdout();
    let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
    let stdout_reader = spawn_token_exec_reader(move || {
        let output = stdout
            .map(read_capped)
            .unwrap_or_else(|| (Vec::new(), false));
        let _ = stdout_tx.send(output);
    });
    let stderr = child.take_stderr();
    let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
    let stderr_reader = spawn_token_exec_reader(move || {
        if let Some(err) = stderr {
            // Bounded discard: keep draining until the child closes the pipe.
            let _ = read_capped(err);
        }
        let _ = stderr_tx.send(());
    });

    // Bounded wall-clock wait: a child still alive at the deadline is killed and
    // reaped so it can neither wedge the connect path nor leak a zombie.
    let status = match child.wait_direct(timeout) {
        Ok(Some(status)) => status,
        Ok(None) => {
            child.terminate_and_reap();
            drop(stdout_reader);
            drop(stderr_reader);
            tracing::warn!(
                reason = "timeout",
                secs = timeout.as_secs(),
                "IAM token_exec failed closed"
            );
            return Err(IamTokenError::ExecTimedOut(timeout.as_secs()));
        }
        Err(_) => {
            child.terminate_and_reap();
            drop(stdout_reader);
            drop(stderr_reader);
            tracing::warn!(reason = "wait-failed", "IAM token_exec failed closed");
            return Err(IamTokenError::ExecSpawnFailed(program.clone()));
        }
    };

    // A direct-child exit does not prove its pipes reached EOF: descendants may
    // have inherited their write ends. Terminate the whole containment unit on
    // success too, then collect both readers under the *same* end-to-end wall
    // deadline. This is deliberately not two fresh per-phase timeouts.
    child.terminate_and_reap();
    let stdout_result = receive_before(&stdout_rx, started, timeout);
    let stderr_result = receive_before(&stderr_rx, started, timeout);
    let ((stdout_bytes, truncated), ()) = match (stdout_result, stderr_result) {
        (Ok(stdout), Ok(stderr)) => (stdout, stderr),
        (Err(RecvTimeoutError::Timeout), _) | (_, Err(RecvTimeoutError::Timeout)) => {
            drop(stdout_reader);
            drop(stderr_reader);
            tracing::warn!(
                reason = "output-timeout",
                secs = timeout.as_secs(),
                "IAM token_exec failed closed"
            );
            return Err(IamTokenError::ExecTimedOut(timeout.as_secs()));
        }
        (Err(RecvTimeoutError::Disconnected), _) | (_, Err(RecvTimeoutError::Disconnected)) => {
            drop(stdout_reader);
            drop(stderr_reader);
            tracing::warn!(
                reason = "output-collection-failed",
                "IAM token_exec failed closed"
            );
            return Err(IamTokenError::ExecSpawnFailed(program.clone()));
        }
    };
    drop_reader(stdout_reader);
    drop_reader(stderr_reader);

    // A non-zero exit (or signal termination) fails closed BEFORE we look at
    // stdout — a token from a command that reported failure is never trusted.
    if !status.success() {
        tracing::warn!(
            reason = "non-zero-exit",
            code = ?status.code(),
            "IAM token_exec failed closed"
        );
        return Err(IamTokenError::ExecNonZeroExit(status.code()));
    }
    if truncated {
        tracing::warn!(
            reason = "output-too-large",
            cap = EXEC_OUTPUT_CAP,
            "IAM token_exec failed closed"
        );
        return Err(IamTokenError::ExecOutputTooLarge);
    }
    // Reject non-UTF-8 output (null-byte-free base64url is ASCII); then trim and
    // enforce the base64url/JWT charset. The output bytes are never logged.
    let text = match std::str::from_utf8(&stdout_bytes) {
        Ok(text) => text,
        Err(_) => {
            tracing::warn!(reason = "bad-charset-utf8", "IAM token_exec failed closed");
            return Err(IamTokenError::ExecBadCharset);
        }
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        tracing::warn!(reason = "empty", "IAM token_exec failed closed");
        return Err(IamTokenError::Empty("exec"));
    }
    if !is_base64url_token(trimmed) {
        tracing::warn!(reason = "bad-charset", "IAM token_exec failed closed");
        return Err(IamTokenError::ExecBadCharset);
    }
    Ok(trimmed.to_owned())
}

/// Resolve the server-side IAM database token for `profile` (env/file source)
/// and inject it into `options.iam_token`, so the B2 adapter wires it through
/// `with_access_token`. A **no-op** when the profile does not use IAM-token auth.
///
/// Fails closed if `use_iam_token` is set but (a) the transport is not provably
/// TCPS (a token must never travel in clear text — refused here as defense in
/// depth, and again by the driver at connect), or (b) the configured source
/// yields an empty/missing token. No error carries the token value.
pub fn inject_iam_token(
    profile: &ConnectionProfile,
    options: &mut OracleConnectOptions,
) -> Result<(), IamTokenError> {
    inject_iam_token_with(profile, options, |name| std::env::var(name).ok())
}

/// [`inject_iam_token`] with an injected environment lookup (deterministic
/// tests). File resolution still reads the real filesystem.
pub fn inject_iam_token_with(
    profile: &ConnectionProfile,
    options: &mut OracleConnectOptions,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Result<(), IamTokenError> {
    let Some(oci) = profile.oci.as_ref() else {
        return Ok(());
    };
    if !oci.use_iam_token {
        return Ok(());
    }
    // Resolve aliases and parse the selected endpoint BEFORE even constructing
    // the token source. This is the exact first-address protocol model used by
    // the pinned driver; wallet/certificate settings are never transport proof.
    let uses_tcps = oraclemcp_db::selected_endpoint_uses_tcps(options).map_err(|_| {
        tracing::warn!(
            reason = "transport-unresolved",
            "IAM token source refused (fail-closed)"
        );
        IamTokenError::TransportUnresolved
    })?;
    if !uses_tcps {
        tracing::warn!(
            reason = "non-tcps",
            "IAM token source refused (fail-closed)"
        );
        return Err(IamTokenError::NonTcpsTransport);
    }
    let Some(source) = ServerIamTokenSource::from_oci(oci)? else {
        return Ok(());
    };
    let token = source.get_token_with(&env_lookup)?;
    options.iam_token = Some(token);
    // OCI IAM *database* tokens are proof-of-possession: resolve the bound private
    // key (a `token_key_file` path or `token_key_env` variable) so the driver can
    // sign the auth header. Absent for a plain OAuth2 bearer token; a database
    // token without its key fails closed later with ORA-01017 at connect.
    if let Some(key) = resolve_iam_token_key(oci, &env_lookup)? {
        options.iam_token_private_key = Some(key);
    }
    Ok(())
}

/// Resolve the OCI IAM database-token proof-of-possession private key (PKCS#8
/// PEM) from the profile's `token_key_file` (path) or `token_key_env` (variable
/// name) reference, re-read fresh on every connect. The two are mutually
/// exclusive. Returns `Ok(None)` when neither is configured (a plain OAuth2
/// bearer token). The key is never persisted or logged; only path/name
/// references appear in errors.
fn resolve_iam_token_key(
    oci: &OciConfig,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<String>, IamTokenError> {
    let file = oci
        .token_key_file
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty());
    let env = oci
        .token_key_env
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    match (file, env) {
        (Some(_), Some(_)) => Err(IamTokenError::AmbiguousKeySource),
        (Some(path), None) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|_| IamTokenError::KeyFileUnreadable(path.to_owned()))?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(IamTokenError::KeyEmpty("file"));
            }
            Ok(Some(trimmed.to_owned()))
        }
        (None, Some(var)) => {
            let raw =
                env_lookup(var).ok_or_else(|| IamTokenError::KeyEnvMissing(var.to_owned()))?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(IamTokenError::KeyEmpty("env"));
            }
            Ok(Some(trimmed.to_owned()))
        }
        (None, None) => Ok(None),
    }
}

/// Read the `exp` (Unix seconds) claim from a JWT **without validating the
/// signature** — a diagnostic-only parse for the doctor near-expiry warning.
/// base64url-decodes the payload (second `.`-separated segment) and reads the
/// numeric `exp`. Returns `None` if the token is not a JWT-shaped string or has
/// no readable numeric `exp`. Never returns or logs the token itself.
#[must_use]
pub fn jwt_exp_unix(token: &str) -> Option<i64> {
    let payload_b64 = token.trim().split('.').nth(1)?;
    let payload = base64url_decode(payload_b64)?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    match claims.get("exp")? {
        serde_json::Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        _ => None,
    }
}

/// Minimal base64url (RFC 4648 §5, no padding) decoder. Pure, allocation-only,
/// no dependency — the workspace does not take a direct `base64` dep and this is
/// a tiny diagnostic decode. Tolerates optional `=` padding by stopping at it.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    fn sextet(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        if c == b'=' {
            break;
        }
        buffer = (buffer << 6) | sextet(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xFF).ok()?);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_config::OracleMcpConfig;

    /// Build a synthetic, unsigned JWT-shaped token: `header.payload.` where the
    /// payload is a base64url `{"exp": <exp>}`. NOT a real token; no signature.
    fn synthetic_jwt_with_exp(exp: i64) -> String {
        // base64url of `{"alg":"none"}` and the exp payload — computed by the
        // same decoder's inverse would be overkill; encode by hand.
        let header = base64url_encode(br#"{"alg":"none"}"#);
        let payload = base64url_encode(format!(r#"{{"exp":{exp}}}"#).as_bytes());
        format!("{header}.{payload}.")
    }

    fn base64url_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for &b in bytes {
            buffer = (buffer << 8) | u32::from(b);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[((buffer >> bits) & 0x3F) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buffer << (6 - bits)) & 0x3F) as usize] as char);
        }
        out
    }

    fn env_map(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        // Own the pairs so the returned closure does not borrow a temporary array.
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| {
            owned
                .iter()
                .find(|(name, _)| name == k)
                .map(|(_, v)| v.clone())
        }
    }

    fn tcps_profile() -> ConnectionProfile {
        OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "cloud"
            connect_string = "tcps://adb.example/svc"
            username = "app"
            [profiles.oci]
            use_iam_token = true
            "#,
        )
        .expect("config")
        .profiles
        .into_iter()
        .next()
        .expect("profile")
    }

    fn connect_options_for(profile: &ConnectionProfile) -> OracleConnectOptions {
        OracleConnectOptions {
            connect_string: profile.connect_string.clone().unwrap_or_default(),
            wallet_location: profile
                .oci
                .as_ref()
                .and_then(|oci| oci.wallet_location.clone()),
            ssl_server_cert_dn: profile
                .oci
                .as_ref()
                .and_then(|oci| oci.ssl_server_cert_dn.clone()),
            use_iam_token: profile.oci.as_ref().is_some_and(|oci| oci.use_iam_token),
            ..Default::default()
        }
    }

    fn tns_fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join("fixtures")
            .join("tns")
    }

    #[test]
    fn env_source_uses_builtin_when_no_token_env() {
        let src = ServerIamTokenSource::Env { var: None };
        let env = env_map(&[(IAM_TOKEN_ENV, "  header.payload.sig\n")]);
        assert_eq!(src.get_token_with(&env).unwrap(), "header.payload.sig");
    }

    #[test]
    fn env_source_uses_named_token_env() {
        let src = ServerIamTokenSource::Env {
            var: Some("MY_IAM_TOKEN".to_owned()),
        };
        let env = env_map(&[("MY_IAM_TOKEN", "tok-abc\n")]);
        assert_eq!(src.get_token_with(&env).unwrap(), "tok-abc");
        // A missing named var is a typed, fail-closed error (never empty token).
        let missing = ServerIamTokenSource::Env {
            var: Some("ABSENT_VAR".to_owned()),
        };
        assert_eq!(
            missing.get_token_with(env_map(&[])),
            Err(IamTokenError::EnvMissing("ABSENT_VAR".to_owned()))
        );
    }

    #[test]
    fn env_empty_token_is_fail_closed_not_silent() {
        let src = ServerIamTokenSource::Env { var: None };
        let env = env_map(&[(IAM_TOKEN_ENV, "   \n")]);
        assert_eq!(src.get_token_with(&env), Err(IamTokenError::Empty("env")));
    }

    #[test]
    fn file_source_reads_and_rereads_on_rotation() {
        let path = std::env::temp_dir().join(format!(
            "oraclemcp-iam-token-rotate-{}.jwt",
            std::process::id()
        ));
        std::fs::write(&path, "token-A\n").expect("write A");
        let src = ServerIamTokenSource::File { path: path.clone() };
        assert_eq!(src.get_token().unwrap(), "token-A");
        // Overwrite with B: the next get_token must observe B (no caching).
        std::fs::write(&path, "token-B\n").expect("write B");
        assert_eq!(src.get_token().unwrap(), "token-B");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_missing_is_fail_closed() {
        let src = ServerIamTokenSource::File {
            path: PathBuf::from("/no/such/oraclemcp/iam-token.jwt"),
        };
        assert!(matches!(
            src.get_token(),
            Err(IamTokenError::FileUnreadable(_))
        ));
    }

    #[test]
    fn from_oci_sources_are_mutually_exclusive() {
        let mut oci = OciConfig {
            use_iam_token: true,
            ..OciConfig::default()
        };
        // No refs -> built-in env.
        assert_eq!(
            ServerIamTokenSource::from_oci(&oci),
            Ok(Some(ServerIamTokenSource::Env { var: None }))
        );
        // token_env alone -> that var.
        oci.token_env = Some("NAMED".to_owned());
        assert_eq!(
            ServerIamTokenSource::from_oci(&oci),
            Ok(Some(ServerIamTokenSource::Env {
                var: Some("NAMED".to_owned())
            }))
        );
        // token_file alone -> file source.
        oci.token_env = None;
        oci.token_file = Some("/etc/iam.jwt".to_owned());
        assert_eq!(
            ServerIamTokenSource::from_oci(&oci),
            Ok(Some(ServerIamTokenSource::File {
                path: PathBuf::from("/etc/iam.jwt")
            }))
        );
        // token_exec alone -> exec source (the arg-array is preserved verbatim).
        oci.token_file = None;
        oci.token_exec = Some(vec!["/usr/bin/fetch".to_owned(), "--adb".to_owned()]);
        assert_eq!(
            ServerIamTokenSource::from_oci(&oci),
            Ok(Some(ServerIamTokenSource::Exec {
                argv: vec!["/usr/bin/fetch".to_owned(), "--adb".to_owned()]
            }))
        );
        // Empty arg-array counts as unset (mirrors empty-string handling) -> builtin.
        oci.token_exec = Some(vec![]);
        assert_eq!(
            ServerIamTokenSource::from_oci(&oci),
            Ok(Some(ServerIamTokenSource::Env { var: None }))
        );
        // Two explicit sources -> fail closed, never silently pick one.
        oci.token_exec = Some(vec!["/usr/bin/fetch".to_owned()]);
        oci.token_file = Some("/etc/iam.jwt".to_owned());
        assert_eq!(
            ServerIamTokenSource::from_oci(&oci),
            Err(IamTokenError::AmbiguousSource)
        );
        // All three configured -> still ambiguous.
        oci.token_env = Some("NAMED".to_owned());
        assert_eq!(
            ServerIamTokenSource::from_oci(&oci),
            Err(IamTokenError::AmbiguousSource)
        );
        // use_iam_token off -> no source (ambiguity is not even evaluated).
        oci.use_iam_token = false;
        assert_eq!(ServerIamTokenSource::from_oci(&oci), Ok(None));
    }

    #[test]
    fn inject_sets_options_token_over_tcps() {
        let profile = tcps_profile();
        let mut opts = connect_options_for(&profile);
        let env = env_map(&[(IAM_TOKEN_ENV, "resolved.jwt.token")]);
        inject_iam_token_with(&profile, &mut opts, &env).expect("inject over tcps");
        assert_eq!(opts.iam_token.as_deref(), Some("resolved.jwt.token"));
    }

    #[test]
    fn inject_refuses_non_tcps_transport() {
        // Same profile but a plaintext EZConnect string (no wallet, no cert DN).
        let profile = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "plain"
            connect_string = "localhost:1521/FREEPDB1"
            username = "app"
            [profiles.oci]
            use_iam_token = true
            "#,
        )
        .expect("config")
        .profiles
        .into_iter()
        .next()
        .expect("profile");
        let mut opts = connect_options_for(&profile);
        let env = env_map(&[(IAM_TOKEN_ENV, "SECRET_JWT_SENTINEL.payload.sig")]);
        let err = inject_iam_token_with(&profile, &mut opts, &env).expect_err("non-tcps refused");
        assert_eq!(err, IamTokenError::NonTcpsTransport);
        // Fail-closed: no token was injected.
        assert!(opts.iam_token.is_none());
        // The refusal must not echo the token.
        assert!(!err.to_string().contains("SECRET_JWT_SENTINEL"));
    }

    #[test]
    fn inject_is_noop_without_iam_token_auth() {
        let profile = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "pw"
            connect_string = "localhost:1521/FREEPDB1"
            username = "app"
            "#,
        )
        .expect("config")
        .profiles
        .into_iter()
        .next()
        .expect("profile");
        let mut opts = connect_options_for(&profile);
        inject_iam_token_with(&profile, &mut opts, env_map(&[])).expect("noop");
        assert!(opts.iam_token.is_none());
    }

    #[test]
    fn jwt_exp_is_parsed_without_signature_validation() {
        let token = synthetic_jwt_with_exp(1_900_000_000);
        assert_eq!(jwt_exp_unix(&token), Some(1_900_000_000));
        // Non-JWT / no exp -> None (diagnostic only).
        assert_eq!(jwt_exp_unix("not-a-jwt"), None);
        assert_eq!(jwt_exp_unix("aaa.bbb.ccc"), None);
    }

    #[test]
    fn no_rendered_surface_leaks_the_token_sentinel() {
        // Adversarial non-leak: a sentinel token flows through resolution, the
        // source Debug, and an error; it must appear in NONE of them.
        const SENTINEL: &str = "SECRET_JWT_SENTINEL";
        let token = format!("{SENTINEL}.payload.sig");

        let env_src = ServerIamTokenSource::Env {
            var: Some("SENTINEL_VAR".to_owned()),
        };
        let file_src = ServerIamTokenSource::File {
            path: PathBuf::from("/etc/oracle/iam.jwt"),
        };
        let rendered_sources = format!("{env_src:?} {file_src:?}");
        assert!(
            !rendered_sources.contains(SENTINEL),
            "source Debug leaked: {rendered_sources}"
        );

        // A successful resolution returns the token but stores nothing on the
        // source; re-rendering the source still shows no token.
        let env = env_map(&[("SENTINEL_VAR", token.as_str())]);
        let resolved = env_src.get_token_with(&env).expect("resolve");
        assert!(resolved.contains(SENTINEL)); // the caller holds it transiently
        let rendered_after = format!("{env_src:?}");
        assert!(!rendered_after.contains(SENTINEL));

        // Every IamTokenError Display is token-free — including the exec variants.
        for err in [
            IamTokenError::EnvMissing("SENTINEL_VAR".to_owned()),
            IamTokenError::FileUnreadable("/etc/oracle/iam.jwt".to_owned()),
            IamTokenError::Empty("env"),
            IamTokenError::Empty("exec"),
            IamTokenError::NonTcpsTransport,
            IamTokenError::AmbiguousSource,
            IamTokenError::ExecEmptyCommand,
            IamTokenError::ExecSpawnFailed("/usr/bin/fetch".to_owned()),
            IamTokenError::ExecTimedOut(5),
            IamTokenError::ExecNonZeroExit(Some(3)),
            IamTokenError::ExecOutputTooLarge,
            IamTokenError::ExecBadCharset,
        ] {
            assert!(!err.to_string().contains(SENTINEL), "{err}");
        }
    }

    // ---- B2.2b: token_exec (subprocess) hardening -------------------------------
    //
    // These tests drive small hermetic coreutils via an **arg-array** (never a
    // shell string): the token fetcher's whole surface is exercised without any
    // external state. Each fail-closed path is proven to return a typed error and
    // never panic or leak.

    /// Resolve a coreutil to an absolute path so it is invoked as a literal argv[0]
    /// (no PATH ambiguity, no shell). Fails the test loudly if the tool is absent.
    fn coreutil(name: &str) -> String {
        // Hermetic exec targets with no PATH ambiguity. On Unix these live in
        // /usr/bin or /bin. On Windows the GitHub runners ship the identical
        // coreutils via Git Bash, so look there too (with the .exe suffix) — the
        // exec-provider tests then exercise the same cross-platform `Command`
        // path on Windows instead of being skipped.
        #[cfg(windows)]
        let (dirs, suffix): (&[&str], &str) = (
            &[r"C:\Program Files\Git\usr\bin", r"C:\Program Files\Git\bin"],
            ".exe",
        );
        #[cfg(not(windows))]
        let (dirs, suffix): (&[&str], &str) = (&["/usr/bin", "/bin"], "");
        for dir in dirs {
            let candidate = std::path::Path::new(dir).join(format!("{name}{suffix}"));
            if candidate.exists() {
                return candidate.to_string_lossy().into_owned();
            }
        }
        panic!("hermetic test requires `{name}` (looked in {dirs:?})");
    }

    fn exec_src(argv: &[&str]) -> ServerIamTokenSource {
        ServerIamTokenSource::Exec {
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
        }
    }

    /// A TCPS profile whose `[profiles.oci]` body is `oci_body` (raw TOML lines).
    fn tcps_profile_with_oci(oci_body: &str) -> ConnectionProfile {
        OracleMcpConfig::from_toml_str(&format!(
            r#"
            [[profiles]]
            name = "cloud"
            connect_string = "tcps://adb.example/svc"
            username = "app"
            [profiles.oci]
            {oci_body}
            "#
        ))
        .expect("config")
        .profiles
        .into_iter()
        .next()
        .expect("profile")
    }

    #[test]
    fn exec_happy_path_returns_the_token_from_stdout() {
        // A JWT-shaped, base64url-charset token on stdout (with a trailing newline
        // that must be trimmed) resolves cleanly.
        let printf = coreutil("printf");
        let src = exec_src(&[&printf, "header.payload-part_0.sig=\n"]);
        assert_eq!(
            src.get_token().unwrap(),
            "header.payload-part_0.sig=",
            "trailing newline must be trimmed; base64url charset accepted"
        );
    }

    #[test]
    fn exec_empty_command_is_fail_closed() {
        assert_eq!(
            exec_src(&[]).get_token(),
            Err(IamTokenError::ExecEmptyCommand)
        );
    }

    #[test]
    fn exec_missing_program_is_fail_closed_not_a_panic() {
        let src = exec_src(&["/nonexistent/oraclemcp-token-fetcher-xyz"]);
        assert!(matches!(
            src.get_token(),
            Err(IamTokenError::ExecSpawnFailed(_))
        ));
    }

    #[test]
    fn exec_non_zero_exit_is_fail_closed() {
        let src = exec_src(&[&coreutil("false")]);
        assert!(matches!(
            src.get_token(),
            Err(IamTokenError::ExecNonZeroExit(_))
        ));
    }

    #[test]
    fn exec_empty_stdout_is_fail_closed_not_a_silent_token() {
        // Exit 0 with no output must NOT become a silent empty token.
        let src = exec_src(&[&coreutil("true")]);
        assert_eq!(src.get_token(), Err(IamTokenError::Empty("exec")));
    }

    #[test]
    fn exec_output_over_64k_cap_is_fail_closed() {
        // 128 KiB of finite output: the child exits (we keep draining), and the
        // cap fires -> ExecOutputTooLarge, never an unbounded buffer.
        let src = exec_src(&[&coreutil("head"), "-c", "131072", "/dev/zero"]);
        assert_eq!(src.get_token(), Err(IamTokenError::ExecOutputTooLarge));
    }

    #[test]
    fn exec_null_bytes_are_fail_closed_bad_charset() {
        // NUL bytes are valid UTF-8 but not base64url -> rejected.
        let src = exec_src(&[&coreutil("head"), "-c", "8", "/dev/zero"]);
        assert_eq!(src.get_token(), Err(IamTokenError::ExecBadCharset));
    }

    #[test]
    fn exec_invalid_utf8_is_fail_closed_bad_charset() {
        // printf octal \377 emits a raw 0xFF byte -> not valid UTF-8 -> rejected.
        let src = exec_src(&[&coreutil("printf"), "\\377"]);
        assert_eq!(src.get_token(), Err(IamTokenError::ExecBadCharset));
    }

    #[test]
    fn exec_spaces_and_control_chars_are_fail_closed_bad_charset() {
        // Internal whitespace / injection punctuation is outside base64url.
        let src = exec_src(&[&coreutil("printf"), "%s", "tok tok"]);
        assert_eq!(src.get_token(), Err(IamTokenError::ExecBadCharset));
    }

    #[test]
    fn exec_hanging_child_hits_the_5s_timeout_and_is_killed() {
        // The 5s wall-clock deadline ALWAYS fires: a `sleep 30` child is killed
        // and reaped, and the fetch fails closed within ~5s (never blocks 30s).
        // This test is expected to take ~5 seconds.
        let src = exec_src(&[&coreutil("sleep"), "30"]);
        let start = std::time::Instant::now();
        let err = src.get_token().expect_err("must time out, not hang");
        let elapsed = start.elapsed();
        assert!(
            matches!(err, IamTokenError::ExecTimedOut(_)),
            "expected a timeout error, got {err:?}"
        );
        assert!(
            elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(15),
            "must return at the ~5s deadline, not block for the full sleep (elapsed {elapsed:?})"
        );
    }

    #[cfg(unix)]
    fn assert_process_gone(pid: &str) {
        let kill = coreutil("kill");
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if !Command::new(&kill)
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
        panic!("token_exec descendant {pid} survived process-tree cleanup");
    }

    #[cfg(unix)]
    fn assert_inherited_pipe_is_bounded(script: &str) {
        // The shell is an explicitly configured argv[0], not an implicit shell.
        // It prints its descendant PID as part of a valid token, then exits 0;
        // the descendant keeps exactly one inherited pipe open for 30 seconds.
        let src = exec_src(&[&coreutil("sh"), "-c", script]);
        let start = Instant::now();
        let token = src.get_token().expect("valid token before descendant EOF");
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(10),
            "direct-child success must not leave output collection blocked on a descendant (elapsed {elapsed:?})"
        );
        let pid = token.split('.').next().expect("PID token segment");
        assert!(pid.bytes().all(|byte| byte.is_ascii_digit()), "{token}");
        assert_process_gone(pid);
    }

    #[cfg(unix)]
    #[test]
    fn exec_successful_parent_with_pipe_inheriting_descendants_is_deadline_bounded() {
        // Five stdout and five stderr inheritances stress the original
        // interleaving at 10x load. Before QA9, the first iteration blocked for
        // the full 30-second sleep despite the advertised five-second deadline.
        for _ in 0..5 {
            assert_inherited_pipe_is_bounded("sleep 30 2>/dev/null & printf '%s.valid.jwt' \"$!\"");
            assert_inherited_pipe_is_bounded("sleep 30 >/dev/null & printf '%s.valid.jwt' \"$!\"");
        }
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
    #[test]
    fn exec_direct_timeouts_cleanup_descendant_trees_and_reader_workers() {
        with_token_exec_test_lock(|| {
            let readers_before = active_token_exec_reader_workers();
            for iteration in 0..10 {
                let marker = format!("qa9-timeout-tree-{}-{iteration}", std::process::id());
                let script = format!("sh -c 'sleep 30' {marker} & wait");
                let argv = vec![coreutil("sh"), "-c".to_owned(), script];
                let start = Instant::now();
                let error = run_token_exec_with_timeout(&argv, Duration::from_millis(100))
                    .expect_err("waiting parent must time out");
                assert_eq!(error, IamTokenError::ExecTimedOut(0));
                assert!(
                    start.elapsed() < Duration::from_secs(2),
                    "short test deadline was not end-to-end bounded"
                );
                let cleanup_deadline = Instant::now() + Duration::from_secs(2);
                while process_with_marker_exists(&marker) && Instant::now() < cleanup_deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(
                    !process_with_marker_exists(&marker),
                    "descendant process tree survived timeout: {marker}"
                );
            }

            // Reader handles are detached only after the tree is killed; give those
            // already-unblocked threads a scheduling turn, then prove retries did not
            // accumulate one stdout/stderr worker pair per attempt. Scope the proof
            // to token_exec reader workers: libtest's shared process may run other
            // tests that spawn unrelated helper threads while this assertion samples.
            let settle_deadline = Instant::now() + Duration::from_secs(2);
            let readers_after = loop {
                let count = active_token_exec_reader_workers();
                if count <= readers_before || Instant::now() >= settle_deadline {
                    break count;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(
                readers_after <= readers_before,
                "token_exec reader workers accumulated across timeout retries (before={readers_before}, after={readers_after})"
            );
        });
    }

    #[test]
    fn exec_arg_array_never_invokes_a_shell_metachars_are_literal() {
        // THE arg-array proof: shell metacharacters (`;`, `$(…)`, backticks, `|`,
        // `&&`) live in a single argv element. If ANY shell interpreted them, the
        // embedded `touch <marker>` would create the marker file. Because we spawn
        // the program directly (no shell), the whole string is inert literal argv:
        // printf echoes it, no file is ever created.
        let marker = std::env::temp_dir().join(format!(
            "oraclemcp-iam-exec-injection-canary-{}-{:?}.marker",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&marker);
        let marker_str = marker.display().to_string();
        let injection = format!(
            "x;touch {m}|touch {m}&&touch {m};$(touch {m});`touch {m}`",
            m = marker_str
        );
        let printf = coreutil("printf");
        let src = exec_src(&[&printf, "%s", &injection]);

        // The output holds `;`, ` `, `$`, `(`, backticks, `|` -> not base64url, so
        // the token fails closed on charset (which also confirms the metachars
        // reached stdout as LITERAL data rather than being executed by a shell).
        assert_eq!(src.get_token(), Err(IamTokenError::ExecBadCharset));
        // The decisive proof: NO shell ran, so the injected `touch` never happened.
        assert!(
            !marker.exists(),
            "shell metacharacters were interpreted — marker file was created (injection!)"
        );
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn exec_never_leaks_the_token_or_stdout_bytes() {
        // Adversarial non-leak for the exec path: a sentinel token is produced on
        // the command's STDOUT (as a real fetcher would — the token is the output,
        // never in the argv). The successful resolution returns it (caller holds it
        // transiently), but the source Debug and every error Display stay
        // token-free, and nothing is cached on the source.
        const SENTINEL: &str = "SECRETJWTSENTINEL"; // base64url-clean so it resolves
        let token = format!("{SENTINEL}.payload.sig");
        let token_file = std::env::temp_dir().join(format!(
            "oraclemcp-iam-exec-leak-{}-{:?}.jwt",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&token_file, &token).expect("write token file");
        // argv holds only the program + the file PATH — never the token value.
        let cat = coreutil("cat");
        let src = exec_src(&[&cat, &token_file.display().to_string()]);

        // Source Debug renders the command + path (config refs), never the token.
        assert!(
            !format!("{src:?}").contains(SENTINEL),
            "source Debug leaked the token"
        );

        let resolved = src.get_token().expect("resolve");
        assert!(resolved.contains(SENTINEL)); // transient, held only by the caller
        assert!(
            !format!("{src:?}").contains(SENTINEL),
            "source still holds no token after resolution"
        );
        let _ = std::fs::remove_file(&token_file);
    }

    #[test]
    fn inject_exec_over_tcps_sets_the_token() {
        let printf = coreutil("printf");
        let profile = tcps_profile_with_oci(&format!(
            r#"
            use_iam_token = true
            token_exec = ["{printf}", "resolved.exec.jwt"]
            "#
        ));
        let mut opts = connect_options_for(&profile);
        inject_iam_token_with(&profile, &mut opts, env_map(&[])).expect("inject over tcps");
        assert_eq!(opts.iam_token.as_deref(), Some("resolved.exec.jwt"));
    }

    #[test]
    fn inject_resolves_the_pop_private_key_from_env() {
        // An OCI IAM *database* token: the profile names both the token and the
        // bound private key. inject must wire the key through so the driver can
        // sign the proof-of-possession header.
        let profile = tcps_profile_with_oci(
            r#"
            use_iam_token = true
            token_env = "OMCP_TEST_IAM_TOKEN"
            token_key_env = "OMCP_TEST_IAM_KEY"
            "#,
        );
        let mut opts = connect_options_for(&profile);
        inject_iam_token_with(
            &profile,
            &mut opts,
            env_map(&[
                ("OMCP_TEST_IAM_TOKEN", "header.payload.sig"),
                (
                    "OMCP_TEST_IAM_KEY",
                    "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
                ),
            ]),
        )
        .expect("inject over tcps");
        assert_eq!(opts.iam_token.as_deref(), Some("header.payload.sig"));
        assert!(
            opts.iam_token_private_key
                .as_deref()
                .is_some_and(|k| k.contains("BEGIN PRIVATE KEY")),
            "the proof-of-possession key must be resolved and wired through"
        );
    }

    #[test]
    fn inject_resolves_the_pop_private_key_from_file() {
        let key_path =
            std::env::temp_dir().join(format!("oraclemcp-iam-pop-key-{}.pem", std::process::id()));
        std::fs::write(
            &key_path,
            "-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n",
        )
        .expect("write key");
        let profile = tcps_profile_with_oci(&format!(
            r#"
            use_iam_token = true
            token_env = "OMCP_TEST_IAM_TOKEN"
            token_key_file = "{}"
            "#,
            key_path.display()
        ));
        let mut opts = connect_options_for(&profile);
        inject_iam_token_with(
            &profile,
            &mut opts,
            env_map(&[("OMCP_TEST_IAM_TOKEN", "header.payload.sig")]),
        )
        .expect("inject over tcps");
        let _ = std::fs::remove_file(&key_path);
        assert!(
            opts.iam_token_private_key
                .as_deref()
                .is_some_and(|k| k.contains("BEGIN PRIVATE KEY"))
        );
    }

    #[test]
    fn inject_ambiguous_pop_key_source_is_fail_closed() {
        let profile = tcps_profile_with_oci(
            r#"
            use_iam_token = true
            token_env = "OMCP_TEST_IAM_TOKEN"
            token_key_file = "/tmp/oraclemcp-does-not-exist.pem"
            token_key_env = "OMCP_TEST_IAM_KEY"
            "#,
        );
        let mut opts = connect_options_for(&profile);
        let err = inject_iam_token_with(
            &profile,
            &mut opts,
            env_map(&[("OMCP_TEST_IAM_TOKEN", "header.payload.sig")]),
        )
        .expect_err("ambiguous key source");
        assert_eq!(err, IamTokenError::AmbiguousKeySource);
    }

    #[test]
    fn inject_bearer_token_needs_no_pop_key() {
        // A plain OAuth2 bearer token names no key: the token resolves and no
        // proof-of-possession key is wired (the None path).
        let profile = tcps_profile_with_oci(
            r#"
            use_iam_token = true
            token_env = "OMCP_TEST_IAM_TOKEN"
            "#,
        );
        let mut opts = connect_options_for(&profile);
        inject_iam_token_with(
            &profile,
            &mut opts,
            env_map(&[("OMCP_TEST_IAM_TOKEN", "header.payload.sig")]),
        )
        .expect("inject");
        assert!(opts.iam_token.is_some());
        assert!(opts.iam_token_private_key.is_none());
    }

    #[test]
    fn inject_exec_on_non_tcps_refuses_and_never_spawns() {
        // A token_exec on a plaintext transport must be refused BEFORE the command
        // runs. The canary command would create a marker file if it were ever
        // spawned; it must not be.
        let marker = std::env::temp_dir().join(format!(
            "oraclemcp-iam-exec-nontcps-canary-{}.marker",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&marker);
        let touch = coreutil("touch");
        let profile = OracleMcpConfig::from_toml_str(&format!(
            r#"
            [[profiles]]
            name = "plain"
            connect_string = "localhost:1521/FREEPDB1"
            username = "app"
            [profiles.oci]
            use_iam_token = true
            wallet_location = "/tmp/qa73-wallet-does-not-upgrade-tcp"
            token_exec = ["{touch}", "{marker}"]
            "#,
            touch = touch,
            marker = marker.display()
        ))
        .expect("config")
        .profiles
        .into_iter()
        .next()
        .expect("profile");
        let mut opts = connect_options_for(&profile);
        let err =
            inject_iam_token_with(&profile, &mut opts, env_map(&[])).expect_err("non-tcps refused");
        assert_eq!(err, IamTokenError::NonTcpsTransport);
        assert!(opts.iam_token.is_none());
        // Give any (erroneously) spawned child a beat, then prove it never ran.
        assert!(
            !marker.exists(),
            "token_exec must NOT run on a non-TCPS transport, but it did"
        );
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn tcp_first_mixed_descriptor_refuses_before_env_resolution() {
        let mut profile = tcps_profile();
        profile.connect_string = Some(
            "(DESCRIPTION=(ADDRESS_LIST=\
                (ADDRESS=(PROTOCOL=TCP)(HOST=plain)(PORT=1521))\
                (ADDRESS=(PROTOCOL=TCPS)(HOST=secure)(PORT=2484)))\
                (CONNECT_DATA=(SERVICE_NAME=svc)))"
                .to_owned(),
        );
        let mut opts = connect_options_for(&profile);
        let lookups = std::cell::Cell::new(0usize);
        let err = inject_iam_token_with(&profile, &mut opts, |_| {
            lookups.set(lookups.get() + 1);
            Some("must.not.be.resolved".to_owned())
        })
        .expect_err("the first selected address is plaintext");
        assert_eq!(err, IamTokenError::NonTcpsTransport);
        assert_eq!(lookups.get(), 0, "token source must not be consulted");
        assert!(opts.iam_token.is_none());
    }

    #[test]
    fn tcps_first_mixed_descriptor_resolves_the_token() {
        let mut profile = tcps_profile();
        profile.connect_string = Some(
            "(DESCRIPTION=(ADDRESS_LIST=\
                (ADDRESS=(PROTOCOL=TCPS)(HOST=secure)(PORT=2484))\
                (ADDRESS=(PROTOCOL=TCP)(HOST=plain)(PORT=1521)))\
                (CONNECT_DATA=(SERVICE_NAME=svc)))"
                .to_owned(),
        );
        let mut opts = connect_options_for(&profile);
        inject_iam_token_with(
            &profile,
            &mut opts,
            env_map(&[(IAM_TOKEN_ENV, "selected.tcps.token")]),
        )
        .expect("the selected first address is TCPS");
        assert_eq!(opts.iam_token.as_deref(), Some("selected.tcps.token"));
    }

    #[test]
    fn tns_alias_transport_is_resolved_before_token_io() {
        if std::env::var_os("TNS_ADMIN").is_some() {
            return;
        }
        let mut profile = tcps_profile();
        profile.connect_string = Some("ez_plain".to_owned());
        profile.oci.as_mut().expect("OCI").wallet_location = Some(tns_fixtures_dir());
        let mut opts = connect_options_for(&profile);
        let lookups = std::cell::Cell::new(0usize);
        let err = inject_iam_token_with(&profile, &mut opts, |_| {
            lookups.set(lookups.get() + 1);
            Some("must.not.be.resolved".to_owned())
        })
        .expect_err("plaintext alias is refused");
        assert_eq!(err, IamTokenError::NonTcpsTransport);
        assert_eq!(lookups.get(), 0, "alias proof precedes token lookup");

        profile.connect_string = Some("primary_tcps".to_owned());
        let mut opts = connect_options_for(&profile);
        inject_iam_token_with(
            &profile,
            &mut opts,
            env_map(&[(IAM_TOKEN_ENV, "alias.tcps.token")]),
        )
        .expect("TCPS alias resolves before token lookup");
        assert_eq!(opts.iam_token.as_deref(), Some("alias.tcps.token"));
    }

    #[test]
    fn missing_or_malformed_target_refuses_before_token_io() {
        if std::env::var_os("TNS_ADMIN").is_some() {
            return;
        }
        for (connect_string, wallet_location) in [
            ("does_not_exist", tns_fixtures_dir()),
            ("anything", tns_fixtures_dir().join("cycle")),
        ] {
            let mut profile = tcps_profile();
            profile.connect_string = Some(connect_string.to_owned());
            profile.oci.as_mut().expect("OCI").wallet_location = Some(wallet_location);
            let mut opts = connect_options_for(&profile);
            let lookups = std::cell::Cell::new(0usize);
            let err = inject_iam_token_with(&profile, &mut opts, |_| {
                lookups.set(lookups.get() + 1);
                Some("must.not.be.resolved".to_owned())
            })
            .expect_err("unresolved target is refused");
            assert_eq!(err, IamTokenError::TransportUnresolved);
            assert_eq!(lookups.get(), 0, "token source must not be consulted");
            assert!(opts.iam_token.is_none());
        }
    }

    #[test]
    fn inject_ambiguous_source_is_fail_closed() {
        let profile = tcps_profile_with_oci(
            r#"
            use_iam_token = true
            token_file = "/etc/iam.jwt"
            token_exec = ["/usr/bin/fetch"]
            "#,
        );
        let mut opts = connect_options_for(&profile);
        let err = inject_iam_token_with(&profile, &mut opts, env_map(&[]))
            .expect_err("ambiguous source refused");
        assert_eq!(err, IamTokenError::AmbiguousSource);
        assert!(opts.iam_token.is_none());
    }

    /// EXEC-FUZZ corpus: every adversarial `token_exec` case MUST fail closed —
    /// never panic, never leak, never yield a token. Live cases use hermetic
    /// coreutils driven purely as arg-arrays.
    #[test]
    fn exec_fuzz_corpus_all_fail_closed() {
        let printf = coreutil("printf");
        let head = coreutil("head");
        let false_ = coreutil("false");
        let true_ = coreutil("true");

        // (argv, human label). Every one must return Err from get_token.
        let corpus: Vec<(Vec<String>, &str)> = vec![
            (vec![], "empty command"),
            (
                vec!["/nonexistent/fetcher-xyz".to_owned()],
                "unspawnable program",
            ),
            (vec![false_.clone()], "non-zero exit"),
            (vec![true_.clone()], "empty stdout"),
            (vec![printf.clone(), "".to_owned()], "explicit empty output"),
            (
                vec![
                    head.clone(),
                    "-c".to_owned(),
                    "8".to_owned(),
                    "/dev/zero".to_owned(),
                ],
                "null bytes",
            ),
            (
                vec![
                    head.clone(),
                    "-c".to_owned(),
                    "131072".to_owned(),
                    "/dev/zero".to_owned(),
                ],
                "over 64k output",
            ),
            (
                vec![printf.clone(), "\\377".to_owned()],
                "invalid utf-8 (0xFF)",
            ),
            (
                vec![printf.clone(), "%s".to_owned(), "bad base64 !!!".to_owned()],
                "bad base64 / spaces",
            ),
            (
                vec![printf.clone(), "%s".to_owned(), "tok; rm -rf /".to_owned()],
                "injection string in output",
            ),
            (
                vec![printf.clone(), "%s".to_owned(), "$(whoami)".to_owned()],
                "command-substitution literal",
            ),
            (
                vec![printf.clone(), "%s".to_owned(), "a|b`c`".to_owned()],
                "pipe + backticks literal",
            ),
        ];

        for (argv, label) in corpus {
            let src = ServerIamTokenSource::Exec { argv };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| src.get_token()));
            let result = result.unwrap_or_else(|_| panic!("get_token PANICKED for case: {label}"));
            assert!(
                result.is_err(),
                "corpus case must fail closed but yielded a token: {label}"
            );
        }
    }
}
