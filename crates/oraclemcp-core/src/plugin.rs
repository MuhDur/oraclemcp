//! The sanctioned third-party-code boundary (plan §8.7, risk R7; bead P3-5 /
//! oracle-qmwz.4.5). Third-party / non-SQL custom logic runs **out-of-process**
//! (a subprocess; WASM is an equivalent sandbox), **capability-scoped**, and
//! **never with direct process/DB/secret access**. It communicates only over a
//! JSON line protocol on stdin/stdout, and every database-touching request it
//! makes is mediated by the host — so a plugin **cannot bypass the classifier,
//! RBAC, the operating-level ceiling, or the audit trail** (R1/R7): it has no
//! handle to the DB, only the host's capability API.
//!
//! This module owns the boundary contract: the capability set, the host-side
//! capability gate ([`check_capability`]), and a crash-isolated subprocess
//! runner. A plugin crash is an isolated `Err`, never a host panic.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use command_group::{CommandGroup, GroupChild};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wait_timeout::ChildExt;

/// Maximum response bytes retained from plugin stdout. Readers continue
/// draining beyond the cap so finite oversized output cannot fill the pipe.
const PLUGIN_STDOUT_CAP: usize = 1024 * 1024;
/// Maximum diagnostic bytes retained from plugin stderr. The bytes are never
/// surfaced because plugin output may contain database data or secrets.
const PLUGIN_STDERR_CAP: usize = 64 * 1024;

/// A capability a plugin may be granted. The set is **read-mediated only** —
/// there is no capability that writes, reads secrets, or touches the process /
/// filesystem directly; every grant is serviced by the host through its guards.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapability {
    /// Run a pre-classified read-only query via the host.
    ReadQuery,
    /// List objects via the host's intelligence layer.
    ListObjects,
    /// Fetch an object's DDL via the host.
    GetDdl,
    /// Search source via the host.
    SearchSource,
}

/// An operator-authored plugin manifest: the plugin's name + the capabilities it
/// is granted. Like custom tools, manifests are operator-supplied, never
/// plugin-self-declared at runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    /// The plugin name.
    pub name: String,
    /// The granted capabilities (least-privilege; empty = no DB access at all).
    pub granted: Vec<PluginCapability>,
}

impl PluginManifest {
    /// Whether `cap` is granted.
    #[must_use]
    pub fn grants(&self, cap: PluginCapability) -> bool {
        self.granted.contains(&cap)
    }
}

/// A request a plugin sends to the host (or the host sends to a plugin).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRequest {
    /// The capability being invoked.
    pub capability: PluginCapability,
    /// Capability arguments (bind values, object names, …).
    pub args: Value,
}

/// A plugin's response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginResponse {
    /// Whether the plugin succeeded.
    pub ok: bool,
    /// The structured result.
    #[serde(default)]
    pub data: Value,
}

/// Why a plugin interaction failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PluginError {
    /// The plugin requested a capability it was not granted (scope violation).
    #[error("plugin '{plugin}' requested ungranted capability {capability:?}")]
    CapabilityDenied {
        /// The plugin name.
        plugin: String,
        /// The denied capability.
        capability: PluginCapability,
    },
    /// The subprocess could not be spawned.
    #[error("plugin spawn failed: {0}")]
    Spawn(String),
    /// The subprocess crashed / exited non-zero (isolated — the host survives).
    #[error("plugin crashed (isolated): {0}")]
    Crashed(String),
    /// The plugin produced a malformed request/response.
    #[error("plugin protocol error: {0}")]
    Protocol(String),
}

/// Host-side capability gate: a plugin may only invoke a capability its manifest
/// grants. This is THE boundary — a granted capability is then serviced by the
/// host through the classifier/RBAC/audit; an ungranted one never executes.
pub fn check_capability(
    manifest: &PluginManifest,
    requested: PluginCapability,
) -> Result<(), PluginError> {
    if manifest.grants(requested) {
        Ok(())
    } else {
        Err(PluginError::CapabilityDenied {
            plugin: manifest.name.clone(),
            capability: requested,
        })
    }
}

/// Default wall-clock deadline for a single plugin invocation. A plugin that has
/// not exited by then is killed and reported as an isolated `Crashed` error so a
/// hung/never-exiting plugin can never wedge the host thread.
pub const DEFAULT_PLUGIN_TIMEOUT: Duration = Duration::from_secs(30);

fn containment_unit_is_absent(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
    ) {
        return true;
    }
    // Unix killpg(2) reports ESRCH when the direct child was already reaped and
    // its process group contains no surviving descendants. `std::io` currently
    // classifies that errno as Uncategorized, so retain the stable POSIX value.
    #[cfg(unix)]
    if error.raw_os_error() == Some(3) {
        return true;
    }
    false
}

#[derive(Debug)]
struct CappedRead {
    bytes: Vec<u8>,
    truncated: bool,
    failed: bool,
}

fn read_capped(mut reader: impl Read, cap: usize) -> CappedRead {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => {
                return CappedRead {
                    bytes,
                    truncated,
                    failed: false,
                };
            }
            Ok(read) => {
                let room = cap.saturating_sub(bytes.len());
                let retained = room.min(read);
                bytes.extend_from_slice(&chunk[..retained]);
                truncated |= retained < read;
            }
            Err(_) => {
                return CappedRead {
                    bytes,
                    truncated,
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

/// A plugin process tree held in one OS containment unit.
///
/// SAFETY: `group_spawn` creates a fresh POSIX process group on Unix and a Job
/// Object on Windows. Every post-spawn exit terminates the unit, including the
/// successful-direct-parent case, so descendants cannot retain pipes or outlive
/// the invocation. The direct child is reaped and `Drop` is a final fallback.
struct PluginProcessTree {
    child: GroupChild,
}

impl PluginProcessTree {
    fn spawn(program: &str, args: &[String]) -> std::io::Result<Self> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
            .group_spawn()
            .map(|child| PluginProcessTree { child })
    }

    fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.child.inner().stdin.take()
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
        // `kill` targets the containment unit even after the direct child has
        // exited. NotFound/InvalidInput means the already-empty unit is gone.
        let kill_ok = match self.child.kill() {
            Ok(()) => true,
            Err(error) => containment_unit_is_absent(&error),
        };
        let wait_ok = self.child.inner().wait().is_ok();
        kill_ok && wait_ok
    }
}

impl Drop for PluginProcessTree {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.inner().wait();
    }
}

struct PluginWorkers {
    stdin: JoinHandle<()>,
    stdout: JoinHandle<()>,
    stderr: JoinHandle<()>,
    stdin_rx: Receiver<bool>,
    stdout_rx: Receiver<CappedRead>,
    stderr_rx: Receiver<CappedRead>,
}

impl PluginWorkers {
    fn spawn(child: &mut PluginProcessTree, line: String) -> std::io::Result<Self> {
        let stdin = child.take_stdin();
        let (stdin_tx, stdin_rx) = mpsc::sync_channel(1);
        let stdin_worker = std::thread::Builder::new()
            .name("plugin-stdin".to_owned())
            .spawn(move || {
                let written = stdin.is_some_and(|mut input| {
                    input.write_all(line.as_bytes()).is_ok()
                        && input.write_all(b"\n").is_ok()
                        && input.flush().is_ok()
                });
                let _ = stdin_tx.send(written);
            })?;

        let stdout = child.take_stdout();
        let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
        let stdout_worker = match std::thread::Builder::new()
            .name("plugin-stdout".to_owned())
            .spawn(move || {
                let output = stdout.map_or(
                    CappedRead {
                        bytes: Vec::new(),
                        truncated: false,
                        failed: true,
                    },
                    |pipe| read_capped(pipe, PLUGIN_STDOUT_CAP),
                );
                let _ = stdout_tx.send(output);
            }) {
            Ok(worker) => worker,
            Err(error) => {
                drop(stdin_worker);
                return Err(error);
            }
        };

        let stderr = child.take_stderr();
        let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
        let stderr_worker = match std::thread::Builder::new()
            .name("plugin-stderr".to_owned())
            .spawn(move || {
                let output = stderr.map_or(
                    CappedRead {
                        bytes: Vec::new(),
                        truncated: false,
                        failed: true,
                    },
                    |pipe| read_capped(pipe, PLUGIN_STDERR_CAP),
                );
                let _ = stderr_tx.send(output);
            }) {
            Ok(worker) => worker,
            Err(error) => {
                drop(stdin_worker);
                drop(stdout_worker);
                return Err(error);
            }
        };

        Ok(PluginWorkers {
            stdin: stdin_worker,
            stdout: stdout_worker,
            stderr: stderr_worker,
            stdin_rx,
            stdout_rx,
            stderr_rx,
        })
    }

    fn collect(
        self,
        started: Instant,
        timeout: Duration,
    ) -> Result<(bool, CappedRead, CappedRead), RecvTimeoutError> {
        let stdin = receive_before(&self.stdin_rx, started, timeout);
        let stdout = receive_before(&self.stdout_rx, started, timeout);
        let stderr = receive_before(&self.stderr_rx, started, timeout);
        // Receipt means each worker has completed its blocking I/O and is only
        // returning from its closure. Dropping avoids an unbounded join while
        // retaining the same end-to-end wall deadline.
        drop(self.stdin);
        drop(self.stdout);
        drop(self.stderr);
        Ok((stdin?, stdout?, stderr?))
    }
}

/// An out-of-process subprocess plugin. The host spawns it, sends one JSON
/// request on stdin, and reads one JSON response on stdout. The plugin has **no**
/// DB/secret/process handle — only what the host passes in the request.
#[derive(Clone, Debug)]
pub struct SubprocessPlugin {
    /// The command + args to spawn (e.g. `["/usr/bin/my-plugin"]`).
    pub command: Vec<String>,
    /// Wall-clock deadline for a single invocation. A plugin still running at the
    /// deadline is killed and reported `Crashed("plugin timed out …")` — a
    /// never-exiting plugin can never block the host forever.
    pub timeout: Duration,
}

impl SubprocessPlugin {
    /// A plugin for `command` with the [`DEFAULT_PLUGIN_TIMEOUT`] deadline.
    #[must_use]
    pub fn new(command: Vec<String>) -> Self {
        SubprocessPlugin {
            command,
            timeout: DEFAULT_PLUGIN_TIMEOUT,
        }
    }

    /// Override the per-invocation deadline (builder style).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Spawn the plugin, send `request`, and read its response. A crash / non-zero
    /// exit / malformed output / timeout is an isolated `Err` — never a host
    /// panic and never an unbounded hang. The caller MUST [`check_capability`]
    /// before invoking (scope enforcement).
    ///
    /// Crash-isolation details: the request is written on a dedicated thread and
    /// capped stdout/stderr are drained on their own threads, so the host never
    /// blocks in `write_all` waiting on a child that is itself blocked writing
    /// stdout (the synchronous-pipe deadlock). One wall-clock deadline
    /// ([`Self::timeout`]) covers the direct process and all pipe workers. Every
    /// exit kills and reaps the whole process containment unit; stderr is never
    /// exposed in an error.
    pub fn run(&self, request: &PluginRequest) -> Result<PluginResponse, PluginError> {
        let started = Instant::now();
        let (program, args) = self
            .command
            .split_first()
            .ok_or_else(|| PluginError::Spawn("empty plugin command".to_owned()))?;
        let line =
            serde_json::to_string(request).map_err(|e| PluginError::Protocol(e.to_string()))?;

        let mut child = PluginProcessTree::spawn(program, args).map_err(|error| {
            PluginError::Spawn(format!(
                "operating system rejected subprocess ({:?})",
                error.kind()
            ))
        })?;
        let workers = match PluginWorkers::spawn(&mut child, line) {
            Ok(workers) => workers,
            Err(error) => {
                let _ = child.terminate_and_reap();
                return Err(PluginError::Crashed(format!(
                    "plugin I/O worker could not start ({:?})",
                    error.kind()
                )));
            }
        };

        // One deadline covers direct execution and all three pipe workers. A
        // successful direct child is not sufficient: descendants may still own
        // stdin/stdout/stderr, so the entire containment unit is terminated
        // before output collection on every path.
        let remaining = self
            .timeout
            .checked_sub(started.elapsed())
            .unwrap_or(Duration::ZERO);
        let status = child.wait_direct(remaining);
        let cleanup_succeeded = child.terminate_and_reap();
        let io = workers.collect(started, self.timeout);

        if !cleanup_succeeded {
            return Err(PluginError::Crashed(
                "plugin process-tree cleanup failed".to_owned(),
            ));
        }
        let status = match status {
            Ok(Some(status)) => status,
            Ok(None) => {
                return Err(PluginError::Crashed(format!(
                    "plugin timed out after {:?}",
                    self.timeout
                )));
            }
            Err(error) => {
                return Err(PluginError::Crashed(format!(
                    "plugin wait failed ({:?})",
                    error.kind()
                )));
            }
        };
        let (stdin_written, stdout, stderr) = match io {
            Ok(io) => io,
            Err(RecvTimeoutError::Timeout) => {
                return Err(PluginError::Crashed(format!(
                    "plugin timed out after {:?}",
                    self.timeout
                )));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(PluginError::Crashed(
                    "plugin I/O collection failed".to_owned(),
                ));
            }
        };
        if stdout.failed || stderr.failed {
            return Err(PluginError::Crashed(
                "plugin pipe collection failed".to_owned(),
            ));
        }
        if !status.success() {
            return Err(PluginError::Crashed(format!(
                "plugin exited unsuccessfully (code {:?}); stderr suppressed",
                status.code()
            )));
        }
        if !stdin_written {
            return Err(PluginError::Protocol(
                "plugin closed stdin before accepting the complete request".to_owned(),
            ));
        }
        if stdout.truncated {
            return Err(PluginError::Protocol(format!(
                "plugin stdout exceeded the {PLUGIN_STDOUT_CAP}-byte limit"
            )));
        }
        // `stderr` is deliberately neither logged nor returned, even when it
        // was truncated: it is untrusted plugin-controlled material and may
        // contain database data or credentials.
        drop(stderr);
        serde_json::from_slice::<PluginResponse>(&stdout.bytes)
            .map_err(|e| PluginError::Protocol(format!("invalid plugin response: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(caps: &[PluginCapability]) -> PluginManifest {
        PluginManifest {
            name: "demo".to_owned(),
            granted: caps.to_vec(),
        }
    }

    #[test]
    fn ungranted_capability_is_denied() {
        let m = manifest(&[PluginCapability::ReadQuery]);
        assert!(check_capability(&m, PluginCapability::ReadQuery).is_ok());
        let err = check_capability(&m, PluginCapability::GetDdl).unwrap_err();
        assert!(matches!(
            err,
            PluginError::CapabilityDenied {
                capability: PluginCapability::GetDdl,
                ..
            }
        ));
    }

    #[test]
    fn empty_manifest_grants_nothing() {
        let m = manifest(&[]);
        for cap in [
            PluginCapability::ReadQuery,
            PluginCapability::ListObjects,
            PluginCapability::GetDdl,
            PluginCapability::SearchSource,
        ] {
            assert!(check_capability(&m, cap).is_err(), "{cap:?} must be denied");
        }
    }

    #[test]
    fn subprocess_roundtrip_over_the_json_protocol() {
        // A minimal out-of-process "plugin": reads+discards stdin, emits a fixed
        // PluginResponse. Proves the IPC boundary without any DB/secret access.
        let plugin = SubprocessPlugin::new(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "cat >/dev/null; printf '{\"ok\":true,\"data\":{\"rows\":7}}'".to_owned(),
        ]);
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: serde_json::json!({"sql": "SELECT 1 FROM dual"}),
        };
        let resp = plugin.run(&req).expect("roundtrip");
        assert!(resp.ok);
        assert_eq!(resp.data["rows"], serde_json::json!(7));
    }

    #[test]
    fn crashing_plugin_is_isolated_not_a_panic() {
        let plugin = SubprocessPlugin::new(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "exit 3".to_owned(),
        ]);
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        // A non-zero exit is a contained Err — the host keeps running.
        assert!(matches!(plugin.run(&req), Err(PluginError::Crashed(_))));
    }

    #[test]
    fn malformed_plugin_output_is_a_protocol_error() {
        let plugin = SubprocessPlugin::new(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "printf 'not json'".to_owned(),
        ]);
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        assert!(matches!(plugin.run(&req), Err(PluginError::Protocol(_))));
    }

    #[test]
    fn missing_program_is_a_spawn_error_not_a_panic() {
        let secret_path = "/nonexistent/QA117-secret-plugin-binary";
        let plugin = SubprocessPlugin::new(vec![secret_path.to_owned()]);
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        let error = plugin.run(&req).expect_err("missing program must fail");
        assert!(matches!(error, PluginError::Spawn(_)));
        assert!(!error.to_string().contains(secret_path));
    }

    #[test]
    fn large_response_before_draining_stdin_does_not_deadlock() {
        // REGRESSION (oracle-clgt.9, fix 1 — concurrent I/O): a plugin that emits
        // a >64KB stdout response *before* reading stdin used to deadlock the
        // host — the host blocked in write_all (request also >64KB) while the
        // child blocked writing stdout, and neither side could drain the other.
        // With the request written on its own thread and stdout drained
        // concurrently, this must complete (never hang) and round-trip cleanly.
        //
        // The plugin writes a valid PluginResponse whose `data.blob` is ~128KB of
        // 'x', then drains+discards stdin. The host sends a request whose
        // serialized JSON is ~128KB so both pipe directions are over a 64KB
        // buffer at once.
        let plugin = SubprocessPlugin::new(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            // Emit the big response first, THEN drain stdin (the deadlocking
            // order). printf builds {"ok":true,"data":{"blob":"xxxx…"}}.
            "printf '{\"ok\":true,\"data\":{\"blob\":\"'; \
             head -c 131072 /dev/zero | tr '\\0' x; \
             printf '\"}}'; cat >/dev/null"
                .to_owned(),
        ]);
        let big_sql = "x".repeat(131_072);
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: serde_json::json!({ "sql": big_sql }),
        };
        let resp = plugin.run(&req).expect("must complete without deadlocking");
        assert!(resp.ok);
        assert_eq!(resp.data["blob"].as_str().map(str::len), Some(131_072));
    }

    #[test]
    fn never_exiting_plugin_hits_the_deadline_instead_of_hanging() {
        // REGRESSION (oracle-clgt.9, fix 2 — wait deadline): a plugin that never
        // exits (sleeps forever) used to hang wait_with_output() — and thus the
        // host thread — indefinitely. It must now be killed at the deadline and
        // reported as an isolated Crashed error.
        // The plugin sleeps far longer than the deadline (120x margin) and never
        // closes its stdout, mimicking a grandchild that inherits the pipe.
        let plugin = SubprocessPlugin::new(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "sleep 30".to_owned(),
        ])
        .with_timeout(Duration::from_millis(250));
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        let start = std::time::Instant::now();
        let err = plugin.run(&req).expect_err("must time out, not hang");
        assert!(
            matches!(err, PluginError::Crashed(ref m) if m.contains("timed out")),
            "expected a timeout Crashed error, got {err:?}"
        );
        // Must return at the deadline, not block for the full sleep. A generous
        // ceiling (well under the 30s sleep) keeps the test robust under load.
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "must return promptly at the deadline ({:?}), not block for the sleep",
            start.elapsed()
        );
    }

    #[cfg(unix)]
    fn assert_successful_parent_with_inherited_pipe_is_bounded(script: &str) {
        let plugin = SubprocessPlugin::new(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            script.to_owned(),
        ])
        .with_timeout(Duration::from_millis(250));
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        let started = std::time::Instant::now();
        let response = plugin
            .run(&req)
            .expect("valid response must not wait for descendant pipe EOF");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "successful direct child exceeded the end-to-end deadline: {:?}",
            started.elapsed()
        );
        let pid = response.data["pid"]
            .as_u64()
            .expect("response carries descendant pid")
            .to_string();
        let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < cleanup_deadline {
            if !Command::new("kill")
                .args(["-0", &pid])
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
        panic!("plugin descendant {pid} survived process-tree cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn successful_parent_with_stdout_inheriting_descendant_is_deadline_bounded() {
        for _ in 0..5 {
            assert_successful_parent_with_inherited_pipe_is_bounded(
                "IFS= read -r _; sleep 2 2>/dev/null & printf '{\"ok\":true,\"data\":{\"pid\":%s}}' \"$!\"",
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn successful_parent_with_stderr_inheriting_descendant_is_deadline_bounded() {
        for _ in 0..5 {
            assert_successful_parent_with_inherited_pipe_is_bounded(
                "IFS= read -r _; sleep 2 >/dev/null & printf '{\"ok\":true,\"data\":{\"pid\":%s}}' \"$!\"",
            );
        }
    }

    #[test]
    fn nonzero_plugin_stderr_is_never_exposed() {
        let secret = "QA117_PLUGIN_STDERR_SECRET";
        let plugin = SubprocessPlugin::new(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            format!("IFS= read -r _; printf '{secret}' >&2; exit 17"),
        ]);
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        let error = plugin.run(&req).expect_err("nonzero plugin must fail");
        let rendered = error.to_string();
        assert!(matches!(error, PluginError::Crashed(_)));
        assert!(!rendered.contains(secret), "stderr leaked: {rendered}");
        assert!(rendered.contains("stderr suppressed"), "{rendered}");
    }

    #[test]
    fn oversized_stdout_is_drained_but_rejected_at_the_cap() {
        let plugin = SubprocessPlugin::new(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            format!(
                "IFS= read -r _; head -c {} /dev/zero | tr '\\0' x",
                PLUGIN_STDOUT_CAP + 1
            ),
        ])
        .with_timeout(Duration::from_secs(5));
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        let error = plugin.run(&req).expect_err("oversized response must fail");
        assert!(
            matches!(error, PluginError::Protocol(ref message) if message.contains("exceeded")),
            "{error:?}"
        );
    }

    #[test]
    fn oversized_stderr_is_drained_capped_and_suppressed() {
        let plugin = SubprocessPlugin::new(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            format!(
                "IFS= read -r _; head -c {} /dev/zero | tr '\\0' s >&2; printf '{{\"ok\":true}}'",
                PLUGIN_STDERR_CAP * 4
            ),
        ])
        .with_timeout(Duration::from_secs(5));
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        let response = plugin.run(&req).expect("stderr is diagnostic-only");
        assert!(response.ok);
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
    fn plugin_worker_count() -> usize {
        std::fs::read_dir("/proc/self/task")
            .expect("read task directory")
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_to_string(entry.path().join("comm")).ok())
            .filter(|name| name.starts_with("plugin-"))
            .count()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repeated_timeouts_leave_no_descendants_or_io_workers() {
        let workers_before = plugin_worker_count();
        for iteration in 0..10 {
            let marker = format!("qa117-plugin-timeout-{}-{iteration}", std::process::id());
            let plugin = SubprocessPlugin::new(vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                format!("sh -c 'sleep 30' {marker} & wait"),
            ])
            .with_timeout(Duration::from_millis(50));
            let req = PluginRequest {
                capability: PluginCapability::ReadQuery,
                args: Value::Null,
            };
            let started = Instant::now();
            let error = plugin.run(&req).expect_err("waiting tree must time out");
            assert!(
                matches!(error, PluginError::Crashed(ref message) if message.contains("timed out")),
                "{error:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "short deadline was not end-to-end bounded"
            );
            let cleanup_deadline = Instant::now() + Duration::from_secs(2);
            while process_with_marker_exists(&marker) && Instant::now() < cleanup_deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                !process_with_marker_exists(&marker),
                "descendant process survived cleanup: {marker}"
            );
        }

        let settle_deadline = Instant::now() + Duration::from_secs(2);
        while plugin_worker_count() > workers_before && Instant::now() < settle_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            plugin_worker_count() <= workers_before,
            "plugin I/O workers accumulated across retries"
        );
    }
}
