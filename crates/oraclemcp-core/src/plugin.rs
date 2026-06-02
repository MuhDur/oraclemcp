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
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use wait_timeout::ChildExt;

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
    /// stdout/stderr are drained on their own threads, so the host never blocks
    /// in `write_all` waiting on a child that is itself blocked writing stdout
    /// (the synchronous-pipe deadlock). A wall-clock deadline ([`Self::timeout`])
    /// kills a plugin that never exits.
    pub fn run(&self, request: &PluginRequest) -> Result<PluginResponse, PluginError> {
        let (program, args) = self
            .command
            .split_first()
            .ok_or_else(|| PluginError::Spawn("empty plugin command".to_owned()))?;
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| PluginError::Spawn(e.to_string()))?;

        let line =
            serde_json::to_string(request).map_err(|e| PluginError::Protocol(e.to_string()))?;

        // Write the request on a dedicated thread so we can drain stdout
        // concurrently: a >64KB request must not deadlock against a >64KB
        // response (synchronous pipe back-pressure on both directions).
        let stdin = child.stdin.take();
        let writer = std::thread::spawn(move || {
            if let Some(mut stdin) = stdin {
                // Best-effort write; if the plugin closed stdin early we still
                // wait. Dropping `stdin` at end of scope sends EOF.
                let _ = stdin.write_all(line.as_bytes());
                let _ = stdin.write_all(b"\n");
            }
        });

        // Drain stdout/stderr on their own threads so a chatty plugin can never
        // fill a pipe buffer and wedge while we are blocked elsewhere.
        let stdout = child.stdout.take();
        let stdout_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut out) = stdout {
                let _ = out.read_to_end(&mut buf);
            }
            buf
        });
        let stderr = child.stderr.take();
        let stderr_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut err) = stderr {
                let _ = err.read_to_end(&mut buf);
            }
            buf
        });

        // Bounded wait: a plugin still alive at the deadline is killed and
        // reported as an isolated crash rather than hanging the host forever.
        let status = match child
            .wait_timeout(self.timeout)
            .map_err(|e| PluginError::Crashed(e.to_string()))?
        {
            Some(status) => status,
            None => {
                let _ = child.kill();
                // Reap the direct child so it does not become a zombie.
                let _ = child.wait();
                // Do NOT join the reader threads here: a misbehaving plugin can
                // spawn a grandchild that inherits the stdout/stderr write ends,
                // so `read_to_end` may stay blocked long after we kill the direct
                // child. Returning without joining is the whole point — the host
                // must not block past the deadline. The detached threads finish
                // on their own when those pipe ends finally close; we drop the
                // handles explicitly to make that intent unmistakable.
                drop(writer);
                drop(stdout_reader);
                drop(stderr_reader);
                return Err(PluginError::Crashed(format!(
                    "plugin timed out after {}s",
                    self.timeout.as_secs()
                )));
            }
        };

        // Child exited within the deadline: collect its output. The threads
        // observe EOF once the child's pipe ends close, so the joins return.
        let _ = writer.join();
        let stdout = stdout_reader
            .join()
            .map_err(|_| PluginError::Crashed("stdout reader thread panicked".to_owned()))?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| PluginError::Crashed("stderr reader thread panicked".to_owned()))?;

        if !status.success() {
            return Err(PluginError::Crashed(format!(
                "exit {:?}: {}",
                status.code(),
                String::from_utf8_lossy(&stderr).trim()
            )));
        }
        serde_json::from_slice::<PluginResponse>(&stdout)
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
        let plugin = SubprocessPlugin::new(vec!["/nonexistent/plugin-binary-xyz".to_owned()]);
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        assert!(matches!(plugin.run(&req), Err(PluginError::Spawn(_))));
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
}
