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

use std::io::Write;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::Value;

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

/// An out-of-process subprocess plugin. The host spawns it, sends one JSON
/// request on stdin, and reads one JSON response on stdout. The plugin has **no**
/// DB/secret/process handle — only what the host passes in the request.
#[derive(Clone, Debug)]
pub struct SubprocessPlugin {
    /// The command + args to spawn (e.g. `["/usr/bin/my-plugin"]`).
    pub command: Vec<String>,
}

impl SubprocessPlugin {
    /// Spawn the plugin, send `request`, and read its response. A crash / non-zero
    /// exit / malformed output is an isolated `Err` — never a host panic. The
    /// caller MUST [`check_capability`] before invoking (scope enforcement).
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
        if let Some(mut stdin) = child.stdin.take() {
            // Best-effort write; if the plugin closed stdin early we still wait.
            let _ = stdin.write_all(line.as_bytes());
            let _ = stdin.write_all(b"\n");
            // Dropping stdin sends EOF.
        }
        let output = child
            .wait_with_output()
            .map_err(|e| PluginError::Crashed(e.to_string()))?;
        if !output.status.success() {
            return Err(PluginError::Crashed(format!(
                "exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        serde_json::from_slice::<PluginResponse>(&output.stdout)
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
        let plugin = SubprocessPlugin {
            command: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "cat >/dev/null; printf '{\"ok\":true,\"data\":{\"rows\":7}}'".to_owned(),
            ],
        };
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
        let plugin = SubprocessPlugin {
            command: vec!["/bin/sh".to_owned(), "-c".to_owned(), "exit 3".to_owned()],
        };
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        // A non-zero exit is a contained Err — the host keeps running.
        assert!(matches!(plugin.run(&req), Err(PluginError::Crashed(_))));
    }

    #[test]
    fn malformed_plugin_output_is_a_protocol_error() {
        let plugin = SubprocessPlugin {
            command: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "printf 'not json'".to_owned(),
            ],
        };
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        assert!(matches!(plugin.run(&req), Err(PluginError::Protocol(_))));
    }

    #[test]
    fn missing_program_is_a_spawn_error_not_a_panic() {
        let plugin = SubprocessPlugin {
            command: vec!["/nonexistent/plugin-binary-xyz".to_owned()],
        };
        let req = PluginRequest {
            capability: PluginCapability::ReadQuery,
            args: Value::Null,
        };
        assert!(matches!(plugin.run(&req), Err(PluginError::Spawn(_))));
    }
}
