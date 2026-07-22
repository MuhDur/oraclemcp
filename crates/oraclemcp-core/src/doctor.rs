//! `oraclemcp doctor` — first-class diagnostic mode (plan §9.3; bead P1-DOC /
//! oracle-qmwz.2.13). The brew/flutter/cargo-doctor pattern: a CLI onboarding +
//! triage step that runs a fixed set of checks, prints an **actionable fix** for
//! every non-pass, and **exits non-zero** on any failure.
//!
//! Checks are **progressive** (per the bead's design note): each lights up as
//! its backing feature lands. A check whose feature/state is not present this
//! run is reported `Skip` *with a reason* — never a fake `Pass`. The offline
//! subset (thin driver posture, TNS/wallet, NLS, classifier self-test) runs
//! WITHOUT a live database; the live subset (connectivity, role/standby,
//! privilege tier) runs only when a connection is supplied.
//!
//! In-MCP, the live-state subset is mirrored by `oracle_capabilities` (an agent
//! can call it); `doctor` is the CLI mode.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use cap_fs_ext::{DirExt as _, FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir as CapDir, DirBuilder as CapDirBuilder, OpenOptions as CapOpenOptions};
use oraclemcp_db::{
    DRIVER_VERSION, DiagnosticsSource, OracleConnection, OracleVpdRlsObservation,
    OracleVpdRlsObservationStatus, canonical_nls_statements, detect_oracle_driver, detect_standby,
    observe_vpd_rls_for_schema, preflight, probe_privileges, probe_write_posture,
    supported_wallet_modes,
};
use oraclemcp_error::{ErrorClass, classify_ora_code, parse_ora_code};
use oraclemcp_guard::{Classifier, ClassifierConfig, OperatingLevel};
use serde::Serialize;
use serde_json::{Value, json};

use crate::capabilities::SkippedCustomTool;
use crate::service_app::ServiceAppDoctorSnapshot;

mod auth;
pub use auth::{
    DoctorAuthCapabilities, DoctorAuthModeCapability, DoctorAuthModeKind, DoctorAuthModeSupport,
    DoctorIamTokenSourceKind, DoctorIamTokenSourceObservation,
};

#[cfg(unix)]
use cap_std::fs::{DirBuilderExt as _, OpenOptionsExt as _};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// A single check's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// The check passed.
    Pass,
    /// A non-fatal concern the operator should address.
    Warn,
    /// A failure — `doctor` exits non-zero.
    Fail,
    /// Not applicable this run (offline, or a feature not yet enabled).
    Skip,
}

impl CheckStatus {
    fn symbol(self) -> char {
        match self {
            CheckStatus::Pass => '✓',
            CheckStatus::Warn => '⚠',
            CheckStatus::Fail => '✗',
            CheckStatus::Skip => '-',
        }
    }
}

/// One diagnostic check result.
#[derive(Clone, Debug, Serialize)]
pub struct CheckResult {
    /// Stable check number.
    pub id: u8,
    /// Short check name.
    pub name: String,
    /// Outcome.
    pub status: CheckStatus,
    /// What was observed.
    pub detail: String,
    /// An actionable fix (present on `Warn`/`Fail`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// Machine-stable failure class for agent triage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<ErrorClass>,
    /// Precise auth/transport classification for a connectivity failure (A5):
    /// driver-unsupported auth vs bad-creds vs TLS vs listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<AuthModeClass>,
    /// Precise wallet-file diagnostic for driver wallet setup failures (A4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_error: Option<DoctorWalletDiagnostic>,
    /// Static wallet-posture verdict from the offline active probe (B2.1): the
    /// diagnostic of "what the driver's wallet loader would do" for the resolved
    /// wallet directory, inferred without opening a live DB connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_posture: Option<DoctorWalletPostureReport>,
    /// Offline cert-expiry diagnostic for the resolved wallet (K1; iec3.6.6):
    /// the earliest `notAfter` across the wallet's certificates and the whole
    /// days until it. Present only when the resolved wallet holds a parseable
    /// certificate; drives a WARN when a cert is within the expiry threshold or
    /// already expired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_cert_expiry: Option<DoctorWalletCertExpiry>,
    /// Parsed Oracle error code, when a check failed because Oracle returned ORA-NNNNN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ora_code: Option<i32>,
}

impl CheckResult {
    fn new(id: u8, name: &str, status: CheckStatus, detail: impl Into<String>) -> Self {
        CheckResult {
            id,
            name: name.to_owned(),
            status,
            detail: detail.into(),
            fix: None,
            failure_class: None,
            auth_mode: None,
            wallet_error: None,
            wallet_posture: None,
            wallet_cert_expiry: None,
            ora_code: None,
        }
    }
    fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
    fn with_failure_class(mut self, class: ErrorClass) -> Self {
        self.failure_class = Some(class);
        self
    }
    fn with_auth_mode(mut self, class: AuthModeClass) -> Self {
        self.auth_mode = Some(class);
        self
    }
    fn with_wallet_error(mut self, wallet_error: Option<DoctorWalletDiagnostic>) -> Self {
        self.wallet_error = wallet_error;
        self
    }
    fn with_wallet_posture(mut self, posture: DoctorWalletPostureReport) -> Self {
        self.wallet_posture = Some(posture);
        self
    }
    fn with_wallet_cert_expiry(mut self, expiry: Option<DoctorWalletCertExpiry>) -> Self {
        self.wallet_cert_expiry = expiry;
        self
    }
    fn with_oracle_error(mut self, message: &str) -> Self {
        if let Some(code) = parse_ora_code(message) {
            self.ora_code = Some(code);
            self.failure_class = Some(classify_ora_code(code));
        }
        self
    }
}

/// Configured/effective level pair for doctor profile-cap reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorLevelCaps {
    /// Fresh-session default level.
    pub default_level: OperatingLevel,
    /// Maximum level this profile can ever reach.
    pub max_level: OperatingLevel,
}

/// Non-secret profile authority posture surfaced by `doctor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorProfileCaps {
    /// Profile name.
    pub profile: String,
    /// Operator-configured profile levels before effective safety clamps.
    pub configured: DoctorLevelCaps,
    /// Effective profile levels after protected/standby/read-only clamps.
    pub effective: DoctorLevelCaps,
    /// Whether this profile is protected.
    pub protected: bool,
    /// Whether config pins this profile as a read-only standby.
    pub read_only_standby: bool,
}

/// Service-manager caps as configured by `oraclemcp service install`, and as
/// observed for the current process/cgroup by `doctor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorServiceUnitCaps {
    /// Service manager family, e.g. `systemd_user`, `launchd_user`, or
    /// `windows_service`.
    pub manager: String,
    /// Caps the generated service definition configures.
    pub configured: DoctorServiceUnitLimitCaps,
    /// Caps visible to the current process. When `doctor` is not itself running
    /// under the generated service, these are still useful host ceilings.
    pub effective: DoctorServiceUnitLimitCaps,
    /// Honest caveats about platform-specific limits or unavailable probes.
    pub notes: Vec<String>,
}

/// Resource-limit row for service-unit cap reporting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorServiceUnitLimitCaps {
    /// systemd `Type=notify` + `NotifyAccess=main`, when configured/effective.
    pub notify: Option<String>,
    /// Restart policy, when configured/effective.
    pub restart_policy: Option<String>,
    /// Open-file limit.
    pub limit_nofile: Option<u64>,
    /// Thread/process task cap (`TasksMax`, `RLIMIT_NPROC`, or cgroup pids).
    pub tasks_max: Option<u64>,
    /// Memory cgroup cap, in bytes.
    pub memory_max_bytes: Option<u64>,
    /// Linux OOM score adjustment.
    pub oom_score_adjust: Option<i16>,
}

/// `doctor --fix` policy summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorFixPolicy {
    /// The only write scope `doctor --fix` may ever use.
    pub write_scope: &'static str,
    /// Targets `doctor --fix` must never mutate.
    pub forbidden_targets: Vec<&'static str>,
    /// Whether every future mutation must have a backup.
    pub backups_required: bool,
    /// Whether every future mutation must publish an undo record.
    pub undo_required: bool,
    /// Rule-1 posture for local files.
    pub delete_policy: &'static str,
}

/// One out-of-scope `doctor --fix` refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorFixRefusal {
    /// Check id that produced this refusal.
    pub check_id: u8,
    /// Check name.
    pub check: String,
    /// Stable target name.
    pub target: &'static str,
    /// Target scope.
    pub scope: &'static str,
    /// Why doctor refused to mutate it.
    pub reason: &'static str,
}

/// One future mutation row. G8 intentionally emits none for out-of-scope checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorFixMutation {
    /// Stable mutation id.
    pub id: &'static str,
    /// Service-local target.
    pub target: &'static str,
    /// Backup artifact path or token.
    pub backup: String,
    /// Undo artifact path or token.
    pub undo: String,
}

/// Filesystem layout inputs for the 0.4.x -> 0.6.0 service-state migration.
///
/// The legacy audit file was under the config directory. The current default
/// keeps durable service state under `$XDG_STATE_HOME/oraclemcp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorStateLayout {
    /// Legacy default audit JSONL path (`~/.config/oraclemcp/audit.jsonl`).
    pub legacy_audit_path: PathBuf,
    /// Current default audit JSONL path under the XDG state file store.
    pub current_audit_path: PathBuf,
    /// Directory where doctor writes backup artifacts before migration writes.
    pub migration_backup_dir: PathBuf,
    /// True when `[audit].path` is explicitly configured; doctor must not
    /// override an operator-owned audit location.
    pub audit_path_configured: bool,
}

/// Signed-audit posture derived by the CLI without constructing an auditor.
///
/// `doctor` must not claim that an audit path has an active auditor merely
/// because the path is the default. The binary supplies this posture from the
/// same reachable-level decision that startup uses, without resolving secrets
/// or opening the audit file during an offline diagnostic run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DoctorAuditPosture {
    /// A signing-key source is configured; server startup will validate it and
    /// arm the signed chain at this path.
    SigningKeyConfigured {
        /// Candidate signed-audit path after applying the default.
        path: PathBuf,
    },
    /// No signing key is configured and every reachable profile is read-only,
    /// so startup intentionally constructs no auditor. The optional path names
    /// the separately configured unsigned refusal trail; it is never a signed
    /// audit path and is not tamper-evident.
    DisabledReadOnly {
        /// Configured unsigned-refusal trail path, absent when opted out.
        unsigned_refusal_trail_path: Option<PathBuf>,
    },
    /// No signing key is configured even though a reachable profile can write;
    /// startup refuses before serving.
    StartupRefused {
        /// Highest operating level the server could reach.
        reachable_ceiling: OperatingLevel,
    },
    /// The CLI could not derive an audit posture from the configuration.
    Unavailable {
        /// Non-secret reason the posture could not be derived.
        reason: String,
    },
}

/// Safe, scoped migration plan for a legacy audit JSONL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorLegacyStateMigrationPlan {
    /// Legacy source. It is copied, never rewritten or deleted.
    pub legacy_audit_path: PathBuf,
    /// Current target. It must not already exist.
    pub current_audit_path: PathBuf,
    /// Backup artifact written before the target is created.
    pub backup_path: PathBuf,
}

/// Overall `doctor --fix` outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorFixOutcome {
    /// No fixable mutation or refusal was produced.
    Noop,
    /// One or more scoped service-local mutations were applied.
    Applied,
    /// One or more blockers remain, but there is no scoped repair plan.
    UnresolvedFindings,
    /// One or more findings had fixes, but every candidate was out of scope.
    RefusedOutOfScope,
}

/// Machine-readable `doctor --fix` report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorFixReport {
    /// Whether `--fix` was requested.
    pub requested: bool,
    /// High-level outcome.
    pub outcome: DoctorFixOutcome,
    /// Process exit code for this fix run.
    pub exit_code: u8,
    /// Safety policy applied before any mutation.
    pub policy: DoctorFixPolicy,
    /// Per-finding refusals.
    pub refusals: Vec<DoctorFixRefusal>,
    /// Performed mutations. Empty until a service-local repair is explicitly wired.
    pub mutations: Vec<DoctorFixMutation>,
}

impl DoctorFixReport {
    /// True when fix mode found any out-of-scope action.
    #[must_use]
    pub fn refused(&self) -> bool {
        !self.refusals.is_empty()
    }
}

/// Inputs for a `doctor` run. A `None` connection runs the offline subset.
#[derive(Default)]
pub struct DoctorContext<'a> {
    /// A live connection, if one could be opened (enables the live checks).
    pub conn: Option<&'a dyn OracleConnection>,
    /// The optional stateless-read pool connection opened for this profile.
    /// When present, online doctor must observe it separately from the pinned
    /// session before declaring the configured hybrid wiring healthy.
    pub stateless_conn: Option<&'a dyn OracleConnection>,
    /// Whether the selected profile configured a stateless-read pool. A `true`
    /// value with no [`Self::stateless_conn`] means pool bootstrap was not
    /// observed to succeed, even if the pinned session is usable.
    pub stateless_pool_configured: bool,
    /// Configuration-load error observed before a profile could be resolved.
    ///
    /// Kept distinct from [`Self::connection_error`] so a malformed
    /// `profiles.toml` is reported as a configuration failure, not as a
    /// firewall, listener, or database-connectivity problem.
    pub configuration_error: Option<String>,
    /// Connection/setup error observed before a live connection was available.
    pub connection_error: Option<String>,
    /// `TNS_ADMIN` (tnsnames/wallet directory), if set.
    pub tns_admin: Option<String>,
    /// A configured wallet location, if any.
    pub wallet_location: Option<String>,
    /// The resolved wallet password (from `wallet_password_ref`), if any. Used
    /// ONLY transiently by the offline wallet-posture probe (B2.1) to attempt a
    /// static decrypt of an encrypted `ewallet.pem`/`.p12`; it is never rendered,
    /// serialized, or included in any doctor output. `DoctorContext` is not
    /// `Serialize`, and the probe returns only typed error classes — never the
    /// password, the wallet path, or key material.
    pub wallet_password: Option<String>,
    /// The resolved OCI IAM database token (a JWT), if one is configured for this
    /// profile through the legacy static-token path. Used ONLY transiently by
    /// the IAM-token near-expiry check to read the JWT `exp` claim (a diagnostic,
    /// no signature validation); it is never rendered, serialized, or included
    /// in any doctor output. Refreshable source profiles should leave this
    /// unset and populate [`Self::iam_token_source`] instead.
    pub iam_token: Option<String>,
    /// Non-secret IAM token-source observation for refreshable source profiles.
    /// Doctor reports this as observation, not proof that a token was fetched.
    pub iam_token_source: Option<DoctorIamTokenSourceObservation>,
    /// True if a `protected` profile has `max_level` above `READ_ONLY` — a
    /// misconfiguration the privilege check warns about (offline-detectable).
    pub protected_profile_writable: bool,
    /// Runtime connection strategy label, such as `single_session` or
    /// `hybrid_pool`. This is non-secret operator-facing metadata.
    pub connection_strategy: Option<String>,
    /// Whether a profile was resolved far enough to know its timeout posture.
    pub call_timeout_resolved: bool,
    /// Resolved Oracle call timeout. `None` with `call_timeout_resolved = true`
    /// means the profile explicitly disabled the driver call timeout.
    pub call_timeout: Option<Duration>,
    /// Authored Oracle Net transport connect timeout in seconds. `None` keeps
    /// the thin driver's 20s descriptor/default timeout.
    pub connect_timeout_seconds: Option<u64>,
    /// Authored per-read inactivity deadline in seconds (B1). `None` keeps the
    /// driver's unbounded idle-read behavior; an authored `0` is a misconfig the
    /// call-timeout check advises removing (mirrors `connect_timeout_seconds`).
    pub inactivity_timeout_seconds: Option<u64>,
    /// Authored Oracle EXPIRE_TIME dead-connection-detection interval in MINUTES
    /// (B1). `None` disables DCD probes; an authored `0` is a misconfig the
    /// call-timeout check advises removing.
    pub keepalive_minutes: Option<u64>,
    /// Whether the optional plsql-intelligence engine is available to this
    /// server build (B5). Reported by the trio-stack provenance check. The full
    /// detection contract is B5.1; this is the honest present/absent signal the
    /// binary knows (its `plsql-intelligence` feature). Defaults to `false`
    /// (`not detected`) for library callers and offline runs.
    pub plsql_intelligence_detected: bool,
    /// Whether a proxy / least-privilege connect user is configured (A2).
    pub proxy_user: bool,
    /// Whether this run was explicitly allowed to open a live connection.
    pub online: bool,
    /// Non-secret profile authority posture.
    pub profile_caps: Option<DoctorProfileCaps>,
    /// Secret-free auth support matrix for the inspected profile.
    pub auth_capabilities: Option<DoctorAuthCapabilities>,
    /// Service/lane health snapshot.
    pub service_health: Option<ServiceAppDoctorSnapshot>,
    /// Service-manager resource caps snapshot.
    pub service_unit_caps: Option<DoctorServiceUnitCaps>,
    /// Service-state layout paths used to detect 0.4.x legacy files.
    pub state_layout: Option<DoctorStateLayout>,
    /// Signed-audit posture supplied by the binary from its startup policy.
    /// This is separate from the state-layout migration inputs: a default path
    /// does not imply that an auditor was constructed.
    pub audit_posture: Option<DoctorAuditPosture>,
    /// Exact setup values that must never appear in doctor output.
    pub sensitive_values: Vec<String>,
    /// A non-blocking, offline credential hint for a profile whose credential
    /// env var is still unset — names the exact env var to export and the
    /// `doctor --online --profile <name>` command to verify it (TNS-onboarding
    /// bead `.14`). `None` when the credential is already set or not an `env:`
    /// ref. Never a secret value; only the variable NAME.
    pub credential_env_hint: Option<String>,
    /// Custom-tool definitions skipped during startup because they were invalid
    /// or exceeded the selected profile ceiling. A skipped tool is never
    /// advertised or executable; signature failures are not represented here
    /// because they still fail startup.
    pub skipped_custom_tools: Vec<SkippedCustomTool>,
}

/// The full diagnostic report.
#[derive(Clone, Debug, Serialize)]
pub struct DoctorReport {
    /// All checks, in order.
    pub checks: Vec<CheckResult>,
    /// Non-secret profile authority posture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_caps: Option<DoctorProfileCaps>,
    /// Secret-free auth support matrix for the inspected profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_capabilities: Option<DoctorAuthCapabilities>,
    /// Service/lane health snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_health: Option<ServiceAppDoctorSnapshot>,
    /// Service-manager resource caps snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_unit_caps: Option<DoctorServiceUnitCaps>,
    /// `doctor --fix` policy/refusal outcome when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<DoctorFixReport>,
}

impl DoctorReport {
    /// Whether any check failed.
    #[must_use]
    pub fn any_failed(&self) -> bool {
        self.checks.iter().any(|c| c.status == CheckStatus::Fail)
    }

    /// The process exit code (non-zero iff any check failed).
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        i32::from(self.any_failed())
    }

    /// Machine-readable report.
    #[must_use]
    pub fn to_json(&self) -> Value {
        self.to_json_with_exit_code(self.exit_code())
    }

    /// Machine-readable report with a caller-selected process exit code.
    #[must_use]
    pub fn to_json_with_exit_code(&self, exit_code: i32) -> Value {
        let mut value = json!({
            "checks": self.checks,
            "ok": !self.any_failed(),
            "exit_code": exit_code,
        });
        if let Some(profile_caps) = &self.profile_caps {
            value["profile_caps"] = serde_json::to_value(profile_caps).unwrap_or(Value::Null);
        }
        if let Some(auth_capabilities) = &self.auth_capabilities {
            value["auth_capabilities"] =
                serde_json::to_value(auth_capabilities).unwrap_or(Value::Null);
        }
        if let Some(service_health) = &self.service_health {
            value["service_health"] = serde_json::to_value(service_health).unwrap_or(Value::Null);
        }
        if let Some(service_unit_caps) = &self.service_unit_caps {
            value["service_unit_caps"] =
                serde_json::to_value(service_unit_caps).unwrap_or(Value::Null);
        }
        if let Some(fix) = &self.fix {
            value["fix"] = serde_json::to_value(fix).unwrap_or(Value::Null);
        }
        value
    }

    /// Human-readable report (one line per check + indented fixes).
    #[must_use]
    pub fn to_text(&self) -> String {
        self.to_text_with_exit_code(self.exit_code())
    }

    /// Human-readable report with a caller-selected process exit code.
    #[must_use]
    pub fn to_text_with_exit_code(&self, exit_code: i32) -> String {
        let mut out = String::from("oraclemcp doctor\n");
        if let Some(profile_caps) = &self.profile_caps {
            out.push_str(&format!(
                "profile caps: {} configured default={:?} max={:?}; effective default={:?} max={:?}; protected={}\n",
                profile_caps.profile,
                profile_caps.configured.default_level,
                profile_caps.configured.max_level,
                profile_caps.effective.default_level,
                profile_caps.effective.max_level,
                profile_caps.protected,
            ));
        }
        if let Some(auth_capabilities) = &self.auth_capabilities {
            let mut supported = Vec::new();
            let mut unsupported = Vec::new();
            for mode in &auth_capabilities.modes {
                match mode.support {
                    DoctorAuthModeSupport::Supported => supported.push(mode.kind.as_str()),
                    DoctorAuthModeSupport::UnsupportedInThin => {
                        unsupported.push(mode.kind.as_str())
                    }
                }
            }
            out.push_str(&format!(
                "auth capabilities: driver={} selected={} supported={}; unsupported_in_thin={}\n",
                auth_capabilities.driver,
                auth_capabilities.selected.as_str(),
                supported.join(","),
                unsupported.join(","),
            ));
        }
        if let Some(service_health) = &self.service_health {
            out.push_str(&format!(
                "service health: spectral={} tasks={} active={} cancelling={} stuck={}\n",
                service_health.spectral.state,
                service_health.task_inspector.summary.total_tasks,
                service_health.task_inspector.active_tasks,
                service_health.task_inspector.summary.cancelling,
                service_health.task_inspector.summary.stuck_count,
            ));
        }
        if let Some(service_unit_caps) = &self.service_unit_caps {
            out.push_str(&format!(
                "service unit caps: manager={} configured nofile={:?} tasks={:?} memory={:?} oom={:?}; effective nofile={:?} tasks={:?} memory={:?} oom={:?}\n",
                service_unit_caps.manager,
                service_unit_caps.configured.limit_nofile,
                service_unit_caps.configured.tasks_max,
                service_unit_caps.configured.memory_max_bytes,
                service_unit_caps.configured.oom_score_adjust,
                service_unit_caps.effective.limit_nofile,
                service_unit_caps.effective.tasks_max,
                service_unit_caps.effective.memory_max_bytes,
                service_unit_caps.effective.oom_score_adjust,
            ));
        }
        for c in &self.checks {
            out.push_str(&format!(
                "[{}] {}. {} — {}\n",
                c.status.symbol(),
                c.id,
                c.name,
                c.detail
            ));
            if let Some(fix) = &c.fix {
                out.push_str(&format!("      fix: {fix}\n"));
            }
        }
        if let Some(fix) = &self.fix {
            out.push_str(&format!(
                "fix: {:?} (refusals={}, mutations={}, exit {})\n",
                fix.outcome,
                fix.refusals.len(),
                fix.mutations.len(),
                fix.exit_code,
            ));
        }
        let verdict = if self.any_failed() { "FAILED" } else { "ok" };
        out.push_str(&format!("verdict: {verdict} (exit {exit_code})\n"));
        out
    }

    /// Attach a `doctor --fix` policy report.
    #[must_use]
    pub fn with_fix_report(mut self) -> Self {
        self.fix = Some(self.plan_fix_report());
        self
    }

    /// Attach a `doctor --fix` policy report with already-applied scoped
    /// service-local mutations.
    #[must_use]
    pub fn with_fix_report_mutations(mut self, mutations: Vec<DoctorFixMutation>) -> Self {
        self.fix = Some(self.plan_fix_report_with_mutations(mutations));
        self
    }

    /// Build the `doctor --fix` policy report without mutating anything.
    #[must_use]
    pub fn plan_fix_report(&self) -> DoctorFixReport {
        self.plan_fix_report_with_mutations(Vec::new())
    }

    /// Build the `doctor --fix` policy report, including scoped mutations the
    /// caller already applied through the doctor migration helper.
    #[must_use]
    pub fn plan_fix_report_with_mutations(
        &self,
        mutations: Vec<DoctorFixMutation>,
    ) -> DoctorFixReport {
        let refusals = self
            .checks
            .iter()
            .filter(|check| {
                matches!(check.status, CheckStatus::Warn | CheckStatus::Fail) && check.fix.is_some()
            })
            .map(fix_refusal_for_check)
            .collect::<Vec<_>>();
        let outcome = if refusals.is_empty() {
            if self.any_failed() {
                DoctorFixOutcome::UnresolvedFindings
            } else if !mutations.is_empty() {
                DoctorFixOutcome::Applied
            } else {
                DoctorFixOutcome::Noop
            }
        } else {
            DoctorFixOutcome::RefusedOutOfScope
        };
        let exit_code = match outcome {
            DoctorFixOutcome::Noop => 0,
            DoctorFixOutcome::Applied => 0,
            DoctorFixOutcome::UnresolvedFindings => 2,
            DoctorFixOutcome::RefusedOutOfScope => 4,
        };
        DoctorFixReport {
            requested: true,
            outcome,
            exit_code,
            policy: doctor_fix_policy(),
            refusals,
            mutations,
        }
    }
}

fn doctor_fix_policy() -> DoctorFixPolicy {
    DoctorFixPolicy {
        write_scope: "service_local_state_only",
        forbidden_targets: vec![
            "oracle_database",
            "audit_hash_chain",
            "classifier",
            "profile_max_level",
        ],
        backups_required: true,
        undo_required: true,
        delete_policy: "quarantine_not_delete",
    }
}

enum LegacyStateLayoutObservation {
    Current,
    ExplicitAuditPath,
    LegacyAuditOnly,
    LegacyAndCurrentAuditIdentical,
    LegacyAndCurrentAudit,
    Unsafe(String),
}

fn inspect_legacy_state_layout(layout: &DoctorStateLayout) -> LegacyStateLayoutObservation {
    if layout.audit_path_configured {
        return LegacyStateLayoutObservation::ExplicitAuditPath;
    }

    let legacy = match regular_file_status(&layout.legacy_audit_path) {
        Ok(status) => status,
        Err(reason) => return LegacyStateLayoutObservation::Unsafe(reason),
    };
    let current = match regular_file_status(&layout.current_audit_path) {
        Ok(status) => status,
        Err(reason) => return LegacyStateLayoutObservation::Unsafe(reason),
    };

    match (legacy, current) {
        (false, _) => LegacyStateLayoutObservation::Current,
        (true, false) => LegacyStateLayoutObservation::LegacyAuditOnly,
        (true, true) => {
            match audit_files_match(&layout.legacy_audit_path, &layout.current_audit_path) {
                Ok(true) => LegacyStateLayoutObservation::LegacyAndCurrentAuditIdentical,
                Ok(false) => LegacyStateLayoutObservation::LegacyAndCurrentAudit,
                Err(reason) => LegacyStateLayoutObservation::Unsafe(reason),
            }
        }
    }
}

fn audit_files_match(left: &Path, right: &Path) -> Result<bool, String> {
    let left = fs::read(left).map_err(|e| format!("failed to read {}: {e}", left.display()))?;
    let right = fs::read(right).map_err(|e| format!("failed to read {}: {e}", right.display()))?;
    Ok(left == right)
}

fn regular_file_status(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(format!("{} is a symlink", path.display()))
        }
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(format!("{} is not a regular file", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Apply the scoped 0.4.x -> 0.6.0 legacy audit-layout migration.
///
/// The migration copies the legacy audit JSONL byte-for-byte into the current
/// XDG state audit path when and only when the current target is absent. The
/// legacy file is never rewritten or removed, and an identical backup artifact
/// is written before the current target is created.
pub fn apply_legacy_state_migration(
    layout: Option<&DoctorStateLayout>,
) -> Result<Option<DoctorFixMutation>, String> {
    let Some(layout) = layout else {
        return Ok(None);
    };
    match inspect_legacy_state_layout(layout) {
        LegacyStateLayoutObservation::LegacyAuditOnly => {}
        LegacyStateLayoutObservation::Current
        | LegacyStateLayoutObservation::LegacyAndCurrentAuditIdentical
        | LegacyStateLayoutObservation::ExplicitAuditPath => return Ok(None),
        LegacyStateLayoutObservation::LegacyAndCurrentAudit => {
            return Err(format!(
                "both legacy audit {} and current audit {} exist; refusing to merge append-only audit chains",
                layout.legacy_audit_path.display(),
                layout.current_audit_path.display()
            ));
        }
        LegacyStateLayoutObservation::Unsafe(reason) => return Err(reason),
    }

    let bytes = read_regular_file_nofollow(&layout.legacy_audit_path)?;
    let backup_dir = open_or_create_private_dir_nofollow(&layout.migration_backup_dir)?;
    let backup_name = OsString::from(format!(
        "legacy-audit-jsonl.{}.backup",
        doctor_migration_timestamp_suffix()
    ));
    let backup_path = layout.migration_backup_dir.join(&backup_name);
    write_new_private_file_at(&backup_dir, &backup_name, &backup_path, &bytes)?;

    let current_parent_path = parent_path(&layout.current_audit_path)?;
    let current_name = file_name(&layout.current_audit_path)?;
    let current_parent = open_or_create_private_dir_nofollow(current_parent_path)?;
    write_new_atomic_file_at(
        &current_parent,
        current_parent_path,
        current_name,
        &layout.current_audit_path,
        &bytes,
    )?;
    Ok(Some(DoctorFixMutation {
        id: "legacy_state_audit_jsonl_migration",
        target: "service_local_state",
        backup: backup_path.display().to_string(),
        undo: format!(
            "legacy source preserved at {}; restore {} from backup {} if rollback is required",
            layout.legacy_audit_path.display(),
            layout.current_audit_path.display(),
            backup_path.display()
        ),
    }))
}

fn doctor_migration_timestamp_suffix() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}-{:09}", now.as_secs(), now.subsec_nanos())
}

fn parent_path(path: &Path) -> Result<&Path, String> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("invalid migration target {}", path.display()))
}

fn file_name(path: &Path) -> Result<&OsStr, String> {
    path.file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| format!("invalid migration target {}", path.display()))
}

/// Open the immutable root of `path`, then walk each directory component with
/// `openat`-style capability operations. The held directory can be renamed,
/// but no later create/link operation will follow its replacement pathname.
fn capability_root(path: &Path) -> Result<CapDir, String> {
    let root = if path.is_absolute() {
        #[cfg(windows)]
        {
            let mut root = PathBuf::new();
            for component in path.components() {
                root.push(component.as_os_str());
                if matches!(component, Component::RootDir) {
                    break;
                }
            }
            root
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/")
        }
    } else {
        PathBuf::from(".")
    };
    CapDir::open_ambient_dir(&root, ambient_authority()).map_err(|e| {
        format!(
            "failed to open migration directory root {}: {e}",
            root.display()
        )
    })
}

fn open_existing_dir_nofollow(path: &Path) -> Result<CapDir, String> {
    let mut current = capability_root(path)?;
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                current = current
                    .open_dir_nofollow(name)
                    .map_err(|e| format!("{} is not a safe directory: {e}", path.display()))?;
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                return Err(format!(
                    "{} is not a safe directory: parent traversal is refused",
                    path.display()
                ));
            }
        }
    }
    Ok(current)
}

fn open_or_create_private_dir_nofollow(path: &Path) -> Result<CapDir, String> {
    let mut current = capability_root(path)?;
    let mut has_normal_component = false;
    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::ParentDir) {
                return Err(format!(
                    "{} is not a safe directory: parent traversal is refused",
                    path.display()
                ));
            }
            continue;
        };
        has_normal_component = true;
        match current.open_dir_nofollow(name) {
            Ok(next) => current = next,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = CapDirBuilder::new();
                #[cfg(unix)]
                builder.mode(0o700);
                match current.create_dir_with(name, &builder) {
                    Ok(()) => {}
                    Err(race) if race.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(format!("failed to create {}: {error}", path.display()));
                    }
                }
                current = current.open_dir_nofollow(name).map_err(|e| {
                    format!(
                        "{} is not a safe directory after creation: {e}",
                        path.display()
                    )
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "{} is not a safe directory: {error}",
                    path.display()
                ));
            }
        }
    }
    if has_normal_component {
        set_private_dir_permissions(&current, path)?;
    }
    Ok(current)
}

fn set_private_dir_permissions(dir: &CapDir, display_path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        // `chmod` the directory THROUGH its own capability handle rather than
        // turning that handle into a std File and calling fchmod on it: cap-std
        // opens a Dir without the access mode fchmod requires, so the old
        // `into_std_file().set_permissions(..)` returned EBADF and every
        // migration that had to create a private directory failed
        // (bead oraclemcp-7f4o9). `set_permissions` is *at-relative, so this
        // keeps the no-follow property the surrounding code exists to provide.
        dir.set_permissions(
            std::path::Component::CurDir.as_os_str(),
            cap_std::fs::Permissions::from_std(fs::Permissions::from_mode(0o700)),
        )
        .map_err(|e| {
            format!(
                "failed to set private permissions on {}: {e}",
                display_path.display()
            )
        })?;
    }
    #[cfg(not(unix))]
    let _ = (dir, display_path);
    Ok(())
}

fn read_regular_file_nofollow(path: &Path) -> Result<Vec<u8>, String> {
    let parent_path = parent_path(path)?;
    let name = file_name(path)?;
    let parent = open_existing_dir_nofollow(parent_path)?;
    let metadata = parent.symlink_metadata(name).map_err(|e| {
        format!(
            "failed to inspect legacy audit JSONL {}: {e}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|e| format!("failed to open legacy audit JSONL {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read legacy audit JSONL {}: {e}", path.display()))?;
    Ok(bytes)
}

fn write_new_private_file_at(
    parent: &CapDir,
    name: &OsStr,
    display_path: &Path,
    bytes: &[u8],
) -> Result<FileIdentity, String> {
    let mut options = CapOpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|e| format!("failed to create {}: {e}", display_path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("failed to write {}: {e}", display_path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("failed to inspect {}: {e}", display_path.display()))?;
    sync_cap_dir(parent, display_path)?;
    Ok(FileIdentity::from_metadata(&metadata))
}

/// Install a fully-fsynced temp through an atomic create-new hard link. Unlike
/// `rename`, the link fails if an attacker creates the destination after the
/// first observation, while still making the completed file appear atomically.
fn write_new_atomic_file_at(
    parent: &CapDir,
    parent_path: &Path,
    name: &OsStr,
    display_path: &Path,
    bytes: &[u8],
) -> Result<(), String> {
    if regular_file_status_at(parent, name, display_path)? {
        return Err(format!("{} already exists", display_path.display()));
    }
    let temp_name = OsString::from(format!(
        ".{}.tmp.{}.{}",
        name.to_string_lossy(),
        std::process::id(),
        doctor_migration_timestamp_suffix()
    ));
    let temp_identity = write_new_private_file_at(parent, &temp_name, display_path, bytes)?;
    run_doctor_atomic_install_hook();
    verify_parent_identity(parent, parent_path, display_path)?;
    verify_file_identity(parent, &temp_name, temp_identity, display_path)?;
    parent
        .hard_link(&temp_name, parent, name)
        .map_err(|e| format!("failed to install {}: {e}", display_path.display()))?;
    verify_file_identity(parent, name, temp_identity, display_path)?;
    parent
        .remove_file(&temp_name)
        .map_err(|e| format!("failed to finalize {}: {e}", display_path.display()))?;
    verify_parent_identity(parent, parent_path, display_path)?;
    sync_cap_dir(parent, display_path)
}

fn regular_file_status_at(
    parent: &CapDir,
    name: &OsStr,
    display_path: &Path,
) -> Result<bool, String> {
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(format!("{} is a symlink", display_path.display()))
        }
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(format!("{} is not a regular file", display_path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("{}: {error}", display_path.display())),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &cap_std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
}

fn verify_file_identity(
    parent: &CapDir,
    name: &OsStr,
    expected: FileIdentity,
    display_path: &Path,
) -> Result<(), String> {
    let metadata = parent
        .symlink_metadata(name)
        .map_err(|e| format!("failed to inspect {}: {e}", display_path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{} was replaced during install",
            display_path.display()
        ));
    }
    let actual = FileIdentity::from_metadata(&metadata);
    if actual != expected {
        return Err(format!(
            "{} was replaced during install",
            display_path.display()
        ));
    }
    Ok(())
}

fn verify_parent_identity(
    held_parent: &CapDir,
    parent_path: &Path,
    display_path: &Path,
) -> Result<(), String> {
    let current_parent = open_existing_dir_nofollow(parent_path)?;
    let held = held_parent
        .dir_metadata()
        .map_err(|e| format!("failed to inspect held migration directory: {e}"))?;
    let current = current_parent
        .dir_metadata()
        .map_err(|e| format!("failed to inspect current migration directory: {e}"))?;
    if held.dev() != current.dev() || held.ino() != current.ino() {
        return Err(format!(
            "migration target parent for {} was replaced during install",
            display_path.display()
        ));
    }
    Ok(())
}

fn sync_cap_dir(dir: &CapDir, display_path: &Path) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        dir.open(".")
            .and_then(|dir| dir.sync_all())
            .map_err(|e| format!("failed to fsync {}: {e}", display_path.display()))?;
    }
    #[cfg(windows)]
    let _ = (dir, display_path);
    Ok(())
}

#[cfg(test)]
thread_local! {
    static DOCTOR_ATOMIC_INSTALL_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_doctor_atomic_install_hook(hook: impl FnOnce() + 'static) {
    DOCTOR_ATOMIC_INSTALL_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_doctor_atomic_install_hook() {
    DOCTOR_ATOMIC_INSTALL_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_doctor_atomic_install_hook() {}

fn fix_refusal_for_check(check: &CheckResult) -> DoctorFixRefusal {
    let (target, scope, reason) = match check.id {
        3 | 10 | 11 => (
            "oracle_database",
            "oracle_database",
            "doctor --fix never touches Oracle objects, grants, sessions, or connectivity state",
        ),
        6 => (
            "profile_max_level",
            "profile_config",
            "doctor --fix never changes a profile max_level; protected ceilings are detect-only",
        ),
        8 => (
            "classifier",
            "classifier",
            "doctor --fix never rewrites the classifier; classifier regressions require code review",
        ),
        13 => (
            "service_local_state",
            "service_local_state",
            "doctor --fix only copies byte-identical legacy audit JSONL into an absent current state path; it refuses symlinks and divergent audit chains",
        ),
        _ => (
            "operator_config",
            "operator_config",
            "doctor --fix is scoped to service-local state; operator-owned config is detect-only",
        ),
    };
    DoctorFixRefusal {
        check_id: check.id,
        check: check.name.clone(),
        target,
        scope,
        reason,
    }
}

/// The bundled adversarial corpus for the classifier self-test (check 8): each
/// statement MUST NOT be cleared as read-only-safe (fail-closed). A regression
/// here is critical — a write/DDL misclassified as a safe read.
const ADVERSARIAL_CORPUS: &[&str] = &[
    "DROP TABLE customers",
    "UPDATE accounts SET balance = 0",
    "DELETE FROM orders",
    "BEGIN DBMS_RANDOM.SEED(1); END;",
    "INSERT INTO t VALUES (1)",
    "SELECT 1 FROM dual; DROP TABLE t",
    "TRUNCATE TABLE audit_log",
];

/// Run all diagnostic checks and assemble the report.
///
/// `Cx`-first and `async` (B1): the connectivity/role/privilege/preflight/
/// write-posture checks issue real DB round trips through the now-async
/// [`OracleConnection`] surface, so they thread `cx` and `.await`. The
/// non-DB checks remain synchronous.
pub async fn run_doctor(cx: &Cx, ctx: &DoctorContext<'_>) -> DoctorReport {
    let checks = vec![
        check_oracle_driver(),
        check_tns_admin(ctx),
        check_connectivity(cx, ctx).await,
        check_role_standby(cx, ctx).await,
        check_nls(ctx),
        check_privilege_tier(cx, ctx).await,
        check_snapshot_freshness(),
        check_classifier_selftest(),
        check_virtual_tools(ctx),
        check_dba_suite_preflight(cx, ctx).await,
        check_write_posture(cx, ctx).await,
        check_call_timeout(ctx),
        check_state_layout(ctx),
        check_iam_token(ctx),
        check_trio_stack(ctx),
        check_configuration(ctx),
        check_rls_vpd_visibility(cx, ctx).await,
    ];
    DoctorReport {
        checks,
        profile_caps: ctx.profile_caps.clone(),
        auth_capabilities: ctx.auth_capabilities.clone(),
        service_health: ctx.service_health.clone(),
        service_unit_caps: ctx.service_unit_caps.clone(),
        fix: None,
    }
}

fn check_oracle_driver() -> CheckResult {
    let p = detect_oracle_driver();
    if !p.driver_compiled {
        return CheckResult::new(
            1,
            "Oracle thin driver",
            CheckStatus::Skip,
            "build-feature observation: built without Oracle connectivity; no connection was attempted",
        );
    }
    CheckResult::new(
        1,
        "Oracle thin driver",
        CheckStatus::Pass,
        format!(
            "build-feature observation: {}; no connection was attempted",
            p.note
        ),
    )
}

fn sanitized_detail(ctx: &DoctorContext, detail: impl Into<String>) -> String {
    crate::redacted::redact_exact_substrings(&detail.into(), &ctx.sensitive_values)
}

fn check_tns_admin(ctx: &DoctorContext) -> CheckResult {
    match (&ctx.tns_admin, &ctx.wallet_location) {
        (None, None) => CheckResult::new(
            2,
            "TNS/wallet",
            CheckStatus::Skip,
            "configuration observation: no TNS_ADMIN or wallet path is configured (EZConnect-only is fine)",
        ),
        _ => {
            for (label, dir) in [
                ("TNS_ADMIN", &ctx.tns_admin),
                ("wallet", &ctx.wallet_location),
            ] {
                match dir {
                    Some(d) if !std::path::Path::new(d).is_dir() => {
                        return CheckResult::new(
                            2,
                            "TNS/wallet",
                            CheckStatus::Fail,
                            format!("filesystem metadata observation: configured {label} path is not a directory"),
                        )
                        .with_fix(format!(
                            "create the configured directory or correct the {label} setting, then rerun `oraclemcp --json doctor --profile <profile>`"
                        ));
                    }
                    _ => {}
                }
            }
            let base = CheckResult::new(
                2,
                "TNS/wallet",
                CheckStatus::Pass,
                "filesystem metadata observation: every configured TNS_ADMIN/wallet path is a directory; readability and a live connection were not probed",
            );
            attach_wallet_posture(ctx, base)
        }
    }
}

/// Offline cert-expiry diagnostic for a resolved wallet (K1; iec3.6.6). Both
/// fields are Unix-epoch seconds / whole days; secret-free (never a path,
/// password, or key material).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorWalletCertExpiry {
    /// Earliest `notAfter` across the wallet's certificates (Unix-epoch seconds).
    pub expires_at: i64,
    /// Whole days from now until [`Self::expires_at`]; negative when the cert has
    /// already expired.
    pub days_until_expiry: i64,
}

/// A wallet certificate at or within this many days of expiry (or already
/// expired) escalates the TNS/wallet check to a WARN (K1; iec3.6.6).
const WALLET_CERT_EXPIRY_WARN_DAYS: i64 = 30;

/// Current wall-clock time as Unix-epoch seconds (saturating; a pre-epoch clock
/// reads as `0`).
fn now_unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// Read the resolved wallet's certificate validity windows through the
/// `oraclemcp-db` adapter seam (K1; iec3.6.6) and reduce them to the *earliest*
/// expiry. Purely offline (parses the wallet files' certs, no DB). Returns
/// `None` when the wallet holds no parseable certificate.
fn wallet_cert_expiry(dir: &Path, password: Option<&str>) -> Option<DoctorWalletCertExpiry> {
    let earliest = oraclemcp_db::wallet_certificate_validity(dir, password)
        .into_iter()
        .map(|c| c.not_after)
        .min()?;
    let days_until_expiry = (earliest - now_unix_secs()).div_euclid(86_400);
    Some(DoctorWalletCertExpiry {
        expires_at: earliest,
        days_until_expiry,
    })
}

/// Fold the wallet's cert-expiry window into an assembled TNS/wallet result
/// (K1; iec3.6.6): always attach the diagnostic, and escalate a `Pass` to `Warn`
/// when a certificate is within [`WALLET_CERT_EXPIRY_WARN_DAYS`] of expiry (or
/// already expired). A posture that is already `Warn`/`Fail` keeps its status
/// and fix; the cert window is still recorded.
fn fold_cert_expiry(
    result: CheckResult,
    cert_expiry: Option<DoctorWalletCertExpiry>,
) -> CheckResult {
    let Some(expiry) = cert_expiry else {
        return result;
    };
    let mut result = result.with_wallet_cert_expiry(Some(expiry));
    if expiry.days_until_expiry < WALLET_CERT_EXPIRY_WARN_DAYS && result.status == CheckStatus::Pass
    {
        let (phrase, fix) = if expiry.days_until_expiry < 0 {
            (
                format!(
                    "wallet certificate expired {} day(s) ago",
                    -expiry.days_until_expiry
                ),
                "renew/replace the expired wallet certificate before it blocks TLS connections",
            )
        } else {
            (
                format!(
                    "wallet certificate expires in {} day(s)",
                    expiry.days_until_expiry
                ),
                "renew/replace the wallet certificate before it expires and blocks TLS connections",
            )
        };
        result.status = CheckStatus::Warn;
        result.detail = format!("{} — {phrase}", result.detail);
        result = result.with_fix(fix);
    }
    result
}

/// Fold the offline wallet-posture probe (B2.1) into the TNS/wallet check when a
/// wallet directory resolves and holds wallet material. When the resolved
/// directory has no wallet files (e.g. a TNS_ADMIN dir with only `tnsnames.ora`),
/// the base filesystem-metadata result is kept unchanged — EZConnect / system-
/// trust connections legitimately need no wallet.
///
/// K1 (iec3.6.6): when the resolved wallet holds a parseable certificate, its
/// earliest expiry is read offline through the `oraclemcp-db` seam and folded in
/// — a near-/already-expired cert escalates an otherwise-usable wallet to WARN.
fn attach_wallet_posture(ctx: &DoctorContext, base: CheckResult) -> CheckResult {
    let Some(dir) = oracledb_protocol::tls::wallet::resolve_wallet_dir(
        ctx.wallet_location.as_deref(),
        ctx.tns_admin.as_deref(),
    ) else {
        return base;
    };
    let report = probe_wallet_posture(&dir, ctx.wallet_password.as_deref());
    let cert_expiry = wallet_cert_expiry(&dir, ctx.wallet_password.as_deref());
    let result = match report.posture {
        // Nothing wallet-shaped in the resolved directory: keep the base result.
        DoctorWalletPosture::NoWalletFiles => return base,
        // A usable primary or auto-login wallet: report the posture as a Pass.
        DoctorWalletPosture::PrimaryUsable | DoctorWalletPosture::AutoLoginUsable => {
            CheckResult::new(2, "TNS/wallet", CheckStatus::Pass, report.summary.clone())
                .with_wallet_posture(report)
        }
        // The primary ewallet is unusable but a parseable cwallet.sso carries the
        // connection: a Warn — the broken ewallet should be fixed or removed.
        DoctorWalletPosture::EwalletUndecryptableSsoFallthrough => {
            CheckResult::new(2, "TNS/wallet", CheckStatus::Warn, report.summary.clone())
                .with_fix(
                    "fix or remove the unusable ewallet.pem/.p12 (wrong/missing wallet_password_ref, or an unsupported cipher); the auto-login cwallet.sso currently carries the connection",
                )
                .with_wallet_posture(report)
        }
        // The primary ewallet is unusable and there is no auto-login fallback:
        // a Fail — the wallet load would fail.
        DoctorWalletPosture::WalletLoadWouldFail => {
            CheckResult::new(2, "TNS/wallet", CheckStatus::Fail, report.summary.clone())
                .with_fix(
                    "supply the correct wallet_password_ref for the ewallet, or add an auto-login cwallet.sso / unencrypted ewallet.pem to the wallet directory",
                )
                .with_wallet_posture(report)
        }
    };
    fold_cert_expiry(result, cert_expiry)
}

/// Why a connection attempt's *authentication / transport* step failed, as a
/// precise typed classification (A5). The fail-closed posture distinguishes a
/// driver-unsupported auth mode (Kerberos / RADIUS / passwordless external
/// wallet — features the pinned thin driver cannot satisfy at all) from a
/// recoverable bad-credential, TLS/wallet, or listener/network failure. This is
/// the load-bearing distinction: a driver-unsupported mode will NEVER succeed
/// by retrying with different inputs, whereas the other three are operator-
/// fixable. IAM token auth is NOT driver-unsupported (the pinned driver wires
/// it via `with_access_token`); a token over a plaintext transport is a `Tls`
/// failure (it requires TCPS), not a driver-capability gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthModeClass {
    /// An enterprise auth mode the published thin driver cannot satisfy:
    /// Kerberos, RADIUS/native MFA, or passwordless external-wallet auth.
    /// Retrying with different credentials cannot help; the operator must use a
    /// supported mode (username/password, proxy, wallet+password, or IAM token).
    DriverUnsupported,
    /// The driver supports this auth mode but the supplied credentials were
    /// rejected (ORA-01017 / invalid username-password).
    BadCredentials,
    /// A TLS/TCPS transport failure: wallet load, handshake, server-cert / DN
    /// mismatch, or an access token offered over a non-TLS transport.
    Tls,
    /// A listener / network / TNS-resolution failure: the request never reached
    /// an authenticating database service (ORA-12154 / 12514 / 12541, refused).
    Listener,
    /// A connectivity failure that is not specifically an auth/transport class
    /// above (kept honest rather than forced into a category).
    Other,
}

/// Which pinned-driver wallet setup error occurred.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorWalletErrorKind {
    /// Neither `ewallet.pem` nor `cwallet.sso` was present in the resolved wallet directory.
    FileMissing,
    /// The wallet file could not be read.
    Io,
    /// `ewallet.pem` was present but malformed or held an unsupported key shape.
    Pem,
    /// The wallet had no usable trust-anchor certificate.
    NoCertificates,
    /// `cwallet.sso` parsing failed on a recognized but unsupported branch.
    Sso,
    /// `cwallet.sso` parsing is not enabled in this build.
    SsoNotEnabled,
    /// A recognized wallet file exists, but this build does not support that file format.
    UnsupportedFormat,
    /// An encrypted `ewallet.pem`/`.p12` private key could not be decrypted
    /// (wrong/missing wallet password, or an unsupported encryption scheme).
    /// Surfaced by the offline active probe (B2.1).
    KeyDecrypt,
    /// A PKCS#12 (`ewallet.p12`) container failed to parse or decrypt. Surfaced
    /// by the offline active probe (B2.1).
    Pkcs12,
    /// The wallet (or its private key) is encrypted and requires a wallet
    /// password, but none was supplied. Surfaced by the offline active probe
    /// (B2.1).
    PasswordRequired,
    /// The wallet image exceeded the driver's fail-closed size limit before any
    /// parser ran (`MAX_WALLET_FILE_BYTES`, 16 MiB in the pinned driver).
    /// Distinct from `Pem`: the bytes were never parsed, so telling an
    /// operator their PEM is malformed sends them to debug a well-formed file.
    TooLarge,
}

/// Secret-free wallet diagnostic attached to the connectivity check.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct DoctorWalletDiagnostic {
    /// Stable wallet error kind.
    pub kind: DoctorWalletErrorKind,
    /// Unsupported wallet format, when the driver reported one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// The static wallet posture the offline active probe infers for a resolved
/// wallet directory (B2.1). This is a diagnostic of **what the driver's wallet
/// loader would do** — it never opens a live DB connection, and it mirrors the
/// driver's documented `load_wallet` precedence (`ewallet.pem` → password-bearing
/// `ewallet.p12` → auto-login `cwallet.sso`) and its fallthrough-eligibility
/// contract (a present-but-unusable primary wallet whose failure is
/// `KeyDecrypt`/`Pkcs12`/`PasswordRequired`/`UnsupportedFormat` falls through to a
/// **parseable** `cwallet.sso`). It never renders a wallet path, password, or key
/// material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorWalletPosture {
    /// The resolved wallet directory holds no `ewallet.pem`/`.p12` and no usable
    /// `cwallet.sso` (a TNS_ADMIN directory with only `tnsnames.ora` is fine —
    /// EZConnect / system-trust connections need no wallet).
    NoWalletFiles,
    /// A primary `ewallet.pem`/`.p12` parses and is directly usable.
    PrimaryUsable,
    /// Only an auto-login `cwallet.sso` is present and it parses end to end →
    /// "auto-login (cwallet.sso) usable".
    AutoLoginUsable,
    /// The higher-precedence `ewallet.pem`/`.p12` is present but fails to decrypt
    /// in a fallthrough-eligible way (e.g. `KeyDecrypt`) AND a usable
    /// `cwallet.sso` is present → the loader would fall through to auto-login.
    EwalletUndecryptableSsoFallthrough,
    /// The primary `ewallet.pem`/`.p12` is present-but-unusable and there is no
    /// usable `cwallet.sso` fallback → the wallet load would fail with the
    /// reported error class.
    WalletLoadWouldFail,
}

/// Secret-free wallet-posture report produced by [`probe_wallet_posture`]
/// (B2.1). Serialized into `CheckResult.wallet_posture`. Every field is either a
/// static enum or a wallet-file-name constant (`"ewallet.pem"`, `"ewallet.p12"`,
/// `"cwallet.sso"`) or a summary built from static phrasing — never a wallet
/// path, password, or key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorWalletPostureReport {
    /// The inferred posture.
    pub posture: DoctorWalletPosture,
    /// The wallet file that is / would be used (e.g. `"cwallet.sso"`), when one
    /// is usable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usable_file: Option<&'static str>,
    /// The higher-precedence wallet file that failed, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_file: Option<&'static str>,
    /// Whether the loader would fall through to auto-login `cwallet.sso`.
    pub fallthrough: bool,
    /// The exact `WalletError` class of the primary-wallet failure, when it
    /// fails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<DoctorWalletErrorKind>,
    /// Human-readable, secret-free summary: states (a) which wallet file is / was
    /// usable, (b) whether a fallthrough would occur, and (c) the exact
    /// `WalletError` class on failure.
    pub summary: String,
}

/// Map a typed driver [`oracledb_protocol::tls::wallet::WalletError`] into the
/// secret-free [`DoctorWalletErrorKind`]. The driver enum is `#[non_exhaustive]`,
/// so a wildcard arm is required; every variant the pinned driver can
/// produce is mapped explicitly.
fn wallet_error_kind(error: &oracledb_protocol::tls::wallet::WalletError) -> DoctorWalletErrorKind {
    use oracledb_protocol::tls::wallet::WalletError;
    match error {
        WalletError::FileMissing(_) => DoctorWalletErrorKind::FileMissing,
        WalletError::Io { .. } => DoctorWalletErrorKind::Io,
        WalletError::Pem(_) => DoctorWalletErrorKind::Pem,
        WalletError::NoCertificates => DoctorWalletErrorKind::NoCertificates,
        WalletError::Sso(_) => DoctorWalletErrorKind::Sso,
        WalletError::SsoNotEnabled => DoctorWalletErrorKind::SsoNotEnabled,
        WalletError::Pkcs12(_) => DoctorWalletErrorKind::Pkcs12,
        WalletError::KeyDecrypt(_) => DoctorWalletErrorKind::KeyDecrypt,
        WalletError::PasswordRequired { .. } => DoctorWalletErrorKind::PasswordRequired,
        WalletError::UnsupportedFormat { .. } => DoctorWalletErrorKind::UnsupportedFormat,
        WalletError::TooLarge { .. } => DoctorWalletErrorKind::TooLarge,
        // Forward-compat only. A future driver variant lands on Pem, which is
        // wrong-but-safe; `wallet_error_kind_maps_every_pinned_driver_variant`
        // is what keeps this arm from quietly absorbing a real one again.
        _ => DoctorWalletErrorKind::Pem,
    }
}

/// A present-but-unusable primary wallet is eligible to fall through to an
/// auto-login `cwallet.sso` iff its failure class is one the driver's
/// `load_wallet` treats as fallthrough-eligible. An I/O or malformed-container
/// failure (`Io`/`Pem`/`NoCertificates`/`Sso`) is never masked by an auto-login
/// wallet — it surfaces verbatim. This mirrors the driver's
/// `falls_through_to_autologin` predicate exactly.
fn wallet_error_falls_through(kind: DoctorWalletErrorKind) -> bool {
    matches!(
        kind,
        DoctorWalletErrorKind::KeyDecrypt
            | DoctorWalletErrorKind::Pkcs12
            | DoctorWalletErrorKind::PasswordRequired
            | DoctorWalletErrorKind::UnsupportedFormat
    )
}

/// Stable, secret-free label for a wallet error class (used in posture summaries).
fn wallet_error_label(kind: DoctorWalletErrorKind) -> &'static str {
    match kind {
        DoctorWalletErrorKind::FileMissing => "FileMissing",
        DoctorWalletErrorKind::Io => "Io",
        DoctorWalletErrorKind::Pem => "Pem",
        DoctorWalletErrorKind::NoCertificates => "NoCertificates",
        DoctorWalletErrorKind::Sso => "Sso",
        DoctorWalletErrorKind::SsoNotEnabled => "SsoNotEnabled",
        DoctorWalletErrorKind::UnsupportedFormat => "UnsupportedFormat",
        DoctorWalletErrorKind::KeyDecrypt => "KeyDecrypt",
        DoctorWalletErrorKind::Pkcs12 => "Pkcs12",
        DoctorWalletErrorKind::PasswordRequired => "PasswordRequired",
        DoctorWalletErrorKind::TooLarge => "TooLarge",
    }
}

/// Statically probe the resolved wallet directory and infer the driver's wallet
/// posture (B2.1) — a diagnostic of "what would happen", WITHOUT opening a live
/// DB connection.
///
/// Uses only the driver's public, sans-I/O parsers
/// (`oracledb_protocol::tls::wallet::{parse_ewallet_pem, parse_ewallet_p12}` and
/// `oracledb_protocol::tls::sso::parse_cwallet_sso`) plus the public path helpers
/// (`pem_wallet_path`/`p12_wallet_path`/`sso_wallet_path`). It mirrors the
/// driver's documented `load_wallet` precedence and fallthrough contract; it does
/// NOT call the driver's (private) resolver, so it can only *infer* the verdict,
/// never obtain it authoritatively. See the module-level note and the bead
/// report for the resolution-seam caveat.
///
/// The returned report is secret-free: it carries only typed enums, wallet-file
/// name constants, and a static-phrased summary — never a wallet path, the
/// wallet password, or any key material (the driver's `WalletError` Debug/Display
/// already redact paths; this probe never even surfaces the message string).
#[must_use]
pub fn probe_wallet_posture(
    dir: &Path,
    wallet_password: Option<&str>,
) -> DoctorWalletPostureReport {
    use oracledb_protocol::tls::sso::parse_cwallet_sso;
    use oracledb_protocol::tls::wallet::{
        p12_wallet_path, parse_ewallet_p12, parse_ewallet_pem, pem_wallet_path, sso_wallet_path,
    };

    // The auto-login cwallet.sso is "usable" iff it exists AND parses end to end
    // — exactly the condition the driver's `load_wallet::read_sso` requires
    // before it will fall through. The path is never rendered.
    let sso_path = sso_wallet_path(dir);
    let sso_usable = sso_path.exists()
        && std::fs::read(&sso_path)
            .ok()
            .is_some_and(|bytes| parse_cwallet_sso(&bytes).is_ok());

    // The primary wallet, in the driver's exact precedence order: ewallet.pem
    // first, else a *password-bearing* ewallet.p12 (a password-less p12 is NOT
    // selected as the primary — mirrors `load_wallet`'s `have_p12 &&
    // password.is_some()`).
    let pem_path = pem_wallet_path(dir);
    let p12_path = p12_wallet_path(dir);
    let probe_pem = |password: Option<&str>| match std::fs::read(&pem_path) {
        Ok(bytes) => parse_ewallet_pem(&bytes, password)
            .map(|_| ())
            .map_err(|e| wallet_error_kind(&e)),
        Err(_) => Err(DoctorWalletErrorKind::Io),
    };
    let probe_p12 = |password: Option<&str>| match std::fs::read(&p12_path) {
        Ok(bytes) => parse_ewallet_p12(&bytes, password)
            .map(|_| ())
            .map_err(|e| wallet_error_kind(&e)),
        Err(_) => Err(DoctorWalletErrorKind::Io),
    };
    let primary: Option<(&'static str, Result<(), DoctorWalletErrorKind>)> = if pem_path.exists() {
        Some(("ewallet.pem", probe_pem(wallet_password)))
    } else if p12_path.exists() && wallet_password.is_some() {
        Some(("ewallet.p12", probe_p12(wallet_password)))
    } else {
        None
    };

    match primary {
        Some((name, Ok(()))) => DoctorWalletPostureReport {
            posture: DoctorWalletPosture::PrimaryUsable,
            usable_file: Some(name),
            failed_file: None,
            fallthrough: false,
            error_kind: None,
            summary: format!("{name} usable"),
        },
        Some((name, Err(kind))) => {
            if wallet_error_falls_through(kind) && sso_usable {
                DoctorWalletPostureReport {
                    posture: DoctorWalletPosture::EwalletUndecryptableSsoFallthrough,
                    usable_file: Some(SSO_WALLET_FILE),
                    failed_file: Some(name),
                    fallthrough: true,
                    error_kind: Some(kind),
                    summary: format!(
                        "ewallet undecryptable ({}) — would fall through to cwallet.sso",
                        wallet_error_label(kind)
                    ),
                }
            } else {
                DoctorWalletPostureReport {
                    posture: DoctorWalletPosture::WalletLoadWouldFail,
                    usable_file: None,
                    failed_file: Some(name),
                    fallthrough: false,
                    error_kind: Some(kind),
                    summary: format!(
                        "wallet load would fail: {}, no auto-login fallback",
                        wallet_error_label(kind)
                    ),
                }
            }
        }
        None => {
            // No pem and no password-bearing p12. The driver prefers an
            // auto-login wallet; otherwise a present-but-password-less p12
            // surfaces PasswordRequired (a wallet load that would fail).
            if sso_usable {
                DoctorWalletPostureReport {
                    posture: DoctorWalletPosture::AutoLoginUsable,
                    usable_file: Some(SSO_WALLET_FILE),
                    failed_file: None,
                    fallthrough: false,
                    error_kind: None,
                    summary: "auto-login (cwallet.sso) usable".to_owned(),
                }
            } else if p12_path.exists() {
                let kind = probe_p12(wallet_password)
                    .err()
                    .unwrap_or(DoctorWalletErrorKind::Io);
                DoctorWalletPostureReport {
                    posture: DoctorWalletPosture::WalletLoadWouldFail,
                    usable_file: None,
                    failed_file: Some("ewallet.p12"),
                    fallthrough: false,
                    error_kind: Some(kind),
                    summary: format!(
                        "wallet load would fail: {}, no auto-login fallback",
                        wallet_error_label(kind)
                    ),
                }
            } else {
                DoctorWalletPostureReport {
                    posture: DoctorWalletPosture::NoWalletFiles,
                    usable_file: None,
                    failed_file: None,
                    fallthrough: false,
                    error_kind: None,
                    summary: "no ewallet.pem/.p12 or usable cwallet.sso in the wallet directory"
                        .to_owned(),
                }
            }
        }
    }
}

/// Auto-login wallet file name, mirrored from
/// `oracledb_protocol::tls::wallet::SSO_WALLET_FILE_NAME` (= `"cwallet.sso"`); a
/// local constant keeps the secret-free summaries free of any borrowed path.
const SSO_WALLET_FILE: &str = oracledb_protocol::tls::wallet::SSO_WALLET_FILE_NAME;

/// Classify the authentication / transport posture of a connection failure into
/// a precise [`AuthModeClass`] (A5). Driver-unsupported enterprise auth modes
/// are detected by the typed adapter messages the DB layer emits; the
/// credential / TLS / listener cases are detected by ORA- code and message.
#[must_use]
pub fn classify_auth_mode(error: &str) -> AuthModeClass {
    let lower = error.to_ascii_lowercase();

    // Driver-unsupported enterprise auth modes. These come from the DB-layer
    // adapter as precise typed `UnsupportedAuth` messages and will never succeed
    // by changing credentials — they are a driver-capability gap.
    let driver_unsupported = lower.contains("kerberos")
        || lower.contains("radius/native mfa")
        || lower.contains("radius")
        || lower.contains("external/wallet auth without username and password");
    if driver_unsupported {
        return AuthModeClass::DriverUnsupported;
    }

    // Bad credentials: ORA-01017 / invalid username-password.
    if lower.contains("ora-01017") || lower.contains("invalid username/password") {
        return AuthModeClass::BadCredentials;
    }

    // TLS / TCPS transport failures, including an access token offered over a
    // non-TLS transport (IAM requires TCPS — a transport failure, not a missing
    // driver capability).
    let tls = lower.contains("dpy-3001")
        || lower.contains("requires a tls")
        || lower.contains("requires a tls (tcps)")
        || lower.contains("tcps")
        || lower.contains("tls")
        || (lower.contains("wallet") && !lower.contains("password"));
    if tls {
        return AuthModeClass::Tls;
    }

    // Listener / network / TNS resolution: never reached an auth step.
    let listener = lower.contains("ora-12154")
        || lower.contains("ora-12514")
        || lower.contains("ora-12541")
        || lower.contains("listener")
        || lower.contains("could not resolve")
        || lower.contains("tns");
    if listener {
        return AuthModeClass::Listener;
    }

    AuthModeClass::Other
}

fn unsupported_wallet_format(error: &str) -> Option<String> {
    let lower = error.to_ascii_lowercase();
    let start = lower.find("wallet format ")? + "wallet format ".len();
    let rest = &error[start..];
    let end = rest
        .to_ascii_lowercase()
        .find(" is not supported")
        .unwrap_or(rest.len());
    let format = rest[..end].trim();
    (!format.is_empty()).then(|| format.to_owned())
}

fn classify_wallet_error(error: &str) -> Option<DoctorWalletDiagnostic> {
    let lower = error.to_ascii_lowercase();
    if !(lower.contains("wallet error:")
        || lower.contains("wallet file")
        || lower.contains("wallet pem")
        || lower.contains("cwallet.sso")
        || lower.contains("wallet contained no certificates")
        || lower.contains("wallet format "))
    {
        return None;
    }

    let (kind, format) = if let Some(format) = unsupported_wallet_format(error) {
        (DoctorWalletErrorKind::UnsupportedFormat, Some(format))
    } else if lower.contains("cwallet.sso support is experimental and not enabled") {
        (DoctorWalletErrorKind::SsoNotEnabled, None)
    } else if lower.contains("cwallet.sso parse error") {
        (DoctorWalletErrorKind::Sso, None)
    } else if lower.contains("wallet file is missing") {
        (DoctorWalletErrorKind::FileMissing, None)
    } else if lower.contains("failed to read wallet file") {
        (DoctorWalletErrorKind::Io, None)
    } else if lower.contains("failed to parse wallet pem") {
        (DoctorWalletErrorKind::Pem, None)
    } else if lower.contains("wallet contained no certificates") {
        (DoctorWalletErrorKind::NoCertificates, None)
    } else {
        return None;
    };

    Some(DoctorWalletDiagnostic { kind, format })
}

fn wallet_connectivity_fix(wallet: &DoctorWalletDiagnostic) -> &'static str {
    match wallet.kind {
        DoctorWalletErrorKind::UnsupportedFormat => {
            "convert the wallet to ewallet.pem; standalone ewallet.p12 is not supported by this thin build"
        }
        DoctorWalletErrorKind::SsoNotEnabled => {
            "convert the wallet to ewallet.pem; cwallet.sso parsing is experimental and not enabled in this build"
        }
        DoctorWalletErrorKind::Sso => {
            "convert the wallet to ewallet.pem or regenerate the cwallet.sso using a supported auto-login format"
        }
        DoctorWalletErrorKind::FileMissing => {
            "place ewallet.pem in the configured wallet directory, or correct wallet_location/TNS_ADMIN"
        }
        DoctorWalletErrorKind::Io => {
            "verify wallet file permissions and readability for the oraclemcp service user"
        }
        DoctorWalletErrorKind::Pem => {
            "regenerate ewallet.pem with valid PEM certificate material and an unencrypted private key if mTLS is required"
        }
        DoctorWalletErrorKind::NoCertificates => {
            "regenerate ewallet.pem with at least one trust-anchor certificate"
        }
        DoctorWalletErrorKind::TooLarge => {
            "the wallet image exceeds the driver's 16 MiB fail-closed limit and was never parsed; export a wallet containing only the certificates and key this profile needs"
        }
        DoctorWalletErrorKind::KeyDecrypt => {
            "supply the correct wallet_password_ref for the encrypted ewallet key, or re-export it as an unencrypted PKCS#8 ewallet.pem; a valid auto-login cwallet.sso would also let the loader fall through"
        }
        DoctorWalletErrorKind::Pkcs12 => {
            "regenerate ewallet.p12 with a supported PBES2/PBKDF2/AES-CBC cipher, or convert the wallet to ewallet.pem"
        }
        DoctorWalletErrorKind::PasswordRequired => {
            "set wallet_password_ref for the encrypted wallet, or use an auto-login cwallet.sso / unencrypted ewallet.pem wallet"
        }
    }
}

/// The doctor-facing rendering of the driver handshake-trace instruction:
/// the concrete command an operator can rerun for protocol-level triage.
const DOCTOR_TRACE_FIX: &str = "capture a driver handshake trace for protocol-level triage: \
     ORACLEDB_TRACE_CONNECT=1 oraclemcp --json doctor --online --profile <profile> \
     (the trace prints to stderr)";

/// Fix guidance for the structured connect/handshake failure classes minted
/// by the driver-seam adapter (`connect handshake failed [label]: …`).
/// Returns `None` when the error carries no handshake class token.
fn handshake_connectivity_fix(lower: &str) -> Option<String> {
    let fix = if lower.contains("[unexpected-tns-packet]") {
        format!(
            "verify the host:port points at an Oracle listener (not another service) of a \
             supported generation; then {DOCTOR_TRACE_FIX}"
        )
    } else if lower.contains("[connect-resend-loop]") {
        format!(
            "check the listener log for redirect loops and retry; if it persists, \
             {DOCTOR_TRACE_FIX}"
        )
    } else if lower.contains("[fast-auth-not-advertised]") {
        "token/IAM authentication requires a server that advertises fast auth (Oracle 23ai or \
         newer); use username/password credential_ref auth for this profile, or point token \
         auth at a 23ai+ service"
            .to_owned()
    } else if lower.contains("[unsupported-wire-feature]") {
        "the server demands a wire feature this thin build does not support (e.g. Native \
         Network Encryption); set SQLNET.ENCRYPTION_SERVER / SQLNET.CRYPTO_CHECKSUM_SERVER to \
         `accepted` on the server, or use TCPS/TLS transport instead"
            .to_owned()
    } else if lower.contains("[listener-refused]") {
        "the listener actively refused the connection; verify the service name is registered \
         (`lsnrctl services` on the database host) — ERR=12514 means the service name in the \
         connect string is wrong or the database has not registered it yet"
            .to_owned()
    } else if lower.contains("[listener-redirect-unsupported]") {
        format!(
            "the listener issued a TNS redirect this thin driver cannot follow; connect \
             directly to the redirect target (dedicated handler host:port) instead of a \
             CMAN/shared-server endpoint; {DOCTOR_TRACE_FIX}"
        )
    } else if lower.contains("[server-generation-unsupported]") {
        "the server's TNS protocol generation is below the driver minimum (Oracle 12.1); this \
         thin driver cannot connect to older servers"
            .to_owned()
    } else if lower.contains("[handshake-protocol-error]") {
        format!(
            "the TNS/TTC connect handshake failed at the wire-protocol layer; verify the \
             endpoint is an Oracle listener of a supported generation (12.1+); then \
             {DOCTOR_TRACE_FIX}"
        )
    } else {
        return None;
    };
    Some(fix)
}

fn connectivity_fix(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if let Some(fix) = handshake_connectivity_fix(&lower) {
        return fix;
    }
    let fix = if let Some(wallet) = classify_wallet_error(error) {
        wallet_connectivity_fix(&wallet)
    } else if lower.contains("no connection profiles are configured") {
        "run `oraclemcp setup --discover` to auto-discover profiles from tnsnames.ora (the zero-config fast path), or `oraclemcp --json setup --write --profile db_ro` then export ORACLE_APP_PASSWORD for the generated credential_ref and rerun `oraclemcp --json doctor --profile db_ro`"
    } else if lower.contains("proxy_auth") {
        "set both profiles.proxy_auth.proxy_user and target_schema; if username is present it must match proxy_user"
    } else if lower.contains("connection profile") || lower.contains("default_profile") {
        "run `oraclemcp --json profiles` to list configured profiles, then rerun doctor with a valid `--profile` name"
    } else if lower.contains("failed to resolve credential_ref")
        || lower.contains("failed to resolve wallet_password_ref")
    {
        "verify the profile credential_ref or wallet_password_ref and its backing environment variable or secrets backend"
    } else if lower.contains("config load failed") {
        "fix profiles.toml or ORACLEMCP_CONFIG, then rerun `oraclemcp --json profiles`"
    } else if lower.contains("external/wallet auth without username and password") {
        "for TCPS wallets, keep wallet_location but add username plus credential_ref for thin username/password auth; passwordless external wallet auth is not supported by this thin driver"
    } else if lower.contains("unsupported auth mode")
        || lower.contains("unsupported database feature")
        || lower.contains("not supported by the published thin driver")
        || lower.contains("unsupported")
    {
        "use username/password thin auth for this profile, or upgrade the thin driver once that auth feature is supported"
    } else if lower.contains("ora-01017") || lower.contains("invalid username/password") {
        "verify the profile username and credential_ref environment variable; do not put literal production passwords in profiles.toml"
    } else if lower.contains("ora-12154")
        || lower.contains("tns")
        || lower.contains("could not resolve")
    {
        "verify the connect string, TNS_ADMIN directory, and net-service alias; use an EZConnect string to isolate TNS lookup issues"
    } else if lower.contains("ora-12514")
        || lower.contains("ora-12541")
        || lower.contains("listener")
    {
        "verify listener reachability, host/port, service name, and database registration"
    } else if lower.contains("tcps") || lower.contains("wallet") {
        "verify the wallet directory, cwallet.sso/tnsnames.ora presence, TCPS alias, and file permissions"
    } else {
        "verify the connect string, credentials, and listener reachability"
    };
    fix.to_owned()
}

fn connectivity_failure_class(error: &str) -> ErrorClass {
    let lower = error.to_ascii_lowercase();
    if let Some(code) = parse_ora_code(error) {
        classify_ora_code(code)
    } else if let Some(wallet) = classify_wallet_error(error) {
        match wallet.kind {
            // Config classes where retrying the same connect cannot help — the
            // operator must change the wallet, cipher, or password reference.
            DoctorWalletErrorKind::UnsupportedFormat
            | DoctorWalletErrorKind::SsoNotEnabled
            | DoctorWalletErrorKind::KeyDecrypt
            | DoctorWalletErrorKind::Pkcs12
            | DoctorWalletErrorKind::PasswordRequired
            | DoctorWalletErrorKind::TooLarge => ErrorClass::InvalidArguments,
            DoctorWalletErrorKind::FileMissing
            | DoctorWalletErrorKind::Io
            | DoctorWalletErrorKind::Pem
            | DoctorWalletErrorKind::NoCertificates
            | DoctorWalletErrorKind::Sso => ErrorClass::ConnectionFailed,
        }
    } else if lower.contains("[fast-auth-not-advertised]")
        || lower.contains("[unsupported-wire-feature]")
        || lower.contains("[server-generation-unsupported]")
    {
        // Structured handshake classes where retrying cannot help: the
        // profile or the server generation has to change.
        ErrorClass::InvalidArguments
    } else if lower.contains("[unexpected-tns-packet]")
        || lower.contains("[connect-resend-loop]")
        || lower.contains("[listener-refused]")
        || lower.contains("[listener-redirect-unsupported]")
        || lower.contains("[handshake-protocol-error]")
    {
        ErrorClass::ConnectionFailed
    } else if lower.contains("config load failed")
        || lower.contains("connection profile")
        || lower.contains("default_profile")
        || lower.contains("unsupported auth mode")
        || lower.contains("unsupported database feature")
        || lower.contains("not supported by the published thin driver")
        || lower.contains("unsupported")
    {
        ErrorClass::InvalidArguments
    } else if lower.contains("invalid username/password") {
        ErrorClass::InsufficientPrivilege
    } else {
        ErrorClass::ConnectionFailed
    }
}

async fn check_connectivity(cx: &Cx, ctx: &DoctorContext<'_>) -> CheckResult {
    if ctx.configuration_error.is_some() {
        return CheckResult::new(
            3,
            "Connectivity",
            CheckStatus::Skip,
            "skipped because configuration could not be loaded",
        );
    }
    if let Some(error) = &ctx.connection_error {
        let detail = sanitized_detail(ctx, format!("connect failed: {error}"));
        let fix = connectivity_fix(&detail);
        return CheckResult::new(3, "Connectivity", CheckStatus::Fail, detail.clone())
            .with_fix(fix)
            .with_failure_class(connectivity_failure_class(error))
            .with_auth_mode(classify_auth_mode(error))
            .with_wallet_error(classify_wallet_error(error))
            .with_oracle_error(&detail);
    }
    match ctx.conn {
        None => {
            if !ctx.online
                && let Some(hint) = &ctx.credential_env_hint
            {
                // A discovered/configured profile whose credential env var is
                // still unset: a non-blocking needs-verification hint that names
                // the exact env var to export. Fail closed — the profile stays
                // READ_ONLY and is never treated as verified.
                return CheckResult::new(
                    3,
                    "Connectivity",
                    CheckStatus::Skip,
                    "offline — profile needs verification before live use",
                )
                .with_fix(hint.clone());
            }
            let detail = if ctx.online {
                "online requested, but no profile resolved to a live connection"
            } else if ctx.profile_caps.is_some() {
                "offline — rerun with --online --profile <profile> to test connectivity + auth"
            } else {
                "offline — rerun with --online and a configured profile to test connectivity + auth"
            };
            CheckResult::new(3, "Connectivity", CheckStatus::Skip, detail)
        }
        Some(conn) => match conn.ping(cx).await {
            Ok(()) => match ctx.stateless_conn {
                Some(stateless) => match stateless.ping(cx).await {
                    Ok(()) => {
                        let detail = ctx.connection_strategy.as_deref().map_or_else(
                            || "Oracle ping round trips succeeded for every opened connection; connection authenticated".to_owned(),
                            |strategy| format!(
                                "Oracle ping round trips succeeded for every opened connection; \
                                 connection authenticated (runtime wiring: {strategy})"
                            ),
                        );
                        CheckResult::new(3, "Connectivity", CheckStatus::Pass, detail)
                    }
                    Err(e) => {
                        let raw = e.to_string();
                        CheckResult::new(
                            3,
                            "Connectivity",
                            CheckStatus::Fail,
                            sanitized_detail(
                                ctx,
                                format!(
                                    "pinned-session ping succeeded, but stateless-pool ping failed: {raw}"
                                ),
                            ),
                        )
                        .with_fix(connectivity_fix(&sanitized_detail(ctx, &raw)))
                        .with_failure_class(connectivity_failure_class(&raw))
                        .with_auth_mode(classify_auth_mode(&raw))
                        .with_wallet_error(classify_wallet_error(&raw))
                        .with_oracle_error(&sanitized_detail(ctx, &raw))
                    }
                },
                None if ctx.stateless_pool_configured => CheckResult::new(
                    3,
                    "Connectivity",
                    CheckStatus::Warn,
                    "pinned-session Oracle ping round trip succeeded, but the configured stateless pool did not open; no pool round trip was observed",
                )
                .with_fix(
                    "inspect the stateless pool configuration and rerun doctor --online before relying on pooled reads",
                ),
                None => {
                    let detail = ctx.connection_strategy.as_deref().map_or_else(
                        || "Oracle ping round trip succeeded; connection authenticated".to_owned(),
                        |strategy| format!(
                            "Oracle ping round trip succeeded; connection authenticated \
                             (runtime wiring: {strategy})"
                        ),
                    );
                    CheckResult::new(3, "Connectivity", CheckStatus::Pass, detail)
                }
            },
            Err(e) => {
                let raw = e.to_string();
                CheckResult::new(
                    3,
                    "Connectivity",
                    CheckStatus::Fail,
                    sanitized_detail(ctx, format!("ping failed: {raw}")),
                )
                .with_fix(connectivity_fix(&sanitized_detail(ctx, &raw)))
                .with_failure_class(connectivity_failure_class(&raw))
                .with_auth_mode(classify_auth_mode(&raw))
                .with_wallet_error(classify_wallet_error(&raw))
                .with_oracle_error(&sanitized_detail(ctx, &raw))
            }
        },
    }
}

/// Configuration-load check. It is deliberately separate from connectivity:
/// retrying a malformed `profiles.toml` against the same listener cannot help.
fn check_configuration(ctx: &DoctorContext<'_>) -> CheckResult {
    const ID: u8 = 16;
    const NAME: &str = "Configuration";

    match &ctx.configuration_error {
        Some(error) => {
            let detail = sanitized_detail(ctx, format!("configuration load failed: {error}"));
            CheckResult::new(ID, NAME, CheckStatus::Fail, detail)
                .with_fix(
                    "fix the named profiles.toml or ORACLEMCP_CONFIG error, then rerun doctor",
                )
                .with_failure_class(ErrorClass::InvalidArguments)
        }
        None => CheckResult::new(ID, NAME, CheckStatus::Pass, "configuration load succeeded"),
    }
}

async fn check_role_standby(cx: &Cx, ctx: &DoctorContext<'_>) -> CheckResult {
    if ctx.connection_error.is_some() {
        return CheckResult::new(
            4,
            "Role/standby",
            CheckStatus::Skip,
            "skipped because connectivity failed",
        );
    }
    match ctx.conn {
        None => CheckResult::new(
            4,
            "Role/standby",
            CheckStatus::Skip,
            "offline — requires a live connection",
        ),
        Some(conn) => match detect_standby(cx, conn).await {
            Ok(s) => {
                let role = s.database_role.unwrap_or_else(|| "unknown".to_owned());
                let mode = s.open_mode.unwrap_or_else(|| "unknown".to_owned());
                let detail = format!("role={role}, open_mode={mode}");
                if s.read_only_standby {
                    CheckResult::new(
                        4,
                        "Role/standby",
                        CheckStatus::Pass,
                        format!("{detail} — READ_ONLY forced"),
                    )
                } else {
                    CheckResult::new(4, "Role/standby", CheckStatus::Pass, detail)
                }
            }
            Err(e) => CheckResult::new(
                4,
                "Role/standby",
                CheckStatus::Warn,
                sanitized_detail(ctx, format!("could not determine role: {e}")),
            )
            .with_fix("grant SELECT on V$DATABASE or accept reduced standby detection"),
        },
    }
}

fn check_nls(ctx: &DoctorContext) -> CheckResult {
    let n = canonical_nls_statements().len();
    let clock = if ctx.conn.is_some() && ctx.connection_error.is_none() {
        ""
    } else {
        " (clock-skew sub-check skipped offline)"
    };
    CheckResult::new(
        5,
        "NLS/charset",
        CheckStatus::Pass,
        format!(
            "{n} canonical NLS statements applied on connect (deterministic NUMBER/date serialization){clock}"
        ),
    )
}

async fn check_privilege_tier(cx: &Cx, ctx: &DoctorContext<'_>) -> CheckResult {
    if ctx.connection_error.is_some() {
        return if ctx.protected_profile_writable {
            CheckResult::new(
                6,
                "Privilege tier",
                CheckStatus::Warn,
                "a protected profile has max_level above READ_ONLY; live privilege probe skipped because connectivity failed",
            )
            .with_fix("set max_level = READ_ONLY (or remove protected), then rerun doctor after connectivity is fixed")
        } else {
            CheckResult::new(
                6,
                "Privilege tier",
                CheckStatus::Skip,
                "skipped because connectivity failed",
            )
        };
    }
    match ctx.conn {
        None => {
            if ctx.protected_profile_writable {
                CheckResult::new(
                    6,
                    "Privilege tier",
                    CheckStatus::Warn,
                    "a protected profile has max_level above READ_ONLY",
                )
                .with_fix("set max_level = READ_ONLY (or remove protected) — protected profiles must pin READ_ONLY")
            } else {
                CheckResult::new(
                    6,
                    "Privilege tier",
                    CheckStatus::Skip,
                    "offline — requires a live connection to probe",
                )
            }
        }
        Some(conn) => {
            let p = probe_privileges(cx, conn).await;
            let detail = format!(
                "dictionary tier {:?}, diagnostics_pack={}, plscope={}",
                p.dictionary_tier, p.diagnostics_pack, p.plscope
            );
            if ctx.protected_profile_writable {
                CheckResult::new(6, "Privilege tier", CheckStatus::Warn, detail).with_fix(
                    "a protected profile has max_level above READ_ONLY; pin max_level = READ_ONLY",
                )
            } else {
                CheckResult::new(6, "Privilege tier", CheckStatus::Pass, detail)
            }
        }
    }
}

async fn check_rls_vpd_visibility(cx: &Cx, ctx: &DoctorContext<'_>) -> CheckResult {
    const ID: u8 = 17;
    const NAME: &str = "RLS/VPD visibility";

    if ctx.connection_error.is_some() {
        return CheckResult::new(
            ID,
            NAME,
            CheckStatus::Skip,
            "skipped because connectivity failed",
        );
    }
    let Some(conn) = ctx.conn else {
        return CheckResult::new(
            ID,
            NAME,
            CheckStatus::Skip,
            "offline — requires a live connection to inspect SESSION_CONTEXT, SESSION_ROLES, and ALL_POLICIES",
        );
    };

    let observation = observe_vpd_rls_for_schema(cx, conn, "").await;
    rls_vpd_check_from_observation(ctx, observation)
}

fn rls_vpd_check_from_observation(
    ctx: &DoctorContext<'_>,
    observation: OracleVpdRlsObservation,
) -> CheckResult {
    let session = observation
        .session
        .as_ref()
        .map(|session| {
            format!(
                "session_user={}, current_schema={}, edition={}, enabled_roles={}",
                session.session_user,
                session.current_schema,
                session.edition_name.as_deref().unwrap_or("unknown"),
                session.enabled_roles.len()
            )
        })
        .unwrap_or_else(|| "session context unavailable".to_owned());
    let named = observation
        .policies
        .iter()
        .map(|policy| {
            format!(
                "{}.{}:{}",
                policy.object_owner, policy.object_name, policy.policy_name
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let visible = if named.is_empty() {
        "visible_policies=none".to_owned()
    } else {
        format!("visible_policies={named}")
    };
    let detail = sanitized_detail(
        ctx,
        format!(
            "{session}; {}; {}; {}",
            observation.detail, observation.all_policies_probe.detail, visible
        ),
    );
    match observation.status {
        OracleVpdRlsObservationStatus::PoliciesObserved => CheckResult::new(
            17,
            "RLS/VPD visibility",
            CheckStatus::Warn,
            detail,
        )
        .with_fix("review the named DBMS_RLS policies; a filtered read may return fewer rows than the base table contains"),
        OracleVpdRlsObservationStatus::NoVisibleMatchingPolicies => CheckResult::new(
            17,
            "RLS/VPD visibility",
            CheckStatus::Pass,
            detail,
        ),
        OracleVpdRlsObservationStatus::NoVisiblePolicyCatalogRows => CheckResult::new(
            17,
            "RLS/VPD visibility",
            CheckStatus::Warn,
            detail,
        )
        .with_fix("rerun doctor as a catalog-sighted principal or grant enough dictionary visibility to inspect ALL_POLICIES"),
        OracleVpdRlsObservationStatus::VisibilityUnavailable => CheckResult::new(
            17,
            "RLS/VPD visibility",
            CheckStatus::Warn,
            detail,
        )
        .with_fix("grant policy catalog visibility or rerun with a principal that can read ALL_POLICIES"),
    }
}

fn check_snapshot_freshness() -> CheckResult {
    CheckResult::new(
        7,
        "Catalog snapshot",
        CheckStatus::Skip,
        "registers when the P1-5 catalog-snapshot capture is wired into the binary",
    )
}

fn check_classifier_selftest() -> CheckResult {
    let classifier = Classifier::new(ClassifierConfig::new());
    let mut leaked = Vec::new();
    for sql in ADVERSARIAL_CORPUS {
        let d = classifier.classify(sql);
        // A dangerous statement is correctly handled iff it is NOT cleared as
        // read-only-safe: required_level is None (Forbidden) or above READ_ONLY.
        let read_only_safe = d.required_level == Some(OperatingLevel::ReadOnly);
        if read_only_safe {
            leaked.push(*sql);
        }
    }
    // A known-safe read must classify as READ_ONLY (no false positives).
    let safe = classifier.classify("SELECT 1 FROM dual");
    let safe_ok = safe.required_level == Some(OperatingLevel::ReadOnly);

    if leaked.is_empty() && safe_ok {
        CheckResult::new(
            8,
            "Classifier self-test",
            CheckStatus::Pass,
            format!(
                "{} adversarial inputs all fail-closed; safe read classified READ_ONLY",
                ADVERSARIAL_CORPUS.len()
            ),
        )
    } else if !leaked.is_empty() {
        CheckResult::new(
            8,
            "Classifier self-test",
            CheckStatus::Fail,
            format!("{} adversarial input(s) cleared as read-only-safe: {:?}", leaked.len(), leaked),
        )
        .with_fix("CRITICAL: the fail-closed classifier regressed — do not run against production until fixed")
    } else {
        CheckResult::new(
            8,
            "Classifier self-test",
            CheckStatus::Fail,
            "a known-safe SELECT was not classified READ_ONLY (over-blocking)",
        )
        .with_fix("review the classifier configuration / side-effect oracle")
    }
}

fn check_virtual_tools(ctx: &DoctorContext<'_>) -> CheckResult {
    if ctx.skipped_custom_tools.is_empty() {
        return CheckResult::new(
            9,
            "Virtual tools",
            CheckStatus::Pass,
            "custom tool descriptors and signing policy are available; the binary loads tools.d at startup",
        );
    }
    let detail = ctx
        .skipped_custom_tools
        .iter()
        .map(|skipped| format!("{}: {}", skipped.name, skipped.reason))
        .collect::<Vec<_>>()
        .join("; ");
    CheckResult::new(
        9,
        "Virtual tools",
        CheckStatus::Warn,
        format!(
            "{} custom tool definition(s) were skipped and are not available: {detail}",
            ctx.skipped_custom_tools.len()
        ),
    )
}

/// Check 10 — DBA-suite privilege/feature preflight (bead C9, **report-only**).
///
/// Reports, for the read-only DBA diagnostic suite, which dictionary tier /
/// diagnostics feature is actually available so an operator knows what
/// `oracle_db_health` / `oracle_top_queries` will be able to run. It reuses
/// `oraclemcp_db::preflight` (and through it the fail-closed `detect_view_tier`
/// / `detect_diagnostics_pack` / `detect_statspack` probes), runs only the cheap
/// `WHERE 1=0` tier probes plus the feature probes, and NEVER runs a diagnostic
/// query or touches a paid-pack object unless the Diagnostics Pack license was
/// confirmed first. It is informational: it reports `Pass` (full tier coverage),
/// `Warn` (some subchecks would degrade/skip, or historical perf history is
/// unavailable), `Skip` (offline), or `Fail` when cancellation/session loss
/// makes the preflight itself untrustworthy.
async fn check_dba_suite_preflight(cx: &Cx, ctx: &DoctorContext<'_>) -> CheckResult {
    const ID: u8 = 10;
    const NAME: &str = "DBA suite preflight";

    if ctx.connection_error.is_some() {
        return CheckResult::new(
            ID,
            NAME,
            CheckStatus::Skip,
            "skipped because connectivity failed",
        );
    }
    let Some(conn) = ctx.conn else {
        return CheckResult::new(
            ID,
            NAME,
            CheckStatus::Skip,
            "offline — supply a profile/connection to preflight the read-only DBA diagnostic suite",
        );
    };

    let report = match preflight(cx, conn).await {
        Ok(report) => report,
        Err(err) => {
            let envelope = err.into_envelope();
            let detail = sanitized_detail(
                ctx,
                format!(
                    "DBA suite preflight aborted at an uncertain database boundary ({:?}): {}",
                    envelope.error_class, envelope.message
                ),
            );
            return CheckResult::new(ID, NAME, CheckStatus::Fail, detail).with_fix(
                "repair connectivity or cancellation state and rerun doctor on a fresh connection",
            );
        }
    };
    let (runnable, skipped, failed) = report.runnable_skipped_failed();
    let total = runnable + skipped + failed;
    let history = match report.top_queries_historical {
        DiagnosticsSource::AwrAsh => "AWR/ASH (Diagnostics Pack licensed)",
        DiagnosticsSource::Statspack => "Statspack (free fallback)",
        DiagnosticsSource::Unavailable => "none (no Diagnostics Pack, no Statspack)",
        // The default top-queries source is always the live cursor; historical
        // never resolves to it, but report it honestly if it ever does.
        DiagnosticsSource::LiveCursor => "live cursor only",
    };
    let detail = format!(
        "oracle_db_health: {runnable}/{total} subchecks runnable, {skipped} would skip, \
         {failed} ordinary probe(s) failed; \
         oracle_top_queries default=live cursor (free), historical={history}"
    );

    // Report-only: a degraded posture is a Warn (informational), never a Fail.
    let history_unavailable = report.top_queries_historical == DiagnosticsSource::Unavailable;
    if skipped == 0 && failed == 0 && !history_unavailable {
        CheckResult::new(ID, NAME, CheckStatus::Pass, detail)
    } else {
        CheckResult::new(ID, NAME, CheckStatus::Warn, detail).with_fix(
            "report-only: grant SELECT on the missing DBA_*/V$ views for full coverage, \
             or install Statspack (free) / license the Diagnostics Pack for historical top-SQL",
        )
    }
}

/// A one-line, honest summary of wallet auth modes for this default build.
fn supported_wallet_modes_note() -> String {
    let supported: Vec<&str> = supported_wallet_modes()
        .iter()
        .filter(|m| m.supported)
        .map(|m| m.mode)
        .collect();
    let unsupported: Vec<&str> = supported_wallet_modes()
        .iter()
        .filter(|m| !m.supported)
        .map(|m| m.mode)
        .collect();
    if unsupported.is_empty() {
        format!("supported wallet modes: {}", supported.join(", "))
    } else {
        format!(
            "supported wallet modes: {}; unsupported in this build: {}",
            supported.join(", "),
            unsupported.join(", ")
        )
    }
}

/// Check 11 — read-only proxy-user / role posture (bead A2, **report-only**).
///
/// Reports whether the connected principal can write at the database. A
/// least-privilege proxy user / read-only role holds NO write-implying system
/// privileges; if it does, the operator is WARNED (the classifier + per-DB
/// ceiling are still the enforced control, but a write-capable principal is not
/// defense in depth). The detail always reports the wallet mode truth table so
/// an operator sees which recognized wallet artifacts this build can load
/// directly. Never `Fail`s the suite.
async fn check_write_posture(cx: &Cx, ctx: &DoctorContext<'_>) -> CheckResult {
    const ID: u8 = 11;
    const NAME: &str = "Write posture";
    let wallet_note = supported_wallet_modes_note();

    if ctx.connection_error.is_some() {
        return CheckResult::new(
            ID,
            NAME,
            CheckStatus::Skip,
            format!("skipped because connectivity failed; {wallet_note}"),
        );
    }
    let proxy = if ctx.proxy_user {
        "proxy/least-privilege connect user configured"
    } else {
        "direct connect user (no proxy)"
    };
    match ctx.conn {
        None => CheckResult::new(
            ID,
            NAME,
            CheckStatus::Skip,
            format!("offline — supply a profile/connection to probe write posture; {wallet_note}"),
        ),
        Some(conn) => {
            let posture = probe_write_posture(cx, conn, ctx.proxy_user).await;
            match posture.can_write {
                Some(false) => CheckResult::new(
                    ID,
                    NAME,
                    CheckStatus::Pass,
                    format!(
                        "read-only posture: principal holds no write-implying system privileges ({proxy}); {wallet_note}"
                    ),
                ),
                Some(true) => CheckResult::new(
                    ID,
                    NAME,
                    CheckStatus::Warn,
                    sanitized_detail(
                        ctx,
                        format!(
                            "principal CAN write — holds {} ({proxy}); {wallet_note}",
                            posture.write_privileges.join(", ")
                        ),
                    ),
                )
                .with_fix(
                    "for least-privilege, connect as a read-only proxy user / role with only \
                     CREATE SESSION + SELECT (or SELECT ANY DICTIONARY); the classifier + per-DB \
                     ceiling remain the enforced control, but a non-writable principal is defense in depth",
                ),
                None => CheckResult::new(
                    ID,
                    NAME,
                    CheckStatus::Warn,
                    format!(
                        "could not determine write posture from SESSION_PRIVS ({proxy}); {wallet_note}"
                    ),
                )
                .with_fix("grant the session SELECT on SESSION_PRIVS, or accept reduced posture reporting"),
            }
        }
    }
}

fn check_state_layout(ctx: &DoctorContext<'_>) -> CheckResult {
    const ID: u8 = 13;
    const NAME: &str = "Audit / state layout";
    const AUDIT_CONFIG_REFERENCE: &str =
        " See README.md#signed-audit-and-unsigned-refusal-trail for the configuration reference.";

    let (audit_status, audit_detail) = match ctx.audit_posture.as_ref() {
        Some(DoctorAuditPosture::SigningKeyConfigured { path }) => (
            CheckStatus::Pass,
            format!(
                "audit configuration observation: signing-key source configured at {}; unsigned refusal trail: INACTIVE (signed audit is the configured tier); this offline check does not resolve the key or construct an auditor.{}",
                path.display(), AUDIT_CONFIG_REFERENCE
            ),
        ),
        Some(DoctorAuditPosture::DisabledReadOnly {
            unsigned_refusal_trail_path: Some(path),
        }) => (
            CheckStatus::Skip,
            format!(
                "audit configuration observation: disabled (no signing key configured; profile is read-only everywhere reachable); unsigned refusal trail: ACTIVE BY CONFIGURATION at {} (UNSIGNED, NOT TAMPER-EVIDENT; this offline check does not open it).{}",
                path.display(), AUDIT_CONFIG_REFERENCE
            ),
        ),
        Some(DoctorAuditPosture::DisabledReadOnly {
            unsigned_refusal_trail_path: None,
        }) => (
            CheckStatus::Skip,
            format!(
                "audit configuration observation: disabled (no signing key configured; profile is read-only everywhere reachable); unsigned refusal trail: DISABLED BY CONFIGURATION.{}",
                AUDIT_CONFIG_REFERENCE
            ),
        ),
        Some(DoctorAuditPosture::StartupRefused { reachable_ceiling }) => (
            CheckStatus::Fail,
            format!(
                "audit configuration observation: startup would be refused (no signing key configured; a reachable profile can reach {} and startup policy requires ORACLEMCP_AUDIT_KEY_REQUIRED); unsigned refusal trail: UNAVAILABLE (the server does not start).{}",
                reachable_ceiling.as_str(), AUDIT_CONFIG_REFERENCE
            ),
        ),
        Some(DoctorAuditPosture::Unavailable { reason }) => (
            CheckStatus::Skip,
            format!("audit configuration observation unavailable ({reason})"),
        ),
        None => (
            CheckStatus::Skip,
            "audit configuration observation unavailable (the binary did not supply an audit posture)".to_owned(),
        ),
    };

    let Some(layout) = ctx.state_layout.as_ref() else {
        return CheckResult::new(
            ID,
            NAME,
            audit_status,
            format!("{audit_detail}; state directory could not be resolved in this environment"),
        );
    };

    let (layout_status, layout_detail, fix) = match inspect_legacy_state_layout(layout) {
        LegacyStateLayoutObservation::Current => (
            CheckStatus::Pass,
            "filesystem observation: legacy default audit JSONL is absent; no default-path migration is needed".to_owned(),
            None,
        ),
        LegacyStateLayoutObservation::LegacyAndCurrentAuditIdentical => (
            CheckStatus::Pass,
            format!(
                "filesystem observation: legacy audit JSONL remains at {} and matches current state audit {}; no merge needed",
                layout.legacy_audit_path.display(),
                layout.current_audit_path.display()
            ),
            None,
        ),
        LegacyStateLayoutObservation::ExplicitAuditPath => (
            CheckStatus::Pass,
            "configuration observation: explicit [audit].path configured; default-path migration was not evaluated"
                .to_owned(),
            None,
        ),
        LegacyStateLayoutObservation::LegacyAuditOnly => (
            CheckStatus::Warn,
            format!(
                "filesystem observation: legacy audit JSONL exists at {}; current state audit path {} is absent",
                layout.legacy_audit_path.display(),
                layout.current_audit_path.display()
            ),
            Some(
                "run oraclemcp doctor --fix to copy the legacy audit JSONL into the XDG state directory; the legacy file is left untouched",
            ),
        ),
        LegacyStateLayoutObservation::LegacyAndCurrentAudit => (
            CheckStatus::Warn,
            format!(
                "filesystem observation: legacy audit {} and current audit {} both exist; automatic merge is refused",
                layout.legacy_audit_path.display(),
                layout.current_audit_path.display()
            ),
            Some(
                "verify both audit chains manually; doctor --fix refuses to merge divergent append-only audit logs",
            ),
        ),
        LegacyStateLayoutObservation::Unsafe(reason) => (
            CheckStatus::Warn,
            format!("filesystem observation requires manual state-layout review: {reason}"),
            Some(
                "repair the filesystem layout manually; doctor --fix refuses symlinks and non-regular audit paths",
            ),
        ),
    };
    let status = if audit_status == CheckStatus::Fail {
        CheckStatus::Fail
    } else if layout_status == CheckStatus::Warn {
        CheckStatus::Warn
    } else if audit_status == CheckStatus::Skip || layout_status == CheckStatus::Skip {
        CheckStatus::Skip
    } else {
        CheckStatus::Pass
    };
    let result = CheckResult::new(ID, NAME, status, format!("{audit_detail}; {layout_detail}"));
    match fix {
        Some(fix) => result.with_fix(fix),
        None => result,
    }
}

/// IAM database-token source check (B16b). Refreshable source profiles report
/// only what doctor can observe: source kind and whether a successful source
/// invocation was explicitly observed. Legacy static-token profiles keep the
/// older near-expiry diagnostic.
fn check_iam_token(ctx: &DoctorContext<'_>) -> CheckResult {
    if let Some(source) = &ctx.iam_token_source {
        return iam_token_source_observation_check(source);
    }
    iam_token_expiry_check(ctx.iam_token.as_deref(), now_unix_seconds())
}

fn iam_token_source_observation_check(source: &DoctorIamTokenSourceObservation) -> CheckResult {
    const ID: u8 = 14;
    const NAME: &str = "IAM token";

    let invocation = match source.last_successful_invocation_unix {
        Some(ts) => format!("last_successful_invocation_unix={ts}"),
        None => "last_successful_invocation=not_observed_by_doctor".to_owned(),
    };
    CheckResult::new(
        ID,
        NAME,
        CheckStatus::Pass,
        format!(
            "OCI IAM database token source configured: source_kind={}; {invocation}; token_value=not_resolved_by_doctor",
            source.source_kind.as_str()
        ),
    )
}

/// Pure core of [`check_iam_token`]: classify an IAM token against `now_unix`.
/// Separated so the near-expiry logic is deterministic and unit-testable with a
/// synthetic JWT and a fixed clock.
fn iam_token_expiry_check(token: Option<&str>, now_unix: i64) -> CheckResult {
    const ID: u8 = 14;
    const NAME: &str = "IAM token";

    let Some(token) = token else {
        return CheckResult::new(
            ID,
            NAME,
            CheckStatus::Skip,
            "no OCI IAM database token is configured for this profile",
        );
    };
    let Some(exp) = crate::iam_token::jwt_exp_unix(token) else {
        // A diagnostic-only parse could not read a numeric `exp` claim. Warn so
        // the operator knows expiry cannot be checked ahead of a connect; the
        // driver still validates the token at connect time.
        return CheckResult::new(
            ID,
            NAME,
            CheckStatus::Warn,
            "an OCI IAM database token is configured but its JWT `exp` claim could not be read \
             (diagnostic only; the driver still validates the token at connect)",
        )
        .with_fix(
            "verify the configured token is a well-formed JWT; the server still injects it over \
             TCPS at connect",
        );
    };
    let remaining = exp - now_unix;
    if remaining <= 0 {
        CheckResult::new(
            ID,
            NAME,
            CheckStatus::Warn,
            format!(
                "the configured OCI IAM database token has expired ({}s ago); the next connect \
                 will be rejected",
                -remaining
            ),
        )
        .with_fix(
            "refresh the token (rotate ORACLEMCP_IAM_TOKEN / the token_env variable, or overwrite \
             token_file); it is re-read on every connect",
        )
    } else if remaining < crate::iam_token::IAM_TOKEN_EXPIRY_WARN_SECS {
        CheckResult::new(
            ID,
            NAME,
            CheckStatus::Warn,
            format!(
                "the configured OCI IAM database token expires in {remaining}s (under 5 minutes)"
            ),
        )
        .with_fix(
            "refresh the token soon; it is re-read on every connect, so a rotated env var / file \
             is picked up without a restart",
        )
    } else {
        CheckResult::new(
            ID,
            NAME,
            CheckStatus::Pass,
            format!("the configured OCI IAM database token is valid for another {remaining}s"),
        )
    }
}

/// Wall-clock Unix seconds for the IAM token near-expiry diagnostic.
fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn check_call_timeout(ctx: &DoctorContext<'_>) -> CheckResult {
    const ID: u8 = 12;
    const NAME: &str = "Call timeout";

    if !ctx.call_timeout_resolved {
        return CheckResult::new(
            ID,
            NAME,
            CheckStatus::Skip,
            "configuration observation unavailable: no profile resolved; this check does not probe direct oraclemcp-db caller timeouts",
        );
    }

    // Each timeout aspect contributes one detail segment and, when misconfigured,
    // one advisory (non-fatal) fix. Collecting them keeps the connect / call
    // posture (original) and the B1 inactivity / keepalive posture uniform.
    let mut details: Vec<String> = Vec::new();
    let mut fixes: Vec<&'static str> = Vec::new();

    match ctx.call_timeout {
        Some(timeout) if !timeout.is_zero() => details.push(format!(
            "configuration sets Oracle call timeout to {}s; request budget uses the same profile ceiling",
            timeout.as_secs()
        )),
        Some(_) | None => {
            details.push(
                "configuration disables Oracle call timeout; this check does not observe a driver round trip"
                    .to_owned(),
            );
            fixes.push("remove call_timeout_seconds = 0 or set it to a positive value such as 30");
        }
    }
    match ctx.connect_timeout_seconds {
        Some(0) => {
            details.push(
                "configuration sets Oracle connect timeout to 0; the documented thin-driver default is 20s (not probed)"
                    .to_owned(),
            );
            fixes.push(
                "remove connect_timeout_seconds = 0 or set it to a positive value such as 20",
            );
        }
        Some(seconds) => details.push(format!("configuration sets Oracle connect timeout to {seconds}s")),
        None => {
            details.push("no configured Oracle connect timeout; the documented thin-driver default is 20s (not probed)".to_owned())
        }
    }
    // B1: an authored `0` for either field is meaningless (both treat 0 as unset);
    // advise removing it. `None` is the honest driver default and passes.
    match ctx.inactivity_timeout_seconds {
        Some(0) => {
            details.push(
                "configuration sets Oracle inactivity timeout to 0; established-session behavior is not probed"
                    .to_owned(),
            );
            fixes.push(
                "remove inactivity_timeout_seconds = 0 or set it to a positive value such as 300",
            );
        }
        Some(seconds) => details.push(format!("configuration sets Oracle inactivity timeout to {seconds}s")),
        None => details.push(
            "no configured Oracle inactivity timeout; documented default is unbounded idle reads (not probed)"
                .to_owned(),
        ),
    }
    match ctx.keepalive_minutes {
        Some(0) => {
            details.push(
                "configuration sets Oracle keepalive (EXPIRE_TIME) to 0; dead-connection detection is not probed"
                    .to_owned(),
            );
            fixes.push("remove keepalive_minutes = 0 or set it to a positive value such as 10");
        }
        Some(minutes) => details.push(format!(
            "configuration requests Oracle keepalive (EXPIRE_TIME) every {minutes}m; runtime application is not probed"
        )),
        None => details.push("no configured Oracle keepalive (EXPIRE_TIME); runtime application is not probed".to_owned()),
    }

    let mut result = CheckResult::new(
        ID,
        NAME,
        if fixes.is_empty() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        details.join("; "),
    );
    if !fixes.is_empty() {
        result = result.with_fix(fixes.join("; "));
    }
    result
}

/// Upstream repository of the pinned thin `oracledb` driver (behavior-inventory).
const DRIVER_UPSTREAM_REPO: &str = "https://github.com/MuhDur/rust-oracledb";

/// Check 15 (B5): thin trio-stack provenance — the server, the pinned thin
/// `oracledb` driver, and the optional plsql-intelligence engine. This is an
/// **informational** `Pass` (a provenance surface for operators and agents), not
/// a health gate.
///
/// The driver version is [`oraclemcp_db::DRIVER_VERSION`] — a re-export of the
/// driver crate's own `VERSION` const (its `CARGO_PKG_VERSION`, resolved at the
/// driver's compile and surfaced through the one adapter seam, so it is never
/// named as a driver path outside the adapter) — and NOT this crate's
/// `env!("CARGO_PKG_VERSION")` (which would report `oraclemcp-core`, the wrong
/// crate). That is the whole point of the check: the reported driver line is
/// guaranteed to be the *pinned driver's* version.
fn check_trio_stack(ctx: &DoctorContext<'_>) -> CheckResult {
    const ID: u8 = 15;
    const NAME: &str = "Trio-stack provenance";

    // Every `oraclemcp-*` crate shares one workspace version, so this crate's
    // `CARGO_PKG_VERSION` is also the `oraclemcp-db` / server version.
    let server_version = env!("CARGO_PKG_VERSION");
    // Read from the DRIVER crate (via the db seam re-export), never this one —
    // the provenance guarantee that `reported == pinned` driver version.
    let driver_line = format!("thin oracledb {DRIVER_VERSION}");

    let plsql_status = if ctx.plsql_intelligence_detected {
        "detected"
    } else {
        "not detected"
    };

    CheckResult::new(
        ID,
        NAME,
        CheckStatus::Pass,
        format!(
            "build metadata observation: server db {server_version}; pinned driver {driver_line} ({DRIVER_UPSTREAM_REPO}); \
             plsql-intelligence {plsql_status}; this provenance check does not probe live connection options or runtime timeout behavior"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::RuntimeBuilder;
    use oraclemcp_db::{
        AuthAdapter, DbError, OracleBackend, OracleBind, OracleConnectOptions,
        OracleConnectionInfo, OracleRow,
    };

    /// Run `run_doctor` on a fresh current-thread runtime with an installed `Cx`.
    fn doctor(ctx: &DoctorContext<'_>) -> DoctorReport {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            run_doctor(&cx, ctx).await
        })
    }

    fn doctor_tmp_dir(name: &str) -> std::path::PathBuf {
        // Walk up with `parent()` rather than pushing "../..". The migration
        // path this helper feeds refuses parent traversal (a deliberate
        // security property, ee1b23ad), and `create_dir_all` does not
        // normalise, so a pushed ".." survived into the PathBuf and every
        // legacy-migration test was refused before it could run. Resolving the
        // workspace root here keeps the refusal strict and hands production
        // code a path with no ".." component (bead oraclemcp-7f4o9).
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest
            .parent()
            .and_then(std::path::Path::parent)
            .expect("crates/<crate> lives two levels below the workspace root");
        let mut path = workspace.join("target/tmp/oraclemcp-core-doctor-tests");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        path.push(format!("{}-{}-{name}", std::process::id(), nanos));
        std::fs::create_dir_all(&path).expect("test temp dir exists");
        std::fs::canonicalize(path).expect("test temp dir canonicalizes")
    }

    fn check_by_id(report: &DoctorReport, id: u8) -> &CheckResult {
        report
            .checks
            .iter()
            .find(|check| check.id == id)
            .expect("check present")
    }

    struct LiveMock;
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for LiveMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            // dba_objects/all_identifiers probes succeed -> Dba tier, plscope true.
            Ok(vec![OracleRow { columns: vec![] }])
        }
        async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    fn doctor_row(columns: &[(&str, Option<&str>)]) -> OracleRow {
        OracleRow {
            columns: columns
                .iter()
                .map(|(name, value)| {
                    (
                        (*name).to_owned(),
                        oraclemcp_db::OracleCell::new("VARCHAR2", value.map(str::to_owned)),
                    )
                })
                .collect(),
        }
    }

    struct VpdRlsDoctorMock {
        policy_visible: bool,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for VpdRlsDoctorMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            let normalized = sql.to_ascii_lowercase();
            if normalized.contains("sys_context('userenv', 'session_user')") {
                return Ok(vec![doctor_row(&[
                    ("SESSION_USER", Some("ORACLEMCP_D3_SIGHTED")),
                    ("CURRENT_SCHEMA", Some("ORACLEMCP_D3_OWNER")),
                    ("EDITION_NAME", Some("ORA$BASE")),
                ])]);
            }
            if normalized.contains("from session_roles") {
                return Ok(self
                    .policy_visible
                    .then(|| doctor_row(&[("ROLE", Some("SELECT_CATALOG_ROLE"))]))
                    .into_iter()
                    .collect());
            }
            if normalized.contains("count(*) as visible_policy_rows") {
                return Ok(vec![doctor_row(&[(
                    "VISIBLE_POLICY_ROWS",
                    Some(if self.policy_visible { "1" } else { "0" }),
                )])]);
            }
            if normalized.contains("from all_policies") {
                return Ok(self
                    .policy_visible
                    .then(|| {
                        doctor_row(&[
                            ("OBJECT_OWNER", Some("ORACLEMCP_D3_OWNER")),
                            ("OBJECT_NAME", Some("ORACLEMCP_D3_PROTECTED")),
                            ("POLICY_NAME", Some("ORACLEMCP_D3_VPD")),
                            ("PF_OWNER", Some("ORACLEMCP_D3_OWNER")),
                            ("PACKAGE", None),
                            ("FUNCTION", Some("ORACLEMCP_D3_VPD")),
                            ("SEL", Some("YES")),
                            ("INS", Some("NO")),
                            ("UPD", Some("NO")),
                            ("DEL", Some("NO")),
                            ("ENABLE", Some("YES")),
                        ])
                    })
                    .into_iter()
                    .collect());
            }
            Ok(Vec::new())
        }
        async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    struct PoolPingFailMock;

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for PoolPingFailMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Err(DbError::ConnectionLost("pool socket reset".to_owned()))
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            Ok(Vec::new())
        }

        async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    struct CancelledPreflightMock;

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for CancelledPreflightMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            if sql.contains("WHERE 1 = 0") {
                return Err(DbError::Cancelled(
                    "injected preflight cancellation".to_owned(),
                ));
            }
            Ok(Vec::new())
        }

        async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    /// Succeeds through every dictionary-tier probe, then loses certainty on
    /// the later Diagnostics Pack feature probe. This proves preflight does not
    /// only protect its initial `WHERE 1 = 0` phase.
    struct LateCancelledPreflightMock;

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for LateCancelledPreflightMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            if sql.contains("control_management_pack_access") {
                return Err(DbError::Cancelled(
                    "late feature-probe cancellation: token=never-render-this".to_owned(),
                ));
            }
            Ok(Vec::new())
        }

        async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    /// A live mock whose `SESSION_PRIVS` includes write-implying privileges
    /// (exercises the A2 write-posture WARN path).
    struct WriteCapableMock;
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for WriteCapableMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            if sql.to_ascii_lowercase().contains("session_privs") {
                return Ok(["CREATE SESSION", "CREATE ANY TABLE", "INSERT ANY TABLE"]
                    .iter()
                    .map(|p| OracleRow {
                        columns: vec![(
                            "PRIVILEGE".to_owned(),
                            oraclemcp_db::OracleCell::new("VARCHAR2", Some((*p).to_owned())),
                        )],
                    })
                    .collect());
            }
            Ok(vec![OracleRow { columns: vec![] }])
        }
        async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[test]
    fn report_has_seventeen_checks_and_classifier_self_test_passes() {
        let report = doctor(&DoctorContext::default());
        assert_eq!(report.checks.len(), 17);
        let selftest = report.checks.iter().find(|c| c.id == 8).unwrap();
        assert_eq!(selftest.status, CheckStatus::Pass, "{}", selftest.detail);
        // The IAM-token near-expiry check (14) skips cleanly when no token is set.
        let iam = report.checks.iter().find(|c| c.id == 14).unwrap();
        assert_eq!(iam.status, CheckStatus::Skip, "{}", iam.detail);
        // The trio-stack provenance check (15) is informational and always passes.
        let trio = report.checks.iter().find(|c| c.id == 15).unwrap();
        assert_eq!(trio.status, CheckStatus::Pass, "{}", trio.detail);
    }

    /// Field-test regression: checks print in numeric id order (13 used to
    /// render before 12 in the human-readable output).
    #[test]
    fn checks_are_ordered_by_id() {
        let report = doctor(&DoctorContext::default());
        let ids: Vec<u8> = report.checks.iter().map(|c| c.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "doctor checks must be in ascending id order");
    }

    #[test]
    fn offline_skips_live_checks_and_does_not_fail() {
        let report = doctor(&DoctorContext::default());
        // Connectivity, role/standby, privilege-tier, snapshot, the DBA-suite
        // preflight (10), write posture (11), and call-timeout posture (12)
        // all skip offline/no-profile.
        for id in [3u8, 4, 6, 7, 10, 11, 12, 17] {
            let c = report.checks.iter().find(|c| c.id == id).unwrap();
            assert_eq!(
                c.status,
                CheckStatus::Skip,
                "check {id} should skip offline: {}",
                c.detail
            );
        }
        let virtual_tools = report.checks.iter().find(|c| c.id == 9).unwrap();
        assert_eq!(virtual_tools.status, CheckStatus::Pass);
        // No live check should FAIL purely because we are offline.
        assert!(!report.any_failed());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn disabled_call_timeout_warns() {
        let ctx = DoctorContext {
            call_timeout_resolved: true,
            call_timeout: None,
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let timeout = report.checks.iter().find(|c| c.id == 12).unwrap();
        assert_eq!(timeout.status, CheckStatus::Warn, "{}", timeout.detail);
        assert!(timeout.detail.contains("configuration disables"));
        assert!(
            timeout
                .detail
                .contains("does not observe a driver round trip")
        );
        assert!(
            timeout
                .fix
                .as_deref()
                .unwrap_or_default()
                .contains("call_timeout_seconds")
        );
    }

    #[test]
    fn skipped_custom_tools_are_reported_as_a_warning() {
        let report = doctor(&DoctorContext {
            skipped_custom_tools: vec![SkippedCustomTool {
                name: "broken.toml".to_owned(),
                reason: "file is malformed".to_owned(),
            }],
            ..DoctorContext::default()
        });
        let virtual_tools = check_by_id(&report, 9);
        assert_eq!(virtual_tools.status, CheckStatus::Warn);
        assert!(
            virtual_tools
                .detail
                .contains("broken.toml: file is malformed")
        );
        assert!(virtual_tools.detail.contains("not available"));
    }

    #[test]
    fn positive_call_timeout_passes() {
        let ctx = DoctorContext {
            call_timeout_resolved: true,
            call_timeout: Some(Duration::from_secs(30)),
            connect_timeout_seconds: Some(20),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let timeout = report.checks.iter().find(|c| c.id == 12).unwrap();
        assert_eq!(timeout.status, CheckStatus::Pass, "{}", timeout.detail);
        assert!(
            timeout
                .detail
                .contains("configuration sets Oracle connect timeout to 20s")
        );
    }

    #[test]
    fn zero_connect_timeout_warns() {
        let ctx = DoctorContext {
            call_timeout_resolved: true,
            call_timeout: Some(Duration::from_secs(30)),
            connect_timeout_seconds: Some(0),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let timeout = report.checks.iter().find(|c| c.id == 12).unwrap();
        assert_eq!(timeout.status, CheckStatus::Warn, "{}", timeout.detail);
        assert!(
            timeout
                .detail
                .contains("configuration sets Oracle connect timeout to 0")
        );
        assert!(
            timeout
                .fix
                .as_deref()
                .unwrap_or_default()
                .contains("connect_timeout_seconds")
        );
    }

    #[test]
    fn zero_inactivity_timeout_warns() {
        let ctx = DoctorContext {
            call_timeout_resolved: true,
            call_timeout: Some(Duration::from_secs(30)),
            inactivity_timeout_seconds: Some(0),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let timeout = report.checks.iter().find(|c| c.id == 12).unwrap();
        assert_eq!(timeout.status, CheckStatus::Warn, "{}", timeout.detail);
        assert!(
            timeout
                .detail
                .contains("configuration sets Oracle inactivity timeout to 0")
        );
        assert!(
            timeout
                .fix
                .as_deref()
                .unwrap_or_default()
                .contains("inactivity_timeout_seconds")
        );
    }

    #[test]
    fn positive_inactivity_timeout_passes() {
        let ctx = DoctorContext {
            call_timeout_resolved: true,
            call_timeout: Some(Duration::from_secs(30)),
            inactivity_timeout_seconds: Some(300),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let timeout = report.checks.iter().find(|c| c.id == 12).unwrap();
        assert_eq!(timeout.status, CheckStatus::Pass, "{}", timeout.detail);
        assert!(
            timeout
                .detail
                .contains("configuration sets Oracle inactivity timeout to 300s")
        );
    }

    #[test]
    fn zero_keepalive_minutes_warns() {
        let ctx = DoctorContext {
            call_timeout_resolved: true,
            call_timeout: Some(Duration::from_secs(30)),
            keepalive_minutes: Some(0),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let timeout = report.checks.iter().find(|c| c.id == 12).unwrap();
        assert_eq!(timeout.status, CheckStatus::Warn, "{}", timeout.detail);
        assert!(
            timeout
                .detail
                .contains("configuration sets Oracle keepalive (EXPIRE_TIME) to 0")
        );
        assert!(
            timeout
                .fix
                .as_deref()
                .unwrap_or_default()
                .contains("keepalive_minutes")
        );
    }

    #[test]
    fn positive_keepalive_minutes_passes() {
        let ctx = DoctorContext {
            call_timeout_resolved: true,
            call_timeout: Some(Duration::from_secs(30)),
            keepalive_minutes: Some(10),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let timeout = report.checks.iter().find(|c| c.id == 12).unwrap();
        assert_eq!(timeout.status, CheckStatus::Pass, "{}", timeout.detail);
        assert!(
            timeout
                .detail
                .contains("configuration requests Oracle keepalive (EXPIRE_TIME) every 10m")
        );
        assert!(timeout.detail.contains("runtime application is not probed"));
    }

    #[test]
    fn trio_stack_reports_pinned_driver_version_and_provenance() {
        let report = doctor(&DoctorContext::default());
        let trio = report.checks.iter().find(|c| c.id == 15).unwrap();
        assert_eq!(trio.status, CheckStatus::Pass, "{}", trio.detail);

        // The DoD: the reported driver version equals the DRIVER crate's own
        // `VERSION` const (re-exported at the db seam as `DRIVER_VERSION`),
        // never this crate's CARGO_PKG_VERSION.
        assert!(!DRIVER_VERSION.is_empty(), "driver VERSION must be set");
        assert!(
            trio.detail
                .contains(&format!("thin oracledb {DRIVER_VERSION}")),
            "trio-stack must report the pinned driver line: {}",
            trio.detail
        );
        // The assertion above derives the expectation from the driver seam, so
        // an intentional exact-pin bump cannot leave a second version literal
        // behind in this doctor contract.

        // Server / db (workspace) version is present.
        assert!(
            trio.detail
                .contains(&format!("server db {}", env!("CARGO_PKG_VERSION"))),
            "trio-stack must report the server db version: {}",
            trio.detail
        );
        assert!(trio.detail.starts_with("build metadata observation:"));
        assert!(
            trio.detail
                .contains("does not probe live connection options or runtime timeout behavior")
        );
        assert!(!trio.detail.contains("rust-oracledb#14"));
        // plsql-intelligence status line (default build / library caller: absent).
        assert!(trio.detail.contains("plsql-intelligence not detected"));
    }

    #[test]
    fn trio_stack_reports_plsql_intelligence_when_detected() {
        let ctx = DoctorContext {
            plsql_intelligence_detected: true,
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let trio = report.checks.iter().find(|c| c.id == 15).unwrap();
        assert_eq!(trio.status, CheckStatus::Pass, "{}", trio.detail);
        assert!(trio.detail.contains("plsql-intelligence detected"));

        // B5.1 no-leak: the status is a bool render — JUST `detected`, never a
        // filesystem/crate path or a version. Isolate the plsql-intelligence
        // segment (the rest of the detail legitimately carries URLs) and assert.
        let segment = trio
            .detail
            .split("; ")
            .find(|s| s.starts_with("plsql-intelligence"))
            .expect("plsql-intelligence status segment present");
        assert_eq!(segment, "plsql-intelligence detected");
        assert!(
            !segment.contains('/') && !segment.contains('\\'),
            "status must not leak a path: {segment}"
        );
        assert!(
            !segment.chars().any(|c| c.is_ascii_digit()),
            "status must not leak a version: {segment}"
        );
    }

    #[test]
    fn live_connection_runs_connectivity_role_and_privilege_checks() {
        let conn = LiveMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        assert_eq!(
            report.checks.iter().find(|c| c.id == 3).unwrap().status,
            CheckStatus::Pass
        );
        assert_eq!(
            report.checks.iter().find(|c| c.id == 6).unwrap().status,
            CheckStatus::Pass
        );
    }

    #[test]
    fn doctor_rls_vpd_visibility_names_visible_policy() {
        let conn = VpdRlsDoctorMock {
            policy_visible: true,
        };
        let report = doctor(&DoctorContext {
            conn: Some(&conn),
            ..DoctorContext::default()
        });
        let check = check_by_id(&report, 17);
        assert_eq!(check.status, CheckStatus::Warn, "{}", check.detail);
        assert!(
            check.detail.contains("ORACLEMCP_D3_VPD"),
            "{}",
            check.detail
        );
        assert!(
            check.detail.contains("session_user=ORACLEMCP_D3_SIGHTED"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn doctor_rls_vpd_visibility_warns_on_empty_policy_catalog() {
        let conn = VpdRlsDoctorMock {
            policy_visible: false,
        };
        let report = doctor(&DoctorContext {
            conn: Some(&conn),
            ..DoctorContext::default()
        });
        let check = check_by_id(&report, 17);
        assert_eq!(check.status, CheckStatus::Warn, "{}", check.detail);
        assert!(
            check.detail.contains("zero visible rows"),
            "empty ALL_POLICIES must not render as no RLS/VPD: {}",
            check.detail
        );
    }

    #[test]
    fn live_connectivity_detail_reports_connection_strategy() {
        let conn = LiveMock;
        let stateless = LiveMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            stateless_conn: Some(&stateless),
            stateless_pool_configured: true,
            connection_strategy: Some("hybrid_pool".to_owned()),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();

        assert_eq!(connectivity.status, CheckStatus::Pass);
        assert_eq!(
            connectivity.detail,
            "Oracle ping round trips succeeded for every opened connection; \
             connection authenticated (runtime wiring: hybrid_pool)"
        );
    }

    #[test]
    fn configured_stateless_pool_that_did_not_open_is_not_reported_healthy() {
        let conn = LiveMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            stateless_pool_configured: true,
            connection_strategy: Some("pinned_plus_stateless_degraded".to_owned()),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();

        assert_eq!(connectivity.status, CheckStatus::Warn);
        assert!(connectivity.detail.contains("stateless pool did not open"));
        assert!(connectivity.fix.is_some());
    }

    #[test]
    fn stateless_pool_ping_failure_fails_connectivity_after_pinned_success() {
        let conn = LiveMock;
        let stateless = PoolPingFailMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            stateless_conn: Some(&stateless),
            stateless_pool_configured: true,
            connection_strategy: Some("pinned_plus_stateless".to_owned()),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();

        assert_eq!(connectivity.status, CheckStatus::Fail);
        assert!(
            connectivity
                .detail
                .contains("pinned-session ping succeeded")
        );
        assert!(connectivity.detail.contains("stateless-pool ping failed"));
        assert_eq!(
            connectivity.failure_class,
            Some(ErrorClass::ConnectionFailed)
        );
    }

    #[test]
    fn protected_profile_with_write_ceiling_warns() {
        let ctx = DoctorContext {
            protected_profile_writable: true,
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let priv_check = report.checks.iter().find(|c| c.id == 6).unwrap();
        assert_eq!(priv_check.status, CheckStatus::Warn);
        assert!(priv_check.fix.is_some());
        // A warning is not a failure.
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn missing_tns_admin_directory_fails_with_a_fix() {
        let ctx = DoctorContext {
            tns_admin: Some("/nonexistent/tns/dir/xyz".to_owned()),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let tns = report.checks.iter().find(|c| c.id == 2).unwrap();
        assert_eq!(tns.status, CheckStatus::Fail);
        assert!(tns.fix.is_some());
        assert!(tns.detail.contains("filesystem metadata observation"));
        let rendered = report.to_json().to_string();
        assert!(!rendered.contains("/nonexistent/tns/dir/xyz"));
        assert_eq!(report.exit_code(), 1, "a failed check exits non-zero");
    }

    #[test]
    fn wallet_path_is_not_rendered_in_doctor_output() {
        let ctx = DoctorContext {
            wallet_location: Some("/home/operator/private-wallet".to_owned()),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let rendered = report.to_json().to_string();
        assert!(!rendered.contains("/home/operator/private-wallet"));
        let tns = report.checks.iter().find(|c| c.id == 2).unwrap();
        assert_eq!(tns.status, CheckStatus::Fail);
        assert!(tns.detail.contains(
            "filesystem metadata observation: configured wallet path is not a directory"
        ));
    }

    #[test]
    fn connection_error_redacts_profile_sensitive_values() {
        let ctx = DoctorContext {
            connection_error: Some(
                "ORA-01017 for APP_USER/super_secret@dbhost:1521/private_service using /wallets/private and iam.jwt.token"
                    .to_owned(),
            ),
            sensitive_values: vec![
                "APP_USER".to_owned(),
                "super_secret".to_owned(),
                "dbhost:1521/private_service".to_owned(),
                "/wallets/private".to_owned(),
                "iam.jwt.token".to_owned(),
            ],
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let serialized = serde_json::to_string(&report.to_json()).expect("json");
        for forbidden in [
            "APP_USER",
            "super_secret",
            "dbhost:1521/private_service",
            "/wallets/private",
            "iam.jwt.token",
        ] {
            assert!(!serialized.contains(forbidden), "{serialized}");
        }
        assert!(serialized.contains("ORA-01017"));
        assert!(serialized.contains("\"ora_code\":1017"));
        assert!(serialized.contains("\"failure_class\":\"INSUFFICIENT_PRIVILEGE\""));
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
        assert_eq!(connectivity.status, CheckStatus::Fail);
        assert_eq!(connectivity.ora_code, Some(1017));
        assert_eq!(
            connectivity.failure_class,
            Some(oraclemcp_error::ErrorClass::InsufficientPrivilege)
        );
        assert!(
            connectivity
                .fix
                .as_deref()
                .unwrap()
                .contains("credential_ref")
        );
    }

    #[test]
    fn wallet_password_ref_resolution_error_has_actionable_fix() {
        let ctx = DoctorContext {
            connection_error: Some(
                "failed to resolve wallet_password_ref for profile `tcps`: secret not found"
                    .to_owned(),
            ),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
        assert_eq!(connectivity.status, CheckStatus::Fail);
        assert!(
            connectivity
                .fix
                .as_deref()
                .unwrap()
                .contains("wallet_password_ref")
        );
    }

    #[test]
    fn wallet_decrypt_password_echo_is_redacted() {
        const PASSWORD: &str = "PlainWalletPasswordEcho";
        let ctx = DoctorContext {
            connection_error: Some(format!(
                "wallet error: PKCS12 decrypt failed: invalid password `{PASSWORD}`"
            )),
            sensitive_values: vec![PASSWORD.to_owned()],
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let serialized = serde_json::to_string(&report.to_json()).expect("json");
        assert!(!serialized.contains(PASSWORD), "{serialized}");
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
        assert!(connectivity.detail.contains(crate::redacted::REDACTED));
    }

    #[test]
    fn iam_token_refresh_failure_redacts_jwt() {
        const TOKEN: &str = "synthetic-iam-refresh-token-fixture";
        let ctx = DoctorContext {
            connection_error: Some(format!(
                "IAM token refresh failed: TokenSourceError: {TOKEN}"
            )),
            sensitive_values: vec![TOKEN.to_owned()],
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let serialized = serde_json::to_string(&report.to_json()).expect("json");
        assert!(!serialized.contains(TOKEN), "{serialized}");
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
        assert!(connectivity.detail.contains(crate::redacted::REDACTED));
    }

    /// A synthetic, unsigned JWT-shaped token `header.payload.` whose payload is a
    /// base64url `{"exp":<exp>}`. NOT a real token; the CN/claims are synthetic
    /// and there is no signature.
    fn synthetic_jwt_with_exp(exp: i64) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        fn b64url(bytes: &[u8]) -> String {
            let mut out = String::new();
            let (mut buffer, mut bits) = (0u32, 0u32);
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
        format!(
            "{}.{}.",
            b64url(br#"{"alg":"none"}"#),
            b64url(format!(r#"{{"exp":{exp},"sub":"synthetic-subject"}}"#).as_bytes())
        )
    }

    #[test]
    fn iam_token_check_skips_when_no_token_configured() {
        let ctx = DoctorContext::default();
        let report = doctor(&ctx);
        let iam = report
            .checks
            .iter()
            .find(|c| c.id == 14)
            .expect("iam check");
        assert_eq!(iam.status, CheckStatus::Skip);
    }

    #[test]
    fn iam_token_check_passes_when_far_from_expiry() {
        // exp comfortably beyond the 5-minute warning window.
        let token = synthetic_jwt_with_exp(now_unix_seconds() + 3_600);
        let ctx = DoctorContext {
            iam_token: Some(token),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let iam = report
            .checks
            .iter()
            .find(|c| c.id == 14)
            .expect("iam check");
        assert_eq!(iam.status, CheckStatus::Pass, "{}", iam.detail);
    }

    #[test]
    fn iam_token_check_warns_when_within_five_minutes() {
        // Directly exercise the pure check with a fixed clock: exp is 60s away.
        let now = 1_000_000_000;
        let token = synthetic_jwt_with_exp(now + 60);
        let result = iam_token_expiry_check(Some(&token), now);
        assert_eq!(result.status, CheckStatus::Warn, "{}", result.detail);
        assert!(result.detail.contains("60s"));
        assert!(result.detail.contains("under 5 minutes"));
        assert!(result.fix.is_some());
    }

    #[test]
    fn iam_token_check_warns_when_already_expired() {
        let now = 1_000_000_000;
        let token = synthetic_jwt_with_exp(now - 120);
        let result = iam_token_expiry_check(Some(&token), now);
        assert_eq!(result.status, CheckStatus::Warn, "{}", result.detail);
        assert!(result.detail.contains("expired"));
    }

    #[test]
    fn iam_token_check_warns_when_exp_unreadable() {
        let result = iam_token_expiry_check(Some("not-a-jwt-without-exp"), 1_000_000_000);
        assert_eq!(result.status, CheckStatus::Warn, "{}", result.detail);
        assert!(result.detail.contains("could not be read"));
    }

    #[test]
    fn iam_token_check_never_renders_the_token() {
        // Adversarial non-leak: a sentinel embedded in the JWT header must not
        // reach any rendered doctor surface (detail, fix, or serialized report).
        const SENTINEL: &str = "SECRET_JWT_SENTINEL";
        // Put the sentinel in the header segment so the token is a distinct,
        // greppable string while its payload still carries a readable exp.
        let payload = {
            const ALPHABET: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let bytes = format!(r#"{{"exp":{}}}"#, now_unix_seconds() + 30).into_bytes();
            let mut out = String::new();
            let (mut buffer, mut bits) = (0u32, 0u32);
            for b in bytes {
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
        };
        let token = format!("{SENTINEL}.{payload}.sig");
        let ctx = DoctorContext {
            iam_token: Some(token.clone()),
            sensitive_values: vec![token],
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let iam = report
            .checks
            .iter()
            .find(|c| c.id == 14)
            .expect("iam check");
        assert_eq!(iam.status, CheckStatus::Warn, "{}", iam.detail);
        assert!(
            !iam.detail.contains(SENTINEL),
            "detail leaked: {}",
            iam.detail
        );
        let serialized = serde_json::to_string(&report.to_json()).expect("json");
        assert!(
            !serialized.contains(SENTINEL),
            "report leaked: {serialized}"
        );
    }

    /// The comment above `wallet_error_kind` used to assert that every variant
    /// the pinned driver can produce is mapped explicitly. It was not true:
    /// `WalletError::TooLarge` fell into the `_` arm and was reported to the
    /// operator as `Pem` — "regenerate ewallet.pem with valid PEM material" for
    /// a wallet whose bytes were never parsed, because the image exceeded the
    /// driver's 16 MiB fail-closed limit.
    ///
    /// This exhausts the driver enum instead of restating a list: the match is
    /// written without a wildcard, so a variant added by a future pinned driver
    /// fails to compile here rather than silently landing on `Pem` again.
    #[test]
    fn wallet_error_kind_maps_every_pinned_driver_variant() {
        use oracledb_protocol::tls::wallet::WalletError;

        fn expected(error: &WalletError) -> DoctorWalletErrorKind {
            match error {
                WalletError::FileMissing(_) => DoctorWalletErrorKind::FileMissing,
                WalletError::Io { .. } => DoctorWalletErrorKind::Io,
                WalletError::TooLarge { .. } => DoctorWalletErrorKind::TooLarge,
                WalletError::Pem(_) => DoctorWalletErrorKind::Pem,
                WalletError::NoCertificates => DoctorWalletErrorKind::NoCertificates,
                WalletError::Sso(_) => DoctorWalletErrorKind::Sso,
                WalletError::SsoNotEnabled => DoctorWalletErrorKind::SsoNotEnabled,
                WalletError::Pkcs12(_) => DoctorWalletErrorKind::Pkcs12,
                WalletError::KeyDecrypt(_) => DoctorWalletErrorKind::KeyDecrypt,
                WalletError::PasswordRequired { .. } => DoctorWalletErrorKind::PasswordRequired,
                WalletError::UnsupportedFormat { .. } => DoctorWalletErrorKind::UnsupportedFormat,
                // Deliberately NO wildcard: see the doc comment.
                other => panic!("unmapped pinned-driver wallet variant: {other}"),
            }
        }

        let cases = [
            WalletError::FileMissing("/w".to_owned()),
            WalletError::TooLarge {
                maximum_bytes: 16 * 1024 * 1024,
            },
            WalletError::Pem("bad".to_owned()),
            WalletError::NoCertificates,
            WalletError::Sso("bad".to_owned()),
            WalletError::SsoNotEnabled,
            WalletError::Pkcs12("bad".to_owned()),
            WalletError::KeyDecrypt("bad".to_owned()),
            WalletError::PasswordRequired { format: "p12" },
            WalletError::UnsupportedFormat { format: "p12" },
        ];
        for error in &cases {
            assert_eq!(
                wallet_error_kind(error),
                expected(error),
                "mapping drifted for {error}"
            );
        }

        // The specific regression: an oversized image must not be reported as a
        // malformed PEM, and it must not be fallthrough-eligible (the driver's
        // falls_through_to_autologin does not list TooLarge either).
        let too_large = WalletError::TooLarge {
            maximum_bytes: 16 * 1024 * 1024,
        };
        assert_eq!(
            wallet_error_kind(&too_large),
            DoctorWalletErrorKind::TooLarge
        );
        assert_ne!(wallet_error_kind(&too_large), DoctorWalletErrorKind::Pem);
        assert!(!wallet_error_falls_through(DoctorWalletErrorKind::TooLarge));
        assert_eq!(
            wallet_error_label(DoctorWalletErrorKind::TooLarge),
            "TooLarge"
        );
    }

    #[test]
    fn wallet_error_classifier_covers_driver_wallet_variants() {
        let cases = [
            (
                "wallet error: wallet file is missing",
                DoctorWalletErrorKind::FileMissing,
                None,
            ),
            (
                "wallet error: failed to read wallet file: permission denied",
                DoctorWalletErrorKind::Io,
                None,
            ),
            (
                "wallet error: failed to parse wallet PEM: malformed pem",
                DoctorWalletErrorKind::Pem,
                None,
            ),
            (
                "wallet error: wallet contained no certificates",
                DoctorWalletErrorKind::NoCertificates,
                None,
            ),
            (
                "wallet error: cwallet.sso parse error: invalid SSO wallet magic",
                DoctorWalletErrorKind::Sso,
                None,
            ),
            (
                "wallet error: cwallet.sso support is experimental and not enabled; rebuild with --features experimental, or convert the wallet to ewallet.pem",
                DoctorWalletErrorKind::SsoNotEnabled,
                None,
            ),
            (
                "wallet error: wallet format ewallet.p12 is not supported by this thin build",
                DoctorWalletErrorKind::UnsupportedFormat,
                Some("ewallet.p12"),
            ),
        ];
        for (error, kind, format) in cases {
            let diagnostic = classify_wallet_error(error).unwrap_or_else(|| panic!("{error}"));
            assert_eq!(diagnostic.kind, kind, "{error}");
            assert_eq!(diagnostic.format.as_deref(), format, "{error}");
        }
    }

    #[test]
    fn wallet_unsupported_format_is_structured_no_path_leak() {
        let ctx = DoctorContext {
            connection_error: Some(
                "wallet error: wallet format ewallet.p12 is not supported by this thin build"
                    .to_owned(),
            ),
            wallet_location: Some("/wallets/private".to_owned()),
            sensitive_values: vec!["/wallets/private".to_owned()],
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
        assert_eq!(connectivity.status, CheckStatus::Fail);
        assert_eq!(
            connectivity.failure_class,
            Some(oraclemcp_error::ErrorClass::InvalidArguments)
        );
        assert_eq!(connectivity.auth_mode, Some(AuthModeClass::Tls));
        assert_eq!(
            connectivity.wallet_error,
            Some(DoctorWalletDiagnostic {
                kind: DoctorWalletErrorKind::UnsupportedFormat,
                format: Some("ewallet.p12".to_owned()),
            })
        );
        assert!(connectivity.fix.as_deref().unwrap().contains("ewallet.pem"));

        let serialized = serde_json::to_string(&report.to_json()).expect("json");
        assert!(serialized.contains("\"wallet_error\""));
        assert!(serialized.contains("\"kind\":\"unsupported_format\""));
        assert!(serialized.contains("\"format\":\"ewallet.p12\""));
        assert!(!serialized.contains("/wallets/private"), "{serialized}");
    }

    #[test]
    fn proxy_auth_config_error_has_actionable_fix() {
        let ctx = DoctorContext {
            connection_error: Some(
                "config load failed: connection profile `proxy` proxy_auth requires non-empty proxy_user and target_schema"
                    .to_owned(),
            ),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
        assert_eq!(connectivity.status, CheckStatus::Fail);
        let fix = connectivity.fix.as_deref().unwrap();
        assert!(fix.contains("proxy_auth.proxy_user"));
        assert!(fix.contains("target_schema"));
    }

    #[test]
    fn text_and_json_render() {
        let report = doctor(&DoctorContext::default());
        let text = report.to_text();
        assert!(text.contains("oraclemcp doctor"));
        assert!(text.contains("Classifier self-test"));
        let j = report.to_json();
        assert_eq!(j["checks"].as_array().unwrap().len(), 16);
        assert_eq!(j["exit_code"], json!(0));
    }

    #[test]
    fn auth_capability_matrix_is_thin_and_redaction_safe() {
        let opts = OracleConnectOptions {
            connect_string: "dbhost:1521/private_service".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("super_secret".to_owned()),
            auth_adapter: AuthAdapter::Proxy {
                proxy_user: "MCP_PROXY".to_owned(),
                target_schema: "APP_OWNER".to_owned(),
            },
            wallet_location: Some("/wallets/private".into()),
            wallet_password: Some("wallet_secret".to_owned()),
            ssl_server_cert_dn: Some("CN=private-db,O=Example,C=US".to_owned()),
            use_iam_token: true,
            iam_token: Some("iam.jwt.token".to_owned()),
            ..OracleConnectOptions::default()
        };

        let capabilities = DoctorAuthCapabilities::from_connect_options(&opts);
        assert_eq!(capabilities.driver, "thin");
        assert_eq!(capabilities.selected, DoctorAuthModeKind::Proxy);
        assert_eq!(capabilities.modes.len(), 6);
        for (kind, support) in [
            (
                DoctorAuthModeKind::Password,
                DoctorAuthModeSupport::Supported,
            ),
            (DoctorAuthModeKind::Proxy, DoctorAuthModeSupport::Supported),
            (
                DoctorAuthModeKind::IamToken,
                DoctorAuthModeSupport::Supported,
            ),
            (
                DoctorAuthModeKind::ExternalWallet,
                DoctorAuthModeSupport::UnsupportedInThin,
            ),
            (
                DoctorAuthModeKind::Kerberos,
                DoctorAuthModeSupport::UnsupportedInThin,
            ),
            (
                DoctorAuthModeKind::Radius,
                DoctorAuthModeSupport::UnsupportedInThin,
            ),
        ] {
            let row = capabilities
                .modes
                .iter()
                .find(|row| row.kind == kind)
                .expect("auth mode row exists");
            assert_eq!(row.support, support);
            assert_eq!(row.selected, kind == DoctorAuthModeKind::Proxy);
        }

        let iam = DoctorAuthCapabilities::from_connect_options(&OracleConnectOptions {
            use_iam_token: true,
            iam_token: Some("another.secret.token".to_owned()),
            ..OracleConnectOptions::default()
        });
        assert_eq!(iam.selected, DoctorAuthModeKind::IamToken);
        let external = DoctorAuthCapabilities::from_connect_options(&OracleConnectOptions {
            external_auth: true,
            ..OracleConnectOptions::default()
        });
        assert_eq!(external.selected, DoctorAuthModeKind::ExternalWallet);

        let ctx = DoctorContext {
            auth_capabilities: Some(capabilities),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let rendered = format!("{}\n{}", report.to_json(), report.to_text());
        for forbidden in [
            "dbhost:1521/private_service",
            "APP_USER",
            "super_secret",
            "MCP_PROXY",
            "APP_OWNER",
            "/wallets/private",
            "wallet_secret",
            "CN=private-db",
            "iam.jwt.token",
            "another.secret.token",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "{forbidden} leaked: {rendered}"
            );
        }
        for expected in [
            "\"driver\":\"thin\"",
            "\"selected\":\"proxy\"",
            "\"kind\":\"password\"",
            "\"kind\":\"iam_token\"",
            "\"kind\":\"external_wallet\"",
            "\"kind\":\"kerberos\"",
            "\"kind\":\"radius\"",
            "\"support\":\"supported\"",
            "\"support\":\"unsupported_in_thin\"",
            "auth capabilities: driver=thin selected=proxy",
        ] {
            assert!(
                rendered.contains(expected),
                "{expected} missing from {rendered}"
            );
        }
    }

    #[test]
    fn service_unit_caps_render_in_json_and_text() {
        let caps = DoctorServiceUnitCaps {
            manager: "systemd_user".to_owned(),
            configured: DoctorServiceUnitLimitCaps {
                notify: Some("type=notify notify_access=main".to_owned()),
                restart_policy: Some("on-failure".to_owned()),
                limit_nofile: Some(65_536),
                tasks_max: Some(512),
                memory_max_bytes: Some(2 * 1024 * 1024 * 1024),
                oom_score_adjust: Some(100),
            },
            effective: DoctorServiceUnitLimitCaps {
                notify: Some("notify_socket_present".to_owned()),
                restart_policy: None,
                limit_nofile: Some(1_048_576),
                tasks_max: Some(32_768),
                memory_max_bytes: None,
                oom_score_adjust: Some(0),
            },
            notes: vec!["current process limits".to_owned()],
        };
        let ctx = DoctorContext {
            service_unit_caps: Some(caps),
            ..DoctorContext::default()
        };

        let report = doctor(&ctx);
        let json = report.to_json();
        assert_eq!(
            json["service_unit_caps"]["configured"]["limit_nofile"],
            json!(65_536)
        );
        assert_eq!(
            json["service_unit_caps"]["effective"]["tasks_max"],
            json!(32_768)
        );
        let text = report.to_text();
        assert!(text.contains("service unit caps"), "{text}");
        assert!(text.contains("manager=systemd_user"), "{text}");
    }

    /// C9 — the DBA-suite preflight is report-only: with a live connection it
    /// reports the resolved tier/feature posture and never `Fail`s the suite,
    /// even when a subcheck would skip or historical perf history is missing.
    #[test]
    fn dba_suite_preflight_privilege_degradation_is_report_only() {
        // LiveMock answers every probe with one empty row: every tier probe
        // succeeds (Dba), detect_statspack succeeds, but detect_diagnostics_pack
        // is false (no DIAGNOSTIC value) -> historical resolves to Statspack, so
        // privilege degradation remains report-only; structurally uncertain
        // cancellation/session loss is covered separately as a hard failure.
        let conn = LiveMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let preflight_check = report.checks.iter().find(|c| c.id == 10).unwrap();
        assert_ne!(
            preflight_check.status,
            CheckStatus::Fail,
            "recognized privilege degradation remains report-only"
        );
        assert!(
            preflight_check.detail.contains("oracle_db_health")
                && preflight_check.detail.contains("oracle_top_queries"),
            "reports what each DBA tool will be able to run: {}",
            preflight_check.detail
        );
        assert_eq!(report.exit_code(), 0, "report-only never exits non-zero");
    }

    #[test]
    fn dba_suite_preflight_cancellation_is_a_hard_failure() {
        let conn = CancelledPreflightMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let preflight = check_by_id(&report, 10);
        assert_eq!(preflight.status, CheckStatus::Fail);
        assert!(preflight.detail.contains("uncertain database boundary"));
        assert_ne!(report.exit_code(), 0);
    }

    #[test]
    fn dba_suite_preflight_late_feature_probe_cancellation_is_a_redacted_hard_failure() {
        let conn = LateCancelledPreflightMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            sensitive_values: vec!["never-render-this".to_owned()],
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let preflight = check_by_id(&report, 10);
        assert_eq!(preflight.status, CheckStatus::Fail);
        assert!(preflight.detail.contains("uncertain database boundary"));
        assert!(!preflight.detail.contains("never-render-this"));
        assert_ne!(report.exit_code(), 0);
    }

    /// When connectivity fails, the preflight (10) skips rather than running any
    /// probe against a dead connection.
    #[test]
    fn dba_suite_preflight_skips_when_connectivity_failed() {
        let ctx = DoctorContext {
            connection_error: Some("could not open connection".to_owned()),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        assert_eq!(
            report.checks.iter().find(|c| c.id == 10).unwrap().status,
            CheckStatus::Skip
        );
    }

    #[test]
    fn connection_error_fails_connectivity_and_skips_dependent_live_checks() {
        let ctx = DoctorContext {
            connection_error: Some("could not open connection".to_owned()),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        assert_eq!(
            report.checks.iter().find(|c| c.id == 3).unwrap().status,
            CheckStatus::Fail
        );
        assert_eq!(
            report.checks.iter().find(|c| c.id == 4).unwrap().status,
            CheckStatus::Skip
        );
        assert_eq!(
            report.checks.iter().find(|c| c.id == 6).unwrap().status,
            CheckStatus::Skip
        );
    }

    #[test]
    fn unsupported_thin_auth_has_actionable_doctor_fix() {
        let ctx = DoctorContext {
            connection_error: Some(
                "external/wallet auth without username and password is not supported by the published thin driver yet"
                    .to_owned(),
            ),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
        assert_eq!(connectivity.status, CheckStatus::Fail);
        assert_eq!(
            connectivity.failure_class,
            Some(oraclemcp_error::ErrorClass::InvalidArguments)
        );
        assert_eq!(connectivity.ora_code, None);
        assert!(
            connectivity
                .fix
                .as_deref()
                .unwrap()
                .contains("username plus credential_ref")
        );
    }

    /// bhw6.2 — a simulated driver handshake failure (the structured
    /// `connect handshake failed [label]: …` envelope minted by the
    /// driver-seam adapter) surfaces the same plain-language guidance in the
    /// doctor's `fix:` line, including how to capture a handshake trace with
    /// ORACLEDB_TRACE_CONNECT=1. No raw driver string without next actions.
    #[test]
    fn simulated_handshake_failure_gets_actionable_fix_with_trace_guidance() {
        let cases: [(&str, &[&str], oraclemcp_error::ErrorClass); 8] = [
            (
                "connect handshake failed [unexpected-tns-packet]: the server replied with \
                 unexpected low-level TNS packet type 11 during the connect handshake \
                 (network layer, before authentication): unexpected TNS packet type 11 (Resend)",
                &["Oracle listener", "ORACLEDB_TRACE_CONNECT=1"],
                oraclemcp_error::ErrorClass::ConnectionFailed,
            ),
            (
                "connect handshake failed [connect-resend-loop]: the listener kept demanding \
                 CONNECT resends (5 rounds): server kept requesting CONNECT resend",
                &["listener log", "ORACLEDB_TRACE_CONNECT=1"],
                oraclemcp_error::ErrorClass::ConnectionFailed,
            ),
            (
                "connect handshake failed [fast-auth-not-advertised]: token/IAM authentication \
                 needs a server that advertises fast authentication: server did not advertise \
                 fast authentication",
                &["23ai", "credential_ref"],
                oraclemcp_error::ErrorClass::InvalidArguments,
            ),
            (
                "connect handshake failed [unsupported-wire-feature]: the server requires \
                 `Native Network Encryption and Data Integrity`: unsupported feature",
                &["SQLNET.ENCRYPTION_SERVER", "TCPS"],
                oraclemcp_error::ErrorClass::InvalidArguments,
            ),
            (
                "connect handshake failed [listener-refused]: the listener refused the \
                 connection (ERR=12514): it does not currently know the service name in the \
                 connect string: (DESCRIPTION=(ERR=12514))",
                &["lsnrctl services", "ERR=12514"],
                oraclemcp_error::ErrorClass::ConnectionFailed,
            ),
            (
                "connect handshake failed [listener-redirect-unsupported]: the listener \
                 redirected the connection to another endpoint: listener redirected this \
                 connection",
                &["connect directly", "ORACLEDB_TRACE_CONNECT=1"],
                oraclemcp_error::ErrorClass::ConnectionFailed,
            ),
            (
                "connect handshake failed [server-generation-unsupported]: the server \
                 negotiated TNS protocol version 298, below the minimum this thin driver \
                 supports (300 = Oracle 12.1): unsupported TNS version 298",
                &["Oracle 12.1"],
                oraclemcp_error::ErrorClass::InvalidArguments,
            ),
            (
                "connect handshake failed [handshake-protocol-error]: the TNS/TTC connect \
                 handshake failed at the protocol layer (wire framing/decode, not SQL): \
                 unknown TTC message type 11 at position 4",
                &["wire-protocol layer", "ORACLEDB_TRACE_CONNECT=1"],
                oraclemcp_error::ErrorClass::ConnectionFailed,
            ),
        ];
        for (error, expected_fix_fragments, expected_class) in cases {
            let ctx = DoctorContext {
                connection_error: Some(error.to_owned()),
                ..DoctorContext::default()
            };
            let report = doctor(&ctx);
            let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
            assert_eq!(connectivity.status, CheckStatus::Fail, "{error}");
            assert_eq!(
                connectivity.failure_class,
                Some(expected_class),
                "failure class for: {error}"
            );
            let fix = connectivity.fix.as_deref().unwrap_or_default();
            for fragment in expected_fix_fragments {
                assert!(
                    fix.contains(fragment),
                    "fix for `{error}` must mention `{fragment}`, got: {fix}"
                );
            }
        }
    }

    /// A5 (R4 acceptance) — the doctor distinguishes driver-unsupported auth
    /// (Kerberos / RADIUS / passwordless external wallet) from bad-creds, TLS,
    /// and listener failures, each with a precise typed [`AuthModeClass`]. This
    /// is the load-bearing distinction: a driver-unsupported mode never succeeds
    /// by retrying, whereas the other three are operator-fixable.
    #[test]
    fn doctor_classifies_auth_failure_modes_precisely() {
        let cases = [
            // Driver-unsupported enterprise auth (typed UnsupportedAuth from the
            // DB adapter) — distinct from a credential / TLS / listener failure.
            (
                "Kerberos authentication is not supported by the published thin driver yet",
                AuthModeClass::DriverUnsupported,
            ),
            (
                "RADIUS/native MFA authentication is not supported by the published thin driver yet",
                AuthModeClass::DriverUnsupported,
            ),
            (
                "external/wallet auth without username and password is not supported by the published thin driver yet",
                AuthModeClass::DriverUnsupported,
            ),
            // Bad credentials — the driver supports the mode, the secret was wrong.
            (
                "ORA-01017: invalid username/password; logon denied",
                AuthModeClass::BadCredentials,
            ),
            // TLS / TCPS transport failures, including an IAM token offered over
            // a non-TLS transport (requires TCPS — a transport failure, NOT a
            // driver-capability gap).
            (
                "DPY-3001: access token authentication requires a TLS (TCPS) connection",
                AuthModeClass::Tls,
            ),
            (
                "TLS/TCPS error: wallet handshake failed",
                AuthModeClass::Tls,
            ),
            // Listener / network / TNS resolution — never reached an auth step.
            ("ORA-12541: TNS:no listener", AuthModeClass::Listener),
            (
                "ORA-12154: TNS:could not resolve the connect identifier specified",
                AuthModeClass::Listener,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(
                classify_auth_mode(error),
                expected,
                "auth-mode classification for {error:?}"
            );
        }

        // And every category is mutually distinct (a driver-unsupported mode is
        // never collapsed into bad-creds / TLS / listener).
        use std::collections::HashSet;
        let distinct: HashSet<_> = cases.iter().map(|(_, class)| *class).collect();
        assert_eq!(
            distinct.len(),
            4,
            "all four auth-mode classes must be represented and distinct"
        );

        // The classification is surfaced on the connectivity check itself.
        let ctx = DoctorContext {
            connection_error: Some(
                "Kerberos authentication is not supported by the published thin driver yet"
                    .to_owned(),
            ),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
        assert_eq!(connectivity.status, CheckStatus::Fail);
        assert_eq!(
            connectivity.auth_mode,
            Some(AuthModeClass::DriverUnsupported)
        );
        // Driver-unsupported auth carries no ORA- code (it never reached Oracle).
        assert_eq!(connectivity.ora_code, None);
        // It serializes into the machine-readable report for agent triage.
        let serialized = serde_json::to_string(&report.to_json()).expect("json");
        assert!(
            serialized.contains("\"auth_mode\":\"driver_unsupported\""),
            "{serialized}"
        );
    }

    #[test]
    fn missing_profile_is_a_structured_setup_error() {
        let ctx = DoctorContext {
            connection_error: Some("connection profile `missing_ro` not found".to_owned()),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
        assert_eq!(connectivity.status, CheckStatus::Fail);
        assert_eq!(
            connectivity.failure_class,
            Some(oraclemcp_error::ErrorClass::InvalidArguments)
        );
        assert_eq!(connectivity.ora_code, None);
    }

    #[test]
    fn renderers_can_use_process_exit_code_override() {
        let ctx = DoctorContext {
            tns_admin: Some("/nonexistent/tns/dir/xyz".to_owned()),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.to_json_with_exit_code(2)["exit_code"], json!(2));
        assert!(
            report
                .to_text_with_exit_code(2)
                .contains("verdict: FAILED (exit 2)")
        );
    }

    #[test]
    fn self_heal_down_never_up_refuses_protected_profile_repair() {
        let ctx = DoctorContext {
            protected_profile_writable: true,
            ..DoctorContext::default()
        };
        let report = doctor(&ctx).with_fix_report();
        let fix = report.fix.as_ref().expect("fix report");

        assert_eq!(fix.exit_code, 4);
        assert_eq!(fix.outcome, DoctorFixOutcome::RefusedOutOfScope);
        assert!(
            fix.mutations.is_empty(),
            "fix must not mutate profile state"
        );
        assert!(
            fix.policy.forbidden_targets.contains(&"profile_max_level"),
            "profile max-level must be a hard forbidden target"
        );
        assert!(
            fix.policy.forbidden_targets.contains(&"audit_hash_chain"),
            "audit chain is detect-only"
        );
        assert!(
            fix.refusals
                .iter()
                .any(|refusal| refusal.target == "profile_max_level"),
            "{fix:?}"
        );
        assert_eq!(report.to_json_with_exit_code(4)["exit_code"], json!(4));
    }

    #[test]
    fn fix_policy_refuses_oracle_and_classifier_targets() {
        let report = DoctorReport {
            checks: vec![
                CheckResult::new(
                    8,
                    "Classifier self-test",
                    CheckStatus::Fail,
                    "classifier regression",
                )
                .with_fix("review classifier"),
                CheckResult::new(
                    11,
                    "Write posture",
                    CheckStatus::Warn,
                    "principal can write",
                )
                .with_fix("tighten grants"),
            ],
            profile_caps: None,
            auth_capabilities: None,
            service_health: None,
            service_unit_caps: None,
            fix: None,
        }
        .with_fix_report();
        let fix = report.fix.as_ref().expect("fix report");

        assert_eq!(fix.exit_code, 4);
        assert!(fix.mutations.is_empty());
        assert!(
            fix.refusals
                .iter()
                .any(|refusal| refusal.target == "classifier")
        );
        assert!(
            fix.refusals
                .iter()
                .any(|refusal| refusal.target == "oracle_database")
        );
    }

    // E4 (bead oraclemcp-eng-program-bp8ia.6.4): "no green-for-blocked
    // rendering anywhere". A `Skip` check ("not applicable this run", per this
    // module's own doc comment: "never a fake `Pass`") must never render,
    // serialize, or count as a `Pass` in any of doctor's three surfaces: the
    // enum itself, the JSON report, and the human `to_text()` report.
    #[test]
    fn skip_checks_never_render_or_serialize_as_pass() {
        let report = DoctorReport {
            checks: vec![
                CheckResult::new(
                    3,
                    "Connectivity",
                    CheckStatus::Skip,
                    "no profile configured",
                ),
                CheckResult::new(4, "Role/standby", CheckStatus::Skip, "offline run"),
            ],
            profile_caps: None,
            auth_capabilities: None,
            service_health: None,
            service_unit_caps: None,
            fix: None,
        };

        // Distinct enum identity: Skip is not Pass.
        assert_ne!(CheckStatus::Skip, CheckStatus::Pass);

        // JSON: each check serializes its own status; a skip must read "skip",
        // never "pass".
        let json = report.to_json();
        for check in json["checks"].as_array().expect("checks array") {
            assert_eq!(check["status"], json!("skip"));
            assert_ne!(check["status"], json!("pass"));
        }
        // All-skip is not a failure, so `ok` is honestly true — that is a
        // distinct claim from "everything passed", and nothing here asserts a
        // fabricated pass.
        assert_eq!(json["ok"], json!(true));
        assert!(!report.any_failed());
        assert_eq!(report.exit_code(), 0);

        // Human text: doctor has no "PASS" literal at all — status is
        // conveyed only by the per-check glyph and the final ok/FAILED
        // verdict word — and a Skip line must render with its own glyph, not
        // the Pass glyph.
        let text = report.to_text();
        assert!(!text.contains("PASS"));
        for line in text.lines().filter(|line| line.starts_with('[')) {
            assert!(
                line.starts_with("[-]"),
                "a Skip check must render with the '-' glyph, not the Pass glyph: {line}"
            );
        }
    }

    #[test]
    fn doctor_fix_fixture_gate_current_repairs_are_fixture_accounted() {
        let missing_tns = DoctorContext {
            tns_admin: Some("/nonexistent/tns/dir/doctor-fixture".to_owned()),
            ..DoctorContext::default()
        };
        let protected_profile = DoctorContext {
            protected_profile_writable: true,
            ..DoctorContext::default()
        };
        let classifier_regression = DoctorReport {
            checks: vec![
                CheckResult::new(
                    8,
                    "Classifier self-test",
                    CheckStatus::Fail,
                    "classifier regression",
                )
                .with_fix("review classifier"),
            ],
            profile_caps: None,
            auth_capabilities: None,
            service_health: None,
            service_unit_caps: None,
            fix: None,
        };
        let write_posture = DoctorReport {
            checks: vec![
                CheckResult::new(
                    11,
                    "Write posture",
                    CheckStatus::Warn,
                    "principal can write",
                )
                .with_fix("tighten grants"),
            ],
            profile_caps: None,
            auth_capabilities: None,
            service_health: None,
            service_unit_caps: None,
            fix: None,
        };
        let unresolved_without_fix = DoctorReport {
            checks: vec![CheckResult::new(
                99,
                "Synthetic unresolved failure",
                CheckStatus::Fail,
                "no scoped repair exists",
            )],
            profile_caps: None,
            auth_capabilities: None,
            service_health: None,
            service_unit_caps: None,
            fix: None,
        };
        let cases = [
            (
                "healthy_offline",
                doctor(&DoctorContext::default()).with_fix_report(),
                DoctorFixOutcome::Noop,
                0,
                &[][..],
            ),
            (
                "missing_tns_admin_directory",
                doctor(&missing_tns).with_fix_report(),
                DoctorFixOutcome::RefusedOutOfScope,
                4,
                &["operator_config"][..],
            ),
            (
                "protected_profile_writable",
                doctor(&protected_profile).with_fix_report(),
                DoctorFixOutcome::RefusedOutOfScope,
                4,
                &["profile_max_level"][..],
            ),
            (
                "classifier_regression",
                classifier_regression.with_fix_report(),
                DoctorFixOutcome::RefusedOutOfScope,
                4,
                &["classifier"][..],
            ),
            (
                "oracle_write_posture",
                write_posture.with_fix_report(),
                DoctorFixOutcome::RefusedOutOfScope,
                4,
                &["oracle_database"][..],
            ),
            (
                "unresolved_without_scoped_fix",
                unresolved_without_fix.with_fix_report(),
                DoctorFixOutcome::UnresolvedFindings,
                2,
                &[][..],
            ),
        ];

        for (name, report, expected_outcome, expected_exit, expected_targets) in cases {
            let fix = report.fix.as_ref().expect("fixture attaches fix report");
            assert_eq!(fix.outcome, expected_outcome, "{name}");
            assert_eq!(fix.exit_code, expected_exit, "{name}");
            assert!(
                fix.policy.backups_required && fix.policy.undo_required,
                "{name}: every future mutation must be backup-backed and undoable"
            );
            assert!(
                fix.mutations.is_empty(),
                "{name}: this fixture is not a scoped service-local migration; \
                 unsafe or unfixture-backed doctor --fix mutations must stay disabled"
            );
            for target in expected_targets {
                assert!(
                    fix.refusals.iter().any(|refusal| refusal.target == *target),
                    "{name}: expected refusal target {target}, got {:?}",
                    fix.refusals
                );
            }
        }
    }

    #[test]
    fn audit_posture_is_not_inferred_from_the_default_audit_path() {
        let root = doctor_tmp_dir("audit-posture");
        let layout = DoctorStateLayout {
            legacy_audit_path: root.join("config").join("audit.jsonl"),
            current_audit_path: root.join("state").join("audit").join("audit.jsonl"),
            migration_backup_dir: root.join("state").join("doctor-migrations").join("backups"),
            audit_path_configured: false,
        };

        let disabled = doctor(&DoctorContext {
            state_layout: Some(layout.clone()),
            audit_posture: Some(DoctorAuditPosture::DisabledReadOnly {
                unsigned_refusal_trail_path: Some(root.join("state").join("corpus/refusals.jsonl")),
            }),
            ..DoctorContext::default()
        });
        let check = check_by_id(&disabled, 13);
        assert_eq!(check.status, CheckStatus::Skip);
        assert!(check.detail.contains(
            "audit configuration observation: disabled (no signing key configured; profile is read-only everywhere reachable)"
        ));
        assert!(
            check
                .detail
                .contains("unsigned refusal trail: ACTIVE BY CONFIGURATION")
        );
        assert!(check.detail.contains("UNSIGNED, NOT TAMPER-EVIDENT"));
        assert!(check.detail.contains("this offline check does not open it"));
        assert!(
            check
                .detail
                .contains("README.md#signed-audit-and-unsigned-refusal-trail")
        );
        assert!(!check.detail.contains("audit default"));

        let configured = doctor(&DoctorContext {
            state_layout: Some(layout.clone()),
            audit_posture: Some(DoctorAuditPosture::SigningKeyConfigured {
                path: layout.current_audit_path.clone(),
            }),
            ..DoctorContext::default()
        });
        let check = check_by_id(&configured, 13);
        assert_eq!(check.status, CheckStatus::Pass);
        assert!(
            check
                .detail
                .contains("audit configuration observation: signing-key source configured"),
            "{}",
            check.detail
        );
        assert!(
            check
                .detail
                .contains("does not resolve the key or construct an auditor")
        );
        assert!(
            check
                .detail
                .contains("unsigned refusal trail: INACTIVE (signed audit is the configured tier)")
        );
        assert!(
            check
                .detail
                .contains("README.md#signed-audit-and-unsigned-refusal-trail")
        );

        let opted_out = doctor(&DoctorContext {
            state_layout: Some(layout.clone()),
            audit_posture: Some(DoctorAuditPosture::DisabledReadOnly {
                unsigned_refusal_trail_path: None,
            }),
            ..DoctorContext::default()
        });
        let check = check_by_id(&opted_out, 13);
        assert_eq!(check.status, CheckStatus::Skip);
        assert!(
            check
                .detail
                .contains("unsigned refusal trail: DISABLED BY CONFIGURATION")
        );
        assert!(
            check
                .detail
                .contains("README.md#signed-audit-and-unsigned-refusal-trail")
        );

        let refused = doctor(&DoctorContext {
            state_layout: Some(layout),
            audit_posture: Some(DoctorAuditPosture::StartupRefused {
                reachable_ceiling: OperatingLevel::ReadWrite,
            }),
            ..DoctorContext::default()
        });
        let check = check_by_id(&refused, 13);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("ORACLEMCP_AUDIT_KEY_REQUIRED"));
        assert!(check.detail.starts_with("audit configuration observation:"));
        assert!(
            check
                .detail
                .contains("unsigned refusal trail: UNAVAILABLE (the server does not start)")
        );
        assert!(
            check
                .detail
                .contains("README.md#signed-audit-and-unsigned-refusal-trail")
        );
    }

    #[test]
    fn observation_only_checks_name_their_evidence_source() {
        let report = doctor(&DoctorContext::default());

        let driver = check_by_id(&report, 1);
        assert!(driver.detail.starts_with("build-feature observation:"));
        assert!(driver.detail.contains("no connection was attempted"));

        let tns = check_by_id(&report, 2);
        assert!(tns.detail.starts_with("configuration observation:"));

        let timeout = check_by_id(&report, 12);
        assert!(
            timeout
                .detail
                .starts_with("configuration observation unavailable:")
        );

        let audit = check_by_id(&report, 13);
        assert!(audit.detail.starts_with("audit configuration observation"));

        let provenance = check_by_id(&report, 15);
        assert!(provenance.detail.starts_with("build metadata observation:"));
        assert!(
            provenance
                .detail
                .contains("does not probe live connection options or runtime timeout behavior")
        );
    }

    #[test]
    fn legacy_state_layout_detects_and_migrates_audit_jsonl_once() {
        let root = doctor_tmp_dir("legacy-state-migration");
        let legacy = root.join("config").join("audit.jsonl");
        let current = root.join("state").join("audit").join("audit.jsonl");
        let backups = root.join("state").join("doctor-migrations").join("backups");
        std::fs::create_dir_all(legacy.parent().expect("legacy parent"))
            .expect("legacy parent exists");
        let audit_jsonl = br#"{"schema_version":1,"seq":1}
"#;
        std::fs::write(&legacy, audit_jsonl).expect("seed legacy audit");
        let layout = DoctorStateLayout {
            legacy_audit_path: legacy.clone(),
            current_audit_path: current.clone(),
            migration_backup_dir: backups,
            audit_path_configured: false,
        };

        let report = doctor(&DoctorContext {
            state_layout: Some(layout.clone()),
            audit_posture: Some(DoctorAuditPosture::SigningKeyConfigured {
                path: layout.current_audit_path.clone(),
            }),
            ..DoctorContext::default()
        });
        let check = check_by_id(&report, 13);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(
            check
                .fix
                .as_deref()
                .is_some_and(|fix| fix.contains("doctor --fix"))
        );

        let mutation = apply_legacy_state_migration(Some(&layout))
            .expect("migration succeeds")
            .expect("migration applied");
        assert_eq!(mutation.id, "legacy_state_audit_jsonl_migration");
        assert_eq!(std::fs::read(&legacy).expect("read legacy"), audit_jsonl);
        assert_eq!(std::fs::read(&current).expect("read current"), audit_jsonl);
        assert_eq!(
            std::fs::read(&mutation.backup).expect("read backup"),
            audit_jsonl
        );

        let rerun = doctor(&DoctorContext {
            state_layout: Some(layout.clone()),
            audit_posture: Some(DoctorAuditPosture::SigningKeyConfigured {
                path: layout.current_audit_path.clone(),
            }),
            ..DoctorContext::default()
        })
        .with_fix_report_mutations(vec![mutation]);
        assert_eq!(check_by_id(&rerun, 13).status, CheckStatus::Pass);
        let fix = rerun.fix.as_ref().expect("fix report");
        assert_eq!(fix.outcome, DoctorFixOutcome::Applied);
        assert_eq!(fix.exit_code, 0);
        assert_eq!(fix.mutations.len(), 1);
        assert!(
            apply_legacy_state_migration(Some(&layout))
                .expect("second migration is noop")
                .is_none(),
            "migration must be idempotent after the byte-identical copy exists"
        );
    }

    #[cfg(unix)]
    #[test]
    fn legacy_migration_refuses_symlink_swaps_at_atomic_install() {
        let audit_jsonl = br#"{"schema_version":1,"seq":1}
"#;

        let parent_swap_root = doctor_tmp_dir("legacy-state-parent-symlink-race");
        let parent_swap_legacy = parent_swap_root.join("config").join("audit.jsonl");
        let parent_swap_current = parent_swap_root
            .join("state")
            .join("audit")
            .join("audit.jsonl");
        let parent_swap_backups = parent_swap_root
            .join("state")
            .join("doctor-migrations")
            .join("backups");
        std::fs::create_dir_all(parent_swap_legacy.parent().expect("legacy parent"))
            .expect("legacy parent exists");
        std::fs::write(&parent_swap_legacy, audit_jsonl).expect("seed legacy audit");
        let verified_parent = parent_swap_current
            .parent()
            .expect("current parent")
            .to_owned();
        let moved_parent = parent_swap_root.join("state").join("audit-verified");
        let attacker_parent = parent_swap_root.join("attacker-parent");
        std::fs::create_dir_all(&attacker_parent).expect("attacker parent exists");
        let attacker_parent_for_hook = attacker_parent.clone();
        set_doctor_atomic_install_hook(move || {
            std::fs::rename(&verified_parent, &moved_parent).expect("move verified parent");
            std::os::unix::fs::symlink(&attacker_parent_for_hook, &verified_parent)
                .expect("replace visible parent with symlink");
        });
        let parent_swap = DoctorStateLayout {
            legacy_audit_path: parent_swap_legacy.clone(),
            current_audit_path: parent_swap_current.clone(),
            migration_backup_dir: parent_swap_backups,
            audit_path_configured: false,
        };
        let parent_error = apply_legacy_state_migration(Some(&parent_swap))
            .expect_err("replaced destination parent must refuse");
        assert!(
            parent_error.contains("not a safe directory"),
            "{parent_error}"
        );
        assert!(
            !attacker_parent.join("audit.jsonl").exists(),
            "the held parent must prevent writes through the replacement symlink"
        );
        assert_eq!(
            std::fs::read(&parent_swap_legacy).expect("legacy source remains readable"),
            audit_jsonl
        );

        let destination_swap_root = doctor_tmp_dir("legacy-state-destination-symlink-race");
        let destination_swap_legacy = destination_swap_root.join("config").join("audit.jsonl");
        let destination_swap_current = destination_swap_root
            .join("state")
            .join("audit")
            .join("audit.jsonl");
        let destination_swap_backups = destination_swap_root
            .join("state")
            .join("doctor-migrations")
            .join("backups");
        std::fs::create_dir_all(destination_swap_legacy.parent().expect("legacy parent"))
            .expect("legacy parent exists");
        std::fs::write(&destination_swap_legacy, audit_jsonl).expect("seed legacy audit");
        let attacker_target = destination_swap_root.join("attacker-target");
        set_doctor_atomic_install_hook({
            let destination_swap_current = destination_swap_current.clone();
            let attacker_target = attacker_target.clone();
            move || {
                std::os::unix::fs::symlink(&attacker_target, &destination_swap_current)
                    .expect("replace destination with symlink");
            }
        });
        let destination_swap = DoctorStateLayout {
            legacy_audit_path: destination_swap_legacy.clone(),
            current_audit_path: destination_swap_current,
            migration_backup_dir: destination_swap_backups,
            audit_path_configured: false,
        };
        let destination_error = apply_legacy_state_migration(Some(&destination_swap))
            .expect_err("replacement destination must preserve create-new semantics");
        assert!(
            destination_error.contains("failed to install"),
            "{destination_error}"
        );
        assert!(
            !attacker_target.exists(),
            "the destination symlink must never receive the migration write"
        );
        assert_eq!(
            std::fs::read(&destination_swap_legacy).expect("legacy source remains readable"),
            audit_jsonl
        );
    }

    /// A2 — a read-only (least-privilege) principal: the write-posture check (11)
    /// passes and reports read-only posture; the suite never fails.
    #[test]
    fn read_only_principal_reports_read_only_write_posture() {
        let conn = LiveMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            proxy_user: true,
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let posture = report.checks.iter().find(|c| c.id == 11).unwrap();
        assert_eq!(posture.status, CheckStatus::Pass, "{}", posture.detail);
        assert!(posture.detail.contains("read-only posture"));
        assert!(
            posture
                .detail
                .contains("proxy/least-privilege connect user")
        );
        assert_eq!(report.exit_code(), 0);
    }

    /// A2 — a write-capable principal is WARNED (not least-privilege), with the
    /// offending privileges named; a warning never fails the suite.
    #[test]
    fn write_capable_principal_warns_with_evidence() {
        let conn = WriteCapableMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let posture = report.checks.iter().find(|c| c.id == 11).unwrap();
        assert_eq!(posture.status, CheckStatus::Warn, "{}", posture.detail);
        assert!(posture.detail.contains("principal CAN write"));
        assert!(posture.detail.contains("CREATE ANY TABLE"));
        assert!(posture.fix.as_deref().unwrap().contains("read-only proxy"));
        assert_eq!(report.exit_code(), 0, "a warning is not a failure");
    }

    /// A4 — the write-posture check reports the wallet truth table for this
    /// default build: all three wallet artifacts are supported by the pinned
    /// driver's public wallet loaders.
    #[test]
    fn doctor_reports_supported_wallet_modes() {
        let conn = LiveMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let posture = report.checks.iter().find(|c| c.id == 11).unwrap();
        for needle in ["cwallet.sso", "ewallet.pem", "ewallet.p12"] {
            assert!(
                posture.detail.contains(needle),
                "wallet mode {needle} should be reported: {}",
                posture.detail
            );
        }
        assert!(posture.detail.contains("supported"));
        assert!(
            supported_wallet_modes()
                .iter()
                .any(|m| m.mode == "ewallet.pem" && m.supported)
        );
        assert!(
            supported_wallet_modes()
                .iter()
                .any(|m| m.mode == "cwallet.sso" && m.supported)
        );
        assert!(
            supported_wallet_modes()
                .iter()
                .any(|m| m.mode == "ewallet.p12" && m.supported)
        );
    }
}
