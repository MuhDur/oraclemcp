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

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use oraclemcp_db::{
    AuthAdapter, DiagnosticsSource, OracleConnectOptions, OracleConnection,
    canonical_nls_statements, detect_oracle_driver, detect_standby, preflight, probe_privileges,
    probe_write_posture, supported_wallet_modes,
};
use oraclemcp_error::{ErrorClass, classify_ora_code, parse_ora_code};
use oraclemcp_guard::{Classifier, ClassifierConfig, OperatingLevel};
use serde::Serialize;
use serde_json::{Value, json};

use crate::service_app::ServiceAppDoctorSnapshot;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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

/// Authentication modes the thin driver reports to `doctor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorAuthModeKind {
    /// Username/password thin authentication.
    Password,
    /// Thin proxy authentication (`CONNECT THROUGH`) with a password or token
    /// owned by the proxy user.
    Proxy,
    /// OCI IAM database-token authentication over TCPS.
    IamToken,
    /// Passwordless external / wallet authentication.
    ExternalWallet,
    /// Kerberos authentication.
    Kerberos,
    /// RADIUS / native MFA authentication.
    Radius,
}

impl DoctorAuthModeKind {
    const fn as_str(self) -> &'static str {
        match self {
            DoctorAuthModeKind::Password => "password",
            DoctorAuthModeKind::Proxy => "proxy",
            DoctorAuthModeKind::IamToken => "iam_token",
            DoctorAuthModeKind::ExternalWallet => "external_wallet",
            DoctorAuthModeKind::Kerberos => "kerberos",
            DoctorAuthModeKind::Radius => "radius",
        }
    }
}

/// Whether a driver supports an auth mode in thin mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorAuthModeSupport {
    /// Supported by the pinned thin driver path.
    Supported,
    /// Explicitly not supported by the pinned thin driver path.
    UnsupportedInThin,
}

/// One auth capability row in the `doctor` matrix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorAuthModeCapability {
    /// Auth mode.
    pub kind: DoctorAuthModeKind,
    /// Thin-driver support posture.
    pub support: DoctorAuthModeSupport,
    /// Whether this mode is selected by the inspected profile.
    pub selected: bool,
    /// Secret-free operator detail.
    pub detail: &'static str,
}

/// Secret-free auth capability matrix surfaced by `doctor --profile`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorAuthCapabilities {
    /// Driver family being reported.
    pub driver: &'static str,
    /// Profile-selected auth mode.
    pub selected: DoctorAuthModeKind,
    /// Complete thin-mode matrix.
    pub modes: Vec<DoctorAuthModeCapability>,
}

impl DoctorAuthCapabilities {
    /// Build the pinned thin-driver matrix with the supplied selected mode.
    #[must_use]
    pub fn thin(selected: DoctorAuthModeKind) -> Self {
        let row = |kind, support, detail| DoctorAuthModeCapability {
            kind,
            support,
            selected: kind == selected,
            detail,
        };
        DoctorAuthCapabilities {
            driver: "thin",
            selected,
            modes: vec![
                row(
                    DoctorAuthModeKind::Password,
                    DoctorAuthModeSupport::Supported,
                    "username/password thin authentication",
                ),
                row(
                    DoctorAuthModeKind::Proxy,
                    DoctorAuthModeSupport::Supported,
                    "thin proxy authentication via CONNECT THROUGH",
                ),
                row(
                    DoctorAuthModeKind::IamToken,
                    DoctorAuthModeSupport::Supported,
                    "OCI IAM database token over TCPS",
                ),
                row(
                    DoctorAuthModeKind::ExternalWallet,
                    DoctorAuthModeSupport::UnsupportedInThin,
                    "passwordless external wallet authentication is not supported by this thin driver",
                ),
                row(
                    DoctorAuthModeKind::Kerberos,
                    DoctorAuthModeSupport::UnsupportedInThin,
                    "Kerberos authentication is not supported by this thin driver",
                ),
                row(
                    DoctorAuthModeKind::Radius,
                    DoctorAuthModeSupport::UnsupportedInThin,
                    "RADIUS/native MFA authentication is not supported by this thin driver",
                ),
            ],
        }
    }

    /// Derive the selected mode from resolved connect options without exposing
    /// any connect material.
    #[must_use]
    pub fn from_connect_options(opts: &OracleConnectOptions) -> Self {
        let selected = match &opts.auth_adapter {
            AuthAdapter::Kerberos { .. } => DoctorAuthModeKind::Kerberos,
            AuthAdapter::Radius => DoctorAuthModeKind::Radius,
            AuthAdapter::External => DoctorAuthModeKind::ExternalWallet,
            AuthAdapter::Proxy { .. } => DoctorAuthModeKind::Proxy,
            AuthAdapter::Password => {
                if opts.use_iam_token || opts.iam_token.is_some() {
                    DoctorAuthModeKind::IamToken
                } else if opts.external_auth || (opts.username.is_none() && opts.password.is_none())
                {
                    DoctorAuthModeKind::ExternalWallet
                } else {
                    DoctorAuthModeKind::Password
                }
            }
        };
        Self::thin(selected)
    }
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
    /// Connection/setup error observed before a live connection was available.
    pub connection_error: Option<String>,
    /// `TNS_ADMIN` (tnsnames/wallet directory), if set.
    pub tns_admin: Option<String>,
    /// A configured wallet location, if any.
    pub wallet_location: Option<String>,
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
    /// Exact setup values that must never appear in doctor output.
    pub sensitive_values: Vec<String>,
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

    let bytes = fs::read(&layout.legacy_audit_path)
        .map_err(|e| format!("failed to read legacy audit JSONL: {e}"))?;
    ensure_private_dir(&layout.migration_backup_dir)?;
    let backup_path = layout.migration_backup_dir.join(format!(
        "legacy-audit-jsonl.{}.backup",
        doctor_migration_timestamp_suffix()
    ));
    write_new_private_file(&backup_path, &bytes)?;
    write_new_atomic_file(&layout.current_audit_path, &bytes)?;
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

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        return Err(format!("{} is not a safe directory", path.display()));
    }
    fs::create_dir_all(path).map_err(|e| format!("failed to create {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| {
            format!(
                "failed to set private permissions on {}: {e}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("failed to create {}: {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn write_new_atomic_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    match regular_file_status(path) {
        Ok(true) => return Err(format!("{} already exists", path.display())),
        Ok(false) => {}
        Err(reason) => return Err(reason),
    }
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid migration target {}", path.display()))?;
    let tmp_path = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        doctor_migration_timestamp_suffix()
    ));
    write_new_private_file(&tmp_path, bytes)?;
    fs::rename(&tmp_path, path)
        .map_err(|e| format!("failed to install {}: {e}", path.display()))?;
    sync_dir(parent)
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| format!("failed to fsync {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<(), String> {
    Ok(())
}

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
        check_virtual_tools(),
        check_dba_suite_preflight(cx, ctx).await,
        check_write_posture(cx, ctx).await,
        check_state_layout(ctx),
        check_call_timeout(ctx),
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
            "built without Oracle connectivity",
        );
    }
    CheckResult::new(1, "Oracle thin driver", CheckStatus::Pass, p.note)
}

fn sanitized_detail(ctx: &DoctorContext, detail: impl Into<String>) -> String {
    let mut message = detail.into();
    for value in ctx
        .sensitive_values
        .iter()
        .filter(|value| !value.is_empty())
    {
        message = message.replace(value, "<redacted>");
    }
    message
}

fn check_tns_admin(ctx: &DoctorContext) -> CheckResult {
    match (&ctx.tns_admin, &ctx.wallet_location) {
        (None, None) => CheckResult::new(
            2,
            "TNS/wallet",
            CheckStatus::Skip,
            "no TNS_ADMIN or wallet configured (EZConnect-only is fine)",
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
                            format!("{label} directory is configured but is not readable as a directory"),
                        )
                        .with_fix(format!(
                            "create the configured directory or correct the {label} setting, then rerun `oraclemcp --json doctor --profile <profile>`"
                        ));
                    }
                    _ => {}
                }
            }
            CheckResult::new(
                2,
                "TNS/wallet",
                CheckStatus::Pass,
                "configured directory resolves",
            )
        }
    }
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
    }
}

fn connectivity_fix(error: &str) -> &'static str {
    let lower = error.to_ascii_lowercase();
    if let Some(wallet) = classify_wallet_error(error) {
        wallet_connectivity_fix(&wallet)
    } else if lower.contains("no connection profiles are configured") {
        "run `oraclemcp --json setup --write --profile db_ro`, then export ORACLE_APP_PASSWORD for the generated credential_ref and rerun `oraclemcp --json doctor --profile db_ro`"
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
    }
}

fn connectivity_failure_class(error: &str) -> ErrorClass {
    let lower = error.to_ascii_lowercase();
    if let Some(code) = parse_ora_code(error) {
        classify_ora_code(code)
    } else if let Some(wallet) = classify_wallet_error(error) {
        match wallet.kind {
            DoctorWalletErrorKind::UnsupportedFormat | DoctorWalletErrorKind::SsoNotEnabled => {
                ErrorClass::InvalidArguments
            }
            DoctorWalletErrorKind::FileMissing
            | DoctorWalletErrorKind::Io
            | DoctorWalletErrorKind::Pem
            | DoctorWalletErrorKind::NoCertificates
            | DoctorWalletErrorKind::Sso => ErrorClass::ConnectionFailed,
        }
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
    if let Some(error) = &ctx.connection_error {
        let detail = sanitized_detail(ctx, format!("connect failed: {error}"));
        let fix = connectivity_fix(&detail);
        return CheckResult::new(3, "Connectivity", CheckStatus::Fail, detail)
            .with_fix(fix)
            .with_failure_class(connectivity_failure_class(error))
            .with_auth_mode(classify_auth_mode(error))
            .with_wallet_error(classify_wallet_error(error))
            .with_oracle_error(error);
    }
    match ctx.conn {
        None => {
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
            Ok(()) => {
                let detail = ctx.connection_strategy.as_deref().map_or_else(
                    || "connected + authenticated".to_owned(),
                    |strategy| format!("connected + authenticated (strategy: {strategy})"),
                );
                CheckResult::new(3, "Connectivity", CheckStatus::Pass, detail)
            }
            Err(e) => CheckResult::new(
                3,
                "Connectivity",
                CheckStatus::Fail,
                sanitized_detail(ctx, format!("ping failed: {e}")),
            )
            .with_fix(connectivity_fix(&e.to_string()))
            .with_failure_class(connectivity_failure_class(&e.to_string()))
            .with_auth_mode(classify_auth_mode(&e.to_string()))
            .with_wallet_error(classify_wallet_error(&e.to_string()))
            .with_oracle_error(&e.to_string()),
        },
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

fn check_virtual_tools() -> CheckResult {
    CheckResult::new(
        9,
        "Virtual tools",
        CheckStatus::Pass,
        "custom tool descriptors and signing policy are available; the binary loads tools.d at startup",
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
/// unavailable), or `Skip` (offline) — never `Fail`.
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

    let report = preflight(cx, conn).await;
    let (runnable, skipped) = report.runnable_skipped();
    let total = runnable + skipped;
    let history = match report.top_queries_historical {
        DiagnosticsSource::AwrAsh => "AWR/ASH (Diagnostics Pack licensed)",
        DiagnosticsSource::Statspack => "Statspack (free fallback)",
        DiagnosticsSource::Unavailable => "none (no Diagnostics Pack, no Statspack)",
        // The default top-queries source is always the live cursor; historical
        // never resolves to it, but report it honestly if it ever does.
        DiagnosticsSource::LiveCursor => "live cursor only",
    };
    let detail = format!(
        "oracle_db_health: {runnable}/{total} subchecks runnable, {skipped} would skip; \
         oracle_top_queries default=live cursor (free), historical={history}"
    );

    // Report-only: a degraded posture is a Warn (informational), never a Fail.
    let history_unavailable = report.top_queries_historical == DiagnosticsSource::Unavailable;
    if skipped == 0 && !history_unavailable {
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
    const NAME: &str = "State layout";

    let Some(layout) = ctx.state_layout.as_ref() else {
        return CheckResult::new(
            ID,
            NAME,
            CheckStatus::Skip,
            "state directory could not be resolved in this environment",
        );
    };

    match inspect_legacy_state_layout(layout) {
        LegacyStateLayoutObservation::Current => CheckResult::new(
            ID,
            NAME,
            CheckStatus::Pass,
            format!(
                "current XDG state layout is in use; audit default is {}",
                layout.current_audit_path.display()
            ),
        ),
        LegacyStateLayoutObservation::LegacyAndCurrentAuditIdentical => CheckResult::new(
            ID,
            NAME,
            CheckStatus::Pass,
            format!(
                "legacy audit JSONL remains at {} and matches current state audit {}; no merge needed",
                layout.legacy_audit_path.display(),
                layout.current_audit_path.display()
            ),
        ),
        LegacyStateLayoutObservation::ExplicitAuditPath => CheckResult::new(
            ID,
            NAME,
            CheckStatus::Pass,
            "explicit [audit].path configured; automatic default-path migration is not needed",
        ),
        LegacyStateLayoutObservation::LegacyAuditOnly => CheckResult::new(
            ID,
            NAME,
            CheckStatus::Warn,
            format!(
                "legacy audit JSONL exists at {}; current state audit path {} is absent",
                layout.legacy_audit_path.display(),
                layout.current_audit_path.display()
            ),
        )
        .with_fix(
            "run oraclemcp doctor --fix to copy the legacy audit JSONL into the XDG state directory; the legacy file is left untouched",
        ),
        LegacyStateLayoutObservation::LegacyAndCurrentAudit => CheckResult::new(
            ID,
            NAME,
            CheckStatus::Warn,
            format!(
                "legacy audit {} and current audit {} both exist; automatic merge is refused",
                layout.legacy_audit_path.display(),
                layout.current_audit_path.display()
            ),
        )
        .with_fix(
            "verify both audit chains manually; doctor --fix refuses to merge divergent append-only audit logs",
        ),
        LegacyStateLayoutObservation::Unsafe(reason) => CheckResult::new(
            ID,
            NAME,
            CheckStatus::Warn,
            format!("state layout requires manual review: {reason}"),
        )
        .with_fix(
            "repair the filesystem layout manually; doctor --fix refuses symlinks and non-regular audit paths",
        ),
    }
}

fn check_call_timeout(ctx: &DoctorContext<'_>) -> CheckResult {
    const ID: u8 = 12;
    const NAME: &str = "Call timeout";

    if !ctx.call_timeout_resolved {
        return CheckResult::new(
            ID,
            NAME,
            CheckStatus::Skip,
            "no profile resolved — direct oraclemcp-db callers still default to a 30s call timeout",
        );
    }

    let (call_warns, call_detail, call_fix) = match ctx.call_timeout {
        Some(timeout) if !timeout.is_zero() => (
            false,
            format!(
                "Oracle call timeout is {}s; request budget uses the same profile ceiling",
                timeout.as_secs()
            ),
            None,
        ),
        Some(_) | None => (
            true,
            "Oracle call timeout is disabled; a driver round trip can wait indefinitely".to_owned(),
            Some("remove call_timeout_seconds = 0 or set it to a positive value such as 30"),
        ),
    };
    let (connect_warns, connect_detail, connect_fix) = match ctx.connect_timeout_seconds {
        Some(0) => (
            true,
            "Oracle connect timeout is configured as 0; the thin driver uses its 20s default instead"
                .to_owned(),
            Some("remove connect_timeout_seconds = 0 or set it to a positive value such as 20"),
        ),
        Some(seconds) => (
            false,
            format!("Oracle connect timeout is {seconds}s"),
            None,
        ),
        None => (
            false,
            "Oracle connect timeout uses the thin driver default (20s)".to_owned(),
            None,
        ),
    };
    let mut result = CheckResult::new(
        ID,
        NAME,
        if call_warns || connect_warns {
            CheckStatus::Warn
        } else {
            CheckStatus::Pass
        },
        format!("{call_detail}; {connect_detail}"),
    );
    result = match (call_fix, connect_fix) {
        (Some(_), Some(_)) => result.with_fix(
            "set call_timeout_seconds and connect_timeout_seconds to positive values, or omit connect_timeout_seconds to keep the 20s driver default",
        ),
        (Some(fix), None) | (None, Some(fix)) => result.with_fix(fix),
        (None, None) => result,
    };
    result
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
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../target/tmp/oraclemcp-core-doctor-tests");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        path.push(format!("{}-{}-{name}", std::process::id(), nanos));
        std::fs::create_dir_all(&path).expect("test temp dir exists");
        path
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

    /// A live mock whose `SESSION_PRIVS` includes write-implying privileges
    /// (exercises the A2 write-posture WARN path).
    struct WriteCapableMock;
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for WriteCapableMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
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
    fn report_has_thirteen_checks_and_classifier_self_test_passes() {
        let report = doctor(&DoctorContext::default());
        assert_eq!(report.checks.len(), 13);
        let selftest = report.checks.iter().find(|c| c.id == 8).unwrap();
        assert_eq!(selftest.status, CheckStatus::Pass, "{}", selftest.detail);
    }

    #[test]
    fn offline_skips_live_checks_and_does_not_fail() {
        let report = doctor(&DoctorContext::default());
        // Connectivity, role/standby, privilege-tier, snapshot, the DBA-suite
        // preflight (10), write posture (11), and call-timeout posture (12)
        // all skip offline/no-profile.
        for id in [3u8, 4, 6, 7, 10, 11, 12] {
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
        assert!(timeout.detail.contains("disabled"));
        assert!(
            timeout
                .fix
                .as_deref()
                .unwrap_or_default()
                .contains("call_timeout_seconds")
        );
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
        assert!(timeout.detail.contains("connect timeout is 20s"));
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
                .contains("connect timeout is configured as 0")
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
    fn live_connectivity_detail_reports_connection_strategy() {
        let conn = LiveMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            connection_strategy: Some("hybrid_pool".to_owned()),
            ..DoctorContext::default()
        };
        let report = doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();

        assert_eq!(connectivity.status, CheckStatus::Pass);
        assert_eq!(
            connectivity.detail,
            "connected + authenticated (strategy: hybrid_pool)"
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
        assert!(tns.detail.contains("wallet directory is configured"));
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
        assert_eq!(j["checks"].as_array().unwrap().len(), 13);
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
    fn dba_suite_preflight_is_report_only_and_never_fails() {
        // LiveMock answers every probe with one empty row: every tier probe
        // succeeds (Dba), detect_statspack succeeds, but detect_diagnostics_pack
        // is false (no DIAGNOSTIC value) -> historical resolves to Statspack, so
        // the preflight passes and, regardless, never fails.
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
            "the preflight is report-only and must never fail the suite"
        );
        assert!(
            preflight_check.detail.contains("oracle_db_health")
                && preflight_check.detail.contains("oracle_top_queries"),
            "reports what each DBA tool will be able to run: {}",
            preflight_check.detail
        );
        assert_eq!(report.exit_code(), 0, "report-only never exits non-zero");
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
    /// default build: ewallet.pem is supported; cwallet.sso and standalone
    /// ewallet.p12 get explicit typed diagnostics instead of false support.
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
        assert!(posture.detail.contains("unsupported in this build"));
        assert!(
            supported_wallet_modes()
                .iter()
                .any(|m| m.mode == "ewallet.pem" && m.supported)
        );
        assert!(
            supported_wallet_modes()
                .iter()
                .any(|m| m.mode == "cwallet.sso" && !m.supported)
        );
        assert!(
            supported_wallet_modes()
                .iter()
                .any(|m| m.mode == "ewallet.p12" && !m.supported)
        );
    }
}
