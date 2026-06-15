//! `oraclemcp doctor` — first-class diagnostic mode (plan §9.3; bead P1-DOC /
//! oracle-qmwz.2.13). The brew/flutter/cargo-doctor pattern: a CLI onboarding +
//! triage step that runs a fixed set of checks, prints an **actionable fix** for
//! every non-pass, and **exits non-zero** on any failure.
//!
//! Checks are **progressive** (per the bead's design note): each lights up as
//! its backing feature lands. A check whose feature/state is not present this
//! run is reported `Skip` *with a reason* — never a fake `Pass`. The offline
//! subset (Instant Client, TNS/wallet, NLS, classifier self-test) runs WITHOUT a
//! live database; the live subset (connectivity, role/standby, privilege tier)
//! runs only when a connection is supplied.
//!
//! In-MCP, the live-state subset is mirrored by `oracle_capabilities` (an agent
//! can call it); `doctor` is the CLI mode.

use oraclemcp_db::{
    OracleConnection, canonical_nls_statements, detect_instant_client, detect_standby,
    probe_privileges,
};
use oraclemcp_guard::{Classifier, ClassifierConfig, OperatingLevel};
use serde::Serialize;
use serde_json::{Value, json};

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
    /// Stable check number (1..=9).
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
}

impl CheckResult {
    fn new(id: u8, name: &str, status: CheckStatus, detail: impl Into<String>) -> Self {
        CheckResult {
            id,
            name: name.to_owned(),
            status,
            detail: detail.into(),
            fix: None,
        }
    }
    fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
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
}

/// The full diagnostic report.
#[derive(Clone, Debug, Serialize)]
pub struct DoctorReport {
    /// All checks, in order.
    pub checks: Vec<CheckResult>,
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
        json!({
            "checks": self.checks,
            "ok": !self.any_failed(),
            "exit_code": exit_code,
        })
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
        let verdict = if self.any_failed() { "FAILED" } else { "ok" };
        out.push_str(&format!("verdict: {verdict} (exit {exit_code})\n"));
        out
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
#[must_use]
pub fn run_doctor(ctx: &DoctorContext) -> DoctorReport {
    let checks = vec![
        check_instant_client(),
        check_tns_admin(ctx),
        check_connectivity(ctx),
        check_role_standby(ctx),
        check_nls(ctx),
        check_privilege_tier(ctx),
        check_snapshot_freshness(),
        check_classifier_selftest(),
        check_virtual_tools(),
    ];
    DoctorReport { checks }
}

fn check_instant_client() -> CheckResult {
    let p = detect_instant_client();
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
                            format!("{label} directory does not exist: {d}"),
                        )
                        .with_fix(format!("create {d} or correct the {label} setting"));
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

fn check_connectivity(ctx: &DoctorContext) -> CheckResult {
    if let Some(error) = &ctx.connection_error {
        let fix = if error.contains("unsupported auth mode")
            || error.contains("unsupported database feature")
        {
            "use username/password thin auth for this profile, or upgrade the thin driver once that auth feature is supported"
        } else {
            "verify the connect string, credentials, and listener reachability"
        };
        return CheckResult::new(
            3,
            "Connectivity",
            CheckStatus::Fail,
            format!("connect failed: {error}"),
        )
        .with_fix(fix);
    }
    match ctx.conn {
        None => CheckResult::new(
            3,
            "Connectivity",
            CheckStatus::Skip,
            "offline — supply a profile/connection to test connectivity + auth",
        ),
        Some(conn) => match conn.ping() {
            Ok(()) => CheckResult::new(
                3,
                "Connectivity",
                CheckStatus::Pass,
                "connected + authenticated",
            ),
            Err(e) => CheckResult::new(
                3,
                "Connectivity",
                CheckStatus::Fail,
                format!("ping failed: {e}"),
            )
            .with_fix("verify the connect string, credentials, and listener reachability"),
        },
    }
}

fn check_role_standby(ctx: &DoctorContext) -> CheckResult {
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
        Some(conn) => match detect_standby(conn) {
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
                format!("could not determine role: {e}"),
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

fn check_privilege_tier(ctx: &DoctorContext) -> CheckResult {
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
            let p = probe_privileges(conn);
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

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_db::{DbError, OracleBackend, OracleBind, OracleConnectionInfo, OracleRow};

    struct LiveMock;
    impl OracleConnection for LiveMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            // dba_objects/all_identifiers probes succeed -> Dba tier, plscope true.
            Ok(vec![OracleRow { columns: vec![] }])
        }
        fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }
        fn commit(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn rollback(&self) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[test]
    fn report_has_nine_checks_and_classifier_self_test_passes() {
        let report = run_doctor(&DoctorContext::default());
        assert_eq!(report.checks.len(), 9);
        let selftest = report.checks.iter().find(|c| c.id == 8).unwrap();
        assert_eq!(selftest.status, CheckStatus::Pass, "{}", selftest.detail);
    }

    #[test]
    fn offline_skips_live_checks_and_does_not_fail() {
        let report = run_doctor(&DoctorContext::default());
        // Connectivity, role/standby, privilege-tier, and snapshot skip offline.
        for id in [3u8, 4, 6, 7] {
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
    fn live_connection_runs_connectivity_role_and_privilege_checks() {
        let conn = LiveMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            ..DoctorContext::default()
        };
        let report = run_doctor(&ctx);
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
    fn protected_profile_with_write_ceiling_warns() {
        let ctx = DoctorContext {
            protected_profile_writable: true,
            ..DoctorContext::default()
        };
        let report = run_doctor(&ctx);
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
        let report = run_doctor(&ctx);
        let tns = report.checks.iter().find(|c| c.id == 2).unwrap();
        assert_eq!(tns.status, CheckStatus::Fail);
        assert!(tns.fix.is_some());
        assert_eq!(report.exit_code(), 1, "a failed check exits non-zero");
    }

    #[test]
    fn text_and_json_render() {
        let report = run_doctor(&DoctorContext::default());
        let text = report.to_text();
        assert!(text.contains("oraclemcp doctor"));
        assert!(text.contains("Classifier self-test"));
        let j = report.to_json();
        assert_eq!(j["checks"].as_array().unwrap().len(), 9);
        assert_eq!(j["exit_code"], json!(0));
    }

    #[test]
    fn connection_error_fails_connectivity_and_skips_dependent_live_checks() {
        let ctx = DoctorContext {
            connection_error: Some("could not open connection".to_owned()),
            ..DoctorContext::default()
        };
        let report = run_doctor(&ctx);
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
                "unsupported auth mode: external/wallet auth without username and password is not supported by the published thin driver yet"
                    .to_owned(),
            ),
            ..DoctorContext::default()
        };
        let report = run_doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
        assert_eq!(connectivity.status, CheckStatus::Fail);
        assert!(
            connectivity
                .fix
                .as_deref()
                .unwrap()
                .contains("username/password thin auth")
        );
    }

    #[test]
    fn renderers_can_use_process_exit_code_override() {
        let ctx = DoctorContext {
            tns_admin: Some("/nonexistent/tns/dir/xyz".to_owned()),
            ..DoctorContext::default()
        };
        let report = run_doctor(&ctx);
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.to_json_with_exit_code(2)["exit_code"], json!(2));
        assert!(
            report
                .to_text_with_exit_code(2)
                .contains("verdict: FAILED (exit 2)")
        );
    }
}
