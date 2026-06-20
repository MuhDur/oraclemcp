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

use oraclemcp_db::{
    DiagnosticsSource, OracleConnection, canonical_nls_statements, detect_oracle_driver,
    detect_standby, preflight, probe_privileges, probe_write_posture, supported_wallet_modes,
};
use oraclemcp_error::{ErrorClass, classify_ora_code, parse_ora_code};
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
    /// Stable check number (1..=11).
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
    fn with_oracle_error(mut self, message: &str) -> Self {
        if let Some(code) = parse_ora_code(message) {
            self.ora_code = Some(code);
            self.failure_class = Some(classify_ora_code(code));
        }
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
    /// Runtime connection strategy label, such as `single_session` or
    /// `hybrid_pool`. This is non-secret operator-facing metadata.
    pub connection_strategy: Option<String>,
    /// Whether a proxy / least-privilege connect user is configured (A2).
    pub proxy_user: bool,
    /// Exact setup values that must never appear in doctor output.
    pub sensitive_values: Vec<String>,
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
        check_oracle_driver(),
        check_tns_admin(ctx),
        check_connectivity(ctx),
        check_role_standby(ctx),
        check_nls(ctx),
        check_privilege_tier(ctx),
        check_snapshot_freshness(),
        check_classifier_selftest(),
        check_virtual_tools(),
        check_dba_suite_preflight(ctx),
        check_write_posture(ctx),
    ];
    DoctorReport { checks }
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

fn connectivity_fix(error: &str) -> &'static str {
    let lower = error.to_ascii_lowercase();
    if lower.contains("proxy_auth") {
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

fn check_connectivity(ctx: &DoctorContext) -> CheckResult {
    if let Some(error) = &ctx.connection_error {
        let detail = sanitized_detail(ctx, format!("connect failed: {error}"));
        let fix = connectivity_fix(&detail);
        return CheckResult::new(3, "Connectivity", CheckStatus::Fail, detail)
            .with_fix(fix)
            .with_failure_class(connectivity_failure_class(error))
            .with_auth_mode(classify_auth_mode(error))
            .with_oracle_error(error);
    }
    match ctx.conn {
        None => CheckResult::new(
            3,
            "Connectivity",
            CheckStatus::Skip,
            "offline — supply a profile/connection to test connectivity + auth",
        ),
        Some(conn) => match conn.ping() {
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
            .with_oracle_error(&e.to_string()),
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
fn check_dba_suite_preflight(ctx: &DoctorContext) -> CheckResult {
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

    let report = preflight(conn);
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

/// A one-line, honest summary of the wallet auth modes the pinned thin driver
/// supports (A2, Round 3): unencrypted `ewallet.pem`, auto-login `cwallet.sso`,
/// and password-protected `ewallet.p12` are all SUPPORTED — never fail-closed.
fn supported_wallet_modes_note() -> String {
    let modes: Vec<&str> = supported_wallet_modes()
        .iter()
        .filter(|m| m.supported)
        .map(|m| m.mode)
        .collect();
    format!("supported wallet modes: {}", modes.join(", "))
}

/// Check 11 — read-only proxy-user / role posture (bead A2, **report-only**).
///
/// Reports whether the connected principal can write at the database. A
/// least-privilege proxy user / read-only role holds NO write-implying system
/// privileges; if it does, the operator is WARNED (the classifier + per-DB
/// ceiling are still the enforced control, but a write-capable principal is not
/// defense in depth). The detail always reports the SUPPORTED wallet modes so an
/// operator can see unencrypted/SSO/password wallets are not fail-closed. Never
/// `Fail`s the suite.
fn check_write_posture(ctx: &DoctorContext) -> CheckResult {
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
            let posture = probe_write_posture(conn, ctx.proxy_user);
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

    /// A live mock whose `SESSION_PRIVS` includes write-implying privileges
    /// (exercises the A2 write-posture WARN path).
    struct WriteCapableMock;
    impl OracleConnection for WriteCapableMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        fn query_rows(&self, sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
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
    fn report_has_eleven_checks_and_classifier_self_test_passes() {
        let report = run_doctor(&DoctorContext::default());
        assert_eq!(report.checks.len(), 11);
        let selftest = report.checks.iter().find(|c| c.id == 8).unwrap();
        assert_eq!(selftest.status, CheckStatus::Pass, "{}", selftest.detail);
    }

    #[test]
    fn offline_skips_live_checks_and_does_not_fail() {
        let report = run_doctor(&DoctorContext::default());
        // Connectivity, role/standby, privilege-tier, snapshot, the DBA-suite
        // preflight (10), and write posture (11) all skip offline.
        for id in [3u8, 4, 6, 7, 10, 11] {
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
    fn live_connectivity_detail_reports_connection_strategy() {
        let conn = LiveMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            connection_strategy: Some("hybrid_pool".to_owned()),
            ..DoctorContext::default()
        };
        let report = run_doctor(&ctx);
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
        let report = run_doctor(&ctx);
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
        let report = run_doctor(&ctx);
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
        let report = run_doctor(&ctx);
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
    fn proxy_auth_config_error_has_actionable_fix() {
        let ctx = DoctorContext {
            connection_error: Some(
                "config load failed: connection profile `proxy` proxy_auth requires non-empty proxy_user and target_schema"
                    .to_owned(),
            ),
            ..DoctorContext::default()
        };
        let report = run_doctor(&ctx);
        let connectivity = report.checks.iter().find(|c| c.id == 3).unwrap();
        assert_eq!(connectivity.status, CheckStatus::Fail);
        let fix = connectivity.fix.as_deref().unwrap();
        assert!(fix.contains("proxy_auth.proxy_user"));
        assert!(fix.contains("target_schema"));
    }

    #[test]
    fn text_and_json_render() {
        let report = run_doctor(&DoctorContext::default());
        let text = report.to_text();
        assert!(text.contains("oraclemcp doctor"));
        assert!(text.contains("Classifier self-test"));
        let j = report.to_json();
        assert_eq!(j["checks"].as_array().unwrap().len(), 11);
        assert_eq!(j["exit_code"], json!(0));
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
        let report = run_doctor(&ctx);
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
        let report = run_doctor(&ctx);
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
                "external/wallet auth without username and password is not supported by the published thin driver yet"
                    .to_owned(),
            ),
            ..DoctorContext::default()
        };
        let report = run_doctor(&ctx);
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
        let report = run_doctor(&ctx);
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
        let report = run_doctor(&ctx);
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
        let report = run_doctor(&ctx);
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.to_json_with_exit_code(2)["exit_code"], json!(2));
        assert!(
            report
                .to_text_with_exit_code(2)
                .contains("verdict: FAILED (exit 2)")
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
        let report = run_doctor(&ctx);
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
        let report = run_doctor(&ctx);
        let posture = report.checks.iter().find(|c| c.id == 11).unwrap();
        assert_eq!(posture.status, CheckStatus::Warn, "{}", posture.detail);
        assert!(posture.detail.contains("principal CAN write"));
        assert!(posture.detail.contains("CREATE ANY TABLE"));
        assert!(posture.fix.as_deref().unwrap().contains("read-only proxy"));
        assert_eq!(report.exit_code(), 0, "a warning is not a failure");
    }

    /// A2 (Round 3) — the write-posture check always reports the SUPPORTED wallet
    /// modes: unencrypted ewallet.pem, auto-login cwallet.sso, and password
    /// ewallet.p12 are SUPPORTED (not fail-closed).
    #[test]
    fn doctor_reports_supported_wallet_modes() {
        let conn = LiveMock;
        let ctx = DoctorContext {
            conn: Some(&conn),
            ..DoctorContext::default()
        };
        let report = run_doctor(&ctx);
        let posture = report.checks.iter().find(|c| c.id == 11).unwrap();
        for needle in ["cwallet.sso", "ewallet.pem", "ewallet.p12"] {
            assert!(
                posture.detail.contains(needle),
                "wallet mode {needle} should be reported SUPPORTED: {}",
                posture.detail
            );
        }
        // And the underlying source-of-truth marks every mode SUPPORTED.
        assert!(supported_wallet_modes().iter().all(|m| m.supported));
    }
}
