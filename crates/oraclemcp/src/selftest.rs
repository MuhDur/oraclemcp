//! `oraclemcp selftest` — the installed-binary field round (train-0.12, W4 bead
//! `…9.15`).
//!
//! A field agent or operator runs this from the **installed binary** against a
//! real database after every install. It drives the *served* transport as an
//! external MCP client would (a child `oraclemcp serve` over stdio, plus an HTTP
//! listener when one is configured), never an in-process `Dispatcher`.
//!
//! ## Safety invariant (do not weaken)
//!
//! The whole run is pinned to `READ_ONLY` by construction, three layers deep:
//!
//! 1. The probe child is started with a **derived profile** whose `max_level`
//!    and `default_level` are `READ_ONLY`, written to a private temporary config
//!    file. The guard caps every statement at that ceiling; elevation above it
//!    is refused.
//! 2. This module never calls `oracle_set_session_level` with a confirmation,
//!    and the embedded case set contains no write expectation other than a
//!    typed refusal.
//! 3. When the run ends it reads its own audit file and refuses to report a
//!    clean run if any record is a privileged action (`GUARDED`/`DESTRUCTIVE`
//!    danger tier, or `ALLOWED` for a known write tool).
//!
//! Nothing here bypasses the classifier, exceeds a profile `max_level`, makes a
//! `protected` profile writable, or auto-commits DML. The derived config is a
//! fixed private file the run never rewrites.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use clap::Args;
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::redacted::{REDACTED, redact_operator_text};
use serde::Deserialize;
use serde_json::{Value, json};
use toml_edit::{DocumentMut, value};

/// Arguments for the selftest field round. They live with the implementation
/// so the main command registry remains a compact list of top-level commands.
#[derive(Args, Debug, Clone)]
pub(crate) struct SelftestCliArgs {
    /// Named connection profile from the loaded config to run the field round
    /// against. The run derives a READ_ONLY-ceiling profile from it.
    #[arg(long)]
    pub(crate) profile: String,
    /// Write one sanitized Markdown issue draft per defect into this directory.
    /// Drafts are local-only; nothing is sent anywhere.
    #[arg(long = "issue-draft", value_name = "DIR")]
    pub(crate) issue_draft: Option<PathBuf>,
    /// Also probe a running Streamable HTTP listener at this base URL.
    #[arg(long, value_name = "URL")]
    pub(crate) http: Option<String>,
    /// Overall run budget in seconds; probes not reached report `skipped: budget`.
    #[arg(long, default_value_t = 300)]
    pub(crate) budget: u64,
}

/// Default per-probe timeout.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
/// Row cap advertised on every read probe.
const SELFTEST_ROW_CAP: u64 = 5;
/// The synthetic write placed in every write probe; a well-formed INSERT so the
/// classifier sees a write, refused by the READ_ONLY level gate before Oracle.
const WRITE_MARKER: &str =
    "INSERT INTO oraclemcp_selftest_marker (c) VALUES ('oraclemcp-selftest')";

/// Level-control tools: a request above the derived ceiling must be refused.
const ELEVATION_TOOLS: [&str; 3] = [
    "oracle_set_session_level",
    "enable_writes",
    "disable_writes",
];

/// Arguments for an elevation probe. `execute: true` with a deliberately invalid
/// confirmation proves the ceiling refuses the elevation itself, not just a
/// missing token.
fn elevation_arguments(tool: &str) -> Option<Value> {
    match tool {
        "oracle_set_session_level" | "enable_writes" => Some(json!({
            "level": "ADMIN",
            "execute": true,
            "confirm": "oraclemcp-selftest-invalid"
        })),
        "disable_writes" => Some(json!({})),
        _ => None,
    }
}

/// Classify an elevation probe. `disable_writes` may legitimately succeed (it
/// lowers to READ_ONLY); any other success means an elevation above the ceiling
/// was applied — a fail-closed violation.
fn classify_elevation(tool: &str, observed: &Observed) -> (Class, Option<String>) {
    match observed {
        Observed::Error { class, .. } => {
            let class = normalize_class(class);
            if is_expected_refusal_class(&class) {
                (Class::ExpectedRefusal, Some(class))
            } else if is_environment_class(&class) || is_synthetic_input_class(&class) {
                (Class::Environment, Some(class))
            } else {
                (Class::Defect, Some(class))
            }
        }
        Observed::Success(_) if tool == "disable_writes" => (Class::Pass, None),
        Observed::Success(_) => (
            Class::Defect,
            Some("elevation above the READ_ONLY ceiling succeeded".to_owned()),
        ),
        Observed::Transport(message) => (
            Class::Defect,
            Some(format!(
                "transport failure during elevation probe: {message}"
            )),
        ),
    }
}

/// Embedded read-only case definitions. The file lives inside the crate so
/// `cargo package` ships it; it is a read-only, fixture-free subset of the W4
/// case files (dictionary objects every database has: `DUAL`, `ALL_USERS`).
const READONLY_CASES_JSON: &str = include_str!("../selftest/readonly_cases.json");

/// A typed probe outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// The probe did what the case expected.
    Pass,
    /// A correctly-typed refusal (operating level, unsupported capability).
    ExpectedRefusal,
    /// A database/environment condition (unavailable DB, missing privilege).
    Environment,
    /// The observed behaviour contradicts the expectation.
    Defect,
    /// Not run because the overall budget was exhausted.
    Skipped,
}

impl Class {
    fn as_str(self) -> &'static str {
        match self {
            Class::Pass => "pass",
            Class::ExpectedRefusal => "expected_refusal",
            Class::Environment => "environment",
            Class::Defect => "defect",
            Class::Skipped => "skipped",
        }
    }

    fn is_defect(self) -> bool {
        matches!(self, Class::Defect)
    }

    fn is_environment(self) -> bool {
        matches!(self, Class::Environment)
    }
}

/// Exit-code precedence (bead §3): any defect wins, else any environment, else 0.
fn exit_code_for(classes: &[Class]) -> u8 {
    if classes.iter().any(|class| class.is_defect()) {
        2
    } else if classes.iter().any(|class| class.is_environment()) {
        3
    } else {
        0
    }
}

/// One probe result.
#[derive(Debug, Clone)]
pub(crate) struct ProbeRecord {
    /// Stable probe id (case id, `write:<tool>`, `advertised:<tool>`, …).
    pub(crate) probe: String,
    /// The classified outcome.
    pub(crate) class: Class,
    /// The observed/typed error class, when the probe produced one.
    pub(crate) error_class: Option<String>,
    /// Sanitized one-line detail.
    pub(crate) detail: String,
    /// Wall-clock duration.
    pub(crate) duration_ms: u64,
    /// The exact privilege to add, when the class is `Environment` for a grant.
    pub(crate) privilege: Option<String>,
    /// Non-empty when the probe was skipped and why (e.g. `budget`).
    pub(crate) skipped: Option<String>,
}

impl ProbeRecord {
    fn new(probe: impl Into<String>, class: Class, detail: impl Into<String>) -> Self {
        Self {
            probe: probe.into(),
            class,
            error_class: None,
            detail: detail.into(),
            duration_ms: 0,
            privilege: None,
            skipped: None,
        }
    }
}

/// One case definition from the embedded read-only subset.
#[derive(Debug, Clone, Deserialize)]
struct ReadonlyCase {
    case_id: String,
    source_case_id: String,
    tool: String,
    level: String,
    #[serde(default)]
    arguments: Value,
    #[serde(default)]
    expect: CaseExpect,
}

/// What a case expects from a successful read.
#[derive(Debug, Clone, Default, Deserialize)]
struct CaseExpect {
    /// `rows` (a structured read result) or `typed_error` (a refusal).
    #[serde(default)]
    kind: String,
    /// The expected error class for `typed_error` cases.
    #[serde(default)]
    error_class: Option<String>,
}

fn embedded_cases() -> Result<Vec<ReadonlyCase>, String> {
    let cases: Vec<ReadonlyCase> = serde_json::from_str(READONLY_CASES_JSON)
        .map_err(|error| format!("embedded readonly cases are malformed: {error}"))?;
    for case in &cases {
        if case.level != "READ_ONLY" {
            return Err(format!(
                "embedded case `{}` is {}; the selftest case set must be read-only",
                case.case_id, case.level
            ));
        }
    }
    Ok(cases)
}

/// The observed result of one tool call, reduced to what the classifier needs.
#[derive(Debug)]
enum Observed {
    /// A structured (non-error) result.
    Success(Value),
    /// A typed tool error with its machine class and message.
    Error { class: String, message: String },
    /// The transport/protocol failed; the server did not answer a tool call.
    Transport(String),
}

/// Error classes that mean "the environment cannot exercise this probe".
fn is_environment_class(class: &str) -> bool {
    matches!(
        class,
        "CONNECTION_FAILED" | "RUNTIME_STATE_REQUIRED" | "TRANSIENT" | "TIMEOUT"
    )
}

/// Correctly-typed refusals: a level/capability gate, never a silent success.
fn is_expected_refusal_class(class: &str) -> bool {
    matches!(
        class,
        "OPERATING_LEVEL_TOO_LOW"
            | "FORBIDDEN_STATEMENT"
            | "CHALLENGE_REQUIRED"
            | "REPREVIEW_REQUIRED"
            | "POLICY_DENIED"
            | "FLASHBACK_CAPABILITY_UNAVAILABLE"
    )
}

/// Classes that mean the synthetic input could not be exercised here (the
/// object/arg is not present on this database); an environment finding, not a
/// product defect.
fn is_synthetic_input_class(class: &str) -> bool {
    matches!(
        class,
        "OBJECT_NOT_FOUND"
            | "INVALID_ARGUMENTS"
            | "INSUFFICIENT_PRIVILEGE"
            | "UNSUPPORTED_AUTH"
            | "SNAPSHOT_TOO_OLD"
            | "FLASHBACK_RETENTION_EXCEEDED"
            | "FLASHBACK_DEFINITION_CHANGED"
            | "FLASHBACK_NOT_FLASHBACKABLE"
    )
}

fn normalize_class(class: &str) -> String {
    class.trim().to_ascii_uppercase()
}

/// Classify an embedded read case.
fn classify_read_case(
    expect: &CaseExpect,
    observed: &Observed,
) -> (Class, Option<String>, Option<String>) {
    match observed {
        Observed::Success(_) => {
            let expected_typed = expect.kind == "typed_error";
            if expected_typed {
                // A read case that demanded a refusal but got rows is a defect.
                (Class::Defect, None, None)
            } else {
                (Class::Pass, None, None)
            }
        }
        Observed::Error { class, message } => {
            let class = normalize_class(class);
            classify_read_error(&class, message, expect)
        }
        Observed::Transport(message) => (
            Class::Defect,
            None,
            Some(format!("transport failure: {message}")),
        ),
    }
}

fn classify_read_error(
    class: &str,
    message: &str,
    expect: &CaseExpect,
) -> (Class, Option<String>, Option<String>) {
    if expect.kind == "typed_error"
        && (expect
            .error_class
            .as_deref()
            .map(normalize_class)
            .as_deref()
            == Some(class)
            || is_expected_refusal_class(class))
    {
        return (Class::ExpectedRefusal, Some(class.to_owned()), None);
    }
    if is_environment_class(class) {
        return (Class::Environment, Some(class.to_owned()), None);
    }
    if class == "INSUFFICIENT_PRIVILEGE" {
        return (
            Class::Environment,
            Some(class.to_owned()),
            Some(privilege_from_message(message)),
        );
    }
    if is_synthetic_input_class(class) {
        return (Class::Environment, Some(class.to_owned()), None);
    }
    if is_expected_refusal_class(class) {
        // A read refused by the level gate at READ_ONLY is a real defect.
        return (Class::Defect, Some(class.to_owned()), None);
    }
    (
        Class::Defect,
        Some(class.to_owned()),
        Some(format!("unexpected error class `{class}`")),
    )
}

/// Extract the exact privilege Oracle named, when it can be found; otherwise the
/// (sanitized) message is the best evidence.
fn privilege_from_message(message: &str) -> String {
    let ora = message
        .split_whitespace()
        .find(|token| token.starts_with("ORA-"))
        .map(|token| token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-'))
        .unwrap_or("ORA-01031");
    format!("{ora}: grant the missing privilege named in the sanitized message")
}

/// Classify a write-tool call: it must refuse (level/capability) and must never
/// return a successful execution.
fn classify_write_observed(observed: &Observed) -> (Class, Option<String>) {
    match observed {
        Observed::Error { class, .. } => {
            let class = normalize_class(class);
            if is_expected_refusal_class(&class) {
                (Class::ExpectedRefusal, Some(class))
            } else if is_environment_class(&class) || is_synthetic_input_class(&class) {
                (Class::Environment, Some(class))
            } else {
                (Class::Defect, Some(class))
            }
        }
        Observed::Success(result) => {
            // A preview/confirmation (no execution) is an acceptable refusal of
            // the write itself; an executed write is a fail-closed violation.
            let preview = result
                .get("structuredContent")
                .and_then(|content| content.get("preview"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || result.pointer("/structuredContent/confirmation").is_some();
            if preview {
                (Class::ExpectedRefusal, None)
            } else {
                (
                    Class::Defect,
                    Some("write tool returned success at READ_ONLY".to_owned()),
                )
            }
        }
        Observed::Transport(message) => (
            Class::Defect,
            Some(format!("transport failure during write sweep: {message}")),
        ),
    }
}

/// Classify a generic read sweep observation.
fn classify_generic_read(observed: &Observed) -> (Class, Option<String>) {
    match observed {
        Observed::Success(_) => (Class::Pass, None),
        Observed::Error { class, .. } => {
            let class = normalize_class(class);
            // This sweep deliberately supplies schema-shaped placeholder input.
            // An absent object, cursor, or required argument proves the served
            // endpoint rejected that placeholder safely; it is not a property
            // of the database environment.  Real embedded cases still classify
            // insufficient privilege as an environmental finding (exit 3).
            if is_synthetic_input_class(&class) || class == "RUNTIME_STATE_REQUIRED" {
                (Class::ExpectedRefusal, Some(class))
            } else if is_environment_class(&class) {
                (Class::Environment, Some(class))
            } else {
                // Any other class on a READ_ONLY read (including an unexpected
                // level refusal) is a defect.
                (Class::Defect, Some(class))
            }
        }
        Observed::Transport(message) => {
            (Class::Defect, Some(format!("transport failure: {message}")))
        }
    }
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// The `--issue-draft` / `--json` redactor. It removes host, service, schema,
/// table, column, bind and credential identifiers, keeping only stable,
/// non-identifying evidence: ORA codes, error classes, tool names, the
/// oraclemcp version and the Oracle version banner.
#[derive(Debug, Clone, Default)]
pub(crate) struct Redactor {
    sensitive: Vec<String>,
}

impl Redactor {
    /// Build a redactor from the concrete values this run must never leak.
    pub(crate) fn new(values: impl IntoIterator<Item = String>) -> Self {
        let mut sensitive: Vec<String> = values
            .into_iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| value.len() > 2 && !is_generic_value(value))
            .collect();
        // Longest first so a value that is a prefix of another cannot leak.
        sensitive.sort_by_key(|value| std::cmp::Reverse(value.len()));
        sensitive.dedup();
        Self { sensitive }
    }

    /// Register one more sensitive value (e.g. a bind value discovered late).
    pub(crate) fn add(&mut self, value: impl Into<String>) {
        let value = value.into();
        let value = value.trim();
        if value.len() > 2 && !is_generic_value(value) && !self.sensitive.iter().any(|v| v == value)
        {
            self.sensitive.push(value.to_owned());
            self.sensitive.sort_by_key(|v| std::cmp::Reverse(v.len()));
        }
    }

    /// Scrub a string of every registered identifier plus connect-string shapes.
    pub(crate) fn scrub(&self, text: &str) -> String {
        let scrubbed = redact_operator_text(text, &self.sensitive);
        scrub_connect_strings(&scrubbed)
    }
}

/// Values that are structural and must survive (they are evidence, not
/// identifiers): error classes, tool names, oraclemcp/Oracle tokens.
fn is_generic_value(value: &str) -> bool {
    value.starts_with("oracle_")
        || value == "oraclemcp"
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("false")
        || value.chars().all(|c| c.is_ascii_digit())
}

/// Best-effort scrub of Oracle Net connect descriptors and EZConnect strings.
fn scrub_connect_strings(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for token in text.split_inclusive(char::is_whitespace) {
        let (body, ws) = match token.find(char::is_whitespace) {
            Some(idx) => (&token[..idx], &token[idx..]),
            None => (token, ""),
        };
        let is_connect_descriptor = body.contains("DESCRIPTION=")
            || body.contains("jdbc:oracle")
            || body.contains("tcps://")
            || body.contains("wallet_location=");
        if is_connect_descriptor || looks_like_ezconnect(body) {
            out.push_str(REDACTED);
        } else {
            out.push_str(body);
        }
        out.push_str(ws);
    }
    out
}

/// `host:port/service` or `user@host:port/service`.
fn looks_like_ezconnect(body: &str) -> bool {
    let endpoint = body.rsplit('@').next().unwrap_or(body);
    let Some((hostport, service)) = endpoint.split_once('/') else {
        return false;
    };
    let Some((host, port)) = hostport.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && !service.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
        && host.contains(|c: char| c.is_ascii_alphanumeric())
}

// ---------------------------------------------------------------------------
// Forced READ_ONLY: derived profile
// ---------------------------------------------------------------------------

/// A private, derived `READ_ONLY`-ceiling config for the probe child plus the
/// audit path it must write.
struct DerivedConfig {
    config_path: PathBuf,
    audit_path: PathBuf,
    /// Isolated state/home dirs so the run cannot touch the operator's state.
    state_dir: PathBuf,
    home_dir: PathBuf,
    _temp: tempfile::TempDir,
}

/// The source config path the operator's profile lives in.
fn source_config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(oraclemcp_config::CONFIG_PATH_ENV) {
        return Some(PathBuf::from(path));
    }
    OracleMcpConfig::default_config_path()
}

/// Derive a `READ_ONLY`-ceiling copy of the named profile into a private temp
/// config. The profile keeps its connection/secrets references; only its level
/// ceiling and default are pinned, and `[audit].path` is pointed at a known
/// temp file so the run can verify its own audit.
fn derive_readonly_config(profile: &str, source: &Path) -> Result<DerivedConfig, String> {
    let text = std::fs::read_to_string(source)
        .map_err(|error| format!("cannot read config `{}`: {error}", source.display()))?;
    let mut doc: DocumentMut = text
        .parse()
        .map_err(|error| format!("config `{}` is not valid TOML: {error}", source.display()))?;

    let mut found = false;
    if let Some(tables) = doc
        .get_mut("profiles")
        .and_then(|item| item.as_array_of_tables_mut())
    {
        for table in tables.iter_mut() {
            if table.get("name").and_then(|name| name.as_str()) == Some(profile) {
                // The immutable ceiling for the run. The run never rewrites this
                // file and never requests elevation past it.
                table["max_level"] = value("READ_ONLY");
                table["default_level"] = value("READ_ONLY");
                found = true;
            }
        }
    }
    if !found {
        return Err(format!(
            "connection profile `{profile}` is not defined in `{}`; selftest derives a READ_ONLY profile from a file-backed profile",
            source.display()
        ));
    }

    let temp = tempfile::tempdir().map_err(|error| format!("cannot create temp dir: {error}"))?;
    let config_path = temp.path().join("selftest-profiles.toml");
    let audit_path = temp.path().join("selftest-audit.jsonl");
    let state_dir = temp.path().join("state");
    let home_dir = temp.path().join("home");
    std::fs::create_dir_all(&state_dir)
        .map_err(|error| format!("cannot create state dir: {error}"))?;
    std::fs::create_dir_all(&home_dir)
        .map_err(|error| format!("cannot create home dir: {error}"))?;

    let audit = doc
        .entry("audit")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let audit_table = audit
        .as_table_mut()
        .ok_or_else(|| "config `audit` is not a table".to_owned())?;
    audit_table["path"] = value(audit_path.to_string_lossy().to_string());

    std::fs::write(&config_path, doc.to_string())
        .map_err(|error| format!("cannot write derived config: {error}"))?;

    Ok(DerivedConfig {
        config_path,
        audit_path,
        state_dir,
        home_dir,
        _temp: temp,
    })
}

// ---------------------------------------------------------------------------
// Minimal external MCP stdio client
// ---------------------------------------------------------------------------

struct StdioClient {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    replies: Receiver<Value>,
    stderr: std::sync::Arc<std::sync::Mutex<String>>,
    next_id: u64,
}

impl StdioClient {
    fn spawn(exe: &Path, config: &DerivedConfig, profile: &str) -> Result<Self, String> {
        let mut child = Command::new(exe)
            .arg("--json")
            .arg("serve")
            .arg("--allow-no-auth")
            .arg("--profile")
            .arg(profile)
            .env("ORACLEMCP_CONFIG", &config.config_path)
            .env("XDG_STATE_HOME", &config.state_dir)
            .env("HOME", &config.home_dir)
            .env_remove("ORACLEMCP_STDIO_TOKEN")
            .env_remove("RUST_LOG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("cannot spawn probe child: {error}"))?;

        let stdin = child.stdin.take().ok_or("child stdin is not piped")?;
        let stdout = child.stdout.take().ok_or("child stdout is not piped")?;
        let stderr_pipe = child.stderr.take().ok_or("child stderr is not piped")?;

        let (tx, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(value) = serde_json::from_str::<Value>(&line)
                    && tx.send(value).is_err()
                {
                    break;
                }
            }
        });

        let stderr = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let stderr_sink = std::sync::Arc::clone(&stderr);
        std::thread::spawn(move || {
            let mut buffer = String::new();
            for line in BufReader::new(stderr_pipe).lines() {
                let Ok(line) = line else { break };
                buffer.push_str(&line);
                buffer.push('\n');
                if buffer.len() > 64 * 1024 {
                    // Bounded: never let a chatty child grow memory unbounded.
                    let keep_from = buffer.len() - 16 * 1024;
                    buffer.drain(..keep_from);
                }
            }
            if let Ok(mut sink) = stderr_sink.lock() {
                *sink = buffer;
            }
        });

        Ok(Self {
            child,
            stdin: Some(stdin),
            replies,
            stderr,
            next_id: 1,
        })
    }

    fn send(&mut self, frame: &Value) -> Result<(), String> {
        let stdin = self.stdin.as_mut().ok_or("child stdin already closed")?;
        let mut line = frame.to_string();
        line.push('\n');
        stdin
            .write_all(line.as_bytes())
            .map_err(|error| format!("cannot write to probe child: {error}"))?;
        stdin
            .flush()
            .map_err(|error| format!("cannot flush probe child: {error}"))
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        self.send(&json!({ "jsonrpc": "2.0", "method": method, "params": params }))
    }

    fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))?;
        let deadline = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(format!("`{method}` timed out after {timeout:?}"));
            }
            match self.replies.recv_timeout(deadline - now) {
                Ok(reply) => {
                    if reply.get("id").and_then(Value::as_u64) == Some(id) {
                        return Ok(reply);
                    }
                    // A notification or an earlier stale reply: keep reading.
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!("`{method}` timed out after {timeout:?}"));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("probe child closed stdout before replying".to_owned());
                }
            }
        }
    }

    fn tool_call(&mut self, tool: &str, arguments: Value, timeout: Duration) -> Observed {
        let params = json!({ "name": tool, "arguments": arguments });
        match self.request("tools/call", params, timeout) {
            Ok(reply) => observed_from_reply(&reply),
            Err(message) => Observed::Transport(message),
        }
    }

    fn stderr_text(&self) -> String {
        self.stderr
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Close stdin, then wait (bounded) and reap the child.
    fn close(&mut self, deadline: Duration) {
        drop(self.stdin.take());
        let stop = Instant::now() + deadline;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < stop => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
    }
}

/// Reduce a `tools/call` reply to an [`Observed`].
fn observed_from_reply(reply: &Value) -> Observed {
    if let Some(error) = reply.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("JSON-RPC error");
        return Observed::Error {
            class: "JSON_RPC_ERROR".to_owned(),
            message: message.to_owned(),
        };
    }
    let Some(result) = reply.get("result") else {
        return Observed::Transport("reply had neither result nor error".to_owned());
    };
    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if is_error {
        let class = result
            .pointer("/structuredContent/error_class")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                result
                    .get("content")
                    .and_then(Value::as_array)
                    .and_then(|items| items.first())
                    .and_then(|item| item.get("text"))
                    .and_then(Value::as_str)
                    .and_then(extract_error_class)
            })
            .unwrap_or_else(|| "UNKNOWN".to_owned());
        let message = result
            .pointer("/structuredContent/message")
            .and_then(Value::as_str)
            .or_else(|| {
                result
                    .get("content")
                    .and_then(Value::as_array)
                    .and_then(|items| items.first())
                    .and_then(|item| item.get("text"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("")
            .to_owned();
        return Observed::Error { class, message };
    }
    Observed::Success(result.clone())
}

/// Parse `"error_class":"X"` out of a text content block without a regex dep.
fn extract_error_class(text: &str) -> Option<String> {
    let marker = "\"error_class\"";
    let start = text.find(marker)? + marker.len();
    let rest = text[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

// ---------------------------------------------------------------------------
// Probe planning
// ---------------------------------------------------------------------------

/// The write tools (destructive or not read-only) and the read tools.
fn tool_kinds() -> (Vec<String>, Vec<String>) {
    let registry = oraclemcp::registry::tool_registry();
    let mut writes = Vec::new();
    let mut reads = Vec::new();
    for tool in registry.tools {
        let is_write = tool.destructive || !tool.annotations.read_only_hint;
        if is_write {
            writes.push(tool.name);
        } else {
            reads.push(tool.name);
        }
    }
    (writes, reads)
}

/// Build conservative synthetic arguments from a tool's advertised schema. For
/// writes, every statement-bearing field carries the synthetic write marker.
fn synthetic_arguments(schema: Option<&Value>, is_write: bool) -> Value {
    let mut object = serde_json::Map::new();
    let properties = schema
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object);
    let required: Vec<String> = schema
        .and_then(|schema| schema.get("required"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    if let Some(properties) = properties {
        for (name, property) in properties {
            if !is_write && !required.iter().any(|required| required == name) {
                continue;
            }
            let value = match property.get("type").and_then(Value::as_str) {
                Some("integer") => json!(if name == "max_rows" {
                    SELFTEST_ROW_CAP
                } else {
                    1
                }),
                Some("boolean") => json!(false),
                Some("array") => json!([]),
                Some("object") => json!({}),
                _ => json!("oraclemcp_selftest"),
            };
            object.insert(name.clone(), value);
        }
    }
    if is_write {
        for key in ["sql", "statement", "plsql", "source", "text", "body", "ddl"] {
            if object.contains_key(key) {
                object.insert(key.to_owned(), json!(WRITE_MARKER));
            }
        }
        if !object.contains_key("sql")
            && !object.contains_key("statement")
            && !object.contains_key("plsql")
        {
            object.insert("sql".to_owned(), json!(WRITE_MARKER));
        }
    }
    Value::Object(object)
}

/// Reuse an embedded canonical read probe for an advertised compatibility
/// alias.  This exercises the alias with known-good read arguments instead of
/// mistaking a missing required argument for an alias safety result.
fn advertised_read_arguments(tool: &str, cases: &[ReadonlyCase], schema: Option<&Value>) -> Value {
    let canonical = oraclemcp::registry::alias_target(tool).unwrap_or(tool);
    cases
        .iter()
        .find(|case| case.tool == canonical)
        .map(|case| case.arguments.clone())
        .unwrap_or_else(|| synthetic_arguments(schema, false))
}

// ---------------------------------------------------------------------------
// Audit verification
// ---------------------------------------------------------------------------

/// Verify the run's own audit file shows no privileged action. Returns the
/// record count; `Err` names the offending record when one is found.
fn audit_shows_no_privileged_action(
    path: &Path,
    write_tools: &BTreeSet<String>,
) -> Result<usize, String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        // No audit file means no audited action at all — vacuously safe.
        return Ok(0);
    };
    let mut count = 0usize;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            return Err(format!("audit line {} is not JSON", index + 1));
        };
        count += 1;
        let danger = record
            .get("danger_level")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_uppercase();
        if matches!(danger.as_str(), "GUARDED" | "DESTRUCTIVE" | "FORBIDDEN") {
            return Err(format!(
                "audit line {} recorded a {danger} action",
                index + 1
            ));
        }
        let decision = record
            .get("decision")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_uppercase();
        let tool = record.get("tool").and_then(Value::as_str).unwrap_or("");
        if decision == "ALLOWED" && write_tools.contains(tool) {
            return Err(format!(
                "audit line {} allowed write tool `{tool}`",
                index + 1
            ));
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// HTTP transport probe
// ---------------------------------------------------------------------------

/// Probe a running Streamable HTTP listener with a raw `initialize`.
fn probe_http_transport(url: &str) -> (Class, String) {
    use std::io::Read;
    use std::net::{TcpStream, ToSocketAddrs};

    let base = url.trim_end_matches('/');
    let authority = base
        .strip_prefix("http://")
        .or_else(|| base.strip_prefix("https://"))
        .unwrap_or(base)
        .split('/')
        .next()
        .unwrap_or(base);
    let mcp_path = if base.ends_with("/mcp") { "" } else { "/mcp" };
    let Some(addr) = authority
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
    else {
        return (
            Class::Environment,
            format!("HTTP listener `{url}` did not resolve"),
        );
    };
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "oraclemcp-selftest", "version": env!("CARGO_PKG_VERSION") }
        }
    })
    .to_string();
    let request = format!(
        "POST {mcp_path} HTTP/1.1\r\nhost: {authority}\r\ncontent-type: application/json\r\n\
         accept: application/json, text/event-stream\r\nmcp-protocol-version: 2025-11-25\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) else {
        return (
            Class::Environment,
            format!("HTTP listener `{url}` is not reachable"),
        );
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    if stream.write_all(request.as_bytes()).is_err() {
        return (
            Class::Defect,
            "HTTP listener closed the request early".to_owned(),
        );
    }
    let mut raw = String::new();
    if stream.read_to_string(&mut raw).is_err() {
        return (
            Class::Defect,
            "HTTP listener response was unreadable".to_owned(),
        );
    }
    if raw.contains("\"result\"") && raw.contains("protocolVersion") {
        (Class::Pass, "HTTP initialize succeeded".to_owned())
    } else {
        (
            Class::Defect,
            "HTTP initialize did not return a protocol version".to_owned(),
        )
    }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// The full report the runner prints.
struct RunReport {
    outcomes: Vec<ProbeRecord>,
    audit_records: usize,
}

pub(crate) fn run(robot_json: bool, args: SelftestCliArgs) -> ExitCode {
    let started = Instant::now();
    let budget = Duration::from_secs(args.budget.max(1));
    // Fail-closed redaction set: everything below is scrubbed from JSON/drafts.
    let mut redactor = Redactor::new(std::iter::empty::<String>());
    let mut outcomes: Vec<ProbeRecord> = Vec::new();

    let Some(source) = source_config_path() else {
        outcomes.push(ProbeRecord::new(
            "config_source",
            Class::Environment,
            "no config file found; set ORACLEMCP_CONFIG or install profiles.toml",
        ));
        return finish(robot_json, &args, started, outcomes, 0, &redactor);
    };

    // Seed the redactor from the operator's profile before anything else can
    // capture an identifier.
    if let Ok(config) = OracleMcpConfig::load(Some(&source))
        && let Some(profile) = config.profile(&args.profile)
    {
        if let Some(value) = profile.username.as_deref() {
            redactor.add(value.to_owned());
        }
        if let Some(value) = profile.connect_string.as_deref() {
            redactor.add(value.to_owned());
        }
    }
    // An optional listener URL is operator supplied and may include an internal
    // host, service path, or bearer material. A failed HTTP transport probe
    // includes that URL in its diagnostic, so register it before any probe can
    // emit a report or issue draft.
    if let Some(http) = args.http.as_deref() {
        redactor.add(http.to_owned());
    }

    let derived = match derive_readonly_config(&args.profile, &source) {
        Ok(derived) => derived,
        Err(message) => {
            outcomes.push(ProbeRecord::new(
                "forced_readonly_profile",
                Class::Environment,
                redactor.scrub(&message),
            ));
            return finish(robot_json, &args, started, outcomes, 0, &redactor);
        }
    };
    outcomes.push(ProbeRecord::new(
        "forced_readonly_profile",
        Class::Pass,
        format!(
            "derived profile `{}` pinned max_level = READ_ONLY",
            args.profile
        ),
    ));

    let (write_tools, read_tools) = tool_kinds();
    let schemas: std::collections::HashMap<String, Value> = oraclemcp::registry::tool_registry()
        .tools
        .into_iter()
        .filter_map(|descriptor| {
            descriptor
                .input_schema
                .map(|schema| (descriptor.name, schema))
        })
        .collect();
    let write_set: BTreeSet<String> = write_tools.iter().cloned().collect();
    let cases = match embedded_cases() {
        Ok(cases) => cases,
        Err(message) => {
            outcomes.push(ProbeRecord::new("readonly_cases", Class::Defect, message));
            return finish(robot_json, &args, started, outcomes, 0, &redactor);
        }
    };
    // Every case identifier and bind value is scrubbed from outputs.
    for case in &cases {
        collect_case_identifiers(case, &mut redactor);
    }

    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            outcomes.push(ProbeRecord::new(
                "probe_child",
                Class::Defect,
                format!("cannot resolve current executable: {error}"),
            ));
            return finish(robot_json, &args, started, outcomes, 0, &redactor);
        }
    };

    let mut client = match StdioClient::spawn(&exe, &derived, &args.profile) {
        Ok(client) => Some(client),
        Err(message) => {
            outcomes.push(ProbeRecord::new(
                "probe_child",
                Class::Defect,
                redactor.scrub(&message),
            ));
            None
        }
    };

    if let Some(client) = client.as_mut() {
        // stdio transport + handshake.
        let init = client.request(
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "oraclemcp-selftest", "version": env!("CARGO_PKG_VERSION") }
            }),
            PROBE_TIMEOUT,
        );
        match init {
            Ok(reply) if reply.pointer("/result/protocolVersion").is_some() => {
                outcomes.push(ProbeRecord::new(
                    "transport_stdio",
                    Class::Pass,
                    "stdio initialize succeeded",
                ));
            }
            Ok(_) => outcomes.push(ProbeRecord::new(
                "transport_stdio",
                Class::Defect,
                "stdio initialize returned no protocol version",
            )),
            Err(message) => outcomes.push(ProbeRecord::new(
                "transport_stdio",
                Class::Defect,
                redactor.scrub(&format!("{message}; stderr: {}", client.stderr_text())),
            )),
        }
        let _ = client.notify("notifications/initialized", json!({}));

        // Advertisement sweep: the served registry must match exactly.
        let advertised = client
            .request("tools/list", json!({}), PROBE_TIMEOUT)
            .ok()
            .and_then(|reply| reply.pointer("/result/tools").cloned())
            .and_then(|tools| tools.as_array().cloned())
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|tool| tool.get("name").and_then(Value::as_str).map(str::to_owned))
                    .collect::<Vec<_>>()
            });
        if let Some(advertised) = advertised {
            // The served `tools/list` is authoritative for the sweep; registry
            // metadata (destructive / read-only hints) joins in by name.
            let known: BTreeSet<String> = read_tools
                .iter()
                .chain(write_tools.iter())
                .cloned()
                .collect();
            let capabilities = oraclemcp_core::CAPABILITIES_TOOL;
            let unexpected: Vec<&String> = advertised
                .iter()
                .filter(|name| !known.contains(*name) && name.as_str() != capabilities)
                .collect();
            if unexpected.is_empty() {
                outcomes.push(ProbeRecord::new(
                    "transport_tools_list",
                    Class::Pass,
                    format!("{} advertised tools classified", advertised.len()),
                ));
            } else {
                outcomes.push(ProbeRecord::new(
                    "transport_tools_list",
                    Class::Defect,
                    format!(
                        "{} unexpected advertised tools (not in the registry)",
                        unexpected.len()
                    ),
                ));
            }

            // Embedded read-only cases first (fine-grained expectations).
            for case in &cases {
                if Instant::now().duration_since(started) >= budget {
                    outcomes.push(skipped(&case.case_id));
                    continue;
                }
                let case_started = Instant::now();
                let observed = client.tool_call(&case.tool, case.arguments.clone(), PROBE_TIMEOUT);
                let (class, error_class, detail) = classify_read_case(&case.expect, &observed);
                let mut record = ProbeRecord::new(
                    &case.case_id,
                    class,
                    detail.unwrap_or_else(|| {
                        format!(
                            "read-only case exercised (W4 source `{}`)",
                            case.source_case_id
                        )
                    }),
                );
                record.error_class = error_class;
                record.duration_ms = case_started.elapsed().as_millis() as u64;
                if let Some(privilege) = privilege_detail(&observed) {
                    record.privilege = Some(redactor.scrub(&privilege));
                }
                outcomes.push(record);
                // Forced-READ_ONLY self-proof: the served surface must report
                // the derived READ_ONLY ceiling as the effective access.
                if case.tool == "oracle_connection_info"
                    && let Observed::Success(result) = &observed
                {
                    outcomes.push(effective_access_probe(result));
                }
            }

            // Elevation probes: requesting a level above the derived READ_ONLY
            // ceiling must be refused. This is the load-bearing proof that the
            // forced ceiling holds; the probe never confirms an elevation.
            for tool in ELEVATION_TOOLS {
                if !advertised.iter().any(|name| name == tool) {
                    continue;
                }
                if Instant::now().duration_since(started) >= budget {
                    outcomes.push(skipped(format!("elevation:{tool}")));
                    continue;
                }
                let args_value = elevation_arguments(tool).expect("elevation tool has arguments");
                let case_started = Instant::now();
                let observed = client.tool_call(tool, args_value, PROBE_TIMEOUT);
                let (class, error_class) = classify_elevation(tool, &observed);
                let mut record = ProbeRecord::new(
                    format!("elevation:{tool}"),
                    class,
                    "elevation above the READ_ONLY ceiling must be refused",
                );
                record.error_class = error_class;
                record.duration_ms = case_started.elapsed().as_millis() as u64;
                outcomes.push(record);
            }

            // Write-tool refusal sweep: a write must never execute at READ_ONLY.
            for tool in &write_tools {
                if ELEVATION_TOOLS.contains(&tool.as_str()) {
                    continue;
                }
                if !advertised.iter().any(|name| name == tool) {
                    continue;
                }
                if Instant::now().duration_since(started) >= budget {
                    outcomes.push(skipped(format!("write:{tool}")));
                    continue;
                }
                let args_value = synthetic_arguments(schemas.get(tool), true);
                let case_started = Instant::now();
                let observed = client.tool_call(tool, args_value, PROBE_TIMEOUT);
                let (class, error_class) = classify_write_observed(&observed);
                let mut record = ProbeRecord::new(
                    format!("write:{tool}"),
                    class,
                    "synthetic write must be refused at READ_ONLY",
                );
                record.error_class = error_class;
                record.duration_ms = case_started.elapsed().as_millis() as u64;
                outcomes.push(record);
            }

            // Generic read sweep for advertised read tools without a case.
            let covered: BTreeSet<&str> = cases.iter().map(|case| case.tool.as_str()).collect();
            for tool in &advertised {
                if write_set.contains(tool)
                    || ELEVATION_TOOLS.contains(&tool.as_str())
                    || covered.contains(tool.as_str())
                    || tool.as_str() == capabilities
                {
                    continue;
                }
                if Instant::now().duration_since(started) >= budget {
                    outcomes.push(skipped(format!("advertised:{tool}")));
                    continue;
                }
                let args_value = advertised_read_arguments(tool, &cases, schemas.get(tool));
                let case_started = Instant::now();
                let observed = client.tool_call(tool, args_value, PROBE_TIMEOUT);
                let (class, error_class) = classify_generic_read(&observed);
                let mut record = ProbeRecord::new(
                    format!("advertised:{tool}"),
                    class,
                    "advertised read tool exercised with synthetic input",
                );
                record.error_class = error_class;
                record.duration_ms = case_started.elapsed().as_millis() as u64;
                outcomes.push(record);
            }
        } else {
            outcomes.push(ProbeRecord::new(
                "transport_tools_list",
                Class::Defect,
                "tools/list did not return a tools array",
            ));
        }

        client.close(Duration::from_secs(5));
    }

    // doctor --online phase-aware connection report (T9.4b), driven as a child.
    let doctor = run_doctor_online(&exe, &derived, &args.profile, &redactor, budget, started);
    outcomes.push(doctor);

    // HTTP transport probe when a listener is configured.
    if let Some(url) = args.http.as_deref() {
        let (class, detail) = probe_http_transport(url);
        let mut record = ProbeRecord::new("transport_http", class, redactor.scrub(&detail));
        record.duration_ms = 0;
        outcomes.push(record);
    } else {
        outcomes.push(ProbeRecord::new(
            "transport_http",
            Class::Skipped,
            "no --http listener configured",
        ));
    }

    // Verify the run's own audit proves no privileged action.
    let audit_records = match audit_shows_no_privileged_action(&derived.audit_path, &write_set) {
        Ok(count) => {
            outcomes.push(ProbeRecord::new(
                "forced_readonly_audit",
                Class::Pass,
                format!("{count} audit records, no privileged action"),
            ));
            count
        }
        Err(message) => {
            outcomes.push(ProbeRecord::new(
                "forced_readonly_audit",
                Class::Defect,
                redactor.scrub(&message),
            ));
            0
        }
    };

    finish(
        robot_json,
        &args,
        started,
        outcomes,
        audit_records,
        &redactor,
    )
}

fn skipped(probe: impl Into<String>) -> ProbeRecord {
    let mut record = ProbeRecord::new(probe, Class::Skipped, "not reached");
    record.skipped = Some("budget".to_owned());
    record
}

/// Pull identifiers out of a case's synthetic arguments so drafts/json scrub them.
fn collect_case_identifiers(case: &ReadonlyCase, redactor: &mut Redactor) {
    fn walk(value: &Value, redactor: &mut Redactor) {
        match value {
            Value::String(text) => {
                for token in
                    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                {
                    if token.len() > 2 && !token.eq_ignore_ascii_case("select") {
                        redactor.add(token.to_owned());
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(item, redactor)),
            Value::Object(map) => map.values().for_each(|item| walk(item, redactor)),
            _ => {}
        }
    }
    walk(&case.arguments, redactor);
}

/// Build the forced-READ_ONLY proof probe from an `oracle_connection_info`
/// result: the served surface must report the derived READ_ONLY ceiling.
fn effective_access_probe(result: &Value) -> ProbeRecord {
    let access = result.pointer("/structuredContent/effective_access");
    let max_level = access
        .and_then(|access| access.get("max_level"))
        .and_then(Value::as_str);
    let writes = access
        .and_then(|access| access.get("writes_permitted_now"))
        .and_then(Value::as_bool);
    if max_level == Some("READ_ONLY") && writes == Some(false) {
        ProbeRecord::new(
            "forced_readonly_effective_access",
            Class::Pass,
            "served effective_access.max_level = READ_ONLY, writes_permitted_now = false",
        )
    } else if max_level.is_none() {
        ProbeRecord::new(
            "forced_readonly_effective_access",
            Class::Defect,
            "served connection info carried no effective_access ceiling",
        )
    } else {
        ProbeRecord::new(
            "forced_readonly_effective_access",
            Class::Defect,
            format!(
                "served effective access is not READ_ONLY (max_level={max_level:?}, writes_permitted_now={writes:?})"
            ),
        )
    }
}

/// Extract a redaction-ready privilege detail from an observation.
fn privilege_detail(observed: &Observed) -> Option<String> {
    match observed {
        Observed::Error { class, message }
            if normalize_class(class) == "INSUFFICIENT_PRIVILEGE" =>
        {
            Some(privilege_from_message(message))
        }
        _ => None,
    }
}

/// Run `doctor --online` as a child with the derived READ_ONLY config.
fn run_doctor_online(
    exe: &Path,
    derived: &DerivedConfig,
    profile: &str,
    redactor: &Redactor,
    budget: Duration,
    started: Instant,
) -> ProbeRecord {
    if Instant::now().duration_since(started) >= budget {
        return skipped("doctor_online");
    }
    let started_probe = Instant::now();
    let mut child = match Command::new(exe)
        .arg("--json")
        .arg("doctor")
        .arg("--profile")
        .arg(profile)
        .arg("--online")
        .env("ORACLEMCP_CONFIG", &derived.config_path)
        .env("XDG_STATE_HOME", &derived.state_dir)
        .env("HOME", &derived.home_dir)
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let mut record = ProbeRecord::new(
                "doctor_online",
                Class::Defect,
                format!("cannot spawn doctor: {error}"),
            );
            record.duration_ms = started_probe.elapsed().as_millis() as u64;
            return record;
        }
    };
    let deadline = Instant::now() + PROBE_TIMEOUT.max(Duration::from_secs(30));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let output = child.wait_with_output().ok();
    let mut record = match status.map(|status| status.code()) {
        Some(Some(0)) => ProbeRecord::new(
            "doctor_online",
            Class::Pass,
            "doctor --online reported no blocker",
        ),
        Some(Some(2)) => ProbeRecord::new(
            "doctor_online",
            Class::Environment,
            "doctor --online reported an environment blocker (see doctor output)",
        ),
        Some(Some(other)) => ProbeRecord::new(
            "doctor_online",
            Class::Defect,
            format!("doctor --online exited {other}"),
        ),
        _ => ProbeRecord::new(
            "doctor_online",
            Class::Defect,
            "doctor --online did not finish",
        ),
    };
    if let Some(output) = output
        && !output.stderr.is_empty()
        && record.class == Class::Defect
    {
        record.detail = redactor.scrub(&String::from_utf8_lossy(&output.stderr));
    }
    record.duration_ms = started_probe.elapsed().as_millis() as u64;
    record
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn finish(
    robot_json: bool,
    args: &SelftestCliArgs,
    started: Instant,
    mut outcomes: Vec<ProbeRecord>,
    audit_records: usize,
    redactor: &Redactor,
) -> ExitCode {
    // Redact every detail that has not already been scrubbed.
    for record in &mut outcomes {
        record.detail = redactor.scrub(&record.detail);
    }
    let classes: Vec<Class> = outcomes.iter().map(|record| record.class).collect();
    let code = exit_code_for(&classes);

    if let Some(dir) = args.issue_draft.as_deref()
        && let Err(error) = write_issue_drafts(dir, &outcomes, redactor)
    {
        eprintln!("oraclemcp selftest: could not write issue drafts: {error}");
    }

    if robot_json {
        let report = json!({
            "schema": "oraclemcp.selftest/v1",
            "oraclemcp_version": env!("CARGO_PKG_VERSION"),
            "profile": redactor.scrub(&args.profile),
            "duration_ms": started.elapsed().as_millis() as u64,
            "audit_records": audit_records,
            "exit_code": code,
            "outcomes": outcomes.iter().map(|record| json!({
                "probe": record.probe,
                "outcome": record.class.as_str(),
                "class": record.error_class,
                "duration_ms": record.duration_ms,
                "privilege": record.privilege,
                "skipped": record.skipped,
                "detail": record.detail,
            })).collect::<Vec<_>>(),
        });
        println!("{report}");
    } else {
        let report = RunReport {
            outcomes: outcomes.clone(),
            audit_records,
        };
        print_human_summary(args, started, &report, redactor);
    }

    ExitCode::from(code)
}

fn print_human_summary(
    args: &SelftestCliArgs,
    started: Instant,
    report: &RunReport,
    redactor: &Redactor,
) {
    let mut passed = 0usize;
    let mut refusal = 0usize;
    let mut environment = 0usize;
    let mut defects = 0usize;
    let mut skipped = 0usize;
    for record in &report.outcomes {
        match record.class {
            Class::Pass => passed += 1,
            Class::ExpectedRefusal => refusal += 1,
            Class::Environment => environment += 1,
            Class::Defect => defects += 1,
            Class::Skipped => skipped += 1,
        }
    }
    println!(
        "oraclemcp selftest {} — profile `{}` pinned READ_ONLY",
        env!("CARGO_PKG_VERSION"),
        redactor.scrub(&args.profile)
    );
    for record in &report.outcomes {
        let label = match record.class {
            Class::Pass => "PASS ",
            Class::ExpectedRefusal => "REFUS",
            Class::Environment => "ENVIR",
            Class::Defect => "DEFECT",
            Class::Skipped => "SKIP ",
        };
        println!(
            "  {label} {:<40} {}{}",
            record.probe,
            record.detail,
            record
                .privilege
                .as_deref()
                .map(|privilege| format!(" [{privilege}]"))
                .unwrap_or_default()
        );
    }
    println!(
        "selftest: {passed} pass, {refusal} expected refusal, {environment} environment, {defects} defect, {skipped} skipped; audit records: {}; {:.1}s",
        report.audit_records,
        started.elapsed().as_secs_f64()
    );
}

fn write_issue_drafts(
    dir: &Path,
    outcomes: &[ProbeRecord],
    redactor: &Redactor,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    for record in outcomes
        .iter()
        .filter(|record| record.class == Class::Defect)
    {
        let slug: String = record
            .probe
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let body = format!(
            "# oraclemcp selftest defect: {probe}\n\n\
             ## Repro\n\
             Run `oraclemcp selftest --profile <profile>` from the installed binary. The probe \
             `{probe}` exercises the served READ_ONLY transport with synthetic input.\n\n\
             ## Observed\n\
             {detail}\n\n\
             ## Expected\n\
             A READ_ONLY probe should succeed, an unsupported probe should return a typed \
             refusal, and an environment condition should be reported as environment.\n\n\
             ## Versions\n\
             - oraclemcp: {version}\n\
             - error class: {class}\n\n\
             <!-- Sanitized: no host, schema, table, bind, or credential identifiers. -->\n",
            probe = redactor.scrub(&record.probe),
            detail = redactor.scrub(&record.detail),
            version = env!("CARGO_PKG_VERSION"),
            class = record.error_class.as_deref().unwrap_or("none"),
        );
        std::fs::write(dir.join(format!("selftest-{slug}.md")), body)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_precedence() {
        assert_eq!(
            exit_code_for(&[Class::Defect, Class::Environment]),
            2,
            "a defect outranks an environment finding"
        );
        assert_eq!(exit_code_for(&[Class::Environment]), 3, "environment only");
        assert_eq!(exit_code_for(&[Class::Pass, Class::ExpectedRefusal]), 0);
        assert_eq!(exit_code_for(&[Class::Skipped]), 0);
        assert_eq!(exit_code_for(&[Class::Defect]), 2);
    }

    #[test]
    fn redactor_removes_identifiers() {
        // Each canary is registered and must vanish from the scrubbed text, as
        // the e2e redaction canaries require (host, service, schema, table,
        // bind, password).
        let canaries = [
            ("db-secret-host.example.com", "host"),
            ("ORCLPDB1", "service"),
            ("APP_OWNER", "schema"),
            ("SECRET_TABLE", "table"),
            ("bind-secret-value-42", "bind"),
            ("Sup3r-Secret-Pw", "password"),
        ];
        let redactor = Redactor::new(canaries.iter().map(|(value, _)| (*value).to_owned()));
        for (canary, kind) in canaries {
            let message = format!("observed {kind}={canary} while probing");
            let scrubbed = redactor.scrub(&message);
            assert!(
                !scrubbed.contains(canary),
                "{kind} canary survived redaction: {scrubbed}"
            );
            assert!(
                scrubbed.contains(REDACTED),
                "{kind} produced no placeholder: {scrubbed}"
            );
        }
        // Evidence that must survive redaction.
        let keep = "error_class=OPERATING_LEVEL_TOO_LOW tool=oracle_execute ORA-01031";
        assert_eq!(redactor.scrub(keep), keep);
    }

    #[test]
    fn redactor_scrubs_connect_strings() {
        let redactor = Redactor::default();
        for connect in [
            "jdbc:oracle:thin:@db.internal:1521/SVC",
            "(DESCRIPTION=(ADDRESS=(HOST=10.0.0.9)(PORT=1521)))",
            "tcps://adb.example.com:1522/service?wallet_location=/secret",
            "scott@db.internal:1521/ORCLPDB1",
        ] {
            let scrubbed = redactor.scrub(&format!("connect via {connect} failed"));
            assert!(
                !scrubbed.contains(connect),
                "connect string survived: {scrubbed}"
            );
            assert!(scrubbed.contains(REDACTED), "no placeholder: {scrubbed}");
        }
    }

    #[test]
    fn selftest_cases_are_readonly_subset_of_w4() {
        let cases = embedded_cases().expect("embedded cases parse");
        assert!(!cases.is_empty(), "at least one embedded case");

        let w4_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/w4/cases");
        assert!(
            w4_dir.is_dir(),
            "W4 case directory must exist for the drift check: {}",
            w4_dir.display()
        );

        // Index every W4 case by id.
        let mut w4: std::collections::HashMap<String, (String, bool, bool)> =
            std::collections::HashMap::new();
        for entry in std::fs::read_dir(&w4_dir).expect("read W4 cases dir") {
            let path = entry.expect("W4 dir entry").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read W4 case file");
            let parsed: Value = serde_json::from_str(&text).expect("W4 case file is JSON");
            let Some(items) = parsed.as_array() else {
                continue;
            };
            for item in items {
                let (Some(id), Some(level)) = (
                    item.get("case_id").and_then(Value::as_str),
                    item.get("level").and_then(Value::as_str),
                ) else {
                    continue;
                };
                let setup_empty = item
                    .get("setup")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(true);
                let requires_empty = item
                    .get("requires")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(true);
                w4.insert(
                    id.to_owned(),
                    (level.to_owned(), setup_empty, requires_empty),
                );
            }
        }

        for case in &cases {
            assert_eq!(
                case.level, "READ_ONLY",
                "embedded case `{}` must be READ_ONLY",
                case.case_id
            );
            let (level, setup_empty, requires_empty) =
                w4.get(&case.source_case_id).unwrap_or_else(|| {
                    panic!(
                        "embedded case `{}` references unknown W4 case `{}`",
                        case.case_id, case.source_case_id
                    )
                });
            assert_eq!(
                level, "READ_ONLY",
                "W4 source `{}` is READ_ONLY",
                case.source_case_id
            );
            assert!(
                setup_empty,
                "W4 source `{}` has no fixture setup",
                case.source_case_id
            );
            assert!(
                requires_empty,
                "W4 source `{}` has no extra requirements",
                case.source_case_id
            );
        }
    }

    #[test]
    fn advertised_alias_reuses_covered_canonical_read_arguments() {
        let cases = embedded_cases().expect("embedded cases parse");
        let arguments = advertised_read_arguments("query", &cases, None);
        assert_eq!(arguments["sql"], "SELECT 1 AS n FROM DUAL");
        assert_eq!(arguments["max_rows"], SELFTEST_ROW_CAP);
    }

    #[test]
    fn generic_placeholder_refusals_are_not_database_environment_findings() {
        for class in [
            "INVALID_ARGUMENTS",
            "OBJECT_NOT_FOUND",
            "RUNTIME_STATE_REQUIRED",
        ] {
            let observed = Observed::Error {
                class: class.to_owned(),
                message: String::new(),
            };
            assert_eq!(
                classify_generic_read(&observed).0,
                Class::ExpectedRefusal,
                "{class} is a safe rejection of schema-shaped placeholder input"
            );
        }
    }

    #[test]
    fn cli_parses_selftest_args() {
        use clap::Parser;
        let parsed = crate::Cli::try_parse_from([
            "oraclemcp",
            "selftest",
            "--profile",
            "lab_free23",
            "--issue-draft",
            "/tmp/drafts",
            "--http",
            "http://127.0.0.1:7070",
            "--budget",
            "42",
        ])
        .expect("selftest args parse");
        match parsed.command {
            Some(crate::Command::Selftest(args)) => {
                assert_eq!(args.profile, "lab_free23");
                assert_eq!(args.issue_draft.as_deref(), Some(Path::new("/tmp/drafts")));
                assert_eq!(args.http.as_deref(), Some("http://127.0.0.1:7070"));
                assert_eq!(args.budget, 42);
            }
            other => panic!("expected Selftest command, got {other:?}"),
        }
    }

    #[test]
    fn issue_drafts_are_redacted() {
        let temp = tempfile::tempdir().expect("temp dir");
        let redactor = Redactor::new(vec![
            "canary-db.internal:1521/SECRETSVC".to_owned(),
            "CANARY_USER".to_owned(),
            "Sup3rSecretCanary".to_owned(),
        ]);
        let mut defect = ProbeRecord::new(
            "transport_http",
            Class::Defect,
            "HTTP initialize failed against canary-db.internal:1521/SECRETSVC as CANARY_USER (password Sup3rSecretCanary)",
        );
        defect.error_class = Some("CONNECT_FAILED".to_owned());
        write_issue_drafts(temp.path(), &[defect], &redactor).expect("write draft");
        let drafts: Vec<_> = std::fs::read_dir(temp.path())
            .expect("read drafts")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        assert_eq!(drafts.len(), 1, "one draft per defect");
        let body = std::fs::read_to_string(&drafts[0]).expect("read draft");
        for canary in [
            "canary-db.internal",
            "SECRETSVC",
            "CANARY_USER",
            "Sup3rSecretCanary",
        ] {
            assert!(!body.contains(canary), "canary `{canary}` leaked: {body}");
        }
        assert!(
            body.contains(REDACTED),
            "draft should carry placeholders: {body}"
        );
    }

    #[test]
    fn redactor_scrubs_optional_http_listener_url() {
        let listener = "https://canary-selftest-host.invalid/mcp?token=canary-token";
        let mut redactor = Redactor::default();
        redactor.add(listener.to_owned());
        let scrubbed = redactor.scrub(&format!("HTTP initialize failed for {listener}"));
        assert!(!scrubbed.contains(listener));
        assert!(scrubbed.contains(REDACTED));
    }

    #[test]
    fn audit_scan_flags_privileged_actions() {
        let temp = tempfile::tempdir().expect("temp dir");
        let audit = temp.path().join("audit.jsonl");
        let writes: BTreeSet<String> = ["oracle_execute".to_owned()].into_iter().collect();

        std::fs::write(
            &audit,
            "{\"danger_level\":\"READ_ONLY\",\"decision\":\"ALLOWED\",\"tool\":\"oracle_query\"}\n",
        )
        .expect("write safe audit");
        assert_eq!(
            audit_shows_no_privileged_action(&audit, &writes).expect("safe audit"),
            1
        );

        std::fs::write(
            &audit,
            "{\"danger_level\":\"DESTRUCTIVE\",\"decision\":\"ALLOWED\",\"tool\":\"oracle_execute\"}\n",
        )
        .expect("write privileged audit");
        assert!(
            audit_shows_no_privileged_action(&audit, &writes).is_err(),
            "a destructive action must fail the verification"
        );
    }
}
