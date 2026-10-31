//! `oraclemcp demo`: a bounded, self-cleaning walkthrough of the guarded write
//! ladder on Oracle FREE 23ai: refuse -> preview -> confirm -> rollback ->
//! audit verify.
//!
//! Docker is driven through its CLI only. Without `--yes`, or with
//! `--dry-run`, only read-only Docker queries run. A started container carries
//! a per-run label token and is the only thing teardown ever stops or removes.

use clap::Args;
use serde::Serialize;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitCode, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// FREE 23ai image, pinned by the same digest as CI's `oracle-free23` job.
pub(crate) const DEMO_IMAGE: &str = "gvenzl/oracle-free:23-slim@sha256:fbbd3023d5abc33e36d3814816e6fd740e8efabeaa70cf470ddeab5874a3f6f8";
const DEMO_LABEL: &str = "oraclemcp.demo";
const RUN_LABEL: &str = "oraclemcp.demo.run";
const CPUS: &str = "2";
// 3g is OOM-killed while the pinned image unpacks its datafiles on first
// start (measured: exit 137, OOMKilled); 4g starts in under 20 s.
const MEMORY: &str = "4g";
const PIDS_LIMIT: &str = "512";
const DEMO_RUN_ID: &str = "DEMO";
const DEMO_USER: &str = "OMCP_DEMO";
const READY_MARKER: &str = "DATABASE IS READY TO USE!";
const SEED_SQL: &str = include_str!("../demo/seed.sql");
// Not `ORACLEMCP_*`: the server reads those as config overrides.
const AUDIT_KEY_ENV: &str = "OMCP_DEMO_AUDIT_KEY";
const PASSWORD_ENV: &str = "OMCP_DEMO_PASSWORD";
const DOCKER_CALL_TIMEOUT: Duration = Duration::from_secs(120);
const DEMO_UPDATE: &str = "UPDATE T_PARENT_DEMO SET LABEL = 'demo-change' WHERE ID = 1";
const DEMO_REREAD: &str = "SELECT LABEL FROM T_PARENT_DEMO WHERE ID = 1";

#[derive(Args, Debug, Clone)]
pub(crate) struct DemoCliArgs {
    /// Start the demo container. Without it only read-only checks run and the
    /// plan is printed.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Print the plan and make no mutating Docker call, even with --yes.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Host port for the container listener, bound on 127.0.0.1 only.
    #[arg(long, default_value_t = 1525)]
    pub(crate) port: u16,
    /// Keep the container after the demo instead of removing it.
    #[arg(long)]
    pub(crate) keep: bool,
    /// Overall wall-clock budget in seconds, including database start.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(10..=3600))]
    pub(crate) timeout_secs: u64,
}

/// Docker CLI seam: read-only queries are kept apart from anything that
/// changes Docker state or runs inside a container.
pub(crate) trait Docker {
    /// A read-only query: `version`, `image inspect`, `inspect`, `logs`, `ps`.
    fn query(&self, args: &[&str], timeout: Duration) -> Result<String, String>;
    /// A mutating call (`run`, `rm`) or a command run inside a container.
    fn mutate(
        &self,
        args: &[&str],
        env: &[(&str, &str)],
        stdin: Option<&str>,
        timeout: Duration,
    ) -> Result<String, String>;
}

struct DockerCli;

impl Docker for DockerCli {
    fn query(&self, args: &[&str], timeout: Duration) -> Result<String, String> {
        let mut command = Command::new("docker");
        command.args(args);
        run_bounded(command, None, timeout)
    }

    fn mutate(
        &self,
        args: &[&str],
        env: &[(&str, &str)],
        stdin: Option<&str>,
        timeout: Duration,
    ) -> Result<String, String> {
        let mut command = Command::new("docker");
        command.args(args);
        for (key, value) in env {
            command.env(key, value);
        }
        run_bounded(command, stdin, timeout)
    }
}

/// Run a child with a hard deadline, draining both pipes so it cannot block.
fn run_bounded(
    mut command: Command,
    stdin: Option<&str>,
    timeout: Duration,
) -> Result<String, String> {
    let program = format!("{:?}", command.get_program());
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes())
            .map_err(|error| format!("cannot write to {program}: {error}"))?;
    }
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(pipe) = pipe {
                let _ = pipe.take(4 * 1024 * 1024).read_to_end(&mut bytes);
            }
            String::from_utf8_lossy(&bytes).into_owned()
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{program} did not finish within {}s",
                    timeout.as_secs()
                ));
            }
            Err(error) => return Err(format!("cannot wait for {program}: {error}")),
        }
    };
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    if status.success() {
        Ok(stdout)
    } else {
        Err(format!("{program} failed ({status}): {}", stderr.trim()))
    }
}

/// The demo's own container. Teardown acts on this id only after the run
/// label proves it is this invocation's container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedContainer {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) token: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Teardown {
    NotStarted,
    Completed,
    Kept,
    Failed(String),
}

impl Teardown {
    fn label(&self) -> String {
        match self {
            Self::NotStarted => "not started".to_owned(),
            Self::Completed => "completed".to_owned(),
            Self::Kept => "kept".to_owned(),
            Self::Failed(reason) => format!("failed({reason})"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Plan printed; nothing changed (no `--yes`, or `--dry-run`).
    Planned,
    /// The scripted session completed.
    Completed,
    /// A preflight check refused before any Docker change.
    Refused(String),
    /// Started, then failed (including an exceeded budget).
    Failed(String),
}

#[derive(Debug, Serialize)]
pub(crate) struct Step {
    pub(crate) step: &'static str,
    pub(crate) ok: bool,
    pub(crate) duration_ms: u64,
    pub(crate) detail: String,
}

#[derive(Debug)]
pub(crate) struct DemoReport {
    pub(crate) outcome: Outcome,
    pub(crate) container: Option<OwnedContainer>,
    pub(crate) transcript: Vec<String>,
    pub(crate) steps: Vec<Step>,
    pub(crate) teardown: Teardown,
}

impl DemoReport {
    fn line(&mut self, text: impl Into<String>) {
        self.transcript.push(text.into());
    }

    fn json(&self, port: u16) -> Value {
        let (outcome, reason) = match &self.outcome {
            Outcome::Planned => ("planned", None),
            Outcome::Completed => ("completed", None),
            Outcome::Refused(reason) => ("refused", Some(reason.clone())),
            Outcome::Failed(reason) => ("failed", Some(reason.clone())),
        };
        json!({
            "outcome": outcome,
            "reason": reason,
            "image": DEMO_IMAGE,
            "port": port,
            "container": self.container.as_ref().map(|c| c.name.clone()),
            "run_token": self.container.as_ref().map(|c| c.token.clone()),
            "transcript": self.transcript,
            "steps": self.steps,
            "teardown": self.teardown.label(),
        })
    }
}

/// Seed statements with the demo's fixed run id.
pub(crate) fn seed_statements() -> Vec<String> {
    SEED_SQL
        .split("-- @statement")
        .skip(1)
        .map(|statement| statement.trim().replace("&run_id", DEMO_RUN_ID))
        .filter(|statement| !statement.is_empty())
        .collect()
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::getrandom(&mut buffer).expect("operating-system randomness");
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A one-time Oracle password: letters and digits, starting with a letter.
fn one_time_password() -> String {
    format!("Dm{}", random_hex(12))
}

fn port_is_free(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

pub(crate) fn run(robot_json: bool, args: DemoCliArgs) -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            eprintln!("oraclemcp demo: cannot locate this binary: {error}");
            return ExitCode::from(2);
        }
    };
    let report = run_with(&args, &DockerCli, &exe);
    if robot_json {
        println!("{}", report.json(args.port));
    } else {
        for line in &report.transcript {
            println!("{line}");
        }
    }
    // 0: planned or completed with a clean teardown; 2: refused before any
    // Docker change; 1: a started demo failed or its teardown failed.
    match (&report.outcome, &report.teardown) {
        (Outcome::Refused(_), _) => ExitCode::from(2),
        (_, Teardown::Failed(_)) | (Outcome::Failed(_), _) => ExitCode::from(1),
        (Outcome::Planned | Outcome::Completed, _) => ExitCode::SUCCESS,
    }
}

/// Plan, then (only with `--yes` and without `--dry-run`) start, seed, play
/// the scripted session, and tear down.
pub(crate) fn run_with(args: &DemoCliArgs, docker: &dyn Docker, exe: &Path) -> DemoReport {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(args.timeout_secs);
    let mut report = DemoReport {
        outcome: Outcome::Planned,
        container: None,
        transcript: Vec::new(),
        steps: Vec::new(),
        teardown: Teardown::NotStarted,
    };
    report.line("oraclemcp demo: guarded writes on Oracle FREE 23ai");

    // Preflight: read-only Docker queries and a local port probe only. A
    // missing Docker refuses only a real start; the plan is still printed.
    let docker_error = docker
        .query(
            &["version", "--format", "{{.Server.Version}}"],
            DOCKER_CALL_TIMEOUT,
        )
        .err();
    let image_present = docker
        .query(
            &["image", "inspect", "--format", "{{.Id}}", DEMO_IMAGE],
            DOCKER_CALL_TIMEOUT,
        )
        .is_ok();
    let token = random_hex(6);
    let name = format!("oraclemcp-demo-{token}");
    let statements = seed_statements();
    report.line("plan:");
    report.line(format!(
        "  image      {DEMO_IMAGE} ({})",
        if image_present {
            "present locally"
        } else {
            "not present; docker pulls it on first start, about 2 GB"
        }
    ));
    report.line(format!(
        "  container  {name} (labels {DEMO_LABEL}=1, {RUN_LABEL}={token})"
    ));
    report.line(format!("  listener   127.0.0.1:{} -> 1521", args.port));
    report.line(format!("  limits     --cpus {CPUS} --memory {MEMORY} --memory-swap {MEMORY} --pids-limit {PIDS_LIMIT}"));
    report.line(format!(
        "  budget     {}s wall clock, including database start",
        args.timeout_secs
    ));
    report.line(format!(
        "  seed       {} statements (W4 fixture parent/child subset) as user {DEMO_USER}",
        statements.len()
    ));
    report.line("  session    refuse -> preview -> confirm -> rollback -> audit verify");
    if let Some(error) = &docker_error {
        report.line(format!("  docker     not available: {error}"));
    }
    report.line(format!(
        "  teardown   {}",
        if args.keep {
            "keep the container (--keep)"
        } else {
            "stop and remove this run's container only"
        }
    ));
    if !port_is_free(args.port) {
        let reason = format!(
            "port {} is in use on 127.0.0.1; pass --port <free port>",
            args.port
        );
        report.line(format!("refused: {reason}"));
        report.outcome = Outcome::Refused(reason);
        return report;
    }
    if args.dry_run {
        report.line("dry run: no Docker changes were made");
        return report;
    }
    if !args.yes {
        report.line("nothing started: re-run with --yes to start the demo container");
        return report;
    }
    if let Some(error) = docker_error {
        let reason = format!("docker is not available: {error}");
        report.line(format!("refused: {reason}"));
        report.outcome = Outcome::Refused(reason);
        return report;
    }

    let system_password = one_time_password();
    let app_password = one_time_password();
    let secrets = [system_password.clone(), app_password.clone()];
    let publish = format!("127.0.0.1:{}:1521", args.port);
    let run_label = format!("{RUN_LABEL}={token}");
    let demo_label = format!("{DEMO_LABEL}=1");
    let step_started = Instant::now();
    let created = docker.mutate(
        &[
            "run",
            "-d",
            "--name",
            &name,
            "--label",
            &demo_label,
            "--label",
            &run_label,
            "--cpus",
            CPUS,
            "--memory",
            MEMORY,
            "--memory-swap",
            MEMORY,
            "--pids-limit",
            PIDS_LIMIT,
            "-p",
            &publish,
            "-e",
            "ORACLE_PASSWORD",
            "-e",
            "APP_USER",
            "-e",
            "APP_USER_PASSWORD",
            DEMO_IMAGE,
        ],
        &[
            ("ORACLE_PASSWORD", &system_password),
            ("APP_USER", DEMO_USER),
            ("APP_USER_PASSWORD", &app_password),
        ],
        None,
        DOCKER_CALL_TIMEOUT.min(deadline.saturating_duration_since(Instant::now())),
    );
    let id = match created {
        Ok(output) => output.trim().to_owned(),
        Err(error) => {
            let reason = redact(
                &format!("cannot start the demo container: {error}"),
                &secrets,
            );
            report.line(format!("failed: {reason}"));
            report.outcome = Outcome::Failed(reason);
            return report;
        }
    };
    let container = OwnedContainer {
        id,
        name: name.clone(),
        token,
    };
    report.container = Some(container.clone());
    record(
        &mut report,
        "container",
        step_started,
        Ok(format!("started {name}")),
    );

    let session = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        play(
            &mut report,
            args,
            docker,
            exe,
            &container,
            &app_password,
            deadline,
        )
    }));
    let failure = match session {
        Ok(Ok(())) => None,
        Ok(Err(reason)) => Some(redact(&reason, &secrets)),
        Err(_) => Some("the demo session panicked".to_owned()),
    };
    report.teardown = if args.keep {
        Teardown::Kept
    } else {
        teardown(docker, &container)
    };
    match failure {
        Some(reason) => {
            report.line(format!("failed: {reason}"));
            report.outcome = Outcome::Failed(reason);
        }
        None => report.outcome = Outcome::Completed,
    }
    report.line(format!("teardown: {}", report.teardown.label()));
    if report.teardown == Teardown::Kept {
        report.line(format!(
            "kept: {name} on 127.0.0.1:{}; remove it with `docker stop {name} && docker container rm {name}`",
            args.port
        ));
    }
    report
}

fn record(
    report: &mut DemoReport,
    step: &'static str,
    started: Instant,
    result: Result<String, String>,
) {
    let (ok, detail) = match result {
        Ok(detail) => (true, detail),
        Err(detail) => (false, detail),
    };
    report.steps.push(Step {
        step,
        ok,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        detail,
    });
}

fn remaining(deadline: Instant, step: &str) -> Result<Duration, String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(format!("time budget exceeded during {step}"))
    } else {
        Ok(left)
    }
}

fn play(
    report: &mut DemoReport,
    args: &DemoCliArgs,
    docker: &dyn Docker,
    exe: &Path,
    container: &OwnedContainer,
    app_password: &str,
    deadline: Instant,
) -> Result<(), String> {
    let started = Instant::now();
    let ready = wait_ready(docker, container, deadline);
    record(
        report,
        "database_ready",
        started,
        ready.clone().map(|()| "listener and PDB ready".to_owned()),
    );
    ready?;
    report.line("[ok] database ready");

    let started = Instant::now();
    let seeded = seed(docker, container, app_password, deadline);
    record(
        report,
        "seed",
        started,
        seeded
            .clone()
            .map(|()| format!("{} statements", seed_statements().len())),
    );
    seeded?;
    report.line(format!(
        "[ok] seeded T_PARENT_{DEMO_RUN_ID} and T_CHILD_{DEMO_RUN_ID} as {DEMO_USER}"
    ));

    session(report, args, docker, exe, container, app_password, deadline)
}

fn wait_ready(
    docker: &dyn Docker,
    container: &OwnedContainer,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        let left = remaining(deadline, "database start")?;
        let call = DOCKER_CALL_TIMEOUT.min(left);
        if docker
            .query(&["logs", &container.id], call)
            .is_ok_and(|logs| logs.contains(READY_MARKER))
        {
            return Ok(());
        }
        let running = docker.query(
            &["inspect", "--format", "{{.State.Running}}", &container.id],
            call,
        )?;
        if running.trim() != "true" {
            return Err("the demo container stopped before the database was ready".to_owned());
        }
        std::thread::sleep(Duration::from_secs(2).min(left));
    }
}

fn sqlplus_script(app_password: &str, body: &str) -> String {
    format!(
        "whenever sqlerror exit failure\nset define off\nset feedback off\nset heading off\nset pagesize 0\n\
         connect {DEMO_USER}/\"{app_password}\"@//localhost:1521/FREEPDB1\n{body}exit\n"
    )
}

fn seed(
    docker: &dyn Docker,
    container: &OwnedContainer,
    app_password: &str,
    deadline: Instant,
) -> Result<(), String> {
    let body: String = seed_statements()
        .iter()
        .map(|statement| format!("{statement}\n/\n"))
        .collect();
    docker
        .mutate(
            &["exec", "-i", &container.id, "sqlplus", "-S", "/nolog"],
            &[],
            Some(&sqlplus_script(app_password, &body)),
            DOCKER_CALL_TIMEOUT.min(remaining(deadline, "seeding")?),
        )
        .map(|_| ())
        .map_err(|error| format!("seeding failed: {error}"))
}

/// Re-read the demo row with an independent session inside the container.
fn independent_reread(
    docker: &dyn Docker,
    container: &OwnedContainer,
    app_password: &str,
    deadline: Instant,
) -> Result<String, String> {
    docker
        .mutate(
            &["exec", "-i", &container.id, "sqlplus", "-S", "/nolog"],
            &[],
            Some(&sqlplus_script(app_password, &format!("{DEMO_REREAD};\n"))),
            DOCKER_CALL_TIMEOUT.min(remaining(deadline, "re-read")?),
        )
        .map(|output| output.trim().to_owned())
}

/// Remove this run's container only: the run label must carry our token.
/// Removal is then checked independently by label.
pub(crate) fn teardown(docker: &dyn Docker, container: &OwnedContainer) -> Teardown {
    let format = format!("{{{{index .Config.Labels \"{RUN_LABEL}\"}}}}");
    match docker.query(
        &["inspect", "--format", &format, &container.id],
        DOCKER_CALL_TIMEOUT,
    ) {
        Ok(label) if label.trim() == container.token => {}
        Ok(label) => {
            return Teardown::Failed(format!(
                "container {} carries run label {:?}, not this run's; left untouched",
                container.id,
                label.trim()
            ));
        }
        Err(error) => return Teardown::Failed(format!("cannot inspect {}: {error}", container.id)),
    }
    // Graceful stop, then remove: never a force-kill of anything.
    if let Err(error) = docker.mutate(
        &["stop", "-t", "10", &container.id],
        &[],
        None,
        DOCKER_CALL_TIMEOUT,
    ) {
        return Teardown::Failed(format!("cannot stop {}: {error}", container.name));
    }
    if let Err(error) = docker.mutate(
        &["container", "rm", &container.id],
        &[],
        None,
        DOCKER_CALL_TIMEOUT,
    ) {
        return Teardown::Failed(format!("cannot remove {}: {error}", container.name));
    }
    let filter = format!("label={RUN_LABEL}={}", container.token);
    match docker.query(
        &["ps", "-a", "-q", "--filter", &filter],
        DOCKER_CALL_TIMEOUT,
    ) {
        Ok(left) if left.trim().is_empty() => Teardown::Completed,
        Ok(left) => Teardown::Failed(format!("container still present: {}", left.trim())),
        Err(error) => Teardown::Failed(format!("cannot confirm removal: {error}")),
    }
}

fn redact(text: &str, secrets: &[String]) -> String {
    secrets.iter().fold(text.to_owned(), |text, secret| {
        text.replace(secret.as_str(), "<redacted>")
    })
}

struct DemoClient {
    child: Child,
    stdin: Option<ChildStdin>,
    replies: Receiver<Value>,
    /// Bounded tail of the server's stderr, reported if it exits early.
    stderr: std::sync::Arc<std::sync::Mutex<String>>,
    next_id: u64,
}

impl DemoClient {
    fn spawn(
        exe: &Path,
        config: &Path,
        home: &Path,
        audit_key: &str,
        password: &str,
    ) -> Result<Self, String> {
        let mut command = Command::new(exe);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("ORACLEMCP_") {
                command.env_remove(key);
            }
        }
        let mut child = command
            .args(["--json", "serve", "--allow-no-auth", "--profile", "demo"])
            .env("ORACLEMCP_CONFIG", config)
            .env(AUDIT_KEY_ENV, audit_key)
            .env(PASSWORD_ENV, password)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HOME", home)
            .env_remove("RUST_LOG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("cannot start the demo server: {error}"))?;
        let stdin = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .ok_or("demo server stdout is not piped")?;
        let (sender, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Ok(value) = serde_json::from_str::<Value>(&line)
                    && sender.send(value).is_err()
                {
                    break;
                }
            }
        });
        let stderr = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        if let Some(pipe) = child.stderr.take() {
            let sink = std::sync::Arc::clone(&stderr);
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines() {
                    let Ok(line) = line else { break };
                    let Ok(mut tail) = sink.lock() else { break };
                    tail.push_str(&line);
                    tail.push('\n');
                    if tail.len() > 8 * 1024 {
                        let cut = tail.len() - 4 * 1024;
                        let cut = (cut..tail.len())
                            .find(|&i| tail.is_char_boundary(i))
                            .unwrap_or(cut);
                        tail.drain(..cut);
                    }
                }
            });
        }
        Ok(Self {
            child,
            stdin,
            replies,
            stderr,
            next_id: 1,
        })
    }

    fn send(&mut self, frame: &Value) -> Result<(), String> {
        let stdin = self.stdin.as_mut().ok_or("demo server stdin is closed")?;
        writeln!(stdin, "{frame}")
            .and_then(|()| stdin.flush())
            .map_err(|error| format!("cannot write to the demo server: {error}"))
    }

    fn request(&mut self, method: &str, params: Value, deadline: Instant) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let timeout = remaining(deadline, method)?.min(Duration::from_secs(120));
        let until = Instant::now() + timeout;
        loop {
            match self
                .replies
                .recv_timeout(until.saturating_duration_since(Instant::now()))
            {
                Ok(reply) if reply.get("id").and_then(Value::as_u64) == Some(id) => {
                    return Ok(reply);
                }
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "`{method}` got no reply within {}s",
                        timeout.as_secs()
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    // Let the stderr reader catch up before reporting.
                    std::thread::sleep(Duration::from_millis(200));
                    let tail = self
                        .stderr
                        .lock()
                        .map(|tail| tail.trim().to_owned())
                        .unwrap_or_default();
                    return Err(format!("the demo server exited: {tail}"));
                }
            }
        }
    }

    fn tool(&mut self, name: &str, arguments: Value, deadline: Instant) -> Result<Value, String> {
        let reply = self.request(
            "tools/call",
            json!({"name": name, "arguments": arguments}),
            deadline,
        )?;
        let result = reply
            .get("result")
            .ok_or_else(|| format!("{name}: no result: {reply}"))?;
        Ok(json!({
            "is_error": result.get("isError").and_then(Value::as_bool).unwrap_or(false),
            "content": result.get("structuredContent").cloned().unwrap_or(Value::Null),
        }))
    }

    fn close(mut self) {
        drop(self.stdin.take());
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn demo_config(dir: &Path, port: u16) -> Result<(PathBuf, PathBuf), String> {
    let config = dir.join("demo-profiles.toml");
    let audit = dir.join("demo-audit.jsonl");
    let quoted = |path: &Path| serde_json::to_string(&path.to_string_lossy()).unwrap_or_default();
    let source = format!(
        "schema_version = 2\ndefault_profile = \"demo\"\n\n[audit]\npath = {audit}\nkey_id = \"demo\"\nkey_ref = \"env:{AUDIT_KEY_ENV}\"\n\n\
         [[profiles]]\nname = \"demo\"\nconnect_string = \"127.0.0.1:{port}/FREEPDB1\"\nusername = \"{DEMO_USER}\"\n\
         credential_ref = \"env:{PASSWORD_ENV}\"\nmax_level = \"READ_WRITE\"\ndefault_level = \"READ_ONLY\"\n",
        audit = quoted(&audit),
    );
    std::fs::write(&config, source)
        .map_err(|error| format!("cannot write the demo profile: {error}"))?;
    Ok((config, audit))
}

fn session(
    report: &mut DemoReport,
    args: &DemoCliArgs,
    docker: &dyn Docker,
    exe: &Path,
    container: &OwnedContainer,
    app_password: &str,
    deadline: Instant,
) -> Result<(), String> {
    let temp = tempfile::tempdir().map_err(|error| format!("cannot create a temp dir: {error}"))?;
    std::fs::create_dir_all(temp.path().join("state")).map_err(|error| error.to_string())?;
    let (config, audit) = demo_config(temp.path(), args.port)?;
    let audit_key = random_hex(32);
    let mut client = DemoClient::spawn(exe, &config, temp.path(), &audit_key, app_password)?;
    let outcome = (|| -> Result<(), String> {
        let started = Instant::now();
        let initialized = client.request(
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "oraclemcp-demo", "version": env!("CARGO_PKG_VERSION")}}),
            deadline,
        )?;
        let ready = initialized.get("result").is_some();
        record(
            report,
            "initialize",
            started,
            if ready {
                Ok("MCP session ready".to_owned())
            } else {
                Err(format!("initialize refused: {initialized}"))
            },
        );
        if !ready {
            return Err(format!("initialize refused: {initialized}"));
        }
        client.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;

        // 1. A write at READ_ONLY is refused before it reaches Oracle.
        let started = Instant::now();
        let refused = client.tool("oracle_execute", json!({"sql": DEMO_UPDATE}), deadline)?;
        let class = refused["content"]["error_class"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let result = if refused["is_error"] == true && class == "OPERATING_LEVEL_TOO_LOW" {
            Ok(format!("refused: {class}"))
        } else {
            Err(format!("expected OPERATING_LEVEL_TOO_LOW, got {refused}"))
        };
        record(report, "refuse", started, result.clone());
        result?;
        report.line(format!(
            "[1/5] refuse   oracle_execute UPDATE at READ_ONLY -> refused: {class}"
        ));

        // 2. Preview the elevation: a single-use confirmation token.
        let started = Instant::now();
        let preview = client.tool(
            "oracle_set_session_level",
            json!({"level": "READ_WRITE"}),
            deadline,
        )?;
        let token = preview["content"]["confirmation"]["confirm"]
            .as_str()
            .map(str::to_owned);
        let result = match (&token, preview["is_error"] == true) {
            (Some(_), false) => Ok("confirmation token issued".to_owned()),
            _ => Err(format!("preview returned no confirmation token: {preview}")),
        };
        record(report, "preview", started, result.clone());
        result?;
        report.line(
            "[2/5] preview  oracle_set_session_level READ_WRITE -> confirmation token issued",
        );

        // 3. Confirm it: a temporary, TTL-bounded READ_WRITE window.
        let started = Instant::now();
        let applied = client.tool(
            "oracle_set_session_level",
            json!({"level": "READ_WRITE", "execute": true, "confirm": token}),
            deadline,
        )?;
        let result = if applied["is_error"] == false && applied["content"]["changed"] == true {
            Ok("session level READ_WRITE".to_owned())
        } else {
            Err(format!("elevation was not applied: {applied}"))
        };
        record(report, "confirm", started, result.clone());
        result?;
        report.line("[3/5] confirm  session level READ_WRITE (temporary elevation)");

        // 4. The same DML now runs, and is rolled back by default.
        let started = Instant::now();
        let executed = client.tool("oracle_execute", json!({"sql": DEMO_UPDATE}), deadline)?;
        let content = &executed["content"];
        let rolled_back = executed["is_error"] == false
            && content["executed"] == true
            && content["committed"] == false
            && content["rolled_back"] == true
            && content["rows_affected"] == 1;
        let served = client.tool("oracle_query", json!({"sql": DEMO_REREAD}), deadline)?;
        let served_label = served["content"]["rows"][0]["LABEL"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let independent = independent_reread(docker, container, app_password, deadline)?;
        let result = if rolled_back && served_label == "parent-1" && independent == "parent-1" {
            Ok(
                "rows_affected=1, rolled back; re-read LABEL='parent-1' (server and independent)"
                    .to_owned(),
            )
        } else {
            Err(format!(
                "rollback not proven: execute={executed}, server re-read={served_label:?}, independent re-read={independent:?}"
            ))
        };
        record(report, "rollback", started, result.clone());
        result?;
        report.line("[4/5] rollback oracle_execute UPDATE -> rows_affected=1, rolled back (committed=false); re-read LABEL='parent-1' (server and independent)");
        Ok(())
    })();
    client.close();
    outcome?;

    // 5. The session's signed audit chain verifies.
    let started = Instant::now();
    let mut command = Command::new(exe);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("ORACLEMCP_") {
            command.env_remove(key);
        }
    }
    command
        .args(["--json", "audit", "verify"])
        .arg(&audit)
        .env("ORACLEMCP_CONFIG", &config)
        .env(AUDIT_KEY_ENV, &audit_key)
        .env("XDG_STATE_HOME", temp.path().join("state"))
        .env("HOME", temp.path());
    let verified = run_bounded(
        command,
        None,
        remaining(deadline, "audit verify")?.min(Duration::from_secs(60)),
    )
    .ok()
    .and_then(|output| serde_json::from_str::<Value>(&output).ok());
    let result = match &verified {
        Some(value) if value["ok"] == true => Ok("audit verify ok".to_owned()),
        other => Err(format!("audit verify did not pass: {other:?}")),
    };
    record(report, "audit_verify", started, result.clone());
    result?;
    report.line("[5/5] audit    audit verify -> ok");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records every Docker call. Any mutation fails unless explicitly allowed.
    struct MockDocker {
        allow_mutation: bool,
        run_label: String,
        calls: RefCell<Vec<(bool, Vec<String>)>>,
    }

    impl MockDocker {
        fn read_only() -> Self {
            Self {
                allow_mutation: false,
                run_label: String::new(),
                calls: RefCell::default(),
            }
        }
        fn mutations(&self) -> Vec<Vec<String>> {
            self.calls
                .borrow()
                .iter()
                .filter(|(mutating, _)| *mutating)
                .map(|(_, args)| args.clone())
                .collect()
        }
    }

    impl Docker for MockDocker {
        fn query(&self, args: &[&str], _timeout: Duration) -> Result<String, String> {
            self.calls
                .borrow_mut()
                .push((false, args.iter().map(|arg| (*arg).to_owned()).collect()));
            match args {
                ["version", ..] => Ok("27.0.0\n".to_owned()),
                ["image", "inspect", ..] => Ok("sha256:image\n".to_owned()),
                ["inspect", "--format", format, _] if format.contains(RUN_LABEL) => {
                    Ok(format!("{}\n", self.run_label))
                }
                ["ps", ..] => Ok(String::new()),
                other => Err(format!("unexpected query {other:?}")),
            }
        }
        fn mutate(
            &self,
            args: &[&str],
            _env: &[(&str, &str)],
            _stdin: Option<&str>,
            _timeout: Duration,
        ) -> Result<String, String> {
            self.calls
                .borrow_mut()
                .push((true, args.iter().map(|arg| (*arg).to_owned()).collect()));
            if self.allow_mutation {
                Ok(String::new())
            } else {
                Err(format!(
                    "mutating docker call refused in this test: {args:?}"
                ))
            }
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn args(yes: bool, dry_run: bool, port: u16) -> DemoCliArgs {
        DemoCliArgs {
            yes,
            dry_run,
            port,
            keep: false,
            timeout_secs: 600,
        }
    }

    #[test]
    fn dry_run_prints_plan_without_docker_calls() {
        let docker = MockDocker::read_only();
        let port = free_port();
        let report = run_with(&args(true, true, port), &docker, Path::new("/nonexistent"));
        assert_eq!(report.outcome, Outcome::Planned);
        assert_eq!(report.teardown, Teardown::NotStarted);
        assert!(docker.mutations().is_empty(), "{:?}", docker.mutations());
        let transcript = report.transcript.join("\n");
        for expected in [
            DEMO_IMAGE,
            "--cpus 2 --memory 4g",
            &format!("127.0.0.1:{port} -> 1521"),
            "600s wall clock",
            "6 statements",
            "dry run: no Docker changes were made",
        ] {
            assert!(
                transcript.contains(expected),
                "missing {expected:?} in\n{transcript}"
            );
        }
    }

    #[test]
    fn dry_run_without_docker_still_prints_the_plan() {
        struct NoDocker;
        impl Docker for NoDocker {
            fn query(&self, _args: &[&str], _timeout: Duration) -> Result<String, String> {
                Err("docker: command not found".to_owned())
            }
            fn mutate(
                &self,
                args: &[&str],
                _env: &[(&str, &str)],
                _stdin: Option<&str>,
                _timeout: Duration,
            ) -> Result<String, String> {
                panic!("no mutation without Docker: {args:?}")
            }
        }
        let port = free_port();
        let planned = run_with(
            &args(true, true, port),
            &NoDocker,
            Path::new("/nonexistent"),
        );
        assert_eq!(planned.outcome, Outcome::Planned);
        assert!(
            planned
                .transcript
                .iter()
                .any(|line| line.contains("docker     not available"))
        );
        let started = run_with(
            &args(true, false, port),
            &NoDocker,
            Path::new("/nonexistent"),
        );
        assert!(
            matches!(&started.outcome, Outcome::Refused(reason) if reason.contains("docker is not available")),
            "{:?}",
            started.outcome
        );
    }

    #[test]
    fn no_yes_performs_no_mutation() {
        let docker = MockDocker::read_only();
        let report = run_with(
            &args(false, false, free_port()),
            &docker,
            Path::new("/nonexistent"),
        );
        assert_eq!(report.outcome, Outcome::Planned);
        assert!(docker.mutations().is_empty());
        assert!(
            report
                .transcript
                .last()
                .unwrap()
                .contains("re-run with --yes")
        );
    }

    #[test]
    fn port_conflict_detected() {
        let occupied = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = occupied.local_addr().unwrap().port();
        let mut docker = MockDocker::read_only();
        docker.allow_mutation = true;
        let report = run_with(&args(true, false, port), &docker, Path::new("/nonexistent"));
        let Outcome::Refused(reason) = &report.outcome else {
            panic!("expected a port refusal, got {:?}", report.outcome);
        };
        assert!(
            reason.contains(&format!("port {port} is in use")) && reason.contains("--port"),
            "{reason}"
        );
        assert!(
            docker.mutations().is_empty(),
            "no docker run before the port check: {:?}",
            docker.mutations()
        );
    }

    #[test]
    fn teardown_only_removes_own_container() {
        let container = OwnedContainer {
            id: "abc123".into(),
            name: "oraclemcp-demo-t1".into(),
            token: "t1".into(),
        };
        let mut foreign = MockDocker::read_only();
        foreign.allow_mutation = true;
        foreign.run_label = "someone-else".into();
        assert!(
            matches!(teardown(&foreign, &container), Teardown::Failed(reason) if reason.contains("left untouched"))
        );
        assert!(
            foreign.mutations().is_empty(),
            "a foreign container is never removed"
        );

        let mut own = MockDocker::read_only();
        own.allow_mutation = true;
        own.run_label = "t1".into();
        assert_eq!(teardown(&own, &container), Teardown::Completed);
        assert_eq!(
            own.mutations(),
            [
                vec![
                    "stop".to_owned(),
                    "-t".to_owned(),
                    "10".to_owned(),
                    "abc123".to_owned()
                ],
                vec!["container".to_owned(), "rm".to_owned(), "abc123".to_owned()],
            ]
        );
        let checked = own.calls.borrow().iter().any(|(mutating, call)| {
            !mutating && call == &["ps", "-a", "-q", "--filter", "label=oraclemcp.demo.run=t1"]
        });
        assert!(checked, "removal is confirmed by label afterwards");
    }

    #[test]
    fn seed_matches_fixture_subset() {
        let fixture = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/e2e/w4/fixture/01_tables.sql"),
        )
        .unwrap();
        let fixture: Vec<String> = fixture
            .split("-- @statement")
            .map(|statement| statement.trim().to_owned())
            .collect();
        let creates: Vec<&str> = SEED_SQL
            .split("-- @statement")
            .skip(1)
            .map(str::trim)
            .filter(|statement| statement.starts_with("CREATE TABLE"))
            .collect();
        assert_eq!(creates.len(), 2);
        for create in creates {
            assert!(
                fixture.iter().any(|statement| statement == create),
                "seed DDL drifted from the W4 fixture:\n{create}"
            );
        }
    }

    #[test]
    fn image_pin_matches_ci() {
        let ci = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml"),
        )
        .unwrap();
        assert!(
            ci.contains(&format!("image: {DEMO_IMAGE}")),
            "demo image pin differs from CI's FREE 23ai pin"
        );
    }
}
