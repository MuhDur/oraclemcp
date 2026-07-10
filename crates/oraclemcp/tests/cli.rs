use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oraclemcp_config::{CONFIG_PATH_ENV, OperatingLevel, OracleMcpConfig};

fn temp_config(contents: &str) -> PathBuf {
    let dir = temp_dir("config");
    let path = dir.join("profiles.toml");
    fs::write(&path, contents).expect("write config");
    path
}

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "oraclemcp-cli-test-{}-{stamp}-{label}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn make_om_alias(dir: &std::path::Path) -> PathBuf {
    let target = PathBuf::from(env!("CARGO_BIN_EXE_oraclemcp"));
    #[cfg(windows)]
    {
        let alias = dir.join("om.exe");
        fs::copy(&target, &alias).expect("copy om.exe alias");
        alias
    }
    #[cfg(not(windows))]
    {
        let alias = dir.join("om");
        std::os::unix::fs::symlink(&target, &alias).expect("symlink om alias");
        alias
    }
}

fn wait_child_with_timeout(mut child: std::process::Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().expect("poll child").is_some() {
            return child.wait_with_output().expect("collect output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect killed output");
            panic!(
                "oraclemcp did not exit within {timeout:?}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_with_timeout(mut cmd: Command, timeout: Duration) -> Output {
    let child = cmd.spawn().expect("spawn oraclemcp");
    wait_child_with_timeout(child, timeout)
}

fn run_binary(args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    wait_with_timeout(cmd, Duration::from_secs(5))
}

fn spawn_healthz_stub() -> (u16, thread::JoinHandle<()>, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind healthz stub");
    let port = listener.local_addr().expect("stub addr").port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = Arc::clone(&shutdown);
    let handle = thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("nonblocking stub listener");
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        while !shutdown_flag.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response.as_bytes());
            }
            thread::sleep(Duration::from_millis(5));
        }
    });
    (port, handle, shutdown)
}

fn count_dashboard_ticket_files(dir: &std::path::Path) -> usize {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("pairing-"))
                .count()
        })
        .unwrap_or(0)
}

#[test]
fn serve_with_missing_explicit_profile_fails_fast() {
    let config = temp_config(
        r#"
        [[profiles]]
        name = "dev"
        connect_string = "localhost:1521/FREEPDB1"
        max_level = "READ_ONLY"
        default_level = "READ_ONLY"
        "#,
    );

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "serve", "--allow-no-auth", "--profile", "missing"])
        .env(oraclemcp_config::CONFIG_PATH_ENV, &config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = wait_with_timeout(cmd, Duration::from_secs(5));
    let _ = fs::remove_dir_all(config.parent().expect("temp config parent"));

    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "serve startup errors keep stdout empty"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf8");
    let value: serde_json::Value = serde_json::from_str(stderr.trim()).expect("structured error");
    assert_eq!(value["kind"], "error");
    assert_eq!(value["code"], "ORACLEMCP_CONFIG_INVALID");
    assert!(
        value["message"]
            .as_str()
            .expect("message")
            .contains("connection profile `missing` not found")
    );
}

#[test]
fn required_stdio_binary_rejects_tool_call_before_initialize() {
    let config = temp_config(
        r#"
        [[profiles]]
        name = "dev"
        connect_string = "127.0.0.1:1/FREEPDB1"
        credential_ref = "env:ORACLEMCP_MISSING_TEST_PASSWORD"
        max_level = "READ_ONLY"
        default_level = "READ_ONLY"
        "#,
    );
    let dir = temp_dir("stdio-auth-first-frame");
    let state = dir.join("state");
    let tools_dir = dir.join("tools.d");
    fs::create_dir_all(&tools_dir).expect("create empty tools dir");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args([
        "--json",
        "serve",
        "--stdio-token",
        "s3cr3t",
        "--profile",
        "dev",
    ])
    .env(CONFIG_PATH_ENV, &config)
    .env("XDG_STATE_HOME", &state)
    .env("HOME", &dir)
    .env("ORACLEMCP_TOOLS_DIR", &tools_dir)
    .env_remove("ORACLEMCP_MISSING_TEST_PASSWORD")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn authenticated stdio server");
    let first_frame = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "oracle_query",
            "arguments": { "sql": "SELECT 1 FROM dual" },
        },
    });
    {
        let mut stdin = child.stdin.take().expect("child stdin is piped");
        serde_json::to_writer(&mut stdin, &first_frame).expect("write first frame");
        stdin.write_all(b"\n").expect("terminate first frame");
    }

    let output = wait_child_with_timeout(child, Duration::from_secs(10));
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let reply: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one JSON-RPC reply");
    assert_eq!(reply["id"], serde_json::json!(7));
    assert_eq!(reply["error"]["code"], serde_json::json!(-32600));
    assert!(
        reply["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("initialize")),
        "first-frame tool call must be rejected at the lifecycle/auth gate: {reply}"
    );
    assert!(
        reply.get("result").is_none(),
        "the protected call must not reach tool dispatch: {reply}"
    );
}

#[test]
fn completions_subcommand_emits_supported_shells() {
    for (shell, marker) in [
        ("bash", "_oraclemcp()"),
        ("zsh", "#compdef oraclemcp"),
        ("fish", "complete -c oraclemcp"),
        ("powershell", "Register-ArgumentCompleter"),
    ] {
        let output = run_binary(&["completions", shell]);
        assert_eq!(output.status.code(), Some(0), "{shell}");
        assert!(
            output.stderr.is_empty(),
            "{shell} stderr should be empty: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("completion script is utf8");
        assert!(stdout.contains("oraclemcp"), "{shell}: {stdout}");
        assert!(stdout.contains(marker), "{shell}: {stdout}");
    }

    let dir = temp_dir("om-completions");
    let alias = make_om_alias(&dir);
    let mut cmd = Command::new(&alias);
    cmd.args(["completions", "bash"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stderr.is_empty(),
        "om completions stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("om completion script is utf8");
    assert!(stdout.contains("_om()"));
    assert!(!stdout.contains("_oraclemcp()"));
}

#[test]
fn dashboard_refuses_pairing_when_http_service_unreachable() {
    let dir = temp_dir("dashboard-no-service");
    let ticket_dir = dir.join("oraclemcp");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args([
        "--json",
        "dashboard",
        "--url",
        "http://127.0.0.1:1",
        "--no-open",
    ])
    .env("XDG_RUNTIME_DIR", &dir)
    .env("HOME", &dir)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(10));
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let err: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("dashboard stderr JSON");
    assert_eq!(err["kind"], "error");
    assert_eq!(err["code"], "ORACLEMCP_DASHBOARD_SERVICE_UNREACHABLE");
    assert_eq!(count_dashboard_ticket_files(&ticket_dir), 0);
}

#[test]
fn om_alias_argv0_aware_runs_dashboard_pairing() {
    let dir = temp_dir("om-alias");
    let alias = make_om_alias(&dir);
    let (port, handle, shutdown) = spawn_healthz_stub();
    let base_url = format!("http://127.0.0.1:{port}");

    let mut help_cmd = Command::new(&alias);
    help_cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let help_output = wait_with_timeout(help_cmd, Duration::from_secs(5));
    assert_eq!(help_output.status.code(), Some(2));
    assert!(help_output.stdout.is_empty());
    let help_stderr = String::from_utf8(help_output.stderr).expect("stderr is utf8");
    assert!(help_stderr.contains("Usage: om "));
    assert!(help_stderr.contains("`om serve`"));
    assert!(help_stderr.contains("`om doctor`"));
    assert!(help_stderr.contains("`om capabilities`"));
    assert!(!help_stderr.contains("Usage: oraclemcp"));

    let mut dashboard_cmd = Command::new(&alias);
    dashboard_cmd
        .args(["--json", "dashboard", "--url", &base_url, "--no-open"])
        .env("XDG_RUNTIME_DIR", &dir)
        .env("HOME", &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let dashboard_output = wait_with_timeout(dashboard_cmd, Duration::from_secs(10));
    shutdown.store(true, Ordering::Relaxed);
    let _ = handle.join();
    assert_eq!(dashboard_output.status.code(), Some(0));
    assert!(
        dashboard_output.stderr.is_empty(),
        "dashboard stderr should be empty: {}",
        String::from_utf8_lossy(&dashboard_output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&dashboard_output.stdout).expect("dashboard JSON");
    assert_eq!(value["kind"], "dashboard_pairing");
    assert_eq!(value["opened"], false);
    assert!(
        value["url"]
            .as_str()
            .expect("url string")
            .starts_with(&format!("{base_url}/dashboard/pair?ticket="))
    );
}

#[test]
fn doctor_zero_profile_is_non_ok_and_names_first_run_fix() {
    let dir = temp_dir("doctor-zero-profile");
    let config = dir.join("profiles.toml");
    fs::write(&config, "schema_version = 2\n").expect("write empty config");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "doctor"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HOME", &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stderr.is_empty(),
        "doctor stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let doctor_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor JSON");
    assert_eq!(doctor_json["ok"], serde_json::json!(false));
    assert_eq!(doctor_json["exit_code"], serde_json::json!(2));
    let connectivity = doctor_json["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["id"] == serde_json::json!(3))
        .expect("connectivity check");
    assert_eq!(connectivity["status"], serde_json::json!("fail"));
    let rendered = connectivity.to_string();
    assert!(rendered.contains("oraclemcp --json setup --write --profile db_ro"));
    assert!(rendered.contains("ORACLE_APP_PASSWORD"));
    assert!(rendered.contains("oraclemcp --json doctor --profile db_ro"));
}

#[test]
fn setup_write_round_trips_profiles_through_config_ops() {
    let dir = temp_dir("setup-write");
    let config = dir.join("profiles.toml");
    let state = dir.join("state");
    let tools_dir = dir.join("tools.d");
    fs::create_dir_all(&tools_dir).expect("create empty tools dir");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args([
        "--json",
        "setup",
        "--write",
        "--profile",
        "tenant_ro",
        "--credential-env",
        "APP_PASSWORD",
    ])
    .env(CONFIG_PATH_ENV, &config)
    .env("XDG_STATE_HOME", &state)
    .env("HOME", &dir)
    .env("ORACLEMCP_TOOLS_DIR", &tools_dir)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let output = wait_with_timeout(cmd, Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stderr.is_empty(),
        "setup --write stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("setup JSON is utf8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("setup JSON");
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["kind"], serde_json::json!("oraclemcp_setup"));
    assert!(value.get("profiles_toml").is_none());
    assert_eq!(value["write"]["source"], serde_json::json!("config_ops"));
    assert_eq!(
        value["write"]["target_path"],
        serde_json::json!(config.display().to_string())
    );
    assert_eq!(
        value["write"]["redaction"],
        serde_json::json!("profiles TOML and secret references are not echoed by setup --write")
    );
    assert!(
        value["write"]["outcome"]["rollback_id"]
            .as_str()
            .expect("rollback id")
            .starts_with("rollback-")
    );

    for forbidden in [
        "credential_ref =",
        "env:APP_PASSWORD",
        "dbhost.example.com",
        "APP_READONLY",
        "wallet_password_ref =",
    ] {
        assert!(
            !stdout.contains(forbidden),
            "setup --write JSON leaked raw draft material {forbidden}: {stdout}"
        );
    }

    let written = fs::read_to_string(&config).expect("profiles config written");
    assert!(written.contains("credential_ref = \"env:APP_PASSWORD\""));
    assert!(written.contains("connect_string = \"dbhost.example.com:1521/service_name\""));
    assert!(!written.contains("[profiles.oci]"));
    assert!(!written.contains("[profiles.drcp]"));
    assert!(!written.contains("[profiles.pool]"));
    assert!(!written.contains("[profiles.proxy_auth]"));
    assert!(!written.contains("[profiles.session_identity]"));
    assert!(!written.contains("[[profiles.app_context]]"));
    assert!(!written.contains("db_ddl"));

    let cfg = OracleMcpConfig::from_toml_str(&written).expect("written setup config parses");
    assert_eq!(cfg.default_profile.as_deref(), Some("tenant_ro"));
    let profile = cfg.profile("tenant_ro").expect("starter profile exists");
    assert_eq!(profile.max_level(), OperatingLevel::ReadOnly);
    assert_eq!(profile.default_level(), OperatingLevel::ReadOnly);
    assert!(!profile.protected());

    let mut serve = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    serve
        .args([
            "--json",
            "serve",
            "--allow-no-auth",
            "--profile",
            "tenant_ro",
        ])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &dir)
        .env("ORACLEMCP_TOOLS_DIR", &tools_dir)
        .env_remove("APP_PASSWORD")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let serve_output = wait_with_timeout(serve, Duration::from_secs(5));
    assert_eq!(serve_output.status.code(), Some(0));
    let serve_stderr = String::from_utf8(serve_output.stderr).expect("serve stderr is utf8");
    assert!(
        serve_stderr.contains("\"kind\":\"status\""),
        "serve must boot to status output: {serve_stderr}"
    );
    assert!(
        !serve_stderr.contains("ORACLEMCP_AUDIT_KEY_REQUIRED"),
        "minimal starter must not create a writable-profile audit gate: {serve_stderr}"
    );

    let mut doctor = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    doctor
        .args(["--json", "doctor", "--profile", "tenant_ro"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &dir)
        .env("ORACLEMCP_TOOLS_DIR", &tools_dir)
        .env_remove("APP_PASSWORD")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let doctor_output = wait_with_timeout(doctor, Duration::from_secs(5));
    assert_eq!(doctor_output.status.code(), Some(0));
    assert!(
        doctor_output.stderr.is_empty(),
        "doctor stderr should be empty: {}",
        String::from_utf8_lossy(&doctor_output.stderr)
    );
    let doctor_json: serde_json::Value =
        serde_json::from_slice(&doctor_output.stdout).expect("doctor JSON");
    assert_eq!(doctor_json["ok"], serde_json::json!(true));
    assert_eq!(doctor_json["exit_code"], serde_json::json!(0));
    assert_eq!(
        doctor_json["profile_caps"]["configured"]["max_level"],
        serde_json::json!("READ_ONLY")
    );

    let backup_path = value["write"]["outcome"]["apply"]["backup_path"]
        .as_str()
        .expect("backup path");
    assert!(PathBuf::from(backup_path).exists());
}

/// Field-test bead `.5`: on a fresh XDG-native box (XDG_CONFIG_HOME set, no
/// config anywhere yet, no ORACLEMCP_CONFIG), the default `setup --write`
/// target must land under `$XDG_CONFIG_HOME/oraclemcp/` — the same place
/// discovery now reads first.
#[test]
fn setup_write_default_target_honors_xdg_config_home() {
    let dir = temp_dir("setup-write-xdg");
    let xdg = dir.join("xdg");
    let state = dir.join("state");
    let expected = xdg.join("oraclemcp").join("profiles.toml");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "setup", "--write", "--profile", "tenant_ro"])
        .env_remove(CONFIG_PATH_ENV)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));
    assert_eq!(
        output.status.code(),
        Some(0),
        "setup --write under XDG_CONFIG_HOME failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("setup JSON parses");
    assert_eq!(
        value["write"]["target_path"],
        serde_json::json!(expected.display().to_string()),
        "default write target must follow XDG_CONFIG_HOME"
    );
    assert!(expected.is_file(), "profiles.toml written under XDG dir");
    assert!(
        !dir.join(".config").join("oraclemcp").exists(),
        "nothing must be written to the ~/.config fallback when XDG_CONFIG_HOME is set"
    );
}

/// The committed canonical TNS fixture tree (design spec §F), at the workspace
/// root `tests/fixtures/tns`.
fn tns_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("tns")
}

// ---- bead .4: consent model (never scan/write without consent) ----

#[test]
fn setup_discover_non_tty_without_consent_refuses_json() {
    let dir = temp_dir("discover-refuse-json");
    let config = dir.join("profiles.toml");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "setup", "--discover"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HOME", &dir)
        .env_remove("TNS_ADMIN")
        .env_remove("ORACLE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));

    assert_eq!(
        output.status.code(),
        Some(2),
        "a non-TTY refusal is a usage/safety block (exit 2)"
    );
    assert!(
        output.stdout.is_empty(),
        "a refusal writes nothing to stdout"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    let value: serde_json::Value =
        serde_json::from_str(stderr.trim()).expect("structured refusal on stderr");
    assert_eq!(value["kind"], serde_json::json!("error"));
    assert_eq!(
        value["code"],
        serde_json::json!("ORACLEMCP_DISCOVER_CONSENT_REQUIRED")
    );
    let message = value["message"].as_str().expect("refusal message");
    assert!(
        message.contains("refusing to scan for tnsnames.ora without consent"),
        "refusal names the safety block: {message}"
    );
    assert!(
        message.contains("--discover-tns"),
        "refusal names the exact consent flag: {message}"
    );
    assert!(!config.exists(), "a refusal creates no config file");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn setup_discover_non_tty_without_consent_refuses_human() {
    let dir = temp_dir("discover-refuse-human");
    let config = dir.join("profiles.toml");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["setup", "--discover"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HOME", &dir)
        .env_remove("TNS_ADMIN")
        .env_remove("ORACLE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert_eq!(
        stderr.trim(),
        "refusing to scan for tnsnames.ora without consent: re-run on an interactive terminal, or pass --discover-tns (or --yes) to consent explicitly (non-interactive).",
        "the human refusal is the exact spec §D sentence"
    );
    assert!(!config.exists());
    let _ = fs::remove_dir_all(&dir);
}

// bead .19: consent gates the SCAN itself, not just the write — a non-TTY
// caller with no consent flag is refused before any filesystem scan, even when
// a populated TNS_ADMIN is present, and leaves the target untouched.
#[test]
fn setup_discover_refuses_before_scanning_even_with_tns_admin_present() {
    let dir = temp_dir("discover-refuse-prescan");
    let config = dir.join("profiles.toml");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["setup", "--discover"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HOME", &dir)
        .env("TNS_ADMIN", tns_fixture_dir())
        .env_remove("ORACLE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(2), "refuses with exit 2");
    assert!(output.stdout.is_empty());
    assert!(
        !config.exists(),
        "a refusal writes nothing even with a populated TNS_ADMIN"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn setup_discover_dry_run_reports_net_services_and_writes_nothing() {
    let dir = temp_dir("discover-report");
    let config = dir.join("profiles.toml");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    // Explicit non-interactive scan consent + a fixture TNS_ADMIN + --dry-run.
    // The report enumerates the discovered net-services and the env vars to
    // export, and writes nothing.
    cmd.args([
        "--json",
        "setup",
        "--discover",
        "--discover-tns",
        "--dry-run",
    ])
    .env(CONFIG_PATH_ENV, &config)
    .env("XDG_STATE_HOME", dir.join("state"))
    .env("HOME", &dir)
    .env("TNS_ADMIN", tns_fixture_dir())
    .env_remove("ORACLE_HOME")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));

    assert_eq!(output.status.code(), Some(0), "consented scan proceeds");
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("discovery JSON");
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["kind"], serde_json::json!("oraclemcp_discover"));
    assert_eq!(value["dry_run"], serde_json::json!(true));
    assert_eq!(value["written"], serde_json::json!(false));
    assert_eq!(
        value["net_services"]
            .as_array()
            .expect("net services")
            .len(),
        4,
        "the primary fixture defines four effective aliases"
    );
    let profiles: Vec<&str> = value["profiles"]
        .as_array()
        .expect("profiles array")
        .iter()
        .map(|p| p["name"].as_str().expect("profile name"))
        .collect();
    assert!(profiles.contains(&"primary_tcps"));
    assert!(profiles.contains(&"ez_plain"));

    // Only env-var NAMES appear — never a secret value.
    let env_vars = value["env_vars"].as_array().expect("env vars array");
    let names: Vec<&str> = env_vars
        .iter()
        .map(|e| e["env_var"].as_str().expect("env var name"))
        .collect();
    assert!(names.contains(&"ORACLE_PRIMARY_TCPS_PASSWORD"));
    assert!(names.contains(&"ORACLE_PRIMARY_TCPS_WALLET_PASSWORD"));
    assert!(!config.exists(), "--dry-run writes nothing");
    let _ = fs::remove_dir_all(&dir);
}

// bead .16: a malformed tnsnames.ora degrades gracefully — the flow recovers
// what the reader can parse and STILL writes a valid, READ_ONLY config (config-
// ops re-parses via the strict loader before writing, so written=true proves it
// parsed) with no literal secret ref.
#[test]
fn setup_discover_over_malformed_tnsnames_writes_read_only_config() {
    let dir = temp_dir("discover-malformed");
    let config = dir.join("profiles.toml");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "setup", "--discover", "--discover-tns"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HOME", &dir)
        .env("TNS_ADMIN", tns_fixture_dir().join("malformed"))
        .env_remove("ORACLE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));
    assert_eq!(
        output.status.code(),
        Some(0),
        "malformed input still succeeds"
    );
    let value: serde_json::Value =
        serde_json::from_str(&String::from_utf8(output.stdout).expect("utf8")).expect("json");
    assert_eq!(
        value["written"],
        serde_json::json!(true),
        "the recovered config parsed via config-ops and was written"
    );
    let written = fs::read_to_string(&config).expect("config written");
    assert!(
        written.contains("max_level = \"READ_ONLY\""),
        "written profiles are capped READ_ONLY"
    );
    assert!(
        written.contains("default_level = \"READ_ONLY\""),
        "written profiles default to READ_ONLY"
    );
    assert!(
        !written.lines().any(|l| {
            let t = l.trim_start();
            !t.starts_with('#') && t.contains("literal:")
        }),
        "no literal secret ref is emitted"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ---- bead .10: setup --discover orchestration (write through config-ops) ----

#[test]
fn setup_discover_writes_discovered_profiles_through_config_ops() {
    let dir = temp_dir("discover-write");
    let config = dir.join("profiles.toml");
    let state = dir.join("state");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "setup", "--discover", "--discover-tns"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &dir)
        .env("TNS_ADMIN", tns_fixture_dir())
        .env_remove("ORACLE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("discovery JSON");
    assert_eq!(value["written"], serde_json::json!(true));
    assert_eq!(value["dry_run"], serde_json::json!(false));
    assert_eq!(value["write_mode"], serde_json::json!("fresh"));
    assert_eq!(
        value["target_path"],
        serde_json::json!(config.display().to_string())
    );
    assert!(
        value["backup_path"].as_str().is_some(),
        "config-ops wrote a timestamped backup"
    );
    let created: Vec<&str> = value["profiles_created"]
        .as_array()
        .expect("profiles_created")
        .iter()
        .map(|p| p.as_str().expect("name"))
        .collect();
    assert!(created.contains(&"primary_tcps"));
    assert!(created.contains(&"included_one"));

    // The spec §D success line is on stderr.
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("wrote 4 read-only profiles to")
            && stderr.contains("discovered 4 net-services"),
        "spec §D success line on stderr: {stderr}"
    );

    // The written config loads, parses, and every profile is READ_ONLY.
    let written = fs::read_to_string(&config).expect("config written");
    let cfg = OracleMcpConfig::from_toml_str(&written).expect("written config parses");
    assert_eq!(cfg.profiles.len(), 4);
    let profile = cfg.profile("primary_tcps").expect("primary_tcps profile");
    assert_eq!(profile.max_level(), OperatingLevel::ReadOnly);
    assert_eq!(profile.default_level(), OperatingLevel::ReadOnly);
    // No secret value is echoed in the JSON — only env-var names.
    assert!(!stdout.contains("credential_ref = "));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn setup_discover_zero_found_falls_back_to_minimal_starter() {
    let dir = temp_dir("discover-fallback");
    let config = dir.join("profiles.toml");
    let state = dir.join("state");
    // An empty TNS_ADMIN directory: no tnsnames.ora anywhere reachable.
    let empty_tns = dir.join("empty-tns");
    fs::create_dir_all(&empty_tns).expect("create empty tns dir");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "setup", "--discover", "--yes"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &empty_tns)
        .env("TNS_ADMIN", &empty_tns)
        .env_remove("ORACLE_HOME")
        .current_dir(&empty_tns)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("discovery JSON");
    assert_eq!(
        value["net_services"]
            .as_array()
            .expect("net services")
            .len(),
        0
    );
    assert_eq!(value["fallback_minimal_starter"], serde_json::json!(true));
    assert_eq!(value["written"], serde_json::json!(true));

    let written = fs::read_to_string(&config).expect("starter written");
    let cfg = OracleMcpConfig::from_toml_str(&written).expect("starter parses");
    assert_eq!(cfg.default_profile.as_deref(), Some("db_ro"));
    let _ = fs::remove_dir_all(&dir);
}

// ---- bead .11: idempotent, non-destructive merge and backup ----

/// Run `setup --discover --discover-tns` (non-interactive consent) against the
/// canonical fixture, returning the parsed JSON report.
fn run_discover_write(dir: &std::path::Path, config: &std::path::Path) -> serde_json::Value {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "setup", "--discover", "--discover-tns"])
        .env(CONFIG_PATH_ENV, config)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HOME", dir)
        .env("TNS_ADMIN", tns_fixture_dir())
        .env_remove("ORACLE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));
    assert_eq!(
        output.status.code(),
        Some(0),
        "discover write stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("discovery JSON")
}

#[test]
fn setup_discover_second_run_is_a_noop() {
    let dir = temp_dir("discover-idempotent");
    let config = dir.join("profiles.toml");

    let first = run_discover_write(&dir, &config);
    assert_eq!(first["written"], serde_json::json!(true));
    let after_first = fs::read(&config).expect("config after first run");

    let second = run_discover_write(&dir, &config);
    assert_eq!(
        second["written"],
        serde_json::json!(false),
        "a second identical run writes nothing"
    );
    assert!(
        second["profiles_created"]
            .as_array()
            .expect("profiles_created")
            .is_empty(),
        "nothing new on the second run"
    );
    let after_second = fs::read(&config).expect("config after second run");
    assert_eq!(
        after_first, after_second,
        "the config is byte-identical after an idempotent re-run"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn setup_discover_merge_adds_only_new_and_preserves_existing() {
    let dir = temp_dir("discover-merge");
    let config = dir.join("profiles.toml");
    // Pre-seed a config with a hand-edited profile plus one profile whose name
    // collides with a discovered net-service (primary_tcps) — both must be left
    // byte-untouched.
    let seed = r#"schema_version = 2
default_profile = "hand_edited"

# operator-authored note that must survive the merge verbatim
[[profiles]]
name = "hand_edited"
description = "my own profile"
connect_string = "myhost:1521/MY"
credential_ref = "env:MY_PW"
max_level = "READ_ONLY"
default_level = "READ_ONLY"

[[profiles]]
name = "primary_tcps"
description = "pre-existing, must not be overwritten"
connect_string = "custom-do-not-touch"
credential_ref = "env:CUSTOM_PW"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
"#;
    fs::write(&config, seed).expect("seed config");

    let value = run_discover_write(&dir, &config);
    assert_eq!(value["written"], serde_json::json!(true));
    assert_eq!(value["write_mode"], serde_json::json!("add_only_merge"));

    let skipped: Vec<&str> = value["profiles_skipped_already_configured"]
        .as_array()
        .expect("skipped array")
        .iter()
        .map(|p| p.as_str().expect("name"))
        .collect();
    assert!(
        skipped.contains(&"primary_tcps"),
        "the colliding name is reported skipped: {skipped:?}"
    );
    let created: Vec<&str> = value["profiles_created"]
        .as_array()
        .expect("created array")
        .iter()
        .map(|p| p.as_str().expect("name"))
        .collect();
    assert!(created.contains(&"ez_plain"));
    assert!(created.contains(&"included_one"));
    assert!(
        !created.contains(&"primary_tcps"),
        "the pre-existing profile is never re-created"
    );

    let written = fs::read_to_string(&config).expect("config re-read");
    assert!(
        written.contains("# operator-authored note that must survive the merge verbatim"),
        "the operator comment is preserved"
    );
    assert!(
        written.contains("connect_string = \"custom-do-not-touch\""),
        "the pre-existing primary_tcps is not overwritten"
    );

    let cfg = OracleMcpConfig::from_toml_str(&written).expect("merged config parses");
    assert_eq!(cfg.default_profile.as_deref(), Some("hand_edited"));
    // hand_edited + primary_tcps + ez_plain + dup_alias + included_one.
    assert_eq!(cfg.profiles.len(), 5);
    assert_eq!(
        cfg.profile("primary_tcps")
            .expect("primary_tcps")
            .connect_string
            .as_deref(),
        Some("custom-do-not-touch")
    );

    // A backup of the pre-existing bytes was captured on the mutating write.
    let backup_path = value["backup_path"].as_str().expect("backup path");
    assert!(PathBuf::from(backup_path).exists());
    let backup = fs::read_to_string(backup_path).expect("backup readable");
    assert!(
        backup.contains("custom-do-not-touch"),
        "the backup holds the pre-existing bytes verbatim"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn setup_discover_refuses_over_an_invalid_existing_config() {
    let dir = temp_dir("discover-invalid-existing");
    let config = dir.join("profiles.toml");
    let invalid = "this is = = not valid toml [[[\n";
    fs::write(&config, invalid).expect("seed invalid config");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "setup", "--discover", "--discover-tns"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HOME", &dir)
        .env("TNS_ADMIN", tns_fixture_dir())
        .env_remove("ORACLE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));

    assert_eq!(
        output.status.code(),
        Some(2),
        "an invalid target is rejected"
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("not valid"),
        "the error names the cause: {stderr}"
    );
    // Nothing was written: the invalid file is unchanged.
    assert_eq!(
        fs::read_to_string(&config).expect("config still present"),
        invalid,
        "a rejected run never mutates the target"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ---- bead .13: agent / non-TTY structured JSON path + CLI contract ----

#[test]
fn setup_discover_yes_json_is_a_complete_agent_report() {
    let dir = temp_dir("discover-agent-json");
    let config = dir.join("profiles.toml");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "setup", "--discover", "--yes"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HOME", &dir)
        .env("TNS_ADMIN", tns_fixture_dir())
        .env_remove("ORACLE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("agent JSON");

    // Every field an agent needs is present.
    for key in [
        "searched_directories",
        "net_services",
        "profiles",
        "profiles_created",
        "profiles_skipped_already_configured",
        "env_vars",
        "target_path",
        "backup_path",
        "written",
        "next_actions",
    ] {
        assert!(value.get(key).is_some(), "missing agent JSON key {key}");
    }
    assert_eq!(value["written"], serde_json::json!(true));
    assert_eq!(
        value["target_path"],
        serde_json::json!(config.display().to_string())
    );
    assert!(value["backup_path"].as_str().is_some());

    // Per-profile connect-string STRATEGY is reported (not the raw string).
    let profile0 = &value["profiles"][0];
    assert!(
        profile0["connect_string_strategy"].as_str().is_some(),
        "connect_string strategy per profile: {profile0}"
    );
    assert!(profile0["password_env_var"].as_str().is_some());

    // next_actions is ordered: env vars first, then doctor, then doctor --online.
    let actions: Vec<&str> = value["next_actions"]
        .as_array()
        .expect("next_actions")
        .iter()
        .map(|a| a.as_str().expect("action string"))
        .collect();
    let doctor_idx = actions
        .iter()
        .position(|a| *a == "oraclemcp doctor")
        .expect("offline doctor action");
    let online_idx = actions
        .iter()
        .position(|a| a.starts_with("oraclemcp doctor --online --profile "))
        .expect("online doctor action");
    assert!(
        actions[..doctor_idx]
            .iter()
            .any(|a| a.starts_with("export ")),
        "env-var exports come first: {actions:?}"
    );
    assert!(doctor_idx < online_idx, "doctor before doctor --online");

    // NAMES ONLY: no secret values, and no raw draft TOML echoed.
    for forbidden in [
        "credential_ref =",
        "connect_string =",
        "literal:",
        "[[profiles]]",
    ] {
        assert!(
            !stdout.contains(forbidden),
            "agent JSON leaked raw draft material {forbidden}: {stdout}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_contract_advertises_setup_discover_under_dangerous_operations() {
    let output = run_binary(&["--json", "robot-docs", "guide"]);
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("robot-docs guide JSON");
    let dangerous = value["cli_contract"]["dangerous_operations"]
        .as_array()
        .expect("dangerous_operations array");
    let discover = dangerous
        .iter()
        .find(|op| op["command"] == serde_json::json!("oraclemcp setup --discover"))
        .expect("setup --discover is advertised as a dangerous operation");
    // safe_preview is the --dry-run form; execute_gate names the consent flags.
    let safe_preview: Vec<&str> = discover["safe_preview"]
        .as_array()
        .expect("safe_preview array")
        .iter()
        .map(|p| p.as_str().expect("arg"))
        .collect();
    assert!(safe_preview.contains(&"--dry-run"));
    assert!(safe_preview.contains(&"--discover"));
    let gate = discover["execute_gate"].as_str().expect("execute_gate");
    assert!(gate.contains("--discover-tns") || gate.contains("--yes"));
    assert!(gate.contains("exits 2") || gate.contains("exit 2"));
}

// ---- bead .14: doctor validation of the discovered config ----

#[test]
fn doctor_offline_on_discovered_config_hints_missing_credentials() {
    let dir = temp_dir("doctor-discovered");
    let config = dir.join("profiles.toml");
    let state = dir.join("state");

    // Discover a fresh config from the fixture.
    let mut discover = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    discover
        .args(["setup", "--discover", "--yes"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &dir)
        .env("TNS_ADMIN", tns_fixture_dir())
        .env_remove("ORACLE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    assert_eq!(
        wait_with_timeout(discover, Duration::from_secs(5))
            .status
            .code(),
        Some(0)
    );

    // Offline doctor on the discovered config, credential env var unset.
    let mut doctor = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    doctor
        .args(["--json", "doctor", "--profile", "primary_tcps"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &dir)
        .env("TNS_ADMIN", tns_fixture_dir())
        .env_remove("ORACLE_PRIMARY_TCPS_PASSWORD")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(doctor, Duration::from_secs(5));

    // Offline doctor on a freshly discovered config is not a blocker.
    assert_eq!(output.status.code(), Some(0), "offline doctor exits 0");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    assert_eq!(json["ok"], serde_json::json!(true));
    assert_eq!(json["exit_code"], serde_json::json!(0));

    let checks = json["checks"].as_array().expect("checks");
    // TNS_ADMIN is reported when set: the TNS/wallet check passes.
    let tns = checks
        .iter()
        .find(|c| c["id"] == serde_json::json!(2))
        .expect("tns check");
    assert_eq!(tns["status"], serde_json::json!("pass"));

    // The connectivity check is a non-blocking needs-verification skip whose fix
    // names the exact per-profile credential env var and the online command.
    let conn = checks
        .iter()
        .find(|c| c["id"] == serde_json::json!(3))
        .expect("connectivity check");
    assert_eq!(conn["status"], serde_json::json!("skip"));
    let fix = conn["fix"].as_str().expect("credential hint fix");
    assert!(
        fix.contains("ORACLE_PRIMARY_TCPS_PASSWORD"),
        "hint names the exact env var: {fix}"
    );
    assert!(
        fix.contains("oraclemcp doctor --online --profile primary_tcps"),
        "hint names the verify command: {fix}"
    );

    // The unverifiable profile remains READ_ONLY (fail closed).
    assert_eq!(
        json["profile_caps"]["configured"]["max_level"],
        serde_json::json!("READ_ONLY")
    );

    // No secret value is printed anywhere.
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(!stdout.contains("literal:"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn doctor_no_profiles_guidance_advertises_setup_discover() {
    let dir = temp_dir("doctor-guidance");
    let config = dir.join("profiles.toml");
    fs::write(&config, "schema_version = 2\n").expect("write empty config");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "doctor"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HOME", &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    let conn = json["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|c| c["id"] == serde_json::json!(3))
        .expect("connectivity check");
    let rendered = conn.to_string();
    assert!(
        rendered.contains("oraclemcp setup --discover"),
        "the no-profiles guidance advertises the discovery fast path: {rendered}"
    );
    // The existing setup --write path is still offered.
    assert!(rendered.contains("setup --write"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn setup_generated_client_snippet_launches_serve_as_written() {
    let dir = temp_dir("setup-snippet-launch");
    let config = dir.join("profiles.toml");
    let state = dir.join("state");
    let tools_dir = dir.join("tools.d");
    fs::create_dir_all(&tools_dir).expect("create empty tools dir");
    fs::write(
        &config,
        r#"
schema_version = 2
default_profile = "tenant_ro"

[[profiles]]
name = "tenant_ro"
connect_string = "dbhost.example.com:1521/service_name"
username = "APP_READONLY"
credential_ref = "env:APP_PASSWORD"
"#,
    )
    .expect("write starter config");

    let mut setup = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    setup
        .args([
            "--json",
            "setup",
            "--profile",
            "tenant_ro",
            "--wrapper-path",
            env!("CARGO_BIN_EXE_oraclemcp"),
            "--config-path",
        ])
        .arg(&config)
        .arg("--tools-dir")
        .arg(&tools_dir)
        .env("HOME", &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let setup_output = wait_with_timeout(setup, Duration::from_secs(5));
    assert_eq!(setup_output.status.code(), Some(0));
    assert!(
        setup_output.stderr.is_empty(),
        "setup stderr should be empty: {}",
        String::from_utf8_lossy(&setup_output.stderr)
    );
    let setup_json: serde_json::Value =
        serde_json::from_slice(&setup_output.stdout).expect("setup JSON");
    let server = &setup_json["claude_mcp_json"]["mcpServers"]["oracle"];
    let command = server["command"].as_str().expect("snippet command");
    assert!(
        std::path::Path::new(command).is_absolute(),
        "snippet command must be absolute: {command}"
    );
    assert!(!command.contains('~'), "snippet command must not contain ~");
    let args = server["args"].as_array().expect("snippet args");
    assert_eq!(args[0], serde_json::json!("serve"));
    assert!(
        args.windows(2).any(|window| window
            == [
                serde_json::json!("--profile"),
                serde_json::json!("tenant_ro")
            ]),
        "snippet args must include --profile tenant_ro: {args:?}"
    );
    assert!(
        setup_json["codex_config_toml"]
            .as_str()
            .expect("codex config")
            .contains("--profile")
    );
    for client_surface in [
        setup_json["claude_mcp_json"].to_string(),
        setup_json["codex_config_toml"]
            .as_str()
            .expect("codex config")
            .to_owned(),
        setup_json["paths"].to_string(),
    ] {
        assert!(
            !client_surface.contains("~/"),
            "generated client/path surface must not contain unexpanded tilde paths: {client_surface}"
        );
    }

    let mut serve = Command::new(command);
    for arg in args {
        serve.arg(arg.as_str().expect("arg string"));
    }
    serve
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &dir)
        .env("ORACLEMCP_TOOLS_DIR", &tools_dir)
        .env_remove("APP_PASSWORD")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let serve_output = wait_with_timeout(serve, Duration::from_secs(5));
    assert_eq!(serve_output.status.code(), Some(0));
    let serve_stderr = String::from_utf8(serve_output.stderr).expect("serve stderr is utf8");
    assert!(
        serve_stderr.contains("stdio transport ready"),
        "serve must boot from generated snippet: {serve_stderr}"
    );
}

/// Field-test bead `.3`: the default (no `--wrapper-path`) snippet command must
/// be the resolved real binary — the same resolution install.sh's
/// `print_client_snippet` performs — never the historical
/// `~/.local/bin/oraclemcp-local` wrapper that nothing creates.
#[test]
fn setup_default_snippet_command_is_the_resolved_binary() {
    let dir = temp_dir("setup-default-snippet");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(["--json", "setup", "--profile", "tenant_ro"])
        .env("HOME", &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("setup JSON is utf8");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("setup JSON");
    let command = value["claude_mcp_json"]["mcpServers"]["oracle"]["command"]
        .as_str()
        .expect("snippet command");
    let resolved = fs::canonicalize(command).expect("snippet command must be an existing binary");
    let expected = fs::canonicalize(env!("CARGO_BIN_EXE_oraclemcp")).expect("test binary resolves");
    assert_eq!(
        resolved, expected,
        "default snippet command must be the resolved running binary"
    );
    assert!(
        value["codex_config_toml"]
            .as_str()
            .expect("codex config")
            .contains(&format!("command = '{command}'")),
        "Codex TOML must use the same command as the Claude JSON snippet"
    );
    assert!(
        !stdout.contains("oraclemcp-local"),
        "default setup output must never advertise the uncreated wrapper path: {stdout}"
    );
    assert_eq!(value["paths"]["wrapper"], serde_json::Value::Null);
}

/// Field-test bead `.3`, explicit flow: `--wrapper-path` still produces
/// wrapper-command snippets, but only with a clear "create this wrapper first"
/// statement — setup never writes the wrapper itself.
#[test]
fn setup_explicit_wrapper_path_snippets_state_wrapper_must_exist() {
    let dir = temp_dir("setup-wrapper-snippet");
    let wrapper = dir.join("bin").join("oraclemcp-wrapped");
    let wrapper_str = wrapper.display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args([
        "--json",
        "setup",
        "--profile",
        "tenant_ro",
        "--wrapper-path",
    ])
    .arg(&wrapper)
    .env("HOME", &dir)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let output = wait_with_timeout(cmd, Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("setup JSON parses");
    assert_eq!(
        value["claude_mcp_json"]["mcpServers"]["oracle"]["command"],
        serde_json::json!(wrapper_str)
    );
    assert!(
        value["codex_config_toml"]
            .as_str()
            .expect("codex config")
            .contains(&format!("command = '{wrapper_str}'")),
        "Codex TOML must use the explicit wrapper path too"
    );
    assert_eq!(value["paths"]["wrapper"], serde_json::json!(wrapper_str));
    assert!(
        value["snippet_command"]["source"]
            .as_str()
            .expect("snippet command source")
            .contains("the wrapper must exist"),
        "explicit wrapper flow must state the wrapper has to exist first"
    );
    let next_actions = value["next_actions"].to_string();
    assert!(
        next_actions.contains("create the wrapper first"),
        "next_actions must lead with creating the wrapper: {next_actions}"
    );

    // Human-readable mode carries the same warning.
    let mut human = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    human
        .args(["setup", "--profile", "tenant_ro", "--wrapper-path"])
        .arg(&wrapper)
        .env("HOME", &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let human_output = wait_with_timeout(human, Duration::from_secs(5));
    assert_eq!(human_output.status.code(), Some(0));
    let human_stdout = String::from_utf8(human_output.stdout).expect("setup text is utf8");
    assert!(
        human_stdout.contains("create this wrapper first"),
        "human setup output must warn the wrapper is not created automatically: {human_stdout}"
    );
}

/// TNS-onboarding bead `.9` boot check: a config rendered by the annotated
/// discovery writer must boot — `serve` loads it without a config error and
/// `doctor` (offline) reports no config blocker.
#[test]
fn discovery_annotated_config_boots() {
    use oraclemcp_config::discovery::render_annotated_config;
    use oraclemcp_config::discovery::synth::{
        DiscoveredNetService, SynthOptions, synthesize_profiles,
    };

    // A single discovered net-service so default_profile is set unambiguously.
    let synth = synthesize_profiles(
        &[DiscoveredNetService::new("SALES_RO")],
        &SynthOptions::default(),
    );
    let rendered = render_annotated_config(&synth);
    // Sanity: the writer chose sales_ro as the default.
    assert!(rendered.contains("default_profile = \"sales_ro\""));

    let dir = temp_dir("discovery-boot");
    let config = dir.join("profiles.toml");
    let state = dir.join("state");
    let tools_dir = dir.join("tools.d");
    fs::create_dir_all(&tools_dir).expect("create empty tools dir");
    fs::write(&config, &rendered).expect("write rendered config");

    // The rendered config loads through the same strict loader the binary uses.
    let cfg = OracleMcpConfig::from_toml_str(&rendered).expect("rendered config parses");
    assert_eq!(cfg.default_profile.as_deref(), Some("sales_ro"));
    assert_eq!(
        cfg.profile("sales_ro").expect("profile").max_level(),
        OperatingLevel::ReadOnly
    );

    // serve boots to status output without a config error and without creating a
    // writable-profile audit gate (every profile is READ_ONLY).
    let mut serve = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    serve
        .args([
            "--json",
            "serve",
            "--allow-no-auth",
            "--profile",
            "sales_ro",
        ])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &dir)
        .env("ORACLEMCP_TOOLS_DIR", &tools_dir)
        .env_remove("ORACLE_SALES_RO_PASSWORD")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let serve_output = wait_with_timeout(serve, Duration::from_secs(5));
    assert_eq!(
        serve_output.status.code(),
        Some(0),
        "serve should boot cleanly against the discovery-rendered config"
    );
    let serve_stderr = String::from_utf8(serve_output.stderr).expect("serve stderr is utf8");
    assert!(
        serve_stderr.contains("\"kind\":\"status\""),
        "serve must boot to status output: {serve_stderr}"
    );
    assert!(
        !serve_stderr.contains("ORACLEMCP_CONFIG_INVALID"),
        "the rendered config must not be a config-load blocker: {serve_stderr}"
    );
    assert!(
        !serve_stderr.contains("ORACLEMCP_AUDIT_KEY_REQUIRED"),
        "a READ_ONLY discovery config must not create an audit-key gate: {serve_stderr}"
    );

    // doctor (offline) reports no config blocker for the profile.
    let mut doctor = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    doctor
        .args(["--json", "doctor", "--profile", "sales_ro"])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &dir)
        .env("ORACLEMCP_TOOLS_DIR", &tools_dir)
        .env_remove("ORACLE_SALES_RO_PASSWORD")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let doctor_output = wait_with_timeout(doctor, Duration::from_secs(5));
    assert_eq!(doctor_output.status.code(), Some(0), "offline doctor is ok");
    let doctor_json: serde_json::Value =
        serde_json::from_slice(&doctor_output.stdout).expect("doctor JSON");
    assert_eq!(doctor_json["ok"], serde_json::json!(true));
    assert_eq!(
        doctor_json["profile_caps"]["configured"]["max_level"],
        serde_json::json!("READ_ONLY")
    );

    let _ = fs::remove_dir_all(&dir);
}
