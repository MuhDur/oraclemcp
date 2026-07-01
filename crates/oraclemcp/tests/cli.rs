use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oraclemcp_config::{CONFIG_PATH_ENV, OracleMcpConfig};

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

fn wait_with_timeout(mut cmd: Command, timeout: Duration) -> Output {
    let mut child = cmd.spawn().expect("spawn oraclemcp");
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

fn run_binary(args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    wait_with_timeout(cmd, Duration::from_secs(5))
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
fn om_alias_argv0_aware_runs_dashboard_pairing() {
    let dir = temp_dir("om-alias");
    let alias = make_om_alias(&dir);

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
        .args([
            "--json",
            "dashboard",
            "--url",
            "http://127.0.0.1:7777",
            "--no-open",
        ])
        .env("XDG_RUNTIME_DIR", &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let dashboard_output = wait_with_timeout(dashboard_cmd, Duration::from_secs(5));
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
            .starts_with("http://127.0.0.1:7777/dashboard/pair?ticket=")
    );
}

#[test]
fn setup_write_round_trips_profiles_through_config_ops() {
    let dir = temp_dir("setup-write");
    let config = dir.join("profiles.toml");
    let state = dir.join("state");

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
    assert!(written.contains("[profiles.drcp]"));
    OracleMcpConfig::from_toml_str(&written).expect("written setup config parses");

    let backup_path = value["write"]["outcome"]["apply"]["backup_path"]
        .as_str()
        .expect("backup path");
    assert!(PathBuf::from(backup_path).exists());
}
