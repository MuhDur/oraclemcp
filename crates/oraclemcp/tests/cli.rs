use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn temp_config(contents: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("oraclemcp-cli-test-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("profiles.toml");
    fs::write(&path, contents).expect("write config");
    path
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
