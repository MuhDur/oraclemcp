use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

const PASSWORD_CANARY: &str = "doctor_verbose_password_canary";
const TOKEN_CANARY: &str = "doctor_verbose_token_canary";
const OCID_CANARY: &str = "ocid1.doctorcanary.synthetic";
const DSN_CANARY: &str = "doctor_verbose_dsn_canary";

fn closed_loopback_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a local TCP port");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    port
}

fn doctor_profile(port: u16) -> String {
    format!(
        "schema_version = 2\n\n[[profiles]]\nname = \"verbose_canary\"\nconnect_string = \"127.0.0.1:{port}/{DSN_CANARY}\"\nusername = \"doctor_user_canary\"\ncredential_ref = \"env:LAB_DOCTOR_PASSWORD_CANARY\"\noci = {{ wallet_password_ref = \"env:LAB_DOCTOR_TOKEN_CANARY\", wallet_location = \"/synthetic/{OCID_CANARY}/wallet\" }}\n"
    )
}

fn connectivity(report: &Value) -> &Value {
    report["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|check| check["name"] == "Connectivity"))
        .expect("doctor JSON has a Connectivity check")
}

#[test]
fn verbose_detail_redacts_password_token_ocid_dsn_canaries() {
    let port = closed_loopback_port();
    let config_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/e2e/doctor-verbose-redaction");
    std::fs::create_dir_all(&config_dir).expect("create ignored doctor test evidence directory");
    let config = config_dir.join(format!("profiles-{}-{port}.toml", std::process::id()));
    std::fs::write(&config, doctor_profile(port)).expect("write canary-only config");
    let base_args = [
        "--json",
        "doctor",
        "--online",
        "--profile",
        "verbose_canary",
    ];
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_oraclemcp"))
            .args(args)
            .env("ORACLEMCP_CONFIG", &config)
            .env("LAB_DOCTOR_PASSWORD_CANARY", PASSWORD_CANARY)
            .env("LAB_DOCTOR_TOKEN_CANARY", TOKEN_CANARY)
            .env_remove("ORACLEMCP_CONNECT_DETAIL")
            .output()
            .expect("run real doctor CLI against a closed loopback TCP endpoint")
    };
    let default = run(&base_args);
    let mut verbose_args = base_args.to_vec();
    verbose_args.insert(3, "--verbose");
    let verbose = run(&verbose_args);
    assert_eq!(
        default.status.code(),
        Some(2),
        "default online doctor should fail connectivity"
    );
    assert_eq!(
        verbose.status.code(),
        Some(2),
        "verbose online doctor should fail connectivity"
    );
    let default_stdout = String::from_utf8_lossy(&default.stdout);
    let default_stderr = String::from_utf8_lossy(&default.stderr);
    let verbose_stdout = String::from_utf8_lossy(&verbose.stdout);
    let verbose_stderr = String::from_utf8_lossy(&verbose.stderr);
    let rendered =
        format!("{default_stdout}\n{default_stderr}\n{verbose_stdout}\n{verbose_stderr}");
    for canary in [PASSWORD_CANARY, TOKEN_CANARY, OCID_CANARY, DSN_CANARY] {
        assert!(!rendered.contains(canary), "leaked {canary}: {rendered}");
    }

    let default_report: Value =
        serde_json::from_str(&default_stdout).expect("default doctor emits JSON");
    let default_detail = connectivity(&default_report)["detail"]
        .as_str()
        .expect("default connectivity detail");
    assert!(
        default_detail.contains("driver detail suppressed"),
        "{default_detail}"
    );
    assert!(
        !default_detail.contains("connect_phase="),
        "{default_detail}"
    );

    let verbose_report: Value =
        serde_json::from_str(&verbose_stdout).expect("verbose doctor emits JSON");
    let detail = connectivity(&verbose_report)["detail"]
        .as_str()
        .expect("verbose connectivity detail");
    assert!(detail.contains("connect_phase=Tcp"), "{detail}");
    assert!(detail.contains("oracle-connect-error"), "{detail}");
}
