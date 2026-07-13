//! Arc E1's CLI must reach the capture gate without becoming a second path for
//! raw incident material. This invokes the compiled binary against a complete
//! synthetic configuration and inspects every emitted bundle byte.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use oraclemcp_config::CONFIG_PATH_ENV;
use oraclemcp_core::incident::verify_bundle;

const RAW_STATEMENT: &str = "UPDATE tenant_customer_8675309.ledger_entries SET amount = 90000 WHERE account_id = :secret_bind";
const CONNECT_STRING: &str = "synthetic-lab.invalid:1521/SYNTHETIC";
const USERNAME: &str = "SYNTHETIC_INCIDENT_USER";
const CREDENTIAL_REF: &str = "env:SYNTHETIC_INCIDENT_PASSWORD";

fn invoke(config: &Path, bundle: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_oraclemcp"))
        .args([
            "--json",
            "incident",
            "capture",
            bundle.to_str().expect("bundle path is UTF-8"),
            "--seed",
            "31337",
        ])
        .env(CONFIG_PATH_ENV, config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn incident capture");
    child
        .stdin
        .take()
        .expect("capture stdin")
        .write_all(RAW_STATEMENT.as_bytes())
        .expect("write raw statement to capture stdin");
    child.wait_with_output().expect("run incident capture")
}

fn bundle_text(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut pending = vec![dir.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path).expect("read bundle directory") {
            let path = entry.expect("bundle entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push((
                    path.clone(),
                    fs::read_to_string(path).expect("bundle artifacts are UTF-8"),
                ));
            }
        }
    }
    files
}

#[test]
fn incident_capture_cli_is_redacted_self_describing_and_non_overwriting() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let config = temp.path().join("profiles.toml");
    fs::write(
        &config,
        format!(
            r#"
schema_version = 2
default_profile = "synthetic"

[[profiles]]
name = "synthetic"
connect_string = "{CONNECT_STRING}"
username = "{USERNAME}"
credential_ref = "{CREDENTIAL_REF}"
description = "synthetic incident fixture"
max_level = "READ_ONLY"
"#,
        ),
    )
    .expect("write synthetic config");
    let bundle = temp.path().join("bundle");

    let output = invoke(&config, &bundle);
    assert!(
        output.status.success(),
        "capture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("capture emits JSON");
    assert_eq!(payload["kind"], "oraclemcp_incident_capture");
    assert_eq!(payload["seed"], 31_337);
    assert_eq!(payload["entries"], 3);
    assert!(
        payload["bundle_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("sha256:")),
        "capture did not return a content-addressed id: {payload}"
    );

    let manifest = verify_bundle(&bundle).expect("written bundle verifies itself");
    assert_eq!(manifest.seed, 31_337);
    assert_eq!(manifest.entries.len(), 3);

    for (path, text) in bundle_text(&bundle) {
        let lower = text.to_ascii_lowercase();
        for raw in [
            RAW_STATEMENT,
            "tenant_customer_8675309",
            "ledger_entries",
            "90000",
            "secret_bind",
            CONNECT_STRING,
            USERNAME,
            CREDENTIAL_REF,
        ] {
            assert!(
                !lower.contains(&raw.to_ascii_lowercase()),
                "{} leaked raw incident material {raw:?}",
                path.display()
            );
        }
    }

    // A second capture cannot merge with or overwrite the first bundle.
    let repeated = invoke(&config, &bundle);
    assert_eq!(repeated.status.code(), Some(2));
    let error: serde_json::Value =
        serde_json::from_slice(&repeated.stderr).expect("refusal is structured JSON");
    assert_eq!(error["code"], "ORACLEMCP_INCIDENT_TARGET_EXISTS");
    assert!(!String::from_utf8_lossy(&repeated.stderr).contains(RAW_STATEMENT));
}
