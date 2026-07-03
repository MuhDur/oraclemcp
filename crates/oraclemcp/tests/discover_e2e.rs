//! Clean-machine end-to-end for TNS-discovery onboarding (bead `.18`).
//!
//! Real components, NO mocks: the real `oraclemcp` binary, the real config-ops
//! backend, and the real upstream `TnsnamesReader` over the canonical synthetic
//! fixture (`tests/fixtures/tns`, design spec §F). Structure mirrors
//! `clean_machine_e2e.rs`, but this leg is OFFLINE by default (no live database)
//! and proves the whole path an operator/agent hits on a fresh machine:
//!   1. `setup --discover --yes --json` writes READ_ONLY profiles via config-ops.
//!   2. `doctor` (offline) validates them and surfaces per-profile credential
//!      next-actions without a live database.
//!   3. re-running is idempotent (add-only merge, no clobber).
//!   4. a hand-edited profile survives a re-run (only new profiles are added).
//!
//! The live-DB leg (`doctor --online`) runs only when the environment supplies a
//! real Oracle target (`ORACLEMCP_E2E_ONLINE=1`); otherwise the test stays fully
//! offline, per the real-service-e2e discipline (mirrors `live_xe_service_attach.rs`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oraclemcp_config::{CONFIG_PATH_ENV, OracleMcpConfig};

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "oraclemcp-discover-e2e-{}-{stamp}-{label}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// The committed canonical fixture tree (design spec §F).
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("tns")
}

fn wait(mut cmd: Command, timeout: Duration) -> Output {
    let mut child = cmd.spawn().expect("spawn oraclemcp");
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().expect("poll child").is_some() {
            return child.wait_with_output().expect("collect output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let out = child.wait_with_output().expect("collect killed output");
            panic!(
                "oraclemcp did not exit within {timeout:?}; stdout={} stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Invoke the real binary with a clean, fixture-scoped environment.
fn invoke(config: &Path, home: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(args)
        .env(CONFIG_PATH_ENV, config)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("HOME", home)
        .env("TNS_ADMIN", fixture_dir())
        .env_remove("ORACLE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    wait(cmd, Duration::from_secs(10))
}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("valid JSON on stdout")
}

#[test]
fn discover_onboarding_clean_machine_e2e() {
    let dir = temp_dir("clean-machine");
    let config = dir.join("profiles.toml");

    // ---- Stage 1: fresh discovery writes READ_ONLY profiles via config-ops ----
    let out = invoke(&config, &dir, &["--json", "setup", "--discover", "--yes"]);
    eprintln!("E2E stage1 discover: exit={:?}", out.status.code());
    assert_eq!(out.status.code(), Some(0), "consented discovery succeeds");
    let v = json(&out.stdout);
    assert_eq!(v["ok"], serde_json::json!(true));
    assert_eq!(v["written"], serde_json::json!(true));
    assert_eq!(v["dry_run"], serde_json::json!(false));
    assert_eq!(v["write_mode"], serde_json::json!("fresh"));
    assert_eq!(
        v["target_path"],
        serde_json::json!(config.display().to_string())
    );
    // Both marquee net-services surface with chosen profile names + env vars.
    let profiles: Vec<&str> = v["profiles"]
        .as_array()
        .expect("profiles array")
        .iter()
        .map(|p| p["name"].as_str().expect("profile name"))
        .collect();
    assert!(profiles.contains(&"primary_tcps"), "TCPS service mapped");
    assert!(profiles.contains(&"ez_plain"), "EZConnect service mapped");
    let env_names: Vec<&str> = v["env_vars"]
        .as_array()
        .expect("env vars")
        .iter()
        .map(|e| e["env_var"].as_str().expect("env var name"))
        .collect();
    assert!(env_names.contains(&"ORACLE_PRIMARY_TCPS_PASSWORD"));
    assert!(env_names.contains(&"ORACLE_PRIMARY_TCPS_WALLET_PASSWORD"));

    // The on-disk config parses through the STRICT loader (config-ops re-parses
    // before writing; we independently confirm) and is READ_ONLY, secret-free.
    let written = fs::read_to_string(&config).expect("config written");
    let parsed = OracleMcpConfig::from_toml_str(&written)
        .expect("written config parses via the strict loader");
    assert!(
        !parsed.profiles.is_empty(),
        "at least one profile synthesized"
    );
    assert!(written.contains("max_level = \"READ_ONLY\""));
    assert!(written.contains("default_level = \"READ_ONLY\""));
    assert!(
        !written.lines().any(|l| {
            let t = l.trim_start();
            !t.starts_with('#') && t.contains("literal:")
        }),
        "no literal secret ref emitted"
    );

    // ---- Stage 2: doctor (offline) validates + surfaces credential hints ----
    let doc = invoke(&config, &dir, &["--json", "doctor"]);
    let doc_json = json(&doc.stdout);
    eprintln!(
        "E2E stage2 doctor: exit={:?} ok={}",
        doc.status.code(),
        doc_json["ok"]
    );
    // With multiple discovered profiles and no default configured, offline
    // doctor honestly reports action-needed (exit 2, ok=false) rather than a
    // false "all good", and guides the operator to select a profile.
    assert_eq!(
        doc.status.code(),
        Some(2),
        "offline doctor reports action-needed for the freshly discovered profiles"
    );
    assert_eq!(doc_json["ok"], serde_json::json!(false));
    let doc_text = format!("{doc_json}");
    assert!(
        doc_text.contains("default_profile") || doc_text.contains("--profile"),
        "doctor guides the operator to pick among the discovered profiles: {doc_text}"
    );
    // Targeting a specific discovered profile, doctor validates it offline and
    // surfaces the connectivity/credential next-action (no live DB / env secret).
    let doc1 = invoke(
        &config,
        &dir,
        &["--json", "doctor", "--profile", "primary_tcps"],
    );
    let doc1_text = format!("{}", json(&doc1.stdout));
    eprintln!("E2E stage2 doctor --profile: exit={:?}", doc1.status.code());
    assert!(
        doc1_text.to_lowercase().contains("credential")
            || doc1_text.contains("ORACLE_PRIMARY_TCPS_PASSWORD")
            || doc1_text.to_lowercase().contains("connect"),
        "per-profile doctor surfaces a connectivity/credential next-action: {doc1_text}"
    );

    // ---- Stage 3: re-running is idempotent — add-only, no clobber ----
    let again = invoke(&config, &dir, &["--json", "setup", "--discover", "--yes"]);
    assert_eq!(again.status.code(), Some(0));
    let av = json(&again.stdout);
    eprintln!(
        "E2E stage3 re-run: write_mode={} created={}",
        av["write_mode"], av["profiles_created"]
    );
    assert_eq!(av["write_mode"], serde_json::json!("add_only_merge"));
    assert!(
        av["profiles_created"]
            .as_array()
            .expect("profiles_created")
            .is_empty(),
        "a second run adds no new profiles"
    );
    // Content is unchanged (no clobber): the same profiles remain parseable.
    let after_rerun = fs::read_to_string(&config).expect("config still present");
    let reparsed = OracleMcpConfig::from_toml_str(&after_rerun).expect("still valid");
    assert_eq!(
        reparsed.profiles.len(),
        parsed.profiles.len(),
        "idempotent re-run neither adds nor drops profiles"
    );

    // ---- Stage 4: a hand-edited profile survives a subsequent discovery ----
    let edited = format!(
        "{after_rerun}\n\n[[profiles]]\nname = \"hand_edited_e2e\"\n\
         connect_string = \"edited.example.com:1521/EDITED\"\n\
         credential_ref = \"env:MY_E2E_PW\"\nmax_level = \"READ_ONLY\"\n\
         default_level = \"READ_ONLY\"\n"
    );
    fs::write(&config, &edited).expect("pre-seed a hand-edited profile");
    let merged = invoke(&config, &dir, &["--json", "setup", "--discover", "--yes"]);
    assert_eq!(merged.status.code(), Some(0));
    let final_cfg = fs::read_to_string(&config).expect("config present after merge");
    assert!(
        final_cfg.contains("hand_edited_e2e") && final_cfg.contains("env:MY_E2E_PW"),
        "the hand-edited profile is preserved across a re-run"
    );
    OracleMcpConfig::from_toml_str(&final_cfg).expect("merged config still valid");

    // ---- Optional live-DB leg (env-gated; the offline test never needs it) ----
    if std::env::var("ORACLEMCP_E2E_ONLINE").is_ok() {
        let online = invoke(&config, &dir, &["--json", "doctor", "--online"]);
        eprintln!("E2E online doctor: exit={:?}", online.status.code());
        assert!(online.status.code().is_some(), "online doctor ran");
    }

    let _ = fs::remove_dir_all(&dir);
}
