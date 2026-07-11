use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has workspace parent")
        .parent()
        .expect("workspace has repo root")
        .to_path_buf()
}

fn run_script(script: &str, args: &[&str]) -> Output {
    let root = repo_root();
    Command::new("bash")
        .arg(root.join(script))
        .args(args)
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .output()
        .unwrap_or_else(|e| panic!("run {script}: {e}"))
}

fn json_lines(stderr: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(stderr)
        .lines()
        .filter(|line| line.trim_start().starts_with('{'))
        .map(|line| serde_json::from_str::<Value>(line).expect("stderr line is valid JSON"))
        .collect()
}

fn required_fields() -> BTreeSet<&'static str> {
    [
        "event",
        "phase",
        "ts",
        "duration_ms",
        "lane",
        "subject",
        "sid",
        "profile",
        "level",
        "grant",
        "outcome",
    ]
    .into_iter()
    .collect()
}

#[test]
fn e2e_scripts_emit_required_json_line_fields() {
    let output = run_script("scripts/e2e/offline_stdio.sh", &["--log", "--dry-run"]);
    assert!(
        output.status.success(),
        "offline_stdio dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events = json_lines(&output.stderr);
    assert!(!events.is_empty(), "script emitted no JSON-line events");
    let required = required_fields();
    for event in &events {
        for field in &required {
            assert!(
                event.get(field).is_some(),
                "event missing required field {field}: {event}"
            );
        }
        assert!(
            matches!(
                event["phase"].as_str(),
                Some("setup" | "act" | "assert" | "teardown")
            ),
            "invalid phase: {event}"
        );
    }
}

#[test]
fn e2e_orchestrator_aggregates_dry_run_scenarios() {
    let output = run_script("scripts/e2e/run_all.sh", &["--log", "--dry-run"]);
    assert!(
        output.status.success(),
        "run_all dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events = json_lines(&output.stderr);
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "orchestrator_summary"
                && event["outcome"] == "pass"
                && event["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("pass=7 fail=0 skipped=5 total=12"))),
        "missing passing orchestrator summary: {events:?}"
    );
}

#[test]
fn clean_machine_e2e_dry_run_schedules_h5_contract() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e/clean_machine_e2e.sh"))
        .args(["--log", "--dry-run"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env("ORACLEMCP_CLEAN_MACHINE_E2E", "1")
        .env("ORACLEMCP_CLEAN_MACHINE_BOOT_ID_BEFORE", "before-reboot")
        .env("ORACLEMCP_CLEAN_MACHINE_BOOT_ID_AFTER", "after-reboot")
        .env("ORACLEMCP_CLEAN_MACHINE_URL", "http://127.0.0.1:7070")
        .env("ORACLEMCP_CLEAN_MACHINE_PROFILE_A", "xe_test_a")
        .env("ORACLEMCP_CLEAN_MACHINE_PROFILE_B", "xe_test_b")
        .env("ORACLEMCP_CLEAN_MACHINE_ALLOW_NO_AUTH", "1")
        .output()
        .expect("run clean_machine_e2e dry-run");
    assert!(
        output.status.success(),
        "clean_machine_e2e dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    assert!(
        command_messages.iter().any(|message| message.contains(
            "cargo test -p oraclemcp --features live-xe --test clean_machine_e2e -- --ignored --nocapture"
        )),
        "clean-machine dry-run did not schedule the ignored H5 Rust proof: {command_messages:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "clean_machine_e2e"),
        "missing passing clean-machine completion: {events:?}"
    );
}

#[test]
fn clean_machine_e2e_refuses_production_markers() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e/clean_machine_e2e.sh"))
        .args(["--log", "--dry-run"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env("ORACLEMCP_CLEAN_MACHINE_E2E", "1")
        .env("ORACLEMCP_CLEAN_MACHINE_BOOT_ID_BEFORE", "before-reboot")
        .env("ORACLEMCP_CLEAN_MACHINE_BOOT_ID_AFTER", "after-reboot")
        .env("ORACLEMCP_CLEAN_MACHINE_URL", "http://127.0.0.1:7070")
        .env("ORACLEMCP_CLEAN_MACHINE_PROFILE_A", "prod_ro")
        .env("ORACLEMCP_CLEAN_MACHINE_PROFILE_B", "xe_test_b")
        .env("ORACLEMCP_CLEAN_MACHINE_ALLOW_NO_AUTH", "1")
        .output()
        .expect("run clean_machine_e2e production-marker check");
    assert!(
        !output.status.success(),
        "production-looking clean-machine profile must be refused"
    );
    let events = json_lines(&output.stderr);
    assert!(
        events.iter().any(|event| event["outcome"] == "fail"
            && event["message"]
                .as_str()
                .is_some_and(|message| message.contains("production-looking"))),
        "missing production-marker refusal event: {events:?}"
    );
}

#[test]
fn release_acceptance_suite_schedules_hci_component_gates() {
    let output = run_script(
        "scripts/release_acceptance_ci_suite.sh",
        &["--log", "--dry-run"],
    );
    assert!(
        output.status.success(),
        "release acceptance dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    for expected in [
        "scripts/oraclemcp_concurrency_lint.sh",
        "scripts/oraclemcp_ergonomics_lint.sh",
        "scripts/e2e/doctor_fixtures.sh --log",
        "scripts/dashboard_bundle_check.sh",
        "scripts/release_sbom_check.sh --source",
        "scripts/local_release_gate_check.sh",
        "scripts/installer_lint_and_offline_smoke.sh --log",
        "scripts/e2e/release_rollback_dry_run.sh --log --dry-run",
        "scripts/validate_docker_provenance_workflow.sh",
        "scripts/e2e/clean_machine_e2e.sh --log --dry-run",
        "scripts/oraclemcp_feature_powerset.sh",
        "scripts/oraclemcp_arch_fitness_lint.sh",
    ] {
        assert!(
            command_messages
                .iter()
                .any(|message| message.contains(expected)),
            "release acceptance suite did not schedule {expected}: {command_messages:?}"
        );
    }
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "release_acceptance_ci_suite"),
        "missing passing release-acceptance completion: {events:?}"
    );
    assert!(
        events.iter().any(|event| event["event"] == "suite_summary"
            && event["message"]
                .as_str()
                .is_some_and(|message| message.contains("installer-jsonl")
                    && message.contains("clean-machine"))),
        "release acceptance summary must account for installer JSON-line logs: {events:?}"
    );
}

#[test]
fn docker_recovery_is_bound_to_immutable_release_provenance() {
    let output = run_script("scripts/validate_docker_provenance_workflow.sh", &[]);
    assert!(
        output.status.success(),
        "Docker provenance workflow guard failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("immutable tag, digest comparison, and rollback contracts verified"),
        "Docker provenance workflow guard did not report its verified contract"
    );
}

#[test]
fn local_release_gate_dry_run_schedules_synthetic_tcps_proof() {
    let output = run_script(
        "scripts/local_release_gate.sh",
        &["--log", "--dry-run", "--real-adb"],
    );
    assert!(
        output.status.success(),
        "local_release_gate dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    for expected in [
        "systemd-run --user --scope",
        "cargo test -p oraclemcp-core --test oci_tcps_e2e profile_wallet_and_iam_token_reach_local_tcps_terminator -- --nocapture",
        "bash scripts/e2e/real_adb_tcps_signoff.sh --log",
    ] {
        assert!(
            command_messages
                .iter()
                .any(|message| message.contains(expected)),
            "local release gate did not schedule {expected}: {command_messages:?}"
        );
    }
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "proof_dry_run" && event["outcome"] == "skipped"),
        "missing dry-run proof event: {events:?}"
    );
}

#[test]
fn real_adb_signoff_dry_run_schedules_wallet_and_iam_doctor_paths() {
    let output = run_script(
        "scripts/e2e/real_adb_tcps_signoff.sh",
        &["--log", "--dry-run"],
    );
    assert!(
        output.status.success(),
        "real_adb_tcps_signoff dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    for expected in [
        "cargo build -p oraclemcp --bin oraclemcp",
        "--json doctor --online --profile real_adb_wallet_smoke",
        "--json doctor --online --profile real_adb_iam_smoke",
        "bash scripts/secret_scan.sh",
    ] {
        assert!(
            command_messages
                .iter()
                .any(|message| message.contains(expected)),
            "real ADB signoff did not schedule {expected}: {command_messages:?}"
        );
    }
    assert!(
        events.iter().any(|event| event["event"] == "env_contract"
            && event["message"]
                .as_str()
                .is_some_and(|message| message.contains("values are never logged or committed"))),
        "missing env contract event: {events:?}"
    );
}

#[test]
fn local_release_gate_check_validates_synthetic_proof() {
    let root = repo_root();
    let proof_dir =
        std::env::temp_dir().join(format!("oraclemcp-local-gate-proof-{}", std::process::id()));
    std::fs::create_dir_all(&proof_dir).expect("create proof dir");
    let proof = proof_dir.join("results-fixturesha.json");
    std::fs::write(
        &proof,
        r#"{
  "schema_version": 1,
  "source_sha": "fixturesha",
  "confidentiality": {
    "server_certificate_subject": "CN=oracle-test.invalid",
    "real_adb_evidence": "out-of-band; never committed"
  },
  "checks": [
    {"name": "synthetic_oci_tcps_wallet_iam_token", "status": "pass"}
  ]
}
"#,
    )
    .expect("write proof");

    let output = Command::new("bash")
        .arg(root.join("scripts/local_release_gate_check.sh"))
        .args(["--proof", proof.to_str().expect("proof path is utf8")])
        .args(["--source-sha", "fixturesha", "--require"])
        .current_dir(&root)
        .output()
        .expect("run local release gate check");
    let _ = std::fs::remove_file(&proof);
    let _ = std::fs::remove_dir(&proof_dir);

    assert!(
        output.status.success(),
        "synthetic proof check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn hardening_acceptance_suite_schedules_b11_component_gates() {
    let output = run_script(
        "scripts/e2e/hardening_acceptance.sh",
        &["--log", "--dry-run"],
    );
    assert!(
        output.status.success(),
        "hardening acceptance dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    for expected in [
        "scripts/oraclemcp_honesty_grep.sh",
        "scripts/sensitive_data_lint.sh",
        "scripts/e2e/conformance_coverage.sh --log",
        "scripts/e2e/mcp_and_operator_v1_conformance_matrix.sh --log",
        "scripts/installer_lint_and_offline_smoke.sh",
        "cargo test -p oraclemcp-core surface_inventory_authn_no_leak",
        "cargo test -p oraclemcp-core uniform_auth_errors_no_enumeration_oracle",
        "cargo test -p oraclemcp-core self_heal_down_never_up_refuses_protected_profile_repair",
        "cargo test -p oraclemcp-core cp_apply_reclassifies_never_trusts_stored_verdict",
        "cargo test -p oraclemcp backup_restore_verifies_audit_chain",
        "cargo test -p oraclemcp audit_verify_with_db_evidence_command_parses",
        "cargo test -p oraclemcp --test e2e_http_oauth",
        "cargo test -p oraclemcp --test e2e_stdio",
        "cargo test -p oraclemcp --test golden_behavior",
        "cargo test -p oraclemcp-core --test mcp_conformance",
        "cargo test -p oraclemcp-db --test structured_schema_golden",
        "cargo test -p oraclemcp --test installer_e2e",
    ] {
        assert!(
            command_messages
                .iter()
                .any(|message| message.contains(expected)),
            "hardening acceptance suite did not schedule {expected}: {command_messages:?}"
        );
    }
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "hardening_acceptance"),
        "missing passing hardening-acceptance completion: {events:?}"
    );
}

#[test]
fn rollback_runbook_dry_run_covers_release_surfaces() {
    let output = run_script(
        "scripts/e2e/release_rollback_dry_run.sh",
        &["--log", "--dry-run"],
    );
    assert!(
        output.status.success(),
        "rollback runbook dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let messages = events
        .iter()
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    for expected in [
        "cargo yank -p oraclemcp-error --vers 0.6.0",
        "cargo yank -p oraclemcp-telemetry --vers 0.6.0",
        "cargo yank -p oraclemcp-audit --vers 0.6.0",
        "cargo yank -p oraclemcp-guard --vers 0.6.0",
        "cargo yank -p oraclemcp-config --vers 0.6.0",
        "cargo yank -p oraclemcp-db --vers 0.6.0",
        "cargo yank -p oraclemcp-auth --vers 0.6.0",
        "cargo yank -p oraclemcp-core --vers 0.6.0",
        "cargo yank -p oraclemcp --vers 0.6.0",
        "gh release edit v0.6.0 --prerelease",
        "gh release delete v0.6.0 --yes --cleanup-tag",
        "gh workflow run docker.yml -f version=0.4.1 -f variant=core",
        "gh workflow run docker.yml -f version=0.4.1 -f variant=plsql-intelligence",
        "git restore --source=v0.4.1 -- server.json",
        "git commit -m chore: revert MCP registry listing to v0.4.1 server.json",
        "gh workflow run publish-mcp.yml --ref main",
        "npm deprecate oraclemcp@0.6.0",
        "npm dist-tag add oraclemcp@0.4.1 latest",
        "Homebrew and winget are pull-based",
        "rollback plan covers crates.io, GitHub release, GHCR latest, server.json, npm, Homebrew, and winget",
    ] {
        assert!(
            messages.iter().any(|message| message.contains(expected)),
            "rollback runbook dry-run did not cover {expected}: {messages:?}"
        );
    }
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "rollback_runbook_dry_run"),
        "missing passing rollback-runbook completion: {events:?}"
    );
}

#[test]
fn release_surface_sync_check_passes_on_workspace() {
    // The surface-sync check verifies the built dashboard SBOM, so it requires
    // `web/dist/` to have been produced by a dashboard build. The authoritative
    // gate is the `release-metadata-sync` CI job (which downloads the built
    // dashboard artifact). In environments that do NOT build the dashboard
    // (e.g. the advisory multi-nightly `cargo test --workspace` job, or a fresh
    // local checkout), skip rather than fail — the release job covers it.
    let dashboard_sbom = repo_root().join("web/dist/oraclemcp-dashboard.cyclonedx.json");
    if !dashboard_sbom.exists() {
        eprintln!(
            "skipped: {} not present (dashboard not built in this environment); \
             surface-sync is authoritatively gated by the release-metadata-sync CI job",
            dashboard_sbom.display()
        );
        return;
    }
    let output = run_script("scripts/release_surface_sync_check.sh", &[]);
    assert!(
        output.status.success(),
        "release surface sync check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("release-surface-sync: OK"),
        "unexpected sync check output: {stdout}"
    );
}

#[test]
fn release_surface_drift_fails_fast() {
    let root = repo_root();
    let health = root.join("tests/fixtures/ui/operator-v1/health.json");
    let original = std::fs::read_to_string(&health).expect("read health fixture");
    let temp = std::env::temp_dir().join(format!(
        "oraclemcp-health-drift-{}.json",
        std::process::id()
    ));
    let bad = original.replace(
        &format!(
            "\"version\": \"{}\"",
            serde_json::from_str::<Value>(&original)
                .expect("health json")
                .pointer("/data/liveness/version")
                .and_then(Value::as_str)
                .expect("liveness.version")
        ),
        "\"version\": \"0.0.0-drift-drill\"",
    );
    std::fs::write(&temp, bad).expect("write drift health fixture");
    let output = Command::new("bash")
        .arg(root.join("scripts/release_surface_sync_check.sh"))
        .current_dir(&root)
        .env("ORACLEMCP_RELEASE_SURFACE_SYNC_HEALTH_PATH", &temp)
        .output()
        .expect("run drift drill");
    let _ = std::fs::remove_file(&temp);
    assert!(
        !output.status.success(),
        "drift drill should fail fast: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("release-surface-sync:") && stderr.contains("liveness.version"),
        "drift drill stderr should name the mismatch: {stderr}"
    );
}

#[test]
fn e2e_live_scripts_refuse_production_looking_targets() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e/live_oracle.sh"))
        .args(["--log", "--dry-run"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env("ORACLEMCP_LIVE_XE", "1")
        .env("ORACLEMCP_TEST_DSN", "prod-db.example:1521/PROD")
        .env("ORACLEMCP_TEST_USER", "TEST_USER")
        .env("ORACLEMCP_TEST_PASSWORD", "placeholder")
        .output()
        .expect("run live_oracle production-target check");
    assert!(
        !output.status.success(),
        "production-looking live target must be refused"
    );
    let events = json_lines(&output.stderr);
    assert!(
        events.iter().any(|event| event["outcome"] == "fail"
            && event["message"]
                .as_str()
                .is_some_and(|message| message.contains("production-looking"))),
        "missing production-target refusal event: {events:?}"
    );
}

#[test]
fn e2e_failure_path_emits_crashpack_and_seed() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg("-c")
        .arg(
            "source scripts/e2e/lib.sh; \
             e2e_run_command act bash -lc 'printf failure-output; exit 9'",
        )
        .current_dir(&root)
        .env("E2E_LOG", "1")
        .env("E2E_SCENARIO", "contract_failure_probe")
        .env("ORACLEMCP_E2E_SEED", "777")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .output()
        .expect("run crashpack probe");
    assert!(!output.status.success(), "failure probe must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("CRASHPACK="), "missing crashpack: {stderr}");
    assert!(stderr.contains("SEED=777"), "missing replay seed: {stderr}");
}
