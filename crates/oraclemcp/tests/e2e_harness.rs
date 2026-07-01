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
                    .is_some_and(|message| message.contains("pass=7 fail=0 skipped=3 total=10"))),
        "missing passing orchestrator summary: {events:?}"
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
        "scripts/installer_lint_and_offline_smoke.sh",
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
