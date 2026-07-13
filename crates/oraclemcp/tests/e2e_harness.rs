use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

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

const DISTRIBUTION_ASSETS: [&str; 3] = [
    "oraclemcp-x86_64-apple-darwin.tar.gz",
    "oraclemcp-aarch64-apple-darwin.tar.gz",
    "oraclemcp-x86_64-pc-windows-msvc.zip",
];

fn distribution_fixture(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let artifact_dir = repo_root().join("target/e2e-contract").join(format!(
        "distribution-manifests-{label}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&artifact_dir).expect("create distribution artifact fixture");
    artifact_dir
}

fn sha256_file(path: &Path) -> String {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Command::new("shasum")
                    .args(["-a", "256"])
                    .arg(path)
                    .output()
            } else {
                Err(error)
            }
        })
        .expect("sha256sum or shasum is available");
    assert!(
        output.status.success(),
        "hash command failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("hash output is utf8")
        .split_whitespace()
        .next()
        .expect("hash output contains a digest")
        .to_ascii_lowercase()
}

fn write_distribution_archives(artifact_dir: &Path) -> [String; 3] {
    for (asset, bytes) in
        DISTRIBUTION_ASSETS
            .iter()
            .zip([b"darwin-x64".as_slice(), b"darwin-arm64", b"windows-x64"])
    {
        std::fs::write(artifact_dir.join(asset), bytes).expect("write release archive fixture");
    }
    DISTRIBUTION_ASSETS.map(|asset| sha256_file(&artifact_dir.join(asset)))
}

fn write_valid_distribution_sidecars(artifact_dir: &Path, hashes: &[String; 3]) {
    std::fs::write(
        artifact_dir.join(format!("{}.sha256", DISTRIBUTION_ASSETS[0])),
        format!("{}  {}\n", hashes[0], DISTRIBUTION_ASSETS[0]),
    )
    .expect("write GNU checksum fixture");
    std::fs::write(
        artifact_dir.join(format!("{}.sha256", DISTRIBUTION_ASSETS[1])),
        format!(
            "SHA256 ({}) = {}\n",
            DISTRIBUTION_ASSETS[1],
            hashes[1].to_ascii_uppercase()
        ),
    )
    .expect("write BSD checksum fixture");
    std::fs::write(
        artifact_dir.join(format!("{}.sha256", DISTRIBUTION_ASSETS[2])),
        format!(
            "SHA256 hash of {}:\r\n{}\r\nCertUtil: -hashfile command completed successfully.\r\n",
            DISTRIBUTION_ASSETS[2],
            hashes[2].to_ascii_uppercase()
        ),
    )
    .expect("write certutil checksum fixture");
}

fn run_distribution_renderer(artifact_dir: &Path, output_dir: &Path) -> Output {
    Command::new("bash")
        .arg(repo_root().join("scripts/render_distribution_manifests.sh"))
        .arg(artifact_dir)
        .current_dir(repo_root())
        .env("VERSION", "9.9.9")
        .env("OUT_DIR", output_dir)
        .output()
        .expect("run distribution manifest renderer")
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
                && event["message"].as_str().is_some_and(|message| {
                    message.contains("pass=")
                        && message.contains("fail=0")
                        && message.contains("total=")
                })),
        "missing passing orchestrator summary: {events:?}"
    );
}

/// Arc L's console scenario is release evidence only when its non-dry-run path
/// requires a real lab connection. A missing live input must fail before any
/// UI-only honesty assertion can be mistaken for a served-Oracle proof.
#[test]
fn served_console_requires_live_oracle_and_dry_run_only_checks_wiring() {
    let root = repo_root();
    let mut command = Command::new("bash");
    let missing_live = command
        .arg(root.join("scripts/e2e/served_console.sh"))
        .arg("--log")
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env_remove("OMCP_LIVE_DSN")
        .env_remove("OMCP_LIVE_USER")
        .env_remove("OMCP_LIVE_CRED")
        .output()
        .expect("run served-console without live inputs");
    assert!(
        !missing_live.status.success(),
        "served-console must not report success without its mandatory live Oracle inputs: {}",
        String::from_utf8_lossy(&missing_live.stderr)
    );
    let missing_events = json_lines(&missing_live.stderr);
    assert!(
        missing_events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "fail"
                && event["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("OMCP_LIVE_DSN"))),
        "missing explicit live-input failure: {missing_events:?}"
    );

    let dry_run = Command::new("bash")
        .arg(root.join("scripts/e2e/served_console.sh"))
        .args(["--log", "--dry-run"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env_remove("OMCP_LIVE_DSN")
        .env_remove("OMCP_LIVE_USER")
        .env_remove("OMCP_LIVE_CRED")
        .output()
        .expect("run served-console dry-run");
    assert!(
        dry_run.status.success(),
        "served-console dry-run failed: {}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let dry_events = json_lines(&dry_run.stderr);
    assert!(
        dry_events
            .iter()
            .any(|event| event["event"] == "command_start"
                && event["message"].as_str().is_some_and(
                    |message| message.contains("omcpb build -p oraclemcp --bin oraclemcp")
                )),
        "served-console dry-run did not schedule its omcpb build: {dry_events:?}"
    );
    assert!(
        dry_events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "served_console"),
        "missing served-console dry-run completion: {dry_events:?}"
    );
}

#[test]
fn time_diff_e2e_dry_run_uses_omcpb_and_reports_a_pass() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e/time_diff.sh"))
        .args(["--log", "--dry-run", "--lane", "xe18"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env("ORACLEMCP_LIVE_XE", "1")
        .env("ORACLE_MATRIX_XE18_USER", "e2e_test")
        .env("ORACLE_MATRIX_XE18_PASSWORD", "not-used-in-dry-run")
        .output()
        .expect("run time_diff dry-run");
    assert!(
        output.status.success(),
        "time_diff dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    assert!(
        command_messages
            .iter()
            .any(|message| message.contains("omcpb build -p oraclemcp --bin oraclemcp")),
        "time-diff dry-run did not schedule the omcpb package build: {command_messages:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "time_diff"),
        "missing passing time-diff completion: {events:?}"
    );
}

/// Arc N's policy proof must exercise the served MCP process, and registration
/// is part of the contract: an unregistered scenario is not release evidence.
#[test]
fn sql_policy_e2e_dry_run_is_registered_and_schedules_omcpb() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e/sql_policy.sh"))
        .args(["--log", "--dry-run"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env("ORACLEMCP_LIVE_XE", "1")
        .env("ORACLEMCP_TEST_DSN", "localhost:1522/FREEPDB1")
        .env("ORACLEMCP_TEST_USER", "E2E_TEST")
        .env("ORACLEMCP_TEST_PASSWORD", "not-used-in-dry-run")
        .output()
        .expect("run sql_policy dry-run");
    assert!(
        output.status.success(),
        "sql_policy dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    assert!(
        command_messages
            .iter()
            .any(|message| message.contains("omcpb build -p oraclemcp --bin oraclemcp")),
        "SQL-policy dry-run did not schedule the omcpb package build: {command_messages:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "sql_policy"),
        "missing passing SQL-policy completion: {events:?}"
    );
    let runner =
        std::fs::read_to_string(root.join("scripts/e2e/run_all.sh")).expect("read run_all.sh");
    assert!(
        runner.contains("scripts/e2e/sql_policy.sh"),
        "served SQL-policy proof must be dispatched by run_all.sh"
    );
}

/// Arc B's certificate proof is release evidence only when the real served
/// scenario remains reachable from the ordinary E2E runner.
#[test]
fn verdict_certificate_e2e_dry_run_is_registered_and_schedules_omcpb() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e/verdict_certificate.sh"))
        .args(["--log", "--dry-run"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env("ORACLEMCP_LIVE_XE", "1")
        .env("ORACLEMCP_TEST_DSN", "localhost:1522/FREEPDB1")
        .env("ORACLEMCP_TEST_USER", "E2E_TEST")
        .env("ORACLEMCP_TEST_PASSWORD", "not-used-in-dry-run")
        .output()
        .expect("run verdict-certificate dry-run");
    assert!(
        output.status.success(),
        "verdict-certificate dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    assert!(
        command_messages
            .iter()
            .any(|message| message.contains("omcpb build -p oraclemcp --bin oraclemcp")),
        "verdict-certificate dry-run did not schedule the omcpb package build: {command_messages:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "verdict_certificate"),
        "missing passing verdict-certificate completion: {events:?}"
    );
    let runner =
        std::fs::read_to_string(root.join("scripts/e2e/run_all.sh")).expect("read run_all.sh");
    assert!(
        runner.contains("scripts/e2e/verdict_certificate.sh"),
        "served verdict-certificate proof must be dispatched by run_all.sh"
    );
}

/// Arc G's cost proof is release evidence only when the served scenario stays
/// on the ordinary E2E path and builds through the repository wrapper.
#[test]
fn cost_gate_e2e_dry_run_is_registered_and_schedules_omcpb() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e/cost_gate.sh"))
        .args(["--log", "--dry-run", "--lane", "free23"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env("ORACLEMCP_LIVE_XE", "1")
        .env("ORACLE_MATRIX_FREE23_DSN", "localhost:1522/FREEPDB1")
        .env("ORACLE_MATRIX_FREE23_USER", "E2E_TEST")
        .env("ORACLE_MATRIX_FREE23_PASSWORD", "not-used-in-dry-run")
        .output()
        .expect("run cost-gate dry-run");
    assert!(
        output.status.success(),
        "cost-gate dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    assert!(
        command_messages
            .iter()
            .any(|message| message.contains("omcpb build -p oraclemcp --bin oraclemcp")),
        "cost-gate dry-run did not schedule the omcpb package build: {command_messages:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "cost_gate"),
        "missing passing cost-gate completion: {events:?}"
    );
    let runner =
        std::fs::read_to_string(root.join("scripts/e2e/run_all.sh")).expect("read run_all.sh");
    assert!(
        runner.contains("scripts/e2e/cost_gate.sh"),
        "served cost-gate proof must be dispatched by run_all.sh"
    );
}

/// Arc J's corpus proof must drive the served binary, and registration is part
/// of the contract: a script absent from `run_all.sh` is not e2e coverage.
#[test]
fn refusal_corpus_e2e_dry_run_is_registered_and_schedules_omcpb() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e/refusal_corpus.sh"))
        .args(["--log", "--dry-run"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .output()
        .expect("run refusal_corpus dry-run");
    assert!(
        output.status.success(),
        "refusal_corpus dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    assert!(
        command_messages
            .iter()
            .any(|message| message.contains("omcpb build -p oraclemcp --bin oraclemcp")),
        "refusal-corpus dry-run did not schedule the omcpb package build: {command_messages:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "refusal_corpus"),
        "missing passing refusal-corpus completion: {events:?}"
    );
    let runner =
        std::fs::read_to_string(root.join("scripts/e2e/run_all.sh")).expect("read run_all.sh");
    assert!(
        runner.contains("scripts/e2e/refusal_corpus.sh"),
        "served refusal-corpus proof must be dispatched by run_all.sh"
    );
}

/// Arc M must prove masking at the actual served MCP boundary. Keeping the
/// scenario in the ordinary runner prevents the real-wire proof from becoming
/// an uncalled script beside the direct DB-layer egress tests.
#[test]
fn served_egress_e2e_dry_run_is_registered_and_schedules_omcpb() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e/served_egress.sh"))
        .args(["--log", "--dry-run"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env("ORACLEMCP_LIVE_XE", "1")
        .env("ORACLEMCP_SERVED_EGRESS_DSN", "localhost:1522/FREEPDB1")
        .env("ORACLEMCP_SERVED_EGRESS_USER", "e2e_test")
        .env("ORACLEMCP_SERVED_EGRESS_PASSWORD", "not-used-in-dry-run")
        .output()
        .expect("run served_egress dry-run");
    assert!(
        output.status.success(),
        "served_egress dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    assert!(
        command_messages
            .iter()
            .any(|message| message.contains("omcpb build -p oraclemcp --bin oraclemcp")),
        "served-egress dry-run did not schedule the omcpb package build: {command_messages:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "served_egress"),
        "missing passing served-egress completion: {events:?}"
    );
    let runner =
        std::fs::read_to_string(root.join("scripts/e2e/run_all.sh")).expect("read run_all.sh");
    assert!(
        runner.contains("scripts/e2e/served_egress.sh"),
        "served governed-egress proof must be dispatched by run_all.sh"
    );
}

/// The reversible-workspace matrix (Arc I) must be reachable from the runner and
/// must schedule its own build, exactly like every other live scenario. Without
/// this test and its `run_all.sh` entry the script would sit on disk being
/// nobody's coverage: it was written, landed, and then never executed anywhere.
#[test]
fn reversible_e2e_dry_run_uses_omcpb_and_reports_a_pass() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e/reversible.sh"))
        .args(["--log", "--dry-run", "--lane", "xe18"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env("ORACLEMCP_LIVE_XE", "1")
        .env("ORACLE_MATRIX_XE18_USER", "e2e_test")
        .env("ORACLE_MATRIX_XE18_PASSWORD", "not-used-in-dry-run")
        .output()
        .expect("run reversible dry-run");
    assert!(
        output.status.success(),
        "reversible dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    assert!(
        command_messages
            .iter()
            .any(|message| message.contains("omcpb build -p oraclemcp --bin oraclemcp")),
        "reversible dry-run did not schedule the omcpb package build: {command_messages:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "reversible"),
        "missing passing reversible completion: {events:?}"
    );
}

/// Arc H's fleet proof must be in the ordinary e2e sweep and must schedule its
/// package build through the swarm wrapper. A script left off `run_all.sh` is
/// not coverage, and a direct Cargo path would bypass the pinned build lane.
#[test]
fn fleet_e2e_dry_run_is_registered_and_schedules_omcpb() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e/fleet.sh"))
        .args(["--log", "--dry-run", "--lane", "xe18", "--lane", "xe21"])
        .current_dir(&root)
        .env("ORACLEMCP_E2E_SEED", "4242")
        .env(
            "ORACLEMCP_E2E_ARTIFACT_DIR",
            root.join("target/e2e-contract"),
        )
        .env("ORACLEMCP_LIVE_XE", "1")
        .env("ORACLE_MATRIX_XE18_USER", "e2e_test")
        .env("ORACLE_MATRIX_XE18_PASSWORD", "not-used-in-dry-run")
        .env("ORACLE_MATRIX_XE21_USER", "e2e_test")
        .env("ORACLE_MATRIX_XE21_PASSWORD", "not-used-in-dry-run")
        .output()
        .expect("run fleet dry-run");
    assert!(
        output.status.success(),
        "fleet dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = json_lines(&output.stderr);
    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    assert!(
        command_messages
            .iter()
            .any(|message| message.contains("omcpb build -p oraclemcp --bin oraclemcp")),
        "fleet dry-run did not schedule the omcpb package build: {command_messages:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "fleet"),
        "missing passing fleet completion: {events:?}"
    );
    let runner =
        std::fs::read_to_string(root.join("scripts/e2e/run_all.sh")).expect("read run_all.sh");
    assert!(
        runner.contains("scripts/e2e/fleet.sh"),
        "fleet live matrix must be dispatched by run_all.sh"
    );
}

/// A scenario that is not in `run_all.sh` never runs in the sweep, so "we have an
/// e2e for that" quietly stops being true. Pin the registration itself: every
/// scenario script in scripts/e2e/ is either dispatched by the runner or is a
/// deliberately release/operator-gated script that carries its own harness test
/// here. Nothing is allowed to be neither.
#[test]
fn every_e2e_scenario_script_is_reachable_from_the_runner_or_its_own_test() {
    let root = repo_root();
    let runner =
        std::fs::read_to_string(root.join("scripts/e2e/run_all.sh")).expect("read run_all.sh");
    let harness = std::fs::read_to_string(root.join("crates/oraclemcp/tests/e2e_harness.rs"))
        .expect("read e2e_harness.rs");

    // Release/operator gates: run from the release suites and pinned by their own
    // dry-run tests above, deliberately not part of the standard sweep.
    let gated = ["hardening_acceptance.sh", "real_adb_tcps_signoff.sh"];
    // The runner and the shared library are not scenarios.
    let infra = ["run_all.sh", "lib.sh"];

    let mut orphans = Vec::new();
    for entry in std::fs::read_dir(root.join("scripts/e2e")).expect("read scripts/e2e") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("sh") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("script name")
            .to_owned();
        if infra.contains(&name.as_str()) || gated.contains(&name.as_str()) {
            continue;
        }
        let dispatched = runner.contains(&format!("scripts/e2e/{name}"));
        let self_tested = harness.contains(&format!("scripts/e2e/{name}"));
        if !dispatched && !self_tested {
            orphans.push(name);
        }
    }
    assert!(
        orphans.is_empty(),
        "e2e scripts that no runner and no test ever execute — they are not coverage, \
         they are files: {orphans:?}"
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
fn distribution_renderer_accepts_bound_platform_checksums_and_hashes_exact_archives() {
    let artifact_dir = distribution_fixture("formats-pass");
    let hashes = write_distribution_archives(&artifact_dir);
    write_valid_distribution_sidecars(&artifact_dir, &hashes);
    let output_dir = artifact_dir.join("rendered");

    let output = run_distribution_renderer(&artifact_dir, &output_dir);
    assert!(
        output.status.success(),
        "GNU, BSD, and certutil checksum records must pass: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let formula = std::fs::read_to_string(output_dir.join("homebrew/Formula/oraclemcp.rb"))
        .expect("read rendered Homebrew formula");
    assert!(
        formula.contains(&format!("sha256 \"{}\"", hashes[0]))
            && formula.contains(&format!("sha256 \"{}\"", hashes[1])),
        "Homebrew digests must equal fresh hashes of the referenced archives: {formula}"
    );

    let winget = std::fs::read_to_string(
        output_dir
            .join("winget/manifests/m/MuhDur/oraclemcp/9.9.9/MuhDur.oraclemcp.installer.yaml"),
    )
    .expect("read rendered winget manifest");
    assert!(
        winget.contains(&format!(
            "InstallerSha256: {}",
            hashes[2].to_ascii_uppercase()
        )),
        "winget digest must equal a fresh hash of the referenced archive: {winget}"
    );
}

#[test]
fn distribution_renderer_rejects_unbound_or_tampered_checksum_inputs_before_rendering() {
    for scenario in [
        "wrong-filename",
        "other-archive-digest",
        "extra-record",
        "prefix-suffix-junk",
        "missing-archive",
        "mutated-archive",
    ] {
        let artifact_dir = distribution_fixture(scenario);
        let hashes = write_distribution_archives(&artifact_dir);
        write_valid_distribution_sidecars(&artifact_dir, &hashes);
        let target = DISTRIBUTION_ASSETS[0];
        let target_sidecar = artifact_dir.join(format!("{target}.sha256"));

        match scenario {
            "wrong-filename" => std::fs::write(
                &target_sidecar,
                format!("{}  another-archive.tar.gz\n", hashes[0]),
            )
            .expect("write wrong-filename checksum"),
            "other-archive-digest" => {
                std::fs::write(&target_sidecar, format!("{}  {target}\n", hashes[1]))
                    .expect("write another archive's digest")
            }
            "extra-record" => std::fs::write(
                &target_sidecar,
                format!(
                    "{}  {target}\n{}  extra-archive.tar.gz\n",
                    hashes[0], hashes[0]
                ),
            )
            .expect("write extra checksum record"),
            "prefix-suffix-junk" => {
                std::fs::write(&target_sidecar, format!("prefix={} suffix\n", hashes[0]))
                    .expect("write checksum junk")
            }
            "missing-archive" => {
                std::fs::rename(
                    artifact_dir.join(target),
                    artifact_dir.join(format!("{target}.withheld")),
                )
                .expect("withhold release archive fixture");
            }
            "mutated-archive" => {
                use std::io::Write as _;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(artifact_dir.join(target))
                    .expect("open release archive fixture")
                    .write_all(b"mutated-byte")
                    .expect("mutate release archive fixture");
            }
            _ => unreachable!("scenario list is exhaustive"),
        }

        let output_dir = artifact_dir.join("rendered");
        let output = run_distribution_renderer(&artifact_dir, &output_dir);
        assert!(
            !output.status.success(),
            "{scenario} must fail closed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output_dir.exists(),
            "{scenario} must fail before writing any distribution manifest"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("render_distribution_manifests:"),
            "{scenario} failure must identify the release gate: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn release_upload_is_sequentially_blocked_by_distribution_verification() {
    let workflow = std::fs::read_to_string(repo_root().join(".github/workflows/release.yml"))
        .expect("read release workflow");
    let verify = workflow
        .find("- name: Generate Homebrew and winget manifests")
        .expect("release workflow has distribution verification step");
    let upload = workflow
        .find("- name: Publish release with checksums, SBOM, and signatures")
        .expect("release workflow has package upload step");
    assert!(
        verify < upload,
        "verification must run before package upload"
    );
    assert!(
        workflow[verify..upload]
            .contains("run: bash scripts/render_distribution_manifests.sh artifacts"),
        "release verification must execute the fail-closed renderer directly"
    );
    assert!(
        !workflow[verify..upload].contains("continue-on-error"),
        "release verification failure must prevent the upload step"
    );
}

#[test]
fn workflow_supply_chain_check_uses_runner_baseline_tools() {
    let script =
        std::fs::read_to_string(repo_root().join("scripts/workflow_supply_chain_check.sh"))
            .expect("read workflow supply-chain check");
    assert!(
        !script
            .lines()
            .any(|line| line.trim_start().starts_with("rg ")),
        "the dependency-free web runner does not provision ripgrep"
    );

    let output = run_script("scripts/workflow_supply_chain_check.sh", &[]);
    assert!(
        output.status.success(),
        "workflow supply-chain check failed: {}",
        String::from_utf8_lossy(&output.stderr)
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
    let missing_versions = run_script(
        "scripts/e2e/release_rollback_dry_run.sh",
        &["--log", "--dry-run"],
    );
    assert!(
        !missing_versions.status.success(),
        "rollback dry-run must refuse an implicit outward-facing version"
    );
    assert!(
        String::from_utf8_lossy(&missing_versions.stderr)
            .contains("both --broken-version and --previous-good are required"),
        "missing-version refusal was not actionable: {}",
        String::from_utf8_lossy(&missing_versions.stderr)
    );

    let output = run_script(
        "scripts/e2e/release_rollback_dry_run.sh",
        &[
            "--log",
            "--dry-run",
            "--broken-version",
            "9.9.9",
            "--previous-good",
            "9.9.8",
        ],
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
        "tag pipeline channels: crates.io, GitHub release, signed artifacts, GHCR, MCP registry; pending registry promotion: Homebrew, winget",
        "release.yml owns tag publication; docker.yml and publish-mcp.yml are manual recovery auxiliaries",
        "cargo yank -p oraclemcp-error --vers 9.9.9",
        "cargo yank -p oraclemcp-telemetry --vers 9.9.9",
        "cargo yank -p oraclemcp-audit --vers 9.9.9",
        "cargo yank -p oraclemcp-guard --vers 9.9.9",
        "cargo yank -p oraclemcp-config --vers 9.9.9",
        "cargo yank -p oraclemcp-db --vers 9.9.9",
        "cargo yank -p oraclemcp-auth --vers 9.9.9",
        "cargo yank -p oraclemcp-core --vers 9.9.9",
        "cargo yank -p oraclemcp --vers 9.9.9",
        "approval=irreversible condition=exact oraclemcp@9.9.9 is published and operator approved yank",
        "gh release edit v9.9.9 --prerelease",
        "approval=destructive-optional condition=artifacts must be hidden",
        "gh release delete v9.9.9 --yes --cleanup-tag",
        "gh workflow run docker.yml -f version=9.9.8 -f variant=core -f operation=rollback",
        "MCP registry: published versions are immutable and cannot be unpublished",
        "cut a fixed higher version through release.yml because republishing 9.9.8 cannot become latest",
        "Homebrew: only submit a rollback formula update if brew info resolves 9.9.9",
        "winget: only submit a rollback manifest update if winget show resolves 9.9.9",
        "rollback plan is non-mutating and covers the current tag pipeline",
    ] {
        assert!(
            messages.iter().any(|message| message.contains(expected)),
            "rollback runbook dry-run did not cover {expected}: {messages:?}"
        );
    }
    for unsupported_command in [
        "npm deprecate",
        "npm dist-tag",
        "variant=plsql-intelligence",
        "git restore --source=v9.9.8 -- server.json",
        "gh workflow run publish-mcp.yml --ref main",
    ] {
        assert!(
            messages
                .iter()
                .all(|message| !message.contains(unsupported_command)),
            "rollback plan emitted unsupported command {unsupported_command}: {messages:?}"
        );
    }

    let release_workflow =
        std::fs::read_to_string(repo_root().join(".github/workflows/release.yml"))
            .expect("read tag release workflow");
    assert!(release_workflow.contains("tags: [\"v*\"]"));
    assert!(release_workflow.contains(
        "ROLLBACK_COVERAGE: crates.io=publish-crates github-release=release \
         signed-artifacts=release ghcr=docker mcp-registry=publish-mcp-registry"
    ));
    for job in [
        "  publish-crates:",
        "  release:",
        "  docker:",
        "  publish-mcp-registry:",
    ] {
        assert!(
            release_workflow.contains(job),
            "tag publication topology changed without rollback coverage: missing {job}"
        );
    }
    for auxiliary in [
        ".github/workflows/docker.yml",
        ".github/workflows/publish-mcp.yml",
    ] {
        let workflow = std::fs::read_to_string(repo_root().join(auxiliary))
            .unwrap_or_else(|error| panic!("read {auxiliary}: {error}"));
        assert!(workflow.contains("  workflow_dispatch:"));
        assert!(
            !workflow.lines().any(|line| line == "  push:"),
            "{auxiliary} must remain dispatch-only"
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
