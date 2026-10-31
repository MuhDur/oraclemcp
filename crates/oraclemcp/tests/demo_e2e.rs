//! Live `oraclemcp demo` proof on a real Docker host (opt-in: set
//! `ORACLEMCP_DEMO_E2E=1`). Each test checks Docker independently afterwards:
//! no container carrying the run's label may remain, and every container that
//! existed beforehand (for example the lab lanes) must still exist.
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

fn enabled(test: &str) -> bool {
    let on = std::env::var("ORACLEMCP_DEMO_E2E").as_deref() == Ok("1");
    if !on {
        eprintln!("[demo-e2e] SKIP {test}: set ORACLEMCP_DEMO_E2E=1 on a Docker host");
    }
    on
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn docker(args: &[&str]) -> String {
    let output = Command::new("docker").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn all_containers() -> BTreeSet<String> {
    docker(&["ps", "-a", "-q", "--no-trunc"])
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Run `oraclemcp --json demo <args>` with no inherited `ORACLEMCP_*` settings.
fn demo(args: &[&str]) -> (i32, Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("ORACLEMCP_")) {
        command.env_remove(key);
    }
    let output = command
        .arg("--json")
        .arg("demo")
        .args(args)
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "demo --json output: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    (output.status.code().unwrap_or(-1), report)
}

fn assert_no_leftover(report: &Value, before: &BTreeSet<String>) {
    let token = report["run_token"]
        .as_str()
        .expect("a started demo has a run token");
    let filter = format!("label=oraclemcp.demo.run={token}");
    let left = docker(&["ps", "-a", "-q", "--filter", &filter]);
    assert!(left.trim().is_empty(), "demo container left behind: {left}");
    let after = all_containers();
    let missing: Vec<_> = before.difference(&after).collect();
    assert!(
        missing.is_empty(),
        "the demo removed containers it did not create: {missing:?}"
    );
}

fn golden_lines() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/demo/transcript.md");
    let golden = std::fs::read_to_string(path).unwrap();
    let block = golden
        .split("```text\n")
        .nth(1)
        .and_then(|rest| rest.split("\n```").next())
        .expect("golden transcript block");
    block.lines().map(str::to_owned).collect()
}

#[test]
fn demo_e2e_full_flow() {
    if !enabled("demo_e2e_full_flow") {
        return;
    }
    let before = all_containers();
    let port = free_port();
    let (code, report) = demo(&["--yes", "--port", &port.to_string()]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["outcome"], "completed", "{report}");
    assert_eq!(report["teardown"], "completed", "{report}");
    let steps: Vec<_> = report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| {
            assert_eq!(step["ok"], true, "{step}");
            step["step"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(
        steps,
        [
            "container",
            "database_ready",
            "seed",
            "initialize",
            "refuse",
            "preview",
            "confirm",
            "rollback",
            "audit_verify"
        ]
    );
    let token = report["run_token"].as_str().unwrap();
    let transcript: Vec<String> = report["transcript"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| {
            line.as_str()
                .unwrap()
                .replace(token, "[TOKEN]")
                .replace(&format!("127.0.0.1:{port}"), "127.0.0.1:[PORT]")
                .replace("(present locally)", "([IMAGE_STATE])")
                .replace(
                    "(not present; docker pulls it on first start, about 2 GB)",
                    "([IMAGE_STATE])",
                )
        })
        .collect();
    assert_eq!(transcript, golden_lines());
    assert_no_leftover(&report, &before);
}

#[test]
fn demo_e2e_budget_exceeded_tears_down() {
    if !enabled("demo_e2e_budget_exceeded_tears_down") {
        return;
    }
    let before = all_containers();
    // FREE 23ai needs well over ten seconds to open its PDB.
    let (code, report) = demo(&[
        "--yes",
        "--port",
        &free_port().to_string(),
        "--timeout-secs",
        "10",
    ]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["outcome"], "failed", "{report}");
    assert!(
        report["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("time budget exceeded")),
        "{report}"
    );
    assert_eq!(report["teardown"], "completed", "{report}");
    assert_no_leftover(&report, &before);
}
