use std::collections::BTreeSet;
use std::fs;
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
        .env("ORACLEMCP_E2E_SEED", "6060")
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

fn read_repo_file(path: &str) -> String {
    fs::read_to_string(repo_root().join(path)).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn assert_contains_all(label: &str, haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            haystack.contains(needle),
            "{label} is missing required B.8 proof marker `{needle}`"
        );
    }
}

#[test]
fn read_only_dashboard_acceptance_gate_has_structured_dry_run() {
    let output = run_script("scripts/e2e/dashboard_readonly.sh", &["--log", "--dry-run"]);
    assert!(
        output.status.success(),
        "dashboard_readonly dry-run failed: {}",
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
        assert_eq!(event["lane"], "dashboard", "unexpected lane: {event}");
        assert_eq!(event["profile"], "operator", "unexpected profile: {event}");
        assert_eq!(event["level"], "READ_ONLY", "unexpected level: {event}");
    }

    let command_messages = events
        .iter()
        .filter(|event| event["event"] == "command_start")
        .filter_map(|event| event["message"].as_str())
        .collect::<Vec<_>>();
    for expected in [
        "scripts/dashboard_skin_lint.sh",
        "scripts/sensitive_data_lint.sh",
        "scripts/dashboard_bundle_check.sh",
        "tsc -p web/tsconfig.json --noEmit",
        "vite build web",
    ] {
        assert!(
            command_messages
                .iter()
                .any(|message| message.contains(expected)),
            "dashboard gate did not schedule {expected}: {command_messages:?}"
        );
    }
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "dashboard_readonly"),
        "missing passing dashboard scenario completion: {events:?}"
    );
}

#[test]
fn read_only_dashboard_surface_contracts_are_registered() {
    let app = read_repo_file("web/src/app/App.tsx");
    let client = read_repo_file("web/src/app/operator-client.ts");
    let skin = read_repo_file("web/src/app/skin.tsx");
    let presentation = read_repo_file("web/src/app/presentation-model.ts");

    for label in [
        "Overview",
        "Sessions",
        "Health",
        "Capacity",
        "Config",
        "Explorer",
        "Reviews",
        "Workbench",
        "Audit",
        "Doctor",
    ] {
        assert!(
            app.contains(&format!("label: \"{label}\"")),
            "dashboard nav is missing {label}"
        );
    }
    for component in [
        "function OverviewPage",
        "function SessionsPage",
        "function HealthPage",
        "function CapacityPage",
        "function ConfigPage",
        "function ExplorerPage",
        "function ReviewsPage",
        "function WorkbenchPage",
        "function AuditPage",
        "function DoctorPage",
    ] {
        assert!(
            app.contains(component),
            "missing dashboard page component {component}"
        );
    }

    for aria_label in [
        "aria-label=\"dashboard\"",
        "aria-label=\"overview metrics\"",
        "aria-label=\"connection health\"",
        "aria-label=\"capacity metrics\"",
        "aria-label=\"ground control\"",
        "aria-label=\"big board\"",
        "aria-label=\"big board table\"",
    ] {
        assert!(
            app.contains(aria_label) || skin.contains(aria_label),
            "missing accessibility anchor {aria_label}"
        );
    }

    assert!(
        client.matches("credentials: \"same-origin\"").count() >= 4,
        "dashboard client must stay same-origin cookie based"
    );
    assert!(
        client.contains("headers[session.csrf_header] = session.csrf_token"),
        "dashboard writes must send the CSRF header from the session"
    );
    assert!(
        client.contains("headers[session.action_ticket_header] = actionTicket"),
        "dashboard writes must send the per-action ticket header"
    );
    assert!(
        !client.contains("localStorage") && !client.contains("sessionStorage"),
        "dashboard client must not persist operator tokens in browser storage"
    );

    assert!(
        skin.contains("defaultBigBoard: \"board2d\""),
        "0.6.0 dashboard must default to the 2D board renderer"
    );
    assert!(
        skin.contains("board2d:") && skin.contains("requiresWebGl: false"),
        "dashboard skin must include a no-WebGL 2D renderer"
    );
    assert!(
        skin.contains("table:") && skin.contains("requiresWebGl: false"),
        "dashboard skin must include a no-WebGL table fallback"
    );
    assert!(
        presentation.contains("\"board2d\"")
            && presentation.contains("\"table\"")
            && presentation.contains("\"orrery3d\""),
        "presentation grammar must keep all required big-board renderer slots"
    );
}

#[test]
fn skin_conformance_2d_fallback_a11y() {
    let app = read_repo_file("web/src/app/App.tsx");
    let client = read_repo_file("web/src/app/operator-client.ts");
    let skin = read_repo_file("web/src/app/skin.tsx");
    let presentation = read_repo_file("web/src/app/presentation-model.ts");

    assert_contains_all(
        "dashboard accessibility anchors",
        &app,
        &[
            "aria-label=\"dashboard\"",
            "aria-label=\"overview metrics\"",
            "aria-label=\"connection health\"",
            "aria-label=\"capacity metrics\"",
            "aria-label=\"Config draft TOML\"",
            "aria-label=\"proposal author\"",
            "aria-label=\"proposal unit\"",
            "aria-label=\"workbench mode\"",
        ],
    );
    assert_contains_all(
        "dashboard skin",
        &skin,
        &[
            "defaultBigBoard: \"board2d\"",
            "board2d:",
            "requiresWebGl: false",
            "table:",
            "orrery3d:",
            "requiresWebGl: true",
            "lazy: true",
            "React.lazy(() => import(\"./orrery-renderer\"))",
            "assertDashboardSkinConformance(GROUND_CONTROL_SKIN)",
        ],
    );
    assert_contains_all(
        "presentation grammar",
        &presentation,
        &[
            "export type BigBoardRendererKind = \"orrery3d\" | \"board2d\" | \"table\"",
            "REQUIRED_BIG_BOARD_RENDERERS",
            "normalizeRendererChoice",
            "return capabilities.webgl && !capabilities.reducedMotion",
            "return rendererAvailable(\"board2d\") ? \"board2d\" : \"table\"",
        ],
    );

    for forbidden in [
        "localStorage",
        "sessionStorage",
        "credential_ref",
        "connect_string",
        "wallet_password_ref",
        "keyring:prod/app",
        "file:/run/secrets/oracle-wallet",
        "literal:",
    ] {
        assert!(
            !app.contains(forbidden) && !client.contains(forbidden),
            "dashboard rendered/client code must not expose sensitive marker `{forbidden}`"
        );
    }
}

#[test]
fn b8_dashboard_acceptance_suite_is_accounted() {
    let plan = read_repo_file("PLAN_0_6_0_INTERACTIVE_ALWAYS_ON.md");
    let http = read_repo_file("crates/oraclemcp-core/src/http.rs");
    let bundle = read_repo_file("scripts/dashboard_bundle_check.sh");
    let readonly_gate = read_repo_file("scripts/e2e/dashboard_readonly.sh");
    let conformance = read_repo_file("tests/conformance/COVERAGE.md");
    let e2e_coverage = read_repo_file("scripts/e2e/COVERAGE.md");

    assert_contains_all(
        "Appendix B.8 plan",
        &plan,
        &[
            "embedded_bundle_served_and_audited",
            "malicious_page_cannot_trigger_gated_action",
            "config_draft_apply_atomic_rollback",
            "workbench_no_bypass_guard_is_the_feature",
            "cp_apply_reclassifies_never_trusts_stored_verdict",
            "skin_conformance_2d_fallback_a11y",
        ],
    );
    assert_contains_all(
        "HTTP/operator proof tests",
        &http,
        &[
            "dashboard_bundle_serves_html_without_api_fallback",
            "malicious_page_cannot_trigger_dashboard_gated_action",
            "operator_config_draft_apply_and_rollback_are_redacted_and_audited",
            "workbench_no_bypass_guard_is_the_feature",
            "dashboard_workbench_ddl_apply_is_release_gated",
            "cp_apply_reclassifies_never_trusts_stored_verdict",
            "dashboard_csp",
            "frame-ancestors 'none'",
            "x-frame-options",
        ],
    );
    assert_contains_all(
        "dashboard bundle gate",
        &bundle,
        &[
            "npm audit --audit-level=high",
            "package-lock.json",
            "CycloneDX",
            "oraclemcp-dashboard.sha256",
        ],
    );
    assert_contains_all(
        "dashboard e2e gate",
        &readonly_gate,
        &[
            "scripts/dashboard_skin_lint.sh",
            "scripts/sensitive_data_lint.sh",
            "scripts/dashboard_bundle_check.sh",
            "tsc -p web/tsconfig.json --noEmit",
            "vite build web",
        ],
    );
    assert_contains_all(
        "conformance coverage",
        &conformance,
        &[
            "DASHBOARD-B8-001",
            "DASHBOARD-B8-002",
            "DASHBOARD-B8-003",
            "DASHBOARD-B8-004",
            "DASHBOARD-B8-005",
            "DASHBOARD-B8-006",
        ],
    );
    assert_contains_all(
        "e2e coverage",
        &e2e_coverage,
        &[
            "WP-W B.8 dashboard acceptance suite",
            "oraclemcp-epic-060-f4xo.8.20",
        ],
    );
}
