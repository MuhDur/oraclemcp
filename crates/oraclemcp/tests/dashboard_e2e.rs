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
        "Clients",
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
        "function ClientsPage",
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
fn wd_search_global_explorer_uses_guarded_dictionary_tools() {
    let app = read_repo_file("web/src/app/App.tsx");
    let client = read_repo_file("web/src/app/operator-client.ts");
    let behavior = read_repo_file("docs/behavior-inventory.md");
    let readme = read_repo_file("README.md");

    assert_contains_all(
        "Explorer global search UI",
        &app,
        &[
            "function ExplorerGlobalSearchPanel",
            "Global Search",
            "All visible schemas",
            "Object Matches",
            "Source Matches",
            "explorerSourceSearchTypes",
            "fetchExplorerObjects(session.data",
            "fetchExplorerSourceSearch(session.data",
            "tool: \"oracle_search_objects\"",
            "tool: \"oracle_search_source\"",
            "owner: ownerFilter",
            "object_type: globalSearchRequest.sourceType",
            "sourceRowsFromResponse",
        ],
    );
    assert_contains_all(
        "Explorer source-search client",
        &client,
        &[
            "export type ExplorerSourceSearchRequest",
            "export async function fetchExplorerSourceSearch",
            "operatorPost(\"/operator/v1/actions/execute\"",
            "idempotency_key: requestId(\"explorer-source-search\")",
            "tool: \"oracle_search_source\"",
            "needle: request.needle.trim()",
        ],
    );
    assert_contains_all(
        "Explorer global search docs",
        &readme,
        &[
            "global search across visible schemas",
            "`oracle_search_objects` with all object types",
            "`oracle_search_source`",
        ],
    );
    assert_contains_all(
        "behavior inventory",
        &behavior,
        &["oracle_search_source", "global object/source search"],
    );
}

#[test]
fn wd_ide_workbench_uses_static_plsql_tools() {
    let app = read_repo_file("web/src/app/App.tsx");
    let client = read_repo_file("web/src/app/operator-client.ts");
    let http = read_repo_file("crates/oraclemcp-core/src/http.rs");
    let operations = read_repo_file("docs/operations.md");
    let readme = read_repo_file("README.md");

    assert_contains_all(
        "Workbench PL/SQL IDE UI",
        &app,
        &[
            "function WorkbenchIdePanel",
            "PL/SQL IDE",
            "workbenchIdeRequest",
            "plsqlDefinitionsFromResponse",
            "identifierOccurrences",
            "buildRefactorPreview",
            "oracle_plsql_parse",
            "oracle_plsql_analyze",
            "oracle_plsql_lineage",
            "oracle_plsql_sast",
            "oracle_plsql_doc",
            "oracle_plsql_what_breaks",
        ],
    );
    assert_contains_all(
        "Workbench PL/SQL IDE client",
        &client,
        &[
            "type WorkbenchPlsqlTool",
            "runWorkbenchPlsqlTool",
            "/operator/v1/actions/execute",
            "tool: request.tool",
            "arguments: request.arguments",
        ],
    );
    assert_contains_all(
        "operator static PL/SQL allowlist",
        &http,
        &[
            "oracle_plsql_parse",
            "oracle_plsql_analyze",
            "oracle_plsql_what_breaks",
            "oracle_plsql_lineage",
            "oracle_plsql_sast",
            "oracle_plsql_doc",
            "operator_execute_allows_read_only_metadata_tools_for_explorer",
        ],
    );
    assert_contains_all(
        "operator docs for Workbench PL/SQL IDE",
        &operations,
        &[
            "Workbench IDE panel",
            "oracle_plsql_parse",
            "oracle_plsql_analyze",
            "oracle_plsql_lineage",
            "oracle_plsql_sast",
            "oracle_plsql_doc",
            "oracle_plsql_what_breaks",
            "live PL/SQL snapshot/blast-radius tools",
            "remain MCP-only",
        ],
    );
    assert_contains_all(
        "README Workbench PL/SQL IDE",
        &readme,
        &[
            "Workbench IDE panel",
            "oracle_plsql_parse",
            "oracle_plsql_analyze",
            "oracle_plsql_lineage",
            "oracle_plsql_sast",
            "oracle_plsql_doc",
            "oracle_plsql_what_breaks",
            "browser allowlist",
        ],
    );
}

#[test]
fn w8b_proof_bundle_is_redacted_and_exportable() {
    let app = read_repo_file("web/src/app/App.tsx");
    let client = read_repo_file("web/src/app/operator-client.ts");
    let http = read_repo_file("crates/oraclemcp-core/src/http.rs");
    let operations = read_repo_file("docs/operations.md");
    let conformance = read_repo_file("tests/conformance/COVERAGE.md");
    let e2e_coverage = read_repo_file("scripts/e2e/COVERAGE.md");

    assert_contains_all(
        "operator proof-bundle export",
        &http,
        &[
            "audit_tail_filters_exports_redacted_proof_bundle",
            "export=proof-bundle",
            "oraclemcp.audit.proof-bundle.v1",
            "\"subject_id_hash\"",
            "\"sql_sha256\"",
            "\"db_evidence\"",
            "\"bind_values\"",
            "sql_sha256_only",
            "subject_id_hash_only",
            "not_stored_redacted_by_default",
            "human@example.test",
            "sensitive-bind-value",
            "UPDATE accounts",
        ],
    );
    assert_contains_all(
        "dashboard proof-bundle UI",
        &app,
        &[
            "exportProofBundle",
            "AuditProofBundlePanel",
            "Proof Bundle",
            "data?.export",
            "<Download className=\"size-4\"",
            "prettyJson(bundle)",
        ],
    );
    assert_contains_all(
        "dashboard proof-bundle client",
        &client,
        &[
            "exportProofBundle: boolean",
            "params.set(\"export\", \"proof-bundle\")",
            "fetch(`/operator/v1/audit-tail",
            "credentials: \"same-origin\"",
        ],
    );
    assert_contains_all(
        "operations proof-bundle docs",
        &operations,
        &[
            "export=proof-bundle",
            "allow-list-first",
            "raw subject ids, SQL",
            "bind values, and secrets are not exported",
            "`sql_sha256`, DB-evidence columns, chain hashes/signature metadata",
        ],
    );
    assert_contains_all(
        "conformance proof-bundle coverage",
        &conformance,
        &[
            "DASHBOARD-B8-008",
            "audit_tail_filters_exports_redacted_proof_bundle",
            "w8b_proof_bundle_is_redacted_and_exportable",
            "AuditProofBundlePanel",
            "fetchAuditTail",
        ],
    );
    assert_contains_all(
        "e2e proof-bundle coverage",
        &e2e_coverage,
        &[
            "W8b proof bundle for gated actions",
            "oraclemcp-epic-060-f4xo.8.10",
            "audit_tail_filters_exports_redacted_proof_bundle",
        ],
    );
}

#[test]
fn w10_client_credentials_screen_is_redacted_and_isolated() {
    let app = read_repo_file("web/src/app/App.tsx");
    let client = read_repo_file("web/src/app/operator-client.ts");
    let http = read_repo_file("crates/oraclemcp-core/src/http.rs");
    let dashboard_auth = read_repo_file("crates/oraclemcp-core/src/dashboard_auth.rs");
    let conformance = read_repo_file("tests/conformance/COVERAGE.md");
    let e2e_coverage = read_repo_file("scripts/e2e/COVERAGE.md");

    assert_contains_all(
        "operator client credential routes",
        &http,
        &[
            "operator_client_credentials_screen_lists_rotates_revokes_without_token_leak",
            "/operator/v1/client-credentials",
            "/operator/v1/client-credentials/rotate",
            "/operator/v1/client-credentials/revoke",
            "bearer_shown_once",
            "close_http_principal_sessions",
            "credential_hash",
            "credential_salt",
            "client_credentials_unavailable",
        ],
    );
    assert_contains_all(
        "dashboard client credential tickets",
        &dashboard_auth,
        &[
            "(\"POST\", \"/operator/v1/client-credentials/rotate\")",
            "(\"POST\", \"/operator/v1/client-credentials/revoke\")",
        ],
    );
    assert_contains_all(
        "dashboard client credential API",
        &client,
        &[
            "export type ClientCredentialView",
            "export async function fetchClientCredentials",
            "operatorGet(\"/operator/v1/client-credentials\")",
            "export async function rotateClientCredential",
            "operatorPost(\"/operator/v1/client-credentials/rotate\"",
            "export async function revokeClientCredential",
            "operatorPost(\"/operator/v1/client-credentials/revoke\"",
            "credentials: \"same-origin\"",
        ],
    );
    assert_contains_all(
        "dashboard client credential UI",
        &app,
        &[
            "label: \"Clients\"",
            "function ClientsPage",
            "function ClientCredentialTable",
            "function ClientCredentialBearerPanel",
            "fetchClientCredentials",
            "rotateClientCredential",
            "revokeClientCredential",
            "Rotated Bearer",
            "bearer_shown_once",
            "last_source_addr",
        ],
    );
    assert_contains_all(
        "client credential conformance",
        &conformance,
        &[
            "HTTP-AUTH-005",
            "DASHBOARD-B8-009",
            "operator_client_credentials_screen_lists_rotates_revokes_without_token_leak",
            "w10_client_credentials_screen_is_redacted_and_isolated",
        ],
    );
    assert_contains_all(
        "client credential e2e coverage",
        &e2e_coverage,
        &[
            "W10 client-credentials dashboard",
            "oraclemcp-epic-060-f4xo.8.12",
            "w10_client_credentials_screen_is_redacted_and_isolated",
        ],
    );
}

#[test]
fn wd_history_source_snapshots_and_revert_are_review_gated() {
    let app = read_repo_file("web/src/app/App.tsx");
    let client = read_repo_file("web/src/app/operator-client.ts");
    let http = read_repo_file("crates/oraclemcp-core/src/http.rs");
    let source_history = read_repo_file("crates/oraclemcp-core/src/source_history.rs");
    let dashboard_auth = read_repo_file("crates/oraclemcp-core/src/dashboard_auth.rs");
    let readme = read_repo_file("README.md");
    let operations = read_repo_file("docs/operations.md");
    let conformance = read_repo_file("tests/conformance/COVERAGE.md");
    let e2e_coverage = read_repo_file("scripts/e2e/COVERAGE.md");

    assert_contains_all(
        "source-history operator routes",
        &http,
        &[
            "/operator/v1/source-history",
            "/operator/v1/source-history/revert",
            "source_history_snapshots_prior_source_and_revert_drafts_review_proposal",
            "source_snapshot",
            "capture_source_snapshot_for_statement",
        ],
    );
    assert_contains_all(
        "source-history store",
        &source_history,
        &[
            "SourceHistoryStore",
            "source_object_from_create_or_replace_sql",
            "SOURCE_SNAPSHOT_COLLECTION",
            "SOURCE_HISTORY_COLLECTION",
            "view(&self) -> SourceSnapshotView",
            "source text",
        ],
    );
    assert_contains_all(
        "dashboard source-history UI",
        &app,
        &[
            "SourceHistoryPanel",
            "fetchSourceHistory",
            "draftSourceHistoryRevert",
            "Source History",
            "Draft revert proposal",
        ],
    );
    assert_contains_all(
        "dashboard source-history client",
        &client,
        &[
            "SourceSnapshotView",
            "/operator/v1/source-history?max_rows=100",
            "/operator/v1/source-history/revert",
            "SourceHistoryRevertData",
        ],
    );
    assert_contains_all(
        "dashboard source-history tickets",
        &dashboard_auth,
        &["(\"POST\", \"/operator/v1/source-history/revert\")"],
    );
    assert_contains_all(
        "source-history docs",
        &(readme + &operations),
        &[
            "content-addressed service",
            "/operator/v1/source-history",
            "/operator/v1/source-history/revert",
            "normal preview, confirmation, classifier, profile-ceiling, and audit path",
            "not as a universal DDL undo guarantee",
        ],
    );
    assert_contains_all(
        "source-history conformance",
        &conformance,
        &[
            "DASHBOARD-B8-010",
            "source_history_snapshots_prior_source_and_revert_drafts_review_proposal",
            "wd_history_source_snapshots_and_revert_are_review_gated",
        ],
    );
    assert_contains_all(
        "source-history e2e coverage",
        &e2e_coverage,
        &[
            "WD-History source snapshots and revert",
            "oraclemcp-epic-060-f4xo.8.18",
            "wd_history_source_snapshots_and_revert_are_review_gated",
        ],
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
            "audit_proof_bundle_is_redacted_and_exportable",
            "client_credentials_screen_is_redacted_and_isolated",
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
            "audit_tail_filters_exports_redacted_proof_bundle",
            "operator_client_credentials_screen_lists_rotates_revokes_without_token_leak",
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
            "DASHBOARD-B8-007",
            "DASHBOARD-B8-008",
            "DASHBOARD-B8-009",
        ],
    );
    assert_contains_all(
        "e2e coverage",
        &e2e_coverage,
        &[
            "WP-W B.8 dashboard acceptance suite",
            "oraclemcp-epic-060-f4xo.8.20",
            "W8b proof bundle for gated actions",
            "oraclemcp-epic-060-f4xo.8.10",
            "W10 client-credentials dashboard",
            "oraclemcp-epic-060-f4xo.8.12",
        ],
    );
}
