//! In-process write-authorization selection and pre-I/O refusal tests.

use super::*;
use oraclemcp_guard::resolver::CatalogGeneration;
use oraclemcp_guard::scoped_grant::{
    ClosureFingerprints, ColumnIdent, EffectiveCeiling, GrantComparison, GrantContainer,
    GrantLimits, GrantOp, GrantOperand, GrantPredicateV1, GrantTargetIdentity, GrantValue,
    LastDdlTime, ScopedGrant, ScopedGrantRequest, SuspendReason,
};
use std::collections::BTreeSet;

const UPDATE: &str = "UPDATE APP.EMPLOYEES SET STATUS = 'DONE' WHERE ID = 101";

fn dispatcher(level: SessionLevelState) -> (OracleDispatcher, Arc<TouchCounts>) {
    let counts = Arc::new(TouchCounts::default());
    (
        OracleDispatcher::new_with_profile_level(
            Box::new(TouchCountingMock {
                counts: Arc::clone(&counts),
            }),
            Some("dev".into()),
            level,
        ),
        counts,
    )
}

fn with_state<R>(dispatcher: &OracleDispatcher, f: impl FnOnce(&mut DispatcherState) -> R) -> R {
    RuntimeBuilder::current_thread()
        .build()
        .expect("test runtime")
        .block_on(async {
            let cx = Cx::current().expect("current context");
            let mut state = dispatcher.state.lock(&cx).await.expect("dispatcher state");
            f(&mut state)
        })
}

fn grant(binding: ExecGrantBinding, ttl: Duration) -> ScopedGrant {
    ScopedGrant::new(
        ScopedGrantRequest {
            profile: "dev".into(),
            binding,
            verbs: vec!["UPDATE".into()],
            target: GrantTargetIdentity {
                owner: "APP".into(),
                object_name: "EMPLOYEES".into(),
                object_id: 101,
                data_object_id: Some(101),
                container: GrantContainer {
                    con_id: 3,
                    con_uid: 7,
                },
                edition: None,
                catalog_generation: CatalogGeneration(1),
                resolved_via: None,
            },
            columns: BTreeSet::from([ColumnIdent::new("STATUS").unwrap()]),
            row_predicate: GrantPredicateV1::new(vec![GrantComparison {
                column: ColumnIdent::new("ID").unwrap(),
                op: GrantOp::Eq,
                operand: GrantOperand::Single(GrantValue::number("101").unwrap()),
            }]),
            limits: GrantLimits {
                max_rows_per_statement: 1,
                max_statements: 1,
                max_total_rows: 1,
            },
            ttl,
            commit_allowed: false,
            closure: ClosureFingerprints::new(),
            last_ddl_time: LastDdlTime::new("2026-09-01T10:00:00").unwrap(),
        },
        EffectiveCeiling {
            profile_max_level: OperatingLevel::ReadWrite,
            oauth_ceiling: None,
        },
        false,
        &SCOPED_GRANT_KEY,
    )
    .expect("valid scoped grant")
}

fn issue(dispatcher: &OracleDispatcher, ttl: Duration) -> (String, String) {
    with_state(dispatcher, |state| {
        let binding =
            ExecGrantBinding::new("process", "process", "process", state.grant_generation);
        let grant = grant(binding.clone(), ttl);
        let digest = grant.scope_digest();
        let id = state.scoped_grants.issue(grant).expect("store grant");
        let reference = SignedGrantRef::sign(&SCOPED_GRANT_KEY, &id, &binding, &digest);
        (id, reference.as_str().to_owned())
    })
}

fn refused(dispatcher: &OracleDispatcher, arguments: Value, code: &str) {
    let error = dispatcher
        .dispatch("oracle_execute", arguments)
        .expect_err("write must be refused");
    assert!(error.message.contains(code), "{error:?}");
    assert_eq!(
        error.statement_outcome,
        Some(oraclemcp_db::StatementOutcome::NotStarted),
        "authorization refusal must prove that no statement reached Oracle: {error:?}"
    );
    assert_eq!(error.to_json()["statement_outcome"], "not_started");
}

/// Replace `reference`'s last hex tag digit with a *different* digit. The
/// old `format!("{}0", ..)` was a no-op whenever the tag already ended in `0`
/// (1 in 16 references), and so "tampered" the valid reference (.15.12).
fn tamper_last_digit(reference: &str) -> String {
    let (head, last) = reference.split_at(reference.len() - 1);
    format!("{head}{}", if last == "0" { "1" } else { "0" })
}

/// Flip the tag digit at `index` (counted within the hex tag after the last
/// `.`) to a different hex digit.
fn tamper_tag_digit(reference: &str, index: usize) -> String {
    let tag_start = reference.rfind('.').expect("signed reference has a tag") + 1;
    let mut bytes = reference.as_bytes().to_vec();
    let at = tag_start + index;
    bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).expect("hex stays ASCII")
}

fn listed_execute_tools(level: SessionLevelState) -> Vec<String> {
    let dispatcher = Arc::new(OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".into()),
        level,
    ));
    let registry = crate::registry::tool_registry();
    let capabilities = oraclemcp_core::CapabilitiesReport::new(
        "write-auth-test",
        registry.tools.clone(),
        OperatingLevel::ReadOnly,
        oraclemcp_core::FeatureTiers {
            live_db: true,
            engine: false,
            http_transport: false,
        },
    );
    let server =
        oraclemcp_core::OracleMcpServer::new("write-auth-test", registry, capabilities, dispatcher);
    server
        .handle_jsonrpc_request(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}), None)
        .expect("tools/list response")["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn write_auth_execute_visible_at_read_only_when_ceiling_allows() {
    let names = listed_execute_tools(SessionLevelState::new(OperatingLevel::ReadWrite, false));
    assert!(names.iter().any(|name| name == "oracle_execute"));
    assert!(names.iter().any(|name| name == "execute_approved"));
    assert!(!names.iter().any(|name| name == "oracle_explain_plan"));
}

#[test]
fn write_auth_execute_hidden_when_ceiling_read_only_or_protected() {
    let mut scoped = SessionLevelState::new(OperatingLevel::ReadWrite, false);
    scoped.apply_scope_ceiling(OperatingLevel::ReadOnly);
    for level in [
        scoped,
        SessionLevelState::new(OperatingLevel::ReadOnly, true),
        SessionLevelState::new(OperatingLevel::Admin, true),
    ] {
        let names = listed_execute_tools(level);
        assert!(!names.iter().any(|name| name == "oracle_execute"));
        assert!(!names.iter().any(|name| name == "execute_approved"));
    }
}

#[test]
fn write_auth_read_only_without_grant_refused_before_io() {
    let (dispatcher, counts) = dispatcher(SessionLevelState::new(OperatingLevel::ReadWrite, false));
    let error = dispatcher
        .dispatch("oracle_execute", json!({"sql": UPDATE}))
        .expect_err("read-only session has no write authority");
    assert_eq!(error.error_class, ErrorClass::OperatingLevelTooLow);
    assert_eq!(
        error.statement_outcome,
        Some(oraclemcp_db::StatementOutcome::NotStarted)
    );
    assert_eq!(counts.total(), 0);
}

#[test]
fn write_auth_confirm_token_as_scoped_grant_refused() {
    let (dispatcher, counts) = dispatcher(read_write_level());
    let confirm = sign_execute_grant_reference(
        "synthetic-execute-id",
        &ExecGrantBinding::new("process", "process", "process", 1),
        Some("dev"),
        OperatingLevel::ReadWrite,
    );
    refused(
        &dispatcher,
        json!({"sql": UPDATE, "scoped_grant": confirm}),
        "GRANT_TOKEN_KIND_MISMATCH",
    );
    assert_eq!(counts.total(), 0);
}

#[test]
fn write_auth_scoped_grant_as_confirm_refused() {
    let (dispatcher, counts) = dispatcher(read_write_level());
    let (_, reference) = issue(&dispatcher, Duration::from_secs(60));
    refused(
        &dispatcher,
        json!({"sql": UPDATE, "confirm": reference}),
        "GRANT_TOKEN_KIND_MISMATCH",
    );
    assert_eq!(counts.total(), 0);
}

#[test]
fn write_auth_null_scoped_grant_never_falls_back() {
    let (dispatcher, counts) = dispatcher(read_write_level());
    for tool in ["oracle_execute", "execute_approved"] {
        let error = dispatcher
            .dispatch(tool, json!({"sql": UPDATE, "scoped_grant": null}))
            .expect_err("an explicit null must not select session authority");
        assert_eq!(error.error_class, ErrorClass::InvalidArguments, "{tool}");
        assert_eq!(
            error.statement_outcome,
            Some(oraclemcp_db::StatementOutcome::NotStarted),
            "{tool} must report no statement started"
        );
    }
    assert_eq!(counts.total(), 0);
}

#[test]
fn write_auth_invalid_grant_never_falls_back_to_elevated_session() {
    let (dispatcher, counts) = dispatcher(read_write_level());
    let (_, reference) = issue(&dispatcher, Duration::from_secs(60));
    let unknown = SignedGrantRef::sign(
        &SCOPED_GRANT_KEY,
        "never-issued",
        &ExecGrantBinding::new("process", "process", "process", 1),
        &[0; 32],
    );
    refused(
        &dispatcher,
        json!({"sql": UPDATE, "scoped_grant": unknown.as_str()}),
        "GRANT_UNKNOWN",
    );
    let tampered = tamper_last_digit(&reference);
    refused(
        &dispatcher,
        json!({"sql": UPDATE, "scoped_grant": tampered}),
        "GRANT_MISMATCH",
    );
    let (id, revoked) = issue(&dispatcher, Duration::from_secs(60));
    with_state(&dispatcher, |state| {
        state
            .scoped_grants
            .drop_grant(
                &id,
                &ExecGrantBinding::new("process", "process", "process", 1),
            )
            .unwrap();
    });
    refused(
        &dispatcher,
        json!({"sql": UPDATE, "scoped_grant": revoked}),
        "GRANT_REVOKED",
    );
    let (id, suspended) = issue(&dispatcher, Duration::from_secs(60));
    with_state(&dispatcher, |state| {
        state
            .scoped_grants
            .suspend(&id, SuspendReason::TargetDrift)
            .unwrap();
    });
    refused(
        &dispatcher,
        json!({"sql": UPDATE, "scoped_grant": suspended}),
        "GRANT_SUSPENDED_DRIFT",
    );
    let (_, expired) = issue(&dispatcher, Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(3));
    refused(
        &dispatcher,
        json!({"sql": UPDATE, "scoped_grant": expired}),
        "GRANT_EXPIRED",
    );
    assert_eq!(counts.total(), 0);
}

#[test]
fn write_auth_grant_never_satisfies_ddl_or_admin() {
    let (dispatcher, counts) = dispatcher(SessionLevelState::new(OperatingLevel::Admin, false));
    let (_, reference) = issue(&dispatcher, Duration::from_secs(60));
    for sql in [
        "CREATE TABLE APP.T152 (ID NUMBER)",
        "ALTER SYSTEM SET cursor_sharing=EXACT",
    ] {
        refused(
            &dispatcher,
            json!({"sql": sql, "scoped_grant": reference}),
            "GRANT_LEVEL_NOT_GRANTABLE",
        );
    }
    assert_eq!(counts.total(), 0);
}

#[test]
fn write_auth_forbidden_operator_statement_keeps_reason_and_not_started() {
    let (dispatcher, counts) = dispatcher(SessionLevelState::new(OperatingLevel::Admin, false));
    let error = dispatcher
        .dispatch(
            "oracle_execute",
            json!({"sql": "ALTER DATABASE DEFAULT EDITION = next_ed", "commit": true}),
        )
        .expect_err("default-edition flip is operator-only");
    assert_eq!(error.error_class, ErrorClass::ForbiddenStatement);
    assert_eq!(
        error
            .structured_reason
            .as_ref()
            .map(|reason| reason.category),
        Some(ReasonCategory::OperatorOnlyStatement)
    );
    assert_eq!(
        error.statement_outcome,
        Some(oraclemcp_db::StatementOutcome::NotStarted)
    );
    assert_eq!(counts.total(), 0);
}

#[test]
fn write_auth_grant_does_not_mutate_session_level() {
    let (dispatcher, counts) = dispatcher(SessionLevelState::new(OperatingLevel::ReadWrite, false));
    let (_, reference) = issue(&dispatcher, Duration::from_secs(60));
    let before = with_state(&dispatcher, |state| format!("{:?}", state.level));
    refused(
        &dispatcher,
        json!({"sql": UPDATE, "scoped_grant": reference}),
        "GRANT_ENFORCEMENT_UNAVAILABLE",
    );
    let after = with_state(&dispatcher, |state| format!("{:?}", state.level));
    assert_eq!(before, after);
    assert_eq!(counts.total(), 0);
}

#[test]
fn write_auth_policy_require_level_not_satisfied_by_grant() {
    let (dispatcher, counts) = dispatcher(SessionLevelState::new(OperatingLevel::ReadWrite, false));
    let dispatcher = dispatcher.with_sql_policy(Some(sql_policy(vec![policy_rule(
        "require-read-write",
        SqlPolicyVerb::Update,
        SqlPolicyEffectConfig::RequireLevel {
            level: OperatingLevel::ReadWrite,
        },
    )])));
    let (_, reference) = issue(&dispatcher, Duration::from_secs(60));
    refused(
        &dispatcher,
        json!({"sql": UPDATE, "scoped_grant": reference}),
        "GRANT_POLICY_FLOOR_UNMET",
    );
    assert_eq!(counts.total(), 0);
}

#[test]
fn write_auth_policy_deny_precedes_grant_lookup() {
    let (dispatcher, counts) = dispatcher(SessionLevelState::new(OperatingLevel::ReadWrite, false));
    let dispatcher = dispatcher.with_sql_policy(Some(sql_policy(vec![policy_rule(
        "deny-update",
        SqlPolicyVerb::Update,
        SqlPolicyEffectConfig::Deny,
    )])));
    let error = dispatcher
        .dispatch("oracle_execute", json!({"sql": UPDATE, "scoped_grant": "sgr1.never-issued.0000000000000000000000000000000000000000000000000000000000000000"}))
        .expect_err("policy deny must win before grant lookup");
    assert_eq!(error.error_class, ErrorClass::PolicyDenied);
    assert_eq!(
        error.statement_outcome,
        Some(oraclemcp_db::StatementOutcome::NotStarted)
    );
    assert!(!error.message.contains("GRANT_UNKNOWN"));
    assert_eq!(counts.total(), 0);
}

#[test]
fn write_auth_cold_policy_refusals_do_not_discover_schema() {
    let (dispatcher, counts) = dispatcher(SessionLevelState::new(OperatingLevel::ReadWrite, false));
    let dispatcher = dispatcher.with_sql_policy(Some(sql_policy(vec![policy_rule(
        "require-read-write",
        SqlPolicyVerb::Update,
        SqlPolicyEffectConfig::RequireLevel {
            level: OperatingLevel::ReadWrite,
        },
    )])));
    let without = dispatcher
        .dispatch("oracle_execute", json!({"sql": UPDATE}))
        .expect_err("read-only session cannot satisfy write level");
    assert_eq!(without.error_class, ErrorClass::OperatingLevelTooLow);
    refused(
        &dispatcher,
        json!({"sql": UPDATE, "scoped_grant": "sgr1.unknown.0000000000000000000000000000000000000000000000000000000000000000"}),
        "GRANT_POLICY_FLOOR_UNMET",
    );
    assert_eq!(
        counts.total(),
        0,
        "no cold schema describe before either refusal"
    );
}

#[test]
fn write_auth_well_formed_grant_refused_until_enforcement_wired() {
    let (dispatcher, counts) = dispatcher(SessionLevelState::new(OperatingLevel::ReadWrite, false));
    let (_, reference) = issue(&dispatcher, Duration::from_secs(60));
    refused(
        &dispatcher,
        json!({"sql": UPDATE, "scoped_grant": reference}),
        "GRANT_ENFORCEMENT_UNAVAILABLE",
    );
    assert_eq!(counts.total(), 0);
}

#[test]
fn write_auth_execute_approved_forwards_explicit_scoped_grant() {
    let (dispatcher, counts) = dispatcher(SessionLevelState::new(OperatingLevel::ReadWrite, false));
    let (_, reference) = issue(&dispatcher, Duration::from_secs(60));
    let error = dispatcher
        .dispatch(
            "execute_approved",
            json!({"sql": UPDATE, "scoped_grant": reference}),
        )
        .expect_err("alias must select the same scoped path");
    assert!(
        error.message.contains("GRANT_ENFORCEMENT_UNAVAILABLE"),
        "{error:?}"
    );
    assert_eq!(
        error.statement_outcome,
        Some(oraclemcp_db::StatementOutcome::NotStarted)
    );
    assert_eq!(counts.total(), 0);
}

/// .15.12 regression: the tamper helper can never hand back the valid
/// reference. The pre-fix `format!("{}0", ..)` returned its input unchanged
/// for a tag ending in `0`, which is what made the invalid-grant test flaky.
#[test]
fn write_auth_tamper_never_returns_the_valid_reference() {
    for digit in "0123456789abcdef".chars() {
        let reference = format!("sgr1.sgrant-1-0.{}{digit}", "a".repeat(63));
        assert_ne!(
            tamper_last_digit(&reference),
            reference,
            "last digit {digit}"
        );
    }
    let ends_in_zero = format!("sgr1.sgrant-1-0.{}0", "a".repeat(63));
    assert_eq!(
        format!("{}0", &ends_in_zero[..ends_in_zero.len() - 1]),
        ends_in_zero,
        "the pre-fix tamper was a no-op on a tag ending in 0"
    );
}

/// Every single-digit change anywhere in a valid reference's MAC tag is
/// refused as GRANT_MISMATCH before any database touch. This is the
/// deterministic form of the property the flaky run appeared to question.
#[test]
fn write_auth_every_tampered_tag_digit_is_refused_as_mismatch() {
    let (dispatcher, counts) = dispatcher(read_write_level());
    let (_, reference) = issue(&dispatcher, Duration::from_secs(60));
    let tag_len = reference.len() - reference.rfind('.').expect("tag") - 1;
    assert_eq!(tag_len, 64, "an HMAC-SHA256 hex tag: {reference}");
    for index in 0..tag_len {
        let tampered = tamper_tag_digit(&reference, index);
        assert_ne!(tampered, reference);
        refused(
            &dispatcher,
            json!({"sql": UPDATE, "scoped_grant": tampered}),
            "GRANT_MISMATCH",
        );
    }
    assert_eq!(counts.total(), 0);
}
