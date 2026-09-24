//! Synthetic regression corpus executed through the served dispatch boundary.

use super::*;
use oraclemcp_audit::{MemoryAuditSink, SigningKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct GuardBypassCase {
    case_id: String,
    sql: String,
    profile: String,
    expected: String,
}

#[test]
fn guard_bypass_corpus_matches_golden() {
    let corpus = include_str!("../../../../../tests/golden/guard/bypass_corpus.jsonl");
    let mut seen = std::collections::HashSet::new();
    let mut count = 0;
    let mut mismatches = Vec::new();
    for line in corpus.lines().filter(|line| !line.trim().is_empty()) {
        let case: GuardBypassCase = serde_json::from_str(line).expect("golden case is closed JSON");
        assert!(
            seen.insert(case.case_id.clone()),
            "duplicate case {}",
            case.case_id
        );
        let (dispatcher, state) = semantic_dispatcher();
        let dispatcher = if case.profile == "sample_rows_masked" {
            let key = SigningKey::new(
                "synthetic-test-key",
                b"0123456789abcdef0123456789abcdef".to_vec(),
            )
            .expect("valid synthetic test key");
            let auditor = Arc::new(Auditor::new(Box::new(MemoryAuditSink::new()), key));
            dispatcher
                .with_auditor(auditor)
                .with_result_masking_policy(Some(ResultMaskingPolicy::new(Vec::new(), true)))
        } else {
            dispatcher
        };
        match case.profile.as_str() {
            "ordinary" | "sample_rows" | "sample_rows_masked" => {}
            "virtual_builtin" => {
                *state
                    .virtual_column_default
                    .lock()
                    .expect("virtual fixture lock") = Some("UPPER(\"LABEL\")".to_owned());
            }
            "virtual_user_function" => {
                *state
                    .virtual_column_default
                    .lock()
                    .expect("virtual fixture lock") = Some("APP.CANARY_FN(\"LABEL\")".to_owned());
            }
            "fga_handler" => {
                *state.fga_handler_table.lock().expect("FGA fixture lock") =
                    Some("ORDERS".to_owned());
            }
            other => panic!("unknown profile {other}"),
        }
        let result = if case.profile == "sample_rows" || case.profile == "sample_rows_masked" {
            let table = case
                .sql
                .split_whitespace()
                .last()
                .expect("sample SQL relation")
                .rsplit('.')
                .next()
                .expect("sample table");
            dispatcher.dispatch(
                "oracle_sample_rows",
                json!({"owner": "APP", "table": table, "max_rows": 1}),
            )
        } else {
            dispatcher.dispatch("oracle_query", json!({"sql": case.sql}))
        };
        let actual = match &result {
            Ok(_) => "admitted".to_owned(),
            Err(error) => format!("refused:{:?}", error.error_class),
        };
        let caller_queries = state.caller_queries.load(Ordering::SeqCst);
        if case.profile == "sample_rows_masked" {
            let output = result
                .as_ref()
                .expect("mask case must return a masked result");
            assert!(
                output["mask_certificate"].is_object(),
                "{}: masked result needs an audit-bound certificate",
                case.case_id
            );
        }
        if actual != case.expected || caller_queries != usize::from(actual == "admitted") {
            mismatches.push(format!("{}: sql={:?} expected={} actual={} caller_queries={caller_queries} result={result:?}",
                case.case_id, case.sql, case.expected, actual));
        }
        count += 1;
    }
    assert!(count >= 20, "bypass corpus unexpectedly shrank: {count}");
    assert!(
        mismatches.is_empty(),
        "golden mismatches:\n{}",
        mismatches.join("\n")
    );
}
