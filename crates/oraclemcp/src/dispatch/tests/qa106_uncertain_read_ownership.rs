//! QA106 uncertain-read ownership tests, relocated verbatim from
//! `dispatch/tests.rs` (C6 de-monolith, bead `oraclemcp-kw1f3`): retained
//! primary sessions quarantine before reuse; stateless read workers own their
//! checkout lifecycle and do not poison the dispatcher's primary session.
//! `super` resolves to the `tests` module, so every reference is unchanged and
//! no assertion or fixture was edited.

use super::*;
use std::sync::Arc;

#[derive(Clone, Copy)]
enum FirstFailure {
    Cancelled,
    Ordinary,
}

struct FailFirstReadMock {
    calls: Arc<AtomicUsize>,
    failure: FirstFailure,
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for FailFirstReadMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        })
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        if let Some(rows) = mock_plain_table_dictionary(sql, binds) {
            return Ok(rows);
        }
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return match self.failure {
                FirstFailure::Cancelled => Err(DbError::Cancelled(
                    "injected uncertain read boundary".to_owned(),
                )),
                FirstFailure::Ordinary => Err(DbError::Query(
                    "ORA-00942: table or view does not exist".to_owned(),
                )),
            };
        }
        Ok(vec![OracleRow {
            columns: vec![(
                "SCHEMA_NAME".to_owned(),
                OracleCell::new("VARCHAR2", Some("APP".to_owned())),
            )],
        }])
    }

    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

fn assert_pinned_retry_is_refused(
    dispatcher: &OracleDispatcher,
    calls: &AtomicUsize,
    tool: &str,
    args: Value,
) {
    let first = dispatcher
        .dispatch(tool, args.clone())
        .expect_err("uncertain pinned read must fail");
    assert_eq!(first.error_class, ErrorClass::Timeout);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let retry = dispatcher
        .dispatch(tool, args)
        .expect_err("quarantined pinned session must not be reused");
    assert_eq!(retry.error_class, ErrorClass::RuntimeStateRequired);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "retry must be refused before another database round trip"
    );
    let quarantine = dispatcher
        .connection_quarantine()
        .expect("quarantine lock")
        .expect("uncertain read records quarantine");
    assert_eq!(quarantine.outcome, AuditOutcome::UnknownDiscarded);
}

#[test]
fn raw_query_uncertainty_quarantines_the_retained_primary_session() {
    let calls = Arc::new(AtomicUsize::new(0));
    let dispatcher = OracleDispatcher::new_with_profile(
        Box::new(FailFirstReadMock {
            calls: Arc::clone(&calls),
            failure: FirstFailure::Cancelled,
        }),
        Some("dev".to_owned()),
    );
    assert_pinned_retry_is_refused(
        &dispatcher,
        &calls,
        "oracle_query",
        json!({ "sql": "SELECT schema_name FROM app_table" }),
    );
}

#[test]
fn generated_read_uncertainty_quarantines_the_retained_primary_session() {
    let calls = Arc::new(AtomicUsize::new(0));
    let dispatcher = OracleDispatcher::new_with_profile(
        Box::new(FailFirstReadMock {
            calls: Arc::clone(&calls),
            failure: FirstFailure::Cancelled,
        }),
        Some("dev".to_owned()),
    );
    assert_pinned_retry_is_refused(
        &dispatcher,
        &calls,
        "oracle_sample_rows",
        json!({ "owner": "APP", "table": "T", "max_rows": 1 }),
    );
}

#[test]
fn ordinary_sql_error_keeps_the_pinned_session_usable() {
    let calls = Arc::new(AtomicUsize::new(0));
    let dispatcher = OracleDispatcher::new_with_profile(
        Box::new(FailFirstReadMock {
            calls: Arc::clone(&calls),
            failure: FirstFailure::Ordinary,
        }),
        Some("dev".to_owned()),
    );

    let first = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT schema_name FROM app_table" }),
        )
        .expect_err("deterministic ORA-00942 propagates");
    assert_eq!(first.error_class, ErrorClass::ObjectNotFound);
    let second = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT schema_name FROM app_table" }),
        )
        .expect("deterministic SQL error must not quarantine the session");
    assert_eq!(second["rows"][0]["SCHEMA_NAME"], json!("APP"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(
        dispatcher
            .connection_quarantine()
            .expect("quarantine lock")
            .is_none()
    );
}

#[test]
fn stateless_read_failure_does_not_poison_the_primary_session() {
    let calls = Arc::new(AtomicUsize::new(0));
    let dispatcher = OracleDispatcher::new_switchable_with_custom_tools_and_stateless(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        default_read_only_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        StatelessReadStrategy::new(Some(Box::new(FailFirstReadMock {
            calls: Arc::clone(&calls),
            failure: FirstFailure::Cancelled,
        }))),
        CustomToolCatalog::default(),
        None,
    );

    let first = dispatcher
        .dispatch("oracle_list_schemas", json!({ "max_rows": 1 }))
        .expect_err("failed stateless checkout propagates");
    assert_eq!(first.error_class, ErrorClass::Timeout);
    assert!(
        dispatcher
            .connection_quarantine()
            .expect("quarantine lock")
            .is_none(),
        "the stateless worker must not quarantine the unrelated primary session"
    );
    let second = dispatcher
        .dispatch("oracle_list_schemas", json!({ "max_rows": 1 }))
        .expect("a fresh stateless read can proceed");
    assert_eq!(second["schemas"][0]["SCHEMA_NAME"], json!("APP"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
