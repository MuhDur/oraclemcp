//! D2: Edition-Based Redefinition against a live Oracle database.
//!
//! This test is deliberately feature-gated and prerequisite-aware: creating an
//! edition needs database-level EBR privileges and `ORA$BASE` must have no
//! existing child. When either condition is absent, it prints an honest SKIP
//! rather than pretending the ordinary XE lane proved a privileged lifecycle.
#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use std::time::Duration;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use asupersync::runtime::RuntimeBuilder;
use asupersync::{Cx, Outcome};
use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp_audit::{AuditError, AuditRecord, AuditSink, Auditor, MemoryAuditSink, SigningKey};
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::http::{HttpRequest, HttpResponse, HttpTransportConfig, handle_http_request};
use oraclemcp_core::{
    ChangeProposalStore, DispatchContext, OracleMcpServer, ToolDispatch, tools::ToolRegistry,
};
use oraclemcp_db::{OracleBind, OracleConnectOptions, OracleConnection, RustOracleConnection};
use oraclemcp_error::{ErrorClass, ErrorEnvelope, ReasonCategory};
use oraclemcp_guard::{OperatingLevel, SessionLevelState};
use serde_json::{Value, json};

const BASE_EDITION: &str = "ORA$BASE";
const FIXTURE_EDITION: &str = "ORACLEMCP_D2_LINEAR";
const OPERATOR_FIXTURE_EDITION: &str = "ORACLEMCP_T13_OPERATOR";
const OPERATOR_PROFILE: &str = "live-edition-operator";

fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("live-XE runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("live-XE runtime installs a request Cx");
        body(cx).await
    })
}

fn test_opts() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN")
            .unwrap_or_else(|_| "//localhost:1522/FREEPDB1".to_owned()),
        username: Some(
            std::env::var("ORACLEMCP_TEST_USER").unwrap_or_else(|_| "system".to_owned()),
        ),
        password: Some(
            std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap_or_else(|_| "test_password".to_owned()),
        ),
        call_timeout: Some(Duration::from_secs(20)),
        ..Default::default()
    }
}

async fn connect_or_skip(cx: &Cx, test_name: &str) -> Option<RustOracleConnection> {
    match RustOracleConnection::connect(cx, test_opts()).await {
        Ok(conn) => Some(conn),
        Err(error) => {
            eprintln!(
                "[live-xe] SKIP {test_name}: no reachable Oracle or prerequisite missing ({error}); \
                 set ORACLEMCP_TEST_DSN / _USER / _PASSWORD"
            );
            None
        }
    }
}

fn ddl_level() -> SessionLevelState {
    let mut level = SessionLevelState::new(OperatingLevel::Ddl, false);
    level
        .set_current_level(OperatingLevel::Ddl)
        .expect("DDL fits the test profile ceiling");
    level
}

fn admin_level() -> SessionLevelState {
    let mut level = SessionLevelState::new(OperatingLevel::Admin, false);
    level
        .set_current_level(OperatingLevel::Admin)
        .expect("ADMIN fits the test profile ceiling");
    level
}

fn operator_post(path: &'static str, body: Value) -> HttpRequest {
    HttpRequest::new(
        "POST",
        path,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json"),
        ],
        body.to_string().into_bytes(),
    )
    .with_peer_loopback(true)
}

fn operator_body(response: &HttpResponse) -> Value {
    serde_json::from_slice(&response.body).expect("operator response is JSON")
}

struct SharedAuditSink(Arc<MemoryAuditSink>);

impl AuditSink for SharedAuditSink {
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.0.append(record)
    }

    fn flush(&self) -> Result<(), AuditError> {
        self.0.flush()
    }
}

async fn fresh_default_edition(cx: &Cx) -> Option<String> {
    let conn = RustOracleConnection::connect(cx, test_opts()).await.ok()?;
    let rows = conn
        .query_rows(
            cx,
            "SELECT SYS_CONTEXT('USERENV', 'CURRENT_EDITION_NAME') AS EDITION_NAME FROM DUAL",
            &[],
        )
        .await
        .ok()?;
    rows.first()
        .and_then(|row| row.text("EDITION_NAME"))
        .map(str::to_owned)
}

async fn database_default_edition(cx: &Cx, conn: &RustOracleConnection) -> Option<String> {
    let rows = conn
        .query_rows(
            cx,
            "SELECT property_value AS EDITION_NAME FROM database_properties WHERE property_name = 'DEFAULT_EDITION'",
            &[],
        )
        .await
        .ok()?;
    rows.first()
        .and_then(|row| row.text("EDITION_NAME"))
        .map(str::to_owned)
}

fn operator_flip(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    path: &'static str,
    proposal_id: &str,
) -> (HttpResponse, Option<HttpResponse>) {
    let preview = handle_http_request(
        server,
        config,
        operator_post(path, json!({ "proposal_id": proposal_id })),
    );
    if preview.status != 200 {
        return (preview, None);
    }
    let token = operator_body(&preview)["data"]["confirmation"]
        .as_str()
        .expect("operator preview returns a confirmation")
        .to_owned();
    let applied = handle_http_request(
        server,
        config,
        operator_post(
            path,
            json!({ "proposal_id": proposal_id, "confirm": token }),
        ),
    );
    (preview, Some(applied))
}

async fn dispatch(
    dispatcher: &OracleDispatcher,
    cx: &Cx,
    tool: &str,
    args: Value,
) -> Result<Value, ErrorEnvelope> {
    match ToolDispatch::dispatch(dispatcher, cx, DispatchContext::default(), tool, args).await {
        Outcome::Ok(value) => Ok(value),
        Outcome::Err(error) => Err(error),
        other => panic!("{tool} returned an unexpected cancellation/outcome: {other:?}"),
    }
}

async fn confirmed_execute(
    dispatcher: &OracleDispatcher,
    cx: &Cx,
    sql: &str,
) -> Result<Value, ErrorEnvelope> {
    let preview = dispatch(dispatcher, cx, "oracle_preview_sql", json!({ "sql": sql })).await?;
    let confirm = preview
        .pointer("/execute_confirmation/confirm")
        .and_then(Value::as_str)
        .expect("DDL preview mints a confirmation");
    dispatch(
        dispatcher,
        cx,
        "oracle_execute",
        json!({ "sql": sql, "commit": true, "confirm": confirm }),
    )
    .await
}

async fn probe_child_slot(
    cx: &Cx,
    conn: &RustOracleConnection,
) -> Result<(bool, bool), oraclemcp_db::DbError> {
    let parent_rows = conn
        .query_rows(
            cx,
            "SELECT edition_name FROM all_editions WHERE parent_edition_name = :1",
            &[OracleBind::String(BASE_EDITION.to_owned())],
        )
        .await?;
    let fixture_rows = conn
        .query_rows(
            cx,
            "SELECT edition_name FROM all_editions WHERE edition_name = :1",
            &[OracleBind::String(FIXTURE_EDITION.to_owned())],
        )
        .await?;
    Ok((!parent_rows.is_empty(), !fixture_rows.is_empty()))
}

/// A real Oracle creates one child edition, then the server refuses a second
/// child before its CREATE reaches the driver. The test retires its exact
/// synthetic edition through the same governed DDL path.
#[test]
fn edition_lifecycle_is_linear_live_and_second_child_never_executes() {
    run_with_cx(|cx| async move {
        let test_name = "edition_lifecycle_is_linear_live_and_second_child_never_executes";
        let Some(probe) = connect_or_skip(&cx, test_name).await else {
            return;
        };
        let (base_has_child, fixture_exists) = match probe_child_slot(&cx, &probe).await {
            Ok(result) => result,
            Err(error) => {
                eprintln!(
                    "[live-xe] SKIP {test_name}: cannot inspect ALL_EDITIONS ({error}); \
                     the test user needs EBR dictionary visibility"
                );
                return;
            }
        };
        if base_has_child || fixture_exists {
            eprintln!(
                "[live-xe] SKIP {test_name}: ORA$BASE already has a child or the prior D2 fixture exists; \
                 this test never mutates a non-empty edition timeline"
            );
            return;
        }

        let Some(served) = connect_or_skip(&cx, &format!("{test_name}/served")).await else {
            return;
        };
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(served),
            Some("live-d2".to_owned()),
            ddl_level(),
        );
        let create = format!("CREATE EDITION {FIXTURE_EDITION} AS CHILD OF {BASE_EDITION}");
        let first = match confirmed_execute(&dispatcher, &cx, &create).await {
            Ok(value) => value,
            Err(error) if error.error_class == ErrorClass::InsufficientPrivilege => {
                eprintln!(
                    "[live-xe] SKIP {test_name}: test user cannot CREATE EDITION ({error:?})"
                );
                return;
            }
            Err(error) => panic!("first governed CREATE EDITION must succeed: {error:?}"),
        };
        assert_eq!(first["executed"], json!(true));
        assert_eq!(first["required_level"], json!("DDL"));

        let second = confirmed_execute(&dispatcher, &cx, &create)
            .await
            .expect_err("the second child must be refused before Oracle emits raw ORA-38807");
        assert_eq!(second.error_class, ErrorClass::ForbiddenStatement);
        assert_eq!(second.ora_code, Some(38_807));
        assert_eq!(
            second
                .structured_reason
                .as_ref()
                .map(|reason| reason.category),
            Some(ReasonCategory::OneChildEdition)
        );

        let retire = format!("DROP EDITION {FIXTURE_EDITION} CASCADE");
        let retired = confirmed_execute(&dispatcher, &cx, &retire)
            .await
            .expect("the synthetic child retires through the governed DDL path");
        assert_eq!(retired["executed"], json!(true));
        assert_eq!(retired["required_level"], json!("DDL"));
    });
}

/// This case changes the default edition of the connected database. Run it
/// only against a dedicated XE 21 test instance, never a shared release lane.
#[test]
fn operator_executor_flips_default_edition_and_back_live_xe() {
    if std::env::var("ORACLEMCP_ISOLATED_EDITION_XE").as_deref() != Ok("1") {
        eprintln!(
            "[live-xe] SKIP operator_executor_flips_default_edition_and_back_live_xe: \
             ORACLEMCP_ISOLATED_EDITION_XE=1 requires a dedicated XE 21 test database"
        );
        return;
    }

    run_with_cx(|cx| async move {
        let probe = RustOracleConnection::connect(&cx, test_opts())
            .await
            .expect("isolated XE 21 must be reachable when the live gate is enabled");
        let (base_has_child, _) = probe_child_slot(&cx, &probe)
            .await
            .expect("dedicated XE must expose ALL_EDITIONS");
        assert!(
            !base_has_child,
            "dedicated XE must begin with an empty ORA$BASE child slot"
        );
        assert_eq!(
            fresh_default_edition(&cx).await.as_deref(),
            Some(BASE_EDITION),
            "dedicated XE must begin at ORA$BASE"
        );
        assert_eq!(
            database_default_edition(&cx, &probe).await.as_deref(),
            Some(BASE_EDITION),
            "dedicated XE database property must begin at ORA$BASE"
        );

        let served = RustOracleConnection::connect(&cx, test_opts())
            .await
            .expect("open dedicated operator execution session");
        let dispatcher = Arc::new(OracleDispatcher::new_with_profile_level(
            Box::new(served),
            Some(OPERATOR_PROFILE.to_owned()),
            admin_level(),
        ));
        let create =
            format!("CREATE EDITION {OPERATOR_FIXTURE_EDITION} AS CHILD OF {BASE_EDITION}");
        let created = confirmed_execute(&dispatcher, &cx, &create)
            .await
            .expect("dedicated XE user can create the synthetic operator edition");
        assert_eq!(created["executed"], json!(true));

        let report = CapabilitiesReport::new(
            "live-edition-operator",
            Vec::new(),
            OperatingLevel::Admin,
            FeatureTiers {
                live_db: true,
                engine: false,
                http_transport: true,
            },
        );
        let server = OracleMcpServer::new(
            "live-edition-operator",
            ToolRegistry::new(),
            report,
            dispatcher.clone(),
        );
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let target_dir = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target")
            });
        let store_root = target_dir
            .join("edition-operator-live")
            .join(format!("{}-{unique}", std::process::id()));
        let store =
            Arc::new(ChangeProposalStore::open(store_root).expect("isolated proposal store"));
        let audit_sink = Arc::new(MemoryAuditSink::default());
        let signing_key = SigningKey::new(
            "live-edition-operator",
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .expect("synthetic test audit key");
        let auditor = Arc::new(Auditor::new(
            Box::new(SharedAuditSink(Arc::clone(&audit_sink))),
            signing_key,
        ));
        let config = HttpTransportConfig {
            operator_auditor: Some(auditor),
            change_proposals: Some(store),
            ..Default::default()
        };

        let draft = handle_http_request(
            &server,
            &config,
            operator_post(
                "/operator/v1/edition-proposals/draft",
                json!({
                    "profile": OPERATOR_PROFILE,
                    "child_edition": OPERATOR_FIXTURE_EDITION,
                    "base_edition": BASE_EDITION,
                    "objects": ["ORACLEMCP_T13_OPERATOR_VIEW"]
                }),
            ),
        );
        assert_eq!(draft.status, 200, "draft: {:?}", operator_body(&draft));
        let proposal_id = operator_body(&draft)["data"]["proposal"]["proposal_id"]
            .as_str()
            .expect("persisted edition proposal id")
            .to_owned();
        let reviewing = handle_http_request(
            &server,
            &config,
            operator_post(
                "/operator/v1/edition-proposals/transition",
                json!({ "proposal_id": proposal_id, "status": "reviewing" }),
            ),
        );
        assert_eq!(
            reviewing.status,
            200,
            "reviewing: {:?}",
            operator_body(&reviewing)
        );

        let (_, merge) = operator_flip(
            &server,
            &config,
            "/operator/v1/edition-proposals/merge",
            &proposal_id,
        );
        let merge = merge.expect("operator merge preview must mint a confirmation");
        let after_merge = fresh_default_edition(&cx).await;
        let property_after_merge = database_default_edition(&cx, &probe).await;

        // Always attempt the operator rollback after the merge request, even
        // if a fresh-session observation failed, before asserting results.
        let (_, rollback) = operator_flip(
            &server,
            &config,
            "/operator/v1/edition-proposals/rollback",
            &proposal_id,
        );
        let rollback = rollback.expect("operator rollback preview must mint a confirmation");
        let after_rollback = fresh_default_edition(&cx).await;
        let property_after_rollback = database_default_edition(&cx, &probe).await;

        assert_eq!(merge.status, 200, "merge: {:?}", operator_body(&merge));
        assert_eq!(operator_body(&merge)["data"]["status"], json!("applied"));
        assert_eq!(
            after_merge.as_deref(),
            Some(OPERATOR_FIXTURE_EDITION),
            "fresh sessions must inherit the operator-selected child"
        );
        assert_eq!(
            property_after_merge.as_deref(),
            Some(OPERATOR_FIXTURE_EDITION),
            "database property must record the operator-selected child"
        );
        assert_eq!(
            rollback.status,
            200,
            "rollback: {:?}",
            operator_body(&rollback)
        );
        assert_eq!(
            after_rollback.as_deref(),
            Some(BASE_EDITION),
            "fresh sessions must inherit ORA$BASE again"
        );
        assert_eq!(
            property_after_rollback.as_deref(),
            Some(BASE_EDITION),
            "database property must record the rollback to ORA$BASE"
        );

        let retire = format!("DROP EDITION {OPERATOR_FIXTURE_EDITION} CASCADE");
        let retired = confirmed_execute(&dispatcher, &cx, &retire)
            .await
            .expect("retire only the synthetic operator edition after rollback");
        assert_eq!(retired["executed"], json!(true));
        assert!(
            audit_sink.records().len() >= 8,
            "operator draft, review, merge and rollback must be audited"
        );
    });
}
