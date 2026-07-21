//! SEC-1 persisted-recovery proof over the real operator HTTP and dispatch
//! boundaries. The stored record lies that synthetic DDL is READ_ONLY; the live
//! dispatcher must classify and refuse it before the mock database can observe
//! an execute call.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use asupersync::{Cx, Outcome};
use async_trait::async_trait;
use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp_audit::{AuditError, AuditRecord, AuditSink, Auditor, MemoryAuditSink, SigningKey};
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::http::{HttpRequest, HttpResponse, HttpTransportConfig, handle_http_request};
use oraclemcp_core::server::{DispatchContext, DispatchFuture, OracleMcpServer, ToolDispatch};
use oraclemcp_core::{
    ChangeProposalStore, FileStore, SourceHistoryStore, SourceObjectTarget, SourceSnapshotDraft,
};
use oraclemcp_db::{
    DbError, OracleBackend, OracleBind, OracleConnection, OracleConnectionInfo, OracleRow,
};
use oraclemcp_guard::{OperatingLevel, SessionLevelState};
use serde_json::{Value, json};

const FORGED_STORED_ALLOW: &str = "stored verdict claims READ_ONLY";
const SYNTHETIC_DDL: &str = "DROP TABLE sec1_reclassification_probe";
const REVERT_SOURCE: &str = "CREATE OR REPLACE PROCEDURE APP.SEC1_REVERT_PROBE IS BEGIN NULL; END;";

/// The database seam records any statement that crossed the apply-time guard.
/// SEC-1 refusals must leave this at zero.
struct RecordingConnection {
    execute_calls: Arc<AtomicUsize>,
}

#[async_trait(?Send)]
impl OracleConnection for RecordingConnection {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo::default())
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Ok(Vec::new())
    }

    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

/// Calls the real served dispatcher for governed actions.  Source-history
/// snapshotting needs a deterministic prior-source lookup, so only that read
/// tool is supplied by the harness; DDL apply always flows into
/// [`OracleDispatcher`].
struct RecoveryDispatch {
    dispatcher: OracleDispatcher,
}

impl ToolDispatch for RecoveryDispatch {
    fn dispatch<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        if name == "oracle_get_source" {
            return Box::pin(async {
                Outcome::Ok(json!({
                    "source": {
                        "owner": "APP",
                        "name": "SEC1_REVERT_PROBE",
                        "object_type": "PROCEDURE",
                        "source": "PROCEDURE SEC1_REVERT_PROBE IS BEGIN NULL; END;",
                        "line_count": 1,
                        "char_count": 48,
                        "truncated": false,
                    }
                }))
            });
        }
        ToolDispatch::dispatch(&self.dispatcher, cx, context, name, args)
    }
}

struct SharedMemorySink(Arc<MemoryAuditSink>);

impl AuditSink for SharedMemorySink {
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.0.append(record)
    }

    fn flush(&self) -> Result<(), AuditError> {
        self.0.flush()
    }
}

struct RecoveryHarness {
    root: PathBuf,
    server: OracleMcpServer,
    config: HttpTransportConfig,
    execute_calls: Arc<AtomicUsize>,
}

fn recovery_harness(case: &str) -> RecoveryHarness {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/sec1-reclassification-e2e")
        .join(format!("{}-{}-{case}", std::process::id(), nanos));
    let service_store = FileStore::open(&root).expect("open isolated service store");
    let owner = service_store
        .acquire_service_owner("sec1-reclassification-e2e")
        .expect("own isolated service store");
    let proposals =
        Arc::new(ChangeProposalStore::open_with_owner(owner.clone()).expect("open proposal store"));
    let history =
        Arc::new(SourceHistoryStore::open_with_owner(owner).expect("open source-history store"));

    let sink = Arc::new(MemoryAuditSink::default());
    let key = SigningKey::new("sec1-e2e", b"0123456789abcdef0123456789abcdef".to_vec())
        .expect("valid synthetic signing key");
    let auditor = Arc::new(Auditor::new(
        Box::new(SharedMemorySink(Arc::clone(&sink))),
        key,
    ));

    // The level ceiling permits DDL, while the current live level remains
    // READ_ONLY.  A stored `READ_ONLY` verdict would be enough to execute only
    // if an apply path trusted it instead of classifying the real DDL now.
    let execute_calls = Arc::new(AtomicUsize::new(0));
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(RecordingConnection {
            execute_calls: Arc::clone(&execute_calls),
        }),
        Some("sec1".to_owned()),
        SessionLevelState::new(OperatingLevel::Ddl, false),
    );
    let report = CapabilitiesReport::new(
        "0.9.0-test",
        Vec::new(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: false,
            engine: true,
            http_transport: true,
        },
    );
    let server = OracleMcpServer::new(
        "0.9.0-test",
        oraclemcp_core::tools::ToolRegistry::new(),
        report,
        Arc::new(RecoveryDispatch { dispatcher }),
    );
    let config = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(proposals),
        source_history: Some(history),
        ..Default::default()
    };
    RecoveryHarness {
        root,
        server,
        config,
        execute_calls,
    }
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

fn body(response: &HttpResponse) -> Value {
    serde_json::from_slice(&response.body).expect("operator response is JSON")
}

fn draft_proposal(server: &OracleMcpServer, config: &HttpTransportConfig, sql: &str) -> String {
    let response = handle_http_request(
        server,
        config,
        operator_post(
            "/operator/v1/change-proposals/draft",
            json!({
                "profile": "sec1",
                "author": "human",
                "title": "forged persisted approval must not execute",
                "stored_verdict": {
                    "required_level": "READ_ONLY",
                    "danger": "SAFE",
                    "note": FORGED_STORED_ALLOW,
                },
                "statements": [{
                    "sql_template": sql,
                    "unit": "ddl",
                    "commit": true,
                    "stored_verdict": {
                        "required_level": "READ_ONLY",
                        "danger": "SAFE",
                        "note": FORGED_STORED_ALLOW,
                    },
                }],
            }),
        ),
    );
    assert_eq!(response.status, 200, "draft response: {}", body(&response));
    body(&response)["data"]["proposal"]["id"]
        .as_str()
        .expect("proposal id")
        .to_owned()
}

fn apply_and_assert_live_refusal(harness: &RecoveryHarness, proposal_id: &str, expected_sql: &str) {
    let response = handle_http_request(
        &harness.server,
        &harness.config,
        operator_post(
            "/operator/v1/change-proposals/apply",
            json!({
                "proposal_id": proposal_id,
                "confirm": "forged-stored-approval",
                "commit": true,
                "idempotency_key": format!("sec1-{proposal_id}"),
            }),
        ),
    );
    assert_eq!(response.status, 200, "apply is an operator envelope");
    let response = body(&response);
    let result = &response["data"]["results"][0];
    assert_eq!(
        response["data"]["status"],
        json!("stopped_on_failure"),
        "live refusal stops recovery apply: {response}"
    );
    assert_eq!(
        result["reclassified"]["required_level"],
        json!("DDL"),
        "apply re-classifies the persisted SQL, not the forged READ_ONLY verdict"
    );
    assert_eq!(
        result["stored_verdict_ignored"],
        json!(true),
        "stored authorization metadata is explicitly ignored at apply"
    );
    assert_eq!(
        result["action_response"]["data"]["mcp_response"]["result"]["structuredContent"]["error_class"],
        json!("OPERATING_LEVEL_TOO_LOW"),
        "the real served dispatcher rejects live DDL at READ_ONLY: {response}"
    );
    assert!(
        result["sql_sha256"].as_str().is_some_and(|_| true),
        "apply reports a digest, never raw persisted SQL"
    );
    assert_eq!(
        harness.execute_calls.load(Ordering::SeqCst),
        0,
        "{expected_sql:?} must be refused before the database execute seam"
    );
}

fn inject_forged_stored_allow(root: &std::path::Path, proposal_id: &str) {
    let path = root
        .join("change-proposals")
        .join(format!("{proposal_id}.json"));
    let mut proposal: Value = serde_json::from_slice(
        &fs::read(&path).expect("recovery proposal persisted before tampering"),
    )
    .expect("recovery proposal JSON");
    let forged = json!({
        "required_level": "READ_ONLY",
        "danger": "SAFE",
        "note": FORGED_STORED_ALLOW,
    });
    proposal["stored_verdict"] = forged.clone();
    proposal["statements"][0]["stored_verdict"] = forged;
    fs::write(
        path,
        serde_json::to_vec_pretty(&proposal).expect("serialize tampered proposal"),
    )
    .expect("persist tampered stored verdict");
}

#[test]
fn change_proposal_apply_ignores_forged_persisted_read_only_verdict_for_live_ddl() {
    let harness = recovery_harness("change-proposal");
    let proposal_id = draft_proposal(&harness.server, &harness.config, SYNTHETIC_DDL);

    apply_and_assert_live_refusal(&harness, &proposal_id, SYNTHETIC_DDL);
}

#[test]
fn source_history_revert_apply_ignores_tampered_read_only_verdict_for_live_ddl() {
    let harness = recovery_harness("source-history-revert");
    let history = harness
        .config
        .source_history
        .as_ref()
        .expect("source history configured");
    let target = SourceObjectTarget {
        owner: Some("APP".to_owned()),
        owner_quoted: false,
        name: "SEC1_REVERT_PROBE".to_owned(),
        name_quoted: false,
        object_type: "PROCEDURE".to_owned(),
    };
    let snapshot =
        history
            .record_snapshot(SourceSnapshotDraft {
                profile: "sec1".to_owned(),
                owner: "APP".to_owned(),
                owner_quoted: false,
                name: "SEC1_REVERT_PROBE".to_owned(),
                name_quoted: false,
                object_type: "PROCEDURE".to_owned(),
                target_identity_sha256: target.identity_sha256("APP"),
                source_kind: "all_source".to_owned(),
                source: REVERT_SOURCE.to_owned(),
                proposal_id: "prior-reviewed-change".to_owned(),
                statement_id: "prior-reviewed-statement".to_owned(),
                statement_sql_sha256:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                lane_id: None,
                subject_id_hash: "sha256:recovery-test".to_owned(),
            })
            .expect("persist source snapshot");

    let revert = handle_http_request(
        &harness.server,
        &harness.config,
        operator_post(
            "/operator/v1/source-history/revert",
            json!({ "snapshot_id": snapshot.id }),
        ),
    );
    assert_eq!(revert.status, 200, "revert drafts a review proposal");
    let proposal_id = body(&revert)["data"]["proposal"]["id"]
        .as_str()
        .expect("source-history revert proposal id")
        .to_owned();

    // This is the recovery-specific adversary: the stored source snapshot is
    // legitimate, but an on-disk review record is altered before its later
    // apply.  The recovery path must treat that stored verdict as evidence only.
    inject_forged_stored_allow(&harness.root, &proposal_id);
    apply_and_assert_live_refusal(&harness, &proposal_id, REVERT_SOURCE);
}
