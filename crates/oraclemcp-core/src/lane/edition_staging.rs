//! Single-call child-edition connections. No ordinary connection is accepted,
//! lent, switched, pooled, or used as a fallback by this owner.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use asupersync::Cx;
use oraclemcp_config::ConnectionProfile;
use oraclemcp_db::{
    CatalogQueryId, DbError, OracleConnectOptions, OracleConnection, connect_oracle,
    run_catalog_query,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope, ReasonCategory, StructuredReason};
use parking_lot::Mutex;

use crate::admission::{AdmissionController, AdmissionPermit};
use crate::change_proposal::validate_dictionary_edition_identifier;

/// The work permitted on a dedicated child-edition connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditionStagingPurpose {
    Stage,
    Verify,
}

/// Server-selected lane purpose; this type is never deserialized from tool args.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LanePurpose {
    Ordinary,
    EditionStaging {
        change_request_id: String,
        child_edition: String,
        purpose: EditionStagingPurpose,
    },
}

/// Proof that this call owns a connection whose current edition was checked.
/// Only the staging owner constructs this capability, after authentication.
pub struct EditionStagingContext {
    purpose: LanePurpose,
}

impl EditionStagingContext {
    pub fn purpose(&self) -> &LanePurpose {
        &self.purpose
    }

    pub fn child_edition(&self) -> &str {
        match &self.purpose {
            LanePurpose::EditionStaging { child_edition, .. } => child_edition,
            LanePurpose::Ordinary => unreachable!("staging context is never ordinary"),
        }
    }
}

/// Server-owned inputs. The caller supplies its already resolved credential
/// snapshot; only the edition differs in the connection actually opened.
pub struct EditionStagingRequest<'a> {
    pub change_request_id: &'a str,
    pub child_edition: &'a str,
    pub purpose: EditionStagingPurpose,
    pub profile: &'a ConnectionProfile,
    pub resolved_options: &'a OracleConnectOptions,
    pub subject: &'a str,
}

fn unavailable() -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::SessionBusy,
        "a separate authenticated child-edition staging lane is unavailable",
    )
    .with_structured_reason(StructuredReason::new(ReasonCategory::StagingLaneUnavailable))
    .with_next_step("resolve the staging connection or capacity problem, then retry oracle_change_request; the pinned lane is never a fallback")
}

/// Assert the ordinary lane's edition around a change-request action. This
/// reads the pinned lane but never switches it; consumers call it with their
/// independently captured pre-action edition, including on failure paths.
pub async fn assert_pinned_edition_unchanged(
    cx: &Cx,
    pinned: &dyn OracleConnection,
    expected_edition: &str,
) -> Result<(), ErrorEnvelope> {
    let rows = run_catalog_query(cx, pinned, CatalogQueryId::StagingCurrentEdition, &[])
        .await
        .map_err(DbError::into_envelope)?;
    if rows.len() == 1 && rows[0].text("EDITION_NAME") == Some(expected_edition) {
        Ok(())
    } else {
        Err(ErrorEnvelope::new(
            ErrorClass::Internal,
            "ordinary pinned lane edition changed during a change-request action",
        ))
    }
}

/// Copy the full profile, changing only connect-time edition selection. The
/// child is its exact dictionary spelling from the change-request record,
/// including the case of an originally quoted identifier.
pub fn derived_staging_profile(
    profile: &ConnectionProfile,
    child_edition: &str,
) -> Result<ConnectionProfile, ErrorEnvelope> {
    validate_dictionary_edition_identifier(child_edition).map_err(|_| unavailable())?;
    let mut derived = profile.clone();
    derived
        .session_identity
        .get_or_insert_with(Default::default)
        .edition = Some(child_edition.to_owned());
    Ok(derived)
}

// This is resource custody, not evidence of server retirement. In particular,
// cancelling a client future does not prove Oracle stopped its statement. Keep
// both the physical owner (if opened) and its admission charge for process life,
// including after the per-request manager is dropped. No quarantined lane is
// ever made available for ordinary work or a second staging call.
struct QuarantinedStagingLane {
    owner: Arc<()>,
    _connection: Option<Box<dyn OracleConnection>>,
    _permit: AdmissionPermit,
}
static QUARANTINED: Mutex<Vec<QuarantinedStagingLane>> = Mutex::new(Vec::new());

struct StagingOwner {
    owner: Arc<()>,
    connection: Option<Box<dyn OracleConnection>>,
    permit: Option<AdmissionPermit>,
}

impl Drop for StagingOwner {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            QUARANTINED.lock().push(QuarantinedStagingLane {
                owner: self.owner.clone(),
                _connection: self.connection.take(),
                _permit: permit,
            });
        }
    }
}

/// Dedicated connections charged to the server's shared admission budget.
/// A cancelled or uncertain call retains its charge in quarantine; successful
/// logical logoff is the only path that returns a slot.
pub struct EditionStagingLanes {
    admission: Arc<AdmissionController>,
    owner: Arc<()>,
}

impl EditionStagingLanes {
    pub fn new(admission: Arc<AdmissionController>) -> Self {
        Self {
            admission,
            owner: Arc::new(()),
        }
    }

    pub fn quarantined_connections(&self) -> usize {
        QUARANTINED
            .lock()
            .iter()
            .filter(|entry| Arc::ptr_eq(&entry.owner, &self.owner))
            .count()
    }

    /// Attempt bounded disposal of quarantined client transports. The capacity
    /// charges remain held: transport disposal is not proof of Oracle session
    /// retirement. Do not call this with the cancelled operation's context.
    pub async fn dispose_quarantined_transports(&self, cleanup_cx: &Cx) {
        let connections: Vec<_> = QUARANTINED
            .lock()
            .iter_mut()
            .filter(|entry| Arc::ptr_eq(&entry.owner, &self.owner))
            .filter_map(|entry| entry._connection.take())
            .collect();
        for connection in connections {
            let _ = connection.cancel_and_close(cleanup_cx).await;
        }
    }

    /// Run one operation after proving the requested edition. The factory is
    /// lazy: capacity, authentication and the catalog assertion precede it.
    /// The callback must still apply the normal classifier, level, confirmation
    /// and content-proof gates; the capability proves only where it runs.
    pub async fn run<T, F>(
        &self,
        cx: &Cx,
        request: EditionStagingRequest<'_>,
        operation: F,
    ) -> Result<T, ErrorEnvelope>
    where
        F: for<'a> FnOnce(
            &'a Cx,
            &'a EditionStagingContext,
            &'a dyn OracleConnection,
        ) -> Pin<Box<dyn Future<Output = Result<T, DbError>> + 'a>>,
    {
        self.run_with_connector(
            cx,
            request,
            |cx, options| Box::pin(connect_oracle(cx, options)),
            operation,
        )
        .await
    }

    async fn run_with_connector<T, F, C>(
        &self,
        cx: &Cx,
        request: EditionStagingRequest<'_>,
        connector: C,
        operation: F,
    ) -> Result<T, ErrorEnvelope>
    where
        C: for<'a> FnOnce(
            &'a Cx,
            OracleConnectOptions,
        ) -> Pin<
            Box<dyn Future<Output = Result<Box<dyn OracleConnection>, DbError>> + 'a>,
        >,
        F: for<'a> FnOnce(
            &'a Cx,
            &'a EditionStagingContext,
            &'a dyn OracleConnection,
        ) -> Pin<Box<dyn Future<Output = Result<T, DbError>> + 'a>>,
    {
        let derived = derived_staging_profile(request.profile, request.child_edition)?;
        let child = derived
            .session_identity
            .as_ref()
            .and_then(|identity| identity.edition.as_ref())
            .ok_or_else(unavailable)?
            .clone();
        if !request.profile.edition_change_requests()
            || request.profile.protected()
            || request.profile.max_level() < oraclemcp_guard::OperatingLevel::Ddl
            || request.profile.read_only_standby()
            || request.change_request_id.trim().is_empty()
        {
            return Err(unavailable());
        }
        let permit = self
            .admission
            .try_admit(cx, request.subject)
            .map_err(|_| unavailable())?;
        let mut guard = StagingOwner {
            owner: self.owner.clone(),
            connection: None,
            permit: Some(permit),
        };
        let mut options = request.resolved_options.clone();
        options
            .session_identity
            .get_or_insert_with(Default::default)
            .edition = Some(child.clone());
        // The guard already owns the charge if logon is cancelled midway.
        guard.connection = Some(connector(cx, options).await.map_err(|_| unavailable())?);
        let connection = guard.connection.as_deref().ok_or_else(unavailable)?;
        let rows =
            run_catalog_query(cx, connection, CatalogQueryId::StagingCurrentEdition, &[]).await;
        let matches = rows.as_ref().is_ok_and(|rows| {
            rows.len() == 1 && rows[0].text("EDITION_NAME") == Some(child.as_str())
        });
        if !matches {
            // Even a successful logon can be redirected by a trusted login
            // hook. Never expose a capability until the final session agrees.
            if rows.as_ref().is_ok() {
                self.finish(cx, &mut guard).await;
            }
            return Err(unavailable());
        }
        let context = EditionStagingContext {
            purpose: LanePurpose::EditionStaging {
                change_request_id: request.change_request_id.to_owned(),
                child_edition: child,
                purpose: request.purpose,
            },
        };
        let result = operation(cx, &context, connection).await;
        if result
            .as_ref()
            .is_err_and(DbError::is_uncertain_session_state)
        {
            return result.map_err(DbError::into_envelope);
        }
        if !self.finish(cx, &mut guard).await {
            // The statement's completed result is authoritative. A subsequent
            // logoff failure affects resource custody, not that result; never
            // turn a known successful effect into a retryable open failure.
            tracing::warn!(
                "staging body completed; logoff failed and connection capacity remains quarantined"
            );
        }
        result.map_err(DbError::into_envelope)
    }

    async fn finish(&self, cx: &Cx, guard: &mut StagingOwner) -> bool {
        let Some(connection) = guard.connection.as_deref() else {
            return false;
        };
        let closed = asupersync::combinator::try_commit_section(cx, 8_192, async {
            asupersync::time::timeout(cx.now(), Duration::from_secs(2), connection.close(cx))
                .await
                .map_err(|_| DbError::Cancelled("staging logoff deadline exceeded".into()))?
        })
        .await
        .is_ok();
        if closed {
            guard.connection.take();
            guard.permit.take();
        }
        closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lane::block_on_lane_bridge;
    use oraclemcp_db::{OracleBackend, OracleBind, OracleCell, OracleConnectionInfo, OracleRow};
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        task::{Context, Poll, Waker},
    };

    struct MockConnection {
        edition: String,
        closed: Arc<AtomicBool>,
        logoff_fails: bool,
    }
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for MockConnection {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn close(&self, _: &Cx) -> Result<(), DbError> {
            if self.logoff_fails {
                return Err(DbError::ConnectionLost(
                    "logoff transport lost after completed body".into(),
                ));
            }
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
        async fn ping(&self, _: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Err(DbError::Internal("unexpected describe".into()))
        }
        async fn query_rows(
            &self,
            _: &Cx,
            sql: &str,
            _: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            assert_eq!(sql, CatalogQueryId::StagingCurrentEdition.spec().sql);
            Ok(vec![OracleRow {
                columns: vec![(
                    "EDITION_NAME".into(),
                    OracleCell::new("VARCHAR2", Some(self.edition.clone())),
                )],
            }])
        }
        async fn execute(&self, _: &Cx, _: &str, _: &[OracleBind]) -> Result<u64, DbError> {
            panic!("no candidate SQL in lifecycle unit")
        }
        async fn commit(&self, _: &Cx) -> Result<(), DbError> {
            panic!("no commit in lifecycle unit")
        }
        async fn rollback(&self, _: &Cx) -> Result<(), DbError> {
            panic!("no rollback in lifecycle unit")
        }
    }
    fn profile() -> ConnectionProfile {
        serde_json::from_value(serde_json::json!({ "name":"stage", "connect_string":"localhost:1521/fake", "max_level":"DDL", "edition_change_requests":true })).unwrap()
    }
    fn request<'a>(
        p: &'a ConnectionProfile,
        options: &'a OracleConnectOptions,
    ) -> EditionStagingRequest<'a> {
        EditionStagingRequest {
            change_request_id: "request-unit",
            child_edition: "TEST_CHILD",
            purpose: EditionStagingPurpose::Stage,
            profile: p,
            resolved_options: options,
            subject: "test",
        }
    }
    type ConnectFuture<'a> =
        Pin<Box<dyn Future<Output = Result<Box<dyn OracleConnection>, DbError>> + 'a>>;
    fn connector(
        closed: Arc<AtomicBool>,
        edition: &'static str,
    ) -> impl for<'a> FnOnce(&'a Cx, OracleConnectOptions) -> ConnectFuture<'a> {
        move |_, options| {
            assert_eq!(
                options
                    .session_identity
                    .as_ref()
                    .and_then(|i| i.edition.as_deref()),
                Some("TEST_CHILD")
            );
            Box::pin(async move {
                Ok(Box::new(MockConnection {
                    edition: edition.into(),
                    closed,
                    logoff_fails: false,
                }) as Box<dyn OracleConnection>)
            })
        }
    }
    fn forbidden_operation() -> Result<(), DbError> {
        panic!("operation must never be invoked")
    }
    fn assert_reason(error: &ErrorEnvelope) {
        assert_eq!(
            serde_json::to_value(error).unwrap()["structured_reason"]["category"],
            "STAGING_LANE_UNAVAILABLE"
        );
    }
    #[test]
    fn derived_staging_profile_keeps_ceiling_and_protected_flag() {
        let mut p = profile();
        p.protected = Some(true);
        p.session_identity = Some(
            serde_json::from_value(
                serde_json::json!({"edition":"ORA$BASE","module":"unit","action":"preserved"}),
            )
            .unwrap(),
        );
        p.sql_policy = None;
        let derived = derived_staging_profile(&p, "TEST_CHILD").unwrap();
        let mut expected = p.clone();
        expected.session_identity.as_mut().unwrap().edition = Some("TEST_CHILD".into());
        assert_eq!(
            serde_json::to_value(&derived).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        assert_eq!(derived.max_level(), p.max_level());
        assert_eq!(derived.protected(), p.protected());
        assert_eq!(
            p.session_identity.as_ref().unwrap().edition.as_deref(),
            Some("ORA$BASE")
        );
        assert_eq!(
            derived_staging_profile(&p, "Child v2")
                .unwrap()
                .session_identity
                .unwrap()
                .edition
                .as_deref(),
            Some("Child v2")
        );
    }
    #[test]
    fn staging_lane_unavailable_refuses_without_fallback() {
        block_on_lane_bridge(async {
            let cx = Cx::for_testing();
            let p = profile();
            let options = OracleConnectOptions::default();
            let budget = Arc::new(AdmissionController::new(1, 1));
            let held = budget.try_admit(&cx, "test").unwrap();
            let lanes = EditionStagingLanes::new(budget);
            let result = lanes
                .run_with_connector(
                    &cx,
                    request(&p, &options),
                    |_, _| panic!("must refuse before opening"),
                    |_, _, _| {
                        Box::pin(async { forbidden_operation() })
                            as Pin<Box<dyn Future<Output = Result<(), DbError>>>>
                    },
                )
                .await;
            assert_reason(&result.unwrap_err());
            drop(held);
        });
    }
    #[test]
    fn staging_lane_edition_mismatch_destroys_and_refuses() {
        block_on_lane_bridge(async {
            let cx = Cx::for_testing();
            let p = profile();
            let options = OracleConnectOptions::default();
            let closed = Arc::new(AtomicBool::new(false));
            let budget = Arc::new(AdmissionController::new(1, 1));
            let lanes = EditionStagingLanes::new(budget.clone());
            let result = lanes
                .run_with_connector(
                    &cx,
                    request(&p, &options),
                    connector(closed.clone(), "WRONG_EDITION"),
                    |_, _, _| {
                        Box::pin(async { forbidden_operation() })
                            as Pin<Box<dyn Future<Output = Result<(), DbError>>>>
                    },
                )
                .await;
            assert_reason(&result.unwrap_err());
            assert!(closed.load(Ordering::SeqCst));
            assert_eq!(lanes.quarantined_connections(), 0);
            assert_eq!(budget.available_global(), 1);
        });
    }
    #[test]
    fn staging_completed_result_survives_logoff_failure_with_capacity_quarantined() {
        block_on_lane_bridge(async {
            let cx = Cx::for_testing();
            let p = profile();
            let options = OracleConnectOptions::default();
            let budget = Arc::new(AdmissionController::new(1, 1));
            let lanes = EditionStagingLanes::new(budget.clone());
            let closed = Arc::new(AtomicBool::new(false));
            let signal = closed.clone();
            let result = lanes
                .run_with_connector(
                    &cx,
                    request(&p, &options),
                    move |_, _| {
                        Box::pin(async move {
                            Ok(Box::new(MockConnection {
                                edition: "TEST_CHILD".into(),
                                closed: signal,
                                logoff_fails: true,
                            }) as Box<dyn OracleConnection>)
                        })
                    },
                    |_, _, _| Box::pin(async { Ok(7) }),
                )
                .await
                .unwrap();
            assert_eq!(
                result, 7,
                "logoff failure must not replace a completed operation result"
            );
            assert!(!closed.load(Ordering::SeqCst));
            assert_eq!(lanes.quarantined_connections(), 1);
            assert_eq!(budget.available_global(), 0);
        });
    }

    #[test]
    fn staging_lane_destroyed_after_completion() {
        block_on_lane_bridge(async {
            let cx = Cx::for_testing();
            let p = profile();
            let options = OracleConnectOptions::default();
            let budget = Arc::new(AdmissionController::new(1, 1));
            let lanes = EditionStagingLanes::new(budget.clone());
            for _ in 0..2 {
                let closed = Arc::new(AtomicBool::new(false));
                lanes
                    .run_with_connector(
                        &cx,
                        request(&p, &options),
                        connector(closed.clone(), "TEST_CHILD"),
                        |cx, context, conn| {
                            Box::pin(async move {
                                assert_eq!(context.child_edition(), "TEST_CHILD");
                                let rows = run_catalog_query(
                                    cx,
                                    conn,
                                    CatalogQueryId::StagingCurrentEdition,
                                    &[],
                                )
                                .await?;
                                assert_eq!(rows[0].text("EDITION_NAME"), Some("TEST_CHILD"));
                                Ok(())
                            })
                        },
                    )
                    .await
                    .unwrap();
                assert!(closed.load(Ordering::SeqCst));
                assert_eq!(budget.available_global(), 1);
            }
        });
    }

    #[test]
    fn staging_logon_cancel_retains_capacity_before_connection_available() {
        block_on_lane_bridge(async {
            let cx = Cx::for_testing();
            let p = profile();
            let options = OracleConnectOptions::default();
            let budget = Arc::new(AdmissionController::new(1, 1));
            let lanes = EditionStagingLanes::new(budget.clone());
            let mut future = Box::pin(lanes.run_with_connector(
                &cx,
                request(&p, &options),
                |_, _| Box::pin(std::future::pending()),
                |_, _, _| Box::pin(async { forbidden_operation() }),
            ));
            let waker = Waker::noop();
            let mut task = Context::from_waker(waker);
            assert!(matches!(future.as_mut().poll(&mut task), Poll::Pending));
            drop(future);
            assert_eq!(lanes.quarantined_connections(), 1);
            assert_eq!(budget.available_global(), 0);
        });
    }

    #[test]
    fn staging_protocol_error_quarantines_without_reuse() {
        block_on_lane_bridge(async {
            let cx = Cx::for_testing();
            let p = profile();
            let options = OracleConnectOptions::default();
            let closed = Arc::new(AtomicBool::new(false));
            let budget = Arc::new(AdmissionController::new(1, 1));
            let lanes = EditionStagingLanes::new(budget.clone());
            let result = lanes
                .run_with_connector(
                    &cx,
                    request(&p, &options),
                    connector(closed.clone(), "TEST_CHILD"),
                    |_, _, _| {
                        Box::pin(async {
                            Err::<(), _>(DbError::ConnectionLost(
                                "protocol stream abandoned".into(),
                            ))
                        })
                    },
                )
                .await;
            assert!(result.is_err());
            assert_eq!(lanes.quarantined_connections(), 1);
            assert!(!closed.load(Ordering::SeqCst));
            assert_eq!(budget.available_global(), 0);
        });
    }

    #[test]
    fn pinned_lane_edition_assertion_detects_a_change() {
        block_on_lane_bridge(async {
            let cx = Cx::for_testing();
            let conn = MockConnection {
                edition: "TEST_CHILD".into(),
                closed: Arc::new(AtomicBool::new(false)),
                logoff_fails: false,
            };
            let error = assert_pinned_edition_unchanged(&cx, &conn, "TEST_PARENT")
                .await
                .unwrap_err();
            assert_eq!(error.error_class, ErrorClass::Internal);
        });
    }
    #[test]
    fn staging_lane_quarantined_on_cancel_and_keeps_budget_after_manager_drop() {
        block_on_lane_bridge(async {
            let cx = Cx::for_testing();
            let p = profile();
            let options = OracleConnectOptions::default();
            let closed = Arc::new(AtomicBool::new(false));
            let entered = Arc::new(AtomicBool::new(false));
            let budget = Arc::new(AdmissionController::new(1, 1));
            let lanes = EditionStagingLanes::new(budget.clone());
            let signal = entered.clone();
            let mut future = Box::pin(lanes.run_with_connector(
                &cx,
                request(&p, &options),
                connector(closed.clone(), "TEST_CHILD"),
                move |_, _, _| {
                    Box::pin(async move {
                        signal.store(true, Ordering::SeqCst);
                        std::future::pending::<Result<(), DbError>>().await
                    })
                },
            ));
            let waker = Waker::noop();
            let mut task = Context::from_waker(waker);
            assert!(matches!(future.as_mut().poll(&mut task), Poll::Pending));
            assert!(entered.load(Ordering::SeqCst));
            drop(future);
            assert_eq!(lanes.quarantined_connections(), 1);
            assert!(!closed.load(Ordering::SeqCst));
            assert_eq!(budget.available_global(), 0);
            drop(lanes);
            assert_eq!(budget.available_global(), 0);
        });
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::change_proposal::normalize_edition_identifier;
    use crate::lane::block_on_lane_bridge;
    use oraclemcp_db::{OracleBind, OracleSessionIdentity};
    use std::sync::atomic::{AtomicBool, Ordering};

    fn check(value: bool, message: &str) -> Result<(), String> {
        if value {
            Ok(())
        } else {
            Err(message.to_owned())
        }
    }
    async fn edition(cx: &Cx, conn: &dyn OracleConnection) -> Result<String, String> {
        let rows = run_catalog_query(cx, conn, CatalogQueryId::StagingCurrentEdition, &[])
            .await
            .map_err(|e| e.to_string())?;
        rows.first()
            .and_then(|r| r.text("EDITION_NAME"))
            .map(str::to_owned)
            .ok_or_else(|| "no current edition".into())
    }
    async fn sessions(cx: &Cx, conn: &dyn OracleConnection, module: &str) -> Result<i64, String> {
        let rows = conn
            .query_rows(
                cx,
                "SELECT COUNT(*) AS n FROM v$session WHERE module = :1",
                &[OracleBind::String(module.into())],
            )
            .await
            .map_err(|e| e.to_string())?;
        rows.first()
            .and_then(|r| r.parse_i64("N"))
            .ok_or_else(|| "no session census".into())
    }
    fn live_contract(cancel: bool) {
        let dsn = std::env::var("ORACLEMCP_TEST_DSN").expect("local lab DSN required");
        assert!(dsn.starts_with("localhost:") || dsn.starts_with("127.0.0.1:"));
        let user = std::env::var("ORACLEMCP_TEST_USER").expect("admin user required");
        let password = std::env::var("ORACLEMCP_TEST_PASSWORD").expect("admin password required");
        block_on_lane_bridge(async move {
            let cx = Cx::current().expect("runtime Cx");
            let options = OracleConnectOptions {
                connect_string: dsn.clone(),
                username: Some(user.clone()),
                password: Some(password),
                ..Default::default()
            };
            let admin = connect_oracle(&cx, options.clone())
                .await
                .expect("live admin");
            let suffix = format!(
                "{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
            );
            let parent = format!("OMCP_STP_{suffix}");
            let child = format!("OMCP_STC_{suffix}");
            let module = format!("OMCP_STAGE_{suffix}");
            let rows=admin.query_rows(&cx,"SELECT e.edition_name FROM all_editions e WHERE e.usable = 'YES' AND NOT EXISTS (SELECT 1 FROM all_editions c WHERE c.parent_edition_name = e.edition_name) ORDER BY e.edition_name FETCH FIRST 1 ROW ONLY",&[]).await.expect("live leaf");
            let leaf = rows
                .first()
                .and_then(|r| r.text("EDITION_NAME"))
                .expect("usable leaf");
            let leaf =
                normalize_edition_identifier(leaf.to_owned()).expect("valid leaf identifier");
            admin
                .execute(
                    &cx,
                    &format!("CREATE EDITION \"{parent}\" AS CHILD OF \"{leaf}\""),
                    &[],
                )
                .await
                .expect("own parent fixture");
            let created = admin
                .execute(
                    &cx,
                    &format!("CREATE EDITION \"{child}\" AS CHILD OF \"{parent}\""),
                    &[],
                )
                .await;
            if let Err(error) = created {
                admin
                    .execute(&cx, &format!("DROP EDITION \"{parent}\" CASCADE"), &[])
                    .await
                    .expect("cleanup own parent after child refusal");
                panic!("create child: {error}");
            }
            let mut pinned_options = options.clone();
            pinned_options.session_identity = Some(OracleSessionIdentity {
                edition: Some(parent.clone()),
                ..Default::default()
            });
            let pinned = connect_oracle(&cx, pinned_options.clone()).await;
            let result = match pinned {
                Err(error) => Err(format!("pinned parent authentication: {error}")),
                Ok(pinned) => {
                    let profile:ConnectionProfile=serde_json::from_value(serde_json::json!({"name":"staging-live","connect_string":dsn,"username":user,"max_level":"DDL","edition_change_requests":true,"session_identity":{"edition":parent}})).unwrap();
                    let mut stage_options = pinned_options.clone();
                    stage_options.session_identity.as_mut().unwrap().module = Some(module.clone());
                    let budget = Arc::new(AdmissionController::new(2, 2));
                    let ordinary = budget
                        .try_admit(&cx, "ordinary")
                        .expect("ordinary lane charge");
                    let lanes = EditionStagingLanes::new(budget.clone());
                    let result = async {
                        let before = edition(&cx, pinned.as_ref()).await?;
                        check(
                            before == parent,
                            "pinned connection did not authenticate into parent",
                        )?;
                        let request = EditionStagingRequest {
                            change_request_id: &suffix,
                            child_edition: &child,
                            purpose: if cancel {
                                EditionStagingPurpose::Verify
                            } else {
                                EditionStagingPurpose::Stage
                            },
                            profile: &profile,
                            resolved_options: &stage_options,
                            subject: "live-stage",
                        };
                        if cancel {
                            let entered = Arc::new(AtomicBool::new(false));
                            let signal = entered.clone();
                            let result = asupersync::time::timeout(
                                cx.now(),
                                Duration::from_millis(250),
                                lanes.run(&cx, request, move |cx, _, conn| {
                                    Box::pin(async move {
                                        signal.store(true, Ordering::SeqCst);
                                        conn.execute(cx, "BEGIN DBMS_SESSION.SLEEP(4); END;", &[])
                                            .await?;
                                        Ok(())
                                    })
                                }),
                            )
                            .await;
                            check(
                                result.is_err(),
                                "slow native call did not reach the cancellation boundary",
                            )?;
                            check(
                                entered.load(Ordering::SeqCst),
                                "native operation never started",
                            )?;
                            check(
                                lanes.quarantined_connections() == 1,
                                "cancelled staging connection not quarantined",
                            )?;
                            check(
                                budget.available_global() == 0,
                                "cancelled operation released capacity",
                            )?;
                            check(
                                sessions(&cx, admin.as_ref(), &module).await? == 1,
                                "cancel control has no actual Oracle session",
                            )?;
                            let active = admin.query_rows(&cx,
                                "SELECT COUNT(*) AS n FROM v$session WHERE module = :1 AND status = 'ACTIVE' AND event = 'PL/SQL lock timer'",
                                &[OracleBind::String(module.clone())]).await.map_err(|e|e.to_string())?;
                            check(active.first().and_then(|row|row.parse_i64("N"))==Some(1),
                                "cancellation control did not leave an actual Oracle sleep executing")?;
                            let again = EditionStagingRequest {
                                change_request_id: &suffix,
                                child_edition: &child,
                                purpose: EditionStagingPurpose::Stage,
                                profile: &profile,
                                resolved_options: &stage_options,
                                subject: "live-stage",
                            };
                            let refused = lanes
                                .run(&cx, again, |_, _, _| {
                                    Box::pin(async {
                                        Err::<(), DbError>(DbError::Internal(
                                            "unexpected replacement staging call".into(),
                                        ))
                                    })
                                        as Pin<Box<dyn Future<Output = Result<(), DbError>>>>
                                })
                                .await;
                            check(
                                refused.is_err(),
                                "quarantined charge admitted a replacement",
                            )?;
                            lanes.dispose_quarantined_transports(&cx).await;
                            check(
                                budget.available_global() == 0,
                                "transport disposal fabricated session retirement",
                            )?;
                        } else {
                            let expected = child.clone();
                            let observed = lanes
                                .run(&cx, request, move |cx, context, conn| {
                                    Box::pin(async move {
                                        if context.child_edition() != expected {
                                            return Err(DbError::Internal(
                                                "wrong context child".into(),
                                            ));
                                        }
                                        let rows = run_catalog_query(
                                            cx,
                                            conn,
                                            CatalogQueryId::StagingCurrentEdition,
                                            &[],
                                        )
                                        .await?;
                                        Ok(rows
                                            .first()
                                            .and_then(|r| r.text("EDITION_NAME"))
                                            .unwrap_or_default()
                                            .to_owned())
                                    })
                                })
                                .await
                                .map_err(|e| format!("staging: {e:?}"))?;
                            check(
                                observed == child,
                                "native staging connection has wrong edition",
                            )?;
                            check(
                                lanes.quarantined_connections() == 0,
                                "successful staging call quarantined",
                            )?;
                            check(
                                budget.available_global() == 1,
                                "successful logical logoff did not return staging slot",
                            )?;
                        }
                        assert_pinned_edition_unchanged(&cx, pinned.as_ref(), &before)
                            .await
                            .map_err(|e| format!("pin invariant: {e:?}"))?;
                        check(
                            edition(&cx, pinned.as_ref()).await? == parent,
                            "ordinary pinned edition changed",
                        )?;
                        Ok(())
                    }
                    .await;
                    // Always dispose this test's abandoned transport before its
                    // bounded native census and own-edition teardown.
                    lanes.dispose_quarantined_transports(&cx).await;
                    let close = pinned.close(&cx).await.map_err(|e| e.to_string());
                    drop(ordinary);
                    result.and(close)
                }
            };
            let census = async {
                for _ in 0..12 {
                    if sessions(&cx, admin.as_ref(), &module).await? == 0 {
                        return Ok(());
                    }
                    asupersync::time::sleep(cx.now(), Duration::from_secs(1)).await;
                }
                Err("staging server session still present after bounded teardown".to_owned())
            }
            .await;
            let child_cleanup = admin
                .execute(&cx, &format!("DROP EDITION \"{child}\" CASCADE"), &[])
                .await;
            let parent_cleanup = admin
                .execute(&cx, &format!("DROP EDITION \"{parent}\" CASCADE"), &[])
                .await;
            admin.close(&cx).await.expect("admin logoff");
            child_cleanup.expect("cleanup own child");
            parent_cleanup.expect("cleanup own parent");
            census.expect("actual staging connection destroyed after call/disposal");
            result.expect("live staging contract");
        });
    }
    #[test]
    #[ignore = "requires a local Oracle lab admin and creates two run-owned editions"]
    fn staging_lane_authenticates_into_child_edition_live() {
        live_contract(false);
    }
    #[test]
    #[ignore = "requires a local Oracle lab admin and creates two run-owned editions"]
    fn pinned_lane_edition_unchanged_after_staging_live() {
        live_contract(false);
    }
    #[test]
    #[ignore = "requires a local Oracle lab admin and creates two run-owned editions"]
    fn staging_lane_destroyed_after_completion_live() {
        live_contract(false);
    }
    #[test]
    #[ignore = "requires a local Oracle lab admin and creates two run-owned editions"]
    fn staging_lane_quarantined_on_cancel_live() {
        live_contract(true);
    }
}
