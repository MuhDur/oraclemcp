use super::*;
use oraclemcp_db::{OracleBackend, OracleCell, OracleConnectionInfo};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Default)]
struct FactConnection {
    queries: AtomicUsize,
    schema_epoch: AtomicUsize,
    source_epoch: AtomicUsize,
    scn: AtomicUsize,
    trigger_count: AtomicUsize,
    source_unreadable: AtomicBool,
    dependency_owner: SyncMutex<Option<String>>,
}

fn row(cells: &[(&str, String)]) -> OracleRow {
    OracleRow {
        columns: cells
            .iter()
            .map(|(key, value)| {
                (
                    (*key).to_owned(),
                    OracleCell::new("VARCHAR2", Some(value.clone())),
                )
            })
            .collect(),
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for FactConnection {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn close(&self, _: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn ping(&self, _: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn describe(&self, _: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            current_schema: Some("APP".into()),
            ..Default::default()
        })
    }
    async fn query_rows(
        &self,
        _: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        self.queries.fetch_add(1, Ordering::Relaxed);
        if sql == CatalogQueryId::SessionContext.spec().sql {
            return Ok(vec![row(&[
                (
                    "CURRENT_SCHEMA",
                    format!("APP{}", self.schema_epoch.load(Ordering::Relaxed)),
                ),
                ("EDITION_NAME", "ORA$BASE".into()),
            ])]);
        }
        if sql == CatalogQueryId::PdbIdentity.spec().sql {
            return Ok(vec![row(&[("DBID", "1".into()), ("CON_UID", "2".into())])]);
        }
        if sql == CatalogQueryId::ClosureTriggers.spec().sql
            || sql == CatalogQueryId::DdlTriggers.spec().sql
        {
            return Ok((0..self.trigger_count.load(Ordering::Relaxed).max(1))
                .map(|index| {
                    row(&[
                        ("OWNER", "APP".into()),
                        ("TRIGGER_NAME", format!("TRG{index}")),
                    ])
                })
                .collect());
        }
        if sql == CatalogQueryId::ClosureSource.spec().sql {
            if self.source_unreadable.load(Ordering::Relaxed) {
                return Err(DbError::ServerQuery(
                    "ORA-01031: synthetic source unavailable".into(),
                ));
            }
            return Ok(vec![row(&[
                ("LINE", "1".into()),
                (
                    "TEXT",
                    format!("source {}", self.source_epoch.load(Ordering::Relaxed)),
                ),
            ])]);
        }
        if sql == CatalogQueryId::DependentsTransitive.spec().sql
            || sql == CatalogQueryId::ClosureCompilerSettings.spec().sql
        {
            if sql == CatalogQueryId::DependentsTransitive.spec().sql
                && let Some(OracleBind::String(json)) = binds.first()
            {
                let roots: Value = serde_json::from_str(json).unwrap();
                *self.dependency_owner.lock().unwrap() =
                    roots[0]["owner"].as_str().map(str::to_owned);
            }
            return Ok(Vec::new());
        }
        panic!("unexpected query outside the decisive fact allow-list");
    }
    async fn execute(&self, _: &Cx, _: &str, _: &[OracleBind]) -> Result<u64, DbError> {
        panic!("fact revalidation must never execute candidate SQL");
    }
    async fn commit(&self, _: &Cx) -> Result<(), DbError> {
        panic!("fact probe committed")
    }
    async fn rollback(&self, _: &Cx) -> Result<(), DbError> {
        panic!("fact probe rolled back")
    }
}

fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async move { body(Cx::current().unwrap()).await })
}

fn context<'a>(
    cx: &'a Cx,
    conn: &'a dyn OracleConnection,
    binding: &'a ExecGrantBinding,
    grants: &'a ScopedGrantStore,
    quarantine: &'a SyncMutex<Option<ConnectionQuarantine>>,
) -> FactProbeContext<'a> {
    FactProbeContext {
        cx,
        conn,
        binding,
        generations: ImpactGenerations {
            profile: binding.generation,
            lane: binding.generation,
        },
        policy: None,
        policy_provider: None,
        current_schema: Some("APP0"),
        quarantine,
        scoped_grants: grants,
        active_profile: Some("test"),
        is_preview: false,
    }
}

#[test]
fn token_fields_sign_decisive_digest_tamper_refused() {
    let binding = ExecGrantBinding::new("s", "l", "p", 1);
    let material = GrantMaterial {
        sql_digest: [6; 32],
        decisive_digest: [7; 32],
    };
    let token = sign_execute_grant_reference(
        "grant",
        &binding,
        Some("test"),
        OperatingLevel::ReadWrite,
        &material,
    );
    assert_eq!(
        verify_execute_grant_reference(&token, &binding, Some("test"), OperatingLevel::ReadWrite)
            .map(|reference| reference.raw_id)
            .as_deref(),
        Some("grant")
    );
    for at in [token.find('~').unwrap() + 1, token.rfind('~').unwrap() + 1] {
        let mut edited = token.clone().into_bytes();
        edited[at] = if edited[at] == b'0' { b'1' } else { b'0' };
        assert!(
            verify_execute_grant_reference(
                std::str::from_utf8(&edited).unwrap(),
                &binding,
                Some("test"),
                OperatingLevel::ReadWrite
            )
            .is_none()
        );
    }
    for changed in [
        GrantMaterial {
            sql_digest: [8; 32],
            ..material.clone()
        },
        GrantMaterial {
            decisive_digest: [8; 32],
            ..material.clone()
        },
    ] {
        assert_ne!(
            execute_grant_token_fields(
                &binding,
                Some("test"),
                OperatingLevel::ReadWrite,
                &material
            ),
            execute_grant_token_fields(&binding, Some("test"), OperatingLevel::ReadWrite, &changed),
        );
    }
}

#[test]
fn revalidate_scn_advance_does_not_invalidate() {
    run_with_cx(|cx| async move {
        let conn = FactConnection::default();
        let binding = ExecGrantBinding::new("s", "l", "p", 1);
        let grants = ScopedGrantStore::new();
        let quarantine = SyncMutex::new(None);
        let context = context(&cx, &conn, &binding, &grants, &quarantine);
        let captured = BoundImpact::capture(
            context,
            "UPDATE APP0.T SET X=:1 WHERE ID=:2",
            "envelope",
            &[],
            None,
            None,
            None,
        )
        .await
        .unwrap();
        conn.scn.store(9000, Ordering::Relaxed);
        captured.revalidate(context).await.unwrap();
        let mut observations_changed = captured.binding.clone();
        observations_changed.observations.scn_bounds = Some(oraclemcp_guard::ScnBounds::Window {
            scn_before: 9000,
            scn_after: 9001,
        });
        assert_eq!(
            observations_changed.decisive_digest().unwrap(),
            captured.material.decisive_digest
        );
    });
}

#[test]
fn revalidation_query_count_bounded_per_action() {
    run_with_cx(|cx| async move {
        let conn = FactConnection::default();
        conn.trigger_count
            .store(MAX_TRIGGER_FACTS, Ordering::Relaxed);
        let binding = ExecGrantBinding::new("s", "l", "p", 1);
        let grants = ScopedGrantStore::new();
        let quarantine = SyncMutex::new(None);
        let context = context(&cx, &conn, &binding, &grants, &quarantine);
        for sql in [
            "UPDATE APP0.T SET X=1 WHERE ID=2",
            "ALTER PROCEDURE APP0.P COMPILE",
            "CREATE OR REPLACE PROCEDURE APP0.P AS BEGIN NULL; END;",
            "BEGIN NULL; END;",
        ] {
            let before = conn.queries.load(Ordering::Relaxed);
            let captured = BoundImpact::capture(context, sql, "envelope", &[], None, None, None)
                .await
                .unwrap();
            let count = conn.queries.load(Ordering::Relaxed) - before;
            assert_eq!(Some(count), captured.query_count);
            assert!(count <= captured.probe.query_bound());
            let before = conn.queries.load(Ordering::Relaxed);
            captured.revalidate(context).await.unwrap();
            assert!(conn.queries.load(Ordering::Relaxed) - before <= captured.probe.query_bound());
        }
    });
}

#[test]
fn revalidate_runs_before_consume_and_before_execute() {
    run_with_cx(|cx| async move {
        let conn = FactConnection::default();
        let binding = ExecGrantBinding::new("s", "l", "p", 1);
        let scoped = ScopedGrantStore::new();
        let quarantine = SyncMutex::new(None);
        let context = context(&cx, &conn, &binding, &scoped, &quarantine);
        let sql = "UPDATE APP0.T SET X=1 WHERE ID=2";
        let preview = BoundImpact::capture(context, sql, "envelope", &[], None, None, None)
            .await
            .unwrap();
        let grants = ExecGrantStore::new();
        let token = grants.issue(
            preview.material.clone(),
            binding.clone(),
            OperatingLevel::ReadWrite,
            Duration::from_secs(60),
        );
        conn.source_epoch.store(1, Ordering::Relaxed);
        let changed = BoundImpact::capture(context, sql, "envelope", &[], None, None, None)
            .await
            .unwrap();
        assert_eq!(
            grants.consume(
                &token,
                &changed.material,
                &binding,
                OperatingLevel::ReadWrite
            ),
            Err(ExecGrantError::DecisiveMismatch)
        );
        conn.source_epoch.store(0, Ordering::Relaxed);
        let before_consume = BoundImpact::capture(context, sql, "envelope", &[], None, None, None)
            .await
            .unwrap();
        grants
            .consume(
                &token,
                &before_consume.material,
                &binding,
                OperatingLevel::ReadWrite,
            )
            .unwrap();
        conn.schema_epoch.store(1, Ordering::Relaxed);
        assert_eq!(
            before_consume
                .revalidate(context)
                .await
                .unwrap_err()
                .error_class,
            ErrorClass::RepreviewRequired
        );
    });
}

#[test]
fn revalidate_bind_value_changed_refused() {
    run_with_cx(|cx| async move {
        let conn = FactConnection::default();
        let binding = ExecGrantBinding::new("s", "l", "p", 1);
        let scoped = ScopedGrantStore::new();
        let quarantine = SyncMutex::new(None);
        let context = context(&cx, &conn, &binding, &scoped, &quarantine);
        let sql = "UPDATE APP0.T SET X=:1 WHERE ID=2";
        let preview = BoundImpact::capture(
            context,
            sql,
            "same-envelope-for-isolated-bind-check",
            &[OracleBind::I64(1)],
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let changed = BoundImpact::capture(
            context,
            sql,
            "same-envelope-for-isolated-bind-check",
            &[OracleBind::I64(2)],
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let grants = ExecGrantStore::new();
        let token = grants.issue(
            preview.material.clone(),
            binding.clone(),
            OperatingLevel::ReadWrite,
            Duration::from_secs(60),
        );
        assert_eq!(
            grants.consume(
                &token,
                &changed.material,
                &binding,
                OperatingLevel::ReadWrite
            ),
            Err(ExecGrantError::DecisiveMismatch)
        );
        grants
            .consume(
                &token,
                &preview.material,
                &binding,
                OperatingLevel::ReadWrite,
            )
            .unwrap();
    });
}

#[derive(Clone)]
struct LogCapture(Arc<SyncMutex<Vec<u8>>>);
impl std::io::Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct SharedAudit(Arc<oraclemcp_audit::MemoryAuditSink>);
impl oraclemcp_audit::AuditSink for SharedAudit {
    fn append(
        &self,
        record: &oraclemcp_audit::AuditRecord,
    ) -> Result<(), oraclemcp_audit::AuditError> {
        oraclemcp_audit::AuditSink::append(self.0.as_ref(), record)
    }
    fn flush(&self) -> Result<(), oraclemcp_audit::AuditError> {
        Ok(())
    }
}

fn captured_audit(
    canary: &'static str,
) -> (oraclemcp_audit::AuditRecord, String, String, GrantMaterial) {
    let records = Arc::new(oraclemcp_audit::MemoryAuditSink::new());
    let sink = records.clone();
    let logs = LogCapture(Arc::new(SyncMutex::new(Vec::new())));
    let log_reader = logs.0.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || logs.clone())
        .finish();
    let (debug, material) = tracing::subscriber::with_default(subscriber, || {
        run_with_cx(|cx| async move {
            let conn = FactConnection::default();
            let binding = ExecGrantBinding::new("s", "l", "p", 1);
            let scoped = ScopedGrantStore::new();
            let quarantine = SyncMutex::new(None);
            let context = context(&cx, &conn, &binding, &scoped, &quarantine);
            let sql = "UPDATE APP0.T SET X=:1 WHERE ID=:2";
            let binds = [OracleBind::String(canary.into()), OracleBind::I64(7)];
            let envelope = action_envelope_material(ActionEnvelopeInput {
                sql,
                binds: &binds,
                kind: ActionKind::ExecuteDml,
                commit: true,
                hold: false,
                capture_dbms_output: false,
                max_lines: None,
                max_chars: None,
                timeout_seconds: None,
                scoped_grant: None,
            });
            let captured = BoundImpact::capture(context, sql, &envelope, &binds, None, None, None)
                .await
                .unwrap();
            let grants = ExecGrantStore::new();
            grants.issue(
                captured.material.clone(),
                binding.clone(),
                OperatingLevel::ReadWrite,
                Duration::from_secs(60),
            );
            captured.revalidate(context).await.unwrap();
            let key = oraclemcp_audit::SigningKey::new("impact-test", vec![7; 32]).unwrap();
            let auditor = Auditor::new(Box::new(SharedAudit(sink)), key);
            let subject = AuditSubject::new("test", "subject");
            let impact = captured
                .audit_binding(oraclemcp_audit::AuditRevalidationStage::BeforeExecute)
                .unwrap();
            append_audit(
                AuditEntryCtx {
                    auditor: Some(&auditor),
                    subject: &subject,
                    db_evidence: None,
                    impact: Some(&impact),
                },
                "oracle_execute",
                sql,
                "GUARDED",
                None,
                AuditOutcome::Pending,
            )
            .unwrap();
            (format!("{grants:?}"), captured.material)
        })
    });
    let log_text = String::from_utf8(log_reader.lock().unwrap().clone()).unwrap();
    (records.records()[0].clone(), debug, log_text, material)
}

#[test]
fn bind_values_absent_from_exec_grant_audit_logs() {
    const CANARY: &str = "synthetic-bind-canary-c90a7df8";
    let (record, debug, logs, material) = captured_audit(CANARY);
    for text in [
        serde_json::to_string(&record).unwrap(),
        format!("{record:?}"),
        debug,
        logs,
        format!("{material:?}"),
    ] {
        assert!(!text.contains(CANARY), "raw bind escaped digest custody");
    }
}

#[test]
fn audit_records_statement_and_decisive_digest() {
    let (record, _, _, material) = captured_audit("audit-fixture-bind");
    assert_eq!(
        record.statement_digest.as_deref(),
        Some(oraclemcp_guard::sql_digest("UPDATE APP0.T SET X=:1 WHERE ID=:2").as_str())
    );
    assert_eq!(
        record.decisive_digest,
        Some(format!("sha256:{}", hex_digest(&material.decisive_digest)))
    );
    assert_eq!(
        record.revalidated_at,
        Some(oraclemcp_audit::AuditRevalidationStage::BeforeExecute)
    );
    let key = oraclemcp_audit::SigningKey::new("impact-test", vec![7; 32]).unwrap();
    assert!(record.hash_is_valid());
    assert!(record.signature_is_valid(&key));
    let mut edited = record.clone();
    edited.statement_digest = None;
    assert!(!edited.hash_is_valid());
    let mut edited = record.clone();
    edited.decisive_digest = None;
    assert!(!edited.hash_is_valid());
    let mut edited = record;
    edited.revalidated_at = Some(oraclemcp_audit::AuditRevalidationStage::BeforeConsume);
    assert!(!edited.hash_is_valid());
}

#[cfg(feature = "plsql-intelligence")]
async fn live_fixture(cx: Cx, case: u8) -> Result<(), String> {
    use oraclemcp_db::{OracleConnectOptions, RustOracleConnection};
    let options = OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN").map_err(|_| "live DSN absent")?,
        username: Some(std::env::var("ORACLEMCP_TEST_USER").map_err(|_| "live user absent")?),
        password: Some(
            std::env::var("ORACLEMCP_TEST_PASSWORD").map_err(|_| "live password absent")?,
        ),
        call_timeout: Some(Duration::from_secs(20)),
        ..Default::default()
    };
    if options.connect_string != "localhost:1523/FREEPDB1" {
        return Err("impact-grant fixture requires local FREE23".into());
    }
    let conn = RustOracleConnection::connect(&cx, options)
        .await
        .map_err(|e| e.to_string())?;
    let owner = conn
        .describe(&cx)
        .await
        .map_err(|e| e.to_string())?
        .current_schema
        .ok_or("schema absent")?;
    let id = oraclemcp_db::PlanStatementId::generate().map_err(|e| e.to_string())?;
    let suffix = id.as_str()[5..13].to_ascii_uppercase();
    let table = format!("OMCPG_{suffix}_T");
    let view = format!("OMCPG_{suffix}_V");
    let source_view = format!("OMCPG_{suffix}_P");
    let trigger = format!("OMCPG_{suffix}_G");
    let qualify = |name: &str| format!("\"{owner}\".\"{name}\"");
    let sql = |statement: String| {
        let conn = &conn;
        let cx = &cx;
        async move {
            conn.execute(cx, &statement, &[])
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
    };
    let mut created = Vec::new();
    let result =
        async {
            sql(format!(
                "CREATE TABLE {} (ID NUMBER PRIMARY KEY, N NUMBER)",
                qualify(&table)
            ))
            .await?;
            created.push(("TABLE", table.clone()));
            sql(format!("INSERT INTO {} VALUES (1, 10)", qualify(&table))).await?;
            conn.commit(&cx).await.map_err(|e| e.to_string())?;
            let candidate = if case == 2 {
                sql(format!(
                    "CREATE VIEW {} AS SELECT /* source v1 */ 1 N FROM SYS.DUAL",
                    qualify(&source_view),
                ))
                .await?;
                created.push(("VIEW", source_view.clone()));
                format!("ALTER VIEW {} COMPILE", qualify(&source_view))
            } else {
                if case == 1 {
                    sql(format!(
                        "CREATE VIEW {} AS SELECT N FROM {}",
                        qualify(&view),
                        qualify(&table)
                    ))
                    .await?;
                    created.push(("VIEW", view.clone()));
                }
                format!("UPDATE {} SET N=:1 WHERE ID=:2", qualify(&table))
            };
            let binding =
                ExecGrantBinding::new("native-impact-session", "native-impact-lane", "fixture", 1);
            let scoped = ScopedGrantStore::new();
            let quarantine = SyncMutex::new(None);
            let context = FactProbeContext {
                cx: &cx,
                conn: &conn,
                binding: &binding,
                generations: ImpactGenerations {
                    profile: 1,
                    lane: 1,
                },
                policy: None,
                policy_provider: None,
                current_schema: Some(&owner),
                quarantine: &quarantine,
                scoped_grants: &scoped,
                active_profile: Some("native-impact"),
                is_preview: false,
            };
            let binds = if case == 2 {
                Vec::new()
            } else {
                vec![OracleBind::I64(11), OracleBind::I64(1)]
            };
            let level = if case == 2 {
                OperatingLevel::Ddl
            } else {
                OperatingLevel::ReadWrite
            };
            let capture = || {
                BoundImpact::capture(
                    context,
                    &candidate,
                    "native-approved-envelope",
                    &binds,
                    None,
                    None,
                    None,
                )
            };
            let mut preview = capture().await.map_err(|e| e.message)?;
            let scn = || async {
                let rows = run_catalog_query(&cx, &conn, CatalogQueryId::CurrentScn, &[])
                    .await
                    .map_err(|e| e.to_string())?;
                rows.first()
                    .and_then(|row| row.parse_i64("OBSERVED_SCN"))
                    .ok_or("native SCN absent".to_owned())
            };
            let scn_before = scn().await?;
            sql(format!("INSERT INTO {} VALUES (2, 20)", qualify(&table))).await?;
            conn.commit(&cx).await.map_err(|e| e.to_string())?;
            let scn_after = scn().await?;
            if scn_after <= scn_before {
                return Err("native SCN did not advance".into());
            }
            preview.revalidate(context).await.map_err(|e| e.message)?;
            if !matches!(
                preview.binding.decisive.objects,
                FieldStatus::Computed { .. }
            ) {
                return Err("native root facts were not computed".into());
            }
            let grants = ExecGrantStore::new();
            let mut confirm = issue_confirmation_grant(
                &grants,
                &binding,
                Some("native-impact"),
                &preview.material,
                level,
            );
            if case == 1 {
                sql(format!(
                    "CREATE OR REPLACE VIEW {} AS SELECT N+1 N FROM {}",
                    qualify(&view),
                    qualify(&table)
                ))
                .await?;
            } else if case == 2 {
                // Read the complete real source/dependency snapshot before the
                // timing window: that bounded query can take seconds on FREE23.
                // Replacing identical v1 source only refreshes root metadata;
                // refresh that metadata from Oracle before signing the grant.
                let mut closure = probe_dependents_transitive(
                    &cx, &conn, &[DependentObject {
                        owner: owner.clone(), name: source_view.clone(), object_type: "VIEW".into(),
                    }], DepCaps::default(),
                ).await.map_err(|e| e.to_string())?;
                let rehash = |closure: &mut oraclemcp_db::DependentsClosure| {
                    use sha2::{Digest, Sha256};
                    closure.dependency_hash = [0; 32];
                    let mut hash = Sha256::new();
                    hash.update(b"omcp/dependents-closure/v1\0");
                    hash.update(serde_json::to_vec(closure).expect("live closure serialization"));
                    closure.dependency_hash = hash.finalize().into();
                };
                let original_hash = closure.dependency_hash;
                rehash(&mut closure);
                assert_eq!(closure.dependency_hash, original_hash, "fixture canonical encoding must match the production collector");
                let metadata = || async {
                    let rows = run_catalog_query(
                        &cx,
                        &conn,
                        CatalogQueryId::ClosureMemberObject,
                        &[
                            OracleBind::String(owner.clone()),
                            OracleBind::String(source_view.clone()),
                            OracleBind::String("VIEW".into()),
                            OracleBind::I64(2),
                        ],
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                    if rows.len() != 1 { return Err("native metadata not unique".to_owned()); }
                    Ok(rows.into_iter().next().unwrap())
                };
                let mut same_second = false;
                for attempt in 0..8 {
                    // This dedicated fixture runtime has no I/O in flight here.
                    // Align to the local lab's wall second without advancing its
                    // async clock or substituting either Oracle dictionary date.
                    let fraction = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|e| e.to_string())?
                        .subsec_millis();
                    std::thread::sleep(Duration::from_millis(u64::from(1020 - fraction)));
                    let measured = std::time::Instant::now();
                    sql(format!(
                        "BEGIN EXECUTE IMMEDIATE 'CREATE OR REPLACE VIEW {} AS SELECT /* source v1 */ 1 N FROM SYS.DUAL'; END;",
                        qualify(&source_view),
                    ))
                    .await?;
                    let root_metadata = metadata().await?;
                    let probe_elapsed = measured.elapsed();
                    let before = root_metadata.text("last_ddl_time").ok_or("native timestamp absent")?.to_owned();
                    let root_node = closure
                        .roots
                        .iter_mut()
                        .find(|node| node.object.name == source_view)
                        .ok_or("native root absent")?;
                    let object_id = root_metadata.text("object_id").and_then(|s| s.parse().ok());
                    let status = root_metadata.text("status").map(str::to_owned);
                    assert_eq!(root_node.object_id, object_id);
                    assert_eq!(root_node.status, status);
                    root_node.last_ddl_time = Some(before.clone());
                    rehash(&mut closure);
                    let FieldStatus::Computed { value: previous } =
                        &preview.binding.decisive.objects
                    else {
                        return Err("native object component unavailable".into());
                    };
                    let trigger_hash = previous
                        .first()
                        .ok_or("native object component empty")?
                        .trigger_hash
                        .clone();
                    let mut objects = dependency_object_facts(&closure);
                    for object in &mut objects {
                        object.trigger_hash = trigger_hash.clone();
                    }
                    preview.binding.decisive.objects = computed(objects);
                    preview.material = GrantMaterial::new(&candidate, &preview.binding)
                        .map_err(|e| e.to_string())?;
                    confirm = issue_confirmation_grant(
                        &grants,
                        &binding,
                        Some("native-impact"),
                        &preview.material,
                        level,
                    );
                    sql(format!(
                        "BEGIN EXECUTE IMMEDIATE 'CREATE OR REPLACE VIEW {} AS SELECT /* source v2 */ 1 N FROM SYS.DUAL'; END;",
                        qualify(&source_view),
                    ))
                    .await?;
                    let after = metadata().await?.text("last_ddl_time").ok_or("native timestamp absent")?.to_owned();
                    tracing::info!(
                        "native source attempt {}: same_last_ddl_time={}, before={}, after={}, object_probe_queries={}, probe_elapsed={:?}, total_elapsed={:?}",
                        attempt + 1,
                        before == after,
                        before,
                        after,
                        closure.query_count(),
                        probe_elapsed,
                        measured.elapsed(),
                    );
                    if before == after {
                        same_second = true;
                        break;
                    }
                    if attempt == 7 {
                        return Err(
                            "could not establish same LAST_DDL_TIME premise in eight attempts"
                                .into(),
                        );
                    }
                }
                assert!(same_second);
            } else {
                sql(format!(
                    "CREATE TRIGGER {} BEFORE UPDATE ON {} FOR EACH ROW BEGIN NULL; END;",
                    qualify(&trigger),
                    qualify(&table)
                ))
                .await?;
                created.push(("TRIGGER", trigger.clone()));
            }
            let current = capture().await.map_err(|e| e.message)?;
            if case == 2 {
                let (
                    FieldStatus::Computed { value: before },
                    FieldStatus::Computed { value: after },
                ) = (
                    &preview.binding.decisive.objects,
                    &current.binding.decisive.objects,
                )
                else {
                    return Err("native source comparison lacks object facts".into());
                };
                if before.len() != after.len() {
                    return Err("native source control changed object membership".into());
                }
                for (old, new) in before.iter().zip(after) {
                    if old.identity != new.identity
                        || old.status != new.status
                        || old.trigger_hash != new.trigger_hash
                    {
                        return Err("native source control changed non-source object facts".into());
                    }
                }
                let source = |objects: &[oraclemcp_guard::ObjectFact]| {
                    objects.iter().find_map(|object| {
                        if let (
                            FieldStatus::Computed { value: identity },
                            FieldStatus::Computed { value: hash },
                        ) = (&object.identity, &object.source_hash)
                            && identity.contains(&source_view)
                        {
                            Some(*hash)
                        } else {
                            None
                        }
                    })
                };
                let old = source(before).ok_or("native original source hash unavailable")?;
                let new = source(after).ok_or("native changed source hash unavailable")?;
                if old == new {
                    return Err("native source content hash did not change".into());
                }
                let mut old_rest = preview.binding.clone();
                old_rest.decisive.objects = FieldStatus::not_wired();
                let mut new_rest = current.binding.clone();
                new_rest.decisive.objects = FieldStatus::not_wired();
                if old_rest.decisive_digest().map_err(|e| e.to_string())?
                    != new_rest.decisive_digest().map_err(|e| e.to_string())?
                {
                    return Err("native source control changed non-object decisive facts".into());
                }
            }
            let failure = consume_confirmation_grant(ConfirmationGrantRequest {
                material: &current.material,
                required_level: level,
                active_profile: Some("native-impact"),
                grants: &grants,
                binding: &binding,
                confirm: Some(&confirm),
                challenge_message: "fixture approval required",
                suggested_tool: "oracle_preview_sql",
                next_step: "preview again",
            })
            .expect_err("native catalog drift must refuse before consuming the grant");
            if failure.error_class != ErrorClass::RepreviewRequired {
                return Err(format!(
                    "native drift had wrong typed refusal: {:?}",
                    failure.error_class
                ));
            }
            let raw =
                verify_execute_grant_reference(&confirm, &binding, Some("native-impact"), level)
                    .ok_or("native grant signature")?;
            grants
                .consume(&raw.raw_id, &preview.material, &binding, level)
                .map_err(|e| format!("stale-fact refusal burned token: {e:?}"))?;
            assert!(
                current
                    .query_count
                    .is_some_and(|count| count <= current.probe.query_bound())
            );
            Ok(())
        }
        .await;
    let mut cleanup = Ok(());
    for (kind, name) in created.into_iter().rev() {
        if let Err(error) = sql(format!("DROP {kind} {}", qualify(&name))).await {
            cleanup = Err(error);
        }
    }
    let closed = conn.close(&cx).await.map_err(|e| e.to_string());
    result?;
    cleanup?;
    closed
}

#[cfg(feature = "plsql-intelligence")]
fn run_native_case(case: u8) {
    // This fixture exercises the real native catalog and signed-grant kernel,
    // not mailbox admission. Its bounded multi-step setup has a separate
    // deadline from any individual production request.
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("native impact runtime");
    let result = runtime.block_on(async {
        let cx = Cx::current().expect("native fixture Cx");
        asupersync::time::timeout(cx.now(), Duration::from_secs(120), live_fixture(cx, case)).await
    });
    result
        .expect("native fixture exceeded 120 seconds")
        .expect("native impact revalidation");
}

#[cfg(feature = "plsql-intelligence")]
#[test]
#[ignore = "requires administrative access to local FREE23"]
fn revalidate_live_dependent_altered_repreview_required() {
    run_native_case(1);
}
#[cfg(feature = "plsql-intelligence")]
#[test]
#[ignore = "requires administrative access to local FREE23"]
fn revalidate_live_source_change_same_last_ddl_time_invalidates() {
    run_native_case(2);
}
#[cfg(feature = "plsql-intelligence")]
#[test]
#[ignore = "requires administrative access to local FREE23"]
fn revalidate_live_trigger_added_repreview_required() {
    run_native_case(3);
}

#[test]
fn revalidate_policy_provider_changed_refused() {
    run_with_cx(|cx| async move {
        let conn = FactConnection::default();
        let binding = ExecGrantBinding::new("s", "l", "p", 1);
        let scoped = ScopedGrantStore::new();
        let quarantine = SyncMutex::new(None);
        let provider = SyncMutex::new(None);
        let context = FactProbeContext {
            policy_provider: Some(&provider),
            ..context(&cx, &conn, &binding, &scoped, &quarantine)
        };
        let captured = BoundImpact::capture(
            context,
            "UPDATE APP0.T SET X=1 WHERE ID=2",
            "envelope",
            &[],
            None,
            None,
            None,
        )
        .await
        .unwrap();
        captured.revalidate(context).await.unwrap();
        *provider.lock().unwrap() = Some(SqlPolicyConfig {
            version: 1,
            rules: Vec::new(),
        });
        assert_eq!(
            captured.revalidate(context).await.unwrap_err().error_class,
            ErrorClass::RepreviewRequired
        );
    });
}

#[test]
fn signed_impact_cannot_alias_another_store_material() {
    let binding = ExecGrantBinding::new("same-session", "same-lane", "same-subject", 1);
    let material_a = GrantMaterial {
        sql_digest: ActionEnvelopeV1::statement_digest("UPDATE APP.T SET N=:1"),
        decisive_digest: [1; 32],
    };
    for material_b in [
        GrantMaterial {
            decisive_digest: [2; 32],
            ..material_a.clone()
        },
        GrantMaterial {
            sql_digest: [3; 32],
            ..material_a.clone()
        },
    ] {
        let grants_a = ExecGrantStore::new();
        let grants_b = ExecGrantStore::new();
        let token_a = issue_confirmation_grant(
            &grants_a,
            &binding,
            Some("same-profile"),
            &material_a,
            OperatingLevel::ReadWrite,
        );
        let token_b = issue_confirmation_grant(
            &grants_b,
            &binding,
            Some("same-profile"),
            &material_b,
            OperatingLevel::ReadWrite,
        );
        let raw_a = verify_execute_grant_reference(
            &token_a,
            &binding,
            Some("same-profile"),
            OperatingLevel::ReadWrite,
        )
        .unwrap();
        let raw_b = verify_execute_grant_reference(
            &token_b,
            &binding,
            Some("same-profile"),
            OperatingLevel::ReadWrite,
        )
        .unwrap();
        assert_eq!(
            raw_a.raw_id, raw_b.raw_id,
            "independent stores restart their counters"
        );
        let consume = |token, material| {
            consume_confirmation_grant(ConfirmationGrantRequest {
                material,
                required_level: OperatingLevel::ReadWrite,
                active_profile: Some("same-profile"),
                grants: &grants_b,
                binding: &binding,
                confirm: Some(token),
                challenge_message: "approval required",
                suggested_tool: "oracle_preview_sql",
                next_step: "preview again",
            })
        };
        assert_eq!(
            consume(&token_a, &material_b).unwrap_err().error_class,
            ErrorClass::RepreviewRequired
        );
        consume(&token_b, &material_b)
            .expect("foreign impact must not burn the legitimate store's token");
        grants_a
            .consume(
                &raw_a.raw_id,
                &material_a,
                &binding,
                OperatingLevel::ReadWrite,
            )
            .unwrap();
    }
}

#[test]
fn unqualified_fact_target_uses_fresh_current_schema() {
    run_with_cx(|cx| async move {
        let conn = FactConnection::default();
        let identity = ExecGrantBinding::new("s", "l", "p", 1);
        let scoped = ScopedGrantStore::new();
        let quarantine = SyncMutex::new(None);
        let context = FactProbeContext {
            current_schema: Some("STALE_CACHED_SCHEMA"),
            ..context(&cx, &conn, &identity, &scoped, &quarantine)
        };
        BoundImpact::capture(
            context,
            "UPDATE T SET X=1 WHERE ID=2",
            "envelope",
            &[],
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            conn.dependency_owner.lock().unwrap().as_deref(),
            Some("APP0")
        );
    });
}

#[test]
fn unreadable_trigger_source_does_not_hide_known_catalog_drift() {
    run_with_cx(|cx| async move {
        let conn = FactConnection::default();
        conn.source_unreadable.store(true, Ordering::Relaxed);
        let identity = ExecGrantBinding::new("s", "l", "p", 1);
        let scoped = ScopedGrantStore::new();
        let quarantine = SyncMutex::new(None);
        let context = context(&cx, &conn, &identity, &scoped, &quarantine);
        let sql = "UPDATE APP0.T SET X=1 WHERE ID=2";
        let preview = BoundImpact::capture(context, sql, "envelope", &[], None, None, None)
            .await
            .unwrap();
        let FieldStatus::Computed { value: objects } = &preview.binding.decisive.objects else {
            panic!("object facts");
        };
        assert!(
            objects
                .iter()
                .all(|object| matches!(object.trigger_hash, FieldStatus::Estimated { .. })),
            "partial source visibility must not claim an exact trigger fingerprint"
        );
        let grants = ExecGrantStore::new();
        let token = grants.issue(
            preview.material.clone(),
            identity.clone(),
            OperatingLevel::ReadWrite,
            Duration::from_secs(60),
        );
        conn.trigger_count.store(2, Ordering::Relaxed);
        let current = BoundImpact::capture(context, sql, "envelope", &[], None, None, None)
            .await
            .unwrap();
        assert_eq!(
            grants.consume(
                &token,
                &current.material,
                &identity,
                OperatingLevel::ReadWrite
            ),
            Err(ExecGrantError::DecisiveMismatch)
        );
        grants
            .consume(
                &token,
                &preview.material,
                &identity,
                OperatingLevel::ReadWrite,
            )
            .unwrap();
    });
}

#[test]
fn revalidate_profile_and_lane_generations_independently() {
    run_with_cx(|cx| async move {
        let conn = FactConnection::default();
        let identity = ExecGrantBinding::new("s", "l", "p", 1);
        let scoped = ScopedGrantStore::new();
        let quarantine = SyncMutex::new(None);
        let initial = context(&cx, &conn, &identity, &scoped, &quarantine);
        let captured = BoundImpact::capture(
            initial,
            "UPDATE APP0.T SET X=1 WHERE ID=2",
            "envelope",
            &[],
            None,
            None,
            None,
        )
        .await
        .unwrap();
        for generations in [
            ImpactGenerations {
                profile: 2,
                lane: 1,
            },
            ImpactGenerations {
                profile: 1,
                lane: 2,
            },
        ] {
            let changed = FactProbeContext {
                generations,
                ..initial
            };
            assert_eq!(
                captured.revalidate(changed).await.unwrap_err().error_class,
                ErrorClass::RepreviewRequired
            );
        }
    });
}
