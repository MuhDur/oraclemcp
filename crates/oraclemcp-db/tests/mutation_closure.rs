//! Unit integration checks with explicit catalog and effect-port test doubles.
//! The native collector fixture lives in the server crate, which owns the engine.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};

use asupersync::{Cx, runtime::RuntimeBuilder};
use oraclemcp_db::mutation_closure::*;
use oraclemcp_db::{
    CatalogQueryId, DbError, OracleBackend, OracleBind, OracleCell, OracleConnection,
    OracleConnectionInfo, OracleRow,
};
use oraclemcp_guard::mutation_closure::*;
use oraclemcp_guard::{
    CatalogObjectKind, EffectRefusal, OperatingLevel, ResolvedIdentity, ResolvedObject,
    RoutineEffect, RoutineEffectsV1,
};
use sha2::{Digest, Sha256};

fn row(values: &[(&str, Option<&str>)]) -> OracleRow {
    OracleRow {
        columns: values
            .iter()
            .map(|(name, value)| {
                (
                    (*name).to_owned(),
                    OracleCell::new("VARCHAR2", value.map(str::to_owned)),
                )
            })
            .collect(),
    }
}

fn target(name: &str) -> ResolvedObject {
    ResolvedObject {
        owner: "APP".into(),
        name: name.into(),
        kind: CatalogObjectKind::Table,
        container: None,
        member: None,
        overloads: Vec::new(),
        quote_exact: true,
        synonym_chain: Vec::new(),
        db_link: None,
        identity: ResolvedIdentity {
            object_id: if name == "ROOT" { 42 } else { 43 },
            edition: None,
        },
    }
}

#[derive(Default)]
struct Catalog {
    overrides: Vec<(CatalogQueryId, String, Vec<OracleRow>)>,
    denied: Option<CatalogQueryId>,
    sources: BTreeMap<String, String>,
    executions: AtomicUsize,
}

impl Catalog {
    fn rows(&mut self, id: CatalogQueryId, table: &str, rows: Vec<OracleRow>) {
        self.overrides.push((id, table.into(), rows));
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for Catalog {
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
        Ok(OracleConnectionInfo::default())
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        let id = *CatalogQueryId::ALL
            .iter()
            .find(|id| id.spec().sql == sql)
            .expect("closed query");
        if self.denied == Some(id) {
            return Err(DbError::Query("catalog visibility denied".into()));
        }
        let text = |index: usize| match binds.get(index) {
            Some(OracleBind::String(value)) => value.as_str(),
            _ => "",
        };
        if let Some((_, _, rows)) = self
            .overrides
            .iter()
            .rev()
            .find(|(query, name, _)| *query == id && name == text(1))
        {
            return Ok(rows.clone());
        }
        Ok(match id {
            CatalogQueryId::ClosureIdentity => vec![row(&[
                ("DBID", Some("42")),
                ("CONTAINER_NAME", Some("FREEPDB1")),
                ("EDITION_NAME", Some("ORA$BASE")),
            ])],
            CatalogQueryId::MutationTarget => vec![row(&[
                ("OWNER", Some(text(0))),
                ("OBJECT_NAME", Some(text(1))),
                (
                    "OBJECT_ID",
                    Some(if text(1) == "ROOT" { "42" } else { "43" }),
                ),
                ("EDITION_NAME", None),
                ("STATUS", Some("VALID")),
                ("LAST_DDL_TIME", Some("2026-10-31T00:00:00")),
            ])],
            CatalogQueryId::MutationColumns => ["C1", "C2"]
                .into_iter()
                .map(|column| {
                    row(&[
                        ("OWNER", Some(text(0))),
                        ("TABLE_NAME", Some(text(1))),
                        ("COLUMN_NAME", Some(column)),
                        ("DATA_TYPE", Some("NUMBER")),
                        ("DATA_TYPE_OWNER", None),
                        ("VIRTUAL_COLUMN", Some("NO")),
                        ("HIDDEN_COLUMN", Some("NO")),
                        ("USER_GENERATED", Some("YES")),
                        ("DEFAULT_LENGTH", None),
                        ("DATA_DEFAULT", None),
                    ])
                })
                .collect(),
            CatalogQueryId::ClosureMemberObject => vec![row(&[
                ("OBJECT_ID", Some("99")),
                ("LAST_DDL_TIME", Some("2026-10-31T00:00:00")),
                ("STATUS", Some("VALID")),
            ])],
            CatalogQueryId::ClosureRoutineAuthid => vec![row(&[
                ("AUTHID", Some("DEFINER")),
                ("SUBPROGRAM_ID", Some("1")),
                ("OVERLOAD", None),
            ])],
            CatalogQueryId::ClosureCompilerSettings => vec![row(&[
                ("PLSQL_OPTIMIZE_LEVEL", Some("2")),
                ("PLSQL_CODE_TYPE", Some("INTERPRETED")),
                ("PLSQL_DEBUG", Some("FALSE")),
                ("PLSQL_WARNINGS", Some("DISABLE:ALL")),
                ("PLSQL_CCFLAGS", None),
                ("NLS_LENGTH_SEMANTICS", Some("BYTE")),
                ("PLSCOPE_SETTINGS", Some("IDENTIFIERS:NONE")),
            ])],
            CatalogQueryId::ClosureSource => {
                let source =
                    self.sources.get(text(1)).cloned().unwrap_or_else(|| {
                        format!("{} {} IS BEGIN NULL; END;\n", text(2), text(1))
                    });
                vec![row(&[("LINE", Some("1")), ("TEXT", Some(&source))])]
            }
            CatalogQueryId::MutationTypeAuthid => vec![row(&[
                ("OWNER", Some(text(0))),
                ("TYPE_NAME", Some(text(1))),
                ("AUTHID", Some("DEFINER")),
            ])],
            CatalogQueryId::OlsInstallationEvidence => vec![row(&[("VALUE", Some("FALSE"))])],
            CatalogQueryId::RedactionInstallationEvidence => {
                vec![row(&[("DATA_REDACTION", Some("FALSE"))])]
            }
            CatalogQueryId::MutationTriggers
            | CatalogQueryId::MutationTriggerColumns
            | CatalogQueryId::MutationForeignKeys
            | CatalogQueryId::MutationIndexes
            | CatalogQueryId::MutationIndexExpressions
            | CatalogQueryId::MutationVpdPolicies
            | CatalogQueryId::MutationFgaPolicies
            | CatalogQueryId::MutationMvLogs
            | CatalogQueryId::MutationRasPolicies => Vec::new(),
            _ => panic!("unexpected collector query {id:?}"),
        })
    }
    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        Err(DbError::Execute("collector must never execute SQL".into()))
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        panic!("collector must not commit")
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        panic!("collector must not roll back")
    }
}

#[derive(Default)]
struct Effects {
    effects: BTreeMap<String, RoutineEffectsV1>,
    wrong_hash: bool,
    expected_owner: Option<String>,
    expected_storage: Option<String>,
    expected_object_id: Option<u64>,
}

#[async_trait::async_trait(?Send)]
impl MutationEffectOracle for Effects {
    async fn prove_source(
        &self,
        _cx: &Cx,
        _conn: &dyn OracleConnection,
        source: &MutationRoutineSource,
    ) -> Result<MutationRoutineProof, MutationUnavailableReason> {
        if self
            .expected_owner
            .as_ref()
            .is_some_and(|owner| *owner != source.owner)
        {
            return Err(MutationUnavailableReason::EffectSourceMismatch);
        }
        if self
            .expected_storage
            .as_ref()
            .is_some_and(|kind| source.expression_storage_type.as_ref() != Some(kind))
            || self
                .expected_object_id
                .is_some_and(|id| source.object_id != id)
        {
            return Err(MutationUnavailableReason::EffectSourceMismatch);
        }
        let bytes = Sha256::digest(source.source.as_bytes());
        let fingerprint = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(MutationRoutineProof {
            use_context: source.use_context,
            source_sha256: if self.wrong_hash {
                "0".repeat(64)
            } else {
                source.source_sha256.clone()
            },
            closure_fingerprint: fingerprint,
            effects: self.effects.get(&source.name).cloned().unwrap_or_default(),
            mutations: Vec::new(),
        })
    }
}

fn index(owner: &str, name: &str, kind: &str) -> OracleRow {
    let domain = kind.contains("DOMAIN");
    row(&[
        ("INDEX_OWNER", Some(owner)),
        ("INDEX_NAME", Some(name)),
        ("TABLE_OWNER", Some("APP")),
        ("TABLE_NAME", Some("ROOT")),
        ("INDEX_TYPE", Some(kind)),
        ("STATUS", Some("VALID")),
        ("ITYP_OWNER", if domain { Some("APP") } else { None }),
        ("ITYP_NAME", if domain { Some("IXTYPE") } else { None }),
        ("DOMIDX_STATUS", if domain { Some("VALID") } else { None }),
        ("DOMIDX_OPSTATUS", if domain { Some("VALID") } else { None }),
        (
            "FUNCIDX_STATUS",
            if kind.starts_with("FUNCTION-BASED") {
                Some("ENABLED")
            } else {
                None
            },
        ),
        ("PARTITIONED", Some("NO")),
        ("JOIN_INDEX", Some("NO")),
    ])
}

#[test]
fn mutation_closure_ordinary_index_rejects_conflicting_callback_metadata() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut catalog = Catalog::default();
        let ordinary = index("APP", "IX_NORMAL", "NORMAL");
        catalog.rows(
            CatalogQueryId::MutationIndexes,
            "ROOT",
            vec![ordinary.clone()],
        );
        assert!(
            collect(
                &cx,
                &catalog,
                &UnknownMutationEffects,
                MutationStatementKind::Update,
                MutationColumns::All
            )
            .await
            .is_complete()
        );
        for column in [
            "ITYP_OWNER",
            "ITYP_NAME",
            "DOMIDX_STATUS",
            "DOMIDX_OPSTATUS",
            "FUNCIDX_STATUS",
        ] {
            let mut conflicting = ordinary.clone();
            conflicting
                .columns
                .iter_mut()
                .find(|(name, _)| name == column)
                .unwrap()
                .1
                .value = Some("UNEXPECTED_CALLBACK".into());
            catalog.rows(CatalogQueryId::MutationIndexes, "ROOT", vec![conflicting]);
            let closure = collect(
                &cx,
                &catalog,
                &UnknownMutationEffects,
                MutationStatementKind::Update,
                MutationColumns::All,
            )
            .await;
            assert!(
                !closure.is_complete(),
                "nonempty {column} cannot be discarded: {closure:?}"
            );
        }
    });
}

#[test]
fn mutation_closure_binary_metadata_is_not_observed_null() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut catalog = Catalog::default();
        let mut malformed = index("APP", "IX_NORMAL", "NORMAL");
        malformed
            .columns
            .iter_mut()
            .find(|(name, _)| name == "ITYP_OWNER")
            .unwrap()
            .1 = OracleCell::binary("RAW", b"CALLBACK_OWNER".to_vec());
        catalog.rows(CatalogQueryId::MutationIndexes, "ROOT", vec![malformed]);
        let closure = collect(
            &cx,
            &catalog,
            &UnknownMutationEffects,
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert!(
            !closure.is_complete(),
            "a binary callback owner is not SQL NULL: {closure:?}"
        );
    });
}

#[test]
fn mutation_closure_domain_index_collected() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationIndexes,
            "ROOT",
            vec![index("APP", "IX_D", "DOMAIN")],
        );
        c.rows(
            CatalogQueryId::MutationIndexImplementation,
            "IXTYPE",
            vec![row(&[
                ("OWNER", Some("APP")),
                ("INDEXTYPE_NAME", Some("IXTYPE")),
                ("IMPLEMENTATION_SCHEMA", Some("APP")),
                ("IMPLEMENTATION_NAME", Some("IX_IMPL")),
                ("INTERFACE_VERSION", Some("2")),
            ])],
        );
        let closure = collect(
            &cx,
            &c,
            &Effects::default(),
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert!(closure.is_complete(), "{closure:?}");
        assert!(matches!(
            closure.mechanisms[0].mechanism,
            MutationMechanism::IndexCallback { domain: true }
        ));
        assert!(
            !closure.mechanisms[0]
                .routine_closure_fingerprints
                .is_empty()
        );
    });
}

fn expression_column(name: &str, expression: Option<&str>, virtual_column: bool) -> OracleRow {
    let length = expression.map(str::len).map(|n| n.to_string());
    row(&[
        ("OWNER", Some("APP")),
        ("TABLE_NAME", Some("ROOT")),
        ("COLUMN_NAME", Some(name)),
        ("DATA_TYPE", Some("NUMBER")),
        ("DATA_TYPE_OWNER", None),
        (
            "VIRTUAL_COLUMN",
            Some(if virtual_column { "YES" } else { "NO" }),
        ),
        ("HIDDEN_COLUMN", Some("NO")),
        ("USER_GENERATED", Some("YES")),
        ("DEFAULT_LENGTH", length.as_deref()),
        ("DATA_DEFAULT", expression),
    ])
}

#[test]
fn mutation_closure_virtual_column_udf_collected() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationColumns,
            "ROOT",
            vec![
                expression_column("C1", None, false),
                expression_column("C2", Some("FX(C1)"), true),
            ],
        );
        let closure = collect(
            &cx,
            &c,
            &Effects::default(),
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert!(closure.is_complete(), "{closure:?}");
        assert!(
            matches!(&closure.mechanisms[0].mechanism,MutationMechanism::VirtualColumnExpr{column}if column=="C2")
        );
    });
}

#[test]
fn mutation_closure_function_index_uses_its_owner_and_storage_identity() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationIndexes,
            "ROOT",
            vec![index("OTHER", "IX_F", "FUNCTION-BASED NORMAL")],
        );
        c.rows(
            CatalogQueryId::MutationIndexExpressions,
            "ROOT",
            vec![row(&[
                ("INDEX_OWNER", Some("OTHER")),
                ("INDEX_NAME", Some("IX_F")),
                ("TABLE_OWNER", Some("APP")),
                ("TABLE_NAME", Some("ROOT")),
                ("COLUMN_POSITION", Some("1")),
                ("COLUMN_EXPRESSION", Some("FX(C1)")),
            ])],
        );
        let closure = collect(
            &cx,
            &c,
            &Effects {
                expected_owner: Some("OTHER".into()),
                expected_storage: Some("INDEX".into()),
                expected_object_id: Some(99),
                ..Default::default()
            },
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert!(closure.is_complete(), "{closure:?}");
        assert!(closure.mechanisms.iter().any(|fact| matches!(
            fact.mechanism,
            MutationMechanism::FunctionBasedIndex { position: 1 }
        )));
    });
}

#[test]
fn mutation_closure_vpd_update_policy_with_check_option() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationVpdPolicies,
            "ROOT",
            vec![row(&[
                ("OBJECT_OWNER", Some("APP")),
                ("OBJECT_NAME", Some("ROOT")),
                ("POLICY_GROUP", Some("SYS_DEFAULT")),
                ("POLICY_NAME", Some("P_UPD")),
                ("PF_OWNER", Some("APP")),
                ("PF_PACKAGE", None),
                ("PF_FUNCTION", Some("PF")),
                ("SEL", Some("NO")),
                ("INS", Some("NO")),
                ("UPD", Some("YES")),
                ("DEL", Some("NO")),
                ("IDX", Some("NO")),
                ("CHK_OPTION", Some("YES")),
                ("ENABLE", Some("YES")),
                ("POLICY_TYPE", Some("DYNAMIC")),
            ])],
        );
        c.sources.insert(
            "PF".into(),
            "FUNCTION PF(s VARCHAR2,o VARCHAR2) RETURN VARCHAR2 IS BEGIN RETURN NULL; END;\n"
                .into(),
        );
        let update = collect(
            &cx,
            &c,
            &Effects::default(),
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert!(update.is_complete(), "{update:?}");
        assert!(
            matches!(&update.mechanisms[0].mechanism,MutationMechanism::VpdPolicy{check_option:true,statement_types}if statement_types==&BTreeSet::from([MutationStatementKind::Update]))
        );
        let delete = collect(
            &cx,
            &c,
            &Effects::default(),
            MutationStatementKind::Delete,
            MutationColumns::All,
        )
        .await;
        assert!(delete.is_complete());
        assert!(delete.mechanisms.is_empty());
    });
}

#[test]
fn mutation_closure_missing_default_text_is_unknown() {
    run(async {
        let cx = Cx::current().unwrap();
        for (reported_length, full_source_hint) in [(Some("12"), None), (None, Some(12))] {
            let mut catalog = Catalog::default();
            let mut column = expression_column("C1", None, false);
            column
                .columns
                .iter_mut()
                .find(|(name, _)| name == "DEFAULT_LENGTH")
                .unwrap()
                .1
                .value = reported_length.map(str::to_owned);
            column
                .columns
                .iter_mut()
                .find(|(name, _)| name == "DATA_DEFAULT")
                .unwrap()
                .1
                .source_length = full_source_hint;
            catalog.rows(CatalogQueryId::MutationColumns, "ROOT", vec![column]);
            let closure = collect(
                &cx,
                &catalog,
                &UnknownMutationEffects,
                MutationStatementKind::Insert,
                MutationColumns::All,
            )
            .await;
            assert_eq!(
                closure.admit(),
                Err(MutationClosureRefusal::Incomplete),
                "a missing nonempty default cannot prove absence: {closure:?}"
            );
        }
    });
}

#[test]
fn mutation_closure_sequence_default_cannot_be_treated_as_virtual_absence() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationColumns,
            "ROOT",
            vec![
                expression_column("C1", Some("S.NEXTVAL"), false),
                expression_column("C2", None, false),
            ],
        );
        let mut effects = Effects::default();
        effects.effects.insert(
            "ROOT".into(),
            RoutineEffectsV1::new([RoutineEffect::SequenceAdvance]),
        );
        let closure = collect(
            &cx,
            &c,
            &effects,
            MutationStatementKind::Insert,
            MutationColumns::All,
        )
        .await;
        assert!(closure.is_complete());
        assert!(matches!(
            closure.mechanisms[0].mechanism,
            MutationMechanism::ColumnDefaultExpr { .. }
        ));
        assert_eq!(
            closure.admit(),
            Err(MutationClosureRefusal::Effect(
                EffectRefusal::AlwaysRefused(RoutineEffect::SequenceAdvance)
            ))
        );
    });
}

async fn collect(
    cx: &Cx,
    catalog: &Catalog,
    effects: &dyn MutationEffectOracle,
    kind: MutationStatementKind,
    columns: MutationColumns,
) -> MutationEffectClosureV1 {
    let closure = collect_mutation_effect_closure(
        cx,
        catalog,
        MutationRequest {
            target: target("ROOT"),
            statement_kind: kind,
            columns,
        },
        effects,
    )
    .await;
    assert_eq!(catalog.executions.load(Ordering::SeqCst), 0);
    closure
}

fn run<F: std::future::Future<Output = ()>>(body: F) {
    RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(body);
}

fn trigger(name: &str, kind: &str, table: &str) -> OracleRow {
    row(&[
        ("OWNER", Some("APP")),
        ("TRIGGER_NAME", Some(name)),
        ("TABLE_OWNER", Some("APP")),
        ("TABLE_NAME", Some(table)),
        ("BASE_OBJECT_TYPE", Some("TABLE")),
        ("COLUMN_NAME", None),
        ("TRIGGER_TYPE", Some(kind)),
        ("TRIGGERING_EVENT", Some("UPDATE OR DELETE")),
        ("STATUS", Some("ENABLED")),
        ("WHEN_CLAUSE", None),
        ("ACTION_TYPE", Some("PL/SQL     ")),
    ])
}

fn fk(rule: &str) -> OracleRow {
    row(&[
        ("FK_OWNER", Some("APP")),
        ("CONSTRAINT_NAME", Some("FK_CHILD")),
        ("CHILD_TABLE", Some("CHILD")),
        ("DELETE_RULE", Some(rule)),
        ("STATUS", Some("ENABLED")),
        ("VALIDATED", Some("VALIDATED")),
        ("DEFERRABLE", Some("NOT DEFERRABLE")),
        ("DEFERRED", Some("IMMEDIATE")),
        ("PARENT_OWNER", Some("APP")),
        ("PARENT_TABLE", Some("ROOT")),
        ("CHILD_COLUMN", Some("C1")),
        ("POSITION", Some("1")),
        ("PARENT_COLUMN", Some("C1")),
    ])
}

#[test]
fn mutation_closure_readable_empty_families_prove_absence() {
    run(async {
        let cx = Cx::current().unwrap();
        let closure = collect(
            &cx,
            &Catalog::default(),
            &UnknownMutationEffects,
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert_eq!(closure.admit(), Ok(OperatingLevel::ReadWrite));
        assert_eq!(closure.observations.len(), MutationCatalogSource::ALL.len());
        assert!(closure.mechanisms.is_empty());
    });
}

#[test]
fn mutation_closure_compound_trigger_collected() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationTriggers,
            "ROOT",
            vec![trigger("TR_C", "COMPOUND", "ROOT")],
        );
        let closure = collect(
            &cx,
            &c,
            &Effects::default(),
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert!(closure.is_complete(), "{closure:?}");
        assert!(matches!(
            closure.mechanisms[0].mechanism,
            MutationMechanism::DmlTrigger { compound: true, .. }
        ));
    });
}

#[test]
fn mutation_closure_column_specific_trigger_only_for_listed_columns() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationTriggers,
            "ROOT",
            vec![trigger("TR_C2", "BEFORE EACH ROW", "ROOT")],
        );
        c.rows(
            CatalogQueryId::MutationTriggerColumns,
            "ROOT",
            vec![row(&[
                ("TRIGGER_OWNER", Some("APP")),
                ("TRIGGER_NAME", Some("TR_C2")),
                ("TABLE_OWNER", Some("APP")),
                ("TABLE_NAME", Some("ROOT")),
                ("COLUMN_NAME", Some("C2")),
                ("COLUMN_LIST", Some("YES")),
                ("COLUMN_USAGE", Some("NEW IN")),
            ])],
        );
        let a = collect(
            &cx,
            &c,
            &Effects::default(),
            MutationStatementKind::Update,
            MutationColumns::Named(BTreeSet::from(["C1".into()])),
        )
        .await;
        let b = collect(
            &cx,
            &c,
            &Effects::default(),
            MutationStatementKind::Update,
            MutationColumns::Named(BTreeSet::from(["C2".into()])),
        )
        .await;
        assert!(a.is_complete() && b.is_complete());
        assert!(a.mechanisms.is_empty());
        assert_eq!(b.mechanisms.len(), 1);
    });
}

async fn check_fk(rule: &str, expected: MutationForeignKeyAction) {
    let cx = Cx::current().unwrap();
    let mut c = Catalog::default();
    c.rows(CatalogQueryId::MutationForeignKeys, "ROOT", vec![fk(rule)]);
    let closure = collect(
        &cx,
        &c,
        &Effects::default(),
        MutationStatementKind::Delete,
        MutationColumns::All,
    )
    .await;
    assert!(closure.is_complete(), "{closure:?}");
    assert_eq!(closure.scopes.len(), 2);
    assert!(
        matches!(&closure.mechanisms[0].mechanism,MutationMechanism::ForeignKeyAction{on_delete,..}if *on_delete==expected)
    );
}

#[test]
fn mutation_closure_on_delete_cascade_collected() {
    run(check_fk("CASCADE", MutationForeignKeyAction::Cascade));
}
#[test]
fn mutation_closure_on_delete_set_null_collected() {
    run(check_fk("SET NULL", MutationForeignKeyAction::SetNull));
}

#[test]
fn mutation_closure_cascade_child_autonomous_trigger_refused() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationForeignKeys,
            "ROOT",
            vec![fk("CASCADE")],
        );
        c.rows(
            CatalogQueryId::MutationTriggers,
            "CHILD",
            vec![trigger("AUTO", "AFTER EACH ROW", "CHILD")],
        );
        let mut effects = Effects::default();
        effects.effects.insert(
            "AUTO".into(),
            RoutineEffectsV1::new([RoutineEffect::Autonomous]),
        );
        let closure = collect(
            &cx,
            &c,
            &effects,
            MutationStatementKind::Delete,
            MutationColumns::All,
        )
        .await;
        assert_eq!(
            closure.admit(),
            Err(MutationClosureRefusal::Effect(
                EffectRefusal::AlwaysRefused(RoutineEffect::Autonomous)
            ))
        );
    });
}

#[test]
fn mutation_closure_mv_log_is_transactional_internal() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationMvLogs,
            "ROOT",
            vec![row(&[
                ("LOG_OWNER", Some("APP")),
                ("MASTER", Some("ROOT")),
                ("LOG_TABLE", Some("MLOG$_ROOT")),
                ("LOG_TRIGGER", None),
                ("ROWIDS", Some("YES")),
                ("PRIMARY_KEY", Some("YES")),
                ("OBJECT_ID", Some("NO")),
                ("SEQUENCE", Some("YES")),
                ("INCLUDE_NEW_VALUES", Some("YES")),
            ])],
        );
        let closure = collect(
            &cx,
            &c,
            &UnknownMutationEffects,
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert!(matches!(
            closure.mechanisms[0].mechanism,
            MutationMechanism::MvLog { .. }
        ));
        assert_eq!(closure.admit(), Ok(OperatingLevel::ReadWrite));
    });
}

#[test]
fn mutation_closure_unreadable_source_is_unknown() {
    run(async {
        let cx = Cx::current().unwrap();
        let c = Catalog {
            denied: Some(CatalogQueryId::MutationForeignKeys),
            ..Default::default()
        };
        let closure = collect(
            &cx,
            &c,
            &Effects::default(),
            MutationStatementKind::Delete,
            MutationColumns::All,
        )
        .await;
        assert_eq!(closure.admit(), Err(MutationClosureRefusal::Incomplete));
        assert!(closure.observations.iter().any(|o| matches!(
            o.computation,
            MutationComputation::Unavailable {
                reason: MutationUnavailableReason::CatalogUnreadable
            }
        )));
    });
}

#[test]
fn mutation_closure_cap_exhaustion_is_unknown() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationTriggers,
            "ROOT",
            vec![row(&[]); MAX_MUTATION_CATALOG_ROWS + 1],
        );
        let closure = collect(
            &cx,
            &c,
            &Effects::default(),
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert!(!closure.is_complete());
        assert!(closure.observations.iter().any(|o| matches!(
            o.computation,
            MutationComputation::Unavailable {
                reason: MutationUnavailableReason::RowCapExhausted
            }
        )));
    });
}

#[test]
fn mutation_closure_autonomous_trigger_refused() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationTriggers,
            "ROOT",
            vec![trigger("AUTO", "BEFORE EACH ROW", "ROOT")],
        );
        let mut effects = Effects::default();
        effects.effects.insert(
            "AUTO".into(),
            RoutineEffectsV1::new([RoutineEffect::Autonomous]),
        );
        let closure = collect(
            &cx,
            &c,
            &effects,
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert!(closure.is_complete());
        assert_eq!(
            closure.admit(),
            Err(MutationClosureRefusal::Effect(
                EffectRefusal::AlwaysRefused(RoutineEffect::Autonomous)
            ))
        );
    });
}

#[test]
fn mutation_closure_hash_changes_on_trigger_source_change() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationTriggers,
            "ROOT",
            vec![trigger("TR", "BEFORE EACH ROW", "ROOT")],
        );
        let a = collect(
            &cx,
            &c,
            &Effects::default(),
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        c.sources
            .insert("TR".into(), "TRIGGER TR IS BEGIN NULL; NULL; END;\n".into());
        let b = collect(
            &cx,
            &c,
            &Effects::default(),
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert!(a.is_complete() && b.is_complete());
        assert_ne!(a.fingerprint(), b.fingerprint());
    });
}

#[test]
fn mutation_closure_stale_effect_hash_is_unknown() {
    run(async {
        let cx = Cx::current().unwrap();
        let mut c = Catalog::default();
        c.rows(
            CatalogQueryId::MutationTriggers,
            "ROOT",
            vec![trigger("TR", "BEFORE EACH ROW", "ROOT")],
        );
        let source = "TRIGGER TR BEFORE UPDATE ON APP.ROOT FOR EACH ROW BEGIN NULL; END;\n";
        c.sources.insert("TR".into(), source.into());
        let closure = collect(
            &cx,
            &c,
            &Effects {
                wrong_hash: true,
                ..Default::default()
            },
            MutationStatementKind::Update,
            MutationColumns::All,
        )
        .await;
        assert_eq!(closure.admit(), Err(MutationClosureRefusal::Incomplete));
        let expected: String = Sha256::digest(source.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            closure.mechanisms[0].source_sha256.as_deref(),
            Some(expected.as_str())
        );
    });
}
