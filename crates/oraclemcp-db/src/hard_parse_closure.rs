//! Catalog proof that an Oracle optimizer hard parse cannot invoke user code.

use std::collections::BTreeSet;

use asupersync::Cx;
use oraclemcp_guard::{CatalogObjectKind, ResolvedObject, hard_parse_user_calls};

use crate::{CatalogQueryId, DbError, OracleBind, OracleConnection, OracleRow, run_catalog_query};

const ROW_CAP: i64 = 256;
const PROBE_LIMIT: i64 = ROW_CAP + 1;

/// Result of the bounded optimizer hard-parse callback proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HardParseEffectClosureV1 {
    /// Every enumerated callback source was readable and absent.
    Proven,
    /// No callback was positively detected, but an Oracle catalog probe was
    /// denied. Callers may proceed only while recording this limitation.
    AdmittedWithObservation {
        /// Stable reason describing the missing evidence.
        reason: &'static str,
    },
    /// Catalog evidence proves that hard parse can invoke user code.
    Refused {
        /// Stable refusal reason for a detected callback source.
        reason: &'static str,
    },
    /// Catalog evidence was missing, unreadable, or incomplete.
    Unavailable {
        /// Stable reason that callback absence could not be proven.
        reason: &'static str,
    },
}

impl HardParseEffectClosureV1 {
    /// Stable machine-readable reason for a non-proven result.
    #[must_use]
    pub const fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Proven => None,
            Self::AdmittedWithObservation { reason }
            | Self::Refused { reason }
            | Self::Unavailable { reason } => Some(reason),
        }
    }

    /// Whether every enumerated callback source was proven absent.
    #[must_use]
    pub const fn is_proven(&self) -> bool {
        matches!(self, Self::Proven)
    }

    /// Whether EXPLAIN may proceed. Observed admissions must be included in
    /// the caller's audit transcript.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Proven | Self::AdmittedWithObservation { .. })
    }

    /// Whether the audit record must disclose incomplete catalog evidence.
    #[must_use]
    pub const fn requires_observation(&self) -> bool {
        matches!(self, Self::AdmittedWithObservation { .. })
    }
}

/// Inspect the object, routine, index, and policy identities a vetted read can
/// expose to the optimizer before EXPLAIN is allowed to hard-parse it.
pub async fn prove_hard_parse_effect_closure(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    relations: &[ResolvedObject],
) -> HardParseEffectClosureV1 {
    let calls = match hard_parse_user_calls(sql) {
        Ok(calls) => calls,
        Err(_) => return unavailable("callback_unprovable"),
    };
    let compact_sql = sql
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if compact_sql.contains("OPERATOR(") {
        // SQL's OPERATOR(...) syntax can name an overloaded implementation
        // whose binding is not represented by the read-plan resolver.
        return refused("callback_unprovable");
    }

    let mut objects = BTreeSet::new();
    for relation in relations {
        if !matches!(&relation.kind, CatalogObjectKind::Table) {
            // This closure receives resolved base relations, not a dependency
            // expansion for views, materialized views, or other object kinds.
            // Their hidden query trees may carry policies and optimizer
            // callbacks, so absence cannot be proven at this boundary.
            return unavailable("callback_unprovable");
        }
        objects.insert((relation.owner.clone(), relation.name.clone()));
    }
    for call in &calls {
        let Some(owner) = call.schema.as_deref() else {
            // An unqualified or three-part callable identity has not been
            // carried through this closure boundary, so it cannot prove the
            // absence of an associated statistics type.
            return refused("callback_unprovable");
        };
        objects.insert((owner.to_owned(), call.name.clone()));
    }

    // R36 permits a least-privilege account to proceed with an explicit
    // observation, but a denied catalog view is not evidence that later
    // relations or evidence families are safe. Keep scanning every readable
    // source and let any positive callback/policy row take precedence.
    let mut privilege_limited = false;

    for (owner, name) in &objects {
        let associations = match run_catalog_query(
            cx,
            conn,
            CatalogQueryId::HardParseAssociations,
            &[
                OracleBind::String(owner.clone()),
                OracleBind::String(name.clone()),
                OracleBind::I64(PROBE_LIMIT),
            ],
        )
        .await
        {
            Ok(rows) => rows,
            Err(error) if is_privilege_denial(&error) => {
                privilege_limited = true;
                Vec::new()
            }
            Err(error) => return catalog_unavailable(error),
        };
        if associations.len() as i64 >= PROBE_LIMIT {
            return unavailable("truncated");
        }
        for row in associations {
            if row.text("STATSTYPE_SCHEMA").is_some() || row.text("STATSTYPE_NAME").is_some() {
                return refused("odci_stats_callback");
            }
        }
    }

    for relation in relations {
        let owner = relation.owner.clone();
        let name = relation.name.clone();
        let column_types = match run_catalog_query(
            cx,
            conn,
            CatalogQueryId::HardParseColumnTypes,
            &[
                OracleBind::String(owner.clone()),
                OracleBind::String(name.clone()),
                OracleBind::I64(PROBE_LIMIT),
            ],
        )
        .await
        {
            Ok(rows) => rows,
            Err(error) if is_privilege_denial(&error) => {
                privilege_limited = true;
                Vec::new()
            }
            Err(error) => return catalog_unavailable(error),
        };
        if column_types.len() as i64 >= PROBE_LIMIT {
            return unavailable("truncated");
        }
        if !column_types.is_empty() {
            return refused("callback_unprovable");
        }
        let indexes = match run_catalog_query(
            cx,
            conn,
            CatalogQueryId::HardParseIndexes,
            &[
                OracleBind::String(owner.clone()),
                OracleBind::String(name.clone()),
                OracleBind::I64(PROBE_LIMIT),
            ],
        )
        .await
        {
            Ok(rows) => rows,
            Err(error) if is_privilege_denial(&error) => {
                privilege_limited = true;
                Vec::new()
            }
            Err(error) => return catalog_unavailable(error),
        };
        if indexes.len() as i64 >= PROBE_LIMIT {
            return unavailable("truncated");
        }
        for index in indexes {
            if index
                .text("INDEX_TYPE")
                .is_some_and(|kind| kind.eq_ignore_ascii_case("DOMAIN"))
            {
                return refused("domain_index_callback");
            }
            if let Some(index_name) = index.text("INDEX_NAME") {
                let index_owner = index.text("INDEX_OWNER").unwrap_or(&owner);
                let rows = match run_catalog_query(
                    cx,
                    conn,
                    CatalogQueryId::HardParseAssociations,
                    &[
                        OracleBind::String(index_owner.to_owned()),
                        OracleBind::String(index_name.to_owned()),
                        OracleBind::I64(PROBE_LIMIT),
                    ],
                )
                .await
                {
                    Ok(rows) => rows,
                    Err(error) if is_privilege_denial(&error) => {
                        privilege_limited = true;
                        Vec::new()
                    }
                    Err(error) => return catalog_unavailable(error),
                };
                if rows.len() as i64 >= PROBE_LIMIT {
                    return unavailable("truncated");
                }
                if rows.iter().any(association_has_statistics_type) {
                    return refused("odci_stats_callback");
                }
                if !rows.is_empty() {
                    return unavailable("callback_unprovable");
                }
            }
        }

        for (query, schema_wide) in [
            (CatalogQueryId::HardParseVpdPolicies, false),
            (CatalogQueryId::HardParseOlsTablePolicies, false),
            (CatalogQueryId::HardParseOlsSchemaPolicies, true),
            (CatalogQueryId::HardParseRasPolicies, false),
            (CatalogQueryId::HardParseRedactionPolicies, false),
        ] {
            let binds = if schema_wide {
                vec![
                    OracleBind::String(owner.clone()),
                    OracleBind::I64(PROBE_LIMIT),
                ]
            } else {
                vec![
                    OracleBind::String(owner.clone()),
                    OracleBind::String(name.clone()),
                    OracleBind::I64(PROBE_LIMIT),
                ]
            };
            let rows = match run_catalog_query(cx, conn, query, &binds).await {
                Ok(rows) => rows,
                Err(error) if is_privilege_denial(&error) => {
                    privilege_limited = true;
                    Vec::new()
                }
                Err(error) => return catalog_unavailable(error),
            };
            if rows.len() as i64 >= PROBE_LIMIT {
                return unavailable("truncated");
            }
            if !rows.is_empty() {
                return refused("policy_code");
            }
        }
    }

    if privilege_limited {
        HardParseEffectClosureV1::AdmittedWithObservation {
            reason: "no_privilege",
        }
    } else {
        HardParseEffectClosureV1::Proven
    }
}

fn association_has_statistics_type(row: &OracleRow) -> bool {
    row.text("STATSTYPE_SCHEMA").is_some() || row.text("STATSTYPE_NAME").is_some()
}

fn catalog_unavailable(error: DbError) -> HardParseEffectClosureV1 {
    let _ = error;
    unavailable("callback_unprovable")
}

fn is_privilege_denial(error: &DbError) -> bool {
    let message = error.to_string();
    message.contains("ORA-00942") || message.contains("ORA-01031")
}

const fn refused(reason: &'static str) -> HardParseEffectClosureV1 {
    HardParseEffectClosureV1::Refused { reason }
}

const fn unavailable(reason: &'static str) -> HardParseEffectClosureV1 {
    HardParseEffectClosureV1::Unavailable { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OracleBackend, OracleCell, OracleConnectionInfo};
    use oraclemcp_guard::{CatalogObjectKind, ResolvedIdentity};
    use std::sync::Mutex;

    #[test]
    fn evidence_rows_distinguish_callbacks_from_empty_associations() {
        let callback = OracleRow {
            columns: vec![
                (
                    "STATSTYPE_SCHEMA".to_owned(),
                    crate::OracleCell::new("VARCHAR2", Some("APP".to_owned())),
                ),
                (
                    "STATSTYPE_NAME".to_owned(),
                    crate::OracleCell::new("VARCHAR2", Some("STATS_TYPE".to_owned())),
                ),
            ],
        };
        let no_callback = OracleRow {
            columns: vec![
                (
                    "STATSTYPE_SCHEMA".to_owned(),
                    crate::OracleCell::new("VARCHAR2", None),
                ),
                (
                    "STATSTYPE_NAME".to_owned(),
                    crate::OracleCell::new("VARCHAR2", None),
                ),
            ],
        };
        assert!(association_has_statistics_type(&callback));
        assert!(!association_has_statistics_type(&no_callback));
    }

    #[derive(Default)]
    struct ClosureMock {
        association: Option<OracleRow>,
        association_denied: bool,
        association_denied_first: bool,
        association_calls: Mutex<usize>,
        domain_index: bool,
        user_defined_column_type: bool,
        policy_sql_fragment: Option<&'static str>,
        queries: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for ClosureMock {
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
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.queries.lock().expect("query log").push(sql.to_owned());
            if sql.contains("FROM all_associations") {
                let call = {
                    let mut calls = self.association_calls.lock().expect("association calls");
                    let call = *calls;
                    *calls += 1;
                    call
                };
                if self.association_denied || (self.association_denied_first && call == 0) {
                    return Err(DbError::ServerQuery(
                        "ORA-01031: insufficient privileges".into(),
                    ));
                }
                return Ok(self.association.iter().cloned().collect());
            }
            if sql.contains("FROM all_indexes") && self.domain_index {
                return Ok(vec![row(&[("INDEX_TYPE", "DOMAIN")])]);
            }
            if sql.contains("FROM all_tab_columns") && self.user_defined_column_type {
                return Ok(vec![row(&[
                    ("DATA_TYPE_OWNER", "APP"),
                    ("DATA_TYPE", "MY_TYPE"),
                ])]);
            }
            if self
                .policy_sql_fragment
                .is_some_and(|fragment| sql.contains(fragment))
            {
                return Ok(vec![row(&[("POLICY_NAME", "CANARY_POLICY")])]);
            }
            Ok(Vec::new())
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    fn row(values: &[(&str, &str)]) -> OracleRow {
        OracleRow {
            columns: values
                .iter()
                .map(|(name, value)| {
                    (
                        (*name).to_owned(),
                        OracleCell::new("VARCHAR2", Some((*value).to_owned())),
                    )
                })
                .collect(),
        }
    }

    fn relation() -> ResolvedObject {
        ResolvedObject {
            owner: "APP".into(),
            name: "ORDERS".into(),
            kind: CatalogObjectKind::Table,
            container: None,
            member: None,
            overloads: Vec::new(),
            quote_exact: false,
            synonym_chain: Vec::new(),
            db_link: None,
            identity: ResolvedIdentity {
                object_id: 17,
                edition: None,
            },
        }
    }

    fn run<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(Cx) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("test runtime");
        runtime.block_on(async move {
            let cx = Cx::current().expect("current cx");
            body(cx).await
        })
    }

    #[test]
    fn hard_parse_closure_refuses_associated_statistics() {
        let mock = ClosureMock {
            association: Some(row(&[
                ("STATSTYPE_SCHEMA", "APP"),
                ("STATSTYPE_NAME", "CANARY_STATS"),
            ])),
            ..ClosureMock::default()
        };
        let result = run(|cx| async move {
            prove_hard_parse_effect_closure(&cx, &mock, "SELECT id FROM APP.ORDERS", &[relation()])
                .await
        });
        assert_eq!(
            result,
            HardParseEffectClosureV1::Refused {
                reason: "odci_stats_callback"
            }
        );
    }

    #[test]
    fn hard_parse_closure_proves_empty_callback_surface() {
        let mock = ClosureMock::default();
        let mock_ref = &mock;
        let result = run(|cx| async move {
            prove_hard_parse_effect_closure(
                &cx,
                mock_ref,
                "SELECT id FROM APP.ORDERS",
                &[relation()],
            )
            .await
        });
        assert_eq!(result, HardParseEffectClosureV1::Proven);
        let queries = mock.queries.lock().expect("query log");
        for source in [
            "from all_associations",
            "from all_tab_columns",
            "from all_indexes",
            "from all_policies",
            "from all_sa_table_policies",
            "from all_sa_schema_policies",
            "from all_xs_applied_policies",
            "from redaction_policies",
        ] {
            assert!(
                queries
                    .iter()
                    .any(|sql| sql.to_ascii_lowercase().contains(source)),
                "missing {source}"
            );
        }
    }

    #[test]
    fn hard_parse_closure_refuses_unexpanded_view_dependencies() {
        let mock = ClosureMock::default();
        let mut view = relation();
        view.kind = CatalogObjectKind::View;
        let mock_ref = &mock;
        let view_ref = &view;
        let result = run(|cx| async move {
            prove_hard_parse_effect_closure(
                &cx,
                mock_ref,
                "SELECT id FROM APP.ORDERS",
                std::slice::from_ref(view_ref),
            )
            .await
        });
        assert_eq!(
            result,
            HardParseEffectClosureV1::Unavailable {
                reason: "callback_unprovable"
            }
        );
        assert!(mock.queries.lock().expect("query log").is_empty());
    }

    #[test]
    fn hard_parse_closure_refuses_user_operator_syntax_before_catalog_io() {
        let mock = ClosureMock::default();
        let mock_ref = &mock;
        let result = run(|cx| async move {
            prove_hard_parse_effect_closure(
                &cx,
                mock_ref,
                "SELECT OPERATOR(APP.CANARY_OP)(1, 2) FROM dual",
                &[],
            )
            .await
        });
        assert_eq!(
            result,
            HardParseEffectClosureV1::Refused {
                reason: "callback_unprovable"
            }
        );
        assert!(mock.queries.lock().expect("query log").is_empty());
    }

    #[test]
    fn hard_parse_closure_refuses_domain_index() {
        let mock = ClosureMock {
            domain_index: true,
            ..ClosureMock::default()
        };
        let result = run(|cx| async move {
            prove_hard_parse_effect_closure(&cx, &mock, "SELECT id FROM APP.ORDERS", &[relation()])
                .await
        });
        assert_eq!(
            result,
            HardParseEffectClosureV1::Refused {
                reason: "domain_index_callback"
            }
        );
    }

    #[test]
    fn hard_parse_closure_refuses_user_defined_column_type() {
        let mock = ClosureMock {
            user_defined_column_type: true,
            ..ClosureMock::default()
        };
        let result = run(|cx| async move {
            prove_hard_parse_effect_closure(&cx, &mock, "SELECT id FROM APP.ORDERS", &[relation()])
                .await
        });
        assert_eq!(
            result,
            HardParseEffectClosureV1::Refused {
                reason: "callback_unprovable"
            }
        );
    }

    #[test]
    fn hard_parse_closure_refuses_vpd_ols_ras_redaction() {
        for fragment in [
            "FROM all_policies",
            "FROM all_sa_table_policies",
            "FROM all_sa_schema_policies",
            "FROM all_xs_applied_policies",
            "FROM redaction_policies",
        ] {
            let mock = ClosureMock {
                policy_sql_fragment: Some(fragment),
                ..ClosureMock::default()
            };
            let result = run(|cx| async move {
                prove_hard_parse_effect_closure(
                    &cx,
                    &mock,
                    "SELECT id FROM APP.ORDERS",
                    &[relation()],
                )
                .await
            });
            assert_eq!(
                result,
                HardParseEffectClosureV1::Refused {
                    reason: "policy_code"
                },
                "policy query {fragment}"
            );
        }
    }

    #[test]
    fn hard_parse_closure_missing_privilege_is_admitted_with_observation() {
        let mock = ClosureMock {
            association_denied: true,
            ..ClosureMock::default()
        };
        let result = run(|cx| async move {
            prove_hard_parse_effect_closure(&cx, &mock, "SELECT id FROM APP.ORDERS", &[relation()])
                .await
        });
        assert_eq!(
            result,
            HardParseEffectClosureV1::AdmittedWithObservation {
                reason: "no_privilege"
            }
        );
        assert!(result.is_admitted());
        assert!(result.requires_observation());
    }

    #[test]
    fn denied_probe_then_positive_evidence_on_later_relation_refuses() {
        let mock = ClosureMock {
            association: Some(row(&[
                ("STATSTYPE_SCHEMA", "APP"),
                ("STATSTYPE_NAME", "CANARY_STATS"),
            ])),
            association_denied_first: true,
            ..ClosureMock::default()
        };
        let mut later_relation = relation();
        later_relation.name = "Z_LATER".into();
        let result = run(|cx| async move {
            prove_hard_parse_effect_closure(
                &cx,
                &mock,
                "SELECT id FROM APP.ORDERS JOIN APP.Z_LATER USING (id)",
                &[relation(), later_relation],
            )
            .await
        });
        assert_eq!(
            result,
            HardParseEffectClosureV1::Refused {
                reason: "odci_stats_callback"
            }
        );
    }
}
