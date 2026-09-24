//! Live Oracle catalog extraction for the PL/SQL-intelligence snapshot seam.
//!
//! This module owns only the Oracle dictionary queries. It deliberately emits
//! driver-free [`OracleRow`] batches named with the same stable strings as
//! `plsql_catalog::CatalogRowSet::as_str()`. The sibling engine crate remains
//! responsible for turning those rows into a `CatalogSnapshot`.

use asupersync::Cx;
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::{
    connection::OracleConnection,
    error::DbError,
    types::{OracleBind, OracleConnectionInfo, OracleRow},
};

/// Stable rowset name understood by the PL/SQL catalog snapshot builder.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum CatalogRowSetName {
    /// Rows from `ALL_OBJECTS`.
    #[serde(rename = "objects")]
    Objects,
    /// Rows from `ALL_TAB_COLS`.
    #[serde(rename = "columns")]
    Columns,
    /// Rows from `ALL_CONSTRAINTS` joined to `ALL_CONS_COLUMNS`.
    #[serde(rename = "constraints")]
    Constraints,
    /// Rows from `ALL_INDEXES` joined to `ALL_IND_COLUMNS`.
    #[serde(rename = "indexes")]
    Indexes,
    /// Rows from `ALL_TRIGGERS`.
    #[serde(rename = "triggers")]
    Triggers,
    /// Rows from `ALL_SYNONYMS`.
    #[serde(rename = "synonyms")]
    Synonyms,
    /// Rows from `ALL_PROCEDURES`.
    #[serde(rename = "routines")]
    Routines,
    /// Rows from `ALL_ARGUMENTS`.
    #[serde(rename = "routine_arguments")]
    RoutineArguments,
    /// Rows from `ALL_VIEWS`.
    #[serde(rename = "views")]
    Views,
    /// Rows from `ALL_MVIEWS`.
    #[serde(rename = "materialized_views")]
    MaterializedViews,
    /// Rows from `ALL_SEQUENCES`.
    #[serde(rename = "sequences")]
    Sequences,
    /// Rows from `ALL_TYPE_ATTRS`.
    #[serde(rename = "type_attributes")]
    TypeAttributes,
    /// Rows from `ALL_USERS`.
    #[serde(rename = "users")]
    Users,
    /// Rows from `ALL_TAB_PRIVS`.
    #[serde(rename = "grants")]
    Grants,
    /// Rows from `ALL_DB_LINKS`.
    #[serde(rename = "database_links")]
    DatabaseLinks,
    /// Rows from `ALL_TAB_COMMENTS`.
    #[serde(rename = "table_comments")]
    TableComments,
    /// Rows from `ALL_COL_COMMENTS`.
    #[serde(rename = "column_comments")]
    ColumnComments,
    /// Rows from `ALL_EDITIONS`.
    #[serde(rename = "editions")]
    Editions,
    /// Rows from `ALL_EDITIONING_VIEWS`.
    #[serde(rename = "editioning_views")]
    EditioningViews,
    /// Rows from `ALL_POLICIES`.
    #[serde(rename = "vpd_policies")]
    VpdPolicies,
    /// Rows from `ALL_DEPENDENCIES`.
    #[serde(rename = "dependencies")]
    Dependencies,
    /// Rows from `ALL_PLSQL_OBJECT_SETTINGS`.
    #[serde(rename = "plscope_availability")]
    PlScopeAvailability,
    /// Rows from `ALL_IDENTIFIERS`.
    #[serde(rename = "plscope_identifiers")]
    PlScopeIdentifiers,
}

impl CatalogRowSetName {
    /// Rowsets extracted by the structural catalog loader, excluding PL/Scope.
    pub const CORE: &'static [CatalogRowSetName] = &[
        CatalogRowSetName::Objects,
        CatalogRowSetName::Columns,
        CatalogRowSetName::Constraints,
        CatalogRowSetName::Indexes,
        CatalogRowSetName::Triggers,
        CatalogRowSetName::Synonyms,
        CatalogRowSetName::Routines,
        CatalogRowSetName::RoutineArguments,
        CatalogRowSetName::Views,
        CatalogRowSetName::MaterializedViews,
        CatalogRowSetName::Sequences,
        CatalogRowSetName::TypeAttributes,
        CatalogRowSetName::Users,
        CatalogRowSetName::Grants,
        CatalogRowSetName::DatabaseLinks,
        CatalogRowSetName::TableComments,
        CatalogRowSetName::ColumnComments,
        CatalogRowSetName::Editions,
        CatalogRowSetName::EditioningViews,
        CatalogRowSetName::VpdPolicies,
        CatalogRowSetName::Dependencies,
    ];

    /// Optional PL/Scope rowsets.
    pub const PLSCOPE: &'static [CatalogRowSetName] = &[
        CatalogRowSetName::PlScopeAvailability,
        CatalogRowSetName::PlScopeIdentifiers,
    ];

    /// The exact rowset string accepted by the PL/SQL snapshot builder.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CatalogRowSetName::Objects => "objects",
            CatalogRowSetName::Columns => "columns",
            CatalogRowSetName::Constraints => "constraints",
            CatalogRowSetName::Indexes => "indexes",
            CatalogRowSetName::Triggers => "triggers",
            CatalogRowSetName::Synonyms => "synonyms",
            CatalogRowSetName::Routines => "routines",
            CatalogRowSetName::RoutineArguments => "routine_arguments",
            CatalogRowSetName::Views => "views",
            CatalogRowSetName::MaterializedViews => "materialized_views",
            CatalogRowSetName::Sequences => "sequences",
            CatalogRowSetName::TypeAttributes => "type_attributes",
            CatalogRowSetName::Users => "users",
            CatalogRowSetName::Grants => "grants",
            CatalogRowSetName::DatabaseLinks => "database_links",
            CatalogRowSetName::TableComments => "table_comments",
            CatalogRowSetName::ColumnComments => "column_comments",
            CatalogRowSetName::Editions => "editions",
            CatalogRowSetName::EditioningViews => "editioning_views",
            CatalogRowSetName::VpdPolicies => "vpd_policies",
            CatalogRowSetName::Dependencies => "dependencies",
            CatalogRowSetName::PlScopeAvailability => "plscope_availability",
            CatalogRowSetName::PlScopeIdentifiers => "plscope_identifiers",
        }
    }
}

/// Schema selector for catalog extraction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogSchemaFilter {
    /// Use the connection's current schema from [`OracleConnectionInfo`].
    CurrentSchema,
    /// Use a named Oracle schema owner.
    Named(String),
}

impl CatalogSchemaFilter {
    /// Select the current schema reported by the live connection.
    #[must_use]
    pub fn current_schema() -> Self {
        Self::CurrentSchema
    }

    /// Select a named schema owner.
    #[must_use]
    pub fn named(schema_name: impl Into<String>) -> Self {
        Self::Named(schema_name.into())
    }
}

/// Request for live Oracle catalog row extraction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogExtractRequest {
    /// Schema filters to resolve before querying owner-scoped dictionary views.
    pub schema_filters: Vec<CatalogSchemaFilter>,
    /// Whether to include PL/Scope rowsets when dictionary access permits it.
    pub include_plscope: bool,
}

impl CatalogExtractRequest {
    /// Extract the connection's current schema and include PL/Scope rowsets.
    #[must_use]
    pub fn for_current_schema() -> Self {
        Self {
            schema_filters: vec![CatalogSchemaFilter::CurrentSchema],
            include_plscope: true,
        }
    }

    /// Extract the named schema owners and include PL/Scope rowsets.
    #[must_use]
    pub fn for_named_schemas<I, S>(schema_names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            schema_filters: schema_names
                .into_iter()
                .map(CatalogSchemaFilter::named)
                .collect(),
            include_plscope: true,
        }
    }

    /// Return this request with PL/Scope rowsets enabled or disabled.
    #[must_use]
    pub fn with_plscope(mut self, include_plscope: bool) -> Self {
        self.include_plscope = include_plscope;
        self
    }
}

impl Default for CatalogExtractRequest {
    fn default() -> Self {
        Self::for_current_schema()
    }
}

/// One dictionary row batch, ready for a downstream snapshot builder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogRowBatch {
    /// The rowset name.
    pub row_set: CatalogRowSetName,
    /// Rows returned by the corresponding dictionary query.
    pub rows: Vec<OracleRow>,
}

/// Non-fatal extraction warning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogExtractWarning {
    /// Rowset that failed or degraded.
    pub row_set: CatalogRowSetName,
    /// Stable warning code.
    pub code: String,
    /// Human-readable warning message.
    pub message: String,
    /// Suggested operator action, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Result of live catalog row extraction.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogExtractReport {
    /// Resolved schema owners used by owner-scoped dictionary queries.
    pub schema_names: Vec<String>,
    /// Row batches in the order expected by the downstream snapshot builder.
    pub batches: Vec<CatalogRowBatch>,
    /// Non-fatal warnings for optional rowsets.
    pub warnings: Vec<CatalogExtractWarning>,
}

struct CatalogQuerySpec {
    row_set: CatalogRowSetName,
    id: crate::CatalogQueryId,
    schema_filtered: bool,
    optional: bool,
    warning_code: Option<&'static str>,
    remediation: Option<&'static str>,
}

/// Return the rowsets extracted by [`extract_catalog_rowsets`].
#[must_use]
pub fn catalog_extract_rowsets(include_plscope: bool) -> Vec<CatalogRowSetName> {
    let mut rowsets = CatalogRowSetName::CORE.to_vec();
    if include_plscope {
        rowsets.extend_from_slice(CatalogRowSetName::PLSCOPE);
    }
    rowsets
}

/// Extract live Oracle dictionary rows for a downstream `CatalogSnapshotBuilder`.
#[instrument(level = "trace", skip(cx, conn, request))]
pub async fn extract_catalog_rowsets(
    cx: &Cx,
    conn: &dyn OracleConnection,
    request: &CatalogExtractRequest,
) -> Result<CatalogExtractReport, DbError> {
    let connection_info = conn.describe(cx).await?;
    let schema_names = resolve_schema_filters(&connection_info, request)?;
    let query_specs = catalog_query_specs(request.include_plscope);
    let mut batches = Vec::with_capacity(query_specs.len());
    let mut warnings = Vec::new();

    for spec in query_specs {
        match run_extract_query(cx, conn, &spec, &schema_names).await {
            Ok(rows) => batches.push(CatalogRowBatch {
                row_set: spec.row_set,
                rows,
            }),
            Err(error) if spec.optional => warnings.push(CatalogExtractWarning {
                row_set: spec.row_set,
                code: spec
                    .warning_code
                    .unwrap_or("catalog-optional-rowset-failed")
                    .to_owned(),
                message: format!("{} query failed: {error}", spec.row_set.as_str()),
                remediation: spec.remediation.map(str::to_owned),
            }),
            Err(error) => return Err(error),
        }
    }

    Ok(CatalogExtractReport {
        schema_names,
        batches,
        warnings,
    })
}

/// The fixed query is repeated over deterministic owner chunks. PUBLIC rows
/// are included only in the first chunk, including when PUBLIC is explicitly
/// named in a later owner chunk.
async fn run_extract_query(
    cx: &Cx,
    conn: &dyn OracleConnection,
    spec: &CatalogQuerySpec,
    schema_names: &[String],
) -> Result<Vec<OracleRow>, DbError> {
    if !spec.schema_filtered {
        return crate::run_catalog_query(cx, conn, spec.id, &[]).await;
    }
    let mut rows = Vec::new();
    for (chunk_index, owners) in schema_names.chunks(32).enumerate() {
        let mut binds = schema_filter_binds_32(owners);
        if matches!(
            spec.id,
            crate::CatalogQueryId::ExtractSynonyms | crate::CatalogQueryId::ExtractDatabaseLinks
        ) {
            binds.push(OracleBind::from(i64::from(chunk_index == 0)));
        }
        rows.extend(crate::run_catalog_query(cx, conn, spec.id, &binds).await?);
    }
    Ok(rows)
}

fn resolve_schema_filters(
    connection_info: &OracleConnectionInfo,
    request: &CatalogExtractRequest,
) -> Result<Vec<String>, DbError> {
    let mut resolved = Vec::new();

    for filter in &request.schema_filters {
        let schema_name = match filter {
            CatalogSchemaFilter::CurrentSchema => {
                connection_info.current_schema.clone().ok_or_else(|| {
                    DbError::Query("catalog extraction requires a current schema".to_owned())
                })?
            }
            CatalogSchemaFilter::Named(schema_name) => {
                let trimmed = schema_name.trim();
                if trimmed.is_empty() {
                    return Err(DbError::Query(
                        "catalog extraction schema filters must not be blank".to_owned(),
                    ));
                }
                trimmed.to_owned()
            }
        };

        if !resolved.iter().any(|candidate| candidate == &schema_name) {
            resolved.push(schema_name);
        }
    }

    if resolved.is_empty() {
        return Err(DbError::Query(
            "catalog extraction requires at least one schema filter".to_owned(),
        ));
    }

    Ok(resolved)
}

fn catalog_query_specs(include_plscope: bool) -> Vec<CatalogQuerySpec> {
    use crate::CatalogQueryId;
    let mut specs = vec![
        required(CatalogRowSetName::Objects, CatalogQueryId::ExtractObjects),
        required(CatalogRowSetName::Columns, CatalogQueryId::ExtractColumns),
        required(
            CatalogRowSetName::Constraints,
            CatalogQueryId::ExtractConstraints,
        ),
        required(CatalogRowSetName::Indexes, CatalogQueryId::ExtractIndexes),
        required(CatalogRowSetName::Triggers, CatalogQueryId::ExtractTriggers),
        required(CatalogRowSetName::Synonyms, CatalogQueryId::ExtractSynonyms),
        required(CatalogRowSetName::Routines, CatalogQueryId::ExtractRoutines),
        required(
            CatalogRowSetName::RoutineArguments,
            CatalogQueryId::ExtractRoutineArguments,
        ),
        required(CatalogRowSetName::Views, CatalogQueryId::ExtractViews),
        required(
            CatalogRowSetName::MaterializedViews,
            CatalogQueryId::ExtractMaterializedViews,
        ),
        required(
            CatalogRowSetName::Sequences,
            CatalogQueryId::ExtractSequences,
        ),
        required(
            CatalogRowSetName::TypeAttributes,
            CatalogQueryId::ExtractTypeAttributes,
        ),
        optional_unfiltered(
            CatalogRowSetName::Users,
            CatalogQueryId::ExtractUsers,
            "all-users-probe",
            "ensure the analysis user can SELECT ALL_USERS so object grants to roles are not misclassified as direct user grants.",
        ),
        required(CatalogRowSetName::Grants, CatalogQueryId::ExtractGrants),
        required(
            CatalogRowSetName::DatabaseLinks,
            CatalogQueryId::ExtractDatabaseLinks,
        ),
        required(
            CatalogRowSetName::TableComments,
            CatalogQueryId::ExtractTableComments,
        ),
        required(
            CatalogRowSetName::ColumnComments,
            CatalogQueryId::ExtractColumnComments,
        ),
        required_unfiltered(CatalogRowSetName::Editions, CatalogQueryId::ExtractEditions),
        required(
            CatalogRowSetName::EditioningViews,
            CatalogQueryId::ExtractEditioningViews,
        ),
        required(
            CatalogRowSetName::VpdPolicies,
            CatalogQueryId::ExtractVpdPolicies,
        ),
        required(
            CatalogRowSetName::Dependencies,
            CatalogQueryId::ExtractDependencies,
        ),
    ];

    if include_plscope {
        specs.push(optional(
            CatalogRowSetName::PlScopeAvailability,
            CatalogQueryId::ExtractPlscopeAvailability,
            "plscope-detect-failed",
            "grant SELECT on ALL_PLSQL_OBJECT_SETTINGS, or accept that PL/Scope detection is unavailable.",
        ));
        specs.push(optional(
            CatalogRowSetName::PlScopeIdentifiers,
            CatalogQueryId::ExtractPlscopeIdentifiers,
            "plscope-identifiers-failed",
            "ensure the user can read ALL_IDENTIFIERS, or recompile target objects with PL/Scope enabled.",
        ));
    }

    specs
}

fn required(row_set: CatalogRowSetName, id: crate::CatalogQueryId) -> CatalogQuerySpec {
    CatalogQuerySpec {
        row_set,
        id,
        schema_filtered: true,
        optional: false,
        warning_code: None,
        remediation: None,
    }
}

fn required_unfiltered(row_set: CatalogRowSetName, id: crate::CatalogQueryId) -> CatalogQuerySpec {
    CatalogQuerySpec {
        row_set,
        id,
        schema_filtered: false,
        optional: false,
        warning_code: None,
        remediation: None,
    }
}

fn optional(
    row_set: CatalogRowSetName,
    id: crate::CatalogQueryId,
    warning_code: &'static str,
    remediation: &'static str,
) -> CatalogQuerySpec {
    CatalogQuerySpec {
        row_set,
        id,
        schema_filtered: true,
        optional: true,
        warning_code: Some(warning_code),
        remediation: Some(remediation),
    }
}

fn optional_unfiltered(
    row_set: CatalogRowSetName,
    id: crate::CatalogQueryId,
    warning_code: &'static str,
    remediation: &'static str,
) -> CatalogQuerySpec {
    CatalogQuerySpec {
        row_set,
        id,
        schema_filtered: false,
        optional: true,
        warning_code: Some(warning_code),
        remediation: Some(remediation),
    }
}

fn schema_filter_binds_32(schema_names: &[String]) -> Vec<OracleBind> {
    let mut binds = schema_names
        .iter()
        .cloned()
        .map(OracleBind::String)
        .collect::<Vec<_>>();
    binds.resize(32, OracleBind::Null);
    binds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OracleBackend, OracleCell};
    use asupersync::runtime::RuntimeBuilder;
    use async_trait::async_trait;
    use std::sync::Mutex;

    fn run_with_cx<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(Cx) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async move {
            let cx = Cx::current().expect("block_on installs a current Cx");
            body(cx).await
        })
    }

    #[derive(Default)]
    struct RecordingConn {
        calls: Mutex<Vec<(String, Vec<OracleBind>)>>,
        fail_contains: Option<&'static str>,
        synthesize_owners: bool,
    }

    #[async_trait(?Send)]
    impl OracleConnection for RecordingConn {
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
                ..OracleConnectionInfo::default()
            })
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.calls
                .lock()
                .expect("call log")
                .push((sql.to_owned(), binds.to_vec()));
            if self
                .fail_contains
                .is_some_and(|needle| sql.contains(needle))
            {
                return Err(DbError::Query("scripted query failure".to_owned()));
            }
            if self.synthesize_owners {
                let public_catalog =
                    sql.contains("from all_synonyms") || sql.contains("from all_db_links");
                let mut owners = binds
                    .iter()
                    .take(32)
                    .filter_map(|bind| match bind {
                        OracleBind::String(owner) if !public_catalog || owner != "PUBLIC" => {
                            Some(owner.clone())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if public_catalog && binds.get(32) == Some(&OracleBind::I64(1)) {
                    owners.push("PUBLIC".to_owned());
                }
                return Ok(owners
                    .into_iter()
                    .map(|owner| OracleRow {
                        columns: vec![(
                            "OWNER".to_owned(),
                            OracleCell::new("VARCHAR2", Some(owner)),
                        )],
                    })
                    .collect());
            }
            Ok(vec![OracleRow {
                columns: vec![(
                    "OWNER".to_owned(),
                    OracleCell::new("VARCHAR2", Some("APP".to_owned())),
                )],
            }])
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

    #[test]
    fn rowset_names_match_plsql_catalog_contract() {
        let names = catalog_extract_rowsets(true)
            .into_iter()
            .map(CatalogRowSetName::as_str)
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "objects",
                "columns",
                "constraints",
                "indexes",
                "triggers",
                "synonyms",
                "routines",
                "routine_arguments",
                "views",
                "materialized_views",
                "sequences",
                "type_attributes",
                "users",
                "grants",
                "database_links",
                "table_comments",
                "column_comments",
                "editions",
                "editioning_views",
                "vpd_policies",
                "dependencies",
                "plscope_availability",
                "plscope_identifiers",
            ]
        );
    }

    #[test]
    fn every_extract_rowset_has_a_closed_bind_contract() {
        let specs = catalog_query_specs(true);
        assert_eq!(
            specs.len(),
            CatalogRowSetName::CORE.len() + CatalogRowSetName::PLSCOPE.len()
        );
        let mut seen = Vec::new();
        for spec in specs {
            assert!(
                !seen.contains(&spec.id),
                "duplicate catalog id for {:?}",
                spec.row_set
            );
            seen.push(spec.id);
            let arity = spec.id.spec().binds.0.len();
            let expected = if !spec.schema_filtered {
                0
            } else if matches!(
                spec.id,
                crate::CatalogQueryId::ExtractSynonyms
                    | crate::CatalogQueryId::ExtractDatabaseLinks
            ) {
                33
            } else {
                32
            };
            assert_eq!(arity, expected, "{:?}", spec.row_set);
        }
    }

    #[test]
    fn extraction_uses_bound_schema_filters_and_builder_order() {
        let conn = RecordingConn::default();
        let request = CatalogExtractRequest::for_named_schemas(["DEMO", "HR"]);
        let conn_ref = &conn;

        let report = run_with_cx(|cx| async move {
            extract_catalog_rowsets(&cx, conn_ref, &request)
                .await
                .expect("extract catalog")
        });

        assert_eq!(report.schema_names, vec!["DEMO", "HR"]);
        assert_eq!(report.batches.len(), 23);
        assert_eq!(report.batches[0].row_set, CatalogRowSetName::Objects);
        assert_eq!(
            report.batches[7].row_set,
            CatalogRowSetName::RoutineArguments
        );
        assert_eq!(
            report.batches[22].row_set,
            CatalogRowSetName::PlScopeIdentifiers
        );

        let calls = conn.calls.lock().expect("call log");
        assert!(calls[0].0.contains("from all_objects"));
        assert!(calls[0].0.contains("owner in (:1, :2, :3"));
        assert_eq!(calls[0].1.len(), 32);
        assert_eq!(calls[0].1[0], OracleBind::String("DEMO".to_owned()));
        assert_eq!(calls[0].1[1], OracleBind::String("HR".to_owned()));
        assert!(calls[0].1[2..].iter().all(|bind| *bind == OracleBind::Null));
        assert!(calls[12].0.contains("from all_users"));
        assert!(calls[12].1.is_empty());
        assert!(calls[17].0.contains("from all_editions"));
        assert!(calls[17].1.is_empty());
    }

    #[test]
    fn seventy_owners_match_unbounded_catalog_content_without_duplicate_public_rows() {
        for explicitly_selected_public in [false, true] {
            let conn = RecordingConn {
                synthesize_owners: true,
                ..RecordingConn::default()
            };
            let mut owners = (0..70)
                .map(|index| format!("O{index:03}"))
                .collect::<Vec<_>>();
            if explicitly_selected_public {
                owners[60] = "PUBLIC".to_owned();
            }
            let request = CatalogExtractRequest::for_named_schemas(owners.clone());
            let conn_ref = &conn;
            let report = run_with_cx(|cx| async move {
                extract_catalog_rowsets(&cx, conn_ref, &request)
                    .await
                    .expect("fixed catalog queries batch all owners")
            });
            assert_eq!(report.batches.len(), 23);
            assert!(report.warnings.is_empty());
            let calls = conn.calls.lock().expect("call log");
            assert_eq!(
                calls.len(),
                65,
                "21 filtered rowsets in three chunks, two unfiltered once"
            );
            let filtered_calls = calls
                .iter()
                .filter(|(sql, _)| {
                    !sql.contains("from all_users") && !sql.contains("from all_editions")
                })
                .collect::<Vec<_>>();
            assert_eq!(filtered_calls.len(), 63);
            for (call_index, (_, binds)) in filtered_calls.iter().enumerate() {
                let chunk_index = call_index % 3;
                let start = chunk_index * 32;
                let end = (start + 32).min(owners.len());
                let expected_binds = schema_filter_binds_32(&owners[start..end]);
                assert_eq!(&binds[..32], expected_binds.as_slice());
                if binds.len() == 33 {
                    assert_eq!(
                        binds[32],
                        OracleBind::I64(i64::from(chunk_index == 0)),
                        "PUBLIC is present only in the first ordered owner chunk"
                    );
                }
            }
            for batch in &report.batches {
                let mut actual = batch
                    .rows
                    .iter()
                    .filter_map(|row| row.text("OWNER"))
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                let mut expected = if matches!(
                    batch.row_set,
                    CatalogRowSetName::Users | CatalogRowSetName::Editions
                ) {
                    Vec::new()
                } else {
                    owners.clone()
                };
                if matches!(
                    batch.row_set,
                    CatalogRowSetName::Synonyms | CatalogRowSetName::DatabaseLinks
                ) && !explicitly_selected_public
                {
                    expected.push("PUBLIC".to_owned());
                }
                actual.sort();
                expected.sort();
                assert_eq!(
                    actual, expected,
                    "{:?}: content must equal the former unbounded owner filter",
                    batch.row_set
                );
            }
            for view in ["from all_synonyms", "from all_db_links"] {
                let flags = calls
                    .iter()
                    .filter(|(sql, _)| sql.contains(view))
                    .map(|(_, binds)| binds[32].clone())
                    .collect::<Vec<_>>();
                assert_eq!(
                    flags,
                    [OracleBind::I64(1), OracleBind::I64(0), OracleBind::I64(0)]
                );
            }
            assert_eq!(
                calls
                    .iter()
                    .filter(|(sql, _)| sql.contains("from all_users"))
                    .count(),
                1
            );
            assert_eq!(
                calls
                    .iter()
                    .filter(|(sql, _)| sql.contains("from all_editions"))
                    .count(),
                1
            );
        }
    }

    #[test]
    fn extraction_can_skip_plscope_rowsets() {
        let conn = RecordingConn::default();
        let request = CatalogExtractRequest::for_current_schema().with_plscope(false);

        let report = run_with_cx(|cx| async move {
            extract_catalog_rowsets(&cx, &conn, &request)
                .await
                .expect("extract catalog")
        });

        assert_eq!(report.schema_names, vec!["APP"]);
        assert_eq!(report.batches.len(), 21);
        assert!(
            report
                .batches
                .iter()
                .all(|batch| !CatalogRowSetName::PLSCOPE.contains(&batch.row_set))
        );
    }

    #[test]
    fn optional_rowset_failure_records_warning_and_continues() {
        let conn = RecordingConn {
            fail_contains: Some("all_identifiers"),
            ..RecordingConn::default()
        };
        let request = CatalogExtractRequest::for_current_schema();

        let report = run_with_cx(|cx| async move {
            extract_catalog_rowsets(&cx, &conn, &request)
                .await
                .expect("optional failure is non-fatal")
        });

        assert_eq!(report.batches.len(), 22);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(
            report.warnings[0].row_set,
            CatalogRowSetName::PlScopeIdentifiers
        );
        assert_eq!(report.warnings[0].code, "plscope-identifiers-failed");
    }
}
