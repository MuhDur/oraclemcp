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
    sql: String,
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
pub async fn extract_catalog_rowsets<C: OracleConnection + ?Sized>(
    cx: &Cx,
    conn: &C,
    request: &CatalogExtractRequest,
) -> Result<CatalogExtractReport, DbError> {
    let connection_info = conn.describe(cx).await?;
    let schema_names = resolve_schema_filters(&connection_info, request)?;
    let query_specs = catalog_query_specs(schema_names.len(), request.include_plscope)?;
    let schema_binds = schema_filter_binds(&schema_names);
    let mut batches = Vec::with_capacity(query_specs.len());
    let mut warnings = Vec::new();

    for spec in query_specs {
        let binds = if spec.schema_filtered {
            schema_binds.as_slice()
        } else {
            &[]
        };
        match conn.query_rows(cx, &spec.sql, binds).await {
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

fn catalog_query_specs(
    schema_count: usize,
    include_plscope: bool,
) -> Result<Vec<CatalogQuerySpec>, DbError> {
    let owner_clause = oracle_bind_placeholders(schema_count, 1)?;
    let mut specs = vec![
        required(CatalogRowSetName::Objects, objects_sql(&owner_clause)),
        required(CatalogRowSetName::Columns, columns_sql(&owner_clause)),
        required(
            CatalogRowSetName::Constraints,
            constraints_sql(&owner_clause),
        ),
        required(CatalogRowSetName::Indexes, indexes_sql(&owner_clause)),
        required(CatalogRowSetName::Triggers, triggers_sql(&owner_clause)),
        required(CatalogRowSetName::Synonyms, synonyms_sql(&owner_clause)),
        required(CatalogRowSetName::Routines, routines_sql(&owner_clause)),
        required(
            CatalogRowSetName::RoutineArguments,
            routine_arguments_sql(&owner_clause),
        ),
        required(CatalogRowSetName::Views, views_sql(&owner_clause)),
        required(
            CatalogRowSetName::MaterializedViews,
            materialized_views_sql(&owner_clause),
        ),
        required(CatalogRowSetName::Sequences, sequences_sql(&owner_clause)),
        required(
            CatalogRowSetName::TypeAttributes,
            type_attributes_sql(&owner_clause),
        ),
        optional_unfiltered(
            CatalogRowSetName::Users,
            "select username from all_users order by username",
            "all-users-probe",
            "ensure the analysis user can SELECT ALL_USERS so object grants to roles are not misclassified as direct user grants.",
        ),
        required(CatalogRowSetName::Grants, grants_sql(&owner_clause)),
        required(
            CatalogRowSetName::DatabaseLinks,
            db_links_sql(&owner_clause),
        ),
        required(
            CatalogRowSetName::TableComments,
            table_comments_sql(&owner_clause),
        ),
        required(
            CatalogRowSetName::ColumnComments,
            column_comments_sql(&owner_clause),
        ),
        required_unfiltered(
            CatalogRowSetName::Editions,
            "select
  edition_name,
  parent_edition_name,
  usable
from all_editions
order by edition_name",
        ),
        required(
            CatalogRowSetName::EditioningViews,
            editioning_views_sql(&owner_clause),
        ),
        required(
            CatalogRowSetName::VpdPolicies,
            vpd_policies_sql(&owner_clause),
        ),
        required(
            CatalogRowSetName::Dependencies,
            dependencies_sql(&owner_clause),
        ),
    ];

    if include_plscope {
        specs.push(optional(
            CatalogRowSetName::PlScopeAvailability,
            plscope_availability_sql(&owner_clause),
            "plscope-detect-failed",
            "grant SELECT on ALL_PLSQL_OBJECT_SETTINGS, or accept that PL/Scope detection is unavailable.",
        ));
        specs.push(optional(
            CatalogRowSetName::PlScopeIdentifiers,
            plscope_identifiers_sql(&owner_clause),
            "plscope-identifiers-failed",
            "ensure the user can read ALL_IDENTIFIERS, or recompile target objects with PL/Scope enabled.",
        ));
    }

    Ok(specs)
}

fn required(row_set: CatalogRowSetName, sql: String) -> CatalogQuerySpec {
    CatalogQuerySpec {
        row_set,
        sql,
        schema_filtered: true,
        optional: false,
        warning_code: None,
        remediation: None,
    }
}

fn required_unfiltered(row_set: CatalogRowSetName, sql: impl Into<String>) -> CatalogQuerySpec {
    CatalogQuerySpec {
        row_set,
        sql: sql.into(),
        schema_filtered: false,
        optional: false,
        warning_code: None,
        remediation: None,
    }
}

fn optional(
    row_set: CatalogRowSetName,
    sql: String,
    warning_code: &'static str,
    remediation: &'static str,
) -> CatalogQuerySpec {
    CatalogQuerySpec {
        row_set,
        sql,
        schema_filtered: true,
        optional: true,
        warning_code: Some(warning_code),
        remediation: Some(remediation),
    }
}

fn optional_unfiltered(
    row_set: CatalogRowSetName,
    sql: impl Into<String>,
    warning_code: &'static str,
    remediation: &'static str,
) -> CatalogQuerySpec {
    CatalogQuerySpec {
        row_set,
        sql: sql.into(),
        schema_filtered: false,
        optional: true,
        warning_code: Some(warning_code),
        remediation: Some(remediation),
    }
}

fn oracle_bind_placeholders(count: usize, start_index: usize) -> Result<String, DbError> {
    if count == 0 {
        return Err(DbError::Query(
            "catalog extraction requires at least one schema bind".to_owned(),
        ));
    }
    Ok((0..count)
        .map(|offset| format!(":{}", start_index + offset))
        .collect::<Vec<_>>()
        .join(", "))
}

fn schema_filter_binds(schema_names: &[String]) -> Vec<OracleBind> {
    schema_names
        .iter()
        .cloned()
        .map(OracleBind::String)
        .collect()
}

fn objects_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  object_name,
  object_type,
  status,
  to_char(last_ddl_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') as last_ddl_time_iso,
  editionable,
  edition_name
from all_objects
where owner in ({owner_clause})
  and object_type in (
    'TABLE',
    'VIEW',
    'MATERIALIZED VIEW',
    'SEQUENCE',
    'TYPE',
    'PACKAGE',
    'PROCEDURE',
    'FUNCTION',
    'TRIGGER',
    'EDITIONING VIEW'
  )
order by owner, object_type, object_name"
    )
}

fn columns_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  table_name,
  column_name,
  nvl(column_id, internal_column_id) as column_position,
  data_type_owner,
  data_type,
  data_length,
  data_precision,
  data_scale,
  char_used,
  nullable,
  data_default_vc,
  virtual_column,
  hidden_column
from all_tab_cols
where owner in ({owner_clause})
order by owner, table_name, nvl(column_id, internal_column_id)"
    )
}

fn constraints_sql(owner_clause: &str) -> String {
    format!(
        "select
  c.owner,
  c.constraint_name,
  c.table_name,
  c.constraint_type,
  c.r_owner as referenced_table_owner,
  p.table_name as referenced_table_name,
  c.search_condition_vc,
  case when c.deferrable = 'DEFERRABLE' then 'Y' else 'N' end as is_deferrable,
  case when c.deferred = 'DEFERRED' then 'Y' else 'N' end as is_deferred,
  child.column_name,
  child.position as column_position,
  parent.column_name as referenced_column_name
from all_constraints c
left join all_constraints p
  on p.owner = c.r_owner
 and p.constraint_name = c.r_constraint_name
left join all_cons_columns child
  on child.owner = c.owner
 and child.constraint_name = c.constraint_name
left join all_cons_columns parent
  on parent.owner = p.owner
 and parent.constraint_name = p.constraint_name
 and parent.position = child.position
where c.owner in ({owner_clause})
  and c.constraint_type in ('P', 'R', 'U', 'C', 'F')
order by c.owner, c.constraint_name, child.position"
    )
}

fn indexes_sql(owner_clause: &str) -> String {
    format!(
        "select
  i.owner,
  i.index_name,
  i.table_owner,
  i.table_name,
  case when i.uniqueness = 'UNIQUE' then 'Y' else 'N' end as is_unique,
  i.index_type,
  i.status,
  c.column_name,
  c.column_position
from all_indexes i
left join all_ind_columns c
  on c.index_owner = i.owner
 and c.index_name = i.index_name
 and c.table_owner = i.table_owner
 and c.table_name = i.table_name
where i.owner in ({owner_clause})
order by i.owner, i.index_name, c.column_position"
    )
}

fn triggers_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  trigger_name,
  table_owner,
  table_name,
  trigger_type,
  triggering_event,
  when_clause
from all_triggers
where owner in ({owner_clause})
  and base_object_type in ('TABLE', 'VIEW')
order by owner, trigger_name"
    )
}

fn synonyms_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  synonym_name,
  table_owner,
  table_name,
  db_link
from all_synonyms
where owner = 'PUBLIC'
   or owner in ({owner_clause})
order by owner, synonym_name"
    )
}

fn routines_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  object_name,
  procedure_name,
  subprogram_id,
  overload,
  object_type,
  deterministic,
  pipelined
from all_procedures
where owner in ({owner_clause})
  and (procedure_name is not null or object_type in ('FUNCTION', 'PROCEDURE'))
order by owner, object_name, procedure_name, subprogram_id"
    )
}

fn routine_arguments_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  package_name,
  object_name,
  subprogram_id,
  overload,
  argument_name,
  position,
  sequence,
  data_type,
  type_owner,
  type_name,
  data_length,
  data_precision,
  data_scale,
  in_out,
  defaulted
from all_arguments
where owner in ({owner_clause})
  and data_level = 0
order by owner, package_name, object_name, subprogram_id, sequence"
    )
}

fn views_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  view_name,
  text_vc,
  read_only
from all_views
where owner in ({owner_clause})
order by owner, view_name"
    )
}

fn materialized_views_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  mview_name,
  refresh_mode,
  refresh_method,
  query
from all_mviews
where owner in ({owner_clause})
order by owner, mview_name"
    )
}

fn sequences_sql(owner_clause: &str) -> String {
    format!(
        "select
  sequence_owner,
  sequence_name,
  min_value,
  max_value,
  increment_by,
  cycle_flag,
  order_flag,
  cache_size
from all_sequences
where sequence_owner in ({owner_clause})
order by sequence_owner, sequence_name"
    )
}

fn type_attributes_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  type_name,
  attr_name,
  attr_no,
  attr_type_owner,
  attr_type_name,
  length,
  precision,
  scale
from all_type_attrs
where owner in ({owner_clause})
order by owner, type_name, attr_no"
    )
}

fn grants_sql(owner_clause: &str) -> String {
    format!(
        "select
  table_schema,
  table_name,
  grantee,
  privilege,
  grantable,
  hierarchy
from all_tab_privs
where table_schema in ({owner_clause})
order by table_schema, table_name, grantee, privilege"
    )
}

fn db_links_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  db_link,
  host
from all_db_links
where owner = 'PUBLIC'
   or owner in ({owner_clause})
order by owner, db_link"
    )
}

fn table_comments_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  table_name,
  table_type,
  comments
from all_tab_comments
where owner in ({owner_clause})
  and comments is not null
order by owner, table_name"
    )
}

fn column_comments_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  table_name,
  column_name,
  comments
from all_col_comments
where owner in ({owner_clause})
  and comments is not null
order by owner, table_name, column_name"
    )
}

fn editioning_views_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  view_name,
  table_name
from all_editioning_views
where owner in ({owner_clause})
order by owner, view_name"
    )
}

fn vpd_policies_sql(owner_clause: &str) -> String {
    format!(
        "select
  object_owner,
  object_name,
  policy_group,
  policy_name,
  pf_owner,
  package,
  function,
  sel,
  ins,
  upd,
  del,
  enable
from all_policies
where object_owner in ({owner_clause})
order by object_owner, object_name, policy_group, policy_name"
    )
}

fn dependencies_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  name,
  type,
  referenced_owner,
  referenced_name,
  referenced_type,
  dependency_type
from all_dependencies
where owner in ({owner_clause})
order by owner, name, referenced_owner, referenced_name"
    )
}

fn plscope_availability_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  plscope_settings
from all_plsql_object_settings
where owner in ({owner_clause})"
    )
}

fn plscope_identifiers_sql(owner_clause: &str) -> String {
    format!(
        "select
  owner,
  name,
  type,
  usage,
  line,
  col,
  object_name
from all_identifiers
where owner in ({owner_clause})
order by owner, object_name, line, col"
    )
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
    }

    #[async_trait(?Send)]
    impl OracleConnection for RecordingConn {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
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
        assert!(calls[0].0.contains("owner in (:1, :2)"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("DEMO".to_owned()),
                OracleBind::String("HR".to_owned())
            ]
        );
        assert!(calls[12].0.contains("from all_users"));
        assert!(calls[12].1.is_empty());
        assert!(calls[17].0.contains("from all_editions"));
        assert!(calls[17].1.is_empty());
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
