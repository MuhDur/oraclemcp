//! Closed dictionary SQL used by the served read-purity proof.
//!
//! Each query has fixed text and a checked bind schema. Adding a catalog read
//! requires a new enum variant and an explicit output and audit policy.

use asupersync::Cx;

use crate::{DbError, OracleBind, OracleConnection, OracleRow};

/// Oracle bind kinds accepted by the closed dictionary runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogBindKind {
    /// A VARCHAR2-style identifier or name.
    Text,
    /// A VARCHAR2-style identifier or name, or SQL NULL for an absent filter.
    NullableText,
    /// An integral row limit.
    Integer,
    /// An integral bound, or SQL NULL for an absent range endpoint.
    NullableInteger,
}

/// Ordered bind kinds required by one fixed query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The positional bind kinds; values are never interpolated into SQL.
pub struct BindSchema(pub &'static [CatalogBindKind]);

/// Governs whether dictionary rows may leave an internal proof path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogOutputPolicy {
    /// Rows are used only to make an internal guard decision.
    InternalProof,
    /// Rows describe the live session that owns a proof.
    SessionContext,
    /// Rows are diagnostic observations, not proof of absence.
    VisibilityObservation,
    /// Dictionary metadata returned by a governed inspection tool.
    DictionaryMetadata,
}

/// The purpose attached to a dictionary query for audit routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogAuditClass {
    /// Read purity evidence.
    ReadPurity,
    /// Semantic name-resolution evidence.
    NameResolution,
    /// A diagnostic catalog observation.
    Diagnostic,
}

/// Fixed SQL and handling metadata for one catalog query.
#[derive(Debug, Clone, Copy)]
pub struct CatalogReadSpec {
    /// Constant SQL text sent to Oracle.
    pub sql: &'static str,
    /// Ordered positional bind schema.
    pub binds: BindSchema,
    /// Why this query exists.
    pub purpose: &'static str,
    /// Whether returned rows may be surfaced.
    pub output_policy: CatalogOutputPolicy,
    /// Audit classification for this query.
    pub audit_class: CatalogAuditClass,
}

macro_rules! top_sql_live {
    ($order:literal, $filter:literal, $limit:literal) => {
        concat!(
            "SELECT * FROM (SELECT sql_id, SUBSTR(sql_text, 1, 200) AS sql_text, executions, ",
            "elapsed_time, cpu_time, buffer_gets, disk_reads, ",
            "ROUND(RATIO_TO_REPORT(",
            $order,
            ") OVER () * 100, 2) AS pct_of_total ",
            "FROM v$sqlstats ORDER BY ",
            $order,
            " DESC NULLS LAST) WHERE ",
            $filter,
            "rownum <= ",
            $limit
        )
    };
}

macro_rules! top_sql_awr {
    ($order:literal) => {
        concat!(
            "SELECT * FROM (SELECT s.sql_id, ",
            "(SELECT SUBSTR(t.sql_text, 1, 200) FROM dba_hist_sqltext t ",
            "WHERE t.sql_id = s.sql_id AND rownum = 1) AS sql_text, ",
            "SUM(s.executions_delta) AS executions, SUM(s.elapsed_time_delta) AS elapsed_time, ",
            "SUM(s.cpu_time_delta) AS cpu_time, SUM(s.buffer_gets_delta) AS buffer_gets, ",
            "SUM(s.disk_reads_delta) AS disk_reads FROM dba_hist_sqlstat s ",
            "GROUP BY s.sql_id ORDER BY ",
            $order,
            " DESC NULLS LAST) WHERE rownum <= :1"
        )
    };
}

macro_rules! top_sql_statspack {
    ($order:literal) => {
        concat!(
            "SELECT * FROM (SELECT old_hash_value AS sql_id, ",
            "SUBSTR(MAX(sql_text), 1, 200) AS sql_text, SUM(executions) AS executions, ",
            "SUM(elapsed_time) AS elapsed_time, SUM(cpu_time) AS cpu_time, ",
            "SUM(buffer_gets) AS buffer_gets, SUM(disk_reads) AS disk_reads ",
            "FROM stats$sql_summary GROUP BY old_hash_value ORDER BY ",
            $order,
            " DESC NULLS LAST) WHERE rownum <= :1"
        )
    };
}

/// The complete catalog-query set used by the current semantic read proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogQueryId {
    /// Session user, current schema and edition.
    SessionContext,
    /// Enabled session roles.
    SessionRoles,
    /// Exact local object candidates.
    Objects,
    /// Synonym target and identity.
    Synonyms,
    /// Standalone routine signatures.
    StandaloneArguments,
    /// Packaged routine signatures.
    MemberArguments,
    /// Standalone subprogram identities, including zero-argument routines.
    StandaloneProcedures,
    /// Packaged member identities, including zero-argument routines.
    MemberProcedures,
    /// Enabled SELECT policies for up to 32 exact relations.
    PolicyRowsForRelations32,
    /// Fine-grained audit policies for up to 32 exact relations.
    FgaPoliciesForRelations32,
    /// Virtual columns for up to 32 exact relations.
    VirtualColumnsForRelations32,
    /// Ambiguous unqualified column candidates.
    ColumnConflict,
    /// One relation's column identity.
    RelationColumn,
    /// Exact column type before interpreting a dotted value path.
    ColumnPathType,
    /// JSON constraint or native JSON column visibility for one exact column.
    JsonColumn,
    /// Enabled validated IS JSON check on one exact text column.
    JsonConstraint,
    /// One exact attribute of a visible SQL object type.
    TypeAttribute,
    /// Enabled SELECT policies on one relation.
    SelectPolicy,
    /// Virtual columns on one relation.
    VirtualColumn,
    /// Diagnostic visibility of ALL_POLICIES.
    AllPoliciesVisibility,
    /// Readability of the policy catalog.
    PolicyCatalogProof,
    /// Readability of the fine-grained audit policy catalog.
    FgaCatalogProof,
    /// Readability of the target column catalog.
    TargetColumnCatalogProof,
    /// Diagnostic access to DBA_OBJECTS.
    DbaObjectsProbe,
    /// Diagnostic access to ALL_OBJECTS.
    AllObjectsProbe,
    /// Whether the Diagnostics Pack is enabled for this database.
    DiagnosticsPackProbe,
    /// Diagnostic access to PL/Scope identifiers.
    AllIdentifiersProbe,
    /// Effective privileges of the current session.
    SessionPrivileges,
    /// Whether Oracle Advanced Security is available for native redaction.
    NativeRedactionOption,
    /// Whether the free Statspack catalog can be read.
    StatspackProbe,
    /// Licensed AWR plan-cost history for one SQL ID.
    PlanCostTimeline,
    /// Bounded PL/Scope identifier map.
    PlscopeIdentifiers,
    /// Bounded PL/Scope statement map.
    PlscopeStatements,
    /// Gathered optimizer statistics for one table.
    TableStats,
    /// Staleness of gathered table statistics.
    TableStatsStale,
    /// Dictionary column count for one table.
    TableColumnCount,
    /// Dictionary comment for one object.
    ObjectComment,
    /// Columns and comments for search results.
    SearchColumns,
    /// Index identities on a table.
    SearchIndexes,
    /// Column identities within one index.
    SearchIndexColumns,
    /// Detailed column metadata for one relation.
    DescribeColumns,
    /// Constraint and constrained-column metadata for one relation.
    DescribeConstraints,
    /// Visible PL/SQL source types for one object.
    SourceTypes,
    /// Primary-key columns for one table.
    PrimaryKeyColumns,
    /// Output from the diagnostic EXPLAIN PLAN just issued.
    ExplainPlanDisplay,
    /// Optimizer estimates from the latest plan root.
    PlanCostEstimate,
    /// Bounded object listing with optional filters.
    ListObjects,
    /// Deterministic object listing page with optional filters.
    ListObjectsPage,
    /// Compact schema projection page with optional filters.
    SchemaProjectionPage,
    /// Bounded schema identity map for orient.
    OrientSchemaPage,
    /// Bounded newest-first DDL feed for orient.
    OrientRecentDdlPage,
    /// Bounded schema list with an optional name filter.
    ListSchemas,
    /// Bounded foreign-key topology page for orient.
    OrientForeignKeysPage,
    /// Bounded table-change activity page for orient.
    OrientHotObjectsPage,
    /// Direct dependents of one object.
    Dependents,
    /// Metadata for one index.
    IndexMetadata,
    /// Ordered columns of one index.
    IndexColumns,
    /// Ordered expressions of one index.
    IndexExpressions,
    /// Metadata and body for one trigger.
    TriggerMetadata,
    /// Definition metadata for one view.
    ViewMetadata,
    /// Current read-only transaction SCN from DBMS_FLASHBACK.
    CurrentScn,
    /// Resolve a timestamp to a flashback SCN.
    TimestampToScn,
    /// Bounded compile diagnostics for an optional object name.
    CompileErrors,
    /// Bounded source search with nullable metadata filters.
    SearchSource,
    /// Source lines for one object with nullable line bounds.
    GetSource,
    /// Bounded DDL text for one allowlisted object type.
    GetDdl,
    /// Database compatibility setting for in-database vector embedding.
    SemanticSearchCompatible,
    /// Visible local ONNX models for in-database vector embedding.
    SemanticSearchOnnxModel,
    /// Existing child of a named edition before creating another.
    EditionChildren,
    /// Free live cursor cache ranked by elapsed time.
    TopSqlLiveElapsed,
    /// Free live cursor cache ranked by CPU time.
    TopSqlLiveCpu,
    /// Free live cursor cache ranked by logical reads.
    TopSqlLiveBufferGets,
    /// Free live cursor cache ranked by physical reads.
    TopSqlLiveDiskReads,
    /// Live cursor cache ranked by elapsed time with a minimum share.
    TopSqlLiveElapsedPct,
    /// Live cursor cache ranked by CPU time with a minimum share.
    TopSqlLiveCpuPct,
    /// Live cursor cache ranked by logical reads with a minimum share.
    TopSqlLiveBufferGetsPct,
    /// Live cursor cache ranked by physical reads with a minimum share.
    TopSqlLiveDiskReadsPct,
    /// Licensed AWR SQL history ranked by elapsed time.
    TopSqlAwrElapsed,
    /// Licensed AWR SQL history ranked by CPU time.
    TopSqlAwrCpu,
    /// Licensed AWR SQL history ranked by logical reads.
    TopSqlAwrBufferGets,
    /// Licensed AWR SQL history ranked by physical reads.
    TopSqlAwrDiskReads,
    /// Free Statspack SQL history ranked by elapsed time.
    TopSqlStatspackElapsed,
    /// Free Statspack SQL history ranked by CPU time.
    TopSqlStatspackCpu,
    /// Free Statspack SQL history ranked by logical reads.
    TopSqlStatspackBufferGets,
    /// Free Statspack SQL history ranked by physical reads.
    TopSqlStatspackDiskReads,
}

impl CatalogQueryId {
    /// Every query ID, used by exhaustive contract tests.
    pub const ALL: [Self; 85] = [
        Self::SessionContext,
        Self::SessionRoles,
        Self::Objects,
        Self::Synonyms,
        Self::StandaloneArguments,
        Self::MemberArguments,
        Self::StandaloneProcedures,
        Self::MemberProcedures,
        Self::PolicyRowsForRelations32,
        Self::FgaPoliciesForRelations32,
        Self::VirtualColumnsForRelations32,
        Self::ColumnConflict,
        Self::RelationColumn,
        Self::ColumnPathType,
        Self::JsonColumn,
        Self::JsonConstraint,
        Self::TypeAttribute,
        Self::SelectPolicy,
        Self::VirtualColumn,
        Self::AllPoliciesVisibility,
        Self::PolicyCatalogProof,
        Self::FgaCatalogProof,
        Self::TargetColumnCatalogProof,
        Self::DbaObjectsProbe,
        Self::AllObjectsProbe,
        Self::DiagnosticsPackProbe,
        Self::AllIdentifiersProbe,
        Self::SessionPrivileges,
        Self::NativeRedactionOption,
        Self::StatspackProbe,
        Self::PlanCostTimeline,
        Self::PlscopeIdentifiers,
        Self::PlscopeStatements,
        Self::TableStats,
        Self::TableStatsStale,
        Self::TableColumnCount,
        Self::ObjectComment,
        Self::SearchColumns,
        Self::SearchIndexes,
        Self::SearchIndexColumns,
        Self::DescribeColumns,
        Self::DescribeConstraints,
        Self::SourceTypes,
        Self::PrimaryKeyColumns,
        Self::ExplainPlanDisplay,
        Self::PlanCostEstimate,
        Self::ListObjects,
        Self::ListObjectsPage,
        Self::SchemaProjectionPage,
        Self::OrientSchemaPage,
        Self::OrientRecentDdlPage,
        Self::ListSchemas,
        Self::OrientForeignKeysPage,
        Self::OrientHotObjectsPage,
        Self::Dependents,
        Self::IndexMetadata,
        Self::IndexColumns,
        Self::IndexExpressions,
        Self::TriggerMetadata,
        Self::ViewMetadata,
        Self::CurrentScn,
        Self::TimestampToScn,
        Self::CompileErrors,
        Self::SearchSource,
        Self::GetSource,
        Self::GetDdl,
        Self::SemanticSearchCompatible,
        Self::SemanticSearchOnnxModel,
        Self::EditionChildren,
        Self::TopSqlLiveElapsed,
        Self::TopSqlLiveCpu,
        Self::TopSqlLiveBufferGets,
        Self::TopSqlLiveDiskReads,
        Self::TopSqlLiveElapsedPct,
        Self::TopSqlLiveCpuPct,
        Self::TopSqlLiveBufferGetsPct,
        Self::TopSqlLiveDiskReadsPct,
        Self::TopSqlAwrElapsed,
        Self::TopSqlAwrCpu,
        Self::TopSqlAwrBufferGets,
        Self::TopSqlAwrDiskReads,
        Self::TopSqlStatspackElapsed,
        Self::TopSqlStatspackCpu,
        Self::TopSqlStatspackBufferGets,
        Self::TopSqlStatspackDiskReads,
    ];

    /// Return the immutable SQL, bind and handling contract for this ID.
    #[must_use]
    pub const fn spec(self) -> CatalogReadSpec {
        use CatalogAuditClass::{Diagnostic, NameResolution, ReadPurity};
        use CatalogBindKind::{Integer, NullableText, Text};
        use CatalogOutputPolicy::{
            DictionaryMetadata, InternalProof, SessionContext, VisibilityObservation,
        };
        const EMPTY: BindSchema = BindSchema(&[]);
        const I: BindSchema = BindSchema(&[Integer]);
        const II: BindSchema = BindSchema(&[Integer, Integer]);
        const TT: BindSchema = BindSchema(&[Text, Text]);
        const TI: BindSchema = BindSchema(&[Text, Integer]);
        const TTI: BindSchema = BindSchema(&[Text, Text, Integer]);
        const TTTI: BindSchema = BindSchema(&[Text, Text, Text, Integer]);
        const TTT: BindSchema = BindSchema(&[Text, Text, Text]);
        const T32: BindSchema = BindSchema(&[Text; 64]);
        const N3I: BindSchema = BindSchema(&[NullableText, NullableText, NullableText, Integer]);
        const N3II: BindSchema =
            BindSchema(&[NullableText, NullableText, NullableText, Integer, Integer]);
        const N2II: BindSchema = BindSchema(&[NullableText, NullableText, Integer, Integer]);
        const NI: BindSchema = BindSchema(&[NullableText, Integer]);
        const NII: BindSchema = BindSchema(&[NullableText, Integer, Integer]);
        let (sql, binds, purpose, output_policy, audit_class) = match self {
            Self::SessionContext => (
                SESSION_CONTEXT_SQL,
                EMPTY,
                "bind resolver to the live session",
                SessionContext,
                NameResolution,
            ),
            Self::SessionRoles => (
                SESSION_ROLES_SQL,
                I,
                "bind resolver to enabled roles",
                SessionContext,
                NameResolution,
            ),
            Self::Objects => (
                OBJECTS_SQL,
                TTI,
                "resolve local object identity",
                InternalProof,
                NameResolution,
            ),
            Self::Synonyms => (
                SYNONYMS_SQL,
                TTI,
                "resolve synonym identity",
                InternalProof,
                NameResolution,
            ),
            Self::StandaloneArguments => (
                STANDALONE_ARGUMENTS_SQL,
                TTI,
                "resolve standalone callable overloads",
                InternalProof,
                NameResolution,
            ),
            Self::MemberArguments => (
                MEMBER_ARGUMENTS_SQL,
                TTTI,
                "resolve member callable overloads",
                InternalProof,
                NameResolution,
            ),
            Self::StandaloneProcedures => (
                STANDALONE_PROCEDURES_SQL,
                TTI,
                "resolve standalone subprogram identities",
                InternalProof,
                NameResolution,
            ),
            Self::MemberProcedures => (
                MEMBER_PROCEDURES_SQL,
                TTTI,
                "resolve packaged subprogram identities",
                InternalProof,
                NameResolution,
            ),
            Self::PolicyRowsForRelations32 => (
                POLICY_ROWS_FOR_RELATIONS_32_SQL,
                T32,
                "prove no enabled SELECT policy across bounded relations",
                InternalProof,
                ReadPurity,
            ),
            Self::FgaPoliciesForRelations32 => (
                FGA_POLICIES_FOR_RELATIONS_32_SQL,
                T32,
                "prove fine-grained audit handlers cannot run for bounded relations",
                InternalProof,
                ReadPurity,
            ),
            Self::VirtualColumnsForRelations32 => (
                VIRTUAL_COLUMNS_FOR_RELATIONS_32_SQL,
                T32,
                "prove virtual columns cannot run user code across bounded relations",
                InternalProof,
                ReadPurity,
            ),
            Self::ColumnConflict => (
                COLUMN_CONFLICT_SQL,
                TI,
                "detect ambiguous unqualified columns",
                InternalProof,
                NameResolution,
            ),
            Self::RelationColumn => (
                RELATION_COLUMN_SQL,
                TTT,
                "resolve a relation column",
                InternalProof,
                NameResolution,
            ),
            Self::ColumnPathType => (
                COLUMN_PATH_TYPE_SQL,
                TTT,
                "prove exact leading column type for dotted value path",
                InternalProof,
                NameResolution,
            ),
            Self::JsonColumn => (
                JSON_COLUMN_SQL,
                TTT,
                "prove constrained JSON column for dotted value path",
                InternalProof,
                NameResolution,
            ),
            Self::JsonConstraint => (
                JSON_CONSTRAINT_SQL,
                TTT,
                "prove enabled validated IS JSON check for dotted value path",
                InternalProof,
                NameResolution,
            ),
            Self::TypeAttribute => (
                TYPE_ATTRIBUTE_SQL,
                TTT,
                "prove exact SQL object attribute chain",
                InternalProof,
                NameResolution,
            ),
            Self::SelectPolicy => (
                SELECT_POLICY_SQL,
                TT,
                "prove no enabled SELECT policy",
                InternalProof,
                ReadPurity,
            ),
            Self::VirtualColumn => (
                VIRTUAL_COLUMN_SQL,
                TT,
                "prove no virtual column",
                InternalProof,
                ReadPurity,
            ),
            Self::AllPoliciesVisibility => (
                ALL_POLICIES_VISIBILITY_SQL,
                EMPTY,
                "observe visible VPD policies",
                VisibilityObservation,
                Diagnostic,
            ),
            Self::PolicyCatalogProof => (
                POLICY_CATALOG_PROOF_SQL,
                EMPTY,
                "prove policy catalog is readable",
                InternalProof,
                ReadPurity,
            ),
            Self::FgaCatalogProof => (
                FGA_CATALOG_PROOF_SQL,
                EMPTY,
                "prove fine-grained audit policy catalog is readable",
                InternalProof,
                ReadPurity,
            ),
            Self::TargetColumnCatalogProof => (
                TARGET_COLUMN_CATALOG_PROOF_SQL,
                TT,
                "prove target column catalog is readable",
                InternalProof,
                ReadPurity,
            ),
            Self::DbaObjectsProbe => (
                "SELECT 1 FROM dba_objects WHERE rownum = 1",
                EMPTY,
                "observe DBA_OBJECTS access",
                VisibilityObservation,
                Diagnostic,
            ),
            Self::AllObjectsProbe => (
                "SELECT 1 FROM all_objects WHERE rownum = 1",
                EMPTY,
                "observe ALL_OBJECTS access",
                VisibilityObservation,
                Diagnostic,
            ),
            Self::DiagnosticsPackProbe => (
                "SELECT value FROM v$parameter WHERE name = 'control_management_pack_access'",
                EMPTY,
                "observe Diagnostics Pack availability",
                VisibilityObservation,
                Diagnostic,
            ),
            Self::AllIdentifiersProbe => (
                "SELECT 1 FROM all_identifiers WHERE rownum = 1",
                EMPTY,
                "observe PL/Scope access",
                VisibilityObservation,
                Diagnostic,
            ),
            Self::SessionPrivileges => (
                "SELECT privilege FROM session_privs",
                EMPTY,
                "observe effective session privileges",
                SessionContext,
                Diagnostic,
            ),
            Self::NativeRedactionOption => (
                crate::native_redaction::NATIVE_REDACTION_OPTION_SQL,
                EMPTY,
                "observe Advanced Security option availability",
                VisibilityObservation,
                Diagnostic,
            ),
            Self::StatspackProbe => (
                "SELECT 1 FROM perfstat.stats$snapshot WHERE rownum = 1",
                EMPTY,
                "observe Statspack access",
                VisibilityObservation,
                Diagnostic,
            ),
            Self::PlanCostTimeline => (
                crate::awr::PLAN_COST_TIMELINE_SQL,
                TI,
                "read licensed AWR plan-cost history",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::PlscopeIdentifiers => (
                "SELECT * FROM ( \
                 SELECT name, type, usage, line, col, signature FROM all_identifiers \
                 WHERE owner = :1 AND object_name = :2 ORDER BY line, col \
             ) WHERE ROWNUM <= :3",
                TTI,
                "read bounded PL/Scope identifiers",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::PlscopeStatements => (
                "SELECT * FROM ( \
                 SELECT type, line, sql_id FROM all_statements \
                 WHERE owner = :1 AND object_name = :2 ORDER BY line \
             ) WHERE ROWNUM <= :3",
                TTI,
                "read bounded PL/Scope statement map",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TableStats => (
                "SELECT num_rows, TO_CHAR(last_analyzed, 'YYYY-MM-DD\"T\"HH24:MI:SS') AS last_analyzed \
                 FROM all_tables WHERE owner = :1 AND table_name = :2",
                TT,
                "read gathered table statistics",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TableStatsStale => (
                "SELECT stale_stats FROM all_tab_statistics \
                 WHERE owner = :1 AND table_name = :2 AND object_type = 'TABLE' \
                   AND partition_name IS NULL",
                TT,
                "read gathered-statistics staleness",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TableColumnCount => (
                "SELECT COUNT(*) AS column_count FROM all_tab_columns \
                 WHERE owner = :1 AND table_name = :2",
                TT,
                "count visible table columns",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ObjectComment => (
                "SELECT comments FROM all_tab_comments \
                 WHERE owner = :1 AND table_name = :2",
                TT,
                "read object comment",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::SearchColumns => (
                "SELECT c.column_name, c.data_type, c.nullable, cc.comments \
                 FROM all_tab_columns c \
                 LEFT JOIN all_col_comments cc \
                   ON cc.owner = c.owner AND cc.table_name = c.table_name \
                  AND cc.column_name = c.column_name \
                 WHERE c.owner = :1 AND c.table_name = :2 \
                 ORDER BY c.column_id",
                TT,
                "read columns and comments for search",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::SearchIndexes => (
                "SELECT index_name, uniqueness FROM all_indexes \
                 WHERE table_owner = :1 AND table_name = :2 \
                 ORDER BY index_name",
                TT,
                "read table index identities",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::SearchIndexColumns => (
                "SELECT column_name FROM all_ind_columns \
                 WHERE index_owner = :1 AND index_name = :2 \
                 ORDER BY column_position",
                TT,
                "read index column identities",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::DescribeColumns => (
                "SELECT column_name, data_type, data_length, nullable, data_default \
                 FROM all_tab_columns WHERE owner = :1 AND table_name = :2 \
                 ORDER BY column_id",
                TT,
                "describe relation columns",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::DescribeConstraints => (
                "SELECT * FROM ( \
                   SELECT c.constraint_name, c.constraint_type, c.status, \
                          c.deferrable, c.deferred, c.validated, c.generated, \
                          c.r_owner, c.r_constraint_name, cc.column_name, cc.position \
                   FROM all_constraints c \
                   LEFT JOIN all_cons_columns cc \
                     ON cc.owner = c.owner \
                    AND cc.constraint_name = c.constraint_name \
                    AND cc.table_name = c.table_name \
                   WHERE c.owner = :1 AND c.table_name = :2 \
                   ORDER BY c.constraint_name, cc.position \
               ) WHERE ROWNUM <= :3",
                TTI,
                "describe relation constraints",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::SourceTypes => (
                "SELECT type \
                 FROM ( \
                     SELECT DISTINCT type, \
                            CASE type \
                                WHEN 'PACKAGE' THEN 1 \
                                WHEN 'PACKAGE BODY' THEN 2 \
                                WHEN 'TYPE' THEN 3 \
                                WHEN 'TYPE BODY' THEN 4 \
                                WHEN 'PROCEDURE' THEN 5 \
                                WHEN 'FUNCTION' THEN 6 \
                                WHEN 'TRIGGER' THEN 7 \
                                ELSE 99 \
                            END sort_key \
                     FROM all_source \
                     WHERE owner = :1 AND name = :2 \
                 ) \
                 ORDER BY sort_key, type",
                TT,
                "list visible source object types",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::PrimaryKeyColumns => (
                "SELECT cc.column_name \
                 FROM all_constraints c \
                 JOIN all_cons_columns cc \
                   ON cc.owner = c.owner \
                  AND cc.constraint_name = c.constraint_name \
                  AND cc.table_name = c.table_name \
                 WHERE c.owner = :1 \
                   AND c.table_name = :2 \
                   AND c.constraint_type = 'P' \
                 ORDER BY cc.position",
                TT,
                "read primary-key column order",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExplainPlanDisplay => (
                "SELECT plan_table_output FROM TABLE(DBMS_XPLAN.DISPLAY)",
                EMPTY,
                "read current diagnostic plan output",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::PlanCostEstimate => (
                crate::intelligence::PLAN_COST_SQL,
                EMPTY,
                "read latest diagnostic plan estimates",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ListObjects => (
                "SELECT * FROM ( \
                   WITH args AS ( \
                       SELECT :1 owner_filter, :2 type_filter, :3 name_filter FROM dual \
                   ) \
                   SELECT o.owner, o.object_name, o.object_type, o.status, o.last_ddl_time \
                   FROM all_objects o CROSS JOIN args \
                   WHERE (args.owner_filter IS NULL OR o.owner = args.owner_filter) \
                     AND (args.type_filter IS NULL OR o.object_type = args.type_filter) \
                     AND (args.name_filter IS NULL OR o.object_name LIKE args.name_filter) \
                   ORDER BY o.owner, o.object_type, o.object_name \
               ) WHERE ROWNUM <= :4",
                N3I,
                "list bounded objects with optional filters",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ListObjectsPage => (
                "SELECT owner, object_name, object_type, status, last_ddl_time FROM ( \
                   SELECT selected.*, ROWNUM AS page_row FROM ( \
                       WITH args AS ( \
                           SELECT :1 owner_filter, :2 type_filter, :3 name_filter FROM dual \
                       ) \
                       SELECT o.owner, o.object_name, o.object_type, o.status, o.last_ddl_time \
                       FROM all_objects o CROSS JOIN args \
                       WHERE (args.owner_filter IS NULL OR o.owner = args.owner_filter) \
                         AND (args.type_filter IS NULL OR o.object_type = args.type_filter) \
                         AND (args.name_filter IS NULL OR o.object_name LIKE args.name_filter) \
                       ORDER BY o.owner, o.object_type, o.object_name \
                   ) selected WHERE ROWNUM <= :4 \
               ) WHERE page_row > :5",
                N3II,
                "page bounded objects with optional filters",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::SchemaProjectionPage => (
                "SELECT owner, object_name, object_type, status, last_ddl_time FROM ( \
                   SELECT selected.*, ROWNUM AS page_row FROM ( \
                       WITH args AS ( \
                           SELECT :1 owner_filter, :2 name_filter FROM dual \
                       ) \
                       SELECT o.owner, o.object_name, o.object_type, o.status, o.last_ddl_time \
                       FROM all_objects o CROSS JOIN args \
                       WHERE (args.owner_filter IS NULL OR o.owner = args.owner_filter) \
                         AND o.object_type IN ('TABLE', 'VIEW', 'PACKAGE') \
                         AND (args.name_filter IS NULL OR o.object_name LIKE args.name_filter) \
                       ORDER BY o.owner, o.object_type, o.object_name \
                   ) selected WHERE ROWNUM <= :3 \
               ) WHERE page_row > :4",
                N2II,
                "page compact schema projection",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::OrientSchemaPage => (
                "SELECT owner, object_name, object_type FROM ( \
                   SELECT selected.*, ROWNUM AS page_row FROM ( \
                       WITH args AS ( \
                           SELECT :1 owner_filter FROM dual \
                       ) \
                       SELECT o.owner, o.object_name, o.object_type \
                       FROM all_objects o CROSS JOIN args \
                       WHERE args.owner_filter IS NULL OR o.owner = args.owner_filter \
                       ORDER BY o.owner, o.object_type, o.object_name \
                   ) selected WHERE ROWNUM <= :2 \
               ) WHERE page_row > :3",
                NII,
                "page bounded orient schema identities",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::OrientRecentDdlPage => (
                r"SELECT owner, object_name, object_type, last_ddl_time FROM (
                   SELECT selected.*, ROWNUM AS page_row FROM (
                       WITH args AS (
                           SELECT :1 owner_filter FROM dual
                       )
                       SELECT o.owner, o.object_name, o.object_type, o.last_ddl_time
                       FROM all_objects o CROSS JOIN args
                       WHERE (args.owner_filter IS NULL OR o.owner = args.owner_filter)
                         AND o.last_ddl_time IS NOT NULL
                       ORDER BY o.last_ddl_time DESC, o.owner, o.object_type, o.object_name
                   ) selected WHERE ROWNUM <= :2
               ) WHERE page_row > :3",
                NII,
                "page bounded recent DDL identities",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ListSchemas => (
                "SELECT * FROM ( \
                   WITH args AS ( \
                       SELECT :1 name_filter FROM dual \
                   ) \
                   SELECT o.owner AS schema_name, COUNT(*) AS object_count \
                   FROM all_objects o CROSS JOIN args \
                   WHERE args.name_filter IS NULL OR o.owner LIKE args.name_filter \
                   GROUP BY o.owner \
                   ORDER BY o.owner \
               ) WHERE ROWNUM <= :2",
                NI,
                "list bounded visible schemas",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::OrientForeignKeysPage => (
                "SELECT * FROM ( \
               WITH args AS ( \
                   SELECT :1 owner_filter FROM dual \
               ), selected_foreign_keys AS ( \
                   SELECT child_owner, child_table, constraint_name, parent_owner, parent_constraint_name \
                   FROM ( \
                       SELECT ordered_foreign_keys.*, ROWNUM AS page_row FROM ( \
                           SELECT child.owner AS child_owner, \
                                  child.table_name AS child_table, \
                                  child.constraint_name, \
                                  child.r_owner AS parent_owner, \
                                  child.r_constraint_name AS parent_constraint_name \
                           FROM all_constraints child CROSS JOIN args \
                           WHERE child.constraint_type = 'R' \
                             AND (args.owner_filter IS NULL OR child.owner = args.owner_filter) \
                           ORDER BY child.owner, child.table_name, child.constraint_name \
                       ) ordered_foreign_keys WHERE ROWNUM <= :2 \
                   ) WHERE page_row > :3 \
               ) \
               SELECT foreign_key.child_owner, foreign_key.child_table, \
                      foreign_key.constraint_name, foreign_key.parent_owner, \
                      parent.table_name AS parent_table, \
                      child_columns.column_name AS child_column, \
                      parent_columns.column_name AS parent_column, \
                      child_columns.position AS column_position \
               FROM selected_foreign_keys foreign_key \
               JOIN all_constraints parent \
                 ON parent.owner = foreign_key.parent_owner \
                AND parent.constraint_name = foreign_key.parent_constraint_name \
               JOIN all_cons_columns child_columns \
                 ON child_columns.owner = foreign_key.child_owner \
                AND child_columns.constraint_name = foreign_key.constraint_name \
               JOIN all_cons_columns parent_columns \
                 ON parent_columns.owner = parent.owner \
                AND parent_columns.constraint_name = parent.constraint_name \
                AND parent_columns.position = child_columns.position \
               ORDER BY foreign_key.child_owner, foreign_key.child_table, \
                        foreign_key.constraint_name, child_columns.position \
               )",
                NII,
                "page bounded foreign-key topology",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::OrientHotObjectsPage => (
                "SELECT owner, object_name, inserts, updates, deletes, last_modified, truncated, drop_segments FROM ( \
                   SELECT selected.*, ROWNUM AS page_row FROM ( \
                       WITH args AS ( \
                           SELECT :1 owner_filter FROM dual \
                       ) \
                       SELECT modifications.table_owner AS owner, \
                              modifications.table_name AS object_name, \
                              NVL(modifications.inserts, 0) AS inserts, \
                              NVL(modifications.updates, 0) AS updates, \
                              NVL(modifications.deletes, 0) AS deletes, \
                              modifications.timestamp AS last_modified, \
                              NVL(modifications.truncated, 'NO') AS truncated, \
                              NVL(modifications.drop_segments, 0) AS drop_segments \
                       FROM all_tab_modifications modifications CROSS JOIN args \
                       WHERE (args.owner_filter IS NULL \
                              OR modifications.table_owner = args.owner_filter) \
                         AND modifications.partition_name IS NULL \
                         AND modifications.subpartition_name IS NULL \
                       ORDER BY (NVL(modifications.inserts, 0) \
                                 + NVL(modifications.updates, 0) \
                                 + NVL(modifications.deletes, 0)) DESC, \
                                modifications.timestamp DESC NULLS LAST, \
                                modifications.table_owner, modifications.table_name \
                   ) selected WHERE ROWNUM <= :2 \
               ) WHERE page_row > :3",
                NII,
                "page bounded table-change activity",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::Dependents => (
                "SELECT * FROM ( \
                   WITH args AS ( \
                       SELECT :1 owner_filter, :2 name_filter FROM dual \
                   ) \
                   SELECT DISTINCT d.owner, d.name, d.type \
                   FROM all_dependencies d CROSS JOIN args \
                   WHERE d.referenced_owner = args.owner_filter \
                     AND d.referenced_name = args.name_filter \
                     AND NOT (d.owner = args.owner_filter AND d.name = args.name_filter) \
                   ORDER BY d.owner, d.type, d.name \
               ) WHERE ROWNUM <= :3",
                TTI,
                "read bounded direct dependents",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::IndexMetadata => (
                "SELECT owner, index_name, index_type, table_owner, table_name, \
                uniqueness, status, partitioned, temporary, generated, degree \
         FROM all_indexes \
         WHERE owner = :1 AND index_name = :2",
                TT,
                "describe index metadata",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::IndexColumns => (
                "SELECT column_position, column_name, descend, column_length, char_length \
         FROM all_ind_columns \
         WHERE index_owner = :1 AND index_name = :2 \
         ORDER BY column_position",
                TT,
                "describe index columns",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::IndexExpressions => (
                "SELECT column_position, column_expression \
         FROM all_ind_expressions \
         WHERE index_owner = :1 AND index_name = :2 \
         ORDER BY column_position",
                TT,
                "describe index expressions",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TriggerMetadata => (
                "SELECT owner, trigger_name, trigger_type, triggering_event, \
                table_owner, table_name, status, when_clause, description, trigger_body \
         FROM all_triggers \
         WHERE owner = :1 AND trigger_name = :2",
                TT,
                "describe trigger metadata and body",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ViewMetadata => (
                "SELECT owner, view_name, text_length, text \
         FROM all_views \
         WHERE owner = :1 AND view_name = :2",
                TT,
                "describe view definition metadata",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::CurrentScn => (
                crate::query::CURRENT_SCN_SQL,
                EMPTY,
                "capture the transaction snapshot SCN",
                SessionContext,
                Diagnostic,
            ),
            Self::TimestampToScn => (
                crate::query::TIMESTAMP_TO_SCN_SQL,
                BindSchema(&[Text]),
                "resolve a flashback timestamp to an SCN",
                SessionContext,
                Diagnostic,
            ),
            Self::CompileErrors => (
                "SELECT * FROM ( \
                   SELECT name, type, line, position, text, attribute \
                   FROM all_errors \
                   WHERE owner = :1 AND (:2 IS NULL OR name = :3) \
                   ORDER BY name, type, sequence \
               ) WHERE ROWNUM <= :4",
                BindSchema(&[Text, NullableText, NullableText, Integer]),
                "inspect bounded compile diagnostics",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::SearchSource => (
                "SELECT * FROM ( \
                   WITH args AS ( \
                       SELECT :1 owner_filter, :2 type_filter, :3 name_filter, :4 needle FROM dual \
                   ) \
                   SELECT s.owner, s.name, s.type, s.line, s.text \
                   FROM all_source s CROSS JOIN args \
                   WHERE (args.owner_filter IS NULL OR s.owner = args.owner_filter) \
                     AND (args.type_filter IS NULL OR s.type = args.type_filter) \
                     AND (args.name_filter IS NULL OR s.name LIKE args.name_filter) \
                     AND UPPER(s.text) LIKE UPPER('%' || args.needle || '%') \
                   ORDER BY s.owner, s.name, s.type, s.line \
               ) WHERE ROWNUM <= :5",
                BindSchema(&[NullableText, NullableText, NullableText, Text, Integer]),
                "search bounded visible source text",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::GetSource => (
                "SELECT line, text FROM all_source \
               WHERE owner = :1 AND name = :2 AND type = :3 \
                 AND (:4 IS NULL OR line >= :5) \
                 AND (:6 IS NULL OR line <= :7) \
               ORDER BY line",
                BindSchema(&[
                    Text,
                    Text,
                    Text,
                    CatalogBindKind::NullableInteger,
                    CatalogBindKind::NullableInteger,
                    CatalogBindKind::NullableInteger,
                    CatalogBindKind::NullableInteger,
                ]),
                "read source lines for one visible object",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::GetDdl => (
                "SELECT DBMS_LOB.SUBSTR(ddl, 4000, 1) AS ddl, DBMS_LOB.GETLENGTH(ddl) AS ddl_length \
         FROM (SELECT DBMS_METADATA.GET_DDL(:1, :2, :3) AS ddl FROM dual)",
                TTT,
                "fetch bounded metadata DDL for one allowlisted object",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::SemanticSearchCompatible => (
                "SELECT value AS compatible FROM v$parameter WHERE name = 'compatible'",
                EMPTY,
                "prove database compatibility for in-database embedding",
                InternalProof,
                Diagnostic,
            ),
            Self::SemanticSearchOnnxModel => (
                "SELECT model_name FROM user_mining_models \
                 WHERE mining_function = 'EMBEDDING' AND algorithm = 'ONNX' \
                 ORDER BY model_name FETCH FIRST 2 ROWS ONLY",
                EMPTY,
                "select one visible local ONNX embedding model",
                InternalProof,
                Diagnostic,
            ),
            Self::EditionChildren => (
                "SELECT edition_name FROM all_editions WHERE parent_edition_name = :1",
                BindSchema(&[Text]),
                "prove a parent edition has no existing child",
                InternalProof,
                Diagnostic,
            ),
            Self::TopSqlLiveElapsed => (
                top_sql_live!("elapsed_time", "", ":1"),
                I,
                "read bounded live top SQL by elapsed time",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlLiveCpu => (
                top_sql_live!("cpu_time", "", ":1"),
                I,
                "read bounded live top SQL by CPU time",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlLiveBufferGets => (
                top_sql_live!("buffer_gets", "", ":1"),
                I,
                "read bounded live top SQL by logical reads",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlLiveDiskReads => (
                top_sql_live!("disk_reads", "", ":1"),
                I,
                "read bounded live top SQL by physical reads",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlLiveElapsedPct => (
                top_sql_live!("elapsed_time", "pct_of_total >= :1 AND ", ":2"),
                II,
                "read bounded live top SQL by elapsed time and share",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlLiveCpuPct => (
                top_sql_live!("cpu_time", "pct_of_total >= :1 AND ", ":2"),
                II,
                "read bounded live top SQL by CPU time and share",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlLiveBufferGetsPct => (
                top_sql_live!("buffer_gets", "pct_of_total >= :1 AND ", ":2"),
                II,
                "read bounded live top SQL by logical reads and share",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlLiveDiskReadsPct => (
                top_sql_live!("disk_reads", "pct_of_total >= :1 AND ", ":2"),
                II,
                "read bounded live top SQL by physical reads and share",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlAwrElapsed => (
                top_sql_awr!("elapsed_time"),
                I,
                "read licensed AWR top SQL by elapsed time",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlAwrCpu => (
                top_sql_awr!("cpu_time"),
                I,
                "read licensed AWR top SQL by CPU time",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlAwrBufferGets => (
                top_sql_awr!("buffer_gets"),
                I,
                "read licensed AWR top SQL by logical reads",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlAwrDiskReads => (
                top_sql_awr!("disk_reads"),
                I,
                "read licensed AWR top SQL by physical reads",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlStatspackElapsed => (
                top_sql_statspack!("elapsed_time"),
                I,
                "read Statspack top SQL by elapsed time",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlStatspackCpu => (
                top_sql_statspack!("cpu_time"),
                I,
                "read Statspack top SQL by CPU time",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlStatspackBufferGets => (
                top_sql_statspack!("buffer_gets"),
                I,
                "read Statspack top SQL by logical reads",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::TopSqlStatspackDiskReads => (
                top_sql_statspack!("disk_reads"),
                I,
                "read Statspack top SQL by physical reads",
                DictionaryMetadata,
                Diagnostic,
            ),
        };
        CatalogReadSpec {
            sql,
            binds,
            purpose,
            output_policy,
            audit_class,
        }
    }
}

/// Refuse malformed internal bindings before any driver call.
pub async fn run_catalog_query(
    cx: &Cx,
    conn: &dyn OracleConnection,
    id: CatalogQueryId,
    binds: &[OracleBind],
) -> Result<Vec<OracleRow>, DbError> {
    let spec = id.spec();
    if binds.len() != spec.binds.0.len()
        || !binds.iter().zip(spec.binds.0).all(|(bind, kind)| {
            matches!(
                (bind, kind),
                (OracleBind::String(_), CatalogBindKind::Text)
                    | (
                        OracleBind::String(_) | OracleBind::Null,
                        CatalogBindKind::NullableText
                    )
                    | (OracleBind::I64(_), CatalogBindKind::Integer)
                    | (
                        OracleBind::I64(_) | OracleBind::Null,
                        CatalogBindKind::NullableInteger
                    )
            )
        })
    {
        return Err(DbError::Internal(format!(
            "catalog query {id:?} bind schema mismatch"
        )));
    }
    conn.query_rows(cx, spec.sql, binds).await
}

pub(crate) const SESSION_CONTEXT_SQL: &str = "SELECT SYS_CONTEXT('USERENV', 'SESSION_USER') AS session_user, \
    SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') AS current_schema, \
    SYS_CONTEXT('USERENV', 'CURRENT_EDITION_NAME') AS edition_name FROM dual";
pub(crate) const SESSION_ROLES_SQL: &str = "SELECT role FROM (SELECT role FROM session_roles ORDER BY role) \
    WHERE ROWNUM <= :1";
pub(crate) const OBJECTS_SQL: &str = "SELECT owner, object_name, object_type, object_id, status, edition_name \
    FROM (SELECT owner, object_name, object_type, object_id, status, edition_name \
          FROM all_objects WHERE owner = :1 AND object_name = :2 ORDER BY object_id) \
    WHERE ROWNUM <= :3";
pub(crate) const SYNONYMS_SQL: &str = "SELECT s.owner, s.synonym_name, s.table_owner, s.table_name, s.db_link, \
    o.object_id, o.status, o.edition_name \
    FROM all_synonyms s LEFT JOIN all_objects o \
      ON o.owner = s.owner AND o.object_name = s.synonym_name AND o.object_type = 'SYNONYM' \
    WHERE s.owner = :1 AND s.synonym_name = :2 AND ROWNUM <= :3";
pub(crate) const STANDALONE_ARGUMENTS_SQL: &str = "SELECT subprogram_id, overload, position, data_level, in_out, defaulted, argument_name, data_type \
    FROM (SELECT subprogram_id, overload, position, data_level, in_out, defaulted, argument_name, data_type, sequence \
          FROM all_arguments WHERE owner = :1 AND package_name IS NULL AND object_name = :2 \
          ORDER BY subprogram_id, sequence) WHERE ROWNUM <= :3";
pub(crate) const MEMBER_ARGUMENTS_SQL: &str = "SELECT subprogram_id, overload, position, data_level, in_out, defaulted, argument_name, data_type \
    FROM (SELECT subprogram_id, overload, position, data_level, in_out, defaulted, argument_name, data_type, sequence \
          FROM all_arguments WHERE owner = :1 AND package_name = :2 AND object_name = :3 \
          ORDER BY subprogram_id, sequence) WHERE ROWNUM <= :4";
pub(crate) const STANDALONE_PROCEDURES_SQL: &str = "SELECT subprogram_id, overload \
    FROM (SELECT subprogram_id, overload FROM all_procedures \
          WHERE owner = :1 AND object_name = :2 AND procedure_name IS NULL \
          ORDER BY subprogram_id) WHERE ROWNUM <= :3";
pub(crate) const MEMBER_PROCEDURES_SQL: &str = "SELECT subprogram_id, overload \
    FROM (SELECT subprogram_id, overload FROM all_procedures \
          WHERE owner = :1 AND object_name = :2 AND procedure_name = :3 \
          ORDER BY subprogram_id) WHERE ROWNUM <= :4";
pub(crate) const COLUMN_CONFLICT_SQL: &str = "SELECT owner, table_name, column_name, column_id \
    FROM all_tab_columns WHERE column_name = :1 AND ROWNUM <= :2";
pub(crate) const RELATION_COLUMN_SQL: &str = "SELECT column_name, column_id FROM all_tab_columns \
    WHERE owner = :1 AND table_name = :2 AND column_name = :3 AND ROWNUM <= 2";
pub(crate) const COLUMN_PATH_TYPE_SQL: &str = "SELECT data_type, data_type_owner FROM all_tab_columns \
    WHERE owner = :1 AND table_name = :2 AND column_name = :3 AND ROWNUM <= 2";
pub(crate) const JSON_COLUMN_SQL: &str = "SELECT column_name FROM all_json_columns \
    WHERE owner = :1 AND table_name = :2 AND column_name = :3 AND ROWNUM <= 2";
pub(crate) const JSON_CONSTRAINT_SQL: &str = "SELECT search_condition_vc FROM all_constraints c \
    JOIN all_cons_columns cc ON cc.owner = c.owner AND cc.constraint_name = c.constraint_name \
    WHERE c.owner = :1 AND c.table_name = :2 AND cc.column_name = :3 \
    AND c.constraint_type = 'C' AND c.status = 'ENABLED' AND c.validated = 'VALIDATED' \
    AND ROWNUM <= 65";
pub(crate) const TYPE_ATTRIBUTE_SQL: &str = "SELECT attr_name, attr_type_owner, attr_type_name, attr_type_mod FROM all_type_attrs \
    WHERE owner = :1 AND type_name = :2 AND attr_name = :3 AND ROWNUM <= 2";
pub(crate) const SELECT_POLICY_SQL: &str = "SELECT policy_name FROM all_policies \
    WHERE object_owner = :1 AND object_name = :2 \
    AND enable = 'YES' AND sel = 'YES' AND ROWNUM <= 1";
pub(crate) const ALL_POLICIES_VISIBILITY_SQL: &str =
    "SELECT COUNT(*) AS VISIBLE_POLICY_ROWS FROM (SELECT 1 FROM all_policies WHERE ROWNUM <= 1)";
pub(crate) const POLICY_CATALOG_PROOF_SQL: &str =
    "SELECT policy_name FROM all_policies WHERE ROWNUM <= 1";
pub(crate) const FGA_CATALOG_PROOF_SQL: &str =
    "SELECT policy_name FROM all_audit_policies WHERE ROWNUM <= 1";
pub(crate) const VIRTUAL_COLUMN_SQL: &str = "SELECT column_name FROM all_tab_cols \
    WHERE owner = :1 AND table_name = :2 \
    AND virtual_column = 'YES' AND ROWNUM <= 1";
pub(crate) const TARGET_COLUMN_CATALOG_PROOF_SQL: &str = "SELECT column_name FROM all_tab_cols \
    WHERE owner = :1 AND table_name = :2 AND ROWNUM <= 1";
pub(crate) const POLICY_ROWS_FOR_RELATIONS_32_SQL: &str = "SELECT object_owner, object_name FROM all_policies \
    WHERE enable = 'YES' AND sel = 'YES' \
    AND (object_owner, object_name) IN ((:1, :2), (:3, :4), (:5, :6), (:7, :8), (:9, :10), (:11, :12), (:13, :14), (:15, :16), (:17, :18), (:19, :20), (:21, :22), (:23, :24), (:25, :26), (:27, :28), (:29, :30), (:31, :32), (:33, :34), (:35, :36), (:37, :38), (:39, :40), (:41, :42), (:43, :44), (:45, :46), (:47, :48), (:49, :50), (:51, :52), (:53, :54), (:55, :56), (:57, :58), (:59, :60), (:61, :62), (:63, :64)) AND ROWNUM <= 1";
pub(crate) const FGA_POLICIES_FOR_RELATIONS_32_SQL: &str = "SELECT object_schema, object_name, policy_name, policy_text, pf_schema, pf_package, pf_function, enabled, sel, ins, upd, del \
    FROM (SELECT object_schema, object_name, policy_name, policy_text, pf_schema, pf_package, pf_function, enabled, sel, ins, upd, del \
          FROM all_audit_policies \
          WHERE (object_schema, object_name) IN ((:1, :2), (:3, :4), (:5, :6), (:7, :8), (:9, :10), (:11, :12), (:13, :14), (:15, :16), (:17, :18), (:19, :20), (:21, :22), (:23, :24), (:25, :26), (:27, :28), (:29, :30), (:31, :32), (:33, :34), (:35, :36), (:37, :38), (:39, :40), (:41, :42), (:43, :44), (:45, :46), (:47, :48), (:49, :50), (:51, :52), (:53, :54), (:55, :56), (:57, :58), (:59, :60), (:61, :62), (:63, :64)) \
          ORDER BY object_schema, object_name, policy_name) WHERE ROWNUM <= 257";
pub(crate) const VIRTUAL_COLUMNS_FOR_RELATIONS_32_SQL: &str = "SELECT owner, table_name, column_name, hidden_column, user_generated, data_default FROM all_tab_cols \
    WHERE virtual_column = 'YES' \
    AND (owner, table_name) IN ((:1, :2), (:3, :4), (:5, :6), (:7, :8), (:9, :10), (:11, :12), (:13, :14), (:15, :16), (:17, :18), (:19, :20), (:21, :22), (:23, :24), (:25, :26), (:27, :28), (:29, :30), (:31, :32), (:33, :34), (:35, :36), (:37, :38), (:39, :40), (:41, :42), (:43, :44), (:45, :46), (:47, :48), (:49, :50), (:51, :52), (:53, :54), (:55, :56), (:57, :58), (:59, :60), (:61, :62), (:63, :64)) AND ROWNUM <= 257";
