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

macro_rules! health_invalid_objects_sql {
    ($view:literal) => {
        concat!(
            "SELECT owner, object_type, COUNT(*) AS invalid_count, ",
            "SUBSTR(LISTAGG(object_name, ',') WITHIN GROUP (ORDER BY object_name), 1, 400) AS sample_objects ",
            "FROM ", $view, " WHERE status = 'INVALID' ",
            "GROUP BY owner, object_type ORDER BY invalid_count DESC, owner, object_type"
        )
    };
}

macro_rules! health_unusable_indexes_sql {
    ($view:literal) => {
        concat!(
            "SELECT owner, index_name, table_name, status ",
            "FROM ",
            $view,
            " WHERE status = 'UNUSABLE' ",
            "ORDER BY owner, table_name, index_name"
        )
    };
}

macro_rules! health_sequence_ceiling_sql {
    ($view:literal) => {
        concat!(
            "SELECT sequence_owner, sequence_name, last_number, max_value, increment_by, cycle_flag, ",
            "ROUND((last_number / max_value) * 100, 2) AS pct_consumed ",
            "FROM ", $view, " ",
            "WHERE cycle_flag = 'N' AND max_value > 0 AND last_number >= max_value * 0.9 ",
            "ORDER BY pct_consumed DESC, sequence_owner, sequence_name"
        )
    };
}

macro_rules! health_disabled_constraints_sql {
    ($view:literal) => {
        concat!(
            "SELECT owner, table_name, constraint_name, constraint_type, status, validated ",
            "FROM ",
            $view,
            " ",
            "WHERE status = 'DISABLED' OR validated = 'NOT VALIDATED' ",
            "ORDER BY owner, table_name, constraint_name"
        )
    };
}

macro_rules! health_probe_sql {
    ($view:literal) => {
        concat!("SELECT 1 FROM ", $view, " WHERE 1 = 0")
    };
}

macro_rules! extract_owner_sql {
    ($before:literal, $after:literal) => {
        concat!(
            $before,
            ":1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11, :12, :13, :14, :15, :16, ",
            ":17, :18, :19, :20, :21, :22, :23, :24, :25, :26, :27, :28, :29, :30, :31, :32",
            $after
        )
    };
}

pub(crate) const VPD_RLS_POLICY_BY_SCHEMA_SQL: &str = "SELECT object_owner, object_name, policy_name, \
    pf_owner, package, function, sel, ins, upd, del, enable \
    FROM (SELECT object_owner, object_name, policy_name, pf_owner, package, function, sel, ins, \
                 upd, del, enable \
          FROM all_policies WHERE object_owner = :1 \
          ORDER BY object_owner, object_name, policy_name) \
    WHERE ROWNUM <= :2";

pub(crate) const VPD_RLS_POLICY_BY_OBJECT_SQL: &str = "SELECT object_owner, object_name, policy_name, \
    pf_owner, package, function, sel, ins, upd, del, enable \
    FROM (SELECT object_owner, object_name, policy_name, pf_owner, package, function, sel, ins, \
                 upd, del, enable \
          FROM all_policies WHERE object_owner = :1 AND object_name = :2 \
          ORDER BY object_owner, object_name, policy_name) \
    WHERE ROWNUM <= :3";

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
    /// Detailed column metadata without a default expression on older Oracle releases.
    DescribeColumnsLegacy,
    /// Whether ALL_TAB_COLS exposes DATA_DEFAULT_VC in this database release.
    DescribeDefaultVcProbe,
    /// Constraint and constrained-column metadata for one relation.
    DescribeConstraints,
    /// Visible PL/SQL source types for one object.
    SourceTypes,
    /// Primary-key columns for one table.
    PrimaryKeyColumns,
    /// Output from the diagnostic EXPLAIN PLAN just issued.
    ExplainPlanDisplay,
    /// Optimizer estimates scoped to one server-generated plan statement id.
    PlanCostEstimate,
    /// Current-schema objects that could shadow the standard plan table.
    PlanTableCurrentObjects,
    /// Current-schema private synonyms that could shadow the standard plan table.
    PlanTablePrivateSynonym,
    /// The public PLAN_TABLE synonym target.
    PlanTablePublicSynonym,
    /// SYS.PLAN_TABLE$ temporary-table and object identity evidence.
    PlanTableSysTemporary,
    /// A configured server-owned table's temporary-table and object identity evidence.
    PlanTableConfigured,
    /// Enabled triggers that could run on writes to a configured plan table.
    PlanTableTriggers,
    /// Associated statistics callbacks for one exact object, capped at 256 rows.
    HardParseAssociations,
    /// Index identities and domain index metadata for one exact table.
    HardParseIndexes,
    /// Enabled SELECT VPD policies for one exact table.
    HardParseVpdPolicies,
    /// Enabled Oracle Label Security table policies for one exact table.
    HardParseOlsTablePolicies,
    /// Enabled Oracle Label Security schema policies for one exact owner.
    HardParseOlsSchemaPolicies,
    /// Enabled Real Application Security policies for one exact table.
    HardParseRasPolicies,
    /// Enabled Oracle Data Redaction policies for one exact table.
    HardParseRedactionPolicies,
    /// A visible user-defined operator with the supplied name.
    HardParseOperator,
    /// User-defined SQL types referenced by columns of one exact table.
    HardParseColumnTypes,
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
    /// Invalid objects from the privileged dictionary.
    HealthInvalidObjectsDba,
    /// Invalid objects visible to the session.
    HealthInvalidObjectsAll,
    /// Unusable indexes from the privileged dictionary.
    HealthUnusableIndexesDba,
    /// Unusable indexes visible to the session.
    HealthUnusableIndexesAll,
    /// Tablespace headroom from privileged metrics.
    HealthTablespaceUsage,
    /// Non-cycling sequences near the configured health threshold.
    HealthSequenceCeilingDba,
    /// Visible non-cycling sequences near the configured health threshold.
    HealthSequenceCeilingAll,
    /// Disabled constraints from the privileged dictionary.
    HealthDisabledConstraintsDba,
    /// Disabled constraints visible to the session.
    HealthDisabledConstraintsAll,
    /// Instance buffer cache counters.
    HealthBufferCacheStats,
    /// Zero-row privilege probe for DBA_OBJECTS.
    HealthProbeDbaObjects,
    /// Zero-row privilege probe for ALL_OBJECTS.
    HealthProbeAllObjects,
    /// Zero-row privilege probe for DBA_INDEXES.
    HealthProbeDbaIndexes,
    /// Zero-row privilege probe for ALL_INDEXES.
    HealthProbeAllIndexes,
    /// Zero-row privilege probe for DBA_TABLESPACE_USAGE_METRICS.
    HealthProbeTablespaceUsage,
    /// Zero-row privilege probe for DBA_SEQUENCES.
    HealthProbeDbaSequences,
    /// Zero-row privilege probe for ALL_SEQUENCES.
    HealthProbeAllSequences,
    /// Zero-row privilege probe for DBA_CONSTRAINTS.
    HealthProbeDbaConstraints,
    /// Zero-row privilege probe for ALL_CONSTRAINTS.
    HealthProbeAllConstraints,
    /// Zero-row privilege probe for V$SYSSTAT.
    HealthProbeSysstat,
    /// Column identities and types for one live lineage relation.
    LineageColumns,
    /// Bounded visible VPD policies for one schema, for diagnostic display only.
    VpdRlsPoliciesBySchema,
    /// Bounded visible VPD policies for one relation, for diagnostic display only.
    VpdRlsPoliciesByObject,
    /// Fixed owner-batched catalog snapshot rowsets.
    ExtractObjects,
    /// Snapshot column metadata.
    ExtractColumns,
    /// Snapshot constraint metadata.
    ExtractConstraints,
    /// Snapshot index metadata.
    ExtractIndexes,
    /// Snapshot trigger metadata.
    ExtractTriggers,
    /// Snapshot visible synonyms and PUBLIC synonyms once.
    ExtractSynonyms,
    /// Snapshot routine metadata.
    ExtractRoutines,
    /// Snapshot routine argument metadata.
    ExtractRoutineArguments,
    /// Snapshot view metadata.
    ExtractViews,
    /// Snapshot materialized view metadata.
    ExtractMaterializedViews,
    /// Snapshot sequence metadata.
    ExtractSequences,
    /// Snapshot object type attributes.
    ExtractTypeAttributes,
    /// Snapshot visible users once.
    ExtractUsers,
    /// Snapshot object grants.
    ExtractGrants,
    /// Snapshot database links and PUBLIC links once.
    ExtractDatabaseLinks,
    /// Snapshot table comments.
    ExtractTableComments,
    /// Snapshot column comments.
    ExtractColumnComments,
    /// Snapshot visible editions once.
    ExtractEditions,
    /// Snapshot editioning views.
    ExtractEditioningViews,
    /// Snapshot VPD policy metadata.
    ExtractVpdPolicies,
    /// Snapshot object dependencies.
    ExtractDependencies,
    /// Snapshot PL/Scope availability.
    ExtractPlscopeAvailability,
    /// Snapshot PL/Scope identifiers.
    ExtractPlscopeIdentifiers,
}

/// Typed origin for a query reaching an [`OracleConnection`].
///
/// Caller and server SQL are admitted by the dispatch read executor. Catalog
/// SQL is identified by a closed [`CatalogQueryId`], never by its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadQueryProvenance {
    /// Caller-provided SQL admitted by the semantic read proof.
    CallerRead,
    /// Server-built application SQL admitted by the same semantic proof.
    ServerRead,
    /// Closed server-owned dictionary or diagnostic SQL.
    Catalog(CatalogQueryId),
}

impl CatalogQueryId {
    /// Every query ID, used by exhaustive contract tests.
    pub const ALL: [Self; 148] = [
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
        Self::DescribeColumnsLegacy,
        Self::DescribeDefaultVcProbe,
        Self::DescribeConstraints,
        Self::SourceTypes,
        Self::PrimaryKeyColumns,
        Self::ExplainPlanDisplay,
        Self::PlanCostEstimate,
        Self::PlanTableCurrentObjects,
        Self::PlanTablePrivateSynonym,
        Self::PlanTablePublicSynonym,
        Self::PlanTableSysTemporary,
        Self::PlanTableConfigured,
        Self::PlanTableTriggers,
        Self::HardParseAssociations,
        Self::HardParseIndexes,
        Self::HardParseVpdPolicies,
        Self::HardParseOlsTablePolicies,
        Self::HardParseOlsSchemaPolicies,
        Self::HardParseRasPolicies,
        Self::HardParseRedactionPolicies,
        Self::HardParseOperator,
        Self::HardParseColumnTypes,
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
        Self::HealthInvalidObjectsDba,
        Self::HealthInvalidObjectsAll,
        Self::HealthUnusableIndexesDba,
        Self::HealthUnusableIndexesAll,
        Self::HealthTablespaceUsage,
        Self::HealthSequenceCeilingDba,
        Self::HealthSequenceCeilingAll,
        Self::HealthDisabledConstraintsDba,
        Self::HealthDisabledConstraintsAll,
        Self::HealthBufferCacheStats,
        Self::HealthProbeDbaObjects,
        Self::HealthProbeAllObjects,
        Self::HealthProbeDbaIndexes,
        Self::HealthProbeAllIndexes,
        Self::HealthProbeTablespaceUsage,
        Self::HealthProbeDbaSequences,
        Self::HealthProbeAllSequences,
        Self::HealthProbeDbaConstraints,
        Self::HealthProbeAllConstraints,
        Self::HealthProbeSysstat,
        Self::LineageColumns,
        Self::VpdRlsPoliciesBySchema,
        Self::VpdRlsPoliciesByObject,
        Self::ExtractObjects,
        Self::ExtractColumns,
        Self::ExtractConstraints,
        Self::ExtractIndexes,
        Self::ExtractTriggers,
        Self::ExtractSynonyms,
        Self::ExtractRoutines,
        Self::ExtractRoutineArguments,
        Self::ExtractViews,
        Self::ExtractMaterializedViews,
        Self::ExtractSequences,
        Self::ExtractTypeAttributes,
        Self::ExtractUsers,
        Self::ExtractGrants,
        Self::ExtractDatabaseLinks,
        Self::ExtractTableComments,
        Self::ExtractColumnComments,
        Self::ExtractEditions,
        Self::ExtractEditioningViews,
        Self::ExtractVpdPolicies,
        Self::ExtractDependencies,
        Self::ExtractPlscopeAvailability,
        Self::ExtractPlscopeIdentifiers,
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
        const T: BindSchema = BindSchema(&[Text]);
        const I: BindSchema = BindSchema(&[Integer]);
        const II: BindSchema = BindSchema(&[Integer, Integer]);
        const TT: BindSchema = BindSchema(&[Text, Text]);
        const TI: BindSchema = BindSchema(&[Text, Integer]);
        const TTI: BindSchema = BindSchema(&[Text, Text, Integer]);
        const TTTI: BindSchema = BindSchema(&[Text, Text, Text, Integer]);
        const TTT: BindSchema = BindSchema(&[Text, Text, Text]);
        const T32: BindSchema = BindSchema(&[Text; 64]);
        const OWNER32: BindSchema = BindSchema(&[NullableText; 32]);
        const OWNER32_PUBLIC: BindSchema = BindSchema(&[
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            NullableText,
            Integer,
        ]);
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
                "SELECT column_name, data_type, data_length, nullable, data_default_vc AS data_default, \
                        virtual_column, hidden_column, user_generated \
                 FROM all_tab_cols WHERE owner = :1 AND table_name = :2 \
                 ORDER BY column_id",
                TT,
                "describe relation columns",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::DescribeColumnsLegacy => (
                "SELECT column_name, data_type, data_length, nullable, \
                        CAST(NULL AS VARCHAR2(4000)) AS data_default, \
                        virtual_column, hidden_column, user_generated \
                 FROM all_tab_cols WHERE owner = :1 AND table_name = :2 \
                 ORDER BY column_id",
                TT,
                "describe relation columns without long defaults on older Oracle releases",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::DescribeDefaultVcProbe => (
                "SELECT 1 FROM all_tab_columns \
                 WHERE owner = 'SYS' AND table_name = 'ALL_TAB_COLS' \
                   AND column_name = 'DATA_DEFAULT_VC' AND ROWNUM = 1",
                EMPTY,
                "probe whether ALL_TAB_COLS exposes bounded default text",
                InternalProof,
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
                "SELECT plan_table_output FROM TABLE(DBMS_XPLAN.DISPLAY(:1, :2))",
                TT,
                "read diagnostic plan output for one verified table and statement id",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::PlanCostEstimate => (
                crate::intelligence::PLAN_COST_SQL,
                T,
                "read estimates for one server-generated plan statement id",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::PlanTableCurrentObjects => (
                "SELECT object_type FROM all_objects WHERE owner = :1 AND object_name = 'PLAN_TABLE' AND ROWNUM <= 2",
                T,
                "check current-schema object shadows for PLAN_TABLE",
                InternalProof,
                Diagnostic,
            ),
            Self::PlanTablePrivateSynonym => (
                "SELECT table_owner, table_name, db_link FROM all_synonyms WHERE owner = :1 AND synonym_name = 'PLAN_TABLE' AND ROWNUM <= 2",
                T,
                "check current-schema private synonym shadows for PLAN_TABLE",
                InternalProof,
                Diagnostic,
            ),
            Self::PlanTablePublicSynonym => (
                "SELECT table_owner, table_name, db_link FROM all_synonyms WHERE owner = 'PUBLIC' AND synonym_name = 'PLAN_TABLE' AND ROWNUM <= 2",
                EMPTY,
                "verify the public PLAN_TABLE synonym target",
                InternalProof,
                Diagnostic,
            ),
            Self::PlanTableSysTemporary => (
                "SELECT t.temporary, t.duration, o.object_id FROM all_tables t JOIN all_objects o ON o.owner = t.owner AND o.object_name = t.table_name AND o.object_type = 'TABLE' WHERE t.owner = 'SYS' AND t.table_name = 'PLAN_TABLE$' AND ROWNUM <= 2",
                EMPTY,
                "verify the standard SYS plan table is session-private temporary and identify it",
                InternalProof,
                Diagnostic,
            ),
            Self::PlanTableConfigured => (
                "SELECT t.temporary, t.duration, o.object_id FROM all_tables t JOIN all_objects o ON o.owner = t.owner AND o.object_name = t.table_name AND o.object_type = 'TABLE' WHERE t.owner = :1 AND t.table_name = :2 AND ROWNUM <= 2",
                TT,
                "verify the configured plan table is session-private temporary and identify it",
                InternalProof,
                Diagnostic,
            ),
            Self::PlanTableTriggers => (
                "SELECT trigger_name FROM all_triggers WHERE table_owner = :1 AND table_name = :2 AND status = 'ENABLED' AND ROWNUM <= 1",
                TT,
                "refuse configured plan tables with enabled write triggers",
                InternalProof,
                Diagnostic,
            ),
            Self::HardParseAssociations => (
                "SELECT object_type, column_name, statstype_schema, statstype_name FROM all_associations WHERE object_owner = :1 AND object_name = :2 AND ROWNUM <= :3",
                TTI,
                "discover optimizer statistics callbacks associated with one object",
                InternalProof,
                Diagnostic,
            ),
            Self::HardParseIndexes => (
                "SELECT owner AS index_owner, index_name, index_type, ityp_owner, ityp_name FROM all_indexes WHERE table_owner = :1 AND table_name = :2 AND ROWNUM <= :3",
                TTI,
                "discover indexes and domain index callbacks for one table",
                InternalProof,
                Diagnostic,
            ),
            Self::HardParseVpdPolicies => (
                "SELECT policy_name FROM all_policies WHERE object_owner = :1 AND object_name = :2 AND enable = 'YES' AND sel = 'YES' AND ROWNUM <= :3",
                TTI,
                "discover enabled SELECT VPD policies for one table",
                InternalProof,
                Diagnostic,
            ),
            Self::HardParseOlsTablePolicies => (
                "SELECT policy_name FROM all_sa_table_policies WHERE schema_name = :1 AND table_name = :2 AND status = 'ENABLED' AND ROWNUM <= :3",
                TTI,
                "discover enabled Oracle Label Security table policies",
                InternalProof,
                Diagnostic,
            ),
            Self::HardParseOlsSchemaPolicies => (
                "SELECT policy_name FROM all_sa_schema_policies WHERE schema_name = :1 AND status = 'ENABLED' AND ROWNUM <= :2",
                TI,
                "discover enabled Oracle Label Security schema policies",
                InternalProof,
                Diagnostic,
            ),
            Self::HardParseRasPolicies => (
                "SELECT policy FROM all_xs_applied_policies WHERE schema = :1 AND object = :2 AND status = 'ENABLED' AND sel = 'YES' AND ROWNUM <= :3",
                TTI,
                "discover enabled SELECT Real Application Security policies",
                InternalProof,
                Diagnostic,
            ),
            Self::HardParseRedactionPolicies => (
                "SELECT policy_name FROM redaction_policies WHERE object_owner = :1 AND object_name = :2 AND enable = 'YES' AND ROWNUM <= :3",
                TTI,
                "discover enabled data-redaction policies",
                InternalProof,
                Diagnostic,
            ),
            Self::HardParseOperator => (
                "SELECT operator_name FROM all_operators WHERE operator_name = :1 AND ROWNUM <= :2",
                TI,
                "resolve a user-defined SQL operator before optimizer hard parse",
                InternalProof,
                Diagnostic,
            ),
            Self::HardParseColumnTypes => (
                "SELECT data_type_owner, data_type FROM all_tab_columns WHERE owner = :1 AND table_name = :2 AND data_type_owner IS NOT NULL AND ROWNUM <= :3",
                TTI,
                "discover user-defined SQL types in a referenced table's columns",
                InternalProof,
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
            Self::HealthInvalidObjectsDba => (
                health_invalid_objects_sql!("DBA_OBJECTS"),
                EMPTY,
                "inspect invalid objects in the privileged dictionary",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::HealthInvalidObjectsAll => (
                health_invalid_objects_sql!("ALL_OBJECTS"),
                EMPTY,
                "inspect invalid objects visible to the session",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::HealthUnusableIndexesDba => (
                health_unusable_indexes_sql!("DBA_INDEXES"),
                EMPTY,
                "inspect unusable indexes in the privileged dictionary",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::HealthUnusableIndexesAll => (
                health_unusable_indexes_sql!("ALL_INDEXES"),
                EMPTY,
                "inspect unusable indexes visible to the session",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::HealthTablespaceUsage => (
                "SELECT tablespace_name, ROUND(used_percent, 2) AS used_percent, used_space, tablespace_size \
                 FROM DBA_TABLESPACE_USAGE_METRICS ORDER BY used_percent DESC",
                EMPTY,
                "inspect privileged tablespace headroom",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::HealthSequenceCeilingDba => (
                health_sequence_ceiling_sql!("DBA_SEQUENCES"),
                EMPTY,
                "inspect privileged sequences near the health threshold",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::HealthSequenceCeilingAll => (
                health_sequence_ceiling_sql!("ALL_SEQUENCES"),
                EMPTY,
                "inspect visible sequences near the health threshold",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::HealthDisabledConstraintsDba => (
                health_disabled_constraints_sql!("DBA_CONSTRAINTS"),
                EMPTY,
                "inspect disabled constraints in the privileged dictionary",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::HealthDisabledConstraintsAll => (
                health_disabled_constraints_sql!("ALL_CONSTRAINTS"),
                EMPTY,
                "inspect disabled constraints visible to the session",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::HealthBufferCacheStats => (
                "SELECT name, value FROM V$SYSSTAT \
                 WHERE name IN ('db block gets', 'consistent gets', 'physical reads cache') \
                 ORDER BY name",
                EMPTY,
                "inspect instance buffer cache counters",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::HealthProbeDbaObjects => (
                health_probe_sql!("DBA_OBJECTS"),
                EMPTY,
                "probe privileged object dictionary access",
                InternalProof,
                Diagnostic,
            ),
            Self::HealthProbeAllObjects => (
                health_probe_sql!("ALL_OBJECTS"),
                EMPTY,
                "probe visible object dictionary access",
                InternalProof,
                Diagnostic,
            ),
            Self::HealthProbeDbaIndexes => (
                health_probe_sql!("DBA_INDEXES"),
                EMPTY,
                "probe privileged index dictionary access",
                InternalProof,
                Diagnostic,
            ),
            Self::HealthProbeAllIndexes => (
                health_probe_sql!("ALL_INDEXES"),
                EMPTY,
                "probe visible index dictionary access",
                InternalProof,
                Diagnostic,
            ),
            Self::HealthProbeTablespaceUsage => (
                health_probe_sql!("DBA_TABLESPACE_USAGE_METRICS"),
                EMPTY,
                "probe privileged tablespace metrics access",
                InternalProof,
                Diagnostic,
            ),
            Self::HealthProbeDbaSequences => (
                health_probe_sql!("DBA_SEQUENCES"),
                EMPTY,
                "probe privileged sequence dictionary access",
                InternalProof,
                Diagnostic,
            ),
            Self::HealthProbeAllSequences => (
                health_probe_sql!("ALL_SEQUENCES"),
                EMPTY,
                "probe visible sequence dictionary access",
                InternalProof,
                Diagnostic,
            ),
            Self::HealthProbeDbaConstraints => (
                health_probe_sql!("DBA_CONSTRAINTS"),
                EMPTY,
                "probe privileged constraint dictionary access",
                InternalProof,
                Diagnostic,
            ),
            Self::HealthProbeAllConstraints => (
                health_probe_sql!("ALL_CONSTRAINTS"),
                EMPTY,
                "probe visible constraint dictionary access",
                InternalProof,
                Diagnostic,
            ),
            Self::HealthProbeSysstat => (
                health_probe_sql!("V$SYSSTAT"),
                EMPTY,
                "probe instance statistic access",
                InternalProof,
                Diagnostic,
            ),
            Self::LineageColumns => (
                "SELECT column_name, data_type \
                 FROM all_tab_columns \
                 WHERE owner = :1 AND table_name = :2 \
                 ORDER BY column_id",
                TT,
                "cross-check live lineage columns against the visible dictionary",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::VpdRlsPoliciesBySchema => (
                VPD_RLS_POLICY_BY_SCHEMA_SQL,
                TI,
                "observe bounded visible VPD policies for one schema",
                VisibilityObservation,
                Diagnostic,
            ),
            Self::VpdRlsPoliciesByObject => (
                VPD_RLS_POLICY_BY_OBJECT_SQL,
                TTI,
                "observe bounded visible VPD policies for one relation",
                VisibilityObservation,
                Diagnostic,
            ),
            Self::ExtractObjects => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, object_name, object_type, status,
  to_char(last_ddl_time, 'YYYY-MM-DD"T"HH24:MI:SS') as last_ddl_time_iso,
  editionable, edition_name
from all_objects
where owner in ("#,
                    r#")
  and object_type in ('TABLE', 'VIEW', 'MATERIALIZED VIEW', 'SEQUENCE', 'TYPE',
                      'PACKAGE', 'PROCEDURE', 'FUNCTION', 'TRIGGER', 'EDITIONING VIEW')
order by owner, object_type, object_name"#
                ),
                OWNER32,
                "extract object identities for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractColumns => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, table_name, column_name, nvl(column_id, internal_column_id) as column_position,
  data_type_owner, data_type, data_length, data_precision, data_scale, char_used,
  nullable, data_default_vc, virtual_column, hidden_column
from all_tab_cols
where owner in ("#,
                    r#")
order by owner, table_name, nvl(column_id, internal_column_id)"#
                ),
                OWNER32,
                "extract columns for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractConstraints => (
                extract_owner_sql!(
                    r#"SELECT "
  c.owner, c.constraint_name, c.table_name, c.constraint_type,
  c.r_owner as referenced_table_owner, p.table_name as referenced_table_name,
  c.search_condition_vc,
  case when c.deferrable = 'DEFERRABLE' then 'Y' else 'N' end as is_deferrable,
  case when c.deferred = 'DEFERRED' then 'Y' else 'N' end as is_deferred,
  child.column_name, child.position as column_position,
  parent.column_name as referenced_column_name
from all_constraints c
left join all_constraints p on p.owner = c.r_owner and p.constraint_name = c.r_constraint_name
left join all_cons_columns child on child.owner = c.owner and child.constraint_name = c.constraint_name
left join all_cons_columns parent on parent.owner = p.owner and parent.constraint_name = p.constraint_name
  and parent.position = child.position
where c.owner in ("#,
                    r#")
  and c.constraint_type in ('P', 'R', 'U', 'C', 'F')
order by c.owner, c.constraint_name, child.position"#
                ),
                OWNER32,
                "extract constraints for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractIndexes => (
                extract_owner_sql!(
                    r#"SELECT "
  i.owner, i.index_name, i.table_owner, i.table_name,
  case when i.uniqueness = 'UNIQUE' then 'Y' else 'N' end as is_unique,
  i.index_type, i.status, c.column_name, c.column_position
from all_indexes i
left join all_ind_columns c on c.index_owner = i.owner and c.index_name = i.index_name
  and c.table_owner = i.table_owner and c.table_name = i.table_name
where i.owner in ("#,
                    r#")
order by i.owner, i.index_name, c.column_position"#
                ),
                OWNER32,
                "extract indexes for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractTriggers => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, trigger_name, table_owner, table_name, trigger_type, triggering_event, when_clause
from all_triggers
where owner in ("#,
                    r#") and base_object_type in ('TABLE', 'VIEW')
order by owner, trigger_name"#
                ),
                OWNER32,
                "extract triggers for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractSynonyms => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, synonym_name, table_owner, table_name, db_link
from all_synonyms
where (owner = 'PUBLIC' and :33 = 1)
   or (owner <> 'PUBLIC' and owner in ("#,
                    r#"))
order by owner, synonym_name"#
                ),
                OWNER32_PUBLIC,
                "extract synonyms, including PUBLIC once",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractRoutines => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, object_name, procedure_name, subprogram_id, overload, object_type,
  deterministic, pipelined
from all_procedures
where owner in ("#,
                    r#")
  and (procedure_name is not null or object_type in ('FUNCTION', 'PROCEDURE'))
order by owner, object_name, procedure_name, subprogram_id"#
                ),
                OWNER32,
                "extract routines for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractRoutineArguments => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, package_name, object_name, subprogram_id, overload, argument_name,
  position, sequence, data_type, type_owner, type_name, data_length,
  data_precision, data_scale, in_out, defaulted
from all_arguments
where owner in ("#,
                    r#") and data_level = 0
order by owner, package_name, object_name, subprogram_id, sequence"#
                ),
                OWNER32,
                "extract routine arguments for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractViews => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, view_name, text_vc, read_only
from all_views
where owner in ("#,
                    r#")
order by owner, view_name"#
                ),
                OWNER32,
                "extract views for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractMaterializedViews => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, mview_name, refresh_mode, refresh_method, query
from all_mviews
where owner in ("#,
                    r#")
order by owner, mview_name"#
                ),
                OWNER32,
                "extract materialized views for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractSequences => (
                extract_owner_sql!(
                    r#"SELECT "
  sequence_owner, sequence_name, min_value, max_value, increment_by,
  cycle_flag, order_flag, cache_size
from all_sequences
where sequence_owner in ("#,
                    r#")
order by sequence_owner, sequence_name"#
                ),
                OWNER32,
                "extract sequences for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractTypeAttributes => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, type_name, attr_name, attr_no, attr_type_owner, attr_type_name,
  length, precision, scale
from all_type_attrs
where owner in ("#,
                    r#")
order by owner, type_name, attr_no"#
                ),
                OWNER32,
                "extract type attributes for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractUsers => (
                "SELECT username from all_users order by username",
                EMPTY,
                "extract visible users once",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractGrants => (
                extract_owner_sql!(
                    r#"SELECT "
  table_schema, table_name, grantee, privilege, grantable, hierarchy
from all_tab_privs
where table_schema in ("#,
                    r#")
order by table_schema, table_name, grantee, privilege"#
                ),
                OWNER32,
                "extract grants for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractDatabaseLinks => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, db_link, host
from all_db_links
where (owner = 'PUBLIC' and :33 = 1)
   or (owner <> 'PUBLIC' and owner in ("#,
                    r#"))
order by owner, db_link"#
                ),
                OWNER32_PUBLIC,
                "extract database links, including PUBLIC once",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractTableComments => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, table_name, table_type, comments
from all_tab_comments
where owner in ("#,
                    r#") and comments is not null
order by owner, table_name"#
                ),
                OWNER32,
                "extract table comments for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractColumnComments => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, table_name, column_name, comments
from all_col_comments
where owner in ("#,
                    r#") and comments is not null
order by owner, table_name, column_name"#
                ),
                OWNER32,
                "extract column comments for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractEditions => (
                "SELECT edition_name, parent_edition_name, usable from all_editions order by edition_name",
                EMPTY,
                "extract visible editions once",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractEditioningViews => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, view_name, table_name
from all_editioning_views
where owner in ("#,
                    r#")
order by owner, view_name"#
                ),
                OWNER32,
                "extract editioning views for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractVpdPolicies => (
                extract_owner_sql!(
                    r#"SELECT "
  object_owner, object_name, policy_group, policy_name, pf_owner, package,
  function, sel, ins, upd, del, enable
from all_policies
where object_owner in ("#,
                    r#")
order by object_owner, object_name, policy_group, policy_name"#
                ),
                OWNER32,
                "extract VPD policies for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractDependencies => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, name, type, referenced_owner, referenced_name, referenced_type,
  dependency_type
from all_dependencies
where owner in ("#,
                    r#")
order by owner, name, referenced_owner, referenced_name"#
                ),
                OWNER32,
                "extract dependencies for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractPlscopeAvailability => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, plscope_settings
from all_plsql_object_settings
where owner in ("#,
                    r#")"#
                ),
                OWNER32,
                "extract PL/Scope settings for selected owners",
                DictionaryMetadata,
                Diagnostic,
            ),
            Self::ExtractPlscopeIdentifiers => (
                extract_owner_sql!(
                    r#"SELECT "
  owner, name, type, usage, line, col, object_name
from all_identifiers
where owner in ("#,
                    r#")
order by owner, object_name, line, col"#
                ),
                OWNER32,
                "extract PL/Scope identifiers for selected owners",
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

    /// Choose the fixed describe projection supported by the live data dictionary.
    #[must_use]
    pub(crate) const fn describe_columns_query(has_data_default_vc: bool) -> Self {
        if has_data_default_vc {
            Self::DescribeColumns
        } else {
            Self::DescribeColumnsLegacy
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
    conn.query_rows_with_provenance(cx, spec.sql, binds, ReadQueryProvenance::Catalog(id), None)
        .await
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
