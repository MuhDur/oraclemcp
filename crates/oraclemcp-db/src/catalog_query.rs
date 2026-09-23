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
    /// An integral row limit.
    Integer,
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
}

impl CatalogQueryId {
    /// Every query ID, used by exhaustive contract tests.
    pub const ALL: [Self; 36] = [
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
    ];

    /// Return the immutable SQL, bind and handling contract for this ID.
    #[must_use]
    pub const fn spec(self) -> CatalogReadSpec {
        use CatalogAuditClass::{Diagnostic, NameResolution, ReadPurity};
        use CatalogBindKind::{Integer, Text};
        use CatalogOutputPolicy::{
            DictionaryMetadata, InternalProof, SessionContext, VisibilityObservation,
        };
        const EMPTY: BindSchema = BindSchema(&[]);
        const I: BindSchema = BindSchema(&[Integer]);
        const TT: BindSchema = BindSchema(&[Text, Text]);
        const TI: BindSchema = BindSchema(&[Text, Integer]);
        const TTI: BindSchema = BindSchema(&[Text, Text, Integer]);
        const TTTI: BindSchema = BindSchema(&[Text, Text, Text, Integer]);
        const TTT: BindSchema = BindSchema(&[Text, Text, Text]);
        const T32: BindSchema = BindSchema(&[Text; 64]);
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
                "prove no virtual column across bounded relations",
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
                    | (OracleBind::I64(_), CatalogBindKind::Integer)
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
pub(crate) const VIRTUAL_COLUMNS_FOR_RELATIONS_32_SQL: &str = "SELECT owner, table_name, column_name FROM all_tab_cols \
    WHERE virtual_column = 'YES' \
    AND (owner, table_name) IN ((:1, :2), (:3, :4), (:5, :6), (:7, :8), (:9, :10), (:11, :12), (:13, :14), (:15, :16), (:17, :18), (:19, :20), (:21, :22), (:23, :24), (:25, :26), (:27, :28), (:29, :30), (:31, :32), (:33, :34), (:35, :36), (:37, :38), (:39, :40), (:41, :42), (:43, :44), (:45, :46), (:47, :48), (:49, :50), (:51, :52), (:53, :54), (:55, :56), (:57, :58), (:59, :60), (:61, :62), (:63, :64)) AND ROWNUM <= 1";
