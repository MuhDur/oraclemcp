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
    /// Readability of the target column catalog.
    TargetColumnCatalogProof,
}

impl CatalogQueryId {
    /// Every query ID, used by exhaustive contract tests.
    pub const ALL: [Self; 13] = [
        Self::SessionContext,
        Self::SessionRoles,
        Self::Objects,
        Self::Synonyms,
        Self::StandaloneArguments,
        Self::MemberArguments,
        Self::ColumnConflict,
        Self::RelationColumn,
        Self::SelectPolicy,
        Self::VirtualColumn,
        Self::AllPoliciesVisibility,
        Self::PolicyCatalogProof,
        Self::TargetColumnCatalogProof,
    ];

    /// Return the immutable SQL, bind and handling contract for this ID.
    #[must_use]
    pub const fn spec(self) -> CatalogReadSpec {
        use CatalogAuditClass::{Diagnostic, NameResolution, ReadPurity};
        use CatalogBindKind::{Integer, Text};
        use CatalogOutputPolicy::{InternalProof, SessionContext, VisibilityObservation};
        const EMPTY: BindSchema = BindSchema(&[]);
        const I: BindSchema = BindSchema(&[Integer]);
        const TT: BindSchema = BindSchema(&[Text, Text]);
        const TI: BindSchema = BindSchema(&[Text, Integer]);
        const TTI: BindSchema = BindSchema(&[Text, Text, Integer]);
        const TTTI: BindSchema = BindSchema(&[Text, Text, Text, Integer]);
        const TTT: BindSchema = BindSchema(&[Text, Text, Text]);
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
            Self::TargetColumnCatalogProof => (
                TARGET_COLUMN_CATALOG_PROOF_SQL,
                TT,
                "prove target column catalog is readable",
                InternalProof,
                ReadPurity,
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
pub(crate) const STANDALONE_ARGUMENTS_SQL: &str = "SELECT subprogram_id, overload, position, data_level, in_out, defaulted \
    FROM (SELECT subprogram_id, overload, position, data_level, in_out, defaulted, sequence \
          FROM all_arguments WHERE owner = :1 AND package_name IS NULL AND object_name = :2 \
          ORDER BY subprogram_id, sequence) WHERE ROWNUM <= :3";
pub(crate) const MEMBER_ARGUMENTS_SQL: &str = "SELECT subprogram_id, overload, position, data_level, in_out, defaulted \
    FROM (SELECT subprogram_id, overload, position, data_level, in_out, defaulted, sequence \
          FROM all_arguments WHERE owner = :1 AND package_name = :2 AND object_name = :3 \
          ORDER BY subprogram_id, sequence) WHERE ROWNUM <= :4";
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
pub(crate) const VIRTUAL_COLUMN_SQL: &str = "SELECT column_name FROM all_tab_cols \
    WHERE owner = :1 AND table_name = :2 \
    AND virtual_column = 'YES' AND ROWNUM <= 1";
pub(crate) const TARGET_COLUMN_CATALOG_PROOF_SQL: &str = "SELECT column_name FROM all_tab_cols \
    WHERE owner = :1 AND table_name = :2 AND ROWNUM <= 1";
