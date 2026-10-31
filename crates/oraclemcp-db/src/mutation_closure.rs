//! Bounded collection of the implicit mechanisms of one local DML operation.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write;

use asupersync::Cx;
use oraclemcp_guard::mutation_closure::*;
use oraclemcp_guard::{
    CatalogObjectKind, ResolvedIdentity, ResolvedObject, RoutineEffect, RoutineEffectsV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CatalogQueryId, OracleBind, OracleConnection, OracleRow, RelationSecurityProofError,
    RelationSecurityState, observe_relation_security, read_closure_database_identity,
    run_catalog_query,
};

/// Maximum rows in one complete mechanism-family answer.
pub const MAX_MUTATION_CATALOG_ROWS: usize = 256;
/// Maximum distinct root/cascading operation scopes.
pub const MAX_MUTATION_SCOPES: usize = 64;
/// Maximum mechanisms retained across all scopes.
pub const MAX_MUTATION_MECHANISMS: usize = 2_048;
/// Maximum captured mechanism/catalog and executable-source rows. Snapshot
/// revalidation rereads each bounded answer once and is separately bounded.
pub const MAX_MUTATION_TOTAL_ROWS: usize = 16_384;
/// Maximum combined executable source bytes submitted to the binding.
pub const MAX_MUTATION_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const PROBE_LIMIT: i64 = MAX_MUTATION_CATALOG_ROWS as i64 + 1;

/// A newly discovered root or implicit child mutation, never caller SQL.
#[derive(Clone, Debug)]
pub struct MutationRequest {
    /// Previously resolved, exact local table identity.
    pub target: ResolvedObject,
    /// Operation whose triggers and policy flags apply.
    pub statement_kind: MutationStatementKind,
    /// Exact changed column names, or an explicitly unknown/all column set.
    pub columns: MutationColumns,
}

/// Callback semantics that the effect binding must preserve.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MutationRoutineUse {
    /// A signed, structured package call, including package initialization.
    CustomToolCall,
    /// All declarations, timing sections and handlers of a DML trigger.
    DmlTrigger,
    /// All declarations and handlers of a schema/database DDL trigger.
    DdlTrigger,
    /// Policy-function execution and evaluation of the returned SQL predicate.
    VpdPolicy,
    /// User FGA handler; Oracle invokes it autonomously.
    FgaHandler,
    /// Domain-index implementation callbacks.
    DomainIndex,
    /// A virtual-column or function-index expression.
    ColumnExpression,
    /// A column default, including an identity sequence.
    ColumnDefault,
}

/// Exact bytes and dictionary identity presented to the engine binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MutationRoutineSource {
    /// The requested runtime callback semantics.
    pub use_context: MutationRoutineUse,
    /// Exact dictionary owner, retained in engine identities.
    pub owner: String,
    /// Exact containing object name.
    pub name: String,
    /// Oracle source kind, or EXPRESSION for a stored SQL expression.
    pub object_type: String,
    /// Packaged member or expression identity when applicable.
    pub member: Option<String>,
    /// Exact ALL_PROCEDURES identity when it is a callable member.
    pub subprogram_id: Option<u32>,
    /// Fresh ALL_OBJECTS identity of the source-bearing object.
    pub object_id: u64,
    /// Fresh canonical object modification time.
    pub last_ddl_time: String,
    /// Observed compiler settings, with nonempty conditional flags refused.
    pub compiler_settings: BTreeMap<String, Option<String>>,
    /// Complete scalar column names/types for expression name resolution.
    pub expression_columns: BTreeMap<String, String>,
    /// TABLE or INDEX for the object that owns an EXPRESSION's static bindings.
    pub expression_storage_type: Option<String>,
    /// Full source with every physical line boundary preserved.
    pub source: String,
    /// SHA-256 of exactly the submitted source bytes.
    pub source_sha256: String,
    /// Number of dictionary source lines, for the caller's total budget.
    pub source_line_count: usize,
}

/// An engine proof must bind the supplied bytes and the complete call closure.
#[derive(Clone, Debug)]
pub struct MutationRoutineProof {
    /// Must equal the submitted callback semantics, including predicate evaluation.
    pub use_context: MutationRoutineUse,
    /// Must equal the submitted source hash.
    pub source_sha256: String,
    /// Canonical hash binding the complete call closure and catalog facts.
    pub closure_fingerprint: String,
    /// Complete W7 effects; Unknown never supplies execution authority.
    pub effects: RoutineEffectsV1,
    /// Every DML operation performed by that call closure, for recursive collection.
    pub mutations: Vec<MutationRequest>,
}

/// Consumer-side engine binding. The DB crate never depends on the PL/SQL engine.
#[async_trait::async_trait(?Send)]
pub trait MutationEffectOracle {
    /// Prove all runtime effects of the fresh source, or return typed uncertainty.
    async fn prove_source(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
        source: &MutationRoutineSource,
    ) -> Result<MutationRoutineProof, MutationUnavailableReason>;
}

/// Explicit engine-free fallback; it supplies no effect authority.
pub struct UnknownMutationEffects;

#[async_trait::async_trait(?Send)]
impl MutationEffectOracle for UnknownMutationEffects {
    async fn prove_source(
        &self,
        _cx: &Cx,
        _conn: &dyn OracleConnection,
        _source: &MutationRoutineSource,
    ) -> Result<MutationRoutineProof, MutationUnavailableReason> {
        Err(MutationUnavailableReason::EffectProofUnavailable)
    }
}

fn digest(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

fn encoded<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("catalog evidence contains serializable values")
}

fn rows_digest(rows: &[OracleRow]) -> String {
    let mut canonical: Vec<Vec<u8>> = rows
        .iter()
        .map(|row| {
            let cells: BTreeMap<_, _> = row
                .columns
                .iter()
                .map(|(name, cell)| {
                    (
                        name.clone(),
                        (
                            serde_json::to_value(cell).expect("cell serialization"),
                            cell.source_length,
                        ),
                    )
                })
                .collect();
            encoded(&cells)
        })
        .collect();
    canonical.sort();
    digest(&encoded(&canonical))
}

pub(crate) fn required<'a>(
    row: &'a OracleRow,
    column: &str,
) -> Result<&'a str, MutationUnavailableReason> {
    row.text(column)
        .filter(|value| !value.is_empty())
        .ok_or(MutationUnavailableReason::CatalogIncomplete)
}

pub(crate) fn optional(
    row: &OracleRow,
    column: &str,
) -> Result<Option<String>, MutationUnavailableReason> {
    let cell = row
        .cell(column)
        .ok_or(MutationUnavailableReason::CatalogIncomplete)?;
    if cell.bytes.is_some()
        || cell.structured.is_some()
        || cell.structured_contract_version.is_some()
        || cell.nested_result.is_some()
        || cell.source_length.is_some_and(|length| {
            length
                > cell
                    .value
                    .as_deref()
                    .map_or(0, |value| value.chars().count())
        })
    {
        return Err(MutationUnavailableReason::CatalogIncomplete);
    }
    Ok(cell.value.clone())
}

pub(crate) fn flag(row: &OracleRow, column: &str) -> Result<bool, MutationUnavailableReason> {
    match required(row, column)? {
        "YES" => Ok(true),
        "NO" => Ok(false),
        _ => Err(MutationUnavailableReason::CatalogIncomplete),
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn target_identity(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    expected_id: Option<u64>,
) -> Result<(MutationTarget, Vec<OracleRow>), MutationUnavailableReason> {
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::MutationTarget,
        &[owner.into(), name.into(), 2_i64.into()],
    )
    .await
    .map_err(|_| MutationUnavailableReason::CatalogUnreadable)?;
    let [row] = rows.as_slice() else {
        return Err(MutationUnavailableReason::IdentityMismatch);
    };
    let id = row
        .parse_i64("OBJECT_ID")
        .and_then(|id| u64::try_from(id).ok())
        .filter(|id| *id != 0)
        .ok_or(MutationUnavailableReason::IdentityMismatch)?;
    if required(row, "OWNER")? != owner
        || required(row, "OBJECT_NAME")? != name
        || required(row, "STATUS")? != "VALID"
        || expected_id.is_some_and(|expected| expected != id)
    {
        return Err(MutationUnavailableReason::IdentityMismatch);
    }
    Ok((
        MutationTarget {
            owner: owner.into(),
            name: name.into(),
            object_id: id,
            object_edition: optional(row, "EDITION_NAME")?,
            last_ddl_time: required(row, "LAST_DDL_TIME")?.into(),
        },
        rows,
    ))
}

/// Dictionary facts that decide whether a scoped grant may target this table:
/// its exact local identity plus partitioning, organization, clustering,
/// temporary and external kind. Object and XMLType tables are absent from
/// `ALL_TABLES` and refuse; an identity that moves between the two reads is
/// uncertainty. The table is resolved locally by name, so it is never remote.
pub async fn read_grant_target_facts(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
) -> Result<oraclemcp_guard::scoped_grant::admission::GrantTargetFacts, MutationUnavailableReason> {
    let (target, _) = target_identity(cx, conn, owner, name, None).await?;
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::GrantTargetTable,
        &[owner.into(), name.into(), 2_i64.into()],
    )
    .await
    .map_err(|_| MutationUnavailableReason::CatalogUnreadable)?;
    let [row] = rows.as_slice() else {
        return Err(MutationUnavailableReason::IdentityMismatch);
    };
    if required(row, "OWNER")? != owner || required(row, "TABLE_NAME")? != name {
        return Err(MutationUnavailableReason::IdentityMismatch);
    }
    let partitioned = match required(row, "PARTITIONED")?.trim_end() {
        "YES" => true,
        "NO" => false,
        _ => return Err(MutationUnavailableReason::CatalogIncomplete),
    };
    let temporary = match required(row, "TEMPORARY")?.trim_end() {
        "Y" => true,
        "N" => false,
        _ => return Err(MutationUnavailableReason::CatalogIncomplete),
    };
    let external = row
        .parse_i64("EXTERNAL_COUNT")
        .ok_or(MutationUnavailableReason::CatalogIncomplete)?
        != 0;
    let facts = oraclemcp_guard::scoped_grant::admission::GrantTargetFacts {
        target,
        partitioned,
        index_organized: optional(row, "IOT_TYPE")?.is_some_and(|value| !value.trim().is_empty()),
        clustered: optional(row, "CLUSTER_NAME")?.is_some_and(|value| !value.trim().is_empty()),
        temporary,
        external,
        remote: false,
    };
    let (fresh, _) = target_identity(cx, conn, owner, name, Some(facts.target.object_id)).await?;
    if fresh != facts.target {
        return Err(MutationUnavailableReason::EffectSourceMismatch);
    }
    Ok(facts)
}

fn resolved_target(target: &MutationTarget) -> ResolvedObject {
    ResolvedObject {
        owner: target.owner.clone(),
        name: target.name.clone(),
        kind: CatalogObjectKind::Table,
        container: None,
        member: None,
        overloads: Vec::new(),
        quote_exact: true,
        synonym_chain: Vec::new(),
        db_link: None,
        identity: ResolvedIdentity {
            object_id: target.object_id,
            edition: target.object_edition.clone(),
        },
    }
}

struct Collector<'a> {
    cx: &'a Cx,
    conn: &'a dyn OracleConnection,
    oracle: &'a dyn MutationEffectOracle,
    closure: MutationEffectClosureV1,
    queue: VecDeque<MutationRequest>,
    visited: BTreeSet<Vec<u8>>,
    total_rows: usize,
    source_bytes: usize,
    snapshots: Vec<(
        MutationRelationScope,
        CatalogQueryId,
        MutationCatalogSource,
        String,
    )>,
}

impl Collector<'_> {
    async fn collect_scope(&mut self, scope: &MutationRelationScope, target: &ResolvedObject) {
        let columns = match self.columns(scope).await {
            Ok(columns) => columns,
            Err(reason) => {
                self.unavailable_source(scope, MutationCatalogSource::VirtualColumns, reason);
                BTreeMap::new()
            }
        };
        for (source, result) in [
            (MutationCatalogSource::Triggers, self.triggers(scope).await),
            (
                MutationCatalogSource::IncomingForeignKeys,
                self.foreign_keys(scope).await,
            ),
            (
                MutationCatalogSource::Indexes,
                self.indexes(scope, &columns).await,
            ),
            (MutationCatalogSource::VpdPolicies, self.vpd(scope).await),
            (MutationCatalogSource::FgaPolicies, self.fga(scope).await),
            (
                MutationCatalogSource::MaterializedViewLogs,
                self.mv_logs(scope).await,
            ),
        ] {
            if let Err(reason) = result {
                self.unavailable_source(scope, source, reason);
            }
        }
        self.security(scope, target).await;
    }

    fn record_identity(&mut self, scope: &MutationRelationScope, rows: &[OracleRow]) {
        let fingerprint = rows_digest(rows);
        self.closure.observations.push(MutationCatalogObservation {
            scope: scope.clone(),
            source: MutationCatalogSource::Identity,
            computation: MutationComputation::Computed,
            source_sha256: Some(fingerprint.clone()),
            row_count: 1,
        });
        self.snapshots.push((
            scope.clone(),
            CatalogQueryId::MutationTarget,
            MutationCatalogSource::Identity,
            fingerprint,
        ));
    }
    async fn indexes(
        &mut self,
        scope: &MutationRelationScope,
        columns: &BTreeMap<String, String>,
    ) -> Result<(), MutationUnavailableReason> {
        let rows = self
            .rows(
                scope,
                MutationCatalogSource::Indexes,
                CatalogQueryId::MutationIndexes,
            )
            .await?;
        let expressions = self
            .rows(
                scope,
                MutationCatalogSource::IndexExpressions,
                CatalogQueryId::MutationIndexExpressions,
            )
            .await?;
        let mut known = BTreeSet::new();
        let mut function_based = BTreeSet::new();
        for row in &rows {
            if required(row, "TABLE_OWNER")? != scope.target.owner
                || required(row, "TABLE_NAME")? != scope.target.name
            {
                return Err(MutationUnavailableReason::IdentityMismatch);
            }
            let owner = required(row, "INDEX_OWNER")?;
            let name = required(row, "INDEX_NAME")?;
            if !known.insert((owner.to_owned(), name.to_owned())) {
                return Err(MutationUnavailableReason::CatalogIncomplete);
            }
            let kind = required(row, "INDEX_TYPE")?;
            if !matches!(
                kind,
                "BITMAP"
                    | "CLUSTER"
                    | "DOMAIN"
                    | "FUNCTION-BASED BITMAP"
                    | "FUNCTION-BASED DOMAIN"
                    | "FUNCTION-BASED NORMAL"
                    | "FUNCTION-BASED NORMAL/REV"
                    | "IOT - TOP"
                    | "LOB"
                    | "NORMAL"
                    | "NORMAL/REV"
            ) {
                return Err(MutationUnavailableReason::UnsupportedMechanism);
            }
            if !matches!(required(row, "STATUS")?, "VALID" | "UNUSABLE" | "N/A") {
                return Err(MutationUnavailableReason::CatalogIncomplete);
            }
            flag(row, "PARTITIONED")?;
            if flag(row, "JOIN_INDEX")? {
                return Err(MutationUnavailableReason::UnsupportedMechanism);
            }
            let domain = kind.contains("DOMAIN");
            let mut fact = Self::fact(
                scope,
                row,
                owner,
                name,
                MutationMechanism::IndexCallback { domain },
            );
            if kind.starts_with("FUNCTION-BASED") {
                function_based.insert((owner.to_owned(), name.to_owned()));
                match optional(row, "FUNCIDX_STATUS")?.as_deref() {
                    Some("ENABLED" | "DISABLED") => {}
                    _ => return Err(MutationUnavailableReason::CatalogIncomplete),
                }
            } else if optional(row, "FUNCIDX_STATUS")?.is_some() {
                return Err(MutationUnavailableReason::CatalogIncomplete);
            }
            if !domain {
                if optional(row, "ITYP_OWNER")?.is_some()
                    || optional(row, "ITYP_NAME")?.is_some()
                    || optional(row, "DOMIDX_STATUS")?.is_some()
                    || optional(row, "DOMIDX_OPSTATUS")?.is_some()
                {
                    return Err(MutationUnavailableReason::CatalogIncomplete);
                }
                fact.effects = RoutineEffectsV1::new([RoutineEffect::Dml]);
                self.add(fact);
                continue;
            }
            if required(row, "DOMIDX_STATUS")? != "VALID"
                || required(row, "DOMIDX_OPSTATUS")? != "VALID"
            {
                return Err(MutationUnavailableReason::SourceUnavailable);
            }
            let type_owner = required(row, "ITYP_OWNER")?;
            let type_name = required(row, "ITYP_NAME")?;
            let implementation = run_catalog_query(
                self.cx,
                self.conn,
                CatalogQueryId::MutationIndexImplementation,
                &[type_owner.into(), type_name.into(), 2_i64.into()],
            )
            .await
            .map_err(|_| MutationUnavailableReason::CatalogUnreadable)?;
            let [implementation] = implementation.as_slice() else {
                return Err(MutationUnavailableReason::CatalogIncomplete);
            };
            if required(implementation, "OWNER")? != type_owner
                || required(implementation, "INDEXTYPE_NAME")? != type_name
            {
                return Err(MutationUnavailableReason::IdentityMismatch);
            }
            fact.metadata_sha256 = digest(&encoded(&(
                rows_digest(std::slice::from_ref(row)),
                rows_digest(std::slice::from_ref(implementation)),
            )));
            self.user_fact(
                fact,
                required(implementation, "IMPLEMENTATION_SCHEMA")?,
                required(implementation, "IMPLEMENTATION_NAME")?,
                "TYPE BODY",
                None,
            )
            .await;
        }
        let mut seen_expressions = BTreeSet::new();
        for row in &expressions {
            if required(row, "TABLE_OWNER")? != scope.target.owner
                || required(row, "TABLE_NAME")? != scope.target.name
            {
                return Err(MutationUnavailableReason::IdentityMismatch);
            }
            let owner = required(row, "INDEX_OWNER")?;
            let name = required(row, "INDEX_NAME")?;
            if !function_based.contains(&(owner.to_owned(), name.to_owned())) {
                return Err(MutationUnavailableReason::CatalogIncomplete);
            }
            let position = row
                .parse_i64("COLUMN_POSITION")
                .and_then(|position| u32::try_from(position).ok())
                .filter(|position| *position != 0)
                .ok_or(MutationUnavailableReason::CatalogIncomplete)?;
            if !seen_expressions.insert((owner.to_owned(), name.to_owned(), position)) {
                return Err(MutationUnavailableReason::CatalogIncomplete);
            }
            let expression = required(row, "COLUMN_EXPRESSION")?;
            let fact = Self::fact(
                scope,
                row,
                owner,
                name,
                MutationMechanism::FunctionBasedIndex { position },
            );
            self.expression_fact(fact, expression, columns).await;
        }
        if function_based.iter().any(|(owner, name)| {
            !seen_expressions
                .iter()
                .any(|(o, n, _)| o == owner && n == name)
        }) {
            return Err(MutationUnavailableReason::SourceUnavailable);
        }
        Ok(())
    }

    async fn vpd(
        &mut self,
        scope: &MutationRelationScope,
    ) -> Result<(), MutationUnavailableReason> {
        let rows = self
            .rows(
                scope,
                MutationCatalogSource::VpdPolicies,
                CatalogQueryId::MutationVpdPolicies,
            )
            .await?;
        for row in &rows {
            if required(row, "OBJECT_OWNER")? != scope.target.owner
                || required(row, "OBJECT_NAME")? != scope.target.name
            {
                return Err(MutationUnavailableReason::IdentityMismatch);
            }
            if !flag(row, "ENABLE")? {
                continue;
            }
            let mut statement_types = BTreeSet::new();
            for (column, kind) in [
                ("INS", MutationStatementKind::Insert),
                ("UPD", MutationStatementKind::Update),
                ("DEL", MutationStatementKind::Delete),
            ] {
                if flag(row, column)? {
                    statement_types.insert(kind);
                }
            }
            flag(row, "SEL")?;
            flag(row, "IDX")?;
            if scope.statement_kind != MutationStatementKind::Merge
                && !statement_types.contains(&scope.statement_kind)
            {
                continue;
            }
            if statement_types.is_empty() {
                continue;
            }
            let check_option = flag(row, "CHK_OPTION")?;
            optional(row, "POLICY_GROUP")?;
            required(row, "POLICY_TYPE")?;
            let name = required(row, "POLICY_NAME")?;
            let function_owner = required(row, "PF_OWNER")?;
            let function = required(row, "PF_FUNCTION")?;
            let package = optional(row, "PF_PACKAGE")?;
            let fact = Self::fact(
                scope,
                row,
                &scope.target.owner,
                name,
                MutationMechanism::VpdPolicy {
                    statement_types,
                    check_option,
                },
            );
            self.user_fact(
                fact,
                function_owner,
                package.as_deref().unwrap_or(function),
                if package.is_some() {
                    "PACKAGE BODY"
                } else {
                    "FUNCTION"
                },
                package.as_ref().map(|_| function),
            )
            .await;
        }
        Ok(())
    }

    async fn fga(
        &mut self,
        scope: &MutationRelationScope,
    ) -> Result<(), MutationUnavailableReason> {
        let rows = self
            .rows(
                scope,
                MutationCatalogSource::FgaPolicies,
                CatalogQueryId::MutationFgaPolicies,
            )
            .await?;
        for row in &rows {
            if required(row, "OBJECT_SCHEMA")? != scope.target.owner
                || required(row, "OBJECT_NAME")? != scope.target.name
            {
                return Err(MutationUnavailableReason::IdentityMismatch);
            }
            if !flag(row, "ENABLED")? {
                continue;
            }
            let applies = match scope.statement_kind {
                MutationStatementKind::Insert => flag(row, "INS")?,
                MutationStatementKind::Update => flag(row, "UPD")?,
                MutationStatementKind::Delete => flag(row, "DEL")?,
                MutationStatementKind::Merge => {
                    flag(row, "INS")? || flag(row, "UPD")? || flag(row, "DEL")?
                }
            };
            if !applies {
                continue;
            }
            let condition = optional(row, "POLICY_TEXT")?;
            if condition
                .as_deref()
                .is_some_and(|text| !matches!(text.trim(), "1=1" | "1 = 1"))
            {
                return Err(MutationUnavailableReason::EffectProofUnavailable);
            }
            let owner = optional(row, "PF_SCHEMA")?;
            let package = optional(row, "PF_PACKAGE")?;
            let function = optional(row, "PF_FUNCTION")?;
            match (owner, package, function) {
                (None, None, None) => {}
                (Some(owner), package, Some(function)) => {
                    let mut fact = Self::fact(
                        scope,
                        row,
                        &scope.target.owner,
                        required(row, "POLICY_NAME")?,
                        MutationMechanism::FgaHandler,
                    );
                    // T1.9: Oracle invokes a user FGA handler in an autonomous transaction.
                    fact.effects = RoutineEffectsV1::new([RoutineEffect::Autonomous]);
                    self.user_fact(
                        fact,
                        &owner,
                        package.as_deref().unwrap_or(&function),
                        if package.is_some() {
                            "PACKAGE BODY"
                        } else {
                            "PROCEDURE"
                        },
                        package.as_ref().map(|_| function.as_str()),
                    )
                    .await;
                }
                _ => return Err(MutationUnavailableReason::CatalogIncomplete),
            }
        }
        Ok(())
    }

    async fn foreign_keys(
        &mut self,
        scope: &MutationRelationScope,
    ) -> Result<(), MutationUnavailableReason> {
        let rows = self
            .rows(
                scope,
                MutationCatalogSource::IncomingForeignKeys,
                CatalogQueryId::MutationForeignKeys,
            )
            .await?;
        let mut grouped: BTreeMap<(String, String, String), Vec<&OracleRow>> = BTreeMap::new();
        for row in &rows {
            if required(row, "PARENT_OWNER")? != scope.target.owner
                || required(row, "PARENT_TABLE")? != scope.target.name
            {
                return Err(MutationUnavailableReason::IdentityMismatch);
            }
            match required(row, "STATUS")? {
                "DISABLED" => continue,
                "ENABLED" => {}
                _ => return Err(MutationUnavailableReason::CatalogIncomplete),
            }
            grouped
                .entry((
                    required(row, "FK_OWNER")?.into(),
                    required(row, "CONSTRAINT_NAME")?.into(),
                    required(row, "CHILD_TABLE")?.into(),
                ))
                .or_default()
                .push(row);
        }
        if scope.statement_kind == MutationStatementKind::Insert {
            return Ok(());
        }
        for ((owner, name, table), group) in grouped {
            let mut child_columns = BTreeSet::new();
            let mut parent_columns = BTreeSet::new();
            let mut positions = BTreeSet::new();
            let rule = required(group[0], "DELETE_RULE")?;
            for row in &group {
                if required(row, "DELETE_RULE")? != rule {
                    return Err(MutationUnavailableReason::CatalogIncomplete);
                }
                child_columns.insert(required(row, "CHILD_COLUMN")?.to_owned());
                parent_columns.insert(required(row, "PARENT_COLUMN")?.to_owned());
                positions.insert(
                    row.parse_i64("POSITION")
                        .ok_or(MutationUnavailableReason::CatalogIncomplete)?,
                );
            }
            if positions.len() != group.len()
                || child_columns.len() != group.len()
                || parent_columns.len() != group.len()
                || positions
                    .iter()
                    .copied()
                    .ne(1..=i64::try_from(group.len()).expect("row cap fits i64"))
            {
                return Err(MutationUnavailableReason::CatalogIncomplete);
            }
            if scope.statement_kind == MutationStatementKind::Update
                && matches!(&scope.columns, MutationColumns::Named(changed) if changed.is_disjoint(&parent_columns))
            {
                continue;
            }
            let on_delete = match rule {
                "NO ACTION" => MutationForeignKeyAction::NoAction,
                "CASCADE" => MutationForeignKeyAction::Cascade,
                "SET NULL" => MutationForeignKeyAction::SetNull,
                _ => return Err(MutationUnavailableReason::UnsupportedMechanism),
            };
            let mut fact = Self::fact(
                scope,
                group[0],
                &owner,
                &name,
                MutationMechanism::ForeignKeyAction {
                    on_delete,
                    child_owner: owner.clone(),
                    child_table: table.clone(),
                    child_columns: child_columns.clone(),
                },
            );
            let group_rows: Vec<_> = group.into_iter().cloned().collect();
            fact.metadata_sha256 = rows_digest(&group_rows);
            fact.source_sha256 = Some(rows_digest(&group_rows));
            fact.effects = RoutineEffectsV1::new([RoutineEffect::ReadDb]);
            if matches!(
                scope.statement_kind,
                MutationStatementKind::Delete | MutationStatementKind::Merge
            ) && on_delete != MutationForeignKeyAction::NoAction
            {
                match target_identity(self.cx, self.conn, &owner, &table, None).await {
                    Ok((target, _)) => {
                        self.queue.push_back(MutationRequest {
                            target: resolved_target(&target),
                            statement_kind: if on_delete == MutationForeignKeyAction::Cascade {
                                MutationStatementKind::Delete
                            } else {
                                MutationStatementKind::Update
                            },
                            columns: if on_delete == MutationForeignKeyAction::Cascade {
                                MutationColumns::All
                            } else {
                                MutationColumns::Named(child_columns)
                            },
                        });
                        fact.effects =
                            RoutineEffectsV1::new([RoutineEffect::ReadDb, RoutineEffect::Dml]);
                    }
                    Err(reason) => fact.computation = MutationComputation::Unavailable { reason },
                }
            }
            self.add(fact);
        }
        Ok(())
    }

    async fn expression_fact(
        &mut self,
        mut fact: MutationMechanismFact,
        expression: &str,
        columns: &BTreeMap<String, String>,
    ) {
        let (owner, name, storage_type, object_id, last_ddl_time) =
            if matches!(fact.mechanism, MutationMechanism::FunctionBasedIndex { .. }) {
                let result = run_catalog_query(
                    self.cx,
                    self.conn,
                    CatalogQueryId::ClosureMemberObject,
                    &[
                        fact.owner.as_str().into(),
                        fact.name.as_str().into(),
                        "INDEX".into(),
                        2_i64.into(),
                    ],
                )
                .await;
                let identity = result
                    .map_err(|_| MutationUnavailableReason::SourceUnavailable)
                    .and_then(|rows| {
                        let [row] = rows.as_slice() else {
                            return Err(MutationUnavailableReason::SourceUnavailable);
                        };
                        if required(row, "STATUS")? != "VALID" {
                            return Err(MutationUnavailableReason::SourceUnavailable);
                        }
                        let id = row
                            .parse_i64("OBJECT_ID")
                            .and_then(|id| u64::try_from(id).ok())
                            .filter(|id| *id != 0)
                            .ok_or(MutationUnavailableReason::IdentityMismatch)?;
                        Ok((id, required(row, "LAST_DDL_TIME")?.to_owned()))
                    });
                let (id, ddl) = match identity {
                    Ok(identity) => identity,
                    Err(reason) => {
                        fact.computation = MutationComputation::Unavailable { reason };
                        self.add(fact);
                        return;
                    }
                };
                (fact.owner.clone(), fact.name.clone(), "INDEX", id, ddl)
            } else {
                (
                    fact.scope.target.owner.clone(),
                    fact.scope.target.name.clone(),
                    "TABLE",
                    fact.scope.target.object_id,
                    fact.scope.target.last_ddl_time.clone(),
                )
            };
        let source = MutationRoutineSource {
            use_context: if matches!(fact.mechanism, MutationMechanism::ColumnDefaultExpr { .. }) {
                MutationRoutineUse::ColumnDefault
            } else {
                MutationRoutineUse::ColumnExpression
            },
            owner,
            name,
            object_type: "EXPRESSION".into(),
            member: Some(fact.name.clone()),
            subprogram_id: None,
            object_id,
            last_ddl_time,
            compiler_settings: BTreeMap::new(),
            expression_columns: columns.clone(),
            expression_storage_type: Some(storage_type.into()),
            source: expression.into(),
            source_sha256: digest(expression.as_bytes()),
            source_line_count: 0,
        };
        self.prove(&mut fact, source).await;
        self.add(fact);
    }

    async fn columns(
        &mut self,
        scope: &MutationRelationScope,
    ) -> Result<BTreeMap<String, String>, MutationUnavailableReason> {
        let rows = self
            .rows(
                scope,
                MutationCatalogSource::VirtualColumns,
                CatalogQueryId::MutationColumns,
            )
            .await?;
        if rows.is_empty() {
            return Err(MutationUnavailableReason::CatalogIncomplete);
        }
        let mut columns = BTreeMap::new();
        for row in &rows {
            if required(row, "OWNER")? != scope.target.owner
                || required(row, "TABLE_NAME")? != scope.target.name
            {
                return Err(MutationUnavailableReason::IdentityMismatch);
            }
            if optional(row, "DATA_TYPE_OWNER")?.is_some() {
                return Err(MutationUnavailableReason::UnsupportedMechanism);
            }
            if columns
                .insert(
                    required(row, "COLUMN_NAME")?.into(),
                    required(row, "DATA_TYPE")?.into(),
                )
                .is_some()
            {
                return Err(MutationUnavailableReason::CatalogIncomplete);
            }
        }
        if matches!(&scope.columns, MutationColumns::Named(changed) if !changed.iter().all(|column| columns.contains_key(column)))
        {
            return Err(MutationUnavailableReason::InvalidInput);
        }
        for row in &rows {
            let column = required(row, "COLUMN_NAME")?;
            let is_virtual = flag(row, "VIRTUAL_COLUMN")?;
            flag(row, "HIDDEN_COLUMN")?;
            flag(row, "USER_GENERATED")?;
            let expression = optional(row, "DATA_DEFAULT")?;
            let Some(expression) = expression else {
                let length = optional(row, "DEFAULT_LENGTH")?;
                if is_virtual
                    || length
                        .as_deref()
                        .is_some_and(|value| value.parse::<usize>() != Ok(0))
                {
                    return Err(MutationUnavailableReason::SourceUnavailable);
                }
                continue;
            };
            if row
                .parse_i64("DEFAULT_LENGTH")
                .and_then(|length| usize::try_from(length).ok())
                != Some(expression.len())
            {
                return Err(MutationUnavailableReason::SourceUnavailable);
            }
            let applies = is_virtual
                || match scope.statement_kind {
                    MutationStatementKind::Insert | MutationStatementKind::Merge => true,
                    MutationStatementKind::Update => match &scope.columns {
                        MutationColumns::All => true,
                        MutationColumns::Named(changed) => changed.contains(column),
                    },
                    MutationStatementKind::Delete => false,
                };
            if !applies {
                continue;
            }
            let mechanism = if is_virtual {
                MutationMechanism::VirtualColumnExpr {
                    column: column.into(),
                }
            } else {
                MutationMechanism::ColumnDefaultExpr {
                    column: column.into(),
                }
            };
            let fact = Self::fact(scope, row, &scope.target.owner, column, mechanism);
            self.expression_fact(fact, &expression, &columns).await;
        }
        Ok(columns)
    }

    async fn triggers(
        &mut self,
        scope: &MutationRelationScope,
    ) -> Result<(), MutationUnavailableReason> {
        let triggers = self
            .rows(
                scope,
                MutationCatalogSource::Triggers,
                CatalogQueryId::MutationTriggers,
            )
            .await?;
        let columns = self
            .rows(
                scope,
                MutationCatalogSource::TriggerColumns,
                CatalogQueryId::MutationTriggerColumns,
            )
            .await?;
        let mut listed: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        for row in &columns {
            if required(row, "TABLE_OWNER")? != scope.target.owner
                || required(row, "TABLE_NAME")? != scope.target.name
            {
                return Err(MutationUnavailableReason::IdentityMismatch);
            }
            let owner = required(row, "TRIGGER_OWNER")?.to_owned();
            let name = required(row, "TRIGGER_NAME")?.to_owned();
            if flag(row, "COLUMN_LIST")? {
                listed
                    .entry((owner, name))
                    .or_default()
                    .insert(required(row, "COLUMN_NAME")?.to_owned());
            }
        }
        for row in &triggers {
            if required(row, "TABLE_OWNER")? != scope.target.owner
                || required(row, "TABLE_NAME")? != scope.target.name
            {
                return Err(MutationUnavailableReason::IdentityMismatch);
            }
            match required(row, "STATUS")? {
                "DISABLED" => continue,
                "ENABLED" => {}
                _ => return Err(MutationUnavailableReason::CatalogIncomplete),
            }
            if required(row, "BASE_OBJECT_TYPE")? != "TABLE"
                || optional(row, "COLUMN_NAME")?.is_some()
                || required(row, "ACTION_TYPE")?.trim_end_matches(' ') != "PL/SQL"
                || optional(row, "WHEN_CLAUSE")?.is_some()
            {
                return Err(MutationUnavailableReason::UnsupportedMechanism);
            }
            let events: BTreeSet<_> = required(row, "TRIGGERING_EVENT")?
                .split_ascii_whitespace()
                .filter(|word| *word != "OR")
                .collect();
            if events.is_empty()
                || events
                    .iter()
                    .any(|word| !matches!(*word, "INSERT" | "UPDATE" | "DELETE"))
            {
                return Err(MutationUnavailableReason::UnsupportedMechanism);
            }
            let applies = match scope.statement_kind {
                MutationStatementKind::Insert => events.contains("INSERT"),
                MutationStatementKind::Update => events.contains("UPDATE"),
                MutationStatementKind::Delete => events.contains("DELETE"),
                MutationStatementKind::Merge => true,
            };
            if !applies {
                continue;
            }
            let owner = required(row, "OWNER")?;
            let name = required(row, "TRIGGER_NAME")?;
            let columns = listed
                .get(&(owner.to_owned(), name.to_owned()))
                .cloned()
                .unwrap_or_default();
            if scope.statement_kind == MutationStatementKind::Update
                && !columns.is_empty()
                && matches!(&scope.columns, MutationColumns::Named(changed) if changed.is_disjoint(&columns))
            {
                continue;
            }
            let (timing, level, compound) = match required(row, "TRIGGER_TYPE")? {
                "BEFORE STATEMENT" => ("BEFORE", "STATEMENT", false),
                "AFTER STATEMENT" => ("AFTER", "STATEMENT", false),
                "BEFORE EACH ROW" => ("BEFORE", "ROW", false),
                "AFTER EACH ROW" => ("AFTER", "ROW", false),
                "COMPOUND" => ("COMPOUND", "COMPOUND", true),
                _ => return Err(MutationUnavailableReason::UnsupportedMechanism),
            };
            let fact = Self::fact(
                scope,
                row,
                owner,
                name,
                MutationMechanism::DmlTrigger {
                    timing: timing.into(),
                    level: level.into(),
                    compound,
                    columns,
                },
            );
            self.user_fact(fact, owner, name, "TRIGGER", None).await;
        }
        Ok(())
    }

    async fn mv_logs(
        &mut self,
        scope: &MutationRelationScope,
    ) -> Result<(), MutationUnavailableReason> {
        let rows = self
            .rows(
                scope,
                MutationCatalogSource::MaterializedViewLogs,
                CatalogQueryId::MutationMvLogs,
            )
            .await?;
        for row in &rows {
            if required(row, "LOG_OWNER")? != scope.target.owner
                || required(row, "MASTER")? != scope.target.name
            {
                return Err(MutationUnavailableReason::IdentityMismatch);
            }
            for name in [
                "ROWIDS",
                "PRIMARY_KEY",
                "OBJECT_ID",
                "SEQUENCE",
                "INCLUDE_NEW_VALUES",
            ] {
                flag(row, name)?;
            }
            // Oracle8i and later keep LOG_TRIGGER null. The readable log row,
            // not a fabricated trigger, proves transactional internal work.
            optional(row, "LOG_TRIGGER")?;
            let log_table = required(row, "LOG_TABLE")?;
            let mut fact = Self::fact(
                scope,
                row,
                &scope.target.owner,
                log_table,
                MutationMechanism::MvLog {
                    log_table: log_table.into(),
                },
            );
            fact.effects = RoutineEffectsV1::new([RoutineEffect::Dml]);
            self.add(fact);
        }
        Ok(())
    }
}

/// Read one complete, valid, definer-rights source object with bounded physical
/// lines and compiler settings. This supplies source data, never effect authority.
pub async fn read_mutation_routine_source(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    object_type: &str,
    member: Option<&str>,
) -> Result<MutationRoutineSource, MutationUnavailableReason> {
    read_pinned_mutation_routine_source(cx, conn, owner, name, object_type, member, None).await
}

/// Read the same complete source projection while selecting one catalog
/// subprogram explicitly. Unpinned consumers still require a unique member.
pub async fn read_pinned_mutation_routine_source(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    object_type: &str,
    member: Option<&str>,
    subprogram_id: Option<u32>,
) -> Result<MutationRoutineSource, MutationUnavailableReason> {
    if !matches!(
        object_type,
        "TRIGGER" | "FUNCTION" | "PROCEDURE" | "PACKAGE" | "PACKAGE BODY" | "TYPE BODY"
    ) || (member.is_some() && object_type != "PACKAGE BODY")
    {
        return Err(MutationUnavailableReason::UnsupportedMechanism);
    }
    let object_rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::ClosureMemberObject,
        &[owner.into(), name.into(), object_type.into(), 2_i64.into()],
    )
    .await
    .map_err(|_| MutationUnavailableReason::SourceUnavailable)?;
    let [object] = object_rows.as_slice() else {
        return Err(MutationUnavailableReason::SourceUnavailable);
    };
    if required(object, "STATUS")? != "VALID" {
        return Err(MutationUnavailableReason::SourceUnavailable);
    }
    let object_id = object
        .parse_i64("OBJECT_ID")
        .and_then(|id| u64::try_from(id).ok())
        .filter(|id| *id != 0)
        .ok_or(MutationUnavailableReason::CatalogIncomplete)?;
    let last_ddl_time = required(object, "LAST_DDL_TIME")?.to_owned();
    let subprogram_id = if matches!(object_type, "FUNCTION" | "PROCEDURE" | "PACKAGE BODY") {
        let rows = run_catalog_query(
            cx,
            conn,
            CatalogQueryId::ClosureRoutineAuthid,
            &[
                owner.into(),
                name.into(),
                member.map_or(OracleBind::Null, OracleBind::from),
                member.map_or(OracleBind::Null, OracleBind::from),
                33_i64.into(),
            ],
        )
        .await
        .map_err(|_| MutationUnavailableReason::SourceUnavailable)?;
        if rows.len() >= 33 {
            return Err(MutationUnavailableReason::ClosureCapExhausted);
        }
        let candidates: Vec<_> = rows
            .iter()
            .filter(|row| {
                subprogram_id.is_none_or(|id| row.parse_i64("SUBPROGRAM_ID") == Some(i64::from(id)))
            })
            .collect();
        let [routine] = candidates.as_slice() else {
            return Err(MutationUnavailableReason::EffectProofUnavailable);
        };
        if required(routine, "AUTHID")? != "DEFINER" {
            return Err(MutationUnavailableReason::EffectProofUnavailable);
        }
        let id = routine
            .parse_i64("SUBPROGRAM_ID")
            .and_then(|id| u32::try_from(id).ok())
            .ok_or(MutationUnavailableReason::CatalogIncomplete)?;
        if id == 0 {
            if object_type != "PACKAGE BODY" || member.is_some() {
                return Err(MutationUnavailableReason::CatalogIncomplete);
            }
            None
        } else {
            Some(id)
        }
    } else {
        if object_type == "TYPE BODY" {
            let rows = run_catalog_query(
                cx,
                conn,
                CatalogQueryId::MutationTypeAuthid,
                &[owner.into(), name.into(), 2_i64.into()],
            )
            .await
            .map_err(|_| MutationUnavailableReason::CatalogUnreadable)?;
            let [row] = rows.as_slice() else {
                return Err(MutationUnavailableReason::CatalogIncomplete);
            };
            if required(row, "OWNER")? != owner
                || required(row, "TYPE_NAME")? != name
                || required(row, "AUTHID")? != "DEFINER"
            {
                return Err(MutationUnavailableReason::EffectProofUnavailable);
            }
        }
        None
    };
    let settings = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::ClosureCompilerSettings,
        &[owner.into(), name.into(), object_type.into(), 2_i64.into()],
    )
    .await
    .map_err(|_| MutationUnavailableReason::SourceUnavailable)?;
    let [settings] = settings.as_slice() else {
        return Err(MutationUnavailableReason::SourceUnavailable);
    };
    let mut compiler_settings = BTreeMap::new();
    for column in [
        "PLSQL_OPTIMIZE_LEVEL",
        "PLSQL_CODE_TYPE",
        "PLSQL_DEBUG",
        "PLSQL_WARNINGS",
        "PLSQL_CCFLAGS",
        "NLS_LENGTH_SEMANTICS",
        "PLSCOPE_SETTINGS",
    ] {
        let value = optional(settings, column)?;
        if column == "PLSQL_CCFLAGS" {
            if value
                .as_deref()
                .is_some_and(|flags| !flags.trim().is_empty())
            {
                return Err(MutationUnavailableReason::EffectProofUnavailable);
            }
        } else if value.as_deref().is_none_or(str::is_empty) {
            return Err(MutationUnavailableReason::CatalogIncomplete);
        }
        compiler_settings.insert(column.to_owned(), value);
    }
    let source_rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::ClosureSource,
        &[
            owner.into(),
            name.into(),
            object_type.into(),
            16_385_i64.into(),
        ],
    )
    .await
    .map_err(|_| MutationUnavailableReason::SourceUnavailable)?;
    if source_rows.is_empty() || source_rows.len() >= 16_385 {
        return Err(MutationUnavailableReason::SourceUnavailable);
    }
    let mut source = String::new();
    for (index, row) in source_rows.iter().enumerate() {
        if row.parse_i64("LINE") != i64::try_from(index + 1).ok() {
            return Err(MutationUnavailableReason::SourceUnavailable);
        }
        let cell = row
            .cell("TEXT")
            .ok_or(MutationUnavailableReason::SourceUnavailable)?;
        let text = optional(row, "TEXT")?.unwrap_or_default();
        if cell
            .source_length
            .is_some_and(|length| length > text.chars().count())
        {
            return Err(MutationUnavailableReason::SourceUnavailable);
        }
        source.push_str(&text);
        if !text.ends_with('\n') {
            source.push('\n');
        }
        if source.len() > MAX_MUTATION_SOURCE_BYTES {
            return Err(MutationUnavailableReason::ClosureCapExhausted);
        }
    }
    if source.trim().is_empty() {
        return Err(MutationUnavailableReason::SourceUnavailable);
    }
    Ok(MutationRoutineSource {
        use_context: MutationRoutineUse::DmlTrigger,
        owner: owner.into(),
        name: name.into(),
        object_type: object_type.into(),
        member: member.map(str::to_owned),
        subprogram_id,
        object_id,
        last_ddl_time,
        compiler_settings,
        expression_columns: BTreeMap::new(),
        expression_storage_type: None,
        source_sha256: digest(source.as_bytes()),
        source_line_count: source_rows.len(),
        source,
    })
}

impl Collector<'_> {
    async fn user_fact(
        &mut self,
        mut fact: MutationMechanismFact,
        owner: &str,
        name: &str,
        object_type: &str,
        member: Option<&str>,
    ) {
        if self.total_rows >= MAX_MUTATION_TOTAL_ROWS
            || self.source_bytes >= MAX_MUTATION_SOURCE_BYTES
        {
            fact.computation = MutationComputation::Unavailable {
                reason: MutationUnavailableReason::ClosureCapExhausted,
            };
            self.add(fact);
            return;
        }
        match read_mutation_routine_source(self.cx, self.conn, owner, name, object_type, member)
            .await
        {
            Ok(mut source) => {
                self.total_rows = self.total_rows.saturating_add(source.source_line_count);
                if self.total_rows > MAX_MUTATION_TOTAL_ROWS {
                    fact.computation = MutationComputation::Unavailable {
                        reason: MutationUnavailableReason::ClosureCapExhausted,
                    };
                    self.add(fact);
                    return;
                }
                source.use_context = match fact.mechanism {
                    MutationMechanism::DmlTrigger { .. } => MutationRoutineUse::DmlTrigger,
                    MutationMechanism::VpdPolicy { .. } => MutationRoutineUse::VpdPolicy,
                    MutationMechanism::FgaHandler => MutationRoutineUse::FgaHandler,
                    MutationMechanism::IndexCallback { domain: true } => {
                        MutationRoutineUse::DomainIndex
                    }
                    _ => {
                        fact.computation = MutationComputation::Unavailable {
                            reason: MutationUnavailableReason::UnsupportedMechanism,
                        };
                        self.add(fact);
                        return;
                    }
                };
                self.prove(&mut fact, source).await;
            }
            Err(reason) => {
                fact.effects = RoutineEffectsV1::new([RoutineEffect::Unknown]);
                fact.computation = MutationComputation::Unavailable { reason };
            }
        }
        self.add(fact);
    }

    fn unavailable(&mut self, reason: MutationUnavailableReason) {
        self.closure.unavailable.insert(reason);
    }

    fn unavailable_source(
        &mut self,
        scope: &MutationRelationScope,
        source: MutationCatalogSource,
        reason: MutationUnavailableReason,
    ) {
        if let Some(observation) = self
            .closure
            .observations
            .iter_mut()
            .find(|observation| observation.scope == *scope && observation.source == source)
        {
            observation.computation = MutationComputation::Unavailable { reason };
        } else {
            self.closure.observations.push(MutationCatalogObservation {
                scope: scope.clone(),
                source,
                computation: MutationComputation::Unavailable { reason },
                source_sha256: None,
                row_count: 0,
            });
        }
    }

    async fn rows(
        &mut self,
        scope: &MutationRelationScope,
        source: MutationCatalogSource,
        query: CatalogQueryId,
    ) -> Result<Vec<OracleRow>, MutationUnavailableReason> {
        if self.total_rows >= MAX_MUTATION_TOTAL_ROWS {
            self.unavailable_source(
                scope,
                source,
                MutationUnavailableReason::ClosureCapExhausted,
            );
            return Err(MutationUnavailableReason::ClosureCapExhausted);
        }
        let result = run_catalog_query(
            self.cx,
            self.conn,
            query,
            &[
                OracleBind::from(scope.target.owner.as_str()),
                OracleBind::from(scope.target.name.as_str()),
                OracleBind::I64(PROBE_LIMIT),
            ],
        )
        .await;
        let rows = match result {
            Ok(rows) if rows.len() <= MAX_MUTATION_CATALOG_ROWS => rows,
            Ok(_) => {
                self.unavailable_source(scope, source, MutationUnavailableReason::RowCapExhausted);
                return Err(MutationUnavailableReason::RowCapExhausted);
            }
            Err(_) => {
                self.unavailable_source(
                    scope,
                    source,
                    MutationUnavailableReason::CatalogUnreadable,
                );
                return Err(MutationUnavailableReason::CatalogUnreadable);
            }
        };
        self.total_rows = self.total_rows.saturating_add(rows.len());
        if self.total_rows > MAX_MUTATION_TOTAL_ROWS {
            self.unavailable_source(
                scope,
                source,
                MutationUnavailableReason::ClosureCapExhausted,
            );
            return Err(MutationUnavailableReason::ClosureCapExhausted);
        }
        let fingerprint = rows_digest(&rows);
        self.closure.observations.push(MutationCatalogObservation {
            scope: scope.clone(),
            source,
            computation: MutationComputation::Computed,
            source_sha256: Some(fingerprint.clone()),
            row_count: u32::try_from(rows.len()).expect("row cap fits u32"),
        });
        self.snapshots
            .push((scope.clone(), query, source, fingerprint));
        Ok(rows)
    }

    fn add(&mut self, fact: MutationMechanismFact) {
        if self.closure.mechanisms.len() >= MAX_MUTATION_MECHANISMS {
            self.unavailable(MutationUnavailableReason::ClosureCapExhausted);
        } else {
            self.closure.mechanisms.push(fact);
        }
    }

    fn fact(
        scope: &MutationRelationScope,
        row: &OracleRow,
        owner: &str,
        name: &str,
        mechanism: MutationMechanism,
    ) -> MutationMechanismFact {
        MutationMechanismFact {
            scope: scope.clone(),
            owner: owner.to_owned(),
            name: name.to_owned(),
            object_id: None,
            mechanism,
            metadata_sha256: rows_digest(std::slice::from_ref(row)),
            source_sha256: Some(rows_digest(std::slice::from_ref(row))),
            routine_closure_fingerprints: BTreeSet::new(),
            effects: RoutineEffectsV1::default(),
            computation: MutationComputation::Computed,
        }
    }

    async fn prove(&mut self, fact: &mut MutationMechanismFact, source: MutationRoutineSource) {
        fact.source_sha256 = Some(source.source_sha256.clone());
        fact.object_id = Some(source.object_id);
        self.source_bytes = self.source_bytes.saturating_add(source.source.len());
        let proof = if self.source_bytes > MAX_MUTATION_SOURCE_BYTES {
            Err(MutationUnavailableReason::ClosureCapExhausted)
        } else {
            self.oracle
                .prove_source(self.cx, self.conn, &source)
                .await
                .and_then(|proof| {
                    if proof.mutations.len() > MAX_MUTATION_SCOPES {
                        Err(MutationUnavailableReason::ClosureCapExhausted)
                    } else if proof.use_context != source.use_context
                        || proof.source_sha256 != source.source_sha256
                        || !valid_hash(&proof.closure_fingerprint)
                    {
                        Err(MutationUnavailableReason::EffectSourceMismatch)
                    } else if proof
                        .effects
                        .iter()
                        .any(|effect| effect == RoutineEffect::Unknown)
                        || (proof
                            .effects
                            .iter()
                            .any(|effect| effect == RoutineEffect::Dml)
                            && proof.mutations.is_empty())
                    {
                        Err(MutationUnavailableReason::EffectProofUnavailable)
                    } else {
                        Ok(proof)
                    }
                })
        };
        match proof {
            Ok(proof) => {
                fact.effects = fact.effects.union(&proof.effects);
                fact.routine_closure_fingerprints
                    .insert(proof.closure_fingerprint);
                if self.queue.len().saturating_add(proof.mutations.len()) > MAX_MUTATION_SCOPES {
                    fact.computation = MutationComputation::Unavailable {
                        reason: MutationUnavailableReason::ClosureCapExhausted,
                    };
                } else {
                    self.queue.extend(proof.mutations);
                }
            }
            Err(reason) => {
                fact.effects = fact
                    .effects
                    .union(&RoutineEffectsV1::new([RoutineEffect::Unknown]));
                fact.computation = MutationComputation::Unavailable { reason };
            }
        }
    }

    async fn security(&mut self, scope: &MutationRelationScope, target: &ResolvedObject) {
        let observation =
            match observe_relation_security(self.cx, self.conn, std::slice::from_ref(target)).await
            {
                Ok(mut observations) if observations.len() == 1 => observations.remove(0),
                Err(RelationSecurityProofError::Protected { observation, .. }) => observation,
                Err(_) | Ok(_) => {
                    self.unavailable_source(
                        scope,
                        MutationCatalogSource::SecurityPolicies,
                        MutationUnavailableReason::CatalogUnreadable,
                    );
                    return;
                }
            };
        let Some(database) = &self.closure.database else {
            self.unavailable_source(
                scope,
                MutationCatalogSource::SecurityPolicies,
                MutationUnavailableReason::IdentityMismatch,
            );
            return;
        };
        if observation.key.dbid.as_deref() != Some(&database.dbid)
            || observation.key.container.as_deref() != Some(&database.container)
            || observation.key.edition.as_deref() != Some(&database.edition)
            || observation.key.owner != scope.target.owner
            || observation.key.name != scope.target.name
            || observation.key.object_id != scope.target.object_id
            || observation.key.object_edition != scope.target.object_edition
        {
            self.unavailable_source(
                scope,
                MutationCatalogSource::SecurityPolicies,
                MutationUnavailableReason::IdentityMismatch,
            );
            return;
        }
        let hash = digest(&encoded(&observation));
        self.closure.observations.push(MutationCatalogObservation {
            scope: scope.clone(),
            source: MutationCatalogSource::SecurityPolicies,
            computation: MutationComputation::Computed,
            source_sha256: Some(hash.clone()),
            row_count: 1,
        });
        for (state, mechanism) in [
            (observation.ols, MutationMechanism::OlsPolicy),
            (observation.ras, MutationMechanism::RasRealm),
            (observation.redaction, MutationMechanism::RedactionPolicy),
        ] {
            match state {
                RelationSecurityState::Absent | RelationSecurityState::NotInstalled => {}
                RelationSecurityState::Unavailable => self.unavailable_source(
                    scope,
                    MutationCatalogSource::SecurityPolicies,
                    MutationUnavailableReason::CatalogUnreadable,
                ),
                RelationSecurityState::Protected => self.add(MutationMechanismFact {
                    scope: scope.clone(),
                    owner: scope.target.owner.clone(),
                    name: String::new(),
                    object_id: Some(scope.target.object_id),
                    mechanism,
                    metadata_sha256: hash.clone(),
                    source_sha256: Some(hash.clone()),
                    routine_closure_fingerprints: BTreeSet::new(),
                    effects: RoutineEffectsV1::new([RoutineEffect::Unknown]),
                    computation: MutationComputation::Unavailable {
                        reason: MutationUnavailableReason::UnsupportedMechanism,
                    },
                }),
            }
        }
    }

    async fn revalidate_catalog_snapshots(&mut self) {
        for (scope, query, source, fingerprint) in self.snapshots.clone() {
            let result = run_catalog_query(
                self.cx,
                self.conn,
                query,
                &[
                    scope.target.owner.as_str().into(),
                    scope.target.name.as_str().into(),
                    PROBE_LIMIT.into(),
                ],
            )
            .await;
            match result {
                Ok(rows)
                    if rows.len() <= MAX_MUTATION_CATALOG_ROWS
                        && rows_digest(&rows) == fingerprint => {}
                Ok(_) => self.unavailable_source(
                    &scope,
                    source,
                    MutationUnavailableReason::IdentityMismatch,
                ),
                Err(_) => self.unavailable_source(
                    &scope,
                    source,
                    MutationUnavailableReason::CatalogUnreadable,
                ),
            }
        }
        for scope in self.closure.scopes.clone() {
            let expected = self
                .closure
                .observations
                .iter()
                .find(|observation| {
                    observation.scope == scope
                        && observation.source == MutationCatalogSource::SecurityPolicies
                })
                .and_then(|observation| observation.source_sha256.clone());
            if expected.is_none() {
                continue;
            }
            let result =
                observe_relation_security(self.cx, self.conn, &[resolved_target(&scope.target)])
                    .await;
            match result {
                Ok(observations)
                    if observations.len() == 1
                        && Some(digest(&encoded(&observations[0]))) == expected => {}
                _ => self.unavailable_source(
                    &scope,
                    MutationCatalogSource::SecurityPolicies,
                    MutationUnavailableReason::IdentityMismatch,
                ),
            }
        }
        match read_closure_database_identity(self.cx, self.conn).await {
            Ok(identity)
                if self.closure.database.as_ref().is_some_and(|database| {
                    database.dbid == identity.dbid
                        && database.container == identity.container
                        && database.edition == identity.edition
                }) => {}
            _ => self.unavailable(MutationUnavailableReason::IdentityMismatch),
        }
    }
}

/// Collect only dictionary data and engine evidence. This function never
/// executes the caller's DML, grants privileges, or estimates affected rows.
pub async fn collect_mutation_effect_closure(
    cx: &Cx,
    conn: &dyn OracleConnection,
    request: MutationRequest,
    oracle: &dyn MutationEffectOracle,
) -> MutationEffectClosureV1 {
    let database = read_closure_database_identity(cx, conn)
        .await
        .ok()
        .map(|identity| MutationDatabaseIdentity {
            dbid: identity.dbid,
            container: identity.container,
            edition: identity.edition,
        });
    let fallback = MutationRelationScope {
        target: MutationTarget {
            owner: request.target.owner.clone(),
            name: request.target.name.clone(),
            object_id: request.target.identity.object_id,
            object_edition: request.target.identity.edition.clone(),
            last_ddl_time: String::new(),
        },
        statement_kind: request.statement_kind,
        columns: request.columns.clone(),
    };
    let mut closure = MutationEffectClosureV1::new(database, fallback);
    if !matches!(&request.target.kind, CatalogObjectKind::Table)
        || request.target.db_link.is_some()
        || request.target.identity.object_id == 0
        || matches!(&request.columns, MutationColumns::Named(columns) if columns.is_empty())
    {
        closure
            .unavailable
            .insert(MutationUnavailableReason::InvalidInput);
        return closure;
    }
    let (target, rows) = match target_identity(
        cx,
        conn,
        &request.target.owner,
        &request.target.name,
        Some(request.target.identity.object_id),
    )
    .await
    {
        Ok(result) => result,
        Err(reason) => {
            closure.unavailable.insert(reason);
            return closure;
        }
    };
    if target.object_edition != request.target.identity.edition {
        closure
            .unavailable
            .insert(MutationUnavailableReason::IdentityMismatch);
        return closure;
    }
    closure.root.target = target;
    closure.scopes = vec![closure.root.clone()];
    let mut collector = Collector {
        cx,
        conn,
        oracle,
        closure,
        queue: VecDeque::new(),
        visited: BTreeSet::new(),
        total_rows: 0,
        source_bytes: 0,
        snapshots: Vec::new(),
    };
    let scope = collector.closure.root.clone();
    collector.visited.insert(encoded(&scope));
    collector.record_identity(&scope, &rows);
    collector.collect_scope(&scope, &request.target).await;
    while let Some(request) = collector.queue.pop_front() {
        if !matches!(&request.target.kind, CatalogObjectKind::Table)
            || request.target.db_link.is_some()
            || request.target.identity.object_id == 0
            || matches!(&request.columns, MutationColumns::Named(columns) if columns.is_empty())
        {
            collector.unavailable(MutationUnavailableReason::InvalidInput);
            continue;
        }
        let (target, rows) = match target_identity(
            cx,
            conn,
            &request.target.owner,
            &request.target.name,
            Some(request.target.identity.object_id),
        )
        .await
        {
            Ok(result) => result,
            Err(reason) => {
                collector.unavailable(reason);
                continue;
            }
        };
        if target.object_edition != request.target.identity.edition {
            collector.unavailable(MutationUnavailableReason::IdentityMismatch);
            continue;
        }
        let scope = MutationRelationScope {
            target,
            statement_kind: request.statement_kind,
            columns: request.columns,
        };
        if !collector.visited.insert(encoded(&scope)) {
            continue;
        }
        if collector.closure.scopes.len() >= MAX_MUTATION_SCOPES {
            collector.unavailable(MutationUnavailableReason::ClosureCapExhausted);
            break;
        }
        collector.closure.scopes.push(scope.clone());
        collector.record_identity(&scope, &rows);
        collector.collect_scope(&scope, &request.target).await;
    }
    collector.revalidate_catalog_snapshots().await;
    collector.closure
}
