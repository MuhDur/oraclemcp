//! Live Oracle dictionary-backed semantic name resolution.
//!
//! The resolver is loaded asynchronously from the connection and then exposed
//! through the synchronous, engine-free [`CatalogResolver`] port.  A loaded
//! snapshot is usable only with the exact session, statement-scope, and catalog
//! generation context that produced it; a cache miss or context mismatch is
//! deliberately unresolved.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::RwLock;

use asupersync::Cx;
use oraclemcp_guard::{
    CatalogObjectKind, CatalogResolver, ObjectRef, Purity, QueryBlock, QueryBlockKind,
    QuoteSemantics, RawName, RawNamePart, Resolution, ResolveCtx, ResolvedContainer,
    ResolvedIdentity, ResolvedObject, ResolvedOverload, RoutineArgument, RoutineArgumentValue,
    RoutineIdentifier, RoutineRef, SemanticReadPlan, SideEffectOracle, StatementScope, SynonymHop,
    SyntacticRole,
};

#[cfg(test)]
use crate::catalog_query::{
    ALL_POLICIES_VISIBILITY_SQL, COLUMN_CONFLICT_SQL, FGA_CATALOG_PROOF_SQL, MEMBER_ARGUMENTS_SQL,
    MEMBER_PROCEDURES_SQL, OBJECTS_SQL, POLICY_CATALOG_PROOF_SQL, POLICY_ROWS_FOR_RELATIONS_32_SQL,
    RELATION_COLUMN_SQL, SELECT_POLICY_SQL, STANDALONE_ARGUMENTS_SQL, STANDALONE_PROCEDURES_SQL,
    SYNONYMS_SQL, TARGET_COLUMN_CATALOG_PROOF_SQL, VIRTUAL_COLUMN_SQL,
    VIRTUAL_COLUMNS_FOR_RELATIONS_32_SQL,
};
use crate::catalog_query::{CatalogQueryId, run_catalog_query};
use crate::{DbError, OracleBind, OracleConnection, OracleRow};

/// Maximum number of syntactic names loaded into one immutable resolver.
pub const MAX_CATALOG_NAMES: usize = 64;

const MAX_CATALOG_CACHE_ENTRIES: usize = 4_096;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_CANDIDATES: usize = 32;
const MAX_SYNONYM_HOPS: usize = 16;
const MAX_ARGUMENT_ROWS: usize = 512;
const MAX_SESSION_ROLES: usize = 256;

const VPD_RLS_POLICY_BY_SCHEMA_SQL: &str = "SELECT object_owner, object_name, policy_name, \
    pf_owner, package, function, sel, ins, upd, del, enable \
    FROM (SELECT object_owner, object_name, policy_name, pf_owner, package, function, sel, ins, \
                 upd, del, enable \
          FROM all_policies WHERE object_owner = :1 \
          ORDER BY object_owner, object_name, policy_name) \
    WHERE ROWNUM <= :2";

const VPD_RLS_POLICY_BY_OBJECT_SQL: &str = "SELECT object_owner, object_name, policy_name, \
    pf_owner, package, function, sel, ins, upd, del, enable \
    FROM (SELECT object_owner, object_name, policy_name, pf_owner, package, function, sel, ins, \
                 upd, del, enable \
          FROM all_policies WHERE object_owner = :1 AND object_name = :2 \
          ORDER BY object_owner, object_name, policy_name) \
    WHERE ROWNUM <= :3";

/// Maximum VPD/RLS policy rows surfaced in one diagnostic observation.
pub const MAX_VPD_RLS_POLICY_ROWS: usize = 64;

/// Session-security context observed through Oracle's own `USERENV` and role
/// catalog for VPD/RLS diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OracleSessionSecurityContext {
    /// `SYS_CONTEXT('USERENV', 'SESSION_USER')`.
    pub session_user: String,
    /// `SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA')`.
    pub current_schema: String,
    /// `SYS_CONTEXT('USERENV', 'CURRENT_EDITION_NAME')`, when Oracle reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition_name: Option<String>,
    /// Enabled roles visible in `SESSION_ROLES`, capped at the resolver role
    /// bound.
    pub enabled_roles: Vec<String>,
}

/// Visibility status for the `ALL_POLICIES` probe used by RLS/VPD diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OraclePolicyCatalogVisibility {
    /// One or more policy rows are visible to the current principal.
    PolicyRowsVisible,
    /// `ALL_POLICIES` returned zero visible rows. This is not proof that no
    /// policy exists; it may mean the principal is catalog-blind.
    NoPolicyRowsVisible,
    /// The probe itself could not be read.
    Unavailable,
}

/// The cheap `ALL_POLICIES` visibility probe attached to VPD/RLS observations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OraclePolicyCatalogProbe {
    /// Probe result.
    pub visibility: OraclePolicyCatalogVisibility,
    /// Whether at least one row was visible, when the count probe succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_policy_rows_probe: Option<bool>,
    /// Human-readable, non-secret explanation of the observation boundary.
    pub detail: String,
}

/// One visible Oracle VPD/RLS policy row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OracleVpdRlsPolicy {
    /// Policy target owner.
    pub object_owner: String,
    /// Policy target object name.
    pub object_name: String,
    /// Policy name.
    pub policy_name: String,
    /// Policy function owner, when visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_owner: Option<String>,
    /// Policy package, when visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    /// Policy function, when visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    /// Statement classes this policy applies to, as visible in `ALL_POLICIES`.
    pub statement_types: Vec<String>,
    /// Whether Oracle reports the policy enabled.
    pub enabled: bool,
}

/// Overall status for a VPD/RLS diagnostic observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleVpdRlsObservationStatus {
    /// One or more matching policies were observed and are named in `policies`.
    PoliciesObserved,
    /// Policy catalog rows are visible, but none matched the requested scope.
    NoVisibleMatchingPolicies,
    /// No policy rows are visible at all; this is explicitly not an absence
    /// proof for protected objects.
    NoVisiblePolicyCatalogRows,
    /// The server could not inspect policy visibility.
    VisibilityUnavailable,
}

/// VPD/RLS observation attached to doctor and query results.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OracleVpdRlsObservation {
    /// Diagnostic status.
    pub status: OracleVpdRlsObservationStatus,
    /// Scope of the observation, such as `schema:APP` or `relations`.
    pub scope: String,
    /// Session-security context, when it could be observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<OracleSessionSecurityContext>,
    /// Visibility probe for `ALL_POLICIES`.
    pub all_policies_probe: OraclePolicyCatalogProbe,
    /// Visible matching policies, capped at [`MAX_VPD_RLS_POLICY_ROWS`].
    pub policies: Vec<OracleVpdRlsPolicy>,
    /// Human-readable, non-secret explanation of the observation boundary.
    pub detail: String,
}

/// Immutable set of live dictionary answers for one exact resolution context.
#[derive(Debug, Clone)]
pub struct OracleCatalogResolver {
    context: ResolveCtx,
    entries: HashMap<RawName, Resolution>,
}

/// A catalog event that invalidates every resolution proof in one lane/profile.
///
/// Reasons are retained as a closed vocabulary so mutation call sites must
/// state why they are advancing the generation. All variants have the same
/// fail-closed effect: advance the monotonic generation and clear positive and
/// negative entries atomically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CatalogInvalidation {
    /// A general DDL statement may have changed object identity or visibility.
    Ddl,
    /// A synonym was created, replaced, altered, or dropped.
    Synonym,
    /// A package or type specification/body was compiled or replaced.
    Package,
    /// Callable overload or argument metadata may have changed.
    Overload,
    /// `CURRENT_SCHEMA` changed for the Oracle session.
    CurrentSchema,
    /// The active Oracle edition changed.
    Edition,
    /// Enabled roles or grants affecting `ALL_*` visibility changed.
    Roles,
    /// A physical connection or active profile was replaced.
    Reconnect,
    /// Live session state changed while a dictionary snapshot was loading.
    SessionContextChanged,
    /// A served read starts a fresh proof, preventing external DDL observed by
    /// the session from inheriting a prior request's object identity.
    SemanticProofRefresh,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResolverCacheKey {
    generation: u64,
    connected_schema: String,
    resolving_schema: String,
    edition: Option<String>,
    enabled_roles: Vec<String>,
    aliases: Vec<RawNamePart>,
    common_table_expressions: Vec<RawNamePart>,
    relations: Vec<oraclemcp_guard::StatementRelation>,
    raw_name: RawName,
}

impl ResolverCacheKey {
    fn new(name: &RawName, context: &ResolveCtx) -> Self {
        Self {
            generation: context.generation.0,
            connected_schema: context.connected_schema.clone(),
            resolving_schema: context.current_schema.clone(),
            edition: context.edition.clone(),
            enabled_roles: context.enabled_roles.iter().cloned().collect(),
            aliases: context.statement_scope.aliases.clone(),
            common_table_expressions: context.statement_scope.common_table_expressions.clone(),
            relations: context.statement_scope.relations.clone(),
            raw_name: name.clone(),
        }
    }
}

#[derive(Debug)]
struct ResolverCacheState {
    generation: u64,
    exhausted: bool,
    entries: HashMap<ResolverCacheKey, Resolution>,
}

/// Bounded generation-scoped resolution cache for one lane/profile.
///
/// The single lock makes generation checks, invalidation, and publication
/// linearizable. No method holds it across an Oracle await: [`Self::preload`]
/// captures a generation, performs dictionary I/O without the lock, then
/// publishes only if that exact generation is still current. A racing
/// invalidation therefore turns the caller's old context stale and cannot
/// repopulate the new generation with old evidence.
#[derive(Debug)]
pub struct OracleCatalogResolverCache {
    // SAFETY: this is the cache's only lock. Never hold it across Oracle I/O or
    // while acquiring dispatcher/lane state; consumers acquire lane state
    // first and call these short non-awaiting critical sections second.
    state: RwLock<ResolverCacheState>,
}

impl Default for OracleCatalogResolverCache {
    fn default() -> Self {
        Self::new()
    }
}

impl OracleCatalogResolverCache {
    /// Build an empty cache at generation one.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(ResolverCacheState {
                generation: 1,
                exhausted: false,
                entries: HashMap::new(),
            }),
        }
    }

    /// Current monotonic generation.
    ///
    /// A poisoned cache reports the terminal generation. Resolution still
    /// fails closed because [`CatalogResolver::resolve`] refuses a poisoned
    /// lock.
    #[must_use]
    pub fn generation(&self) -> oraclemcp_guard::CatalogGeneration {
        self.state
            .read()
            .map(|state| oraclemcp_guard::CatalogGeneration(state.generation))
            .unwrap_or(oraclemcp_guard::CatalogGeneration(u64::MAX))
    }

    /// Number of positive and negative entries in the current generation.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state
            .read()
            .map(|state| state.entries.len())
            .unwrap_or(0)
    }

    /// Whether the current generation contains no cached answers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Atomically advance the generation and discard all prior evidence.
    ///
    /// Generation exhaustion permanently disables publication and resolution
    /// rather than wrapping to a value that could make ancient evidence appear
    /// current again.
    pub fn invalidate(&self, _reason: CatalogInvalidation) -> oraclemcp_guard::CatalogGeneration {
        let Ok(mut state) = self.state.write() else {
            return oraclemcp_guard::CatalogGeneration(u64::MAX);
        };
        state.entries.clear();
        match state.generation.checked_add(1) {
            Some(next) if !state.exhausted => state.generation = next,
            _ => {
                state.generation = u64::MAX;
                state.exhausted = true;
            }
        }
        oraclemcp_guard::CatalogGeneration(state.generation)
    }

    /// Load missing names from the live session into the current generation.
    ///
    /// The returned context is the exact context used for cache keys. If an
    /// invalidation races the load, that context is intentionally stale and
    /// subsequent [`CatalogResolver::resolve`] calls return `Unresolved`.
    pub async fn preload(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
        names: &[RawName],
        statement_scope: StatementScope,
    ) -> Result<ResolveCtx, DbError> {
        if names.len() > MAX_CATALOG_NAMES {
            return Err(DbError::Query(format!(
                "catalog resolver name cap exceeded: {} > {MAX_CATALOG_NAMES}",
                names.len()
            )));
        }
        let generation = {
            let state = self.state.read().map_err(cache_lock_error)?;
            if state.exhausted {
                return Err(DbError::Query(
                    "catalog resolver generation is exhausted".to_owned(),
                ));
            }
            oraclemcp_guard::CatalogGeneration(state.generation)
        };
        let context = read_catalog_resolve_context(cx, conn, generation, statement_scope).await?;
        let missing = {
            let state = self.state.read().map_err(cache_lock_error)?;
            if state.exhausted || state.generation != generation.0 {
                return Ok(context);
            }
            let mut seen = HashSet::new();
            names
                .iter()
                .filter(|name| seen.insert((*name).clone()))
                .filter(|name| {
                    !state
                        .entries
                        .contains_key(&ResolverCacheKey::new(name, &context))
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        if missing.is_empty() {
            return Ok(context);
        }

        let loaded = OracleCatalogResolver::load(cx, conn, &missing, &context).await?;
        if loaded.entries.len() != missing.len() {
            self.invalidate(CatalogInvalidation::SessionContextChanged);
            return Ok(context);
        }
        self.publish(generation, &context, loaded.entries);
        Ok(context)
    }

    fn publish(
        &self,
        generation: oraclemcp_guard::CatalogGeneration,
        context: &ResolveCtx,
        entries: HashMap<RawName, Resolution>,
    ) -> bool {
        let Ok(mut state) = self.state.write() else {
            return false;
        };
        if state.exhausted || state.generation != generation.0 || context.generation != generation {
            return false;
        }
        if state.entries.len().saturating_add(entries.len()) > MAX_CATALOG_CACHE_ENTRIES {
            state.entries.clear();
        }
        for (name, resolution) in entries {
            state
                .entries
                .insert(ResolverCacheKey::new(&name, context), resolution);
        }
        true
    }
}

impl CatalogResolver for OracleCatalogResolverCache {
    fn resolve(&self, name: &RawName, context: &ResolveCtx) -> Resolution {
        let Ok(state) = self.state.read() else {
            return Resolution::Unresolved;
        };
        if state.exhausted || state.generation != context.generation.0 {
            return Resolution::Unresolved;
        }
        state
            .entries
            .get(&ResolverCacheKey::new(name, context))
            .cloned()
            .unwrap_or(Resolution::Unresolved)
    }
}

/// Prove that exact resolved relations cannot invoke user-controlled code on a
/// plain fetch under the currently visible catalog and statement value names.
///
/// The lean server deliberately proves only ordinary tables with no enabled
/// SELECT VPD policy or executable virtual-column dependency. Views and every unknown object
/// kind remain `Unknown`: their defining query can hide function invocation and
/// cannot be cleared by object-type syntax alone.
pub async fn resolved_relations_read_purity(
    cx: &Cx,
    conn: &dyn OracleConnection,
    relations: &[ResolvedObject],
    values: &[RawName],
) -> Result<oraclemcp_guard::Purity, DbError> {
    if relations.is_empty() {
        return Ok(oraclemcp_guard::Purity::ProvenReadOnly);
    }
    if relations.len() > 256 {
        return Ok(oraclemcp_guard::Purity::Unknown);
    }
    for relation in relations {
        if relation.db_link.is_some()
            || !matches!(relation.kind, CatalogObjectKind::Table)
            || relation.identity.object_id == 0
        {
            return Ok(oraclemcp_guard::Purity::Unknown);
        }
    }
    for chunk in relations.chunks(32) {
        let mut binds = Vec::with_capacity(64);
        for relation in chunk {
            binds.push(OracleBind::from(relation.owner.as_str()));
            binds.push(OracleBind::from(relation.name.as_str()));
        }
        while binds.len() < 64 {
            binds.push(OracleBind::from(""));
        }
        if !run_catalog_query(cx, conn, CatalogQueryId::PolicyRowsForRelations32, &binds)
            .await?
            .is_empty()
        {
            return Ok(oraclemcp_guard::Purity::Unknown);
        }
        let virtual_columns = run_catalog_query(
            cx,
            conn,
            CatalogQueryId::VirtualColumnsForRelations32,
            &binds,
        )
        .await?;
        // The row cap must be strictly above the number processed. An exact
        // hit may conceal a later unsafe virtual column.
        if virtual_columns.len() >= 257
            || virtual_columns.iter().any(|row| {
                let Some(owner) = required_text(row, "OWNER") else {
                    return true;
                };
                let Some(table) = required_text(row, "TABLE_NAME") else {
                    return true;
                };
                let Some(column) = required_text(row, "COLUMN_NAME") else {
                    return true;
                };
                let Some(expression) = required_text(row, "DATA_DEFAULT") else {
                    return true;
                };
                !chunk
                    .iter()
                    .any(|relation| relation.owner == owner && relation.name == table)
                    || row.text("HIDDEN_COLUMN") != Some("YES")
                    || row.text("USER_GENERATED") != Some("NO")
                    || row.cell("DATA_DEFAULT").is_some_and(|cell| {
                        cell.source_length
                            .is_some_and(|length| length > expression.chars().count())
                    })
                    || values.iter().any(|value| {
                        normalize_parts(&value.parts)
                            .is_some_and(|parts| parts.iter().any(|part| part == &column))
                    })
                    || !oraclemcp_guard::builtin_only_virtual_column_expression(
                        &column,
                        &expression,
                    )
            })
        {
            return Ok(oraclemcp_guard::Purity::Unknown);
        }
    }
    // Once per statement, prove both catalog surfaces are readable. Successful
    // empty probes are visibility evidence; a failed probe aborts the proof.
    prove_policy_catalog_readable(cx, conn).await?;
    prove_target_column_catalog_readable(cx, conn, &relations[0]).await?;
    Ok(oraclemcp_guard::Purity::ProvenReadOnly)
}

/// Statement class used to match Oracle FGA policy flags. The mutation effect
/// collector uses the same catalog proof for its three DML classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FgaStatementKind {
    /// SELECT, including a query nested in another statement.
    Select,
    /// INSERT.
    Insert,
    /// UPDATE.
    Update,
    /// DELETE.
    Delete,
}

/// The four statement classes named by one FGA policy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FgaAppliesTo {
    /// SELECT applicability.
    pub select: bool,
    /// INSERT applicability.
    pub insert: bool,
    /// UPDATE applicability.
    pub update: bool,
    /// DELETE applicability.
    pub delete: bool,
}

impl FgaAppliesTo {
    fn includes(self, kind: FgaStatementKind) -> bool {
        match kind {
            FgaStatementKind::Select => self.select,
            FgaStatementKind::Insert => self.insert,
            FgaStatementKind::Update => self.update,
            FgaStatementKind::Delete => self.delete,
        }
    }
}

/// Exact catalog evidence for one fine-grained auditing policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FgaPolicyEvidence {
    /// Target owner and object name.
    pub object: (String, String),
    /// Oracle policy name.
    pub policy_name: String,
    /// Whether Oracle reports the policy enabled.
    pub enabled: bool,
    /// Statement classes to which the policy applies.
    pub applies_to: FgaAppliesTo,
    /// Handler owner, optional package, and function.
    pub handler: Option<(String, Option<String>, String)>,
    /// Condition evaluated by Oracle as the statement runs.
    pub audit_condition: Option<String>,
}

/// A complete FGA closure or the specific evidence that refuses admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FgaClosure {
    /// Catalog was readable, complete, and no matching policy invokes user code.
    ProvenReadOnly,
    /// A matching enabled policy can run an autonomous handler.
    Autonomous {
        /// Exact policy that can call an autonomous handler.
        policy: FgaPolicyEvidence,
    },
    /// Catalog evidence was unavailable, truncated, or ambiguous.
    Unknown {
        /// Stable internal evidence-gap reason.
        reason: &'static str,
    },
}

impl FgaClosure {
    /// Project the FGA verdict onto the common purity lattice.
    #[must_use]
    pub fn purity(&self) -> Purity {
        match self {
            Self::ProvenReadOnly => Purity::ProvenReadOnly,
            Self::Autonomous { .. } => Purity::ProvenSideEffecting,
            Self::Unknown { .. } => Purity::Unknown,
        }
    }
}

fn fga_flag(row: &OracleRow, name: &str) -> Option<bool> {
    match row.text(name)? {
        "YES" => Some(true),
        "NO" => Some(false),
        _ => None,
    }
}

fn parse_fga_policy(row: &OracleRow) -> Result<FgaPolicyEvidence, &'static str> {
    let object = (
        required_text(row, "OBJECT_SCHEMA").ok_or("fga_object_identity_unknown")?,
        required_text(row, "OBJECT_NAME").ok_or("fga_object_identity_unknown")?,
    );
    let policy_name = required_text(row, "POLICY_NAME").ok_or("fga_policy_identity_unknown")?;
    let enabled = fga_flag(row, "ENABLED").ok_or("fga_enabled_flag_unknown")?;
    let applies_to = FgaAppliesTo {
        select: fga_flag(row, "SEL").ok_or("fga_statement_flag_unknown")?,
        insert: fga_flag(row, "INS").ok_or("fga_statement_flag_unknown")?,
        update: fga_flag(row, "UPD").ok_or("fga_statement_flag_unknown")?,
        delete: fga_flag(row, "DEL").ok_or("fga_statement_flag_unknown")?,
    };
    if ["PF_SCHEMA", "PF_PACKAGE", "PF_FUNCTION", "POLICY_TEXT"]
        .iter()
        .any(|name| row.cell(name).is_none())
    {
        return Err("fga_catalog_columns_unknown");
    }
    let schema = optional_text(row, "PF_SCHEMA");
    let package = optional_text(row, "PF_PACKAGE");
    let function = optional_text(row, "PF_FUNCTION");
    let handler = match (schema, package, function) {
        (Some(schema), package, Some(function)) => Some((schema, package, function)),
        (None, None, None) => None,
        _ => return Err("fga_handler_identity_unknown"),
    };
    Ok(FgaPolicyEvidence {
        object,
        policy_name,
        enabled,
        applies_to,
        handler,
        audit_condition: optional_text(row, "POLICY_TEXT"),
    })
}

fn fga_condition_proven_builtin(condition: Option<&str>) -> bool {
    // A null condition is Oracle's unconditional policy. These exact constant
    // forms contain no callable expression. All other text stays unproven:
    // Oracle's audit condition grammar can invoke a user function.
    condition.is_none_or(|text| matches!(text.trim(), "1=1" | "1 = 1"))
}

fn fga_policy_impossible_for_local_sys_object(object: &ResolvedObject) -> bool {
    object.owner == "SYS" && object.db_link.is_none() && object.identity.object_id != 0
}

/// Prove FGA policies cannot invoke user code for the exact resolved objects.
/// An unreadable catalog, malformed row, or a saturated batch is uncertainty.
pub async fn fga_closure(
    cx: &Cx,
    conn: &dyn OracleConnection,
    relations: &[ResolvedObject],
    kind: FgaStatementKind,
) -> FgaClosure {
    // No base object can have an FGA policy. This is a complete structural
    // proof for relationless reads; requiring catalog visibility here would
    // refuse SELECT 1 without increasing safety.
    if relations.is_empty() {
        return FgaClosure::ProvenReadOnly;
    }
    if relations.len() > 256 {
        return FgaClosure::Unknown {
            reason: "fga_relation_cap_exceeded",
        };
    }
    if relations
        .iter()
        .any(|relation| relation.db_link.is_some() || relation.identity.object_id == 0)
    {
        return FgaClosure::Unknown {
            reason: "fga_relation_identity_unknown",
        };
    }
    // Oracle refuses FGA policies on SYS-owned objects. Only exact resolved,
    // local object identities qualify; a synonym targeting another owner is
    // checked under the target owner, and any unresolved identity refused above.
    let policy_eligible = relations
        .iter()
        .filter(|relation| !fga_policy_impossible_for_local_sys_object(relation))
        .collect::<Vec<_>>();
    if policy_eligible.is_empty() {
        return FgaClosure::ProvenReadOnly;
    }
    for chunk in policy_eligible.chunks(32) {
        let mut binds = Vec::with_capacity(64);
        for relation in chunk {
            binds.push(OracleBind::from(relation.owner.as_str()));
            binds.push(OracleBind::from(relation.name.as_str()));
        }
        while binds.len() < 64 {
            binds.push(OracleBind::from(""));
        }
        let rows =
            match run_catalog_query(cx, conn, CatalogQueryId::FgaPoliciesForRelations32, &binds)
                .await
            {
                Ok(rows) => rows,
                Err(_) => {
                    return FgaClosure::Unknown {
                        reason: "fga_catalog_unavailable",
                    };
                }
            };
        if rows.len() >= 257 {
            return FgaClosure::Unknown {
                reason: "fga_evidence_truncated",
            };
        }
        for row in &rows {
            // Oracle cannot run a disabled policy or a policy for a different
            // statement class. Its handler metadata is immaterial in those
            // cases, including a partially populated legacy row.
            let Some(enabled) = fga_flag(row, "ENABLED") else {
                return FgaClosure::Unknown {
                    reason: "fga_enabled_flag_unknown",
                };
            };
            let column = match kind {
                FgaStatementKind::Select => "SEL",
                FgaStatementKind::Insert => "INS",
                FgaStatementKind::Update => "UPD",
                FgaStatementKind::Delete => "DEL",
            };
            let Some(applies) = fga_flag(row, column) else {
                return FgaClosure::Unknown {
                    reason: "fga_statement_flag_unknown",
                };
            };
            if !enabled || !applies {
                continue;
            }
            let policy = match parse_fga_policy(row) {
                Ok(policy) => policy,
                Err(reason) => return FgaClosure::Unknown { reason },
            };
            if !chunk.iter().any(|relation| {
                relation.owner == policy.object.0 && relation.name == policy.object.1
            }) {
                return FgaClosure::Unknown {
                    reason: "fga_object_identity_mismatch",
                };
            }
            debug_assert!(policy.enabled && policy.applies_to.includes(kind));
            if policy.handler.is_some() {
                return FgaClosure::Autonomous { policy };
            }
            if !fga_condition_proven_builtin(policy.audit_condition.as_deref()) {
                return FgaClosure::Unknown {
                    reason: "fga_audit_condition_unknown",
                };
            }
        }
    }
    // A successful empty probe establishes catalog readability even when no
    // FGA policy is visible. ALL_AUDIT_POLICIES covers accessible objects only
    // when the principal can query the view; a failed probe never proves absence.
    if run_catalog_query(cx, conn, CatalogQueryId::FgaCatalogProof, &[])
        .await
        .is_err()
    {
        return FgaClosure::Unknown {
            reason: "fga_catalog_unavailable",
        };
    }
    FgaClosure::ProvenReadOnly
}

/// Why a lexical read plan failed before caller SQL could reach Oracle.
#[derive(Debug)]
pub enum ReadPlanProofError {
    /// A required dictionary read failed.
    Database(DbError),
    /// A base relation had no unique local catalog identity.
    MissingRelation(RawName),
    /// A value was neither a column nor a proven local projection.
    MissingColumn(RawName),
    /// A structural or effect dependency remains unproven.
    Unproven(&'static str),
    /// An enabled FGA handler can execute autonomously on this read.
    FgaHandlerAutonomous,
    /// FGA catalog evidence did not establish absence of user code.
    FgaEvidenceUnknown,
}

/// The full local identity of a catalog relation, including its edition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ReadObjectIdentity {
    owner: String,
    name: String,
    identity: ResolvedIdentity,
}

impl From<&ResolvedObject> for ReadObjectIdentity {
    fn from(object: &ResolvedObject) -> Self {
        Self {
            owner: object.owner.clone(),
            name: object.name.clone(),
            identity: object.identity.clone(),
        }
    }
}

/// A statement-purity oracle bound to the exact syntactic base-object set and
/// every catalog identity proved for each member of that set.
pub struct ReadPlanProof {
    /// Every resolved base relation, retained for consumers that need its identity.
    pub relations: Vec<ResolvedObject>,
    by_source: HashMap<ObjectRef, Vec<ReadObjectIdentity>>,
    by_identity: HashMap<ReadObjectIdentity, Purity>,
    proved_value_columns: HashSet<RawName>,
}

impl SideEffectOracle for ReadPlanProof {
    fn proves_value_column(&self, name: &RawName) -> bool {
        self.proved_value_columns.contains(name)
    }

    fn statement_purity(&self, base_objects: &[ObjectRef]) -> Purity {
        let asked: HashSet<_> = base_objects.iter().collect();
        if asked.len() != self.by_source.len()
            || !asked
                .iter()
                .all(|source| self.by_source.contains_key(*source))
        {
            return Purity::Unknown;
        }
        if self
            .by_source
            .values()
            .flatten()
            .all(|identity| self.by_identity.get(identity) == Some(&Purity::ProvenReadOnly))
        {
            Purity::ProvenReadOnly
        } else {
            Purity::Unknown
        }
    }
}

fn source_object(name: &RawName) -> Option<ObjectRef> {
    let last = name.parts.last()?;
    let schema = (name.parts.len() > 1).then(|| name.parts[name.parts.len() - 2].text.clone());
    Some(ObjectRef::new(schema, last.text.clone()))
}

fn same_session(left: &ResolveCtx, right: &ResolveCtx) -> bool {
    left.connected_schema == right.connected_schema
        && left.current_schema == right.current_schema
        && left.edition == right.edition
        && left.enabled_roles == right.enabled_roles
        && left.generation == right.generation
}

fn same_part(left: &RawNamePart, right: &RawNamePart) -> bool {
    match (left.quoting, right.quoting) {
        (QuoteSemantics::Quoted, QuoteSemantics::Quoted) => left.text == right.text,
        (QuoteSemantics::Unquoted, QuoteSemantics::Unquoted) => {
            left.text.eq_ignore_ascii_case(&right.text)
        }
        _ => false,
    }
}

fn projected_from_local_source(
    plan: &SemanticReadPlan,
    block: &QueryBlock,
    name: &RawName,
) -> bool {
    let (qualifier, column) = match name.parts.as_slice() {
        [column] => (None, column),
        [qualifier, column] => (Some(qualifier), column),
        _ => return false,
    };
    let mut sources = Vec::new();
    let mut visited_ctes = HashSet::new();
    for cte in &block.cte_refs {
        if !visited_ctes.insert((cte.text.clone(), cte.quoting)) {
            continue;
        }
        let mut scope = Some(block.id);
        while let Some(id) = scope {
            if let Some((_, definition)) = plan.blocks[id.0]
                .cte_definitions
                .iter()
                .find(|(alias, _)| same_part(alias, cte))
            {
                let aliases = block
                    .cte_source_aliases
                    .iter()
                    .filter(|(source, _)| same_part(source, cte))
                    .map(|(_, alias)| alias)
                    .collect::<Vec<_>>();
                for alias in &aliases {
                    sources.push((*alias, *definition));
                }
                let references = block
                    .cte_refs
                    .iter()
                    .filter(|source| same_part(source, cte))
                    .count();
                if references > aliases.len() {
                    sources.push((cte, *definition));
                }
                break;
            }
            scope = plan.blocks[id.0].parent;
        }
    }
    sources.extend(block.derived_sources.iter().map(|(alias, id)| (alias, *id)));
    let matching = sources
        .into_iter()
        .filter(|(alias, id)| {
            qualifier.is_none_or(|part| same_part(part, alias))
                && plan.blocks[id.0]
                    .projected_columns
                    .iter()
                    .any(|part| same_part(part, column))
        })
        .count();
    matching == 1 && (qualifier.is_some() || block.statement_scope.relations.is_empty())
}

/// Resolve every lexical block in its own scope, then bind the recursive
/// classifier's base-object consult to the exact identities just proved.
pub async fn prove_semantic_read_plan(
    cx: &Cx,
    conn: &dyn OracleConnection,
    cache: &OracleCatalogResolverCache,
    plan: &SemanticReadPlan,
) -> Result<ReadPlanProof, ReadPlanProofError> {
    if plan.blocks.len() > 128 || plan.relations.len() > 256 {
        return Err(ReadPlanProofError::Unproven("relation_plan_cap_exceeded"));
    }
    if plan
        .blocks
        .iter()
        .any(|block| block.kind == QueryBlockKind::TableFunction)
    {
        return Err(ReadPlanProofError::Unproven(
            "table-function callee has no complete routine effect proof",
        ));
    }
    cache.invalidate(CatalogInvalidation::SemanticProofRefresh);
    let mut session: Option<ResolveCtx> = None;
    let mut contexts = Vec::with_capacity(plan.blocks.len());
    for block in &plan.blocks {
        let mut names = block.relations.clone();
        names.extend(
            block
                .values
                .iter()
                .filter(|name| {
                    !projected_from_local_source(plan, block, name)
                        && !block.correlated_outer_refs.contains(name)
                })
                .cloned(),
        );
        let mut context = None;
        for chunk in names.chunks(MAX_CATALOG_NAMES) {
            let loaded = cache
                .preload(cx, conn, chunk, block.statement_scope.clone())
                .await
                .map_err(ReadPlanProofError::Database)?;
            if session
                .as_ref()
                .is_some_and(|first| !same_session(first, &loaded))
                || context
                    .as_ref()
                    .is_some_and(|first| !same_session(first, &loaded))
            {
                return Err(ReadPlanProofError::Unproven(
                    "session context changed during proof",
                ));
            }
            session.get_or_insert_with(|| loaded.clone());
            context = Some(loaded);
        }
        if context.is_none() {
            let loaded = cache
                .preload(cx, conn, &[], block.statement_scope.clone())
                .await
                .map_err(ReadPlanProofError::Database)?;
            if session
                .as_ref()
                .is_some_and(|first| !same_session(first, &loaded))
            {
                return Err(ReadPlanProofError::Unproven(
                    "session context changed during proof",
                ));
            }
            session.get_or_insert_with(|| loaded.clone());
            context = Some(loaded);
        }
        contexts.push(context.expect("every block has a context"));
    }
    let mut relations = Vec::new();
    let mut by_source: HashMap<ObjectRef, Vec<ReadObjectIdentity>> = HashMap::new();
    for (block, context) in plan.blocks.iter().zip(&contexts) {
        for name in &block.relations {
            let Resolution::Resolved(object) = cache.resolve(name, context) else {
                return Err(ReadPlanProofError::MissingRelation(name.clone()));
            };
            let source =
                source_object(name).ok_or(ReadPlanProofError::Unproven("empty relation name"))?;
            by_source
                .entry(source)
                .or_default()
                .push(ReadObjectIdentity::from(object.as_ref()));
            relations.push(*object);
        }
    }
    match fga_closure(cx, conn, &relations, FgaStatementKind::Select).await {
        FgaClosure::ProvenReadOnly => {}
        FgaClosure::Autonomous { .. } => return Err(ReadPlanProofError::FgaHandlerAutonomous),
        FgaClosure::Unknown { .. } => return Err(ReadPlanProofError::FgaEvidenceUnknown),
    }
    let values = plan
        .blocks
        .iter()
        .flat_map(|block| block.values.iter().cloned())
        .collect::<Vec<_>>();
    let purity = resolved_relations_read_purity(cx, conn, &relations, &values)
        .await
        .map_err(ReadPlanProofError::Database)?;
    if !purity.permits_safe() {
        return Err(ReadPlanProofError::Unproven(
            "a relation can invoke an unproven view, policy, or virtual-column dependency",
        ));
    }
    let mut proved_value_columns = HashSet::new();
    for (block, context) in plan.blocks.iter().zip(&contexts) {
        for name in &block.values {
            if projected_from_local_source(plan, block, name) {
                continue;
            }
            let known_outer = block.correlated_outer_refs.contains(name);
            if !known_outer {
                let current = cache.resolve(name, context);
                if let Resolution::Resolved(object) = current {
                    if object.kind == CatalogObjectKind::Column {
                        proved_value_columns.insert(name.clone());
                        continue;
                    }
                    return Err(ReadPlanProofError::Unproven(
                        "a value identifier resolves to executable code rather than a column",
                    ));
                }
                if !matches!(current, Resolution::Unresolved) {
                    return Err(ReadPlanProofError::Unproven(
                        "ambiguous or remote value identifier",
                    ));
                }
            }
            if block.parent.is_some() {
                let mut ancestor = block.parent;
                while let Some(id) = ancestor {
                    let outer = &plan.blocks[id.0];
                    if projected_from_local_source(plan, outer, name) {
                        break;
                    }
                    let outer_context = cache
                        .preload(
                            cx,
                            conn,
                            std::slice::from_ref(name),
                            outer.statement_scope.clone(),
                        )
                        .await
                        .map_err(ReadPlanProofError::Database)?;
                    if !same_session(&contexts[id.0], &outer_context) {
                        return Err(ReadPlanProofError::Unproven(
                            "session context changed during proof",
                        ));
                    }
                    if let Resolution::Resolved(object) = cache.resolve(name, &outer_context)
                        && object.kind == CatalogObjectKind::Column
                    {
                        proved_value_columns.insert(name.clone());
                        break;
                    }
                    ancestor = outer.parent;
                }
                if ancestor.is_some() {
                    continue;
                }
            }
            return Err(ReadPlanProofError::MissingColumn(name.clone()));
        }
    }
    let by_identity = relations
        .iter()
        .map(|object| (ReadObjectIdentity::from(object), Purity::ProvenReadOnly))
        .collect();
    Ok(ReadPlanProof {
        relations,
        by_source,
        by_identity,
        proved_value_columns,
    })
}

impl OracleCatalogResolver {
    /// Resolve one local routine call against a live, exact session context.
    /// No matching or ambiguous overload yields no identity. The caller must
    /// still obtain an independent complete effect proof for this identity.
    pub async fn resolve_routine_call(
        cx: &Cx,
        conn: &dyn OracleConnection,
        candidate: &RoutineRef,
        arguments: &[RoutineArgument],
        context: &ResolveCtx,
    ) -> Result<Option<RoutineRef>, DbError> {
        if arguments.len() > 128
            || read_catalog_resolve_context(
                cx,
                conn,
                context.generation,
                context.statement_scope.clone(),
            )
            .await?
                != *context
        {
            return Ok(None);
        }
        let lookup = DictionaryLookup { cx, conn, context };
        let current = context.current_schema.as_str();
        let result = match (&candidate.schema, &candidate.package) {
            (Some(owner), Some(package)) => {
                lookup
                    .exact_routine(
                        owner.text.as_str(),
                        Some(package.text.as_str()),
                        candidate.member.text.as_str(),
                        false,
                        arguments,
                    )
                    .await?
            }
            (Some(owner), None) => {
                lookup
                    .exact_routine(
                        owner.text.as_str(),
                        None,
                        candidate.member.text.as_str(),
                        false,
                        arguments,
                    )
                    .await?
            }
            (None, Some(first)) => {
                let standalone = lookup
                    .exact_routine(
                        first.text.as_str(),
                        None,
                        candidate.member.text.as_str(),
                        false,
                        arguments,
                    )
                    .await?;
                let packaged = lookup
                    .exact_routine(
                        current,
                        Some(first.text.as_str()),
                        candidate.member.text.as_str(),
                        true,
                        arguments,
                    )
                    .await?;
                match (standalone, packaged) {
                    (Some(_), Some(_)) => None,
                    (Some(one), None) | (None, Some(one)) => Some(one),
                    (None, None) => None,
                }
            }
            (None, None) => {
                lookup
                    .exact_routine(
                        current,
                        None,
                        candidate.member.text.as_str(),
                        true,
                        arguments,
                    )
                    .await?
            }
        };
        Ok(result)
    }

    /// Load bounded dictionary evidence for `names` using `conn`.
    ///
    /// The connection's session user, current schema, edition, and enabled
    /// roles must exactly match `context`. A mismatch produces an empty,
    /// fail-closed snapshot rather than attaching evidence from another
    /// session context. Dictionary query failures are returned to the caller;
    /// incomplete individual answers are stored as [`Resolution::Unresolved`].
    pub async fn load(
        cx: &Cx,
        conn: &dyn OracleConnection,
        names: &[RawName],
        context: &ResolveCtx,
    ) -> Result<Self, DbError> {
        if names.len() > MAX_CATALOG_NAMES {
            return Err(DbError::Query(format!(
                "catalog resolver name cap exceeded: {} > {MAX_CATALOG_NAMES}",
                names.len()
            )));
        }

        let live = read_catalog_resolve_context(
            cx,
            conn,
            context.generation,
            context.statement_scope.clone(),
        )
        .await?;
        if live != *context {
            return Ok(Self {
                context: context.clone(),
                entries: HashMap::new(),
            });
        }

        let lookup = DictionaryLookup { cx, conn, context };
        let mut entries = HashMap::with_capacity(names.len());
        for name in names {
            if entries.contains_key(name) {
                continue;
            }
            let resolution = lookup.resolve_name(name).await?;
            entries.insert(name.clone(), resolution);
        }
        Ok(Self {
            context: context.clone(),
            entries,
        })
    }

    /// Number of distinct syntactic names loaded into this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether this resolver contains no dictionary answers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl CatalogResolver for OracleCatalogResolver {
    fn resolve(&self, name: &RawName, context: &ResolveCtx) -> Resolution {
        if context != &self.context {
            return Resolution::Unresolved;
        }
        self.entries
            .get(name)
            .cloned()
            .unwrap_or(Resolution::Unresolved)
    }
}

/// Read the live session inputs needed to construct a truthful resolver
/// context. `generation` remains consumer-owned and `statement_scope` remains
/// parser-owned; every other field is obtained from the Oracle session.
pub async fn read_catalog_resolve_context(
    cx: &Cx,
    conn: &dyn OracleConnection,
    generation: oraclemcp_guard::CatalogGeneration,
    statement_scope: StatementScope,
) -> Result<ResolveCtx, DbError> {
    let session = read_session_security_context(cx, conn).await?;
    Ok(ResolveCtx {
        connected_schema: session.session_user,
        current_schema: session.current_schema,
        edition: session.edition_name,
        enabled_roles: session.enabled_roles.into_iter().collect(),
        statement_scope,
        generation,
    })
}

/// Read the live session security inputs that affect dictionary visibility and
/// VPD/RLS diagnosis.
pub async fn read_session_security_context(
    cx: &Cx,
    conn: &dyn OracleConnection,
) -> Result<OracleSessionSecurityContext, DbError> {
    let rows = run_catalog_query(cx, conn, CatalogQueryId::SessionContext, &[]).await?;
    let [row] = rows.as_slice() else {
        return Err(DbError::Query(
            "catalog resolver session context query returned an incomplete answer".to_owned(),
        ));
    };
    let Some(connected_schema) = required_text(row, "SESSION_USER") else {
        return Err(DbError::Query(
            "catalog resolver session user was missing".to_owned(),
        ));
    };
    let Some(current_schema) = required_text(row, "CURRENT_SCHEMA") else {
        return Err(DbError::Query(
            "catalog resolver current schema was missing".to_owned(),
        ));
    };
    let Some(edition) = required_text(row, "EDITION_NAME") else {
        return Err(DbError::Query(
            "catalog resolver current edition was missing".to_owned(),
        ));
    };

    let role_rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::SessionRoles,
        &[OracleBind::from((MAX_SESSION_ROLES + 1) as i64)],
    )
    .await?;
    if role_rows.len() > MAX_SESSION_ROLES {
        return Err(DbError::Query(format!(
            "catalog resolver enabled-role cap exceeded: more than {MAX_SESSION_ROLES}"
        )));
    }
    let mut enabled_roles = Vec::new();
    for row in &role_rows {
        let Some(role) = required_text(row, "ROLE") else {
            return Err(DbError::Query(
                "catalog resolver enabled-role row was incomplete".to_owned(),
            ));
        };
        enabled_roles.push(role);
    }
    enabled_roles.sort();
    enabled_roles.dedup();
    Ok(OracleSessionSecurityContext {
        session_user: connected_schema,
        current_schema,
        edition_name: Some(edition),
        enabled_roles,
    })
}

/// Observe VPD/RLS policies visible for a schema. Empty policy rows are reported
/// as an observation boundary, not as proof that no protected objects exist.
pub async fn observe_vpd_rls_for_schema(
    cx: &Cx,
    conn: &dyn OracleConnection,
    schema: &str,
) -> OracleVpdRlsObservation {
    let session = read_session_security_context(cx, conn).await.ok();
    let schema = if schema.trim().is_empty() {
        session
            .as_ref()
            .map(|session| session.current_schema.as_str())
            .unwrap_or("")
    } else {
        schema
    };
    let schema = schema.to_ascii_uppercase();
    let scope = format!("schema:{schema}");
    let (policies, policy_error) = query_vpd_rls_policies(
        cx,
        conn,
        VPD_RLS_POLICY_BY_SCHEMA_SQL,
        &[
            OracleBind::from(schema),
            OracleBind::from((MAX_VPD_RLS_POLICY_ROWS + 1) as i64),
        ],
    )
    .await;
    let probe = query_policy_catalog_probe(cx, conn).await;
    build_vpd_rls_observation(scope, session, probe, policies, policy_error)
}

/// Observe VPD/RLS policies visible for resolved query relations. Empty policy
/// rows are reported as an observation boundary, not as proof of absence.
pub async fn observe_vpd_rls_for_relations(
    cx: &Cx,
    conn: &dyn OracleConnection,
    relations: &[ResolvedObject],
) -> OracleVpdRlsObservation {
    let session = read_session_security_context(cx, conn).await.ok();
    let mut policies = Vec::new();
    let mut policy_error = None;
    let mut seen = BTreeSet::new();
    for relation in relations {
        if relation.db_link.is_some()
            || !seen.insert((relation.owner.clone(), relation.name.clone()))
        {
            continue;
        }
        let (mut rows, error) = query_vpd_rls_policies(
            cx,
            conn,
            VPD_RLS_POLICY_BY_OBJECT_SQL,
            &[
                OracleBind::from(relation.owner.as_str()),
                OracleBind::from(relation.name.as_str()),
                OracleBind::from((MAX_VPD_RLS_POLICY_ROWS + 1) as i64),
            ],
        )
        .await;
        policies.append(&mut rows);
        if error.is_some() {
            policy_error = error;
            break;
        }
        if policies.len() > MAX_VPD_RLS_POLICY_ROWS {
            policies.truncate(MAX_VPD_RLS_POLICY_ROWS);
            break;
        }
    }
    let probe = query_policy_catalog_probe(cx, conn).await;
    build_vpd_rls_observation(
        "relations".to_owned(),
        session,
        probe,
        policies,
        policy_error,
    )
}

struct DictionaryLookup<'a> {
    cx: &'a Cx,
    conn: &'a dyn OracleConnection,
    context: &'a ResolveCtx,
}

impl DictionaryLookup<'_> {
    async fn exact_routine(
        &self,
        owner: &str,
        package: Option<&str>,
        member: &str,
        allow_public: bool,
        arguments: &[RoutineArgument],
    ) -> Result<Option<RoutineRef>, DbError> {
        let object_name = package.unwrap_or(member);
        let walked = self
            .walk_synonyms(owner, object_name, allow_public, |kind| {
                if package.is_some() {
                    matches!(kind, CatalogObjectKind::Package)
                } else {
                    matches!(
                        kind,
                        CatalogObjectKind::Procedure | CatalogObjectKind::Function
                    )
                }
            })
            .await?;
        let WalkResult::Objects { objects, .. } = walked else {
            return Ok(None);
        };
        let [object] = objects.as_slice() else {
            return Ok(None);
        };
        let binds = if package.is_some() {
            vec![
                OracleBind::from(object.owner.as_str()),
                OracleBind::from(object.name.as_str()),
                OracleBind::from(member),
                OracleBind::from((MAX_CANDIDATES + 1) as i64),
            ]
        } else {
            vec![
                OracleBind::from(object.owner.as_str()),
                OracleBind::from(object.name.as_str()),
                OracleBind::from((MAX_CANDIDATES + 1) as i64),
            ]
        };
        let query = if package.is_some() {
            CatalogQueryId::MemberProcedures
        } else {
            CatalogQueryId::StandaloneProcedures
        };
        let rows = run_catalog_query(self.cx, self.conn, query, &binds).await?;
        if rows.is_empty() || rows.len() > MAX_CANDIDATES {
            return Ok(None);
        }
        let Some(facts) = self
            .argument_rows(
                &object.owner,
                package.map(|_| object.name.as_str()),
                if package.is_some() {
                    member
                } else {
                    &object.name
                },
            )
            .await?
        else {
            return Ok(None);
        };
        let mut matches = Vec::new();
        for row in &rows {
            let Some(id) = row
                .parse_i64("SUBPROGRAM_ID")
                .and_then(|id| u32::try_from(id).ok())
            else {
                return Ok(None);
            };
            let overload = optional_text(row, "OVERLOAD");
            let params: Vec<_> = facts
                .iter()
                .filter(|fact| fact.subprogram_id == id && fact.overload == overload)
                .collect();
            if routine_arguments_match(&params, arguments) {
                matches.push(id);
            }
        }
        if matches.len() != 1 {
            return Ok(None);
        }
        Ok(Some(RoutineRef {
            schema: Some(RoutineIdentifier::new(&object.owner, true)),
            package: package.map(|_| RoutineIdentifier::new(&object.name, true)),
            member: RoutineIdentifier::new(
                if package.is_some() {
                    member
                } else {
                    &object.name
                },
                true,
            ),
            overload: Some(matches[0]),
        }))
    }

    async fn resolve_name(&self, raw: &RawName) -> Result<Resolution, DbError> {
        if let Some(db_link) = &raw.db_link {
            return Ok(Resolution::Remote {
                db_link: db_link.clone(),
            });
        }
        let Some(parts) = normalize_parts(&raw.parts) else {
            return Ok(Resolution::Unresolved);
        };
        if parts.is_empty() {
            return Ok(Resolution::Unresolved);
        }

        match raw.role {
            SyntacticRole::FromFactor if !self.references_statement_scope(raw) => {
                self.resolve_from(raw, &parts).await
            }
            SyntacticRole::CallWithArgs if !self.references_statement_scope(raw) => {
                self.resolve_callable(raw, &parts, false).await
            }
            SyntacticRole::ValuePosition => self.resolve_value(raw, &parts).await,
            _ => Ok(Resolution::Unresolved),
        }
    }

    async fn resolve_value(&self, raw: &RawName, parts: &[String]) -> Result<Resolution, DbError> {
        let relations = &self.context.statement_scope.relations;
        if parts.len() >= 3 {
            let aliased = relations
                .iter()
                .filter(|relation| {
                    relation.alias.is_some() && relation_matches_qualifier(relation, &parts[0])
                })
                .collect::<Vec<_>>();
            if !aliased.is_empty() {
                return if let [relation] = aliased.as_slice() {
                    self.resolve_dotted_value_path(relation, raw, parts).await
                } else {
                    Ok(Resolution::Unresolved)
                };
            }
        }
        let (candidate_relations, column, relation_qualified) = match parts {
            [column] => (relations.iter().collect::<Vec<_>>(), column.as_str(), false),
            [qualifier, column] => {
                let matching = relations
                    .iter()
                    .filter(|relation| relation_matches_qualifier(relation, qualifier))
                    .collect::<Vec<_>>();
                let relation_qualified = !matching.is_empty();
                (matching, column.as_str(), relation_qualified)
            }
            [owner, relation_name, column] => {
                let mut matching = Vec::new();
                let explicit = RawName::new(raw.parts[..2].to_vec(), SyntacticRole::FromFactor);
                let Some(explicit_parts) = normalize_parts(&explicit.parts) else {
                    return Ok(Resolution::Unresolved);
                };
                let explicit_identity = match self.resolve_from(&explicit, &explicit_parts).await? {
                    Resolution::Resolved(object) => Some(*object),
                    _ => None,
                };
                for relation in relations {
                    if relation.alias.is_some() {
                        continue;
                    }
                    if relation.name.parts.len() == 2
                        && !relation_matches_owner_name(relation, owner, relation_name)
                    {
                        continue;
                    }
                    let Some(relation_parts) = normalize_parts(&relation.name.parts) else {
                        continue;
                    };
                    if let (Some(expected), Resolution::Resolved(actual)) = (
                        explicit_identity.as_ref(),
                        self.resolve_from(&relation.name, &relation_parts).await?,
                    ) && resolved_relation_identity_matches(expected, &actual)
                    {
                        matching.push(relation);
                    }
                }
                let relation_qualified = !matching.is_empty();
                (matching, column.as_str(), relation_qualified)
            }
            _ => (Vec::new(), "", false),
        };
        let qualified_merge = parts.len() > 1
            && self
                .context
                .statement_scope
                .merged_joins
                .iter()
                .any(|merge| {
                    merge.using_columns.is_some()
                        && merged_join_contains_column(merge, column)
                        && candidate_relations
                            .iter()
                            .any(|relation| **relation == merge.left || **relation == merge.right)
                });
        if qualified_merge {
            return Ok(Resolution::Unresolved);
        }
        let mut columns = Vec::new();
        for relation in &candidate_relations {
            if let Some(column) = self.resolve_relation_column(relation, column, raw).await? {
                columns.push(((*relation).clone(), column));
            }
        }
        for merge in self
            .context
            .statement_scope
            .merged_joins
            .iter()
            .filter(|merge| merged_join_contains_column(merge, column))
        {
            let left = columns
                .iter()
                .position(|(relation, _)| *relation == merge.left);
            let right = columns
                .iter()
                .position(|(relation, _)| *relation == merge.right);
            if parts.len() == 1
                && let (Some(left), Some(_right)) = (left, right)
                && columns.len() == 2
            {
                return Ok(Resolution::Resolved(Box::new(columns.remove(left).1)));
            }
            if merge.using_columns.is_some()
                && parts.len() == 1
                && (left.is_some() || right.is_some())
            {
                return Ok(Resolution::Unresolved);
            }
            if merge.using_columns.is_none() && parts.len() > 1 {
                let counterpart = if left.is_some() {
                    Some(&merge.right)
                } else if right.is_some() {
                    Some(&merge.left)
                } else {
                    None
                };
                if let Some(counterpart) = counterpart
                    && self
                        .resolve_relation_column(counterpart, column, raw)
                        .await?
                        .is_some()
                {
                    return Ok(Resolution::Unresolved);
                }
            }
        }
        match columns.len() {
            1 => return Ok(Resolution::Resolved(Box::new(columns.remove(0).1))),
            2.. => {
                return Ok(Resolution::Ambiguous {
                    candidates: columns
                        .into_iter()
                        .map(|(_, column)| column.identity)
                        .collect(),
                });
            }
            _ => {}
        }
        if relation_qualified {
            // A visible relation qualifier shadows a package/schema name. A
            // missing column is not permission to reinterpret `alias.member`
            // as a zero-argument routine.
            return Ok(Resolution::Unresolved);
        }
        if parts.len() == 1 && self.has_column_conflict(&parts[0]).await? {
            return Ok(Resolution::Unresolved);
        }
        self.resolve_callable(raw, parts, true).await
    }

    async fn resolve_dotted_value_path(
        &self,
        relation: &oraclemcp_guard::StatementRelation,
        raw: &RawName,
        parts: &[String],
    ) -> Result<Resolution, DbError> {
        let Some(column) = self
            .resolve_relation_column(relation, &parts[1], raw)
            .await?
        else {
            return Ok(Resolution::Unresolved);
        };
        let Some(container) = column.container.as_ref() else {
            return Ok(Resolution::Unresolved);
        };
        let type_rows = run_catalog_query(
            self.cx,
            self.conn,
            CatalogQueryId::ColumnPathType,
            &[
                OracleBind::from(column.owner.as_str()),
                OracleBind::from(container.name.as_str()),
                OracleBind::from(column.name.as_str()),
            ],
        )
        .await?;
        let [type_row] = type_rows.as_slice() else {
            return Ok(Resolution::Unresolved);
        };
        let Some(data_type) = required_text(type_row, "DATA_TYPE") else {
            return Ok(Resolution::Unresolved);
        };
        if data_type == "JSON" {
            return Ok(Resolution::Resolved(Box::new(column)));
        }
        if matches!(data_type.as_str(), "VARCHAR2" | "CLOB" | "BLOB") {
            let binds = [
                OracleBind::from(column.owner.as_str()),
                OracleBind::from(container.name.as_str()),
                OracleBind::from(column.name.as_str()),
            ];
            let json_rows =
                run_catalog_query(self.cx, self.conn, CatalogQueryId::JsonColumn, &binds).await?;
            if json_rows.len() != 1
                || json_rows[0].text("COLUMN_NAME") != Some(column.name.as_str())
            {
                return Ok(Resolution::Unresolved);
            }
            // ALL_JSON_COLUMNS retains a text column after its check is
            // disabled. Require a separate enabled, validated exact check.
            let constraints =
                run_catalog_query(self.cx, self.conn, CatalogQueryId::JsonConstraint, &binds)
                    .await?;
            return if constraints.len() < 65
                && constraints.iter().any(|row| {
                    row.text("SEARCH_CONDITION_VC")
                        .is_some_and(|condition| exact_is_json_check(condition, &column.name))
                }) {
                Ok(Resolution::Resolved(Box::new(column)))
            } else {
                Ok(Resolution::Unresolved)
            };
        }
        let Some(mut type_owner) = required_text(type_row, "DATA_TYPE_OWNER") else {
            return Ok(Resolution::Unresolved);
        };
        let mut type_name = data_type;
        for (index, attribute) in parts[2..].iter().enumerate() {
            let rows = run_catalog_query(
                self.cx,
                self.conn,
                CatalogQueryId::TypeAttribute,
                &[
                    OracleBind::from(type_owner.as_str()),
                    OracleBind::from(type_name.as_str()),
                    OracleBind::from(attribute.as_str()),
                ],
            )
            .await?;
            let [attr_row] = rows.as_slice() else {
                return Ok(Resolution::Unresolved);
            };
            if attr_row.text("ATTR_NAME") != Some(attribute.as_str())
                || optional_text(attr_row, "ATTR_TYPE_MOD").is_some()
            {
                // REF attributes and any unknown modifier may dereference or
                // invoke code; neither is a plain stored attribute chain.
                return Ok(Resolution::Unresolved);
            }
            if index + 1 < parts.len() - 2 {
                let Some(next_owner) = required_text(attr_row, "ATTR_TYPE_OWNER") else {
                    return Ok(Resolution::Unresolved);
                };
                let Some(next_type) = required_text(attr_row, "ATTR_TYPE_NAME") else {
                    return Ok(Resolution::Unresolved);
                };
                type_owner = next_owner;
                type_name = next_type;
            }
        }
        Ok(Resolution::Resolved(Box::new(column)))
    }

    async fn resolve_relation_column(
        &self,
        relation: &oraclemcp_guard::StatementRelation,
        column: &str,
        raw: &RawName,
    ) -> Result<Option<ResolvedObject>, DbError> {
        let Some(relation_parts) = normalize_parts(&relation.name.parts) else {
            return Ok(None);
        };
        let Resolution::Resolved(object) =
            self.resolve_from(&relation.name, &relation_parts).await?
        else {
            return Ok(None);
        };
        let rows = run_catalog_query(
            self.cx,
            self.conn,
            CatalogQueryId::RelationColumn,
            &[
                OracleBind::from(object.owner.as_str()),
                OracleBind::from(object.name.as_str()),
                OracleBind::from(column),
            ],
        )
        .await?;
        if rows.len() != 1 || rows[0].parse_i64("COLUMN_ID").is_none() {
            return Ok(None);
        }
        Ok(Some(ResolvedObject {
            owner: object.owner.clone(),
            name: column.to_owned(),
            kind: CatalogObjectKind::Column,
            container: Some(ResolvedContainer {
                name: object.name.clone(),
                kind: object.kind.clone(),
            }),
            member: None,
            overloads: Vec::new(),
            quote_exact: raw
                .parts
                .last()
                .is_some_and(|part| part.quoting == QuoteSemantics::Quoted),
            synonym_chain: object.synonym_chain.clone(),
            db_link: None,
            identity: object.identity.clone(),
        }))
    }

    fn references_statement_scope(&self, raw: &RawName) -> bool {
        let Some(first) = raw.parts.first() else {
            return false;
        };
        self.context
            .statement_scope
            .aliases
            .iter()
            .chain(self.context.statement_scope.common_table_expressions.iter())
            .any(|local| parts_equal(first, local))
    }

    async fn resolve_from(&self, raw: &RawName, parts: &[String]) -> Result<Resolution, DbError> {
        let (owner, name, allow_public) = match parts {
            [name] => (self.context.current_schema.as_str(), name.as_str(), true),
            [owner, name] => (owner.as_str(), name.as_str(), false),
            _ => return Ok(Resolution::Unresolved),
        };
        self.resolve_object(owner, name, raw, allow_public, ObjectPurpose::From)
            .await
    }

    async fn resolve_callable(
        &self,
        raw: &RawName,
        parts: &[String],
        zero_arg_only: bool,
    ) -> Result<Resolution, DbError> {
        match parts {
            [name] => {
                self.resolve_object(
                    &self.context.current_schema,
                    name,
                    raw,
                    true,
                    ObjectPurpose::Callable { zero_arg_only },
                )
                .await
            }
            [first, second] => {
                let standalone = self
                    .resolve_object(
                        first,
                        second,
                        raw,
                        false,
                        ObjectPurpose::Callable { zero_arg_only },
                    )
                    .await?;
                let member = self
                    .resolve_member(
                        &self.context.current_schema,
                        first,
                        second,
                        raw,
                        true,
                        zero_arg_only,
                    )
                    .await?;
                Ok(merge_alternatives(standalone, member))
            }
            [owner, container, member] => {
                self.resolve_member(owner, container, member, raw, false, zero_arg_only)
                    .await
            }
            _ => Ok(Resolution::Unresolved),
        }
    }

    async fn resolve_object(
        &self,
        owner: &str,
        name: &str,
        raw: &RawName,
        allow_public: bool,
        purpose: ObjectPurpose,
    ) -> Result<Resolution, DbError> {
        let walked = self
            .walk_synonyms(owner, name, allow_public, |kind| purpose.accepts(kind))
            .await?;
        let WalkResult::Objects {
            objects,
            synonym_chain,
        } = walked
        else {
            return Ok(walked.into_resolution());
        };
        self.finish_objects(objects, synonym_chain, raw, purpose)
            .await
    }

    async fn resolve_member(
        &self,
        owner: &str,
        container: &str,
        member: &str,
        raw: &RawName,
        allow_public: bool,
        zero_arg_only: bool,
    ) -> Result<Resolution, DbError> {
        let walked = self
            .walk_synonyms(owner, container, allow_public, |kind| {
                matches!(kind, CatalogObjectKind::Package | CatalogObjectKind::Type)
            })
            .await?;
        let WalkResult::Objects {
            objects,
            synonym_chain,
        } = walked
        else {
            return Ok(walked.into_resolution());
        };
        if objects.len() != 1 {
            return Ok(ambiguous_objects(&objects));
        }
        let object = &objects[0];
        let Some(arguments) = self
            .argument_rows(&object.owner, Some(&object.name), member)
            .await?
        else {
            return Ok(Resolution::Unresolved);
        };
        let Some(callable) = callable_overloads(&arguments, zero_arg_only) else {
            return Ok(Resolution::Unresolved);
        };
        if callable.overloads.is_empty() {
            return Ok(Resolution::Unresolved);
        }
        Ok(Resolution::Resolved(Box::new(ResolvedObject {
            owner: object.owner.clone(),
            name: member.to_owned(),
            kind: callable.kind,
            container: Some(ResolvedContainer {
                name: object.name.clone(),
                kind: object.kind.clone(),
            }),
            member: Some(member.to_owned()),
            overloads: callable.overloads,
            quote_exact: raw
                .parts
                .iter()
                .any(|part| part.quoting == QuoteSemantics::Quoted),
            synonym_chain,
            db_link: None,
            identity: object.identity.clone(),
        })))
    }

    async fn finish_objects(
        &self,
        objects: Vec<ObjectFact>,
        synonym_chain: Vec<SynonymHop>,
        raw: &RawName,
        purpose: ObjectPurpose,
    ) -> Result<Resolution, DbError> {
        if objects.len() != 1 {
            return Ok(ambiguous_objects(&objects));
        }
        let object = &objects[0];
        let overloads = if let ObjectPurpose::Callable { zero_arg_only } = purpose {
            let Some(arguments) = self
                .argument_rows(&object.owner, None, &object.name)
                .await?
            else {
                return Ok(Resolution::Unresolved);
            };
            let Some(callable) = callable_overloads(&arguments, zero_arg_only) else {
                return Ok(Resolution::Unresolved);
            };
            if callable.kind != object.kind || (zero_arg_only && callable.overloads.is_empty()) {
                return Ok(Resolution::Unresolved);
            }
            callable.overloads
        } else {
            Vec::new()
        };
        Ok(Resolution::Resolved(Box::new(ResolvedObject {
            owner: object.owner.clone(),
            name: object.name.clone(),
            kind: object.kind.clone(),
            container: None,
            member: None,
            overloads,
            quote_exact: raw
                .parts
                .iter()
                .any(|part| part.quoting == QuoteSemantics::Quoted),
            synonym_chain,
            db_link: None,
            identity: object.identity.clone(),
        })))
    }

    async fn walk_synonyms<F>(
        &self,
        owner: &str,
        name: &str,
        allow_public: bool,
        accepts: F,
    ) -> Result<WalkResult, DbError>
    where
        F: Fn(&CatalogObjectKind) -> bool,
    {
        let mut owner = owner.to_owned();
        let mut name = name.to_owned();
        let mut permit_public = allow_public;
        let mut chain = Vec::new();
        let mut visited = HashSet::new();

        loop {
            if !record_synonym_visit(&mut visited, &owner, &name, chain.len()) {
                return Ok(WalkResult::Unresolved);
            }
            let facts = self.object_rows(&owner, &name).await?;
            if facts.incomplete {
                return Ok(WalkResult::Unresolved);
            }
            if !facts.objects.is_empty() {
                let accepted: Vec<_> = facts
                    .objects
                    .into_iter()
                    .filter(|object| accepts(&object.kind))
                    .collect();
                if accepted.is_empty() {
                    return Ok(WalkResult::Unresolved);
                }
                return Ok(WalkResult::Objects {
                    objects: accepted,
                    synonym_chain: chain,
                });
            }

            let mut synonym = self.synonym_row(&owner, &name).await?;
            if synonym.is_none() && permit_public && owner != "PUBLIC" {
                synonym = self.synonym_row("PUBLIC", &name).await?;
            }
            permit_public = false;
            let Some(synonym) = synonym else {
                return Ok(WalkResult::Unresolved);
            };
            let Some(identity) = synonym.identity else {
                return Ok(WalkResult::Unresolved);
            };
            chain.push(SynonymHop {
                owner: synonym.owner,
                name: synonym.name,
                identity,
            });
            if let Some(db_link) = synonym.db_link {
                return Ok(WalkResult::Remote {
                    db_link: RawNamePart::quoted(db_link),
                });
            }
            owner = synonym.target_owner;
            name = synonym.target_name;
        }
    }

    async fn object_rows(&self, owner: &str, name: &str) -> Result<ObjectFacts, DbError> {
        let rows = run_catalog_query(
            self.cx,
            self.conn,
            CatalogQueryId::Objects,
            &[
                OracleBind::from(owner),
                OracleBind::from(name),
                OracleBind::from((MAX_CANDIDATES + 1) as i64),
            ],
        )
        .await?;
        if rows.len() > MAX_CANDIDATES {
            return Ok(ObjectFacts {
                objects: Vec::new(),
                incomplete: true,
            });
        }
        let mut objects = Vec::new();
        for row in &rows {
            let Some(object) = ObjectFact::from_row(row, self.context) else {
                return Ok(ObjectFacts {
                    objects: Vec::new(),
                    incomplete: true,
                });
            };
            if object.kind != CatalogObjectKind::Synonym {
                objects.push(object);
            }
        }
        Ok(ObjectFacts {
            objects,
            incomplete: false,
        })
    }

    async fn synonym_row(&self, owner: &str, name: &str) -> Result<Option<SynonymFact>, DbError> {
        let rows = run_catalog_query(
            self.cx,
            self.conn,
            CatalogQueryId::Synonyms,
            &[
                OracleBind::from(owner),
                OracleBind::from(name),
                OracleBind::from(2_i64),
            ],
        )
        .await?;
        if rows.len() != 1 {
            return Ok(None);
        }
        Ok(SynonymFact::from_row(&rows[0], self.context))
    }

    async fn argument_rows(
        &self,
        owner: &str,
        package: Option<&str>,
        name: &str,
    ) -> Result<Option<Vec<ArgumentFact>>, DbError> {
        let (id, binds) = if let Some(package) = package {
            (
                CatalogQueryId::MemberArguments,
                vec![
                    OracleBind::from(owner),
                    OracleBind::from(package),
                    OracleBind::from(name),
                    OracleBind::from((MAX_ARGUMENT_ROWS + 1) as i64),
                ],
            )
        } else {
            (
                CatalogQueryId::StandaloneArguments,
                vec![
                    OracleBind::from(owner),
                    OracleBind::from(name),
                    OracleBind::from((MAX_ARGUMENT_ROWS + 1) as i64),
                ],
            )
        };
        let rows = run_catalog_query(self.cx, self.conn, id, &binds).await?;
        if rows.len() > MAX_ARGUMENT_ROWS {
            return Ok(None);
        }
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let Some(argument) = ArgumentFact::from_row(row) else {
                return Ok(None);
            };
            out.push(argument);
        }
        Ok(Some(out))
    }

    async fn has_column_conflict(&self, name: &str) -> Result<bool, DbError> {
        let rows = run_catalog_query(
            self.cx,
            self.conn,
            CatalogQueryId::ColumnConflict,
            &[
                OracleBind::from(name),
                OracleBind::from((MAX_CANDIDATES + 1) as i64),
            ],
        )
        .await?;
        Ok(!rows.is_empty())
    }
}

#[derive(Clone, Copy)]
enum ObjectPurpose {
    From,
    Callable { zero_arg_only: bool },
}

impl ObjectPurpose {
    fn accepts(self, kind: &CatalogObjectKind) -> bool {
        match self {
            Self::From => matches!(
                kind,
                CatalogObjectKind::Table
                    | CatalogObjectKind::View
                    | CatalogObjectKind::MaterializedView
            ),
            Self::Callable {
                zero_arg_only: true,
            } => matches!(kind, CatalogObjectKind::Function),
            Self::Callable {
                zero_arg_only: false,
            } => matches!(
                kind,
                CatalogObjectKind::Function | CatalogObjectKind::Procedure
            ),
        }
    }
}

struct ObjectFacts {
    objects: Vec<ObjectFact>,
    incomplete: bool,
}

#[derive(Clone)]
struct ObjectFact {
    owner: String,
    name: String,
    kind: CatalogObjectKind,
    identity: ResolvedIdentity,
}

impl ObjectFact {
    fn from_row(row: &OracleRow, context: &ResolveCtx) -> Option<Self> {
        let owner = required_text(row, "OWNER")?;
        let name = required_text(row, "OBJECT_NAME")?;
        let object_type = required_text(row, "OBJECT_TYPE")?;
        let object_id = u64::try_from(row.parse_i64("OBJECT_ID")?).ok()?;
        if row.text("STATUS")? != "VALID" {
            return None;
        }
        let edition = optional_text(row, "EDITION_NAME");
        if edition.is_some() && edition != context.edition {
            return None;
        }
        Some(Self {
            owner,
            name,
            kind: object_kind(&object_type),
            identity: ResolvedIdentity { object_id, edition },
        })
    }
}

struct SynonymFact {
    owner: String,
    name: String,
    target_owner: String,
    target_name: String,
    db_link: Option<String>,
    identity: Option<ResolvedIdentity>,
}

impl SynonymFact {
    fn from_row(row: &OracleRow, context: &ResolveCtx) -> Option<Self> {
        let status = row.text("STATUS")?;
        if status != "VALID" {
            return None;
        }
        let edition = optional_text(row, "EDITION_NAME");
        if edition.is_some() && edition != context.edition {
            return None;
        }
        Some(Self {
            owner: required_text(row, "OWNER")?,
            name: required_text(row, "SYNONYM_NAME")?,
            target_owner: required_text(row, "TABLE_OWNER")?,
            target_name: required_text(row, "TABLE_NAME")?,
            db_link: optional_text(row, "DB_LINK"),
            identity: Some(ResolvedIdentity {
                object_id: u64::try_from(row.parse_i64("OBJECT_ID")?).ok()?,
                edition,
            }),
        })
    }
}

#[derive(Clone)]
struct ArgumentFact {
    subprogram_id: u32,
    overload: Option<String>,
    position: u32,
    data_level: u32,
    in_out: String,
    defaulted: bool,
    argument_name: Option<String>,
    data_type: Option<String>,
}

impl ArgumentFact {
    fn from_row(row: &OracleRow) -> Option<Self> {
        Some(Self {
            subprogram_id: u32::try_from(row.parse_i64("SUBPROGRAM_ID")?).ok()?,
            overload: optional_text(row, "OVERLOAD"),
            position: u32::try_from(row.parse_i64("POSITION")?).ok()?,
            data_level: u32::try_from(row.parse_i64("DATA_LEVEL")?).ok()?,
            in_out: required_text(row, "IN_OUT")?,
            defaulted: row.text("DEFAULTED")? == "Y",
            argument_name: optional_text(row, "ARGUMENT_NAME"),
            data_type: optional_text(row, "DATA_TYPE"),
        })
    }
}

fn routine_arguments_match(params: &[&ArgumentFact], arguments: &[RoutineArgument]) -> bool {
    if params.iter().any(|p| p.data_level > 0) {
        return false;
    }
    let params: Vec<_> = params
        .iter()
        .copied()
        .filter(|p| p.data_level == 0 && p.position > 0)
        .collect();
    let mut positions = HashSet::new();
    if params.iter().any(|p| !positions.insert(p.position)) {
        return false;
    }
    let mut supplied = HashSet::new();
    let mut next_pos = 1_u32;
    for argument in arguments {
        let position = if let Some(name) = &argument.name {
            let Some(param) = params
                .iter()
                .find(|p| p.argument_name.as_deref() == Some(name.text.as_str()))
            else {
                return false;
            };
            param.position
        } else {
            let position = next_pos;
            next_pos += 1;
            position
        };
        let Some(param) = params.iter().find(|p| p.position == position) else {
            return false;
        };
        if !supplied.insert(position) || !argument_type_matches(param, &argument.value) {
            return false;
        }
    }
    params
        .iter()
        .all(|p| p.defaulted || supplied.contains(&p.position))
}

fn argument_type_matches(param: &ArgumentFact, value: &RoutineArgumentValue) -> bool {
    let Some(data_type) = param.data_type.as_deref() else {
        return false;
    };
    if !matches!(value, RoutineArgumentValue::Bind) && param.in_out != "IN" {
        return false;
    }
    match value {
        RoutineArgumentValue::Bind | RoutineArgumentValue::Null => true,
        RoutineArgumentValue::Number => matches!(
            data_type,
            "NUMBER"
                | "INTEGER"
                | "BINARY_INTEGER"
                | "PLS_INTEGER"
                | "BINARY_FLOAT"
                | "BINARY_DOUBLE"
                | "FLOAT"
        ),
        RoutineArgumentValue::Text => matches!(
            data_type,
            "VARCHAR2" | "VARCHAR" | "CHAR" | "NVARCHAR2" | "NCHAR" | "CLOB" | "NCLOB"
        ),
    }
}

enum WalkResult {
    Objects {
        objects: Vec<ObjectFact>,
        synonym_chain: Vec<SynonymHop>,
    },
    Remote {
        db_link: RawNamePart,
    },
    Unresolved,
}

impl WalkResult {
    fn into_resolution(self) -> Resolution {
        match self {
            Self::Remote { db_link } => Resolution::Remote { db_link },
            Self::Objects { objects, .. } => ambiguous_objects(&objects),
            Self::Unresolved => Resolution::Unresolved,
        }
    }
}

struct CallableFacts {
    kind: CatalogObjectKind,
    overloads: Vec<ResolvedOverload>,
}

fn callable_overloads(rows: &[ArgumentFact], zero_arg_only: bool) -> Option<CallableFacts> {
    if rows.is_empty() {
        return Some(CallableFacts {
            kind: CatalogObjectKind::Procedure,
            overloads: Vec::new(),
        });
    }
    let mut grouped: HashMap<(u32, Option<String>), (bool, bool)> = HashMap::new();
    for row in rows {
        let required_input =
            row.data_level == 0 && row.position > 0 && row.in_out.contains("IN") && !row.defaulted;
        let is_function = row.data_level == 0 && row.position == 0;
        grouped
            .entry((row.subprogram_id, row.overload.clone()))
            .and_modify(|(has_required, has_return)| {
                *has_required |= required_input;
                *has_return |= is_function;
            })
            .or_insert((required_input, is_function));
    }
    if grouped.len() > MAX_CANDIDATES {
        return None;
    }
    let has_function = grouped.values().any(|(_, has_return)| *has_return);
    let has_procedure = grouped.values().any(|(_, has_return)| !*has_return);
    if has_function && has_procedure {
        return None;
    }
    let mut out: Vec<_> = grouped
        .into_iter()
        .filter(|(_, (has_required, has_return))| !zero_arg_only || (!*has_required && *has_return))
        .map(|((subprogram_id, overload), _)| ResolvedOverload {
            subprogram_id,
            overload,
        })
        .collect();
    out.sort_by(|left, right| {
        left.subprogram_id
            .cmp(&right.subprogram_id)
            .then_with(|| left.overload.cmp(&right.overload))
    });
    Some(CallableFacts {
        kind: if has_function {
            CatalogObjectKind::Function
        } else {
            CatalogObjectKind::Procedure
        },
        overloads: out,
    })
}

fn merge_alternatives(left: Resolution, right: Resolution) -> Resolution {
    match (left, right) {
        (Resolution::Unresolved, resolution) | (resolution, Resolution::Unresolved) => resolution,
        (Resolution::Resolved(left), Resolution::Resolved(right)) => Resolution::Ambiguous {
            candidates: vec![left.identity.clone(), right.identity.clone()],
        },
        (Resolution::Ambiguous { candidates }, _) | (_, Resolution::Ambiguous { candidates }) => {
            Resolution::Ambiguous { candidates }
        }
        (Resolution::Remote { .. }, Resolution::Resolved(_))
        | (Resolution::Resolved(_), Resolution::Remote { .. })
        | (Resolution::Remote { .. }, Resolution::Remote { .. }) => Resolution::Unresolved,
    }
}

fn record_synonym_visit(
    visited: &mut HashSet<(String, String)>,
    owner: &str,
    name: &str,
    completed_hops: usize,
) -> bool {
    completed_hops < MAX_SYNONYM_HOPS && visited.insert((owner.to_owned(), name.to_owned()))
}

fn ambiguous_objects(objects: &[ObjectFact]) -> Resolution {
    if objects.is_empty() {
        Resolution::Unresolved
    } else if objects.len() == 1 {
        Resolution::Ambiguous {
            candidates: vec![objects[0].identity.clone()],
        }
    } else {
        Resolution::Ambiguous {
            candidates: objects
                .iter()
                .take(MAX_CANDIDATES)
                .map(|object| object.identity.clone())
                .collect(),
        }
    }
}

fn normalize_parts(parts: &[RawNamePart]) -> Option<Vec<String>> {
    parts
        .iter()
        .map(|part| {
            if part.text.is_empty()
                || part.text.len() > MAX_IDENTIFIER_BYTES
                || part.text.chars().any(char::is_control)
            {
                return None;
            }
            Some(match part.quoting {
                QuoteSemantics::Unquoted => part.text.to_ascii_uppercase(),
                QuoteSemantics::Quoted => part.text.clone(),
            })
        })
        .collect()
}

fn parts_equal(left: &RawNamePart, right: &RawNamePart) -> bool {
    match (left.quoting, right.quoting) {
        (QuoteSemantics::Quoted, QuoteSemantics::Quoted) => left.text == right.text,
        (QuoteSemantics::Quoted, QuoteSemantics::Unquoted) => {
            left.text == right.text.to_ascii_uppercase()
        }
        (QuoteSemantics::Unquoted, QuoteSemantics::Quoted) => {
            left.text.to_ascii_uppercase() == right.text
        }
        (QuoteSemantics::Unquoted, QuoteSemantics::Unquoted) => {
            left.text.eq_ignore_ascii_case(&right.text)
        }
    }
}

fn relation_matches_qualifier(
    relation: &oraclemcp_guard::StatementRelation,
    qualifier: &str,
) -> bool {
    relation
        .alias
        .as_ref()
        .or_else(|| relation.name.parts.last())
        .is_some_and(|part| match part.quoting {
            QuoteSemantics::Unquoted => part.text.to_ascii_uppercase() == qualifier,
            QuoteSemantics::Quoted => part.text == qualifier,
        })
}

fn relation_matches_owner_name(
    relation: &oraclemcp_guard::StatementRelation,
    owner: &str,
    name: &str,
) -> bool {
    let Some(parts) = normalize_parts(&relation.name.parts) else {
        return false;
    };
    matches!(parts.as_slice(), [relation_owner, relation_name] if relation_owner == owner && relation_name == name)
}

fn merged_join_contains_column(
    merge: &oraclemcp_guard::resolver::MergedJoin,
    column: &str,
) -> bool {
    match &merge.using_columns {
        None => true,
        Some(parts) => parts.iter().any(|part| {
            normalize_parts(std::slice::from_ref(part)).is_some_and(|name| name[0] == column)
        }),
    }
}

fn resolved_relation_identity_matches(expected: &ResolvedObject, actual: &ResolvedObject) -> bool {
    expected.identity == actual.identity
        && expected.owner == actual.owner
        && expected.name == actual.name
        && expected.kind == actual.kind
}

fn object_kind(value: &str) -> CatalogObjectKind {
    match value {
        "TABLE" => CatalogObjectKind::Table,
        "VIEW" | "EDITIONING VIEW" => CatalogObjectKind::View,
        "MATERIALIZED VIEW" => CatalogObjectKind::MaterializedView,
        "SEQUENCE" => CatalogObjectKind::Sequence,
        "FUNCTION" => CatalogObjectKind::Function,
        "PROCEDURE" => CatalogObjectKind::Procedure,
        "PACKAGE" => CatalogObjectKind::Package,
        "TYPE" => CatalogObjectKind::Type,
        "SYNONYM" => CatalogObjectKind::Synonym,
        other => CatalogObjectKind::Other(other.to_owned()),
    }
}

fn required_text(row: &OracleRow, name: &str) -> Option<String> {
    let value = row.text(name)?;
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn optional_text(row: &OracleRow, name: &str) -> Option<String> {
    row.text(name)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn exact_is_json_check(condition: &str, column: &str) -> bool {
    if condition.len() >= 4000 || column.is_empty() {
        return false;
    }
    let compact = condition
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '(' && *ch != ')')
        .collect::<String>();
    compact == format!("\"{column}\"ISJSON") || compact == format!("{column}ISJSON")
}

/// Prove the principal can read `ALL_POLICIES`.
///
/// The determinant is Ok-vs-error, never row count. `ALL_POLICIES` is a PUBLIC
/// data dictionary view listing every VPD policy on objects accessible to the
/// current user, so a *successful* read — including one that returns zero rows —
/// is positive proof of catalog visibility and, given the caller's empty
/// object-scoped policy probe, of the absence of any VPD policy. Genuine
/// blindness (the view is unreadable) surfaces as an Oracle error, which the
/// `?` propagates to a fail-closed refusal. Treating a successful empty read as
/// blindness (the pre-fix behavior) refused every read on any database with no
/// VPD policies; treating an error as absence would be a fail-open. This keeps
/// the error=refuse path exactly as fail-closed as before.
async fn prove_policy_catalog_readable(
    cx: &Cx,
    conn: &dyn OracleConnection,
) -> Result<(), DbError> {
    run_catalog_query(cx, conn, CatalogQueryId::PolicyCatalogProof, &[]).await?;
    Ok(())
}

/// Prove the principal can read `ALL_TAB_COLS` for `relation`.
///
/// Same Ok-vs-error determinant as [`prove_policy_catalog_readable`]: a
/// successful read proves the column dictionary is visible, so the empty
/// `virtual_column = 'YES'` result above is trustworthy absence rather than
/// blindness; an unreadable view errors and fails closed via `?`.
async fn prove_target_column_catalog_readable(
    cx: &Cx,
    conn: &dyn OracleConnection,
    relation: &ResolvedObject,
) -> Result<(), DbError> {
    run_catalog_query(
        cx,
        conn,
        CatalogQueryId::TargetColumnCatalogProof,
        &[
            OracleBind::from(relation.owner.as_str()),
            OracleBind::from(relation.name.as_str()),
        ],
    )
    .await?;
    Ok(())
}

async fn query_policy_catalog_probe(
    cx: &Cx,
    conn: &dyn OracleConnection,
) -> OraclePolicyCatalogProbe {
    match run_catalog_query(cx, conn, CatalogQueryId::AllPoliciesVisibility, &[]).await {
        Ok(rows) => {
            let visible = rows
                .first()
                .and_then(|row| row.parse_i64("VISIBLE_POLICY_ROWS"))
                .is_some_and(|count| count > 0);
            if visible {
                OraclePolicyCatalogProbe {
                    visibility: OraclePolicyCatalogVisibility::PolicyRowsVisible,
                    visible_policy_rows_probe: Some(true),
                    detail: "ALL_POLICIES returned at least one row visible to this principal"
                        .to_owned(),
                }
            } else {
                OraclePolicyCatalogProbe {
                    visibility: OraclePolicyCatalogVisibility::NoPolicyRowsVisible,
                    visible_policy_rows_probe: Some(false),
                    detail: "ALL_POLICIES returned zero visible rows; this may be a catalog-blind principal and is not proof that no policy exists".to_owned(),
                }
            }
        }
        Err(error) => OraclePolicyCatalogProbe {
            visibility: OraclePolicyCatalogVisibility::Unavailable,
            visible_policy_rows_probe: None,
            detail: format!("ALL_POLICIES visibility probe failed: {error}"),
        },
    }
}

async fn query_vpd_rls_policies(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    binds: &[OracleBind],
) -> (Vec<OracleVpdRlsPolicy>, Option<String>) {
    match conn.query_rows(cx, sql, binds).await {
        Ok(rows) => (
            rows.iter()
                .take(MAX_VPD_RLS_POLICY_ROWS)
                .filter_map(vpd_rls_policy_from_row)
                .collect(),
            None,
        ),
        Err(error) => (Vec::new(), Some(error.to_string())),
    }
}

fn vpd_rls_policy_from_row(row: &OracleRow) -> Option<OracleVpdRlsPolicy> {
    let object_owner = required_text(row, "OBJECT_OWNER")?;
    let object_name = required_text(row, "OBJECT_NAME")?;
    let policy_name = required_text(row, "POLICY_NAME")?;
    Some(OracleVpdRlsPolicy {
        object_owner,
        object_name,
        policy_name,
        function_owner: optional_text(row, "PF_OWNER"),
        package_name: optional_text(row, "PACKAGE"),
        function_name: optional_text(row, "FUNCTION"),
        statement_types: policy_statement_types(row),
        enabled: is_yes(row.text("ENABLE")),
    })
}

fn policy_statement_types(row: &OracleRow) -> Vec<String> {
    [
        ("SEL", "select"),
        ("INS", "insert"),
        ("UPD", "update"),
        ("DEL", "delete"),
    ]
    .into_iter()
    .filter_map(|(column, label)| is_yes(row.text(column)).then_some(label.to_owned()))
    .collect()
}

fn is_yes(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.eq_ignore_ascii_case("YES") || value.eq_ignore_ascii_case("Y"))
}

fn build_vpd_rls_observation(
    scope: String,
    session: Option<OracleSessionSecurityContext>,
    all_policies_probe: OraclePolicyCatalogProbe,
    policies: Vec<OracleVpdRlsPolicy>,
    policy_error: Option<String>,
) -> OracleVpdRlsObservation {
    let (status, detail) = if let Some(error) = policy_error {
        (
            OracleVpdRlsObservationStatus::VisibilityUnavailable,
            format!("could not inspect VPD/RLS policies for {scope}: {error}"),
        )
    } else if !policies.is_empty() {
        (
            OracleVpdRlsObservationStatus::PoliciesObserved,
            format!(
                "{} visible VPD/RLS polic{} observed for {scope}",
                policies.len(),
                if policies.len() == 1 { "y" } else { "ies" }
            ),
        )
    } else {
        match all_policies_probe.visibility {
            OraclePolicyCatalogVisibility::PolicyRowsVisible => (
                OracleVpdRlsObservationStatus::NoVisibleMatchingPolicies,
                format!(
                    "ALL_POLICIES is readable, but no matching VPD/RLS policies were visible for {scope}; this is observed catalog evidence only"
                ),
            ),
            OraclePolicyCatalogVisibility::NoPolicyRowsVisible => (
                OracleVpdRlsObservationStatus::NoVisiblePolicyCatalogRows,
                format!(
                    "no ALL_POLICIES rows are visible to this principal while inspecting {scope}; a filtered read may still be silent"
                ),
            ),
            OraclePolicyCatalogVisibility::Unavailable => (
                OracleVpdRlsObservationStatus::VisibilityUnavailable,
                format!(
                    "ALL_POLICIES visibility is unavailable while inspecting {scope}; policy absence is not proven"
                ),
            ),
        }
    };
    OracleVpdRlsObservation {
        status,
        scope,
        session,
        all_policies_probe,
        policies,
        detail,
    }
}

fn cache_lock_error<T>(_error: std::sync::PoisonError<T>) -> DbError {
    DbError::Query("catalog resolver cache lock poisoned".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OracleBackend, OracleCell, OracleConnectionInfo};
    use asupersync::runtime::RuntimeBuilder;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    fn synthetic_object(owner: &str, name: &str) -> OracleRow {
        row(&[
            ("OWNER", Some(owner)),
            ("OBJECT_NAME", Some(name)),
            ("OBJECT_TYPE", Some("PROCEDURE")),
            ("OBJECT_ID", Some("91")),
            ("STATUS", Some("VALID")),
            ("EDITION_NAME", None),
        ])
    }

    fn synthetic_synonym(owner: &str, target_owner: &str) -> OracleRow {
        row(&[
            ("OWNER", Some(owner)),
            ("SYNONYM_NAME", Some("P")),
            ("TABLE_OWNER", Some(target_owner)),
            ("TABLE_NAME", Some("RUN")),
            ("DB_LINK", None),
            ("OBJECT_ID", Some("31")),
            ("STATUS", Some("VALID")),
            ("EDITION_NAME", None),
        ])
    }

    #[test]
    fn call_ambiguous_overload_is_unknown() {
        let args = [RoutineArgument {
            name: None,
            value: RoutineArgumentValue::Bind,
        }];
        let a = ArgumentFact {
            subprogram_id: 1,
            overload: Some("1".to_owned()),
            position: 1,
            data_level: 0,
            in_out: "IN".to_owned(),
            defaulted: false,
            argument_name: Some("VALUE".to_owned()),
            data_type: Some("NUMBER".to_owned()),
        };
        let b = ArgumentFact {
            subprogram_id: 2,
            overload: Some("2".to_owned()),
            data_type: Some("VARCHAR2".to_owned()),
            ..a.clone()
        };
        assert!(routine_arguments_match(&[&a], &args));
        assert!(routine_arguments_match(&[&b], &args));
        // Both candidates fit an untyped bind. The catalog path must return
        // None rather than arbitrarily selecting either subprogram.
        run_with_cx(|cx| async move {
            let context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(1));
            let conn = ScriptedRows::new([
                vec![synthetic_object("APP", "RUN")],
                vec![
                    row(&[("SUBPROGRAM_ID", Some("1")), ("OVERLOAD", Some("1"))]),
                    row(&[("SUBPROGRAM_ID", Some("2")), ("OVERLOAD", Some("2"))]),
                ],
                vec![
                    row(&[
                        ("SUBPROGRAM_ID", Some("1")),
                        ("OVERLOAD", Some("1")),
                        ("POSITION", Some("1")),
                        ("DATA_LEVEL", Some("0")),
                        ("IN_OUT", Some("IN")),
                        ("DEFAULTED", Some("N")),
                        ("ARGUMENT_NAME", Some("VALUE")),
                        ("DATA_TYPE", Some("NUMBER")),
                    ]),
                    row(&[
                        ("SUBPROGRAM_ID", Some("2")),
                        ("OVERLOAD", Some("2")),
                        ("POSITION", Some("1")),
                        ("DATA_LEVEL", Some("0")),
                        ("IN_OUT", Some("IN")),
                        ("DEFAULTED", Some("N")),
                        ("ARGUMENT_NAME", Some("VALUE")),
                        ("DATA_TYPE", Some("VARCHAR2")),
                    ]),
                ],
            ]);
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            assert_eq!(
                lookup
                    .exact_routine("APP", None, "RUN", false, &args)
                    .await
                    .unwrap(),
                None
            );
        });
    }

    #[test]
    fn named_notation_and_literal_type_select_only_one_overload() {
        let numeric = ArgumentFact {
            subprogram_id: 1,
            overload: Some("1".to_owned()),
            position: 1,
            data_level: 0,
            in_out: "IN".to_owned(),
            defaulted: false,
            argument_name: Some("VALUE".to_owned()),
            data_type: Some("NUMBER".to_owned()),
        };
        let textual = ArgumentFact {
            subprogram_id: 2,
            overload: Some("2".to_owned()),
            data_type: Some("VARCHAR2".to_owned()),
            ..numeric.clone()
        };
        let named = [RoutineArgument {
            name: Some(RoutineIdentifier::new("value", false)),
            value: RoutineArgumentValue::Text,
        }];
        assert!(!routine_arguments_match(&[&numeric], &named));
        assert!(routine_arguments_match(&[&textual], &named));
        let wrong_case = [RoutineArgument {
            name: Some(RoutineIdentifier::new("value", true)),
            value: RoutineArgumentValue::Text,
        }];
        assert!(!routine_arguments_match(&[&textual], &wrong_case));
        assert!(!routine_arguments_match(&[&textual, &textual], &named));
        let nested = ArgumentFact {
            data_level: 1,
            ..textual.clone()
        };
        assert!(!routine_arguments_match(&[&textual, &nested], &named));
    }

    #[test]
    fn call_synonym_resolves_to_exact_target() {
        run_with_cx(|cx| async move {
            let context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(1));
            let conn = ScriptedRows::new([
                Vec::new(),
                vec![synthetic_synonym("APP", "OWNER")],
                vec![synthetic_object("OWNER", "RUN")],
                vec![row(&[("SUBPROGRAM_ID", Some("7")), ("OVERLOAD", None)])],
                Vec::new(),
            ]);
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            let exact = lookup
                .exact_routine("APP", None, "P", true, &[])
                .await
                .unwrap()
                .unwrap();
            assert_eq!(exact.schema.unwrap().text, "OWNER");
            assert_eq!(exact.member.text, "RUN");
            assert_eq!(exact.overload, Some(7));
            assert_eq!(conn.queries.lock().unwrap().len(), 5);
        });
    }

    #[test]
    fn call_remote_synonym_refused() {
        run_with_cx(|cx| async move {
            let context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(1));
            let conn = ScriptedRows::new([
                Vec::new(),
                vec![row(&[
                    ("OWNER", Some("APP")),
                    ("SYNONYM_NAME", Some("P")),
                    ("TABLE_OWNER", Some("OWNER")),
                    ("TABLE_NAME", Some("RUN")),
                    ("DB_LINK", Some("REMOTE")),
                    ("OBJECT_ID", Some("31")),
                    ("STATUS", Some("VALID")),
                    ("EDITION_NAME", None),
                ])],
            ]);
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            assert_eq!(
                lookup
                    .exact_routine("APP", None, "P", true, &[])
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(conn.queries.lock().unwrap().len(), 2);
        });
    }

    #[test]
    fn call_public_synonym_after_private() {
        run_with_cx(|cx| async move {
            let context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(1));
            let conn = ScriptedRows::new([
                Vec::new(),
                Vec::new(),
                vec![synthetic_synonym("PUBLIC", "OWNER")],
                vec![synthetic_object("OWNER", "RUN")],
                vec![row(&[("SUBPROGRAM_ID", Some("7")), ("OVERLOAD", None)])],
                Vec::new(),
            ]);
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            let exact = lookup
                .exact_routine("APP", None, "P", true, &[])
                .await
                .unwrap()
                .unwrap();
            assert_eq!(exact.schema.unwrap().text, "OWNER");
            assert_eq!(exact.overload, Some(7));
            let queries = conn.queries.lock().unwrap();
            assert_eq!(queries[2].0, SYNONYMS_SQL);
            assert_eq!(queries.len(), 6);
        });
    }

    fn write_catalog_test_artifact(name: &str, cases: &[serde_json::Value]) {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
        let dir = target.join("test-artifacts/read_executor");
        std::fs::create_dir_all(&dir).expect("create catalog test artifact dir");
        let mut jsonl = cases
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        jsonl.push('\n');
        std::fs::write(dir.join(format!("{name}.jsonl")), jsonl)
            .expect("write catalog test artifact");
    }

    fn run_with_cx<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(Cx) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime installs Cx");
            body(cx).await
        })
    }

    struct ScriptedRows {
        responses: Mutex<VecDeque<Result<Vec<OracleRow>, DbError>>>,
        queries: Mutex<Vec<(String, Vec<OracleBind>)>>,
    }

    impl ScriptedRows {
        fn new(responses: impl IntoIterator<Item = Vec<OracleRow>>) -> Self {
            Self::results(responses.into_iter().map(Ok))
        }

        fn results(responses: impl IntoIterator<Item = Result<Vec<OracleRow>, DbError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                queries: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for ScriptedRows {
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
            self.queries
                .lock()
                .expect("queries lock")
                .push((sql.to_owned(), binds.to_vec()));
            self.responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .unwrap_or_else(|| Err(DbError::Query("unexpected dictionary query".to_owned())))
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Err(DbError::Execute("unexpected execute".to_owned()))
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Err(DbError::Execute("unexpected commit".to_owned()))
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Err(DbError::Execute("unexpected rollback".to_owned()))
        }
    }

    fn row(columns: &[(&str, Option<&str>)]) -> OracleRow {
        OracleRow {
            columns: columns
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

    fn fga_row(
        enabled: &str,
        flags: [&str; 4],
        handler: Option<&str>,
        condition: Option<&str>,
    ) -> OracleRow {
        row(&[
            ("OBJECT_SCHEMA", Some("APP")),
            ("OBJECT_NAME", Some("ORDERS")),
            ("POLICY_NAME", Some("AUDIT_ORDERS")),
            ("POLICY_TEXT", condition),
            ("PF_SCHEMA", handler.map(|_| "APP")),
            ("PF_PACKAGE", None),
            ("PF_FUNCTION", handler),
            ("ENABLED", Some(enabled)),
            ("SEL", Some(flags[0])),
            ("INS", Some(flags[1])),
            ("UPD", Some(flags[2])),
            ("DEL", Some(flags[3])),
        ])
    }

    fn fga_test_connection(rows: Vec<OracleRow>) -> ScriptedRows {
        ScriptedRows::new([rows, Vec::new()])
    }

    #[test]
    fn fga_enabled_select_policy_with_handler_is_autonomous() {
        run_with_cx(|cx| async move {
            let conn = fga_test_connection(vec![fga_row(
                "YES",
                ["YES", "NO", "NO", "NO"],
                Some("AUDIT_HANDLER"),
                None,
            )]);
            let result = fga_closure(&cx, &conn, &[table_object()], FgaStatementKind::Select).await;
            assert_eq!(result.purity(), Purity::ProvenSideEffecting);
            let FgaClosure::Autonomous { policy } = result else {
                panic!("enabled handler must refuse")
            };
            assert_eq!(policy.policy_name, "AUDIT_ORDERS");
            assert_eq!(
                policy.handler,
                Some(("APP".to_owned(), None, "AUDIT_HANDLER".to_owned()))
            );
            assert_eq!(conn.queries.lock().unwrap().len(), 1);
        });
    }

    #[test]
    fn fga_disabled_policy_does_not_refuse() {
        run_with_cx(|cx| async move {
            let conn = fga_test_connection(vec![fga_row(
                "NO",
                ["YES", "NO", "NO", "NO"],
                Some("AUDIT_HANDLER"),
                None,
            )]);
            assert_eq!(
                fga_closure(&cx, &conn, &[table_object()], FgaStatementKind::Select).await,
                FgaClosure::ProvenReadOnly
            );
        });
    }

    #[test]
    fn fga_insert_only_policy_does_not_refuse_select() {
        run_with_cx(|cx| async move {
            let conn = fga_test_connection(vec![fga_row(
                "YES",
                ["NO", "YES", "NO", "NO"],
                Some("AUDIT_HANDLER"),
                None,
            )]);
            assert_eq!(
                fga_closure(&cx, &conn, &[table_object()], FgaStatementKind::Select).await,
                FgaClosure::ProvenReadOnly
            );
        });
    }

    #[test]
    fn fga_policy_on_view_in_closure_refuses() {
        run_with_cx(|cx| async move {
            let conn = fga_test_connection(vec![fga_row(
                "YES",
                ["YES", "NO", "NO", "NO"],
                Some("AUDIT_HANDLER"),
                None,
            )]);
            let view = ResolvedObject {
                kind: CatalogObjectKind::View,
                ..table_object()
            };
            assert!(matches!(
                fga_closure(&cx, &conn, &[view], FgaStatementKind::Select).await,
                FgaClosure::Autonomous { .. }
            ));
        });
    }

    #[test]
    fn fga_ambiguous_handler_identity_is_unknown() {
        run_with_cx(|cx| async move {
            let mut ambiguous = fga_row(
                "YES",
                ["YES", "NO", "NO", "NO"],
                Some("AUDIT_HANDLER"),
                None,
            );
            let (_, function) = ambiguous
                .columns
                .iter_mut()
                .find(|(name, _)| name == "PF_FUNCTION")
                .expect("handler function column");
            *function = OracleCell::new("VARCHAR2", None);
            let conn = fga_test_connection(vec![ambiguous]);
            assert!(matches!(
                fga_closure(&cx, &conn, &[table_object()], FgaStatementKind::Select).await,
                FgaClosure::Unknown { .. }
            ));
        });
    }

    #[test]
    fn fga_audit_condition_with_user_function_is_unknown() {
        run_with_cx(|cx| async move {
            let conn = fga_test_connection(vec![fga_row(
                "YES",
                ["YES", "NO", "NO", "NO"],
                None,
                Some("APP.CANARY_FN(id) = 1"),
            )]);
            assert_eq!(
                fga_closure(&cx, &conn, &[table_object()], FgaStatementKind::Select).await,
                FgaClosure::Unknown {
                    reason: "fga_audit_condition_unknown"
                }
            );
        });
    }

    #[test]
    fn fga_catalog_invisible_is_unknown() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::results([
                Ok(Vec::new()),
                Err(DbError::Query("ORA-00942".to_owned())),
            ]);
            assert_eq!(
                fga_closure(&cx, &conn, &[table_object()], FgaStatementKind::Select).await,
                FgaClosure::Unknown {
                    reason: "fga_catalog_unavailable"
                }
            );
        });
    }

    #[test]
    fn fga_relationless_read_needs_no_catalog_probe() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new([]);
            assert_eq!(
                fga_closure(&cx, &conn, &[], FgaStatementKind::Select).await,
                FgaClosure::ProvenReadOnly
            );
            assert!(conn.queries.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn fga_sys_owned_local_relation_needs_no_catalog_probe() {
        // LIVE FREE23 23.0.0.0.0: DBMS_FGA.ADD_POLICY on SYS.DUAL returned
        // ORA-46399 (FGA policy cannot be applied to a SYS-owned object);
        // DBA_AUDIT_POLICIES contained zero rows for the unique probe policy.
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new([]);
            let dual = ResolvedObject {
                owner: "SYS".to_owned(),
                name: "DUAL".to_owned(),
                ..table_object()
            };
            for kind in [
                FgaStatementKind::Select,
                FgaStatementKind::Insert,
                FgaStatementKind::Update,
                FgaStatementKind::Delete,
            ] {
                assert_eq!(
                    fga_closure(&cx, &conn, std::slice::from_ref(&dual), kind).await,
                    FgaClosure::ProvenReadOnly
                );
            }
            assert!(conn.queries.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn fga_mixed_sys_and_non_sys_relations_still_probe_non_sys() {
        run_with_cx(|cx| async move {
            let dual = ResolvedObject {
                owner: "SYS".to_owned(),
                name: "DUAL".to_owned(),
                ..table_object()
            };
            let relations = [dual, table_object()];
            let conn = ScriptedRows::results([
                Ok(Vec::new()),
                Err(DbError::Query("ORA-00942".to_owned())),
            ]);
            assert_eq!(
                fga_closure(&cx, &conn, &relations, FgaStatementKind::Select).await,
                FgaClosure::Unknown {
                    reason: "fga_catalog_unavailable"
                }
            );
            let queries = conn.queries.lock().unwrap();
            assert_eq!(queries.len(), 2);
            assert_eq!(queries[0].1[0], OracleBind::from("APP"));
            assert_eq!(queries[0].1[1], OracleBind::from("ORDERS"));
            assert_eq!(queries[1].0, FGA_CATALOG_PROOF_SQL);
        });
    }

    #[test]
    fn fga_owner_spelled_like_sys_is_not_the_sys_owner_proof() {
        run_with_cx(|cx| async move {
            let quoted_other_owner = ResolvedObject {
                owner: "sys".to_owned(),
                ..table_object()
            };
            let conn = ScriptedRows::results([
                Ok(Vec::new()),
                Err(DbError::Query("ORA-00942".to_owned())),
            ]);
            assert_eq!(
                fga_closure(&cx, &conn, &[quoted_other_owner], FgaStatementKind::Select).await,
                FgaClosure::Unknown {
                    reason: "fga_catalog_unavailable"
                }
            );
            assert_eq!(
                conn.queries.lock().unwrap()[0].1[0],
                OracleBind::from("sys")
            );
        });
    }

    #[test]
    fn fga_sys_owner_without_exact_local_identity_stays_unknown() {
        run_with_cx(|cx| async move {
            for relation in [
                ResolvedObject {
                    owner: "SYS".to_owned(),
                    identity: ResolvedIdentity {
                        object_id: 0,
                        edition: None,
                    },
                    ..table_object()
                },
                ResolvedObject {
                    owner: "SYS".to_owned(),
                    db_link: Some("REMOTE".to_owned()),
                    ..table_object()
                },
            ] {
                let conn = ScriptedRows::new([]);
                assert_eq!(
                    fga_closure(&cx, &conn, &[relation], FgaStatementKind::Select).await,
                    FgaClosure::Unknown {
                        reason: "fga_relation_identity_unknown"
                    }
                );
                assert!(conn.queries.lock().unwrap().is_empty());
            }
        });
    }

    #[test]
    fn fga_truncated_evidence_is_unknown() {
        run_with_cx(|cx| async move {
            let row = fga_row("NO", ["YES", "NO", "NO", "NO"], None, None);
            let conn = fga_test_connection(vec![row; 257]);
            assert_eq!(
                fga_closure(&cx, &conn, &[table_object()], FgaStatementKind::Select).await,
                FgaClosure::Unknown {
                    reason: "fga_evidence_truncated"
                }
            );
        });
    }

    #[test]
    fn fga_statement_kind_keying_serves_dml_kinds() {
        run_with_cx(|cx| async move {
            for kind in [
                FgaStatementKind::Insert,
                FgaStatementKind::Update,
                FgaStatementKind::Delete,
            ] {
                let conn = fga_test_connection(vec![fga_row(
                    "YES",
                    ["NO", "YES", "YES", "YES"],
                    Some("AUDIT_HANDLER"),
                    None,
                )]);
                assert!(matches!(
                    fga_closure(&cx, &conn, &[table_object()], kind).await,
                    FgaClosure::Autonomous { .. }
                ));
            }
        });
    }

    #[test]
    fn fga_catalog_batches_1_10_100_relations_with_one_visibility_probe() {
        run_with_cx(|cx| async move {
            for count in [1_usize, 10, 100] {
                let chunks = count.div_ceil(32);
                let conn = ScriptedRows::new(vec![Vec::new(); chunks + 1]);
                let relations = (0..count)
                    .map(|index| ResolvedObject {
                        name: format!("T{index}"),
                        ..table_object()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    fga_closure(&cx, &conn, &relations, FgaStatementKind::Select).await,
                    FgaClosure::ProvenReadOnly
                );
                let queries = conn.queries.lock().unwrap();
                assert_eq!(queries.len(), chunks + 1);
                assert!(
                    queries
                        .iter()
                        .take(chunks)
                        .all(|(_, binds)| binds.len() == 64)
                );
                assert_eq!(queries.last().unwrap().0, FGA_CATALOG_PROOF_SQL);
            }
        });
    }

    #[test]
    fn dictionary_queries_bind_every_dynamic_identifier_and_bound_every_result() {
        assert!(OBJECTS_SQL.contains("owner = :1 AND object_name = :2"));
        assert!(OBJECTS_SQL.contains("ROWNUM <= :3"));
        assert!(SYNONYMS_SQL.contains("s.owner = :1 AND s.synonym_name = :2"));
        assert!(SYNONYMS_SQL.contains("ROWNUM <= :3"));
        assert!(STANDALONE_ARGUMENTS_SQL.contains("owner = :1"));
        assert!(STANDALONE_ARGUMENTS_SQL.contains("object_name = :2"));
        assert!(MEMBER_ARGUMENTS_SQL.contains("package_name = :2 AND object_name = :3"));
        assert!(MEMBER_ARGUMENTS_SQL.contains("ROWNUM <= :4"));
        assert!(COLUMN_CONFLICT_SQL.contains("column_name = :1"));
        assert!(COLUMN_CONFLICT_SQL.contains("ROWNUM <= :2"));
        for sql in [
            OBJECTS_SQL,
            SYNONYMS_SQL,
            STANDALONE_ARGUMENTS_SQL,
            MEMBER_ARGUMENTS_SQL,
            STANDALONE_PROCEDURES_SQL,
            MEMBER_PROCEDURES_SQL,
            COLUMN_CONFLICT_SQL,
            RELATION_COLUMN_SQL,
            SELECT_POLICY_SQL,
            VPD_RLS_POLICY_BY_SCHEMA_SQL,
            VPD_RLS_POLICY_BY_OBJECT_SQL,
            ALL_POLICIES_VISIBILITY_SQL,
            POLICY_CATALOG_PROOF_SQL,
            VIRTUAL_COLUMN_SQL,
            TARGET_COLUMN_CATALOG_PROOF_SQL,
        ] {
            assert!(!sql.contains("{}"));
        }
    }

    #[test]
    fn catalog_query_sql_is_const_for_every_variant() {
        let specs = CatalogQueryId::ALL.map(CatalogQueryId::spec);
        assert_eq!(specs.len(), 66);
        let mut cases = Vec::new();
        for (id, spec) in CatalogQueryId::ALL.into_iter().zip(specs) {
            let _: &'static str = spec.sql;
            assert!(spec.sql.starts_with("SELECT "));
            assert!(!spec.sql.contains("{}"));
            assert!(!spec.purpose.is_empty());
            cases.push(serde_json::json!({"case_id": format!("catalog_sql_{id:?}"), "expected": {"is_select": true, "has_format_markers": false, "purpose_present": true}, "actual": {"is_select": spec.sql.starts_with("SELECT "), "has_format_markers": spec.sql.contains("{}"), "purpose_present": !spec.purpose.is_empty()}}));
        }
        write_catalog_test_artifact("catalog_sql", &cases);
    }

    #[test]
    fn catalog_query_runner_refuses_bind_arity_mismatch_without_executing() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new([]);
            let err = run_catalog_query(&cx, &conn, CatalogQueryId::Objects, &[])
                .await
                .expect_err("missing binds must fail");
            let arity_internal = matches!(err, DbError::Internal(_));
            assert!(arity_internal);
            let err = run_catalog_query(
                &cx,
                &conn,
                CatalogQueryId::SessionRoles,
                &[OracleBind::from("wrong type")],
            )
            .await
            .expect_err("wrong bind type must fail");
            let type_internal = matches!(err, DbError::Internal(_));
            assert!(type_internal);
            let query_count = conn.queries.lock().expect("queries lock").len();
            assert_eq!(query_count, 0);
            write_catalog_test_artifact(
                "catalog_binds",
                &[
                    serde_json::json!({"case_id": "catalog_wrong_arity", "expected": {"internal": true, "query_count": 0}, "actual": {"internal": arity_internal, "query_count": query_count}}),
                    serde_json::json!({"case_id": "catalog_wrong_type", "expected": {"internal": true, "query_count": 0}, "actual": {"internal": type_internal, "query_count": query_count}}),
                ],
            );
        });
    }

    #[test]
    fn catalog_query_nullable_filter_accepts_only_text_or_null() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new([Vec::new()]);
            run_catalog_query(
                &cx,
                &conn,
                CatalogQueryId::ListObjects,
                &[
                    OracleBind::Null,
                    OracleBind::Null,
                    OracleBind::Null,
                    OracleBind::I64(5),
                ],
            )
            .await
            .expect("absent optional text filters are represented by SQL NULL");
            let accepted = conn.queries.lock().expect("queries lock").len();
            assert_eq!(accepted, 1);
            let error = run_catalog_query(
                &cx,
                &conn,
                CatalogQueryId::ListObjects,
                &[
                    OracleBind::I64(1),
                    OracleBind::Null,
                    OracleBind::Null,
                    OracleBind::I64(5),
                ],
            )
            .await
            .expect_err("an integer cannot be an optional text filter");
            assert!(matches!(error, DbError::Internal(_)));
            let actual_queries = conn.queries.lock().expect("queries lock").len();
            assert_eq!(actual_queries, 1);
            write_catalog_test_artifact(
                "catalog_nullable_text",
                &[serde_json::json!({
                    "case_id": "catalog_nullable_text",
                    "expected": {"accepted_queries": 1, "wrong_type_refused_without_query": true},
                    "actual": {"accepted_queries": accepted, "wrong_type_refused_without_query": actual_queries == 1},
                })],
            );
        });
    }

    #[test]
    fn vpd_rls_schema_observation_names_visible_policy() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new([
                vec![row(&[
                    ("SESSION_USER", Some("ORACLEMCP_D3_SIGHTED")),
                    ("CURRENT_SCHEMA", Some("ORACLEMCP_D3_OWNER")),
                    ("EDITION_NAME", Some("ORA$BASE")),
                ])],
                vec![row(&[("ROLE", Some("SELECT_CATALOG_ROLE"))])],
                vec![row(&[
                    ("OBJECT_OWNER", Some("ORACLEMCP_D3_OWNER")),
                    ("OBJECT_NAME", Some("ORACLEMCP_D3_PROTECTED")),
                    ("POLICY_NAME", Some("ORACLEMCP_D3_VPD")),
                    ("PF_OWNER", Some("ORACLEMCP_D3_OWNER")),
                    ("PACKAGE", None),
                    ("FUNCTION", Some("ORACLEMCP_D3_VPD")),
                    ("SEL", Some("YES")),
                    ("INS", Some("NO")),
                    ("UPD", Some("NO")),
                    ("DEL", Some("NO")),
                    ("ENABLE", Some("YES")),
                ])],
                vec![row(&[("VISIBLE_POLICY_ROWS", Some("1"))])],
            ]);
            let observation = observe_vpd_rls_for_schema(&cx, &conn, "").await;
            assert_eq!(
                observation.status,
                OracleVpdRlsObservationStatus::PoliciesObserved
            );
            assert_eq!(observation.scope, "schema:ORACLEMCP_D3_OWNER");
            assert_eq!(
                observation
                    .session
                    .as_ref()
                    .map(|session| session.session_user.as_str()),
                Some("ORACLEMCP_D3_SIGHTED")
            );
            assert_eq!(observation.policies.len(), 1);
            assert_eq!(observation.policies[0].policy_name, "ORACLEMCP_D3_VPD");
            assert_eq!(
                observation.policies[0].statement_types,
                vec!["select".to_owned()]
            );
        });
    }

    #[test]
    fn vpd_rls_observation_treats_empty_all_policies_as_blind_risk() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new([
                vec![row(&[
                    ("SESSION_USER", Some("ORACLEMCP_D3_BLIND")),
                    ("CURRENT_SCHEMA", Some("ORACLEMCP_D3_OWNER")),
                    ("EDITION_NAME", Some("ORA$BASE")),
                ])],
                Vec::new(),
                Vec::new(),
                vec![row(&[("VISIBLE_POLICY_ROWS", Some("0"))])],
            ]);
            let observation = observe_vpd_rls_for_schema(&cx, &conn, "").await;
            assert_eq!(
                observation.status,
                OracleVpdRlsObservationStatus::NoVisiblePolicyCatalogRows
            );
            assert!(
                observation
                    .detail
                    .contains("filtered read may still be silent"),
                "empty ALL_POLICIES must be a warning boundary: {observation:?}"
            );
            assert!(observation.policies.is_empty());
        });
    }

    #[test]
    fn quote_normalization_and_scope_matching_follow_oracle_rules() {
        let normalized = normalize_parts(&[
            RawNamePart::unquoted("mixed_case"),
            RawNamePart::quoted("MixedCase"),
        ])
        .expect("valid names");
        assert_eq!(normalized, ["MIXED_CASE", "MixedCase"]);
        assert!(parts_equal(
            &RawNamePart::unquoted("orders"),
            &RawNamePart::quoted("ORDERS")
        ));
        assert!(!parts_equal(
            &RawNamePart::unquoted("orders"),
            &RawNamePart::quoted("orders")
        ));

        let relation = oraclemcp_guard::StatementRelation {
            name: RawName::new(
                [RawNamePart::unquoted("app"), RawNamePart::quoted("Orders")],
                SyntacticRole::FromFactor,
            ),
            alias: Some(RawNamePart::quoted("o")),
        };
        assert!(relation_matches_qualifier(&relation, "o"));
        assert!(!relation_matches_qualifier(&relation, "O"));
        assert!(relation_matches_owner_name(&relation, "APP", "Orders"));
        assert!(!relation_matches_owner_name(&relation, "APP", "ORDERS"));
    }

    fn table_object() -> ResolvedObject {
        ResolvedObject {
            owner: "APP".to_owned(),
            name: "ORDERS".to_owned(),
            kind: CatalogObjectKind::Table,
            container: None,
            member: None,
            overloads: Vec::new(),
            quote_exact: false,
            synonym_chain: Vec::new(),
            db_link: None,
            identity: ResolvedIdentity {
                object_id: 42,
                edition: None,
            },
        }
    }

    fn table_catalog_row(owner: &str, name: &str, object_id: &str) -> OracleRow {
        row(&[
            ("OWNER", Some(owner)),
            ("OBJECT_NAME", Some(name)),
            ("OBJECT_TYPE", Some("TABLE")),
            ("OBJECT_ID", Some(object_id)),
            ("STATUS", Some("VALID")),
            ("EDITION_NAME", None),
        ])
    }

    #[test]
    fn issue31_three_part_column_binds_unqualified_from_by_identity() {
        run_with_cx(|cx| async move {
            let mut context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(1));
            context
                .statement_scope
                .relations
                .push(oraclemcp_guard::StatementRelation {
                    name: RawName::new(
                        [RawNamePart::unquoted("orders")],
                        SyntacticRole::FromFactor,
                    ),
                    alias: None,
                });
            let conn = ScriptedRows::new([
                vec![table_catalog_row("APP", "ORDERS", "42")],
                vec![table_catalog_row("APP", "ORDERS", "42")],
                vec![table_catalog_row("APP", "ORDERS", "42")],
                vec![row(&[("COLUMN_ID", Some("1"))])],
            ]);
            let raw = RawName::new(
                [
                    RawNamePart::unquoted("app"),
                    RawNamePart::unquoted("orders"),
                    RawNamePart::unquoted("id"),
                ],
                SyntacticRole::ValuePosition,
            );
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            let resolved = lookup.resolve_name(&raw).await.expect("catalog proof");
            let Resolution::Resolved(column) = resolved else {
                panic!("the owner-qualified column must bind the unaliased FROM identity")
            };
            assert_eq!(column.kind, CatalogObjectKind::Column);
            assert_eq!(column.owner, "APP");
            assert_eq!(column.name, "ID");
            assert_eq!(column.identity.object_id, 42);
            assert_eq!(conn.queries.lock().unwrap().len(), 4);
        });
    }

    #[test]
    fn issue31_three_part_column_with_other_owner_stays_refused() {
        let expected = table_object();
        let different_owner = ResolvedObject {
            owner: "OTHER".to_owned(),
            ..expected.clone()
        };
        let different_identity = ResolvedObject {
            identity: ResolvedIdentity {
                object_id: 43,
                edition: None,
            },
            ..expected.clone()
        };
        assert!(!resolved_relation_identity_matches(
            &expected,
            &different_owner
        ));
        assert!(!resolved_relation_identity_matches(
            &expected,
            &different_identity
        ));
    }

    fn issue32_context(alias: Option<&str>) -> ResolveCtx {
        let mut context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(1));
        context
            .statement_scope
            .relations
            .push(oraclemcp_guard::StatementRelation {
                name: RawName::new([RawNamePart::unquoted("orders")], SyntacticRole::FromFactor),
                alias: alias.map(RawNamePart::unquoted),
            });
        context
    }

    fn issue32_value(parts: &[&str]) -> RawName {
        RawName::new(
            parts.iter().map(|part| RawNamePart::unquoted(*part)),
            SyntacticRole::ValuePosition,
        )
    }

    #[test]
    fn issue32_json_dot_path_resolves_to_json_column() {
        run_with_cx(|cx| async move {
            for (data_type, json_rows) in [
                ("JSON", None),
                ("CLOB", Some(vec![row(&[("COLUMN_NAME", Some("DOC"))])])),
            ] {
                let mut responses = vec![
                    vec![table_catalog_row("APP", "ORDERS", "42")],
                    vec![row(&[("COLUMN_ID", Some("2"))])],
                    vec![row(&[
                        ("DATA_TYPE", Some(data_type)),
                        ("DATA_TYPE_OWNER", None),
                    ])],
                ];
                if let Some(json_rows) = json_rows {
                    responses.push(json_rows);
                    responses.push(vec![row(&[(
                        "SEARCH_CONDITION_VC",
                        Some("\"DOC\" IS JSON"),
                    )])]);
                }
                let conn = ScriptedRows::new(responses);
                let context = issue32_context(Some("j"));
                let raw = issue32_value(&["j", "doc", "customer", "id"]);
                let lookup = DictionaryLookup {
                    cx: &cx,
                    conn: &conn,
                    context: &context,
                };
                let Resolution::Resolved(column) =
                    lookup.resolve_name(&raw).await.expect("JSON catalog proof")
                else {
                    panic!("aliased JSON path must bind to its exact column");
                };
                assert_eq!(column.name, "DOC");
                assert_eq!(column.identity.object_id, 42);
            }
        });
    }

    #[test]
    fn issue32_text_json_path_requires_enabled_exact_constraint() {
        run_with_cx(|cx| async move {
            for constraints in [
                Vec::new(),
                vec![row(&[(
                    "SEARCH_CONDITION_VC",
                    Some("\"DOC\" IS JSON OR 1 = 1"),
                )])],
            ] {
                let conn = ScriptedRows::new([
                    vec![table_catalog_row("APP", "ORDERS", "42")],
                    vec![row(&[("COLUMN_ID", Some("2"))])],
                    vec![row(&[("DATA_TYPE", Some("CLOB"))])],
                    vec![row(&[("COLUMN_NAME", Some("DOC"))])],
                    constraints,
                ]);
                let context = issue32_context(Some("j"));
                let raw = issue32_value(&["j", "doc", "customer", "id"]);
                let lookup = DictionaryLookup {
                    cx: &cx,
                    conn: &conn,
                    context: &context,
                };
                assert!(matches!(
                    lookup.resolve_name(&raw).await.expect("check evidence"),
                    Resolution::Unresolved
                ));
            }
        });
    }

    #[test]
    fn issue32_object_attribute_chain_resolves() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new([
                vec![table_catalog_row("APP", "ORDERS", "42")],
                vec![row(&[("COLUMN_ID", Some("3"))])],
                vec![row(&[
                    ("DATA_TYPE", Some("ADDRESS_T")),
                    ("DATA_TYPE_OWNER", Some("APP")),
                ])],
                vec![row(&[
                    ("ATTR_NAME", Some("CITY")),
                    ("ATTR_TYPE_OWNER", None),
                    ("ATTR_TYPE_NAME", Some("VARCHAR2")),
                    ("ATTR_TYPE_MOD", None),
                ])],
            ]);
            let context = issue32_context(Some("e"));
            let raw = issue32_value(&["e", "address", "city"]);
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            let Resolution::Resolved(column) = lookup.resolve_name(&raw).await.expect("type proof")
            else {
                panic!("plain object attribute must bind to the leading column");
            };
            assert_eq!(column.name, "ADDRESS");
        });
    }

    #[test]
    fn issue32_object_method_call_stays_refused() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new([
                vec![table_catalog_row("APP", "ORDERS", "42")],
                vec![row(&[("COLUMN_ID", Some("3"))])],
                vec![row(&[
                    ("DATA_TYPE", Some("ADDRESS_T")),
                    ("DATA_TYPE_OWNER", Some("APP")),
                ])],
                Vec::new(),
            ]);
            let context = issue32_context(Some("e"));
            let raw = issue32_value(&["e", "address", "get_city"]);
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            assert!(matches!(
                lookup
                    .resolve_name(&raw)
                    .await
                    .expect("missing method attribute"),
                Resolution::Unresolved
            ));
        });
    }

    #[test]
    fn issue32_ref_attribute_stays_refused() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new([
                vec![table_catalog_row("APP", "ORDERS", "42")],
                vec![row(&[("COLUMN_ID", Some("3"))])],
                vec![row(&[
                    ("DATA_TYPE", Some("ADDRESS_T")),
                    ("DATA_TYPE_OWNER", Some("APP")),
                ])],
                vec![row(&[
                    ("ATTR_NAME", Some("CITY")),
                    ("ATTR_TYPE_OWNER", Some("APP")),
                    ("ATTR_TYPE_NAME", Some("CITY_T")),
                    ("ATTR_TYPE_MOD", Some("REF")),
                ])],
            ]);
            let context = issue32_context(Some("e"));
            let raw = issue32_value(&["e", "address", "city"]);
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            assert!(matches!(
                lookup
                    .resolve_name(&raw)
                    .await
                    .expect("REF attribute evidence"),
                Resolution::Unresolved
            ));
        });
    }

    #[test]
    fn issue32_unaliased_dotted_path_keeps_owner_table_column_meaning() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new(vec![Vec::new(); 16]);
            let context = issue32_context(None);
            let raw = issue32_value(&["orders", "doc", "customer"]);
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            assert!(matches!(
                lookup
                    .resolve_name(&raw)
                    .await
                    .expect("unaliased resolution"),
                Resolution::Unresolved
            ));
            assert!(conn.queries.lock().unwrap().iter().all(|(sql, _)| {
                !sql.contains("all_json_columns") && !sql.contains("all_type_attrs")
            }));
        });
    }

    fn merged_join_context(natural: bool) -> ResolveCtx {
        let left = oraclemcp_guard::StatementRelation {
            name: RawName::new([RawNamePart::unquoted("t1")], SyntacticRole::FromFactor),
            alias: None,
        };
        let right = oraclemcp_guard::StatementRelation {
            name: RawName::new([RawNamePart::unquoted("t2")], SyntacticRole::FromFactor),
            alias: None,
        };
        let mut context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(1));
        context.statement_scope.relations = vec![left.clone(), right.clone()];
        context
            .statement_scope
            .merged_joins
            .push(oraclemcp_guard::resolver::MergedJoin {
                left,
                right,
                using_columns: (!natural).then(|| vec![RawNamePart::unquoted("id")]),
            });
        context
    }

    fn merged_id_catalog() -> ScriptedRows {
        ScriptedRows::new([
            vec![table_catalog_row("APP", "T1", "42")],
            vec![row(&[("COLUMN_ID", Some("1"))])],
            vec![table_catalog_row("APP", "T2", "43")],
            vec![row(&[("COLUMN_ID", Some("1"))])],
        ])
    }

    #[test]
    fn issue29_using_column_resolves_once() {
        run_with_cx(|cx| async move {
            let context = merged_join_context(false);
            let conn = merged_id_catalog();
            let raw = RawName::new([RawNamePart::unquoted("id")], SyntacticRole::ValuePosition);
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            let Resolution::Resolved(column) =
                lookup.resolve_name(&raw).await.expect("catalog proof")
            else {
                panic!("USING must merge two proved ID columns into one output")
            };
            assert_eq!(column.kind, CatalogObjectKind::Column);
            assert_eq!(column.name, "ID");
            assert_eq!(conn.queries.lock().unwrap().len(), 4);
        });
    }

    #[test]
    fn issue29_natural_join_merges_shared_columns() {
        run_with_cx(|cx| async move {
            let context = merged_join_context(true);
            let conn = merged_id_catalog();
            let raw = RawName::new([RawNamePart::unquoted("id")], SyntacticRole::ValuePosition);
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            assert!(matches!(
                lookup.resolve_name(&raw).await.expect("catalog proof"),
                Resolution::Resolved(_)
            ));
            assert_eq!(conn.queries.lock().unwrap().len(), 4);
        });
    }

    #[test]
    fn issue29_qualified_using_column_stays_refused() {
        run_with_cx(|cx| async move {
            let context = merged_join_context(false);
            let conn = ScriptedRows::new([]);
            let raw = RawName::new(
                [RawNamePart::unquoted("t1"), RawNamePart::unquoted("id")],
                SyntacticRole::ValuePosition,
            );
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };
            assert!(matches!(
                lookup.resolve_name(&raw).await.expect("merge refusal"),
                Resolution::Unresolved
            ));
            assert!(conn.queries.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn resolved_relation_purity_answers_unknown_for_unproven_object() {
        let object = table_object();
        let source = ObjectRef::new(Some("app".to_owned()), "orders");
        let proof = ReadPlanProof {
            relations: vec![object.clone()],
            by_source: HashMap::from([(source.clone(), vec![ReadObjectIdentity::from(&object)])]),
            by_identity: HashMap::from([(
                ReadObjectIdentity::from(&object),
                Purity::ProvenReadOnly,
            )]),
            proved_value_columns: HashSet::new(),
        };
        assert_eq!(
            proof.statement_purity(std::slice::from_ref(&source)),
            Purity::ProvenReadOnly
        );
        assert_eq!(proof.statement_purity(&[]), Purity::Unknown);
        assert_eq!(
            proof.statement_purity(&[source, ObjectRef::new(Some("app".to_owned()), "secret")]),
            Purity::Unknown
        );
        let substituted = ReadPlanProof {
            by_identity: HashMap::new(),
            ..proof
        };
        assert_eq!(
            substituted.statement_purity(&[ObjectRef::new(Some("app".to_owned()), "orders")]),
            Purity::Unknown
        );
    }

    #[test]
    fn batched_proof_query_count_at_1_10_100_relations() {
        run_with_cx(|cx| async move {
            let mut cases = Vec::new();
            for count in [1_usize, 10, 100] {
                let chunks = count.div_ceil(32);
                let conn = ScriptedRows::new(vec![Vec::new(); 2 * chunks + 2]);
                let relations = (0..count)
                    .map(|index| ResolvedObject {
                        name: format!("T{index}"),
                        identity: ResolvedIdentity {
                            object_id: 1_000 + index as u64,
                            edition: None,
                        },
                        ..table_object()
                    })
                    .collect::<Vec<_>>();
                let started = std::time::Instant::now();
                assert_eq!(
                    resolved_relations_read_purity(&cx, &conn, &relations, &[])
                        .await
                        .expect("clean batched proof"),
                    Purity::ProvenReadOnly
                );
                let queries = conn.queries.lock().expect("queries lock");
                assert_eq!(queries.len(), 2 + 2 * chunks);
                for (_, binds) in queries.iter().take(2 * chunks) {
                    assert_eq!(binds.len(), 64, "fixed-width padded batch binds");
                }
                cases.push(serde_json::json!({
                    "relations": count,
                    "queries": queries.len(),
                    "elapsed_ms": started.elapsed().as_millis(),
                }));
            }
            write_catalog_test_artifact("batched_purity_1_10_100", &cases);
        });
    }

    #[test]
    fn relation_purity_requires_plain_policy_free_non_virtual_tables() {
        run_with_cx(|cx| async move {
            // Every catalog probe SUCCEEDS with zero rows: no object-scoped VPD
            // policy, no virtual column, and — the fix — empty-but-successful
            // ALL_POLICIES / ALL_TAB_COLS visibility probes. A successful empty
            // read is positive proof of no VPD (0 policies = nothing to prove
            // around), not blindness, so the proof is satisfied.
            let clean = ScriptedRows::new([Vec::new(), Vec::new(), Vec::new(), Vec::new()]);
            assert_eq!(
                resolved_relations_read_purity(&cx, &clean, &[table_object()], &[])
                    .await
                    .expect("clean table proof"),
                oraclemcp_guard::Purity::ProvenReadOnly
            );
            {
                let queries = clean.queries.lock().expect("queries lock");
                assert_eq!(queries.len(), 4);
                assert_eq!(queries[0].0, POLICY_ROWS_FOR_RELATIONS_32_SQL);
                assert_eq!(queries[1].0, VIRTUAL_COLUMNS_FOR_RELATIONS_32_SQL);
                assert_eq!(queries[2].0, POLICY_CATALOG_PROOF_SQL);
                assert_eq!(queries[3].0, TARGET_COLUMN_CATALOG_PROOF_SQL);
            }

            let policy = ScriptedRows::new([vec![row(&[("POLICY_NAME", Some("P"))])]]);
            assert_eq!(
                resolved_relations_read_purity(&cx, &policy, &[table_object()], &[])
                    .await
                    .expect("policy evidence"),
                oraclemcp_guard::Purity::Unknown
            );

            let virtual_column =
                ScriptedRows::new([Vec::new(), vec![row(&[("COLUMN_NAME", Some("TOTAL"))])]]);
            assert_eq!(
                resolved_relations_read_purity(&cx, &virtual_column, &[table_object()], &[])
                    .await
                    .expect("virtual-column evidence"),
                oraclemcp_guard::Purity::Unknown
            );

            for object in [
                ResolvedObject {
                    kind: CatalogObjectKind::View,
                    ..table_object()
                },
                ResolvedObject {
                    db_link: Some("REMOTE".to_owned()),
                    ..table_object()
                },
                ResolvedObject {
                    identity: ResolvedIdentity {
                        object_id: 0,
                        edition: None,
                    },
                    ..table_object()
                },
            ] {
                let no_io = ScriptedRows::new([]);
                assert_eq!(
                    resolved_relations_read_purity(&cx, &no_io, std::slice::from_ref(&object), &[])
                        .await
                        .expect("unsupported relation fails closed"),
                    oraclemcp_guard::Purity::Unknown
                );
                assert!(no_io.queries.lock().expect("queries lock").is_empty());
            }
        });
    }

    fn issue30_virtual_column_row(
        column: &str,
        hidden: &str,
        generated: &str,
        expression: &str,
    ) -> OracleRow {
        row(&[
            ("OWNER", Some("APP")),
            ("TABLE_NAME", Some("ORDERS")),
            ("COLUMN_NAME", Some(column)),
            ("HIDDEN_COLUMN", Some(hidden)),
            ("USER_GENERATED", Some(generated)),
            ("DATA_DEFAULT", Some(expression)),
        ])
    }

    #[test]
    fn issue30_hidden_system_virtual_column_is_ignored_when_unreferenced() {
        run_with_cx(|cx| async move {
            for (column, expression) in [
                ("SYS_NC00003$", "UPPER(\"LABEL\")"),
                ("SYS_STU$123", "SYS_OP_COMBINED_HASH(\"LABEL\",\"ID\")"),
                (
                    "SYS_IME_OSON_123",
                    "OSON(\"DOC\" FORMAT OSON , 'ime' RETURNING RAW(2000) NULL ON ERROR)",
                ),
            ] {
                let conn = ScriptedRows::new([
                    Vec::new(),
                    vec![issue30_virtual_column_row(column, "YES", "NO", expression)],
                    Vec::new(),
                    Vec::new(),
                ]);
                assert_eq!(
                    resolved_relations_read_purity(&cx, &conn, &[table_object()], &[])
                        .await
                        .expect("bounded complete built-in expression"),
                    Purity::ProvenReadOnly,
                );
            }
        });
    }

    #[test]
    fn issue30_user_visible_virtual_column_stays_unknown() {
        run_with_cx(|cx| async move {
            for (hidden, generated, values) in [
                ("NO", "YES", Vec::new()),
                (
                    "YES",
                    "NO",
                    vec![RawName::new(
                        [RawNamePart::unquoted("SYS_NC00003$")],
                        SyntacticRole::ValuePosition,
                    )],
                ),
            ] {
                let conn = ScriptedRows::new([
                    Vec::new(),
                    vec![issue30_virtual_column_row(
                        "SYS_NC00003$",
                        hidden,
                        generated,
                        "UPPER(\"LABEL\")",
                    )],
                ]);
                assert_eq!(
                    resolved_relations_read_purity(&cx, &conn, &[table_object()], &values)
                        .await
                        .expect("visible or referenced virtual column"),
                    Purity::Unknown,
                );
            }
        });
    }

    #[test]
    fn issue30_hidden_column_calling_user_function_stays_unknown() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new([
                Vec::new(),
                vec![issue30_virtual_column_row(
                    "SYS_NC00003$",
                    "YES",
                    "NO",
                    "APP.CANARY_FN(\"LABEL\")",
                )],
            ]);
            assert_eq!(
                resolved_relations_read_purity(&cx, &conn, &[table_object()], &[])
                    .await
                    .expect("user routine evidence"),
                Purity::Unknown,
            );
        });
    }

    #[test]
    fn issue30_truncated_data_default_stays_unknown() {
        run_with_cx(|cx| async move {
            let truncated = " ".repeat(4000);
            let conn = ScriptedRows::new([
                Vec::new(),
                vec![issue30_virtual_column_row(
                    "SYS_NC00003$",
                    "YES",
                    "NO",
                    &truncated,
                )],
            ]);
            assert_eq!(
                resolved_relations_read_purity(&cx, &conn, &[table_object()], &[])
                    .await
                    .expect("truncated expression evidence"),
                Purity::Unknown,
            );
            let mut capped =
                issue30_virtual_column_row("SYS_NC00004$", "YES", "NO", "UPPER(\"LABEL\")");
            capped
                .columns
                .iter_mut()
                .find(|(name, _)| name == "DATA_DEFAULT")
                .expect("synthetic expression cell")
                .1
                .source_length = Some(5000);
            let conn = ScriptedRows::new([Vec::new(), vec![capped]]);
            assert_eq!(
                resolved_relations_read_purity(&cx, &conn, &[table_object()], &[])
                    .await
                    .expect("driver capped expression evidence"),
                Purity::Unknown,
            );
        });
    }

    /// Default-build differential for the VPD and virtual-column metadata
    /// boundary.  Only a complete, successful clean snapshot earns the
    /// `READ_ONLY`-permitting purity proof.  A visible VPD policy is
    /// deliberately `Unknown`; unavailable policy or column metadata aborts
    /// the proof, which the dispatcher turns into its fail-closed refusal.
    #[test]
    fn default_resolver_vpd_metadata_never_grants_read_only_on_uncertainty() {
        run_with_cx(|cx| async move {
            let clean = ScriptedRows::new([Vec::new(), Vec::new(), Vec::new(), Vec::new()]);
            assert_eq!(
                resolved_relations_read_purity(&cx, &clean, &[table_object()], &[])
                    .await
                    .expect("complete clean metadata proves read-only"),
                oraclemcp_guard::Purity::ProvenReadOnly
            );

            let vpd = ScriptedRows::new([vec![row(&[("POLICY_NAME", Some("SYNTHETIC_VPD"))])]]);
            let vpd_purity = resolved_relations_read_purity(&cx, &vpd, &[table_object()], &[])
                .await
                .expect("visible VPD is a normal, non-error metadata answer");
            assert_eq!(vpd_purity, oraclemcp_guard::Purity::Unknown);
            assert!(
                !vpd_purity.permits_safe(),
                "a table with a SELECT VPD policy must not be admitted at READ_ONLY"
            );

            for (name, responses, expected_probe) in [
                (
                    "policy catalog",
                    vec![Err(DbError::Query(
                        "ORA-00942: ALL_POLICIES unavailable".to_owned(),
                    ))],
                    POLICY_ROWS_FOR_RELATIONS_32_SQL,
                ),
                (
                    "column catalog",
                    vec![
                        Ok(Vec::new()),
                        Err(DbError::Query(
                            "ORA-00942: ALL_TAB_COLS unavailable".to_owned(),
                        )),
                    ],
                    VIRTUAL_COLUMNS_FOR_RELATIONS_32_SQL,
                ),
            ] {
                let blind = ScriptedRows::results(responses);
                let refusal =
                    resolved_relations_read_purity(&cx, &blind, &[table_object()], &[]).await;
                assert!(
                    refusal.is_err(),
                    "unavailable {name} metadata must abort the proof so dispatch refuses; got {refusal:?}"
                );
                assert!(
                    blind
                        .queries
                        .lock()
                        .expect("queries lock")
                        .iter()
                        .any(|(sql, _)| sql == expected_probe),
                    "the intended {name} boundary must be queried before refusal"
                );
            }

            // The object-scoped probes above are not sufficient evidence by
            // themselves: both readability proofs must run and must propagate
            // their own errors.  Keep these separate from the earlier cases so
            // deleting either proof cannot be masked by an earlier query
            // failure.
            for (name, responses, expected_proof) in [
                (
                    "ALL_POLICIES readability proof",
                    vec![
                        Ok(Vec::new()),
                        Ok(Vec::new()),
                        Err(DbError::Query(
                            "ORA-00942: ALL_POLICIES readability proof unavailable".to_owned(),
                        )),
                    ],
                    POLICY_CATALOG_PROOF_SQL,
                ),
                (
                    "ALL_TAB_COLS readability proof",
                    vec![
                        Ok(Vec::new()),
                        Ok(Vec::new()),
                        Ok(Vec::new()),
                        Err(DbError::Query(
                            "ORA-00942: ALL_TAB_COLS readability proof unavailable".to_owned(),
                        )),
                    ],
                    TARGET_COLUMN_CATALOG_PROOF_SQL,
                ),
            ] {
                let blind = ScriptedRows::results(responses);
                let refusal =
                    resolved_relations_read_purity(&cx, &blind, &[table_object()], &[]).await;
                assert!(
                    refusal.is_err(),
                    "unavailable {name} must abort the proof so dispatch refuses; got {refusal:?}"
                );
                assert!(
                    blind
                        .queries
                        .lock()
                        .expect("queries lock")
                        .iter()
                        .any(|(sql, _)| sql == expected_proof),
                    "the {name} query itself must be reached before refusal"
                );
            }
        });
    }

    #[test]
    fn object_rows_reject_invalid_and_wrong_edition_evidence() {
        let mut context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(7));
        context.edition = Some("BLUE".to_owned());
        let valid = row(&[
            ("OWNER", Some("APP")),
            ("OBJECT_NAME", Some("ORDERS")),
            ("OBJECT_TYPE", Some("TABLE")),
            ("OBJECT_ID", Some("42")),
            ("STATUS", Some("VALID")),
            ("EDITION_NAME", None),
        ]);
        assert!(ObjectFact::from_row(&valid, &context).is_some());
        let wrong_edition = row(&[
            ("OWNER", Some("APP")),
            ("OBJECT_NAME", Some("F")),
            ("OBJECT_TYPE", Some("FUNCTION")),
            ("OBJECT_ID", Some("43")),
            ("STATUS", Some("VALID")),
            ("EDITION_NAME", Some("GREEN")),
        ]);
        assert!(ObjectFact::from_row(&wrong_edition, &context).is_none());
    }

    #[test]
    fn zero_arg_filter_keeps_only_overloads_without_required_inputs() {
        let rows = vec![
            ArgumentFact {
                subprogram_id: 1,
                overload: Some("1".to_owned()),
                position: 0,
                data_level: 0,
                in_out: "OUT".to_owned(),
                defaulted: false,
                argument_name: None,
                data_type: None,
            },
            ArgumentFact {
                subprogram_id: 2,
                overload: Some("2".to_owned()),
                position: 0,
                data_level: 0,
                in_out: "OUT".to_owned(),
                defaulted: false,
                argument_name: None,
                data_type: None,
            },
            ArgumentFact {
                subprogram_id: 2,
                overload: Some("2".to_owned()),
                position: 1,
                data_level: 0,
                in_out: "IN".to_owned(),
                defaulted: false,
                argument_name: None,
                data_type: None,
            },
            ArgumentFact {
                subprogram_id: 3,
                overload: Some("3".to_owned()),
                position: 0,
                data_level: 0,
                in_out: "OUT".to_owned(),
                defaulted: false,
                argument_name: None,
                data_type: None,
            },
            ArgumentFact {
                subprogram_id: 3,
                overload: Some("3".to_owned()),
                position: 1,
                data_level: 0,
                in_out: "IN".to_owned(),
                defaulted: true,
                argument_name: None,
                data_type: None,
            },
        ];
        let overloads = callable_overloads(&rows, true).expect("bounded overload set");
        assert_eq!(
            overloads
                .overloads
                .iter()
                .map(|item| item.subprogram_id)
                .collect::<Vec<_>>(),
            [1, 3]
        );
    }

    #[test]
    fn unshadowed_qualified_value_resolves_as_zero_arg_package_member() {
        run_with_cx(|cx| async move {
            let conn = ScriptedRows::new([
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![row(&[
                    ("OWNER", Some("APP")),
                    ("SYNONYM_NAME", Some("PKG_ALIAS")),
                    ("TABLE_OWNER", Some("APP")),
                    ("TABLE_NAME", Some("PKG")),
                    ("DB_LINK", None),
                    ("OBJECT_ID", Some("101")),
                    ("STATUS", Some("VALID")),
                    ("EDITION_NAME", None),
                ])],
                vec![row(&[
                    ("OWNER", Some("APP")),
                    ("OBJECT_NAME", Some("PKG")),
                    ("OBJECT_TYPE", Some("PACKAGE")),
                    ("OBJECT_ID", Some("102")),
                    ("STATUS", Some("VALID")),
                    ("EDITION_NAME", None),
                ])],
                vec![row(&[
                    ("SUBPROGRAM_ID", Some("1")),
                    ("OVERLOAD", None),
                    ("POSITION", Some("0")),
                    ("DATA_LEVEL", Some("0")),
                    ("IN_OUT", Some("OUT")),
                    ("DEFAULTED", Some("N")),
                ])],
            ]);
            let context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(11));
            let raw = RawName::new(
                [
                    RawNamePart::unquoted("pkg_alias"),
                    RawNamePart::unquoted("zero"),
                ],
                SyntacticRole::ValuePosition,
            );
            let lookup = DictionaryLookup {
                cx: &cx,
                conn: &conn,
                context: &context,
            };

            let Resolution::Resolved(resolved) = lookup
                .resolve_value(&raw, &["PKG_ALIAS".to_owned(), "ZERO".to_owned()])
                .await
                .expect("dictionary resolution")
            else {
                panic!("unshadowed package.member must resolve");
            };
            assert_eq!(resolved.kind, CatalogObjectKind::Function);
            assert_eq!(resolved.name, "ZERO");
            assert_eq!(resolved.container.as_ref().unwrap().name, "PKG");
            assert_eq!(resolved.synonym_chain.len(), 1);
            assert_eq!(resolved.overloads.len(), 1);
        });
    }

    #[test]
    fn snapshot_rejects_generation_role_scope_or_name_misses() {
        let context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(4));
        let loaded = RawName::new([RawNamePart::unquoted("orders")], SyntacticRole::FromFactor);
        let mut entries = HashMap::new();
        entries.insert(
            loaded.clone(),
            Resolution::Resolved(Box::new(ResolvedObject {
                owner: "APP".to_owned(),
                name: "ORDERS".to_owned(),
                kind: CatalogObjectKind::Table,
                container: None,
                member: None,
                overloads: Vec::new(),
                quote_exact: false,
                synonym_chain: Vec::new(),
                db_link: None,
                identity: ResolvedIdentity {
                    object_id: 44,
                    edition: None,
                },
            })),
        );
        let resolver = OracleCatalogResolver {
            context: context.clone(),
            entries,
        };
        assert!(matches!(
            resolver.resolve(&loaded, &context),
            Resolution::Resolved(_)
        ));
        let mut stale = context.clone();
        stale.generation = oraclemcp_guard::CatalogGeneration(5);
        assert_eq!(resolver.resolve(&loaded, &stale), Resolution::Unresolved);
        let mut role_drift = context.clone();
        role_drift.enabled_roles.insert("REPORTER".to_owned());
        assert_eq!(
            resolver.resolve(&loaded, &role_drift),
            Resolution::Unresolved
        );
        let mut scope_drift = context.clone();
        scope_drift
            .statement_scope
            .aliases
            .push(RawNamePart::unquoted("o"));
        assert_eq!(
            resolver.resolve(&loaded, &scope_drift),
            Resolution::Unresolved
        );
        let missing = RawName::new(
            [RawNamePart::unquoted("customers")],
            SyntacticRole::FromFactor,
        );
        assert_eq!(resolver.resolve(&missing, &context), Resolution::Unresolved);
    }

    #[test]
    fn synonym_walk_rejects_cycles_and_overlong_chains() {
        let mut visited = HashSet::new();
        assert!(record_synonym_visit(&mut visited, "APP", "A", 0));
        assert!(record_synonym_visit(&mut visited, "APP", "B", 1));
        assert!(!record_synonym_visit(&mut visited, "APP", "A", 2));

        let mut fresh = HashSet::new();
        assert!(!record_synonym_visit(
            &mut fresh,
            "APP",
            "TOO_DEEP",
            MAX_SYNONYM_HOPS
        ));
    }

    #[test]
    fn remote_alternative_never_becomes_a_resolved_identity() {
        let local = Resolution::Resolved(Box::new(ResolvedObject {
            owner: "APP".to_owned(),
            name: "P".to_owned(),
            kind: CatalogObjectKind::Procedure,
            container: None,
            member: None,
            overloads: Vec::new(),
            quote_exact: false,
            synonym_chain: Vec::new(),
            db_link: None,
            identity: ResolvedIdentity {
                object_id: 9,
                edition: None,
            },
        }));
        let remote = Resolution::Remote {
            db_link: RawNamePart::unquoted("REMOTE_DB"),
        };
        assert_eq!(
            merge_alternatives(local.clone(), remote.clone()),
            Resolution::Unresolved
        );
        assert_eq!(merge_alternatives(remote, local), Resolution::Unresolved);
    }

    fn resolved_table(object_id: u64) -> Resolution {
        Resolution::Resolved(Box::new(ResolvedObject {
            owner: "APP".to_owned(),
            name: "ORDERS".to_owned(),
            kind: CatalogObjectKind::Table,
            container: None,
            member: None,
            overloads: Vec::new(),
            quote_exact: false,
            synonym_chain: Vec::new(),
            db_link: None,
            identity: ResolvedIdentity {
                object_id,
                edition: None,
            },
        }))
    }

    fn cache_context(cache: &OracleCatalogResolverCache) -> ResolveCtx {
        let mut context = ResolveCtx::new("APP", "APP", cache.generation());
        context.edition = Some("ORA$BASE".to_owned());
        context
    }

    fn publish_one(
        cache: &OracleCatalogResolverCache,
        name: &RawName,
        context: &ResolveCtx,
        resolution: Resolution,
    ) -> bool {
        cache.publish(
            context.generation,
            context,
            HashMap::from([(name.clone(), resolution)]),
        )
    }

    #[test]
    fn every_catalog_mutation_reason_advances_monotonically_and_clears_entries() {
        let cache = OracleCatalogResolverCache::new();
        let name = RawName::new([RawNamePart::unquoted("orders")], SyntacticRole::FromFactor);
        let reasons = [
            CatalogInvalidation::Ddl,
            CatalogInvalidation::Synonym,
            CatalogInvalidation::Package,
            CatalogInvalidation::Overload,
            CatalogInvalidation::CurrentSchema,
            CatalogInvalidation::Edition,
            CatalogInvalidation::Roles,
            CatalogInvalidation::Reconnect,
            CatalogInvalidation::SessionContextChanged,
            CatalogInvalidation::SemanticProofRefresh,
        ];
        let mut prior = cache.generation().0;
        for reason in reasons {
            let context = cache_context(&cache);
            assert!(publish_one(&cache, &name, &context, resolved_table(prior)));
            assert_eq!(cache.len(), 1);
            let next = cache.invalidate(reason).0;
            assert_eq!(next, prior + 1);
            assert!(cache.is_empty());
            assert_eq!(cache.resolve(&name, &context), Resolution::Unresolved);
            prior = next;
        }
    }

    #[test]
    fn cache_key_is_exact_for_schema_edition_roles_scope_and_quote_identity() {
        let cache = OracleCatalogResolverCache::new();
        let unquoted = RawName::new([RawNamePart::unquoted("orders")], SyntacticRole::FromFactor);
        let quoted = RawName::new([RawNamePart::quoted("ORDERS")], SyntacticRole::FromFactor);
        let context = cache_context(&cache);
        assert!(publish_one(&cache, &unquoted, &context, resolved_table(71)));
        assert!(matches!(
            cache.resolve(&unquoted, &context),
            Resolution::Resolved(_)
        ));
        assert_eq!(cache.resolve(&quoted, &context), Resolution::Unresolved);

        let mut changed = context.clone();
        changed.current_schema = "OTHER".to_owned();
        assert_eq!(cache.resolve(&unquoted, &changed), Resolution::Unresolved);
        changed = context.clone();
        changed.edition = Some("BLUE".to_owned());
        assert_eq!(cache.resolve(&unquoted, &changed), Resolution::Unresolved);
        changed = context.clone();
        changed.enabled_roles.insert("REPORTER".to_owned());
        assert_eq!(cache.resolve(&unquoted, &changed), Resolution::Unresolved);
        changed = context.clone();
        changed
            .statement_scope
            .aliases
            .push(RawNamePart::unquoted("o"));
        assert_eq!(cache.resolve(&unquoted, &changed), Resolution::Unresolved);
    }

    #[test]
    fn stale_publication_cannot_cross_an_invalidation_race() {
        let cache = Arc::new(OracleCatalogResolverCache::new());
        let context = cache_context(&cache);
        let name = RawName::new([RawNamePart::unquoted("orders")], SyntacticRole::FromFactor);
        let barrier = Arc::new(Barrier::new(2));
        let invalidator_cache = Arc::clone(&cache);
        let invalidator_barrier = Arc::clone(&barrier);
        let invalidator = thread::spawn(move || {
            invalidator_barrier.wait();
            invalidator_cache.invalidate(CatalogInvalidation::Ddl)
        });
        barrier.wait();
        let new_generation = invalidator.join().expect("invalidation thread");
        assert!(new_generation > context.generation);
        assert!(!publish_one(&cache, &name, &context, resolved_table(72)));
        assert!(cache.is_empty());
        assert_eq!(cache.resolve(&name, &context), Resolution::Unresolved);
    }

    #[test]
    fn concurrent_readers_never_accept_old_context_after_invalidation_completes() {
        let cache = Arc::new(OracleCatalogResolverCache::new());
        let context = cache_context(&cache);
        let name = RawName::new([RawNamePart::unquoted("orders")], SyntacticRole::FromFactor);
        assert!(publish_one(&cache, &name, &context, resolved_table(73)));
        let start = Arc::new(Barrier::new(17));
        let mut readers = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            let context = context.clone();
            let name = name.clone();
            let start = Arc::clone(&start);
            readers.push(thread::spawn(move || {
                start.wait();
                while cache.generation() == context.generation {
                    let _ = cache.resolve(&name, &context);
                }
                for _ in 0..1_000 {
                    assert_eq!(cache.resolve(&name, &context), Resolution::Unresolved);
                }
            }));
        }
        start.wait();
        cache.invalidate(CatalogInvalidation::Reconnect);
        for reader in readers {
            reader.join().expect("reader thread");
        }
    }

    #[test]
    fn negative_entries_are_cached_only_in_their_generation() {
        let cache = OracleCatalogResolverCache::new();
        let name = RawName::new(
            [RawNamePart::unquoted("missing")],
            SyntacticRole::FromFactor,
        );
        let old = cache_context(&cache);
        assert!(publish_one(&cache, &name, &old, Resolution::Unresolved));
        assert_eq!(cache.len(), 1);
        cache.invalidate(CatalogInvalidation::Ddl);
        assert!(cache.is_empty());
        let current = cache_context(&cache);
        assert_ne!(old.generation, current.generation);
        assert_eq!(cache.resolve(&name, &old), Resolution::Unresolved);
        assert_eq!(cache.resolve(&name, &current), Resolution::Unresolved);
    }

    #[test]
    fn generation_exhaustion_is_terminal_and_never_wraps_to_old_evidence() {
        let cache = OracleCatalogResolverCache::new();
        {
            let mut state = cache.state.write().expect("cache state");
            state.generation = u64::MAX - 1;
        }
        assert_eq!(
            cache.invalidate(CatalogInvalidation::Ddl),
            oraclemcp_guard::CatalogGeneration(u64::MAX)
        );
        assert_eq!(
            cache.invalidate(CatalogInvalidation::Ddl),
            oraclemcp_guard::CatalogGeneration(u64::MAX)
        );
        let context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(u64::MAX));
        let name = RawName::new([RawNamePart::unquoted("orders")], SyntacticRole::FromFactor);
        assert!(!publish_one(&cache, &name, &context, resolved_table(74)));
        assert_eq!(cache.resolve(&name, &context), Resolution::Unresolved);
    }

    // ---------------------------------------------------------------------
    // C8 fixture — a blind catalog probe is not evidence of absence.
    // Plan §4-C8 / §A.2.3 / §A.10 S1,
    // bead oraclemcp-091-c8-blind-catalog-refuse-w9iie.
    // ---------------------------------------------------------------------

    /// A connection whose dictionary visibility is a property of the
    /// *principal*, not of the object being asked about.
    ///
    /// Both purity probes return empty either way — that is the whole point.
    /// Two principals to tell apart: one that can genuinely read the data
    /// dictionary and sees a clean table (no SELECT VPD policy, no virtual
    /// column), and one that cannot read `ALL_POLICIES` / `ALL_TAB_COLS` at
    /// all. On these PUBLIC dictionary views the difference is Ok-vs-error, NOT
    /// row count: the sighted principal's every probe SUCCEEDS with zero rows,
    /// while the blind principal's probe ERRORS (ORA-00942 / insufficient
    /// privilege). Modeling blindness as an empty success — the pre-fix
    /// assumption — is simply wrong for Oracle's dictionary views, and it is
    /// what made the guard refuse every read on any VPD-free database.
    struct CatalogVisibility {
        readable: bool,
        queries: Mutex<Vec<String>>,
    }

    impl CatalogVisibility {
        fn blind() -> Self {
            Self {
                readable: false,
                queries: Mutex::new(Vec::new()),
            }
        }

        fn sighted() -> Self {
            Self {
                readable: true,
                queries: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for CatalogVisibility {
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
            self.queries
                .lock()
                .expect("queries lock")
                .push(sql.to_owned());
            if !self.readable {
                // A principal that cannot read the data dictionary gets an
                // Oracle error, never an empty success. This is the only honest
                // model of catalog blindness on these PUBLIC views, and it is
                // what makes the probe's Ok-vs-error determinant meaningful:
                // the error propagates out of the proof and fails closed.
                return Err(DbError::Query(
                    "ORA-00942: table or view does not exist".to_owned(),
                ));
            }
            // Sighted principal, genuinely clean table: no VPD policy, no
            // virtual column, and the visibility probes succeed with zero rows.
            // Empty here is proven absence, not blindness.
            Ok(Vec::new())
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Err(DbError::Execute("unexpected execute".to_owned()))
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Err(DbError::Execute("unexpected commit".to_owned()))
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Err(DbError::Execute("unexpected rollback".to_owned()))
        }
    }

    /// The allow half of C8, and it must stay allowed: a principal that can
    /// genuinely read the dictionary, asking about a genuinely clean table,
    /// earns a read-only proof from a SUCCESSFUL-BUT-EMPTY catalog probe. An
    /// empty `ALL_POLICIES` read is positive proof of no VPD (0 policies =
    /// nothing to prove around), the case that dominates real databases.
    ///
    /// Without this, the fix has a trivial wrong answer available — return
    /// `Unknown` on every empty probe and call the fail-open closed. That is
    /// exactly the regression this change repairs: it refused every ordinary
    /// table on every VPD-free database.
    #[test]
    fn c8_a_sighted_principal_on_a_clean_table_still_proves_read_only() {
        run_with_cx(|cx| async move {
            let sighted = CatalogVisibility::sighted();
            assert_eq!(
                resolved_relations_read_purity(&cx, &sighted, &[table_object()], &[])
                    .await
                    .expect("clean table proof"),
                oraclemcp_guard::Purity::ProvenReadOnly,
                "a readable dictionary plus a clean table is a real read-only proof"
            );
            // Both gates are reached, so the red case below is about both of
            // them and not merely the first one short-circuiting.
            let asked = sighted.queries.lock().expect("queries lock");
            assert!(
                asked
                    .iter()
                    .any(|sql| sql == POLICY_ROWS_FOR_RELATIONS_32_SQL),
                "the SELECT VPD policy probe must run: {asked:?}"
            );
            assert!(
                asked
                    .iter()
                    .any(|sql| sql == VIRTUAL_COLUMNS_FOR_RELATIONS_32_SQL),
                "the virtual-column probe must run: {asked:?}"
            );
        });
    }

    /// The failing-closed half of C8: genuine catalog blindness must refuse.
    ///
    /// A principal that cannot read `ALL_POLICIES` / `ALL_TAB_COLS` gets an
    /// Oracle error, never an empty success (these are PUBLIC views; losing
    /// access is ORA-00942, not zero rows). That error propagates out of the
    /// read-purity proof and the caller maps it to a fail-closed refusal, so a
    /// blind principal never earns a read-only verdict. This is the correct
    /// distinction the guard now draws: an *error* is blindness (refuse); a
    /// *successful empty* read is proven absence (see the sighted companion).
    /// Treating an unreadable catalog as "no policy" would certify a
    /// VPD-protected table as side-effect-free and hand back silently filtered
    /// rows with exit-success — the one thing AGENTS.md forbids.
    ///
    /// Test-shape rule §A.8-4: an *error* from a privileged catalog query is
    /// not evidence of absence; a *successful empty* read is.
    #[test]
    fn c8_a_catalog_blind_principal_must_not_yield_a_read_only_proof() {
        run_with_cx(|cx| async move {
            let blind = CatalogVisibility::blind();
            let refused = resolved_relations_read_purity(&cx, &blind, &[table_object()], &[]).await;
            assert!(
                refused.is_err(),
                "a catalog-blind principal (probe errors) must fail the read-purity proof \
                 closed, never earn a read-only verdict; got {refused:?}"
            );
        });
    }
}
