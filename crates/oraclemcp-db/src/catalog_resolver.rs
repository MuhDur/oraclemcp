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
    CatalogObjectKind, CatalogResolver, QuoteSemantics, RawName, RawNamePart, Resolution,
    ResolveCtx, ResolvedContainer, ResolvedIdentity, ResolvedObject, ResolvedOverload,
    StatementScope, SynonymHop, SyntacticRole,
};

use crate::{DbError, OracleBind, OracleConnection, OracleRow};

/// Maximum number of syntactic names loaded into one immutable resolver.
pub const MAX_CATALOG_NAMES: usize = 64;

const MAX_CATALOG_CACHE_ENTRIES: usize = 4_096;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_CANDIDATES: usize = 32;
const MAX_SYNONYM_HOPS: usize = 16;
const MAX_ARGUMENT_ROWS: usize = 512;
const MAX_SESSION_ROLES: usize = 256;

const SESSION_CONTEXT_SQL: &str = "SELECT SYS_CONTEXT('USERENV', 'SESSION_USER') AS session_user, \
    SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') AS current_schema, \
    SYS_CONTEXT('USERENV', 'CURRENT_EDITION_NAME') AS edition_name FROM dual";

const SESSION_ROLES_SQL: &str = "SELECT role FROM (SELECT role FROM session_roles ORDER BY role) \
    WHERE ROWNUM <= :1";

const OBJECTS_SQL: &str = "SELECT owner, object_name, object_type, object_id, status, edition_name \
    FROM (SELECT owner, object_name, object_type, object_id, status, edition_name \
          FROM all_objects WHERE owner = :1 AND object_name = :2 ORDER BY object_id) \
    WHERE ROWNUM <= :3";

const SYNONYMS_SQL: &str = "SELECT s.owner, s.synonym_name, s.table_owner, s.table_name, s.db_link, \
    o.object_id, o.status, o.edition_name \
    FROM all_synonyms s LEFT JOIN all_objects o \
      ON o.owner = s.owner AND o.object_name = s.synonym_name AND o.object_type = 'SYNONYM' \
    WHERE s.owner = :1 AND s.synonym_name = :2 AND ROWNUM <= :3";

const STANDALONE_ARGUMENTS_SQL: &str = "SELECT subprogram_id, overload, position, data_level, in_out, defaulted \
    FROM (SELECT subprogram_id, overload, position, data_level, in_out, defaulted, sequence \
          FROM all_arguments WHERE owner = :1 AND package_name IS NULL AND object_name = :2 \
          ORDER BY subprogram_id, sequence) WHERE ROWNUM <= :3";

const MEMBER_ARGUMENTS_SQL: &str = "SELECT subprogram_id, overload, position, data_level, in_out, defaulted \
    FROM (SELECT subprogram_id, overload, position, data_level, in_out, defaulted, sequence \
          FROM all_arguments WHERE owner = :1 AND package_name = :2 AND object_name = :3 \
          ORDER BY subprogram_id, sequence) WHERE ROWNUM <= :4";

const COLUMN_CONFLICT_SQL: &str = "SELECT owner, table_name, column_name, column_id \
    FROM all_tab_columns WHERE column_name = :1 AND ROWNUM <= :2";

const RELATION_COLUMN_SQL: &str = "SELECT column_name, column_id FROM all_tab_columns \
    WHERE owner = :1 AND table_name = :2 AND column_name = :3 AND ROWNUM <= 2";

const SELECT_POLICY_SQL: &str = "SELECT policy_name FROM all_policies \
    WHERE object_owner = :1 AND object_name = :2 \
    AND enable = 'YES' AND sel = 'YES' AND ROWNUM <= 1";

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

const ALL_POLICIES_VISIBILITY_SQL: &str =
    "SELECT COUNT(*) AS VISIBLE_POLICY_ROWS FROM (SELECT 1 FROM all_policies WHERE ROWNUM <= 1)";

const POLICY_CATALOG_PROOF_SQL: &str = "SELECT policy_name FROM all_policies WHERE ROWNUM <= 1";

const VIRTUAL_COLUMN_SQL: &str = "SELECT column_name FROM all_tab_cols \
    WHERE owner = :1 AND table_name = :2 \
    AND virtual_column = 'YES' AND ROWNUM <= 1";

const TARGET_COLUMN_CATALOG_PROOF_SQL: &str = "SELECT column_name FROM all_tab_cols \
    WHERE owner = :1 AND table_name = :2 AND ROWNUM <= 1";

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
/// plain fetch under the currently visible catalog.
///
/// The lean server deliberately proves only ordinary tables with no enabled
/// SELECT VPD policy and no virtual columns. Views and every unknown object
/// kind remain `Unknown`: their defining query can hide function invocation and
/// cannot be cleared by object-type syntax alone.
pub async fn resolved_relations_read_purity(
    cx: &Cx,
    conn: &dyn OracleConnection,
    relations: &[ResolvedObject],
) -> Result<oraclemcp_guard::Purity, DbError> {
    if relations.is_empty() {
        return Ok(oraclemcp_guard::Purity::ProvenReadOnly);
    }
    for relation in relations {
        if relation.db_link.is_some()
            || !matches!(relation.kind, CatalogObjectKind::Table)
            || relation.identity.object_id == 0
        {
            return Ok(oraclemcp_guard::Purity::Unknown);
        }
        let policies = conn
            .query_rows(
                cx,
                SELECT_POLICY_SQL,
                &[
                    OracleBind::from(relation.owner.as_str()),
                    OracleBind::from(relation.name.as_str()),
                ],
            )
            .await?;
        if !policies.is_empty() {
            return Ok(oraclemcp_guard::Purity::Unknown);
        }
        let virtual_columns = conn
            .query_rows(
                cx,
                VIRTUAL_COLUMN_SQL,
                &[
                    OracleBind::from(relation.owner.as_str()),
                    OracleBind::from(relation.name.as_str()),
                ],
            )
            .await?;
        if !virtual_columns.is_empty() {
            return Ok(oraclemcp_guard::Purity::Unknown);
        }
        // Prove the principal can READ these dictionary views at all. On the
        // PUBLIC `ALL_POLICIES` / `ALL_TAB_COLS` views the determinant is
        // Ok-vs-error, not row count: a genuinely blind principal cannot read
        // them and errors (ORA-00942 / insufficient privilege), and that error
        // propagates via `?` to a fail-closed refusal. A *successful* probe —
        // even one returning zero rows — proves visibility. `ALL_POLICIES`
        // lists every VPD policy on objects the current user can access, so a
        // successful empty read is positive proof there is no VPD policy on any
        // readable relation (0 policies = nothing to prove around). This means
        // the empty `SELECT_POLICY_SQL` / `VIRTUAL_COLUMN_SQL` results above are
        // proven absence, not blindness — the read-purity proof is satisfied.
        prove_policy_catalog_readable(cx, conn).await?;
        prove_target_column_catalog_readable(cx, conn, relation).await?;
    }
    Ok(oraclemcp_guard::Purity::ProvenReadOnly)
}

impl OracleCatalogResolver {
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
    let rows = conn.query_rows(cx, SESSION_CONTEXT_SQL, &[]).await?;
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

    let role_rows = conn
        .query_rows(
            cx,
            SESSION_ROLES_SQL,
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
                let matching = relations
                    .iter()
                    .filter(|relation| {
                        relation.alias.is_none()
                            && relation_matches_owner_name(relation, owner, relation_name)
                    })
                    .collect::<Vec<_>>();
                let relation_qualified = !matching.is_empty();
                (matching, column.as_str(), relation_qualified)
            }
            _ => (Vec::new(), "", false),
        };
        let mut columns = Vec::new();
        for relation in candidate_relations {
            if let Some(column) = self.resolve_relation_column(relation, column, raw).await? {
                columns.push(column);
            }
        }
        match columns.len() {
            1 => return Ok(Resolution::Resolved(Box::new(columns.remove(0)))),
            2.. => {
                return Ok(Resolution::Ambiguous {
                    candidates: columns.into_iter().map(|column| column.identity).collect(),
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
        let rows = self
            .conn
            .query_rows(
                self.cx,
                RELATION_COLUMN_SQL,
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
        let rows = self
            .conn
            .query_rows(
                self.cx,
                OBJECTS_SQL,
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
        let rows = self
            .conn
            .query_rows(
                self.cx,
                SYNONYMS_SQL,
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
        let (sql, binds) = if let Some(package) = package {
            (
                MEMBER_ARGUMENTS_SQL,
                vec![
                    OracleBind::from(owner),
                    OracleBind::from(package),
                    OracleBind::from(name),
                    OracleBind::from((MAX_ARGUMENT_ROWS + 1) as i64),
                ],
            )
        } else {
            (
                STANDALONE_ARGUMENTS_SQL,
                vec![
                    OracleBind::from(owner),
                    OracleBind::from(name),
                    OracleBind::from((MAX_ARGUMENT_ROWS + 1) as i64),
                ],
            )
        };
        let rows = self.conn.query_rows(self.cx, sql, &binds).await?;
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
        let rows = self
            .conn
            .query_rows(
                self.cx,
                COLUMN_CONFLICT_SQL,
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
        })
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
    conn.query_rows(cx, POLICY_CATALOG_PROOF_SQL, &[]).await?;
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
    conn.query_rows(
        cx,
        TARGET_COLUMN_CATALOG_PROOF_SQL,
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
    match conn.query_rows(cx, ALL_POLICIES_VISIBILITY_SQL, &[]).await {
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
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

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
        responses: Mutex<VecDeque<Vec<OracleRow>>>,
        queries: Mutex<Vec<(String, Vec<OracleBind>)>>,
    }

    impl ScriptedRows {
        fn new(responses: impl IntoIterator<Item = Vec<OracleRow>>) -> Self {
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
                .ok_or_else(|| DbError::Query("unexpected dictionary query".to_owned()))
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
                resolved_relations_read_purity(&cx, &clean, &[table_object()])
                    .await
                    .expect("clean table proof"),
                oraclemcp_guard::Purity::ProvenReadOnly
            );
            {
                let queries = clean.queries.lock().expect("queries lock");
                assert_eq!(queries.len(), 4);
                assert_eq!(queries[0].0, SELECT_POLICY_SQL);
                assert_eq!(queries[1].0, VIRTUAL_COLUMN_SQL);
                assert_eq!(queries[2].0, POLICY_CATALOG_PROOF_SQL);
                assert_eq!(queries[3].0, TARGET_COLUMN_CATALOG_PROOF_SQL);
            }

            let policy = ScriptedRows::new([vec![row(&[("POLICY_NAME", Some("P"))])]]);
            assert_eq!(
                resolved_relations_read_purity(&cx, &policy, &[table_object()])
                    .await
                    .expect("policy evidence"),
                oraclemcp_guard::Purity::Unknown
            );

            let virtual_column =
                ScriptedRows::new([Vec::new(), vec![row(&[("COLUMN_NAME", Some("TOTAL"))])]]);
            assert_eq!(
                resolved_relations_read_purity(&cx, &virtual_column, &[table_object()])
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
                    resolved_relations_read_purity(&cx, &no_io, std::slice::from_ref(&object))
                        .await
                        .expect("unsupported relation fails closed"),
                    oraclemcp_guard::Purity::Unknown
                );
                assert!(no_io.queries.lock().expect("queries lock").is_empty());
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
            },
            ArgumentFact {
                subprogram_id: 2,
                overload: Some("2".to_owned()),
                position: 0,
                data_level: 0,
                in_out: "OUT".to_owned(),
                defaulted: false,
            },
            ArgumentFact {
                subprogram_id: 2,
                overload: Some("2".to_owned()),
                position: 1,
                data_level: 0,
                in_out: "IN".to_owned(),
                defaulted: false,
            },
            ArgumentFact {
                subprogram_id: 3,
                overload: Some("3".to_owned()),
                position: 0,
                data_level: 0,
                in_out: "OUT".to_owned(),
                defaulted: false,
            },
            ArgumentFact {
                subprogram_id: 3,
                overload: Some("3".to_owned()),
                position: 1,
                data_level: 0,
                in_out: "IN".to_owned(),
                defaulted: true,
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
                resolved_relations_read_purity(&cx, &sighted, &[table_object()])
                    .await
                    .expect("clean table proof"),
                oraclemcp_guard::Purity::ProvenReadOnly,
                "a readable dictionary plus a clean table is a real read-only proof"
            );
            // Both gates are reached, so the red case below is about both of
            // them and not merely the first one short-circuiting.
            let asked = sighted.queries.lock().expect("queries lock");
            assert!(
                asked.iter().any(|sql| sql == SELECT_POLICY_SQL),
                "the SELECT VPD policy probe must run: {asked:?}"
            );
            assert!(
                asked.iter().any(|sql| sql == VIRTUAL_COLUMN_SQL),
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
            let refused = resolved_relations_read_purity(&cx, &blind, &[table_object()]).await;
            assert!(
                refused.is_err(),
                "a catalog-blind principal (probe errors) must fail the read-purity proof \
                 closed, never earn a read-only verdict; got {refused:?}"
            );
        });
    }
}
