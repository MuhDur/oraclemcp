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
    prove_hard_parse_callbacks(cx, conn, sql, relations, false).await
}

// Compile callers obtain policy evidence through the strict mutation metadata
// port below. EXPLAIN retains its existing observation policy unchanged.
async fn prove_hard_parse_callbacks(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    relations: &[ResolvedObject],
    strict_compile_policies: bool,
) -> HardParseEffectClosureV1 {
    let observed_calls = if strict_compile_policies {
        oraclemcp_guard::classifier::hard_parse_sql_routine_calls(sql)
    } else {
        hard_parse_user_calls(sql)
    };
    let calls = match observed_calls {
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
            if strict_compile_policies
                && (row.cell("STATSTYPE_SCHEMA").is_none() || row.cell("STATSTYPE_NAME").is_none())
            {
                return unavailable("callback_unprovable");
            }
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
            if strict_compile_policies
                && (index.text("INDEX_TYPE").is_none()
                    || index.text("INDEX_NAME").is_none()
                    || index
                        .text("INDEX_TYPE")
                        .is_some_and(|kind| kind.to_ascii_uppercase().contains("FUNCTION-BASED")))
            {
                return unavailable("callback_unprovable");
            }
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

        if strict_compile_policies {
            continue;
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
                    // ALL_OBJECTS and ALL_SYNONYMS are privilege-filtered.
                    // Their silence cannot prove an optional OLS/RAS view is
                    // absent, so every denied policy probe remains unknown.
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

use oraclemcp_guard::mutation_closure::{
    MutationDatabaseIdentity, MutationTarget, MutationUnavailableReason as CompileUnknown,
};
use oraclemcp_guard::{CatalogResolver, OperatingLevel, Resolution, StatementScope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

use crate::mutation_closure::{
    MutationEffectOracle, MutationRoutineUse, UnknownMutationEffects, flag as mutation_flag,
    optional as mutation_optional, read_mutation_routine_source, required as mutation_required,
};
use crate::{
    OracleCatalogResolver, RelationSecurityState, observe_relation_security,
    read_closure_database_identity,
};

/// Callback class, never policy source text, identifying a compile refusal.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompileParseCallbackClass {
    /// The candidate source could not be projected completely.
    Source,
    /// An embedded SQL shape is unsupported.
    StaticSql,
    /// A referenced object could not be resolved exactly.
    Resolution,
    /// The authenticated database context or catalog is unproven.
    CatalogVisibility,
    /// An optimizer, index or datatype callback is unproven.
    Optimizer,
    /// A SQL routine callback is unproven.
    SqlRoutine,
    /// A VPD callback is effectful or unproven.
    VpdPolicy,
    /// An OLS, RAS or redaction policy is unproven.
    SecurityPolicy,
}

/// One bounded observation that cannot authorize a candidate compile.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CompileParseUnproven {
    /// One-based static SQL position; zero identifies the source/context itself.
    pub statement_ordinal: u32,
    /// The callback family whose proof failed.
    pub callback_class: CompileParseCallbackClass,
    /// The shared typed reason for uncertainty.
    pub reason: CompileUnknown,
}

/// Source-free effect evidence for an actual policy callback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompileParseCallbackFact {
    /// Dictionary-exact callback owner.
    pub owner: String,
    /// Dictionary-exact callback object name.
    pub name: String,
    /// SHA-256 of the complete source bytes.
    pub source_sha256: String,
    /// Fingerprint from the existing routine effect oracle.
    pub routine_closure_fingerprint: String,
    /// The complete effects reported by that oracle.
    pub effects: oraclemcp_guard::RoutineEffectsV1,
}

/// Exact tables and policy callbacks in one offline-extracted SQL statement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompileParseStatementClosure {
    /// One-based position in the grammar projection.
    pub ordinal: u32,
    /// SHA-256 of the embedded SQL bytes.
    pub sql_sha256: [u8; 32],
    /// Resolved local table identities.
    pub objects: Vec<MutationTarget>,
    /// Observed callback source and effect commitments.
    pub callbacks: Vec<CompileParseCallbackFact>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum CompileParseContract {
    CompileParseEffectClosureV1,
}

/// A source-bound compile proof. Consumers must recollect and compare its
/// digest on the authenticated target connection immediately before DDL.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompileParseEffectClosureV1 {
    contract: CompileParseContract,
    /// SHA-256 of the complete source bytes.
    pub source_sha256: [u8; 32],
    /// Authenticated database, container and edition, when known.
    pub database: Option<MutationDatabaseIdentity>,
    /// Dictionary-exact schema used to resolve unqualified names.
    pub resolution_schema: String,
    /// Bounded per-statement catalog and effect proofs.
    pub statements: Vec<CompileParseStatementClosure>,
    /// Every collected uncertainty that prevents admission.
    pub unavailable: BTreeSet<CompileParseUnproven>,
    /// Canonical commitments to the actual bounded catalog answers, including
    /// source, compiler settings, identity and observed absence.
    pub catalog_commitments: BTreeSet<[u8; 32]>,
}

impl CompileParseEffectClosureV1 {
    fn new(source: &str, schema: &str) -> Self {
        Self {
            contract: CompileParseContract::CompileParseEffectClosureV1,
            source_sha256: Sha256::digest(source.as_bytes()).into(),
            database: None,
            resolution_schema: schema.to_owned(),
            statements: Vec::new(),
            unavailable: BTreeSet::new(),
            catalog_commitments: BTreeSet::new(),
        }
    }
    fn unknown(&mut self, ordinal: u32, class: CompileParseCallbackClass, reason: CompileUnknown) {
        self.unavailable.insert(CompileParseUnproven {
            statement_ordinal: ordinal,
            callback_class: class,
            reason,
        });
    }
    /// All source and metadata observations were complete. This alone does not
    /// admit an effectful callback; use `admit` before candidate DDL.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.database.is_some() && !self.resolution_schema.is_empty() && self.unavailable.is_empty()
    }
    /// A parse callback may read; every stronger, unknown or unsupported effect
    /// refuses through the shared effect admission rule.
    pub fn admit(&self) -> Result<(), CompileParseUnproven> {
        if let Some(reason) = self.unavailable.first() {
            return Err(reason.clone());
        }
        if !self.is_complete() {
            return Err(CompileParseUnproven {
                statement_ordinal: 0,
                callback_class: CompileParseCallbackClass::CatalogVisibility,
                reason: CompileUnknown::CatalogIncomplete,
            });
        }
        for statement in &self.statements {
            for callback in &statement.callbacks {
                if oraclemcp_guard::admit(
                    &callback.effects,
                    oraclemcp_guard::AdmissionContext::CustomToolCall,
                ) != Ok(OperatingLevel::ReadOnly)
                {
                    return Err(CompileParseUnproven {
                        statement_ordinal: statement.ordinal,
                        callback_class: CompileParseCallbackClass::VpdPolicy,
                        reason: CompileUnknown::EffectProofUnavailable,
                    });
                }
            }
        }
        Ok(())
    }
    /// Canonical source, identity, metadata and effect binding for a preview.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"omcp/compile-parse-effect-closure/v1\0");
        hash.update(serde_json::to_vec(self).expect("typed compile evidence serializes"));
        hash.finalize().into()
    }
}

/// The served grammar projection and the existing mutation effect-proof port.
/// No runtime heuristic or text-scanning fallback may supply an empty result.
pub trait CompileParseEffectOracle: MutationEffectOracle {
    /// Project complete static SQL through the canonical grammar frontend.
    fn static_sql(&self, source: &str) -> Result<Vec<String>, CompileUnknown>;
}

impl CompileParseEffectOracle for UnknownMutationEffects {
    /// Project complete static SQL through the canonical grammar frontend.
    fn static_sql(&self, _source: &str) -> Result<Vec<String>, CompileUnknown> {
        Err(CompileUnknown::EffectProofUnavailable)
    }
}
#[derive(Default)]
struct CompileTrace {
    commitments: BTreeSet<[u8; 32]>,
    queries: usize,
    rows: usize,
    bytes: usize,
}

// Observe real answers without replacing any query or synthesizing rows. The
// same connection and closed query runner feed both hard-parse consumers.
struct CompileCatalog<'a> {
    inner: &'a dyn OracleConnection,
    trace: Mutex<CompileTrace>,
}

impl CompileCatalog<'_> {
    fn reserve_query(&self) -> Result<(), DbError> {
        let mut trace = self
            .trace
            .lock()
            .map_err(|_| DbError::Internal("compile catalog trace unavailable".into()))?;
        trace.queries += 1;
        if trace.queries > 512 {
            return Err(DbError::Internal(
                "compile catalog query cap exhausted".into(),
            ));
        }
        Ok(())
    }
    fn record_rows(
        &self,
        sql: &str,
        binds: &[OracleBind],
        rows: Vec<OracleRow>,
    ) -> Result<Vec<OracleRow>, DbError> {
        if rows.iter().flat_map(|row| &row.columns).any(|(_, cell)| {
            cell.bytes.is_some()
                || cell.structured.is_some()
                || cell.structured_contract_version.is_some()
                || cell.nested_result.is_some()
                || cell.source_length.is_some_and(|length| {
                    length > cell.value.as_deref().unwrap_or("").chars().count()
                })
        }) {
            return Err(DbError::Internal(
                "compile catalog projection incomplete".into(),
            ));
        }
        let mut canonical = rows
            .iter()
            .map(|row| serde_json::to_vec(row).expect("catalog row serializes"))
            .collect::<Vec<_>>();
        canonical.sort();
        let bytes = canonical.iter().map(Vec::len).sum::<usize>();
        let mut trace = self
            .trace
            .lock()
            .map_err(|_| DbError::Internal("compile catalog trace unavailable".into()))?;
        trace.rows = trace.rows.saturating_add(rows.len());
        trace.bytes = trace.bytes.saturating_add(bytes);
        if trace.rows > 65_536 || trace.bytes > 16 * 1024 * 1024 {
            return Err(DbError::Internal(
                "compile catalog evidence cap exhausted".into(),
            ));
        }
        trace.commitments.insert(
            Sha256::digest(
                serde_json::to_vec(&(sql, binds, canonical))
                    .expect("catalog commitment serializes"),
            )
            .into(),
        );
        Ok(rows)
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for CompileCatalog<'_> {
    fn backend(&self) -> crate::OracleBackend {
        self.inner.backend()
    }
    async fn close(&self, _: &Cx) -> Result<(), DbError> {
        Err(DbError::Internal(
            "compile proof cannot close the execution lane".into(),
        ))
    }
    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.ping(cx).await
    }
    async fn describe(&self, cx: &Cx) -> Result<crate::OracleConnectionInfo, DbError> {
        self.inner.describe(cx).await
    }
    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        self.reserve_query()?;
        let rows = self.inner.query_rows(cx, sql, binds).await?;
        self.record_rows(sql, binds, rows)
    }
    async fn query_rows_with_provenance(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
        provenance: crate::ReadQueryProvenance,
        options: Option<&crate::SerializeOptions>,
    ) -> Result<Vec<OracleRow>, DbError> {
        self.reserve_query()?;
        let rows = self
            .inner
            .query_rows_with_provenance(cx, sql, binds, provenance, options)
            .await?;
        self.record_rows(sql, binds, rows)
    }
    async fn execute(&self, _: &Cx, _: &str, _: &[OracleBind]) -> Result<u64, DbError> {
        Err(DbError::Internal(
            "compile proof cannot execute candidate SQL".into(),
        ))
    }
    async fn commit(&self, _: &Cx) -> Result<(), DbError> {
        Err(DbError::Internal("compile proof cannot commit".into()))
    }
    async fn rollback(&self, _: &Cx) -> Result<(), DbError> {
        Err(DbError::Internal("compile proof cannot rollback".into()))
    }
}

/// Collect a fresh compile proof in a caller-specified schema and authenticated
/// edition/container. Unknown source or any unreadable catalog family refuses.
pub async fn collect_compile_parse_effect_closure(
    cx: &Cx,
    conn: &dyn OracleConnection,
    source: &str,
    resolution_schema: &str,
    expected_database: Option<&MutationDatabaseIdentity>,
    effects: &dyn CompileParseEffectOracle,
) -> CompileParseEffectClosureV1 {
    use CompileParseCallbackClass as Class;
    let mut closure = CompileParseEffectClosureV1::new(source, resolution_schema);
    let sql = match effects.static_sql(source) {
        Ok(sql) if sql.len() <= 256 => sql,
        _ => {
            closure.unknown(0, Class::Source, CompileUnknown::SourceUnavailable);
            return closure;
        }
    };
    if resolution_schema.is_empty() || resolution_schema.len() > 128 {
        closure.unknown(0, Class::Resolution, CompileUnknown::InvalidInput);
        return closure;
    }
    let catalog = CompileCatalog {
        inner: conn,
        trace: Mutex::new(CompileTrace::default()),
    };
    match read_closure_database_identity(cx, &catalog).await {
        Ok(identity) => {
            let database = MutationDatabaseIdentity {
                dbid: identity.dbid,
                container: identity.container,
                edition: identity.edition,
            };
            if expected_database.is_some_and(|expected| expected != &database) {
                closure.unknown(
                    0,
                    Class::CatalogVisibility,
                    CompileUnknown::IdentityMismatch,
                );
                return closure;
            }
            closure.database = Some(database);
        }
        _ => {
            closure.unknown(
                0,
                Class::CatalogVisibility,
                CompileUnknown::IdentityMismatch,
            );
            return closure;
        }
    }
    for (index, sql) in sql.iter().enumerate() {
        let ordinal = index as u32 + 1;
        let mut statement = CompileParseStatementClosure {
            ordinal,
            sql_sha256: Sha256::digest(sql.as_bytes()).into(),
            objects: Vec::new(),
            callbacks: Vec::new(),
        };
        match compile_statement(
            cx,
            &catalog,
            sql,
            resolution_schema,
            closure.database.as_ref().expect("identity established"),
            effects,
            &mut statement,
        )
        .await
        {
            Ok(()) => (),
            Err((class, reason)) => closure.unknown(ordinal, class, reason),
        }
        closure.statements.push(statement);
        if !closure.unavailable.is_empty() {
            break;
        }
    }
    match catalog.trace.into_inner() {
        Ok(trace) => closure.catalog_commitments = trace.commitments,
        Err(_) => closure.unknown(
            0,
            Class::CatalogVisibility,
            CompileUnknown::CatalogIncomplete,
        ),
    }
    closure
}

async fn compile_statement(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    schema: &str,
    database: &MutationDatabaseIdentity,
    effects: &dyn CompileParseEffectOracle,
    statement: &mut CompileParseStatementClosure,
) -> Result<(), (CompileParseCallbackClass, CompileUnknown)> {
    use CompileParseCallbackClass as Class;
    let names = oraclemcp_guard::classifier::compile_static_sql_relations(sql)
        .map_err(|_| (Class::StaticSql, CompileUnknown::UnsupportedMechanism))?;
    if !oraclemcp_guard::classifier::hard_parse_sql_routine_calls(sql)
        .map_err(|_| (Class::StaticSql, CompileUnknown::UnsupportedMechanism))?
        .is_empty()
    {
        return Err((Class::SqlRoutine, CompileUnknown::UnsupportedMechanism));
    }
    let context = crate::read_catalog_resolve_context(
        cx,
        conn,
        oraclemcp_guard::CatalogGeneration::default(),
        StatementScope::default(),
    )
    .await
    .map_err(|_| (Class::Resolution, CompileUnknown::CatalogUnreadable))?;
    if context.edition.as_deref() != Some(database.edition.as_str()) {
        return Err((Class::Resolution, CompileUnknown::IdentityMismatch));
    }
    let resolver = OracleCatalogResolver::load_for_schema(cx, conn, &names, &context, schema)
        .await
        .map_err(|_| (Class::Resolution, CompileUnknown::CatalogUnreadable))?;
    let mut source_context = context;
    source_context.current_schema = schema.to_owned();
    let mut relations = Vec::new();
    for name in names {
        let Resolution::Resolved(object) = resolver.resolve(&name, &source_context) else {
            return Err((Class::Resolution, CompileUnknown::CatalogIncomplete));
        };
        if object.kind != CatalogObjectKind::Table || object.db_link.is_some() {
            return Err((Class::Resolution, CompileUnknown::UnsupportedMechanism));
        }
        let rows = run_catalog_query(
            cx,
            conn,
            CatalogQueryId::MutationTarget,
            &[
                object.owner.as_str().into(),
                object.name.as_str().into(),
                2_i64.into(),
            ],
        )
        .await
        .map_err(|_| (Class::Resolution, CompileUnknown::CatalogUnreadable))?;
        let [row] = rows.as_slice() else {
            return Err((Class::Resolution, CompileUnknown::CatalogIncomplete));
        };
        if row.text("STATUS") != Some("VALID")
            || row
                .parse_i64("OBJECT_ID")
                .and_then(|id| u64::try_from(id).ok())
                != Some(object.identity.object_id)
        {
            return Err((Class::Resolution, CompileUnknown::IdentityMismatch));
        }
        let time = row
            .text("LAST_DDL_TIME")
            .filter(|text| !text.is_empty())
            .ok_or((Class::Resolution, CompileUnknown::CatalogIncomplete))?;
        statement.objects.push(MutationTarget {
            owner: object.owner.clone(),
            name: object.name.clone(),
            object_id: object.identity.object_id,
            object_edition: object.identity.edition.clone(),
            last_ddl_time: time.to_owned(),
        });
        relations.push(*object);
    }
    if !prove_hard_parse_callbacks(cx, conn, sql, &relations, true)
        .await
        .is_proven()
    {
        return Err((Class::Optimizer, CompileUnknown::EffectProofUnavailable));
    }
    let security = observe_relation_security(cx, conn, &relations)
        .await
        .map_err(|_| (Class::SecurityPolicy, CompileUnknown::CatalogUnreadable))?;
    if security.len() != relations.len()
        || security.iter().any(|fact| {
            fact.key.dbid.as_deref() != Some(database.dbid.as_str())
                || fact.key.container.as_deref() != Some(database.container.as_str())
                || fact.key.edition.as_deref() != Some(database.edition.as_str())
                || !matches!(
                    fact.ols,
                    RelationSecurityState::Absent | RelationSecurityState::NotInstalled
                )
                || !matches!(
                    fact.ras,
                    RelationSecurityState::Absent | RelationSecurityState::NotInstalled
                )
                || !matches!(
                    fact.redaction,
                    RelationSecurityState::Absent | RelationSecurityState::NotInstalled
                )
        })
    {
        return Err((Class::SecurityPolicy, CompileUnknown::CatalogIncomplete));
    }
    for relation in &relations {
        let mut policies = run_catalog_query(
            cx,
            conn,
            CatalogQueryId::MutationVpdPolicies,
            &[
                relation.owner.as_str().into(),
                relation.name.as_str().into(),
                257_i64.into(),
            ],
        )
        .await
        .map_err(|_| (Class::VpdPolicy, CompileUnknown::CatalogUnreadable))?;
        if policies.len() > 256 {
            return Err((Class::VpdPolicy, CompileUnknown::RowCapExhausted));
        }
        policies
            .sort_by_cached_key(|row| serde_json::to_vec(row).expect("policy metadata serializes"));
        for policy in policies {
            if [
                "OBJECT_OWNER",
                "OBJECT_NAME",
                "POLICY_GROUP",
                "POLICY_NAME",
                "PF_OWNER",
                "PF_PACKAGE",
                "PF_FUNCTION",
                "SEL",
                "INS",
                "UPD",
                "DEL",
                "IDX",
                "CHK_OPTION",
                "ENABLE",
                "POLICY_TYPE",
            ]
            .iter()
            .any(|column| policy.cell(column).is_none())
            {
                return Err((Class::VpdPolicy, CompileUnknown::CatalogIncomplete));
            }
            let invalid = |reason| (Class::VpdPolicy, reason);
            if mutation_required(&policy, "OBJECT_OWNER").map_err(invalid)? != relation.owner
                || mutation_required(&policy, "OBJECT_NAME").map_err(invalid)? != relation.name
            {
                return Err((Class::VpdPolicy, CompileUnknown::IdentityMismatch));
            }
            if !mutation_flag(&policy, "ENABLE").map_err(invalid)? {
                continue;
            }
            for column in ["SEL", "INS", "UPD", "DEL", "IDX", "CHK_OPTION"] {
                mutation_flag(&policy, column).map_err(invalid)?;
            }
            mutation_optional(&policy, "POLICY_GROUP").map_err(invalid)?;
            mutation_required(&policy, "POLICY_TYPE").map_err(invalid)?;
            mutation_required(&policy, "POLICY_NAME").map_err(invalid)?;
            if statement.callbacks.len() >= 32 {
                return Err((Class::VpdPolicy, CompileUnknown::ClosureCapExhausted));
            }
            let owner = mutation_required(&policy, "PF_OWNER").map_err(invalid)?;
            let function = mutation_required(&policy, "PF_FUNCTION").map_err(invalid)?;
            let package_name = mutation_optional(&policy, "PF_PACKAGE").map_err(invalid)?;
            let package = package_name.as_deref();
            let mut source = read_mutation_routine_source(
                cx,
                conn,
                owner,
                package.unwrap_or(function),
                if package.is_some() {
                    "PACKAGE BODY"
                } else {
                    "FUNCTION"
                },
                package.map(|_| function),
            )
            .await
            .map_err(|reason| (Class::VpdPolicy, reason))?;
            source.use_context = MutationRoutineUse::VpdPolicy;
            let proof = effects
                .prove_source(cx, conn, &source)
                .await
                .map_err(|reason| (Class::VpdPolicy, reason))?;
            if proof.use_context != source.use_context
                || proof.source_sha256 != source.source_sha256
                || proof.closure_fingerprint.len() != 64
                || !proof
                    .closure_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || (!proof.mutations.is_empty()
                    && proof
                        .effects
                        .iter()
                        .all(|effect| effect == oraclemcp_guard::RoutineEffect::ReadDb))
            {
                return Err((Class::VpdPolicy, CompileUnknown::EffectSourceMismatch));
            }
            statement.callbacks.push(CompileParseCallbackFact {
                owner: source.owner,
                name: source.name,
                source_sha256: source.source_sha256,
                routine_closure_fingerprint: proof.closure_fingerprint,
                effects: proof.effects,
            });
        }
    }
    statement
        .objects
        .sort_by(|a, b| (&a.owner, &a.name, a.object_id).cmp(&(&b.owner, &b.name, b.object_id)));
    statement
        .callbacks
        .sort_by_cached_key(|fact| serde_json::to_vec(fact).expect("callback proof serializes"));
    Ok(())
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
        identity_readable: bool,
        association: Option<OracleRow>,
        association_denied: bool,
        association_denied_first: bool,
        association_calls: Mutex<usize>,
        domain_index: bool,
        user_defined_column_type: bool,
        policy_sql_fragment: Option<&'static str>,
        optional_policy_catalog_denied: bool,
        optional_policy_catalog_names: Vec<&'static str>,
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
            if sql == CatalogQueryId::ClosureIdentity.spec().sql && self.identity_readable {
                return Ok(vec![row(&[
                    ("DBID", "1"),
                    ("CONTAINER_NAME", "3"),
                    ("EDITION_NAME", "ORA$BASE"),
                ])]);
            }
            if sql.contains("FROM SYS.all_associations") {
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
            if sql.contains("FROM SYS.all_indexes") && self.domain_index {
                return Ok(vec![row(&[("INDEX_TYPE", "DOMAIN")])]);
            }
            if self.optional_policy_catalog_denied
                && [
                    "FROM LBACSYS.all_sa_table_policies",
                    "FROM LBACSYS.all_sa_schema_policies",
                    "FROM SYS.all_xs_applied_policies",
                ]
                .iter()
                .any(|view| sql.contains(view))
            {
                return Err(DbError::ServerQuery(
                    "ORA-00942: table or view does not exist".into(),
                ));
            }
            if sql.contains("FROM SYS.all_objects") && sql.contains("ALL_SA_TABLE_POLICIES") {
                return Ok(self
                    .optional_policy_catalog_names
                    .iter()
                    .map(|name| row(&[("OBJECT_NAME", name)]))
                    .collect());
            }
            if sql.contains("FROM SYS.all_tab_columns") && self.user_defined_column_type {
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

    struct Projection(Result<Vec<String>, CompileUnknown>);
    #[async_trait::async_trait(?Send)]
    impl MutationEffectOracle for Projection {
        async fn prove_source(
            &self,
            _: &Cx,
            _: &dyn OracleConnection,
            _: &crate::mutation_closure::MutationRoutineSource,
        ) -> Result<crate::mutation_closure::MutationRoutineProof, CompileUnknown> {
            Err(CompileUnknown::EffectProofUnavailable)
        }
    }
    impl CompileParseEffectOracle for Projection {
        fn static_sql(&self, _: &str) -> Result<Vec<String>, CompileUnknown> {
            self.0.clone()
        }
    }

    #[test]
    fn compile_parse_closure_incomplete_source_refuses_before_catalog_io() {
        let mock = ClosureMock::default();
        let oracle = Projection(Err(CompileUnknown::SourceUnavailable));
        let mock_ref = &mock;
        let oracle_ref = &oracle;
        let proof = run(|cx| async move {
            collect_compile_parse_effect_closure(&cx, mock_ref, "bad", "APP", None, oracle_ref)
                .await
        });
        assert_eq!(
            proof.admit().unwrap_err().callback_class,
            CompileParseCallbackClass::Source
        );
        assert!(mock.queries.lock().unwrap().is_empty());
    }

    #[test]
    fn compile_parse_closure_missing_catalog_visibility_refuses() {
        let mock = ClosureMock::default();
        let oracle = Projection(Ok(vec!["SELECT id FROM app.t".into()]));
        let proof = run(|cx| async move {
            collect_compile_parse_effect_closure(&cx, &mock, "unit", "APP", None, &oracle).await
        });
        assert!(!proof.is_complete());
        assert_eq!(
            proof.admit().unwrap_err().callback_class,
            CompileParseCallbackClass::CatalogVisibility
        );
    }

    fn empty_compile_proof() -> CompileParseEffectClosureV1 {
        let mut proof = CompileParseEffectClosureV1::new("unit", "APP");
        proof.database = Some(MutationDatabaseIdentity {
            dbid: "1".into(),
            container: "3".into(),
            edition: "ORA$BASE".into(),
        });
        proof
    }

    #[test]
    fn compile_parse_closure_no_static_sql_is_computed_empty() {
        let mock = ClosureMock {
            identity_readable: true,
            ..Default::default()
        };
        let oracle = Projection(Ok(Vec::new()));
        let mock_ref = &mock;
        let proof = run(|cx| async move {
            collect_compile_parse_effect_closure(&cx, mock_ref, "unit", "APP", None, &oracle).await
        });
        assert!(proof.is_complete());
        assert!(proof.statements.is_empty());
        assert_eq!(proof.admit(), Ok(()));
        assert_eq!(
            mock.queries.lock().unwrap().len(),
            1,
            "empty source requires only authenticated context"
        );
    }

    #[test]
    fn compile_parse_closure_unsupported_sql_refuses() {
        let mock = ClosureMock {
            identity_readable: true,
            ..Default::default()
        };
        let oracle = Projection(Ok(vec!["SELECT * FROM TABLE(app.callback())".into()]));
        let proof = run(|cx| async move {
            collect_compile_parse_effect_closure(&cx, &mock, "unit", "APP", None, &oracle).await
        });
        let reason = proof.admit().unwrap_err();
        assert_eq!(reason.statement_ordinal, 1);
        assert_eq!(reason.callback_class, CompileParseCallbackClass::StaticSql);
    }

    #[test]
    fn compile_parse_closure_callback_effects_and_digest_are_decisive() {
        use oraclemcp_guard::RoutineEffect;
        let mut proof = empty_compile_proof();
        let empty = proof.digest();
        proof.statements.push(CompileParseStatementClosure {
            ordinal: 1,
            sql_sha256: [1; 32],
            objects: vec![],
            callbacks: vec![CompileParseCallbackFact {
                owner: "APP".into(),
                name: "POLICY".into(),
                source_sha256: "a".repeat(64),
                routine_closure_fingerprint: "b".repeat(64),
                effects: oraclemcp_guard::RoutineEffectsV1::new([RoutineEffect::ReadDb]),
            }],
        });
        assert_eq!(proof.admit(), Ok(()));
        let clean = proof.digest();
        assert_ne!(empty, clean);
        for effect in [
            RoutineEffect::Autonomous,
            RoutineEffect::Dml,
            RoutineEffect::Unknown,
        ] {
            proof.statements[0].callbacks[0].effects =
                oraclemcp_guard::RoutineEffectsV1::new([effect]);
            let refusal = proof.admit().unwrap_err();
            assert_eq!(refusal.statement_ordinal, 1);
            assert_eq!(refusal.callback_class, CompileParseCallbackClass::VpdPolicy);
            assert_ne!(clean, proof.digest());
        }
        proof.statements[0].callbacks[0].effects =
            oraclemcp_guard::RoutineEffectsV1::new([RoutineEffect::ReadDb]);
        proof.catalog_commitments.insert([3; 32]);
        assert_ne!(clean, proof.digest());
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
            "from sys.all_associations",
            "from sys.all_tab_columns",
            "from sys.all_indexes",
            "from sys.all_policies",
            "from lbacsys.all_sa_table_policies",
            "from lbacsys.all_sa_schema_policies",
            "from sys.all_xs_applied_policies",
            "from sys.redaction_policies",
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
            "FROM SYS.all_policies",
            "FROM LBACSYS.all_sa_table_policies",
            "FROM LBACSYS.all_sa_schema_policies",
            "FROM SYS.all_xs_applied_policies",
            "FROM SYS.redaction_policies",
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
    fn optional_policy_view_absent_from_filtered_catalog_is_still_unproven() {
        let mock = ClosureMock {
            optional_policy_catalog_denied: true,
            ..ClosureMock::default()
        };
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
        assert_eq!(
            result,
            HardParseEffectClosureV1::AdmittedWithObservation {
                reason: "no_privilege"
            }
        );
        assert!(
            mock.queries
                .lock()
                .expect("query log")
                .iter()
                .all(|sql| !sql.contains("FROM SYS.all_objects"))
        );
    }

    #[test]
    fn optional_policy_view_present_but_denied_remains_unavailable_evidence() {
        let mock = ClosureMock {
            optional_policy_catalog_denied: true,
            optional_policy_catalog_names: vec!["ALL_XS_APPLIED_POLICIES"],
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
