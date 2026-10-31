//! Tier-1 PL/SQL intelligence — the live-dictionary tools (plan §9.3; bead
//! P1-5): `schema_inspect`, `get_ddl`, compile-error retrieval, source search,
//! `explain_plan`, and safe sampling. These are pure Oracle **dictionary**
//! queries (`ALL_*` / `DBMS_METADATA` / `DBMS_XPLAN`) — engine-free, so they
//! live here. The offline dep-graph cross-check and the `CatalogSnapshot`
//! capture that feed the analysis engine are the engine-side wiring (they use
//! `plsql-catalog` / `plsql-engine` from the consumer side).
//!
//! Values are **bound** wherever Oracle allows it; the few unavoidable
//! identifier positions (schema/table/type in `DBMS_METADATA`, the sampled
//! table) are validated as simple identifiers, never interpolated raw.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::{Mutex, OnceLock};

use asupersync::Cx;

use crate::catalog_query::{CatalogQueryId, run_catalog_query};
use crate::connection::OracleConnection;
use crate::error::DbError;
use crate::query::QueryResponse;
use crate::types::{OracleBind, OracleCell, OracleRow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A simple unquoted Oracle identifier (≤ 30 chars). Rejects injection.
#[must_use]
pub fn is_simple_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '#'))
        && !s.is_empty()
        && s.len() <= 30
}

const PLAN_ID_PREFIX: &str = "OMCP_";
const PLAN_ID_ALPHABET: &[u8; 36] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// A server-generated Oracle `STATEMENT_ID` with strict grammar validation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlanStatementId(String);

impl PlanStatementId {
    /// Generate an unpredictable, SQL-literal-safe plan statement id.
    pub fn generate() -> Result<Self, DbError> {
        let mut value = String::from(PLAN_ID_PREFIX);
        while value.len() < PLAN_ID_PREFIX.len() + 24 {
            let mut random = [0_u8; 32];
            getrandom::getrandom(&mut random).map_err(|error| {
                DbError::Internal(format!("plan statement id RNG failed: {error}"))
            })?;
            for byte in random {
                if byte < 252 {
                    value.push(PLAN_ID_ALPHABET[usize::from(byte % 36)] as char);
                    if value.len() == PLAN_ID_PREFIX.len() + 24 {
                        break;
                    }
                }
            }
        }
        Ok(Self(value))
    }

    /// Validate an id received from a trusted internal boundary.
    pub fn parse(value: impl Into<String>) -> Result<Self, DbError> {
        let value = value.into();
        if value.len() != PLAN_ID_PREFIX.len() + 24
            || !value.starts_with(PLAN_ID_PREFIX)
            || !value[PLAN_ID_PREFIX.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return Err(DbError::InvalidArgument(
                "invalid server plan statement id".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    /// Read the validated identifier without giving callers a SQL rendering path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn sql_literal(&self) -> String {
        format!("'{}'", self.0)
    }
}

/// A verified, fixed Oracle table identity permitted for server-built EXPLAIN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPlanTable {
    owner: String,
    name: String,
    object_id: i64,
    verification_observation: Option<&'static str>,
}

impl VerifiedPlanTable {
    fn new(owner: impl Into<String>, name: impl Into<String>, object_id: i64) -> Self {
        Self {
            owner: owner.into(),
            name: name.into(),
            object_id,
            verification_observation: None,
        }
    }

    fn safe_fallback(configured_table_unavailable: bool) -> Self {
        Self {
            owner: "SYS".to_owned(),
            name: "PLAN_TABLE$".to_owned(),
            // The fixed SYS-qualified identity bypasses caller synonyms. Its
            // object id is unknown when the account cannot read the catalog.
            object_id: 0,
            verification_observation: Some(if configured_table_unavailable {
                "configured_plan_table_unavailable_sys_fallback"
            } else {
                "plan_table_verification_no_privilege_sys_fallback"
            }),
        }
    }

    /// Verified table owner.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Verified table name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Object identity pinned during verification.
    #[must_use]
    pub const fn object_id(&self) -> i64 {
        self.object_id
    }

    /// Audit observation required when a privilege-limited account forced
    /// use of the fixed server-owned fallback.
    #[must_use]
    pub const fn verification_observation(&self) -> Option<&'static str> {
        self.verification_observation
    }

    fn qualified_name(&self) -> String {
        format!("{}.{}", self.owner, self.name)
    }

    fn is_standard_plan_table(&self) -> bool {
        self.owner == "SYS" && self.name == "PLAN_TABLE$"
    }
}

/// Why a server-selected Oracle plan table could not be verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanTableUnavailable {
    reason: &'static str,
}

impl PlanTableUnavailable {
    /// Stable machine-readable reason for this unavailable result.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for PlanTableUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}

impl std::error::Error for PlanTableUnavailable {}

static PLAN_TABLE_OBJECT_IDS: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();

/// Resolve the standard PLAN_TABLE synonym or a configured server-owned GTT.
/// Configured identities are pinned to their first observed `OBJECT_ID` for
/// this server process and Oracle database identity.
pub async fn resolve_plan_table(
    cx: &Cx,
    conn: &dyn OracleConnection,
    configured: Option<&str>,
) -> Result<VerifiedPlanTable, PlanTableUnavailable> {
    let info = match conn.describe(cx).await {
        Ok(info) => info,
        Err(error) => return safe_plan_table_fallback(error, configured.is_some()),
    };
    let current_schema = info
        .current_schema
        .as_deref()
        .ok_or(PlanTableUnavailable {
            reason: "callback_unprovable",
        })?
        .to_ascii_uppercase();

    if let Some(configured) = configured {
        let (owner, name) = parse_plan_table_name(configured)?;
        if info
            .session_user
            .as_deref()
            .is_none_or(|session_user| !session_user.eq_ignore_ascii_case(&owner))
        {
            return Err(PlanTableUnavailable {
                reason: "callback_unprovable",
            });
        }
        let rows = match run_catalog_query(
            cx,
            conn,
            CatalogQueryId::PlanTableConfigured,
            &[
                OracleBind::String(owner.clone()),
                OracleBind::String(name.clone()),
            ],
        )
        .await
        {
            Ok(rows) => rows,
            Err(error) => return safe_plan_table_fallback(error, true),
        };
        if rows.len() != 1
            || rows[0].text("TEMPORARY") != Some("Y")
            || rows[0].text("DURATION") != Some("SYS$SESSION")
        {
            return Err(PlanTableUnavailable {
                reason: "callback_unprovable",
            });
        }
        let object_id = rows[0].parse_i64("OBJECT_ID").ok_or(PlanTableUnavailable {
            reason: "callback_unprovable",
        })?;
        let triggers = match run_catalog_query(
            cx,
            conn,
            CatalogQueryId::PlanTableTriggers,
            &[
                OracleBind::String(owner.clone()),
                OracleBind::String(name.clone()),
            ],
        )
        .await
        {
            Ok(rows) => rows,
            Err(error) => return safe_plan_table_fallback(error, true),
        };
        if !triggers.is_empty() {
            return Err(PlanTableUnavailable {
                reason: "callback_unprovable",
            });
        }
        let database = info.db_unique_name.as_deref().ok_or(PlanTableUnavailable {
            reason: "callback_unprovable",
        })?;
        let key = format!(
            "{database}\0{}\0{owner}.{name}",
            info.service_name.as_deref().unwrap_or("")
        );
        pin_plan_table_identity(key, object_id)?;
        return Ok(VerifiedPlanTable::new(owner, name, object_id));
    }

    let local_objects = match run_catalog_query(
        cx,
        conn,
        CatalogQueryId::PlanTableCurrentObjects,
        &[OracleBind::String(current_schema.clone())],
    )
    .await
    {
        Ok(rows) => rows,
        Err(error) => return safe_plan_table_fallback(error, false),
    };
    let private_synonyms = match run_catalog_query(
        cx,
        conn,
        CatalogQueryId::PlanTablePrivateSynonym,
        &[OracleBind::String(current_schema)],
    )
    .await
    {
        Ok(rows) => rows,
        Err(error) => return safe_plan_table_fallback(error, false),
    };
    if !local_objects.is_empty() || !private_synonyms.is_empty() {
        return Err(PlanTableUnavailable {
            reason: "callback_unprovable",
        });
    }
    let synonym =
        match run_catalog_query(cx, conn, CatalogQueryId::PlanTablePublicSynonym, &[]).await {
            Ok(rows) => rows,
            Err(error) => return safe_plan_table_fallback(error, false),
        };
    if synonym.len() != 1
        || synonym[0].text("TABLE_OWNER") != Some("SYS")
        || synonym[0].text("TABLE_NAME") != Some("PLAN_TABLE$")
        || synonym[0].text("DB_LINK").is_some()
    {
        return Err(PlanTableUnavailable {
            reason: "callback_unprovable",
        });
    }
    let table = match run_catalog_query(cx, conn, CatalogQueryId::PlanTableSysTemporary, &[]).await
    {
        Ok(rows) => rows,
        Err(error) => return safe_plan_table_fallback(error, false),
    };
    if table.len() != 1
        || table[0].text("TEMPORARY") != Some("Y")
        || table[0].text("DURATION") != Some("SYS$SESSION")
    {
        return Err(PlanTableUnavailable {
            reason: "callback_unprovable",
        });
    }
    let object_id = table[0]
        .parse_i64("OBJECT_ID")
        .ok_or(PlanTableUnavailable {
            reason: "callback_unprovable",
        })?;
    Ok(VerifiedPlanTable::new("SYS", "PLAN_TABLE$", object_id))
}

fn safe_plan_table_fallback(
    error: DbError,
    configured_table_unavailable: bool,
) -> Result<VerifiedPlanTable, PlanTableUnavailable> {
    match plan_table_catalog_error(&error).reason() {
        "no_privilege" => Ok(VerifiedPlanTable::safe_fallback(
            configured_table_unavailable,
        )),
        reason => Err(PlanTableUnavailable { reason }),
    }
}

fn parse_plan_table_name(value: &str) -> Result<(String, String), PlanTableUnavailable> {
    let Some((owner, name)) = value.split_once('.') else {
        return Err(PlanTableUnavailable {
            reason: "callback_unprovable",
        });
    };
    if name.contains('.') || !is_simple_identifier(owner) || !is_simple_identifier(name) {
        return Err(PlanTableUnavailable {
            reason: "callback_unprovable",
        });
    }
    Ok((owner.to_ascii_uppercase(), name.to_ascii_uppercase()))
}

fn plan_table_catalog_error(error: &DbError) -> PlanTableUnavailable {
    if error.to_string().contains("ORA-00942") || error.to_string().contains("ORA-01031") {
        PlanTableUnavailable {
            reason: "no_privilege",
        }
    } else {
        PlanTableUnavailable {
            reason: "callback_unprovable",
        }
    }
}

fn pin_plan_table_identity(key: String, object_id: i64) -> Result<(), PlanTableUnavailable> {
    let pins = PLAN_TABLE_OBJECT_IDS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut pins = pins.lock().map_err(|_| PlanTableUnavailable {
        reason: "identity_drift",
    })?;
    match pins.get(&key) {
        Some(expected) if *expected != object_id => Err(PlanTableUnavailable {
            reason: "identity_drift",
        }),
        Some(_) => Ok(()),
        None => {
            pins.insert(key, object_id);
            Ok(())
        }
    }
}

/// The Oracle `VECTOR_DISTANCE` metric keywords supported by the governed
/// semantic-search surface.  These are grammar tokens, never caller SQL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticSearchMetric {
    /// Cosine distance.
    Cosine,
    /// Euclidean distance.
    Euclidean,
    /// Dot-product distance.
    Dot,
}

impl SemanticSearchMetric {
    /// Parse one documented Oracle vector-distance metric.
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Option<Self> {
        match raw
            .map(|metric| metric.trim().to_ascii_uppercase())
            .as_deref()
        {
            None | Some("") | Some("COSINE") => Some(Self::Cosine),
            Some("EUCLIDEAN") => Some(Self::Euclidean),
            Some("DOT") => Some(Self::Dot),
            Some(_) => None,
        }
    }

    /// The exact Oracle grammar token.
    #[must_use]
    pub const fn as_sql(self) -> &'static str {
        match self {
            Self::Cosine => "COSINE",
            Self::Euclidean => "EUCLIDEAN",
            Self::Dot => "DOT",
        }
    }
}

/// Build the bounded SQL shape used by `oracle_semantic_search`.
///
/// The schema, table, and vector-column positions cannot be bound by Oracle,
/// so this helper accepts only simple unquoted identifiers. The query vector
/// and top-k count remain positional binds (`:1`, `:2`); callers never supply
/// a SQL fragment or a metric token outside [`SemanticSearchMetric`]. The
/// dispatcher still runs the resulting statement through the live semantic
/// resolver before execution, which proves the relation and value dependency.
pub fn semantic_search_query(
    owner: &str,
    table: &str,
    column: &str,
    metric: SemanticSearchMetric,
) -> Result<String, DbError> {
    for (label, value) in [("owner", owner), ("table", table), ("column", column)] {
        if !is_simple_identifier(value) {
            return Err(DbError::InvalidArgument(format!(
                "invalid semantic-search {label} identifier: {value:?}"
            )));
        }
    }
    Ok(format!(
        "SELECT t.* FROM {}.{} t ORDER BY VECTOR_DISTANCE(t.{}, :1, {}) FETCH FIRST :2 ROWS ONLY",
        owner.to_ascii_uppercase(),
        table.to_ascii_uppercase(),
        column.to_ascii_uppercase(),
        metric.as_sql(),
    ))
}

/// Build a bounded hybrid vector query with one bind-only equality predicate.
///
/// The filter column is an identifier position and therefore has the same
/// strict simple-identifier proof as the relation and vector column. Its value
/// is always the first bind (`:1`), followed by vector (`:2`). The already
/// range-checked top-k is rendered as server-owned numeric grammar, matching
/// the pagination envelope: callers cannot supply an operator, literal, or SQL
/// fragment that could widen the search's egress surface.
pub fn semantic_search_query_with_filter(
    owner: &str,
    table: &str,
    column: &str,
    filter_column: &str,
    metric: SemanticSearchMetric,
    k: usize,
) -> Result<String, DbError> {
    for (label, value) in [
        ("owner", owner),
        ("table", table),
        ("column", column),
        ("filter column", filter_column),
    ] {
        if !is_simple_identifier(value) {
            return Err(DbError::InvalidArgument(format!(
                "invalid semantic-search {label} identifier: {value:?}"
            )));
        }
    }
    Ok(format!(
        "SELECT t.* FROM {}.{} t WHERE t.{} = :1 ORDER BY VECTOR_DISTANCE(t.{}, :2, {}) FETCH FIRST {} ROWS ONLY",
        owner.to_ascii_uppercase(),
        table.to_ascii_uppercase(),
        filter_column.to_ascii_uppercase(),
        column.to_ascii_uppercase(),
        metric.as_sql(),
        k,
    ))
}

/// Build the bounded text-embedding SQL shape used by
/// `oracle_semantic_search` after the dispatcher has proved the selected model
/// is a local ONNX embedding model on a compatible 23ai database.
///
/// The model name is dictionary-derived, never accepted from the caller. It is
/// still validated as a simple identifier before it reaches the SQL grammar.
/// The source text and top-k count remain positional binds (`:1`, `:2`).
pub fn semantic_search_text_query(
    owner: &str,
    table: &str,
    column: &str,
    model: &str,
    metric: SemanticSearchMetric,
) -> Result<String, DbError> {
    for (label, value) in [
        ("owner", owner),
        ("table", table),
        ("column", column),
        ("model", model),
    ] {
        if !is_simple_identifier(value) {
            return Err(DbError::InvalidArgument(format!(
                "invalid semantic-search {label} identifier: {value:?}"
            )));
        }
    }
    Ok(format!(
        "SELECT t.* FROM {}.{} t ORDER BY VECTOR_DISTANCE(t.{}, VECTOR_EMBEDDING({} USING :1), {}) FETCH FIRST :2 ROWS ONLY",
        owner.to_ascii_uppercase(),
        table.to_ascii_uppercase(),
        column.to_ascii_uppercase(),
        model.to_ascii_uppercase(),
        metric.as_sql(),
    ))
}

/// Build the bounded text-embedding hybrid query after the dispatcher has
/// proven one local ONNX model. The caller contributes only the first bind
/// (`:1`) used by the equality filter, followed by text (`:2`); model,
/// identifiers, metric, top-k, and predicate grammar remain server-owned.
pub fn semantic_search_text_query_with_filter(
    owner: &str,
    table: &str,
    column: &str,
    model: &str,
    filter_column: &str,
    metric: SemanticSearchMetric,
    k: usize,
) -> Result<String, DbError> {
    for (label, value) in [
        ("owner", owner),
        ("table", table),
        ("column", column),
        ("model", model),
        ("filter column", filter_column),
    ] {
        if !is_simple_identifier(value) {
            return Err(DbError::InvalidArgument(format!(
                "invalid semantic-search {label} identifier: {value:?}"
            )));
        }
    }
    Ok(format!(
        "SELECT t.* FROM {}.{} t WHERE t.{} = :1 ORDER BY VECTOR_DISTANCE(t.{}, VECTOR_EMBEDDING({} USING :2), {}) FETCH FIRST {} ROWS ONLY",
        owner.to_ascii_uppercase(),
        table.to_ascii_uppercase(),
        filter_column.to_ascii_uppercase(),
        column.to_ascii_uppercase(),
        model.to_ascii_uppercase(),
        metric.as_sql(),
        k,
    ))
}

/// `ALL_OBJECTS.OBJECT_TYPE` values accepted by the object-list filters.
pub const CATALOG_OBJECT_TYPES: &[&str] = &[
    "TABLE",
    "VIEW",
    "MATERIALIZED VIEW",
    "PACKAGE",
    "PACKAGE BODY",
    "PROCEDURE",
    "FUNCTION",
    "TRIGGER",
    "TYPE",
    "TYPE BODY",
    "SEQUENCE",
    "INDEX",
    "SYNONYM",
];

/// The `DBMS_METADATA` object types we expose (validated allowlist).
pub const DDL_OBJECT_TYPES: &[&str] = &[
    "TABLE",
    "VIEW",
    "PACKAGE",
    "PACKAGE BODY",
    "PACKAGE_BODY",
    "PROCEDURE",
    "FUNCTION",
    "TRIGGER",
    "TYPE",
    "TYPE BODY",
    "TYPE_BODY",
    "SEQUENCE",
    "INDEX",
    "SYNONYM",
];

/// Source object types accepted by `oracle_get_source`.
pub const SOURCE_OBJECT_TYPES: &[&str] = &[
    "PACKAGE",
    "PACKAGE BODY",
    "PACKAGE_BODY",
    "PROCEDURE",
    "FUNCTION",
    "TRIGGER",
    "TYPE",
    "TYPE BODY",
    "TYPE_BODY",
    "VIEW",
];

/// `ALL_SOURCE.TYPE` values accepted by source search. Views are fetched from
/// `ALL_VIEWS.TEXT`, so they are valid for `get_source` but not `search_source`.
pub const SOURCE_SEARCH_OBJECT_TYPES: &[&str] = &[
    "PACKAGE",
    "PACKAGE BODY",
    "PACKAGE_BODY",
    "PROCEDURE",
    "FUNCTION",
    "TRIGGER",
    "TYPE",
    "TYPE BODY",
    "TYPE_BODY",
];

/// Object types accepted by the Oracle compiler path.
pub const COMPILE_OBJECT_TYPES: &[&str] = &[
    "PACKAGE",
    "PACKAGE BODY",
    "PACKAGE_BODY",
    "PROCEDURE",
    "FUNCTION",
    "TRIGGER",
    "TYPE",
    "TYPE BODY",
    "TYPE_BODY",
    "VIEW",
    "TABLE",
];

/// Object types accepted by patch_source, including TABLE's typed refusal.
pub const PATCH_SOURCE_OBJECT_TYPES: &[&str] = &[
    "PACKAGE",
    "PACKAGE BODY",
    "PACKAGE_BODY",
    "PROCEDURE",
    "FUNCTION",
    "TRIGGER",
    "TYPE",
    "TYPE BODY",
    "TYPE_BODY",
    "VIEW",
    "TABLE",
];

/// Return the supported `ALL_OBJECTS.OBJECT_TYPE` filters.
#[must_use]
pub const fn catalog_object_types() -> &'static [&'static str] {
    CATALOG_OBJECT_TYPES
}

/// Return the supported `DBMS_METADATA.GET_DDL` object types.
#[must_use]
pub const fn ddl_object_types() -> &'static [&'static str] {
    DDL_OBJECT_TYPES
}

/// Return the supported `oracle_get_source` object types.
#[must_use]
pub const fn source_object_types() -> &'static [&'static str] {
    SOURCE_OBJECT_TYPES
}

/// Return the supported `oracle_search_source` object types.
#[must_use]
pub const fn source_search_object_types() -> &'static [&'static str] {
    SOURCE_SEARCH_OBJECT_TYPES
}

/// Return the supported `oracle_compile_object` object types.
#[must_use]
pub const fn compile_object_types() -> &'static [&'static str] {
    COMPILE_OBJECT_TYPES
}

/// Return the supported `oracle_patch_source` object types.
#[must_use]
pub const fn patch_source_object_types() -> &'static [&'static str] {
    PATCH_SOURCE_OBJECT_TYPES
}

/// Full source text plus truncation metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceText {
    /// Schema owner.
    pub owner: String,
    /// Object name.
    pub name: String,
    /// Normalized `ALL_SOURCE.TYPE`.
    pub object_type: String,
    /// Concatenated source text.
    pub source: String,
    /// Number of source rows read.
    pub line_count: usize,
    /// Characters in the untruncated source.
    pub char_count: usize,
    /// Whether `source` was truncated to the requested cap.
    pub truncated: bool,
}

/// Server-owned bounds for one `ALL_SOURCE` read.
///
/// Keeping the optional inclusive line range and the character ceiling together
/// makes the bounded-read contract explicit at every caller. The database layer
/// does not accept an unbounded form: `max_chars` remains mandatory and is
/// clamped to at least one character by [`get_source`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceReadOptions {
    /// First inclusive `ALL_SOURCE.LINE`, if the caller requests a range.
    pub from_line: Option<usize>,
    /// Last inclusive `ALL_SOURCE.LINE`, if the caller requests a range.
    pub to_line: Option<usize>,
    /// Maximum returned source characters before explicit truncation.
    pub max_chars: usize,
}

/// DDL text returned by `DBMS_METADATA.GET_DDL`, with the full CLOB length.
///
/// The thin driver path reads a bounded prefix rather than materializing an
/// unbounded CLOB. Callers must inspect [`Self::truncated`] before treating
/// [`Self::text`] as a complete DDL document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DdlText {
    /// Bounded DDL prefix returned from Oracle.
    pub text: String,
    /// Character length of the full Oracle CLOB.
    pub char_count: usize,
    /// Whether `text` is only a prefix of the full DDL CLOB.
    pub truncated: bool,
}

/// Metadata and column/expression details for one index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexDescription {
    /// The `ALL_INDEXES` metadata row for the visible index.
    pub metadata: Option<OracleRow>,
    /// `ALL_IND_COLUMNS` rows in column position order.
    pub columns: Vec<OracleRow>,
    /// `ALL_IND_EXPRESSIONS` rows for function-based index expressions.
    pub expressions: Vec<OracleRow>,
}

/// Metadata and body for one visible trigger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriggerDescription {
    /// The `ALL_TRIGGERS` metadata row for the visible trigger.
    pub metadata: Option<OracleRow>,
}

/// Metadata/definition and column details for one visible view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewDescription {
    /// The `ALL_VIEWS` metadata row for the visible view.
    pub metadata: Option<OracleRow>,
    /// View columns from `ALL_TAB_COLUMNS`.
    pub columns: Vec<OracleRow>,
}

/// Whether `t` is an allowlisted `DBMS_METADATA` object type.
#[must_use]
pub fn is_ddl_object_type(t: &str) -> bool {
    DDL_OBJECT_TYPES.contains(&t)
}

/// Normalize a supported source object type to `ALL_SOURCE.TYPE`.
#[must_use]
pub fn normalize_source_object_type(t: &str) -> Option<&'static str> {
    if t == "PACKAGE_BODY" {
        return Some("PACKAGE BODY");
    }
    if t == "TYPE_BODY" {
        return Some("TYPE BODY");
    }
    SOURCE_OBJECT_TYPES
        .iter()
        .copied()
        .find(|object_type| *object_type == t)
}

/// Normalize an `ALL_SOURCE.TYPE` value used by `oracle_search_source`.
#[must_use]
pub fn normalize_source_search_object_type(t: &str) -> Option<&'static str> {
    if t == "PACKAGE_BODY" {
        return Some("PACKAGE BODY");
    }
    if t == "TYPE_BODY" {
        return Some("TYPE BODY");
    }
    SOURCE_SEARCH_OBJECT_TYPES
        .iter()
        .copied()
        .find(|object_type| *object_type == t)
}

/// The detail level for [`search_objects`] (E4). Higher levels add bounded,
/// read-only dictionary detail per object. `summary` deliberately uses the
/// optimizer's `ALL_TABLES.NUM_ROWS` estimate (NOT `COUNT(*)`) so the tool never
/// triggers a full table scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchDetailLevel {
    /// Identifier + object metadata only (owner, name, type, status). The
    /// cheapest level: one `ALL_OBJECTS` query.
    Names,
    /// `names` plus, for tables, the optimizer row-count estimate
    /// (`ALL_TABLES.NUM_ROWS`), column count, last-analyzed/staleness, and the
    /// table/column comments (`ALL_TAB_COMMENTS`). No `COUNT(*)`.
    Summary,
    /// `summary` plus the column list (name/type/nullable) for tables and views.
    Standard,
    /// `standard` plus the object's indexes (name/uniqueness/columns).
    Full,
}

impl SearchDetailLevel {
    /// Parse a caller-supplied detail level, case-insensitively. `None`/empty
    /// defaults to [`SearchDetailLevel::Standard`].
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Option<Self> {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            None | Some("") | Some("standard") => Some(SearchDetailLevel::Standard),
            Some("names") => Some(SearchDetailLevel::Names),
            Some("summary") => Some(SearchDetailLevel::Summary),
            Some("full") => Some(SearchDetailLevel::Full),
            Some(_) => None,
        }
    }

    /// The wire/string form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SearchDetailLevel::Names => "names",
            SearchDetailLevel::Summary => "summary",
            SearchDetailLevel::Standard => "standard",
            SearchDetailLevel::Full => "full",
        }
    }

    fn at_least_summary(self) -> bool {
        !matches!(self, SearchDetailLevel::Names)
    }

    fn at_least_standard(self) -> bool {
        matches!(self, SearchDetailLevel::Standard | SearchDetailLevel::Full)
    }

    fn is_full(self) -> bool {
        matches!(self, SearchDetailLevel::Full)
    }
}

/// One object returned by [`search_objects`] (E4). The optional fields are
/// populated according to the requested [`SearchDetailLevel`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchObject {
    /// Schema owner (always upper-cased by the dictionary).
    pub owner: String,
    /// Object name, exactly as stored — quoted/case-sensitive identifiers are
    /// preserved verbatim (the dictionary stores the unquoted upper-case name
    /// for ordinary identifiers and the exact case for quoted ones).
    pub object_name: String,
    /// `ALL_OBJECTS.OBJECT_TYPE` (e.g. `TABLE`, `VIEW`, `PACKAGE`).
    pub object_type: String,
    /// `ALL_OBJECTS.STATUS` (`VALID`/`INVALID`).
    pub status: Option<String>,
    /// Summary+ : the optimizer row-count estimate from `ALL_TABLES.NUM_ROWS`.
    /// This is the gathered-statistics estimate, **not** a live `COUNT(*)`, so
    /// it may be stale or `None` (no stats gathered / not a table). See
    /// `row_count_is_estimate` and `stats_stale`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_rows: Option<i64>,
    /// Summary+ : always `true` when `num_rows` is present — the row count is the
    /// optimizer estimate, never an exact live count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count_is_estimate: Option<bool>,
    /// Summary+ : `ALL_TABLES.LAST_ANALYZED`, when stats were last gathered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analyzed: Option<String>,
    /// Summary+ : `true` when the optimizer marks the table's stats stale
    /// (`ALL_TAB_STATISTICS.STALE_STATS = 'YES'`), so `num_rows` should not be
    /// trusted as current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_stale: Option<bool>,
    /// Summary+ : number of columns (`COUNT(*)` over `ALL_TAB_COLUMNS`, a cheap
    /// dictionary count — NOT a data scan).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_count: Option<i64>,
    /// Summary+ : the object comment from `ALL_TAB_COMMENTS`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Standard+ : columns (name/type/nullable/comment) for tables and views.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub columns: Option<Vec<SearchColumn>>,
    /// Full : indexes on the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexes: Option<Vec<SearchIndex>>,
}

/// One column in a [`SearchObject`] (standard+ detail).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchColumn {
    /// Column name.
    pub name: String,
    /// Oracle data type.
    pub data_type: Option<String>,
    /// `Y`/`N` nullable flag.
    pub nullable: Option<String>,
    /// The column comment from `ALL_COL_COMMENTS`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// One index in a [`SearchObject`] (full detail).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchIndex {
    /// Index name.
    pub name: String,
    /// `UNIQUE`/`NONUNIQUE`.
    pub uniqueness: Option<String>,
    /// Indexed columns in position order.
    pub columns: Vec<String>,
}

/// E4 unified object search/inspection. Returns objects matching the
/// owner/type/name filters, enriched per `detail` level:
///
/// - **names**: one `ALL_OBJECTS` query, identifiers + metadata only.
/// - **summary**: + the optimizer `ALL_TABLES.NUM_ROWS` estimate (never
///   `COUNT(*)`), column count, last-analyzed + stale-stats, and comments.
/// - **standard**: + the column list.
/// - **full**: + the indexes.
///
/// Owner/type/name filters are all bound. `owner = None` searches every visible
/// schema; a `name_like` is a SQL `LIKE` pattern. Identifier inputs are bound,
/// never interpolated; the per-object enrichment queries also bind owner/name,
/// so quoted/case-sensitive identifiers (which the dictionary stores verbatim)
/// are matched exactly.
pub async fn search_objects(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    object_type: Option<&str>,
    name_like: Option<&str>,
    detail: SearchDetailLevel,
    max_rows: usize,
) -> Result<Vec<SearchObject>, DbError> {
    // The base listing is the same cheap ALL_OBJECTS query schema_inspect uses
    // (owner/type/name bound, row-capped). Quoted identifiers are stored
    // verbatim in the dictionary, so binding the exact owner/name matches them.
    let base = list_objects(cx, conn, owner, object_type, name_like, max_rows).await?;

    search_objects_from_base(cx, conn, base, detail).await
}

/// E4 object search filtered by a bound set of object types.
pub async fn search_objects_by_types(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    object_types: &[String],
    name_like: Option<&str>,
    detail: SearchDetailLevel,
    max_rows: usize,
) -> Result<Vec<SearchObject>, DbError> {
    let base = list_objects_by_types(cx, conn, owner, object_types, name_like, max_rows).await?;
    search_objects_from_base(cx, conn, base, detail).await
}

async fn search_objects_from_base(
    cx: &Cx,
    conn: &dyn OracleConnection,
    base: Vec<OracleRow>,
    detail: SearchDetailLevel,
) -> Result<Vec<SearchObject>, DbError> {
    let mut results = Vec::with_capacity(base.len());
    for row in &base {
        let owner = row.text("OWNER").unwrap_or_default().to_owned();
        let object_name = row.text("OBJECT_NAME").unwrap_or_default().to_owned();
        let object_type = row.text("OBJECT_TYPE").unwrap_or_default().to_owned();
        let status = row.text("STATUS").map(str::to_owned);

        let mut object = SearchObject {
            owner: owner.clone(),
            object_name: object_name.clone(),
            object_type: object_type.clone(),
            status,
            num_rows: None,
            row_count_is_estimate: None,
            last_analyzed: None,
            stats_stale: None,
            column_count: None,
            comment: None,
            columns: None,
            indexes: None,
        };

        let is_relation = matches!(object_type.as_str(), "TABLE" | "VIEW");

        if detail.at_least_summary() {
            // The object comment (cheap dictionary read for any object type).
            object.comment = object_comment(cx, conn, &owner, &object_name).await?;
            if is_relation {
                // Column count is a dictionary COUNT over ALL_TAB_COLUMNS — a
                // metadata count, never a data scan.
                object.column_count = Some(column_count(cx, conn, &owner, &object_name).await?);
            }
            if object_type == "TABLE" {
                // The row count is the OPTIMIZER estimate from ALL_TABLES.NUM_ROWS
                // (gathered statistics), NOT COUNT(*). It may be NULL (no stats)
                // or stale; we surface both so the estimate is never mistaken for
                // a live count.
                if let Some(stats) = table_stats(cx, conn, &owner, &object_name).await? {
                    object.num_rows = stats.num_rows;
                    object.row_count_is_estimate = stats.num_rows.map(|_| true);
                    object.last_analyzed = stats.last_analyzed;
                }
                object.stats_stale = Some(table_stats_stale(cx, conn, &owner, &object_name).await?);
            }
        }

        if detail.at_least_standard() && is_relation {
            object.columns = Some(search_columns(cx, conn, &owner, &object_name).await?);
        }

        if detail.is_full() && is_relation {
            object.indexes = Some(search_indexes(cx, conn, &owner, &object_name).await?);
        }

        results.push(object);
    }

    Ok(results)
}

/// The optimizer table statistics for one table (E4 summary). Pulls
/// `ALL_TABLES.NUM_ROWS` (the gathered estimate, NOT a live count) and
/// `LAST_ANALYZED`. Returns `None` when the name is not a table in `ALL_TABLES`.
struct TableStats {
    num_rows: Option<i64>,
    last_analyzed: Option<String>,
}

async fn table_stats(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Option<TableStats>, DbError> {
    // NUM_ROWS is the optimizer's gathered-statistics estimate. We deliberately
    // read it from ALL_TABLES instead of running COUNT(*) so a search never
    // triggers a full table scan on a large table.
    let row = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::TableStats,
        &[OracleBind::from(owner), OracleBind::from(table)],
    )
    .await?
    .into_iter()
    .next();
    Ok(row.map(|row| TableStats {
        num_rows: row.parse_i64("NUM_ROWS"),
        last_analyzed: row.text("LAST_ANALYZED").map(str::to_owned),
    }))
}

/// Whether the optimizer marks this table's statistics stale (E4 summary). Reads
/// `ALL_TAB_STATISTICS.STALE_STATS`; absent/unknown is treated as not stale.
async fn table_stats_stale(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<bool, DbError> {
    let row = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::TableStatsStale,
        &[OracleBind::from(owner), OracleBind::from(table)],
    )
    .await?
    .into_iter()
    .next();
    Ok(row
        .and_then(|row| {
            row.text("STALE_STATS")
                .map(|s| s.eq_ignore_ascii_case("YES"))
        })
        .unwrap_or(false))
}

/// Cheap dictionary column count (`COUNT(*)` over `ALL_TAB_COLUMNS`). This is a
/// metadata count over the dictionary, not a scan of the table's data.
async fn column_count(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<i64, DbError> {
    let row = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::TableColumnCount,
        &[OracleBind::from(owner), OracleBind::from(table)],
    )
    .await?
    .into_iter()
    .next();
    Ok(row
        .and_then(|row| row.parse_i64("COLUMN_COUNT"))
        .unwrap_or(0))
}

/// The object comment from `ALL_TAB_COMMENTS` (tables/views), when present.
async fn object_comment(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    object_name: &str,
) -> Result<Option<String>, DbError> {
    let row = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::ObjectComment,
        &[OracleBind::from(owner), OracleBind::from(object_name)],
    )
    .await?
    .into_iter()
    .next();
    Ok(row.and_then(|row| row.text("COMMENTS").map(str::to_owned)))
}

/// Columns with comments for E4 standard+ detail (`ALL_TAB_COLUMNS` left-joined
/// to `ALL_COL_COMMENTS`).
async fn search_columns(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Vec<SearchColumn>, DbError> {
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::SearchColumns,
        &[OracleBind::from(owner), OracleBind::from(table)],
    )
    .await?;
    Ok(rows
        .iter()
        .map(|row| SearchColumn {
            name: row.text("COLUMN_NAME").unwrap_or_default().to_owned(),
            data_type: row.text("DATA_TYPE").map(str::to_owned),
            nullable: row.text("NULLABLE").map(str::to_owned),
            comment: row.text("COMMENTS").map(str::to_owned),
        })
        .collect())
}

/// Indexes on the object for E4 full detail (`ALL_INDEXES` + `ALL_IND_COLUMNS`).
async fn search_indexes(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Vec<SearchIndex>, DbError> {
    let index_rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::SearchIndexes,
        &[OracleBind::from(owner), OracleBind::from(table)],
    )
    .await?;
    let mut indexes = Vec::with_capacity(index_rows.len());
    for row in &index_rows {
        let name = row.text("INDEX_NAME").unwrap_or_default().to_owned();
        let uniqueness = row.text("UNIQUENESS").map(str::to_owned);
        let column_rows = run_catalog_query(
            cx,
            conn,
            CatalogQueryId::SearchIndexColumns,
            &[OracleBind::from(owner), OracleBind::from(name.as_str())],
        )
        .await?;
        let columns = column_rows
            .iter()
            .filter_map(|row| row.text("COLUMN_NAME").map(str::to_owned))
            .collect();
        indexes.push(SearchIndex {
            name,
            uniqueness,
            columns,
        });
    }
    Ok(indexes)
}

/// `schema_inspect`: objects in one schema or all accessible schemas, with
/// optional type/name filters. Owner, type, and name pattern are all bound; a
/// NULL owner means "all accessible schemas".
pub async fn list_objects(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    object_type: Option<&str>,
    name_like: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    let owner_bind = owner.map_or(OracleBind::Null, |o| {
        OracleBind::from(o.to_ascii_uppercase())
    });
    let type_bind = object_type.map_or(OracleBind::Null, |t| {
        OracleBind::from(t.to_ascii_uppercase())
    });
    let name_like_bind = name_like.map_or(OracleBind::Null, |n| {
        OracleBind::from(n.to_ascii_uppercase())
    });
    run_catalog_query(
        cx,
        conn,
        CatalogQueryId::ListObjects,
        &[
            owner_bind,
            type_bind,
            name_like_bind,
            OracleBind::from(max_rows as i64),
        ],
    )
    .await
}

/// `schema_inspect` object listing filtered by a nonempty set of exact
/// `ALL_OBJECTS.OBJECT_TYPE` values. Each requested value is bound separately;
/// the fixed query's unused type slots are bound as SQL NULL.
pub async fn list_objects_by_types(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    object_types: &[String],
    name_like: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    if object_types.is_empty() || object_types.len() > CATALOG_OBJECT_TYPES.len() {
        return Err(DbError::InvalidArgument(format!(
            "object_types must contain between 1 and {} values",
            CATALOG_OBJECT_TYPES.len()
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for object_type in object_types {
        if !CATALOG_OBJECT_TYPES.contains(&object_type.as_str()) {
            return Err(DbError::InvalidArgument(format!(
                "unsupported object_type: {object_type:?}"
            )));
        }
        if !seen.insert(object_type.as_str()) {
            return Err(DbError::InvalidArgument(format!(
                "object_types contains duplicate value {object_type:?}"
            )));
        }
    }
    let mut binds = Vec::with_capacity(CATALOG_OBJECT_TYPES.len() + 3);
    binds.push(owner.map_or(OracleBind::Null, |o| {
        OracleBind::from(o.to_ascii_uppercase())
    }));
    binds.extend(object_types.iter().cloned().map(OracleBind::from));
    binds.resize(CATALOG_OBJECT_TYPES.len() + 1, OracleBind::Null);
    binds.push(name_like.map_or(OracleBind::Null, |n| {
        OracleBind::from(n.to_ascii_uppercase())
    }));
    binds.push(OracleBind::from(max_rows.max(1) as i64));
    run_catalog_query(cx, conn, CatalogQueryId::ListObjectsByTypes, &binds).await
}

/// One deterministic, bounded page from the `schema_inspect` object listing.
///
/// This is deliberately separate from [`list_objects`] so existing focused
/// inspection callers retain their established SQL shape. Compact aliases use
/// the extra sentinel row to say truthfully whether another page exists.
pub async fn list_objects_page(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    object_type: Option<&str>,
    name_like: Option<&str>,
    offset: usize,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    let owner_bind = owner.map_or(OracleBind::Null, |value| {
        OracleBind::from(value.to_ascii_uppercase())
    });
    let type_bind = object_type.map_or(OracleBind::Null, |value| {
        OracleBind::from(value.to_ascii_uppercase())
    });
    let name_like_bind = name_like.map_or(OracleBind::Null, |value| {
        OracleBind::from(value.to_ascii_uppercase())
    });
    let upper_bound = page_upper_bound(offset, max_rows)?;
    run_catalog_query(
        cx,
        conn,
        CatalogQueryId::ListObjectsPage,
        &[
            owner_bind,
            type_bind,
            name_like_bind,
            OracleBind::from(upper_bound),
            OracleBind::from(offset as i64),
        ],
    )
    .await
}

/// Compact `get_schema` projection. Its object-kind predicate is fixed in the
/// server SQL rather than supplied by the caller, so an empty alias call never
/// expands back into every accessible index, synonym, trigger, and generated
/// object. Pagination stays positional-bind-only and deterministic.
pub async fn list_schema_projection_page(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    name_like: Option<&str>,
    offset: usize,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    let owner_bind = owner.map_or(OracleBind::Null, |value| {
        OracleBind::from(value.to_ascii_uppercase())
    });
    let name_like_bind = name_like.map_or(OracleBind::Null, |value| {
        OracleBind::from(value.to_ascii_uppercase())
    });
    let upper_bound = page_upper_bound(offset, max_rows)?;
    run_catalog_query(
        cx,
        conn,
        CatalogQueryId::SchemaProjectionPage,
        &[
            owner_bind,
            name_like_bind,
            OracleBind::from(upper_bound),
            OracleBind::from(offset as i64),
        ],
    )
    .await
}

/// One object in the bounded `oracle_orient` schema map.
///
/// This intentionally carries only the stable identity triplet from
/// `ALL_OBJECTS`; object-specific detail belongs to the focused dictionary
/// tools rather than the shared orient snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrientSchemaObject {
    /// Schema owner as stored in `ALL_OBJECTS`.
    pub owner: String,
    /// Object name as stored in `ALL_OBJECTS`.
    pub object_name: String,
    /// Oracle object kind from `ALL_OBJECTS.OBJECT_TYPE`.
    pub object_type: String,
}

/// One positional child-to-parent column pairing in an [`OrientForeignKey`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrientForeignKeyColumn {
    /// One-based key-column position in both the child and parent constraints.
    pub position: usize,
    /// Child table column at [`Self::position`].
    pub child_column: String,
    /// Parent key column at [`Self::position`].
    pub parent_column: String,
}

/// One directed foreign-key edge in the bounded `oracle_orient` topology.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrientForeignKey {
    /// Foreign-key constraint name, unique together with [`Self::child_owner`].
    pub constraint_name: String,
    /// Schema that owns the referencing table.
    pub child_owner: String,
    /// Referencing table name.
    pub child_table: String,
    /// Schema that owns the referenced key.
    pub parent_owner: String,
    /// Referenced table name.
    pub parent_table: String,
    /// Child-to-parent column pairings in constraint-position order.
    pub columns: Vec<OrientForeignKeyColumn>,
}

/// Read the bounded schema/type map for `oracle_orient` from `ALL_OBJECTS`.
///
/// The optional owner is normalized to upper case and bound positionally; when
/// it is absent, the map covers all objects visible to the session. Results are
/// deterministically ordered and capped with `ROWNUM`, so callers can safely
/// assemble them into a cacheable snapshot without ever interpolating an
/// identifier.
pub async fn orient_schema(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OrientSchemaObject>, DbError> {
    orient_schema_page(cx, conn, owner, 0, max_rows).await
}

/// Read one stable, offset-based schema-map page for `oracle_orient`.
pub async fn orient_schema_page(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    offset: usize,
    max_rows: usize,
) -> Result<Vec<OrientSchemaObject>, DbError> {
    let owner_bind = owner.map_or(OracleBind::Null, |value| {
        OracleBind::from(value.to_ascii_uppercase())
    });
    let upper_bound = page_upper_bound(offset, max_rows)?;
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::OrientSchemaPage,
        &[
            owner_bind,
            OracleBind::from(upper_bound),
            OracleBind::from(offset as i64),
        ],
    )
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| OrientSchemaObject {
            owner: row.text("OWNER").unwrap_or_default().to_owned(),
            object_name: row.text("OBJECT_NAME").unwrap_or_default().to_owned(),
            object_type: row.text("OBJECT_TYPE").unwrap_or_default().to_owned(),
        })
        .collect())
}

fn page_upper_bound(offset: usize, max_rows: usize) -> Result<i64, DbError> {
    let upper_bound = offset.checked_add(max_rows.max(1)).ok_or_else(|| {
        DbError::InvalidArgument("bounded metadata page offset overflowed".to_owned())
    })?;
    i64::try_from(upper_bound).map_err(|_| {
        DbError::InvalidArgument("bounded metadata page exceeds Oracle limit".to_owned())
    })
}

/// Read bounded child-to-parent foreign-key topology for `oracle_orient`.
///
/// This joins the child `R` constraint to its referenced key and then joins
/// both `ALL_CONS_COLUMNS` projections on their one-based positions. The cap
/// is deliberately applied to foreign-key *constraints* before those column
/// joins, preventing a composite key from being returned with only a prefix of
/// its column pairings. The optional owner is a positional, upper-cased bind;
/// `None` covers every foreign key visible to the session.
pub async fn orient_fks(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OrientForeignKey>, DbError> {
    orient_fks_page(cx, conn, owner, 0, max_rows).await
}

/// Read one stable, offset-based foreign-key page for `oracle_orient`.
pub async fn orient_fks_page(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    offset: usize,
    max_rows: usize,
) -> Result<Vec<OrientForeignKey>, DbError> {
    // Keep the outermost statement a SELECT. Besides matching the generated
    // read-path contract, the thin driver recognizes this shape consistently
    // when the dictionary query contains a CTE.
    let owner_bind = owner.map_or(OracleBind::Null, |value| {
        OracleBind::from(value.to_ascii_uppercase())
    });
    let upper_bound = page_upper_bound(offset, max_rows)?;
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::OrientForeignKeysPage,
        &[
            owner_bind,
            OracleBind::from(upper_bound),
            OracleBind::from(offset as i64),
        ],
    )
    .await?;

    let mut foreign_keys: Vec<OrientForeignKey> = Vec::new();
    for row in rows {
        let constraint_name = row.text("CONSTRAINT_NAME").unwrap_or_default().to_owned();
        let child_owner = row.text("CHILD_OWNER").unwrap_or_default().to_owned();
        let child_table = row.text("CHILD_TABLE").unwrap_or_default().to_owned();
        let parent_owner = row.text("PARENT_OWNER").unwrap_or_default().to_owned();
        let parent_table = row.text("PARENT_TABLE").unwrap_or_default().to_owned();
        let column = OrientForeignKeyColumn {
            position: row
                .parse_i64("COLUMN_POSITION")
                .and_then(|position| usize::try_from(position).ok())
                .unwrap_or_default(),
            child_column: row.text("CHILD_COLUMN").unwrap_or_default().to_owned(),
            parent_column: row.text("PARENT_COLUMN").unwrap_or_default().to_owned(),
        };

        if let Some(existing) = foreign_keys.last_mut()
            && existing.constraint_name == constraint_name
            && existing.child_owner == child_owner
        {
            existing.columns.push(column);
            continue;
        }

        foreign_keys.push(OrientForeignKey {
            constraint_name,
            child_owner,
            child_table,
            parent_owner,
            parent_table,
            columns: vec![column],
        });
    }

    Ok(foreign_keys)
}

/// Per-table DML activity and freshness evidence for `oracle_orient`.
///
/// Oracle records these counters in `ALL_TAB_MODIFICATIONS` since the table's
/// last statistics collection. They are dictionary telemetry, never a scan of
/// table data, and are therefore suitable for the bounded read-only orient
/// snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrientHotObject {
    /// Schema owner of the changed table.
    pub owner: String,
    /// Changed table name.
    pub object_name: String,
    /// Object kind; activity telemetry is currently table-only.
    pub object_type: String,
    /// Inserts reported since the last statistics collection.
    pub inserts: i64,
    /// Updates reported since the last statistics collection.
    pub updates: i64,
    /// Deletes reported since the last statistics collection.
    pub deletes: i64,
    /// Sum of inserts, updates, and deletes since the last statistics collection.
    pub changes_since_last_stats: i64,
    /// Time Oracle last recorded table-modification activity, when available.
    pub last_modified: Option<String>,
    /// Whether Oracle recorded a table truncate since the last statistics collection.
    pub truncated: bool,
    /// Number of segment drops recorded since the last statistics collection.
    pub drop_segments: i64,
}

/// Read bounded hot-table activity and freshness from `ALL_TAB_MODIFICATIONS`.
///
/// The optional owner is upper-cased and bound positionally; `None` includes
/// every visible schema. Only table-level rows are admitted so partition and
/// subpartition telemetry cannot duplicate an object in the orient snapshot.
/// The result is ordered by DML volume, then recency, and capped with `ROWNUM`.
pub async fn orient_hot_objects(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OrientHotObject>, DbError> {
    orient_hot_objects_page(cx, conn, owner, 0, max_rows).await
}

/// Read one stable, offset-based hot-object page for `oracle_orient`.
pub async fn orient_hot_objects_page(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    offset: usize,
    max_rows: usize,
) -> Result<Vec<OrientHotObject>, DbError> {
    let owner_bind = owner.map_or(OracleBind::Null, |value| {
        OracleBind::from(value.to_ascii_uppercase())
    });
    let upper_bound = page_upper_bound(offset, max_rows)?;
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::OrientHotObjectsPage,
        &[
            owner_bind,
            OracleBind::from(upper_bound),
            OracleBind::from(offset as i64),
        ],
    )
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let inserts = row.parse_i64("INSERTS").unwrap_or_default();
            let updates = row.parse_i64("UPDATES").unwrap_or_default();
            let deletes = row.parse_i64("DELETES").unwrap_or_default();
            OrientHotObject {
                owner: row.text("OWNER").unwrap_or_default().to_owned(),
                object_name: row.text("OBJECT_NAME").unwrap_or_default().to_owned(),
                object_type: "TABLE".to_owned(),
                inserts,
                updates,
                deletes,
                changes_since_last_stats: inserts.saturating_add(updates).saturating_add(deletes),
                last_modified: row.text("LAST_MODIFIED").map(str::to_owned),
                truncated: row
                    .text("TRUNCATED")
                    .is_some_and(|value| value.eq_ignore_ascii_case("YES")),
                drop_segments: row.parse_i64("DROP_SEGMENTS").unwrap_or_default(),
            }
        })
        .collect())
}

/// One object with recent DDL evidence for `oracle_orient`.
///
/// `LAST_DDL_TIME` comes from the Oracle dictionary rather than table data, so
/// it captures structural freshness for every object type visible to the
/// current session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrientRecentDdlObject {
    /// Schema owner as stored in `ALL_OBJECTS`.
    pub owner: String,
    /// Object name as stored in `ALL_OBJECTS`.
    pub object_name: String,
    /// Oracle object kind from `ALL_OBJECTS.OBJECT_TYPE`.
    pub object_type: String,
    /// Most recent DDL timestamp, when Oracle supplies one.
    pub last_ddl_time: Option<String>,
}

/// Read a bounded, newest-first DDL feed for `oracle_orient`.
///
/// The optional owner is upper-cased and bound positionally; `None` covers all
/// objects visible to the session. A deterministic tie-break prevents cache
/// churn when several objects share the same Oracle timestamp, and the outer
/// `ROWNUM` cap bounds the dictionary response before it enters a snapshot.
pub async fn orient_recent_ddl(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OrientRecentDdlObject>, DbError> {
    orient_recent_ddl_page(cx, conn, owner, 0, max_rows).await
}

/// Read one stable, offset-based recent-DDL page for `oracle_orient`.
pub async fn orient_recent_ddl_page(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    offset: usize,
    max_rows: usize,
) -> Result<Vec<OrientRecentDdlObject>, DbError> {
    let owner_bind = owner.map_or(OracleBind::Null, |value| {
        OracleBind::from(value.to_ascii_uppercase())
    });
    let upper_bound = page_upper_bound(offset, max_rows)?;
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::OrientRecentDdlPage,
        &[
            owner_bind,
            OracleBind::from(upper_bound),
            OracleBind::from(offset as i64),
        ],
    )
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| OrientRecentDdlObject {
            owner: row.text("OWNER").unwrap_or_default().to_owned(),
            object_name: row.text("OBJECT_NAME").unwrap_or_default().to_owned(),
            object_type: row.text("OBJECT_TYPE").unwrap_or_default().to_owned(),
            last_ddl_time: row.text("LAST_DDL_TIME").map(str::to_owned),
        })
        .collect())
}

/// List schemas that own objects visible to this session, optionally filtered
/// by a SQL `LIKE` pattern.
pub async fn list_schemas(
    cx: &Cx,
    conn: &dyn OracleConnection,
    name_like: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    let name_like_bind = name_like.map_or(OracleBind::Null, |n| {
        OracleBind::from(n.to_ascii_uppercase())
    });
    run_catalog_query(
        cx,
        conn,
        CatalogQueryId::ListSchemas,
        &[name_like_bind, OracleBind::from(max_rows as i64)],
    )
    .await
}

/// An exact dictionary object identity in the approval dependency closure.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DependentObject {
    /// Owner (schema) of the dependent object.
    pub owner: String,
    /// Name of the dependent object.
    pub name: String,
    /// `ALL_DEPENDENCIES.TYPE` of the dependent (e.g. `VIEW`, `PROCEDURE`).
    pub object_type: String,
}

/// Fixed ceilings for approval dependency observations in 0.12.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepCaps {
    /// Maximum dependent distance, at most ten; roots have distance zero.
    pub max_depth: usize,
    /// Maximum dependent objects, excluding the requested roots, at most 1000.
    pub max_count: usize,
}

impl Default for DepCaps {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_count: 1000,
        }
    }
}

const MAX_DEPENDENT_EDGES: usize = 8000;
const MAX_DEPENDENT_SOURCE_LINES: usize = 4096;
const MAX_DEPENDENT_SOURCE_BYTES: usize = 1_048_576;

/// Why a dependency observation cannot establish a complete result.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyUncertaintyKind {
    /// Session-visible dependencies were read without verifying full visibility.
    VisibilityUnverified,
    /// A requested root was not visible as an exact dictionary object.
    UnresolvedRoot,
    /// A dependent's identity, status or modification facts were missing.
    UnresolvedObject,
    /// A dependency target could not be resolved locally.
    UnresolvedTarget,
    /// A database link prevents observing the referenced object locally.
    RemoteDependency,
    /// The dictionary dependency strength was not recognized.
    UnknownStrength,
    /// A returned row did not satisfy the closed projection.
    MalformedRow,
    /// Stored source required for a fingerprint could not be read.
    SourceUnavailable,
    /// The source observation was incomplete or exceeded a bound.
    SourceTruncated,
    /// Repeated observations disagreed during collection.
    ChangedDuringObservation,
}

/// One explicit gap; absence of a total is never an assertion of zero.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DependencyUncertainty {
    /// Closed reason for the gap.
    pub reason: DependencyUncertaintyKind,
    /// Exact affected object, when the row supplied one.
    pub object: Option<DependentObject>,
}

/// A hard resource ceiling that prevented a complete observation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyTruncation {
    /// Another dependent exists beyond the maximum distance.
    Depth,
    /// The dependent object count was exhausted.
    Count,
    /// The bounded edge projection was exhausted.
    Edges,
    /// The source line budget was exhausted.
    SourceLines,
    /// The source byte budget or a complete view-text projection was exhausted.
    SourceBytes,
    /// The bound JSON frontier would exceed the SQL bind budget.
    FrontierBytes,
}

/// Whether current stored source contributed a trustworthy content hash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DependencySourceHash {
    /// SHA-256 over complete source in dictionary line order.
    Computed {
        /// Content digest, independent of LAST_DDL_TIME precision.
        sha256: [u8; 32],
    },
    /// This object class has no stored source representation.
    NotApplicable,
    /// Missing or incomplete source never receives an empty-source hash.
    Unavailable {
        /// Closed reason no hash could be established.
        reason: DependencyUncertaintyKind,
    },
}

/// Exact object facts at one distance in a dependency observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DependentNode {
    /// Owner, name and object type, preserving dictionary case.
    pub object: DependentObject,
    /// Minimum observed distance from any requested root.
    pub depth: usize,
    /// Oracle object identity; missing identity is uncertain, not object zero.
    pub object_id: Option<u64>,
    /// Observed ALL_OBJECTS status.
    pub status: Option<String>,
    /// Canonical observed modification timestamp.
    pub last_ddl_time: Option<String>,
    /// Current content fingerprint or a typed missing/not-applicable status.
    pub source_hash: DependencySourceHash,
}

/// One observed dictionary edge, including unresolved and remote evidence.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// Referencing object.
    pub dependent: DependentObject,
    /// Referenced identity, when complete enough to name.
    pub referenced: Option<DependentObject>,
    /// Locally observed target identity; absent for remote or unresolved edges.
    pub referenced_object_id: Option<u64>,
    /// A remote link is evidence of uncertainty, never a local graph edge.
    pub referenced_link_name: Option<String>,
    /// HARD, REF, EXTENDED or an explicitly unknown dictionary strength.
    pub dependency_type: Option<String>,
}

/// One bounded, cycle-safe dictionary observation. An incomplete observation
/// retains its known nodes and explicit gaps; callers must not render it as 0.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DependentsClosure {
    /// Original exact roots, including ones whose metadata was unavailable.
    pub requested_roots: Vec<DependentObject>,
    /// Observed facts for the requested roots.
    pub roots: Vec<DependentNode>,
    /// Bounded transitive dependents with minimum distances.
    pub nodes: Vec<DependentNode>,
    /// Bounded incoming/outgoing evidence collected at the visited frontiers.
    pub edges: Vec<DependencyEdge>,
    /// Active depth and object ceilings.
    pub caps: DepCaps,
    /// At least one hard bound prevented completing the observation.
    pub truncated: bool,
    /// Every hard bound encountered.
    pub truncation: Vec<DependencyTruncation>,
    /// Every observed gap that prevents asserting an exact total.
    pub uncertainties: Vec<DependencyUncertainty>,
    /// Domain-separated SHA-256 binding sorted node facts, source hashes,
    /// edges, roots, gaps and truncation; collection timing is excluded.
    pub dependency_hash: [u8; 32],
    #[serde(skip)]
    query_count: usize,
}

impl DependentsClosure {
    /// Number of statements, bounded by max_depth + 4 with privilege fallbacks.
    #[must_use]
    pub fn query_count(&self) -> usize {
        self.query_count
    }
}

/// Typed failure to obtain a dependency observation.
#[derive(Debug, thiserror::Error)]
pub enum DependentsError {
    /// Caller-supplied roots or ceilings exceeded the closed API contract.
    #[error("dependency closure caps or roots are invalid")]
    InvalidCaps,
    /// Session-visible reads were denied, or comparison exposed hidden dependencies.
    #[error("dependency dictionary visibility could not be established")]
    NoPrivilege,
    /// The underlying database operation failed.
    #[error(transparent)]
    Database(#[from] DbError),
}

#[derive(Default)]
struct DependencySources {
    expected: Option<usize>,
    lines: BTreeMap<usize, String>,
    incomplete: bool,
}

fn dependency_identity(row: &OracleRow, columns: [&str; 3]) -> Option<DependentObject> {
    let [owner, name, object_type] = columns.map(|column| row.text(column));
    let (owner, name, object_type) = (owner?, name?, object_type?);
    if owner.is_empty() || name.is_empty() || object_type.is_empty() {
        return None;
    }
    Some(DependentObject {
        owner: owner.into(),
        name: name.into(),
        object_type: object_type.into(),
    })
}

fn dependency_source_required(kind: &str) -> bool {
    matches!(
        kind,
        "PACKAGE"
            | "PACKAGE BODY"
            | "PROCEDURE"
            | "FUNCTION"
            | "TRIGGER"
            | "TYPE"
            | "TYPE BODY"
            | "JAVA SOURCE"
            | "VIEW"
            | "MATERIALIZED VIEW"
    )
}

fn dependency_node(row: &OracleRow, depth: usize) -> Option<DependentNode> {
    let object = dependency_identity(row, ["OWNER", "NAME", "TYPE"])?;
    let source_hash = if dependency_source_required(&object.object_type) {
        DependencySourceHash::Unavailable {
            reason: DependencyUncertaintyKind::SourceUnavailable,
        }
    } else {
        DependencySourceHash::NotApplicable
    };
    Some(DependentNode {
        object,
        depth,
        object_id: row
            .text("OBJECT_ID")
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|id| *id > 0),
        status: row
            .text("STATUS")
            .filter(|status| !status.is_empty())
            .map(str::to_owned),
        last_ddl_time: row
            .text("LAST_DDL_TIME")
            .filter(|time| !time.is_empty())
            .map(str::to_owned),
        source_hash,
    })
}

async fn read_dependency_frontier(
    cx: &Cx,
    conn: &dyn OracleConnection,
    binds: &[OracleBind],
    visibility_verified: &mut bool,
    owner_source_views: &mut bool,
    query_count: &mut usize,
) -> Result<Vec<OracleRow>, DependentsError> {
    let mut attempts = vec![(*visibility_verified, *owner_source_views)];
    if *visibility_verified {
        attempts.push((false, *owner_source_views));
    }
    if *owner_source_views {
        // USER_* grants are independent of ALL_* grants. Preserve readable
        // source facts even if an installation restricts the owning views.
        attempts.push((*visibility_verified, false));
        if *visibility_verified {
            attempts.push((false, false));
        }
    }
    for (verified, owned) in attempts {
        let id = match (verified, owned) {
            (true, true) => CatalogQueryId::DependentsTransitive,
            (false, true) => CatalogQueryId::DependentsTransitiveVisible,
            (true, false) => CatalogQueryId::DependentsTransitiveAllSources,
            (false, false) => CatalogQueryId::DependentsTransitiveVisibleAllSources,
        };
        *query_count += 1;
        match run_catalog_query(cx, conn, id, binds).await {
            Ok(rows) => {
                *visibility_verified = verified;
                *owner_source_views = owned;
                return Ok(rows);
            }
            Err(error)
                if matches!(
                    oraclemcp_error::parse_ora_code(&error.to_string()),
                    Some(942 | 1031)
                ) => {}
            Err(error) => return Err(DependentsError::Database(error)),
        }
    }
    Err(DependentsError::NoPrivilege)
}

/// Read one successful statement per depth level, including the boundary probe
/// that distinguishes a leaf at the depth cap from a silently omitted child.
/// If full visibility cannot be checked, one denied statement precedes the
/// session-visible fallback; subsequent levels use that fallback directly.
/// Restricted USER_* grants can require two further denied probes before
/// retaining the original ALL_* source path. Each fallback is remembered.
/// Values are bound as a bounded JSON frontier; stored object IDs keep a
/// 1000-object frontier below Oracle's VARCHAR2 bind ceiling. Source is hashed
/// and discarded, never returned in the approval payload.
pub async fn probe_dependents_transitive(
    cx: &Cx,
    conn: &dyn OracleConnection,
    roots: &[DependentObject],
    caps: DepCaps,
) -> Result<DependentsClosure, DependentsError> {
    if caps.max_depth == 0
        || caps.max_depth > 10
        || caps.max_count == 0
        || caps.max_count > 1000
        || roots.is_empty()
        || roots.len() > 32
        || roots.iter().any(|root| {
            root.owner.is_empty()
                || root.name.is_empty()
                || root.object_type.is_empty()
                || root.owner.len() > 128
                || root.name.len() > 128
                || root.object_type.len() > 30
        })
    {
        return Err(DependentsError::InvalidCaps);
    }
    let root_keys: BTreeSet<_> = roots.iter().cloned().collect();
    let mut frontier = root_keys.clone();
    let mut nodes: BTreeMap<DependentObject, DependentNode> = BTreeMap::new();
    let mut edges = BTreeSet::new();
    let mut uncertainties = BTreeSet::new();
    let mut truncation = BTreeSet::new();
    let mut sources: BTreeMap<DependentObject, DependencySources> = BTreeMap::new();
    let mut source_bytes = 0usize;
    let mut source_lines = 0usize;
    let mut query_count = 0;
    let mut visibility_verified = true;
    let mut owner_source_views = true;
    for depth in 0..=caps.max_depth {
        if frontier.is_empty() {
            break;
        }
        let request: Vec<_> = frontier.iter().map(|object| {
            nodes.get(object).and_then(|node| node.object_id).map_or_else(
                || serde_json::json!({"owner":object.owner,"name":object.name,"type":object.object_type}),
                |id| serde_json::json!({"id":id}))
        }).collect();
        let json = serde_json::to_string(&request).map_err(|_| DependentsError::InvalidCaps)?;
        if json.len() > 32767 {
            truncation.insert(DependencyTruncation::FrontierBytes);
            break;
        }
        let binds = [
            OracleBind::from(json),
            OracleBind::I64((MAX_DEPENDENT_EDGES + 1) as i64),
            OracleBind::I64((MAX_DEPENDENT_SOURCE_LINES + 1) as i64),
        ];
        let rows = read_dependency_frontier(
            cx,
            conn,
            &binds,
            &mut visibility_verified,
            &mut owner_source_views,
            &mut query_count,
        )
        .await?;
        if !visibility_verified {
            uncertainties.insert(DependencyUncertainty {
                reason: DependencyUncertaintyKind::VisibilityUnverified,
                object: None,
            });
        }
        if rows
            .iter()
            .any(|row| row.text("ROW_KIND") == Some("visibility_gap"))
        {
            return Err(DependentsError::NoPrivilege);
        }
        if rows.iter().any(|row| {
            !matches!(
                row.text("ROW_KIND"),
                Some("object" | "dependency" | "source")
            )
        }) {
            uncertainties.insert(DependencyUncertainty {
                reason: DependencyUncertaintyKind::MalformedRow,
                object: None,
            });
        }
        let mut headers = BTreeMap::new();
        for row in rows
            .iter()
            .filter(|row| row.text("ROW_KIND") == Some("object"))
        {
            let Some(node) = dependency_node(row, depth) else {
                uncertainties.insert(DependencyUncertainty {
                    reason: DependencyUncertaintyKind::MalformedRow,
                    object: None,
                });
                continue;
            };
            if let Some(previous) = headers.insert(node.object.clone(), node.clone())
                && previous != node
            {
                uncertainties.insert(DependencyUncertainty {
                    reason: DependencyUncertaintyKind::MalformedRow,
                    object: Some(node.object),
                });
            }
        }
        for key in &frontier {
            if let Some(header) = headers.get(key) {
                if let Some(previous) = nodes.get(key) {
                    if previous.object_id != header.object_id
                        || previous.status != header.status
                        || previous.last_ddl_time != header.last_ddl_time
                    {
                        uncertainties.insert(DependencyUncertainty {
                            reason: DependencyUncertaintyKind::ChangedDuringObservation,
                            object: Some(key.clone()),
                        });
                    }
                } else {
                    nodes.insert(key.clone(), header.clone());
                }
            } else {
                uncertainties.insert(DependencyUncertainty {
                    reason: DependencyUncertaintyKind::UnresolvedRoot,
                    object: Some(key.clone()),
                });
            }
        }
        let dependency_rows: Vec<_> = rows
            .iter()
            .filter(|row| row.text("ROW_KIND") == Some("dependency"))
            .collect();
        if dependency_rows.len() > MAX_DEPENDENT_EDGES {
            truncation.insert(DependencyTruncation::Edges);
        }
        let mut next = BTreeSet::new();
        for row in dependency_rows {
            let Some(dependent) = dependency_identity(row, ["OWNER", "NAME", "TYPE"]) else {
                uncertainties.insert(DependencyUncertainty {
                    reason: DependencyUncertaintyKind::MalformedRow,
                    object: None,
                });
                continue;
            };
            let edge = DependencyEdge {
                dependent: dependent.clone(),
                referenced: dependency_identity(
                    row,
                    ["REFERENCED_OWNER", "REFERENCED_NAME", "REFERENCED_TYPE"],
                ),
                referenced_object_id: row
                    .text("REFERENCED_OBJECT_ID")
                    .and_then(|s| s.parse::<u64>().ok())
                    .filter(|id| *id > 0),
                referenced_link_name: row
                    .text("REFERENCED_LINK_NAME")
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
                dependency_type: row.text("DEPENDENCY_TYPE").map(str::to_owned),
            };
            if row.cell("REFERENCED_LINK_NAME").is_none() {
                uncertainties.insert(DependencyUncertainty {
                    reason: DependencyUncertaintyKind::MalformedRow,
                    object: Some(dependent.clone()),
                });
            }
            if edge.referenced_link_name.is_some() {
                uncertainties.insert(DependencyUncertainty {
                    reason: DependencyUncertaintyKind::RemoteDependency,
                    object: Some(dependent.clone()),
                });
            } else if edge.referenced.is_none() || edge.referenced_object_id.is_none() {
                uncertainties.insert(DependencyUncertainty {
                    reason: DependencyUncertaintyKind::UnresolvedTarget,
                    object: Some(dependent.clone()),
                });
            }
            if !matches!(
                edge.dependency_type.as_deref(),
                Some("HARD" | "REF" | "EXTENDED")
            ) {
                uncertainties.insert(DependencyUncertainty {
                    reason: DependencyUncertaintyKind::UnknownStrength,
                    object: Some(dependent.clone()),
                });
            }
            let incoming = edge
                .referenced
                .as_ref()
                .is_some_and(|target| frontier.contains(target))
                && edge.referenced_link_name.is_none();
            if !edges.contains(&edge) && edges.len() >= MAX_DEPENDENT_EDGES {
                truncation.insert(DependencyTruncation::Edges);
            } else {
                edges.insert(edge);
            }
            if !incoming || nodes.contains_key(&dependent) {
                continue;
            }
            if depth >= caps.max_depth {
                truncation.insert(DependencyTruncation::Depth);
                continue;
            }
            if nodes.keys().filter(|key| !root_keys.contains(*key)).count() >= caps.max_count {
                truncation.insert(DependencyTruncation::Count);
                continue;
            }
            let node = headers.get(&dependent).cloned().map(|mut node| {
                node.depth = depth + 1;
                node
            });
            if let Some(node) = node {
                if node.object_id.is_some() {
                    next.insert(dependent.clone());
                }
                nodes.insert(dependent, node);
            } else {
                uncertainties.insert(DependencyUncertainty {
                    reason: DependencyUncertaintyKind::UnresolvedObject,
                    object: Some(dependent),
                });
            }
        }
        let source_rows: Vec<_> = rows
            .iter()
            .filter(|row| row.text("ROW_KIND") == Some("source"))
            .collect();
        if source_rows.len() > MAX_DEPENDENT_SOURCE_LINES {
            truncation.insert(DependencyTruncation::SourceLines);
        }
        for row in source_rows {
            let Some(key) = dependency_identity(row, ["OWNER", "NAME", "TYPE"]) else {
                uncertainties.insert(DependencyUncertainty {
                    reason: DependencyUncertaintyKind::MalformedRow,
                    object: None,
                });
                continue;
            };
            if !nodes.contains_key(&key) {
                continue;
            }
            let source = sources.entry(key.clone()).or_default();
            let expected = row
                .text("SOURCE_LINES")
                .and_then(|s| s.parse::<usize>().ok());
            if source.expected.is_some() && source.expected != expected {
                source.incomplete = true;
            }
            source.expected = expected;
            let Some((line, text)) = row
                .text("LINE")
                .and_then(|s| s.parse::<usize>().ok())
                .zip(row.text("TEXT"))
            else {
                source.incomplete = true;
                continue;
            };
            if line == 0 {
                source.incomplete = true;
                continue;
            }
            if row
                .text("SOURCE_LENGTH")
                .and_then(|s| s.parse::<usize>().ok())
                != Some(text.len())
            {
                source.incomplete = true;
                truncation.insert(DependencyTruncation::SourceBytes);
            }
            if let Some(previous) = source.lines.get(&line) {
                if previous != text {
                    source.incomplete = true;
                    uncertainties.insert(DependencyUncertainty {
                        reason: DependencyUncertaintyKind::ChangedDuringObservation,
                        object: Some(key),
                    });
                }
                continue;
            }
            if source_lines >= MAX_DEPENDENT_SOURCE_LINES {
                truncation.insert(DependencyTruncation::SourceLines);
                source.incomplete = true;
                continue;
            }
            if source_bytes.saturating_add(text.len()) > MAX_DEPENDENT_SOURCE_BYTES {
                truncation.insert(DependencyTruncation::SourceBytes);
                source.incomplete = true;
                continue;
            }
            source_lines += 1;
            source_bytes += text.len();
            source.lines.insert(line, text.to_owned());
        }
        frontier = next;
        if truncation.contains(&DependencyTruncation::Count)
            || truncation.contains(&DependencyTruncation::Edges)
        {
            break;
        }
    }
    for (key, node) in &mut nodes {
        if node.object_id.is_none() || node.status.is_none() || node.last_ddl_time.is_none() {
            uncertainties.insert(DependencyUncertainty {
                reason: DependencyUncertaintyKind::UnresolvedObject,
                object: Some(key.clone()),
            });
        }
        if !dependency_source_required(&key.object_type) {
            continue;
        }
        if let Some(source) = sources.get(key)
            && !source.incomplete
            && !source.lines.is_empty()
            && source.expected == Some(source.lines.len())
            && source.lines.keys().copied().eq(1..=source.lines.len())
        {
            let mut hash = Sha256::new();
            for text in source.lines.values() {
                hash.update(text.as_bytes());
            }
            node.source_hash = DependencySourceHash::Computed {
                sha256: hash.finalize().into(),
            };
        } else {
            let reason = if sources
                .get(key)
                .is_some_and(|source| source.incomplete || !source.lines.is_empty())
            {
                DependencyUncertaintyKind::SourceTruncated
            } else {
                DependencyUncertaintyKind::SourceUnavailable
            };
            node.source_hash = DependencySourceHash::Unavailable { reason };
            uncertainties.insert(DependencyUncertainty {
                reason,
                object: Some(key.clone()),
            });
        }
    }
    let (roots, nodes): (Vec<_>, Vec<_>) = nodes
        .into_values()
        .partition(|node| root_keys.contains(&node.object));
    let mut closure = DependentsClosure {
        requested_roots: root_keys.into_iter().collect(),
        roots,
        nodes,
        edges: edges.into_iter().collect(),
        caps,
        truncated: !truncation.is_empty(),
        truncation: truncation.into_iter().collect(),
        uncertainties: uncertainties.into_iter().collect(),
        dependency_hash: [0; 32],
        query_count,
    };
    let canonical = serde_json::to_vec(&closure)
        .map_err(|error| DependentsError::Database(DbError::Internal(error.to_string())))?;
    let mut hash = Sha256::new();
    hash.update(b"omcp/dependents-closure/v1\0");
    hash.update(canonical);
    closure.dependency_hash = hash.finalize().into();
    Ok(closure)
}

#[cfg(test)]
mod transitive_dependents_tests {
    use super::*;
    use crate::{OracleBackend, OracleConnectionInfo};
    use asupersync::runtime::RuntimeBuilder;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct GraphConnection {
        objects: BTreeMap<u64, DependentObject>,
        edges: Vec<(u64, u64, bool)>,
        calls: AtomicUsize,
        denied: bool,
        verification_denied: bool,
        owner_source_denied: bool,
        verification_calls: AtomicUsize,
        /// The `(:2, :3)` edge and source-line fetch binds of every frontier read.
        fetch_caps: std::sync::Mutex<Vec<(i64, i64)>>,
        source: String,
        transform: fn(&mut Vec<OracleRow>),
    }

    impl GraphConnection {
        fn new(edges: &[(u64, u64)]) -> Self {
            let ids = edges
                .iter()
                .flat_map(|(from, to)| [*from, *to])
                .chain([1])
                .collect::<BTreeSet<_>>();
            Self {
                objects: ids
                    .into_iter()
                    .map(|id| {
                        (
                            id,
                            DependentObject {
                                owner: "APP".into(),
                                name: format!("P{id}"),
                                object_type: "PROCEDURE".into(),
                            },
                        )
                    })
                    .collect(),
                edges: edges.iter().map(|(from, to)| (*from, *to, false)).collect(),
                calls: AtomicUsize::new(0),
                denied: false,
                verification_denied: false,
                owner_source_denied: false,
                verification_calls: AtomicUsize::new(0),
                fetch_caps: std::sync::Mutex::new(Vec::new()),
                source: "PROCEDURE P AS BEGIN NULL; END;\n".into(),
                transform: |_| {},
            }
        }

        fn row(&self, kind: &str, id: u64) -> OracleRow {
            let object = &self.objects[&id];
            let fields = [
                ("ROW_KIND", kind.to_owned()),
                ("OWNER", object.owner.clone()),
                ("NAME", object.name.clone()),
                ("TYPE", object.object_type.clone()),
                ("OBJECT_ID", id.to_string()),
                ("STATUS", "VALID".into()),
                ("LAST_DDL_TIME", "2026-10-31T00:00:00".into()),
            ];
            OracleRow {
                columns: fields
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), OracleCell::new("VARCHAR2", Some(value))))
                    .collect(),
            }
        }

        fn root(&self) -> Vec<DependentObject> {
            vec![self.objects[&1].clone()]
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for GraphConnection {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn close(&self, _: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn ping(&self, _: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        async fn execute(&self, _: &Cx, _: &str, _: &[OracleBind]) -> Result<u64, DbError> {
            panic!("dependency observation executed SQL")
        }
        async fn commit(&self, _: &Cx) -> Result<(), DbError> {
            panic!("dependency observation committed")
        }
        async fn rollback(&self, _: &Cx) -> Result<(), DbError> {
            panic!("dependency observation rolled back")
        }
        async fn query_rows(
            &self,
            _: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            assert!(
                [
                    CatalogQueryId::DependentsTransitive,
                    CatalogQueryId::DependentsTransitiveVisible,
                    CatalogQueryId::DependentsTransitiveAllSources,
                    CatalogQueryId::DependentsTransitiveVisibleAllSources,
                ]
                .iter()
                .any(|id| id.spec().sql == sql),
                "frontier SQL must stay in the closed dependency projection"
            );
            let verified = [
                CatalogQueryId::DependentsTransitive,
                CatalogQueryId::DependentsTransitiveAllSources,
            ]
            .iter()
            .any(|id| sql == id.spec().sql);
            let owned = [
                CatalogQueryId::DependentsTransitive,
                CatalogQueryId::DependentsTransitiveVisible,
            ]
            .iter()
            .any(|id| sql == id.spec().sql);
            self.calls.fetch_add(1, Ordering::SeqCst);
            if verified {
                self.verification_calls.fetch_add(1, Ordering::SeqCst);
            }
            if self.denied
                || (verified && self.verification_denied)
                || (owned && self.owner_source_denied)
            {
                return Err(DbError::Query(
                    "ORA-00942: table or view does not exist".into(),
                ));
            }
            let OracleBind::String(json) = &binds[0] else {
                panic!("JSON frontier bind")
            };
            assert!(json.len() <= 32767);
            // Like Oracle's `ROWNUM <= :2` / `:3`, the database returns no more
            // rows than the fetch binds allow, so the binds decide what the
            // collector can see of each cap.
            let (Some(OracleBind::I64(edge_cap)), Some(OracleBind::I64(line_cap))) =
                (binds.get(1), binds.get(2))
            else {
                panic!("edge and source-line fetch binds")
            };
            self.fetch_caps.lock().unwrap().push((*edge_cap, *line_cap));
            let edge_cap = usize::try_from(*edge_cap).expect("non-negative edge bind");
            let line_cap = usize::try_from(*line_cap).expect("non-negative line bind");
            let request: serde_json::Value = serde_json::from_str(json).unwrap();
            let frontier = request
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|item| {
                    item["id"].as_u64().or_else(|| {
                        self.objects
                            .iter()
                            .find(|(_, object)| {
                                item["owner"] == object.owner
                                    && item["name"] == object.name
                                    && item["type"] == object.object_type
                            })
                            .map(|(id, _)| *id)
                    })
                })
                .collect::<BTreeSet<_>>();
            let selected = self
                .edges
                .iter()
                .filter(|(from, to, _)| frontier.contains(from) || frontier.contains(to))
                .take(edge_cap)
                .collect::<Vec<_>>();
            let mut object_ids = frontier.clone();
            object_ids.extend(
                selected
                    .iter()
                    .filter(|(_, to, remote)| frontier.contains(to) && !remote)
                    .map(|(from, _, _)| *from),
            );
            let mut rows = object_ids
                .iter()
                .map(|id| self.row("object", *id))
                .collect::<Vec<_>>();
            for (from, to, remote) in selected {
                let mut row = self.row("dependency", *from);
                let target = &self.objects[to];
                for (key, value) in [
                    ("REFERENCED_OWNER", Some(target.owner.clone())),
                    ("REFERENCED_NAME", Some(target.name.clone())),
                    ("REFERENCED_TYPE", Some(target.object_type.clone())),
                    ("REFERENCED_LINK_NAME", remote.then(|| "REMOTE_DB".into())),
                    ("DEPENDENCY_TYPE", Some("HARD".into())),
                    ("REFERENCED_OBJECT_ID", (!remote).then(|| to.to_string())),
                ] {
                    row.columns
                        .push((key.into(), OracleCell::new("VARCHAR2", value)));
                }
                rows.push(row);
            }
            for id in object_ids.into_iter().take(line_cap) {
                let mut row = self.row("source", id);
                for (key, value) in [
                    ("LINE", "1".into()),
                    ("TEXT", self.source.clone()),
                    ("SOURCE_LINES", "1".into()),
                    ("SOURCE_LENGTH", self.source.len().to_string()),
                ] {
                    row.columns
                        .push((key.into(), OracleCell::new("VARCHAR2", Some(value))));
                }
                rows.push(row);
            }
            (self.transform)(&mut rows);
            Ok(rows)
        }
    }

    fn run<F: Future<Output = ()>>(body: impl FnOnce(Cx) -> F) {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async { body(Cx::current().unwrap()).await });
    }

    use std::future::Future;

    #[test]
    fn dependents_transitive_depth_cap_truncated() {
        run(|cx| async move {
            let conn = GraphConnection::new(&[(2, 1), (3, 2), (4, 3)]);
            let result = probe_dependents_transitive(
                &cx,
                &conn,
                &conn.root(),
                DepCaps {
                    max_depth: 2,
                    max_count: 100,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                result
                    .nodes
                    .iter()
                    .map(|node| node.depth)
                    .collect::<Vec<_>>(),
                vec![1, 2]
            );
            assert!(result.truncated && result.truncation.contains(&DependencyTruncation::Depth));
            assert_eq!(result.query_count(), 3);
        });
    }

    #[test]
    fn dependents_count_cap_truncated() {
        run(|cx| async move {
            let conn = GraphConnection::new(&[(2, 1), (3, 1), (4, 1)]);
            let result = probe_dependents_transitive(
                &cx,
                &conn,
                &conn.root(),
                DepCaps {
                    max_depth: 10,
                    max_count: 2,
                },
            )
            .await
            .unwrap();
            assert_eq!(result.nodes.len(), 2);
            assert!(result.truncated && result.truncation.contains(&DependencyTruncation::Count));
            assert_eq!(result.query_count(), 1);
        });
    }

    /// pvlqq oraclemcp-pjotx: each frontier read fetches exactly one row past
    /// the edge and source-line caps. One fewer hides the boundary row; more
    /// fetches dictionary rows the collector is bound never to read.
    #[test]
    fn dependents_fetch_binds_probe_one_row_past_each_cap() {
        run(|cx| async move {
            let conn = GraphConnection::new(&[(2, 1), (3, 2)]);
            probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            let caps = conn.fetch_caps.lock().unwrap();
            assert_eq!(caps.len(), conn.calls.load(Ordering::SeqCst));
            assert!(!caps.is_empty());
            let expected = (
                i64::try_from(MAX_DEPENDENT_EDGES + 1).unwrap(),
                i64::try_from(MAX_DEPENDENT_SOURCE_LINES + 1).unwrap(),
            );
            assert!(caps.iter().all(|seen| *seen == expected), "{caps:?}");
        });
    }

    /// The edge cap is detected only through the boundary row the bind admits:
    /// one dependency past the cap must surface as `Edges` truncation.
    #[test]
    fn dependents_edge_cap_boundary_row_is_seen_through_the_fetch_bind() {
        run(|cx| async move {
            let edges = (2..=MAX_DEPENDENT_EDGES as u64 + 2)
                .map(|id| (id, 1))
                .collect::<Vec<_>>();
            assert_eq!(edges.len(), MAX_DEPENDENT_EDGES + 1);
            let conn = GraphConnection::new(&edges);
            let result = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            assert!(result.truncated);
            assert!(
                result.truncation.contains(&DependencyTruncation::Edges),
                "{:?}",
                result.truncation
            );
        });
    }

    #[test]
    fn dependents_cycle_terminates() {
        run(|cx| async move {
            let conn = GraphConnection::new(&[(2, 1), (1, 2), (3, 2)]);
            let result = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            assert_eq!(result.nodes.len(), 2);
            assert_eq!(result.query_count(), 3);
            assert!(!result.truncated);
        });
    }

    #[test]
    fn dependents_batched_one_query_per_level() {
        run(|cx| async move {
            let conn = GraphConnection::new(&[(2, 1), (3, 1), (4, 2), (5, 3)]);
            let result = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            assert_eq!(result.nodes.len(), 4);
            assert_eq!(result.query_count(), 3);
            assert_eq!(
                conn.calls.load(Ordering::SeqCst),
                3,
                "width must not multiply queries"
            );
            assert!(result.uncertainties.is_empty() && !result.truncated);
        });
    }

    #[test]
    fn dependents_remote_edges_are_uncertain() {
        run(|cx| async move {
            let mut conn = GraphConnection::new(&[(2, 1)]);
            conn.edges[0].2 = true;
            let result = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            assert!(result.nodes.is_empty());
            assert!(
                result
                    .uncertainties
                    .iter()
                    .any(|item| item.reason == DependencyUncertaintyKind::RemoteDependency)
            );
            assert_eq!(result.edges.len(), 1, "remote evidence must not disappear");
        });
    }

    #[test]
    fn dependents_no_privilege_is_typed() {
        run(|cx| async move {
            let mut conn = GraphConnection::new(&[]);
            conn.denied = true;
            assert!(matches!(
                probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default()).await,
                Err(DependentsError::NoPrivilege)
            ));
        });
    }

    #[test]
    fn dependents_without_dba_visibility_retains_visible_transitive_nodes() {
        run(|cx| async move {
            let mut conn = GraphConnection::new(&[(2, 1), (3, 2)]);
            conn.verification_denied = true;
            let result = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .expect("session-visible ALL_DEPENDENCIES closure remains available");
            assert_eq!(
                result
                    .nodes
                    .iter()
                    .map(|node| node.depth)
                    .collect::<Vec<_>>(),
                vec![1, 2]
            );
            assert!(!result.truncated);
            assert!(
                result
                    .uncertainties
                    .iter()
                    .any(|gap| gap.reason == DependencyUncertaintyKind::VisibilityUnverified)
            );
            assert_eq!(
                conn.verification_calls.load(Ordering::SeqCst),
                1,
                "denied DBA verification must not be retried at each level"
            );
            assert_eq!(
                conn.calls.load(Ordering::SeqCst),
                4,
                "three successful batched levels plus one denied verification"
            );
            assert_eq!(result.query_count(), 4);
        });
    }

    #[test]
    fn dependents_restricted_owning_views_preserve_verified_source_facts() {
        run(|cx| async move {
            let baseline = GraphConnection::new(&[(2, 1), (3, 2)]);
            let expected =
                probe_dependents_transitive(&cx, &baseline, &baseline.root(), DepCaps::default())
                    .await
                    .unwrap();
            let mut restricted = GraphConnection::new(&[(2, 1), (3, 2)]);
            restricted.owner_source_denied = true;
            let actual = probe_dependents_transitive(
                &cx,
                &restricted,
                &restricted.root(),
                DepCaps::default(),
            )
            .await
            .expect("readable ALL_* source facts must not become unavailable");
            assert_eq!(actual.roots, expected.roots);
            assert_eq!(actual.nodes, expected.nodes);
            assert_eq!(actual.edges, expected.edges);
            assert_eq!(actual.uncertainties, expected.uncertainties);
            assert_eq!(actual.dependency_hash, expected.dependency_hash);
            assert!(!actual.truncated);
            assert_eq!(
                actual.query_count(),
                5,
                "two denied probes then three verified levels"
            );
        });
    }

    #[test]
    fn dependents_restricted_owning_views_preserve_visibility_and_query_bound() {
        run(|cx| async move {
            let edges = (2..=11).map(|id| (id, id - 1)).collect::<Vec<_>>();
            let mut baseline = GraphConnection::new(&edges);
            baseline.verification_denied = true;
            let expected =
                probe_dependents_transitive(&cx, &baseline, &baseline.root(), DepCaps::default())
                    .await
                    .unwrap();
            let mut restricted = GraphConnection::new(&edges);
            restricted.verification_denied = true;
            restricted.owner_source_denied = true;
            let actual = probe_dependents_transitive(
                &cx,
                &restricted,
                &restricted.root(),
                DepCaps::default(),
            )
            .await
            .expect("visible ALL_* facts remain available without owning-view grants");
            assert_eq!(actual.roots, expected.roots);
            assert_eq!(actual.nodes, expected.nodes);
            assert_eq!(actual.edges, expected.edges);
            assert_eq!(actual.uncertainties, expected.uncertainties);
            assert_eq!(actual.dependency_hash, expected.dependency_hash);
            assert_eq!(actual.uncertainties.len(), 1);
            assert_eq!(
                actual.uncertainties[0].reason,
                DependencyUncertaintyKind::VisibilityUnverified
            );
            assert!(!actual.truncated);
            assert_eq!(
                actual.query_count(),
                14,
                "eleven levels and at most three denied probes"
            );
        });
    }

    #[test]
    fn dependents_hash_binds_source_with_unchanged_last_ddl_time() {
        run(|cx| async move {
            let mut conn = GraphConnection::new(&[(2, 1)]);
            let first = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            conn.source = "PROCEDURE P AS BEGIN RAISE NO_DATA_FOUND; END;\n".into();
            let changed = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            assert_eq!(first.nodes[0].last_ddl_time, changed.nodes[0].last_ddl_time);
            assert_ne!(first.nodes[0].source_hash, changed.nodes[0].source_hash);
            assert_ne!(first.dependency_hash, changed.dependency_hash);
        });
    }

    #[test]
    fn dependents_leaf_at_depth_cap_is_complete() {
        run(|cx| async move {
            let conn = GraphConnection::new(&[(2, 1), (3, 2)]);
            let result = probe_dependents_transitive(
                &cx,
                &conn,
                &conn.root(),
                DepCaps {
                    max_depth: 2,
                    max_count: 10,
                },
            )
            .await
            .unwrap();
            assert_eq!(result.nodes.len(), 2);
            assert_eq!(result.query_count(), 3);
            assert!(!result.truncated);
        });
    }

    #[test]
    fn dependents_detected_hidden_rows_are_no_privilege() {
        run(|cx| async move {
            let mut conn = GraphConnection::new(&[]);
            conn.transform = |rows| {
                rows.push(OracleRow {
                    columns: vec![(
                        "ROW_KIND".into(),
                        OracleCell::new("VARCHAR2", Some("visibility_gap".into())),
                    )],
                })
            };
            assert!(matches!(
                probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default()).await,
                Err(DependentsError::NoPrivilege)
            ));
        });
    }

    #[test]
    fn dependents_unresolved_native_identity_is_uncertain() {
        run(|cx| async move {
            let mut conn = GraphConnection::new(&[(2, 1)]);
            conn.transform = |rows| {
                for row in rows
                    .iter_mut()
                    .filter(|row| row.text("ROW_KIND") == Some("dependency"))
                {
                    row.columns.retain(|(key, _)| {
                        key != "REFERENCED_OBJECT_ID" && key != "REFERENCED_LINK_NAME"
                    });
                }
            };
            let result = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            assert_eq!(
                result.nodes.len(),
                1,
                "retain known incoming identities alongside the gap"
            );
            for reason in [
                DependencyUncertaintyKind::UnresolvedTarget,
                DependencyUncertaintyKind::MalformedRow,
            ] {
                assert!(
                    result
                        .uncertainties
                        .iter()
                        .any(|item| item.reason == reason)
                );
            }
        });
    }

    #[test]
    fn dependents_source_budget_is_typed_truncation() {
        run(|cx| async move {
            let edges = (2..=260).map(|id| (id, 1)).collect::<Vec<_>>();
            let mut conn = GraphConnection::new(&edges);
            conn.source = "x".repeat(4096);
            let result = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            assert!(
                result.truncated
                    && result
                        .truncation
                        .contains(&DependencyTruncation::SourceBytes)
            );
            assert!(
                result.nodes.iter().any(|node| matches!(
                    node.source_hash,
                    DependencySourceHash::Unavailable { .. }
                ))
            );
        });
    }

    #[test]
    fn dependents_missing_source_never_has_an_empty_computed_hash() {
        run(|cx| async move {
            let mut conn = GraphConnection::new(&[(2, 1)]);
            conn.transform = |rows| rows.retain(|row| row.text("ROW_KIND") != Some("source"));
            let result = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            assert!(
                result
                    .roots
                    .iter()
                    .chain(&result.nodes)
                    .all(|node| matches!(
                        node.source_hash,
                        DependencySourceHash::Unavailable {
                            reason: DependencyUncertaintyKind::SourceUnavailable
                        }
                    ))
            );
            assert_eq!(result.uncertainties.len(), 2);
        });
    }

    #[test]
    fn dependents_frontier_ids_preserve_the_full_count_cap_in_one_batch() {
        run(|cx| async move {
            let edges = (2..=1001).map(|id| (id, 1)).collect::<Vec<_>>();
            let conn = GraphConnection::new(&edges);
            let result = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            assert_eq!(result.nodes.len(), 1000);
            assert_eq!(result.query_count(), 2);
            assert!(!result.truncated);
        });
    }

    #[test]
    fn dependents_quoted_identity_is_exact_and_caps_fail_before_io() {
        run(|cx| async move {
            let mut conn = GraphConnection::new(&[(2, 1)]);
            let root = conn.objects.get_mut(&1).unwrap();
            root.owner = "MiX".into();
            root.name = "Dotted.Name\"Quoted".into();
            let result = probe_dependents_transitive(&cx, &conn, &conn.root(), DepCaps::default())
                .await
                .unwrap();
            assert_eq!(result.roots[0].object, conn.root()[0]);
            let before = conn.calls.load(Ordering::SeqCst);
            assert!(matches!(
                probe_dependents_transitive(
                    &cx,
                    &conn,
                    &conn.root(),
                    DepCaps {
                        max_depth: 11,
                        max_count: 1000
                    }
                )
                .await,
                Err(DependentsError::InvalidCaps)
            ));
            assert_eq!(conn.calls.load(Ordering::SeqCst), before);
        });
    }
}

/// Describe one index's metadata, indexed columns, and function-based
/// expressions. Owner + index name are bound.
pub async fn describe_index(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    index_name: &str,
) -> Result<IndexDescription, DbError> {
    let owner = owner.to_ascii_uppercase();
    let index_name = index_name.to_ascii_uppercase();
    let binds = [
        OracleBind::from(owner.clone()),
        OracleBind::from(index_name.clone()),
    ];

    let metadata = run_catalog_query(cx, conn, CatalogQueryId::IndexMetadata, &binds)
        .await?
        .into_iter()
        .next();
    if metadata.is_none() {
        return Err(describe_object_not_found("index", &owner, &index_name));
    }
    let columns = run_catalog_query(cx, conn, CatalogQueryId::IndexColumns, &binds).await?;
    let expressions = run_catalog_query(cx, conn, CatalogQueryId::IndexExpressions, &binds).await?;

    Ok(IndexDescription {
        metadata,
        columns,
        expressions,
    })
}

/// Describe one trigger's timing/event/status and body. Owner + trigger name
/// are bound.
pub async fn describe_trigger(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    trigger_name: &str,
) -> Result<TriggerDescription, DbError> {
    let owner = owner.to_ascii_uppercase();
    let trigger_name = trigger_name.to_ascii_uppercase();
    let metadata = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::TriggerMetadata,
        &[
            OracleBind::from(owner.clone()),
            OracleBind::from(trigger_name.clone()),
        ],
    )
    .await?
    .into_iter()
    .next();
    if metadata.is_none() {
        return Err(describe_object_not_found("trigger", &owner, &trigger_name));
    }
    Ok(TriggerDescription { metadata })
}

/// Describe one view's definition metadata and columns. Owner + view name are
/// bound.
pub async fn describe_view(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    view_name: &str,
) -> Result<ViewDescription, DbError> {
    let owner = owner.to_ascii_uppercase();
    let view_name = view_name.to_ascii_uppercase();
    let binds = [
        OracleBind::from(owner.clone()),
        OracleBind::from(view_name.clone()),
    ];

    let metadata = run_catalog_query(cx, conn, CatalogQueryId::ViewMetadata, &binds)
        .await?
        .into_iter()
        .next();
    if metadata.is_none() {
        return Err(describe_object_not_found("view", &owner, &view_name));
    }
    let columns = describe_columns(cx, conn, &owner, &view_name).await?;
    Ok(ViewDescription { metadata, columns })
}

fn describe_object_not_found(object_type: &str, owner: &str, name: &str) -> DbError {
    DbError::Refused(Box::new(
        oraclemcp_error::ErrorEnvelope::new(
            oraclemcp_error::ErrorClass::ObjectNotFound,
            format!("{object_type} {owner}.{name} was not found or is not visible to this session"),
        )
        .with_suggested_tool("oracle_schema_inspect")
        .with_next_step("call oracle_schema_inspect to list objects visible to this session")
        .with_next_step("verify the owner, object name, and exact case for quoted identifiers"),
    ))
}

/// Columns of a table/view (owner + name bound exactly as resolved by the
/// caller, so double-quoted Oracle identifiers retain their case).
pub async fn describe_columns(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Vec<OracleRow>, DbError> {
    let data_default_vc_available =
        !run_catalog_query(cx, conn, CatalogQueryId::DescribeDefaultVcProbe, &[])
            .await?
            .is_empty();
    run_catalog_query(
        cx,
        conn,
        CatalogQueryId::describe_columns_query(data_default_vc_available),
        &[OracleBind::from(owner), OracleBind::from(table)],
    )
    .await
}

/// Constraint metadata for a table/view (owner + name bound exactly as
/// resolved by the caller, so double-quoted Oracle identifiers retain case).
pub async fn describe_constraints(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    run_catalog_query(
        cx,
        conn,
        CatalogQueryId::DescribeConstraints,
        &[
            OracleBind::from(owner),
            OracleBind::from(table),
            OracleBind::from(max_rows.max(1) as i64),
        ],
    )
    .await
}

/// `get_ddl`: `DBMS_METADATA.GET_DDL` for an object. The type stays allowlisted,
/// and all three scalar arguments are bound.
pub async fn get_ddl(
    cx: &Cx,
    conn: &dyn OracleConnection,
    object_type: &str,
    owner: &str,
    name: &str,
) -> Result<Option<DdlText>, DbError> {
    if !is_ddl_object_type(object_type) {
        return Err(DbError::InvalidArgument(format!(
            "unsupported DDL object type: {object_type:?}"
        )));
    }
    let metadata_type = match object_type {
        "PACKAGE BODY" => "PACKAGE_BODY",
        "TYPE BODY" => "TYPE_BODY",
        other => other,
    };
    // DBMS_METADATA returns a CLOB. The thin-driver path intentionally reads a
    // bounded VARCHAR2 prefix, and carries GETLENGTH alongside it so the MCP
    // surface can never silently present a partial document as complete.
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::GetDdl,
        &[
            OracleBind::from(metadata_type.to_ascii_uppercase()),
            OracleBind::from(name.to_ascii_uppercase()),
            OracleBind::from(owner.to_ascii_uppercase()),
        ],
    )
    .await?;
    Ok(rows.first().and_then(ddl_text_from_row))
}

fn ddl_text_from_row(row: &OracleRow) -> Option<DdlText> {
    let text = row.text("DDL")?.to_owned();
    let returned_chars = text.chars().count();
    let char_count = row
        .parse_i64("DDL_LENGTH")
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(returned_chars);
    Some(DdlText {
        truncated: char_count > returned_chars,
        text,
        char_count,
    })
}

/// Compile errors for an owner, optionally narrowed to one object (`ALL_ERRORS`;
/// owner + name bound).
pub async fn compile_errors(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    // Each `:n` OCCURRENCE consumes one positional value — the thin driver
    // binds per occurrence, not per distinct name, so the optional name filter
    // is written `:2 ... :3` and its value supplied twice. Reusing `:2` made
    // this statement declare four slots against three values, and Oracle
    // answered every call with ORA-01008.
    let name_bind = || {
        name.map_or(OracleBind::Null, |n| {
            OracleBind::from(n.to_ascii_uppercase())
        })
    };
    run_catalog_query(
        cx,
        conn,
        CatalogQueryId::CompileErrors,
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            name_bind(),
            name_bind(),
            OracleBind::from(max_rows.max(1) as i64),
        ],
    )
    .await
}

/// Full-text search across `ALL_SOURCE`, optionally owner/type/name-filtered
/// and row-capped. NULL owner means all visible schemas.
pub async fn search_source(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    needle: &str,
    object_type: Option<&str>,
    name_like: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    let source_type = match object_type {
        Some(t) => Some(normalize_source_search_object_type(t).ok_or_else(|| {
            DbError::InvalidArgument(format!("unsupported source object type: {t:?}"))
        })?),
        None => None,
    };
    let owner_bind = owner.map_or(OracleBind::Null, |o| {
        OracleBind::from(o.to_ascii_uppercase())
    });
    let type_bind = source_type.map_or(OracleBind::Null, OracleBind::from);
    let name_like_bind = name_like.map_or(OracleBind::Null, |n| {
        OracleBind::from(n.to_ascii_uppercase())
    });
    run_catalog_query(
        cx,
        conn,
        CatalogQueryId::SearchSource,
        &[
            owner_bind,
            type_bind,
            name_like_bind,
            OracleBind::from(needle),
            OracleBind::from(max_rows as i64),
        ],
    )
    .await
}

/// Full source text for one object from `ALL_SOURCE`, capped by characters.
pub async fn get_source(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    object_type: &str,
    options: SourceReadOptions,
) -> Result<SourceText, DbError> {
    let Some(source_type) = normalize_source_object_type(object_type) else {
        return Err(DbError::InvalidArgument(format!(
            "unsupported source object type: {object_type:?}"
        )));
    };
    if source_type == "VIEW" {
        return get_view_source(cx, conn, owner, name, options).await;
    }
    // One positional value per `:n` OCCURRENCE (see `compile_errors`): each
    // optional line bound is tested and compared through its own placeholder
    // and supplied twice, rather than reusing `:4`/`:5`.
    let from_bind = || {
        options
            .from_line
            .map_or(OracleBind::Null, |line| OracleBind::from(line as i64))
    };
    let to_bind = || {
        options
            .to_line
            .map_or(OracleBind::Null, |line| OracleBind::from(line as i64))
    };
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::GetSource,
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            OracleBind::from(name.to_ascii_uppercase()),
            OracleBind::from(source_type),
            from_bind(),
            from_bind(),
            to_bind(),
            to_bind(),
        ],
    )
    .await?;

    if rows.is_empty()
        && !list_source_types(cx, conn, owner, name)
            .await?
            .iter()
            .any(|visible_type| visible_type == source_type)
    {
        return Err(describe_object_not_found(
            &source_type.to_ascii_lowercase(),
            &owner.to_ascii_uppercase(),
            &name.to_ascii_uppercase(),
        ));
    }

    let cap = options.max_chars.max(1);
    let mut source = String::new();
    let mut char_count = 0usize;
    let mut truncated = false;
    for row in &rows {
        let text = row.text("TEXT").unwrap_or_default();
        let text_chars = text.chars().count();
        if !truncated && char_count.saturating_add(text_chars) <= cap {
            source.push_str(text);
        } else if !truncated {
            let remaining = cap.saturating_sub(char_count);
            source.extend(text.chars().take(remaining));
            truncated = true;
        }
        char_count = char_count.saturating_add(text_chars);
    }

    Ok(SourceText {
        owner: owner.to_ascii_uppercase(),
        name: name.to_ascii_uppercase(),
        object_type: source_type.to_owned(),
        source,
        line_count: rows.len(),
        char_count,
        truncated,
    })
}

/// Return a bounded view definition from the same version-neutral
/// `ALL_VIEWS.TEXT` read used by `describe_view`.
async fn get_view_source(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    options: SourceReadOptions,
) -> Result<SourceText, DbError> {
    let owner = owner.to_ascii_uppercase();
    let name = name.to_ascii_uppercase();
    let row = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::ViewMetadata,
        &[
            OracleBind::from(owner.clone()),
            OracleBind::from(name.clone()),
        ],
    )
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| describe_object_not_found("view", &owner, &name))?;
    let text = row.text("TEXT").ok_or_else(|| {
        DbError::Internal(format!(
            "view {owner}.{name} metadata returned no definition text"
        ))
    })?;
    let lines = text.lines().collect::<Vec<_>>();
    let first = options.from_line.unwrap_or(1).saturating_sub(1);
    let end = options.to_line.unwrap_or(lines.len());
    let selected = if first < end && first < lines.len() {
        &lines[first..end.min(lines.len())]
    } else {
        &[]
    };
    let selected_text = selected.join("\n");
    let char_count = selected_text.chars().count();
    let cap = options.max_chars.max(1);
    let truncated = char_count > cap;
    let source = selected_text.chars().take(cap).collect();

    Ok(SourceText {
        owner,
        name,
        object_type: "VIEW".to_owned(),
        source,
        line_count: selected.len(),
        char_count,
        truncated,
    })
}

/// List visible `ALL_SOURCE.TYPE` variants for one object name.
pub async fn list_source_types(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
) -> Result<Vec<String>, DbError> {
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::SourceTypes,
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            OracleBind::from(name.to_ascii_uppercase()),
        ],
    )
    .await?;
    let mut types = Vec::new();
    for row in rows {
        if let Some(source_type) = row.text("TYPE").and_then(normalize_source_object_type)
            && !types.iter().any(|t| t == source_type)
        {
            types.push(source_type.to_owned());
        }
    }
    Ok(types)
}

/// Full source text for every visible source type for one object name.
pub async fn get_sources_by_name(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    from_line: Option<usize>,
    to_line: Option<usize>,
    max_chars: usize,
) -> Result<Vec<SourceText>, DbError> {
    let mut out = Vec::new();
    for source_type in list_source_types(cx, conn, owner, name).await? {
        out.push(
            get_source(
                cx,
                conn,
                owner,
                name,
                &source_type,
                SourceReadOptions {
                    from_line,
                    to_line,
                    max_chars,
                },
            )
            .await?,
        );
    }
    Ok(out)
}

/// Ordered primary-key column names for one visible table, or an empty list
/// when the relation has no primary key visible to the current user. This is a
/// dictionary read only; owner/table are bound and normalized before lookup.
pub async fn primary_key_columns(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Vec<String>, DbError> {
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::PrimaryKeyColumns,
        &[
            OracleBind::String(owner.to_ascii_uppercase()),
            OracleBind::String(table.to_ascii_uppercase()),
        ],
    )
    .await?;
    Ok(rows
        .iter()
        .filter_map(|row| row.text("COLUMN_NAME").map(str::to_owned))
        .collect())
}

/// Semantic diff between two serialized query pages. With key columns, rows are
/// aligned by that key and value changes are reported as `changed`; without key
/// columns, rows are treated as a multiset and only add/remove can be proven.
///
/// A *side* is one page of the same proven read. The two sides may differ in
/// time (the same database at two SCNs) or in space (two databases in the
/// fleet); the alignment maths is identical either way, so this type carries the
/// side provenance in [`QueryDiff::source_a`] / [`QueryDiff::source_b`] rather
/// than assuming an SCN pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryDiff {
    /// Column names in the compared query shape.
    pub columns: Vec<String>,
    /// Whether `changed` was computed by row key.
    pub keyed: bool,
    /// Key columns used for row alignment, in caller/primary-key order.
    pub key_columns: Vec<String>,
    /// Rows present on side B but not on side A.
    pub added: Vec<serde_json::Value>,
    /// Rows present on side A but not on side B.
    pub removed: Vec<serde_json::Value>,
    /// Key-aligned rows whose non-key payload differs between the two sides.
    pub changed: Vec<QueryDiffChange>,
    /// Rows compared from the first page.
    pub row_count_a: usize,
    /// Rows compared from the second page.
    pub row_count_b: usize,
    /// True when either input page was truncated before all rows were compared.
    pub truncated: bool,
    /// Where side A was read from. Empty unless the caller attaches it with
    /// [`QueryDiff::with_sources`].
    #[serde(default, skip_serializing_if = "QueryDiffSource::is_empty")]
    pub source_a: QueryDiffSource,
    /// Where side B was read from.
    #[serde(default, skip_serializing_if = "QueryDiffSource::is_empty")]
    pub source_b: QueryDiffSource,
}

impl QueryDiff {
    /// Attach the provenance of each compared side. The diff maths never needs
    /// this, but a cross-database delta is not interpretable without it.
    #[must_use]
    pub fn with_sources(mut self, source_a: QueryDiffSource, source_b: QueryDiffSource) -> Self {
        self.source_a = source_a;
        self.source_b = source_b;
        self
    }
}

/// Where one compared side of a [`QueryDiff`] was read from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryDiffSource {
    /// Connection profile the side was read from, for a cross-database diff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// System change number the side was read as of, when it was a flashback
    /// read rather than a read of the current committed state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scn: Option<u64>,
}

impl QueryDiffSource {
    /// A side read from `profile` at its current committed state.
    #[must_use]
    pub fn profile(profile: impl Into<String>) -> Self {
        Self {
            profile: Some(profile.into()),
            scn: None,
        }
    }

    /// A side read as of `scn`.
    #[must_use]
    pub fn scn(scn: u64) -> Self {
        Self {
            profile: None,
            scn: Some(scn),
        }
    }

    /// Pin this side to an SCN as well as a profile.
    #[must_use]
    pub fn at_scn(mut self, scn: Option<u64>) -> Self {
        self.scn = scn;
        self
    }

    #[must_use]
    fn is_empty(&self) -> bool {
        self.profile.is_none() && self.scn.is_none()
    }
}

/// One key-aligned row whose payload differs between the two compared sides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryDiffChange {
    /// The key object that aligned the two rows.
    pub key: serde_json::Value,
    /// Row on side A.
    pub before: serde_json::Value,
    /// Row on side B.
    pub after: serde_json::Value,
}

/// Why a serialized-row diff could not be computed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueryDiffError {
    /// A caller-supplied or inferred key column was not present in every row.
    MissingKeyColumn {
        /// Missing result-column name.
        column: String,
    },
}

impl fmt::Display for QueryDiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryDiffError::MissingKeyColumn { column } => {
                write!(f, "diff key column `{column}` is not present in every row")
            }
        }
    }
}

impl std::error::Error for QueryDiffError {}

#[must_use]
fn response_columns(a: &QueryResponse, b: &QueryResponse) -> Vec<String> {
    if !b.columns.is_empty() {
        b.columns.clone()
    } else {
        a.columns.clone()
    }
}

fn row_cell<'a>(row: &'a serde_json::Value, column: &str) -> Option<&'a serde_json::Value> {
    let object = row.as_object()?;
    object.get(column).or_else(|| {
        object
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(column))
            .map(|(_, v)| v)
    })
}

fn stable_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned())
}

fn row_signature(row: &serde_json::Value, columns: &[String]) -> String {
    let projection = serde_json::Value::Array(
        columns
            .iter()
            .map(|column| {
                serde_json::json!([
                    column,
                    row_cell(row, column)
                        .cloned()
                        .unwrap_or(serde_json::Value::Null)
                ])
            })
            .collect(),
    );
    stable_json(&projection)
}

fn key_value(
    row: &serde_json::Value,
    key_columns: &[String],
) -> Result<serde_json::Value, QueryDiffError> {
    let mut key = serde_json::Map::new();
    for column in key_columns {
        let value = row
            .as_object()
            .and_then(|_| row_cell(row, column))
            .cloned()
            .ok_or_else(|| QueryDiffError::MissingKeyColumn {
                column: column.clone(),
            })?;
        key.insert(column.clone(), value);
    }
    Ok(serde_json::Value::Object(key))
}

fn push_multiset_row(
    rows: &mut BTreeMap<String, VecDeque<serde_json::Value>>,
    row: &serde_json::Value,
    columns: &[String],
) {
    rows.entry(row_signature(row, columns))
        .or_default()
        .push_back(row.clone());
}

fn push_keyed_row(
    rows: &mut BTreeMap<String, VecDeque<(serde_json::Value, serde_json::Value)>>,
    row: &serde_json::Value,
    key_columns: &[String],
) -> Result<(), QueryDiffError> {
    let key = key_value(row, key_columns)?;
    rows.entry(stable_json(&key))
        .or_default()
        .push_back((key, row.clone()));
    Ok(())
}

/// Diff two serialized query responses. Keyed mode aligns by `key_columns` and
/// emits row-level changes; keyless mode treats each side as a multiset of full
/// rows and emits add/remove only.
pub fn diff_query_responses(
    a: &QueryResponse,
    b: &QueryResponse,
    key_columns: &[String],
) -> Result<QueryDiff, QueryDiffError> {
    let columns = response_columns(a, b);
    let keyed = !key_columns.is_empty();
    if !keyed {
        let mut after = BTreeMap::<String, VecDeque<serde_json::Value>>::new();
        for row in &b.rows {
            push_multiset_row(&mut after, row, &columns);
        }

        let mut removed = Vec::new();
        for row in &a.rows {
            let signature = row_signature(row, &columns);
            match after.get_mut(&signature).and_then(VecDeque::pop_front) {
                Some(_) => {}
                None => removed.push(row.clone()),
            }
        }
        let added = after.into_values().flat_map(VecDeque::into_iter).collect();
        return Ok(QueryDiff {
            columns,
            keyed: false,
            key_columns: Vec::new(),
            added,
            removed,
            changed: Vec::new(),
            row_count_a: a.row_count,
            row_count_b: b.row_count,
            truncated: a.truncated || b.truncated,
            source_a: QueryDiffSource::default(),
            source_b: QueryDiffSource::default(),
        });
    }

    let mut after = BTreeMap::<String, VecDeque<(serde_json::Value, serde_json::Value)>>::new();
    for row in &b.rows {
        push_keyed_row(&mut after, row, key_columns)?;
    }

    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for before in &a.rows {
        let key = key_value(before, key_columns)?;
        match after
            .get_mut(&stable_json(&key))
            .and_then(VecDeque::pop_front)
        {
            Some((_, after_row))
                if row_signature(before, &columns) != row_signature(&after_row, &columns) =>
            {
                changed.push(QueryDiffChange {
                    key,
                    before: before.clone(),
                    after: after_row,
                });
            }
            Some(_) => {}
            None => removed.push(before.clone()),
        }
    }
    let added = after
        .into_values()
        .flat_map(VecDeque::into_iter)
        .map(|(_, row)| row)
        .collect();

    Ok(QueryDiff {
        columns,
        keyed: true,
        key_columns: key_columns.to_vec(),
        added,
        removed,
        changed,
        row_count_a: a.row_count,
        row_count_b: b.row_count,
        truncated: a.truncated || b.truncated,
        source_a: QueryDiffSource::default(),
        source_b: QueryDiffSource::default(),
    })
}

/// `explain_plan`: on a primary, `EXPLAIN PLAN` writes into the verified plan
/// table with a unique server-generated statement id and reads that same plan
/// through `DBMS_XPLAN.DISPLAY`; on a read-only standby it is refused (route
/// to `DISPLAY_CURSOR`). `sql` must already have passed the classifier as a
/// vetted SELECT, and callers must separately gate the diagnostic table write.
pub async fn explain_plan(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    table: &VerifiedPlanTable,
    statement_id: &PlanStatementId,
    read_only_standby: bool,
) -> Result<Vec<OracleRow>, DbError> {
    if read_only_standby {
        return Err(DbError::InvalidArgument(
            "EXPLAIN PLAN writes PLAN_TABLE and is disabled on a read-only standby; \
             use SYS.DBMS_XPLAN.DISPLAY_CURSOR against an existing cursor"
                .to_owned(),
        ));
    }
    // Oracle's EXPLAIN PLAN grammar has no bind position for STATEMENT_ID or
    // INTO. Both fragments come from validated server-only capability types;
    // only the caller's already-admitted SELECT remains as SQL text.
    conn.execute(cx, &explain_plan_sql(sql, table, statement_id), &[])
        .await?;
    run_catalog_query(
        cx,
        conn,
        CatalogQueryId::ExplainPlanDisplay,
        &[
            OracleBind::String(table.qualified_name()),
            OracleBind::String(statement_id.as_str().to_owned()),
        ],
    )
    .await
}

fn explain_plan_sql(
    sql: &str,
    table: &VerifiedPlanTable,
    statement_id: &PlanStatementId,
) -> String {
    format!(
        "EXPLAIN PLAN SET STATEMENT_ID = {} INTO {} FOR {sql}",
        statement_id.sql_literal(),
        table.qualified_name()
    )
}

/// Reminder folded into every [`PlanCostEstimate`]: these numbers are the
/// Oracle optimizer's **relative** estimates used to rank candidate plans, not
/// wall-clock timings and not a runtime guarantee.
pub const PLAN_COST_ESTIMATE_NOTE: &str = "cost and cardinality are the Oracle \
optimizer's RELATIVE estimates for ranking candidate plans (derived from the \
current statistics), not wall-clock time and not a guarantee of runtime; any of \
cost/cardinality/bytes may be null when statistics are absent or under RULE-mode \
optimization";

/// The optimizer's estimates for a single `PLAN_TABLE` line.
///
/// `cost`, `cardinality`, and `bytes` are `NUMBER` columns that are `NULL` when
/// the optimizer produced no estimate (missing statistics, or a RULE-mode plan
/// on an ancient database). They are surfaced as `None` — never an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanCostRow {
    /// The `PLAN_TABLE.ID` plan-line number (`0` is the plan root).
    pub id: i64,
    /// Plan operation (`SELECT STATEMENT`, `TABLE ACCESS`, …), when available.
    pub operation: Option<String>,
    /// Operation options (`FULL`, `BY INDEX ROWID`, …), when available.
    pub options: Option<String>,
    /// Referenced object owner, when available.
    pub object_owner: Option<String>,
    /// Referenced object name, when available.
    pub object_name: Option<String>,
    /// Relative optimizer cost for this operation, or `None` when unavailable.
    pub cost: Option<i64>,
    /// Estimated rows this operation produces, or `None` when unavailable.
    pub cardinality: Option<i64>,
    /// Estimated bytes this operation produces, or `None` when unavailable.
    pub bytes: Option<i64>,
    /// Access predicate text reported by Oracle for this plan line, when
    /// available. Callers must sanitize before exposing it to untrusted clients.
    pub access_predicates: Option<String>,
    /// Filter predicate text reported by Oracle for this plan line, when
    /// available. Callers must sanitize before exposing it to untrusted clients.
    pub filter_predicates: Option<String>,
}

/// The plan root (`ID = 0`) totals: the optimizer's estimate for the whole plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanCostSummary {
    /// Total relative optimizer cost of the whole plan (root line; nullable).
    pub total_cost: Option<i64>,
    /// Estimated total rows the plan returns (root line; nullable).
    pub total_cardinality: Option<i64>,
    /// Estimated total bytes the plan returns (root line; nullable).
    pub total_bytes: Option<i64>,
}

/// A structured optimizer cost/cardinality block that accompanies an
/// `EXPLAIN PLAN`, additive to the human-readable `DBMS_XPLAN.DISPLAY` output.
///
/// See [`PLAN_COST_ESTIMATE_NOTE`]: the figures are relative optimizer
/// estimates, not measured runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanCostEstimate {
    /// Per-line estimates, ordered by `PLAN_TABLE.ID`.
    pub rows: Vec<PlanCostRow>,
    /// The plan-root (`ID = 0`) totals.
    pub summary: PlanCostSummary,
    /// Reminder that these are relative optimizer estimates (see
    /// [`PLAN_COST_ESTIMATE_NOTE`]).
    pub note: String,
}

/// The scoped `PLAN_TABLE` read that surfaces per-line optimizer estimates for
/// one server-generated statement id. Concurrent explanations cannot select a
/// different request's plan.
pub(crate) const PLAN_COST_SQL: &str = "SELECT id, operation, options, object_owner, object_name, \
cost, cardinality, bytes, access_predicates, filter_predicates \
FROM SYS.PLAN_TABLE$ \
WHERE statement_id = :1 \
ORDER BY id";

/// Parse an optional `PLAN_TABLE` numeric cell into `Option<i64>`. A SQL `NULL`
/// (or an empty/blank rendering) becomes `None`; a non-integer `NUMBER` is
/// truncated toward zero. Never panics, never errors.
fn plan_cell_i64(cell: Option<&OracleCell>) -> Option<i64> {
    let text = cell.and_then(OracleCell::text)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .parse::<i64>()
        .ok()
        .or_else(|| trimmed.parse::<f64>().ok().map(|value| value as i64))
}

fn plan_cell_text(cell: Option<&OracleCell>) -> Option<String> {
    let trimmed = cell.and_then(OracleCell::text)?.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Assemble a [`PlanCostEstimate`] from `PLAN_TABLE` rows shaped as
/// `id, cost, cardinality, bytes` (case-insensitive column lookup).
///
/// Pure: no I/O, no classifier interaction. `NULL` estimate columns become
/// `None`. Rows whose `ID` cannot be parsed are skipped (defensive; `ID` is
/// `NOT NULL` in a real `PLAN_TABLE`). Returns `None` when no plan-root line
/// (`ID = 0`) is present, so the caller omits the block rather than emitting a
/// summary it cannot ground on the root.
#[must_use]
pub fn assemble_cost_estimate(rows: &[OracleRow]) -> Option<PlanCostEstimate> {
    let mut cost_rows: Vec<PlanCostRow> = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(id) = plan_cell_i64(row.cell("ID")) else {
            continue;
        };
        cost_rows.push(PlanCostRow {
            id,
            operation: plan_cell_text(row.cell("OPERATION")),
            options: plan_cell_text(row.cell("OPTIONS")),
            object_owner: plan_cell_text(row.cell("OBJECT_OWNER")),
            object_name: plan_cell_text(row.cell("OBJECT_NAME")),
            cost: plan_cell_i64(row.cell("COST")),
            cardinality: plan_cell_i64(row.cell("CARDINALITY")),
            bytes: plan_cell_i64(row.cell("BYTES")),
            access_predicates: plan_cell_text(row.cell("ACCESS_PREDICATES")),
            filter_predicates: plan_cell_text(row.cell("FILTER_PREDICATES")),
        });
    }
    let root = cost_rows.iter().find(|row| row.id == 0)?;
    let summary = PlanCostSummary {
        total_cost: root.cost,
        total_cardinality: root.cardinality,
        total_bytes: root.bytes,
    };
    Some(PlanCostEstimate {
        rows: cost_rows,
        summary,
        note: PLAN_COST_ESTIMATE_NOTE.to_owned(),
    })
}

/// Read the optimizer cost/cardinality estimates for the plan identified by
/// the server-generated statement id used by [`explain_plan`]. This is
/// additive/observational — a plain read of
/// `PLAN_TABLE`, gated by the same diagnostic-write permission as the
/// `EXPLAIN PLAN` that produced the rows; it never re-runs the statement and
/// never touches the classifier.
///
/// 11g-safe / graceful degradation: on databases whose `PLAN_TABLE` lacks a
/// cost column (or the table/`statement_id` entirely) the `SELECT` fails; that error
/// is returned so the caller can *omit* the block and note why — the surrounding
/// `EXPLAIN PLAN` output must never be failed by a missing cost estimate.
/// `Ok(None)` means the query ran but produced no scoped plan-root line.
pub async fn plan_cost_estimate(
    cx: &Cx,
    conn: &dyn OracleConnection,
    table: &VerifiedPlanTable,
    statement_id: &PlanStatementId,
) -> Result<Option<PlanCostEstimate>, DbError> {
    // The fixed query ID addresses only Oracle's verified standard table. A
    // configured table can still produce DISPLAY output; its optional numeric
    // cost block is omitted until that table-specific read has a closed query
    // provenance form of its own.
    if !table.is_standard_plan_table() {
        return Ok(None);
    }
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::PlanCostEstimate,
        &[OracleBind::String(statement_id.as_str().to_owned())],
    )
    .await?;
    Ok(assemble_cost_estimate(&rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OracleBackend, OracleCell, OracleConnectionInfo};
    use asupersync::runtime::RuntimeBuilder;

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
    struct CaptureMock {
        calls: std::sync::Mutex<Vec<(String, Vec<OracleBind>)>>,
        data_default_vc_available: bool,
        describe_metadata_available: bool,
        view_text: Option<String>,
        source_types: Vec<String>,
    }

    struct PlanResolverMock {
        info: OracleConnectionInfo,
        local_object: bool,
        private_synonym: bool,
        describe_denied: bool,
        denied_query_fragment: Option<&'static str>,
        configured_object_id: i64,
        duration: &'static str,
        configured_enabled_trigger: bool,
    }

    impl PlanResolverMock {
        fn new(service: String) -> Self {
            Self {
                info: OracleConnectionInfo {
                    current_schema: Some("APP".to_owned()),
                    session_user: Some("APP".to_owned()),
                    db_unique_name: Some("PLAN_TEST_DB".to_owned()),
                    service_name: Some(service),
                    ..OracleConnectionInfo::default()
                },
                local_object: false,
                private_synonym: false,
                describe_denied: false,
                denied_query_fragment: None,
                configured_object_id: 9001,
                duration: "SYS$SESSION",
                configured_enabled_trigger: false,
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for PlanResolverMock {
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
            if self.describe_denied {
                return Err(DbError::ServerQuery(
                    "ORA-01031: insufficient privileges".into(),
                ));
            }
            Ok(self.info.clone())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            if self
                .denied_query_fragment
                .is_some_and(|fragment| sql.contains(fragment))
            {
                return Err(DbError::ServerQuery(
                    "ORA-01031: insufficient privileges".into(),
                ));
            }
            if sql.contains("FROM SYS.all_objects WHERE owner = :1") && self.local_object {
                return Ok(vec![cell_row(&[("OBJECT_TYPE", "TABLE")])]);
            }
            if sql.contains("FROM SYS.all_synonyms WHERE owner = :1") && self.private_synonym {
                return Ok(vec![cell_row(&[
                    ("TABLE_OWNER", "APP"),
                    ("TABLE_NAME", "OTHER"),
                ])]);
            }
            if sql.contains("FROM SYS.all_synonyms WHERE owner = 'PUBLIC'") {
                return Ok(vec![cell_row(&[
                    ("TABLE_OWNER", "SYS"),
                    ("TABLE_NAME", "PLAN_TABLE$"),
                ])]);
            }
            if sql.contains("t.owner = 'SYS'") {
                return Ok(vec![cell_row(&[
                    ("TEMPORARY", "Y"),
                    ("DURATION", self.duration),
                    ("OBJECT_ID", "42"),
                ])]);
            }
            if sql.contains("t.owner = :1") {
                return Ok(vec![cell_row(&[
                    ("TEMPORARY", "Y"),
                    ("DURATION", self.duration),
                    ("OBJECT_ID", &self.configured_object_id.to_string()),
                ])]);
            }
            if sql.contains("FROM SYS.all_triggers") && self.configured_enabled_trigger {
                return Ok(vec![cell_row(&[("TRIGGER_NAME", "PLAN_TABLE_TRIGGER")])]);
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

    fn unique_plan_service() -> String {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "PLAN_TEST_{}",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for CaptureMock {
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
            self.calls
                .lock()
                .expect("capture lock")
                .push((sql.to_owned(), binds.to_vec()));
            let lower_sql = sql.to_ascii_lowercase();
            if self.describe_metadata_available
                && ["all_indexes", "all_triggers", "all_views"]
                    .iter()
                    .any(|marker| lower_sql.contains(marker))
            {
                return Ok(vec![OracleRow { columns: vec![] }]);
            }
            if lower_sql.contains("from sys.all_views") {
                return Ok(self.view_text.as_ref().map_or_else(Vec::new, |text| {
                    vec![OracleRow {
                        columns: vec![(
                            "TEXT".to_owned(),
                            OracleCell::new("VARCHAR2", Some(text.clone())),
                        )],
                    }]
                }));
            }
            if lower_sql.contains("from sys.all_source") && lower_sql.contains("select type") {
                return Ok(self
                    .source_types
                    .iter()
                    .map(|source_type| cell_row(&[("TYPE", source_type)]))
                    .collect());
            }
            if self.data_default_vc_available && sql.contains("column_name = 'DATA_DEFAULT_VC'") {
                Ok(vec![OracleRow { columns: vec![] }])
            } else {
                Ok(vec![])
            }
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

    fn query_response(rows: Vec<serde_json::Value>) -> QueryResponse {
        QueryResponse {
            columns: vec!["ID".to_owned(), "NAME".to_owned(), "QTY".to_owned()],
            row_count: rows.len(),
            rows,
            truncated: false,
            next_cursor: None,
            total_bytes: 0,
            observed_scn: None,
            rls_vpd: None,
            mask_certificate: None,
        }
    }

    #[test]
    fn plan_statement_id_generator_and_validator_are_strict() {
        let mut generated = std::collections::HashSet::new();
        for _ in 0..256 {
            let id = PlanStatementId::generate().expect("OS CSPRNG");
            assert_eq!(id.as_str().len(), 29);
            assert!(id.as_str().starts_with("OMCP_"));
            assert!(
                id.as_str()[5..]
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            );
            assert!(generated.insert(id.as_str().to_owned()));
        }
        assert!(PlanStatementId::parse("OMCP_ABCDEFGHIJKLMNOPQRSTUVWX").is_ok());
        for invalid in [
            "OMCP_abcdefghijklmnopqrstuvwx",
            "OMCP_ABCDEFGHIJKLMNOPQRSTUVWX'",
            "OMCP_ABCDEFGHIJKLMNOPQRSTUVW",
            "NOTOMCPABCDEFGHIJKLMNOPQRSTUVWX",
        ] {
            assert!(PlanStatementId::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn explain_sql_uses_statement_id_literal_and_never_max_plan_id() {
        let table = VerifiedPlanTable::new("SYS", "PLAN_TABLE$", 42);
        let statement_id =
            PlanStatementId::parse("OMCP_ABCDEFGHIJKLMNOPQRSTUVWX").expect("valid id");
        let sql = explain_plan_sql(
            "SELECT employee_id FROM employees WHERE department_id = :1",
            &table,
            &statement_id,
        );
        assert_eq!(
            sql,
            "EXPLAIN PLAN SET STATEMENT_ID = 'OMCP_ABCDEFGHIJKLMNOPQRSTUVWX' INTO SYS.PLAN_TABLE$ FOR SELECT employee_id FROM employees WHERE department_id = :1"
        );
        assert!(!sql.contains("MAX(plan_id)"));
    }

    #[test]
    fn plan_table_local_object_shadow_is_unavailable() {
        let mut mock = PlanResolverMock::new(unique_plan_service());
        mock.local_object = true;
        let result = run_with_cx(|cx| async move { resolve_plan_table(&cx, &mock, None).await });
        assert_eq!(result.unwrap_err().reason(), "callback_unprovable");
    }

    #[test]
    fn plan_table_private_synonym_shadow_is_unavailable() {
        let mut mock = PlanResolverMock::new(unique_plan_service());
        mock.private_synonym = true;
        let result = run_with_cx(|cx| async move { resolve_plan_table(&cx, &mock, None).await });
        assert_eq!(result.unwrap_err().reason(), "callback_unprovable");
    }

    #[test]
    fn plan_table_public_synonym_to_sys_plan_table_is_verified() {
        let mock = PlanResolverMock::new(unique_plan_service());
        let table = run_with_cx(|cx| async move {
            resolve_plan_table(&cx, &mock, None)
                .await
                .expect("verified synonym")
        });
        assert!(table.is_standard_plan_table());
        assert_eq!(table.object_id(), 42);
    }

    #[test]
    fn plan_table_catalog_privilege_gap_uses_fixed_sys_table_with_observation() {
        let mut mock = PlanResolverMock::new(unique_plan_service());
        mock.denied_query_fragment = Some("FROM SYS.all_synonyms WHERE owner = 'PUBLIC'");
        let table = run_with_cx(|cx| async move {
            resolve_plan_table(&cx, &mock, None)
                .await
                .expect("safe fixed SYS table fallback")
        });
        assert!(table.is_standard_plan_table());
        assert_eq!(table.owner(), "SYS");
        assert_eq!(table.name(), "PLAN_TABLE$");
        assert_eq!(table.object_id(), 0);
        assert_eq!(
            table.verification_observation(),
            Some("plan_table_verification_no_privilege_sys_fallback")
        );
    }

    #[test]
    fn plan_table_describe_privilege_gap_uses_fixed_sys_table_with_observation() {
        let mut mock = PlanResolverMock::new(unique_plan_service());
        mock.describe_denied = true;
        let table = run_with_cx(|cx| async move {
            resolve_plan_table(&cx, &mock, None)
                .await
                .expect("safe fixed SYS table fallback")
        });
        assert!(table.is_standard_plan_table());
        assert_eq!(
            table.verification_observation(),
            Some("plan_table_verification_no_privilege_sys_fallback")
        );
    }

    #[test]
    fn configured_plan_table_privilege_gap_names_sys_fallback() {
        let mut mock = PlanResolverMock::new(unique_plan_service());
        mock.denied_query_fragment = Some("FROM SYS.all_tables");
        let table = run_with_cx(|cx| async move {
            resolve_plan_table(&cx, &mock, Some("APP.PLAN_TABLE"))
                .await
                .expect("fixed SYS fallback under R36")
        });
        assert_eq!(table.owner(), "SYS");
        assert_eq!(table.name(), "PLAN_TABLE$");
        assert_eq!(
            table.verification_observation(),
            Some("configured_plan_table_unavailable_sys_fallback")
        );
    }

    #[test]
    fn plan_table_transaction_temporary_table_is_unavailable() {
        let mut mock = PlanResolverMock::new(unique_plan_service());
        mock.duration = "SYS$TRANSACTION";
        let error =
            run_with_cx(
                |cx| async move { resolve_plan_table(&cx, &mock, None).await.unwrap_err() },
            );
        assert_eq!(error.reason(), "callback_unprovable");
    }

    #[test]
    fn configured_plan_table_identity_drift_is_unavailable() {
        let service = unique_plan_service();
        let first = PlanResolverMock::new(service.clone());
        run_with_cx(|cx| async move {
            resolve_plan_table(&cx, &first, Some("APP.PLAN_TABLE"))
                .await
                .expect("first identity pinned");
        });
        let mut replacement = PlanResolverMock::new(service);
        replacement.configured_object_id += 1;
        let error = run_with_cx(|cx| async move {
            resolve_plan_table(&cx, &replacement, Some("APP.PLAN_TABLE"))
                .await
                .unwrap_err()
        });
        assert_eq!(error.reason(), "identity_drift");
    }

    #[test]
    fn configured_plan_table_enabled_trigger_is_unavailable() {
        let mut mock = PlanResolverMock::new(unique_plan_service());
        mock.configured_enabled_trigger = true;
        let error = run_with_cx(|cx| async move {
            resolve_plan_table(&cx, &mock, Some("APP.PLAN_TABLE"))
                .await
                .unwrap_err()
        });
        assert_eq!(error.reason(), "callback_unprovable");
    }

    #[test]
    fn diff_query_responses_aligns_by_key_and_reports_changes() {
        let before = query_response(vec![
            serde_json::json!({ "ID": "1", "NAME": "old", "QTY": "10" }),
            serde_json::json!({ "ID": "2", "NAME": "gone", "QTY": "20" }),
        ]);
        let after = query_response(vec![
            serde_json::json!({ "ID": "1", "NAME": "new", "QTY": "10" }),
            serde_json::json!({ "ID": "3", "NAME": "added", "QTY": "30" }),
        ]);

        let diff = diff_query_responses(&before, &after, &["ID".to_owned()]).expect("diff");

        assert!(diff.keyed);
        assert_eq!(diff.key_columns, vec!["ID"]);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].key, serde_json::json!({ "ID": "1" }));
        assert_eq!(
            diff.removed,
            vec![serde_json::json!({ "ID": "2", "NAME": "gone", "QTY": "20" })]
        );
        assert_eq!(
            diff.added,
            vec![serde_json::json!({ "ID": "3", "NAME": "added", "QTY": "30" })]
        );
    }

    #[test]
    fn diff_query_responses_without_key_reports_multiset_add_remove_only() {
        let before = query_response(vec![
            serde_json::json!({ "ID": "1", "NAME": "same", "QTY": "10" }),
            serde_json::json!({ "ID": "2", "NAME": "old", "QTY": "20" }),
        ]);
        let after = query_response(vec![
            serde_json::json!({ "ID": "1", "NAME": "same", "QTY": "10" }),
            serde_json::json!({ "ID": "2", "NAME": "new", "QTY": "20" }),
        ]);

        let diff = diff_query_responses(&before, &after, &[]).expect("diff");

        assert!(!diff.keyed);
        assert!(diff.changed.is_empty());
        assert_eq!(
            diff.removed,
            vec![serde_json::json!({ "ID": "2", "NAME": "old", "QTY": "20" })]
        );
        assert_eq!(
            diff.added,
            vec![serde_json::json!({ "ID": "2", "NAME": "new", "QTY": "20" })]
        );
    }

    #[test]
    fn diff_query_responses_refuses_missing_key_column() {
        let before = query_response(vec![serde_json::json!({ "ID": "1" })]);
        let after = query_response(vec![serde_json::json!({ "ID": "1" })]);

        let err = diff_query_responses(&before, &after, &["MISSING".to_owned()])
            .expect_err("missing key");

        assert_eq!(
            err,
            QueryDiffError::MissingKeyColumn {
                column: "MISSING".to_owned(),
            }
        );
    }

    #[test]
    fn primary_key_columns_binds_owner_and_table() {
        let conn = CaptureMock::default();
        let conn_ref = &conn;
        run_with_cx(|cx| async move {
            primary_key_columns(&cx, conn_ref, "app", "orders")
                .await
                .expect("pk lookup")
        });
        let (sql, binds) = conn
            .calls
            .lock()
            .expect("calls")
            .first()
            .cloned()
            .expect("one call");

        assert!(sql.contains("all_constraints"));
        assert!(sql.contains("all_cons_columns"));
        assert_eq!(
            binds,
            vec![
                OracleBind::String("APP".to_owned()),
                OracleBind::String("ORDERS".to_owned()),
            ]
        );
    }

    struct SourceMock;

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for SourceMock {
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
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            Ok(vec![
                OracleRow {
                    columns: vec![(
                        "TEXT".to_owned(),
                        OracleCell::new("VARCHAR2", Some("BEGIN\n".to_owned())),
                    )],
                },
                OracleRow {
                    columns: vec![(
                        "TEXT".to_owned(),
                        OracleCell::new("VARCHAR2", Some("  NULL;\nEND;\n".to_owned())),
                    )],
                },
            ])
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

    struct MultiSourceMock;

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for MultiSourceMock {
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
            if sql.contains("SELECT type") {
                assert_eq!(
                    binds,
                    &[
                        OracleBind::String("HR".to_owned()),
                        OracleBind::String("EMP_API".to_owned()),
                    ]
                );
                return Ok(vec![
                    OracleRow {
                        columns: vec![(
                            "TYPE".to_owned(),
                            OracleCell::new("VARCHAR2", Some("PACKAGE".to_owned())),
                        )],
                    },
                    OracleRow {
                        columns: vec![(
                            "TYPE".to_owned(),
                            OracleCell::new("VARCHAR2", Some("PACKAGE BODY".to_owned())),
                        )],
                    },
                ]);
            }

            Ok(vec![OracleRow {
                columns: vec![(
                    "TEXT".to_owned(),
                    OracleCell::new("VARCHAR2", Some("BEGIN NULL; END;\n".to_owned())),
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
    fn identifier_and_type_validation() {
        assert!(is_simple_identifier("HR"));
        assert!(!is_simple_identifier("HR; DROP TABLE t"));
        assert!(is_ddl_object_type("TABLE"));
        assert!(!is_ddl_object_type("table"));
        assert!(is_ddl_object_type("PACKAGE BODY"));
        assert!(!is_ddl_object_type("ANYTHING_ELSE"));
        assert_eq!(normalize_source_object_type("package_body"), None);
        assert_eq!(
            normalize_source_object_type("PACKAGE BODY"),
            Some("PACKAGE BODY")
        );
        assert_eq!(normalize_source_object_type("TYPE BODY"), Some("TYPE BODY"));
        assert_eq!(normalize_source_object_type("TABLE"), None);
    }

    #[test]
    fn semantic_search_query_keeps_values_bound_and_metrics_allowlisted() {
        let query =
            semantic_search_query("hr", "documents", "embedding", SemanticSearchMetric::Cosine)
                .expect("simple identifiers build a bounded semantic query");
        assert_eq!(
            query,
            "SELECT t.* FROM HR.DOCUMENTS t ORDER BY VECTOR_DISTANCE(t.EMBEDDING, :1, COSINE) FETCH FIRST :2 ROWS ONLY"
        );
        assert_eq!(
            SemanticSearchMetric::parse(Some("euclidean")),
            Some(SemanticSearchMetric::Euclidean)
        );
        assert_eq!(SemanticSearchMetric::parse(Some("cosine; DROP")), None);
        assert!(
            semantic_search_query(
                "HR",
                "DOCUMENTS; DROP TABLE DOCUMENTS",
                "EMBEDDING",
                SemanticSearchMetric::Dot,
            )
            .is_err()
        );
    }

    #[test]
    fn semantic_search_hybrid_filter_is_an_identifier_plus_scalar_bind_only() {
        let query = semantic_search_query_with_filter(
            "hr",
            "documents",
            "embedding",
            "tenant_id",
            SemanticSearchMetric::Cosine,
            25,
        )
        .expect("simple identifiers build a bounded hybrid query");
        assert_eq!(
            query,
            "SELECT t.* FROM HR.DOCUMENTS t WHERE t.TENANT_ID = :1 ORDER BY \
             VECTOR_DISTANCE(t.EMBEDDING, :2, COSINE) FETCH FIRST 25 ROWS ONLY"
        );
        assert!(
            semantic_search_query_with_filter(
                "HR",
                "DOCUMENTS",
                "EMBEDDING",
                "tenant_id OR 1=1",
                SemanticSearchMetric::Cosine,
                25,
            )
            .is_err(),
            "a caller cannot widen the predicate with a SQL fragment"
        );
    }

    #[test]
    fn semantic_search_text_query_uses_only_a_dictionary_safe_model_identifier() {
        let query = semantic_search_text_query(
            "hr",
            "documents",
            "embedding",
            "local_onnx_model",
            SemanticSearchMetric::Dot,
        )
        .expect("a dictionary-derived simple model name builds text embedding SQL");
        assert_eq!(
            query,
            "SELECT t.* FROM HR.DOCUMENTS t ORDER BY VECTOR_DISTANCE(t.EMBEDDING, \
             VECTOR_EMBEDDING(LOCAL_ONNX_MODEL USING :1), DOT) FETCH FIRST :2 ROWS ONLY"
        );
        assert!(
            semantic_search_text_query(
                "HR",
                "DOCUMENTS",
                "EMBEDDING",
                "model); DROP TABLE documents",
                SemanticSearchMetric::Cosine,
            )
            .is_err(),
            "a model name cannot inject into the VECTOR_EMBEDDING grammar"
        );
    }

    #[test]
    fn semantic_search_text_hybrid_filter_keeps_the_model_and_value_bound() {
        let query = semantic_search_text_query_with_filter(
            "hr",
            "documents",
            "embedding",
            "local_onnx_model",
            "tenant_id",
            SemanticSearchMetric::Dot,
            25,
        )
        .expect("a dictionary-derived model and simple filter build hybrid SQL");
        assert_eq!(
            query,
            "SELECT t.* FROM HR.DOCUMENTS t WHERE t.TENANT_ID = :1 ORDER BY \
             VECTOR_DISTANCE(t.EMBEDDING, VECTOR_EMBEDDING(LOCAL_ONNX_MODEL USING :2), DOT) \
             FETCH FIRST 25 ROWS ONLY"
        );
    }

    #[test]
    fn list_objects_binds_filters_and_limit() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            list_objects(&cx, m, None, Some("package"), Some("emp%"), 25)
                .await
                .unwrap();
        });

        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].0.contains("SELECT o.owner, o.object_name"),
            "query should include OWNER for cross-schema results"
        );
        assert!(calls[0].0.contains("ROWNUM <= :4"));
        assert!(!calls[0].0.contains("FETCH FIRST :4"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::Null,
                OracleBind::String("PACKAGE".to_owned()),
                OracleBind::String("EMP%".to_owned()),
                OracleBind::I64(25),
            ]
        );
    }

    #[test]
    fn list_objects_page_binds_a_bounded_offset_window() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            list_objects_page(&cx, m, Some("hr"), Some("package"), Some("emp%"), 250, 101)
                .await
                .unwrap();
        });

        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("ROWNUM <= :4"));
        assert!(calls[0].0.contains("page_row > :5"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("PACKAGE".to_owned()),
                OracleBind::String("EMP%".to_owned()),
                OracleBind::I64(351),
                OracleBind::I64(250),
            ]
        );
    }

    #[test]
    fn compact_schema_projection_is_static_and_offset_bounded() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            list_schema_projection_page(&cx, m, Some("hr"), Some("emp%"), 100, 101)
                .await
                .unwrap();
        });

        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0]
                .0
                .contains("o.object_type IN ('TABLE', 'VIEW', 'PACKAGE')")
        );
        assert!(calls[0].0.contains("ROWNUM <= :3"));
        assert!(calls[0].0.contains("page_row > :4"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("EMP%".to_owned()),
                OracleBind::I64(201),
                OracleBind::I64(100),
            ]
        );
    }

    #[test]
    fn list_schemas_binds_filter_and_limit() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            list_schemas(&cx, m, Some("app%"), 100).await.unwrap();
        });

        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("SELECT o.owner AS schema_name"));
        assert!(calls[0].0.contains("COUNT(*) AS object_count"));
        assert!(calls[0].0.contains("ROWNUM <= :2"));
        assert!(!calls[0].0.contains("FETCH FIRST :2"));
        assert_eq!(
            calls[0].1,
            vec![OracleBind::String("APP%".to_owned()), OracleBind::I64(100),]
        );
    }

    #[test]
    fn search_objects_object_types_binds_each_value() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            search_objects_by_types(
                &cx,
                m,
                Some("app"),
                &["TABLE".to_owned(), "VIEW".to_owned()],
                Some("PARENT%"),
                SearchDetailLevel::Names,
                25,
            )
            .await
            .unwrap();
        });
        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0]
                .0
                .contains("o.object_type IN (args.type_1, args.type_2")
        );
        let placeholder_order = calls[0]
            .0
            .split(':')
            .skip(1)
            .filter_map(|tail| {
                let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
                (!digits.is_empty()).then(|| digits.parse::<usize>().expect("numeric bind"))
            })
            .collect::<Vec<_>>();
        assert_eq!(placeholder_order, (1..=16).collect::<Vec<_>>());
        assert_eq!(calls[0].1[0], OracleBind::String("APP".to_owned()));
        assert_eq!(calls[0].1[1], OracleBind::String("TABLE".to_owned()));
        assert_eq!(calls[0].1[2], OracleBind::String("VIEW".to_owned()));
        assert!(
            calls[0].1[3..14]
                .iter()
                .all(|bind| matches!(bind, OracleBind::Null))
        );
        assert_eq!(calls[0].1[14], OracleBind::String("PARENT%".to_owned()));
        assert_eq!(calls[0].1[15], OracleBind::I64(25));
    }

    #[test]
    fn search_source_binds_optional_scope_filters() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            search_source(
                &cx,
                m,
                None,
                "commit",
                Some("PACKAGE BODY"),
                Some("emp%"),
                25,
            )
            .await
            .unwrap();
        });

        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("SELECT s.owner, s.name"));
        assert!(calls[0].0.contains("args.owner_filter IS NULL"));
        assert!(calls[0].0.contains("ROWNUM <= :5"));
        assert!(!calls[0].0.contains("FETCH FIRST :5"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::Null,
                OracleBind::String("PACKAGE BODY".to_owned()),
                OracleBind::String("EMP%".to_owned()),
                OracleBind::String("commit".to_owned()),
                OracleBind::I64(25),
            ]
        );
    }

    #[test]
    fn search_source_rejects_unknown_source_type() {
        let mock = CaptureMock::default();
        let err = run_with_cx(|cx| async move {
            search_source(&cx, &mock, Some("hr"), "commit", Some("table"), None, 25)
                .await
                .expect_err("TABLE is not an ALL_SOURCE type")
        });
        let envelope = err.clone().into_envelope();
        assert_eq!(
            envelope.error_class,
            oraclemcp_error::ErrorClass::InvalidArguments
        );
        assert_eq!(
            envelope.suggested_tool.as_deref(),
            Some("oracle_get_source")
        );
        assert!(err.to_string().contains("unsupported source object type"));
    }

    #[test]
    fn get_source_view_returns_view_text_issue_39() {
        let mock = CaptureMock {
            view_text: Some("SELECT ID, LABEL\nFROM APP.T_PARENT\nWHERE ID > 0".to_owned()),
            ..CaptureMock::default()
        };
        let m = &mock;
        let source = run_with_cx(|cx| async move {
            get_source(
                &cx,
                m,
                "app",
                "parent_view",
                "VIEW",
                SourceReadOptions {
                    from_line: Some(2),
                    to_line: Some(3),
                    max_chars: 100,
                },
            )
            .await
            .unwrap()
        });
        assert_eq!(source.object_type, "VIEW");
        assert_eq!(source.source, "FROM APP.T_PARENT\nWHERE ID > 0");
        assert_eq!(source.line_count, 2);
        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("FROM SYS.all_views"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("APP".to_owned()),
                OracleBind::String("PARENT_VIEW".to_owned()),
            ]
        );
    }

    #[test]
    fn get_source_missing_view_is_object_not_found() {
        let mock = CaptureMock::default();
        let m = &mock;
        let err = run_with_cx(|cx| async move {
            get_source(
                &cx,
                m,
                "hr",
                "view_demo",
                "VIEW",
                SourceReadOptions {
                    from_line: None,
                    to_line: None,
                    max_chars: 100,
                },
            )
            .await
            .expect_err("missing view should not become empty source")
        });
        let envelope = err.into_envelope();
        assert_eq!(
            envelope.error_class,
            oraclemcp_error::ErrorClass::ObjectNotFound
        );
        assert_eq!(
            envelope.suggested_tool.as_deref(),
            Some("oracle_schema_inspect")
        );
        assert_eq!(mock.calls.lock().expect("capture lock").len(), 1);
    }

    #[test]
    fn get_source_missing_all_source_object_is_object_not_found() {
        let mock = CaptureMock::default();
        let m = &mock;
        let err = run_with_cx(|cx| async move {
            get_source(
                &cx,
                m,
                "hr",
                "missing_procedure",
                "PROCEDURE",
                SourceReadOptions {
                    from_line: None,
                    to_line: None,
                    max_chars: 100,
                },
            )
            .await
            .expect_err("missing source object must not become empty success")
        });
        let envelope = err.into_envelope();
        assert_eq!(
            envelope.error_class,
            oraclemcp_error::ErrorClass::ObjectNotFound
        );
        assert_eq!(
            envelope.suggested_tool.as_deref(),
            Some("oracle_schema_inspect")
        );
        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 2, "source read followed by visible-type proof");
        assert!(calls[0].0.contains("FROM SYS.all_source"));
        assert!(calls[1].0.contains("SELECT type"));
        assert_eq!(
            calls[1].1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("MISSING_PROCEDURE".to_owned()),
            ]
        );
    }

    #[test]
    fn get_ddl_unsupported_type_is_invalid_arguments_issue_38() {
        let mock = CaptureMock::default();
        let m = &mock;
        let err = run_with_cx(|cx| async move {
            get_ddl(&cx, m, "DATABASE LINK", "hr", "remote_db")
                .await
                .expect_err("unsupported DDL type must be rejected before SQL")
        });
        let envelope = err.into_envelope();
        assert_eq!(
            envelope.error_class,
            oraclemcp_error::ErrorClass::InvalidArguments
        );
        assert_eq!(envelope.suggested_tool.as_deref(), Some("oracle_get_ddl"));
        assert!(mock.calls.lock().expect("capture lock").is_empty());
    }

    #[test]
    fn get_ddl_uses_text_slice_not_raw_metadata_lob() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            get_ddl(&cx, m, "PACKAGE", "hr", "pkg_demo").await.unwrap();
        });

        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("DBMS_LOB.SUBSTR(ddl, 4000, 1)"));
        assert!(calls[0].0.contains("DBMS_LOB.GETLENGTH(ddl)"));
        assert!(calls[0].0.contains("DBMS_METADATA.GET_DDL(:1, :2, :3)"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("PACKAGE".to_owned()),
                OracleBind::String("PKG_DEMO".to_owned()),
                OracleBind::String("HR".to_owned()),
            ]
        );
    }

    #[test]
    fn get_ddl_space_spelling_maps_to_metadata_body_type() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            get_ddl(&cx, m, "PACKAGE BODY", "hr", "pkg_demo")
                .await
                .unwrap();
        });
        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1[0], OracleBind::String("PACKAGE_BODY".to_owned()));
    }

    #[test]
    fn ddl_prefix_carries_the_full_length_and_never_looks_complete() {
        let row = OracleRow {
            columns: vec![
                (
                    "DDL".to_owned(),
                    OracleCell::new("VARCHAR2", Some("CREATE TABLE T".to_owned())),
                ),
                (
                    "DDL_LENGTH".to_owned(),
                    OracleCell::new("NUMBER", Some("4001".to_owned())),
                ),
            ],
        };

        let ddl = ddl_text_from_row(&row).expect("DDL row converts");
        assert_eq!(ddl.text, "CREATE TABLE T");
        assert_eq!(ddl.char_count, 4_001);
        assert!(
            ddl.truncated,
            "a bounded prefix must carry explicit loss metadata"
        );
    }

    #[test]
    fn describe_index_trigger_and_view_bind_names() {
        let index_mock = CaptureMock {
            describe_metadata_available: true,
            ..CaptureMock::default()
        };
        let im = &index_mock;
        let index =
            run_with_cx(|cx| async move { describe_index(&cx, im, "hr", "emp_ix").await.unwrap() });
        assert!(index.metadata.is_some());
        assert!(index.columns.is_empty());
        assert!(index.expressions.is_empty());
        let calls = index_mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 3);
        assert!(calls[0].0.contains("FROM SYS.all_indexes"));
        assert!(calls[1].0.contains("FROM SYS.all_ind_columns"));
        assert!(calls[2].0.contains("FROM SYS.all_ind_expressions"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("EMP_IX".to_owned()),
            ]
        );
        drop(calls);

        let trigger_mock = CaptureMock {
            describe_metadata_available: true,
            ..CaptureMock::default()
        };
        let tm = &trigger_mock;
        let trigger =
            run_with_cx(
                |cx| async move { describe_trigger(&cx, tm, "hr", "emp_biu").await.unwrap() },
            );
        assert!(trigger.metadata.is_some());
        let calls = trigger_mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("FROM SYS.all_triggers"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("EMP_BIU".to_owned()),
            ]
        );
        drop(calls);

        let view_mock = CaptureMock {
            describe_metadata_available: true,
            ..CaptureMock::default()
        };
        let vm = &view_mock;
        let view =
            run_with_cx(|cx| async move { describe_view(&cx, vm, "hr", "emp_v").await.unwrap() });
        assert!(view.metadata.is_some());
        assert!(view.columns.is_empty());
        let calls = view_mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 3);
        assert!(calls[0].0.contains("FROM SYS.all_views"));
        assert!(calls[1].0.contains("FROM SYS.all_tab_columns"));
        assert!(
            calls[2]
                .0
                .contains("CAST(NULL AS VARCHAR2(4000)) AS data_default")
        );
        assert!(calls[2].0.contains("FROM SYS.all_tab_cols"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("EMP_V".to_owned()),
            ]
        );
        assert_eq!(calls[1].1, vec![]);
        assert_eq!(
            calls[2].1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("EMP_V".to_owned()),
            ]
        );
        drop(calls);

        let modern_mock = CaptureMock {
            data_default_vc_available: true,
            ..CaptureMock::default()
        };
        let mm = &modern_mock;
        run_with_cx(|cx| async move { describe_columns(&cx, mm, "hr", "emp_v").await.unwrap() });
        let calls = modern_mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 2);
        assert!(calls[0].0.contains("FROM SYS.all_tab_columns"));
        assert!(calls[1].0.contains("data_default_vc AS data_default"));
        assert_eq!(calls[0].1, vec![]);
        assert_eq!(
            calls[1].1,
            vec![
                OracleBind::String("hr".to_owned()),
                OracleBind::String("emp_v".to_owned()),
            ]
        );
    }

    #[test]
    fn describe_view_missing_is_object_not_found_issue_43() {
        let conn = CaptureMock::default();
        let conn_ref = &conn;
        let error =
            run_with_cx(
                |cx| async move { describe_view(&cx, conn_ref, "app", "missing_view").await },
            )
            .expect_err("an absent view must not return empty success");

        let envelope = error.into_envelope();
        assert_eq!(
            envelope.error_class,
            oraclemcp_error::ErrorClass::ObjectNotFound
        );
        assert_eq!(
            envelope.suggested_tool.as_deref(),
            Some("oracle_schema_inspect")
        );
        assert!(envelope.message.contains("APP.MISSING_VIEW"));
        let calls = conn.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1, "view absence stops before column lookup");
        assert!(calls[0].0.contains("FROM SYS.all_views"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("APP".to_owned()),
                OracleBind::String("MISSING_VIEW".to_owned()),
            ]
        );
    }

    #[test]
    fn describe_index_missing_is_object_not_found() {
        let conn = CaptureMock::default();
        let error =
            run_with_cx(
                |cx| async move { describe_index(&cx, &conn, "app", "missing_index").await },
            )
            .expect_err("an absent index must not return empty success");

        let envelope = error.into_envelope();
        assert_eq!(
            envelope.error_class,
            oraclemcp_error::ErrorClass::ObjectNotFound
        );
        assert_eq!(
            envelope.suggested_tool.as_deref(),
            Some("oracle_schema_inspect")
        );
    }

    #[test]
    fn describe_trigger_missing_is_object_not_found() {
        let conn = CaptureMock::default();
        let error = run_with_cx(|cx| async move {
            describe_trigger(&cx, &conn, "app", "missing_trigger").await
        })
        .expect_err("an absent trigger must not return empty success");

        let envelope = error.into_envelope();
        assert_eq!(
            envelope.error_class,
            oraclemcp_error::ErrorClass::ObjectNotFound
        );
        assert_eq!(
            envelope.suggested_tool.as_deref(),
            Some("oracle_schema_inspect")
        );
    }

    #[test]
    fn describe_constraints_binds_owner_and_table() {
        let mock = CaptureMock::default();
        let m = &mock;
        let constraints = run_with_cx(|cx| async move {
            describe_constraints(&cx, m, "hr", "employees", 25)
                .await
                .unwrap()
        });
        assert!(constraints.is_empty());
        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("FROM SYS.all_constraints"));
        assert!(calls[0].0.contains("LEFT JOIN SYS.all_cons_columns"));
        assert!(calls[0].0.contains("ROWNUM <= :3"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("hr".to_owned()),
                OracleBind::String("employees".to_owned()),
                OracleBind::I64(25),
            ]
        );
    }

    #[test]
    fn get_source_caps_text_and_reports_metadata() {
        let source = run_with_cx(|cx| async move {
            get_source(
                &cx,
                &SourceMock,
                "hr",
                "emp_api",
                "PACKAGE BODY",
                SourceReadOptions {
                    from_line: None,
                    to_line: None,
                    max_chars: 8,
                },
            )
            .await
            .unwrap()
        });
        assert_eq!(source.owner, "HR");
        assert_eq!(source.name, "EMP_API");
        assert_eq!(source.object_type, "PACKAGE BODY");
        assert_eq!(source.line_count, 2);
        assert_eq!(source.char_count, "BEGIN\n  NULL;\nEND;\n".chars().count());
        assert_eq!(source.source, "BEGIN\n  ");
        assert!(source.truncated);
    }

    #[test]
    fn get_source_range_binds_inclusive_line_bounds() {
        let conn = CaptureMock {
            source_types: vec!["PACKAGE BODY".to_owned()],
            ..CaptureMock::default()
        };
        let conn_ref = &conn;
        run_with_cx(|cx| async move {
            get_source(
                &cx,
                conn_ref,
                "hr",
                "emp_api",
                "PACKAGE BODY",
                SourceReadOptions {
                    from_line: Some(37),
                    to_line: Some(42),
                    max_chars: 1_000,
                },
            )
            .await
            .expect("range lookup succeeds")
        });
        let (sql, binds) = conn
            .calls
            .lock()
            .expect("calls")
            .first()
            .cloned()
            .expect("one source query");
        // Each bound is tested and compared through its OWN placeholder. The
        // earlier `(:4 IS NULL OR line >= :4)` spelling looked economical and
        // was a bug: the driver binds per occurrence, so it declared seven
        // slots against five values and Oracle refused every call with
        // ORA-01008. This assertion pinned the SQL text but not the agreement
        // between the text and the bind vector, which is the pair that has to
        // hold; tests/positional_bind_shape.rs now enforces it crate-wide.
        assert!(sql.contains("(:4 IS NULL OR line >= :5)"));
        assert!(sql.contains("(:6 IS NULL OR line <= :7)"));
        assert_eq!(
            binds,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("EMP_API".to_owned()),
                OracleBind::String("PACKAGE BODY".to_owned()),
                OracleBind::I64(37),
                OracleBind::I64(37),
                OracleBind::I64(42),
                OracleBind::I64(42),
            ]
        );
    }

    #[test]
    fn get_sources_by_name_lists_source_types_and_fetches_each() {
        let sources = run_with_cx(|cx| async move {
            get_sources_by_name(&cx, &MultiSourceMock, "hr", "emp_api", None, None, 64)
                .await
                .unwrap()
        });
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].object_type, "PACKAGE");
        assert_eq!(sources[1].object_type, "PACKAGE BODY");
        assert_eq!(sources[0].owner, "HR");
        assert_eq!(sources[0].name, "EMP_API");
        assert_eq!(sources[0].source, "BEGIN NULL; END;\n");
    }

    #[test]
    fn server_read_sql_builders_validate_every_identifier_and_bind_values() {
        let sample = crate::query::sample_rows_sql("hr", "docs").expect("valid relation");
        assert_eq!(
            sample,
            "SELECT * FROM (SELECT * FROM HR.DOCS) WHERE ROWNUM <= (:1 + 1)"
        );
        assert!(crate::query::sample_rows_sql("hr", "docs;drop").is_err());

        let lob =
            crate::query::read_lob_sql("hr", "docs", "body", "id").expect("valid column and key");
        assert_eq!(
            lob,
            "SELECT BODY FROM HR.DOCS WHERE ID = :1 FETCH FIRST 1 ROW ONLY"
        );
        for names in [
            ["hr;drop", "docs", "body", "id"],
            ["hr", "docs;drop", "body", "id"],
            ["hr", "docs", "body;drop", "id"],
            ["hr", "docs", "body", "id;drop"],
        ] {
            assert!(crate::query::read_lob_sql(names[0], names[1], names[2], names[3]).is_err());
        }
    }

    /// A scripted mock for [`search_objects`] (E4): returns SQL-shape-dependent
    /// rows and records every SQL it sees, so the test can prove the summary
    /// uses ALL_TABLES.NUM_ROWS and never COUNT(*) over the table's data.
    struct SearchObjectsMock {
        seen_sql: std::sync::Mutex<Vec<String>>,
        /// Optional STALE_STATS value returned by all_tab_statistics.
        stale: Option<&'static str>,
    }

    impl SearchObjectsMock {
        fn new(stale: Option<&'static str>) -> Self {
            Self {
                seen_sql: std::sync::Mutex::new(Vec::new()),
                stale,
            }
        }
    }

    fn cell_row(pairs: &[(&str, &str)]) -> OracleRow {
        OracleRow {
            columns: pairs
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

    /// Synthetic `ALL_OBJECTS` and FK-topology rows for the C2.1 orient
    /// contract. It also retains the generated SQL and positional binds so the
    /// test proves the dictionary reads stay bounded and parameterized.
    #[derive(Default)]
    struct OrientMock {
        calls: std::sync::Mutex<Vec<(String, Vec<OracleBind>)>>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for OrientMock {
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
            self.calls
                .lock()
                .expect("orient mock lock")
                .push((sql.to_owned(), binds.to_vec()));

            if sql.contains("o.last_ddl_time DESC") {
                return Ok(vec![
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "ORDER_REPORT"),
                        ("OBJECT_TYPE", "VIEW"),
                        ("LAST_DDL_TIME", "2026-07-13T12:05:00"),
                    ]),
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "ORDERS"),
                        ("OBJECT_TYPE", "TABLE"),
                        ("LAST_DDL_TIME", "2026-07-13T12:00:00"),
                    ]),
                ]);
            }

            if sql.contains("FROM SYS.all_objects") {
                return Ok(vec![
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "CUSTOMERS"),
                        ("OBJECT_TYPE", "TABLE"),
                    ]),
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "ORDERS"),
                        ("OBJECT_TYPE", "TABLE"),
                    ]),
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "ORDER_REPORT"),
                        ("OBJECT_TYPE", "VIEW"),
                    ]),
                ]);
            }

            if sql.contains("FROM SYS.all_tab_modifications") {
                return Ok(vec![
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "ORDERS"),
                        ("INSERTS", "12"),
                        ("UPDATES", "4"),
                        ("DELETES", "1"),
                        ("LAST_MODIFIED", "2026-07-13T12:00:00"),
                        ("TRUNCATED", "NO"),
                        ("DROP_SEGMENTS", "0"),
                    ]),
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "ARCHIVE"),
                        ("INSERTS", "0"),
                        ("UPDATES", "0"),
                        ("DELETES", "0"),
                        ("LAST_MODIFIED", "2026-07-13T11:00:00"),
                        ("TRUNCATED", "YES"),
                        ("DROP_SEGMENTS", "1"),
                    ]),
                ]);
            }

            assert!(sql.contains("FROM SYS.all_constraints child"));
            Ok(vec![
                cell_row(&[
                    ("CHILD_OWNER", "HR"),
                    ("CHILD_TABLE", "ORDER_LINES"),
                    ("CONSTRAINT_NAME", "ORDER_LINES_ORDER_FK"),
                    ("PARENT_OWNER", "HR"),
                    ("PARENT_TABLE", "ORDERS"),
                    ("CHILD_COLUMN", "ORDER_ID"),
                    ("PARENT_COLUMN", "ID"),
                    ("COLUMN_POSITION", "1"),
                ]),
                cell_row(&[
                    ("CHILD_OWNER", "HR"),
                    ("CHILD_TABLE", "ORDER_LINES"),
                    ("CONSTRAINT_NAME", "ORDER_LINES_ORDER_FK"),
                    ("PARENT_OWNER", "HR"),
                    ("PARENT_TABLE", "ORDERS"),
                    ("CHILD_COLUMN", "ORDER_REGION"),
                    ("PARENT_COLUMN", "REGION"),
                    ("COLUMN_POSITION", "2"),
                ]),
            ])
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
    fn orient_schema_and_fks_return_bounded_synthetic_topology() {
        let mock = OrientMock::default();
        let conn = &mock;
        let (schema, foreign_keys) = run_with_cx(|cx| async move {
            let schema = orient_schema(&cx, conn, Some("hr"), 25)
                .await
                .expect("schema map");
            let foreign_keys = orient_fks(&cx, conn, Some("hr"), 1)
                .await
                .expect("foreign-key topology");
            (schema, foreign_keys)
        });

        assert_eq!(
            schema,
            vec![
                OrientSchemaObject {
                    owner: "HR".to_owned(),
                    object_name: "CUSTOMERS".to_owned(),
                    object_type: "TABLE".to_owned(),
                },
                OrientSchemaObject {
                    owner: "HR".to_owned(),
                    object_name: "ORDERS".to_owned(),
                    object_type: "TABLE".to_owned(),
                },
                OrientSchemaObject {
                    owner: "HR".to_owned(),
                    object_name: "ORDER_REPORT".to_owned(),
                    object_type: "VIEW".to_owned(),
                },
            ]
        );
        assert_eq!(foreign_keys.len(), 1, "one capped FK edge");
        assert_eq!(foreign_keys[0].constraint_name, "ORDER_LINES_ORDER_FK");
        assert_eq!(foreign_keys[0].child_owner, "HR");
        assert_eq!(foreign_keys[0].child_table, "ORDER_LINES");
        assert_eq!(foreign_keys[0].parent_owner, "HR");
        assert_eq!(foreign_keys[0].parent_table, "ORDERS");
        assert_eq!(
            foreign_keys[0].columns,
            vec![
                OrientForeignKeyColumn {
                    position: 1,
                    child_column: "ORDER_ID".to_owned(),
                    parent_column: "ID".to_owned(),
                },
                OrientForeignKeyColumn {
                    position: 2,
                    child_column: "ORDER_REGION".to_owned(),
                    parent_column: "REGION".to_owned(),
                },
            ],
            "the cap is on constraints, so a composite FK remains complete"
        );

        let calls = mock.calls.lock().expect("orient mock lock");
        assert_eq!(
            calls.len(),
            2,
            "schema map and FK topology are separate reads"
        );
        let schema_call = calls
            .iter()
            .find(|(sql, _)| sql.contains("FROM SYS.all_objects"))
            .expect("ALL_OBJECTS schema-map read");
        assert!(schema_call.0.contains("ROWNUM <= :2"));
        assert!(schema_call.0.contains("page_row > :3"));
        assert_eq!(
            schema_call.1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::I64(25),
                OracleBind::I64(0),
            ],
            "schema owner, cap, and zero offset are normalized positional binds"
        );

        let fk_call = calls
            .iter()
            .find(|(sql, _)| sql.contains("FROM SYS.all_constraints child"))
            .expect("ALL_CONSTRAINTS FK read");
        assert!(fk_call.0.contains("JOIN SYS.all_constraints parent"));
        assert!(
            fk_call
                .0
                .contains("JOIN SYS.all_cons_columns child_columns")
        );
        assert!(
            fk_call
                .0
                .contains("JOIN SYS.all_cons_columns parent_columns")
        );
        assert!(fk_call.0.contains("page_row > :3"));
        assert!(
            fk_call
                .0
                .contains("parent_columns.position = child_columns.position"),
            "child and parent columns must be joined by their key position"
        );
        assert!(fk_call.0.contains("ROWNUM <= :2"));
        assert_eq!(
            fk_call.1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::I64(1),
                OracleBind::I64(0),
            ],
            "FK owner, cap, and zero offset are positional binds"
        );
    }

    #[test]
    fn orient_hot_objects_reports_dml_activity_and_freshness_with_bound_scope() {
        let mock = OrientMock::default();
        let conn = &mock;
        let objects = run_with_cx(|cx| async move {
            orient_hot_objects(&cx, conn, Some("hr"), 10)
                .await
                .expect("hot-object activity")
        });

        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].owner, "HR");
        assert_eq!(objects[0].object_name, "ORDERS");
        assert_eq!(objects[0].object_type, "TABLE");
        assert_eq!(objects[0].inserts, 12);
        assert_eq!(objects[0].updates, 4);
        assert_eq!(objects[0].deletes, 1);
        assert_eq!(objects[0].changes_since_last_stats, 17);
        assert_eq!(
            objects[0].last_modified.as_deref(),
            Some("2026-07-13T12:00:00")
        );
        assert!(!objects[0].truncated);
        assert_eq!(objects[0].drop_segments, 0);

        assert_eq!(objects[1].object_name, "ARCHIVE");
        assert_eq!(objects[1].changes_since_last_stats, 0);
        assert!(objects[1].truncated, "truncate is freshness evidence");
        assert_eq!(objects[1].drop_segments, 1);

        let calls = mock.calls.lock().expect("orient mock lock");
        let activity_call = calls
            .iter()
            .find(|(sql, _)| sql.contains("FROM SYS.all_tab_modifications"))
            .expect("ALL_TAB_MODIFICATIONS activity read");
        assert!(activity_call.0.contains("ROWNUM <= :2"));
        assert!(activity_call.0.contains("page_row > :3"));
        assert!(activity_call.0.contains("partition_name IS NULL"));
        assert!(activity_call.0.contains("subpartition_name IS NULL"));
        assert!(
            activity_call
                .0
                .contains("ORDER BY (NVL(modifications.inserts, 0)"),
            "hot objects must order by accumulated DML volume"
        );
        assert_eq!(
            activity_call.1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::I64(10),
                OracleBind::I64(0),
            ],
            "owner, cap, and zero offset are normalized positional binds"
        );
    }

    #[test]
    fn orient_recent_ddl_is_bounded_parameterized_and_newest_first() {
        let mock = OrientMock::default();
        let conn = &mock;
        let objects = run_with_cx(|cx| async move {
            orient_recent_ddl(&cx, conn, Some("hr"), 10)
                .await
                .expect("recent DDL feed")
        });

        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].owner, "HR");
        assert_eq!(objects[0].object_name, "ORDER_REPORT");
        assert_eq!(objects[0].object_type, "VIEW");
        assert_eq!(
            objects[0].last_ddl_time.as_deref(),
            Some("2026-07-13T12:05:00"),
            "newest dictionary DDL evidence is retained"
        );
        assert_eq!(objects[1].object_name, "ORDERS");

        let calls = mock.calls.lock().expect("orient mock lock");
        let recent_ddl_call = calls
            .iter()
            .find(|(sql, _)| sql.contains("o.last_ddl_time DESC"))
            .expect("ALL_OBJECTS recent-DDL read");
        assert!(recent_ddl_call.0.contains("FROM SYS.all_objects"));
        assert!(recent_ddl_call.0.contains("o.last_ddl_time DESC"));
        assert!(recent_ddl_call.0.contains("ROWNUM <= :2"));
        assert!(recent_ddl_call.0.contains("page_row > :3"));
        assert_eq!(
            recent_ddl_call.1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::I64(10),
                OracleBind::I64(0),
            ],
            "owner, cap, and zero offset are normalized positional binds"
        );
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for SearchObjectsMock {
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
            self.seen_sql.lock().unwrap().push(sql.to_owned());
            if sql.contains("FROM SYS.all_objects") {
                // Two objects: a table and a view. (Quoted-identifier case: the
                // dictionary stores the exact case, so "MixedCase" round-trips.)
                return Ok(vec![
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "EMPLOYEES"),
                        ("OBJECT_TYPE", "TABLE"),
                        ("STATUS", "VALID"),
                    ]),
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "MixedCase"),
                        ("OBJECT_TYPE", "VIEW"),
                        ("STATUS", "VALID"),
                    ]),
                ]);
            }
            if sql.contains("all_col_comments") {
                return Ok(vec![cell_row(&[
                    ("COLUMN_NAME", "ID"),
                    ("DATA_TYPE", "NUMBER"),
                    ("NULLABLE", "N"),
                    ("COMMENTS", "primary key"),
                ])]);
            }
            if sql.contains("FROM SYS.all_tables") {
                return Ok(vec![cell_row(&[
                    ("NUM_ROWS", "1234"),
                    ("LAST_ANALYZED", "2026-01-01T00:00:00"),
                ])]);
            }
            if sql.contains("all_tab_statistics") {
                return Ok(self
                    .stale
                    .map(|value| cell_row(&[("STALE_STATS", value)]))
                    .into_iter()
                    .collect());
            }
            if sql.contains("FROM SYS.all_tab_columns") {
                // Column count query.
                return Ok(vec![cell_row(&[("COLUMN_COUNT", "3")])]);
            }
            if sql.contains("all_tab_comments") {
                return Ok(vec![cell_row(&[("COMMENTS", "the employees table")])]);
            }
            if sql.contains("all_ind_columns") {
                return Ok(vec![cell_row(&[("COLUMN_NAME", "ID")])]);
            }
            if sql.contains("FROM SYS.all_indexes") {
                return Ok(vec![cell_row(&[
                    ("INDEX_NAME", "EMP_PK"),
                    ("UNIQUENESS", "UNIQUE"),
                ])]);
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

    #[test]
    fn search_detail_level_parses_and_defaults_to_standard() {
        assert_eq!(
            SearchDetailLevel::parse(None),
            Some(SearchDetailLevel::Standard)
        );
        assert_eq!(
            SearchDetailLevel::parse(Some("")),
            Some(SearchDetailLevel::Standard)
        );
        assert_eq!(
            SearchDetailLevel::parse(Some("Summary")),
            Some(SearchDetailLevel::Summary)
        );
        assert_eq!(
            SearchDetailLevel::parse(Some(" NAMES ")),
            Some(SearchDetailLevel::Names)
        );
        assert_eq!(
            SearchDetailLevel::parse(Some("full")),
            Some(SearchDetailLevel::Full)
        );
        assert_eq!(SearchDetailLevel::parse(Some("bogus")), None);
    }

    #[test]
    fn search_objects_summary_uses_all_tables_num_rows_not_count_star() {
        let mock = SearchObjectsMock::new(None);
        let m = &mock;
        let results = run_with_cx(|cx| async move {
            search_objects(
                &cx,
                m,
                Some("HR"),
                None,
                None,
                SearchDetailLevel::Summary,
                100,
            )
            .await
            .unwrap()
        });

        // Two objects (table + view). The TABLE carries the optimizer estimate;
        // the VIEW does not (no ALL_TABLES row).
        assert_eq!(results.len(), 2);
        let table = &results[0];
        assert_eq!(table.object_name, "EMPLOYEES");
        assert_eq!(table.num_rows, Some(1234));
        assert_eq!(table.row_count_is_estimate, Some(true));
        assert_eq!(table.last_analyzed.as_deref(), Some("2026-01-01T00:00:00"));
        assert_eq!(table.column_count, Some(3));
        assert_eq!(table.comment.as_deref(), Some("the employees table"));
        // Summary stops before the column list / indexes.
        assert!(table.columns.is_none());
        assert!(table.indexes.is_none());

        // Quoted/case-sensitive identifier is preserved verbatim.
        assert_eq!(results[1].object_name, "MixedCase");

        // The load-bearing AC: the row count came from ALL_TABLES.NUM_ROWS, and
        // we NEVER issued a COUNT(*) over the table's data.
        let seen = mock.seen_sql.lock().unwrap();
        assert!(
            seen.iter()
                .any(|sql| sql.contains("num_rows") && sql.contains("all_tables")),
            "summary must read ALL_TABLES.NUM_ROWS: {seen:?}"
        );
        assert!(
            !seen.iter().any(|sql| {
                let lower = sql.to_ascii_lowercase();
                lower.contains("count(*) from hr")
                    || lower.contains("count(*) from \"hr\"")
                    || (lower.contains("count(*)") && lower.contains("employees"))
            }),
            "summary must NOT COUNT(*) the table's data: {seen:?}"
        );
    }

    #[test]
    fn search_objects_summary_flags_stale_stats() {
        // Stale-stats case: ALL_TAB_STATISTICS.STALE_STATS = 'YES' so the
        // optimizer estimate must be flagged untrustworthy.
        let mock = SearchObjectsMock::new(Some("YES"));
        let m = &mock;
        let results = run_with_cx(|cx| async move {
            search_objects(
                &cx,
                m,
                Some("HR"),
                Some("TABLE"),
                None,
                SearchDetailLevel::Summary,
                100,
            )
            .await
            .unwrap()
        });
        let table = results.iter().find(|o| o.object_type == "TABLE").unwrap();
        assert_eq!(table.num_rows, Some(1234));
        assert_eq!(
            table.stats_stale,
            Some(true),
            "STALE_STATS=YES must surface stats_stale=true so the estimate is not trusted"
        );
    }

    #[test]
    fn search_objects_names_level_is_identifiers_only() {
        let mock = SearchObjectsMock::new(None);
        let m = &mock;
        let results = run_with_cx(|cx| async move {
            search_objects(
                &cx,
                m,
                Some("HR"),
                None,
                None,
                SearchDetailLevel::Names,
                100,
            )
            .await
            .unwrap()
        });
        assert_eq!(results.len(), 2);
        let table = &results[0];
        assert!(table.num_rows.is_none());
        assert!(table.column_count.is_none());
        assert!(table.comment.is_none());
        assert!(table.columns.is_none());
        assert!(table.indexes.is_none());
        // Names level only touches ALL_OBJECTS — no ALL_TABLES read at all.
        let seen = mock.seen_sql.lock().unwrap();
        assert!(
            !seen.iter().any(|sql| sql.contains("all_tables")),
            "names level must not read optimizer stats: {seen:?}"
        );
    }

    #[test]
    fn search_objects_full_level_adds_columns_and_indexes() {
        let mock = SearchObjectsMock::new(None);
        let m = &mock;
        let results = run_with_cx(|cx| async move {
            search_objects(
                &cx,
                m,
                Some("HR"),
                Some("TABLE"),
                None,
                SearchDetailLevel::Full,
                100,
            )
            .await
            .unwrap()
        });
        let table = results.iter().find(|o| o.object_type == "TABLE").unwrap();
        let columns = table.columns.as_ref().expect("full includes columns");
        assert_eq!(columns[0].name, "ID");
        assert_eq!(columns[0].comment.as_deref(), Some("primary key"));
        let indexes = table.indexes.as_ref().expect("full includes indexes");
        assert_eq!(indexes[0].name, "EMP_PK");
        assert_eq!(indexes[0].uniqueness.as_deref(), Some("UNIQUE"));
        assert_eq!(indexes[0].columns, vec!["ID".to_owned()]);
    }

    /// Build a `PLAN_TABLE` row with the four cost columns; a `None` value
    /// models a SQL `NULL` (no-stats / RULE-mode) for that column.
    fn plan_row(
        id: Option<&str>,
        cost: Option<&str>,
        cardinality: Option<&str>,
        bytes: Option<&str>,
    ) -> OracleRow {
        OracleRow {
            columns: vec![
                (
                    "ID".to_owned(),
                    OracleCell::new("NUMBER", id.map(str::to_owned)),
                ),
                (
                    "COST".to_owned(),
                    OracleCell::new("NUMBER", cost.map(str::to_owned)),
                ),
                (
                    "CARDINALITY".to_owned(),
                    OracleCell::new("NUMBER", cardinality.map(str::to_owned)),
                ),
                (
                    "BYTES".to_owned(),
                    OracleCell::new("NUMBER", bytes.map(str::to_owned)),
                ),
            ],
        }
    }

    #[test]
    fn cost_estimate_assembles_rows_and_root_summary() {
        // A tiny two-line plan: root (id=0) then a full-scan child (id=1).
        let rows = vec![
            plan_row(Some("0"), Some("842"), Some("100000"), Some("2400000")),
            plan_row(Some("1"), Some("842"), Some("100000"), Some("2400000")),
        ];
        let estimate = assemble_cost_estimate(&rows).expect("root line present");
        assert_eq!(estimate.rows.len(), 2);
        assert_eq!(estimate.rows[0].id, 0);
        assert_eq!(estimate.rows[0].cost, Some(842));
        assert_eq!(estimate.rows[0].cardinality, Some(100_000));
        assert_eq!(estimate.rows[0].bytes, Some(2_400_000));
        // Summary mirrors the id=0 root line.
        assert_eq!(estimate.summary.total_cost, Some(842));
        assert_eq!(estimate.summary.total_cardinality, Some(100_000));
        assert_eq!(estimate.summary.total_bytes, Some(2_400_000));
        assert_eq!(estimate.note, PLAN_COST_ESTIMATE_NOTE);
    }

    #[test]
    fn cost_estimate_carries_plan_metadata_and_predicates() {
        let rows = vec![
            plan_row(Some("0"), Some("842"), Some("100000"), Some("2400000")),
            OracleRow {
                columns: vec![
                    (
                        "ID".to_owned(),
                        OracleCell::new("NUMBER", Some("1".to_owned())),
                    ),
                    (
                        "OPERATION".to_owned(),
                        OracleCell::new("VARCHAR2", Some("TABLE ACCESS".to_owned())),
                    ),
                    (
                        "OPTIONS".to_owned(),
                        OracleCell::new("VARCHAR2", Some("FULL".to_owned())),
                    ),
                    (
                        "OBJECT_OWNER".to_owned(),
                        OracleCell::new("VARCHAR2", Some("APP".to_owned())),
                    ),
                    (
                        "OBJECT_NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("ORDERS".to_owned())),
                    ),
                    (
                        "COST".to_owned(),
                        OracleCell::new("NUMBER", Some("842".to_owned())),
                    ),
                    (
                        "CARDINALITY".to_owned(),
                        OracleCell::new("NUMBER", Some("100000".to_owned())),
                    ),
                    (
                        "BYTES".to_owned(),
                        OracleCell::new("NUMBER", Some("2400000".to_owned())),
                    ),
                    (
                        "ACCESS_PREDICATES".to_owned(),
                        OracleCell::new("VARCHAR2", Some("\"ID\"=:B1".to_owned())),
                    ),
                    (
                        "FILTER_PREDICATES".to_owned(),
                        OracleCell::new("VARCHAR2", Some("\"STATUS\"='OPEN'".to_owned())),
                    ),
                ],
            },
        ];

        let estimate = assemble_cost_estimate(&rows).expect("root line present");
        assert_eq!(estimate.rows[1].operation.as_deref(), Some("TABLE ACCESS"));
        assert_eq!(estimate.rows[1].options.as_deref(), Some("FULL"));
        assert_eq!(estimate.rows[1].object_owner.as_deref(), Some("APP"));
        assert_eq!(estimate.rows[1].object_name.as_deref(), Some("ORDERS"));
        assert_eq!(
            estimate.rows[1].access_predicates.as_deref(),
            Some("\"ID\"=:B1")
        );
        assert_eq!(
            estimate.rows[1].filter_predicates.as_deref(),
            Some("\"STATUS\"='OPEN'")
        );
    }

    #[test]
    fn cost_estimate_emits_null_for_missing_estimates() {
        // 11g / RULE-mode / no-stats: cost, cardinality, bytes come back NULL.
        // They must surface as None (never an error), and the summary stays
        // grounded on the id=0 root even when its estimates are null.
        let rows = vec![
            plan_row(Some("0"), None, None, None),
            plan_row(Some("1"), None, Some("14"), None),
        ];
        let estimate = assemble_cost_estimate(&rows).expect("root line present");
        assert_eq!(estimate.rows[0].cost, None);
        assert_eq!(estimate.rows[0].cardinality, None);
        assert_eq!(estimate.rows[0].bytes, None);
        assert_eq!(estimate.rows[1].cardinality, Some(14));
        assert_eq!(estimate.summary.total_cost, None);
        assert_eq!(estimate.summary.total_cardinality, None);
        assert_eq!(estimate.summary.total_bytes, None);
    }

    #[test]
    fn cost_estimate_handles_blank_and_non_integer_cells() {
        // A blank rendering is treated as NULL; a non-integer NUMBER truncates.
        let rows = vec![plan_row(Some("0"), Some("   "), Some("12.9"), Some("500"))];
        let estimate = assemble_cost_estimate(&rows).expect("root line present");
        assert_eq!(estimate.rows[0].cost, None);
        assert_eq!(estimate.rows[0].cardinality, Some(12));
        assert_eq!(estimate.rows[0].bytes, Some(500));
    }

    #[test]
    fn cost_estimate_omitted_when_no_root_line() {
        // Rows without an id=0 root (degenerate) yield no block, so the caller
        // omits cost_estimate rather than fabricate a summary.
        let rows = vec![plan_row(Some("2"), Some("5"), Some("1"), Some("10"))];
        assert!(assemble_cost_estimate(&rows).is_none());
        // Empty PLAN_TABLE read → no block.
        assert!(assemble_cost_estimate(&[]).is_none());
    }
}
