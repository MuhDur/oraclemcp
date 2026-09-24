//! Scoped grants: least privilege at statement-shape granularity (W13 seam).
//!
//! Instead of raising a whole session to `READ_WRITE`, an agent asks for exactly
//! the shape it needs — "UPDATE `APP.ORDERS` column `STATUS` where `ID IN (101,
//! 102, 103)`, at most 5 rows per statement, 20 statements, 10 minutes" — and the
//! guard enforces that shape on every statement. The 0.12 contract covers
//! single-target `UPDATE` and `DELETE` only.
//!
//! This module is the owning seam: the grant data model, its canonical encoding,
//! the three-part keyed scope digest, the lifecycle store ([`ScopedGrantStore`])
//! and the signed client reference ([`SignedGrantRef`]). Predicate parsing,
//! scope matching, closure admission, reservation accounting and the tool are
//! other beads; they build on these types and never bypass them.
//!
//! **Honesty.** Like the single-use execution grant ([`crate::exec_grant`]), a
//! scoped grant is least-privilege *friction* plus an audit artifact. Without
//! step-up delivery configured the agent confirms its own grants, so nothing
//! here claims a human approved anything. The value holds either way: a
//! confused or compromised agent can do far less with a narrow grant than with
//! a session-wide level.
//!
//! **Invariants enforced at construction** ([`ScopedGrant::new`]): protected
//! profiles hold no grants; `READ_WRITE` never exceeds the profile `max_level`
//! or the OAuth ceiling; verbs are a subset of {UPDATE, DELETE}; TTL is in
//! `(0, 3600 s]`; UPDATE names the columns it may SET and DELETE names none; a
//! grant never SETs a column its own predicate filters on; limits are non-zero
//! and coherent; `required_level` is always `READ_WRITE`.
//!
//! **Digest split** (round-5 High finding). A plain SHA-256 over the whole scope
//! would let anyone holding an audited digest enumerate low-entropy predicate
//! values (tenant ids, status codes) offline. So the digest is split:
//! [`ScopeDigests::shape`] is SHA-256 over the non-secret structure with each
//! predicate value replaced by its type tag; [`ScopeDigests::value_hmac`] is a
//! domain-separated keyed HMAC over the canonical typed values; and
//! [`ScopeDigests::binding`] (= [`ScopedGrant::scope_digest`]) is a keyed HMAC
//! over both. The key is a per-process random 32-byte key the caller owns (this
//! crate stays key-agnostic), so a restart invalidates every grant.
//!
//! **Redaction.** Raw predicate values never appear in `Debug`, `Display`,
//! status serialization or error text; they are zeroized when dropped.

mod authorization;
pub mod matcher;
pub mod predicate;
mod signed_ref;
mod store;

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use oraclemcp_audit::{ct_eq, hmac_sha256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::exec_grant::ExecGrantBinding;
use crate::levels::OperatingLevel;
use crate::resolver::CatalogGeneration;

pub use authorization::{ScopedGrantId, WriteAuthRefusal, WriteAuthorization, authorize_level};
pub use matcher::{
    AssignedValue, GrantMatch, GrantMismatch, ResolvedDmlTarget, SetExpressionKind, match_sql,
    match_statement,
};
pub use predicate::{
    GrantBind, GrantPredicateBuilder, PredicateColumnType, PredicateConjunctRequest,
    PredicateExpressionRequest, PredicateInputValue, PredicateOperator, PredicateRefusal,
    ResolvedColumns, compose_where, render_ast,
};
pub use signed_ref::{SCOPED_GRANT_TOKEN_SCOPE, SignedGrantRef};
pub use store::{
    GrantState, MAX_LIVE_SCOPED_GRANTS, ScopedGrantLookupError, ScopedGrantStore,
    ScopedGrantSummary, SuspendReason,
};

/// Longest scoped-grant TTL: one hour.
pub const MAX_SCOPED_GRANT_TTL: Duration = Duration::from_secs(3600);

/// Oracle's own limit on an `IN` list; a grant predicate list never exceeds it.
pub const MAX_IN_LIST_VALUES: usize = 1000;

/// Longest identifier accepted in a grant (Oracle 12.2+ long identifiers).
pub const MAX_IDENTIFIER_BYTES: usize = 128;

const ENCODING_VERSION: &[u8] = b"v1";
const SHAPE_DOMAIN: &[u8] = b"omcp/scoped-grant/shape/v1";
const VALUES_DOMAIN: &[u8] = b"omcp/scoped-grant/values/v1";
const BINDING_DOMAIN: &[u8] = b"omcp/scoped-grant/binding/v1";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A verb a scoped grant cannot carry.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GrantVerbError {
    /// INSERT, MERGE, multi-table INSERT ALL/FIRST, or anything that is not
    /// UPDATE/DELETE. `verb` is the normalized (upper-case, single-spaced) text.
    Unsupported {
        /// The refused verb, normalized.
        verb: String,
    },
    /// No verb was requested.
    Empty,
}

/// Why a scoped grant could not be constructed. Every variant maps to a stable
/// `GRANT_*` code via [`ScopedGrantError::code`]. No variant carries a
/// predicate value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopedGrantError {
    /// The active profile is `protected`; it can never hold a grant.
    ProtectedProfile,
    /// `READ_WRITE` exceeds the profile `max_level` or the OAuth ceiling.
    AboveCeiling {
        /// The level every scoped grant requires (`READ_WRITE`).
        required: OperatingLevel,
        /// The effective ceiling (min of profile `max_level` and OAuth ceiling).
        ceiling: OperatingLevel,
    },
    /// A requested verb is not UPDATE or DELETE, or none was requested.
    Verb(GrantVerbError),
    /// TTL is zero or longer than [`MAX_SCOPED_GRANT_TTL`].
    TtlInvalid {
        /// The requested TTL in milliseconds.
        requested_ms: u128,
    },
    /// UPDATE was requested without any column it may SET.
    UpdateWithoutColumns,
    /// DELETE-only grant named SET columns (DELETE sets nothing).
    DeleteWithColumns,
    /// A SET column also appears in the grant's own row predicate.
    SetPredicateColumn {
        /// The offending column (an identifier, not a value).
        column: String,
    },
    /// A limit is zero.
    ZeroLimit {
        /// Which limit (`max_rows_per_statement`, `max_statements`,
        /// `max_total_rows`).
        limit: &'static str,
    },
    /// `max_rows_per_statement` exceeds `max_total_rows`.
    PerStatementExceedsTotal,
    /// The row predicate is empty (a grant never covers a whole table).
    PredicateEmpty,
    /// A comparison's operand does not fit its operator (e.g. `IN` without a
    /// list, `=` with a list, an empty or oversized `IN` list).
    PredicateMalformed {
        /// The comparison's column.
        column: String,
        /// The operator.
        op: GrantOp,
    },
    /// An identifier is empty, too long, or contains NUL.
    InvalidIdentifier {
        /// Which identifier field.
        field: &'static str,
    },
    /// A typed value is not in canonical form. The value itself is never
    /// echoed.
    InvalidValue {
        /// The value's type tag.
        kind: GrantValueKind,
    },
}

impl ScopedGrantError {
    /// The stable machine-readable refusal code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ScopedGrantError::ProtectedProfile => "GRANT_PROTECTED_PROFILE",
            ScopedGrantError::AboveCeiling { .. } => "GRANT_ABOVE_CEILING",
            ScopedGrantError::Verb(_) => "GRANT_VERB_UNSUPPORTED",
            ScopedGrantError::TtlInvalid { .. } => "GRANT_TTL_INVALID",
            ScopedGrantError::UpdateWithoutColumns => "GRANT_UPDATE_WITHOUT_COLUMNS",
            ScopedGrantError::DeleteWithColumns => "GRANT_DELETE_WITH_COLUMNS",
            ScopedGrantError::SetPredicateColumn { .. } => "GRANT_SET_PREDICATE_COLUMN",
            ScopedGrantError::ZeroLimit { .. } => "GRANT_LIMIT_ZERO",
            ScopedGrantError::PerStatementExceedsTotal => "GRANT_LIMIT_INCOHERENT",
            ScopedGrantError::PredicateEmpty => "GRANT_PREDICATE_EMPTY",
            ScopedGrantError::PredicateMalformed { .. } => "GRANT_PREDICATE_MALFORMED",
            ScopedGrantError::InvalidIdentifier { .. } => "GRANT_IDENTIFIER_INVALID",
            ScopedGrantError::InvalidValue { .. } => "GRANT_VALUE_INVALID",
        }
    }
}

impl fmt::Display for ScopedGrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            ScopedGrantError::ProtectedProfile => {
                write!(f, "{code}: protected profiles cannot hold scoped grants")
            }
            ScopedGrantError::AboveCeiling { required, ceiling } => write!(
                f,
                "{code}: a scoped grant requires {} but the effective ceiling is {}",
                required.as_str(),
                ceiling.as_str()
            ),
            ScopedGrantError::Verb(GrantVerbError::Unsupported { verb }) => write!(
                f,
                "{code}: scoped grants cover UPDATE and DELETE only, not {verb}"
            ),
            ScopedGrantError::Verb(GrantVerbError::Empty) => {
                write!(f, "{code}: no verb requested")
            }
            ScopedGrantError::TtlInvalid { requested_ms } => write!(
                f,
                "{code}: ttl must be in (0, {}] seconds, got {requested_ms} ms",
                MAX_SCOPED_GRANT_TTL.as_secs()
            ),
            ScopedGrantError::UpdateWithoutColumns => {
                write!(
                    f,
                    "{code}: an UPDATE grant must name the columns it may SET"
                )
            }
            ScopedGrantError::DeleteWithColumns => {
                write!(f, "{code}: a DELETE-only grant cannot name SET columns")
            }
            ScopedGrantError::SetPredicateColumn { column } => write!(
                f,
                "{code}: column {column} is both SET and filtered on by the grant predicate"
            ),
            ScopedGrantError::ZeroLimit { limit } => write!(f, "{code}: {limit} must be > 0"),
            ScopedGrantError::PerStatementExceedsTotal => write!(
                f,
                "{code}: max_rows_per_statement cannot exceed max_total_rows"
            ),
            ScopedGrantError::PredicateEmpty => {
                write!(f, "{code}: a scoped grant requires a row predicate")
            }
            ScopedGrantError::PredicateMalformed { column, op } => write!(
                f,
                "{code}: operand does not fit operator {} on column {column}",
                op.as_str()
            ),
            ScopedGrantError::InvalidIdentifier { field } => {
                write!(f, "{code}: invalid identifier in {field}")
            }
            ScopedGrantError::InvalidValue { kind } => {
                write!(f, "{code}: value is not a canonical {}", kind.as_str())
            }
        }
    }
}

impl std::error::Error for ScopedGrantError {}

impl From<GrantVerbError> for ScopedGrantError {
    fn from(err: GrantVerbError) -> Self {
        ScopedGrantError::Verb(err)
    }
}

// ---------------------------------------------------------------------------
// Identifiers, verbs, target
// ---------------------------------------------------------------------------

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ScopedGrantError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.contains('\0') {
        return Err(ScopedGrantError::InvalidIdentifier { field });
    }
    Ok(())
}

/// A column identifier in exact catalog case (never normalized here: case is
/// semantic for quoted identifiers).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ColumnIdent(String);

impl ColumnIdent {
    /// A validated column identifier.
    pub fn new(name: impl Into<String>) -> Result<Self, ScopedGrantError> {
        let name = name.into();
        validate_identifier("column", &name)?;
        Ok(ColumnIdent(name))
    }

    /// The identifier text, exact catalog case.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ColumnIdent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One verb a scoped grant can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GrantVerb {
    /// `UPDATE`.
    Update,
    /// `DELETE`.
    Delete,
}

impl GrantVerb {
    /// The SQL keyword.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GrantVerb::Update => "UPDATE",
            GrantVerb::Delete => "DELETE",
        }
    }
}

/// The non-empty verb set of a grant: a subset of {UPDATE, DELETE}.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct GrantVerbs(BTreeSet<GrantVerb>);

impl GrantVerbs {
    /// Parse requested verbs. Matching is ASCII-case-insensitive with
    /// whitespace collapsed; INSERT, MERGE, INSERT ALL/FIRST and every other
    /// verb are refused with [`GrantVerbError::Unsupported`].
    pub fn parse<S: AsRef<str>>(verbs: &[S]) -> Result<Self, GrantVerbError> {
        let mut set = BTreeSet::new();
        for raw in verbs {
            let normalized = raw
                .as_ref()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_uppercase();
            let verb = match normalized.as_str() {
                "UPDATE" => GrantVerb::Update,
                "DELETE" => GrantVerb::Delete,
                _ => return Err(GrantVerbError::Unsupported { verb: normalized }),
            };
            set.insert(verb);
        }
        if set.is_empty() {
            return Err(GrantVerbError::Empty);
        }
        Ok(GrantVerbs(set))
    }

    /// Whether `verb` is granted.
    #[must_use]
    pub fn contains(&self, verb: GrantVerb) -> bool {
        self.0.contains(&verb)
    }

    /// The granted verbs, sorted.
    pub fn iter(&self) -> impl Iterator<Item = GrantVerb> + '_ {
        self.0.iter().copied()
    }
}

/// The PDB a target lives in: `CON_ID` plus the globally unique `CON_UID`
/// (a `CON_ID` alone is reused across unplug/plug).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct GrantContainer {
    /// `V$CONTAINERS.CON_ID`.
    pub con_id: u32,
    /// `V$CONTAINERS.CON_UID`.
    pub con_uid: u64,
}

/// The synonym a target was reached through, retained as evidence.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct SynonymIdentity {
    /// Synonym owner (`PUBLIC` for a public synonym), exact catalog case.
    pub owner: String,
    /// Synonym name, exact catalog case.
    pub name: String,
    /// The synonym's own `OBJECT_ID`.
    pub object_id: u64,
}

/// Exactly one table, bound to its catalog identity. Any drift in these values
/// between grant and use means a different object, and the grant does not
/// apply.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct GrantTargetIdentity {
    /// Table owner, exact catalog case.
    pub owner: String,
    /// Table name, exact catalog case.
    pub object_name: String,
    /// `OBJECT_ID`.
    pub object_id: u64,
    /// `DATA_OBJECT_ID` (NULL for a partitioned table's logical segment).
    pub data_object_id: Option<u64>,
    /// The container the table was resolved in.
    pub container: GrantContainer,
    /// The edition the table was resolved under, if editioning applies.
    pub edition: Option<String>,
    /// The catalog generation of the resolution.
    #[serde(serialize_with = "serialize_generation")]
    pub catalog_generation: CatalogGeneration,
    /// The synonym the caller named, when resolution went through one.
    pub resolved_via: Option<SynonymIdentity>,
}

fn serialize_generation<S: serde::Serializer>(
    generation: &CatalogGeneration,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(generation.0)
}

impl GrantTargetIdentity {
    fn validate(&self) -> Result<(), ScopedGrantError> {
        validate_identifier("target.owner", &self.owner)?;
        validate_identifier("target.object_name", &self.object_name)?;
        if let Some(edition) = &self.edition {
            validate_identifier("target.edition", edition)?;
        }
        if let Some(synonym) = &self.resolved_via {
            validate_identifier("target.resolved_via.owner", &synonym.owner)?;
            validate_identifier("target.resolved_via.name", &synonym.name)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Predicate data model (parsing/validation/rendering against SQL is T13.2)
// ---------------------------------------------------------------------------

/// A comparison operator in a grant predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum GrantOp {
    /// `=`.
    Eq,
    /// `<>`.
    NotEq,
    /// `<`.
    Lt,
    /// `<=`.
    Le,
    /// `>`.
    Gt,
    /// `>=`.
    Ge,
    /// `IN (...)`.
    In,
    /// `BETWEEN a AND b`.
    Between,
    /// `IS NULL`.
    IsNull,
    /// `IS NOT NULL`.
    IsNotNull,
}

impl GrantOp {
    /// The SQL spelling (also the canonical encoding tag).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GrantOp::Eq => "=",
            GrantOp::NotEq => "<>",
            GrantOp::Lt => "<",
            GrantOp::Le => "<=",
            GrantOp::Gt => ">",
            GrantOp::Ge => ">=",
            GrantOp::In => "IN",
            GrantOp::Between => "BETWEEN",
            GrantOp::IsNull => "IS NULL",
            GrantOp::IsNotNull => "IS NOT NULL",
        }
    }
}

/// The type tag of a grant value — the only part of a value that enters the
/// non-secret shape digest, status output and error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GrantValueKind {
    /// Oracle `NUMBER`, canonical decimal text.
    Number,
    /// Character data (`VARCHAR2`/`CHAR`/`NVARCHAR2`), exact bytes.
    Text,
    /// Oracle `DATE`, canonical `YYYY-MM-DDTHH:MM:SS`.
    Date,
    /// Oracle `TIMESTAMP`, canonical local ISO-8601 wall time.
    Timestamp,
}

impl GrantValueKind {
    /// The canonical tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GrantValueKind::Number => "NUMBER",
            GrantValueKind::Text => "TEXT",
            GrantValueKind::Date => "DATE",
            GrantValueKind::Timestamp => "TIMESTAMP",
        }
    }
}

/// A typed, immutable predicate value. Its text is secret-ish (tenant ids,
/// status codes): `Debug`, `Display` and `Serialize` render only
/// `<redacted:KIND>`, and the text is zeroized on drop.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GrantValue {
    kind: GrantValueKind,
    text: String,
}

impl GrantValue {
    /// A `NUMBER` in canonical decimal form: optional `-`, no leading zeros,
    /// no trailing fractional zeros, no exponent, no `+`, and never `-0`.
    pub fn number(canonical: impl Into<String>) -> Result<Self, ScopedGrantError> {
        let mut text = canonical.into();
        if !is_canonical_decimal(&text) {
            text.zeroize();
            return Err(ScopedGrantError::InvalidValue {
                kind: GrantValueKind::Number,
            });
        }
        Ok(GrantValue {
            kind: GrantValueKind::Number,
            text,
        })
    }

    /// Character data, exact bytes (no trimming or case folding: both are
    /// semantic in Oracle comparisons). NUL is refused.
    pub fn text(value: impl Into<String>) -> Result<Self, ScopedGrantError> {
        let mut text = value.into();
        if text.contains('\0') {
            text.zeroize();
            return Err(ScopedGrantError::InvalidValue {
                kind: GrantValueKind::Text,
            });
        }
        Ok(GrantValue {
            kind: GrantValueKind::Text,
            text,
        })
    }

    /// A `DATE` in canonical `YYYY-MM-DDTHH:MM:SS` form (shape-checked only;
    /// calendar validity belongs to predicate parsing).
    pub fn date(canonical: impl Into<String>) -> Result<Self, ScopedGrantError> {
        let mut text = canonical.into();
        if !is_canonical_date(&text) {
            text.zeroize();
            return Err(ScopedGrantError::InvalidValue {
                kind: GrantValueKind::Date,
            });
        }
        Ok(GrantValue {
            kind: GrantValueKind::Date,
            text,
        })
    }

    /// An Oracle `TIMESTAMP` in canonical local ISO-8601 form. The value has
    /// no time-zone suffix; a `TIMESTAMP WITH TIME ZONE` is a different type.
    pub fn timestamp(canonical: impl Into<String>) -> Result<Self, ScopedGrantError> {
        let mut text = canonical.into();
        if !is_canonical_timestamp(&text) {
            text.zeroize();
            return Err(ScopedGrantError::InvalidValue {
                kind: GrantValueKind::Timestamp,
            });
        }
        Ok(GrantValue {
            kind: GrantValueKind::Timestamp,
            text,
        })
    }

    /// The value's type tag.
    #[must_use]
    pub fn kind(&self) -> GrantValueKind {
        self.kind
    }

    /// The raw canonical text. Only enforcement code that binds the value into
    /// a statement may read it; never log or serialize it.
    #[must_use]
    pub fn expose_canonical(&self) -> &str {
        &self.text
    }
}

impl Drop for GrantValue {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

impl fmt::Debug for GrantValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted:{}>", self.kind.as_str())
    }
}

impl fmt::Display for GrantValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted:{}>", self.kind.as_str())
    }
}

impl Serialize for GrantValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

fn is_canonical_decimal(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    let (int, frac) = match digits.split_once('.') {
        Some((int, frac)) => (int, Some(frac)),
        None => (digits, None),
    };
    let int_ok = !int.is_empty()
        && int.bytes().all(|b| b.is_ascii_digit())
        && (int == "0" || !int.starts_with('0'));
    let frac_ok = match frac {
        None => true,
        Some(frac) => {
            !frac.is_empty() && frac.bytes().all(|b| b.is_ascii_digit()) && !frac.ends_with('0')
        }
    };
    let negative_zero = text.starts_with('-') && int == "0" && frac.is_none();
    int_ok && frac_ok && !negative_zero
}

fn is_canonical_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 19
        && bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            10 => *b == b'T',
            13 | 16 => *b == b':',
            _ => b.is_ascii_digit(),
        })
}

fn is_canonical_timestamp(text: &str) -> bool {
    let (date, time) = match text.split_once('T') {
        Some(parts) => parts,
        None => return false,
    };
    let date_bytes = date.as_bytes();
    if date_bytes.len() != 10
        || date_bytes[4] != b'-'
        || date_bytes[7] != b'-'
        || !date_bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let (clock, fraction) = match time.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (time, None),
    };
    let clock_bytes = clock.as_bytes();
    if clock_bytes.len() != 8
        || clock_bytes[2] != b':'
        || clock_bytes[5] != b':'
        || !clock_bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 2 | 5) || byte.is_ascii_digit())
    {
        return false;
    }
    match fraction {
        Some(fraction) => {
            !fraction.is_empty()
                && fraction.len() <= 9
                && fraction.bytes().all(|byte| byte.is_ascii_digit())
                && !fraction.ends_with('0')
        }
        None => true,
    }
}

/// The operand of one comparison.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum GrantOperand {
    /// No operand (`IS NULL`, `IS NOT NULL`).
    None,
    /// One value (`=`, `<>`, `<`, `<=`, `>`, `>=`).
    Single(GrantValue),
    /// A non-empty list (`IN`), at most [`MAX_IN_LIST_VALUES`].
    List(Vec<GrantValue>),
    /// A closed range (`BETWEEN low AND high`).
    Range(GrantValue, GrantValue),
}

/// One comparison `column op operand` in the grant predicate.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct GrantComparison {
    /// The filtered column.
    pub column: ColumnIdent,
    /// The operator.
    pub op: GrantOp,
    /// The typed operand.
    pub operand: GrantOperand,
}

impl GrantComparison {
    fn validate(&self) -> Result<(), ScopedGrantError> {
        let fits = match (&self.op, &self.operand) {
            (GrantOp::IsNull | GrantOp::IsNotNull, GrantOperand::None) => true,
            (
                GrantOp::Eq
                | GrantOp::NotEq
                | GrantOp::Lt
                | GrantOp::Le
                | GrantOp::Gt
                | GrantOp::Ge,
                GrantOperand::Single(_),
            ) => true,
            (GrantOp::In, GrantOperand::List(values)) => {
                !values.is_empty() && values.len() <= MAX_IN_LIST_VALUES
            }
            (GrantOp::Between, GrantOperand::Range(low, high)) => low.kind() == high.kind(),
            _ => false,
        };
        if fits {
            Ok(())
        } else {
            Err(ScopedGrantError::PredicateMalformed {
                column: self.column.as_str().to_owned(),
                op: self.op,
            })
        }
    }
}

impl fmt::Display for GrantComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.column, self.op.as_str())?;
        match &self.operand {
            GrantOperand::None => Ok(()),
            GrantOperand::Single(value) => write!(f, " {value}"),
            GrantOperand::List(values) => {
                f.write_str(" (")?;
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{value}")?;
                }
                f.write_str(")")
            }
            GrantOperand::Range(low, high) => write!(f, " {low} AND {high}"),
        }
    }
}

/// The grant's row predicate: an ordered AND-list of comparisons. This is the
/// canonical data model only; parsing caller SQL into it is T13.2.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct GrantPredicateV1(Vec<GrantComparison>);

impl GrantPredicateV1 {
    /// An AND-list of comparisons, in the given order (order is part of the
    /// canonical form; T13.2 decides the canonical ordering it emits).
    #[must_use]
    pub fn new(conjuncts: Vec<GrantComparison>) -> Self {
        GrantPredicateV1(conjuncts)
    }

    /// The conjuncts, in order.
    #[must_use]
    pub fn conjuncts(&self) -> &[GrantComparison] {
        &self.0
    }

    /// The set of columns the predicate filters on.
    #[must_use]
    pub fn columns(&self) -> BTreeSet<&ColumnIdent> {
        self.0.iter().map(|c| &c.column).collect()
    }
}

impl fmt::Display for GrantPredicateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, comparison) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" AND ")?;
            }
            write!(f, "{comparison}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Limits, closure, ceiling, digests
// ---------------------------------------------------------------------------

/// Row and statement budgets. `max_total_rows` counts *attempted* rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct GrantLimits {
    /// Most rows one statement may touch.
    pub max_rows_per_statement: u64,
    /// Most statements the grant may run.
    pub max_statements: u64,
    /// Most rows all statements together may attempt.
    pub max_total_rows: u64,
}

/// Fingerprints of the DML effect closure (triggers, FK cascades, …). An
/// opaque sorted set of 32-byte fingerprints, filled by T13.2a from
/// `MutationEffectClosureV1`; empty until then.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ClosureFingerprints(BTreeSet<[u8; 32]>);

impl ClosureFingerprints {
    /// The empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A set from fingerprints (duplicates collapse; order is irrelevant).
    #[must_use]
    pub fn from_fingerprints(fingerprints: impl IntoIterator<Item = [u8; 32]>) -> Self {
        ClosureFingerprints(fingerprints.into_iter().collect())
    }

    /// The fingerprints, sorted.
    pub fn iter(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.0.iter()
    }
}

/// The target's `LAST_DDL_TIME` as canonical `YYYY-MM-DDTHH:MM:SS` text.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct LastDdlTime(String);

impl LastDdlTime {
    /// A canonical `LAST_DDL_TIME`.
    pub fn new(canonical: impl Into<String>) -> Result<Self, ScopedGrantError> {
        let text = canonical.into();
        if !is_canonical_date(&text) {
            return Err(ScopedGrantError::InvalidValue {
                kind: GrantValueKind::Date,
            });
        }
        Ok(LastDdlTime(text))
    }

    /// The canonical text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The level ceiling a grant must fit under: the profile's `max_level` and,
/// when the request is OAuth-authenticated, the scope-derived ceiling. OAuth
/// can only lower the effective level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectiveCeiling {
    /// The profile's `max_level`.
    pub profile_max_level: OperatingLevel,
    /// The OAuth scope ceiling, if the caller is OAuth-authenticated.
    pub oauth_ceiling: Option<OperatingLevel>,
}

impl EffectiveCeiling {
    /// The lower of the two ceilings.
    #[must_use]
    pub fn effective(self) -> OperatingLevel {
        match self.oauth_ceiling {
            Some(oauth) => self.profile_max_level.min(oauth),
            None => self.profile_max_level,
        }
    }
}

/// The three-part scope digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeDigests {
    /// SHA-256 over the non-secret structure (values replaced by type tags).
    pub shape: [u8; 32],
    /// Keyed HMAC over the canonical typed predicate values.
    pub value_hmac: [u8; 32],
    /// Keyed HMAC binding `shape` and `value_hmac`; the grant's
    /// `scope_digest`.
    pub binding: [u8; 32],
}

impl fmt::Debug for ScopeDigests {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopeDigests")
            .field("shape", &hex(&self.shape))
            .field("value_hmac", &hex(&self.value_hmac))
            .field("binding", &hex(&self.binding))
            .finish()
    }
}

/// Lowercase hex of a digest.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

/// Length-prefixed, fixed-order canonical encoder. Every field is written as
/// `u64-BE length || bytes`, so no choice of values can collide with a
/// different split; optional fields carry an explicit presence tag.
#[derive(Default)]
pub(crate) struct Canonical(Vec<u8>);

impl Canonical {
    pub(crate) fn bytes(&mut self, part: &[u8]) -> &mut Self {
        self.0.extend_from_slice(&(part.len() as u64).to_be_bytes());
        self.0.extend_from_slice(part);
        self
    }

    pub(crate) fn str(&mut self, part: &str) -> &mut Self {
        self.bytes(part.as_bytes())
    }

    pub(crate) fn u64(&mut self, value: u64) -> &mut Self {
        self.str(&value.to_string())
    }

    fn opt_str(&mut self, value: Option<&str>) -> &mut Self {
        match value {
            Some(value) => self.str("some").str(value),
            None => self.str("none"),
        }
    }

    fn opt_u64(&mut self, value: Option<u64>) -> &mut Self {
        match value {
            Some(value) => self.str("some").u64(value),
            None => self.str("none"),
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for Canonical {
    fn drop(&mut self) {
        // The values encoding carries raw predicate values.
        self.0.zeroize();
    }
}

// ---------------------------------------------------------------------------
// The grant
// ---------------------------------------------------------------------------

/// What an agent asks for. Validated into a [`ScopedGrant`] by
/// [`ScopedGrant::new`].
#[derive(Clone, Debug)]
pub struct ScopedGrantRequest {
    /// The active profile name.
    pub profile: String,
    /// The lane/session/subject/generation the grant is pinned to.
    pub binding: ExecGrantBinding,
    /// Requested verbs (only UPDATE/DELETE are accepted).
    pub verbs: Vec<String>,
    /// The resolved target table.
    pub target: GrantTargetIdentity,
    /// Columns an UPDATE may SET (empty for DELETE-only).
    pub columns: BTreeSet<ColumnIdent>,
    /// The row predicate.
    pub row_predicate: GrantPredicateV1,
    /// Row/statement budgets.
    pub limits: GrantLimits,
    /// Lifetime, in `(0, 3600 s]`.
    pub ttl: Duration,
    /// Whether the grant may COMMIT (default false: DML rolls back).
    pub commit_allowed: bool,
    /// DML effect closure fingerprints (T13.2a).
    pub closure: ClosureFingerprints,
    /// The target's `LAST_DDL_TIME` at grant time.
    pub last_ddl_time: LastDdlTime,
}

/// A validated, digested scoped grant. Immutable: every field is fixed at
/// construction and covered by [`ScopedGrant::scope_digest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedGrant {
    profile: String,
    binding: ExecGrantBinding,
    verbs: GrantVerbs,
    target: GrantTargetIdentity,
    columns: BTreeSet<ColumnIdent>,
    row_predicate: GrantPredicateV1,
    limits: GrantLimits,
    ttl: Duration,
    commit_allowed: bool,
    required_level: OperatingLevel,
    closure: ClosureFingerprints,
    last_ddl_time: LastDdlTime,
    digests: ScopeDigests,
}

impl ScopedGrant {
    /// Validate `request` against the ceiling and compute its digests under
    /// `key` (the caller's per-process random 32-byte key).
    ///
    /// Refusal order is fixed and fail-closed: protected profile, ceiling,
    /// verbs, TTL, identifiers, columns, predicate, limits.
    pub fn new(
        request: ScopedGrantRequest,
        ceiling: EffectiveCeiling,
        profile_protected: bool,
        key: &[u8; 32],
    ) -> Result<Self, ScopedGrantError> {
        if profile_protected {
            return Err(ScopedGrantError::ProtectedProfile);
        }
        let required_level = OperatingLevel::ReadWrite;
        let effective = ceiling.effective();
        if required_level > effective {
            return Err(ScopedGrantError::AboveCeiling {
                required: required_level,
                ceiling: effective,
            });
        }
        let verbs = GrantVerbs::parse(&request.verbs)?;
        if request.ttl.is_zero() || request.ttl > MAX_SCOPED_GRANT_TTL {
            return Err(ScopedGrantError::TtlInvalid {
                requested_ms: request.ttl.as_millis(),
            });
        }
        request.target.validate()?;

        if verbs.contains(GrantVerb::Update) && request.columns.is_empty() {
            return Err(ScopedGrantError::UpdateWithoutColumns);
        }
        if !verbs.contains(GrantVerb::Update) && !request.columns.is_empty() {
            return Err(ScopedGrantError::DeleteWithColumns);
        }

        if request.row_predicate.conjuncts().is_empty() {
            return Err(ScopedGrantError::PredicateEmpty);
        }
        for comparison in request.row_predicate.conjuncts() {
            comparison.validate()?;
        }
        let predicate_columns = request.row_predicate.columns();
        if let Some(column) = request
            .columns
            .iter()
            .find(|column| predicate_columns.contains(column))
        {
            return Err(ScopedGrantError::SetPredicateColumn {
                column: column.as_str().to_owned(),
            });
        }

        let limits = request.limits;
        for (name, value) in [
            ("max_rows_per_statement", limits.max_rows_per_statement),
            ("max_statements", limits.max_statements),
            ("max_total_rows", limits.max_total_rows),
        ] {
            if value == 0 {
                return Err(ScopedGrantError::ZeroLimit { limit: name });
            }
        }
        if limits.max_rows_per_statement > limits.max_total_rows {
            return Err(ScopedGrantError::PerStatementExceedsTotal);
        }

        let mut grant = ScopedGrant {
            profile: request.profile,
            binding: request.binding,
            verbs,
            target: request.target,
            columns: request.columns,
            row_predicate: request.row_predicate,
            limits,
            ttl: request.ttl,
            commit_allowed: request.commit_allowed,
            required_level,
            closure: request.closure,
            last_ddl_time: request.last_ddl_time,
            digests: ScopeDigests {
                shape: [0; 32],
                value_hmac: [0; 32],
                binding: [0; 32],
            },
        };
        grant.digests = grant.compute_digests(key);
        Ok(grant)
    }

    /// The canonical non-secret structure: every field in fixed order, with
    /// predicate values replaced by their type tags.
    #[must_use]
    pub fn canonical_shape(&self) -> Vec<u8> {
        let mut enc = Canonical::default();
        enc.bytes(ENCODING_VERSION)
            .str("profile")
            .str(&self.profile)
            .str("binding")
            .str(&self.binding.session_id)
            .str(&self.binding.lane_id)
            .str(&self.binding.subject_id)
            .u64(self.binding.generation)
            .str("verbs")
            .u64(self.verbs.0.len() as u64);
        for verb in self.verbs.iter() {
            enc.str(verb.as_str());
        }
        let target = &self.target;
        enc.str("target")
            .str(&target.owner)
            .str(&target.object_name)
            .u64(target.object_id)
            .opt_u64(target.data_object_id)
            .u64(u64::from(target.container.con_id))
            .u64(target.container.con_uid)
            .opt_str(target.edition.as_deref())
            .u64(target.catalog_generation.0);
        match &target.resolved_via {
            Some(synonym) => enc
                .str("some")
                .str(&synonym.owner)
                .str(&synonym.name)
                .u64(synonym.object_id),
            None => enc.str("none"),
        };
        enc.str("columns").u64(self.columns.len() as u64);
        for column in &self.columns {
            enc.str(column.as_str());
        }
        enc.str("predicate")
            .u64(self.row_predicate.conjuncts().len() as u64);
        for comparison in self.row_predicate.conjuncts() {
            enc.str(comparison.column.as_str())
                .str(comparison.op.as_str());
            encode_operand(&mut enc, &comparison.operand, |enc, value| {
                enc.str(value.kind().as_str());
            });
        }
        enc.str("limits")
            .u64(self.limits.max_rows_per_statement)
            .u64(self.limits.max_statements)
            .u64(self.limits.max_total_rows)
            .str("ttl")
            .u64(self.ttl.as_secs())
            .u64(u64::from(self.ttl.subsec_nanos()))
            .str("commit_allowed")
            .str(if self.commit_allowed { "true" } else { "false" })
            .str("required_level")
            .str(self.required_level.as_str())
            .str("closure")
            .u64(self.closure.0.len() as u64);
        for fingerprint in self.closure.iter() {
            enc.bytes(fingerprint);
        }
        enc.str("last_ddl_time").str(self.last_ddl_time.as_str());
        enc.finish()
    }

    /// The canonical typed predicate values, in predicate order. Secret: only
    /// ever fed to the keyed HMAC.
    fn canonical_values(&self) -> Canonical {
        let mut enc = Canonical::default();
        enc.bytes(ENCODING_VERSION)
            .u64(self.row_predicate.conjuncts().len() as u64);
        for comparison in self.row_predicate.conjuncts() {
            encode_operand(&mut enc, &comparison.operand, |enc, value| {
                enc.str(value.kind().as_str()).str(value.expose_canonical());
            });
        }
        enc
    }

    fn compute_digests(&self, key: &[u8; 32]) -> ScopeDigests {
        let mut shape_input = Canonical::default();
        shape_input
            .bytes(SHAPE_DOMAIN)
            .bytes(&self.canonical_shape());
        let shape: [u8; 32] = Sha256::digest(shape_input.finish()).into();

        // Both value-bearing buffers stay inside `Canonical`, which zeroizes
        // on drop.
        let values = self.canonical_values();
        let mut values_input = Canonical::default();
        values_input.bytes(VALUES_DOMAIN).bytes(values.as_slice());
        let value_hmac = hmac_sha256(key, values_input.as_slice());

        let mut binding_input = Canonical::default();
        binding_input
            .bytes(BINDING_DOMAIN)
            .bytes(&shape)
            .bytes(&value_hmac);
        let binding = hmac_sha256(key, &binding_input.finish());

        ScopeDigests {
            shape,
            value_hmac,
            binding,
        }
    }

    /// Recompute the digests under `key` and constant-time compare them to the
    /// recorded ones. Run before every use: a rotated key (restart) or any
    /// in-memory drift makes this `false`, and the grant must not apply.
    #[must_use]
    pub fn recheck_digests(&self, key: &[u8; 32]) -> bool {
        let fresh = self.compute_digests(key);
        ct_eq(&fresh.shape, &self.digests.shape)
            & ct_eq(&fresh.value_hmac, &self.digests.value_hmac)
            & ct_eq(&fresh.binding, &self.digests.binding)
    }

    /// The keyed binding digest: the value audit records and W14 carries as an
    /// opaque `Option<[u8; 32]>`. It reveals nothing about predicate values to
    /// anyone without the key.
    #[must_use]
    pub fn scope_digest(&self) -> [u8; 32] {
        self.digests.binding
    }

    /// All three digests.
    #[must_use]
    pub fn digests(&self) -> ScopeDigests {
        self.digests
    }

    /// The profile the grant was minted under.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The lane/session/subject/generation binding.
    #[must_use]
    pub fn binding(&self) -> &ExecGrantBinding {
        &self.binding
    }

    /// The granted verbs.
    #[must_use]
    pub fn verbs(&self) -> &GrantVerbs {
        &self.verbs
    }

    /// The target identity.
    #[must_use]
    pub fn target(&self) -> &GrantTargetIdentity {
        &self.target
    }

    /// Columns an UPDATE may SET.
    #[must_use]
    pub fn columns(&self) -> &BTreeSet<ColumnIdent> {
        &self.columns
    }

    /// The row predicate.
    #[must_use]
    pub fn row_predicate(&self) -> &GrantPredicateV1 {
        &self.row_predicate
    }

    /// The budgets.
    #[must_use]
    pub fn limits(&self) -> GrantLimits {
        self.limits
    }

    /// The lifetime.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Whether the grant may COMMIT.
    #[must_use]
    pub fn commit_allowed(&self) -> bool {
        self.commit_allowed
    }

    /// Always [`OperatingLevel::ReadWrite`].
    #[must_use]
    pub fn required_level(&self) -> OperatingLevel {
        self.required_level
    }

    /// The effect-closure fingerprints.
    #[must_use]
    pub fn closure(&self) -> &ClosureFingerprints {
        &self.closure
    }

    /// The target's `LAST_DDL_TIME` at grant time.
    #[must_use]
    pub fn last_ddl_time(&self) -> &LastDdlTime {
        &self.last_ddl_time
    }

    /// A redacted, serializable status view (no predicate values).
    #[must_use]
    pub fn status(&self) -> ScopedGrantStatus {
        ScopedGrantStatus {
            profile: self.profile.clone(),
            verbs: self.verbs.clone(),
            target: self.target.clone(),
            columns: self.columns.clone(),
            row_predicate: self.row_predicate.to_string(),
            limits: self.limits,
            ttl_ms: self.ttl.as_millis(),
            commit_allowed: self.commit_allowed,
            required_level: self.required_level.as_str(),
            closure_fingerprints: self.closure.0.len(),
            last_ddl_time: self.last_ddl_time.clone(),
            scope_digest: hex(&self.digests.binding),
            shape_digest: hex(&self.digests.shape),
        }
    }
}

fn encode_operand(
    enc: &mut Canonical,
    operand: &GrantOperand,
    mut value: impl FnMut(&mut Canonical, &GrantValue),
) {
    match operand {
        GrantOperand::None => {
            enc.str("none");
        }
        GrantOperand::Single(v) => {
            enc.str("single");
            value(enc, v);
        }
        GrantOperand::List(values) => {
            enc.str("list").u64(values.len() as u64);
            for v in values {
                value(enc, v);
            }
        }
        GrantOperand::Range(low, high) => {
            enc.str("range");
            value(enc, low);
            value(enc, high);
        }
    }
}

/// The redacted status view of a grant, safe for tool output and logs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScopedGrantStatus {
    /// Profile name.
    pub profile: String,
    /// Granted verbs.
    pub verbs: GrantVerbs,
    /// Target identity.
    pub target: GrantTargetIdentity,
    /// SET columns.
    pub columns: BTreeSet<ColumnIdent>,
    /// The predicate with every value rendered `<redacted:KIND>`.
    pub row_predicate: String,
    /// Budgets.
    pub limits: GrantLimits,
    /// Lifetime in milliseconds.
    pub ttl_ms: u128,
    /// Whether COMMIT is allowed.
    pub commit_allowed: bool,
    /// Always `READ_WRITE`.
    pub required_level: &'static str,
    /// Number of effect-closure fingerprints.
    pub closure_fingerprints: usize,
    /// `LAST_DDL_TIME` at grant time.
    pub last_ddl_time: LastDdlTime,
    /// Hex keyed binding digest.
    pub scope_digest: String,
    /// Hex non-secret shape digest.
    pub shape_digest: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_decimal_accepts_only_canonical_forms() {
        for ok in ["0", "7", "101", "-3", "0.5", "-0.25", "12.034"] {
            assert!(is_canonical_decimal(ok), "{ok} should be canonical");
        }
        for bad in [
            "", "-", "-0", "00", "01", "1.", ".5", "1.50", "+1", "1e3", "1_0", " 1", "0.0",
        ] {
            assert!(!is_canonical_decimal(bad), "{bad:?} must be refused");
        }
    }

    #[test]
    fn canonical_date_shape() {
        assert!(is_canonical_date("2026-09-23T18:00:00"));
        for bad in ["2026-09-23", "2026-09-23 18:00:00", "2026-9-23T18:00:00"] {
            assert!(!is_canonical_date(bad), "{bad:?} must be refused");
        }
    }

    #[test]
    fn invalid_value_error_never_echoes_the_value() {
        let err = GrantValue::number("913377.0").unwrap_err();
        assert!(!err.to_string().contains("913377"));
        assert!(!format!("{err:?}").contains("913377"));
    }

    #[test]
    fn canonical_encoding_is_length_prefixed() {
        let mut a = Canonical::default();
        a.str("ab").str("c");
        let mut b = Canonical::default();
        b.str("a").str("bc");
        assert_ne!(a.finish(), b.finish());
    }
}
