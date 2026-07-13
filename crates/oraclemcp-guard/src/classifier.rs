//! The fail-closed, engine-aware statement classifier (plan §5.3; bead P1-1 +
//! P1-1a..f). This is the safety spine: it replaces a fail-OPEN string
//! predicate with a staged, fail-CLOSED classifier.
//!
//! Pipeline (per call):
//! 0. **Session ownership** — caller-controlled transaction boundaries and
//!    non-allowlisted `ALTER SESSION` state changes are always `Forbidden`;
//!    only the server policy may reshape its transaction or security context.
//! 1. **Stage A** ([`stage_a`]) — operator allow-list (SHA-256 of exact
//!    statement bytes) → block-list (regex) → PL/SQL-block detector. (P1-1a)
//! 2. **Splitter** ([`analyze_batch`]) — a *lexer-based*, literal/quote-aware
//!    balance check: `;`/`BEGIN`/`END` inside `'…'`/`q'[…]'`/`N'…'`/`"…"` are
//!    never counted (they are single tokens), and a `BEGIN`/`END` desync makes
//!    the **whole batch `Forbidden`** (fail-closed). (P1-1c)
//! 3. **Stage B** ([`classify_statement`]) — parse pure SQL with `sqlparser`
//!    `OracleDialect` and map each `Statement` to a [`DangerLevel`] + required
//!    [`OperatingLevel`]; `DELETE`/`UPDATE` with no `WHERE` escalates to
//!    `Destructive`; `EXPLAIN PLAN` is `Guarded`. (P1-1b)
//! 4. **Purity consult** — a `SELECT` calling a user-defined function is
//!    `Guarded` **unless** the [`SideEffectOracle`] proves it `ProvenReadOnly`;
//!    for routine calls, absence of a write edge is `Unknown`, never `Safe`
//!    (P1-1e, R15). A UDF-free `SELECT` also consults `statement_purity` over
//!    its resolved
//!    base objects (the engine's trigger/VPD walk): a base object the engine
//!    proves `ProvenSideEffecting` escalates the `SELECT` to `Guarded`, and an
//!    engine-bound classifier can opt into treating statement-level `Unknown`
//!    as `Guarded`.
//!
//! **Fail-closed law:** anything that does not parse, any PL/SQL block, any
//! desync, and any user-defined routine the engine cannot prove
//! `ProvenReadOnly` is classified ≥ `Guarded`. The batch danger is the max over
//! statements; any `Forbidden` sub-statement rejects the whole batch.

use std::borrow::Cow;
use std::collections::HashSet;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlparser::ast::{
    Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, Ident, Query, Select, SetExpr,
    TableAlias, TableFactor, TableWithJoins, Visit, Visitor,
};
use sqlparser::dialect::OracleDialect;
use sqlparser::keywords::Keyword;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};

use oraclemcp_error::ReasonCategory;

use crate::edition_lifecycle::{EditionLifecycleParse, parse_edition_lifecycle_sql};
use crate::enforcement::alter_session_policy;
use crate::levels::{DangerLevel, LevelDecision, OperatingLevel, SessionLevelState};
use crate::purity::{ObjectRef, Purity, SideEffectOracle, UnknownOracle};
use crate::resolver::{
    QuoteSemantics, RawName, RawNamePart, SemanticReadPlan, StatementRelation, StatementScope,
    SyntacticRole,
};

/// One redacted, immutable rule application recorded in a verdict certificate.
///
/// `construct` is selected solely from the certificate registry's fixed
/// allowlist. It is deliberately not the parser rendering, a reason string, an
/// object name, or any user-controlled text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictDerivationStep {
    /// Redacted, registry-approved construct label.
    pub construct: String,
    /// Immutable certificate-registry identifier for the applied rule.
    pub rule_id: String,
}

/// A redacted witness for the exact statement and decision returned by one
/// [`Classifier::classify`] call.
///
/// This is a proof *of the decision already enforced by the guard*; it never
/// authorizes execution by itself. The response-side `bound_audit_hash` is
/// intentionally excluded from [`Self::core_hash`] to avoid a cycle with the
/// audit entry hash that covers the core hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictCertificate {
    /// SHA-256 of the exact statement bytes classified by the guard.
    pub stmt_digest: String,
    /// Required operating level, absent only for a forbidden verdict.
    pub level: Option<OperatingLevel>,
    /// Final risk verdict returned by this classification call.
    pub verdict: DangerLevel,
    /// Ordered, redacted derivation facts from the immutable registry.
    pub derivation: Vec<VerdictDerivationStep>,
    /// Guard package version plus immutable rule-registry generation.
    pub classifier_version: String,
    /// Oracle-observed SCN when a later execution path has one.
    pub observed_scn: Option<String>,
    /// Response-side binding to the durable audit entry, added only after a
    /// matching audit append and fsync succeeds.
    pub bound_audit_hash: Option<String>,
}

/// Why a certificate could not be bound to a persisted audit record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerdictCertificateBindingError {
    /// The audit record describes different exact SQL bytes.
    SqlDigestMismatch,
    /// The audit record is missing this certificate's core hash, or contains a
    /// hash for a different certificate core.
    CoreHashMismatch,
    /// The purported audit entry hash is not the canonical SHA-256 wire form.
    InvalidAuditEntryHash,
}

/// Current immutable certificate registry generation.
pub const VERDICT_CERTIFICATE_REGISTRY_GENERATION: u16 = 1;

/// Classifier build and certificate-registry identity carried in every proof.
pub const VERDICT_CERTIFICATE_CLASSIFIER_VERSION: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    ";registry=1"
);

const CERTIFICATE_CORE_HASH_DOMAIN: &str = "oraclemcp:verdict-certificate-core:v1\n";
const CERTIFICATE_TERMINAL_RULE_ID: &str = "R16";

/// `sqlparser`'s Oracle dialect does not yet parse Oracle 23ai's
/// `VECTOR_EMBEDDING(model USING :bind)` grammar. This recognizes only the
/// builtin's unqualified, identifier-and-positional-bind form and presents an
/// equivalent comma-argument form to the parser. Everything outside that
/// narrow shape remains unparseable and therefore fail-closed.
static VECTOR_EMBEDDING_USING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\bVECTOR_EMBEDDING\s*\(\s*([A-Z][A-Z0-9_$#]{0,29})\s+USING\s+(:[1-9][0-9]*)\s*\)",
    )
    .expect("VECTOR_EMBEDDING parser-normalization regex is valid")
});

fn normalize_vector_embedding_for_parser(sql: &str) -> Cow<'_, str> {
    VECTOR_EMBEDDING_USING_RE.replace_all(sql, "VECTOR_EMBEDDING($1, $2)")
}

impl VerdictCertificate {
    fn from_decision(sql: &str, decision: &GuardDecision) -> Self {
        let mut derivation = decision.certificate_derivation.clone();
        derivation.push(VerdictDerivationStep {
            construct: terminal_verdict_construct(decision.danger).to_owned(),
            rule_id: CERTIFICATE_TERMINAL_RULE_ID.to_owned(),
        });
        VerdictCertificate {
            stmt_digest: oraclemcp_audit::sha256_hex(sql.as_bytes()),
            level: decision.required_level,
            verdict: decision.danger,
            derivation,
            classifier_version: VERDICT_CERTIFICATE_CLASSIFIER_VERSION.to_owned(),
            observed_scn: None,
            bound_audit_hash: None,
        }
    }

    /// Return a copy carrying an Oracle-observed SCN in the canonical decimal
    /// wire form. The SCN remains inside the core hash, so callers must make
    /// this update before persisting that hash to the audit record.
    #[must_use]
    pub fn with_observed_scn(mut self, observed_scn: Option<u64>) -> Self {
        self.observed_scn = observed_scn.map(|scn| scn.to_string());
        self
    }

    /// Bind this response projection to a persisted audit entry only when that
    /// entry attests to the same SQL digest and certificate core. Callers must
    /// treat an error as fail-closed: returning an unbound certificate (or a
    /// read result that relies on it) would make the proof unverifiable.
    ///
    /// The audit record stores [`Self::core_hash`], not the returned
    /// `bound_audit_hash`, to keep the two hash domains non-circular.
    pub fn bind_to_persisted_audit(
        mut self,
        audit_sql_sha256: &str,
        audit_certificate_core_hash: Option<&str>,
        audit_entry_hash: &str,
    ) -> Result<Self, VerdictCertificateBindingError> {
        if self.stmt_digest != audit_sql_sha256 {
            return Err(VerdictCertificateBindingError::SqlDigestMismatch);
        }
        let certificate_core_hash = self.core_hash();
        if audit_certificate_core_hash != Some(certificate_core_hash.as_str()) {
            return Err(VerdictCertificateBindingError::CoreHashMismatch);
        }
        if !is_canonical_sha256(audit_entry_hash) {
            return Err(VerdictCertificateBindingError::InvalidAuditEntryHash);
        }
        self.bound_audit_hash = Some(audit_entry_hash.to_owned());
        Ok(self)
    }

    /// Compute the domain-separated SHA-256 over the RFC-8785-compatible core
    /// JSON. The core has only ASCII strings, `null`, and arrays of fixed
    /// labels, so `serde_json`'s compact serialization of this lexicographically
    /// ordered struct is JCS-equivalent without accepting arbitrary JSON values.
    #[must_use]
    pub fn core_hash(&self) -> String {
        #[derive(Serialize)]
        struct CertificateCore<'a> {
            classifier_version: &'a str,
            derivation: &'a [VerdictDerivationStep],
            level: Option<OperatingLevel>,
            observed_scn: &'a Option<String>,
            stmt_digest: &'a str,
            verdict: DangerLevel,
        }

        let core = CertificateCore {
            classifier_version: &self.classifier_version,
            derivation: &self.derivation,
            level: self.level,
            observed_scn: &self.observed_scn,
            stmt_digest: &self.stmt_digest,
            verdict: self.verdict,
        };
        let canonical = serde_json::to_vec(&core)
            .expect("verdict certificate core contains only infallibly serializable fields");
        let mut payload = Vec::with_capacity(CERTIFICATE_CORE_HASH_DOMAIN.len() + canonical.len());
        payload.extend_from_slice(CERTIFICATE_CORE_HASH_DOMAIN.as_bytes());
        payload.extend_from_slice(&canonical);
        oraclemcp_audit::sha256_hex(&payload)
    }

    /// Convert this guard-owned witness into the audit leaf's closed,
    /// redaction-safe persistence grammar. This is deliberately fallible: a
    /// future classifier branch cannot smuggle a new free-form derivation label
    /// onto the audit or HTTP surfaces before the immutable registry is updated.
    pub fn audit_certificate(
        &self,
    ) -> Result<
        oraclemcp_audit::AuditVerdictCertificate,
        oraclemcp_audit::AuditVerdictCertificateError,
    > {
        use oraclemcp_audit::{
            AuditVerdict, AuditVerdictConstruct, AuditVerdictDerivationStep,
            AuditVerdictOperatingLevel, AuditVerdictRuleId,
        };

        let derivation =
            self.derivation
                .iter()
                .map(|step| {
                    let rule_id = match step.rule_id.as_str() {
                        "R15" => AuditVerdictRuleId::R15,
                        "R16" => AuditVerdictRuleId::R16,
                        _ => return Err(
                            oraclemcp_audit::AuditVerdictCertificateError::UnregisteredDerivation,
                        ),
                    };
                    let construct = match step.construct.as_str() {
                        "routine_calls:absent" => AuditVerdictConstruct::RoutineCallsAbsent,
                        "routine_purity:all_proven_read_only" => {
                            AuditVerdictConstruct::RoutinePurityAllProvenReadOnly
                        }
                        "routine_purity:unproven_present" => {
                            AuditVerdictConstruct::RoutinePurityUnprovenPresent
                        }
                        "final_verdict:SAFE" => AuditVerdictConstruct::FinalSafe,
                        "final_verdict:GUARDED" => AuditVerdictConstruct::FinalGuarded,
                        "final_verdict:DESTRUCTIVE" => AuditVerdictConstruct::FinalDestructive,
                        "final_verdict:FORBIDDEN" => AuditVerdictConstruct::FinalForbidden,
                        _ => return Err(
                            oraclemcp_audit::AuditVerdictCertificateError::UnregisteredDerivation,
                        ),
                    };
                    AuditVerdictDerivationStep::new(rule_id, construct)
                })
                .collect::<Result<Vec<_>, _>>()?;
        let level = self.level.map(|level| match level {
            OperatingLevel::ReadOnly => AuditVerdictOperatingLevel::ReadOnly,
            OperatingLevel::ReadWrite => AuditVerdictOperatingLevel::ReadWrite,
            OperatingLevel::Ddl => AuditVerdictOperatingLevel::Ddl,
            OperatingLevel::Admin => AuditVerdictOperatingLevel::Admin,
        });
        let verdict = match self.verdict {
            DangerLevel::Safe => AuditVerdict::Safe,
            DangerLevel::Guarded => AuditVerdict::Guarded,
            DangerLevel::Destructive => AuditVerdict::Destructive,
            DangerLevel::Forbidden => AuditVerdict::Forbidden,
        };
        oraclemcp_audit::AuditVerdictCertificate::new(
            self.classifier_version.clone(),
            derivation,
            level,
            self.observed_scn.clone(),
            self.stmt_digest.clone(),
            verdict,
        )
    }
}

fn is_canonical_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn terminal_verdict_construct(danger: DangerLevel) -> &'static str {
    match danger {
        DangerLevel::Safe => "final_verdict:SAFE",
        DangerLevel::Guarded => "final_verdict:GUARDED",
        DangerLevel::Destructive => "final_verdict:DESTRUCTIVE",
        DangerLevel::Forbidden => "final_verdict:FORBIDDEN",
    }
}

/// What the guard decided about a statement batch (before the level gate).
#[derive(Clone, Debug, Eq)]
pub struct GuardDecision {
    /// The batch danger tier (max over statements).
    pub danger: DangerLevel,
    /// The operating level required to run it, or `None` if `Forbidden`.
    pub required_level: Option<OperatingLevel>,
    /// Object/routine names the batch touches (best-effort).
    pub objects_affected: Vec<String>,
    /// A safer alternative to suggest to the agent, if any.
    pub safe_alternative: Option<String>,
    /// Human/audit explanation of the decision.
    pub reason: String,
    /// Machine-stable category of *why* this decision refused or level-gated the
    /// statement (K8), or `None` for an allowed/safe decision. Additive and
    /// observational — it never affects the danger tier or required level.
    pub reason_category: Option<ReasonCategory>,
    /// The specific construct that triggered a refusal, when the guard can name
    /// it (a marker keyword, the matched block pattern, `BEGIN/END`, …). Never
    /// contains bind values or secrets.
    pub offending_construct: Option<String>,
    /// Whether successful evaluation can persist an effect even when the
    /// surrounding transaction is rolled back. Such statements need explicit
    /// execution confirmation even on the rollback-default path.
    pub non_transactional_effect: bool,
    /// Whether the permanent effect sits in a top-level query and therefore
    /// occurs only when query rows are fetched. The generic execute path must
    /// not report this effect as completed without driving that fetch.
    pub query_effect_requires_fetch: bool,
    /// Always populated by public [`Classifier::classify`]. The raw classifier
    /// keeps it absent while it builds a decision so every public certificate
    /// is derived from the exact final decision, not an early approximation.
    verdict_certificate: Option<VerdictCertificate>,
    /// Internal redacted rule facts accumulated by the exact classification
    /// branches that ran. They are copied into the public certificate only
    /// after the final decision is fixed.
    certificate_derivation: Vec<VerdictDerivationStep>,
}

impl PartialEq for GuardDecision {
    fn eq(&self, other: &Self) -> bool {
        self.danger == other.danger
            && self.required_level == other.required_level
            && self.objects_affected == other.objects_affected
            && self.safe_alternative == other.safe_alternative
            && self.reason == other.reason
            && self.reason_category == other.reason_category
            && self.offending_construct == other.offending_construct
            && self.non_transactional_effect == other.non_transactional_effect
            && self.query_effect_requires_fetch == other.query_effect_requires_fetch
    }
}

impl GuardDecision {
    /// The redacted certificate produced by the same call that returned this
    /// decision. This accessor cannot be absent for public classifications.
    #[must_use]
    pub fn verdict_certificate(&self) -> &VerdictCertificate {
        self.verdict_certificate
            .as_ref()
            .expect("public Classifier::classify must attach a verdict certificate")
    }

    fn with_verdict_certificate(mut self, certificate: VerdictCertificate) -> Self {
        self.verdict_certificate = Some(certificate);
        self
    }

    /// Gate the decision against a session's operating level (wires P1-1 into
    /// the P0-7 level core): classification runs *before* the step-up gate, so
    /// the required level is known when compared to the session's current level.
    #[must_use]
    pub fn gate(&self, session: &SessionLevelState) -> LevelDecision {
        session.evaluate(self.required_level)
    }

    /// Set the K8 structured-reason fields fluently (category + the construct
    /// that triggered the refusal). Purely additive: it touches neither the
    /// danger tier nor the required level.
    #[must_use]
    fn categorized(mut self, category: ReasonCategory, offending: Option<String>) -> Self {
        self.reason_category = Some(category);
        self.offending_construct = offending;
        self
    }
}

/// Operator-curated classifier configuration. The allow-list and block-list are
/// the operator's responsibility; neither weakens the fail-closed law for
/// anything they do not explicitly name.
#[derive(Clone, Default)]
pub struct ClassifierConfig {
    /// SHA-256 (hex) of exact statement bytes that are pre-approved as `Safe`.
    allow_list: HashSet<String>,
    /// Regexes that, if matched, force `Forbidden`.
    block_patterns: Vec<Regex>,
    /// When set, a `SELECT`/`WITH` carrying a **qualified, paren-less** identifier
    /// in value/expression position whose qualifier has no exact relation/alias
    /// prefix exposed by the current or correlated scope is treated as an
    /// unproven callable and forced `≥ Guarded` (bead .102). Oracle invokes a
    /// zero-arg function with no parentheses (`SELECT app_admin.run_ddl FROM
    /// dual` *calls* `run_ddl`), which the `ident(`-only `user_defined_calls`
    /// scan never sees. Default `false`
    /// (backward-compatible); the served/strict gate opts in. Over-restriction is
    /// the only cost — an in-scope `alias.column` is never flagged, and an
    /// attacker cannot alias their way out (`FROM dual app_admin` rebinds
    /// `app_admin.run_ddl` to a *column* of `dual`, not the function).
    guard_unresolved_qualified_calls: bool,
}

impl ClassifierConfig {
    /// An empty config (no allow/block entries).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The fail-closed **served/strict** preset: enable the qualified paren-less
    /// callable guard (bead .102). Pair with [`Classifier::served_strict`] (which
    /// additionally tightens statement-level `Unknown` purity, bead .82) for the
    /// full served posture.
    #[must_use]
    pub fn served_strict() -> Self {
        Self::default().with_unresolved_qualified_calls_guarded()
    }

    /// Opt into treating a qualified, paren-less identifier whose root qualifier
    /// is not in scope as an unproven callable → `≥ Guarded` (bead .102). See
    /// [`ClassifierConfig::guard_unresolved_qualified_calls`].
    #[must_use]
    pub fn with_unresolved_qualified_calls_guarded(mut self) -> Self {
        self.guard_unresolved_qualified_calls = true;
        self
    }

    /// Pre-approve one exact statement as `Safe`.
    #[must_use]
    pub fn with_allow(mut self, sql: &str) -> Self {
        self.allow_list.insert(exact_sha256(sql));
        self
    }

    /// Add a block-list regex (matched against the raw text, case-insensitive
    /// by the caller's pattern). Invalid patterns are ignored.
    #[must_use]
    pub fn with_block_pattern(mut self, pattern: &str) -> Self {
        if let Ok(re) = Regex::new(pattern) {
            self.block_patterns.push(re);
        }
        self
    }
}

/// Hash exact SQL bytes for operator allow-list binding.
///
/// Oracle quoted identifiers and literals preserve both case and whitespace,
/// so normalizing either property can make distinct statements collide.
fn exact_sha256(sql: &str) -> String {
    let digest = Sha256::digest(sql.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// PL/SQL side-effect markers that force fail-closed handling (P1-1a).
const PLSQL_SIDE_EFFECT_MARKERS: &[&str] = &[
    "EXECUTE IMMEDIATE",
    "DBMS_SQL",
    "UTL_FILE",
    "UTL_HTTP",
    "UTL_TCP",
    "UTL_SMTP",
    "DBMS_VECTOR",
    "DBMS_SCHEDULER",
    "DBMS_JOB",
    "PRAGMA AUTONOMOUS_TRANSACTION",
];

/// Return the exact caller-controlled transaction boundary present in `sql`.
/// The Oracle tokenizer keeps literals, q-quotes, comments, and quoted
/// identifiers out of the bare-word stream, so data containing the text
/// `COMMIT` is not confused with executable transaction control. Comments and
/// whitespace between `SET` and `TRANSACTION` are intentionally ignored.
fn transaction_control_construct(sql: &str) -> Option<&'static str> {
    // Keep the classifier hot path cheap: most SQL contains none of these
    // words, so avoid a second Oracle-tokenizer pass unless a case-insensitive
    // byte prefilter finds a candidate. The tokenizer below remains the source
    // of truth and removes literal/comment/quoted-identifier false positives.
    let candidate = [
        b"COMMIT".as_slice(),
        b"ROLLBACK",
        b"SAVEPOINT",
        b"TRANSACTION",
    ]
    .iter()
    .any(|needle| {
        sql.as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
    });
    if !candidate {
        return None;
    }

    let tokens = Tokenizer::new(&OracleDialect {}, sql).tokenize().ok()?;
    let mut previous_was_set = false;
    for token in &tokens {
        match token {
            Token::Whitespace(_) => continue,
            Token::Word(word) if word.quote_style.is_none() => {
                if previous_was_set && word.value.eq_ignore_ascii_case("TRANSACTION") {
                    return Some("SET TRANSACTION");
                }
                previous_was_set = word.value.eq_ignore_ascii_case("SET");
                if word.value.eq_ignore_ascii_case("COMMIT") {
                    return Some("COMMIT");
                }
                if word.value.eq_ignore_ascii_case("ROLLBACK") {
                    return Some("ROLLBACK");
                }
                if word.value.eq_ignore_ascii_case("SAVEPOINT") {
                    return Some("SAVEPOINT");
                }
            }
            _ => previous_was_set = false,
        }
    }
    None
}

/// Stage A outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageA {
    /// Operator allow-listed → clear to `Safe`.
    AllowListed,
    /// Block-list regex matched → `Forbidden`.
    BlockListed(String),
    /// Input is (or contains) a PL/SQL block → fail-closed handling.
    PlSqlBlock {
        /// Whether a dangerous side-effect marker was found.
        dangerous: bool,
    },
    /// Pure SQL → proceed to the splitter + Stage B.
    PureSql,
}

/// Canonicalize PL/SQL text for the Stage A marker scan: tokenize with the
/// Oracle dialect (so string/`q'[…]'`/quoted-identifier literals are single
/// tokens and their contents are never mistaken for keywords), drop all
/// whitespace **and comment** tokens (both are `Token::Whitespace(_)` —
/// `--`/`/* … */`), uppercase every *bare* word token, and join the
/// significant tokens with a single space. Every non-word significant token
/// (punctuation, operator, string/number/quoted-identifier literal) collapses
/// to a sentinel (`\u{1}`) that can never appear inside a marker, so two words
/// separated by punctuation (`EXECUTE; IMMEDIATE`) never read as adjacent.
///
/// This is what closes the headline evasion (oracle-rwjl.1): a comment, extra
/// space, tab, or newline wedged between the two keywords of a multi-word
/// marker (`EXECUTE/**/IMMEDIATE`, `PRAGMA  AUTONOMOUS_TRANSACTION`) used to
/// defeat the literal substring scan over the merely-uppercased source and
/// silently downgrade a Forbidden dynamic-SQL / autonomous-transaction block to
/// Guarded. The canonical form makes the two keywords adjacent again, so the
/// marker scan re-catches them. Tokenization failure (e.g. an unterminated
/// literal) is fail-closed: we fall back to the raw uppercase source so the
/// scan still sees whatever markers survived in the clear.
///
/// The result is space-padded on both ends so a marker is found whether it sits
/// at the start, middle, or end of the block.
fn canonical_marker_scan(upper_source: &str) -> String {
    let dialect = OracleDialect {};
    let Ok(tokens) = Tokenizer::new(&dialect, upper_source).tokenize() else {
        // Fail-closed: an untokenizable block falls back to the raw uppercase
        // text so the literal substring scan still runs against what survives.
        return format!(" {upper_source} ");
    };
    // Sentinel for any significant non-word token: a control char that can
    // never appear inside a marker, keeping punctuation-separated words apart.
    const SEP: &str = "\u{1}";
    let mut parts: Vec<String> = Vec::with_capacity(tokens.len());
    for token in &tokens {
        match token {
            // Whitespace AND comments (`--`, `/* */`) are token separators only.
            Token::Whitespace(_) => {}
            // A bare (un-quoted) word contributes its uppercase value; a quoted
            // identifier (`"EXECUTE"`) is data, never a keyword → sentinel.
            Token::Word(w) if w.quote_style.is_none() => {
                parts.push(w.value.to_ascii_uppercase());
            }
            _ => parts.push(SEP.to_owned()),
        }
    }
    format!(" {} ", parts.join(" "))
}

/// Extract the distinct **named bind placeholders** (`:name`) referenced by
/// `sql`, in first-appearance order, using the *same* fail-closed Oracle
/// tokenizer the classifier itself uses. This is a read-only projection of the
/// token stream — it NEVER participates in, and can never loosen, a
/// classification/enforcement decision; it only reports which bind identifiers a
/// body mentions so callers (e.g. custom-tool loading) can reject a definition
/// whose declared parameters do not match its binds *at load time* instead of on
/// every Oracle round trip.
///
/// Because the tokenizer treats string/`q'[…]'`/`n'…'` literals, `"quoted
/// identifiers"`, and `--` / `/* … */` comments as single opaque tokens, a colon
/// buried inside any of them can never register as a bind. PL/SQL assignment
/// (`:=`, `Token::Assignment`) and PostgreSQL-style casts (`::`,
/// `Token::DoubleColon`) are distinct tokens from a bare `Token::Colon`, so they
/// never register either. Only a `Token::Colon` *immediately* followed (no
/// intervening whitespace) by a bare, unquoted word is a named bind; positional
/// binds (`:1`) and quoted bind names (`:"X"`) are ignored because they cannot be
/// declared as simple identifier parameters.
///
/// Names are returned **uppercased** because Oracle bind names are
/// case-insensitive (`:Id` and `:ID` denote the same bind), so callers can do a
/// case-insensitive set comparison. Tokenization failure is fail-closed for the
/// caller: an empty set makes every declared parameter read as unmatched, so a
/// body the tokenizer cannot lex is rejected rather than silently accepted.
#[must_use]
pub fn named_bind_placeholders(sql: &str) -> Vec<String> {
    let dialect = OracleDialect {};
    let Ok(tokens) = Tokenizer::new(&dialect, sql).tokenize() else {
        return Vec::new();
    };
    let mut binds: Vec<String> = Vec::new();
    let mut after_colon = false;
    for token in &tokens {
        // A bind is a bare `:` glued to the very next token being an unquoted
        // word. `after_colon` is the previous token; recompute it for the next
        // iteration *before* the check so a word only counts when it directly
        // follows the colon (any intervening whitespace token clears the flag).
        if let Token::Word(w) = token
            && after_colon
            && w.quote_style.is_none()
        {
            let name = w.value.to_ascii_uppercase();
            if !binds.contains(&name) {
                binds.push(name);
            }
        }
        after_colon = matches!(token, Token::Colon);
    }
    binds
}

/// Statement-leading admin/DCL verb sequences that require `OperatingLevel::Admin`
/// (levels.rs:37 — "GRANT / REVOKE, ALTER USER/SYSTEM, cross-schema DCL"). These
/// are matched against the *canonicalized* token stream produced by
/// [`canonical_marker_scan`] — uppercased bare words joined by single spaces and
/// space-padded on both ends — and only when they sit at the **start** of the
/// statement (the canonical form begins with `" "` then the first token). Each
/// entry is therefore the leading-token sequence with a single trailing space, so
/// the match is WORD-BOUNDARED: `"GRANT "` matches `GRANT DBA TO scott` but never
/// a column/identifier whose name merely begins with the letters `GRANT`
/// (`GRANTED_FLAG` tokenizes to the single word `GRANTED_FLAG`, not `GRANT`), and
/// never a non-leading occurrence buried inside a larger statement. Quoted
/// identifiers and literals are already collapsed to a sentinel by
/// `canonical_marker_scan`, so they can never smuggle a keyword into this scan.
///
/// This is the fail-CLOSED admin floor for the parse-failure branch
/// (oracle-clgt.3): sqlparser 0.62 cannot parse most Oracle admin/DCL
/// (`GRANT DBA`, `ALTER USER … IDENTIFIED BY`, `ALTER SYSTEM/DATABASE/PROFILE`,
/// `AUDIT`/`NOAUDIT`, `CREATE/ALTER USER`, `ALTER ROLE`, …), and the old
/// parse-failure default under-levelled every one of them to `ReadWrite`, letting
/// a ReadWrite-elevated session run privilege-escalation DCL with no Admin
/// step-up. A leading admin verb here forces `Destructive` / `Admin` instead.
const LEADING_ADMIN_VERBS: &[&str] = &[
    "GRANT ",
    "REVOKE ",
    "AUDIT ",
    "NOAUDIT ",
    "CREATE USER ",
    "ALTER USER ",
    "DROP USER ",
    "CREATE ROLE ",
    "ALTER ROLE ",
    "DROP ROLE ",
    // Profiles govern login/password/resource policy for users. CREATE and DROP
    // need the same Admin floor as the already-covered ALTER PROFILE; treating
    // them as ordinary object DDL lets a DDL-only profile reshape account
    // security policy.
    "CREATE PROFILE ",
    "ALTER SYSTEM ",
    "ALTER DATABASE ",
    "ALTER PROFILE ",
    "DROP PROFILE ",
    // CREATE SCHEMA may embed GRANT statements. Whole-database and PDB
    // lifecycle statements require administrative database privileges and can
    // create, move, or delete data files; none belongs to the object-DDL tier.
    "CREATE SCHEMA ",
    "CREATE DATABASE ",
    "DROP DATABASE ",
    "CREATE PLUGGABLE DATABASE ",
    "ALTER PLUGGABLE DATABASE ",
    "DROP PLUGGABLE DATABASE ",
    // Audit and lockdown policies alter security posture rather than one
    // schema object. sqlparser does not reliably recognize the Oracle forms,
    // so preserve their Admin floor independently of parser success.
    "CREATE AUDIT POLICY ",
    "ALTER AUDIT POLICY ",
    "DROP AUDIT POLICY ",
    "CREATE LOCKDOWN PROFILE ",
    "ALTER LOCKDOWN PROFILE ",
    "DROP LOCKDOWN PROFILE ",
    "SET ROLE ",
    // FLASHBACK of an entire (pluggable) database is a server-wide point-in-time
    // rewind — strictly an Admin operation, not object DDL. The shorter
    // `FLASHBACK TABLE`/`FLASHBACK STANDBY …` forms stay at the Ddl floor below
    // (see LEADING_DDL_VERBS). The admin scan runs FIRST in the parse-failure
    // arm, so `FLASHBACK DATABASE` / `FLASHBACK PLUGGABLE DATABASE` resolve here
    // (Admin) before the broader leading `FLASHBACK ` Ddl match could fire.
    "FLASHBACK DATABASE ",
    "FLASHBACK PLUGGABLE DATABASE ",
];

/// Statement-leading object-level destructive DDL verb sequences that require
/// `OperatingLevel::Ddl` (levels.rs:36/115 — Destructive maps to the Ddl floor).
/// Matched against the *canonicalized* token stream produced by
/// [`canonical_marker_scan`] (uppercased bare words joined by single spaces,
/// space-padded), word-boundaried, and only at the statement-leading position —
/// exactly like [`LEADING_ADMIN_VERBS`].
///
/// sqlparser 0.62 cannot parse these irreversible Oracle DDL forms, so the
/// parse-failure branch of [`classify_statement`] used to under-level every one
/// of them to Guarded/ReadWrite — letting a ReadWrite-elevated session RENAME a
/// table, PURGE a table/recyclebin/tablespace, FLASHBACK a table back, or
/// (DIS)ASSOCIATE optimizer statistics with NO forced Ddl step-up, bypassing the
/// schema deny_ddl / guarded-destructive policy (oracle-j1ep.3). A leading DDL
/// verb here forces `Destructive` / `Ddl`. The trailing space enforces a word
/// boundary so a column/identifier whose name merely begins with these letters
/// (`PURGED_AT`, `RENAMED_FLAG`) never matches, and the leading-only anchor keeps
/// a non-leading occurrence (`SELECT billing.purge() FROM dual`) at Guarded.
const LEADING_DDL_VERBS: &[&str] = &[
    "RENAME ",
    "PURGE ",
    "FLASHBACK ",
    "ASSOCIATE STATISTICS ",
    "DISASSOCIATE STATISTICS ",
    // Object DDL that Oracle implicit-commits and that sqlparser 0.62 either
    // cannot parse (DROP SYNONYM/TABLESPACE/DIRECTORY) or parses to a variant the
    // pre-.84 catch-all under-levelled to ReadWrite (COMMENT ON, ANALYZE,
    // TRUNCATE). A leading `COMMENT `/`ANALYZE ` unambiguously names the DDL form —
    // no read statement starts with them — so, unlike the buried scan, matching
    // them at the statement-leading position never over-restricts a legitimate
    // read whose column merely happens to be named COMMENT/ANALYZE (bead
    // QA100 .84). `DROP ` here floors every non-account object DROP at Ddl; the
    // account/role DROPs (DROP USER / DROP ROLE) are resolved to Admin by the
    // admin scan that every caller runs FIRST.
    "COMMENT ",
    "ANALYZE ",
    "TRUNCATE ",
    "DROP ",
    // Any leading `CREATE <object>` that reaches the parse-failure branch is an
    // unparseable object DDL form sqlparser 0.62 cannot handle (CREATE [OR
    // REPLACE] SYNONYM / DIRECTORY / TYPE / CONTEXT / MATERIALIZED VIEW / …).
    // Without this it under-levelled to Guarded/ReadWrite, the same fail-open
    // class as the RENAME/PURGE forms above (oracle-y54x.1). Admin-level CREATE
    // forms (CREATE USER / CREATE ROLE) are caught by the admin scan that runs
    // FIRST in the parse-failure arm, so they resolve to Admin before this
    // broader leading `CREATE ` match can fire. PL/SQL-bearing creates
    // (PROCEDURE/FUNCTION/PACKAGE/TRIGGER) are intercepted by Stage A and never
    // reach this branch; parseable creates (VIEW/TABLE/INDEX) are tiered Ddl by
    // Stage B.
    "CREATE ",
];

/// Leading `CREATE [OR REPLACE] <object>` forms whose object body carries
/// PL/SQL and must take the fail-closed PL/SQL-block path in [`stage_a`].
/// Matched against the canonical token stream produced by
/// [`canonical_marker_scan`] (uppercased bare words joined by single spaces,
/// word-boundaried by the trailing space) so inter-keyword whitespace/comments
/// (`CREATE  OR /*x*/ REPLACE  PROCEDURE`) cannot split the multi-word marker.
///
/// PURE-DDL replace forms (VIEW / SYNONYM / TYPE / DIRECTORY / …) are
/// deliberately ABSENT: they carry no PL/SQL, so routing them through the
/// non-dangerous PL/SQL-block arm floored them at Guarded/ReadWrite — strictly
/// below the Destructive/Ddl their plain `CREATE …` counterparts earn via Stage
/// B (`Statement::CreateView`) / the parse-failure leading-`CREATE ` DDL floor.
/// That inverted, fail-open tier for an object-clobbering replace is the defect
/// this set fixes (oracle-y54x.1). A side-effect-bearing object body (e.g. a
/// `CREATE TYPE BODY` containing `EXECUTE IMMEDIATE`) is still caught by the
/// `dangerous` marker scan in [`stage_a`], independent of this list.
const PLSQL_BEARING_CREATE_FORMS: &[&str] = &[
    "CREATE PACKAGE ",
    "CREATE OR REPLACE PACKAGE ",
    "CREATE FUNCTION ",
    "CREATE OR REPLACE FUNCTION ",
    "CREATE PROCEDURE ",
    "CREATE OR REPLACE PROCEDURE ",
    "CREATE TRIGGER ",
    "CREATE OR REPLACE TRIGGER ",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoredUnitKind {
    PackageSpec,
    PackageBody,
    TypeBody,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredUnitCreate {
    kind: StoredUnitKind,
    /// Canonical token identity of the unit's unqualified object name. Quoted
    /// and unquoted names intentionally occupy distinct namespaces.
    end_name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PackageSubprogramHeader {
    Declaration,
    AfterAsOrIs,
    AfterLanguage,
    PlSqlBody,
    CallSpec,
}

fn identifier_key(token: &Token) -> Option<String> {
    let Token::Word(word) = token else {
        return None;
    };
    Some(if word.quote_style.is_some() {
        format!("Q:{}", word.value)
    } else {
        format!("U:{}", word.value.to_ascii_uppercase())
    })
}

/// Recognize the stored declaration units whose member semicolons and final
/// named `END` belong to one `CREATE` statement. The result also captures the
/// unqualified object name so only the unit's real optional end-name is accepted
/// after the outer `END`; an arbitrary trailing keyword cannot masquerade as it.
///
/// Keep this token-aware. Comments and arbitrary whitespace are valid between
/// header keywords, while quoted identifiers and literals must never be
/// mistaken for `PACKAGE`, `TYPE`, or `BODY` keywords.
fn stored_unit_create(sql: &str) -> Option<StoredUnitCreate> {
    let Ok(tokens) = Tokenizer::new(&OracleDialect {}, sql).tokenize() else {
        return None;
    };
    let tokens: Vec<&Token> = tokens
        .iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .collect();
    let bare_word_is = |idx: usize, expected: &str| {
        matches!(
            tokens.get(idx),
            Some(Token::Word(word))
                if word.quote_style.is_none() && word.value.eq_ignore_ascii_case(expected)
        )
    };

    if !bare_word_is(0, "CREATE") {
        return None;
    }
    let mut idx = 1;
    if bare_word_is(idx, "OR") {
        if !bare_word_is(idx + 1, "REPLACE") {
            return None;
        }
        idx += 2;
    }
    if bare_word_is(idx, "EDITIONABLE") || bare_word_is(idx, "NONEDITIONABLE") {
        idx += 1;
    }
    let kind = if bare_word_is(idx, "PACKAGE") {
        idx += 1;
        if bare_word_is(idx, "BODY") {
            idx += 1;
            StoredUnitKind::PackageBody
        } else {
            StoredUnitKind::PackageSpec
        }
    } else if bare_word_is(idx, "TYPE") && bare_word_is(idx + 1, "BODY") {
        idx += 2;
        StoredUnitKind::TypeBody
    } else {
        return None;
    };

    let mut end_name = identifier_key(tokens.get(idx).copied()?)?;
    if matches!(tokens.get(idx + 1), Some(Token::Period)) {
        end_name = identifier_key(tokens.get(idx + 2).copied()?)?;
    }
    Some(StoredUnitCreate { kind, end_name })
}

fn stored_unit_final_end(tokens: &[Token], unit: &StoredUnitCreate) -> Option<usize> {
    let significant: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter_map(|(idx, token)| (!matches!(token, Token::Whitespace(_))).then_some(idx))
        .collect();
    let mut pos = significant.len().checked_sub(1)?;
    if matches!(tokens.get(significant[pos]), Some(Token::Div)) {
        pos = pos.checked_sub(1)?;
    }
    if !matches!(tokens.get(significant[pos]), Some(Token::SemiColon)) {
        return None;
    }
    pos = pos.checked_sub(1)?;
    if identifier_key(tokens.get(significant[pos])?).as_ref() == Some(&unit.end_name) {
        pos = pos.checked_sub(1)?;
    }
    let end_idx = significant[pos];
    matches!(tokens.get(end_idx), Some(Token::Word(word))
        if word.quote_style.is_none() && word.value.eq_ignore_ascii_case("END"))
    .then_some(end_idx)
}

/// Whether the structural `END` matching `tokens[begin_idx]` is exactly the
/// stored unit's final terminator. This mirrors the analyzer's BEGIN/END and
/// END-IF/LOOP/CASE rules and deliberately ignores literals/comments/quoted
/// identifiers. It lets a PACKAGE BODY initialization section share the final
/// unit END without suppressing member or nested BEGIN depth.
fn begin_matches_final_end(tokens: &[Token], begin_idx: usize, final_end_idx: usize) -> bool {
    let mut depth = 0i64;
    let mut expecting_close = false;
    for (idx, token) in tokens
        .iter()
        .enumerate()
        .take(final_end_idx + 1)
        .skip(begin_idx)
    {
        match token {
            Token::Word(word) if word.quote_style.is_none() => {
                match word.value.to_ascii_uppercase().as_str() {
                    "BEGIN" => {
                        depth += 1;
                        expecting_close = false;
                    }
                    "IF" | "CASE" | "LOOP" => {
                        if !expecting_close {
                            depth += 1;
                        }
                        expecting_close = false;
                    }
                    "END" => {
                        depth -= 1;
                        if depth == 0 {
                            return idx == final_end_idx;
                        }
                        if depth < 0 {
                            return false;
                        }
                        expecting_close = true;
                    }
                    _ => expecting_close = false,
                }
            }
            Token::Whitespace(_) => {}
            _ => expecting_close = false,
        }
    }
    false
}

/// Whether the statement is a PL/SQL-bearing `CREATE [OR REPLACE]` of a stored
/// object (PROCEDURE/FUNCTION/PACKAGE/TRIGGER). A pure function of the SQL text
/// (canonical marker scan + [`PLSQL_BEARING_CREATE_FORMS`]) so `stage_a` (block
/// detection) and `Classifier::classify` (the `OperatingLevel::Ddl` floor,
/// oracle-p0d6) derive it IDENTICALLY from a single source — without threading
/// it through the public `StageA` enum (which would be a breaking API change for
/// an internal classifier detail).
fn is_plsql_bearing_create(sql: &str) -> bool {
    if stored_unit_create(sql).is_some() {
        return true;
    }
    let upper = sql.trim_start().to_ascii_uppercase();
    let scan = canonical_marker_scan(&upper);
    let leading = scan.strip_prefix(' ').unwrap_or(&scan);
    PLSQL_BEARING_CREATE_FORMS
        .iter()
        .any(|f| leading.starts_with(f))
}

/// Whether the (already-uppercased) statement text begins with an admin/DCL verb
/// requiring `OperatingLevel::Admin`. Runs over [`canonical_marker_scan`] so the
/// match is literal/quote-aware and word-boundaried (see [`LEADING_ADMIN_VERBS`]).
/// Used by the parse-failure branch of [`classify_statement`] so an unparseable
/// admin statement fails CLOSED to Admin rather than under-levelling to ReadWrite
/// (oracle-clgt.3).
fn starts_with_admin_verb(upper_source: &str) -> bool {
    let scan = canonical_marker_scan(upper_source);
    // `scan` is `" TOK1 TOK2 … "`; strip the leading pad so a leading verb sits
    // at offset 0 and the trailing space in each pattern enforces a word boundary.
    let leading = scan.strip_prefix(' ').unwrap_or(&scan);
    LEADING_ADMIN_VERBS.iter().any(|v| leading.starts_with(v))
}

/// Whether the (already-uppercased) statement text begins with an object-level
/// destructive DDL verb requiring `OperatingLevel::Ddl`. Runs over
/// [`canonical_marker_scan`] so the match is literal/quote-aware and
/// word-boundaried (see [`LEADING_DDL_VERBS`]). Used by the parse-failure branch
/// of [`classify_statement`], AFTER the admin-verb scan, so an unparseable
/// destructive DDL statement fails CLOSED to Destructive/Ddl rather than
/// under-levelling to Guarded/ReadWrite (oracle-j1ep.3).
fn starts_with_ddl_verb(upper_source: &str) -> bool {
    let scan = canonical_marker_scan(upper_source);
    // `scan` is `" TOK1 TOK2 … "`; strip the leading pad so a leading verb sits
    // at offset 0 and the trailing space in each pattern enforces a word boundary.
    let leading = scan.strip_prefix(' ').unwrap_or(&scan);
    if LEADING_DDL_VERBS.iter().any(|v| leading.starts_with(v)) {
        return true;
    }
    // Generic `ALTER <object>` (ALTER TABLE/INDEX/VIEW/SEQUENCE/TRIGGER/TYPE/
    // TABLESPACE/MATERIALIZED VIEW/…) is object DDL that sqlparser 0.62 largely
    // cannot parse; floor it at Ddl instead of letting it under-level to ReadWrite
    // (bead QA100 .84). The admin-scope ALTER forms (USER/SYSTEM/DATABASE/PROFILE/
    // ROLE) are resolved to Admin by `starts_with_admin_verb`, which every caller
    // runs FIRST, so they never reach this generic arm. `ALTER SESSION SET …` is
    // deliberately EXCLUDED: its safe-parameter policy is owned separately and it
    // keeps its existing ReadWrite floor — this scan must not change it.
    leading.starts_with("ALTER ") && !leading.starts_with("ALTER SESSION ")
}

/// Destructive / privilege / DML verbs that, when they appear at a NON-leading
/// position inside an *unparseable* single SQL segment, signal a buried second
/// statement smuggled in without a top-level `;` (whitespace / newline / SQL*Plus
/// `/` separated — e.g. `SELECT 1 FROM dual <nl> DROP TABLE t`). Space-padded so
/// the match over [`canonical_marker_scan`] is word-boundaried (the canonicalizer
/// collapses inter-keyword whitespace, so multi-word markers like `SET ROLE` /
/// `ASSOCIATE STATISTICS` match too).
///
/// This MUST stay symmetric with every verb the leading-position scans escalate
/// ([`LEADING_ADMIN_VERBS`] + [`LEADING_DDL_VERBS`]): a verb that fails closed
/// when leading but not when buried is an asymmetric fail-open (oracle-qo1v.1 —
/// the initial set omitted `SET ROLE`/`PURGE`/`FLASHBACK`/`(DIS)ASSOCIATE
/// STATISTICS`, letting `SELECT 1 FROM dual <nl> SET ROLE dba` slip through to
/// Guarded/ReadWrite). `SET` alone is deliberately NOT listed — it would
/// over-trigger on a benign buried `UPDATE … SET`; only the two-word `SET ROLE`
/// DCL form is dangerous, mirroring `LEADING_ADMIN_VERBS`.
const BURIED_DANGEROUS_VERBS: &[&str] = &[
    " GRANT ",
    " REVOKE ",
    " AUDIT ",
    " NOAUDIT ",
    " DROP ",
    " TRUNCATE ",
    " ALTER ",
    " CREATE ",
    " RENAME ",
    " UPDATE ",
    " DELETE ",
    " INSERT ",
    " MERGE ",
    " SET ROLE ",
    " PURGE ",
    " FLASHBACK ",
    " ASSOCIATE STATISTICS ",
    " DISASSOCIATE STATISTICS ",
];

/// Whether the canonical token stream of an unparseable single SQL segment
/// carries a destructive/privilege/DML verb at a NON-leading position. This is
/// the pure-SQL analog of the buried-`;` desync (`saw_buried_semicolon`) and the
/// trailing-SQL-after-`END` desync (`saw_top_level_after_block_close`): a no-`;`
/// batch leads with a benign `SELECT` (so the leading admin/DDL scans do not
/// fire) yet buries a `GRANT DBA`/`DROP`/`TRUNCATE`/no-WHERE `UPDATE`/… after it,
/// and would otherwise fall through to the Guarded/ReadWrite default. Failing
/// closed here keeps the `;`-vs-no-`;` forms symmetric (oracle-b6yl.1).
///
/// Only the INTERIOR is scanned: a statement's own LEADING verb (its legitimate
/// DML/DDL head — already tiered by the leading-verb scans or the Guarded
/// default) is stripped first, so a merely-unparseable but single legitimate
/// `UPDATE`/`MERGE`/… is not over-restricted to Forbidden.
fn has_buried_dangerous_verb(upper_source: &str) -> bool {
    let scan = canonical_marker_scan(upper_source);
    let leading = scan.strip_prefix(' ').unwrap_or(&scan); // "TOK1 TOK2 … "
    // The interior is everything from the space after the first token onward
    // (keeping that space so each pattern's leading space still word-boundaries).
    match leading.find(' ') {
        Some(sp) => {
            let interior = &leading[sp..];
            BURIED_DANGEROUS_VERBS.iter().any(|v| interior.contains(v))
        }
        None => false, // a single token — nothing buried
    }
}

/// Run Stage A: allow-list → block-list → PL/SQL-block detection.
#[must_use]
pub fn stage_a(sql: &str, config: &ClassifierConfig) -> StageA {
    // Skip the SHA-256 + hex hash entirely when there is nothing to match
    // against (the default: no operator-configured allow-list). An empty
    // set can never contain the digest, so this short-circuit is behavior-
    // identical yet removes the per-statement hashing cost on the hot path.
    if !config.allow_list.is_empty() && config.allow_list.contains(&exact_sha256(sql)) {
        return StageA::AllowListed;
    }
    for re in &config.block_patterns {
        if re.is_match(sql) {
            return StageA::BlockListed(re.as_str().to_owned());
        }
    }
    let upper = sql.trim_start().to_ascii_uppercase();
    // Scan a canonicalized (comment-stripped, whitespace-collapsed, token-aware)
    // form so a comment/space/tab/newline wedged between the two keywords of a
    // multi-word marker cannot split it and evade the fail-closed scan
    // (oracle-rwjl.1). Single-token markers (DBMS_SQL/UTL_FILE/…) match either
    // way; they contain no internal whitespace.
    let scan = canonical_marker_scan(&upper);
    // Only PL/SQL-bearing CREATE forms take the fail-closed PL/SQL-block path;
    // pure-DDL replace forms fall through so Stage B / the DDL floor tiers them
    // Destructive/Ddl rather than under-levelling them to Guarded/ReadWrite (see
    // [`PLSQL_BEARING_CREATE_FORMS`] — oracle-y54x.1).
    // A PL/SQL-bearing `CREATE [OR REPLACE] <object>` REPLACES a stored object
    // and is DDL. Tracked separately from the anonymous-block detectors so the
    // `Classifier::classify` caller can floor it at `OperatingLevel::Ddl`
    // (oracle-p0d6) — the same object-clobbering-replace fail-open-tier fix
    // oracle-y54x.1 applied to the pure-DDL create forms — while leaving an
    // anonymous `DECLARE`/`BEGIN` block at its body-derived `ReadWrite` floor.
    let plsql_create = is_plsql_bearing_create(sql);
    let starts_block = upper.starts_with("DECLARE")
        || upper.starts_with("BEGIN")
        || sql.trim() == "/"
        || plsql_create;
    let dangerous = PLSQL_SIDE_EFFECT_MARKERS.iter().any(|m| scan.contains(m));
    if starts_block || dangerous {
        return StageA::PlSqlBlock { dangerous };
    }
    StageA::PureSql
}

/// The lexer-level shape of a batch (P1-1c).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchShape {
    /// Whether `BEGIN`/`END`/`CASE`/`IF`/`LOOP` nesting balanced (returned to 0
    /// and never went negative). A desync means a hidden boundary → `Forbidden`.
    pub balanced: bool,
    /// Whether any PL/SQL block keyword (`BEGIN`/`DECLARE`) was seen.
    pub has_plsql_block: bool,
    /// Count of depth-0 statements (non-empty segments between `;` boundaries).
    pub statement_count: usize,
    /// Whether a `;` was seen at block depth > 0. In a *pure-SQL* batch (StageA
    /// returned `PureSql`, i.e. no PL/SQL block) this is always a desync: a `;`
    /// can only legitimately nest inside a real `BEGIN`/`DECLARE` block, so a
    /// buried `;` here means a keyword-collision identifier or an unbalanced SQL
    /// `CASE`/`IF`/`LOOP` swallowed a real top-level boundary. The pure-SQL
    /// caller forces `Forbidden` on this (oracle-73t1.1 / oracle-73t1.5). The
    /// internal `has_plsql_block` flag is NOT trusted for this decision because a
    /// bare `BEGIN`/`DECLARE` used as a SQL alias falsely flips it.
    pub saw_buried_semicolon: bool,
    /// Whether — after a PL/SQL block body has *opened* (a `BEGIN` drove depth to
    /// ≥ 1) and its `END` returned depth to 0 — any further *significant*
    /// top-level token (a word/punctuation/literal that is not the SQL*Plus `/`
    /// run terminator, a statement-terminating `;`, whitespace, or a comment)
    /// appears at depth 0. This is the trailing-SQL-after-`END` signature
    /// (oracle-lokg.1): `BEGIN NULL; END; GRANT DBA TO scott` parses as a single
    /// balanced anonymous block to the depth counter, so the trailing
    /// `GRANT`/`DROP`/`TRUNCATE` would be silently dropped from classification and
    /// run with no Admin/DDL step-up. The `StageA::PlSqlBlock` caller forces
    /// `Forbidden` on this. Unlike `has_plsql_block`, this only arms once a real
    /// block body opened and closed, so a leading `DECLARE … ;` section (which
    /// sets `has_plsql_block` but never raises depth) can never falsely trip it.
    pub saw_top_level_after_block_close: bool,
}

/// Tokenize with the Oracle dialect (so `'…'`/`q'[…]'`/`N'…'`/`"…"` are single
/// tokens) and compute the batch shape. Literal-embedded `;`/`BEGIN`/`END` are
/// never counted because they are inside a single string/identifier token.
#[must_use]
pub fn analyze_batch(sql: &str) -> BatchShape {
    let dialect = OracleDialect {};
    let Ok(tokens) = Tokenizer::new(&dialect, sql).tokenize() else {
        // Tokenization failure (e.g. an unterminated literal) is fail-closed:
        // report imbalance so the orchestrator treats the batch as Forbidden.
        return BatchShape {
            balanced: false,
            has_plsql_block: false,
            statement_count: 0,
            saw_buried_semicolon: false,
            saw_top_level_after_block_close: false,
        };
    };
    // Stored package/type units have an implicit outer scope: member declaration
    // semicolons are internal, and the unit-closing END balances that scope
    // without a matching executable BEGIN. This is equally true of package
    // specifications, package bodies, and type bodies.
    let stored_unit = stored_unit_create(sql);
    let stored_unit_final_end = stored_unit
        .as_ref()
        .and_then(|unit| stored_unit_final_end(&tokens, unit));
    let is_package_body = stored_unit
        .as_ref()
        .is_some_and(|unit| unit.kind == StoredUnitKind::PackageBody);
    let mut depth: i64 = i64::from(stored_unit.is_some());
    let mut went_negative = false;
    let mut has_plsql_block = false;
    let mut segment_has_content = false;
    let mut statement_count = 0usize;
    // A `;` seen while `depth > 0`. In pure SQL (StageA::PureSql) a `;` is
    // *always* a top-level statement terminator — it never legitimately nests
    // inside a `CASE`/`IF`/`LOOP` expression. A buried `;` in that context means
    // the depth counter was inflated by a keyword-collision identifier (e.g.
    // `SELECT 1 AS loop FROM dual; DROP TABLE orders; END;`) or an unbalanced SQL
    // `CASE` (`SELECT CASE WHEN 1=1 THEN 1 FROM dual ; DROP TABLE t END`),
    // swallowing the real top-level `;` boundary and letting a trailing `END`
    // rebalance the batch to a single Guarded statement. We surface it on
    // `BatchShape` so the pure-SQL caller can fire the fail-closed desync law
    // (oracle-73t1.1 / oracle-73t1.5).
    let mut saw_buried_semicolon = false;
    // Trailing-SQL-after-`END` tracking (oracle-lokg.1). `block_body_opened`
    // arms once a `BEGIN` drives depth to ≥ 1 (a *real* anonymous-block body,
    // not a leading `DECLARE` section, which never raises depth). Once such a
    // body's `END` returns depth to 0, any further significant top-level token
    // (not the SQL*Plus `/` terminator, a statement `;`, whitespace, or a
    // comment) is trailing top-level SQL smuggled after the block close — the
    // depth counter rebalanced to 0 and would otherwise hide a
    // GRANT/DROP/TRUNCATE from classification. We surface it so the
    // `StageA::PlSqlBlock` caller can fail closed.
    let mut block_body_opened = false;
    let mut saw_top_level_after_block_close = false;
    // Once the implicit stored-unit scope closes, only its optional matching
    // unqualified object name, a terminator semicolon, and the SQL*Plus slash
    // are legal. This special state prevents `END member_name` and `END
    // unit_name` from looking like trailing SQL without granting arbitrary
    // trailing words the same exception.
    let mut stored_unit_closed = false;
    let mut stored_unit_end_name_seen = false;
    let mut stored_unit_terminated = false;
    // A package body may end with an optional initialization section whose
    // `BEGIN ... END package_name;` is simultaneously the executable section
    // and the outer unit terminator. Track open member/local subprogram headers
    // so only a terminal, non-subprogram BEGIN receives that one-level shape
    // treatment. The header state also distinguishes a PL/SQL body from a
    // completed Java/C/MLE call specification: both use AS/IS, but only the
    // call specification legitimately ends at that member semicolon without a
    // BEGIN. A semicolon in Declaration is a forward declaration.
    let mut package_subprogram_headers: Vec<PackageSubprogramHeader> = Vec::new();
    let mut package_initialization_opened = false;
    // `END IF` / `END LOOP` / `END CASE` close one opener: the `END` decrements
    // and the trailing IF/LOOP/CASE must NOT re-increment. `expecting_close`
    // tracks "previous significant token was END" (whitespace does not reset it).
    let mut expecting_close = false;
    for (token_idx, token) in tokens.iter().enumerate() {
        match token {
            Token::Word(w) => {
                // A double-quoted (delimited) identifier — `w.quote_style.is_some()`,
                // e.g. `"BEGIN"` / `"END"` — is a column/table name, NOT a PL/SQL
                // structural keyword, so it must NEVER move the block-depth counter.
                // Ignoring quote_style let a quoted "BEGIN" inflate depth so a stray
                // top-level END rebalanced the batch and the fail-closed desync law
                // downgraded a Forbidden batch to Guarded. Only bare words count.
                let keyword = w
                    .quote_style
                    .is_none()
                    .then(|| w.value.to_ascii_uppercase());
                let is_matching_stored_unit_end_name = stored_unit_closed
                    && !stored_unit_end_name_seen
                    && !stored_unit_terminated
                    && identifier_key(token)
                        == stored_unit.as_ref().map(|unit| unit.end_name.clone());
                if is_matching_stored_unit_end_name {
                    stored_unit_end_name_seen = true;
                    expecting_close = false;
                    segment_has_content = true;
                    continue;
                }
                // A bare word at depth 0 *after* a block body opened and closed is
                // trailing top-level SQL smuggled after `END` (oracle-lokg.1). This
                // is evaluated against the depth *before* this token's own
                // structural effect, so a re-opening `BEGIN` (a second stacked
                // block) is caught too; a stray top-level `END` is already a desync
                // via `went_negative`.
                if (block_body_opened && depth == 0) || stored_unit_closed {
                    saw_top_level_after_block_close = true;
                }
                match keyword.as_deref() {
                    Some("BEGIN") => {
                        let package_initialization_begin = is_package_body
                            && depth == 1
                            && !package_initialization_opened
                            && package_subprogram_headers.is_empty()
                            && stored_unit_final_end.is_some_and(|final_end_idx| {
                                begin_matches_final_end(&tokens, token_idx, final_end_idx)
                            });
                        if package_initialization_begin {
                            package_initialization_opened = true;
                        } else {
                            depth += 1;
                            if is_package_body && depth == 2 {
                                package_subprogram_headers.pop();
                            }
                        }
                        has_plsql_block = true;
                        block_body_opened = true;
                        expecting_close = false;
                    }
                    Some("DECLARE") => {
                        has_plsql_block = true;
                        expecting_close = false;
                    }
                    Some("IF") | Some("CASE") | Some("LOOP") => {
                        if !expecting_close {
                            depth += 1;
                        }
                        expecting_close = false;
                    }
                    Some("END") => {
                        let closes_stored_unit = stored_unit.is_some() && depth == 1;
                        depth -= 1;
                        if depth < 0 {
                            went_negative = true;
                        }
                        if closes_stored_unit {
                            stored_unit_closed = true;
                        }
                        expecting_close = true;
                    }
                    Some("PROCEDURE" | "FUNCTION")
                        if is_package_body && depth == 1 && !package_initialization_opened =>
                    {
                        package_subprogram_headers.push(PackageSubprogramHeader::Declaration);
                        expecting_close = false;
                    }
                    Some("AS" | "IS")
                        if is_package_body
                            && depth == 1
                            && !package_initialization_opened
                            && package_subprogram_headers.last()
                                == Some(&PackageSubprogramHeader::Declaration) =>
                    {
                        if let Some(header) = package_subprogram_headers.last_mut() {
                            *header = PackageSubprogramHeader::AfterAsOrIs;
                        }
                        expecting_close = false;
                    }
                    Some("LANGUAGE")
                        if package_subprogram_headers.last()
                            == Some(&PackageSubprogramHeader::AfterAsOrIs) =>
                    {
                        if let Some(header) = package_subprogram_headers.last_mut() {
                            *header = PackageSubprogramHeader::AfterLanguage;
                        }
                        expecting_close = false;
                    }
                    Some("JAVA" | "C")
                        if package_subprogram_headers.last()
                            == Some(&PackageSubprogramHeader::AfterLanguage) =>
                    {
                        if let Some(header) = package_subprogram_headers.last_mut() {
                            *header = PackageSubprogramHeader::CallSpec;
                        }
                        expecting_close = false;
                    }
                    Some("EXTERNAL" | "MLE")
                        if package_subprogram_headers.last()
                            == Some(&PackageSubprogramHeader::AfterAsOrIs) =>
                    {
                        if let Some(header) = package_subprogram_headers.last_mut() {
                            *header = PackageSubprogramHeader::CallSpec;
                        }
                        expecting_close = false;
                    }
                    _ => {
                        if let Some(
                            header @ (PackageSubprogramHeader::AfterAsOrIs
                            | PackageSubprogramHeader::AfterLanguage),
                        ) = package_subprogram_headers.last_mut()
                        {
                            *header = PackageSubprogramHeader::PlSqlBody;
                        }
                        expecting_close = false;
                    }
                }
                segment_has_content = true;
            }
            Token::SemiColon => {
                expecting_close = false;
                if depth == 0 {
                    if segment_has_content {
                        statement_count += 1;
                    }
                    segment_has_content = false;
                    if stored_unit_closed {
                        stored_unit_terminated = true;
                    }
                } else {
                    // A `;` nested inside CASE/IF/LOOP/BEGIN depth. Only a real
                    // PL/SQL block (StageA::PlSqlBlock) can legitimately carry a
                    // nested statement-terminator `;`; the pure-SQL caller treats
                    // this as a hidden top-level boundary the counter swallowed
                    // and forces Forbidden.
                    saw_buried_semicolon = true;
                    if is_package_body
                        && depth == 1
                        && !package_initialization_opened
                        && matches!(
                            package_subprogram_headers.last(),
                            Some(
                                PackageSubprogramHeader::Declaration
                                    | PackageSubprogramHeader::CallSpec
                            )
                        )
                    {
                        package_subprogram_headers.pop();
                    }
                }
            }
            // Whitespace must NOT reset `expecting_close` (END <ws> IF).
            Token::Whitespace(_) => {}
            // The SQL*Plus `/` run terminator (`END; /`) is a benign batch
            // terminator, never trailing SQL — it must NOT trip the
            // trailing-after-`END` desync (oracle-lokg.1). It still resets
            // `expecting_close` and (defensively) does not count as statement
            // content so a lone `/` after a closed block stays a clean terminator.
            Token::Div => {
                if stored_unit_closed && !stored_unit_terminated {
                    saw_top_level_after_block_close = true;
                }
                expecting_close = false;
            }
            _ => {
                // Any other significant token (punctuation, operator, literal,
                // number, string) at depth 0 after a block body has opened and
                // closed is trailing top-level SQL after `END` (oracle-lokg.1).
                if (block_body_opened && depth == 0) || stored_unit_closed {
                    saw_top_level_after_block_close = true;
                }
                expecting_close = false;
                segment_has_content = true;
            }
        }
    }
    if segment_has_content {
        statement_count += 1;
    }
    BatchShape {
        balanced: depth == 0 && !went_negative && package_subprogram_headers.is_empty(),
        has_plsql_block,
        statement_count,
        saw_buried_semicolon,
        saw_top_level_after_block_close,
    }
}

/// A single statement's classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementClass {
    /// Risk tier.
    pub danger: DangerLevel,
    /// Operating level required, or `None` for `Forbidden`.
    pub required: Option<OperatingLevel>,
    /// Objects/routines referenced (best-effort).
    pub objects: Vec<String>,
    /// Redacted R15 outcome when this query actually consulted the routine
    /// purity oracle. Internal so no caller can confuse object names with the
    /// certificate's fixed construct vocabulary.
    r15_derivation: Option<R15Derivation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum R15Derivation {
    AllProvenReadOnly,
    UnprovenPresent,
}

impl R15Derivation {
    const fn construct(self) -> &'static str {
        match self {
            R15Derivation::AllProvenReadOnly => "routine_purity:all_proven_read_only",
            R15Derivation::UnprovenPresent => "routine_purity:unproven_present",
        }
    }
}

impl StatementClass {
    fn forbidden() -> Self {
        StatementClass {
            danger: DangerLevel::Forbidden,
            required: None,
            objects: Vec::new(),
            r15_derivation: None,
        }
    }
}

/// Known Oracle SQL built-in functions that are pure (never trigger the UDF
/// purity consult). Anything *not* here that is called as `ident(` is treated
/// as a user-defined function → consult the oracle (default `Unknown`).
fn is_builtin_function(name: &str, verified_local_vector_embedding: bool) -> bool {
    const BUILTINS: &[&str] = &[
        "count",
        "sum",
        "avg",
        "min",
        "max",
        "nvl",
        "nvl2",
        "coalesce",
        "decode",
        "to_char",
        "to_date",
        "to_number",
        "to_timestamp",
        "cast",
        "substr",
        "instr",
        "length",
        "upper",
        "lower",
        "trim",
        "ltrim",
        "rtrim",
        "lpad",
        "rpad",
        "replace",
        "round",
        "trunc",
        "floor",
        "ceil",
        "mod",
        "abs",
        "sign",
        "power",
        "sqrt",
        "greatest",
        "least",
        "extract",
        "row_number",
        "rank",
        "dense_rank",
        "listagg",
        "sys_context",
        "user",
        "sysdate",
        "systimestamp",
        "rownum",
        "rowid",
        "concat",
        "initcap",
        "regexp_replace",
        "regexp_substr",
        "regexp_like",
        "nullif",
        "case",
        "exists",
        "cardinality",
        "vector_distance",
    ];
    let name = name.to_ascii_lowercase();
    BUILTINS.contains(&name.as_str())
        || (verified_local_vector_embedding && name == "vector_embedding")
}

/// Keyword-collision identifiers that, when used as a **bare** `name(` call, are
/// genuine routine-name candidates rather than SQL syntax. These are the
/// non-reserved Oracle words an agent can legally define a side-effecting UDF /
/// package member under (PURGE/MERGE/DELETE/COMMENT/ANALYZE/REFRESH/…). The old
/// blanket `keyword != NoKeyword { continue }` fail-OPENED *all* of them straight
/// to `Safe`; routing them through `is_builtin_function` + the purity consult
/// closes that hole (oracle-ajm2.1).
///
/// The complement — structural / clause-introducing keywords that legally
/// precede `(` in well-formed SQL but are never routine names (`AS (` for a CTE,
/// `IN (…)`, `VALUES (…)`, `OVER (…)`, `OR (…)`, `JOIN (…)`, …) — is left to the
/// default skip so a plain read is never mis-flagged Guarded. Schema-qualified
/// `schema.name(` forms are handled separately (always a routine call), so this
/// set only governs the *bare* case.
fn is_routine_name_keyword(name: &str) -> bool {
    const ROUTINE_NAME_KEYWORDS: &[&str] = &[
        "purge", "merge", "delete", "comment", "analyze", "refresh", "load", "export", "import",
        "truncate", "replace", "rename", "call",
    ];
    ROUTINE_NAME_KEYWORDS.contains(&name.to_ascii_lowercase().as_str())
}

/// Token-based UDF detection: an identifier (optionally `schema.`-qualified)
/// immediately followed by `(` that is not a known built-in is a candidate
/// user-defined function call. Fail-closed: over-detection only adds Guarded.
fn user_defined_calls(sql: &str, verified_local_vector_embedding: bool) -> Vec<ObjectRef> {
    let dialect = OracleDialect {};
    let Ok(tokens) = Tokenizer::new(&dialect, sql).tokenize() else {
        return Vec::new();
    };
    // Drop whitespace for adjacency checks.
    let toks: Vec<&Token> = tokens
        .iter()
        .filter(|t| !matches!(t, Token::Whitespace(_)))
        .collect();
    let mut calls = Vec::new();
    for i in 0..toks.len() {
        if !matches!(toks[i], Token::LParen) {
            continue;
        }
        // Look back for `name` or `schema . name` before the '('.
        if i == 0 {
            continue;
        }
        if let Token::Word(name) = toks[i - 1] {
            let is_qualified = i >= 3
                && matches!(toks[i - 2], Token::Period)
                && matches!(toks[i - 3], Token::Word(_));
            // A schema-qualified `schema.name(` is unambiguously a routine call
            // (SQL constructs like VALUES/IN/CAST/AS are never schema-qualified),
            // so it is NEVER skipped — closing the headline `billing.purge()`
            // fail-open. A *bare* keyword-named `name(` is skipped only when the
            // keyword is a structural / clause word that legally precedes `(`
            // (AS/IN/VALUES/OVER/OR/JOIN/…); a keyword that is also a plausible
            // non-reserved Oracle routine name (PURGE/MERGE/DELETE/COMMENT/…) is
            // still routed through the purity consult (oracle-ajm2.1).
            if !is_qualified
                && name.keyword != Keyword::NoKeyword
                && !is_routine_name_keyword(&name.value)
            {
                continue;
            }
            // `is_qualified` was established above with `matches!(toks[i - 3],
            // Token::Word(_))`, so the schema word is present in correct logic.
            // Fail closed rather than `unreachable!()`: if the token state ever
            // diverges, fall back to a schema-less qualified call. The routine
            // is STILL pushed (over-detection only adds Guarded), so an
            // unexpected state refuses by flagging rather than unwinding out of
            // classification or fail-opening to Safe.
            let (schema, fname) = if is_qualified {
                match toks[i - 3] {
                    Token::Word(s) => (Some(s.value.clone()), name.value.clone()),
                    _ => (None, name.value.clone()),
                }
            } else {
                (None, name.value.clone())
            };
            // A SQL builtin (REPLACE / ROUND / TRUNC / MOD / USER / LENGTH /
            // EXTRACT / …) is NEVER written schema-qualified, so when the call
            // IS qualified the builtin name-collision filter must not apply:
            // `SELECT billing.replace(x)` is unambiguously a routine call on
            // package BILLING and dropping it (because its bare name "replace"
            // is in BUILTINS) fail-opened the whole statement to Safe/ReadOnly,
            // executing the routine's side effects unguarded. This matches the
            // module's own stated invariant ("a schema-qualified name is never
            // skipped") and the earlier keyword-named-UDF fix (oracle-ajm2); the
            // qualified-builtin subcase was the remaining gap (oracle-b6yl.2).
            if is_qualified || !is_builtin_function(&fname, verified_local_vector_embedding) {
                calls.push(ObjectRef::new(schema, fname));
            }
        }
    }
    calls
}

/// Whether the submitted text immediately executes PL/SQL rather than merely
/// defining stored code. Leading PL/SQL labels are allowed on anonymous blocks,
/// so skip `<<label>>` prefixes before checking the first executable keyword.
/// Stored `CREATE PROCEDURE/FUNCTION/PACKAGE/TRIGGER` bodies are deliberately
/// excluded: creation is already DDL-gated and does not invoke the body.
fn plsql_invocation_keyword(sql: &str) -> Option<&'static str> {
    let Ok(tokens) = Tokenizer::new(&OracleDialect {}, sql).tokenize() else {
        return None;
    };
    let toks: Vec<&Token> = tokens
        .iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .collect();
    let mut index = 0;
    while index + 2 < toks.len()
        && matches!(toks[index], Token::ShiftLeft)
        && matches!(toks[index + 1], Token::Word(_))
        && matches!(toks[index + 2], Token::ShiftRight)
    {
        index += 3;
    }
    let Some(Token::Word(word)) = toks.get(index) else {
        return None;
    };
    if word.quote_style.is_some() {
        return None;
    }
    ["BEGIN", "DECLARE", "CALL"]
        .into_iter()
        .find(|keyword| word.value.eq_ignore_ascii_case(keyword))
}

fn tokens_are_literal_or_bind_expression(tokens: &[&Token]) -> bool {
    let mut depth = 0_i64;
    let mut expect_bind_name = false;
    for token in tokens {
        if expect_bind_name {
            if matches!(token, Token::Word(_) | Token::Number(_, _)) {
                expect_bind_name = false;
                continue;
            }
            return false;
        }
        match token {
            Token::SingleQuotedString(_)
            | Token::NationalStringLiteral(_)
            | Token::QuoteDelimitedStringLiteral(_)
            | Token::NationalQuoteDelimitedStringLiteral(_)
            | Token::HexStringLiteral(_)
            | Token::Number(_, _)
            | Token::Placeholder(_)
            | Token::Plus
            | Token::Minus
            | Token::Mul
            | Token::Div
            | Token::StringConcat => {}
            Token::Word(word)
                if word.quote_style.is_none()
                    && ["NULL", "TRUE", "FALSE"]
                        .iter()
                        .any(|literal| word.value.eq_ignore_ascii_case(literal)) => {}
            Token::Colon => expect_bind_name = true,
            Token::LParen => depth += 1,
            Token::RParen if depth > 0 => depth -= 1,
            _ => return false,
        }
    }
    !expect_bind_name && depth == 0
}

/// Comments and whitespace do not add executable behavior to a reviewed
/// anonymous block. Tokenize them rather than stripping text so comment markers
/// inside literals retain their ordinary data meaning.
fn is_plsql_trivia(segment: &str) -> bool {
    Tokenizer::new(&OracleDialect {}, segment)
        .tokenize()
        .is_ok_and(|tokens| {
            !tokens.is_empty()
                && tokens
                    .iter()
                    .all(|token| matches!(token, Token::Whitespace(_)))
        })
}

fn is_plsql_null_statement(segment: &str) -> bool {
    let Ok(tokens) = Tokenizer::new(&OracleDialect {}, segment).tokenize() else {
        return false;
    };
    let toks: Vec<&Token> = tokens
        .iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .collect();
    matches!(
        toks.as_slice(),
        [Token::Word(word)]
            if word.quote_style.is_none() && word.value.eq_ignore_ascii_case("NULL")
    )
}

/// The one caller-visible package operation the engine-free server can prove
/// locally: writing a literal/bind-derived value to SYS.DBMS_OUTPUT's session
/// buffer. The full owner/package/member spelling is mandatory, and the
/// argument grammar deliberately excludes identifiers that might resolve to a
/// zero-argument function, subqueries, member access, or nested calls.
fn is_reviewed_dbms_output_statement(segment: &str) -> bool {
    let Ok(tokens) = Tokenizer::new(&OracleDialect {}, segment).tokenize() else {
        return false;
    };
    let toks: Vec<&Token> = tokens
        .iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .collect();
    if toks.len() < 7
        || !matches!(toks[0], Token::Word(word) if word.quote_style.is_none() && word.value.eq_ignore_ascii_case("SYS"))
        || !matches!(toks[1], Token::Period)
        || !matches!(toks[2], Token::Word(word) if word.quote_style.is_none() && word.value.eq_ignore_ascii_case("DBMS_OUTPUT"))
        || !matches!(toks[3], Token::Period)
        || !matches!(toks[4], Token::Word(word) if word.quote_style.is_none() && word.value.eq_ignore_ascii_case("PUT_LINE"))
        || !matches!(toks[5], Token::LParen)
        || !matches!(toks[toks.len() - 1], Token::RParen)
    {
        return false;
    }

    !toks[6..toks.len() - 1].is_empty()
        && tokens_are_literal_or_bind_expression(&toks[6..toks.len() - 1])
}

/// Return the class of caller PL/SQL that the engine-free guard cannot prove
/// complete. Oracle permits parameterless functions to omit parentheses in any
/// PL/SQL expression, making them lexically indistinguishable from variables,
/// constants, and record fields. Consequently DECLARE sections and procedural
/// expressions/control flow must fail closed without a semantic PL/SQL engine.
/// A BEGIN block remains available only for NULL and the exact reviewed
/// SYS.DBMS_OUTPUT statement above. Static DML must be submitted directly so
/// its SQL grammar is classified without PL/SQL name-resolution ambiguity.
/// Explicit CALL also fails closed because the current two-field ObjectRef
/// cannot distinguish schema routines, package/type members, and synonyms.
fn unanalyzable_plsql_construct(sql: &str) -> Option<&'static str> {
    let keyword = plsql_invocation_keyword(sql)?;
    if keyword == "CALL" {
        return Some("CALL target without complete semantic name resolution");
    }

    // Preserve the classifier's more specific fail-closed reasons for dynamic
    // markers and structural desynchronization. This subset check runs before
    // the operator allow-list only so allow-listing cannot bless an opaque
    // block; it should not mask stronger diagnostics handled by Stage A.
    let scan = canonical_marker_scan(&sql.trim_start().to_ascii_uppercase());
    if PLSQL_SIDE_EFFECT_MARKERS
        .iter()
        .any(|marker| scan.contains(marker))
    {
        return None;
    }
    let shape = analyze_batch(sql);
    if !shape.balanced || shape.saw_top_level_after_block_close {
        return None;
    }

    match keyword {
        "DECLARE" => Some("DECLARE section without complete semantic analysis"),
        "BEGIN" => {
            let segments = block_interior_segments(sql);
            if segments.is_empty() {
                return Some("empty or unrecognized PL/SQL body");
            }
            for segment in &segments {
                let trimmed = segment.trim();
                if is_plsql_trivia(trimmed)
                    || is_plsql_null_statement(trimmed)
                    || is_reviewed_dbms_output_statement(trimmed)
                {
                    continue;
                }
                return Some("procedural PL/SQL expression without complete semantic analysis");
            }
            None
        }
        _ => Some("unrecognized PL/SQL invocation context"),
    }
}

/// Find Oracle sequence `NEXTVAL` pseudocolumn references.
///
/// `NEXTVAL` has no call parentheses, so the UDF detector cannot see it. Oracle
/// accepts `sequence.NEXTVAL`, `schema.sequence.NEXTVAL`, and the latter with a
/// trailing `@dblink`. Advancing a sequence is permanent even if the surrounding
/// transaction rolls back, so a query containing this token shape is never a
/// read-only statement.
///
/// Tokens inside comments and literals are kept out by `sqlparser`'s tokenizer.
/// A quoted `"NEXTVAL"` remains an ordinary delimited identifier and is not the
/// pseudocolumn. An unquoted qualified column named `NEXTVAL` is conservatively
/// treated as the pseudocolumn: over-detection requires a governed READ_WRITE
/// path, while under-detection would irreversibly mutate state at READ_ONLY.
fn sequence_nextval_refs(sql: &str) -> Vec<ObjectRef> {
    let dialect = OracleDialect {};
    let Ok(tokens) = Tokenizer::new(&dialect, sql).tokenize() else {
        return Vec::new();
    };
    let toks: Vec<&Token> = tokens
        .iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .collect();

    let mut refs = Vec::new();
    for i in 2..toks.len() {
        let Token::Word(pseudocolumn) = toks[i] else {
            continue;
        };
        // OracleDialect keeps an immediately-attached database link in the
        // same word (`NEXTVAL@prod`). Compare the pseudocolumn portion before
        // `@`; spaced `NEXTVAL @ prod` is already the exact-word case.
        let pseudocolumn_name = pseudocolumn
            .value
            .split_once('@')
            .map_or(pseudocolumn.value.as_str(), |(name, _)| name);
        if pseudocolumn.quote_style.is_some()
            || !pseudocolumn_name.eq_ignore_ascii_case("NEXTVAL")
            || !matches!(toks[i - 1], Token::Period)
        {
            continue;
        }
        let Token::Word(sequence) = toks[i - 2] else {
            continue;
        };
        let schema = if i >= 4 && matches!(toks[i - 3], Token::Period) {
            match toks[i - 4] {
                Token::Word(owner) => Some(owner.value.clone()),
                _ => None,
            }
        } else {
            None
        };
        refs.push(ObjectRef::new(schema, sequence.value.clone()));
    }
    refs
}

/// Whether a sequence effect belongs to a top-level query result.
///
/// Oracle does not evaluate a `SELECT sequence.NEXTVAL` merely because the
/// statement was parsed/executed: the result must be fetched. This distinction
/// lets callers that only have an execute-with-rowcount primitive refuse the
/// query rather than falsely reporting that the permanent effect occurred.
fn sequence_nextval_query_requires_fetch(sql: &str) -> bool {
    if sequence_nextval_refs(sql).is_empty() {
        return false;
    }
    match Parser::parse_sql(&OracleDialect {}, sql) {
        Ok(statements) => statements
            .iter()
            .any(|statement| matches!(statement, sqlparser::ast::Statement::Query(_))),
        Err(_) => {
            // Fail closed for valid Oracle query syntax that sqlparser cannot
            // model. PL/SQL is handled by Stage A before this value is exposed.
            let scan = canonical_marker_scan(&sql.trim_start().to_ascii_uppercase());
            let leading = scan.strip_prefix(' ').unwrap_or(&scan);
            leading.starts_with("SELECT ") || leading.starts_with("WITH ")
        }
    }
}

/// The per-classification strict-mode flags threaded into the per-statement
/// classifier. Both default off (the backward-compatible baseline); the
/// served/strict gate flips them on. Purely additive — a set flag can only ever
/// RAISE a statement's classification, never lower it.
#[derive(Clone, Copy, Debug, Default)]
struct StrictModes {
    /// Treat a statement-level `Unknown` purity verdict over a non-empty base
    /// object set as fail-closed `≥ Guarded` (bead .82). Meaningful only with a
    /// bound oracle; under the default `UnknownOracle` this forces *every* read of
    /// a real base object to `Guarded` (the documented aggressive containment).
    statement_unknown_guarded: bool,
    /// Treat a qualified, paren-less identifier whose root qualifier is not in
    /// scope as an unproven callable → `≥ Guarded` (bead .102).
    guard_unresolved_qualified_calls: bool,
}

/// Oracle identifier identity for relation qualifiers. Unquoted names fold to
/// uppercase; quoted names retain their exact spelling. Consequently `EMP` and
/// `"EMP"` resolve to the same identifier, while `EMP` and `"emp"` do not.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct QualifierPart(String);

fn qualifier_part(ident: &Ident) -> QualifierPart {
    QualifierPart(if ident.quote_style.is_some() {
        ident.value.clone()
    } else {
        ident.value.to_ascii_uppercase()
    })
}

type RelationQualifier = Vec<QualifierPart>;

fn alias_qualifier(alias: &TableAlias) -> RelationQualifier {
    vec![qualifier_part(&alias.name)]
}

fn object_name_qualifiers(name: &sqlparser::ast::ObjectName) -> Vec<RelationQualifier> {
    let mut parts = RelationQualifier::new();
    for ident in name.0.iter().filter_map(|part| part.as_ident()) {
        // sqlparser encodes `employees@prod.example.com` as ObjectName parts
        // `[employees@prod, example, com]`. Oracle column qualification uses
        // only the local relation (`employees.name`), so truncate at the first
        // unquoted @ and discard every database-link domain component after it.
        if ident.quote_style.is_none()
            && let Some((relation, _link)) = ident.value.split_once('@')
        {
            if relation.is_empty() {
                return Vec::new();
            }
            parts.push(QualifierPart(relation.to_ascii_uppercase()));
            break;
        }
        parts.push(qualifier_part(ident));
    }
    let mut qualifiers = Vec::new();
    if let Some(last) = parts.last() {
        qualifiers.push(vec![last.clone()]);
    }
    if parts.len() > 1 {
        qualifiers.push(parts);
    }
    qualifiers
}

/// Collect only the relation qualifiers exposed by one SELECT scope. A table
/// alias hides its underlying table/schema qualifier; a schema component alone
/// is never a column qualifier. This is deliberately per-scope — aliases from a
/// nested subquery must not turn an outer `pkg.member` function invocation into
/// a supposed column reference (the fail-open in the first .102 containment).
fn collect_factor_qualifiers(factor: &TableFactor, out: &mut Vec<RelationQualifier>) {
    match factor {
        TableFactor::Table { name, alias, .. } => {
            if let Some(alias) = alias {
                out.push(alias_qualifier(alias));
            } else {
                out.extend(object_name_qualifiers(name));
            }
        }
        TableFactor::NestedJoin {
            table_with_joins,
            alias,
        } => {
            if let Some(alias) = alias {
                out.push(alias_qualifier(alias));
            } else {
                collect_table_with_joins_qualifiers(table_with_joins, out);
            }
        }
        TableFactor::Pivot { table, alias, .. }
        | TableFactor::Unpivot { table, alias, .. }
        | TableFactor::MatchRecognize { table, alias, .. } => {
            if let Some(alias) = alias {
                out.push(alias_qualifier(alias));
            } else {
                collect_factor_qualifiers(table, out);
            }
        }
        TableFactor::Derived {
            alias: Some(alias), ..
        }
        | TableFactor::TableFunction {
            alias: Some(alias), ..
        }
        | TableFactor::Function {
            alias: Some(alias), ..
        }
        | TableFactor::UNNEST {
            alias: Some(alias), ..
        }
        | TableFactor::JsonTable {
            alias: Some(alias), ..
        }
        | TableFactor::OpenJsonTable {
            alias: Some(alias), ..
        }
        | TableFactor::XmlTable {
            alias: Some(alias), ..
        }
        | TableFactor::SemanticView {
            alias: Some(alias), ..
        } => out.push(alias_qualifier(alias)),
        // An unaliased derived/table-function factor exposes no reliable dotted
        // qualifier we can prove from syntax alone. Omitting it is fail-closed:
        // a genuine reference is over-restricted rather than a callable admitted.
        _ => {}
    }
}

fn collect_table_with_joins_qualifiers(table: &TableWithJoins, out: &mut Vec<RelationQualifier>) {
    collect_factor_qualifiers(&table.relation, out);
    for join in &table.joins {
        collect_factor_qualifiers(&join.relation, out);
    }
}

fn select_scope_qualifiers(select: &Select) -> Vec<RelationQualifier> {
    let mut out = Vec::new();
    for table in &select.from {
        collect_table_with_joins_qualifiers(table, &mut out);
    }
    out
}

fn select_id(select: &Select) -> usize {
    select as *const Select as usize
}

fn table_factor_id(factor: &TableFactor) -> usize {
    factor as *const TableFactor as usize
}

fn collect_body_select_ids(body: &SetExpr, out: &mut HashSet<usize>) {
    match body {
        SetExpr::Select(select) => {
            out.insert(select_id(select));
        }
        SetExpr::SetOperation { left, right, .. } => {
            collect_body_select_ids(left, out);
            collect_body_select_ids(right, out);
        }
        // A parenthesized Query owns its own query frame and lexical scope.
        SetExpr::Query(_) => {}
        _ => {}
    }
}

struct QueryScopeFrame {
    /// SELECT nodes belonging to this Query's body, excluding WITH bodies and
    /// nested parenthesized Query nodes. Used to end the WITH visibility barrier
    /// exactly when traversal reaches the main query body.
    body_select_ids: HashSet<usize>,
    /// Only a single direct SELECT exposes relation qualifiers to Query-level
    /// ORDER BY/FETCH expressions. Set-operation arm aliases never leak across.
    direct_select_id: Option<usize>,
    order_scope: Vec<RelationQualifier>,
    /// WITH bodies cannot see aliases introduced later by the main query body.
    /// Stop lookup at this frame until traversal reaches a body SELECT.
    barrier_outer: bool,
}

impl QueryScopeFrame {
    fn new(query: &Query) -> Self {
        let mut body_select_ids = HashSet::new();
        collect_body_select_ids(query.body.as_ref(), &mut body_select_ids);
        Self {
            direct_select_id: match query.body.as_ref() {
                SetExpr::Select(select) => Some(select_id(select)),
                _ => None,
            },
            barrier_outer: query.with.is_some(),
            body_select_ids,
            order_scope: Vec::new(),
        }
    }
}

struct SelectScopeFrame {
    /// All relations are visible to the projection, regardless of their textual
    /// order in FROM.
    full_scope: Vec<RelationQualifier>,
    /// FROM/JOIN traversal activates relations left-to-right. This prevents a
    /// later alias from laundering a package call in an earlier JOIN condition.
    active_scope: Vec<RelationQualifier>,
    in_from: bool,
    factor_depth: usize,
    /// Oracle CROSS/OUTER APPLY is lateral even though sqlparser records the
    /// correlation on JoinOperator rather than TableFactor::Derived.
    implicit_lateral_factor_ids: HashSet<usize>,
    /// A non-lateral factor's children cannot correlate to this query block (or
    /// any older block). Treat the frame as a lexical barrier while visiting it.
    suppressed: bool,
}

impl SelectScopeFrame {
    fn new(select: &Select) -> Self {
        let implicit_lateral_factor_ids = select
            .from
            .iter()
            .flat_map(|table| &table.joins)
            .filter(|join| {
                matches!(
                    join.join_operator,
                    sqlparser::ast::JoinOperator::CrossApply
                        | sqlparser::ast::JoinOperator::OuterApply
                )
            })
            .map(|join| table_factor_id(&join.relation))
            .collect();
        Self {
            full_scope: select_scope_qualifiers(select),
            active_scope: Vec::new(),
            in_from: false,
            factor_depth: 0,
            implicit_lateral_factor_ids,
            suppressed: false,
        }
    }

    fn visible_scope(&self) -> &[RelationQualifier] {
        if self.in_from {
            &self.active_scope
        } else {
            &self.full_scope
        }
    }
}

enum QualifierScopeFrame {
    Query(QueryScopeFrame),
    Select(SelectScopeFrame),
}

struct UnresolvedQualifiedCallVisitor {
    scopes: Vec<QualifierScopeFrame>,
    unresolved: Vec<String>,
}

impl UnresolvedQualifiedCallVisitor {
    fn qualifier_is_visible(&self, qualifier: &[QualifierPart]) -> bool {
        for frame in self.scopes.iter().rev() {
            match frame {
                QualifierScopeFrame::Select(select) => {
                    if select.suppressed {
                        return false;
                    }
                    if select
                        .visible_scope()
                        .iter()
                        .any(|visible| qualifier.starts_with(visible))
                    {
                        return true;
                    }
                }
                QualifierScopeFrame::Query(query) => {
                    if query
                        .order_scope
                        .iter()
                        .any(|visible| qualifier.starts_with(visible))
                    {
                        return true;
                    }
                    if query.barrier_outer {
                        return false;
                    }
                }
            }
        }
        false
    }

    fn current_select_mut(&mut self) -> Option<&mut SelectScopeFrame> {
        self.scopes.iter_mut().rev().find_map(|frame| match frame {
            QualifierScopeFrame::Select(select) => Some(select),
            QualifierScopeFrame::Query(_) => None,
        })
    }

    fn current_query_mut(&mut self) -> Option<&mut QueryScopeFrame> {
        self.scopes.iter_mut().rev().find_map(|frame| match frame {
            QualifierScopeFrame::Query(query) => Some(query),
            QualifierScopeFrame::Select(_) => None,
        })
    }
}

impl Visitor for UnresolvedQualifiedCallVisitor {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.scopes
            .push(QualifierScopeFrame::Query(QueryScopeFrame::new(query)));
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        debug_assert!(matches!(
            self.scopes.pop(),
            Some(QualifierScopeFrame::Query(_))
        ));
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        let id = select_id(select);
        if let Some(query) = self.current_query_mut()
            && query.body_select_ids.contains(&id)
        {
            query.barrier_outer = false;
        }
        self.scopes
            .push(QualifierScopeFrame::Select(SelectScopeFrame::new(select)));
        ControlFlow::Continue(())
    }

    fn post_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        let Some(QualifierScopeFrame::Select(scope)) = self.scopes.pop() else {
            debug_assert!(false, "SELECT scope stack must remain balanced");
            return ControlFlow::Continue(());
        };
        if let Some(query) = self.current_query_mut()
            && query.direct_select_id == Some(select_id(select))
        {
            query.order_scope = scope.full_scope;
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        let Some(select) = self.current_select_mut() else {
            return ControlFlow::Continue(());
        };
        if select.factor_depth == 0 {
            if !select.in_from {
                select.in_from = true;
                select.active_scope.clear();
            }
            let lateral = matches!(
                factor,
                TableFactor::Derived { lateral: true, .. }
                    | TableFactor::Function { lateral: true, .. }
                    // Oracle makes these table-producing factors implicitly
                    // lateral: their input expression can reference relations
                    // already activated to the left.
                    | TableFactor::TableFunction { .. }
                    | TableFactor::JsonTable { .. }
                    | TableFactor::XmlTable { .. }
            ) || select
                .implicit_lateral_factor_ids
                .contains(&table_factor_id(factor));
            select.suppressed = !lateral;
        }
        select.factor_depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        let Some(select) = self.current_select_mut() else {
            return ControlFlow::Continue(());
        };
        debug_assert!(select.factor_depth > 0);
        select.factor_depth = select.factor_depth.saturating_sub(1);
        if select.factor_depth == 0 {
            select.suppressed = false;
            collect_factor_qualifiers(factor, &mut select.active_scope);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        let parts = match expr {
            Expr::Identifier(part) if part.quote_style.is_none() && part.value.contains('@') => {
                self.unresolved.push(part.to_string());
                return ControlFlow::Continue(());
            }
            Expr::CompoundIdentifier(parts) => parts,
            _ => return ControlFlow::Continue(()),
        };
        if parts.len() < 2 {
            return ControlFlow::Continue(());
        }
        let rendered = parts
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".");
        // Oracle's `pkg.fn@dblink` expression syntax resolves a remote callable
        // even when `pkg` is also a local table alias; alias-prefix shadowing
        // does not apply across the database link. Remote table columns put the
        // @link only in the FROM ObjectName, never in the value qualifier.
        if parts
            .iter()
            .any(|part| part.quote_style.is_none() && part.value.contains('@'))
        {
            self.unresolved.push(rendered);
            return ControlFlow::Continue(());
        }
        let qualifier: RelationQualifier = parts[..parts.len() - 1]
            .iter()
            .map(qualifier_part)
            .collect();
        if !self.qualifier_is_visible(&qualifier) {
            self.unresolved.push(rendered);
        }
        ControlFlow::Continue(())
    }
}

/// AST/scope-aware scan for qualified, paren-less expression identifiers that
/// are not proven relation-qualified columns. Oracle permits a zero/default-arg
/// function invocation without `()`. Only a relation-qualifier prefix exposed
/// by the current or correlated outer SELECT scope is treated as data; schema
/// names and aliases from sibling/nested scopes never bless a callable. Remote
/// expression identifiers are always unresolved because `fn@dblink` overrides
/// local alias shadowing. Catalog-backed
/// identity is still required for unqualified bare identifiers (the .102
/// residual), but this containment no longer carries the original scope leaks.
fn unresolved_qualified_calls(query: &Query) -> Vec<String> {
    let mut visitor = UnresolvedQualifiedCallVisitor {
        scopes: Vec::new(),
        unresolved: Vec::new(),
    };
    let _ = query.visit(&mut visitor);
    visitor.unresolved.sort();
    visitor.unresolved.dedup();
    visitor.unresolved
}

struct SemanticValueVisitor {
    values: Vec<RawName>,
    /// Addresses of the exact `VECTOR_DISTANCE` metric expressions currently
    /// being visited. The metric is Oracle grammar, not a caller-controlled
    /// data identifier, but this must not suppress an identically named column
    /// elsewhere in the same query.
    vector_metric_expressions: Vec<*const Expr>,
    /// The first `VECTOR_EMBEDDING` argument is a server-owned model grammar
    /// identifier. It is never caller SQL on the governed surface; treating it
    /// as a column would make the resolver prove a fictitious data dependency.
    vector_embedding_model_expressions: Vec<*const Expr>,
}

impl Visitor for SemanticValueVisitor {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if let Expr::Function(function) = expr
            && let Some(metric) = vector_distance_metric_expr(function)
        {
            self.vector_metric_expressions.push(metric as *const Expr);
        }
        if let Expr::Function(function) = expr
            && let Some(model) = vector_embedding_model_expr(function)
        {
            self.vector_embedding_model_expressions
                .push(model as *const Expr);
        }
        if self
            .vector_metric_expressions
            .iter()
            .any(|metric| std::ptr::eq(*metric, expr as *const Expr))
            || self
                .vector_embedding_model_expressions
                .iter()
                .any(|model| std::ptr::eq(*model, expr as *const Expr))
        {
            return ControlFlow::Continue(());
        }
        let parts = match expr {
            Expr::Identifier(part) => std::slice::from_ref(part),
            Expr::CompoundIdentifier(parts) => parts.as_slice(),
            _ => return ControlFlow::Continue(()),
        };
        if parts.len() == 1 && is_semantic_builtin_identifier(&parts[0]) {
            return ControlFlow::Continue(());
        }
        if let Some(name) = raw_name_from_idents(parts, SyntacticRole::ValuePosition) {
            self.values.push(name);
        }
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if let Expr::Function(function) = expr
            && let Some(metric) = vector_distance_metric_expr(function)
        {
            let metric = metric as *const Expr;
            let position = self
                .vector_metric_expressions
                .iter()
                .rposition(|active| std::ptr::eq(*active, metric))
                .expect("VECTOR_DISTANCE metric was registered before its arguments");
            self.vector_metric_expressions.remove(position);
        }
        if let Expr::Function(function) = expr
            && let Some(model) = vector_embedding_model_expr(function)
        {
            let model = model as *const Expr;
            let position = self
                .vector_embedding_model_expressions
                .iter()
                .rposition(|active| std::ptr::eq(*active, model))
                .expect("VECTOR_EMBEDDING model was registered before its arguments");
            self.vector_embedding_model_expressions.remove(position);
        }
        ControlFlow::Continue(())
    }
}

/// Return the exact third argument when it is one of Oracle's documented
/// `VECTOR_DISTANCE` metric keywords. This intentionally recognizes no quoted
/// identifier, qualified call, named argument, or unreviewed metric spelling.
fn vector_distance_metric_expr(function: &Function) -> Option<&Expr> {
    let [name] = function.name.0.as_slice() else {
        return None;
    };
    let name = name.as_ident()?;
    if name.quote_style.is_some() || !name.value.eq_ignore_ascii_case("VECTOR_DISTANCE") {
        return None;
    }
    let FunctionArguments::List(arguments) = &function.args else {
        return None;
    };
    let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(metric @ Expr::Identifier(identifier)))) =
        arguments.args.get(2)
    else {
        return None;
    };
    is_vector_distance_metric(identifier).then_some(metric)
}

/// Return the exact dictionary-derived model identifier in a bare,
/// unqualified `VECTOR_EMBEDDING(model USING :bind)` call. The inner source
/// remains an ordinary expression and is still visited/proven normally.
fn vector_embedding_model_expr(function: &Function) -> Option<&Expr> {
    let [name] = function.name.0.as_slice() else {
        return None;
    };
    let name = name.as_ident()?;
    if name.quote_style.is_some() || !name.value.eq_ignore_ascii_case("VECTOR_EMBEDDING") {
        return None;
    }
    let FunctionArguments::List(arguments) = &function.args else {
        return None;
    };
    let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(model @ Expr::Identifier(identifier)))) =
        arguments.args.first()
    else {
        return None;
    };
    (identifier.quote_style.is_none()).then_some(model)
}

fn is_vector_distance_metric(metric: &Ident) -> bool {
    metric.quote_style.is_none()
        && matches!(
            metric.value.to_ascii_uppercase().as_str(),
            "COSINE" | "EUCLIDEAN" | "DOT"
        )
}

fn is_semantic_builtin_identifier(ident: &Ident) -> bool {
    if ident.quote_style.is_some() {
        return false;
    }
    matches!(
        ident.value.to_ascii_uppercase().as_str(),
        "CURRENT_DATE"
            | "CURRENT_TIMESTAMP"
            | "CURRENT_USER"
            | "LEVEL"
            | "ROWID"
            | "ROWNUM"
            | "SESSION_USER"
            | "SYSDATE"
            | "SYSTIMESTAMP"
            | "UID"
            | "USER"
    )
}

fn raw_name_part(ident: &Ident) -> RawNamePart {
    RawNamePart {
        text: ident.value.clone(),
        quoting: if ident.quote_style.is_some() {
            QuoteSemantics::Quoted
        } else {
            QuoteSemantics::Unquoted
        },
    }
}

fn raw_name_from_idents(parts: &[Ident], role: SyntacticRole) -> Option<RawName> {
    if parts.is_empty() {
        return None;
    }
    let mut raw_parts = parts.iter().map(raw_name_part).collect::<Vec<_>>();
    let mut db_link = None;
    if let Some(last) = raw_parts.last_mut()
        && last.quoting == QuoteSemantics::Unquoted
        && let Some((name, link)) = last.text.split_once('@')
    {
        if name.is_empty() || link.is_empty() || link.contains('@') {
            return None;
        }
        let name = name.to_owned();
        let link = link.to_owned();
        last.text = name;
        db_link = Some(RawNamePart::unquoted(link));
    }
    let mut name = RawName::new(raw_parts, role);
    name.db_link = db_link;
    Some(name)
}

fn raw_name_from_object(name: &sqlparser::ast::ObjectName, role: SyntacticRole) -> Option<RawName> {
    let parts = name
        .0
        .iter()
        .map(|part| part.as_ident().cloned())
        .collect::<Option<Vec<_>>>()?;
    raw_name_from_idents(&parts, role)
}

fn simple_statement_relation(factor: &TableFactor) -> Option<StatementRelation> {
    let TableFactor::Table {
        name, alias, args, ..
    } = factor
    else {
        return None;
    };
    if args.is_some() {
        return None;
    }
    let name = raw_name_from_object(name, SyntacticRole::FromFactor)?;
    let alias = alias.as_ref().map(|alias| raw_name_part(&alias.name));
    Some(StatementRelation { name, alias })
}

/// Build exact-name resolution work for the conservative served-read subset.
///
/// Only one query block containing plain table/view factors is planned. CTEs,
/// set operations, derived/table-function factors, and other scope-bearing
/// shapes return `None`; a safety caller must refuse those until a per-block
/// resolver can represent them without alias leakage.
#[must_use]
pub fn semantic_read_plan(sql: &str) -> Option<SemanticReadPlan> {
    let parser_sql = normalize_vector_embedding_for_parser(sql);
    let statements = Parser::parse_sql(&OracleDialect {}, &parser_sql).ok()?;
    let [sqlparser::ast::Statement::Query(query)] = statements.as_slice() else {
        return None;
    };
    if query.with.is_some() {
        return None;
    }
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };

    let mut relations = Vec::new();
    for table in &select.from {
        relations.push(simple_statement_relation(&table.relation)?);
        for join in &table.joins {
            relations.push(simple_statement_relation(&join.relation)?);
        }
    }
    let mut visitor = SemanticValueVisitor {
        values: Vec::new(),
        vector_metric_expressions: Vec::new(),
        vector_embedding_model_expressions: Vec::new(),
    };
    let _ = query.visit(&mut visitor);
    let mut seen_values = HashSet::new();
    visitor
        .values
        .retain(|value| seen_values.insert(value.clone()));

    let relation_names = relations
        .iter()
        .map(|relation| relation.name.clone())
        .collect();
    let aliases = relations
        .iter()
        .filter_map(|relation| relation.alias.clone())
        .collect();
    Some(SemanticReadPlan {
        relations: relation_names,
        values: visitor.values,
        statement_scope: StatementScope {
            aliases,
            common_table_expressions: Vec::new(),
            relations,
        },
    })
}

/// Convert a parsed `ObjectName` (the `schema.table` of a `FROM`/`JOIN` factor)
/// into the guard's [`ObjectRef`]. Multi-part names keep the *last* part as the
/// object name and the *second-to-last* as the schema (`a.b.c` → schema `b`,
/// name `c`); a bare name has no schema. Empty names are skipped by the caller.
fn object_name_to_ref(name: &sqlparser::ast::ObjectName) -> Option<ObjectRef> {
    let parts: Vec<String> = name
        .0
        .iter()
        .filter_map(|p| p.as_ident().map(|i| i.value.clone()))
        .collect();
    match parts.as_slice() {
        [] => None,
        [n] => Some(ObjectRef::new(None, n.clone())),
        [.., schema, n] => Some(ObjectRef::new(Some(schema.clone()), n.clone())),
    }
}

/// Recursive SQLParser visitor that collects every real table/view named by a
/// [`TableFactor::Table`], while retaining the lexical CTE aliases active for
/// the query currently being visited.
///
/// The visitor deliberately follows SQLParser's complete AST traversal instead
/// of hand-enumerating expression positions. `Query` nodes can occur in SELECT
/// lists, predicates, comparison operands, and dialect-specific expressions;
/// missing one can make the side-effect oracle see an empty base-object list.
#[derive(Default)]
struct QueryBaseObjectCollector {
    objects: Vec<ObjectRef>,
    cte_alias_scopes: Vec<HashSet<String>>,
}

impl Visitor for QueryBaseObjectCollector {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        let mut aliases = self.cte_alias_scopes.last().cloned().unwrap_or_default();
        if let Some(with) = &query.with {
            aliases.extend(
                with.cte_tables
                    .iter()
                    .map(|cte| cte.alias.name.value.to_ascii_lowercase()),
            );
        }
        self.cte_alias_scopes.push(aliases);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        debug_assert!(
            self.cte_alias_scopes.pop().is_some(),
            "every post-visited query must have an alias scope"
        );
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        if let TableFactor::Table { name, .. } = factor
            && let Some(object) = object_name_to_ref(name)
        {
            let is_cte_reference = object.schema.is_none()
                && self
                    .cte_alias_scopes
                    .last()
                    .is_some_and(|aliases| aliases.contains(&object.name.to_ascii_lowercase()));
            if !is_cte_reference {
                self.objects.push(object);
            }
        }
        ControlFlow::Continue(())
    }
}

/// Walk a `Query` and collect the **base objects** (real tables/views named in
/// `FROM`/`JOIN` factors, including factors inside CTEs, derived queries, and
/// every expression-contained subquery). CTE *alias* names are not base objects,
/// so a `FROM cte` reference is filtered out (its body's base tables are already
/// collected).
///
/// This is the resolved-object set the engine's [`SideEffectOracle::statement_purity`]
/// trigger/VPD walk runs over (a `SELECT`/DML can fire a side-effecting trigger
/// or row-level-security policy function the statement text never names).
/// This collection is safety-critical: omitting a base object can make an empty
/// list look `ProvenReadOnly`, while over-collection can only tighten through a
/// `ProvenSideEffecting` oracle result.
fn query_base_objects(query: &sqlparser::ast::Query) -> Vec<ObjectRef> {
    let mut collector = QueryBaseObjectCollector::default();
    let _ = query.visit(&mut collector);

    // Deduplicate while preserving order (small N; readability over a HashSet).
    let mut seen: HashSet<(Option<String>, String)> = HashSet::new();
    collector
        .objects
        .retain(|object| seen.insert((object.schema.clone(), object.name.clone())));
    collector.objects
}

/// Whether a `SELECT`/`WITH` query body carries a DML `SetExpr` at any depth —
/// recursing through parenthesized subquery bodies, set operations, CTE bodies,
/// **and the derived (FROM/JOIN) subqueries of a `SELECT`**.
///
/// sqlparser 0.62 maps `WITH cte {INSERT|UPDATE|DELETE|MERGE} …` to a
/// `Statement::Query` whose `body` is `SetExpr::{Insert,Update,Delete,Merge}`
/// — the trailing DML is absorbed as a "query body" rather than surfacing as a
/// separate `Statement::Update`/… . A genuine read body is only
/// `Select`/`Values`/`Table`/set-ops of the same, so the presence of a DML
/// `SetExpr` means a write was smuggled in under a read shell. The classifier
/// must NOT tier such text `Safe`/`ReadOnly` (fail-closed; oracle-cte-dml-body).
///
/// The original fix only inspected the *top-level* body, so a DML `SetExpr`
/// wrapped in a FROM-derived subquery, a JOIN-derived subquery, a nested join,
/// or a UNION branch's `FROM (…)` (`SELECT * FROM (UPDATE t SET x=1)`,
/// `SELECT 1 FROM dual UNION SELECT * FROM (DELETE FROM t)`, …) slipped through
/// to `Safe` — a fail-closed-net hole in the same smuggled-DML class
/// (oracle-derived-dml-body, multi-pass 2026-07). Descending into the `Select`
/// arm's derived tables closes it. Expr-embedded subqueries (a DML in a
/// `WHERE … IN (…)` / scalar subquery) are covered by the reserved-verb
/// canonical scan in [`query_embeds_reserved_dml_verb`].
///
/// The `SetExpr` match is exhaustive on purpose: `SetExpr` is not
/// `#[non_exhaustive]`, so a future sqlparser bump that adds a body variant
/// breaks the build and forces a deliberate read-vs-write triage rather than
/// silently defaulting to read.
fn set_expr_carries_dml(body: &sqlparser::ast::SetExpr) -> bool {
    use sqlparser::ast::SetExpr;
    match body {
        SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Delete(_) | SetExpr::Merge(_) => true,
        SetExpr::Query(q) => set_expr_carries_dml(&q.body),
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_carries_dml(left) || set_expr_carries_dml(right)
        }
        SetExpr::Select(select) => select.from.iter().any(table_with_joins_carries_dml),
        SetExpr::Values(_) | SetExpr::Table(_) => false,
    }
}

/// Whether a `Query` (its CTE bodies or its body `SetExpr`) carries DML anywhere.
fn query_carries_dml(query: &sqlparser::ast::Query) -> bool {
    if let Some(with) = &query.with
        && with.cte_tables.iter().any(|c| query_carries_dml(&c.query))
    {
        return true;
    }
    set_expr_carries_dml(&query.body)
}

/// Whether any relation of a `FROM` item (its base factor or its joins) is a
/// derived subquery / nested join that carries DML.
fn table_with_joins_carries_dml(twj: &sqlparser::ast::TableWithJoins) -> bool {
    table_factor_carries_dml(&twj.relation)
        || twj
            .joins
            .iter()
            .any(|j| table_factor_carries_dml(&j.relation))
}

/// Whether a single table factor is a derived subquery / nested join whose body
/// carries DML. Non-subquery factors (base tables, table functions, pivots, …)
/// name no DML body here — a table *function* that calls a side-effecting
/// routine is caught separately by the UDF purity consult.
fn table_factor_carries_dml(factor: &sqlparser::ast::TableFactor) -> bool {
    use sqlparser::ast::TableFactor;
    match factor {
        TableFactor::Derived { subquery, .. } => query_carries_dml(subquery),
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => table_with_joins_carries_dml(table_with_joins),
        _ => false,
    }
}

/// Fail-closed net for a reserved DML verb (`INSERT` / `UPDATE` / `DELETE`)
/// smuggled inside an **expression** subquery of a `SELECT` — a `WHERE … IN
/// (UPDATE …)`, a scalar `(DELETE …)`, `EXISTS (INSERT …)`, etc. — which the
/// structural [`set_expr_carries_dml`] walk (FROM/JOIN/CTE/set-op only) does not
/// descend into. These three verbs are Oracle **reserved** words: in a genuine
/// read they can appear only as `FOR UPDATE` (which the caller already forces
/// `Guarded` via `query.locks`), never as an identifier, so scanning the
/// canonicalized token stream (string/`q'[…]'`/quoted-identifier literals and
/// comments already collapsed by [`canonical_marker_scan`], word-boundaried by
/// the surrounding spaces) adds **no** false positive on a legitimate read while
/// closing the Expr-embedded smuggled-DML case (oracle-derived-dml-body).
/// `MERGE` is deliberately excluded — it is a *non-reserved* Oracle keyword that
/// may legally be a column/table/alias name, so a bare-token scan for it would
/// over-restrict real reads; a structural `MERGE` is still caught by
/// [`set_expr_carries_dml`].
fn query_embeds_reserved_dml_verb(sql: &str) -> bool {
    let scan = canonical_marker_scan(&sql.to_ascii_uppercase());
    [" INSERT ", " UPDATE ", " DELETE "]
        .iter()
        .any(|verb| scan.contains(verb))
}

/// Fold the conservative, parser-INDEPENDENT leading-verb floor into a
/// statement's parser-derived classification (bead QA100 .84, defense-in-depth
/// fix #2). A statement whose LEADING tokens name a DCL/admin operation floors at
/// `Admin`; an object-DDL leading verb floors at `Ddl`; anything else contributes
/// no floor. The floor is applied as a pure MAX on BOTH the danger tier and the
/// required level, so a *successful* parse can never LOWER a statement below the
/// tier its leading tokens demand — even if sqlparser evolves a new, lower-tier
/// arm for it, or its arm is (mis)mapped here. This is the tighten-only twin of
/// the parse-failure branch, which already applies the same leading-verb scans.
///
/// `Forbidden` (required `None`) is the strictest verdict; the floor never
/// re-admits it to a permissible level. The admin scan is consulted FIRST so an
/// admin-scope leading verb (GRANT / ALTER USER / …) wins over the broader
/// object-DDL match.
fn raise_to_leading_floor(class: StatementClass, sql: &str) -> StatementClass {
    let upper = sql.trim_start().to_ascii_uppercase();
    let (floor_danger, floor_level) = if starts_with_admin_verb(&upper) {
        (DangerLevel::Destructive, OperatingLevel::Admin)
    } else if starts_with_ddl_verb(&upper) {
        (DangerLevel::Destructive, OperatingLevel::Ddl)
    } else {
        return class;
    };
    StatementClass {
        danger: class.danger.max(floor_danger),
        // `None` (Forbidden) is the strictest verdict; `map` preserves it, so the
        // floor never relaxes a Forbidden statement back to a permissible level.
        required: class.required.map(|level| level.max(floor_level)),
        objects: class.objects,
        r15_derivation: class.r15_derivation,
    }
}

/// Classify a single pre-split, pure-SQL statement (Stage B + purity consult).
fn classify_statement(
    sql: &str,
    oracle: &dyn SideEffectOracle,
    modes: StrictModes,
    verified_local_vector_embedding: bool,
) -> StatementClass {
    use sqlparser::ast::Statement;
    let dialect = OracleDialect {};
    let parser_sql = normalize_vector_embedding_for_parser(sql);
    let parsed = match Parser::parse_sql(&dialect, &parser_sql) {
        Ok(stmts) if stmts.len() == 1 => stmts.into_iter().next().expect("len 1"),
        // Unparseable or unexpectedly multi → fail-closed. Before settling on the
        // ReadWrite default, run a leading admin/DCL verb scan over the
        // canonicalized (literal/quote-aware, word-boundaried) text: sqlparser
        // 0.62 cannot parse most Oracle admin statements (`GRANT DBA`, `ALTER
        // USER … IDENTIFIED BY`, `ALTER SYSTEM/DATABASE/PROFILE`, `AUDIT`/
        // `NOAUDIT`, `CREATE/ALTER/DROP USER|ROLE`, …), and under-levelling every
        // one of them to ReadWrite lets a ReadWrite-elevated session run
        // privilege escalation with no Admin step-up. A leading admin verb forces
        // Destructive / Admin; genuinely non-admin unparseable SQL keeps the
        // ReadWrite fail-closed default (oracle-clgt.3).
        _ => {
            let upper = sql.trim_start().to_ascii_uppercase();
            if starts_with_admin_verb(&upper) {
                return StatementClass {
                    danger: DangerLevel::Destructive,
                    required: Some(OperatingLevel::Admin),
                    objects: Vec::new(),
                    r15_derivation: None,
                };
            }
            // Object-level destructive DDL that sqlparser 0.62 cannot parse —
            // RENAME / PURGE / FLASHBACK <table> / (DIS)ASSOCIATE STATISTICS —
            // would otherwise under-level to Guarded/ReadWrite, letting a
            // ReadWrite-elevated session run irreversible DDL with no Ddl
            // step-up and bypassing the schema deny_ddl / guarded-destructive
            // policy. Force Destructive / Ddl (oracle-j1ep.3). Runs AFTER the
            // admin scan so the database-level FLASHBACK forms already escalated
            // to Admin above.
            if starts_with_ddl_verb(&upper) {
                return StatementClass {
                    danger: DangerLevel::Destructive,
                    required: Some(OperatingLevel::Ddl),
                    objects: Vec::new(),
                    r15_derivation: None,
                };
            }
            // A dangerous verb BURIED after a benign leading clause in an
            // unparseable single segment (`SELECT 1 FROM dual <nl> DROP TABLE t`)
            // is a no-`;` desync — the pure-SQL analog of the buried-`;`
            // (saw_buried_semicolon) and trailing-SQL-after-END
            // (saw_top_level_after_block_close) arms. The leading SELECT means
            // the admin/DDL scans above do not fire; without this it falls
            // through to Guarded/ReadWrite and a ReadWrite session would be
            // Allowed to run the hidden GRANT/DROP/TRUNCATE/no-WHERE-UPDATE once
            // any per-statement / savepoint-preview executor splits the batch.
            // Fail closed, symmetric with the `;`-delimited form (oracle-b6yl.1).
            if has_buried_dangerous_verb(&upper) {
                return StatementClass::forbidden();
            }
            return StatementClass {
                danger: DangerLevel::Guarded,
                required: Some(OperatingLevel::ReadWrite),
                objects: Vec::new(),
                r15_derivation: None,
            };
        }
    };
    let guarded_rw = |objects: Vec<String>| StatementClass {
        danger: DangerLevel::Guarded,
        required: Some(OperatingLevel::ReadWrite),
        objects,
        r15_derivation: None,
    };
    let destructive = |level: OperatingLevel, objects: Vec<String>| StatementClass {
        danger: DangerLevel::Destructive,
        required: Some(level),
        objects,
        r15_derivation: None,
    };
    // NOTE: `Statement::Variant { .. }` matches tuple / newtype variants too
    // (their fields are positional `0`, `1`, …), so every arm below uses the
    // uniform `{ .. }` form except genuine field-less unit variants.
    let base = match parsed {
        Statement::Query(ref query) => {
            // A `Statement::Query` whose body is (or contains, under a set
            // operation / parenthesized subquery / CTE body / FROM-JOIN derived
            // subquery) a DML `SetExpr` is a smuggled write: `WITH a AS (SELECT …)
            // UPDATE t SET …` parses as Query→SetExpr::Update, and
            // `SELECT * FROM (UPDATE t SET x=1)` hides the write in a derived
            // subquery — neither surfaces as `Statement::Update`. Fail closed to a
            // write classification so a READ_ONLY session never sees an
            // `allow`/ReadOnly verdict for text carrying a
            // UPDATE/DELETE/MERGE/INSERT (oracle-cte-dml-body /
            // oracle-derived-dml-body). The reserved-verb canonical scan closes
            // the remaining Expr-embedded case (`WHERE … IN (UPDATE …)`, scalar
            // `(DELETE …)`) the structural walk does not descend into.
            if set_expr_carries_dml(&query.body) || query_embeds_reserved_dml_verb(sql) {
                return guarded_rw(Vec::new());
            }
            // `sequence.NEXTVAL` is syntactically a pseudocolumn rather than a
            // function call, but it permanently advances sequence state even if
            // the surrounding transaction rolls back. It therefore requires the
            // governed READ_WRITE path and must never reach `oracle_query`.
            let sequence_nextvals = sequence_nextval_refs(sql);
            if !sequence_nextvals.is_empty() {
                return guarded_rw(
                    sequence_nextvals
                        .into_iter()
                        .map(|sequence| sequence.name)
                        .collect(),
                );
            }
            // SELECT/WITH: Safe only if it calls no unproven user-defined
            // function (R15). Any UDF not ProvenReadOnly → Guarded.
            let calls = user_defined_calls(sql, verified_local_vector_embedding);
            let all_proven = calls
                .iter()
                .all(|c| oracle.routine_purity(c).permits_safe());
            // The engine's trigger/VPD walk also gets a say: a UDF-free SELECT
            // can still fire side-effecting database logic the SQL text never
            // names. The default UnknownOracle keeps statement-level `Unknown`
            // permissive so the engine-free baseline stays stable; a consumer
            // that binds a real oracle can opt into fail-closed `Unknown`
            // handling with `Classifier::with_statement_unknown_guarded`.
            let base_objects = query_base_objects(query);
            let stmt_purity = if base_objects.is_empty() {
                Purity::ProvenReadOnly
            } else {
                oracle.statement_purity(&base_objects)
            };
            let stmt_blocks_safe = matches!(stmt_purity, Purity::ProvenSideEffecting)
                || (modes.statement_unknown_guarded && matches!(stmt_purity, Purity::Unknown));
            // `SELECT … FOR UPDATE` (incl. OF/NOWAIT/SKIP LOCKED) takes row
            // locks and holds a transaction open — levels.rs:93 documents it as
            // Guarded, never Safe. The AST carries `query.locks`; a non-empty
            // lock list forces the guarded branch (oracle-ajm2.6).
            let has_row_lock = !query.locks.is_empty();
            // A qualified, paren-less callable in value position invokes a
            // function Oracle never required `()` for (bead .102). Opt-in
            // (served/strict): a `root.member` whose root is not a table / view /
            // alias in the current/correlated scope is an unproven call → block Safe.
            let unresolved_calls = if modes.guard_unresolved_qualified_calls {
                unresolved_qualified_calls(query)
            } else {
                Vec::new()
            };
            let has_unresolved_call = !unresolved_calls.is_empty();
            let stmt_pure = (calls.is_empty() || all_proven)
                && !stmt_blocks_safe
                && !has_row_lock
                && !has_unresolved_call;
            let r15_derivation = (!calls.is_empty()).then_some(if all_proven {
                R15Derivation::AllProvenReadOnly
            } else {
                R15Derivation::UnprovenPresent
            });
            let mut objects: Vec<String> = calls.iter().map(|c| c.name.clone()).collect();
            if stmt_pure {
                StatementClass {
                    danger: DangerLevel::Safe,
                    required: Some(OperatingLevel::ReadOnly),
                    objects,
                    r15_derivation,
                }
            } else {
                if stmt_blocks_safe {
                    objects.extend(base_objects.iter().map(|o| o.name.clone()));
                }
                objects.extend(unresolved_calls);
                StatementClass {
                    danger: DangerLevel::Guarded,
                    required: Some(OperatingLevel::ReadWrite),
                    objects,
                    r15_derivation,
                }
            }
        }
        Statement::Insert(_) => guarded_rw(Vec::new()),
        Statement::Update(u) => {
            if u.selection.is_none() {
                destructive(OperatingLevel::ReadWrite, Vec::new()) // no WHERE
            } else {
                guarded_rw(Vec::new())
            }
        }
        Statement::Delete(d) => {
            if d.selection.is_none() {
                destructive(OperatingLevel::ReadWrite, Vec::new()) // no WHERE
            } else {
                guarded_rw(Vec::new())
            }
        }
        Statement::Merge { .. } => guarded_rw(Vec::new()),
        Statement::Explain { .. } => StatementClass {
            // EXPLAIN PLAN writes PLAN_TABLE — Guarded, never Safe (§5.4/§5.8).
            danger: DangerLevel::Guarded,
            required: Some(OperatingLevel::ReadWrite),
            objects: Vec::new(),
            r15_derivation: None,
        },
        // Transaction control, cursor lifecycle, table locks, non-role session
        // SET, and CALL are session-/transaction-scoped ReadWrite operations —
        // neither DDL nor DCL. They are enumerated EXPLICITLY so they keep their
        // Guarded/ReadWrite floor rather than being swept into the fail-closed
        // `Forbidden` default at the bottom (bead QA100 .84 fix #1). `SET ROLE`
        // is NOT here — it is DCL and is handled with the Admin set below.
        Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. }
        | Statement::ReleaseSavepoint { .. }
        | Statement::StartTransaction { .. }
        | Statement::Declare { .. }
        | Statement::Fetch { .. }
        | Statement::Open { .. }
        | Statement::Close { .. }
        | Statement::Lock { .. }
        | Statement::LockTables { .. }
        | Statement::UnlockTables
        | Statement::Call { .. } => guarded_rw(Vec::new()),
        // DROP USER / DROP ROLE is account/role administration (cross-schema
        // DCL, levels.rs:37), NOT ordinary object DDL — it requires Admin, not
        // Ddl. Matched BEFORE the generic object `Drop` arm; other DROPs
        // (TABLE/VIEW/INDEX/…) stay Ddl (oracle-clgt.3).
        Statement::Drop {
            object_type: sqlparser::ast::ObjectType::User | sqlparser::ast::ObjectType::Role,
            ..
        } => destructive(OperatingLevel::Admin, Vec::new()),
        // DCL / privilege / security / instance / whole-database administration →
        // Admin. GRANT/REVOKE/DENY touch the privilege model; role & policy
        // create/alter/drop, database create/attach, secrets, servers/connectors,
        // and instance verbs (KILL/FLUSH/DISCARD/INSTALL) are all account- or
        // instance-level. `SET [SESSION|LOCAL] ROLE …` (Statement::Set(SetRole))
        // enables a possibly write-bearing role post-connect and is DCL. Every one
        // of these previously fell through the catch-all and under-levelled to
        // ReadWrite (oracle-clgt.3 / oracle-clgt.13 / bead QA100 .84).
        Statement::Set(sqlparser::ast::Set::SetRole { .. })
        | Statement::Grant { .. }
        | Statement::Deny { .. }
        | Statement::Revoke { .. }
        | Statement::CreateRole { .. }
        | Statement::AlterRole { .. }
        | Statement::CreatePolicy { .. }
        | Statement::AlterPolicy { .. }
        | Statement::DropPolicy { .. }
        | Statement::CreateSchema { .. }
        | Statement::CreateDatabase { .. }
        | Statement::AttachDatabase { .. }
        | Statement::CreateSecret { .. }
        | Statement::DropSecret { .. }
        | Statement::CreateServer { .. }
        | Statement::CreateConnector { .. }
        | Statement::AlterConnector { .. }
        | Statement::DropConnector { .. }
        | Statement::Kill { .. }
        | Statement::Flush { .. }
        | Statement::Discard { .. }
        | Statement::Install { .. } => destructive(OperatingLevel::Admin, Vec::new()),
        // Any OTHER session-local `SET` (SET TRANSACTION READ ONLY, SET <NLS
        // param>, …) is benign session state — Guarded/ReadWrite. Placed AFTER the
        // `Set(SetRole)` DCL arm so role-switching never reaches here.
        Statement::Set(_) => guarded_rw(Vec::new()),
        // Object-level DDL (schema-object create/alter/drop, COMMENT ON, ANALYZE,
        // TRUNCATE, table stats/cache). Oracle DDL implicit-commits before AND
        // after and cannot be rolled back, so NONE of these may run at ReadWrite —
        // they floor at Ddl. Every variant sqlparser 0.62 can produce for these
        // forms is enumerated so a parsed-but-unmatched DDL statement can never
        // fall through to the old ReadWrite default again (bead QA100 .84 fix #1).
        Statement::CreateTable { .. }
        | Statement::CreateView { .. }
        | Statement::CreateVirtualTable { .. }
        | Statement::CreateIndex { .. }
        | Statement::CreateSequence { .. }
        | Statement::CreateDomain { .. }
        | Statement::CreateType { .. }
        | Statement::CreateExtension { .. }
        | Statement::CreateCollation { .. }
        | Statement::CreateFunction { .. }
        | Statement::CreateTrigger { .. }
        | Statement::CreateProcedure { .. }
        | Statement::CreateMacro { .. }
        | Statement::CreateStage { .. }
        | Statement::CreateOperator { .. }
        | Statement::CreateOperatorClass { .. }
        | Statement::CreateOperatorFamily { .. }
        | Statement::AlterTable { .. }
        | Statement::AlterIndex { .. }
        | Statement::AlterView { .. }
        | Statement::AlterType { .. }
        | Statement::AlterFunction { .. }
        | Statement::AlterCollation { .. }
        | Statement::AlterSchema { .. }
        | Statement::AlterOperator { .. }
        | Statement::AlterOperatorClass { .. }
        | Statement::AlterOperatorFamily { .. }
        | Statement::Drop { .. }
        | Statement::DropFunction { .. }
        | Statement::DropDomain { .. }
        | Statement::DropProcedure { .. }
        | Statement::DropTrigger { .. }
        | Statement::DropExtension { .. }
        | Statement::DropOperator { .. }
        | Statement::DropOperatorClass { .. }
        | Statement::DropOperatorFamily { .. }
        | Statement::Truncate { .. }
        | Statement::Comment { .. }
        | Statement::Analyze { .. }
        | Statement::OptimizeTable { .. }
        | Statement::Cache { .. }
        | Statement::UNCache { .. }
        | Statement::Msck { .. } => destructive(OperatingLevel::Ddl, Vec::new()),
        // Anything else sqlparser recognizes but this classifier does not
        // explicitly tier (exotic non-Oracle DDL, data-movement, dynamic EXECUTE,
        // SHOW/USE, …) fails CLOSED to Forbidden — NEVER the old ReadWrite default.
        // A successful parse is not a license to admit an unrecognized statement
        // below its true floor (bead QA100 .84 fix #1). An operator who genuinely
        // needs a specific such statement can allow-list it by exact bytes.
        _ => StatementClass::forbidden(),
    };
    // Defense in depth (bead QA100 .84 fix #2): fold in the parser-INDEPENDENT
    // leading-verb floor so a successful parse can never LOWER a statement below
    // the DDL/DCL/Admin tier its leading tokens demand.
    raise_to_leading_floor(base, sql)
}

/// Split a benign, balanced PL/SQL block's *outer* body (the tokens strictly
/// between the `BEGIN` that drives block depth 0→1 and its matching `END`) into
/// its top-level statement segments, reconstructed as SQL text. The single depth
/// model mirrors [`analyze_batch`] exactly (`BEGIN`/`IF`/`CASE`/`LOOP` open a
/// level, `END`/`END IF`/`END LOOP`/`END CASE` close one, whitespace never
/// resets `expecting_close`), so `;` terminators buried inside nested control
/// flow stay attached to their enclosing segment and only depth-1 `;` split the
/// body. Used to re-apply the bare-statement classifier to a block's interior so
/// wrapping a statement in `BEGIN … END` can never LOWER its classification
/// (iec3.2.30). Extraction only — classification stays in [`classify_statement`].
fn block_interior_segments(sql: &str) -> Vec<String> {
    let Ok(tokens) = Tokenizer::new(&OracleDialect {}, sql).tokenize() else {
        return Vec::new();
    };
    let mut depth: i64 = 0;
    let mut expecting_close = false;
    let mut in_body = false;
    let mut segments: Vec<String> = Vec::new();
    let mut current = String::new();
    for token in &tokens {
        match token {
            Token::Word(w) => {
                let keyword = w
                    .quote_style
                    .is_none()
                    .then(|| w.value.to_ascii_uppercase());
                match keyword.as_deref() {
                    Some("BEGIN") => {
                        depth += 1;
                        expecting_close = false;
                        if depth == 1 && !in_body {
                            // The opening BEGIN: the body starts AFTER it, so the
                            // BEGIN keyword itself is never part of a segment.
                            in_body = true;
                            continue;
                        }
                    }
                    Some("IF") | Some("CASE") | Some("LOOP") => {
                        if !expecting_close {
                            depth += 1;
                        }
                        expecting_close = false;
                    }
                    Some("END") => {
                        depth -= 1;
                        expecting_close = true;
                        if depth == 0 && in_body {
                            // The matching outer END: flush any trailing segment
                            // and stop before appending the END itself.
                            if !current.trim().is_empty() {
                                segments.push(std::mem::take(&mut current));
                            }
                            break;
                        }
                    }
                    // Any other word (incl. DECLARE) is ordinary content.
                    _ => expecting_close = false,
                }
            }
            Token::SemiColon => {
                expecting_close = false;
                if in_body && depth == 1 {
                    // A body top-level statement boundary: flush and drop the `;`.
                    if !current.trim().is_empty() {
                        segments.push(std::mem::take(&mut current));
                    }
                    continue;
                }
            }
            // Whitespace/comments must NOT reset `expecting_close` (`END <ws> IF`).
            Token::Whitespace(_) => {}
            _ => expecting_close = false,
        }
        if in_body {
            current.push_str(&token.to_string());
        }
    }
    segments
}

/// The classification floor contributed by a benign block's interior: the MAX
/// `(danger, required level)` over every interior statement that parses cleanly
/// as exactly one SQL statement, obtained by re-running the SAME bare-statement
/// classifier ([`classify_statement`]) — the single source of truth, so a
/// WHERE-less DML inside a block earns the same Destructive/ReadWrite tier it
/// earns bare (iec3.2.30). Segments that do not parse cleanly (control flow,
/// PL/SQL-only statements) contribute nothing, and a cleanly-parsed single
/// statement never classifies Forbidden here (the [`classify_statement`] match
/// arms only ever return Safe/Guarded/Destructive), so this can only ever RAISE
/// the floor — never lower it and never introduce a level-less verdict.
fn block_interior_floor(
    sql: &str,
    oracle: &dyn SideEffectOracle,
    modes: StrictModes,
) -> Option<(DangerLevel, OperatingLevel)> {
    let mut acc: Option<(DangerLevel, OperatingLevel)> = None;
    for seg in block_interior_segments(sql) {
        // Only fold in a segment that parses as exactly one SQL statement.
        // Routing an unparseable/multi segment through `classify_statement`
        // would hit its fail-closed admin/DDL/buried-verb scans and could
        // OVER-raise a benign WHERE-qualified block (e.g. an `IF … UPDATE …
        // WHERE …; END IF` control-flow segment) — the pre-check keeps the fold
        // a faithful reuse of the bare-statement path, nothing more.
        if Parser::parse_sql(&OracleDialect {}, &seg)
            .map(|s| s.len())
            .unwrap_or(0)
            != 1
        {
            continue;
        }
        let class = classify_statement(&seg, oracle, modes, false);
        if let Some(level) = class.required {
            acc = Some(match acc {
                Some((d, l)) => (d.max(class.danger), l.max(level)),
                None => (class.danger, level),
            });
        }
    }
    acc
}

/// The fail-closed, engine-aware classifier.
pub struct Classifier {
    config: ClassifierConfig,
    oracle: Arc<dyn SideEffectOracle>,
    statement_unknown_guarded: bool,
}

impl Default for Classifier {
    fn default() -> Self {
        Classifier {
            config: ClassifierConfig::new(),
            oracle: Arc::new(UnknownOracle),
            statement_unknown_guarded: false,
        }
    }
}

impl Classifier {
    /// A classifier with the default fail-closed oracle (no engine bound).
    #[must_use]
    pub fn new(config: ClassifierConfig) -> Self {
        Classifier {
            config,
            oracle: Arc::new(UnknownOracle),
            statement_unknown_guarded: false,
        }
    }

    /// Bind the engine's real side-effect oracle (from the consumer side).
    #[must_use]
    pub fn with_oracle(mut self, oracle: Arc<dyn SideEffectOracle>) -> Self {
        self.oracle = oracle;
        self
    }

    /// Tighten statement-level `Unknown` purity to `Guarded` for SELECT base
    /// objects. This is intentionally opt-in so the default no-engine
    /// `UnknownOracle` continues to keep UDF-free plain SELECTs `Safe`.
    #[must_use]
    pub fn with_statement_unknown_guarded(mut self) -> Self {
        self.statement_unknown_guarded = true;
        self
    }

    /// The fully fail-closed **served/strict** posture: tighten statement-level
    /// `Unknown` purity (bead .82 — under the default `UnknownOracle` this
    /// refuses *every* read whose base objects are not proven read-only) **and**
    /// guard qualified paren-less callables (bead .102). Intended for the served
    /// raw-query gate where usability is subordinate to fail-closed safety; the
    /// caller accepts that reads then require a bound engine oracle proving the
    /// base objects read-only, or an operator allow-list entry.
    #[must_use]
    pub fn served_strict(mut self) -> Self {
        self.statement_unknown_guarded = true;
        self.config.guard_unresolved_qualified_calls = true;
        self
    }

    /// The strict-mode flags this classifier threads into per-statement analysis.
    fn modes(&self) -> StrictModes {
        StrictModes {
            statement_unknown_guarded: self.statement_unknown_guarded,
            guard_unresolved_qualified_calls: self.config.guard_unresolved_qualified_calls,
        }
    }

    /// Classify a statement / batch into a [`GuardDecision`], fail-closed, and
    /// attach the certificate built from this exact final decision.
    #[must_use]
    pub fn classify(&self, sql: &str) -> GuardDecision {
        let decision = self.classify_raw(sql, false);
        let certificate = VerdictCertificate::from_decision(sql, &decision);
        decision.with_verdict_certificate(certificate)
    }

    /// Classify a server-constructed `VECTOR_EMBEDDING` read after the caller
    /// has separately proven the exact local 23ai ONNX-model capability. This
    /// is deliberately opt-in: ordinary caller SQL must use [`Self::classify`]
    /// and therefore continues to treat `VECTOR_EMBEDDING` as an unproven UDF.
    ///
    /// The method does not authorize an arbitrary user model or filter. The
    /// only production caller constructs the query from a dictionary-derived
    /// model identifier and bind-only caller input before invoking this path.
    #[must_use]
    pub fn classify_verified_local_vector_embedding(&self, sql: &str) -> GuardDecision {
        let decision = self.classify_raw(sql, true);
        let certificate = VerdictCertificate::from_decision(sql, &decision);
        decision.with_verdict_certificate(certificate)
    }

    /// Classification implementation before the response/audit witness is
    /// attached. Keeping this private makes it impossible for callers to obtain
    /// an enforced decision without the certificate from the same call.
    fn classify_raw(&self, sql: &str, verified_local_vector_embedding: bool) -> GuardDecision {
        let trimmed = sql.trim();
        if trimmed.is_empty() {
            return GuardDecision {
                danger: DangerLevel::Safe,
                required_level: Some(OperatingLevel::ReadOnly),
                objects_affected: Vec::new(),
                safe_alternative: None,
                reason: "empty input".to_owned(),
                reason_category: None,
                offending_construct: None,
                non_transactional_effect: false,
                query_effect_requires_fetch: false,
                verdict_certificate: None,
                certificate_derivation: Vec::new(),
            };
        }

        // ALTER SESSION persists independently of DML rollback and can change
        // container, trace/events, hidden parameters, and other security or
        // diagnostic state. Apply the same strict allowlist used by profile
        // login/session setup before the operator allow-list or level gate, so
        // raw oracle_execute and aliases cannot turn READ_WRITE into a bypass.
        if let Some(allowed) = alter_session_policy(sql) {
            if !allowed {
                let mut decision = forbidden_decision(
                    "ALTER SESSION targets a non-allowlisted or malformed session setting"
                        .to_owned(),
                );
                decision.safe_alternative = Some(
                    "use only an allowlisted ALTER SESSION SET parameter; configure trusted initialization through profile login_statements"
                        .to_owned(),
                );
                return decision
                    .categorized(ReasonCategory::Other, Some("ALTER SESSION".to_owned()));
            }

            return GuardDecision {
                danger: DangerLevel::Guarded,
                required_level: Some(OperatingLevel::ReadWrite),
                objects_affected: Vec::new(),
                safe_alternative: None,
                reason: "allowlisted ALTER SESSION setting (persists outside transaction rollback)"
                    .to_owned(),
                reason_category: Some(ReasonCategory::RequiresHigherLevel),
                offending_construct: Some("ALTER SESSION".to_owned()),
                non_transactional_effect: true,
                query_effect_requires_fetch: false,
                verdict_certificate: None,
                certificate_derivation: Vec::new(),
            };
        }

        // The dispatcher can prove Oracle's one-child edition rule only for
        // the exact lifecycle grammar below. Refuse every alternate
        // CREATE/DROP EDITION spelling here, before operator allow-lists and
        // before a database call, so no variant can dodge the preflight by
        // falling through generic CREATE/DROP DDL classification.
        let edition_lifecycle = parse_edition_lifecycle_sql(sql);
        if matches!(edition_lifecycle, EditionLifecycleParse::Invalid) {
            let mut decision = forbidden_decision(
                "edition lifecycle SQL must be exactly CREATE EDITION <child> AS CHILD OF <parent> or DROP EDITION <edition> [CASCADE]"
                    .to_owned(),
            );
            decision.safe_alternative = Some(
                "create one linear child with CREATE EDITION <child> AS CHILD OF <parent>, or retire an old edition with DROP EDITION <edition> [CASCADE]"
                    .to_owned(),
            );
            return decision
                .categorized(ReasonCategory::Other, Some("EDITION lifecycle".to_owned()));
        }

        // The dispatcher owns the transaction boundary. If caller SQL can
        // commit, roll back, create a savepoint, or change transaction mode,
        // the rollback-default response and audit outcome cease to be true.
        // This invariant precedes the operator allow-list: an exact allow-list
        // entry may approve statement effects, but cannot transfer transaction
        // ownership away from the server. ALTER SESSION is handled first so a
        // session clause containing words such as COMMIT is still governed by
        // the complete shared session-setting policy.
        if let Some(construct) = transaction_control_construct(sql) {
            let mut decision = forbidden_decision(format!(
                "caller-controlled {construct} is forbidden because the server owns commit, rollback, and transaction audit outcomes"
            ));
            decision.safe_alternative = Some(
                "submit only the DML body and let oracle_execute perform the requested commit or rollback"
                    .to_owned(),
            );
            return decision.categorized(
                ReasonCategory::TransactionControl,
                Some(construct.to_owned()),
            );
        }

        // Oracle allows zero/default-argument functions to omit parentheses in
        // PL/SQL expressions. Without a semantic symbol table, `pkg.value` (or
        // even bare `value`) might be a variable, record field, or an opaque
        // function invocation. Admit only the engine-free subset whose complete
        // executable statements are independently classified.
        if let Some(construct) = unanalyzable_plsql_construct(sql) {
            let mut decision = forbidden_decision(format!(
                "{construct}; hidden routine effects cannot be ruled out"
            ));
            decision.safe_alternative = Some(
                "submit each static SQL statement directly; procedural execution requires catalog-aware resolution that is not available on this path"
                    .to_owned(),
            );
            return decision.categorized(
                ReasonCategory::UnprovenSideEffect,
                Some(construct.to_owned()),
            );
        }

        let has_sequence_nextval = !sequence_nextval_refs(sql).is_empty();

        match stage_a(sql, &self.config) {
            // A human's exact-statement allow-list can never turn a governed
            // edition create/drop into a READ_ONLY statement. These operations
            // must retain their normal DDL floor and dispatcher preflight.
            StageA::AllowListed
                if !matches!(edition_lifecycle, EditionLifecycleParse::Parsed(_)) =>
            {
                return GuardDecision {
                    danger: DangerLevel::Safe,
                    required_level: Some(OperatingLevel::ReadOnly),
                    objects_affected: Vec::new(),
                    safe_alternative: None,
                    reason: "operator allow-listed".to_owned(),
                    reason_category: None,
                    offending_construct: None,
                    non_transactional_effect: false,
                    query_effect_requires_fetch: false,
                    verdict_certificate: None,
                    certificate_derivation: Vec::new(),
                };
            }
            StageA::AllowListed => {}
            StageA::BlockListed(pat) => {
                return forbidden_decision(format!("matched block-list pattern: {pat}"))
                    .categorized(ReasonCategory::BlockListed, Some(pat));
            }
            StageA::PlSqlBlock { dangerous } => {
                // Re-derive (single source: `is_plsql_bearing_create`) whether
                // this is a PL/SQL-bearing CREATE [OR REPLACE] of a stored
                // object, rather than threading it through the public `StageA`
                // enum (that would break the crate API for an internal detail).
                // oracle-p0d6.
                let plsql_create = is_plsql_bearing_create(sql);
                let stored_unit_create = stored_unit_create(sql).is_some();
                // Any PL/SQL block is at minimum Guarded; a dangerous
                // side-effect marker (EXECUTE IMMEDIATE / UTL_FILE / …) is
                // Forbidden (fail-closed — we cannot prove its purity here).
                // This runs BEFORE the create-form floor so a dangerous body
                // (e.g. `CREATE TRIGGER … EXECUTE IMMEDIATE 'DROP …'`) still
                // escalates ABOVE Ddl to Forbidden — the create-form floor only
                // ever RAISES a benign body's level, never lowers this one.
                if dangerous {
                    return forbidden_decision(
                        "PL/SQL block contains a dynamic-SQL / file / network / scheduler side-effect marker".to_owned(),
                    )
                    .categorized(
                        ReasonCategory::DynamicSql,
                        Some("dynamic-SQL / file / network / scheduler side-effect marker".to_owned()),
                    );
                }
                let shape = analyze_batch(sql);
                if !shape.balanced {
                    return forbidden_decision(
                        "PL/SQL block has unbalanced BEGIN/END (desync) — fail-closed".to_owned(),
                    )
                    .categorized(
                        ReasonCategory::UnbalancedBlock,
                        Some("unbalanced BEGIN/END".to_owned()),
                    );
                }
                // Stored package/type units have one implicit outer scope, so
                // member semicolons stay nested and the unit-closing `;` is the
                // sole top-level boundary. Anything else is a second statement
                // and must fail closed. This keeps package specs and executable
                // package/type bodies on the same token-aware shape law.
                if stored_unit_create && shape.statement_count != 1 {
                    return forbidden_decision(
                        "stored package/type unit contains trailing or multiple top-level statements — fail-closed"
                            .to_owned(),
                    )
                    .categorized(
                        ReasonCategory::MultiStatementBatch,
                        Some("multiple statements around stored package/type unit".to_owned()),
                    );
                }
                // oracle-lokg.1: a balanced anonymous block followed by trailing
                // top-level SQL after `END` (`BEGIN NULL; END; GRANT DBA TO scott`)
                // rebalances the depth counter to 0, so the trailing
                // GRANT/DROP/TRUNCATE would be silently dropped from classification
                // and run with no Admin/DDL step-up. Fail closed — the trailing SQL
                // must be submitted as its own statement so Stage B can level it.
                if shape.saw_top_level_after_block_close {
                    return forbidden_decision(
                        "PL/SQL block followed by trailing top-level SQL after END — fail-closed"
                            .to_owned(),
                    )
                    .categorized(
                        ReasonCategory::MultiStatementBatch,
                        Some("trailing top-level SQL after END".to_owned()),
                    );
                }
                // Body-derived floor for a benign, balanced block: at minimum
                // Guarded / ReadWrite (it may run DML we cannot prove
                // side-effect-free). We then re-apply the bare-statement
                // classifier to the block's interior and fold it in as a pure MAX
                // on BOTH danger and level, so wrapping a statement in `BEGIN …
                // END` can never LOWER its classification below the same statement
                // submitted bare: a WHERE-less DELETE/UPDATE stays
                // Destructive/ReadWrite instead of collapsing to Guarded
                // (iec3.2.30, the monotone-wrap TIGHTENING). Interior segments
                // that do not parse cleanly contribute nothing, so the fold can
                // only ever RAISE.
                let mut body_danger = DangerLevel::Guarded;
                let mut body_level = OperatingLevel::ReadWrite;
                if let Some((interior_danger, interior_level)) =
                    block_interior_floor(sql, self.oracle.as_ref(), self.modes())
                {
                    body_danger = body_danger.max(interior_danger);
                    body_level = body_level.max(interior_level);
                }
                // A PL/SQL-bearing `CREATE [OR REPLACE] <object>` additionally
                // REPLACES a stored object — that is DDL — so it floors at Ddl /
                // Destructive. Both floors are pure MAXes (never replacements), so
                // the change can only ever RAISE: benign anonymous blocks stay at
                // their body-derived floor, benign creates rise to at least Ddl,
                // and nothing that already earned Ddl+ (or Forbidden, above) is
                // lowered (oracle-p0d6 — the object-clobbering-replace
                // fail-open-tier fix, mirroring oracle-y54x.1 for the pure-DDL
                // create forms).
                let (required, danger, reason) = if plsql_create {
                    (
                        body_level.max(OperatingLevel::Ddl),
                        body_danger.max(DangerLevel::Destructive),
                        "CREATE [OR REPLACE] of a PL/SQL stored object (DDL — replaces stored code)"
                            .to_owned(),
                    )
                } else {
                    (
                        body_level,
                        body_danger,
                        "PL/SQL block (cannot be proven side-effect-free here)".to_owned(),
                    )
                };
                let reason = if has_sequence_nextval {
                    format!(
                        "sequence NEXTVAL advances state independently of transaction rollback; classified PL/SQL block as {danger:?}/{}",
                        required.as_str()
                    )
                } else {
                    reason
                };
                return GuardDecision {
                    danger,
                    required_level: Some(required),
                    objects_affected: Vec::new(),
                    safe_alternative: Some(
                        "wrap the logic in an analysable package and call it, or run pure SQL"
                            .to_owned(),
                    ),
                    reason,
                    reason_category: Some(ReasonCategory::PlSqlBlock),
                    offending_construct: Some("PL/SQL block".to_owned()),
                    non_transactional_effect: has_sequence_nextval,
                    query_effect_requires_fetch: false,
                    verdict_certificate: None,
                    certificate_derivation: Vec::new(),
                };
            }
            StageA::PureSql => {}
        }

        // Splitter: literal/quote-aware balance + statement count.
        let shape = analyze_batch(sql);
        if !shape.balanced {
            return forbidden_decision(
                "lexer desync (unbalanced BEGIN/END or unterminated literal) — fail-closed"
                    .to_owned(),
            )
            .categorized(
                ReasonCategory::UnbalancedBlock,
                Some("unbalanced BEGIN/END or unterminated literal".to_owned()),
            );
        }
        // We reached this branch via `StageA::PureSql`, so there is no PL/SQL
        // block — yet the lexer saw a `;` nested at block depth > 0. In pure SQL
        // a `;` is always a top-level statement terminator; a buried one means a
        // keyword-collision identifier alias (e.g. `SELECT 1 AS loop … ; DROP …;
        // END;`) or an unbalanced SQL `CASE`/`IF`/`LOOP` inflated the depth
        // counter and swallowed a real top-level boundary, letting a trailing
        // `END` rebalance the batch to a single Guarded statement and hide a
        // DROP/GRANT/TRUNCATE. Fail closed (oracle-73t1.1 / oracle-73t1.5). The
        // internal `has_plsql_block` flag is deliberately NOT trusted here: a
        // bare `BEGIN`/`DECLARE` used as a SQL alias falsely flips it, but StageA
        // already authoritatively determined this is pure SQL.
        if shape.saw_buried_semicolon {
            return forbidden_decision(
                "pure-SQL batch hides a `;` boundary inside CASE/IF/LOOP depth (desync) — fail-closed"
                    .to_owned(),
            )
            .categorized(
                ReasonCategory::MultiStatementBatch,
                Some("hidden `;` boundary inside CASE/IF/LOOP depth".to_owned()),
            );
        }

        // Classify each statement; the batch danger is the max, and any
        // Forbidden sub-statement rejects the whole batch.
        let classes: Vec<StatementClass> = if shape.statement_count <= 1 {
            vec![classify_statement(
                sql,
                self.oracle.as_ref(),
                self.modes(),
                verified_local_vector_embedding,
            )]
        } else {
            // Multi-statement pure SQL: let the parser split, classify each.
            match Parser::parse_sql(&OracleDialect {}, sql) {
                Ok(stmts) => stmts
                    .iter()
                    .map(|s| {
                        classify_statement(
                            &s.to_string(),
                            self.oracle.as_ref(),
                            self.modes(),
                            verified_local_vector_embedding,
                        )
                    })
                    .collect(),
                Err(_) => vec![StatementClass::forbidden()],
            }
        };

        let danger = classes
            .iter()
            .map(|c| c.danger)
            .max()
            .unwrap_or(DangerLevel::Forbidden);
        if danger == DangerLevel::Forbidden {
            let category = if shape.statement_count > 1 {
                ReasonCategory::MultiStatementBatch
            } else {
                ReasonCategory::Other
            };
            return forbidden_decision("a sub-statement is Forbidden".to_owned())
                .categorized(category, None);
        }
        // Required level = the max over statements (None only if Forbidden,
        // already handled).
        let required_level = classes
            .iter()
            .filter_map(|c| c.required)
            .max()
            .or(Some(OperatingLevel::ReadOnly));
        let objects_affected: Vec<String> =
            classes.iter().flat_map(|c| c.objects.clone()).collect();
        let certificate_derivation = classes
            .iter()
            .filter_map(|class| class.r15_derivation)
            .map(|r15| VerdictDerivationStep {
                construct: r15.construct().to_owned(),
                rule_id: "R15".to_owned(),
            })
            .collect();
        // A well-formed statement that needs more than READ_ONLY is a level gate
        // (K8: RequiresHigherLevel); a proven read stays uncategorized.
        let needs_escalation = required_level.is_some_and(|level| level > OperatingLevel::ReadOnly);
        let reason_category = needs_escalation.then_some(ReasonCategory::RequiresHigherLevel);
        let query_effect_requires_fetch =
            has_sequence_nextval && sequence_nextval_query_requires_fetch(sql);
        GuardDecision {
            danger,
            required_level,
            objects_affected,
            safe_alternative: query_effect_requires_fetch.then(|| {
                "use sequence NEXTVAL inside a governed DML or PL/SQL statement; a query-shaped NEXTVAL must be fetched and is not an execute-with-rowcount operation"
                    .to_owned()
            }),
            reason: if has_sequence_nextval {
                format!(
                    "sequence NEXTVAL advances state independently of transaction rollback; classified {} statement(s) as {danger:?}/{}",
                    shape.statement_count.max(1),
                    required_level
                        .map(OperatingLevel::as_str)
                        .unwrap_or("FORBIDDEN")
                )
            } else {
                format!(
                    "classified {} statement(s) as {danger:?}",
                    shape.statement_count.max(1)
                )
            },
            reason_category,
            offending_construct: has_sequence_nextval.then(|| "sequence.NEXTVAL".to_owned()),
            non_transactional_effect: has_sequence_nextval,
            query_effect_requires_fetch,
            verdict_certificate: None,
            certificate_derivation,
        }
    }
}

fn forbidden_decision(reason: String) -> GuardDecision {
    GuardDecision {
        danger: DangerLevel::Forbidden,
        required_level: None,
        objects_affected: Vec::new(),
        safe_alternative: None,
        reason,
        // Default category for a bare forbidden decision; call sites refine it
        // via `categorized` where they can name the specific construct.
        reason_category: Some(ReasonCategory::Other),
        offending_construct: None,
        non_transactional_effect: false,
        query_effect_requires_fetch: false,
        verdict_certificate: None,
        certificate_derivation: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::levels::BlockReason;

    fn classify(sql: &str) -> GuardDecision {
        Classifier::default().classify(sql)
    }

    fn classify_one_statement(sql: &str) -> StatementClass {
        classify_statement(sql, &UnknownOracle, StrictModes::default(), false)
    }

    fn oracle_tokens(sql: &str) -> Vec<Token> {
        Tokenizer::new(&OracleDialect {}, sql)
            .tokenize()
            .expect("test SQL should tokenize")
    }

    fn token_refs(tokens: &[Token]) -> Vec<&Token> {
        tokens.iter().collect()
    }

    fn nth_unquoted_word(tokens: &[Token], value: &str, nth: usize) -> usize {
        tokens
            .iter()
            .enumerate()
            .filter(|(_, token)| {
                matches!(token, Token::Word(word) if word.quote_style.is_none() && word.value.eq_ignore_ascii_case(value))
            })
            .nth(nth)
            .map(|(idx, _)| idx)
            .unwrap_or_else(|| panic!("missing unquoted word {value:?} at occurrence {nth}"))
    }

    #[test]
    fn plain_select_is_safe() {
        let d = classify("SELECT id, name FROM employees WHERE id = 42");
        assert_eq!(d.danger, DangerLevel::Safe);
        assert_eq!(d.required_level, Some(OperatingLevel::ReadOnly));
        // K8: an allowed read carries no refusal category.
        assert_eq!(d.reason_category, None);
    }

    #[test]
    fn semantic_read_plan_preserves_relations_aliases_values_and_quotes() {
        let plan = semantic_read_plan(
            r#"SELECT o."Id", name, SYSDATE
               FROM "App"."Orders" o
               JOIN customers c ON c.id = o.customer_id
               WHERE o.status = :status"#,
        )
        .expect("simple query has an exact semantic plan");
        assert_eq!(plan.relations.len(), 2);
        assert_eq!(plan.statement_scope.relations.len(), 2);
        assert_eq!(plan.statement_scope.aliases.len(), 2);
        assert_eq!(plan.relations[0].parts[0].text, "App");
        assert_eq!(plan.relations[0].parts[0].quoting, QuoteSemantics::Quoted);
        assert!(plan.values.iter().any(|name| {
            name.parts.len() == 2
                && name.parts[0].text.eq_ignore_ascii_case("o")
                && name.parts[1].text == "Id"
                && name.parts[1].quoting == QuoteSemantics::Quoted
        }));
        assert!(
            !plan
                .values
                .iter()
                .any(|name| name.parts.len() == 1 && name.parts[0].text == "SYSDATE"),
            "Oracle pseudocolumn/built-in identifiers do not require catalog column proof"
        );
    }

    #[test]
    fn semantic_read_plan_exposes_parenthesis_free_callable_candidates() {
        let plan =
            semantic_read_plan("SELECT dangerous_fn, app_admin.run_ddl, pkg.member FROM dual")
                .expect("simple query has a plan");
        for expected in ["dangerous_fn", "run_ddl", "member"] {
            assert!(
                plan.values
                    .iter()
                    .any(|name| name.parts.last().is_some_and(|part| part.text == expected)),
                "missing semantic value candidate {expected}"
            );
        }
    }

    #[test]
    fn semantic_read_plan_treats_only_vector_distance_metrics_as_grammar() {
        for metric in ["COSINE", "EUCLIDEAN", "DOT"] {
            let sql = format!(
                "SELECT VECTOR_DISTANCE(d.embedding, '[1,0,0]', {metric}) AS distance FROM docs d"
            );
            let plan = semantic_read_plan(&sql).expect("vector query has an exact semantic plan");
            assert!(plan.values.iter().any(|name| {
                name.parts.len() == 2
                    && name.parts[0].text.eq_ignore_ascii_case("d")
                    && name.parts[1].text.eq_ignore_ascii_case("embedding")
            }));
            assert!(
                !plan.values.iter().any(|name| {
                    name.parts.len() == 1 && name.parts[0].text.eq_ignore_ascii_case(metric)
                }),
                "approved VECTOR_DISTANCE metric {metric} is grammar, not a column"
            );
        }

        let retained = semantic_read_plan(
            "SELECT COSINE, VECTOR_DISTANCE(d.embedding, '[1,0,0]', COSINE) AS distance FROM docs d",
        )
        .expect("query mixing a column and metric has an exact semantic plan");
        assert!(
            retained.values.iter().any(|name| {
                name.parts.len() == 1 && name.parts[0].text.eq_ignore_ascii_case("COSINE")
            }),
            "a same-named column outside the metric position still needs catalog proof"
        );

        let unknown = semantic_read_plan(
            "SELECT VECTOR_DISTANCE(d.embedding, '[1,0,0]', UNREVIEWED_METRIC) AS distance FROM docs d",
        )
        .expect("unknown metric query still has a plan");
        assert!(
            unknown.values.iter().any(|name| {
                name.parts.len() == 1
                    && name.parts[0].text.eq_ignore_ascii_case("UNREVIEWED_METRIC")
            }),
            "unreviewed metric spelling must remain a resolved value dependency"
        );

        // The exemption is keyed to the FUNCTION as much as to the metric. Dropping
        // an identifier from the catalog-proof set is a fail-open — it is how a
        // reference the classifier cannot resolve stops being asked about — so it
        // must apply to the real, unquoted Oracle builtin and to nothing else.
        for sql in [
            // A user-defined function that merely takes a metric-shaped argument.
            "SELECT FOO(d.embedding, '[1,0,0]', COSINE) AS distance FROM docs d",
            // A QUOTED "VECTOR_DISTANCE" is a user object that happens to share the
            // builtin's spelling, not the builtin (see is_semantic_builtin_identifier).
            "SELECT \"VECTOR_DISTANCE\"(d.embedding, '[1,0,0]', COSINE) AS distance FROM docs d",
        ] {
            let plan = semantic_read_plan(sql).expect("query still has a semantic plan");
            assert!(
                plan.values.iter().any(|name| {
                    name.parts.len() == 1 && name.parts[0].text.eq_ignore_ascii_case("COSINE")
                }),
                "only the real unquoted VECTOR_DISTANCE makes its metric grammar; \
                 everywhere else COSINE is an ordinary identifier that still needs \
                 catalog proof: {sql}"
            );
        }
    }

    #[test]
    fn semantic_read_plan_refuses_unrepresented_query_scopes() {
        for sql in [
            "WITH q AS (SELECT id FROM t) SELECT id FROM q",
            "SELECT x.id FROM (SELECT id FROM t) x",
            "SELECT id FROM a UNION ALL SELECT id FROM b",
        ] {
            assert!(
                semantic_read_plan(sql).is_none(),
                "scope-bearing query must fail closed until represented: {sql}"
            );
        }
    }

    #[test]
    fn k8_reason_category_names_the_refusal_cause() {
        // A benign write that only needs a higher level.
        let write = classify("UPDATE t SET a = 1 WHERE id = 2");
        assert_eq!(
            write.reason_category,
            Some(ReasonCategory::RequiresHigherLevel)
        );
        // Dynamic SQL inside a PL/SQL block.
        let dynamic = classify("BEGIN EXECUTE IMMEDIATE 'DROP TABLE t'; END;");
        assert_eq!(dynamic.reason_category, Some(ReasonCategory::DynamicSql));
        assert!(dynamic.offending_construct.is_some());
        // A block-list hit names the matched pattern.
        let blocked = Classifier::new(ClassifierConfig::new().with_block_pattern("(?i)shutdown"))
            .classify("SHUTDOWN ABORT");
        assert_eq!(blocked.reason_category, Some(ReasonCategory::BlockListed));
        // Trailing SQL after a balanced block is a stacking refusal.
        let stacked = classify("BEGIN NULL; END; DROP TABLE t");
        assert_eq!(
            stacked.reason_category,
            Some(ReasonCategory::MultiStatementBatch)
        );
    }

    #[test]
    fn select_calling_udf_is_guarded_not_safe() {
        // The headline fail-open the old predicate had: a function call in a
        // SELECT may DML. With the default Unknown oracle it must be Guarded.
        let d = classify("SELECT billing.purge_old_rows() FROM dual");
        assert_eq!(d.danger, DangerLevel::Guarded);
        assert_eq!(d.required_level, Some(OperatingLevel::ReadWrite));
    }

    #[test]
    fn select_with_builtin_only_is_safe() {
        let d = classify("SELECT COUNT(*), MAX(salary) FROM employees");
        assert_eq!(d.danger, DangerLevel::Safe);
    }

    #[test]
    fn vector_distance_builtin_is_safe() {
        // Oracle 23ai VECTOR_DISTANCE is deterministic math over its arguments.
        // It must not be routed through the unknown-UDF purity consult, otherwise
        // normal semantic-search reads would be refused as Guarded/ReadWrite.
        let d = classify(
            "SELECT VECTOR_DISTANCE(doc_embedding, query_embedding) AS distance FROM docs",
        );
        assert_eq!(d.danger, DangerLevel::Safe);
        assert_eq!(d.required_level, Some(OperatingLevel::ReadOnly));
    }

    #[test]
    fn vector_embedding_is_safe_only_as_the_unqualified_sql_builtin() {
        let sql = "SELECT VECTOR_DISTANCE(d.embedding, VECTOR_EMBEDDING(LOCAL_ONNX_MODEL USING :1), COSINE) FROM docs d";
        let d = classify(sql);
        assert_eq!(d.danger, DangerLevel::Guarded, "{d:?}");
        let d = Classifier::default().classify_verified_local_vector_embedding(sql);
        assert_eq!(d.danger, DangerLevel::Safe, "{d:?}");
        let plan = semantic_read_plan(sql)
            .expect("the generated text-embedding query has an exact semantic plan");
        assert!(
            plan.values.iter().any(|name| {
                name.parts.len() == 2
                    && name.parts[0].text.eq_ignore_ascii_case("d")
                    && name.parts[1].text.eq_ignore_ascii_case("embedding")
            }),
            "the vector column remains a catalog-proven dependency"
        );
        assert!(
            !plan.values.iter().any(|name| {
                name.parts.len() == 1 && name.parts[0].text.eq_ignore_ascii_case("LOCAL_ONNX_MODEL")
            }),
            "the dictionary-proven model is SQL grammar, not a row/column dependency"
        );
        assert_eq!(
            Classifier::default()
                .classify_verified_local_vector_embedding(
                    "SELECT app.VECTOR_EMBEDDING(x) FROM dual"
                )
                .danger,
            DangerLevel::Guarded,
            "a qualified lookalike remains a user-defined routine candidate"
        );

        // The model-position exemption is keyed to the FUNCTION, and a *qualified*
        // lookalike is not the only lookalike. Dropping an identifier from the
        // catalog-proof set is a fail-open — it is how a reference the classifier
        // cannot resolve stops being asked about — so the exemption must belong to
        // the real, unquoted, unqualified builtin and to nothing else.
        for sql in [
            // A user-defined function whose first argument merely looks like a model.
            "SELECT FOO(LOCAL_ONNX_MODEL) FROM dual",
            // A QUOTED "VECTOR_EMBEDDING" is a user object that happens to share the
            // builtin's spelling, not the builtin.
            "SELECT \"VECTOR_EMBEDDING\"(LOCAL_ONNX_MODEL) FROM dual",
        ] {
            let plan = semantic_read_plan(sql).expect("the query still has a semantic plan");
            assert!(
                plan.values.iter().any(|name| {
                    name.parts.len() == 1
                        && name.parts[0].text.eq_ignore_ascii_case("LOCAL_ONNX_MODEL")
                }),
                "only the real unquoted VECTOR_EMBEDDING makes its model argument \
                 grammar; everywhere else it is an ordinary identifier that still \
                 needs catalog proof: {sql}"
            );
        }
    }

    #[test]
    fn sequence_nextval_is_not_read_only() {
        for sql in [
            "SELECT app_seq.NEXTVAL FROM dual",
            "SELECT app.app_seq.nextval FROM dual",
            "SELECT \"App Seq\".NeXtVaL FROM dual",
            "SELECT \"App\".\"App Seq\".NEXTVAL FROM dual",
            "SELECT (app_seq . NEXTVAL) AS generated_id FROM dual",
            "SELECT app_seq /* split */ . /* split */ NEXTVAL FROM dual",
            "SELECT app.app_seq.NEXTVAL@prod.example FROM dual",
        ] {
            assert!(
                !sequence_nextval_refs(sql).is_empty(),
                "token detector missed {sql:?}: {:?}",
                Tokenizer::new(&OracleDialect {}, sql).tokenize()
            );
            let d = classify(sql);
            assert_eq!(d.danger, DangerLevel::Guarded, "{sql:?}");
            assert_eq!(d.required_level, Some(OperatingLevel::ReadWrite), "{sql:?}");
            assert!(
                d.reason.contains("independently of transaction rollback"),
                "the governed execution preview must warn about permanence: {sql:?}"
            );
            assert_eq!(d.offending_construct.as_deref(), Some("sequence.NEXTVAL"));
            assert!(d.non_transactional_effect, "{sql:?}");
            assert!(d.query_effect_requires_fetch, "{sql:?}");
        }
    }

    #[test]
    fn sequence_nextval_helpers_preserve_owner_and_fetch_semantics() {
        let refs = sequence_nextval_refs("SELECT x, app.seq.NEXTVAL FROM dual");
        assert!(
            refs.iter().any(|reference| {
                reference.schema.as_deref() == Some("app")
                    && reference.name.eq_ignore_ascii_case("seq")
            }),
            "schema-qualified NEXTVAL should preserve the sequence owner: {refs:?}"
        );

        let unqualified_later = sequence_nextval_refs("SELECT x, seq.NEXTVAL FROM dual");
        assert!(
            unqualified_later.iter().any(|reference| {
                reference.schema.is_none() && reference.name.eq_ignore_ascii_case("seq")
            }),
            "later unqualified NEXTVAL must not borrow a preceding SELECT-list word as schema: {unqualified_later:?}"
        );

        assert!(
            sequence_nextval_query_requires_fetch(
                "SELECT app.seq.NEXTVAL@prod.example.com FROM dual"
            ),
            "a SELECT containing NEXTVAL behind Oracle dblink syntax still needs fetch"
        );
        let malformed_select = "SELECT seq.NEXTVAL FROM dual WHERE";
        assert!(
            Parser::parse_sql(&OracleDialect {}, malformed_select).is_err(),
            "test precondition: malformed SELECT should force the fail-closed lexical path"
        );
        assert!(
            sequence_nextval_query_requires_fetch(malformed_select),
            "a tokenizable SELECT containing NEXTVAL still needs fetch even when sqlparser cannot parse it"
        );
        assert!(
            !sequence_nextval_query_requires_fetch("UPDATE t SET id = app.seq.NEXTVAL"),
            "non-query NEXTVAL effects are not result-fetch driven"
        );
    }

    #[test]
    fn sequence_currval_and_quoted_nextval_column_remain_read_only() {
        for sql in [
            "SELECT app_seq.CURRVAL FROM dual",
            "SELECT t.\"NEXTVAL\" FROM app.t t",
            "SELECT 'app_seq.NEXTVAL' FROM dual",
            "SELECT q'[app_seq.NEXTVAL]' FROM dual",
            "SELECT 1 FROM dual /* app_seq.NEXTVAL */",
        ] {
            let d = classify(sql);
            assert_eq!(d.danger, DangerLevel::Safe, "{sql:?}");
            assert_eq!(d.required_level, Some(OperatingLevel::ReadOnly), "{sql:?}");
            assert!(!d.non_transactional_effect, "{sql:?}");
            assert!(!d.query_effect_requires_fetch, "{sql:?}");
        }
    }

    #[test]
    fn sequence_nextval_reason_preserves_the_aggregate_danger_and_level() {
        let d = classify("SELECT app_seq.NEXTVAL FROM dual; DROP TABLE audit_log");
        assert_eq!(d.danger, DangerLevel::Destructive);
        assert_eq!(d.required_level, Some(OperatingLevel::Ddl));
        assert!(
            d.reason.contains("Destructive/DDL"),
            "reason must describe the aggregate class, not only the NEXTVAL sub-statement: {d:?}"
        );
        assert!(
            !d.reason.contains("Guarded/READ_WRITE"),
            "a DDL batch must not claim its aggregate classification is Guarded/READ_WRITE: {d:?}"
        );
        assert!(d.query_effect_requires_fetch);
    }

    #[test]
    fn sequence_nextval_marks_direct_dml_as_non_transactional() {
        for sql in [
            "INSERT INTO orders (id) VALUES (app_seq.NEXTVAL)",
            "UPDATE orders SET id = app_seq.NEXTVAL WHERE id = 1",
        ] {
            let d = classify(sql);
            assert!(
                d.required_level
                    .is_some_and(|level| level >= OperatingLevel::ReadWrite),
                "{sql:?} -> {d:?}"
            );
            assert!(d.non_transactional_effect, "{sql:?} -> {d:?}");
            assert!(!d.query_effect_requires_fetch, "{sql:?} -> {d:?}");
            assert!(
                d.reason.contains("independently of transaction rollback"),
                "{sql:?} -> {d:?}"
            );
        }

        let wrapped = classify("BEGIN x := app_seq.NEXTVAL; END;");
        assert_eq!(wrapped.danger, DangerLevel::Forbidden);
        assert_eq!(
            wrapped.reason_category,
            Some(ReasonCategory::UnprovenSideEffect)
        );
    }

    #[test]
    fn select_calling_keyword_named_udf_is_guarded_not_safe() {
        // oracle-ajm2.1: a UDF whose name collides with a non-reserved Oracle /
        // sqlparser keyword (PURGE/MERGE/DELETE/COMMENT/ANALYZE/REFRESH/...) must
        // still be routed through the purity consult and classified Guarded under
        // the default UnknownOracle — NOT silently dropped (fail-open) to Safe.
        for sql in [
            "SELECT billing.purge() FROM dual",
            "SELECT app.merge(x) FROM dual",
            "SELECT app.delete(x) FROM dual",
            "SELECT app.comment() FROM dual",
            "SELECT app.analyze() FROM dual",
            "SELECT app.refresh() FROM dual",
            // bare (un-qualified) keyword-named UDF too.
            "SELECT purge() FROM dual",
        ] {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Guarded,
                "keyword-named UDF must be Guarded, not Safe: {sql:?}"
            );
            assert_eq!(d.required_level, Some(OperatingLevel::ReadWrite), "{sql:?}");
        }
    }

    #[test]
    fn select_calling_builtin_named_qualified_udf_is_guarded_not_safe() {
        // oracle-b6yl.2: a SCHEMA-QUALIFIED routine whose BARE name collides with
        // a SQL builtin (replace/round/trunc/mod/user/length/extract/...) must
        // still be routed through the purity consult — `billing.replace(x)` is a
        // package-member call, not the builtin REPLACE. Dropping it (because the
        // bare name is in BUILTINS) fail-opened the whole SELECT to Safe/ReadOnly,
        // running the routine's side effects unguarded. A genuine SQL builtin is
        // never written schema-qualified, so the qualified form is unambiguous.
        for sql in [
            "SELECT billing.replace(x) FROM dual",
            "SELECT app.trunc(x) FROM dual",
            "SELECT app.round(x) FROM dual",
            "SELECT app.user() FROM dual",
            "SELECT app.mod(x) FROM dual",
            "SELECT billing.length(x) FROM dual",
            "SELECT app.extract(x) FROM dual",
        ] {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Guarded,
                "builtin-named QUALIFIED UDF must be Guarded, not Safe: {sql:?}"
            );
            assert_eq!(d.required_level, Some(OperatingLevel::ReadWrite), "{sql:?}");
        }
        // Control: a BARE builtin is a genuine read and stays Safe.
        assert_eq!(
            classify("SELECT replace(x, 'a', 'b') FROM dual").danger,
            DangerLevel::Safe,
            "bare builtin REPLACE must stay Safe"
        );
    }

    #[test]
    fn no_semicolon_batch_with_buried_dangerous_verb_fails_closed() {
        // oracle-b6yl.1: a no-`;` pure-SQL batch that buries a dangerous verb
        // after a benign SELECT prefix must fail closed to Forbidden, symmetric
        // with the `;`-delimited form — the pure-SQL analog of the buried-`;`
        // (saw_buried_semicolon) and trailing-SQL-after-END desyncs.
        for sql in [
            "SELECT 1 FROM dual GRANT DBA TO scott",
            "SELECT 1 FROM dual\n/\nGRANT DBA TO scott",
            "SELECT 1 FROM dual\nDROP TABLE orders",
            "SELECT 1 FROM dual\nTRUNCATE TABLE orders",
            "SELECT 1 FROM dual\nUPDATE orders SET x = 1",
            // oracle-qo1v.1: verbs that fail closed when LEADING must also fail
            // closed when buried — the set was previously asymmetric.
            "SELECT 1 FROM dual\nSET ROLE dba",
            "SELECT 1 FROM dual\nPURGE TABLE orders",
            "SELECT 1 FROM dual\nDISASSOCIATE STATISTICS FROM COLUMNS orders.id",
            "SELECT 1 FROM dual\nFLASHBACK TABLE orders TO BEFORE DROP",
        ] {
            assert_eq!(
                classify(sql).danger,
                DangerLevel::Forbidden,
                "no-`;` batch with a buried dangerous verb must fail closed: {sql:?}"
            );
        }
        // A benign buried `UPDATE … SET` must NOT trip on the `SET ROLE` pattern
        // (the `SET` alone is not dangerous) — but `UPDATE` itself is in the set,
        // so this whole batch is still (correctly) Forbidden via the UPDATE verb.
        // The point is `SET ROLE` is a distinct two-word marker, not bare `SET`.
        assert!(!BURIED_DANGEROUS_VERBS.contains(&" SET "));
        // Control 1: the `;`-delimited equivalent already fails closed (multi-stmt).
        assert_eq!(
            classify("SELECT 1 FROM dual; GRANT DBA TO scott").danger,
            DangerLevel::Forbidden
        );
        // Control 2: a benign single SELECT (no buried verb) stays a read, even
        // when it merely mentions a dangerous keyword inside an identifier.
        assert_eq!(
            classify("SELECT update_ts FROM orders WHERE id = 1").danger,
            DangerLevel::Safe,
            "a column named update_ts must not trip the buried-verb scan"
        );
    }

    #[test]
    fn genuine_sql_constructs_are_not_treated_as_udf_calls() {
        // The contrapositive of the keyword-named-UDF fix: real SQL constructs
        // (VALUES/IN/CAST/CASE/EXISTS) that legally precede `(` must NOT be
        // mistaken for user-defined function calls — a plain read stays Safe.
        for sql in [
            "SELECT id FROM t WHERE dept IN (1, 2, 3)",
            "SELECT CAST(x AS NUMBER) FROM t",
            "SELECT id FROM t WHERE EXISTS (SELECT 1 FROM dual)",
        ] {
            assert_eq!(
                classify(sql).danger,
                DangerLevel::Safe,
                "SQL construct must stay Safe: {sql:?}"
            );
        }
    }

    #[test]
    fn select_for_update_is_guarded_not_safe() {
        // oracle-ajm2.6: SELECT ... FOR UPDATE (incl. OF/NOWAIT/SKIP LOCKED)
        // takes row locks + holds a transaction open — levels.rs:93 documents it
        // as Guarded, never Safe. A plain SELECT (no lock) must stay Safe.
        assert_eq!(classify("SELECT * FROM t").danger, DangerLevel::Safe);
        for sql in [
            "SELECT * FROM t FOR UPDATE",
            "SELECT * FROM t WHERE id = 1 FOR UPDATE",
            "SELECT * FROM t FOR UPDATE OF status",
            "SELECT * FROM t FOR UPDATE NOWAIT",
            "SELECT * FROM t FOR UPDATE SKIP LOCKED",
        ] {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Guarded,
                "SELECT ... FOR UPDATE must be Guarded: {sql:?}"
            );
            assert_eq!(d.required_level, Some(OperatingLevel::ReadWrite), "{sql:?}");
        }
    }

    #[test]
    fn proven_readonly_udf_clears_to_safe() {
        struct ProvenOracle;
        impl SideEffectOracle for ProvenOracle {
            fn routine_purity(&self, _r: &ObjectRef) -> Purity {
                Purity::ProvenReadOnly
            }
        }
        let c = Classifier::default().with_oracle(Arc::new(ProvenOracle));
        let d = c.classify("SELECT billing.lookup(x) FROM dual");
        assert_eq!(d.danger, DangerLevel::Safe);
    }

    #[test]
    fn select_over_side_effecting_table_is_guarded_not_safe() {
        // Regression for oracle-qm3q.8 (purity.rs:88 / classifier.rs:438): a
        // UDF-free SELECT over a table whose AFTER-SELECT trigger / VPD policy
        // function the engine proves side-effecting must NOT clear to Safe.
        // Before the statement_purity wiring this returned Safe because the
        // trigger/VPD verdict was never consulted (the comment was a lie).
        struct TriggerOnReadOracle;
        impl SideEffectOracle for TriggerOnReadOracle {
            fn statement_purity(&self, base_objects: &[ObjectRef]) -> Purity {
                // `orders` carries a side-effecting AFTER-SELECT trigger.
                if base_objects
                    .iter()
                    .any(|o| o.name.eq_ignore_ascii_case("orders"))
                {
                    Purity::ProvenSideEffecting
                } else {
                    Purity::ProvenReadOnly
                }
            }
        }
        let c = Classifier::default().with_oracle(Arc::new(TriggerOnReadOracle));
        let d = c.classify("SELECT * FROM orders");
        assert_eq!(
            d.danger,
            DangerLevel::Guarded,
            "a SELECT whose base object is ProvenSideEffecting must be Guarded"
        );
        assert_eq!(d.required_level, Some(OperatingLevel::ReadWrite));
        assert!(
            d.objects_affected.iter().any(|o| o == "orders"),
            "the side-effecting base object should be surfaced for audit"
        );
        // The verdict reaches the decision through a JOIN factor too.
        let joined = c.classify("SELECT e.id FROM employees e JOIN orders o ON e.id = o.id");
        assert_eq!(joined.danger, DangerLevel::Guarded);
        // ...and through a CTE body, even though the outer FROM names the alias.
        let cte = c.classify("WITH x AS (SELECT id FROM orders) SELECT * FROM x");
        assert_eq!(cte.danger, DangerLevel::Guarded);
    }

    #[test]
    fn cte_smuggled_dml_body_is_never_read_only() {
        // oracle-cte-dml-body: sqlparser 0.62 maps `WITH cte {UPDATE|DELETE|
        // MERGE|INSERT} …` to a Statement::Query whose *body* is a DML SetExpr
        // (the trailing DML is absorbed as the "query body"). A READ_ONLY
        // profile must never see this text tiered Safe/ReadOnly — even though
        // Oracle itself rejects the syntax (ORA-00928), the classifier verdict
        // must fail closed. The dangerous variants (WITH FUNCTION autonomous
        // DML, WITH … DROP/TRUNCATE/GRANT) already fail parse and are caught by
        // the buried-verb / leading-verb scans; this closes the one parse-OK
        // form that slipped through to the Query arm.
        for sql in [
            "WITH a AS (SELECT 1 x FROM dual) UPDATE t SET x = 1",
            "WITH a AS (SELECT 1 x FROM dual) DELETE FROM t",
            "WITH a AS (SELECT 1 x FROM dual) INSERT INTO t SELECT * FROM a",
            "WITH a AS (SELECT 1 x FROM dual) MERGE INTO t USING a ON (1=1) \
             WHEN MATCHED THEN UPDATE SET x = 1",
        ] {
            let d = classify(sql);
            assert_ne!(
                d.danger,
                DangerLevel::Safe,
                "CTE-smuggled DML must not be Safe: {sql}"
            );
            assert_ne!(
                d.required_level,
                Some(OperatingLevel::ReadOnly),
                "CTE-smuggled DML must not be admitted at READ_ONLY: {sql}"
            );
        }
    }

    #[test]
    fn legitimate_cte_reads_stay_safe_after_dml_body_tightening() {
        // Regression guard for the fix above: the tightening is purely
        // structural (it inspects the query body AST, never scans text), so a
        // genuine CTE read — including one whose columns/tables are spelled with
        // non-reserved words that a text scan would false-positive on
        // (PURGE/AUDIT/FLASHBACK are legal Oracle identifiers) — must stay Safe.
        for sql in [
            "WITH x AS (SELECT id FROM orders) SELECT * FROM x",
            "SELECT purge, audit, flashback FROM app_log",
            "WITH a AS (SELECT 1 x FROM dual) SELECT * FROM a UNION ALL SELECT 2 FROM dual",
        ] {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Safe,
                "legit read must stay Safe: {sql}"
            );
            assert_eq!(
                d.required_level,
                Some(OperatingLevel::ReadOnly),
                "legit read must stay READ_ONLY: {sql}"
            );
        }
        // `SELECT … FOR UPDATE` takes row locks: it must remain Guarded/ReadWrite
        // (a legitimate step-up-able lockable read), NOT be over-tightened to
        // Forbidden by the DML-body check — the ` UPDATE ` there is a lock
        // clause, not a smuggled DML SetExpr.
        let locked = classify("SELECT * FROM orders FOR UPDATE");
        assert_eq!(locked.danger, DangerLevel::Guarded);
        assert_eq!(locked.required_level, Some(OperatingLevel::ReadWrite));
    }

    #[test]
    fn select_over_clean_table_with_proven_readonly_stmt_purity_is_safe() {
        // The contrapositive: a real oracle whose statement_purity proves the
        // base objects ProvenReadOnly must still clear a UDF-free SELECT to Safe
        // (no false positive that would block legitimate reads).
        struct CleanOracle;
        impl SideEffectOracle for CleanOracle {
            fn statement_purity(&self, _base_objects: &[ObjectRef]) -> Purity {
                Purity::ProvenReadOnly
            }
        }
        let c = Classifier::default().with_oracle(Arc::new(CleanOracle));
        assert_eq!(
            c.classify("SELECT id, name FROM employees WHERE id = 42")
                .danger,
            DangerLevel::Safe
        );
    }

    #[test]
    fn default_oracle_keeps_plain_select_safe_despite_statement_purity_wiring() {
        // Baseline preservation: under the default UnknownOracle, statement_purity
        // returns Unknown (NOT ProvenSideEffecting), so the new consult must not
        // regress any plain SELECT to Guarded — the corpus depends on this.
        for sql in [
            "SELECT id, name FROM employees WHERE id = 42",
            "WITH d AS (SELECT * FROM dept) SELECT * FROM d",
            "SELECT * FROM orders",
            "SELECT e.id FROM employees e JOIN dept d ON e.dept = d.id",
        ] {
            assert_eq!(
                classify(sql).danger,
                DangerLevel::Safe,
                "default oracle must keep {sql:?} Safe"
            );
        }
    }

    #[test]
    fn statement_unknown_guarded_mode_tightens_udf_free_selects() {
        struct UnknownStatementOracle;
        impl SideEffectOracle for UnknownStatementOracle {
            fn statement_purity(&self, _base_objects: &[ObjectRef]) -> Purity {
                Purity::Unknown
            }
        }

        let default_binding = Classifier::default().with_oracle(Arc::new(UnknownStatementOracle));
        assert_eq!(
            default_binding.classify("SELECT * FROM orders").danger,
            DangerLevel::Safe,
            "`with_oracle` alone must preserve the no-engine SELECT baseline"
        );

        let tightened = Classifier::default()
            .with_oracle(Arc::new(UnknownStatementOracle))
            .with_statement_unknown_guarded();
        let d = tightened.classify("SELECT * FROM orders");
        assert_eq!(
            d.danger,
            DangerLevel::Guarded,
            "engine-bound statement Unknown must fail closed to Guarded"
        );
        assert_eq!(d.required_level, Some(OperatingLevel::ReadWrite));
        assert!(
            d.objects_affected.iter().any(|o| o == "orders"),
            "the unresolved base object should be surfaced for audit"
        );
    }

    #[test]
    fn parenless_qualified_callable_fails_open_by_default_but_guards_under_flag() {
        // Bead .102 — the live fail-open: Oracle invokes a zero-arg function with
        // NO parentheses, so `SELECT app_admin.run_ddl FROM dual` *runs* the
        // function `run_ddl`, but `user_defined_calls` only sees `ident(`, so the
        // paren-less (esp. schema-qualified) call reads as a column reference and
        // clears to Safe.
        let payloads = [
            "SELECT app_admin.run_ddl FROM dual",
            "SELECT app_admin.run_ddl, ROUND(x) FROM dual",
            "SELECT id FROM orders WHERE app.flag = 1", // qualifier in WHERE
            // A schema name used in FROM is not itself a column qualifier. The
            // first containment globally collected every name part and therefore
            // let this real schema-qualified zero-arg call through as Safe.
            "SELECT hr.dangerous_fn FROM hr.employees",
            // An alias from a nested scope is not visible in the outer SELECT.
            "SELECT app_admin.run_ddl FROM dual WHERE EXISTS (SELECT 1 FROM audit_log app_admin)",
            // Once a table is aliased, its underlying name is hidden as a column
            // qualifier; it cannot bless a same-named package/function call.
            "SELECT employees.dangerous_fn FROM hr.employees e",
            // Main-query aliases are not visible while a preceding WITH body is
            // evaluated. Oracle executes DBMS_RANDOM.VALUE in this CTE.
            "WITH c AS (SELECT dbms_random.value v FROM dual) SELECT c.v FROM dual dbms_random, c",
            // A derived-table alias is visible only outside its subquery; it
            // cannot bless the same package name inside the derived query.
            "SELECT dbms_random.v FROM (SELECT dbms_random.value v FROM dual) dbms_random",
            // JOIN aliases become visible left-to-right. A later alias cannot
            // launder a package call in an earlier ON condition.
            "SELECT 1 FROM dual d JOIN dual x ON dbms_random.value > 0 JOIN dual dbms_random ON 1=1",
            // Quoted lowercase and unquoted-uppercase identifiers are distinct.
            "SELECT emp.dummy FROM dual \"emp\"",
            // An expression-level database link forces remote callable
            // resolution even when the root also names a local relation.
            "SELECT run_ddl@oraclemcp_missing_link FROM dual",
            "SELECT dbms_random.value@oraclemcp_missing_link FROM dual dbms_random",
            "SELECT sys.dbms_random.value@oraclemcp_missing_link FROM dual sys",
            "SELECT dbms_random.value@prod.example.com FROM dual dbms_random",
        ];
        // NOTE: `SELECT s.nextval FROM dual` is deliberately NOT in this list — the
        // sequence pseudo-column is already classified Guarded by the dedicated
        // bead-.79 NEXTVAL detector at the default level, so it cannot demonstrate
        // the .102 flag's default-fail-open baseline. The .102 mechanism is proven
        // here on genuinely paren-less schema/package callables instead.

        // Baseline: the default classifier documents the (contained-elsewhere)
        // fail-open — plain `Classifier::new` stays permissive for backward
        // compatibility. This half is what makes the strict half mutation-killing:
        // if the guard logic is deleted the strict assertion below flips to Safe.
        let permissive = Classifier::default();
        for sql in payloads {
            assert_eq!(
                permissive.classify(sql).danger,
                DangerLevel::Safe,
                "default (flag off) keeps the baseline: {sql:?}"
            );
        }

        // Opt-in `.102` guard alone (no statement-Unknown tightening, so plain
        // reads stay usable) forces every paren-less qualified callable to Guarded.
        let strict =
            Classifier::new(ClassifierConfig::new().with_unresolved_qualified_calls_guarded());
        for sql in payloads {
            let d = strict.classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Guarded,
                "the .102 guard must fail closed on a paren-less qualified callable: {sql:?}"
            );
            assert_eq!(d.required_level, Some(OperatingLevel::ReadWrite), "{sql:?}");
        }
        // The offending dotted name is surfaced for audit.
        assert!(
            strict
                .classify("SELECT app_admin.run_ddl FROM dual")
                .objects_affected
                .iter()
                .any(|o| o.eq_ignore_ascii_case("app_admin.run_ddl")),
            "the paren-less callable should be surfaced"
        );
    }

    #[test]
    fn config_served_strict_enables_qualified_callable_guard_only() {
        let strict_config = Classifier::new(ClassifierConfig::served_strict());

        let callable = strict_config.classify("SELECT app_admin.run_ddl FROM dual");
        assert_eq!(callable.danger, DangerLevel::Guarded);
        assert_eq!(callable.required_level, Some(OperatingLevel::ReadWrite));
        assert!(
            callable
                .objects_affected
                .iter()
                .any(|object| object.eq_ignore_ascii_case("app_admin.run_ddl")),
            "served-strict config must surface the paren-less callable"
        );

        let ordinary_read = strict_config.classify("SELECT * FROM orders");
        assert_eq!(
            ordinary_read.danger,
            DangerLevel::Safe,
            "ClassifierConfig::served_strict only enables the .102 callable guard; \
             Classifier::served_strict owns statement-Unknown tightening"
        );
        assert_eq!(ordinary_read.required_level, Some(OperatingLevel::ReadOnly));
    }

    #[test]
    fn parenless_qualified_guard_is_surgical_and_spares_real_column_refs() {
        // Regression guard for the .102 tightening: an in-scope `alias.column` /
        // `schema.table.column` / CTE-qualified / correlated column reference is
        // an ordinary read and must stay Safe (no destruction of normal reads).
        let strict =
            Classifier::new(ClassifierConfig::new().with_unresolved_qualified_calls_guarded());
        for sql in [
            "SELECT e.name, e.id FROM employees e",
            "SELECT e.name FROM employees e JOIN dept d ON e.dept = d.id",
            "SELECT hr.employees.salary FROM hr.employees",
            "WITH x AS (SELECT id FROM orders) SELECT x.id FROM x",
            "SELECT (SELECT o.amt FROM orders o WHERE o.id = c.id) FROM customers c",
            "SELECT t.* FROM t",
            "SELECT id, name FROM employees WHERE dept = 10",
            "SELECT ROUND(x), COUNT(*) FROM dual",
            "SELECT d.* FROM (SELECT 1 id FROM dual) d WHERE d.id = 1",
            // A correlated outer qualifier remains visible inside the nested
            // query, while a sibling/nested alias never leaks outward.
            "SELECT c.id FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.id)",
            // Quote identity is preserved for a genuinely quoted alias.
            "SELECT \"Emp\".\"Name\" FROM employees \"Emp\"",
            // Oracle folds an unquoted name to uppercase, so a quoted-uppercase
            // alias and its unquoted spelling are the same identifier.
            "SELECT EMP.dummy FROM dual \"EMP\"",
            "SELECT \"EMP\".dummy FROM dual EMP",
            "SELECT d.dummy, q.v FROM dual d, LATERAL (SELECT d.dummy v FROM dual) q",
            "SELECT d.dummy, q.v FROM dual d CROSS APPLY (SELECT d.dummy v FROM dual) q",
            // Once the relation prefix resolves, remaining dotted parts are
            // object/JSON attributes, not a package invocation.
            "SELECT j.doc.a FROM (SELECT json_col doc FROM json_docs) j",
            "SELECT e.address.city.name FROM employees e",
            "SELECT t.x FROM nested_docs d, TABLE(d.vals) t",
            "SELECT jt.a FROM json_docs d, JSON_TABLE(d.doc, '$' COLUMNS(a NUMBER PATH '$.a')) jt",
            "SELECT xt.a FROM xml_docs d, XMLTABLE('/r' PASSING d.doc COLUMNS a NUMBER PATH '.') xt",
            "SELECT employees.name FROM hr.employees@prod",
            "SELECT employees.name FROM employees@prod",
            "SELECT employees.name FROM hr.employees@prod.example.com",
            "SELECT employees.name FROM employees@prod.example.com",
            "SELECT \"run@ddl\" FROM (SELECT 1 \"run@ddl\" FROM dual)",
            "WITH c AS (SELECT 1 id FROM dual) SELECT c.id FROM c ORDER BY c.id",
        ] {
            assert_eq!(
                strict.classify(sql).danger,
                DangerLevel::Safe,
                "a genuine in-scope column reference must stay Safe under the .102 guard: {sql:?}"
            );
        }
    }

    #[test]
    fn served_strict_is_fully_fail_closed_over_unproven_reads() {
        // Bead .82 containment: `served_strict` additionally tightens
        // statement-level `Unknown` purity, so under the default `UnknownOracle`
        // (which proves nothing) every read of a real base object — including a
        // view whose hidden VPD/trigger dependency writes — fails closed to
        // Guarded. This is the aggressive, documented containment; it is opt-in
        // precisely because it refuses reads a bound engine oracle would clear.
        let strict = Classifier::default().served_strict();
        for sql in [
            "SELECT * FROM orders", // .82: unprovable view/table read
            "SELECT id FROM some_reporting_view",
            "SELECT app_admin.run_ddl FROM dual", // .102: still caught here too
        ] {
            let d = strict.classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Guarded,
                "served_strict must refuse an unproven read: {sql:?}"
            );
            assert_ne!(
                d.required_level,
                Some(OperatingLevel::ReadOnly),
                "served_strict must never admit an unproven read at READ_ONLY: {sql:?}"
            );
        }
        // A base-object-free scalar read has nothing to prove — it stays Safe.
        assert_eq!(
            strict.classify("SELECT 1").danger,
            DangerLevel::Safe,
            "a base-object-free read has no unproven object"
        );
    }

    #[test]
    fn query_base_objects_resolves_from_join_and_cte_bodies() {
        use sqlparser::ast::Statement;
        let parse = |sql: &str| -> Vec<ObjectRef> {
            let stmts = Parser::parse_sql(&OracleDialect {}, sql).expect("parse");
            match stmts.into_iter().next().expect("one stmt") {
                Statement::Query(q) => query_base_objects(&q),
                other => panic!("expected query, got {other:?}"),
            }
        };
        let names = |objs: &[ObjectRef]| -> Vec<String> {
            objs.iter().map(|o| o.name.to_ascii_lowercase()).collect()
        };

        // FROM + JOIN base tables both resolve.
        let a = parse("SELECT * FROM employees e JOIN orders o ON e.id = o.id");
        assert_eq!(names(&a), vec!["employees", "orders"]);

        // Schema-qualified name keeps the schema, drops it for the bare table.
        let b = parse("SELECT * FROM hr.employees");
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].schema.as_deref(), Some("hr"));
        assert_eq!(b[0].name.to_ascii_lowercase(), "employees");

        // CTE alias is NOT a base object; the CTE body's base table is.
        let c = parse("WITH x AS (SELECT id FROM orders) SELECT * FROM x");
        assert_eq!(names(&c), vec!["orders"]);

        // Derived subquery base table resolves through the parenthesized factor.
        let d = parse("SELECT * FROM (SELECT id FROM orders) t");
        assert_eq!(names(&d), vec!["orders"]);

        // Set operations on both arms.
        let e = parse("SELECT id FROM a UNION SELECT id FROM b");
        assert_eq!(names(&e), vec!["a", "b"]);

        // Every expression-position subquery contributes its base object. These
        // are deliberately tested through the collector rather than only the
        // classifier: an omission here would otherwise turn an engine oracle's
        // `ProvenSideEffecting` answer into an unasked, fail-open Safe verdict.
        for sql in [
            "SELECT 1 FROM dual WHERE EXISTS (SELECT 1 FROM sensitive_orders)",
            "SELECT 1 FROM dual WHERE 1 IN (SELECT id FROM sensitive_orders)",
            "SELECT (SELECT id FROM sensitive_orders WHERE ROWNUM = 1) FROM dual",
            "SELECT 1 FROM dual WHERE 1 = ANY (SELECT id FROM sensitive_orders)",
            "SELECT 1 FROM dual WHERE 1 = ALL (SELECT id FROM sensitive_orders)",
            "SELECT 1 FROM dual WHERE 1 = (SELECT id FROM sensitive_orders WHERE ROWNUM = 1)",
        ] {
            let mut found = names(&parse(sql));
            found.sort_unstable();
            assert_eq!(
                found,
                vec!["dual", "sensitive_orders"],
                "expression subquery base object must be collected: {sql}"
            );
        }

        // A CTE alias remains an alias even when the reference is inside a
        // predicate subquery, and repeated references remain de-duplicated.
        let mut cte_expression = names(&parse(
            "WITH sensitive AS (SELECT id FROM sensitive_orders) \
             SELECT 1 FROM dual WHERE EXISTS (SELECT 1 FROM sensitive) \
             AND 1 IN (SELECT id FROM sensitive)",
        ));
        cte_expression.sort_unstable();
        assert_eq!(cte_expression, vec!["dual", "sensitive_orders"]);
    }

    #[test]
    fn relation_scope_helpers_keep_distinct_ids_and_minimal_qualifiers() {
        use sqlparser::ast::{SetExpr, Statement, TableFactor};

        let stmts = Parser::parse_sql(&OracleDialect {}, "SELECT employees.name FROM employees")
            .expect("parse single-table query");
        let Statement::Query(query) = &stmts[0] else {
            panic!("expected query");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected select body");
        };
        let TableFactor::Table { name, .. } = &select.from[0].relation else {
            panic!("expected table factor");
        };
        let qualifiers = object_name_qualifiers(name);
        assert_eq!(
            qualifiers.len(),
            1,
            "a single-part table name should expose one qualifier, not a duplicate full path"
        );

        let stmts = Parser::parse_sql(&OracleDialect {}, "SELECT * FROM a JOIN b ON a.id = b.id")
            .expect("parse join query");
        let Statement::Query(query) = &stmts[0] else {
            panic!("expected query");
        };
        let SetExpr::Select(select) = query.body.as_ref() else {
            panic!("expected select body");
        };
        let left_id = table_factor_id(&select.from[0].relation);
        let right_id = table_factor_id(&select.from[0].joins[0].relation);
        assert_ne!(
            left_id, right_id,
            "different table factors must retain distinct identities"
        );

        let stmts = Parser::parse_sql(
            &OracleDialect {},
            "SELECT id FROM a UNION ALL SELECT id FROM b",
        )
        .expect("parse set operation");
        let Statement::Query(query) = &stmts[0] else {
            panic!("expected query");
        };
        let SetExpr::SetOperation { left, right, .. } = query.body.as_ref() else {
            panic!("expected set operation");
        };
        let SetExpr::Select(left_select) = left.as_ref() else {
            panic!("expected left select");
        };
        let SetExpr::Select(right_select) = right.as_ref() else {
            panic!("expected right select");
        };
        assert_ne!(
            select_id(left_select),
            select_id(right_select),
            "different SELECT nodes must retain distinct identities"
        );
        let mut ids = HashSet::new();
        collect_body_select_ids(query.body.as_ref(), &mut ids);
        assert_eq!(
            ids.len(),
            2,
            "set-operation query bodies must register both arm SELECT ids"
        );
        assert!(ids.contains(&select_id(left_select)), "{ids:?}");
        assert!(ids.contains(&select_id(right_select)), "{ids:?}");
    }

    #[test]
    fn query_dml_walkers_detect_nested_write_bodies_directly() {
        use sqlparser::ast::Statement;
        let carries_dml = |sql: &str| -> bool {
            let stmts = Parser::parse_sql(&OracleDialect {}, sql).expect(sql);
            match stmts.into_iter().next().expect("one stmt") {
                Statement::Query(q) => query_carries_dml(&q),
                other => panic!("expected query, got {other:?}"),
            }
        };

        for sql in [
            "WITH a AS (SELECT 1 x FROM dual) UPDATE t SET x = 1",
            "WITH a AS (SELECT 1 x FROM dual) DELETE FROM t",
            "WITH a AS (SELECT 1 x FROM dual) INSERT INTO t SELECT * FROM a",
            "WITH a AS (SELECT 1 x FROM dual) MERGE INTO t USING a ON (1=1) \
             WHEN MATCHED THEN UPDATE SET x = 1",
            "SELECT * FROM (UPDATE t SET x=1)",
            "SELECT * FROM (SELECT * FROM (DELETE FROM t))",
            "SELECT 1 FROM dual UNION SELECT * FROM (DELETE FROM t)",
            "SELECT * FROM a JOIN (UPDATE t SET x=1) b ON a.id=b.id",
        ] {
            assert!(
                carries_dml(sql),
                "query_carries_dml must detect nested DML body: {sql:?}"
            );
        }

        assert!(
            !carries_dml(
                "WITH a AS (SELECT 1 x FROM dual) SELECT * FROM a UNION ALL SELECT 2 FROM dual"
            ),
            "genuine read-only CTE/set-op queries must not be marked as DML"
        );
    }

    #[test]
    fn delete_without_where_is_destructive() {
        let d = classify("DELETE FROM orders");
        assert_eq!(d.danger, DangerLevel::Destructive);
        let d2 = classify("DELETE FROM orders WHERE id = 1");
        assert_eq!(d2.danger, DangerLevel::Guarded);
    }

    #[test]
    fn update_without_where_is_destructive() {
        assert_eq!(
            classify("UPDATE orders SET status = 'X'").danger,
            DangerLevel::Destructive
        );
        assert_eq!(
            classify("UPDATE orders SET status = 'X' WHERE id = 1").danger,
            DangerLevel::Guarded
        );
    }

    #[test]
    fn insert_is_guarded() {
        assert_eq!(
            classify("INSERT INTO t (a) VALUES (1)").danger,
            DangerLevel::Guarded
        );
    }

    #[test]
    fn merge_explain_have_floors_and_transaction_control_is_forbidden() {
        let merge = classify(
            "MERGE INTO t USING s ON (t.id = s.id) WHEN MATCHED THEN UPDATE SET t.v = s.v",
        );
        assert_eq!(merge.danger, DangerLevel::Guarded);
        assert_eq!(merge.required_level, Some(OperatingLevel::ReadWrite));

        let explain = classify("EXPLAIN PLAN FOR SELECT * FROM employees");
        assert_eq!(explain.danger, DangerLevel::Guarded);
        assert_eq!(explain.required_level, Some(OperatingLevel::ReadWrite));

        for sql in ["COMMIT", "ROLLBACK", "SAVEPOINT before_patch"] {
            let d = classify(sql);
            assert_eq!(d.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(d.required_level, None, "{sql:?}");
            assert_eq!(
                d.reason_category,
                Some(ReasonCategory::TransactionControl),
                "{sql:?}"
            );
        }
    }

    #[test]
    fn block_wrap_is_monotone_for_where_less_dml() {
        // iec3.2.30 — wrapping a statement in `BEGIN … END` must never LOWER its
        // classification below the same statement bare. A WHERE-less DELETE/UPDATE
        // is Destructive/ReadWrite bare; wrapped it used to collapse to the flat
        // benign-block floor Guarded/ReadWrite (a fail-open under wrapping). The
        // interior-tier fold now re-applies the bare classifier so the block earns
        // AT LEAST the interior's tier.
        for (bare, wrapped) in [
            ("DELETE FROM orders", "BEGIN DELETE FROM orders; END;"),
            (
                "UPDATE orders SET status = 'X'",
                "BEGIN UPDATE orders SET status = 'X'; END;",
            ),
        ] {
            let b = classify(bare);
            let w = classify(wrapped);
            assert_eq!(
                b.danger,
                DangerLevel::Destructive,
                "precondition: bare WHERE-less DML is Destructive: {bare:?}"
            );
            assert!(
                w.danger >= b.danger,
                "block-wrapped DML must never drop below bare: {wrapped:?}: {w:?}"
            );
            assert_eq!(w.danger, DangerLevel::Forbidden, "{wrapped:?}");
        }
        // Engine-free caller PL/SQL now refuses even WHERE-qualified DML: the
        // same expression grammar can contain zero-argument functions without
        // parentheses. Submit the static DML directly instead.
        let qualified = classify("BEGIN UPDATE orders SET status = 'X' WHERE id = 1; END;");
        assert_eq!(
            qualified.danger,
            DangerLevel::Forbidden,
            "wrapped static DML needs semantic PL/SQL analysis"
        );
        // A benign no-op block is unaffected — its body carries no interior tier.
        let noop = classify("BEGIN NULL; END;");
        assert_eq!(noop.danger, DangerLevel::Guarded);
        assert_eq!(noop.required_level, Some(OperatingLevel::ReadWrite));
    }

    #[test]
    fn block_interior_floor_reports_the_max_parsed_statement_tier() {
        let floor = block_interior_floor(
            "BEGIN UPDATE orders SET status = 'X'; INSERT INTO audit_log(msg) VALUES ('x'); END;",
            &UnknownOracle,
            StrictModes::default(),
        )
        .expect("parseable block body statements should contribute a floor");
        assert_eq!(floor, (DangerLevel::Destructive, OperatingLevel::ReadWrite));

        assert_eq!(
            block_interior_floor(
                "BEGIN IF flag = 1 THEN UPDATE orders SET status = 'X'; END IF; END;",
                &UnknownOracle,
                StrictModes::default(),
            ),
            None,
            "control-flow segments are intentionally not flattened into bare SQL"
        );
    }

    #[test]
    fn ddl_is_destructive_and_needs_ddl_level() {
        let d = classify("DROP TABLE orders");
        assert_eq!(d.danger, DangerLevel::Destructive);
        assert_eq!(d.required_level, Some(OperatingLevel::Ddl));
        assert_eq!(
            classify("TRUNCATE TABLE orders").required_level,
            Some(OperatingLevel::Ddl)
        );
    }

    #[test]
    fn grant_needs_admin() {
        let d = classify("GRANT SELECT ON orders TO scott");
        assert_eq!(d.danger, DangerLevel::Destructive);
        assert_eq!(d.required_level, Some(OperatingLevel::Admin));
    }

    #[test]
    fn parsed_ddl_dcl_never_default_to_read_write() {
        // bead QA100 .84: NO parsed-or-recognized DDL/DCL/Admin statement may be
        // admitted at READ_WRITE. Oracle DDL implicit-commits and cannot be rolled
        // back, so COMMENT ON / ANALYZE / CREATE SEQUENCE / the many CREATE/ALTER/
        // DROP object & account forms must floor at Ddl (object DDL) or Admin
        // (account/role/database/system/audit/policy DCL) — never at ReadWrite via
        // the old catch-all. Each case asserts danger ≥ Guarded and the required
        // level ≥ its floor; a `Forbidden` (None) verdict is STRICTER than any
        // level and also satisfies the floor.
        use OperatingLevel::{Admin, Ddl};
        let cases: &[(&str, OperatingLevel)] = &[
            // The headline regressions — parse-success variants that used to fall
            // through the catch-all to Guarded/ReadWrite.
            ("COMMENT ON TABLE emp IS 'x'", Ddl),
            ("COMMENT ON COLUMN emp.id IS 'note'", Ddl),
            ("ANALYZE TABLE emp COMPUTE STATISTICS", Ddl),
            ("CREATE SEQUENCE s START WITH 1", Ddl),
            // Object DDL — parse-success and parse-fail leading-verb floors alike.
            ("CREATE TABLE t (id NUMBER)", Ddl),
            ("ALTER TABLE emp ADD (x NUMBER)", Ddl),
            ("DROP TABLE emp", Ddl),
            ("CREATE OR REPLACE VIEW v AS SELECT 1 FROM dual", Ddl),
            ("DROP VIEW v", Ddl),
            ("CREATE INDEX i ON emp(id)", Ddl),
            ("ALTER INDEX i REBUILD", Ddl),
            ("DROP INDEX i", Ddl),
            ("ALTER SEQUENCE s INCREMENT BY 2", Ddl),
            ("DROP SEQUENCE s", Ddl),
            ("CREATE SYNONYM syn FOR hr.emp", Ddl),
            ("CREATE OR REPLACE SYNONYM syn FOR hr.emp", Ddl),
            ("DROP SYNONYM syn", Ddl),
            (
                "CREATE TRIGGER trg BEFORE INSERT ON emp BEGIN NULL; END;",
                Ddl,
            ),
            ("CREATE PROCEDURE p AS BEGIN NULL; END;", Ddl),
            ("CREATE PACKAGE pkg AS PROCEDURE q; END;", Ddl),
            ("CREATE TYPE ty AS OBJECT (id NUMBER)", Ddl),
            ("DROP TYPE ty", Ddl),
            ("CREATE TABLESPACE ts DATAFILE 'x.dbf' SIZE 10M", Ddl),
            ("ALTER TABLESPACE ts OFFLINE", Ddl),
            ("DROP TABLESPACE ts", Ddl),
            ("CREATE PROFILE prof LIMIT SESSIONS_PER_USER 1", Admin),
            ("DROP PROFILE prof CASCADE", Admin),
            (
                "CREATE SCHEMA AUTHORIZATION app GRANT SELECT ON app.t TO reader",
                Admin,
            ),
            ("TRUNCATE TABLE emp", Ddl),
            ("CREATE DIRECTORY d AS '/tmp'", Ddl),
            ("CREATE MATERIALIZED VIEW mv AS SELECT 1 FROM dual", Ddl),
            // Account / role / database / system / audit / policy DCL → Admin.
            ("CREATE USER u IDENTIFIED BY p", Admin),
            ("ALTER USER u IDENTIFIED BY p", Admin),
            ("DROP USER u", Admin),
            ("CREATE ROLE r", Admin),
            ("ALTER ROLE r", Admin),
            ("DROP ROLE r", Admin),
            ("GRANT SELECT ON emp TO scott", Admin),
            ("REVOKE SELECT ON emp FROM scott", Admin),
            ("AUDIT SELECT ON emp", Admin),
            ("NOAUDIT SELECT ON emp", Admin),
            ("CREATE POLICY pol ON emp", Admin),
            ("ALTER POLICY pol ON emp", Admin),
            ("DROP POLICY pol ON emp", Admin),
            ("ALTER SYSTEM FLUSH SHARED_POOL", Admin),
            ("ALTER DATABASE OPEN", Admin),
            ("CREATE DATABASE db", Admin),
            ("DROP DATABASE", Admin),
            ("CREATE PLUGGABLE DATABASE apppdb FROM pdb$seed", Admin),
            ("ALTER PLUGGABLE DATABASE apppdb OPEN", Admin),
            ("DROP PLUGGABLE DATABASE apppdb INCLUDING DATAFILES", Admin),
            (
                "CREATE AUDIT POLICY app_audit ACTIONS SELECT ON app.t",
                Admin,
            ),
            ("SET ROLE dba", Admin),
        ];
        for (sql, min_level) in cases {
            let d = classify(sql);
            assert!(
                d.danger >= DangerLevel::Guarded,
                "DDL/DCL under-classified in danger: {sql:?} -> {d:?}"
            );
            assert_ne!(
                d.required_level,
                Some(OperatingLevel::ReadOnly),
                "DDL/DCL must never be admitted at READ_ONLY: {sql:?} -> {d:?}"
            );
            assert_ne!(
                d.required_level,
                Some(OperatingLevel::ReadWrite),
                "DDL/DCL must never be admitted at READ_WRITE: {sql:?} -> {d:?}"
            );
            // Forbidden (None) is stricter than any level and satisfies the floor.
            assert!(
                d.required_level.is_none_or(|l| l >= *min_level),
                "DDL/DCL under-levelled below {min_level:?}: {sql:?} -> {:?}",
                d.required_level
            );
        }
    }

    #[test]
    fn successful_parse_never_lowers_the_leading_verb_floor() {
        // bead QA100 .84 fix #2 (defense in depth): the parser-INDEPENDENT
        // leading-verb floor is an invariant — for any statement whose LEADING
        // tokens name a DDL/DCL/Admin verb, the final required level is ≥ that
        // floor whether or not sqlparser parses it. Parsing is never a downgrade.
        for sql in [
            "CREATE TABLE t (id NUMBER)",
            "CREATE SEQUENCE s START WITH 1",
            "CREATE INDEX i ON emp(id)",
            "ALTER TABLE emp ADD (x NUMBER)",
            "ALTER INDEX i REBUILD",
            "DROP TABLE emp",
            "DROP INDEX i",
            "TRUNCATE TABLE emp",
            "COMMENT ON TABLE emp IS 'x'",
            "ANALYZE TABLE emp COMPUTE STATISTICS",
            "RENAME emp TO emp2",
            "PURGE TABLE emp",
        ] {
            let d = classify(sql);
            assert!(
                d.danger >= DangerLevel::Destructive,
                "leading-DDL danger lowered: {sql:?} -> {d:?}"
            );
            assert!(
                d.required_level.is_none_or(|l| l >= OperatingLevel::Ddl),
                "leading-DDL floor lowered by parse: {sql:?} -> {:?}",
                d.required_level
            );
        }
        for sql in [
            "GRANT SELECT ON emp TO scott",
            "REVOKE SELECT ON emp FROM scott",
            "AUDIT SELECT ON emp",
            "CREATE USER u IDENTIFIED BY p",
            "ALTER USER u IDENTIFIED BY p",
            "ALTER SYSTEM FLUSH SHARED_POOL",
            "CREATE PROFILE prof LIMIT SESSIONS_PER_USER 1",
            "DROP PROFILE prof CASCADE",
            "CREATE SCHEMA AUTHORIZATION app GRANT SELECT ON app.t TO reader",
            "DROP DATABASE",
            "CREATE PLUGGABLE DATABASE apppdb FROM pdb$seed",
            "ALTER PLUGGABLE DATABASE apppdb OPEN",
            "DROP PLUGGABLE DATABASE apppdb INCLUDING DATAFILES",
            "SET ROLE dba",
        ] {
            let d = classify(sql);
            assert!(
                d.danger >= DangerLevel::Destructive,
                "leading-Admin danger lowered: {sql:?} -> {d:?}"
            );
            assert!(
                d.required_level.is_none_or(|l| l >= OperatingLevel::Admin),
                "leading-Admin floor lowered by parse: {sql:?} -> {:?}",
                d.required_level
            );
        }
    }

    #[test]
    fn exhaustive_ddl_match_spares_dml_but_keeps_txn_control_forbidden() {
        // Guard against over-tightening from the .84 exhaustive-match / Forbidden
        // default, with two invariants:
        // (a) Caller transaction control is Forbidden — bead .80 owns this and its
        //     check precedes classify_statement, so the exhaustive DDL match must
        //     never silently downgrade SET TRANSACTION / COMMIT / ROLLBACK /
        //     SAVEPOINT back to ReadWrite.
        for sql in [
            "SET TRANSACTION READ ONLY",
            "SET TRANSACTION READ WRITE",
            "COMMIT",
            "ROLLBACK",
            "SAVEPOINT sp",
        ] {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Forbidden,
                "caller transaction control must stay Forbidden: {sql:?} -> {d:?}"
            );
        }
        // (b) Ordinary DML is NOT DDL and must keep its Guarded/ReadWrite floor —
        //     the exhaustive DDL match and the fail-closed Forbidden default must
        //     not sweep an INSERT/UPDATE up into DDL/Admin/Forbidden.
        for sql in [
            "INSERT INTO audit_log (msg) VALUES ('x')",
            "UPDATE orders SET status = 'X' WHERE id = 1",
        ] {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Guarded,
                "ordinary DML must stay Guarded (not over-tightened): {sql:?} -> {d:?}"
            );
            assert_eq!(
                d.required_level,
                Some(OperatingLevel::ReadWrite),
                "ordinary DML must stay ReadWrite: {sql:?} -> {d:?}"
            );
        }
    }

    #[test]
    fn create_or_replace_pure_ddl_is_not_under_tiered_below_plain_create() {
        // oracle-y54x.1: Stage A's broad `CREATE OR REPLACE` prefix used to
        // swallow pure-DDL replace forms (VIEW/SYNONYM/TYPE/DIRECTORY) into the
        // non-dangerous PL/SQL-block arm → Guarded/ReadWrite, STRICTLY BELOW the
        // Destructive/Ddl their (less destructive) plain `CREATE …` counterparts
        // earn. An object-clobbering replace must never tier below the plain
        // create. Each replace form must classify Destructive/Ddl and at least as
        // high as its plain counterpart.
        let pairs = [
            (
                "CREATE VIEW v AS SELECT 1 FROM dual", // parses → Stage B
                "CREATE OR REPLACE VIEW v AS SELECT 1 FROM dual",
            ),
            (
                "CREATE SYNONYM s FOR hr.emp", // unparseable → parse-failure floor
                "CREATE OR REPLACE SYNONYM s FOR hr.emp",
            ),
            (
                "CREATE TYPE t AS OBJECT (x NUMBER)",
                "CREATE OR REPLACE TYPE t AS OBJECT (x NUMBER)",
            ),
            (
                "CREATE DIRECTORY d AS '/tmp'",
                "CREATE OR REPLACE DIRECTORY d AS '/tmp'",
            ),
        ];
        for (plain, replace) in pairs {
            let dp = classify(plain);
            let dr = classify(replace);
            assert_eq!(
                dr.danger,
                DangerLevel::Destructive,
                "CREATE OR REPLACE pure-DDL must be Destructive: {replace:?}"
            );
            assert_eq!(
                dr.required_level,
                Some(OperatingLevel::Ddl),
                "CREATE OR REPLACE pure-DDL must require Ddl: {replace:?}"
            );
            assert!(
                dr.required_level >= dp.required_level,
                "the OR REPLACE form must never tier below its plain counterpart: \
                 {replace:?} ({:?}) vs {plain:?} ({:?})",
                dr.required_level,
                dp.required_level,
            );
        }
    }

    #[test]
    fn create_user_and_role_still_admin_not_just_ddl() {
        // The generic leading-`CREATE ` DDL floor must NOT down-shadow the
        // admin-level CREATE forms: the admin scan runs FIRST in the
        // parse-failure arm, so CREATE USER / CREATE ROLE stay Destructive/Admin.
        for sql in ["CREATE USER evil IDENTIFIED BY pw", "CREATE ROLE evil"] {
            let d = classify(sql);
            assert_eq!(d.danger, DangerLevel::Destructive, "{sql:?}");
            assert_eq!(
                d.required_level,
                Some(OperatingLevel::Admin),
                "CREATE USER/ROLE must require Admin, not Ddl: {sql:?}"
            );
        }
    }

    #[test]
    fn plsql_bearing_create_floors_at_ddl_and_still_scans_body() {
        // oracle-p0d6: a PL/SQL-bearing CREATE [OR REPLACE] REPLACES a stored
        // object — that is DDL. A clean body must FLOOR at Destructive/Ddl (the
        // object-clobbering-replace fail-open-tier fix, mirroring oracle-y54x.1
        // for the pure-DDL create forms and consistent with `CREATE OR REPLACE
        // VIEW`, `oracle_patch_source`, and the levels.rs ladder doc). The body
        // side-effect scan is UNCHANGED: a dynamic-SQL marker must still escalate
        // ABOVE Ddl to Forbidden — even with inter-keyword spacing. This is a pure
        // tightening: the floor only ever RAISES a benign body's level.
        for (kind, sql) in [
            (
                "or-replace procedure",
                "CREATE OR REPLACE PROCEDURE p IS BEGIN NULL; END;",
            ),
            ("plain procedure", "CREATE PROCEDURE p IS BEGIN NULL; END;"),
            (
                "or-replace function",
                "CREATE OR REPLACE FUNCTION f RETURN NUMBER IS BEGIN RETURN 1; END;",
            ),
            (
                "or-replace trigger",
                "CREATE OR REPLACE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW BEGIN NULL; END;",
            ),
            // NOTE: a PACKAGE / PACKAGE BODY spec is not balanceable by the
            // generic BEGIN/END counter (it fails closed to Forbidden on the
            // create_or_replace path and is handled by oracle_patch_source's
            // body-balance override) — so it is deliberately excluded here; the
            // point of this case set is the ReadWrite→Ddl floor on the forms that
            // DO reach the non-dangerous PL/SQL-block arm.
        ] {
            let clean = classify(sql);
            assert_eq!(
                clean.danger,
                DangerLevel::Destructive,
                "clean PL/SQL create must be Destructive (DDL replace): {kind}"
            );
            assert_eq!(
                clean.required_level,
                Some(OperatingLevel::Ddl),
                "clean PL/SQL create must FLOOR at Ddl (not ReadWrite): {kind}"
            );
        }

        // The dangerous-body escalation is preserved and lands ABOVE Ddl: a
        // dynamic-SQL-bearing body fails closed to Forbidden regardless of the
        // inter-keyword spacing that the canonical scan collapses.
        let dynamic = classify(
            "CREATE  OR  REPLACE  PROCEDURE p IS BEGIN EXECUTE IMMEDIATE 'DROP TABLE t'; END;",
        );
        assert_eq!(
            dynamic.danger,
            DangerLevel::Forbidden,
            "a dynamic-SQL-bearing proc body must fail closed (above Ddl) regardless of spacing"
        );
        assert_eq!(
            dynamic.required_level, None,
            "a Forbidden body has no admitting level — strictly above the Ddl floor"
        );
    }

    #[test]
    fn plsql_create_ddl_floor_is_pure_tightening() {
        // Prove monotonicity for oracle-p0d6: the Ddl floor may only RAISE the
        // level of a PL/SQL-bearing create, and must not touch anything else.
        // (a) The reviewed NULL-only anonymous block is not a create and keeps
        // its body-derived ReadWrite floor. DECLARE needs semantic analysis and
        // is now independently Forbidden, not accidentally DDL-floored.
        let noop = classify("BEGIN NULL; END;");
        assert_eq!(noop.danger, DangerLevel::Guarded);
        assert_eq!(noop.required_level, Some(OperatingLevel::ReadWrite));
        let declare = classify("DECLARE x NUMBER; BEGIN x := 1; END;");
        assert_eq!(declare.danger, DangerLevel::Forbidden);
        // (b) The create floor never LOWERS a level: a PL/SQL create is >= Ddl,
        //     strictly above the ReadWrite it earned before, and never below the
        //     plain anonymous-block body floor.
        let create = classify("CREATE OR REPLACE PROCEDURE p IS BEGIN NULL; END;");
        assert!(
            create.required_level >= Some(OperatingLevel::Ddl),
            "PL/SQL create must be at least Ddl"
        );
        assert!(
            create.required_level > Some(OperatingLevel::ReadWrite),
            "PL/SQL create must tier strictly ABOVE the old ReadWrite floor"
        );
    }

    #[test]
    fn unparseable_admin_dcl_fails_closed_to_admin_not_readwrite() {
        // oracle-clgt.3: sqlparser 0.62 cannot parse most Oracle admin/DCL, and
        // the old parse-failure default under-levelled every one of them to
        // ReadWrite — letting a ReadWrite-elevated session run privilege
        // escalation (GRANT DBA, ALTER USER … IDENTIFIED BY, ALTER SYSTEM, …)
        // with NO Admin step-up. Each of these must classify Destructive/Admin so
        // a session at ReadWrite is forced to step up to Admin (RequireStepUp),
        // not Allowed. Mix of parse-failure-branch statements and statements that
        // DO parse (CREATE/DROP ROLE, DROP USER, SET ROLE) that previously hit the
        // ReadWrite catch-all.
        let admin_dcl = [
            // --- parse-failure branch (leading admin-verb scan) ---
            "GRANT DBA TO scott",
            "REVOKE DBA FROM scott",
            "ALTER USER sys IDENTIFIED BY hacked",
            "ALTER SYSTEM SET sga_target = 0",
            "ALTER DATABASE OPEN",
            "ALTER PROFILE default LIMIT sessions_per_user 10",
            "CREATE USER evil IDENTIFIED BY pw",
            "ALTER ROLE evil",
            "AUDIT SELECT ON orders",
            "NOAUDIT SELECT ON orders",
            // --- parse successfully but previously hit the ReadWrite catch-all ---
            "CREATE ROLE evil",
            "DROP ROLE evil",
            "DROP USER evil",
            "SET ROLE dba",
        ];
        // A session whose ceiling is Admin, currently elevated only to ReadWrite
        // (the exact escalation the bead describes).
        let mut session = SessionLevelState::new(OperatingLevel::Admin, false);
        session
            .set_current_level(OperatingLevel::ReadWrite)
            .expect("step current level to ReadWrite");
        for sql in admin_dcl {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Destructive,
                "admin/DCL must be Destructive, not Guarded: {sql:?}"
            );
            assert_eq!(
                d.required_level,
                Some(OperatingLevel::Admin),
                "admin/DCL must require Admin, not ReadWrite: {sql:?}"
            );
            assert_eq!(
                d.gate(&session),
                LevelDecision::RequireStepUp {
                    target: OperatingLevel::Admin
                },
                "a ReadWrite-elevated session must be forced to step up to Admin, \
                 never Allowed, for: {sql:?}"
            );
        }
    }

    #[test]
    fn unparseable_destructive_ddl_fails_closed_to_ddl_not_readwrite() {
        // oracle-j1ep.3: sqlparser 0.62 cannot parse these irreversible Oracle
        // DDL forms, and the old parse-failure default under-levelled every one
        // of them to Guarded/ReadWrite — letting a ReadWrite-elevated session
        // RENAME a table, PURGE a table/recyclebin/tablespace, FLASHBACK a table
        // back, or (DIS)ASSOCIATE optimizer statistics with NO forced Ddl
        // step-up, bypassing the schema deny_ddl / guarded-destructive policy.
        // Each must classify Destructive/Ddl so a session at ReadWrite is forced
        // to step up to Ddl (RequireStepUp), not Allowed.
        let destructive_ddl = [
            "RENAME orders TO orders_old",
            "PURGE TABLE orders",
            "PURGE RECYCLEBIN",
            "PURGE TABLESPACE ts1",
            "FLASHBACK TABLE orders TO BEFORE DROP",
            "ASSOCIATE STATISTICS WITH COLUMNS orders.id DEFAULT SELECTIVITY 5",
            "DISASSOCIATE STATISTICS FROM COLUMNS orders.id",
        ];
        // A session whose ceiling is Admin, currently elevated only to ReadWrite
        // (the exact escalation the bead describes).
        let mut session = SessionLevelState::new(OperatingLevel::Admin, false);
        session
            .set_current_level(OperatingLevel::ReadWrite)
            .expect("step current level to ReadWrite");
        for sql in destructive_ddl {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Destructive,
                "destructive DDL must be Destructive, not Guarded: {sql:?}"
            );
            assert_eq!(
                d.required_level,
                Some(OperatingLevel::Ddl),
                "destructive DDL must require Ddl, not ReadWrite: {sql:?}"
            );
            assert_eq!(
                d.gate(&session),
                LevelDecision::RequireStepUp {
                    target: OperatingLevel::Ddl
                },
                "a ReadWrite-elevated session must be forced to step up to Ddl, \
                 never Allowed, for: {sql:?}"
            );
        }
    }

    #[test]
    fn flashback_database_escalates_to_admin_not_ddl() {
        // oracle-j1ep.3: FLASHBACK of an entire (pluggable) database is a
        // server-wide point-in-time rewind — an Admin operation, not object DDL.
        // The admin-verb scan runs before the broader leading-`FLASHBACK ` Ddl
        // match, so these resolve to Destructive/Admin while `FLASHBACK TABLE`
        // stays at Ddl (covered above).
        let mut session = SessionLevelState::new(OperatingLevel::Admin, false);
        session
            .set_current_level(OperatingLevel::ReadWrite)
            .expect("step current level to ReadWrite");
        for sql in [
            "FLASHBACK DATABASE TO RESTORE POINT before_upgrade",
            "FLASHBACK PLUGGABLE DATABASE pdb1 TO RESTORE POINT rp1",
        ] {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Destructive,
                "database FLASHBACK must be Destructive: {sql:?}"
            );
            assert_eq!(
                d.required_level,
                Some(OperatingLevel::Admin),
                "database FLASHBACK must require Admin, not Ddl: {sql:?}"
            );
            assert_eq!(
                d.gate(&session),
                LevelDecision::RequireStepUp {
                    target: OperatingLevel::Admin
                },
                "{sql:?} must require Admin step-up from a ReadWrite session"
            );
        }
    }

    #[test]
    fn ddl_verb_scan_is_word_boundaried_and_leading_only() {
        // The contrapositive of the DDL-verb scan: a verb that merely appears as
        // a *prefix of an identifier* (PURGED_AT, RENAMED_FLAG), or NOT at the
        // statement-leading position (a non-leading `purge()` call), must NOT be
        // mis-escalated to Destructive/Ddl. The canonical token scan tokenizes
        // PURGED_AT / RENAMED_FLAG as single word tokens (never the verb), and
        // the patterns only match at offset 0.
        for sql in [
            "SELECT purged_at FROM t",
            "SELECT renamed_flag FROM t",
            "UPDATE t SET purged_at = SYSDATE WHERE id = 1",
            // A non-leading package-member call named `purge` is data, not a verb.
            "SELECT billing.purge() FROM dual",
            // A quoted identifier "PURGE" is data, never the verb.
            r#"SELECT "PURGE" FROM t"#,
        ] {
            let d = classify(sql);
            assert_ne!(
                d.required_level,
                Some(OperatingLevel::Ddl),
                "word-boundary / leading-only: {sql:?} must not require Ddl"
            );
            assert_ne!(
                d.danger,
                DangerLevel::Destructive,
                "word-boundary / leading-only: {sql:?} must not be Destructive"
            );
        }
    }

    #[test]
    fn admin_verb_scan_is_word_boundaried_and_leading_only() {
        // The contrapositive of the admin-verb scan: a verb that merely appears as
        // a *prefix of an identifier* (DELETED_FLAG, GRANTED_FLAG), or NOT at the
        // statement-leading position, must NOT be mis-escalated to Admin. The
        // canonical token scan tokenizes DELETED_FLAG / GRANTED_FLAG as single
        // word tokens (never the verb), and the patterns only match at offset 0.
        // None of these is admin/DCL; none may classify Admin.
        for sql in [
            "SELECT deleted_flag FROM t",
            "SELECT granted_flag, revoked_at FROM audit_log",
            "UPDATE t SET granted_flag = 1 WHERE id = 1",
            "SELECT * FROM grants_audit WHERE auditor = 'x'",
            // A quoted identifier "GRANT" is data, never the verb.
            r#"SELECT "GRANT" FROM t"#,
        ] {
            let d = classify(sql);
            assert_ne!(
                d.required_level,
                Some(OperatingLevel::Admin),
                "word-boundary / leading-only: {sql:?} must not require Admin"
            );
            assert_ne!(
                d.danger,
                DangerLevel::Destructive,
                "word-boundary / leading-only: {sql:?} must not be Destructive"
            );
        }
    }

    #[test]
    fn set_role_and_create_role_require_admin_step_up() {
        // oracle-clgt.13: SET ROLE and CREATE/ALTER/DROP ROLE touch the privilege
        // model and require Admin. A session at ReadWrite must NOT be allowed to
        // enable a write-bearing role post-connect via SET ROLE; it must be forced
        // to step up to Admin. (The hard guarantee on a correctly-provisioned
        // deployment still rests on layer A, but layer C now refuses to Allow it.)
        let mut session = SessionLevelState::new(OperatingLevel::Admin, false);
        session
            .set_current_level(OperatingLevel::ReadWrite)
            .expect("step current level to ReadWrite");
        for sql in ["SET ROLE dba", "SET ROLE ALL", "CREATE ROLE evil"] {
            let d = classify(sql);
            assert_eq!(d.required_level, Some(OperatingLevel::Admin), "{sql:?}");
            assert_eq!(
                d.gate(&session),
                LevelDecision::RequireStepUp {
                    target: OperatingLevel::Admin
                },
                "{sql:?} must require Admin step-up from a ReadWrite session"
            );
        }
    }

    #[test]
    fn allowlisted_alter_session_is_guarded_non_transactional_readwrite() {
        let read_only = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        let mut read_write = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        read_write
            .set_current_level(OperatingLevel::ReadWrite)
            .expect("step to ReadWrite");
        for sql in [
            "ALTER SESSION SET CURRENT_SCHEMA = hr",
            "ALTER SESSION SET EDITION = app_release_v2",
            "ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL'",
            "ALTER SESSION SET PLSCOPE_SETTINGS = 'IDENTIFIERS:ALL, STATEMENTS:ALL'",
            "/* oraclemcp audit */ ALTER/**/SESSION SET NLS_DATE_FORMAT/**/=/**/'YYYY'",
        ] {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Guarded,
                "reviewed ALTER SESSION setting must stay Guarded: {sql:?}"
            );
            assert_eq!(d.required_level, Some(OperatingLevel::ReadWrite), "{sql:?}");
            assert!(
                d.non_transactional_effect,
                "session state survives transaction rollback: {sql:?}"
            );
            assert_eq!(
                d.gate(&read_only),
                LevelDecision::RequireStepUp {
                    target: OperatingLevel::ReadWrite
                },
                "a READ_ONLY session must step up for: {sql:?}"
            );
            assert_eq!(
                d.gate(&read_write),
                LevelDecision::Allow,
                "a reviewed setting is allowed at READ_WRITE after confirmation: {sql:?}"
            );
        }
    }

    #[test]
    fn non_allowlisted_alter_session_is_forbidden_before_operator_allowlist() {
        let denied = [
            "ALTER SESSION SET SQL_TRACE = TRUE",
            "ALTER SESSION SET CONTAINER = CDB$ROOT",
            "ALTER SESSION SET EVENTS = '10046 trace name context forever, level 12'",
            "ALTER SESSION SET \"_PRIVATE_PARAMETER\" = TRUE",
            "ALTER SESSION DISABLE GUARD",
            "ALTER SESSION ENABLE COMMIT IN PROCEDURE",
            "ALTER/**/SESSION SET CURRENT_SCHEMA=HR/**/SQL_TRACE=TRUE",
            "ALTER SESSION SET EDITION = app_release_v2 SQL_TRACE = TRUE",
            "/* oraclemcp audit */ ALTER SESSION SET CONTAINER = CDB$ROOT",
        ];

        for sql in denied {
            let d = classify(sql);
            assert_eq!(d.danger, DangerLevel::Forbidden, "{sql:?} -> {d:?}");
            assert_eq!(d.required_level, None, "{sql:?}");
            assert_eq!(d.offending_construct.as_deref(), Some("ALTER SESSION"));
            for ceiling in [
                OperatingLevel::ReadOnly,
                OperatingLevel::ReadWrite,
                OperatingLevel::Ddl,
                OperatingLevel::Admin,
            ] {
                let session = SessionLevelState::new(ceiling, false);
                assert_eq!(
                    d.gate(&session),
                    LevelDecision::Blocked {
                        reason: BlockReason::Forbidden
                    },
                    "no operating level may authorize {sql:?}"
                );
            }

            let blessed = Classifier::new(ClassifierConfig::new().with_allow(sql)).classify(sql);
            assert_eq!(
                blessed.danger,
                DangerLevel::Forbidden,
                "an exact operator allow-list entry must not bypass session policy: {sql:?}"
            );
        }
    }

    #[test]
    fn edition_lifecycle_is_exact_ddl_and_cannot_be_allow_listed_downward() {
        for sql in [
            "CREATE EDITION app_release_v2 AS CHILD OF app_release_v1",
            "DROP EDITION app_release_v1 CASCADE",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Destructive, "{sql:?}");
            assert_eq!(
                decision.required_level,
                Some(OperatingLevel::Ddl),
                "{sql:?}"
            );

            let allow_listed =
                Classifier::new(ClassifierConfig::new().with_allow(sql)).classify(sql);
            assert_eq!(
                allow_listed.danger,
                DangerLevel::Destructive,
                "an exact operator allow-list must not turn edition DDL into a read: {sql:?}"
            );
            assert_eq!(
                allow_listed.required_level,
                Some(OperatingLevel::Ddl),
                "{sql:?}"
            );
        }

        for sql in [
            "CREATE EDITION app_release_v2",
            "CREATE EDITION app_release_v2 AS CHILD OF app_release_v1 EXTRA",
            "DROP EDITION app_release_v1 PURGE",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(decision.required_level, None, "{sql:?}");
            assert_eq!(
                decision.offending_construct.as_deref(),
                Some("EDITION lifecycle")
            );
        }
    }

    #[test]
    fn alter_session_text_in_data_is_not_a_session_statement() {
        for sql in [
            "SELECT 'ALTER SESSION SET SQL_TRACE=TRUE' AS text FROM dual",
            "SELECT 1 AS alter_session FROM dual",
            "ALTER TABLE session_log MOVE",
        ] {
            assert_ne!(
                classify(sql).offending_construct.as_deref(),
                Some("ALTER SESSION")
            );
        }
    }

    #[test]
    fn explain_plan_is_guarded_never_safe() {
        let d = classify("EXPLAIN PLAN FOR SELECT * FROM employees");
        assert_eq!(d.danger, DangerLevel::Guarded);
    }

    #[test]
    fn parsed_statement_classifier_arms_keep_their_internal_floors() {
        for sql in [
            "EXPLAIN PLAN FOR SELECT * FROM employees",
            "COMMIT",
            "ROLLBACK",
            "SAVEPOINT before_change",
            "CALL app_admin.run_ddl(:target)",
            "SET TRANSACTION READ ONLY",
        ] {
            let class = classify_one_statement(sql);
            assert_eq!(class.danger, DangerLevel::Guarded, "{sql:?} -> {class:?}");
            assert_eq!(
                class.required,
                Some(OperatingLevel::ReadWrite),
                "{sql:?} -> {class:?}"
            );
        }

        for sql in ["DROP ROLE app_role", "SET ROLE app_admin"] {
            let class = classify_one_statement(sql);
            assert_eq!(
                class.danger,
                DangerLevel::Destructive,
                "{sql:?} -> {class:?}"
            );
            assert_eq!(
                class.required,
                Some(OperatingLevel::Admin),
                "{sql:?} -> {class:?}"
            );
        }
    }

    #[test]
    fn plsql_block_is_at_least_guarded() {
        let d = classify("BEGIN UPDATE t SET x = 1 WHERE id = 2; END;");
        assert!(d.danger >= DangerLevel::Guarded);
    }

    #[test]
    fn plsql_with_execute_immediate_is_forbidden() {
        let d = classify("BEGIN EXECUTE IMMEDIATE 'DELETE FROM orders'; END;");
        assert_eq!(d.danger, DangerLevel::Forbidden);
        assert_eq!(d.required_level, None);
    }

    #[test]
    fn plsql_with_dbms_vector_provider_call_is_forbidden() {
        // DBMS_VECTOR.UTL_TO_EMBEDDING can call an external provider; keep the
        // package marker fail-closed even though bare VECTOR_DISTANCE is pure SQL
        // math and safe above.
        let d = classify("BEGIN :v := DBMS_VECTOR.UTL_TO_EMBEDDING(:txt); END;");
        assert_eq!(d.danger, DangerLevel::Forbidden);
        assert_eq!(d.required_level, None);
        assert_eq!(d.reason_category, Some(ReasonCategory::DynamicSql));
    }

    #[test]
    fn caller_transaction_control_is_always_forbidden() {
        for (sql, construct) in [
            ("COMMIT", "COMMIT"),
            ("COMMIT WORK WRITE NOWAIT", "COMMIT"),
            ("ROLLBACK", "ROLLBACK"),
            ("ROLLBACK TO SAVEPOINT before_change", "ROLLBACK"),
            ("SAVEPOINT before_change", "SAVEPOINT"),
            ("SET TRANSACTION READ WRITE", "SET TRANSACTION"),
            (
                "BEGIN UPDATE t SET x = 1 WHERE id = 7; COMMIT; END;",
                "COMMIT",
            ),
            (
                "BEGIN IF flag = 1 THEN COMMIT WRITE BATCH NOWAIT; END IF; END;",
                "COMMIT",
            ),
            (
                "BEGIN LOOP ROLLBACK TO SAVEPOINT before_change; EXIT; END LOOP; END;",
                "ROLLBACK",
            ),
            (
                "BEGIN SAVEPOINT before_change; EXCEPTION WHEN OTHERS THEN ROLLBACK; END;",
                "SAVEPOINT",
            ),
            (
                "BEGIN SET /* operator comment */ TRANSACTION READ ONLY; END;",
                "SET TRANSACTION",
            ),
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(decision.required_level, None, "{sql:?}");
            assert_eq!(
                decision.reason_category,
                Some(ReasonCategory::TransactionControl),
                "{sql:?}"
            );
            assert_eq!(
                decision.offending_construct.as_deref(),
                Some(construct),
                "{sql:?}"
            );
        }
    }

    #[test]
    fn transaction_control_cannot_be_operator_allow_listed() {
        let sql = "BEGIN UPDATE t SET x = 1 WHERE id = 7; COMMIT; END;";
        let decision = Classifier::new(ClassifierConfig::new().with_allow(sql)).classify(sql);
        assert_eq!(decision.danger, DangerLevel::Forbidden);
        assert_eq!(
            decision.reason_category,
            Some(ReasonCategory::TransactionControl)
        );
    }

    #[test]
    fn transaction_words_in_data_and_identifiers_do_not_false_trigger() {
        for sql in [
            "SELECT 'COMMIT ROLLBACK SAVEPOINT SET TRANSACTION' AS message FROM dual",
            r#"SELECT "COMMIT", commitment, rollback_count, savepoint_name FROM ledger"#,
            "BEGIN note := 'COMMIT'; -- ROLLBACK TO x\n NULL; END;",
            "BEGIN commitment := rollback_count + savepoint_count; END;",
        ] {
            let decision = classify(sql);
            assert_ne!(
                decision.reason_category,
                Some(ReasonCategory::TransactionControl),
                "data-only keyword mention was treated as executable control: {sql:?}"
            );
        }
    }

    #[test]
    fn opaque_plsql_routine_calls_are_forbidden() {
        for sql in [
            "BEGIN DBMS_UTILITY.EXEC_DDL_STATEMENT('DROP TABLE target'); END;",
            "BEGIN dbms_utility /* gap */ . execute_ddl_statement('DROP ' || 'TABLE target'); END;",
            "BEGIN util.exec_ddl_statement('DROP TABLE target'); END;",
            "CALL DBMS_UTILITY.EXEC_DDL_STATEMENT('DROP TABLE target')",
            "BEGIN SYS.DBMS_SYSTEM.KSDWRT(2, 'operator message'); END;",
            "BEGIN app_admin.run_ddl(:object_name); END;",
            "BEGIN app_admin.run_ddl; END;",
            "BEGIN app_owner.app_admin.run_ddl; END;",
            "BEGIN app_admin.run_ddl@remote_db; END;",
            "<<audit_step>> BEGIN app_admin.run_ddl; END;",
            "BEGIN <<audit_step>> app_admin.run_ddl; END;",
            "BEGIN dangerous_proc; END;",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(decision.required_level, None, "{sql:?}");
            assert_eq!(
                decision.reason_category,
                Some(ReasonCategory::UnprovenSideEffect),
                "{sql:?}"
            );
            assert!(decision.objects_affected.is_empty(), "{sql:?}");
        }
    }

    #[test]
    fn stored_program_declarations_are_not_mistaken_for_invocation() {
        for sql in [
            "CREATE OR REPLACE PROCEDURE p(p_value NUMBER) AS BEGIN NULL; END;",
            "CREATE OR REPLACE FUNCTION f(p_value NUMBER) RETURN NUMBER AS BEGIN RETURN p_value; END;",
        ] {
            let decision = classify(sql);
            assert_ne!(
                decision.reason_category,
                Some(ReasonCategory::UnprovenSideEffect),
                "a declaration signature is not an executed routine: {sql:?}"
            );
            assert_eq!(
                decision.required_level,
                Some(OperatingLevel::Ddl),
                "{sql:?}"
            );
        }

        // Package specifications currently take a separate, pre-existing
        // unbalanced-block refusal path (tracked independently). This assertion
        // is intentionally limited to the declaration-vs-invocation contract.
        let package =
            classify("CREATE OR REPLACE PACKAGE p AS PROCEDURE run(p_value NUMBER); END;");
        assert_ne!(
            package.reason_category,
            Some(ReasonCategory::UnprovenSideEffect)
        );
    }

    #[test]
    fn package_specifications_balance_as_single_ddl_units() {
        for sql in [
            "CREATE OR REPLACE PACKAGE p AS PROCEDURE run(p_value NUMBER); END;",
            "CREATE OR REPLACE PACKAGE p AUTHID DEFINER AS PROCEDURE a; FUNCTION b RETURN NUMBER; END p;",
            "create /* header */ or replace package p authid current_user as procedure q; end p;",
            "CREATE OR REPLACE EDITIONABLE PACKAGE app.p AS PROCEDURE q; END p;",
            "CREATE NONEDITIONABLE PACKAGE \"MixedCase\" AS PROCEDURE q; END \"MixedCase\";",
        ] {
            let shape = analyze_batch(sql);
            assert!(
                shape.balanced,
                "package spec must balance: {sql:?} -> {shape:?}"
            );
            assert_eq!(
                shape.statement_count, 1,
                "member semicolons stay inside the package unit: {sql:?} -> {shape:?}"
            );

            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Destructive, "{sql:?}");
            assert_eq!(
                decision.required_level,
                Some(OperatingLevel::Ddl),
                "package replacement must retain the DDL floor: {sql:?}"
            );
            assert_eq!(
                decision.reason_category,
                Some(ReasonCategory::PlSqlBlock),
                "{sql:?}"
            );
        }

        let mut read_write = SessionLevelState::new(OperatingLevel::Ddl, false);
        read_write
            .set_current_level(OperatingLevel::ReadWrite)
            .expect("raise session to READ_WRITE");
        let decision = classify("CREATE OR REPLACE PACKAGE p AS PROCEDURE q; END;");
        assert_eq!(
            decision.gate(&read_write),
            LevelDecision::RequireStepUp {
                target: OperatingLevel::Ddl
            },
            "balancing a package spec must not lower its required authority"
        );
    }

    #[test]
    fn package_specification_balance_exception_stays_fail_closed() {
        for sql in [
            "CREATE OR REPLACE PACKAGE p AS PROCEDURE q;",
            "CREATE OR REPLACE PACKAGE p AS PROCEDURE q; END; END;",
            "CREATE OR REPLACE PACKAGE p AS PROCEDURE q; END; DROP TABLE t",
            "CREATE OR REPLACE PACKAGE p AS PROCEDURE q; END; / GRANT DBA TO app",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(decision.required_level, None, "{sql:?}");
        }

        for sql in [
            "CREATE OR REPLACE PACKAGE p AS PRAGMA AUTONOMOUS_TRANSACTION; END;",
            "CREATE OR REPLACE PACKAGE p AS EXECUTE IMMEDIATE 'DROP TABLE t'; END;",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(
                decision.reason_category,
                Some(ReasonCategory::DynamicSql),
                "the existing dynamic-marker refusal must run before package balancing: {sql:?}"
            );
        }
    }

    #[test]
    fn package_specification_fix_does_not_change_other_block_shapes() {
        let body = classify("CREATE OR REPLACE PACKAGE BODY p AS BEGIN NULL; END;");
        assert_eq!(body.danger, DangerLevel::Destructive);
        assert_eq!(body.required_level, Some(OperatingLevel::Ddl));

        let anonymous = classify("BEGIN NULL; END;");
        assert_eq!(anonymous.danger, DangerLevel::Guarded);
        assert_eq!(anonymous.required_level, Some(OperatingLevel::ReadWrite));

        let object_type =
            classify("CREATE OR REPLACE TYPE t AS OBJECT (x NUMBER, MEMBER PROCEDURE run);");
        assert_eq!(object_type.danger, DangerLevel::Destructive);
        assert_eq!(object_type.required_level, Some(OperatingLevel::Ddl));
    }

    #[test]
    fn package_body_final_end_matching_tracks_nested_and_quoted_keywords() {
        let control_flow =
            "CREATE OR REPLACE PACKAGE BODY p AS BEGIN IF TRUE THEN NULL; END IF; END p;";
        let tokens = oracle_tokens(control_flow);
        let unit = stored_unit_create(control_flow).expect("package body should be recognized");
        let final_end = stored_unit_final_end(&tokens, &unit).expect("final END should be found");
        let init_begin = nth_unquoted_word(&tokens, "BEGIN", 0);
        assert!(
            begin_matches_final_end(&tokens, init_begin, final_end),
            "package initialization BEGIN must match the unit-final END despite nested END IF"
        );

        let member_then_init = "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q IS BEGIN NULL; END q; BEGIN NULL; END p;";
        let tokens = oracle_tokens(member_then_init);
        let unit = stored_unit_create(member_then_init).expect("package body should be recognized");
        let final_end = stored_unit_final_end(&tokens, &unit).expect("final END should be found");
        let member_begin = nth_unquoted_word(&tokens, "BEGIN", 0);
        let init_begin = nth_unquoted_word(&tokens, "BEGIN", 1);
        assert!(
            !begin_matches_final_end(&tokens, member_begin, final_end),
            "a member subprogram BEGIN must not be mistaken for package initialization"
        );
        assert!(
            begin_matches_final_end(&tokens, init_begin, final_end),
            "the later package initialization BEGIN owns the final END"
        );

        let quoted_keyword = oracle_tokens(r#"BEGIN "IF" END"#);
        let begin = nth_unquoted_word(&quoted_keyword, "BEGIN", 0);
        let end = nth_unquoted_word(&quoted_keyword, "END", 0);
        assert!(
            begin_matches_final_end(&quoted_keyword, begin, end),
            "quoted identifiers that spell control-flow keywords are not structural"
        );
    }

    #[test]
    fn stored_package_and_type_bodies_are_single_ddl_units() {
        for sql in [
            // Initialization sections: the terminal END closes both the
            // executable section and the package unit, with or without a name.
            "CREATE OR REPLACE PACKAGE BODY p AS BEGIN NULL; END;",
            "CREATE OR REPLACE PACKAGE BODY p AS BEGIN NULL; END p;",
            // Member bodies may use named or unnamed END independently of the
            // final unit END.
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q IS BEGIN NULL; END q; END p;",
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q IS BEGIN NULL; END; END p;",
            // Declarations/member bodies followed by package initialization.
            "CREATE OR REPLACE PACKAGE BODY p AS g NUMBER := 0; PROCEDURE q IS BEGIN g := 1; END q; BEGIN g := 2; END p;",
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q IS BEGIN NULL; END; BEGIN NULL; END;",
            "CREATE OR REPLACE PACKAGE BODY app.p AUTHID DEFINER AS FUNCTION f RETURN NUMBER IS BEGIN RETURN 1; END f; END p;",
            "create /* header */ or replace editionable package body \"App\".\"P\" as procedure \"Q\" is begin null; end \"Q\"; end \"P\";",
            "CREATE NONEDITIONABLE TYPE BODY app.t AS MEMBER PROCEDURE q IS BEGIN NULL; END q; END t;",
            "CREATE OR REPLACE TYPE BODY t AS MEMBER PROCEDURE q IS BEGIN NULL; END; END t;",
            "CREATE OR REPLACE TYPE BODY \"App\".\"T\" AS MEMBER FUNCTION f RETURN NUMBER IS BEGIN RETURN 1; END f; END \"T\";",
        ] {
            let shape = analyze_batch(sql);
            assert!(
                shape.balanced,
                "stored body must balance: {sql:?} -> {shape:?}"
            );
            assert_eq!(
                shape.statement_count, 1,
                "member semicolons stay inside the stored unit: {sql:?} -> {shape:?}"
            );
            assert!(
                !shape.saw_top_level_after_block_close,
                "named member/unit terminators are not trailing SQL: {sql:?} -> {shape:?}"
            );

            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Destructive, "{sql:?}");
            assert_eq!(
                decision.required_level,
                Some(OperatingLevel::Ddl),
                "stored-code replacement must retain the DDL floor: {sql:?}"
            );
            assert_eq!(
                decision.reason_category,
                Some(ReasonCategory::PlSqlBlock),
                "{sql:?}"
            );
        }
    }

    #[test]
    fn stored_body_shape_exception_stays_fail_closed() {
        for sql in [
            // Missing and extra outer closes.
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q IS BEGIN NULL; END q;",
            "CREATE OR REPLACE TYPE BODY t AS MEMBER PROCEDURE q IS BEGIN NULL; END q; END t; END;",
            // The optional named terminator must match the created unit.
            "CREATE OR REPLACE PACKAGE BODY p AS BEGIN NULL; END other;",
            // Nothing may follow the final unit terminator except SQL*Plus `/`.
            "CREATE OR REPLACE PACKAGE BODY p AS BEGIN NULL; END p; DROP TABLE t",
            "CREATE OR REPLACE TYPE BODY t AS MEMBER PROCEDURE q IS BEGIN NULL; END q; END t; GRANT DBA TO app",
            "CREATE OR REPLACE PACKAGE BODY p AS BEGIN NULL; END p; / DROP TABLE t",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(decision.required_level, None, "{sql:?}");
        }

        for sql in [
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q IS BEGIN EXECUTE/**/IMMEDIATE 'DROP TABLE t'; END q; END p;",
            "CREATE OR REPLACE TYPE BODY t AS MEMBER PROCEDURE q IS BEGIN UTL_FILE.PUT_LINE(f, 'x'); END q; END t;",
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q IS BEGIN UTL_HTTP.REQUEST('https://example.invalid'); END q; END p;",
            "CREATE OR REPLACE TYPE BODY t AS MEMBER PROCEDURE q IS BEGIN DBMS_SCHEDULER.RUN_JOB('j'); END q; END t;",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(decision.required_level, None, "{sql:?}");
            assert_eq!(
                decision.reason_category,
                Some(ReasonCategory::DynamicSql),
                "side-effect marker scan must precede stored-unit balancing: {sql:?}"
            );
        }

        // The implicit outer scope belongs only to recognized CREATE package/type
        // units. Anonymous-block behavior must not inherit the stored-unit name
        // exception or the DDL floor.
        let anonymous = classify("BEGIN NULL; END;");
        assert_eq!(anonymous.danger, DangerLevel::Guarded);
        assert_eq!(anonymous.required_level, Some(OperatingLevel::ReadWrite));

        for sql in [
            "BEGIN NULL; END block_name;",
            "BEGIN NULL; END; DROP TABLE t",
            "BEGIN EXECUTE IMMEDIATE 'DROP TABLE t'; END;",
        ] {
            assert_eq!(classify(sql).danger, DangerLevel::Forbidden, "{sql:?}");
        }
    }

    #[test]
    fn analyze_batch_distinguishes_package_body_header_states() {
        let initialization = analyze_batch(
            "CREATE OR REPLACE PACKAGE BODY p AS BEGIN IF TRUE THEN NULL; END IF; END p;",
        );
        assert!(initialization.balanced, "{initialization:?}");
        assert_eq!(initialization.statement_count, 1, "{initialization:?}");
        assert!(
            !initialization.saw_top_level_after_block_close,
            "{initialization:?}"
        );

        let member_body = analyze_batch(
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q IS BEGIN NULL; END q; BEGIN NULL; END p;",
        );
        assert!(member_body.balanced, "{member_body:?}");
        assert_eq!(member_body.statement_count, 1, "{member_body:?}");
        assert!(
            !member_body.saw_top_level_after_block_close,
            "{member_body:?}"
        );

        let declaration_and_callspec = analyze_batch(
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE declared_only; PROCEDURE j AS LANGUAGE JAVA NAME 'X.y()'; END p;",
        );
        assert!(
            declaration_and_callspec.balanced,
            "{declaration_and_callspec:?}"
        );
        assert_eq!(
            declaration_and_callspec.statement_count, 1,
            "{declaration_and_callspec:?}"
        );

        for sql in [
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q AS AS LANGUAGE JAVA NAME 'X.y()'; END p;",
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q AS JAVA NAME 'X.y()'; END p;",
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q AS LANGUAGE LANGUAGE JAVA NAME 'X.y()'; END p;",
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q AS LANGUAGE EXTERNAL NAME 'X.y()'; END p;",
        ] {
            let shape = analyze_batch(sql);
            assert!(
                !shape.balanced,
                "malformed call-spec header sequence must remain fail-closed: {sql:?} -> {shape:?}"
            );
        }

        let mismatched_unit_name =
            analyze_batch("CREATE OR REPLACE PACKAGE BODY p AS BEGIN NULL; END other;");
        assert!(
            !mismatched_unit_name.balanced,
            "the optional final END name must match the created unit: {mismatched_unit_name:?}"
        );
        assert!(
            mismatched_unit_name.saw_buried_semicolon,
            "the mismatched final name leaves the unit scope unclosed: {mismatched_unit_name:?}"
        );

        for sql in [
            "CREATE OR REPLACE PACKAGE p AS END other;",
            "CREATE OR REPLACE PACKAGE p AS END p /;",
            "CREATE OR REPLACE PACKAGE p AS END p 1;",
        ] {
            let shape = analyze_batch(sql);
            assert!(
                shape.saw_top_level_after_block_close,
                "unexpected tokens after a stored-unit END must be surfaced: {sql:?} -> {shape:?}"
            );
        }

        let declare_only = analyze_batch("DECLARE x NUMBER;");
        assert!(
            declare_only.has_plsql_block,
            "DECLARE must mark the batch as PL/SQL even before BEGIN: {declare_only:?}"
        );
    }

    #[test]
    fn stored_body_call_specifications_are_single_ddl_units() {
        for sql in [
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q AS LANGUAGE JAVA NAME 'X.y()'; END p;",
            "CREATE OR REPLACE PACKAGE BODY p AS FUNCTION f RETURN NUMBER AS LANGUAGE C NAME \"c_f\" LIBRARY c_lib; END p;",
            "CREATE OR REPLACE PACKAGE BODY p AS FUNCTION f RETURN NUMBER IS EXTERNAL NAME \"c_f\" LIBRARY c_lib LANGUAGE C WITH CONTEXT; END p;",
            "CREATE OR REPLACE TYPE BODY t AS MEMBER PROCEDURE q AS LANGUAGE JAVA NAME 'X.y(oracle.sql.STRUCT)'; END t;",
            "CREATE OR REPLACE TYPE BODY t AS STATIC FUNCTION f RETURN NUMBER AS LANGUAGE C NAME \"c_f\" LIBRARY c_lib; END t;",
        ] {
            let shape = analyze_batch(sql);
            assert!(
                shape.balanced,
                "stored call specification must balance: {sql:?} -> {shape:?}"
            );
            assert_eq!(shape.statement_count, 1, "{sql:?} -> {shape:?}");
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Destructive, "{sql:?}");
            assert_eq!(
                decision.required_level,
                Some(OperatingLevel::Ddl),
                "{sql:?}"
            );
        }
    }

    #[test]
    fn stored_body_call_spec_shape_stays_fail_closed() {
        for sql in [
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q AS LANGUAGE JAVA NAME 'X.y()';",
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q AS LANGUAGE JAVA NAME 'X.y()'; END p; END;",
            "CREATE OR REPLACE TYPE BODY t AS MEMBER PROCEDURE q AS LANGUAGE JAVA NAME 'X.y(oracle.sql.STRUCT)'; END t; DROP TABLE x",
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q AS LANGUAGE JAVA NAME 'X.y()'; PROCEDURE bad IS BEGIN EXECUTE IMMEDIATE 'DROP TABLE x'; END bad; END p;",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(decision.required_level, None, "{sql:?}");
        }

        // Marker text inside the foreign symbol string is data, not an
        // executable PL/SQL side-effect marker.
        let literal = classify(
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q AS LANGUAGE JAVA NAME 'X.UTL_FILE_EXECUTE_IMMEDIATE()'; END p;",
        );
        assert_eq!(literal.danger, DangerLevel::Destructive);
        assert_eq!(literal.required_level, Some(OperatingLevel::Ddl));
    }

    #[test]
    fn wrapping_an_opaque_call_never_lowers_its_authority() {
        for sql in [
            "CALL app_admin.run_ddl(:target)",
            "BEGIN app_admin.run_ddl(:target); END;",
            "DECLARE n PLS_INTEGER := 1; BEGIN app_admin.run_ddl(:target); END;",
            "BEGIN IF :enabled = 1 THEN app_admin.run_ddl(:target); END IF; END;",
            "BEGIN LOOP app_admin.run_ddl; EXIT; END LOOP; END;",
            "<<outer_block>> BEGIN <<step>> app_admin.run_ddl; END;",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(
                decision.reason_category,
                Some(ReasonCategory::UnprovenSideEffect),
                "{sql:?}"
            );
        }
    }

    #[test]
    fn plsql_invocation_keyword_skips_all_leading_labels() {
        assert_eq!(
            plsql_invocation_keyword("<<outer_block>> <<inner_step>> BEGIN NULL; END;"),
            Some("BEGIN")
        );
        assert_eq!(
            plsql_invocation_keyword("<<one>> <<two>> <<three>> BEGIN NULL; END;"),
            Some("BEGIN")
        );
        assert_eq!(
            plsql_invocation_keyword("<<one>> <<two>> <<three>> <<four>> BEGIN NULL; END;"),
            Some("BEGIN")
        );
        assert_eq!(
            plsql_invocation_keyword("<<declare_label>> DECLARE x NUMBER; BEGIN NULL; END;"),
            Some("DECLARE")
        );
        assert_eq!(
            plsql_invocation_keyword("<<call_label>> CALL app_admin.run_ddl(:target)"),
            Some("CALL")
        );
        assert_eq!(
            plsql_invocation_keyword("<<not_plsql>> SELECT 1 FROM dual"),
            None
        );
        assert_eq!(
            plsql_invocation_keyword("<<complete>> <<dangling"),
            None,
            "malformed trailing label syntax must not panic or skip beyond the token stream"
        );
    }

    #[test]
    fn routine_purity_proof_cannot_clear_call_without_exact_name_resolution() {
        struct NarrowProof;
        impl SideEffectOracle for NarrowProof {
            fn routine_purity(&self, routine: &ObjectRef) -> Purity {
                if routine.schema.as_deref() == Some("app_read")
                    && routine.name.eq_ignore_ascii_case("lookup")
                {
                    Purity::ProvenReadOnly
                } else {
                    Purity::Unknown
                }
            }
        }
        let classifier = Classifier::default().with_oracle(Arc::new(NarrowProof));

        let ambiguous = classifier.classify("CALL app_read.lookup(:id)");
        assert_eq!(ambiguous.danger, DangerLevel::Forbidden);
        assert_eq!(
            ambiguous.reason_category,
            Some(ReasonCategory::UnprovenSideEffect)
        );

        let unknown = classifier.classify("CALL app_read.unproven(:id)");
        assert_eq!(unknown.danger, DangerLevel::Forbidden);
        assert_eq!(
            unknown.reason_category,
            Some(ReasonCategory::UnprovenSideEffect)
        );

        let dynamic = classifier
            .classify("BEGIN app_read.lookup(:id); EXECUTE IMMEDIATE 'DROP TABLE target'; END;");
        assert_eq!(dynamic.danger, DangerLevel::Forbidden);
        assert_eq!(dynamic.reason_category, Some(ReasonCategory::DynamicSql));

        let quoted = classifier.classify("CALL \"app_read\".\"lookup\"(:id)");
        assert_eq!(quoted.danger, DangerLevel::Forbidden);
        assert_eq!(
            quoted.reason_category,
            Some(ReasonCategory::UnprovenSideEffect)
        );

        for sql in [
            "CALL app_read.lookup(app_admin.run_ddl)",
            "CALL app_read.lookup(dangerous_func)",
        ] {
            let hidden_argument = classifier.classify(sql);
            assert_eq!(hidden_argument.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(
                hidden_argument.reason_category,
                Some(ReasonCategory::UnprovenSideEffect),
                "callee proof cannot prove argument evaluation: {sql:?}"
            );
        }
    }

    #[test]
    fn semantic_proof_cannot_launder_owner_chains_or_database_links() {
        struct PackageMemberProof;
        impl SideEffectOracle for PackageMemberProof {
            fn routine_purity(&self, routine: &ObjectRef) -> Purity {
                if routine.schema.as_deref() == Some("pkg")
                    && routine.name.eq_ignore_ascii_case("run")
                {
                    Purity::ProvenReadOnly
                } else {
                    Purity::Unknown
                }
            }
        }
        let classifier = Classifier::default().with_oracle(Arc::new(PackageMemberProof));

        for sql in [
            "BEGIN trusted_owner.pkg.run(:id); END;",
            "BEGIN evil_owner.pkg.run(:id); END;",
            "BEGIN trusted_owner.pkg.run; END;",
            "BEGIN evil_owner.pkg.run; END;",
            "BEGIN pkg.run@trusted_link(:id); END;",
            "BEGIN pkg.run@evil_link; END;",
            "BEGIN run@evil_link; END;",
        ] {
            let decision = classifier.classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(
                decision.reason_category,
                Some(ReasonCategory::UnprovenSideEffect),
                "a two-part proof must not clear a richer identity: {sql:?}"
            );
        }

        let ambiguous_two_part = classifier.classify("CALL pkg.run(:id)");
        assert_eq!(ambiguous_two_part.danger, DangerLevel::Forbidden);
        assert_eq!(
            ambiguous_two_part.reason_category,
            Some(ReasonCategory::UnprovenSideEffect)
        );

        struct AllProof;
        impl SideEffectOracle for AllProof {
            fn routine_purity(&self, _routine: &ObjectRef) -> Purity {
                Purity::ProvenReadOnly
            }
        }
        let all_proven = Classifier::default().with_oracle(Arc::new(AllProof));
        for sql in [
            "BEGIN owner.pkg.run(:id); END;",
            "BEGIN owner.pkg.run; END;",
            "BEGIN pkg.run@evil_link(:id); END;",
            "BEGIN pkg.run@evil_link; END;",
            "BEGIN run@evil_link; END;",
            "CALL pkg.run@evil_link(:id)",
            "<<step>> CALL pkg.run(:id)",
            "CALL pkg.run(:id)",
            "CALL run(:id)",
        ] {
            let decision = all_proven.classify(sql);
            assert_eq!(
                decision.danger,
                DangerLevel::Forbidden,
                "even an all-accepting two-field oracle cannot prove a richer identity: {sql:?}"
            );
            assert_eq!(
                decision.reason_category,
                Some(ReasonCategory::UnprovenSideEffect),
                "{sql:?}"
            );
        }
    }

    #[test]
    fn pragma_syntax_is_not_misreported_as_a_routine_but_declare_fails_closed() {
        for sql in [
            "DECLARE e EXCEPTION; PRAGMA EXCEPTION_INIT(e, -20001); BEGIN NULL; END;",
            "DECLARE PROCEDURE p IS BEGIN NULL; END; PRAGMA INLINE(p, 'YES'); BEGIN NULL; END;",
            "DECLARE PROCEDURE p; PRAGMA RESTRICT_REFERENCES(p, WNDS); BEGIN NULL; END;",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert!(decision.objects_affected.is_empty(), "{sql:?}");
            assert!(
                !decision.reason.contains("EXCEPTION_INIT")
                    && !decision.reason.contains("RESTRICT_REFERENCES")
                    && !decision.reason.contains("INLINE"),
                "pragma syntax must not be misreported as a routine: {decision:?}"
            );
        }

        let real_call = classify("BEGIN exception_init(:code); END;");
        assert_eq!(
            real_call.reason_category,
            Some(ReasonCategory::UnprovenSideEffect)
        );
    }

    #[test]
    fn dbms_output_exception_requires_exact_sys_identity_and_safe_arguments() {
        let exact = classify("BEGIN SYS.DBMS_OUTPUT.PUT_LINE('hello' || :suffix); END;");
        assert_ne!(exact.danger, DangerLevel::Forbidden);
        assert_eq!(exact.required_level, Some(OperatingLevel::ReadWrite));

        for sql in [
            "BEGIN DBMS_OUTPUT.PUT_LINE('shadowable'); END;",
            "BEGIN APP.DBMS_OUTPUT.PUT_LINE('wrong owner'); END;",
            "BEGIN SYS.DBMS_OUTPUT.PUT_LINE@remote_db('remote'); END;",
            "BEGIN SYS.DBMS_OUTPUT.PUT_LINE(app_admin.message()); END;",
            "BEGIN SYS.DBMS_OUTPUT.PUT_LINE(app_admin.message); END;",
            "BEGIN SYS.DBMS_OUTPUT.PUT_LINE(local_value); END;",
            "CALL SYS.DBMS_OUTPUT.PUT_LINE(app_admin.message)",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(
                decision.reason_category,
                Some(ReasonCategory::UnprovenSideEffect),
                "{sql:?}"
            );
        }
    }

    #[test]
    fn reviewed_dbms_output_arguments_are_literals_binds_and_balanced_parens_only() {
        for segment in [
            "SYS.DBMS_OUTPUT.PUT_LINE(NULL)",
            "SYS.DBMS_OUTPUT.PUT_LINE(TRUE || ':' || FALSE)",
            "SYS.DBMS_OUTPUT.PUT_LINE(('hello' || :suffix) || 42)",
        ] {
            assert!(
                is_reviewed_dbms_output_statement(segment),
                "safe reviewed DBMS_OUTPUT segment should be admitted: {segment}"
            );
        }

        for expression in [
            "\"NULL\"",
            "('missing-close'",
            "'extra-close')",
            ":",
            ": suffix",
            ")(",
            "local_value",
            "app_admin.message",
            "app_admin.message()",
        ] {
            let tokens = oracle_tokens(expression);
            let refs = token_refs(&tokens);
            assert!(
                !tokens_are_literal_or_bind_expression(&refs),
                "unsafe expression must not be accepted as literal/bind-only: {expression}"
            );
        }

        for segment in [
            "SYS.WRONG_OUTPUT.PUT_LINE('x')",
            "SYS.DBMS_OUTPUT.GET_LINE('x')",
            "SYS.DBMS_OUTPUT.PUT_LINE",
            "SYS.DBMS_OUTPUT.PUT_LINE()",
            "SYS.DBMS_OUTPUT.PUT_LINE('x'",
            "SYS.DBMS_OUTPUT.PUT_LINE('x' || 'y'",
        ] {
            assert!(
                !is_reviewed_dbms_output_statement(segment),
                "near-miss DBMS_OUTPUT shape must fail closed: {segment}"
            );
        }
    }

    #[test]
    fn only_the_narrow_reviewed_engine_free_plsql_subset_is_admitted() {
        for sql in [
            "BEGIN NULL; END;",
            "BEGIN /* before */ NULL /* after */; END;",
            "BEGIN NULL; -- trailing note\n END;",
            "BEGIN -- before statement\n NULL; /* body note */ END;",
            "BEGIN SYS /* owner */ . DBMS_OUTPUT . PUT_LINE('hello' || :suffix); -- note\n END;",
        ] {
            let reviewed = classify(sql);
            assert_ne!(reviewed.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(
                reviewed.required_level,
                Some(OperatingLevel::ReadWrite),
                "{sql:?}"
            );
        }

        for sql in [
            "BEGIN UPDATE t SET x = ROUND(x), note = 'DBMS_UTILITY.EXEC_DDL_STATEMENT()' WHERE id = NVL(:id, 0); END;",
            "BEGIN :out := app_admin.run_ddl; END;",
            "BEGIN :out := dangerous_func; END;",
            "BEGIN IF app_admin.can_run THEN NULL; END IF; END;",
            "BEGIN WHILE app_admin.keep_running LOOP NULL; END LOOP; END;",
            "BEGIN rec.status := rec.previous_status; NULL; END;",
            "BEGIN note := 'DBMS_UTILITY.EXEC_DDL_STATEMENT()'; NULL; END;",
        ] {
            let decision = classify(sql);
            assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
            assert_eq!(
                decision.reason_category,
                Some(ReasonCategory::UnprovenSideEffect),
                "procedural expressions are ambiguous without semantic analysis: {sql:?}"
            );
        }
    }

    #[test]
    fn whitespace_or_comment_split_marker_is_still_forbidden() {
        // oracle-rwjl.1: a comment / extra space / tab / newline wedged between
        // the two keywords of a multi-word side-effect marker must NOT split it
        // and downgrade the Forbidden dynamic-SQL / autonomous-transaction block
        // to Guarded. The Stage A scan canonicalizes (comment-strip + whitespace
        // collapse + token-aware) before matching, so every evasion re-catches.
        for sql in [
            // EXECUTE IMMEDIATE separated by a block comment / double space / tab
            // / newline / line comment.
            "BEGIN EXECUTE/**/IMMEDIATE 'DELETE FROM orders'; END;",
            "BEGIN EXECUTE  IMMEDIATE 'DELETE FROM orders'; END;",
            "BEGIN EXECUTE\tIMMEDIATE 'DELETE FROM orders'; END;",
            "BEGIN EXECUTE\nIMMEDIATE 'DELETE FROM orders'; END;",
            "BEGIN EXECUTE --x\nIMMEDIATE 'DELETE FROM orders'; END;",
            // PRAGMA AUTONOMOUS_TRANSACTION likewise.
            "DECLARE PRAGMA/**/AUTONOMOUS_TRANSACTION; BEGIN COMMIT; END;",
            "DECLARE PRAGMA  AUTONOMOUS_TRANSACTION; BEGIN COMMIT; END;",
            "DECLARE PRAGMA\tAUTONOMOUS_TRANSACTION; BEGIN COMMIT; END;",
            "DECLARE PRAGMA\nAUTONOMOUS_TRANSACTION; BEGIN COMMIT; END;",
        ] {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Forbidden,
                "whitespace/comment-split marker must stay Forbidden: {sql:?}"
            );
            assert_eq!(d.required_level, None, "{sql:?}");
        }
    }

    #[test]
    fn marker_keywords_separated_by_punctuation_do_not_false_trigger() {
        // The contrapositive: two marker keywords separated by a *real* token
        // boundary (not just whitespace) must NOT be read as adjacent. A bare
        // block that merely mentions the words across statement boundaries — or
        // a quoted-identifier `"EXECUTE"` next to IMMEDIATE — is not a dynamic
        // EXECUTE IMMEDIATE and stays at most Guarded (still fail-closed for the
        // plain block, but never wrongly hard-Forbidden by a phantom marker).
        // EXECUTE and IMMEDIATE on opposite sides of a `;` are not adjacent.
        let d = classify("BEGIN x := EXECUTE; y := IMMEDIATE; END;");
        assert_eq!(d.danger, DangerLevel::Forbidden);
        assert_ne!(
            d.reason_category,
            Some(ReasonCategory::DynamicSql),
            "punctuation-separated words must not be misreported as EXECUTE IMMEDIATE"
        );
    }

    #[test]
    fn canonical_marker_scan_ignores_quoted_keyword_identifiers() {
        let scan = canonical_marker_scan(r#"BEGIN "EXECUTE" IMMEDIATE 'x'; END;"#);
        assert!(
            !scan.contains(" EXECUTE IMMEDIATE "),
            "quoted EXECUTE is data, not the EXECUTE IMMEDIATE marker: {scan:?}"
        );
        let dynamic = canonical_marker_scan("BEGIN EXECUTE IMMEDIATE 'x'; END;");
        assert!(dynamic.contains(" EXECUTE IMMEDIATE "), "{dynamic:?}");
    }

    #[test]
    fn literal_embedded_semicolon_is_not_a_boundary() {
        // 'a;b' contains a ; that is NOT a statement boundary; one SELECT.
        let shape = analyze_batch("SELECT 'a;b;c' FROM dual");
        assert!(shape.balanced);
        assert_eq!(shape.statement_count, 1);
    }

    #[test]
    fn q_quote_embedded_end_does_not_desync() {
        // The crafted q'{ … END; … }' that desynced the old literal-blind
        // counter is a single token here → balanced, one statement.
        let shape = analyze_batch("SELECT q'{ BEGIN END; }' FROM dual");
        assert!(
            shape.balanced,
            "q-quoted literal must not affect BEGIN/END depth"
        );
        assert_eq!(shape.statement_count, 1);
    }

    #[test]
    fn named_bind_placeholders_extracts_only_real_named_binds() {
        // Named binds: uppercased, de-duplicated, first-appearance order.
        assert_eq!(
            named_bind_placeholders("SELECT * FROM t WHERE a = :a AND b = :B AND a2 = :a"),
            vec!["A".to_owned(), "B".to_owned()]
        );
        // `::` casts and PL/SQL `:=` assignment are distinct tokens — never binds.
        assert!(named_bind_placeholders("SELECT col::text FROM t").is_empty());
        assert!(named_bind_placeholders("BEGIN x := 1; END;").is_empty());
        // Positional (`:1`) and quoted (`:\"x\"`) binds are not simple named binds.
        assert!(named_bind_placeholders("SELECT :1 FROM dual").is_empty());
        assert!(named_bind_placeholders("SELECT :\"x\" FROM dual").is_empty());
        // Colons inside string / q-quote / national literals, quoted identifiers,
        // and line/block comments never register as binds.
        assert!(
            named_bind_placeholders(
                "SELECT 'a:b', q'{c:d}', n'e:f', \"g:h\" FROM t -- :i\n/* :j */"
            )
            .is_empty()
        );
        // A colon separated from its name by whitespace is not a bind (Oracle
        // requires the name glued to the colon).
        assert!(named_bind_placeholders("SELECT : x FROM dual").is_empty());
        // A tokenizer failure (unterminated literal) is fail-closed: no binds.
        assert!(named_bind_placeholders("SELECT 'unterminated :x").is_empty());
    }

    #[test]
    fn quoted_keyword_identifier_does_not_move_block_depth() {
        // A double-quoted identifier like "BEGIN"/"END" is a column name, NOT a
        // PL/SQL structural keyword, so it must never move the fail-closed desync
        // counter. Before the quote_style fix, the quoted "BEGIN" inflated depth so
        // the stray top-level END netted back to 0 and the batch was wrongly
        // downgraded from Forbidden to Guarded.
        // Baseline: a bare stray top-level END desyncs → Forbidden.
        assert_eq!(
            classify("SELECT 1 FROM dual; END;").danger,
            DangerLevel::Forbidden
        );
        // Regression: the quoted "BEGIN" must NOT balance the stray END.
        let shape = analyze_batch(r#"SELECT "BEGIN" FROM dual; END;"#);
        assert!(
            !shape.balanced,
            "quoted \"BEGIN\" must not balance the stray top-level END"
        );
        assert_eq!(
            classify(r#"SELECT "BEGIN" FROM dual; END;"#).danger,
            DangerLevel::Forbidden,
            "quoted keyword identifiers must not defeat the fail-closed desync law"
        );
    }

    #[test]
    fn keyword_collision_alias_cannot_hide_a_destructive_boundary() {
        // oracle-73t1.1: a bare unquoted word that collides with a PL/SQL
        // structural keyword (LOOP/IF/CASE/BEGIN), used as a column alias in
        // pure SQL, must NOT inflate the block-depth counter and swallow the
        // real top-level `;` boundaries. Before the fix, `loop` pushed depth to
        // 1, the two inner `;` were counted as nested (uncounted), a trailing
        // top-level END netted depth back to 0 (balanced=true, count=1), and the
        // whole batch — hiding a DROP TABLE — collapsed to a single Guarded
        // statement, defeating the fail-closed desync law and the Destructive
        // step-up gate.
        for alias in ["loop", "if", "case", "begin"] {
            let sql = format!("SELECT 1 AS {alias} FROM dual; DROP TABLE orders; END;");
            let shape = analyze_batch(&sql);
            assert!(
                shape.saw_buried_semicolon,
                "keyword-collision alias `{alias}` inflated depth and buried a top-level `;`: {sql:?} -> {shape:?}"
            );
            assert_eq!(
                classify(&sql).danger,
                DangerLevel::Forbidden,
                "a keyword-alias batch hiding DROP TABLE must be Forbidden, never Guarded: {sql:?}"
            );
        }
        // Control: the SAME batch with a non-keyword alias has both `;` at
        // depth 0, splits cleanly into two statements, and surfaces the DROP as
        // Destructive (never collapses to a single Guarded statement).
        let control = classify("SELECT 1 AS foo FROM dual; DROP TABLE orders");
        assert_eq!(
            control.danger,
            DangerLevel::Destructive,
            "non-keyword alias must still surface the DROP as Destructive"
        );
        // Control: a genuine balanced SQL CASE with no buried `;` stays balanced
        // with no buried boundary (the fix must not over-trigger on legitimate
        // CASE expressions).
        let ok = analyze_batch("SELECT CASE WHEN x = 1 THEN 'a' ELSE 'b' END FROM dual");
        assert!(
            ok.balanced && !ok.saw_buried_semicolon && ok.statement_count == 1,
            "a legitimate balanced CASE with no buried `;` must stay balanced: {ok:?}"
        );
    }

    #[test]
    fn buried_semicolon_in_pure_sql_case_is_forbidden() {
        // oracle-73t1.5: a malformed batch whose unbalanced SQL CASE/IF/LOOP
        // hides a top-level `;` boundary (no BEGIN/DECLARE anywhere) must fail
        // closed to Forbidden, not be downgraded to Guarded/ReadWrite. The `;`
        // nested at depth > 0 in a pure-SQL context is illegitimate — it can
        // only be a swallowed top-level boundary.
        for payload in [
            "SELECT CASE WHEN 1=1 THEN 1 FROM dual ; DROP TABLE t END",
            "SELECT CASE WHEN 1=1 THEN 1 FROM dual ; GRANT DBA TO scott END",
            "SELECT CASE WHEN 1=1 THEN 1 FROM dual ; TRUNCATE TABLE t END",
        ] {
            let shape = analyze_batch(payload);
            assert!(
                shape.saw_buried_semicolon,
                "a buried `;` inside a pure-SQL CASE must be detected: {payload:?} -> {shape:?}"
            );
            assert_eq!(
                classify(payload).danger,
                DangerLevel::Forbidden,
                "a buried-`;` CASE desync must be Forbidden (fail-closed law): {payload:?}"
            );
        }
        // Control: a VALID balanced CASE in a multi-statement batch still splits
        // cleanly and surfaces the trailing DROP as Destructive — legitimate
        // multi-statement detection must not regress.
        let control = classify("SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END FROM dual; DROP TABLE t");
        assert_eq!(
            control.danger,
            DangerLevel::Destructive,
            "a balanced CASE followed by a real top-level DROP must still be Destructive"
        );
        // Control: a buried `;` inside a *real* PL/SQL block (StageA routes it
        // via PlSqlBlock, not PureSql) is a legitimate nested statement
        // terminator — the buried-`;` desync rule only fires on the PureSql path.
        // The shape stays balanced, while the independent semantic-completeness
        // rule now refuses the caller PL/SQL block.
        let plsql = analyze_batch("BEGIN UPDATE t SET x = 1 WHERE id = 2; END;");
        assert!(
            plsql.balanced,
            "a `;` nested in a real BEGIN..END block must stay depth-balanced: {plsql:?}"
        );
        assert_eq!(
            classify("BEGIN UPDATE t SET x = 1 WHERE id = 2; END;").danger,
            DangerLevel::Forbidden,
            "balanced shape alone cannot prove PL/SQL name resolution"
        );
    }

    #[test]
    fn trailing_sql_after_block_close_is_forbidden() {
        // oracle-lokg.1: a *balanced* anonymous block followed by trailing
        // top-level SQL after `END` (`BEGIN NULL; END; GRANT DBA TO scott`)
        // rebalances the BEGIN/END depth counter back to 0, so the old
        // StageA::PlSqlBlock arm — which consulted only `shape.balanced` — silently
        // classified the whole batch as a single Guarded/ReadWrite block and DROPPED
        // the trailing GRANT/DROP/TRUNCATE from classification. A ReadWrite-elevated
        // session (whose ceiling reaches Admin) would then Allow the
        // privilege-escalation DCL/DDL with NO Admin/DDL step-up. It must fail closed.
        //
        // A session whose ceiling is Admin, currently elevated only to ReadWrite —
        // the exact escalation the bead describes (layer B is off at ReadWrite, so
        // the classifier is the active gate).
        let mut session = SessionLevelState::new(OperatingLevel::Admin, false);
        session
            .set_current_level(OperatingLevel::ReadWrite)
            .expect("step current level to ReadWrite");
        for sql in [
            "BEGIN NULL; END; GRANT DBA TO scott",
            "BEGIN NULL; END; DROP TABLE orders",
            "BEGIN UPDATE t SET x=1 WHERE id=2; END; TRUNCATE TABLE orders",
            // The trailing SQL after a SQL*Plus `/` terminator is still smuggled
            // top-level SQL that the depth counter rebalances away.
            "BEGIN NULL; END;\n/\nDROP TABLE orders",
        ] {
            let shape = analyze_batch(sql);
            assert!(
                shape.saw_top_level_after_block_close,
                "trailing top-level SQL after END must be detected: {sql:?} -> {shape:?}"
            );
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Forbidden,
                "a block followed by trailing top-level SQL must be Forbidden, never \
                 Guarded: {sql:?} -> {d:?}"
            );
            assert_ne!(
                d.gate(&session),
                LevelDecision::Allow,
                "a ReadWrite-elevated session must NOT Allow a block hiding trailing \
                 DCL/DDL: {sql:?}"
            );
            assert_eq!(
                d.gate(&session),
                LevelDecision::Blocked {
                    reason: BlockReason::Forbidden
                },
                "the trailing-SQL block must gate to Blocked(Forbidden): {sql:?}"
            );
        }

        // Distinguishability controls (a naive fix that keyed only on
        // statement_count / saw_buried_semicolon would regress every one of these):
        // Legitimate single anonymous-block SHAPES — including a leading
        // `DECLARE … ;` section and SQL*Plus `/` terminators — must not be
        // misreported as trailing SQL. The independent semantic-completeness
        // policy may still refuse DECLARE or wrapped DML.
        for sql in [
            "DECLARE x NUMBER; BEGIN x := 1; END;",
            "BEGIN NULL; END;",
            "BEGIN UPDATE t SET x=1 WHERE id=2; END;",
            "BEGIN NULL; END; /",
            "BEGIN NULL; END;\n/",
        ] {
            let shape = analyze_batch(sql);
            assert!(
                shape.balanced && !shape.saw_top_level_after_block_close,
                "a legitimate single block (incl. trailing `/`) must not be flagged \
                 as trailing-after-END: {sql:?} -> {shape:?}"
            );
            let d = classify(sql);
            let reviewed_noop = !sql.starts_with("DECLARE") && !sql.contains("UPDATE");
            if reviewed_noop {
                assert_eq!(d.danger, DangerLevel::Guarded, "{sql:?} -> {d:?}");
                assert_eq!(d.required_level, Some(OperatingLevel::ReadWrite));
                assert_eq!(d.gate(&session), LevelDecision::Allow);
            } else {
                assert_eq!(d.danger, DangerLevel::Forbidden, "{sql:?} -> {d:?}");
                assert_eq!(
                    d.gate(&session),
                    LevelDecision::Blocked {
                        reason: BlockReason::Forbidden
                    }
                );
            }
        }
    }

    #[test]
    fn unbalanced_block_is_forbidden() {
        // A BEGIN with no matching END desyncs → Forbidden.
        let d = classify("DECLARE x NUMBER; BEGIN x := 1;");
        assert_eq!(d.danger, DangerLevel::Forbidden);
    }

    #[test]
    fn analyze_batch_reports_declare_and_stray_end_directly() {
        let declare = analyze_batch("DECLARE x NUMBER; BEGIN x := 1; END;");
        assert!(declare.has_plsql_block, "{declare:?}");
        assert!(declare.balanced, "{declare:?}");

        let stray = analyze_batch("END;");
        assert!(
            !stray.balanced,
            "a top-level END must make the batch unbalanced: {stray:?}"
        );
    }

    #[test]
    fn unanalyzable_plsql_construct_keeps_shape_and_declare_refusals_distinct() {
        assert_eq!(
            unanalyzable_plsql_construct("BEGIN NULL;"),
            None,
            "unbalanced PL/SQL shape is handled by the stronger structural refusal"
        );
        assert_eq!(
            unanalyzable_plsql_construct("DECLARE x NUMBER; BEGIN NULL; END;"),
            Some("DECLARE section without complete semantic analysis")
        );
    }

    #[test]
    fn block_list_regex_forbids() {
        let cfg = ClassifierConfig::new().with_block_pattern("(?i)drop\\s+table");
        let d = Classifier::new(cfg).classify("DROP TABLE orders");
        assert_eq!(d.danger, DangerLevel::Forbidden);
    }

    #[test]
    fn allow_list_clears_to_safe() {
        let sql = "SELECT billing.weird_udf() FROM dual";
        let cfg = ClassifierConfig::new().with_allow(sql);
        let d = Classifier::new(cfg).classify(sql);
        assert_eq!(d.danger, DangerLevel::Safe);
        let changed = Classifier::new(ClassifierConfig::new().with_allow(sql))
            .classify("select billing.weird_udf() from dual");
        assert_ne!(changed.danger, DangerLevel::Safe);
    }

    #[test]
    fn allow_list_hash_is_stable_and_exact() {
        let a = exact_sha256("SELECT * FROM dual");
        let b = exact_sha256("SELECT * FROM dual");
        let c = exact_sha256("select * from dual");
        assert_eq!(a, b, "identical statement bytes must have a stable digest");
        assert_ne!(
            a, c,
            "case-different SQL must not share an authorization digest"
        );
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn allow_list_does_not_collapse_semantic_whitespace() {
        let approved = "UPDATE \"A  B\" SET x = 1";
        let different_object = "UPDATE \"A B\" SET x = 1";
        assert_ne!(
            exact_sha256(approved),
            exact_sha256(different_object),
            "quoted identifiers with different whitespace name different Oracle objects"
        );
        assert_eq!(
            stage_a(
                different_object,
                &ClassifierConfig::new().with_allow(approved)
            ),
            StageA::PureSql,
            "an allow-list entry must authorize only the reviewed statement"
        );
    }

    #[test]
    fn populated_allow_list_does_not_clear_other_statements() {
        let cfg = ClassifierConfig::new().with_allow("SELECT 1 FROM dual");
        let d = Classifier::new(cfg).classify("SELECT billing.side_effect() FROM dual");
        assert_eq!(
            d.danger,
            DangerLevel::Guarded,
            "a nonmatching statement must not be allowed merely because the allow-list is nonempty"
        );
    }

    #[test]
    fn multi_statement_takes_the_max_danger() {
        let d = classify("SELECT 1 FROM dual; DROP TABLE orders");
        assert_eq!(d.danger, DangerLevel::Destructive);
        assert_eq!(d.required_level, Some(OperatingLevel::Ddl));
    }

    #[test]
    fn qualified_udf_call_classify_path_stays_guarded() {
        // The schema-qualified UDF detection path in `user_defined_calls` (the
        // one that extracts the schema word from `toks[i - 3]`) must keep
        // surfacing the call as a Guarded routine candidate. The schema-word
        // extraction was hardened from `unreachable!()` to a fail-closed
        // fallback; the fallback still PUSHES the call, so an unexpected token
        // state flags Guarded rather than unwinding out of classification or
        // fail-opening to Safe. Default oracle (Unknown purity) ⇒ a qualified
        // UDF call is Guarded.
        let d = classify("SELECT billing.weird_udf(x) FROM dual");
        assert_eq!(d.danger, DangerLevel::Guarded);
        assert!(
            d.objects_affected
                .iter()
                .any(|o| o.to_ascii_lowercase().contains("weird_udf")),
            "the qualified routine call should be surfaced"
        );
        // The bare-name builtin filter still applies when NOT qualified.
        let safe = classify("SELECT ROUND(x) FROM dual");
        assert_eq!(safe.danger, DangerLevel::Safe);
    }

    #[test]
    fn user_defined_calls_preserves_schema_on_qualified_calls() {
        let calls = user_defined_calls(
            "SELECT billing.purge_old_rows(x), ROUND(x) FROM dual",
            false,
        );
        assert!(
            calls.iter().any(|call| {
                call.schema.as_deref() == Some("billing")
                    && call.name.eq_ignore_ascii_case("purge_old_rows")
            }),
            "schema-qualified UDF should preserve schema and routine name: {calls:?}"
        );
        let later_calls = user_defined_calls(
            "SELECT id, status, billing.purge_old_rows(x) FROM dual",
            false,
        );
        assert!(
            later_calls.iter().any(|call| {
                call.schema.as_deref() == Some("billing")
                    && call.name.eq_ignore_ascii_case("purge_old_rows")
            }),
            "schema extraction must look three tokens behind the call paren, not at an \
             index-derived earlier token: {later_calls:?}"
        );
        assert!(
            !calls
                .iter()
                .any(|call| call.name.eq_ignore_ascii_case("round")),
            "bare builtins must not be reported as user-defined calls: {calls:?}"
        );
    }

    #[test]
    fn block_interior_segments_split_only_outer_body_statements() {
        let segments = block_interior_segments(
            "BEGIN IF x = 1 THEN UPDATE t SET x = 1 WHERE id = 1; END IF; DELETE FROM t; END;",
        );
        assert_eq!(segments.len(), 2, "{segments:?}");
        assert!(
            segments[0].contains("IF") && segments[0].contains("END IF"),
            "nested control-flow segment stays intact: {segments:?}"
        );
        assert!(
            segments[1].to_ascii_uppercase().contains("DELETE FROM T"),
            "outer body DELETE is split as its own segment: {segments:?}"
        );
    }

    #[test]
    fn decision_gates_against_session_level() {
        let session = SessionLevelState::new(OperatingLevel::ReadOnly, true);
        // A write on a protected READ_ONLY session is hard-blocked.
        let d = classify("INSERT INTO t (a) VALUES (1)");
        assert!(matches!(d.gate(&session), LevelDecision::Blocked { .. }));
        // A read is allowed.
        let read = classify("SELECT 1 FROM dual");
        assert_eq!(read.gate(&session), LevelDecision::Allow);
    }
}
