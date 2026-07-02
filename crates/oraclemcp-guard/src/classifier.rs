//! The fail-closed, engine-aware statement classifier (plan §5.3; bead P1-1 +
//! P1-1a..f). This is the safety spine: it replaces a fail-OPEN string
//! predicate with a staged, fail-CLOSED classifier.
//!
//! Pipeline (per call):
//! 1. **Stage A** ([`stage_a`]) — operator allow-list (SHA-256 of normalized
//!    text) → block-list (regex) → PL/SQL-block detector. (P1-1a)
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

use std::collections::HashSet;
use std::sync::Arc;

use regex::Regex;
use sha2::{Digest, Sha256};
use sqlparser::dialect::OracleDialect;
use sqlparser::keywords::Keyword;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};

use crate::levels::{DangerLevel, LevelDecision, OperatingLevel, SessionLevelState};
use crate::purity::{ObjectRef, Purity, SideEffectOracle, UnknownOracle};

/// What the guard decided about a statement batch (before the level gate).
#[derive(Clone, Debug, PartialEq, Eq)]
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
}

impl GuardDecision {
    /// Gate the decision against a session's operating level (wires P1-1 into
    /// the P0-7 level core): classification runs *before* the step-up gate, so
    /// the required level is known when compared to the session's current level.
    #[must_use]
    pub fn gate(&self, session: &SessionLevelState) -> LevelDecision {
        session.evaluate(self.required_level)
    }
}

/// Operator-curated classifier configuration. The allow-list and block-list are
/// the operator's responsibility; neither weakens the fail-closed law for
/// anything they do not explicitly name.
#[derive(Clone, Default)]
pub struct ClassifierConfig {
    /// SHA-256 (hex) of normalized text that is pre-approved as `Safe`.
    allow_list: HashSet<String>,
    /// Regexes that, if matched, force `Forbidden`.
    block_patterns: Vec<Regex>,
}

impl ClassifierConfig {
    /// An empty config (no allow/block entries).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-approve a statement's normalized text as `Safe`.
    #[must_use]
    pub fn with_allow(mut self, sql: &str) -> Self {
        self.allow_list.insert(normalized_sha256(sql));
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

/// Normalize SQL for allow-list hashing: trim, collapse internal whitespace,
/// lowercase. (Whitespace/case-insensitive; semantics-preserving for the hash.)
fn normalized_sha256(sql: &str) -> String {
    let normalized = sql
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let digest = Sha256::digest(normalized.as_bytes());
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
    "DBMS_SCHEDULER",
    "DBMS_JOB",
    "PRAGMA AUTONOMOUS_TRANSACTION",
];

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
    "ALTER SYSTEM ",
    "ALTER DATABASE ",
    "ALTER PROFILE ",
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
    LEADING_DDL_VERBS.iter().any(|v| leading.starts_with(v))
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
    // Skip the normalize + SHA-256 + hex hash entirely when there is nothing to
    // match against (the default: no operator-configured allow-list). An empty
    // set can never contain the digest, so this short-circuit is behavior-
    // identical yet removes the per-statement hashing cost on the hot path.
    if !config.allow_list.is_empty() && config.allow_list.contains(&normalized_sha256(sql)) {
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
    // `scan` is `" TOK1 TOK2 … "`; strip the leading pad so a leading marker
    // sits at offset 0 and the trailing space in each pattern enforces a word
    // boundary, exactly as the admin/DDL leading-verb scans do.
    let leading = scan.strip_prefix(' ').unwrap_or(&scan);
    // Only PL/SQL-bearing CREATE forms take the fail-closed PL/SQL-block path;
    // pure-DDL replace forms fall through so Stage B / the DDL floor tiers them
    // Destructive/Ddl rather than under-levelling them to Guarded/ReadWrite (see
    // [`PLSQL_BEARING_CREATE_FORMS`] — oracle-y54x.1).
    let starts_block = upper.starts_with("DECLARE")
        || upper.starts_with("BEGIN")
        || sql.trim() == "/"
        || PLSQL_BEARING_CREATE_FORMS
            .iter()
            .any(|f| leading.starts_with(f));
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
    let mut depth: i64 = 0;
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
    // `END IF` / `END LOOP` / `END CASE` close one opener: the `END` decrements
    // and the trailing IF/LOOP/CASE must NOT re-increment. `expecting_close`
    // tracks "previous significant token was END" (whitespace does not reset it).
    let mut expecting_close = false;
    for token in &tokens {
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
                // A bare word at depth 0 *after* a block body opened and closed is
                // trailing top-level SQL smuggled after `END` (oracle-lokg.1). This
                // is evaluated against the depth *before* this token's own
                // structural effect, so a re-opening `BEGIN` (a second stacked
                // block) is caught too; a stray top-level `END` is already a desync
                // via `went_negative`.
                if block_body_opened && depth == 0 {
                    saw_top_level_after_block_close = true;
                }
                match keyword.as_deref() {
                    Some("BEGIN") => {
                        depth += 1;
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
                        depth -= 1;
                        if depth < 0 {
                            went_negative = true;
                        }
                        expecting_close = true;
                    }
                    _ => expecting_close = false,
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
                } else {
                    // A `;` nested inside CASE/IF/LOOP/BEGIN depth. Only a real
                    // PL/SQL block (StageA::PlSqlBlock) can legitimately carry a
                    // nested statement-terminator `;`; the pure-SQL caller treats
                    // this as a hidden top-level boundary the counter swallowed
                    // and forces Forbidden.
                    saw_buried_semicolon = true;
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
                expecting_close = false;
            }
            _ => {
                // Any other significant token (punctuation, operator, literal,
                // number, string) at depth 0 after a block body has opened and
                // closed is trailing top-level SQL after `END` (oracle-lokg.1).
                if block_body_opened && depth == 0 {
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
        balanced: depth == 0 && !went_negative,
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
}

impl StatementClass {
    fn forbidden() -> Self {
        StatementClass {
            danger: DangerLevel::Forbidden,
            required: None,
            objects: Vec::new(),
        }
    }
}

/// Known Oracle SQL built-in functions that are pure (never trigger the UDF
/// purity consult). Anything *not* here that is called as `ident(` is treated
/// as a user-defined function → consult the oracle (default `Unknown`).
fn is_builtin_function(name: &str) -> bool {
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
    ];
    BUILTINS.contains(&name.to_ascii_lowercase().as_str())
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
fn user_defined_calls(sql: &str) -> Vec<ObjectRef> {
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
            if is_qualified || !is_builtin_function(&fname) {
                calls.push(ObjectRef::new(schema, fname));
            }
        }
    }
    calls
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

/// Walk a `Query`'s FROM/JOIN/CTE structure and collect the **base objects**
/// (real tables/views named in `FROM`/`JOIN` factors and inside CTE bodies and
/// derived subqueries). CTE *alias* names are not base objects, so a `FROM cte`
/// reference is filtered out (its body's base tables are already collected).
///
/// This is the resolved-object set the engine's [`SideEffectOracle::statement_purity`]
/// trigger/VPD walk runs over (a `SELECT`/DML can fire a side-effecting trigger
/// or row-level-security policy function the statement text never names).
/// Best-effort + fail-closed: missing a factor only *omits* an object (it can
/// never invent a `ProvenReadOnly`), and over-collection only adds objects the
/// oracle is free to report `ProvenSideEffecting`.
fn query_base_objects(query: &sqlparser::ast::Query) -> Vec<ObjectRef> {
    use sqlparser::ast::{SetExpr, TableFactor};

    let mut objects: Vec<ObjectRef> = Vec::new();
    let mut cte_aliases: HashSet<String> = HashSet::new();

    fn collect_factor(
        factor: &TableFactor,
        objects: &mut Vec<ObjectRef>,
        cte_aliases: &HashSet<String>,
    ) {
        match factor {
            TableFactor::Table { name, .. } => {
                if let Some(obj) = object_name_to_ref(name) {
                    // A single-part name that matches a CTE alias is a CTE
                    // reference, not a base table.
                    let is_cte_ref = obj.schema.is_none()
                        && cte_aliases.contains(&obj.name.to_ascii_lowercase());
                    if !is_cte_ref {
                        objects.push(obj);
                    }
                }
            }
            TableFactor::Derived { subquery, .. } => {
                collect_query(subquery, objects, cte_aliases);
            }
            // Table functions, UNNEST, JSON_TABLE, pivots, etc. name no base
            // table (or are handled via the UDF/routine consult) — skip.
            _ => {}
        }
    }

    fn collect_set_expr(
        body: &SetExpr,
        objects: &mut Vec<ObjectRef>,
        cte_aliases: &HashSet<String>,
    ) {
        match body {
            SetExpr::Select(select) => {
                for twj in &select.from {
                    collect_factor(&twj.relation, objects, cte_aliases);
                    for join in &twj.joins {
                        collect_factor(&join.relation, objects, cte_aliases);
                    }
                }
            }
            SetExpr::Query(q) => collect_query(q, objects, cte_aliases),
            SetExpr::SetOperation { left, right, .. } => {
                collect_set_expr(left, objects, cte_aliases);
                collect_set_expr(right, objects, cte_aliases);
            }
            // VALUES / TABLE / nested INSERT|UPDATE|DELETE|MERGE bodies name no
            // SELECT base table here (DML arms are classified separately).
            _ => {}
        }
    }

    fn collect_query(
        query: &sqlparser::ast::Query,
        objects: &mut Vec<ObjectRef>,
        cte_aliases: &HashSet<String>,
    ) {
        let mut local_aliases = cte_aliases.clone();
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                local_aliases.insert(cte.alias.name.value.to_ascii_lowercase());
            }
            for cte in &with.cte_tables {
                collect_query(&cte.query, objects, &local_aliases);
            }
        }
        collect_set_expr(&query.body, objects, &local_aliases);
    }

    // Seed top-level CTE aliases, then walk.
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            cte_aliases.insert(cte.alias.name.value.to_ascii_lowercase());
        }
    }
    collect_query(query, &mut objects, &cte_aliases);

    // Deduplicate while preserving order (small N; readability over a HashSet).
    let mut seen: HashSet<(Option<String>, String)> = HashSet::new();
    objects.retain(|o| seen.insert((o.schema.clone(), o.name.clone())));
    objects
}

/// Classify a single pre-split, pure-SQL statement (Stage B + purity consult).
fn classify_statement(
    sql: &str,
    oracle: &dyn SideEffectOracle,
    statement_unknown_guarded: bool,
) -> StatementClass {
    use sqlparser::ast::Statement;
    let dialect = OracleDialect {};
    let parsed = match Parser::parse_sql(&dialect, sql) {
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
            };
        }
    };
    let guarded_rw = |objects: Vec<String>| StatementClass {
        danger: DangerLevel::Guarded,
        required: Some(OperatingLevel::ReadWrite),
        objects,
    };
    let destructive = |level: OperatingLevel, objects: Vec<String>| StatementClass {
        danger: DangerLevel::Destructive,
        required: Some(level),
        objects,
    };
    match parsed {
        Statement::Query(ref query) => {
            // SELECT/WITH: Safe only if it calls no unproven user-defined
            // function (R15). Any UDF not ProvenReadOnly → Guarded.
            let calls = user_defined_calls(sql);
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
                || (statement_unknown_guarded && matches!(stmt_purity, Purity::Unknown));
            // `SELECT … FOR UPDATE` (incl. OF/NOWAIT/SKIP LOCKED) takes row
            // locks and holds a transaction open — levels.rs:93 documents it as
            // Guarded, never Safe. The AST carries `query.locks`; a non-empty
            // lock list forces the guarded branch (oracle-ajm2.6).
            let has_row_lock = !query.locks.is_empty();
            let stmt_pure = (calls.is_empty() || all_proven) && !stmt_blocks_safe && !has_row_lock;
            let mut objects: Vec<String> = calls.iter().map(|c| c.name.clone()).collect();
            if stmt_pure {
                StatementClass {
                    danger: DangerLevel::Safe,
                    required: Some(OperatingLevel::ReadOnly),
                    objects,
                }
            } else {
                if stmt_blocks_safe {
                    objects.extend(base_objects.iter().map(|o| o.name.clone()));
                }
                guarded_rw(objects)
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
        },
        // DROP USER / DROP ROLE is account/role administration (cross-schema
        // DCL, levels.rs:37), NOT ordinary object DDL — it requires Admin, not
        // Ddl. Other DROPs (TABLE/VIEW/INDEX/…) stay Ddl (oracle-clgt.3).
        Statement::Drop {
            object_type: sqlparser::ast::ObjectType::User | sqlparser::ast::ObjectType::Role,
            ..
        } => destructive(OperatingLevel::Admin, Vec::new()),
        // DDL.
        Statement::CreateTable(_)
        | Statement::CreateView { .. }
        | Statement::CreateIndex(_)
        | Statement::AlterTable { .. }
        | Statement::Drop { .. }
        | Statement::Truncate { .. } => destructive(OperatingLevel::Ddl, Vec::new()),
        // DCL / admin: GRANT/REVOKE, role creation/alteration, and SET ROLE all
        // touch the privilege model and require Admin. CREATE ROLE parses to
        // Statement::CreateRole, ALTER ROLE to Statement::AlterRole, and
        // `SET [SESSION|LOCAL] ROLE …` to Statement::Set(Set::SetRole) — all
        // previously fell through to the catch-all and under-levelled to
        // ReadWrite, letting a ReadWrite-elevated session enable a write-bearing
        // role post-connect (oracle-clgt.3 / oracle-clgt.13).
        Statement::Grant { .. }
        | Statement::Revoke { .. }
        | Statement::CreateRole(_)
        | Statement::AlterRole { .. } => destructive(OperatingLevel::Admin, Vec::new()),
        Statement::Set(sqlparser::ast::Set::SetRole { .. }) => {
            destructive(OperatingLevel::Admin, Vec::new())
        }
        // Standalone transaction control is Guarded (lease-bound).
        Statement::Commit { .. } | Statement::Rollback { .. } | Statement::Savepoint { .. } => {
            guarded_rw(Vec::new())
        }
        // Anything else recognized but not explicitly safe → fail-closed Guarded.
        _ => guarded_rw(Vec::new()),
    }
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

    /// Classify a statement / batch into a [`GuardDecision`], fail-closed.
    #[must_use]
    pub fn classify(&self, sql: &str) -> GuardDecision {
        let trimmed = sql.trim();
        if trimmed.is_empty() {
            return GuardDecision {
                danger: DangerLevel::Safe,
                required_level: Some(OperatingLevel::ReadOnly),
                objects_affected: Vec::new(),
                safe_alternative: None,
                reason: "empty input".to_owned(),
            };
        }

        match stage_a(sql, &self.config) {
            StageA::AllowListed => {
                return GuardDecision {
                    danger: DangerLevel::Safe,
                    required_level: Some(OperatingLevel::ReadOnly),
                    objects_affected: Vec::new(),
                    safe_alternative: None,
                    reason: "operator allow-listed".to_owned(),
                };
            }
            StageA::BlockListed(pat) => {
                return forbidden_decision(format!("matched block-list pattern: {pat}"));
            }
            StageA::PlSqlBlock { dangerous } => {
                // Any PL/SQL block is at minimum Guarded; a dangerous
                // side-effect marker (EXECUTE IMMEDIATE / UTL_FILE / …) is
                // Forbidden (fail-closed — we cannot prove its purity here).
                if dangerous {
                    return forbidden_decision(
                        "PL/SQL block contains a dynamic-SQL / file / network / scheduler side-effect marker".to_owned(),
                    );
                }
                let shape = analyze_batch(sql);
                if !shape.balanced {
                    return forbidden_decision(
                        "PL/SQL block has unbalanced BEGIN/END (desync) — fail-closed".to_owned(),
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
                    );
                }
                return GuardDecision {
                    danger: DangerLevel::Guarded,
                    required_level: Some(OperatingLevel::ReadWrite),
                    objects_affected: Vec::new(),
                    safe_alternative: Some(
                        "wrap the logic in an analysable package and call it, or run pure SQL"
                            .to_owned(),
                    ),
                    reason: "PL/SQL block (cannot be proven side-effect-free here)".to_owned(),
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
            );
        }

        // Classify each statement; the batch danger is the max, and any
        // Forbidden sub-statement rejects the whole batch.
        let classes: Vec<StatementClass> = if shape.statement_count <= 1 {
            vec![classify_statement(
                sql,
                self.oracle.as_ref(),
                self.statement_unknown_guarded,
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
                            self.statement_unknown_guarded,
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
            return forbidden_decision("a sub-statement is Forbidden".to_owned());
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
        GuardDecision {
            danger,
            required_level,
            objects_affected,
            safe_alternative: None,
            reason: format!(
                "classified {} statement(s) as {danger:?}",
                shape.statement_count.max(1)
            ),
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::levels::BlockReason;

    fn classify(sql: &str) -> GuardDecision {
        Classifier::default().classify(sql)
    }

    #[test]
    fn plain_select_is_safe() {
        let d = classify("SELECT id, name FROM employees WHERE id = 42");
        assert_eq!(d.danger, DangerLevel::Safe);
        assert_eq!(d.required_level, Some(OperatingLevel::ReadOnly));
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
    fn plsql_bearing_create_still_takes_block_path() {
        // The narrowing must not stop PL/SQL-bearing creates from being
        // side-effect-scanned. A clean CREATE OR REPLACE PROCEDURE stays on the
        // PL/SQL-block path (Guarded/ReadWrite); one carrying a dynamic-SQL marker
        // must still fail closed to Forbidden — even with inter-keyword spacing.
        let clean = classify("CREATE OR REPLACE PROCEDURE p IS BEGIN NULL; END;");
        assert_eq!(
            clean.danger,
            DangerLevel::Guarded,
            "clean proc → block path"
        );
        assert_eq!(clean.required_level, Some(OperatingLevel::ReadWrite));

        let dynamic = classify(
            "CREATE  OR  REPLACE  PROCEDURE p IS BEGIN EXECUTE IMMEDIATE 'DROP TABLE t'; END;",
        );
        assert_eq!(
            dynamic.danger,
            DangerLevel::Forbidden,
            "a dynamic-SQL-bearing proc body must fail closed regardless of spacing"
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
    fn alter_session_classifies_guarded_readwrite_matching_doc() {
        // oracle-clgt.13: locks the enforcement.rs module doc to reality. ALTER
        // SESSION SET <param> does NOT parse under sqlparser's OracleDialect, so
        // it falls through the parse-failure branch to Guarded/ReadWrite — it is
        // NOT classified Admin (it is not a leading admin verb) and NOT Forbidden,
        // and the ALTER SESSION allowlist is never consulted on the classify path.
        // A READ_ONLY session must step up; a READ_WRITE session is Allowed.
        let read_only = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        let mut read_write = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        read_write
            .set_current_level(OperatingLevel::ReadWrite)
            .expect("step to ReadWrite");
        for sql in [
            // Non-allowlisted (security/trace) AND allowlisted params both behave
            // identically on the classify path — the allowlist is not consulted.
            "ALTER SESSION SET SQL_TRACE = TRUE",
            "ALTER SESSION SET CURRENT_SCHEMA = hr",
            "ALTER SESSION SET CONTAINER = CDB$ROOT",
        ] {
            let d = classify(sql);
            assert_eq!(
                d.danger,
                DangerLevel::Guarded,
                "ALTER SESSION must classify Guarded (not Admin/Forbidden): {sql:?}"
            );
            assert_eq!(d.required_level, Some(OperatingLevel::ReadWrite), "{sql:?}");
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
                "a READ_WRITE session is Allowed (allowlist not consulted in classify): {sql:?}"
            );
        }
    }

    #[test]
    fn explain_plan_is_guarded_never_safe() {
        let d = classify("EXPLAIN PLAN FOR SELECT * FROM employees");
        assert_eq!(d.danger, DangerLevel::Guarded);
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
        assert_ne!(
            d.danger,
            DangerLevel::Forbidden,
            "punctuation-separated marker words must not trigger the dynamic-SQL marker"
        );
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
        // terminator — the buried-`;` desync rule only fires on the PureSql path,
        // so the block stays balanced and Guarded, never Forbidden.
        let plsql = analyze_batch("BEGIN UPDATE t SET x = 1 WHERE id = 2; END;");
        assert!(
            plsql.balanced,
            "a `;` nested in a real BEGIN..END block must stay depth-balanced: {plsql:?}"
        );
        assert_eq!(
            classify("BEGIN UPDATE t SET x = 1 WHERE id = 2; END;").danger,
            DangerLevel::Guarded,
            "a balanced PL/SQL block with a nested `;` must stay Guarded, not Forbidden"
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
        // legitimate single anonymous blocks — including a leading `DECLARE … ;`
        // section, which sets has_plsql_block but never raises depth — and a block
        // followed only by the SQL*Plus `/` run terminator must STAY balanced,
        // Guarded/ReadWrite, and gate to Allow at ReadWrite.
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
            assert_eq!(
                d.danger,
                DangerLevel::Guarded,
                "a legitimate single anonymous block must stay Guarded: {sql:?} -> {d:?}"
            );
            assert_eq!(
                d.required_level,
                Some(OperatingLevel::ReadWrite),
                "a legitimate single anonymous block must require ReadWrite: {sql:?}"
            );
            assert_eq!(
                d.gate(&session),
                LevelDecision::Allow,
                "a ReadWrite-elevated session must still Allow a legitimate block: {sql:?}"
            );
        }
    }

    #[test]
    fn unbalanced_block_is_forbidden() {
        // A BEGIN with no matching END desyncs → Forbidden.
        let d = classify("DECLARE x NUMBER; BEGIN x := 1;");
        assert_eq!(d.danger, DangerLevel::Forbidden);
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
        // Same statement, different whitespace/case → still allow-listed.
        let d = Classifier::new(cfg).classify("select   billing.weird_udf()  from dual");
        assert_eq!(d.danger, DangerLevel::Safe);
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
