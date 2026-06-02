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
//!    absence of a write edge is `Unknown`, never `Safe` (P1-1e, R15).
//!
//! **Fail-closed law:** anything that does not parse, any PL/SQL block, any
//! desync, and anything the engine cannot prove `ProvenReadOnly` is classified
//! ≥ `Guarded`. The batch danger is the max over statements; any `Forbidden`
//! sub-statement rejects the whole batch.

use std::collections::HashSet;
use std::sync::Arc;

use regex::Regex;
use sha2::{Digest, Sha256};
use sqlparser::dialect::OracleDialect;
use sqlparser::keywords::Keyword;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};

use crate::levels::{DangerLevel, LevelDecision, OperatingLevel, SessionLevelState};
use crate::purity::{ObjectRef, SideEffectOracle, UnknownOracle};

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

/// Run Stage A: allow-list → block-list → PL/SQL-block detection.
#[must_use]
pub fn stage_a(sql: &str, config: &ClassifierConfig) -> StageA {
    if config.allow_list.contains(&normalized_sha256(sql)) {
        return StageA::AllowListed;
    }
    for re in &config.block_patterns {
        if re.is_match(sql) {
            return StageA::BlockListed(re.as_str().to_owned());
        }
    }
    let upper = sql.trim_start().to_ascii_uppercase();
    let starts_block = upper.starts_with("DECLARE")
        || upper.starts_with("BEGIN")
        || sql.trim() == "/"
        || upper.starts_with("CREATE OR REPLACE")
        || upper.starts_with("CREATE PACKAGE")
        || upper.starts_with("CREATE FUNCTION")
        || upper.starts_with("CREATE PROCEDURE")
        || upper.starts_with("CREATE TRIGGER");
    let dangerous = PLSQL_SIDE_EFFECT_MARKERS.iter().any(|m| upper.contains(m));
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
        };
    };
    let mut depth: i64 = 0;
    let mut went_negative = false;
    let mut has_plsql_block = false;
    let mut segment_has_content = false;
    let mut statement_count = 0usize;
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
                match keyword.as_deref() {
                    Some("BEGIN") => {
                        depth += 1;
                        has_plsql_block = true;
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
                }
            }
            // Whitespace must NOT reset `expecting_close` (END <ws> IF).
            Token::Whitespace(_) => {}
            _ => {
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
            if name.keyword != Keyword::NoKeyword {
                continue; // a keyword like VALUES( / IN( etc.
            }
            let (schema, fname) = if i >= 3
                && matches!(toks[i - 2], Token::Period)
                && matches!(toks[i - 3], Token::Word(_))
            {
                let Token::Word(s) = toks[i - 3] else {
                    unreachable!()
                };
                (Some(s.value.clone()), name.value.clone())
            } else {
                (None, name.value.clone())
            };
            if !is_builtin_function(&fname) {
                calls.push(ObjectRef::new(schema, fname));
            }
        }
    }
    calls
}

/// Classify a single pre-split, pure-SQL statement (Stage B + purity consult).
fn classify_statement(sql: &str, oracle: &dyn SideEffectOracle) -> StatementClass {
    use sqlparser::ast::Statement;
    let dialect = OracleDialect {};
    let parsed = match Parser::parse_sql(&dialect, sql) {
        Ok(stmts) if stmts.len() == 1 => stmts.into_iter().next().expect("len 1"),
        // Unparseable or unexpectedly multi → fail-closed.
        _ => {
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
        Statement::Query(_) => {
            // SELECT/WITH: Safe only if it calls no unproven user-defined
            // function (R15). Any UDF not ProvenReadOnly → Guarded.
            let calls = user_defined_calls(sql);
            let all_proven = calls
                .iter()
                .all(|c| oracle.routine_purity(c).permits_safe());
            // The engine's trigger/VPD walk also gets a say (default Unknown).
            let stmt_pure = calls.is_empty() || all_proven;
            if stmt_pure {
                StatementClass {
                    danger: DangerLevel::Safe,
                    required: Some(OperatingLevel::ReadOnly),
                    objects: calls.iter().map(|c| c.name.clone()).collect(),
                }
            } else {
                guarded_rw(calls.iter().map(|c| c.name.clone()).collect())
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
        // DDL.
        Statement::CreateTable(_)
        | Statement::CreateView { .. }
        | Statement::CreateIndex(_)
        | Statement::AlterTable { .. }
        | Statement::Drop { .. }
        | Statement::Truncate { .. } => destructive(OperatingLevel::Ddl, Vec::new()),
        // DCL / admin.
        Statement::Grant { .. } | Statement::Revoke { .. } => {
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
}

impl Default for Classifier {
    fn default() -> Self {
        Classifier {
            config: ClassifierConfig::new(),
            oracle: Arc::new(UnknownOracle),
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
        }
    }

    /// Bind the engine's real side-effect oracle (from the consumer side).
    #[must_use]
    pub fn with_oracle(mut self, oracle: Arc<dyn SideEffectOracle>) -> Self {
        self.oracle = oracle;
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

        // Classify each statement; the batch danger is the max, and any
        // Forbidden sub-statement rejects the whole batch.
        let classes: Vec<StatementClass> = if shape.statement_count <= 1 {
            vec![classify_statement(sql, self.oracle.as_ref())]
        } else {
            // Multi-statement pure SQL: let the parser split, classify each.
            match Parser::parse_sql(&OracleDialect {}, sql) {
                Ok(stmts) => stmts
                    .iter()
                    .map(|s| classify_statement(&s.to_string(), self.oracle.as_ref()))
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
    use crate::purity::Purity;

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
