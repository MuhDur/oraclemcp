//! D6.1 — classifier metamorphic property tests, mutation-validated.
//!
//! The fail-closed classifier ([`Classifier::classify`]) has the *oracle
//! problem*: for an arbitrary generated statement we cannot cheaply state the
//! one true verdict. Metamorphic testing sidesteps that — instead of asserting
//! an absolute verdict we assert **relations between the verdicts of related
//! inputs**, relations that must hold for *any* correct fail-closed classifier.
//!
//! This suite is the **safety core** the D6.4 `cargo-mutants` gate kills guard
//! mutants with, so each relation here is **mutation-validated**: a relation is
//! only worth keeping if it *catches a planted bug*. Alongside every property
//! test we run the same relation against a family of deliberately-loosening
//! *planted mutants* (a fast, deterministic model of the source mutations
//! `cargo-mutants` injects — a guard that returned a too-low / non-idempotent /
//! whitespace-sensitive / oracle-inverted verdict) and assert the relation
//! *fails*. A relation that no mutant can break is decorative and is removed.
//!
//! The five relations (per the D6.1 spec):
//!
//! * **MR1 monotonicity** — adding a danger marker never LOOSENS the verdict
//!   (danger and required-level are both non-decreasing under danger-adding
//!   transforms). [`mr_monotonicity`]
//! * **MR2 reclass-idempotence** — classifying the same text twice yields an
//!   identical verdict (the guard is a pure function; no hidden state).
//!   [`mr_reclass_idempotence`]
//! * **MR3 `SideEffectOracle`-never-loosens** — binding a stricter side-effect
//!   oracle (and the statement-`Unknown`-guarded tightening) never produces a
//!   verdict *below* the engine-free baseline. [`mr_oracle_never_loosens`]
//! * **MR4 flashback-with-any-write-token-still-refused** — a flashback form
//!   carrying any write token is never cleared to `Safe`/`READ_ONLY` and its
//!   severity never drops below the bare flashback form. [`mr_flashback_write_refused`]
//! * **MR5 normalize-before-classify stability** — a semantics-preserving
//!   whitespace/case normalization never changes the verdict.
//!   [`mr_normalize_stability`]
//!
//! Distinct from `proptest_invariants.rs`, which owns the ALTER SESSION
//! allowlist law and the comment-wedge relation; this file owns the five
//! classifier MRs above and the mutation-validation harness. No overlap.
//!
//! Per-case logging: set `OMCP_MR_LOG=1` to stream one structured line per
//! generated case (`mr`, `input`, `transform`, `expected relation`, base and
//! actual verdict, hold/violation). On a property failure the full context is
//! always in the assertion message regardless of the env var.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use oraclemcp_guard::{
    Classifier, DangerLevel, GuardDecision, ObjectRef, OperatingLevel, Purity, SideEffectOracle,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Severity ranks (fail-closed on any future variant)
// ---------------------------------------------------------------------------

/// Monotone rank of a danger tier. `DangerLevel` is `#[non_exhaustive]`, so any
/// future variant ranks as *maximally dangerous* — the fail-closed default.
fn danger_rank(d: DangerLevel) -> u8 {
    match d {
        DangerLevel::Safe => 0,
        DangerLevel::Guarded => 1,
        DangerLevel::Destructive => 2,
        DangerLevel::Forbidden => 3,
        _ => u8::MAX,
    }
}

/// Monotone rank of a required operating level. `None` means `Forbidden` — no
/// level ever admits it — so it ranks *above* `ADMIN`, not below `READ_ONLY`
/// (the derived `Option` ordering would get this backwards, hence the explicit
/// rank). Unknown future levels rank maximally.
fn level_rank(l: Option<OperatingLevel>) -> u8 {
    match l {
        Some(OperatingLevel::ReadOnly) => 0,
        Some(OperatingLevel::ReadWrite) => 1,
        Some(OperatingLevel::Ddl) => 2,
        Some(OperatingLevel::Admin) => 3,
        None => 4,
        Some(_) => u8::MAX,
    }
}

/// The full severity of a decision as a `(danger, level)` pair. A verdict A is
/// "at least as strict as" B iff both components of A are `>=` B's.
fn severity(d: &GuardDecision) -> (u8, u8) {
    (danger_rank(d.danger), level_rank(d.required_level))
}

/// True iff `a` is no less strict than `b` on *both* axes.
fn no_looser(a: &GuardDecision, b: &GuardDecision) -> bool {
    let (ad, al) = severity(a);
    let (bd, bl) = severity(b);
    ad >= bd && al >= bl
}

fn verdict_str(d: &GuardDecision) -> String {
    let lvl = match d.required_level {
        Some(l) => l.as_str().to_owned(),
        None => "NONE(forbidden)".to_owned(),
    };
    format!("danger={:?} level={lvl}", d.danger)
}

// ---------------------------------------------------------------------------
// Structured per-case logging (opt-in via OMCP_MR_LOG)
// ---------------------------------------------------------------------------

fn log_case(
    mr: &str,
    input: &str,
    transform: &str,
    relation: &str,
    base: &str,
    actual: &str,
    held: bool,
) {
    if std::env::var_os("OMCP_MR_LOG").is_none() {
        return;
    }
    // One structured line per case (JSON so it is machine-greppable in CI logs).
    eprintln!(
        "{{\"mr\":{:?},\"input\":{:?},\"transform\":{:?},\"expected_relation\":{:?},\"base_verdict\":{:?},\"actual_verdict\":{:?},\"result\":{:?}}}",
        mr,
        input,
        transform,
        relation,
        base,
        actual,
        if held { "hold" } else { "VIOLATION" }
    );
}

// ---------------------------------------------------------------------------
// Metamorphic relations. Each returns Ok(()) when the relation holds, or
// Err(detailed message) on violation. They are generic over a classify closure
// so the *same* relation runs against the real classifier (must hold) and
// against planted mutants (must be caught).
// ---------------------------------------------------------------------------

/// MR1 — monotonicity: a danger-adding transform never lowers severity.
fn mr_monotonicity(
    classify: &dyn Fn(&str) -> GuardDecision,
    base_sql: &str,
    transform: &str,
    transformed_sql: &str,
) -> Result<(), String> {
    let base = classify(base_sql);
    let transformed = classify(transformed_sql);
    let held = no_looser(&transformed, &base);
    log_case(
        "MR1-monotonicity",
        base_sql,
        transform,
        "severity(transformed) >= severity(base)",
        &verdict_str(&base),
        &verdict_str(&transformed),
        held,
    );
    if held {
        Ok(())
    } else {
        Err(format!(
            "MR1 monotonicity VIOLATION: danger-adding transform {transform:?} LOWERED the verdict\n  \
             base:        {base_sql:?} -> {}\n  transformed: {transformed_sql:?} -> {}",
            verdict_str(&base),
            verdict_str(&transformed),
        ))
    }
}

/// MR2 — reclass-idempotence: the guard is a pure function of its input.
fn mr_reclass_idempotence(
    classify: &dyn Fn(&str) -> GuardDecision,
    sql: &str,
) -> Result<(), String> {
    let first = classify(sql);
    let second = classify(sql);
    let held = first == second;
    log_case(
        "MR2-idempotence",
        sql,
        "classify twice",
        "classify(x) == classify(x)",
        &verdict_str(&first),
        &verdict_str(&second),
        held,
    );
    if held {
        Ok(())
    } else {
        Err(format!(
            "MR2 idempotence VIOLATION: re-classifying identical text changed the verdict\n  \
             input:  {sql:?}\n  first:  {}\n  second: {}",
            verdict_str(&first),
            verdict_str(&second),
        ))
    }
}

/// MR3 — `SideEffectOracle`-never-loosens: a stricter oracle never lowers the
/// verdict below the engine-free baseline.
fn mr_oracle_never_loosens(
    baseline: &dyn Fn(&str) -> GuardDecision,
    strict: &dyn Fn(&str) -> GuardDecision,
    sql: &str,
) -> Result<(), String> {
    let base = baseline(sql);
    let tightened = strict(sql);
    let held = no_looser(&tightened, &base);
    log_case(
        "MR3-oracle-never-loosens",
        sql,
        "bind ProvenSideEffecting oracle + statement-unknown-guarded",
        "severity(strict) >= severity(baseline)",
        &verdict_str(&base),
        &verdict_str(&tightened),
        held,
    );
    if held {
        Ok(())
    } else {
        Err(format!(
            "MR3 oracle-never-loosens VIOLATION: binding a stricter oracle LOWERED the verdict\n  \
             input:    {sql:?}\n  baseline: {}\n  strict:   {}",
            verdict_str(&base),
            verdict_str(&tightened),
        ))
    }
}

/// MR4 — flashback-with-any-write-token-still-refused.
fn mr_flashback_write_refused(
    classify: &dyn Fn(&str) -> GuardDecision,
    flashback_sql: &str,
    write_token: &str,
    combined_sql: &str,
) -> Result<(), String> {
    let base = classify(flashback_sql);
    let combined = classify(combined_sql);
    // A write token present ⇒ the result is never cleared to Safe/READ_ONLY,
    // and its severity is never below the bare flashback form.
    let refused = combined.danger != DangerLevel::Safe
        && combined.required_level != Some(OperatingLevel::ReadOnly);
    let not_looser = no_looser(&combined, &base);
    let held = refused && not_looser;
    log_case(
        "MR4-flashback-write-refused",
        flashback_sql,
        write_token,
        "combined not Safe/READ_ONLY AND severity(combined) >= severity(flashback)",
        &verdict_str(&base),
        &verdict_str(&combined),
        held,
    );
    if held {
        Ok(())
    } else {
        Err(format!(
            "MR4 flashback+write VIOLATION: a flashback form carrying write token {write_token:?} was not refused\n  \
             flashback: {flashback_sql:?} -> {}\n  combined:  {combined_sql:?} -> {}\n  refused={refused} not_looser={not_looser}",
            verdict_str(&base),
            verdict_str(&combined),
        ))
    }
}

/// MR5 — normalize-before-classify stability: a semantics-preserving
/// whitespace/case normalization never changes the verdict.
fn mr_normalize_stability(
    classify: &dyn Fn(&str) -> GuardDecision,
    raw_sql: &str,
    normalized_sql: &str,
) -> Result<(), String> {
    let raw = classify(raw_sql);
    let norm = classify(normalized_sql);
    let held = (raw.danger, raw.required_level) == (norm.danger, norm.required_level);
    log_case(
        "MR5-normalize-stability",
        raw_sql,
        "collapse whitespace",
        "verdict(raw) == verdict(normalized)",
        &verdict_str(&raw),
        &verdict_str(&norm),
        held,
    );
    if held {
        Ok(())
    } else {
        Err(format!(
            "MR5 normalize-stability VIOLATION: whitespace normalization changed the verdict\n  \
             raw:        {raw_sql:?} -> {}\n  normalized: {normalized_sql:?} -> {}",
            verdict_str(&raw),
            verdict_str(&norm),
        ))
    }
}

// ---------------------------------------------------------------------------
// Corpora + strategies
// ---------------------------------------------------------------------------

/// Base statements spanning the danger tiers. Every transform below is applied
/// to these so the relations are exercised from Safe through Destructive.
const BASE_STATEMENTS: &[&str] = &[
    "SELECT id, name FROM employees WHERE dept = 10",
    "SELECT * FROM orders",
    "SELECT app.recalc(id) FROM orders",
    "WITH c AS (SELECT id FROM employees) SELECT * FROM c",
    "INSERT INTO audit_log (id, msg) VALUES (1, 'x')",
    "UPDATE orders SET status = 'X' WHERE id = 1",
    "DELETE FROM orders WHERE id = 1",
    "MERGE INTO t USING s ON (t.id = s.id) WHEN MATCHED THEN UPDATE SET t.v = s.v",
    "DROP TABLE staging_tmp",
    "TRUNCATE TABLE staging_tmp",
    "GRANT SELECT ON employees TO reporting",
];

/// SELECT bases eligible for the in-statement `FOR UPDATE` danger marker.
const SELECT_BASES: &[&str] = &[
    "SELECT id, name FROM employees WHERE dept = 10",
    "SELECT * FROM orders",
    "SELECT app.recalc(id) FROM orders",
];

/// Danger-adding statements appended/prepended via `;`. Batch danger is the max
/// over statements, so composing any base with one of these can only RAISE the
/// verdict — the ground truth MR1 leans on.
const DANGER_STATEMENTS: &[&str] = &[
    "DROP TABLE victims",
    "TRUNCATE TABLE victims",
    "GRANT DBA TO scott",
    "DELETE FROM victims",
    "UPDATE victims SET x = 1",
    "ALTER USER scott IDENTIFIED BY hunter2",
    "BEGIN EXECUTE IMMEDIATE 'DROP TABLE t'; END;",
];

/// Flashback base forms — both the rewind-DDL (`FLASHBACK TABLE`) and the
/// read-side flashback query (`AS OF` / `VERSIONS BETWEEN`).
const FLASHBACK_BASES: &[&str] = &[
    "FLASHBACK TABLE orders TO BEFORE DROP",
    "FLASHBACK TABLE orders TO TIMESTAMP SYSTIMESTAMP - 1",
    "SELECT * FROM orders AS OF TIMESTAMP SYSTIMESTAMP - INTERVAL '5' MINUTE",
    "SELECT * FROM orders AS OF SCN 12345",
    "SELECT * FROM orders VERSIONS BETWEEN SCN 1 AND 2",
];

/// Write tokens/statements combined with a flashback form. Each unambiguously
/// introduces a write; a fail-closed guard must keep the combination refused.
const WRITE_TOKENS: &[&str] = &[
    " FOR UPDATE",
    "; DROP TABLE orders",
    "; DELETE FROM orders",
    "; UPDATE orders SET x = 1",
    "; GRANT DBA TO scott",
];

fn base_stmt() -> impl Strategy<Value = &'static str> {
    (0..BASE_STATEMENTS.len()).prop_map(|i| BASE_STATEMENTS[i])
}

fn danger_stmt() -> impl Strategy<Value = &'static str> {
    (0..DANGER_STATEMENTS.len()).prop_map(|i| DANGER_STATEMENTS[i])
}

/// A whitespace/case renoise of a statement that preserves its semantics:
/// collapse-and-re-expand the token stream with random blank runs, randomly
/// upper/lower-casing whole tokens (never touching quoted-literal contents,
/// which `split_whitespace` keeps intact only when unquoted — so we operate on
/// the already-token-split words and skip anything holding a quote).
fn whitespace_renoise(sql: &str, pads: &[usize], cases: &[bool]) -> String {
    sql.split_whitespace()
        .enumerate()
        .map(|(i, tok)| {
            let has_quote = tok.contains('\'') || tok.contains('"');
            let cased = if !has_quote && *cases.get(i % cases.len().max(1)).unwrap_or(&false) {
                tok.to_ascii_uppercase()
            } else {
                tok.to_owned()
            };
            let pad = " ".repeat(1 + pads.get(i % pads.len().max(1)).copied().unwrap_or(0) % 3);
            format!("{pad}{cased}")
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

// ---------------------------------------------------------------------------
// The real classifier under test (helper closures)
// ---------------------------------------------------------------------------

fn real_classify(sql: &str) -> GuardDecision {
    Classifier::default().classify(sql)
}

/// An oracle that reports *every* routine and statement as side-effecting — the
/// strictest engine binding. Combined with `with_statement_unknown_guarded` it
/// is the tightening MR3 compares against the engine-free baseline.
struct AllSideEffectingOracle;
impl SideEffectOracle for AllSideEffectingOracle {
    fn routine_purity(&self, _r: &ObjectRef) -> Purity {
        Purity::ProvenSideEffecting
    }
    fn statement_purity(&self, _base: &[ObjectRef]) -> Purity {
        Purity::ProvenSideEffecting
    }
}

fn strict_classify(sql: &str) -> GuardDecision {
    Classifier::default()
        .with_oracle(Arc::new(AllSideEffectingOracle))
        .with_statement_unknown_guarded()
        .classify(sql)
}

// ---------------------------------------------------------------------------
// Planted mutants — a deterministic model of the source mutations D6.4's
// cargo-mutants run injects. Each wraps the real classifier and LOOSENS its
// output in one realistic way. The mutation-validation test proves every MR
// catches at least one of these.
//
// IMPORTANT — why the mutants are all *non-uniform*: a metamorphic relation
// compares the verdicts of related inputs, so a mutation that loosens *every*
// verdict by the same amount (a uniform scaling) preserves the relation and is
// invisible to it. That whole class — uniform loosen-by-one, clamp-Forbidden —
// is caught instead by the ABSOLUTE-floor corpora (`adversarial_corpus.rs`,
// `admin_dcl_fail_closed.rs`) and by D6.4's real cargo-mutants run. The mutants
// below each break a *relation* by mishandling one specific input class
// (a danger marker, one call in a pair, the strict side only, a flashback
// keyword, whitespace) — exactly the kind of bug metamorphic testing exists to
// catch. `planted_mutants_are_genuine_loosenings` proves each really loosens.
// ---------------------------------------------------------------------------

/// Recompute a decision's `required_level` from its (possibly-mutated) danger,
/// so a loosened danger drags the level down with it (as a real guard bug
/// would) rather than leaving an inconsistent pair.
fn with_danger(mut d: GuardDecision, danger: DangerLevel) -> GuardDecision {
    d.danger = danger;
    d.required_level = danger.default_required_level();
    d
}

fn loosen_one(d: DangerLevel) -> DangerLevel {
    match d {
        DangerLevel::Forbidden => DangerLevel::Destructive,
        DangerLevel::Destructive => DangerLevel::Guarded,
        DangerLevel::Guarded => DangerLevel::Safe,
        DangerLevel::Safe => DangerLevel::Safe,
        _ => DangerLevel::Safe,
    }
}

/// The high-danger keyword markers a broken block-list / inverted verdict arm
/// might mishandle.
const DANGER_KEYWORDS: &[&str] = &["DROP", "TRUNCATE", "GRANT", "ALTER USER"];

/// MUT-MARKER: an *inverted verdict* mutant — when a high-danger keyword is
/// present it returns `Safe` instead of escalating (models a block-list arm
/// that matched but returned the wrong tier). Non-uniform: only marker-bearing
/// inputs are loosened, so a base without the marker outranks its marker-bearing
/// transform → breaks MR1 monotonicity.
fn mutant_marker_blind(sql: &str) -> GuardDecision {
    let upper = sql.to_ascii_uppercase();
    let real = real_classify(sql);
    if DANGER_KEYWORDS.iter().any(|k| upper.contains(k)) {
        with_danger(real, DangerLevel::Safe)
    } else {
        real
    }
}

/// MUT-STATE: a *stateful* guard whose verdict flip-flops between calls. Breaks
/// MR2 (idempotence) — the archetype of a guard that memoizes/toggles wrongly.
fn mutant_nonidempotent(sql: &str) -> GuardDecision {
    static TOGGLE: AtomicU64 = AtomicU64::new(0);
    let real = real_classify(sql);
    if TOGGLE.fetch_add(1, Ordering::Relaxed) % 2 == 1 {
        let danger = loosen_one(real.danger);
        with_danger(real, danger)
    } else {
        real
    }
}

/// MUT-WS: a whitespace-sensitive guard — it loosens whenever the text carries a
/// run of two or more spaces. Non-uniform between the padded and collapsed forms
/// → breaks MR5 (normalize stability).
fn mutant_whitespace_sensitive(sql: &str) -> GuardDecision {
    let real = real_classify(sql);
    if sql.contains("  ") {
        let danger = loosen_one(real.danger);
        with_danger(real, danger)
    } else {
        real
    }
}

/// MUT-ORACLE: the "oracle wiring inverted" mutant — the *strict* side ignores
/// the oracle and additionally loosens one tier, so the tightened path can fall
/// BELOW the engine-free baseline. Applied only to the strict side, it is
/// non-uniform across the baseline/strict pair → breaks MR3.
fn mutant_strict_loosened(sql: &str) -> GuardDecision {
    let real = real_classify(sql);
    let danger = loosen_one(real.danger);
    with_danger(real, danger)
}

/// MUT-FB: a "flashback is just a historical read, so it's safe" mutant —
/// returns `Safe` whenever a flashback keyword is present, ignoring any write
/// token riding along. Non-uniform: only flashback-bearing inputs are loosened
/// → breaks MR4 (flashback+write must stay refused).
fn mutant_flashback_blind(sql: &str) -> GuardDecision {
    let upper = sql.to_ascii_uppercase();
    let real = real_classify(sql);
    if upper.contains("FLASHBACK") || upper.contains(" AS OF ") || upper.contains(" VERSIONS ") {
        with_danger(real, DangerLevel::Safe)
    } else {
        real
    }
}

// ---------------------------------------------------------------------------
// Property tests against the REAL classifier — every relation must hold.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// MR1 — appending / prepending a dangerous statement (batch danger = max)
    /// never lowers the verdict.
    #[test]
    fn mr1_batch_composition_never_loosens(
        base in base_stmt(),
        danger in danger_stmt(),
        prepend in any::<bool>(),
    ) {
        let (transform, combined) = if prepend {
            ("prepend dangerous stmt", format!("{danger}; {base}"))
        } else {
            ("append dangerous stmt", format!("{base}; {danger}"))
        };
        prop_assert!(
            mr_monotonicity(&real_classify, base, transform, &combined).is_ok(),
            "{}",
            mr_monotonicity(&real_classify, base, transform, &combined).unwrap_err()
        );
    }

    /// MR1 — the in-statement `FOR UPDATE` marker turns a read into a write and
    /// must never lower the verdict.
    #[test]
    fn mr1_for_update_marker_never_loosens(
        idx in 0..SELECT_BASES.len(),
    ) {
        let base = SELECT_BASES[idx];
        let combined = format!("{base} FOR UPDATE");
        prop_assert!(
            mr_monotonicity(&real_classify, base, "append FOR UPDATE", &combined).is_ok(),
            "{}",
            mr_monotonicity(&real_classify, base, "append FOR UPDATE", &combined).unwrap_err()
        );
    }

    /// MR2 — classifying identical text twice yields an identical verdict.
    #[test]
    fn mr2_idempotent(
        base in base_stmt(),
        danger in danger_stmt(),
        compose in any::<bool>(),
    ) {
        let sql = if compose { format!("{base}; {danger}") } else { base.to_owned() };
        prop_assert!(
            mr_reclass_idempotence(&real_classify, &sql).is_ok(),
            "{}",
            mr_reclass_idempotence(&real_classify, &sql).unwrap_err()
        );
    }

    /// MR3 — the strictest oracle + statement-unknown-guarded never loosens
    /// below the engine-free baseline.
    #[test]
    fn mr3_stricter_oracle_never_loosens(
        base in base_stmt(),
        danger in danger_stmt(),
        compose in any::<bool>(),
    ) {
        let sql = if compose { format!("{base}; {danger}") } else { base.to_owned() };
        prop_assert!(
            mr_oracle_never_loosens(&real_classify, &strict_classify, &sql).is_ok(),
            "{}",
            mr_oracle_never_loosens(&real_classify, &strict_classify, &sql).unwrap_err()
        );
    }

    /// MR4 — a flashback form carrying any write token stays refused.
    #[test]
    fn mr4_flashback_plus_write_refused(
        fb_idx in 0..FLASHBACK_BASES.len(),
        wt_idx in 0..WRITE_TOKENS.len(),
    ) {
        let flashback = FLASHBACK_BASES[fb_idx];
        let token = WRITE_TOKENS[wt_idx];
        let combined = format!("{flashback}{token}");
        prop_assert!(
            mr_flashback_write_refused(&real_classify, flashback, token, &combined).is_ok(),
            "{}",
            mr_flashback_write_refused(&real_classify, flashback, token, &combined).unwrap_err()
        );
    }

    /// MR5 — whitespace/case normalization never changes the verdict.
    #[test]
    fn mr5_normalize_stability(
        base in base_stmt(),
        danger in danger_stmt(),
        compose in any::<bool>(),
        pads in prop::collection::vec(0usize..3, 1..8),
        cases in prop::collection::vec(any::<bool>(), 1..8),
    ) {
        let sql = if compose { format!("{base}; {danger}") } else { base.to_owned() };
        let renoised = whitespace_renoise(&sql, &pads, &cases);
        // The renoise must be a pure whitespace/case change (same token stream,
        // case-folded) — assert that as a precondition so a bug in the test
        // generator can never mask a classifier bug.
        prop_assume!(
            sql.split_whitespace().count() == renoised.split_whitespace().count()
        );
        prop_assert!(
            mr_normalize_stability(&real_classify, &renoised, &sql).is_ok(),
            "{}",
            mr_normalize_stability(&real_classify, &renoised, &sql).unwrap_err()
        );
    }
}

// ---------------------------------------------------------------------------
// Mutation validation — each MR MUST kill at least one planted mutant.
// If any of these assertions fails, the corresponding MR is decorative and the
// suite has lost its teeth (this is exactly what D6.4's cargo-mutants gate
// checks against the real source; this test is the fast in-tree proxy).
// ---------------------------------------------------------------------------

/// Assert an MR run against a mutant reports a violation for at least one input
/// in the corpus. Returns the witness for logging.
fn assert_mr_kills<F>(mr_name: &str, mutant_name: &str, mut probe: F)
where
    F: FnMut() -> Option<String>,
{
    match probe() {
        Some(witness) => {
            if std::env::var_os("OMCP_MR_LOG").is_some() {
                eprintln!(
                    "{{\"mutation_validation\":{mr_name:?},\"mutant\":{mutant_name:?},\"killed\":true,\"witness\":{witness:?}}}"
                );
            }
        }
        None => panic!(
            "MUTATION-VALIDATION FAILURE: relation {mr_name} did NOT catch planted mutant \
             {mutant_name} on ANY corpus input — the relation is decorative and must be \
             strengthened before it can feed the D6.4 cargo-mutants gate"
        ),
    }
}

#[test]
fn mr1_kills_marker_blind_mutant() {
    // A base with no danger keyword (e.g. `UPDATE … WHERE …` = Guarded) composed
    // with a `; DROP …` stmt: the marker-blind mutant sees the DROP keyword and
    // returns Safe for the composition, so the "more dangerous" transform scores
    // BELOW the base — a monotonicity inversion.
    assert_mr_kills("MR1-monotonicity", "MUT-MARKER(marker-blind)", || {
        for &base in BASE_STATEMENTS {
            for &danger in DANGER_STATEMENTS {
                let combined = format!("{base}; {danger}");
                if let Err(w) = mr_monotonicity(&mutant_marker_blind, base, "append", &combined) {
                    return Some(w);
                }
            }
        }
        None
    });
}

#[test]
fn mr2_kills_nonidempotent_mutant() {
    assert_mr_kills("MR2-idempotence", "MUT-STATE(nonidempotent)", || {
        for &base in BASE_STATEMENTS {
            for &danger in DANGER_STATEMENTS {
                let sql = format!("{base}; {danger}");
                if let Err(w) = mr_reclass_idempotence(&mutant_nonidempotent, &sql) {
                    return Some(w);
                }
            }
        }
        None
    });
}

#[test]
fn mr3_kills_strict_loosened_mutant() {
    assert_mr_kills(
        "MR3-oracle-never-loosens",
        "MUT-ORACLE(strict-loosened)",
        || {
            for &base in BASE_STATEMENTS {
                for &danger in DANGER_STATEMENTS {
                    let sql = format!("{base}; {danger}");
                    if let Err(w) =
                        mr_oracle_never_loosens(&real_classify, &mutant_strict_loosened, &sql)
                    {
                        return Some(w);
                    }
                }
            }
            None
        },
    );
}

#[test]
fn mr4_kills_flashback_blind_mutant() {
    assert_mr_kills(
        "MR4-flashback-write-refused",
        "MUT-FB(flashback-blind)",
        || {
            for &flashback in FLASHBACK_BASES {
                for &token in WRITE_TOKENS {
                    let combined = format!("{flashback}{token}");
                    if let Err(w) = mr_flashback_write_refused(
                        &mutant_flashback_blind,
                        flashback,
                        token,
                        &combined,
                    ) {
                        return Some(w);
                    }
                }
            }
            None
        },
    );
}

#[test]
fn mr5_kills_whitespace_sensitive_mutant() {
    assert_mr_kills(
        "MR5-normalize-stability",
        "MUT-WS(whitespace-sensitive)",
        || {
            for &base in BASE_STATEMENTS {
                // A raw form with double spaces vs the collapsed form: the
                // whitespace-sensitive mutant classifies them differently.
                let raw = format!("{base}  ;  {}", DANGER_STATEMENTS[0]);
                let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
                if let Err(w) =
                    mr_normalize_stability(&mutant_whitespace_sensitive, &raw, &collapsed)
                {
                    return Some(w);
                }
            }
            None
        },
    );
}

// ---------------------------------------------------------------------------
// Guards on the mutants themselves: each planted mutant must be a REAL loosening
// (else "the MR killed it" would be vacuous). This proves MUT-* actually differ
// from the real classifier in the loosening direction on at least one input.
// ---------------------------------------------------------------------------

#[test]
fn planted_mutants_are_genuine_loosenings() {
    // Each planted mutant must produce a strictly-lower severity than the real
    // classifier on at least one input — otherwise "the MR killed it" would be
    // vacuous (a no-op mutant is trivially caught by nothing / everything).
    let mut marker = false;
    let mut ws = false;
    let mut fb = false;
    for &base in BASE_STATEMENTS {
        for &danger in DANGER_STATEMENTS {
            let sql = format!("{base}; {danger}");
            if severity(&mutant_marker_blind(&sql)) < severity(&real_classify(&sql)) {
                marker = true;
            }
            let raw = format!("{base}  ;  {danger}");
            if severity(&mutant_whitespace_sensitive(&raw)) < severity(&real_classify(&raw)) {
                ws = true;
            }
        }
    }
    for &flashback in FLASHBACK_BASES {
        for &token in WRITE_TOKENS {
            let combined = format!("{flashback}{token}");
            if severity(&mutant_flashback_blind(&combined)) < severity(&real_classify(&combined)) {
                fb = true;
            }
        }
    }
    assert!(
        marker,
        "MUT-MARKER never loosened any corpus input — not a valid mutant"
    );
    assert!(
        ws,
        "MUT-WS never loosened any corpus input — not a valid mutant"
    );
    assert!(
        fb,
        "MUT-FB never loosened any corpus input — not a valid mutant"
    );
}
