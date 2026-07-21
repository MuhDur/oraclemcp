//! Conformance fixtures for `proofs/purity-core/PurityCore.lean`.
//!
//! The Lean theorem `safe_iff_all_proven_read_only` covers the *routine-purity
//! core* only. These parseable, unlocked SELECT fixtures isolate that core from
//! DML, parser-failure, lock, and statement-purity floors. This is a tested
//! conformance link, not verified extraction of the deployed Rust classifier.

use std::sync::Arc;

use oraclemcp_guard::{
    Classifier, DangerLevel, ObjectRef, OperatingLevel, OperatorPureFunction,
    OperatorPureFunctionAllowlist, OperatorPureFunctionRestriction, Purity, SideEffectOracle,
};

#[derive(Clone, Copy)]
struct FixedRoutineOracle {
    first: Purity,
    second: Purity,
}

impl SideEffectOracle for FixedRoutineOracle {
    fn routine_purity(&self, routine: &ObjectRef) -> Purity {
        match routine.name.to_ascii_lowercase().as_str() {
            "first_fn" => self.first,
            "second_fn" => self.second,
            _ => Purity::Unknown,
        }
    }
}

fn classify_routine_calls(first: Purity, second: Purity) -> (DangerLevel, Option<OperatingLevel>) {
    let classifier =
        Classifier::default().with_oracle(Arc::new(FixedRoutineOracle { first, second }));
    let decision = classifier.classify("SELECT app.first_fn(1), app.second_fn(2) FROM dual");
    (decision.danger, decision.required_level)
}

#[test]
fn routine_purity_core_matches_the_lean_safe_iff_all_proven_lemma() {
    let all_proven = classify_routine_calls(Purity::ProvenReadOnly, Purity::ProvenReadOnly);
    assert_eq!(
        all_proven,
        (DangerLevel::Safe, Some(OperatingLevel::ReadOnly)),
        "all user-defined routines ProvenReadOnly is the only Safe branch"
    );

    for first in [
        Purity::ProvenReadOnly,
        Purity::Unknown,
        Purity::ProvenSideEffecting,
    ] {
        for second in [
            Purity::ProvenReadOnly,
            Purity::Unknown,
            Purity::ProvenSideEffecting,
        ] {
            let expected = if first == Purity::ProvenReadOnly && second == Purity::ProvenReadOnly {
                (DangerLevel::Safe, Some(OperatingLevel::ReadOnly))
            } else {
                (DangerLevel::Guarded, Some(OperatingLevel::ReadWrite))
            };
            assert_eq!(
                classify_routine_calls(first, second),
                expected,
                "the Lean purity core must hold for first={first:?}, second={second:?}"
            );
        }
    }
}

#[test]
fn no_user_defined_routine_is_the_vacuous_safe_case_of_the_purity_core() {
    let decision = Classifier::default().classify("SELECT 1 FROM dual");
    assert_eq!(decision.danger, DangerLevel::Safe);
    assert_eq!(decision.required_level, Some(OperatingLevel::ReadOnly));
}

#[derive(Clone, Copy)]
struct AllProvenOracle;

impl SideEffectOracle for AllProvenOracle {
    fn routine_purity(&self, _routine: &ObjectRef) -> Purity {
        Purity::ProvenReadOnly
    }
}

fn restricted_classifier(independent: Arc<dyn SideEffectOracle>) -> Classifier {
    let allowlist =
        OperatorPureFunctionAllowlist::new([
            OperatorPureFunction::parse("app_read.lookup").expect("exact operator declaration")
        ]);
    Classifier::default().with_oracle(Arc::new(OperatorPureFunctionRestriction::new(
        independent,
        allowlist,
    )))
}

#[test]
fn operator_pure_function_allowlist_only_narrows_independent_purity_proof() {
    let unrestricted = Classifier::default().with_oracle(Arc::new(AllProvenOracle));
    let restricted = restricted_classifier(Arc::new(AllProvenOracle));

    let exact = "SELECT app_read.lookup(:id) FROM dual";
    assert_eq!(
        restricted.classify(exact),
        unrestricted.classify(exact),
        "an exact entry preserves an independently proven routine"
    );

    let omitted = "SELECT app_read.other_lookup(:id) FROM dual";
    assert_eq!(unrestricted.classify(omitted).danger, DangerLevel::Safe);
    let narrowed = restricted.classify(omitted);
    assert_eq!(narrowed.danger, DangerLevel::Guarded);
    assert_eq!(narrowed.required_level, Some(OperatingLevel::ReadWrite));
}

#[test]
fn operator_pure_function_allowlist_never_promotes_default_unknown_oracle() {
    let baseline = Classifier::default();
    let restricted = restricted_classifier(Arc::new(oraclemcp_guard::UnknownOracle));

    for sql in [
        "SELECT app_read.lookup(:id) FROM dual",
        "SELECT app_read.other_lookup(:id) FROM dual",
        "SELECT lookup(:id) FROM dual",
    ] {
        let without_config = baseline.classify(sql);
        let with_config = restricted.classify(sql);
        assert_eq!(without_config.danger, DangerLevel::Guarded, "{sql:?}");
        assert_eq!(
            with_config, without_config,
            "an allowlist must not promote a statement the default classifier refuses: {sql:?}"
        );
    }
}
