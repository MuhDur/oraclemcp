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

/// An oracle that returns one fixed verdict, so the restriction wrapper can be
/// driven across every input it will ever see.
struct FixedOracle(Purity);

impl SideEffectOracle for FixedOracle {
    fn routine_purity(&self, _routine: &ObjectRef) -> Purity {
        self.0
    }
}

/// B12d — THE INVARIANT ANY "ADVISORY EVIDENCE" MUST PRESERVE, checked
/// exhaustively rather than on the one case that happened to be written.
///
/// B12d proposes feeding Oracle's own purity metadata (`DETERMINISTIC`,
/// `ALL_PROCEDURES`) into the purity oracle as evidence. Whatever such a channel
/// looked like, this is the property it could not be allowed to break: the
/// restriction layer may only ever NARROW what the independent oracle proved. It
/// must never permit `Safe` where the independent oracle did not.
///
/// Every (independent verdict x allowlist state) pair is enumerated, because the
/// dangerous direction is the one nobody writes a test for: the wrapper turning
/// an `Unknown` or `ProvenSideEffecting` routine into a proof on its own
/// authority. B12a's first attempt (1365e0d1) asserted exactly that promotion
/// before 535 lines were deleted (c5f1b85c) and it was redesigned as 3eae7815.
#[test]
fn no_allowlist_state_can_promote_a_verdict_the_independent_oracle_refused() {
    let routine = ObjectRef::new(Some("app_read".to_owned()), "lookup".to_owned());
    let other = ObjectRef::new(Some("app_read".to_owned()), "not_listed".to_owned());

    for independent in [
        Purity::ProvenReadOnly,
        Purity::ProvenSideEffecting,
        Purity::Unknown,
    ] {
        for (label, probe) in [("allowlisted", &routine), ("not allowlisted", &other)] {
            let allowlist = OperatorPureFunctionAllowlist::new([OperatorPureFunction::parse(
                "app_read.lookup",
            )
            .expect("exact declaration")]);
            let restriction =
                OperatorPureFunctionRestriction::new(Arc::new(FixedOracle(independent)), allowlist);
            let verdict = restriction.routine_purity(probe);

            // The whole safety property in one line: permitting Safe after the
            // wrapper requires the independent oracle to have permitted it
            // before.
            assert!(
                !verdict.permits_safe() || independent.permits_safe(),
                "restriction promoted {independent:?} to {verdict:?} for a {label} routine; \
                 an advisory layer may narrow a proof, never manufacture one"
            );

            // And the specific shape B12d must never introduce: metadata (or any
            // other advisory input) turning a non-proof into a proof.
            if !independent.permits_safe() {
                assert_eq!(
                    verdict, independent,
                    "a non-proof must pass through unchanged for a {label} routine; \
                     Oracle's DETERMINISTIC flag is a developer assertion about repeatability, \
                     not a verified statement about side effects, and must not upgrade it"
                );
            }
        }
    }
}
