//! Public-API regression for Arc D's database-wide default-edition operation.
//!
//! A default-edition flip must never inherit ordinary object-DDL authority: it
//! is an ADMIN action, has to stop at a profile ceiling below ADMIN, and must
//! request an ADMIN step-up when that ceiling is available.  The protected and
//! read-only-standby cases are explicit fail-closed coverage rather than an
//! assumption about configuration plumbing.

use oraclemcp_guard::classifier::Classifier;
use oraclemcp_guard::levels::{
    BlockReason, DangerLevel, LevelDecision, OperatingLevel, SessionLevelState,
};

#[test]
fn default_edition_flip_is_admin_only_and_never_reachable_below_the_ceiling() {
    let classifier = Classifier::default();
    let mut admin_profile = SessionLevelState::new(OperatingLevel::Admin, false);
    admin_profile
        .set_current_level(OperatingLevel::Ddl)
        .expect("an ADMIN-capable profile may be elevated only to DDL first");

    for sql in [
        "ALTER DATABASE DEFAULT EDITION = stage_v2",
        "ALTER DATABASE DEFAULT EDITION = \"stage v2\"",
    ] {
        let decision = classifier.classify(sql);
        assert_eq!(
            decision.danger,
            DangerLevel::Destructive,
            "a database-wide default-edition flip is destructive: {sql:?}"
        );
        assert_eq!(
            decision.required_level,
            Some(OperatingLevel::Admin),
            "a default-edition flip must require ADMIN: {sql:?}"
        );
        assert_eq!(
            decision.gate(&admin_profile),
            LevelDecision::RequireStepUp {
                target: OperatingLevel::Admin,
            },
            "DDL is not sufficient; the flip must request an ADMIN confirmation step-up: {sql:?}"
        );

        for (profile_name, session) in [
            (
                "read_only_standby",
                SessionLevelState::new(OperatingLevel::ReadOnly, false),
            ),
            (
                "protected",
                SessionLevelState::new(OperatingLevel::ReadOnly, true),
            ),
        ] {
            assert_eq!(
                decision.gate(&session),
                LevelDecision::Blocked {
                    reason: BlockReason::ExceedsCeiling {
                        required: OperatingLevel::Admin,
                        ceiling: OperatingLevel::ReadOnly,
                    },
                },
                "{profile_name} must refuse the ADMIN flip before any database action: {sql:?}"
            );
        }
    }
}
