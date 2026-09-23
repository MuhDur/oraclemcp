//! Public-API regression for the operator-only default-edition boundary.
//! No agent operating level, including ADMIN, can preview or execute a flip.

use oraclemcp_error::ReasonCategory;
use oraclemcp_guard::classifier::{Classifier, ClassifierConfig};
use oraclemcp_guard::levels::{
    BlockReason, DangerLevel, LevelDecision, OperatingLevel, SessionLevelState,
};

#[test]
fn default_edition_flip_is_operator_only_at_every_level() {
    let classifier = Classifier::default();
    for sql in [
        "ALTER DATABASE DEFAULT EDITION = stage_v2",
        "ALTER DATABASE DEFAULT EDITION = \"stage v2\"",
    ] {
        let decision = classifier.classify(sql);
        assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql}");
        assert_eq!(decision.required_level, None, "{sql}");
        assert_eq!(
            decision.reason_category,
            Some(ReasonCategory::OperatorOnlyStatement),
            "{sql}"
        );
        for level in OperatingLevel::all() {
            let mut session = SessionLevelState::new(OperatingLevel::Admin, false);
            session
                .set_current_level(level)
                .expect("level is within ceiling");
            assert_eq!(
                decision.gate(&session),
                LevelDecision::Blocked {
                    reason: BlockReason::Forbidden,
                },
                "agent at {level:?} cannot flip {sql:?}"
            );
        }
        for session in [
            SessionLevelState::new(OperatingLevel::ReadOnly, false),
            SessionLevelState::new(OperatingLevel::ReadOnly, true),
        ] {
            assert_eq!(
                decision.gate(&session),
                LevelDecision::Blocked {
                    reason: BlockReason::Forbidden
                }
            );
        }
        let allowlisted = Classifier::new(ClassifierConfig::new().with_allow(sql)).classify(sql);
        assert_eq!(
            allowlisted.danger,
            DangerLevel::Forbidden,
            "operator allow-list cannot override the refusal"
        );
        assert_eq!(
            allowlisted.reason_category,
            Some(ReasonCategory::OperatorOnlyStatement)
        );
    }
}

#[test]
fn default_edition_flip_spelling_corpus_refused() {
    let classifier = Classifier::default();
    for sql in [
        "alter database default edition = next_ed",
        "ALTER\nDATABASE\nDEFAULT\nEDITION = next_ed",
        "/* lead */ ALTER /*c*/ DATABASE /*c*/ DEFAULT /*c*/ EDITION = next_ed",
        "ALTER -- c\n DATABASE DEFAULT -- c\n EDITION = next_ed",
        "ALTER DATABASE \"DB One\" DEFAULT EDITION = \"Next Ed\"",
        "ALTER DATABASE appdb DEFAULT EDITION = next_ed",
        "ALTER PLUGGABLE DATABASE DEFAULT EDITION = next_ed",
        "ALTER PLUGGABLE DATABASE \"PDB One\" DEFAULT EDITION = \"Next Ed\"",
        "ALTER DATABASE DEFAULT EDITION = next_ed;",
    ] {
        let decision = classifier.classify(sql);
        assert_eq!(decision.danger, DangerLevel::Forbidden, "{sql:?}");
        assert_eq!(decision.required_level, None, "{sql:?}");
        assert_eq!(
            decision.reason_category,
            Some(ReasonCategory::OperatorOnlyStatement),
            "{sql:?}"
        );
    }
}

#[test]
fn default_edition_flip_in_execute_immediate_refused() {
    let decision = Classifier::default()
        .classify("BEGIN EXECUTE IMMEDIATE 'ALTER DATABASE DEFAULT EDITION = next_ed'; END;");
    assert_eq!(decision.danger, DangerLevel::Forbidden);
    assert_eq!(decision.reason_category, Some(ReasonCategory::DynamicSql));
}

#[test]
fn default_edition_flip_tokenizer_failure_cannot_use_allow_list() {
    let sql = "ALTER DATABASE DEFAULT EDITION = 'unterminated";
    let decision = Classifier::new(ClassifierConfig::new().with_allow(sql)).classify(sql);
    assert_eq!(decision.danger, DangerLevel::Forbidden);
    assert_eq!(
        decision.reason_category,
        Some(ReasonCategory::OperatorOnlyStatement)
    );
}

#[test]
fn alter_database_open_classification_unchanged() {
    for sql in [
        "ALTER DATABASE OPEN",
        "ALTER DATABASE OPEN /* DEFAULT EDITION */",
    ] {
        let decision = Classifier::default().classify(sql);
        assert_eq!(decision.danger, DangerLevel::Destructive, "{sql}");
        assert_eq!(
            decision.required_level,
            Some(OperatingLevel::Admin),
            "{sql}"
        );
        assert_ne!(
            decision.reason_category,
            Some(ReasonCategory::OperatorOnlyStatement),
            "{sql}"
        );
    }
}
