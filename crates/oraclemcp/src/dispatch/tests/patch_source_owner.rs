//! oraclemcp-nqauq: a source patch is bound to the previewed owner and name.
//!
//! ALL_SOURCE blanks the schema on line 1, so re-issuing its text as
//! `CREATE OR REPLACE` landed the unit in the session's current schema while the
//! response named the previewed owner. These pin the owner-qualified statement,
//! the refusals for a header that names another target, and that a confirmation
//! minted for one owner cannot apply to another.

use super::*;

fn qualify(
    source: &str,
    owner: &str,
    name: &str,
    object_type: &str,
) -> Result<String, ErrorEnvelope> {
    owner_qualified_patch_ddl(source, owner, name, object_type, "oracle_patch_source")
}

#[test]
fn owner_less_stored_header_is_bound_to_the_previewed_owner() {
    // Oracle's ALL_SOURCE text for `CREATE PROCEDURE W4O_X.P_SRC AS ...`: the
    // qualifier is blanked, not kept.
    let stored = "PROCEDURE                  P_SRC AS\n  v NUMBER := 7;\nBEGIN\n  NULL;\nEND;";
    assert_eq!(
        qualify(stored, "W4O_X", "P_SRC", "PROCEDURE").expect("owner-less header binds"),
        "CREATE OR REPLACE PROCEDURE W4O_X.P_SRC AS\n  v NUMBER := 7;\nBEGIN\n  NULL;\nEND;"
    );
}

#[test]
fn every_stored_unit_header_shape_is_qualified_in_place() {
    let cases = [
        (
            "package body emp_api as\nEND;",
            "APP",
            "EMP_API",
            "PACKAGE BODY",
            "CREATE OR REPLACE package body APP.EMP_API as\nEND;",
        ),
        (
            "TYPE BODY EMPLOYEE_T AS\nEND;",
            "APP",
            "EMPLOYEE_T",
            "TYPE BODY",
            "CREATE OR REPLACE TYPE BODY APP.EMPLOYEE_T AS\nEND;",
        ),
        (
            "TRIGGER TRG_A\nBEFORE INSERT ON APP.T FOR EACH ROW\nBEGIN NULL; END;",
            "APP",
            "TRG_A",
            "TRIGGER",
            "CREATE OR REPLACE TRIGGER APP.TRG_A\nBEFORE INSERT ON APP.T FOR EACH ROW\nBEGIN NULL; END;",
        ),
        (
            "EDITIONABLE FUNCTION \"MixedCase\" RETURN NUMBER AS BEGIN RETURN 1; END;",
            "APP",
            "MixedCase",
            "FUNCTION",
            "CREATE OR REPLACE EDITIONABLE FUNCTION APP.\"MixedCase\" RETURN NUMBER AS BEGIN RETURN 1; END;",
        ),
        (
            "PACKAGE APP.EMP_API AS\nEND;",
            "APP",
            "EMP_API",
            "PACKAGE",
            "CREATE OR REPLACE PACKAGE APP.EMP_API AS\nEND;",
        ),
        (
            "\n  CREATE OR REPLACE FORCE EDITIONABLE VIEW APP.V_EMP (\"ID\") AS SELECT 1 FROM DUAL",
            "APP",
            "V_EMP",
            "VIEW",
            "CREATE OR REPLACE FORCE EDITIONABLE VIEW APP.V_EMP (\"ID\") AS SELECT 1 FROM DUAL",
        ),
    ];
    for (stored, owner, name, object_type, expected) in cases {
        assert_eq!(
            qualify(stored, owner, name, object_type).expect("stored header binds"),
            expected,
            "{object_type} {owner}.{name}"
        );
    }
}

#[test]
fn a_header_naming_another_target_is_refused() {
    let refusals = [
        // A patch that renames the unit re-targets the statement.
        ("PROCEDURE P_OTHER AS BEGIN NULL; END;", "PROCEDURE"),
        // An explicit qualifier for a different owner.
        ("PROCEDURE SYS.P_SRC AS BEGIN NULL; END;", "PROCEDURE"),
        // The stored text does not start with the object type.
        (
            "FUNCTION P_SRC RETURN NUMBER AS BEGIN RETURN 1; END;",
            "PROCEDURE",
        ),
        // A name that merely starts like the object's name.
        ("PROCEDURE P_SRC_2 AS BEGIN NULL; END;", "PROCEDURE"),
        // A keyword glued to the name is not the keyword.
        ("PROCEDUREP_SRC AS BEGIN NULL; END;", "PROCEDURE"),
    ];
    for (stored, object_type) in refusals {
        let err = qualify(stored, "W4O_X", "P_SRC", object_type).expect_err(stored);
        assert_eq!(err.error_class, ErrorClass::InvalidArguments, "{stored}");
        assert!(
            err.message.contains("must keep the header of"),
            "{stored}: {}",
            err.message
        );
    }
}

fn exec_dispatcher() -> (OracleDispatcher, Arc<ExecState>) {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
    );
    (dispatcher, state)
}

fn patch_args(owner: &str) -> Value {
    json!({
        "owner": owner,
        "name": "EMP_API",
        "object_type": "PACKAGE_BODY",
        "old_text": "NULL",
        "new_text": "1",
    })
}

#[test]
fn applied_patch_executes_the_owner_qualified_statement_and_reports_it() {
    let (dispatcher, state) = exec_dispatcher();
    let preview = dispatcher
        .dispatch("oracle_patch_source", patch_args("APP"))
        .expect("patch preview succeeds");
    let mut execute = patch_args("APP");
    execute["execute"] = json!(true);
    execute["confirm"] = preview["confirmation"]["confirm"].clone();
    let out = dispatcher
        .dispatch("oracle_patch_source", execute)
        .expect("patch execute succeeds");

    let executed = state.executed.lock().expect("executed SQL");
    assert_eq!(executed.len(), 1);
    // The mock's stored text has no owner on line 1, exactly like ALL_SOURCE.
    assert!(
        executed[0]
            .0
            .starts_with("CREATE OR REPLACE PACKAGE BODY APP.EMP_API AS"),
        "{}",
        executed[0].0
    );
    assert_eq!(
        out["executed_target"],
        json!({
            "owner": "APP",
            "name": "EMP_API",
            "object_type": "PACKAGE BODY",
            "statement_head": "CREATE OR REPLACE PACKAGE BODY APP.EMP_API AS",
        })
    );
}

#[test]
fn a_confirmation_minted_for_one_owner_cannot_apply_to_another() {
    let (dispatcher, state) = exec_dispatcher();
    let preview = dispatcher
        .dispatch("oracle_patch_source", patch_args("APP"))
        .expect("patch preview succeeds");
    let mut execute = patch_args("OTHER");
    execute["execute"] = json!(true);
    execute["confirm"] = preview["confirmation"]["confirm"].clone();
    let err = dispatcher
        .dispatch("oracle_patch_source", execute)
        .expect_err("a grant for APP.EMP_API must not apply to OTHER.EMP_API");
    assert!(
        matches!(
            err.error_class,
            ErrorClass::ChallengeRequired | ErrorClass::RepreviewRequired
        ),
        "{:?}: {}",
        err.error_class,
        err.message
    );
    assert!(
        state.executed.lock().expect("executed SQL").is_empty(),
        "nothing may execute on a mismatched confirmation"
    );
}
