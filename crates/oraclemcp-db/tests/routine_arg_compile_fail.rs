//! R1 release gate: `OracleRoutineArg` is adapter-internal routine plumbing and
//! must not become an agent-facing serde input type.

#[test]
fn routine_arg_is_not_deserialize() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/routine_arg_is_not_deserialize.rs");
}
