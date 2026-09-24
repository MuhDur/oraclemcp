//! Metamorphic checks at the served read boundary, with the semantic catalog
//! model in the parent test module answering every proof query.

use super::*;
use oraclemcp_guard::resolver::QueryBlockKind;
use oraclemcp_guard::semantic_read_plan_checked;
use proptest::prelude::*;

#[derive(Clone, Copy)]
struct Base {
    id: &'static str,
    sql: &'static str,
    refused: bool,
    virtual_user_function: bool,
}

const BASES: &[Base] = &[
    Base {
        id: "ordinary",
        sql: "SELECT id FROM APP.ORDERS",
        refused: false,
        virtual_user_function: false,
    },
    Base {
        id: "view",
        sql: "SELECT id FROM APP.SIDE_VIEW",
        refused: true,
        virtual_user_function: false,
    },
    Base {
        id: "vpd",
        sql: "SELECT id FROM APP.POLICY_TABLE",
        refused: true,
        virtual_user_function: false,
    },
    Base {
        id: "virtual_udf",
        sql: "SELECT id FROM APP.ORDERS",
        refused: true,
        virtual_user_function: true,
    },
    Base {
        id: "fga_handler",
        sql: "SELECT id FROM APP.ORDERS",
        refused: true,
        virtual_user_function: false,
    },
    Base {
        id: "zero_arg_function",
        sql: "SELECT APP.DANGEROUS_FN FROM APP.ORDERS",
        refused: true,
        virtual_user_function: false,
    },
    Base {
        id: "db_link",
        sql: "SELECT id FROM APP.ORDERS@REMOTE_LINK",
        refused: true,
        virtual_user_function: false,
    },
    Base {
        id: "i28_alias_callable",
        sql: "SELECT APP.DANGEROUS_FN AS ID FROM APP.ORDERS ORDER BY ID",
        refused: true,
        virtual_user_function: false,
    },
    Base {
        id: "i29_qualified_using",
        sql: "SELECT o.ID FROM APP.ORDERS o JOIN APP.ORDERS p USING (ID)",
        refused: true,
        virtual_user_function: false,
    },
    Base {
        id: "i31_wrong_owner",
        sql: "SELECT OTHER.ORDERS.ID AS ID FROM APP.ORDERS",
        refused: true,
        virtual_user_function: false,
    },
    Base {
        id: "i32_object_method",
        sql: "SELECT e.ADDRESS.CITY() AS ID FROM APP.ORDERS e",
        refused: true,
        virtual_user_function: false,
    },
    Base {
        id: "i32_unproved_json_path",
        sql: "SELECT j.BAD_DOC.customer.id AS ID FROM APP.ORDERS j",
        refused: true,
        virtual_user_function: false,
    },
    Base {
        id: "i33_nextval",
        sql: "SELECT APP.SEQ.NEXTVAL AS ID FROM APP.ORDERS",
        refused: true,
        virtual_user_function: false,
    },
];

const WRAPPERS: &[&str] = &[
    "exists",
    "in",
    "scalar_select",
    "scalar_where",
    "cte",
    "union_left",
    "union_right",
    "derived",
    "lateral",
    "join",
    "not_exists",
    "any",
    "all",
];

fn wrap(sql: &str, wrapper: &str) -> String {
    match wrapper {
        "exists" => format!("SELECT o.id FROM APP.ORDERS o WHERE EXISTS ({sql})"),
        "in" => format!("SELECT o.id FROM APP.ORDERS o WHERE o.id IN ({sql})"),
        "scalar_select" => format!("SELECT ({sql}) FROM APP.ORDERS o"),
        "scalar_where" => format!("SELECT o.id FROM APP.ORDERS o WHERE o.id = ({sql})"),
        "cte" => format!("WITH w AS ({sql}) SELECT id FROM w"),
        "union_left" => format!("{sql} UNION ALL SELECT id FROM APP.ORDERS"),
        "union_right" => format!("SELECT id FROM APP.ORDERS UNION ALL {sql}"),
        "derived" => format!("SELECT d.id FROM ({sql}) d"),
        "lateral" => format!("SELECT o.id FROM APP.ORDERS o, LATERAL ({sql}) d"),
        "join" => format!("SELECT o.id FROM APP.ORDERS o JOIN ({sql}) d ON 1 = 1"),
        "not_exists" => format!("SELECT o.id FROM APP.ORDERS o WHERE NOT EXISTS ({sql})"),
        "any" => format!("SELECT o.id FROM APP.ORDERS o WHERE o.id = ANY ({sql})"),
        "all" => format!("SELECT o.id FROM APP.ORDERS o WHERE o.id = ALL ({sql})"),
        _ => unreachable!("closed wrapper grammar"),
    }
}

fn served(base: Base, sql: &str) -> (bool, usize, Option<ErrorClass>) {
    let (dispatcher, state) = semantic_dispatcher();
    if base.virtual_user_function {
        *state
            .virtual_column_default
            .lock()
            .expect("virtual column fixture lock") = Some("APP.CANARY_FN(\"LABEL\")".to_owned());
    }
    if base.id == "fga_handler" {
        *state.fga_handler_table.lock().expect("FGA fixture lock") = Some("ORDERS".to_owned());
    }
    let result = dispatcher.dispatch("oracle_query", json!({"sql": sql}));
    (
        result.is_ok(),
        state.caller_queries.load(Ordering::SeqCst),
        result.err().map(|error| error.error_class),
    )
}

fn check_wrap(base: Base, wrapper: &str, depth: usize) {
    let (base_admitted, base_calls, _) = served(base, base.sql);
    assert_eq!(
        base_admitted, !base.refused,
        "base fixture changed: {}",
        base.id
    );
    assert_eq!(
        base_calls,
        usize::from(base_admitted),
        "base IO: {}",
        base.id
    );
    let mut sql = base.sql.to_owned();
    for _ in 0..depth {
        sql = wrap(&sql, wrapper);
    }
    let (actual, calls, error_class) = served(base, &sql);
    let held = !base.refused || (!actual && calls == 0);
    if !held {
        write_executor_test_artifact(
            "guard_metamorphic_failure",
            &[json!({
                "case_id": format!("{}_{}_{}", base.id, wrapper, depth),
                "base": base.sql,
                "wrapper": wrapper,
                "expected": "refused; caller_queries=0",
                "actual": {"admitted": actual, "caller_queries": calls, "error_class": error_class},
            })],
        );
    }
    assert!(
        held,
        "refusal-to-allow flip: base={} wrapper={wrapper} depth={depth} sql={sql:?} admitted={actual} caller_queries={calls} error={error_class:?}",
        base.id
    );
    if actual {
        assert_eq!(calls, 1, "admitted read must have one caller query: {sql}");
        let base_plan = semantic_read_plan_checked(base.sql).expect("admitted base has plan");
        let wrapped_plan = semantic_read_plan_checked(&sql).expect("admitted wrapper has plan");
        for relation in &base_plan.relations {
            assert!(
                wrapped_plan.relations.contains(relation),
                "admitted wrapper lost row source {relation:?}: {sql}"
            );
        }
    }
}

#[test]
fn guard_metamorphic_wrap_never_turns_refusal_into_allow() {
    // The complete Cartesian product is deterministic; proptest below also
    // samples compositions that put different wrappers at each depth.
    for base in BASES {
        for wrapper in WRAPPERS {
            for depth in [1, 2] {
                check_wrap(*base, wrapper, depth);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]
    #[test]
    fn guard_metamorphic_composed_wrappers(base in 0..BASES.len(), first in 0..WRAPPERS.len(), second in 0..WRAPPERS.len()) {
        let base = BASES[base];
        let sql = wrap(&wrap(base.sql, WRAPPERS[first]), WRAPPERS[second]);
        let (admitted, calls, error) = served(base, &sql);
        if base.refused && (admitted || calls != 0) {
            write_executor_test_artifact("guard_metamorphic_failure", &[json!({
                "case_id": format!("{}_{}_{}", base.id, WRAPPERS[first], WRAPPERS[second]),
                "base": base.sql,
                "wrapper": [WRAPPERS[first], WRAPPERS[second]],
                "expected": "refused; caller_queries=0",
                "actual": {"admitted": admitted, "caller_queries": calls, "error_class": error},
            })]);
        }
        prop_assert!(!base.refused || (!admitted && calls == 0),
            "base={} wrappers={:?} sql={sql:?} admitted={admitted} caller_queries={calls} error={error:?}",
            base.id, [WRAPPERS[first], WRAPPERS[second]]);
    }
}

#[test]
fn guard_metamorphic_name_variants_preserve_verdict() {
    for (id, variants) in [
        (
            "ordinary",
            [
                "SELECT id FROM APP.ORDERS",
                "select id from app.orders",
                "SELECT \"ID\" FROM \"APP\".\"ORDERS\"",
                "SELECT id FROM /* name */ APP . ORDERS",
            ],
        ),
        (
            "view",
            [
                "SELECT id FROM APP.SIDE_VIEW",
                "select id from app.side_view",
                "SELECT \"ID\" FROM \"APP\".\"SIDE_VIEW\"",
                "SELECT id FROM /* name */ APP . SIDE_VIEW",
            ],
        ),
        (
            "vpd",
            [
                "SELECT id FROM APP.POLICY_TABLE",
                "select id from app.policy_table",
                "SELECT \"ID\" FROM \"APP\".\"POLICY_TABLE\"",
                "SELECT id FROM /* name */ APP . POLICY_TABLE",
            ],
        ),
    ] {
        let baseline = served(BASES[0], variants[0]);
        for sql in variants.iter().skip(1) {
            let actual = served(BASES[0], sql);
            assert_eq!(
                actual, baseline,
                "{id}: name-only variant changed verdict: {sql}"
            );
        }
    }
    for sql in [
        "SELECT o.id FROM APP.ORDERS o",
        "SELECT x.id FROM APP.ORDERS x",
    ] {
        assert!(served(BASES[0], sql).0, "alias rename: {sql}");
    }
    let qualified = served(BASES[0], "SELECT id FROM APP.ORDERS");
    for sql in ["SELECT id FROM ORDERS", "SELECT id FROM APP.ORDERS_ALIAS"] {
        assert_eq!(
            served(BASES[0], sql),
            qualified,
            "current-schema or synonym spelling changed verdict: {sql}"
        );
    }
}

fn top_level_only_gate(sql: &str) -> bool {
    let Ok(plan) = semantic_read_plan_checked(sql) else {
        return false;
    };
    !plan
        .blocks
        .iter()
        .filter(|block| matches!(block.kind, QueryBlockKind::Root))
        .flat_map(|block| &block.relations)
        .any(|relation| {
            relation
                .parts
                .last()
                .is_some_and(|part| part.text.eq_ignore_ascii_case("SIDE_VIEW"))
        })
}

fn ignore_base_objects_oracle(sql: &str) -> bool {
    // Pre-fix defect: root relation evidence is consulted, but nested base
    // objects are discarded before the side-effect oracle is called. The
    // empty list is then mistaken for proven purity.
    let Ok(plan) = semantic_read_plan_checked(sql) else {
        return false;
    };
    plan.blocks.len() > 1
        || !plan.relations.iter().any(|relation| {
            relation
                .parts
                .last()
                .is_some_and(|part| part.text.eq_ignore_ascii_case("SIDE_VIEW"))
        })
}

#[test]
fn guard_metamorphic_catches_top_level_only_gate() {
    let base = "SELECT id FROM APP.SIDE_VIEW";
    assert!(!top_level_only_gate(base));
    assert!(
        top_level_only_gate(&wrap(base, "derived")),
        "the planted root-only gate must flip when the view moves to a child block"
    );
    check_wrap(BASES[1], "derived", 1);
}

#[test]
fn guard_metamorphic_catches_ignore_base_objects_oracle() {
    let base = "SELECT id FROM APP.SIDE_VIEW";
    assert!(
        !ignore_base_objects_oracle(base),
        "planted oracle refuses the direct unsafe view"
    );
    assert!(
        ignore_base_objects_oracle(&wrap(base, "derived")),
        "planted oracle must flip when nested objects are discarded"
    );
    check_wrap(BASES[1], "derived", 1);
}

#[test]
fn guard_metamorphic_local_alias_shadowing_and_correlated_controls() {
    let unsafe_base = BASES
        .iter()
        .find(|base| base.id == "i29_qualified_using")
        .copied()
        .expect("qualified USING base");
    for sql in [
        "SELECT o.ID FROM APP.ORDERS o WHERE EXISTS (SELECT o.ID FROM APP.ORDERS o JOIN APP.ORDERS p USING (ID))",
        "SELECT o.ID FROM APP.ORDERS o WHERE EXISTS (SELECT m.ID FROM APP.ORDERS m WHERE EXISTS (SELECT o.ID FROM APP.ORDERS o JOIN APP.ORDERS p USING (ID)))",
    ] {
        let (admitted, calls, error) = served(unsafe_base, sql);
        assert!(
            !admitted && calls == 0,
            "locally bound qualified USING column escaped: {sql} error={error:?} calls={calls}"
        );
    }
    for sql in [
        "SELECT o.ID FROM APP.ORDERS o WHERE EXISTS (SELECT 1 FROM APP.ORDERS i WHERE i.ID = o.ID)",
        "SELECT o.ID FROM APP.ORDERS o WHERE EXISTS (SELECT m.ID FROM APP.ORDERS m WHERE EXISTS (SELECT 1 FROM APP.ORDERS i WHERE i.ID = o.ID AND i.ID = m.ID))",
        "SELECT ID FROM APP.ORDERS o JOIN APP.ORDERS p USING (ID)",
    ] {
        let (admitted, calls, error) = served(BASES[0], sql);
        assert!(
            admitted && calls == 1,
            "genuine correlation or unqualified USING must stay admitted: {sql} error={error:?} calls={calls}"
        );
    }
}

#[test]
fn cte_qualified_projection_and_order_are_served_reads() {
    let ordinary = BASES[0];
    let sql =
        "WITH p AS (SELECT ID, LABEL FROM APP.ORDERS) SELECT p.ID, p.LABEL FROM p ORDER BY p.ID";
    let (admitted, calls, error) = served(ordinary, sql);
    assert!(admitted, "CTE-qualified columns refused: {error:?}");
    assert_eq!(calls, 1);

    // The CTE exposes only its projected columns. A similarly spelled
    // qualified callable must remain refused before caller SQL reaches Oracle.
    let unsafe_sql = "WITH p AS (SELECT ID, LABEL FROM APP.ORDERS) SELECT p.DANGEROUS_FN FROM p";
    let (admitted, calls, error) = served(ordinary, unsafe_sql);
    assert!(!admitted, "unprojected CTE member admitted: {error:?}");
    assert_eq!(calls, 0);
}
