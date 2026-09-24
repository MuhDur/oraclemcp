use oraclemcp_guard::scoped_grant::{
    GrantPredicateBuilder, PredicateColumnType, PredicateConjunctRequest,
    PredicateExpressionRequest, PredicateInputValue, PredicateRefusal, ResolvedColumns,
    compose_where, render_ast,
};
use proptest::prelude::*;
use sqlparser::ast::{BinaryOperator, Expr, Ident, Value};

fn columns() -> ResolvedColumns {
    ResolvedColumns::new([
        (
            "ID".to_owned(),
            PredicateColumnType::Number {
                precision: Some(10),
                scale: Some(0),
            },
        ),
        (
            "TENANT_ID".to_owned(),
            PredicateColumnType::Number {
                precision: Some(10),
                scale: Some(0),
            },
        ),
        (
            "STATUS".to_owned(),
            PredicateColumnType::Varchar2 {
                max_bytes: 20,
                max_chars: 20,
            },
        ),
        ("CREATED_AT".to_owned(), PredicateColumnType::Date),
        (
            "UPDATED_AT".to_owned(),
            PredicateColumnType::Timestamp {
                fractional_precision: 6,
            },
        ),
    ])
    .expect("fixture metadata is valid")
}

fn number(text: &str) -> PredicateInputValue {
    PredicateInputValue::Number(text.to_owned())
}

fn string(text: &str) -> PredicateInputValue {
    PredicateInputValue::String(text.to_owned())
}

fn build(
    requests: &[PredicateConjunctRequest],
) -> Result<oraclemcp_guard::scoped_grant::GrantPredicateV1, PredicateRefusal> {
    GrantPredicateBuilder::from_request(requests, &columns())
}

fn expression(kind: PredicateExpressionRequest) -> PredicateInputValue {
    PredicateInputValue::Expression(kind)
}

#[test]
fn grant_predicate_accepts_each_allowed_operator() {
    let requests = [
        PredicateConjunctRequest::comparison("ID", "eq", number("1")),
        PredicateConjunctRequest::comparison("ID", "ne", number("2")),
        PredicateConjunctRequest::comparison("ID", "lt", number("3")),
        PredicateConjunctRequest::comparison("ID", "le", number("4")),
        PredicateConjunctRequest::comparison("ID", "gt", number("5")),
        PredicateConjunctRequest::comparison("ID", "ge", number("6")),
        PredicateConjunctRequest::in_list("ID", vec![number("7"), number("8")]),
        PredicateConjunctRequest::between("ID", number("9"), number("10")),
        PredicateConjunctRequest::is_null("STATUS", false),
        PredicateConjunctRequest::is_null("STATUS", true),
    ];
    let predicate = build(&requests).expect("all documented operators are accepted");
    let (ast, binds) = render_ast(&predicate);
    assert_eq!(binds.len(), 10);
    assert_eq!(
        oraclemcp_guard::scoped_grant::predicate::parse_rendered_ast(&ast),
        Ok(ast)
    );
}

#[test]
fn grant_predicate_rejects_or_and_not() {
    for op in ["or", "not"] {
        let request = PredicateConjunctRequest::comparison("ID", op, number("1"));
        assert_eq!(build(&[request]), Err(PredicateRefusal::OrNotUnsupported));
    }
    for value in [
        expression(PredicateExpressionRequest::Or),
        expression(PredicateExpressionRequest::Not),
    ] {
        let request = PredicateConjunctRequest::comparison("ID", "eq", value);
        assert_eq!(build(&[request]), Err(PredicateRefusal::OrNotUnsupported));
    }
}

#[test]
fn grant_predicate_rejects_subquery_value() {
    let request = PredicateConjunctRequest::comparison(
        "ID",
        "eq",
        expression(PredicateExpressionRequest::Subquery),
    );
    assert_eq!(build(&[request]), Err(PredicateRefusal::SubqueryRefused));
}

#[test]
fn grant_predicate_rejects_function_value() {
    let request = PredicateConjunctRequest::comparison(
        "ID",
        "eq",
        expression(PredicateExpressionRequest::Function),
    );
    assert_eq!(build(&[request]), Err(PredicateRefusal::FunctionRefused));
}

#[test]
fn grant_predicate_rejects_column_to_column() {
    let request = PredicateConjunctRequest::comparison(
        "ID",
        "eq",
        expression(PredicateExpressionRequest::Column("TENANT_ID".to_owned())),
    );
    assert_eq!(
        build(&[request]),
        Err(PredicateRefusal::ColumnToColumnRefused)
    );
}

#[test]
fn grant_predicate_rejects_in_list_over_1000_and_empty() {
    let empty = PredicateConjunctRequest::in_list("ID", vec![]);
    assert_eq!(build(&[empty]), Err(PredicateRefusal::InListEmpty));

    let oversized = PredicateConjunctRequest::in_list(
        "ID",
        (0..=1000).map(|value| number(&value.to_string())).collect(),
    );
    assert_eq!(
        build(&[oversized]),
        Err(PredicateRefusal::InListTooLarge { len: 1001 })
    );

    let boundary = PredicateConjunctRequest::in_list(
        "ID",
        (0..1000).map(|value| number(&value.to_string())).collect(),
    );
    assert!(build(&[boundary]).is_ok());
}

#[test]
fn grant_predicate_rejects_type_mismatch_and_unknown_column() {
    let text_for_number = PredicateConjunctRequest::comparison("ID", "eq", string("913377"));
    assert!(matches!(
        build(&[text_for_number]),
        Err(PredicateRefusal::TypeMismatch { column, expected: "NUMBER" }) if column == "ID"
    ));
    let unknown = PredicateConjunctRequest::comparison("NO_SUCH_COLUMN", "eq", number("1"));
    assert!(matches!(
        build(&[unknown]),
        Err(PredicateRefusal::UnknownColumn { column }) if column == "NO_SUCH_COLUMN"
    ));
}

#[test]
fn grant_predicate_uses_typed_date_timestamp_and_checks_number_shape() {
    assert!(
        build(&[PredicateConjunctRequest::comparison(
            "CREATED_AT",
            "eq",
            string("2024-02-29T23:59:59"),
        )])
        .is_ok()
    );
    assert!(
        build(&[PredicateConjunctRequest::comparison(
            "UPDATED_AT",
            "eq",
            string("2024-02-29T23:59:59.123456"),
        )])
        .is_ok()
    );
    for invalid in [
        "2023-02-29T00:00:00",
        "2024-01-01T24:00:00",
        "2024-01-01T00:00:00Z",
    ] {
        assert!(matches!(
            build(&[PredicateConjunctRequest::comparison(
                "UPDATED_AT",
                "eq",
                string(invalid),
            )]),
            Err(PredicateRefusal::InvalidValue)
        ));
    }
    assert!(matches!(
        build(&[PredicateConjunctRequest::comparison(
            "ID",
            "eq",
            number("1.1")
        )]),
        Err(PredicateRefusal::TypeMismatch { .. })
    ));
    assert!(matches!(
        build(&[PredicateConjunctRequest::comparison(
            "ID",
            "eq",
            number("12345678901")
        )]),
        Err(PredicateRefusal::TypeMismatch { .. })
    ));
    assert!(matches!(
        build(&[PredicateConjunctRequest::comparison(
            "STATUS",
            "eq",
            string("a string longer than twenty")
        )]),
        Err(PredicateRefusal::TypeMismatch { .. })
    ));
}

#[test]
fn grant_predicate_handles_unconstrained_number_and_negative_scale_zero() {
    let unconstrained = ResolvedColumns::new([(
        "AMOUNT".to_owned(),
        PredicateColumnType::Number {
            precision: None,
            scale: None,
        },
    )])
    .expect("valid NUMBER metadata");
    assert!(
        GrantPredicateBuilder::from_request(
            &[PredicateConjunctRequest::comparison(
                "AMOUNT",
                "eq",
                number("0.125"),
            )],
            &unconstrained,
        )
        .is_ok()
    );

    let negative_scale = ResolvedColumns::new([(
        "ROUNDED_AMOUNT".to_owned(),
        PredicateColumnType::Number {
            precision: Some(3),
            scale: Some(-2),
        },
    )])
    .expect("valid negative scale metadata");
    assert!(
        GrantPredicateBuilder::from_request(
            &[PredicateConjunctRequest::comparison(
                "ROUNDED_AMOUNT",
                "eq",
                number("0"),
            )],
            &negative_scale,
        )
        .is_ok()
    );
}

#[test]
fn grant_predicate_rejects_operator_synonyms_case_and_quoted_tokens() {
    for op in [
        "=", "==", "!=", "<>", "EQ", "Eq", "equals", "IS NULL", "`eq`", "\"eq\"",
    ] {
        let request = PredicateConjunctRequest::comparison("ID", op, number("1"));
        assert_eq!(
            build(&[request]),
            Err(PredicateRefusal::InvalidOperator),
            "{op:?}"
        );
    }
}

#[test]
fn grant_predicate_rejects_null_comparison_and_reserved_bind_name() {
    let null = PredicateConjunctRequest::comparison("ID", "eq", PredicateInputValue::Null);
    assert_eq!(build(&[null]), Err(PredicateRefusal::NullComparison));
    let reserved = PredicateConjunctRequest::comparison(
        "ID",
        "eq",
        expression(PredicateExpressionRequest::Bind(":OmCp_G7".to_owned())),
    );
    assert_eq!(build(&[reserved]), Err(PredicateRefusal::ReservedBindName));
}

#[test]
fn grant_predicate_canonicalizes_in_duplicates_and_never_inlines_canary() {
    let request = PredicateConjunctRequest::in_list(
        "ID",
        vec![number("913377"), number("2"), number("913377")],
    );
    let predicate = build(&[request]).expect("valid IN request");
    let (ast, binds) = render_ast(&predicate);
    assert_eq!(binds.len(), 2);
    assert!(!ast.to_string().contains("913377"));
    assert_eq!(
        binds.iter().map(|bind| bind.name()).collect::<Vec<_>>(),
        ["omcp_g1", "omcp_g2"]
    );
}

#[test]
fn compose_where_emits_three_nested_conjuncts() {
    let caller = Expr::Identifier(Ident::with_quote('"', "CALLER_FILTER"));
    let policy = Expr::Identifier(Ident::with_quote('"', "POLICY_FILTER"));
    let grant = Expr::Identifier(Ident::with_quote('"', "GRANT_FILTER"));
    let composed = compose_where(Some(caller.clone()), Some(policy.clone()), grant.clone());
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::And,
        right,
    } = &composed
    else {
        panic!("outer node must be AND");
    };
    assert_eq!(right.as_ref(), &Expr::Nested(Box::new(grant)));
    let Expr::Nested(first_pair) = left.as_ref() else {
        panic!("left pair must remain parenthesized");
    };
    let Expr::BinaryOp {
        left: caller_part,
        op: BinaryOperator::And,
        right: policy_part,
    } = first_pair.as_ref()
    else {
        panic!("caller and policy must be the left pair");
    };
    assert_eq!(caller_part.as_ref(), &Expr::Nested(Box::new(caller)));
    assert_eq!(policy_part.as_ref(), &Expr::Nested(Box::new(policy)));
}

fn nested(expression: Expr) -> Expr {
    Expr::Nested(Box::new(expression))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, ..ProptestConfig::default() })]

    #[test]
    fn prop_composed_where_implies_p_and_q(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let payload = bytes.into_iter().map(|byte| char::from(32 + byte % 95)).collect::<String>();
        let caller = Expr::Value(Value::SingleQuotedString(payload).into());
        let policy = Expr::Identifier(Ident::with_quote('"', "TENANT_ID"));
        let grant = Expr::Identifier(Ident::with_quote('"', "ID"));
        let composed = compose_where(Some(caller.clone()), Some(policy.clone()), grant.clone());

        let Expr::BinaryOp { left, op: BinaryOperator::And, right } = composed else {
            prop_assert!(false, "composed root was not AND");
            return Ok(());
        };
        prop_assert_eq!(*right, nested(grant));
        let Expr::Nested(first_pair) = *left else {
            prop_assert!(false, "left pair lost parentheses");
            return Ok(());
        };
        let Expr::BinaryOp { left: caller_part, op: BinaryOperator::And, right: policy_part } = *first_pair else {
            prop_assert!(false, "caller-policy pair was not AND");
            return Ok(());
        };
        prop_assert_eq!(*caller_part, nested(caller));
        prop_assert_eq!(*policy_part, nested(policy));
    }
}
