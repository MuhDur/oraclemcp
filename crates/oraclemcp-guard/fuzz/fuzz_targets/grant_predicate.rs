#![no_main]

use libfuzzer_sys::fuzz_target;
use oraclemcp_guard::scoped_grant::{
    predicate::{parse_rendered_ast, MAX_PREDICATE_IN_VALUES},
    render_ast, GrantPredicateBuilder, PredicateColumnType, PredicateConjunctRequest,
    PredicateInputValue, ResolvedColumns,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let (op, value) = text.split_once('\t').unwrap_or((text.as_ref(), "913377"));
    if op.len() > 64 || value.len() > 256 {
        return;
    }

    let columns = match ResolvedColumns::new([
        (
            "ID".to_owned(),
            PredicateColumnType::Number {
                precision: Some(38),
                scale: Some(0),
            },
        ),
        (
            "STATUS".to_owned(),
            PredicateColumnType::Varchar2 {
                max_bytes: 256,
                max_chars: 256,
            },
        ),
    ]) {
        Ok(columns) => columns,
        Err(_) => return,
    };
    let request = match op {
        "is_null" => PredicateConjunctRequest::is_null("STATUS", false),
        "is_not_null" => PredicateConjunctRequest::is_null("STATUS", true),
        "in" => PredicateConjunctRequest::in_list(
            "ID",
            vec![PredicateInputValue::Number(value.to_owned())],
        ),
        "between" => PredicateConjunctRequest::between(
            "ID",
            PredicateInputValue::Number("1".to_owned()),
            PredicateInputValue::Number("2".to_owned()),
        ),
        _ => PredicateConjunctRequest::comparison(
            "ID",
            op,
            PredicateInputValue::Number(value.to_owned()),
        ),
    };
    let result = GrantPredicateBuilder::from_request(&[request], &columns);
    if let Ok(predicate) = result {
        let (ast, binds) = render_ast(&predicate);
        assert!(binds.len() <= MAX_PREDICATE_IN_VALUES);
        for (index, bind) in binds.iter().enumerate() {
            assert_eq!(bind.name(), format!("omcp_g{}", index + 1));
        }
        assert_eq!(parse_rendered_ast(&ast), Ok(ast.clone()));
        if value == "913377" {
            assert!(!ast.to_string().contains(value));
        }
    }
});
