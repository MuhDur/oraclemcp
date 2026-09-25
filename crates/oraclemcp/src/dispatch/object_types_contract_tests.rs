use super::*;
use serde_json::json;

#[test]
fn object_type_out_of_enum_is_invalid_arguments() {
    let error = validate_enum_arguments(
        "oracle_get_ddl",
        &json!({
            "object_type": "NOT_A_TYPE",
            "name": "T"
        }),
    )
    .expect_err("unknown object types are rejected by the dispatcher enum gate");
    assert_eq!(error.error_class, ErrorClass::InvalidArguments);
    assert!(error.message.contains("object_type must be one of"));
    assert!(error.message.contains("TABLE"));
    assert!(error.message.contains("VIEW"));
}

#[test]
fn object_type_lowercase_is_invalid_arguments_naming_uppercase() {
    let error = validate_enum_arguments(
        "oracle_get_source",
        &json!({
            "name": "V",
            "object_type": "view"
        }),
    )
    .expect_err("object type values are exact uppercase enum members");
    assert_eq!(error.error_class, ErrorClass::InvalidArguments);
    assert!(error.message.contains("VIEW"));
}

#[test]
fn orient_include_json_string_is_invalid_arguments_issue_41() {
    let error = validate_json_array_arguments("oracle_orient", &json!({"include": "[\"schema\"]"}))
        .expect_err("a JSON string is not an array argument");
    assert_eq!(error.error_class, ErrorClass::InvalidArguments);
    assert!(error.message.contains("include must be a JSON array"));
}

#[test]
fn search_objects_object_type_and_object_types_conflict() {
    let error = validate_enum_arguments(
        "oracle_search_objects",
        &json!({"object_type": "TABLE", "object_types": ["TABLE"]}),
    )
    .expect_err("the scalar alias and array filter are mutually exclusive");
    assert_eq!(error.error_class, ErrorClass::InvalidArguments);
    assert!(error.message.contains("cannot be supplied together"));
}

#[test]
fn search_objects_object_types_json_string_is_invalid_arguments() {
    let error = validate_enum_arguments(
        "oracle_search_objects",
        &json!({"object_types": "[\"TABLE\",\"VIEW\"]"}),
    )
    .expect_err("a JSON string is not a JSON array");
    assert_eq!(error.error_class, ErrorClass::InvalidArguments);
    assert!(error.message.contains("object_types must be a JSON array"));
}
