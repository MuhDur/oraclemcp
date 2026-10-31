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

struct CanonicalSearchCatalog;

#[async_trait::async_trait(?Send)]
impl OracleConnection for CanonicalSearchCatalog {
    fn backend(&self) -> oraclemcp_db::OracleBackend {
        oraclemcp_db::OracleBackend::RustOracle
    }
    async fn close(&self, _: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn ping(&self, _: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn describe(&self, _: &Cx) -> Result<oraclemcp_db::OracleConnectionInfo, DbError> {
        Ok(Default::default())
    }
    async fn query_rows(
        &self,
        _: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<oraclemcp_db::OracleRow>, DbError> {
        assert_eq!(
            sql,
            oraclemcp_db::CatalogQueryId::ListObjectsByTypes.spec().sql,
            "filtered searches must use the canonical multi-type query"
        );
        assert_eq!(binds[0], OracleBind::from("APP"));
        assert_eq!(binds[1], OracleBind::from("TABLE"));
        assert!(binds[2] == OracleBind::Null || binds[2] == OracleBind::from("VIEW"));
        Ok(vec![oraclemcp_db::OracleRow {
            columns: [
                ("OWNER", "APP"),
                ("OBJECT_NAME", "T"),
                ("OBJECT_TYPE", "TABLE"),
                ("STATUS", "VALID"),
            ]
            .into_iter()
            .map(|(name, value)| {
                (
                    name.into(),
                    oraclemcp_db::OracleCell::new("VARCHAR2", Some(value.into())),
                )
            })
            .collect(),
        }])
    }
    async fn execute(&self, _: &Cx, sql: &str, _: &[OracleBind]) -> Result<u64, DbError> {
        assert_eq!(sql, oraclemcp_guard::SET_TRANSACTION_READ_ONLY);
        Ok(0)
    }
    async fn commit(&self, _: &Cx) -> Result<(), DbError> {
        panic!("search cannot commit")
    }
    async fn rollback(&self, _: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

#[test]
fn search_objects_deprecated_scalar_returns_only_the_canonical_filter_echo() {
    let dispatcher = OracleDispatcher::new(Box::new(CanonicalSearchCatalog));
    for (arguments, expected) in [
        (
            json!({"owner":"APP","detail_level":"names","object_type":"TABLE"}),
            json!(["TABLE"]),
        ),
        (
            json!({"owner":"APP","detail_level":"names","object_types":["TABLE","VIEW"]}),
            json!(["TABLE", "VIEW"]),
        ),
    ] {
        let result = dispatcher
            .dispatch("oracle_search_objects", arguments)
            .expect("canonical or deprecated search filter");
        assert_eq!(result["object_types"], expected);
        assert!(
            result.get("object_type").is_none(),
            "top-level filter echo must use only the canonical array"
        );
        assert_eq!(
            result["results"][0]["object_type"], "TABLE",
            "per-object identity is retained"
        );
    }
}

#[test]
fn fleet_search_objects_returns_only_the_canonical_filter_echo() {
    let types = vec!["TABLE".to_owned(), "VIEW".to_owned()];
    let result = fleet_catalog_response(Vec::new(), Some("APP"), Some(&types), None, 20);
    assert_eq!(result["object_types"], json!(["TABLE", "VIEW"]));
    assert!(result.get("object_type").is_none());
}
