use super::args::QueryArgs;
use super::parse_args;
use oraclemcp_error::ErrorClass;
use serde_json::json;

#[test]
fn query_export_format_rejects_unknown_enum_as_invalid_arguments() {
    let error = parse_args::<QueryArgs>(
        "oracle_query",
        json!({
            "sql": "SELECT 1 FROM DUAL",
            "export": true,
            "export_format": "xml"
        }),
    )
    .err()
    .expect("unsupported export format must refuse");

    assert_eq!(error.error_class, ErrorClass::InvalidArguments);

    for export_format in ["csv", "json", "CSV", " JSON ", ""] {
        assert!(
            parse_args::<QueryArgs>(
                "oracle_query",
                json!({
                    "sql": "SELECT 1 FROM DUAL",
                    "export": true,
                    "export_format": export_format
                })
            )
            .is_ok(),
            "supported export format {export_format} should decode"
        );
    }
}
