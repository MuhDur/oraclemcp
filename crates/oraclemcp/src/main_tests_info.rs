//! Build metadata tests for the `oraclemcp info` payload.

use super::*;

#[test]
fn info_payload_reports_exact_driver_and_optional_engine_versions() {
    let info = info_payload();
    assert_eq!(
        info["driver_version"],
        serde_json::json!(oraclemcp_db::DRIVER_VERSION)
    );
    assert_eq!(
        info["engine"],
        serde_json::json!(cfg!(feature = "plsql-intelligence"))
    );
    if cfg!(feature = "plsql-intelligence") {
        assert_eq!(
            info["engine_version"],
            serde_json::json!(env!("OMCP_BUILD_PLSQL_ENGINE_VERSION"))
        );
    } else {
        assert!(info["engine_version"].is_null());
    }
}
