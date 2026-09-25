#![forbid(unsafe_code)]

use asupersync::Cx;
use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp_db::{
    CatalogQueryId, DbError, OracleBackend, OracleBind, OracleCell, OracleConnection,
    OracleConnectionInfo, OracleRow,
};
use serde_json::json;

struct VisibleCatalogQueryMock;

fn row(columns: &[(&str, Option<&str>)]) -> OracleRow {
    OracleRow {
        columns: columns
            .iter()
            .map(|(name, value)| {
                (
                    (*name).to_owned(),
                    OracleCell::new("VARCHAR2", value.map(str::to_owned)),
                )
            })
            .collect(),
    }
}

fn string_bind(binds: &[OracleBind], index: usize) -> Option<&str> {
    match binds.get(index) {
        Some(OracleBind::String(value)) => Some(value),
        _ => None,
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for VisibleCatalogQueryMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            current_schema: Some("APP".to_owned()),
            session_user: Some("APP".to_owned()),
            current_edition: Some("ORA$BASE".to_owned()),
            ..Default::default()
        })
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        // The synthetic table has no FGA policy; both the bounded lookup and
        // the separate catalog-readability probe succeed with no rows.
        if sql == CatalogQueryId::FgaPoliciesForRelations32.spec().sql
            || sql == CatalogQueryId::FgaCatalogProof.spec().sql
        {
            return Ok(Vec::new());
        }
        if sql == CatalogQueryId::ClosureIdentity.spec().sql {
            return Ok(vec![row(&[
                ("DBID", Some("424242")),
                ("CONTAINER_NAME", Some("FREEPDB1")),
                ("EDITION_NAME", Some("ORA$BASE")),
            ])]);
        }
        if sql == CatalogQueryId::OlsInstallationEvidence.spec().sql {
            return Ok(vec![row(&[("VALUE", Some("FALSE"))])]);
        }
        if sql == CatalogQueryId::RedactionInstallationEvidence.spec().sql {
            return Ok(vec![row(&[("ADVANCED_SECURITY", Some("FALSE"))])]);
        }
        if sql == CatalogQueryId::ReadRasPolicies.spec().sql
            || sql == CatalogQueryId::ReadRedactionPolicies.spec().sql
        {
            return Ok(Vec::new());
        }
        let normalized = sql.to_ascii_lowercase();
        if normalized.contains("sys_context('userenv', 'session_user')") {
            return Ok(vec![row(&[
                ("SESSION_USER", Some("APP")),
                ("CURRENT_SCHEMA", Some("APP")),
                ("EDITION_NAME", Some("ORA$BASE")),
            ])]);
        }
        if normalized.contains("from session_roles") {
            return Ok(Vec::new());
        }
        if normalized.contains("count(*) as visible_policy_rows") {
            return Ok(vec![row(&[("VISIBLE_POLICY_ROWS", Some("1"))])]);
        }
        if normalized.contains("from all_objects") {
            let owner = string_bind(binds, 0).unwrap_or_default();
            let name = string_bind(binds, 1).unwrap_or_default();
            if owner == "APP" && name == "ORDERS" {
                return Ok(vec![row(&[
                    ("OWNER", Some("APP")),
                    ("OBJECT_NAME", Some("ORDERS")),
                    ("OBJECT_TYPE", Some("TABLE")),
                    ("OBJECT_ID", Some("42")),
                    ("STATUS", Some("VALID")),
                    ("EDITION_NAME", None),
                ])]);
            }
            return Ok(Vec::new());
        }
        if normalized.contains("from all_synonyms")
            || normalized.contains("from all_arguments")
            || normalized.contains("from all_tab_columns")
                && !normalized.contains("table_name = :2")
        {
            return Ok(Vec::new());
        }
        if normalized.contains("select policy_name from all_policies where rownum <= 1") {
            return Ok(vec![row(&[("POLICY_NAME", Some("VISIBLE_ELSEWHERE"))])]);
        }
        if normalized.contains("from all_policies") {
            return Ok(Vec::new());
        }
        if normalized.contains("from all_tab_cols") && normalized.contains("virtual_column = 'yes'")
        {
            return Ok(Vec::new());
        }
        if normalized.contains("from all_tab_cols") {
            return Ok(vec![row(&[("COLUMN_NAME", Some("ID"))])]);
        }
        if normalized.contains("from all_tab_columns") && normalized.contains("table_name = :2") {
            return Ok((string_bind(binds, 2) == Some("ID"))
                .then(|| row(&[("COLUMN_NAME", Some("ID")), ("COLUMN_ID", Some("1"))]))
                .into_iter()
                .collect());
        }
        Ok(vec![row(&[("ID", Some("1"))])])
    }

    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

#[test]
fn oracle_query_carries_vpd_rls_observation_on_successful_read() {
    let dispatcher = OracleDispatcher::new(Box::new(VisibleCatalogQueryMock));
    let out = dispatcher
        .dispatch("oracle_query", json!({"sql": "SELECT id FROM app.orders"}))
        .expect("ordinary read returns its observed rows");

    assert_eq!(out["row_count"], json!(1));
    assert_eq!(
        out["rls_vpd"]["status"],
        json!("no_visible_matching_policies"),
        "a successful read must carry explicit RLS/VPD observation metadata: {out}"
    );
    assert_eq!(
        out["rls_vpd"]["all_policies_probe"]["visibility"],
        json!("policy_rows_visible")
    );
}
