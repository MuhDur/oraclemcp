//! C2.4: end-to-end `oracle_orient` coverage against a live Oracle XE.
//!
//! The DB crate proves each bounded dictionary reader independently. This test
//! proves the public dispatcher assembles that evidence into one guarded,
//! cacheable orientation snapshot without accepting caller SQL.
#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use asupersync::runtime::RuntimeBuilder;
use asupersync::{Cx, Outcome};
use oraclemcp::dispatch::{
    McpExposurePolicy, OracleDispatcher, ProfileConnectionBundle, ProfileConnector,
    ProfileDrainState, ProfileGenerationLease,
};
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::{DispatchContext, ToolDispatch};
use oraclemcp_db::{OracleBind, OracleConnectOptions, OracleConnection, RustOracleConnection};
use oraclemcp_guard::{OperatingLevel, SessionLevelState};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

const PARENT: &str = "ORACLEMCP_C2_ORIENT_LIVE_PARENT";
const CHILD: &str = "ORACLEMCP_C2_ORIENT_LIVE_CHILD";
const FOREIGN_KEY: &str = "ORACLEMCP_C2_ORIENT_LIVE_FK";

fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("current-thread runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("live-XE runtime installs a request Cx");
        body(cx).await
    })
}

fn test_opts() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN")
            .unwrap_or_else(|_| "//localhost:1521/FREEPDB1".to_owned()),
        username: Some(
            std::env::var("ORACLEMCP_TEST_USER").unwrap_or_else(|_| "system".to_owned()),
        ),
        password: Some(
            std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap_or_else(|_| "test_password".to_owned()),
        ),
        call_timeout: Some(Duration::from_secs(20)),
        ..Default::default()
    }
}

async fn connect_or_skip(cx: &Cx, test_name: &str) -> Option<RustOracleConnection> {
    match RustOracleConnection::connect(cx, test_opts()).await {
        Ok(conn) => Some(conn),
        Err(error) => {
            eprintln!(
                "[live-xe] SKIP {test_name}: no reachable Oracle or prerequisite missing ({error}); \
                 set ORACLEMCP_TEST_DSN / _USER / _PASSWORD"
            );
            None
        }
    }
}

async fn drop_fixture(cx: &Cx, conn: &RustOracleConnection) {
    for table in [CHILD, PARENT] {
        let _ = conn
            .execute(
                cx,
                &format!("DROP TABLE {table} PURGE"),
                &[] as &[OracleBind],
            )
            .await;
    }
}

fn fleet_test_config() -> OracleMcpConfig {
    OracleMcpConfig::from_toml_str(
        r#"
        default_profile = "live"

        [[profiles]]
        name = "live"
        connect_string = "live-test"

        [[profiles]]
        name = "offline"
        connect_string = "offline-test"
        "#,
    )
    .expect("live fleet test config is valid")
}

fn unreachable_test_opts() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: "//127.0.0.1:1/UNAVAILABLE".to_owned(),
        connect_timeout: Some(Duration::from_secs(1)),
        call_timeout: Some(Duration::from_secs(2)),
        ..test_opts()
    }
}

/// The public tool returns all C2.1-C2.3 evidence in one stable snapshot over
/// a synthetic schema. A second selector call is deliberately narrower but
/// must preserve its cached catalog revision and omit unrequested sections.
#[test]
fn oracle_orient_assembles_live_schema_fk_hot_freshness_and_ddl() {
    run_with_cx(|cx| async move {
        let test_name = "oracle_orient_assembles_live_schema_fk_hot_freshness_and_ddl";
        let Some(setup) = connect_or_skip(&cx, test_name).await else {
            return;
        };
        setup.set_call_timeout(Some(Duration::from_secs(30))).ok();
        drop_fixture(&cx, &setup).await;

        if let Err(error) = setup
            .execute(
                &cx,
                &format!(
                    "CREATE TABLE {PARENT} ( \
                     id NUMBER NOT NULL, tenant_id NUMBER NOT NULL, \
                     CONSTRAINT ORACLEMCP_C2_ORIENT_LIVE_PK PRIMARY KEY (id, tenant_id) \
                     )"
                ),
                &[] as &[OracleBind],
            )
            .await
        {
            eprintln!("[live-xe] SKIP {test_name}: cannot create parent fixture ({error})");
            return;
        }
        if let Err(error) = setup
            .execute(
                &cx,
                &format!(
                    "CREATE TABLE {CHILD} ( \
                     id NUMBER PRIMARY KEY, parent_id NUMBER NOT NULL, \
                     parent_tenant_id NUMBER NOT NULL, value NUMBER, \
                     CONSTRAINT {FOREIGN_KEY} FOREIGN KEY (parent_id, parent_tenant_id) \
                     REFERENCES {PARENT} (id, tenant_id) \
                     )"
                ),
                &[] as &[OracleBind],
            )
            .await
        {
            eprintln!("[live-xe] SKIP {test_name}: cannot create child fixture ({error})");
            drop_fixture(&cx, &setup).await;
            return;
        }
        if let Err(error) = setup
            .execute(
                &cx,
                &format!("BEGIN DBMS_STATS.GATHER_TABLE_STATS(USER, '{CHILD}'); END;"),
                &[] as &[OracleBind],
            )
            .await
        {
            eprintln!("[live-xe] SKIP {test_name}: cannot gather fixture stats ({error})");
            drop_fixture(&cx, &setup).await;
            return;
        }
        setup
            .execute(
                &cx,
                &format!("INSERT INTO {PARENT} VALUES (1, 1)"),
                &[] as &[OracleBind],
            )
            .await
            .expect("insert FK parent fixture row");
        setup
            .execute(
                &cx,
                &format!("INSERT INTO {CHILD} VALUES (1, 1, 1, 1)"),
                &[] as &[OracleBind],
            )
            .await
            .expect("insert hot-object fixture row");
        setup
            .execute(
                &cx,
                &format!("UPDATE {CHILD} SET value = 2 WHERE id = 1"),
                &[] as &[OracleBind],
            )
            .await
            .expect("update hot-object fixture row");
        setup.commit(&cx).await.expect("commit fixture DML");
        if let Err(error) = setup
            .execute(
                &cx,
                "BEGIN DBMS_STATS.FLUSH_DATABASE_MONITORING_INFO; END;",
                &[] as &[OracleBind],
            )
            .await
        {
            eprintln!("[live-xe] SKIP {test_name}: cannot flush monitoring info ({error})");
            drop_fixture(&cx, &setup).await;
            return;
        }

        let owner = setup
            .describe(&cx)
            .await
            .ok()
            .and_then(|info| info.current_schema)
            .or_else(|| std::env::var("ORACLEMCP_TEST_USER").ok())
            .unwrap_or_else(|| "SYSTEM".to_owned())
            .to_ascii_uppercase();
        let Some(served) = connect_or_skip(&cx, test_name).await else {
            drop_fixture(&cx, &setup).await;
            return;
        };
        let dispatcher =
            OracleDispatcher::new_with_profile(Box::new(served), Some("live".to_owned()));
        let full = match ToolDispatch::dispatch(
            &dispatcher,
            &cx,
            DispatchContext::default(),
            "oracle_orient",
            json!({ "owner": owner }),
        )
        .await
        {
            Outcome::Ok(value) => value,
            other => panic!("live oracle_orient must succeed: {other:?}"),
        };
        assert!(full["schema"].as_array().is_some_and(|objects| {
            objects.iter().any(|object| object["object_name"] == PARENT)
                && objects.iter().any(|object| object["object_name"] == CHILD)
        }));
        let edge = full["fks"]
            .as_array()
            .and_then(|edges| {
                edges
                    .iter()
                    .find(|edge| edge["constraint_name"] == FOREIGN_KEY)
            })
            .expect("synthetic foreign key is present in assembled snapshot");
        assert_eq!(edge["columns"].as_array().map(Vec::len), Some(2));
        let hot = full["hot_objects"]
            .as_array()
            .and_then(|objects| objects.iter().find(|object| object["object_name"] == CHILD))
            .expect("synthetic DML is present in assembled hot-object feed");
        assert!(hot["inserts"].as_i64().is_some_and(|count| count >= 1));
        assert!(hot["updates"].as_i64().is_some_and(|count| count >= 1));
        assert!(full["freshness"]["latest_dml_time"].is_string());
        assert!(full["recent_ddl"].as_array().is_some_and(|objects| {
            objects.iter().any(|object| object["object_name"] == CHILD)
        }));

        let selected = match ToolDispatch::dispatch(
            &dispatcher,
            &cx,
            DispatchContext::default(),
            "oracle_orient",
            json!({ "owner": owner, "include": ["freshness", "ddl"] }),
        )
        .await
        {
            Outcome::Ok(value) => value,
            other => panic!("selected live oracle_orient must succeed: {other:?}"),
        };
        assert_eq!(selected["catalog_revision"], full["catalog_revision"]);
        assert!(selected.get("schema").is_none());
        assert!(selected.get("fks").is_none());
        assert!(selected.get("hot_objects").is_none());
        assert!(selected["freshness"].is_object());
        assert!(selected["recent_ddl"].is_array());

        drop_fixture(&cx, &setup).await;
    });
}

/// H1 exercises the public fleet path against one real profile and one
/// deliberately unreachable profile. The live lane proves the transient
/// connector path uses the configured profile's own session; the offline lane
/// must remain present as a typed status instead of failing or truncating the
/// whole call.
#[test]
fn oracle_orient_fleet_preserves_a_live_lane_when_another_is_unreachable() {
    run_with_cx(|cx| async move {
        let test_name = "oracle_orient_fleet_preserves_a_live_lane_when_another_is_unreachable";
        let Some(served) = connect_or_skip(&cx, test_name).await else {
            return;
        };
        let owner = served
            .describe(&cx)
            .await
            .ok()
            .and_then(|info| info.current_schema)
            .or_else(|| std::env::var("ORACLEMCP_TEST_USER").ok())
            .unwrap_or_else(|| "SYSTEM".to_owned())
            .to_ascii_uppercase();
        let config = fleet_test_config();
        let exposure = McpExposurePolicy::from_config(&config);
        let drain = ProfileDrainState::from_config(config);
        let connector: Arc<ProfileConnector> =
            Arc::new(|cx: &Cx, lease: &ProfileGenerationLease| {
                let opts = if lease.profile() == "live" {
                    test_opts()
                } else {
                    unreachable_test_opts()
                };
                Box::pin(async move {
                    RustOracleConnection::connect(cx, opts)
                        .await
                        .map(|conn| ProfileConnectionBundle::new(Box::new(conn), None))
                })
            });
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(served),
            Some("live".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadOnly, false),
            connector,
        )
        .with_mcp_exposure(exposure)
        .with_profile_drain_state(drain);

        let out = match ToolDispatch::dispatch(
            &dispatcher,
            &cx,
            DispatchContext::default(),
            "oracle_orient",
            json!({ "fleet": true, "owner": owner, "include": ["schema", "freshness"] }),
        )
        .await
        {
            Outcome::Ok(value) => value,
            other => panic!("fleet orientation must retain its live lane: {other:?}"),
        };

        assert_eq!(out["summary"]["profile_count"], json!(2));
        assert_eq!(out["summary"]["reachable_count"], json!(1));
        assert_eq!(out["summary"]["unreachable_count"], json!(1));
        let profiles = out["profiles"].as_array().expect("fleet profile array");
        assert_eq!(profiles[0]["profile"], json!("live"));
        assert_eq!(profiles[0]["status"], json!("REACHABLE"));
        assert!(profiles[0]["orient"]["schema"].is_array());
        assert_eq!(profiles[1]["profile"], json!("offline"));
        assert_eq!(profiles[1]["status"], json!("UNREACHABLE"));
        assert!(profiles[1].get("orient").is_none());
    });
}

/// H3 covers the public merged catalog against one real profile and a
/// deliberately unreachable companion. Unlike fleet orientation, catalog
/// output deliberately has no profile roster or aggregate lane counts: only
/// object rows that passed their source profile's egress policy may escape.
#[test]
fn oracle_search_objects_fleet_reads_the_live_catalog_without_a_profile_roster() {
    run_with_cx(|cx| async move {
        let test_name =
            "oracle_search_objects_fleet_reads_the_live_catalog_without_a_profile_roster";
        let Some(served) = connect_or_skip(&cx, test_name).await else {
            return;
        };
        let owner = served
            .describe(&cx)
            .await
            .ok()
            .and_then(|info| info.current_schema)
            .or_else(|| std::env::var("ORACLEMCP_TEST_USER").ok())
            .unwrap_or_else(|| "SYSTEM".to_owned())
            .to_ascii_uppercase();
        let config = fleet_test_config();
        let exposure = McpExposurePolicy::from_config(&config);
        let drain = ProfileDrainState::from_config(config);
        let connector: Arc<ProfileConnector> =
            Arc::new(|cx: &Cx, lease: &ProfileGenerationLease| {
                let opts = if lease.profile() == "live" {
                    test_opts()
                } else {
                    unreachable_test_opts()
                };
                Box::pin(async move {
                    RustOracleConnection::connect(cx, opts)
                        .await
                        .map(|conn| ProfileConnectionBundle::new(Box::new(conn), None))
                })
            });
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(served),
            Some("live".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadOnly, false),
            connector,
        )
        .with_mcp_exposure(exposure)
        .with_profile_drain_state(drain);

        let out = match ToolDispatch::dispatch(
            &dispatcher,
            &cx,
            DispatchContext::default(),
            "oracle_search_objects",
            json!({
                "fleet": true,
                "detail_level": "names",
                "owner": owner,
                "max_rows": 5,
            }),
        )
        .await
        {
            Outcome::Ok(value) => value,
            other => panic!("fleet catalog must retain the live lane: {other:?}"),
        };

        assert_eq!(out["fleet"], json!(true));
        assert_eq!(out["detail_level"], json!("names"));
        assert!(out["results"].is_array());
        assert!(out.get("profiles").is_none());
        assert!(out.get("summary").is_none());
        assert!(
            out["results"]
                .as_array()
                .expect("catalog rows")
                .iter()
                .all(|row| row["profile"] == "live")
        );
        assert!(
            !out.to_string().contains("offline"),
            "the unreachable profile is not a roster entry or a catalog side channel"
        );
    });
}
