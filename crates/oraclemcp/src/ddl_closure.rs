//! Engine binding for the DDL-trigger collector seam. Custom-tool and W12
//! execution consumers deliberately remain separate from this collection API.

use asupersync::Cx;
use oraclemcp_db::OracleConnection;
use oraclemcp_guard::ddl_closure::{DdlEffectClosureV1, DdlEvent, DdlObject};

/// Collect fresh source-bound trigger effects using the served PL/SQL engine.
/// Engine-free builds preserve Unknown rather than supplying an empty proof.
pub async fn collect_ddl_effect_closure(
    cx: &Cx,
    conn: &dyn OracleConnection,
    event: DdlEvent,
    object: DdlObject,
    container: &str,
) -> DdlEffectClosureV1 {
    #[cfg(feature = "plsql-intelligence")]
    let effects = crate::mutation_closure::EngineMutationEffects;
    #[cfg(not(feature = "plsql-intelligence"))]
    let effects = oraclemcp_db::mutation_closure::UnknownMutationEffects;
    oraclemcp_db::ddl_closure::collect_ddl_effect_closure(
        cx, conn, event, object, container, &effects,
    )
    .await
}

#[cfg(all(test, feature = "live-xe", feature = "plsql-intelligence"))]
mod tests {
    use super::*;
    use oraclemcp_db::{OracleConnectOptions, connect_oracle};
    use oraclemcp_guard::{OperatingLevel, RoutineEffect};
    use std::time::{SystemTime, UNIX_EPOCH};

    // These cases install different system-event triggers in the same fixture
    // schema. Concurrent cases would fire each other's canaries and change the
    // catalog snapshot under collection.
    static NATIVE_DDL_FIXTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    #[ignore = "requires FREE23 catalog visibility; collects existing DATABASE DROP triggers without executing DDL"]
    fn ddl_closure_live_database_trigger_collected_for_drop() {
        let _fixture = NATIVE_DDL_FIXTURE.lock().expect("DDL fixture lock");
        let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("installed Cx");
            let options = OracleConnectOptions {
                connect_string: std::env::var("ORACLEMCP_TEST_DSN").expect("explicit FREE23 DSN"),
                username: Some(std::env::var("ORACLEMCP_TEST_USER").expect("catalog fixture account")),
                password: Some(std::env::var("ORACLEMCP_TEST_PASSWORD").expect("fixture password")),
                ..Default::default()
            };
            let owner = options.username.as_ref().unwrap().to_uppercase();
            let conn = connect_oracle(&cx, options).await.expect("native fixture connection");
            assert_eq!(conn.backend(), oraclemcp_db::OracleBackend::RustOracle);
            let identity = oraclemcp_db::read_closure_database_identity(&cx, conn.as_ref()).await.expect("container identity");
            let catalog = oraclemcp_db::run_catalog_query(&cx, conn.as_ref(),
                oraclemcp_db::CatalogQueryId::DdlTriggers, &[257_i64.into()]).await.expect("DDL trigger catalog");
            let closure = collect_ddl_effect_closure(&cx, conn.as_ref(), DdlEvent::Drop,
                DdlObject { owner, name: "OMCP_DDL_DROP_OBSERVATION".into(), object_type: "TABLE".into() },
                &identity.container).await;
            conn.close(&cx).await.expect("close native connection");
            println!("{}", serde_json::json!({"case":"ddl_closure_live_database_trigger_collected_for_drop","closure":closure}));
            assert!(closure.database_triggers_visible);
            assert!(closure.triggers.iter().any(|fact| fact.scope == oraclemcp_guard::ddl_closure::DdlTriggerScope::Database
                && fact.name == "XDB_PI_TRIG"), "the enabled FREE23 DATABASE DROP trigger must be retained: {closure:?}");
            assert!(closure.admit().is_err(), "unproved SYS trigger effects must refuse");
            for row in &catalog {
                for column in ["BASE_OBJECT_TYPE", "TRIGGER_TYPE", "TRIGGERING_EVENT", "STATUS", "ACTION_TYPE", "CROSSEDITION"] {
                    let value = row.text(column).expect("projected catalog discriminator");
                    assert_eq!(value, value.trim_end_matches(' '), "SQL projection must normalize {column}");
                }
            }
        });
    }

    #[test]
    #[ignore = "requires isolated FREE23 CREATE TABLE/TRIGGER fixture and SELECT_CATALOG_ROLE"]
    fn ddl_closure_live_servererror_trigger_collected_for_create() {
        let _fixture = NATIVE_DDL_FIXTURE.lock().expect("DDL fixture lock");
        let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("installed Cx");
            let options = OracleConnectOptions {
                connect_string: std::env::var("ORACLEMCP_TEST_DSN").expect("explicit FREE23 DSN"),
                username: Some(std::env::var("ORACLEMCP_TEST_USER").expect("isolated synthetic fixture account")),
                password: Some(std::env::var("ORACLEMCP_TEST_PASSWORD").expect("fixture password")),
                ..Default::default()
            };
            let owner = options.username.as_ref().unwrap().to_uppercase();
            let conn = connect_oracle(&cx, options).await.expect("native fixture connection");
            assert_eq!(conn.backend(), oraclemcp_db::OracleBackend::RustOracle);
            let identity = oraclemcp_db::read_closure_database_identity(&cx, conn.as_ref()).await.expect("container identity");
            let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let trigger = format!("OMCP_DDL_ERR_{suffix:X}");
            let canary = format!("OMCP_DDL_ERRLOG_{suffix:X}");
            let result: Result<_, oraclemcp_db::DbError> = async {
                conn.execute(&cx, &format!("CREATE TABLE {canary} (n NUMBER)"), &[]).await?;
                conn.execute(&cx, &format!("CREATE TRIGGER {trigger} AFTER SERVERERROR ON SCHEMA DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN INSERT INTO {canary} (n) VALUES (1); COMMIT; END;"), &[]).await?;
                let catalog = oraclemcp_db::run_catalog_query(&cx, conn.as_ref(),
                    oraclemcp_db::CatalogQueryId::DdlTriggers, &[257_i64.into()]).await?;
                let catalog_event = catalog.iter().find(|row| row.text("TRIGGER_NAME") == Some(trigger.as_str()))
                    .and_then(|row| row.text("TRIGGERING_EVENT")).map(str::to_owned);
                let closure = collect_ddl_effect_closure(&cx, conn.as_ref(), DdlEvent::Create,
                    DdlObject { owner: owner.clone(), name: canary.clone(), object_type: "TABLE".into() }, &identity.container).await;
                let before = conn.query_rows(&cx, &format!("SELECT n FROM {canary}"), &[]).await?.len();
                // Deliberate raw fixture DDL fails with ORA-00955 and fires the
                // real error trigger. The collector itself must execute nothing.
                let failed = conn.execute(&cx, &format!("CREATE TABLE {canary} (n NUMBER)"), &[]).await.is_err();
                let after = conn.query_rows(&cx, &format!("SELECT n FROM {canary}"), &[]).await?.len();
                Ok((closure, before, failed, after, catalog_event))
            }.await;
            let mut cleanup_errors = Vec::new();
            for sql in [format!("DROP TRIGGER {trigger}"), format!("DROP TABLE {canary} PURGE")] {
                if let Err(error) = conn.execute(&cx, &sql, &[]).await { cleanup_errors.push(error); }
            }
            conn.close(&cx).await.expect("close native connection");
            let (closure, before, failed, after, catalog_event) = result.expect("native SERVERERROR fixture");
            assert!(cleanup_errors.is_empty(), "synthetic fixture cleanup failed: {cleanup_errors:?}");
            println!("{}", serde_json::json!({"case":"ddl_closure_live_servererror_trigger_collected_for_create","closure":closure,"before":before,"failed_ddl":failed,"after":after,"catalog_event":catalog_event}));
            assert_eq!(catalog_event.as_deref().and_then(DdlEvent::from_catalog), Some(DdlEvent::ServerError));
            let fact = closure.triggers.iter().find(|fact| fact.owner == owner && fact.name == trigger).expect("SERVERERROR trigger must be collected even for CREATE");
            assert!(closure.is_complete(), "{:?}", closure.unavailable);
            assert!(fact.effects.iter().any(|effect| effect == RoutineEffect::Autonomous));
            assert!(closure.admit().is_err());
            assert_eq!(before, 0, "collection must leave the canary empty");
            assert!(failed, "the deliberate duplicate CREATE must fail");
            assert!(after >= 1, "the Oracle SERVERERROR body must really commit");
        });
    }

    #[test]
    #[ignore = "requires isolated FREE23 fixture account with CREATE TABLE/TRIGGER and SELECT_CATALOG_ROLE"]
    fn ddl_closure_live_schema_trigger_collected() {
        let _fixture = NATIVE_DDL_FIXTURE.lock().expect("DDL fixture lock");
        let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("installed Cx");
            let options = OracleConnectOptions {
                connect_string: std::env::var("ORACLEMCP_TEST_DSN").expect("explicit FREE23 DSN"),
                username: Some(std::env::var("ORACLEMCP_TEST_USER").expect("isolated synthetic fixture account")),
                password: Some(std::env::var("ORACLEMCP_TEST_PASSWORD").expect("fixture password")),
                ..Default::default()
            };
            let owner = options.username.as_ref().unwrap().to_uppercase();
            let conn = connect_oracle(&cx, options).await.expect("native fixture connection");
            assert_eq!(conn.backend(), oraclemcp_db::OracleBackend::RustOracle);
            let identity = oraclemcp_db::read_closure_database_identity(&cx, conn.as_ref()).await.expect("container identity");
            let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let trigger = format!("OMCP_DDL_TR_{suffix:X}");
            let canary = format!("OMCP_DDL_LOG_{suffix:X}");
            let target = format!("OMCP_DDL_T_{suffix:X}");
            let object = DdlObject { owner: owner.clone(), name: target.clone(), object_type: "TABLE".into() };
            let result: Result<_, oraclemcp_db::DbError> = async {
                conn.execute(&cx, &format!("CREATE TABLE {canary} (object_name VARCHAR2(128))"), &[]).await?;
                conn.execute(&cx, &format!("CREATE TRIGGER {trigger} AFTER CREATE ON SCHEMA BEGIN NULL; END;"), &[]).await?;
                let readonly = collect_ddl_effect_closure(&cx, conn.as_ref(), DdlEvent::Create, object.clone(), &identity.container).await;
                conn.execute(&cx, &format!("CREATE OR REPLACE TRIGGER {trigger} AFTER CREATE ON SCHEMA DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN INSERT INTO {canary} (object_name) VALUES ('{target}'); COMMIT; END;"), &[]).await?;
                let harmful = collect_ddl_effect_closure(&cx, conn.as_ref(), DdlEvent::Create, object.clone(), &identity.container).await;
                conn.execute(&cx, &format!("CREATE TABLE {target} (n NUMBER)"), &[]).await?;
                let canary_rows = conn.query_rows(&cx, &format!("SELECT object_name FROM {canary} WHERE object_name = :1"), &[target.as_str().into()]).await?;
                conn.execute(&cx, &format!("ALTER TRIGGER {trigger} DISABLE"), &[]).await?;
                let disabled = collect_ddl_effect_closure(&cx, conn.as_ref(), DdlEvent::Create, object.clone(), &identity.container).await;
                conn.execute(&cx, "SET ROLE NONE", &[]).await?;
                let invisible = collect_ddl_effect_closure(&cx, conn.as_ref(), DdlEvent::Create, object, &identity.container).await;
                conn.execute(&cx, "SET ROLE ALL", &[]).await?;
                Ok((readonly, harmful, disabled, invisible, canary_rows.len()))
            }.await;
            // Drop only this run's synthetic objects. Drop the trigger first so
            // cleanup cannot invoke its autonomous body on subsequent DDL.
            let mut cleanup_errors = Vec::new();
            for sql in [format!("DROP TRIGGER {trigger}"), format!("DROP TABLE {target} PURGE"), format!("DROP TABLE {canary} PURGE")] {
                if let Err(error) = conn.execute(&cx, &sql, &[]).await {
                    eprintln!("synthetic DDL fixture cleanup: {error}");
                    cleanup_errors.push(error);
                }
            }
            conn.close(&cx).await.expect("close native connection");
            let (readonly, harmful, disabled, invisible, canary_count) = result.expect("native fixture statements");
            assert!(cleanup_errors.is_empty(), "synthetic fixture cleanup failed: {cleanup_errors:?}");
            println!("{}", serde_json::json!({"case":"ddl_closure_live_schema_trigger_collected","phase":"readonly","closure":readonly}));
            println!("{}", serde_json::json!({"case":"ddl_closure_live_schema_trigger_collected","phase":"autonomous_insert","closure":harmful,"canary_rows":canary_count}));
            println!("{}", serde_json::json!({"case":"ddl_closure_live_schema_trigger_collected","phase":"disabled","closure":disabled}));
            println!("{}", serde_json::json!({"case":"ddl_closure_live_schema_trigger_collected","phase":"without_visibility","closure":invisible}));
            let find = |closure: &DdlEffectClosureV1| closure.triggers.iter().find(|fact| fact.owner == owner && fact.name == trigger).cloned();
            let read_trigger = find(&readonly).expect("enabled schema trigger collected");
            assert!(read_trigger.source_sha256.is_some());
            assert_eq!(readonly.admit(), Ok(OperatingLevel::ReadOnly));
            let write_trigger = find(&harmful).expect("recompiled trigger collected");
            assert!(harmful.is_complete(), "{:?}", harmful.unavailable);
            assert!(write_trigger.effects.iter().any(|effect| effect == RoutineEffect::Dml));
            assert!(write_trigger.effects.iter().any(|effect| effect == RoutineEffect::Autonomous));
            assert!(harmful.admit().is_err());
            assert_ne!(read_trigger.source_sha256, write_trigger.source_sha256);
            assert_ne!(readonly.fingerprint(), harmful.fingerprint());
            assert!(canary_count >= 1, "Oracle actually ran the synthetic autonomous trigger");
            assert!(find(&disabled).is_none());
            assert_eq!(disabled.admit(), Ok(OperatingLevel::ReadOnly));
            assert!(!invisible.database_triggers_visible);
            assert_eq!(invisible.admit(), Err(oraclemcp_guard::ddl_closure::DdlClosureRefusal::Unknown));
        });
    }
}
