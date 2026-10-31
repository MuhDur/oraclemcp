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

    #[test]
    #[ignore = "requires isolated FREE23 fixture account with CREATE TABLE/TRIGGER and SELECT_CATALOG_ROLE"]
    fn ddl_closure_live_schema_trigger_collected() {
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
