//! Live Free 23ai catalog fact proof. No database responses are mocked.

#![forbid(unsafe_code)]

use std::process::Command;

use asupersync::{Cx, runtime::RuntimeBuilder};
use oraclemcp_core::catalog_facts::CatalogFactFileStore;
use oraclemcp_db::{
    AuthAdapter, ClosureFactStore, ClosureMember, DmlTarget, OracleConnectOptions,
    OracleConnection, Revalidation, RoutineClosure, RustOracleConnection,
    catalog_facts::{ClosureFactKey, extract_closure_facts, revalidate},
};
use oraclemcp_guard::purity::{RoutineIdentifier, RoutineRef};
use serde::{Deserialize, Serialize};

fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("runtime");
    runtime.block_on(async move { body(Cx::current().expect("runtime Cx")).await })
}

fn enabled() -> bool {
    std::env::var("ORACLEMCP_CATALOG_FACTS_LIVE").as_deref() == Ok("1")
}

fn log_case(case: &str, result: &str) {
    println!(
        "{}",
        serde_json::json!({"case_id":case,"lane":"free23","verdict":"pass","result":result})
    );
}

fn opts() -> Option<(OracleConnectOptions, String)> {
    let user = std::env::var("ORACLE_MATRIX_FREE23_USER").ok()?;
    let password = std::env::var("ORACLE_MATRIX_FREE23_PASSWORD").ok()?;
    let dsn = std::env::var("ORACLE_MATRIX_FREE23_DSN")
        .unwrap_or_else(|_| "localhost:1523/FREEPDB1".into());
    if !(dsn.starts_with("localhost:") || dsn.starts_with("127.0.0.1:")) {
        return None;
    }
    Some((
        OracleConnectOptions {
            connect_string: dsn,
            username: Some(user.clone()),
            password: Some(password),
            auth_adapter: AuthAdapter::Password,
            ..Default::default()
        },
        user.to_ascii_uppercase(),
    ))
}

fn closure(owner: &str, package: &str) -> RoutineClosure {
    let routine = RoutineRef {
        schema: Some(RoutineIdentifier::new(owner, false)),
        package: Some(RoutineIdentifier::new(package, false)),
        member: RoutineIdentifier::new("RUN", false),
        overload: None,
    };
    let members = ["PACKAGE", "PACKAGE BODY"]
        .into_iter()
        .map(|object_type| ClosureMember {
            routine: routine.clone(),
            owner: owner.into(),
            object_name: package.into(),
            object_type: object_type.into(),
            source_types: vec![object_type.into()],
        })
        .collect();
    RoutineClosure {
        root: routine,
        members,
        dml_targets: Vec::<DmlTarget>::new(),
    }
}

fn package_name() -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("OMCP_CF_{:X}{:X}", std::process::id(), stamp & 0xFFFFF)
}

async fn connect(cx: &Cx) -> Option<(RustOracleConnection, String)> {
    let (options, owner) = opts()?;
    match RustOracleConnection::connect(cx, options).await {
        Ok(conn) => {
            let info = conn.describe(cx).await.expect("Free23 server identity");
            assert!(
                info.server_version
                    .as_deref()
                    .is_some_and(|version| version.starts_with("23.")),
                "live catalog proof requires Oracle 23ai"
            );
            Some((conn, owner))
        }
        Err(error) => panic!("Free23 catalog-facts connection failed: {error}"),
    }
}

async fn ddl(cx: &Cx, conn: &dyn OracleConnection, sql: &str) {
    conn.execute(cx, sql, &[])
        .await
        .unwrap_or_else(|error| panic!("synthetic Free23 fixture DDL failed: {error}"));
}

#[derive(Serialize, Deserialize)]
struct ChildPayload {
    profile: String,
    closure: RoutineClosure,
    key: ClosureFactKey,
    state_dir: String,
}

#[test]
fn catalog_facts_live_roundtrip() {
    if !enabled() {
        eprintln!(
            "[catalog-facts-live] SKIP; set ORACLEMCP_CATALOG_FACTS_LIVE=1 and ORACLE_MATRIX_FREE23_* credentials"
        );
        return;
    }
    let Some((_, owner)) = opts() else {
        panic!("Free23 credentials missing or DSN is not a local FREEPDB1 lane");
    };
    let package = package_name();
    let dir = tempfile::tempdir().expect("private state directory");
    let state_dir = dir.path().to_path_buf();
    run_with_cx(|cx| async move {
        let Some((conn, _)) = connect(&cx).await else {
            panic!("Free23 credentials disappeared");
        };
        ddl(
            &cx,
            &conn,
            &format!("CREATE PACKAGE {package} AS PROCEDURE run; END;"),
        )
        .await;
        ddl(
            &cx,
            &conn,
            &format!("CREATE PACKAGE BODY {package} AS PROCEDURE run IS BEGIN NULL; END; END;"),
        )
        .await;
        let closure = closure(&owner, &package);
        let facts = extract_closure_facts(&cx, &conn, &closure, Some(17))
            .await
            .expect("live Free23 catalog extraction");
        let store = CatalogFactFileStore::open(&state_dir).expect("state FileStore");
        store
            .save("synthetic-free23-profile", &facts)
            .expect("persist complete facts");
        let payload = ChildPayload {
            profile: "synthetic-free23-profile".into(),
            closure,
            key: facts.key,
            state_dir: state_dir.to_string_lossy().into_owned(),
        };
        drop(store);
        let encoded = serde_json::to_string(&payload).expect("child payload");
        let status = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "catalog_facts_restart_process_child",
                "--nocapture",
            ])
            .env("ORACLEMCP_CATALOG_FACTS_CHILD", encoded)
            .status()
            .expect("spawn fresh test process");
        ddl(&cx, &conn, &format!("DROP PACKAGE {package}")).await;
        assert!(
            status.success(),
            "fresh process must revalidate stored Free23 facts"
        );
        log_case(
            "catalog_facts_live_roundtrip",
            "fresh_after_process_restart",
        );
        eprintln!(
            "[catalog-facts-live] FREE23 unchanged synthetic package was Fresh after process restart"
        );
    });
}

#[test]
fn catalog_facts_restart_process_child() {
    let Ok(encoded) = std::env::var("ORACLEMCP_CATALOG_FACTS_CHILD") else {
        return;
    };
    let payload: ChildPayload = serde_json::from_str(&encoded).expect("child payload");
    run_with_cx(|cx| async move {
        let Some((conn, _)) = connect(&cx).await else {
            panic!("Free23 credentials unavailable in child");
        };
        let store =
            CatalogFactFileStore::open(&payload.state_dir).expect("fresh-process FileStore");
        let result = revalidate(
            &cx,
            &conn,
            &store,
            &payload.profile,
            &payload.closure,
            &payload.key,
            Some(999),
        )
        .await;
        assert_eq!(
            result,
            Revalidation::Fresh,
            "catalog revision must not key persisted facts"
        );
        log_case("catalog_facts_restart_process_child", "fresh");
    });
}

#[test]
fn catalog_facts_live_recompile_is_stale() {
    if !enabled() {
        eprintln!(
            "[catalog-facts-live] SKIP; set ORACLEMCP_CATALOG_FACTS_LIVE=1 and ORACLE_MATRIX_FREE23_* credentials"
        );
        return;
    }
    let Some((_, owner)) = opts() else {
        panic!("Free23 credentials missing or DSN is not a local FREEPDB1 lane");
    };
    let package = package_name();
    let dir = tempfile::tempdir().expect("private state directory");
    run_with_cx(|cx| async move {
        let Some((conn, _)) = connect(&cx).await else {
            panic!("Free23 credentials disappeared");
        };
        ddl(
            &cx,
            &conn,
            &format!("CREATE PACKAGE {package} AS PROCEDURE run; END;"),
        )
        .await;
        ddl(
            &cx,
            &conn,
            &format!("CREATE PACKAGE BODY {package} AS PROCEDURE run IS BEGIN NULL; END; END;"),
        )
        .await;
        let closure = closure(&owner, &package);
        let facts = extract_closure_facts(&cx, &conn, &closure, None)
            .await
            .expect("pre-recompile extraction");
        let store = CatalogFactFileStore::open(dir.path()).expect("state FileStore");
        store
            .save("synthetic-free23-profile", &facts)
            .expect("persist pre-recompile facts");
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        ddl(&cx, &conn, &format!("ALTER PACKAGE {package} COMPILE BODY")).await;
        let after_compile = extract_closure_facts(&cx, &conn, &closure, None)
            .await
            .expect("post-recompile catalog extraction");
        let timestamp_changed = facts.members.iter().any(|before| {
            after_compile.members.iter().any(|after| {
                before.routine == after.routine
                    && before.object_type == after.object_type
                    && before.last_ddl_time != after.last_ddl_time
            })
        });
        let result = revalidate(
            &cx,
            &conn,
            &store,
            "synthetic-free23-profile",
            &closure,
            &facts.key,
            None,
        )
        .await;
        drop(store);
        ddl(&cx, &conn, &format!("DROP PACKAGE {package}")).await;
        assert!(
            timestamp_changed,
            "Free23 must expose the recompile through LAST_DDL_TIME"
        );
        assert!(
            matches!(result, Revalidation::Stale(_)),
            "recompile must stale facts, got {result:?}"
        );
        log_case(
            "catalog_facts_live_recompile_is_stale",
            "stale_after_last_ddl_time_change",
        );
        eprintln!("[catalog-facts-live] FREE23 package recompile returned Stale");
    });
}
