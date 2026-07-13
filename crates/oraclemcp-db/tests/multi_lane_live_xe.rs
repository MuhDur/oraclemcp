#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_db::{
    DbError, OracleBind, OracleConnectOptions, OracleConnection, OracleConnectionInfo,
    OracleSessionIdentity, RustOracleConnection,
};
use serde_json::json;

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
        let cx = Cx::current().expect("block_on installs a current Cx");
        body(cx).await
    })
}

fn opts(
    dsn: String,
    user: String,
    password: String,
    lane_label: &str,
    call_timeout: Duration,
) -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: dsn,
        username: Some(user),
        password: Some(password),
        call_timeout: Some(call_timeout),
        session_identity: Some(OracleSessionIdentity {
            module: Some("oraclemcp-n9".to_owned()),
            action: Some(lane_label.to_owned()),
            client_identifier: Some(format!("oraclemcp-n9-{lane_label}")),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn env_triplet(prefix: &str) -> Option<(String, String, String)> {
    let dsn = std::env::var(format!("ORACLEMCP_TEST_DSN_{prefix}")).ok()?;
    let user = std::env::var(format!("ORACLEMCP_TEST_USER_{prefix}")).ok()?;
    let password = std::env::var(format!("ORACLEMCP_TEST_PASSWORD_{prefix}")).ok()?;
    Some((dsn, user, password))
}

fn default_triplet() -> Option<(String, String, String)> {
    Some((
        std::env::var("ORACLEMCP_TEST_DSN").ok()?,
        std::env::var("ORACLEMCP_TEST_USER").ok()?,
        std::env::var("ORACLEMCP_TEST_PASSWORD").ok()?,
    ))
}

fn database_identity_fingerprint(info: &OracleConnectionInfo) -> String {
    format!(
        "{}|{}|{}|{}",
        info.db_unique_name.as_deref().unwrap_or("unknown-db"),
        info.service_name.as_deref().unwrap_or("unknown-service"),
        info.instance_name.as_deref().unwrap_or("unknown-instance"),
        info.session_user.as_deref().unwrap_or("unknown-user")
    )
}

fn session_identity(info: &OracleConnectionInfo) -> Option<String> {
    Some(format!(
        "{}|{}",
        info.sid.as_deref()?,
        info.serial_number.as_deref()?
    ))
}

fn describe_lane(
    lane_label: &'static str,
    dsn: String,
    user: String,
    password: String,
) -> Result<OracleConnectionInfo, String> {
    run_with_cx(|cx| async move {
        let conn = RustOracleConnection::connect(
            &cx,
            opts(dsn, user, password, lane_label, Duration::from_secs(10)),
        )
        .await
        .map_err(|err| err.to_string())?;
        conn.ping(&cx).await.map_err(|err| err.to_string())?;
        conn.describe(&cx).await.map_err(|err| err.to_string())
    })
}

#[test]
#[ignore = "live-xe: set ORACLEMCP_MULTI_DB_LIVE_XE=1 and ORACLEMCP_TEST_*_A/B to prove two configured live lanes"]
fn live_xe_two_configured_lanes_keep_session_isolation() {
    if std::env::var("ORACLEMCP_MULTI_DB_LIVE_XE").is_err() {
        eprintln!(
            "{}",
            json!({
                "contract": "WP-N",
                "requirement_id": "WPN-B-001",
                "lane": "db-a/db-b",
                "subject": "live-xe",
                "sid": "not-opened",
                "profile": "multi-db",
                "level": "READ_ONLY",
                "grant": "none",
                "outcome": "not_run",
                "reason": "set ORACLEMCP_MULTI_DB_LIVE_XE=1 with ORACLEMCP_TEST_DSN_A/_USER_A/_PASSWORD_A and _B"
            })
        );
        return;
    }
    let Some((dsn_a, user_a, password_a)) = env_triplet("A") else {
        eprintln!("live_xe_two_database_lanes: missing A env triplet");
        return;
    };
    let Some((dsn_b, user_b, password_b)) = env_triplet("B") else {
        eprintln!("live_xe_two_database_lanes: missing B env triplet");
        return;
    };

    let lane_a = std::thread::spawn(move || describe_lane("db-a", dsn_a, user_a, password_a));
    let lane_b = std::thread::spawn(move || describe_lane("db-b", dsn_b, user_b, password_b));
    let info_a = match lane_a.join().expect("db-a lane thread joins") {
        Ok(info) => info,
        Err(err) => {
            eprintln!("live_xe_two_database_lanes: db-a not reachable: {err}");
            return;
        }
    };
    let info_b = match lane_b.join().expect("db-b lane thread joins") {
        Ok(info) => info,
        Err(err) => {
            eprintln!("live_xe_two_database_lanes: db-b not reachable: {err}");
            return;
        }
    };
    assert_eq!(
        info_a.action.as_deref(),
        Some("db-a"),
        "lane A must retain its server-observed action rather than borrowing lane B state"
    );
    assert_eq!(
        info_b.action.as_deref(),
        Some("db-b"),
        "lane B must retain its server-observed action rather than borrowing lane A state"
    );
    assert_eq!(
        info_a.client_identifier.as_deref(),
        Some("oraclemcp-n9-db-a"),
        "lane A must retain its configured client identity"
    );
    assert_eq!(
        info_b.client_identifier.as_deref(),
        Some("oraclemcp-n9-db-b"),
        "lane B must retain its configured client identity"
    );

    // Profile lanes can intentionally share a database, and cloned XE labs can
    // legitimately report the same DB_UNIQUE_NAME/service/instance values.
    // That metadata is therefore not a database-uniqueness oracle. When the
    // database identity is shared, prove the thing multi-lane dispatch actually
    // promises: each profile owns a distinct Oracle session and its state.
    let database_identity_a = database_identity_fingerprint(&info_a);
    let database_identity_b = database_identity_fingerprint(&info_b);
    let database_identity_relation = if database_identity_a == database_identity_b {
        assert_ne!(
            session_identity(&info_a).expect("same-database lane A exposes SID and serial"),
            session_identity(&info_b).expect("same-database lane B exposes SID and serial"),
            "profiles sharing a database identity must still use distinct Oracle sessions"
        );
        "shared"
    } else {
        "distinct"
    };
    eprintln!(
        "{}",
        json!({
            "contract": "WP-N",
            "requirement_id": "WPN-B-001",
            "lane": "db-a/db-b",
            "subject": "subject-sha256:live-xe",
            "sid": {
                "a": info_a.sid,
                "b": info_b.sid
            },
            "profile": "multi-db",
            "level": "READ_ONLY",
            "grant": "none",
            "outcome": "pass",
            "database_identity": {
                "a": database_identity_a,
                "b": database_identity_b,
                "relation": database_identity_relation
            },
            "session_isolation": {
                "a": session_identity(&info_a),
                "b": session_identity(&info_b)
            }
        })
    );
}

fn generated_table_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("ORAMCP_N9_{}", nanos % 1_000_000_000)
}

async fn drop_table_if_exists(cx: &Cx, conn: &RustOracleConnection, table: &str) {
    let _ = conn
        .execute(
            cx,
            &format!("DROP TABLE {table} PURGE"),
            &[] as &[OracleBind],
        )
        .await;
    let _ = conn.rollback(cx).await;
}

async fn setup_lock_table(cx: &Cx, opts: OracleConnectOptions, table: &str) -> Result<(), DbError> {
    let conn = RustOracleConnection::connect(cx, opts).await?;
    drop_table_if_exists(cx, &conn, table).await;
    conn.execute(
        cx,
        &format!("CREATE TABLE {table} (id NUMBER PRIMARY KEY, val NUMBER)"),
        &[] as &[OracleBind],
    )
    .await?;
    conn.execute(
        cx,
        &format!("INSERT INTO {table} (id, val) VALUES (1, 1)"),
        &[] as &[OracleBind],
    )
    .await?;
    conn.commit(cx).await
}

async fn cleanup_lock_table(cx: &Cx, opts: OracleConnectOptions, table: &str) {
    if let Ok(conn) = RustOracleConnection::connect(cx, opts).await {
        drop_table_if_exists(cx, &conn, table).await;
    }
}

#[test]
#[ignore = "live-xe: set ORACLEMCP_LIVE_XE_CONTENTION=1 and ORACLEMCP_TEST_* to run same-DB contention"]
fn live_xe_same_database_contention_is_typed_or_succeeds_without_hanging() {
    if std::env::var("ORACLEMCP_LIVE_XE_CONTENTION").is_err() {
        eprintln!(
            "{}",
            json!({
                "contract": "WP-N",
                "requirement_id": "WPN-C-001",
                "lane": "contended-lane",
                "subject": "live-xe",
                "sid": "not-opened",
                "profile": "same-db",
                "level": "READ_WRITE",
                "grant": "xgrant-bound",
                "outcome": "not_run",
                "reason": "set ORACLEMCP_LIVE_XE_CONTENTION=1 with ORACLEMCP_TEST_DSN/_USER/_PASSWORD"
            })
        );
        return;
    }
    let Some((dsn, user, password)) = default_triplet() else {
        eprintln!("live_xe_same_database_contention: missing ORACLEMCP_TEST_* env triplet");
        return;
    };
    let setup_opts = opts(
        dsn.clone(),
        user.clone(),
        password.clone(),
        "contention-setup",
        Duration::from_secs(10),
    );
    let table = generated_table_name();
    let setup_table = table.clone();
    let setup = run_with_cx(move |cx| {
        let setup_table = setup_table.clone();
        let setup_opts = setup_opts.clone();
        async move { setup_lock_table(&cx, setup_opts, &setup_table).await }
    });
    if let Err(err) = setup {
        eprintln!("live_xe_same_database_contention: setup unavailable: {err}");
        return;
    }

    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let holder_opts = opts(
        dsn.clone(),
        user.clone(),
        password.clone(),
        "contention-holder",
        Duration::from_secs(10),
    );
    let waiter_opts = opts(
        dsn.clone(),
        user.clone(),
        password.clone(),
        "contention-waiter",
        Duration::from_secs(2),
    );
    let holder_table = table.clone();
    let holder = std::thread::spawn(move || {
        run_with_cx(|cx| async move {
            let outcome = async {
                let conn = RustOracleConnection::connect(&cx, holder_opts).await?;
                conn.execute(
                    &cx,
                    &format!("UPDATE {holder_table} SET val = val + 1 WHERE id = 1"),
                    &[] as &[OracleBind],
                )
                .await?;
                locked_tx.send(()).expect("test waits for held lock");
                release_rx.recv().expect("test releases held lock");
                conn.rollback(&cx).await
            }
            .await;
            outcome.map_err(|err: DbError| err.to_string())
        })
    });

    if locked_rx.recv_timeout(Duration::from_secs(10)).is_err() {
        let _ = release_tx.send(());
        let _ = holder.join();
        run_with_cx(|cx| async move {
            cleanup_lock_table(
                &cx,
                opts(
                    dsn,
                    user,
                    password,
                    "contention-cleanup",
                    Duration::from_secs(10),
                ),
                &table,
            )
            .await;
        });
        panic!("lock holder did not acquire the row lock before timeout");
    }

    let waiter_table = table.clone();
    let waiter = std::thread::spawn(move || {
        let outcome = run_with_cx(|cx| async move {
            let conn = RustOracleConnection::connect(&cx, waiter_opts).await?;
            conn.execute(
                &cx,
                &format!("UPDATE {waiter_table} SET val = val + 1 WHERE id = 1"),
                &[] as &[OracleBind],
            )
            .await
        });
        result_tx
            .send(outcome.map(|_| ()).map_err(|err| err.to_string()))
            .expect("test receives waiter outcome");
    });

    let waiter_result = result_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("contended lane returns before the test deadline");
    release_tx.send(()).expect("release held row lock");
    holder
        .join()
        .expect("holder lane thread joins")
        .expect("holder rolls back cleanly");
    waiter.join().expect("waiter lane thread joins");

    match waiter_result {
        Ok(()) => {}
        Err(message) => {
            assert!(
                message.contains("call timeout")
                    || message.contains("ORA-00060")
                    || message.contains("ORA-00054")
                    || message.contains("ORA-01013"),
                "contention must be a typed timeout/deadlock/busy outcome, got: {message}"
            );
        }
    }

    run_with_cx(|cx| async move {
        cleanup_lock_table(
            &cx,
            opts(
                dsn,
                user,
                password,
                "contention-cleanup",
                Duration::from_secs(10),
            ),
            &table,
        )
        .await;
    });
    eprintln!(
        "{}",
        json!({
            "contract": "WP-N",
            "requirement_id": "WPN-C-001",
            "lane": "contention-holder/contention-waiter",
            "subject": "subject-sha256:live-xe",
            "sid": "live",
            "profile": "same-db",
            "level": "READ_WRITE",
            "grant": "xgrant-bound",
            "outcome": "pass"
        })
    );
}
