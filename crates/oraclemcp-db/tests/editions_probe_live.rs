//! Mock-free EBR catalog checks against the three disposable Oracle lanes.

#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use asupersync::{Cx, runtime::RuntimeBuilder};
use oraclemcp_db::{
    AuthAdapter, EditionsProofStatus, OracleConnectOptions, OracleConnection, RustOracleConnection,
    probe_editions_catalog, probe_editions_enabled,
};
use oraclemcp_error::{ErrorClass, ReasonCategory, StatementOutcome};

const LANES: &[(&str, &str, &str)] = &[
    ("XE18", "localhost:1518/XEPDB1", "18."),
    ("XE21", "localhost:1520/XEPDB1", "21."),
    ("FREE23", "localhost:1523/FREEPDB1", "23."),
];

fn enabled() -> bool {
    std::env::var("ORACLEMCP_EDITIONS_LIVE").as_deref() == Ok("1")
}

fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("runtime installs Cx");
        body(cx).await
    })
}

async fn connect(cx: &Cx, lane: &str, default_dsn: &str) -> RustOracleConnection {
    let user = std::env::var(format!("ORACLE_MATRIX_{lane}_USER"))
        .unwrap_or_else(|_| panic!("{lane} live editions user missing"));
    let password = std::env::var(format!("ORACLE_MATRIX_{lane}_PASSWORD"))
        .unwrap_or_else(|_| panic!("{lane} live editions password missing"));
    let dsn = std::env::var(format!("ORACLE_MATRIX_{lane}_DSN"))
        .unwrap_or_else(|_| default_dsn.to_owned());
    assert!(
        dsn.starts_with("localhost:") || dsn.starts_with("127.0.0.1:"),
        "editions matrix runs only against local lab lanes"
    );
    RustOracleConnection::connect(
        cx,
        OracleConnectOptions {
            connect_string: dsn,
            username: Some(user),
            password: Some(password),
            auth_adapter: AuthAdapter::Password,
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|error| panic!("{lane} live editions connection failed: {error}"))
}

fn synthetic_owner(lane: &str, marker: &str) -> String {
    let lane = match lane {
        "XE18" => "18",
        "XE21" => "21",
        "FREE23" => "23",
        _ => unreachable!("closed lane list"),
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!(
        "OMCP_E{marker}_{lane}_{:X}{:X}",
        std::process::id(),
        stamp & 0xFFFF
    )
}

async fn create_user(cx: &Cx, conn: &RustOracleConnection, owner: &str, password: &str) {
    conn.execute(
        cx,
        &format!("CREATE USER {owner} IDENTIFIED BY \"{password}\""),
        &[],
    )
    .await
    .unwrap_or_else(|error| panic!("synthetic owner creation failed: {error}"));
    conn.execute(cx, &format!("GRANT CREATE SESSION TO {owner}"), &[])
        .await
        .unwrap_or_else(|error| panic!("synthetic owner grant failed: {error}"));
}

async fn drop_user(cx: &Cx, conn: &RustOracleConnection, owner: &str) {
    conn.execute(cx, &format!("DROP USER {owner} CASCADE"), &[])
        .await
        .unwrap_or_else(|error| panic!("synthetic owner cleanup failed: {error}"));
}

fn assert_live_enabled(proof: &oraclemcp_db::EditionsEnabledProof, lane: &str) {
    assert_eq!(proof.owner_enabled, EditionsProofStatus::Proven, "{lane}");
    assert_eq!(proof.type_enabled, EditionsProofStatus::Proven, "{lane}");
    assert!(proof.is_proven(), "{lane}");
}

fn assert_refused_before_statement(proof: &oraclemcp_db::EditionsEnabledProof, lane: &str) {
    let refusal = proof.refusal_envelope();
    assert_eq!(refusal.error_class, ErrorClass::PolicyDenied, "{lane}");
    assert_eq!(
        refusal.statement_outcome,
        Some(StatementOutcome::NotStarted),
        "{lane} refusal must stop before a statement starts"
    );
    assert_eq!(
        refusal.structured_reason.unwrap().category,
        ReasonCategory::EditionsNotEnabled,
        "{lane}"
    );
}

#[test]
fn editions_probe_owner_enabled_live() {
    if !enabled() {
        eprintln!(
            "[editions-live] SKIP; set ORACLEMCP_EDITIONS_LIVE=1 and XE18/XE21/FREE23 credentials"
        );
        return;
    }
    run_with_cx(|cx| async move {
        for (lane, dsn, version_prefix) in LANES {
            let conn = connect(&cx, lane, dsn).await;
            let info = conn.describe(&cx).await.expect("server identity");
            assert!(
                info.server_version
                    .as_deref()
                    .is_some_and(|version| version.starts_with(version_prefix)),
                "{lane} server version did not match the requested lane"
            );
            let owner = synthetic_owner(lane, "PV");
            let password = format!("Ep{}_{:X}", lane, std::process::id());
            create_user(&cx, &conn, &owner, &password).await;
            let setup = conn
                .execute(
                    &cx,
                    &format!("ALTER USER {owner} ENABLE EDITIONS FOR VIEW"),
                    &[],
                )
                .await;
            let proof = if setup.is_ok() {
                let capabilities = probe_editions_catalog(&cx, &conn).await;
                Some(probe_editions_enabled(&cx, &conn, &capabilities, &owner, "VIEW").await)
            } else {
                None
            };
            let self_proof = if setup.is_ok() {
                match RustOracleConnection::connect(
                    &cx,
                    OracleConnectOptions {
                        connect_string: (*dsn).to_owned(),
                        username: Some(owner.clone()),
                        password: Some(password.clone()),
                        auth_adapter: AuthAdapter::Password,
                        ..Default::default()
                    },
                )
                .await
                {
                    Ok(owner_conn) => {
                        let capabilities = probe_editions_catalog(&cx, &owner_conn).await;
                        Some(
                            probe_editions_enabled(&cx, &owner_conn, &capabilities, &owner, "VIEW")
                                .await,
                        )
                    }
                    Err(_) => None,
                }
            } else {
                None
            };
            drop_user(&cx, &conn, &owner).await;
            setup.unwrap_or_else(|error| panic!("{lane} synthetic EBR setup failed: {error}"));
            let proof = proof.expect("setup succeeded");
            let self_proof = self_proof.expect("synthetic owner connection succeeded");
            assert_live_enabled(&proof, lane);
            assert_live_enabled(&self_proof, lane);
            println!(
                "{}",
                serde_json::json!({
                    "case_id":"editions_probe_owner_enabled_live",
                    "lane":lane,
                    "version":info.server_version,
                    "dba_owner_view":proof.owner_evidence_view,
                    "dba_type_view":proof.type_evidence_view,
                    "self_owner_view":self_proof.owner_evidence_view,
                    "self_type_view":self_proof.type_evidence_view,
                    "verdict":"pass"
                })
            );
        }
    });
}

#[test]
fn editions_probe_owner_disabled_refuses_live() {
    if !enabled() {
        return;
    }
    run_with_cx(|cx| async move {
        for (lane, dsn, _) in LANES {
            let conn = connect(&cx, lane, dsn).await;
            let owner = synthetic_owner(lane, "OFF");
            let password = format!("Of{}_{:X}", lane, std::process::id());
            create_user(&cx, &conn, &owner, &password).await;
            let capabilities = probe_editions_catalog(&cx, &conn).await;
            let proof = probe_editions_enabled(&cx, &conn, &capabilities, &owner, "VIEW").await;
            drop_user(&cx, &conn, &owner).await;
            assert_eq!(proof.owner_enabled, EditionsProofStatus::Disabled, "{lane}");
            assert_eq!(proof.type_enabled, EditionsProofStatus::Disabled, "{lane}");
            assert_refused_before_statement(&proof, lane);
            println!(
                "{}",
                serde_json::json!({"case_id":"editions_probe_owner_disabled_refuses_live","lane":lane,"statement_outcome":"NOT_STARTED","verdict":"pass"})
            );
        }
    });
}

#[test]
fn editions_probe_type_omitted_refuses_live() {
    if !enabled() {
        return;
    }
    run_with_cx(|cx| async move {
        for (lane, dsn, _) in LANES {
            let conn = connect(&cx, lane, dsn).await;
            let owner = synthetic_owner(lane, "PR");
            let password = format!("Pr{}_{:X}", lane, std::process::id());
            create_user(&cx, &conn, &owner, &password).await;
            let setup = conn
                .execute(
                    &cx,
                    &format!("ALTER USER {owner} ENABLE EDITIONS FOR PROCEDURE"),
                    &[],
                )
                .await;
            let proof = if setup.is_ok() {
                let capabilities = probe_editions_catalog(&cx, &conn).await;
                Some(probe_editions_enabled(&cx, &conn, &capabilities, &owner, "VIEW").await)
            } else {
                None
            };
            drop_user(&cx, &conn, &owner).await;
            setup.unwrap_or_else(|error| panic!("{lane} procedure-only setup failed: {error}"));
            let proof = proof.expect("setup succeeded");
            assert_eq!(proof.owner_enabled, EditionsProofStatus::Proven, "{lane}");
            assert_eq!(proof.type_enabled, EditionsProofStatus::Disabled, "{lane}");
            assert_refused_before_statement(&proof, lane);
            println!(
                "{}",
                serde_json::json!({"case_id":"editions_probe_type_omitted_refuses_live","lane":lane,"object_type":"VIEW","statement_outcome":"NOT_STARTED","verdict":"pass"})
            );
        }
    });
}

#[test]
fn editions_probe_other_owner_without_dba_privilege_unknown_live() {
    if !enabled() {
        return;
    }
    run_with_cx(|cx| async move {
        for (lane, dsn, _) in LANES {
            let admin = connect(&cx, lane, dsn).await;
            let low_owner = synthetic_owner(lane, "LOW");
            let target_owner = synthetic_owner(lane, "TG");
            let password = format!("Lo{}_{:X}", lane, std::process::id());
            create_user(&cx, &admin, &low_owner, &password).await;
            create_user(&cx, &admin, &target_owner, &password).await;
            let low_conn = RustOracleConnection::connect(
                &cx,
                OracleConnectOptions {
                    connect_string: (*dsn).to_owned(),
                    username: Some(low_owner.clone()),
                    password: Some(password),
                    auth_adapter: AuthAdapter::Password,
                    ..Default::default()
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{lane} low-privilege connect failed: {error}"));
            let capabilities = probe_editions_catalog(&cx, &low_conn).await;
            let proof =
                probe_editions_enabled(&cx, &low_conn, &capabilities, &target_owner, "VIEW").await;
            drop(low_conn);
            drop_user(&cx, &admin, &low_owner).await;
            drop_user(&cx, &admin, &target_owner).await;
            assert_eq!(proof.owner_enabled, EditionsProofStatus::Unknown, "{lane}");
            assert_eq!(proof.type_enabled, EditionsProofStatus::Unknown, "{lane}");
            assert!(!proof.is_proven(), "{lane}");
            assert_refused_before_statement(&proof, lane);
            println!(
                "{}",
                serde_json::json!({"case_id":"editions_probe_other_owner_without_dba_privilege_unknown_live","lane":lane,"verdict":"pass"})
            );
        }
    });
}

#[test]
fn editions_probe_columns_present_per_version_live() {
    if !enabled() {
        return;
    }
    run_with_cx(|cx| async move {
        for (lane, dsn, version_prefix) in LANES {
            let conn = connect(&cx, lane, dsn).await;
            let capabilities = probe_editions_catalog(&cx, &conn).await;
            assert!(
                capabilities.metadata_visible,
                "{lane} ALL_TAB_COLUMNS unavailable"
            );
            assert!(
                capabilities
                    .server_version
                    .as_deref()
                    .is_some_and(|version| version.starts_with(version_prefix)),
                "{lane} version mismatch"
            );
            for column in &capabilities.columns {
                println!(
                    "{}",
                    serde_json::json!({
                        "case_id":"editions_probe_columns_present_per_version_live",
                        "version":capabilities.server_version,
                        "lane":lane,
                        "view":column.view,
                        "column":column.column,
                        "present":column.present,
                        "verdict":"pass"
                    })
                );
            }
        }
    });
}
