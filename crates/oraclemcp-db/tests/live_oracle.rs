//! Live Oracle integration tests for `oraclemcp-db` (bead P0-3; part of the
//! §12 real-Oracle matrix, T-INTEG).
//!
//! Gated behind the `live-xe` feature AND a runtime reachability probe: if no
//! Oracle is reachable, each test prints a loud SKIP banner and returns rather
//! than failing — so CI without a database stays
//! green, matching the repo's `live-xe` / estate-absent convention.
//!
//! To run against the repo's containerized Oracle 23ai Free:
//!   cargo test -p oraclemcp-db --features live-xe -- --nocapture
//! Override target with ORACLEMCP_TEST_DSN / _USER / _PASSWORD.
//! Optional TCPS fields: ORACLEMCP_TEST_WALLET_LOCATION,
//! ORACLEMCP_TEST_WALLET_PASSWORD, ORACLEMCP_TEST_SSL_SERVER_DN_MATCH,
//! ORACLEMCP_TEST_SSL_SERVER_CERT_DN, ORACLEMCP_TEST_USE_SNI.
//! Optional proxy auth fields: ORACLEMCP_TEST_PROXY_USER and
//! ORACLEMCP_TEST_PROXY_TARGET_SCHEMA. The database must grant:
//!   ALTER USER <target> GRANT CONNECT THROUGH <proxy>;
//! Optional app-context triples:
//!   ORACLEMCP_TEST_APP_CONTEXT='namespace:key:value;namespace:key2:value2'
//! The database must have matching application context namespaces available.
//! Optional edition check: ORACLEMCP_TEST_EDITION must name a valid edition.
//! Optional DRCP check: ORACLEMCP_TEST_DRCP=1 and optionally
//! ORACLEMCP_TEST_DRCP_CLASS.
#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_db::{
    AuthAdapter, CatalogExtractRequest, CatalogRowSetName, DbError, DependentsProbe, DrcpConfig,
    OracleBind, OracleConnectOptions, OracleConnection, OracleSessionIdentity, QueryCaps,
    RustOracleConnection, SearchDetailLevel, SessionPurity, explain_plan, extract_catalog_rowsets,
    plan_cost_estimate, probe_dependents, search_objects,
};
use oraclemcp_db::{LeaseManager, OraclePool, PoolSettings, SerializeOptions, serialize_row};
use serde_json::json;
use std::time::{Duration, Instant};

/// Run an async test body on a fresh current-thread runtime, handing it the
/// installed request `Cx`. The only `block_on` in this file.
fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    // Live tests do real socket I/O, so the runtime needs a reactor (release-gre.16).
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("rt");
    runtime.block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx");
        body(cx).await
    })
}

fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name).ok().map(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn env_app_context() -> Option<Vec<(String, String, String)>> {
    let raw = std::env::var("ORACLEMCP_TEST_APP_CONTEXT").ok()?;
    let mut out = Vec::new();
    for (index, item) in raw
        .split(';')
        .filter(|item| !item.trim().is_empty())
        .enumerate()
    {
        let parts: Vec<&str> = item.splitn(3, ':').collect();
        assert!(
            parts.len() == 3 && !parts[0].trim().is_empty() && !parts[1].trim().is_empty(),
            "ORACLEMCP_TEST_APP_CONTEXT entry {index} must be namespace:key:value"
        );
        out.push((
            parts[0].trim().to_owned(),
            parts[1].trim().to_owned(),
            parts[2].to_owned(),
        ));
    }
    assert!(
        !out.is_empty(),
        "ORACLEMCP_TEST_APP_CONTEXT must contain at least one namespace:key:value entry"
    );
    Some(out)
}

async fn connect_or_skip(
    cx: &Cx,
    test_name: &str,
    opts: OracleConnectOptions,
) -> Option<RustOracleConnection> {
    match RustOracleConnection::connect(cx, opts).await {
        Ok(conn) => Some(conn),
        Err(e) => {
            eprintln!(
                "[live-xe] SKIP {test_name}: no reachable Oracle or prerequisite missing ({e}); \
                 set ORACLEMCP_TEST_DSN / _USER / _PASSWORD and optional profile-matrix env vars"
            );
            None
        }
    }
}

fn env_or_skip(test_name: &str, name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(_) => {
            eprintln!("[live-xe] SKIP {test_name}: set {name}");
            None
        }
    }
}

fn test_opts() -> OracleConnectOptions {
    let proxy_user = std::env::var("ORACLEMCP_TEST_PROXY_USER").ok();
    let proxy_target_schema = std::env::var("ORACLEMCP_TEST_PROXY_TARGET_SCHEMA").ok();
    let auth_adapter = match (&proxy_user, &proxy_target_schema) {
        (Some(proxy_user), Some(target_schema)) => AuthAdapter::Proxy {
            proxy_user: proxy_user.clone(),
            target_schema: target_schema.clone(),
        },
        (None, None) => AuthAdapter::Password,
        _ => {
            panic!(
                "set both ORACLEMCP_TEST_PROXY_USER and ORACLEMCP_TEST_PROXY_TARGET_SCHEMA for proxy live tests"
            )
        }
    };
    OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN")
            .unwrap_or_else(|_| "//localhost:1521/FREEPDB1".to_owned()),
        username: Some(
            proxy_user
                .or_else(|| std::env::var("ORACLEMCP_TEST_USER").ok())
                .unwrap_or_else(|| "system".to_owned()),
        ),
        password: Some(
            std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap_or_else(|_| "test_password".to_owned()),
        ),
        auth_adapter,
        wallet_location: std::env::var("ORACLEMCP_TEST_WALLET_LOCATION")
            .ok()
            .map(Into::into),
        wallet_password: std::env::var("ORACLEMCP_TEST_WALLET_PASSWORD").ok(),
        ssl_server_dn_match: env_bool("ORACLEMCP_TEST_SSL_SERVER_DN_MATCH"),
        ssl_server_cert_dn: std::env::var("ORACLEMCP_TEST_SSL_SERVER_CERT_DN").ok(),
        use_sni: env_bool("ORACLEMCP_TEST_USE_SNI"),
        session_identity: Some(OracleSessionIdentity {
            program: Some("oraclemcp-live-program".to_owned()),
            machine: Some("oraclemcp-live-machine".to_owned()),
            os_user: Some("oraclemcp-live-os-user".to_owned()),
            terminal: Some("oraclemcp-live-terminal".to_owned()),
            module: Some("oraclemcp-live-test".to_owned()),
            action: Some("oraclemcp-live-action".to_owned()),
            client_identifier: Some("oraclemcp-test-agent".to_owned()),
            client_info: Some("oraclemcp-live-client-info".to_owned()),
            driver_name: Some("oraclemcp-live-driver".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn live_profile_config_username_password_identity_and_session_fields_round_trip() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(
            &cx,
            "live_profile_config_username_password_identity_and_session_fields_round_trip",
            test_opts(),
        )
        .await
        else {
            return;
        };
        conn.ping(&cx).await.expect("profile-matrix ping");

        // This is the database metadata source used by oracle_connection_info.
        let info = conn.describe(&cx).await.expect("profile-matrix describe");
        assert!(
            info.session_user.is_some(),
            "username/password thin connection should report a session user"
        );
        assert_eq!(info.module.as_deref(), Some("oraclemcp-live-test"));
        assert_eq!(info.action.as_deref(), Some("oraclemcp-live-action"));
        assert_eq!(
            info.client_identifier.as_deref(),
            Some("oraclemcp-test-agent")
        );
        assert_eq!(
            info.client_info.as_deref(),
            Some("oraclemcp-live-client-info")
        );
        if let Some(program) = info.program.as_deref() {
            assert_eq!(program, "oraclemcp-live-program");
        }
        if let Some(machine) = info.machine.as_deref() {
            assert_eq!(machine, "oraclemcp-live-machine");
        }
        if let Some(os_user) = info.os_user.as_deref() {
            assert_eq!(os_user, "oraclemcp-live-os-user");
        }
        if let Some(terminal) = info.terminal.as_deref() {
            assert_eq!(terminal, "oraclemcp-live-terminal");
        }
        if let Some(client_driver) = info.client_driver.as_deref() {
            assert!(
                client_driver.contains("oraclemcp-live-driver"),
                "client_driver should include configured driver name when visible: {client_driver}"
            );
        }
    });
}

#[test]
fn live_profile_config_invalid_edition_fails_at_connect_time() {
    run_with_cx(|cx| async move {
        let opts = test_opts();
        if connect_or_skip(
            &cx,
            "live_profile_config_invalid_edition_fails_at_connect_time/base",
            opts.clone(),
        )
        .await
        .is_none()
        {
            return;
        }

        let invalid_edition = "ORACLEMCP_NO_SUCH_EDITION_000000";
        let mut bad_opts = opts;
        bad_opts
            .session_identity
            .get_or_insert_with(Default::default)
            .edition = Some(invalid_edition.to_owned());
        let err = match RustOracleConnection::connect(&cx, bad_opts).await {
            Ok(_) => panic!("invalid edition unexpectedly connected"),
            Err(err) => err,
        };
        assert!(
            matches!(err, DbError::Connect(_)),
            "invalid edition should fail during thin authentication, got {err}"
        );
        let rendered = err.to_string();
        assert!(
            !rendered.contains(invalid_edition),
            "edition names must be redacted from driver errors: {rendered}"
        );
    });
}

#[test]
fn live_profile_config_wallet_username_password_when_configured() {
    run_with_cx(|cx| async move {
        if env_or_skip(
            "live_profile_config_wallet_username_password_when_configured",
            "ORACLEMCP_TEST_WALLET_LOCATION",
        )
        .is_none()
        {
            return;
        }
        let opts = test_opts();
        assert!(
            opts.username.is_some() && opts.password.is_some(),
            "TCPS wallet mode in thin still uses explicit username/password"
        );
        let Some(conn) = connect_or_skip(
            &cx,
            "live_profile_config_wallet_username_password_when_configured",
            opts,
        )
        .await
        else {
            return;
        };
        conn.ping(&cx).await.expect("wallet username/password ping");
    });
}

#[test]
fn live_profile_config_proxy_auth_when_configured() {
    run_with_cx(|cx| async move {
        let Some(proxy_user) = env_or_skip(
            "live_profile_config_proxy_auth_when_configured",
            "ORACLEMCP_TEST_PROXY_USER",
        ) else {
            return;
        };
        let Some(target_schema) = env_or_skip(
            "live_profile_config_proxy_auth_when_configured",
            "ORACLEMCP_TEST_PROXY_TARGET_SCHEMA",
        ) else {
            return;
        };
        let Some(conn) = connect_or_skip(
            &cx,
            "live_profile_config_proxy_auth_when_configured",
            test_opts(),
        )
        .await
        else {
            return;
        };
        let rows = conn
            .query_rows(
                &cx,
                "SELECT \
                    SYS_CONTEXT('USERENV','PROXY_USER') AS proxy_user, \
                    SYS_CONTEXT('USERENV','SESSION_USER') AS session_user, \
                    SYS_CONTEXT('USERENV','CURRENT_SCHEMA') AS current_schema \
                 FROM dual",
                &[],
            )
            .await
            .expect("proxy SYS_CONTEXT query");
        assert_eq!(
            rows[0]
                .text("PROXY_USER")
                .map(str::to_ascii_uppercase)
                .as_deref(),
            Some(proxy_user.to_ascii_uppercase().as_str())
        );
        assert_eq!(
            rows[0]
                .text("SESSION_USER")
                .map(str::to_ascii_uppercase)
                .as_deref(),
            Some(target_schema.to_ascii_uppercase().as_str())
        );
        assert_eq!(
            rows[0]
                .text("CURRENT_SCHEMA")
                .map(str::to_ascii_uppercase)
                .as_deref(),
            Some(target_schema.to_ascii_uppercase().as_str())
        );
    });
}

#[test]
fn live_profile_config_sdu_override_connects() {
    run_with_cx(|cx| async move {
        let mut opts = test_opts();
        opts.sdu = Some(32_768);
        let Some(conn) =
            connect_or_skip(&cx, "live_profile_config_sdu_override_connects", opts).await
        else {
            return;
        };
        let rows = conn
            .query_rows(&cx, "SELECT 1 AS sdu_probe FROM dual", &[])
            .await
            .expect("SDU override probe query");
        assert_eq!(rows[0].text("SDU_PROBE"), Some("1"));
    });
}

#[test]
fn live_profile_config_drcp_routing_when_configured() {
    run_with_cx(|cx| async move {
        if !env_bool("ORACLEMCP_TEST_DRCP").unwrap_or(false) {
            eprintln!(
                "[live-xe] SKIP live_profile_config_drcp_routing_when_configured: set ORACLEMCP_TEST_DRCP=1"
            );
            return;
        }
        let mut opts = test_opts();
        let base = opts.connect_string.clone();
        let drcp = DrcpConfig {
            pooled: true,
            connection_class: std::env::var("ORACLEMCP_TEST_DRCP_CLASS").ok(),
            purity: SessionPurity::Reuse,
        };
        opts.connect_string = drcp.apply_to_connect_string(&base);
        assert_ne!(
            opts.connect_string, base,
            "DRCP routing should transform the connect string"
        );
        let rendered = format!("{opts:?}");
        assert!(
            !rendered.contains(&opts.connect_string),
            "debug output must not leak transformed connect strings"
        );
        let Some(conn) = connect_or_skip(
            &cx,
            "live_profile_config_drcp_routing_when_configured",
            opts,
        )
        .await
        else {
            return;
        };
        conn.ping(&cx).await.expect("DRCP ping");
    });
}

#[test]
fn live_app_context_round_trip_when_configured() {
    run_with_cx(|cx| async move {
        let Some(app_context) = env_app_context() else {
            eprintln!(
                "[live-xe] SKIP live_app_context_round_trip_when_configured: set ORACLEMCP_TEST_APP_CONTEXT"
            );
            return;
        };
        let mut opts = test_opts();
        if let Err(e) = RustOracleConnection::connect(&cx, opts.clone()).await {
            eprintln!(
                "[live-xe] SKIP live_app_context_round_trip_when_configured: no reachable Oracle ({e}); \
                 set ORACLEMCP_TEST_*"
            );
            return;
        }
        opts.app_context = app_context.clone();
        let conn = RustOracleConnection::connect(&cx, opts)
            .await
            .expect("app-context connect should succeed after the base live connection succeeds");

        for (namespace, key, expected) in app_context {
            let rows = conn
                .query_rows(
                    &cx,
                    "SELECT SYS_CONTEXT(:1, :2) AS value FROM dual",
                    &[
                        OracleBind::from(namespace.as_str()),
                        OracleBind::from(key.as_str()),
                    ],
                )
                .await
                .expect("SYS_CONTEXT query");
            assert_eq!(rows[0].text("VALUE"), Some(expected.as_str()));
        }
    });
}

#[test]
fn live_edition_round_trip_when_configured() {
    run_with_cx(|cx| async move {
        let Ok(edition) = std::env::var("ORACLEMCP_TEST_EDITION") else {
            eprintln!(
                "[live-xe] SKIP live_edition_round_trip_when_configured: set ORACLEMCP_TEST_EDITION"
            );
            return;
        };
        let mut opts = test_opts();
        if let Err(e) = RustOracleConnection::connect(&cx, opts.clone()).await {
            eprintln!(
                "[live-xe] SKIP live_edition_round_trip_when_configured: no reachable Oracle ({e}); \
                 set ORACLEMCP_TEST_*"
            );
            return;
        }
        let identity = opts.session_identity.get_or_insert_with(Default::default);
        identity.edition = Some(edition.clone());

        let conn = RustOracleConnection::connect(&cx, opts)
            .await
            .expect("edition connect should succeed after the base live connection succeeds");
        let rows = conn
            .query_rows(
                &cx,
                "SELECT SYS_CONTEXT('USERENV', 'CURRENT_EDITION_NAME') AS edition FROM dual",
                &[],
            )
            .await
            .expect("edition SYS_CONTEXT query");
        assert_eq!(rows[0].text("EDITION"), Some(edition.as_str()));
    });
}

#[test]
fn live_connect_ping_query_bind_describe() {
    run_with_cx(|cx| async move {
        let conn = match RustOracleConnection::connect(&cx, test_opts()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "[live-xe] SKIP live_connect_ping_query_bind_describe: no reachable Oracle ({e}); \
                     set ORACLEMCP_TEST_*"
                );
                return;
            }
        };
        conn.ping(&cx).await.expect("ping");

        let rows = conn
            .query_rows(&cx, "SELECT 1 AS one FROM dual", &[])
            .await
            .expect("scalar query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text("ONE"), Some("1"));

        // Bind values are bound, never interpolated.
        let rows = conn
            .query_rows(
                &cx,
                "SELECT :1 AS v FROM dual",
                &[OracleBind::from("hello")],
            )
            .await
            .expect("bind query");
        assert_eq!(rows[0].text("V"), Some("hello"));

        let rows = conn
            .query_rows(&cx, "SELECT :1 AS n FROM dual", &[OracleBind::from(42i64)])
            .await
            .expect("int bind");
        assert_eq!(rows[0].parse_i64("N"), Some(42));

        let info = conn.describe(&cx).await.expect("describe");
        assert!(
            info.server_version.is_some(),
            "server_version should be populated"
        );
        assert_eq!(info.module.as_deref(), Some("oraclemcp-live-test"));
        assert_eq!(
            info.client_identifier.as_deref(),
            Some("oraclemcp-test-agent")
        );
        if let Some(program) = info.program.as_deref() {
            assert_eq!(program, "oraclemcp-live-program");
        }
        if let Some(machine) = info.machine.as_deref() {
            assert_eq!(machine, "oraclemcp-live-machine");
        }
        if let Some(os_user) = info.os_user.as_deref() {
            assert_eq!(os_user, "oraclemcp-live-os-user");
        }
        if let Some(terminal) = info.terminal.as_deref() {
            assert_eq!(terminal, "oraclemcp-live-terminal");
        }
        assert!(
            info.session_user.is_some(),
            "session_user should be populated"
        );
        assert!(
            info.current_user.is_some(),
            "current_user should be populated"
        );
        eprintln!(
            "[live-xe] connected: version={:?} role={:?} open_mode={:?} schema={:?}",
            info.server_version, info.database_role, info.open_mode, info.current_schema
        );

        let rows = conn
            .query_rows(&cx, "SELECT 1 AS after_describe FROM dual", &[])
            .await
            .expect("query after describe");
        assert_eq!(rows[0].text("AFTER_DESCRIBE"), Some("1"));
    });
}

/// K2: the live `server_features` probe must match the server generation.
///
/// Self-adapting: it reads the negotiated version tuple and asserts the derived
/// helpers exactly equal the pure `derive_version_capabilities(major)` math,
/// plus per-generation invariants (xe18 → no vector/boolean; xe21 → json but no
/// vector; free23 → vector+boolean+json). `edition`/`partitioning` are
/// privilege-degradable, so they are asserted only when present (a low-privilege
/// account omits them without failing the probe). Point the harness at any lane
/// via `ORACLEMCP_TEST_DSN` / `_USER` / `_PASSWORD`.
#[test]
fn live_server_features_probe_matches_generation() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(
            &cx,
            "live_server_features_probe_matches_generation",
            test_opts(),
        )
        .await
        else {
            return;
        };

        let info = conn
            .describe(&cx)
            .await
            .expect("describe should carry server_features");
        let features = info
            .server_features
            .expect("server_features populated on a live thin connection");

        // Driver-negotiated facts: always present on a real connection.
        let version = features
            .version
            .expect("server_version_tuple negotiated at connect time");
        assert!(
            features.sdu.unwrap_or(0) > 0,
            "SDU should be a positive negotiated size"
        );
        assert!(
            features.supports_pipelining.is_some(),
            "pipelining reported"
        );
        assert!(features.supports_oob.is_some(), "oob reported");

        let major = version.major;

        // The derived helpers must EXACTLY match the pure version math — no
        // drift between the live path and the offline-tested derivation.
        let expected = oraclemcp_db::derive_version_capabilities(major);
        assert_eq!(features.supports_vector, Some(expected.supports_vector));
        assert_eq!(features.supports_json, Some(expected.supports_json));
        assert_eq!(features.supports_boolean, Some(expected.supports_boolean));
        assert_eq!(features.supports_soda, Some(expected.supports_soda));

        // Per-generation invariants for the K2 lanes.
        if major >= 23 {
            assert_eq!(features.supports_vector, Some(true), "23ai+ has vector");
            assert_eq!(features.supports_boolean, Some(true), "23ai+ has BOOLEAN");
            assert_eq!(features.supports_json, Some(true), "23ai+ has JSON type");
        } else if major == 21 {
            assert_eq!(features.supports_json, Some(true), "21c has JSON type");
            assert_eq!(features.supports_vector, Some(false), "21c: no vector");
            assert_eq!(features.supports_boolean, Some(false), "21c: no BOOLEAN");
        } else if major <= 18 {
            assert_eq!(features.supports_vector, Some(false), "<=18c: no vector");
            assert_eq!(features.supports_boolean, Some(false), "<=18c: no BOOLEAN");
            assert_eq!(features.supports_json, Some(false), "<=18c: no JSON type");
        }

        // Privilege-degradable dictionary bits: assert shape only when present.
        if let Some(edition) = features.edition.as_deref() {
            assert!(
                edition.to_uppercase().contains("DATABASE"),
                "edition banner should be an Oracle Database product descriptor: {edition}"
            );
        }

        eprintln!(
            "[live-xe] server_features: version={}.{}.{} sdu={:?} pipelining={:?} oob={:?} \
             vector={:?} json={:?} boolean={:?} soda={:?} edition={:?} partitioning={:?}",
            major,
            version.minor,
            version.patch,
            features.sdu,
            features.supports_pipelining,
            features.supports_oob,
            features.supports_vector,
            features.supports_json,
            features.supports_boolean,
            features.supports_soda,
            features.edition,
            features.partitioning,
        );
    });
}

#[test]
fn live_catalog_extract_current_schema_rowsets() {
    run_with_cx(|cx| async move {
        let test_name = "live_catalog_extract_current_schema_rowsets";
        let Some(conn) = connect_or_skip(&cx, test_name, test_opts()).await else {
            return;
        };

        let report = extract_catalog_rowsets(
            &cx,
            &conn,
            &CatalogExtractRequest::for_current_schema().with_plscope(true),
        )
        .await
        .expect("live catalog extraction runs against Oracle dictionary views");

        assert!(
            !report.schema_names.is_empty(),
            "current schema must resolve"
        );
        let rowsets = report
            .batches
            .iter()
            .map(|batch| batch.row_set)
            .collect::<Vec<_>>();
        assert!(rowsets.starts_with(CatalogRowSetName::CORE));
        assert!(rowsets.contains(&CatalogRowSetName::Objects));
        assert!(rowsets.contains(&CatalogRowSetName::RoutineArguments));
        assert!(rowsets.contains(&CatalogRowSetName::Dependencies));
        eprintln!(
            "[live-xe] catalog extraction schema={:?} batches={} warnings={}",
            report.schema_names,
            report.batches.len(),
            report.warnings.len()
        );
    });
}

#[test]
#[ignore = "profiling helper; run explicitly with --ignored --nocapture"]
fn live_perf_phase_split_connect_ping_query_describe() {
    run_with_cx(|cx| async move {
        let opts = test_opts();
        if let Err(e) = RustOracleConnection::connect(&cx, opts.clone()).await {
            eprintln!(
                "[live-xe] SKIP live_perf_phase_split_connect_ping_query_describe: no reachable Oracle ({e}); \
                 set ORACLEMCP_TEST_*"
            );
            return;
        }

        // Time an awaited DB-phase future and emit a CSV row, mirroring the old
        // closure-timed helper now that each phase is async.
        macro_rules! emit_live_phase {
            ($scope:expr, $run:expr, $phase:expr, $fut:expr) => {{
                let start = Instant::now();
                $fut.map(|_| ())
                    .unwrap_or_else(|e| panic!("{} {} failed: {e}", $scope, $phase));
                eprintln!(
                    "{},{},{},{}",
                    $scope,
                    $run,
                    $phase,
                    start.elapsed().as_nanos()
                );
            }};
        }

        eprintln!("scope,run,phase,ns");
        for run in 1..=20 {
            let start = Instant::now();
            let conn = RustOracleConnection::connect(&cx, opts.clone())
                .await
                .expect("cold connect");
            eprintln!("cold,{run},connect,{}", start.elapsed().as_nanos());

            emit_live_phase!("cold", run, "ping", conn.ping(&cx).await);
            emit_live_phase!(
                "cold",
                run,
                "query_scalar",
                conn.query_rows(&cx, "SELECT 1 AS one FROM dual", &[]).await
            );
            emit_live_phase!(
                "cold",
                run,
                "query_bind",
                conn.query_rows(
                    &cx,
                    "SELECT :1 AS v FROM dual",
                    &[OracleBind::from("hello")]
                )
                .await
            );
            emit_live_phase!("cold", run, "describe", conn.describe(&cx).await);
        }

        let conn = RustOracleConnection::connect(&cx, opts)
            .await
            .expect("steady connect");
        for run in 1..=50 {
            emit_live_phase!("steady", run, "ping", conn.ping(&cx).await);
            emit_live_phase!(
                "steady",
                run,
                "query_scalar",
                conn.query_rows(&cx, "SELECT 1 AS one FROM dual", &[]).await
            );
            emit_live_phase!(
                "steady",
                run,
                "query_bind",
                conn.query_rows(
                    &cx,
                    "SELECT :1 AS v FROM dual",
                    &[OracleBind::from("hello")]
                )
                .await
            );
            emit_live_phase!("steady", run, "describe", conn.describe(&cx).await);
        }
    });
}

#[test]
fn live_type_fidelity_number_string_and_iso_date() {
    run_with_cx(|cx| async move {
        let conn = match RustOracleConnection::connect(&cx, test_opts()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[live-xe] SKIP live_type_fidelity: {e}");
                return;
            }
        };
        // A 20-digit NUMBER (overflows f64), a DATE, and a BINARY_DOUBLE.
        let rows = conn
            .query_rows(
                &cx,
                "SELECT 12345678901234567890 AS big_num, \
                 TO_DATE('2026-06-01 12:00:00','YYYY-MM-DD HH24:MI:SS') AS d, \
                 CAST(3.5 AS BINARY_DOUBLE) AS bd FROM dual",
                &[],
            )
            .await
            .expect("query");
        let v = serialize_row(&rows[0], &SerializeOptions::default());
        eprintln!("[live-xe] type-fidelity row: {v}");
        // NUMBER serializes losslessly as a STRING (never f64-truncated).
        assert_eq!(v["BIG_NUM"], json!("12345678901234567890"));
        // DATE comes back ISO-8601 thanks to the canonical session NLS.
        assert_eq!(v["D"], json!("2026-06-01T12:00:00"));
        // BINARY_DOUBLE is a JSON number.
        assert_eq!(v["BD"], json!(3.5));
    });
}

#[test]
fn tstz_live_bind_fetch_preserves_numeric_offset() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(
            &cx,
            "tstz_live_bind_fetch_preserves_numeric_offset",
            test_opts(),
        )
        .await
        else {
            return;
        };
        let expected = "2026-06-29T12:34:56.987654321-05:30";
        let rows = conn
            .query_rows(
                &cx,
                "SELECT :1 AS tstz_value FROM dual",
                &[OracleBind::TimestampTz {
                    year: 2026,
                    month: 6,
                    day: 29,
                    hour: 12,
                    minute: 34,
                    second: 56,
                    nanosecond: 987_654_321,
                    offset_minutes: -330,
                }],
            )
            .await
            .expect("TSTZ bind/fetch query");
        let v = serialize_row(&rows[0], &SerializeOptions::default());
        eprintln!(
            "{}",
            json!({
                "suite": "live_oracle",
                "test": "tstz_live_bind_fetch_preserves_numeric_offset",
                "phase": "assert",
                "event": "tstz_bind_fetch",
                "expected": expected,
                "actual": v["TSTZ_VALUE"],
            })
        );
        assert_eq!(v["TSTZ_VALUE"], json!(expected));
    });
}

#[test]
fn live_query_materializes_lob_locators_with_caps() {
    run_with_cx(|cx| async move {
        let opts = test_opts();
        let setup = match RustOracleConnection::connect(&cx, opts.clone()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[live-xe] SKIP live_query_materializes_lob_locators_with_caps: {e}");
                return;
            }
        };
        let table = "ORACLEMCP_LOB_T";
        let _ = setup
            .execute(&cx, &format!("DROP TABLE {table} PURGE"), &[])
            .await;
        setup
            .execute(
                &cx,
                &format!("CREATE TABLE {table} (id NUMBER, c CLOB, b BLOB)"),
                &[],
            )
            .await
            .expect("create LOB table");
        setup
            .execute(
                &cx,
                &format!(
                    "INSERT INTO {table} VALUES (1, TO_CLOB(RPAD('x', 20, 'x')), TO_BLOB(HEXTORAW('DEADBEEFCAFEBABE')))"
                ),
                &[],
            )
            .await
            .expect("insert LOB row");
        setup.commit(&cx).await.expect("commit LOB row");

        let direct = setup
            .query_rows_with_serialize_options(
                &cx,
                &format!("SELECT c, b FROM {table} WHERE id = :1"),
                &[OracleBind::from(1i32)],
                &SerializeOptions {
                    max_lob_chars: 4,
                    max_blob_bytes: 2,
                    ..Default::default()
                },
            )
            .await
            .expect("direct LOB query should materialize locators");
        assert_eq!(direct[0].text("C"), Some("xxxx"));
        assert_eq!(
            direct[0].cell("B").and_then(|cell| cell.bytes.as_deref()),
            Some([0xDE, 0xAD].as_slice())
        );

        let pool = OraclePool::connect(&cx, opts, PoolSettings::default())
            .await
            .expect("pool should connect after setup connection succeeds");
        let caps = QueryCaps {
            max_rows: 1,
            max_result_bytes: 1_000_000,
        };
        let serialize_opts = SerializeOptions {
            max_lob_chars: 4,
            max_blob_bytes: 2,
            ..Default::default()
        };
        let response = pool
            .read_query(
                &cx,
                format!("SELECT c, b FROM {table} WHERE id = :1"),
                vec![OracleBind::from(1i32)],
                caps,
                0,
                serialize_opts,
            )
            .await
            .expect("LOB query should materialize locators");

        assert_eq!(response.row_count, 1);
        assert_eq!(
            response.rows[0]["C"],
            json!({ "value": "xxxx", "truncated": true, "char_length": 20 })
        );
        assert_eq!(response.rows[0]["B"]["encoding"], json!("base64"));
        assert_eq!(response.rows[0]["B"]["data"], json!("3q0="));
        assert_eq!(response.rows[0]["B"]["byte_length"], json!(8));
        assert_eq!(response.rows[0]["B"]["truncated"], json!(true));
        let _ = setup
            .execute(&cx, &format!("DROP TABLE {table} PURGE"), &[])
            .await;
    });
}

#[test]
fn live_implicit_resultset_serializes_ref_cursor_with_caps() {
    run_with_cx(|cx| async move {
        let conn = match RustOracleConnection::connect(&cx, test_opts()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[live-xe] SKIP live_implicit_resultset_serializes_ref_cursor: {e}");
                return;
            }
        };
        let rows = conn
            .query_rows_with_serialize_options(
                &cx,
                "DECLARE
                   rc SYS_REFCURSOR;
                 BEGIN
                   OPEN rc FOR
                     SELECT 1 AS n, 'one' AS label FROM dual
                     UNION ALL
                     SELECT 2 AS n, 'two' AS label FROM dual;
                   DBMS_SQL.RETURN_RESULT(rc);
                 END;",
                &[],
                &SerializeOptions {
                    max_nested_cursor_rows: 1,
                    max_nested_cursor_cells: 8,
                    ..Default::default()
                },
            )
            .await
            .expect("implicit REF CURSOR result should serialize");

        assert_eq!(rows.len(), 1);
        let rendered = serialize_row(
            &rows[0],
            &SerializeOptions {
                max_nested_cursor_rows: 1,
                max_nested_cursor_cells: 8,
                ..Default::default()
            },
        );
        let nested = &rendered["IMPLICIT_RESULT_1"];
        assert_eq!(nested["columns"], json!(["N", "LABEL"]));
        assert_eq!(nested["row_count"], json!(1));
        assert_eq!(nested["fetched_count"], json!(1));
        assert_eq!(nested["truncated"], json!(true));
        assert_eq!(nested["rows"][0], json!({ "N": "1", "LABEL": "one" }));
    });
}

#[test]
fn live_cursor_expression_serializes_ref_cursor_with_caps() {
    run_with_cx(|cx| async move {
        let conn = match RustOracleConnection::connect(&cx, test_opts()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[live-xe] SKIP live_cursor_expression_serializes_ref_cursor: {e}");
                return;
            }
        };
        let rows = conn
            .query_rows_with_serialize_options(
                &cx,
                "SELECT CURSOR(
                   SELECT 1 AS n FROM dual
                   UNION ALL
                   SELECT 2 AS n FROM dual
                 ) AS child FROM dual",
                &[],
                &SerializeOptions {
                    max_nested_cursor_rows: 1,
                    max_nested_cursor_cells: 4,
                    ..Default::default()
                },
            )
            .await
            .expect("cursor expression should serialize");

        assert_eq!(rows.len(), 1);
        let rendered = serialize_row(
            &rows[0],
            &SerializeOptions {
                max_nested_cursor_rows: 1,
                max_nested_cursor_cells: 4,
                ..Default::default()
            },
        );
        let nested = &rendered["CHILD"];
        assert_eq!(nested["columns"], json!(["N"]));
        assert_eq!(nested["row_count"], json!(1));
        assert_eq!(nested["fetched_count"], json!(1));
        assert_eq!(nested["truncated"], json!(true));
        assert_eq!(nested["rows"][0], json!({ "N": "1" }));
    });
}

#[test]
fn live_lease_lifecycle_on_a_pinned_session() {
    run_with_cx(|cx| async move {
        let conn = match RustOracleConnection::connect(&cx, test_opts()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[live-xe] SKIP live_lease_lifecycle: {e}");
                return;
            }
        };
        let mgr = LeaseManager::new();
        // acquire applies the (empty) login script + stamps DBMS_APPLICATION_INFO.
        let id = mgr
            .acquire(
                &cx,
                "live",
                "agent-live",
                Duration::from_secs(900),
                &[],
                Box::new(conn),
            )
            .await
            .expect("acquire lease");
        assert_eq!(mgr.active_count(), 1);
        let info = mgr.info(&cx, &id).await.expect("info");
        assert_eq!(info.agent_identity, "agent-live");
        assert!(info.expires_in_ms > 0);

        // Side-effect-free transaction lifecycle on the pinned session.
        mgr.begin_transaction(&cx, &id).await.expect("begin");
        mgr.savepoint(&cx, &id, "oraclemcp_sp1")
            .await
            .expect("savepoint");
        mgr.rollback(&cx, &id).await.expect("rollback");
        mgr.commit(&cx, &id).await.expect("commit (no-op)");
        let renewed = mgr.renew(&cx, &id).await.expect("renew");
        assert!(renewed.expires_in_ms > 0);

        mgr.release(&cx, &id).await;
        assert_eq!(mgr.active_count(), 0);
        assert!(mgr.info(&cx, &id).await.is_err(), "released lease is gone");
    });
}

#[test]
fn live_query_pagination_caps_and_cursor() {
    run_with_cx(|cx| async move {
        let pool = match OraclePool::connect(&cx, test_opts(), PoolSettings::default()).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[live-xe] SKIP live_query_pagination: {e}");
                return;
            }
        };
        let caps = QueryCaps {
            max_rows: 5,
            max_result_bytes: 1_000_000,
        };
        // Deterministic source of >5 rows.
        let sql = "SELECT object_name FROM all_objects ORDER BY object_name";
        let page1 = pool
            .read_query(&cx, sql, vec![], caps, 0, SerializeOptions::default())
            .await
            .expect("page1");
        assert_eq!(page1.row_count, 5);
        assert!(page1.truncated, "all_objects has > 5 rows");
        let offset: usize = page1.next_cursor.as_deref().unwrap().parse().unwrap();
        assert_eq!(offset, 5);

        let page2 = pool
            .read_query(&cx, sql, vec![], caps, offset, SerializeOptions::default())
            .await
            .expect("page2");
        assert_eq!(page2.row_count, 5);
        // Page 2 is a disjoint window (OFFSET/FETCH wrapping is valid Oracle SQL).
        assert_ne!(page1.rows[0], page2.rows[0], "page 2 starts after page 1");
    });
}

#[test]
fn live_savepoint_preview_is_ground_truth_and_rolls_back() {
    run_with_cx(|cx| async move {
        let setup = match RustOracleConnection::connect(&cx, test_opts()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[live-xe] SKIP live_savepoint_preview: {e}");
                return;
            }
        };
        let table = "ORACLEMCP_PREVIEW_T";
        // Best-effort clean slate, then create + seed 3 rows + commit.
        let _ = setup
            .execute(&cx, &format!("DROP TABLE {table}"), &[])
            .await;
        setup
            .execute(&cx, &format!("CREATE TABLE {table} (id NUMBER)"), &[])
            .await
            .expect("create");
        for i in 1..=3 {
            setup
                .execute(&cx, &format!("INSERT INTO {table} VALUES ({i})"), &[])
                .await
                .expect("insert");
        }
        setup.commit(&cx).await.expect("commit");

        // Preview a whole-table DELETE on a leased session.
        let conn = RustOracleConnection::connect(&cx, test_opts())
            .await
            .expect("lease conn");
        let mgr = LeaseManager::new();
        let id = mgr
            .acquire(
                &cx,
                "live",
                "agent",
                Duration::from_secs(300),
                &[],
                Box::new(conn),
            )
            .await
            .expect("lease");
        let impact = mgr
            .preview_dml(&cx, &id, &format!("DELETE FROM {table}"), &[])
            .await
            .expect("preview");
        assert_eq!(
            impact.rows_affected, 3,
            "ground-truth blast radius, not an estimate"
        );
        assert!(impact.rolled_back);
        mgr.release(&cx, &id).await;

        // The DB is unchanged — all 3 rows still present.
        let rows = setup
            .query_rows(&cx, &format!("SELECT COUNT(*) AS n FROM {table}"), &[])
            .await
            .expect("count");
        assert_eq!(
            rows[0].parse_i64("N"),
            Some(3),
            "preview rolled back; DB unchanged"
        );
        setup
            .execute(&cx, &format!("DROP TABLE {table}"), &[])
            .await
            .expect("drop");
        setup.commit(&cx).await.ok();
    });
}

#[test]
fn live_tier1_intelligence_dictionary_tools() {
    run_with_cx(|cx| async move {
        let conn = match RustOracleConnection::connect(&cx, test_opts()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[live-xe] SKIP live_tier1_intelligence: {e}");
                return;
            }
        };
        // schema_inspect: DEMO packages (the synthetic lab ships PKG_AUTONOMOUS etc.).
        let pkgs = oraclemcp_db::list_objects(&cx, &conn, Some("demo"), Some("PACKAGE"), None, 500)
            .await
            .expect("list");
        if !pkgs
            .iter()
            .any(|r| r.text("OBJECT_NAME") == Some("PKG_AUTONOMOUS"))
        {
            eprintln!(
                "[live-xe] SKIP live_tier1_intelligence: DEMO.PKG_AUTONOMOUS fixture not present"
            );
            return;
        }

        // get_ddl of a package returns DDL text.
        let ddl = oraclemcp_db::get_ddl(&cx, &conn, "PACKAGE", "demo", "PKG_AUTONOMOUS")
            .await
            .expect("ddl");
        let ddl = ddl.expect("some ddl");
        assert!(
            ddl.to_uppercase().contains("PACKAGE"),
            "DDL: {}",
            &ddl[..ddl.len().min(60)]
        );

        // compile_errors runs (valid package -> empty is fine).
        let _ = oraclemcp_db::compile_errors(&cx, &conn, "demo", Some("PKG_AUTONOMOUS"))
            .await
            .expect("errors query runs");

        // search_source over ALL_SOURCE.
        let hits =
            oraclemcp_db::search_source(&cx, &conn, Some("demo"), "AUTONOMOUS", None, None, 50)
                .await
                .expect("search");
        assert!(
            !hits.is_empty(),
            "PKG_AUTONOMOUS source should mention AUTONOMOUS"
        );

        // get_ddl rejects an unsupported (injection-shaped) object type.
        assert!(
            oraclemcp_db::get_ddl(&cx, &conn, "TABLE; DROP", "demo", "x")
                .await
                .is_err()
        );
    });
}

#[test]
fn live_pool_thin_roundtrip() {
    run_with_cx(|cx| async move {
        let pool = match OraclePool::connect(&cx, test_opts(), PoolSettings::default()).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[live-xe] SKIP live_pool_thin_roundtrip: pool build failed ({e})");
                return;
            }
        };
        pool.ping(&cx).await.expect("pool ping");
        let rows = pool
            .query_rows(&cx, "SELECT 7 AS n FROM dual", vec![])
            .await
            .expect("pool query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].parse_i64("N"), Some(7));
        assert!(pool.state_connections() >= 1);
    });
}

#[test]
fn live_dbms_output_capture_uses_thin_output_binds() {
    run_with_cx(|cx| async move {
        let conn = match RustOracleConnection::connect(&cx, test_opts()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[live-xe] SKIP live_dbms_output_capture: {e}");
                return;
            }
        };

        conn.enable_dbms_output(&cx, Some(2_000))
            .await
            .expect("enable DBMS_OUTPUT");
        conn.execute(
            &cx,
            "BEGIN DBMS_OUTPUT.PUT_LINE('oraclemcp-live-output'); END;",
            &[],
        )
        .await
        .expect("write DBMS_OUTPUT line");
        let out = conn
            .read_dbms_output(&cx, 10, 200)
            .await
            .expect("capture DBMS_OUTPUT from thin output binds");
        assert_eq!(out.lines, vec!["oraclemcp-live-output"]);
        assert_eq!(out.line_count, 1);
        assert!(!out.truncated);
    });
}

#[test]
fn live_cancelled_query_context_leaves_pool_usable() {
    run_with_cx(|cx| async move {
        let pool = match OraclePool::connect(&cx, test_opts(), PoolSettings::default()).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[live-xe] SKIP live_cancelled_query_context: {e}");
                return;
            }
        };

        // A cancelled request context must abort at the query boundary.
        cx.set_cancel_requested(true);
        let err = pool
            .read_query(
                &cx,
                "SELECT 1 AS n FROM dual",
                vec![],
                QueryCaps::default(),
                0,
                SerializeOptions::default(),
            )
            .await
            .expect_err("cancelled context must abort query boundary");
        assert!(matches!(err, DbError::Cancelled(_)), "{err}");

        // A subsequent (uncancelled) request on the same pool succeeds — the
        // cancellation did not poison the pool.
        cx.set_cancel_requested(false);
        let rows = pool
            .query_rows(&cx, "SELECT 7 AS n FROM dual", vec![])
            .await
            .expect("pool remains usable after cancelled request context");
        assert_eq!(rows[0].parse_i64("N"), Some(7));
    });
}

/// WP-C live verification: the read-only DBA health suite runs against a real
/// 23ai, returns a finding per requested subcheck, and — critically — every
/// subcheck either succeeds against a readable view or degrades to a structured
/// skip; it must NEVER bubble a raw ORA- error or fail the whole call. This is
/// the live half of C1's privilege-degradation acceptance criterion (the unit
/// SQL-shape + degradation tests live in `health.rs`).
#[test]
fn live_db_health_suite_runs_all_subchecks_without_hard_failure() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(
            &cx,
            "live_db_health_suite_runs_all_subchecks_without_hard_failure",
            test_opts(),
        )
        .await
        else {
            return;
        };
        conn.ping(&cx).await.expect("health ping");

        let subchecks = oraclemcp_db::HealthSubcheck::all();
        let findings = oraclemcp_db::run_health(&cx, &conn, subchecks)
            .await
            .expect("live health suite must not lose or cancel its Oracle session");
        assert_eq!(
            findings.len(),
            subchecks.len(),
            "every requested subcheck produces exactly one finding"
        );

        for finding in &findings {
            // The view name each subcheck actually used / attempted is recorded.
            assert!(
                !finding.source_view.is_empty(),
                "{:?} must record its source view",
                finding.subcheck
            );
            // A skipped subcheck is structured (status=skipped), never a raw ORA-.
            let status = finding.detail.get("status").and_then(|v| v.as_str());
            if status == Some("skipped") {
                assert_eq!(
                    finding.severity,
                    oraclemcp_db::Severity::Info,
                    "a privilege skip is informational, not an alarm"
                );
                let reason = finding
                    .detail
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                eprintln!(
                    "[live-xe] db_health subcheck {} degraded to skip ({reason})",
                    finding.subcheck.name()
                );
            } else {
                assert_eq!(status, Some("ok"), "non-skip findings carry status=ok");
            }
        }

        // Verify the DBA_*->ALL_* degradation actually exercises a live view by
        // running each builder's SQL directly through the read path; a privilege
        // error is acceptable (that is the degradation path), but a SUCCESS proves
        // the SQL is valid against the live dictionary.
        let (_, invalid_sql) = oraclemcp_db::invalid_objects_sql(oraclemcp_db::ViewTier::All);
        match conn.query_rows(&cx, &invalid_sql, &[]).await {
            Ok(_) => {}
            Err(e) => eprintln!("[live-xe] ALL_OBJECTS invalid-objects query degraded ({e})"),
        }
    });
}

// C10 consolidated live coverage (bead oraclemcp-040-epic-wp-c-17t.10): the
// full DBA suite + `oracle_top_queries` (incl. the Statspack-fallback path) +
// the C9 preflight, all run against a real 23ai. Together with the `health.rs`
// / `awr.rs` unit tests, the dispatch `db_health`/`top_queries` tests, and the
// `live_db_health_suite_runs_all_subchecks_without_hard_failure` test above,
// this is the consolidated WP-C coverage. The acceptance criterion is
// "CI-green-with-Oracle = every subcheck (C2–C7) + top_queries Statspack
// fallback (C8) + privilege-degradation (DBA_*→ALL_*) all pass against live
// 23ai". Without a reachable Oracle each test prints a SKIP banner and returns.

/// C9 live: the report-only preflight resolves a tier/feature posture for every
/// subcheck and for top_queries (default + historical) against a real DB. It
/// must report a runnable/skip/ordinary-failure resolution per subcheck;
/// the resolved tiers must be consistent with what `run_health` actually used.
#[test]
fn live_dba_suite_preflight_reports_runnable_posture() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(
            &cx,
            "live_dba_suite_preflight_reports_runnable_posture",
            test_opts(),
        )
        .await
        else {
            return;
        };
        conn.ping(&cx).await.expect("preflight ping");

        let report = oraclemcp_db::preflight(&cx, &conn)
            .await
            .expect("live preflight must not lose/cancel its Oracle session");
        assert_eq!(
            report.subchecks.len(),
            oraclemcp_db::HealthSubcheck::all().len(),
            "one preflight row per subcheck"
        );
        let (runnable, skipped, failed) = report.runnable_skipped_failed();
        assert_eq!(runnable + skipped + failed, report.subchecks.len());
        eprintln!(
            "[live-xe] preflight: {runnable} runnable, {skipped} skip, {failed} failed; default={:?} historical={:?} pack={} statspack={}",
            report.top_queries_default,
            report.top_queries_historical,
            report.diagnostics_pack_licensed,
            report.statspack_installed,
        );
        // Default top-queries is always the free live cursor (no pack required).
        assert_eq!(
            report.top_queries_default,
            oraclemcp_db::DiagnosticsSource::LiveCursor,
            "the default top-SQL source is the free live cursor cache"
        );
        // The preflight's per-subcheck tier must match what run_health would use:
        // a subcheck the preflight marks runnable must NOT degrade to a skip.
        let findings = oraclemcp_db::run_health(&cx, &conn, oraclemcp_db::HealthSubcheck::all())
            .await
            .expect("live health rerun must not lose or cancel its Oracle session");
        for row in &report.subchecks {
            let finding = findings
                .iter()
                .find(|f| f.subcheck == row.subcheck)
                .expect("a finding per subcheck");
            let actually_skipped =
                finding.detail.get("status").and_then(|v| v.as_str()) == Some("skipped");
            assert_eq!(
                row.tier.is_none(),
                actually_skipped,
                "preflight tier for {:?} must agree with run_health's skip decision",
                row.subcheck
            );
        }
    });
}

/// C8/C10 live: `oracle_top_queries` resolves to a working source and the
/// resolved source's query runs as a pure read. The default (live cursor) path
/// always works; the historical path resolves to AWR (only if the Diagnostics
/// Pack is licensed) → Statspack (the free fallback) → a structured Unavailable
/// error — never a silent empty success. Whichever source is resolved, its SQL
/// is exercised against the live dictionary (the Statspack-fallback path is
/// covered whenever PERFSTAT is installed but the pack is not licensed).
#[test]
fn live_top_queries_resolves_source_and_runs_including_statspack_fallback() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(
            &cx,
            "live_top_queries_resolves_source_and_runs_including_statspack_fallback",
            test_opts(),
        )
        .await
        else {
            return;
        };
        conn.ping(&cx).await.expect("top_queries ping");

        // Default mode: always the free live cursor cache, query must run.
        let default_source = oraclemcp_db::resolve_top_sql_source(&cx, &conn, false).await;
        assert_eq!(default_source, oraclemcp_db::DiagnosticsSource::LiveCursor);
        let live_sql = oraclemcp_db::top_sql_query(
            default_source,
            oraclemcp_db::TopSqlMetric::Elapsed,
            5,
            None,
        )
        .expect("live cursor query builds");
        conn.query_rows(&cx, &live_sql, &[])
            .await
            .expect("live top-SQL runs as a pure read");

        // Historical mode: resolve the real posture and exercise the resolved path.
        let historical = oraclemcp_db::resolve_top_sql_source(&cx, &conn, true).await;
        eprintln!("[live-xe] top_queries historical source resolved to {historical:?}");
        match oraclemcp_db::top_sql_query(historical, oraclemcp_db::TopSqlMetric::Elapsed, 5, None)
        {
            Ok(sql) => {
                // AWR or Statspack: the SQL is valid against the live dictionary.
                // (A privilege miss is acceptable; a success proves the path works.)
                match conn.query_rows(&cx, &sql, &[]).await {
                    Ok(_) => eprintln!("[live-xe] historical top-SQL ran against {historical:?}"),
                    Err(e) => eprintln!(
                        "[live-xe] historical top-SQL ({historical:?}) degraded on a privilege/feature miss ({e})"
                    ),
                }
            }
            Err(envelope) => {
                // Unavailable: a clear structured error that offers Statspack —
                // never an empty success.
                assert_eq!(historical, oraclemcp_db::DiagnosticsSource::Unavailable);
                assert!(envelope.is_error);
                assert!(
                    envelope
                        .next_steps
                        .iter()
                        .any(|s| s.to_lowercase().contains("statspack")),
                    "the unavailable error offers the free Statspack fallback"
                );
            }
        }
    });
}

/// E4 (live): the `oracle_search_objects` summary row count is the optimizer's
/// `ALL_TABLES.NUM_ROWS` ESTIMATE from gathered statistics, NOT a live
/// `COUNT(*)`. We prove it by gathering stats at one cardinality, then inserting
/// many more rows WITHOUT re-gathering: a COUNT(*) would jump, but the summary's
/// `num_rows` must stay at the stale gathered estimate (the stale-stats case).
#[test]
fn live_search_objects_summary_uses_optimizer_num_rows_not_count_star() {
    run_with_cx(|cx| async move {
        let test_name = "live_search_objects_summary_uses_optimizer_num_rows_not_count_star";
        let Some(conn) = connect_or_skip(&cx, test_name, test_opts()).await else {
            return;
        };
        // Fail fast instead of hanging: a blocked DDL/stats round trip on an
        // unprovisioned instance should surface as an error (then a SKIP),
        // never an indefinite hang.
        conn.set_call_timeout(Some(Duration::from_secs(30))).ok();

        let table = "ORACLEMCP_E4_STATS_T";
        // Best-effort clean slate.
        let _ = conn
            .execute(&cx, &format!("DROP TABLE {table} PURGE"), &[])
            .await;
        // If basic DDL is not possible on this instance (privileges / locked /
        // read-only), skip rather than fail — the offline tests cover the logic.
        if let Err(e) = conn
            .execute(
                &cx,
                &format!("CREATE TABLE {table} (id NUMBER, note VARCHAR2(40))"),
                &[],
            )
            .await
        {
            eprintln!("[live-xe] SKIP {test_name}: cannot create fixture table ({e})");
            return;
        }
        conn.execute(
            &cx,
            &format!("COMMENT ON TABLE {table} IS 'oraclemcp E4 stats fixture'"),
            &[],
        )
        .await
        .ok();

        // Seed exactly 10 rows and commit.
        for i in 1..=10 {
            conn.execute(
                &cx,
                &format!("INSERT INTO {table} VALUES ({i}, 'seed')"),
                &[],
            )
            .await
            .expect("insert seed");
        }
        conn.commit(&cx).await.expect("commit seed");

        // Resolve the current schema to scope the search.
        let owner = conn
            .describe(&cx)
            .await
            .ok()
            .and_then(|info| info.current_schema)
            .or_else(|| std::env::var("ORACLEMCP_TEST_USER").ok())
            .unwrap_or_else(|| "SYSTEM".to_owned())
            .to_ascii_uppercase();

        // Gather stats so the optimizer estimate is exactly 10. A privilege or
        // resource block here degrades to a SKIP rather than a hang/failure.
        if let Err(e) = conn
            .execute(
                &cx,
                &format!("BEGIN DBMS_STATS.GATHER_TABLE_STATS(USER, '{table}'); END;"),
                &[],
            )
            .await
        {
            eprintln!("[live-xe] SKIP {test_name}: cannot gather table stats ({e})");
            let _ = conn
                .execute(&cx, &format!("DROP TABLE {table} PURGE"), &[])
                .await;
            return;
        }

        let after_gather = search_objects(
            &cx,
            &conn,
            Some(&owner),
            Some("TABLE"),
            Some(table),
            SearchDetailLevel::Summary,
            50,
        )
        .await
        .expect("search after gather");
        let row = after_gather
            .iter()
            .find(|o| o.object_name == table)
            .expect("the fixture table is found");
        assert_eq!(
            row.num_rows,
            Some(10),
            "summary num_rows is the gathered ALL_TABLES.NUM_ROWS estimate"
        );
        assert_eq!(row.row_count_is_estimate, Some(true));
        assert!(
            row.last_analyzed.is_some(),
            "gathered stats record a last_analyzed timestamp"
        );
        assert_eq!(
            row.comment.as_deref(),
            Some("oraclemcp E4 stats fixture"),
            "ALL_TAB_COMMENTS surfaces the table comment"
        );
        assert_eq!(
            row.column_count,
            Some(2),
            "two columns via dictionary count"
        );

        // Insert 90 more rows WITHOUT re-gathering. A live COUNT(*) would now be
        // 100; the optimizer estimate must remain the stale gathered value (10).
        for i in 11..=100 {
            conn.execute(
                &cx,
                &format!("INSERT INTO {table} VALUES ({i}, 'extra')"),
                &[],
            )
            .await
            .expect("insert extra");
        }
        conn.commit(&cx).await.expect("commit extra");

        // Ground truth: a real COUNT(*) is 100 now.
        let live = conn
            .query_rows(&cx, &format!("SELECT COUNT(*) AS n FROM {table}"), &[])
            .await
            .expect("count");
        assert_eq!(live[0].parse_i64("N"), Some(100), "live data really grew");

        let after_insert = search_objects(
            &cx,
            &conn,
            Some(&owner),
            Some("TABLE"),
            Some(table),
            SearchDetailLevel::Summary,
            50,
        )
        .await
        .expect("search after insert");
        let row = after_insert
            .iter()
            .find(|o| o.object_name == table)
            .expect("the fixture table is found");
        assert_eq!(
            row.num_rows,
            Some(10),
            "the STALE optimizer estimate (10) is reported, NOT the live COUNT(*) of 100 — \
             proving summary reads ALL_TABLES.NUM_ROWS and never scans the data"
        );

        // Flush monitoring info so the optimizer can mark the stats stale, then
        // confirm the staleness signal surfaces (best-effort: STALE_STATS lags
        // behind monitoring on some configs, so we only assert it is observable).
        conn.execute(
            &cx,
            "BEGIN DBMS_STATS.FLUSH_DATABASE_MONITORING_INFO; END;",
            &[],
        )
        .await
        .ok();
        let stale_view = search_objects(
            &cx,
            &conn,
            Some(&owner),
            Some("TABLE"),
            Some(table),
            SearchDetailLevel::Summary,
            50,
        )
        .await
        .expect("search for staleness");
        let row = stale_view
            .iter()
            .find(|o| o.object_name == table)
            .expect("found");
        // num_rows is still the stale estimate; stats_stale is present (true once
        // the optimizer flags it, false until monitoring catches up).
        assert_eq!(row.num_rows, Some(10));
        assert!(
            row.stats_stale.is_some(),
            "the summary always reports whether the optimizer considers stats stale"
        );
        eprintln!(
            "[live-xe] E4 stale-stats: num_rows={:?} (estimate) vs live COUNT(*)=100, stats_stale={:?}",
            row.num_rows, row.stats_stale
        );

        conn.execute(&cx, &format!("DROP TABLE {table} PURGE"), &[])
            .await
            .ok();
        conn.commit(&cx).await.ok();
    });
}

/// K3: `explain_plan` + `plan_cost_estimate` surface the optimizer's relative
/// cost/cardinality. DoD: an expensive full-table scan reports a HIGH estimate
/// and a primary-key unique lookup a LOW one. Creates a throwaway table with a
/// PK index, EXPLAINs both a full scan and a PK lookup, and asserts the cost
/// estimate summary orders as expected. Cleans up the table.
#[test]
fn live_explain_plan_cost_estimate_orders_full_scan_above_pk_lookup() {
    let name = "live_explain_plan_cost_estimate_orders_full_scan_above_pk_lookup";
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(&cx, name, test_opts()).await else {
            return;
        };
        let table = "ORACLEMCP_COST_EST_T";

        // Fresh throwaway table with a PRIMARY KEY (→ a unique index).
        let _ = conn
            .execute(&cx, &format!("DROP TABLE {table} PURGE"), &[])
            .await;
        conn.execute(
            &cx,
            &format!("CREATE TABLE {table} (id NUMBER PRIMARY KEY, filler VARCHAR2(80))"),
            &[],
        )
        .await
        .expect("create cost-estimate table");
        conn.execute(
            &cx,
            &format!(
                "INSERT INTO {table} SELECT LEVEL, RPAD('x', 80, 'x') \
                 FROM dual CONNECT BY LEVEL <= 5000"
            ),
            &[],
        )
        .await
        .expect("seed rows");
        conn.commit(&cx).await.expect("commit seed rows");
        // Give the optimizer real statistics so the estimates are non-null and
        // reflect the 5000-row full scan vs the unique-index lookup.
        conn.execute(
            &cx,
            &format!(
                "BEGIN DBMS_STATS.GATHER_TABLE_STATS(USER, '{table}', \
                 cascade => TRUE); END;"
            ),
            &[],
        )
        .await
        .expect("gather stats");

        // Expensive: a full-table scan returning every row (high cost + card).
        explain_plan(&cx, &conn, &format!("SELECT * FROM {table}"), false)
            .await
            .expect("explain full scan");
        let full = plan_cost_estimate(&cx, &conn)
            .await
            .expect("full-scan cost query")
            .expect("full-scan cost estimate present");

        // Cheap: a primary-key unique lookup (low cost + cardinality of 1).
        explain_plan(
            &cx,
            &conn,
            &format!("SELECT * FROM {table} WHERE id = 42"),
            false,
        )
        .await
        .expect("explain PK lookup");
        let pk = plan_cost_estimate(&cx, &conn)
            .await
            .expect("pk-lookup cost query")
            .expect("pk-lookup cost estimate present");

        eprintln!(
            "[live-xe] K3 cost estimate: full_scan(cost={:?}, card={:?}) vs \
             pk_lookup(cost={:?}, card={:?})",
            full.summary.total_cost,
            full.summary.total_cardinality,
            pk.summary.total_cost,
            pk.summary.total_cardinality,
        );

        // Both summaries are grounded on the plan root (id = 0).
        assert_eq!(full.rows.first().map(|row| row.id), Some(0));
        assert_eq!(pk.rows.first().map(|row| row.id), Some(0));

        // Cardinality ordering is unambiguous: a full scan returns the whole
        // table (~5000 rows), a unique PK lookup returns exactly one.
        let full_card = full
            .summary
            .total_cardinality
            .expect("full-scan cardinality is estimated after gather_stats");
        let pk_card = pk
            .summary
            .total_cardinality
            .expect("pk-lookup cardinality is estimated after gather_stats");
        assert!(
            full_card > pk_card,
            "full-scan cardinality ({full_card}) must exceed PK-lookup cardinality ({pk_card})"
        );
        assert_eq!(pk_card, 1, "a unique PK lookup estimates exactly one row");

        // When the optimizer reports cost (it does under CBO with stats), the
        // full scan must cost more than the single-block unique index lookup.
        if let (Some(full_cost), Some(pk_cost)) = (full.summary.total_cost, pk.summary.total_cost) {
            assert!(
                full_cost > pk_cost,
                "full-scan cost ({full_cost}) must exceed PK-lookup cost ({pk_cost})"
            );
        }

        conn.execute(&cx, &format!("DROP TABLE {table} PURGE"), &[])
            .await
            .ok();
        conn.commit(&cx).await.ok();
    });
}

/// K11 blast-radius probe: a package with a dependent view + procedure. The
/// direct-dependents probe (which backs the DDL preview `dependents` block)
/// must surface both dependents and flag them invalidatable. Self-skips without
/// a reachable Oracle; cleans up its throwaway objects on every path.
#[test]
fn live_probe_dependents_flags_dependent_view_and_proc_at_risk() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(
            &cx,
            "live_probe_dependents_flags_dependent_view_and_proc_at_risk",
            test_opts(),
        )
        .await
        else {
            return;
        };

        // Resolve the owner from the live session (current schema / session user).
        let info = conn.describe(&cx).await.expect("describe");
        let Some(owner) = info.current_schema.or(info.session_user) else {
            eprintln!("[live-xe] SKIP live_probe_dependents: session has no current schema / user");
            return;
        };

        let pkg = "K11_DEP_PKG";
        let view = "K11_DEP_VIEW";
        let proc = "K11_DEP_PROC";

        // Best-effort pre-clean of any leftovers, then build the fixture.
        for stmt in [
            format!("DROP VIEW {view}"),
            format!("DROP PROCEDURE {proc}"),
            format!("DROP PACKAGE {pkg}"),
        ] {
            conn.execute(&cx, &stmt, &[]).await.ok();
        }

        let build = [
            format!("CREATE OR REPLACE PACKAGE {pkg} AS FUNCTION f RETURN NUMBER; END;"),
            format!(
                "CREATE OR REPLACE PACKAGE BODY {pkg} AS \
                 FUNCTION f RETURN NUMBER IS BEGIN RETURN 1; END; END;"
            ),
            format!("CREATE OR REPLACE VIEW {view} AS SELECT {pkg}.f AS n FROM dual"),
            format!(
                "CREATE OR REPLACE PROCEDURE {proc} AS x NUMBER; \
                 BEGIN x := {pkg}.f; END;"
            ),
        ];
        let mut build_ok = true;
        for stmt in &build {
            if let Err(e) = conn.execute(&cx, stmt, &[]).await {
                eprintln!("[live-xe] SKIP live_probe_dependents: fixture build failed: {e}");
                build_ok = false;
                break;
            }
        }
        conn.commit(&cx).await.ok();

        // Probe the package's direct dependents (this is what the DDL preview's
        // `dependents` block runs when previewing a create_or_replace / patch of
        // the package body).
        let probe = if build_ok {
            Some(probe_dependents(&cx, &conn, &owner, pkg, 200).await)
        } else {
            None
        };

        // Always tear down the throwaway objects before asserting.
        for stmt in [
            format!("DROP VIEW {view}"),
            format!("DROP PROCEDURE {proc}"),
            format!("DROP PACKAGE {pkg}"),
        ] {
            conn.execute(&cx, &stmt, &[]).await.ok();
        }
        conn.commit(&cx).await.ok();

        if !build_ok {
            return;
        }

        match probe.expect("probe ran") {
            DependentsProbe::Available { direct } => {
                let view_dep = direct
                    .iter()
                    .find(|d| d.name.eq_ignore_ascii_case(view))
                    .unwrap_or_else(|| panic!("dependent view {view} not surfaced: {direct:?}"));
                assert_eq!(view_dep.object_type.to_ascii_uppercase(), "VIEW");
                assert!(
                    view_dep.is_invalidatable(),
                    "dependent view must be flagged at_risk_of_invalid"
                );

                let proc_dep = direct
                    .iter()
                    .find(|d| d.name.eq_ignore_ascii_case(proc))
                    .unwrap_or_else(|| panic!("dependent proc {proc} not surfaced: {direct:?}"));
                assert_eq!(proc_dep.object_type.to_ascii_uppercase(), "PROCEDURE");
                assert!(
                    proc_dep.is_invalidatable(),
                    "dependent procedure must be flagged at_risk_of_invalid"
                );
            }
            DependentsProbe::Unavailable { reason } => {
                panic!("ALL_DEPENDENCIES probe should be available for the test user: {reason}");
            }
        }
    });
}
