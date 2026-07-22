//! D4 live privilege-matrix assertions.
//!
//! The Rig L1 `privilege-matrix` command provisions these deliberately
//! restricted principals.  This test intentionally has no fallback to the
//! normal `ORACLEMCP_TEST_*` account: running it against an accidentally
//! privileged account would turn the negative fixture into a false green.
#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use asupersync::{Cx, runtime::RuntimeBuilder};
use oraclemcp_db::{
    AsOf, AuthAdapter, DbError, FlashbackRefusalKind, OracleConnectOptions, OracleConnection,
    QueryCaps, RustOracleConnection, SerializeOptions, read_query_as_of,
    resolved_relations_read_purity,
};
use oraclemcp_error::ErrorClass;
use oraclemcp_guard::{CatalogObjectKind, Purity, ResolvedIdentity, ResolvedObject};

const CATALOG_BLIND_OWNER: &str = "ORACLEMCP_D4_OWNER";
const CATALOG_BLIND_TABLE: &str = "ORACLEMCP_D4_GUARDED";

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

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "D4 privilege-matrix fixture is not provisioned: set {name} via \
             `bash scripts/rig/oracle_l1.sh privilege-matrix --log`"
        )
    })
}

fn no_flashback_options() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: required_env("ORACLEMCP_D4_DSN"),
        username: Some(required_env("ORACLEMCP_D4_NO_FLASHBACK_USER")),
        password: Some(required_env("ORACLEMCP_D4_NO_FLASHBACK_PASSWORD")),
        auth_adapter: AuthAdapter::Password,
        ..Default::default()
    }
}

fn catalog_blind_options() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: required_env("ORACLEMCP_D4_DSN"),
        username: Some(required_env("ORACLEMCP_D4_CATALOG_BLIND_USER")),
        password: Some(required_env("ORACLEMCP_D4_CATALOG_BLIND_PASSWORD")),
        auth_adapter: AuthAdapter::Password,
        ..Default::default()
    }
}

fn catalog_blind_object_id() -> u64 {
    required_env("ORACLEMCP_D4_CATALOG_OBJECT_ID")
        .parse()
        .expect("Rig L1 must pass the numeric object id it verified as SYSDBA")
}

fn guarded_fixture_table() -> ResolvedObject {
    // The rig verifies this object's policy and virtual column from SYS before
    // it exposes the blind principal.  `resolved_relations_read_purity` needs
    // carries forward the exact numeric identity verified by the rig, so this
    // test cannot get an `Unknown` result merely from the unrelated stale- or
    // zero-identity guard before its two visibility probes run.
    ResolvedObject {
        owner: CATALOG_BLIND_OWNER.to_owned(),
        name: CATALOG_BLIND_TABLE.to_owned(),
        kind: CatalogObjectKind::Table,
        container: None,
        member: None,
        overloads: Vec::new(),
        quote_exact: false,
        synonym_chain: Vec::new(),
        db_link: None,
        identity: ResolvedIdentity {
            object_id: catalog_blind_object_id(),
            edition: None,
        },
    }
}

/// This is deliberately an expected failure until A3a performs its capability
/// check before `DBMS_FLASHBACK.DISABLE`.  The fixture executes the exact
/// state-changing path, rather than a synthetic error mapper, and then proves
/// whether the same physical connection remains usable.
#[test]
#[ignore = "expected failure until A3a preflights missing DBMS_FLASHBACK EXECUTE before session-state cleanup"]
fn d4_no_flashback_principal_gets_typed_refusal_and_connection_stays_usable() {
    run_with_cx(|cx| async move {
        let conn = RustOracleConnection::connect(&cx, no_flashback_options())
            .await
            .expect("D4 no-flashback principal must connect with CREATE SESSION only");

        // Repeat the request to catch the pool/session degradation that a
        // one-shot assertion would miss.  SCN 1 is intentionally just a
        // deterministic input: the pre-A3 defect occurs in the initial
        // DBMS_FLASHBACK cleanup call, before Oracle evaluates the target SCN.
        for attempt in 1..=2 {
            let error = read_query_as_of(
                &cx,
                &conn,
                "SELECT 1 AS N FROM DUAL",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(1),
            )
            .await
            .expect_err("a principal without DBMS_FLASHBACK EXECUTE must never receive rows");

            assert!(
                matches!(
                    &error,
                    DbError::FlashbackRefusal {
                        kind: FlashbackRefusalKind::CapabilityUnavailable,
                        ..
                    }
                ),
                "attempt {attempt}: missing DBMS_FLASHBACK EXECUTE must be a typed capability \
                 refusal, not an Oracle driver error or a partial success: {error:?}"
            );
            assert_eq!(
                error.into_envelope().error_class,
                ErrorClass::FlashbackCapabilityUnavailable,
                "attempt {attempt}: the client-visible envelope must name the missing capability"
            );

            let rows = conn
                .query_rows(&cx, "SELECT 42 AS N FROM DUAL", &[])
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "attempt {attempt}: a clean flashback capability refusal must not \
                         quarantine the session: {error}"
                    )
                });
            assert_eq!(
                rows.len(),
                1,
                "attempt {attempt}: post-refusal probe row count"
            );
            assert_eq!(
                rows[0].text("N"),
                Some("42"),
                "attempt {attempt}: post-refusal probe must return the normal result"
            );
        }
    });
}

/// Live twin of C8's blind-dictionary half.  The rig creates a table that has
/// both a SELECT VPD policy and a virtual column, but grants this principal
/// only `CREATE SESSION`; therefore both `ALL_POLICIES` and `ALL_TAB_COLS`
/// probes successfully return an empty result.  The product must regard that
/// as missing proof, not as evidence that the known guarded table is clean.
#[test]
fn d4_catalog_blind_principal_cannot_prove_the_known_guarded_table_read_only() {
    run_with_cx(|cx| async move {
        let conn = RustOracleConnection::connect(&cx, catalog_blind_options())
            .await
            .expect("D4 catalog-blind principal must connect with CREATE SESSION only");
        let table = guarded_fixture_table();
        let purity = resolved_relations_read_purity(&cx, &conn, &[table])
            .await
            .expect(
                "D4's restricted dictionary probes must be successful empty results; \
                 an Oracle privilege error is not this fixture",
            );
        assert_eq!(
            purity,
            Purity::Unknown,
            "a principal blind to the known VPD policy and virtual column has no read-only proof; \
             returning ProvenReadOnly would permit a policy-filtered partial result as success"
        );
    });
}
