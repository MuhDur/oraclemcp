//! Unit tests for the `oraclemcp` binary, relocated verbatim from the former
//! inline `#[cfg(test)] mod tests` block in `main.rs`, so the CLI flow there
//! stays readable. Reached via `#[cfg(test)] #[path = "main_tests.rs"] mod tests;`
//! at the crate root, so `super::*` still resolves to `main.rs`. Top-level items
//! are de-indented one level by rustfmt; every raw-string fixture stays
//! byte-identical (rustfmt never rewrites inside raw string literals).

use super::*;
use oraclemcp_audit::{AuditRecord, DbEvidence};
use oraclemcp_config::HttpOAuthConfig;
use std::sync::atomic::AtomicUsize;

#[test]
fn self_update_uses_only_authenticated_embedded_installer_bytes() {
    assert_eq!(embedded_installer_sha256(EMBEDDED_INSTALLER_SH).len(), 64);
    assert_eq!(embedded_installer_sha256(EMBEDDED_INSTALLER_PS1).len(), 64);
    assert!(self_update_installer_source().starts_with("embedded:install."));
    assert!(!self_update_installer_source().contains("/main/"));

    let expected = embedded_installer_sha256(EMBEDDED_SELF_UPDATE_INSTALLER);
    let verified = materialize_verified_installer(EMBEDDED_SELF_UPDATE_INSTALLER, &expected)
        .expect("exact embedded installer authenticates");
    assert_eq!(
        fs::read(verified.path()).expect("read verified installer"),
        EMBEDDED_SELF_UPDATE_INSTALLER
    );

    let mut tampered = EMBEDDED_SELF_UPDATE_INSTALLER.to_vec();
    tampered[0] ^= 1;
    let error = materialize_verified_installer(&tampered, &expected)
        .expect_err("tampered installer is rejected before a command is built");
    assert!(error.contains("authentication failed"), "{error}");
}

#[test]
fn self_update_resolves_and_validates_one_immutable_release_tag() {
    assert_eq!(
        parse_latest_release_version(br#"{"tag_name":"v0.8.0"}"#).expect("release tag"),
        "0.8.0"
    );
    assert_eq!(
        normalize_self_update_version("v1.2.3-rc.1").expect("prerelease"),
        "1.2.3-rc.1"
    );
    for invalid in [
        "latest",
        "1.2",
        "01.2.3",
        "1.2.3-01",
        "1.2.3;touch-pwned",
        "v1.2.3-",
    ] {
        assert!(
            normalize_self_update_version(invalid).is_err(),
            "invalid version accepted: {invalid}"
        );
    }
    assert!(parse_latest_release_version(br#"{"tag_name":"main"}"#).is_err());
    assert!(parse_latest_release_version(&vec![b'x'; LATEST_RELEASE_MAX_BYTES + 1]).is_err());
}

#[test]
fn self_update_plan_never_references_a_mutable_installer_url() {
    let args = SelfUpdateCliArgs {
        version: "0.8.0".to_owned(),
        verify: Some("require".to_owned()),
        yes: true,
        no_service: true,
        dry_run: true,
    };
    let argv = self_update_argv(&args, "0.8.0", "<verified-embedded-installer>");
    let rendered = argv.join(" ");
    assert!(
        !rendered.contains("raw.githubusercontent.com"),
        "{rendered}"
    );
    assert!(!rendered.contains("/main/"), "{rendered}");
    assert!(rendered.contains("0.8.0"), "{rendered}");
    assert!(rendered.contains("require"), "{rendered}");
    assert!(rendered.contains("<verified-embedded-installer>"));
}

fn self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    (
        cert.cert.pem().into_bytes(),
        cert.key_pair.serialize_pem().into_bytes(),
    )
}

fn target_tmp_file(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../target/tmp/oraclemcp-main-tests");
    fs::create_dir_all(&path).expect("test temp dir exists");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    path.push(format!("{}-{}-{name}", std::process::id(), nanos));
    path
}

#[test]
fn runtime_profile_selection_does_not_resolve_secret_refs() {
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            schema_version = 1
            default_profile = "prod"

            [[profiles]]
            name = "prod"
            connect_string = "prod.example:1521/service"
            username = "APP_USER"
            credential_ref = "env:ORACLEMCP_TEST_UNSET_DB_PASSWORD"

            [profiles.oci]
            wallet_password_ref = "env:ORACLEMCP_TEST_UNSET_WALLET_PASSWORD"
            "#,
    )
    .expect("valid config");

    let selected = select_runtime_profile_from_config(&cfg, None)
        .expect("metadata selection does not touch secret backends")
        .expect("default profile selected");
    assert_eq!(selected.name, "prod");
    assert_eq!(selected.level.max_level(), OperatingLevel::ReadOnly);
    assert_eq!(
        selected.request_timeout,
        Some(std::time::Duration::from_secs(30))
    );
}

#[test]
fn runtime_connection_bundle_uses_one_resolved_secret_epoch() {
    use std::sync::atomic::AtomicUsize;

    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "prod"
            connect_string = "tcps://prod.example:1522/service"
            username = "APP_USER"
            credential_ref = "env:DB_PASSWORD"

            [profiles.oci]
            wallet_location = "/wallet"
            wallet_password_ref = "env:WALLET_PASSWORD"

            [profiles.pool]
            max_size = 2
            min_idle = 0
        "#,
    )
    .expect("valid profile");
    let calls = AtomicUsize::new(0);
    let resolver = oraclemcp_auth::EnvLookupSecretResolver::new(|locator: &str| {
        let epoch = calls.fetch_add(1, Ordering::SeqCst);
        Some(format!("{locator}-epoch-{epoch}"))
    });

    let resolved = resolve_profile_options_from_config_with(&cfg, Some("prod"), &resolver)
        .expect("profile resolves")
        .expect("profile exists");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "each configured reference is resolved once for the bundle"
    );

    let (session, stateless, pool) = runtime_connection_options(resolved);
    assert!(pool.is_some(), "the stateless pool connection is planned");
    assert_eq!(session, stateless, "both connections use one secret epoch");
    assert_eq!(session.password.as_deref(), Some("DB_PASSWORD-epoch-0"));
    assert_eq!(
        session.wallet_password.as_deref(),
        Some("WALLET_PASSWORD-epoch-1")
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "splitting the connection plan must never re-resolve secrets"
    );
}

#[test]
fn optional_pool_failure_retains_the_authoritative_primary_session() {
    let session_calls = AtomicUsize::new(0);
    let pool_calls = AtomicUsize::new(0);
    let connections = block_on_connect(|_cx| async {
        try_open_runtime_connections_with(
            || async {
                session_calls.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(stub::StubConnection::new(DbError::Query(
                    "primary-session-marker".to_owned(),
                ))) as Box<dyn OracleConnection>)
            },
            || async {
                pool_calls.fetch_add(1, Ordering::SeqCst);
                Err(DbError::Pool(
                    "secret-bearing pool detail must never be logged".to_owned(),
                ))
            },
        )
        .await
        .expect("a pool-only failure must preserve the primary")
    });

    assert_eq!(session_calls.load(Ordering::SeqCst), 1);
    assert_eq!(pool_calls.load(Ordering::SeqCst), 1);
    assert!(connections.stateless.is_none());
    assert_eq!(
        runtime_connection_strategy(true, &connections),
        "hybrid_pool_degraded"
    );
    let error = block_on_connect(|cx| async move {
        connections
            .session
            .ping(&cx)
            .await
            .expect_err("marker connection intentionally returns its identity")
    });
    assert!(error.to_string().contains("primary-session-marker"));
}

#[test]
fn healthy_optional_pool_is_installed_and_reported() {
    let connections = block_on_connect(|_cx| async {
        try_open_runtime_connections_with(
            || async {
                Ok(Box::new(stub::StubConnection::new(DbError::Query(
                    "primary".to_owned(),
                ))) as Box<dyn OracleConnection>)
            },
            || async {
                Ok(Some(
                    Box::new(stub::StubConnection::new(DbError::Query("pool".to_owned())))
                        as Box<dyn OracleConnection>,
                ))
            },
        )
        .await
        .expect("primary and pool bootstrap succeed")
    });

    assert!(connections.stateless.is_some());
    assert_eq!(
        runtime_connection_strategy(true, &connections),
        "hybrid_pool"
    );
}

#[test]
fn primary_failure_remains_fatal_and_skips_optional_pool_bootstrap() {
    let pool_calls = AtomicUsize::new(0);
    let error = block_on_connect(|_cx| async {
        try_open_runtime_connections_with(
            || async { Err(DbError::Connect("primary failed".to_owned())) },
            || async {
                pool_calls.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            },
        )
        .await
        .expect_err("the authoritative primary must still gate runtime startup")
    });

    assert!(error.to_string().contains("primary failed"));
    assert_eq!(
        pool_calls.load(Ordering::SeqCst),
        0,
        "pool bootstrap must not run after primary failure"
    );
}

#[test]
fn a_later_bootstrap_can_install_a_pool_without_reusing_the_failed_attempt() {
    let attempts = AtomicUsize::new(0);
    let first = block_on_connect(|_cx| async {
        try_open_runtime_connections_with(
            || async {
                Ok(Box::new(stub::StubConnection::new(DbError::Query(
                    "generation-one-primary".to_owned(),
                ))) as Box<dyn OracleConnection>)
            },
            || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err(DbError::Pool("first generation unavailable".to_owned()))
            },
        )
        .await
        .expect("first generation degrades")
    });
    assert!(first.stateless.is_none());

    let second = block_on_connect(|_cx| async {
        try_open_runtime_connections_with(
            || async {
                Ok(Box::new(stub::StubConnection::new(DbError::Query(
                    "generation-two-primary".to_owned(),
                ))) as Box<dyn OracleConnection>)
            },
            || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                Ok(Some(Box::new(stub::StubConnection::new(DbError::Query(
                    "generation-two-pool".to_owned(),
                ))) as Box<dyn OracleConnection>))
            },
        )
        .await
        .expect("later generation installs its own healthy pool")
    });

    assert!(second.stateless.is_some());
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[test]
fn fresh_stateful_lane_uses_reloaded_profile_ceiling_and_timeout() {
    let lowered = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod.example:1521/service"
            max_level = "READ_ONLY"
            call_timeout_seconds = 7
            max_query_cost = 11
            "#,
    )
    .expect("lowered config");
    let selected = select_runtime_profile_from_config(&lowered, Some("prod"))
        .expect("profile selection")
        .expect("profile exists");
    let mut wiring = DispatcherWiring {
        active_profile: Some("prod".to_owned()),
        level: SessionLevelState::new(OperatingLevel::Admin, false),
        request_timeout: Some(std::time::Duration::from_secs(30)),
        max_query_cost: None,
        secret_resolver: Arc::new(SystemSecretResolver),
        custom_catalog: CustomToolCatalog::default(),
        exposure: McpExposurePolicy::AllowAll,
        profile_drain: ProfileDrainState::new(),
        auditor: None,
        write_intents: None,
        exports: Arc::new(ExportRegistry::new()),
    };

    apply_selected_profile_to_wiring(&mut wiring, selected);

    assert_eq!(wiring.active_profile.as_deref(), Some("prod"));
    assert_eq!(wiring.level.max_level(), OperatingLevel::ReadOnly);
    assert_eq!(
        wiring.request_timeout,
        Some(std::time::Duration::from_secs(7))
    );
    assert_eq!(wiring.max_query_cost, Some(11));
}

#[test]
fn failed_live_snapshot_compare_never_reports_reload_applied() {
    let config = |connect_string: &str| {
        OracleMcpConfig::from_toml_str(&format!(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "{connect_string}"
            "#
        ))
        .expect("config")
    };
    let a = config("a:1521/svc");
    let b = config("b:1521/svc");
    let c = config("c:1521/svc");
    let state = ProfileDrainState::from_config(a.clone());
    let applier = HttpConfigReloadApplier {
        profile_drain: state.clone(),
    };

    let report = applier.apply_config_reload_plan(
        &oraclemcp_config::ConfigReloadPlan::between(&b, &c),
        &b,
        &c,
    );
    assert_eq!(report.status, "restart_required");
    assert!(!report.hot_reloadable);
    assert!(report.message.contains("accepted snapshot was not changed"));
    assert_eq!(
        state
            .accepted_config()
            .expect("A remains accepted")
            .profile("prod")
            .and_then(|profile| profile.connect_string.as_deref()),
        Some("a:1521/svc")
    );
}

#[test]
fn http_listen_refused_without_allow_no_auth() {
    let err = http_listen_guard(false, false, false, "127.0.0.1:7070", false).unwrap_err();
    assert_eq!(err.0, "ORACLEMCP_AUTH_REQUIRED");
}

// ── A8 multi-profile audit reachability (the keystone) ──────────────────

#[test]
fn reachable_ceiling_spans_writable_exposed_profile_with_readonly_startup() {
    // Per-profile opt-out: both profiles are exposed (neither sets
    // mcp_exposed=false). The startup profile is read-only, but a writable
    // profile is reachable — so a switch to it can run writes, and the
    // reachable ceiling must reflect that.
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "ro_start"
            connect_string = "localhost:1521/FREEPDB1"
            mcp_exposed = true

            [[profiles]]
            name = "writable"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "DDL"
            mcp_exposed = true
            "#,
    )
    .expect("config parses");
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    assert_eq!(
        max_reachable_write_ceiling(&cfg, &active),
        OperatingLevel::Ddl
    );
}

#[test]
fn reachable_ceiling_ignores_explicitly_hidden_writable_profile() {
    // Per-profile opt-out: a writable profile explicitly hidden with
    // `mcp_exposed = false` is not servable (the agent can never switch to
    // it), so it does not raise the reachable ceiling.
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "ro_exposed"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles]]
            name = "hidden_writable"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "READ_WRITE"
            mcp_exposed = false
            "#,
    )
    .expect("config parses");
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    assert_eq!(
        max_reachable_write_ceiling(&cfg, &active),
        OperatingLevel::ReadOnly
    );
}

#[test]
fn reachable_ceiling_spans_all_profiles_by_default() {
    // Per-profile opt-out default: with no profile hidden, all profiles are
    // servable, so a writable one raises the reachable ceiling even though
    // the server started on a read-only profile.
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "ro_start"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles]]
            name = "writable"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "READ_WRITE"
            "#,
    )
    .expect("config parses");
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    assert_eq!(
        max_reachable_write_ceiling(&cfg, &active),
        OperatingLevel::ReadWrite
    );
}

#[test]
fn exposed_profiles_summary_lists_exposed_and_counts_hidden() {
    // E5 boot notice (visibility only): exposed profiles are listed with
    // their ceiling; an explicitly hidden one is counted, not named.
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles]]
            name = "prod_admin"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "DDL"
            mcp_exposed = false
            "#,
    )
    .expect("config parses");
    let summary = exposed_profiles_summary(&cfg);
    assert!(summary.contains("dev [ReadOnly]"), "{summary}");
    assert!(summary.contains("1 hidden"), "{summary}");
    assert!(
        !summary.contains("prod_admin"),
        "a hidden profile must not be named: {summary}"
    );
}

#[test]
fn build_auditor_fails_closed_when_a_switchable_profile_can_write() {
    // The A8 keystone: a read-only startup profile + a writable exposed
    // profile + NO audit key must fail closed at startup (so the writable
    // profile can never be switched into and run writes UNAUDITED). This is
    // the case the old single-profile check missed. Assumes a clean env
    // (no ORACLEMCP_AUDIT_KEY), as the rest of the suite does.
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    let audit = AuditConfig::default(); // no key_ref
    match build_auditor(&audit, &active, OperatingLevel::Ddl, &SystemSecretResolver) {
        Err((code, _)) => assert_eq!(code, "ORACLEMCP_AUDIT_KEY_REQUIRED"),
        Ok(_) => panic!("must fail closed: write reachable, no key"),
    }
}

#[test]
fn build_auditor_installs_when_writable_profile_has_a_key() {
    // With a signing key configured, a writable reachable profile installs
    // an auditor (so the writable profile, after a switch, is audited).
    let dir = target_tmp_file("a8-audit");
    fs::create_dir_all(&dir).expect("tmp dir");
    let audit = AuditConfig {
        path: Some(dir.join("audit.jsonl")),
        key_ref: Some("literal:0123456789abcdef0123456789abcdef".to_owned()),
        ..AuditConfig::default()
    };
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    match build_auditor(&audit, &active, OperatingLevel::Ddl, &SystemSecretResolver) {
        Ok(auditor) => assert!(
            auditor.is_some(),
            "an auditor must be installed when a write level is reachable"
        ),
        Err((code, msg)) => panic!("auditor should build with a key: {code}: {msg}"),
    }
}

#[test]
fn audit_startup_rejects_lexical_worm_alias_before_creating_files() {
    let root = target_tmp_file("qa32-lexical-worm-alias");
    let primary = root.join("audit.jsonl");
    let audit = AuditConfig {
        path: Some(primary.clone()),
        key_ref: Some("literal:0123456789abcdef0123456789abcdef".to_owned()),
        shipping: Some(oraclemcp_config::AuditShippingConfig {
            worm_path: Some(root.join("nested/../audit.jsonl")),
            ..oraclemcp_config::AuditShippingConfig::default()
        }),
        ..AuditConfig::default()
    };
    let level = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    let error = match build_auditor(&audit, &level, OperatingLevel::Ddl, &SystemSecretResolver) {
        Err(error) => error,
        Ok(_) => panic!("same WORM destination must fail closed"),
    };
    assert_eq!(error.0, "ORACLEMCP_AUDIT_SHIPPING_INVALID");
    assert!(error.1.contains("distinct"), "{}", error.1);
    assert!(
        !error.1.contains(&root.display().to_string()),
        "{}",
        error.1
    );
    assert!(
        !root.exists(),
        "obvious aliases must fail before creating a primary log or lock"
    );
}

#[test]
fn audit_startup_rejects_short_resolved_keys_before_opening_the_log() {
    let locator = "QA2_AUDIT_KEY_LOCATOR_MUST_NOT_RENDER";
    for len in [0, 1, 31] {
        let secret = "S".repeat(len);
        let resolver = oraclemcp_auth::EnvLookupSecretResolver::new({
            let secret = secret.clone();
            move |_: &str| Some(secret.clone())
        });
        let root = target_tmp_file(&format!("qa2-short-audit-{len}"));
        let audit = AuditConfig {
            path: Some(root.join("audit.jsonl")),
            key_ref: Some(format!("env:{locator}")),
            ..AuditConfig::default()
        };
        let level = SessionLevelState::new(OperatingLevel::ReadOnly, false);
        let error = match build_auditor(&audit, &level, OperatingLevel::Ddl, &resolver) {
            Err(error) => error,
            Ok(_) => panic!("undersized resolved audit key must fail closed"),
        };
        assert_eq!(error.0, "ORACLEMCP_AUDIT_KEY_INVALID");
        assert!(error.1.contains(&format!("{len} bytes")), "{}", error.1);
        assert!(!error.1.contains(locator), "{}", error.1);
        if len == 31 {
            assert!(!error.1.contains(&secret), "{}", error.1);
        }
        assert!(
            !root.exists(),
            "key validation must precede audit directory/file creation"
        );
    }
}

#[test]
fn audit_startup_accepts_32_byte_and_longer_resolved_keys() {
    for len in [32, 33] {
        let secret = "K".repeat(len);
        let resolver =
            oraclemcp_auth::EnvLookupSecretResolver::new(move |_: &str| Some(secret.clone()));
        let audit = AuditConfig {
            key_ref: Some("env:QA2_AUDIT_KEY".to_owned()),
            ..AuditConfig::default()
        };
        let key = resolve_audit_keyring(&audit, false, &resolver)
            .expect("minimum-size resolved audit key is valid");
        assert!(key.is_some());
    }
}

#[test]
fn audit_startup_rejects_newline_only_key_file_without_leaking_its_path() {
    let key_path = target_tmp_file("qa2-newline-audit-key");
    fs::write(&key_path, "\n").expect("write newline-only key fixture");
    let audit = AuditConfig {
        key_ref: Some(format!("file:{}", key_path.display())),
        ..AuditConfig::default()
    };
    let error = resolve_audit_keyring(&audit, false, &SystemSecretResolver)
        .expect_err("newline-only audit key resolves empty and must be rejected");
    assert_eq!(error.0, "ORACLEMCP_AUDIT_KEY_INVALID");
    assert!(error.1.contains("0 bytes"), "{}", error.1);
    assert!(
        !error.1.contains(&key_path.display().to_string()),
        "{}",
        error.1
    );
}

#[test]
fn audit_verify_enforces_key_size_for_config_and_legacy_env_sources() {
    let locator = "QA2_VERIFY_KEY_LOCATOR_MUST_NOT_RENDER";
    let audit = AuditConfig {
        key_ref: Some(format!("env:{locator}")),
        ..AuditConfig::default()
    };
    for len in [0, 1, 31] {
        let secret = "V".repeat(len);
        let resolver = oraclemcp_auth::EnvLookupSecretResolver::new({
            let secret = secret.clone();
            move |_: &str| Some(secret.clone())
        });
        let error = audit_verification_keyring_from_sources(&audit, None, &resolver, None)
            .expect_err("undersized resolved verification key must fail closed");
        assert!(error.contains(&format!("{len} bytes")), "{error}");
        assert!(!error.contains(locator), "{error}");
        if len == 31 {
            assert!(!error.contains(&secret), "{error}");
        }
    }
    for len in [32, 33] {
        let secret = "V".repeat(len);
        let resolver =
            oraclemcp_auth::EnvLookupSecretResolver::new(move |_: &str| Some(secret.clone()));
        assert_eq!(
            audit_verification_keyring_from_sources(&audit, None, &resolver, None)
                .expect("minimum-size resolved verification key is valid")
                .verification_keys()
                .len(),
            1
        );
    }

    let no_config = AuditConfig::default();
    for len in [0, 1, 31] {
        let secret = "E".repeat(len);
        let error = audit_verification_keyring_from_sources(
            &no_config,
            None,
            &SystemSecretResolver,
            Some(&secret),
        )
        .expect_err("undersized legacy environment verification key must fail closed");
        assert!(error.contains(&format!("{len} bytes")), "{error}");
        if len == 31 {
            assert!(!error.contains(&secret), "{error}");
        }
    }
    for len in [32, 33] {
        let secret = "E".repeat(len);
        assert_eq!(
            audit_verification_keyring_from_sources(
                &no_config,
                None,
                &SystemSecretResolver,
                Some(&secret),
            )
            .expect("minimum-size legacy environment verification key is valid")
            .verification_keys()
            .len(),
            1
        );
    }
}

#[test]
fn audit_keyring_resolves_active_and_historical_keys_without_leaking_locators() {
    let active_locator = "QA37_ACTIVE_LOCATOR_MUST_NOT_RENDER";
    let old_locator = "QA37_OLD_LOCATOR_MUST_NOT_RENDER";
    let audit = AuditConfig {
        key_ref: Some(format!("env:{active_locator}")),
        key_id: Some("new".to_owned()),
        verification_keys: vec![oraclemcp_config::AuditVerificationKeyConfig {
            key_id: "old".to_owned(),
            key_ref: format!("env:{old_locator}"),
        }],
        ..AuditConfig::default()
    };
    let resolver = oraclemcp_auth::EnvLookupSecretResolver::new(move |name: &str| match name {
        "QA37_ACTIVE_LOCATOR_MUST_NOT_RENDER" => Some("A".repeat(32)),
        "QA37_OLD_LOCATOR_MUST_NOT_RENDER" => Some("B".repeat(32)),
        _ => None,
    });
    let keyring = audit_verification_keyring_from_sources(&audit, None, &resolver, None)
        .expect("complete keyring resolves");
    assert_eq!(keyring.active().key_id(), "new");
    assert_eq!(
        keyring
            .verification_keys()
            .iter()
            .map(SigningKey::key_id)
            .collect::<Vec<_>>(),
        vec!["new", "old"]
    );

    let missing = oraclemcp_auth::EnvLookupSecretResolver::new(|_: &str| None);
    let error = audit_verification_keyring_from_sources(&audit, None, &missing, None)
        .expect_err("unresolvable keyring fails closed");
    assert!(!error.contains(active_locator), "{error}");
    assert!(!error.contains(old_locator), "{error}");
}

#[test]
fn audit_keyring_rejects_same_material_under_different_ids() {
    let audit = AuditConfig {
        key_ref: Some("env:ACTIVE".to_owned()),
        key_id: Some("new".to_owned()),
        verification_keys: vec![oraclemcp_config::AuditVerificationKeyConfig {
            key_id: "old".to_owned(),
            key_ref: "env:OLD".to_owned(),
        }],
        ..AuditConfig::default()
    };
    let resolver = oraclemcp_auth::EnvLookupSecretResolver::new(|_: &str| Some("K".repeat(32)));
    let error = audit_verification_keyring_from_sources(&audit, None, &resolver, None)
        .expect_err("key reuse across ids is ambiguous");
    assert!(error.contains("reused under ids"), "{error}");
    assert!(!error.contains(&"K".repeat(32)), "{error}");
}

#[test]
fn audit_keyring_historical_secrets_follow_protected_policy_and_require_active_key() {
    let sentinel = "QA37_HISTORICAL_LITERAL_MUST_NOT_RENDER_123456789";
    let protected = AuditConfig {
        key_ref: Some("env:ACTIVE".to_owned()),
        key_id: Some("new".to_owned()),
        verification_keys: vec![oraclemcp_config::AuditVerificationKeyConfig {
            key_id: "old".to_owned(),
            key_ref: format!("literal:{sentinel}"),
        }],
        ..AuditConfig::default()
    };
    let resolver = oraclemcp_auth::EnvLookupSecretResolver::new(|_: &str| Some("A".repeat(32)));
    let error = resolve_audit_keyring_from_sources(&protected, None, true, &resolver, None)
        .expect_err("protected historical literal must fail closed");
    assert!(error.contains("forbidden"), "{error}");
    assert!(!error.contains(sentinel), "{error}");

    let historical_only = AuditConfig {
        verification_keys: vec![oraclemcp_config::AuditVerificationKeyConfig {
            key_id: "old".to_owned(),
            key_ref: "env:OLD".to_owned(),
        }],
        ..AuditConfig::default()
    };
    let error = resolve_audit_keyring_from_sources(&historical_only, None, false, &resolver, None)
        .expect_err("historical-only keyring has no signer");
    assert!(error.contains("without an active signing key"), "{error}");
}

#[test]
fn startup_performs_authenticated_mixed_key_rotation_end_to_end() {
    let root = target_tmp_file("qa37-startup-rotation");
    let path = root.join("audit.jsonl");
    let resolver = oraclemcp_auth::EnvLookupSecretResolver::new(|name: &str| match name {
        "QA37_OLD" => Some("O".repeat(32)),
        "QA37_NEW" => Some("N".repeat(32)),
        "QA37_CHANGED" => Some("C".repeat(32)),
        _ => None,
    });
    let level = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    let draft = oraclemcp_audit::AuditEntryDraft {
        subject: AuditSubject::new("startup-test", "qa37"),
        db_evidence: None,
        cancel: None,
        tool: "oracle_execute".to_owned(),
        sql: "delete from qa37 where id = 1".to_owned(),
        danger_level: "GUARDED".to_owned(),
        decision: oraclemcp_audit::AuditDecision::Allowed,
        rows_affected: Some(1),
        outcome: oraclemcp_audit::AuditOutcome::Succeeded,
    };
    let old_config = AuditConfig {
        path: Some(path.clone()),
        key_ref: Some("env:QA37_OLD".to_owned()),
        key_id: Some("old".to_owned()),
        ..AuditConfig::default()
    };
    {
        let auditor = build_auditor(&old_config, &level, OperatingLevel::Ddl, &resolver)
            .expect("old startup")
            .expect("auditor");
        auditor
            .append(&draft, "t1".to_owned(), true)
            .expect("old record");
    }

    let rotated_config = AuditConfig {
        path: Some(path.clone()),
        key_ref: Some("env:QA37_NEW".to_owned()),
        key_id: Some("new".to_owned()),
        verification_keys: vec![oraclemcp_config::AuditVerificationKeyConfig {
            key_id: "old".to_owned(),
            key_ref: "env:QA37_OLD".to_owned(),
        }],
        ..AuditConfig::default()
    };
    {
        let auditor = build_auditor(&rotated_config, &level, OperatingLevel::Ddl, &resolver)
            .expect("authenticated rotation startup")
            .expect("auditor");
        let record = auditor
            .append(&draft, "t2".to_owned(), true)
            .expect("new record");
        assert_eq!(record.seq, 2);
        assert_eq!(record.key_id.as_deref(), Some("new"));
    }
    let keyring = audit_verification_keyring_from_sources(&rotated_config, None, &resolver, None)
        .expect("verification keyring");
    let records = oraclemcp_audit::parse_jsonl(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        oraclemcp_audit::verify_records(&records, keyring.verification_keys()),
        oraclemcp_audit::VerifyOutcome::Ok { records: 2 }
    );

    let missing_history = AuditConfig {
        path: Some(path.clone()),
        key_ref: Some("env:QA37_NEW".to_owned()),
        key_id: Some("new".to_owned()),
        ..AuditConfig::default()
    };
    let error = match build_auditor(&missing_history, &level, OperatingLevel::Ddl, &resolver) {
        Err(error) => error,
        Ok(_) => panic!("missing old key must refuse startup"),
    };
    assert_eq!(error.0, "ORACLEMCP_AUDIT_CHAIN_RESUME_REFUSED");
    assert!(error.1.contains("old"), "{}", error.1);

    let same_id_changed_bytes = AuditConfig {
        path: Some(path),
        key_ref: Some("env:QA37_CHANGED".to_owned()),
        key_id: Some("old".to_owned()),
        ..AuditConfig::default()
    };
    let error = match build_auditor(
        &same_id_changed_bytes,
        &level,
        OperatingLevel::Ddl,
        &resolver,
    ) {
        Err(error) => error,
        Ok(_) => panic!("changed bytes behind old id must refuse startup"),
    };
    assert_eq!(error.0, "ORACLEMCP_AUDIT_CHAIN_RESUME_REFUSED");
    assert!(!error.1.contains(&"C".repeat(32)));
}

#[test]
fn build_auditor_optional_when_only_read_only_is_reachable() {
    // Read-only everywhere reachable + no key: auditor is optional (None).
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    let audit = AuditConfig::default();
    match build_auditor(
        &audit,
        &active,
        OperatingLevel::ReadOnly,
        &SystemSecretResolver,
    ) {
        Ok(auditor) => assert!(auditor.is_none()),
        Err((code, msg)) => panic!("read-only-only needs no key: {code}: {msg}"),
    }
}

#[test]
fn build_write_intent_log_fails_closed_on_unresolved_restart_intent() {
    let root = target_tmp_file("cx-c1-write-intents");
    {
        let log = WriteIntentLog::open(&root).expect("open intent log");
        let binding = oraclemcp_guard::ExecGrantBinding::new("sess-1", "lane-1", "principal-1", 1);
        let intent = oraclemcp_core::WriteIntent::new(oraclemcp_core::WriteIntentDetails {
            idempotency_key_material: "grant-1",
            subject: "profile:dev",
            active_profile: Some("dev"),
            tool: "oracle_execute",
            sql: "UPDATE employees SET name = name WHERE employee_id = 100",
            required_level: OperatingLevel::ReadWrite,
            binding: &binding,
        });
        log.append_pending(intent).expect("append pending intent");
    }

    match build_write_intent_log_at(&root, OperatingLevel::ReadWrite) {
        Err((code, message)) => {
            assert_eq!(code, "ORACLEMCP_WRITE_INTENT_IN_DOUBT");
            assert!(message.contains("unresolved intent"), "{message}");
            assert!(message.contains("sql_hash=sha256:"), "{message}");
        }
        Ok(_) => panic!("writable startup must fail closed with an unresolved intent"),
    }
}

#[test]
fn writable_http_state_and_client_credentials_share_startup_owner() {
    let root = target_tmp_file("qa1-writable-http-state");
    let owner = build_service_owner_at(&root, true)
        .expect("service state owner")
        .expect("owner required");
    let write_intents = build_write_intent_log(OperatingLevel::ReadWrite, Some(&owner))
        .expect("write-intent startup")
        .expect("writable log required");
    let clients =
        ClientCredentialStore::open_with_owner(owner.clone()).expect("client credential startup");
    let config = ConfigOpsBackend::open_with_owner(owner.clone()).expect("config ops startup");
    let proposals =
        ChangeProposalStore::open_with_owner(owner.clone()).expect("change proposal startup");
    let history = SourceHistoryStore::open_with_owner(owner).expect("source history startup");

    assert!(write_intents.unresolved().expect("intent state").is_empty());
    assert!(clients.list().is_empty());
    let target = root.join("profiles.toml");
    assert!(config.stage_config_draft(target, "").is_ok());
    assert!(proposals.list().expect("proposal list").is_empty());
    assert!(
        history
            .list(oraclemcp_core::SourceHistoryFilter::default())
            .expect("history list")
            .is_empty()
    );
}

#[test]
fn http_listen_loopback_allowed_with_allow_no_auth() {
    assert!(http_listen_guard(true, false, false, "127.0.0.1:7070", false).is_ok());
    assert!(http_listen_guard(true, false, true, "[::1]:7070", false).is_ok());
}

#[test]
fn http_listen_loopback_allowed_with_oauth_or_mtls() {
    assert!(http_listen_guard(false, true, false, "127.0.0.1:7070", false).is_ok());
    assert!(http_listen_guard(false, true, true, "127.0.0.1:7070", false).is_ok());
}

#[test]
fn http_listen_non_loopback_refused_without_remote_optin() {
    let err = http_listen_guard(true, false, false, "0.0.0.0:7070", false).unwrap_err();
    assert_eq!(err.0, "ORACLEMCP_HTTP_REMOTE_BIND_REFUSED");
    let err = http_listen_guard(false, true, true, "192.168.1.10:7070", false).unwrap_err();
    assert_eq!(err.0, "ORACLEMCP_HTTP_REMOTE_BIND_REFUSED");
}

#[test]
fn http_listen_non_loopback_allowed_with_remote_optin() {
    assert!(http_listen_guard(true, false, false, "0.0.0.0:7070", true).is_ok());
    assert!(http_listen_guard(false, true, true, "0.0.0.0:7070", true).is_ok());
}

#[test]
fn http_listen_auth_refusal_precedes_remote_check() {
    let err = http_listen_guard(false, false, true, "0.0.0.0:7070", true).unwrap_err();
    assert_eq!(err.0, "ORACLEMCP_AUTH_REQUIRED");
}

#[test]
fn http_cli_oauth_builds_enforced_transport_config() {
    let args = HttpServeArgs {
        allowed_hosts: vec!["mcp.example.com".to_owned()],
        allowed_origins: vec!["https://client.example.com".to_owned()],
        json_response: true,
        stateful: true,
        oauth_resource: Some("https://mcp.example.com/mcp".to_owned()),
        oauth_issuers: vec!["https://idp.example.com".to_owned()],
        oauth_authorization_servers: vec!["https://idp.example.com".to_owned()],
        oauth_required_scopes: vec!["oracle:read".to_owned()],
        oauth_hs256_secret_ref: Some("literal:0123456789abcdef0123456789abcdef".to_owned()),
        ..Default::default()
    };
    let http = apply_http_cli_overrides(HttpConfig::default(), &args);
    let cfg = http_transport_config_from_merged(http, false, &SystemSecretResolver)
        .expect("valid OAuth transport config");

    assert!(cfg.transport.oauth.is_some());
    assert_eq!(
        cfg.transport.resource_metadata.as_ref().expect("metadata")["resource"],
        serde_json::json!("https://mcp.example.com/mcp")
    );
    assert_eq!(cfg.transport.allowed_hosts, ["mcp.example.com"]);
    assert_eq!(
        cfg.transport.allowed_origins,
        ["https://client.example.com"]
    );
    assert!(cfg.transport.json_response);
    assert!(cfg.transport.stateful);
    assert!(cfg.transport.single_principal_guard.is_some());
    assert!(cfg.tls.is_none());
}

#[test]
fn trusted_https_termination_sets_effective_scheme_without_native_tls() {
    let cfg = http_transport_config_from_merged(
        HttpConfig {
            trusted_https_termination: true,
            ..Default::default()
        },
        false,
        &SystemSecretResolver,
    )
    .expect("trusted HTTPS termination resolves");

    assert_eq!(cfg.transport.effective_scheme, EffectiveHttpScheme::Https);
    assert!(
        cfg.tls.is_none(),
        "trusted termination is not native rustls"
    );

    let default_cfg =
        http_transport_config_from_merged(HttpConfig::default(), false, &SystemSecretResolver)
            .expect("default HTTP resolves");
    assert_eq!(
        default_cfg.transport.effective_scheme,
        EffectiveHttpScheme::Http
    );
}

#[test]
fn http_oauth_literal_secret_is_rejected_for_protected_profiles() {
    let http = HttpConfig {
        oauth: Some(HttpOAuthConfig {
            resource: Some("https://mcp.example.com/mcp".to_owned()),
            allowed_issuers: vec!["https://idp.example.com".to_owned()],
            authorization_servers: vec!["https://idp.example.com".to_owned()],
            required_scopes: vec!["oracle:read".to_owned()],
            hs256_secret_ref: Some("literal:test-secret".to_owned()),
            metadata_url: None,
        }),
        ..Default::default()
    };

    let err = http_transport_config_from_merged(http, true, &SystemSecretResolver)
        .expect_err("protected profile rejects literal OAuth secret");
    assert_eq!(err.0, "ORACLEMCP_HTTP_OAUTH_SECRET_INVALID");
    assert!(err.1.contains("plaintext literal credential is forbidden"));
    assert!(!err.1.contains("test-secret"));
}

fn oauth_http_config(secret_ref: String) -> HttpConfig {
    HttpConfig {
        oauth: Some(HttpOAuthConfig {
            resource: Some("https://mcp.example.com/mcp".to_owned()),
            allowed_issuers: vec!["https://idp.example.com".to_owned()],
            authorization_servers: vec!["https://idp.example.com".to_owned()],
            required_scopes: vec!["oracle:read".to_owned()],
            hs256_secret_ref: Some(secret_ref),
            metadata_url: None,
        }),
        ..Default::default()
    }
}

#[test]
fn http_oauth_resolved_secret_enforces_31_32_byte_boundary_and_redacts() {
    let locator = "QA2_OAUTH_SECRET_LOCATOR_MUST_NOT_RENDER";
    for len in [0, 1, 31] {
        let secret = "O".repeat(len);
        let resolver = oraclemcp_auth::EnvLookupSecretResolver::new({
            let secret = secret.clone();
            move |_: &str| Some(secret.clone())
        });
        let error = http_transport_config_from_merged(
            oauth_http_config(format!("env:{locator}")),
            false,
            &resolver,
        )
        .expect_err("undersized resolved OAuth key must fail closed");
        assert_eq!(error.0, "ORACLEMCP_HTTP_OAUTH_SECRET_INVALID");
        assert!(error.1.contains(&format!("{len} bytes")), "{}", error.1);
        assert!(!error.1.contains(locator), "{}", error.1);
        if len == 31 {
            assert!(!error.1.contains(&secret), "{}", error.1);
        }
    }

    for len in [32, 33] {
        let secret = "O".repeat(len);
        let resolver =
            oraclemcp_auth::EnvLookupSecretResolver::new(move |_: &str| Some(secret.clone()));
        let resolved = http_transport_config_from_merged(
            oauth_http_config("env:QA2_OAUTH_SECRET".to_owned()),
            false,
            &resolver,
        )
        .expect("minimum-size resolved OAuth key is valid");
        assert!(resolved.transport.oauth.is_some());
    }
}

#[test]
fn http_oauth_rejects_newline_only_key_file_without_leaking_its_path() {
    let key_path = target_tmp_file("qa2-newline-oauth-key");
    fs::write(&key_path, "\n").expect("write newline-only key fixture");
    let error = http_transport_config_from_merged(
        oauth_http_config(format!("file:{}", key_path.display())),
        false,
        &SystemSecretResolver,
    )
    .expect_err("newline-only OAuth key resolves empty and must be rejected");
    assert_eq!(error.0, "ORACLEMCP_HTTP_OAUTH_SECRET_INVALID");
    assert!(error.1.contains("0 bytes"), "{}", error.1);
    assert!(
        !error.1.contains(&key_path.display().to_string()),
        "{}",
        error.1
    );
}

#[test]
fn metrics_dispatch_forwards_stream_frames_and_records_one_terminal_outcome() {
    struct StreamAwareDispatch {
        ordinary_calls: Arc<std::sync::atomic::AtomicUsize>,
        stream_calls: Arc<std::sync::atomic::AtomicUsize>,
        first_row_sent: std::sync::mpsc::Sender<()>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        completed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ToolDispatch for StreamAwareDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            self.ordinary_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { DispatchOutcome::Ok(serde_json::json!({ "buffered": true })) })
        }

        fn dispatch_stream<'a>(
            &'a self,
            cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
            frames: ToolStreamSender,
        ) -> DispatchFuture<'a> {
            self.stream_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                frames
                    .send(
                        cx,
                        oraclemcp_core::ToolStreamFrame::Row {
                            seq: 0,
                            row: serde_json::json!({ "id": 1 }),
                        },
                    )
                    .await
                    .expect("first row reaches the transport channel");
                self.first_row_sent
                    .send(())
                    .expect("first-row observer is alive");
                let (lock, cvar) = &*self.release;
                {
                    let mut released = lock.lock().expect("release mutex not poisoned");
                    while !*released {
                        released = cvar.wait(released).expect("release mutex not poisoned");
                    }
                }
                frames
                    .send(
                        cx,
                        oraclemcp_core::ToolStreamFrame::Row {
                            seq: 1,
                            row: serde_json::json!({ "id": 2 }),
                        },
                    )
                    .await
                    .expect("second row reaches the transport channel");
                self.completed.store(true, Ordering::SeqCst);
                DispatchOutcome::Ok(serde_json::json!({
                    "streaming": true,
                    "rows_returned": 2
                }))
            })
        }
    }

    let ordinary_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stream_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (first_row_tx, first_row_rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let metrics = Arc::new(Metrics::new());
    let dispatch: Arc<dyn ToolDispatch> = Arc::new(MetricsDispatch::new(
        Arc::new(StreamAwareDispatch {
            ordinary_calls: Arc::clone(&ordinary_calls),
            stream_calls: Arc::clone(&stream_calls),
            first_row_sent: first_row_tx,
            release: Arc::clone(&release),
            completed: Arc::clone(&completed),
        }),
        Arc::clone(&metrics),
    ));
    let lane = LaneRuntime::spawn("metrics-stream-lane", dispatch, 4);
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("test runtime builds");
    let (outcome, frames) = runtime.block_on(async {
        let cx = Cx::current().expect("test runtime installs Cx");
        let (frames_tx, mut frames_rx) = asupersync::channel::mpsc::channel(2);
        let mut reply = lane
            .dispatch_stream_start(
                &cx,
                DispatchContext::default().with_principal_key("oauth:streamer"),
                "oracle_query",
                serde_json::json!({ "sql": "SELECT id FROM demo", "streaming": true }),
                frames_tx,
            )
            .await
            .expect("streaming lane accepts the call");
        let first = frames_rx.recv(&cx).await.expect("first forwarded frame");
        first_row_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("inner dispatcher emitted the first row");
        assert!(
            !completed.load(Ordering::SeqCst),
            "the first row is observable before terminal completion"
        );
        let (lock, cvar) = &*release;
        *lock.lock().expect("release mutex not poisoned") = true;
        cvar.notify_all();
        let second = frames_rx.recv(&cx).await.expect("second forwarded frame");
        let outcome = reply
            .recv(&cx)
            .await
            .expect("streaming lane returns a terminal outcome");
        (outcome, vec![first, second])
    });

    assert_eq!(
        frames,
        vec![
            oraclemcp_core::ToolStreamFrame::Row {
                seq: 0,
                row: serde_json::json!({ "id": 1 }),
            },
            oraclemcp_core::ToolStreamFrame::Row {
                seq: 1,
                row: serde_json::json!({ "id": 2 }),
            },
        ]
    );
    assert_eq!(
        outcome,
        DispatchOutcome::Ok(serde_json::json!({
            "streaming": true,
            "rows_returned": 2
        }))
    );
    assert_eq!(ordinary_calls.load(Ordering::SeqCst), 0);
    assert_eq!(stream_calls.load(Ordering::SeqCst), 1);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.requests.len(), 1);
    assert_eq!(snapshot.requests[0].tool, "oracle_query");
    assert_eq!(snapshot.requests[0].status, "ok");
    assert_eq!(snapshot.requests[0].count, 1);
    assert_eq!(snapshot.lane_requests.len(), 1);
    assert_eq!(snapshot.lane_requests[0].lane_id, "metrics-stream-lane");
    assert_eq!(snapshot.lane_requests[0].status, "ok");
    assert_eq!(snapshot.lane_requests[0].count, 1);
    assert_eq!(snapshot.lane_request_duration_ms.len(), 1);
    assert_eq!(
        snapshot.lane_request_duration_ms[0].histogram.count, 1,
        "streaming completion records exactly one duration"
    );
}

#[test]
fn metrics_dispatch_forwards_stream_cancellation_and_records_it_once() {
    struct CancellationAwareStream {
        stream_calls: Arc<std::sync::atomic::AtomicUsize>,
        entered: std::sync::mpsc::Sender<()>,
    }

    impl ToolDispatch for CancellationAwareStream {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async { DispatchOutcome::Ok(serde_json::Value::Null) })
        }

        fn dispatch_stream<'a>(
            &'a self,
            cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
            _frames: ToolStreamSender,
        ) -> DispatchFuture<'a> {
            self.stream_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                self.entered
                    .send(())
                    .expect("stream-entry observer is alive");
                while cx.checkpoint().is_ok() {
                    asupersync::runtime::yield_now().await;
                }
                DispatchOutcome::Cancelled(
                    cx.cancel_reason().unwrap_or_else(|| {
                        asupersync::CancelReason::user("stream cancelled in test")
                    }),
                )
            })
        }
    }

    let stream_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let metrics = Arc::new(Metrics::new());
    let dispatch: Arc<dyn ToolDispatch> = Arc::new(MetricsDispatch::new(
        Arc::new(CancellationAwareStream {
            stream_calls: Arc::clone(&stream_calls),
            entered: entered_tx,
        }),
        Arc::clone(&metrics),
    ));
    let lane = LaneRuntime::spawn("metrics-cancel-lane", dispatch, 4);
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("test runtime builds");
    let outcome = runtime.block_on(async {
        let cx = Cx::current().expect("test runtime installs Cx");
        let (frames_tx, _frames_rx) = asupersync::channel::mpsc::channel(1);
        let mut reply = lane
            .dispatch_stream_start(
                &cx,
                DispatchContext::default(),
                "oracle_query",
                serde_json::json!({ "streaming": true }),
                frames_tx,
            )
            .await
            .expect("streaming lane accepts the call");
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("inner streaming dispatch starts");
        cx.set_cancel_requested(true);
        reply
            .recv(&cx)
            .await
            .expect("cancelled stream returns its terminal classification")
    });

    assert!(matches!(outcome, DispatchOutcome::Cancelled(_)));
    assert_eq!(stream_calls.load(Ordering::SeqCst), 1);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.requests.len(), 1);
    assert_eq!(snapshot.requests[0].status, "cancelled");
    assert_eq!(snapshot.requests[0].count, 1);
    assert_eq!(snapshot.lane_request_duration_ms.len(), 1);
    assert_eq!(snapshot.lane_request_duration_ms[0].histogram.count, 1);
}

#[test]
fn stateless_http_read_workers_do_not_head_of_line_block() {
    struct ControlDispatch;

    impl ToolDispatch for ControlDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async {
                DispatchOutcome::Ok(serde_json::json!({
                    "control": true
                }))
            })
        }
    }

    struct BlockingReadDispatch {
        started: std::sync::mpsc::Sender<()>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    impl ToolDispatch for BlockingReadDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                self.started.send(()).expect("test observer is alive");
                let (lock, cvar) = &*self.release;
                let mut released = lock.lock().expect("release mutex not poisoned");
                while !*released {
                    released = cvar.wait(released).expect("release mutex not poisoned");
                }
                DispatchOutcome::Ok(serde_json::json!({
                    "schemas": []
                }))
            })
        }
    }

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let read_factory: Arc<ReadWorkerFactoryBuilder> = Arc::new({
        let release = Arc::clone(&release);
        move |_profile| {
            let started = started_tx.clone();
            let release = Arc::clone(&release);
            let factory: Arc<LaneDispatchFactory> =
                Arc::new(move |_cx: &Cx, _lane_context: &LaneContext| {
                    let dispatch: Arc<dyn ToolDispatch> = Arc::new(BlockingReadDispatch {
                        started: started.clone(),
                        release: Arc::clone(&release),
                    });
                    Box::pin(async move { Ok(dispatch) })
                });
            Ok(PreparedLaneDispatch::new(
                factory,
                oraclemcp_core::DEFAULT_REQUEST_TIMEOUT,
            ))
        }
    });
    let control_lane = LaneRuntime::spawn("test-stateless-control", Arc::new(ControlDispatch), 4);
    let dispatch = Arc::new(HttpStatelessReadDispatch::new(
        control_lane,
        Some("dev".to_owned()),
        2,
        read_factory,
    ));

    let mut handles = Vec::new();
    for _ in 0..2 {
        let dispatch = Arc::clone(&dispatch);
        handles.push(std::thread::spawn(move || {
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .build()
                .expect("test runtime builds");
            runtime.block_on(async move {
                let cx = Cx::current().expect("test runtime installs Cx");
                let outcome = dispatch
                    .dispatch(
                        &cx,
                        oraclemcp_core::DispatchContext::default()
                            .with_principal_key("oauth:reader"),
                        "oracle_list_schemas",
                        serde_json::json!({ "max_rows": 1 }),
                    )
                    .await;
                assert!(matches!(outcome, DispatchOutcome::Ok(_)));
            });
        }));
    }

    started_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("first read worker starts");
    started_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("second read worker starts without waiting for first to finish");

    let (lock, cvar) = &*release;
    *lock.lock().expect("release mutex not poisoned") = true;
    cvar.notify_all();
    for handle in handles {
        handle.join().expect("read worker caller joins");
    }
}

#[test]
fn stateless_http_rebuilds_a_failed_prepared_read_worker() {
    struct ControlDispatch;

    impl ToolDispatch for ControlDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async { DispatchOutcome::Ok(serde_json::json!({ "control": true })) })
        }
    }

    struct ReadOkDispatch;

    impl ToolDispatch for ReadOkDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async { DispatchOutcome::Ok(serde_json::json!({ "schemas": [] })) })
        }
    }

    let builder_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted_runs = Arc::clone(&builder_runs);
    let read_factory: Arc<ReadWorkerFactoryBuilder> = Arc::new(move |_profile| {
        let attempt = counted_runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
            Box::pin(async move {
                if attempt == 0 {
                    Err(ErrorEnvelope::new(
                        ErrorClass::ConnectionFailed,
                        "transient first read-worker initialization failure",
                    ))
                } else {
                    Ok(Arc::new(ReadOkDispatch) as Arc<dyn ToolDispatch>)
                }
            })
        });
        Ok(PreparedLaneDispatch::new(
            factory,
            oraclemcp_core::DEFAULT_REQUEST_TIMEOUT,
        ))
    });
    let dispatch = HttpStatelessReadDispatch::new(
        LaneRuntime::spawn(
            "test-stateless-rebuild-control",
            Arc::new(ControlDispatch),
            4,
        ),
        Some("dev".to_owned()),
        1,
        read_factory,
    );
    let call = || {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            let cx = Cx::current().expect("test runtime installs Cx");
            dispatch
                .dispatch(
                    &cx,
                    oraclemcp_core::DispatchContext::default().with_principal_key("oauth:reader"),
                    "oracle_list_schemas",
                    serde_json::json!({ "max_rows": 1 }),
                )
                .await
        })
    };

    assert!(matches!(call(), DispatchOutcome::Err(_)));
    assert!(matches!(call(), DispatchOutcome::Ok(_)));
    assert_eq!(builder_runs.load(std::sync::atomic::Ordering::SeqCst), 2,);
}

#[test]
fn pre_cancelled_stateless_read_allocates_no_worker_or_factory() {
    struct ControlDispatch;

    impl ToolDispatch for ControlDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async { DispatchOutcome::Ok(serde_json::json!({ "control": true })) })
        }
    }

    let builder_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted_runs = Arc::clone(&builder_runs);
    let read_factory: Arc<ReadWorkerFactoryBuilder> = Arc::new(move |_profile| {
        counted_runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
            Box::pin(async { Ok(Arc::new(ControlDispatch) as Arc<dyn ToolDispatch>) })
        });
        Ok(PreparedLaneDispatch::new(
            factory,
            oraclemcp_core::DEFAULT_REQUEST_TIMEOUT,
        ))
    });
    let dispatch = HttpStatelessReadDispatch::new(
        LaneRuntime::spawn(
            "test-stateless-pre-cancel-control",
            Arc::new(ControlDispatch),
            4,
        ),
        Some("dev".to_owned()),
        1,
        read_factory,
    );
    let outcome = {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            let cx = Cx::current().expect("test runtime installs Cx");
            cx.set_cancel_requested(true);
            dispatch
                .dispatch(
                    &cx,
                    oraclemcp_core::DispatchContext::default().with_principal_key("oauth:reader"),
                    "oracle_list_schemas",
                    serde_json::json!({ "max_rows": 1 }),
                )
                .await
        })
    };

    assert!(matches!(outcome, DispatchOutcome::Cancelled(_)));
    assert_eq!(builder_runs.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(dispatch.read_lane_count(), 0);
}

#[test]
fn qa45_stateless_http_discovery_and_custom_execution_share_the_control_catalog() {
    struct CatalogDispatch {
        tool_name: &'static str,
    }

    impl ToolDispatch for CatalogDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            let allowed = name == self.tool_name || name == "oracle_list_schemas";
            Box::pin(async move {
                if allowed {
                    DispatchOutcome::Ok(serde_json::json!({"executed": name}))
                } else {
                    DispatchOutcome::Err(ErrorEnvelope::new(
                        ErrorClass::InvalidArguments,
                        "tool is absent from this dispatch catalog",
                    ))
                }
            })
        }

        fn mcp_surface_state<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            _detail: McpSurfaceDetail,
        ) -> McpSurfaceFuture<'a> {
            let descriptor = oraclemcp_core::ToolDescriptor::new(
                self.tool_name,
                oraclemcp_core::ToolTier::FoundationLiveDb,
                "stateless catalog marker",
            );
            Box::pin(async move {
                asupersync::Outcome::Ok(Some(oraclemcp_core::McpSurfaceState {
                    current_level: OperatingLevel::ReadOnly,
                    effective_ceiling: OperatingLevel::ReadOnly,
                    max_level: OperatingLevel::ReadOnly,
                    protected: false,
                    active_profile: Some("dev".to_owned()),
                    custom_catalog: oraclemcp_core::McpToolCatalogSnapshot {
                        generation: 7,
                        tools: vec![descriptor].into(),
                    },
                    connection: oraclemcp_core::ConnectionStatus::default(),
                }))
            })
        }
    }

    let read_factory: Arc<ReadWorkerFactoryBuilder> = Arc::new(|_profile| {
        let factory: Arc<LaneDispatchFactory> = Arc::new(|_cx, _lane| {
            let dispatch: Arc<dyn ToolDispatch> = Arc::new(CatalogDispatch {
                tool_name: "custom_read_worker_only",
            });
            Box::pin(async move { Ok(dispatch) })
        });
        Ok(PreparedLaneDispatch::new(
            factory,
            oraclemcp_core::DEFAULT_REQUEST_TIMEOUT,
        ))
    });
    let dispatch = HttpStatelessReadDispatch::new(
        LaneRuntime::spawn(
            "qa45-stateless-control",
            Arc::new(CatalogDispatch {
                tool_name: "custom_control",
            }),
            4,
        ),
        Some("dev".to_owned()),
        1,
        read_factory,
    );

    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("test runtime builds");
    runtime.block_on(async {
        let cx = Cx::current().expect("test runtime installs Cx");
        let context =
            oraclemcp_core::DispatchContext::default().with_principal_key("oauth:stateless-reader");
        let before = dispatch
            .mcp_surface_state(&cx, context, McpSurfaceDetail::LevelOnly)
            .await
            .expect("control surface succeeds")
            .expect("control surface is present");
        assert_eq!(before.custom_catalog.generation, 7);
        assert_eq!(before.custom_catalog.tools[0].name, "custom_control");

        dispatch
            .dispatch(&cx, context, "oracle_list_schemas", serde_json::json!({}))
            .await
            .expect("read worker is created");
        let after = dispatch
            .mcp_surface_state(&cx, context, McpSurfaceDetail::LevelOnly)
            .await
            .expect("control surface succeeds")
            .expect("control surface is present");
        assert_eq!(after.custom_catalog.tools[0].name, "custom_control");
        assert_ne!(
            after.custom_catalog.tools[0].name, "custom_read_worker_only",
            "read-worker catalogs must not replace stateless control discovery"
        );
        dispatch
            .dispatch(&cx, context, "custom_control", serde_json::json!({}))
            .await
            .expect("advertised custom tool executes on the control lane");
    });
}

#[test]
fn stateless_http_profile_switch_closes_read_workers() {
    struct SwitchControlDispatch;

    impl ToolDispatch for SwitchControlDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                if name == "oracle_switch_profile" {
                    DispatchOutcome::Ok(serde_json::json!({
                        "active_profile": "prod"
                    }))
                } else {
                    DispatchOutcome::Ok(serde_json::json!({
                        "control": name
                    }))
                }
            })
        }
    }

    struct ProfileReadDispatch {
        profile: Option<String>,
        seen: std::sync::mpsc::Sender<Option<String>>,
        closed: std::sync::mpsc::Sender<DispatchCloseReason>,
    }

    impl ToolDispatch for ProfileReadDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                self.seen
                    .send(self.profile.clone())
                    .expect("test profile observer is alive");
                DispatchOutcome::Ok(serde_json::json!({
                    "schemas": []
                }))
            })
        }

        fn close<'a>(
            &'a self,
            _cx: &'a Cx,
            reason: DispatchCloseReason,
        ) -> oraclemcp_core::DispatchCloseFuture<'a> {
            self.closed
                .send(reason)
                .expect("test close observer is alive");
            Box::pin(async { Ok(()) })
        }
    }

    let (profile_tx, profile_rx) = std::sync::mpsc::channel();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    let read_factory: Arc<ReadWorkerFactoryBuilder> = Arc::new(move |profile| {
        let seen = profile_tx.clone();
        let closed = closed_tx.clone();
        let factory: Arc<LaneDispatchFactory> =
            Arc::new(move |_cx: &Cx, _lane_context: &LaneContext| {
                let dispatch: Arc<dyn ToolDispatch> = Arc::new(ProfileReadDispatch {
                    profile: profile.clone(),
                    seen: seen.clone(),
                    closed: closed.clone(),
                });
                Box::pin(async move { Ok(dispatch) })
            });
        Ok(PreparedLaneDispatch::new(
            factory,
            oraclemcp_core::DEFAULT_REQUEST_TIMEOUT,
        ))
    });
    let control_lane = LaneRuntime::spawn(
        "test-stateless-switch-control",
        Arc::new(SwitchControlDispatch),
        4,
    );
    let dispatch =
        HttpStatelessReadDispatch::new(control_lane, Some("dev".to_owned()), 1, read_factory);

    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("test runtime builds");
    runtime.block_on(async {
        let cx = Cx::current().expect("test runtime installs Cx");
        let first = dispatch
            .dispatch(
                &cx,
                oraclemcp_core::DispatchContext::default().with_principal_key("oauth:reader"),
                "oracle_list_schemas",
                serde_json::json!({ "max_rows": 1 }),
            )
            .await;
        assert!(matches!(first, DispatchOutcome::Ok(_)));

        let switched = dispatch
            .dispatch(
                &cx,
                oraclemcp_core::DispatchContext::default().with_principal_key("oauth:reader"),
                "oracle_switch_profile",
                serde_json::json!({ "profile": "prod" }),
            )
            .await;
        assert!(matches!(switched, DispatchOutcome::Ok(_)));

        let second = dispatch
            .dispatch(
                &cx,
                oraclemcp_core::DispatchContext::default().with_principal_key("oauth:reader"),
                "oracle_list_schemas",
                serde_json::json!({ "max_rows": 1 }),
            )
            .await;
        assert!(matches!(second, DispatchOutcome::Ok(_)));
    });

    assert_eq!(
        profile_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("first read records startup profile"),
        Some("dev".to_owned())
    );
    assert_eq!(
        closed_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("profile switch closes old read lane"),
        DispatchCloseReason::RuntimeDrop
    );
    assert_eq!(
        profile_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("next read records switched profile"),
        Some("prod".to_owned())
    );
}

#[test]
fn http_tls_material_builds_native_tls_config() {
    let (server_cert, server_key) = self_signed_cert();
    let (client_ca, _client_ca_key) = self_signed_cert();
    let cert_path = target_tmp_file("server.pem");
    let key_path = target_tmp_file("server.key");
    let client_ca_path = target_tmp_file("client-ca.pem");
    fs::write(&cert_path, server_cert).expect("server cert fixture");
    fs::write(&key_path, server_key).expect("server key fixture");
    fs::write(&client_ca_path, client_ca).expect("client CA fixture");

    let args = HttpServeArgs {
        tls_cert: Some(cert_path.clone()),
        tls_key: Some(key_path),
        mtls_client_ca: Some(client_ca_path.clone()),
        mtls_client_fingerprints: vec![
            "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
        ],
        control_listen: Some("127.0.0.1:7443".to_owned()),
        ..Default::default()
    };
    let mut base = HttpConfig::default();
    base.operator.allowed_subjects = vec![
        "mtls:sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
    ];
    let http = apply_http_cli_overrides(base, &args);
    assert_eq!(
        http.tls
            .as_ref()
            .and_then(|tls| tls.client_ca_path.as_deref()),
        Some(client_ca_path.as_path())
    );

    let cfg = http_transport_config_from_merged(http, false, &SystemSecretResolver)
        .expect("native TLS listener config builds");
    assert!(cfg.tls.is_some());
    assert!(cfg.mtls_required);
    assert!(!cfg.transport.mtls_clients.is_empty());
    assert_eq!(
        cfg.control.as_ref().map(|control| control.listen.as_str()),
        Some("127.0.0.1:7443")
    );
}

#[test]
fn stub_connection_returns_an_envelopable_error() {
    let stub = stub::StubConnection::new(oraclemcp_db::DbError::Connect(
        "listener refused the connection".to_owned(),
    ));
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("current-thread runtime");
    let err = runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        stub.ping(&cx).await.expect_err("stub always errors")
    });
    // It maps to a structured envelope (no panic).
    let _ = err.into_envelope();
}

#[test]
fn stdout_exit_treats_broken_pipe_as_success_path() {
    let code = stdout_exit(
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed")),
        ExitCode::from(2),
    );
    assert_eq!(format!("{code:?}"), "ExitCode(unix_exit_status(0))");
}

#[test]
fn doctor_process_exit_code_matches_cli_contract() {
    let ok = oraclemcp_core::DoctorReport {
        checks: Vec::new(),
        profile_caps: None,
        auth_capabilities: None,
        service_health: None,
        service_unit_caps: None,
        fix: None,
    };
    assert_eq!(doctor_process_exit_code(&ok), 0);

    let failed = oraclemcp_core::DoctorReport {
        checks: vec![oraclemcp_core::CheckResult {
            id: 1,
            name: "example".to_owned(),
            status: oraclemcp_core::CheckStatus::Fail,
            detail: "failed".to_owned(),
            fix: None,
            failure_class: None,
            auth_mode: None,
            wallet_error: None,
            wallet_posture: None,
            wallet_cert_expiry: None,
            ora_code: None,
        }],
        profile_caps: None,
        auth_capabilities: None,
        service_health: None,
        service_unit_caps: None,
        fix: None,
    };
    let process_code = doctor_process_exit_code(&failed);
    assert_eq!(process_code, 2);
    assert_eq!(
        failed.to_json_with_exit_code(i32::from(process_code))["exit_code"],
        serde_json::json!(2)
    );
    let fix_report = failed.with_fix_report();
    assert_eq!(doctor_process_exit_code(&fix_report), 2);
}

/// B5.1 — plsql-intelligence DETECTION CONTRACT.
///
/// B5 wired the detection as a COMPILE-TIME gate
/// (`cfg!(feature = "plsql-intelligence")`); the existing doctor.rs tests only
/// cover the RENDER with a MOCK bool. This test proves the REAL feature path in
/// the crate that OWNS the feature: it derives detection from the same
/// `cfg!(...)` expression `run_doctor_cmd` uses (not a mock) and runs the actual
/// doctor trio-stack, then asserts the outcome per build. The present/absent
/// expectations are gated on the SAME real `cfg`, so under
/// `--features plsql-intelligence` (and in the `cargo hack` feature powerset) the
/// present-arm truly executes, and the default build executes the absent-arm.
/// Neither arm may crash and neither may LEAK a path, crate name, or version.
#[test]
fn trio_stack_reports_real_cfg_gated_plsql_intelligence_detection() {
    // Derive detection from the SAME compile-time gate `run_doctor_cmd` uses —
    // this is the real feature path, not a mock bool.
    let ctx = DoctorContext {
        plsql_intelligence_detected: cfg!(feature = "plsql-intelligence"),
        ..DoctorContext::default()
    };
    // Run the ACTUAL doctor path (offline, default context). It must not panic
    // on either build.
    let report = block_on_connect(|cx| async move { run_doctor(&cx, &ctx).await });
    let trio = report
        .checks
        .iter()
        .find(|c| c.id == 15)
        .expect("trio-stack provenance check is present");
    assert_eq!(
        trio.status,
        oraclemcp_core::CheckStatus::Pass,
        "trio-stack must pass on both feature builds: {}",
        trio.detail
    );

    // Isolate the plsql-intelligence status segment from the "; "-joined detail
    // (the rest of the detail legitimately carries URLs with '/').
    let segment = trio
        .detail
        .split("; ")
        .find(|s| s.starts_with("plsql-intelligence"))
        .expect("trio-stack renders a plsql-intelligence status segment");

    // Present-arm vs absent-arm, gated on the SAME real cfg the code compiles
    // against — so the present expectation only runs under the feature build and
    // actually exercises the compiled-in engine's detection.
    #[cfg(feature = "plsql-intelligence")]
    assert_eq!(
        segment, "plsql-intelligence detected",
        "the --features plsql-intelligence build must report the engine PRESENT"
    );
    #[cfg(not(feature = "plsql-intelligence"))]
    assert_eq!(
        segment, "plsql-intelligence not detected",
        "the default build must report the engine ABSENT, cleanly"
    );

    // No-leak: detection is a bool, so its rendered status is JUST
    // `detected`/`not detected` — never a filesystem path, a crate path, or a
    // version. Assert it so a future change that leaks an engine path or a
    // version string is caught here.
    assert!(
        !segment.contains('/') && !segment.contains('\\'),
        "plsql-intelligence status must not leak a filesystem/crate path: {segment:?}"
    );
    assert!(
        !segment.chars().any(|c| c.is_ascii_digit()),
        "plsql-intelligence status must not leak a version: {segment:?}"
    );
    for engine_crate in [
        "plsql-core",
        "plsql-engine",
        "plsql-catalog",
        "plsql-depgraph",
        "plsql-lineage",
        "plsql-ir",
        "plsql-parser-antlr",
        "plsql-symbols",
        "plsql-cicd",
        "plsql-doc",
        "plsql-sast",
        "plsql-output",
    ] {
        assert!(
            !segment.contains(engine_crate),
            "plsql-intelligence status must not leak the engine crate {engine_crate}: {segment:?}"
        );
    }
}

#[test]
fn doctor_sensitive_values_include_connect_material() {
    let opts = OracleConnectOptions {
        connect_string: "dbhost:1521/private_service".to_owned(),
        username: Some("APP_USER".to_owned()),
        password: Some("super_secret".to_owned()),
        auth_adapter: oraclemcp_db::AuthAdapter::Proxy {
            proxy_user: "MCP_PROXY".to_owned(),
            target_schema: "APP_OWNER".to_owned(),
        },
        wallet_location: Some("/home/operator/private-wallet".into()),
        wallet_password: Some("wallet_secret".to_owned()),
        ssl_server_cert_dn: Some("CN=private-db,O=Example,C=US".to_owned()),
        use_iam_token: true,
        iam_token: Some("iam.jwt.token".to_owned()),
        app_context: vec![(
            "private-namespace".to_owned(),
            "private-key".to_owned(),
            "private-value".to_owned(),
        )],
        session_identity: Some(oraclemcp_db::OracleSessionIdentity {
            program: Some("private-program".to_owned()),
            machine: Some("private-machine".to_owned()),
            os_user: Some("private-os-user".to_owned()),
            terminal: Some("private-terminal".to_owned()),
            module: Some("private-module".to_owned()),
            action: Some("private-action".to_owned()),
            client_identifier: Some("private-client-id".to_owned()),
            client_info: Some("private-client-info".to_owned()),
            driver_name: Some("private-driver".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let values = doctor_sensitive_values(&opts);
    for expected in [
        "dbhost:1521/private_service",
        "APP_USER",
        "super_secret",
        "MCP_PROXY",
        "APP_OWNER",
        "/home/operator/private-wallet",
        "wallet_secret",
        "CN=private-db,O=Example,C=US",
        "iam.jwt.token",
        "private-program",
        "private-machine",
        "private-os-user",
        "private-terminal",
        "private-module",
        "private-action",
        "private-client-id",
        "private-client-info",
        "private-driver",
        "private-namespace",
        "private-key",
        "private-value",
    ] {
        assert!(values.iter().any(|value| value == expected), "{values:?}");
    }
}

#[test]
fn wallet_password_ref_uses_profile_secret_resolution_policy() {
    let secret = resolve_profile_secret(
        "wallet_password_ref",
        "dev",
        Some("literal:wallet"),
        false,
        &SystemSecretResolver,
    )
    .expect("dev literal")
    .expect("secret");
    assert_eq!(secret, "wallet");

    let err = resolve_profile_secret(
        "wallet_password_ref",
        "prod",
        Some("literal:wallet"),
        true,
        &SystemSecretResolver,
    )
    .expect_err("protected literal rejected");
    assert!(err.to_string().contains("wallet_password_ref"));
    assert!(
        err.to_string()
            .contains("plaintext literal credential is forbidden")
    );
}

#[test]
fn profile_secret_resolution_errors_do_not_echo_secret_locators() {
    let err = resolve_profile_secret(
        "wallet_password_ref",
        "prod",
        Some("env:PRIVATE_WALLET_PASSWORD_NAME"),
        true,
        &SystemSecretResolver,
    )
    .expect_err("missing env var");
    let rendered = err.to_string();
    assert!(rendered.contains("wallet_password_ref"));
    assert!(rendered.contains("secret not found"));
    assert!(!rendered.contains("PRIVATE_WALLET_PASSWORD_NAME"));
    assert!(!rendered.contains("env:"));

    let err = resolve_profile_secret(
        "credential_ref",
        "prod",
        Some("noscheme-secret-ref"),
        true,
        &SystemSecretResolver,
    )
    .expect_err("malformed ref");
    let rendered = err.to_string();
    assert!(rendered.contains("credential_ref"));
    assert!(rendered.contains("malformed secret reference"));
    assert!(!rendered.contains("noscheme-secret-ref"));
}

#[test]
fn doctor_connection_error_uses_agent_envelope_message() {
    let message = doctor_connection_error(oraclemcp_db::DbError::UnsupportedAuth(
        "connection profile `missing_ro` not found".to_owned(),
    ));
    assert_eq!(message, "connection profile `missing_ro` not found");
}

#[test]
fn doctor_profile_auth_capabilities_are_metadata_only() {
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            schema_version = 1

            [[profiles]]
            name = "proxy"
            connect_string = "localhost:1521/FREEPDB1"
            username = "APP_USER"
            credential_ref = "env:ORACLE_PASSWORD"

            [profiles.proxy_auth]
            proxy_user = "APP_USER"
            target_schema = "APP_OWNER"

            [[profiles]]
            name = "iam"
            connect_string = "tcps://private.example/svc"
            username = "IAM_USER"

            [profiles.oci]
            wallet_location = "/wallets/private"
            use_iam_token = true

            [[profiles]]
            name = "external"
            connect_string = "tcps://private.example/svc"

            [profiles.oci]
            wallet_location = "/wallets/private"
            wallet_password_ref = "env:WALLET_PASSWORD"
            "#,
    )
    .expect("valid config");

    let proxy = doctor_auth_capabilities_for_profile(cfg.profile("proxy").unwrap());
    assert_eq!(proxy.selected, DoctorAuthModeKind::Proxy);
    let iam = doctor_auth_capabilities_for_profile(cfg.profile("iam").unwrap());
    assert_eq!(iam.selected, DoctorAuthModeKind::IamToken);
    let external = doctor_auth_capabilities_for_profile(cfg.profile("external").unwrap());
    assert_eq!(external.selected, DoctorAuthModeKind::ExternalWallet);

    let serialized = serde_json::to_string(&serde_json::json!([proxy, iam, external]))
        .expect("auth capabilities serialize");
    for forbidden in [
        "APP_USER",
        "APP_OWNER",
        "ORACLE_PASSWORD",
        "WALLET_PASSWORD",
        "/wallets/private",
        "private.example",
        "FREEPDB1",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "{forbidden} leaked: {serialized}"
        );
    }
    for expected in [
        "\"driver\":\"thin\"",
        "\"selected\":\"proxy\"",
        "\"selected\":\"iam_token\"",
        "\"selected\":\"external_wallet\"",
        "\"support\":\"unsupported_in_thin\"",
    ] {
        assert!(
            serialized.contains(expected),
            "{expected} missing from {serialized}"
        );
    }
}

#[test]
fn profiles_json_reports_non_secret_metadata() {
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            schema_version = 1
            default_profile = "dev"

            [[profiles]]
            name = "dev"
            description = "Development profile"
            connect_string = "localhost:1521/FREEPDB1"
            username = "APP_USER"
            credential_ref = "env:ORACLE_PASSWORD"
            max_level = "READ_ONLY"
            default_level = "READ_ONLY"
            require_signed_tools = true
            dashboard_ddl_workbench = true
            sdu = 32768

            [profiles.oci]
            wallet_location = "/wallets/private"
            wallet_password_ref = "env:WALLET_PASSWORD"
            ssl_server_cert_dn = "CN=private-db"

            [profiles.proxy_auth]
            proxy_user = "APP_USER"
            target_schema = "APP_OWNER"

            [profiles.drcp]
            pooled = true
            connection_class = "PRIVATE_CLASS"
            purity = "reuse"

            [[profiles.app_context]]
            namespace = "ORACLEMCP_CTX"
            key = "tenant_id"
            value = "tenant-123"
            "#,
    )
    .expect("valid config");

    let out = profiles_json(&cfg);
    assert_eq!(out["ok"], serde_json::json!(true));
    assert_eq!(out["profile_count"], serde_json::json!(1));
    assert_eq!(out["has_default_profile"], serde_json::json!(true));
    assert_eq!(out["profiles"][0]["name"], serde_json::json!("dev"));
    assert_eq!(out["profiles"][0]["is_default"], serde_json::json!(true));
    assert_eq!(
        out["profiles"][0]["require_signed_tools"],
        serde_json::json!(true)
    );
    assert_eq!(
        out["profiles"][0]["dashboard_ddl_workbench"],
        serde_json::json!(true)
    );
    let serialized = serde_json::to_string(&out).expect("json");
    assert!(!serialized.contains("APP_USER"));
    assert!(!serialized.contains("APP_OWNER"));
    assert!(!serialized.contains("ORACLE_PASSWORD"));
    assert!(!serialized.contains("WALLET_PASSWORD"));
    assert!(!serialized.contains("/wallets/private"));
    assert!(!serialized.contains("CN=private-db"));
    assert!(!serialized.contains("credential_ref"));
    assert!(!serialized.contains("wallet_password_ref"));
    assert!(!serialized.contains("proxy_auth"));
    assert!(!serialized.contains("target_schema"));
    assert!(!serialized.contains("PRIVATE_CLASS"));
    assert!(!serialized.contains("drcp"));
    assert!(!serialized.contains("ORACLEMCP_CTX"));
    assert!(!serialized.contains("tenant_id"));
    assert!(!serialized.contains("tenant-123"));
    assert!(!serialized.contains("app_context"));
    assert!(!serialized.contains("FREEPDB1"));
    assert!(!serialized.contains("connect_string"));
}

#[test]
fn resolved_secret_material_is_absent_from_rendered_surfaces() {
    let resolved_db_secret = "resolved-db-secret-not-in-config";
    let resolved_wallet_secret = "resolved-wallet-secret-not-in-config";
    let resolved_audit_secret = "resolved-audit-secret-not-in-config";
    let credential_ref = "keyring:prod/app";
    let wallet_ref = "file:/run/secrets/oracle-wallet";

    let cfg = OracleMcpConfig::from_toml_str(&format!(
        r#"
            schema_version = 1

            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            username = "APP_USER"
            credential_ref = "{credential_ref}"

            [profiles.oci]
            wallet_password_ref = "{wallet_ref}"
            "#
    ))
    .expect("valid config");
    let profile_json = serde_json::to_string(&profiles_json(&cfg)).expect("profile json");

    let opts = OracleConnectOptions {
        connect_string: "prod:1521/svc".to_owned(),
        username: Some("APP_USER".to_owned()),
        password: Some(resolved_db_secret.to_owned()),
        wallet_password: Some(resolved_wallet_secret.to_owned()),
        iam_token: Some("resolved-iam-token-not-in-config".to_owned()),
        ..OracleConnectOptions::default()
    };
    let options_debug = format!("{opts:?}");

    let connection_info = oraclemcp_db::OracleConnectionInfo {
        session_user: Some("APP_USER".to_owned()),
        current_schema: Some("APP".to_owned()),
        ..Default::default()
    };
    let connection_info_json = serde_json::to_string(&connection_info).expect("conn json");

    let signing_key = SigningKey::new("test-key", resolved_audit_secret.as_bytes().to_vec())
        .expect("valid test key");
    let signing_key_debug = format!("{signing_key:?}");
    let audit_record = oraclemcp_audit::AuditRecord::chained_signed(
        &oraclemcp_audit::AuditEntryDraft {
            subject: oraclemcp_audit::AuditSubject::new("subject", "hash"),
            db_evidence: None,
            cancel: None,
            tool: "oracle_query".to_owned(),
            sql: "select 1 from dual".to_owned(),
            danger_level: "READ_ONLY".to_owned(),
            decision: oraclemcp_audit::AuditDecision::Allowed,
            rows_affected: None,
            outcome: oraclemcp_audit::AuditOutcome::Succeeded,
        },
        1,
        oraclemcp_audit::GENESIS_HASH,
        "2026-06-30T00:00:00Z".to_owned(),
        &signing_key,
    );
    let audit_json = serde_json::to_string(&audit_record).expect("audit json");

    for rendered in [
        profile_json.as_str(),
        options_debug.as_str(),
        connection_info_json.as_str(),
        signing_key_debug.as_str(),
        audit_json.as_str(),
    ] {
        for forbidden in [
            resolved_db_secret,
            resolved_wallet_secret,
            resolved_audit_secret,
            "resolved-iam-token-not-in-config",
            credential_ref,
            wallet_ref,
        ] {
            assert!(
                !rendered.contains(forbidden),
                "rendered surface leaked {forbidden}: {rendered}"
            );
        }
    }
}

fn audit_record_for_db_evidence_summary(seq: u64, db_evidence: Option<DbEvidence>) -> AuditRecord {
    let key = SigningKey::new("test-key", b"db-evidence-summary-key-123456789".to_vec())
        .expect("valid test key");
    AuditRecord::chained_signed(
        &oraclemcp_audit::AuditEntryDraft {
            subject: AuditSubject::new("oauth", "subject-hash"),
            db_evidence,
            cancel: None,
            tool: "oracle_execute".to_owned(),
            sql: format!("DELETE FROM private_table WHERE secret_id = {seq}"),
            danger_level: "GUARDED".to_owned(),
            decision: oraclemcp_audit::AuditDecision::Allowed,
            rows_affected: Some(1),
            outcome: oraclemcp_audit::AuditOutcome::Succeeded,
        },
        seq,
        oraclemcp_audit::GENESIS_HASH,
        format!("2026-07-02T00:00:{seq:02}Z"),
        &key,
    )
}

#[test]
fn audit_db_evidence_summary_correlates_signed_session_tags() {
    let records = vec![
        audit_record_for_db_evidence_summary(
            1,
            Some(DbEvidence {
                availability: Some("captured".to_owned()),
                db_unique_name: Some("ORCL23A".to_owned()),
                service_name: Some("freepdb1".to_owned()),
                instance_name: Some("free".to_owned()),
                session_user: Some("APP".to_owned()),
                sid: Some("101".to_owned()),
                serial_number: Some("202".to_owned()),
                client_identifier: Some("oauth-subject".to_owned()),
                module: Some("oraclemcp-test".to_owned()),
                action: Some("execute".to_owned()),
                ..DbEvidence::default()
            }),
        ),
        audit_record_for_db_evidence_summary(2, None),
    ];

    let summary = audit_db_evidence_summary(&records);
    assert_eq!(summary.status, "correlated");
    assert_eq!(summary.records, 2);
    assert_eq!(summary.with_db_evidence, 1);
    assert_eq!(summary.captured, 1);
    assert_eq!(summary.correlated, 1);
    assert_eq!(summary.with_session_tags, 1);
    assert_eq!(summary.missing, 1);

    let payload = audit_db_evidence_payload(&summary);
    assert_eq!(payload["source"], serde_json::json!("signed_audit_records"));
    assert_eq!(payload["live_database_query"], serde_json::json!(false));
    assert_eq!(
        payload["sample_correlations"][0]["seq"],
        serde_json::json!(1)
    );
    assert_eq!(
        payload["sample_correlations"][0]["sid"],
        serde_json::json!("101")
    );
    assert_eq!(
        payload["sample_correlations"][0]["serial_number"],
        serde_json::json!("202")
    );
    let rendered = serde_json::to_string(&payload).expect("payload json");
    assert!(!rendered.contains("DELETE"));
    assert!(!rendered.contains("private_table"));
    assert!(!rendered.contains("secret_id"));
}

#[test]
fn audit_db_evidence_summary_degrades_when_evidence_unavailable() {
    let records = vec![
        audit_record_for_db_evidence_summary(1, Some(DbEvidence::unavailable("describe_failed"))),
        audit_record_for_db_evidence_summary(2, None),
    ];

    let summary = audit_db_evidence_summary(&records);
    assert_eq!(summary.status, "degraded");
    assert_eq!(summary.degraded_reason, Some("db_evidence_unavailable"));
    assert_eq!(summary.records, 2);
    assert_eq!(summary.with_db_evidence, 1);
    assert_eq!(summary.unavailable, 1);
    assert_eq!(summary.missing, 1);
    assert_eq!(summary.correlated, 0);
    assert_eq!(summary.unavailable_reasons, vec!["describe_failed"]);
    assert!(audit_db_evidence_text(&summary).contains("DEGRADED"));
}

#[test]
fn profiles_text_handles_empty_config() {
    let cfg = OracleMcpConfig::from_toml_str("").expect("empty config is valid");
    let text = profiles_text(&cfg);
    assert!(text.contains("no profiles configured"));
    assert!(text.contains("ORACLEMCP_CONFIG"));
}

#[test]
fn setup_payload_is_generic_and_client_ready() {
    let out = setup_payload(
        "tenant_ro",
        "APP_PASSWORD",
        "/opt/oraclemcp-wrapper",
        Some("/opt/oraclemcp-wrapper"),
        "/etc/oraclemcp/profiles.toml",
        "/etc/oraclemcp/tools.d",
    );
    assert_eq!(out["ok"], serde_json::json!(true));
    assert_eq!(out["kind"], serde_json::json!("oraclemcp_setup"));
    assert!(
        out["profiles_toml"]
            .as_str()
            .expect("profiles_toml")
            .contains("credential_ref = \"env:APP_PASSWORD\"")
    );
    let profiles_toml = out["profiles_toml"].as_str().expect("profiles_toml");
    let cfg = OracleMcpConfig::from_toml_str(profiles_toml).expect("setup profiles TOML parses");
    assert_eq!(cfg.default_profile.as_deref(), Some("tenant_ro"));
    let profile = cfg.profile("tenant_ro").expect("starter profile exists");
    assert_eq!(profile.max_level(), OperatingLevel::ReadOnly);
    assert_eq!(profile.default_level(), OperatingLevel::ReadOnly);
    assert!(!profiles_toml.contains("wallet_password_ref"));
    assert!(!profiles_toml.contains("[profiles.oci]"));
    assert!(!profiles_toml.contains("[profiles.drcp]"));
    assert!(!profiles_toml.contains("[profiles.proxy_auth]"));
    assert!(!profiles_toml.contains("[[profiles.app_context]]"));
    assert!(!profiles_toml.contains("[profiles.session_identity]"));
    assert_eq!(
        out["paths"]["full_profile_example"],
        serde_json::json!("oraclemcp.example.toml")
    );
    assert_eq!(
        out["claude_mcp_json"]["mcpServers"]["oracle"]["command"],
        serde_json::json!("/opt/oraclemcp-wrapper")
    );
    assert!(
        out["codex_config_toml"]
            .as_str()
            .expect("codex config")
            .contains("tenant_ro")
    );
    assert_eq!(
        out["http_client_credentials"]["serve_args"],
        serde_json::json!([
            "serve",
            "--listen",
            "127.0.0.1:7070",
            "--client-credentials",
            "--profile",
            "tenant_ro"
        ])
    );
    assert_eq!(
        out["http_client_credentials"]["claude_mcp_add"],
        serde_json::json!([
            "claude",
            "mcp",
            "add",
            "oracle",
            "--transport",
            "http",
            "http://127.0.0.1:7070/mcp"
        ])
    );
    assert!(
        out["http_client_credentials"]["secret_rule"]
            .as_str()
            .expect("secret rule")
            .contains("never in profiles.toml")
    );
    assert!(
        out["custom_tool_toml"]
            .as_str()
            .expect("custom tool template")
            .contains("oraclemcp sign-tool")
    );
    let serialized = serde_json::to_string(&out).expect("json");
    assert!(serialized.contains("dbhost.example.com"));
    assert!(!serialized.contains("literal:"));
    // Explicit wrapper flow: the payload must say the wrapper has to exist first.
    assert_eq!(
        out["paths"]["wrapper"],
        serde_json::json!("/opt/oraclemcp-wrapper")
    );
    assert!(
        out["snippet_command"]["source"]
            .as_str()
            .expect("snippet command source")
            .contains("the wrapper must exist")
    );
    assert!(serialized.contains("create the wrapper first"));
}

/// Field-test bead `.3`: without `--wrapper-path` the snippets must point at
/// the real resolved binary — never the historical `~/.local/bin/oraclemcp-local`
/// wrapper that nothing ever creates.
#[test]
fn setup_payload_default_snippets_use_the_real_binary_not_a_wrapper() {
    let binary = setup_snippet_command();
    let out = setup_payload(
        "tenant_ro",
        "APP_PASSWORD",
        &binary,
        None,
        "/etc/oraclemcp/profiles.toml",
        "/etc/oraclemcp/tools.d",
    );
    assert_eq!(
        out["claude_mcp_json"]["mcpServers"]["oracle"]["command"],
        serde_json::json!(binary)
    );
    assert!(
        out["codex_config_toml"]
            .as_str()
            .expect("codex config")
            .contains(&format!("command = {}", toml_string_encode(&binary))),
        "Codex TOML must use the same command as the Claude JSON snippet"
    );
    assert_eq!(out["paths"]["wrapper"], serde_json::Value::Null);
    assert_eq!(
        out["snippet_command"]["source"],
        serde_json::json!("resolved oraclemcp binary")
    );
    let serialized = serde_json::to_string(&out).expect("json");
    assert!(
        !serialized.contains("oraclemcp-local"),
        "default setup output must never advertise the uncreated wrapper path"
    );
    // Install hints must match the supported channels (field-test bead `.4`).
    assert!(
        out["install"]["one_line"]
            .as_str()
            .expect("one-line install")
            .contains("install.sh")
    );
    assert_eq!(
        out["install"]["self_update"],
        serde_json::json!("oraclemcp self-update")
    );
    assert_eq!(
        out["install"]["cargo_binstall"],
        serde_json::json!("cargo binstall oraclemcp")
    );
    assert!(
        out["install"]["source_build"]
            .as_str()
            .expect("source build hint")
            .starts_with("cargo +nightly-2026-05-11 install oraclemcp"),
        "source build must carry the nightly pin; plain cargo install fails on stable"
    );
    assert!(
        !serialized.contains("\"cargo install oraclemcp\""),
        "bare cargo install (stable) must not be advertised"
    );
}

/// The hand-rolled `codex_config_toml` snippet must be VALID TOML for any
/// binary path — including a Windows path whose backslashes would be treated as
/// (invalid) escapes in a basic double-quoted string, and a path containing a
/// literal quote. Regression for the 2026-07 bug hunt A1 finding.
#[test]
fn codex_config_toml_is_valid_toml_for_awkward_paths() {
    for (label, command) in [
        ("windows backslash path", r"C:\Users\alice\oraclemcp.exe"),
        ("unix path", "/usr/local/bin/oraclemcp"),
        ("path with spaces", "/opt/My Tools/oraclemcp"),
        ("path with a single quote", "/opt/o'brien/oraclemcp"),
        ("path with a double quote", "/opt/wat\"quote/oraclemcp"),
    ] {
        let out = setup_payload(
            "tenant_ro",
            "APP_PASSWORD",
            command,
            None,
            "/etc/oraclemcp/profiles.toml",
            "/etc/oraclemcp/tools.d",
        );
        let snippet = out["codex_config_toml"].as_str().expect("codex config");
        let parsed: toml::Value = toml::from_str(snippet)
            .unwrap_or_else(|e| panic!("codex TOML must parse ({label}): {e}\n{snippet}"));
        // The parsed command must equal the exact input path (no escape mangling).
        assert_eq!(
            parsed["mcp_servers"]["oracle"]["command"].as_str(),
            Some(command),
            "round-trip command mismatch for {label}"
        );
    }
}

/// `toml_string_encode` prefers a literal for backslash paths and escapes only
/// when a single-quote / control char forces a basic string.
#[test]
fn toml_string_encode_prefers_literal_then_escapes() {
    assert_eq!(toml_string_encode(r"C:\x\y"), r"'C:\x\y'");
    assert_eq!(toml_string_encode("/usr/bin/x"), "'/usr/bin/x'");
    // A single quote cannot live in a literal → escaped basic string.
    assert_eq!(toml_string_encode("o'brien"), "\"o'brien\"");
    // In the basic-string fallback, backslashes are doubled.
    assert_eq!(toml_string_encode("a'b\\c"), "\"a'b\\\\c\"");
}

#[test]
fn json_alias_is_accepted_before_and_after_subcommand() {
    let before = Cli::try_parse_from(["oraclemcp", "--json", "profiles"]).expect("parse");
    assert!(before.robot_json);
    assert!(matches!(before.command, Some(Command::Profiles)));

    let after = Cli::try_parse_from(["oraclemcp", "profiles", "--json"]).expect("parse");
    assert!(after.robot_json);
    assert!(matches!(after.command, Some(Command::Profiles)));
}

#[test]
fn setup_and_sign_tool_commands_parse() {
    let setup = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "setup",
        "--write",
        "--profile",
        "tenant_ro",
        "--credential-env",
        "APP_PASSWORD",
    ])
    .expect("parse setup");
    assert!(setup.robot_json);
    assert!(matches!(
        setup.command,
        Some(Command::Setup {
            write: true,
            ref profile,
            ref credential_env,
            ..
        }) if profile == "tenant_ro" && credential_env == "APP_PASSWORD"
    ));

    let self_update = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "self-update",
        "--dry-run",
        "--version",
        "0.6.6",
        "--verify",
        "require",
        "--no-service",
    ])
    .expect("parse self-update");
    assert!(self_update.robot_json);
    assert!(matches!(
        self_update.command,
        Some(Command::SelfUpdate(SelfUpdateCliArgs {
            ref version,
            ref verify,
            dry_run: true,
            no_service: true,
            ..
        })) if version == "0.6.6" && verify.as_deref() == Some("require")
    ));

    let sign = Cli::try_parse_from([
        "oraclemcp",
        "sign-tool",
        "tools.toml",
        "--tool",
        "app_lookup",
    ])
    .expect("parse sign-tool");
    assert!(matches!(
        sign.command,
        Some(Command::SignTool {
            ref path,
            ref tool,
        }) if path == Path::new("tools.toml") && tool.as_deref() == Some("app_lookup")
    ));
}

#[test]
fn audit_verify_with_db_evidence_command_parses() {
    let audit = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "audit",
        "verify",
        "audit.jsonl",
        "--with-db-evidence",
    ])
    .expect("parse audit verify");
    assert!(audit.robot_json);
    assert!(matches!(
        audit.command,
        Some(Command::Audit {
            command: AuditCommand::Verify {
                ref file,
                key_id: None,
                with_db_evidence: true,
            }
        }) if file == Path::new("audit.jsonl")
    ));
}

#[test]
fn dashboard_command_parses() {
    let dashboard = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "dashboard",
        "--url",
        "http://127.0.0.1:7777",
        "--no-open",
    ])
    .expect("parse dashboard");
    assert!(dashboard.robot_json);
    assert!(matches!(
        dashboard.command,
        Some(Command::Dashboard {
            ref url,
            no_open: true,
        }) if url == "http://127.0.0.1:7777"
    ));
}

#[test]
fn om_alias_argv0_aware_parses_dashboard_help() {
    assert_eq!(
        display_binary_name_from_argv0(Some(std::ffi::OsStr::new("/usr/local/bin/om"))),
        "om"
    );
    assert_eq!(
        display_binary_name_from_argv0(Some(std::ffi::OsStr::new("OM.exe"))),
        "om"
    );
    assert_eq!(
        display_binary_name_from_argv0(Some(std::ffi::OsStr::new("/usr/local/bin/oraclemcp",))),
        "oraclemcp"
    );
    assert_eq!(display_binary_name_from_argv0(None), "oraclemcp");

    let matches = cli_command("om")
        .try_get_matches_from([
            "om",
            "--json",
            "dashboard",
            "--url",
            "http://127.0.0.1:7777",
            "--no-open",
        ])
        .expect("parse om dashboard");
    let dashboard = Cli::from_arg_matches(&matches).expect("build cli from alias matches");
    assert!(dashboard.robot_json);
    assert!(matches!(
        dashboard.command,
        Some(Command::Dashboard {
            ref url,
            no_open: true,
        }) if url == "http://127.0.0.1:7777"
    ));

    let mut help = Vec::new();
    cli_command("om")
        .write_long_help(&mut help)
        .expect("render om help");
    let help = String::from_utf8(help).expect("help is utf8");
    assert!(help.contains("Usage: om "));
    assert!(!help.contains("Usage: oraclemcp"));
    assert!(bare_invocation_hint("om").contains("`om serve`"));
    assert!(bare_invocation_hint("om").contains("`om doctor`"));
    assert!(bare_invocation_hint("om").contains("`om capabilities`"));
}

#[test]
fn service_commands_parse() {
    let install = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "service",
        "install",
        "--dry-run",
        "--listen",
        "127.0.0.1:7070",
        "--profile",
        "dev_ro",
        "--allow-no-auth",
        "--client-credentials",
        "--skip-linger",
    ])
    .expect("parse service install");
    assert!(install.robot_json);
    assert!(matches!(
        install.command,
        Some(Command::Service {
            command: ServiceCliCommand::Install(ServiceInstallCliArgs {
                ref listen,
                ref profile,
                allow_no_auth: true,
                client_credentials: true,
                skip_linger: true,
                dry_run: true,
                ..
            })
        }) if listen == "127.0.0.1:7070" && profile.as_deref() == Some("dev_ro")
    ));

    let uninstall = Cli::try_parse_from(["oraclemcp", "service", "uninstall", "--yes"])
        .expect("parse service uninstall");
    assert!(matches!(
        uninstall.command,
        Some(Command::Service {
            command: ServiceCliCommand::Uninstall(ServiceMutationCliArgs { yes: true, .. })
        })
    ));

    let status =
        Cli::try_parse_from(["oraclemcp", "service", "status"]).expect("parse service status");
    assert!(matches!(
        status.command,
        Some(Command::Service {
            command: ServiceCliCommand::Status(ServiceReadCliArgs { .. })
        })
    ));

    let logs = Cli::try_parse_from(["oraclemcp", "service", "logs", "--lines", "25"])
        .expect("parse service logs");
    assert!(matches!(
        logs.command,
        Some(Command::Service {
            command: ServiceCliCommand::Logs(ServiceLogsCliArgs { lines: 25, .. })
        })
    ));

    let restart = Cli::try_parse_from(["oraclemcp", "service", "restart", "--dry-run"])
        .expect("parse service restart");
    assert!(matches!(
        restart.command,
        Some(Command::Service {
            command: ServiceCliCommand::Restart(ServiceMutationCliArgs { dry_run: true, .. })
        })
    ));

    let backup = Cli::try_parse_from([
        "oraclemcp",
        "service",
        "backup",
        "--output",
        "/tmp/oraclemcp-backup",
        "--dry-run",
    ])
    .expect("parse service backup");
    assert!(matches!(
        backup.command,
        Some(Command::Service {
            command: ServiceCliCommand::Backup(ServiceBackupCliArgs {
                ref output,
                dry_run: true,
                ..
            })
        }) if output.as_deref() == Some(Path::new("/tmp/oraclemcp-backup"))
    ));

    let restore = Cli::try_parse_from([
        "oraclemcp",
        "service",
        "restore",
        "/tmp/oraclemcp-backup",
        "--key_id",
        "2026-q2",
        "--dry-run",
    ])
    .expect("parse service restore");
    assert!(matches!(
        restore.command,
        Some(Command::Service {
            command: ServiceCliCommand::Restore(ServiceRestoreCliArgs {
                ref backup,
                ref key_id,
                dry_run: true,
                ..
            })
        }) if backup == Path::new("/tmp/oraclemcp-backup")
            && key_id.as_deref() == Some("2026-q2")
    ));
}

#[test]
fn client_credential_commands_parse() {
    let issue = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "clients",
        "issue",
        "--label",
        "Claude Desktop",
        "--scope",
        "oracle:read",
        "--scope",
        "oracle:execute",
    ])
    .expect("parse client issue");
    assert!(issue.robot_json);
    assert!(matches!(
        issue.command,
        Some(Command::Clients {
            command: ClientCredentialCliCommand::Issue(ClientCredentialIssueCliArgs {
                ref label,
                ref scopes,
            })
        }) if label == "Claude Desktop"
            && scopes == &vec!["oracle:read".to_owned(), "oracle:execute".to_owned()]
    ));

    let issue_default_scope =
        Cli::try_parse_from(["oraclemcp", "clients", "issue", "--label", "Claude Desktop"])
            .expect("parse client issue with default scope");
    assert!(matches!(
        issue_default_scope.command,
        Some(Command::Clients {
            command: ClientCredentialCliCommand::Issue(ClientCredentialIssueCliArgs {
                ref scopes,
                ..
            })
        }) if scopes == &vec!["oracle:read".to_owned()]
    ));

    let rotate = Cli::try_parse_from([
        "oraclemcp",
        "client-credentials",
        "rotate",
        "client-0123456789abcdef0123456789abcdef",
    ])
    .expect("parse client rotate");
    assert!(matches!(
        rotate.command,
        Some(Command::Clients {
            command: ClientCredentialCliCommand::Rotate(ClientCredentialIdCliArgs {
                ref client_id,
            })
        }) if client_id == "client-0123456789abcdef0123456789abcdef"
    ));

    let revoke = Cli::try_parse_from([
        "oraclemcp",
        "clients",
        "revoke",
        "client-0123456789abcdef0123456789abcdef",
    ])
    .expect("parse client revoke");
    assert!(matches!(
        revoke.command,
        Some(Command::Clients {
            command: ClientCredentialCliCommand::Revoke(ClientCredentialIdCliArgs {
                ref client_id,
            })
        }) if client_id == "client-0123456789abcdef0123456789abcdef"
    ));
}

#[test]
fn robot_docs_guide_is_available_with_or_without_guide_subcommand() {
    let bare = Cli::try_parse_from(["oraclemcp", "robot-docs"]).expect("parse");
    assert!(matches!(
        bare.command,
        Some(Command::RobotDocs { command: None })
    ));

    let explicit = Cli::try_parse_from(["oraclemcp", "robot-docs", "guide"]).expect("parse");
    assert!(matches!(
        explicit.command,
        Some(Command::RobotDocs {
            command: Some(RobotDocsCommand::Guide)
        })
    ));
}

#[test]
fn agent_ergonomics_drift_guard_pins_capabilities_schema() {
    let out = capabilities_payload();
    for key in [
        "server_name",
        "server_version",
        "protocol_version",
        "tools",
        "operating_level",
        "transports",
        "connection",
        "features",
        "cli_contract",
        "mcp_cli_dashboard_parity",
    ] {
        assert!(out.get(key).is_some(), "missing capabilities key {key}");
    }
    assert_eq!(
        out["cli_contract"]["contract_version"],
        serde_json::json!(1)
    );
    assert_eq!(
        out["cli_contract"]["structured_output"]["alias"],
        serde_json::json!("--json")
    );
    assert_eq!(
        out["cli_contract"]["binary_names"],
        serde_json::json!(["oraclemcp", "om"])
    );

    let exit_codes = out["cli_contract"]["exit_codes"]
        .as_array()
        .expect("exit code dictionary");
    for code in [0, 1, 2, 3, 4] {
        assert!(
            exit_codes
                .iter()
                .any(|entry| entry["code"] == serde_json::json!(code)),
            "missing exit code {code}: {exit_codes:?}"
        );
    }
    assert!(
        serde_json::to_string(&out["cli_contract"])
            .expect("json")
            .contains("--dry-run")
    );

    let parity = out["mcp_cli_dashboard_parity"]["matrix"]
        .as_array()
        .expect("parity matrix");
    assert_eq!(parity.len(), 7);
    for id in [
        "discovery",
        "profile_inventory",
        "diagnostics",
        "guarded_sql",
        "schema_explorer",
        "service_and_auth",
        "audit",
    ] {
        let row = parity
            .iter()
            .find(|row| row["id"] == serde_json::json!(id))
            .unwrap_or_else(|| panic!("missing parity row {id}: {parity:?}"));
        assert_eq!(row["status"], serde_json::json!("aligned"));
        for face in ["cli", "mcp", "dashboard"] {
            assert!(
                row[face]
                    .as_array()
                    .is_some_and(|values| !values.is_empty()),
                "{id} has no {face} surface"
            );
        }
    }
}

#[test]
fn agent_ergonomics_drift_guard_pins_help_footer() {
    for binary_name in ["oraclemcp", "om"] {
        let mut help = Vec::new();
        cli_command(binary_name)
            .write_long_help(&mut help)
            .expect("render help");
        let help = String::from_utf8(help).expect("help utf8");
        assert!(help.contains(&format!("Usage: {binary_name} ")));
        assert!(help.contains("Agent surfaces:"));
        assert!(help.contains("--json"));
        assert!(help.contains("oraclemcp --json capabilities"));
        assert!(help.contains("oraclemcp robot-docs guide"));
        assert!(help.contains("oraclemcp --json service install --dry-run"));
        assert!(help.contains("service mutations require --yes"));
    }
}

#[test]
fn robot_docs_guide_outputs_agent_workflows() {
    let text = robot_docs::robot_docs_guide_text();
    assert!(text.contains("oraclemcp robot-docs guide"));
    assert!(text.contains("oracle_preview_sql"));
    assert!(text.contains("oracle_execute"));
    assert!(text.contains("READ_ONLY < READ_WRITE < DDL < ADMIN"));

    let out = robot_docs::robot_docs_guide_json();
    assert_eq!(out["ok"], serde_json::json!(true));
    assert_eq!(
        out["structured_output"]["alias"],
        serde_json::json!("--json")
    );
    assert_eq!(
        out["cli_contract"]["exit_codes"][4]["code"],
        serde_json::json!(4)
    );
    assert_eq!(
        out["mcp_cli_dashboard_parity"]["status"],
        serde_json::json!("aligned")
    );
    assert!(text.contains("MCP / CLI / dashboard parity"));
    assert!(text.contains("Exit codes: 0 success"));
    assert!(text.contains("Client smoke tests"));
    assert!(text.contains("oraclemcp --json setup --profile <profile>"));
    assert!(text.contains("Always-on service"));
    assert!(text.contains("oraclemcp --json service install --dry-run --profile <profile>"));
    assert!(
        text.contains("oraclemcp service install --yes --client-credentials --profile <profile>")
    );
    assert!(text.contains("Thin diagnostics"));
    assert!(text.contains("does not need Oracle Instant Client"));
    assert!(text.contains("Result materialization"));
    assert!(
        serde_json::to_string(&out)
            .expect("json")
            .contains("custom_tool_signing")
    );
    assert!(text.contains("MCP tools/list"));
    assert_eq!(
        out["tool_schema_contract"]["strict_client_safe"],
        serde_json::json!(
            "tool parameter schemas avoid top-level oneOf, anyOf, allOf, enum, and not"
        )
    );
    assert_eq!(
        out["client_setup"]["stdio"]["argv"],
        serde_json::json!([
            "oraclemcp",
            "serve",
            "--profile",
            "<profile>",
            "--allow-no-auth"
        ])
    );
    assert_eq!(
        out["client_setup"]["smoke_tests"][1]["mcp_method"],
        serde_json::Value::Null
    );
    assert_eq!(
        out["client_setup"]["smoke_tests"][2]["mcp_method"],
        serde_json::json!("tools/list")
    );
    assert_eq!(
        out["diagnostic_flow"][5]["argv"],
        serde_json::json!(["oraclemcp", "--json", "capabilities"])
    );
    assert_eq!(
        out["diagnostic_flow"][6]["argv"],
        serde_json::json!(["oraclemcp", "--json", "service", "status"])
    );
    assert_eq!(
        out["first_commands"][0]["argv"],
        serde_json::json!(["oraclemcp", "--json", "setup", "--profile", "<profile>"])
    );
    assert_eq!(
        out["first_commands"][1]["argv"],
        serde_json::json!(["oraclemcp", "--json", "profiles"])
    );
    assert_eq!(
        out["first_commands"][3]["argv"],
        serde_json::json!([
            "oraclemcp",
            "--json",
            "doctor",
            "--online",
            "--profile",
            "<profile>"
        ])
    );
    assert_eq!(
        out["first_commands"][5]["argv"],
        serde_json::json!([
            "oraclemcp",
            "--json",
            "service",
            "install",
            "--dry-run",
            "--profile",
            "<profile>"
        ])
    );
    assert_eq!(
        out["client_setup"]["service"]["status"]["argv"],
        serde_json::json!(["oraclemcp", "--json", "service", "status"])
    );
    assert_eq!(
        out["safety_model"]["levels"],
        serde_json::json!(["READ_ONLY", "READ_WRITE", "DDL", "ADMIN"])
    );
    assert_eq!(
        out["thin_diagnostics"]["driver"],
        serde_json::json!(
            "pure-Rust oracledb thin driver; no Oracle Instant Client, ODPI-C, libclntsh, or C toolchain required"
        )
    );
    assert!(
        out["thin_diagnostics"]["secret_handling"]
            .as_str()
            .expect("secret handling text")
            .contains("wallet paths")
    );
    assert!(
        out["result_materialization"]["ref_cursors"]
            .as_str()
            .expect("ref cursor text")
            .contains("nested result objects")
    );
    assert!(
        serde_json::to_string(&out)
            .expect("json")
            .contains("oracle_preview_sql")
    );
}

fn custom_def(name: &str) -> CustomToolDef {
    CustomToolDef {
        name: name.to_owned(),
        description: "Test custom tool".to_owned(),
        sql: Some("SELECT 1 FROM dual".to_owned()),
        call: None,
        params: Vec::new(),
        output_mode: oraclemcp_core::OutputMode::Rows,
        declared_level: None,
        signature: None,
    }
}

#[test]
fn custom_tool_names_cannot_duplicate_or_shadow_advertised_tools() {
    let err = validate_custom_tool_names(&[custom_def("app_lookup"), custom_def("app_lookup")])
        .expect_err("duplicate custom names rejected");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert!(err.message.contains("duplicate custom tool name"));

    let err = validate_custom_tool_names(&[custom_def("query")])
        .expect_err("compatibility alias collision rejected");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert!(err.message.contains("collides"));
}

#[test]
fn production_loader_rejects_form_b_package_calls() {
    // QA100 .65: Form B (`call = ...`) is not a supported execution mode. The
    // production catalog loader must refuse it at load with an actionable error,
    // never register a tool that could never execute (accepted config ==
    // behavior). Even a well-formed, unsigned definition on an unprotected
    // profile is rejected.
    let tools_dir = target_tmp_file("qa100-65-form-b");
    fs::create_dir_all(&tools_dir).expect("create tools dir");
    fs::write(
        tools_dir.join("form_b.toml"),
        r#"
        [[tool]]
        name = "myco_billing"
        description = "Wrap the billing package"
        call = "billing_api.get_summary(:acct)"
        [[tool.params]]
        name = "acct"
        type = "string"
        required = true
        "#,
    )
    .expect("write form-b tool");
    let err = load_custom_catalog_from_sources(Some(&tools_dir), None, false)
        .expect_err("form B must be rejected by the production loader");
    assert!(
        err.message.contains("Form B"),
        "unexpected error: {}",
        err.message
    );

    // Form A on the same loader still loads and advertises.
    fs::write(
        tools_dir.join("form_b.toml"),
        r#"
        [[tool]]
        name = "myco_billing"
        description = "Read the billing summary"
        sql = "SELECT amount FROM billing_summary_v WHERE acct = :acct"
        [[tool.params]]
        name = "acct"
        type = "string"
        required = true
        "#,
    )
    .expect("rewrite as form A");
    let catalog =
        load_custom_catalog_from_sources(Some(&tools_dir), None, false).expect("form A loads");
    assert_eq!(catalog.len(), 1);
}

#[test]
fn custom_tool_catalog_and_sign_cli_enforce_hmac_key_size() {
    let tools_dir = target_tmp_file("qa2-custom-tool-keys");
    fs::create_dir_all(&tools_dir).expect("create tools dir");
    let tool_path = tools_dir.join("qa2.toml");
    fs::write(
        &tool_path,
        r#"
        [[tool]]
        name = "qa2_lookup"
        description = "QA2 signed lookup"
        sql = "SELECT 1 FROM dual"
        output_mode = "rows"
        "#,
    )
    .expect("write unsigned custom tool");

    for len in [0, 1, 31] {
        let secret = if len == 1 {
            "\n".to_owned()
        } else {
            "C".repeat(len)
        };
        let catalog_error = load_custom_catalog_from_sources(Some(&tools_dir), Some(&secret), true)
            .expect_err("undersized custom-tool load key must fail closed");
        assert!(
            catalog_error.message.contains(&format!("{len} bytes")),
            "{}",
            catalog_error.message
        );
        if len == 31 {
            assert!(!catalog_error.message.contains(&secret));
        }

        let sign_error = custom_tool_signatures_with_key(&tool_path, None, &secret)
            .expect_err("undersized sign-tool key must fail closed");
        assert!(
            sign_error.message.contains(&format!("{len} bytes")),
            "{}",
            sign_error.message
        );
        if len == 31 {
            assert!(!sign_error.message.contains(&secret));
        }
    }

    for len in [32, 33] {
        let secret = "C".repeat(len);
        let key = HmacSha256Key::new(secret.as_bytes().to_vec()).expect("valid custom-tool key");
        let def = custom_def("qa2_lookup");
        let signature = sign(&def, &key);
        fs::write(
            &tool_path,
            format!(
                r#"
                [[tool]]
                name = "qa2_lookup"
                description = "Test custom tool"
                sql = "SELECT 1 FROM dual"
                output_mode = "rows"
                signature = "{signature}"
                "#
            ),
        )
        .expect("write signed custom tool");

        assert_eq!(
            load_custom_catalog_from_sources(Some(&tools_dir), Some(&secret), true)
                .expect("minimum-size custom-tool load key is valid")
                .len(),
            1
        );
        let payload = custom_tool_signatures_with_key(&tool_path, None, &secret)
            .expect("minimum-size sign-tool key is valid");
        assert_eq!(payload["signatures"].as_array().map(Vec::len), Some(1));
    }
}

#[test]
fn reloaded_generation_enforces_its_own_custom_tool_signature_policy() {
    let tools_dir = target_tmp_file("generation-tools");
    fs::create_dir_all(&tools_dir).expect("create tools dir");
    fs::write(
        tools_dir.join("unsigned.toml"),
        r#"
        [[tool]]
        name = "app_lookup"
        description = "Unsigned read-only lookup"
        sql = "SELECT 1 FROM dual"
        output_mode = "rows"
        "#,
    )
    .expect("write unsigned tool");
    let before = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "prod"
        connect_string = "prod:1521/svc"
        require_signed_tools = false
        "#,
    )
    .expect("before config");
    let after = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "prod"
        connect_string = "prod:1521/svc"
        require_signed_tools = true
        "#,
    )
    .expect("after config");
    let level = default_read_only_level();
    let state = ProfileDrainState::from_config(before.clone());
    let old = match state.admit_mcp_profile("prod", true) {
        oraclemcp::dispatch::ProfileGenerationAdmission::Ready(lease) => lease,
        other => panic!("old generation was not admitted: {other:?}"),
    };
    let old_requires_signatures = custom_tools_require_signatures(
        old.config().expect("old accepted config"),
        Some(old.profile()),
        &level,
    )
    .expect("old policy");
    assert!(!old_requires_signatures);
    assert_eq!(
        load_custom_catalog_from_sources(Some(&tools_dir), None, old_requires_signatures,)
            .expect("old generation admits unsigned read-only tool")
            .len(),
        1
    );

    let plan = oraclemcp_config::ConfigReloadPlan::between(&before, &after);
    assert!(plan.hot_reloadable);
    state
        .apply_config_reload_plan(&plan, &before, &after)
        .expect("signature policy reload applies");
    let new = match state.admit_mcp_profile("prod", true) {
        oraclemcp::dispatch::ProfileGenerationAdmission::Ready(lease) => lease,
        other => panic!("new generation was not admitted: {other:?}"),
    };
    assert!(old.is_draining());
    assert!(!new.is_draining());
    let new_requires_signatures = custom_tools_require_signatures(
        new.config().expect("new accepted config"),
        Some(new.profile()),
        &level,
    )
    .expect("new policy");
    assert!(new_requires_signatures);
    let error = load_custom_catalog_from_sources(Some(&tools_dir), None, new_requires_signatures)
        .expect_err("new generation refuses unsigned catalog without signing key");
    assert!(error.message.contains(CUSTOM_TOOLS_HMAC_KEY_ENV));
}

#[test]
fn build_server_advertises_the_active_custom_catalog_plus_capabilities() {
    let defs = oraclemcp_core::parse_tools_file(
        r#"
            [[tool]]
            name = "startup_custom"
            description = "Startup catalog marker"
            sql = "SELECT 1 FROM dual"
        "#,
    )
    .expect("custom tool parses");
    let custom_catalog = CustomToolCatalog::new(
        oraclemcp_core::load_tools(
            &defs,
            &Classifier::new(ClassifierConfig::new()),
            OperatingLevel::ReadOnly,
        )
        .expect("custom tool loads"),
    );
    let conn = open_connection(OracleConnectOptions::default());
    let server = build_server(
        conn,
        None,
        None,
        default_read_only_level(),
        ServerBuildOptions {
            transport: ServerTransportMode::Stdio,
            custom_catalog,
            auditor: None,
            write_intents: None,
            secret_resolver: Arc::new(SystemSecretResolver),
            request_timeout: OracleConnectOptions::default().call_timeout,
            max_query_cost: None,
            metrics: None,
            profile_drain: ProfileDrainState::default(),
        },
    );
    // The capabilities report carries the registry's tools.
    let caps = registry::capabilities(env!("CARGO_PKG_VERSION"), LIVE_DB, false);
    assert_eq!(caps.tools.len(), registry::tool_names().len());
    let listed = server
        .handle_jsonrpc_request(
            serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"}),
            None,
        )
        .expect("tools/list response");
    let listed_tools = listed["result"]["tools"].as_array().expect("tools array");
    assert!(
        listed_tools
            .iter()
            .any(|tool| tool["name"] == serde_json::json!("startup_custom")),
        "startup custom catalog must come from the dispatch surface"
    );
    // The meta-dispatch fan-out tool is never registered: first-class is the
    // only custom-tool registration mode in production (QA100 .65).
    assert!(
        !listed_tools
            .iter()
            .any(|tool| tool["name"] == serde_json::json!("oracle_run_named")),
        "meta-dispatch surface must not be advertised"
    );
    // Smoke: the server clones (it is Clone) — proves it is fully built.
    let _ = server.clone();
}

// ---- K4: bounded reason_class + operating_level labels on the blocked counter ----

#[test]
fn blocked_labels_bucket_reason_class_and_required_level() {
    use oraclemcp_error::{ErrorEnvelope, ReasonCategory, StructuredReason};

    // Capacity backpressure: bucketed as `capacity`, no level context -> `n/a`.
    let busy: DispatchOutcome = asupersync::Outcome::Err(ErrorEnvelope::new(ErrorClass::Busy, "x"));
    assert_eq!(blocked_labels(&busy), Some(("capacity", "n/a")));

    // A level gate carries the required level from the K8 structured reason.
    let gated: DispatchOutcome = asupersync::Outcome::Err(
        ErrorEnvelope::new(ErrorClass::OperatingLevelTooLow, "needs a higher level")
            .with_structured_reason(
                StructuredReason::new(ReasonCategory::RequiresHigherLevel)
                    .with_required_level("READ_WRITE"),
            ),
    );
    assert_eq!(
        blocked_labels(&gated),
        Some(("operating_level", "READ_WRITE"))
    );

    // A classifier refusal with no level context.
    let forbidden: DispatchOutcome = asupersync::Outcome::Err(ErrorEnvelope::new(
        ErrorClass::ForbiddenStatement,
        "refused",
    ));
    assert_eq!(blocked_labels(&forbidden), Some(("classifier", "n/a")));

    // A non-blocking error yields no blocked-counter labels.
    let other: DispatchOutcome =
        asupersync::Outcome::Err(ErrorEnvelope::new(ErrorClass::ObjectNotFound, "x"));
    assert_eq!(blocked_labels(&other), None);

    // An out-of-range level is clamped to `n/a` so cardinality stays bounded.
    let weird: DispatchOutcome = asupersync::Outcome::Err(
        ErrorEnvelope::new(ErrorClass::ForbiddenStatement, "x").with_structured_reason(
            StructuredReason::new(ReasonCategory::Other).with_required_level("WAT"),
        ),
    );
    assert_eq!(blocked_labels(&weird), Some(("classifier", "n/a")));
}
