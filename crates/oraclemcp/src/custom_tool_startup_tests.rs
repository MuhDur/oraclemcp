//! Startup parsing/signing is exercised through the production catalog loader.
use super::*;

#[test]
fn signed_structured_startup_retains_pending_tools_and_rejects_pin_tampering() {
    let key_text = "0123456789abcdef0123456789abcdef";
    let key = HmacSha256Key::new(key_text.as_bytes().to_vec()).unwrap();
    let text = format!(
        r#"[[tool]]
name = "app_increment"
description = "Signed structured startup fixture"
closure_sha256 = "{}"
routine = {{ owner="APP", package="PKG", member="INC", subprogram_id=1 }}
args = [{{oracle_type="NUMBER",direction="RETURN",bind_name="result"}},{{oracle_name="PX",oracle_type="NUMBER",direction="IN",bind_name="x"}}]
params = [{{name="x",type="integer",required=true}}]
"#,
        "a".repeat(64)
    );
    let definition = oraclemcp_core::parse_tools_file(&text).unwrap().remove(0);
    let signature = oraclemcp_core::sign(&definition, &key);
    let text = format!("{text}signature = \"{signature}\"\n");
    let dir = target_tmp_file("package-startup");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("signed.toml");
    fs::write(&path, &text).unwrap();
    let catalog =
        load_custom_catalog_from_sources(Some(&dir), Some(key_text), false, OperatingLevel::Ddl)
            .unwrap();
    assert!(
        catalog.is_empty(),
        "startup signatures cannot grant live activation"
    );
    assert_eq!(catalog.pending().len(), 1);
    let mut registry = oraclemcp_core::ToolRegistry::new();
    catalog.register_first_class(&mut registry);
    assert!(
        registry.tools.is_empty(),
        "pending definitions must not be advertised"
    );
    fs::write(&path, text.replace(&"a".repeat(64), &"b".repeat(64))).unwrap();
    let error =
        load_custom_catalog_from_sources(Some(&dir), Some(key_text), false, OperatingLevel::Ddl)
            .unwrap_err();
    assert!(
        error.message.contains("invalid HMAC signature"),
        "{error:?}"
    );
}

#[test]
fn unsigned_write_is_rejected_by_the_production_startup_loader() {
    let dir = target_tmp_file("package-unsigned-write");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("write.toml"),
        r#"[[tool]]
name="app_update"
description="Unsigned write fixture"
sql="UPDATE APP.T SET C = 1"
"#,
    )
    .unwrap();
    let error = load_custom_catalog_from_sources(
        Some(&dir),
        Some("0123456789abcdef0123456789abcdef"),
        false,
        OperatingLevel::ReadWrite,
    )
    .unwrap_err();
    assert!(error.message.contains("is unsigned;"), "{error:?}");
}

#[test]
fn custom_tool_loader_uses_each_profiles_real_ceiling() {
    let tools_dir = target_tmp_file("b12b-custom-tool-ceilings");
    fs::create_dir_all(&tools_dir).expect("create tools dir");
    let tool_path = tools_dir.join("guarded.toml");

    // Signed static DML must still use the selected profile's actual ceiling.
    let secret = "0123456789abcdef0123456789abcdef";
    let key = HmacSha256Key::new(secret.as_bytes().to_vec()).expect("valid signing key");
    let config = r#"
        [[tool]]
        name = "app_bump"
        description = "Update one status"
        sql = "UPDATE accounts SET status = 'ACTIVE' WHERE id = 7"
        output_mode = "rows"
        "#;
    let definition = oraclemcp_core::parse_tools_file(config).unwrap().remove(0);
    fs::write(
        &tool_path,
        format!("{config}\nsignature = \"{}\"\n", sign(&definition, &key)),
    )
    .expect("write signed guarded tool");

    let profile_ceiling = |max_level: &str| {
        let config = OracleMcpConfig::from_toml_str(&format!(
            r#"
            [[profiles]]
            name = "custom_tool_profile"
            connect_string = "db:1521/service"
            max_level = "{max_level}"
            "#
        ))
        .expect("profile config parses");
        let profile = config
            .profile("custom_tool_profile")
            .expect("profile exists");
        oraclemcp_core::session_level_state(profile, false).max_level()
    };

    for (profile_max, should_load) in [
        ("READ_ONLY", false),
        ("READ_WRITE", true),
        ("DDL", true),
        ("ADMIN", true),
    ] {
        let result = load_custom_catalog_from_sources(
            Some(&tools_dir),
            Some(secret),
            false,
            profile_ceiling(profile_max),
        );
        if should_load {
            assert_eq!(
                result
                    .expect("tool must load at the profile's real ceiling")
                    .len(),
                1,
                "{profile_max} profile should load its READ_WRITE custom tool"
            );
        } else {
            let error = result.expect_err("READ_ONLY profile must refuse a write tool");
            assert!(
                error.message.contains("profile ceiling is READ_ONLY"),
                "unexpected error: {}",
                error.message
            );
        }
    }

    // The signed path must report the selected profile's real ceiling too.
    // A declaration can only raise a classifier-derived floor, so this remains
    // a fail-closed test without requiring executable DDL in the fixture.
    let mut signed = custom_def("app_schema_report");
    signed.declared_level = Some("DDL".to_owned());
    signed.signature = Some(sign(&signed, &key));
    fs::write(
        &tool_path,
        format!(
            r#"
            [[tool]]
            name = "{}"
            description = "{}"
            sql = "{}"
            output_mode = "rows"
            declared_level = "DDL"
            signature = "{}"
            "#,
            signed.name,
            signed.description,
            signed.sql.as_deref().expect("inline SQL"),
            signed.signature.as_deref().expect("signature"),
        ),
    )
    .expect("write signed DDL-pinned tool");

    let error = load_custom_catalog_from_sources(
        Some(&tools_dir),
        Some(secret),
        true,
        profile_ceiling("READ_WRITE"),
    )
    .expect_err("signed DDL-pinned tool must not load above the profile ceiling");
    assert!(error.message.contains("requires DDL"), "{error:?}");
    assert!(
        error.message.contains("profile ceiling is READ_WRITE"),
        "signed-tool refusal must name the real profile ceiling: {error:?}"
    );
    assert_eq!(
        load_custom_catalog_from_sources(
            Some(&tools_dir),
            Some(secret),
            true,
            profile_ceiling("DDL")
        )
        .expect("signed DDL-pinned tool loads at DDL")
        .len(),
        1
    );
}
