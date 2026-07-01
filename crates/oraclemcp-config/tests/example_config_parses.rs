//! Guard test: the shipped, fully annotated `oraclemcp.example.toml` at the
//! workspace root must parse AND validate through the real config loader. This
//! is what keeps the worked example (the copy-pasteable config + the canonical
//! field reference it backs in `docs/configuration.md`) from silently rotting
//! when a field is renamed, a default changes, or validation tightens — a stale
//! example would fail this test instead of misleading an operator.

use std::path::PathBuf;

use oraclemcp_config::{OperatingLevel, OracleMcpConfig};

/// Resolve the workspace-root example from this crate's manifest dir.
/// `CARGO_MANIFEST_DIR` is `<workspace>/crates/oraclemcp-config`, so the example
/// lives two directories up.
fn example_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("oraclemcp.example.toml")
}

#[test]
fn example_config_parses_and_validates() {
    let path = example_config_path();
    let toml =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    // `from_toml_str` runs the full loader: strict parse (deny_unknown_fields),
    // base-inheritance resolution, and the same validation `load` applies. If the
    // example drifts out of the schema, this returns Err and the test fails.
    let cfg = OracleMcpConfig::from_toml_str(&toml)
        .unwrap_or_else(|e| panic!("example config must parse + validate, got: {e}"));

    // Sanity-anchor the worked example so a future edit that guts it is noticed.
    assert_eq!(cfg.schema_version, 2);
    assert_eq!(cfg.default_profile.as_deref(), Some("dev_ro"));
    assert!(!cfg.http.dashboard_workbench);

    // The exposed read-only profile is the default-open case.
    let dev = cfg.profile("dev_ro").expect("dev_ro profile present");
    assert!(dev.mcp_exposed(), "dev_ro is exposed by default");
    assert!(!dev.dashboard_ddl_workbench());
    assert_eq!(dev.max_level(), OperatingLevel::ReadOnly);
    assert!(cfg.is_mcp_exposed("dev_ro"));

    // The worked opt-out: a privileged profile hidden from the agent surface but
    // still visible to the operator/CLI.
    let prod = cfg
        .profile("prod_admin")
        .expect("prod_admin profile present");
    assert!(
        !prod.mcp_exposed(),
        "prod_admin opts out with mcp_exposed = false"
    );
    assert!(
        cfg.mcp_profile("prod_admin").is_none(),
        "hidden profile is invisible to the served surface"
    );

    // One profile's opt-out never changes another's exposure.
    assert!(
        cfg.is_mcp_exposed("dev_ro"),
        "dev_ro stays exposed even though prod_admin opted out"
    );

    // The served list omits the hidden profile; the operator list shows both.
    let served: Vec<String> = cfg
        .list_mcp_profiles()
        .iter()
        .map(|p| p.name.clone())
        .collect();
    assert_eq!(served, vec!["dev_ro".to_owned()]);
    assert_eq!(cfg.list_profiles().len(), 2);
}
