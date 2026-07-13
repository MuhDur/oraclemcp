//! Annotated-writer parity + anti-rot test (TNS-onboarding bead `.9`; design
//! spec §C, `docs/tns-discovery-onboarding.md`).
//!
//! Proves the annotated discovery writer output is valid, bootable, and cannot
//! silently drift from the `ConnectionProfile` / `OracleMcpConfig` serde schema
//! or from `oraclemcp.example.toml`. This complements the schema-drift guard in
//! `discovery::contract` (bead `.1`, which pins the disposition TABLE to the
//! structs): here we pin the RENDERED OUTPUT to the structs' real serde field
//! sets, end to end, so a new field cannot be added without appearing in the
//! generated annotated config.

use std::collections::BTreeSet;
use std::path::PathBuf;

use oraclemcp_config::discovery::synth::{DiscoveredNetService, SynthOptions, synthesize_profiles};
use oraclemcp_config::discovery::{DiscoverySynthesis, render_annotated_config};
use oraclemcp_config::{
    AppContextConfig, ConnectionProfile, DrcpRoutingConfig, HttpConfig, OciConfig, OperatingLevel,
    OracleMcpConfig, PoolConfig, ProxyAuthConfig, SessionIdentityConfig,
};

/// A two-net-service synthesis: a plain alias and a TCPS + wallet target (so the
/// `[profiles.oci] wallet_password_ref` placeholder path is exercised).
fn two_service_synth() -> DiscoverySynthesis {
    let mut tcps = DiscoveredNetService::new("PRIMARY_TCPS");
    tcps.protocol = Some("TCPS".to_owned());
    tcps.host = Some("tcps.example.com".to_owned());
    tcps.port = Some(2484);
    tcps.service_name = Some("PRIMARY.example.com".to_owned());
    tcps.wallet_location = Some("/etc/oracle/wallet/primary".to_owned());
    let services = vec![DiscoveredNetService::new("SALES_RO"), tcps];
    synthesize_profiles(&services, &SynthOptions::default())
}

/// The exact serde field-name set of a struct, from serializing a FULLY
/// populated instance (every `Option` = `Some`, so no `skip_serializing_if`
/// hides a field). This is deliberately independent of the disposition table:
/// it reads the *structs' own* serde surface, so the parity assertions below
/// hold even if the table and the structs ever diverged.
fn serde_field_names<T: serde::Serialize>(value: &T) -> BTreeSet<String> {
    let json = serde_json::to_value(value).expect("serialize to serde_json::Value");
    json.as_object()
        .expect("struct serializes to a JSON object")
        .keys()
        .cloned()
        .collect()
}

fn fully_populated_profile() -> ConnectionProfile {
    ConnectionProfile {
        name: "sample".to_owned(),
        description: Some("sample".to_owned()),
        connect_string: Some("host:1521/svc".to_owned()),
        username: Some("APP_RO".to_owned()),
        credential_ref: Some("env:ORACLE_SAMPLE_PASSWORD".to_owned()),
        login_script: Some(PathBuf::from("/dev/null")),
        login_statements: Some(vec!["ALTER SESSION SET NLS_LANGUAGE = english".to_owned()]),
        trusted_session_statements: Some(vec!["BEGIN NULL; END;".to_owned()]),
        call_timeout_seconds: Some(30),
        max_query_cost: Some(1_000),
        connect_timeout_seconds: Some(20),
        inactivity_timeout_seconds: Some(300),
        keepalive_minutes: Some(10),
        sdu: Some(8192),
        max_level: Some(OperatingLevel::ReadOnly),
        default_level: Some(OperatingLevel::ReadOnly),
        protected: Some(false),
        require_signed_tools: Some(false),
        read_only_standby: Some(false),
        mcp_exposed: Some(true),
        dashboard_ddl_workbench: Some(false),
        session_identity: Some(SessionIdentityConfig::default()),
        pool: Some(PoolConfig::default()),
        oci: Some(OciConfig::default()),
        drcp: Some(DrcpRoutingConfig::default()),
        proxy_auth: Some(ProxyAuthConfig::default()),
        app_context: Some(vec![AppContextConfig::default()]),
        base: Some("base_profile".to_owned()),
    }
}

fn fully_populated_config() -> OracleMcpConfig {
    OracleMcpConfig {
        schema_version: 2,
        default_profile: Some("sample".to_owned()),
        monitor_profile: Some("monitor_ro".to_owned()),
        http: HttpConfig::default(),
        audit: oraclemcp_config::AuditConfig::default(),
        profiles: Vec::new(),
    }
}

/// Does the rendered output surface `field` — SET (`field =`), commented
/// (`# field =`), or as a `[profiles.field]` / `[[profiles.field]]` sub-table?
fn output_surfaces_profile_field(rendered: &str, field: &str) -> bool {
    rendered.contains(&format!("\n{field} = "))
        || rendered.contains(&format!("# {field} = "))
        || rendered.contains(&format!("[profiles.{field}]"))
        || rendered.contains(&format!("[[profiles.{field}]]"))
}

fn output_surfaces_top_level_field(rendered: &str, field: &str) -> bool {
    match field {
        // http / audit are represented by the example.toml pointer notes.
        "http" => rendered.contains("oraclemcp.example.toml [http]"),
        "audit" => rendered.contains("oraclemcp.example.toml [audit]"),
        // profiles is the [[profiles]] array.
        "profiles" => rendered.contains("[[profiles]]"),
        _ => {
            rendered.contains(&format!("\n{field} = "))
                || rendered.contains(&format!("# {field} = "))
        }
    }
}

#[test]
fn rendered_output_parses_through_the_strict_loader() {
    let rendered = render_annotated_config(&two_service_synth());
    let cfg = OracleMcpConfig::from_toml_str(&rendered)
        .expect("annotated writer output parses + validates (deny_unknown_fields honored)");
    assert_eq!(cfg.profiles.len(), 2);
    // Both levels are SET to READ_ONLY (safety-legibility regression guard).
    for profile in &cfg.profiles {
        assert_eq!(profile.max_level, Some(OperatingLevel::ReadOnly));
        assert_eq!(profile.default_level, Some(OperatingLevel::ReadOnly));
    }
}

#[test]
fn every_connection_profile_serde_field_appears_in_output() {
    let rendered = render_annotated_config(&two_service_synth());
    let expected = serde_field_names(&fully_populated_profile());
    let missing: Vec<&String> = expected
        .iter()
        .filter(|field| !output_surfaces_profile_field(&rendered, field))
        .collect();
    assert!(
        missing.is_empty(),
        "these ConnectionProfile serde fields are missing from the annotated \
         writer output (anti-rot): {missing:?}"
    );
}

#[test]
fn every_top_level_serde_field_appears_in_output() {
    let rendered = render_annotated_config(&two_service_synth());
    let expected = serde_field_names(&fully_populated_config());
    let missing: Vec<&String> = expected
        .iter()
        .filter(|field| !output_surfaces_top_level_field(&rendered, field))
        .collect();
    assert!(
        missing.is_empty(),
        "these OracleMcpConfig serde fields are missing from the annotated \
         writer output (anti-rot): {missing:?}"
    );
}

#[test]
fn uncommenting_a_sampled_scalar_and_section_still_parses() {
    let rendered = render_annotated_config(&two_service_synth());
    // Uncomment call_timeout_seconds (a scalar) and the FIRST [profiles.oci]
    // header + its wallet_location key as a unit.
    let mut oci_header_done = false;
    let mut in_first_oci = false;
    let mut wallet_done = false;
    let mut out = String::new();
    for line in rendered.lines() {
        let emit = if line == "# call_timeout_seconds = 30" {
            "call_timeout_seconds = 30".to_owned()
        } else if !oci_header_done && line == "# [profiles.oci]" {
            oci_header_done = true;
            in_first_oci = true;
            "[profiles.oci]".to_owned()
        } else if in_first_oci
            && !wallet_done
            && line == "# wallet_location = \"/etc/oracle/wallet\""
        {
            wallet_done = true;
            in_first_oci = false;
            "wallet_location = \"/etc/oracle/wallet\"".to_owned()
        } else {
            line.to_owned()
        };
        out.push_str(&emit);
        out.push('\n');
    }
    let cfg = OracleMcpConfig::from_toml_str(&out)
        .expect("uncommenting a sampled scalar + section still parses");
    assert_eq!(cfg.profiles[0].call_timeout_seconds, Some(30));
    assert!(cfg.profiles[0].oci.is_some());
}

#[test]
fn help_wording_is_consistent_in_meaning_with_example_toml() {
    let rendered = render_annotated_config(&two_service_synth());
    let example_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("oraclemcp.example.toml");
    let example = std::fs::read_to_string(&example_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", example_path.display()));

    // For a sampled set of overlapping COMMENTED fields (only commented fields
    // render their help; SET fields render just their value), both the annotated
    // writer help and the worked example use the same distinctive term — so the
    // two documents are reconciled in meaning, not merely both naming the field.
    let shared_terms = [
        ("mcp_exposed", "opt-out"),
        ("read_only_standby", "Active Data Guard"),
        ("protected", "immutable"),
        ("login_statements", "allowlist-validated"),
        ("sdu", "512..=65535"),
    ];
    for (field, term) in shared_terms {
        assert!(
            rendered.contains(term),
            "the writer's {field} help should use the shared term {term:?}"
        );
        assert!(
            example.contains(term),
            "oraclemcp.example.toml should use the shared term {term:?} for {field}"
        );
    }
}
