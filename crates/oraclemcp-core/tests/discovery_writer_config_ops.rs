//! Annotated-writer / config-ops re-parse guarantee (TNS-onboarding bead `.9`;
//! design spec §C/§E, `docs/tns-discovery-onboarding.md`).
//!
//! The annotated discovery writer lives in `oraclemcp-config`; the config-ops
//! apply path (`oraclemcp-core`) re-parses any draft with the strict loader
//! (`OracleMcpConfig::from_toml_str`, `config_ops.rs:280`) before staging it.
//! This test proves the writer output is accepted verbatim by that real path —
//! not just by a direct `from_toml_str` call — so a discovery-written config
//! round-trips through the same machinery `oraclemcp setup --write` uses.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_config::discovery::render_annotated_config;
use oraclemcp_config::discovery::synth::{DiscoveredNetService, SynthOptions, synthesize_profiles};
use oraclemcp_core::config_ops::ConfigOpsBackend;
use oraclemcp_core::file_store::FileStore;

fn unique_temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "oraclemcp-configops-{}-{stamp}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn annotated_writer_output_stages_through_config_ops() {
    // A two-net-service synthesis (plain alias + TCPS/wallet target).
    let mut tcps = DiscoveredNetService::new("PRIMARY_TCPS");
    tcps.protocol = Some("TCPS".to_owned());
    tcps.host = Some("tcps.example.com".to_owned());
    tcps.port = Some(2484);
    tcps.service_name = Some("PRIMARY.example.com".to_owned());
    tcps.wallet_location = Some("/etc/oracle/wallet/primary".to_owned());
    let synth = synthesize_profiles(
        &[DiscoveredNetService::new("SALES_RO"), tcps],
        &SynthOptions::default(),
    );
    let rendered = render_annotated_config(&synth);

    let store_root = unique_temp_dir("store");
    let backend = ConfigOpsBackend::new(FileStore::open(&store_root).expect("open file store"));
    let target = unique_temp_dir("target").join("profiles.toml");

    // stage_config_draft re-parses the draft with the strict loader
    // (config_ops.rs:281, the same loader as :280) — an unknown key or a
    // validation failure would return Err here.
    let plan = backend
        .stage_config_draft(&target, &rendered)
        .expect("annotated writer output stages through config-ops re-parse path");

    // The staged draft hashes the exact bytes we rendered (comments preserved).
    let preview = plan.preview();
    assert_eq!(
        preview.draft_sha256,
        oraclemcp_audit::sha256_hex(rendered.as_bytes()),
        "config-ops stages the rendered bytes verbatim"
    );
    assert!(!preview.original_existed, "target did not pre-exist");

    std::fs::remove_dir_all(&store_root).ok();
    std::fs::remove_dir_all(target.parent().expect("target parent")).ok();
}
