use std::path::{Path, PathBuf};

use oraclemcp_config::{HttpConfig, OciConfig, OperatingLevel, PoolConfig};
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_db::ServerFeatures;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path)).unwrap_or_else(|err| {
        panic!("read {path}: {err}");
    })
}

fn assert_mentions(haystack: &str, needle: &str, label: &str) {
    assert!(haystack.contains(needle), "{label} must mention {needle:?}");
}

#[test]
fn release_docs_cover_0_8_config_migration_surfaces() {
    let upgrade = read_repo_file("docs/upgrading-to-0.8.0.md");
    let downgrade = read_repo_file("docs/downgrading-0.8.0-to-0.7.2.md");
    let readme = read_repo_file("README.md");
    let configuration = read_repo_file("docs/configuration.md");

    for field in [
        "connect_timeout_seconds",
        "inactivity_timeout_seconds",
        "keepalive_minutes",
        "allow_remote",
        "use_iam_token",
        "token_env",
        "token_file",
        "token_exec",
        "streaming",
        "tnsnames.ora",
    ] {
        assert_mentions(&upgrade, field, "0.8.0 upgrade doc");
    }

    for field in [
        "connect_timeout_seconds",
        "inactivity_timeout_seconds",
        "keepalive_minutes",
        "allow_remote",
        "token_env",
        "token_file",
        "token_exec",
        "audit records use hash-chain format v4",
    ] {
        assert_mentions(&downgrade, field, "0.8.0 downgrade runbook");
    }

    for link in [
        "docs/upgrading-to-0.8.0.md",
        "docs/downgrading-0.8.0-to-0.7.2.md",
        "docs/feature-rollout-0.8.0.md",
    ] {
        assert_mentions(&readme, link, "README release-doc links");
    }

    for field in [
        "`inactivity_timeout_seconds`",
        "`keepalive_minutes`",
        "`token_exec`",
    ] {
        assert_mentions(&configuration, field, "configuration field reference");
    }
}

#[test]
fn feature_rollout_doc_defaults_match_shipped_defaults() {
    let rollout = read_repo_file("docs/feature-rollout-0.8.0.md");

    let stdio = CapabilitiesReport::new(
        "0.8.0",
        Vec::new(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: true,
            engine: false,
            http_transport: false,
        },
    );
    assert!(
        !stdio.tool_features.streaming,
        "stdio does not advertise SSE chunk-frame streaming"
    );
    assert!(stdio.tool_features.incremental_fetch);
    assert_mentions(&rollout, "Off per request", "streaming default");
    assert_mentions(
        &rollout,
        "`oracle_capabilities.tool_features.streaming` is `false` on stdio",
        "streaming transport gate",
    );

    let http = CapabilitiesReport::new(
        "0.8.0",
        Vec::new(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: true,
            engine: false,
            http_transport: true,
        },
    );
    assert!(http.tool_features.streaming);
    assert_mentions(&rollout, "`streaming = true`", "streaming opt-in");

    let pool = PoolConfig::default();
    assert_eq!(pool.statement_cache_size, 50);
    assert_mentions(
        &rollout,
        "[profiles.pool].statement_cache_size = 50",
        "statement-cache default",
    );

    let http_config = HttpConfig::default();
    assert!(!http_config.allow_remote);
    assert_mentions(
        &rollout,
        "[http].allow_remote` defaults to `false`",
        "allow_remote default",
    );

    let oci = OciConfig::default();
    assert!(!oci.use_iam_token);
    assert!(oci.token_env.is_none());
    assert!(oci.token_file.is_none());
    assert!(oci.token_exec.is_none());
    assert_mentions(
        &rollout,
        "[profiles.oci].use_iam_token` defaults to `false`",
        "IAM token default",
    );
    assert_mentions(
        &rollout,
        "`token_env`, `token_file`, and `token_exec` default to unset",
        "IAM source defaults",
    );

    let features = ServerFeatures::default();
    assert!(features.supports_pipelining.is_none());
    assert_mentions(
        &rollout,
        "Unknown until a live connection reports `connection.server_features.supports_pipelining`",
        "pipelining default",
    );
    assert_mentions(
        &rollout,
        "There is no profile key that can force pipelining",
        "pipelining opt-in path",
    );
}
