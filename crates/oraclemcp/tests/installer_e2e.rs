use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has workspace parent")
        .parent()
        .expect("workspace has repo root")
        .to_path_buf()
}

#[test]
fn installer_lint_and_offline_smoke_passes() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/installer_lint_and_offline_smoke.sh"))
        .current_dir(&root)
        .output()
        .expect("run installer smoke");

    assert!(
        output.status.success(),
        "installer smoke failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn npx_verifies_binary_no_postinstall_side_effects() {
    let root = repo_root();
    let package_json = root.join("npm/oraclemcp/package.json");
    let wrapper = root.join("npm/oraclemcp/bin/oraclemcp.js");
    let package: Value =
        serde_json::from_str(&fs::read_to_string(&package_json).expect("read npm package.json"))
            .expect("npm package.json parses");
    let wrapper_text = fs::read_to_string(&wrapper).expect("read npm wrapper");
    let cargo_toml =
        fs::read_to_string(root.join("crates/oraclemcp/Cargo.toml")).expect("read Cargo.toml");
    let crate_version = cargo_toml
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|tail| tail.strip_suffix('"'))
        .expect("oraclemcp crate version");

    assert_eq!(package["name"], "oraclemcp");
    assert_eq!(package["version"], crate_version);
    assert_eq!(package["publishConfig"]["provenance"], true);
    assert_eq!(package["bin"]["oraclemcp"], "bin/oraclemcp.js");
    assert_eq!(package["bin"]["om"], "bin/oraclemcp.js");

    let scripts = package["scripts"].as_object().expect("scripts object");
    for lifecycle in ["preinstall", "install", "postinstall", "prepare"] {
        assert!(
            !scripts.contains_key(lifecycle),
            "npm wrapper must not run {lifecycle} on user machines"
        );
    }

    for needle in [
        ".sha256",
        ".sig",
        ".crt",
        ".attestation.sigstore.json",
        "verify-blob",
        "verify-blob-attestation",
        "sha256",
        "ORACLEMCP_NPM_DRY_RUN",
    ] {
        assert!(
            wrapper_text.contains(needle),
            "npm wrapper must contain verification path {needle}"
        );
    }
    for forbidden in ["service install", "clients issue"] {
        assert!(
            !wrapper_text.contains(forbidden),
            "npm wrapper must not mutate service/client state via {forbidden}"
        );
    }
}

#[test]
fn cargo_binstall_metadata_matches_release_assets() {
    let root = repo_root();
    let manifest =
        fs::read_to_string(root.join("crates/oraclemcp/Cargo.toml")).expect("read Cargo.toml");

    for needle in [
        "[package.metadata.binstall]",
        "pkg-url = \"{ repo }/releases/download/v{ version }/{ name }-{ target }{ archive-suffix }\"",
        "bin-dir = \"{ name }-{ target }/{ bin }{ binary-ext }\"",
        "pkg-fmt = \"tgz\"",
        "disabled-strategies = [\"quick-install\", \"compile\"]",
        "[package.metadata.binstall.overrides.x86_64-pc-windows-msvc]",
        "pkg-fmt = \"zip\"",
    ] {
        assert!(
            manifest.contains(needle),
            "Cargo.toml binstall metadata must contain {needle}"
        );
    }

    let release_assets = fs::read_to_string(root.join("docs/operations.md"))
        .expect("read documented release asset matrix");
    for (target, archive_suffix, binary_ext) in [
        ("x86_64-unknown-linux-gnu", ".tar.gz", ""),
        ("x86_64-unknown-linux-musl", ".tar.gz", ""),
        ("aarch64-unknown-linux-gnu", ".tar.gz", ""),
        ("aarch64-unknown-linux-musl", ".tar.gz", ""),
        ("x86_64-apple-darwin", ".tar.gz", ""),
        ("aarch64-apple-darwin", ".tar.gz", ""),
        ("x86_64-pc-windows-msvc", ".zip", ".exe"),
    ] {
        let asset = format!("oraclemcp-{target}{archive_suffix}");
        let binary = format!("oraclemcp-{target}/oraclemcp{binary_ext}");
        assert!(
            release_assets.contains(&asset),
            "release asset matrix must document {asset}"
        );
        assert_eq!(
            expand_binstall_template(
                "{ repo }/releases/download/v{ version }/{ name }-{ target }{ archive-suffix }",
                target,
                archive_suffix,
                binary_ext,
            ),
            format!("https://github.com/MuhDur/oraclemcp/releases/download/v9.9.9-test/{asset}")
        );
        assert_eq!(
            expand_binstall_template(
                "{ name }-{ target }/{ bin }{ binary-ext }",
                target,
                archive_suffix,
                binary_ext,
            ),
            binary
        );
    }
}

fn expand_binstall_template(
    template: &str,
    target: &str,
    archive_suffix: &str,
    binary_ext: &str,
) -> String {
    template
        .replace("{ repo }", "https://github.com/MuhDur/oraclemcp")
        .replace("{ version }", "9.9.9-test")
        .replace("{ name }", "oraclemcp")
        .replace("{ target }", target)
        .replace("{ archive-suffix }", archive_suffix)
        .replace("{ bin }", "oraclemcp")
        .replace("{ binary-ext }", binary_ext)
}
