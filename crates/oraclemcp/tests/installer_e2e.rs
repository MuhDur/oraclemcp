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
fn readme_leads_with_hosted_install_one_liner_service_and_dashboard() {
    let root = repo_root();
    let readme = fs::read_to_string(root.join("README.md")).expect("read README.md");
    let install = readme
        .find("## Install, service, dashboard")
        .expect("install-first heading");
    let why = readme.find("## Why oraclemcp").expect("why heading");
    let source = readme
        .find("## Source builds and runtime requirements")
        .expect("source-build heading");

    assert!(
        install < why,
        "README must lead with installation before rationale"
    );
    assert!(
        install < source,
        "release installer must come before source-build instructions"
    );

    for needle in [
        "https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh",
        "bash -s -- --dry-run --version 0.6.0",
        "bash -s -- --version 0.6.0",
        "https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.ps1",
        "powershell -ExecutionPolicy Bypass -File .\\install.ps1 -DryRun -Version 0.6.0",
        "powershell -ExecutionPolicy Bypass -File .\\install.ps1 -Version 0.6.0",
        "bash install.sh --offline ./oraclemcp-x86_64-unknown-linux-musl.tar.gz",
        "powershell -ExecutionPolicy Bypass -File .\\install.ps1 `",
        "-Offline .\\oraclemcp-x86_64-pc-windows-msvc.zip -Version 0.6.0",
        "Use the dry-run command first when you want a preview",
        "installer lock path",
        "exits before downloading, verifying, writing files, or",
        "The normal command downloads, verifies, and",
        "installs into `$HOME/.local`",
        "literal",
        "copy-paste commands for release `0.6.0`",
        "Later examples that contain `...`, `<pw>`, `<profile>`",
        "The release installer does not silently fall back",
        "bash install.sh --uninstall --dry-run",
        "bash install.sh --uninstall --service --yes",
        "powershell -ExecutionPolicy Bypass -File .\\install.ps1 -Service -Yes -Profile db_ro",
        "oraclemcp --json service install --dry-run",
        "oraclemcp service install --yes",
        "om dashboard",
        "database Subject",
        "isolated per-principal lanes",
    ] {
        assert!(
            readme.contains(needle),
            "README install-first section must contain {needle}"
        );
    }
}

#[test]
fn windows_installer_verifies_before_mutating_and_requires_service_consent() {
    let root = repo_root();
    let installer = fs::read_to_string(root.join("install.ps1")).expect("read install.ps1");

    for needle in [
        "certutil.exe -hashfile",
        "cosign verify-blob",
        "cosign verify-blob-attestation",
        "x86_64-pc-windows-msvc",
        "oraclemcp-$Target.zip",
        "ORACLEMCP_INSTALL_OFFLINE_BUNDLE_MISSING",
        "Expand-Archive",
        "completions powershell",
        "service install requires -Service -Yes or -DryRun",
        "service: not requested; no service-manager files or units will be touched",
        "Windows service '$ServiceName'",
    ] {
        assert!(
            installer.contains(needle),
            "install.ps1 must contain contract marker {needle}"
        );
    }

    let service_gate = installer
        .find("service install requires -Service -Yes or -DryRun")
        .expect("service consent gate");
    let service_exec = installer
        .find("& $oraclemcp @serviceArguments")
        .expect("service install command");
    assert!(
        service_gate < service_exec,
        "install.ps1 must check explicit service consent before invoking service install"
    );
}

#[test]
fn unix_installer_reinstall_is_idempotent_for_identical_files() {
    let root = repo_root();
    let installer = fs::read_to_string(root.join("install.sh")).expect("read install.sh");
    let smoke = fs::read_to_string(root.join("scripts/installer_lint_and_offline_smoke.sh"))
        .expect("read installer smoke");

    for needle in [
        "shopt -s lastpipe 2>/dev/null || true",
        "umask 022",
        "curl -fsSL \"https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh?$(date +%s)\"",
        "PROXY_ARGS=()",
        "setup_proxy()",
        "curl --fail --location --show-error --silent --proto '=https' --tlsv1.2 \"${PROXY_ARGS[@]}\"",
        "curl --fail --silent --show-error --noproxy '*' \"$url\"",
        "lock_path()",
        "acquire_lock()",
        "mkdir \"$lock\"",
        "another oraclemcp installer is already running",
        "should_replace_file()",
        "cmp -s \"$src\" \"$dest\"",
        "already exists with different content; rerun with --force",
    ] {
        assert!(
            installer.contains(needle),
            "install.sh must contain idempotency marker {needle}"
        );
    }

    for needle in [
        "built artifact idempotent reinstall failed",
        "--offline \"$archive\"",
        "--no-service",
    ] {
        assert!(
            smoke.contains(needle),
            "installer smoke must contain idempotent reinstall marker {needle}"
        );
    }
}

#[test]
fn installer_ci_runs_built_artifact_and_windows_pssa_gates() {
    let root = repo_root();
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read ci.yml");
    let release_acceptance =
        fs::read_to_string(root.join("scripts/release_acceptance_ci_suite.sh"))
            .expect("read release acceptance script");

    for needle in [
        "installer lint and built-artifact smoke",
        "ORACLEMCP_INSTALLER_REQUIRE_SHELLCHECK",
        "ORACLEMCP_INSTALLER_BUILT_BINARY",
        "target/x86_64-unknown-linux-musl/debug/oraclemcp",
        "Windows installer PSSA and dry-run",
        "Install-Module PSScriptAnalyzer",
        "Invoke-ScriptAnalyzer -Path \"install.ps1\"",
        "windows-installer",
    ] {
        assert!(ci.contains(needle), "ci.yml must contain {needle}");
    }

    for needle in [
        "installer lint and built-artifact smoke",
        "ORACLEMCP_INSTALLER_BUILT_BINARY",
        "Windows installer PSSA and dry-run",
        "scripts/installer_lint_and_offline_smoke.sh",
    ] {
        assert!(
            release_acceptance.contains(needle),
            "release acceptance must assert installer CI marker {needle}"
        );
    }
}

#[test]
fn release_sbom_workflow_merges_dashboard_and_rust_sboms() {
    let root = repo_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect("read release workflow");
    let preflight =
        fs::read_to_string(root.join("scripts/release_preflight.sh")).expect("read preflight");
    let release_acceptance =
        fs::read_to_string(root.join("scripts/release_acceptance_ci_suite.sh"))
            .expect("read release acceptance");
    let operations = fs::read_to_string(root.join("docs/operations.md")).expect("read operations");

    for needle in [
        "pattern: oraclemcp-*-*-*",
        "name: oraclemcp-dashboard-dist",
        "path: web/dist",
        "bash scripts/merge_release_sbom.sh",
        "web/dist/oraclemcp-dashboard.cyclonedx.json",
        "bash scripts/release_sbom_check.sh --artifact",
        "artifacts/oraclemcp-${{ steps.version.outputs.version }}.cdx.json",
        "artifacts/*.cdx.json.attestation.sigstore.json",
    ] {
        assert!(
            workflow.contains(needle),
            "release workflow must contain SBOM marker {needle}"
        );
    }
    assert!(
        preflight.contains("bash \"$ROOT/scripts/release_sbom_check.sh\" --source"),
        "release preflight must check merged SBOM source wiring"
    );
    assert!(
        release_acceptance.contains("scripts/release_sbom_check.sh --source"),
        "release acceptance must schedule the SBOM source gate"
    );
    assert!(
        fs::read_to_string(root.join("scripts/release_sbom_check.sh"))
            .expect("read SBOM check script")
            .contains("npm sbom --sbom-format cyclonedx --json"),
        "release SBOM source gate must regenerate the dashboard SBOM from the lockfile"
    );
    assert!(
        operations.contains("Rust Cargo graph and the dashboard npm graph"),
        "operations docs must describe the merged release SBOM"
    );
}

#[test]
fn release_sbom_merge_script_includes_rust_and_dashboard_components() {
    let root = repo_root();
    let fixture_dir = root.join("target/release-sbom-fixtures");
    fs::create_dir_all(&fixture_dir).expect("create SBOM fixture dir");

    let web_package: Value = serde_json::from_str(
        &fs::read_to_string(root.join("web/package.json")).expect("read web package"),
    )
    .expect("web package parses");
    let dashboard_version = web_package["version"]
        .as_str()
        .expect("dashboard package version");
    let dashboard_ref = format!("@oraclemcp/dashboard@{dashboard_version}");
    let dashboard_purl = format!("pkg:npm/%40oraclemcp/dashboard@{dashboard_version}");

    let rust_sbom = fixture_dir.join("rust.cdx.json");
    let dashboard_sbom = fixture_dir.join("dashboard.cdx.json");
    let merged_sbom = fixture_dir.join("merged.cdx.json");
    let rust_doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "oraclemcp",
                "version": "0.6.0-test",
                "bom-ref": "pkg:cargo/oraclemcp@0.6.0-test"
            },
            "tools": [
                {"vendor": "CycloneDX", "name": "cargo-cyclonedx", "version": "0.5.9"}
            ]
        },
        "components": [
            {
                "type": "library",
                "name": "serde",
                "version": "1.0.0",
                "bom-ref": "pkg:cargo/serde@1.0.0",
                "purl": "pkg:cargo/serde@1.0.0"
            }
        ],
        "dependencies": [
            {"ref": "pkg:cargo/oraclemcp@0.6.0-test", "dependsOn": ["pkg:cargo/serde@1.0.0"]}
        ]
    });
    let dashboard_doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "name": "web",
                "version": dashboard_version,
                "bom-ref": dashboard_ref,
                "purl": dashboard_purl
            },
            "tools": [
                {"vendor": "npm", "name": "cli", "version": "10.9.4"}
            ]
        },
        "components": [
            {
                "type": "library",
                "name": "react",
                "version": "19.2.7",
                "bom-ref": "react@19.2.7",
                "purl": "pkg:npm/react@19.2.7"
            }
        ],
        "dependencies": [
            {"ref": dashboard_ref, "dependsOn": ["react@19.2.7"]}
        ]
    });
    fs::write(
        &rust_sbom,
        serde_json::to_vec_pretty(&rust_doc).expect("serialize Rust SBOM"),
    )
    .expect("write Rust SBOM fixture");
    fs::write(
        &dashboard_sbom,
        serde_json::to_vec_pretty(&dashboard_doc).expect("serialize dashboard SBOM"),
    )
    .expect("write dashboard SBOM fixture");

    let output = Command::new("bash")
        .arg(root.join("scripts/merge_release_sbom.sh"))
        .arg(&rust_sbom)
        .arg(&dashboard_sbom)
        .arg(&merged_sbom)
        .current_dir(&root)
        .output()
        .expect("run SBOM merge script");
    assert!(
        output.status.success(),
        "SBOM merge failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let merged: Value =
        serde_json::from_str(&fs::read_to_string(&merged_sbom).expect("read merged SBOM"))
            .expect("merged SBOM parses");
    let dashboard_root_ref = format!("npm:{dashboard_ref}");
    let root_dep = merged["dependencies"]
        .as_array()
        .expect("dependencies array")
        .iter()
        .find(|dep| dep["ref"] == "pkg:cargo/oraclemcp@0.6.0-test")
        .expect("root dependency entry");

    assert_eq!(merged["bomFormat"], "CycloneDX");
    assert!(
        merged["components"]
            .as_array()
            .expect("components array")
            .iter()
            .any(|component| component["purl"] == dashboard_purl
                && component["bom-ref"] == dashboard_root_ref),
        "merged SBOM must contain dashboard root component"
    );
    assert!(
        merged["components"]
            .as_array()
            .expect("components array")
            .iter()
            .any(|component| component["purl"] == "pkg:npm/react@19.2.7"
                && component["bom-ref"] == "npm:react@19.2.7"),
        "merged SBOM must prefix npm dependency bom-refs"
    );
    assert!(
        root_dep["dependsOn"]
            .as_array()
            .expect("root dependsOn")
            .iter()
            .any(|dep| dep == &dashboard_root_ref),
        "Rust release SBOM root must depend on the dashboard component"
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

#[test]
fn binstall_brew_winget_metadata_valid() {
    let root = repo_root();
    let manifest =
        fs::read_to_string(root.join("crates/oraclemcp/Cargo.toml")).expect("read Cargo.toml");
    assert!(manifest.contains("[package.metadata.binstall]"));
    assert!(manifest.contains("[package.metadata.binstall.overrides.x86_64-pc-windows-msvc]"));

    let homebrew_template =
        fs::read_to_string(root.join("packaging/homebrew/Formula/oraclemcp.rb.in"))
            .expect("read Homebrew formula template");
    for needle in [
        "class Oraclemcp < Formula",
        "license any_of: [\"Apache-2.0\", \"MIT\"]",
        "oraclemcp-aarch64-apple-darwin.tar.gz",
        "oraclemcp-x86_64-apple-darwin.tar.gz",
        "bin.install \"oraclemcp\"",
        "bin.install \"om\"",
    ] {
        assert!(
            homebrew_template.contains(needle),
            "Homebrew template must contain {needle}"
        );
    }

    let winget_installer =
        fs::read_to_string(root.join("packaging/winget/MuhDur.oraclemcp.installer.yaml.in"))
            .expect("read winget installer template");
    for needle in [
        "PackageIdentifier: MuhDur.oraclemcp",
        "InstallerType: zip",
        "NestedInstallerType: portable",
        "Architecture: x64",
        "oraclemcp-x86_64-pc-windows-msvc.zip",
        "RelativeFilePath: oraclemcp-x86_64-pc-windows-msvc\\oraclemcp.exe",
        "PortableCommandAlias: oraclemcp",
        "RelativeFilePath: oraclemcp-x86_64-pc-windows-msvc\\om.exe",
        "PortableCommandAlias: om",
        "ManifestVersion: 1.12.0",
    ] {
        assert!(
            winget_installer.contains(needle),
            "winget installer template must contain {needle}"
        );
    }

    let workflow =
        fs::read_to_string(root.join(".github/workflows/release.yml")).expect("read release.yml");
    assert!(workflow.contains("scripts/render_distribution_manifests.sh artifacts"));
    assert!(workflow.contains("artifacts/distribution-manifests/homebrew/Formula/oraclemcp.rb"));
    assert!(workflow.contains("artifacts/distribution-manifests/winget/**/*.yaml"));

    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let test_root = target_dir.join("dist-metadata-test");
    let artifacts = test_root.join("artifacts");
    let out = test_root.join("out");
    fs::create_dir_all(&artifacts).expect("create artifact fixture dir");
    write_checksum_fixture(
        &artifacts,
        "oraclemcp-x86_64-apple-darwin.tar.gz",
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_checksum_fixture(
        &artifacts,
        "oraclemcp-aarch64-apple-darwin.tar.gz",
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    write_checksum_fixture(
        &artifacts,
        "oraclemcp-x86_64-pc-windows-msvc.zip",
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    );

    let output = Command::new("bash")
        .arg(root.join("scripts/render_distribution_manifests.sh"))
        .env("VERSION", "9.9.9-test.1")
        .env("ARTIFACT_DIR", &artifacts)
        .env("OUT_DIR", &out)
        .current_dir(&root)
        .output()
        .expect("run distribution metadata renderer");
    assert!(
        output.status.success(),
        "distribution renderer failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let formula = fs::read_to_string(out.join("homebrew/Formula/oraclemcp.rb"))
        .expect("read rendered Homebrew formula");
    assert!(!formula.contains("__"));
    assert!(formula.contains("version \"9.9.9-test.1\""));
    assert!(
        formula.contains(
            "sha256 \"1111111111111111111111111111111111111111111111111111111111111111\""
        )
    );
    assert!(
        formula.contains(
            "sha256 \"2222222222222222222222222222222222222222222222222222222222222222\""
        )
    );

    let winget_dir = out.join("winget/manifests/m/MuhDur/oraclemcp/9.9.9-test.1");
    let winget_version = fs::read_to_string(winget_dir.join("MuhDur.oraclemcp.yaml"))
        .expect("read rendered winget version manifest");
    let winget_locale = fs::read_to_string(winget_dir.join("MuhDur.oraclemcp.locale.en-US.yaml"))
        .expect("read rendered winget locale manifest");
    let winget_installer = fs::read_to_string(winget_dir.join("MuhDur.oraclemcp.installer.yaml"))
        .expect("read rendered winget installer manifest");
    for rendered in [&winget_version, &winget_locale, &winget_installer] {
        assert!(!rendered.contains("__"));
        assert!(rendered.contains("PackageVersion: 9.9.9-test.1"));
        assert!(rendered.contains("PackageIdentifier: MuhDur.oraclemcp"));
    }
    assert!(winget_version.contains("ManifestType: version"));
    assert!(winget_locale.contains("ManifestType: defaultLocale"));
    assert!(winget_installer.contains("ManifestType: installer"));
    assert!(winget_installer.contains(
        "InstallerSha256: ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"
    ));
}

fn write_checksum_fixture(dir: &Path, asset: &str, digest: &str) {
    fs::write(
        dir.join(format!("{asset}.sha256")),
        format!("{digest}  {asset}\n"),
    )
    .expect("write checksum fixture");
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
