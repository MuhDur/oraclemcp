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
        .arg("--log")
        .current_dir(&root)
        .output()
        .expect("run installer smoke");

    assert!(
        output.status.success(),
        "installer smoke failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("installer smoke emits JSON lines"))
        .collect::<Vec<_>>();
    for expected in [
        "static installer contracts",
        "non-TTY dry-run agent path",
        "cosign-absent prefer install path",
        "update backup idempotency and rollback",
        "verify-require without cosign fails closed",
        "bad cosign signature fails closed",
        "tampered checksum fails closed",
        "service dry-run consent plan",
        "offline plan and missing metadata failure",
        "uninstall preview remove and idempotent rerun",
    ] {
        assert!(
            events.iter().any(|event| event["event"] == "component_gate"
                && event["outcome"] == "pass"
                && event["message"].as_str() == Some(expected)),
            "installer smoke JSONL missing pass event {expected}: {events:?}"
        );
    }
    assert!(
        events.iter().any(|event| event["event"] == "suite_summary"
            && event["outcome"] == "pass"
            && event["message"]
                .as_str()
                .is_some_and(|message| message.contains("installer acceptance cases passed"))),
        "installer smoke JSONL missing suite summary: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "scenario_complete"
                && event["outcome"] == "pass"
                && event["scenario"] == "installer_lint_and_offline_smoke"),
        "installer smoke JSONL missing completion: {events:?}"
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
    let install_section = &readme[install..why];
    let first_shell_fence = install_section
        .find("```sh\n")
        .expect("install section must have a shell code fence");
    let first_shell_body = &install_section[first_shell_fence + "```sh\n".len()..];
    let first_shell_end = first_shell_body
        .find("\n```")
        .expect("first shell fence must close");
    let first_shell_command = first_shell_body[..first_shell_end].trim();
    assert_eq!(
        first_shell_command,
        r#"curl -fsSL "https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh?$(date +%s)" | bash -s -- --version 0.6.6"#,
        "first install command must be the single copy-paste install/update line"
    );
    assert!(
        !first_shell_command.contains("--dry-run"),
        "dry-run must be advanced preview text, not the primary install command"
    );

    for needle in [
        "One line installs or updates `oraclemcp`",
        "works as pasted",
        "https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh",
        "bash -s -- --dry-run --version 0.6.6",
        "bash -s -- --version 0.6.6",
        "https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.ps1",
        "powershell -ExecutionPolicy Bypass -File .\\install.ps1 -DryRun -Version 0.6.6",
        "powershell -ExecutionPolicy Bypass -File .\\install.ps1 -Version 0.6.6",
        "The Windows installer accepts the same release operations",
        "-Verify prefer",
        "-Verify require",
        "-Verify checksum-only",
        "powershell -ExecutionPolicy Bypass -File .\\install.ps1 -Update -Version 0.6.6 -NoService",
        "bash install.sh --offline ./oraclemcp-x86_64-unknown-linux-musl.tar.gz",
        "powershell -ExecutionPolicy Bypass -File .\\install.ps1 `",
        "-Offline .\\oraclemcp-x86_64-pc-windows-msvc.zip -Version 0.6.6",
        "Use the dry-run command first when you want a preview",
        "installer lock path",
        "exits before downloading, verifying, writing files, or",
        "The normal command downloads, verifies, and",
        "installs into `$HOME/.local`",
        "updates atomically after backing up the previous",
        "A downgrade is refused unless you pass `--force`",
        "exact `PATH` line plus next steps",
        "next steps on stderr",
        "oraclemcp --json self-update --dry-run --version 0.6.6",
        "oraclemcp self-update --version 0.6.6 --no-service",
        "literal",
        "copy-pasteable for release",
        "### Advanced install paths",
        "placeholder env values",
        "The release installer does not silently fall back",
        "bash install.sh --uninstall --dry-run",
        "bash install.sh --uninstall --service --yes",
        "powershell -ExecutionPolicy Bypass -File .\\install.ps1 -Uninstall -DryRun",
        "powershell -ExecutionPolicy Bypass -File .\\install.ps1 -Uninstall -Yes",
        "powershell -ExecutionPolicy Bypass -File .\\install.ps1 -Service -Yes -Profile db_ro",
        "oraclemcp --json service install --dry-run",
        "oraclemcp service install --yes",
        "om dashboard",
        "database Subject",
        "isolated per-principal lanes",
        "Pending registry-backed channels",
        "brew info MuhDur/oraclemcp/oraclemcp",
        "winget search --id MuhDur.oraclemcp --exact",
        "An npm/npx channel is not offered",
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
        "Get-NormalizedVerifyPosture",
        "cosign is required by -Verify require",
        "authenticity unverified: cosign not installed; SHA-256 checksum verified",
        "cosign verification intentionally skipped by -Verify checksum-only",
        "x86_64-pc-windows-msvc",
        "oraclemcp-$Target.zip",
        "ORACLEMCP_INSTALL_OFFLINE_BUNDLE_MISSING",
        "Test-AlreadyCurrentByVersion",
        "already current: installed oraclemcp $installed matches target $Version",
        "ORACLEMCP_INSTALL_DOWNGRADE_REFUSED",
        "Backup-ExistingFile",
        "Install-ExecutableAtomically",
        "Write-UninstallPlan",
        "uninstall requires -Yes or -DryRun",
        "-Uninstall cannot be combined with -Update",
        "Write-PathGuidance",
        "Run oraclemcp doctor now?",
        "Print an MCP client wiring snippet now?",
        "Install and start the local oraclemcp service now?",
        "-HonorYes $false",
        "oraclemcp installer: next steps",
        "verify: $VerifyPosture",
        "update: $([bool]$Update)",
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
        "already_current_by_version()",
        "guard_downgrade()",
        "backup_existing_binary()",
        "ORACLEMCP_INSTALL_DOWNGRADE_REFUSED",
        "mv -f \"$tmp_dest\" \"$dest\"",
        "path_export_line()",
        "bin_dir_on_path()",
        "prompt_yes_no()",
        "print_next_steps()",
        "Add $BIN_DIR to PATH in $rc_file?",
        "Run oraclemcp doctor now?",
        "Print an MCP client wiring snippet now?",
        "oraclemcp installer: next steps",
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
        "export PATH='$NO_COSIGN_PREFIX/bin'",
        "oraclemcp --json setup --write --profile db_ro",
        "script -qefc",
        "already current: installed oraclemcp 1.1.0 matches target 1.1.0",
        "backup is not byte-identical to prior binary",
        "rollback from backup did not restore prior bytes",
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
        "bash scripts/installer_lint_and_offline_smoke.sh --log",
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
        "scripts/installer_lint_and_offline_smoke.sh --log",
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
    let release_workflow =
        fs::read_to_string(root.join(".github/workflows/release.yml")).expect("read release.yml");
    let npm_workflow = fs::read_to_string(root.join(".github/workflows/publish-npm.yml"))
        .expect("read publish-npm.yml");
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
    assert!(
        release_workflow.contains("name: validate npm wrapper package"),
        "release workflow must validate the npm wrapper without requiring npm registry auth"
    );
    assert!(
        release_workflow.contains("npm --prefix npm/oraclemcp test"),
        "release workflow must smoke-test the npm wrapper"
    );
    assert!(
        release_workflow.contains("npm pack ./npm/oraclemcp --dry-run"),
        "release workflow must validate the npm package contents"
    );
    assert!(
        !release_workflow.contains("npm publish"),
        "release workflow must not fail the signed release on externally gated npm publishing"
    );
    assert!(
        npm_workflow.contains("npm publish ./npm/oraclemcp --provenance"),
        "manual npm workflow must publish the local npm wrapper directory explicitly"
    );
    assert!(
        !release_workflow.contains("npm publish npm/oraclemcp "),
        "bare npm/oraclemcp is parsed as a package spec, not a local publish path"
    );
    assert!(
        !npm_workflow.contains("npm publish npm/oraclemcp "),
        "bare npm/oraclemcp is parsed as a package spec, not a local publish path"
    );
    assert!(
        npm_workflow.contains("npm install -g npm@11.5.1"),
        "npm publish workflow must use an npm CLI new enough for OIDC publishing"
    );
    assert!(
        npm_workflow.contains("NODE_VERSION: 22.17.0"),
        "npm publish workflow must use a Node version new enough for trusted publishing"
    );
    assert!(
        npm_workflow.contains("id-token: write"),
        "npm publish workflow must request OIDC id-token permission"
    );
    assert!(
        npm_workflow.contains("auth_mode:"),
        "manual npm publish workflow must expose explicit auth mode selection"
    );
    for mode in ["auto", "token", "oidc"] {
        assert!(
            npm_workflow.contains(&format!("- {mode}")),
            "manual npm publish workflow must support auth_mode={mode}"
        );
    }
    assert!(
        npm_workflow.contains("auth_mode=token requires the npm environment NPM_TOKEN secret"),
        "token mode must fail before publish when the npm token is absent"
    );
    assert!(
        npm_workflow.contains("trusted publishing/OIDC; npm must trust MuhDur/oraclemcp, workflow publish-npm.yml, environment npm"),
        "OIDC mode must name the exact trusted-publisher tuple operators need to configure"
    );
    assert!(
        npm_workflow.contains("unset NODE_AUTH_TOKEN NPM_CONFIG_USERCONFIG"),
        "OIDC mode must ignore a present NPM_TOKEN and setup-node npmrc"
    );
    assert!(
        npm_workflow.contains("npm whoami --registry=https://registry.npmjs.org/"),
        "token mode must preflight token authentication without treating whoami as an OIDC proof"
    );
    assert!(
        npm_workflow.contains("npm publish returned E403"),
        "npm publish workflow must explain npm permission failures"
    );
    assert!(
        npm_workflow.contains("unset NODE_AUTH_TOKEN NPM_CONFIG_USERCONFIG"),
        "npm publish workflow must fall back to OIDC when NPM_TOKEN is absent"
    );

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
        "ORACLEMCP_NPM_VERIFY",
        "DEFAULT_VERIFY_POSTURE = 'prefer'",
        "cosign:${verifyPosture}",
        "checksum-only",
        "authenticity unverified: cosign not installed",
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

// bead .15: an interactive install OFFERS zero-config TNS discovery (default
// No) and every install advertises the next-step command — but the shells never
// scan or parse tnsnames.ora themselves. Discovery lives in ONE place, the
// binary (`setup --discover`), which carries the consent gate and the config-ops
// write; the installers only invoke it, in Unix/PowerShell parity.
#[test]
fn installers_offer_consent_gated_tns_discovery_via_the_binary() {
    let root = repo_root();
    let sh = fs::read_to_string(root.join("install.sh")).expect("read install.sh");
    for needle in [
        "maybe_offer_discovery()",
        "Discover databases from tnsnames.ora now?",
        "\"$BIN_DIR/oraclemcp\" setup --discover",
        "discover databases from tnsnames.ora: %s setup --discover",
        "  maybe_offer_discovery\n",
    ] {
        assert!(
            sh.contains(needle),
            "install.sh must integrate binary-delegated discovery: {needle}"
        );
    }
    assert!(
        sh.contains("maybe_offer_discovery() {\n  if ! interactive_install; then"),
        "discovery is offered only in an interactive install (never scans non-interactively)"
    );

    let ps = fs::read_to_string(root.join("install.ps1")).expect("read install.ps1");
    for needle in [
        "function Invoke-OptionalDiscovery",
        "Discover databases from tnsnames.ora now?",
        "& $oraclemcp setup --discover",
        "    Invoke-OptionalDiscovery\n",
    ] {
        assert!(
            ps.contains(needle),
            "install.ps1 must reach discovery parity: {needle}"
        );
    }
}
