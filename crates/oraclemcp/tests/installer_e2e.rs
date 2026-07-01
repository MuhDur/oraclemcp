use std::path::{Path, PathBuf};
use std::process::Command;

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
