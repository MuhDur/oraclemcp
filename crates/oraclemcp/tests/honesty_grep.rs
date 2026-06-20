//! Honesty-grep gate (bead F1a / plan §8 item 8) — a `cargo test` mirror of
//! `scripts/oraclemcp_honesty_grep.sh`, so over-claiming framing in
//! release-visible text fails the test suite, not only CI.
//!
//! oraclemcp is GOVERNED and least-privilege (a fail-closed SQL guard with a
//! confirmation-gated operating-level ladder, read-only by default, escalation
//! up to ADMIN within per-profile ceilings) — never "safe by default", a
//! "read-only binary", or "fully audited". Add a `honesty-allow: <reason>`
//! marker to a line that legitimately needs one of these phrases.

use std::path::{Path, PathBuf};

// Keep aligned with scripts/oraclemcp_honesty_grep.sh.  honesty-allow: pattern definition
const FORBIDDEN: &[&str] = &[
    "safe-by-default",
    "safe by default",
    "read-only binary",
    "fully audited",
];

fn workspace_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("Cargo.toml").exists() && dir.join("crates").is_dir() {
            return dir;
        }
        assert!(dir.pop(), "could not find workspace root");
    }
}

fn is_scanned(p: &Path) -> bool {
    let s = p.to_string_lossy();
    let ext_ok = matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("md" | "rs" | "toml")
    );
    let excluded = s.contains("/tests/")
        || s.ends_with("tests.rs")
        || s.contains("/fuzz/")
        || s.contains("/target/");
    ext_ok && !excluded
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, "target" | ".git") {
                continue;
            }
            collect(&p, out);
        } else if is_scanned(&p) {
            out.push(p);
        }
    }
}

#[test]
fn no_overclaiming_framing_in_release_visible_text() {
    let root = workspace_root();
    let mut files = vec![root.join("README.md")];
    for sub in ["docs", "crates"] {
        collect(&root.join(sub), &mut files);
    }

    let mut violations = Vec::new();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            if line.contains("honesty-allow") {
                continue;
            }
            let lc = line.to_ascii_lowercase();
            if FORBIDDEN.iter().any(|p| lc.contains(p)) {
                violations.push(format!("{}:{}: {}", f.display(), i + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "over-claiming framing in release-visible text (reframe to governed/least-privilege, \
         or add a `honesty-allow: <reason>` marker):\n{}",
        violations.join("\n")
    );
}
