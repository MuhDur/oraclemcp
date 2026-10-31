//! Honesty-grep gate (bead F1a / plan §8 item 8) — a `cargo test` mirror of
//! `scripts/oraclemcp_honesty_grep.sh`, so over-claiming framing in
//! release-visible text, including `server.json`, fails the test suite, not
//! only CI.
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
    // Normalize to `/` so the path-substring exclusions below match on Windows
    // too: without this, a Windows path like `crates\oraclemcp\tests\honesty_grep.rs`
    // never matches `/tests/`, so no test file is excluded and this scanner reads
    // its own FORBIDDEN phrase list as violations.
    let s = p.to_string_lossy().replace('\\', "/");
    let is_dockerfile = p
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "Dockerfile" || n.ends_with(".Dockerfile"));
    let ext_ok = is_dockerfile
        || matches!(
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
    let mut files = vec![
        root.join("README.md"),
        root.join("server.json"),
        root.join("Dockerfile"),
    ];
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

fn stale_driver_or_image_claim(line: &str) -> bool {
    let line = line.to_ascii_lowercase();
    line.contains("plsql-intelligence-latest")
        || (line.contains("driver-cx")
            && (line.contains("frozen") || line.contains("discontinued")))
}

#[test]
fn driver_image_claim_matcher_rejects_retired_states() {
    for stale in [
        "image: ghcr.io/muhdur/oraclemcp:plsql-intelligence-latest",
        "the frozen, async `oraclemcp-driver-cx` driver",
        "Driver-cx is DISCONTINUED",
        "discontinued driver-cx",
    ] {
        assert!(stale_driver_or_image_claim(stale), "{stale}");
    }
    for current in [
        "The maintained primary driver is oraclemcp-driver-cx.",
        "The release has one ghcr.io/muhdur/oraclemcp image.",
        "The unrelated schema is frozen.",
    ] {
        assert!(!stale_driver_or_image_claim(current), "{current}");
    }
}

#[test]
fn maintained_docs_do_not_revive_retired_driver_or_image_claims() {
    let root = workspace_root();
    let mut files = vec![root.join("README.md"), root.join("AGENTS.md")];
    collect(&root.join("docs"), &mut files);
    let mut violations = Vec::new();
    for file in files {
        if file.starts_with(root.join("docs/plan"))
            || file
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("CHANGELOG"))
        {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("read maintained documentation");
        for (index, line) in text.lines().enumerate() {
            if !line.contains("honesty-allow") && stale_driver_or_image_claim(line) {
                violations.push(format!("{}:{}: {line}", file.display(), index + 1));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "stale driver/image claims:\n{}",
        violations.join("\n")
    );
}

#[test]
fn call_routine_absent_from_agent_surface() {
    let root = workspace_root();
    let mut files = vec![
        root.join("crates/oraclemcp/Cargo.toml"),
        root.join("crates/oraclemcp-core/Cargo.toml"),
    ];
    collect(&root.join("crates/oraclemcp/src"), &mut files);
    collect(&root.join("crates/oraclemcp-core/src"), &mut files);

    let mut violations = Vec::new();
    let mut allowed_calls = 0;
    for f in &files {
        let s = f.to_string_lossy().replace('\\', "/"); // normalize for Windows paths
        if s.contains("/tests/") || s.ends_with("tests.rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        let relative = f.strip_prefix(&root).expect("scanned workspace file");
        let (allowed, rejected) = native_call_sites(relative, &text);
        allowed_calls += allowed;
        violations.extend(
            rejected
                .into_iter()
                .map(|(line, source)| format!("{}:{line}: {source}", f.display())),
        );
    }

    assert_native_boundary(allowed_calls, &violations);
}

fn assert_native_boundary(allowed_calls: usize, violations: &[String]) {
    assert!(
        violations.is_empty(),
        "`call_routine` stays adapter-internal except the single signed-plan runner; \
         oraclemcp-wbbn6 must remove that exception:\n{}",
        violations.join("\n")
    );
    assert_eq!(
        allowed_calls, 1,
        "exactly one signed-plan runner call is permitted until oraclemcp-wbbn6 moves verification into the adapter and removes this exception"
    );
}

/// This temporary exception follows the named, module-level function, never a
/// line number or an entire file. Rustfmt places its closing brace at column
/// zero, so product functions after it remain outside the permitted range.
fn native_call_sites(path: &Path, text: &str) -> (usize, Vec<(usize, String)>) {
    let exact_file =
        path.to_string_lossy().replace('\\', "/") == "crates/oraclemcp/src/dispatch/custom_tool.rs";
    let mut runner = None;
    let mut start = None;
    let mut offset = 0;
    let mut definitions = 0;
    for line in text.split_inclusive('\n') {
        let source = line.trim_end_matches(['\r', '\n']);
        if source
            .strip_prefix("async fn ")
            .and_then(|rest| rest.split_once('('))
            .is_some_and(|(name, _)| name.trim() == "run_package_wire")
        {
            definitions += 1;
            start = Some(offset);
        }
        if source == "}"
            && let Some(start) = start.take()
        {
            runner = Some(start..offset + line.len());
        }
        offset += line.len();
    }
    let mut allowed = 0;
    let mut rejected = Vec::new();
    for (offset, _) in text.match_indices("call_routine") {
        let method_call = text[..offset].trim_end().ends_with('.')
            && text[offset + "call_routine".len()..]
                .trim_start()
                .starts_with('(');
        if exact_file
            && definitions == 1
            && method_call
            && runner.as_ref().is_some_and(|range| range.contains(&offset))
        {
            allowed += 1;
        } else {
            let line = text[..offset].bytes().filter(|byte| *byte == b'\n').count() + 1;
            rejected.push((
                line,
                text.lines().nth(line - 1).unwrap_or("").trim().to_owned(),
            ));
        }
    }
    (allowed, rejected)
}

#[test]
fn native_runner_exception_is_exact_and_does_not_hide_product_after_it() {
    let path = Path::new("crates/oraclemcp/src/dispatch/custom_tool.rs");
    let runner =
        "async fn run_package_wire(\n) {\n    conn.call_routine(cx, sql, args).await;\n}\n";
    assert_eq!(native_call_sites(path, runner), (1, Vec::new()));
    assert_eq!(
        native_call_sites(Path::new("crates/oraclemcp-core/src/server.rs"), runner)
            .1
            .len(),
        1
    );
    for extra in [
        "async fn other() { conn.call_routine(cx, sql, args).await; }\n",
        "const DESCRIPTOR: &str = \"oracle_call_routine\";\n",
    ] {
        let (allowed, rejected) = native_call_sites(path, &format!("{runner}{extra}"));
        assert_eq!(allowed, 1);
        assert_eq!(rejected.len(), 1);
    }
    let twice = runner.replace(
        "    conn.",
        "    conn.call_routine(cx, sql, args).await; conn.",
    );
    assert_eq!(
        native_call_sites(path, &twice).0,
        2,
        "the enclosing gate must refuse a second call even on the same line"
    );
    for count in [0, 2] {
        assert!(
            std::panic::catch_unwind(|| assert_native_boundary(count, &[])).is_err(),
            "missing or second calls must fail the same gate assertion"
        );
    }
}
