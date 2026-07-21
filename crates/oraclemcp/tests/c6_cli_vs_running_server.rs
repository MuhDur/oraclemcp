//! C6 fixture — the CLI while a server owns the state store.
//!
//! Plan §4-C6 / §A.1, bead `oraclemcp-091-c6-cli-vs-server-collision-6o0m9`.
//!
//! A running server holds a process-wide exclusive `flock` over the whole state
//! store (`FileStore::acquire_service_owner`). Every state-mutating CLI verb run
//! against that same store therefore *cannot* proceed — which is correct, and
//! entirely fine, provided the operator is told so.
//!
//! Today they are not. `ConfigOpsError::FileStore(_)` is folded into a catch-all
//! (`main.rs`) that reports `ORACLEMCP_SETUP_WRITE_FAILED` with the fixed text
//! "config workflow failed before completion" — the same code and the same
//! sentence you get for a full disk, a bad path, or a validation failure. The
//! one fact that makes the situation actionable, *another process owns this
//! store, stop it or point elsewhere*, is discarded at the very last step.
//!
//! Why no existing test catches it: every `file_store` test runs offline with a
//! single actor and no contention, and the operator-API tests call handlers
//! in-process, where the lock is already held by the caller. Contention between
//! a *live server* and a *separate CLI process* is exactly the configuration no
//! test creates — and exactly the one an operator hits the first time they try
//! to reconfigure a running service.
//!
//! The lock here is taken by this test process rather than by spawning
//! `serve`. That is deliberate: `flock` is held per open file description, so a
//! child process opening the same lock file contends identically, and the
//! fixture stays offline, fast, and free of a server's readiness race. What it
//! asserts is the CLI's behaviour under contention, which is the same either
//! way.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_config::CONFIG_PATH_ENV;
use oraclemcp_core::{FileStore, ServiceOwner};

/// Error codes that would tell an operator what actually happened. The fix is
/// free to choose the spelling; what it may not do is keep reporting a generic
/// write failure.
const ACTIONABLE_LOCK_CODES: [&str; 3] = [
    "ORACLEMCP_STATE_STORE_LOCKED",
    "ORACLEMCP_STATE_LOCKED",
    "ORACLEMCP_SERVICE_RUNNING",
];

/// The exact text today's catch-all produces. Named so the assertions can say
/// "not this" without restating it four times.
const GENERIC_FAILURE_TEXT: &str = "config workflow failed before completion";

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "oraclemcp-c6-{}-{stamp}-{label}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Take the store lock the way a running server does, and keep it for the
/// lifetime of the returned guard.
fn own_the_store(state_home: &Path) -> ServiceOwner {
    let root = state_home.join("oraclemcp");
    fs::create_dir_all(&root).expect("create state root");
    let store = FileStore::open(&root).expect("open state store");
    store
        .acquire_service_owner("c6-fixture-server")
        .expect("the fixture is the first owner, so this must succeed")
}

fn run_cli(args: &[&str], dir: &Path, state_home: &Path, config: &Path) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    cmd.args(args)
        .env(CONFIG_PATH_ENV, config)
        .env("XDG_STATE_HOME", state_home)
        .env("HOME", dir)
        .env("ORACLEMCP_TOOLS_DIR", dir.join("tools.d"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().expect("spawn oraclemcp");
    let output = child.wait_with_output().expect("collect CLI output");
    assert!(
        output.status.code().is_some(),
        "the CLI must exit, not be signalled"
    );
    output
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A state-mutating CLI verb, run while the store is owned.
struct Collision {
    label: &'static str,
    args: Vec<String>,
}

fn collisions() -> Vec<Collision> {
    vec![
        Collision {
            label: "setup --write",
            args: [
                "--json",
                "setup",
                "--write",
                "--profile",
                "c6_ro",
                "--credential-env",
                "C6_PASSWORD",
            ]
            .iter()
            .map(|a| (*a).to_owned())
            .collect(),
        },
        Collision {
            label: "clients revoke",
            args: ["--json", "clients", "revoke", "c6-unknown-client"]
                .iter()
                .map(|a| (*a).to_owned())
                .collect(),
        },
    ]
}

/// Green half: whatever else is true, a CLI verb that collides with a running
/// server must not silently appear to succeed. This is the floor, and it holds
/// today.
#[test]
fn c6_state_mutating_cli_verbs_fail_while_the_store_is_owned() {
    let dir = temp_dir("owned-store-fails");
    let state_home = dir.join("state");
    let config = dir.join("profiles.toml");
    fs::create_dir_all(dir.join("tools.d")).expect("create tools dir");
    let _owner = own_the_store(&state_home);

    for collision in collisions() {
        let args: Vec<&str> = collision.args.iter().map(String::as_str).collect();
        let output = run_cli(&args, &dir, &state_home, &config);
        assert_ne!(
            output.status.code(),
            Some(0),
            "`{}` must not report success while another process owns the store; output: {}",
            collision.label,
            combined(&output)
        );
    }
}

/// The failing half of C6.
///
/// Every one of these collisions is the same situation with the same remedy,
/// and the operator is told none of it. The message is indistinguishable from a
/// full disk or an unwritable path, so the natural next move — retry, or start
/// editing the config by hand — is the wrong one, and the running server is
/// never suspected.
///
/// Bead `oraclemcp-091-a2a-*` (A2a) maps `FileStoreError::Locked` to a distinct
/// code before the catch-all. Flipping this green means removing the
/// `#[ignore]`; the assertions must not change. The fix may pick any of
/// [`ACTIONABLE_LOCK_CODES`], or extend that list with a better name — what it
/// may not do is keep emitting the generic write failure.
#[test]
fn c6_a_store_collision_names_the_lock_holder_and_the_remedy() {
    let dir = temp_dir("owned-store-diagnostic");
    let state_home = dir.join("state");
    let config = dir.join("profiles.toml");
    fs::create_dir_all(dir.join("tools.d")).expect("create tools dir");
    let _owner = own_the_store(&state_home);

    for collision in collisions() {
        let args: Vec<&str> = collision.args.iter().map(String::as_str).collect();
        let output = run_cli(&args, &dir, &state_home, &config);
        let text = combined(&output);

        assert!(
            ACTIONABLE_LOCK_CODES.iter().any(|code| text.contains(code)),
            "`{}` must report that the state store is locked, using one of {:?}; \
             got: {text}",
            collision.label,
            ACTIONABLE_LOCK_CODES
        );
        assert!(
            !text.contains(GENERIC_FAILURE_TEXT),
            "`{}` must not fall back to the catch-all text, which reads identically to a \
             full disk or a bad path; got: {text}",
            collision.label
        );
    }
}
