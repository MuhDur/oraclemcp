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
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_config::CONFIG_PATH_ENV;
use oraclemcp_core::{FileStore, ServiceOwner, TlsMaterial, build_server_config};
use rustls::{ServerConnection, StreamOwned};

/// Error codes that would tell an operator what actually happened. The fix is
/// free to choose the spelling; what it may not do is keep reporting a generic
/// write failure.
const ACTIONABLE_LOCK_CODES: [&str; 4] = [
    "ORACLEMCP_STATE_STORE_LOCKED",
    "ORACLEMCP_STATE_LOCKED",
    "ORACLEMCP_SERVICE_RUNNING",
    "ORACLEMCP_SETUP_ONLINE_WORKFLOW_FAILED",
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

fn ca_cert() -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params =
        rcgen::CertificateParams::new(vec!["oraclemcp-c6-ca".to_owned()]).expect("CA params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key = rcgen::KeyPair::generate().expect("CA key");
    let cert = params.self_signed(&key).expect("self-signed CA");
    (cert, key)
}

fn cert_signed_by(
    name: &str,
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
) -> (Vec<u8>, Vec<u8>) {
    let params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("cert params");
    let key = rcgen::KeyPair::generate().expect("cert key");
    let cert = params
        .signed_by(&key, ca_cert, ca_key)
        .expect("cert signed by test CA");
    (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
}

fn response(body: serde_json::Value) -> Vec<u8> {
    let body = serde_json::to_vec(&body).expect("response JSON");
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body)
    .collect()
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_https_request(stream: &mut StreamOwned<ServerConnection, TcpStream>) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let body_end = loop {
        let count = stream.read(&mut buffer).expect("read TLS request");
        assert_ne!(count, 0, "client closed before completing request headers");
        bytes.extend_from_slice(&buffer[..count]);
        let Some(headers_end) = header_end(&bytes) else {
            continue;
        };
        let headers = std::str::from_utf8(&bytes[..headers_end]).expect("UTF-8 headers");
        let content_length = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .expect("content length")
            .parse::<usize>()
            .expect("numeric content length");
        break headers_end + 4 + content_length;
    };
    while bytes.len() < body_end {
        let count = stream.read(&mut buffer).expect("read TLS request body");
        assert_ne!(count, 0, "client closed before completing request body");
        bytes.extend_from_slice(&buffer[..count]);
    }
    String::from_utf8(bytes).expect("UTF-8 request")
}

fn spawn_mtls_config_listener(
    config_target: PathBuf,
    server_cert: Vec<u8>,
    server_key: Vec<u8>,
    client_ca: Vec<u8>,
) -> (
    u16,
    std::thread::JoinHandle<Vec<(String, serde_json::Value)>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let port = listener.local_addr().expect("control listener addr").port();
    let tls = build_server_config(&TlsMaterial {
        cert_chain_pem: server_cert,
        private_key_pem: server_key,
        client_ca_pem: Some(client_ca),
    })
    .expect("mTLS listener config");
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for response_body in [
            serde_json::json!({
                "source": "config_ops",
                "preview": {
                    "target_path": config_target,
                    "preview_token": "c6-reviewed-preview",
                    "draft_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                }
            }),
            serde_json::json!({
                "source": "config_ops",
                "outcome": {
                    "rollback_id": "c6-rollback",
                    "reload": { "status": "applied" }
                }
            }),
        ] {
            let (tcp, _) = listener.accept().expect("accept mTLS control request");
            let connection = ServerConnection::new(Arc::clone(&tls)).expect("start TLS server");
            let mut stream = StreamOwned::new(connection, tcp);
            let request = read_https_request(&mut stream);
            let mut lines = request.split("\r\n");
            let path = lines
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .expect("request path")
                .to_owned();
            let body = request
                .split_once("\r\n\r\n")
                .map(|(_, body)| body)
                .expect("request body");
            requests.push((path, serde_json::from_str(body).expect("JSON request body")));
            stream
                .write_all(&response(response_body))
                .and_then(|()| stream.flush())
                .expect("write control response");
            stream.conn.send_close_notify();
            stream.flush().expect("flush TLS close notify");
        }
        requests
    });
    (port, handle)
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

/// A2c's live-service path. The server keeps the service-owner flock while the
/// CLI performs the same reviewed config workflow over a separately
/// authenticated mTLS connection. This is deliberately a wire fixture: it
/// proves the CLI does not sidestep the owner or mutate `profiles.toml` itself.
#[test]
fn c6_setup_write_uses_authenticated_control_listener_while_store_is_owned() {
    let dir = temp_dir("owned-store-online-setup");
    let state_home = dir.join("state");
    let config = dir.join("profiles.toml");
    fs::create_dir_all(dir.join("tools.d")).expect("create tools dir");
    let _owner = own_the_store(&state_home);

    let (ca, ca_key) = ca_cert();
    let (server_cert, server_key) = cert_signed_by("localhost", &ca, &ca_key);
    let (operator_cert, operator_key) = cert_signed_by("operator", &ca, &ca_key);
    let cert_path = dir.join("operator-cert.pem");
    let key_path = dir.join("operator-key.pem");
    let ca_path = dir.join("control-ca.pem");
    fs::write(&cert_path, &operator_cert).expect("write operator cert");
    fs::write(&key_path, &operator_key).expect("write operator key");
    fs::write(&ca_path, ca.pem()).expect("write control CA");

    let (port, control) = spawn_mtls_config_listener(
        config.clone(),
        server_cert,
        server_key,
        ca.pem().into_bytes(),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_oraclemcp"))
        .args([
            "--json",
            "setup",
            "--write",
            "--profile",
            "c6_ro",
            "--credential-env",
            "C6_PASSWORD",
        ])
        .env(CONFIG_PATH_ENV, &config)
        .env("XDG_STATE_HOME", &state_home)
        .env("HOME", &dir)
        .env("ORACLEMCP_TOOLS_DIR", dir.join("tools.d"))
        .env("ORACLEMCP_CONTROL_URL", format!("https://localhost:{port}"))
        .env("ORACLEMCP_OPERATOR_CERT", cert_path)
        .env("ORACLEMCP_OPERATOR_KEY", key_path)
        .env("ORACLEMCP_CONTROL_CA", ca_path)
        .output()
        .expect("run setup through control listener");
    assert_eq!(
        output.status.code(),
        Some(0),
        "setup must use the running service rather than fail on its owner lock: {}",
        combined(&output)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("setup JSON output");
    assert_eq!(
        payload["write"]["source"],
        serde_json::json!("authenticated_control_listener")
    );
    assert_eq!(
        payload["write"]["outcome"]["outcome"]["reload"]["status"],
        "applied"
    );

    let requests = control.join().expect("control listener joins");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].0, "/operator/v1/config/draft");
    assert_eq!(requests[1].0, "/operator/v1/config/apply");
    assert_eq!(requests[1].1["preview_token"], "c6-reviewed-preview");
    assert_eq!(requests[1].1["confirm_preview"], true);
    assert_eq!(
        requests[0].1["draft_toml"], requests[1].1["draft_toml"],
        "the exact reviewed draft must be the draft applied by the running service"
    );
}
