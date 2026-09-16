//! Regression for `oraclemcp-2q4em.8`: `oraclemcp dashboard` ignored the live
//! listener recorded in `<state>/oraclemcp/service-instance.json` and silently
//! probed the default `:7070`.
//!
//! The test drives the built binary end to end. A real `serve` binds an
//! ephemeral non-default loopback port under an isolated `XDG_STATE_HOME`; then
//! `--json dashboard` runs WITHOUT `--url` and must pair against that recorded
//! port (and the pairing form must answer `GET` 200). A second case proves the
//! typed unreachable error names BOTH candidates and the lock path.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

const DEFAULT_URL: &str = "http://127.0.0.1:7070";

/// One isolated operator home: an `XDG_STATE_HOME` for the service-instance
/// lock, an `XDG_RUNTIME_DIR` for pairing tickets, and a minimal offline config.
struct TestHome {
    root: PathBuf,
    state: PathBuf,
    runtime: PathBuf,
    config: PathBuf,
    tools: PathBuf,
}

impl TestHome {
    fn new(label: &str) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/dashboard-listener-discovery")
            .join(format!("{}-{stamp}-{label}", std::process::id()));
        let state = root.join("state");
        let runtime = root.join("runtime");
        let tools = root.join("tools.d");
        for dir in [&state, &runtime, &tools] {
            fs::create_dir_all(dir).expect("create isolated dir");
        }
        let config = root.join("profiles.toml");
        fs::write(
            &config,
            "schema_version = 2\n[http]\njson_response = true\nstateful = false\n",
        )
        .expect("write isolated config");
        Self {
            root,
            state,
            runtime,
            config,
            tools,
        }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
        cmd.env("ORACLEMCP_CONFIG", &self.config)
            .env("XDG_STATE_HOME", &self.state)
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env("HOME", &self.root)
            .env("ORACLEMCP_TOOLS_DIR", &self.tools)
            .env_remove("ORACLEMCP_STDIO_TOKEN")
            .env_remove("RUST_LOG");
        cmd
    }

    fn lock_path(&self) -> PathBuf {
        self.state.join("oraclemcp").join("service-instance.json")
    }
}

struct ServeChild {
    child: Child,
    stdout: Option<thread::JoinHandle<Vec<u8>>>,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
}

impl Drop for ServeChild {
    fn drop(&mut self) {
        if self.child.try_wait().expect("poll serve").is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(handle) = self.stdout.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr.take() {
            let _ = handle.join();
        }
    }
}

fn reserve_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    listener.local_addr().expect("read reserved addr")
}

fn spawn_serve(home: &TestHome, addr: SocketAddr) -> ServeChild {
    let mut child = home
        .command()
        .args([
            "--json",
            "serve",
            "--listen",
            &addr.to_string(),
            "--allow-no-auth",
            "--http-json-response",
            "--http-allowed-host",
            &addr.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let stdout = drain(child.stdout.take().expect("serve stdout"));
    let stderr = drain(child.stderr.take().expect("serve stderr"));
    ServeChild {
        child,
        stdout: Some(stdout),
        stderr: Some(stderr),
    }
}

fn drain<R: Read + Send + 'static>(mut pipe: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
}

fn wait_for_recorded_listener(home: &TestHome, addr: SocketAddr, serve: &mut ServeChild) {
    let lock = home.lock_path();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(body) = fs::read_to_string(&lock)
            && let Ok(value) = serde_json::from_str::<Value>(&body)
            && value["listen"] == json!(addr.to_string())
        {
            return;
        }
        if let Some(status) = serve.child.try_wait().expect("poll serve") {
            panic!("serve exited before recording the listener (status {status})");
        }
        assert!(
            Instant::now() < deadline,
            "service-instance.json never recorded {}",
            addr
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Output {
    let child = cmd.spawn().expect("spawn oraclemcp");
    let mut child = child;
    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return Output {
                status,
                stdout: stdout
                    .map(|h| h.join().unwrap_or_default())
                    .unwrap_or_default(),
                stderr: stderr
                    .map(|h| h.join().unwrap_or_default())
                    .unwrap_or_default(),
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("oraclemcp did not exit within {timeout:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn http_get_status(addr: SocketAddr, path: &str) -> u16 {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .expect("connect to served listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("write GET request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read GET response");
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in response: {response:?}"))
}

#[test]
fn dashboard_without_url_pairs_with_the_recorded_nondefault_listener() {
    let home = TestHome::new("recorded-listener");
    let addr = reserve_loopback_addr();
    assert_ne!(
        addr.port(),
        7070,
        "regression only means something on a non-default port"
    );
    let mut serve = spawn_serve(&home, addr);
    wait_for_recorded_listener(&home, addr, &mut serve);

    let output = run_with_timeout(
        {
            let mut cmd = home.command();
            cmd.args(["--json", "dashboard", "--no-open"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        },
        Duration::from_secs(30),
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "dashboard without --url must resolve the recorded listener; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "dashboard --json stderr should be empty on success: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("dashboard JSON");
    assert_eq!(value["kind"], "dashboard_pairing");
    assert_eq!(value["source"], "service-instance");
    assert_eq!(value["listener"], addr.to_string());
    let url = value["url"].as_str().expect("pairing url");
    assert_eq!(url, format!("http://{addr}/dashboard/pair"));
    assert_eq!(
        value["pairing_code"].as_str().map(str::len),
        Some(64),
        "one-time code must be the full-length secret-free ticket"
    );

    let status = http_get_status(addr, "/dashboard/pair");
    assert_eq!(status, 200, "the pairing form must be served at {url}");
}

#[test]
fn dashboard_without_url_reports_both_candidates_and_lock_path_when_unreachable() {
    let home = TestHome::new("unreachable-candidates");
    // Reserve then release a port: the recorded listener is a closed socket.
    let dead = reserve_loopback_addr();

    let lock = home.lock_path();
    fs::create_dir_all(lock.parent().expect("lock parent")).expect("state dir");
    // Written WITHOUT `scheme`: an older lock must still resolve and default to
    // plaintext http.
    fs::write(
        &lock,
        json!({
            "schema_version": 1,
            "pid": 4_194_304_u32,
            "listen": dead.to_string(),
            "started_unix_ms": 1,
            "token": "test-token",
        })
        .to_string(),
    )
    .expect("write stale lock");

    let output = run_with_timeout(
        {
            let mut cmd = home.command();
            cmd.args(["--json", "dashboard", "--no-open"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        },
        Duration::from_secs(30),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let err: Value = serde_json::from_slice(&output.stderr).expect("dashboard stderr JSON");
    assert_eq!(err["code"], "ORACLEMCP_DASHBOARD_SERVICE_UNREACHABLE");
    assert_eq!(err["source"], "service-instance");
    assert_eq!(err["listener"], dead.to_string());
    assert_eq!(err["lock_path"], lock.display().to_string());

    let recorded = format!("http://{dead}");
    let candidates: Vec<&str> = err["candidates"]
        .as_array()
        .expect("candidates array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        candidates.contains(&recorded.as_str()),
        "candidates must name the recorded listener: {candidates:?}"
    );
    assert!(
        candidates.contains(&DEFAULT_URL),
        "candidates must name the default fallback: {candidates:?}"
    );
}
