//! #51 process-level proof (bead .7.7): a second `oraclemcp serve` sharing the
//! first one's state directory completes the MCP handshake and refuses every
//! tool call with a typed lock error naming the first instance's pid, then
//! recovers without a restart once the first instance exits.
//!
//! Both instances are the built executable, driven over its real stdio or
//! HTTP boundary by a raw JSON-RPC client. No in-process dispatcher stands in
//! for either process. Each case appends one JSONL row to
//! `target/e2e/w4/<lane>/rel012_i51_second_instance.jsonl`. The offline cases
//! need no database. The live recovery case (feature `live-xe`) also proves,
//! through `V$SESSION`, that the locked instance opened no Oracle session.
//!
//! `ORACLEMCP_W4_BINARY` points the test at a release-profile binary, and each
//! row records which binary ran.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

const PROTOCOL_VERSION: &str = "2025-11-25";
const CASE_ID: &str = "w4_runtime_issue51_second_instance_typed_locked";
/// Synthetic signing key: it only arms the audit chain in a throwaway state
/// directory.
const AUDIT_KEY: &str = "i51-synthetic-audit-key-0123456789abcdef";
const REPLY_TIMEOUT: Duration = Duration::from_secs(60);

fn binary() -> PathBuf {
    std::env::var_os("ORACLEMCP_W4_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_oraclemcp")))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves")
}

/// One throwaway home whose state directory both instances share.
struct SharedHome {
    root: PathBuf,
    state: PathBuf,
}

impl SharedHome {
    fn new(label: &str) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = repo_root()
            .join("target/w4-issue51")
            .join(format!("{}-{stamp}-{label}", std::process::id()));
        let state = root.join("state");
        fs::create_dir_all(&state).expect("create shared state dir");
        fs::create_dir_all(root.join("tools.d")).expect("create tools dir");
        Self { root, state }
    }

    fn config(&self, name: &str, body: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, format!("schema_version = 2\n{body}")).expect("write config");
        path
    }

    fn command(&self, config: &Path) -> Command {
        let mut cmd = Command::new(binary());
        // `ORACLEMCP_*` variables are config overrides: the test's own knobs
        // (lane, binary, credentials) must not reach the server.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("ORACLEMCP_") {
                cmd.env_remove(key);
            }
        }
        cmd.env("ORACLEMCP_CONFIG", config)
            .env("XDG_STATE_HOME", &self.state)
            .env("HOME", &self.root)
            .env("ORACLEMCP_TOOLS_DIR", self.root.join("tools.d"))
            .env("ORACLEMCP_AUDIT_KEY", AUDIT_KEY)
            .env_remove("RUST_LOG");
        cmd
    }
}

/// A spawned `serve` over stdio with a line-oriented raw JSON-RPC client.
struct StdioInstance {
    child: Child,
    stdin: Option<ChildStdin>,
    replies: Receiver<String>,
}

impl StdioInstance {
    fn spawn(home: &SharedHome, config: &Path, extra_env: &[(&str, &str)]) -> Self {
        let mut cmd = home.command(config);
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        // Operator stderr is kept next to the config for diagnosis.
        let stderr = fs::File::create(config.with_extension("stderr")).expect("stderr file");
        let mut child = cmd
            .args(["--json", "serve", "--allow-no-auth"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .expect("spawn oraclemcp serve (stdio)");
        let stdout = child.stdout.take().expect("stdout piped");
        let (sender, replies) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if !line.trim().is_empty() && sender.send(line).is_err() {
                    break;
                }
            }
        });
        let stdin = child.stdin.take();
        Self {
            child,
            stdin,
            replies,
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn request(&mut self, frame: &Value) -> Value {
        let stdin = self.stdin.as_mut().expect("stdin open");
        let mut line = serde_json::to_vec(frame).expect("serialize frame");
        line.push(b'\n');
        stdin.write_all(&line).expect("write frame");
        stdin.flush().expect("flush frame");
        if frame.get("id").is_none() {
            return Value::Null;
        }
        let deadline = Instant::now() + REPLY_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let reply = self
                .replies
                .recv_timeout(remaining)
                .unwrap_or_else(|error| panic!("no stdio reply to {frame} ({error})"));
            let value: Value = serde_json::from_str(&reply).expect("stdio reply is JSON");
            // Skip server notifications; answer the request's own id.
            if value.get("id") == frame.get("id") {
                return value;
            }
        }
    }

    fn handshake(&mut self, client: &str) -> (Value, Value) {
        let initialize = self.request(&initialize_request(1, client));
        self.request(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        let tools = self.request(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
        (initialize, tools)
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for StdioInstance {
    fn drop(&mut self) {
        drop(self.stdin.take());
        self.kill();
    }
}

struct HttpInstance {
    child: Child,
    addr: SocketAddr,
}

impl HttpInstance {
    fn spawn(home: &SharedHome, config: &Path) -> Self {
        let addr = TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("reserve loopback port");
        let mut child = home
            .command(config)
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
            .stdout(Stdio::null())
            .stderr(fs::File::create(config.with_extension("stderr")).expect("stderr file"))
            .spawn()
            .expect("spawn oraclemcp serve (HTTP)");
        let deadline = Instant::now() + REPLY_TIMEOUT;
        while TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_err() {
            if let Some(status) = child.try_wait().expect("poll HTTP server") {
                panic!("HTTP serve exited before listening ({status}); the lock must not stop it");
            }
            assert!(Instant::now() < deadline, "HTTP serve never listened");
            std::thread::sleep(Duration::from_millis(25));
        }
        Self { child, addr }
    }

    /// POST one frame; returns the HTTP status and the JSON body.
    fn request(&self, frame: &Value) -> (u16, Value) {
        let body = frame.to_string();
        let request = format!(
            "POST /mcp HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\n\
             accept: application/json, text/event-stream\r\nmcp-protocol-version: \
             {PROTOCOL_VERSION}\r\ncontent-length: {len}\r\nconnection: close\r\n\r\n{body}",
            addr = self.addr,
            len = body.len()
        );
        let mut stream = TcpStream::connect(self.addr).expect("connect HTTP client");
        stream
            .set_read_timeout(Some(REPLY_TIMEOUT))
            .expect("read timeout");
        stream.write_all(request.as_bytes()).expect("write request");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("finish request");
        let mut raw = String::new();
        stream.read_to_string(&mut raw).expect("read response");
        let (head, body) = raw
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("HTTP response has a body: {raw:?}"));
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("HTTP status line: {head}"));
        let body = serde_json::from_str(body).unwrap_or_else(|e| panic!("JSON body ({e}): {body}"));
        (status, body)
    }
}

impl Drop for HttpInstance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn initialize_request(id: u64, client: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": client, "version": "0.0.0-i51"}
        }
    })
}

fn query_call(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": "oracle_query", "arguments": {"sql": "SELECT 1 AS one FROM dual"}}
    })
}

fn handshake_ok(initialize: &Value, tools: &Value) -> bool {
    initialize["result"]["serverInfo"]["name"] == json!("oraclemcp")
        && tools["result"]["tools"]
            .as_array()
            .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == "oracle_query"))
}

/// The typed refusal: names `code` and the holder pid, and says nothing ran.
fn typed_lock(reply: &Value, code: &str, holder_pid: u32) -> bool {
    let text = reply.to_string();
    text.contains(code)
        && text.contains(&format!("(pid {holder_pid})"))
        && text.contains("executed nothing")
}

fn any_lock(reply: &Value) -> bool {
    let text = reply.to_string();
    text.contains("ORACLEMCP_AUDIT_LOG_LOCKED") || text.contains("ORACLEMCP_SERVICE_OWNER_LOCKED")
}

fn doctor_json(home: &SharedHome, config: &Path) -> String {
    let output = home
        .command(config)
        .args(["--json", "doctor"])
        .stdin(Stdio::null())
        .output()
        .expect("run oraclemcp doctor");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn emit_row(lane: &str, row: &Value) {
    let dir = repo_root().join("target/e2e/w4").join(lane);
    fs::create_dir_all(&dir).expect("evidence dir");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("rel012_i51_second_instance.jsonl"))
        .expect("open evidence JSONL");
    writeln!(file, "{row}").expect("append evidence row");
}

/// stdio: instance 2 shares instance 1's default audit log. It completes the
/// handshake, refuses tool calls with ORACLEMCP_AUDIT_LOG_LOCKED naming
/// instance 1's pid, `doctor` reports `audit_log_locked`, and once instance 1
/// exits the next call is no longer refused by the lock.
#[test]
fn w4_runtime_issue51_second_instance_typed_locked() {
    let started = Instant::now();
    let home = SharedHome::new("stdio");
    let config = home.config("serve.toml", "");

    let mut first = StdioInstance::spawn(&home, &config, &[]);
    let (first_init, _) = first.handshake("i51-first");
    assert!(
        first_init.get("result").is_some(),
        "instance 1 starts: {first_init}"
    );
    let holder = first.pid();

    let mut second = StdioInstance::spawn(&home, &config, &[]);
    let (initialize, tools) = second.handshake("i51-second");
    let locked = [
        second.request(&query_call(3)),
        second.request(&query_call(4)),
    ];
    let doctor = doctor_json(&home, &config);
    first.kill();
    let recovered = second.request(&query_call(5));

    let handshake = handshake_ok(&initialize, &tools);
    let typed = locked
        .iter()
        .all(|reply| typed_lock(reply, "ORACLEMCP_AUDIT_LOG_LOCKED", holder));
    let doctor_reports =
        doctor.contains("audit_log_locked") && doctor.contains(&format!("(pid {holder})"));
    let unlocked = !any_lock(&recovered);
    emit_row(
        "offline",
        &json!({
            "case_id": CASE_ID,
            "manifest_case": "rel012_i51_second_instance",
            "variant": "stdio_audit_log_locked",
            "transport": "stdio",
            "binary": binary().display().to_string(),
            "holder_pid": holder,
            "handshake_completed": handshake,
            "typed_lock_refusals": typed,
            "doctor_audit_log_locked": doctor_reports,
            "recovered_without_restart": unlocked,
            "verdict": if handshake && typed && doctor_reports && unlocked { "pass" } else { "fail" },
            "duration_ms": started.elapsed().as_millis() as u64,
        }),
    );
    assert!(handshake, "handshake while locked: {initialize} / {tools}");
    assert!(typed, "typed lock refusal naming pid {holder}: {locked:?}");
    assert!(doctor_reports, "doctor reports audit_log_locked: {doctor}");
    assert!(
        unlocked,
        "no lock refusal after the holder exits: {recovered}"
    );
}

/// HTTP service-owner variant: instance 1 (stdio, write-reachable profile)
/// owns the service state. An HTTP instance sharing the state directory, with
/// its own audit log, still listens, completes the handshake and refuses tool
/// calls with ORACLEMCP_SERVICE_OWNER_LOCKED naming instance 1's pid. Once
/// instance 1 exits, the next call is no longer refused by the lock.
#[test]
fn w4_runtime_issue51_http_service_owner_typed_locked() {
    let started = Instant::now();
    let home = SharedHome::new("http");
    // Top-level keys precede every table.
    let profile = "[[profiles]]\nname = \"w\"\n\
                   connect_string = \"//127.0.0.1:9/I51NOSUCH\"\nusername = \"i51\"\n\
                   credential_ref = \"env:I51_DB_PASSWORD\"\nmax_level = \"READ_WRITE\"\n\
                   mcp_exposed = true\n";
    let config_with = |audit_dir: &str, http: &str| {
        format!(
            "default_profile = \"w\"\n\n[audit]\npath = {:?}\n\n{http}{profile}",
            home.root
                .join(audit_dir)
                .join("audit.jsonl")
                .display()
                .to_string()
        )
    };
    let first_config = home.config("first.toml", &config_with("a1", ""));
    let second_config = home.config(
        "second.toml",
        &config_with("a2", "[http]\njson_response = true\nstateful = false\n\n"),
    );
    let password = [("I51_DB_PASSWORD", "i51-synthetic")];

    let mut first = StdioInstance::spawn(&home, &first_config, &password);
    let (first_init, _) = first.handshake("i51-first");
    assert!(
        first_init.get("result").is_some(),
        "instance 1 starts: {first_init}"
    );
    let holder = first.pid();

    let second = HttpInstance::spawn(&home, &second_config);
    let (init_status, initialize) = second.request(&initialize_request(1, "i51-http"));
    let (list_status, tools) =
        second.request(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let locked = [
        second.request(&query_call(3)),
        second.request(&query_call(4)),
    ];
    first.kill();
    let (recovered_status, recovered) = second.request(&query_call(5));

    let handshake = init_status == 200 && list_status == 200 && handshake_ok(&initialize, &tools);
    // The typed Busy refusal maps to HTTP 429 with Retry-After on this
    // transport; the body carries the typed code and holder pid.
    let typed = locked.iter().all(|(status, reply)| {
        *status == 429 && typed_lock(reply, "ORACLEMCP_SERVICE_OWNER_LOCKED", holder)
    });
    let unlocked = recovered_status != 429 && !any_lock(&recovered);
    emit_row(
        "offline",
        &json!({
            "case_id": CASE_ID,
            "manifest_case": "rel012_i51_second_instance",
            "variant": "http_service_owner_locked",
            "transport": "http",
            "binary": binary().display().to_string(),
            "holder_pid": holder,
            "handshake_completed": handshake,
            "typed_lock_refusals": typed,
            "locked_http_status": locked.iter().map(|(status, _)| *status).collect::<Vec<_>>(),
            "recovered_http_status": recovered_status,
            "recovered_without_restart": unlocked,
            "verdict": if handshake && typed && unlocked { "pass" } else { "fail" },
            "duration_ms": started.elapsed().as_millis() as u64,
        }),
    );
    assert!(
        handshake,
        "HTTP handshake while locked: {initialize} / {tools}"
    );
    assert!(typed, "typed owner refusal naming pid {holder}: {locked:?}");
    assert!(
        unlocked,
        "no lock refusal after the holder exits: {recovered}"
    );
}

/// Live recovery: instance 2 targets a real Oracle lane and tags its sessions
/// with a run-id MODULE. While instance 1 holds the audit log, `V$SESSION`
/// shows no session with that MODULE. After instance 1 exits, the next
/// `oracle_query` succeeds without a restart, and the MODULE session appears
/// (the positive control for the probe).
#[cfg(feature = "live-xe")]
#[test]
fn w4_runtime_issue51_recovers_against_live_oracle() {
    use asupersync::Cx;
    use asupersync::runtime::RuntimeBuilder;
    use oraclemcp_db::{OracleBind, OracleConnectOptions, OracleConnection, RustOracleConnection};

    let (Ok(dsn), Ok(user), Ok(password)) = (
        std::env::var("ORACLEMCP_TEST_DSN"),
        std::env::var("ORACLEMCP_TEST_USER"),
        std::env::var("ORACLEMCP_TEST_PASSWORD"),
    ) else {
        eprintln!(
            "[live-xe] SKIP w4_runtime_issue51_recovers_against_live_oracle: set \
             ORACLEMCP_TEST_DSN / _USER / _PASSWORD and ORACLEMCP_W4_LANE"
        );
        return;
    };
    let lane = std::env::var("ORACLEMCP_W4_LANE").unwrap_or_else(|_| "live".to_owned());
    let module = format!(
        "I51{:X}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_micros()
            % 0xFFFF_FFFF
    );
    let module_sessions = |module: &str| -> u64 {
        let reactor = asupersync::runtime::reactor::create_reactor().expect("reactor");
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a Cx");
            let conn = RustOracleConnection::connect(
                &cx,
                OracleConnectOptions {
                    connect_string: dsn.clone(),
                    username: Some(user.clone()),
                    password: Some(password.clone()),
                    call_timeout: Some(Duration::from_secs(20)),
                    ..Default::default()
                },
            )
            .await
            .expect("admin probe connects");
            let rows = conn
                .query_rows(
                    &cx,
                    "SELECT TO_CHAR(COUNT(*)) AS n FROM v$session WHERE module = :1",
                    &[OracleBind::String(module.to_owned())],
                )
                .await
                .expect("V$SESSION probe");
            let count = rows[0]
                .text("N")
                .expect("count column")
                .parse()
                .expect("numeric count");
            let _ = conn.close(&cx).await;
            count
        })
    };

    let started = Instant::now();
    let home = SharedHome::new(&format!("live-{lane}"));
    // Both instances share the default audit log under the shared state
    // directory; instance 1 tags its sessions differently, so every session
    // carrying `module` belongs to instance 2.
    let config_for = |name: &str, module: &str| {
        home.config(
            name,
            &format!(
                "default_profile = \"live\"\n\n[[profiles]]\nname = \"live\"\n\
                 connect_string = {dsn:?}\nusername = {user:?}\n\
                 credential_ref = \"env:I51_DB_PASSWORD\"\nmcp_exposed = true\n\n\
                 [profiles.session_identity]\nmodule = {module:?}\n"
            ),
        )
    };
    let first_config = config_for("first.toml", &format!("{module}H"));
    let config = config_for("second.toml", &module);
    let password_env = [("I51_DB_PASSWORD", password.as_str())];

    let mut first = StdioInstance::spawn(&home, &first_config, &password_env);
    first.handshake("i51-first");
    let holder = first.pid();
    let baseline = module_sessions(&module);

    let mut second = StdioInstance::spawn(&home, &config, &password_env);
    let (initialize, tools) = second.handshake("i51-second");
    let locked = second.request(&query_call(3));
    let while_locked = module_sessions(&module);
    first.kill();
    let after_holder_exit = module_sessions(&module);
    let recovered = second.request(&query_call(4));
    let after_recovery = module_sessions(&module);

    let handshake = handshake_ok(&initialize, &tools);
    let typed = typed_lock(&locked, "ORACLEMCP_AUDIT_LOG_LOCKED", holder);
    let no_session_while_locked = baseline == 0 && while_locked == 0;
    let recovered_ok = recovered["result"]["isError"] != json!(true)
        && recovered.to_string().contains("\"1\"")
        && !any_lock(&recovered);
    let session_after = after_holder_exit == 0 && after_recovery > 0;
    emit_row(
        &lane,
        &json!({
            "case_id": CASE_ID,
            "manifest_case": "rel012_i51_second_instance",
            "variant": "live_recovery",
            "transport": "stdio",
            "lane": lane,
            "binary": binary().display().to_string(),
            "holder_pid": holder,
            "handshake_completed": handshake,
            "typed_lock_refusal": typed,
            "module_sessions": {
                "before_second": baseline,
                "while_locked": while_locked,
                "after_holder_exit": after_holder_exit,
                "after_recovery": after_recovery,
            },
            "no_session_while_locked": no_session_while_locked,
            "recovered_query_succeeded": recovered_ok,
            "verdict": if handshake && typed && no_session_while_locked && recovered_ok && session_after { "pass" } else { "fail" },
            "duration_ms": started.elapsed().as_millis() as u64,
        }),
    );
    assert!(handshake, "handshake while locked: {initialize} / {tools}");
    assert!(typed, "typed lock refusal naming pid {holder}: {locked}");
    assert!(
        no_session_while_locked,
        "the locked instance opened no session: {baseline} / {while_locked}"
    );
    assert!(
        recovered_ok,
        "the query succeeds after the holder exits: {recovered}"
    );
    assert!(
        session_after,
        "the recovered instance's MODULE session is visible (probe positive control): \
         {after_holder_exit} -> {after_recovery}"
    );
}
