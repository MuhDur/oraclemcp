//! R1 external-client reachability proof.
//!
//! This intentionally does not import the server crate or its MCP helpers. The
//! client side is a tiny raw JSON-RPC/HTTP probe that drives the built
//! `oraclemcp` executable through the same process boundary as an installed
//! MCP client.

use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

const MCP_PATH: &str = "/mcp";
const PROTOCOL_VERSION: &str = "2025-11-25";

struct TestHome {
    root: PathBuf,
    config: PathBuf,
    state: PathBuf,
    tools: PathBuf,
}

impl TestHome {
    fn new(label: &str) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/r1-external-client")
            .join(format!("{}-{stamp}-{label}", std::process::id()));
        let state = root.join("state");
        let tools = root.join("tools.d");
        fs::create_dir_all(&state).expect("create isolated state dir");
        fs::create_dir_all(&tools).expect("create isolated tools dir");
        let config = root.join("profiles.toml");
        fs::write(
            &config,
            "schema_version = 2\n[http]\njson_response = true\nstateful = false\n",
        )
        .expect("write isolated config");
        Self {
            root,
            config,
            state,
            tools,
        }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
        cmd.env("ORACLEMCP_CONFIG", &self.config)
            .env("XDG_STATE_HOME", &self.state)
            .env("HOME", &self.root)
            .env("ORACLEMCP_TOOLS_DIR", &self.tools)
            .env_remove("ORACLEMCP_STDIO_TOKEN")
            .env_remove("RUST_LOG");
        cmd
    }
}

fn initialize_request(id: impl Into<Value>, client: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.into(),
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": client, "version": "0.0.0-r1" }
        }
    })
}

fn initialized_notification() -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    })
}

fn tools_list_request(id: impl Into<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.into(),
        "method": "tools/list"
    })
}

fn tool_call_request(id: impl Into<Value>, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.into(),
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments
        }
    })
}

fn json_line(value: &Value) -> Vec<u8> {
    let mut frame = serde_json::to_vec(value).expect("serialize JSON-RPC frame");
    frame.push(b'\n');
    frame
}

fn assert_initialize(response: &Value) {
    assert_eq!(response["jsonrpc"], json!("2.0"), "initialize JSON-RPC");
    assert_eq!(
        response["result"]["protocolVersion"],
        json!(PROTOCOL_VERSION)
    );
    assert_eq!(response["result"]["serverInfo"]["name"], json!("oraclemcp"));
    assert!(
        response["result"]["capabilities"].get("tools").is_some(),
        "initialize advertises tool capabilities: {response}"
    );
}

fn assert_tools_list(response: &Value) {
    let tools = response["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list returns tools array: {response}"));
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == json!("oracle_query")),
        "external client sees oracle_query in tools/list: {response}"
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == json!("oracle_capabilities")),
        "external client sees oracle_capabilities in tools/list: {response}"
    );
}

fn assert_governed_read_reaches_tool_boundary(response: &Value) {
    assert_eq!(
        response["result"]["isError"],
        json!(true),
        "offline oracle_query should return a structured tool error, not a transport failure: {response}"
    );
    assert!(
        response["result"]["structuredContent"]
            .get("error_class")
            .is_some(),
        "governed read returns the structured error envelope: {response}"
    );
}

#[test]
fn installed_artifact_accepts_raw_external_stdio_client() {
    let home = TestHome::new("stdio");
    let mut child = home
        .command()
        .args(["--json", "serve", "--allow-no-auth"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn installed oraclemcp artifact for stdio");

    {
        let mut stdin = child.stdin.take().expect("child stdin is piped");
        for frame in [
            initialize_request(1, "r1-raw-stdio"),
            initialized_notification(),
            tools_list_request(2),
            tool_call_request(3, "oracle_query", json!({ "sql": "SELECT 1 FROM dual" })),
        ] {
            stdin
                .write_all(&json_line(&frame))
                .expect("write external stdio JSON-RPC frame");
        }
    }

    let output = child
        .wait_with_output()
        .expect("collect stdio server output");
    assert!(
        output.status.success(),
        "stdio server exits cleanly after EOF; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let replies: Vec<Value> = String::from_utf8(output.stdout)
        .expect("stdio stdout is UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("stdio reply is JSON"))
        .collect();
    assert_eq!(
        replies.len(),
        3,
        "initialize, tools/list, and governed-read replies"
    );
    assert_initialize(&replies[0]);
    assert_tools_list(&replies[1]);
    assert_governed_read_reaches_tool_boundary(&replies[2]);
}

struct HttpServer {
    child: Child,
    stderr: Option<std::thread::JoinHandle<String>>,
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        if self.child.try_wait().expect("poll child").is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
    }
}

fn reserve_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    listener.local_addr().expect("read reserved addr")
}

fn spawn_http_server(home: &TestHome, addr: SocketAddr) -> HttpServer {
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
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn installed oraclemcp artifact for HTTP");
    let stderr_pipe = child.stderr.take().expect("stderr is piped");
    let stderr = std::thread::spawn(move || {
        let mut text = String::new();
        let mut reader = BufReader::new(stderr_pipe);
        reader
            .read_to_string(&mut text)
            .expect("read HTTP server stderr");
        text
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return HttpServer {
                child,
                stderr: Some(stderr),
            };
        }
        if let Some(status) = child.try_wait().expect("poll HTTP server") {
            panic!("HTTP server exited before accepting requests with status {status}");
        }
        assert!(
            Instant::now() < deadline,
            "HTTP server did not accept loopback connections before deadline"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn post_json(addr: SocketAddr, body: &Value) -> (u16, Value) {
    let body = body.to_string();
    let request = format!(
        "POST {MCP_PATH} HTTP/1.1\r\n\
         host: {addr}\r\n\
         content-type: application/json\r\n\
         accept: application/json, text/event-stream\r\n\
         mcp-protocol-version: {PROTOCOL_VERSION}\r\n\
         content-length: {}\r\n\
         connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).expect("connect raw HTTP client to oraclemcp");
    stream
        .write_all(request.as_bytes())
        .expect("write raw HTTP request");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("finish raw HTTP request");

    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .expect("read raw HTTP response");
    let (head, response_body) = raw
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("HTTP response must contain headers and body, got: {raw:?}"));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("HTTP status line is parseable: {head}"));
    let body = if response_body.trim().is_empty() {
        Value::Null
    } else if response_body.trim_start().starts_with('{') {
        serde_json::from_str(response_body)
            .unwrap_or_else(|error| panic!("HTTP body is JSON ({error}): {response_body}"))
    } else {
        let event = response_body
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .find(|data| *data != "null")
            .unwrap_or_else(|| panic!("SSE response carries JSON data: {response_body}"));
        serde_json::from_str(event)
            .unwrap_or_else(|error| panic!("SSE data is JSON ({error}): {event}"))
    };
    (status, body)
}

#[test]
fn installed_artifact_accepts_raw_external_http_client() {
    let home = TestHome::new("http");
    let addr = reserve_loopback_addr();
    let _server = spawn_http_server(&home, addr);

    let (status, initialize) = post_json(addr, &initialize_request(1, "r1-raw-http"));
    assert_eq!(status, 200, "HTTP initialize succeeds: {initialize}");
    assert_initialize(&initialize);

    let (status, tools) = post_json(addr, &tools_list_request(2));
    assert_eq!(status, 200, "HTTP tools/list succeeds: {tools}");
    assert_tools_list(&tools);

    let (status, governed_read) = post_json(
        addr,
        &tool_call_request(3, "oracle_query", json!({ "sql": "SELECT 1 FROM dual" })),
    );
    assert_eq!(
        status, 200,
        "HTTP governed read reaches JSON-RPC tool boundary: {governed_read}"
    );
    assert_governed_read_reaches_tool_boundary(&governed_read);
}
