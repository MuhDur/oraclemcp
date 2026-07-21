//! C2 wire-contract fixture — the stdio init-token `initialize` frame.
//!
//! Plan §4-C2 / §A.5.3, bead `oraclemcp-091-c2-stdio-token-literal-frame-t2b5q`.
//!
//! The stdio handshake gate reads the shared token from
//! `params._meta["oraclemcp/initToken"]`. Every existing test builds that frame
//! from `INIT_TOKEN_META_KEY` (`server.rs:37`, used at `server.rs:3426`), so it
//! would keep passing if the key were renamed to something no client could ever
//! guess — which is, near enough, the state the field found it in: the key
//! contains a slash, and the string `oraclemcp/initToken` appears nowhere
//! outside Rust source. The decisive evidence that no client ever found it is
//! that the tester always got `Missing`, never `Mismatch`.
//!
//! So the frames below are **committed literal JSON**, written the way a client
//! author would write them from documentation, and never assembled from the
//! server's own constant. If someone renames the key, the green half of this
//! file goes red — which is the entire point.
//!
//! **Two-sided proof.** The two `#[ignore]`d tests are the failing half against
//! today's `main`: the `Missing` error does not name the JSON path it wants, and
//! the path is undocumented everywhere a client author would look. Bead
//! `oraclemcp-091-b3-stdio-token-nzmiv` (B3) flips both green by deleting the
//! attributes. The rest passes today and pins the extraction contract.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use asupersync::{Cx, Outcome};
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::server::{DispatchContext, DispatchFuture, ToolDispatch};
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_core::{OracleMcpServer, StdioAuthPolicy};
use oraclemcp_guard::OperatingLevel;
use serde_json::{Value, json};

/// The literal JSON path a client author has to discover. Spelled out here as a
/// plain string so this file never imports the server's own constant.
const DOCUMENTED_PATH: &str = r#"params._meta["oraclemcp/initToken"]"#;

const EXPECTED_TOKEN: &str = "c2-fixture-stdio-token-Kq7wZ2";
const OTHER_TOKEN: &str = "c2-fixture-stdio-token-DIFFERENT";

/// A conformant `initialize` frame carrying the token at the real path. Hand
/// written, byte for byte, as an external client would emit it.
const FRAME_WITH_TOKEN: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c2-fixture-client","version":"1.0"},"_meta":{"oraclemcp/initToken":"c2-fixture-stdio-token-Kq7wZ2"}}}"#;

/// Same frame, no `_meta` at all — the shape a client that never found the path
/// would send.
const FRAME_WITHOUT_META: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c2-fixture-client","version":"1.0"}}}"#;

/// The token placed under keys a client author would plausibly guess when the
/// real one is undocumented. All of these must read as absent, not as a
/// mismatch — that asymmetry is the field's diagnostic fingerprint.
const FRAMES_WITH_GUESSED_KEYS: [(&str, &str); 3] = [
    (
        "initToken (no namespace)",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c2-fixture-client","version":"1.0"},"_meta":{"initToken":"c2-fixture-stdio-token-Kq7wZ2"}}}"#,
    ),
    (
        "oraclemcp_initToken (underscore instead of slash)",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c2-fixture-client","version":"1.0"},"_meta":{"oraclemcp_initToken":"c2-fixture-stdio-token-Kq7wZ2"}}}"#,
    ),
    (
        "_meta.oraclemcp.initToken (nested object)",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c2-fixture-client","version":"1.0"},"_meta":{"oraclemcp":{"initToken":"c2-fixture-stdio-token-Kq7wZ2"}}}}"#,
    ),
];

/// Right path, wrong JSON type. `as_str()` on a number yields `None`, so this
/// reads as absent rather than as a mismatch — worth pinning, because it is a
/// third way to see `Missing` while believing you sent a token.
const FRAME_WITH_NON_STRING_TOKEN: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c2-fixture-client","version":"1.0"},"_meta":{"oraclemcp/initToken":42}}}"#;

struct NeverDispatch;

impl ToolDispatch for NeverDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        _name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move { Outcome::Ok(json!({})) })
    }
}

fn fixture_server() -> OracleMcpServer {
    let mut registry = ToolRegistry::new();
    registry.register(ToolDescriptor::new(
        "oracle_capabilities",
        ToolTier::FoundationStatic,
        "discover the tool surface",
    ));
    let report = CapabilitiesReport::new(
        env!("CARGO_PKG_VERSION"),
        registry.tools.clone(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: false,
            engine: false,
            http_transport: false,
        },
    );
    OracleMcpServer::new(
        env!("CARGO_PKG_VERSION"),
        registry,
        report,
        Arc::new(NeverDispatch),
    )
}

/// Feed one literal frame through the real stdio serve loop and return the
/// single JSON-RPC reply.
fn send_frame(frame: &str, expected_token: &str) -> Value {
    let policy = StdioAuthPolicy::Required {
        expected: expected_token.to_owned(),
    };
    let mut input = frame.as_bytes().to_vec();
    input.push(b'\n');
    let mut output = Vec::new();
    fixture_server()
        .serve_stdio_with_io(std::io::Cursor::new(input), &mut output, &policy)
        .expect("stdio session completes");
    let text = String::from_utf8(output).expect("stdio replies are UTF-8");
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("the server answered the initialize frame");
    serde_json::from_str(line).expect("the reply is JSON")
}

fn error_message(reply: &Value) -> String {
    reply["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a JSON-RPC error, got: {reply}"))
        .to_owned()
}

#[test]
fn c2_literal_frame_authenticates_against_the_matching_token() {
    let reply = send_frame(FRAME_WITH_TOKEN, EXPECTED_TOKEN);
    assert!(
        reply.get("error").is_none(),
        "a hand-written frame carrying the token at the documented path must be accepted; got: {reply}"
    );
    assert_eq!(reply["result"]["protocolVersion"], json!("2025-11-25"));
}

#[test]
fn c2_literal_frame_is_a_mismatch_not_a_miss_against_a_different_token() {
    // This is the assertion that proves the extractor actually reads the path
    // in the committed literal frame. `Missing` here would mean the key in the
    // frame and the key in the server had drifted apart.
    let message = error_message(&send_frame(FRAME_WITH_TOKEN, OTHER_TOKEN));
    assert!(
        message.contains("mismatch"),
        "the server must report a MISMATCH for a token found at the right path; got: {message}"
    );
    assert!(
        !message.contains("missing"),
        "reporting `missing` here would mean the literal path no longer matches the server's key; got: {message}"
    );
}

#[test]
fn c2_absent_and_misplaced_tokens_all_read_as_missing() {
    let mut cases: Vec<(&str, &str)> = vec![("no _meta at all", FRAME_WITHOUT_META)];
    cases.extend(FRAMES_WITH_GUESSED_KEYS);
    cases.push((
        "non-string value at the right path",
        FRAME_WITH_NON_STRING_TOKEN,
    ));

    for (label, frame) in cases {
        let message = error_message(&send_frame(frame, EXPECTED_TOKEN));
        assert!(
            message.contains("missing"),
            "{label} must report the token as MISSING (this is the field's fingerprint for \
             'the client never found the path'); got: {message}"
        );
    }
}

// ---------------------------------------------------------------------------
// The failing half: the path is unfindable.
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<crate> sits two levels below the repo root")
        .to_path_buf()
}

/// Every file a client author would read before giving up. `docs/plan/` is
/// excluded deliberately: an internal planning document is not where an
/// integrator looks, and counting it would let the gap close on paper.
fn client_facing_sources() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = vec![
        root.join("README.md"),
        root.join("oraclemcp.example.toml"),
        root.join("crates/oraclemcp-core/src/robot_docs.rs"),
    ];
    let mut stack = vec![root.join("docs")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "plan") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                files.push(path);
            }
        }
    }
    files.retain(|path| path.exists());
    files
}

/// Bead `oraclemcp-091-b3-stdio-token-nzmiv` (B3) documents the path.
#[test]
fn c2_init_token_path_is_documented_somewhere_a_client_author_would_look() {
    let hits: Vec<String> = client_facing_sources()
        .into_iter()
        .filter(|path| {
            fs::read_to_string(path).is_ok_and(|text| text.contains("oraclemcp/initToken"))
        })
        .map(|path| path.display().to_string())
        .collect();
    assert!(
        !hits.is_empty(),
        "the literal key `oraclemcp/initToken` must appear in at least one client-facing \
         source. A token an integrator cannot spell is a gate that is always closed, and \
         `--allow-no-auth` is the only door left."
    );
}

/// Bead `oraclemcp-091-b3-stdio-token-nzmiv` (B3) puts the literal path into the
/// error text.
#[test]
fn c2_missing_token_error_names_the_exact_json_path() {
    let message = error_message(&send_frame(FRAME_WITHOUT_META, EXPECTED_TOKEN));
    assert!(
        message.contains(DOCUMENTED_PATH),
        "the `missing token` error is the one place a stuck integrator is guaranteed to \
         look, so it must spell out {DOCUMENTED_PATH}; got: {message}"
    );
}
