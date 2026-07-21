//! C1 wire-contract fixture — externally minted OAuth bearer tokens.
//!
//! Plan §4-C1 / §A.5.2, bead `oraclemcp-091-c1-oauth-literal-jwt-v9m9z`.
//!
//! **The rule this file exists to enforce:** where a contract crosses a wire
//! boundary, at least one test must use a *literal, externally authored* value
//! committed as an opaque string — never a value produced by the same helper the
//! server consumes. Every other OAuth test in this repository mints its token
//! with an in-repo `b64url` + HMAC helper (`golden_behavior.rs:181-222`,
//! `oauth_rs.rs` unit tests) or verifies it with an `AcceptHs256` stub that
//! ignores the signature entirely. Those prove self-consistency; none of them
//! ever proved that a token minted by a real, third-party OAuth issuer is
//! accepted. The field report (P1-11) is what that blind spot looks like from
//! the outside.
//!
//! **Provenance of the constants below.** Minted once, out of tree, with PyJWT
//! 2.10.1 (`pip install pyjwt`; no oraclemcp code involved) and pasted here as
//! opaque strings. Do not regenerate them from repo code — that would recreate
//! exactly the self-reference this fixture removes. The recipe, for audit:
//!
//! ```text
//! import base64, jwt
//! PLAIN  = b"oraclemcp-c1-fixture-hs256-key-01"        # 33 bytes of key material
//! SECRET = base64.b64encode(PLAIN).decode()            # what an operator puts in config
//! CLAIMS = {"iss": "https://idp.c1-fixture.example",
//!           "aud": "https://oraclemcp.c1-fixture.example/mcp",
//!           "sub": "c1-fixture-subject", "client_id": "c1-fixture-client",
//!           "jti": "c1-fixture-jti-0001", "iat": 1752000000, "exp": 4102444800,
//!           "scope": "oracle:read oracle:execute"}
//! jwt.encode(CLAIMS, SECRET, algorithm="HS256", headers={"typ": "at+jwt"})
//! ```
//!
//! The negatives drop `client_id` / `jti`, set `typ` to plain `"JWT"`, or sign
//! with `PLAIN` instead of `SECRET`. All values are synthetic: `SECRET` is a
//! published test constant with no production meaning.
//!
//! **Two-sided proof.** `c1_negative_tokens_are_pairwise_distinguishable_on_the_wire`
//! is the failing half and is `#[ignore]`d against today's `main`
//! (`token_error_code`, `http/mod.rs:517-523`, collapses Malformed /
//! BadSignature / AudienceMismatch / UntrustedIssuer / Expired into one
//! `invalid_token` code with no `error_description`). Bead
//! `oraclemcp-091-b2-oauth-contract-g5xmr` (B2a+B2b) flips it to enforced-green
//! by removing the `#[ignore]`. Everything else in this file passes today and
//! guards the acceptance path against regression.

use std::sync::Arc;

use asupersync::{Cx, Outcome};
use oraclemcp_auth::{Hs256Verifier, ResourceServerConfig, TokenError};
use oraclemcp_core::OracleMcpServer;
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::http::{
    HttpRequest, HttpResponse, HttpTransportConfig, MCP_PATH, OAuthEnforcement, handle_http_request,
};
use oraclemcp_core::server::{DispatchContext, DispatchFuture, ToolDispatch};
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_guard::OperatingLevel;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Externally authored constants. Opaque on purpose — never derive one from
// another in Rust.
// ---------------------------------------------------------------------------

/// The configured HS256 secret exactly as an operator would write it. The server
/// uses its **raw UTF-8 bytes** as the HMAC key (`main.rs`
/// `Hs256Verifier::new(secret.expose().as_bytes().to_vec())`): no base64 decode,
/// no hex decode. 44 characters, comfortably over the 32-byte HS256 floor.
const HS256_SECRET_RAW_UTF8: &str = "b3JhY2xlbWNwLWMxLWZpeHR1cmUtaHMyNTYta2V5LTAx";

/// What that secret decodes to if someone base64-decodes it first — the mistake
/// every JWT tutorial invites. It is *not* the key this server uses.
const HS256_SECRET_BASE64_DECODED: &[u8] = b"oraclemcp-c1-fixture-hs256-key-01";

const ISSUER: &str = "https://idp.c1-fixture.example";
const RESOURCE: &str = "https://oraclemcp.c1-fixture.example/mcp";
const METADATA_URL: &str =
    "https://oraclemcp.c1-fixture.example/.well-known/oauth-protected-resource";

/// A wall clock strictly between the fixture's `iat` (1752000000) and its `exp`
/// (4102444800), for the offline verifier-level assertions.
const NOW_UNIX: i64 = 1_800_000_000;

/// Fully conformant RFC 9068 access token: `typ=at+jwt`, all six required
/// claims, `aud` as a string, `scope` as a space-delimited string.
const TOKEN_VALID: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJpc3MiOiJodHRwczovL2lkcC5jMS1maXh0dXJlLmV4YW1wbGUiLCJhdWQiOiJodHRwczovL29yYWNsZW1jcC5jMS1maXh0dXJlLmV4YW1wbGUvbWNwIiwic3ViIjoiYzEtZml4dHVyZS1zdWJqZWN0IiwiY2xpZW50X2lkIjoiYzEtZml4dHVyZS1jbGllbnQiLCJqdGkiOiJjMS1maXh0dXJlLWp0aS0wMDAxIiwiaWF0IjoxNzUyMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDAsInNjb3BlIjoib3JhY2xlOnJlYWQgb3JhY2xlOmV4ZWN1dGUifQ.FYgbqfI_MkDSqLEYF205KYefA9v5LbGq4vE9HPfT46g";

/// Same claims, header `typ` is the generic `"JWT"` rather than `at+jwt`.
const TOKEN_WRONG_TYP: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lkcC5jMS1maXh0dXJlLmV4YW1wbGUiLCJhdWQiOiJodHRwczovL29yYWNsZW1jcC5jMS1maXh0dXJlLmV4YW1wbGUvbWNwIiwic3ViIjoiYzEtZml4dHVyZS1zdWJqZWN0IiwiY2xpZW50X2lkIjoiYzEtZml4dHVyZS1jbGllbnQiLCJqdGkiOiJjMS1maXh0dXJlLWp0aS0wMDAxIiwiaWF0IjoxNzUyMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDAsInNjb3BlIjoib3JhY2xlOnJlYWQgb3JhY2xlOmV4ZWN1dGUifQ.YQAecBKIsbLrmVNyZz29yqlB_Xb1q9D5h-TxwFlpIqI";

/// Same claims minus `client_id` — routinely omitted by hand-built tokens.
const TOKEN_MISSING_CLIENT_ID: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJpc3MiOiJodHRwczovL2lkcC5jMS1maXh0dXJlLmV4YW1wbGUiLCJhdWQiOiJodHRwczovL29yYWNsZW1jcC5jMS1maXh0dXJlLmV4YW1wbGUvbWNwIiwic3ViIjoiYzEtZml4dHVyZS1zdWJqZWN0IiwianRpIjoiYzEtZml4dHVyZS1qdGktMDAwMSIsImlhdCI6MTc1MjAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwLCJzY29wZSI6Im9yYWNsZTpyZWFkIG9yYWNsZTpleGVjdXRlIn0.Q5hRyrSyksi3OD-xpog3NKFvUyk3jXw-IcwUIk-Ii5I";

/// Same claims minus `jti`.
const TOKEN_MISSING_JTI: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJpc3MiOiJodHRwczovL2lkcC5jMS1maXh0dXJlLmV4YW1wbGUiLCJhdWQiOiJodHRwczovL29yYWNsZW1jcC5jMS1maXh0dXJlLmV4YW1wbGUvbWNwIiwic3ViIjoiYzEtZml4dHVyZS1zdWJqZWN0IiwiY2xpZW50X2lkIjoiYzEtZml4dHVyZS1jbGllbnQiLCJpYXQiOjE3NTIwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMCwic2NvcGUiOiJvcmFjbGU6cmVhZCBvcmFjbGU6ZXhlY3V0ZSJ9.Ufzp-YB_thLl5WMKE2IC__3a2pPP8u8vl0gpOIBZUOE";

/// Fully conformant claims, but signed with the base64-*decoded* secret.
const TOKEN_BASE64_DECODED_KEY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJpc3MiOiJodHRwczovL2lkcC5jMS1maXh0dXJlLmV4YW1wbGUiLCJhdWQiOiJodHRwczovL29yYWNsZW1jcC5jMS1maXh0dXJlLmV4YW1wbGUvbWNwIiwic3ViIjoiYzEtZml4dHVyZS1zdWJqZWN0IiwiY2xpZW50X2lkIjoiYzEtZml4dHVyZS1jbGllbnQiLCJqdGkiOiJjMS1maXh0dXJlLWp0aS0wMDAxIiwiaWF0IjoxNzUyMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDAsInNjb3BlIjoib3JhY2xlOnJlYWQgb3JhY2xlOmV4ZWN1dGUifQ.7IvABqRInKIhq4chI_EYLIuaBNpDz6LppsgJHDee5L8";

/// The four negatives, paired with the label used in failure messages.
const NEGATIVES: [(&str, &str); 4] = [
    ("wrong typ (plain \"JWT\")", TOKEN_WRONG_TYP),
    ("missing client_id", TOKEN_MISSING_CLIENT_ID),
    ("missing jti", TOKEN_MISSING_JTI),
    (
        "signed with the base64-decoded key",
        TOKEN_BASE64_DECODED_KEY,
    ),
];

// ---------------------------------------------------------------------------
// Verifier-level assertions (offline, no HTTP).
// ---------------------------------------------------------------------------

fn resource_server() -> ResourceServerConfig {
    ResourceServerConfig {
        resource: RESOURCE.to_owned(),
        allowed_issuers: vec![ISSUER.to_owned()],
        authorization_servers: vec![ISSUER.to_owned()],
        required_scopes: vec!["oracle:read".to_owned()],
    }
}

fn verifier_with_raw_secret() -> Hs256Verifier {
    Hs256Verifier::new(HS256_SECRET_RAW_UTF8.as_bytes().to_vec())
        .expect("the configured secret is >= 32 bytes")
}

#[test]
fn c1_externally_minted_token_is_accepted_by_the_production_verifier() {
    let scopes = resource_server()
        .validate(TOKEN_VALID, &verifier_with_raw_secret(), NOW_UNIX)
        .expect("a PyJWT-minted RFC 9068 access token must verify against the real Hs256Verifier");
    assert_eq!(
        scopes,
        vec!["oracle:read".to_owned(), "oracle:execute".to_owned()],
        "space-delimited `scope` must be split into the granted scope list"
    );
}

#[test]
fn c1_hmac_key_is_the_raw_utf8_secret_not_its_base64_decoding() {
    // This is the undocumented requirement behind the field report: the key is
    // the raw bytes of the configured string. Prove it both ways so neither
    // side can drift silently.
    let raw = verifier_with_raw_secret();
    let decoded = Hs256Verifier::new(HS256_SECRET_BASE64_DECODED.to_vec())
        .expect("the decoded material is also >= 32 bytes");
    let config = resource_server();

    assert!(
        config.validate(TOKEN_VALID, &raw, NOW_UNIX).is_ok(),
        "raw-UTF-8 key must accept the token the issuer signed with the configured string"
    );
    assert_eq!(
        config.validate(TOKEN_VALID, &decoded, NOW_UNIX),
        Err(TokenError::BadSignature),
        "base64-decoding the configured secret must not produce a working key"
    );
    assert_eq!(
        config.validate(TOKEN_BASE64_DECODED_KEY, &raw, NOW_UNIX),
        Err(TokenError::BadSignature),
        "a client that base64-decoded the shared secret must be refused"
    );
    assert!(
        config
            .validate(TOKEN_BASE64_DECODED_KEY, &decoded, NOW_UNIX)
            .is_ok(),
        "control: that token is well-formed and only the key choice differs"
    );
}

#[test]
fn c1_every_negative_is_refused_by_the_verifier() {
    let config = resource_server();
    let verifier = verifier_with_raw_secret();
    for (label, token) in NEGATIVES {
        assert!(
            config.validate(token, &verifier, NOW_UNIX).is_err(),
            "negative fixture ({label}) must be refused"
        );
    }
}

// ---------------------------------------------------------------------------
// Wire-level assertions: the same tokens through the real HTTP OAuth path.
// ---------------------------------------------------------------------------

struct EchoDispatch;

impl ToolDispatch for EchoDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move { Outcome::Ok(json!({ "tool": name, "args": args })) })
    }
}

fn fixture_server() -> OracleMcpServer {
    let mut registry = ToolRegistry::new();
    registry.register(ToolDescriptor::new(
        "oracle_schema_inspect",
        ToolTier::FoundationLiveDb,
        "inspect a schema",
    ));
    let report = CapabilitiesReport::new(
        env!("CARGO_PKG_VERSION"),
        registry.tools.clone(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: false,
            engine: false,
            http_transport: true,
        },
    );
    OracleMcpServer::new(
        env!("CARGO_PKG_VERSION"),
        registry,
        report,
        Arc::new(EchoDispatch),
    )
}

fn oauth_http_config() -> HttpTransportConfig {
    HttpTransportConfig {
        json_response: true,
        stateful: false,
        oauth: Some(Arc::new(OAuthEnforcement {
            config: resource_server(),
            verifier: Arc::new(verifier_with_raw_secret()),
            metadata_url: METADATA_URL.to_owned(),
        })),
        ..Default::default()
    }
}

fn initialize_with_bearer(token: Option<&str>) -> HttpResponse {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "c1-fixture-client", "version": "1.0" }
        }
    })
    .to_string()
    .into_bytes();

    let mut headers = vec![
        ("host".to_owned(), "127.0.0.1".to_owned()),
        ("content-type".to_owned(), "application/json".to_owned()),
        (
            "accept".to_owned(),
            "application/json, text/event-stream".to_owned(),
        ),
    ];
    if let Some(token) = token {
        headers.push(("authorization".to_owned(), format!("Bearer {token}")));
    }

    handle_http_request(
        &fixture_server(),
        &oauth_http_config(),
        HttpRequest::new("POST", MCP_PATH, headers, body),
    )
}

#[test]
fn c1_externally_minted_token_authorizes_a_real_mcp_request() {
    let response = initialize_with_bearer(Some(TOKEN_VALID));
    assert_eq!(
        response.status,
        200,
        "externally minted token must pass the HTTP OAuth gate; body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let body: Value =
        serde_json::from_slice(&response.body).expect("initialize returns a JSON-RPC response");
    assert_eq!(body["result"]["protocolVersion"], json!("2025-11-25"));
}

#[test]
fn c1_negatives_are_refused_with_an_rfc6750_challenge() {
    for (label, token) in NEGATIVES {
        let response = initialize_with_bearer(Some(token));
        assert_eq!(response.status, 401, "negative ({label}) must be a 401");
        let challenge = response.header("www-authenticate").unwrap_or_else(|| {
            panic!("negative ({label}) must carry a WWW-Authenticate challenge")
        });
        assert!(
            challenge.contains("error=\"invalid_token\""),
            "negative ({label}) must keep the RFC 6750 error code; got: {challenge}"
        );
        assert!(
            !response
                .headers
                .iter()
                .any(|(_, value)| value.contains(token)),
            "negative ({label}) must not echo token material back to the client"
        );
    }
}

/// The failing half of C1's two-sided proof.
///
/// A hand-built token that is missing `client_id` and one that is missing `jti`
/// both collapse to `TokenError::Malformed`, and every rejection class collapses
/// to a bare `error="invalid_token"` with no `error_description`
/// (`http/mod.rs:517-523`). An operator debugging a rejected token therefore
/// gets the same six words no matter what is actually wrong — which is precisely
/// how P1-11 was misdiagnosed as a broken HS256 implementation.
///
/// Ignored against pre-fix `main`; bead `oraclemcp-091-b2-oauth-contract-g5xmr`
/// (B2a+B2b) removes the `#[ignore]` as its acceptance.
#[test]
#[ignore = "expected failure until oraclemcp-091-b2-oauth-contract-g5xmr (B2b) widens error_description"]
fn c1_negative_tokens_are_pairwise_distinguishable_on_the_wire() {
    let challenges: Vec<(&str, String)> = NEGATIVES
        .iter()
        .map(|(label, token)| {
            let response = initialize_with_bearer(Some(token));
            let challenge = response
                .header("www-authenticate")
                .unwrap_or_else(|| panic!("negative ({label}) must carry a challenge"))
                .to_owned();
            (*label, challenge)
        })
        .collect();

    for i in 0..challenges.len() {
        for j in (i + 1)..challenges.len() {
            let (left_label, left) = &challenges[i];
            let (right_label, right) = &challenges[j];
            assert_ne!(
                left, right,
                "'{left_label}' and '{right_label}' are different failures and must produce \
                 different diagnostics; both said: {left}"
            );
        }
    }

    // A missing bearer is a fifth, distinct case: it must stay distinguishable
    // from a bearer that was presented and rejected.
    let missing = initialize_with_bearer(None);
    let missing_challenge = missing
        .header("www-authenticate")
        .expect("a missing bearer must still carry a challenge")
        .to_owned();
    for (label, challenge) in &challenges {
        assert_ne!(
            &missing_challenge, challenge,
            "'no bearer at all' must not read the same as '{label}'"
        );
    }
}
