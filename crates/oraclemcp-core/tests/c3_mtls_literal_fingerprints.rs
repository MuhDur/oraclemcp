//! C3 wire-contract fixture — hand-written mTLS fingerprints.
//!
//! Plan §4-C3 / §A.5.1, bead `oraclemcp-091-c3-mtls-literal-fingerprints-fqh5k`.
//!
//! A certificate fingerprint reaches this server through an operator's fingers:
//! they run `openssl x509 -fingerprint -sha256`, and they paste some rendering
//! of that output into `profiles.toml`. The runtime principal key, meanwhile, is
//! always exactly `mtls:sha256:<64 lowercase hex>`. Two config fields consume
//! that same value and disagree about which spellings survive:
//!
//! - `http.mtls.client_fingerprints` normalizes on store *and* on lookup
//!   (`http/config.rs:92`, `:107`) — three spellings all work.
//! - `http.operator.allowed_subjects` is stored trim-only (`main.rs:3352-3360`)
//!   and compared with a raw `==` (`admin_auth.rs:102-107`), while the
//!   control-listener precondition check normalizes *both* sides
//!   (`oraclemcp-config/src/lib.rs:648-660`).
//!
//! So a config written in openssl's own casing validates cleanly, starts, logs
//! that the control transport is enabled, and then authorizes nobody.
//!
//! Per test-shape rule §A.8-2, a config field with more than one accepted
//! spelling is exercised in its **ugliest** accepted spelling, not its
//! prettiest. The fingerprint below belongs to a real X.509 certificate
//! committed next to this file; the literal hex was produced by openssl, not by
//! repository code, and `c3_committed_certificate_hashes_to_the_literal_hex`
//! keeps the two honest about each other.
//!
//! **Provenance.** Generated once, out of tree:
//!
//! ```text
//! openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out c3_client.pem \
//!   -days 36500 -nodes -subj "/CN=c3-fixture-mtls-client/O=oraclemcp-test-fixtures"
//! openssl x509 -in c3_client.pem -outform DER -out c3_client.der
//! openssl x509 -inform DER -in c3_client.der -noout -fingerprint -sha256
//! #   sha256 Fingerprint=E0:54:AB:20:...:01
//! ```
//!
//! The private key was discarded — this fixture never completes a TLS handshake,
//! it only carries the certificate's identity through the authorization path.
//! Inspect it with `openssl x509 -inform DER -in <path> -noout -text`.
//!
//! **Two-sided proof.** `c3_operator_allowed_subjects_authorize_in_every_accepted_spelling`
//! is the failing half against today's `main`. Bead
//! `oraclemcp-091-b1a-mtls-normalize-eg2il` (B1a) flips it green by normalizing
//! `allowed_subjects` at load; deleting the `#[ignore]` is part of its
//! acceptance.

use std::sync::Arc;

use asupersync::{Cx, Outcome};
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::server::{DispatchContext, DispatchFuture, ToolDispatch};
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_core::{
    HttpRequest, HttpTransportConfig, MCP_PATH, MtlsClientRegistry, OperatorAuthorityPolicy,
    OracleMcpServer, handle_http_request,
};
use oraclemcp_guard::OperatingLevel;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// A real client leaf certificate, DER encoded. See the provenance note above.
const CLIENT_CERT_DER: &[u8] = include_bytes!("fixtures/mtls/c3_client.der");

/// `openssl x509 -fingerprint -sha256` over that certificate, transcribed by
/// hand into the form the server derives its principal key from.
const FINGERPRINT_LOWER_HEX: &str =
    "e054ab20728e767d8345c46ff53c4f33453094af5688cdff64b45922c01aef01";

/// The one spelling the runtime ever produces.
const CANONICAL_FINGERPRINT: &str =
    "sha256:e054ab20728e767d8345c46ff53c4f33453094af5688cdff64b45922c01aef01";
const CANONICAL_PRINCIPAL_KEY: &str =
    "mtls:sha256:e054ab20728e767d8345c46ff53c4f33453094af5688cdff64b45922c01aef01";

/// Every spelling an operator can legitimately produce from openssl output plus
/// ordinary copy-paste, ugliest first. `client_fingerprints` documents all of
/// them as accepted (`oraclemcp-config/src/lib.rs:845-849`).
const ACCEPTED_SPELLINGS: [(&str, &str); 5] = [
    (
        "uppercase hex with uppercase prefix and stray padding",
        "  SHA256:E054AB20728E767D8345C46FF53C4F33453094AF5688CDFF64B45922C01AEF01  ",
    ),
    (
        "bare uppercase hex (openssl output with the colons removed)",
        "E054AB20728E767D8345C46FF53C4F33453094AF5688CDFF64B45922C01AEF01",
    ),
    (
        "bare lowercase hex (sha256sum output)",
        "e054ab20728e767d8345c46ff53c4f33453094af5688cdff64b45922c01aef01",
    ),
    (
        "mixed case with the documented prefix",
        "sha256:E054ab20728e767D8345C46FF53C4F33453094af5688cdff64B45922C01AEF01",
    ),
    ("canonical", CANONICAL_FINGERPRINT),
];

/// An unrelated, well-formed fingerprint: registering this one must not
/// authorize our certificate.
const OTHER_FINGERPRINT: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

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
            http_transport: true,
        },
    );
    OracleMcpServer::new(
        env!("CARGO_PKG_VERSION"),
        registry,
        report,
        Arc::new(NeverDispatch),
    )
}

/// Present our certificate to a server whose registry was configured with
/// `configured`, and report the response status.
fn initialize_with_client_cert(configured: &str) -> (u16, String) {
    let config = HttpTransportConfig {
        json_response: true,
        stateful: false,
        mtls_clients: MtlsClientRegistry::from_fingerprints([configured]),
        ..Default::default()
    };
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "c3-fixture-client", "version": "1.0" }
        }
    })
    .to_string()
    .into_bytes();
    let request = HttpRequest::new(
        "POST",
        MCP_PATH,
        vec![
            ("host".to_owned(), "127.0.0.1".to_owned()),
            ("content-type".to_owned(), "application/json".to_owned()),
            (
                "accept".to_owned(),
                "application/json, text/event-stream".to_owned(),
            ),
        ],
        body,
    )
    .with_peer_cert_fingerprint_sha256(Some(CANONICAL_FINGERPRINT.to_owned()));

    let response = handle_http_request(&fixture_server(), &config, request);
    (
        response.status,
        String::from_utf8_lossy(&response.body).into_owned(),
    )
}

#[test]
fn c3_committed_certificate_hashes_to_the_literal_hex() {
    // Ties the openssl-produced literal to the committed bytes. If either drifts,
    // every other assertion in this file is meaningless, so this one runs first.
    let digest = Sha256::digest(CLIENT_CERT_DER);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex, FINGERPRINT_LOWER_HEX,
        "the committed certificate no longer hashes to the transcribed openssl fingerprint"
    );
    assert_eq!(CANONICAL_FINGERPRINT, format!("sha256:{hex}"));
    assert_eq!(CANONICAL_PRINCIPAL_KEY, format!("mtls:sha256:{hex}"));
}

#[test]
fn c3_client_fingerprints_authorize_in_every_accepted_spelling() {
    for (label, configured) in ACCEPTED_SPELLINGS {
        let (status, body) = initialize_with_client_cert(configured);
        assert_ne!(
            status, 403,
            "client_fingerprints written as {label} must authorize the certificate; body: {body}"
        );
        assert_eq!(
            status, 200,
            "client_fingerprints written as {label} must complete initialize; body: {body}"
        );
    }
}

#[test]
fn c3_an_unrelated_registered_fingerprint_does_not_authorize() {
    let (status, body) = initialize_with_client_cert(OTHER_FINGERPRINT);
    assert_eq!(status, 403, "a different certificate must be refused");
    assert!(
        body.contains("mtls_client_not_registered"),
        "the refusal must say the client is unregistered; body: {body}"
    );
}

fn operator_policy(allowed_subject: &str) -> OperatorAuthorityPolicy {
    OperatorAuthorityPolicy {
        // Loopback-owner fallback off: this test is about the authenticated
        // principal path, and leaving it on would mask the failure.
        allow_loopback_owner: false,
        local_owner_stable_id: "c3-fixture-owner".to_owned(),
        // Exactly what main.rs stores today: the operator's string, trimmed.
        allowed_subjects: vec![allowed_subject.trim().to_owned()],
    }
}

#[test]
fn c3_operator_allowed_subject_authorizes_in_the_canonical_spelling() {
    let policy = operator_policy(CANONICAL_PRINCIPAL_KEY);
    assert!(
        policy
            .authorize(Some(CANONICAL_PRINCIPAL_KEY), false)
            .is_some(),
        "the one spelling that already works must keep working"
    );
}

#[test]
fn c3_config_load_accepts_every_operator_subject_spelling() {
    // This is the trap, and it passes today: config validation accepts all of
    // them, so the operator gets no warning at any point before requests start
    // dying. Keeping it green means the fix cannot "solve" the problem by
    // rejecting the config instead of normalizing it.
    for (label, spelling) in ACCEPTED_SPELLINGS {
        let subject = format!("mtls:{}", spelling.trim());
        let toml = format!(
            "[http.operator]\nallow_loopback_owner = false\nallowed_subjects = [\"{subject}\"]\n"
        );
        let config = OracleMcpConfig::from_toml_str(&toml)
            .unwrap_or_else(|error| panic!("config with {label} must load: {error}"));
        assert_eq!(config.http.operator.allowed_subjects, vec![subject]);
    }
}

/// The failing half. Bead `oraclemcp-091-b1a-mtls-normalize-eg2il` (B1a)
/// normalizes `allowed_subjects` at load; deleting the `#[ignore]` is part of
/// its acceptance.
#[test]
#[ignore = "expected failure until oraclemcp-091-b1a-mtls-normalize-eg2il (B1a) normalizes allowed_subjects at load"]
fn c3_operator_allowed_subjects_authorize_in_every_accepted_spelling() {
    for (label, spelling) in ACCEPTED_SPELLINGS {
        let policy = operator_policy(&format!("mtls:{spelling}"));
        assert!(
            policy
                .authorize(Some(CANONICAL_PRINCIPAL_KEY), false)
                .is_some(),
            "an operator subject written as {label} passes config validation, so it must also \
             authorize the certificate it names — otherwise the service starts, reports the \
             control transport enabled, and refuses every request without ever saying why"
        );
    }
}
