#![no_main]
//! Fuzz the OAuth resource-server token surface (bead H6 /
//! oraclemcp-eng-program-bp8ia.9.6). A presented bearer token is THE
//! network-untrusted input of the HTTP transport: `extract_bearer` sees raw
//! `Authorization` header values and `ResourceServerConfig::validate` sees
//! raw JWT compact serializations from unauthenticated peers. Arbitrary bytes
//! must never panic either path — every input must fail closed as a
//! structured `TokenError` (or validate, for a genuinely well-formed token).
//!
//! This target only proves panic-freedom; WHICH tokens are accepted or
//! rejected (alg confusion, issuer allowlist, audience binding, expiry,
//! scopes) is pinned by `oraclemcp-auth`'s own unit tests.
//!
//! Run: `cargo +nightly-2026-05-11 fuzz run oauth_token_validate` (from
//! crates/oraclemcp-auth).

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use oraclemcp_auth::{extract_bearer, Hs256Verifier, ResourceServerConfig};

fn verifier() -> &'static Hs256Verifier {
    static VERIFIER: OnceLock<Hs256Verifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        Hs256Verifier::new(b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("fixed fuzz secret meets the HS256 minimum")
    })
}

fn config() -> &'static ResourceServerConfig {
    static CONFIG: OnceLock<ResourceServerConfig> = OnceLock::new();
    CONFIG.get_or_init(|| ResourceServerConfig {
        resource: "https://mcp.example.com".to_owned(),
        allowed_issuers: vec!["https://issuer.example.com".to_owned()],
        authorization_servers: vec!["https://issuer.example.com".to_owned()],
        required_scopes: vec!["oraclemcp.read".to_owned()],
    })
}

fuzz_target!(|data: &[u8]| {
    // A JWT/header is small in legitimate deployments. Bound oversized fuzz
    // inputs so decoding/allocation cannot turn a local campaign into a host
    // memory-pressure test.
    if data.len() > 65_536 {
        return;
    }
    let Ok(presented) = std::str::from_utf8(data) else {
        return;
    };
    // Raw JWT compact serialization → full fail-closed validation.
    let _ = config().validate(presented, verifier(), 1_700_000_000);
    // Raw Authorization header value → bearer extraction, then validate the
    // extracted token so one header-shaped input exercises both layers.
    if let Ok(token) = extract_bearer(Some(presented)) {
        let _ = config().validate(token, verifier(), 1_700_000_000);
    }
});
