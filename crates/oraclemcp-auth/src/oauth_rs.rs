//! OAuth 2.1 **resource-server** token validation (plan §7.1, risk R12; bead
//! P1-9b / oracle-qmwz.2.9.2). The server **validates, never issues** tokens.
//!
//! This module owns the security-relevant validation logic, kept transport- and
//! crypto-edge-agnostic so it is fully unit-testable and the highest-CVE surface
//! is small and audited:
//!
//! - **JWT parse** — `header.payload.signature`, base64url, alg check.
//! - **Signature** — real HS256 (HMAC-SHA256) verification built on `sha2`;
//!   asymmetric algs (RS256/ES256 via JWKS) go through the [`SignatureVerifier`]
//!   seam, wired with `jsonwebtoken` at the axum transport (P1-9a) so this crate
//!   carries no RSA/ring dependency.
//! - **Claims** — issuer allowlist; **RFC 8707 audience binding** (the token's
//!   `aud` MUST contain our resource — prevents a token minted for another
//!   resource being replayed here); `exp`/`nbf` against an injected wall clock;
//!   scope extraction (`scope` string or `scp` array).
//! - **RFC 9728** — the Protected Resource Metadata document + the
//!   `WWW-Authenticate: Bearer` challenge for a 401.
//!
//! Downstream, [`crate::scope`] maps the validated scopes to the operating-level
//! ceiling (scope can only LOWER it; bead P1-9e).

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Why resource-server token validation failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// No bearer token was presented.
    #[error("missing bearer token")]
    Missing,
    /// The token is not a well-formed JWT.
    #[error("malformed token")]
    Malformed,
    /// The token's `alg` is not supported by the configured verifier.
    #[error("unsupported token alg: {0}")]
    UnsupportedAlg(String),
    /// The signature did not verify.
    #[error("bad token signature")]
    BadSignature,
    /// `exp` has passed.
    #[error("token expired")]
    Expired,
    /// `nbf` is in the future.
    #[error("token not yet valid")]
    NotYetValid,
    /// `iss` is not on the allowlist.
    #[error("untrusted token issuer: {0}")]
    UntrustedIssuer(String),
    /// `aud` does not include this resource (RFC 8707).
    #[error("token audience does not include this resource")]
    AudienceMismatch,
    /// A required scope is absent.
    #[error("insufficient scope")]
    InsufficientScope,
}

/// Verifies a JWT signature for a given `alg`. Implemented for HS256 here; the
/// transport supplies an asymmetric verifier (RS256/ES256 via JWKS).
pub trait SignatureVerifier {
    /// Whether `signature` is valid for `signing_input` under `alg`.
    fn verify(&self, alg: &str, signing_input: &[u8], signature: &[u8]) -> bool;
}

/// HS256 (HMAC-SHA256) verifier.
pub struct Hs256Verifier {
    /// The shared secret.
    pub secret: Vec<u8>,
}

impl SignatureVerifier for Hs256Verifier {
    fn verify(&self, alg: &str, signing_input: &[u8], signature: &[u8]) -> bool {
        // Reject `none` and any non-HS256 alg outright (alg-confusion / alg=none).
        alg == "HS256" && constant_time_eq(&hmac_sha256(&self.secret, signing_input), signature)
    }
}

/// Resource-server configuration.
#[derive(Clone, Debug, Default)]
pub struct ResourceServerConfig {
    /// The canonical resource identifier this server represents — the token's
    /// `aud` must contain it (RFC 8707).
    pub resource: String,
    /// Allowed token issuers (`iss`). Empty = reject all (fail-closed).
    pub allowed_issuers: Vec<String>,
    /// Authorization servers to advertise in RFC 9728 metadata.
    pub authorization_servers: Vec<String>,
    /// Scopes that MUST all be present on the token (empty = none required here;
    /// per-tool scope enforcement is the scope→ceiling layer's job).
    pub required_scopes: Vec<String>,
}

impl ResourceServerConfig {
    /// Validate a presented JWT and return its granted scopes. `now_unix` is the
    /// current time (injected for testability). Fail-closed on every error.
    pub fn validate(
        &self,
        token: &str,
        verifier: &dyn SignatureVerifier,
        now_unix: i64,
    ) -> Result<Vec<String>, TokenError> {
        let (alg, claims, signing_input, signature) = parse_jwt(token)?;
        if alg == "none" || alg.is_empty() {
            return Err(TokenError::UnsupportedAlg(alg));
        }
        if !verifier.verify(&alg, &signing_input, &signature) {
            return Err(TokenError::BadSignature);
        }
        self.validate_claims(&claims, now_unix)
    }

    /// Validate the (already signature-verified) claim set; returns the scopes.
    pub fn validate_claims(
        &self,
        claims: &Value,
        now_unix: i64,
    ) -> Result<Vec<String>, TokenError> {
        // Issuer allowlist (fail-closed: empty allowlist rejects everything).
        let iss = claims["iss"].as_str().unwrap_or_default();
        if !self.allowed_issuers.iter().any(|i| i == iss) {
            return Err(TokenError::UntrustedIssuer(iss.to_owned()));
        }
        // RFC 8707 audience binding.
        if !audiences(claims).iter().any(|a| a == &self.resource) {
            return Err(TokenError::AudienceMismatch);
        }
        // Expiry / not-before (exp is required per RFC 9068).
        let exp = claims["exp"].as_i64().ok_or(TokenError::Malformed)?;
        if now_unix >= exp {
            return Err(TokenError::Expired);
        }
        if claims["nbf"].as_i64().is_some_and(|nbf| now_unix < nbf) {
            return Err(TokenError::NotYetValid);
        }
        // Scopes.
        let scopes = token_scopes(claims);
        if !self
            .required_scopes
            .iter()
            .all(|r| scopes.iter().any(|s| s == r))
        {
            return Err(TokenError::InsufficientScope);
        }
        Ok(scopes)
    }

    /// The RFC 9728 Protected Resource Metadata document (served at
    /// `/.well-known/oauth-protected-resource`).
    #[must_use]
    pub fn protected_resource_metadata(&self) -> Value {
        json!({
            "resource": self.resource,
            "authorization_servers": self.authorization_servers,
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["oracle:read", "oracle:write", "oracle:ddl", "oracle:admin"],
        })
    }

    /// The `WWW-Authenticate: Bearer …` header value for a 401 (RFC 9728 §5.1):
    /// points the client at the resource-metadata URL and, optionally, the error.
    #[must_use]
    pub fn www_authenticate(&self, metadata_url: &str, error: Option<&str>) -> String {
        let mut s = format!("Bearer resource_metadata=\"{metadata_url}\"");
        if let Some(e) = error {
            s.push_str(&format!(", error=\"{e}\""));
        }
        s
    }
}

/// Extract the bearer token from an `Authorization` header value.
pub fn extract_bearer(header: Option<&str>) -> Result<&str, TokenError> {
    let h = header.ok_or(TokenError::Missing)?.trim();
    let rest = h
        .strip_prefix("Bearer ")
        .or_else(|| h.strip_prefix("bearer "));
    match rest {
        Some(tok) if !tok.trim().is_empty() => Ok(tok.trim()),
        _ => Err(TokenError::Missing),
    }
}

/// Parse a JWT into (`alg`, claims JSON, signing input bytes, signature bytes).
fn parse_jwt(token: &str) -> Result<(String, Value, Vec<u8>, Vec<u8>), TokenError> {
    let mut parts = token.trim().split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(TokenError::Malformed),
    };
    let header: Value = serde_json::from_slice(&b64url_decode(h).ok_or(TokenError::Malformed)?)
        .map_err(|_| TokenError::Malformed)?;
    let claims: Value = serde_json::from_slice(&b64url_decode(p).ok_or(TokenError::Malformed)?)
        .map_err(|_| TokenError::Malformed)?;
    let signature = b64url_decode(s).ok_or(TokenError::Malformed)?;
    let alg = header["alg"].as_str().unwrap_or_default().to_owned();
    let signing_input = format!("{h}.{p}").into_bytes();
    Ok((alg, claims, signing_input, signature))
}

fn audiences(claims: &Value) -> Vec<String> {
    match &claims["aud"] {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => vec![],
    }
}

fn token_scopes(claims: &Value) -> Vec<String> {
    if let Some(s) = claims["scope"].as_str() {
        return s.split_whitespace().map(str::to_owned).collect();
    }
    if let Value::Array(a) = &claims["scp"] {
        return a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
    }
    Vec::new()
}

/// HMAC-SHA256 (RFC 2104) over `sha2`.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        k[..32].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// Constant-time byte-slice equality (length-independent timing on content).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// base64url decode (no padding required; tolerates `=`).
fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        if c == b'=' {
            continue;
        }
        let v = u32::from(val(c)?);
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// base64url encode (test-only, for minting JWTs).
    fn b64url_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[(n & 63) as usize] as char);
            }
        }
        out
    }

    const SECRET: &[u8] = b"super-secret-signing-key";

    fn mint(claims: Value) -> String {
        let header = json!({ "alg": "HS256", "typ": "JWT" });
        let h = b64url_encode(serde_json::to_string(&header).unwrap().as_bytes());
        let p = b64url_encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let signing_input = format!("{h}.{p}");
        let sig = b64url_encode(&hmac_sha256(SECRET, signing_input.as_bytes()));
        format!("{h}.{p}.{sig}")
    }

    fn cfg() -> ResourceServerConfig {
        ResourceServerConfig {
            resource: "https://oraclemcp.example/mcp".to_owned(),
            allowed_issuers: vec!["https://idp.example".to_owned()],
            authorization_servers: vec!["https://idp.example".to_owned()],
            required_scopes: vec![],
        }
    }

    fn verifier() -> Hs256Verifier {
        Hs256Verifier {
            secret: SECRET.to_vec(),
        }
    }

    fn good_claims() -> Value {
        json!({
            "iss": "https://idp.example",
            "aud": ["https://oraclemcp.example/mcp"],
            "exp": 2_000_000_000i64,
            "nbf": 1_000_000_000i64,
            "scope": "openid oracle:read oracle:execute",
        })
    }

    #[test]
    fn hmac_known_answer() {
        // RFC-style KAT: HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog").
        let mac = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn valid_token_passes_and_returns_scopes() {
        let token = mint(good_claims());
        let scopes = cfg()
            .validate(&token, &verifier(), 1_500_000_000)
            .expect("valid");
        assert!(scopes.contains(&"oracle:read".to_owned()));
        assert!(scopes.contains(&"oracle:execute".to_owned()));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut token = mint(good_claims());
        token.pop();
        token.push(if token.ends_with('A') { 'B' } else { 'A' });
        assert_eq!(
            cfg().validate(&token, &verifier(), 1_500_000_000),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        let token = mint(good_claims());
        // now > exp.
        assert_eq!(
            cfg().validate(&token, &verifier(), 2_000_000_001),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn not_yet_valid_token_is_rejected() {
        let token = mint(good_claims());
        // now < nbf.
        assert_eq!(
            cfg().validate(&token, &verifier(), 999_999_999),
            Err(TokenError::NotYetValid)
        );
    }

    #[test]
    fn wrong_audience_is_rejected_rfc8707() {
        let mut c = good_claims();
        c["aud"] = json!(["https://some-other-resource.example"]);
        let token = mint(c);
        assert_eq!(
            cfg().validate(&token, &verifier(), 1_500_000_000),
            Err(TokenError::AudienceMismatch)
        );
    }

    #[test]
    fn untrusted_issuer_is_rejected() {
        let mut c = good_claims();
        c["iss"] = json!("https://evil-idp.example");
        let token = mint(c);
        assert!(matches!(
            cfg().validate(&token, &verifier(), 1_500_000_000),
            Err(TokenError::UntrustedIssuer(_))
        ));
    }

    #[test]
    fn insufficient_scope_is_rejected() {
        let mut config = cfg();
        config.required_scopes = vec!["oracle:admin".to_owned()];
        let token = mint(good_claims()); // only has read/execute
        assert_eq!(
            config.validate(&token, &verifier(), 1_500_000_000),
            Err(TokenError::InsufficientScope)
        );
    }

    #[test]
    fn alg_none_is_rejected() {
        // Forge an alg=none token (no signature).
        let header = json!({ "alg": "none", "typ": "JWT" });
        let h = b64url_encode(serde_json::to_string(&header).unwrap().as_bytes());
        let p = b64url_encode(serde_json::to_string(&good_claims()).unwrap().as_bytes());
        let token = format!("{h}.{p}.");
        assert!(matches!(
            cfg().validate(&token, &verifier(), 1_500_000_000),
            Err(TokenError::UnsupportedAlg(_))
        ));
    }

    #[test]
    fn extract_bearer_parses_header() {
        assert_eq!(
            extract_bearer(Some("Bearer abc.def.ghi")),
            Ok("abc.def.ghi")
        );
        assert_eq!(extract_bearer(Some("bearer xyz")), Ok("xyz"));
        assert_eq!(extract_bearer(None), Err(TokenError::Missing));
        assert_eq!(extract_bearer(Some("Basic Zm9v")), Err(TokenError::Missing));
        assert_eq!(extract_bearer(Some("Bearer   ")), Err(TokenError::Missing));
    }

    #[test]
    fn metadata_and_challenge_render() {
        let c = cfg();
        let meta = c.protected_resource_metadata();
        assert_eq!(meta["resource"], json!("https://oraclemcp.example/mcp"));
        assert_eq!(
            meta["authorization_servers"][0],
            json!("https://idp.example")
        );
        let chal = c.www_authenticate(
            "https://oraclemcp.example/.well-known/oauth-protected-resource",
            Some("invalid_token"),
        );
        assert!(chal.starts_with("Bearer resource_metadata="));
        assert!(chal.contains("error=\"invalid_token\""));
    }

    #[test]
    fn scp_array_scope_form_is_supported() {
        let mut c = good_claims();
        c.as_object_mut().unwrap().remove("scope");
        c["scp"] = json!(["oracle:read", "oracle:write"]);
        let token = mint(c);
        let scopes = cfg()
            .validate(&token, &verifier(), 1_500_000_000)
            .expect("valid");
        assert_eq!(
            scopes,
            vec!["oracle:read".to_owned(), "oracle:write".to_owned()]
        );
    }
}
