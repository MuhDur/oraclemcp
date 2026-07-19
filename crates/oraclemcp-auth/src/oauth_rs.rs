//! OAuth 2.1 **resource-server** token validation (plan §7.1, risk R12; bead
//! P1-9b / oracle-qmwz.2.9.2). The server **validates, never issues** tokens.
//!
//! This module owns the security-relevant validation logic, kept transport- and
//! crypto-edge-agnostic so it is fully unit-testable and the highest-CVE surface
//! is small:
//!
//! - **JWT parse**: `header.payload.signature`, base64url, alg check, and RFC 9068
//!   access-token type/claim validation.
//! - **Signature**: real HS256 (HMAC-SHA256) verification built on `sha2`. This
//!   is the only algorithm wired in production. Asymmetric algs (RS256/ES256 via
//!   JWKS) are routed through the [`SignatureVerifier`] boundary so this crate
//!   carries no RSA/ring dependency — but it is a **fail-closed seam**: no
//!   JWKS-backed asymmetric verifier ships, so such tokens are currently rejected
//!   (`BadSignature`/`UnsupportedAlg`) until an embedding transport supplies one.
//! - **Claims**: issuer allowlist; **RFC 8707 audience binding** (the token's
//!   `aud` MUST contain our resource, which prevents a token minted for another
//!   resource being replayed here); `exp`/`nbf` against an injected wall clock;
//!   scope extraction (`scope` string or `scp` array).
//! - **RFC 9728**: the Protected Resource Metadata document + the
//!   `WWW-Authenticate: Bearer` challenge for a 401.
//!
//! Downstream, [`crate::scope`] maps the validated scopes to the operating-level
//! ceiling (scope can only LOWER it; bead P1-9e).

use std::collections::HashSet;
use std::fmt;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
#[cfg(test)]
use sha2::{Digest, Sha256};

use oraclemcp_audit::{HmacSha256Key, HmacSha256KeyError};

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
    /// The JWT does not explicitly identify itself as an RFC 9068 access token.
    #[error("unexpected JWT token type")]
    UnexpectedTokenType,
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

/// Verifies a JWT signature for a given `alg`. Only HS256 is implemented in
/// production ([`Hs256Verifier`]). An asymmetric verifier (RS256/ES256 via JWKS)
/// is a fail-closed seam the embedding transport may supply; none ships, so
/// asymmetric tokens are rejected until one is wired.
pub trait SignatureVerifier {
    /// Whether `signature` is valid for `signing_input` under `alg`.
    fn verify(&self, alg: &str, signing_input: &[u8], signature: &[u8]) -> bool;
}

/// HS256 (HMAC-SHA256) verifier.
#[derive(Debug)]
pub struct Hs256Verifier {
    secret: HmacSha256Key,
}

impl Hs256Verifier {
    /// Validate and install the HS256 shared secret.
    ///
    /// # Errors
    ///
    /// Returns [`HmacSha256KeyError`] when the secret is shorter than the
    /// 256-bit minimum required for HS256.
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, HmacSha256KeyError> {
        Ok(Self {
            secret: HmacSha256Key::new(secret)?,
        })
    }
}

impl SignatureVerifier for Hs256Verifier {
    fn verify(&self, alg: &str, signing_input: &[u8], signature: &[u8]) -> bool {
        // Reject `none` and any non-HS256 alg outright (alg-confusion / alg=none).
        alg == "HS256" && constant_time_eq(&self.secret.authenticate(signing_input), signature)
    }
}

/// Resource-server configuration.
#[derive(Clone, Debug, Default)]
pub struct ResourceServerConfig {
    /// The canonical resource identifier this server represents. The token's
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
        let (header, claims, signing_input, signature) = parse_jwt(token)?;
        if !is_access_token_type(&header.typ) {
            return Err(TokenError::UnexpectedTokenType);
        }
        let alg = header.alg;
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
        // RFC 9068 required access-token claims. Validate their shapes even
        // when a caller supplies an already signature-verified claim set.
        for claim in ["iss", "sub", "client_id", "jti"] {
            if !claims[claim]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty())
            {
                return Err(TokenError::Malformed);
            }
        }
        if !claims["iat"].is_number() {
            return Err(TokenError::Malformed);
        }
        // Issuer allowlist (fail-closed: empty allowlist rejects everything).
        let iss = claims["iss"].as_str().ok_or(TokenError::Malformed)?;
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

#[derive(Debug)]
struct JwtHeader {
    alg: String,
    typ: String,
}

impl<'de> Deserialize<'de> for JwtHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HeaderVisitor;

        impl<'de> Visitor<'de> for HeaderVisitor {
            type Value = JwtHeader;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JWT protected-header object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut alg = None;
                let mut typ = None;

                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom(
                            "duplicate JWT protected-header parameter",
                        ));
                    }
                    match key.as_str() {
                        "alg" => alg = Some(map.next_value::<String>()?),
                        "typ" => typ = Some(map.next_value::<String>()?),
                        _ => {
                            let _: IgnoredAny = map.next_value()?;
                        }
                    }
                }

                Ok(JwtHeader {
                    alg: alg.unwrap_or_default(),
                    typ: typ.unwrap_or_default(),
                })
            }
        }

        deserializer.deserialize_map(HeaderVisitor)
    }
}

fn is_access_token_type(value: &str) -> bool {
    value.eq_ignore_ascii_case("at+jwt") || value.eq_ignore_ascii_case("application/at+jwt")
}

/// Parse a JWT into (header, claims JSON, signing input bytes, signature bytes).
fn parse_jwt(token: &str) -> Result<(JwtHeader, Value, Vec<u8>, Vec<u8>), TokenError> {
    let mut parts = token.trim().split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(TokenError::Malformed),
    };
    let header: JwtHeader = serde_json::from_slice(&b64url_decode(h).ok_or(TokenError::Malformed)?)
        .map_err(|_| TokenError::Malformed)?;
    let claims: Value = serde_json::from_slice(&b64url_decode(p).ok_or(TokenError::Malformed)?)
        .map_err(|_| TokenError::Malformed)?;
    let signature = b64url_decode(s).ok_or(TokenError::Malformed)?;
    let signing_input = format!("{h}.{p}").into_bytes();
    Ok((header, claims, signing_input, signature))
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
#[cfg(test)]
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

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn mint(claims: Value) -> String {
        mint_with_header(json!({ "alg": "HS256", "typ": "at+jwt" }), claims)
    }

    fn mint_with_header(header: Value, claims: Value) -> String {
        mint_with_raw_header(&serde_json::to_string(&header).unwrap(), claims)
    }

    fn mint_with_raw_header(header: &str, claims: Value) -> String {
        let h = b64url_encode(header.as_bytes());
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
        Hs256Verifier::new(SECRET.to_vec()).expect("valid HS256 test key")
    }

    #[test]
    fn hs256_verifier_rejects_undersized_keys() {
        for len in [0, 1, 31] {
            Hs256Verifier::new(vec![0x5a; len]).expect_err("undersized HS256 key must fail closed");
        }
        Hs256Verifier::new(vec![0x5a; 32]).expect("32-byte HS256 key is valid");
        Hs256Verifier::new(vec![0x5a; 33]).expect("longer HS256 key is valid");
    }

    fn good_claims() -> Value {
        json!({
            "iss": "https://idp.example",
            "aud": ["https://oraclemcp.example/mcp"],
            "exp": 2_000_000_000i64,
            "nbf": 1_000_000_000i64,
            "sub": "subject-123",
            "client_id": "client-123",
            "iat": 1_000_000_000i64,
            "jti": "token-123",
            "scope": "openid oracle:read oracle:execute",
        })
    }

    #[derive(Clone, Copy, Debug)]
    enum OAuthMatrixCase {
        Accept,
        MalformedParts,
        UnexpectedTokenType,
        UnsupportedAlg,
        BadSignature,
        Expired,
        NotYetValid,
        UntrustedIssuer,
        AudienceMismatch,
        InsufficientScope,
    }

    struct OAuthMatrixRow {
        name: &'static str,
        case: OAuthMatrixCase,
        now_unix: i64,
        expected_error: Option<TokenError>,
    }

    fn tamper_signature(token: &str) -> String {
        let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(parts.len(), 3, "minted test token has three JWT parts");
        let first = parts[2]
            .as_bytes()
            .first()
            .copied()
            .expect("minted HS256 signature is non-empty");
        // Change the first sextet, not the final base64url character whose low
        // padding bits may be discarded while decoding a 32-byte signature.
        parts[2].replace_range(..1, if first == b'A' { "Q" } else { "A" });
        parts.join(".")
    }

    #[test]
    fn oauth_validation_matrix_has_nine_typed_rejections_and_one_accept() {
        const NOW: i64 = 1_500_000_000;
        let rows = [
            OAuthMatrixRow {
                name: "valid",
                case: OAuthMatrixCase::Accept,
                now_unix: NOW,
                expected_error: None,
            },
            OAuthMatrixRow {
                name: "parts",
                case: OAuthMatrixCase::MalformedParts,
                now_unix: NOW,
                expected_error: Some(TokenError::Malformed),
            },
            OAuthMatrixRow {
                name: "typ",
                case: OAuthMatrixCase::UnexpectedTokenType,
                now_unix: NOW,
                expected_error: Some(TokenError::UnexpectedTokenType),
            },
            OAuthMatrixRow {
                name: "alg",
                case: OAuthMatrixCase::UnsupportedAlg,
                now_unix: NOW,
                expected_error: Some(TokenError::UnsupportedAlg("none".to_owned())),
            },
            OAuthMatrixRow {
                name: "signature",
                case: OAuthMatrixCase::BadSignature,
                now_unix: NOW,
                expected_error: Some(TokenError::BadSignature),
            },
            OAuthMatrixRow {
                name: "exp",
                case: OAuthMatrixCase::Expired,
                now_unix: 2_000_000_000,
                expected_error: Some(TokenError::Expired),
            },
            OAuthMatrixRow {
                name: "nbf",
                case: OAuthMatrixCase::NotYetValid,
                now_unix: 999_999_999,
                expected_error: Some(TokenError::NotYetValid),
            },
            OAuthMatrixRow {
                name: "iss",
                case: OAuthMatrixCase::UntrustedIssuer,
                now_unix: NOW,
                expected_error: Some(TokenError::UntrustedIssuer(
                    "https://evil-idp.example".to_owned(),
                )),
            },
            OAuthMatrixRow {
                name: "aud",
                case: OAuthMatrixCase::AudienceMismatch,
                now_unix: NOW,
                expected_error: Some(TokenError::AudienceMismatch),
            },
            OAuthMatrixRow {
                name: "scope",
                case: OAuthMatrixCase::InsufficientScope,
                now_unix: NOW,
                expected_error: Some(TokenError::InsufficientScope),
            },
        ];
        assert_eq!(
            rows.len(),
            10,
            "matrix contract is nine rejects + one accept"
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.expected_error.is_some())
                .count(),
            9,
            "matrix contract retains every rejection class"
        );

        for row in rows {
            let mut config = cfg();
            config.required_scopes = vec!["oracle:read".to_owned()];
            let mut claims = good_claims();
            let token = match row.case {
                OAuthMatrixCase::Accept => mint(claims),
                OAuthMatrixCase::MalformedParts => "only.two".to_owned(),
                OAuthMatrixCase::UnexpectedTokenType => {
                    mint_with_header(json!({ "alg": "HS256", "typ": "JWT" }), claims)
                }
                OAuthMatrixCase::UnsupportedAlg => {
                    mint_with_header(json!({ "alg": "none", "typ": "at+jwt" }), claims)
                }
                OAuthMatrixCase::BadSignature => tamper_signature(&mint(claims)),
                OAuthMatrixCase::Expired | OAuthMatrixCase::NotYetValid => mint(claims),
                OAuthMatrixCase::UntrustedIssuer => {
                    claims["iss"] = json!("https://evil-idp.example");
                    mint(claims)
                }
                OAuthMatrixCase::AudienceMismatch => {
                    claims["aud"] = json!(["https://some-other-resource.example"]);
                    mint(claims)
                }
                OAuthMatrixCase::InsufficientScope => {
                    config.required_scopes.push("oracle:admin".to_owned());
                    mint(claims)
                }
            };

            let result = config.validate(&token, &verifier(), row.now_unix);
            match row.expected_error {
                Some(expected) => assert_eq!(result, Err(expected), "row {}", row.name),
                None => assert_eq!(
                    result,
                    Ok(vec![
                        "openid".to_owned(),
                        "oracle:read".to_owned(),
                        "oracle:execute".to_owned(),
                    ]),
                    "row {}",
                    row.name
                ),
            }
        }
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
    fn rfc9068_access_token_types_are_case_insensitive() {
        for typ in [
            "at+jwt",
            "AT+JWT",
            "application/at+jwt",
            "Application/AT+Jwt",
        ] {
            let token = mint_with_header(json!({ "alg": "HS256", "typ": typ }), good_claims());
            cfg()
                .validate(&token, &verifier(), 1_500_000_000)
                .expect("RFC 9068 access-token type must pass");
        }
    }

    #[test]
    fn generic_missing_and_id_token_types_are_rejected() {
        for header in [
            json!({ "alg": "HS256", "typ": "JWT" }),
            json!({ "alg": "HS256" }),
            json!({ "alg": "HS256", "typ": "id+jwt" }),
            json!({ "alg": "HS256", "typ": "application/id+jwt" }),
            json!({ "alg": "HS256", "typ": " at+jwt" }),
        ] {
            let token = mint_with_header(header, good_claims());
            assert_eq!(
                cfg().validate(&token, &verifier(), 1_500_000_000),
                Err(TokenError::UnexpectedTokenType)
            );
        }
    }

    #[test]
    fn malformed_and_duplicate_protected_headers_fail_closed() {
        let non_string_type =
            mint_with_header(json!({ "alg": "HS256", "typ": ["at+jwt"] }), good_claims());
        assert_eq!(
            cfg().validate(&non_string_type, &verifier(), 1_500_000_000),
            Err(TokenError::Malformed)
        );

        for header in [
            r#"{"alg":"HS256","typ":"at+jwt","typ":"JWT"}"#,
            r#"{"alg":"HS256","typ":"JWT","typ":"at+jwt"}"#,
            r#"{"alg":"HS256","alg":"HS256","typ":"at+jwt"}"#,
        ] {
            let token = mint_with_raw_header(header, good_claims());
            assert_eq!(
                cfg().validate(&token, &verifier(), 1_500_000_000),
                Err(TokenError::Malformed)
            );
        }
    }

    #[test]
    fn required_rfc9068_claims_must_have_valid_shapes() {
        for claim in ["iss", "sub", "client_id", "iat", "jti"] {
            let mut missing = good_claims();
            missing.as_object_mut().unwrap().remove(claim);
            assert_eq!(
                cfg().validate(&mint(missing), &verifier(), 1_500_000_000),
                Err(TokenError::Malformed),
                "missing {claim}"
            );
        }

        for (claim, invalid) in [
            ("iss", json!("")),
            ("sub", json!("  ")),
            ("client_id", json!(null)),
            ("iat", json!("1000000000")),
            ("jti", json!([])),
        ] {
            let mut malformed = good_claims();
            malformed[claim] = invalid;
            assert_eq!(
                cfg().validate(&mint(malformed), &verifier(), 1_500_000_000),
                Err(TokenError::Malformed),
                "malformed {claim}"
            );
        }

        let mut missing_exp = good_claims();
        missing_exp.as_object_mut().unwrap().remove("exp");
        assert_eq!(
            cfg().validate(&mint(missing_exp), &verifier(), 1_500_000_000),
            Err(TokenError::Malformed)
        );

        let mut missing_aud = good_claims();
        missing_aud.as_object_mut().unwrap().remove("aud");
        assert_eq!(
            cfg().validate(&mint(missing_aud), &verifier(), 1_500_000_000),
            Err(TokenError::AudienceMismatch)
        );
    }

    #[test]
    fn token_type_is_rejected_before_claim_validation() {
        let token = mint_with_header(
            json!({ "alg": "HS256", "typ": "JWT" }),
            json!({ "iss": "https://idp.example" }),
        );
        assert_eq!(
            cfg().validate(&token, &verifier(), 1_500_000_000),
            Err(TokenError::UnexpectedTokenType)
        );
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
