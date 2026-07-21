//! Streamable-HTTP transport hardening (plan §7.1, risk R12; bead P1-9d /
//! oracle-qmwz.2.9.4). These are the known local-HTTP failure modes the
//! MCP spec (2025-11-25) calls out for servers that bind a port:
//!
//! - **DNS-rebinding guard**: a malicious page can point a victim browser at
//!   `http://attacker.example` that resolves to `127.0.0.1`, smuggling requests
//!   to a localhost MCP server. We defend by validating the `Host` header is one
//!   we actually serve (loopback, or an operator allowlist). A rebinding
//!   request carries the attacker's hostname in `Host` and is rejected.
//! - **Origin check**: reject cross-origin browser requests whose `Origin` is
//!   not loopback and not on the operator allowlist.
//! - **Reject non-loopback `http://`**: off-box traffic must be HTTPS; plain
//!   `http` to a non-loopback host is refused unless the operator explicitly
//!   opts in (e.g. a TLS-terminating reverse proxy on the same host).
//!
//! This module is transport-agnostic pure logic. The native HTTP transport and
//! any embedding transport call [`HttpGuardPolicy::check`] before dispatch.

/// Why an inbound HTTP request was rejected by the transport guard.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HttpGuardError {
    /// The `Host` header was absent (required for the DNS-rebinding guard).
    #[error("missing Host header")]
    MissingHost,
    /// The `Host` header names an authority this server does not serve
    /// (DNS-rebinding guard).
    #[error("untrusted Host header: {0}")]
    UntrustedHost(String),
    /// Plain `http://` to a non-loopback host (HTTPS required off-box).
    #[error("plain http to a non-loopback host is refused; use https")]
    NonLoopbackHttp,
    /// The `Origin` header is not loopback and not on the allowlist.
    #[error("forbidden Origin: {0}")]
    ForbiddenOrigin(String),
}

/// Operator policy for the HTTP transport guard.
#[derive(Clone, Debug, Default)]
pub struct HttpGuardPolicy {
    /// Exact-match allowed `Origin` values (e.g. `https://app.example`).
    /// Loopback origins are always allowed regardless of this list.
    pub allowed_origins: Vec<String>,
    /// Allowed `Host` authorities (host or `host:port`) beyond loopback. Set
    /// when the server is reached via a known external name / reverse proxy.
    pub allowed_hosts: Vec<String>,
    /// Permit plain `http://` to a non-loopback host (default `false`: HTTPS
    /// required off-box). Set only behind a same-host TLS-terminating proxy.
    pub allow_non_loopback_http: bool,
}

/// Strip a `:port` suffix from an authority, handling bracketed IPv6
/// (`[::1]:443` → `::1`, `[::1]` → `::1`, `host:80` → `host`).
fn host_only(authority: &str) -> &str {
    let a = authority.trim();
    if let Some(rest) = a.strip_prefix('[') {
        // IPv6 literal `[inner]` optionally followed by `:port`. The remainder
        // after the closing `]` MUST be empty or a valid `:port`; otherwise the
        // authority carries trailing garbage (e.g. `[::1].attacker.example`,
        // `[::1]@attacker.example`, `[::1]evil`) and must NOT be reduced to its
        // inner literal, lest a crafted authority masquerade as loopback. In
        // that case return the authority unchanged so it cannot match the set.
        if let Some((inner, after)) = rest.split_once(']') {
            let after_ok = after.is_empty()
                || after.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
                });
            if after_ok {
                return inner;
            }
        }
        // Unterminated bracket or trailing garbage: not a clean IPv6 authority.
        return a;
    }
    match a.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => host,
        _ => a,
    }
}

/// Whether an authority refers to the loopback interface.
#[must_use]
pub fn authority_is_loopback(authority: &str) -> bool {
    matches!(
        host_only(authority).to_ascii_lowercase().as_str(),
        "127.0.0.1" | "::1" | "localhost"
    )
}

/// Canonicalize a browser origin without accepting a path, query, fragment, or
/// credentials. A configuration entry may carry one cosmetic trailing slash;
/// an inbound Origin must already use the browser's serialized no-slash form.
///
/// This is deliberately a comparison normalization, not a permissive parser:
/// normalizing an operator spelling must not turn a malformed request origin
/// into an allowlisted one.
fn normalized_origin(value: &str, config_entry: bool) -> Option<String> {
    let value = value.trim();
    let (scheme, authority) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }
    let authority = if config_entry {
        authority.strip_suffix('/').unwrap_or(authority)
    } else {
        authority
    };
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || (config_entry && authority.ends_with('/'))
    {
        return None;
    }
    let authority = normalized_authority(authority)?;
    let authority = match (scheme.as_str(), authority.as_str()) {
        ("http", authority) if authority.ends_with(":80") => &authority[..authority.len() - 3],
        ("https", authority) if authority.ends_with(":443") => &authority[..authority.len() - 4],
        _ => authority.as_str(),
    };
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

/// Canonicalize one complete HTTP authority. This is intentionally stricter
/// than [`host_only`]: the latter preserves legacy loopback checking, while an
/// allowlist match must never turn a path, credential, malformed bracket, or
/// invalid port into a trusted host.
fn normalized_authority(authority: &str) -> Option<String> {
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (literal, suffix) = bracketed.split_once(']')?;
        if literal.parse::<std::net::Ipv6Addr>().is_err() {
            return None;
        }
        let port = match suffix {
            "" => None,
            _ => Some(suffix.strip_prefix(':')?),
        };
        (format!("[{}]", literal.to_ascii_lowercase()), port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(port)),
            Some(_) => return None,
            None => (authority, None),
        };
        if host.is_empty()
            || host.starts_with('.')
            || host.ends_with('.')
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return None;
        }
        (host.to_ascii_lowercase(), port)
    };
    let port = match port {
        Some(port)
            if !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok() =>
        {
            format!(":{port}")
        }
        Some(_) => return None,
        None => String::new(),
    };
    Some(format!("{host}{port}"))
}

impl HttpGuardPolicy {
    /// Validate an inbound request. `scheme` is `http`/`https`; `host_header` is
    /// the `Host` value; `origin` is the `Origin` value if the client sent one
    /// (non-browser MCP clients may omit it). Returns `Ok(())` if the request
    /// may proceed, else the specific [`HttpGuardError`].
    pub fn check(
        &self,
        scheme: &str,
        host_header: Option<&str>,
        origin: Option<&str>,
    ) -> Result<(), HttpGuardError> {
        // 1) Host is required, and must be one we serve (DNS-rebinding guard).
        let host = host_header.ok_or(HttpGuardError::MissingHost)?;
        let host_loopback = authority_is_loopback(host);
        if !host_loopback && !self.host_allowed(host) {
            return Err(HttpGuardError::UntrustedHost(host.to_owned()));
        }

        // 2) Plain http to a non-loopback host requires explicit opt-in.
        if scheme.eq_ignore_ascii_case("http") && !host_loopback && !self.allow_non_loopback_http {
            return Err(HttpGuardError::NonLoopbackHttp);
        }

        // 3) Origin (when present) must be loopback or allowlisted.
        if let Some(origin) = origin {
            let normalized = normalized_origin(origin, false);
            let origin_ok = normalized.as_deref().is_some_and(|origin| {
                authority_is_loopback(
                    origin
                        .strip_prefix("http://")
                        .or_else(|| origin.strip_prefix("https://"))
                        .unwrap_or(origin),
                ) || self
                    .allowed_origins
                    .iter()
                    .any(|allowed| normalized_origin(allowed, true).as_deref() == Some(origin))
            });
            if !origin_ok {
                return Err(HttpGuardError::ForbiddenOrigin(origin.to_owned()));
            }
        }
        Ok(())
    }

    fn host_allowed(&self, host: &str) -> bool {
        let Some(host) = normalized_authority(host.trim()) else {
            return false;
        };
        self.allowed_hosts.iter().any(|h| {
            let Some(h) = normalized_authority(h.trim()) else {
                return false;
            };
            // Match either the full authority or the host portion.
            h == host || host_only(&h) == host_only(&host)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> HttpGuardPolicy {
        HttpGuardPolicy::default()
    }

    #[test]
    fn loopback_http_is_allowed() {
        let p = default_policy();
        assert!(p.check("http", Some("127.0.0.1:8080"), None).is_ok());
        assert!(
            p.check(
                "http",
                Some("localhost:8080"),
                Some("http://localhost:8080")
            )
            .is_ok()
        );
        assert!(p.check("http", Some("[::1]:8080"), None).is_ok());
    }

    #[test]
    fn non_loopback_http_is_rejected_by_default() {
        let mut p = default_policy();
        p.allowed_hosts.push("mcp.internal".to_owned());
        assert_eq!(
            p.check("http", Some("mcp.internal"), None),
            Err(HttpGuardError::NonLoopbackHttp)
        );
        // HTTPS to the same allowlisted host is fine.
        assert!(p.check("https", Some("mcp.internal"), None).is_ok());
    }

    #[test]
    fn non_loopback_http_allowed_when_opted_in() {
        let p = HttpGuardPolicy {
            allowed_hosts: vec!["mcp.internal".to_owned()],
            allow_non_loopback_http: true,
            ..Default::default()
        };
        assert!(p.check("http", Some("mcp.internal"), None).is_ok());
    }

    #[test]
    fn dns_rebinding_host_is_rejected() {
        // Attacker page makes the browser send a request whose Host is the
        // attacker's domain (which resolves to 127.0.0.1). Not on the allowlist.
        let p = default_policy();
        assert_eq!(
            p.check("https", Some("attacker.example"), None),
            Err(HttpGuardError::UntrustedHost("attacker.example".to_owned()))
        );
    }

    #[test]
    fn allowlisted_host_passes_the_rebinding_guard() {
        let p = HttpGuardPolicy {
            allowed_hosts: vec!["mcp.corp.example:8443".to_owned()],
            ..Default::default()
        };
        assert!(
            p.check("https", Some("mcp.corp.example:8443"), None)
                .is_ok()
        );
        // Host portion match (different/absent port) also accepted.
        assert!(p.check("https", Some("mcp.corp.example"), None).is_ok());
    }

    #[test]
    fn missing_host_is_rejected() {
        let p = default_policy();
        assert_eq!(
            p.check("https", None, None),
            Err(HttpGuardError::MissingHost)
        );
    }

    #[test]
    fn cross_origin_is_rejected_but_allowlisted_origin_passes() {
        let p = HttpGuardPolicy {
            allowed_origins: vec!["https://app.example".to_owned()],
            allowed_hosts: vec!["mcp.internal".to_owned()],
            ..Default::default()
        };
        // Foreign origin -> rejected.
        assert_eq!(
            p.check("https", Some("mcp.internal"), Some("https://evil.example")),
            Err(HttpGuardError::ForbiddenOrigin(
                "https://evil.example".to_owned()
            ))
        );
        // Allowlisted origin -> ok.
        assert!(
            p.check("https", Some("mcp.internal"), Some("https://app.example"))
                .is_ok()
        );
    }

    #[test]
    fn normalization_is_tightening_only_for_inbound_guard_grammar() {
        let p = HttpGuardPolicy {
            // These are common operator spellings; browsers serialize the same
            // authorities lowercase, without the default port or slash.
            allowed_origins: vec!["HTTPS://APP.EXAMPLE:443/".to_owned()],
            allowed_hosts: vec!["MCP.INTERNAL:443".to_owned()],
            ..Default::default()
        };
        assert!(
            p.check("https", Some("mcp.internal"), Some("https://app.example"),)
                .is_ok(),
            "canonical operator entries match the browser's canonical wire spelling"
        );
        assert!(
            p.check(
                "https",
                Some("mcp.internal:443"),
                Some("https://app.example"),
            )
            .is_ok(),
            "Host is case-insensitive and retains the existing host-only match"
        );

        for malformed in [
            "https://app.example/",
            "https://app.example/path",
            "https://app.example?query",
            "https://user@app.example",
        ] {
            assert_eq!(
                p.check("https", Some("mcp.internal"), Some(malformed)),
                Err(HttpGuardError::ForbiddenOrigin(malformed.to_owned())),
                "comparison normalization must not broaden inbound Origin grammar: {malformed}"
            );
        }

        for malformed in [
            "mcp.internal/path",
            "mcp.internal@evil.example",
            "mcp.internal:443:1",
        ] {
            assert_eq!(
                p.check("https", Some(malformed), Some("https://app.example")),
                Err(HttpGuardError::UntrustedHost(malformed.to_owned())),
                "a normalized allowlist entry must still reject every malformed Host grammar: {malformed}"
            );
        }

        let malformed_config = HttpGuardPolicy {
            allowed_origins: vec!["https://app.example/path".to_owned()],
            allowed_hosts: vec!["mcp.internal/path".to_owned()],
            ..Default::default()
        };
        assert_eq!(
            malformed_config.check("https", Some("mcp.internal"), None),
            Err(HttpGuardError::UntrustedHost("mcp.internal".to_owned())),
            "an unproven configured host stays inert rather than gaining a canonical match"
        );
        let malformed_origin_config = HttpGuardPolicy {
            allowed_origins: vec!["https://app.example/path".to_owned()],
            allowed_hosts: vec!["mcp.internal".to_owned()],
            ..Default::default()
        };
        assert_eq!(
            malformed_origin_config.check(
                "https",
                Some("mcp.internal"),
                Some("https://app.example"),
            ),
            Err(HttpGuardError::ForbiddenOrigin(
                "https://app.example".to_owned()
            )),
            "an unproven configured origin stays inert rather than gaining a canonical match"
        );
    }

    #[test]
    fn ipv6_bracket_trailing_garbage_is_not_loopback() {
        // Clean IPv6 loopback authorities still reduce to their inner literal.
        assert_eq!(host_only("[::1]"), "::1");
        assert_eq!(host_only("[::1]:443"), "::1");
        assert!(authority_is_loopback("[::1]"));
        assert!(authority_is_loopback("[::1]:443"));
        // Non-loopback IPv6 with a port still parses cleanly.
        assert_eq!(host_only("[2001:db8::1]:8080"), "2001:db8::1");
        assert!(!authority_is_loopback("[2001:db8::1]:8080"));

        // Crafted authorities with trailing garbage after the closing bracket
        // must NOT be reduced to "::1" and must NOT be classified as loopback
        // (DNS-rebinding hardening: `[::1].attacker.example` etc.).
        for crafted in [
            "[::1].attacker.example",
            "[::1]@attacker.example",
            "[::1]evil",
            "[::1]:443x",
            "[::1]:",
            "[::1", // unterminated bracket
        ] {
            assert_eq!(
                host_only(crafted),
                crafted,
                "trailing-garbage authority {crafted:?} should be returned unchanged"
            );
            assert!(
                !authority_is_loopback(crafted),
                "trailing-garbage authority {crafted:?} must not be loopback"
            );
        }
    }

    #[test]
    fn check_rejects_ipv6_bracket_trailing_garbage_host() {
        // With the parser hardened, a crafted `[::1].attacker.example` Host
        // (not loopback, not on the allowlist) is rejected by the rebinding
        // guard rather than silently passing as loopback.
        let p = default_policy();
        assert_eq!(
            p.check("https", Some("[::1].attacker.example"), None),
            Err(HttpGuardError::UntrustedHost(
                "[::1].attacker.example".to_owned()
            ))
        );
    }

    #[test]
    fn loopback_origin_always_allowed() {
        let p = default_policy();
        assert!(
            p.check("http", Some("127.0.0.1:9"), Some("http://127.0.0.1:9"))
                .is_ok()
        );
        assert!(
            p.check("http", Some("localhost:9"), Some("https://localhost"))
                .is_ok()
        );
    }
}
