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

/// Extract the host authority from an `Origin` value (`https://h:port` → `h:port`).
fn origin_authority(origin: &str) -> &str {
    origin
        .trim()
        .split_once("://")
        .map_or(origin.trim(), |(_, rest)| rest.trim_end_matches('/'))
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
            let auth = origin_authority(origin);
            let origin_ok = authority_is_loopback(auth)
                || self.allowed_origins.iter().any(|o| o == origin.trim());
            if !origin_ok {
                return Err(HttpGuardError::ForbiddenOrigin(origin.to_owned()));
            }
        }
        Ok(())
    }

    fn host_allowed(&self, host: &str) -> bool {
        let host = host.trim();
        self.allowed_hosts.iter().any(|h| {
            // Match either the full authority or the host portion.
            h == host || host_only(h) == host_only(host)
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
