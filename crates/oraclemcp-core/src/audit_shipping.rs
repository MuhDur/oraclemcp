//! SIEM HTTP forwarder for the audit shipping seam (bead D2).
//!
//! `oraclemcp-audit` defines the [`ShippingForwarder`] seam and the
//! [`WormFileForwarder`](oraclemcp_audit::WormFileForwarder) (a local, no-network
//! WORM mirror) plus the SIEM-native line formats ([`cef_line`] / [`syslog_line`]).
//! This module adds the **network** forwarder: [`SiemHttpForwarder`] POSTs each
//! signed [`AuditRecord`] to a configured SIEM/WORM endpoint over
//! asupersync's Tokio-free HTTP/1 client — the same egress path the OTLP
//! exporter uses, so the engine-free boundary lint stays green (no
//! reqwest/hyper/tokio).
//! Remote destinations require HTTPS. An unauthenticated literal-loopback HTTP
//! endpoint is the sole local-development exception, and redirects are never
//! followed so neither headers nor bodies can be replayed after a downgrade.
//!
//! # Fail-safe by construction
//!
//! Production wiring wraps this blocking transport in
//! [`DurableShippingForwarder`](oraclemcp_audit::DurableShippingForwarder).
//! The signed record is durably spooled after the authoritative local fsync,
//! then this transport runs on the spool's dedicated worker without holding the
//! audit chain mutex. A SIEM outage therefore degrades to an ordered retrying
//! local spool and never delays or fails the audited call.
//!
//! # Off by default
//!
//! Nothing here is constructed unless an operator configures a shipping
//! destination (`[audit.shipping]` / env). The binary builds a `SiemHttpForwarder`
//! only when an endpoint is set; otherwise the auditor uses the plain
//! `FileAuditSink` exactly as before.

use std::time::Duration;

use asupersync::Cx;
use asupersync::http::h1::http_client::HttpClient;
use asupersync::http::h1::types::Method;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_audit::{AuditRecord, ShippingError, ShippingForwarder, cef_line, syslog_line};
use oraclemcp_config::SiemEndpoint;

/// The wire format a [`SiemHttpForwarder`] POSTs to the SIEM endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SiemFormat {
    /// One JSON object per request — the exact signed [`AuditRecord`], so the
    /// destination can reconstruct a JSONL stream that re-verifies under
    /// `oraclemcp audit verify`. `Content-Type: application/json`.
    Json,
    /// ArcSight CEF v0 line. `Content-Type: text/plain`.
    Cef,
    /// RFC-5424 syslog line with the chain-integrity structured-data element.
    /// `Content-Type: text/plain`.
    Syslog,
}

impl SiemFormat {
    /// Parse a format name (case-insensitive). `None` for an unknown name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "cef" => Some(Self::Cef),
            "syslog" => Some(Self::Syslog),
            _ => None,
        }
    }

    /// The `Content-Type` for this format.
    #[must_use]
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Cef | Self::Syslog => "text/plain; charset=utf-8",
        }
    }

    /// Render one record to this format's request body bytes.
    #[must_use]
    pub fn encode(self, record: &AuditRecord) -> Vec<u8> {
        match self {
            // Serialization of an AuditRecord never fails (all fields are plain
            // data); fall back to an empty object on the impossible error.
            Self::Json => serde_json::to_vec(record).unwrap_or_else(|_| b"{}".to_vec()),
            Self::Cef => cef_line(record).into_bytes(),
            Self::Syslog => syslog_line(record).into_bytes(),
        }
    }
}

/// Forwards each signed audit record to a transport-policy-validated SIEM/WORM
/// endpoint over
/// asupersync's HTTP/1 client.
///
/// One record per POST keeps tamper-evidence simple: the destination receives
/// the records in `seq` order and (for [`SiemFormat::Json`]) can append them to
/// a JSONL file that `oraclemcp audit verify` accepts unchanged.
pub struct SiemHttpForwarder {
    endpoint: SiemEndpoint,
    format: SiemFormat,
    timeout: Duration,
    /// Extra request headers (e.g. `Authorization: Splunk <token>`). Never
    /// logged; sent only on the outbound request.
    headers: Vec<(String, String)>,
}

impl SiemHttpForwarder {
    /// Default per-request timeout for a SIEM POST.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

    /// Build a forwarder for a transport-policy-validated `endpoint` using
    /// `format`. Add auth headers with [`Self::with_header`].
    #[must_use]
    pub fn new(endpoint: SiemEndpoint, format: SiemFormat) -> Self {
        Self {
            endpoint,
            format,
            timeout: Self::DEFAULT_TIMEOUT,
            headers: Vec::new(),
        }
    }

    /// Override the per-request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Attach an outbound request header (e.g. a SIEM API token). Sent only on
    /// the wire; never emitted as telemetry or logs.
    ///
    /// # Errors
    /// Refuses every authentication header on the narrow plaintext-loopback
    /// development transport so a direct library caller cannot bypass config
    /// validation.
    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, ShippingError> {
        if !self.endpoint.uses_confidential_transport() {
            return Err(ShippingError::Transport(
                "SIEM authentication headers require an HTTPS endpoint".to_owned(),
            ));
        }
        self.headers.push((name.into(), value.into()));
        Ok(self)
    }

    /// The configured endpoint's safe origin for diagnostics. Path and query
    /// material are omitted.
    #[must_use]
    pub fn diagnostic_origin(&self) -> &str {
        self.endpoint.diagnostic_origin()
    }

    /// POST one encoded record on a dedicated current-thread asupersync runtime.
    /// This is deliberately blocking and must run behind the production
    /// durable-spool worker, not on an audited request thread.
    fn post(&self, record: &AuditRecord, body: Vec<u8>) -> Result<(), ShippingError> {
        // The SIEM POST is real network I/O; the forwarder runtime needs a
        // reactor to drive it — without one the POST hangs (release-gre.16).
        let reactor = asupersync::runtime::reactor::create_reactor()
            .map_err(|e| ShippingError::Transport(format!("forwarder reactor: {e}")))?;
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .map_err(|e| ShippingError::Transport(format!("forwarder runtime: {e}")))?;

        let endpoint = self.endpoint.clone();
        let timeout = self.timeout;
        let mut headers = vec![(
            "Content-Type".to_owned(),
            self.format.content_type().to_owned(),
        )];
        // Delivery is at least once: a crash can occur after the collector
        // accepts a POST but before the spool atomically acknowledges it. Give
        // collectors a stable, non-secret deduplication key for that replay.
        headers.push((
            "Idempotency-Key".to_owned(),
            format!("oraclemcp-audit-{}-{}", record.seq, record.entry_hash),
        ));
        headers.push(("X-Oraclemcp-Audit-Seq".to_owned(), record.seq.to_string()));
        headers.extend(self.headers.iter().cloned());

        // block-on-boundary: dedicated audit-forwarder runtime after local fsync.
        runtime.block_on(async move {
            let cx = Cx::current().expect("asupersync block_on installs a current Cx");
            // Audit records are confidential. Never replay their body or
            // headers to a redirect target, even when an HTTPS endpoint tries
            // to downgrade or move the request. Operators must configure the
            // final ingest URL explicitly.
            let client = HttpClient::builder().no_redirects().build();
            let response = asupersync::time::timeout(cx.now(), timeout, async {
                client
                    .request(&cx, Method::Post, endpoint.as_str(), headers, body)
                    .await
            })
            .await
            .map_err(|_| ShippingError::Transport("SIEM request timed out".to_owned()))?
            .map_err(|e| ShippingError::Transport(format!("SIEM request failed: {e}")))?;

            // 2xx = accepted. Any other status means the destination did not
            // durably accept the record; surface it so the decorator counts a
            // forward failure (the local chain still has the record).
            if (200..300).contains(&response.status) {
                Ok(())
            } else {
                Err(ShippingError::Transport(format!(
                    "SIEM endpoint returned HTTP {}",
                    response.status
                )))
            }
        })
    }
}

impl ShippingForwarder for SiemHttpForwarder {
    fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError> {
        let body = self.format.encode(record);
        self.post(record, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_audit::{
        AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, GENESIS_HASH, SigningKey,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    const SQL_SENTINEL: &str = "QA31_HTTP_SIEM_SECRET";

    fn rec() -> AuditRecord {
        let draft = AuditEntryDraft {
            subject: AuditSubject::new("agent", "agent-1"),
            db_evidence: None,
            cancel: None,
            tool: "oracle_execute".to_owned(),
            sql: format!("UPDATE users SET password='{SQL_SENTINEL}'"),
            danger_level: "DESTRUCTIVE".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: Some(1),
            outcome: AuditOutcome::Succeeded,
        };
        AuditRecord::chained_signed(
            &draft,
            1,
            GENESIS_HASH,
            "2026-06-20T00:00:00Z".to_owned(),
            &SigningKey::new("k1", b"0123456789abcdef0123456789abcdef".to_vec())
                .expect("valid test key"),
        )
    }

    #[test]
    fn format_parse_is_case_insensitive() {
        assert_eq!(SiemFormat::parse("JSON"), Some(SiemFormat::Json));
        assert_eq!(SiemFormat::parse(" cef "), Some(SiemFormat::Cef));
        assert_eq!(SiemFormat::parse("Syslog"), Some(SiemFormat::Syslog));
        assert_eq!(SiemFormat::parse("xml"), None);
    }

    #[test]
    fn json_encoding_roundtrips_to_the_same_record() {
        let r = rec();
        let body = SiemFormat::Json.encode(&r);
        assert!(
            !body
                .windows(SQL_SENTINEL.len())
                .any(|bytes| bytes == SQL_SENTINEL.as_bytes()),
            "current JSON SIEM body must not contain SQL literals"
        );
        let back: AuditRecord = serde_json::from_slice(&body).expect("json record");
        assert_eq!(back, r, "JSON wire body is the exact signed record");
    }

    #[test]
    fn cef_and_syslog_encodings_carry_chain_fields() {
        let r = rec();
        let cef = String::from_utf8(SiemFormat::Cef.encode(&r)).unwrap();
        assert!(cef.starts_with("CEF:0|oraclemcp|"));
        assert!(cef.contains("entryHash="));
        assert!(!cef.contains(SQL_SENTINEL));
        let sys = String::from_utf8(SiemFormat::Syslog.encode(&r)).unwrap();
        assert!(sys.contains("[oraclemcp@0"));
        assert!(sys.contains("seq=\"1\""));
        assert!(!sys.contains(SQL_SENTINEL));
    }

    #[test]
    fn content_type_matches_format() {
        assert_eq!(SiemFormat::Json.content_type(), "application/json");
        assert!(SiemFormat::Cef.content_type().starts_with("text/plain"));
    }

    #[test]
    fn unreachable_endpoint_yields_transport_error_not_panic() {
        // Port 1 is unbound; the POST must fail with a Transport error (which
        // the ShippingAuditSink treats as non-fatal), never panic or block.
        let endpoint = SiemEndpoint::parse("http://127.0.0.1:1/audit")
            .expect("literal loopback plaintext is the explicit test-only exception");
        let fwd = SiemHttpForwarder::new(endpoint, SiemFormat::Json)
            .with_timeout(Duration::from_millis(200));
        let result = fwd.forward(&rec());
        assert!(
            matches!(result, Err(ShippingError::Transport(_))),
            "an unreachable SIEM yields a transport error, got {result:?}"
        );
    }

    #[test]
    fn plaintext_loopback_forwarder_rejects_auth_headers_without_retaining_secret() {
        let endpoint =
            SiemEndpoint::parse("http://127.0.0.1:1/audit").expect("literal loopback endpoint");
        let secret = "QA13_MUST_NOT_LEAK";
        let error = match SiemHttpForwarder::new(endpoint, SiemFormat::Json)
            .with_header("Authorization", secret)
        {
            Err(error) => error,
            Ok(_) => panic!("auth headers require confidential transport"),
        };
        let error = error.to_string();
        assert!(error.contains("require an HTTPS endpoint"));
        assert!(!error.contains(secret));
    }

    #[test]
    fn siem_forwarder_never_follows_redirects() {
        let redirect_listener = TcpListener::bind("127.0.0.1:0").expect("bind redirect server");
        let redirect_addr = redirect_listener.local_addr().expect("redirect address");
        let target_listener = TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
        target_listener
            .set_nonblocking(true)
            .expect("nonblocking target listener");
        let target_addr = target_listener.local_addr().expect("target address");

        let redirect_server = thread::spawn(move || {
            let (mut stream, _) = redirect_listener.accept().expect("accept SIEM POST");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            let mut request = [0_u8; 16 * 1024];
            let bytes = stream.read(&mut request).expect("read SIEM POST");
            assert!(
                request[..bytes].starts_with(b"POST /initial HTTP/1.1\r\n"),
                "unexpected request: {}",
                String::from_utf8_lossy(&request[..bytes])
            );
            let request = String::from_utf8_lossy(&request[..bytes]);
            assert!(
                request.contains("Idempotency-Key: oraclemcp-audit-1-sha256:"),
                "restart-safe idempotency key missing: {request}"
            );
            assert!(
                request.contains("X-Oraclemcp-Audit-Seq: 1"),
                "audit sequence header missing: {request}"
            );
            write!(
                stream,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target_addr}/downgraded\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("write redirect");
        });

        let endpoint = SiemEndpoint::parse(format!("http://{redirect_addr}/initial"))
            .expect("literal loopback endpoint");
        let result = SiemHttpForwarder::new(endpoint, SiemFormat::Json)
            .with_timeout(Duration::from_secs(2))
            .forward(&rec());
        redirect_server.join().expect("redirect server joins");

        assert!(
            matches!(result, Err(ShippingError::Transport(ref message)) if message.contains("HTTP 307")),
            "redirect must be surfaced as a failed shipment, got {result:?}"
        );
        assert!(
            matches!(target_listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "redirect target must never receive the signed audit body"
        );
    }
}
