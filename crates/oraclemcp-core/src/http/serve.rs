//! Listener lifecycle for the native HTTP transport: bind/accept loops,
//! per-connection workers, the TLS and mandatory-mTLS control handshakes, and
//! graceful shutdown (stop accepting, drain workers, close stateful sessions).
//!
//! Extracted verbatim from `http/mod.rs` (behavior-identical). The request
//! handling itself still lives in the parent module: every accept path funnels
//! into [`handle_stream`], which reads one request through `wire` and hands it
//! to `super::handle_http_exchange`.
//!
//! Security-relevant invariants preserved exactly as they were:
//!
//! - the transport admission permit is taken BEFORE a worker thread is spawned,
//!   and a rejected connection is answered (HTTP) or dropped (HTTPS) without one;
//! - the dedicated control ingress completes certificate verification,
//!   fingerprint registration, and operator authorization BEFORE any HTTP byte is
//!   parsed, and only then moves from its separately bounded pre-auth handshake
//!   ledger into the authenticated control reserve;
//! - every ingress phase keeps its absolute deadline (TLS handshake, request
//!   header, request body), with the control probe's shorter windows intact.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rustls::{ServerConnection, StreamOwned};

use crate::admission::{AdmissionController, AdmissionPermit};
use crate::server::{DispatchCloseReason, OracleMcpServer};
use crate::tls::TlsServerConfig;

use super::wire::{DeadlineRead, parse_error_status, read_http_request, write_http_response};
use super::{
    EffectiveHttpScheme, HttpExchange, HttpResponse, HttpResultStore, HttpSessionStore,
    HttpTransportConfig, STATEFUL_IDLE_REAP_INTERVAL, cert_fingerprint_sha256,
    detached_admission_cx, handle_http_exchange, try_admit_http_transport,
};

const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(30);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// Short exposure window for the single loopback-only pre-auth control probe.
const CONTROL_PROBE_INGRESS_TIMEOUT: Duration = Duration::from_secs(1);
/// Absolute TLS deadline on the separately bounded remote control ingress.
const CONTROL_INGRESS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_CONTROL_PREAUTH_CAPACITY_SUBJECT: &str = "control-mtls-handshake";

/// Serve the MCP server over plaintext Streamable HTTP on `listener`.
///
/// # Errors
/// Returns fatal listener or connection write errors. Individual malformed
/// client requests are answered with HTTP errors and the listener continues.
pub fn serve_http(
    listener: TcpListener,
    server: OracleMcpServer,
    config: &HttpTransportConfig,
) -> std::io::Result<()> {
    serve_http_until(listener, server, config, Arc::new(AtomicBool::new(false)))
}

/// Serve HTTP until `shutdown` becomes true, then stop accepting new
/// connections and join active request workers before returning.
///
/// This is primarily used by tests and future signal wiring; the production
/// `serve_http` wrapper passes a never-set flag and therefore runs until the
/// listener itself fails or the process exits.
pub fn serve_http_until(
    listener: TcpListener,
    server: OracleMcpServer,
    config: &HttpTransportConfig,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let config = Arc::new(listener_config(config, EffectiveHttpScheme::Http));
    let mut last_idle_reap = Instant::now();
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::SeqCst) {
        reap_finished_workers(&mut workers);
        if last_idle_reap.elapsed() >= STATEFUL_IDLE_REAP_INTERVAL {
            reap_idle_stateful_sessions(&server, &config);
            last_idle_reap = Instant::now();
        }
        match listener.accept() {
            Ok((mut stream, addr)) => {
                let transport_permit = match try_admit_http_transport(
                    &config.transport_admission,
                    addr.ip().is_loopback(),
                ) {
                    Ok(permit) => permit,
                    Err(response) => {
                        let _ = stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT));
                        if let Err(e) = write_http_response(&mut stream, &response) {
                            tracing::debug!(
                                error = %e,
                                "native HTTP capacity rejection failed"
                            );
                        }
                        continue;
                    }
                };
                let server = server.clone();
                let config = Arc::clone(&config);
                workers.push(std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, &server, &config, transport_permit) {
                        tracing::debug!(error = %e, "native HTTP connection failed");
                    }
                }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    close_stateful_sessions_for_shutdown(&server, &config);
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

/// Serve the MCP server over TLS-terminating Streamable HTTPS on `listener`.
///
/// # Errors
/// Returns fatal listener or connection write errors. Individual malformed
/// client requests are answered with HTTP errors and the listener continues.
pub fn serve_https(
    listener: TcpListener,
    server: OracleMcpServer,
    config: &HttpTransportConfig,
    tls: Arc<TlsServerConfig>,
) -> std::io::Result<()> {
    serve_https_until(
        listener,
        server,
        config,
        tls,
        Arc::new(AtomicBool::new(false)),
    )
}

/// Serve HTTPS until `shutdown` becomes true, then stop accepting new
/// connections and join active request workers before returning.
pub fn serve_https_until(
    listener: TcpListener,
    server: OracleMcpServer,
    config: &HttpTransportConfig,
    tls: Arc<TlsServerConfig>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let config = Arc::new(listener_config(config, EffectiveHttpScheme::Https));
    let mut last_idle_reap = Instant::now();
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::SeqCst) {
        reap_finished_workers(&mut workers);
        if last_idle_reap.elapsed() >= STATEFUL_IDLE_REAP_INTERVAL {
            reap_idle_stateful_sessions(&server, &config);
            last_idle_reap = Instant::now();
        }
        match listener.accept() {
            Ok((stream, addr)) => {
                let transport_permit = match try_admit_http_transport(
                    &config.transport_admission,
                    addr.ip().is_loopback(),
                ) {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::debug!("native HTTPS connection rejected at transport capacity");
                        continue;
                    }
                };
                let server = server.clone();
                let config = Arc::clone(&config);
                let tls = Arc::clone(&tls);
                workers.push(std::thread::spawn(move || {
                    if let Err(e) =
                        handle_tls_connection(stream, &server, &config, tls, transport_permit)
                    {
                        tracing::debug!(error = %e, "native HTTPS connection failed");
                    }
                }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    close_stateful_sessions_for_shutdown(&server, &config);
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

/// Serve a separately bounded, mandatory-mTLS control ingress until shutdown.
///
/// Certificate verification and registration are completed before any HTTP
/// request bytes are parsed. The pre-authentication handshake ledger is
/// independent from the authenticated operator/readiness ledger in
/// `config.transport_admission`, so an unauthenticated peer can never consume a
/// control reserve. Only exact health/readiness and operator routes can promote
/// the authenticated control probe; every other route fails closed.
///
/// # Errors
/// Returns fatal listener errors. Individual TLS/auth/request failures are
/// isolated to their bounded connection worker.
pub fn serve_control_https_until(
    listener: TcpListener,
    server: OracleMcpServer,
    config: &HttpTransportConfig,
    tls: Arc<TlsServerConfig>,
    preauth_admission: Arc<AdmissionController>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let config = Arc::new(listener_config(config, EffectiveHttpScheme::Https));
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::SeqCst) {
        reap_finished_workers(&mut workers);
        match listener.accept() {
            Ok((stream, _)) => {
                let cx = detached_admission_cx();
                let preauth_permit =
                    match preauth_admission.try_admit(&cx, HTTP_CONTROL_PREAUTH_CAPACITY_SUBJECT) {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::debug!(
                                "dedicated control TLS handshake rejected at pre-auth capacity"
                            );
                            continue;
                        }
                    };
                let server = server.clone();
                let config = Arc::clone(&config);
                let tls = Arc::clone(&tls);
                workers.push(std::thread::spawn(move || {
                    if let Err(e) =
                        handle_control_tls_connection(stream, &server, &config, tls, preauth_permit)
                    {
                        tracing::debug!(error = %e, "dedicated control HTTPS connection failed");
                    }
                }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

fn reap_finished_workers(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        } else {
            index += 1;
        }
    }
}

fn listener_config(
    config: &HttpTransportConfig,
    native_scheme: EffectiveHttpScheme,
) -> HttpTransportConfig {
    let mut config = config.clone();
    if native_scheme.is_https() {
        config.effective_scheme = EffectiveHttpScheme::Https;
    }
    if config.stateful && config.session_store.is_none() {
        config.session_store = Some(Arc::new(HttpSessionStore::default()));
    }
    if config.stateful && config.result_store.is_none() {
        config.result_store = Some(Arc::new(HttpResultStore::new()));
    }
    config
}

pub(super) fn close_stateful_sessions_for_shutdown(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
) {
    if let Some(lifecycle) = &config.session_lifecycle {
        lifecycle.close_all_sessions();
    }
    if let Some(session_store) = &config.session_store {
        for session_id in session_store.session_ids() {
            server.notifications().forget_session(&session_id);
        }
        session_store.close_all();
    }
    if let Some(result_store) = &config.result_store {
        result_store.close_all();
    }
}

/// Close all stateful HTTP sessions and dispatch lanes for one principal.
///
/// Per-client credential rotate/revoke calls this after mutating
/// `clients.json`: the transport-facing session ids are removed, buffered SSE
/// results are closed, and the lane dispatch cleanup path revokes any in-memory
/// grants.
pub fn close_http_principal_sessions(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    principal_key: &str,
    reason: DispatchCloseReason,
    min_generation: Option<u64>,
) -> usize {
    let session_ids = config
        .session_store
        .as_ref()
        .map(|store| store.remove_principal(principal_key))
        .unwrap_or_default();
    if let Some(result_store) = &config.result_store {
        for session_id in &session_ids {
            result_store.remove_session(session_id);
        }
    }
    for session_id in &session_ids {
        server.notifications().forget_session(session_id);
    }
    let closed_lanes = config
        .session_lifecycle
        .as_ref()
        .map(|lifecycle| lifecycle.close_principal_sessions(principal_key, reason, min_generation))
        .unwrap_or(0);
    closed_lanes.max(session_ids.len())
}

pub(super) fn reap_idle_stateful_sessions(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
) -> usize {
    if !config.stateful || config.stateful_idle_ttl.is_zero() {
        return 0;
    }
    let Some(session_store) = &config.session_store else {
        return 0;
    };
    let expired = session_store.reap_idle(config.stateful_idle_ttl);
    let count = expired.len();
    for (session_id, principal_key) in expired {
        server.notifications().forget_session(&session_id);
        if let Some(result_store) = &config.result_store {
            result_store.remove_session(&session_id);
        }
        if let Some(lifecycle) = &config.session_lifecycle {
            lifecycle.close_session_with_reason(
                &session_id,
                &principal_key,
                DispatchCloseReason::Timeout,
            );
        }
    }
    count
}

fn handle_connection(
    mut stream: TcpStream,
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    mut transport_permit: AdmissionPermit,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    let peer_addr = stream.peer_addr().ok();
    let peer_is_loopback = peer_addr.is_some_and(|addr| addr.ip().is_loopback());
    handle_stream(
        &mut stream,
        server,
        config,
        peer_is_loopback,
        peer_addr.map(|addr| addr.to_string()),
        None,
        &mut transport_permit,
    )
}

impl DeadlineRead for TcpStream {
    fn set_ingress_read_timeout(&mut self, timeout: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }
}

impl DeadlineRead for StreamOwned<ServerConnection, TcpStream> {
    fn set_ingress_read_timeout(&mut self, timeout: Duration) -> std::io::Result<()> {
        self.sock.set_read_timeout(Some(timeout))
    }
}

fn handle_tls_connection(
    mut stream: TcpStream,
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    tls: Arc<TlsServerConfig>,
    mut transport_permit: AdmissionPermit,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    let mut connection = ServerConnection::new(tls).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("TLS setup: {e}"))
    })?;
    let peer_addr = stream.peer_addr().ok();
    let peer_is_loopback = peer_addr.is_some_and(|addr| addr.ip().is_loopback());
    let handshake_timeout = if transport_permit.is_control_probe() {
        CONTROL_PROBE_INGRESS_TIMEOUT
    } else {
        TLS_HANDSHAKE_TIMEOUT
    };
    complete_tls_handshake(&mut stream, &mut connection, handshake_timeout)?;
    stream.set_read_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    let peer_cert_fingerprint_sha256 = connection
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert_fingerprint_sha256(cert.as_ref()));
    let mut stream = StreamOwned::new(connection, stream);
    let result = handle_stream(
        &mut stream,
        server,
        config,
        peer_is_loopback,
        peer_addr.map(|addr| addr.to_string()),
        peer_cert_fingerprint_sha256,
        &mut transport_permit,
    );
    stream.conn.send_close_notify();
    let _ = stream.flush();
    result
}

fn handle_control_tls_connection(
    mut stream: TcpStream,
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    tls: Arc<TlsServerConfig>,
    preauth_permit: AdmissionPermit,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    let mut connection = ServerConnection::new(tls).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("TLS setup: {e}"))
    })?;
    let peer_addr = stream.peer_addr().ok();
    let peer_is_loopback = peer_addr.is_some_and(|addr| addr.ip().is_loopback());
    complete_tls_handshake(
        &mut stream,
        &mut connection,
        CONTROL_INGRESS_HANDSHAKE_TIMEOUT,
    )?;
    let fingerprint = connection
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert_fingerprint_sha256(cert.as_ref()))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "dedicated control ingress requires a verified client certificate",
            )
        })?;
    let principal_key = config
        .mtls_clients
        .principal_key_for_fingerprint(&fingerprint)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "dedicated control ingress client certificate is not registered",
            )
        })?;
    config
        .operator_authority
        .authorize(Some(&principal_key), false)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "dedicated control ingress certificate is not operator-authorized",
            )
        })?;

    // Authentication is complete before any HTTP bytes are parsed. Move this
    // worker from the separately bounded handshake ledger into the control
    // reserve; an unauthenticated peer can therefore never hold this permit.
    let cx = detached_admission_cx();
    let mut control_permit = config
        .transport_admission
        .try_admit_control_probe(&cx)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "dedicated control ingress is at authenticated capacity",
            )
        })?;
    drop(preauth_permit);

    stream.set_read_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    let mut stream = StreamOwned::new(connection, stream);
    let result = handle_stream(
        &mut stream,
        server,
        config,
        peer_is_loopback,
        peer_addr.map(|addr| addr.to_string()),
        Some(fingerprint),
        &mut control_permit,
    );
    stream.conn.send_close_notify();
    let _ = stream.flush();
    result
}

pub(super) fn complete_tls_handshake(
    stream: &mut TcpStream,
    connection: &mut ServerConnection,
    timeout: Duration,
) -> std::io::Result<()> {
    let deadline = Instant::now() + timeout;
    while connection.is_handshaking() {
        let mut progressed = false;
        while connection.wants_write() {
            stream.set_write_timeout(Some(tls_handshake_remaining(deadline)?))?;
            let written = connection
                .write_tls(stream)
                .map_err(map_tls_handshake_io_error)?;
            if written == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "TLS peer closed while handshake output was pending",
                ));
            }
            progressed = true;
        }
        if connection.wants_read() {
            stream.set_read_timeout(Some(tls_handshake_remaining(deadline)?))?;
            let read = connection
                .read_tls(stream)
                .map_err(map_tls_handshake_io_error)?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "TLS peer closed before the handshake completed",
                ));
            }
            progressed = true;
            connection
                .process_new_packets()
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        }
        if !progressed && connection.is_handshaking() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "TLS handshake cannot make progress",
            ));
        }
    }
    while connection.wants_write() {
        stream.set_write_timeout(Some(tls_handshake_remaining(deadline)?))?;
        let written = connection
            .write_tls(stream)
            .map_err(map_tls_handshake_io_error)?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "TLS peer closed while final handshake output was pending",
            ));
        }
    }
    stream.set_write_timeout(Some(tls_handshake_remaining(deadline)?))?;
    stream.flush().map_err(map_tls_handshake_io_error)?;
    Ok(())
}

fn tls_handshake_remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(tls_handshake_timed_out)
}

fn map_tls_handshake_io_error(error: std::io::Error) -> std::io::Error {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        tls_handshake_timed_out()
    } else {
        error
    }
}

fn tls_handshake_timed_out() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "TLS handshake absolute deadline exceeded",
    )
}

fn handle_stream(
    stream: &mut (impl DeadlineRead + Write),
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    peer_is_loopback: bool,
    peer_addr: Option<String>,
    peer_cert_fingerprint_sha256: Option<String>,
    transport_permit: &mut AdmissionPermit,
) -> std::io::Result<()> {
    let (header_timeout, body_timeout) = if transport_permit.is_control_probe() {
        (CONTROL_PROBE_INGRESS_TIMEOUT, CONTROL_PROBE_INGRESS_TIMEOUT)
    } else {
        (REQUEST_HEADER_TIMEOUT, REQUEST_BODY_TIMEOUT)
    };
    let exchange = match read_http_request(stream, header_timeout, body_timeout) {
        Ok(Some(request)) => handle_http_exchange(
            server,
            config,
            request
                .with_peer_loopback(peer_is_loopback)
                .with_peer_addr(peer_addr)
                .with_peer_cert_fingerprint_sha256(peer_cert_fingerprint_sha256),
            true,
            Some(transport_permit),
        ),
        Ok(None) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            let status = parse_error_status(&e).unwrap_or(400);
            HttpExchange::Buffered(HttpResponse {
                status,
                headers: vec![
                    ("cache-control".to_owned(), "no-store".to_owned()),
                    (
                        "content-type".to_owned(),
                        "text/plain; charset=utf-8".to_owned(),
                    ),
                ],
                body: e.to_string().into_bytes(),
            })
        }
        Err(e) => return Err(e),
    };
    match exchange {
        HttpExchange::Buffered(response) => write_http_response(stream, &response),
        HttpExchange::SseStream(response) => response.write_to(stream),
        HttpExchange::ToolStream(response) => (*response).write_to(stream),
    }
}
