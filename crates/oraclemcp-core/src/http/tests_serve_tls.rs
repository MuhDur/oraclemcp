fn self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    (
        cert.cert.pem().into_bytes(),
        cert.key_pair.serialize_pem().into_bytes(),
    )
}

fn ca_cert() -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params =
        rcgen::CertificateParams::new(vec!["oraclemcp-test-ca".to_owned()]).expect("CA params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key = rcgen::KeyPair::generate().expect("CA key");
    let cert = params.self_signed(&key).expect("self-signed CA");
    (cert, key)
}

fn cert_signed_by(
    name: &str,
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
) -> (Vec<u8>, Vec<u8>) {
    let params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("cert params");
    let key = rcgen::KeyPair::generate().expect("cert key");
    let cert = params
        .signed_by(&key, ca_cert, ca_key)
        .expect("certificate signed by test CA");
    (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
}

fn pem_certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .expect("certificate PEM parses")
}

fn pem_key(pem: &[u8]) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(pem).expect("private-key PEM parses")
}

fn tls_client_config(
    server_cert_pem: &[u8],
    client_cert_and_key: Option<(&[u8], &[u8])>,
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in pem_certs(server_cert_pem) {
        roots.add(cert).expect("server cert added to roots");
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("default TLS versions")
    .with_root_certificates(roots);
    match client_cert_and_key {
        Some((cert_pem, key_pem)) => builder
            .with_client_auth_cert(pem_certs(cert_pem), pem_key(key_pem))
            .expect("client auth cert config"),
        None => builder.with_no_client_auth(),
    }
    .into()
}

fn spawn_https_with(
    tls: Arc<TlsServerConfig>,
    server: OracleMcpServer,
    config: HttpTransportConfig,
) -> (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback HTTPS listener");
    let addr = listener.local_addr().expect("listener has local addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || {
        serve_https_until(listener, server, &config, tls, server_shutdown)
            .expect("native HTTPS server exits cleanly")
    });
    (addr, shutdown, handle)
}

fn spawn_https(
    tls: Arc<TlsServerConfig>,
) -> (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    spawn_https_with(
        tls,
        test_server(),
        HttpTransportConfig {
            json_response: true,
            stateful: false,
            ..Default::default()
        },
    )
}

fn https_get(
    addr: std::net::SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> std::io::Result<String> {
    let stream = TcpStream::connect(addr)?;
    let connection =
        rustls::ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
            .map_err(|e| std::io::Error::other(format!("TLS client setup: {e}")))?;
    let mut stream = rustls::StreamOwned::new(connection, stream);
    write!(
        stream,
        "GET {MCP_PATH} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n\r\n"
    )?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn https_request(
    addr: std::net::SocketAddr,
    config: Arc<rustls::ClientConfig>,
    raw: &str,
) -> std::io::Result<String> {
    let stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let connection =
        rustls::ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
            .map_err(|e| std::io::Error::other(format!("TLS client setup: {e}")))?;
    let mut stream = rustls::StreamOwned::new(connection, stream);
    stream.write_all(raw.as_bytes())?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn spawn_control_https(
    tls: Arc<TlsServerConfig>,
    config: HttpTransportConfig,
    preauth_admission: Arc<AdmissionController>,
) -> (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control HTTPS listener");
    let addr = listener
        .local_addr()
        .expect("control listener has local addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || {
        serve_control_https_until(
            listener,
            test_server(),
            &config,
            tls,
            preauth_admission,
            server_shutdown,
        )
        .expect("control HTTPS server exits cleanly")
    });
    (addr, shutdown, handle)
}

fn https_post(
    addr: std::net::SocketAddr,
    config: Arc<rustls::ClientConfig>,
    body: &str,
) -> std::io::Result<String> {
    let stream = TcpStream::connect(addr)?;
    let connection =
        rustls::ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
            .map_err(|e| std::io::Error::other(format!("TLS client setup: {e}")))?;
    let mut stream = rustls::StreamOwned::new(connection, stream);
    write!(
        stream,
        "POST {MCP_PATH} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    )?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn http_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("HTTP response has body separator")
}

#[test]
fn serve_https_accepts_tls_handshake() {
    let (cert, key) = self_signed_cert();
    let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
        cert_chain_pem: cert.clone(),
        private_key_pem: key,
        client_ca_pem: None,
    })
    .expect("server-only TLS config builds");
    let (addr, shutdown, handle) = spawn_https(tls);

    let response = https_get(addr, tls_client_config(&cert, None)).expect("HTTPS request");
    assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));

    shutdown.store(true, Ordering::SeqCst);
    handle.join().expect("HTTPS server thread joins");
}

#[test]
fn stalled_tls_peer_cannot_reset_the_absolute_handshake_deadline() {
    let (cert, key) = self_signed_cert();
    let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
        cert_chain_pem: cert,
        private_key_pem: key,
        client_ca_pem: None,
    })
    .expect("server-only TLS config builds");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled TLS listener");
    let client = TcpStream::connect(listener.local_addr().expect("listener address"))
        .expect("connect stalled TLS peer");
    let (mut server_stream, _) = listener.accept().expect("accept stalled TLS peer");
    let mut connection = ServerConnection::new(tls).expect("TLS server connection");
    let started = Instant::now();
    let error = complete_tls_handshake(
        &mut server_stream,
        &mut connection,
        Duration::from_millis(25),
    )
    .expect_err("silent TLS peer must hit the absolute handshake deadline");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("TLS handshake"));
    assert!(started.elapsed() < Duration::from_millis(500));
    drop(client);
}

#[test]
fn trickled_tls_client_hello_cannot_reset_the_absolute_handshake_deadline() {
    let (cert, key) = self_signed_cert();
    let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
        cert_chain_pem: cert.clone(),
        private_key_pem: key,
        client_ca_pem: None,
    })
    .expect("server-only TLS config builds");
    let client_config = tls_client_config(&cert, None);
    let mut client_connection = rustls::ClientConnection::new(
        client_config,
        ServerName::try_from("localhost").expect("server name"),
    )
    .expect("TLS client connection");
    let mut client_hello = Vec::new();
    while client_connection.wants_write() {
        client_connection
            .write_tls(&mut client_hello)
            .expect("serialize client hello");
    }
    assert!(
        client_hello.len() > 16,
        "client hello must span the deadline"
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trickled TLS listener");
    let mut client = TcpStream::connect(listener.local_addr().expect("listener address"))
        .expect("connect trickled TLS peer");
    let (mut server_stream, _) = listener.accept().expect("accept trickled TLS peer");
    let writer = std::thread::spawn(move || {
        for byte in client_hello {
            std::thread::sleep(Duration::from_millis(4));
            if client.write_all(&[byte]).is_err() {
                break;
            }
        }
    });

    let mut server_connection = ServerConnection::new(tls).expect("TLS server connection");
    let started = Instant::now();
    let error = complete_tls_handshake(
        &mut server_stream,
        &mut server_connection,
        Duration::from_millis(25),
    )
    .expect_err("a trickled client hello must hit the absolute handshake deadline");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("TLS handshake"));
    assert!(started.elapsed() < Duration::from_millis(500));
    drop(server_stream);
    writer.join().expect("trickle writer joins");
}

#[test]
fn native_https_forces_secure_stateful_session_cookie() {
    let (cert, key) = self_signed_cert();
    let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
        cert_chain_pem: cert.clone(),
        private_key_pem: key,
        client_ca_pem: None,
    })
    .expect("server-only TLS config builds");
    let (addr, shutdown, handle) = spawn_https_with(
        tls,
        test_server(),
        HttpTransportConfig {
            json_response: true,
            stateful: true,
            ..Default::default()
        },
    );
    let body = init_body().to_string();
    let response =
        https_post(addr, tls_client_config(&cert, None), &body).expect("HTTPS initialize request");

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response.lines().any(|line| {
            line.to_ascii_lowercase().starts_with("set-cookie:")
                && line.contains("HttpOnly")
                && line.contains("SameSite=Strict")
                && line.contains("Secure")
        }),
        "native rustls must force Secure on the stateful cookie: {response}"
    );

    shutdown.store(true, Ordering::SeqCst);
    handle.join().expect("HTTPS server thread joins");
}

#[test]
fn serve_https_requires_client_certificate_when_mtls_is_configured() {
    let (server_cert, server_key) = self_signed_cert();
    let (client_ca, client_ca_key) = ca_cert();
    let (client_cert, client_key) =
        cert_signed_by("oraclemcp-test-client", &client_ca, &client_ca_key);
    let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
        cert_chain_pem: server_cert.clone(),
        private_key_pem: server_key,
        client_ca_pem: Some(client_ca.pem().into_bytes()),
    })
    .expect("mTLS config builds");
    let (addr, shutdown, handle) = spawn_https(tls);

    let without_client_cert = https_get(addr, tls_client_config(&server_cert, None));
    assert!(
        without_client_cert.is_err(),
        "mTLS listener must reject clients without a certificate"
    );

    let response = https_get(
        addr,
        tls_client_config(&server_cert, Some((&client_cert, &client_key))),
    )
    .expect("mTLS request with client certificate");
    assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
    assert!(
        response.contains("mtls_client_not_registered"),
        "CA-valid but unregistered mTLS client must fail closed: {response}"
    );

    shutdown.store(true, Ordering::SeqCst);
    handle.join().expect("mTLS server thread joins");
}

#[test]
fn registered_mtls_client_certificate_becomes_dispatch_principal() {
    let (server_cert, server_key) = self_signed_cert();
    let (client_ca, client_ca_key) = ca_cert();
    let (client_cert, client_key) =
        cert_signed_by("oraclemcp-test-client", &client_ca, &client_ca_key);
    let fingerprint = cert_fingerprint_sha256(pem_certs(&client_cert)[0].as_ref());
    let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
        cert_chain_pem: server_cert.clone(),
        private_key_pem: server_key,
        client_ca_pem: Some(client_ca.pem().into_bytes()),
    })
    .expect("mTLS config builds");
    let (addr, shutdown, handle) = spawn_https_with(
        tls,
        scope_echo_server(),
        HttpTransportConfig {
            json_response: true,
            stateful: false,
            mtls_clients: MtlsClientRegistry::from_fingerprints([fingerprint.clone()]),
            ..Default::default()
        },
    );

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "oracle_preview_sql",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        }
    })
    .to_string();
    let response = https_post(
        addr,
        tls_client_config(&server_cert, Some((&client_cert, &client_key))),
        &body,
    )
    .expect("mTLS request with registered client certificate");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "registered mTLS client should dispatch successfully: {response}"
    );
    let json: Value = serde_json::from_str(http_body(&response)).expect("JSON response body");
    assert_eq!(
        json["result"]["structuredContent"]["principal_key"],
        serde_json::json!(format!("mtls:{fingerprint}"))
    );
    assert_eq!(
        json["result"]["structuredContent"]["scopes"],
        serde_json::json!([])
    );

    shutdown.store(true, Ordering::SeqCst);
    handle.join().expect("mTLS server thread joins");
}

#[test]
fn dedicated_mtls_control_ingress_survives_ordinary_saturation_and_fails_closed() {
    let ordinary_admission = Arc::new(AdmissionController::new(1, 1));
    let ordinary_listener = TcpListener::bind("127.0.0.1:0").expect("bind ordinary listener");
    let ordinary_addr = ordinary_listener
        .local_addr()
        .expect("ordinary listener addr");
    let ordinary_shutdown = Arc::new(AtomicBool::new(false));
    let ordinary_server_shutdown = Arc::clone(&ordinary_shutdown);
    let ordinary_config = HttpTransportConfig {
        transport_admission: Arc::clone(&ordinary_admission),
        ..Default::default()
    };
    let ordinary_handle = std::thread::spawn(move || {
        serve_http_until(
            ordinary_listener,
            test_server(),
            &ordinary_config,
            ordinary_server_shutdown,
        )
        .expect("ordinary listener exits cleanly")
    });
    let stalled_ordinary = TcpStream::connect(ordinary_addr).expect("saturate ordinary worker");
    for _ in 0..100 {
        if ordinary_admission.available_global() == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(ordinary_admission.available_global(), 0);

    let (server_cert, server_key) = self_signed_cert();
    let (client_ca, client_ca_key) = ca_cert();
    let (operator_cert, operator_key) =
        cert_signed_by("registered-control", &client_ca, &client_ca_key);
    let (unknown_cert, unknown_key) = cert_signed_by("unknown-control", &client_ca, &client_ca_key);
    let fingerprint = cert_fingerprint_sha256(pem_certs(&operator_cert)[0].as_ref());
    let nonoperator_fingerprint = cert_fingerprint_sha256(pem_certs(&unknown_cert)[0].as_ref());
    let principal = format!("mtls:{fingerprint}");
    let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
        cert_chain_pem: server_cert.clone(),
        private_key_pem: server_key,
        client_ca_pem: Some(client_ca.pem().into_bytes()),
    })
    .expect("mandatory mTLS config builds");
    let control_admission = Arc::new(AdmissionController::with_reserved(2, 2, 1, 1));
    let preauth_admission = Arc::new(AdmissionController::new(2, 2));
    let (auditor, _sink) = operator_auditor();
    let control_config = HttpTransportConfig {
        transport_admission: Arc::clone(&control_admission),
        mtls_clients: MtlsClientRegistry::from_fingerprints([fingerprint, nonoperator_fingerprint]),
        operator_authority: OperatorAuthorityPolicy {
            allow_loopback_owner: false,
            local_owner_stable_id: "disabled".to_owned(),
            allowed_subjects: [principal].into_iter().collect(),
        },
        operator_auditor: Some(auditor),
        observability: ObservabilityState {
            health: Some(HealthState::new("0.1.0")),
            metrics: None,
            readiness_probe: None,
        },
        ..Default::default()
    };
    let (control_addr, control_shutdown, control_handle) = spawn_control_https(
        Arc::clone(&tls),
        control_config,
        Arc::clone(&preauth_admission),
    );
    let operator_client = tls_client_config(&server_cert, Some((&operator_cert, &operator_key)));

    let stalled_handshake_a =
        TcpStream::connect(control_addr).expect("occupy first pre-auth worker");
    let stalled_handshake_b =
        TcpStream::connect(control_addr).expect("occupy second pre-auth worker");
    for _ in 0..100 {
        if preauth_admission
            .snapshot("preauth", "control-mtls-handshake")
            .global_in_use
            == 2
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        preauth_admission
            .snapshot("preauth", "control-mtls-handshake")
            .global_in_use,
        2,
        "pre-auth workers stop exactly at their configured cap"
    );
    let mut rejected_handshake =
        TcpStream::connect(control_addr).expect("connect over-cap handshake");
    rejected_handshake
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("over-cap read timeout");
    let mut rejected_bytes = Vec::new();
    let _ = rejected_handshake.read_to_end(&mut rejected_bytes);
    assert!(rejected_bytes.is_empty());
    assert_eq!(
        preauth_admission
            .snapshot("preauth", "control-mtls-handshake")
            .global_in_use,
        2
    );
    assert_eq!(
        control_admission
            .snapshot("control", "registered")
            .global_in_use,
        0,
        "unauthenticated sockets never occupy the authenticated reserve"
    );
    drop(stalled_handshake_a);
    drop(stalled_handshake_b);
    for _ in 0..100 {
        if preauth_admission
            .snapshot("preauth", "control-mtls-handshake")
            .global_in_use
            == 0
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        preauth_admission
            .snapshot("preauth", "control-mtls-handshake")
            .global_in_use,
        0
    );

    let health = https_request(
        control_addr,
        Arc::clone(&operator_client),
        "GET /healthz HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n\r\n",
    )
    .expect("registered mTLS readiness request");
    assert!(health.starts_with("HTTP/1.1 200 OK"), "{health}");
    let operator = https_request(
        control_addr,
        Arc::clone(&operator_client),
        "GET /operator/v1/health HTTP/1.1\r\nhost: 127.0.0.1\r\naccept: application/json\r\ncontent-length: 0\r\n\r\n",
    )
    .expect("allow-listed remote operator request");
    assert!(operator.starts_with("HTTP/1.1 200 OK"), "{operator}");
    let ordinary_route = https_request(
        control_addr,
        Arc::clone(&operator_client),
        "GET /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n\r\n",
    )
    .expect("registered certificate receives fail-closed response");
    assert!(
        ordinary_route.starts_with("HTTP/1.1 429 Too Many Requests"),
        "control ingress must never expose MCP routes: {ordinary_route}"
    );

    assert!(
        https_request(
            control_addr,
            tls_client_config(&server_cert, None),
            "GET /healthz HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n\r\n",
        )
        .is_err(),
        "a client without a certificate is rejected during mTLS"
    );
    let unknown = https_request(
        control_addr,
        tls_client_config(&server_cert, Some((&unknown_cert, &unknown_key))),
        "GET /healthz HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n\r\n",
    );
    assert!(
        unknown.is_err() || unknown.as_ref().is_ok_and(String::is_empty),
        "a registered but non-operator identity is closed before HTTP parsing: {unknown:?}"
    );

    let control_snapshot = control_admission.snapshot("control", "registered");
    let preauth_snapshot = preauth_admission.snapshot("preauth", "registered");
    assert_eq!(control_snapshot.global_in_use, 0);
    assert_eq!(preauth_snapshot.global_in_use, 0);
    assert!(control_snapshot.global_in_use <= control_snapshot.global_cap);
    assert!(preauth_snapshot.global_in_use <= preauth_snapshot.global_cap);
    assert_eq!(
        ordinary_admission.available_global(),
        0,
        "ordinary hostile saturation remains in place throughout the proof"
    );

    drop(stalled_ordinary);
    ordinary_shutdown.store(true, Ordering::SeqCst);
    ordinary_handle.join().expect("ordinary listener joins");
    control_shutdown.store(true, Ordering::SeqCst);
    control_handle.join().expect("control listener joins");
}

#[test]
fn dedicated_control_header_deadline_is_absolute_after_mtls_authentication() {
    let (server_cert, server_key) = self_signed_cert();
    let (client_ca, client_ca_key) = ca_cert();
    let (client_cert, client_key) = cert_signed_by("slow-control", &client_ca, &client_ca_key);
    let fingerprint = cert_fingerprint_sha256(pem_certs(&client_cert)[0].as_ref());
    let principal = format!("mtls:{fingerprint}");
    let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
        cert_chain_pem: server_cert.clone(),
        private_key_pem: server_key,
        client_ca_pem: Some(client_ca.pem().into_bytes()),
    })
    .expect("mandatory mTLS config builds");
    let control_admission = Arc::new(AdmissionController::with_reserved(2, 2, 1, 1));
    let preauth_admission = Arc::new(AdmissionController::new(1, 1));
    let (addr, shutdown, handle) = spawn_control_https(
        tls,
        HttpTransportConfig {
            transport_admission: Arc::clone(&control_admission),
            mtls_clients: MtlsClientRegistry::from_fingerprints([fingerprint]),
            operator_authority: OperatorAuthorityPolicy {
                allow_loopback_owner: false,
                local_owner_stable_id: "disabled".to_owned(),
                allowed_subjects: [principal].into_iter().collect(),
            },
            ..Default::default()
        },
        Arc::clone(&preauth_admission),
    );
    let tcp = TcpStream::connect(addr).expect("connect authenticated slow reader");
    tcp.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("client read timeout");
    let connection = rustls::ClientConnection::new(
        tls_client_config(&server_cert, Some((&client_cert, &client_key))),
        ServerName::try_from("localhost").expect("server name"),
    )
    .expect("TLS client connection");
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    stream.write_all(b"G").expect("write partial header");
    stream.flush().expect("complete mTLS handshake");
    let started = Instant::now();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the one-second control header deadline is absolute"
    );
    for _ in 0..100 {
        if control_admission
            .snapshot("control", "registered")
            .global_available
            == 2
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        control_admission
            .snapshot("control", "registered")
            .global_available,
        2
    );
    assert_eq!(preauth_admission.available_global(), 1);

    shutdown.store(true, Ordering::SeqCst);
    handle.join().expect("control listener joins");
}
