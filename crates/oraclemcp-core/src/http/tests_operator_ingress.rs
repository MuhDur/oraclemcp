#[test]
fn public_operator_dispatch_refuses_oversized_body_before_audit_or_json_parsing() {
    // The native socket reader rejects this at Content-Length, but
    // `handle_http_request` is also a public embedded-ingress boundary. It
    // must not feed a caller-provided oversized operator body to audit or JSON
    // handling simply because it did not come through `wire`.
    let (auditor, sink) = operator_auditor();
    let config = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let request = HttpRequest::new(
        "POST",
        "/operator/v1/lanes/cancel",
        [
            ("host", "127.0.0.1"),
            ("accept", "application/json"),
            ("content-type", "application/json"),
        ],
        vec![b'x'; MAX_BODY_BYTES + 1],
    )
    .with_peer_loopback(true);

    let response = handle_http_request(&test_server(), &config, request);

    assert_eq!(response.status, 413);
    assert!(
        sink.records().is_empty(),
        "the rejection must happen before operator audit admission"
    );
}
