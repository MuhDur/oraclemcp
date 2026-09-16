#[test]
fn audit_tail_filters_exports_redacted_proof_bundle() {
    // The configured path can include a tenant or account identifier. It is
    // runtime-only service topology, not cryptographic proof, so an export
    // must never serialize it.
    let path = write_audit_tail_fixture("customer-tenant-identity", false);
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_audit_tail_path: Some(path.clone()),
        ..Default::default()
    };

    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/audit-tail?limit=5&tool=oracle_execute&level=GUARDED&export=proof-bundle",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );

    assert_eq!(response.status, 200);
    let body = response_json(&response);
    let data = &body["data"];
    assert_eq!(data["source"], serde_json::json!("self_lane"));
    assert_eq!(data["scanned_records"], serde_json::json!(2));
    assert_eq!(data["selected_records"], serde_json::json!(1));
    assert_eq!(
        data["proof"]["verification"]["hash_chain"]["status"],
        serde_json::json!("ok")
    );
    assert_eq!(
        data["proof"]["verification"]["keyed_mac"]["status"],
        serde_json::json!("not_checked")
    );
    assert_eq!(
        data["export"]["format"],
        serde_json::json!("oraclemcp.audit.proof-bundle.v1")
    );

    let record = &data["records"][0];
    assert_eq!(record["tool"], serde_json::json!("oracle_execute"));
    assert_eq!(record["danger_level"], serde_json::json!("GUARDED"));
    assert_eq!(
        record["db_evidence"]["current_user"],
        serde_json::json!("APP_USER")
    );
    assert_eq!(
        record["bind_values"]["stored"],
        serde_json::json!(false),
        "bind values are never exported from the audit tail"
    );
    assert_eq!(
        record["proof"]["prev_hash"],
        serde_json::json!(GENESIS_HASH)
    );
    assert!(
        record["proof"]["signature"]
            .as_str()
            .expect("signature")
            .starts_with("hmac-sha256:")
    );

    let rendered = data.to_string();
    assert!(
        !rendered.contains("human@example.test"),
        "raw subject stable ids must not be serialized"
    );
    assert!(
        !rendered.contains("sensitive-bind-value"),
        "unknown/raw bind fields in JSONL must be dropped by the allow-list"
    );
    assert!(
        !rendered.contains("UPDATE accounts"),
        "timeline and proof bundle must not export sql_preview/inlined SQL text"
    );
    assert!(
        !rendered.contains("customer-tenant-identity"),
        "timeline and proof bundle must not export the configured audit path"
    );

    let subject_id_hash = record["subject_id_hash"].as_str().expect("subject hash");
    let subject_filter_response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            format!("/operator/v1/audit-tail?subject_id_hash={subject_id_hash}"),
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(subject_filter_response.status, 200);
    let subject_filter_body = response_json(&subject_filter_response);
    assert_eq!(
        subject_filter_body["data"]["selected_records"],
        serde_json::json!(1)
    );
    assert_eq!(
        subject_filter_body["data"]["records"][0]["subject_id_hash"],
        serde_json::json!(subject_id_hash)
    );
}

/// A configured audit-tail FIFO must be rejected before the endpoint reads it:
/// operator diagnostics must not let a local filesystem object pin a request
/// worker indefinitely. The unavailable envelope must likewise keep the
/// configured path private.
#[cfg(unix)]
#[test]
fn audit_tail_refuses_a_fifo_without_blocking_or_leaking_its_path() {
    use std::fs::File;
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::Duration;

    let path = audit_tail_fixture_path("customer-tenant-fifo");
    let status = Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("run mkfifo for audit-tail fixture");
    assert!(status.success(), "mkfifo must create the audit-tail fixture");
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_audit_tail_path: Some(path.clone()),
        ..Default::default()
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        sender
            .send(handle_http_request(
                &test_server(),
                &cfg,
                HttpRequest::new(
                    "GET",
                    "/operator/v1/audit-tail",
                    [("host", "127.0.0.1"), ("accept", "application/json")],
                    Vec::new(),
                )
                .with_peer_loopback(true),
            ))
            .expect("test receiver remains available");
    });
    let response = match receiver.recv_timeout(Duration::from_secs(2)) {
        Ok(response) => response,
        Err(timeout) => {
            // Release the legacy path-following reader before failing, so the
            // regression itself never leaks a blocked test worker.
            drop(
                File::options()
                    .write(true)
                    .open(&path)
                    .expect("open FIFO writer to release legacy reader"),
            );
            let _ = receiver.recv_timeout(Duration::from_secs(2));
            panic!("audit-tail FIFO blocked the operator request: {timeout}");
        }
    };

    assert_eq!(response.status, 200);
    let data = response_json(&response)["data"].clone();
    assert_eq!(data["source"], serde_json::json!("unavailable"));
    assert!(
        data["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("not a regular file")),
        "unexpected refusal: {}",
        data["reason"]
    );
    assert!(
        !data.to_string().contains("customer-tenant-fifo"),
        "audit-tail refusal leaked the configured path"
    );
}

/// The audit-tail reader is an allow-list input path, not a general filesystem
/// viewer. A symlink must therefore be refused even when its target is an
/// otherwise valid audit chain.
#[cfg(unix)]
#[test]
fn audit_tail_refuses_a_symlinked_input_without_leaking_its_path() {
    let target = write_audit_tail_fixture("symlink-target", false);
    let path = audit_tail_fixture_path("customer-tenant-symlink");
    std::os::unix::fs::symlink(&target, &path).expect("create audit-tail symlink fixture");
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_audit_tail_path: Some(path),
        ..Default::default()
    };

    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/audit-tail",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );

    assert_eq!(response.status, 200);
    let data = response_json(&response)["data"].clone();
    assert_eq!(data["source"], serde_json::json!("unavailable"));
    assert!(
        data["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("not a regular file")),
        "unexpected refusal: {}",
        data["reason"]
    );
    assert!(
        !data.to_string().contains("customer-tenant-symlink"),
        "audit-tail refusal leaked the configured path"
    );
}

fn audit_tail_budget_record() -> AuditRecord {
    let key = oraclemcp_audit::SigningKey::new(
        "tail-budget-test",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("valid key");
    AuditRecord::chained_signed(
        &audit_tail_draft(
            "budget@example.test",
            "oracle_query",
            "SELECT 1 FROM dual",
            "SAFE",
            AuditOutcome::Succeeded,
            None,
        ),
        1,
        GENESIS_HASH,
        "2026-08-01T00:00:00Z".to_owned(),
        &key,
    )
}

fn audit_tail_budget_response(path: &Path) -> Value {
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_audit_tail_path: Some(path.to_owned()),
        ..Default::default()
    };
    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/audit-tail?tool=never_matches",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(response.status, 200);
    response_json(&response)["data"].clone()
}

#[test]
fn audit_tail_rejects_an_overlong_nonmatching_record_as_unavailable() {
    let path = audit_tail_fixture_path("overlong-budget");
    let mut line = serde_json::to_vec(&audit_tail_budget_record()).expect("serialize record");
    assert!(line.len() < oraclemcp_audit::MAX_AUDIT_LINE_LEN);
    line.resize(oraclemcp_audit::MAX_AUDIT_LINE_LEN + 1, b' ');
    line.push(b'\n');
    std::fs::write(&path, line).expect("write overlong audit line");

    let data = audit_tail_budget_response(&path);
    assert_eq!(data["source"], serde_json::json!("unavailable"));
    assert_eq!(data["records"], serde_json::json!([]));
    assert!(
        data["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("record line exceeds the 1048576-byte maximum")),
        "unexpected refusal: {}",
        data["reason"]
    );
}

#[test]
fn audit_tail_counts_nonmatching_records_before_the_record_budget() {
    let path = audit_tail_fixture_path("record-budget");
    let mut line = serde_json::to_vec(&audit_tail_budget_record()).expect("serialize record");
    line.push(b'\n');
    let mut file = std::fs::File::create(&path).expect("create audit fixture");
    for _ in 0..10_001 {
        file.write_all(&line).expect("write audit record");
    }
    file.flush().expect("flush audit fixture");

    let data = audit_tail_budget_response(&path);
    assert_eq!(data["source"], serde_json::json!("unavailable"));
    assert_eq!(data["records"], serde_json::json!([]));
    assert!(
        data["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("exceeds the 10000-record maximum")),
        "unexpected refusal: {}",
        data["reason"]
    );
}

#[test]
fn audit_tail_counts_nonmatching_bytes_before_the_physical_scan_budget() {
    let path = audit_tail_fixture_path("physical-scan-budget");
    let mut line = serde_json::to_vec(&audit_tail_budget_record()).expect("serialize record");
    assert!(line.len() < oraclemcp_audit::MAX_AUDIT_LINE_LEN);
    line.resize(oraclemcp_audit::MAX_AUDIT_LINE_LEN, b' ');
    line.push(b'\n');
    let mut file = std::fs::File::create(&path).expect("create audit fixture");
    for _ in 0..64 {
        file.write_all(&line).expect("write padded audit record");
    }
    file.flush().expect("flush audit fixture");

    let data = audit_tail_budget_response(&path);
    assert_eq!(data["source"], serde_json::json!("unavailable"));
    assert_eq!(data["records"], serde_json::json!([]));
    assert!(
        data["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("exceeds the 67108864-byte maximum")),
        "unexpected refusal: {}",
        data["reason"]
    );
}

#[test]
fn audit_tail_projects_hash_covered_operator_correlation() {
    let key = oraclemcp_audit::SigningKey::new(
        "tail-correlation",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("valid key");
    let draft = audit_tail_draft(
        "operator",
        "operator_api",
        "POST /operator/v1/actions/execute",
        "OPERATOR",
        AuditOutcome::Failed,
        None,
    );
    let record = AuditRecord::chained_signed_correlated(
        &draft,
        9,
        GENESIS_HASH,
        "unix:1".to_owned(),
        &key,
        Some(AuditCorrelation::terminal("sha256:request-9", 8)),
    );

    let redacted = redacted_audit_record(&record, None);
    assert_eq!(
        redacted["correlation"]["request_sha256"],
        serde_json::json!("sha256:request-9")
    );
    assert_eq!(redacted["correlation"]["parent_seq"], serde_json::json!(8));
    assert_eq!(redacted["outcome"], serde_json::json!("FAILED"));
    assert!(record.hash_is_valid());
}

#[test]
fn audit_tail_projects_a_bound_redacted_verdict_certificate() {
    let path = write_certificate_audit_tail_fixture("verdict-certificate");
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_audit_tail_path: Some(path),
        ..Default::default()
    };

    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/audit-tail?limit=10",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );

    assert_eq!(response.status, 200);
    let body = response_json(&response);
    let record = &body["data"]["records"][0];
    let certificate = &record["verdict_certificate"];
    assert_eq!(
        record["observed_scn"],
        serde_json::json!(42_000_001_u64),
        "the audit tail exposes the exact SCN recorded for replay"
    );
    // The four client-side checks from the verdict-proof inspector all hold.
    assert_eq!(
        certificate["bound_audit_hash"], record["proof"]["entry_hash"],
        "certificate is bound to this exact signed audit record"
    );
    assert_eq!(certificate["stmt_digest"], record["sql_sha256"]);
    assert_eq!(
        certificate["derivation"][0]["rule_id"],
        serde_json::json!("R16")
    );
    assert_eq!(
        certificate["derivation"][0]["construct"],
        serde_json::json!("final_verdict:SAFE")
    );
    assert_eq!(record["proof"]["hash_valid"], serde_json::json!(true));
    assert!(
        record["verdict_certificate_core_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:")),
        "the signed record exposes the certificate core hash"
    );

    let rendered = body.to_string();
    for forbidden in [
        "payroll",
        "secret_bonus",
        "secret_employee",
        "SELECT payroll",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "audit-tail certificate must not expose SQL, binds, or identifiers: {forbidden}"
        );
    }
}

#[test]
fn audit_tail_omits_a_certificate_forged_after_the_signed_append() {
    let path = write_certificate_audit_tail_fixture("forged-verdict-certificate");
    let persisted = std::fs::read_to_string(&path).expect("read certificate fixture");
    let forged = persisted.replacen("final_verdict:SAFE", "final_verdict:FORBIDDEN", 1);
    assert_ne!(
        persisted, forged,
        "fixture must contain the registered label"
    );
    std::fs::write(&path, forged).expect("rewrite only the unauthenticated sidecar envelope");

    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_audit_tail_path: Some(path),
        ..Default::default()
    };
    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/audit-tail?limit=10",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );

    assert_eq!(response.status, 200);
    let record = &response_json(&response)["data"]["records"][0];
    assert_eq!(record["proof"]["hash_valid"], serde_json::json!(true));
    assert!(
        record["verdict_certificate"].is_null()
            && record["verdict_certificate_core_hash"].is_null(),
        "the HTTP surface must not promote a certificate whose core no longer matches the signed record"
    );
}

#[test]
fn audit_tail_reports_broken_hash_chain_without_exposing_raw_json_fields() {
    let path = write_audit_tail_fixture("broken", true);
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_audit_tail_path: Some(path),
        ..Default::default()
    };

    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/audit-tail?limit=10",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );

    assert_eq!(response.status, 200);
    let body = response_json(&response);
    assert_eq!(
        body["data"]["proof"]["verification"]["hash_chain"]["status"],
        serde_json::json!("broken")
    );
    assert_eq!(
        body["data"]["proof"]["verification"]["hash_chain"]["broken"]["check"],
        serde_json::json!("entry_hash")
    );
    assert_eq!(
        body["data"]["records"][1]["proof"]["hash_valid"],
        serde_json::json!(false)
    );
    assert!(
        !body["data"].to_string().contains("sensitive-bind-value"),
        "proof export path must stay allow-list-only even on broken chains"
    );
}
