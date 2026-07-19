#[test]
fn ci_lane_catalog_covers_every_scheduled_and_advisory_taxonomy_job() {
    let raw = include_str!("../../../../docs/ci_taxonomy.json");
    let document: Value = serde_json::from_str(raw).expect("taxonomy parses as JSON");
    let expected = document["jobs"]
        .as_array()
        .expect("taxonomy jobs")
        .iter()
        .filter(|job| matches!(job["tier"].as_str(), Some("scheduled" | "advisory")))
        .map(|job| job["check_name"].as_str().expect("check name").to_owned())
        .collect::<HashSet<_>>();
    let catalog = parse_ci_lane_catalog(raw).expect("lane catalog parses");
    let actual = catalog
        .iter()
        .map(|lane| lane.check_name.clone())
        .collect::<HashSet<_>>();

    assert_eq!(
        actual, expected,
        "the dashboard may not omit a watched lane"
    );
    assert_eq!(
        catalog.len(),
        expected.len(),
        "lane identities must be unique"
    );
    assert!(
        catalog
            .iter()
            .all(|lane| matches!(lane.tier.as_str(), "scheduled" | "advisory"))
    );
}

#[test]
fn ci_lane_catalog_rejects_unobservable_or_unsafe_workflows() {
    let unsafe_path = r#"{
        "schema":"ci-taxonomy/v1",
        "repo":"oraclemcp",
        "jobs":[{
            "check_name":"mutation",
            "tier":"scheduled",
            "workflow":"Mutation",
            "workflow_file":"../mutation.yml",
            "job_id":"mutation",
            "triggers":["schedule"],
            "path_filtered":false
        }]
    }"#;
    assert!(
        parse_ci_lane_catalog(unsafe_path)
            .expect_err("path escape must fail")
            .contains("safe basename")
    );

    let no_schedule = unsafe_path
        .replace("../mutation.yml", "mutation.yml")
        .replace("[\"schedule\"]", "[\"workflow_dispatch\"]");
    assert!(
        parse_ci_lane_catalog(&no_schedule)
            .expect_err("scheduled lane without schedule event must fail")
            .contains("no schedule trigger")
    );
}

fn fixture_catalog_entry() -> CiLaneCatalogEntry {
    CiLaneCatalogEntry {
        check_name: "guard + audit cargo-mutants".to_owned(),
        tier: "scheduled".to_owned(),
        workflow: "Mutation Safety".to_owned(),
        workflow_file: "mutation-safety.yml".to_owned(),
        job_id: "mutation-safety".to_owned(),
        event: "schedule".to_owned(),
        path_filtered: false,
        whole_workflow: true,
    }
}

#[test]
fn ci_lane_streak_is_exact_and_missing_evidence_is_never_green() {
    let catalog = fixture_catalog_entry();
    let observation = |run_id, conclusion: &str| {
        Ok(CiLaneObservation {
            status: "completed".to_owned(),
            conclusion: Some(conclusion.to_owned()),
            run_id,
            run_url: format!("https://github.com/MuhDur/oraclemcp/actions/runs/{run_id}"),
            head_sha: "e004ebd5b5532a4b85984a62f8ad48a81aa3460c".to_owned(),
            completed_at: Some("2026-07-18T00:00:00Z".to_owned()),
        })
    };
    let health = ci_lane_health_from_observations(
        catalog.clone(),
        &[
            observation(4, "success"),
            observation(3, "success"),
            observation(2, "success"),
            observation(1, "cancelled"),
        ],
    );
    assert_eq!(health.streak_conclusion.as_deref(), Some("success"));
    assert_eq!(health.streak_count, 3);
    assert!(!health.streak_capped);
    assert_eq!(ci_lane_health_json(&health, false)["state"], "success");
    assert_eq!(
        ci_lane_health_json(&health, true)["state"],
        "unknown",
        "stale success cannot render green"
    );

    let missing_latest = ci_lane_health_from_observations(
        catalog.clone(),
        &[Err("job missing from latest completed run".to_owned())],
    );
    assert_eq!(
        ci_lane_health_json(&missing_latest, false)["state"],
        "unknown"
    );
    assert_eq!(missing_latest.streak_count, 0);

    let history_gap = ci_lane_health_from_observations(
        catalog,
        &[
            observation(4, "success"),
            Err("older job observation missing".to_owned()),
        ],
    );
    assert!(history_gap.source_error.is_some());
    assert_eq!(
        ci_lane_health_json(&history_gap, false)["state"],
        "unknown",
        "an unprovable streak cannot render as a green lane"
    );
}

/// Drives an async future on a dedicated test-only runtime. `block_on` is
/// allowed here because the concurrency lint scans production code only
/// (`#[cfg(test)]` items are skipped) — this mirrors the sanctioned CLI-entry
/// idiom in `main::block_on_connect` and `dashboard_auth`'s own test probe. No
/// production code path in this crate drives `fetch_ci_lane_snapshot`; see the
/// `ci_lanes` module docs for why.
fn drive<F: std::future::Future>(future: F) -> F::Output {
    let reactor =
        asupersync::runtime::reactor::create_reactor().expect("test fetch reactor builds");
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("test fetch runtime builds");
    // block-on-boundary: test-only helper driving fetch_ci_lane_snapshot; there
    // is no production caller (the ci_lanes route is sync/file-backed). The
    // concurrency lint's cfg(test) skip is path-based (/tests/ or tests.rs) and
    // does not match this tests_-prefixed src file, so sanction it explicitly.
    runtime.block_on(async {
        let _cx = Cx::current().expect("block_on installs a current Cx");
        future.await
    })
}

/// Minimal single-shot HTTP/1.1 mock: accepts one connection, ignores the
/// request, and replies with `body` as `application/json`.
fn spawn_json_mock(body: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock GitHub server");
    let port = listener.local_addr().expect("mock server address").port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept mock request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set mock read timeout");
        let mut buf = [0_u8; 8 * 1024];
        let _ = stream.read(&mut buf);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
    });
    (port, handle)
}

/// Client settings that mirror what a production caller would configure
/// (bounded body, no redirects/retries/cookies) so the test proves the same
/// shape of client asupersync's HTTP/1 client would actually be built with.
fn ci_lane_test_client() -> asupersync::http::h1::http_client::HttpClient {
    asupersync::http::h1::http_client::HttpClient::builder()
        .no_redirects()
        .no_retries()
        .no_cookie_store()
        .request_timeout(Duration::from_secs(2))
        .max_body_size(CI_LANE_MAX_RESPONSE_BYTES)
        .build()
}

fn spawn_status_mock(status_line: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock GitHub server");
    let port = listener.local_addr().expect("mock server address").port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept mock request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set mock read timeout");
        let mut buf = [0_u8; 8 * 1024];
        let _ = stream.read(&mut buf);
        let response = format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = stream.write_all(response.as_bytes());
    });
    (port, handle)
}

#[test]
fn fetch_ci_lane_snapshot_is_genuinely_async_and_never_blocks_on_a_new_runtime() {
    // The lint that catches the reintroduced trap (`unsanctioned-block-on`)
    // scans production `.rs` files textually; this asserts the behavioral
    // side instead — that the fetch pipeline itself is a real `.await` chain
    // that correctly threads a mocked GitHub response end to end.
    const RUNS_BODY: &str = r#"{"workflow_runs":[{
        "id": 42,
        "status": "completed",
        "conclusion": "success",
        "html_url": "https://github.com/MuhDur/oraclemcp/actions/runs/42",
        "head_sha": "e004ebd5b5532a4b85984a62f8ad48a81aa3460c",
        "updated_at": "2026-07-18T00:00:00Z"
    }]}"#;
    let (port, handle) = spawn_json_mock(RUNS_BODY);
    let base_url = format!("http://127.0.0.1:{port}");
    let catalog = vec![fixture_catalog_entry()];

    let client = ci_lane_test_client();
    let snapshot = drive(async {
        let cx = Cx::current().expect("current Cx inside block_on");
        fetch_ci_lane_snapshot(&cx, &client, &base_url, &catalog).await
    });
    handle.join().expect("mock server thread joins");

    assert!(snapshot.errors.is_empty(), "errors: {:?}", snapshot.errors);
    assert_eq!(snapshot.lanes.len(), 1);
    assert_eq!(
        snapshot.lanes[0].streak_conclusion.as_deref(),
        Some("success")
    );
    assert_eq!(snapshot.lanes[0].catalog.check_name, catalog[0].check_name);
    assert_eq!(
        snapshot.lanes[0]
            .latest
            .as_ref()
            .expect("latest observation")
            .run_id,
        42
    );
}

#[test]
fn fetch_ci_lane_snapshot_never_upgrades_a_transport_failure_to_green() {
    let (port, handle) = spawn_status_mock("HTTP/1.1 503 Service Unavailable");
    let base_url = format!("http://127.0.0.1:{port}");
    let catalog = vec![fixture_catalog_entry()];

    let client = ci_lane_test_client();
    let snapshot = drive(async {
        let cx = Cx::current().expect("current Cx inside block_on");
        fetch_ci_lane_snapshot(&cx, &client, &base_url, &catalog).await
    });
    handle.join().expect("mock server thread joins");

    assert!(!snapshot.errors.is_empty());
    assert_eq!(snapshot.lanes.len(), 1);
    assert_eq!(ci_lane_health_json(&snapshot.lanes[0], false)["state"], "unknown");
}

#[test]
fn ci_lane_snapshot_round_trips_through_durable_storage() {
    let dir = dashboard_test_dir("ci-lanes-storage");
    let path = dir.join("ci-lanes-snapshot.json");
    let catalog = fixture_catalog_entry();
    let health = ci_lane_health_from_observations(
        catalog,
        &[Ok(CiLaneObservation {
            status: "completed".to_owned(),
            conclusion: Some("success".to_owned()),
            run_id: 7,
            run_url: "https://github.com/MuhDur/oraclemcp/actions/runs/7".to_owned(),
            head_sha: "e004ebd5b5532a4b85984a62f8ad48a81aa3460c".to_owned(),
            completed_at: Some("2026-07-18T00:00:00Z".to_owned()),
        })],
    );
    let snapshot = CiLaneSnapshot::new(vec![health], Vec::new());

    write_ci_lane_snapshot(&path, &snapshot).expect("snapshot writes");
    let reloaded = load_ci_lane_snapshot(&path).expect("snapshot reads back");
    assert_eq!(reloaded.schema, snapshot.schema);
    assert_eq!(reloaded.refreshed_at_unix, snapshot.refreshed_at_unix);
    assert_eq!(reloaded.lanes.len(), 1);
    assert_eq!(
        reloaded.lanes[0].catalog.check_name,
        snapshot.lanes[0].catalog.check_name
    );
    assert_eq!(reloaded.lanes[0].streak_count, snapshot.lanes[0].streak_count);
}

#[test]
fn load_ci_lane_snapshot_fails_closed_on_a_missing_or_corrupt_file() {
    let dir = dashboard_test_dir("ci-lanes-corrupt");
    let missing = dir.join("does-not-exist.json");
    assert!(load_ci_lane_snapshot(&missing).is_err());

    let corrupt = dir.join("corrupt.json");
    std::fs::write(&corrupt, b"not json").expect("write corrupt fixture");
    assert!(load_ci_lane_snapshot(&corrupt).is_err());

    let wrong_schema = dir.join("wrong-schema.json");
    std::fs::write(&wrong_schema, br#"{"schema":"other/v1","refreshed_at_unix":1,"lanes":[],"errors":[]}"#)
        .expect("write wrong-schema fixture");
    assert!(load_ci_lane_snapshot(&wrong_schema).is_err());
}

#[test]
fn operator_ci_lanes_route_is_unavailable_without_a_configured_snapshot() {
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/ci-lanes",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(response.status, 200);
    let body = response_json(&response);
    assert_eq!(body["data"]["source"], serde_json::json!("unavailable"));
    assert_eq!(body["data"]["refresh_state"], serde_json::json!("failed"));
    assert_eq!(body["data"]["freshness"], serde_json::json!("unavailable"));
    assert_eq!(body["data"]["summary"]["posture"], serde_json::json!("unknown"));
    assert!(
        body["data"]["lanes"]
            .as_array()
            .expect("lanes array")
            .iter()
            .all(|lane| lane["state"] == "unknown"),
        "an unconfigured snapshot must never render a green lane"
    );
}

#[test]
fn operator_ci_lanes_route_serves_a_fresh_configured_snapshot() {
    let raw = include_str!("../../../../docs/ci_taxonomy.json");
    let catalog = parse_ci_lane_catalog(raw).expect("lane catalog parses");
    let watched = catalog.first().expect("catalog has at least one lane").clone();
    let watched_check_name = watched.check_name.clone();
    let health = ci_lane_health_from_observations(
        watched,
        &[Ok(CiLaneObservation {
            status: "completed".to_owned(),
            conclusion: Some("success".to_owned()),
            run_id: 99,
            run_url: "https://github.com/MuhDur/oraclemcp/actions/runs/99".to_owned(),
            head_sha: "e004ebd5b5532a4b85984a62f8ad48a81aa3460c".to_owned(),
            completed_at: Some("2026-07-18T00:00:00Z".to_owned()),
        })],
    );
    let snapshot = CiLaneSnapshot::new(vec![health], Vec::new());
    let dir = dashboard_test_dir("ci-lanes-route");
    let path = dir.join("ci-lanes-snapshot.json");
    write_ci_lane_snapshot(&path, &snapshot).expect("snapshot writes");

    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ci_lane_snapshot_path: Some(path),
        ..Default::default()
    };
    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/ci-lanes",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(response.status, 200);
    let body = response_json(&response);
    assert_eq!(body["data"]["source"], serde_json::json!("github_actions"));
    assert_eq!(body["data"]["refresh_state"], serde_json::json!("ready"));
    assert_eq!(body["data"]["freshness"], serde_json::json!("fresh"));
    let lanes = body["data"]["lanes"].as_array().expect("lanes array");
    assert_eq!(lanes.len(), catalog.len());
    let watched_lane = lanes
        .iter()
        .find(|lane| lane["check_name"] == serde_json::json!(watched_check_name))
        .expect("watched lane is present");
    assert_eq!(watched_lane["state"], serde_json::json!("success"));
    let unwatched_count = lanes
        .iter()
        .filter(|lane| lane["check_name"] != serde_json::json!(watched_check_name))
        .count();
    assert_eq!(
        lanes
            .iter()
            .filter(|lane| lane["check_name"] != serde_json::json!(watched_check_name)
                && lane["state"] == "unknown")
            .count(),
        unwatched_count,
        "lanes absent from the stored snapshot must render unknown, never green"
    );
}
