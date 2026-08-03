#[test]
fn change_proposals_list_returns_stripped_projection_with_etag_and_next_cursor() {
    let (server, cfg, _proposal_id) = change_proposals_test_config();

    let list = handle_http_request(
        &server,
        &cfg,
        operator_json_get("/operator/v1/change-proposals"),
    );
    assert_eq!(list.status, 200);
    let etag = list.header("etag").expect("list carries an ETag validator");
    assert!(!etag.is_empty(), "ETag must be a non-empty validator");

    let body = String::from_utf8(list.body.clone()).expect("list body utf8");
    assert!(
        !body.contains("UPDATE accounts"),
        "list projection must not serialize sql_template bodies"
    );

    let list_json = response_json(&list);
    let statement = &list_json["data"]["proposals"][0]["statements"][0];
    assert!(
        statement["sql_sha256"]
            .as_str()
            .expect("sql digest present")
            .starts_with("sha256:"),
        "list statement keeps the SQL digest"
    );
    assert_eq!(
        statement.get("sql_template"),
        None,
        "list statement omits the sql_template body"
    );
    assert_eq!(statement["unit"], serde_json::json!("dml"));
    assert_eq!(
        list_json["data"]["nextCursor"],
        Value::Null,
        "a single-page board reports no next cursor"
    );
    assert_eq!(
        list_json["data"]["source"],
        serde_json::json!("change_proposals")
    );
}

#[test]
fn change_proposals_list_answers_304_on_matching_if_none_match() {
    let (server, cfg, _proposal_id) = change_proposals_test_config();

    let first = handle_http_request(
        &server,
        &cfg,
        operator_json_get("/operator/v1/change-proposals"),
    );
    assert_eq!(first.status, 200);
    let etag = first
        .header("etag")
        .expect("first list carries an ETag")
        .to_owned();

    let revalidated = handle_http_request(
        &server,
        &cfg,
        operator_get_owned("/operator/v1/change-proposals".to_owned(), Some(&etag)),
    );
    assert_eq!(
        revalidated.status, 304,
        "an unchanged board revalidates to 304 Not Modified"
    );
    assert!(
        revalidated.body.is_empty(),
        "a 304 response carries no body"
    );
    assert_eq!(
        revalidated.header("etag"),
        Some(etag.as_str()),
        "the 304 response echoes the ETag validator"
    );
}

#[test]
fn change_proposal_detail_route_returns_full_sql_template() {
    let (server, cfg, proposal_id) = change_proposals_test_config();

    let detail = handle_http_request(
        &server,
        &cfg,
        operator_get_owned(format!("/operator/v1/change-proposals/{proposal_id}"), None),
    );
    assert_eq!(detail.status, 200);
    let detail_json = response_json(&detail);
    assert_eq!(
        detail_json["data"]["source"],
        serde_json::json!("change_proposals")
    );
    assert_eq!(
        detail_json["data"]["proposal"]["statements"][0]["sql_template"],
        serde_json::json!("UPDATE accounts SET status = :1 WHERE id = :2"),
        "the detail view restores the sql_template the list projection omits"
    );

    let missing = handle_http_request(
        &server,
        &cfg,
        operator_get_owned(
            "/operator/v1/change-proposals/cp-does-not-exist".to_owned(),
            None,
        ),
    );
    assert_eq!(missing.status, 404);
    assert_eq!(
        response_json(&missing)["data"]["error"],
        serde_json::json!("unknown_change_proposal")
    );
}

#[test]
fn schema_diff_export_is_redacted_and_review_gated() {
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };

    let response = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/schema-diff",
            &serde_json::json!({
                "title": "App migration",
                "before": {
                    "objects": [
                        {
                            "object_type": "TABLE",
                            "owner": null,
                            "name": {"text": "T_OLD", "quoted": false},
                            "ddl": "create table t_old (id number)"
                        },
                        {
                            "object_type": "TABLE",
                            "owner": null,
                            "name": {"text": "T_CHANGED", "quoted": false},
                            "ddl": "create table t_changed (id number)"
                        }
                    ]
                },
                "after": {
                    "objects": [
                        {
                            "object_type": "TABLE",
                            "owner": null,
                            "name": {"text": "T_CHANGED", "quoted": false},
                            "ddl": "create table t_changed (id number, name varchar2(30))"
                        },
                        {
                            "object_type": "VIEW",
                            "owner": null,
                            "name": {"text": "V_NEW", "quoted": false},
                            "ddl": "create or replace view v_new as select id from t_changed"
                        }
                    ]
                }
            }),
        ),
    );

    assert_eq!(response.status, 200);
    let body = response_json(&response);
    assert_eq!(body["data"]["source"], serde_json::json!("schema_diff"));
    assert_eq!(body["data"]["summary"]["added"], serde_json::json!(1));
    assert_eq!(body["data"]["summary"]["dropped"], serde_json::json!(1));
    assert_eq!(body["data"]["summary"]["changed"], serde_json::json!(1));
    assert_eq!(
        body["data"]["diff"]["changed"][0]["name"],
        serde_json::json!({"text": "T_CHANGED", "quoted": false})
    );
    assert_eq!(
        body["data"]["diff"]["changed"][0].get("ddl"),
        None,
        "redacted diff view must not expose object DDL"
    );
    assert!(
        body["data"]["diff"]["changed"][0]["ddl_sha256"]
            .as_str()
            .expect("ddl hash")
            .starts_with("sha256:")
    );
    let script = body["data"]["migration_script"]
        .as_str()
        .expect("migration script");
    assert!(script.contains("review artifact only"));
    assert!(script.contains("Oracle DDL commits independently"));
    assert!(script.contains("create or replace view v_new"));
    assert!(script.contains("DROP TABLE T_OLD"));
    assert_eq!(
        body["data"]["proposal_statements"][0]["unit"],
        serde_json::json!("ddl"),
        "apply is via a normal Change Proposal statement"
    );
    assert_eq!(
        body["data"]["proposal_statements"][0]["binds"],
        serde_json::json!([])
    );
}

#[test]
fn source_history_snapshots_prior_source_and_revert_drafts_review_proposal() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let server = server_with_dispatch(Arc::new(SourceHistoryDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("source-history");
    let state = dir.join("state");
    let service_store = crate::file_store::FileStore::open(&state).expect("service store");
    let owner = service_store
        .acquire_service_owner("http-test")
        .expect("service owner");
    let change_proposals = Arc::new(
        crate::change_proposal::ChangeProposalStore::open_with_owner(owner.clone())
            .expect("proposal store"),
    );
    let source_history = Arc::new(
        crate::source_history::SourceHistoryStore::open_with_owner(owner)
            .expect("source-history store"),
    );
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(change_proposals),
        source_history: Some(source_history),
        ..Default::default()
    };
    let ddl = "CREATE OR REPLACE PACKAGE BODY app.emp_api AS BEGIN NULL; END;";

    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/draft",
            &serde_json::json!({
                "profile": "prod",
                "author": "agent",
                "title": "Patch package body",
                "statements": [{
                    "sql_template": ddl,
                    "unit": "ddl",
                    "commit": true
                }]
            }),
        ),
    );
    assert_eq!(draft.status, 200);
    let proposal_id = response_json(&draft)["data"]["proposal"]["id"]
        .as_str()
        .expect("proposal id")
        .to_owned();

    let apply = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/apply",
            &serde_json::json!({
                "proposal_id": proposal_id,
                "confirm": "opaque-preview-grant",
                "commit": true,
                "idempotency_key": "source-history-apply"
            }),
        ),
    );
    assert_eq!(apply.status, 200);
    let apply_json = response_json(&apply);
    let snapshot = &apply_json["data"]["results"][0]["source_snapshot"]["snapshot"];
    assert_eq!(
        apply_json["data"]["results"][0]["source_snapshot"]["status"],
        serde_json::json!("captured")
    );
    assert_eq!(snapshot["owner"], serde_json::json!("APP"));
    assert_eq!(snapshot["name"], serde_json::json!("EMP_API"));
    assert_eq!(snapshot["object_type"], serde_json::json!("PACKAGE BODY"));
    let snapshot_id = snapshot["id"].as_str().expect("snapshot id").to_owned();

    let history = handle_http_request(
        &server,
        &cfg,
        operator_json_get("/operator/v1/source-history"),
    );
    assert_eq!(history.status, 200);
    let history_body = String::from_utf8(history.body.clone()).expect("history utf8");
    assert!(
        !history_body.contains("BEGIN NULL"),
        "source-history list must not serialize source text"
    );
    let history_json = response_json(&history);
    assert_eq!(
        history_json["data"]["snapshots"][0]["id"],
        serde_json::json!(snapshot_id)
    );
    assert_eq!(
        history_json["data"]["nextCursor"],
        Value::Null,
        "a single-page history reports no next cursor"
    );
    let history_etag = history
        .header("etag")
        .expect("source-history list carries an ETag")
        .to_owned();
    assert!(!history_etag.is_empty());

    let history_revalidated = handle_http_request(
        &server,
        &cfg,
        operator_get_owned(
            "/operator/v1/source-history".to_owned(),
            Some(&history_etag),
        ),
    );
    assert_eq!(
        history_revalidated.status, 304,
        "an unchanged source-history board revalidates to 304"
    );
    assert!(history_revalidated.body.is_empty());
    assert_eq!(
        history_revalidated.header("etag"),
        Some(history_etag.as_str())
    );

    let revert = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/source-history/revert",
            &serde_json::json!({ "snapshot_id": snapshot_id }),
        ),
    );
    assert_eq!(revert.status, 200);
    let revert_json = response_json(&revert);
    assert_eq!(
        revert_json["data"]["status"],
        serde_json::json!("revert_drafted")
    );
    assert_eq!(
        revert_json["data"]["proposal"]["statements"][0]["unit"],
        serde_json::json!("ddl")
    );
    assert!(
        revert_json["data"]["proposal"]["statements"][0]["sql_template"]
            .as_str()
            .expect("revert SQL")
            .starts_with("CREATE OR REPLACE PACKAGE BODY")
    );

    let call_names = calls
        .lock()
        .iter()
        .map(|(tool, _)| tool.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        call_names,
        vec!["oracle_get_source".to_owned(), "oracle_execute".to_owned()]
    );
}

type QuotedSourceApplyFixture = (
    OracleMcpServer,
    HttpTransportConfig,
    Arc<Mutex<Vec<(String, Value)>>>,
    Value,
);

fn apply_quoted_source_change(return_wrong_unquoted_object: bool) -> QuotedSourceApplyFixture {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let server = server_with_dispatch(Arc::new(QuotedSourceHistoryDispatch {
        calls: Arc::clone(&calls),
        return_wrong_unquoted_object,
    }));
    let dir = dashboard_test_dir(if return_wrong_unquoted_object {
        "source-history-quoted-mismatch"
    } else {
        "source-history-quoted-exact"
    });
    let state = dir.join("state");
    let service_store = crate::file_store::FileStore::open(&state).expect("service store");
    let owner = service_store
        .acquire_service_owner("http-test")
        .expect("service owner");
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(Arc::new(
            crate::change_proposal::ChangeProposalStore::open_with_owner(owner.clone())
                .expect("proposal store"),
        )),
        source_history: Some(Arc::new(
            crate::source_history::SourceHistoryStore::open_with_owner(owner)
                .expect("source-history store"),
        )),
        ..Default::default()
    };
    let ddl = "CREATE /* identity */ OR\n-- quote guard\nREPLACE EDITIONABLE PROCEDURE \"App\".\"foo\" IS BEGIN NULL; END;";
    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/draft",
            &serde_json::json!({
                "profile": "prod",
                "author": "agent",
                "title": "Patch quoted procedure",
                "statements": [{
                    "sql_template": ddl,
                    "unit": "ddl",
                    "commit": true
                }]
            }),
        ),
    );
    assert_eq!(
        draft.status,
        200,
        "quoted-source draft response: {}",
        String::from_utf8_lossy(&draft.body)
    );
    let proposal_id = response_json(&draft)["data"]["proposal"]["id"]
        .as_str()
        .expect("proposal id")
        .to_owned();
    let apply = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/apply",
            &serde_json::json!({
                "proposal_id": proposal_id,
                "confirm": "opaque-preview-grant",
                "commit": true,
                "idempotency_key": "source-history-quoted-apply"
            }),
        ),
    );
    assert_eq!(apply.status, 200);
    let apply_json = response_json(&apply);
    (server, cfg, calls, apply_json)
}

#[test]
fn quoted_source_snapshot_fetch_capture_and_revert_keep_exact_identity() {
    let (server, cfg, calls, apply_json) = apply_quoted_source_change(false);
    let source_snapshot = &apply_json["data"]["results"][0]["source_snapshot"];
    assert_eq!(source_snapshot["status"], serde_json::json!("captured"));
    let snapshot = &source_snapshot["snapshot"];
    assert_eq!(snapshot["owner"], serde_json::json!("App"));
    assert_eq!(snapshot["owner_quoted"], serde_json::json!(true));
    assert_eq!(snapshot["name"], serde_json::json!("foo"));
    assert_eq!(snapshot["name_quoted"], serde_json::json!(true));
    assert!(
        snapshot["target_identity_sha256"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );

    let snapshot_id = snapshot["id"].as_str().expect("snapshot id");
    let revert = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/source-history/revert",
            &serde_json::json!({ "snapshot_id": snapshot_id }),
        ),
    );
    assert_eq!(revert.status, 200);
    let revert_json = response_json(&revert);
    let revert_sql = revert_json["data"]["proposal"]["statements"][0]["sql_template"]
        .as_str()
        .expect("revert SQL");
    assert!(revert_sql.starts_with("CREATE OR REPLACE PROCEDURE \"foo\""));

    let calls = calls.lock();
    assert_eq!(calls[0].0, "oracle_get_source");
    assert_eq!(calls[0].1["owner"], serde_json::json!("\"App\""));
    assert_eq!(calls[0].1["name"], serde_json::json!("\"foo\""));
    assert_eq!(calls[0].1["owner_quoted"], serde_json::json!(true));
    assert_eq!(calls[0].1["name_quoted"], serde_json::json!(true));
    assert_eq!(calls[1].0, "oracle_execute");
}

#[test]
fn coexisting_unquoted_object_cannot_satisfy_quoted_snapshot_identity() {
    let (server, cfg, calls, apply_json) = apply_quoted_source_change(true);
    let source_snapshot = &apply_json["data"]["results"][0]["source_snapshot"];
    assert_eq!(source_snapshot["status"], serde_json::json!("skipped"));
    assert_eq!(
        source_snapshot["reason"],
        serde_json::json!("source fetch target identity did not match apply target")
    );
    assert_eq!(source_snapshot["expected_object"]["name"], "foo");
    assert_eq!(source_snapshot["actual_object"]["name"], "FOO");
    assert_ne!(
        source_snapshot["expected_identity_sha256"],
        source_snapshot["actual_identity_sha256"]
    );

    let history = handle_http_request(
        &server,
        &cfg,
        operator_json_get("/operator/v1/source-history"),
    );
    assert_eq!(
        response_json(&history)["data"]["snapshots"],
        serde_json::json!([])
    );
    let call_names = calls
        .lock()
        .iter()
        .map(|(tool, _)| tool.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        call_names,
        vec!["oracle_get_source".to_owned(), "oracle_execute".to_owned()]
    );
}

#[test]
fn fetched_source_text_cannot_disagree_with_exact_quoted_metadata() {
    let target = source_object_from_create_or_replace_sql(
        "CREATE OR REPLACE PROCEDURE \"App\".\"foo\" IS BEGIN NULL; END;",
    )
    .expect("quoted target");
    let outcome = current_source_document(
        &target,
        "PROCEDURE",
        "App",
        "foo",
        "PROCEDURE",
        "all_source",
        "CREATE OR REPLACE PROCEDURE FOO IS BEGIN NULL; END;",
    );
    let SourceSnapshotFetchOutcome::Skipped(skipped) = outcome else {
        panic!("mismatched source text must not become a captured document");
    };
    assert_eq!(skipped["status"], serde_json::json!("skipped"));
    assert_eq!(
        skipped["reason"],
        serde_json::json!("source fetch target identity did not match apply target")
    );
}

#[test]
fn unsupported_quoted_source_header_skips_snapshot_without_fetching() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let server = server_with_dispatch(Arc::new(SourceHistoryDispatch {
        calls: Arc::clone(&calls),
    }));
    let state = dashboard_test_dir("source-history-unsupported-quote").join("state");
    let service_store = crate::file_store::FileStore::open(&state).expect("service store");
    let owner = service_store
        .acquire_service_owner("http-test")
        .expect("service owner");
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(Arc::new(
            crate::change_proposal::ChangeProposalStore::open_with_owner(owner.clone())
                .expect("proposal store"),
        )),
        source_history: Some(Arc::new(
            crate::source_history::SourceHistoryStore::open_with_owner(owner)
                .expect("source-history store"),
        )),
        ..Default::default()
    };
    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/draft",
            &serde_json::json!({
                "profile": "prod",
                "author": "agent",
                "statements": [{
                    "sql_template": "CREATE OR REPLACE PROCEDURE \"fo\"\"o\" IS BEGIN NULL; END;",
                    "unit": "ddl",
                    "commit": true
                }]
            }),
        ),
    );
    assert_eq!(draft.status, 200);
    let proposal_id = response_json(&draft)["data"]["proposal"]["id"]
        .as_str()
        .expect("proposal id")
        .to_owned();
    let apply = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/apply",
            &serde_json::json!({
                "proposal_id": proposal_id,
                "confirm": "opaque-preview-grant",
                "commit": true,
                "idempotency_key": "source-history-unsupported-quote"
            }),
        ),
    );
    assert_eq!(apply.status, 200);
    let apply_json = response_json(&apply);
    assert_eq!(
        apply_json["data"]["results"][0]["source_snapshot"]["status"],
        serde_json::json!("skipped")
    );
    assert_eq!(
        apply_json["data"]["results"][0]["source_snapshot"]["reason"],
        serde_json::json!(
            "statement is not a supported source-replaceable CREATE OR REPLACE shape"
        )
    );
    let call_names = calls
        .lock()
        .iter()
        .map(|(tool, _)| tool.clone())
        .collect::<Vec<_>>();
    assert_eq!(call_names, vec!["oracle_execute".to_owned()]);
}
