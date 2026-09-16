#[test]
fn idempotency_ttl_never_expires_an_in_progress_lease() {
    let ledger = OperatorIdempotencyLedger::new();
    let facts = idempotency_fact("long-running-action");
    let older_than_replay_window = std::time::Instant::now()
        .checked_sub(OPERATOR_IDEMPOTENCY_TTL + std::time::Duration::from_secs(1))
        .expect("idempotency replay window is representable");
    ledger.insert_for_test(
        facts.storage_key.clone(),
        OperatorIdempotencyEntry {
            facts: facts.clone(),
            response: None,
            created_at: older_than_replay_window,
            generation: 1,
        },
    );

    match ledger.begin("/operator/v1/actions/execute", facts) {
        OperatorIdempotencyBegin::InProgress(response) => {
            assert_eq!(response.status, 409);
            assert_eq!(
                response_json(&response)["data"]["error"],
                serde_json::json!("operator_idempotency_in_progress")
            );
        }
        other => panic!(
            "a long-running action must retain its idempotency marker, got {}",
            operator_idempotency_begin_kind(&other)
        ),
    }
}

#[test]
fn idempotency_ttl_still_expires_a_completed_replay() {
    let ledger = OperatorIdempotencyLedger::new();
    let facts = idempotency_fact("expired-completed-action");
    let older_than_replay_window = std::time::Instant::now()
        .checked_sub(OPERATOR_IDEMPOTENCY_TTL + std::time::Duration::from_secs(1))
        .expect("idempotency replay window is representable");
    ledger.insert_for_test(
        facts.storage_key.clone(),
        OperatorIdempotencyEntry {
            facts: facts.clone(),
            response: Some(empty_response(200)),
            created_at: older_than_replay_window,
            generation: 1,
        },
    );

    match ledger.begin("/operator/v1/actions/execute", facts) {
        OperatorIdempotencyBegin::Fresh(_) => {}
        other => panic!(
            "a completed replay past its TTL must permit a fresh request, got {}",
            operator_idempotency_begin_kind(&other)
        ),
    }
}
