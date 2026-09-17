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

#[test]
fn idempotency_cap_refuses_a_fresh_key_when_every_slot_is_live_then_recovers() {
    // A transport-level request permit is not universal: embedded callers enter
    // the same operator ledger without one. The ledger itself must therefore
    // remain bounded even when every existing key is still executing.
    let ledger = OperatorIdempotencyLedger::new();
    let mut live_leases = Vec::with_capacity(OPERATOR_IDEMPOTENCY_MAX_ENTRIES);
    for index in 0..OPERATOR_IDEMPOTENCY_MAX_ENTRIES {
        let key = format!("live-{index}");
        match ledger.begin("/operator/v1/actions/execute", idempotency_fact(&key)) {
            OperatorIdempotencyBegin::Fresh(lease) => live_leases.push(lease),
            other => panic!(
                "each slot before the cap must be fresh, got {}",
                operator_idempotency_begin_kind(&other)
            ),
        }
    }

    let refusal = match ledger.begin(
        "/operator/v1/actions/execute",
        idempotency_fact("must-not-grow-past-cap"),
    ) {
        OperatorIdempotencyBegin::CapacityExhausted(response) => response,
        other => panic!(
            "a fresh key above a fully-live cap must be refused, got {}",
            operator_idempotency_begin_kind(&other)
        ),
    };
    assert_eq!(refusal.status, 503);
    assert_eq!(
        response_json(&refusal)["data"]["error"],
        serde_json::json!("operator_idempotency_capacity_exhausted")
    );

    drop(live_leases.pop());
    match ledger.begin(
        "/operator/v1/actions/execute",
        idempotency_fact("admitted-after-live-lease-drop"),
    ) {
        OperatorIdempotencyBegin::Fresh(_) => {}
        other => panic!(
            "dropping a live lease must free exactly one slot, got {}",
            operator_idempotency_begin_kind(&other)
        ),
    }
}
