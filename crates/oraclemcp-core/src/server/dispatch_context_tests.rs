use super::*;

#[test]
fn owned_dispatch_context_preserves_lane_time_and_caller_budget() {
    let request_started_at = Instant::now();
    let admitted_at = Time::from_secs(100);
    let caller_budget = Budget::new()
        .with_deadline(Time::from_secs(130))
        .with_poll_quota(321)
        .with_cost_quota(654);
    let request_budget = RequestBudget::from_budget_at(admitted_at, caller_budget);
    let owned = DispatchContext::default()
        .with_http_session_id("session-1")
        .with_principal_key("principal-1")
        .with_local_transport(false)
        .with_lane_identity("lane-1", 7)
        .with_request_started_at(request_started_at)
        .with_admitted_at(admitted_at)
        .with_caller_budget(caller_budget)
        .with_request_budget(&request_budget)
        .to_owned_context();
    let borrowed = owned.as_dispatch_context();

    assert_eq!(borrowed.http_session_id(), Some("session-1"));
    assert_eq!(borrowed.principal_key(), Some("principal-1"));
    assert_eq!(borrowed.lane_id(), Some("lane-1"));
    assert_eq!(borrowed.lane_generation(), Some(7));
    assert!(!borrowed.is_local_transport());
    assert_eq!(borrowed.request_started_at(), Some(request_started_at));
    assert_eq!(borrowed.admitted_at(), Some(admitted_at));
    assert_eq!(borrowed.caller_budget(), Some(caller_budget));
    assert!(
        borrowed
            .request_budget()
            .expect("request budget round-trips")
            .db_quota()
            .ptr_eq(&request_budget.db_quota()),
        "owned context clones must share consumed quota"
    );
}
