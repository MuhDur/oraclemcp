#![forbid(unsafe_code)]

use serde_json::json;

#[derive(Clone, Copy)]
struct Requirement {
    id: &'static str,
    group: &'static str,
    description: &'static str,
    primary_proof: &'static str,
    lane: &'static str,
    sid: &'static str,
    profile: &'static str,
    level: &'static str,
    grant: &'static str,
}

const REQUIREMENTS: &[Requirement] = &[
    Requirement {
        id: "WPN-A-001",
        group: "A lane isolation",
        description: "per-session and per-subject lanes keep operating level, profile, connection, and session state isolated",
        primary_proof: "stateful_http_lanes_keep_operating_level_isolated_per_session_and_subject",
        lane: "lane-a",
        sid: "session-a",
        profile: "dev",
        level: "READ_WRITE",
        grant: "scoped",
    },
    Requirement {
        id: "WPN-A-002",
        group: "A lane isolation",
        description: "confirmation and execution grants are single-use and bound to lane, subject, session, profile, and generation",
        primary_proof: "execute_grant_is_lane_bound_and_not_consumed_by_wrong_lane",
        lane: "lane-a",
        sid: "session-a",
        profile: "dev",
        level: "READ_WRITE",
        grant: "xgrant-bound",
    },
    Requirement {
        id: "WPN-B-001",
        group: "B different DBs",
        description: "different configured databases stay isolated under concurrent live lanes",
        primary_proof: "live_xe_two_database_lanes_keep_db_identity_isolated",
        lane: "db-a",
        sid: "live-session-a",
        profile: "db-a",
        level: "READ_ONLY",
        grant: "none",
    },
    Requirement {
        id: "WPN-C-001",
        group: "C same-DB contention",
        description: "blocked or contended database work cannot head-of-line-block unrelated lanes and must finish or return a typed timeout",
        primary_proof: "live_xe_same_database_contention_is_typed_or_succeeds_without_hanging",
        lane: "contended-lane",
        sid: "live-contention",
        profile: "same-db",
        level: "READ_WRITE",
        grant: "xgrant-bound",
    },
    Requirement {
        id: "WPN-D-001",
        group: "D capacity/fairness",
        description: "capacity is bounded, redacted, reserve-aware, and fair across subjects",
        primary_proof: "queued_admission_round_robins_between_subjects",
        lane: "stateful-capacity",
        sid: "capacity-session",
        profile: "dev",
        level: "READ_ONLY",
        grant: "none",
    },
    Requirement {
        id: "WPN-E-001",
        group: "E lifecycle",
        description: "DELETE, timeout, cancel, shutdown, and reaper terminal paths release permits and roll back dirty work exactly once",
        primary_proof: "permit_released_exactly_once_for_every_terminal_lane_path",
        lane: "lifecycle-lane",
        sid: "lifecycle-session",
        profile: "dev",
        level: "READ_WRITE",
        grant: "xgrant-revoked",
    },
    Requirement {
        id: "WPN-F-001",
        group: "F stdio decoupling",
        description: "Streamable HTTP lanes coexist with the frozen stdio contract without changing stdio golden behavior",
        primary_proof: "golden_http_stateful_streamable_session",
        lane: "stdio-compatible",
        sid: "stdio-process",
        profile: "process",
        level: "READ_ONLY",
        grant: "none",
    },
    Requirement {
        id: "WPN-G-001",
        group: "G audit concurrency",
        description: "concurrent actions keep per-subject audit identity, valid hash chains, and idempotency replay semantics",
        primary_proof: "operator_action_idempotency_replays_same_response_and_conflicts_on_drift",
        lane: "operator-lane",
        sid: "operator-session",
        profile: "operator",
        level: "READ_WRITE",
        grant: "idempotency-key-hash",
    },
    Requirement {
        id: "WPN-H-001",
        group: "H headline e2e",
        description: "mixed lane live/load evidence captures latency percentiles and zero leak/starvation verdicts",
        primary_proof: "phase0_capacity_spike",
        lane: "phase0-lane",
        sid: "phase0-session",
        profile: "live-xe",
        level: "READ_ONLY",
        grant: "none",
    },
    Requirement {
        id: "WPN-J-001",
        group: "J streamable HTTP",
        description: "SSE ids, Last-Event-ID/cursor replay, typed expiry/gaps, and DELETE are scoped to the target session/stream",
        primary_proof: "stateful_get_replays_buffered_lane_results_by_cursor",
        lane: "http-stream",
        sid: "mcp-session",
        profile: "dev",
        level: "READ_ONLY",
        grant: "none",
    },
    Requirement {
        id: "WPN-K-001",
        group: "K lane state-machine",
        description: "the lane model forbids permit leaks, stale grants, ceiling races, and subject/connection/audit mixing",
        primary_proof: "switch_generation_invalidates_stale_grants_and_subject_mix",
        lane: "model-lane",
        sid: "model-session",
        profile: "dev",
        level: "READ_WRITE",
        grant: "xgrant-generation",
    },
];

#[test]
fn wp_n_concurrency_contract_matrix_is_complete_and_jsonl_logged() {
    let coverage = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/conformance/COVERAGE.md"
    ));

    assert_eq!(
        REQUIREMENTS.len(),
        11,
        "N9 pins exactly eleven WP-N MUST rows in the conformance matrix"
    );
    assert!(
        coverage.contains("| WP-N concurrency/session | 11 | 0 | 11 | 11 | 0 | 100% |"),
        "coverage matrix must account for the WP-N contract row"
    );
    assert!(
        coverage.contains("Total tracked requirements: 61 MUST, 2 SHOULD, 63 tested."),
        "coverage totals must include WP-N"
    );

    for requirement in REQUIREMENTS {
        assert!(
            coverage.contains(requirement.id),
            "{} must be named in tests/conformance/COVERAGE.md",
            requirement.id
        );
        assert!(
            coverage.contains(requirement.primary_proof),
            "{} must map to its primary proof {}",
            requirement.id,
            requirement.primary_proof
        );
        eprintln!(
            "{}",
            json!({
                "contract": "WP-N",
                "requirement_id": requirement.id,
                "group": requirement.group,
                "lane": requirement.lane,
                "subject": "subject-sha256:contract",
                "sid": requirement.sid,
                "profile": requirement.profile,
                "level": requirement.level,
                "grant": requirement.grant,
                "outcome": "pass",
                "primary_proof": requirement.primary_proof,
                "description": requirement.description
            })
        );
    }
}
