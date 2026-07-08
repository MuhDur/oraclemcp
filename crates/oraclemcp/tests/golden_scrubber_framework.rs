//! Golden-artifact discipline framework (bead D6.3d).
//!
//! This is the reference test for the shared golden discipline every other
//! golden surface adopts:
//!
//!   * `Scrubber` — the reusable canonicalizer (masks timestamps, UUIDs,
//!     durations, SCN, absolute paths, host:port, and memory addresses BEFORE
//!     comparison, so a golden can never leak a secret or flake).
//!   * `insta` — one representative *clean* surface (the capabilities /
//!     serverInfo document) snapshot-tested with the same `Scrubber` wired in as
//!     `insta` filters. The large protocol transcripts deliberately stay on the
//!     value-aware JSON-golden mechanism (see the round-trip demo below and the
//!     module docs in `tests/golden/support.rs`).
//!   * `UPDATE_GOLDENS` — the regenerate/verify workflow, proven end-to-end by
//!     the round-trip demo: generate -> scrub -> assert -> an intentional change
//!     FAILS with a unified diff -> `UPDATE_GOLDENS=1` re-approves.

#[path = "../../../tests/golden/support.rs"]
mod golden_support;

use golden_support::{Scrubber, assert_golden, check_golden};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Scrubber rule set — unit coverage for each standard masker.
// ---------------------------------------------------------------------------

#[test]
fn standard_masks_timestamps() {
    let s = Scrubber::standard();
    assert_eq!(
        s.scrub("at 2026-07-08T12:34:56Z done"),
        "at [TIMESTAMP] done"
    );
    assert_eq!(s.scrub("2026-07-08 12:34:56.123456+02:00"), "[TIMESTAMP]");
    // A deterministic fixture timestamp is still masked (canonicalization).
    assert_eq!(s.scrub("2026-06-01T08:00:00"), "[TIMESTAMP]");
}

#[test]
fn standard_masks_uuids() {
    let s = Scrubber::standard();
    assert_eq!(
        s.scrub("id=550e8400-e29b-41d4-a716-446655440000!"),
        "id=[UUID]!"
    );
}

#[test]
fn standard_masks_paths_addresses_and_hex() {
    let s = Scrubber::standard();
    assert_eq!(
        s.scrub("log at /home/alice/run.log now"),
        "log at [PATH] now"
    );
    assert_eq!(s.scrub("wallet /Users/bob/w"), "wallet [PATH]");
    assert_eq!(s.scrub(r"C:\Users\bob\w.txt end"), "[PATH] end");
    assert_eq!(s.scrub("bind 127.0.0.1:5432 ok"), "bind [ADDR] ok");
    assert_eq!(s.scrub("v6 [::1]:8080"), "v6 [ADDR]");
    assert_eq!(s.scrub("ptr 0xdeadbeef99 freed"), "ptr [ADDR] freed");
}

#[test]
fn standard_masks_durations_and_scn() {
    let s = Scrubber::standard();
    assert_eq!(s.scrub("took 1500ms"), "took [DURATION]");
    assert_eq!(
        s.scrub("took 3.2ms / 900us / 12ns"),
        "took [DURATION] / [DURATION] / [DURATION]"
    );
    assert_eq!(s.scrub(r#"{"scn": 42000111}"#), r#"{"scn": [SCN]}"#);
    assert_eq!(
        s.scrub("flashback to SCN 9987654 done"),
        "flashback to SCN [SCN] done"
    );
}

#[test]
fn standard_never_touches_semantic_constants() {
    // The exact over-scrub hazards found in the real transcripts: schema bounds,
    // row counts, host headers without a port, and dotted version numbers must
    // all survive untouched.
    let s = Scrubber::standard();
    for keep in [
        r#""maximum":5000"#,
        r#""num_rows":1234"#,
        r#""host":"127.0.0.1""#,
        "Oracle 23.0.0",
        r#""scn" is a system change number"#, // the bare word in prose
    ] {
        assert_eq!(
            s.scrub(keep),
            keep,
            "must not scrub semantic constant: {keep}"
        );
    }
}

#[test]
fn with_custom_appends_a_rule() {
    let s = Scrubber::empty().with_custom(r"secret-\w+", "[REDACTED]");
    assert_eq!(s.scrub("token=secret-abc123 ok"), "token=[REDACTED] ok");
}

#[test]
fn scrubbing_is_idempotent() {
    let s = Scrubber::standard();
    let once = s.scrub("2026-07-08T12:00:00Z /home/x 127.0.0.1:99 0xabcdef99 42ms");
    assert_eq!(s.scrub(&once), once, "re-scrubbing placeholders is a no-op");
}

#[test]
fn scrub_value_walks_only_string_leaves() {
    let s = Scrubber::standard();
    let scrubbed = s.scrub_value(&json!({
        "when": "2026-07-08T12:00:00Z",
        "count": 5000,               // number leaf: untouched
        "nested": ["/home/a/b", 1234] // string masked, number kept
    }));
    assert_eq!(
        scrubbed,
        json!({ "when": "[TIMESTAMP]", "count": 5000, "nested": ["[PATH]", 1234] })
    );
}

// ---------------------------------------------------------------------------
// insta — one CLEAN surface (capabilities / serverInfo) with the Scrubber
// wired in as insta filters. Gated to the engine-free build so the tool surface
// and feature tiers are deterministic across the feature powerset.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "plsql-intelligence"))]
#[test]
fn insta_capabilities_serverinfo_snapshot() {
    // `env!("CARGO_PKG_VERSION")` is the one genuinely dynamic input — it changes
    // every release. The Scrubber (via the `server_version` custom filter below)
    // keeps this snapshot stable across version bumps.
    let report = oraclemcp::registry::capabilities(env!("CARGO_PKG_VERSION"), true, true);
    let rendered = serde_json::to_string_pretty(&report).expect("capabilities serialize");

    let mut settings = insta::Settings::clone_current();
    // Wire the SHARED Scrubber in as insta filters: the same discipline the
    // JSON-golden surfaces use, expressed as insta's native filter list.
    for (pattern, replacement) in Scrubber::standard().rules() {
        settings.add_filter(pattern, replacement);
    }
    // A precise, surface-specific rule so the snapshot survives every release
    // bump instead of freezing the crate version (demonstrates `with_custom`
    // parity for a field-scoped mask).
    settings.add_filter(
        r#""server_version": "[^"]+""#,
        r#""server_version": "[VERSION]""#,
    );
    settings.bind(|| {
        insta::assert_snapshot!("capabilities_serverinfo", rendered);
    });
}

// ---------------------------------------------------------------------------
// Round-trip demo: generate -> scrub -> assert -> intentional change fails ->
// UPDATE_GOLDENS re-approves. Uses the value-aware JSON-golden mechanism so the
// whole `UPDATE_GOLDENS` workflow is exercised.
// ---------------------------------------------------------------------------

/// A synthetic status payload carrying exactly the dynamic value shapes the
/// standard scrubber owns. NONE of these are real secrets — they are here to be
/// masked. `operating_level` is the one semantic constant (flipped in the
/// negative case below).
fn demo_payload(
    generated_at: &str,
    request_id: &str,
    log_path: &str,
    bind_addr: &str,
    scn: u64,
    elapsed: &str,
    heap: &str,
) -> Value {
    json!({
        "operating_level": "READ_ONLY",
        "generated_at": generated_at,
        "request_id": request_id,
        "log_path": log_path,
        "bind_addr": bind_addr,
        "flashback": format!("SCN {scn}"),
        "elapsed": elapsed,
        "heap": heap,
        "note": "deterministic synthetic payload"
    })
}

#[test]
fn golden_roundtrip_demo() {
    let scrubber = Scrubber::standard();

    // 1. generate -> scrub -> assert (round-trips through UPDATE_GOLDENS).
    let run_a = demo_payload(
        "2026-07-08T12:00:00Z",
        "550e8400-e29b-41d4-a716-446655440000",
        "/home/alice/run.log",
        "127.0.0.1:5432",
        42_000_111,
        "1500ms",
        "0xdeadbeef99",
    );
    let scrubbed_a = scrubber.scrub_value(&run_a);
    assert_golden("demo/roundtrip", &scrubbed_a);

    // 2. the SAME surface with entirely different dynamic values scrubs to the
    //    identical canonical form -> a golden built from it never flakes.
    let run_b = demo_payload(
        "2019-01-01T00:00:00Z",
        "11111111-2222-3333-4444-555555555555",
        "/Users/bob/app/x.log",
        "10.0.0.9:8080",
        99_888_777,
        "42ms",
        "0xfeedface12",
    );
    let scrubbed_b = scrubber.scrub_value(&run_b);
    assert_eq!(
        scrubbed_a, scrubbed_b,
        "scrubbing absorbs non-deterministic churn -> no flake"
    );

    // 3. a real SEMANTIC change MUST be caught, with a unified diff and the
    //    re-approval hint in the failure message. Skipped under UPDATE_GOLDENS,
    //    which is a regenerate pass, not a verify pass.
    if std::env::var_os("UPDATE_GOLDENS").is_none() {
        let mut escalated = run_a.clone();
        escalated["operating_level"] = json!("READ_WRITE"); // was READ_ONLY
        let scrubbed_change = scrubber.scrub_value(&escalated);

        let report = check_golden("demo/roundtrip", &scrubbed_change)
            .expect_err("a semantic change must fail the golden");
        assert!(
            report.contains("--- expected"),
            "failure carries a unified diff:\n{report}"
        );
        assert!(
            report.contains("READ_ONLY") && report.contains("READ_WRITE"),
            "the diff shows the semantic delta:\n{report}"
        );
        assert!(
            report.contains("[UUID]") || report.contains("[TIMESTAMP]"),
            "scrubbed placeholders are visible in the golden:\n{report}"
        );
        assert!(
            report.contains("UPDATE_GOLDENS"),
            "failure explains how to re-approve:\n{report}"
        );
    }
}
