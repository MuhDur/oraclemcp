//! Governed-egress live matrix (bead oraclemcp-epic-09x-alien-6sj8.4.6).
//!
//! The egress seam is the last thing standing between a live Oracle row and the
//! model. A gap here is a data-exfiltration hole, not a regression, so every
//! case below runs against a REAL database and asserts on the REAL serialized
//! page — never on a hand-built row.
//!
//! Four properties, one per attack:
//!
//! 1. **Tokenization.** A configured sensitive column egresses as a stable
//!    token, never as plaintext.
//! 2. **Mask-unknown default (fail-closed).** A column the policy never heard of
//!    is masked, not passed through. An unconfigured column is the common way a
//!    new sensitive column silently escapes.
//! 3. **No plaintext through a self-join (inference).** Oracle joins on the
//!    PLAINTEXT server-side, so the join relation survives into a page whose
//!    values are tokenized. The page must stay join-consistent (equal plaintext
//!    ⇒ equal token) while leaking no plaintext — that is the whole point of a
//!    token, and the exact place a naive per-column mask leaks by comparison.
//! 4. **Certificate re-derivation.** The per-result mask certificate must
//!    re-derive to the same decisions from an independently built policy, and
//!    must agree with what actually landed in the rows.
//!
//! Gated behind the `live-xe` feature AND a runtime reachability probe: with no
//! reachable Oracle the cases skip green, matching the repo's `live-xe` /
//! estate-absent convention.
//!
//!   cargo test -p oraclemcp-db --features live-xe --test live_egress -- --nocapture
//!
//! Target with ORACLEMCP_TEST_DSN / _USER / _PASSWORD. Driven across the lane
//! matrix by `scripts/e2e/egress.sh`.
#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_db::{
    MASKED_RESULT_VALUE, OracleConnectOptions, OracleConnection, OracleRow, ProfileMaskingSalt,
    ResultMaskingAction, ResultMaskingDecisionAction, ResultMaskingDecisionSource,
    ResultMaskingPolicy, ResultMaskingRule, RustOracleConnection, SerializeOptions, serialize_row,
};
use serde_json::Value;

/// Synthetic, non-customer fixture rows. Ids 1 and 3 deliberately SHARE an
/// email so the self-join has something to match on and tokenization has a
/// collision to stay consistent about.
const ALICE_EMAIL: &str = "alice@example.test";
const BOB_EMAIL: &str = "bob@example.test";
const ALICE_SSN: &str = "111-22-3333";
const BOB_SSN: &str = "444-55-6666";
const CAROL_SSN: &str = "777-88-9999";

/// Every plaintext the fixture puts in the database. No serialized page may
/// contain any of these once a masking policy is in force.
const ALL_PLAINTEXT: &[&str] = &[ALICE_EMAIL, BOB_EMAIL, ALICE_SSN, BOB_SSN, CAROL_SSN];

/// The fixture as an inline view: no DDL, no cleanup, no privileges beyond
/// SELECT ... FROM dual, so the identical statement runs on every lane.
///
/// Deliberately an inline view rather than the more natural `WITH staff AS (…)`:
/// the pinned `oracledb` 0.8.3 driver decides a statement is a query by looking
/// for a literal leading `SELECT` keyword (`statement_is_query`), so a CTE-led
/// query is sent down the non-query path and comes back ORA-00900. That is a
/// real driver gap (the guard admits CTE reads), filed separately; it is not
/// what this egress suite is here to prove, so the fixture routes around it.
fn staff() -> String {
    format!(
        "(SELECT 1 AS id, '{ALICE_EMAIL}' AS email, '{ALICE_SSN}' AS ssn FROM dual UNION ALL \
          SELECT 2, '{BOB_EMAIL}', '{BOB_SSN}' FROM dual UNION ALL \
          SELECT 3, '{ALICE_EMAIL}', '{CAROL_SSN}' FROM dual)"
    )
}

fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("rt");
    runtime.block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx");
        body(cx).await
    })
}

fn test_opts() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN")
            .unwrap_or_else(|_| "//localhost:1521/FREEPDB1".to_owned()),
        username: Some(
            std::env::var("ORACLEMCP_TEST_USER").unwrap_or_else(|_| "system".to_owned()),
        ),
        password: Some(
            std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap_or_else(|_| "oracle".to_owned()),
        ),
        ..Default::default()
    }
}

async fn connect_or_skip(cx: &Cx, test_name: &str) -> Option<RustOracleConnection> {
    match RustOracleConnection::connect(cx, test_opts()).await {
        Ok(conn) => Some(conn),
        Err(error) => {
            eprintln!(
                "[live-xe] SKIP {test_name}: no reachable Oracle ({error}); \
                 set ORACLEMCP_TEST_DSN / _USER / _PASSWORD"
            );
            None
        }
    }
}

/// A 32-byte non-secret test salt. Tokens are HMAC(salt, type-tag, plaintext),
/// so a fixed salt is what makes them reproducible across rows and columns.
fn test_salt() -> ProfileMaskingSalt {
    ProfileMaskingSalt::new(
        "profile:egress-e2e:masking:v1",
        (0_u8..32).collect::<Vec<u8>>(),
    )
    .expect("32-byte test salt is valid")
}

/// The policy under test: EMAIL is tokenized, everything else the policy has not
/// been told about is masked by default.
fn tokenizing_policy() -> ResultMaskingPolicy {
    ResultMaskingPolicy::new(
        vec![ResultMaskingRule::column(
            "EMAIL",
            ResultMaskingAction::Tokenize,
        )],
        true,
    )
    .with_profile("egress-e2e")
    .with_token_salt(test_salt())
}

fn masking_opts(policy: ResultMaskingPolicy) -> SerializeOptions {
    SerializeOptions {
        result_masking: Some(policy),
        ..Default::default()
    }
}

/// THE anti-exfiltration assertion: scan the WHOLE serialized page, not just the
/// columns we happen to expect, so a plaintext that escapes through a column the
/// test never thought about still fails the run.
fn assert_no_plaintext_anywhere(rows: &[Value], case: &str) {
    let page = serde_json::to_string(rows).expect("page serializes");
    for plaintext in ALL_PLAINTEXT {
        assert!(
            !page.contains(plaintext),
            "PLAINTEXT EXFILTRATION in {case}: {plaintext:?} escaped into the serialized page: {page}"
        );
    }
}

fn cell(row: &Value, column: &str) -> String {
    row.get(column)
        .unwrap_or_else(|| panic!("column {column} present in row {row}"))
        .as_str()
        .unwrap_or_else(|| panic!("column {column} serializes as a string in row {row}"))
        .to_owned()
}

async fn masked_page(
    cx: &Cx,
    conn: &RustOracleConnection,
    sql: &str,
    policy: ResultMaskingPolicy,
) -> (Vec<OracleRow>, Vec<Value>) {
    let rows = conn.query_rows(cx, sql, &[]).await.expect("live query");
    let opts = masking_opts(policy);
    let serialized = rows
        .iter()
        .map(|row| serialize_row(row, &opts))
        .collect::<Vec<_>>();
    (rows, serialized)
}

#[test]
fn live_egress_tokenizes_a_configured_sensitive_column() {
    run_with_cx(|cx| async move {
        let Some(conn) =
            connect_or_skip(&cx, "live_egress_tokenizes_a_configured_sensitive_column").await
        else {
            return;
        };
        let sql = format!("SELECT id, email FROM {} staff ORDER BY id", staff());
        let (_, rows) = masked_page(&cx, &conn, &sql, tokenizing_policy()).await;
        assert_eq!(rows.len(), 3, "fixture returns three rows");
        assert_no_plaintext_anywhere(&rows, "tokenization");

        let tokens: Vec<String> = rows.iter().map(|row| cell(row, "EMAIL")).collect();
        for (index, token) in tokens.iter().enumerate() {
            assert_ne!(
                token, ALICE_EMAIL,
                "row {index}: a tokenized column must never egress plaintext"
            );
            assert_ne!(
                token, BOB_EMAIL,
                "row {index}: a tokenized column must never egress plaintext"
            );
            assert_ne!(
                token, MASKED_RESULT_VALUE,
                "row {index}: a Tokenize rule with a live salt must produce a token, not a flat mask \
                 (a silent degrade to Mask would destroy join-consistency without anyone noticing)"
            );
            assert!(
                !token.is_empty(),
                "row {index}: an empty token is not a token"
            );
        }

        // Determinism is the property that makes a token useful: equal plaintext
        // (rows 1 and 3) must produce equal tokens, unequal plaintext must not.
        assert_eq!(
            tokens[0], tokens[2],
            "the same plaintext must tokenize identically (rows 1 and 3 share an email)"
        );
        assert_ne!(
            tokens[0], tokens[1],
            "different plaintext must not collide onto the same token"
        );
        eprintln!("[live-xe] egress tokenization OK: {} distinct tokens", {
            let mut distinct = tokens.clone();
            distinct.sort();
            distinct.dedup();
            distinct.len()
        });
    });
}

#[test]
fn live_egress_masks_an_unconfigured_column_by_default() {
    run_with_cx(|cx| async move {
        let Some(conn) =
            connect_or_skip(&cx, "live_egress_masks_an_unconfigured_column_by_default").await
        else {
            return;
        };
        let sql = format!("SELECT id, email, ssn FROM {} staff ORDER BY id", staff());

        // SSN is sensitive but the policy was never told about it. Fail-closed:
        // it must be masked anyway.
        let (_, rows) = masked_page(&cx, &conn, &sql, tokenizing_policy()).await;
        assert_no_plaintext_anywhere(&rows, "mask-unknown-default");
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(
                cell(row, "SSN"),
                MASKED_RESULT_VALUE,
                "row {index}: an unconfigured column must be masked by default, never passed through"
            );
        }

        // Mutation-killing counterpart: with the default OFF, that very column
        // egresses as plaintext. This proves it is `mask_unknown_default` doing
        // the work above — not some unrelated rule that would keep passing if the
        // fail-closed default regressed to `false`.
        let permissive = ResultMaskingPolicy::new(
            vec![ResultMaskingRule::column(
                "EMAIL",
                ResultMaskingAction::Tokenize,
            )],
            false,
        )
        .with_token_salt(test_salt());
        let (_, leaky) = masked_page(&cx, &conn, &sql, permissive).await;
        assert_eq!(
            cell(&leaky[0], "SSN"),
            ALICE_SSN,
            "with mask_unknown_default = false the same column passes through — \
             this is exactly what the fail-closed default is protecting against"
        );
    });
}

#[test]
fn live_egress_self_join_over_a_tokenized_column_leaks_no_plaintext() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(
            &cx,
            "live_egress_self_join_over_a_tokenized_column_leaks_no_plaintext",
        )
        .await
        else {
            return;
        };

        // Oracle evaluates the join on PLAINTEXT, server-side, before egress
        // masking ever runs. The join relation therefore survives into the page:
        // the inference question is whether the VALUES do too.
        let staff = staff();
        let sql = format!(
            "SELECT a.id AS id_a, b.id AS id_b, a.email AS email_a, b.email AS email_b \
             FROM {staff} a JOIN {staff} b ON a.email = b.email \
             WHERE a.id < b.id ORDER BY a.id, b.id"
        );
        let policy = ResultMaskingPolicy::new(
            vec![
                ResultMaskingRule::column("EMAIL_A", ResultMaskingAction::Tokenize),
                ResultMaskingRule::column("EMAIL_B", ResultMaskingAction::Tokenize),
            ],
            true,
        )
        .with_token_salt(test_salt());
        let (_, rows) = masked_page(&cx, &conn, &sql, policy).await;

        // Only alice (ids 1 and 3) shares an email, so the self-join yields
        // exactly one pair. If this ever changes, the join stopped being the
        // thing under test.
        assert_eq!(
            rows.len(),
            1,
            "the fixture's only shared email is alice's (ids 1 and 3)"
        );
        assert_no_plaintext_anywhere(&rows, "self-join inference");

        let row = &rows[0];
        let email_a = cell(row, "EMAIL_A");
        let email_b = cell(row, "EMAIL_B");
        assert_ne!(
            email_a, ALICE_EMAIL,
            "the join must not carry plaintext out"
        );
        assert_ne!(
            email_a, MASKED_RESULT_VALUE,
            "a live salt must tokenize, not flatten to a mask"
        );

        // Join-consistency: the two sides of a row that JOINED on equal plaintext
        // must carry equal tokens. A token that varied per column would make the
        // page self-contradictory (a matched join whose keys differ), and one that
        // varied per row would destroy the join relation the operator can see.
        assert_eq!(
            email_a, email_b,
            "JOIN-INCONSISTENT: rows joined on equal plaintext egressed unequal tokens"
        );

        // And the ids — non-sensitive, but unconfigured — are still masked by the
        // fail-closed default, so the pair cannot be re-identified through them.
        assert_eq!(cell(row, "ID_A"), MASKED_RESULT_VALUE);
        assert_eq!(cell(row, "ID_B"), MASKED_RESULT_VALUE);
        eprintln!("[live-xe] self-join egress OK: joined pair shares token {email_a}");
    });
}

#[test]
fn live_egress_mask_certificate_re_derives_the_decision() {
    run_with_cx(|cx| async move {
        let Some(conn) =
            connect_or_skip(&cx, "live_egress_mask_certificate_re_derives_the_decision").await
        else {
            return;
        };
        let sql = format!("SELECT id, email, ssn FROM {} staff ORDER BY id", staff());
        let (raw, rows) = masked_page(&cx, &conn, &sql, tokenizing_policy()).await;

        let policy = tokenizing_policy();
        let certificate = policy
            .certificate_for_row(&raw[0])
            .expect("a policy that transforms columns must emit a certificate");
        assert_eq!(certificate.schema_version, 1);
        assert_eq!(certificate.profile.as_deref(), Some("egress-e2e"));

        // Re-derivation: an independently constructed but identical policy must
        // reach the identical decisions and the identical policy identity. If the
        // certificate could not be re-derived, it would not be a proof of
        // anything — it would just be a claim travelling next to the data.
        let rederived = tokenizing_policy()
            .certificate_for_row(&raw[0])
            .expect("re-derivation emits a certificate");
        assert_eq!(
            certificate, rederived,
            "the mask certificate must re-derive exactly from an identical policy"
        );
        assert_eq!(
            certificate.policy_id, rederived.policy_id,
            "policy identity must be a stable function of the policy content"
        );

        let decision = |column: &str| {
            certificate
                .decisions
                .iter()
                .find(|decision| decision.column == column)
                .unwrap_or_else(|| panic!("certificate covers column {column}"))
                .clone()
        };

        let email = decision("EMAIL");
        assert_eq!(email.action, ResultMaskingDecisionAction::Tokenize);
        assert_eq!(email.source, ResultMaskingDecisionSource::Rule);
        assert!(
            email.salt_id.is_some(),
            "a Tokenize decision must name the salt that produced the token"
        );

        let ssn = decision("SSN");
        assert_eq!(ssn.action, ResultMaskingDecisionAction::Mask);
        assert_eq!(
            ssn.source,
            ResultMaskingDecisionSource::MaskUnknownDefault,
            "the certificate must attribute the mask to the fail-closed default, not invent a rule"
        );

        // Bind the proof to the data. A certificate that claims a column was
        // transformed while its plaintext sits in the page is worse than no
        // certificate at all, because it launders the leak.
        for decision in &certificate.decisions {
            if decision.action == ResultMaskingDecisionAction::Pass {
                continue;
            }
            let value = cell(&rows[0], &decision.column);
            for plaintext in ALL_PLAINTEXT {
                assert_ne!(
                    value, *plaintext,
                    "certificate claims {:?} on {} but the plaintext egressed anyway",
                    decision.action, decision.column
                );
            }
        }
        eprintln!(
            "[live-xe] mask certificate OK: policy_id={} decisions={}",
            certificate.policy_id,
            certificate.decisions.len()
        );
    });
}
