//! W13 seam contract for `oraclemcp_guard::scoped_grant` (bead T14.1 /
//! pvlqq.15.1): data model, canonical keyed digest, construction refusals,
//! lifecycle store and signed-reference domain separation. Offline/unit proof
//! only — no enforcement, matching or live-catalog claim.

use std::collections::BTreeSet;
use std::time::Duration;

use oraclemcp_audit::hmac_sha256;
use oraclemcp_guard::resolver::CatalogGeneration;
use oraclemcp_guard::scoped_grant::MAX_LIVE_SCOPED_GRANTS;
use oraclemcp_guard::{
    ClosureFingerprints, ColumnIdent, EffectiveCeiling, ExecGrantBinding, GrantComparison,
    GrantContainer, GrantLimits, GrantOp, GrantOperand, GrantPredicateV1, GrantState,
    GrantTargetIdentity, GrantValue, LastDdlTime, OperatingLevel, SCOPED_GRANT_TOKEN_SCOPE,
    ScopedGrant, ScopedGrantLookupError, ScopedGrantRequest, ScopedGrantStore, SignedGrantRef,
    SynonymIdentity,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

const KEY: [u8; 32] = [7; 32];
const OTHER_KEY: [u8; 32] = [8; 32];
/// Synthetic canary predicate value; must never surface in any rendering.
const CANARY: &str = "913377";

fn binding() -> ExecGrantBinding {
    ExecGrantBinding::new("sess-1", "lane-1", "subject-1", 1)
}

fn col(name: &str) -> ColumnIdent {
    ColumnIdent::new(name).unwrap()
}

fn num(value: &str) -> GrantValue {
    GrantValue::number(value).unwrap()
}

fn target() -> GrantTargetIdentity {
    GrantTargetIdentity {
        owner: "OMCP_FX_T141".into(),
        object_name: "ORDERS".into(),
        object_id: 74_001,
        data_object_id: Some(74_001),
        container: GrantContainer {
            con_id: 3,
            con_uid: 2_811_000_001,
        },
        edition: Some("ORA$BASE".into()),
        catalog_generation: CatalogGeneration(11),
        resolved_via: None,
    }
}

fn id_in(values: &[&str]) -> GrantPredicateV1 {
    GrantPredicateV1::new(vec![GrantComparison {
        column: col("ID"),
        op: GrantOp::In,
        operand: GrantOperand::List(values.iter().map(|v| num(v)).collect()),
    }])
}

/// The AC request: UPDATE ORDERS SET STATUS WHERE ID IN (101,102,103),
/// limits 5/20/20, ttl 600 s.
fn request() -> ScopedGrantRequest {
    ScopedGrantRequest {
        profile: "dev".into(),
        binding: binding(),
        verbs: vec!["UPDATE".into()],
        target: target(),
        columns: BTreeSet::from([col("STATUS")]),
        row_predicate: id_in(&["101", "102", "103"]),
        limits: GrantLimits {
            max_rows_per_statement: 5,
            max_statements: 20,
            max_total_rows: 20,
        },
        ttl: Duration::from_secs(600),
        commit_allowed: false,
        closure: ClosureFingerprints::new(),
        last_ddl_time: LastDdlTime::new("2026-09-01T10:00:00").unwrap(),
    }
}

fn rw_ceiling() -> EffectiveCeiling {
    EffectiveCeiling {
        profile_max_level: OperatingLevel::ReadWrite,
        oauth_ceiling: None,
    }
}

fn grant(req: ScopedGrantRequest) -> ScopedGrant {
    ScopedGrant::new(req, rw_ceiling(), false, &KEY).expect("valid grant")
}

fn refusal_code(req: ScopedGrantRequest) -> &'static str {
    ScopedGrant::new(req, rw_ceiling(), false, &KEY)
        .expect_err("must be refused")
        .code()
}

#[test]
fn scoped_grant_ac_request_has_a_stable_scope_digest() {
    let a = grant(request());
    let b = grant(request());
    assert_eq!(a.scope_digest(), b.scope_digest());
    assert_eq!(a.digests(), b.digests());
    assert_eq!(a.required_level(), OperatingLevel::ReadWrite);
    assert!(!a.commit_allowed());
    assert!(a.recheck_digests(&KEY));
    // Same input, different key: the keyed parts differ, the shape does not.
    let other = ScopedGrant::new(request(), rw_ceiling(), false, &OTHER_KEY).unwrap();
    assert_eq!(a.digests().shape, other.digests().shape);
    assert_ne!(a.digests().value_hmac, other.digests().value_hmac);
    assert_ne!(a.scope_digest(), other.scope_digest());
}

#[test]
fn scoped_grant_digest_changes_on_every_field() {
    type Mutation = (&'static str, bool, fn(&mut ScopedGrantRequest));
    // (name, is_value_only, mutation). Value-only mutations must keep the
    // non-secret shape digest and change only the keyed parts.
    let mutations: Vec<Mutation> = vec![
        ("profile", false, |r| r.profile = "prod".into()),
        ("binding.session_id", false, |r| {
            r.binding.session_id = "sess-2".into()
        }),
        ("binding.lane_id", false, |r| {
            r.binding.lane_id = "lane-2".into()
        }),
        ("binding.subject_id", false, |r| {
            r.binding.subject_id = "subject-2".into()
        }),
        ("binding.generation", false, |r| r.binding.generation = 2),
        ("verbs", false, |r| r.verbs.push("DELETE".into())),
        ("target.owner", false, |r| {
            r.target.owner = "OMCP_FX_OTHER".into()
        }),
        ("target.object_name", false, |r| {
            r.target.object_name = "ORDERS2".into()
        }),
        ("target.object_id", false, |r| r.target.object_id += 1),
        ("target.data_object_id", false, |r| {
            r.target.data_object_id = None
        }),
        ("target.container.con_id", false, |r| {
            r.target.container.con_id = 4
        }),
        ("target.container.con_uid", false, |r| {
            r.target.container.con_uid += 1
        }),
        ("target.edition", false, |r| r.target.edition = None),
        ("target.catalog_generation", false, |r| {
            r.target.catalog_generation = CatalogGeneration(12);
        }),
        ("target.resolved_via", false, |r| {
            r.target.resolved_via = Some(SynonymIdentity {
                owner: "PUBLIC".into(),
                name: "ORDERS".into(),
                object_id: 9,
            });
        }),
        ("columns", false, |r| {
            r.columns.insert(col("NOTE"));
        }),
        ("predicate.column", false, |r| {
            r.row_predicate = GrantPredicateV1::new(vec![GrantComparison {
                column: col("ORDER_ID"),
                op: GrantOp::In,
                operand: GrantOperand::List(vec![num("101"), num("102"), num("103")]),
            }]);
        }),
        ("predicate.op", false, |r| {
            r.row_predicate = GrantPredicateV1::new(vec![GrantComparison {
                column: col("ID"),
                op: GrantOp::Between,
                operand: GrantOperand::Range(num("101"), num("103")),
            }]);
        }),
        ("predicate.list_len", false, |r| {
            r.row_predicate = id_in(&["101", "102"])
        }),
        ("predicate.value_kind", false, |r| {
            r.row_predicate = GrantPredicateV1::new(vec![GrantComparison {
                column: col("ID"),
                op: GrantOp::In,
                operand: GrantOperand::List(vec![
                    GrantValue::text("101").unwrap(),
                    num("102"),
                    num("103"),
                ]),
            }]);
        }),
        ("predicate.extra_conjunct", false, |r| {
            let mut conjuncts = r.row_predicate.conjuncts().to_vec();
            conjuncts.push(GrantComparison {
                column: col("TENANT_ID"),
                op: GrantOp::Eq,
                operand: GrantOperand::Single(num("7")),
            });
            r.row_predicate = GrantPredicateV1::new(conjuncts);
        }),
        ("predicate.value", true, |r| {
            r.row_predicate = id_in(&["101", "102", "104"])
        }),
        ("predicate.value_order", true, |r| {
            r.row_predicate = id_in(&["103", "102", "101"]);
        }),
        ("limits.max_rows_per_statement", false, |r| {
            r.limits.max_rows_per_statement = 4;
        }),
        ("limits.max_statements", false, |r| {
            r.limits.max_statements = 21
        }),
        ("limits.max_total_rows", false, |r| {
            r.limits.max_total_rows = 21
        }),
        ("ttl", false, |r| r.ttl = Duration::from_secs(601)),
        ("ttl.subsec", false, |r| {
            r.ttl = Duration::from_millis(600_001)
        }),
        ("commit_allowed", false, |r| r.commit_allowed = true),
        ("closure", false, |r| {
            r.closure = ClosureFingerprints::from_fingerprints([[1; 32]]);
        }),
        ("last_ddl_time", false, |r| {
            r.last_ddl_time = LastDdlTime::new("2026-09-01T10:00:01").unwrap();
        }),
    ];
    let base = grant(request());
    let mut seen = BTreeSet::from([base.scope_digest()]);
    for (name, value_only, mutate) in mutations {
        let mut req = request();
        mutate(&mut req);
        let mutated = grant(req);
        assert_ne!(
            mutated.scope_digest(),
            base.scope_digest(),
            "scope_digest must change when {name} changes"
        );
        assert!(
            seen.insert(mutated.scope_digest()),
            "{name} collided with another mutation"
        );
        if value_only {
            assert_eq!(
                mutated.digests().shape,
                base.digests().shape,
                "{name}: a value-only change must not move the non-secret shape digest"
            );
            assert_ne!(mutated.digests().value_hmac, base.digests().value_hmac);
        } else {
            assert_ne!(
                mutated.digests().shape,
                base.digests().shape,
                "{name}: a structural change must move the shape digest"
            );
        }
    }
}

#[test]
fn scoped_grant_canonical_encoding_order_independent() {
    let mut a = request();
    a.verbs = vec!["UPDATE".into(), "DELETE".into()];
    a.columns = ["STATUS", "NOTE", "AMOUNT"].into_iter().map(col).collect();
    a.closure = ClosureFingerprints::from_fingerprints([[1; 32], [2; 32], [3; 32]]);

    let mut b = request();
    b.verbs = vec!["delete".into(), "  Update ".into(), "UPDATE".into()];
    let mut columns = BTreeSet::new();
    for name in ["AMOUNT", "STATUS", "NOTE"] {
        columns.insert(col(name));
    }
    b.columns = columns;
    b.closure = ClosureFingerprints::from_fingerprints([[3; 32], [1; 32], [2; 32], [1; 32]]);

    let (ga, gb) = (grant(a), grant(b));
    assert_eq!(ga.canonical_shape(), gb.canonical_shape());
    assert_eq!(ga.digests(), gb.digests());
}

#[test]
fn scoped_grant_rejects_insert_merge_and_multitable_verbs() {
    for verbs in [
        vec!["INSERT"],
        vec!["MERGE"],
        vec!["INSERT ALL"],
        vec!["insert   first"],
        vec!["UPDATE", "MERGE"],
        vec!["SELECT"],
    ] {
        let mut req = request();
        req.verbs = verbs.iter().map(|v| (*v).to_owned()).collect();
        assert_eq!(refusal_code(req), "GRANT_VERB_UNSUPPORTED", "{verbs:?}");
    }
    let mut req = request();
    req.verbs.clear();
    assert_eq!(refusal_code(req), "GRANT_VERB_UNSUPPORTED");
}

#[test]
fn scoped_grant_rejects_ttl_zero_and_over_3600() {
    for ttl in [
        Duration::ZERO,
        Duration::from_secs(3601),
        Duration::from_secs(3600) + Duration::from_millis(1),
    ] {
        let mut req = request();
        req.ttl = ttl;
        assert_eq!(refusal_code(req), "GRANT_TTL_INVALID", "{ttl:?}");
    }
    let mut req = request();
    req.ttl = Duration::from_secs(3600);
    grant(req);
}

#[test]
fn scoped_grant_rejects_protected_profile() {
    let err = ScopedGrant::new(request(), rw_ceiling(), true, &KEY).unwrap_err();
    assert_eq!(err.code(), "GRANT_PROTECTED_PROFILE");
    // Protected wins even when everything else is also wrong.
    let mut req = request();
    req.verbs = vec!["MERGE".into()];
    let admin = EffectiveCeiling {
        profile_max_level: OperatingLevel::Admin,
        oauth_ceiling: None,
    };
    assert_eq!(
        ScopedGrant::new(req, admin, true, &KEY).unwrap_err().code(),
        "GRANT_PROTECTED_PROFILE"
    );
}

#[test]
fn scoped_grant_rejects_level_above_profile_or_oauth_ceiling() {
    let refused = [
        (OperatingLevel::ReadOnly, None),
        (OperatingLevel::ReadOnly, Some(OperatingLevel::Admin)),
        (OperatingLevel::Admin, Some(OperatingLevel::ReadOnly)),
    ];
    for (profile_max_level, oauth_ceiling) in refused {
        let ceiling = EffectiveCeiling {
            profile_max_level,
            oauth_ceiling,
        };
        let err = ScopedGrant::new(request(), ceiling, false, &KEY).unwrap_err();
        assert_eq!(err.code(), "GRANT_ABOVE_CEILING", "{ceiling:?}");
    }
    let admitted = [
        (OperatingLevel::ReadWrite, None),
        (OperatingLevel::Admin, Some(OperatingLevel::ReadWrite)),
        (OperatingLevel::Ddl, Some(OperatingLevel::Admin)),
    ];
    for (profile_max_level, oauth_ceiling) in admitted {
        let ceiling = EffectiveCeiling {
            profile_max_level,
            oauth_ceiling,
        };
        let granted = ScopedGrant::new(request(), ceiling, false, &KEY).unwrap();
        // Never more than READ_WRITE, whatever the ceiling allows.
        assert_eq!(granted.required_level(), OperatingLevel::ReadWrite);
    }
}

#[test]
fn scoped_grant_rejects_set_of_predicate_column() {
    let mut req = request();
    req.columns.insert(col("ID"));
    assert_eq!(refusal_code(req), "GRANT_SET_PREDICATE_COLUMN");
}

#[test]
fn scoped_grant_rejects_incoherent_shapes() {
    let mut req = request();
    req.columns.clear();
    assert_eq!(refusal_code(req), "GRANT_UPDATE_WITHOUT_COLUMNS");

    let mut req = request();
    req.verbs = vec!["DELETE".into()];
    assert_eq!(refusal_code(req), "GRANT_DELETE_WITH_COLUMNS");
    let mut req = request();
    req.verbs = vec!["DELETE".into()];
    req.columns.clear();
    grant(req);

    let mut req = request();
    req.row_predicate = GrantPredicateV1::new(vec![]);
    assert_eq!(refusal_code(req), "GRANT_PREDICATE_EMPTY");

    let mut req = request();
    req.row_predicate = id_in(&[]);
    assert_eq!(refusal_code(req), "GRANT_PREDICATE_MALFORMED");
    let mut req = request();
    req.row_predicate = GrantPredicateV1::new(vec![GrantComparison {
        column: col("ID"),
        op: GrantOp::Eq,
        operand: GrantOperand::List(vec![num("1")]),
    }]);
    assert_eq!(refusal_code(req), "GRANT_PREDICATE_MALFORMED");

    for (limits, code) in [
        ((0, 20, 20), "GRANT_LIMIT_ZERO"),
        ((5, 0, 20), "GRANT_LIMIT_ZERO"),
        ((5, 20, 0), "GRANT_LIMIT_ZERO"),
        ((21, 20, 20), "GRANT_LIMIT_INCOHERENT"),
    ] {
        let mut req = request();
        req.limits = GrantLimits {
            max_rows_per_statement: limits.0,
            max_statements: limits.1,
            max_total_rows: limits.2,
        };
        assert_eq!(refusal_code(req), code, "{limits:?}");
    }
}

fn tenant_request(tenant: &str) -> ScopedGrantRequest {
    let mut req = request();
    req.row_predicate = GrantPredicateV1::new(vec![GrantComparison {
        column: col("TENANT_ID"),
        op: GrantOp::Eq,
        operand: GrantOperand::Single(num(tenant)),
    }]);
    req
}

/// The strawman the round-5 finding rejected: SHA-256 over the full canonical
/// scope *including* the raw predicate value, no key. `prefix` is a hasher
/// already fed the (value-independent) shape, cloned per candidate so the
/// million-entry dictionary stays fast in debug builds.
fn plain_sha256_scope(prefix: &Sha256, tenant: &str) -> [u8; 32] {
    let mut hasher = prefix.clone();
    hasher.update(b"NUMBER");
    hasher.update(tenant.as_bytes());
    hasher.finalize().into()
}

#[test]
fn scoped_grant_value_hmac_resists_dictionary() {
    const SECRET_TENANT: &str = "424242";
    let victim = grant(tenant_request(SECRET_TENANT));
    // What an offline attacker holds: the audited binding digest and the
    // non-secret shape (both appear in status/audit output).
    let audited_binding = victim.scope_digest();
    let status = serde_json::to_string(&victim.status()).unwrap();
    assert!(status.contains(&oraclemcp_guard::scoped_grant::hex(&audited_binding)));
    let mut shape_prefix = Sha256::new();
    shape_prefix.update(victim.canonical_shape());
    let mut digest_prefix = Sha256::new();
    digest_prefix.update(victim.digests().shape);

    // Control: had the scope digest been plain SHA-256, a dictionary over
    // 0..1_000_000 recovers the tenant id. This is the failure mode the keyed
    // split exists to prevent.
    let plain_audited = plain_sha256_scope(&shape_prefix, SECRET_TENANT);
    let recovered = (0u32..1_000_000)
        .map(|t| t.to_string())
        .find(|t| plain_sha256_scope(&shape_prefix, t) == plain_audited);
    assert_eq!(recovered.as_deref(), Some(SECRET_TENANT));

    // The same SHA-256 dictionary against the keyed binding digest, over both
    // the canonical structure and the published shape digest: no hit.
    let sha_hit = (0u32..1_000_000).any(|t| {
        let candidate = t.to_string();
        plain_sha256_scope(&shape_prefix, &candidate) == audited_binding
            || plain_sha256_scope(&digest_prefix, &candidate) == audited_binding
    });
    assert!(
        !sha_hit,
        "an unkeyed dictionary reproduced the binding digest"
    );

    // A wrong-key attacker running the real construction path, over a window
    // that contains the true value: no candidate reproduces the digest, and
    // the shape is identical for every candidate (it carries no value).
    for t in 419_242u32..=429_242 {
        let candidate = t.to_string();
        let guess =
            ScopedGrant::new(tenant_request(&candidate), rw_ceiling(), false, &OTHER_KEY).unwrap();
        assert_ne!(guess.scope_digest(), audited_binding, "{candidate}");
        assert_eq!(guess.digests().shape, victim.digests().shape);
    }
}

#[test]
fn scoped_grant_value_canary_absent_from_debug_status_serde() {
    let mut req = request();
    req.row_predicate = GrantPredicateV1::new(vec![
        GrantComparison {
            column: col("TENANT_ID"),
            op: GrantOp::Eq,
            operand: GrantOperand::Single(num(CANARY)),
        },
        GrantComparison {
            column: col("REGION"),
            op: GrantOp::Between,
            operand: GrantOperand::Range(
                GrantValue::text(format!("R{CANARY}")).unwrap(),
                GrantValue::text(format!("S{CANARY}")).unwrap(),
            ),
        },
    ]);
    let granted = grant(req.clone());
    let store = ScopedGrantStore::new();
    let id = store.issue(granted.clone()).unwrap();

    let mut renderings = vec![
        format!("{granted:?}"),
        format!("{req:?}"),
        granted.row_predicate().to_string(),
        format!("{:?}", granted.row_predicate()),
        serde_json::to_string(&granted.status()).unwrap(),
        serde_json::to_string(granted.row_predicate()).unwrap(),
        format!("{:?}", granted.status()),
        format!("{:?}", store.list_for_binding(&binding())),
        format!("{:?}", store.get(&id, &binding()).unwrap()),
    ];
    // Error text of refusals raised on a request carrying the canary.
    for mutate in [
        |r: &mut ScopedGrantRequest| r.columns.insert(col("TENANT_ID")).then_some(()).unwrap(),
        |r: &mut ScopedGrantRequest| r.verbs = vec!["MERGE".into()],
        |r: &mut ScopedGrantRequest| r.ttl = Duration::ZERO,
    ] {
        let mut bad = req.clone();
        mutate(&mut bad);
        let err = ScopedGrant::new(bad, rw_ceiling(), false, &KEY).unwrap_err();
        renderings.push(err.to_string());
        renderings.push(format!("{err:?}"));
    }
    let bad_value = GrantValue::number(format!("{CANARY}.0")).unwrap_err();
    renderings.push(bad_value.to_string());
    renderings.push(format!("{bad_value:?}"));

    for rendering in &renderings {
        assert!(
            !rendering.contains(CANARY),
            "canary leaked into: {rendering}"
        );
    }
    assert!(renderings[2].contains("<redacted:NUMBER>"));
    assert!(renderings[2].contains("<redacted:TEXT>"));
}

#[test]
fn scoped_grant_dies_on_generation_change_drop_and_ttl() {
    let store = ScopedGrantStore::new();
    let b = binding();

    // Minting binding finds it; foreign session/lane/subject never do.
    let id = store.issue(grant(request())).unwrap();
    assert!(store.get(&id, &b).is_ok());
    for (other, expected) in [
        (
            ExecGrantBinding::new("sess-2", "lane-1", "subject-1", 1),
            ScopedGrantLookupError::SessionMismatch,
        ),
        (
            ExecGrantBinding::new("sess-1", "lane-2", "subject-1", 1),
            ScopedGrantLookupError::LaneMismatch,
        ),
        (
            ExecGrantBinding::new("sess-1", "lane-1", "subject-2", 1),
            ScopedGrantLookupError::SubjectMismatch,
        ),
    ] {
        assert_eq!(store.get(&id, &other).unwrap_err(), expected);
        assert!(store.drop_grant(&id, &other).is_err());
    }
    assert!(
        store.get(&id, &b).is_ok(),
        "foreign probes must not kill it"
    );

    // Generation change via the lane hook (reconnect / profile switch).
    assert_eq!(store.invalidate_generation("sess-1", "lane-1", 2), 1);
    assert_eq!(
        store.get(&id, &b).unwrap_err(),
        ScopedGrantLookupError::Revoked
    );

    // Generation change observed at lookup: the newer lane kills the grant.
    let id = store.issue(grant(request())).unwrap();
    let newer = ExecGrantBinding::new("sess-1", "lane-1", "subject-1", 2);
    assert_eq!(
        store.get(&id, &newer).unwrap_err(),
        ScopedGrantLookupError::GenerationMismatch {
            presented: 2,
            granted: 1
        }
    );
    assert_eq!(
        store.get(&id, &b).unwrap_err(),
        ScopedGrantLookupError::Revoked
    );

    // Explicit drop.
    let id = store.issue(grant(request())).unwrap();
    store.drop_grant(&id, &b).unwrap();
    assert_eq!(
        store.get(&id, &b).unwrap_err(),
        ScopedGrantLookupError::Revoked
    );
    assert_eq!(
        store.drop_grant(&id, &b).unwrap_err(),
        ScopedGrantLookupError::Revoked
    );

    // Suspension blocks use.
    let id = store.issue(grant(request())).unwrap();
    store
        .suspend(
            &id,
            oraclemcp_guard::scoped_grant::SuspendReason::TargetDrift,
        )
        .unwrap();
    assert!(matches!(
        store.get(&id, &b).unwrap_err(),
        ScopedGrantLookupError::Suspended { .. }
    ));

    // TTL.
    let mut short = request();
    short.ttl = Duration::from_millis(30);
    let id = store.issue(grant(short)).unwrap();
    assert!(store.get(&id, &b).is_ok());
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        store.get(&id, &b).unwrap_err(),
        ScopedGrantLookupError::Expired
    );
    assert!(
        store
            .list_for_binding(&b)
            .iter()
            .any(|row| row.id == id && row.state == GrantState::Expired)
    );
    assert!(store.purge_expired() >= 1);
    assert_eq!(
        store.get(&id, &b).unwrap_err(),
        ScopedGrantLookupError::Unknown
    );
    assert_eq!(
        store.get("sgrant-never", &b).unwrap_err(),
        ScopedGrantLookupError::Unknown
    );
}

#[test]
fn scoped_grant_store_refuses_when_full_without_evicting_live_grants() {
    let store = ScopedGrantStore::new();
    let template = grant(request());
    let ids = (0..MAX_LIVE_SCOPED_GRANTS)
        .map(|_| store.issue(template.clone()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        store.issue(template.clone()).unwrap_err(),
        ScopedGrantLookupError::StoreFull
    );
    assert!(store.get(&ids[0], &binding()).is_ok());
    // A tombstone frees a slot.
    store.drop_grant(&ids[0], &binding()).unwrap();
    assert!(store.issue(template).is_ok());
}

#[test]
fn scoped_grant_key_rotation_invalidates_all_refs() {
    let store = ScopedGrantStore::new();
    let b = binding();
    let refs = (0..3)
        .map(|i| {
            let mut req = request();
            req.row_predicate = id_in(&[&(100 + i).to_string()]);
            let granted = grant(req);
            let digest = granted.scope_digest();
            let id = store.issue(granted).unwrap();
            (
                id.clone(),
                digest,
                SignedGrantRef::sign(&KEY, &id, &b, &digest),
            )
        })
        .collect::<Vec<_>>();
    for (id, digest, signed) in &refs {
        assert_eq!(
            signed.verify(&KEY, &b, digest).as_deref(),
            Some(id.as_str())
        );
        assert_eq!(signed.verify(&OTHER_KEY, &b, digest), None);
        let held = store.get(id, &b).unwrap();
        assert!(held.recheck_digests(&KEY));
        assert!(!held.recheck_digests(&OTHER_KEY));
    }
    // Rotation (restart) revokes every live grant.
    assert_eq!(store.revoke_all(), 3);
    for (id, _, _) in &refs {
        assert_eq!(
            store.get(id, &b).unwrap_err(),
            ScopedGrantLookupError::Revoked
        );
    }
}

#[test]
fn scoped_grant_ref_binds_lane_and_scope_digest() {
    let granted = grant(request());
    let digest = granted.scope_digest();
    let signed = SignedGrantRef::sign(&KEY, "sgrant-1-0", &binding(), &digest);
    assert_eq!(signed.grant_id_unverified(), Some("sgrant-1-0"));
    let newer = ExecGrantBinding::new("sess-1", "lane-1", "subject-1", 2);
    assert_eq!(signed.verify(&KEY, &newer, &digest), None);
    let other_digest = grant(tenant_request("7")).scope_digest();
    assert_eq!(signed.verify(&KEY, &binding(), &other_digest), None);
    // An edited id keeps a well-formed shape but fails the MAC.
    let forged = SignedGrantRef::from_client(signed.as_str().replace("sgrant-1-0", "sgrant-1-1"));
    assert_eq!(forged.verify(&KEY, &binding(), &digest), None);
}

// A byte-exact replica of the execute-confirmation token wire format
// (`oraclemcp_core::tamper_token::{sign_token, verify_token}` with scope
// `grant:execute`, as used by `dispatch::sign_execute_grant_reference`). The
// guard crate cannot depend on core (core depends on guard), so the replica
// lets this test use the *same key* for both token kinds — the strongest form
// of the non-interchangeability claim.
fn execute_token_mac(key: &[u8; 32], scope: &str, payload: &str, fields: &[&str]) -> String {
    let mut message = Vec::new();
    let mut push = |part: &[u8]| {
        message.extend_from_slice(&(part.len() as u64).to_le_bytes());
        message.extend_from_slice(part);
    };
    push(b"oraclemcp:tamper-token:v1");
    push(scope.as_bytes());
    push(payload.as_bytes());
    for field in fields {
        push(field.as_bytes());
    }
    oraclemcp_guard::scoped_grant::hex(&hmac_sha256(key, &message)[..8])
}

fn execute_fields(b: &ExecGrantBinding) -> Vec<String> {
    vec![
        "dev".into(),
        b.session_id.clone(),
        b.lane_id.clone(),
        b.subject_id.clone(),
        b.generation.to_string(),
        OperatingLevel::ReadWrite.as_str().into(),
    ]
}

fn sign_execute(key: &[u8; 32], grant_id: &str, b: &ExecGrantBinding) -> String {
    let fields = execute_fields(b);
    let refs = fields.iter().map(String::as_str).collect::<Vec<_>>();
    format!(
        "{grant_id}.{}",
        execute_token_mac(key, "grant:execute", grant_id, &refs)
    )
}

fn verify_execute(key: &[u8; 32], token: &str, b: &ExecGrantBinding) -> Option<String> {
    let (payload, tag) = token.rsplit_once('.')?;
    if tag.len() != 16 {
        return None;
    }
    let fields = execute_fields(b);
    let refs = fields.iter().map(String::as_str).collect::<Vec<_>>();
    (execute_token_mac(key, "grant:execute", payload, &refs) == tag).then(|| payload.to_owned())
}

#[test]
fn scoped_grant_ref_not_interchangeable_with_execute_token() {
    assert_eq!(SCOPED_GRANT_TOKEN_SCOPE, "grant:scoped");
    assert_ne!(SCOPED_GRANT_TOKEN_SCOPE, "grant:execute");
    let b = binding();
    let digest = grant(request()).scope_digest();
    let grant_id = "xgrant-1-0";

    let execute = sign_execute(&KEY, grant_id, &b);
    // The replica round-trips, so the negatives below are not vacuous.
    assert_eq!(
        verify_execute(&KEY, &execute, &b).as_deref(),
        Some(grant_id)
    );
    let scoped = SignedGrantRef::sign(&KEY, grant_id, &b, &digest);
    assert_eq!(scoped.verify(&KEY, &b, &digest).as_deref(), Some(grant_id));

    // execute -> scoped: refused, raw and with the scoped prefix grafted on.
    assert_eq!(
        SignedGrantRef::from_client(execute.clone()).verify(&KEY, &b, &digest),
        None
    );
    assert_eq!(
        SignedGrantRef::from_client(format!("sgr1.{execute}")).verify(&KEY, &b, &digest),
        None
    );
    // scoped -> execute: refused, raw and with the prefix stripped.
    assert_eq!(verify_execute(&KEY, scoped.as_str(), &b), None);
    let stripped = scoped.as_str().trim_start_matches("sgr1.");
    assert_eq!(verify_execute(&KEY, stripped, &b), None);
    let truncated = format!("{grant_id}.{}", &stripped[stripped.len() - 16..]);
    assert_eq!(verify_execute(&KEY, &truncated, &b), None);
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Fields {
    profile: u8,
    generation: u64,
    object_id: u64,
    edition: Option<u8>,
    extra_column: bool,
    value: u16,
    op_between: bool,
    rows: (u64, u64, u64),
    ttl_secs: u64,
    commit: bool,
    closure: Option<u8>,
}

fn build(f: &Fields) -> ScopedGrant {
    let mut req = request();
    req.profile = format!("p{}", f.profile);
    req.binding.generation = f.generation;
    req.target.object_id = f.object_id;
    req.target.edition = f.edition.map(|e| format!("E{e}"));
    if f.extra_column {
        req.columns.insert(col("NOTE"));
    }
    let value = f.value.to_string();
    req.row_predicate = GrantPredicateV1::new(vec![GrantComparison {
        column: col("ID"),
        op: if f.op_between {
            GrantOp::Between
        } else {
            GrantOp::Eq
        },
        operand: if f.op_between {
            GrantOperand::Range(num(&value), num(&value))
        } else {
            GrantOperand::Single(num(&value))
        },
    }]);
    req.limits = GrantLimits {
        max_rows_per_statement: f.rows.0,
        max_statements: f.rows.1,
        max_total_rows: f.rows.0 + f.rows.2,
    };
    req.ttl = Duration::from_secs(f.ttl_secs);
    req.commit_allowed = f.commit;
    req.closure = ClosureFingerprints::from_fingerprints(f.closure.map(|c| [c; 32]));
    grant(req)
}

fn fields() -> impl Strategy<Value = Fields> {
    (
        0u8..2,
        0u64..3,
        0u64..3,
        proptest::option::of(0u8..2),
        any::<bool>(),
        0u16..4,
        any::<bool>(),
        (1u64..3, 1u64..3, 0u64..2),
        1u64..3,
        any::<bool>(),
        proptest::option::of(0u8..2),
    )
        .prop_map(
            |(
                profile,
                generation,
                object_id,
                edition,
                extra_column,
                value,
                op_between,
                rows,
                ttl_secs,
                commit,
                closure,
            )| Fields {
                profile,
                generation,
                object_id,
                edition,
                extra_column,
                value,
                op_between,
                rows,
                ttl_secs,
                commit,
                closure,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_scope_digest_injective_over_fields(a in fields(), b in fields()) {
        let (ga, gb) = (build(&a), build(&b));
        prop_assert_eq!(a == b, ga.scope_digest() == gb.scope_digest());
        prop_assert_eq!(a == b, ga.canonical_shape() == gb.canonical_shape()
            && ga.digests().value_hmac == gb.digests().value_hmac);
    }
}
