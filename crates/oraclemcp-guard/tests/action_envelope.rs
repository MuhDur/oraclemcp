use oraclemcp_guard::{
    ActionEnvelopeV1, ActionKind, BindEnvelope, CanonicalBind, ExecLimits, OperatingLevel,
    OutputCapture, bind_value_hmac, canonical_binds,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

fn sample() -> ActionEnvelopeV1 {
    let binds = [
        CanonicalBind::I64(42),
        CanonicalBind::String("synthetic-canary"),
    ];
    ActionEnvelopeV1 {
        version: 1,
        action_kind: ActionKind::ExecuteDml,
        statement_digest: ActionEnvelopeV1::statement_digest("UPDATE t SET v = :1 WHERE id = :2"),
        binds: BindEnvelope::from_binds(&[7; 32], &binds),
        commit: false,
        hold: false,
        output: OutputCapture {
            capture_dbms_output: false,
            max_lines: 100,
            max_chars: 1000,
        },
        limits: ExecLimits {
            timeout_seconds: None,
        },
        scoped_grant_ref: None,
    }
}

#[test]
fn envelope_canonical_encoding_deterministic() {
    let first = sample();
    let second = sample();
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.digest(), second.digest());
    assert!(!format!("{first:?}").contains("synthetic-canary"));
}

#[test]
fn envelope_digest_changes_on_each_field() {
    let base = sample();
    let base_digest = base.digest();
    let mut variants = Vec::new();
    let mut changed = base.clone();
    changed.version = 2;
    variants.push(changed);
    let mut changed = base.clone();
    changed.action_kind = ActionKind::SetSessionLevel {
        level: OperatingLevel::Ddl,
        ttl: 30,
    };
    variants.push(changed);
    let mut changed = base.clone();
    changed.statement_digest = ActionEnvelopeV1::statement_digest("UPDATE other SET v = :1");
    variants.push(changed);
    let mut changed = base.clone();
    changed.binds = BindEnvelope::from_binds(&[7; 32], &[CanonicalBind::I64(43)]);
    variants.push(changed);
    let mut changed = base.clone();
    changed.commit = true;
    variants.push(changed);
    let mut changed = base.clone();
    changed.hold = true;
    variants.push(changed);
    let mut changed = base.clone();
    changed.output.capture_dbms_output = true;
    variants.push(changed);
    let mut changed = base.clone();
    changed.output.max_lines += 1;
    variants.push(changed);
    let mut changed = base.clone();
    changed.output.max_chars += 1;
    variants.push(changed);
    let mut changed = base.clone();
    changed.limits.timeout_seconds = Some(5);
    variants.push(changed);
    let mut changed = base.clone();
    changed.scoped_grant_ref = Some(ActionEnvelopeV1::reference_digest("sgr1.synthetic"));
    variants.push(changed);
    for variant in variants {
        assert_ne!(variant.digest(), base_digest);
    }
}

#[test]
fn bind_hmac_domain_separated() {
    let canonical = canonical_binds(&[CanonicalBind::I64(42)]);
    let key = [3; 32];
    let bound = bind_value_hmac(&key, &canonical);
    assert_ne!(bound, oraclemcp_audit::hmac_sha256(&key, &canonical));
    assert_ne!(bound, bind_value_hmac(&[4; 32], &canonical));
}

#[test]
fn bind_hmac_dictionary_attack_fails() {
    let key = [9; 32];
    let target = canonical_binds(&[CanonicalBind::I64(42_424)]);
    let recorded = bind_value_hmac(&key, &target);
    for id in 0..100_000 {
        let guess = canonical_binds(&[CanonicalBind::I64(id)]);
        let plain_sha: [u8; 32] = Sha256::digest(&*guess).into();
        assert_ne!(plain_sha, recorded);
        assert_ne!(bind_value_hmac(&[8; 32], &guess), recorded);
    }
}

#[test]
fn bind_canonical_buffer_zeroized() {
    let mut canonical = canonical_binds(&[CanonicalBind::String("synthetic-secret")]);
    assert!(
        canonical
            .windows(16)
            .any(|window| window == b"synthetic-secret")
    );
    canonical.zeroize();
    assert!(canonical.iter().all(|byte| *byte == 0));
}

proptest! {
    #[test]
    fn prop_envelope_injective(value in any::<i64>(), other in any::<i64>()) {
        prop_assume!(value != other);
        let mut first = sample();
        let mut second = sample();
        first.binds = BindEnvelope::from_binds(&[7; 32], &[CanonicalBind::I64(value)]);
        second.binds = BindEnvelope::from_binds(&[7; 32], &[CanonicalBind::I64(other)]);
        prop_assert_ne!(first.canonical_bytes(), second.canonical_bytes());
        prop_assert_ne!(first.digest(), second.digest());
    }
}
