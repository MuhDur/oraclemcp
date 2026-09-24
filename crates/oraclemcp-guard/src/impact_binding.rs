//! Versioned impact facts for previews and later apply-time comparison.
//!
//! Only `decisive` enters the digest. Observations are display and audit data;
//! a changing SCN or cost estimate cannot silently invalidate a grant.

use std::{collections::BTreeMap, future::Future, time::Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const IMPACT_DOMAIN: &[u8] = b"omcp/impact-binding/decisive/v1";
pub const IMPACT_BINDING_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    LevelBelowRequired,
    UntrustedTriggers,
    UnsupportedDmlShape,
    EngineNotWired,
    ReadOnlyTxn,
    HardParseCallbacks,
    Vpd,
    NoPrivilege,
    PlanTableUnverified,
    Timeout,
    Truncated,
    NotWired,
}

impl UnavailableReason {
    const fn tag(self) -> u8 {
        match self {
            Self::LevelBelowRequired => 1,
            Self::UntrustedTriggers => 2,
            Self::UnsupportedDmlShape => 3,
            Self::EngineNotWired => 4,
            Self::ReadOnlyTxn => 5,
            Self::HardParseCallbacks => 6,
            Self::Vpd => 7,
            Self::NoPrivilege => 8,
            Self::PlanTableUnverified => 9,
            Self::Timeout => 10,
            Self::Truncated => 11,
            Self::NotWired => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotApplicableReason {
    NotDml,
    NoObject,
    NoSource,
    NoEffect,
}

impl NotApplicableReason {
    const fn tag(self) -> u8 {
        match self {
            Self::NotDml => 1,
            Self::NoObject => 2,
            Self::NoSource => 3,
            Self::NoEffect => 4,
        }
    }
}

/// A field is always present. Unavailable and inapplicable have closed,
/// machine-readable reasons rather than a missing or null value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FieldStatus<T> {
    Computed { value: T },
    Estimated { value: T },
    Unavailable { reason: UnavailableReason },
    NotApplicable { reason: NotApplicableReason },
}

impl<T> FieldStatus<T> {
    #[must_use]
    pub const fn not_wired() -> Self {
        Self::Unavailable {
            reason: UnavailableReason::NotWired,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObjectFact {
    pub identity: FieldStatus<String>,
    pub status: FieldStatus<String>,
    pub source_hash: FieldStatus<[u8; 32]>,
    pub dependency_hash: FieldStatus<[u8; 32]>,
    pub trigger_hash: FieldStatus<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DbIdentity {
    pub dbid: u64,
    pub con_uid: u64,
}

/// Facts that must be rechecked against the same identity before execution.
/// The envelope digest already includes the keyed bind HMAC; `bind_hmac`
/// remains explicit so a preview can show its status without exposing values.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecisiveFacts {
    pub envelope_digest: FieldStatus<[u8; 32]>,
    pub statement_digest: FieldStatus<[u8; 32]>,
    pub bind_hmac: FieldStatus<[u8; 32]>,
    pub objects: FieldStatus<Vec<ObjectFact>>,
    pub edition: FieldStatus<String>,
    pub compiler_facts: FieldStatus<String>,
    pub engine_version: FieldStatus<String>,
    pub ruleset_digest: FieldStatus<[u8; 32]>,
    pub db_identity: FieldStatus<DbIdentity>,
    pub current_schema: FieldStatus<String>,
    pub profile_generation: FieldStatus<u64>,
    pub lane_generation: FieldStatus<u64>,
    /// Opaque until W13 supplies its own typed scope fingerprint.
    pub scope_digest: FieldStatus<Option<[u8; 32]>>,
}

impl Default for DecisiveFacts {
    fn default() -> Self {
        Self {
            envelope_digest: FieldStatus::not_wired(),
            statement_digest: FieldStatus::not_wired(),
            bind_hmac: FieldStatus::not_wired(),
            objects: FieldStatus::not_wired(),
            edition: FieldStatus::not_wired(),
            compiler_facts: FieldStatus::not_wired(),
            engine_version: FieldStatus::not_wired(),
            ruleset_digest: FieldStatus::not_wired(),
            db_identity: FieldStatus::not_wired(),
            current_schema: FieldStatus::not_wired(),
            profile_generation: FieldStatus::not_wired(),
            lane_generation: FieldStatus::not_wired(),
            scope_digest: FieldStatus::not_wired(),
        }
    }
}

/// An AS OF observation has one SCN; an ordinary query has a before/after
/// window. The two shapes cannot serialize as one another.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScnBounds {
    AsOf { observed_at_scn: u64 },
    Window { scn_before: u64, scn_after: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowEstimateKind {
    Estimated,
    Observed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RowEstimate {
    pub kind: RowEstimateKind,
    pub value: u64,
    pub scn: ScnBounds,
    pub profile_generation: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Observations {
    pub rows: Option<RowEstimate>,
    pub cost: Option<Value>,
    pub timings: BTreeMap<String, u64>,
    pub statuses: BTreeMap<String, FieldStatus<()>>,
    pub scn_bounds: Option<ScnBounds>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImpactBindingV1 {
    pub version: u8,
    pub decisive: DecisiveFacts,
    pub observations: Observations,
}

impl Default for ImpactBindingV1 {
    fn default() -> Self {
        Self {
            version: IMPACT_BINDING_VERSION,
            decisive: DecisiveFacts::default(),
            observations: Observations::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("unsupported impact binding version {found}")]
pub struct ImpactVersionError {
    pub found: u8,
}

impl ImpactBindingV1 {
    /// SHA-256 of the length-prefixed, domain-separated decisive facts only.
    /// All statuses and reasons are encoded, including unavailable fields.
    pub fn decisive_digest(&self) -> Result<[u8; 32], ImpactVersionError> {
        if self.version != IMPACT_BINDING_VERSION {
            return Err(ImpactVersionError {
                found: self.version,
            });
        }
        let mut out = Vec::new();
        put_bytes(&mut out, IMPACT_DOMAIN);
        out.push(self.version);
        self.decisive.encode(&mut out);
        Ok(Sha256::digest(out).into())
    }
}

/// User-visible impact. Every field is serialized even when no computation
/// is wired yet. T14.2-T14.5 replace the corresponding statuses.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImpactV1 {
    pub binding: ImpactBindingV1,
    pub rows: FieldStatus<RowEstimate>,
    pub dependents: FieldStatus<Value>,
    pub effects: FieldStatus<Value>,
    pub sast: FieldStatus<Value>,
    pub cost: FieldStatus<Value>,
    pub locks: FieldStatus<Value>,
    pub reversibility: FieldStatus<Value>,
}

impl Default for ImpactV1 {
    fn default() -> Self {
        Self {
            binding: ImpactBindingV1::default(),
            rows: FieldStatus::not_wired(),
            dependents: FieldStatus::not_wired(),
            effects: FieldStatus::not_wired(),
            sast: FieldStatus::not_wired(),
            cost: FieldStatus::not_wired(),
            locks: FieldStatus::not_wired(),
            reversibility: FieldStatus::not_wired(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldCaps {
    pub max_depth: usize,
    pub max_count: usize,
}

pub struct FieldMeasure<T> {
    pub value: T,
    pub depth: usize,
    pub count: usize,
}

pub struct FieldBudget;

impl FieldBudget {
    /// Bound one asynchronous field computation. Its worker must also check
    /// caps while traversing; this final check prevents a computed status if
    /// it exceeded them. Expiry drops the future and returns a typed refusal.
    pub async fn run<T, F>(deadline: Instant, caps: FieldCaps, future: F) -> FieldStatus<T>
    where
        F: Future<Output = FieldMeasure<T>>,
    {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return FieldStatus::Unavailable {
                reason: UnavailableReason::Timeout,
            };
        }
        match asupersync::time::timeout(asupersync::time::wall_now(), remaining, future).await {
            Ok(measure) if measure.depth > caps.max_depth || measure.count > caps.max_count => {
                FieldStatus::Unavailable {
                    reason: UnavailableReason::Truncated,
                }
            }
            Ok(measure) => FieldStatus::Computed {
                value: measure.value,
            },
            Err(_) => FieldStatus::Unavailable {
                reason: UnavailableReason::Timeout,
            },
        }
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn put_text(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}

fn put_status<T>(out: &mut Vec<u8>, status: &FieldStatus<T>, encode: impl Fn(&mut Vec<u8>, &T)) {
    match status {
        FieldStatus::Computed { value } => {
            out.push(1);
            encode(out, value);
        }
        FieldStatus::Estimated { value } => {
            out.push(2);
            encode(out, value);
        }
        FieldStatus::Unavailable { reason } => out.extend_from_slice(&[3, reason.tag()]),
        FieldStatus::NotApplicable { reason } => out.extend_from_slice(&[4, reason.tag()]),
    }
}

impl DecisiveFacts {
    fn encode(&self, out: &mut Vec<u8>) {
        put_status(out, &self.envelope_digest, |out, v| put_bytes(out, v));
        put_status(out, &self.statement_digest, |out, v| put_bytes(out, v));
        put_status(out, &self.bind_hmac, |out, v| put_bytes(out, v));
        put_status(out, &self.objects, |out, objects| {
            out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
            let mut encoded_objects = Vec::with_capacity(objects.len());
            for object in objects {
                let mut encoded = Vec::new();
                put_status(&mut encoded, &object.identity, |out, v| put_text(out, v));
                put_status(&mut encoded, &object.status, |out, v| put_text(out, v));
                put_status(&mut encoded, &object.source_hash, |out, v| {
                    put_bytes(out, v)
                });
                put_status(&mut encoded, &object.dependency_hash, |out, v| {
                    put_bytes(out, v)
                });
                put_status(&mut encoded, &object.trigger_hash, |out, v| {
                    put_bytes(out, v)
                });
                encoded_objects.push(encoded);
            }
            encoded_objects.sort_unstable();
            for encoded in encoded_objects {
                put_bytes(out, &encoded);
            }
        });
        put_status(out, &self.edition, |out, v| put_text(out, v));
        put_status(out, &self.compiler_facts, |out, v| put_text(out, v));
        put_status(out, &self.engine_version, |out, v| put_text(out, v));
        put_status(out, &self.ruleset_digest, |out, v| put_bytes(out, v));
        put_status(out, &self.db_identity, |out, v| {
            out.extend_from_slice(&v.dbid.to_be_bytes());
            out.extend_from_slice(&v.con_uid.to_be_bytes());
        });
        put_status(out, &self.current_schema, |out, v| put_text(out, v));
        put_status(out, &self.profile_generation, |out, v| {
            out.extend_from_slice(&v.to_be_bytes());
        });
        put_status(out, &self.lane_generation, |out, v| {
            out.extend_from_slice(&v.to_be_bytes());
        });
        put_status(out, &self.scope_digest, |out, v| match v {
            Some(digest) => {
                out.push(1);
                put_bytes(out, digest);
            }
            None => out.push(0),
        });
    }
}
