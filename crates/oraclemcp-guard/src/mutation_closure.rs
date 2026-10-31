//! Canonical evidence for every mechanism a resolved DML operation can invoke.
//!
//! This is collector output, not execution authority. Consumers must recollect
//! and compare the digest at apply, then use the shared effect admission rule.

use std::collections::BTreeSet;
use std::fmt::Write;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::OperatingLevel;
use crate::purity::{AdmissionContext, EffectRefusal, RoutineEffect, RoutineEffectsV1, admit};

/// Oracle operation whose implicit effects are collected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationStatementKind {
    Insert,
    Update,
    Delete,
    /// Conservatively includes INSERT, UPDATE and a matched DELETE clause.
    Merge,
}

/// Exact updated column spellings; `All` never means an empty known set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "selection", content = "names", rename_all = "snake_case")]
pub enum MutationColumns {
    All,
    Named(BTreeSet<String>),
}

/// Current database identity shared by the entire collection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationDatabaseIdentity {
    pub dbid: String,
    pub container: String,
    pub edition: String,
}

/// Fresh, local dictionary identity; names preserve dictionary spelling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationTarget {
    pub owner: String,
    pub name: String,
    pub object_id: u64,
    pub object_edition: Option<String>,
    pub last_ddl_time: String,
}

/// A root or cascading child operation included in the closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationRelationScope {
    pub target: MutationTarget,
    pub statement_kind: MutationStatementKind,
    pub columns: MutationColumns,
}

/// Every family must have an explicit readable, bounded observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationCatalogSource {
    Identity,
    Triggers,
    TriggerColumns,
    IncomingForeignKeys,
    Indexes,
    VirtualColumns,
    IndexExpressions,
    VpdPolicies,
    FgaPolicies,
    SecurityPolicies,
    MaterializedViewLogs,
}

impl MutationCatalogSource {
    pub const ALL: [Self; 11] = [
        Self::Identity,
        Self::Triggers,
        Self::TriggerColumns,
        Self::IncomingForeignKeys,
        Self::Indexes,
        Self::VirtualColumns,
        Self::IndexExpressions,
        Self::VpdPolicies,
        Self::FgaPolicies,
        Self::SecurityPolicies,
        Self::MaterializedViewLogs,
    ];
}

/// A stable uncertainty reason, without query text or driver diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationUnavailableReason {
    InvalidInput,
    CatalogUnreadable,
    CatalogIncomplete,
    RowCapExhausted,
    ClosureCapExhausted,
    IdentityMismatch,
    SourceUnavailable,
    EffectProofUnavailable,
    EffectSourceMismatch,
    UnsupportedMechanism,
}

/// `Unavailable` is uncertainty, never an observation of absence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum MutationComputation {
    Computed,
    Unavailable { reason: MutationUnavailableReason },
}

/// Complete or unavailable evidence for one family on one relation scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationCatalogObservation {
    pub scope: MutationRelationScope,
    pub source: MutationCatalogSource,
    pub computation: MutationComputation,
    /// Hash of canonical bounded rows, including an actually observed empty set.
    pub source_sha256: Option<String>,
    pub row_count: u32,
}

/// The delete action of an enabled incoming foreign key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationForeignKeyAction {
    NoAction,
    Cascade,
    SetNull,
}

/// One implicit Oracle mechanism; ordinary internal maintenance remains visible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mechanism", rename_all = "snake_case", deny_unknown_fields)]
pub enum MutationMechanism {
    DmlTrigger {
        timing: String,
        level: String,
        compound: bool,
        columns: BTreeSet<String>,
    },
    ForeignKeyAction {
        on_delete: MutationForeignKeyAction,
        child_owner: String,
        child_table: String,
        child_columns: BTreeSet<String>,
    },
    IndexCallback {
        domain: bool,
    },
    VirtualColumnExpr {
        column: String,
    },
    /// Includes identity/sequence defaults; their non-transactional effects refuse.
    ColumnDefaultExpr {
        column: String,
    },
    FunctionBasedIndex {
        position: u32,
    },
    VpdPolicy {
        statement_types: BTreeSet<MutationStatementKind>,
        check_option: bool,
    },
    FgaHandler,
    OlsPolicy,
    RasRealm,
    RedactionPolicy,
    /// Transactional internal maintenance, independently of LOG_TRIGGER.
    MvLog {
        log_table: String,
    },
}

/// A mechanism bound to its relation, exact identity and source/metadata bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationMechanismFact {
    pub scope: MutationRelationScope,
    pub owner: String,
    pub name: String,
    pub object_id: Option<u64>,
    pub mechanism: MutationMechanism,
    /// Catalog properties that select/parameterize this mechanism, separate from its code.
    pub metadata_sha256: String,
    pub source_sha256: Option<String>,
    /// Whole routine-call closure fingerprints supplied by the engine binding.
    pub routine_closure_fingerprints: BTreeSet<String>,
    pub effects: RoutineEffectsV1,
    pub computation: MutationComputation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum MutationClosureContract {
    #[serde(rename = "MutationEffectClosureV1")]
    V1,
}

/// Versioned collector result. An empty mechanism list proves nothing unless
/// every required family has a complete observation for every visited scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationEffectClosureV1 {
    contract: MutationClosureContract,
    pub database: Option<MutationDatabaseIdentity>,
    pub root: MutationRelationScope,
    pub scopes: Vec<MutationRelationScope>,
    pub mechanisms: Vec<MutationMechanismFact>,
    pub observations: Vec<MutationCatalogObservation>,
    pub unavailable: BTreeSet<MutationUnavailableReason>,
}

/// Why this collection cannot support a mutation consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationClosureRefusal {
    Incomplete,
    Effect(EffectRefusal),
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("mutation evidence contains only JSON-serializable values")
}

impl MutationEffectClosureV1 {
    #[must_use]
    pub fn new(database: Option<MutationDatabaseIdentity>, root: MutationRelationScope) -> Self {
        Self {
            contract: MutationClosureContract::V1,
            database,
            scopes: vec![root.clone()],
            root,
            mechanisms: Vec::new(),
            observations: Vec::new(),
            unavailable: BTreeSet::new(),
        }
    }

    /// Complete evidence includes all cascading child scopes and all families.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        if !self.unavailable.is_empty()
            || self.database.as_ref().is_none_or(|database| {
                database.dbid.is_empty()
                    || database.container.is_empty()
                    || database.edition.is_empty()
            })
            || self.scopes.is_empty()
            || !self.scopes.contains(&self.root)
        {
            return false;
        }
        for scope in &self.scopes {
            if scope.target.object_id == 0
                || scope.target.owner.is_empty()
                || scope.target.name.is_empty()
                || scope.target.last_ddl_time.is_empty()
                || matches!(&scope.columns, MutationColumns::Named(names) if names.is_empty())
            {
                return false;
            }
            for source in MutationCatalogSource::ALL {
                let matching: Vec<_> = self
                    .observations
                    .iter()
                    .filter(|observation| {
                        observation.scope == *scope && observation.source == source
                    })
                    .collect();
                let [observation] = matching.as_slice() else {
                    return false;
                };
                if observation.computation != MutationComputation::Computed
                    || observation
                        .source_sha256
                        .as_deref()
                        .is_none_or(|hash| !is_sha256(hash))
                {
                    return false;
                }
            }
        }
        self.observations
            .iter()
            .all(|observation| self.scopes.contains(&observation.scope))
            && self.mechanisms.iter().all(|fact| {
                self.scopes.contains(&fact.scope)
                    && !fact.owner.is_empty()
                    && !fact.name.is_empty()
                    && fact.computation == MutationComputation::Computed
                    && is_sha256(&fact.metadata_sha256)
                    && fact.source_sha256.as_deref().is_some_and(is_sha256)
                    && fact
                        .routine_closure_fingerprints
                        .iter()
                        .all(|hash| is_sha256(hash))
                    && (!matches!(
                        fact.mechanism,
                        MutationMechanism::DmlTrigger { .. }
                            | MutationMechanism::IndexCallback { domain: true }
                            | MutationMechanism::VirtualColumnExpr { .. }
                            | MutationMechanism::ColumnDefaultExpr { .. }
                            | MutationMechanism::FunctionBasedIndex { .. }
                            | MutationMechanism::VpdPolicy { .. }
                            | MutationMechanism::FgaHandler
                    ) || !fact.routine_closure_fingerprints.is_empty())
                    && !fact
                        .effects
                        .iter()
                        .any(|effect| effect == RoutineEffect::Unknown)
            })
    }

    /// Admission delegates every effect to the one shared W7 admission rule.
    pub fn admit(&self) -> Result<OperatingLevel, MutationClosureRefusal> {
        if !self.is_complete() {
            return Err(MutationClosureRefusal::Incomplete);
        }
        self.mechanisms
            .iter()
            .try_fold(OperatingLevel::ReadWrite, |level, fact| {
                admit(&fact.effects, AdmissionContext::DmlMutationClosure)
                    .map(|required| level.max(required))
                    .map_err(MutationClosureRefusal::Effect)
            })
    }

    /// Stable encoding independent of catalog row and traversal order.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut value = self.clone();
        value.scopes.sort_by_key(canonical);
        value.mechanisms.sort_by_key(canonical);
        value.observations.sort_by_key(canonical);
        canonical(&value)
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"omcp/mutation-effect-closure/v1\0");
        hash.update(self.canonical_bytes());
        let mut encoded = String::with_capacity(64);
        for byte in hash.finalize() {
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> MutationEffectClosureV1 {
        let scope = MutationRelationScope {
            target: MutationTarget {
                owner: "APP".into(),
                name: "T".into(),
                object_id: 42,
                object_edition: None,
                last_ddl_time: "2026-10-31T00:00:00".into(),
            },
            statement_kind: MutationStatementKind::Update,
            columns: MutationColumns::Named(BTreeSet::from(["C1".into()])),
        };
        let mut closure = MutationEffectClosureV1::new(
            Some(MutationDatabaseIdentity {
                dbid: "1".into(),
                container: "FREEPDB1".into(),
                edition: "ORA$BASE".into(),
            }),
            scope.clone(),
        );
        closure.observations = MutationCatalogSource::ALL
            .into_iter()
            .map(|source| MutationCatalogObservation {
                scope: scope.clone(),
                source,
                computation: MutationComputation::Computed,
                source_sha256: Some("a".repeat(64)),
                row_count: 0,
            })
            .collect();
        closure
    }

    #[test]
    fn mutation_closure_requires_every_source_even_when_no_mechanisms_exist() {
        let mut closure = complete();
        assert_eq!(closure.admit(), Ok(OperatingLevel::ReadWrite));
        closure.observations.pop();
        assert_eq!(closure.admit(), Err(MutationClosureRefusal::Incomplete));
    }

    #[test]
    fn mutation_closure_canonical_hash_binds_source_and_ignores_row_order() {
        let closure = complete();
        let mut reordered = closure.clone();
        reordered.observations.reverse();
        assert_eq!(closure.canonical_bytes(), reordered.canonical_bytes());
        assert_eq!(closure.fingerprint(), reordered.fingerprint());
        reordered.observations[0].source_sha256 = Some("b".repeat(64));
        assert_ne!(closure.fingerprint(), reordered.fingerprint());
    }

    #[test]
    fn mutation_closure_autonomous_trigger_refused_by_shared_admission() {
        let mut closure = complete();
        closure.mechanisms.push(MutationMechanismFact {
            scope: closure.root.clone(),
            owner: "APP".into(),
            name: "TR".into(),
            object_id: Some(43),
            mechanism: MutationMechanism::DmlTrigger {
                timing: "BEFORE".into(),
                level: "ROW".into(),
                compound: false,
                columns: BTreeSet::new(),
            },
            metadata_sha256: "e".repeat(64),
            source_sha256: Some("c".repeat(64)),
            routine_closure_fingerprints: BTreeSet::from(["d".repeat(64)]),
            effects: RoutineEffectsV1::new([RoutineEffect::Autonomous]),
            computation: MutationComputation::Computed,
        });
        assert!(closure.is_complete());
        assert_eq!(
            closure.admit(),
            Err(MutationClosureRefusal::Effect(
                EffectRefusal::AlwaysRefused(RoutineEffect::Autonomous)
            ))
        );
    }

    #[test]
    fn mutation_closure_wire_version_and_unavailable_evidence_fail_closed() {
        let mut closure = complete();
        let wire = serde_json::to_string(&closure).unwrap();
        assert!(
            serde_json::from_str::<MutationEffectClosureV1>(
                &wire.replace("MutationEffectClosureV1", "MutationEffectClosureV2")
            )
            .is_err()
        );
        closure.observations[0].computation = MutationComputation::Unavailable {
            reason: MutationUnavailableReason::CatalogUnreadable,
        };
        assert!(!closure.is_complete());
    }
}
