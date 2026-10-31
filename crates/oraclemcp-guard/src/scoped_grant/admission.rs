//! Grant admission over the shared mutation-effect closure (T13.2a).
//!
//! A scoped grant is admitted in 0.12 only for an ordinary local heap table
//! whose collected [`MutationEffectClosureV1`] proves that a granted statement
//! fires no user code: no enabled DML trigger for the verb (whatever its
//! effects), no cascading foreign key, no domain index, no policy or security
//! callback, and no expression callback beyond proven reads. Oracle-internal
//! transactional maintenance (a materialized-view log) is admitted and bound
//! into the fingerprint, so its appearance or drift is visible.
//!
//! Every effect is judged by the one shared W7 rule,
//! [`admit`]`(.., `[`AdmissionContext::DmlMutationClosure`]`)`. This module
//! never keeps its own effect list and takes no pluggable admission: a
//! caller-supplied rule could only ever be weaker. An incomplete or
//! unavailable closure family refuses as [`GrantAdmissionRefusal::ClosureUnknown`]
//! (unknown is never absent).

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::{ClosureFingerprints, ColumnIdent, GrantVerb, GrantVerbs, LastDdlTime};
use crate::OperatingLevel;
use crate::mutation_closure::{
    MutationCatalogSource, MutationColumns, MutationComputation, MutationEffectClosureV1,
    MutationForeignKeyAction, MutationMechanism, MutationStatementKind, MutationTarget,
    MutationUnavailableReason,
};
use crate::purity::{AdmissionContext, EffectRefusal, RoutineEffect, admit};

/// Physical facts of the grant target, read from the dictionary for exactly
/// the identity the closure was collected for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantTargetFacts {
    /// The exact local identity, including `LAST_DDL_TIME`.
    pub target: MutationTarget,
    /// `ALL_TABLES.PARTITIONED = 'YES'`.
    pub partitioned: bool,
    /// `ALL_TABLES.IOT_TYPE` is set (index-organized table, overflow or mapping).
    pub index_organized: bool,
    /// `ALL_TABLES.CLUSTER_NAME` is set.
    pub clustered: bool,
    /// `ALL_TABLES.TEMPORARY = 'Y'` (global or private temporary table).
    pub temporary: bool,
    /// The table is listed in `ALL_EXTERNAL_TABLES`.
    pub external: bool,
    /// The name resolved through a database link.
    pub remote: bool,
}

/// Why the target is not an ordinary local heap table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonHeapKind {
    Remote,
    External,
    Temporary,
    Partitioned,
    IndexOrganized,
    Clustered,
}

impl GrantTargetFacts {
    /// The first reason this target is not an ordinary local heap table.
    #[must_use]
    pub fn non_heap_kind(&self) -> Option<NonHeapKind> {
        [
            (self.remote, NonHeapKind::Remote),
            (self.external, NonHeapKind::External),
            (self.temporary, NonHeapKind::Temporary),
            (self.partitioned, NonHeapKind::Partitioned),
            (self.index_organized, NonHeapKind::IndexOrganized),
            (self.clustered, NonHeapKind::Clustered),
        ]
        .into_iter()
        .find_map(|(present, kind)| present.then_some(kind))
    }
}

/// A typed refusal naming the mechanism that blocks the grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantAdmissionRefusal {
    NotOrdinaryHeapTable {
        kind: NonHeapKind,
    },
    /// Any enabled DML trigger for a granted verb, whatever its effects.
    UserDmlTrigger {
        trigger: String,
    },
    FkDeleteAction {
        constraint: String,
        rule: MutationForeignKeyAction,
    },
    DomainIndex {
        index: String,
    },
    /// Policy, security or expression code that is not proven to only read.
    UnprovenCallback {
        mechanism: &'static str,
        identity: String,
    },
    /// The shared W7 admission refused an effect.
    EffectRefused {
        effect: RoutineEffect,
    },
    /// A closure family is missing, unavailable or does not describe this
    /// exact target and verb.
    ClosureUnknown {
        source: MutationCatalogSource,
        reason: MutationUnavailableReason,
    },
}

/// A target that may hold a scoped grant, with the fingerprints the grant
/// binds into its `scope_digest`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedGrantTarget {
    pub target: MutationTarget,
    pub closure: ClosureFingerprints,
    pub last_ddl_time: LastDdlTime,
    /// Always `READ_WRITE`: the grant's statements are DML.
    pub required_level: OperatingLevel,
}

/// Why a previously admitted grant no longer matches its target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantDrift {
    /// The fresh closure is no longer admissible.
    Refused(GrantAdmissionRefusal),
    /// The fresh closure is admissible but differs, e.g. a disabled trigger
    /// was enabled or an MV log appeared.
    FingerprintChanged,
}

fn statement_kind(verb: GrantVerb) -> MutationStatementKind {
    match verb {
        GrantVerb::Update => MutationStatementKind::Update,
        GrantVerb::Delete => MutationStatementKind::Delete,
    }
}

fn unknown(
    source: MutationCatalogSource,
    reason: MutationUnavailableReason,
) -> GrantAdmissionRefusal {
    GrantAdmissionRefusal::ClosureUnknown { source, reason }
}

/// The first recorded uncertainty of an incomplete closure.
fn incompleteness(closure: &MutationEffectClosureV1) -> GrantAdmissionRefusal {
    if let Some(observation) = closure
        .observations
        .iter()
        .find_map(|observation| match observation.computation {
            MutationComputation::Unavailable { reason } => Some((observation.source, reason)),
            MutationComputation::Computed => None,
        })
    {
        return unknown(observation.0, observation.1);
    }
    if let Some(fact) = closure
        .mechanisms
        .iter()
        .find_map(|fact| match fact.computation {
            MutationComputation::Unavailable { reason } => Some(reason),
            MutationComputation::Computed => None,
        })
    {
        return unknown(MutationCatalogSource::Identity, fact);
    }
    if let Some(reason) = closure.unavailable.iter().next() {
        return unknown(MutationCatalogSource::Identity, *reason);
    }
    for scope in &closure.scopes {
        for source in MutationCatalogSource::ALL {
            if !closure
                .observations
                .iter()
                .any(|observation| observation.scope == *scope && observation.source == source)
            {
                return unknown(source, MutationUnavailableReason::CatalogIncomplete);
            }
        }
    }
    unknown(
        MutationCatalogSource::Identity,
        MutationUnavailableReason::CatalogIncomplete,
    )
}

fn identity(owner: &str, name: &str) -> String {
    format!("{owner}.{name}")
}

/// Refusals that follow from a mechanism's presence alone. They hold even when
/// the closure is otherwise incomplete: a collected trigger is a real trigger,
/// whatever its unproven effects, so it is named rather than hidden behind
/// `ClosureUnknown`.
fn presence_refusal(closure: &MutationEffectClosureV1) -> Option<GrantAdmissionRefusal> {
    closure.mechanisms.iter().find_map(|fact| {
        let name = identity(&fact.owner, &fact.name);
        match &fact.mechanism {
            MutationMechanism::DmlTrigger { .. } => {
                Some(GrantAdmissionRefusal::UserDmlTrigger { trigger: name })
            }
            MutationMechanism::ForeignKeyAction { on_delete, .. }
                if *on_delete != MutationForeignKeyAction::NoAction =>
            {
                Some(GrantAdmissionRefusal::FkDeleteAction {
                    constraint: name,
                    rule: *on_delete,
                })
            }
            MutationMechanism::IndexCallback { domain: true } => {
                Some(GrantAdmissionRefusal::DomainIndex { index: name })
            }
            // A mutation-time policy changes the row set the pre-count saw.
            MutationMechanism::VpdPolicy { .. } => Some(GrantAdmissionRefusal::UnprovenCallback {
                mechanism: "vpd_policy",
                identity: name,
            }),
            // Oracle runs an FGA handler autonomously.
            MutationMechanism::FgaHandler => Some(GrantAdmissionRefusal::EffectRefused {
                effect: RoutineEffect::Autonomous,
            }),
            MutationMechanism::OlsPolicy => Some(GrantAdmissionRefusal::UnprovenCallback {
                mechanism: "ols_policy",
                identity: name,
            }),
            MutationMechanism::RasRealm => Some(GrantAdmissionRefusal::UnprovenCallback {
                mechanism: "ras_realm",
                identity: name,
            }),
            MutationMechanism::RedactionPolicy => Some(GrantAdmissionRefusal::UnprovenCallback {
                mechanism: "redaction_policy",
                identity: name,
            }),
            MutationMechanism::ForeignKeyAction { .. }
            | MutationMechanism::IndexCallback { domain: false }
            | MutationMechanism::VirtualColumnExpr { .. }
            | MutationMechanism::ColumnDefaultExpr { .. }
            | MutationMechanism::FunctionBasedIndex { .. }
            | MutationMechanism::MvLog { .. } => None,
        }
    })
}

/// On a complete closure, the remaining mechanisms are admitted only through
/// their proven effects: expression code may only read, and every effect goes
/// through the shared W7 rule.
fn admit_effects(closure: &MutationEffectClosureV1) -> Result<(), GrantAdmissionRefusal> {
    for fact in &closure.mechanisms {
        if matches!(
            fact.mechanism,
            MutationMechanism::VirtualColumnExpr { .. }
                | MutationMechanism::ColumnDefaultExpr { .. }
                | MutationMechanism::FunctionBasedIndex { .. }
        ) && fact
            .effects
            .iter()
            .any(|effect| effect != RoutineEffect::ReadDb)
        {
            // Expression code runs inside the granted statement.
            return Err(GrantAdmissionRefusal::UnprovenCallback {
                mechanism: "expression",
                identity: identity(&fact.owner, &fact.name),
            });
        }
        if let Err(refusal) = admit(&fact.effects, AdmissionContext::DmlMutationClosure) {
            let effect = match refusal {
                EffectRefusal::AlwaysRefused(effect) | EffectRefusal::DdlTriggerEffect(effect) => {
                    effect
                }
                EffectRefusal::ImpactReportNotExecutable => RoutineEffect::Unknown,
            };
            return Err(GrantAdmissionRefusal::EffectRefused { effect });
        }
    }
    Ok(())
}

fn closure_fingerprint(closure: &MutationEffectClosureV1) -> Option<[u8; 32]> {
    let hex = closure.fingerprint();
    let mut bytes = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        *bytes.get_mut(index)? = u8::from_str_radix(text, 16).ok()?;
    }
    (hex.len() == 64).then_some(bytes)
}

fn facts_fingerprint(facts: &GrantTargetFacts) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"omcp/grant-target-facts/v1\0");
    let target = &facts.target;
    for part in [
        target.owner.as_str(),
        target.name.as_str(),
        target.object_edition.as_deref().unwrap_or(""),
        target.last_ddl_time.as_str(),
    ] {
        hash.update(part.as_bytes());
        hash.update([0]);
    }
    hash.update(target.object_id.to_be_bytes());
    hash.update([
        u8::from(facts.partitioned),
        u8::from(facts.index_organized),
        u8::from(facts.clustered),
        u8::from(facts.temporary),
        u8::from(facts.external),
        u8::from(facts.remote),
    ]);
    hash.finalize().into()
}

/// Admit a grant target from its dictionary facts and exactly one collected
/// closure per granted verb. An UPDATE closure must cover every granted
/// column (or all columns), so a column-specific trigger cannot hide.
pub fn admit_grant_target(
    target: &GrantTargetFacts,
    closures: &[MutationEffectClosureV1],
    verbs: &GrantVerbs,
    columns: &BTreeSet<ColumnIdent>,
) -> Result<AdmittedGrantTarget, GrantAdmissionRefusal> {
    if let Some(kind) = target.non_heap_kind() {
        return Err(GrantAdmissionRefusal::NotOrdinaryHeapTable { kind });
    }
    let mismatch = || {
        unknown(
            MutationCatalogSource::Identity,
            MutationUnavailableReason::IdentityMismatch,
        )
    };
    if closures.len() != verbs.iter().count() {
        return Err(mismatch());
    }
    let mut fingerprints = vec![facts_fingerprint(target)];
    for verb in verbs.iter() {
        let kind = statement_kind(verb);
        let matching: Vec<_> = closures
            .iter()
            .filter(|closure| closure.root.statement_kind == kind)
            .collect();
        let [closure] = matching.as_slice() else {
            return Err(mismatch());
        };
        if closure.root.target != target.target || closure.database != closures[0].database {
            return Err(mismatch());
        }
        if kind == MutationStatementKind::Update {
            let covered = match &closure.root.columns {
                MutationColumns::All => true,
                MutationColumns::Named(named) => {
                    columns.iter().all(|column| named.contains(column.as_str()))
                }
            };
            if !covered || columns.is_empty() {
                return Err(unknown(
                    MutationCatalogSource::TriggerColumns,
                    MutationUnavailableReason::InvalidInput,
                ));
            }
        }
        if let Some(refusal) = presence_refusal(closure) {
            return Err(refusal);
        }
        if !closure.is_complete() {
            return Err(incompleteness(closure));
        }
        admit_effects(closure)?;
        fingerprints.push(closure_fingerprint(closure).ok_or_else(mismatch)?);
    }
    let last_ddl_time = LastDdlTime::new(target.target.last_ddl_time.clone()).map_err(|_| {
        unknown(
            MutationCatalogSource::Identity,
            MutationUnavailableReason::CatalogIncomplete,
        )
    })?;
    Ok(AdmittedGrantTarget {
        target: target.target.clone(),
        closure: ClosureFingerprints::from_fingerprints(fingerprints),
        last_ddl_time,
        required_level: OperatingLevel::ReadWrite,
    })
}

/// Recompute admission from fresh facts and closures before a grant is used.
/// Any refusal, and any change to the bound fingerprints, is drift.
pub fn recheck_grant_closure(
    grant: &AdmittedGrantTarget,
    target: &GrantTargetFacts,
    fresh_closures: &[MutationEffectClosureV1],
    verbs: &GrantVerbs,
    columns: &BTreeSet<ColumnIdent>,
) -> Result<(), GrantDrift> {
    let fresh =
        admit_grant_target(target, fresh_closures, verbs, columns).map_err(GrantDrift::Refused)?;
    if fresh.target != grant.target
        || fresh.closure != grant.closure
        || fresh.last_ddl_time != grant.last_ddl_time
    {
        return Err(GrantDrift::FingerprintChanged);
    }
    Ok(())
}
