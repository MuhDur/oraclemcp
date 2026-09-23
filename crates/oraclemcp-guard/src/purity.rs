//! The `SideEffectOracle` port + three-valued `Purity` verdict (plan §5.3;
//! beads P1-1d, P1-1e). This is the boundary-preserving seam (§0 hard rule 1):
//! the port lives in the engine-free guard with a default impl that returns
//! `Unknown`, so the classifier ships fully functional with no engine
//! dependency. Routine and statement `Unknown` are fail-closed by default; an
//! engine-free consumer must make an explicit, independently justified opt-out
//! before allowing an unproven plain read. The PL/SQL engine binds the *real* implementation — over
//! its `DepGraph` / `plsql-lineage::column_writers` and the trigger/VPD walk —
//! from the *consumer* side, exactly like every other engine tool.

use std::{
    collections::{BTreeSet, HashSet},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use crate::levels::OperatingLevel;

/// Statement classes reserved for an operator, even when a profile permits ADMIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OperatorStatementClass {
    /// Changing the database's default edition is never an agent action.
    DefaultEditionFlip,
}

impl OperatorStatementClass {
    /// Recognize only the operator executor's fixed rendering. This is not
    /// agent SQL admission: the ordinary classifier refuses this statement at
    /// every level, including ADMIN.
    #[must_use]
    pub fn from_exact_rendered_sql(sql: &str) -> Option<Self> {
        let identifier = sql
            .strip_prefix("ALTER DATABASE DEFAULT EDITION = \"")?
            .strip_suffix('"')?;
        if identifier.is_empty()
            || identifier.len() > 128
            || identifier.contains(['"', '\0'])
            || identifier.chars().any(char::is_control)
        {
            return None;
        }
        Some(Self::DefaultEditionFlip)
    }
}

/// A routine's proven effects. These form a set, not a privilege ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RoutineEffect {
    ReadDb,
    RowLock,
    SessionState,
    Dml,
    Ddl,
    Admin,
    SequenceAdvance,
    OperatorOnly(OperatorStatementClass),
    TxnControl,
    Autonomous,
    DynamicSql,
    ExternalIo,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
enum RoutineEffectsContract {
    #[default]
    #[serde(rename = "RoutineEffectsV1")]
    V1,
}

/// Canonical, versioned effect set for a complete routine call closure.
///
/// The private contract field rejects a different wire version. `BTreeSet`
/// removes duplicates and gives the same serialization for every union order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutineEffectsV1 {
    contract: RoutineEffectsContract,
    effects: BTreeSet<RoutineEffect>,
}

impl RoutineEffectsV1 {
    #[must_use]
    pub fn new(effects: impl IntoIterator<Item = RoutineEffect>) -> Self {
        Self {
            contract: RoutineEffectsContract::V1,
            effects: effects.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self::new(self.effects.union(&other.effects).copied())
    }

    pub fn iter(&self) -> impl Iterator<Item = RoutineEffect> + '_ {
        self.effects.iter().copied()
    }
}

/// The execution context that consumes a proven effect set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionContext {
    CustomToolCall,
    DdlTrigger,
    DmlMutationClosure,
    ChangeRequestTest,
    ImpactReport,
}

/// Why a routine effect set cannot authorize execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectRefusal {
    /// This effect cannot run through any agent path in 0.12.
    AlwaysRefused(RoutineEffect),
    /// DDL triggers may read or change session state only.
    DdlTriggerEffect(RoutineEffect),
    /// An impact report describes effects; it never executes a routine.
    ImpactReportNotExecutable,
}

/// The single admission decision for every consumer of `RoutineEffectsV1`.
/// Refusals are checked before deriving a level, so transaction control and
/// autonomous work cannot be misread as merely higher privilege.
pub fn admit(
    effects: &RoutineEffectsV1,
    context: AdmissionContext,
) -> Result<OperatingLevel, EffectRefusal> {
    for effect in effects.iter() {
        match effect {
            RoutineEffect::SequenceAdvance
            | RoutineEffect::OperatorOnly(_)
            | RoutineEffect::TxnControl
            | RoutineEffect::Autonomous
            | RoutineEffect::DynamicSql
            | RoutineEffect::ExternalIo
            | RoutineEffect::Unknown => return Err(EffectRefusal::AlwaysRefused(effect)),
            RoutineEffect::ReadDb
            | RoutineEffect::RowLock
            | RoutineEffect::SessionState
            | RoutineEffect::Dml
            | RoutineEffect::Ddl
            | RoutineEffect::Admin => {}
        }
    }

    match context {
        AdmissionContext::ImpactReport => return Err(EffectRefusal::ImpactReportNotExecutable),
        AdmissionContext::DdlTrigger => {
            for effect in effects.iter() {
                match effect {
                    RoutineEffect::ReadDb | RoutineEffect::SessionState => {}
                    RoutineEffect::RowLock
                    | RoutineEffect::Dml
                    | RoutineEffect::Ddl
                    | RoutineEffect::Admin => {
                        return Err(EffectRefusal::DdlTriggerEffect(effect));
                    }
                    RoutineEffect::SequenceAdvance
                    | RoutineEffect::OperatorOnly(_)
                    | RoutineEffect::TxnControl
                    | RoutineEffect::Autonomous
                    | RoutineEffect::DynamicSql
                    | RoutineEffect::ExternalIo
                    | RoutineEffect::Unknown => unreachable!("refused above"),
                }
            }
        }
        AdmissionContext::CustomToolCall
        | AdmissionContext::DmlMutationClosure
        | AdmissionContext::ChangeRequestTest => {}
    }

    Ok(derived_level(effects))
}

fn derived_level(effects: &RoutineEffectsV1) -> OperatingLevel {
    effects
        .iter()
        .fold(OperatingLevel::ReadOnly, |level, effect| {
            let required = match effect {
                RoutineEffect::ReadDb => OperatingLevel::ReadOnly,
                RoutineEffect::RowLock | RoutineEffect::SessionState | RoutineEffect::Dml => {
                    OperatingLevel::ReadWrite
                }
                RoutineEffect::Ddl => OperatingLevel::Ddl,
                RoutineEffect::Admin => OperatingLevel::Admin,
                RoutineEffect::SequenceAdvance
                | RoutineEffect::OperatorOnly(_)
                | RoutineEffect::TxnControl
                | RoutineEffect::Autonomous
                | RoutineEffect::DynamicSql
                | RoutineEffect::ExternalIo
                | RoutineEffect::Unknown => unreachable!("admit refuses these effects"),
            };
            level.max(required)
        })
}

/// A reference to a database routine / object for the purity consult.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectRef {
    /// Owning schema, if qualified (`billing` in `billing.purge_old_rows`).
    pub schema: Option<String>,
    /// The object / routine name.
    pub name: String,
}

impl ObjectRef {
    /// A reference from an optional schema + name.
    #[must_use]
    pub fn new(schema: Option<String>, name: impl Into<String>) -> Self {
        ObjectRef {
            schema,
            name: name.into(),
        }
    }

    /// Parse a possibly-qualified `schema.name` (or bare `name`).
    #[must_use]
    pub fn parse(qualified: &str) -> Self {
        match qualified.split_once('.') {
            Some((s, n)) => ObjectRef {
                schema: Some(s.to_owned()),
                name: n.to_owned(),
            },
            None => ObjectRef {
                schema: None,
                name: qualified.to_owned(),
            },
        }
    }
}

/// The three-valued purity verdict (§5.3, R15). For routine calls, **only
/// `ProvenReadOnly` permits clearing a statement to `Safe`.** Absence of a
/// write edge is `Unknown`, never routine-safe; `Measured::Unmeasured` /
/// `OpaqueDynamic` / unloaded / cycle all map to `Unknown`. Routine and
/// statement-level `Unknown` are fail-closed by the default classifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum Purity {
    /// Body fully loaded + parsed clean; every transitively-reachable routine
    /// has all completeness signals `Measured(0)`; no Writes/DDL/OpaqueDynamic/
    /// DbLink/TriggersOn edge reachable. The *only* verdict that permits `Safe`.
    ProvenReadOnly,
    /// A reachable write/DDL/autonomous-transaction edge → escalate to ≥ Guarded.
    ProvenSideEffecting,
    /// The default: not proven either way. Routine consults and tightened
    /// statement consults treat this as fail-closed.
    Unknown,
}

impl Purity {
    /// Whether this verdict permits clearing to `Safe`. Only `ProvenReadOnly`.
    #[must_use]
    pub fn permits_safe(self) -> bool {
        matches!(self, Purity::ProvenReadOnly)
    }
}

/// The engine-aware side-effect consult port. Every method defaults to
/// `Unknown`, so a guard with no engine bound treats every user-defined routine
/// and base-object read as unproven. The default classifier fails closed; an
/// explicit engine-free baseline is available only for callers with an
/// independent semantic-read proof.
pub trait SideEffectOracle: Send + Sync {
    /// The purity of a user-defined routine (function/procedure/package member).
    fn routine_purity(&self, routine: &ObjectRef) -> Purity {
        let _ = routine;
        Purity::Unknown
    }

    /// The purity of a statement given its resolved base objects — this is where
    /// the engine performs the trigger / VPD (`DBMS_RLS`) walk: a SELECT or DML
    /// can fire a side-effecting trigger or row-level-security function the
    /// statement text never names.
    ///
    /// Wired into the classifier's `SELECT` arm (the base objects are the
    /// resolved `FROM`/`JOIN` tables + CTE/derived bodies). The default
    /// `UnknownOracle` makes a UDF-free plain SELECT unproven, and the default
    /// classifier maps it to `≥ Guarded`. Consumers that have an independent
    /// semantic-read proof may explicitly construct
    /// `Classifier::engine_free_baseline`; that opt-out preserves the historical
    /// engine-free behavior without weakening the library default.
    fn statement_purity(&self, base_objects: &[ObjectRef]) -> Purity {
        let _ = base_objects;
        Purity::Unknown
    }
}

/// The default oracle: everything is `Unknown`. Used until the engine binds a
/// real implementation from the consumer side.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnknownOracle;

impl SideEffectOracle for UnknownOracle {}

/// A schema-qualified routine identity from operator-only configuration.
///
/// This is deliberately an identity, **not** a purity proof. It can restrict
/// an independent [`SideEffectOracle`] proof through
/// [`OperatorPureFunctionRestriction`], but it can never make an `Unknown`
/// routine [`Purity::ProvenReadOnly`] by itself. Bare names depend on
/// `CURRENT_SCHEMA`; wildcards, database links, quoted names, and
/// package/member chains are not represented by [`ObjectRef`] with enough
/// fidelity to safely match them, so they are rejected at the configuration
/// boundary rather than guessed at runtime.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OperatorPureFunction(ObjectRef);

impl OperatorPureFunction {
    /// Parse one exact `SCHEMA.FUNCTION` operator declaration.
    ///
    /// Call this only while loading operator-owned configuration. Client input
    /// must never reach the pure-function restriction.
    pub fn parse(value: &str) -> Result<Self, OperatorPureFunctionError> {
        let value = value.trim();
        let Some((schema, name)) = value.split_once('.') else {
            return Err(OperatorPureFunctionError::MissingSchema);
        };
        if name.contains('.') {
            return Err(OperatorPureFunctionError::AmbiguousIdentity);
        }
        let schema = normalize_simple_identifier(schema)
            .ok_or(OperatorPureFunctionError::InvalidSchemaIdentifier)?;
        let name = normalize_simple_identifier(name)
            .ok_or(OperatorPureFunctionError::InvalidFunctionIdentifier)?;
        Ok(Self(ObjectRef::new(Some(schema), name)))
    }

    /// The canonical schema-qualified spelling for operator configuration and
    /// audit display.
    #[must_use]
    pub fn qualified_name(&self) -> String {
        let schema = self
            .0
            .schema
            .as_deref()
            .expect("OperatorPureFunction is always schema-qualified");
        format!("{schema}.{}", self.0.name)
    }

    fn matches(&self, routine: &ObjectRef) -> bool {
        let Some(schema) = routine.schema.as_deref() else {
            return false;
        };
        let Some(schema) = normalize_simple_identifier(schema) else {
            return false;
        };
        let Some(name) = normalize_simple_identifier(&routine.name) else {
            return false;
        };
        self.0.schema.as_deref() == Some(schema.as_str()) && self.0.name == name
    }
}

/// Why an operator pure-function declaration was rejected before it could
/// restrict the classifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperatorPureFunctionError {
    /// A bare routine name cannot be resolved without ambient schema state.
    MissingSchema,
    /// More than `SCHEMA.FUNCTION` was supplied; package chains are ambiguous.
    AmbiguousIdentity,
    /// The schema was not one simple, unquoted Oracle identifier.
    InvalidSchemaIdentifier,
    /// The function was not one simple, unquoted Oracle identifier.
    InvalidFunctionIdentifier,
}

impl std::fmt::Display for OperatorPureFunctionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissingSchema => "must use an exact SCHEMA.FUNCTION identity",
            Self::AmbiguousIdentity => {
                "must contain exactly one dot; package chains and database links are not allowed"
            }
            Self::InvalidSchemaIdentifier => {
                "schema must be one unquoted Oracle identifier (letters, digits, _, $, #)"
            }
            Self::InvalidFunctionIdentifier => {
                "function must be one unquoted Oracle identifier (letters, digits, _, $, #)"
            }
        })
    }
}

impl std::error::Error for OperatorPureFunctionError {}

fn normalize_simple_identifier(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    let mut chars = value.bytes();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic()
        || !chars.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'#'))
    {
        return None;
    }
    Some(value.to_ascii_uppercase())
}

/// Exact operator declarations that may restrict independent routine proofs.
///
/// A present empty list deliberately restricts every user-defined routine. To
/// preserve the independent oracle unchanged, do not bind an
/// [`OperatorPureFunctionRestriction`] at all.
#[derive(Clone, Debug, Default)]
pub struct OperatorPureFunctionAllowlist {
    entries: HashSet<OperatorPureFunction>,
}

impl OperatorPureFunctionAllowlist {
    /// Build a restriction from already-validated operator declarations.
    #[must_use]
    pub fn new(entries: impl IntoIterator<Item = OperatorPureFunction>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    fn permits(&self, routine: &ObjectRef) -> bool {
        self.entries.iter().any(|entry| entry.matches(routine))
    }
}

/// A [`SideEffectOracle`] that intersects an independent proof with exact
/// operator-owned configuration.
///
/// This wrapper is tightening-only: it returns [`Purity::ProvenReadOnly`] for
/// a routine only when the independent oracle already returned that verdict
/// *and* the exact routine identity is in the operator allowlist. Unknown,
/// malformed, and non-matching declarations therefore fail closed. The
/// operator list is a restriction on a proof source, never a proof source of
/// its own.
pub struct OperatorPureFunctionRestriction {
    independent: Arc<dyn SideEffectOracle>,
    allowlist: OperatorPureFunctionAllowlist,
}

impl OperatorPureFunctionRestriction {
    /// Restrict `independent` using already-validated, operator-owned entries.
    #[must_use]
    pub fn new(
        independent: Arc<dyn SideEffectOracle>,
        allowlist: OperatorPureFunctionAllowlist,
    ) -> Self {
        Self {
            independent,
            allowlist,
        }
    }
}

impl SideEffectOracle for OperatorPureFunctionRestriction {
    fn routine_purity(&self, routine: &ObjectRef) -> Purity {
        match self.independent.routine_purity(routine) {
            Purity::ProvenReadOnly if self.allowlist.permits(routine) => Purity::ProvenReadOnly,
            Purity::ProvenReadOnly => Purity::Unknown,
            verdict => verdict,
        }
    }

    fn statement_purity(&self, base_objects: &[ObjectRef]) -> Purity {
        self.independent.statement_purity(base_objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn one(effect: RoutineEffect) -> RoutineEffectsV1 {
        RoutineEffectsV1::new([effect])
    }

    #[test]
    fn effects_select_calling_nextval_routine_not_read_only() {
        assert_eq!(
            admit(
                &one(RoutineEffect::SequenceAdvance),
                AdmissionContext::CustomToolCall
            ),
            Err(EffectRefusal::AlwaysRefused(RoutineEffect::SequenceAdvance))
        );
    }

    #[test]
    fn effects_select_for_update_routine_not_read_only() {
        assert_eq!(
            admit(
                &one(RoutineEffect::RowLock),
                AdmissionContext::CustomToolCall
            ),
            Ok(OperatingLevel::ReadWrite)
        );
    }

    #[test]
    fn effects_literal_alter_database_default_edition_is_operator_only_on_admin_lane() {
        let effects = RoutineEffectsV1::new([
            RoutineEffect::Admin,
            RoutineEffect::OperatorOnly(OperatorStatementClass::DefaultEditionFlip),
        ]);
        assert_eq!(
            admit(&effects, AdmissionContext::CustomToolCall),
            Err(EffectRefusal::AlwaysRefused(RoutineEffect::OperatorOnly(
                OperatorStatementClass::DefaultEditionFlip
            )))
        );
    }

    #[test]
    fn operator_statement_class_rejects_any_other_text() {
        assert_eq!(
            OperatorStatementClass::from_exact_rendered_sql(
                "ALTER DATABASE DEFAULT EDITION = \"STAGE_V2\""
            ),
            Some(OperatorStatementClass::DefaultEditionFlip)
        );
        for sql in [
            "alter database default edition = \"STAGE_V2\"",
            "ALTER DATABASE DEFAULT EDITION = STAGE_V2",
            "ALTER DATABASE DEFAULT EDITION = \"\"",
            "ALTER DATABASE DEFAULT EDITION = \"STAGE_V2\";",
            "ALTER DATABASE DEFAULT EDITION = \"STAGE_V2\" -- tail",
            "ALTER DATABASE DEFAULT EDITION = \"STAGE\"; DROP TABLE T; --\"",
            "ALTER DATABASE DEFAULT EDITION = \"STAGE\0V2\"",
            "ALTER DATABASE DEFAULT EDITION = \"STAGE\nV2\"",
        ] {
            assert_eq!(
                OperatorStatementClass::from_exact_rendered_sql(sql),
                None,
                "{sql:?}"
            );
        }
        let too_long = format!("ALTER DATABASE DEFAULT EDITION = \"{}\"", "X".repeat(129));
        assert_eq!(
            OperatorStatementClass::from_exact_rendered_sql(&too_long),
            None
        );
    }

    #[test]
    fn effects_package_init_dml_requires_read_write() {
        let effects = one(RoutineEffect::ReadDb).union(&one(RoutineEffect::Dml));
        assert_eq!(
            admit(&effects, AdmissionContext::CustomToolCall),
            Ok(OperatingLevel::ReadWrite)
        );
    }

    #[test]
    fn effects_package_init_commit_refused() {
        let effects = one(RoutineEffect::Ddl).union(&one(RoutineEffect::TxnControl));
        assert_eq!(
            admit(&effects, AdmissionContext::CustomToolCall),
            Err(EffectRefusal::AlwaysRefused(RoutineEffect::TxnControl))
        );
    }

    #[test]
    fn effects_package_init_autonomous_refused() {
        let effects = one(RoutineEffect::Dml).union(&one(RoutineEffect::Autonomous));
        assert_eq!(
            admit(&effects, AdmissionContext::CustomToolCall),
            Err(EffectRefusal::AlwaysRefused(RoutineEffect::Autonomous))
        );
    }

    #[test]
    fn effects_package_init_nextval_refused() {
        let effects = one(RoutineEffect::Dml).union(&one(RoutineEffect::SequenceAdvance));
        assert_eq!(
            admit(&effects, AdmissionContext::CustomToolCall),
            Err(EffectRefusal::AlwaysRefused(RoutineEffect::SequenceAdvance))
        );
    }

    #[test]
    fn effects_package_init_utl_refused() {
        let effects = one(RoutineEffect::ReadDb).union(&one(RoutineEffect::ExternalIo));
        assert_eq!(
            admit(&effects, AdmissionContext::CustomToolCall),
            Err(EffectRefusal::AlwaysRefused(RoutineEffect::ExternalIo))
        );
    }

    #[test]
    fn effects_ddl_trigger_context_refuses_nextval() {
        assert_eq!(
            admit(
                &one(RoutineEffect::SequenceAdvance),
                AdmissionContext::DdlTrigger
            ),
            Err(EffectRefusal::AlwaysRefused(RoutineEffect::SequenceAdvance))
        );
    }

    #[test]
    fn effects_ddl_trigger_context_refuses_dynamic_sql() {
        assert_eq!(
            admit(
                &one(RoutineEffect::DynamicSql),
                AdmissionContext::DdlTrigger
            ),
            Err(EffectRefusal::AlwaysRefused(RoutineEffect::DynamicSql))
        );
    }

    #[test]
    fn effects_ddl_trigger_context_refuses_operator_only() {
        let effect = RoutineEffect::OperatorOnly(OperatorStatementClass::DefaultEditionFlip);
        assert_eq!(
            admit(&one(effect), AdmissionContext::DdlTrigger),
            Err(EffectRefusal::AlwaysRefused(effect))
        );
    }

    #[test]
    fn effects_ddl_trigger_context_refuses_dml() {
        assert_eq!(
            admit(&one(RoutineEffect::Dml), AdmissionContext::DdlTrigger),
            Err(EffectRefusal::DdlTriggerEffect(RoutineEffect::Dml))
        );
    }

    #[test]
    fn effects_ddl_trigger_context_admits_read_and_session_state() {
        let effects = RoutineEffectsV1::new([RoutineEffect::ReadDb, RoutineEffect::SessionState]);
        assert_eq!(
            admit(&effects, AdmissionContext::DdlTrigger),
            Ok(OperatingLevel::ReadWrite)
        );
    }

    proptest! {
        #[test]
        fn effects_union_is_order_independent(left in proptest::collection::vec(0usize..13, 0..20), right in proptest::collection::vec(0usize..13, 0..20)) {
            let all = [RoutineEffect::ReadDb, RoutineEffect::RowLock, RoutineEffect::SessionState,
                RoutineEffect::Dml, RoutineEffect::Ddl, RoutineEffect::Admin,
                RoutineEffect::SequenceAdvance,
                RoutineEffect::OperatorOnly(OperatorStatementClass::DefaultEditionFlip),
                RoutineEffect::TxnControl, RoutineEffect::Autonomous, RoutineEffect::DynamicSql,
                RoutineEffect::ExternalIo, RoutineEffect::Unknown];
            let a = RoutineEffectsV1::new(left.into_iter().map(|i| all[i]));
            let b = RoutineEffectsV1::new(right.into_iter().map(|i| all[i]));
            prop_assert_eq!(a.union(&b), b.union(&a));
        }
    }

    #[test]
    fn effects_level_derivation_table() {
        let cases = [
            (RoutineEffect::ReadDb, Ok(OperatingLevel::ReadOnly)),
            (RoutineEffect::RowLock, Ok(OperatingLevel::ReadWrite)),
            (RoutineEffect::SessionState, Ok(OperatingLevel::ReadWrite)),
            (RoutineEffect::Dml, Ok(OperatingLevel::ReadWrite)),
            (RoutineEffect::Ddl, Ok(OperatingLevel::Ddl)),
            (RoutineEffect::Admin, Ok(OperatingLevel::Admin)),
            (
                RoutineEffect::SequenceAdvance,
                Err(EffectRefusal::AlwaysRefused(RoutineEffect::SequenceAdvance)),
            ),
            (
                RoutineEffect::OperatorOnly(OperatorStatementClass::DefaultEditionFlip),
                Err(EffectRefusal::AlwaysRefused(RoutineEffect::OperatorOnly(
                    OperatorStatementClass::DefaultEditionFlip,
                ))),
            ),
            (
                RoutineEffect::TxnControl,
                Err(EffectRefusal::AlwaysRefused(RoutineEffect::TxnControl)),
            ),
            (
                RoutineEffect::Autonomous,
                Err(EffectRefusal::AlwaysRefused(RoutineEffect::Autonomous)),
            ),
            (
                RoutineEffect::DynamicSql,
                Err(EffectRefusal::AlwaysRefused(RoutineEffect::DynamicSql)),
            ),
            (
                RoutineEffect::ExternalIo,
                Err(EffectRefusal::AlwaysRefused(RoutineEffect::ExternalIo)),
            ),
            (
                RoutineEffect::Unknown,
                Err(EffectRefusal::AlwaysRefused(RoutineEffect::Unknown)),
            ),
        ];
        for context in [
            AdmissionContext::CustomToolCall,
            AdmissionContext::DmlMutationClosure,
            AdmissionContext::ChangeRequestTest,
            AdmissionContext::DdlTrigger,
            AdmissionContext::ImpactReport,
        ] {
            for (effect, expected) in cases {
                let expected = if expected.is_ok() && context == AdmissionContext::ImpactReport {
                    Err(EffectRefusal::ImpactReportNotExecutable)
                } else if expected.is_ok()
                    && context == AdmissionContext::DdlTrigger
                    && !matches!(effect, RoutineEffect::ReadDb | RoutineEffect::SessionState)
                {
                    Err(EffectRefusal::DdlTriggerEffect(effect))
                } else {
                    expected
                };
                assert_eq!(
                    admit(&one(effect), context),
                    expected,
                    "{effect:?} in {context:?}"
                );
            }
        }
        assert_eq!(
            admit(
                &RoutineEffectsV1::default(),
                AdmissionContext::CustomToolCall
            ),
            Ok(OperatingLevel::ReadOnly)
        );
    }

    #[test]
    fn effects_serialization_is_canonical() {
        let a = RoutineEffectsV1::new([
            RoutineEffect::Dml,
            RoutineEffect::ReadDb,
            RoutineEffect::Dml,
        ]);
        let b = RoutineEffectsV1::new([RoutineEffect::ReadDb, RoutineEffect::Dml]);
        let wire = serde_json::to_string(&a).expect("serialize effect set");
        assert_eq!(
            wire,
            serde_json::to_string(&b).expect("serialize reversed set")
        );
        assert_eq!(
            wire,
            r#"{"contract":"RoutineEffectsV1","effects":["ReadDb","Dml"]}"#
        );
        assert_eq!(
            serde_json::from_str::<RoutineEffectsV1>(&wire).expect("round trip"),
            a
        );
        assert!(
            serde_json::from_str::<RoutineEffectsV1>(
                r#"{"contract":"RoutineEffectsV2","effects":[]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn default_oracle_is_fail_closed_unknown() {
        let oracle = UnknownOracle;
        assert_eq!(
            oracle.routine_purity(&ObjectRef::parse("billing.purge_old_rows")),
            Purity::Unknown
        );
        assert_eq!(
            oracle.statement_purity(&[ObjectRef::parse("orders")]),
            Purity::Unknown
        );
        assert!(!Purity::Unknown.permits_safe());
        assert!(!Purity::ProvenSideEffecting.permits_safe());
        assert!(Purity::ProvenReadOnly.permits_safe());
    }

    #[test]
    fn object_ref_parse_qualified_and_bare() {
        assert_eq!(
            ObjectRef::parse("billing.purge"),
            ObjectRef {
                schema: Some("billing".to_owned()),
                name: "purge".to_owned()
            }
        );
        assert_eq!(
            ObjectRef::parse("purge"),
            ObjectRef {
                schema: None,
                name: "purge".to_owned()
            }
        );
    }

    #[test]
    fn operator_pure_function_requires_an_exact_schema_qualified_identity() {
        assert_eq!(
            OperatorPureFunction::parse("app_read.lookup")
                .expect("two simple identifiers are exact")
                .qualified_name(),
            "APP_READ.LOOKUP"
        );
        for value in [
            "lookup",
            "app_read.pkg.lookup",
            "app_read.lookup@remote",
            "app_read.*",
            "\"app_read\".lookup",
            "app read.lookup",
        ] {
            assert!(
                OperatorPureFunction::parse(value).is_err(),
                "must reject non-exact pure-function declaration: {value:?}"
            );
        }
    }

    #[test]
    fn operator_pure_function_restriction_cannot_prove_an_unknown_routine() {
        let allowlist =
            OperatorPureFunctionAllowlist::new([
                OperatorPureFunction::parse("app_read.lookup").expect("exact declaration")
            ]);
        let restriction = OperatorPureFunctionRestriction::new(Arc::new(UnknownOracle), allowlist);

        assert_eq!(
            restriction.routine_purity(&ObjectRef::parse("app_read.lookup")),
            Purity::Unknown,
            "the operator entry is not an independent purity proof"
        );
    }
}
