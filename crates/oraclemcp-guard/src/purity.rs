//! The `SideEffectOracle` port + three-valued `Purity` verdict (plan §5.3;
//! beads P1-1d, P1-1e). This is the boundary-preserving seam (§0 hard rule 1):
//! the port lives in the engine-free guard with a default impl that returns
//! `Unknown`, so the classifier ships fully functional with no engine
//! dependency. Routine `Unknown` is always fail-closed; statement `Unknown`
//! stays permissive until a real engine binding opts into SELECT-side-effect
//! tightening. The PL/SQL engine binds the *real* implementation — over
//! its `DepGraph` / `plsql-lineage::column_writers` and the trigger/VPD walk —
//! from the *consumer* side, exactly like every other engine tool.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

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
/// `OpaqueDynamic` / unloaded / cycle all map to `Unknown`. Statement-level
/// `Unknown` is fail-closed only when the classifier is explicitly tightened.
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
/// as side-effecting. Statement-level `Unknown` is tightened only when a real
/// engine-bound classifier opts in.
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
    /// `UnknownOracle` preserves the engine-free baseline: a UDF-free plain
    /// SELECT stays `Safe` unless an oracle explicitly returns
    /// `ProvenSideEffecting`. Consumers that bind a real engine oracle opt into
    /// statement-level `Unknown` tightening with
    /// `Classifier::with_statement_unknown_guarded`, making any non-proven base
    /// object force `≥ Guarded`.
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

/// A schema-qualified, operator-declared routine identity suitable for the
/// pure-function allowlist.
///
/// The guard deliberately accepts only two simple Oracle identifiers. Bare
/// names depend on `CURRENT_SCHEMA`; wildcards, database links, quoted names,
/// and package/member chains are not represented by [`ObjectRef`] with enough
/// fidelity to prove them safe, so they are rejected at the configuration
/// boundary rather than guessed at runtime.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OperatorPureFunction(ObjectRef);

impl OperatorPureFunction {
    /// Parse an exact `SCHEMA.FUNCTION` operator declaration.
    ///
    /// This does not infer purity from database metadata. A successfully parsed
    /// value becomes `ProvenReadOnly` only after an operator places it in an
    /// [`OperatorPureFunctionOracle`].
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

    /// The canonical schema-qualified identity used for audit/config display.
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

/// Why an operator-declared pure function was rejected before it could reach
/// the classifier. Configuration maps these variants to actionable errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperatorPureFunctionError {
    /// A bare routine name cannot be resolved without ambient schema state.
    MissingSchema,
    /// More than `SCHEMA.FUNCTION` was supplied; package chains are ambiguous
    /// at this engine-free seam.
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

/// A narrow [`SideEffectOracle`] whose proof is an operator's exact,
/// schema-qualified pure-function declaration.
///
/// This is authority, not inference: declarations are validated before the
/// server starts, and a routine not represented by one exact declaration
/// remains [`Purity::Unknown`]. It never consults Oracle metadata or broadens
/// a proof to a bare name, wildcard, package chain, or database link.
#[derive(Clone, Debug, Default)]
pub struct OperatorPureFunctionOracle {
    allowlist: HashSet<OperatorPureFunction>,
}

impl OperatorPureFunctionOracle {
    /// Build a pure-function oracle from already-validated exact declarations.
    #[must_use]
    pub fn new(allowlist: impl IntoIterator<Item = OperatorPureFunction>) -> Self {
        Self {
            allowlist: allowlist.into_iter().collect(),
        }
    }

    /// Return the exact operator declaration that admits `routine`, if any.
    #[must_use]
    pub fn admitted_routine(&self, routine: &ObjectRef) -> Option<&OperatorPureFunction> {
        self.allowlist
            .iter()
            .find(|allowed| allowed.matches(routine))
    }
}

impl SideEffectOracle for OperatorPureFunctionOracle {
    fn routine_purity(&self, routine: &ObjectRef) -> Purity {
        self.admitted_routine(routine)
            .map_or(Purity::Unknown, |_| Purity::ProvenReadOnly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn operator_pure_function_oracle_does_not_expand_a_proof() {
        let oracle =
            OperatorPureFunctionOracle::new([
                OperatorPureFunction::parse("app_read.lookup").expect("exact declaration")
            ]);

        assert_eq!(
            oracle.routine_purity(&ObjectRef::new(Some("APP_READ".to_owned()), "LOOKUP",)),
            Purity::ProvenReadOnly
        );
        for routine in [
            ObjectRef::new(None, "LOOKUP"),
            ObjectRef::new(Some("OTHER".to_owned()), "LOOKUP"),
            ObjectRef::new(Some("APP_READ".to_owned()), "OTHER"),
            ObjectRef::new(Some("APP_READ".to_owned()), "LOOKUP@REMOTE"),
        ] {
            assert_eq!(
                oracle.routine_purity(&routine),
                Purity::Unknown,
                "a declaration must not expand to {routine:?}"
            );
        }
    }
}
