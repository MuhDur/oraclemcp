//! The `SideEffectOracle` port + three-valued `Purity` verdict (plan §5.3;
//! beads P1-1d, P1-1e). This is the boundary-preserving seam (§0 hard rule 1):
//! the port lives in the engine-free guard with a default impl that returns
//! `Unknown`, so the classifier ships fully functional with no engine
//! dependency. Routine `Unknown` is always fail-closed; statement `Unknown`
//! stays permissive until a real engine binding opts into SELECT-side-effect
//! tightening. The PL/SQL engine binds the *real* implementation — over
//! its `DepGraph` / `plsql-lineage::column_writers` and the trigger/VPD walk —
//! from the *consumer* side, exactly like every other engine tool.

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
}
