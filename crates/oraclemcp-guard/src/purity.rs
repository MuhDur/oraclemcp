//! The `SideEffectOracle` port + three-valued `Purity` verdict (plan §5.3;
//! beads P1-1d, P1-1e). This is the boundary-preserving seam (§0 hard rule 1):
//! the port lives in the engine-free guard with a **default impl that returns
//! `Unknown` (fail-closed)**, so the classifier ships fully functional with no
//! engine dependency. The PL/SQL engine binds the *real* implementation — over
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

/// The three-valued purity verdict (§5.3, R15). **Only `ProvenReadOnly` permits
/// clearing a statement to `Safe`.** Absence of a write edge is `Unknown`, never
/// `Safe`; `Measured::Unmeasured` / `OpaqueDynamic` / unloaded / cycle all map
/// to `Unknown` → treated as side-effecting.
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
    /// The default: not proven either way → treated as `ProvenSideEffecting`
    /// (fail-closed).
    Unknown,
}

impl Purity {
    /// Whether this verdict permits clearing to `Safe`. Only `ProvenReadOnly`.
    #[must_use]
    pub fn permits_safe(self) -> bool {
        matches!(self, Purity::ProvenReadOnly)
    }
}

/// The engine-aware side-effect consult port. Every method **defaults to
/// `Unknown`** (fail-closed), so a guard with no engine bound treats every
/// user-defined function / statement as side-effecting.
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
    /// resolved `FROM`/`JOIN` tables + CTE/derived bodies). **Current phase
    /// (oracle-qm3q.8 / P1-1e):** the classifier escalates a UDF-free SELECT to
    /// `≥ Guarded` only on an explicit `ProvenSideEffecting` verdict, treating
    /// `Unknown` as the permissive default so the no-engine baseline (default
    /// `UnknownOracle` → every plain SELECT stays `Safe`) is preserved. A real
    /// engine oracle should return `ProvenSideEffecting` for any base object
    /// reaching a side-effecting trigger/VPD policy. Tightening this to fail
    /// closed on `Unknown` (any object not `ProvenReadOnly` forces ≥ Guarded,
    /// *including for SELECT*) is deferred to the engine-binding phase, when a
    /// real non-default oracle is bound and base-object resolution is trusted.
    fn statement_purity(&self, base_objects: &[ObjectRef]) -> Purity {
        let _ = base_objects;
        Purity::Unknown
    }
}

/// The default fail-closed oracle: everything is `Unknown`. Used until the
/// engine binds a real implementation from the consumer side.
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
