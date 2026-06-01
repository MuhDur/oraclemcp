//! The operating-level model — "one user, all levels" (plan §6.6; bead P0-7).
//!
//! A session operates at an ordered [`OperatingLevel`]
//! (`READ_ONLY` < `READ_WRITE` < `DDL` < `ADMIN`), defaulting to `READ_ONLY`.
//! Every statement is mapped by the classifier (P1-1) to a *required* level;
//! [`SessionLevelState::evaluate`] is the enforcement point that decides
//! Allow / RequireStepUp / Blocked.
//!
//! The **ceiling** (`max_level`) is a per-target-database property of the
//! connection profile and the primary control: nothing — token, confirmation,
//! OAuth scope, or config reload — can raise it at runtime (there is no API to
//! raise it; [`SessionLevelState`] is constructed with its ceiling and only
//! ever lowers the *effective* ceiling). Over HTTP an OAuth scope can only
//! lower the effective ceiling further, never raise it (§7.1).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::clock::MonotonicDeadline;

/// The ordered operating levels. `Ord` follows declaration order, so
/// `ReadOnly < ReadWrite < Ddl < Admin`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum OperatingLevel {
    /// SELECT (no unproven function call), introspection, plan analysis via
    /// `DBMS_XPLAN.DISPLAY_CURSOR`, safe sampling. Always allowed.
    #[default]
    ReadOnly,
    /// INSERT / UPDATE / DELETE / MERGE, transaction control, `DBMS_OUTPUT`.
    ReadWrite,
    /// CREATE / ALTER / DROP / TRUNCATE, CREATE OR REPLACE, recompile.
    Ddl,
    /// GRANT / REVOKE, ALTER USER/SYSTEM, cross-schema DCL.
    Admin,
}

impl OperatingLevel {
    /// The stable wire string for this level.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OperatingLevel::ReadOnly => "READ_ONLY",
            OperatingLevel::ReadWrite => "READ_WRITE",
            OperatingLevel::Ddl => "DDL",
            OperatingLevel::Admin => "ADMIN",
        }
    }

    /// Parse a flat operating-level string (trimmed, case-insensitive) — the
    /// inverse of [`Self::as_str`]. `None` for an unrecognized level. The single
    /// source of truth for the operating-level vocabulary across the server.
    #[must_use]
    pub fn parse(s: &str) -> Option<OperatingLevel> {
        match s.trim().to_ascii_uppercase().as_str() {
            "READ_ONLY" => Some(OperatingLevel::ReadOnly),
            "READ_WRITE" => Some(OperatingLevel::ReadWrite),
            "DDL" => Some(OperatingLevel::Ddl),
            "ADMIN" => Some(OperatingLevel::Admin),
            _ => None,
        }
    }

    /// All levels, ascending.
    #[must_use]
    pub fn all() -> [OperatingLevel; 4] {
        [
            OperatingLevel::ReadOnly,
            OperatingLevel::ReadWrite,
            OperatingLevel::Ddl,
            OperatingLevel::Admin,
        ]
    }
}

/// The classifier's risk tier for a statement (plan §5.3). Distinct from the
/// required [`OperatingLevel`]: danger is a *risk* dimension, the required
/// level is *what capability* the statement needs. The classifier (P1-1)
/// produces both.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum DangerLevel {
    /// Proven read-only: SELECT/WITH with no unproven function call,
    /// `DBMS_OUTPUT.PUT_LINE`.
    Safe,
    /// Writes data or has a bounded effect: INSERT, UPDATE/DELETE with WHERE,
    /// MERGE, CTAS, `SELECT … FOR UPDATE`, COMMIT/ROLLBACK, EXPLAIN PLAN.
    Guarded,
    /// DROP, TRUNCATE, DELETE/UPDATE without WHERE, GRANT/REVOKE, ALTER
    /// USER/SYSTEM, CREATE OR REPLACE on an existing object.
    Destructive,
    /// Never dispatchable: dynamic SQL via string concat, `UTL_FILE` write,
    /// outbound network, unconditional DDL inside PL/SQL, or any unbalanced
    /// multi-statement batch (fail-closed on desync).
    #[default]
    Forbidden,
}

impl DangerLevel {
    /// A conservative default mapping from danger to the minimum operating
    /// level, used by the purely-syntactic core before the classifier refines
    /// `required_level` for a specific statement. `Forbidden` maps to `None` —
    /// no level ever permits it.
    #[must_use]
    pub fn default_required_level(self) -> Option<OperatingLevel> {
        match self {
            DangerLevel::Safe => Some(OperatingLevel::ReadOnly),
            DangerLevel::Guarded => Some(OperatingLevel::ReadWrite),
            DangerLevel::Destructive => Some(OperatingLevel::Ddl),
            DangerLevel::Forbidden => None,
        }
    }
}

/// The reason a call was hard-blocked (not merely gated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockReason {
    /// The required level exceeds the (effective) profile ceiling — escalation
    /// is impossible, not merely un-approved.
    ExceedsCeiling {
        /// The level the statement needs.
        required: OperatingLevel,
        /// The effective ceiling that forbids it.
        ceiling: OperatingLevel,
    },
    /// The statement is `Forbidden` and is never dispatchable at any level.
    Forbidden,
}

/// The level-gate decision for a statement of a given required level.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LevelDecision {
    /// The session's effective level already permits the statement.
    Allow,
    /// A human step-up to `target` is required (the gate, §7.2). Reachable —
    /// `target` is within the ceiling.
    RequireStepUp {
        /// The level the session must reach.
        target: OperatingLevel,
    },
    /// Hard-blocked; escalation cannot help.
    Blocked {
        /// Why.
        reason: BlockReason,
    },
}

/// Escalation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum EscalationError {
    /// The requested level is above the immutable profile ceiling.
    #[error(
        "requested level {requested} exceeds the profile ceiling {ceiling} (immutable for the life of the process)"
    )]
    ExceedsCeiling {
        /// The level requested.
        requested: OperatingLevel,
        /// The ceiling.
        ceiling: OperatingLevel,
    },
}

impl std::fmt::Display for OperatingLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A temporary, monotonically-expiring elevation window (§6.6): the session
/// runs at `level` until the deadline, then auto-drops back.
#[derive(Debug, Clone, Copy)]
struct Elevation {
    level: OperatingLevel,
    deadline: MonotonicDeadline,
}

/// The per-session operating-level state machine.
#[derive(Debug, Clone)]
pub struct SessionLevelState {
    current_level: OperatingLevel,
    max_level: OperatingLevel,
    protected: bool,
    scope_ceiling: Option<OperatingLevel>,
    elevation: Option<Elevation>,
}

impl SessionLevelState {
    /// A new session at `READ_ONLY`, capped at `max_level`. `protected` marks a
    /// production profile (the ceiling is documented as immutable; this type
    /// has no API to raise it regardless).
    #[must_use]
    pub fn new(max_level: OperatingLevel, protected: bool) -> Self {
        SessionLevelState {
            current_level: OperatingLevel::ReadOnly,
            max_level,
            protected,
            scope_ceiling: None,
            elevation: None,
        }
    }

    /// The profile ceiling (before any scope narrowing).
    #[must_use]
    pub fn max_level(&self) -> OperatingLevel {
        self.max_level
    }

    /// Whether this is a `protected` (production) profile.
    #[must_use]
    pub fn is_protected(&self) -> bool {
        self.protected
    }

    /// The effective ceiling = `min(profile ceiling, scope ceiling)`. An OAuth
    /// scope can only ever lower this, never raise it (§7.1).
    #[must_use]
    pub fn effective_ceiling(&self) -> OperatingLevel {
        match self.scope_ceiling {
            Some(scope) => scope.min(self.max_level),
            None => self.max_level,
        }
    }

    /// The effective current level = `max(current, active elevation window)`,
    /// clamped to the effective ceiling. An expired window contributes nothing.
    #[must_use]
    pub fn effective_level(&self) -> OperatingLevel {
        let from_window = self
            .elevation
            .filter(|e| !e.deadline.is_expired())
            .map(|e| e.level)
            .unwrap_or(OperatingLevel::ReadOnly);
        self.current_level
            .max(from_window)
            .min(self.effective_ceiling())
    }

    /// Whether an elevation window is currently active (non-expired).
    #[must_use]
    pub fn has_active_elevation(&self) -> bool {
        self.elevation.is_some_and(|e| !e.deadline.is_expired())
    }

    /// Apply (or tighten) the scope-derived ceiling. Monotone: the new scope
    /// ceiling can only lower the effective ceiling — a higher scope is ignored
    /// (it never raises the profile ceiling).
    pub fn apply_scope_ceiling(&mut self, scope: OperatingLevel) {
        self.scope_ceiling = Some(match self.scope_ceiling {
            Some(existing) => existing.min(scope),
            None => scope,
        });
    }

    /// Decide the gate outcome for a statement requiring `required` (or
    /// `Forbidden`, signalled by `required = None`).
    #[must_use]
    pub fn evaluate(&self, required: Option<OperatingLevel>) -> LevelDecision {
        let Some(required) = required else {
            return LevelDecision::Blocked {
                reason: BlockReason::Forbidden,
            };
        };
        let ceiling = self.effective_ceiling();
        if required > ceiling {
            return LevelDecision::Blocked {
                reason: BlockReason::ExceedsCeiling { required, ceiling },
            };
        }
        if required <= self.effective_level() {
            LevelDecision::Allow
        } else {
            LevelDecision::RequireStepUp { target: required }
        }
    }

    /// Grant a time-boxed elevation window to `target` for `ttl` (monotonic).
    /// Rejected (hard) if `target` exceeds the effective ceiling — on a
    /// `protected` profile with `max_level = READ_ONLY` this rejects every
    /// write/DDL/admin escalation, by design.
    pub fn escalate_window(
        &mut self,
        target: OperatingLevel,
        ttl: std::time::Duration,
    ) -> Result<(), EscalationError> {
        let ceiling = self.effective_ceiling();
        if target > ceiling {
            return Err(EscalationError::ExceedsCeiling {
                requested: target,
                ceiling,
            });
        }
        self.elevation = Some(Elevation {
            level: target,
            deadline: MonotonicDeadline::after(ttl),
        });
        Ok(())
    }

    /// Drop any active elevation window, returning to the base current level.
    pub fn drop_elevation(&mut self) {
        self.elevation = None;
    }

    /// Persistently raise the base current level (still bounded by the
    /// ceiling). Used for a deliberate, gated de-escalation-resistant change;
    /// most escalations should use [`escalate_window`].
    pub fn set_current_level(&mut self, target: OperatingLevel) -> Result<(), EscalationError> {
        let ceiling = self.effective_ceiling();
        if target > ceiling {
            return Err(EscalationError::ExceedsCeiling {
                requested: target,
                ceiling,
            });
        }
        self.current_level = target;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn ordering_is_strict_superset() {
        assert!(OperatingLevel::ReadOnly < OperatingLevel::ReadWrite);
        assert!(OperatingLevel::ReadWrite < OperatingLevel::Ddl);
        assert!(OperatingLevel::Ddl < OperatingLevel::Admin);
        assert_eq!(OperatingLevel::default(), OperatingLevel::ReadOnly);
    }

    #[test]
    fn read_only_default_allows_reads_and_gates_writes() {
        let s = SessionLevelState::new(OperatingLevel::Admin, false);
        assert_eq!(
            s.evaluate(Some(OperatingLevel::ReadOnly)),
            LevelDecision::Allow
        );
        assert_eq!(
            s.evaluate(Some(OperatingLevel::ReadWrite)),
            LevelDecision::RequireStepUp {
                target: OperatingLevel::ReadWrite
            }
        );
    }

    #[test]
    fn forbidden_is_blocked_not_gated() {
        let s = SessionLevelState::new(OperatingLevel::Admin, false);
        assert_eq!(
            s.evaluate(None),
            LevelDecision::Blocked {
                reason: BlockReason::Forbidden
            }
        );
    }

    #[test]
    fn protected_ceiling_blocks_escalation_entirely() {
        let mut s = SessionLevelState::new(OperatingLevel::ReadOnly, true);
        // A write needs READ_WRITE, which exceeds the READ_ONLY ceiling: hard
        // blocked, not merely gated.
        assert_eq!(
            s.evaluate(Some(OperatingLevel::ReadWrite)),
            LevelDecision::Blocked {
                reason: BlockReason::ExceedsCeiling {
                    required: OperatingLevel::ReadWrite,
                    ceiling: OperatingLevel::ReadOnly
                }
            }
        );
        // And escalation is refused outright — nothing can raise the ceiling.
        assert_eq!(
            s.escalate_window(OperatingLevel::ReadWrite, Duration::from_secs(900)),
            Err(EscalationError::ExceedsCeiling {
                requested: OperatingLevel::ReadWrite,
                ceiling: OperatingLevel::ReadOnly
            })
        );
    }

    #[test]
    fn elevation_window_allows_then_auto_drops_on_expiry() {
        let mut s = SessionLevelState::new(OperatingLevel::Ddl, false);
        s.escalate_window(OperatingLevel::ReadWrite, Duration::from_secs(900))
            .expect("granted");
        assert!(s.has_active_elevation());
        assert_eq!(
            s.evaluate(Some(OperatingLevel::ReadWrite)),
            LevelDecision::Allow
        );
        assert_eq!(s.effective_level(), OperatingLevel::ReadWrite);

        // Force the window expired and confirm the session auto-drops.
        s.elevation = Some(Elevation {
            level: OperatingLevel::ReadWrite,
            deadline: MonotonicDeadline::already_expired(),
        });
        assert!(!s.has_active_elevation());
        assert_eq!(s.effective_level(), OperatingLevel::ReadOnly);
        assert_eq!(
            s.evaluate(Some(OperatingLevel::ReadWrite)),
            LevelDecision::RequireStepUp {
                target: OperatingLevel::ReadWrite
            }
        );
    }

    #[test]
    fn stale_generation_window_is_treated_as_expired() {
        let mut s = SessionLevelState::new(OperatingLevel::Ddl, false);
        s.elevation = Some(Elevation {
            level: OperatingLevel::ReadWrite,
            deadline: MonotonicDeadline::stale_generation(),
        });
        // A prior-process-generation window never re-grants elevation.
        assert!(!s.has_active_elevation());
        assert_eq!(s.effective_level(), OperatingLevel::ReadOnly);
    }

    #[test]
    fn scope_can_only_lower_the_ceiling() {
        let mut s = SessionLevelState::new(OperatingLevel::Ddl, false);
        s.apply_scope_ceiling(OperatingLevel::ReadWrite);
        assert_eq!(s.effective_ceiling(), OperatingLevel::ReadWrite);
        // A higher scope cannot raise it back.
        s.apply_scope_ceiling(OperatingLevel::Admin);
        assert_eq!(s.effective_ceiling(), OperatingLevel::ReadWrite);
        // DDL now exceeds the scoped ceiling.
        assert!(matches!(
            s.evaluate(Some(OperatingLevel::Ddl)),
            LevelDecision::Blocked { .. }
        ));
    }

    #[test]
    fn danger_default_required_level_mapping() {
        assert_eq!(
            DangerLevel::Safe.default_required_level(),
            Some(OperatingLevel::ReadOnly)
        );
        assert_eq!(
            DangerLevel::Guarded.default_required_level(),
            Some(OperatingLevel::ReadWrite)
        );
        assert_eq!(
            DangerLevel::Destructive.default_required_level(),
            Some(OperatingLevel::Ddl)
        );
        assert_eq!(DangerLevel::Forbidden.default_required_level(), None);
    }
}
