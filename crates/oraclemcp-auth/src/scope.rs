//! OAuth-scope → operating-level RBAC (plan §6.6, §7.1; bead P2-4).
//!
//! Progressive scopes `oracle:read` → `oracle:execute` → `oracle:admin` map to
//! the operating-level ceiling. **A scope can only LOWER the effective ceiling,
//! never raise it** — the effective ceiling is `min(profile max_level, scope
//! ceiling)`. Replay-hardening (single-use, SQL-digest-bound approvals; monotonic
//! auto-dropping elevation windows) is provided by `oraclemcp-guard`'s
//! `AllowOnceStore` / `StepUpRegistry` / `SessionLevelState` (P1-10), which this
//! layer composes.

use oraclemcp_guard::{OperatingLevel, SessionLevelState};

/// Map a single OAuth scope to the operating level it authorizes, if recognized.
#[must_use]
pub fn scope_to_level(scope: &str) -> Option<OperatingLevel> {
    match scope.trim() {
        "oracle:read" => Some(OperatingLevel::ReadOnly),
        "oracle:write" | "oracle:execute" => Some(OperatingLevel::ReadWrite),
        "oracle:ddl" => Some(OperatingLevel::Ddl),
        "oracle:admin" => Some(OperatingLevel::Admin),
        _ => None,
    }
}

/// The ceiling a set of granted scopes authorizes: the highest recognized
/// scope level, defaulting to `READ_ONLY` (the safe floor) when no `oracle:*`
/// scope is present.
#[must_use]
pub fn scopes_ceiling(scopes: &[&str]) -> OperatingLevel {
    scopes
        .iter()
        .filter_map(|s| scope_to_level(s))
        .max()
        .unwrap_or(OperatingLevel::ReadOnly)
}

/// Apply the granted scopes to a session: lowers the effective ceiling to
/// `min(existing, scope ceiling)` (monotone-down — never raises it).
pub fn apply_oauth_scopes(state: &mut SessionLevelState, scopes: &[&str]) {
    state.apply_scope_ceiling(scopes_ceiling(scopes));
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_guard::LevelDecision;

    #[test]
    fn scope_mapping() {
        assert_eq!(
            scope_to_level("oracle:read"),
            Some(OperatingLevel::ReadOnly)
        );
        assert_eq!(
            scope_to_level("oracle:execute"),
            Some(OperatingLevel::ReadWrite)
        );
        assert_eq!(scope_to_level("oracle:admin"), Some(OperatingLevel::Admin));
        assert_eq!(scope_to_level("unrelated"), None);
    }

    #[test]
    fn ceiling_is_highest_scope_default_read_only() {
        assert_eq!(
            scopes_ceiling(&["oracle:read", "oracle:execute"]),
            OperatingLevel::ReadWrite
        );
        assert_eq!(scopes_ceiling(&["oracle:admin"]), OperatingLevel::Admin);
        // No oracle:* scope -> the safe floor.
        assert_eq!(
            scopes_ceiling(&["profile", "email"]),
            OperatingLevel::ReadOnly
        );
        assert_eq!(scopes_ceiling(&[]), OperatingLevel::ReadOnly);
    }

    #[test]
    fn scope_can_only_lower_the_ceiling() {
        // Profile allows up to DDL; an oracle:read token narrows it to READ_ONLY.
        let mut state = SessionLevelState::new(OperatingLevel::Ddl, false);
        apply_oauth_scopes(&mut state, &["oracle:read"]);
        assert_eq!(state.effective_ceiling(), OperatingLevel::ReadOnly);
        // A subsequent higher scope cannot raise it back (monotone-down).
        apply_oauth_scopes(&mut state, &["oracle:admin"]);
        assert_eq!(state.effective_ceiling(), OperatingLevel::ReadOnly);
    }

    #[test]
    fn read_scope_blocks_a_write_at_the_gate() {
        let mut state = SessionLevelState::new(OperatingLevel::Admin, false);
        apply_oauth_scopes(&mut state, &["oracle:read"]);
        // A write (requires READ_WRITE) is hard-blocked by the scoped ceiling.
        assert!(matches!(
            state.evaluate(Some(OperatingLevel::ReadWrite)),
            LevelDecision::Blocked { .. }
        ));
        // A read is allowed.
        assert_eq!(
            state.evaluate(Some(OperatingLevel::ReadOnly)),
            LevelDecision::Allow
        );
    }

    #[test]
    fn execute_scope_permits_write_but_not_ddl() {
        let mut state = SessionLevelState::new(OperatingLevel::Admin, false);
        apply_oauth_scopes(&mut state, &["oracle:execute"]);
        // ReadWrite is within the scoped ceiling -> step-up reachable (not blocked).
        assert!(matches!(
            state.evaluate(Some(OperatingLevel::ReadWrite)),
            LevelDecision::RequireStepUp { .. }
        ));
        // DDL exceeds the scoped ceiling -> hard blocked.
        assert!(matches!(
            state.evaluate(Some(OperatingLevel::Ddl)),
            LevelDecision::Blocked { .. }
        ));
    }
}
