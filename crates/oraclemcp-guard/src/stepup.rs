//! Step-up confirmation policy + state machine (plan §6.6, §7.2; bead P1-10
//! / P1-10c, P1-10d). The guard owns the challenge/approval/level state; the
//! *delivery* (MCP elicitation selector, poll/Task) is `oraclemcp-auth`.
//!
//! When the classifier says `required > current` and no approval is present,
//! the dispatcher issues a [`StepUpChallenge`] (returned to the agent as
//! `CHALLENGE_REQUIRED`) and the agent polls — never a long-held request
//! (§7.2). The operator's choice resolves the challenge to one of four
//! outcomes; an approval becomes either a single-use, SQL-digest-bound grant
//! (per-statement) or a time-boxed, monotonic elevation window (auto-drops).
//! Headless CI uses a pre-issued [`CiToken`] (a real credential, not the
//! self-issued allow-once token).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::clock::MonotonicDeadline;
use crate::levels::OperatingLevel;
use crate::token::sql_digest;

/// The selector options offered for a step-up (§7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpOption {
    /// Approve this exact statement once (single-use, digest-bound).
    ApproveOnce,
    /// Approve the target level for a time-boxed window (seconds).
    ApproveWindow {
        /// Window TTL in seconds.
        ttl_secs: u64,
    },
    /// Run the ground-truth savepoint preview only (no commit).
    PreviewOnly,
    /// Deny.
    Deny,
}

/// How a challenge was resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpResolution {
    /// Approved this exact statement once.
    ApprovedOnce,
    /// Approved a time-boxed elevation window to `level`.
    ApprovedWindow {
        /// The granted level.
        level: OperatingLevel,
        /// Window TTL in seconds.
        ttl_secs: u64,
    },
    /// Preview-only (no execution).
    PreviewOnly,
    /// Denied.
    Denied,
}

/// The status an agent sees when polling a challenge (poll/Task — P1-10b).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ChallengeStatus {
    /// Still awaiting the operator's choice.
    Pending,
    /// Resolved; the agent may now proceed per the resolution.
    Resolved {
        /// The resolution.
        resolution: StepUpResolution,
    },
    /// Unknown id or the challenge expired before resolution.
    ExpiredOrUnknown,
}

/// Why resolving a step-up challenge failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StepUpError {
    /// No challenge with that id.
    #[error("step-up challenge not found")]
    NotFound,
    /// The challenge expired before resolution.
    #[error("step-up challenge expired")]
    Expired,
    /// The CI token does not authorize the target level.
    #[error("CI token not authorized for the requested level")]
    Unauthorized,
}

/// A pending step-up challenge handed to the agent as `CHALLENGE_REQUIRED`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepUpChallenge {
    /// Opaque challenge id the agent polls with.
    pub challenge_id: String,
    /// The operating level the statement needs.
    pub target_level: OperatingLevel,
    /// `sha256:` digest of the statement the approval will be bound to.
    pub sql_digest: String,
    /// The selector options the client renders.
    pub options: Vec<StepUpOption>,
    /// A human-readable summary of what is being requested.
    pub summary: String,
}

/// A pre-issued, scoped, time-boxed CI token for non-interactive escalation
/// (P1-10d). A real credential to protect — unlike the self-issued allow-once
/// token, this auto-approves up to its `scope` ceiling.
#[derive(Clone, Debug)]
pub struct CiToken {
    secret: String,
    scope: OperatingLevel,
    deadline: MonotonicDeadline,
}

impl CiToken {
    /// Issue a CI token authorizing escalation up to `scope` for `ttl`.
    #[must_use]
    pub fn issue(secret: impl Into<String>, scope: OperatingLevel, ttl: Duration) -> Self {
        CiToken {
            secret: secret.into(),
            scope,
            deadline: MonotonicDeadline::after(ttl),
        }
    }

    /// Whether this token authorizes `target` right now.
    #[must_use]
    pub fn authorizes(&self, presented_secret: &str, target: OperatingLevel) -> bool {
        !self.deadline.is_expired() && presented_secret == self.secret && target <= self.scope
    }
}

struct Pending {
    target_level: OperatingLevel,
    sql_digest: String,
    deadline: MonotonicDeadline,
    resolution: Option<StepUpResolution>,
}

/// Tracks outstanding step-up challenges and their resolutions.
#[derive(Default)]
pub struct StepUpRegistry {
    challenges: Mutex<HashMap<String, Pending>>,
    counter: AtomicU64,
}

impl StepUpRegistry {
    /// A new registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a challenge for a statement needing `target_level`, valid `ttl`.
    pub fn issue(
        &self,
        target_level: OperatingLevel,
        sql: &str,
        summary: impl Into<String>,
        ttl: Duration,
    ) -> StepUpChallenge {
        let digest = sql_digest(sql);
        let id = format!(
            "chal-{}-{}",
            std::process::id(),
            self.counter.fetch_add(1, Ordering::SeqCst)
        );
        self.challenges
            .lock()
            .expect("stepup mutex poisoned")
            .insert(
                id.clone(),
                Pending {
                    target_level,
                    sql_digest: digest.clone(),
                    deadline: MonotonicDeadline::after(ttl),
                    resolution: None,
                },
            );
        StepUpChallenge {
            challenge_id: id,
            target_level,
            sql_digest: digest,
            options: vec![
                StepUpOption::ApproveOnce,
                StepUpOption::ApproveWindow { ttl_secs: 900 },
                StepUpOption::PreviewOnly,
                StepUpOption::Deny,
            ],
            summary: summary.into(),
        }
    }

    /// The operator resolves a challenge by picking an option.
    pub fn resolve(
        &self,
        challenge_id: &str,
        option: StepUpOption,
    ) -> Result<StepUpResolution, StepUpError> {
        let mut challenges = self.challenges.lock().expect("stepup mutex poisoned");
        let pending = challenges
            .get_mut(challenge_id)
            .ok_or(StepUpError::NotFound)?;
        if pending.deadline.is_expired() {
            return Err(StepUpError::Expired);
        }
        let resolution = match option {
            StepUpOption::ApproveOnce => StepUpResolution::ApprovedOnce,
            StepUpOption::ApproveWindow { ttl_secs } => StepUpResolution::ApprovedWindow {
                level: pending.target_level,
                ttl_secs,
            },
            StepUpOption::PreviewOnly => StepUpResolution::PreviewOnly,
            StepUpOption::Deny => StepUpResolution::Denied,
        };
        pending.resolution = Some(resolution);
        Ok(resolution)
    }

    /// Resolve via a CI token (non-interactive) — auto-approves a window to the
    /// target level if the token authorizes it (P1-10d).
    pub fn resolve_with_ci_token(
        &self,
        challenge_id: &str,
        token: &CiToken,
        presented_secret: &str,
    ) -> Result<StepUpResolution, StepUpError> {
        let target = {
            let challenges = self.challenges.lock().expect("stepup mutex poisoned");
            let pending = challenges.get(challenge_id).ok_or(StepUpError::NotFound)?;
            if pending.deadline.is_expired() {
                return Err(StepUpError::Expired);
            }
            pending.target_level
        };
        if !token.authorizes(presented_secret, target) {
            return Err(StepUpError::Unauthorized);
        }
        self.resolve(challenge_id, StepUpOption::ApproveWindow { ttl_secs: 900 })
    }

    /// The agent polls a challenge's status (poll/Task — P1-10b).
    #[must_use]
    pub fn poll(&self, challenge_id: &str) -> ChallengeStatus {
        let challenges = self.challenges.lock().expect("stepup mutex poisoned");
        match challenges.get(challenge_id) {
            None => ChallengeStatus::ExpiredOrUnknown,
            Some(p) if p.deadline.is_expired() => ChallengeStatus::ExpiredOrUnknown,
            Some(p) => match p.resolution {
                Some(resolution) => ChallengeStatus::Resolved { resolution },
                None => ChallengeStatus::Pending,
            },
        }
    }

    /// Whether the resolved approval covers `sql` (single-use approvals are
    /// digest-bound — the executed statement must match what was approved).
    #[must_use]
    pub fn approval_matches_sql(&self, challenge_id: &str, sql: &str) -> bool {
        let challenges = self.challenges.lock().expect("stepup mutex poisoned");
        challenges
            .get(challenge_id)
            .is_some_and(|p| p.sql_digest == sql_digest(sql))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_offers_four_options() {
        let reg = StepUpRegistry::new();
        let c = reg.issue(
            OperatingLevel::ReadWrite,
            "UPDATE t SET x=1 WHERE id=2",
            "write",
            Duration::from_secs(300),
        );
        assert_eq!(c.target_level, OperatingLevel::ReadWrite);
        assert_eq!(c.options.len(), 4);
        assert!(c.options.contains(&StepUpOption::ApproveOnce));
        assert!(c.options.contains(&StepUpOption::Deny));
        assert_eq!(reg.poll(&c.challenge_id), ChallengeStatus::Pending);
    }

    #[test]
    fn approve_once_resolves_and_is_digest_bound() {
        let reg = StepUpRegistry::new();
        let sql = "UPDATE t SET x=1 WHERE id=2";
        let c = reg.issue(
            OperatingLevel::ReadWrite,
            sql,
            "w",
            Duration::from_secs(300),
        );
        reg.resolve(&c.challenge_id, StepUpOption::ApproveOnce)
            .expect("resolve");
        assert_eq!(
            reg.poll(&c.challenge_id),
            ChallengeStatus::Resolved {
                resolution: StepUpResolution::ApprovedOnce
            }
        );
        assert!(reg.approval_matches_sql(&c.challenge_id, "UPDATE   t SET x=1 WHERE id=2"));
        assert!(!reg.approval_matches_sql(&c.challenge_id, "DROP TABLE t"));
    }

    #[test]
    fn approve_window_carries_level_and_ttl() {
        let reg = StepUpRegistry::new();
        let c = reg.issue(
            OperatingLevel::Ddl,
            "DROP TABLE t",
            "ddl",
            Duration::from_secs(300),
        );
        let res = reg
            .resolve(
                &c.challenge_id,
                StepUpOption::ApproveWindow { ttl_secs: 600 },
            )
            .expect("resolve");
        assert_eq!(
            res,
            StepUpResolution::ApprovedWindow {
                level: OperatingLevel::Ddl,
                ttl_secs: 600
            }
        );
    }

    #[test]
    fn deny_resolves_denied() {
        let reg = StepUpRegistry::new();
        let c = reg.issue(
            OperatingLevel::ReadWrite,
            "UPDATE t SET x=1",
            "w",
            Duration::from_secs(300),
        );
        reg.resolve(&c.challenge_id, StepUpOption::Deny)
            .expect("resolve");
        assert_eq!(
            reg.poll(&c.challenge_id),
            ChallengeStatus::Resolved {
                resolution: StepUpResolution::Denied
            }
        );
    }

    #[test]
    fn expired_challenge_cannot_resolve_or_poll() {
        let reg = StepUpRegistry::new();
        let c = reg.issue(
            OperatingLevel::ReadWrite,
            "UPDATE t SET x=1",
            "w",
            Duration::from_secs(0),
        );
        assert!(
            reg.resolve(&c.challenge_id, StepUpOption::ApproveOnce)
                .is_err()
        );
        assert_eq!(reg.poll(&c.challenge_id), ChallengeStatus::ExpiredOrUnknown);
    }

    #[test]
    fn ci_token_authorizes_only_within_scope_and_ttl() {
        let token = CiToken::issue(
            "s3cret",
            OperatingLevel::ReadWrite,
            Duration::from_secs(3600),
        );
        assert!(token.authorizes("s3cret", OperatingLevel::ReadWrite));
        assert!(token.authorizes("s3cret", OperatingLevel::ReadOnly)); // below scope
        assert!(!token.authorizes("s3cret", OperatingLevel::Ddl)); // above scope
        assert!(!token.authorizes("wrong", OperatingLevel::ReadWrite));
        let expired = CiToken::issue("s", OperatingLevel::Admin, Duration::from_secs(0));
        assert!(!expired.authorizes("s", OperatingLevel::ReadOnly));
    }

    #[test]
    fn ci_token_resolves_a_challenge_non_interactively() {
        let reg = StepUpRegistry::new();
        let token = CiToken::issue("ci", OperatingLevel::ReadWrite, Duration::from_secs(3600));
        let c = reg.issue(
            OperatingLevel::ReadWrite,
            "UPDATE t SET x=1 WHERE id=1",
            "w",
            Duration::from_secs(300),
        );
        let res = reg
            .resolve_with_ci_token(&c.challenge_id, &token, "ci")
            .expect("ci resolve");
        assert!(matches!(res, StepUpResolution::ApprovedWindow { .. }));
        // A token scoped below the target cannot approve.
        let weak = CiToken::issue("ci", OperatingLevel::ReadOnly, Duration::from_secs(3600));
        let c2 = reg.issue(
            OperatingLevel::Ddl,
            "DROP TABLE t",
            "d",
            Duration::from_secs(300),
        );
        assert!(
            reg.resolve_with_ci_token(&c2.challenge_id, &weak, "ci")
                .is_err()
        );
    }
}
