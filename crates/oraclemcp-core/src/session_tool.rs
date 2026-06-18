//! The unified `oracle_session` tool (plan §8.1; bead P1-SESS / oracle-qmwz.2.17).
//!
//! A single tool with action variants is the one front for the several stateful
//! actions otherwise spread across P0-4 (leases), P1-10 (escalation), P1-6
//! (`ALTER SESSION`), and P2-3 (transactions / `DBMS_OUTPUT`). This module owns
//! the **dispatch + flat schema + routing**, so the contract is implementable
//! as a unit. Each action routes to the right subsystem:
//!
//! - `lease_acquire` / `lease_renew` / `lease_release` → [`LeaseManager`] (P0-4);
//! - `escalate` / `de_escalate` → [`SessionLevelState`] gated by [`StepUpRegistry`] (P1-10);
//! - `get_session` / `set_session` → operating-level view + `ALTER SESSION`
//!   allowlist ([`is_allowed_alter_session`], P1-6);
//! - `enable_dbms_output` / `begin` / `commit` / `rollback` / `savepoint` →
//!   the lease's session (the transaction *bodies* land fully with P2-3).
//!
//! Lease-bound actions error without a live lease (the [`LeaseManager`] returns
//! `LeaseNotFound`). `lease_acquire` opens a connection engine/DB-side, so it is
//! injected via [`LeaseAcquirer`] to keep this router engine-free and testable.
//!
//! Product-surface decision for `oraclemcp` v0.3.x: this router is deliberately
//! not advertised by the read-only `oraclemcp` binary. It is guarded-write
//! machinery for the broader Oracle MCP family; surfacing it here would weaken
//! the binary's safe-by-default contract. If this tool is ever exposed, it
//! belongs behind a separate explicit opt-in surface with its own release gates.

use std::time::Duration;

use oraclemcp_db::{LeaseId, LeaseManager};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{
    ChallengeStatus, CiToken, EscalationError, OperatingLevel, SessionLevelState, StepUpRegistry,
    StepUpResolution, is_allowed_alter_session,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// Default elevation-window TTL granted on a step-up approval (§6.6).
pub const ESCALATION_WINDOW: Duration = Duration::from_secs(900);
/// Default step-up challenge TTL.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(900);

/// Opens a connection and acquires a lease engine/DB-side. Injected so the
/// router stays engine-free (the one-way boundary) and unit-testable.
pub trait LeaseAcquirer: Send + Sync {
    /// Acquire a lease for `profile`/`agent_identity` with `ttl`; return its id.
    fn acquire(
        &self,
        profile: &str,
        agent_identity: &str,
        ttl: Duration,
    ) -> Result<String, ErrorEnvelope>;
}

/// `oracle_session` arguments — one flat object discriminated by `action`.
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SessionAction {
    /// Acquire a session lease (opens + pins a physical session).
    LeaseAcquire {
        /// The connection profile to lease.
        profile: String,
        /// The calling agent's identity (stamped for auditing).
        agent_identity: String,
        /// Lease TTL; defaults to the server's lease TTL when omitted.
        #[serde(default)]
        ttl_seconds: Option<u64>,
    },
    /// Renew a lease's TTL.
    LeaseRenew {
        /// The lease handle.
        lease_id: String,
    },
    /// Release a lease (force-rollback + drop the session).
    LeaseRelease {
        /// The lease handle.
        lease_id: String,
    },
    /// Escalate the session operating level (confirmation-gated).
    Escalate {
        /// The target level (`READ_WRITE` / `DDL` / `ADMIN`).
        target_level: String,
        /// An in-flight challenge id to apply once the operator has resolved it.
        #[serde(default)]
        challenge_id: Option<String>,
        /// A CI-token secret for non-interactive approval.
        #[serde(default)]
        ci_secret: Option<String>,
    },
    /// Drop any active elevation window (always allowed — lowering is safe).
    DeEscalate,
    /// Report the session's operating-level state.
    GetSession,
    /// Apply an allowlisted `ALTER SESSION` statement on the leased session.
    SetSession {
        /// The lease handle.
        lease_id: String,
        /// The `ALTER SESSION` statement (validated against the allowlist).
        statement: String,
    },
    /// Enable `DBMS_OUTPUT` capture on the leased session.
    EnableDbmsOutput {
        /// The lease handle.
        lease_id: String,
    },
    /// Begin an explicit transaction on the leased session.
    Begin {
        /// The lease handle.
        lease_id: String,
    },
    /// Commit the leased session's transaction.
    Commit {
        /// The lease handle.
        lease_id: String,
    },
    /// Roll back the leased session's transaction.
    Rollback {
        /// The lease handle.
        lease_id: String,
    },
    /// Create a savepoint on the leased session.
    Savepoint {
        /// The lease handle.
        lease_id: String,
        /// The savepoint name (a simple identifier).
        name: String,
    },
}

/// The subsystems the router needs, bundled.
pub struct SessionDeps<'a> {
    /// The lease manager (P0-4).
    pub leases: &'a LeaseManager,
    /// The per-session operating-level state (P1-10), mutated by escalate/de-escalate.
    pub level: &'a mut SessionLevelState,
    /// The step-up gate (P1-10).
    pub stepup: &'a StepUpRegistry,
    /// Acquires leases engine/DB-side.
    pub acquirer: &'a dyn LeaseAcquirer,
    /// An optional operator CI token for non-interactive escalation.
    pub ci_token: Option<&'a CiToken>,
    /// Default lease TTL (seconds) when `lease_acquire` omits one.
    pub default_ttl_seconds: u64,
}

fn parse_target_level(raw: &str) -> Result<OperatingLevel, ErrorEnvelope> {
    OperatingLevel::parse(raw).ok_or_else(|| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!(
                "unknown operating level '{}'",
                raw.trim().to_ascii_uppercase()
            ),
        )
    })
}

fn escalation_error_to_envelope(e: EscalationError) -> ErrorEnvelope {
    match e {
        EscalationError::ExceedsCeiling { requested, ceiling } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "cannot escalate to {} — the profile ceiling {} is immutable",
                requested.as_str(),
                ceiling.as_str()
            ),
        ),
        _ => ErrorEnvelope::new(ErrorClass::PolicyDenied, "escalation rejected"),
    }
}

/// Snapshot the operating-level view (the `get_session` payload + escalate result).
fn level_view(level: &SessionLevelState) -> Value {
    json!({
        "current_level": level.effective_level().as_str(),
        "effective_ceiling": level.effective_ceiling().as_str(),
        "max_level": level.max_level().as_str(),
        "protected": level.is_protected(),
        "has_active_elevation": level.has_active_elevation(),
    })
}

fn apply_window(
    level: &mut SessionLevelState,
    target: OperatingLevel,
    ttl: Duration,
) -> Result<Value, ErrorEnvelope> {
    level
        .escalate_window(target, ttl)
        .map_err(escalation_error_to_envelope)?;
    Ok(json!({
        "action": "escalate",
        "status": "escalated",
        "granted_level": target.as_str(),
        "window_seconds": ttl.as_secs(),
        "session": level_view(level),
    }))
}

/// Dispatch one `oracle_session` action.
pub fn oracle_session(
    action: SessionAction,
    deps: &mut SessionDeps,
) -> Result<Value, ErrorEnvelope> {
    match action {
        SessionAction::LeaseAcquire {
            profile,
            agent_identity,
            ttl_seconds,
        } => {
            let ttl = Duration::from_secs(ttl_seconds.unwrap_or(deps.default_ttl_seconds));
            let lease_id = deps.acquirer.acquire(&profile, &agent_identity, ttl)?;
            Ok(json!({
                "action": "lease_acquire",
                "lease_id": lease_id,
                "ttl_seconds": ttl.as_secs(),
            }))
        }
        SessionAction::LeaseRenew { lease_id } => {
            let info = deps
                .leases
                .renew(&LeaseId(lease_id))
                .map_err(oraclemcp_db::DbError::into_envelope)?;
            let mut v = serde_json::to_value(&info).unwrap_or(Value::Null);
            if let Value::Object(map) = &mut v {
                map.insert("action".to_owned(), json!("lease_renew"));
            }
            Ok(v)
        }
        SessionAction::LeaseRelease { lease_id } => {
            deps.leases.release(&LeaseId(lease_id.clone()));
            Ok(json!({ "action": "lease_release", "lease_id": lease_id, "released": true }))
        }
        SessionAction::DeEscalate => {
            deps.level.drop_elevation();
            Ok(
                json!({ "action": "de_escalate", "status": "de_escalated", "session": level_view(deps.level) }),
            )
        }
        SessionAction::GetSession => {
            Ok(json!({ "action": "get_session", "session": level_view(deps.level) }))
        }
        SessionAction::SetSession {
            lease_id,
            statement,
        } => {
            // Allowlist FIRST (the safety check); only then route to the session.
            if !is_allowed_alter_session(&statement) {
                return Err(ErrorEnvelope::new(
                    ErrorClass::ForbiddenStatement,
                    format!("ALTER SESSION not on the allowlist: {statement:?}"),
                ));
            }
            deps.leases
                .apply_session_statement(&LeaseId(lease_id), &statement)
                .map_err(oraclemcp_db::DbError::into_envelope)?;
            Ok(json!({ "action": "set_session", "applied": statement }))
        }
        SessionAction::EnableDbmsOutput { lease_id } => {
            deps.leases
                .enable_dbms_output(&LeaseId(lease_id))
                .map_err(oraclemcp_db::DbError::into_envelope)?;
            Ok(json!({ "action": "enable_dbms_output", "enabled": true }))
        }
        SessionAction::Begin { lease_id } => {
            deps.leases
                .begin_transaction(&LeaseId(lease_id))
                .map_err(oraclemcp_db::DbError::into_envelope)?;
            Ok(json!({ "action": "begin", "in_transaction": true }))
        }
        SessionAction::Commit { lease_id } => {
            deps.leases
                .commit(&LeaseId(lease_id))
                .map_err(oraclemcp_db::DbError::into_envelope)?;
            Ok(json!({ "action": "commit", "in_transaction": false }))
        }
        SessionAction::Rollback { lease_id } => {
            deps.leases
                .rollback(&LeaseId(lease_id))
                .map_err(oraclemcp_db::DbError::into_envelope)?;
            Ok(json!({ "action": "rollback", "in_transaction": false }))
        }
        SessionAction::Savepoint { lease_id, name } => {
            deps.leases
                .savepoint(&LeaseId(lease_id), &name)
                .map_err(oraclemcp_db::DbError::into_envelope)?;
            Ok(json!({ "action": "savepoint", "name": name }))
        }
        SessionAction::Escalate {
            target_level,
            challenge_id,
            ci_secret,
        } => {
            let target = parse_target_level(&target_level)?;
            match challenge_id {
                // No challenge yet → mint one and ask the operator to confirm.
                None => {
                    let chal = deps.stepup.issue(
                        target,
                        &format!("ESCALATE SESSION TO {}", target.as_str()),
                        format!("Escalate session operating level to {}", target.as_str()),
                        CHALLENGE_TTL,
                    );
                    Ok(json!({
                        "action": "escalate",
                        "status": "challenge_required",
                        "challenge_id": chal.challenge_id,
                        "target_level": target.as_str(),
                        "summary": chal.summary,
                    }))
                }
                Some(cid) => {
                    // Non-interactive CI-token approval.
                    if let (Some(secret), Some(token)) = (ci_secret.as_deref(), deps.ci_token) {
                        let res = deps
                            .stepup
                            .resolve_with_ci_token(&cid, token, secret)
                            .map_err(|e| {
                                ErrorEnvelope::new(
                                    ErrorClass::ChallengeRequired,
                                    format!("CI-token approval failed: {e}"),
                                )
                            })?;
                        return resolution_to_result(deps.level, target, res);
                    }
                    // Interactive: poll the (operator-resolved) challenge.
                    match deps.stepup.poll(&cid) {
                        ChallengeStatus::Pending => Ok(json!({
                            "action": "escalate", "status": "pending", "challenge_id": cid,
                        })),
                        ChallengeStatus::Resolved { resolution } => {
                            resolution_to_result(deps.level, target, resolution)
                        }
                        ChallengeStatus::ExpiredOrUnknown => Err(ErrorEnvelope::new(
                            ErrorClass::ChallengeRequired,
                            "step-up challenge expired or unknown; request a fresh escalation",
                        )),
                    }
                }
            }
        }
    }
}

fn resolution_to_result(
    level: &mut SessionLevelState,
    target: OperatingLevel,
    resolution: StepUpResolution,
) -> Result<Value, ErrorEnvelope> {
    match resolution {
        StepUpResolution::ApprovedWindow {
            level: granted,
            ttl_secs,
        } => apply_window(level, granted, Duration::from_secs(ttl_secs)),
        StepUpResolution::ApprovedOnce => {
            // A session escalation needs a window; a single-statement approval
            // does not raise the session level. Direct the agent to use the
            // per-statement execute path instead.
            Err(ErrorEnvelope::new(
                ErrorClass::PolicyDenied,
                "approved once (per-statement) — use oracle_query_execute; session escalation needs an approved window",
            ))
        }
        StepUpResolution::PreviewOnly => Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "approved preview-only — no session escalation granted",
        )),
        StepUpResolution::Denied => Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            format!("escalation to {} was denied", target.as_str()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_guard::StepUpOption;

    struct OkAcquirer;
    impl LeaseAcquirer for OkAcquirer {
        fn acquire(
            &self,
            profile: &str,
            _id: &str,
            _ttl: Duration,
        ) -> Result<String, ErrorEnvelope> {
            Ok(format!("lease-for-{profile}"))
        }
    }

    fn deps<'a>(
        leases: &'a LeaseManager,
        level: &'a mut SessionLevelState,
        stepup: &'a StepUpRegistry,
        acquirer: &'a dyn LeaseAcquirer,
    ) -> SessionDeps<'a> {
        SessionDeps {
            leases,
            level,
            stepup,
            acquirer,
            ci_token: None,
            default_ttl_seconds: 300,
        }
    }

    fn parse(json_str: &str) -> SessionAction {
        serde_json::from_str(json_str).expect("parse action")
    }

    #[test]
    fn lease_acquire_routes_to_the_acquirer() {
        let leases = LeaseManager::new();
        let mut level = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        let stepup = StepUpRegistry::new();
        let acq = OkAcquirer;
        let mut d = deps(&leases, &mut level, &stepup, &acq);
        let out = oracle_session(
            parse(r#"{"action":"lease_acquire","profile":"dev","agent_identity":"a"}"#),
            &mut d,
        )
        .expect("acquire ok");
        assert_eq!(out["lease_id"], json!("lease-for-dev"));
        assert_eq!(out["ttl_seconds"], json!(300));
    }

    #[test]
    fn lease_bound_actions_error_without_a_lease() {
        let leases = LeaseManager::new();
        let mut level = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        let stepup = StepUpRegistry::new();
        let acq = OkAcquirer;
        let mut d = deps(&leases, &mut level, &stepup, &acq);
        for action in [
            r#"{"action":"lease_renew","lease_id":"nope"}"#,
            r#"{"action":"begin","lease_id":"nope"}"#,
            r#"{"action":"commit","lease_id":"nope"}"#,
            r#"{"action":"rollback","lease_id":"nope"}"#,
            r#"{"action":"savepoint","lease_id":"nope","name":"sp1"}"#,
            r#"{"action":"enable_dbms_output","lease_id":"nope"}"#,
        ] {
            let err = oracle_session(parse(action), &mut d).expect_err(action);
            // LeaseNotFound maps to a RuntimeStateRequired/lease envelope, never a panic.
            assert!(
                matches!(
                    err.error_class,
                    ErrorClass::LeaseRequired
                        | ErrorClass::RuntimeStateRequired
                        | ErrorClass::Internal
                ),
                "{action}: unexpected class {:?}",
                err.error_class
            );
        }
    }

    #[test]
    fn set_session_rejects_non_allowlisted_alter_session() {
        let leases = LeaseManager::new();
        let mut level = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        let stepup = StepUpRegistry::new();
        let acq = OkAcquirer;
        let mut d = deps(&leases, &mut level, &stepup, &acq);
        let err = oracle_session(
            parse(r#"{"action":"set_session","lease_id":"l","statement":"ALTER SESSION SET CONTAINER = CDB$ROOT"}"#),
            &mut d,
        )
        .expect_err("forbidden");
        assert_eq!(err.error_class, ErrorClass::ForbiddenStatement);
    }

    #[test]
    fn escalate_without_challenge_requests_confirmation() {
        let leases = LeaseManager::new();
        let mut level = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        let stepup = StepUpRegistry::new();
        let acq = OkAcquirer;
        let mut d = deps(&leases, &mut level, &stepup, &acq);
        let out = oracle_session(
            parse(r#"{"action":"escalate","target_level":"READ_WRITE"}"#),
            &mut d,
        )
        .expect("challenge issued");
        assert_eq!(out["status"], json!("challenge_required"));
        assert!(out["challenge_id"].as_str().unwrap().starts_with("chal-"));
    }

    #[test]
    fn escalate_applies_an_approved_window() {
        let leases = LeaseManager::new();
        let mut level = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        let stepup = StepUpRegistry::new();
        let acq = OkAcquirer;
        // Issue + operator-approve a window to READ_WRITE out of band.
        let chal = stepup.issue(
            OperatingLevel::ReadWrite,
            "ESCALATE SESSION TO READ_WRITE",
            "x",
            CHALLENGE_TTL,
        );
        stepup
            .resolve(
                &chal.challenge_id,
                StepUpOption::ApproveWindow { ttl_secs: 600 },
            )
            .expect("resolve");
        let mut d = deps(&leases, &mut level, &stepup, &acq);
        let out = oracle_session(
            parse(&format!(
                r#"{{"action":"escalate","target_level":"READ_WRITE","challenge_id":"{}"}}"#,
                chal.challenge_id
            )),
            &mut d,
        )
        .expect("escalated");
        assert_eq!(out["status"], json!("escalated"));
        assert!(d.level.has_active_elevation());
        assert_eq!(d.level.effective_level(), OperatingLevel::ReadWrite);
    }

    #[test]
    fn escalate_above_ceiling_is_rejected() {
        let leases = LeaseManager::new();
        // Protected READ_ONLY ceiling: no escalation possible.
        let mut level = SessionLevelState::new(OperatingLevel::ReadOnly, true);
        let stepup = StepUpRegistry::new();
        let acq = OkAcquirer;
        let chal = stepup.issue(
            OperatingLevel::Ddl,
            "ESCALATE SESSION TO DDL",
            "x",
            CHALLENGE_TTL,
        );
        stepup
            .resolve(
                &chal.challenge_id,
                StepUpOption::ApproveWindow { ttl_secs: 600 },
            )
            .expect("resolve");
        let mut d = deps(&leases, &mut level, &stepup, &acq);
        let err = oracle_session(
            parse(&format!(
                r#"{{"action":"escalate","target_level":"DDL","challenge_id":"{}"}}"#,
                chal.challenge_id
            )),
            &mut d,
        )
        .expect_err("ceiling pinned");
        assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
    }

    #[test]
    fn de_escalate_drops_the_window() {
        let leases = LeaseManager::new();
        let mut level = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        level
            .escalate_window(OperatingLevel::ReadWrite, ESCALATION_WINDOW)
            .unwrap();
        assert!(level.has_active_elevation());
        let stepup = StepUpRegistry::new();
        let acq = OkAcquirer;
        let mut d = deps(&leases, &mut level, &stepup, &acq);
        let out =
            oracle_session(parse(r#"{"action":"de_escalate"}"#), &mut d).expect("de-escalate");
        assert_eq!(out["status"], json!("de_escalated"));
        assert!(!d.level.has_active_elevation());
    }

    #[test]
    fn get_session_reports_the_level_view() {
        let leases = LeaseManager::new();
        let mut level = SessionLevelState::new(OperatingLevel::Ddl, false);
        let stepup = StepUpRegistry::new();
        let acq = OkAcquirer;
        let mut d = deps(&leases, &mut level, &stepup, &acq);
        let out = oracle_session(parse(r#"{"action":"get_session"}"#), &mut d).expect("get");
        assert_eq!(out["session"]["max_level"], json!("DDL"));
        assert_eq!(out["session"]["current_level"], json!("READ_ONLY"));
        assert_eq!(out["session"]["protected"], json!(false));
    }
}
