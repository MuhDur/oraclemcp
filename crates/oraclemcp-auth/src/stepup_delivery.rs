//! Step-up confirmation **delivery** (plan §7.2; beads P1-10a, P1-10b). The
//! guard owns the challenge/approval/level state (`oraclemcp_guard::stepup`);
//! this module renders it to the agent two complementary ways:
//!
//! - **MCP elicitation selector** (P1-10a): a server-driven choice
//!   ("Approve once / Approve for 15 min / Preview only / Deny") any MCP client
//!   renders — the real default gate, independent of harness annotation support.
//! - **poll/Task** (P1-10b): return `CHALLENGE_REQUIRED` with a challenge id and
//!   have the agent poll `tasks/get`, rather than holding an HTTP request open
//!   across SSE keepalives / proxies / load balancers.

use oraclemcp_guard::{StepUpChallenge, StepUpOption};
use serde::{Deserialize, Serialize};

/// One rendered selector choice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorChoice {
    /// The label the client shows (e.g. "Approve READ_WRITE for 15 min").
    pub label: String,
    /// The option this choice maps back to.
    pub option: StepUpOption,
}

/// A server-driven elicitation request (the in-band selector gate).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElicitationRequest {
    /// The challenge id to resolve / poll.
    pub challenge_id: String,
    /// The operator-facing prompt.
    pub prompt: String,
    /// The selector choices.
    pub choices: Vec<SelectorChoice>,
}

/// The `CHALLENGE_REQUIRED` response that tells the agent to poll rather than
/// wait on a long-held request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRequired {
    /// Always `"CHALLENGE_REQUIRED"`.
    pub status: String,
    /// The challenge id to poll.
    pub challenge_id: String,
    /// How the agent proceeds (poll this).
    pub poll_with: String,
    /// The elicitation the client may render to the operator.
    pub elicitation: ElicitationRequest,
}

fn label_for(option: StepUpOption, target: &str) -> String {
    match option {
        StepUpOption::ApproveOnce => "Approve once (this exact statement)".to_owned(),
        StepUpOption::ApproveWindow { ttl_secs } => {
            format!("Approve {target} for {} min", ttl_secs / 60)
        }
        StepUpOption::PreviewOnly => "Preview only (no commit)".to_owned(),
        StepUpOption::Deny => "Deny".to_owned(),
    }
}

/// Render a guard challenge into an elicitation request (the selector).
#[must_use]
pub fn to_elicitation(challenge: &StepUpChallenge) -> ElicitationRequest {
    let target = challenge.target_level.as_str();
    ElicitationRequest {
        challenge_id: challenge.challenge_id.clone(),
        prompt: format!(
            "Agent requests {} to run:\n  {}\nChoose how to proceed:",
            target, challenge.summary
        ),
        choices: challenge
            .options
            .iter()
            .map(|&option| SelectorChoice {
                label: label_for(option, target),
                option,
            })
            .collect(),
    }
}

/// Render the poll/Task `CHALLENGE_REQUIRED` response for a challenge.
#[must_use]
pub fn to_challenge_required(challenge: &StepUpChallenge) -> ChallengeRequired {
    ChallengeRequired {
        status: "CHALLENGE_REQUIRED".to_owned(),
        challenge_id: challenge.challenge_id.clone(),
        poll_with: format!(
            "oracle_set_session_level(challenge_id={})",
            challenge.challenge_id
        ),
        elicitation: to_elicitation(challenge),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_guard::{OperatingLevel, StepUpRegistry};
    use std::time::Duration;

    fn challenge() -> StepUpChallenge {
        StepUpRegistry::new().issue(
            OperatingLevel::ReadWrite,
            "UPDATE orders SET status='X' WHERE id=42",
            "UPDATE orders SET status='X' WHERE id=42  (preview: ~1 row)",
            Duration::from_secs(300),
        )
    }

    #[test]
    fn elicitation_renders_all_four_choices() {
        let e = to_elicitation(&challenge());
        assert_eq!(e.choices.len(), 4);
        assert!(
            e.choices
                .iter()
                .any(|c| matches!(c.option, StepUpOption::ApproveOnce))
        );
        assert!(e.choices.iter().any(|c| c.label.contains("for 15 min")));
        assert!(
            e.choices
                .iter()
                .any(|c| matches!(c.option, StepUpOption::Deny))
        );
        assert!(e.prompt.contains("READ_WRITE"));
    }

    #[test]
    fn challenge_required_uses_poll_not_long_request() {
        let cr = to_challenge_required(&challenge());
        assert_eq!(cr.status, "CHALLENGE_REQUIRED");
        assert!(cr.poll_with.contains("oracle_set_session_level"));
        assert_eq!(cr.challenge_id, cr.elicitation.challenge_id);
    }

    #[test]
    fn choices_roundtrip_to_options() {
        // The label maps back to the option the operator's pick resolves with.
        let e = to_elicitation(&challenge());
        let window = e.choices.iter().find(|c| c.label.contains("min")).unwrap();
        assert!(matches!(
            window.option,
            StepUpOption::ApproveWindow { ttl_secs: 900 }
        ));
    }
}
