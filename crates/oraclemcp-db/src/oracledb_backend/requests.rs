//! Owned actor requests, replies and budgets, independent of the Oracle SDK.

use super::{
    ConnectFailure, DbError, DbRequestQuota, ExecuteOutcome, OfficialBinds, OfficialRoutineBind,
    OracleConnectOptions, OracleConnectionInfo, OracleRow, SerializeOptions,
};
use asupersync::{Cx, types::Time};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub(super) struct OfficialCallBudget {
    pub(super) timeout: Option<Duration>,
    pub(super) deadline: Option<Time>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct OfficialWireLimits {
    pub(super) call_timeout: Option<Duration>,
    pub(super) request_deadline: Option<Time>,
    pub(super) request_quota: Option<DbRequestQuota>,
}

impl OfficialWireLimits {
    pub(super) fn effective_budget(
        &self,
        cx: &Cx,
        phase: &'static str,
    ) -> Result<OfficialCallBudget, DbError> {
        if let Some(quota) = &self.request_quota {
            quota.consume_checkpoint(phase)?;
        }

        let mut timeout = self.call_timeout;
        let mut effective_deadline = None;
        for (kind, deadline) in [
            ("request", self.request_deadline),
            ("context", cx.budget().deadline),
        ] {
            let Some(deadline) = deadline else {
                continue;
            };
            if cx.now() >= deadline {
                return Err(DbError::Cancelled(format!(
                    "{phase}: {kind} deadline exceeded"
                )));
            }
            let until_deadline =
                Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
            timeout = Some(timeout.map_or(until_deadline, |limit| limit.min(until_deadline)));
            effective_deadline =
                Some(effective_deadline.map_or(deadline, |current: Time| current.min(deadline)));
        }
        Ok(OfficialCallBudget {
            timeout,
            deadline: effective_deadline,
        })
    }
}

pub(super) enum OfficialCommand {
    Connect {
        options: Box<OracleConnectOptions>,
        timeout: Option<Duration>,
    },
    Ping {
        timeout: Option<Duration>,
    },
    Describe {
        timeout: Option<Duration>,
    },
    Query {
        sql: String,
        binds: OfficialBinds,
        lob_limits: OfficialLobLimits,
        timeout: Option<Duration>,
    },
    StartStream {
        sql: String,
        binds: OfficialBinds,
        timeout: Option<Duration>,
    },
    NextStream {
        timeout: Option<Duration>,
    },
    RecoverStream {
        timeout: Option<Duration>,
    },
    Execute {
        sql: String,
        binds: OfficialBinds,
        timeout: Option<Duration>,
    },
    CallRoutine {
        sql: String,
        binds: Vec<OfficialRoutineBind>,
        timeout: Option<Duration>,
    },
    Commit {
        timeout: Option<Duration>,
    },
    Rollback {
        timeout: Option<Duration>,
    },
    Close {
        timeout: Option<Duration>,
    },
}

impl OfficialCommand {
    pub(super) fn timeout(&self) -> Option<Duration> {
        match self {
            Self::Connect { timeout, .. }
            | Self::Ping { timeout }
            | Self::Describe { timeout }
            | Self::Query { timeout, .. }
            | Self::StartStream { timeout, .. }
            | Self::NextStream { timeout }
            | Self::RecoverStream { timeout }
            | Self::Execute { timeout, .. }
            | Self::CallRoutine { timeout, .. }
            | Self::Commit { timeout }
            | Self::Rollback { timeout }
            | Self::Close { timeout } => *timeout,
        }
    }

    pub(super) fn with_timeout(self, timeout: Option<Duration>) -> Self {
        match self {
            Self::Connect { options, .. } => Self::Connect { options, timeout },
            Self::Ping { .. } => Self::Ping { timeout },
            Self::Describe { .. } => Self::Describe { timeout },
            Self::Query {
                sql,
                binds,
                lob_limits,
                ..
            } => Self::Query {
                sql,
                binds,
                lob_limits,
                timeout,
            },
            Self::StartStream { sql, binds, .. } => Self::StartStream {
                sql,
                binds,
                timeout,
            },
            Self::NextStream { .. } => Self::NextStream { timeout },
            Self::RecoverStream { .. } => Self::RecoverStream { timeout },
            Self::Execute { sql, binds, .. } => Self::Execute {
                sql,
                binds,
                timeout,
            },
            Self::CallRoutine { sql, binds, .. } => Self::CallRoutine {
                sql,
                binds,
                timeout,
            },
            Self::Commit { .. } => Self::Commit { timeout },
            Self::Rollback { .. } => Self::Rollback { timeout },
            Self::Close { .. } => Self::Close { timeout },
        }
    }

    pub(super) fn tighten_for_actor_admission(self, remaining_timeout: Option<Duration>) -> Self {
        let timeout = match (self.timeout(), remaining_timeout) {
            (Some(configured), Some(remaining)) => Some(configured.min(remaining)),
            (Some(configured), None) => Some(configured),
            (None, Some(remaining)) => Some(remaining),
            (None, None) => None,
        };
        self.with_timeout(timeout)
    }
}

pub(super) enum OfficialReply {
    Unit,
    ConnectFailed(ConnectFailure),
    ConnectionInfo(Box<OracleConnectionInfo>),
    Rows(Vec<OracleRow>),
    StreamStarted { columns: Vec<String> },
    NextRow(Option<OracleRow>),
    RowsAffected(u64),
    Routine(ExecuteOutcome),
}

#[derive(Clone, Copy)]
pub(super) struct OfficialLobLimits {
    pub(super) max_lob_chars: usize,
    pub(super) max_blob_bytes: usize,
}

impl From<&SerializeOptions> for OfficialLobLimits {
    fn from(options: &SerializeOptions) -> Self {
        Self {
            max_lob_chars: options.max_lob_chars,
            max_blob_bytes: options.max_blob_bytes,
        }
    }
}
