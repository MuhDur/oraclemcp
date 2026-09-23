//! Feature-gated adapter for Oracle's official synchronous Rust driver.
//!
//! The official driver's connection and cursor types never leave the dedicated
//! actor thread. This module passes only owned, backend-neutral requests and
//! serialized rows through [`super::oracledb_actor::BlockingConnectionActor`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::Cx;
use asupersync::combinator::try_commit_section;
use asupersync::types::Time;
use chrono::{Datelike, Timelike};
use serde_json::{Number, Value, json};

use crate::auth_adapter::AuthAdapter;
use crate::connection::{
    DbRequestQuota, OracleConnection, QueryRowStream, QueryRowStreamStart, WalletFileChoice,
    timestamp_tz_wall_clock,
};
use crate::error::QuarantineOutcome;
use crate::oracledb_actor::{
    ActorAdmission, BlockingConnectionActor, OfficialConnectGuard, OfficialConnectSlot,
};
use crate::serialize::canonical_nls_statements;
use crate::types::{
    OracleBackend, OracleBind, OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleRow,
};
use crate::{DbError, SerializeOptions};

const CLEANUP_MASKED_POLLS: u32 = 100;

// Keep the identity surface aligned with the driver-cx implementation without
// depending on `V$SESSION` visibility. `USERENV` is available to every
// authenticated Oracle session and this query remains actor-owned.
const OFFICIAL_SESSION_CONTEXT_SQL: &str = concat!(
    "SELECT ",
    "SYS_CONTEXT('USERENV','CURRENT_SCHEMA') AS current_schema, ",
    "SYS_CONTEXT('USERENV','CURRENT_EDITION_NAME') AS current_edition, ",
    "SYS_CONTEXT('USERENV','SESSION_USER') AS session_user, ",
    "SYS_CONTEXT('USERENV','CURRENT_USER') AS current_user, ",
    "SYS_CONTEXT('USERENV','PROXY_USER') AS proxy_user, ",
    "SYS_CONTEXT('USERENV','MODULE') AS module, ",
    "SYS_CONTEXT('USERENV','ACTION') AS session_action, ",
    "SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') AS client_identifier, ",
    "SYS_CONTEXT('USERENV','CLIENT_INFO') AS client_info, ",
    "SYS_CONTEXT('USERENV','OS_USER') AS os_user, ",
    "SYS_CONTEXT('USERENV','HOST') AS host, ",
    "SYS_CONTEXT('USERENV','TERMINAL') AS terminal ",
    "FROM dual",
);

/// An [`OracleConnection`] backed by Oracle's official synchronous driver.
///
/// Every physical driver connection is confined to a dedicated actor thread.
/// This adapter is compiled only with the `oracledb` feature and is selected
/// only for capability-compatible connection acquisition.
pub struct OfficialOracleConnection {
    options: OracleConnectOptions,
    actor: Arc<BlockingConnectionActor<OfficialCommand, OfficialReply>>,
    wire_limits: Arc<Mutex<OfficialWireLimits>>,
    closed: AtomicBool,
}

/// Classifies an official-driver establishment failure by whether a physical
/// session could already have been used for setup work.
///
/// The registry may try driver-cx after [`Self::RawAcquisition`] only. Once
/// `oracledb::connect` has returned, even a failed timeout/NLS/session setup
/// can have an observable effect on that session, so a fresh backend would be
/// a forbidden second session rather than an acquisition retry.
#[derive(Debug)]
pub(crate) enum ConnectFailure {
    RawAcquisition(DbError),
    PostConnectSetup(DbError),
}

impl ConnectFailure {
    pub(crate) fn into_error(self) -> DbError {
        match self {
            Self::RawAcquisition(error) | Self::PostConnectSetup(error) => error,
        }
    }
}

impl OfficialOracleConnection {
    /// Opens a feature-gated official-driver connection through the actor.
    ///
    /// The adapter accepts only basic credentials and the driver's documented
    /// PEM-wallet configuration. IAM, external authentication, proxy auth,
    /// and unsupported TLS overrides are refused here so a later selector can
    /// route them directly to driver-cx; none is silently dropped.
    pub async fn connect(cx: &Cx, options: OracleConnectOptions) -> Result<Self, DbError> {
        Self::connect_for_backend_registry(cx, options)
            .await
            .map_err(ConnectFailure::into_error)
    }

    /// Opens an official connection while retaining the phase needed by the
    /// backend registry's acquisition-only fallback policy.
    ///
    /// Actor-boundary failures are intentionally conservative: the caller
    /// cannot determine whether the synchronous actor had advanced beyond the
    /// raw native connect, so they are treated as post-connect and never cause
    /// a new driver-cx session.
    pub(crate) async fn connect_for_backend_registry(
        cx: &Cx,
        options: OracleConnectOptions,
    ) -> Result<Self, ConnectFailure> {
        checkpoint(cx, "official Oracle connect before actor startup")
            .map_err(ConnectFailure::RawAcquisition)?;
        validate_supported_connect_options(&options).map_err(ConnectFailure::RawAcquisition)?;

        let connect_slot = OfficialConnectGuard::shared()
            .acquire(cx)
            .await
            .map_err(ConnectFailure::RawAcquisition)?;
        let actor = Arc::new(
            BlockingConnectionActor::spawn(
                move || OfficialActorResource::with_connect_slot(connect_slot),
                execute_actor_command,
            )
            .map_err(ConnectFailure::RawAcquisition)?,
        );
        let adapter = Self {
            wire_limits: Arc::new(Mutex::new(OfficialWireLimits {
                call_timeout: options.call_timeout,
                request_deadline: None,
                request_quota: None,
            })),
            options,
            actor,
            closed: AtomicBool::new(false),
        };
        let budget = match adapter.effective_budget(cx, "official Oracle connect") {
            Ok(budget) => budget,
            Err(error) => {
                Self::discard_failed_connect(&adapter.actor);
                return Err(ConnectFailure::RawAcquisition(error));
            }
        };
        let reply = match adapter
            .actor
            .call_with_deadline(
                cx,
                budget.deadline,
                OfficialCommand::Connect {
                    options: Box::new(adapter.options.clone()),
                    timeout: budget.timeout,
                },
            )
            .await
        {
            Ok(reply) => reply,
            Err(error) => {
                Self::discard_failed_connect(&adapter.actor);
                return Err(ConnectFailure::PostConnectSetup(error));
            }
        };
        if let Err(error) = expect_connect_reply(reply) {
            Self::discard_failed_connect(&adapter.actor);
            return Err(error);
        }
        if let Err(error) = checkpoint(cx, "official Oracle connect after actor startup") {
            Self::discard_failed_connect(&adapter.actor);
            return Err(ConnectFailure::PostConnectSetup(error));
        }
        Ok(adapter)
    }

    /// A failed establishment never leaves its just-created owner actor
    /// available for another command. This covers synchronous driver
    /// connection/setup errors, deadline/cancellation reports, and an
    /// unexpected connect reply.
    fn discard_failed_connect(actor: &BlockingConnectionActor<OfficialCommand, OfficialReply>) {
        actor.discard_nonblocking("official Oracle connection establishment failed");
    }

    async fn call(
        &self,
        cx: &Cx,
        command: OfficialCommand,
        phase: &'static str,
    ) -> Result<OfficialReply, DbError> {
        self.require_open()?;
        checkpoint(cx, phase)?;
        let budget = self.effective_budget(cx, phase)?;
        self.actor
            .call_with_deadline(cx, budget.deadline, command.with_timeout(budget.timeout))
            .await
    }

    async fn call_terminal(
        &self,
        cx: &Cx,
        command: OfficialCommand,
        phase: &'static str,
    ) -> Result<OfficialReply, DbError> {
        self.require_open()?;
        checkpoint(cx, phase)?;
        let budget = self.effective_budget(cx, phase)?;
        self.actor
            .call_terminal_with_deadline(cx, budget.deadline, command.with_timeout(budget.timeout))
            .await
    }

    fn effective_budget(
        &self,
        cx: &Cx,
        phase: &'static str,
    ) -> Result<OfficialCallBudget, DbError> {
        let limits = self
            .wire_limits
            .lock()
            .map_err(|_| DbError::Internal("official Oracle wire-limits lock poisoned".to_owned()))?
            .clone();
        limits.effective_budget(cx, phase)
    }

    fn require_open(&self) -> Result<(), DbError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                message: "official Oracle connection has already been closed and discarded"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn cleanup_timeout(&self) -> Option<Duration> {
        // Teardown must still retire the actor if a prior caller poisoned the
        // configuration lock. Falling back to the driver's default timeout is
        // safer than preserving a live session because cleanup configuration
        // could not be read.
        self.wire_limits
            .lock()
            .map(|limits| limits.call_timeout)
            .unwrap_or(None)
    }
}

#[derive(Clone, Copy, Debug)]
struct OfficialCallBudget {
    timeout: Option<Duration>,
    deadline: Option<Time>,
}

#[derive(Clone, Debug, Default)]
struct OfficialWireLimits {
    call_timeout: Option<Duration>,
    request_deadline: Option<Time>,
    request_quota: Option<DbRequestQuota>,
}

impl OfficialWireLimits {
    fn effective_budget(
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

#[derive(Default)]
struct OfficialActorResource {
    connection: Option<oracledb::Connection>,
    stream: Option<OfficialCursor>,
    /// Held only while the synchronous initial connection may still be
    /// uninterruptibly blocked. A successful setup releases it before this
    /// healthy session is returned; every failed/cancelled setup retains it
    /// until the actor and its native thread actually retire.
    connect_slot: Option<OfficialConnectSlot>,
}

impl OfficialActorResource {
    fn with_connect_slot(connect_slot: OfficialConnectSlot) -> Self {
        Self {
            connection: None,
            stream: None,
            connect_slot: Some(connect_slot),
        }
    }

    fn release_connect_slot(&mut self) {
        let _ = self.connect_slot.take();
    }
}

struct OfficialCursor {
    cursor: oracledb::Cursor,
    metadata: Vec<oracledb::Metadata>,
}

enum OfficialCommand {
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
    fn timeout(&self) -> Option<Duration> {
        match self {
            Self::Connect { timeout, .. }
            | Self::Ping { timeout }
            | Self::Describe { timeout }
            | Self::Query { timeout, .. }
            | Self::StartStream { timeout, .. }
            | Self::NextStream { timeout }
            | Self::RecoverStream { timeout }
            | Self::Execute { timeout, .. }
            | Self::Commit { timeout }
            | Self::Rollback { timeout }
            | Self::Close { timeout } => *timeout,
        }
    }

    fn with_timeout(self, timeout: Option<Duration>) -> Self {
        match self {
            Self::Connect { options, .. } => Self::Connect { options, timeout },
            Self::Ping { .. } => Self::Ping { timeout },
            Self::Describe { .. } => Self::Describe { timeout },
            Self::Query { sql, binds, .. } => Self::Query {
                sql,
                binds,
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
            Self::Commit { .. } => Self::Commit { timeout },
            Self::Rollback { .. } => Self::Rollback { timeout },
            Self::Close { .. } => Self::Close { timeout },
        }
    }

    fn tighten_for_actor_admission(self, remaining_timeout: Option<Duration>) -> Self {
        let timeout = match (self.timeout(), remaining_timeout) {
            (Some(configured), Some(remaining)) => Some(configured.min(remaining)),
            (Some(configured), None) => Some(configured),
            (None, Some(remaining)) => Some(remaining),
            (None, None) => None,
        };
        self.with_timeout(timeout)
    }
}

enum OfficialReply {
    Unit,
    ConnectFailed(ConnectFailure),
    ConnectionInfo(Box<OracleConnectionInfo>),
    Rows(Vec<OracleRow>),
    StreamStarted { columns: Vec<String> },
    NextRow(Option<OracleRow>),
    RowsAffected(u64),
}

#[derive(Clone)]
struct OfficialBinds(Vec<OfficialBind>);

#[derive(Clone)]
enum OfficialBind {
    Null(Option<String>),
    String(String),
    I64(i64),
    F64(f64),
    Bool(bool),
}

impl OfficialBinds {
    fn from_oracle_binds(binds: &[OracleBind]) -> Result<Self, DbError> {
        binds
            .iter()
            .map(OfficialBind::from_oracle_bind)
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    fn params(&self) -> Vec<&dyn oracledb::ToDbValue> {
        self.0.iter().map(OfficialBind::as_driver_value).collect()
    }
}

impl OfficialBind {
    fn from_oracle_bind(bind: &OracleBind) -> Result<Self, DbError> {
        match bind {
            OracleBind::Null => Ok(Self::Null(None)),
            OracleBind::String(value) => Ok(Self::String(value.clone())),
            OracleBind::I64(value) => Ok(Self::I64(*value)),
            OracleBind::F64(value) => Ok(Self::F64(*value)),
            OracleBind::Bool(value) => Ok(Self::Bool(*value)),
            OracleBind::TimestampTz { .. } => Err(DbError::UnsupportedFeature(
                "official Oracle backend cannot bind TIMESTAMP WITH TIME ZONE without losing its UTC offset"
                    .to_owned(),
            )),
        }
    }

    fn as_driver_value(&self) -> &dyn oracledb::ToDbValue {
        match self {
            Self::Null(value) => value,
            Self::String(value) => value,
            Self::I64(value) => value,
            Self::F64(value) => value,
            Self::Bool(value) => value,
        }
    }
}

fn execute_actor_command(
    resource: &mut OfficialActorResource,
    command: OfficialCommand,
    admission: ActorAdmission,
) -> Result<OfficialReply, DbError> {
    match command.tighten_for_actor_admission(admission.remaining_timeout()) {
        OfficialCommand::Connect { options, timeout } => {
            if resource.connection.is_some() {
                return Err(DbError::Internal(
                    "official Oracle actor received a duplicate connect command".to_owned(),
                ));
            }
            let config = match config_from_options(&options) {
                Ok(config) => config,
                Err(error) => {
                    return Ok(OfficialReply::ConnectFailed(
                        ConnectFailure::RawAcquisition(error),
                    ));
                }
            };
            let connection = match oracledb::connect(config) {
                Ok(connection) => connection,
                Err(error) => {
                    return Ok(OfficialReply::ConnectFailed(
                        ConnectFailure::RawAcquisition(official_error(
                            error,
                            OfficialOperation::Connect,
                        )),
                    ));
                }
            };
            if let Err(error) = connection
                .set_call_timeout(timeout)
                .map_err(|error| official_error(error, OfficialOperation::Connect))
            {
                return Ok(OfficialReply::ConnectFailed(
                    ConnectFailure::PostConnectSetup(error),
                ));
            }
            for statement in canonical_nls_statements() {
                if let Err(error) = connection
                    .execute(statement, &[])
                    .map_err(|error| official_error(error, OfficialOperation::Connect))
                {
                    return Ok(OfficialReply::ConnectFailed(
                        ConnectFailure::PostConnectSetup(error),
                    ));
                }
            }
            for statement in &options.session_statements {
                if let Err(error) = connection
                    .execute(statement, &[])
                    .map_err(|error| official_error(error, OfficialOperation::Connect))
                {
                    return Ok(OfficialReply::ConnectFailed(
                        ConnectFailure::PostConnectSetup(error),
                    ));
                }
            }
            resource.connection = Some(connection);
            resource.release_connect_slot();
            Ok(OfficialReply::Unit)
        }
        OfficialCommand::Ping { timeout } => {
            let connection = ready_connection(resource)?;
            set_driver_timeout(connection, timeout, OfficialOperation::Query)?;
            connection
                .ping()
                .map_err(|error| official_error(error, OfficialOperation::Query))?;
            Ok(OfficialReply::Unit)
        }
        OfficialCommand::Describe { timeout } => {
            let connection = ready_connection(resource)?;
            set_driver_timeout(connection, timeout, OfficialOperation::Query)?;
            let session_context = official_session_context(connection)?;
            let info = OracleConnectionInfo {
                backend: Some(OracleBackend::OfficialOracle),
                server_version: Some(
                    connection
                        .version()
                        .map_err(|error| official_error(error, OfficialOperation::Query))?
                        .to_string(),
                ),
                service_name: Some(
                    connection
                        .service_name()
                        .map_err(|error| official_error(error, OfficialOperation::Query))?
                        .to_owned(),
                ),
                instance_name: Some(
                    connection
                        .instance_name()
                        .map_err(|error| official_error(error, OfficialOperation::Query))?
                        .to_owned(),
                ),
                sid: Some(
                    connection
                        .session_id()
                        .map_err(|error| official_error(error, OfficialOperation::Query))?
                        .to_string(),
                ),
                serial_number: Some(
                    connection
                        .serial_num()
                        .map_err(|error| official_error(error, OfficialOperation::Query))?
                        .to_string(),
                ),
                current_schema: session_context.current_schema,
                current_edition: session_context.current_edition,
                session_user: session_context.session_user,
                current_user: session_context.current_user,
                proxy_user: session_context.proxy_user,
                module: session_context.module,
                action: session_context.action,
                client_identifier: session_context.client_identifier,
                client_info: session_context.client_info,
                os_user: session_context.os_user,
                host: session_context.host,
                terminal: session_context.terminal,
                ..OracleConnectionInfo::default()
            };
            Ok(OfficialReply::ConnectionInfo(Box::new(info)))
        }
        OfficialCommand::Query {
            sql,
            binds,
            timeout,
        } => {
            let connection = ready_connection(resource)?;
            set_driver_timeout(connection, timeout, OfficialOperation::Query)?;
            let params = binds.params();
            let mut cursor = connection
                .query(&sql, &params)
                .map_err(|error| official_error(error, OfficialOperation::Query))?;
            let metadata = cursor.columns().clone();
            let mut rows = Vec::new();
            for next in &mut cursor {
                let row = next.map_err(|error| official_error(error, OfficialOperation::Query))?;
                rows.push(row_from_official(&row, &metadata)?);
            }
            Ok(OfficialReply::Rows(rows))
        }
        OfficialCommand::StartStream {
            sql,
            binds,
            timeout,
        } => {
            if resource.stream.is_some() {
                return Err(stream_not_recovered());
            }
            let connection = ready_connection(resource)?;
            set_driver_timeout(connection, timeout, OfficialOperation::Query)?;
            let params = binds.params();
            let cursor = connection
                .query(&sql, &params)
                .map_err(|error| official_error(error, OfficialOperation::Query))?;
            let metadata = cursor.columns().clone();
            let columns = metadata
                .iter()
                .map(|column| column.name().to_owned())
                .collect();
            resource.stream = Some(OfficialCursor { cursor, metadata });
            Ok(OfficialReply::StreamStarted { columns })
        }
        OfficialCommand::NextStream { timeout } => {
            let stream = resource.stream.as_mut().ok_or_else(stream_not_started)?;
            let connection = resource.connection.as_ref().ok_or_else(closed_connection)?;
            set_driver_timeout(connection, timeout, OfficialOperation::Query)?;
            let row = match stream.cursor.next() {
                Some(Ok(row)) => Some(row_from_official(&row, &stream.metadata)?),
                Some(Err(error)) => return Err(official_error(error, OfficialOperation::Query)),
                None => None,
            };
            Ok(OfficialReply::NextRow(row))
        }
        OfficialCommand::RecoverStream { timeout } => {
            let connection = resource.connection.as_ref().ok_or_else(closed_connection)?;
            set_driver_timeout(connection, timeout, OfficialOperation::Query)?;
            let _ = resource.stream.take();
            Ok(OfficialReply::Unit)
        }
        OfficialCommand::Execute {
            sql,
            binds,
            timeout,
        } => {
            let connection = ready_connection(resource)?;
            set_driver_timeout(connection, timeout, OfficialOperation::Execute)?;
            let params = binds.params();
            let result = connection
                .execute(&sql, &params)
                .map_err(|error| official_error(error, OfficialOperation::Execute))?;
            Ok(OfficialReply::RowsAffected(result.rows_affected()))
        }
        OfficialCommand::Commit { timeout } => {
            let connection = ready_connection(resource)?;
            set_driver_timeout(connection, timeout, OfficialOperation::Execute)?;
            connection
                .commit()
                .map_err(|error| official_error(error, OfficialOperation::Execute))?;
            Ok(OfficialReply::Unit)
        }
        OfficialCommand::Rollback { timeout } => {
            let connection = ready_connection(resource)?;
            set_driver_timeout(connection, timeout, OfficialOperation::Execute)?;
            connection
                .rollback()
                .map_err(|error| official_error(error, OfficialOperation::Execute))?;
            Ok(OfficialReply::Unit)
        }
        OfficialCommand::Close { timeout } => {
            let mut connection = resource.connection.take().ok_or_else(closed_connection)?;
            resource.stream.take();
            set_driver_timeout(&connection, timeout, OfficialOperation::Execute)?;
            connection
                .close()
                .map_err(|error| official_error(error, OfficialOperation::Execute))?;
            Ok(OfficialReply::Unit)
        }
    }
}

fn ready_connection(resource: &OfficialActorResource) -> Result<&oracledb::Connection, DbError> {
    if resource.stream.is_some() {
        return Err(stream_not_recovered());
    }
    resource.connection.as_ref().ok_or_else(closed_connection)
}

#[derive(Default)]
struct OfficialSessionContext {
    current_schema: Option<String>,
    current_edition: Option<String>,
    session_user: Option<String>,
    current_user: Option<String>,
    proxy_user: Option<String>,
    module: Option<String>,
    action: Option<String>,
    client_identifier: Option<String>,
    client_info: Option<String>,
    os_user: Option<String>,
    host: Option<String>,
    terminal: Option<String>,
}

fn official_session_context(
    connection: &oracledb::Connection,
) -> Result<OfficialSessionContext, DbError> {
    let row = connection
        .query_row(OFFICIAL_SESSION_CONTEXT_SQL, &[])
        .map_err(|error| official_error(error, OfficialOperation::Query))?;
    let get = |index| {
        row.get::<Option<String>>(index)
            .map_err(|error| official_error(error, OfficialOperation::Query))
    };
    Ok(OfficialSessionContext {
        current_schema: get(0)?,
        current_edition: get(1)?,
        session_user: get(2)?,
        current_user: get(3)?,
        proxy_user: get(4)?,
        module: get(5)?,
        action: get(6)?,
        client_identifier: get(7)?,
        client_info: get(8)?,
        os_user: get(9)?,
        host: get(10)?,
        terminal: get(11)?,
    })
}

fn closed_connection() -> DbError {
    DbError::Quarantined {
        outcome: QuarantineOutcome::UnknownDiscarded,
        message: "official Oracle connection is closed and cannot be reused".to_owned(),
    }
}

fn stream_not_started() -> DbError {
    DbError::Quarantined {
        outcome: QuarantineOutcome::UnknownDiscarded,
        message: "official Oracle owned row stream is no longer available".to_owned(),
    }
}

fn stream_not_recovered() -> DbError {
    DbError::Quarantined {
        outcome: QuarantineOutcome::UnknownDiscarded,
        message: "official Oracle owned row stream was not recovered before another operation"
            .to_owned(),
    }
}

fn set_driver_timeout(
    connection: &oracledb::Connection,
    timeout: Option<Duration>,
    operation: OfficialOperation,
) -> Result<(), DbError> {
    connection
        .set_call_timeout(timeout)
        .map_err(|error| official_error(error, operation))
}

fn config_from_options(options: &OracleConnectOptions) -> Result<oracledb::Config, DbError> {
    validate_supported_connect_options(options)?;
    reject_auto_login_wallet_at_consumption(options)?;
    let username = options.username.as_deref().ok_or_else(|| {
        DbError::UnsupportedAuth(
            "official Oracle backend requires a username for password authentication".to_owned(),
        )
    })?;
    let password = options.password.as_deref().ok_or_else(|| {
        DbError::UnsupportedAuth(
            "official Oracle backend requires a password for password authentication".to_owned(),
        )
    })?;

    let mut config = oracledb::Config::default();
    if let Some(wallet) = &options.wallet_location {
        let wallet = wallet.to_str().ok_or_else(|| {
            DbError::UnsupportedAuth(
                "official Oracle backend requires a UTF-8 PEM wallet path".to_owned(),
            )
        })?;
        config = config.set_config_dir(wallet).set_wallet_location(wallet);
    }
    config = config
        .set_connect_string(&options.connect_string)
        .map_err(|error| official_error(error, OfficialOperation::Connect))?
        .set_credentials(username, password)
        .set_driver_name("oraclemcp");
    if let Some(wallet_password) = options.wallet_password.as_deref() {
        config = config.set_wallet_password(wallet_password);
    }
    if let Some(cache_size) = options.statement_cache_size {
        config = config.set_stmtcachesize(cache_size as usize);
    }
    Ok(config)
}

/// Refuse an auto-login wallet at the last boundary before the official driver
/// receives its directory path.
///
/// The capability selector is intentionally side-effect free apart from its
/// initial file observation. A `cwallet.sso` can appear after that observation
/// while driver-cx acquisition is in progress, so a selector result is not
/// sufficient authority to hand a wallet path to the PEM-only official driver.
/// This re-check runs on the owner actor immediately before building the
/// official configuration and fails closed instead of silently treating the
/// changed directory as a PEM wallet.
fn reject_auto_login_wallet_at_consumption(options: &OracleConnectOptions) -> Result<(), DbError> {
    let Some(wallet) = &options.wallet_location else {
        return Ok(());
    };
    if wallet.join(WalletFileChoice::Sso.file_name()).is_file() {
        return Err(DbError::UnsupportedAuth(
            "official Oracle backend does not support cwallet.sso auto-login wallets".to_owned(),
        ));
    }
    Ok(())
}

fn validate_supported_connect_options(options: &OracleConnectOptions) -> Result<(), DbError> {
    if options.use_iam_token || options.iam_token.is_some() || options.iam_token_source.is_some() {
        return Err(DbError::UnsupportedAuth(
            "official Oracle backend does not support IAM or OAuth database tokens".to_owned(),
        ));
    }
    if options.external_auth || !matches!(options.auth_adapter, AuthAdapter::Password) {
        return Err(DbError::UnsupportedAuth(
            "official Oracle backend supports only password authentication; route this auth mode to driver-cx"
                .to_owned(),
        ));
    }
    if options.ssl_server_dn_match.is_some()
        || options.ssl_server_cert_dn.is_some()
        || options.use_sni.is_some()
    {
        return Err(DbError::UnsupportedAuth(
            "official Oracle backend cannot apply the requested TLS override safely".to_owned(),
        ));
    }
    if options.sdu.is_some()
        || options.connect_timeout.is_some()
        || options.inactivity_timeout.is_some()
        || options.keepalive_minutes.is_some()
        || !options.app_context.is_empty()
        || options.session_identity.is_some()
    {
        return Err(DbError::UnsupportedFeature(
            "official Oracle backend cannot apply one or more requested connection settings safely"
                .to_owned(),
        ));
    }
    Ok(())
}

fn row_from_official(
    row: &oracledb::Row,
    metadata: &[oracledb::Metadata],
) -> Result<OracleRow, DbError> {
    let mut columns = Vec::with_capacity(metadata.len());
    for (index, metadata) in metadata.iter().enumerate() {
        let name = metadata.name().to_owned();
        columns.push((name, cell_from_official(row, index, metadata)?));
    }
    Ok(OracleRow { columns })
}

fn cell_from_official(
    row: &oracledb::Row,
    index: usize,
    metadata: &oracledb::Metadata,
) -> Result<OracleCell, DbError> {
    let oracle_type = oracle_type_name(metadata);
    let db_type = metadata.db_type().name();
    let cell = match db_type {
        "DB_TYPE_NUMBER" => number_cell(
            row.get::<Option<oracledb::OracleNumber>>(index)
                .map_err(|error| official_error(error, OfficialOperation::Query))?,
            oracle_type,
        ),
        "DB_TYPE_BINARY_DOUBLE" => OracleCell::new(
            oracle_type,
            row.get::<Option<f64>>(index)
                .map_err(|error| official_error(error, OfficialOperation::Query))?
                .map(|value| value.to_string()),
        ),
        "DB_TYPE_BINARY_FLOAT" => OracleCell::new(
            oracle_type,
            row.get::<Option<f32>>(index)
                .map_err(|error| official_error(error, OfficialOperation::Query))?
                .map(|value| value.to_string()),
        ),
        "DB_TYPE_BOOLEAN" => OracleCell::new(
            oracle_type,
            row.get::<Option<bool>>(index)
                .map_err(|error| official_error(error, OfficialOperation::Query))?
                .map(|value| value.to_string()),
        ),
        "DB_TYPE_RAW" | "DB_TYPE_LONG_RAW" => match row
            .get::<Option<Vec<u8>>>(index)
            .map_err(|error| official_error(error, OfficialOperation::Query))?
        {
            Some(bytes) => OracleCell::binary(oracle_type, bytes),
            None => OracleCell::new(oracle_type, None),
        },
        "DB_TYPE_CHAR"
        | "DB_TYPE_NCHAR"
        | "DB_TYPE_VARCHAR"
        | "DB_TYPE_NVARCHAR"
        | "DB_TYPE_LONG"
        | "DB_TYPE_LONG_NVARCHAR"
        | "DB_TYPE_ROWID"
        | "DB_TYPE_UROWID" => OracleCell::new(
            oracle_type,
            row.get::<Option<String>>(index)
                .map_err(|error| official_error(error, OfficialOperation::Query))?,
        ),
        "DB_TYPE_DATE" | "DB_TYPE_TIMESTAMP" | "DB_TYPE_TIMESTAMP_LTZ" | "DB_TYPE_TIMESTAMP_TZ" => {
            OracleCell::new(
                oracle_type,
                row.get::<Option<oracledb::OracleTimestamp>>(index)
                    .map_err(|error| official_error(error, OfficialOperation::Query))?
                    .as_ref()
                    .map(|value| format_official_timestamp_for_type(value, db_type))
                    .transpose()?,
            )
        }
        "DB_TYPE_VECTOR" => vector_cell(
            row.get::<Option<oracledb::Vector>>(index)
                .map_err(|error| official_error(error, OfficialOperation::Query))?,
            oracle_type,
        ),
        unsupported => {
            return Err(DbError::UnsupportedFeature(format!(
                "official Oracle backend does not yet serialize {unsupported} columns"
            )));
        }
    };
    Ok(cell)
}

fn number_cell(value: Option<oracledb::OracleNumber>, oracle_type: &'static str) -> OracleCell {
    // Deliberately format OracleNumber directly. Never decode a NUMBER through
    // f64: its 53-bit mantissa cannot represent a 38-digit Oracle NUMBER.
    OracleCell::new(oracle_type, value.map(|number| number.to_string()))
}

/// Project an official-driver timestamp according to the database column
/// metadata rather than inferring a timezone from its zero-valued fields.
///
/// `OracleTimestamp` represents DATE, plain TIMESTAMP, LTZ, and TSTZ with the
/// same struct. The first two have no timezone, so their zero offset must not
/// become a fabricated UTC `Z`. LTZ/TSTZ retain an explicit offset. We also
/// render the latter ourselves because the beta driver's Display implementation
/// formats a negative minute component as "-05:-30".
fn format_official_timestamp_for_type(
    value: &oracledb::OracleTimestamp,
    db_type: &str,
) -> Result<String, DbError> {
    match db_type {
        "DB_TYPE_DATE" => Ok(format_official_date_components(value)),
        "DB_TYPE_TIMESTAMP" => Ok(format_official_timestamp_components(value)),
        "DB_TYPE_TIMESTAMP_LTZ" | "DB_TYPE_TIMESTAMP_TZ" => {
            let offset_minutes =
                i32::from(value.tz_hour_offset()) * 60 + i32::from(value.tz_minute_offset());
            let wall = timestamp_tz_wall_clock(
                i32::from(value.year()),
                value.month(),
                value.day(),
                value.hour(),
                value.minute(),
                value.second(),
                value.nanoseconds(),
                offset_minutes,
            )
            .ok_or_else(|| DbError::Query("invalid TIMESTAMP WITH TIME ZONE value".to_owned()))?;
            let timestamp = format_official_wall_clock_components(wall);
            if offset_minutes == 0 {
                return Ok(format!("{timestamp}Z"));
            }
            let sign = if offset_minutes < 0 { '-' } else { '+' };
            let offset_abs = i64::from(offset_minutes).abs();
            Ok(format!(
                "{timestamp}{sign}{:02}:{:02}",
                offset_abs / 60,
                offset_abs % 60
            ))
        }
        _ => unreachable!("only timestamp database types may use this formatter"),
    }
}

fn format_official_wall_clock_components(wall: chrono::NaiveDateTime) -> String {
    let timestamp = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        wall.year(),
        wall.month(),
        wall.day(),
        wall.hour(),
        wall.minute(),
        wall.second(),
    );
    if wall.nanosecond() == 0 {
        return timestamp;
    }
    let fractional = format!("{:09}", wall.nanosecond());
    format!("{timestamp}.{}", fractional.trim_end_matches('0'))
}

fn format_official_date_components(value: &oracledb::OracleTimestamp) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        value.year(),
        value.month(),
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
    )
}

fn format_official_timestamp_components(value: &oracledb::OracleTimestamp) -> String {
    let timestamp = format_official_date_components(value);
    if value.nanoseconds() == 0 {
        return timestamp;
    }
    let fractional = format!("{:09}", value.nanoseconds());
    format!("{timestamp}.{}", fractional.trim_end_matches('0'))
}

fn vector_cell(value: Option<oracledb::Vector>, oracle_type: &'static str) -> OracleCell {
    match value {
        Some(vector) => OracleCell::structured(oracle_type, structured_official_vector(&vector)),
        None => OracleCell::new(oracle_type, None),
    }
}

/// Project the official driver's VECTOR value onto the existing structured
/// `OracleCell` contract. This deliberately matches the driver-cx shape so
/// callers observe no backend-dependent representation change.
fn structured_official_vector(vector: &oracledb::Vector) -> Value {
    match vector {
        oracledb::Vector::Dense(values) => {
            let (format, values) = structured_official_vector_values(values);
            json!({
                "kind": "vector",
                "storage": "dense",
                "format": format,
                "values": values,
            })
        }
        oracledb::Vector::Sparse(sparse) => {
            let (format, values) = structured_official_vector_values(sparse.values());
            json!({
                "kind": "vector",
                "storage": "sparse",
                "format": format,
                "num_dimensions": sparse.num_dimensions(),
                "indices": sparse.indices(),
                "values": values,
            })
        }
    }
}

fn structured_official_vector_values(values: &oracledb::VectorData) -> (&'static str, Value) {
    match values {
        oracledb::VectorData::Float32(values) => (
            "float32",
            Value::Array(
                values
                    .iter()
                    .map(|value| json_number_or_string(f64::from(*value)))
                    .collect(),
            ),
        ),
        oracledb::VectorData::Float64(values) => (
            "float64",
            Value::Array(
                values
                    .iter()
                    .map(|value| json_number_or_string(*value))
                    .collect(),
            ),
        ),
        oracledb::VectorData::Int8(values) => (
            "int8",
            Value::Array(values.iter().map(|value| json!(*value)).collect()),
        ),
        oracledb::VectorData::Binary(values) => (
            "binary",
            Value::Array(values.iter().map(|value| json!(*value)).collect()),
        ),
    }
}

fn json_number_or_string(value: f64) -> Value {
    Number::from_f64(value).map_or_else(|| Value::String(value.to_string()), Value::Number)
}

fn oracle_type_name(metadata: &oracledb::Metadata) -> &'static str {
    match metadata.db_type().name() {
        "DB_TYPE_NUMBER" => "NUMBER",
        "DB_TYPE_BINARY_DOUBLE" => "BINARY_DOUBLE",
        "DB_TYPE_BINARY_FLOAT" => "BINARY_FLOAT",
        "DB_TYPE_BOOLEAN" => "BOOLEAN",
        "DB_TYPE_RAW" => "RAW",
        "DB_TYPE_LONG_RAW" => "LONG RAW",
        "DB_TYPE_CHAR" => "CHAR",
        "DB_TYPE_NCHAR" => "NCHAR",
        "DB_TYPE_VARCHAR" => "VARCHAR2",
        "DB_TYPE_NVARCHAR" => "NVARCHAR2",
        "DB_TYPE_LONG" => "LONG",
        "DB_TYPE_LONG_NVARCHAR" => "LONG NVARCHAR",
        "DB_TYPE_ROWID" => "ROWID",
        "DB_TYPE_UROWID" => "UROWID",
        "DB_TYPE_DATE" => "DATE",
        "DB_TYPE_TIMESTAMP" => "TIMESTAMP",
        "DB_TYPE_TIMESTAMP_LTZ" => "TIMESTAMP WITH LOCAL TIME ZONE",
        "DB_TYPE_TIMESTAMP_TZ" => "TIMESTAMP WITH TIME ZONE",
        "DB_TYPE_VECTOR" => "VECTOR",
        _ => "UNSUPPORTED",
    }
}

#[derive(Clone, Copy)]
enum OfficialOperation {
    Connect,
    Query,
    Execute,
}

fn official_error(error: oracledb::Error, operation: OfficialOperation) -> DbError {
    let error_code = oraclemcp_error::parse_ora_code(&error.to_string());
    let detail = error_code.map_or_else(
        || "official Oracle driver operation failed".to_owned(),
        |code| format!("ORA-{code:05}: official Oracle driver operation failed"),
    );
    match error.kind() {
        oracledb::ErrorKind::CallTimeoutExceeded => {
            DbError::Cancelled("official Oracle driver call timeout exceeded".to_owned())
        }
        oracledb::ErrorKind::DeadConnection
        | oracledb::ErrorKind::NotConnected
        | oracledb::ErrorKind::UnableToRecover => DbError::ConnectionLost(detail),
        _ => match operation {
            OfficialOperation::Connect => DbError::Connect(detail),
            OfficialOperation::Query => DbError::Query(detail),
            OfficialOperation::Execute => DbError::Execute(detail),
        },
    }
}

fn expect_unit(reply: OfficialReply, operation: &str) -> Result<(), DbError> {
    match reply {
        OfficialReply::Unit => Ok(()),
        OfficialReply::ConnectFailed(_) => Err(DbError::Internal(format!(
            "official Oracle actor returned an unexpected connect failure reply for {operation}"
        ))),
        _ => Err(DbError::Internal(format!(
            "official Oracle actor returned an unexpected {operation} reply"
        ))),
    }
}

fn expect_connect_reply(reply: OfficialReply) -> Result<(), ConnectFailure> {
    match reply {
        OfficialReply::Unit => Ok(()),
        OfficialReply::ConnectFailed(failure) => Err(failure),
        _ => Err(ConnectFailure::PostConnectSetup(DbError::Internal(
            "official Oracle actor returned an unexpected connect reply".to_owned(),
        ))),
    }
}

fn checkpoint(cx: &Cx, phase: &str) -> Result<(), DbError> {
    cx.checkpoint()
        .map_err(|error| DbError::Cancelled(format!("{phase}: {error}")))
}

fn stream_effective_budget(
    wire_limits: &Mutex<OfficialWireLimits>,
    cx: &Cx,
    phase: &'static str,
) -> Result<OfficialCallBudget, DbError> {
    wire_limits
        .lock()
        .map_err(|_| DbError::Internal("official Oracle wire-limits lock poisoned".to_owned()))?
        .effective_budget(cx, phase)
}

/// Actor-owned facade for an official-driver cursor.
pub(crate) struct OfficialOracleRowStream {
    actor: Arc<BlockingConnectionActor<OfficialCommand, OfficialReply>>,
    columns: Vec<String>,
    wire_limits: Arc<Mutex<OfficialWireLimits>>,
    recovered: bool,
}

impl OfficialOracleRowStream {
    pub(crate) fn columns(&self) -> &[String] {
        &self.columns
    }

    pub(crate) async fn next_row(&mut self, cx: &Cx) -> Result<Option<OracleRow>, DbError> {
        let budget =
            stream_effective_budget(&self.wire_limits, cx, "official Oracle row stream next")?;
        match self
            .actor
            .call_with_deadline(
                cx,
                budget.deadline,
                OfficialCommand::NextStream {
                    timeout: budget.timeout,
                },
            )
            .await?
        {
            OfficialReply::NextRow(row) => Ok(row),
            _ => Err(DbError::Internal(
                "official Oracle actor returned an unexpected row-stream reply".to_owned(),
            )),
        }
    }

    pub(crate) async fn recover(mut self, cx: &Cx) -> Result<(), DbError> {
        let budget =
            stream_effective_budget(&self.wire_limits, cx, "official Oracle row stream recovery")?;
        match self
            .actor
            .call_with_deadline(
                cx,
                budget.deadline,
                OfficialCommand::RecoverStream {
                    timeout: budget.timeout,
                },
            )
            .await?
        {
            OfficialReply::Unit => {
                self.recovered = true;
                Ok(())
            }
            _ => Err(DbError::Internal(
                "official Oracle actor returned an unexpected row-stream recovery reply".to_owned(),
            )),
        }
    }
}

impl Drop for OfficialOracleRowStream {
    fn drop(&mut self) {
        if !self.recovered {
            self.actor.discard_nonblocking(
                "official Oracle row stream was dropped before recovery; session discarded",
            );
        }
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for OfficialOracleConnection {
    fn backend(&self) -> OracleBackend {
        OracleBackend::OfficialOracle
    }

    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        expect_unit(
            self.call(
                cx,
                OfficialCommand::Ping { timeout: None },
                "official Oracle ping before",
            )
            .await?,
            "ping",
        )
    }

    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        match self
            .call(
                cx,
                OfficialCommand::Describe { timeout: None },
                "official Oracle describe before",
            )
            .await?
        {
            OfficialReply::ConnectionInfo(info) => Ok(*info),
            _ => Err(DbError::Internal(
                "official Oracle actor returned an unexpected describe reply".to_owned(),
            )),
        }
    }

    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        let binds = OfficialBinds::from_oracle_binds(binds)?;
        match self
            .call(
                cx,
                OfficialCommand::Query {
                    sql: sql.to_owned(),
                    binds,
                    timeout: None,
                },
                "official Oracle query before",
            )
            .await?
        {
            OfficialReply::Rows(rows) => Ok(rows),
            _ => Err(DbError::Internal(
                "official Oracle actor returned an unexpected query reply".to_owned(),
            )),
        }
    }

    async fn query_row_stream(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
        _arraysize: usize,
        _serialize_opts: &SerializeOptions,
    ) -> Result<QueryRowStreamStart, DbError> {
        let binds = OfficialBinds::from_oracle_binds(binds)?;
        match self
            .call(
                cx,
                OfficialCommand::StartStream {
                    sql: sql.to_owned(),
                    binds,
                    timeout: None,
                },
                "official Oracle row stream before",
            )
            .await?
        {
            OfficialReply::StreamStarted { columns } => Ok(QueryRowStreamStart::Stream(
                QueryRowStream::new_official(OfficialOracleRowStream {
                    actor: Arc::clone(&self.actor),
                    columns,
                    wire_limits: Arc::clone(&self.wire_limits),
                    recovered: false,
                }),
            )),
            _ => Err(DbError::Internal(
                "official Oracle actor returned an unexpected row-stream start reply".to_owned(),
            )),
        }
    }

    async fn execute(&self, cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
        let binds = OfficialBinds::from_oracle_binds(binds)?;
        match self
            .call(
                cx,
                OfficialCommand::Execute {
                    sql: sql.to_owned(),
                    binds,
                    timeout: None,
                },
                "official Oracle execute before",
            )
            .await?
        {
            OfficialReply::RowsAffected(rows) => Ok(rows),
            _ => Err(DbError::Internal(
                "official Oracle actor returned an unexpected execute reply".to_owned(),
            )),
        }
    }

    async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
        // Commit intentionally has no post-completion checkpoint: a successful
        // commit cannot be undone by a late cancellation observation.
        expect_unit(
            self.call_terminal(
                cx,
                OfficialCommand::Commit { timeout: None },
                "official Oracle commit before",
            )
            .await?,
            "commit",
        )
    }

    async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
        try_commit_section(cx, CLEANUP_MASKED_POLLS, async {
            expect_unit(
                self.call(
                    cx,
                    OfficialCommand::Rollback { timeout: None },
                    "official Oracle rollback cleanup",
                )
                .await?,
                "rollback",
            )
        })
        .await
    }

    async fn close(&self, cx: &Cx) -> Result<(), DbError> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let timeout = self.cleanup_timeout();
        try_commit_section(cx, CLEANUP_MASKED_POLLS, async {
            expect_unit(
                self.actor
                    .call_disposing_with_deadline(cx, None, OfficialCommand::Close { timeout })
                    .await?,
                "close",
            )
        })
        .await
    }

    fn call_timeout(&self) -> Result<Option<Duration>, DbError> {
        self.wire_limits
            .lock()
            .map(|limits| limits.call_timeout)
            .map_err(|_| DbError::Internal("official Oracle wire-limits lock poisoned".to_owned()))
    }

    fn set_call_timeout(&self, timeout: Option<Duration>) -> Result<(), DbError> {
        self.wire_limits
            .lock()
            .map(|mut limits| limits.call_timeout = timeout)
            .map_err(|_| DbError::Internal("official Oracle wire-limits lock poisoned".to_owned()))
    }

    fn request_deadline(&self, _cx: &Cx) -> Result<Option<Time>, DbError> {
        self.wire_limits
            .lock()
            .map(|limits| limits.request_deadline)
            .map_err(|_| DbError::Internal("official Oracle wire-limits lock poisoned".to_owned()))
    }

    fn set_request_deadline(&self, _cx: &Cx, deadline: Option<Time>) -> Result<(), DbError> {
        self.wire_limits
            .lock()
            .map(|mut limits| limits.request_deadline = deadline)
            .map_err(|_| DbError::Internal("official Oracle wire-limits lock poisoned".to_owned()))
    }

    fn request_quota(&self, _cx: &Cx) -> Result<Option<DbRequestQuota>, DbError> {
        self.wire_limits
            .lock()
            .map(|limits| limits.request_quota.clone())
            .map_err(|_| DbError::Internal("official Oracle wire-limits lock poisoned".to_owned()))
    }

    fn set_request_quota(&self, _cx: &Cx, quota: Option<DbRequestQuota>) -> Result<(), DbError> {
        self.wire_limits
            .lock()
            .map(|mut limits| limits.request_quota = quota)
            .map_err(|_| DbError::Internal("official Oracle wire-limits lock poisoned".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize::serialize_cell;
    use serde_json::json;
    use std::str::FromStr;

    fn block_on_backend<T>(future: impl std::future::Future<Output = T>) -> T {
        let reactor = asupersync::runtime::reactor::create_reactor()
            .expect("native reactor must build for official backend test");
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("current-thread runtime must build for official backend test");
        runtime.block_on(future)
    }

    #[test]
    fn successful_official_setup_releases_its_connect_guard_slot() {
        let guard = OfficialConnectGuard::for_test(1, Duration::from_millis(25));
        let slot = block_on_backend(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            guard
                .acquire(&cx)
                .await
                .expect("official setup reserves its only connect slot")
        });
        let mut resource = OfficialActorResource::with_connect_slot(slot);
        assert_eq!(
            guard.available_for_test(),
            0,
            "an actor owns its slot until successful setup is complete"
        );

        resource.release_connect_slot();

        assert_eq!(
            guard.available_for_test(),
            1,
            "a healthy established session does not consume stalled-connect capacity"
        );
    }

    #[test]
    fn late_cwallet_appearance_refuses_official_config_before_consumption() {
        struct TestWalletDir(std::path::PathBuf);

        impl Drop for TestWalletDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is after the Unix epoch")
            .as_nanos();
        let wallet = TestWalletDir(std::env::temp_dir().join(format!(
            "oraclemcp-official-wallet-consumption-{}-{nonce}",
            std::process::id()
        )));
        std::fs::create_dir_all(&wallet.0).expect("create empty PEM-eligible wallet directory");
        let options = OracleConnectOptions {
            username: Some("test-user".to_owned()),
            password: Some("test-password".to_owned()),
            wallet_location: Some(wallet.0.clone()),
            ..OracleConnectOptions::default()
        };
        assert!(
            reject_auto_login_wallet_at_consumption(&options).is_ok(),
            "the selector could have observed this directory before cwallet.sso appeared"
        );

        std::fs::write(
            wallet.0.join(WalletFileChoice::Sso.file_name()),
            b"test-sso",
        )
        .expect("simulate cwallet.sso appearing after backend selection");

        assert!(matches!(
            config_from_options(&options),
            Err(DbError::UnsupportedAuth(message))
                if message == "official Oracle backend does not support cwallet.sso auto-login wallets"
        ));
    }

    #[test]
    fn dropped_official_row_stream_quarantines_and_stops_its_actor() {
        let actor = Arc::new(
            BlockingConnectionActor::spawn(
                || (),
                |_, _, _| -> Result<OfficialReply, DbError> {
                    Err(DbError::Internal(
                        "discarded stream must not execute an actor command".to_owned(),
                    ))
                },
            )
            .expect("actor thread starts for stream-drop test"),
        );
        let stream = OfficialOracleRowStream {
            actor: Arc::clone(&actor),
            columns: Vec::new(),
            wire_limits: Arc::new(Mutex::new(OfficialWireLimits::default())),
            recovered: false,
        };

        drop(stream);
        actor.join_for_test();

        assert!(actor.is_quarantined_for_test());
        assert!(matches!(
            block_on_backend(async {
                let cx = Cx::current().expect("test runtime installs a current Cx");
                actor
                    .call_with_deadline(&cx, None, OfficialCommand::Ping { timeout: None })
                    .await
            }),
            Err(DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                ..
            })
        ));
    }

    #[test]
    fn official_close_is_terminal_and_idempotent() {
        let close_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let actor_close_calls = Arc::clone(&close_calls);
        let actor = Arc::new(
            BlockingConnectionActor::spawn(
                OfficialActorResource::default,
                move |_, command, _| -> Result<OfficialReply, DbError> {
                    assert!(matches!(command, OfficialCommand::Close { .. }));
                    actor_close_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(OfficialReply::Unit)
                },
            )
            .expect("actor thread starts for explicit-close test"),
        );
        let connection = OfficialOracleConnection {
            options: OracleConnectOptions::default(),
            actor: Arc::clone(&actor),
            wire_limits: Arc::new(Mutex::new(OfficialWireLimits::default())),
            closed: AtomicBool::new(false),
        };

        let first = block_on_backend(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            connection.close(&cx).await
        });
        assert!(matches!(first, Ok(())));
        actor.join_for_test();
        assert!(actor.is_closed_for_test());

        let second = block_on_backend(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            connection.close(&cx).await
        });
        assert!(matches!(second, Ok(())));
        assert_eq!(close_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_official_connect_discards_actor_and_refuses_reuse() {
        struct Resource(Arc<std::sync::atomic::AtomicUsize>);

        impl Drop for Resource {
            fn drop(&mut self) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resource_dropped = Arc::clone(&dropped);
        let actor = Arc::new(
            BlockingConnectionActor::spawn(
                move || Resource(resource_dropped),
                |_, command, _| -> Result<OfficialReply, DbError> {
                    assert!(matches!(command, OfficialCommand::Connect { .. }));
                    Err(DbError::Connect(
                        "official Oracle driver operation failed".to_owned(),
                    ))
                },
            )
            .expect("actor thread starts for failed-connect test"),
        );

        let result = block_on_backend(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            let result = actor
                .call_with_deadline(
                    &cx,
                    None,
                    OfficialCommand::Connect {
                        options: Box::new(OracleConnectOptions::default()),
                        timeout: None,
                    },
                )
                .await;
            if result.is_err() {
                OfficialOracleConnection::discard_failed_connect(&actor);
            }
            result
        });

        assert!(matches!(result, Err(DbError::Connect(_))));
        actor.join_for_test();
        assert!(actor.is_quarantined_for_test());
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(matches!(
            block_on_backend(async {
                let cx = Cx::current().expect("test runtime installs a current Cx");
                actor
                    .call_with_deadline(&cx, None, OfficialCommand::Ping { timeout: None })
                    .await
            }),
            Err(DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                ..
            })
        ));
    }

    #[test]
    fn actor_admission_tightens_never_expands_driver_timeout() {
        let command = OfficialCommand::Ping {
            timeout: Some(Duration::from_secs(5)),
        };
        assert_eq!(
            command
                .tighten_for_actor_admission(Some(Duration::from_millis(25)))
                .timeout(),
            Some(Duration::from_millis(25))
        );

        let command = OfficialCommand::Ping { timeout: None };
        assert_eq!(
            command
                .tighten_for_actor_admission(Some(Duration::from_millis(25)))
                .timeout(),
            Some(Duration::from_millis(25))
        );
    }

    #[test]
    fn number_38_digits_stays_an_exact_decimal_string() {
        let decimal = "12345678901234567890123456789012345678";
        let driver_number = oracledb::OracleNumber::from_str(decimal)
            .expect("the official driver accepts a 38-digit Oracle NUMBER");

        let cell = number_cell(Some(driver_number), "NUMBER");

        assert_eq!(cell.oracle_type, "NUMBER");
        assert_eq!(cell.value.as_deref(), Some(decimal));
        assert!(cell.bytes.is_none());
    }

    #[test]
    fn timestamp_tz_bind_refuses_official_driver_offset_loss() {
        let bind = OracleBind::TimestampTz {
            year: 2026,
            month: 9,
            day: 16,
            hour: 12,
            minute: 34,
            second: 56,
            nanosecond: 0,
            offset_minutes: -330,
        };

        assert!(matches!(
            OfficialBind::from_oracle_bind(&bind),
            Err(DbError::UnsupportedFeature(message)) if message.contains("without losing its UTC offset")
        ));
    }

    #[test]
    fn timestamp_projection_obeys_column_timezone_metadata() {
        let date = oracledb::OracleTimestamp::new_timestamp(2026, 6, 1, 12, 0, 0, 0);
        assert_eq!(
            format_official_timestamp_for_type(&date, "DB_TYPE_DATE").expect("valid DATE"),
            "2026-06-01T12:00:00"
        );
        assert_eq!(
            serialize_cell(
                &OracleCell::new(
                    "DATE",
                    Some(
                        format_official_timestamp_for_type(&date, "DB_TYPE_DATE")
                            .expect("valid DATE")
                    ),
                ),
                &SerializeOptions::default(),
            ),
            json!("2026-06-01T12:00:00")
        );

        let plain_timestamp =
            oracledb::OracleTimestamp::new_timestamp(2026, 6, 1, 12, 0, 0, 123_456_789);
        assert_eq!(
            format_official_timestamp_for_type(&plain_timestamp, "DB_TYPE_TIMESTAMP")
                .expect("valid TIMESTAMP"),
            "2026-06-01T12:00:00.123456789"
        );
        assert_eq!(
            serialize_cell(
                &OracleCell::new(
                    "TIMESTAMP",
                    Some(
                        format_official_timestamp_for_type(&plain_timestamp, "DB_TYPE_TIMESTAMP")
                            .expect("valid TIMESTAMP")
                    ),
                ),
                &SerializeOptions::default(),
            ),
            json!("2026-06-01T12:00:00.123456789")
        );

        let fractional_timestamp =
            oracledb::OracleTimestamp::new_timestamp(2026, 6, 1, 12, 0, 0, 120_000_000);
        assert_eq!(
            format_official_timestamp_for_type(&fractional_timestamp, "DB_TYPE_TIMESTAMP")
                .expect("valid TIMESTAMP"),
            "2026-06-01T12:00:00.12"
        );
    }

    #[test]
    fn timestamp_tz_projection_converts_utc_fields_to_display_wall_clock() {
        for (
            label,
            (year, month, day, hour, minute, second, nanos),
            hour_offset,
            minute_offset,
            expected,
        ) in [
            (
                "free23 +05:45",
                (2020, 2, 29, 17, 45, 0, 0),
                5,
                45,
                "2020-02-29T23:30:00+05:45",
            ),
            (
                "leap-day -09:30",
                (2020, 3, 1, 8, 15, 0, 0),
                -9,
                -30,
                "2020-02-29T22:45:00-09:30",
            ),
            (
                "UTC",
                (2020, 2, 29, 23, 59, 0, 0),
                0,
                0,
                "2020-02-29T23:59:00Z",
            ),
            (
                "+14:00 next day",
                (2020, 2, 29, 17, 0, 0, 0),
                14,
                0,
                "2020-03-01T07:00:00+14:00",
            ),
            (
                "negative minute only",
                (2026, 9, 16, 12, 34, 56, 123_456_789),
                0,
                -30,
                "2026-09-16T12:04:56.123456789-00:30",
            ),
            (
                "positive minute only",
                (2026, 9, 16, 12, 34, 56, 123_456_789),
                0,
                30,
                "2026-09-16T13:04:56.123456789+00:30",
            ),
            (
                "America/New_York before DST",
                (2020, 3, 8, 6, 59, 0, 0),
                -5,
                0,
                "2020-03-08T01:59:00-05:00",
            ),
            (
                "America/New_York after DST",
                (2020, 3, 8, 7, 1, 0, 0),
                -4,
                0,
                "2020-03-08T03:01:00-04:00",
            ),
            (
                "negative fraction",
                (2026, 9, 16, 12, 34, 56, 123_456_789),
                -5,
                -30,
                "2026-09-16T07:04:56.123456789-05:30",
            ),
        ] {
            let timestamp = oracledb::OracleTimestamp::new_timestamp_tz(
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanos,
                hour_offset,
                minute_offset,
            );
            assert_eq!(
                format_official_timestamp_for_type(&timestamp, "DB_TYPE_TIMESTAMP_TZ")
                    .expect("valid TSTZ"),
                expected,
                "{label}"
            );
        }
    }

    #[test]
    fn vector_projection_matches_dense_and_sparse_structured_contract() {
        let dense = vector_cell(
            Some(oracledb::Vector::Dense(oracledb::VectorData::Float32(
                vec![1.25, -2.5],
            ))),
            "VECTOR",
        );
        assert_eq!(dense.oracle_type, "VECTOR");
        assert_eq!(
            dense.structured,
            Some(json!({
                "kind": "vector",
                "storage": "dense",
                "format": "float32",
                "values": [1.25, -2.5],
            }))
        );

        let sparse = vector_cell(
            Some(oracledb::Vector::Sparse(oracledb::SparseVector::new(
                1_000,
                vec![0, 500, 999],
                oracledb::VectorData::Float64(vec![1.5, 2.5, 3.5]),
            ))),
            "VECTOR",
        );
        assert_eq!(sparse.oracle_type, "VECTOR");
        assert_eq!(
            sparse.structured,
            Some(json!({
                "kind": "vector",
                "storage": "sparse",
                "format": "float64",
                "num_dimensions": 1_000,
                "indices": [0, 500, 999],
                "values": [1.5, 2.5, 3.5],
            }))
        );
    }

    #[test]
    fn iam_and_external_auth_are_refused_before_driver_connect() {
        let options = OracleConnectOptions {
            use_iam_token: true,
            ..OracleConnectOptions::default()
        };
        assert!(matches!(
            validate_supported_connect_options(&options),
            Err(DbError::UnsupportedAuth(_))
        ));

        let options = OracleConnectOptions {
            external_auth: true,
            ..OracleConnectOptions::default()
        };
        assert!(matches!(
            validate_supported_connect_options(&options),
            Err(DbError::UnsupportedAuth(_))
        ));
    }

    #[test]
    fn timeout_error_is_cancelled_and_therefore_quarantined_by_the_actor() {
        assert!(DbError::Cancelled("timeout".to_owned()).is_uncertain_session_state());
    }
}
