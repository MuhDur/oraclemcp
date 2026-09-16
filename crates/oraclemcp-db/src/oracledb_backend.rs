//! Feature-gated adapter for Oracle's official synchronous Rust driver.
//!
//! The official driver's connection and cursor types never leave the dedicated
//! actor thread. This module passes only owned, backend-neutral requests and
//! serialized rows through [`super::oracledb_actor::BlockingConnectionActor`].

use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::Cx;
use asupersync::combinator::try_commit_section;
use asupersync::types::Time;

use crate::auth_adapter::AuthAdapter;
use crate::connection::{DbRequestQuota, OracleConnection, QueryRowStream, QueryRowStreamStart};
use crate::error::QuarantineOutcome;
use crate::oracledb_actor::BlockingConnectionActor;
use crate::serialize::canonical_nls_statements;
use crate::types::{
    OracleBackend, OracleBind, OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleRow,
};
use crate::{DbError, SerializeOptions};

const CLEANUP_MASKED_POLLS: u32 = 100;

/// An [`OracleConnection`] backed by Oracle's official synchronous driver.
///
/// Every physical driver connection is confined to a dedicated actor thread.
/// This adapter is compiled only with the `oracledb` feature and is selected
/// only for capability-compatible connection acquisition.
pub struct OfficialOracleConnection {
    options: OracleConnectOptions,
    actor: Arc<BlockingConnectionActor<OfficialCommand, OfficialReply>>,
    wire_limits: Arc<Mutex<OfficialWireLimits>>,
}

impl OfficialOracleConnection {
    /// Opens a feature-gated official-driver connection through the actor.
    ///
    /// The adapter accepts only basic credentials and the driver's documented
    /// PEM-wallet configuration. IAM, external authentication, proxy auth,
    /// and unsupported TLS overrides are refused here so a later selector can
    /// route them directly to driver-cx; none is silently dropped.
    pub async fn connect(cx: &Cx, options: OracleConnectOptions) -> Result<Self, DbError> {
        checkpoint(cx, "official Oracle connect before actor startup")?;
        validate_supported_connect_options(&options)?;

        let actor = Arc::new(BlockingConnectionActor::spawn(
            OfficialActorResource::default,
            execute_actor_command,
        ));
        let adapter = Self {
            wire_limits: Arc::new(Mutex::new(OfficialWireLimits {
                call_timeout: options.call_timeout,
                request_deadline: None,
                request_quota: None,
            })),
            options,
            actor,
        };
        let timeout = adapter.effective_timeout(cx, "official Oracle connect")?;
        let reply = adapter
            .actor
            .call(
                cx,
                OfficialCommand::Connect {
                    options: Box::new(adapter.options.clone()),
                    timeout,
                },
            )
            .await?;
        expect_unit(reply, "connect")?;
        checkpoint(cx, "official Oracle connect after actor startup")?;
        Ok(adapter)
    }

    async fn call(
        &self,
        cx: &Cx,
        command: OfficialCommand,
        phase: &'static str,
    ) -> Result<OfficialReply, DbError> {
        checkpoint(cx, phase)?;
        let timeout = self.effective_timeout(cx, phase)?;
        self.actor.call(cx, command.with_timeout(timeout)).await
    }

    async fn call_terminal(
        &self,
        cx: &Cx,
        command: OfficialCommand,
        phase: &'static str,
    ) -> Result<OfficialReply, DbError> {
        checkpoint(cx, phase)?;
        let timeout = self.effective_timeout(cx, phase)?;
        self.actor
            .call_terminal(cx, command.with_timeout(timeout))
            .await
    }

    fn effective_timeout(&self, cx: &Cx, phase: &'static str) -> Result<Option<Duration>, DbError> {
        let limits = self
            .wire_limits
            .lock()
            .map_err(|_| DbError::Internal("official Oracle wire-limits lock poisoned".to_owned()))?
            .clone();
        limits.effective_timeout(cx, phase)
    }
}

#[derive(Clone, Debug, Default)]
struct OfficialWireLimits {
    call_timeout: Option<Duration>,
    request_deadline: Option<Time>,
    request_quota: Option<DbRequestQuota>,
}

impl OfficialWireLimits {
    fn effective_timeout(&self, cx: &Cx, phase: &'static str) -> Result<Option<Duration>, DbError> {
        if let Some(quota) = &self.request_quota {
            quota.consume_checkpoint(phase)?;
        }

        let mut remaining = self.call_timeout;
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
            remaining = Some(remaining.map_or(until_deadline, |limit| limit.min(until_deadline)));
        }
        Ok(remaining)
    }
}

#[derive(Default)]
struct OfficialActorResource {
    connection: Option<oracledb::Connection>,
    stream: Option<OfficialCursor>,
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
}

enum OfficialReply {
    Unit,
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
    Timestamp(oracledb::OracleTimestamp),
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
            OracleBind::TimestampTz {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
                offset_minutes,
            } => {
                let offset_abs = offset_minutes.unsigned_abs();
                let offset_sign = if *offset_minutes < 0 { -1_i8 } else { 1_i8 };
                let tz_hour_offset = i8::try_from(offset_abs / 60).map_err(|_| {
                    DbError::UnsupportedFeature(
                        "official Oracle backend cannot represent this timestamp UTC offset"
                            .to_owned(),
                    )
                })? * offset_sign;
                let tz_minute_offset = i8::try_from(offset_abs % 60).map_err(|_| {
                    DbError::UnsupportedFeature(
                        "official Oracle backend cannot represent this timestamp UTC offset"
                            .to_owned(),
                    )
                })? * offset_sign;
                Ok(Self::Timestamp(
                    oracledb::OracleTimestamp::new_timestamp_tz(
                        i16::try_from(*year).map_err(|_| {
                            DbError::UnsupportedFeature(
                                "official Oracle backend cannot represent this timestamp year"
                                    .to_owned(),
                            )
                        })?,
                        *month,
                        *day,
                        *hour,
                        *minute,
                        *second,
                        *nanosecond,
                        tz_hour_offset,
                        tz_minute_offset,
                    ),
                ))
            }
        }
    }

    fn as_driver_value(&self) -> &dyn oracledb::ToDbValue {
        match self {
            Self::Null(value) => value,
            Self::String(value) => value,
            Self::I64(value) => value,
            Self::F64(value) => value,
            Self::Bool(value) => value,
            Self::Timestamp(value) => value,
        }
    }
}

fn execute_actor_command(
    resource: &mut OfficialActorResource,
    command: OfficialCommand,
) -> Result<OfficialReply, DbError> {
    match command {
        OfficialCommand::Connect { options, timeout } => {
            if resource.connection.is_some() {
                return Err(DbError::Internal(
                    "official Oracle actor received a duplicate connect command".to_owned(),
                ));
            }
            let config = config_from_options(&options)?;
            let connection = oracledb::connect(config)
                .map_err(|error| official_error(error, OfficialOperation::Connect))?;
            connection
                .set_call_timeout(timeout)
                .map_err(|error| official_error(error, OfficialOperation::Connect))?;
            for statement in canonical_nls_statements() {
                connection
                    .execute(statement, &[])
                    .map_err(|error| official_error(error, OfficialOperation::Connect))?;
            }
            for statement in &options.session_statements {
                connection
                    .execute(statement, &[])
                    .map_err(|error| official_error(error, OfficialOperation::Connect))?;
            }
            resource.connection = Some(connection);
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
    let cell = match metadata.db_type().name() {
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
                    .map(|value| value.to_string()),
            )
        }
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
        _ => Err(DbError::Internal(format!(
            "official Oracle actor returned an unexpected {operation} reply"
        ))),
    }
}

fn checkpoint(cx: &Cx, phase: &str) -> Result<(), DbError> {
    cx.checkpoint()
        .map_err(|error| DbError::Cancelled(format!("{phase}: {error}")))
}

fn stream_effective_timeout(
    wire_limits: &Mutex<OfficialWireLimits>,
    cx: &Cx,
    phase: &'static str,
) -> Result<Option<Duration>, DbError> {
    wire_limits
        .lock()
        .map_err(|_| DbError::Internal("official Oracle wire-limits lock poisoned".to_owned()))?
        .effective_timeout(cx, phase)
}

/// Actor-owned facade for an official-driver cursor.
pub(crate) struct OfficialOracleRowStream {
    actor: Arc<BlockingConnectionActor<OfficialCommand, OfficialReply>>,
    columns: Vec<String>,
    wire_limits: Arc<Mutex<OfficialWireLimits>>,
}

impl OfficialOracleRowStream {
    pub(crate) fn columns(&self) -> &[String] {
        &self.columns
    }

    pub(crate) async fn next_row(&mut self, cx: &Cx) -> Result<Option<OracleRow>, DbError> {
        let timeout =
            stream_effective_timeout(&self.wire_limits, cx, "official Oracle row stream next")?;
        match self
            .actor
            .call(cx, OfficialCommand::NextStream { timeout })
            .await?
        {
            OfficialReply::NextRow(row) => Ok(row),
            _ => Err(DbError::Internal(
                "official Oracle actor returned an unexpected row-stream reply".to_owned(),
            )),
        }
    }

    pub(crate) async fn recover(self, cx: &Cx) -> Result<(), DbError> {
        let timeout =
            stream_effective_timeout(&self.wire_limits, cx, "official Oracle row stream recovery")?;
        match self
            .actor
            .call(cx, OfficialCommand::RecoverStream { timeout })
            .await?
        {
            OfficialReply::Unit => Ok(()),
            _ => Err(DbError::Internal(
                "official Oracle actor returned an unexpected row-stream recovery reply".to_owned(),
            )),
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
        try_commit_section(cx, CLEANUP_MASKED_POLLS, async {
            expect_unit(
                self.call(
                    cx,
                    OfficialCommand::Close { timeout: None },
                    "official Oracle close cleanup",
                )
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
    use std::str::FromStr;

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
    fn timestamp_tz_bind_keeps_negative_hour_and_minute_offsets() {
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

        let OfficialBind::Timestamp(timestamp) = OfficialBind::from_oracle_bind(&bind)
            .expect("the official driver represents a -05:30 offset")
        else {
            panic!("timestamp bind must remain a timestamp");
        };
        assert_eq!(timestamp.tz_hour_offset(), -5);
        assert_eq!(timestamp.tz_minute_offset(), -30);
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
