//! Optional Oracle-native Data Redaction policy support.
//!
//! This is deliberately a **second** egress tier. The server-side result
//! masker remains mandatory because it protects every response immediately
//! before serialization; a database-native policy can only tighten a live
//! Oracle result. The module never generates VPD predicates or policy
//! functions: those are privileged, operator-owned database objects and must
//! be supplied and audited through a separate ADMIN-controlled path.
//!
//! Data Redaction requires Oracle Advanced Security. Availability is therefore
//! fail-closed: an absent/unreadable `v$option` value, a false value, or a
//! missing operator license acknowledgement becomes the serializable
//! `requires_advanced_security` state. Callers must preserve the server-side
//! masker in that state and must not claim native enforcement is active.

use asupersync::Cx;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::connection::OracleConnection;
use crate::error::DbError;
use crate::types::OracleBind;

/// Read-only probe for Oracle's Advanced Security option.
///
/// The statement is server-authored and contains no caller data. A failure to
/// read `v$option` is not treated as a positive capability signal.
pub const NATIVE_REDACTION_OPTION_SQL: &str =
    "SELECT value AS advanced_security FROM v$option WHERE parameter = 'Advanced Security'";

/// Server-authored, bound `DBMS_REDACT.ADD_POLICY` call for a full-redaction
/// policy that is always active for non-exempt users.
///
/// Every object identifier is a positional bind. The expression is deliberately
/// fixed to `1=1`: the server does not accept a caller-provided expression that
/// could turn a requested protection into a conditional bypass.
pub const NATIVE_REDACTION_ADD_POLICY_SQL: &str = "BEGIN \
    DBMS_REDACT.ADD_POLICY( \
        object_schema => :1, \
        object_name => :2, \
        policy_name => :3, \
        column_name => :4, \
        function_type => DBMS_REDACT.FULL, \
        expression => '1=1', \
        enable => TRUE); \
END;";

/// A typed readiness decision for the optional native Data Redaction tier.
///
/// `RequiresAdvancedSecurity` is intentionally the conservative outcome for
/// an unavailable or unreadable option probe. It is safe to serialize into an
/// operator-facing capability/status response without exposing Oracle errors.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRedactionAvailability {
    /// The database reports that the Advanced Security option is enabled.
    Available,
    /// The database cannot prove that Advanced Security is available.
    #[default]
    RequiresAdvancedSecurity,
}

impl NativeRedactionAvailability {
    /// The stable operator note for an unavailable native tier.
    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::Available => "Oracle reports Advanced Security as enabled",
            Self::RequiresAdvancedSecurity => {
                "native Data Redaction requires Oracle Advanced Security; the server-side result masker remains in force"
            }
        }
    }
}

/// The effective gate for a native Data Redaction request.
///
/// A database option probe only reports technical availability; it cannot prove
/// that an operator holds a license. The explicit acknowledgement prevents a
/// successful `v$option` read from becoming an implicit licensing decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRedactionGate {
    /// No native policy was requested; no database policy call may occur.
    Disabled,
    /// Native policy application must refuse and retain the server masker.
    RequiresAdvancedSecurity,
    /// A server-owned, ADMIN-gated caller may attempt policy application.
    Ready,
}

impl NativeRedactionGate {
    /// Whether policy application is permitted by this gate.
    #[must_use]
    pub const fn permits_application(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Stable, redaction-safe status text for logs and operator responses.
    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::Disabled => "native Data Redaction is not configured",
            Self::RequiresAdvancedSecurity => {
                "native Data Redaction requires Oracle Advanced Security; refusing native policy application and retaining the server-side result masker"
            }
            Self::Ready => "native Data Redaction is ready for an ADMIN-gated policy application",
        }
    }
}

/// Combine an operator request, an explicit license acknowledgement, and the
/// database probe into a fail-closed native-tier gate.
#[must_use]
pub const fn gate_native_redaction(
    requested: bool,
    license_acknowledged: bool,
    availability: NativeRedactionAvailability,
) -> NativeRedactionGate {
    if !requested {
        NativeRedactionGate::Disabled
    } else if !license_acknowledged
        || matches!(
            availability,
            NativeRedactionAvailability::RequiresAdvancedSecurity
        )
    {
        NativeRedactionGate::RequiresAdvancedSecurity
    } else {
        NativeRedactionGate::Ready
    }
}

/// Probe the optional Data Redaction tier without creating or altering a
/// database policy.
///
/// A normal privilege/query failure is deliberately collapsed into
/// [`NativeRedactionAvailability::RequiresAdvancedSecurity`], because neither
/// an unavailable option nor an unreadable option can authorize native policy
/// application. Cancellation and uncertain connection state still propagate so
/// their owner can discard the session safely.
///
/// # Errors
///
/// Returns a cancellation or uncertain-session [`DbError`] without degrading
/// it to a capability result.
pub async fn probe_native_redaction(
    cx: &Cx,
    conn: &dyn OracleConnection,
) -> Result<NativeRedactionAvailability, DbError> {
    match conn.query_rows(cx, NATIVE_REDACTION_OPTION_SQL, &[]).await {
        Ok(rows) => Ok(
            if rows
                .first()
                .and_then(|row| row.text("ADVANCED_SECURITY"))
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("TRUE"))
            {
                NativeRedactionAvailability::Available
            } else {
                NativeRedactionAvailability::RequiresAdvancedSecurity
            },
        ),
        Err(error) if error.is_uncertain_session_state() => Err(error),
        Err(_) => Ok(NativeRedactionAvailability::RequiresAdvancedSecurity),
    }
}

/// Validated operator-owned target for one full-redaction column policy.
///
/// This deliberately accepts only simple unquoted Oracle identifiers. The
/// policy call binds them rather than interpolating them, and limiting the
/// grammar keeps the installation surface stable across the supported 11g+
/// database range. Quoted/mixed-case object names should remain protected by
/// the server-side masker until an explicitly reviewed native-policy extension
/// supports them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeRedactionPolicy {
    object_schema: String,
    object_name: String,
    policy_name: String,
    column_name: String,
}

impl NativeRedactionPolicy {
    /// Construct a policy target from four simple Oracle identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`NativeRedactionPolicyError`] when an identifier is empty,
    /// longer than the cross-version 30-byte limit, or outside the simple
    /// identifier grammar.
    pub fn new(
        object_schema: impl Into<String>,
        object_name: impl Into<String>,
        policy_name: impl Into<String>,
        column_name: impl Into<String>,
    ) -> Result<Self, NativeRedactionPolicyError> {
        let object_schema = validate_identifier("object_schema", object_schema.into())?;
        let object_name = validate_identifier("object_name", object_name.into())?;
        let policy_name = validate_identifier("policy_name", policy_name.into())?;
        let column_name = validate_identifier("column_name", column_name.into())?;
        Ok(Self {
            object_schema,
            object_name,
            policy_name,
            column_name,
        })
    }

    /// Schema owning the protected object.
    #[must_use]
    pub fn object_schema(&self) -> &str {
        &self.object_schema
    }

    /// Table or view receiving the native policy.
    #[must_use]
    pub fn object_name(&self) -> &str {
        &self.object_name
    }

    /// Database-unique Data Redaction policy name.
    #[must_use]
    pub fn policy_name(&self) -> &str {
        &self.policy_name
    }

    /// Column receiving full redaction.
    #[must_use]
    pub fn column_name(&self) -> &str {
        &self.column_name
    }
}

/// Invalid native Data Redaction policy target.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeRedactionPolicyError {
    /// The field was empty, too long, or not a simple Oracle identifier.
    #[error("native Data Redaction {field} must be a simple unquoted Oracle identifier")]
    InvalidIdentifier {
        /// The invalid field name; never the operator-provided value.
        field: &'static str,
    },
}

fn validate_identifier(
    field: &'static str,
    value: String,
) -> Result<String, NativeRedactionPolicyError> {
    let value = value.trim();
    let valid_start = value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic);
    let valid_rest = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'#'));
    if value.is_empty() || value.len() > 30 || !valid_start || !valid_rest {
        return Err(NativeRedactionPolicyError::InvalidIdentifier { field });
    }
    Ok(value.to_ascii_uppercase())
}

/// Failure while applying a native Data Redaction policy.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NativeRedactionApplyError {
    /// The feature gate refused before any policy-mutating database call.
    #[error("{0}")]
    RequiresAdvancedSecurity(&'static str),
    /// The operator target did not pass the narrow identifier validation.
    #[error(transparent)]
    InvalidPolicy(#[from] NativeRedactionPolicyError),
    /// Oracle refused the server-authored policy call.
    #[error(transparent)]
    Database(#[from] DbError),
}

/// Apply one full-redaction database policy after the caller has completed its
/// ADMIN confirmation and audit preflight.
///
/// The function probes before it mutates and refuses **before `execute`** when
/// the feature cannot be proven available. It does not commit: `DBMS_REDACT`
/// policy DDL has Oracle-defined transaction semantics, and the caller must
/// record the exact operation in the server audit chain before invoking it.
///
/// # Errors
///
/// Returns [`NativeRedactionApplyError::RequiresAdvancedSecurity`] without
/// calling `DBMS_REDACT` unless the option probe, explicit license
/// acknowledgement, and request gate all agree. Oracle failures propagate as
/// [`NativeRedactionApplyError::Database`].
pub async fn apply_native_redaction_policy(
    cx: &Cx,
    conn: &dyn OracleConnection,
    requested: bool,
    license_acknowledged: bool,
    policy: &NativeRedactionPolicy,
) -> Result<(), NativeRedactionApplyError> {
    let availability = probe_native_redaction(cx, conn).await?;
    let gate = gate_native_redaction(requested, license_acknowledged, availability);
    if !gate.permits_application() {
        return Err(NativeRedactionApplyError::RequiresAdvancedSecurity(
            gate.note(),
        ));
    }
    conn.execute(
        cx,
        NATIVE_REDACTION_ADD_POLICY_SQL,
        &[
            OracleBind::String(policy.object_schema.clone()),
            OracleBind::String(policy.object_name.clone()),
            OracleBind::String(policy.policy_name.clone()),
            OracleBind::String(policy.column_name.clone()),
        ],
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::RuntimeBuilder;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use crate::types::{OracleBackend, OracleCell, OracleConnectionInfo, OracleRow};

    fn run_with_cx<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(Cx) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async move {
            let cx = Cx::current().expect("block_on installs a current Cx");
            body(cx).await
        })
    }

    struct RecordingConnection {
        responses: Mutex<VecDeque<Result<Vec<OracleRow>, DbError>>>,
        executed: Mutex<Vec<(String, Vec<OracleBind>)>>,
    }

    impl RecordingConnection {
        fn with_probe(response: Result<Vec<OracleRow>, DbError>) -> Self {
            Self {
                responses: Mutex::new(VecDeque::from([response])),
                executed: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait(?Send)]
    impl OracleConnection for RecordingConnection {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            assert_eq!(sql, NATIVE_REDACTION_OPTION_SQL);
            self.responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .expect("one native-redaction probe response")
        }

        async fn execute(&self, _cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
            self.executed
                .lock()
                .expect("executed lock")
                .push((sql.to_owned(), binds.to_vec()));
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    fn option(value: Option<&str>) -> OracleRow {
        OracleRow {
            columns: vec![(
                "ADVANCED_SECURITY".to_owned(),
                OracleCell::new("VARCHAR2", value.map(str::to_owned)),
            )],
        }
    }

    fn policy() -> NativeRedactionPolicy {
        NativeRedactionPolicy::new("app", "customers", "mcp_customer_pii", "email")
            .expect("simple identifiers")
    }

    #[test]
    fn gate_is_fail_closed_for_every_non_ready_combination() {
        for (requested, acknowledged, availability) in [
            (false, false, NativeRedactionAvailability::Available),
            (true, false, NativeRedactionAvailability::Available),
            (
                true,
                true,
                NativeRedactionAvailability::RequiresAdvancedSecurity,
            ),
            (
                true,
                false,
                NativeRedactionAvailability::RequiresAdvancedSecurity,
            ),
        ] {
            assert_ne!(
                gate_native_redaction(requested, acknowledged, availability),
                NativeRedactionGate::Ready
            );
        }
        assert_eq!(
            gate_native_redaction(true, true, NativeRedactionAvailability::Available),
            NativeRedactionGate::Ready
        );
    }

    #[test]
    fn unavailable_gate_has_machine_readable_requires_advanced_security_status() {
        let value = serde_json::to_value(NativeRedactionGate::RequiresAdvancedSecurity)
            .expect("serialize gate");
        assert_eq!(
            value,
            serde_json::Value::String("requires_advanced_security".to_owned())
        );
    }

    #[test]
    fn unavailable_option_refuses_before_any_dbms_redact_call() {
        let conn = RecordingConnection::with_probe(Ok(vec![option(Some("FALSE"))]));
        let conn_ref = &conn;
        let err = run_with_cx(|cx| async move {
            apply_native_redaction_policy(&cx, conn_ref, true, true, &policy())
                .await
                .expect_err("unlicensed option must refuse")
        });
        assert!(matches!(
            err,
            NativeRedactionApplyError::RequiresAdvancedSecurity(_)
        ));
        assert!(
            conn.executed.lock().expect("executed lock").is_empty(),
            "the unavailable gate must not silently call DBMS_REDACT"
        );
    }

    #[test]
    fn unreadable_option_refuses_before_any_dbms_redact_call() {
        let conn = RecordingConnection::with_probe(Err(DbError::Query(
            "ORA-00942: table or view does not exist".to_owned(),
        )));
        let conn_ref = &conn;
        let err = run_with_cx(|cx| async move {
            apply_native_redaction_policy(&cx, conn_ref, true, true, &policy())
                .await
                .expect_err("unreadable option must refuse")
        });
        assert!(matches!(
            err,
            NativeRedactionApplyError::RequiresAdvancedSecurity(_)
        ));
        assert!(conn.executed.lock().expect("executed lock").is_empty());
    }

    #[test]
    fn acknowledged_available_option_uses_only_bound_policy_identifiers() {
        let conn = RecordingConnection::with_probe(Ok(vec![option(Some("TRUE"))]));
        let conn_ref = &conn;
        run_with_cx(|cx| async move {
            apply_native_redaction_policy(&cx, conn_ref, true, true, &policy())
                .await
                .expect("available acknowledged option applies policy")
        });
        let executed = conn.executed.lock().expect("executed lock");
        assert_eq!(executed.len(), 1);
        let (sql, binds) = &executed[0];
        assert_eq!(sql, NATIVE_REDACTION_ADD_POLICY_SQL);
        assert!(sql.contains("DBMS_REDACT.ADD_POLICY"));
        assert!(sql.contains("object_schema => :1"));
        assert!(sql.contains("column_name => :4"));
        assert!(!sql.contains("APP"));
        assert_eq!(
            binds,
            &[
                OracleBind::String("APP".to_owned()),
                OracleBind::String("CUSTOMERS".to_owned()),
                OracleBind::String("MCP_CUSTOMER_PII".to_owned()),
                OracleBind::String("EMAIL".to_owned()),
            ]
        );
    }

    #[test]
    fn invalid_or_quoted_policy_identifiers_are_refused() {
        for (field, args) in [
            ("object_schema", ("app owner", "CUSTOMERS", "P", "EMAIL")),
            ("object_name", ("APP", "\"Customers\"", "P", "EMAIL")),
            ("policy_name", ("APP", "CUSTOMERS", "", "EMAIL")),
            ("column_name", ("APP", "CUSTOMERS", "P", "9EMAIL")),
        ] {
            let err = NativeRedactionPolicy::new(args.0, args.1, args.2, args.3)
                .expect_err("narrow identifier grammar");
            assert_eq!(err, NativeRedactionPolicyError::InvalidIdentifier { field });
        }
    }
}
