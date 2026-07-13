//! The **oracledb contract suite** (B7; reciprocal cross-repo gate, provides
//! oracledb's W3-E7.3).
//!
//! This suite pins the behavior `oraclemcp` relies on from the `oracledb`
//! driver *through* the [`OracleConnection`] adapter seam (ADR-0002). It is
//! authored to be **shared with `oracledb`**: `oracledb`'s own 1.0
//! qualification builds and runs this "direct oraclemcp contract suite" on its
//! RC SHA. To keep it liftable/referenceable from the other repo, it is a
//! single self-contained module with no dependency on `oraclemcp` internals
//! beyond the published `oraclemcp-db` surface and the shared
//! `oraclemcp-error` classifier.
//!
//! # Structure
//!
//! Two layers, both with explicit assertions per case:
//!
//! - **Deterministic (no database, always runs):** the contract that does not
//!   need a live server — the error-classification mapping (`ora_code` →
//!   `ErrorClass` → retry hint, the `is_connection_lost`/`is_transient`/
//!   `is_retryable` semantics), the type-serialization shape (NUMBER→string
//!   fidelity, ISO-8601 dates, RAW hex, BLOB base64, NULL, unsupported marker),
//!   and the [`OracleConnection`] trait contract exercised through a scripted
//!   in-process backend (query rows + typed values, positional and named bind
//!   variants, execute + rowcount, the single-execute path the adapter drives
//!   through 0.5.x's `execute_raw` primitive, the explicit default
//!   rejections, and the cancellation-checkpoint mapping of the `*_cx`
//!   methods).
//! - **Live (`live-xe` feature, env-gated):** the same cases against a real
//!   Oracle through [`RustOracleConnection`]. Without a reachable database each
//!   live case prints a loud SKIP banner and returns, matching the repo's
//!   `live-xe` convention so CI without a database stays green.
//!
//! ## `execute` on the 0.5.x driver
//!
//! The `oracledb` 0.5.x driver exposes its execute surface through
//! `Connection::execute_raw` — the array-DML primitive taking
//! `&[Vec<BindValue>]` (the 0.2.2 `execute_query_with_binds*` family was
//! removed). The [`OracleConnection`] adapter surface that `oraclemcp` depends
//! on intentionally exposes only the single-statement `execute` / `execute_cx`:
//! the adapter always drives `execute_raw` with **at most one bind row**,
//! because the server's guarded write path runs one classified statement at a
//! time, never a hidden batch. The contract therefore pins the **single-execute
//! rowcount path** (and, live, the DBMS_OUTPUT OUT-bind retrieval that rides the
//! same `execute_raw` path) as the supported surface, and treats multi-row array
//! DML as a deliberate non-member of the adapter contract until a future seam
//! extension adds it (at which point an `execute_many` case is added here and to
//! the shared oracledb copy).

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_db::{
    DbError, ExecuteOutcome, OracleBackend, OracleBind, OracleCell, OracleConnection,
    OracleConnectionInfo, OracleRoutineArg, OracleRow, SerializeOptions, serialize_cell,
    serialize_row,
};
use oraclemcp_error::{
    ErrorClass, classify_ora_code, envelope_from_oracle_message, parse_ora_code,
};
use serde_json::{Value, json};

/// Run an async test body on a fresh current-thread runtime, handing it the
/// installed request `Cx`.
fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reactor =
        asupersync::runtime::reactor::create_reactor().expect("native reactor for live I/O");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("current-thread runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx");
        body(cx).await
    })
}

/// The cancellation-checkpoint the real adapter applies at each DB boundary,
/// mirrored in the scripted backend so the `Cx`-first cancellation contract can
/// be asserted without a live server.
fn contract_checkpoint(cx: &Cx) -> Result<(), DbError> {
    cx.checkpoint()
        .map_err(|err| DbError::Cancelled(err.to_string()))
}

// ---------------------------------------------------------------------------
// Shared scripted backend
//
// A deterministic in-process `OracleConnection` so the trait contract can be
// asserted without a live server. It records the SQL/binds it was handed and
// replays canned rows, so every assertion below is exact.
// ---------------------------------------------------------------------------

use std::sync::Mutex;

/// One recorded call against the scripted backend.
#[derive(Clone, Debug, PartialEq)]
enum Call {
    Query {
        sql: String,
        binds: Vec<OracleBind>,
    },
    QueryNamed {
        sql: String,
        binds: Vec<(String, OracleBind)>,
    },
    Execute {
        sql: String,
        binds: Vec<OracleBind>,
    },
    Routine {
        plsql_block: String,
        args: Vec<OracleRoutineArg>,
    },
    Commit,
    Rollback,
}

struct ScriptedConn {
    /// Canned rows returned by `query_rows` / `query_rows_named`.
    rows: Vec<OracleRow>,
    /// Rowcount returned by `execute`.
    rowcount: u64,
    /// Ordered OUT cells returned by `call_routine`.
    routine_out_binds: Vec<OracleCell>,
    /// Recorded calls, in order.
    calls: Mutex<Vec<Call>>,
}

impl ScriptedConn {
    fn new(rows: Vec<OracleRow>, rowcount: u64) -> Self {
        ScriptedConn {
            rows,
            rowcount,
            routine_out_binds: Vec::new(),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn with_routine_out_binds(mut self, out_binds: Vec<OracleCell>) -> Self {
        self.routine_out_binds = out_binds;
        self
    }

    fn record(&self, call: Call) {
        self.calls.lock().expect("calls lock").push(call);
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("calls lock").clone()
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for ScriptedConn {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        contract_checkpoint(cx)
    }
    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        contract_checkpoint(cx)?;
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            server_version: Some("23.0.0.0.0".to_owned()),
            ..Default::default()
        })
    }
    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        contract_checkpoint(cx)?;
        self.record(Call::Query {
            sql: sql.to_owned(),
            binds: binds.to_vec(),
        });
        Ok(self.rows.clone())
    }
    async fn query_rows_named(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
    ) -> Result<Vec<OracleRow>, DbError> {
        contract_checkpoint(cx)?;
        self.record(Call::QueryNamed {
            sql: sql.to_owned(),
            binds: binds.to_vec(),
        });
        Ok(self.rows.clone())
    }
    async fn execute(&self, cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
        contract_checkpoint(cx)?;
        self.record(Call::Execute {
            sql: sql.to_owned(),
            binds: binds.to_vec(),
        });
        Ok(self.rowcount)
    }
    async fn call_routine(
        &self,
        cx: &Cx,
        plsql_block: &str,
        args: &[OracleRoutineArg],
    ) -> Result<ExecuteOutcome, DbError> {
        contract_checkpoint(cx)?;
        self.record(Call::Routine {
            plsql_block: plsql_block.to_owned(),
            args: args.to_vec(),
        });
        Ok(ExecuteOutcome::new(
            self.rowcount,
            self.routine_out_binds.clone(),
        ))
    }
    async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
        contract_checkpoint(cx)?;
        self.record(Call::Commit);
        Ok(())
    }
    async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
        contract_checkpoint(cx)?;
        self.record(Call::Rollback);
        Ok(())
    }
}

/// Build a one-row result with the given `(column, type, value)` cells.
fn row(cells: &[(&str, &str, Option<&str>)]) -> OracleRow {
    OracleRow {
        columns: cells
            .iter()
            .map(|(name, ty, value)| {
                (
                    (*name).to_owned(),
                    OracleCell::new(*ty, value.map(ToOwned::to_owned)),
                )
            })
            .collect(),
    }
}

// ===========================================================================
// CONTRACT GROUP 1 — error mapping
//
// The adapter classifies driver errors string-first on 0.2.2: an embedded
// `ORA-` code drives the ErrorClass, which drives the retry hint. This is the
// `ora_code` / connection-disposition / retry-hint path the dispatch layer
// relies on.
// ===========================================================================

#[test]
fn contract_error_ora_code_extraction() {
    // `ora_code`: the leading ORA- code is extracted; a code embedded mid-string
    // is still found; non-Oracle text yields None.
    assert_eq!(
        parse_ora_code("ORA-00942: table or view does not exist"),
        Some(942)
    );
    assert_eq!(
        parse_ora_code("driver: ORA-01031: insufficient privileges"),
        Some(1031)
    );
    assert_eq!(parse_ora_code("connection reset by peer"), None);
}

#[test]
fn contract_error_connection_lost_is_transient_and_retryable() {
    // is_connection_lost: ORA-03113/03114 (end-of-file / not-connected) are the
    // canonical lost-connection codes. The adapter classifies them Transient,
    // and Transient is retryable.
    for code in [3113, 3114] {
        let class = classify_ora_code(code);
        assert_eq!(
            class,
            ErrorClass::Transient,
            "ORA-{code} is a lost connection"
        );
        assert!(class.is_retryable(), "a lost connection is safe to retry");
    }
}

#[test]
fn contract_error_transient_network_is_retryable() {
    // is_transient: TNS/network conditions (no-listener, timeout) are Transient
    // and retryable.
    for code in [12541, 12170, 12537] {
        let class = classify_ora_code(code);
        assert_eq!(class, ErrorClass::Transient, "ORA-{code} is transient");
        assert!(class.is_retryable());
    }
}

#[test]
fn contract_error_admission_backpressure_is_busy_retryable() {
    // Listener/session-limit conditions are admission backpressure (Busy), which
    // is retryable with a wait hint rather than a hard failure.
    let class = classify_ora_code(12519);
    assert_eq!(class, ErrorClass::Busy);
    assert!(class.is_retryable());
}

#[test]
fn contract_error_object_and_privilege_are_not_retryable() {
    // The retry hint must NOT fire for deterministic user-fixable errors: a
    // missing object or a privilege error will fail identically on retry.
    let missing = classify_ora_code(942);
    assert_eq!(missing, ErrorClass::ObjectNotFound);
    assert!(!missing.is_retryable());

    let denied = classify_ora_code(1031);
    assert_eq!(denied, ErrorClass::InsufficientPrivilege);
    assert!(!denied.is_retryable());
}

#[test]
fn contract_error_unknown_code_is_honest_internal() {
    // An unmapped Oracle code is classified Internal (an honest "not classified
    // yet"), never guessed into a friendlier, possibly-wrong class.
    let class = classify_ora_code(7777);
    assert_eq!(class, ErrorClass::Internal);
    assert!(!class.is_retryable());
}

#[test]
fn contract_error_dberror_into_envelope_carries_code_and_class() {
    // The adapter's DbError -> ErrorEnvelope rendering: an Oracle-originated
    // DbError::Query with an embedded code surfaces both the numeric ora_code
    // and the classified ErrorClass for the agent to branch on.
    let env = DbError::Query("ORA-00942: table or view does not exist".to_owned()).into_envelope();
    assert_eq!(env.error_class, ErrorClass::ObjectNotFound);
    assert_eq!(env.ora_code, Some(942));

    // A connect error with no recognizable code stays ConnectionFailed (not a
    // bare Internal) — the disposition is "the server connection failed".
    let env = DbError::Connect("listener refused".to_owned()).into_envelope();
    assert_eq!(env.error_class, ErrorClass::ConnectionFailed);

    // A pool acquire failure is admission Busy and carries a retry-after hint.
    let env = DbError::Pool("acquire timed out".to_owned()).into_envelope();
    assert_eq!(env.error_class, ErrorClass::Busy);
    assert_eq!(env.retry_after_ms, Some(250));

    // A cancelled boundary maps to Timeout with no retry-after (cancellation is
    // caller-driven, not a backoff condition).
    let env = DbError::Cancelled("query.before: cancelled".to_owned()).into_envelope();
    assert_eq!(env.error_class, ErrorClass::Timeout);
    assert!(env.retry_after_ms.is_none());
}

#[test]
fn contract_error_envelope_from_message_round_trips_class() {
    // The shared classifier the adapter calls: a raw driver message round-trips
    // to the same class as classify_ora_code(code).
    let env = envelope_from_oracle_message("ORA-03113: end-of-file on communication channel");
    assert_eq!(env.error_class, ErrorClass::Transient);
    assert_eq!(env.ora_code, Some(3113));
    assert!(env.error_class.is_retryable());
}

// ===========================================================================
// CONTRACT GROUP 2 — type serialization shape (NUMBER->string fidelity etc.)
//
// The adapter fetches every cell as the Oracle type name plus nullable text;
// the serializer applies the canonical JSON mapping. This pins the shape a
// fetched row must serialize to, deterministically and NLS-invariantly.
// ===========================================================================

fn ser(ty: &str, value: &str) -> Value {
    serialize_cell(
        &OracleCell::new(ty, Some(value.to_owned())),
        &SerializeOptions::default(),
    )
}

#[test]
fn contract_type_number_is_lossless_string() {
    // The non-negotiable rule: NUMBER -> JSON string, never an f64 (no precision
    // loss for 38-digit NUMBER).
    assert_eq!(ser("NUMBER", "42"), json!("42"));
    assert_eq!(ser("NUMBER", "-3.14159"), json!("-3.14159"));
    assert_eq!(
        ser("NUMBER(38,0)", "99999999999999999999999999999999999999"),
        json!("99999999999999999999999999999999999999")
    );
}

#[test]
fn contract_type_native_floats_are_json_numbers() {
    // BINARY_DOUBLE / BINARY_FLOAT are IEEE and f64-safe, so they serialize as
    // JSON numbers (distinct from NUMBER's string contract).
    assert_eq!(ser("BINARY_DOUBLE", "3.5"), json!(3.5));
    assert_eq!(ser("BINARY_FLOAT", "1.25"), json!(1.25));
}

#[test]
fn contract_type_dates_are_iso_8601_and_nls_invariant() {
    // DATE/TIMESTAMP canonicalize to ISO-8601 regardless of the driver's
    // locale-dependent input spacing — the NLS-decoupling guarantee.
    assert_eq!(
        ser("DATE", "2026-06-01 12:00:00"),
        json!("2026-06-01T12:00:00")
    );
    assert_eq!(
        ser("TIMESTAMP(6)", "2026-06-01 12:00:00.123456"),
        json!("2026-06-01T12:00:00.123456")
    );
    assert_eq!(
        ser(
            "TIMESTAMP(9) WITH TIME ZONE",
            "2026-06-29 12:34:56.987654321 -05:30"
        ),
        json!("2026-06-29T12:34:56.987654321-05:30")
    );
    // Already-ISO input yields the identical canonical output.
    assert_eq!(
        ser("DATE", "2026-06-01T12:00:00"),
        ser("DATE", "2026-06-01 12:00:00")
    );
}

#[test]
fn contract_type_raw_is_hex_and_blob_is_base64() {
    // RAW fetched as text is hex; a binary BLOB cell is base64 with a length and
    // a truncation flag.
    assert_eq!(ser("RAW(4)", "DEADBEEF"), json!("DEADBEEF"));

    let blob = serialize_cell(
        &OracleCell::binary("BLOB", vec![0xDE, 0xAD, 0xBE, 0xEF]),
        &SerializeOptions::default(),
    );
    assert_eq!(blob["encoding"], json!("base64"));
    assert_eq!(blob["data"], json!("3q2+7w=="));
    assert_eq!(blob["byte_length"], json!(4));
    assert_eq!(blob["truncated"], json!(false));
}

#[test]
fn contract_type_null_is_json_null() {
    // A SQL NULL is JSON null for every type — never an empty string or a
    // type-specific sentinel.
    for ty in [
        "NUMBER",
        "VARCHAR2(10)",
        "DATE",
        "TIMESTAMP(6)",
        "RAW(4)",
        "BLOB",
        "CLOB",
    ] {
        let v = serialize_cell(&OracleCell::new(ty, None), &SerializeOptions::default());
        assert_eq!(v, Value::Null, "NULL {ty} must be JSON null");
    }
}

#[test]
fn contract_type_unsupported_is_explicit_marker_never_silent() {
    // An unserialized type emits an explicit unsupported marker + warning, never
    // a silent best-effort coercion.
    let v = ser("SDO_GEOMETRY", "(MDSYS.SDO_GEOMETRY...)");
    assert_eq!(v["unsupported"], json!("SDO_GEOMETRY"));
    assert_eq!(v["value"], Value::Null);
    assert!(v["warning"].is_string());

    // Driver ObjectValue/UDT payloads are carried as typed unsupported markers
    // with object identity and byte length, not as dumped packed bytes.
    let object = serialize_cell(
        &OracleCell::structured(
            "HR.ADDRESS_T",
            json!({
                "kind": "unsupported",
                "unsupported": "oracle_object",
                "oracle_value_kind": "Object",
                "schema": "HR",
                "type_name": "ADDRESS_T",
                "packed_byte_length": 4,
                "value": null,
                "warning": "Oracle object/UDT values are not decoded by default"
            }),
        ),
        &SerializeOptions::default(),
    );
    assert_eq!(object["unsupported"], json!("oracle_object"));
    assert_eq!(object["schema"], json!("HR"));
    assert_eq!(object["type_name"], json!("ADDRESS_T"));
    assert_eq!(object["packed_byte_length"], json!(4));
    assert_eq!(object["value"], Value::Null);
    assert!(object["warning"].is_string());
    assert!(
        !object.to_string().contains("deadbeef"),
        "packed object bytes must not leak through the public marker"
    );
}

#[test]
fn contract_type_structured_carrier_serializes_verbatim() {
    // Non-scalar values that the adapter materializes structurally must not
    // flatten through lossy debug/text rendering before serialization.
    let v = serialize_cell(
        &OracleCell::structured(
            "JSON",
            json!({
                "kind": "json",
                "value": {
                    "customer": 42,
                    "flags": [true, false],
                    "nested": { "status": "active" }
                }
            }),
        ),
        &SerializeOptions::default(),
    );
    assert_eq!(
        v,
        json!({
            "kind": "json",
            "value": {
                "customer": 42,
                "flags": [true, false],
                "nested": { "status": "active" }
            }
        })
    );
}

#[test]
fn contract_type_tstz_round_trips_with_offset_in_structured_carrier() {
    // The C1 carrier is intentionally typed rather than raw JSON: it preserves
    // Oracle scalar identity for arrays, OSON, vectors, and nested TSTZ values.
    let structured = json!({
        "kind": "array",
        "items": [
            {
                "kind": "json",
                "value": {
                    "kind": "object",
                    "entries": [
                        {
                            "key": "wide_number",
                            "value": {
                                "kind": "number",
                                "value": "99999999999999999999999999999999999999"
                            }
                        },
                        {
                            "key": "raw",
                            "value": {
                                "kind": "raw",
                                "encoding": "hex",
                                "data": "deadbeef",
                                "byte_length": 4
                            }
                        }
                    ]
                }
            },
            {
                "kind": "vector",
                "storage": "sparse",
                "format": "float64",
                "num_dimensions": 4,
                "indices": [0, 3],
                "values": [1.0, -1.5]
            },
            {
                "kind": "timestamp_tz",
                "value": "2026-06-29 12:34:56.987654321 -05:30",
                "year": 2026,
                "month": 6,
                "day": 29,
                "hour": 12,
                "minute": 34,
                "second": 56,
                "nanosecond": 987654321,
                "offset_minutes": -330
            }
        ]
    });

    let rendered = serialize_cell(
        &OracleCell::structured("TABLE OF ANYDATA", structured.clone()),
        &SerializeOptions::default(),
    );
    assert_eq!(rendered, structured);

    let encoded = serde_json::to_string(&rendered).expect("structured cell serializes");
    let decoded: Value = serde_json::from_str(&encoded).expect("structured cell parses");
    assert_eq!(decoded, structured);
}

#[test]
fn contract_row_serializes_as_named_object() {
    // A whole row serializes to a JSON object keyed by column name, each value
    // following its per-type contract above.
    let r = row(&[
        ("ID", "NUMBER", Some("7")),
        ("NAME", "VARCHAR2(10)", Some("scott")),
        ("MISSING", "VARCHAR2(10)", None),
    ]);
    let v = serialize_row(&r, &SerializeOptions::default());
    assert_eq!(v["ID"], json!("7"));
    assert_eq!(v["NAME"], json!("scott"));
    assert_eq!(v["MISSING"], Value::Null);
}

// ===========================================================================
// CONTRACT GROUP 3 — the OracleConnection trait contract (scripted backend)
//
// These pin the adapter SHAPE: how query/bind/execute/commit/rollback flow
// through the trait, what binds are forwarded, what rowcount comes back, and
// what the defaulted methods reject. They run with no live server.
// ===========================================================================

#[test]
fn contract_query_returns_rows_with_typed_values() {
    // query_rows: rows come back in select-list order, NUMBER preserved as text
    // (never coerced through f64 at the boundary), case-insensitive lookups.
    let conn = ScriptedConn::new(
        vec![row(&[
            ("ID", "NUMBER", Some("1234567890123456789")),
            ("NAME", "VARCHAR2(10)", Some("scott")),
        ])],
        0,
    );
    let c = &conn;
    let rows = run_with_cx(|cx| async move {
        c.query_rows(
            &cx,
            "SELECT id, name FROM emp WHERE id = :1",
            &[OracleBind::from(1i64)],
        )
        .await
        .expect("query")
    });
    assert_eq!(rows.len(), 1);
    // NUMBER fidelity at the row boundary: the full 19-digit value survives.
    assert_eq!(rows[0].text("ID"), Some("1234567890123456789"));
    assert_eq!(rows[0].parse_i64("ID"), Some(1234567890123456789));
    assert_eq!(rows[0].text("name"), Some("scott")); // case-insensitive

    // The SQL and the positional bind were forwarded verbatim (bound, not
    // interpolated).
    assert_eq!(
        conn.calls(),
        vec![Call::Query {
            sql: "SELECT id, name FROM emp WHERE id = :1".to_owned(),
            binds: vec![OracleBind::I64(1)],
        }]
    );
}

#[test]
fn contract_bind_variants_are_forwarded_as_typed_binds() {
    // Every OracleBind variant is forwarded as itself — the contract is that
    // values are ALWAYS bound, never rendered into SQL text.
    let conn = ScriptedConn::new(vec![], 0);
    let binds = vec![
        OracleBind::Null,
        OracleBind::String("hi".to_owned()),
        OracleBind::I64(-7),
        OracleBind::F64(2.5),
        OracleBind::Bool(true),
        OracleBind::TimestampTz {
            year: 2026,
            month: 6,
            day: 29,
            hour: 12,
            minute: 34,
            second: 56,
            nanosecond: 987_654_321,
            offset_minutes: -330,
        },
    ];
    let c = &conn;
    let b = &binds;
    run_with_cx(|cx| async move {
        c.query_rows(&cx, "SELECT :1,:2,:3,:4,:5,:6 FROM dual", b)
            .await
            .expect("query");
    });
    assert_eq!(
        conn.calls(),
        vec![Call::Query {
            sql: "SELECT :1,:2,:3,:4,:5,:6 FROM dual".to_owned(),
            binds,
        }]
    );
}

#[test]
fn contract_named_binds_are_forwarded_by_name() {
    // query_rows_named: named binds are forwarded as (name, value) pairs, in
    // order, to a backend that supports them.
    let conn = ScriptedConn::new(vec![row(&[("V", "VARCHAR2(5)", Some("x"))])], 0);
    let binds = vec![
        ("p_id".to_owned(), OracleBind::I64(9)),
        ("p_name".to_owned(), OracleBind::String("x".to_owned())),
    ];
    let c = &conn;
    let b = &binds;
    let rows = run_with_cx(|cx| async move {
        c.query_rows_named(&cx, "SELECT :p_name AS v FROM emp WHERE id = :p_id", b)
            .await
            .expect("named query")
    });
    assert_eq!(rows[0].text("V"), Some("x"));
    assert_eq!(
        conn.calls(),
        vec![Call::QueryNamed {
            sql: "SELECT :p_name AS v FROM emp WHERE id = :p_id".to_owned(),
            binds,
        }]
    );
}

#[test]
fn contract_execute_returns_rowcount() {
    // execute: a DML statement returns SQL%ROWCOUNT. The single-execute path is
    // the supported write surface (see the module note on execute_many).
    let conn = ScriptedConn::new(vec![], 3);
    let c = &conn;
    let affected = run_with_cx(|cx| async move {
        c.execute(
            &cx,
            "UPDATE emp SET sal = sal * 1.1 WHERE deptno = :1",
            &[OracleBind::from(10i64)],
        )
        .await
        .expect("execute")
    });
    assert_eq!(
        affected, 3,
        "rowcount is the SQL%ROWCOUNT the driver returned"
    );
    assert_eq!(
        conn.calls(),
        vec![Call::Execute {
            sql: "UPDATE emp SET sal = sal * 1.1 WHERE deptno = :1".to_owned(),
            binds: vec![OracleBind::I64(10)],
        }]
    );
}

#[test]
fn contract_call_routine_returns_ordered_out_binds() {
    // call_routine is an adapter-internal routine seam, not an agent tool. Its
    // public contract is ordered OUT cells: callers may mix ordinary input
    // binds with return / OUT / IN-OUT slots, and out_binds() contains only the
    // output-producing slots in declared positional order.
    let conn = ScriptedConn::new(vec![], 0).with_routine_out_binds(vec![
        OracleCell::new("NUMBER", Some("42".to_owned())),
        OracleCell::new("VARCHAR2", Some("first".to_owned())),
    ]);
    let args = vec![
        OracleRoutineArg::return_output(2, 1, 22),
        OracleRoutineArg::input(OracleBind::String("input".to_owned())),
        OracleRoutineArg::output(1, 1, 32_767),
    ];
    let c = &conn;
    let a = &args;
    let outcome = run_with_cx(|cx| async move {
        c.call_routine(&cx, "BEGIN :1 := pkg.contract_probe(:2, :3); END;", a)
            .await
            .expect("routine call")
    });
    assert_eq!(outcome.rows_affected(), 0);
    assert_eq!(
        outcome.out_binds(),
        &[
            OracleCell::new("NUMBER", Some("42".to_owned())),
            OracleCell::new("VARCHAR2", Some("first".to_owned())),
        ]
    );
    assert_eq!(
        conn.calls(),
        vec![Call::Routine {
            plsql_block: "BEGIN :1 := pkg.contract_probe(:2, :3); END;".to_owned(),
            args,
        }]
    );
}

#[test]
fn contract_named_binds_default_rejects_explicitly_not_silently() {
    // A backend without named-bind support must FAIL EXPLICITLY rather than
    // silently rewrite SQL — pinned via the trait's default method on a backend
    // that does not override it.
    struct NoNamedBinds;
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for NoNamedBinds {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
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
            _: &str,
            _: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            Ok(vec![])
        }
        async fn execute(&self, _cx: &Cx, _: &str, _: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }
    let conn = NoNamedBinds;
    run_with_cx(|cx| async move {
        let err = conn
            .query_rows_named(
                &cx,
                "SELECT :x FROM dual",
                &[("x".to_owned(), OracleBind::I64(1))],
            )
            .await
            .expect_err("default named-bind path must reject");
        assert!(matches!(err, DbError::Query(_)), "{err:?}");

        // DBMS_OUTPUT capture is likewise an explicit-rejection default.
        let err = conn
            .read_dbms_output(&cx, 10, 100)
            .await
            .expect_err("default dbms_output rejects");
        assert!(matches!(err, DbError::Execute(_)), "{err:?}");

        // Adapter-internal routine execution is also an explicit opt-in backend
        // capability. A backend that does not implement it must fail closed.
        let err = conn
            .call_routine(
                &cx,
                "BEGIN pkg.contract_probe(:1); END;",
                &[OracleRoutineArg::output(1, 1, 32_767)],
            )
            .await
            .expect_err("default routine call rejects");
        assert!(matches!(err, DbError::Execute(_)), "{err:?}");
    });
}

#[test]
fn contract_commit_and_rollback_flow_through_trait() {
    // commit / rollback are forwarded to the backend in call order.
    let conn = ScriptedConn::new(vec![], 1);
    let c = &conn;
    run_with_cx(|cx| async move {
        c.execute(&cx, "INSERT INTO t VALUES (1)", &[])
            .await
            .expect("insert");
        c.commit(&cx).await.expect("commit");
        c.execute(&cx, "INSERT INTO t VALUES (2)", &[])
            .await
            .expect("insert");
        c.rollback(&cx).await.expect("rollback");
    });
    let calls = conn.calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[1], Call::Commit);
    assert_eq!(calls[3], Call::Rollback);
}

#[test]
fn contract_cancellation_checkpoint_maps_to_cancelled_error() {
    // The `Cx`-first cancellation contract: when the request context is already
    // cancelled, the adapter's checkpoint aborts the DB boundary with
    // DbError::Cancelled BEFORE the underlying call runs — proven here with a
    // scripted backend (which mirrors the real adapter's boundary checkpoint) so
    // no live server is needed.
    let conn = ScriptedConn::new(vec![row(&[("N", "NUMBER", Some("1"))])], 0);
    let c = &conn;
    run_with_cx(|cx| async move {
        cx.set_cancel_requested(true);

        let err = c
            .query_rows(&cx, "SELECT 1 FROM dual", &[])
            .await
            .expect_err("cancelled context aborts the query boundary");
        assert!(matches!(err, DbError::Cancelled(_)), "{err:?}");

        let err = c
            .execute(&cx, "UPDATE t SET x = 1", &[])
            .await
            .expect_err("cancelled context aborts the execute boundary");
        assert!(matches!(err, DbError::Cancelled(_)), "{err:?}");
    });
    // The cancelled boundary aborted BEFORE the backend was touched: no Query /
    // Execute call was recorded.
    assert!(
        conn.calls().is_empty(),
        "a pre-cancelled context must not reach the backend: {:?}",
        conn.calls()
    );
}

// ===========================================================================
// CONTRACT GROUP 4 — live (real Oracle through RustOracleConnection)
//
// Gated behind `live-xe` AND a runtime reachability probe. Without a reachable
// database each case prints a SKIP banner and returns, so CI without a DB stays
// green. These prove the SAME contract against a live 23ai.
// ===========================================================================

#[cfg(feature = "live-xe")]
mod live {
    use super::*;
    use oraclemcp_db::{OracleConnectOptions, RustOracleConnection};

    fn live_opts() -> OracleConnectOptions {
        OracleConnectOptions {
            connect_string: std::env::var("ORACLEMCP_TEST_DSN")
                .unwrap_or_else(|_| "//localhost:1521/FREEPDB1".to_owned()),
            username: Some(
                std::env::var("ORACLEMCP_TEST_USER").unwrap_or_else(|_| "system".to_owned()),
            ),
            password: Some(
                std::env::var("ORACLEMCP_TEST_PASSWORD")
                    .unwrap_or_else(|_| "test_password".to_owned()),
            ),
            ..Default::default()
        }
    }

    async fn connect_or_skip(cx: &Cx, test_name: &str) -> Option<RustOracleConnection> {
        match RustOracleConnection::connect(cx, live_opts()).await {
            Ok(conn) => Some(conn),
            Err(e) => {
                eprintln!(
                    "[live-xe] SKIP {test_name}: no reachable Oracle ({e}); set \
                     ORACLEMCP_TEST_DSN / _USER / _PASSWORD"
                );
                None
            }
        }
    }

    #[test]
    fn live_contract_query_binds_typed_values() {
        run_with_cx(|cx| async move {
            let Some(conn) = connect_or_skip(&cx, "live_contract_query_binds_typed_values").await
            else {
                return;
            };
            // Scalar query.
            let rows = conn
                .query_rows(&cx, "SELECT 1 AS one FROM dual", &[])
                .await
                .expect("scalar");
            assert_eq!(rows[0].text("ONE"), Some("1"));

            // Positional bind, bound not interpolated.
            let rows = conn
                .query_rows(
                    &cx,
                    "SELECT :1 AS v FROM dual",
                    &[OracleBind::from("hello")],
                )
                .await
                .expect("string bind");
            assert_eq!(rows[0].text("V"), Some("hello"));

            // NUMBER->string fidelity against a live server: a 38-digit literal
            // must survive as an exact string (no f64 truncation).
            let big = "99999999999999999999999999999999999999";
            let rows = conn
                .query_rows(
                    &cx,
                    &format!("SELECT TO_NUMBER('{big}') AS n FROM dual"),
                    &[],
                )
                .await
                .expect("big number");
            assert_eq!(rows[0].text("N"), Some(big));
        });
    }

    #[test]
    fn live_contract_execute_rowcount_and_rollback() {
        run_with_cx(|cx| async move {
            let Some(conn) =
                connect_or_skip(&cx, "live_contract_execute_rowcount_and_rollback").await
            else {
                return;
            };
            // Use a private temp table so the test is self-contained and leaves no
            // trace (rollback discards the rows; the table is session-scoped).
            if let Err(e) = conn
                .execute(
                    &cx,
                    "CREATE PRIVATE TEMPORARY TABLE ora$ptt_b7_contract (id NUMBER) \
             ON COMMIT PRESERVE DEFINITION",
                    &[],
                )
                .await
            {
                eprintln!("[live-xe] SKIP execute rowcount: cannot create PTT ({e})");
                return;
            }
            let affected = conn
                .execute(
                    &cx,
                    "INSERT INTO ora$ptt_b7_contract (id) SELECT level FROM dual CONNECT BY level <= :1",
                    &[OracleBind::from(3i64)],
                )
                .await
                .expect("insert rows");
            assert_eq!(affected, 3, "INSERT...CONNECT BY level<=3 affects 3 rows");

            let rows = conn
                .query_rows(&cx, "SELECT COUNT(*) AS c FROM ora$ptt_b7_contract", &[])
                .await
                .expect("count");
            assert_eq!(rows[0].parse_i64("C"), Some(3));

            // Rollback discards the uncommitted rows.
            conn.rollback(&cx).await.expect("rollback");
            let rows = conn
                .query_rows(&cx, "SELECT COUNT(*) AS c FROM ora$ptt_b7_contract", &[])
                .await
                .expect("count after rollback");
            assert_eq!(
                rows[0].parse_i64("C"),
                Some(0),
                "rollback discarded the rows"
            );
        });
    }

    #[test]
    fn live_contract_error_mapping_object_not_found() {
        run_with_cx(|cx| async move {
            let Some(conn) =
                connect_or_skip(&cx, "live_contract_error_mapping_object_not_found").await
            else {
                return;
            };
            // A real ORA-00942 from the server must classify to ObjectNotFound
            // with the numeric code preserved through the adapter's error path.
            let err = conn
                .query_rows(&cx, "SELECT * FROM a_table_that_does_not_exist_b7", &[])
                .await
                .expect_err("missing table must error");
            let env = err.into_envelope();
            assert_eq!(env.ora_code, Some(942), "envelope: {env:?}");
            assert_eq!(env.error_class, ErrorClass::ObjectNotFound);
            assert!(!env.error_class.is_retryable());
        });
    }

    #[test]
    fn live_contract_dbms_output_out_binds() {
        // Pins the OUT-bind retrieval path that the 0.2.2 -> 0.5.x cut-over moved
        // onto `execute_raw`: `read_dbms_output` runs `DBMS_OUTPUT.GET_LINE(:1, :2)`
        // and reads the two OUT binds (`:1` line text, `:2` status) out of
        // `QueryResult::out_values` via the adapter's key-based `output_value`.
        // The adversarial cut-over review flagged this equivalence as resting on
        // the external 0.5.x driver contract; this asserts it against a real 23ai.
        run_with_cx(|cx| async move {
            let Some(conn) = connect_or_skip(&cx, "live_contract_dbms_output_out_binds").await
            else {
                return;
            };
            conn.enable_dbms_output(&cx, None)
                .await
                .expect("enable dbms_output");
            conn.execute(
                &cx,
                "BEGIN DBMS_OUTPUT.PUT_LINE('b7 line one'); \
                 DBMS_OUTPUT.PUT_LINE('b7 line two'); END;",
                &[],
            )
            .await
            .expect("emit dbms_output lines");
            let out = conn
                .read_dbms_output(&cx, 100, 100_000)
                .await
                .expect("drain dbms_output");
            assert_eq!(
                out.lines,
                vec!["b7 line one".to_owned(), "b7 line two".to_owned()],
                "DBMS_OUTPUT lines must drain in emission order through the \
                 execute_raw OUT-bind path"
            );
            assert!(!out.truncated, "two short lines must not truncate");
        });
    }

    #[test]
    fn live_contract_call_routine_out_bind_order_deterministic() {
        // Pins the R2 adapter routine path against a real server. The two OUT
        // values are declared as line text then status; the returned
        // ExecuteOutcome must keep that order regardless of the driver's raw
        // OUT-bind vector ordering.
        run_with_cx(|cx| async move {
            let Some(conn) = connect_or_skip(
                &cx,
                "live_contract_call_routine_out_bind_order_deterministic",
            )
            .await
            else {
                return;
            };
            conn.enable_dbms_output(&cx, None)
                .await
                .expect("enable dbms_output");
            conn.execute(
                &cx,
                "BEGIN DBMS_OUTPUT.PUT_LINE('r2 routine line'); END;",
                &[],
            )
            .await
            .expect("emit dbms_output line");

            let outcome = conn
                .call_routine(
                    &cx,
                    "BEGIN DBMS_OUTPUT.GET_LINE(:1, :2); END;",
                    &[
                        // ORA_TYPE_NUM_VARCHAR + CS_FORM_IMPLICIT.
                        OracleRoutineArg::output(1, 1, 32_767),
                        // ORA_TYPE_NUM_NUMBER + CS_FORM_IMPLICIT.
                        OracleRoutineArg::output(2, 1, 22),
                    ],
                )
                .await
                .expect("call routine");
            assert_eq!(outcome.out_binds().len(), 2);
            assert_eq!(outcome.out_binds()[0].text(), Some("r2 routine line"));
            assert_eq!(outcome.out_binds()[1].text(), Some("0"));
        });
    }

    #[test]
    fn live_contract_call_routine_mixes_input_return_and_out_binds() {
        // Pins the #2 closeout shape against a real server: one ordinary input
        // bind plus a return slot and an OUT slot, with only output-producing
        // positions returned to the caller.
        run_with_cx(|cx| async move {
            let Some(conn) = connect_or_skip(
                &cx,
                "live_contract_call_routine_mixes_input_return_and_out_binds",
            )
            .await
            else {
                return;
            };

            let outcome = conn
                .call_routine(
                    &cx,
                    "BEGIN :1 := LENGTH(:2); :3 := UPPER(:2); END;",
                    &[
                        // ORA_TYPE_NUM_NUMBER + CS_FORM_IMPLICIT.
                        OracleRoutineArg::return_output(2, 1, 22),
                        OracleRoutineArg::input(OracleBind::String("r4".to_owned())),
                        // ORA_TYPE_NUM_VARCHAR + CS_FORM_IMPLICIT.
                        OracleRoutineArg::output(1, 1, 32_767),
                    ],
                )
                .await
                .expect("call mixed routine block");
            assert_eq!(outcome.out_binds().len(), 2);
            assert_eq!(outcome.out_binds()[0].text(), Some("2"));
            assert_eq!(outcome.out_binds()[1].text(), Some("R4"));
        });
    }

    #[test]
    fn live_flashback_read_as_of_current_scn_returns_rows_and_leaves_session_clean() {
        // K9: prove `read_query_as_of` runs the SAME proven SQL inside a bounded
        // DBMS_FLASHBACK window against a real server, returns rows, and leaves
        // the session in normal (current-SCN) read mode afterwards.
        use oraclemcp_db::{AsOf, QueryCaps, read_query_as_of};
        run_with_cx(|cx| async move {
            let Some(conn) = connect_or_skip(
                &cx,
                "live_flashback_read_as_of_current_scn_returns_rows_and_leaves_session_clean",
            )
            .await
            else {
                return;
            };

            // Current SCN via the flashback API (also confirms the session can
            // read the SCN at all).
            let scn_rows = match conn
                .query_rows(
                    &cx,
                    "SELECT dbms_flashback.get_system_change_number AS scn FROM dual",
                    &[],
                )
                .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    eprintln!("[live-xe] SKIP flashback: cannot read current SCN ({e})");
                    return;
                }
            };
            let scn: u64 = scn_rows[0]
                .text("SCN")
                .and_then(|s| s.parse().ok())
                .expect("a numeric current SCN");

            // Flashback-read a STABLE object: `dual` has no DDL churn, so AS OF at
            // the current SCN is well-defined (no ORA-01466). The SAME proven SQL
            // runs UNCHANGED inside the DBMS_FLASHBACK window.
            let response = match read_query_as_of(
                &cx,
                &conn,
                "SELECT count(*) AS c FROM dual",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(scn),
            )
            .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    // A profile without the FLASHBACK privilege surfaces ORA-01031
                    // here — a correct fail-closed refusal, not a test failure.
                    eprintln!(
                        "[live-xe] SKIP flashback read (likely missing FLASHBACK privilege): {e}"
                    );
                    return;
                }
            };
            assert_eq!(response.row_count, 1, "AS OF SCN read returns the dual row");
            assert_eq!(
                response.rows[0]["C"],
                serde_json::json!("1"),
                "count(*) FROM dual AS OF the current SCN is 1"
            );

            // The window was torn down: a NORMAL read afterwards succeeds and sees
            // live data (the session was NOT stranded in Flashback mode).
            let after = conn
                .query_rows(&cx, "SELECT 42 AS n FROM dual", &[])
                .await
                .expect("a normal read after a flashback read (session left clean)");
            assert_eq!(after[0].text("N"), Some("42"));
        });
    }

    #[test]
    fn live_flashback_old_timestamp_returns_typed_retention_refusal() {
        use oraclemcp_db::{AsOf, FlashbackRefusalKind, QueryCaps, read_query_as_of};
        run_with_cx(|cx| async move {
            let Some(conn) = connect_or_skip(
                &cx,
                "live_flashback_old_timestamp_returns_typed_retention_refusal",
            )
            .await
            else {
                return;
            };

            let error = match read_query_as_of(
                &cx,
                &conn,
                "SELECT count(*) AS c FROM dual",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Timestamp("1900-01-01 00:00:00".to_owned()),
            )
            .await
            {
                Ok(resp) => {
                    panic!("1900 flashback timestamp unexpectedly succeeded: {resp:?}");
                }
                Err(e) if e.to_string().contains("ORA-01031") => {
                    eprintln!(
                        "[live-xe] SKIP flashback retention refusal: missing FLASHBACK privilege ({e})"
                    );
                    return;
                }
                Err(e) => e,
            };

            match error {
                DbError::FlashbackRefusal {
                    kind,
                    ora_code,
                    message,
                } => {
                    assert_eq!(kind, FlashbackRefusalKind::RetentionExceeded);
                    assert!(
                        matches!(ora_code, Some(8180 | 1555)),
                        "unexpected retention ORA code: {ora_code:?}"
                    );
                    assert!(
                        message.contains("ORA-08180") || message.contains("ORA-01555"),
                        "{message}"
                    );
                    let env = DbError::FlashbackRefusal {
                        kind,
                        message,
                        ora_code,
                    }
                    .into_envelope();
                    assert_eq!(
                        env.error_class,
                        oraclemcp_error::ErrorClass::FlashbackRetentionExceeded
                    );
                    assert!(
                        env.next_steps.iter().any(|step| step.contains("newer SCN")),
                        "{:?}",
                        env.next_steps
                    );
                }
                other => panic!("expected typed flashback retention refusal, got {other:?}"),
            }
        });
    }

    #[test]
    fn live_flashback_post_ddl_scn_returns_typed_definition_refusal() {
        use oraclemcp_db::{AsOf, FlashbackRefusalKind, QueryCaps, read_query_as_of};
        run_with_cx(|cx| async move {
            let Some(conn) = connect_or_skip(
                &cx,
                "live_flashback_post_ddl_scn_returns_typed_definition_refusal",
            )
            .await
            else {
                return;
            };
            let table = format!("ORAMCP_DDL_{}", std::process::id());
            let cleanup_sql = format!("DROP TABLE {table} PURGE");

            if let Err(e) = conn
                .execute(
                    &cx,
                    &format!("CREATE TABLE {table} (id NUMBER PRIMARY KEY)"),
                    &[],
                )
                .await
            {
                eprintln!("[live-xe] SKIP flashback DDL refusal setup: cannot create table ({e})");
                return;
            }

            let test_result: Result<(), DbError> = async {
                conn.execute(
                    &cx,
                    &format!("INSERT INTO {table} (id) VALUES (:1)"),
                    &[OracleBind::I64(1)],
                )
                .await?;
                conn.commit(&cx).await?;

                let scn_before_ddl = conn
                    .query_rows(
                        &cx,
                        "SELECT dbms_flashback.get_system_change_number AS scn FROM dual",
                        &[],
                    )
                    .await?
                    .first()
                    .and_then(|row| row.text("SCN"))
                    .and_then(|scn| scn.parse::<u64>().ok())
                    .expect("numeric pre-DDL SCN");

                conn.execute(&cx, &format!("ALTER TABLE {table} ADD (extra NUMBER)"), &[])
                    .await?;

                let sql = format!("SELECT id FROM {table}");
                match read_query_as_of(
                    &cx,
                    &conn,
                    &sql,
                    &[],
                    QueryCaps::default(),
                    0,
                    &SerializeOptions::default(),
                    &AsOf::Scn(scn_before_ddl),
                )
                .await
                {
                    Err(DbError::FlashbackRefusal {
                        kind,
                        ora_code,
                        message,
                    }) => {
                        assert_eq!(kind, FlashbackRefusalKind::DefinitionChanged);
                        assert_eq!(ora_code, Some(1466));
                        assert!(message.contains("ORA-01466"), "{message}");
                        let env = DbError::FlashbackRefusal {
                            kind,
                            message,
                            ora_code,
                        }
                        .into_envelope();
                        assert_eq!(
                            env.error_class,
                            oraclemcp_error::ErrorClass::FlashbackDefinitionChanged
                        );
                        assert!(
                            env.next_steps
                                .iter()
                                .any(|step| step.contains("DDL boundary")),
                            "{:?}",
                            env.next_steps
                        );
                        Ok(())
                    }
                    Err(error) => Err(error),
                    Ok(response) => Err(DbError::Query(format!(
                        "expected ORA-01466 definition-change refusal, got {} rows",
                        response.row_count
                    ))),
                }
            }
            .await;

            let _ = conn.execute(&cx, &cleanup_sql, &[]).await;
            match test_result {
                Ok(()) => {}
                Err(e) => {
                    let message = e.to_string();
                    if message.contains("ORA-01031")
                        || message.contains("ORA-08180")
                        || message.contains("FLASHBACK")
                    {
                        eprintln!(
                            "[live-xe] SKIP flashback DDL refusal (privilege/retention): {e}"
                        );
                        return;
                    }
                    panic!("flashback DDL refusal live check failed: {e}");
                }
            }
        });
    }

    #[test]
    fn live_flashback_diff_synthetic_table_across_scns() {
        use oraclemcp_db::{
            AsOf, QueryCaps, diff_query_responses, primary_key_columns, read_query_as_of,
        };
        run_with_cx(|cx| async move {
            let Some(conn) =
                connect_or_skip(&cx, "live_flashback_diff_synthetic_table_across_scns").await
            else {
                return;
            };
            let table = format!("ORAMCP_DF_{}", std::process::id());
            let cleanup_sql = format!("DROP TABLE {table} PURGE");
            let owner = conn
                .describe(&cx)
                .await
                .ok()
                .and_then(|info| info.current_schema)
                .unwrap_or_else(|| {
                    std::env::var("ORACLEMCP_TEST_USER")
                        .unwrap_or_else(|_| "system".to_owned())
                        .to_ascii_uppercase()
                });

            if let Err(e) = conn
                .execute(
                    &cx,
                    &format!("CREATE TABLE {table} (id NUMBER PRIMARY KEY, val VARCHAR2(30))"),
                    &[],
                )
                .await
            {
                eprintln!("[live-xe] SKIP oracle_diff live setup: cannot create table ({e})");
                return;
            }

            let test_result: Result<(), DbError> = async {
                conn.execute(
                    &cx,
                    &format!("INSERT INTO {table} (id, val) VALUES (:1, :2)"),
                    &[OracleBind::I64(1), OracleBind::from("old")],
                )
                .await?;
                conn.execute(
                    &cx,
                    &format!("INSERT INTO {table} (id, val) VALUES (:1, :2)"),
                    &[OracleBind::I64(2), OracleBind::from("gone")],
                )
                .await?;
                conn.commit(&cx).await?;

                let scn_a = conn
                    .query_rows(
                        &cx,
                        "SELECT dbms_flashback.get_system_change_number AS scn FROM dual",
                        &[],
                    )
                    .await?
                    .first()
                    .and_then(|row| row.text("SCN"))
                    .and_then(|scn| scn.parse::<u64>().ok())
                    .expect("numeric scn_a");

                conn.execute(
                    &cx,
                    &format!("UPDATE {table} SET val = :1 WHERE id = :2"),
                    &[OracleBind::from("new"), OracleBind::I64(1)],
                )
                .await?;
                conn.execute(
                    &cx,
                    &format!("DELETE FROM {table} WHERE id = :1"),
                    &[OracleBind::I64(2)],
                )
                .await?;
                conn.execute(
                    &cx,
                    &format!("INSERT INTO {table} (id, val) VALUES (:1, :2)"),
                    &[OracleBind::I64(3), OracleBind::from("added")],
                )
                .await?;
                conn.commit(&cx).await?;

                let scn_b = conn
                    .query_rows(
                        &cx,
                        "SELECT dbms_flashback.get_system_change_number AS scn FROM dual",
                        &[],
                    )
                    .await?
                    .first()
                    .and_then(|row| row.text("SCN"))
                    .and_then(|scn| scn.parse::<u64>().ok())
                    .expect("numeric scn_b");

                let key = primary_key_columns(&cx, &conn, &owner, &table).await?;
                assert_eq!(key, vec!["ID".to_owned()]);

                let sql = format!("SELECT id, val FROM {table} ORDER BY id");
                let before = read_query_as_of(
                    &cx,
                    &conn,
                    &sql,
                    &[],
                    QueryCaps::default(),
                    0,
                    &SerializeOptions::default(),
                    &AsOf::Scn(scn_a),
                )
                .await?;
                let after = read_query_as_of(
                    &cx,
                    &conn,
                    &sql,
                    &[],
                    QueryCaps::default(),
                    0,
                    &SerializeOptions::default(),
                    &AsOf::Scn(scn_b),
                )
                .await?;
                let diff = diff_query_responses(&before, &after, &key)
                    .map_err(|e| DbError::Query(e.to_string()))?;

                assert!(diff.keyed);
                assert_eq!(diff.changed.len(), 1);
                assert_eq!(diff.changed[0].key, json!({ "ID": "1" }));
                assert_eq!(diff.removed, vec![json!({ "ID": "2", "VAL": "gone" })]);
                assert_eq!(diff.added, vec![json!({ "ID": "3", "VAL": "added" })]);
                Ok(())
            }
            .await;

            let _ = conn.execute(&cx, &cleanup_sql, &[]).await;
            match test_result {
                Ok(()) => {}
                Err(e) => {
                    let message = e.to_string();
                    if message.contains("ORA-01031")
                        || message.contains("ORA-08180")
                        || message.contains("FLASHBACK")
                    {
                        eprintln!(
                            "[live-xe] SKIP oracle_diff flashback live check (privilege/retention): {e}"
                        );
                        return;
                    }
                    panic!("oracle_diff live check failed: {e}");
                }
            }
        });
    }
}
