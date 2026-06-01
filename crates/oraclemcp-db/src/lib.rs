#![forbid(unsafe_code)]

//! Oracle connectivity for the `oraclemcp` server (plan §4.3, §5.1, §5.2; bead
//! P0-3).
//!
//! Layers:
//! - [`OracleConnection`] — the backend-independent sync connection trait, with
//!   the `oracle`-crate-backed [`RustOracleConnection`].
//! - [`OraclePool`] — an `r2d2` pool behind a `tokio::task::spawn_blocking`
//!   boundary so DB I/O never blocks the async executor and an
//!   `oracle::Connection` is never held across an `.await` (`oracle-driver`).
//! - [`detect_instant_client`] — the offline-safe Instant Client posture probe
//!   for `doctor`.
//!
//! The session-lease primitive (P0-4) and the deterministic NUMBER→string /
//! ISO-8601 / NLS serializer (P0-5) build on these.

mod connection;
mod doctor;
mod error;
mod lease;
mod query;
mod serialize;
mod types;

#[cfg(feature = "oracle-driver")]
mod pool;

pub use connection::{OracleConnection, RustOracleConnection};
pub use doctor::{InstantClientPosture, detect_instant_client, oracle_driver_compiled};
pub use error::DbError;
pub use lease::{LeaseId, LeaseInfo, LeaseManager, require_lease_id};
pub use query::{QueryCaps, QueryResponse, cursor_to_offset, paginated_sql, read_query};
pub use serialize::{
    SerializeOptions, TypeRepr, base64_encode, canonical_nls_statements, canonicalize_datetime,
    classify_type, serialize_cell, serialize_row,
};
pub use types::{
    OracleBackend, OracleBind, OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleRow,
};

#[cfg(feature = "oracle-driver")]
pub use pool::{OracleConnectionManager, OraclePool, PoolSettings};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error_envelope;
