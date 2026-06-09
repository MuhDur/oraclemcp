#![forbid(unsafe_code)]
// ErrorEnvelope-returning fns (the ToolDispatch contract) trip result_large_err;
// boxing every cold error path adds noise for no benefit — oraclemcp-core does
// the same. See oraclemcp-core/src/lib.rs.
#![allow(clippy::result_large_err)]

//! `oraclemcp` — the engine-free Oracle Database MCP server binary (Phase-E
//! E-2b).
//!
//! A thin consumer of `oraclemcp-core` (the rmcp [`OracleMcpServer`] +
//! `oracle_capabilities`) and `oraclemcp-db` (the read-only dictionary ops). It
//! advertises read-only live-DB/config-inspection tools ([`registry`]) and
//! dispatches them through [`dispatch::OracleDispatcher`]. There is NO engine,
//! NO `plsql-*` dependency, and NO write/DDL surface — reads only, gated by the
//! live-DB build feature.
//!
//! CLI shape (mirrors `plsql-mcp`): a top-level `--robot-json` flag plus
//! `serve` (stdio default, `--listen <ADDR>` for Streamable HTTP), `info`,
//! `doctor`, and `capabilities`.

use std::process::ExitCode;
use std::sync::Arc;

use clap::{CommandFactory, Parser, Subcommand};
use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp::registry;
use oraclemcp_auth::resolve_secret;
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::{
    DoctorContext, HttpTransportConfig, OracleMcpServer, StdioAuthPolicy, run_doctor, serve_http,
};
use oraclemcp_db::{DbError, OracleConnectOptions, OracleConnection, RustOracleConnection};

/// Whether this build compiled in the Oracle driver (the `live-db` feature).
const LIVE_DB: bool = cfg!(feature = "live-db");

#[derive(Parser, Debug)]
#[command(
    name = "oraclemcp",
    version,
    about = "Engine-free, read-only-by-default Oracle Database MCP server",
    long_about = "Speaks the Model Context Protocol over stdio (default) or \
                  Streamable HTTP (--listen). Exposes read-only Oracle tools \
                  (profile discovery, connection info, query, schema_inspect, \
                  describe, get_ddl, get_source, compile_errors, search_source, \
                  explain_plan) plus the zero-arg oracle_capabilities discovery tool. No \
                  PL/SQL engine, no write/DDL surface."
)]
struct Cli {
    /// Emit a single JSON object on stdout instead of human text.
    #[arg(long, global = true)]
    robot_json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the MCP server (stdio by default; --listen <ADDR> for HTTP).
    Serve {
        /// Bind a Streamable HTTP listener at <ADDR> (e.g. 127.0.0.1:7070)
        /// instead of stdio. The HTTP transport is unauthenticated at this
        /// layer; bind loopback only.
        #[arg(long)]
        listen: Option<String>,
        /// Run stdio without an init token (development only). Without this and
        /// without $ORACLEMCP_STDIO_TOKEN, stdio serve refuses to start.
        #[arg(long)]
        allow_no_auth: bool,
        /// The expected stdio init token (overrides $ORACLEMCP_STDIO_TOKEN).
        #[arg(long)]
        stdio_token: Option<String>,
        /// Connect using this named profile from the loaded config.
        #[arg(long)]
        profile: Option<String>,
    },
    /// Print build information (version, enabled features) and exit.
    Info,
    /// Run offline diagnostics; exit 2 on a blocker.
    Doctor,
    /// Print the capabilities report (tools, level, feature tiers) as JSON.
    Capabilities,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let robot_json = cli.robot_json;

    let Some(command) = cli.command else {
        // Bare invocation: help to stderr, exit 2. stdout stays empty so a
        // launcher piping JSON-RPC never mistakes the hint for data.
        let mut cmd = Cli::command();
        let _ = cmd.write_long_help(&mut std::io::stderr());
        eprintln!(
            "\nno subcommand given — try `oraclemcp serve`, `oraclemcp doctor`, or `oraclemcp capabilities`."
        );
        return ExitCode::from(2);
    };

    match command {
        Command::Serve {
            listen,
            allow_no_auth,
            stdio_token,
            profile,
        } => run_serve(listen, allow_no_auth, stdio_token, profile, robot_json),
        Command::Info => run_info(robot_json),
        Command::Doctor => run_doctor_cmd(robot_json),
        Command::Capabilities => run_capabilities(robot_json),
    }
}

/// Initialize tracing once for the serve loop. Logs go to stderr so stdout
/// stays pure JSON-RPC over the stdio transport.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_env("ORACLEMCP_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
}

/// Resolve the connection options from config + an optional profile name.
/// Falls back to an empty (unconnectable) option set when no implicit profile
/// resolves. Explicit profile/config/secret failures are returned so `serve`
/// can expose them through the same structured-error stub path as live connect
/// failures.
fn resolve_connect_options(profile: Option<&str>) -> Result<OracleConnectOptions, DbError> {
    let cfg = OracleMcpConfig::load(None)
        .map_err(|e| DbError::UnsupportedAuth(format!("config load failed: {e}")))?;

    let Some(chosen) = (match profile {
        Some(name) => Some(cfg.profile(name).ok_or_else(|| {
            DbError::UnsupportedAuth(format!("connection profile `{name}` not found"))
        })?),
        // No explicit profile: use the sole profile if there is exactly
        // one, else none (the agent can still drive capabilities/doctor).
        None if cfg.profiles.len() == 1 => cfg.profiles.first(),
        None => None,
    }) else {
        return Ok(OracleConnectOptions::default());
    };

    let password = match chosen.credential_ref.as_deref() {
        Some(reference) => {
            let secret = resolve_secret(reference, chosen.protected(), |name| {
                std::env::var(name).ok()
            })
            .map_err(|e| {
                DbError::UnsupportedAuth(format!(
                    "failed to resolve credential_ref for profile `{}`: {e}",
                    chosen.name
                ))
            })?;
            Some(secret.expose().to_owned())
        }
        None => None,
    };

    Ok(oraclemcp_core::profile_to_options(chosen, password))
}

/// Open the live connection, or — when the driver is absent / the connect fails
/// — a stub connection that returns the same `DbError` on every call. Either
/// way `serve` starts: capabilities/doctor work offline, and live tool calls
/// return a structured envelope instead of crashing the process.
fn open_connection(opts: OracleConnectOptions) -> Box<dyn OracleConnection> {
    // `RustOracleConnection` only implements `OracleConnection` when the
    // `oracle-driver` feature (pulled by `live-db`) is on. Without it, connect
    // always fails (`BackendNotCompiled`), so we go straight to the stub and
    // never need the (unimplemented) trait bound on the real type.
    #[cfg(feature = "live-db")]
    {
        match RustOracleConnection::connect(opts) {
            Ok(conn) => Box::new(conn),
            Err(e) => {
                tracing::warn!(error = %e, "no live connection; live tools will return a structured error envelope");
                Box::new(stub::StubConnection::new(e))
            }
        }
    }
    #[cfg(not(feature = "live-db"))]
    {
        // Drive `connect` for its error (BackendNotCompiled) so the stub carries
        // an accurate message; the `Ok` arm is unreachable in this build.
        let e = match RustOracleConnection::connect(opts) {
            Ok(_) => unreachable!("offline build cannot open a live connection"),
            Err(e) => e,
        };
        tracing::warn!(error = %e, "no live connection (driver not compiled); live tools will return a structured error envelope");
        Box::new(stub::StubConnection::new(e))
    }
}

/// Build the server from the registry + capabilities + dispatcher over `conn`.
fn build_server(conn: Box<dyn OracleConnection>, http: bool) -> OracleMcpServer {
    let version = env!("CARGO_PKG_VERSION");
    let registry = registry::tool_registry();
    let caps = registry::capabilities(version, LIVE_DB, http);
    let dispatcher = OracleDispatcher::new(conn);
    OracleMcpServer::new(version, registry, caps, Arc::new(dispatcher))
}

fn run_serve(
    listen: Option<String>,
    allow_no_auth: bool,
    stdio_token: Option<String>,
    profile: Option<String>,
    robot_json: bool,
) -> ExitCode {
    init_tracing();
    let conn = match resolve_connect_options(profile.as_deref()) {
        Ok(opts) => open_connection(opts),
        Err(e) => {
            tracing::warn!(error = %e, "no live connection; live tools will return a structured error envelope");
            Box::new(stub::StubConnection::new(e))
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("oraclemcp serve: failed to start tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };

    match listen {
        // ── stdio transport (default) ──────────────────────────────────────
        None => {
            // Resolve the init-token policy fail-closed (mirrors the §7.1 gate).
            let env_token = stdio_token
                .or_else(|| std::env::var(oraclemcp_core::init_token::STDIO_TOKEN_ENV).ok());
            let auth = match StdioAuthPolicy::resolve(env_token, allow_no_auth) {
                Ok(a) => a,
                Err(e) => {
                    emit_status_error(robot_json, "ORACLEMCP_AUTH_REQUIRED", &e.to_string());
                    return ExitCode::from(2);
                }
            };
            let server = build_server(conn, false);
            emit_serve_status(robot_json, "stdio", None);
            match runtime.block_on(server.serve_stdio(&auth)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("oraclemcp serve: stdio transport error: {e}");
                    ExitCode::from(1)
                }
            }
        }
        // ── Streamable HTTP transport (--listen) ───────────────────────────
        Some(addr) => {
            let server = build_server(conn, true);
            let cfg = HttpTransportConfig::default();
            emit_serve_status(robot_json, "http", Some(&addr));
            let bind_addr = addr.clone();
            let result = runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
                // Graceful shutdown on Ctrl-C; ignore the join error.
                let shutdown = async {
                    let _ = tokio::signal::ctrl_c().await;
                };
                serve_http(listener, server, &cfg, shutdown).await
            });
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("oraclemcp serve: http transport error on {addr}: {e}");
                    ExitCode::from(1)
                }
            }
        }
    }
}

/// Emit a serve startup status line on stderr (stdout stays JSON-RPC data).
fn emit_serve_status(robot_json: bool, transport: &str, addr: Option<&str>) {
    if robot_json {
        eprintln!(
            "{}",
            serde_json::json!({
                "kind": "status",
                "transport": transport,
                "listen": addr,
                "live_db": LIVE_DB,
                "tools": registry::TOOL_NAMES,
            })
        );
    } else {
        match addr {
            Some(a) => eprintln!(
                "oraclemcp serve: http transport listening on {a} ({} tools, live-db: {LIVE_DB})",
                registry::TOOL_NAMES.len()
            ),
            None => eprintln!(
                "oraclemcp serve: stdio transport ready ({} tools, live-db: {LIVE_DB})",
                registry::TOOL_NAMES.len()
            ),
        }
    }
}

/// Emit a structured error on stderr (used before the serve loop starts).
fn emit_status_error(robot_json: bool, code: &str, message: &str) {
    if robot_json {
        eprintln!(
            "{}",
            serde_json::json!({ "kind": "error", "code": code, "message": message })
        );
    } else {
        eprintln!("oraclemcp serve: {message}");
    }
}

fn run_info(robot_json: bool) -> ExitCode {
    let info = serde_json::json!({
        "binary": "oraclemcp",
        "version": env!("CARGO_PKG_VERSION"),
        "engine": false,
        "live_db": LIVE_DB,
        "transports": ["stdio", "http"],
        "tools": registry::TOOL_NAMES,
        "mcp_protocol_version": oraclemcp_core::PROTOCOL_VERSION,
    });
    if robot_json {
        println!("{}", serde_json::to_string(&info).unwrap());
    } else {
        println!("{}", serde_json::to_string_pretty(&info).unwrap());
    }
    ExitCode::SUCCESS
}

fn run_capabilities(robot_json: bool) -> ExitCode {
    // HTTP is advertised as available (the binary can serve it); live_db tracks
    // the compiled driver feature.
    let caps = registry::capabilities(env!("CARGO_PKG_VERSION"), LIVE_DB, true);
    let value = serde_json::to_value(&caps).unwrap_or(serde_json::Value::Null);
    if robot_json {
        println!("{}", serde_json::to_string(&value).unwrap());
    } else {
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
    }
    ExitCode::SUCCESS
}

fn run_doctor_cmd(robot_json: bool) -> ExitCode {
    // Offline doctor context: no live connection (the live subset reports Skip
    // with a reason). TNS_ADMIN is surfaced if set so its directory check runs.
    let ctx = DoctorContext {
        conn: None,
        tns_admin: std::env::var("TNS_ADMIN").ok(),
        wallet_location: None,
        protected_profile_writable: false,
    };
    let report = run_doctor(&ctx);
    if robot_json {
        println!("{}", report.to_json());
    } else {
        // The human report is the data here; print it on stdout.
        print!("{}", report.to_text());
    }
    // Mirror plsql-mcp: a blocker (any failed check) exits 2.
    if report.any_failed() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// A no-driver / failed-connect stub connection: every operation returns the
/// recorded connect error, so serve can start and live tool calls degrade to a
/// structured envelope instead of a panic.
mod stub {
    use oraclemcp_db::{
        DbError, OracleBackend, OracleBind, OracleConnection, OracleConnectionInfo, OracleRow,
    };

    pub(super) struct StubConnection {
        error: DbError,
    }

    impl StubConnection {
        pub(super) fn new(error: DbError) -> Self {
            StubConnection { error }
        }
        fn err(&self) -> DbError {
            self.error.clone()
        }
    }

    impl OracleConnection for StubConnection {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        fn ping(&self) -> Result<(), DbError> {
            Err(self.err())
        }
        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Err(self.err())
        }
        fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            Err(self.err())
        }
        fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Err(self.err())
        }
        fn commit(&self) -> Result<(), DbError> {
            Err(self.err())
        }
        fn rollback(&self) -> Result<(), DbError> {
            Err(self.err())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_connection_returns_an_envelopable_error() {
        let stub = stub::StubConnection::new(oraclemcp_db::DbError::BackendNotCompiled {
            backend: oraclemcp_db::OracleBackend::RustOracle,
        });
        let err = stub.ping().expect_err("stub always errors");
        // It maps to a structured envelope (no panic).
        let _ = err.into_envelope();
    }

    #[test]
    fn build_server_advertises_the_registered_tools_plus_capabilities() {
        let conn = open_connection(OracleConnectOptions::default());
        let server = build_server(conn, false);
        // The capabilities report carries the registry's tools.
        let caps = registry::capabilities(env!("CARGO_PKG_VERSION"), LIVE_DB, false);
        assert_eq!(caps.tools.len(), registry::TOOL_NAMES.len());
        // Smoke: the server clones (it is Clone) — proves it is fully built.
        let _ = server.clone();
    }
}
