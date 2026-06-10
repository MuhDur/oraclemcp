#![forbid(unsafe_code)]
// ErrorEnvelope-returning fns (the ToolDispatch contract) trip result_large_err;
// boxing every cold error path adds noise for no benefit — oraclemcp-core does
// the same. See oraclemcp-core/src/lib.rs.
#![allow(clippy::result_large_err)]

//! `oraclemcp` — the engine-free Oracle Database MCP server binary (Phase-E
//! E-2b).
//!
//! A thin consumer of `oraclemcp-core` (the rmcp [`OracleMcpServer`] +
//! `oracle_capabilities`) and `oraclemcp-db` (the read-only dictionary ops plus
//! one guarded execute primitive). It advertises safe-by-default
//! live-DB/config-inspection tools ([`registry`]) and dispatches them through
//! [`dispatch::OracleDispatcher`]. There is NO engine and NO `plsql-*`
//! dependency; non-read execution is isolated behind the classifier,
//! profile/session operating level, rollback default, and commit confirmation.
//!
//! CLI shape (mirrors `plsql-mcp`): a top-level `--robot-json` flag plus
//! `serve` (stdio default, `--listen <ADDR>` for Streamable HTTP), `info`,
//! `doctor`, `capabilities`, and `robot-docs guide`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{CommandFactory, Parser, Subcommand};
use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp::registry;
use oraclemcp_auth::resolve_secret;
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::{
    CapabilitiesReport, CustomToolCatalog, CustomToolDef, DoctorContext, FeatureTiers,
    HttpTransportConfig, OracleMcpServer, StdioAuthPolicy, load_tools, load_tools_for_profile,
    parse_tools_file, run_doctor, serve_http,
};
use oraclemcp_db::{DbError, OracleConnectOptions, OracleConnection, RustOracleConnection};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{Classifier, ClassifierConfig, OperatingLevel, SessionLevelState};

/// Whether this build compiled in the Oracle driver (the `live-db` feature).
const LIVE_DB: bool = cfg!(feature = "live-db");
const CUSTOM_TOOLS_DIR_ENV: &str = "ORACLEMCP_TOOLS_DIR";
const CUSTOM_TOOLS_HMAC_KEY_ENV: &str = "ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY";

#[derive(Parser, Debug)]
#[command(
    name = "oraclemcp",
    version,
    about = "Engine-free, safe-by-default Oracle Database MCP server",
    long_about = "Speaks the Model Context Protocol over stdio (default) or \
                  Streamable HTTP (--listen). Exposes safe-by-default Oracle tools \
                  (profile discovery, connection info, query, schema_inspect, \
                  list_schemas, switch_profile, set_session_level, preview_sql, describe, get_ddl, \
                  get_source, compile_errors, search_source, plscope_inspect, \
                  sample_rows, read_clob, explain_plan, compile_object, compile_with_warnings, \
                  create_or_replace, patch_source, guarded execute) plus the \
                  zero-arg oracle_capabilities discovery tool. No PL/SQL engine, \
                  no environment-specific workflow engine."
)]
struct Cli {
    /// Emit a single JSON object on stdout instead of human text.
    #[arg(long, visible_alias = "json", global = true)]
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
    /// Run diagnostics; exit 2 on a blocker.
    Doctor {
        /// Connect using this named profile and include live connectivity checks.
        /// Omit for offline diagnostics only.
        #[arg(long)]
        profile: Option<String>,
    },
    /// List configured connection profiles without opening a database connection.
    #[command(alias = "list-profiles")]
    Profiles,
    /// Print the capabilities report (tools, level, feature tiers) as JSON.
    Capabilities,
    /// Print an agent-oriented usage guide from the binary itself.
    #[command(name = "robot-docs", alias = "robot_docs")]
    RobotDocs {
        #[command(subcommand)]
        command: Option<RobotDocsCommand>,
    },
}

#[derive(Subcommand, Debug)]
enum RobotDocsCommand {
    /// Print the compact agent guide.
    Guide,
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
        Command::Doctor { profile } => run_doctor_cmd(robot_json, profile),
        Command::Profiles => run_profiles(robot_json),
        Command::Capabilities => run_capabilities(robot_json),
        Command::RobotDocs { command } => match command {
            None | Some(RobotDocsCommand::Guide) => run_robot_docs_guide(robot_json),
        },
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

/// Resolve the selected profile name and connection options from config + an
/// optional profile name. When no explicit/default/sole profile resolves, the
/// result is `None` so `serve` can still start for capabilities/doctor.
fn default_read_only_level() -> SessionLevelState {
    SessionLevelState::new(OperatingLevel::ReadOnly, false)
}

fn resolve_profile_options(
    profile: Option<&str>,
) -> Result<Option<(String, OracleConnectOptions, SessionLevelState)>, DbError> {
    let cfg = OracleMcpConfig::load(None)
        .map_err(|e| DbError::UnsupportedAuth(format!("config load failed: {e}")))?;

    let Some(chosen) = (match profile {
        Some(name) => Some(cfg.profile(name).ok_or_else(|| {
            DbError::UnsupportedAuth(format!("connection profile `{name}` not found"))
        })?),
        None if cfg.default_profile.is_some() => {
            let name = cfg.default_profile.as_deref().expect("checked is_some");
            Some(cfg.profile(name).ok_or_else(|| {
                DbError::UnsupportedAuth(format!("default_profile `{name}` not found"))
            })?)
        }
        // No explicit/default profile: use the sole profile if there is exactly
        // one, else none (the agent can still drive capabilities/doctor).
        None if cfg.profiles.len() == 1 => cfg.profiles.first(),
        None => None,
    }) else {
        return Ok(None);
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

    let ctx = oraclemcp_core::build_session_context(chosen, password, false)?;
    Ok(Some((chosen.name.clone(), ctx.options, ctx.level_state)))
}

fn connect_profile(profile: &str) -> Result<Box<dyn OracleConnection>, DbError> {
    let Some((_, opts, _level)) = resolve_profile_options(Some(profile))? else {
        return Err(DbError::UnsupportedAuth(format!(
            "connection profile `{profile}` not found"
        )));
    };
    try_open_connection(opts)
}

fn try_open_connection(opts: OracleConnectOptions) -> Result<Box<dyn OracleConnection>, DbError> {
    #[cfg(feature = "live-db")]
    {
        RustOracleConnection::connect(opts).map(|conn| Box::new(conn) as Box<dyn OracleConnection>)
    }
    #[cfg(not(feature = "live-db"))]
    {
        match RustOracleConnection::connect(opts) {
            Ok(_) => unreachable!("offline build cannot open a live connection"),
            Err(e) => Err(e),
        }
    }
}

/// Open the live connection, or — when the driver is absent / the connect fails
/// — a stub connection that returns the same `DbError` on every call. Either
/// way `serve` starts: capabilities/doctor work offline, and live tool calls
/// return a structured envelope instead of crashing the process.
fn open_connection(opts: OracleConnectOptions) -> Box<dyn OracleConnection> {
    match try_open_connection(opts) {
        Ok(conn) => conn,
        Err(e) => {
            tracing::warn!(error = %e, "no live connection; live tools will return a structured error envelope");
            Box::new(stub::StubConnection::new(e))
        }
    }
}

fn custom_tools_dir() -> Option<PathBuf> {
    std::env::var_os(CUSTOM_TOOLS_DIR_ENV)
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".config/oraclemcp/tools.d"))
        })
}

fn custom_tool_error(message: impl Into<String>) -> ErrorEnvelope {
    ErrorEnvelope::new(ErrorClass::InvalidArguments, message)
}

fn read_custom_tool_defs(dir: &Path) -> Result<Vec<CustomToolDef>, ErrorEnvelope> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    if !dir.is_dir() {
        return Err(custom_tool_error(format!(
            "{} must point to a directory of .toml tool definitions",
            CUSTOM_TOOLS_DIR_ENV
        )));
    }

    let mut paths = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| custom_tool_error(format!("failed to read custom tools dir: {e}")))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| custom_tool_error(format!("failed to read tools.d entry: {e}")))?;
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "toml") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut defs = Vec::new();
    for path in paths {
        let src = std::fs::read_to_string(&path).map_err(|e| {
            custom_tool_error(format!(
                "failed to read custom tool file {}: {e}",
                path.display()
            ))
        })?;
        let mut file_defs = parse_tools_file(&src).map_err(|e| {
            custom_tool_error(format!(
                "failed to parse custom tool file {}: {e}",
                path.display()
            ))
        })?;
        defs.append(&mut file_defs);
    }
    Ok(defs)
}

fn validate_custom_tool_names(defs: &[CustomToolDef]) -> Result<(), ErrorEnvelope> {
    let reserved_names: HashSet<String> = registry::tool_registry()
        .tools
        .into_iter()
        .map(|tool| tool.name)
        .chain(std::iter::once(
            oraclemcp_core::CAPABILITIES_TOOL.to_owned(),
        ))
        .collect();
    let mut seen = HashSet::new();
    for def in defs {
        if !seen.insert(def.name.as_str()) {
            return Err(custom_tool_error(format!(
                "duplicate custom tool name `{}`",
                def.name
            )));
        }
        if reserved_names.contains(&def.name) {
            return Err(custom_tool_error(format!(
                "custom tool name `{}` collides with a built-in tool or alias",
                def.name
            )));
        }
    }
    Ok(())
}

fn load_custom_catalog_for_level(
    level: &SessionLevelState,
) -> Result<CustomToolCatalog, ErrorEnvelope> {
    let Some(dir) = custom_tools_dir() else {
        return Ok(CustomToolCatalog::default());
    };
    let defs = read_custom_tool_defs(&dir)?;
    if defs.is_empty() {
        return Ok(CustomToolCatalog::default());
    }
    validate_custom_tool_names(&defs)?;

    let classifier = Classifier::new(ClassifierConfig::new());
    let key = std::env::var(CUSTOM_TOOLS_HMAC_KEY_ENV).ok();
    let signed_defs_present = defs.iter().any(|def| def.signature.is_some());
    let loaded = if level.is_protected() {
        let key = key.ok_or_else(|| {
            custom_tool_error(format!(
                "{CUSTOM_TOOLS_HMAC_KEY_ENV} is required when loading custom tools for a protected profile"
            ))
        })?;
        load_tools_for_profile(
            &defs,
            &classifier,
            OperatingLevel::ReadOnly,
            key.as_bytes(),
            true,
        )
    } else if let Some(key) = key {
        load_tools_for_profile(
            &defs,
            &classifier,
            OperatingLevel::ReadOnly,
            key.as_bytes(),
            false,
        )
    } else if signed_defs_present {
        return Err(custom_tool_error(format!(
            "custom tool signatures are present but {CUSTOM_TOOLS_HMAC_KEY_ENV} is not set"
        )));
    } else {
        load_tools(&defs, &classifier, OperatingLevel::ReadOnly)
    }
    .map_err(|e| custom_tool_error(format!("failed to load custom tools: {e}")))?;

    Ok(CustomToolCatalog::new(loaded))
}

/// Build the server from the registry + capabilities + dispatcher over `conn`.
fn build_server(
    conn: Box<dyn OracleConnection>,
    active_profile: Option<String>,
    level: SessionLevelState,
    http: bool,
    custom_catalog: CustomToolCatalog,
) -> OracleMcpServer {
    let version = env!("CARGO_PKG_VERSION");
    let mut registry = registry::tool_registry();
    custom_catalog.register_first_class(&mut registry);
    let caps = CapabilitiesReport::new(
        version,
        registry.tools.clone(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: LIVE_DB,
            engine: false,
            http_transport: http,
        },
    );
    let dispatcher = OracleDispatcher::new_switchable_with_custom_tools(
        conn,
        active_profile,
        level,
        Arc::new(connect_profile),
        custom_catalog,
        Some(Arc::new(load_custom_catalog_for_level)),
    );
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
    let (conn, active_profile, level) = match resolve_profile_options(profile.as_deref()) {
        Ok(Some((profile_name, opts, level))) => (open_connection(opts), Some(profile_name), level),
        Ok(None) => (
            open_connection(OracleConnectOptions::default()),
            None,
            default_read_only_level(),
        ),
        Err(e) if profile.is_some() => {
            emit_status_error(
                robot_json,
                "ORACLEMCP_CONFIG_INVALID",
                &format!("failed to resolve connection profile: {e}"),
            );
            return ExitCode::from(2);
        }
        Err(e) => {
            tracing::warn!(error = %e, "no live connection; live tools will return a structured error envelope");
            (
                Box::new(stub::StubConnection::new(e)) as Box<dyn OracleConnection>,
                None,
                default_read_only_level(),
            )
        }
    };

    let custom_catalog = match load_custom_catalog_for_level(&level) {
        Ok(catalog) => catalog,
        Err(e) => {
            emit_status_error(robot_json, "ORACLEMCP_CUSTOM_TOOLS_INVALID", &e.message);
            return ExitCode::from(2);
        }
    };
    let mut advertised_registry = registry::tool_registry();
    custom_catalog.register_first_class(&mut advertised_registry);
    let advertised_tools: Vec<String> = advertised_registry
        .tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect();

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
            let server = build_server(conn, active_profile, level, false, custom_catalog);
            emit_serve_status(robot_json, "stdio", None, &advertised_tools);
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
            let server = build_server(conn, active_profile, level, true, custom_catalog);
            let cfg = HttpTransportConfig::default();
            emit_serve_status(robot_json, "http", Some(&addr), &advertised_tools);
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
fn emit_serve_status(robot_json: bool, transport: &str, addr: Option<&str>, tools: &[String]) {
    if robot_json {
        eprintln!(
            "{}",
            serde_json::json!({
                "kind": "status",
                "transport": transport,
                "listen": addr,
                "live_db": LIVE_DB,
                "tools": tools,
            })
        );
    } else {
        match addr {
            Some(a) => eprintln!(
                "oraclemcp serve: http transport listening on {a} ({} tools, live-db: {LIVE_DB})",
                tools.len()
            ),
            None => eprintln!(
                "oraclemcp serve: stdio transport ready ({} tools, live-db: {LIVE_DB})",
                tools.len()
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
        "tools": &registry::TOOL_NAMES[..],
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

fn robot_docs_guide_json() -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "guide_version": 1,
        "binary": "oraclemcp",
        "structured_output": {
            "flag": "--robot-json",
            "alias": "--json",
            "contract": "stdout is compact JSON; diagnostics go to stderr"
        },
        "tool_schema_contract": {
            "top_level": "every advertised MCP tool input schema is a JSON object",
            "strict_client_safe": "tool parameter schemas avoid top-level oneOf, anyOf, allOf, enum, and not"
        },
        "client_setup": {
            "principle": "install or build one oraclemcp binary, then configure each MCP client to call the same command, args, config file, and environment",
            "stdio": {
                "command": "oraclemcp",
                "args": ["serve", "--profile", "<profile>", "--allow-no-auth"],
                "argv": ["oraclemcp", "serve", "--profile", "<profile>", "--allow-no-auth"],
                "notes": [
                    "Use --allow-no-auth only for local stdio clients you already trust.",
                    "If Oracle client libraries or network files need environment setup, point every MCP client at the same small wrapper script."
                ]
            },
            "secure_stdio": {
                "command": "oraclemcp",
                "args": ["serve", "--profile", "<profile>"],
                "env": {
                    "ORACLEMCP_STDIO_TOKEN": "<shared-init-token>"
                },
                "notes": [
                    "Use this when the MCP client can send the init token in initialize _meta.",
                    "If the client cannot send an init token, keep the server local and use --allow-no-auth intentionally."
                ]
            },
            "smoke_tests": [
                {
                    "intent": "verify the installed binary and local config without MCP",
                    "command": "oraclemcp --json doctor --profile <profile>",
                    "argv": ["oraclemcp", "--json", "doctor", "--profile", "<profile>"]
                },
                {
                    "intent": "verify the MCP client can import the tool list",
                    "mcp_method": "tools/list",
                    "expected": "the client discovers oracle_capabilities plus the advertised Oracle tools without schema import errors"
                },
                {
                    "intent": "verify a zero-arg MCP call works",
                    "mcp_tool": "oracle_capabilities",
                    "arguments": {}
                }
            ],
            "restart_rule": "after replacing the binary or wrapper, restart or reconnect each MCP client so it imports the fresh tool schema"
        },
        "first_commands": [
            {
                "intent": "discover configured profiles without opening a database connection",
                "command": "oraclemcp --json profiles",
                "argv": ["oraclemcp", "--json", "profiles"]
            },
            {
                "intent": "run offline diagnostics",
                "command": "oraclemcp --json doctor",
                "argv": ["oraclemcp", "--json", "doctor"]
            },
            {
                "intent": "run profile-backed diagnostics",
                "command": "oraclemcp --json doctor --profile <profile>",
                "argv": ["oraclemcp", "--json", "doctor", "--profile", "<profile>"]
            },
            {
                "intent": "inspect the MCP tool surface",
                "command": "oraclemcp --json capabilities",
                "argv": ["oraclemcp", "--json", "capabilities"]
            },
            {
                "intent": "start stdio MCP for a local agent",
                "command": "oraclemcp serve --profile <profile> --allow-no-auth",
                "argv": ["oraclemcp", "serve", "--profile", "<profile>", "--allow-no-auth"]
            }
        ],
        "mcp_workflows": [
            {
                "intent": "read data safely",
                "steps": [
                    "oracle_list_profiles",
                    "oracle_switch_profile if needed",
                    "oracle_preview_sql",
                    "oracle_query"
                ]
            },
            {
                "intent": "commit DML deliberately",
                "steps": [
                    "oracle_preview_sql",
                    "oracle_set_session_level when the preview asks for step-up",
                    "oracle_execute with commit=false for rollback preview",
                    "oracle_execute with commit=true and execute_confirmation.confirm only when committing"
                ]
            },
            {
                "intent": "apply DDL deliberately",
                "steps": [
                    "oracle_preview_sql or oracle_create_or_replace without execute=true",
                    "oracle_set_session_level with level=DDL when permitted",
                    "oracle_create_or_replace or oracle_execute with commit=true and the preview confirmation token"
                ]
            },
            {
                "intent": "patch stored source deliberately",
                "steps": [
                    "oracle_get_source or oracle_get_ddl to inspect the current object",
                    "oracle_patch_source with exact old_text/new_text and execute omitted",
                    "oracle_set_session_level with level=DDL when permitted",
                    "oracle_patch_source with execute=true and the preview confirmation token"
                ]
            }
        ],
        "safety_model": {
            "levels": ["READ_ONLY", "READ_WRITE", "DDL", "ADMIN"],
            "default_level": "READ_ONLY",
            "ceiling": "profile max_level is immutable for the running profile",
            "writes": "DML rolls back by default; commit requires a preview-derived confirmation token",
            "ddl_admin": "DDL and ADMIN statements require commit=true plus a confirmation token because Oracle cannot rollback-preview them"
        },
        "config": {
            "profiles": "~/.config/oraclemcp/profiles.toml or ORACLEMCP_CONFIG",
            "custom_tools": "~/.config/oraclemcp/tools.d/*.toml or ORACLEMCP_TOOLS_DIR",
            "secret_refs": "prefer credential_ref over literal passwords",
            "environment_specifics": "database aliases, session identity, client module/program labels, and custom workflow tools belong in profiles or tools.d config, not in the general core"
        },
        "diagnostic_flow": [
            {
                "intent": "binary and build posture",
                "argv": ["oraclemcp", "--json", "info"]
            },
            {
                "intent": "profile inventory without connecting",
                "argv": ["oraclemcp", "--json", "profiles"]
            },
            {
                "intent": "offline checks",
                "argv": ["oraclemcp", "--json", "doctor"]
            },
            {
                "intent": "profile-backed checks",
                "argv": ["oraclemcp", "--json", "doctor", "--profile", "<profile>"]
            },
            {
                "intent": "MCP tool surface and schema inspection",
                "argv": ["oraclemcp", "--json", "capabilities"]
            }
        ],
        "agent_rules": [
            "Prefer oracle_query for SELECT/WITH statements.",
            "Use oracle_preview_sql before oracle_execute or DDL helpers.",
            "Use oracle_patch_source for exact stored-source edits instead of hand-building full replacement DDL when possible.",
            "Never assume DDL can be rollback-previewed.",
            "Treat profile max_level as the hard ceiling for the running server.",
            "Keep company-specific tools, names, identities, and connection details in config."
        ],
        "exit_codes": [
            { "code": 0, "meaning": "success" },
            { "code": 2, "meaning": "invalid arguments, config error, failed diagnostics, or startup safety block" }
        ]
    })
}

fn robot_docs_guide_text() -> &'static str {
    r#"oraclemcp robot-docs guide

Output contract
- Use --robot-json or --json for compact machine-readable stdout.
- Diagnostics and serve startup status are written to stderr.
- Read-only commands do not open a database unless their command explicitly says so.
- MCP tool parameter schemas are top-level JSON objects and avoid top-level oneOf, anyOf, allOf, enum, and not for strict client adapters.

Client setup
- Install or build one oraclemcp binary, then configure every MCP client to call the same command, args, config file, and environment.
- Local stdio command: oraclemcp serve --profile <profile> --allow-no-auth
- Secure stdio command: ORACLEMCP_STDIO_TOKEN=<token> oraclemcp serve --profile <profile>
- If Oracle client libraries or network files need environment setup, point every MCP client at the same small wrapper script.
- After replacing the binary or wrapper, restart or reconnect each MCP client so it imports the fresh tool schema.

Client smoke tests
1. oraclemcp --json doctor --profile <profile>
2. MCP tools/list discovers oracle_capabilities plus the advertised Oracle tools without schema import errors
3. MCP tools/call oracle_capabilities with empty arguments succeeds

First commands
- oraclemcp --json profiles
- oraclemcp --json doctor
- oraclemcp --json doctor --profile <profile>
- oraclemcp --json capabilities
- oraclemcp serve --profile <profile> --allow-no-auth

MCP read workflow
1. oracle_list_profiles
2. oracle_switch_profile if the active profile is not the target profile
3. oracle_preview_sql to classify raw SQL before running it
4. oracle_query for proven read-only SELECT/WITH statements

MCP write workflow
1. oracle_preview_sql
2. oracle_set_session_level if the preview requires step-up and the profile ceiling permits it
3. oracle_execute with commit=false for rollback preview of DML
4. oracle_execute with commit=true and execute_confirmation.confirm only when committing

MCP DDL workflow
1. oracle_preview_sql or oracle_create_or_replace without execute=true
2. oracle_set_session_level with level=DDL when permitted by the profile ceiling
3. oracle_create_or_replace or oracle_execute with commit=true and the preview confirmation token

MCP source patch workflow
1. oracle_get_source or oracle_get_ddl to inspect the current object
2. oracle_patch_source with exact old_text/new_text and execute omitted
3. oracle_set_session_level with level=DDL when permitted by the profile ceiling
4. oracle_patch_source with execute=true and the preview confirmation token

Safety model
- Levels are ordered READ_ONLY < READ_WRITE < DDL < ADMIN.
- Profiles default to READ_ONLY and cannot be raised above max_level at runtime.
- DML rolls back by default.
- DDL and ADMIN require commit=true plus confirmation because Oracle cannot rollback-preview them.

Configuration
- Profiles: ~/.config/oraclemcp/profiles.toml or ORACLEMCP_CONFIG.
- Custom tools: ~/.config/oraclemcp/tools.d/*.toml or ORACLEMCP_TOOLS_DIR.
- Prefer credential_ref over literal passwords.
- Database aliases, session identity, client module/program labels, and custom workflow tools belong in profiles or tools.d config, not in the general core.

Diagnostic flow
1. oraclemcp --json info
2. oraclemcp --json profiles
3. oraclemcp --json doctor
4. oraclemcp --json doctor --profile <profile>
5. oraclemcp --json capabilities

Agent rules
- Prefer oracle_query for SELECT/WITH statements.
- Use oracle_preview_sql before oracle_execute or DDL helpers.
- Use oracle_patch_source for exact stored-source edits instead of hand-building full replacement DDL when possible.
- Never assume DDL can be rollback-previewed.
- Treat profile max_level as the hard ceiling for the running server.
- Keep company-specific tools, names, identities, and connection details in config.
"#
}

fn run_robot_docs_guide(robot_json: bool) -> ExitCode {
    if robot_json {
        println!(
            "{}",
            serde_json::to_string(&robot_docs_guide_json()).unwrap()
        );
    } else {
        print!("{}", robot_docs_guide_text());
    }
    ExitCode::SUCCESS
}

fn profiles_json(cfg: &OracleMcpConfig) -> serde_json::Value {
    let profiles = cfg
        .list_profiles()
        .into_iter()
        .map(|profile| {
            serde_json::json!({
                "name": profile.name,
                "description": profile.description,
                "is_default": profile.is_default,
                "call_timeout_seconds": profile.call_timeout_seconds,
                "max_level": profile.max_level,
                "default_level": profile.default_level,
                "protected": profile.protected,
                "read_only_standby": profile.read_only_standby,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "ok": true,
        "profile_count": profiles.len(),
        "has_default_profile": cfg.default_profile.is_some(),
        "profiles": profiles,
    })
}

fn profiles_text(cfg: &OracleMcpConfig) -> String {
    let profiles = cfg.list_profiles();
    if profiles.is_empty() {
        return "oraclemcp profiles\nno profiles configured\ncreate ~/.config/oraclemcp/profiles.toml or set ORACLEMCP_CONFIG\n".to_owned();
    }

    let mut out = String::from("oraclemcp profiles\n");
    for profile in profiles {
        let default = if profile.is_default { " default" } else { "" };
        let protected = if profile.protected { " protected" } else { "" };
        out.push_str(&format!(
            "- {}{}{} max_level={} default_level={}",
            profile.name, default, protected, profile.max_level, profile.default_level
        ));
        if let Some(description) = profile.description {
            out.push_str(&format!(" — {description}"));
        }
        out.push('\n');
    }
    out
}

fn run_profiles(robot_json: bool) -> ExitCode {
    match OracleMcpConfig::load(None) {
        Ok(cfg) => {
            if robot_json {
                println!("{}", profiles_json(&cfg));
            } else {
                print!("{}", profiles_text(&cfg));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            if robot_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "exit_code": 2,
                        "error": {
                            "class": "ConfigError",
                            "message": e.to_string(),
                        }
                    })
                );
            } else {
                eprintln!("oraclemcp profiles: {e}");
                eprintln!("fix: correct ~/.config/oraclemcp/profiles.toml or set ORACLEMCP_CONFIG");
            }
            ExitCode::from(2)
        }
    }
}

fn doctor_process_exit_code(report: &oraclemcp_core::DoctorReport) -> u8 {
    // Mirror plsql-mcp: a blocker (any failed check) exits 2.
    if report.any_failed() { 2 } else { 0 }
}

struct DoctorProfileContext {
    conn: Option<Box<dyn OracleConnection>>,
    connection_error: Option<String>,
    wallet_location: Option<String>,
    protected_profile_writable: bool,
}

fn doctor_profile_context(profile: Option<&str>) -> DoctorProfileContext {
    let Some(profile) = profile else {
        return DoctorProfileContext {
            conn: None,
            connection_error: None,
            wallet_location: None,
            protected_profile_writable: false,
        };
    };

    match resolve_profile_options(Some(profile)) {
        Ok(Some((_, opts, level))) => {
            let wallet_location = opts
                .wallet_location
                .as_ref()
                .map(|path| path.display().to_string());
            let protected_profile_writable =
                level.is_protected() && level.max_level() > OperatingLevel::ReadOnly;
            match try_open_connection(opts) {
                Ok(conn) => DoctorProfileContext {
                    conn: Some(conn),
                    connection_error: None,
                    wallet_location,
                    protected_profile_writable,
                },
                Err(e) => DoctorProfileContext {
                    conn: None,
                    connection_error: Some(e.to_string()),
                    wallet_location,
                    protected_profile_writable,
                },
            }
        }
        Ok(None) => DoctorProfileContext {
            conn: None,
            connection_error: Some(format!("connection profile `{profile}` not found")),
            wallet_location: None,
            protected_profile_writable: false,
        },
        Err(e) => DoctorProfileContext {
            conn: None,
            connection_error: Some(e.to_string()),
            wallet_location: None,
            protected_profile_writable: false,
        },
    }
}

fn run_doctor_cmd(robot_json: bool, profile: Option<String>) -> ExitCode {
    // Offline by default: no live connection (the live subset reports Skip with
    // a reason). With --profile, use the configured profile and let the live
    // checks report connection/auth/role failures as ordinary doctor checks.
    let profile_ctx = doctor_profile_context(profile.as_deref());
    let ctx = DoctorContext {
        conn: profile_ctx.conn.as_deref(),
        connection_error: profile_ctx.connection_error,
        tns_admin: std::env::var("TNS_ADMIN").ok(),
        wallet_location: profile_ctx.wallet_location,
        protected_profile_writable: profile_ctx.protected_profile_writable,
    };
    let report = run_doctor(&ctx);
    let exit_code = doctor_process_exit_code(&report);
    if robot_json {
        println!("{}", report.to_json_with_exit_code(i32::from(exit_code)));
    } else {
        // The human report is the data here; print it on stdout.
        print!("{}", report.to_text_with_exit_code(i32::from(exit_code)));
    }
    ExitCode::from(exit_code)
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
        fn query_rows_named(
            &self,
            _sql: &str,
            _b: &[(String, OracleBind)],
        ) -> Result<Vec<OracleRow>, DbError> {
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
    fn doctor_process_exit_code_matches_cli_contract() {
        let ok = oraclemcp_core::DoctorReport { checks: Vec::new() };
        assert_eq!(doctor_process_exit_code(&ok), 0);

        let failed = oraclemcp_core::DoctorReport {
            checks: vec![oraclemcp_core::CheckResult {
                id: 1,
                name: "example".to_owned(),
                status: oraclemcp_core::CheckStatus::Fail,
                detail: "failed".to_owned(),
                fix: None,
            }],
        };
        let process_code = doctor_process_exit_code(&failed);
        assert_eq!(process_code, 2);
        assert_eq!(
            failed.to_json_with_exit_code(i32::from(process_code))["exit_code"],
            serde_json::json!(2)
        );
    }

    #[test]
    fn profiles_json_reports_non_secret_metadata() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            schema_version = 1
            default_profile = "dev"

            [[profiles]]
            name = "dev"
            description = "Development profile"
            connect_string = "localhost:1521/FREEPDB1"
            username = "APP_USER"
            credential_ref = "env:ORACLE_PASSWORD"
            max_level = "READ_ONLY"
            default_level = "READ_ONLY"
            "#,
        )
        .expect("valid config");

        let out = profiles_json(&cfg);
        assert_eq!(out["ok"], serde_json::json!(true));
        assert_eq!(out["profile_count"], serde_json::json!(1));
        assert_eq!(out["has_default_profile"], serde_json::json!(true));
        assert_eq!(out["profiles"][0]["name"], serde_json::json!("dev"));
        assert_eq!(out["profiles"][0]["is_default"], serde_json::json!(true));
        let serialized = serde_json::to_string(&out).expect("json");
        assert!(!serialized.contains("APP_USER"));
        assert!(!serialized.contains("ORACLE_PASSWORD"));
        assert!(!serialized.contains("credential_ref"));
        assert!(!serialized.contains("FREEPDB1"));
        assert!(!serialized.contains("connect_string"));
    }

    #[test]
    fn profiles_text_handles_empty_config() {
        let cfg = OracleMcpConfig::from_toml_str("").expect("empty config is valid");
        let text = profiles_text(&cfg);
        assert!(text.contains("no profiles configured"));
        assert!(text.contains("ORACLEMCP_CONFIG"));
    }

    #[test]
    fn json_alias_is_accepted_before_and_after_subcommand() {
        let before = Cli::try_parse_from(["oraclemcp", "--json", "profiles"]).expect("parse");
        assert!(before.robot_json);
        assert!(matches!(before.command, Some(Command::Profiles)));

        let after = Cli::try_parse_from(["oraclemcp", "profiles", "--json"]).expect("parse");
        assert!(after.robot_json);
        assert!(matches!(after.command, Some(Command::Profiles)));
    }

    #[test]
    fn robot_docs_guide_is_available_with_or_without_guide_subcommand() {
        let bare = Cli::try_parse_from(["oraclemcp", "robot-docs"]).expect("parse");
        assert!(matches!(
            bare.command,
            Some(Command::RobotDocs { command: None })
        ));

        let explicit = Cli::try_parse_from(["oraclemcp", "robot-docs", "guide"]).expect("parse");
        assert!(matches!(
            explicit.command,
            Some(Command::RobotDocs {
                command: Some(RobotDocsCommand::Guide)
            })
        ));
    }

    #[test]
    fn robot_docs_guide_outputs_agent_workflows() {
        let text = robot_docs_guide_text();
        assert!(text.contains("oraclemcp robot-docs guide"));
        assert!(text.contains("oracle_preview_sql"));
        assert!(text.contains("oracle_execute"));
        assert!(text.contains("READ_ONLY < READ_WRITE < DDL < ADMIN"));

        let out = robot_docs_guide_json();
        assert_eq!(out["ok"], serde_json::json!(true));
        assert_eq!(
            out["structured_output"]["alias"],
            serde_json::json!("--json")
        );
        assert!(text.contains("Client smoke tests"));
        assert!(text.contains("MCP tools/list"));
        assert_eq!(
            out["tool_schema_contract"]["strict_client_safe"],
            serde_json::json!(
                "tool parameter schemas avoid top-level oneOf, anyOf, allOf, enum, and not"
            )
        );
        assert_eq!(
            out["client_setup"]["stdio"]["argv"],
            serde_json::json!([
                "oraclemcp",
                "serve",
                "--profile",
                "<profile>",
                "--allow-no-auth"
            ])
        );
        assert_eq!(
            out["client_setup"]["smoke_tests"][1]["mcp_method"],
            serde_json::json!("tools/list")
        );
        assert_eq!(
            out["diagnostic_flow"][4]["argv"],
            serde_json::json!(["oraclemcp", "--json", "capabilities"])
        );
        assert_eq!(
            out["first_commands"][0]["argv"],
            serde_json::json!(["oraclemcp", "--json", "profiles"])
        );
        assert_eq!(
            out["first_commands"][2]["argv"],
            serde_json::json!(["oraclemcp", "--json", "doctor", "--profile", "<profile>"])
        );
        assert_eq!(
            out["safety_model"]["levels"],
            serde_json::json!(["READ_ONLY", "READ_WRITE", "DDL", "ADMIN"])
        );
        assert!(
            serde_json::to_string(&out)
                .expect("json")
                .contains("oracle_preview_sql")
        );
    }

    fn custom_def(name: &str) -> CustomToolDef {
        CustomToolDef {
            name: name.to_owned(),
            description: "Test custom tool".to_owned(),
            sql: Some("SELECT 1 FROM dual".to_owned()),
            call: None,
            params: Vec::new(),
            output_mode: oraclemcp_core::OutputMode::Rows,
            declared_level: None,
            signature: None,
        }
    }

    #[test]
    fn custom_tool_names_cannot_duplicate_or_shadow_advertised_tools() {
        let err = validate_custom_tool_names(&[custom_def("app_lookup"), custom_def("app_lookup")])
            .expect_err("duplicate custom names rejected");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
        assert!(err.message.contains("duplicate custom tool name"));

        let err = validate_custom_tool_names(&[custom_def("query")])
            .expect_err("compatibility alias collision rejected");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
        assert!(err.message.contains("collides"));
    }

    #[test]
    fn build_server_advertises_the_registered_tools_plus_capabilities() {
        let conn = open_connection(OracleConnectOptions::default());
        let server = build_server(
            conn,
            None,
            default_read_only_level(),
            false,
            CustomToolCatalog::default(),
        );
        // The capabilities report carries the registry's tools.
        let caps = registry::capabilities(env!("CARGO_PKG_VERSION"), LIVE_DB, false);
        assert_eq!(caps.tools.len(), registry::TOOL_NAMES.len());
        // Smoke: the server clones (it is Clone) — proves it is fully built.
        let _ = server.clone();
    }
}
