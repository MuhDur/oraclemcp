//! Process hosting and transport attachment for the per-root broker.

use super::*;

#[derive(Clone)]
pub(super) struct SharedService {
    pub config: OracleMcpConfig,
    pub owner: ServiceOwner,
    pub auditor: Option<Arc<Auditor>>,
    pub write_intents: Option<Arc<WriteIntentLog>>,
    pub cost_budgets: Option<Arc<QueryCostBudgetStore>>,
    pub reservations: Arc<Mutex<HashSet<String>>>,
}

pub(super) struct HttpService {
    pub shared: SharedService,
    pub resolver: Arc<dyn SecretResolver>,
    pub shutdown: Arc<std::sync::atomic::AtomicBool>,
    pub status: Arc<Mutex<interprocess::local_socket::Stream>>,
    pub allow_remote_from_env: bool,
    listener_permit: Arc<Mutex<Option<HttpListenerPermit>>>,
}

#[derive(Default)]
struct HttpListenerState {
    running: bool,
    disconnected: bool,
}

type HttpListenerSlot = Arc<(Mutex<HttpListenerState>, std::sync::Condvar)>;

struct HttpListenerPermit(HttpListenerSlot);
impl Drop for HttpListenerPermit {
    fn drop(&mut self) {
        let (state, changed) = &*self.0;
        state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .running = false;
        changed.notify_all();
    }
}

fn acquire_http_listener(slot: &HttpListenerSlot) -> Option<HttpListenerPermit> {
    let (state, changed) = &**slot;
    let mut state = state.lock().expect("broker HTTP listener lock");
    if state.running && !state.disconnected {
        // A replacement can reach this thread just before the control reader
        // observes the dead launcher's EOF. Give that reader one scheduling
        // turn; a live launcher still owns its listener and is refused.
        state = changed
            .wait_timeout_while(state, std::time::Duration::from_millis(50), |s| {
                s.running && !s.disconnected
            })
            .expect("broker HTTP liveness wait")
            .0;
    }
    if state.running && state.disconnected {
        // Positive IPC EOF (or explicit shutdown), never a guessed stale PID.
        // Wait for listener closure, not telemetry/probe/session tail cleanup.
        state = changed
            .wait_timeout_while(state, std::time::Duration::from_secs(2), |s| s.running)
            .expect("broker HTTP closure wait")
            .0;
    }
    if state.running {
        return None;
    }
    state.running = true;
    state.disconnected = false;
    Some(HttpListenerPermit(slot.clone()))
}

impl HttpService {
    pub fn listener_closed(&self) {
        self.listener_permit
            .lock()
            .expect("HTTP listener permit lock")
            .take();
    }
    pub fn ready(&self, transport: &str, address: &str, tools: &[String]) {
        let mut writer = self.status.lock().expect("HTTP broker status lock");
        let _ = serde_json::to_writer(
            &mut *writer,
            &serve_status_payload(transport, Some(address), tools),
        );
        let _ = writer.write_all(b"\n");
        let _ = writer.flush();
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpStart {
    listen: String,
    allow_no_auth: bool,
    profile: Option<String>,
    strict_custom_tools: bool,
    http: HttpServeArgs,
    robot_json: bool,
    allow_remote_from_env: bool,
    environment: std::collections::BTreeMap<String, String>,
}

fn referenced_environment(
    value: &serde_json::Value,
    environment: &mut std::collections::BTreeMap<String, String>,
) {
    match value {
        serde_json::Value::String(value) => {
            if let Some(name) = value.strip_prefix("env:")
                && let Ok(secret) = std::env::var(name)
            {
                environment.insert(name.to_owned(), secret);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                referenced_environment(value, environment);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                referenced_environment(value, environment);
            }
        }
        _ => {}
    }
}

pub(super) fn run_http_proxy(
    listen: &str,
    allow_no_auth: bool,
    profile: Option<String>,
    strict_custom_tools: bool,
    http: HttpServeArgs,
    robot_json: bool,
) -> ExitCode {
    let result = (|| -> Result<ExitCode, ErrorEnvelope> {
        let config = OracleMcpConfig::load(None)
            .map_err(|e| ErrorEnvelope::new(ErrorClass::InvalidArguments, e.to_string()))?;
        let mut environment = std::collections::BTreeMap::new();
        referenced_environment(
            &serde_json::to_value(&config)
                .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?,
            &mut environment,
        );
        referenced_environment(
            &serde_json::to_value(&http)
                .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?,
            &mut environment,
        );
        let start = HttpStart {
            listen: listen.to_owned(),
            allow_no_auth,
            profile: profile.clone(),
            strict_custom_tools,
            http,
            robot_json,
            allow_remote_from_env: effective_http_allow_remote(false),
            environment,
        };
        let request = oraclemcp::broker::AttachRequest {
            identity: oraclemcp::broker::BrokerIdentity::from_config(
                &config,
                &serde_json::to_string(&strict_custom_tools).unwrap(),
            )?,
            profile,
            client_info: serde_json::json!({"name":"http-listener","version":env!("CARGO_PKG_VERSION")}),
            auth: StdioAuthPolicy::Disabled,
            http: Some(
                serde_json::to_value(start)
                    .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?,
            ),
        };
        let store = FileStore::open_default()
            .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
        let mut attached = attach_or_spawn_broker(
            &store,
            &request,
            &StdioAuthPolicy::Disabled,
            strict_custom_tools,
        )?;
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Keep the frontend alive until the broker acknowledges listener
        // closure. Default signal termination would race a replacement launcher.
        #[cfg(unix)]
        for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
            signal_hook::flag::register(signal, shutdown.clone())
                .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
        }
        let stopped = shutdown.clone();
        std::thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            let _ = attached.writer.write_all(b"q");
            let _ = attached.writer.flush();
        });
        let mut reader = attached.reader;
        use std::io::BufRead;
        loop {
            let mut line = String::new();
            if reader
                .read_line(&mut line)
                .map_err(|e| ErrorEnvelope::new(ErrorClass::Transient, e.to_string()))?
                == 0
            {
                shutdown.store(true, Ordering::Release);
                return Err(ErrorEnvelope::new(
                    ErrorClass::Transient,
                    "HTTP broker disconnected",
                ));
            }
            let frame: serde_json::Value = serde_json::from_str(&line)
                .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
            if let Some(code) = frame["exit"].as_u64() {
                shutdown.store(true, Ordering::Release);
                if let Some(error) = frame.get("error") {
                    let error: ErrorEnvelope = serde_json::from_value(error.clone())
                        .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
                    return Err(error);
                }
                return Ok(ExitCode::from(code as u8));
            }
            if robot_json {
                eprintln!("{frame}");
            } else if frame["kind"] == "status" {
                eprintln!(
                    "oraclemcp serve: {} transport listening on {}",
                    frame["transport"].as_str().unwrap_or("http"),
                    frame["listen"].as_str().unwrap_or(listen)
                );
            }
            if frame["kind"] == "status" {
                readiness::notify_systemd_ready();
            }
        }
    })();
    match result {
        Ok(code) => code,
        Err(error) => {
            if robot_json {
                eprintln!("{}", serde_json::json!({"kind":"error","error":error}));
            } else {
                eprintln!(
                    "oraclemcp HTTP proxy: {:?}: {}",
                    error.error_class, error.message
                );
            }
            ExitCode::from(2)
        }
    }
}

fn serve_http(
    mut reader: std::io::BufReader<interprocess::local_socket::Stream>,
    writer: interprocess::local_socket::Stream,
    start: serde_json::Value,
    shared: SharedService,
    permit: HttpListenerPermit,
) -> Result<(), ErrorEnvelope> {
    let start: HttpStart = serde_json::from_value(start)
        .map_err(|e| ErrorEnvelope::new(ErrorClass::InvalidArguments, e.to_string()))?;
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let disconnected = shutdown.clone();
    let slot = permit.0.clone();
    std::thread::spawn(move || {
        let _ = reader.read(&mut [0_u8]);
        let (state, changed) = &*slot;
        state
            .lock()
            .expect("HTTP listener liveness lock")
            .disconnected = true;
        disconnected.store(true, Ordering::Release);
        changed.notify_all();
    });
    let listener_permit = Arc::new(Mutex::new(Some(permit)));
    let resolver = oraclemcp_auth::EnvLookupSecretResolver::new(move |name: &str| {
        start.environment.get(name).cloned()
    });
    let status = Arc::new(Mutex::new(writer));
    let service = HttpService {
        shared,
        resolver: Arc::new(resolver),
        shutdown,
        status: status.clone(),
        allow_remote_from_env: start.allow_remote_from_env,
        listener_permit: listener_permit.clone(),
    };
    let result = run_serve(
        Some(start.listen),
        start.allow_no_auth,
        None,
        start.profile,
        start.strict_custom_tools,
        start.http,
        (start.robot_json, Some(service)),
    );
    let code = (0..=u8::MAX)
        .find(|code| ExitCode::from(*code) == result)
        .unwrap_or(1);
    // A successful frontend exit must also acknowledge that another launcher
    // may acquire this root's listener, rather than just that the socket closed.
    listener_permit
        .lock()
        .expect("HTTP listener permit lock")
        .take();
    let mut writer = status.lock().expect("HTTP broker status lock");
    serde_json::to_writer(&mut *writer, &serde_json::json!({"exit":code}))
        .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|e| ErrorEnvelope::new(ErrorClass::Transient, e.to_string()))
}

fn validate_spawn_credentials(profile: Option<&str>) -> Result<(), ErrorEnvelope> {
    let config = OracleMcpConfig::load(None)
        .map_err(|e| ErrorEnvelope::new(ErrorClass::InvalidArguments, e.to_string()))?;
    let resolved = resolve_profile_options_from_config_with(&config, profile, &SystemSecretResolver)
        .map_err(|_| ErrorEnvelope::new(ErrorClass::PolicyDenied,
            "ORACLEMCP_BROKER_CREDENTIAL_INVALID: resolve this client's configured credentials before starting a broker"))?;
    let Some(resolved) = resolved else {
        return Ok(());
    };
    let outcome = block_on_connect(|cx| async move {
        let connection = try_open_connection(&cx, resolved.opts).await?;
        // This validates authentication only; no agent statement is executed.
        let _ = connection.close(&cx).await;
        Ok::<(), DbError>(())
    });
    if let Err(error) = outcome {
        let error = error.into_envelope();
        if matches!(
            error.ora_code,
            Some(1017 | 1005 | 1045 | 28000 | 28001 | 28009)
        ) {
            return Err(ErrorEnvelope::new(ErrorClass::PolicyDenied,
                "ORACLEMCP_BROKER_CREDENTIAL_INVALID: Oracle refused this client's credentials; a broker was not started")
                .with_ora_code(error.ora_code.expect("matched Oracle authentication code")));
        }
        // Unknown/unreachable database evidence must not block offline tools
        // (R36). Only a positive authentication refusal prevents ownership.
    }
    Ok(())
}

fn attach_or_spawn_broker(
    store: &FileStore,
    request: &oraclemcp::broker::AttachRequest,
    auth: &StdioAuthPolicy,
    strict_custom_tools: bool,
) -> Result<oraclemcp::broker::AttachedStream, ErrorEnvelope> {
    match oraclemcp::broker::attach(store, request) {
        Ok(stream) => return Ok(stream),
        Err(error) if error.error_class != ErrorClass::Transient => return Err(error),
        Err(_) => {}
    }
    // A bad first client must not fix the broker's credential binding for all
    // later clients. Authenticate before electing/spawning the root owner.
    validate_spawn_credentials(request.profile.as_deref())?;
    let binary = std::env::current_exe()
        .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
    let mut command = std::process::Command::new(binary);
    command
        .arg("broker")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null());
    match auth {
        StdioAuthPolicy::Disabled => {
            command.arg("--allow-no-auth");
        }
        StdioAuthPolicy::Required { expected } => {
            command.env(oraclemcp_core::init_token::STDIO_TOKEN_ENV, expected);
        }
    }
    if strict_custom_tools {
        command.arg("--strict-custom-tools");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x00000008 | 0x00000200);
    }
    let mut child = command.spawn().map_err(|e| {
        ErrorEnvelope::new(
            ErrorClass::Transient,
            format!("cannot spawn local broker: {e}"),
        )
    })?;
    // Attachment may succeed before a losing election child exits. Retain its
    // handle in a reaper instead of dropping it and leaving a zombie for the
    // whole lifetime of this proxy. Waiting for the winning detached broker
    // happens on this thread too, without delaying MCP traffic.
    std::thread::spawn(move || {
        if let Err(error) = child.wait() {
            tracing::warn!(%error, "failed to reap spawned broker process");
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match oraclemcp::broker::attach(store, request) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if error.error_class != ErrorClass::Transient
                    || std::time::Instant::now() >= deadline =>
            {
                return Err(error);
            }
            Err(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

pub(super) fn run_stdio_broker_proxy(
    config: &OracleMcpConfig,
    auth: &StdioAuthPolicy,
    profile: Option<String>,
    strict_custom_tools: bool,
) -> ExitCode {
    use std::io::{BufRead, Read, Write};
    use std::sync::mpsc;
    enum Event {
        Client(Vec<u8>),
        ClientClosed,
        Broker(u64, Vec<u8>),
        BrokerClosed(u64),
    }
    fn write_refusal(
        writer: &mut impl Write,
        id: &serde_json::Value,
        tool: bool,
        error: &ErrorEnvelope,
    ) -> Result<(), ErrorEnvelope> {
        let result = if tool {
            serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"isError":true,"content":[{"type":"text","text":serde_json::to_string(error).unwrap_or_default()}],"structuredContent":error}})
        } else {
            serde_json::json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":error.message,"data":error}})
        };
        serde_json::to_writer(&mut *writer, &result)
            .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
        writer
            .write_all(b"\n")
            .and_then(|()| writer.flush())
            .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))
    }
    let result = (|| -> Result<(), ErrorEnvelope> {
        let policy = serde_json::to_string(&strict_custom_tools)
            .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
        let identity = oraclemcp::broker::BrokerIdentity::from_config(config, &policy)?;
        let store = FileStore::open_default()
            .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
        let (events, received) = mpsc::sync_channel(32);
        let client_events = events.clone();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            loop {
                let mut frame = Vec::new();
                match (&mut stdin)
                    .take(1024 * 1024 + 1)
                    .read_until(b'\n', &mut frame)
                {
                    Ok(0) | Err(_) => break,
                    Ok(_) if frame.len() > 1024 * 1024 => break,
                    Ok(_) => {
                        if client_events.send(Event::Client(frame)).is_err() {
                            return;
                        }
                    }
                }
            }
            let _ = client_events.send(Event::ClientClosed);
        });
        let mut stdout = std::io::stdout().lock();
        let mut attached = None;
        let mut generation = 0_u64;
        let mut recovery_used = false;
        let mut initialization: Option<Vec<u8>> = None;
        let mut initialized = false;
        let mut request = oraclemcp::broker::AttachRequest {
            identity,
            profile,
            client_info: serde_json::Value::Null,
            auth: auth.clone(),
            http: None,
        };
        let mut pending: HashMap<String, (serde_json::Value, bool)> = HashMap::new();
        loop {
            match received
                .recv()
                .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?
            {
                Event::Client(frame) => {
                    let metadata: serde_json::Value =
                        serde_json::from_slice(&frame).unwrap_or(serde_json::Value::Null);
                    let id = metadata.get("id").cloned();
                    let tool = metadata["method"] == "tools/call";
                    if metadata["method"] == "initialize" && initialization.is_none() {
                        request.client_info = metadata
                            .pointer("/params/clientInfo")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        initialization = Some(frame.clone());
                    }
                    if attached.is_none() {
                        let recovered = generation != 0;
                        if recovered && recovery_used {
                            let error = ErrorEnvelope::new(
                                ErrorClass::Transient,
                                "broker recovery exhausted; restart this MCP client; no statement was replayed",
                            );
                            if let Some(id) = id {
                                write_refusal(&mut stdout, &id, tool, &error)?;
                            }
                            continue;
                        }
                        if recovered {
                            recovery_used = true;
                        }
                        let mut connection = match attach_or_spawn_broker(
                            &store,
                            &request,
                            auth,
                            strict_custom_tools,
                        ) {
                            Ok(connection) => connection,
                            Err(error) => {
                                if let Some(id) = id {
                                    write_refusal(&mut stdout, &id, tool, &error)?;
                                }
                                continue;
                            }
                        };
                        if recovered
                            && initialized
                            && let Some(init) = &initialization
                            && let Err(error) =
                                oraclemcp::broker::reinitialize(&mut connection, init)
                        {
                            if let Some(id) = id {
                                write_refusal(&mut stdout, &id, tool, &error)?;
                            }
                            continue;
                        }
                        generation += 1;
                        let reader_generation = generation;
                        let broker_events = events.clone();
                        let mut reader = connection.reader;
                        std::thread::spawn(move || {
                            loop {
                                let mut response = Vec::new();
                                match (&mut reader)
                                    .take(16 * 1024 * 1024 + 1)
                                    .read_until(b'\n', &mut response)
                                {
                                    Ok(0) | Err(_) => break,
                                    Ok(_) if response.len() > 16 * 1024 * 1024 => break,
                                    Ok(_) => {
                                        if broker_events
                                            .send(Event::Broker(reader_generation, response))
                                            .is_err()
                                        {
                                            return;
                                        }
                                    }
                                }
                            }
                            let _ = broker_events.send(Event::BrokerClosed(reader_generation));
                        });
                        attached = Some(connection.writer);
                    }
                    if metadata["method"] == "notifications/initialized" {
                        initialized = true;
                    }
                    if let Some(id) = id {
                        pending.insert(id.to_string(), (id, tool));
                    }
                    let write_result = attached
                        .as_mut()
                        .expect("attached above")
                        .write_all(&frame)
                        .and_then(|()| attached.as_mut().expect("attached above").flush());
                    if write_result.is_err() {
                        let _ = events.try_send(Event::BrokerClosed(generation));
                    }
                }
                Event::Broker(current, frame) if current == generation => {
                    if let Ok(metadata) = serde_json::from_slice::<serde_json::Value>(&frame)
                        && let Some(id) = metadata.get("id")
                    {
                        pending.remove(&id.to_string());
                    }
                    stdout
                        .write_all(&frame)
                        .and_then(|()| stdout.flush())
                        .map_err(|e| ErrorEnvelope::new(ErrorClass::Transient, e.to_string()))?;
                }
                Event::ClientClosed => return Ok(()),
                Event::BrokerClosed(current) if current == generation => {
                    attached = None;
                    let error = ErrorEnvelope::new(
                        ErrorClass::Transient,
                        "local broker connection lost; statement fate may be unknown; no statement was replayed; session elevations and transactions are lost",
                    );
                    for (_, (id, tool)) in pending.drain() {
                        write_refusal(&mut stdout, &id, tool, &error)?;
                    }
                }
                Event::Broker(_, _) | Event::BrokerClosed(_) => {}
            }
        }
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "oraclemcp proxy: {:?}: {}",
                error.error_class, error.message
            );
            ExitCode::from(2)
        }
    }
}

pub(super) fn run_broker(_allow_no_auth: bool, strict_custom_tools: bool) -> ExitCode {
    let _telemetry = oraclemcp_telemetry::init_telemetry("info", OtlpConfig::from_env());
    let result = (|| -> Result<(), ErrorEnvelope> {
        let config = OracleMcpConfig::load(None)
            .map_err(|e| ErrorEnvelope::new(ErrorClass::InvalidArguments, e.to_string()))?;
        let policy = serde_json::to_string(&strict_custom_tools)
            .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
        let identity = oraclemcp::broker::BrokerIdentity::from_config(&config, &policy)?;
        let store = FileStore::open_default()
            .map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
        let broker = oraclemcp::broker::BrokerListener::bind(&store, identity)?;
        let owner = broker.owner();
        let resolver: Arc<dyn SecretResolver> = Arc::new(SystemSecretResolver);
        let ceiling = max_reachable_write_ceiling(&config, &default_read_only_level());
        let auditor = open_auditor(
            &config.audit,
            &default_read_only_level(),
            ceiling,
            resolver.as_ref(),
        )
        .map_err(|e| {
            let (code, message) = e.into_pair();
            ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                format!("{code}: {message}"),
            )
        })?;
        let write_intents =
            build_write_intent_log(ceiling, Some(&owner)).map_err(|(code, message)| {
                ErrorEnvelope::new(ErrorClass::Internal, format!("{code}: {message}"))
            })?;
        let cost_budgets =
            build_query_cost_budget_store(has_cumulative_query_cost_budget(&config), Some(&owner))
                .map_err(|(code, message)| {
                    ErrorEnvelope::new(ErrorClass::Internal, format!("{code}: {message}"))
                })?;
        let reservations = Arc::new(Mutex::new(HashSet::new()));
        let shared = SharedService {
            config: config.clone(),
            owner,
            auditor: auditor.clone(),
            write_intents: write_intents.clone(),
            cost_budgets: cost_budgets.clone(),
            reservations: reservations.clone(),
        };
        let http_listener = Arc::new((
            Mutex::new(HttpListenerState::default()),
            std::sync::Condvar::new(),
        ));
        broker.serve(
            oraclemcp::broker::IDLE_TIMEOUT,
            move |reader, writer, peer| {
                if let Some(start) = peer.http {
                    let Some(permit) = acquire_http_listener(&http_listener) else {
                        let error = ErrorEnvelope::new(ErrorClass::Busy, "ORACLEMCP_HTTP_LISTENER_ALREADY_RUNNING: connect to this root's existing HTTP listener");
                        let mut writer = writer;
                        serde_json::to_writer(&mut writer, &serde_json::json!({"exit":2,"error":error})).map_err(|e| ErrorEnvelope::new(ErrorClass::Internal, e.to_string()))?;
                        writer.write_all(b"\n").and_then(|()| writer.flush()).map_err(|e| ErrorEnvelope::new(ErrorClass::Transient, e.to_string()))?;
                        return Ok(());
                    };
                    return serve_http(reader, writer, start, shared.clone(), permit);
                }
                let selected = select_runtime_profile_from_config(&config, peer.profile.as_deref())
                    .map_err(|e| ErrorEnvelope::new(ErrorClass::InvalidArguments, e.to_string()))?;
                let (plan, profile, level, timeout, max_cost, budget, masking, sql_policy) =
                    match selected {
                        Some(selected) => (
                            RuntimeConnectionPlan::Profile(selected.name.clone()),
                            Some(selected.name),
                            selected.level,
                            selected.request_timeout,
                            selected.max_query_cost,
                            selected.cumulative_query_cost_budget,
                            selected.result_masking,
                            selected.sql_policy,
                        ),
                        None => (
                            RuntimeConnectionPlan::Default,
                            None,
                            default_read_only_level(),
                            OracleConnectOptions::default().call_timeout,
                            None,
                            None,
                            None,
                            None,
                        ),
                    };
                // Validate this profile's protected-key policy without opening
                // a second writer. The broker alone owns the already armed sink.
                resolve_audit_keyring(&config.audit, level.is_protected(), resolver.as_ref())
                    .map_err(|(code, message)| {
                        ErrorEnvelope::new(ErrorClass::PolicyDenied, format!("{code}: {message}"))
                    })?;
                let custom = load_custom_catalog_for_snapshot(
                    &config,
                    profile.as_deref(),
                    &level,
                    strict_custom_tools,
                )?;
                let exports = Arc::new(ExportRegistry::new());
                let max_level = level.max_level();
                let connections =
                    open_runtime_connection_plan(plan, &config, true, resolver.as_ref());
                let mut wiring = dispatcher_wiring(
                    profile,
                    level,
                    ServerBuildOptions {
                        custom_catalog: custom.catalog,
                        strict_custom_tools,
                        auditor: auditor.clone(),
                        write_intents: write_intents.clone(),
                        secret_resolver: resolver.clone(),
                        request_timeout: timeout,
                        max_query_cost: max_cost,
                        cumulative_query_cost_budget: budget,
                        query_cost_budgets: cost_budgets.clone(),
                        result_masking: masking,
                        sql_policy,
                        profile_drain: ProfileDrainState::from_config(config.clone()),
                        unsigned_refusal_log: unsigned_refusal_trail_enabled(
                            auditor.is_some(),
                            config.audit.unsigned_refusal_log,
                        ),
                    },
                    &exports,
                );
                wiring.edition_creation_reservations = reservations.clone();
                let subject = AuditSubject::new(
                    "stdio-broker",
                    format!("{}:session:{}", peer.peer_identity, peer.session_id),
                )
                .with_authn_method("local-ipc")
                .with_client_id(peer.client_info.to_string());
                let dispatcher =
                    build_oracle_dispatcher(connections.session, connections.stateless, &wiring)
                        .with_default_audit_subject(subject);
                let dispatch: Arc<dyn ToolDispatch> =
                    Arc::new(LaneRuntime::spawn_default_with_panic_auditor(
                        "served-broker-stdio",
                        Arc::new(dispatcher),
                        auditor.clone(),
                    ));
                let server = server_shell(
                    max_level,
                    ServerTransportMode::Stdio,
                    custom.skipped,
                    dispatch,
                    exports,
                );
                let served = server.serve_stdio_with_io(reader, writer, &peer.auth);
                let closed = server.close_blocking(DispatchCloseReason::ServerShutdown);
                served.map_err(|e| ErrorEnvelope::new(ErrorClass::Transient, e.to_string()))?;
                closed
            },
        )
    })();
    broker_exit_code(result)
}

pub(super) fn broker_exit_code(result: Result<(), ErrorEnvelope>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error)
            if error.error_class == ErrorClass::Transient
                && error.message.starts_with("ORACLEMCP_BROKER_OWNER_LOCKED:") =>
        {
            // A racing candidate is done once another broker owns the root.
            // Its proxy attaches to that winner; this is normal startup.
            tracing::debug!("another broker won the local service election");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "oraclemcp broker: {:?}: {}",
                error.error_class, error.message
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_launcher_retains_exclusive_http_ownership() {
        let slot = Arc::new((
            Mutex::new(HttpListenerState::default()),
            std::sync::Condvar::new(),
        ));
        let permit = acquire_http_listener(&slot).expect("first listener");
        assert!(
            acquire_http_listener(&slot).is_none(),
            "a live launcher is never displaced"
        );
        drop(permit);
        assert!(
            acquire_http_listener(&slot).is_some(),
            "closed listener releases ownership"
        );
    }

    #[test]
    fn positive_launcher_disconnect_waits_for_listener_release() {
        let slot = Arc::new((
            Mutex::new(HttpListenerState::default()),
            std::sync::Condvar::new(),
        ));
        let permit = acquire_http_listener(&slot).unwrap();
        slot.0.lock().unwrap().disconnected = true;
        let next_slot = slot.clone();
        let next = std::thread::spawn(move || acquire_http_listener(&next_slot));
        drop(permit);
        let replacement = next
            .join()
            .unwrap()
            .expect("dead launcher's replacement acquires the released listener");
        assert!(slot.0.lock().unwrap().running);
        assert!(!slot.0.lock().unwrap().disconnected);
        drop(replacement);
        assert!(!slot.0.lock().unwrap().running);
    }
}
