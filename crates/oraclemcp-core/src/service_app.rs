//! Always-on service supervision topology.
//!
//! This module is the AppSpec bridge for the service-mode work package. It
//! keeps the service child ordering and restart semantics as data so production
//! startup can migrate away from ad-hoc shutdown flags without rediscovering
//! those contracts in the transport layer.

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use asupersync::app::{AppHandle, AppSpec, AppStartError, AppStopError};
use asupersync::cx::registry::RegistryHandle;
use asupersync::observability::{
    CancellationExplanation, TaskInspector, TaskSummaryWire,
    spectral_health::{
        EarlyWarningSeverity, HealthClassification, SpectralHealthMonitor, SpectralThresholds,
    },
};
use asupersync::runtime::{RuntimeBuilder, state::RuntimeState};
use asupersync::supervision::{
    ChildSpec, ChildStart, NameCollisionPolicy, NameRegistrationPolicy, RestartConfig,
    RestartPolicy, StartTieBreak, SupervisionStrategy,
};
use asupersync::types::{Budget, CancelKind, RegionId};
use parking_lot::Mutex;
use serde::Serialize;

use crate::admission::AdmissionController;
use crate::http::{
    HttpTransportConfig, serve_control_https_until, serve_http_until, serve_https_until,
};
use crate::server::OracleMcpServer;
use crate::tls::TlsServerConfig;

/// Root AppSpec name for the persistent service tree.
pub const SERVICE_APP_NAME: &str = "oraclemcp-service";

/// Audit writer child. Must be available before any externally visible child.
pub const SERVICE_CHILD_AUDIT_CHAIN_WRITER: &str = "audit-chain-writer";
/// Metrics/readiness collector child.
pub const SERVICE_CHILD_METRICS_HEALTH_COLLECTOR: &str = "metrics-health-collector";
/// Lane registry/supervisor child. Holds Send lane handles, not connections.
pub const SERVICE_CHILD_LANE_REGISTRY_SUPERVISOR: &str = "lane-registry-supervisor";
/// Dashboard/operator API child.
pub const SERVICE_CHILD_DASHBOARD_API: &str = "dashboard-api";
/// HTTP/SSE accept transport child. Starts last.
pub const SERVICE_CHILD_TRANSPORT: &str = "transport";

const SERVICE_RESTART_MAX: u32 = 3;
const SERVICE_RESTART_WINDOW: Duration = Duration::from_secs(60);

/// Children in the service AppSpec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceAppChild {
    /// Append-only audit chain writer.
    AuditChainWriter,
    /// In-memory metrics and health collector.
    MetricsHealthCollector,
    /// Lane registry and supervisor.
    LaneRegistrySupervisor,
    /// Dashboard/operator API.
    DashboardApi,
    /// HTTP/SSE transport acceptor.
    Transport,
}

impl ServiceAppChild {
    /// Stable child name used by AppSpec, traces, and future registry leases.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AuditChainWriter => SERVICE_CHILD_AUDIT_CHAIN_WRITER,
            Self::MetricsHealthCollector => SERVICE_CHILD_METRICS_HEALTH_COLLECTOR,
            Self::LaneRegistrySupervisor => SERVICE_CHILD_LANE_REGISTRY_SUPERVISOR,
            Self::DashboardApi => SERVICE_CHILD_DASHBOARD_API,
            Self::Transport => SERVICE_CHILD_TRANSPORT,
        }
    }

    fn dependencies(self) -> &'static [&'static str] {
        match self {
            Self::AuditChainWriter => &[],
            Self::MetricsHealthCollector => &[SERVICE_CHILD_AUDIT_CHAIN_WRITER],
            Self::LaneRegistrySupervisor => &[SERVICE_CHILD_AUDIT_CHAIN_WRITER],
            Self::DashboardApi => &[
                SERVICE_CHILD_METRICS_HEALTH_COLLECTOR,
                SERVICE_CHILD_LANE_REGISTRY_SUPERVISOR,
            ],
            Self::Transport => &[SERVICE_CHILD_DASHBOARD_API],
        }
    }

    fn supervision_strategy(self) -> SupervisionStrategy {
        match self {
            Self::AuditChainWriter => SupervisionStrategy::Escalate,
            Self::MetricsHealthCollector
            | Self::LaneRegistrySupervisor
            | Self::DashboardApi
            | Self::Transport => SupervisionStrategy::Restart(RestartConfig::new(
                SERVICE_RESTART_MAX,
                SERVICE_RESTART_WINDOW,
            )),
        }
    }
}

/// Expected deterministic startup order for the service tree.
#[must_use]
pub const fn service_app_start_order() -> [ServiceAppChild; 5] {
    [
        ServiceAppChild::AuditChainWriter,
        ServiceAppChild::MetricsHealthCollector,
        ServiceAppChild::LaneRegistrySupervisor,
        ServiceAppChild::DashboardApi,
        ServiceAppChild::Transport,
    ]
}

/// One service child row in the doctor health snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceChildDoctorSnapshot {
    /// Stable child name.
    pub name: &'static str,
    /// Stable dependency names.
    pub dependencies: Vec<&'static str>,
    /// Supervision behavior for this child.
    pub supervision: &'static str,
}

/// Compact spectral topology row for `oraclemcp doctor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceSpectralDoctorSnapshot {
    /// Health state vocabulary expected by operator surfaces.
    pub state: &'static str,
    /// Full asupersync spectral classification rendered for humans.
    pub classification: String,
    /// Quantized Fiedler value to avoid unstable floating-point JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fiedler_micro_units: Option<u64>,
    /// Quantized spectral gap in basis points.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spectral_gap_bps: Option<u16>,
    /// Number of structural bottleneck nodes.
    pub bottleneck_count: usize,
    /// Early-warning severity from the Spectral Health Monitor.
    pub early_warning: &'static str,
}

/// TaskInspector summary row for `oraclemcp doctor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceTaskDoctorSnapshot {
    /// Stable summary produced through asupersync TaskInspector.
    pub summary: TaskSummaryWire,
    /// Non-terminal tasks in the snapshot.
    pub active_tasks: usize,
}

/// CancellationExplanation summary row for `oraclemcp doctor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceCancellationDoctorSnapshot {
    /// Whether a cancellation chain is currently observed in the snapshot.
    pub observed: bool,
    /// asupersync cancellation kind rendered from CancellationExplanation.
    pub kind: String,
    /// Optional sanitized cancellation context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Number of propagation hops in the explanation.
    pub propagation_path_len: usize,
}

/// Configured/effective service-topology caps surfaced by doctor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceCapsDoctorSnapshot {
    /// Root AppSpec restart policy.
    pub restart_policy: &'static str,
    /// Number of configured service children.
    pub child_count: usize,
    /// Maximum restart attempts per restart window for restartable children.
    pub restart_max: u32,
    /// Restart window in seconds.
    pub restart_window_seconds: u64,
}

/// Read-only service/lane health snapshot for `oraclemcp doctor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceAppDoctorSnapshot {
    /// Snapshot producer.
    pub source: &'static str,
    /// AppSpec name.
    pub app: &'static str,
    /// Configured service children.
    pub children: Vec<ServiceChildDoctorSnapshot>,
    /// Spectral Health Monitor summary.
    pub spectral: ServiceSpectralDoctorSnapshot,
    /// TaskInspector summary.
    pub task_inspector: ServiceTaskDoctorSnapshot,
    /// CancellationExplanation summary.
    pub cancellation: ServiceCancellationDoctorSnapshot,
    /// Configured topology caps.
    pub configured_caps: ServiceCapsDoctorSnapshot,
    /// Effective topology caps after this binary's static policy.
    pub effective_caps: ServiceCapsDoctorSnapshot,
}

fn service_child_supervision_label(child: ServiceAppChild) -> &'static str {
    match child {
        ServiceAppChild::AuditChainWriter => "escalate",
        ServiceAppChild::MetricsHealthCollector
        | ServiceAppChild::LaneRegistrySupervisor
        | ServiceAppChild::DashboardApi
        | ServiceAppChild::Transport => "restart",
    }
}

fn service_child_doctor_snapshots() -> Vec<ServiceChildDoctorSnapshot> {
    service_app_start_order()
        .into_iter()
        .map(|child| ServiceChildDoctorSnapshot {
            name: child.name(),
            dependencies: child.dependencies().to_vec(),
            supervision: service_child_supervision_label(child),
        })
        .collect()
}

fn service_dependency_edges(children: &[ServiceChildDoctorSnapshot]) -> Vec<(usize, usize)> {
    children
        .iter()
        .enumerate()
        .flat_map(|(child_index, child)| {
            child.dependencies.iter().filter_map(move |dependency| {
                children
                    .iter()
                    .position(|candidate| candidate.name == *dependency)
                    .map(|dependency_index| (dependency_index, child_index))
            })
        })
        .collect()
}

fn finite_micro_units(value: f64) -> Option<u64> {
    if value.is_finite() && value >= 0.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some((value * 1_000_000.0).round().min(u64::MAX as f64) as u64)
    } else {
        None
    }
}

fn finite_bps(value: f64) -> Option<u16> {
    if value.is_finite() && value >= 0.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some((value * 10_000.0).round().clamp(0.0, f64::from(u16::MAX)) as u16)
    } else {
        None
    }
}

fn early_warning_label(severity: EarlyWarningSeverity) -> &'static str {
    match severity {
        EarlyWarningSeverity::None => "none",
        EarlyWarningSeverity::Watch => "watch",
        EarlyWarningSeverity::Warning => "warning",
        EarlyWarningSeverity::Critical => "critical",
    }
}

fn spectral_state(
    classification: &HealthClassification,
    early_warning: EarlyWarningSeverity,
) -> &'static str {
    if early_warning != EarlyWarningSeverity::None {
        return early_warning_label(early_warning);
    }
    match classification {
        HealthClassification::Healthy { .. } => "none",
        HealthClassification::Degraded { .. } => "watch",
        HealthClassification::Critical { .. } | HealthClassification::Fragmented { .. } => {
            "warning"
        }
        HealthClassification::Deadlocked => "critical",
    }
}

fn service_spectral_snapshot(
    children: &[ServiceChildDoctorSnapshot],
) -> ServiceSpectralDoctorSnapshot {
    let edges = service_dependency_edges(children);
    let mut monitor = SpectralHealthMonitor::new(SpectralThresholds::default());
    let report = monitor.analyze(children.len(), &edges);
    let early_warning = report
        .bifurcation
        .as_ref()
        .map_or(EarlyWarningSeverity::None, |warning| warning.severity);
    ServiceSpectralDoctorSnapshot {
        state: spectral_state(&report.classification, early_warning),
        classification: report.classification.to_string(),
        fiedler_micro_units: finite_micro_units(report.decomposition.fiedler_value),
        spectral_gap_bps: finite_bps(report.decomposition.spectral_gap),
        bottleneck_count: report.bottlenecks.len(),
        early_warning: early_warning_label(early_warning),
    }
}

fn service_caps_snapshot(child_count: usize) -> ServiceCapsDoctorSnapshot {
    ServiceCapsDoctorSnapshot {
        restart_policy: "rest_for_one",
        child_count,
        restart_max: SERVICE_RESTART_MAX,
        restart_window_seconds: SERVICE_RESTART_WINDOW.as_secs(),
    }
}

/// Build the doctor service/lane health snapshot without touching service files,
/// Oracle, audit records, or profile configuration.
#[allow(clippy::arc_with_non_send_sync)]
pub fn service_app_doctor_snapshot() -> Result<ServiceAppDoctorSnapshot, ServiceAppStartError> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .map_err(ServiceAppStartError::RuntimeBuild)?;

    // block-on-boundary: one-shot local AppSpec introspection for doctor output.
    runtime.block_on(async move {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = asupersync::Cx::current().ok_or(ServiceAppStartError::MissingCurrentCx)?;
        let spec = oraclemcp_service_app_spec(
            None,
            dormant_service_child(),
            dormant_service_child(),
            dormant_service_child(),
            dormant_service_child(),
            dormant_service_child(),
        );
        let _handle = spec
            .start(&mut state, &cx, root)
            .map_err(ServiceAppStartError::AppStart)?;
        let inspector = TaskInspector::new(Arc::new(state), None);
        let summary = TaskSummaryWire::from(inspector.summary());
        let active_tasks = summary.total_tasks.saturating_sub(summary.completed);

        let cancellation = CancellationExplanation {
            kind: CancelKind::User,
            message: Some("no cancellation observed in doctor snapshot".to_owned()),
            propagation_path: Vec::new(),
        };
        let children = service_child_doctor_snapshots();
        let caps = service_caps_snapshot(children.len());
        Ok(ServiceAppDoctorSnapshot {
            source: "local_appspec_introspection",
            app: SERVICE_APP_NAME,
            spectral: service_spectral_snapshot(&children),
            task_inspector: ServiceTaskDoctorSnapshot {
                summary,
                active_tasks,
            },
            cancellation: ServiceCancellationDoctorSnapshot {
                observed: false,
                kind: cancellation.kind.to_string(),
                message: cancellation.message,
                propagation_path_len: cancellation.propagation_path.len(),
            },
            configured_caps: caps.clone(),
            effective_caps: caps,
            children,
        })
    })
}

fn service_child<F>(kind: ServiceAppChild, start: F) -> ChildSpec
where
    F: ChildStart + 'static,
{
    let mut spec = ChildSpec::new(kind.name(), start)
        .with_restart(kind.supervision_strategy())
        .with_shutdown_budget(Budget::INFINITE)
        .with_registration(NameRegistrationPolicy::Register {
            name: kind.name().to_owned(),
            collision: NameCollisionPolicy::Fail,
        });
    for dependency in kind.dependencies() {
        spec = spec.depends_on(*dependency);
    }
    spec
}

/// Build the persistent-service AppSpec from concrete child start factories.
///
/// The tree uses `RestForOne` at the root because later children depend on
/// earlier service obligations: audit before all visible service work, the lane
/// registry before dashboard/transport, and transport last. Per-child
/// `SupervisionStrategy` remains separate from that structural policy.
#[must_use]
pub fn oraclemcp_service_app_spec<A, M, L, D, T>(
    registry: Option<RegistryHandle>,
    audit_chain_writer: A,
    metrics_health_collector: M,
    lane_registry_supervisor: L,
    dashboard_api: D,
    transport: T,
) -> AppSpec
where
    A: ChildStart + 'static,
    M: ChildStart + 'static,
    L: ChildStart + 'static,
    D: ChildStart + 'static,
    T: ChildStart + 'static,
{
    let spec = AppSpec::new(SERVICE_APP_NAME)
        .with_restart_policy(RestartPolicy::RestForOne)
        .with_tie_break(StartTieBreak::InsertionOrder)
        .child(service_child(
            ServiceAppChild::AuditChainWriter,
            audit_chain_writer,
        ))
        .child(service_child(
            ServiceAppChild::MetricsHealthCollector,
            metrics_health_collector,
        ))
        .child(service_child(
            ServiceAppChild::LaneRegistrySupervisor,
            lane_registry_supervisor,
        ))
        .child(service_child(ServiceAppChild::DashboardApi, dashboard_api))
        .child(service_child(ServiceAppChild::Transport, transport));

    match registry {
        Some(registry) => spec.with_registry(registry),
        None => spec,
    }
}

/// Runtime-owned persistent-service AppHandle obligation.
///
/// The current production transport still uses the native blocking listener,
/// but service mode now owns and resolves an AppHandle that matches the
/// persistent topology. This keeps the supervision-tree obligation explicit
/// while the transport accept loop is migrated into a concrete child.
#[derive(Debug)]
pub struct ServiceAppRuntime {
    state: RuntimeState,
    handle: AppHandle,
    app_region: RegionId,
    transport_shutdown: Option<Arc<AtomicBool>>,
    transport_join: Arc<Mutex<Option<JoinHandle<std::io::Result<()>>>>>,
}

impl ServiceAppRuntime {
    /// Application name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.handle.name()
    }

    /// Root region owned by the AppHandle.
    #[must_use]
    pub fn root_region(&self) -> RegionId {
        self.app_region
    }

    /// Ask the transport child to stop accepting.
    pub fn request_shutdown(&self) {
        if let Some(shutdown) = &self.transport_shutdown {
            shutdown.store(true, Ordering::SeqCst);
        }
    }

    /// Wait for the transport child thread, if this AppSpec owns one.
    pub fn wait_for_transport(&mut self) -> std::io::Result<()> {
        let handle = self.transport_join.lock().take();
        let Some(handle) = handle else {
            return Ok(());
        };
        match handle.join() {
            Ok(result) => result,
            Err(_) => Err(std::io::Error::other("service transport thread panicked")),
        }
    }

    /// Request service shutdown and drive the app region to quiescence.
    pub fn stop_and_join(&mut self) -> Result<(), ServiceAppStopError> {
        self.request_shutdown();
        self.wait_for_transport()
            .map_err(ServiceAppStopError::Transport)?;
        self.handle
            .stop(&mut self.state)
            .map_err(ServiceAppStopError::AppStop)?;
        close_app_region(&mut self.state, self.app_region);
        self.handle
            .join(&self.state)
            .map_err(ServiceAppStopError::AppStop)?;
        Ok(())
    }
}

/// Bound service transport owned by the AppSpec transport child.
pub enum ServiceTransport {
    /// Plain HTTP Streamable MCP listener.
    Http {
        /// Bound TCP listener. It is cloned for the transport thread at start.
        listener: TcpListener,
        /// MCP server surface.
        server: OracleMcpServer,
        /// HTTP transport configuration.
        config: HttpTransportConfig,
    },
    /// TLS-terminating HTTPS Streamable MCP listener.
    Https {
        /// Bound TCP listener. It is cloned for the transport thread at start.
        listener: TcpListener,
        /// MCP server surface.
        server: OracleMcpServer,
        /// HTTP transport configuration.
        config: HttpTransportConfig,
        /// TLS server config.
        tls: Arc<TlsServerConfig>,
    },
    /// Ordinary HTTPS plus an independently bounded, mandatory-mTLS control
    /// listener. Both accept loops share one shutdown flag but no admission
    /// permits.
    HttpsWithControl {
        /// Ordinary MCP HTTPS listener.
        listener: TcpListener,
        /// Dedicated control HTTPS listener.
        control_listener: TcpListener,
        /// MCP and operator server surface shared by both listeners.
        server: OracleMcpServer,
        /// Ordinary HTTP transport configuration.
        config: HttpTransportConfig,
        /// Control-only transport configuration and authenticated reserve.
        control_config: Box<HttpTransportConfig>,
        /// Bounded pre-certificate handshake admission.
        control_preauth_admission: Arc<AdmissionController>,
        /// Mandatory-mTLS server configuration shared by both listeners.
        tls: Arc<TlsServerConfig>,
    },
}

impl ServiceTransport {
    fn try_clone_for_thread(&self) -> std::io::Result<Self> {
        match self {
            Self::Http {
                listener,
                server,
                config,
            } => Ok(Self::Http {
                listener: listener.try_clone()?,
                server: server.clone(),
                config: config.clone(),
            }),
            Self::Https {
                listener,
                server,
                config,
                tls,
            } => Ok(Self::Https {
                listener: listener.try_clone()?,
                server: server.clone(),
                config: config.clone(),
                tls: Arc::clone(tls),
            }),
            Self::HttpsWithControl {
                listener,
                control_listener,
                server,
                config,
                control_config,
                control_preauth_admission,
                tls,
            } => Ok(Self::HttpsWithControl {
                listener: listener.try_clone()?,
                control_listener: control_listener.try_clone()?,
                server: server.clone(),
                config: config.clone(),
                control_config: Box::new((**control_config).clone()),
                control_preauth_admission: Arc::clone(control_preauth_admission),
                tls: Arc::clone(tls),
            }),
        }
    }

    fn serve(self, shutdown: Arc<AtomicBool>) -> std::io::Result<()> {
        match self {
            Self::Http {
                listener,
                server,
                config,
            } => serve_http_until(listener, server, &config, shutdown),
            Self::Https {
                listener,
                server,
                config,
                tls,
            } => serve_https_until(listener, server, &config, tls, shutdown),
            Self::HttpsWithControl {
                listener,
                control_listener,
                server,
                config,
                control_config,
                control_preauth_admission,
                tls,
            } => {
                let control_shutdown = Arc::clone(&shutdown);
                let control_server = server.clone();
                let control_tls = Arc::clone(&tls);
                let control_handle = std::thread::Builder::new()
                    .name("oraclemcp-control-transport".to_owned())
                    .spawn(move || {
                        let result = serve_control_https_until(
                            control_listener,
                            control_server,
                            &control_config,
                            control_tls,
                            control_preauth_admission,
                            Arc::clone(&control_shutdown),
                        );
                        control_shutdown.store(true, Ordering::SeqCst);
                        result
                    })?;
                let ordinary_result =
                    serve_https_until(listener, server, &config, tls, Arc::clone(&shutdown));
                shutdown.store(true, Ordering::SeqCst);
                let control_result = control_handle
                    .join()
                    .map_err(|_| std::io::Error::other("control transport thread panicked"))?;
                ordinary_result.and(control_result)
            }
        }
    }
}

/// Error starting the service AppSpec obligation.
#[derive(Debug)]
pub enum ServiceAppStartError {
    /// The helper runtime used to obtain a production `Cx` could not be built.
    RuntimeBuild(asupersync::Error),
    /// The service AppSpec failed during compile or spawn.
    AppStart(AppStartError),
    /// `Runtime::block_on` did not install the ambient `Cx` promised by asupersync.
    MissingCurrentCx,
}

impl std::fmt::Display for ServiceAppStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuntimeBuild(e) => write!(f, "service helper runtime build failed: {e}"),
            Self::AppStart(e) => write!(f, "{e}"),
            Self::MissingCurrentCx => {
                write!(f, "service helper runtime did not install a current Cx")
            }
        }
    }
}

impl std::error::Error for ServiceAppStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RuntimeBuild(e) => Some(e),
            Self::AppStart(e) => Some(e),
            Self::MissingCurrentCx => None,
        }
    }
}

/// Error stopping the service AppSpec obligation.
#[derive(Debug)]
pub enum ServiceAppStopError {
    /// Transport child failed or panicked while stopping.
    Transport(std::io::Error),
    /// AppHandle stop/join failed.
    AppStop(AppStopError),
}

impl std::fmt::Display for ServiceAppStopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "service transport shutdown failed: {e}"),
            Self::AppStop(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ServiceAppStopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::AppStop(e) => Some(e),
        }
    }
}

fn dormant_service_child() -> impl ChildStart {
    move |scope: &asupersync::cx::Scope<'static, asupersync::types::policy::FailFast>,
          state: &mut RuntimeState,
          _cx: &asupersync::Cx| {
        state
            .create_task(scope.region_id(), scope.budget(), async {})
            .map(|(_, stored)| stored.task_id())
    }
}

/// Start the persistent service AppSpec and return the handle obligation.
///
/// Production callers must keep the returned value alive for the whole service
/// lifetime and call [`ServiceAppRuntime::stop_and_join`] during shutdown.
pub fn start_oraclemcp_service_app(
    registry: Option<RegistryHandle>,
) -> Result<ServiceAppRuntime, ServiceAppStartError> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .map_err(ServiceAppStartError::RuntimeBuild)?;

    // block-on-boundary: service AppSpec bootstrap on its owning runtime.
    runtime.block_on(async move {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = asupersync::Cx::current().ok_or(ServiceAppStartError::MissingCurrentCx)?;
        let spec = oraclemcp_service_app_spec(
            registry,
            dormant_service_child(),
            dormant_service_child(),
            dormant_service_child(),
            dormant_service_child(),
            dormant_service_child(),
        );
        let handle = spec
            .start(&mut state, &cx, root)
            .map_err(ServiceAppStartError::AppStart)?;
        let app_region = handle.root_region();
        Ok(ServiceAppRuntime {
            state,
            handle,
            app_region,
            transport_shutdown: None,
            transport_join: Arc::new(Mutex::new(None)),
        })
    })
}

fn spawn_error_for_transport(reason: impl Into<String>) -> asupersync::runtime::SpawnError {
    asupersync::runtime::SpawnError::NameRegistrationFailed {
        name: SERVICE_CHILD_TRANSPORT.to_owned(),
        reason: reason.into(),
    }
}

fn transport_service_child(
    transport: ServiceTransport,
    shutdown: Arc<AtomicBool>,
    join_slot: Arc<Mutex<Option<JoinHandle<std::io::Result<()>>>>>,
) -> impl ChildStart {
    move |scope: &asupersync::cx::Scope<'static, asupersync::types::policy::FailFast>,
          state: &mut RuntimeState,
          _cx: &asupersync::Cx| {
        let (task_id, _stored) = state.create_task(scope.region_id(), scope.budget(), async {})?;
        let transport = transport
            .try_clone_for_thread()
            .map_err(|e| spawn_error_for_transport(format!("listener clone failed: {e}")))?;
        let shutdown = Arc::clone(&shutdown);
        let handle = std::thread::Builder::new()
            .name("oraclemcp-transport".to_owned())
            .spawn(move || transport.serve(shutdown))
            .map_err(|e| spawn_error_for_transport(format!("thread spawn failed: {e}")))?;
        *join_slot.lock() = Some(handle);
        Ok(task_id)
    }
}

/// Start the persistent service AppSpec with a transport child that owns the
/// HTTP/HTTPS accept loop.
pub fn start_oraclemcp_service_app_with_transport(
    registry: Option<RegistryHandle>,
    transport: ServiceTransport,
    shutdown: Arc<AtomicBool>,
) -> Result<ServiceAppRuntime, ServiceAppStartError> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .map_err(ServiceAppStartError::RuntimeBuild)?;
    let transport_join = Arc::new(Mutex::new(None));
    let transport_child = transport_service_child(
        transport,
        Arc::clone(&shutdown),
        Arc::clone(&transport_join),
    );

    // block-on-boundary: service AppSpec bootstrap with transport child.
    runtime.block_on(async move {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = asupersync::Cx::current().ok_or(ServiceAppStartError::MissingCurrentCx)?;
        let spec = oraclemcp_service_app_spec(
            registry,
            dormant_service_child(),
            dormant_service_child(),
            dormant_service_child(),
            dormant_service_child(),
            transport_child,
        );
        let handle = spec
            .start(&mut state, &cx, root)
            .map_err(ServiceAppStartError::AppStart)?;
        let app_region = handle.root_region();
        Ok(ServiceAppRuntime {
            state,
            handle,
            app_region,
            transport_shutdown: Some(shutdown),
            transport_join,
        })
    })
}

fn close_app_region(state: &mut RuntimeState, region: RegionId) {
    let _ = state.cancel_request(region, &asupersync::types::CancelReason::shutdown(), None);
    let mut previous_region_count = usize::MAX;
    while state.region(region).is_some() && state.regions_len() != previous_region_count {
        previous_region_count = state.regions_len();
        let region_ids: Vec<_> = state.regions_iter().map(|(_, region)| region.id).collect();
        let task_ids: Vec<_> = region_ids
            .iter()
            .flat_map(|region_id| {
                state
                    .region(*region_id)
                    .map(asupersync::record::RegionRecord::task_ids)
                    .unwrap_or_default()
            })
            .collect();
        for task_id in task_ids {
            let _ = state.complete_task(
                task_id,
                asupersync::Outcome::Cancelled(asupersync::types::CancelReason::shutdown()),
            );
            let _ = state.task_completed(task_id);
        }
        for region_id in region_ids {
            state.advance_region_state(region_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use asupersync::cx::{NameRegistry, RegistryHandle};
    use asupersync::runtime::state::RuntimeState;
    use asupersync::types::TaskId;
    use asupersync::{Cx, Outcome};
    use oraclemcp_guard::OperatingLevel;
    use parking_lot::Mutex;
    use serde_json::Value;

    use crate::capabilities::{CapabilitiesReport, FeatureTiers};
    use crate::server::{DispatchContext, DispatchFuture, ToolDispatch};
    use crate::tools::ToolRegistry;

    struct NoopDispatch;

    impl ToolDispatch for NoopDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async { Outcome::Ok(serde_json::json!({})) })
        }
    }

    fn test_server() -> OracleMcpServer {
        let report = CapabilitiesReport::new(
            "0.1.0",
            vec![],
            OperatingLevel::ReadOnly,
            FeatureTiers {
                live_db: false,
                engine: true,
                http_transport: true,
            },
        );
        OracleMcpServer::new("0.1.0", ToolRegistry::new(), report, Arc::new(NoopDispatch))
    }

    fn recording_child(
        child: ServiceAppChild,
        log: Arc<Mutex<Vec<&'static str>>>,
        saw_registry: Arc<Mutex<Vec<&'static str>>>,
    ) -> impl ChildStart {
        move |scope: &asupersync::cx::Scope<'static, asupersync::types::policy::FailFast>,
              state: &mut RuntimeState,
              cx: &Cx| {
            log.lock().push(child.name());
            if cx.registry_handle().is_some() {
                saw_registry.lock().push(child.name());
            }
            state
                .create_task(scope.region_id(), scope.budget(), async {})
                .map(|(_, stored)| stored.task_id())
        }
    }

    #[test]
    fn appspec_topology_starts_in_dep_order_and_drains() {
        let expected: Vec<_> = service_app_start_order()
            .iter()
            .map(|child| child.name())
            .collect();
        let log = Arc::new(Mutex::new(Vec::new()));
        let saw_registry = Arc::new(Mutex::new(Vec::new()));
        let registry = RegistryHandle::new(Arc::new(NameRegistry::new()));

        let spec = oraclemcp_service_app_spec(
            Some(registry),
            recording_child(
                ServiceAppChild::AuditChainWriter,
                Arc::clone(&log),
                Arc::clone(&saw_registry),
            ),
            recording_child(
                ServiceAppChild::MetricsHealthCollector,
                Arc::clone(&log),
                Arc::clone(&saw_registry),
            ),
            recording_child(
                ServiceAppChild::LaneRegistrySupervisor,
                Arc::clone(&log),
                Arc::clone(&saw_registry),
            ),
            recording_child(
                ServiceAppChild::DashboardApi,
                Arc::clone(&log),
                Arc::clone(&saw_registry),
            ),
            recording_child(
                ServiceAppChild::Transport,
                Arc::clone(&log),
                Arc::clone(&saw_registry),
            ),
        );
        let compiled = spec.compile().expect("service app topology compiles");
        let supervisor = compiled.compiled_supervisor();
        assert_eq!(supervisor.restart_policy, RestartPolicy::RestForOne);
        assert_eq!(supervisor.child_start_order_names(), expected);
        let stop_order: Vec<_> = expected.iter().rev().copied().collect();
        assert_eq!(supervisor.child_stop_order_names(), stop_order);
        let registry_plan = supervisor
            .restart_plan_for(SERVICE_CHILD_LANE_REGISTRY_SUPERVISOR)
            .expect("lane registry child is present");
        assert_eq!(
            registry_plan
                .restart_order
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>(),
            vec![
                SERVICE_CHILD_LANE_REGISTRY_SUPERVISOR,
                SERVICE_CHILD_DASHBOARD_API,
                SERVICE_CHILD_TRANSPORT,
            ],
            "RestForOne restarts the lane registry and later dependents only",
        );

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(root, TaskId::testing_default(), Budget::INFINITE);
        let mut handle = compiled
            .start(&mut state, &cx, root)
            .expect("service app starts");
        assert_eq!(&*log.lock(), &expected);
        assert_eq!(&*saw_registry.lock(), &expected);

        let app_region = handle.root_region();
        handle.stop(&mut state).expect("service app stop begins");
        close_app_region(&mut state, app_region);
        handle.join(&state).expect("service app joins after drain");
    }

    #[test]
    fn service_app_runtime_resolves_app_handle_obligation() {
        let mut runtime = start_oraclemcp_service_app(None).expect("service app starts");

        assert_eq!(runtime.name(), SERVICE_APP_NAME);
        let _root_region = runtime.root_region();
        runtime
            .stop_and_join()
            .expect("service app stops and joins");
    }

    #[test]
    fn doctor_snapshot_surfaces_spectral_task_and_cancellation_health() {
        let snapshot = service_app_doctor_snapshot().expect("doctor snapshot builds");

        assert_eq!(snapshot.app, SERVICE_APP_NAME);
        assert_eq!(snapshot.children.len(), service_app_start_order().len());
        assert!(matches!(
            snapshot.spectral.state,
            "none" | "watch" | "warning" | "critical"
        ));
        assert!(snapshot.task_inspector.summary.total_tasks >= snapshot.children.len());
        assert_eq!(
            snapshot.task_inspector.active_tasks,
            snapshot
                .task_inspector
                .summary
                .total_tasks
                .saturating_sub(snapshot.task_inspector.summary.completed)
        );
        assert!(!snapshot.cancellation.observed);
        assert_eq!(snapshot.cancellation.kind, "user");
        assert_eq!(snapshot.configured_caps, snapshot.effective_caps);
    }

    #[test]
    fn service_app_transport_child_owns_http_accept_loop() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let shutdown = Arc::new(AtomicBool::new(false));
        let transport = ServiceTransport::Http {
            listener,
            server: test_server(),
            config: HttpTransportConfig::default(),
        };
        let mut runtime =
            start_oraclemcp_service_app_with_transport(None, transport, Arc::clone(&shutdown))
                .expect("service app starts with transport child");

        runtime
            .stop_and_join()
            .expect("transport child stops and app joins");
        assert!(shutdown.load(Ordering::SeqCst));
    }
}
