//! Safe config draft/apply primitives shared by CLI setup and dashboard flows.
//!
//! The backend never diffs raw TOML. It validates drafts with the same strict
//! loader used at startup, exposes only redacted metadata, writes a verbatim
//! timestamped backup, then replaces the target with same-directory
//! write-temp-and-rename while holding the service lock.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_config::{ConfigError, ConfigReloadPlan, OracleMcpConfig, ProfileMetadata};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::file_store::{FileStore, FileStoreError};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Config-ops backend error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigOpsError {
    /// Strict config parsing or validation failed.
    #[error("config validation failed: {0}")]
    Config(#[from] ConfigError),
    /// File-store lock or state handling failed.
    #[error("{0}")]
    FileStore(#[from] FileStoreError),
    /// An I/O operation failed.
    #[error("config-ops io error: {0}")]
    Io(String),
    /// Config TOML was not valid UTF-8.
    #[error("config file {path} is not valid UTF-8")]
    InvalidUtf8 {
        /// Path being read.
        path: PathBuf,
    },
    /// Target path shape is unsafe for atomic replacement.
    #[error("invalid config target path: {0}")]
    InvalidTargetPath(String),
    /// The on-disk target changed after the draft was staged.
    #[error("config target changed after draft was staged")]
    CurrentChanged {
        /// Hash captured during staging.
        expected_sha256: String,
        /// Hash read immediately before apply.
        actual_sha256: String,
    },
    /// The requested rollback id is unknown to this process.
    #[error("unknown config rollback id")]
    UnknownRollbackId,
}

/// Redacted before/after field change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigFieldChange {
    /// Dot-separated path in the redacted config snapshot.
    pub path: String,
    /// Redacted old value.
    pub before: Value,
    /// Redacted new value.
    pub after: Value,
}

/// Redacted config diff. This is safe for operator UI/JSON output.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ConfigRedactedDiff {
    /// Stable, sorted changes over allow-listed metadata only.
    pub changes: Vec<ConfigFieldChange>,
}

/// Safe preview for a staged config draft.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigDraftPreview {
    /// File that would be replaced.
    pub target_path: PathBuf,
    /// Timestamped backup path written before replacement.
    pub backup_path: PathBuf,
    /// Whether the target existed when the draft was staged.
    pub original_existed: bool,
    /// SHA-256 of the current target bytes.
    pub current_sha256: String,
    /// SHA-256 of the draft bytes.
    pub draft_sha256: String,
    /// Redacted metadata diff.
    pub redacted_diff: ConfigRedactedDiff,
    /// Conservative S5 reload/drain plan between current and draft configs.
    pub reload_plan: ConfigReloadPlan,
}

/// Staged config draft. Raw TOML is deliberately private and not serializable.
pub struct ConfigDraftPlan {
    preview: ConfigDraftPreview,
    current_bytes: Vec<u8>,
    draft_bytes: Vec<u8>,
}

impl fmt::Debug for ConfigDraftPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigDraftPlan")
            .field("preview", &self.preview)
            .field(
                "current_bytes",
                &format_args!("<{} bytes>", self.current_bytes.len()),
            )
            .field(
                "draft_bytes",
                &format_args!("<{} bytes>", self.draft_bytes.len()),
            )
            .finish()
    }
}

impl ConfigDraftPlan {
    /// Safe preview of the staged draft.
    #[must_use]
    pub fn preview(&self) -> &ConfigDraftPreview {
        &self.preview
    }

    /// Reload plan for this draft.
    #[must_use]
    pub fn reload_plan(&self) -> &ConfigReloadPlan {
        &self.preview.reload_plan
    }
}

/// Result after applying a staged config draft.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigApplyReport {
    /// File that was replaced.
    pub target_path: PathBuf,
    /// Verbatim backup written before replacement.
    pub backup_path: PathBuf,
    /// Whether the target existed before apply.
    pub original_existed: bool,
    /// SHA-256 restored by rollback.
    pub backup_sha256: String,
    /// SHA-256 now present at the target.
    pub applied_sha256: String,
    /// Reload/drain plan that should be handed to S5.
    pub reload_plan: ConfigReloadPlan,
}

/// Result after rolling back an applied config draft.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigRollbackReport {
    /// File restored from the backup.
    pub target_path: PathBuf,
    /// Backup source used for restoration.
    pub backup_path: PathBuf,
    /// SHA-256 now present at the target.
    pub restored_sha256: String,
}

/// Redacted current-config status for the operator UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigOpsStatus {
    /// File managed by this config-ops service.
    pub target_path: PathBuf,
    /// Whether the target exists on disk.
    pub target_exists: bool,
    /// SHA-256 of the current target bytes.
    pub current_sha256: String,
    /// Configured default profile, if any.
    pub default_profile: Option<String>,
    /// Redacted, agent-safe profile metadata.
    pub profiles: Vec<ProfileMetadata>,
}

/// Result of asking the live service to consume a config reload plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigReloadApplyReport {
    /// `applied`, `restart_required`, or `not_configured`.
    pub status: String,
    /// Whether the config transition is hot-reloadable by design.
    pub hot_reloadable: bool,
    /// Restart-required reasons for non-hot transitions.
    pub restart_required: Vec<String>,
    /// Profiles currently marked draining by the live service.
    pub draining_profiles: Vec<String>,
    /// Operator-facing summary.
    pub message: String,
}

impl ConfigReloadApplyReport {
    fn restart_required(plan: &ConfigReloadPlan) -> Self {
        Self {
            status: "restart_required".to_owned(),
            hot_reloadable: false,
            restart_required: plan
                .restart_required
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect(),
            draining_profiles: Vec::new(),
            message: "config file was updated; restart the service to apply non-profile changes"
                .to_owned(),
        }
    }

    fn not_configured(plan: &ConfigReloadPlan) -> Self {
        Self {
            status: "not_configured".to_owned(),
            hot_reloadable: plan.hot_reloadable,
            restart_required: plan
                .restart_required
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect(),
            draining_profiles: plan.draining_profiles(),
            message: "config file was updated; no live reload applier is installed".to_owned(),
        }
    }
}

/// Live service hook that consumes validated reload plans.
pub trait ConfigReloadApplier: Send + Sync {
    /// Apply a hot-reloadable plan to live process state.
    fn apply_config_reload_plan(&self, plan: &ConfigReloadPlan) -> ConfigReloadApplyReport;
}

/// Apply result retained for safe one-click rollback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigApplyOutcome {
    /// File write report.
    pub apply: ConfigApplyReport,
    /// Live reload/drain report.
    pub reload: ConfigReloadApplyReport,
    /// Opaque id accepted by [`ConfigOpsService::rollback`].
    pub rollback_id: String,
}

/// Rollback result plus live reload/drain report for the restored config.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigRollbackOutcome {
    /// File restore report.
    pub rollback: ConfigRollbackReport,
    /// Live reload/drain report for the restored config.
    pub reload: ConfigReloadApplyReport,
}

/// Shared config-ops backend.
pub struct ConfigOpsBackend {
    store: FileStore,
}

impl ConfigOpsBackend {
    /// Open the backend using the default service file-store root.
    pub fn open_default() -> Result<Self, ConfigOpsError> {
        Ok(Self::new(FileStore::open_default()?))
    }

    /// Build the backend from an existing service file-store.
    #[must_use]
    pub fn new(store: FileStore) -> Self {
        Self { store }
    }

    /// Stage and validate a draft for `target_path`.
    ///
    /// The current target is treated as an empty config when absent. Both
    /// current and draft TOML are parsed by [`OracleMcpConfig::from_toml_str`].
    pub fn stage_config_draft(
        &self,
        target_path: impl AsRef<Path>,
        draft_toml: &str,
    ) -> Result<ConfigDraftPlan, ConfigOpsError> {
        let target_path = normalize_target_path(target_path.as_ref())?;
        let current_bytes = read_or_empty(&target_path)?;
        let current_toml = bytes_to_toml(&target_path, &current_bytes)?;
        let current = OracleMcpConfig::from_toml_str(current_toml)?;
        let draft = OracleMcpConfig::from_toml_str(draft_toml)?;
        let before = redacted_snapshot(&current);
        let after = redacted_snapshot(&draft);
        let reload_plan = ConfigReloadPlan::between(&current, &draft);
        let draft_bytes = draft_toml.as_bytes().to_vec();
        let preview = ConfigDraftPreview {
            backup_path: backup_path_for(&target_path)?,
            original_existed: target_path.exists(),
            current_sha256: oraclemcp_audit::sha256_hex(&current_bytes),
            draft_sha256: oraclemcp_audit::sha256_hex(&draft_bytes),
            redacted_diff: redacted_diff(&before, &after),
            reload_plan,
            target_path,
        };
        Ok(ConfigDraftPlan {
            preview,
            current_bytes,
            draft_bytes,
        })
    }

    /// Apply a staged draft: backup current bytes, atomically replace target,
    /// then revalidate the installed file with the strict config loader.
    pub fn apply_config_draft(
        &self,
        plan: &ConfigDraftPlan,
    ) -> Result<ConfigApplyReport, ConfigOpsError> {
        let lock = self.store.acquire_service_lock("config-ops")?;
        let current_bytes = read_or_empty(&plan.preview.target_path)?;
        let actual_sha256 = oraclemcp_audit::sha256_hex(&current_bytes);
        if actual_sha256 != plan.preview.current_sha256 {
            return Err(ConfigOpsError::CurrentChanged {
                expected_sha256: plan.preview.current_sha256.clone(),
                actual_sha256,
            });
        }
        write_backup(&plan.preview.backup_path, &current_bytes)?;
        write_atomic_path(&plan.preview.target_path, &plan.draft_bytes)?;
        validate_target(&plan.preview.target_path)?;
        drop(lock);

        Ok(ConfigApplyReport {
            target_path: plan.preview.target_path.clone(),
            backup_path: plan.preview.backup_path.clone(),
            original_existed: plan.preview.original_existed,
            backup_sha256: plan.preview.current_sha256.clone(),
            applied_sha256: plan.preview.draft_sha256.clone(),
            reload_plan: plan.preview.reload_plan.clone(),
        })
    }

    /// Restore a target from an apply report's backup, then revalidate.
    ///
    /// When the original target did not exist, the backup is the empty config;
    /// rollback writes that empty config back rather than deleting the file.
    pub fn rollback_applied_config(
        &self,
        report: &ConfigApplyReport,
    ) -> Result<ConfigRollbackReport, ConfigOpsError> {
        let lock = self.store.acquire_service_lock("config-ops")?;
        let backup =
            fs::read(&report.backup_path).map_err(|e| ConfigOpsError::Io(e.to_string()))?;
        bytes_to_toml(&report.backup_path, &backup)
            .and_then(|toml| OracleMcpConfig::from_toml_str(toml).map_err(ConfigOpsError::from))?;
        write_atomic_path(&report.target_path, &backup)?;
        validate_target(&report.target_path)?;
        drop(lock);

        Ok(ConfigRollbackReport {
            target_path: report.target_path.clone(),
            backup_path: report.backup_path.clone(),
            restored_sha256: oraclemcp_audit::sha256_hex(&backup),
        })
    }
}

/// Operator-facing config workflow service.
///
/// Raw draft TOML is never stored in this service. The browser submits the
/// draft for preview and again for apply; only redacted previews and apply
/// reports are serializable.
pub struct ConfigOpsService {
    backend: ConfigOpsBackend,
    target_path: PathBuf,
    reload_applier: Option<Arc<dyn ConfigReloadApplier>>,
    rollback_reports: Mutex<BTreeMap<String, ConfigApplyReport>>,
}

impl ConfigOpsService {
    /// Build a service for a single operator-controlled target file.
    #[must_use]
    pub fn new(
        backend: ConfigOpsBackend,
        target_path: PathBuf,
        reload_applier: Option<Arc<dyn ConfigReloadApplier>>,
    ) -> Self {
        Self {
            backend,
            target_path,
            reload_applier,
            rollback_reports: Mutex::new(BTreeMap::new()),
        }
    }

    /// Current target status, redacted for UI/protocol use.
    pub fn status(&self) -> Result<ConfigOpsStatus, ConfigOpsError> {
        let current_bytes = read_or_empty(&self.target_path)?;
        let current_toml = bytes_to_toml(&self.target_path, &current_bytes)?;
        let current = OracleMcpConfig::from_toml_str(current_toml)?;
        let mut profiles = current.list_profiles();
        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(ConfigOpsStatus {
            target_path: self.target_path.clone(),
            target_exists: self.target_path.exists(),
            current_sha256: oraclemcp_audit::sha256_hex(&current_bytes),
            default_profile: current.default_profile,
            profiles,
        })
    }

    /// Stage a draft and return a redacted preview.
    pub fn stage(&self, draft_toml: &str) -> Result<ConfigDraftPreview, ConfigOpsError> {
        self.backend
            .stage_config_draft(&self.target_path, draft_toml)
            .map(|plan| plan.preview().clone())
    }

    /// Apply a draft after validating that the previewed base hash still
    /// matches, then ask the live service to consume the reload plan.
    pub fn apply(
        &self,
        draft_toml: &str,
        expected_current_sha256: Option<&str>,
    ) -> Result<ConfigApplyOutcome, ConfigOpsError> {
        let plan = self
            .backend
            .stage_config_draft(&self.target_path, draft_toml)?;
        if let Some(expected) = expected_current_sha256
            .map(str::trim)
            .filter(|s| !s.is_empty())
            && expected != plan.preview().current_sha256
        {
            return Err(ConfigOpsError::CurrentChanged {
                expected_sha256: expected.to_owned(),
                actual_sha256: plan.preview().current_sha256.clone(),
            });
        }
        let report = self.backend.apply_config_draft(&plan)?;
        let reload = self.reload_outcome(&report.reload_plan);
        let rollback_id = rollback_id_for(&report);
        self.rollback_reports
            .lock()
            .insert(rollback_id.clone(), report.clone());
        Ok(ConfigApplyOutcome {
            apply: report,
            reload,
            rollback_id,
        })
    }

    /// Restore a previously applied config from its timestamped backup.
    pub fn rollback(&self, rollback_id: &str) -> Result<ConfigRollbackOutcome, ConfigOpsError> {
        let report = self
            .rollback_reports
            .lock()
            .get(rollback_id)
            .cloned()
            .ok_or(ConfigOpsError::UnknownRollbackId)?;
        let reverse_plan = reverse_reload_plan(&report)?;
        let rollback = self.backend.rollback_applied_config(&report)?;
        let reload = self.reload_outcome(&reverse_plan);
        self.rollback_reports.lock().remove(rollback_id);
        Ok(ConfigRollbackOutcome { rollback, reload })
    }

    fn reload_outcome(&self, plan: &ConfigReloadPlan) -> ConfigReloadApplyReport {
        if !plan.hot_reloadable {
            return ConfigReloadApplyReport::restart_required(plan);
        }
        match &self.reload_applier {
            Some(applier) => applier.apply_config_reload_plan(plan),
            None => ConfigReloadApplyReport::not_configured(plan),
        }
    }
}

fn reverse_reload_plan(report: &ConfigApplyReport) -> Result<ConfigReloadPlan, ConfigOpsError> {
    let applied_bytes = read_or_empty(&report.target_path)?;
    let backup = fs::read(&report.backup_path).map_err(|e| ConfigOpsError::Io(e.to_string()))?;
    let applied_toml = bytes_to_toml(&report.target_path, &applied_bytes)?;
    let backup_toml = bytes_to_toml(&report.backup_path, &backup)?;
    let applied = OracleMcpConfig::from_toml_str(applied_toml)?;
    let restored = OracleMcpConfig::from_toml_str(backup_toml)?;
    Ok(ConfigReloadPlan::between(&applied, &restored))
}

fn rollback_id_for(report: &ConfigApplyReport) -> String {
    let material = format!(
        "{}\0{}\0{}\0{}",
        report.target_path.display(),
        report.backup_path.display(),
        report.backup_sha256,
        report.applied_sha256
    );
    let digest = oraclemcp_audit::sha256_hex(material.as_bytes());
    format!("rollback-{}", &digest[..32])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RedactedConfigSnapshot {
    schema_version: u32,
    default_profile: Option<String>,
    http: RedactedHttpSnapshot,
    audit: RedactedAuditSnapshot,
    profiles: Vec<ProfileMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RedactedHttpSnapshot {
    allowed_hosts_count: usize,
    allowed_origins_count: usize,
    json_response: bool,
    stateful: bool,
    stateful_idle_ttl_seconds: u64,
    oauth_enabled: bool,
    oauth_issuer_count: usize,
    oauth_scope_count: usize,
    oauth_secret_ref_configured: bool,
    tls_enabled: bool,
    mtls_required: bool,
    operator_loopback_owner: bool,
    operator_allowed_subject_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RedactedAuditSnapshot {
    path_configured: bool,
    key_ref_configured: bool,
    shipping_configured: bool,
    worm_configured: bool,
    siem_configured: bool,
    siem_auth_ref_configured: bool,
}

fn redacted_snapshot(config: &OracleMcpConfig) -> RedactedConfigSnapshot {
    let mut profiles = config.list_profiles();
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    let oauth = config.http.oauth.as_ref();
    let tls = config.http.tls.as_ref();
    let shipping = config.audit.shipping.as_ref();
    RedactedConfigSnapshot {
        schema_version: config.schema_version,
        default_profile: config.default_profile.clone(),
        http: RedactedHttpSnapshot {
            allowed_hosts_count: config.http.allowed_hosts.len(),
            allowed_origins_count: config.http.allowed_origins.len(),
            json_response: config.http.json_response,
            stateful: config.http.stateful,
            stateful_idle_ttl_seconds: config.http.stateful_idle_ttl_seconds,
            oauth_enabled: oauth.is_some(),
            oauth_issuer_count: oauth.map_or(0, |value| value.allowed_issuers.len()),
            oauth_scope_count: oauth.map_or(0, |value| value.required_scopes.len()),
            oauth_secret_ref_configured: oauth
                .is_some_and(|value| value.hs256_secret_ref.is_some()),
            tls_enabled: tls.is_some_and(|value| value.cert_chain_path.is_some()),
            mtls_required: tls.is_some_and(|value| value.client_ca_path.is_some()),
            operator_loopback_owner: config.http.operator.allow_loopback_owner,
            operator_allowed_subject_count: config.http.operator.allowed_subjects.len(),
        },
        audit: RedactedAuditSnapshot {
            path_configured: config.audit.path.is_some(),
            key_ref_configured: config.audit.key_ref.is_some(),
            shipping_configured: shipping.is_some(),
            worm_configured: shipping.is_some_and(|value| value.worm_path.is_some()),
            siem_configured: shipping.is_some_and(|value| value.siem_endpoint.is_some()),
            siem_auth_ref_configured: shipping
                .is_some_and(|value| value.siem_auth_header_ref.is_some()),
        },
        profiles,
    }
}

fn redacted_diff(
    before: &RedactedConfigSnapshot,
    after: &RedactedConfigSnapshot,
) -> ConfigRedactedDiff {
    let before = serde_json::to_value(before).unwrap_or(Value::Null);
    let after = serde_json::to_value(after).unwrap_or(Value::Null);
    let mut changes = Vec::new();
    diff_value("", &before, &after, &mut changes);
    ConfigRedactedDiff { changes }
}

fn diff_value(path: &str, before: &Value, after: &Value, changes: &mut Vec<ConfigFieldChange>) {
    if before == after {
        return;
    }
    match (before, after) {
        (Value::Object(before_map), Value::Object(after_map)) => {
            let keys: BTreeSet<_> = before_map.keys().chain(after_map.keys()).collect();
            for key in keys {
                let child_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                diff_value(
                    &child_path,
                    before_map.get(key).unwrap_or(&Value::Null),
                    after_map.get(key).unwrap_or(&Value::Null),
                    changes,
                );
            }
        }
        _ => changes.push(ConfigFieldChange {
            path: path.to_owned(),
            before: before.clone(),
            after: after.clone(),
        }),
    }
}

fn normalize_target_path(path: &Path) -> Result<PathBuf, ConfigOpsError> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(ConfigOpsError::InvalidTargetPath(
            path.display().to_string(),
        ));
    }
    if let Some(parent) = path.parent()
        && parent.as_os_str().is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    Ok(path.to_path_buf())
}

fn read_or_empty(path: &Path) -> Result<Vec<u8>, ConfigOpsError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ConfigOpsError::InvalidTargetPath(format!(
                "{} is a symlink",
                path.display()
            )));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(ConfigOpsError::InvalidTargetPath(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(ConfigOpsError::Io(e.to_string())),
    }
    fs::read(path).map_err(|e| ConfigOpsError::Io(e.to_string()))
}

fn bytes_to_toml<'a>(path: &Path, bytes: &'a [u8]) -> Result<&'a str, ConfigOpsError> {
    std::str::from_utf8(bytes).map_err(|_| ConfigOpsError::InvalidUtf8 {
        path: path.to_path_buf(),
    })
}

fn validate_target(path: &Path) -> Result<(), ConfigOpsError> {
    let bytes = fs::read(path).map_err(|e| ConfigOpsError::Io(e.to_string()))?;
    let toml = bytes_to_toml(path, &bytes)?;
    OracleMcpConfig::from_toml_str(toml)?;
    Ok(())
}

fn backup_path_for(target_path: &Path) -> Result<PathBuf, ConfigOpsError> {
    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ConfigOpsError::InvalidTargetPath(target_path.display().to_string()))?;
    Ok(parent.join(format!("{file_name}.backup.{}", timestamp_suffix())))
}

fn timestamp_suffix() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}-{:09}", now.as_secs(), now.subsec_nanos())
}

fn write_backup(path: &Path, bytes: &[u8]) -> Result<(), ConfigOpsError> {
    ensure_parent_dir(path)?;
    let mut file = create_new_private_file(path).map_err(|e| ConfigOpsError::Io(e.to_string()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| ConfigOpsError::Io(e.to_string()))?;
    fsync_dir(path.parent().unwrap_or_else(|| Path::new(".")))
}

fn write_atomic_path(path: &Path, bytes: &[u8]) -> Result<(), ConfigOpsError> {
    ensure_parent_dir(path)?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(ConfigOpsError::InvalidTargetPath(format!(
            "{} is a symlink",
            path.display()
        )));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ConfigOpsError::InvalidTargetPath(path.display().to_string()))?;
    let tmp_path = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        timestamp_suffix()
    ));
    let mut tmp =
        create_new_private_file(&tmp_path).map_err(|e| ConfigOpsError::Io(e.to_string()))?;
    tmp.write_all(bytes)
        .and_then(|()| tmp.sync_all())
        .map_err(|e| ConfigOpsError::Io(e.to_string()))?;
    drop(tmp);
    fs::rename(&tmp_path, path).map_err(|e| ConfigOpsError::Io(e.to_string()))?;
    fsync_dir(parent)
}

fn ensure_parent_dir(path: &Path) -> Result<(), ConfigOpsError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if let Ok(metadata) = fs::symlink_metadata(parent) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ConfigOpsError::InvalidTargetPath(format!(
                "{} is not a safe directory",
                parent.display()
            )));
        }
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(parent)
        .map_err(|e| ConfigOpsError::Io(e.to_string()))
}

fn create_new_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}

fn fsync_dir(path: &Path) -> Result<(), ConfigOpsError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| ConfigOpsError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_config::ReloadProfileAction;

    fn test_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/config-ops-tests")
            .join(format!("{name}-{}-{stamp}", std::process::id()))
    }

    fn backend(name: &str) -> (ConfigOpsBackend, PathBuf) {
        let root = test_root(name);
        let store = FileStore::open(root.join("state")).expect("store");
        (ConfigOpsBackend::new(store), root.join("profiles.toml"))
    }

    #[test]
    fn stages_redacted_diff_without_secret_material() {
        let (backend, target) = backend("redacted-diff");
        let current = r#"
            [http.oauth]
            resource = "https://mcp.example.com/mcp"
            allowed_issuers = ["https://issuer.example.com"]
            authorization_servers = ["https://issuer.example.com"]
            required_scopes = ["oracle:read"]
            hs256_secret_ref = "env:OLD_OAUTH_SECRET"

            [audit]
            key_ref = "env:OLD_AUDIT_KEY"

            [[profiles]]
            name = "prod"
            description = "safe label"
            connect_string = "prod-old:1521/svc"
            username = "OLD_APP"
            credential_ref = "keyring:old/prod"

            [profiles.oci]
            wallet_location = "/secret/wallet"
            wallet_password_ref = "env:OLD_WALLET_PASSWORD"
            "#;
        write_atomic_path(&target, current.as_bytes()).expect("seed current config");

        let draft = r#"
            [http.oauth]
            resource = "https://mcp.example.com/mcp"
            allowed_issuers = ["https://issuer.example.com", "https://issuer2.example.com"]
            authorization_servers = ["https://issuer.example.com"]
            required_scopes = ["oracle:read", "oracle:write"]
            hs256_secret_ref = "env:NEW_OAUTH_SECRET"

            [audit]
            key_ref = "env:NEW_AUDIT_KEY"

            [[profiles]]
            name = "prod"
            description = "safe label changed"
            connect_string = "prod-new:1521/svc"
            username = "NEW_APP"
            credential_ref = "keyring:new/prod"

            [profiles.oci]
            wallet_location = "/new-secret/wallet"
            wallet_password_ref = "env:NEW_WALLET_PASSWORD"
            "#;

        let plan = backend
            .stage_config_draft(&target, draft)
            .expect("stage draft");
        let rendered = serde_json::to_string(plan.preview()).expect("preview json");

        for forbidden in [
            "prod-old:1521/svc",
            "prod-new:1521/svc",
            "OLD_APP",
            "NEW_APP",
            "keyring:old/prod",
            "keyring:new/prod",
            "/secret/wallet",
            "/new-secret/wallet",
            "OLD_WALLET_PASSWORD",
            "NEW_WALLET_PASSWORD",
            "OLD_AUDIT_KEY",
            "NEW_AUDIT_KEY",
            "OLD_OAUTH_SECRET",
            "NEW_OAUTH_SECRET",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "leaked {forbidden}: {rendered}"
            );
        }
        assert!(
            plan.preview()
                .redacted_diff
                .changes
                .iter()
                .any(|change| change.path == "profiles"),
            "{:?}",
            plan.preview().redacted_diff
        );
        assert!(
            plan.preview()
                .redacted_diff
                .changes
                .iter()
                .any(|change| change.path == "http.oauth_issuer_count")
        );
    }

    #[test]
    fn apply_writes_backup_atomic_target_reload_plan_and_rollback() {
        let (backend, target) = backend("apply-rollback");
        let current = r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod-old:1521/svc"
            credential_ref = "env:OLD_PASSWORD"
            "#;
        let draft = r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod-new:1521/svc"
            credential_ref = "env:NEW_PASSWORD"
            "#;
        write_atomic_path(&target, current.as_bytes()).expect("seed current config");
        let plan = backend
            .stage_config_draft(&target, draft)
            .expect("stage draft");
        assert_eq!(
            plan.reload_plan().draining_profiles(),
            vec!["prod".to_owned()]
        );

        let report = backend.apply_config_draft(&plan).expect("apply draft");
        assert_eq!(fs::read_to_string(&target).expect("read target"), draft);
        assert_eq!(
            fs::read_to_string(&report.backup_path).expect("read backup"),
            current
        );
        assert_eq!(
            report.reload_plan.profiles[0].action,
            ReloadProfileAction::Drain
        );
        assert!(report.backup_path.exists());

        let rollback = backend
            .rollback_applied_config(&report)
            .expect("rollback from backup");
        assert_eq!(fs::read_to_string(&target).expect("read target"), current);
        assert_eq!(rollback.restored_sha256, report.backup_sha256);
        OracleMcpConfig::load(Some(&target)).expect("rolled-back config validates");
    }

    #[test]
    fn apply_rejects_current_file_race() {
        let (backend, target) = backend("race");
        let current = r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod-old:1521/svc"
            "#;
        let draft = r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod-new:1521/svc"
            "#;
        write_atomic_path(&target, current.as_bytes()).expect("seed current config");
        let plan = backend
            .stage_config_draft(&target, draft)
            .expect("stage draft");
        write_atomic_path(&target, draft.as_bytes()).expect("racy write");

        let err = backend
            .apply_config_draft(&plan)
            .expect_err("race rejected");
        assert!(matches!(err, ConfigOpsError::CurrentChanged { .. }));
    }

    #[test]
    fn rollback_of_new_file_restores_empty_valid_config_without_delete() {
        let (backend, target) = backend("new-file-rollback");
        let draft = r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            "#;

        let plan = backend
            .stage_config_draft(&target, draft)
            .expect("stage new config");
        assert!(!plan.preview().original_existed);
        let report = backend.apply_config_draft(&plan).expect("apply new config");
        assert_eq!(fs::read_to_string(&target).expect("read target"), draft);
        assert_eq!(
            fs::read_to_string(&report.backup_path).expect("read empty backup"),
            ""
        );

        backend
            .rollback_applied_config(&report)
            .expect("rollback new config");
        assert_eq!(
            fs::read_to_string(&target).expect("read rolled-back target"),
            ""
        );
        OracleMcpConfig::load(Some(&target)).expect("empty rollback config validates");
    }

    #[test]
    fn invalid_draft_is_rejected_by_strict_loader() {
        let (backend, target) = backend("invalid");
        let err = backend
            .stage_config_draft(&target, "nonsense_key = 42")
            .expect_err("invalid draft rejected");
        assert!(matches!(
            err,
            ConfigOpsError::Config(ConfigError::Figment(_))
        ));
    }
}
