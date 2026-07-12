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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oraclemcp_config::{
    ConfigError, ConfigReloadPlan, ConnectionProfile, OracleMcpConfig, ProfileMetadata,
};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::file_store::{FileStore, FileStoreError, ServiceOwner};

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
    /// The apply request did not present a live review token.
    #[error("config apply requires a reviewed preview token")]
    PreviewRequired,
    /// The review token was unknown, already consumed, or bound elsewhere.
    #[error("config preview token is invalid or already consumed")]
    InvalidPreviewToken,
    /// The review token expired before apply.
    #[error("config preview token expired")]
    PreviewExpired,
    /// The submitted draft no longer matches the reviewed bytes.
    #[error("config draft changed after preview")]
    PreviewDraftChanged,
    /// A sensitive preview requires an explicit second confirmation.
    #[error("config preview requires explicit confirmation")]
    PreviewConfirmationRequired,
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

/// Browser/operator preview plus the opaque authority required for apply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigReviewedDraftPreview {
    /// Redacted preview of the exact reviewed draft.
    #[serde(flatten)]
    pub preview: ConfigDraftPreview,
    /// Opaque, single-use review authority. This is never persisted.
    pub preview_token: String,
    /// Safe digest used to correlate preview and apply evidence.
    pub preview_token_sha256: String,
    /// Digest of the exact redacted diff shown to the operator.
    pub redacted_diff_sha256: String,
    /// Wall-clock expiry shown to the operator UI.
    pub preview_expires_unix: u64,
    /// Whether apply requires a deliberate second confirmation.
    pub confirmation_required: bool,
    /// Redacted reasons for the deliberate confirmation step.
    pub confirmation_reasons: Vec<String>,
}

/// Secret-safe evidence binding an apply to its reviewed preview.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigReviewEvidence {
    /// Digest of the single-use token, never the token itself.
    pub preview_token_sha256: String,
    /// Digest of the exact applied draft bytes.
    pub draft_sha256: String,
    /// Digest of the exact redacted diff that was reviewed.
    pub redacted_diff_sha256: String,
}

/// Staged config draft. Raw TOML is deliberately private and not serializable.
pub struct ConfigDraftPlan {
    preview: ConfigDraftPreview,
    current_bytes: Vec<u8>,
    draft_bytes: Vec<u8>,
    current_config: OracleMcpConfig,
    draft_config: OracleMcpConfig,
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

struct AppliedConfigRollback {
    report: ConfigRollbackReport,
    reverse_plan: ConfigReloadPlan,
    applied_config: OracleMcpConfig,
    restored_config: OracleMcpConfig,
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
    /// Atomically apply a hot-reloadable plan and its already-validated target
    /// snapshot to live process state. Runtime readers must consume this
    /// accepted in-memory snapshot, never re-read the just-written file.
    fn apply_config_reload_plan(
        &self,
        plan: &ConfigReloadPlan,
        expected: &OracleMcpConfig,
        next: &OracleMcpConfig,
    ) -> ConfigReloadApplyReport;
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
    /// Evidence that this apply consumed the matching reviewed preview.
    pub review: Option<ConfigReviewEvidence>,
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
    owner: ServiceOwner,
    redaction_key: OpaqueRevisionKey,
}

impl ConfigOpsBackend {
    /// Open the backend using the default service file-store root.
    pub fn open_default() -> Result<Self, ConfigOpsError> {
        Self::open(FileStore::default_state_dir()?)
    }

    /// Open a standalone backend rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ConfigOpsError> {
        let store = FileStore::open(root)?;
        let owner = store.acquire_service_owner("config-ops")?;
        Self::open_with_owner(owner)
    }

    /// Open the backend under an existing process-wide service owner.
    pub fn open_with_owner(owner: ServiceOwner) -> Result<Self, ConfigOpsError> {
        Ok(Self {
            owner,
            redaction_key: OpaqueRevisionKey::generate()?,
        })
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
        let before = redacted_snapshot(&current, &self.redaction_key);
        let after = redacted_snapshot(&draft, &self.redaction_key);
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
            current_config: current,
            draft_config: draft,
        })
    }

    /// Apply a staged draft: backup current bytes, atomically replace target,
    /// then revalidate the installed file with the strict config loader.
    pub fn apply_config_draft(
        &self,
        plan: &ConfigDraftPlan,
    ) -> Result<ConfigApplyReport, ConfigOpsError> {
        let _mutation = self.owner.mutation_guard();
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
    /// The restore is compare-and-swap: the target must still contain the exact
    /// generation named by `report.applied_sha256`.
    pub fn rollback_applied_config(
        &self,
        report: &ConfigApplyReport,
    ) -> Result<ConfigRollbackReport, ConfigOpsError> {
        self.rollback_applied_config_with_reload(report)
            .map(|applied| applied.report)
    }

    fn rollback_applied_config_with_reload(
        &self,
        report: &ConfigApplyReport,
    ) -> Result<AppliedConfigRollback, ConfigOpsError> {
        let _mutation = self.owner.mutation_guard();
        let applied_bytes = read_or_empty(&report.target_path)?;
        let actual_sha256 = oraclemcp_audit::sha256_hex(&applied_bytes);
        if actual_sha256 != report.applied_sha256 {
            return Err(ConfigOpsError::CurrentChanged {
                expected_sha256: report.applied_sha256.clone(),
                actual_sha256,
            });
        }
        let backup =
            fs::read(&report.backup_path).map_err(|e| ConfigOpsError::Io(e.to_string()))?;
        let applied_toml = bytes_to_toml(&report.target_path, &applied_bytes)?;
        let backup_toml = bytes_to_toml(&report.backup_path, &backup)?;
        let applied_config = OracleMcpConfig::from_toml_str(applied_toml)?;
        let restored_config = OracleMcpConfig::from_toml_str(backup_toml)?;
        let reverse_plan = ConfigReloadPlan::between(&applied_config, &restored_config);
        write_atomic_path(&report.target_path, &backup)?;
        validate_target(&report.target_path)?;

        Ok(AppliedConfigRollback {
            report: ConfigRollbackReport {
                target_path: report.target_path.clone(),
                backup_path: report.backup_path.clone(),
                restored_sha256: oraclemcp_audit::sha256_hex(&backup),
            },
            reverse_plan,
            applied_config,
            restored_config,
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
    /// Serializes stage, file replacement, and live snapshot application so
    /// two dashboard requests cannot commit disk order A→B but live order B→A.
    ///
    /// SAFETY: every config mutation takes this lock before touching
    /// `rollback_reports`; that total order makes a rollback id single-consumer
    /// and keeps disk plus live-generation transitions indivisible in-process.
    apply_lock: Mutex<()>,
    rollback_reports: Mutex<BTreeMap<String, ConfigApplyReport>>,
    reviewed_previews: Mutex<BTreeMap<String, ReviewedConfigDraft>>,
    preview_ttl: Duration,
}

const CONFIG_PREVIEW_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_REVIEWED_CONFIG_PREVIEWS: usize = 128;

struct ReviewedConfigDraft {
    binding_sha256: String,
    current_sha256: String,
    draft_sha256: String,
    redacted_diff_sha256: String,
    confirmation_required: bool,
    expires_at: Instant,
    created_at: Instant,
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
            apply_lock: Mutex::new(()),
            rollback_reports: Mutex::new(BTreeMap::new()),
            reviewed_previews: Mutex::new(BTreeMap::new()),
            preview_ttl: CONFIG_PREVIEW_TTL,
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

    /// Stage a draft for an operator and mint a bounded, single-use apply authority.
    pub fn stage_reviewed(
        &self,
        draft_toml: &str,
        review_binding: &str,
    ) -> Result<ConfigReviewedDraftPreview, ConfigOpsError> {
        self.stage_reviewed_at(draft_toml, review_binding, Instant::now(), unix_now())
    }

    fn stage_reviewed_at(
        &self,
        draft_toml: &str,
        review_binding: &str,
        now: Instant,
        now_unix: u64,
    ) -> Result<ConfigReviewedDraftPreview, ConfigOpsError> {
        let _apply_guard = self.apply_lock.lock();
        let plan = self
            .backend
            .stage_config_draft(&self.target_path, draft_toml)?;
        let preview = plan.preview().clone();
        let redacted_diff_sha256 = redacted_diff_sha256(&preview.redacted_diff);
        let confirmation_reasons = config_confirmation_reasons(&preview);
        let confirmation_required = !confirmation_reasons.is_empty();
        let preview_token = random_preview_token()?;
        let preview_token_sha256 = oraclemcp_audit::sha256_hex(preview_token.as_bytes());
        let expires_at = now + self.preview_ttl;
        let mut previews = self.reviewed_previews.lock();
        prune_reviewed_previews(&mut previews, now);
        while previews.len() >= MAX_REVIEWED_CONFIG_PREVIEWS {
            let Some(oldest) = previews
                .iter()
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(token, _)| token.clone())
            else {
                break;
            };
            previews.remove(&oldest);
        }
        previews.insert(
            preview_token.clone(),
            ReviewedConfigDraft {
                binding_sha256: review_binding_sha256(review_binding),
                current_sha256: preview.current_sha256.clone(),
                draft_sha256: preview.draft_sha256.clone(),
                redacted_diff_sha256: redacted_diff_sha256.clone(),
                confirmation_required,
                expires_at,
                created_at: now,
            },
        );
        Ok(ConfigReviewedDraftPreview {
            preview,
            preview_token,
            preview_token_sha256,
            redacted_diff_sha256,
            preview_expires_unix: now_unix.saturating_add(self.preview_ttl.as_secs()),
            confirmation_required,
            confirmation_reasons,
        })
    }

    /// Apply only the exact bytes authorized by a live reviewed preview.
    ///
    /// The token is claimed before validation, so mismatch, cross-session use,
    /// expiry, and concurrent replay all consume the authority and fail closed.
    pub fn apply_reviewed(
        &self,
        draft_toml: &str,
        expected_draft_sha256: &str,
        preview_token: &str,
        review_binding: &str,
        confirmed: bool,
    ) -> Result<ConfigApplyOutcome, ConfigOpsError> {
        self.apply_reviewed_at(
            draft_toml,
            expected_draft_sha256,
            preview_token,
            review_binding,
            confirmed,
            Instant::now(),
        )
    }

    fn apply_reviewed_at(
        &self,
        draft_toml: &str,
        expected_draft_sha256: &str,
        preview_token: &str,
        review_binding: &str,
        confirmed: bool,
        now: Instant,
    ) -> Result<ConfigApplyOutcome, ConfigOpsError> {
        let preview_token = preview_token.trim();
        if preview_token.is_empty() {
            return Err(ConfigOpsError::PreviewRequired);
        }
        let _apply_guard = self.apply_lock.lock();
        let reviewed = self
            .reviewed_previews
            .lock()
            .remove(preview_token)
            .ok_or(ConfigOpsError::InvalidPreviewToken)?;
        if reviewed.expires_at <= now {
            return Err(ConfigOpsError::PreviewExpired);
        }
        if reviewed.binding_sha256 != review_binding_sha256(review_binding) {
            return Err(ConfigOpsError::InvalidPreviewToken);
        }
        let submitted_sha256 = oraclemcp_audit::sha256_hex(draft_toml.as_bytes());
        if expected_draft_sha256.trim() != reviewed.draft_sha256
            || submitted_sha256 != reviewed.draft_sha256
        {
            return Err(ConfigOpsError::PreviewDraftChanged);
        }
        if reviewed.confirmation_required && !confirmed {
            return Err(ConfigOpsError::PreviewConfirmationRequired);
        }
        let plan = self
            .backend
            .stage_config_draft(&self.target_path, draft_toml)?;
        if plan.preview().current_sha256 != reviewed.current_sha256 {
            return Err(ConfigOpsError::CurrentChanged {
                expected_sha256: reviewed.current_sha256,
                actual_sha256: plan.preview().current_sha256.clone(),
            });
        }
        if redacted_diff_sha256(&plan.preview().redacted_diff) != reviewed.redacted_diff_sha256 {
            return Err(ConfigOpsError::PreviewDraftChanged);
        }
        let review = ConfigReviewEvidence {
            preview_token_sha256: oraclemcp_audit::sha256_hex(preview_token.as_bytes()),
            draft_sha256: reviewed.draft_sha256,
            redacted_diff_sha256: reviewed.redacted_diff_sha256,
        };
        self.apply_plan_locked(plan, Some(review))
    }

    /// Apply a draft after validating that the previewed base hash still
    /// matches, then ask the live service to consume the reload plan.
    pub fn apply(
        &self,
        draft_toml: &str,
        expected_current_sha256: Option<&str>,
    ) -> Result<ConfigApplyOutcome, ConfigOpsError> {
        let _apply_guard = self.apply_lock.lock();
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
        self.apply_plan_locked(plan, None)
    }

    fn apply_plan_locked(
        &self,
        plan: ConfigDraftPlan,
        review: Option<ConfigReviewEvidence>,
    ) -> Result<ConfigApplyOutcome, ConfigOpsError> {
        let current_config = plan.current_config.clone();
        let next_config = plan.draft_config.clone();
        let report = self.backend.apply_config_draft(&plan)?;
        let reload = self.reload_outcome(&report.reload_plan, &current_config, &next_config);
        let rollback_id = rollback_id_for(&report);
        let mut rollback_reports = self.rollback_reports.lock();
        // Only the newest apply can be the predecessor of the current
        // generation. Retaining older ids is both misleading and unnecessary:
        // the backend CAS would reject them, while this makes supersession
        // explicit and bounds the map to one actionable rollback.
        rollback_reports.clear();
        rollback_reports.insert(rollback_id.clone(), report.clone());
        self.reviewed_previews.lock().clear();
        Ok(ConfigApplyOutcome {
            apply: report,
            reload,
            rollback_id,
            review,
        })
    }

    /// Restore a previously applied config from its timestamped backup.
    ///
    /// The id is claimed before any I/O and consumed only after a successful
    /// compare-and-swap restore. Failed attempts release the claim for a safe
    /// retry; every retry repeats the generation check before writing. A live
    /// reload refusal is reported as `restart_required`, not as a failed file
    /// restore: the id remains consumed because the disk generation has already
    /// changed, and restarting is the safe way to reconcile live state.
    pub fn rollback(&self, rollback_id: &str) -> Result<ConfigRollbackOutcome, ConfigOpsError> {
        let _apply_guard = self.apply_lock.lock();
        let report = self
            .rollback_reports
            .lock()
            .remove(rollback_id)
            .ok_or(ConfigOpsError::UnknownRollbackId)?;
        let applied = match self.backend.rollback_applied_config_with_reload(&report) {
            Ok(applied) => applied,
            Err(error) => {
                self.rollback_reports
                    .lock()
                    .insert(rollback_id.to_owned(), report);
                return Err(error);
            }
        };
        let reload = self.reload_outcome(
            &applied.reverse_plan,
            &applied.applied_config,
            &applied.restored_config,
        );
        Ok(ConfigRollbackOutcome {
            rollback: applied.report,
            reload,
        })
    }

    fn reload_outcome(
        &self,
        plan: &ConfigReloadPlan,
        expected: &OracleMcpConfig,
        next: &OracleMcpConfig,
    ) -> ConfigReloadApplyReport {
        if !plan.hot_reloadable {
            return ConfigReloadApplyReport::restart_required(plan);
        }
        match &self.reload_applier {
            Some(applier) => applier.apply_config_reload_plan(plan, expected, next),
            None => ConfigReloadApplyReport::not_configured(plan),
        }
    }
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

fn redacted_diff_sha256(diff: &ConfigRedactedDiff) -> String {
    let encoded = serde_json::to_vec(diff).expect("redacted config diff must serialize");
    oraclemcp_audit::sha256_hex(&encoded)
}

fn review_binding_sha256(review_binding: &str) -> String {
    let mut material = b"oraclemcp-config-review-binding-v1\0".to_vec();
    material.extend_from_slice(review_binding.as_bytes());
    oraclemcp_audit::sha256_hex(&material)
}

fn random_preview_token() -> Result<String, ConfigOpsError> {
    let mut random = [0_u8; 32];
    getrandom::getrandom(&mut random)
        .map_err(|error| ConfigOpsError::Io(format!("preview-token generation failed: {error}")))?;
    let mut token = String::with_capacity("config-preview-v1-".len() + random.len() * 2);
    token.push_str("config-preview-v1-");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut token, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(token)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn prune_reviewed_previews(previews: &mut BTreeMap<String, ReviewedConfigDraft>, now: Instant) {
    previews.retain(|_, preview| preview.expires_at > now);
}

fn config_confirmation_reasons(preview: &ConfigDraftPreview) -> Vec<String> {
    let mut reasons = BTreeSet::new();
    if !preview.reload_plan.restart_required.is_empty() {
        reasons.insert("restart-required configuration change".to_owned());
    }
    if !preview.reload_plan.draining_profiles().is_empty() {
        reasons.insert("profile drain or connection replacement".to_owned());
    }
    if preview.redacted_diff.changes.iter().any(|change| {
        let path = change.path.as_str();
        path.starts_with("http.oauth")
            || path.starts_with("http.mtls")
            || path.starts_with("http.tls")
            || path.starts_with("http.operator")
            || path == "http.allow_remote"
            || path == "http.trusted_https_termination"
            || path.starts_with("audit.key")
            || path.starts_with("audit.verification_keys")
            || path.contains(".metadata.max_level")
            || path.contains(".metadata.default_level")
            || path.contains(".metadata.protected")
            || path.contains(".metadata.mcp_exposed")
    }) {
        reasons.insert("authorization, authentication, or exposure change".to_owned());
    }
    reasons.into_iter().collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RedactedConfigSnapshot {
    schema_version: u32,
    default_profile: Option<String>,
    monitor_profile: Option<String>,
    /// Catch-all for newly added config fields until a more specific safe
    /// descriptor is added. The process-local HMAC makes this complete without
    /// turning low-entropy values into offline-guessable public hashes.
    semantic_revision: String,
    http: RedactedHttpSnapshot,
    audit: RedactedAuditSnapshot,
    profiles: BTreeMap<String, RedactedProfileSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RedactedHttpSnapshot {
    semantic_revision: String,
    allowed_hosts: RedactedSetSnapshot,
    allowed_origins: RedactedSetSnapshot,
    json_response: bool,
    stateful: bool,
    stateful_idle_ttl_seconds: u64,
    oauth: RedactedOptionalRevision,
    oauth_resource: RedactedOptionalRevision,
    oauth_allowed_issuers: RedactedSetSnapshot,
    oauth_authorization_servers: RedactedSetSnapshot,
    oauth_required_scopes: RedactedSetSnapshot,
    oauth_secret_ref: RedactedOptionalRevision,
    oauth_metadata_url: RedactedOptionalRevision,
    mtls_client_fingerprints: RedactedSetSnapshot,
    tls: RedactedOptionalRevision,
    tls_cert_chain_path: RedactedOptionalRevision,
    tls_private_key_path: RedactedOptionalRevision,
    tls_client_ca_path: RedactedOptionalRevision,
    operator_loopback_owner: bool,
    operator_allowed_subjects: RedactedSetSnapshot,
    dashboard_workbench: bool,
    trusted_https_termination: bool,
    allow_remote: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RedactedAuditSnapshot {
    semantic_revision: String,
    path: RedactedOptionalRevision,
    key_ref: RedactedOptionalRevision,
    key_id: RedactedOptionalRevision,
    verification_keys: RedactedSetSnapshot,
    shipping: RedactedOptionalRevision,
    worm_path: RedactedOptionalRevision,
    siem_endpoint: RedactedOptionalRevision,
    siem_format: RedactedOptionalRevision,
    siem_auth_header_ref: RedactedOptionalRevision,
    siem_auth_header_name: RedactedOptionalRevision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RedactedProfileSnapshot {
    metadata: ProfileMetadata,
    semantic_revision: String,
    connection_identity_revision: String,
    session_setup_revision: String,
    thin_routing_revision: String,
    session_identity_revision: String,
    app_context_revision: String,
    inheritance_revision: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RedactedSetSnapshot {
    count: usize,
    /// Stable only for this backend lifetime. Members are sorted so order-only
    /// changes to set-like config fields do not create noise.
    member_revisions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RedactedOptionalRevision {
    configured: bool,
    revision: Option<String>,
}

struct OpaqueRevisionKey([u8; 32]);

impl OpaqueRevisionKey {
    fn generate() -> Result<Self, ConfigOpsError> {
        let mut key = [0_u8; 32];
        getrandom::getrandom(&mut key).map_err(|error| {
            ConfigOpsError::Io(format!("redaction-key generation failed: {error}"))
        })?;
        Ok(Self(key))
    }

    fn revision<T: Serialize + ?Sized>(&self, domain: &str, value: &T) -> String {
        let encoded = serde_json::to_vec(value)
            .expect("validated config values must serialize to finite JSON");
        let mut message = Vec::with_capacity(32 + domain.len() + encoded.len());
        message.extend_from_slice(b"oraclemcp-config-preview:v1\0");
        message.extend_from_slice(&(domain.len() as u64).to_be_bytes());
        message.extend_from_slice(domain.as_bytes());
        message.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        message.extend_from_slice(&encoded);
        let digest = oraclemcp_audit::hmac_sha256_hex(&self.0, &message);
        format!("opaque-v1:{}", digest.trim_start_matches("hmac-sha256:"))
    }

    fn optional<T: Serialize>(&self, domain: &str, value: Option<&T>) -> RedactedOptionalRevision {
        RedactedOptionalRevision {
            configured: value.is_some(),
            revision: value.map(|value| self.revision(domain, value)),
        }
    }

    fn set<T: Serialize>(&self, domain: &str, values: &[T]) -> RedactedSetSnapshot {
        let mut member_revisions = values
            .iter()
            .map(|value| self.revision(domain, value))
            .collect::<Vec<_>>();
        member_revisions.sort();
        RedactedSetSnapshot {
            count: values.len(),
            member_revisions,
        }
    }
}

fn redacted_profile_snapshot(
    profile: &ConnectionProfile,
    metadata: ProfileMetadata,
    key: &OpaqueRevisionKey,
) -> RedactedProfileSnapshot {
    RedactedProfileSnapshot {
        metadata,
        semantic_revision: key.revision("profile.semantic", profile),
        connection_identity_revision: key.revision(
            "profile.connection_identity",
            &(
                &profile.connect_string,
                &profile.username,
                &profile.credential_ref,
            ),
        ),
        session_setup_revision: key.revision(
            "profile.session_setup",
            &(
                &profile.login_script,
                &profile.login_statements,
                &profile.trusted_session_statements,
            ),
        ),
        thin_routing_revision: key.revision(
            "profile.thin_routing",
            &(
                profile.connect_timeout_seconds,
                profile.inactivity_timeout_seconds,
                profile.keepalive_minutes,
                profile.sdu,
                &profile.oci,
                &profile.drcp,
                &profile.proxy_auth,
            ),
        ),
        session_identity_revision: key
            .revision("profile.session_identity", &profile.session_identity),
        app_context_revision: key.revision("profile.app_context", &profile.app_context),
        inheritance_revision: key.revision("profile.inheritance", &profile.base),
    }
}

fn redacted_snapshot(config: &OracleMcpConfig, key: &OpaqueRevisionKey) -> RedactedConfigSnapshot {
    let metadata = config
        .list_profiles()
        .into_iter()
        .map(|profile| (profile.name.clone(), profile))
        .collect::<BTreeMap<_, _>>();
    let profiles = config
        .profiles
        .iter()
        .map(|profile| {
            (
                profile.name.clone(),
                redacted_profile_snapshot(
                    profile,
                    metadata
                        .get(&profile.name)
                        .cloned()
                        .unwrap_or_else(|| profile.metadata()),
                    key,
                ),
            )
        })
        .collect();
    let oauth = config.http.oauth.as_ref();
    let tls = config.http.tls.as_ref();
    let shipping = config.audit.shipping.as_ref();
    RedactedConfigSnapshot {
        schema_version: config.schema_version,
        default_profile: config.default_profile.clone(),
        monitor_profile: config.monitor_profile.clone(),
        semantic_revision: key.revision("config.semantic", config),
        http: RedactedHttpSnapshot {
            semantic_revision: key.revision("http.semantic", &config.http),
            allowed_hosts: key.set("http.allowed_hosts.member", &config.http.allowed_hosts),
            allowed_origins: key.set("http.allowed_origins.member", &config.http.allowed_origins),
            json_response: config.http.json_response,
            stateful: config.http.stateful,
            stateful_idle_ttl_seconds: config.http.stateful_idle_ttl_seconds,
            oauth: key.optional("http.oauth", oauth),
            oauth_resource: key.optional(
                "http.oauth.resource",
                oauth.and_then(|value| value.resource.as_ref()),
            ),
            oauth_allowed_issuers: key.set(
                "http.oauth.allowed_issuers.member",
                oauth.map_or(&[], |value| value.allowed_issuers.as_slice()),
            ),
            oauth_authorization_servers: key.set(
                "http.oauth.authorization_servers.member",
                oauth.map_or(&[], |value| value.authorization_servers.as_slice()),
            ),
            oauth_required_scopes: key.set(
                "http.oauth.required_scopes.member",
                oauth.map_or(&[], |value| value.required_scopes.as_slice()),
            ),
            oauth_secret_ref: key.optional(
                "http.oauth.hs256_secret_ref",
                oauth.and_then(|value| value.hs256_secret_ref.as_ref()),
            ),
            oauth_metadata_url: key.optional(
                "http.oauth.metadata_url",
                oauth.and_then(|value| value.metadata_url.as_ref()),
            ),
            mtls_client_fingerprints: key.set(
                "http.mtls.client_fingerprints.member",
                &config.http.mtls.client_fingerprints,
            ),
            tls: key.optional("http.tls", tls),
            tls_cert_chain_path: key.optional(
                "http.tls.cert_chain_path",
                tls.and_then(|value| value.cert_chain_path.as_ref()),
            ),
            tls_private_key_path: key.optional(
                "http.tls.private_key_path",
                tls.and_then(|value| value.private_key_path.as_ref()),
            ),
            tls_client_ca_path: key.optional(
                "http.tls.client_ca_path",
                tls.and_then(|value| value.client_ca_path.as_ref()),
            ),
            operator_loopback_owner: config.http.operator.allow_loopback_owner,
            operator_allowed_subjects: key.set(
                "http.operator.allowed_subjects.member",
                &config.http.operator.allowed_subjects,
            ),
            dashboard_workbench: config.http.dashboard_workbench,
            trusted_https_termination: config.http.trusted_https_termination,
            allow_remote: config.http.allow_remote,
        },
        audit: RedactedAuditSnapshot {
            semantic_revision: key.revision("audit.semantic", &config.audit),
            path: key.optional("audit.path", config.audit.path.as_ref()),
            key_ref: key.optional("audit.key_ref", config.audit.key_ref.as_ref()),
            key_id: key.optional("audit.key_id", config.audit.key_id.as_ref()),
            verification_keys: key.set(
                "audit.verification_keys.member",
                &config.audit.verification_keys,
            ),
            shipping: key.optional("audit.shipping", shipping),
            worm_path: key.optional(
                "audit.shipping.worm_path",
                shipping.and_then(|value| value.worm_path.as_ref()),
            ),
            siem_endpoint: key.optional(
                "audit.shipping.siem_endpoint",
                shipping.and_then(|value| value.siem_endpoint.as_ref()),
            ),
            siem_format: key.optional(
                "audit.shipping.siem_format",
                shipping.and_then(|value| value.siem_format.as_ref()),
            ),
            siem_auth_header_ref: key.optional(
                "audit.shipping.siem_auth_header_ref",
                shipping.and_then(|value| value.siem_auth_header_ref.as_ref()),
            ),
            siem_auth_header_name: key.optional(
                "audit.shipping.siem_auth_header_name",
                shipping.and_then(|value| value.siem_auth_header_name.as_ref()),
            ),
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

    struct BlockingReloadApplier {
        calls: Arc<Mutex<Vec<(String, String)>>>,
        first_entered: std::sync::mpsc::Sender<()>,
        release_first: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    #[derive(Default)]
    struct RecordingReloadApplier {
        calls: Mutex<Vec<(String, String)>>,
    }

    #[derive(Default)]
    struct RejectSecondReloadApplier {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl ConfigReloadApplier for RecordingReloadApplier {
        fn apply_config_reload_plan(
            &self,
            plan: &ConfigReloadPlan,
            expected: &OracleMcpConfig,
            next: &OracleMcpConfig,
        ) -> ConfigReloadApplyReport {
            let connect_string = |config: &OracleMcpConfig| {
                config
                    .profile("prod")
                    .and_then(|profile| profile.connect_string.clone())
                    .expect("prod connect string")
            };
            self.calls
                .lock()
                .push((connect_string(expected), connect_string(next)));
            ConfigReloadApplyReport {
                status: "applied".to_owned(),
                hot_reloadable: true,
                restart_required: Vec::new(),
                draining_profiles: plan.draining_profiles(),
                message: "test reload applied".to_owned(),
            }
        }
    }

    impl ConfigReloadApplier for RejectSecondReloadApplier {
        fn apply_config_reload_plan(
            &self,
            plan: &ConfigReloadPlan,
            _expected: &OracleMcpConfig,
            _next: &OracleMcpConfig,
        ) -> ConfigReloadApplyReport {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call == 0 {
                return ConfigReloadApplyReport {
                    status: "applied".to_owned(),
                    hot_reloadable: true,
                    restart_required: Vec::new(),
                    draining_profiles: plan.draining_profiles(),
                    message: "initial reload applied".to_owned(),
                };
            }
            ConfigReloadApplyReport {
                status: "restart_required".to_owned(),
                hot_reloadable: false,
                restart_required: vec!["simulated live-generation refusal".to_owned()],
                draining_profiles: Vec::new(),
                message: "disk restored; restart required".to_owned(),
            }
        }
    }

    impl ConfigReloadApplier for BlockingReloadApplier {
        fn apply_config_reload_plan(
            &self,
            plan: &ConfigReloadPlan,
            expected: &OracleMcpConfig,
            next: &OracleMcpConfig,
        ) -> ConfigReloadApplyReport {
            let connect_string = |config: &OracleMcpConfig| {
                config
                    .profile("prod")
                    .and_then(|profile| profile.connect_string.clone())
                    .expect("prod connect string")
            };
            self.calls
                .lock()
                .push((connect_string(expected), connect_string(next)));
            let release = self.release_first.lock().take();
            if let Some(release) = release {
                self.first_entered.send(()).expect("announce first apply");
                release.recv().expect("release first apply");
            }
            ConfigReloadApplyReport {
                status: "applied".to_owned(),
                hot_reloadable: true,
                restart_required: Vec::new(),
                draining_profiles: plan.draining_profiles(),
                message: "test reload applied".to_owned(),
            }
        }
    }

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
        let backend = ConfigOpsBackend::open(root.join("state")).expect("config ops");
        (backend, root.join("profiles.toml"))
    }

    fn profile_config(connect_string: &str) -> String {
        format!(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "{connect_string}"
            "#
        )
    }

    fn privileged_profile_config(connect_string: &str, max_level: &str) -> String {
        format!(
            r#"
            [audit]
            key_ref = "env:ORACLEMCP_AUDIT_KEY"

            [[profiles]]
            name = "prod"
            connect_string = "{connect_string}"
            max_level = "{max_level}"
            default_level = "READ_ONLY"
            "#
        )
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
                .any(|change| change.path == "http.oauth_allowed_issuers.count")
        );
        for path in [
            "profiles.prod.connection_identity_revision",
            "profiles.prod.thin_routing_revision",
        ] {
            assert!(
                plan.preview()
                    .redacted_diff
                    .changes
                    .iter()
                    .any(|change| change.path == path),
                "missing {path}: {:?}",
                plan.preview().redacted_diff
            );
        }
        assert!(rendered.contains("opaque-v1:"));
    }

    #[test]
    fn same_cardinality_sensitive_substitutions_are_visible_but_opaque() {
        let (backend, target) = backend("same-cardinality-redacted-diff");
        let current = r#"
            [http]
            allowed_hosts = ["old.internal.example:443"]
            allowed_origins = ["https://old.example"]

            [http.oauth]
            resource = "https://old.example/mcp"
            allowed_issuers = ["https://issuer-old.example"]
            authorization_servers = ["https://auth-old.example"]
            required_scopes = ["oracle:read"]
            hs256_secret_ref = "env:OLD_OAUTH_SECRET"
            metadata_url = "https://old.example/oauth-metadata"

            [http.mtls]
            client_fingerprints = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]

            [http.tls]
            cert_chain_path = "/old/tls/cert.pem"
            private_key_path = "/old/tls/key.pem"
            client_ca_path = "/old/tls/ca.pem"

            [http.operator]
            allowed_subjects = ["oauth:old-subject"]

            [audit]
            path = "/old/audit.jsonl"
            key_ref = "env:OLD_AUDIT_KEY"
            key_id = "old-active"

            [[audit.verification_keys]]
            key_id = "old-history"
            key_ref = "env:OLD_HISTORY_KEY"

            [audit.shipping]
            worm_path = "/old/worm.jsonl"
            siem_endpoint = "https://siem-old.example/ingest"
            siem_format = "cef"
            siem_auth_header_ref = "env:OLD_SIEM_TOKEN"
            siem_auth_header_name = "Authorization"
            "#;
        let draft = r#"
            [http]
            allowed_hosts = ["new.internal.example:8443"]
            allowed_origins = ["https://new.example"]

            [http.oauth]
            resource = "https://new.example/mcp"
            allowed_issuers = ["https://issuer-new.example"]
            authorization_servers = ["https://auth-new.example"]
            required_scopes = ["oracle:admin"]
            hs256_secret_ref = "env:NEW_OAUTH_SECRET"
            metadata_url = "https://new.example/oauth-metadata"

            [http.mtls]
            client_fingerprints = ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]

            [http.tls]
            cert_chain_path = "/new/tls/cert.pem"
            private_key_path = "/new/tls/key.pem"
            client_ca_path = "/new/tls/ca.pem"

            [http.operator]
            allowed_subjects = ["mtls:new-subject"]

            [audit]
            path = "/new/audit.jsonl"
            key_ref = "env:NEW_AUDIT_KEY"
            key_id = "new-active"

            [[audit.verification_keys]]
            key_id = "new-history"
            key_ref = "env:NEW_HISTORY_KEY"

            [audit.shipping]
            worm_path = "/new/worm.jsonl"
            siem_endpoint = "https://siem-new.example/collect"
            siem_format = "syslog"
            siem_auth_header_ref = "env:NEW_SIEM_TOKEN"
            siem_auth_header_name = "X-Collector-Token"
            "#;
        write_atomic_path(&target, current.as_bytes()).expect("seed current config");

        let preview = backend
            .stage_config_draft(&target, draft)
            .expect("stage same-cardinality substitutions")
            .preview()
            .clone();
        let paths = preview
            .redacted_diff
            .changes
            .iter()
            .map(|change| change.path.as_str())
            .collect::<BTreeSet<_>>();
        for path in [
            "http.allowed_hosts.member_revisions",
            "http.allowed_origins.member_revisions",
            "http.oauth_resource.revision",
            "http.oauth_allowed_issuers.member_revisions",
            "http.oauth_authorization_servers.member_revisions",
            "http.oauth_required_scopes.member_revisions",
            "http.oauth_secret_ref.revision",
            "http.oauth_metadata_url.revision",
            "http.mtls_client_fingerprints.member_revisions",
            "http.tls_cert_chain_path.revision",
            "http.tls_private_key_path.revision",
            "http.tls_client_ca_path.revision",
            "http.operator_allowed_subjects.member_revisions",
            "audit.path.revision",
            "audit.key_ref.revision",
            "audit.key_id.revision",
            "audit.verification_keys.member_revisions",
            "audit.worm_path.revision",
            "audit.siem_endpoint.revision",
            "audit.siem_format.revision",
            "audit.siem_auth_header_ref.revision",
            "audit.siem_auth_header_name.revision",
        ] {
            assert!(paths.contains(path), "missing {path}: {paths:?}");
        }

        let rendered = serde_json::to_string(&preview).expect("serialize preview");
        for forbidden in [
            "old.internal.example",
            "new.internal.example",
            "issuer-old",
            "issuer-new",
            "old-subject",
            "new-subject",
            "/old/",
            "/new/",
            "OLD_",
            "NEW_",
            "siem-old",
            "siem-new",
            "X-Collector-Token",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "redacted preview leaked {forbidden}: {rendered}"
            );
        }
    }

    #[test]
    fn catch_all_revision_covers_new_semantics_and_is_deterministic_per_backend() {
        let (backend, target) = backend("complete-redacted-revision");
        let current = profile_config("old.internal:1521/svc");
        let draft = r#"
            [[profiles]]
            name = "prod"
            connect_string = "new.internal:1521/svc"
            username = "PRIVATE_USER"
            credential_ref = "env:PRIVATE_PASSWORD"
            trusted_session_statements = ["BEGIN NULL; END;"]

            [profiles.session_identity]
            module = "PRIVATE_MODULE"

            [[profiles.app_context]]
            namespace = "PRIVATE_NAMESPACE"
            key = "PRIVATE_KEY"
            value = "PRIVATE_VALUE"
            "#;
        write_atomic_path(&target, current.as_bytes()).expect("seed current config");

        let first = backend
            .stage_config_draft(&target, draft)
            .expect("first stage");
        let second = backend
            .stage_config_draft(&target, draft)
            .expect("repeat stage");
        assert_eq!(
            first.preview().redacted_diff,
            second.preview().redacted_diff,
            "the same backend and exact draft must render a stable preview"
        );
        let paths = first
            .preview()
            .redacted_diff
            .changes
            .iter()
            .map(|change| change.path.as_str())
            .collect::<BTreeSet<_>>();
        for path in [
            "semantic_revision",
            "profiles.prod.semantic_revision",
            "profiles.prod.connection_identity_revision",
            "profiles.prod.session_setup_revision",
            "profiles.prod.session_identity_revision",
            "profiles.prod.app_context_revision",
        ] {
            assert!(paths.contains(path), "missing {path}: {paths:?}");
        }
        let rendered = serde_json::to_string(first.preview()).expect("serialize preview");
        for forbidden in [
            "old.internal",
            "new.internal",
            "PRIVATE_USER",
            "PRIVATE_PASSWORD",
            "PRIVATE_MODULE",
            "PRIVATE_NAMESPACE",
            "PRIVATE_KEY",
            "PRIVATE_VALUE",
            "BEGIN NULL",
        ] {
            assert!(!rendered.contains(forbidden), "leaked {forbidden}");
        }
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

    #[test]
    fn concurrent_applies_serialize_disk_and_live_snapshot_order() {
        let (backend, target) = backend("serialized-live-apply");
        let config = |connect_string: &str| {
            format!(
                r#"
                [[profiles]]
                name = "prod"
                connect_string = "{connect_string}"
                "#
            )
        };
        let a = config("a:1521/svc");
        let b = config("b:1521/svc");
        let c = config("c:1521/svc");
        write_atomic_path(&target, a.as_bytes()).expect("seed A");

        let (first_entered_tx, first_entered_rx) = std::sync::mpsc::channel();
        let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let applier = Arc::new(BlockingReloadApplier {
            calls: Arc::clone(&calls),
            first_entered: first_entered_tx,
            release_first: Mutex::new(Some(release_first_rx)),
        });
        let service = Arc::new(ConfigOpsService::new(
            backend,
            target.clone(),
            Some(applier),
        ));

        let first_service = Arc::clone(&service);
        let b_for_apply = b.clone();
        let first = std::thread::spawn(move || first_service.apply(&b_for_apply, None));
        first_entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("first live apply entered");

        let second_service = Arc::clone(&service);
        let (second_done_tx, second_done_rx) = std::sync::mpsc::channel();
        let c_for_apply = c.clone();
        let second = std::thread::spawn(move || {
            let result = second_service.apply(&c_for_apply, None);
            second_done_tx.send(()).expect("announce second completion");
            result
        });
        assert!(
            second_done_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "the second request must not replace disk while A to B live apply is blocked"
        );
        assert_eq!(
            fs::read_to_string(&target).expect("read blocked target"),
            b,
            "disk and live apply remain one serialized transaction"
        );

        release_first_tx.send(()).expect("release first live apply");
        first.join().expect("first apply thread").expect("apply B");
        second
            .join()
            .expect("second apply thread")
            .expect("apply C");
        assert_eq!(fs::read_to_string(&target).expect("read target"), c);
        assert_eq!(
            calls.lock().as_slice(),
            &[
                ("a:1521/svc".to_owned(), "b:1521/svc".to_owned()),
                ("b:1521/svc".to_owned(), "c:1521/svc".to_owned()),
            ],
            "the exact expected snapshot handed to the applier follows disk order"
        );
    }

    #[test]
    fn rollback_rejects_an_external_edit_without_replacing_it() {
        let (backend, target) = backend("rollback-external-edit");
        let before = profile_config("before:1521/svc");
        let applied = profile_config("applied:1521/svc");
        let external = profile_config("external:1521/svc");
        write_atomic_path(&target, before.as_bytes()).expect("seed before config");
        let service = ConfigOpsService::new(backend, target.clone(), None);
        let outcome = service.apply(&applied, None).expect("apply config");
        write_atomic_path(&target, external.as_bytes()).expect("external config edit");

        let error = service
            .rollback(&outcome.rollback_id)
            .expect_err("stale rollback must be rejected");

        assert!(matches!(error, ConfigOpsError::CurrentChanged { .. }));
        assert_eq!(
            fs::read_to_string(&target).expect("read preserved target"),
            external,
            "rollback must not replace a generation it did not create"
        );
    }

    #[test]
    fn newer_apply_invalidates_older_rollback_id() {
        let (backend, target) = backend("rollback-superseded");
        let a = profile_config("a:1521/svc");
        let b = profile_config("b:1521/svc");
        let c = profile_config("c:1521/svc");
        write_atomic_path(&target, a.as_bytes()).expect("seed A");
        let service = ConfigOpsService::new(backend, target.clone(), None);
        let apply_b = service.apply(&b, None).expect("apply B");
        let apply_c = service.apply(&c, None).expect("apply C");

        let stale = service
            .rollback(&apply_b.rollback_id)
            .expect_err("apply C supersedes the rollback to A");
        assert!(matches!(stale, ConfigOpsError::UnknownRollbackId));
        assert_eq!(
            fs::read_to_string(&target).expect("read C"),
            c,
            "a stale id must not overwrite the newer generation"
        );

        service
            .rollback(&apply_c.rollback_id)
            .expect("the newest rollback remains actionable");
        assert_eq!(fs::read_to_string(&target).expect("read B"), b);
    }

    #[test]
    fn concurrent_same_id_rollback_has_exactly_one_consumer() {
        const CALLERS: usize = 32;

        let (backend, target) = backend("rollback-single-consumer");
        let before = profile_config("before:1521/svc");
        let applied = profile_config("applied:1521/svc");
        write_atomic_path(&target, before.as_bytes()).expect("seed before config");
        let service = Arc::new(ConfigOpsService::new(backend, target.clone(), None));
        let rollback_id = service
            .apply(&applied, None)
            .expect("apply config")
            .rollback_id;
        let barrier = Arc::new(std::sync::Barrier::new(CALLERS));

        let callers: Vec<_> = (0..CALLERS)
            .map(|_| {
                let service = Arc::clone(&service);
                let rollback_id = rollback_id.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    service.rollback(&rollback_id)
                })
            })
            .collect();

        let mut successes = 0;
        let mut consumed = 0;
        for caller in callers {
            match caller.join().expect("rollback caller") {
                Ok(_) => successes += 1,
                Err(ConfigOpsError::UnknownRollbackId) => consumed += 1,
                Err(other) => panic!("unexpected rollback error: {other}"),
            }
        }
        assert_eq!(successes, 1, "exactly one caller may consume the id");
        assert_eq!(consumed, CALLERS - 1);
        assert_eq!(
            fs::read_to_string(&target).expect("read restored target"),
            before
        );
    }

    #[test]
    fn successful_rollback_reloads_the_exact_applied_and_restored_snapshots() {
        let (backend, target) = backend("rollback-reload-snapshots");
        let before = profile_config("before:1521/svc");
        let applied = profile_config("applied:1521/svc");
        write_atomic_path(&target, before.as_bytes()).expect("seed before config");
        let applier = Arc::new(RecordingReloadApplier::default());
        let service = ConfigOpsService::new(backend, target.clone(), Some(applier.clone()));
        let outcome = service.apply(&applied, None).expect("apply config");

        service
            .rollback(&outcome.rollback_id)
            .expect("rollback current generation");

        assert_eq!(
            applier.calls.lock().as_slice(),
            &[
                ("before:1521/svc".to_owned(), "applied:1521/svc".to_owned()),
                ("applied:1521/svc".to_owned(), "before:1521/svc".to_owned()),
            ],
            "rollback reload must use the same locked bytes that the CAS replaced"
        );
        assert_eq!(fs::read_to_string(&target).expect("read restored"), before);
    }

    #[test]
    fn rollback_io_failure_releases_claim_for_safe_retry() {
        let (backend, target) = backend("rollback-io-retry");
        let before = profile_config("before:1521/svc");
        let applied = profile_config("applied:1521/svc");
        write_atomic_path(&target, before.as_bytes()).expect("seed before config");
        let service = ConfigOpsService::new(backend, target.clone(), None);
        let outcome = service.apply(&applied, None).expect("apply config");
        let original_report = service
            .rollback_reports
            .lock()
            .get(&outcome.rollback_id)
            .cloned()
            .expect("retained report");
        let mut broken_report = original_report.clone();
        broken_report.backup_path = target.with_extension("missing-backup");
        service
            .rollback_reports
            .lock()
            .insert(outcome.rollback_id.clone(), broken_report);

        let error = service
            .rollback(&outcome.rollback_id)
            .expect_err("missing backup fails before replacement");
        assert!(matches!(error, ConfigOpsError::Io(_)));
        assert!(
            service
                .rollback_reports
                .lock()
                .contains_key(&outcome.rollback_id),
            "a failed execution releases its single-consumer claim"
        );
        assert_eq!(fs::read_to_string(&target).expect("read applied"), applied);

        service
            .rollback_reports
            .lock()
            .insert(outcome.rollback_id.clone(), original_report);
        service
            .rollback(&outcome.rollback_id)
            .expect("retry succeeds while the applied generation still matches");
        assert_eq!(fs::read_to_string(&target).expect("read restored"), before);
    }

    #[test]
    fn reload_refusal_after_restore_consumes_id_and_requires_restart() {
        let (backend, target) = backend("rollback-reload-refusal");
        let before = profile_config("before:1521/svc");
        let applied = profile_config("applied:1521/svc");
        write_atomic_path(&target, before.as_bytes()).expect("seed before config");
        let applier = Arc::new(RejectSecondReloadApplier::default());
        let service = ConfigOpsService::new(backend, target.clone(), Some(applier));
        let outcome = service.apply(&applied, None).expect("apply config");

        let rollback = service
            .rollback(&outcome.rollback_id)
            .expect("file restore succeeds even when live state refuses it");

        assert_eq!(rollback.reload.status, "restart_required");
        assert_eq!(
            fs::read_to_string(&target).expect("read restored config"),
            before,
            "the file restore completed before the live reload refusal"
        );
        assert!(matches!(
            service.rollback(&outcome.rollback_id),
            Err(ConfigOpsError::UnknownRollbackId)
        ));
    }

    #[test]
    fn stale_id_cannot_undo_a_newer_security_ceiling_reduction() {
        let (backend, target) = backend("rollback-security-reduction");
        let admin = privileged_profile_config("prod:1521/svc", "ADMIN");
        let read_write = privileged_profile_config("prod:1521/svc", "READ_WRITE");
        let read_only = privileged_profile_config("prod:1521/svc", "READ_ONLY");
        write_atomic_path(&target, admin.as_bytes()).expect("seed ADMIN config");
        let service = ConfigOpsService::new(backend, target.clone(), None);
        let older = service
            .apply(&read_write, None)
            .expect("lower to READ_WRITE");
        service.apply(&read_only, None).expect("lower to READ_ONLY");

        let stale = service
            .rollback(&older.rollback_id)
            .expect_err("older rollback id was superseded");
        assert!(matches!(stale, ConfigOpsError::UnknownRollbackId));
        assert_eq!(
            fs::read_to_string(&target).expect("read protected ceiling"),
            read_only,
            "the stale rollback must not restore the older, higher ceiling"
        );
        let parsed = OracleMcpConfig::load(Some(&target)).expect("parse reduced config");
        assert_eq!(
            parsed.profile("prod").expect("prod profile").max_level(),
            oraclemcp_config::OperatingLevel::ReadOnly
        );
    }

    #[test]
    fn reviewed_apply_binds_exact_bytes_binding_and_single_use() {
        let (backend, target) = backend("reviewed-exact-binding");
        let current = profile_config("current:1521/svc");
        let reviewed = profile_config("reviewed:1521/svc");
        let substituted = profile_config("substituted:1521/svc");
        write_atomic_path(&target, current.as_bytes()).expect("seed current config");
        let service = ConfigOpsService::new(backend, target.clone(), None);

        let preview = service
            .stage_reviewed(&reviewed, "operator-session-a")
            .expect("review draft");
        let cross_session = service
            .apply_reviewed(
                &reviewed,
                &preview.preview.draft_sha256,
                &preview.preview_token,
                "operator-session-b",
                true,
            )
            .expect_err("cross-session token must fail");
        assert!(matches!(cross_session, ConfigOpsError::InvalidPreviewToken));
        assert_eq!(fs::read_to_string(&target).expect("read current"), current);
        assert!(matches!(
            service.apply_reviewed(
                &reviewed,
                &preview.preview.draft_sha256,
                &preview.preview_token,
                "operator-session-a",
                true,
            ),
            Err(ConfigOpsError::InvalidPreviewToken)
        ));

        let preview = service
            .stage_reviewed(&reviewed, "operator-session-a")
            .expect("review draft again");
        let drift = service
            .apply_reviewed(
                &substituted,
                &preview.preview.draft_sha256,
                &preview.preview_token,
                "operator-session-a",
                true,
            )
            .expect_err("different bytes must fail");
        assert!(matches!(drift, ConfigOpsError::PreviewDraftChanged));
        assert_eq!(fs::read_to_string(&target).expect("read current"), current);

        let preview = service
            .stage_reviewed(&reviewed, "operator-session-a")
            .expect("review exact draft");
        let outcome = service
            .apply_reviewed(
                &reviewed,
                &preview.preview.draft_sha256,
                &preview.preview_token,
                "operator-session-a",
                true,
            )
            .expect("exact reviewed draft applies");
        let evidence = outcome.review.expect("review evidence");
        assert_eq!(evidence.draft_sha256, preview.preview.draft_sha256);
        assert_eq!(evidence.redacted_diff_sha256, preview.redacted_diff_sha256);
        assert_eq!(evidence.preview_token_sha256, preview.preview_token_sha256);
        assert_eq!(fs::read_to_string(&target).expect("read applied"), reviewed);
        assert!(matches!(
            service.apply_reviewed(
                &reviewed,
                &preview.preview.draft_sha256,
                &preview.preview_token,
                "operator-session-a",
                true,
            ),
            Err(ConfigOpsError::InvalidPreviewToken)
        ));
    }

    #[test]
    fn reviewed_apply_rejects_expiry_base_race_and_missing_confirmation() {
        let (backend, target) = backend("reviewed-expiry-race-confirm");
        let current = privileged_profile_config("current:1521/svc", "READ_ONLY");
        let sensitive = privileged_profile_config("current:1521/svc", "ADMIN");
        let external = privileged_profile_config("external:1521/svc", "READ_ONLY");
        write_atomic_path(&target, current.as_bytes()).expect("seed current config");
        let mut service = ConfigOpsService::new(backend, target.clone(), None);
        service.preview_ttl = Duration::from_secs(2);
        let start = Instant::now();

        let expired = service
            .stage_reviewed_at(&sensitive, "operator", start, 100)
            .expect("stage expiring preview");
        assert!(expired.confirmation_required);
        assert_eq!(expired.preview_expires_unix, 102);
        assert!(matches!(
            service.apply_reviewed_at(
                &sensitive,
                &expired.preview.draft_sha256,
                &expired.preview_token,
                "operator",
                true,
                start + Duration::from_secs(2),
            ),
            Err(ConfigOpsError::PreviewExpired)
        ));
        assert_eq!(fs::read_to_string(&target).expect("read current"), current);

        let unconfirmed = service
            .stage_reviewed_at(&sensitive, "operator", start, 100)
            .expect("stage sensitive preview");
        assert!(matches!(
            service.apply_reviewed_at(
                &sensitive,
                &unconfirmed.preview.draft_sha256,
                &unconfirmed.preview_token,
                "operator",
                false,
                start,
            ),
            Err(ConfigOpsError::PreviewConfirmationRequired)
        ));
        assert_eq!(fs::read_to_string(&target).expect("read current"), current);

        let raced = service
            .stage_reviewed_at(&sensitive, "operator", start, 100)
            .expect("stage raced preview");
        write_atomic_path(&target, external.as_bytes()).expect("external edit");
        assert!(matches!(
            service.apply_reviewed_at(
                &sensitive,
                &raced.preview.draft_sha256,
                &raced.preview_token,
                "operator",
                true,
                start,
            ),
            Err(ConfigOpsError::CurrentChanged { .. })
        ));
        assert_eq!(
            fs::read_to_string(&target).expect("preserved external"),
            external
        );
    }

    #[test]
    fn reviewed_preview_registry_is_bounded() {
        let (backend, target) = backend("reviewed-preview-bound");
        let current = profile_config("current:1521/svc");
        write_atomic_path(&target, current.as_bytes()).expect("seed current config");
        let service = ConfigOpsService::new(backend, target, None);
        for index in 0..(MAX_REVIEWED_CONFIG_PREVIEWS + 17) {
            let draft = profile_config(&format!("draft-{index}:1521/svc"));
            service
                .stage_reviewed(&draft, "operator")
                .expect("bounded preview");
        }
        assert_eq!(
            service.reviewed_previews.lock().len(),
            MAX_REVIEWED_CONFIG_PREVIEWS
        );
    }
}
