//! `/operator/v1/ci-lanes`: the Ground Control CI-lane-health tile.
//!
//! Every `scheduled` and `advisory` job in `docs/ci_taxonomy.json` (the
//! generated, single-source-of-truth CI taxonomy) is a "lane" this tile
//! watches. The point is the plan's own framing: **the operator must never
//! discover a red lane first** — a scheduled nightly or an advisory check that
//! goes red should be visible on the dashboard, not only in a GitHub Actions
//! inbox nobody is watching.
//!
//! # Two halves, deliberately not wired together yet
//!
//! 1. `fetch_ci_lane_snapshot` (test-only in this change — see below) is a
//!    genuine `async fn`: it polls the GitHub Actions REST API through
//!    asupersync's Tokio-free HTTP/1 client (the same engine-free egress path
//!    `crate::audit_shipping::SiemHttpForwarder` and the OTLP exporter use) and
//!    produces a [`CiLaneSnapshot`]. Every step is `.await`-driven; this file
//!    constructs no reactor, no runtime, and calls `block_on` nowhere in
//!    production code.
//! 2. `/operator/v1/ci-lanes` itself ([`operator_ci_lane_health_data`]) is a
//!    plain **synchronous** handler, because the native HTTP transport
//!    (`http/serve.rs`) is a thread-per-connection blocking-I/O server with no
//!    async executor backing an individual request — there is no "current
//!    runtime" a sync handler could safely `.await` into. Standing one up for
//!    this one route is exactly the mistake this module must not repeat (a
//!    prior salvage did that: a fresh reactor + `current_thread` runtime built
//!    and `block_on`-ed inside the request path, unmarked, on every scheduled
//!    refresh — the concurrency lint's `unsanctioned-block-on` check exists
//!    precisely to catch this). So the handler never calls
//!    `fetch_ci_lane_snapshot` directly; it synchronously reads whatever
//!    [`CiLaneSnapshot`] was last durably written to
//!    [`HttpTransportConfig::ci_lane_snapshot_path`] and renders it, exactly
//!    like every other operator route reads its own file-backed state
//!    (`source_history`, `change_proposals`, the audit tail).
//!
//! Driving half 1 on a schedule and writing its result to the path half 2
//! reads is a follow-up integration (an external caller — a scheduled
//! workflow or a future `oraclemcp` subcommand — on the existing sanctioned
//! CLI `block_on_connect` boundary in `main.rs`, not a new always-on
//! in-process poller). Until that lands, an unconfigured or unreadable
//! snapshot renders as an honest `"unavailable"` tile: catalog listed, every
//! lane `"unknown"`, never a fabricated green.
//!
//! Because no in-tree caller drives it yet, `fetch_ci_lane_snapshot` and its
//! helpers below compile only under `#[cfg(test)]` in this change — Rust's own
//! dead-code analysis is correctly strict about code with zero non-test call
//! sites, and adding a speculative production caller just to silence it would
//! be worse than being honest about the current wiring. This crate's test
//! suite drives the pipeline end to end against a local mock GitHub server
//! (see `tests_ci_lanes.rs`), proving the async design. The follow-up bead
//! that adds a real scheduled caller removes these `#[cfg(test)]` gates
//! without changing the implementation underneath them.
use super::*;
#[cfg(test)]
use asupersync::http::h1::http_client::HttpClient;
#[cfg(test)]
use asupersync::http::h1::types::Method;
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::OnceLock;

// Embedded from a crate-local copy, not `docs/ci_taxonomy.json` directly:
// `include_str!` on a path outside this crate directory would compile fine in
// a full checkout but leaves `cargo package`'s tarball missing the file (the
// exact class of bug fixed in cfc650b for install.sh/install.ps1 — see
// `crate_local_ci_taxonomy_matches_repo_root` in tests_ci_lanes.rs, which
// keeps this copy byte-identical to the source of truth).
const CI_LANE_TAXONOMY: &str = include_str!("../../ci_taxonomy.json");
const CI_LANE_TAXONOMY_SCHEMA: &str = "ci-taxonomy/v1";
const CI_LANE_REPO: &str = "oraclemcp";
const CI_LANE_GITHUB_REPO: &str = "MuhDur/oraclemcp";
const CI_LANE_STREAK_WINDOW: usize = 4;
const CI_LANE_REFRESH_INTERVAL: Duration = Duration::from_secs(30 * 60);
const CI_LANE_STALE_AFTER: Duration = Duration::from_secs(60 * 60);
pub(super) const CI_LANE_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Storage schema tag for the durable snapshot file. Bumped on any
/// incompatible field change so a stale on-disk snapshot from an older build
/// fails closed (parses as an error) instead of rendering under a
/// misinterpreted shape.
const CI_LANE_SNAPSHOT_SCHEMA: &str = "ci-lane-snapshot/v1";
/// Hard cap on the stored snapshot file so a corrupted or hostile file cannot
/// make this route allocate unbounded memory. Matches the GitHub response cap
/// this file itself produces.
const CI_LANE_SNAPSHOT_MAX_BYTES: u64 = CI_LANE_MAX_RESPONSE_BYTES as u64;

static CI_LANE_CATALOG: OnceLock<Result<Vec<CiLaneCatalogEntry>, String>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize)]
struct CiTaxonomyDocument {
    schema: String,
    repo: String,
    jobs: Vec<CiTaxonomyJob>,
}

#[derive(Clone, Debug, Deserialize)]
struct CiTaxonomyJob {
    check_name: String,
    tier: String,
    workflow: String,
    workflow_file: String,
    job_id: String,
    triggers: Vec<String>,
    path_filtered: bool,
}

/// One watched CI lane's static identity, derived from `docs/ci_taxonomy.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CiLaneCatalogEntry {
    pub(super) check_name: String,
    pub(super) tier: String,
    pub(super) workflow: String,
    pub(super) workflow_file: String,
    pub(super) job_id: String,
    pub(super) event: String,
    pub(super) path_filtered: bool,
    pub(super) whole_workflow: bool,
}

#[cfg(test)]
#[derive(Clone, Debug, Deserialize)]
struct GitHubWorkflowRuns {
    workflow_runs: Vec<GitHubWorkflowRun>,
}

#[cfg(test)]
#[derive(Clone, Debug, Deserialize)]
struct GitHubWorkflowRun {
    id: u64,
    status: String,
    conclusion: Option<String>,
    html_url: String,
    head_sha: String,
    updated_at: String,
}

#[cfg(test)]
#[derive(Clone, Debug, Deserialize)]
struct GitHubWorkflowJobs {
    jobs: Vec<GitHubWorkflowJob>,
}

#[cfg(test)]
#[derive(Clone, Debug, Deserialize)]
struct GitHubWorkflowJob {
    name: String,
    status: String,
    conclusion: Option<String>,
    html_url: String,
    completed_at: Option<String>,
}

/// One observed GitHub Actions run/job conclusion, already validated against
/// this repository.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct CiLaneObservation {
    pub(super) status: String,
    pub(super) conclusion: Option<String>,
    pub(super) run_id: u64,
    pub(super) run_url: String,
    pub(super) head_sha: String,
    pub(super) completed_at: Option<String>,
}

/// A catalog lane plus its most recent observation and streak, ready to
/// render as one tile card.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct CiLaneHealth {
    pub(super) catalog: CiLaneCatalogEntry,
    pub(super) latest: Option<CiLaneObservation>,
    pub(super) streak_conclusion: Option<String>,
    pub(super) streak_count: usize,
    pub(super) streak_capped: bool,
    pub(super) source_error: Option<String>,
}

/// The durable, on-disk unit this tile serves from. Produced by
/// `fetch_ci_lane_snapshot` (or hand-authored for a fixture); read
/// synchronously by [`operator_ci_lane_health_data`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct CiLaneSnapshot {
    pub(super) schema: String,
    pub(super) refreshed_at_unix: u64,
    pub(super) lanes: Vec<CiLaneHealth>,
    pub(super) errors: Vec<String>,
}

#[cfg(test)]
impl CiLaneSnapshot {
    /// Build a fresh, currently-timestamped snapshot from computed lane health.
    /// Production never constructs one in-process (see the module docs) — it
    /// only deserializes one via [`load_ci_lane_snapshot`]. Tests use this to
    /// build fixtures and to build what [`fetch_ci_lane_snapshot`] returns.
    #[must_use]
    pub(super) fn new(lanes: Vec<CiLaneHealth>, errors: Vec<String>) -> Self {
        Self {
            schema: CI_LANE_SNAPSHOT_SCHEMA.to_owned(),
            refreshed_at_unix: unix_now(),
            lanes,
            errors,
        }
    }
}

// ---------------------------------------------------------------------------
// Catalog: parsed once from the embedded, generated taxonomy document. Pure
// and synchronous — no I/O beyond reading the binary's own `.rodata`.
// ---------------------------------------------------------------------------

pub(super) fn parse_ci_lane_catalog(raw: &str) -> Result<Vec<CiLaneCatalogEntry>, String> {
    let document: CiTaxonomyDocument = serde_json::from_str(raw)
        .map_err(|error| format!("CI taxonomy is not valid JSON: {error}"))?;
    if document.schema != CI_LANE_TAXONOMY_SCHEMA {
        return Err(format!(
            "CI taxonomy schema must be {CI_LANE_TAXONOMY_SCHEMA}, got {}",
            document.schema
        ));
    }
    if document.repo != CI_LANE_REPO {
        return Err(format!(
            "CI taxonomy repo must be {CI_LANE_REPO}, got {}",
            document.repo
        ));
    }
    if document.jobs.len() > 256 {
        return Err("CI taxonomy exceeds the 256-job dashboard bound".to_owned());
    }

    let mut workflow_job_counts = HashMap::<String, usize>::new();
    for job in &document.jobs {
        *workflow_job_counts
            .entry(job.workflow_file.clone())
            .or_default() += 1;
    }

    let mut seen = HashSet::new();
    let mut lanes = Vec::new();
    for job in document.jobs {
        if !matches!(job.tier.as_str(), "scheduled" | "advisory") {
            continue;
        }
        if job.check_name.trim().is_empty()
            || job.workflow.trim().is_empty()
            || job.job_id.trim().is_empty()
        {
            return Err("CI taxonomy lane identity fields must be non-empty".to_owned());
        }
        if job.check_name.len() > 256 || job.workflow.len() > 128 || job.job_id.len() > 128 {
            return Err("CI taxonomy lane identity exceeds its dashboard bound".to_owned());
        }
        if !safe_workflow_file(&job.workflow_file) {
            return Err(format!(
                "CI taxonomy workflow file is not a safe basename: {}",
                job.workflow_file
            ));
        }
        let event = if job.tier == "scheduled" {
            if !job.triggers.iter().any(|trigger| trigger == "schedule") {
                return Err(format!(
                    "scheduled lane {} has no schedule trigger",
                    job.check_name
                ));
            }
            "schedule"
        } else if job.triggers.iter().any(|trigger| trigger == "push") {
            "push"
        } else if job.triggers.iter().any(|trigger| trigger == "schedule") {
            "schedule"
        } else if job.triggers.iter().any(|trigger| trigger == "pull_request") {
            "pull_request"
        } else {
            return Err(format!(
                "advisory lane {} has no observable Actions trigger",
                job.check_name
            ));
        };
        let identity = format!("{}\0{}\0{}", job.workflow_file, event, job.check_name);
        if !seen.insert(identity) {
            return Err(format!(
                "CI taxonomy repeats lane {} in {}",
                job.check_name, job.workflow_file
            ));
        }
        lanes.push(CiLaneCatalogEntry {
            whole_workflow: workflow_job_counts
                .get(&job.workflow_file)
                .is_some_and(|count| *count == 1),
            check_name: job.check_name,
            tier: job.tier,
            workflow: job.workflow,
            workflow_file: job.workflow_file,
            job_id: job.job_id,
            event: event.to_owned(),
            path_filtered: job.path_filtered,
        });
    }
    if lanes.is_empty() {
        return Err("CI taxonomy contains no scheduled or advisory lanes".to_owned());
    }
    lanes.sort_by(|left, right| {
        left.tier
            .cmp(&right.tier)
            .then_with(|| left.workflow.cmp(&right.workflow))
            .then_with(|| left.check_name.cmp(&right.check_name))
    });
    Ok(lanes)
}

fn safe_workflow_file(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && matches!(
            value.rsplit_once('.').map(|(_, extension)| extension),
            Some("yml" | "yaml")
        )
}

fn ci_lane_catalog() -> Result<&'static [CiLaneCatalogEntry], &'static str> {
    match CI_LANE_CATALOG.get_or_init(|| parse_ci_lane_catalog(CI_LANE_TAXONOMY)) {
        Ok(catalog) => Ok(catalog.as_slice()),
        Err(error) => Err(error.as_str()),
    }
}

// ---------------------------------------------------------------------------
// Async fetch: genuine `.await` all the way, no `block_on`, no reactor/runtime
// construction. Not called from the request path (see module docs) — driven
// by tests here, and available for a future scheduled caller.
// ---------------------------------------------------------------------------

/// Poll GitHub Actions for every lane in `catalog` and build a fresh
/// [`CiLaneSnapshot`]. `base_url` is the GitHub REST API origin
/// (`https://api.github.com` in production; a loopback mock in tests).
#[cfg(test)]
pub(super) async fn fetch_ci_lane_snapshot(
    cx: &Cx,
    client: &HttpClient,
    base_url: &str,
    catalog: &[CiLaneCatalogEntry],
) -> CiLaneSnapshot {
    let mut groups = BTreeMap::<(String, String), Vec<CiLaneCatalogEntry>>::new();
    for lane in catalog {
        groups
            .entry((lane.workflow_file.clone(), lane.event.clone()))
            .or_default()
            .push(lane.clone());
    }

    let mut health_by_name = HashMap::<String, CiLaneHealth>::new();
    let mut errors = Vec::new();
    for ((workflow_file, event), lanes) in groups {
        match fetch_ci_lane_group(cx, client, base_url, &workflow_file, &event, &lanes).await {
            Ok(health) => {
                for lane in health {
                    health_by_name.insert(lane.catalog.check_name.clone(), lane);
                }
            }
            Err(error) => {
                errors.push(format!("{workflow_file}: {error}"));
                for lane in lanes {
                    health_by_name.insert(
                        lane.check_name.clone(),
                        unknown_ci_lane(lane, "workflow evidence is unavailable"),
                    );
                }
            }
        }
    }
    let lanes = catalog
        .iter()
        .map(|lane| {
            health_by_name
                .remove(&lane.check_name)
                .unwrap_or_else(|| unknown_ci_lane(lane.clone(), "lane evidence was not produced"))
        })
        .collect();
    CiLaneSnapshot::new(lanes, errors)
}

#[cfg(test)]
async fn fetch_ci_lane_group(
    cx: &Cx,
    client: &HttpClient,
    base_url: &str,
    workflow_file: &str,
    event: &str,
    lanes: &[CiLaneCatalogEntry],
) -> Result<Vec<CiLaneHealth>, String> {
    let branch = if event == "push" { "&branch=main" } else { "" };
    let runs_url = format!(
        "{base_url}/repos/{CI_LANE_GITHUB_REPO}/actions/workflows/{workflow_file}/runs?event={event}&status=completed&per_page={CI_LANE_STREAK_WINDOW}{branch}"
    );
    let mut runs: GitHubWorkflowRuns = github_get_json(cx, client, &runs_url).await?;
    runs.workflow_runs
        .sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    runs.workflow_runs.truncate(CI_LANE_STREAK_WINDOW);

    if lanes.len() == 1 && lanes[0].whole_workflow {
        let observations = runs
            .workflow_runs
            .into_iter()
            .map(workflow_run_observation)
            .collect::<Vec<_>>();
        return Ok(vec![ci_lane_health_from_observations(
            lanes[0].clone(),
            &observations,
        )]);
    }

    let mut histories = lanes
        .iter()
        .map(|lane| (lane.check_name.clone(), Vec::new()))
        .collect::<HashMap<_, _>>();
    for run in runs.workflow_runs {
        let jobs_url = format!(
            "{base_url}/repos/{CI_LANE_GITHUB_REPO}/actions/runs/{}/jobs?filter=latest&per_page=100",
            run.id
        );
        let jobs: GitHubWorkflowJobs = github_get_json(cx, client, &jobs_url).await?;
        for lane in lanes {
            let matches = jobs
                .jobs
                .iter()
                .filter(|job| job.name == lane.check_name)
                .collect::<Vec<_>>();
            let observation = match matches.as_slice() {
                [job] => workflow_job_observation(&run, job),
                [] => Err(format!("job was missing from completed run {}", run.id)),
                _ => Err(format!("job was ambiguous in completed run {}", run.id)),
            };
            histories
                .get_mut(&lane.check_name)
                .expect("catalog initialized every lane history")
                .push(observation);
        }
    }
    Ok(lanes
        .iter()
        .map(|lane| {
            ci_lane_health_from_observations(
                lane.clone(),
                histories
                    .get(&lane.check_name)
                    .expect("catalog initialized every lane history"),
            )
        })
        .collect())
}

#[cfg(test)]
async fn github_get_json<T: for<'de> Deserialize<'de>>(
    cx: &Cx,
    client: &HttpClient,
    url: &str,
) -> Result<T, String> {
    let response = client
        .request(cx, Method::Get, url, Vec::new(), Vec::new())
        .await
        .map_err(|error| format!("GitHub Actions request failed: {error}"))?;
    if response.status != 200 {
        return Err(format!(
            "GitHub Actions request returned HTTP {}",
            response.status
        ));
    }
    let content_type_is_json = response.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && value.split(';').next().is_some_and(|media_type| {
                media_type.trim().eq_ignore_ascii_case("application/json")
            })
    });
    if !content_type_is_json {
        return Err("GitHub Actions response was not JSON".to_owned());
    }
    serde_json::from_slice(&response.body)
        .map_err(|error| format!("GitHub Actions response shape was invalid: {error}"))
}

#[cfg(test)]
fn workflow_run_observation(run: GitHubWorkflowRun) -> Result<CiLaneObservation, String> {
    validate_github_observation(
        run.status,
        run.conclusion,
        run.id,
        run.html_url,
        run.head_sha,
        Some(run.updated_at),
    )
}

#[cfg(test)]
fn workflow_job_observation(
    run: &GitHubWorkflowRun,
    job: &GitHubWorkflowJob,
) -> Result<CiLaneObservation, String> {
    validate_github_observation(
        job.status.clone(),
        job.conclusion.clone(),
        run.id,
        job.html_url.clone(),
        run.head_sha.clone(),
        job.completed_at
            .clone()
            .or_else(|| Some(run.updated_at.clone())),
    )
}

#[cfg(test)]
fn validate_github_observation(
    status: String,
    conclusion: Option<String>,
    run_id: u64,
    run_url: String,
    head_sha: String,
    completed_at: Option<String>,
) -> Result<CiLaneObservation, String> {
    if status != "completed" {
        return Err(format!("run {run_id} was not completed"));
    }
    let conclusion = conclusion
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("run {run_id} had no conclusion"))?;
    if !run_url.starts_with("https://github.com/MuhDur/oraclemcp/") {
        return Err(format!("run {run_id} returned an unexpected result URL"));
    }
    if head_sha.len() != 40 || !head_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("run {run_id} returned an invalid head SHA"));
    }
    Ok(CiLaneObservation {
        status,
        conclusion: Some(conclusion),
        run_id,
        run_url,
        head_sha,
        completed_at,
    })
}

#[cfg(test)]
pub(super) fn ci_lane_health_from_observations(
    catalog: CiLaneCatalogEntry,
    observations: &[Result<CiLaneObservation, String>],
) -> CiLaneHealth {
    let Some(first) = observations.first() else {
        return unknown_ci_lane(catalog, "no completed lane run was found");
    };
    let latest = match first {
        Ok(observation) => observation.clone(),
        Err(error) => return unknown_ci_lane(catalog, error),
    };
    let Some(conclusion) = latest.conclusion.clone() else {
        return unknown_ci_lane(catalog, "latest lane run had no conclusion");
    };

    let mut streak_count = 0;
    let mut source_error = None;
    for observation in observations {
        match observation {
            Ok(observation) if observation.conclusion.as_deref() == Some(conclusion.as_str()) => {
                streak_count += 1;
            }
            Ok(_) => break,
            Err(error) => {
                source_error = Some(format!("streak history is incomplete: {error}"));
                break;
            }
        }
    }
    CiLaneHealth {
        catalog,
        latest: Some(latest),
        streak_conclusion: Some(conclusion),
        streak_count,
        streak_capped: streak_count == CI_LANE_STREAK_WINDOW
            && observations.len() == CI_LANE_STREAK_WINDOW,
        source_error,
    }
}

fn unknown_ci_lane(catalog: CiLaneCatalogEntry, error: impl Into<String>) -> CiLaneHealth {
    CiLaneHealth {
        catalog,
        latest: None,
        streak_conclusion: None,
        streak_count: 0,
        streak_capped: false,
        source_error: Some(error.into()),
    }
}

// ---------------------------------------------------------------------------
// Durable storage: plain synchronous file I/O (no async, no block_on — this is
// local disk access from an already-synchronous request handler, exactly like
// every other file-backed operator route).
// ---------------------------------------------------------------------------

/// Read and validate a stored [`CiLaneSnapshot`] from `path`. `Err` covers
/// every failure mode (missing file, oversized file, invalid JSON, schema
/// mismatch) with a message safe to surface on the tile — never panics, never
/// partially trusts a corrupt file.
pub(super) fn load_ci_lane_snapshot(path: &Path) -> Result<CiLaneSnapshot, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("cannot read snapshot: {error}"))?;
    if metadata.len() > CI_LANE_SNAPSHOT_MAX_BYTES {
        return Err(format!(
            "stored CI lane snapshot exceeds the {CI_LANE_SNAPSHOT_MAX_BYTES}-byte bound"
        ));
    }
    let raw = fs::read_to_string(path).map_err(|error| format!("cannot read snapshot: {error}"))?;
    let snapshot: CiLaneSnapshot = serde_json::from_str(&raw)
        .map_err(|error| format!("stored CI lane snapshot is not valid JSON: {error}"))?;
    if snapshot.schema != CI_LANE_SNAPSHOT_SCHEMA {
        return Err(format!(
            "stored CI lane snapshot schema must be {CI_LANE_SNAPSHOT_SCHEMA}, got {}",
            snapshot.schema
        ));
    }
    Ok(snapshot)
}

/// Durably write `snapshot` to `path` (write-temp then rename, so a reader
/// never observes a torn file). Used by tests today; a future scheduled
/// refresher is the production caller (see the module docs). Never called
/// from the request path.
#[cfg(test)]
pub(super) fn write_ci_lane_snapshot(path: &Path, snapshot: &CiLaneSnapshot) -> Result<(), String> {
    let body = serde_json::to_vec(snapshot)
        .map_err(|error| format!("CI lane snapshot does not serialize: {error}"))?;
    let mut tmp_path = path.to_path_buf();
    let tmp_name = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => format!(".{name}.tmp"),
        None => return Err("CI lane snapshot path has no file name".to_owned()),
    };
    tmp_path.set_file_name(tmp_name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create snapshot directory: {error}"))?;
    }
    fs::write(&tmp_path, &body).map_err(|error| format!("cannot write snapshot: {error}"))?;
    fs::rename(&tmp_path, path).map_err(|error| format!("cannot install snapshot: {error}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Rendering: pure and synchronous, combining the always-available catalog with
// whatever stored snapshot (if any) is currently on disk.
// ---------------------------------------------------------------------------

/// Synchronous `/operator/v1/ci-lanes` handler. Never touches the network and
/// never blocks on an async future — see the module docs for why.
pub(super) fn operator_ci_lane_health_data(config: &HttpTransportConfig) -> Value {
    let catalog = match ci_lane_catalog() {
        Ok(catalog) => catalog,
        Err(error) => {
            return json!({
                "source": "unavailable",
                "catalog_schema": CI_LANE_TAXONOMY_SCHEMA,
                "catalog_complete": false,
                "repo": CI_LANE_GITHUB_REPO,
                "refresh_state": "failed",
                "freshness": "unavailable",
                "refreshed_at": null,
                "last_attempt_at": null,
                "age_seconds": null,
                "streak_window": CI_LANE_STREAK_WINDOW,
                "refresh_interval_seconds": CI_LANE_REFRESH_INTERVAL.as_secs(),
                "stale_after_seconds": CI_LANE_STALE_AFTER.as_secs(),
                "summary": { "posture": "unknown", "total": 0, "success": 0, "not_green": 0, "unknown": 0 },
                "lanes": [],
                "errors": [error],
            });
        }
    };

    let loaded = match &config.ci_lane_snapshot_path {
        Some(path) => match load_ci_lane_snapshot(path) {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => Err(error),
        },
        None => Err("no CI lane snapshot is configured for this transport".to_owned()),
    };
    render_ci_lane_health_data(catalog, loaded.as_ref().ok(), loaded.as_ref().err())
}

fn render_ci_lane_health_data(
    catalog: &[CiLaneCatalogEntry],
    snapshot: Option<&CiLaneSnapshot>,
    load_error: Option<&String>,
) -> Value {
    let now = unix_now();
    let by_identity = snapshot
        .map(|snapshot| {
            snapshot
                .lanes
                .iter()
                .map(|lane| {
                    (
                        (
                            lane.catalog.workflow_file.clone(),
                            lane.catalog.event.clone(),
                            lane.catalog.check_name.clone(),
                        ),
                        lane.clone(),
                    )
                })
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();

    let age_seconds = snapshot.map(|snapshot| now.saturating_sub(snapshot.refreshed_at_unix));
    let stale = match age_seconds {
        Some(age) => age >= CI_LANE_STALE_AFTER.as_secs(),
        None => true,
    };
    let health: Vec<CiLaneHealth> = catalog
        .iter()
        .map(|entry| {
            let key = (
                entry.workflow_file.clone(),
                entry.event.clone(),
                entry.check_name.clone(),
            );
            by_identity.get(&key).cloned().unwrap_or_else(|| {
                unknown_ci_lane(
                    entry.clone(),
                    if snapshot.is_some() {
                        "lane evidence was not produced by the stored snapshot"
                    } else {
                        "lane evidence has not been captured yet"
                    },
                )
            })
        })
        .collect();

    let lanes = health
        .iter()
        .map(|lane| ci_lane_health_json(lane, stale))
        .collect::<Vec<_>>();
    let success = lanes
        .iter()
        .filter(|lane| lane["state"] == "success")
        .count();
    let not_green = lanes
        .iter()
        .filter(|lane| lane["state"] == "not_green")
        .count();
    let unknown = lanes.len().saturating_sub(success + not_green);

    let mut errors = snapshot
        .map(|snapshot| snapshot.errors.clone())
        .unwrap_or_default();
    if let Some(error) = load_error {
        errors.push(error.clone());
    }
    let posture = if unknown > 0 || !errors.is_empty() {
        "unknown"
    } else if not_green > 0 {
        "not_green"
    } else {
        "green"
    };
    let freshness = match (snapshot, stale) {
        (None, _) => "unavailable",
        (Some(_), true) => "stale",
        (Some(_), false) => "fresh",
    };
    let source = match (snapshot, errors.is_empty()) {
        (None, _) => "unavailable",
        (Some(_), true) => "github_actions",
        (Some(_), false) => "github_actions_partial",
    };
    json!({
        "source": source,
        "catalog_schema": CI_LANE_TAXONOMY_SCHEMA,
        "catalog_complete": true,
        "repo": CI_LANE_GITHUB_REPO,
        "refresh_state": if snapshot.is_some() { "ready" } else { "failed" },
        "freshness": freshness,
        "refreshed_at": snapshot.map(|snapshot| format!("unix:{}", snapshot.refreshed_at_unix)),
        "last_attempt_at": snapshot.map(|snapshot| format!("unix:{}", snapshot.refreshed_at_unix)),
        "age_seconds": age_seconds,
        "streak_window": CI_LANE_STREAK_WINDOW,
        "refresh_interval_seconds": CI_LANE_REFRESH_INTERVAL.as_secs(),
        "stale_after_seconds": CI_LANE_STALE_AFTER.as_secs(),
        "summary": {
            "posture": posture,
            "total": lanes.len(),
            "success": success,
            "not_green": not_green,
            "unknown": unknown,
        },
        "lanes": lanes,
        "errors": errors,
    })
}

pub(super) fn ci_lane_health_json(lane: &CiLaneHealth, stale: bool) -> Value {
    let source_error = lane.source_error.as_deref();
    let conclusion = lane
        .latest
        .as_ref()
        .and_then(|latest| latest.conclusion.as_deref());
    let state = if stale || source_error.is_some() || conclusion.is_none() {
        "unknown"
    } else if conclusion == Some("success") {
        "success"
    } else {
        "not_green"
    };
    json!({
        "check_name": lane.catalog.check_name,
        "tier": lane.catalog.tier,
        "workflow": lane.catalog.workflow,
        "workflow_file": lane.catalog.workflow_file,
        "job_id": lane.catalog.job_id,
        "event": lane.catalog.event,
        "path_filtered": lane.catalog.path_filtered,
        "state": state,
        "last_status": lane.latest.as_ref().map(|latest| latest.status.as_str()),
        "last_conclusion": conclusion,
        "streak": {
            "conclusion": lane.streak_conclusion,
            "count": lane.streak_count,
            "capped": lane.streak_capped,
        },
        "run_id": lane.latest.as_ref().map(|latest| latest.run_id),
        "run_url": lane.latest.as_ref().map(|latest| latest.run_url.as_str()),
        "head_sha": lane.latest.as_ref().map(|latest| latest.head_sha.as_str()),
        "completed_at": lane.latest.as_ref().and_then(|latest| latest.completed_at.as_deref()),
        "source_error": source_error,
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
