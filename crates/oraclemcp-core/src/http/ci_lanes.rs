//! `/operator/v1/ci-lanes`: the Ground Control CI-lane-health tile.
//!
//! Every `scheduled` and `advisory` job in `docs/ci_taxonomy.json` (the
//! generated, single-source-of-truth CI taxonomy) is a "lane" this tile
//! watches. The point is the plan's own framing: **the operator must never
//! discover a red lane first** — a scheduled nightly or an advisory check that
//! goes red should be visible on the dashboard, not only in a GitHub Actions
//! inbox nobody is watching.
//!
//! # Two halves
//!
//! 1. `fetch_ci_lane_snapshot` (test-only — see below) is a
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
//! # Production evidence source: the CI heartbeat snapshot (E4 follow-up)
//!
//! The production writer of that file is the E4 CI heartbeat notifier
//! (`scripts/ci_heartbeat.sh`, driven every 30 minutes by
//! `.github/workflows/ci-heartbeat.yml`, or run locally / from cron by the
//! operator). It durably writes a `ci-heartbeat/v1` JSON snapshot to
//! `CI_HEARTBEAT_OUTPUT` (default `$XDG_STATE_HOME/oraclemcp/ci-heartbeat.json`),
//! and `oraclemcp serve` points [`HttpTransportConfig::ci_lane_snapshot_path`]
//! at that same default. [`load_ci_lane_snapshot`] accepts either the native
//! `ci-lane-snapshot/v1` schema or `ci-heartbeat/v1`, converting the latter
//! onto the taxonomy catalog. The ingest is deliberately conservative:
//!
//! - The heartbeat records **workflow-level** run conclusions, so only a
//!   whole-workflow `scheduled` lane may adopt one. Advisory per-job lanes
//!   (`continue-on-error` jobs whose failure never reddens their workflow run)
//!   and the heartbeat's own lane (which it excludes from self-observation)
//!   stay `unknown` — a green required workflow must never paint an advisory
//!   job green.
//! - The heartbeat's exit-code semantics are untouched and not re-derived
//!   here: required lanes drive its exit code, scheduled lanes are
//!   advisory-only. Its `blocked` flag is surfaced as a tile error so a red or
//!   unknown required lane keeps the summary posture away from green.
//! - Fail-closed-to-unknown is retained end to end: a missing, oversized,
//!   malformed, wrong-schema, stale, or future-dated (beyond
//!   [`CI_LANE_MAX_FUTURE_SKEW`]) snapshot renders `unknown`/`unavailable`,
//!   never a fabricated green, and every adopted observation is re-validated
//!   (repository-scoped run URL, 40-hex SHA, completed conclusion, state and
//!   conclusion in agreement) before it may render at all.
//!
//! Because no in-tree caller drives it, `fetch_ci_lane_snapshot` and its
//! HTTP-fetch helpers below still compile only under `#[cfg(test)]` — Rust's
//! own dead-code analysis is correctly strict about code with zero non-test
//! call sites, and adding a speculative production caller just to silence it
//! would be worse than being honest about the current wiring. This crate's
//! test suite drives that pipeline end to end against a local mock GitHub
//! server (see `tests_ci_lanes.rs`), proving the async design. A future bead
//! that adds a per-job-granular Rust-side scheduled caller (richer than the
//! heartbeat's workflow-level view) removes those `#[cfg(test)]` gates
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
/// The explicit freshness window with fail-closed expiry: a stored snapshot
/// older than this renders every lane `unknown`. Sized to exactly two CI
/// heartbeat cycles (`.github/workflows/ci-heartbeat.yml` runs `*/30 * * * *`),
/// so one late or superseded heartbeat run does not flap the tile to unknown,
/// while two missed beats — the heartbeat being down is itself a silent gap —
/// always do.
const CI_LANE_STALE_AFTER: Duration = Duration::from_secs(60 * 60);
/// How far in the future a snapshot's own timestamp may sit (small NTP skew
/// between the heartbeat host and this host) before the snapshot is treated as
/// expired. Without this bound a future-dated timestamp would render "fresh"
/// forever — a lying clock must fail closed like every other lying input.
const CI_LANE_MAX_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);
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
/// Schema tag of the CI heartbeat notifier's snapshot file
/// (`scripts/ci_heartbeat.sh`). Any other tag fails closed in
/// [`load_ci_lane_snapshot`].
const CI_HEARTBEAT_SCHEMA: &str = "ci-heartbeat/v1";
/// The heartbeat prefixes each recorded lane's `check_name` with its own tier
/// label; a server scheduled workflow `foo.yml` records as `scheduled:foo.yml`.
const CI_HEARTBEAT_SCHEDULED_PREFIX: &str = "scheduled:";

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
// Heartbeat ingestion: pure conversion of the CI heartbeat notifier's
// `ci-heartbeat/v1` snapshot (scripts/ci_heartbeat.sh) onto the taxonomy
// catalog. No network, no clock reads — the snapshot carries its own
// `generated_at`, and staleness is judged against it at render time.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
struct CiHeartbeatDocument {
    schema: String,
    generated_at: String,
    /// Required, not defaulted: a heartbeat snapshot that cannot say whether a
    /// required lane is blocked is malformed and must fail closed as a whole.
    blocked: bool,
    /// These are part of the writer's v1 contract, not advisory duplicates:
    /// requiring them to agree with `blocked` catches torn or hand-edited
    /// snapshots before they can suppress the required-lane posture.
    any_red: bool,
    any_unknown: bool,
    lanes: Vec<CiHeartbeatLane>,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct CiHeartbeatLane {
    repo: String,
    check_name: String,
    tier: String,
    state: String,
    conclusion: Option<String>,
    run_url: Option<String>,
    head_sha: Option<String>,
    updated_at: Option<String>,
}

/// Convert a raw `ci-heartbeat/v1` document into the catalog-shaped
/// [`CiLaneSnapshot`] the tile renders. Only a whole-workflow `scheduled`
/// catalog lane may adopt a heartbeat observation (the heartbeat records
/// workflow-level run conclusions); every other lane stays `unknown` with an
/// honest reason. `Err` covers structural failure of the document itself.
pub(super) fn ci_lane_snapshot_from_heartbeat(
    catalog: &[CiLaneCatalogEntry],
    raw: &str,
) -> Result<CiLaneSnapshot, String> {
    let document: CiHeartbeatDocument = serde_json::from_str(raw)
        .map_err(|error| format!("CI heartbeat snapshot shape is invalid: {error}"))?;
    if document.schema != CI_HEARTBEAT_SCHEMA {
        return Err(format!(
            "CI heartbeat snapshot schema must be {CI_HEARTBEAT_SCHEMA}, got {}",
            document.schema
        ));
    }
    if document.lanes.len() > 256 || document.errors.len() > 64 {
        return Err("CI heartbeat snapshot exceeds its dashboard bound".to_owned());
    }
    if document.blocked != (document.any_red || document.any_unknown) {
        return Err(
            "CI heartbeat snapshot blocked verdict contradicts its red/unknown flags".to_owned(),
        );
    }
    let refreshed_at_unix = parse_ci_heartbeat_generated_at(&document.generated_at)?;
    let lanes = catalog
        .iter()
        .map(|entry| heartbeat_lane_health(entry, &document.lanes, refreshed_at_unix))
        .collect();
    let mut errors = document.errors;
    if document.blocked {
        // Never re-derive the heartbeat's required-vs-advisory exit semantics
        // here; carry its own verdict forward so a red or unknown REQUIRED
        // lane (which this tile's scheduled/advisory catalog does not list)
        // still keeps the summary posture away from green.
        errors.push(
            "the CI heartbeat reports a blocked lane: at least one required lane is red or unknown"
                .to_owned(),
        );
    }
    Ok(CiLaneSnapshot {
        schema: CI_LANE_SNAPSHOT_SCHEMA.to_owned(),
        refreshed_at_unix,
        lanes,
        errors,
    })
}

/// Resolve one catalog lane against the heartbeat's recorded lanes,
/// fail-closed: anything short of an unambiguous, self-consistent, completed
/// observation of this repository renders `unknown`.
fn heartbeat_lane_health(
    entry: &CiLaneCatalogEntry,
    lanes: &[CiHeartbeatLane],
    refreshed_at_unix: u64,
) -> CiLaneHealth {
    if entry.tier != "scheduled" || !entry.whole_workflow {
        return unknown_ci_lane(
            entry.clone(),
            "the CI heartbeat records workflow-level conclusions only; \
             this per-job lane has no heartbeat evidence",
        );
    }
    let check_name = format!("{CI_HEARTBEAT_SCHEDULED_PREFIX}{}", entry.workflow_file);
    let matches = lanes
        .iter()
        .filter(|lane| lane.repo == CI_LANE_GITHUB_REPO && lane.check_name == check_name)
        .collect::<Vec<_>>();
    let lane = match matches.as_slice() {
        [lane] => *lane,
        [] => {
            return unknown_ci_lane(
                entry.clone(),
                "the CI heartbeat snapshot has no observation for this lane",
            );
        }
        _ => {
            return unknown_ci_lane(
                entry.clone(),
                "the CI heartbeat snapshot records this lane ambiguously",
            );
        }
    };
    if lane.tier != "scheduled" {
        return unknown_ci_lane(
            entry.clone(),
            "the CI heartbeat lane tier contradicts its scheduled identity",
        );
    }
    // The recorded `state` and `conclusion` must agree before either may
    // render: contradictory evidence (say, `state: not_green` next to
    // `conclusion: success`) proves the file cannot be trusted for this lane.
    let conclusion = lane.conclusion.as_deref().unwrap_or("");
    let consistent = match lane.state.as_str() {
        "success" => conclusion == "success",
        "not_green" => !conclusion.is_empty() && conclusion != "success",
        _ => {
            return unknown_ci_lane(
                entry.clone(),
                "the CI heartbeat could not observe this lane",
            );
        }
    };
    if !consistent {
        return unknown_ci_lane(
            entry.clone(),
            "the CI heartbeat lane state contradicts its recorded conclusion",
        );
    }
    let (Some(run_url), Some(head_sha), Some(updated_at)) = (
        lane.run_url.clone(),
        lane.head_sha.clone(),
        lane.updated_at.clone(),
    ) else {
        return unknown_ci_lane(
            entry.clone(),
            "the CI heartbeat observation is missing its run evidence",
        );
    };
    let run_id = match heartbeat_run_id(&run_url) {
        Ok(run_id) => run_id,
        Err(error) => return unknown_ci_lane(entry.clone(), error),
    };
    let updated_at_unix = match parse_ci_heartbeat_timestamp(&updated_at, "lane updated_at") {
        Ok(updated_at_unix) => updated_at_unix,
        Err(error) => return unknown_ci_lane(entry.clone(), error),
    };
    if updated_at_unix > refreshed_at_unix.saturating_add(CI_LANE_MAX_FUTURE_SKEW.as_secs()) {
        return unknown_ci_lane(
            entry.clone(),
            "the CI heartbeat lane was updated after the snapshot was generated",
        );
    }
    // The heartbeat only records completed, non-superseded runs, and the
    // conclusion is present and consistent by this point; re-validate the
    // observation with the same rules the GitHub fetch path applies.
    let observation = validate_github_observation(
        "completed".to_owned(),
        lane.conclusion.clone(),
        run_id,
        run_url,
        head_sha,
        Some(updated_at),
    );
    match observation {
        Ok(observation) => ci_lane_health_from_observations(entry.clone(), &[Ok(observation)]),
        Err(error) => unknown_ci_lane(entry.clone(), error),
    }
}

fn heartbeat_run_id(run_url: &str) -> Result<u64, String> {
    let run_id = run_url
        .strip_prefix("https://github.com/MuhDur/oraclemcp/actions/runs/")
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|digits| digits.parse::<u64>().ok())
        .filter(|run_id| *run_id > 0);
    run_id
        .ok_or_else(|| "the CI heartbeat run URL does not name a run in this repository".to_owned())
}

/// Parse the heartbeat's `generated_at` (`date -u +%Y-%m-%dT%H:%M:%SZ`) as
/// strict UTC seconds. Anything else — offsets, fractions, missing `Z`,
/// out-of-range fields — fails closed; a snapshot whose age cannot be proven
/// must not render as evidence.
pub(super) fn parse_ci_heartbeat_generated_at(value: &str) -> Result<u64, String> {
    parse_ci_heartbeat_timestamp(value, "generated_at")
}

fn parse_ci_heartbeat_timestamp(value: &str, field_name: &str) -> Result<u64, String> {
    let malformed =
        || format!("CI heartbeat {field_name} is not strict UTC (YYYY-MM-DDTHH:MM:SSZ): {value}");
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(malformed());
    }
    let field = |range: std::ops::Range<usize>| -> Result<u64, String> {
        let digits = &value[range];
        if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(malformed());
        }
        digits.parse::<u64>().map_err(|_| malformed())
    };
    let year = field(0..4)?;
    let month = field(5..7)?;
    let day = field(8..10)?;
    let hour = field(11..13)?;
    let minute = field(14..16)?;
    let second = field(17..19)?;
    let leap_year = |year: u64| {
        (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
    };
    let month_days = |year: u64| -> [u64; 12] {
        let february = if leap_year(year) { 29 } else { 28 };
        [31, february, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    if year < 1970
        || !(1..=12).contains(&month)
        || day == 0
        || day > month_days(year)[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(malformed());
    }
    let days_in_prior_years: u64 = (1970..year)
        .map(|prior| if leap_year(prior) { 366 } else { 365 })
        .sum();
    let days_in_prior_months: u64 = month_days(year)[..(month - 1) as usize].iter().sum();
    let days = days_in_prior_years + days_in_prior_months + (day - 1);
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

// ---------------------------------------------------------------------------
// Durable storage: plain synchronous file I/O (no async, no block_on — this is
// local disk access from an already-synchronous request handler, exactly like
// every other file-backed operator route).
// ---------------------------------------------------------------------------

/// Read and validate a stored [`CiLaneSnapshot`] from `path`. The file may be
/// the native `ci-lane-snapshot/v1` format or the CI heartbeat notifier's
/// `ci-heartbeat/v1` output, which is converted onto the embedded taxonomy
/// catalog. `Err` covers every failure mode (missing file, oversized file,
/// invalid JSON, schema mismatch, malformed heartbeat) with a message safe to
/// surface on the tile — never panics, never partially trusts a corrupt file.
pub(super) fn load_ci_lane_snapshot(path: &Path) -> Result<CiLaneSnapshot, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("cannot read snapshot: {error}"))?;
    if metadata.len() > CI_LANE_SNAPSHOT_MAX_BYTES {
        return Err(format!(
            "stored CI lane snapshot exceeds the {CI_LANE_SNAPSHOT_MAX_BYTES}-byte bound"
        ));
    }
    let raw = fs::read_to_string(path).map_err(|error| format!("cannot read snapshot: {error}"))?;
    #[derive(Deserialize)]
    struct SchemaProbe {
        schema: String,
    }
    let probe: SchemaProbe = serde_json::from_str(&raw)
        .map_err(|error| format!("stored CI lane snapshot is not valid JSON: {error}"))?;
    match probe.schema.as_str() {
        CI_LANE_SNAPSHOT_SCHEMA => serde_json::from_str(&raw)
            .map_err(|error| format!("stored CI lane snapshot shape is invalid: {error}")),
        CI_HEARTBEAT_SCHEMA => {
            let catalog = ci_lane_catalog().map_err(str::to_owned)?;
            ci_lane_snapshot_from_heartbeat(catalog, &raw)
        }
        other => Err(format!(
            "stored CI lane snapshot schema must be {CI_LANE_SNAPSHOT_SCHEMA} or \
             {CI_HEARTBEAT_SCHEMA}, got {other}"
        )),
    }
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

pub(super) fn render_ci_lane_health_data(
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
    let stale = match (snapshot, age_seconds) {
        (Some(snapshot), Some(age)) => {
            // Fail closed on both directions of clock trouble: an old snapshot
            // has expired, and a future-dated one (beyond small NTP skew)
            // would otherwise saturate to age 0 and render "fresh" forever off
            // a timestamp that cannot be honest.
            age >= CI_LANE_STALE_AFTER.as_secs()
                || snapshot.refreshed_at_unix
                    > now.saturating_add(CI_LANE_MAX_FUTURE_SKEW.as_secs())
        }
        _ => true,
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
