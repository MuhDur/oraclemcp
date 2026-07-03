//! `oraclemcp setup --discover` — consent-gated TNS discovery onboarding.
//!
//! Wires the library pieces built by the earlier slices into the user-facing
//! flow (TNS-onboarding beads `.4`, `.10`–`.14`; design spec §A–§F,
//! [`docs/tns-discovery-onboarding.md`](../../../docs/tns-discovery-onboarding.md)):
//!
//! - the pure-`std` search-path resolver + the `tnsnames.ora` parse adapter
//!   ([`oraclemcp_config::discovery::resolve_candidate_dirs`] and
//!   [`oraclemcp_db::parse_tnsnames_dir`]),
//! - the config-owned net-service → profile synthesis
//!   ([`oraclemcp_config::discovery::synthesize_profiles`]) fed through the
//!   binary-owned `TnsNetService → DiscoveredNetService` bridge,
//! - the annotated safe-config writer
//!   ([`oraclemcp_config::discovery::render_annotated_config`]),
//! - and the config-ops backend (backup + atomic replace + strict revalidate).
//!
//! # Consent (bead `.4`, SAFETY-CRITICAL; design spec §D)
//!
//! Discovery **never scans without consent** and **never prompts a
//! non-interactive caller**:
//!
//! - a human on a TTY is asked interactively before any write,
//! - an agent / CI / any non-TTY caller must pass an explicit flag
//!   (`--discover-tns` or `--yes`); without it a non-TTY invocation **refuses**
//!   to scan or write and exits `2` (`usage_config_or_safety_block`).
//!
//! Scan consent and write consent are distinct: on a TTY the scan happens (the
//! candidate directories and net-services are reported) and only the *write* is
//! prompted; a `--dry-run` scans and previews but never writes.

use std::collections::BTreeSet;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oraclemcp_config::OracleMcpConfig;
use oraclemcp_config::discovery::synth::{
    ConnectStringKind, DiscoveredNetService, SynthOptions, SynthesizedProfile, synthesize_profiles,
};
use oraclemcp_config::discovery::{
    DiscoverySynthesis, TnsCandidateDir, render_annotated_config, resolve_candidate_dirs,
};
use oraclemcp_db::{TnsNetService, parse_tnsnames_dir};

/// Structured-error code for a discovery consent refusal (maps to exit `2`,
/// `usage_config_or_safety_block`).
pub(crate) const CONSENT_REFUSED_CODE: &str = "ORACLEMCP_DISCOVER_CONSENT_REQUIRED";

/// The exact non-TTY scan refusal (design spec §D).
///
/// Deviation from the spec's literal wording: the spec sentence names
/// `--discover`, but in the implemented flag model `--discover` only *selects*
/// discovery mode (it is already present on the refusing invocation), while the
/// flag that actually grants non-interactive consent is `--discover-tns` (or the
/// broader `--yes`). Naming the already-passed mode flag would be a no-op
/// instruction and violates bead `.4`'s "name the exact flag" requirement, so
/// the refusal names the real consent flag while preserving the spec sentence
/// structure. honesty-allow: documented flag-name reconciliation, not framing.
pub(crate) const SCAN_REFUSAL: &str = "refusing to scan for tnsnames.ora without consent: re-run on an interactive terminal, or pass --discover-tns (or --yes) to consent explicitly (non-interactive).";

/// The consent-relevant inputs for one `setup --discover` invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DiscoverFlags {
    /// Whether stdin is an interactive terminal.
    pub interactive: bool,
    /// `--discover-tns`: explicit non-interactive consent to scan and write.
    pub discover_tns: bool,
    /// `--yes`: explicit non-interactive consent to scan and write.
    pub yes: bool,
    /// `--dry-run`: scan and preview, never write.
    pub dry_run: bool,
}

impl DiscoverFlags {
    /// Whether the caller granted explicit non-interactive consent.
    fn has_explicit_consent(&self) -> bool {
        self.discover_tns || self.yes
    }

    /// Whether scanning the filesystem for `tnsnames.ora` is consented.
    ///
    /// An interactive session consents by being interactive (the scan reads
    /// files read-only and reports what it finds before any write); a non-TTY
    /// caller consents only with an explicit flag.
    pub(crate) fn scan_consented(&self) -> bool {
        self.interactive || self.has_explicit_consent()
    }
}

/// The distinct write-consent decision, resolved only *after* a successful,
/// consented scan (design spec §D — scan and write consent are separate steps).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteDecision {
    /// Proceed to write the (merged) config through config-ops.
    Write,
    /// `--dry-run`: report the plan and write nothing.
    DryRun,
    /// The interactive operator declined the write prompt (exit 0, no-op).
    Declined,
}

/// Resolve write consent. `prompt` is invoked only in the interactive,
/// no-explicit-consent case and returns whether the operator answered yes.
///
/// Fails closed: a non-interactive caller that somehow reaches here without an
/// explicit consent flag is treated as declined (never writes). In practice the
/// scan gate refuses that caller before this point.
pub(crate) fn resolve_write_consent<F: FnOnce() -> bool>(
    flags: &DiscoverFlags,
    prompt: F,
) -> WriteDecision {
    if flags.dry_run {
        return WriteDecision::DryRun;
    }
    if flags.has_explicit_consent() {
        return WriteDecision::Write;
    }
    if flags.interactive {
        if prompt() {
            WriteDecision::Write
        } else {
            WriteDecision::Declined
        }
    } else {
        WriteDecision::Declined
    }
}

/// `""` for a plural count, `"s"` for a singular one — for `net-service(s)` /
/// `read-only profile(s)` in the spec §D lines.
fn plural_s(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// `candidate directory` / `candidate directories` for the spec §D
/// `candidate director(y|ies)` fragment.
fn candidate_dirs_phrase(n: usize) -> &'static str {
    if n == 1 {
        "candidate directory"
    } else {
        "candidate directories"
    }
}

/// The exact TTY write prompt (design spec §D): `Write <K> read-only profile(s)
/// to <path>? [y/N]:` — a trailing space follows the colon so the caller's
/// answer echoes on the same line.
pub(crate) fn write_prompt(profiles: usize, target: &Path) -> String {
    format!(
        "Write {profiles} read-only profile{} to {}? [y/N]: ",
        plural_s(profiles),
        target.display()
    )
}

/// The exact success line (design spec §D, stderr, exit 0): `discovered <N>
/// net-service(s) across <M> candidate director(y|ies); wrote <K> read-only
/// profile(s) to <path>.`
pub(crate) fn success_line(
    services: usize,
    directories: usize,
    profiles_written: usize,
    target: &Path,
) -> String {
    format!(
        "discovered {services} net-service{} across {directories} {}; wrote {profiles_written} read-only profile{} to {}.",
        plural_s(services),
        candidate_dirs_phrase(directories),
        plural_s(profiles_written),
        target.display()
    )
}

/// Whether the process is running with an interactive stdin.
pub(crate) fn stdin_is_interactive() -> bool {
    std::io::stdin().is_terminal()
}

/// Bridge one `oraclemcp-db` [`TnsNetService`] into the config-owned
/// [`DiscoveredNetService`] the synthesizer consumes (design spec §B). The raw
/// connect descriptor never crosses the seam — only the non-sensitive alias and
/// hints do — so a descriptor that ever embedded a credential cannot leak into
/// synthesis, the report, or the written file.
fn bridge_service(service: &TnsNetService) -> DiscoveredNetService {
    DiscoveredNetService {
        alias: service.service_name.clone(),
        protocol: service.hints.protocol.clone(),
        host: service.hints.host.clone(),
        port: service.hints.port,
        service_name: service.hints.service_name.clone(),
        wallet_location: service.hints.wallet_location.clone(),
    }
}

/// The result of a consented scan across the candidate directories.
struct DiscoveryScan {
    /// Every candidate directory, in precedence order, for the operator report.
    candidates: Vec<TnsCandidateDir>,
    /// The net-services from the authoritative directory (first that yielded any).
    services: Vec<TnsNetService>,
    /// The authoritative directory the net-services came from, when one yielded.
    authoritative_dir: Option<PathBuf>,
    /// Non-fatal scan notes (e.g. an `IFILE` cycle in a candidate directory).
    notes: Vec<String>,
}

/// Scan the candidate directories for `tnsnames.ora` (design spec §A):
/// scan-all-for-report, but the first directory that actually yields
/// net-services is authoritative. Degrades gracefully — a parse error in one
/// candidate becomes a note, never a hard failure.
fn scan_for_net_services() -> DiscoveryScan {
    let candidates = resolve_candidate_dirs();
    let mut services = Vec::new();
    let mut authoritative_dir = None;
    let mut notes = Vec::new();

    for candidate in &candidates {
        if !candidate.exists() || !candidate.has_tnsnames_ora || authoritative_dir.is_some() {
            continue;
        }
        let dir = candidate.canonical.as_deref().unwrap_or(&candidate.path);
        match parse_tnsnames_dir(dir) {
            Ok(result) if !result.services.is_empty() => {
                services = result.services;
                authoritative_dir = Some(candidate.path.clone());
            }
            Ok(_) => {}
            Err(error) => notes.push(format!("{}: {error}", candidate.path.display())),
        }
    }

    DiscoveryScan {
        candidates,
        services,
        authoritative_dir,
        notes,
    }
}

/// Synthesize governed, least-privilege profiles from the scanned net-services
/// (design spec §B) using the default thin-reference (alias) connect-string
/// strategy: the setup wrapper points `TNS_ADMIN` at the shared `tnsnames.ora`,
/// so an alias resolves and each profile stays a small reference.
fn synthesize(services: &[TnsNetService]) -> DiscoverySynthesis {
    let bridged: Vec<DiscoveredNetService> = services.iter().map(bridge_service).collect();
    synthesize_profiles(&bridged, &SynthOptions::default())
}

/// A short, stable status label for one candidate directory in the report.
fn candidate_status_label(candidate: &TnsCandidateDir) -> &'static str {
    use oraclemcp_config::discovery::CandidateStatus;
    match candidate.status {
        CandidateStatus::Exists if candidate.has_tnsnames_ora => "found",
        CandidateStatus::Exists => "empty",
        CandidateStatus::Missing => "missing",
        CandidateStatus::Skipped => "skipped",
    }
}

/// Render the human discovery report (candidate directories scanned,
/// net-services found, and the env vars to export) to `out`.
fn render_human_report(out: &mut String, scan: &DiscoveryScan, synth: &DiscoverySynthesis) {
    out.push_str("oraclemcp setup --discover\n\n");
    out.push_str(&format!(
        "Searched {} {} for tnsnames.ora (precedence order):\n",
        scan.candidates.len(),
        candidate_dirs_phrase(scan.candidates.len())
    ));
    for candidate in &scan.candidates {
        out.push_str(&format!(
            "  [{status}] {source}: {path} — {note}\n",
            status = candidate_status_label(candidate),
            source = candidate.source.label(),
            path = candidate.path.display(),
            note = candidate.note,
        ));
    }
    for note in &scan.notes {
        out.push_str(&format!("  note: {note}\n"));
    }
    out.push('\n');

    match &scan.authoritative_dir {
        Some(dir) => out.push_str(&format!(
            "Discovered {} net-service{} in {}:\n",
            scan.services.len(),
            plural_s(scan.services.len()),
            dir.display()
        )),
        None => out.push_str("No net-services were discovered in any candidate directory.\n"),
    }
    for synth_profile in &synth.profiles {
        out.push_str(&format!(
            "  {alias} -> profile {name}\n",
            alias = synth_profile.plan.source_alias,
            name = synth_profile.plan.profile_name,
        ));
    }
    for note in &synth.notes {
        out.push_str(&format!("  note: {note}\n"));
    }

    let env_vars = synth.required_env_vars();
    if !env_vars.is_empty() {
        out.push_str(
            "\nEnvironment variables to export before going live (values never written to disk):\n",
        );
        for (profile, var) in &env_vars {
            out.push_str(&format!("  {var}  (profile {profile})\n"));
        }
    }
}

/// The template profile name / credential env var for the zero-found
/// minimal-starter fallback (parity with `setup --write`'s defaults).
const FALLBACK_PROFILE: &str = "db_ro";
const FALLBACK_CREDENTIAL_ENV: &str = "ORACLE_APP_PASSWORD";

/// The add-only write plan derived from a consented scan (design spec §E).
///
/// The bytes to write are chosen non-destructively: a fresh/empty target gets
/// the full generated config; a non-empty target gets **only** the new
/// `[[profiles]]` blocks appended, leaving every existing profile, comment, and
/// hand-edit byte-untouched. `draft` is `None` when there is nothing to write
/// (the idempotent second-run / already-configured case).
struct DiscoveryPlan {
    /// The exact current target bytes the plan was computed from (the
    /// verify-before-mutate base for the config-ops apply).
    base_bytes: Vec<u8>,
    /// Profile names that will be written (new, not already configured).
    new_profiles: Vec<String>,
    /// Profile names skipped because a profile of that name already exists.
    skipped_profiles: Vec<String>,
    /// The bytes to write, or `None` when nothing is new (idempotent no-op).
    draft: Option<String>,
    /// Whether the draft is a full fresh render (vs an add-only merge append).
    fresh: bool,
    /// Whether the zero-found minimal-starter fallback was used.
    fallback_used: bool,
}

/// The distinct kinds of `draft` outcome the human/JSON report distinguishes.
fn parse_existing(base_bytes: &[u8], target: &Path) -> Result<Option<OracleMcpConfig>, String> {
    if base_bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let text = std::str::from_utf8(base_bytes)
        .map_err(|_| format!("existing config at {} is not valid UTF-8", target.display()))?;
    OracleMcpConfig::from_toml_str(text).map(Some).map_err(|_| {
        format!(
            "existing config at {} is not valid; review or move it before running discovery",
            target.display()
        )
    })
}

/// Render only the `[[profiles]]` blocks for `new_names`, for an add-only merge
/// append. Reuses the annotated writer on a filtered synthesis, then drops the
/// header / top-level / safety-comment preamble so nothing above the first
/// profile block is duplicated into an existing file.
fn render_new_profile_blocks(synth: &DiscoverySynthesis, new_names: &BTreeSet<String>) -> String {
    let filtered = DiscoverySynthesis {
        profiles: synth
            .profiles
            .iter()
            .filter(|p| new_names.contains(&p.plan.profile_name))
            .cloned()
            .collect::<Vec<SynthesizedProfile>>(),
        // A merge never rewrites the existing top-level (default_profile stays
        // whatever the operator already has).
        default_profile: None,
        notes: Vec::new(),
    };
    let rendered = render_annotated_config(&filtered);
    match rendered.find("[[profiles]]") {
        Some(idx) => rendered[idx..].to_owned(),
        None => String::new(),
    }
}

/// Append `blocks` to the existing config bytes with a clean separator so the
/// existing content is preserved verbatim (design spec §E: add-only).
fn append_blocks(existing: &str, blocks: &str) -> String {
    let mut out = existing.to_owned();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(blocks);
    out
}

/// Build the non-destructive write plan (design spec §E) from the consented
/// scan/synthesis and the current target bytes.
fn build_plan(target: &Path, synth: &DiscoverySynthesis) -> Result<DiscoveryPlan, String> {
    let base_bytes = std::fs::read(target).unwrap_or_default();
    let existing = parse_existing(&base_bytes, target)?;
    let existing_names: BTreeSet<String> = existing
        .as_ref()
        .map(|cfg| {
            cfg.list_profiles()
                .into_iter()
                .map(|meta| meta.name)
                .collect()
        })
        .unwrap_or_default();
    let target_is_empty = base_bytes.iter().all(u8::is_ascii_whitespace);

    // Zero net-services discovered: fall back to the minimal starter so the
    // operator is never left empty-handed — but never over an existing file.
    if synth.profiles.is_empty() {
        if target_is_empty {
            let draft = crate::robot_docs::setup_profiles_template(
                FALLBACK_PROFILE,
                FALLBACK_CREDENTIAL_ENV,
            );
            return Ok(DiscoveryPlan {
                base_bytes,
                new_profiles: vec![FALLBACK_PROFILE.to_owned()],
                skipped_profiles: Vec::new(),
                draft: Some(draft),
                fresh: true,
                fallback_used: true,
            });
        }
        return Ok(DiscoveryPlan {
            base_bytes,
            new_profiles: Vec::new(),
            skipped_profiles: Vec::new(),
            draft: None,
            fresh: false,
            fallback_used: false,
        });
    }

    let mut new_profiles = Vec::new();
    let mut skipped_profiles = Vec::new();
    for synth_profile in &synth.profiles {
        let name = &synth_profile.plan.profile_name;
        if existing_names.contains(name) {
            skipped_profiles.push(name.clone());
        } else {
            new_profiles.push(name.clone());
        }
    }

    if target_is_empty {
        // Fresh: the full generated config (sets default_profile when single).
        return Ok(DiscoveryPlan {
            base_bytes,
            new_profiles,
            skipped_profiles,
            draft: Some(render_annotated_config(synth)),
            fresh: true,
            fallback_used: false,
        });
    }

    // Existing, non-empty target: add-only merge. Never overwrite.
    if new_profiles.is_empty() {
        return Ok(DiscoveryPlan {
            base_bytes,
            new_profiles,
            skipped_profiles,
            draft: None,
            fresh: false,
            fallback_used: false,
        });
    }
    let new_set: BTreeSet<String> = new_profiles.iter().cloned().collect();
    let blocks = render_new_profile_blocks(synth, &new_set);
    let existing_text = String::from_utf8(base_bytes.clone())
        .map_err(|_| format!("existing config at {} is not valid UTF-8", target.display()))?;
    Ok(DiscoveryPlan {
        base_bytes,
        new_profiles,
        skipped_profiles,
        draft: Some(append_blocks(&existing_text, &blocks)),
        fresh: false,
        fallback_used: false,
    })
}

/// Prompt the interactive operator before writing (design spec §D), reading a
/// yes/no answer from stdin. Any answer other than `y`/`yes` (case-insensitive)
/// is a decline.
fn prompt_write_consent(profiles: usize, target: &Path) -> bool {
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{}", write_prompt(profiles, target));
    let _ = stderr.flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    let answer = line.trim().to_ascii_lowercase();
    answer == "y" || answer == "yes"
}

/// The label for a profile's connect-string strategy (design spec §B).
fn connect_kind_label(kind: ConnectStringKind) -> &'static str {
    match kind {
        ConnectStringKind::Alias => "alias",
        ConnectStringKind::EzConnect => "ezconnect",
    }
}

/// The ordered next actions an agent/operator runs after a write (bead `.13`):
/// set the credential env vars, run offline doctor, then verify a live
/// connection. Every entry is a command runnable verbatim (the export lines name
/// the exact env var; the operator supplies the secret value).
fn next_actions(synth: &DiscoverySynthesis) -> Vec<String> {
    let mut actions = Vec::new();
    for (profile, var) in synth.required_env_vars() {
        actions.push(format!("export {var}=<db-password for {profile}>"));
    }
    actions.push("oraclemcp doctor".to_owned());
    match synth.profiles.first() {
        Some(first) => actions.push(format!(
            "oraclemcp doctor --online --profile {}",
            first.plan.profile_name
        )),
        None => actions.push("oraclemcp doctor --online --profile <profile>".to_owned()),
    }
    actions
}

/// The `oraclemcp setup --discover` orchestration (design spec §A–§F).
///
/// Enforces the consent gate (bead `.4`), scans the candidate directories,
/// synthesizes least-privilege READ_ONLY profiles, builds the non-destructive
/// add-only write plan (bead `.11`), and — on write consent — applies it through
/// config-ops (bead `.10`/`.12`: backup + atomic replace + strict revalidate +
/// reload plan). `--dry-run` previews and writes nothing.
pub(crate) fn run_setup_discover(
    robot_json: bool,
    flags: DiscoverFlags,
    target: PathBuf,
) -> ExitCode {
    // 1. Scan-consent gate (design spec §D). Fail closed on a non-TTY caller
    //    without an explicit consent flag.
    if !flags.scan_consented() {
        if robot_json {
            eprintln!(
                "{}",
                serde_json::json!({
                    "kind": "error",
                    "code": CONSENT_REFUSED_CODE,
                    "message": SCAN_REFUSAL,
                })
            );
        } else {
            eprintln!("{SCAN_REFUSAL}");
        }
        return ExitCode::from(2);
    }

    // 2. Scan + synthesize.
    let scan = scan_for_net_services();
    let synth = synthesize(&scan.services);

    // 3. Build the non-destructive write plan.
    let plan = match build_plan(&target, &synth) {
        Ok(plan) => plan,
        Err(message) => {
            emit_discover_error(
                robot_json,
                "ORACLEMCP_DISCOVER_EXISTING_CONFIG_INVALID",
                &message,
            );
            return ExitCode::from(2);
        }
    };

    // 4. Resolve write consent (prompt on a TTY, honor flags, respect dry-run).
    //    Nothing to write (idempotent no-op) short-circuits to a report.
    let decision = if plan.draft.is_none() {
        WriteDecision::DryRun
    } else {
        resolve_write_consent(&flags, || {
            prompt_write_consent(plan.new_profiles.len(), &target)
        })
    };

    // 5. Apply, or report a preview / decline / no-op.
    let write_result = match (&decision, &plan.draft) {
        (WriteDecision::Write, Some(draft)) => {
            let expected = oraclemcp_audit::sha256_hex(&plan.base_bytes);
            match crate::setup_apply_discovery_config(target.clone(), draft, &expected) {
                Ok(result) => Some(result),
                Err(error) => {
                    let (code, message) = crate::setup_config_error_status(&error);
                    emit_discover_error(robot_json, code, &message);
                    return ExitCode::from(2);
                }
            }
        }
        _ => None,
    };

    // 6. Emit the report (and the spec §D success line on a real write).
    if robot_json {
        emit_discover_json(
            &scan,
            &synth,
            &plan,
            &decision,
            write_result.as_ref(),
            &target,
        )
    } else {
        emit_discover_human(
            &scan,
            &synth,
            &plan,
            &decision,
            write_result.as_ref(),
            &target,
        )
    }
}

/// Emit a structured discovery error on stderr (both modes) and nothing on
/// stdout.
fn emit_discover_error(robot_json: bool, code: &str, message: &str) {
    if robot_json {
        eprintln!(
            "{}",
            serde_json::json!({ "kind": "error", "code": code, "message": message })
        );
    } else {
        eprintln!("oraclemcp setup --discover: {message}");
    }
}

/// Render and print the JSON discovery report (bead `.13`): names and safe
/// metadata only — never a secret value.
fn emit_discover_json(
    scan: &DiscoveryScan,
    synth: &DiscoverySynthesis,
    plan: &DiscoveryPlan,
    decision: &WriteDecision,
    write_result: Option<&crate::SetupWriteResult>,
    target: &Path,
) -> ExitCode {
    let searched: Vec<serde_json::Value> = scan
        .candidates
        .iter()
        .map(|candidate| {
            serde_json::json!({
                "source": candidate.source.label(),
                "path": candidate.path.display().to_string(),
                "status": candidate_status_label(candidate),
                "has_tnsnames_ora": candidate.has_tnsnames_ora,
                "note": candidate.note,
            })
        })
        .collect();
    let net_services: Vec<serde_json::Value> = scan
        .services
        .iter()
        .map(|service| serde_json::json!({ "alias": service.service_name }))
        .collect();
    let profiles: Vec<serde_json::Value> = synth
        .profiles
        .iter()
        .map(|synth_profile| {
            let p = &synth_profile.plan;
            serde_json::json!({
                "name": p.profile_name,
                "source_alias": p.source_alias,
                "connect_string_strategy": connect_kind_label(p.connect_string_kind),
                "password_env_var": p.password_env_var,
                "wallet_password_env_var": p.wallet_password_env_var,
                "needs_verification": p.needs_verification,
                "status": if plan.skipped_profiles.contains(&p.profile_name) {
                    "already_configured"
                } else {
                    "created"
                },
            })
        })
        .collect();
    let env_vars: Vec<serde_json::Value> = synth
        .required_env_vars()
        .into_iter()
        .map(|(profile, var)| serde_json::json!({ "profile": profile, "env_var": var }))
        .collect();

    let written = write_result.is_some();
    let backup_path = write_result.map(|r| r.outcome.apply.backup_path.display().to_string());

    let payload = serde_json::json!({
        "ok": true,
        "kind": "oraclemcp_discover",
        "consented": true,
        "dry_run": matches!(decision, WriteDecision::DryRun) && plan.draft.is_some() && !written,
        "written": written,
        "write_mode": if plan.fresh { "fresh" } else { "add_only_merge" },
        "fallback_minimal_starter": plan.fallback_used,
        "target_path": target.display().to_string(),
        "backup_path": backup_path,
        "searched_directories": searched,
        "net_services": net_services,
        "profiles": profiles,
        "profiles_created": plan.new_profiles,
        "profiles_skipped_already_configured": plan.skipped_profiles,
        "env_vars": env_vars,
        "redaction": "profiles TOML and secret references are not echoed; only env-var names and safe metadata are returned",
        "next_actions": next_actions(synth),
    });
    let output = serde_json::to_string(&payload).unwrap();
    let exit = crate::write_stdout_line(&output);
    if written {
        eprintln!(
            "{}",
            success_line(
                scan.services.len(),
                scan.candidates.len(),
                plan.new_profiles.len(),
                target,
            )
        );
    }
    crate::stdout_exit(exit, ExitCode::SUCCESS)
}

/// Render and print the human discovery report (bead `.10`), plus the spec §D
/// success line on a real write.
fn emit_discover_human(
    scan: &DiscoveryScan,
    synth: &DiscoverySynthesis,
    plan: &DiscoveryPlan,
    decision: &WriteDecision,
    write_result: Option<&crate::SetupWriteResult>,
    target: &Path,
) -> ExitCode {
    let mut report = String::new();
    render_human_report(&mut report, scan, synth);

    if !plan.skipped_profiles.is_empty() {
        report.push_str("\nAlready configured (left untouched):\n");
        for name in &plan.skipped_profiles {
            report.push_str(&format!("  {name}\n"));
        }
    }

    match (decision, write_result) {
        (_, Some(result)) => {
            report.push_str(&format!("\nWrote config through config-ops:\n  target: {}\n  backup: {}\n  rollback: {}\n  reload: {}\n",
                result.outcome.apply.target_path.display(),
                result.outcome.apply.backup_path.display(),
                result.outcome.rollback_id,
                result.outcome.reload.status));
        }
        (WriteDecision::DryRun, None) if plan.draft.is_some() => {
            report.push_str(&format!(
                "\nDry run — nothing written. The config that would be written to {}:\n\n",
                target.display()
            ));
            if let Some(draft) = &plan.draft {
                report.push_str(draft);
                if !draft.ends_with('\n') {
                    report.push('\n');
                }
            }
        }
        (WriteDecision::DryRun, None) => {
            report.push_str(
                "\nNo new net-services to add — the config already covers every discovered profile; nothing written.\n",
            );
        }
        (WriteDecision::Declined, None) => {
            report.push_str("\nDeclined — nothing written.\n");
        }
        (WriteDecision::Write, None) => {}
    }

    let exit = crate::write_stdout_text(&report);
    if write_result.is_some() {
        // The spec §D success line is a stderr notice (exit 0).
        eprintln!(
            "{}",
            success_line(
                scan.services.len(),
                scan.candidates.len(),
                plan.new_profiles.len(),
                target,
            )
        );
    }
    crate::stdout_exit(exit, ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn flags(interactive: bool, discover_tns: bool, yes: bool, dry_run: bool) -> DiscoverFlags {
        DiscoverFlags {
            interactive,
            discover_tns,
            yes,
            dry_run,
        }
    }

    #[test]
    fn non_tty_without_flag_refuses_scan() {
        // The single safety-critical case: no TTY, no consent flag -> no scan.
        assert!(!flags(false, false, false, false).scan_consented());
        assert!(!flags(false, false, false, true).scan_consented());
    }

    #[test]
    fn tty_or_explicit_flag_consents_to_scan() {
        assert!(flags(true, false, false, false).scan_consented());
        assert!(flags(false, true, false, false).scan_consented());
        assert!(flags(false, false, true, false).scan_consented());
    }

    #[test]
    fn dry_run_never_writes_even_with_consent() {
        assert_eq!(
            resolve_write_consent(&flags(true, false, false, true), || true),
            WriteDecision::DryRun
        );
        assert_eq!(
            resolve_write_consent(&flags(false, true, false, true), || true),
            WriteDecision::DryRun
        );
    }

    #[test]
    fn explicit_consent_writes_without_prompting() {
        // The prompt closure must NOT be consulted when a flag already consents.
        let never = || panic!("prompt must not run when an explicit flag consents");
        assert_eq!(
            resolve_write_consent(&flags(false, true, false, false), never),
            WriteDecision::Write
        );
        assert_eq!(
            resolve_write_consent(&flags(true, false, true, false), never),
            WriteDecision::Write
        );
    }

    #[test]
    fn interactive_prompt_decides_write() {
        assert_eq!(
            resolve_write_consent(&flags(true, false, false, false), || true),
            WriteDecision::Write
        );
        assert_eq!(
            resolve_write_consent(&flags(true, false, false, false), || false),
            WriteDecision::Declined
        );
    }

    #[test]
    fn non_interactive_without_consent_fails_closed_on_write() {
        // Unreachable in practice (the scan gate refuses first), but must never
        // silently write.
        assert_eq!(
            resolve_write_consent(&flags(false, false, false, false), || true),
            WriteDecision::Declined
        );
    }

    #[test]
    fn spec_d_wording_is_exact() {
        let path = PathBuf::from("/home/op/.config/oraclemcp/profiles.toml");
        // Singular forms.
        assert_eq!(
            write_prompt(1, &path),
            "Write 1 read-only profile to /home/op/.config/oraclemcp/profiles.toml? [y/N]: "
        );
        assert_eq!(
            success_line(1, 1, 1, &path),
            "discovered 1 net-service across 1 candidate directory; wrote 1 read-only profile to /home/op/.config/oraclemcp/profiles.toml."
        );
        // Plural forms.
        assert_eq!(
            write_prompt(3, &path),
            "Write 3 read-only profiles to /home/op/.config/oraclemcp/profiles.toml? [y/N]: "
        );
        assert_eq!(
            success_line(4, 9, 3, &path),
            "discovered 4 net-services across 9 candidate directories; wrote 3 read-only profiles to /home/op/.config/oraclemcp/profiles.toml."
        );
    }

    #[test]
    fn refusal_is_actionable_and_names_the_consent_flag() {
        assert!(SCAN_REFUSAL.contains("refusing to scan for tnsnames.ora without consent"));
        assert!(SCAN_REFUSAL.contains("re-run on an interactive terminal"));
        assert!(SCAN_REFUSAL.contains("--discover-tns"));
    }
}
