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

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oraclemcp_config::discovery::synth::{DiscoveredNetService, SynthOptions, synthesize_profiles};
use oraclemcp_config::discovery::{DiscoverySynthesis, TnsCandidateDir, resolve_candidate_dirs};
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
///
// The write path that consumes this is wired by the orchestration bead `.10`;
// bead `.4` delivers and unit-tests the decision logic.
#[allow(dead_code)]
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
#[allow(dead_code)] // consumed by the write path wired in bead `.10`.
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
#[allow(dead_code)] // emitted by the interactive write path wired in bead `.10`.
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
#[allow(dead_code)] // emitted after a real write by the path wired in bead `.10`.
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

/// The `oraclemcp setup --discover` orchestration (design spec §A–§F).
///
/// Bead `.4` scope: enforce the consent gate (refuse a non-TTY caller without an
/// explicit flag, exit `2`), then — once scanning is consented — scan the
/// candidate directories, synthesize the read-only profiles, and print the human
/// discovery report. The write path (config-ops apply, add-only merge, and the
/// spec §D success line) lands in the orchestration/idempotency beads.
pub(crate) fn run_setup_discover(
    robot_json: bool,
    flags: DiscoverFlags,
    _target: PathBuf,
) -> ExitCode {
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

    let scan = scan_for_net_services();
    let synth = synthesize(&scan.services);

    if robot_json {
        let payload = serde_json::json!({
            "ok": true,
            "kind": "oraclemcp_discover",
            "net_services_found": scan.services.len(),
            "candidate_directories": scan.candidates.len(),
            "profiles": synth
                .profiles
                .iter()
                .map(|p| p.plan.profile_name.clone())
                .collect::<Vec<_>>(),
            "env_vars": synth
                .required_env_vars()
                .into_iter()
                .map(|(profile, var)| serde_json::json!({ "profile": profile, "env_var": var }))
                .collect::<Vec<_>>(),
        });
        let output = serde_json::to_string(&payload).unwrap();
        crate::stdout_exit(crate::write_stdout_line(&output), ExitCode::SUCCESS)
    } else {
        let mut report = String::new();
        render_human_report(&mut report, &scan, &synth);
        crate::stdout_exit(crate::write_stdout_text(&report), ExitCode::SUCCESS)
    }
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
