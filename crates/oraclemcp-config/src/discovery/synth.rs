//! Net-service → [`ConnectionProfile`] synthesis (TNS-onboarding beads `.5`,
//! `.6`, `.7`; design spec §B, `docs/tns-discovery-onboarding.md`).
//!
//! Given the net-services a discovery scan found, this module synthesizes one
//! governed, least-privilege [`ConnectionProfile`] per net-service plus a
//! machine-readable [`DiscoverySynthesis`] report the binary renders for the
//! operator. The synthesis is deliberately conservative and **fails closed**:
//!
//! - every profile is capped at `READ_ONLY` (both `max_level` and
//!   `default_level` are set **explicitly**, never left to a struct default),
//! - `credential_ref` is always a placeholder `env:` secret-ref — never a
//!   literal — and each profile gets a distinct, deterministic env-var name,
//! - nothing is verified at synthesis time (no live connection is made), so
//!   every synthesized profile is flagged **needs-verification** in the report.
//!
//! # Crate-DAG note
//!
//! `oraclemcp-config` does not depend on `oraclemcp-db`, so this module cannot
//! consume the `oracledb`-side `TnsNetService` directly. It operates on the
//! config-owned [`DiscoveredNetService`] input struct instead; the binary
//! (which depends on both crates) bridges each `TnsNetService` into a
//! [`DiscoveredNetService`] before calling [`synthesize_profiles`]. The raw
//! connect descriptor never crosses that seam — only the non-sensitive hints
//! do — so a descriptor that ever embedded a credential cannot leak here.

use std::collections::BTreeSet;

use oraclemcp_guard::OperatingLevel;

use crate::ConnectionProfile;

/// A single net-service handed to the synthesizer — the config-owned mirror of
/// the `oraclemcp-db` `TnsNetService` (minus the raw, possibly-sensitive
/// descriptor, which never crosses the crate seam).
///
/// The binary populates this from a discovered `TnsNetService`: `alias` is the
/// Oracle Net alias (service name, upper-cased as Oracle stores it) and the
/// remaining fields are the best-effort descriptor hints.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoveredNetService {
    /// The Oracle Net alias (service name), as stored (upper-cased).
    pub alias: String,
    /// Transport protocol when explicit (`TCP` / `TCPS`), else `None`.
    pub protocol: Option<String>,
    /// Host hint, when extractable.
    pub host: Option<String>,
    /// Port hint, when extractable.
    pub port: Option<u16>,
    /// Service-name hint, when extractable.
    pub service_name: Option<String>,
    /// Wallet directory hint (present for a TCPS / wallet descriptor).
    pub wallet_location: Option<String>,
}

impl DiscoveredNetService {
    /// A net-service with only its alias known (all hints unset).
    #[must_use]
    pub fn new(alias: impl Into<String>) -> Self {
        DiscoveredNetService {
            alias: alias.into(),
            ..Self::default()
        }
    }

    /// Whether this descriptor implies a TCPS / wallet target — an explicit
    /// `TCPS` protocol or a wallet-directory hint. Such a target additionally
    /// wants a wallet-password secret-ref placeholder (bead `.6`).
    #[must_use]
    pub fn is_tcps_or_wallet(&self) -> bool {
        self.wallet_location.is_some()
            || self
                .protocol
                .as_deref()
                .is_some_and(|p| p.eq_ignore_ascii_case("TCPS"))
    }
}

/// How the synthesizer chose a profile's `connect_string` (design spec §B).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectStringKind {
    /// The `tnsnames.ora` alias itself (a thin reference; resolves when
    /// `TNS_ADMIN` points at the shared `tnsnames.ora` at runtime).
    Alias,
    /// A normalized EZConnect (`host:port/service`, `tcps://…` for TCPS)
    /// synthesized from the descriptor hints.
    EzConnect,
}

/// Options controlling net-service → profile synthesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynthOptions {
    /// Whether the runtime will have `TNS_ADMIN` pointing at a `tnsnames.ora`
    /// that resolves these aliases (the setup wrapper sets `TNS_ADMIN`,
    /// `robot_docs.rs:22`). When `true` (the default), `connect_string` stores
    /// the alias — a thin reference. When `false`, `connect_string` is a
    /// normalized EZConnect synthesized from the descriptor hints, falling back
    /// to the alias (with a note) when the hints are too incomplete.
    pub tns_admin_reachable: bool,
}

impl Default for SynthOptions {
    fn default() -> Self {
        // Default is the thin-reference alias: the setup wrapper sets TNS_ADMIN,
        // so the alias resolves and the profile stays a small reference.
        SynthOptions {
            tns_admin_reachable: true,
        }
    }
}

/// The per-profile report entry: the machine-readable half of what discovery
/// tells the operator about one synthesized profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredProfilePlan {
    /// The synthesized, sanitized profile name (`[a-z0-9_]`, unique).
    pub profile_name: String,
    /// The source Oracle Net alias this profile was synthesized from.
    pub source_alias: String,
    /// How `connect_string` was chosen.
    pub connect_string_kind: ConnectStringKind,
    /// The exact environment variable the operator must export for the DB
    /// password before going live (`ORACLE_<NAME>_PASSWORD`).
    pub password_env_var: String,
    /// The exact environment variable for the wallet password, when this is a
    /// TCPS / wallet target (`ORACLE_<NAME>_WALLET_PASSWORD`); else `None`
    /// (populated by the secret-ref bead `.6`).
    pub wallet_password_env_var: Option<String>,
    /// Whether this profile still needs verification before it can serve live
    /// traffic (populated by the read-only-safe-defaults bead `.7`). Discovery
    /// makes no live connection, so a freshly discovered profile is always
    /// needs-verification: fail closed, unknown maps to least privilege.
    pub needs_verification: bool,
    /// Non-fatal per-profile notes for the operator (e.g. a fallback
    /// connect-string decision, or incomplete descriptor hints).
    pub notes: Vec<String>,
}

/// One synthesized profile plus its report entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynthesizedProfile {
    /// The governed, least-privilege profile ready to render.
    pub profile: ConnectionProfile,
    /// The report metadata for this profile.
    pub plan: DiscoveredProfilePlan,
}

/// The full synthesis outcome: the profiles, the report, and the chosen default.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DiscoverySynthesis {
    /// The synthesized profiles, in first-seen net-service order.
    pub profiles: Vec<SynthesizedProfile>,
    /// The `default_profile` to write — `Some` only when exactly one profile was
    /// synthesized (unambiguous); `None` otherwise (the loader would reject a
    /// `default_profile` naming no profile, so we leave it unset and note it).
    pub default_profile: Option<String>,
    /// Overall notes for the operator (e.g. "pick a default_profile").
    pub notes: Vec<String>,
}

impl DiscoverySynthesis {
    /// The environment variables the operator must export before going live,
    /// keyed by profile in profile order (bead `.6`). Each entry is
    /// `(profile_name, var_name)`; a TCPS / wallet profile contributes a second
    /// entry for its `ORACLE_<NAME>_WALLET_PASSWORD`. Only variable *names* are
    /// ever returned — never a secret value, since the value lives solely in the
    /// environment and is never written to disk.
    #[must_use]
    pub fn required_env_vars(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for synth in &self.profiles {
            out.push((
                synth.plan.profile_name.clone(),
                synth.plan.password_env_var.clone(),
            ));
            if let Some(wallet) = &synth.plan.wallet_password_env_var {
                out.push((synth.plan.profile_name.clone(), wallet.clone()));
            }
        }
        out
    }
}

/// Synthesize one governed, least-privilege [`ConnectionProfile`] per
/// net-service, plus the discovery report (design spec §B).
///
/// The output is deterministic: profile names are stable functions of the input
/// aliases (collisions get a numeric suffix in first-seen order), so a re-run
/// over the same input produces the same names — which the idempotency bead
/// relies on. Every profile is `READ_ONLY`-capped on both levels, non-protected,
/// and carries an `env:` credential placeholder (never a literal).
#[must_use]
pub fn synthesize_profiles(
    services: &[DiscoveredNetService],
    opts: &SynthOptions,
) -> DiscoverySynthesis {
    let mut used_names: BTreeSet<String> = BTreeSet::new();
    let mut profiles: Vec<SynthesizedProfile> = Vec::with_capacity(services.len());

    for service in services {
        let profile_name = unique_name(&sanitize_name(&service.alias), &mut used_names);
        let env_upper = profile_name.to_ascii_uppercase();
        let password_env_var = format!("ORACLE_{env_upper}_PASSWORD");
        let credential_ref = format!("env:{password_env_var}");

        // A TCPS / wallet target also needs an external wallet-password ref. The
        // writer renders a commented `wallet_password_ref = "env:…"` under
        // [profiles.oci]; here we derive the deterministic, per-profile var name
        // the operator must export. Never a literal, never written to disk.
        let wallet_password_env_var = if service.is_tcps_or_wallet() {
            Some(format!("ORACLE_{env_upper}_WALLET_PASSWORD"))
        } else {
            None
        };

        let (connect_string, connect_string_kind, notes) = choose_connect_string(service, opts);

        let profile = ConnectionProfile {
            name: profile_name.clone(),
            description: Some(format!(
                "Read-only profile for Oracle Net service {}",
                service.alias
            )),
            connect_string: Some(connect_string),
            // username is left unset — discovery never guesses a real account;
            // the writer renders a commented least-privilege hint instead.
            username: None,
            credential_ref: Some(credential_ref),
            // Both levels are SET explicitly (never left to the accessor
            // default) so the READ_ONLY safety ceiling is legible in the file.
            max_level: Some(OperatingLevel::ReadOnly),
            default_level: Some(OperatingLevel::ReadOnly),
            // Everything else is left unset (the writer renders each as a
            // commented, help-annotated menu entry): protected stays unset so an
            // operator can later deliberately opt a target up, mcp_exposed stays
            // unset (exposed-by-default), and all optional tables stay unset.
            login_script: None,
            login_statements: None,
            trusted_session_statements: None,
            call_timeout_seconds: None,
            max_query_cost: None,
            connect_timeout_seconds: None,
            inactivity_timeout_seconds: None,
            keepalive_minutes: None,
            sdu: None,
            protected: None,
            require_signed_tools: None,
            read_only_standby: None,
            mcp_exposed: None,
            dashboard_ddl_workbench: None,
            session_identity: None,
            pool: None,
            oci: None,
            drcp: None,
            proxy_auth: None,
            app_context: None,
            masking: None,
            base: None,
        };

        let plan = DiscoveredProfilePlan {
            profile_name,
            source_alias: service.alias.clone(),
            connect_string_kind,
            password_env_var,
            wallet_password_env_var,
            // Fail closed (bead `.7`): discovery makes no live connection, so a
            // freshly synthesized profile is ALWAYS unverified — READ_ONLY and
            // flagged needs-verification — never dropped and never loosened.
            needs_verification: true,
            notes,
        };

        profiles.push(SynthesizedProfile { profile, plan });
    }

    let (default_profile, notes) = match profiles.as_slice() {
        [] => (None, Vec::new()),
        [only] => (Some(only.plan.profile_name.clone()), Vec::new()),
        _ => (
            None,
            vec![
                "multiple net-services discovered; no default_profile was chosen — set \
                 default_profile to the profile the launcher should use by default"
                    .to_owned(),
            ],
        ),
    };

    DiscoverySynthesis {
        profiles,
        default_profile,
        notes,
    }
}

/// Sanitize an Oracle Net alias to a stable, lower-snake profile name
/// (`[a-z0-9_]`). Any other character becomes `_`; an empty result becomes
/// `profile` so a name is never empty (design spec §B).
fn sanitize_name(alias: &str) -> String {
    let sanitized: String = alias
        .chars()
        .map(|ch| {
            let lower = ch.to_ascii_lowercase();
            if lower.is_ascii_alphanumeric() || lower == '_' {
                lower
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "profile".to_owned()
    } else {
        sanitized
    }
}

/// Return `base` if free, else `base_2`, `base_3`, … — the first name not yet in
/// `used`. Deterministic in first-seen order, so re-runs are stable.
fn unique_name(base: &str, used: &mut BTreeSet<String>) -> String {
    if used.insert(base.to_owned()) {
        return base.to_owned();
    }
    let mut suffix = 2u32;
    loop {
        let candidate = format!("{base}_{suffix}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        suffix += 1;
    }
}

/// Choose a profile's `connect_string` and record why (design spec §B).
fn choose_connect_string(
    service: &DiscoveredNetService,
    opts: &SynthOptions,
) -> (String, ConnectStringKind, Vec<String>) {
    if opts.tns_admin_reachable {
        return (service.alias.clone(), ConnectStringKind::Alias, Vec::new());
    }
    match ezconnect_from_hints(service) {
        Some(ez) => (ez, ConnectStringKind::EzConnect, Vec::new()),
        None => (
            service.alias.clone(),
            ConnectStringKind::Alias,
            vec![
                "descriptor hints were incomplete for an EZConnect; kept the tnsnames alias as \
                 connect_string — verify TNS_ADMIN resolves it at runtime"
                    .to_owned(),
            ],
        ),
    }
}

/// Build a normalized EZConnect (`host:port/service`, `tcps://…` for TCPS) from
/// the descriptor hints, or `None` when host / port / service are not all known.
fn ezconnect_from_hints(service: &DiscoveredNetService) -> Option<String> {
    let host = service.host.as_deref()?.trim();
    let port = service.port?;
    let svc = service.service_name.as_deref()?.trim();
    if host.is_empty() || svc.is_empty() {
        return None;
    }
    let scheme = match service.protocol.as_deref() {
        Some(p) if p.eq_ignore_ascii_case("TCPS") => "tcps://",
        _ => "",
    };
    Some(format!("{scheme}{host}:{port}/{svc}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OracleMcpConfig;

    fn svc(alias: &str) -> DiscoveredNetService {
        DiscoveredNetService::new(alias)
    }

    /// Render the synthesized profiles' bootable-minimum keys into a small TOML
    /// document, purely so this bead's tests can prove the synthesized set
    /// parses through the real loader without pre-empting the annotated writer
    /// (bead `.8`). Only the SET fields the synthesizer produces are emitted.
    fn minimal_toml(synth: &DiscoverySynthesis) -> String {
        let mut out = String::from("schema_version = 2\n");
        if let Some(default_profile) = &synth.default_profile {
            out.push_str(&format!("default_profile = \"{default_profile}\"\n"));
        }
        for s in &synth.profiles {
            let p = &s.profile;
            out.push_str("\n[[profiles]]\n");
            out.push_str(&format!("name = \"{}\"\n", p.name));
            out.push_str(&format!(
                "description = \"{}\"\n",
                p.description.as_deref().unwrap_or_default()
            ));
            out.push_str(&format!(
                "connect_string = \"{}\"\n",
                p.connect_string.as_deref().unwrap_or_default()
            ));
            out.push_str(&format!(
                "credential_ref = \"{}\"\n",
                p.credential_ref.as_deref().unwrap_or_default()
            ));
            out.push_str(&format!(
                "max_level = \"{}\"\n",
                p.max_level.expect("max_level set").as_str()
            ));
            out.push_str(&format!(
                "default_level = \"{}\"\n",
                p.default_level.expect("default_level set").as_str()
            ));
        }
        out
    }

    #[test]
    fn single_service_selects_default_profile() {
        let synth = synthesize_profiles(&[svc("SALES_RO")], &SynthOptions::default());
        assert_eq!(synth.profiles.len(), 1);
        assert_eq!(synth.default_profile.as_deref(), Some("sales_ro"));
        assert_eq!(
            synth.profiles[0].plan.password_env_var,
            "ORACLE_SALES_RO_PASSWORD"
        );
        let cfg = OracleMcpConfig::from_toml_str(&minimal_toml(&synth))
            .expect("single synthesized profile parses + validates");
        assert_eq!(cfg.default_profile.as_deref(), Some("sales_ro"));
    }

    #[test]
    fn many_services_leaves_default_profile_unset_with_note() {
        let synth = synthesize_profiles(
            &[svc("SALES_RO"), svc("HR_RO"), svc("FIN_RO")],
            &SynthOptions::default(),
        );
        assert_eq!(synth.profiles.len(), 3);
        assert!(
            synth.default_profile.is_none(),
            "an ambiguous multi-service scan leaves default_profile unset"
        );
        assert!(
            synth.notes.iter().any(|n| n.contains("default_profile")),
            "the operator is told to pick a default_profile"
        );
        // A config with no default_profile and several profiles still validates.
        OracleMcpConfig::from_toml_str(&minimal_toml(&synth))
            .expect("multi-profile set parses + validates");
    }

    #[test]
    fn names_are_normalized_lower_snake() {
        let synth = synthesize_profiles(
            &[svc("SALES.RO@PROD"), svc("Weird Name!")],
            &SynthOptions::default(),
        );
        let names: Vec<&str> = synth
            .profiles
            .iter()
            .map(|s| s.profile.name.as_str())
            .collect();
        assert_eq!(names, vec!["sales_ro_prod", "weird_name_"]);
        for name in names {
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "name {name} is sanitized to [a-z0-9_]"
            );
        }
    }

    #[test]
    fn colliding_aliases_get_deterministic_suffixes() {
        // Three aliases that all sanitize to the same base name.
        let synth = synthesize_profiles(
            &[svc("SALES-RO"), svc("SALES_RO"), svc("SALES.RO")],
            &SynthOptions::default(),
        );
        let names: Vec<&str> = synth
            .profiles
            .iter()
            .map(|s| s.profile.name.as_str())
            .collect();
        assert_eq!(names, vec!["sales_ro", "sales_ro_2", "sales_ro_3"]);
        // Re-running over the same input yields the identical mapping.
        let again = synthesize_profiles(
            &[svc("SALES-RO"), svc("SALES_RO"), svc("SALES.RO")],
            &SynthOptions::default(),
        );
        assert_eq!(synth, again, "synthesis is deterministic");
        // Env vars are unique per profile (they key off the unique name).
        let mut env_vars: Vec<&str> = synth
            .profiles
            .iter()
            .map(|s| s.plan.password_env_var.as_str())
            .collect();
        let count = env_vars.len();
        env_vars.sort_unstable();
        env_vars.dedup();
        assert_eq!(env_vars.len(), count, "password env vars are unique");
        // The whole set is still loadable (unique names, valid connect_strings).
        OracleMcpConfig::from_toml_str(&minimal_toml(&synth)).expect("collided set parses");
    }

    #[test]
    fn connect_string_is_alias_when_tns_admin_reachable() {
        let mut s = svc("PRIMARY_TCPS");
        s.protocol = Some("TCPS".to_owned());
        s.host = Some("tcps.example.com".to_owned());
        s.port = Some(2484);
        s.service_name = Some("PRIMARY.example.com".to_owned());
        let synth = synthesize_profiles(&[s], &SynthOptions::default());
        let only = &synth.profiles[0];
        assert_eq!(only.plan.connect_string_kind, ConnectStringKind::Alias);
        assert_eq!(
            only.profile.connect_string.as_deref(),
            Some("PRIMARY_TCPS"),
            "with TNS_ADMIN reachable, connect_string is the alias (thin reference)"
        );
    }

    #[test]
    fn connect_string_is_ezconnect_when_not_reachable() {
        let mut s = svc("EZ_PLAIN");
        s.host = Some("ez.example.com".to_owned());
        s.port = Some(1521);
        s.service_name = Some("EZSERVICE".to_owned());
        let synth = synthesize_profiles(
            &[s],
            &SynthOptions {
                tns_admin_reachable: false,
            },
        );
        let only = &synth.profiles[0];
        assert_eq!(only.plan.connect_string_kind, ConnectStringKind::EzConnect);
        assert_eq!(
            only.profile.connect_string.as_deref(),
            Some("ez.example.com:1521/EZSERVICE")
        );
    }

    #[test]
    fn tcps_ezconnect_carries_scheme() {
        let mut s = svc("PRIMARY_TCPS");
        s.protocol = Some("TCPS".to_owned());
        s.host = Some("tcps.example.com".to_owned());
        s.port = Some(2484);
        s.service_name = Some("PRIMARY.example.com".to_owned());
        let synth = synthesize_profiles(
            &[s],
            &SynthOptions {
                tns_admin_reachable: false,
            },
        );
        assert_eq!(
            synth.profiles[0].profile.connect_string.as_deref(),
            Some("tcps://tcps.example.com:2484/PRIMARY.example.com")
        );
    }

    #[test]
    fn incomplete_hints_fall_back_to_alias_with_note() {
        // No host/port/service and TNS_ADMIN not reachable: keep the alias, note it.
        let synth = synthesize_profiles(
            &[svc("BARE_ALIAS")],
            &SynthOptions {
                tns_admin_reachable: false,
            },
        );
        let only = &synth.profiles[0];
        assert_eq!(only.plan.connect_string_kind, ConnectStringKind::Alias);
        assert_eq!(only.profile.connect_string.as_deref(), Some("BARE_ALIAS"));
        assert!(
            only.plan.notes.iter().any(|n| n.contains("incomplete")),
            "an incomplete-hints fallback is noted for the operator"
        );
    }

    #[test]
    fn every_profile_is_read_only_and_env_ref_never_literal() {
        let synth = synthesize_profiles(&[svc("SALES_RO"), svc("HR_RO")], &SynthOptions::default());
        for s in &synth.profiles {
            assert_eq!(s.profile.max_level, Some(OperatingLevel::ReadOnly));
            assert_eq!(s.profile.default_level, Some(OperatingLevel::ReadOnly));
            assert_eq!(s.profile.protected, None, "discovery never marks protected");
            let cred = s
                .profile
                .credential_ref
                .as_deref()
                .expect("credential_ref set");
            assert!(
                cred.starts_with("env:"),
                "credential_ref is an env: placeholder"
            );
            assert!(
                !cred.contains("literal:"),
                "no literal secret ref is ever synthesized"
            );
        }
    }

    #[test]
    fn empty_input_synthesizes_nothing() {
        let synth = synthesize_profiles(&[], &SynthOptions::default());
        assert!(synth.profiles.is_empty());
        assert!(synth.default_profile.is_none());
        // An empty profile set is still a valid config.
        OracleMcpConfig::from_toml_str(&minimal_toml(&synth)).expect("empty set parses");
    }

    // ---- bead .6: secret-ref placeholders + per-service env-var guidance ----

    #[test]
    fn env_var_names_are_deterministic_and_unique_per_profile() {
        let synth = synthesize_profiles(
            &[svc("SALES_RO"), svc("HR_RO"), svc("FIN_RO")],
            &SynthOptions::default(),
        );
        let vars: Vec<&str> = synth
            .profiles
            .iter()
            .map(|s| s.plan.password_env_var.as_str())
            .collect();
        assert_eq!(
            vars,
            vec![
                "ORACLE_SALES_RO_PASSWORD",
                "ORACLE_HR_RO_PASSWORD",
                "ORACLE_FIN_RO_PASSWORD",
            ]
        );
        // The credential_ref on each profile is exactly env:<that var>.
        for s in &synth.profiles {
            assert_eq!(
                s.profile.credential_ref.as_deref(),
                Some(format!("env:{}", s.plan.password_env_var).as_str())
            );
        }
        let unique: BTreeSet<&str> = vars.iter().copied().collect();
        assert_eq!(unique.len(), vars.len(), "env var names are unique");
    }

    #[test]
    fn colliding_aliases_still_get_distinct_env_vars() {
        // Two aliases sanitizing to the same base must not share an env var.
        let synth = synthesize_profiles(
            &[svc("SALES-RO"), svc("SALES_RO")],
            &SynthOptions::default(),
        );
        assert_eq!(
            synth.profiles[0].plan.password_env_var,
            "ORACLE_SALES_RO_PASSWORD"
        );
        assert_eq!(
            synth.profiles[1].plan.password_env_var,
            "ORACLE_SALES_RO_2_PASSWORD"
        );
    }

    #[test]
    fn no_literal_secret_ref_anywhere() {
        let mut tcps = svc("PRIMARY_TCPS");
        tcps.protocol = Some("TCPS".to_owned());
        tcps.wallet_location = Some("/etc/oracle/wallet/primary".to_owned());
        let synth = synthesize_profiles(&[svc("SALES_RO"), tcps], &SynthOptions::default());
        // Neither the profile credential_ref nor any report field is a literal.
        for s in &synth.profiles {
            assert!(
                !s.profile
                    .credential_ref
                    .as_deref()
                    .unwrap_or_default()
                    .contains("literal:")
            );
            assert!(!s.plan.password_env_var.contains("literal:"));
            if let Some(w) = &s.plan.wallet_password_env_var {
                assert!(!w.contains("literal:"));
            }
        }
        // The whole rendered minimum carries no literal token either.
        assert!(!minimal_toml(&synth).contains("literal:"));
    }

    #[test]
    fn tcps_or_wallet_descriptor_surfaces_wallet_password_env_var() {
        // A TCPS protocol implies a wallet-password placeholder.
        let mut tcps = svc("PRIMARY_TCPS");
        tcps.protocol = Some("TCPS".to_owned());
        // A plain descriptor with only a wallet_location hint does too.
        let mut walletonly = svc("WALLET_ONLY");
        walletonly.wallet_location = Some("/etc/oracle/wallet".to_owned());
        // A plain TCP EZConnect does NOT.
        let mut plain = svc("PLAIN_TCP");
        plain.protocol = Some("TCP".to_owned());

        let synth = synthesize_profiles(&[tcps, walletonly, plain], &SynthOptions::default());
        assert_eq!(
            synth.profiles[0].plan.wallet_password_env_var.as_deref(),
            Some("ORACLE_PRIMARY_TCPS_WALLET_PASSWORD")
        );
        assert_eq!(
            synth.profiles[1].plan.wallet_password_env_var.as_deref(),
            Some("ORACLE_WALLET_ONLY_WALLET_PASSWORD")
        );
        assert_eq!(
            synth.profiles[2].plan.wallet_password_env_var, None,
            "a plain TCP target needs no wallet-password ref"
        );
    }

    #[test]
    fn required_env_vars_matches_profiles_including_wallet() {
        let mut tcps = svc("PRIMARY_TCPS");
        tcps.wallet_location = Some("/etc/oracle/wallet/primary".to_owned());
        let synth = synthesize_profiles(&[svc("SALES_RO"), tcps], &SynthOptions::default());
        let env = synth.required_env_vars();
        assert_eq!(
            env,
            vec![
                ("sales_ro".to_owned(), "ORACLE_SALES_RO_PASSWORD".to_owned()),
                (
                    "primary_tcps".to_owned(),
                    "ORACLE_PRIMARY_TCPS_PASSWORD".to_owned()
                ),
                (
                    "primary_tcps".to_owned(),
                    "ORACLE_PRIMARY_TCPS_WALLET_PASSWORD".to_owned()
                ),
            ],
            "the env-var list enumerates every profile's password var, plus a \
             wallet-password var for the TCPS/wallet target"
        );
        // Every listed profile name is a real synthesized profile.
        let names: BTreeSet<&str> = synth
            .profiles
            .iter()
            .map(|s| s.plan.profile_name.as_str())
            .collect();
        for (profile, _) in &env {
            assert!(names.contains(profile.as_str()));
        }
    }

    // ---- bead .7: read-only-safe defaults + fail-closed for unverifiable ----

    #[test]
    fn every_synthesized_profile_is_flagged_needs_verification() {
        let synth = synthesize_profiles(&[svc("SALES_RO"), svc("HR_RO")], &SynthOptions::default());
        for s in &synth.profiles {
            assert!(
                s.plan.needs_verification,
                "a freshly discovered profile is never verified until doctor --online"
            );
        }
    }

    #[test]
    fn unverifiable_bare_alias_stays_read_only_and_flagged() {
        // A degenerate input — an alias with no descriptor hints at all — cannot
        // be confirmed, but it must still yield a profile, capped READ_ONLY on
        // both levels, present and flagged (fail closed, never dropped).
        let synth = synthesize_profiles(&[svc("MYSTERY")], &SynthOptions::default());
        assert_eq!(synth.profiles.len(), 1, "unverifiable input is not dropped");
        let only = &synth.profiles[0];
        assert_eq!(only.profile.max_level, Some(OperatingLevel::ReadOnly));
        assert_eq!(only.profile.default_level, Some(OperatingLevel::ReadOnly));
        assert_eq!(
            only.profile.protected, None,
            "an unverifiable target is never opted up to protected/READ_WRITE"
        );
        assert!(only.plan.needs_verification);
    }
}
