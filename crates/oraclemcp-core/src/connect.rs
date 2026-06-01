//! Connection bootstrap (plan §8.4; bead P1-6): turn a named profile into the
//! connection options + the session's operating-level ceiling + the ordered
//! login statements, so `oracle_connect(profile)` needs no out-of-band setup
//! and the agent never handles raw credentials or Oracle connection syntax.
//!
//! `list_profiles` is `oraclemcp_config::OracleMcpConfig::list_profiles` (it
//! already omits secret references). The login script runs on lease acquire
//! (`oraclemcp_db::LeaseManager::acquire`).

use oraclemcp_config::ConnectionProfile;
use oraclemcp_db::{OracleConnectOptions, canonical_nls_statements};
use oraclemcp_guard::{OperatingLevel, SessionLevelState, read_only_setup_statements};

/// Everything `oracle_connect` needs once a profile is resolved.
#[derive(Clone, Debug)]
pub struct SessionContext {
    /// The profile name.
    pub profile_name: String,
    /// The driver connect options (credential filled by the secrets backend).
    pub options: OracleConnectOptions,
    /// The session operating-level state (ceiling applied, standby-forced).
    pub level_state: SessionLevelState,
    /// Ordered login statements: canonical NLS, the read-only backstop (if the
    /// level is `READ_ONLY`), then the operator's profile login statements.
    pub login_statements: Vec<String>,
}

/// Map a profile to driver connect options. `password` comes from the secrets
/// backend (never the profile/metadata).
#[must_use]
pub fn profile_to_options(
    profile: &ConnectionProfile,
    password: Option<String>,
) -> OracleConnectOptions {
    let oci = profile.oci.clone();
    OracleConnectOptions {
        connect_string: profile.connect_string.clone().unwrap_or_default(),
        username: profile.username.clone(),
        password,
        external_auth: profile.username.is_none() && password_is_none(&profile.credential_ref),
        wallet_location: oci.as_ref().and_then(|o| o.wallet_location.clone()),
        use_iam_token: oci.as_ref().is_some_and(|o| o.use_iam_token),
        iam_token: None,
    }
}

fn password_is_none(credential_ref: &Option<String>) -> bool {
    credential_ref.is_none()
}

/// The session's operating-level ceiling: the profile's `max_level`, forced to
/// `READ_ONLY` (and `protected`) when the target is a read-only standby (§5.8).
#[must_use]
pub fn session_level_state(
    profile: &ConnectionProfile,
    standby_read_only: bool,
) -> SessionLevelState {
    let max = if standby_read_only || profile.read_only_standby() {
        OperatingLevel::ReadOnly
    } else {
        profile.max_level()
    };
    let protected = profile.protected() || standby_read_only || profile.read_only_standby();
    SessionLevelState::new(max, protected)
}

/// Assemble a [`SessionContext`] for a profile.
#[must_use]
pub fn build_session_context(
    profile: &ConnectionProfile,
    password: Option<String>,
    standby_read_only: bool,
) -> SessionContext {
    let level_state = session_level_state(profile, standby_read_only);
    let mut login_statements: Vec<String> = canonical_nls_statements()
        .into_iter()
        .map(str::to_owned)
        .collect();
    // Read-only backstop when the session starts (and stays capped at) READ_ONLY.
    if level_state.effective_ceiling() == OperatingLevel::ReadOnly {
        login_statements.extend(
            read_only_setup_statements(OperatingLevel::ReadOnly)
                .into_iter()
                .map(str::to_owned),
        );
    }
    if let Some(extra) = &profile.login_statements {
        login_statements.extend(extra.clone());
    }
    SessionContext {
        profile_name: profile.name.clone(),
        options: profile_to_options(profile, password),
        level_state,
        login_statements,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_config::OracleMcpConfig;

    fn profile(toml: &str) -> ConnectionProfile {
        OracleMcpConfig::from_toml_str(toml)
            .expect("config")
            .profiles
            .into_iter()
            .next()
            .expect("profile")
    }

    #[test]
    fn maps_connect_string_and_username() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            username = "scott"
            "#,
        );
        let ctx = build_session_context(&p, Some("tiger".to_owned()), false);
        assert_eq!(ctx.options.connect_string, "localhost:1521/FREEPDB1");
        assert_eq!(ctx.options.username.as_deref(), Some("scott"));
        assert_eq!(ctx.options.password.as_deref(), Some("tiger"));
        assert!(!ctx.options.external_auth);
    }

    #[test]
    fn protected_profile_pins_read_only_and_adds_backstop() {
        let p = profile(
            r#"
            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            protected = true
            "#,
        );
        let ctx = build_session_context(&p, None, false);
        assert_eq!(ctx.level_state.max_level(), OperatingLevel::ReadOnly);
        assert!(ctx.level_state.is_protected());
        assert!(
            ctx.login_statements
                .iter()
                .any(|s| s.contains("SET TRANSACTION READ ONLY"))
        );
        // Canonical NLS is always applied.
        assert!(
            ctx.login_statements
                .iter()
                .any(|s| s.contains("NLS_DATE_FORMAT"))
        );
    }

    #[test]
    fn standby_forces_read_only_even_for_a_high_ceiling_profile() {
        let p = profile(
            r#"
            [[profiles]]
            name = "replica"
            connect_string = "replica:1521/svc"
            max_level = "DDL"
            "#,
        );
        let ctx = build_session_context(&p, None, true);
        assert_eq!(ctx.level_state.max_level(), OperatingLevel::ReadOnly);
        assert!(ctx.level_state.is_protected());
    }

    #[test]
    fn wallet_profile_uses_external_auth() {
        let p = profile(
            r#"
            [[profiles]]
            name = "cloud"
            connect_string = "tcps://adb.example/svc"
            [profiles.oci]
            wallet_location = "/wallets/adb"
            "#,
        );
        let ctx = build_session_context(&p, None, false);
        assert!(
            ctx.options.external_auth,
            "no username/credential -> external/wallet auth"
        );
        assert_eq!(
            ctx.options.wallet_location.as_deref(),
            Some(std::path::Path::new("/wallets/adb"))
        );
    }
}
