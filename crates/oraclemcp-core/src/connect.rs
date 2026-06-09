//! Connection bootstrap (plan §8.4; bead P1-6): turn a named profile into the
//! connection options + the session's operating-level ceiling + the ordered
//! login statements, so `oracle_connect(profile)` needs no out-of-band setup
//! and the agent never handles raw credentials or Oracle connection syntax.
//!
//! `list_profiles` is `oraclemcp_config::OracleMcpConfig::list_profiles` (it
//! already omits secret references). Profile login statements are allowlisted
//! and carried to both the default connection and leased sessions.

use std::{fs, path::Path};

use oraclemcp_config::ConnectionProfile;
use oraclemcp_db::{
    DbError, OracleConnectOptions, OracleSessionIdentity, canonical_nls_statements,
};
use oraclemcp_guard::{
    OperatingLevel, SessionLevelState, is_allowed_alter_session, read_only_setup_statements,
};

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
pub fn profile_to_options(
    profile: &ConnectionProfile,
    password: Option<String>,
) -> Result<OracleConnectOptions, DbError> {
    let level_state = session_level_state(profile, false);
    profile_to_options_for_level(profile, password, &level_state)
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
    let forced_read_only = standby_read_only || profile.read_only_standby();
    let max = if forced_read_only {
        OperatingLevel::ReadOnly
    } else {
        profile.max_level()
    };
    let protected = profile.protected() || forced_read_only;
    let default = if forced_read_only {
        OperatingLevel::ReadOnly
    } else {
        profile.default_level().min(max)
    };
    let mut level_state = SessionLevelState::new(max, protected);
    level_state
        .set_current_level(default)
        .expect("default level is clamped to the effective ceiling");
    level_state
}

/// Assemble a [`SessionContext`] for a profile.
pub fn build_session_context(
    profile: &ConnectionProfile,
    password: Option<String>,
    standby_read_only: bool,
) -> Result<SessionContext, DbError> {
    let level_state = session_level_state(profile, standby_read_only);
    let mut login_statements: Vec<String> = canonical_nls_statements()
        .into_iter()
        .map(str::to_owned)
        .collect();
    login_statements.extend(profile_session_statements(profile, &level_state)?);
    Ok(SessionContext {
        profile_name: profile.name.clone(),
        options: profile_to_options_for_level(profile, password, &level_state)?,
        level_state,
        login_statements,
    })
}

fn profile_to_options_for_level(
    profile: &ConnectionProfile,
    password: Option<String>,
    level_state: &SessionLevelState,
) -> Result<OracleConnectOptions, DbError> {
    let oci = profile.oci.clone();
    Ok(OracleConnectOptions {
        connect_string: profile.connect_string.clone().unwrap_or_default(),
        username: profile.username.clone(),
        password,
        external_auth: profile.username.is_none() && password_is_none(&profile.credential_ref),
        wallet_location: oci.as_ref().and_then(|o| o.wallet_location.clone()),
        use_iam_token: oci.as_ref().is_some_and(|o| o.use_iam_token),
        iam_token: None,
        session_identity: profile
            .session_identity
            .as_ref()
            .map(|identity| OracleSessionIdentity {
                edition: identity.edition.clone(),
                module: identity.module.clone(),
                action: identity.action.clone(),
                client_identifier: identity.client_identifier.clone(),
                client_info: identity.client_info.clone(),
                driver_name: identity.driver_name.clone(),
            }),
        session_statements: profile_session_statements(profile, level_state)?,
    })
}

fn profile_session_statements(
    profile: &ConnectionProfile,
    level_state: &SessionLevelState,
) -> Result<Vec<String>, DbError> {
    let mut out = Vec::new();
    // Read-only backstop when the session starts (and stays capped at) READ_ONLY.
    if level_state.effective_ceiling() == OperatingLevel::ReadOnly {
        out.extend(
            read_only_setup_statements(OperatingLevel::ReadOnly)
                .into_iter()
                .map(str::to_owned),
        );
    }
    if let Some(extra) = &profile.login_statements {
        for stmt in extra {
            out.push(validate_login_statement(&profile.name, stmt)?);
        }
    }
    if let Some(path) = &profile.login_script {
        for stmt in read_login_script(&profile.name, path)? {
            out.push(validate_login_statement(&profile.name, &stmt)?);
        }
    }
    if let Some(extra) = &profile.trusted_session_statements {
        for stmt in extra {
            out.push(validate_trusted_session_statement(&profile.name, stmt)?);
        }
    }
    Ok(out)
}

fn validate_login_statement(profile: &str, statement: &str) -> Result<String, DbError> {
    let trimmed = statement.trim().trim_end_matches(';').trim();
    if trimmed.is_empty() {
        return Err(DbError::UnsupportedAuth(format!(
            "profile `{profile}` contains an empty login statement"
        )));
    }
    if is_allowed_alter_session(trimmed) {
        Ok(trimmed.to_owned())
    } else {
        Err(DbError::UnsupportedAuth(format!(
            "profile `{profile}` login statement is not an allowlisted ALTER SESSION SET statement: {trimmed:?}"
        )))
    }
}

fn validate_trusted_session_statement(profile: &str, statement: &str) -> Result<String, DbError> {
    let trimmed = statement.trim();
    if trimmed.is_empty() {
        return Err(DbError::UnsupportedAuth(format!(
            "profile `{profile}` contains an empty trusted_session_statements entry"
        )));
    }
    Ok(trimmed.to_owned())
}

fn read_login_script(profile: &str, path: &Path) -> Result<Vec<String>, DbError> {
    let text = fs::read_to_string(path).map_err(|e| {
        DbError::UnsupportedAuth(format!(
            "failed to read login_script for profile `{profile}` at {}: {e}",
            path.display()
        ))
    })?;
    Ok(split_login_script(&text))
}

fn split_login_script(text: &str) -> Vec<String> {
    let mut script = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("--") {
            continue;
        }
        script.push_str(line);
        script.push('\n');
    }

    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    for ch in script.chars() {
        match ch {
            '\'' => {
                in_string = !in_string;
                current.push(ch);
            }
            ';' if !in_string => {
                let stmt = current.trim();
                if !stmt.is_empty() {
                    out.push(stmt.to_owned());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let stmt = current.trim();
    if !stmt.is_empty() {
        out.push(stmt.to_owned());
    }
    out
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
        let ctx = build_session_context(&p, Some("tiger".to_owned()), false).expect("context");
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
        let ctx = build_session_context(&p, None, false).expect("context");
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
            default_level = "READ_WRITE"
            "#,
        );
        let ctx = build_session_context(&p, None, true).expect("context");
        assert_eq!(ctx.level_state.max_level(), OperatingLevel::ReadOnly);
        assert_eq!(ctx.level_state.effective_level(), OperatingLevel::ReadOnly);
        assert!(ctx.level_state.is_protected());
    }

    #[test]
    fn default_level_sets_initial_session_level_within_ceiling() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "DDL"
            default_level = "READ_WRITE"
            "#,
        );
        let ctx = build_session_context(&p, None, false).expect("context");
        assert_eq!(ctx.level_state.max_level(), OperatingLevel::Ddl);
        assert_eq!(ctx.level_state.effective_level(), OperatingLevel::ReadWrite);
        assert!(!ctx.level_state.is_protected());
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
        let ctx = build_session_context(&p, None, false).expect("context");
        assert!(
            ctx.options.external_auth,
            "no username/credential -> external/wallet auth"
        );
        assert_eq!(
            ctx.options.wallet_location.as_deref(),
            Some(std::path::Path::new("/wallets/adb"))
        );
    }

    #[test]
    fn session_identity_is_carried_to_connect_options() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.session_identity]
            edition = "v1"
            module = "local-tool"
            action = "inspect"
            client_identifier = "agent"
            client_info = "workspace"
            driver_name = "driver"
            "#,
        );
        let ctx = build_session_context(&p, None, false).expect("context");
        let identity = ctx
            .options
            .session_identity
            .as_ref()
            .expect("session identity");
        assert_eq!(identity.edition.as_deref(), Some("v1"));
        assert_eq!(identity.module.as_deref(), Some("local-tool"));
        assert_eq!(identity.action.as_deref(), Some("inspect"));
        assert_eq!(identity.client_identifier.as_deref(), Some("agent"));
        assert_eq!(identity.client_info.as_deref(), Some("workspace"));
        assert_eq!(identity.driver_name.as_deref(), Some("driver"));
    }

    #[test]
    fn trusted_session_statements_are_carried_after_guarded_login_statements() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            login_statements = [
              "ALTER SESSION SET NLS_LANGUAGE=english",
            ]
            trusted_session_statements = [
              "BEGIN DBMS_OUTPUT.ENABLE(500000); END;",
            ]
            "#,
        );
        let ctx = build_session_context(&p, None, false).expect("context");
        assert!(
            ctx.options
                .session_statements
                .iter()
                .any(|s| s == "ALTER SESSION SET NLS_LANGUAGE=english")
        );
        assert_eq!(
            ctx.options.session_statements.last().map(String::as_str),
            Some("BEGIN DBMS_OUTPUT.ENABLE(500000); END;")
        );
    }

    #[test]
    fn empty_trusted_session_statement_is_rejected() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            trusted_session_statements = ["  "]
            "#,
        );
        let err = build_session_context(&p, None, false).unwrap_err();
        assert!(
            err.to_string()
                .contains("empty trusted_session_statements entry")
        );
    }

    #[test]
    fn profile_login_statements_are_validated_and_carried_to_connect_options() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            login_statements = [
              "ALTER SESSION SET NLS_LANGUAGE=english",
              "ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL';",
            ]
            "#,
        );
        let ctx = build_session_context(&p, None, false).expect("context");
        assert!(
            ctx.options
                .session_statements
                .iter()
                .any(|s| s == "ALTER SESSION SET NLS_LANGUAGE=english")
        );
        assert!(
            ctx.options
                .session_statements
                .iter()
                .any(|s| s == "ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL'")
        );
    }

    #[test]
    fn unsafe_profile_login_statement_is_rejected() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            login_statements = ["ALTER SESSION SET SQL_TRACE = TRUE"]
            "#,
        );
        let err = build_session_context(&p, None, false).expect_err("unsafe statement rejected");
        assert!(err.to_string().contains("not an allowlisted ALTER SESSION"));
    }

    #[test]
    fn login_script_is_read_split_and_validated() {
        let path = std::env::temp_dir().join(format!("oraclemcp-login-{}.sql", std::process::id()));
        std::fs::write(
            &path,
            "-- profile-local setup\n\
             ALTER SESSION SET NLS_LANGUAGE = english;\n\
             ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL';\n",
        )
        .expect("write login script");
        let toml = format!(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            login_script = "{}"
            "#,
            path.display()
        );
        let p = profile(&toml);
        let ctx = build_session_context(&p, None, false).expect("context");
        let _ = std::fs::remove_file(&path);
        assert!(
            ctx.options
                .session_statements
                .iter()
                .any(|s| s == "ALTER SESSION SET NLS_LANGUAGE = english")
        );
        assert!(
            ctx.options
                .session_statements
                .iter()
                .any(|s| s == "ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL'")
        );
    }

    #[test]
    fn split_login_script_keeps_semicolons_inside_literals() {
        let stmts = split_login_script("ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL;';");
        assert_eq!(
            stmts,
            vec!["ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL;'"]
        );
    }
}
