//! Connection bootstrap (plan §8.4; bead P1-6): turn a named profile into the
//! connection options + the session's operating-level ceiling + the ordered
//! login statements, so `oracle_connect(profile)` needs no out-of-band setup
//! and the agent never handles raw credentials or Oracle connection syntax.
//!
//! `list_profiles` is `oraclemcp_config::OracleMcpConfig::list_profiles` (it
//! already omits secret references). Profile login statements are allowlisted
//! and carried to both the default connection and leased sessions.

use std::{fs, path::Path, time::Duration};

use oraclemcp_config::{ConnectionProfile, DrcpRoutingConfig, DrcpSessionPurity};
use oraclemcp_db::{
    AuthAdapter, DbError, DrcpConfig, OracleConnectOptions, OracleSessionIdentity, PoolSettings,
    SessionPurity, canonical_nls_statements,
};
use oraclemcp_guard::{
    OperatingLevel, SessionLevelState, is_allowed_alter_session, read_only_setup_statements,
};

/// Everything `oracle_connect` needs once a profile is resolved.
#[derive(Clone)]
pub struct SessionContext {
    /// The profile name.
    pub profile_name: String,
    /// The driver connect options (credential filled by the secrets backend).
    pub options: OracleConnectOptions,
    /// The session operating-level state (ceiling applied, standby-forced).
    pub level_state: SessionLevelState,
    /// Optional local stateless-read pool settings from `[profiles.pool]`.
    pub pool_settings: Option<PoolSettings>,
    /// Ordered login statements: canonical NLS, the read-only backstop (if the
    /// level is `READ_ONLY`), then the operator's profile login statements.
    pub login_statements: Vec<String>,
}

impl std::fmt::Debug for SessionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionContext")
            .field("profile_name", &self.profile_name)
            .field("options", &self.options)
            .field("level_state", &self.level_state)
            .field("pool_settings", &self.pool_settings)
            .field("login_statement_count", &self.login_statements.len())
            .finish()
    }
}

impl SessionContext {
    /// Derive this session's per-request resource budget (B6) from its
    /// configured per-call timeout (or the default when unset), anchored to
    /// `now` (pass the request `Cx`'s `cx.now()` so production and lab share one
    /// deterministic clock).
    ///
    /// The dispatch boundary attaches this budget so the DB round trips run
    /// under a single cooperative bound: a runaway request is bounded
    /// (`Cancelled`/`Timeout`, per B1), while a normal request is unaffected.
    /// The budget's deadline maps onto the same `call_timeout` the adapter
    /// already pushes down as an Oracle op-deadline, so the two agree by
    /// construction.
    #[must_use]
    pub fn request_budget(&self, now: asupersync::Time) -> crate::request_budget::RequestBudget {
        crate::request_budget::RequestBudget::from_call_timeout(now, self.options.call_timeout)
    }
}

/// Map a profile to driver connect options. `password` comes from the secrets
/// backend (never the profile/metadata). `wallet_password` comes from the
/// same secret-resolution path via `[profiles.oci].wallet_password_ref`.
pub fn profile_to_options(
    profile: &ConnectionProfile,
    password: Option<String>,
    wallet_password: Option<String>,
) -> Result<OracleConnectOptions, DbError> {
    let level_state = session_level_state(profile, false);
    profile_to_options_for_level(profile, password, wallet_password, &level_state)
}

fn password_is_none(credential_ref: &Option<String>) -> bool {
    credential_ref.is_none()
}

fn profile_auth_adapter(profile: &ConnectionProfile) -> Result<AuthAdapter, DbError> {
    let Some(proxy) = &profile.proxy_auth else {
        return Ok(AuthAdapter::Password);
    };
    let proxy_user = proxy.proxy_user().ok_or_else(|| {
        DbError::UnsupportedAuth(
            "profile proxy_auth requires non-empty proxy_user and target_schema".to_owned(),
        )
    })?;
    let target_schema = proxy.target_schema().ok_or_else(|| {
        DbError::UnsupportedAuth(
            "profile proxy_auth requires non-empty proxy_user and target_schema".to_owned(),
        )
    })?;
    if let Some(username) = profile.username.as_deref()
        && username.trim() != proxy_user
    {
        return Err(DbError::UnsupportedAuth(
            "profile proxy_auth.proxy_user must match username when both are set".to_owned(),
        ));
    }
    Ok(AuthAdapter::Proxy {
        proxy_user: proxy_user.to_owned(),
        target_schema: target_schema.to_owned(),
    })
}

fn profile_username(profile: &ConnectionProfile, auth_adapter: &AuthAdapter) -> Option<String> {
    match auth_adapter {
        AuthAdapter::Proxy { proxy_user, .. } => Some(proxy_user.clone()),
        _ => profile.username.clone(),
    }
}

fn profile_app_context(
    profile: &ConnectionProfile,
) -> Result<Vec<(String, String, String)>, DbError> {
    let Some(entries) = &profile.app_context else {
        return Ok(Vec::new());
    };
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            entry.driver_tuple().ok_or_else(|| {
                DbError::UnsupportedAuth(format!(
                    "profile `{}` app_context[{index}] requires non-empty namespace and key",
                    profile.name
                ))
            })
        })
        .collect()
}

fn profile_drcp_config(drcp: &DrcpRoutingConfig) -> DrcpConfig {
    let purity = match drcp.purity {
        DrcpSessionPurity::Reuse => SessionPurity::Reuse,
        DrcpSessionPurity::New => SessionPurity::New,
    };
    DrcpConfig {
        pooled: drcp.pooled,
        connection_class: drcp.connection_class().map(str::to_owned),
        purity,
    }
}

fn profile_connect_string(profile: &ConnectionProfile) -> String {
    let base = profile.connect_string.clone().unwrap_or_default();
    profile.drcp.as_ref().map_or(base.clone(), |drcp| {
        profile_drcp_config(drcp).apply_to_connect_string(&base)
    })
}

/// Map `[profiles.pool]` into the DB crate's runtime pool settings.
#[must_use]
pub fn profile_pool_settings(profile: &ConnectionProfile) -> Option<PoolSettings> {
    profile.pool.as_ref().map(|pool| PoolSettings {
        max_size: pool.max_size,
        min_idle: pool.min_idle,
        acquire_timeout_secs: pool.acquire_timeout_secs,
        statement_cache_size: pool.statement_cache_size,
    })
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
    wallet_password: Option<String>,
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
        options: profile_to_options_for_level(profile, password, wallet_password, &level_state)?,
        level_state,
        pool_settings: profile_pool_settings(profile),
        login_statements,
    })
}

fn profile_to_options_for_level(
    profile: &ConnectionProfile,
    password: Option<String>,
    wallet_password: Option<String>,
    level_state: &SessionLevelState,
) -> Result<OracleConnectOptions, DbError> {
    let oci = profile.oci.clone();
    let auth_adapter = profile_auth_adapter(profile)?;
    let username = profile_username(profile, &auth_adapter);
    Ok(OracleConnectOptions {
        connect_string: profile_connect_string(profile),
        username: username.clone(),
        password,
        auth_adapter,
        external_auth: username.is_none() && password_is_none(&profile.credential_ref),
        wallet_location: oci.as_ref().and_then(|o| o.wallet_location.clone()),
        wallet_password,
        ssl_server_dn_match: oci.as_ref().and_then(|o| o.ssl_server_dn_match),
        ssl_server_cert_dn: oci.as_ref().and_then(|o| o.ssl_server_cert_dn.clone()),
        use_sni: oci.as_ref().and_then(|o| o.use_sni),
        use_iam_token: oci.as_ref().is_some_and(|o| o.use_iam_token),
        // The B2 adapter (oraclemcp_db) now wires an IAM database token through
        // `with_access_token` (TCPS-enforced) whenever this field is `Some`. The
        // token itself is fetched at the edge from OCI IAM via
        // `oraclemcp_db::IamTokenSource` / `ensure_fresh_token` and injected here
        // by the caller that owns the token lifecycle (proactive skew-based
        // refresh); profile bootstrap never embeds a token. With `use_iam_token`
        // set but no token yet injected, the adapter returns a precise setup
        // error rather than attempting a password connect.
        iam_token: None,
        session_identity: profile
            .session_identity
            .as_ref()
            .map(|identity| OracleSessionIdentity {
                edition: identity.edition.clone(),
                program: identity.program.clone(),
                machine: identity.machine.clone(),
                os_user: identity.os_user.clone(),
                terminal: identity.terminal.clone(),
                module: identity.module.clone(),
                action: identity.action.clone(),
                client_identifier: identity.client_identifier.clone(),
                client_info: identity.client_info.clone(),
                driver_name: identity.driver_name.clone(),
            }),
        app_context: profile_app_context(profile)?,
        sdu: profile.sdu,
        statement_cache_size: profile.pool.as_ref().map(|pool| pool.statement_cache_size),
        call_timeout: profile.call_timeout_seconds.map(Duration::from_secs),
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
        let ctx =
            build_session_context(&p, Some("tiger".to_owned()), None, false).expect("context");
        assert_eq!(ctx.options.connect_string, "localhost:1521/FREEPDB1");
        assert_eq!(ctx.options.username.as_deref(), Some("scott"));
        assert_eq!(ctx.options.password.as_deref(), Some("tiger"));
        assert!(!ctx.options.external_auth);
        assert_eq!(ctx.options.sdu, None);
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
        let ctx = build_session_context(&p, None, None, false).expect("context");
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
        let ctx = build_session_context(&p, None, None, true).expect("context");
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
            call_timeout_seconds = 45
            "#,
        );
        let ctx = build_session_context(&p, None, None, false).expect("context");
        assert_eq!(ctx.level_state.max_level(), OperatingLevel::Ddl);
        assert_eq!(ctx.level_state.effective_level(), OperatingLevel::ReadWrite);
        assert_eq!(ctx.options.call_timeout, Some(Duration::from_secs(45)));
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
        let ctx = build_session_context(&p, None, None, false).expect("context");
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
    fn oci_tls_fields_are_carried_to_connect_options() {
        let p = profile(
            r#"
            [[profiles]]
            name = "cloud"
            connect_string = "tcps://adb.example/svc"
            username = "app"
            credential_ref = "env:APP_PASSWORD"

            [profiles.oci]
            wallet_location = "/wallets/adb"
            wallet_password_ref = "env:WALLET_PASSWORD"
            ssl_server_dn_match = false
            ssl_server_cert_dn = "CN=db.example.com,O=Example,C=US"
            use_sni = false
            "#,
        );
        let ctx = build_session_context(
            &p,
            Some("db-password".to_owned()),
            Some("wallet-password".to_owned()),
            false,
        )
        .expect("context");

        assert!(!ctx.options.external_auth);
        assert_eq!(
            ctx.options.wallet_location.as_deref(),
            Some(std::path::Path::new("/wallets/adb"))
        );
        assert_eq!(
            ctx.options.wallet_password.as_deref(),
            Some("wallet-password")
        );
        assert_eq!(ctx.options.ssl_server_dn_match, Some(false));
        assert_eq!(
            ctx.options.ssl_server_cert_dn.as_deref(),
            Some("CN=db.example.com,O=Example,C=US")
        );
        assert_eq!(ctx.options.use_sni, Some(false));
    }

    #[test]
    fn proxy_auth_is_carried_to_connect_options() {
        let p = profile(
            r#"
            [[profiles]]
            name = "proxy"
            connect_string = "localhost:1521/FREEPDB1"
            credential_ref = "env:PROXY_PASSWORD"
            max_level = "READ_ONLY"
            default_level = "READ_ONLY"

            [profiles.proxy_auth]
            proxy_user = "MCP_PROXY"
            target_schema = "APP_OWNER"
            "#,
        );
        let ctx = build_session_context(&p, Some("proxy-password".to_owned()), None, false)
            .expect("context");

        assert_eq!(ctx.options.username.as_deref(), Some("MCP_PROXY"));
        assert_eq!(ctx.options.password.as_deref(), Some("proxy-password"));
        assert!(!ctx.options.external_auth);
        assert_eq!(ctx.level_state.max_level(), OperatingLevel::ReadOnly);
        assert_eq!(ctx.level_state.effective_level(), OperatingLevel::ReadOnly);
        assert!(matches!(
            ctx.options.auth_adapter,
            AuthAdapter::Proxy {
                ref proxy_user,
                ref target_schema
            } if proxy_user == "MCP_PROXY" && target_schema == "APP_OWNER"
        ));
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
            program = "agent-program"
            machine = "agent-host"
            os_user = "agent-os-user"
            terminal = "agent-terminal"
            module = "local-tool"
            action = "inspect"
            client_identifier = "agent"
            client_info = "workspace"
            driver_name = "driver"
            "#,
        );
        let ctx = build_session_context(&p, None, None, false).expect("context");
        let identity = ctx
            .options
            .session_identity
            .as_ref()
            .expect("session identity");
        assert_eq!(identity.edition.as_deref(), Some("v1"));
        assert_eq!(identity.program.as_deref(), Some("agent-program"));
        assert_eq!(identity.machine.as_deref(), Some("agent-host"));
        assert_eq!(identity.os_user.as_deref(), Some("agent-os-user"));
        assert_eq!(identity.terminal.as_deref(), Some("agent-terminal"));
        assert_eq!(identity.module.as_deref(), Some("local-tool"));
        assert_eq!(identity.action.as_deref(), Some("inspect"));
        assert_eq!(identity.client_identifier.as_deref(), Some("agent"));
        assert_eq!(identity.client_info.as_deref(), Some("workspace"));
        assert_eq!(identity.driver_name.as_deref(), Some("driver"));
    }

    #[test]
    fn app_context_is_carried_to_connect_options_in_order() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles.app_context]]
            namespace = "ORACLEMCP_CTX"
            key = "tenant_id"
            value = "tenant-123"

            [[profiles.app_context]]
            namespace = "ORACLEMCP_CTX"
            key = "request_id"
            value = "req-456"
            "#,
        );
        let ctx = build_session_context(&p, None, None, false).expect("context");

        assert_eq!(
            ctx.options.app_context,
            vec![
                (
                    "ORACLEMCP_CTX".to_owned(),
                    "tenant_id".to_owned(),
                    "tenant-123".to_owned()
                ),
                (
                    "ORACLEMCP_CTX".to_owned(),
                    "request_id".to_owned(),
                    "req-456".to_owned()
                )
            ]
        );
    }

    #[test]
    fn drcp_and_sdu_are_carried_to_connect_options() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1?wallet_location=/wallets/dev"
            sdu = 32768

            [profiles.drcp]
            pooled = true
            connection_class = "AGENTS_RO"
            purity = "new"
            "#,
        );
        let ctx = build_session_context(&p, None, None, false).expect("context");

        assert_eq!(
            ctx.options.connect_string,
            "localhost:1521/FREEPDB1?wallet_location=/wallets/dev&server=pooled&pool_connection_class=AGENTS_RO&pool_purity=new"
        );
        assert_eq!(ctx.options.sdu, Some(32_768));
    }

    #[test]
    fn pool_settings_are_carried_to_session_context() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"

            [profiles.pool]
            max_size = 7
            min_idle = 3
            acquire_timeout_secs = 9
            statement_cache_size = 128
            "#,
        );
        let ctx = build_session_context(&p, None, None, false).expect("context");
        let pool = ctx.pool_settings.expect("pool settings");

        assert_eq!(pool.max_size, 7);
        assert_eq!(pool.min_idle, 3);
        assert_eq!(pool.acquire_timeout_secs, 9);
        assert_eq!(pool.statement_cache_size, 128);
        assert_eq!(ctx.options.statement_cache_size, Some(128));
    }

    #[test]
    fn absent_pool_keeps_single_session_strategy() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            "#,
        );
        let ctx = build_session_context(&p, None, None, false).expect("context");
        assert!(ctx.pool_settings.is_none());
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
        let ctx = build_session_context(&p, None, None, false).expect("context");
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
    fn session_context_debug_redacts_login_statement_values() {
        let p = profile(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"
            trusted_session_statements = [
              "BEGIN DBMS_SESSION.SET_CONTEXT('PRIVATE_NS','TOKEN','secret-token'); END;",
            ]
            "#,
        );
        let ctx = build_session_context(&p, Some("secret-password".to_owned()), None, false)
            .expect("context");
        let rendered = format!("{ctx:?}");

        assert!(
            !rendered.contains("secret-token") && !rendered.contains("PRIVATE_NS"),
            "login statement leaked: {rendered}"
        );
        assert!(
            !rendered.contains("secret-password"),
            "password leaked: {rendered}"
        );
        assert!(rendered.contains("login_statement_count"));
        assert!(rendered.contains("session_statement_count"));
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
        let err = build_session_context(&p, None, None, false).unwrap_err();
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
        let ctx = build_session_context(&p, None, None, false).expect("context");
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
        let err =
            build_session_context(&p, None, None, false).expect_err("unsafe statement rejected");
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
        let ctx = build_session_context(&p, None, None, false).expect("context");
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
