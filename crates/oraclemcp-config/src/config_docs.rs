//! Generated config-reference metadata (bead `oraclemcp-2q4em.3.2`).
//!
//! One [`ConfigFieldDoc`] per leaf configuration key, rendered by
//! `oraclemcp robot-docs config --markdown` and written into
//! `docs/configuration.md` by `scripts/docs_generate.sh`. This table is
//! hand-kept (no derive/proc-macro dependency in an engine-free crate), and it
//! is guarded by [`tests::documented_keys_cover_every_serialized_config_key`],
//! which serializes a maximal config, re-parses it through serde
//! (`deny_unknown_fields`), and asserts the documented key set equals the
//! parsed key set — completeness by construction, not by a reviewer's memory.

/// Documentation metadata for one leaf configuration key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigFieldDoc {
    /// Full dotted key path, e.g. `profiles.masking.rules.action`.
    pub key: &'static str,
    /// Value type as written in TOML.
    pub ty: &'static str,
    /// Documented default when the key is omitted.
    pub default: &'static str,
    /// Whether `base` inheritance fills this key from a parent profile.
    pub inherits_from_base: bool,
    /// Whether diagnostics/profile output redact the value.
    pub redacted_in_diagnostics: bool,
    /// Config `schema_version` that first accepted the key.
    pub since: &'static str,
    /// One-line effect.
    pub description: &'static str,
}

macro_rules! doc {
    ($key:literal, $ty:literal, $default:literal, $inherits:literal, $redacted:literal, $since:literal, $desc:literal) => {
        ConfigFieldDoc {
            key: $key,
            ty: $ty,
            default: $default,
            inherits_from_base: $inherits,
            redacted_in_diagnostics: $redacted,
            since: $since,
            description: $desc,
        }
    };
}

/// Every leaf configuration key, in reference order.
#[must_use]
pub fn config_field_docs() -> &'static [ConfigFieldDoc] {
    DOCS
}

#[rustfmt::skip]
static DOCS: &[ConfigFieldDoc] = &[
    // ---- top level -------------------------------------------------------
    doc!("schema_version", "integer", "2", false, false, "1", "Config schema version this build understands; a higher value is rejected."),
    doc!("default_profile", "string", "none", false, false, "1", "Profile used when serve is not given --profile."),
    doc!("monitor_profile", "string", "none", false, false, "1", "Least-privilege profile for fleet-wide v$session/DB observability."),
    // ---- [http] ----------------------------------------------------------
    doc!("http.allowed_hosts", "array of string", "[]", false, false, "1", "Host authorities allowed beyond loopback."),
    doc!("http.allowed_origins", "array of string", "[]", false, false, "1", "Browser Origin values allowed beyond loopback origins."),
    doc!("http.json_response", "bool", "false", false, false, "1", "Prefer direct JSON responses for stateless requests."),
    doc!("http.stateful", "bool", "false", false, false, "1", "Enable Streamable HTTP stateful session framing."),
    doc!("http.stateful_idle_ttl_seconds", "integer", "900", false, false, "1", "Seconds before an idle stateful session is reaped; 0 disables reaping."),
    doc!("http.dashboard_workbench", "bool", "false", false, false, "1", "Release gate for the browser Safe SQL Workbench."),
    doc!("http.trusted_https_termination", "bool", "false", false, false, "1", "Assert external clients reach this plaintext listener only through a trusted HTTPS terminator."),
    doc!("http.allow_remote", "bool", "false", false, false, "1", "Permit a non-loopback bind without auth/TLS when combined with --allow-no-auth (fail-closed default)."),
    doc!("http.oauth.resource", "string", "none", false, false, "1", "Canonical resource/audience identifier expected in JWT aud."),
    doc!("http.oauth.allowed_issuers", "array of string", "[]", false, false, "1", "Allowed JWT issuers (iss); empty is invalid config."),
    doc!("http.oauth.authorization_servers", "array of string", "[]", false, false, "1", "Authorization servers advertised in RFC 9728 metadata."),
    doc!("http.oauth.required_scopes", "array of string", "[]", false, false, "1", "Scopes every token must carry before dispatch."),
    doc!("http.oauth.hs256_secret_ref", "secret ref", "none", false, true, "1", "Secret reference for the built-in HS256 verifier; resolved key must be at least 32 bytes."),
    doc!("http.oauth.metadata_url", "string", "none", false, false, "1", "Metadata URL advertised in WWW-Authenticate; defaults from resource."),
    doc!("http.mtls.client_fingerprints", "array of string", "[]", false, false, "1", "Registered client leaf-certificate SHA-256 fingerprints; become mtls:sha256:<hex> principals."),
    doc!("http.tls.cert_chain_path", "path", "none", false, false, "1", "Server certificate chain PEM path."),
    doc!("http.tls.private_key_path", "path", "none", false, false, "1", "Server private key PEM path."),
    doc!("http.tls.client_ca_path", "path", "none", false, false, "1", "Client CA PEM path; when present mTLS is required."),
    doc!("http.control.listen", "string", "127.0.0.1:7071", false, false, "1", "Socket address for the mandatory-mTLS control listener."),
    doc!("http.control.preauth_workers", "integer", "4", false, false, "1", "Maximum concurrent TLS handshakes before certificate identity exists (1..=64)."),
    doc!("http.control.operator_workers", "integer", "1", false, false, "1", "Authenticated operator-request worker reserve (1..=64)."),
    doc!("http.control.doctor_workers", "integer", "1", false, false, "1", "Authenticated health/readiness worker reserve (1..=64)."),
    doc!("http.operator.allow_loopback_owner", "bool", "true", false, false, "1", "Allow unauthenticated loopback requests from the local process owner to act as operator."),
    doc!("http.operator.allowed_subjects", "array of string", "[]", false, false, "1", "Server-derived principal keys (oauth:..., mtls:...) allowed to act as operator."),
    // ---- [audit] ---------------------------------------------------------
    doc!("audit.path", "path", "XDG state default", false, false, "1", "Append-only audit log file path."),
    doc!("audit.key_ref", "secret ref", "none", false, true, "1", "Secret reference for the HMAC signing key; resolved key must be at least 32 bytes."),
    doc!("audit.key_id", "string", "default", false, false, "1", "Identifier of the active signing key, recorded so keys can rotate."),
    doc!("audit.verification_keys.key_id", "string", "required", false, false, "1", "Unique identifier carried by historical records/anchors."),
    doc!("audit.verification_keys.key_ref", "secret ref", "required", false, true, "1", "Secret reference resolving a historical verification-only HMAC key."),
    doc!("audit.shipping.worm_path", "path", "none", false, false, "2", "Append-only WORM mirror file path."),
    doc!("audit.shipping.siem_endpoint", "string", "none", false, false, "2", "SIEM endpoint receiving one signed record per POST; remote must be HTTPS."),
    doc!("audit.shipping.siem_format", "enum(json|cef|syslog)", "json", false, false, "2", "SIEM wire format."),
    doc!("audit.shipping.siem_auth_header_ref", "secret ref", "none", false, true, "2", "Secret reference for an outbound SIEM auth header value."),
    doc!("audit.shipping.siem_auth_header_name", "string", "Authorization", false, false, "2", "Header name for the SIEM auth value."),
    doc!("audit.unsigned_refusal_log", "bool", "true", false, false, "2", "Persist redacted guard refusals to the unsigned local security-event trail."),
    // ---- [[profiles]] core ----------------------------------------------
    doc!("profiles.name", "string", "required", false, false, "1", "Stable identifier the agent connects by; unique across profiles."),
    doc!("profiles.description", "string", "none", true, false, "1", "Friendly description shown in list_profiles."),
    doc!("profiles.connect_string", "string", "none", true, true, "1", "Oracle Net connect identifier: EZConnect, EZConnect-Plus, or a tnsnames.ora alias."),
    doc!("profiles.username", "string", "none", true, true, "1", "Oracle username; omit for wallet / OS-auth / OCI IAM."),
    doc!("profiles.credential_ref", "secret ref", "none", true, true, "1", "Secret reference for the credential; literal: is rejected when protected = true."),
    doc!("profiles.login_script", "path", "none", true, true, "1", "Path to a login script of allowlisted ALTER SESSION statements."),
    doc!("profiles.login_statements", "array of string", "none", true, false, "1", "Inline allowlist-validated ALTER SESSION login statements."),
    doc!("profiles.trusted_session_statements", "array of string", "none", true, false, "2", "Operator-authored session setup statements, never agent supplied."),
    doc!("profiles.session_release_statements", "array of string", "none", true, false, "2", "Operator-authored cleanup before a pooled session returns to idle reuse."),
    doc!("profiles.logoff_statements", "array of string", "none", true, false, "2", "Operator-authored cleanup before logical Oracle logoff."),
    doc!("profiles.call_timeout_seconds", "integer", "30", true, false, "1", "Oracle call timeout and total request-budget ceiling, in seconds."),
    doc!("profiles.max_query_cost", "integer", "none", true, false, "2", "Arc G: per-query optimizer-cost ceiling for oracle_query; can only lower the effective ceiling."),
    doc!("profiles.cumulative_query_cost_budget.max_cost", "integer", "required", true, false, "2", "Arc G: total estimated optimizer cost a principal may consume per window."),
    doc!("profiles.cumulative_query_cost_budget.window_seconds", "integer", "required", true, false, "2", "Arc G: duration of one cumulative-cost accounting window, in seconds."),
    doc!("profiles.connect_timeout_seconds", "integer", "20", true, false, "1", "Oracle Net transport connect timeout, in seconds, bounding connect/auth reads."),
    doc!("profiles.inactivity_timeout_seconds", "integer", "none", true, false, "1", "Per-read inactivity deadline on an established session; 0 is unset."),
    doc!("profiles.keepalive_minutes", "integer", "none", true, false, "1", "Oracle EXPIRE_TIME dead-connection-detection probe interval, in minutes."),
    doc!("profiles.sdu", "integer", "none", true, false, "1", "Thin Session Data Unit request size (512..=65535)."),
    doc!("profiles.max_level", "enum(READ_ONLY|READ_WRITE|DDL|ADMIN)", "READ_ONLY", true, false, "1", "Per-target operating-level ceiling; session elevation cannot exceed it."),
    doc!("profiles.default_level", "enum(READ_ONLY|READ_WRITE|DDL|ADMIN)", "READ_ONLY", true, false, "1", "Level a fresh session starts at; must not exceed max_level."),
    doc!("profiles.protected", "bool", "false", true, false, "1", "Pin the ceiling immutable at READ_ONLY and reject literal: secret refs."),
    doc!("profiles.require_signed_tools", "bool", "false", true, false, "1", "Require an HMAC signature for every operator-defined custom tool on this profile."),
    doc!("profiles.read_only_standby", "bool", "false", true, false, "1", "Force READ_ONLY regardless of max_level for an Active Data Guard standby."),
    doc!("profiles.allow_change_notification", "bool", "false", true, false, "2", "Permit CQN registration (still classifier/step-up/audit gated; never widens SQL admission)."),
    doc!("profiles.require_fga_evidence", "bool", "false", true, false, "2", "Refuse reads when ALL_AUDIT_POLICIES is unreadable (default admits them with an fga_evidence: unavailable observation + audit record; a proven FGA handler always refuses)."),
    doc!("profiles.max_subscriptions", "integer", "4", true, false, "2", "Per-principal live-subscription cap; 0 disables new subscriptions fail-closed."),
    doc!("profiles.mcp_exposed", "bool", "true", true, false, "1", "E5 per-profile MCP exposure opt-out (visibility, never access control)."),
    doc!("profiles.dashboard_ddl_workbench", "bool", "false", true, false, "2", "Reserved profile metadata; browser DDL/Admin apply is refused in this release."),
    doc!("profiles.base", "string", "none", false, false, "1", "Name of a profile to inherit unset fields from (shallow merge, child wins)."),
    // ---- [profiles.session_identity] ------------------------------------
    doc!("profiles.session_identity.edition", "string", "none", false, true, "1", "Optional Oracle edition for Edition-Based Redefinition."),
    doc!("profiles.session_identity.program", "string", "none", false, true, "1", "Connect-time client program recorded by Oracle (V$SESSION.PROGRAM)."),
    doc!("profiles.session_identity.machine", "string", "none", false, true, "1", "Connect-time client machine recorded by Oracle (V$SESSION.MACHINE)."),
    doc!("profiles.session_identity.os_user", "string", "none", false, true, "1", "Connect-time OS user recorded by Oracle (V$SESSION.OSUSER)."),
    doc!("profiles.session_identity.terminal", "string", "none", false, true, "1", "Connect-time terminal recorded by Oracle (V$SESSION.TERMINAL)."),
    doc!("profiles.session_identity.module", "string", "none", false, true, "1", "DBMS_APPLICATION_INFO module / SYS_CONTEXT MODULE, applied post-connect."),
    doc!("profiles.session_identity.action", "string", "none", false, true, "1", "DBMS_APPLICATION_INFO action / SYS_CONTEXT ACTION, applied post-connect."),
    doc!("profiles.session_identity.client_identifier", "string", "none", false, true, "1", "DBMS_SESSION client identifier."),
    doc!("profiles.session_identity.client_info", "string", "none", false, true, "1", "DBMS_APPLICATION_INFO client info."),
    doc!("profiles.session_identity.driver_name", "string", "none", false, true, "1", "Driver name shown by Oracle connection-info views where supported."),
    // ---- [profiles.pool] -------------------------------------------------
    doc!("profiles.pool.max_size", "integer", "16", false, false, "1", "Maximum pooled connections (runtime clamps to cpu*2+1)."),
    doc!("profiles.pool.min_idle", "integer", "2", false, false, "1", "Minimum idle connections kept warm; must be <= max_size."),
    doc!("profiles.pool.acquire_timeout_secs", "integer", "5", false, false, "1", "Seconds to wait for a checkout before returning BUSY (1..=3600)."),
    doc!("profiles.pool.statement_cache_size", "integer", "50", false, false, "1", "Per-connection statement-cache size passed to the thin driver."),
    // ---- [profiles.oci] --------------------------------------------------
    doc!("profiles.oci.wallet_location", "path", "none", false, true, "1", "TCPS wallet directory loaded by the thin driver."),
    doc!("profiles.oci.wallet_password_ref", "secret ref", "none", false, true, "1", "Secret reference for an encrypted-wallet password."),
    doc!("profiles.oci.ssl_server_dn_match", "bool", "driver default", false, false, "1", "Override Oracle server-certificate DN matching."),
    doc!("profiles.oci.ssl_server_cert_dn", "string", "none", false, true, "1", "Exact expected server-certificate DN."),
    doc!("profiles.oci.use_sni", "bool", "driver default", false, false, "1", "Override TCPS SNI behavior."),
    doc!("profiles.oci.use_iam_token", "bool", "false", false, false, "1", "Authenticate with a pre-fetched OCI IAM database token instead of a password."),
    doc!("profiles.oci.iam_config_profile", "string", "none", false, true, "1", "~/.oci/config profile name for an IAM token (parses; reserved)."),
    doc!("profiles.oci.token_env", "string", "ORACLEMCP_IAM_TOKEN", false, true, "1", "Name of an env var holding the pre-fetched IAM token (a reference, not the value)."),
    doc!("profiles.oci.token_file", "path", "none", false, true, "1", "Path to a file holding the pre-fetched IAM token, re-read on every connect."),
    doc!("profiles.oci.token_exec", "array of string", "none", false, true, "1", "Argv command run with no shell to fetch a fresh IAM token from stdout."),
    doc!("profiles.oci.token_key_file", "path", "none", false, true, "1", "PKCS#8 PEM private key the IAM database token is bound to (proof-of-possession)."),
    doc!("profiles.oci.token_key_env", "string", "none", false, true, "1", "Name of an env var holding the PKCS#8 PEM private key for the IAM database token."),
    // ---- [profiles.drcp] -------------------------------------------------
    doc!("profiles.drcp.pooled", "bool", "false", false, false, "1", "Request a DRCP pooled server (SERVER=POOLED)."),
    doc!("profiles.drcp.connection_class", "string", "none", false, true, "1", "DRCP connection class; requires pooled = true."),
    doc!("profiles.drcp.purity", "enum(reuse|new)", "reuse", false, false, "1", "DRCP session purity."),
    // ---- [profiles.proxy_auth] ------------------------------------------
    doc!("profiles.proxy_auth.proxy_user", "string", "none", false, true, "1", "Authenticating account that owns credential_ref."),
    doc!("profiles.proxy_auth.target_schema", "string", "none", false, true, "1", "Target schema granted CONNECT THROUGH proxy_user."),
    // ---- [[profiles.app_context]] ---------------------------------------
    doc!("profiles.app_context.namespace", "string", "required", false, true, "1", "Application-context namespace (<= 128 chars)."),
    doc!("profiles.app_context.key", "string", "required", false, true, "1", "Application-context key/name (<= 128 chars)."),
    doc!("profiles.app_context.value", "string", "empty", false, true, "1", "Application-context value; sensitive and redacted (<= 4000 chars)."),
    // ---- [profiles.masking] ---------------------------------------------
    doc!("profiles.masking.mask_unknown_default", "bool", "true", false, false, "2", "Arc M: mask any result column not matched by a rule."),
    doc!("profiles.masking.salt_ref", "string", "none", false, false, "2", "Non-secret salt id/reference required when any rule uses action = tokenize."),
    doc!("profiles.masking.rules.column_match.schema", "string", "none", false, false, "2", "Arc M: optional owner/schema constraint on a masking rule."),
    doc!("profiles.masking.rules.column_match.table", "string", "none", false, false, "2", "Arc M: optional table/object constraint on a masking rule."),
    doc!("profiles.masking.rules.column_match.column", "string", "none", false, false, "2", "Arc M: result/catalog column name; mutually exclusive with tag."),
    doc!("profiles.masking.rules.column_match.tag", "string", "none", false, false, "2", "Arc M: operator-defined sensitivity tag; mutually exclusive with column."),
    doc!("profiles.masking.rules.action", "enum(mask|tokenize|null)", "required", false, false, "2", "Arc M: action applied to matching non-null cells."),
    doc!("profiles.masking.rules.tag", "string", "none", false, false, "2", "Arc M: optional non-secret policy/audit tag on a rule."),
    // ---- [profiles.sql_policy] ------------------------------------------
    doc!("profiles.sql_policy.version", "integer", "1", false, false, "2", "Arc N: declarative policy grammar version."),
    doc!("profiles.sql_policy.rules.id", "string", "required", false, false, "2", "Arc N: non-secret stable rule identifier retained by audit."),
    doc!("profiles.sql_policy.rules.match.schema", "string", "none", false, false, "2", "Arc N: exact resolved owner/schema selector."),
    doc!("profiles.sql_policy.rules.match.object", "string", "none", false, false, "2", "Arc N: exact object selector; requires match.schema."),
    doc!("profiles.sql_policy.rules.match.verb", "enum(select|insert|update|delete|merge|ddl|admin|plsql|alter_session)", "none", false, false, "2", "Arc N: top-level verb supplied by the classifier."),
    doc!("profiles.sql_policy.rules.match.principal", "string", "none", false, false, "2", "Arc N: exact server-derived principal key selector."),
    doc!("profiles.sql_policy.rules.effect.kind", "enum(deny|require_level|require_predicate)", "required", false, false, "2", "Arc N: tightening-only effect kind; no allow/override is representable."),
    doc!("profiles.sql_policy.rules.effect.level", "enum(READ_ONLY|READ_WRITE|DDL|ADMIN)", "none", false, false, "2", "Arc N: operating-level floor for a require_level effect."),
    doc!("profiles.sql_policy.rules.effect.sql_fragment", "string", "none", false, false, "2", "Arc N: restricted conjunctive row filter for a require_predicate effect."),
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use crate::{
        AppContextConfig, AuditConfig, AuditShippingConfig, AuditVerificationKeyConfig,
        ConnectionProfile, CumulativeQueryCostBudgetConfig, DrcpRoutingConfig, DrcpSessionPurity,
        HttpConfig, HttpControlConfig, HttpMtlsConfig, HttpOAuthConfig, HttpOperatorConfig,
        HttpTlsConfig, OciConfig, OperatingLevel, PoolConfig, ProxyAuthConfig,
        ResultColumnMatchConfig, ResultMaskingActionConfig, ResultMaskingConfig,
        ResultMaskingRuleConfig, SessionIdentityConfig, SiemEndpoint, SqlPolicyConfig,
        SqlPolicyEffectConfig, SqlPolicyMatchConfig, SqlPolicyRuleConfig, SqlPolicyVerb,
    };

    use super::config_field_docs;

    fn fingerprint() -> String {
        format!("sha256:{}", "a".repeat(64))
    }

    fn maximal_profile() -> ConnectionProfile {
        ConnectionProfile {
            name: "dev_ro".to_owned(),
            description: Some("read-only".to_owned()),
            connect_string: Some("db.example.com:1521/service".to_owned()),
            username: Some("APP_READONLY".to_owned()),
            credential_ref: Some("env:APP_PASSWORD".to_owned()),
            login_script: Some(PathBuf::from("/etc/oraclemcp/login.sql")),
            login_statements: Some(vec![
                "ALTER SESSION SET NLS_DATE_FORMAT='YYYY-MM-DD'".to_owned(),
            ]),
            trusted_session_statements: Some(vec![
                "ALTER SESSION SET CURRENT_SCHEMA=APP".to_owned(),
            ]),
            session_release_statements: Some(vec![
                "ALTER SESSION CLOSE DATABASE LINK x".to_owned(),
            ]),
            logoff_statements: Some(vec!["ALTER SESSION SET CURRENT_SCHEMA=SYS".to_owned()]),
            call_timeout_seconds: Some(30),
            max_query_cost: Some(1000),
            cumulative_query_cost_budget: Some(CumulativeQueryCostBudgetConfig {
                max_cost: 100_000,
                window_seconds: 3600,
            }),
            connect_timeout_seconds: Some(20),
            inactivity_timeout_seconds: Some(60),
            keepalive_minutes: Some(10),
            sdu: Some(8192),
            max_level: Some(OperatingLevel::ReadOnly),
            default_level: Some(OperatingLevel::ReadOnly),
            protected: Some(false),
            require_signed_tools: Some(false),
            read_only_standby: Some(false),
            allow_change_notification: Some(false),
            require_fga_evidence: Some(true),
            max_subscriptions: Some(4),
            mcp_exposed: Some(true),
            dashboard_ddl_workbench: Some(false),
            session_identity: Some(SessionIdentityConfig {
                edition: Some("ORA$BASE".to_owned()),
                program: Some("oraclemcp".to_owned()),
                machine: Some("mcp-host".to_owned()),
                os_user: Some("oraclemcp".to_owned()),
                terminal: Some("tty".to_owned()),
                module: Some("oracle_query".to_owned()),
                action: Some("read".to_owned()),
                client_identifier: Some("client".to_owned()),
                client_info: Some("info".to_owned()),
                driver_name: Some("oraclemcp-thin".to_owned()),
            }),
            pool: Some(PoolConfig {
                max_size: 16,
                min_idle: 2,
                acquire_timeout_secs: 5,
                statement_cache_size: 50,
            }),
            oci: Some(OciConfig {
                wallet_location: Some(PathBuf::from("/etc/oraclemcp/wallet")),
                wallet_password_ref: Some("env:WALLET_PASSWORD".to_owned()),
                ssl_server_dn_match: Some(true),
                ssl_server_cert_dn: Some("CN=adb".to_owned()),
                use_sni: Some(true),
                use_iam_token: true,
                iam_config_profile: Some("DEFAULT".to_owned()),
                token_env: Some("OCI_IAM_TOKEN".to_owned()),
                token_file: Some("/etc/oraclemcp/token".to_owned()),
                token_exec: Some(vec![
                    "oci".to_owned(),
                    "iam".to_owned(),
                    "db-token".to_owned(),
                ]),
                token_key_file: Some("/etc/oraclemcp/oci_db_key.pem".to_owned()),
                token_key_env: Some("OCI_DB_KEY".to_owned()),
            }),
            drcp: Some(DrcpRoutingConfig {
                pooled: true,
                connection_class: Some("mcp".to_owned()),
                purity: DrcpSessionPurity::Reuse,
            }),
            proxy_auth: Some(ProxyAuthConfig {
                proxy_user: Some("MCP_PROXY".to_owned()),
                target_schema: Some("APP".to_owned()),
            }),
            app_context: Some(vec![AppContextConfig {
                namespace: Some("APP_CTX".to_owned()),
                key: Some("tenant".to_owned()),
                value: Some("acme".to_owned()),
            }]),
            masking: Some(ResultMaskingConfig {
                mask_unknown_default: true,
                salt_ref: Some("profile:dev_ro:masking:v1".to_owned()),
                rules: vec![ResultMaskingRuleConfig {
                    column_match: ResultColumnMatchConfig {
                        schema: Some("APP".to_owned()),
                        table: Some("CUSTOMERS".to_owned()),
                        column: Some("EMAIL".to_owned()),
                        tag: Some("pii".to_owned()),
                    },
                    action: ResultMaskingActionConfig::Mask,
                    tag: Some("pii".to_owned()),
                }],
            }),
            sql_policy: Some(SqlPolicyConfig {
                version: 1,
                rules: vec![
                    SqlPolicyRuleConfig {
                        id: "deny-ddl".to_owned(),
                        match_clause: SqlPolicyMatchConfig {
                            schema: Some("APP".to_owned()),
                            object: Some("CUSTOMERS".to_owned()),
                            verb: Some(SqlPolicyVerb::Select),
                            principal: Some("oauth:stable".to_owned()),
                        },
                        effect: SqlPolicyEffectConfig::Deny,
                    },
                    SqlPolicyRuleConfig {
                        id: "floor".to_owned(),
                        match_clause: SqlPolicyMatchConfig::default(),
                        effect: SqlPolicyEffectConfig::RequireLevel {
                            level: OperatingLevel::Ddl,
                        },
                    },
                    SqlPolicyRuleConfig {
                        id: "filter".to_owned(),
                        match_clause: SqlPolicyMatchConfig::default(),
                        effect: SqlPolicyEffectConfig::RequirePredicate {
                            sql_fragment: "tenant_id = 1".to_owned(),
                        },
                    },
                ],
            }),
            base: Some("shared_defaults".to_owned()),
        }
    }

    /// A config with every optional key populated so serialization emits every
    /// key the schema accepts.
    fn maximal() -> crate::OracleMcpConfig {
        crate::OracleMcpConfig {
            schema_version: crate::SUPPORTED_SCHEMA_VERSION,
            default_profile: Some("dev_ro".to_owned()),
            monitor_profile: Some("monitor_ro".to_owned()),
            http: HttpConfig {
                allowed_hosts: vec!["127.0.0.1:7070".to_owned()],
                allowed_origins: vec!["https://client.example.com".to_owned()],
                json_response: true,
                stateful: true,
                stateful_idle_ttl_seconds: 900,
                oauth: Some(HttpOAuthConfig {
                    resource: Some("https://mcp.example.com".to_owned()),
                    allowed_issuers: vec!["https://issuer.example.com".to_owned()],
                    authorization_servers: vec!["https://as.example.com".to_owned()],
                    required_scopes: vec!["oracle:read".to_owned()],
                    hs256_secret_ref: Some("env:MCP_OAUTH_SECRET".to_owned()),
                    metadata_url: Some(
                        "https://mcp.example.com/.well-known/oauth-protected-resource".to_owned(),
                    ),
                }),
                mtls: HttpMtlsConfig {
                    client_fingerprints: vec![fingerprint()],
                },
                tls: Some(HttpTlsConfig {
                    cert_chain_path: Some(PathBuf::from("/etc/oraclemcp/tls/fullchain.pem")),
                    private_key_path: Some(PathBuf::from("/etc/oraclemcp/tls/key.pem")),
                    client_ca_path: Some(PathBuf::from("/etc/oraclemcp/tls/client-ca.pem")),
                }),
                control: Some(HttpControlConfig {
                    listen: "127.0.0.1:7071".to_owned(),
                    preauth_workers: 4,
                    operator_workers: 1,
                    doctor_workers: 1,
                }),
                operator: HttpOperatorConfig {
                    allow_loopback_owner: true,
                    allowed_subjects: vec!["oauth:stable".to_owned()],
                },
                dashboard_workbench: true,
                trusted_https_termination: true,
                allow_remote: true,
            },
            audit: AuditConfig {
                path: Some(PathBuf::from("/var/log/oraclemcp/audit.jsonl")),
                key_ref: Some("env:ORACLEMCP_AUDIT_KEY".to_owned()),
                key_id: Some("2026-q3".to_owned()),
                verification_keys: vec![AuditVerificationKeyConfig {
                    key_id: "2026-q2".to_owned(),
                    key_ref: "env:ORACLEMCP_AUDIT_KEY_2026_Q2".to_owned(),
                }],
                shipping: Some(AuditShippingConfig {
                    worm_path: Some(PathBuf::from("/mnt/worm/oraclemcp/audit.jsonl")),
                    siem_endpoint: Some(
                        SiemEndpoint::parse("https://siem.example.com/ingest")
                            .expect("valid https endpoint"),
                    ),
                    siem_format: Some("cef".to_owned()),
                    siem_auth_header_ref: Some("env:SIEM_TOKEN".to_owned()),
                    siem_auth_header_name: Some("Authorization".to_owned()),
                }),
                unsigned_refusal_log: true,
            },
            profiles: vec![maximal_profile()],
        }
    }

    fn collect_keys(value: &toml::Value, prefix: &str, out: &mut BTreeSet<String>) {
        match value {
            toml::Value::Table(map) => {
                for (key, child) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    collect_keys(child, &path, out);
                }
            }
            toml::Value::Array(items) => {
                if items.iter().any(toml::Value::is_table) {
                    for item in items {
                        collect_keys(item, prefix, out);
                    }
                } else if !prefix.is_empty() {
                    out.insert(prefix.to_owned());
                }
            }
            _ => {
                if !prefix.is_empty() {
                    out.insert(prefix.to_owned());
                }
            }
        }
    }

    #[test]
    fn documented_keys_cover_every_serialized_config_key() {
        let config = maximal();
        let toml_text = toml::to_string(&config).expect("maximal config serializes to TOML");

        // Round-trip through strict serde. `toml::from_str` enforces
        // `deny_unknown_fields` at every level but deliberately does NOT run the
        // semantic validator, so documentable-but-mutually-exclusive keys (for
        // example a masking rule's `column` and `tag`) can both be present for
        // coverage without the fixture needing to be a valid runtime profile.
        let parsed: crate::OracleMcpConfig =
            toml::from_str(&toml_text).expect("maximal config round-trips through strict serde");
        let re_serialized = toml::to_string(&parsed).expect("parsed config re-serializes");
        assert_eq!(
            toml_text, re_serialized,
            "config is stable under round-trip"
        );

        let value: toml::Value = toml::from_str(&toml_text).expect("valid TOML document");
        let mut serialized = BTreeSet::new();
        collect_keys(&value, "", &mut serialized);

        let documented: BTreeSet<String> = config_field_docs()
            .iter()
            .map(|field| field.key.to_owned())
            .collect();

        let undocumented: Vec<&String> = serialized.difference(&documented).collect();
        let stale: Vec<&String> = documented.difference(&serialized).collect();
        assert!(
            undocumented.is_empty(),
            "config keys missing from config_field_docs(): {undocumented:?}"
        );
        assert!(
            stale.is_empty(),
            "config_field_docs() keys absent from the config schema: {stale:?}"
        );
        assert_eq!(
            serialized, documented,
            "documented key set == parsed key set"
        );
    }

    #[test]
    fn documented_keys_are_unique_and_described() {
        let mut seen = BTreeSet::new();
        for field in config_field_docs() {
            assert!(
                seen.insert(field.key),
                "duplicate documented config key {}",
                field.key
            );
            assert!(
                !field.ty.is_empty() && !field.description.is_empty(),
                "{} needs a type and description",
                field.key
            );
        }
    }
}
