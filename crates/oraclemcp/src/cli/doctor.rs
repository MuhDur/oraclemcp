use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub(crate) struct DoctorArgs {
    /// Inspect this named profile. Offline unless --online is also set.
    #[arg(long)]
    pub(crate) profile: Option<String>,
    /// Open a live database connection for connectivity/auth/role probes.
    #[arg(long)]
    pub(crate) online: bool,
    /// Show a redacted driver class and Oracle code for an online connect failure.
    #[arg(long, requires = "online")]
    pub(crate) verbose: bool,
    /// Plan scoped self-repair. Out-of-scope targets are refused with exit 4.
    #[arg(long)]
    pub(crate) fix: bool,
    /// Local-only doctor diagnostics.
    #[command(subcommand)]
    pub(crate) command: Option<DoctorCommand>,
}

/// Local-only `doctor` diagnostics. These are never part of an MCP or HTTP request path.
#[derive(Subcommand, Debug)]
pub(crate) enum DoctorCommand {
    /// Validate one supplied OAuth token against the local resource-server config.
    Oauth {
        /// JWT to diagnose. It is never logged, persisted, or rendered.
        #[arg(long, value_name = "JWT")]
        token: String,
    },
}

#[cfg(test)]
mod tests {
    use super::super::{Cli, Command};
    use super::DoctorArgs;
    use clap::Parser;

    #[test]
    fn verbose_requires_online_and_is_opt_in() {
        let error = Cli::try_parse_from(["oraclemcp", "doctor", "--verbose"])
            .expect_err("--verbose without --online must be rejected");
        assert!(error.to_string().contains("--online"));

        let parsed = Cli::try_parse_from(["oraclemcp", "doctor", "--online", "--verbose"])
            .expect("parse explicit online verbose doctor");
        assert!(matches!(
            parsed.command,
            Some(Command::Doctor {
                args: DoctorArgs {
                    online: true,
                    verbose: true,
                    ..
                }
            })
        ));
    }

    #[test]
    fn connect_hint_after_accept_never_suggests_connect_string() {
        let hint = oraclemcp_db::connect_hint_for(oraclemcp_db::ConnectPhaseReached::AuthTtc);
        let lower = hint.to_ascii_lowercase();
        assert!(
            lower.contains("authentication") && lower.contains("ttc"),
            "{hint}"
        );
        assert!(
            !lower.contains("connect string") && !lower.contains("host and port"),
            "post-ACCEPT diagnostics must not send operators back to the connect string: {hint}"
        );
    }

    #[test]
    fn doctor_json_keeps_security_catalog_warning_visible() {
        let report = oraclemcp_core::DoctorReport {
            checks: vec![oraclemcp_core::doctor::CheckResult {
                id: 20,
                name: "Security feature catalog visibility".to_owned(),
                status: oraclemcp_core::doctor::CheckStatus::Warn,
                detail: "security_feature_catalog_unreadable: OLS/RAS/Data Redaction evidence is incomplete; reads proceed with security_feature_evidence: unavailable, a keyed observation, and an audit record".to_owned(),
                fix: Some("Grant catalog visibility, then rerun `oraclemcp doctor --online`".to_owned()),
                failure_class: None,
                auth_mode: None,
                wallet_error: None,
                wallet_posture: None,
                wallet_cert_expiry: None,
                ora_code: None,
            }],
            profile_caps: None,
            auth_capabilities: None,
            service_health: None,
            service_unit_caps: None,
            fix: None,
        };

        let check = &report.to_json_with_exit_code(0)["checks"][0];
        assert_eq!(check["id"], 20);
        assert_eq!(check["status"], "warn");
        assert!(
            check["detail"]
                .as_str()
                .unwrap()
                .contains("security_feature_evidence: unavailable")
        );
        assert!(check.get("fix").is_some());
    }
}
