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
}
