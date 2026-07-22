use oraclemcp_db::{AuthAdapter, OracleConnectOptions};
use serde::Serialize;

/// Authentication modes the thin driver reports to `doctor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorAuthModeKind {
    /// Username/password thin authentication.
    Password,
    /// Thin proxy authentication (`CONNECT THROUGH`) with a password or token
    /// owned by the proxy user.
    Proxy,
    /// OCI IAM database-token authentication over TCPS.
    IamToken,
    /// Passwordless external / wallet authentication.
    ExternalWallet,
    /// Kerberos authentication.
    Kerberos,
    /// RADIUS / native MFA authentication.
    Radius,
}

impl DoctorAuthModeKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            DoctorAuthModeKind::Password => "password",
            DoctorAuthModeKind::Proxy => "proxy",
            DoctorAuthModeKind::IamToken => "iam_token",
            DoctorAuthModeKind::ExternalWallet => "external_wallet",
            DoctorAuthModeKind::Kerberos => "kerberos",
            DoctorAuthModeKind::Radius => "radius",
        }
    }
}

/// Whether a driver supports an auth mode in thin mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorAuthModeSupport {
    /// Supported by the pinned thin driver path.
    Supported,
    /// Explicitly not supported by the pinned thin driver path.
    UnsupportedInThin,
}

/// One auth capability row in the `doctor` matrix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorAuthModeCapability {
    /// Auth mode.
    pub kind: DoctorAuthModeKind,
    /// Thin-driver support posture.
    pub support: DoctorAuthModeSupport,
    /// Whether this mode is selected by the inspected profile.
    pub selected: bool,
    /// Secret-free operator detail.
    pub detail: &'static str,
}

/// Secret-free auth capability matrix surfaced by `doctor --profile`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorAuthCapabilities {
    /// Driver family being reported.
    pub driver: &'static str,
    /// Profile-selected auth mode.
    pub selected: DoctorAuthModeKind,
    /// Complete thin-mode matrix.
    pub modes: Vec<DoctorAuthModeCapability>,
}

/// IAM token source kind observed from non-secret profile configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorIamTokenSourceKind {
    /// Built-in fallback environment variable (`ORACLEMCP_IAM_TOKEN`).
    BuiltinEnv,
    /// Profile-named `token_env`.
    Env,
    /// Profile-named `token_file`.
    File,
    /// Profile `token_exec` command.
    Exec,
}

impl DoctorIamTokenSourceKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            DoctorIamTokenSourceKind::BuiltinEnv => "builtin_env",
            DoctorIamTokenSourceKind::Env => "env",
            DoctorIamTokenSourceKind::File => "file",
            DoctorIamTokenSourceKind::Exec => "exec",
        }
    }
}

/// What doctor can truthfully observe about the IAM token source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorIamTokenSourceObservation {
    /// Non-secret source kind, derived from profile configuration.
    pub source_kind: DoctorIamTokenSourceKind,
    /// Last successful source invocation time, when the caller has an explicit
    /// runtime observation. `None` means doctor did not observe an invocation and
    /// must say so instead of implying the source was already fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_successful_invocation_unix: Option<i64>,
}

impl DoctorAuthCapabilities {
    /// Build the pinned thin-driver matrix with the supplied selected mode.
    #[must_use]
    pub fn thin(selected: DoctorAuthModeKind) -> Self {
        let row = |kind, support, detail| DoctorAuthModeCapability {
            kind,
            support,
            selected: kind == selected,
            detail,
        };
        DoctorAuthCapabilities {
            driver: "thin",
            selected,
            modes: vec![
                row(
                    DoctorAuthModeKind::Password,
                    DoctorAuthModeSupport::Supported,
                    "username/password thin authentication",
                ),
                row(
                    DoctorAuthModeKind::Proxy,
                    DoctorAuthModeSupport::Supported,
                    "thin proxy authentication via CONNECT THROUGH",
                ),
                row(
                    DoctorAuthModeKind::IamToken,
                    DoctorAuthModeSupport::Supported,
                    "OCI IAM database token over TCPS",
                ),
                row(
                    DoctorAuthModeKind::ExternalWallet,
                    DoctorAuthModeSupport::UnsupportedInThin,
                    "passwordless external wallet authentication is not supported by this thin driver",
                ),
                row(
                    DoctorAuthModeKind::Kerberos,
                    DoctorAuthModeSupport::UnsupportedInThin,
                    "Kerberos authentication is not supported by this thin driver",
                ),
                row(
                    DoctorAuthModeKind::Radius,
                    DoctorAuthModeSupport::UnsupportedInThin,
                    "RADIUS/native MFA authentication is not supported by this thin driver",
                ),
            ],
        }
    }

    /// Derive the selected mode from resolved connect options without exposing
    /// any connect material.
    #[must_use]
    pub fn from_connect_options(opts: &OracleConnectOptions) -> Self {
        let selected = match &opts.auth_adapter {
            AuthAdapter::Kerberos { .. } => DoctorAuthModeKind::Kerberos,
            AuthAdapter::Radius => DoctorAuthModeKind::Radius,
            AuthAdapter::External => DoctorAuthModeKind::ExternalWallet,
            AuthAdapter::Proxy { .. } => DoctorAuthModeKind::Proxy,
            AuthAdapter::Password => {
                if opts.use_iam_token || opts.iam_token.is_some() {
                    DoctorAuthModeKind::IamToken
                } else if opts.external_auth || (opts.username.is_none() && opts.password.is_none())
                {
                    DoctorAuthModeKind::ExternalWallet
                } else {
                    DoctorAuthModeKind::Password
                }
            }
        };
        Self::thin(selected)
    }
}
