//! Enterprise Oracle Net authentication adapters (plan §7.5; bead P3-1 /
//! oracle-qmwz.4.1). Thin mode supports username/password and proxy user
//! shaping today; Kerberos, RADIUS/native MFA, and external wallet auth are
//! explicit unsupported-auth cases until the thin driver exposes those paths.
//!
//! These apply to interactive DBA users; pooled service accounts enforce MFA at
//! the MCP layer instead. This module maps each adapter to the `sqlnet.ora`
//! settings + connect-time behavior it needs (the driver applies them); device
//! 2FA is out of scope.

use std::path::PathBuf;

/// An Oracle Net authentication adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthAdapter {
    /// Username + password (the default).
    Password,
    /// Kerberos 5 with a keytab; `delegation_constrained` sets
    /// `KERBEROS5_DELEGATION_MODE=CONSTRAINED` (the safer, scoped delegation).
    Kerberos {
        /// Path to the service keytab.
        keytab: PathBuf,
        /// Use constrained delegation.
        delegation_constrained: bool,
    },
    /// RADIUS / native MFA (Oracle 19c Jul-2025 DBRU / 23ai).
    Radius,
    /// Proxy auth: connect as `proxy_user` then `CONNECT THROUGH` into
    /// `target_schema` — per-agent identity in Unified Auditing **without**
    /// per-agent passwords.
    Proxy {
        /// The authenticating proxy user.
        proxy_user: String,
        /// The schema whose identity the session assumes.
        target_schema: String,
    },
    /// OS / wallet external authentication.
    External,
}

/// Why an auth adapter is invalid.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthAdapterError {
    /// Kerberos needs a keytab path.
    #[error("Kerberos auth requires a keytab path")]
    MissingKeytab,
    /// Proxy auth needs both a proxy user and a target schema.
    #[error("proxy auth requires a non-empty proxy_user and target_schema")]
    IncompleteProxy,
}

impl AuthAdapter {
    /// Validate the adapter's required parameters.
    pub fn validate(&self) -> Result<(), AuthAdapterError> {
        match self {
            AuthAdapter::Kerberos { keytab, .. } if keytab.as_os_str().is_empty() => {
                Err(AuthAdapterError::MissingKeytab)
            }
            AuthAdapter::Proxy {
                proxy_user,
                target_schema,
            } if proxy_user.trim().is_empty() || target_schema.trim().is_empty() => {
                Err(AuthAdapterError::IncompleteProxy)
            }
            _ => Ok(()),
        }
    }

    /// The `sqlnet.ora` settings this adapter requires (the driver applies them
    /// to the connection's network config).
    #[must_use]
    pub fn sqlnet_settings(&self) -> Vec<(String, String)> {
        let kv = |k: &str, v: &str| (k.to_owned(), v.to_owned());
        match self {
            AuthAdapter::Kerberos {
                keytab,
                delegation_constrained,
            } => {
                let mut s = vec![
                    kv("SQLNET.AUTHENTICATION_SERVICES", "(KERBEROS5)"),
                    kv("SQLNET.KERBEROS5_KEYTAB", &keytab.display().to_string()),
                ];
                if *delegation_constrained {
                    s.push(kv("SQLNET.KERBEROS5_DELEGATION_MODE", "CONSTRAINED"));
                }
                s
            }
            AuthAdapter::Radius => vec![kv("SQLNET.AUTHENTICATION_SERVICES", "(RADIUS)")],
            AuthAdapter::Password | AuthAdapter::Proxy { .. } | AuthAdapter::External => Vec::new(),
        }
    }

    /// The proxy connect specifier (`proxy_user[target_schema]`) for `CONNECT
    /// THROUGH`, or `None` for non-proxy adapters. Stamps per-agent identity into
    /// Unified Auditing without a per-agent password.
    #[must_use]
    pub fn proxy_connect_user(&self) -> Option<String> {
        match self {
            AuthAdapter::Proxy {
                proxy_user,
                target_schema,
            } => Some(format!("{proxy_user}[{target_schema}]")),
            _ => None,
        }
    }

    /// Whether the adapter authenticates WITHOUT a password supplied by us.
    #[must_use]
    pub fn uses_external_auth(&self) -> bool {
        matches!(
            self,
            AuthAdapter::Kerberos { .. } | AuthAdapter::Radius | AuthAdapter::External
        )
    }

    /// Whether the adapter is currently unsupported by the thin driver.
    #[must_use]
    pub fn unsupported_in_thin_mode(&self) -> bool {
        matches!(
            self,
            AuthAdapter::Kerberos { .. } | AuthAdapter::Radius | AuthAdapter::External
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kerberos_emits_keytab_and_constrained_delegation() {
        let a = AuthAdapter::Kerberos {
            keytab: PathBuf::from("/etc/oracle/svc.keytab"),
            delegation_constrained: true,
        };
        a.validate().expect("valid");
        let s = a.sqlnet_settings();
        assert!(s.contains(&(
            "SQLNET.AUTHENTICATION_SERVICES".to_owned(),
            "(KERBEROS5)".to_owned()
        )));
        assert!(
            s.iter()
                .any(|(k, v)| k == "SQLNET.KERBEROS5_KEYTAB" && v.contains("svc.keytab"))
        );
        assert!(s.contains(&(
            "SQLNET.KERBEROS5_DELEGATION_MODE".to_owned(),
            "CONSTRAINED".to_owned()
        )));
        assert!(a.uses_external_auth() && a.unsupported_in_thin_mode());
    }

    #[test]
    fn kerberos_without_keytab_is_invalid() {
        let a = AuthAdapter::Kerberos {
            keytab: PathBuf::new(),
            delegation_constrained: true,
        };
        assert_eq!(a.validate(), Err(AuthAdapterError::MissingKeytab));
    }

    #[test]
    fn radius_sets_the_radius_service_and_is_unsupported_in_thin_mode() {
        let a = AuthAdapter::Radius;
        assert_eq!(
            a.sqlnet_settings(),
            vec![(
                "SQLNET.AUTHENTICATION_SERVICES".to_owned(),
                "(RADIUS)".to_owned()
            )]
        );
        assert!(a.unsupported_in_thin_mode());
    }

    #[test]
    fn proxy_emits_connect_through_identity() {
        let a = AuthAdapter::Proxy {
            proxy_user: "mcp_proxy".to_owned(),
            target_schema: "APP_OWNER".to_owned(),
        };
        a.validate().expect("valid");
        // Per-agent identity for Unified Auditing without a per-agent password.
        assert_eq!(
            a.proxy_connect_user().as_deref(),
            Some("mcp_proxy[APP_OWNER]")
        );
        // Proxy itself adds no sqlnet auth service.
        assert!(a.sqlnet_settings().is_empty());
        assert!(!a.uses_external_auth());
    }

    #[test]
    fn incomplete_proxy_is_invalid() {
        let a = AuthAdapter::Proxy {
            proxy_user: "".to_owned(),
            target_schema: "S".to_owned(),
        };
        assert_eq!(a.validate(), Err(AuthAdapterError::IncompleteProxy));
    }

    #[test]
    fn password_and_external_are_plain() {
        assert!(AuthAdapter::Password.sqlnet_settings().is_empty());
        assert!(AuthAdapter::Password.proxy_connect_user().is_none());
        assert!(!AuthAdapter::Password.unsupported_in_thin_mode());
        assert!(AuthAdapter::External.uses_external_auth());
        assert!(AuthAdapter::External.unsupported_in_thin_mode());
    }
}
