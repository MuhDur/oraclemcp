//! DRCP — Database Resident Connection Pooling (plan §9.4; bead P3-6 /
//! oracle-qmwz.4.6, sub-feature 1). Non-homogeneous / proxy pools: many agents
//! share a small pool of pooled DB servers via `SERVER=POOLED` + a connection
//! class (`pool_connection_class`) + session purity (`pool_purity`). Pure config
//! mapping onto the EZConnect-Plus connect string; the driver applies it.

/// Session purity for a DRCP-pooled connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPurity {
    /// Reuse the pooled session's state (`PURITY=SELF`).
    Reuse,
    /// Force a fresh session (`PURITY=NEW`).
    New,
}

impl SessionPurity {
    fn as_param(self) -> &'static str {
        match self {
            SessionPurity::Reuse => "self",
            SessionPurity::New => "new",
        }
    }
}

/// DRCP configuration for a connection profile.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DrcpConfig {
    /// Use a DRCP pooled server (`SERVER=POOLED`).
    pub pooled: bool,
    /// Connection class for non-homogeneous pools (sessions only shared within a
    /// class — keeps tenants/agents isolated).
    pub connection_class: Option<String>,
    /// Session purity.
    pub purity: SessionPurity,
}

impl Default for DrcpConfig {
    fn default() -> Self {
        DrcpConfig {
            pooled: false,
            connection_class: None,
            purity: SessionPurity::Reuse,
        }
    }
}

impl DrcpConfig {
    /// Append the DRCP attributes to a base EZConnect connect string. A
    /// non-pooled config returns the base unchanged (dedicated server).
    #[must_use]
    pub fn apply_to_connect_string(&self, base: &str) -> String {
        if !self.pooled {
            return base.to_owned();
        }
        let mut params = vec!["server=pooled".to_owned()];
        if let Some(class) = &self.connection_class {
            params.push(format!("pool_connection_class={class}"));
        }
        params.push(format!("pool_purity={}", self.purity.as_param()));
        let sep = if base.contains('?') { '&' } else { '?' };
        format!("{base}{sep}{}", params.join("&"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_pooled_leaves_the_connect_string_unchanged() {
        let cfg = DrcpConfig::default();
        assert_eq!(
            cfg.apply_to_connect_string("host:1521/svc"),
            "host:1521/svc"
        );
    }

    #[test]
    fn pooled_appends_server_class_and_purity() {
        let cfg = DrcpConfig {
            pooled: true,
            connection_class: Some("AGENTS".to_owned()),
            purity: SessionPurity::Reuse,
        };
        assert_eq!(
            cfg.apply_to_connect_string("host:1521/svc"),
            "host:1521/svc?server=pooled&pool_connection_class=AGENTS&pool_purity=self"
        );
    }

    #[test]
    fn pooled_uses_ampersand_when_base_already_has_query() {
        let cfg = DrcpConfig {
            pooled: true,
            connection_class: None,
            purity: SessionPurity::New,
        };
        assert_eq!(
            cfg.apply_to_connect_string("host:1521/svc?wallet_location=/w"),
            "host:1521/svc?wallet_location=/w&server=pooled&pool_purity=new"
        );
    }
}
