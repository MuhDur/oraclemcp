//! Oracle Unified Auditing policy as the DB-side authoritative record (plan
//! §5.13, §6.4; bead P2-10). The out-of-band file sink (P1-4) gives
//! fsync-before-execute durability; a per-MCP-user Unified Auditing policy makes
//! `UNIFIED_AUDIT_TRAIL` the compliance system-of-record. Compliance language is
//! only sound where **both** hold.
//!
//! This module generates the (identifier-validated) DDL + the trail query;
//! applying them is the engine-side / live-DB caller's job.

/// A simple unquoted Oracle identifier (policy name / username): letter then
/// letters/digits/`_`/`$`/`#`, ≤ 30 chars. Rejects injection.
#[must_use]
pub fn is_simple_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '#'))
        && !s.is_empty()
        && s.len() <= 30
}

/// Error building a Unified Auditing policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UnifiedAuditError {
    /// A policy name or username was not a safe simple identifier.
    #[error("invalid identifier: {0:?}")]
    InvalidIdentifier(String),
}

/// A per-MCP-user Unified Auditing policy specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiedAuditPolicy {
    policy_name: String,
    mcp_user: String,
}

impl UnifiedAuditPolicy {
    /// Build a policy for `mcp_user` (both identifiers validated).
    pub fn new(policy_name: &str, mcp_user: &str) -> Result<Self, UnifiedAuditError> {
        for id in [policy_name, mcp_user] {
            if !is_simple_identifier(id) {
                return Err(UnifiedAuditError::InvalidIdentifier(id.to_owned()));
            }
        }
        Ok(UnifiedAuditPolicy {
            policy_name: policy_name.to_owned(),
            mcp_user: mcp_user.to_owned(),
        })
    }

    /// DDL to create the policy. Audits the actions that matter for an MCP
    /// session: DDL, DML, and `EXECUTE` (PL/SQL invocation).
    #[must_use]
    pub fn create_ddl(&self) -> String {
        format!(
            "CREATE AUDIT POLICY {} ACTIONS CREATE TABLE, DROP TABLE, ALTER TABLE, \
             INSERT, UPDATE, DELETE, MERGE, GRANT, REVOKE, CREATE PROCEDURE, EXECUTE",
            self.policy_name
        )
    }

    /// DDL to enable the policy for the MCP user (the system-of-record link).
    #[must_use]
    pub fn enable_ddl(&self) -> String {
        format!("AUDIT POLICY {} BY {}", self.policy_name, self.mcp_user)
    }

    /// DDL to disable the policy for the MCP user (cleanup step 1).
    #[must_use]
    pub fn disable_ddl(&self) -> String {
        format!("NOAUDIT POLICY {} BY {}", self.policy_name, self.mcp_user)
    }

    /// DDL to drop the policy (cleanup step 2).
    #[must_use]
    pub fn drop_ddl(&self) -> String {
        format!("DROP AUDIT POLICY {}", self.policy_name)
    }

    /// A bind-first query over `UNIFIED_AUDIT_TRAIL` for this MCP user's recent
    /// actions. The username binds (`:1`); never interpolated.
    #[must_use]
    pub fn trail_query(&self) -> &'static str {
        "SELECT event_timestamp, action_name, object_schema, object_name, return_code \
         FROM unified_audit_trail \
         WHERE dbusername = :1 \
         ORDER BY event_timestamp DESC \
         FETCH FIRST 100 ROWS ONLY"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_validation_rejects_injection() {
        assert!(is_simple_identifier("ORACLEMCP_AUDIT"));
        assert!(is_simple_identifier("mcp_user$1"));
        assert!(!is_simple_identifier("1bad"));
        assert!(!is_simple_identifier("a; DROP TABLE t"));
        assert!(!is_simple_identifier("a b"));
        assert!(!is_simple_identifier(""));
        assert!(!is_simple_identifier(&"x".repeat(31)));
    }

    #[test]
    fn policy_rejects_bad_identifiers() {
        assert!(UnifiedAuditPolicy::new("p; DROP", "u").is_err());
        assert!(UnifiedAuditPolicy::new("p", "u; GRANT DBA").is_err());
        assert!(UnifiedAuditPolicy::new("ORACLEMCP_AUDIT", "MCP_RO").is_ok());
    }

    /// The loose `.is_err()` check above never named the variant, so a future
    /// second `UnifiedAuditError` arm (the type is `#[non_exhaustive]`) could
    /// silently swap in for `InvalidIdentifier` and this test would not notice.
    /// Pin the exact variant and, critically, WHICH of the two identifiers it
    /// names — a policy name that fails but reports the `mcp_user` value (or
    /// vice versa) would misdirect an operator fixing the config.
    #[test]
    fn policy_rejects_bad_identifiers_names_the_offending_one() {
        assert_eq!(
            UnifiedAuditPolicy::new("p; DROP", "u"),
            Err(UnifiedAuditError::InvalidIdentifier("p; DROP".to_owned())),
            "the policy_name is checked first and must be the one named"
        );
        assert_eq!(
            UnifiedAuditPolicy::new("ORACLEMCP_AUDIT", "u; GRANT DBA"),
            Err(UnifiedAuditError::InvalidIdentifier(
                "u; GRANT DBA".to_owned()
            )),
            "a valid policy_name paired with a bad mcp_user must name the mcp_user"
        );
    }

    #[test]
    fn ddl_shapes() {
        let p = UnifiedAuditPolicy::new("ORACLEMCP_AUDIT", "MCP_RO").unwrap();
        assert!(
            p.create_ddl()
                .starts_with("CREATE AUDIT POLICY ORACLEMCP_AUDIT ACTIONS")
        );
        assert!(p.create_ddl().contains("DELETE"));
        assert_eq!(p.enable_ddl(), "AUDIT POLICY ORACLEMCP_AUDIT BY MCP_RO");
        assert_eq!(p.disable_ddl(), "NOAUDIT POLICY ORACLEMCP_AUDIT BY MCP_RO");
        assert_eq!(p.drop_ddl(), "DROP AUDIT POLICY ORACLEMCP_AUDIT");
    }

    #[test]
    fn trail_query_is_bind_first() {
        let p = UnifiedAuditPolicy::new("P", "U").unwrap();
        assert!(p.trail_query().contains("dbusername = :1"));
        assert!(p.trail_query().contains("unified_audit_trail"));
        // The username is a bind, never embedded in the static query text.
        assert!(!p.trail_query().contains("MCP_RO"));
    }
}
