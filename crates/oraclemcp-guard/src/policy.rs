//! Per-schema scoping & allow/deny policy (plan §6.2; bead P1-POLICY).
//!
//! A policy can only ever **further restrict** the classifier's verdict — never
//! loosen it. `SYSTEM`/`SYS`/`SYSAUX` are deny-all by default and cannot be
//! unlocked by an allow-once token. Schema is resolved by the caller from the
//! parsed `ObjectName` (or `SYS_CONTEXT('USERENV','CURRENT_SCHEMA')`).

use std::collections::BTreeMap;

use regex::Regex;
use serde::Deserialize;

use crate::levels::DangerLevel;

/// The default posture for a schema with no explicit rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultMode {
    /// Reads only (DML/DDL denied).
    #[default]
    ReadOnly,
    /// Reads + preview/approve flows; direct writes still gated elsewhere.
    Guarded,
    /// No per-schema restriction (the classifier + level gate still apply).
    Permissive,
}

/// Schemas that are deny-all regardless of config (cannot be unlocked).
const ALWAYS_DENY_ALL: &[&str] = &["SYS", "SYSTEM", "SYSAUX", "AUDSYS", "DBSNMP"];

/// Per-schema policy (one entry; raw form from TOML).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaPolicyRaw {
    /// Posture for statements not otherwise matched.
    #[serde(default)]
    pub default_mode: DefaultMode,
    /// Permit DML (INSERT/UPDATE/DELETE/MERGE) in this schema.
    #[serde(default)]
    pub allow_dml: bool,
    /// Deny DDL in this schema.
    #[serde(default)]
    pub deny_ddl: bool,
    /// Deny everything in this schema.
    #[serde(default)]
    pub deny_all: bool,
    /// Regex patterns that, if matched against the SQL, deny the call.
    #[serde(default)]
    pub deny_patterns: Vec<String>,
}

/// A compiled per-schema policy.
#[derive(Clone, Debug, Default)]
pub struct SchemaPolicy {
    mode: DefaultMode,
    allow_dml: bool,
    deny_ddl: bool,
    deny_all: bool,
    deny_patterns: Vec<Regex>,
}

impl SchemaPolicy {
    /// Compile from the raw (TOML) form; invalid regexes are dropped.
    #[must_use]
    pub fn compile(raw: &SchemaPolicyRaw) -> Self {
        SchemaPolicy {
            mode: raw.default_mode,
            allow_dml: raw.allow_dml,
            deny_ddl: raw.deny_ddl,
            deny_all: raw.deny_all,
            deny_patterns: raw
                .deny_patterns
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect(),
        }
    }
}

/// The whole-server schema policy set.
#[derive(Clone, Debug, Default)]
pub struct SchemaPolicySet {
    per_schema: BTreeMap<String, SchemaPolicy>,
}

/// A per-schema policy decision (it can only deny, never loosen the classifier).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The policy permits the call (subject to the classifier + level gate).
    Allow,
    /// The policy denies the call.
    Deny {
        /// The schema that triggered the denial.
        schema: String,
        /// Why.
        reason: String,
    },
}

impl SchemaPolicySet {
    /// An empty policy set (only the built-in `ALWAYS_DENY_ALL` applies).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a compiled per-schema policy (schema name is upper-cased).
    #[must_use]
    pub fn with_schema(mut self, schema: &str, policy: SchemaPolicy) -> Self {
        self.per_schema.insert(schema.to_ascii_uppercase(), policy);
        self
    }

    /// Evaluate the policy for a statement of `danger` touching `schemas`,
    /// matching `sql` against deny patterns. Denies on the first offending
    /// schema; otherwise `Allow`.
    #[must_use]
    pub fn evaluate(&self, schemas: &[&str], danger: DangerLevel, sql: &str) -> PolicyDecision {
        for schema in schemas {
            let upper = schema.to_ascii_uppercase();
            if ALWAYS_DENY_ALL.contains(&upper.as_str()) {
                return PolicyDecision::Deny {
                    schema: upper,
                    reason: "system schema is deny-all (cannot be unlocked)".to_owned(),
                };
            }
            let Some(p) = self.per_schema.get(&upper) else {
                // No explicit rule: default-deny writes/DDL to unknown schemas
                // only if the statement is mutating; reads pass.
                if danger >= DangerLevel::Guarded {
                    // Unknown schema + mutating: deny unless a permissive default
                    // exists for it (none here) — conservative.
                    return PolicyDecision::Deny {
                        schema: upper,
                        reason: "no policy for schema; mutating statements denied by default"
                            .to_owned(),
                    };
                }
                continue;
            };
            if p.deny_all {
                return deny(&upper, "schema policy: deny_all");
            }
            for re in &p.deny_patterns {
                if re.is_match(sql) {
                    return deny(
                        &upper,
                        &format!("schema policy: matched deny pattern {}", re.as_str()),
                    );
                }
            }
            // DDL family (Destructive level via CREATE/ALTER/DROP/TRUNCATE).
            if p.deny_ddl && danger == DangerLevel::Destructive {
                return deny(&upper, "schema policy: deny_ddl");
            }
            match p.mode {
                DefaultMode::ReadOnly if danger >= DangerLevel::Guarded && !p.allow_dml => {
                    return deny(&upper, "schema policy: read_only (DML/DDL not allowed)");
                }
                DefaultMode::Guarded if danger == DangerLevel::Destructive && !p.allow_dml => {
                    return deny(&upper, "schema policy: guarded (destructive not allowed)");
                }
                _ => {}
            }
        }
        PolicyDecision::Allow
    }
}

fn deny(schema: &str, reason: &str) -> PolicyDecision {
    PolicyDecision::Deny {
        schema: schema.to_owned(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permissive(schema: &str) -> SchemaPolicySet {
        SchemaPolicySet::new().with_schema(
            schema,
            SchemaPolicy::compile(&SchemaPolicyRaw {
                default_mode: DefaultMode::Permissive,
                allow_dml: true,
                ..Default::default()
            }),
        )
    }

    #[test]
    fn system_schemas_are_always_deny_all() {
        let set = SchemaPolicySet::new();
        for sys in ["SYS", "SYSTEM", "sysaux"] {
            assert!(matches!(
                set.evaluate(&[sys], DangerLevel::Safe, "SELECT 1 FROM dual"),
                PolicyDecision::Deny { .. }
            ));
        }
    }

    #[test]
    fn unknown_schema_allows_reads_denies_writes() {
        let set = SchemaPolicySet::new();
        assert_eq!(
            set.evaluate(&["HR"], DangerLevel::Safe, "SELECT * FROM hr.emp"),
            PolicyDecision::Allow
        );
        assert!(matches!(
            set.evaluate(
                &["HR"],
                DangerLevel::Guarded,
                "UPDATE hr.emp SET x=1 WHERE id=2"
            ),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn permissive_schema_allows_dml() {
        let set = permissive("APP");
        assert_eq!(
            set.evaluate(
                &["APP"],
                DangerLevel::Guarded,
                "INSERT INTO app.t VALUES (1)"
            ),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn read_only_schema_denies_dml() {
        let set = SchemaPolicySet::new().with_schema(
            "REPORTS",
            SchemaPolicy::compile(&SchemaPolicyRaw {
                default_mode: DefaultMode::ReadOnly,
                ..Default::default()
            }),
        );
        assert!(matches!(
            set.evaluate(
                &["REPORTS"],
                DangerLevel::Guarded,
                "INSERT INTO reports.t VALUES (1)"
            ),
            PolicyDecision::Deny { .. }
        ));
        assert_eq!(
            set.evaluate(&["REPORTS"], DangerLevel::Safe, "SELECT * FROM reports.t"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn deny_ddl_blocks_destructive() {
        let set = SchemaPolicySet::new().with_schema(
            "APP",
            SchemaPolicy::compile(&SchemaPolicyRaw {
                default_mode: DefaultMode::Permissive,
                allow_dml: true,
                deny_ddl: true,
                ..Default::default()
            }),
        );
        assert!(matches!(
            set.evaluate(&["APP"], DangerLevel::Destructive, "DROP TABLE app.t"),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn deny_pattern_matches() {
        let set = SchemaPolicySet::new().with_schema(
            "APP",
            SchemaPolicy::compile(&SchemaPolicyRaw {
                default_mode: DefaultMode::Permissive,
                allow_dml: true,
                deny_patterns: vec!["(?i)salaries".to_owned()],
                ..Default::default()
            }),
        );
        assert!(matches!(
            set.evaluate(&["APP"], DangerLevel::Safe, "SELECT * FROM app.salaries"),
            PolicyDecision::Deny { .. }
        ));
    }
}
