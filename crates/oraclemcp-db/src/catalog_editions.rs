//! Version-aware Edition-Based Redefinition catalog proofs.
//!
//! The caller loads [`EditionsCatalogCapabilities`] once for a connection and
//! reuses that snapshot for each owner/type pair it checks. Dictionary queries
//! are selected only after their columns have been observed in
//! `ALL_TAB_COLUMNS`; this avoids naming version-specific columns in SQL sent
//! to older Oracle releases.

use asupersync::Cx;
use oraclemcp_error::{
    ErrorClass, ErrorEnvelope, ReasonCategory, StatementOutcome, StructuredReason,
};
use serde::{Deserialize, Serialize};

use crate::catalog_query::{CatalogQueryId, run_catalog_query};
use crate::{OracleBind, OracleConnection};

/// Bound for the object types returned when checking an owner's editioned
/// types. If the cap is reached, absence of a requested type remains unknown.
pub const MAX_EDITIONED_TYPES: usize = 128;

const EBR_COLUMNS: &[(&str, &str)] = &[
    ("USER_USERS", "EDITIONS_ENABLED"),
    ("DBA_USERS", "USERNAME"),
    ("DBA_USERS", "EDITIONS_ENABLED"),
    ("USER_EDITIONED_TYPES", "OBJECT_TYPE"),
    ("DBA_EDITIONED_TYPES", "SCHEMA"),
    ("DBA_EDITIONED_TYPES", "OBJECT_TYPE"),
    ("V_$EDITIONABLE_TYPES", "EDITIONABLE_TYPE"),
];

/// Strength of one editions-enabled proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditionsProofStatus {
    /// Oracle metadata directly proved the requested fact.
    Proven,
    /// A readable catalog directly proved the requested fact false.
    Disabled,
    /// Required metadata was absent, unreadable, or inconclusive.
    Unknown,
}

/// One observed view-column availability fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditionsCatalogColumn {
    /// Oracle dictionary view name, such as `DBA_USERS`.
    pub view: String,
    /// Column name in that view.
    pub column: String,
    /// Whether the column appeared in the live metadata probe.
    pub present: bool,
}

/// Capability snapshot for one Oracle connection.
///
/// The version string and column observations are captured together and can be
/// reused for all checks on the same physical connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditionsCatalogCapabilities {
    /// Server version reported by the connection, when available.
    pub server_version: Option<String>,
    /// Connected session user, when available.
    pub session_user: Option<String>,
    /// Whether `ALL_TAB_COLUMNS` itself could be read.
    pub metadata_visible: bool,
    /// The supported view-column set and observed availability.
    pub columns: Vec<EditionsCatalogColumn>,
}

impl EditionsCatalogCapabilities {
    /// Return whether a required view column was observed.
    #[must_use]
    pub fn has_column(&self, view: &str, column: &str) -> bool {
        self.metadata_visible
            && self.columns.iter().any(|item| {
                item.present
                    && item.view.eq_ignore_ascii_case(view)
                    && item.column.eq_ignore_ascii_case(column)
            })
    }
}

/// Typed evidence for one exact `(owner, object_type)` pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditionsEnabledProof {
    /// Requested schema owner.
    pub owner: String,
    /// Requested Oracle object type.
    pub object_type: String,
    /// Whether the owner has editions enabled.
    pub owner_enabled: EditionsProofStatus,
    /// Whether this exact owner/type pair has editions enabled.
    pub type_enabled: EditionsProofStatus,
    /// Database-wide support for editioning this type. This never proves that
    /// the owner or owner/type pair is enabled.
    pub database_type_capability: EditionsProofStatus,
    /// View that supplied owner-level evidence, when one was readable.
    pub owner_evidence_view: Option<String>,
    /// View that supplied the owner/type evidence, when one was readable.
    pub type_evidence_view: Option<String>,
    /// View that supplied database-level capability evidence, when readable.
    pub capability_evidence_view: Option<String>,
}

impl EditionsEnabledProof {
    /// Whether both required owner and owner/type proofs are positive.
    #[must_use]
    pub fn is_proven(&self) -> bool {
        self.owner_enabled == EditionsProofStatus::Proven
            && self.type_enabled == EditionsProofStatus::Proven
    }

    /// Build the typed refusal used when the required editions proof is not
    /// positive. No DDL is issued by this helper.
    #[must_use]
    pub fn refusal_envelope(&self) -> ErrorEnvelope {
        let owner = quote_identifier(&self.owner);
        let object_type = self.object_type.to_ascii_uppercase();
        let remediation = format!("ALTER USER {owner} ENABLE EDITIONS FOR {object_type}");
        let message = if self.owner_enabled == EditionsProofStatus::Unknown
            || self.type_enabled == EditionsProofStatus::Unknown
        {
            format!(
                "Could not prove editions are enabled for {}.{}; catalog evidence is unavailable or incomplete. The server never runs ALTER USER. An operator can verify or apply: {remediation}.",
                self.owner, self.object_type
            )
        } else {
            format!(
                "Editions are not enabled for {}.{}; the server never runs ALTER USER. An operator can verify or apply: {remediation}.",
                self.owner, self.object_type
            )
        };
        ErrorEnvelope::new(ErrorClass::PolicyDenied, message)
            .with_statement_outcome(StatementOutcome::NotStarted)
            .with_structured_reason(
                StructuredReason::new(ReasonCategory::EditionsNotEnabled)
                    .with_offending_construct(format!("{}.{}", self.owner, self.object_type)),
            )
            .with_next_step(format!(
                "Ask an authorized operator to verify editions for {}. The server will not execute ALTER USER.",
                self.owner
            ))
    }
}

/// Probe server version, session identity, and supported EBR view columns.
/// Call once per connection and reuse the returned snapshot for owner/type
/// probes.
pub async fn probe_editions_catalog(
    cx: &Cx,
    conn: &dyn OracleConnection,
) -> EditionsCatalogCapabilities {
    let info = conn.describe(cx).await.ok();
    let (metadata_visible, rows) =
        match run_catalog_query(cx, conn, CatalogQueryId::EditionsCatalogColumns, &[]).await {
            Ok(rows) => (true, rows),
            Err(_) => (false, Vec::new()),
        };
    let columns = EBR_COLUMNS
        .iter()
        .map(|(view, column)| EditionsCatalogColumn {
            view: (*view).to_owned(),
            column: (*column).to_owned(),
            present: rows.iter().any(|row| {
                row.text("TABLE_NAME")
                    .is_some_and(|value| value.eq_ignore_ascii_case(view))
                    && row
                        .text("COLUMN_NAME")
                        .is_some_and(|value| value.eq_ignore_ascii_case(column))
            }),
        })
        .collect();

    EditionsCatalogCapabilities {
        server_version: info.as_ref().and_then(|item| item.server_version.clone()),
        session_user: info.and_then(|item| item.session_user),
        metadata_visible,
        columns,
    }
}

/// Prove editions enablement for one exact owner and object type.
///
/// Direct owner flags are preferred when present. `*_EDITIONED_TYPES` rows
/// prove the requested type and may positively prove owner enablement; empty
/// or capped results are never widened into stronger claims.
pub async fn probe_editions_enabled(
    cx: &Cx,
    conn: &dyn OracleConnection,
    capabilities: &EditionsCatalogCapabilities,
    owner: &str,
    object_type: &str,
) -> EditionsEnabledProof {
    let owner = owner.trim().to_owned();
    let object_type = object_type.trim().to_ascii_uppercase();
    let self_owner = capabilities
        .session_user
        .as_deref()
        .is_some_and(|session_user| session_user == owner);

    let owner_flag = if self_owner && capabilities.has_column("USER_USERS", "EDITIONS_ENABLED") {
        Some((
            CatalogQueryId::EditionsEnabledOwnerSelf,
            Vec::new(),
            "USER_USERS",
        ))
    } else if !self_owner
        && capabilities.has_column("DBA_USERS", "USERNAME")
        && capabilities.has_column("DBA_USERS", "EDITIONS_ENABLED")
    {
        Some((
            CatalogQueryId::EditionsEnabledOwnerDba,
            vec![OracleBind::String(owner.clone())],
            "DBA_USERS",
        ))
    } else {
        None
    };
    let mut owner_enabled = EditionsProofStatus::Unknown;
    let mut owner_evidence_view = None;
    if let Some((query, binds, view)) = owner_flag
        && let Ok(rows) = run_catalog_query(cx, conn, query, &binds).await
    {
        owner_evidence_view = Some(view.to_owned());
        owner_enabled = rows
            .first()
            .and_then(|row| row.text("EDITIONS_ENABLED"))
            .map(parse_enabled_flag)
            .unwrap_or(EditionsProofStatus::Unknown);
    }

    let type_catalog =
        if self_owner && capabilities.has_column("USER_EDITIONED_TYPES", "OBJECT_TYPE") {
            Some((
                CatalogQueryId::EditionedTypesSelf,
                vec![OracleBind::I64(MAX_EDITIONED_TYPES as i64)],
                "USER_EDITIONED_TYPES",
            ))
        } else if !self_owner
            && capabilities.has_column("DBA_EDITIONED_TYPES", "SCHEMA")
            && capabilities.has_column("DBA_EDITIONED_TYPES", "OBJECT_TYPE")
        {
            Some((
                CatalogQueryId::EditionedTypesDba,
                vec![
                    OracleBind::String(owner.clone()),
                    OracleBind::I64(MAX_EDITIONED_TYPES as i64),
                ],
                "DBA_EDITIONED_TYPES",
            ))
        } else {
            None
        };

    let mut type_enabled = EditionsProofStatus::Unknown;
    let mut type_evidence_view = None;
    if let Some((query, binds, view)) = type_catalog
        && let Ok(rows) = run_catalog_query(cx, conn, query, &binds).await
    {
        type_evidence_view = Some(view.to_owned());
        let type_present = rows.iter().any(|row| {
            row.text("OBJECT_TYPE")
                .is_some_and(|actual| actual.eq_ignore_ascii_case(&object_type))
        });
        type_enabled = if type_present {
            EditionsProofStatus::Proven
        } else if rows.len() < MAX_EDITIONED_TYPES {
            EditionsProofStatus::Disabled
        } else {
            EditionsProofStatus::Unknown
        };
        if owner_enabled == EditionsProofStatus::Unknown && !rows.is_empty() {
            owner_enabled = EditionsProofStatus::Proven;
            owner_evidence_view = Some(view.to_owned());
        }
    }

    if owner_enabled == EditionsProofStatus::Disabled {
        type_enabled = EditionsProofStatus::Disabled;
    }

    let (database_type_capability, capability_evidence_view) =
        if capabilities.has_column("V_$EDITIONABLE_TYPES", "EDITIONABLE_TYPE") {
            match run_catalog_query(
                cx,
                conn,
                CatalogQueryId::EditionableTypesCapability,
                &[OracleBind::String(object_type.clone()), OracleBind::I64(1)],
            )
            .await
            {
                Ok(rows) => (
                    if rows.is_empty() {
                        EditionsProofStatus::Disabled
                    } else {
                        EditionsProofStatus::Proven
                    },
                    Some("V$EDITIONABLE_TYPES".to_owned()),
                ),
                Err(_) => (EditionsProofStatus::Unknown, None),
            }
        } else {
            (EditionsProofStatus::Unknown, None)
        };

    EditionsEnabledProof {
        owner,
        object_type,
        owner_enabled,
        type_enabled,
        database_type_capability,
        owner_evidence_view,
        type_evidence_view,
        capability_evidence_view,
    }
}

fn parse_enabled_flag(value: &str) -> EditionsProofStatus {
    match value.trim().to_ascii_uppercase().as_str() {
        "Y" => EditionsProofStatus::Proven,
        "N" => EditionsProofStatus::Disabled,
        _ => EditionsProofStatus::Unknown,
    }
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(
        owner_enabled: EditionsProofStatus,
        type_enabled: EditionsProofStatus,
    ) -> EditionsEnabledProof {
        EditionsEnabledProof {
            owner: "SYNTH_OWNER".to_owned(),
            object_type: "VIEW".to_owned(),
            owner_enabled,
            type_enabled,
            database_type_capability: EditionsProofStatus::Proven,
            owner_evidence_view: Some("DBA_USERS".to_owned()),
            type_evidence_view: Some("DBA_EDITIONED_TYPES".to_owned()),
            capability_evidence_view: Some("V$EDITIONABLE_TYPES".to_owned()),
        }
    }

    #[test]
    fn editions_probe_unknown_refuses() {
        let envelope =
            proof(EditionsProofStatus::Unknown, EditionsProofStatus::Unknown).refusal_envelope();
        assert_eq!(envelope.error_class, ErrorClass::PolicyDenied);
        assert_eq!(
            envelope.statement_outcome,
            Some(StatementOutcome::NotStarted)
        );
        assert_eq!(
            envelope
                .structured_reason
                .as_ref()
                .map(|reason| reason.category),
            Some(ReasonCategory::EditionsNotEnabled)
        );
        assert!(envelope.message.contains("Could not prove editions"));
        assert!(envelope.message.contains("server never runs ALTER USER"));
        assert!(!proof(EditionsProofStatus::Unknown, EditionsProofStatus::Unknown).is_proven());
    }

    #[test]
    fn editions_probe_capability_view_never_proves_enablement() {
        let proof = proof(EditionsProofStatus::Unknown, EditionsProofStatus::Unknown);
        assert_eq!(proof.database_type_capability, EditionsProofStatus::Proven);
        assert!(!proof.is_proven());
        assert_eq!(
            proof.owner_enabled,
            EditionsProofStatus::Unknown,
            "V$ editionability is not an owner proof"
        );
    }

    #[test]
    fn editions_probe_catalog_queries_never_issue_ddl() {
        let query_ids = [
            CatalogQueryId::EditionsCatalogColumns,
            CatalogQueryId::EditionsEnabledOwnerSelf,
            CatalogQueryId::EditionsEnabledOwnerDba,
            CatalogQueryId::EditionedTypesSelf,
            CatalogQueryId::EditionedTypesDba,
            CatalogQueryId::EditionableTypesCapability,
        ];
        for query_id in query_ids {
            let sql = query_id.spec().sql.trim_start().to_ascii_uppercase();
            assert!(sql.starts_with("SELECT "), "{query_id:?}: {sql}");
            assert!(!sql.contains("ALTER USER"), "{query_id:?}: {sql}");
        }
    }

    #[test]
    fn editions_not_enabled_message_names_remediation() {
        let envelope =
            proof(EditionsProofStatus::Proven, EditionsProofStatus::Disabled).refusal_envelope();
        assert!(
            envelope
                .message
                .contains("ALTER USER \"SYNTH_OWNER\" ENABLE EDITIONS FOR VIEW")
        );
        assert!(envelope.message.contains("server never runs ALTER USER"));
    }
}
