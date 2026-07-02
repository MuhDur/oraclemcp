//! Operator schema diff and migration export response builder.

use oraclemcp_db::{
    ChangeKind, MigrationStep, SchemaDiff, SchemaObject, SchemaSnapshot, StepKind, compare_schemas,
    migration_plan,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::change_proposal::{ChangeProposalApplyUnit, ChangeProposalStatementDraft};

const MAX_SCHEMA_OBJECTS: usize = 512;
const MAX_OBJECT_DDL_BYTES: usize = 512 * 1024;

/// Request body for `/operator/v1/schema-diff`.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SchemaDiffExportRequest {
    pub(crate) before: SchemaSnapshot,
    pub(crate) after: SchemaSnapshot,
    #[serde(default)]
    pub(crate) title: Option<String>,
}

/// Schema diff/export request errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum SchemaDiffExportError {
    #[error("invalid schema diff request: {0}")]
    Invalid(String),
    #[error("schema diff response could not be serialized: {0}")]
    Serialization(String),
}

/// Build the redacted diff view and migration export artifact.
pub(crate) fn schema_diff_export_data(
    request: SchemaDiffExportRequest,
) -> Result<Value, SchemaDiffExportError> {
    validate_snapshot("before", &request.before)?;
    validate_snapshot("after", &request.after)?;

    let title = request
        .title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Schema diff migration")
        .to_owned();
    let diff = compare_schemas(&request.before, &request.after);
    let steps = migration_plan(&diff);
    let proposal_statements = proposal_statements_from_steps(&steps);
    let script = render_migration_script(&title, &steps);
    let response = SchemaDiffExportData {
        source: "schema_diff",
        status: "previewed",
        title,
        redaction: "diff and step views omit object DDL; migration_script is the explicit review artifact",
        summary: SchemaDiffSummary {
            added: diff.added.len(),
            dropped: diff.dropped.len(),
            changed: diff.changed.len(),
            migration_steps: steps.len(),
            executable_steps: proposal_statements.len(),
            manual_review_steps: steps
                .iter()
                .filter(|step| step.kind == StepKind::ManualReview)
                .count(),
        },
        diff: diff_view(&diff),
        migration_steps: steps.iter().map(step_view).collect(),
        migration_script_sha256: prefixed_sha256_hex(script.as_bytes()),
        migration_script: script,
        proposal_statements,
    };
    serde_json::to_value(response).map_err(|error| {
        SchemaDiffExportError::Serialization(format!("schema diff response JSON: {error}"))
    })
}

pub(crate) fn schema_diff_error_data(error: SchemaDiffExportError) -> Value {
    json!({
        "source": "schema_diff",
        "error": "invalid_schema_diff_request",
        "message": error.to_string(),
    })
}

#[derive(Clone, Debug, Serialize)]
struct SchemaDiffExportData {
    source: &'static str,
    status: &'static str,
    title: String,
    redaction: &'static str,
    summary: SchemaDiffSummary,
    diff: SchemaDiffView,
    migration_steps: Vec<MigrationStepView>,
    migration_script_sha256: String,
    migration_script: String,
    proposal_statements: Vec<ChangeProposalStatementDraft>,
}

#[derive(Clone, Debug, Serialize)]
struct SchemaDiffSummary {
    added: usize,
    dropped: usize,
    changed: usize,
    migration_steps: usize,
    executable_steps: usize,
    manual_review_steps: usize,
}

#[derive(Clone, Debug, Serialize)]
struct SchemaDiffView {
    added: Vec<SchemaObjectDiffView>,
    dropped: Vec<SchemaObjectDiffView>,
    changed: Vec<SchemaObjectDiffView>,
}

#[derive(Clone, Debug, Serialize)]
struct SchemaObjectDiffView {
    kind: ChangeKind,
    object_type: String,
    name: String,
    ddl_sha256: String,
    ddl_chars: usize,
    source_replaceable: bool,
}

#[derive(Clone, Debug, Serialize)]
struct MigrationStepView {
    order: usize,
    kind: StepKind,
    object_type: String,
    name: String,
    ddl_sha256: String,
    ddl_chars: usize,
    executable: bool,
    source_replaceable: bool,
}

fn validate_snapshot(
    label: &'static str,
    snapshot: &SchemaSnapshot,
) -> Result<(), SchemaDiffExportError> {
    if snapshot.objects.len() > MAX_SCHEMA_OBJECTS {
        return Err(SchemaDiffExportError::Invalid(format!(
            "{label} snapshot has too many objects; max {MAX_SCHEMA_OBJECTS}"
        )));
    }
    for (index, object) in snapshot.objects.iter().enumerate() {
        validate_label(label, index, "object_type", &object.object_type)?;
        validate_label(label, index, "name", &object.name)?;
        if object.ddl.len() > MAX_OBJECT_DDL_BYTES {
            return Err(SchemaDiffExportError::Invalid(format!(
                "{label}.objects[{index}].ddl exceeds {MAX_OBJECT_DDL_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

fn validate_label(
    snapshot: &'static str,
    index: usize,
    field: &'static str,
    value: &str,
) -> Result<(), SchemaDiffExportError> {
    if value.trim().is_empty() {
        return Err(SchemaDiffExportError::Invalid(format!(
            "{snapshot}.objects[{index}].{field} must be non-empty"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(SchemaDiffExportError::Invalid(format!(
            "{snapshot}.objects[{index}].{field} must not contain control characters"
        )));
    }
    Ok(())
}

fn diff_view(diff: &SchemaDiff) -> SchemaDiffView {
    SchemaDiffView {
        added: diff
            .added
            .iter()
            .map(|object| object_view(ChangeKind::Added, object))
            .collect(),
        dropped: diff
            .dropped
            .iter()
            .map(|object| object_view(ChangeKind::Dropped, object))
            .collect(),
        changed: diff
            .changed
            .iter()
            .map(|object| object_view(ChangeKind::Changed, object))
            .collect(),
    }
}

fn object_view(kind: ChangeKind, object: &SchemaObject) -> SchemaObjectDiffView {
    SchemaObjectDiffView {
        kind,
        object_type: object.object_type.clone(),
        name: object.name.clone(),
        ddl_sha256: prefixed_sha256_hex(object.ddl.as_bytes()),
        ddl_chars: object.ddl.chars().count(),
        source_replaceable: is_source_replaceable(&object.object_type),
    }
}

fn step_view(step: &MigrationStep) -> MigrationStepView {
    MigrationStepView {
        order: step.order,
        kind: step.kind,
        object_type: step.object_type.clone(),
        name: step.name.clone(),
        ddl_sha256: prefixed_sha256_hex(step.ddl.as_bytes()),
        ddl_chars: step.ddl.chars().count(),
        executable: step_is_executable(step),
        source_replaceable: is_source_replaceable(&step.object_type),
    }
}

fn proposal_statements_from_steps(steps: &[MigrationStep]) -> Vec<ChangeProposalStatementDraft> {
    steps
        .iter()
        .filter(|step| step_is_executable(step))
        .map(|step| ChangeProposalStatementDraft {
            sql_template: step.ddl.trim().to_owned(),
            binds: Vec::new(),
            unit: Some(ChangeProposalApplyUnit::Ddl),
            commit: Some(true),
            capture_dbms_output: Some(false),
            stored_verdict: None,
        })
        .collect()
}

fn step_is_executable(step: &MigrationStep) -> bool {
    matches!(
        step.kind,
        StepKind::Create | StepKind::Replace | StepKind::Drop
    ) && !step.ddl.trim().is_empty()
}

fn render_migration_script(title: &str, steps: &[MigrationStep]) -> String {
    let mut out = String::new();
    out.push_str("-- oraclemcp schema-diff migration export\n");
    out.push_str(&format!("-- title: {}\n", sanitize_comment(title)));
    out.push_str("-- review artifact only: this endpoint never applies DDL\n");
    out.push_str(
        "-- apply path: draft a Change Proposal, then apply through /operator/v1/change-proposals/apply\n",
    );
    out.push_str("-- atomicity: Oracle DDL commits independently; failures may leave earlier successful steps committed\n");
    out.push_str(
        "-- order: creates/replaces use baseline dependency rank; drops run after dependents\n\n",
    );
    if steps.is_empty() {
        out.push_str("-- no schema differences detected\n");
        return out;
    }
    for step in steps {
        out.push_str(&format!(
            "-- step {}: {:?} {}.{} sha256={}\n",
            step.order + 1,
            step.kind,
            sanitize_comment(&step.object_type),
            sanitize_comment(&step.name),
            prefixed_sha256_hex(step.ddl.as_bytes())
        ));
        if step.kind == StepKind::ManualReview {
            out.push_str(step.ddl.trim());
            out.push_str("\n\n");
            continue;
        }
        out.push_str(&terminated_statement(&step.ddl));
        out.push_str("\n\n");
    }
    out
}

fn terminated_statement(ddl: &str) -> String {
    let trimmed = ddl.trim();
    if trimmed.ends_with(';') || trimmed.ends_with('/') {
        trimmed.to_owned()
    } else {
        format!("{trimmed};")
    }
}

fn sanitize_comment(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\r' | '\n' => ' ',
            _ => ch,
        })
        .collect()
}

fn is_source_replaceable(object_type: &str) -> bool {
    matches!(
        object_type.to_ascii_uppercase().as_str(),
        "VIEW"
            | "FUNCTION"
            | "PROCEDURE"
            | "PACKAGE"
            | "PACKAGE BODY"
            | "TRIGGER"
            | "TYPE"
            | "TYPE BODY"
            | "SYNONYM"
    )
}

fn prefixed_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(object_type: &str, name: &str, ddl: &str) -> SchemaObject {
        SchemaObject {
            object_type: object_type.to_owned(),
            name: name.to_owned(),
            ddl: ddl.to_owned(),
        }
    }

    #[test]
    fn export_redacts_diff_and_generates_review_artifact() {
        let request = SchemaDiffExportRequest {
            before: SchemaSnapshot {
                objects: vec![
                    obj("TABLE", "T_OLD", "create table t_old (id number)"),
                    obj("TABLE", "T_CHANGED", "create table t_changed (id number)"),
                    obj(
                        "VIEW",
                        "V_CHANGED",
                        "create or replace view v_changed as select 1 x from dual",
                    ),
                ],
            },
            after: SchemaSnapshot {
                objects: vec![
                    obj(
                        "TABLE",
                        "T_CHANGED",
                        "create table t_changed (id number, name varchar2(30))",
                    ),
                    obj(
                        "VIEW",
                        "V_CHANGED",
                        "create or replace view v_changed as select 2 x from dual",
                    ),
                    obj(
                        "PACKAGE",
                        "P_NEW",
                        "create or replace package p_new as end p_new",
                    ),
                ],
            },
            title: Some("Review export".to_owned()),
        };

        let data = schema_diff_export_data(request).expect("schema diff exports");
        assert_eq!(data["source"], json!("schema_diff"));
        assert_eq!(data["summary"]["added"], json!(1));
        assert_eq!(data["summary"]["dropped"], json!(1));
        assert_eq!(data["summary"]["changed"], json!(2));
        assert_eq!(data["summary"]["manual_review_steps"], json!(1));
        assert_eq!(data["diff"]["changed"][0].get("ddl"), None);
        assert!(
            data["diff"]["changed"][0]["ddl_sha256"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        let proposal_statements = data["proposal_statements"].as_array().unwrap();
        assert_eq!(
            proposal_statements
                .iter()
                .filter(|statement| statement["unit"] == "ddl")
                .count(),
            proposal_statements.len()
        );
        assert!(
            proposal_statements
                .iter()
                .all(|statement| statement["binds"].as_array().unwrap().is_empty())
        );
        let script = data["migration_script"].as_str().unwrap();
        assert!(script.contains("review artifact only"));
        assert!(script.contains("Oracle DDL commits independently"));
        assert!(script.contains("create or replace view v_changed"));
        assert!(script.contains("DROP TABLE T_OLD"));
        assert!(script.contains("REVIEW REQUIRED"));
    }

    #[test]
    fn rejects_oversized_snapshots_before_diffing() {
        let request = SchemaDiffExportRequest {
            before: SchemaSnapshot {
                objects: (0..=MAX_SCHEMA_OBJECTS)
                    .map(|index| obj("TABLE", &format!("T{index}"), "create table t (id number)"))
                    .collect(),
            },
            after: SchemaSnapshot::default(),
            title: None,
        };

        let err = schema_diff_export_data(request).expect_err("oversized snapshot rejected");
        assert!(
            err.to_string().contains("too many objects"),
            "unexpected error: {err}"
        );
    }
}
