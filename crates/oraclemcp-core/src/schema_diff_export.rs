//! Operator schema diff and migration export response builder.

use oraclemcp_db::{
    ChangeKind, MigrationStep, OracleIdentifier, SchemaDiff, SchemaObject, SchemaObjectType,
    SchemaSnapshot, StepKind, compare_schemas, migration_plan,
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
    let diff = compare_schemas(&request.before, &request.after)
        .map_err(|error| SchemaDiffExportError::Invalid(error.to_string()))?;
    let steps =
        migration_plan(&diff).map_err(|error| SchemaDiffExportError::Invalid(error.to_string()))?;
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
    owner: Option<OracleIdentifier>,
    object_type: SchemaObjectType,
    name: OracleIdentifier,
    ddl_sha256: String,
    ddl_chars: usize,
    source_replaceable: bool,
}

#[derive(Clone, Debug, Serialize)]
struct MigrationStepView {
    order: usize,
    kind: StepKind,
    owner: Option<OracleIdentifier>,
    object_type: SchemaObjectType,
    name: OracleIdentifier,
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
        if object.ddl.len() > MAX_OBJECT_DDL_BYTES {
            return Err(SchemaDiffExportError::Invalid(format!(
                "{label}.objects[{index}].ddl exceeds {MAX_OBJECT_DDL_BYTES} bytes"
            )));
        }
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
        owner: object.owner.clone(),
        object_type: object.object_type,
        name: object.name.clone(),
        ddl_sha256: prefixed_sha256_hex(object.ddl.as_bytes()),
        ddl_chars: object.ddl.chars().count(),
        source_replaceable: is_source_replaceable(object.object_type),
    }
}

fn step_view(step: &MigrationStep) -> MigrationStepView {
    MigrationStepView {
        order: step.order,
        kind: step.kind,
        owner: step.owner.clone(),
        object_type: step.object_type,
        name: step.name.clone(),
        ddl_sha256: prefixed_sha256_hex(step.ddl.as_bytes()),
        ddl_chars: step.ddl.chars().count(),
        executable: step_is_executable(step),
        source_replaceable: is_source_replaceable(step.object_type),
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
            "-- step {}: {:?} {} {} sha256={}\n",
            step.order + 1,
            step.kind,
            step.object_type.as_str(),
            sanitize_comment(
                &step
                    .qualified_name()
                    .unwrap_or_else(|_| "<invalid identifier>".to_owned()),
            ),
            prefixed_sha256_hex(step.ddl.as_bytes())
        ));
        if step.kind == StepKind::ManualReview {
            out.push_str("-- manual-review payload follows; every line is intentionally inert\n");
            out.push_str(&commented_lines(&step.ddl));
            out.push('\n');
            continue;
        }
        out.push_str(&terminated_statement(step));
        out.push_str("\n\n");
    }
    out
}

fn commented_lines(value: &str) -> String {
    let mut out = String::new();
    for line in value.trim().split(['\r', '\n']) {
        if line.trim_start().starts_with("--") {
            out.push_str(line);
        } else {
            out.push_str("-- ");
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

fn terminated_statement(step: &MigrationStep) -> String {
    let trimmed = step.ddl.trim();
    if is_sqlplus_block_step(step) {
        let statement = trimmed.strip_suffix('/').map_or(trimmed, str::trim_end);
        if statement.ends_with(';') {
            format!("{statement}\n/")
        } else {
            format!("{statement};\n/")
        }
    } else if trimmed.ends_with(';') || trimmed.ends_with('/') {
        trimmed.to_owned()
    } else {
        format!("{trimmed};")
    }
}

fn is_sqlplus_block_step(step: &MigrationStep) -> bool {
    matches!(step.kind, StepKind::Create | StepKind::Replace)
        && matches!(
            step.object_type,
            SchemaObjectType::Function
                | SchemaObjectType::Procedure
                | SchemaObjectType::Package
                | SchemaObjectType::PackageBody
                | SchemaObjectType::Trigger
                | SchemaObjectType::Type
                | SchemaObjectType::TypeBody
        )
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

fn is_source_replaceable(object_type: SchemaObjectType) -> bool {
    matches!(
        object_type,
        SchemaObjectType::View
            | SchemaObjectType::Function
            | SchemaObjectType::Procedure
            | SchemaObjectType::Package
            | SchemaObjectType::PackageBody
            | SchemaObjectType::Trigger
            | SchemaObjectType::Type
            | SchemaObjectType::TypeBody
            | SchemaObjectType::Synonym
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
            owner: None,
            object_type: match object_type {
                "TABLE" => SchemaObjectType::Table,
                "VIEW" => SchemaObjectType::View,
                "PACKAGE" => SchemaObjectType::Package,
                other => panic!("unsupported test object type {other}"),
            },
            name: identifier(name),
            ddl: ddl.to_owned(),
        }
    }

    fn identifier(text: &str) -> OracleIdentifier {
        OracleIdentifier {
            text: text.to_owned(),
            quoted: false,
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
    fn manual_review_payload_is_line_commented_even_when_multiline_or_q_quoted() {
        let steps = [MigrationStep {
            order: 0,
            kind: StepKind::ManualReview,
            object_type: SchemaObjectType::Table,
            owner: None,
            name: identifier("T_CHANGED"),
            ddl: "-- REVIEW REQUIRED\nCREATE TABLE t_changed (note varchar2(40) default q'[\nDROP TABLE victims;\n]');\rDROP USER bare_cr CASCADE;\n/\nPROMPT still-not-a-command"
                .to_owned(),
        }];

        let script = render_migration_script("inert review", &steps);
        for forbidden in [
            "CREATE TABLE t_changed (note varchar2(40) default q'[",
            "DROP TABLE victims;",
            "DROP USER bare_cr CASCADE;",
            "/",
            "PROMPT still-not-a-command",
        ] {
            assert!(
                !script.lines().any(|line| line.trim() == forbidden),
                "manual payload line became active: {forbidden}\n{script}"
            );
        }
        assert!(script.contains("-- CREATE TABLE t_changed"));
        assert!(script.contains("-- DROP TABLE victims;"));
        assert!(script.contains("-- DROP USER bare_cr CASCADE;"));
        assert!(script.contains("-- /"));
        assert!(script.contains("-- PROMPT still-not-a-command"));
        assert!(proposal_statements_from_steps(&steps).is_empty());
    }

    #[test]
    fn sqlplus_block_steps_get_one_slash_and_plain_ddl_one_semicolon() {
        let steps = [
            MigrationStep {
                order: 0,
                kind: StepKind::Replace,
                object_type: SchemaObjectType::Package,
                owner: None,
                name: identifier("P"),
                ddl: "CREATE OR REPLACE PACKAGE p AS\n  PROCEDURE run;\nEND p;".to_owned(),
            },
            MigrationStep {
                order: 1,
                kind: StepKind::Replace,
                object_type: SchemaObjectType::Procedure,
                owner: None,
                name: identifier("RUN"),
                ddl: "CREATE OR REPLACE PROCEDURE run AS BEGIN NULL; END;\n/".to_owned(),
            },
            MigrationStep {
                order: 2,
                kind: StepKind::Replace,
                object_type: SchemaObjectType::View,
                owner: None,
                name: identifier("V"),
                ddl: "CREATE OR REPLACE VIEW v AS SELECT 1 x FROM dual;".to_owned(),
            },
            MigrationStep {
                order: 3,
                kind: StepKind::Drop,
                object_type: SchemaObjectType::Package,
                owner: None,
                name: identifier("OLD_P"),
                ddl: "DROP PACKAGE old_p".to_owned(),
            },
        ];

        let script = render_migration_script("runner boundaries", &steps);
        assert!(script.contains("END p;\n/\n\n-- step 2"), "{script}");
        assert!(
            script.contains("BEGIN NULL; END;\n/\n\n-- step 3"),
            "{script}"
        );
        assert!(
            script.contains("CREATE OR REPLACE VIEW v AS SELECT 1 x FROM dual;\n\n-- step 4"),
            "{script}"
        );
        assert!(script.ends_with("DROP PACKAGE old_p;\n\n"), "{script}");
        assert!(!script.contains(";;"), "{script}");
        assert!(!script.contains("\n/\n/"), "{script}");
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

    #[test]
    fn rejects_identical_and_conflicting_duplicate_identities_with_indexes() {
        for second_ddl in ["same", "different"] {
            let request = SchemaDiffExportRequest {
                before: SchemaSnapshot {
                    objects: vec![obj("TABLE", "foo", "same"), obj("TABLE", "FOO", second_ddl)],
                },
                after: SchemaSnapshot::default(),
                title: None,
            };

            let error = schema_diff_export_data(request).expect_err("duplicates rejected");
            assert!(
                error
                    .to_string()
                    .contains("before snapshot entries 0 and 1 have duplicate identity TABLE FOO"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn typed_object_allowlist_and_identifier_validation_fail_closed() {
        let unsupported = serde_json::from_value::<SchemaDiffExportRequest>(json!({
            "before": {"objects": [{
                "owner": null,
                "object_type": "TABLE; DROP USER VICTIM CASCADE",
                "name": {"text": "T", "quoted": false},
                "ddl": ""
            }]},
            "after": {"objects": []}
        }));
        assert!(
            unsupported.is_err(),
            "unsupported type must fail deserialization"
        );

        let malformed_name = SchemaDiffExportRequest {
            before: SchemaSnapshot {
                objects: vec![SchemaObject {
                    owner: None,
                    object_type: SchemaObjectType::Table,
                    name: OracleIdentifier {
                        text: "T; DROP USER VICTIM CASCADE".to_owned(),
                        quoted: false,
                    },
                    ddl: String::new(),
                }],
            },
            after: SchemaSnapshot::default(),
            title: None,
        };
        let error = schema_diff_export_data(malformed_name).expect_err("malformed name rejected");
        assert!(error.to_string().contains("simple unquoted"));
    }

    #[test]
    fn quoted_mixed_case_owner_and_escaped_name_render_as_one_drop_target() {
        let request = SchemaDiffExportRequest {
            before: SchemaSnapshot {
                objects: vec![SchemaObject {
                    owner: Some(OracleIdentifier {
                        text: "MixedOwner".to_owned(),
                        quoted: true,
                    }),
                    object_type: SchemaObjectType::Table,
                    name: OracleIdentifier {
                        text: "odd\"; DROP USER VICTIM CASCADE --".to_owned(),
                        quoted: true,
                    },
                    ddl: String::new(),
                }],
            },
            after: SchemaSnapshot::default(),
            title: None,
        };

        let data = schema_diff_export_data(request).expect("quoted identifier is legal");
        let sql = data["proposal_statements"][0]["sql_template"]
            .as_str()
            .expect("drop SQL");
        assert_eq!(
            sql,
            "DROP TABLE \"MixedOwner\".\"odd\"\"; DROP USER VICTIM CASCADE --\""
        );
        assert_eq!(
            sql.matches(';').count(),
            1,
            "semicolon remains inside quotes"
        );
        assert_eq!(data["migration_steps"][0]["name"]["quoted"], json!(true));
        assert_eq!(
            data["migration_steps"][0]["owner"]["text"],
            json!("MixedOwner")
        );
    }
}
