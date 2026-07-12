//! `oracle_compare_schemas` — structural schema diff → migration plan (plan
//! §11.4; bead P3-4 / oracle-qmwz.4.4). Diff two schema snapshots (captured by
//! the Tier-1 intelligence, P1-5) into a set of add/drop/change operations and
//! emit an ordered, safe `CREATE`/`DROP`/`CREATE OR REPLACE` migration sequence.
//!
//! readOnly + idempotent: this generates the plan, it never executes it (running
//! it is DDL-level + step-up confirmed). The *structural* diff + a safe
//! type-rank ordering are engine-free and live here; the precise topological
//! recompile order comes from the engine's dependency graph (injected at the
//! tool boundary) and refines this baseline ordering.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_ORACLE_IDENTIFIER_BYTES: usize = 128;

/// An Oracle identifier with its quoting semantics preserved explicitly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleIdentifier {
    /// Identifier contents without surrounding double quotes.
    pub text: String,
    /// Whether Oracle treats `text` as a delimited (case-sensitive) identifier.
    pub quoted: bool,
}

impl OracleIdentifier {
    fn canonical(&self, location: &str) -> Result<String, SchemaDiffError> {
        if self.text.is_empty() {
            return Err(SchemaDiffError::InvalidIdentifier {
                location: location.to_owned(),
                reason: "must be non-empty",
            });
        }
        if self.text.len() > MAX_ORACLE_IDENTIFIER_BYTES {
            return Err(SchemaDiffError::InvalidIdentifier {
                location: location.to_owned(),
                reason: "exceeds Oracle's 128-byte identifier limit",
            });
        }
        if self.text.chars().any(char::is_control) {
            return Err(SchemaDiffError::InvalidIdentifier {
                location: location.to_owned(),
                reason: "must not contain control characters",
            });
        }
        if self.quoted {
            return Ok(self.text.clone());
        }
        let mut chars = self.text.chars();
        if !chars.next().is_some_and(|ch| ch.is_ascii_alphabetic())
            || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$' | '#'))
        {
            return Err(SchemaDiffError::InvalidIdentifier {
                location: location.to_owned(),
                reason: "must be one simple unquoted Oracle identifier",
            });
        }
        Ok(self.text.to_ascii_uppercase())
    }

    /// Render this identifier as injection-safe Oracle SQL.
    pub fn render(&self) -> Result<String, SchemaDiffError> {
        let canonical = self.canonical("identifier")?;
        if self.quoted {
            Ok(format!("\"{}\"", canonical.replace('"', "\"\"")))
        } else {
            Ok(canonical)
        }
    }
}

/// Oracle schema object kinds supported by schema snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SchemaObjectType {
    /// Sequence.
    #[serde(rename = "SEQUENCE")]
    Sequence,
    /// Object type specification.
    #[serde(rename = "TYPE")]
    Type,
    /// Object type body.
    #[serde(rename = "TYPE BODY")]
    TypeBody,
    /// Table.
    #[serde(rename = "TABLE")]
    Table,
    /// Index.
    #[serde(rename = "INDEX")]
    Index,
    /// Constraint (always review-only because its parent table is required).
    #[serde(rename = "CONSTRAINT")]
    Constraint,
    /// View.
    #[serde(rename = "VIEW")]
    View,
    /// Materialized view.
    #[serde(rename = "MATERIALIZED VIEW")]
    MaterializedView,
    /// Synonym.
    #[serde(rename = "SYNONYM")]
    Synonym,
    /// Function.
    #[serde(rename = "FUNCTION")]
    Function,
    /// Procedure.
    #[serde(rename = "PROCEDURE")]
    Procedure,
    /// Package specification.
    #[serde(rename = "PACKAGE")]
    Package,
    /// Package body.
    #[serde(rename = "PACKAGE BODY")]
    PackageBody,
    /// Trigger.
    #[serde(rename = "TRIGGER")]
    Trigger,
}

impl SchemaObjectType {
    /// Canonical Oracle spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sequence => "SEQUENCE",
            Self::Type => "TYPE",
            Self::TypeBody => "TYPE BODY",
            Self::Table => "TABLE",
            Self::Index => "INDEX",
            Self::Constraint => "CONSTRAINT",
            Self::View => "VIEW",
            Self::MaterializedView => "MATERIALIZED VIEW",
            Self::Synonym => "SYNONYM",
            Self::Function => "FUNCTION",
            Self::Procedure => "PROCEDURE",
            Self::Package => "PACKAGE",
            Self::PackageBody => "PACKAGE BODY",
            Self::Trigger => "TRIGGER",
        }
    }
}

/// Invalid or ambiguous schema snapshot input.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SchemaDiffError {
    /// An owner or object name cannot denote the claimed Oracle identifier.
    #[error("{location} {reason}")]
    InvalidIdentifier {
        /// Field path within the snapshot or diff.
        location: String,
        /// Stable validation reason.
        reason: &'static str,
    },
    /// Two entries collapse to the same concrete Oracle identity.
    #[error(
        "{snapshot} snapshot entries {first_index} and {duplicate_index} have duplicate identity {identity}"
    )]
    DuplicateIdentity {
        /// Snapshot label (`before` or `after`).
        snapshot: &'static str,
        /// Index of the first entry.
        first_index: usize,
        /// Index of the duplicate entry.
        duplicate_index: usize,
        /// Canonical owner/type/name identity.
        identity: String,
    },
}

/// One object in a schema snapshot (the DDL is used to detect changes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaObject {
    /// Optional schema owner. `None` means the captured current schema.
    pub owner: Option<OracleIdentifier>,
    /// Object type from the supported Oracle allowlist.
    pub object_type: SchemaObjectType,
    /// Exact object identifier and quoting semantics.
    pub name: OracleIdentifier,
    /// The object's DDL / source (compared to detect changes).
    pub ddl: String,
}

impl SchemaObject {
    fn key(&self, location: &str) -> Result<ObjectKey, SchemaDiffError> {
        Ok(ObjectKey {
            owner: self
                .owner
                .as_ref()
                .map(|owner| owner.canonical(&format!("{location}.owner")))
                .transpose()?,
            object_type: self.object_type,
            name: self.name.canonical(&format!("{location}.name"))?,
        })
    }

    /// Render the owner-qualified identifier exactly and safely.
    pub fn qualified_name(&self) -> Result<String, SchemaDiffError> {
        let name = self.name.render()?;
        self.owner.as_ref().map_or(Ok(name.clone()), |owner| {
            Ok(format!("{}.{}", owner.render()?, name))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ObjectKey {
    owner: Option<String>,
    object_type: SchemaObjectType,
    name: String,
}

impl ObjectKey {
    fn display(&self) -> String {
        let name = self.owner.as_ref().map_or_else(
            || self.name.clone(),
            |owner| format!("{owner}.{}", self.name),
        );
        format!("{} {name}", self.object_type.as_str())
    }
}

/// A captured schema snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaSnapshot {
    /// The objects in the schema.
    pub objects: Vec<SchemaObject>,
}

/// What changed about an object between two snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Present in `after`, absent in `before`.
    Added,
    /// Present in `before`, absent in `after`.
    Dropped,
    /// Present in both, DDL differs.
    Changed,
}

/// The migration step kind (drives how it is applied).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    /// A `CREATE` of a new object.
    Create,
    /// A `CREATE OR REPLACE` of a changed, replaceable object.
    Replace,
    /// A `DROP` of a removed object.
    Drop,
    /// A changed non-replaceable object (e.g. TABLE) needing a reviewed `ALTER`.
    ManualReview,
}

/// One ordered migration step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MigrationStep {
    /// Apply order (ascending).
    pub order: usize,
    /// The step kind.
    pub kind: StepKind,
    /// The object type.
    pub object_type: SchemaObjectType,
    /// The optional schema owner.
    pub owner: Option<OracleIdentifier>,
    /// The exact object identifier.
    pub name: OracleIdentifier,
    /// The DDL to apply (or a review note for `ManualReview`).
    pub ddl: String,
}

impl MigrationStep {
    /// Render the owner-qualified step target exactly and safely.
    pub fn qualified_name(&self) -> Result<String, SchemaDiffError> {
        let name = self.name.render()?;
        self.owner.as_ref().map_or(Ok(name.clone()), |owner| {
            Ok(format!("{}.{}", owner.render()?, name))
        })
    }
}

/// The structural diff of two snapshots.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SchemaDiff {
    /// Objects to add.
    pub added: Vec<SchemaObject>,
    /// Objects to drop.
    pub dropped: Vec<SchemaObject>,
    /// Objects whose DDL changed (the `after` version).
    pub changed: Vec<SchemaObject>,
}

impl SchemaDiff {
    /// Whether the two schemas are identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.dropped.is_empty() && self.changed.is_empty()
    }
}

/// Compare `before` → `after` by exact Oracle identity; DDL difference marks a change.
pub fn compare_schemas(
    before: &SchemaSnapshot,
    after: &SchemaSnapshot,
) -> Result<SchemaDiff, SchemaDiffError> {
    let before_map = snapshot_map("before", before)?;
    let after_map = snapshot_map("after", after)?;

    let mut diff = SchemaDiff::default();
    for o in &after.objects {
        let key = o.key("after object")?;
        match before_map.get(&key) {
            None => diff.added.push(o.clone()),
            Some(prev) if prev.ddl.trim() != o.ddl.trim() => diff.changed.push(o.clone()),
            Some(_) => {}
        }
    }
    for o in &before.objects {
        if !after_map.contains_key(&o.key("before object")?) {
            diff.dropped.push(o.clone());
        }
    }
    Ok(diff)
}

fn snapshot_map<'a>(
    label: &'static str,
    snapshot: &'a SchemaSnapshot,
) -> Result<HashMap<ObjectKey, &'a SchemaObject>, SchemaDiffError> {
    let mut map = HashMap::with_capacity(snapshot.objects.len());
    let mut indexes = HashMap::with_capacity(snapshot.objects.len());
    for (index, object) in snapshot.objects.iter().enumerate() {
        let key = object.key(&format!("{label}.objects[{index}]"))?;
        if let Some(first_index) = indexes.insert(key.clone(), index) {
            return Err(SchemaDiffError::DuplicateIdentity {
                snapshot: label,
                first_index,
                duplicate_index: index,
                identity: key.display(),
            });
        }
        map.insert(key, object);
    }
    Ok(map)
}

/// Creation-order rank by object type (lower = create earlier). Drops run in
/// reverse rank. A safe baseline; the engine's dependency graph refines it.
fn create_rank(object_type: SchemaObjectType) -> u8 {
    match object_type {
        SchemaObjectType::Sequence | SchemaObjectType::Type => 0,
        SchemaObjectType::Table => 1,
        SchemaObjectType::Index | SchemaObjectType::Constraint => 2,
        SchemaObjectType::View | SchemaObjectType::MaterializedView => 3,
        SchemaObjectType::Synonym => 4,
        SchemaObjectType::Function
        | SchemaObjectType::Procedure
        | SchemaObjectType::Package
        | SchemaObjectType::PackageBody
        | SchemaObjectType::TypeBody
        | SchemaObjectType::Trigger => 5,
    }
}

/// Whether a changed object of this type can be replaced in place
/// (`CREATE OR REPLACE`) vs needing a reviewed `ALTER` (tables, indexes, …).
fn is_replaceable(object_type: SchemaObjectType) -> bool {
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

fn create_needs_dependency_context(object_type: SchemaObjectType) -> bool {
    object_type == SchemaObjectType::Constraint
}

fn drop_needs_dependency_context(object_type: SchemaObjectType) -> bool {
    matches!(
        object_type,
        SchemaObjectType::Constraint | SchemaObjectType::PackageBody | SchemaObjectType::TypeBody
    )
}

/// Build an ordered, safe migration plan from a diff: creates + replaces in
/// dependency-safe creation order, then drops in reverse order.
pub fn migration_plan(diff: &SchemaDiff) -> Result<Vec<MigrationStep>, SchemaDiffError> {
    let mut creates: Vec<(u8, StepKind, &SchemaObject)> = Vec::new();
    for o in &diff.added {
        o.key("diff.added object")?;
        let kind = if create_needs_dependency_context(o.object_type) {
            StepKind::ManualReview
        } else {
            StepKind::Create
        };
        creates.push((create_rank(o.object_type), kind, o));
    }
    for o in &diff.changed {
        o.key("diff.changed object")?;
        let kind = if is_replaceable(o.object_type) {
            StepKind::Replace
        } else {
            StepKind::ManualReview
        };
        creates.push((create_rank(o.object_type), kind, o));
    }
    // Stable sort by creation rank (creates/replaces in dependency-safe order).
    creates.sort_by_key(|(rank, _, _)| *rank);

    // Drops in REVERSE creation order (dependents before their dependencies).
    let mut drops: Vec<&SchemaObject> = diff.dropped.iter().collect();
    for object in &drops {
        object.key("diff.dropped object")?;
    }
    drops.sort_by_key(|o| std::cmp::Reverse(create_rank(o.object_type)));

    let mut steps = Vec::new();
    let mut order = 0;
    for (_, kind, o) in creates {
        let ddl = match kind {
            StepKind::ManualReview => inert_manual_review_ddl(o, "operation needs reviewed DDL"),
            _ => o.ddl.clone(),
        };
        steps.push(MigrationStep {
            order,
            kind,
            object_type: o.object_type,
            owner: o.owner.clone(),
            name: o.name.clone(),
            ddl,
        });
        order += 1;
    }
    for o in drops {
        let kind = if drop_needs_dependency_context(o.object_type) {
            StepKind::ManualReview
        } else {
            StepKind::Drop
        };
        let ddl = if kind == StepKind::ManualReview {
            inert_manual_review_ddl(o, "drop needs parent-object dependency context")
        } else {
            format!("DROP {} {}", o.object_type.as_str(), o.qualified_name()?)
        };
        steps.push(MigrationStep {
            order,
            kind,
            object_type: o.object_type,
            owner: o.owner.clone(),
            name: o.name.clone(),
            ddl,
        });
        order += 1;
    }
    Ok(steps)
}

fn inert_manual_review_ddl(object: &SchemaObject, reason: &str) -> String {
    let mut ddl = format!(
        "-- REVIEW REQUIRED: {} {}: {reason}.\n-- target DDL (inert):\n",
        object.object_type.as_str(),
        object
            .qualified_name()
            .unwrap_or_else(|_| "<invalid identifier>".to_owned())
    );
    for line in object.ddl.trim().split(['\r', '\n']) {
        ddl.push_str("-- ");
        ddl.push_str(line);
        ddl.push('\n');
    }
    ddl
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(ty: &str, name: &str, ddl: &str) -> SchemaObject {
        SchemaObject {
            owner: None,
            object_type: match ty {
                "TABLE" => SchemaObjectType::Table,
                "PACKAGE" => SchemaObjectType::Package,
                "VIEW" => SchemaObjectType::View,
                "TYPE BODY" => SchemaObjectType::TypeBody,
                other => panic!("unsupported test object type {other}"),
            },
            name: OracleIdentifier {
                text: name.to_owned(),
                quoted: false,
            },
            ddl: ddl.to_owned(),
        }
    }

    #[test]
    fn diff_detects_added_dropped_changed() {
        let before = SchemaSnapshot {
            objects: vec![
                obj("TABLE", "T1", "create table t1 (a number)"),
                obj("PACKAGE", "P1", "package p1 v1"),
                obj("VIEW", "V_OLD", "view v_old"),
            ],
        };
        let after = SchemaSnapshot {
            objects: vec![
                obj("TABLE", "T1", "create table t1 (a number)"), // unchanged
                obj("PACKAGE", "P1", "package p1 v2"),            // changed
                obj("TABLE", "T2", "create table t2 (b number)"), // added
            ],
        };
        let diff = compare_schemas(&before, &after).expect("valid snapshots");
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name.text, "T2");
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].name.text, "P1");
        assert_eq!(diff.dropped.len(), 1);
        assert_eq!(diff.dropped[0].name.text, "V_OLD");
        assert!(!diff.is_empty());
    }

    #[test]
    fn identical_schemas_have_empty_diff() {
        let s = SchemaSnapshot {
            objects: vec![obj("TABLE", "T", "ddl")],
        };
        assert!(compare_schemas(&s, &s).expect("valid snapshot").is_empty());
    }

    #[test]
    fn migration_orders_creates_then_drops_and_classifies_steps() {
        let diff = SchemaDiff {
            added: vec![
                obj("PACKAGE", "P_NEW", "create package p_new"),
                obj("TABLE", "T_NEW", "create table t_new (a number)"),
            ],
            changed: vec![
                obj(
                    "VIEW",
                    "V1",
                    "create or replace view v1 as select 2 from dual",
                ), // replaceable
                obj("TABLE", "T_CH", "create table t_ch (a number, b number)"), // manual review
            ],
            dropped: vec![obj("TABLE", "T_OLD", "")],
        };
        let plan = migration_plan(&diff).expect("valid diff");
        // Orders are sequential.
        assert!(plan.iter().enumerate().all(|(i, s)| s.order == i));
        // The new TABLE is created before the new PACKAGE (lower create rank).
        let t_pos = plan.iter().position(|s| s.name.text == "T_NEW").unwrap();
        let p_pos = plan.iter().position(|s| s.name.text == "P_NEW").unwrap();
        assert!(t_pos < p_pos, "tables created before packages");
        // The changed VIEW is a Replace; the changed TABLE is ManualReview.
        assert_eq!(
            plan.iter().find(|s| s.name.text == "V1").unwrap().kind,
            StepKind::Replace
        );
        let t_ch = plan.iter().find(|s| s.name.text == "T_CH").unwrap();
        assert_eq!(t_ch.kind, StepKind::ManualReview);
        assert!(t_ch.ddl.contains("REVIEW REQUIRED"));
        assert!(t_ch.ddl.lines().all(|line| line.starts_with("--")));
        // The DROP comes after all creates/replaces.
        let drop_step = plan.iter().find(|s| s.kind == StepKind::Drop).unwrap();
        assert_eq!(drop_step.ddl, "DROP TABLE T_OLD");
        assert!(drop_step.order > t_pos && drop_step.order > p_pos);
    }

    #[test]
    fn manual_review_step_never_contains_active_target_lines() {
        let diff = SchemaDiff {
            added: Vec::new(),
            changed: vec![obj(
                "TABLE",
                "T_CH",
                "CREATE TABLE t_ch (note varchar2(40) default q'[\nDROP USER victim CASCADE;\n]');\r/",
            )],
            dropped: Vec::new(),
        };

        let plan = migration_plan(&diff).expect("valid diff");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].kind, StepKind::ManualReview);
        assert!(
            plan[0].ddl.lines().all(|line| line.starts_with("--")),
            "manual review DDL must be inert at its source: {}",
            plan[0].ddl
        );
        assert!(plan[0].ddl.contains("-- DROP USER victim CASCADE;"));
        assert!(plan[0].ddl.contains("-- /"));
    }

    #[test]
    fn type_body_changes_are_replaceable_source_objects() {
        let diff = SchemaDiff {
            added: Vec::new(),
            changed: vec![obj(
                "TYPE BODY",
                "T_BODY",
                "create or replace type body t_body as end;",
            )],
            dropped: Vec::new(),
        };
        let plan = migration_plan(&diff).expect("valid diff");
        assert_eq!(plan[0].kind, StepKind::Replace);
        assert_eq!(plan[0].object_type, SchemaObjectType::TypeBody);
    }

    #[test]
    fn quoted_lowercase_and_unquoted_folded_names_diff_independently() {
        let after = SchemaSnapshot {
            objects: vec![
                obj("TABLE", "foo", "create table foo (id number)"),
                SchemaObject {
                    owner: None,
                    object_type: SchemaObjectType::Table,
                    name: OracleIdentifier {
                        text: "foo".to_owned(),
                        quoted: true,
                    },
                    ddl: "create table \"foo\" (id number)".to_owned(),
                },
            ],
        };

        let diff = compare_schemas(&SchemaSnapshot::default(), &after)
            .expect("distinct Oracle identities are accepted");
        assert_eq!(diff.added.len(), 2);
        assert_eq!(diff.added[0].name.render().unwrap(), "FOO");
        assert_eq!(diff.added[1].name.render().unwrap(), "\"foo\"");

        let folded_before = SchemaSnapshot {
            objects: vec![obj("TABLE", "foo", "same ddl")],
        };
        let folded_after = SchemaSnapshot {
            objects: vec![obj("TABLE", "FOO", "same ddl")],
        };
        assert!(
            compare_schemas(&folded_before, &folded_after)
                .expect("unquoted case folds")
                .is_empty()
        );
    }

    #[test]
    fn quoted_owner_and_name_escape_double_quotes_in_drop_sql() {
        let object = SchemaObject {
            owner: Some(OracleIdentifier {
                text: "Mixed\"Owner".to_owned(),
                quoted: true,
            }),
            object_type: SchemaObjectType::Table,
            name: OracleIdentifier {
                text: "lower\"name".to_owned(),
                quoted: true,
            },
            ddl: String::new(),
        };
        let diff = SchemaDiff {
            added: Vec::new(),
            changed: Vec::new(),
            dropped: vec![object],
        };

        let plan = migration_plan(&diff).expect("quoted identity is valid");
        assert_eq!(
            plan[0].ddl,
            "DROP TABLE \"Mixed\"\"Owner\".\"lower\"\"name\""
        );
        assert_eq!(
            plan[0].qualified_name().unwrap(),
            "\"Mixed\"\"Owner\".\"lower\"\"name\""
        );
    }

    #[test]
    fn duplicate_snapshot_identity_is_rejected_with_both_indexes() {
        for second_ddl in ["same ddl", "conflicting ddl"] {
            let snapshot = SchemaSnapshot {
                objects: vec![
                    obj("TABLE", "foo", "same ddl"),
                    obj("TABLE", "FOO", second_ddl),
                ],
            };
            let error = compare_schemas(&snapshot, &SchemaSnapshot::default())
                .expect_err("duplicate identity must fail closed");
            assert_eq!(
                error,
                SchemaDiffError::DuplicateIdentity {
                    snapshot: "before",
                    first_index: 0,
                    duplicate_index: 1,
                    identity: "TABLE FOO".to_owned(),
                }
            );
        }
    }

    #[test]
    fn malformed_unquoted_identifier_never_reaches_drop_text() {
        let diff = SchemaDiff {
            added: Vec::new(),
            changed: Vec::new(),
            dropped: vec![SchemaObject {
                owner: None,
                object_type: SchemaObjectType::Table,
                name: OracleIdentifier {
                    text: "T; DROP USER VICTIM CASCADE".to_owned(),
                    quoted: false,
                },
                ddl: String::new(),
            }],
        };

        let error = migration_plan(&diff).expect_err("malformed name must fail closed");
        assert!(error.to_string().contains("simple unquoted"));
    }

    #[test]
    fn constraint_operations_remain_review_only_without_parent_identity() {
        let constraint = SchemaObject {
            owner: None,
            object_type: SchemaObjectType::Constraint,
            name: OracleIdentifier {
                text: "T_PK".to_owned(),
                quoted: false,
            },
            ddl: "alter table t add constraint t_pk primary key (id)".to_owned(),
        };
        let diff = SchemaDiff {
            added: vec![constraint.clone()],
            changed: Vec::new(),
            dropped: vec![constraint],
        };

        let plan = migration_plan(&diff).expect("constraint identity itself is valid");
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|step| step.kind == StepKind::ManualReview));
        assert!(
            plan.iter()
                .all(|step| step.ddl.lines().all(|line| line.starts_with("--")))
        );
    }
}
