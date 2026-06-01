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

use serde::{Deserialize, Serialize};

/// One object in a schema snapshot (the DDL is used to detect changes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaObject {
    /// Object type (`TABLE`, `PACKAGE`, `VIEW`, …), upper-case.
    pub object_type: String,
    /// Object name.
    pub name: String,
    /// The object's DDL / source (compared to detect changes).
    pub ddl: String,
}

impl SchemaObject {
    fn key(&self) -> (String, String) {
        (
            self.object_type.to_ascii_uppercase(),
            self.name.to_ascii_uppercase(),
        )
    }
}

/// A captured schema snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    pub object_type: String,
    /// The object name.
    pub name: String,
    /// The DDL to apply (or a review note for `ManualReview`).
    pub ddl: String,
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

/// Compare `before` → `after` by (type, name); DDL difference marks a change.
#[must_use]
pub fn compare_schemas(before: &SchemaSnapshot, after: &SchemaSnapshot) -> SchemaDiff {
    let before_map: std::collections::HashMap<_, _> =
        before.objects.iter().map(|o| (o.key(), o)).collect();
    let after_map: std::collections::HashMap<_, _> =
        after.objects.iter().map(|o| (o.key(), o)).collect();

    let mut diff = SchemaDiff::default();
    for o in &after.objects {
        match before_map.get(&o.key()) {
            None => diff.added.push(o.clone()),
            Some(prev) if prev.ddl.trim() != o.ddl.trim() => diff.changed.push(o.clone()),
            Some(_) => {}
        }
    }
    for o in &before.objects {
        if !after_map.contains_key(&o.key()) {
            diff.dropped.push(o.clone());
        }
    }
    diff
}

/// Creation-order rank by object type (lower = create earlier). Drops run in
/// reverse rank. A safe baseline; the engine's dependency graph refines it.
fn create_rank(object_type: &str) -> u8 {
    match object_type.to_ascii_uppercase().as_str() {
        "SEQUENCE" | "TYPE" => 0,
        "TABLE" => 1,
        "INDEX" | "CONSTRAINT" => 2,
        "VIEW" | "MATERIALIZED VIEW" => 3,
        "SYNONYM" => 4,
        "FUNCTION" | "PROCEDURE" | "PACKAGE" | "PACKAGE BODY" | "TRIGGER" => 5,
        _ => 6,
    }
}

/// Whether a changed object of this type can be replaced in place
/// (`CREATE OR REPLACE`) vs needing a reviewed `ALTER` (tables, indexes, …).
fn is_replaceable(object_type: &str) -> bool {
    matches!(
        object_type.to_ascii_uppercase().as_str(),
        "VIEW"
            | "FUNCTION"
            | "PROCEDURE"
            | "PACKAGE"
            | "PACKAGE BODY"
            | "TRIGGER"
            | "TYPE"
            | "SYNONYM"
    )
}

/// Build an ordered, safe migration plan from a diff: creates + replaces in
/// dependency-safe creation order, then drops in reverse order.
#[must_use]
pub fn migration_plan(diff: &SchemaDiff) -> Vec<MigrationStep> {
    let mut creates: Vec<(u8, StepKind, &SchemaObject)> = Vec::new();
    for o in &diff.added {
        creates.push((create_rank(&o.object_type), StepKind::Create, o));
    }
    for o in &diff.changed {
        let kind = if is_replaceable(&o.object_type) {
            StepKind::Replace
        } else {
            StepKind::ManualReview
        };
        creates.push((create_rank(&o.object_type), kind, o));
    }
    // Stable sort by creation rank (creates/replaces in dependency-safe order).
    creates.sort_by_key(|(rank, _, _)| *rank);

    // Drops in REVERSE creation order (dependents before their dependencies).
    let mut drops: Vec<&SchemaObject> = diff.dropped.iter().collect();
    drops.sort_by_key(|o| std::cmp::Reverse(create_rank(&o.object_type)));

    let mut steps = Vec::new();
    let mut order = 0;
    for (_, kind, o) in creates {
        let ddl = match kind {
            StepKind::ManualReview => format!(
                "-- REVIEW REQUIRED: {} {} changed; generate a reasoned ALTER (not auto-derived).\n-- target DDL:\n{}",
                o.object_type, o.name, o.ddl
            ),
            _ => o.ddl.clone(),
        };
        steps.push(MigrationStep {
            order,
            kind,
            object_type: o.object_type.clone(),
            name: o.name.clone(),
            ddl,
        });
        order += 1;
    }
    for o in drops {
        steps.push(MigrationStep {
            order,
            kind: StepKind::Drop,
            object_type: o.object_type.clone(),
            name: o.name.clone(),
            ddl: format!("DROP {} {}", o.object_type.to_ascii_uppercase(), o.name),
        });
        order += 1;
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(ty: &str, name: &str, ddl: &str) -> SchemaObject {
        SchemaObject {
            object_type: ty.to_owned(),
            name: name.to_owned(),
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
        let diff = compare_schemas(&before, &after);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name, "T2");
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].name, "P1");
        assert_eq!(diff.dropped.len(), 1);
        assert_eq!(diff.dropped[0].name, "V_OLD");
        assert!(!diff.is_empty());
    }

    #[test]
    fn identical_schemas_have_empty_diff() {
        let s = SchemaSnapshot {
            objects: vec![obj("TABLE", "T", "ddl")],
        };
        assert!(compare_schemas(&s, &s).is_empty());
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
        let plan = migration_plan(&diff);
        // Orders are sequential.
        assert!(plan.iter().enumerate().all(|(i, s)| s.order == i));
        // The new TABLE is created before the new PACKAGE (lower create rank).
        let t_pos = plan.iter().position(|s| s.name == "T_NEW").unwrap();
        let p_pos = plan.iter().position(|s| s.name == "P_NEW").unwrap();
        assert!(t_pos < p_pos, "tables created before packages");
        // The changed VIEW is a Replace; the changed TABLE is ManualReview.
        assert_eq!(
            plan.iter().find(|s| s.name == "V1").unwrap().kind,
            StepKind::Replace
        );
        let t_ch = plan.iter().find(|s| s.name == "T_CH").unwrap();
        assert_eq!(t_ch.kind, StepKind::ManualReview);
        assert!(t_ch.ddl.contains("REVIEW REQUIRED"));
        // The DROP comes after all creates/replaces.
        let drop_step = plan.iter().find(|s| s.kind == StepKind::Drop).unwrap();
        assert_eq!(drop_step.ddl, "DROP TABLE T_OLD");
        assert!(drop_step.order > t_pos && drop_step.order > p_pos);
    }
}
