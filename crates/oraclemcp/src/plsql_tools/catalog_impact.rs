//! Live dictionary dependency projection into the pinned lineage predictor.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use oraclemcp_db::{
    CatalogExtractReport, CatalogRowBatch, CatalogRowSetName, DependentObject, DependentsClosure,
    OracleCell, OracleRow,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use plsql_catalog::CatalogSnapshot;
use plsql_cicd::{
    ChangeSet, ChangedObjectKind, InvalidationPrediction, LineageObjectMetadata, PredictMode,
    UncertaintyRecord, predict_with_lineage,
};
use plsql_core::{Confidence, ConfidenceLevel, ObjectName, SchemaName, SymbolId, UnknownReason};
use plsql_depgraph::{
    DepGraph, Edge, EdgeId, EdgeKind, LogicalObjectId, Node, NodeId, NodeIdentityKind,
    ObjectRevisionId, Provenance, QualifiedName, ResolutionStrategy,
};
use serde::Serialize;
use serde_json::Value;

const MAX_DEPENDENCY_ROWS: usize = 10_000;
const MAX_CHANGED_OBJECTS: usize = 256;
const PUBLIC_SYNONYM_PAGE_SIZE: usize = 128;
const MAX_SNAPSHOT_RESPONSE_BYTES: usize = 1_048_576;

#[derive(Serialize)]
pub(super) struct PublicSynonymPage {
    offset: u32,
    limit: usize,
    total: usize,
    included: usize,
    omitted: usize,
    next_offset: Option<u32>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum SnapshotExportStatus {
    Complete {
        public_synonyms: PublicSynonymPage,
    },
    Partial {
        public_synonyms: PublicSynonymPage,
    },
    TooLarge {
        public_synonyms: PublicSynonymPage,
        object_count: usize,
        symbol_count: usize,
        max_response_bytes: usize,
    },
}

pub(super) struct SnapshotExport {
    pub body: Option<Value>,
    pub status: SnapshotExportStatus,
}

struct BoundedJson {
    bytes: Vec<u8>,
    overflowed: bool,
    limit: usize,
}

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > self.limit {
            self.overflowed = true;
            return Err(io::Error::other("bounded snapshot serialization is full"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Bound only the exported view. The predictor has already consumed the
/// complete internal catalog, and all interned symbol IDs remain unchanged.
pub(super) fn export(
    mut snapshot: CatalogSnapshot,
    public_synonym_offset: u32,
) -> Result<SnapshotExport, ErrorEnvelope> {
    let public = snapshot
        .schemas
        .keys()
        .copied()
        .find(|name| snapshot.interner.resolve(name.symbol()) == Some("PUBLIC"));
    let mut synonyms: Vec<_> = public
        .and_then(|name| snapshot.schemas.get_mut(&name))
        .map(|schema| std::mem::take(&mut schema.synonyms).into_iter().collect())
        .unwrap_or_default();
    synonyms.sort_by(|(left, _), (right, _)| {
        snapshot
            .interner
            .resolve(left.symbol())
            .cmp(&snapshot.interner.resolve(right.symbol()))
    });
    let total = synonyms.len();
    let offset = public_synonym_offset as usize;
    if offset > total {
        return Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("public_synonym_offset {offset} exceeds the observed synonym count {total}"),
        )
        .with_next_step("use the previous response's next_offset, or restart at 0"));
    }
    let included = PUBLIC_SYNONYM_PAGE_SIZE.min(total.saturating_sub(offset));
    if let Some(schema) = public.and_then(|name| snapshot.schemas.get_mut(&name)) {
        schema.synonyms = synonyms.into_iter().skip(offset).take(included).collect();
    }
    let page = PublicSynonymPage {
        offset: public_synonym_offset,
        limit: PUBLIC_SYNONYM_PAGE_SIZE,
        total,
        included,
        omitted: total.saturating_sub(included),
        next_offset: (offset + included < total)
            .then(|| u32::try_from(offset + included).ok())
            .flatten(),
    };
    let object_count = snapshot
        .schemas
        .values()
        .map(|schema| schema.objects.len())
        .sum();
    let symbol_count = snapshot.interner.len();
    let mut buffer = BoundedJson {
        bytes: Vec::new(),
        overflowed: false,
        limit: MAX_SNAPSHOT_RESPONSE_BYTES / 2,
    };
    let serialized = serde_json::to_writer(&mut buffer, &snapshot);
    if serialized.is_err() && !buffer.overflowed {
        return Err(ErrorEnvelope::new(
            ErrorClass::Internal,
            "catalog snapshot serialization failed",
        ));
    }
    // The MCP result carries structured JSON and an escaped text copy. Reserve
    // envelope/marker space as well; never enlarge the harness's 1 MiB limit.
    let fits = !buffer.overflowed
        && serde_json::to_vec(&String::from_utf8_lossy(&buffer.bytes)).is_ok_and(|escaped| {
            buffer
                .bytes
                .len()
                .saturating_add(escaped.len())
                .saturating_add(8192)
                <= MAX_SNAPSHOT_RESPONSE_BYTES
        });
    if !fits {
        return Ok(SnapshotExport {
            body: None,
            status: SnapshotExportStatus::TooLarge {
                public_synonyms: page,
                object_count,
                symbol_count,
                max_response_bytes: MAX_SNAPSHOT_RESPONSE_BYTES,
            },
        });
    }
    let body = serde_json::from_slice(&buffer.bytes).map_err(|_| {
        ErrorEnvelope::new(
            ErrorClass::Internal,
            "serialized catalog snapshot is invalid",
        )
    })?;
    let status = if included == total {
        SnapshotExportStatus::Complete {
            public_synonyms: page,
        }
    } else {
        SnapshotExportStatus::Partial {
            public_synonyms: page,
        }
    };
    Ok(SnapshotExport {
        body: Some(body),
        status,
    })
}

fn response_fits(value: &Value) -> bool {
    let mut raw = BoundedJson {
        bytes: Vec::new(),
        overflowed: false,
        limit: MAX_SNAPSHOT_RESPONSE_BYTES / 2,
    };
    if serde_json::to_writer(&mut raw, value).is_err() {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&raw.bytes) else {
        return false;
    };
    // Match the core's dual structured/text result, using its real fencing
    // implementation. Both W4 transports use integer JSON-RPC request IDs.
    let frame = serde_json::json!({"jsonrpc":"2.0", "id":u64::MAX, "result": {
        "isError":false, "structuredContent":value,
        "content":[{"type":"text", "text":oraclemcp_core::fence::fence_untrusted_text(text)}],
    }});
    let mut wire = BoundedJson {
        bytes: Vec::new(),
        overflowed: false,
        limit: MAX_SNAPSHOT_RESPONSE_BYTES,
    };
    serde_json::to_writer(&mut wire, &frame).is_ok()
}

/// Never present omitted snapshot material as complete. Keep a useful compact
/// summary when possible, and expose an explicit too_large outcome with counts
/// if even the remaining result cannot fit the unchanged wire budget.
pub(super) fn bound_response(mut value: Value, object_count: usize, symbol_count: usize) -> Value {
    if response_fits(&value) {
        return value;
    }
    let too_large = serde_json::json!({"status":"too_large", "object_count":object_count,
        "symbol_count":symbol_count, "max_response_bytes":MAX_SNAPSHOT_RESPONSE_BYTES});
    let snapshot = if value.get("prediction").is_some() {
        value.get_mut("snapshot").and_then(Value::as_object_mut)
    } else {
        value.as_object_mut()
    };
    if let Some(snapshot) = snapshot {
        snapshot.remove("catalog_snapshot");
        snapshot.insert("snapshot_export".to_owned(), too_large.clone());
    }
    if response_fits(&value) {
        return value;
    }
    serde_json::json!({"status":"too_large", "object_count":object_count,
        "symbol_count":symbol_count, "max_response_bytes":MAX_SNAPSHOT_RESPONSE_BYTES,
        "invalidation_count":value.pointer("/prediction/payload/summary/invalidation_count"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_db::{CatalogRowBatch, OracleCell};
    use plsql_cicd::ChangedObject;

    fn row(fields: &[(&str, &str)]) -> OracleRow {
        OracleRow {
            columns: fields
                .iter()
                .map(|(name, value)| {
                    (
                        (*name).to_owned(),
                        OracleCell::new("VARCHAR2", Some((*value).to_owned())),
                    )
                })
                .collect(),
        }
    }

    fn fixture() -> CatalogExtractReport {
        let objects = [
            ("PKG", "PACKAGE"),
            ("P_DEP", "PROCEDURE"),
            ("P_DEP2", "PROCEDURE"),
        ]
        .into_iter()
        .map(|(name, kind)| {
            row(&[
                ("OWNER", "APP"),
                ("OBJECT_NAME", name),
                ("OBJECT_TYPE", kind),
                ("STATUS", "VALID"),
            ])
        })
        .collect();
        let dependencies = [
            ("PKG", "PACKAGE BODY", "PKG", "PACKAGE"),
            ("P_DEP", "PROCEDURE", "PKG", "PACKAGE"),
            ("P_DEP2", "PROCEDURE", "P_DEP", "PROCEDURE"),
        ]
        .into_iter()
        .map(|(name, kind, target, target_kind)| {
            let mut observed = row(&[
                ("OWNER", "APP"),
                ("NAME", name),
                ("TYPE", kind),
                ("REFERENCED_OWNER", "APP"),
                ("REFERENCED_NAME", target),
                ("REFERENCED_TYPE", target_kind),
                ("DEPENDENCY_TYPE", "HARD"),
            ]);
            observed.columns.push((
                "REFERENCED_LINK_NAME".to_owned(),
                OracleCell::new("VARCHAR2", None),
            ));
            observed
        })
        .collect();
        CatalogExtractReport {
            schema_names: vec!["APP".to_owned()],
            batches: vec![
                CatalogRowBatch {
                    row_set: CatalogRowSetName::Objects,
                    rows: objects,
                },
                CatalogRowBatch {
                    row_set: CatalogRowSetName::Dependencies,
                    rows: dependencies,
                },
            ],
            ..CatalogExtractReport::default()
        }
    }

    fn change(snapshot: &CatalogSnapshot) -> ChangeSet {
        let mut interner = snapshot.interner.clone();
        assert!(interner.contains("APP") && interner.contains("PKG"));
        ChangeSet {
            objects: vec![ChangedObject {
                owner: SchemaName::from(interner.intern("APP").unwrap()),
                name: ObjectName::from(interner.intern("PKG").unwrap()),
                kind: ChangedObjectKind::PackageSpec,
                new_hash: None,
                previous_hash: None,
                file_paths: Vec::new(),
                uncertainties: Vec::new(),
            }],
            ..ChangeSet::default()
        }
    }

    #[test]
    fn actual_catalog_rows_reach_direct_and_transitive_predictor_with_body_identity() {
        let report = fixture();
        let snapshot = super::super::snapshot_from_report(&report).unwrap();
        let prediction = predict(
            &snapshot,
            &report,
            &change(&snapshot),
            PredictMode::LiveSnapshot,
        )
        .unwrap();
        let rows: BTreeSet<_> = prediction
            .predicted_invalidations
            .iter()
            .map(|item| {
                (
                    snapshot
                        .interner
                        .resolve(item.owner.symbol())
                        .unwrap()
                        .to_owned(),
                    snapshot
                        .interner
                        .resolve(item.name.symbol())
                        .unwrap()
                        .to_owned(),
                    item.object_type.clone(),
                    item.distance,
                )
            })
            .collect();
        assert_eq!(
            rows,
            BTreeSet::from([
                ("APP".to_owned(), "PKG".to_owned(), "PACKAGE".to_owned(), 1),
                (
                    "APP".to_owned(),
                    "PKG".to_owned(),
                    "PACKAGE BODY".to_owned(),
                    1
                ),
                (
                    "APP".to_owned(),
                    "P_DEP".to_owned(),
                    "PROCEDURE".to_owned(),
                    1
                ),
                (
                    "APP".to_owned(),
                    "P_DEP2".to_owned(),
                    "PROCEDURE".to_owned(),
                    2
                ),
            ])
        );
        assert_eq!(prediction.recompile_order.len(), 3);
        assert!(prediction.uncertainties.is_empty());
    }

    #[test]
    fn remote_dictionary_target_is_counted_without_hiding_real_dependents() {
        let mut report = fixture();
        report.batches[1].rows.push(row(&[
            ("OWNER", "APP"),
            ("NAME", "P_DEP2"),
            ("TYPE", "PROCEDURE"),
            ("REFERENCED_OWNER", "REMOTE_APP"),
            ("REFERENCED_NAME", "UNRESOLVED"),
            ("REFERENCED_TYPE", "PROCEDURE"),
            ("REFERENCED_LINK_NAME", "UNOBSERVED_LINK"),
            ("DEPENDENCY_TYPE", "HARD"),
        ]));
        let snapshot = super::super::snapshot_from_report(&report).unwrap();
        let prediction = predict(
            &snapshot,
            &report,
            &change(&snapshot),
            PredictMode::LiveSnapshot,
        )
        .unwrap();
        assert_eq!(prediction.predicted_invalidations.len(), 4);
        assert!(!prediction.uncertainties.is_empty());
        assert_eq!(
            prediction.completeness.diagnostics_total,
            prediction.uncertainties.len()
        );
    }

    #[test]
    fn a_missing_dependency_rowset_cannot_report_complete_zero_uncertainty() {
        let mut report = fixture();
        report.batches.pop();
        let snapshot = super::super::snapshot_from_report(&report).unwrap();
        let prediction = predict(
            &snapshot,
            &report,
            &change(&snapshot),
            PredictMode::LiveSnapshot,
        )
        .unwrap();
        assert!(!prediction.uncertainties.is_empty());
    }

    #[test]
    fn a_mismatched_change_kind_cannot_borrow_a_package_anchor() {
        let report = fixture();
        let snapshot = super::super::snapshot_from_report(&report).unwrap();
        let mut changeset = change(&snapshot);
        changeset.objects[0].kind = ChangedObjectKind::TableDestructiveDdl;
        let prediction =
            predict(&snapshot, &report, &changeset, PredictMode::LiveSnapshot).unwrap();
        assert_eq!(prediction.predicted_invalidations.len(), 1);
        assert!(prediction.recompile_order.is_empty());
        assert!(
            prediction
                .uncertainties
                .iter()
                .any(|gap| gap.description.contains("no resolved live anchor"))
        );
    }

    fn snapshot_with_public_synonyms() -> CatalogSnapshot {
        let mut report = fixture();
        let synonyms = (0..130)
            .map(|index| {
                row(&[
                    ("OWNER", "PUBLIC"),
                    ("SYNONYM_NAME", &format!("S{index:03}")),
                    ("TABLE_OWNER", "APP"),
                    ("TABLE_NAME", "PKG"),
                ])
            })
            .collect();
        report.batches.push(CatalogRowBatch {
            row_set: CatalogRowSetName::Synonyms,
            rows: synonyms,
        });
        super::super::snapshot_from_report(&report).unwrap()
    }

    #[test]
    fn public_synonym_pages_keep_symbol_ids_and_report_omitted_rows() {
        let snapshot = snapshot_with_public_synonyms();
        let symbols = serde_json::to_value(&snapshot.interner).unwrap();
        let first = export(snapshot.clone(), 0).unwrap();
        let status = serde_json::to_value(first.status).unwrap();
        assert_eq!(status["status"], "partial");
        assert_eq!(status["public_synonyms"]["total"], 130);
        assert_eq!(status["public_synonyms"]["included"], 128);
        assert_eq!(status["public_synonyms"]["omitted"], 2);
        assert_eq!(status["public_synonyms"]["next_offset"], 128);
        assert_eq!(first.body.as_ref().unwrap()["interner"], symbols);
        let second = export(snapshot, 128).unwrap();
        let status = serde_json::to_value(second.status).unwrap();
        assert_eq!(status["public_synonyms"]["included"], 2);
        assert_eq!(status["public_synonyms"]["next_offset"], Value::Null);
        assert_eq!(second.body.as_ref().unwrap()["interner"], symbols);
    }

    #[test]
    fn an_oversized_symbol_table_returns_typed_too_large_with_real_counts() {
        let mut snapshot = snapshot_with_public_synonyms();
        for index in 0..6000 {
            snapshot
                .interner
                .intern(format!("N{index:08}_{}", "X".repeat(100)))
                .unwrap();
        }
        let count = snapshot.interner.len();
        let exported = export(snapshot, 0).unwrap();
        assert!(exported.body.is_none());
        let status = serde_json::to_value(exported.status).unwrap();
        assert_eq!(status["status"], "too_large");
        assert_eq!(status["symbol_count"], count);
        assert_eq!(status["object_count"], 3);
        assert_eq!(status["max_response_bytes"], 1_048_576);
    }

    #[test]
    fn the_final_wire_bound_preserves_real_counts_instead_of_silent_truncation() {
        let large = serde_json::json!({"prediction":{"payload":{"summary":{
            "invalidation_count":123}, "details":"X".repeat(800_000)}}});
        let result = bound_response(large, 456, 789);
        assert_eq!(result["status"], "too_large");
        assert_eq!(result["object_count"], 456);
        assert_eq!(result["symbol_count"], 789);
        assert_eq!(result["invalidation_count"], 123);
        assert!(response_fits(&result));
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ObjectKey {
    owner: String,
    name: String,
    kind: String,
}

impl ObjectKey {
    fn from_row(row: &OracleRow, owner: &str, name: &str, kind: &str) -> Option<Self> {
        Some(Self {
            owner: row.text(owner)?.to_owned(),
            name: row.text(name)?.to_owned(),
            kind: row.text(kind)?.to_owned(),
        })
    }

    fn logical_id(&self) -> String {
        // Quoting both names makes dots and quotes in Oracle identifiers
        // unambiguous. The object type distinguishes a package from its body.
        format!(
            "\"{}\".\"{}\" [{}]",
            self.owner.replace('"', "\"\""),
            self.name.replace('"', "\"\""),
            self.kind
        )
    }
}

struct CatalogGraph {
    graph: DepGraph,
    nodes: BTreeMap<ObjectKey, NodeId>,
    metadata: BTreeMap<String, LineageObjectMetadata>,
    symbols: BTreeMap<String, SymbolId>,
    gaps: BTreeSet<String>,
}

impl CatalogGraph {
    fn new(snapshot: &CatalogSnapshot) -> Self {
        let symbols = (0..snapshot.interner.len())
            .filter_map(|index| {
                let id = SymbolId::new(u64::try_from(index).ok()?);
                snapshot
                    .interner
                    .resolve(id)
                    .map(|name| (name.to_owned(), id))
            })
            .collect();
        Self {
            graph: DepGraph::default(),
            nodes: BTreeMap::new(),
            metadata: BTreeMap::new(),
            symbols,
            gaps: BTreeSet::new(),
        }
    }

    fn ensure_node(&mut self, key: &ObjectKey) -> Option<NodeId> {
        if let Some(id) = self.nodes.get(key) {
            return Some(*id);
        }
        let owner = self
            .symbols
            .get(&key.owner)
            .copied()
            .map(SchemaName::from)?;
        let name = self.symbols.get(&key.name).copied().map(ObjectName::from)?;
        let id = NodeId::new(u64::try_from(self.nodes.len()).ok()?.checked_add(1)?);
        let logical = key.logical_id();
        let identity = identity_kind(&key.kind);
        if identity == NodeIdentityKind::Unknown {
            self.gaps
                .insert(format!("unsupported dictionary object type at {logical}"));
        }
        self.graph.insert_node(Node::new(
            id,
            LogicalObjectId::new(&logical),
            ObjectRevisionId::new("live-dictionary"),
            QualifiedName::new(Some(owner), name),
            identity,
        ));
        self.metadata.insert(
            logical,
            LineageObjectMetadata::new(
                owner,
                name,
                &key.kind,
                matches!(
                    key.kind.as_str(),
                    "PACKAGE"
                        | "PACKAGE BODY"
                        | "PROCEDURE"
                        | "FUNCTION"
                        | "TRIGGER"
                        | "VIEW"
                        | "TYPE"
                        | "TYPE BODY"
                ),
            ),
        );
        self.nodes.insert(key.clone(), id);
        Some(id)
    }

    fn add_dependency(&mut self, row: &OracleRow) {
        let Some(from) = ObjectKey::from_row(row, "OWNER", "NAME", "TYPE") else {
            self.gaps
                .insert("dependency row has no exact source identity".to_owned());
            return;
        };
        let Some(to) = ObjectKey::from_row(
            row,
            "REFERENCED_OWNER",
            "REFERENCED_NAME",
            "REFERENCED_TYPE",
        ) else {
            self.gaps.insert(format!(
                "unresolved dependency target from {}",
                from.logical_id()
            ));
            return;
        };
        if row
            .text("REFERENCED_LINK_NAME")
            .is_some_and(|link| !link.is_empty())
        {
            self.gaps.insert(format!(
                "remote dependency from {} was not observed locally",
                from.logical_id()
            ));
            return;
        }
        let (Some(source), Some(target)) = (self.ensure_node(&from), self.ensure_node(&to)) else {
            self.gaps.insert(format!(
                "dependency symbol identity is unavailable: {} -> {}",
                from.logical_id(),
                to.logical_id()
            ));
            return;
        };
        let mut confidence = ConfidenceLevel::High;
        if row.cell("REFERENCED_LINK_NAME").is_none() {
            self.gaps.insert(format!(
                "remote-link metadata was not observed for {}",
                from.logical_id()
            ));
            confidence = ConfidenceLevel::Opaque;
        }
        if !matches!(
            row.text("DEPENDENCY_TYPE"),
            Some("HARD" | "REF" | "EXTENDED")
        ) {
            self.gaps.insert(format!(
                "dependency strength is unknown for {}",
                from.logical_id()
            ));
            confidence = ConfidenceLevel::Opaque;
        }
        if identity_kind(&from.kind) == NodeIdentityKind::Unknown
            || identity_kind(&to.kind) == NodeIdentityKind::Unknown
        {
            confidence = ConfidenceLevel::Opaque;
        }
        let id = EdgeId::new(
            u64::try_from(self.graph.edges.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        );
        let provenance = Provenance {
            resolution_strategy: ResolutionStrategy::CatalogLookup,
            notes: vec!["observed SYS.ALL_DEPENDENCIES row".to_owned()],
            ..Provenance::default()
        };
        self.graph.insert_edge(
            Edge::new(
                id,
                source,
                target,
                EdgeKind::References,
                Confidence::new(confidence, None),
            ),
            provenance,
            None,
        );
    }
}

fn identity_kind(kind: &str) -> NodeIdentityKind {
    match kind {
        "PACKAGE" => NodeIdentityKind::PackageSpecification,
        "PACKAGE BODY" => NodeIdentityKind::PackageBody,
        "PROCEDURE" => NodeIdentityKind::StandaloneProcedure,
        "FUNCTION" => NodeIdentityKind::StandaloneFunction,
        "TABLE" => NodeIdentityKind::Table,
        "VIEW" => NodeIdentityKind::View,
        "MATERIALIZED VIEW" => NodeIdentityKind::MaterializedView,
        "TYPE" => NodeIdentityKind::Type,
        "TYPE BODY" => NodeIdentityKind::BodyImplementation,
        "TRIGGER" => NodeIdentityKind::Trigger,
        "SEQUENCE" => NodeIdentityKind::Sequence,
        "SYNONYM" => NodeIdentityKind::Synonym,
        "CONSTRAINT" => NodeIdentityKind::Constraint,
        _ => NodeIdentityKind::Unknown,
    }
}

pub(super) fn predict(
    snapshot: &CatalogSnapshot,
    report: &CatalogExtractReport,
    changeset: &ChangeSet,
    mode: PredictMode,
) -> Result<InvalidationPrediction, ErrorEnvelope> {
    if matches!(mode, PredictMode::SourceOnly) {
        return Ok(plsql_cicd::predict(changeset, mode));
    }
    let dependency_count: usize = report
        .batches
        .iter()
        .filter(|batch| batch.row_set == CatalogRowSetName::Dependencies)
        .fold(0usize, |count, batch| {
            count.saturating_add(batch.rows.len())
        });
    let object_count = report
        .batches
        .iter()
        .filter(|batch| batch.row_set == CatalogRowSetName::Objects)
        .fold(0usize, |count, batch| {
            count.saturating_add(batch.rows.len())
        });
    if dependency_count.saturating_add(object_count) > MAX_DEPENDENCY_ROWS
        || changeset.objects.len() > MAX_CHANGED_OBJECTS
    {
        return Err(ErrorEnvelope::new(ErrorClass::InvalidArguments,
            format!("live impact input too_large: {dependency_count} dependency rows and {} changed objects", changeset.objects.len()))
            .with_next_step("request fewer schemas and at most 256 changed objects"));
    }
    let mut catalog = CatalogGraph::new(snapshot);
    for batch in &report.batches {
        if batch.row_set == CatalogRowSetName::Objects {
            for row in &batch.rows {
                if let Some(key) = ObjectKey::from_row(row, "OWNER", "OBJECT_NAME", "OBJECT_TYPE") {
                    if catalog.ensure_node(&key).is_none() {
                        catalog.gaps.insert(format!(
                            "catalog object symbol is unavailable: {}",
                            key.logical_id()
                        ));
                    }
                } else {
                    catalog
                        .gaps
                        .insert("catalog object row has incomplete identity".to_owned());
                }
            }
        }
        if batch.row_set == CatalogRowSetName::Dependencies {
            for row in &batch.rows {
                catalog.add_dependency(row);
            }
        }
    }
    if !report
        .batches
        .iter()
        .any(|batch| batch.row_set == CatalogRowSetName::Dependencies)
    {
        catalog
            .gaps
            .insert("live dependency rowset was not observed".to_owned());
    }
    for warning in &report.warnings {
        if warning.row_set == CatalogRowSetName::Dependencies {
            catalog
                .gaps
                .insert(format!("dependency extraction degraded: {}", warning.code));
        }
    }
    let mut impacts = Vec::new();
    for changed in &changeset.objects {
        // The predictor already records an explicit gap for an unclassified
        // change; no invented object kind can authorize a lineage anchor.
        if matches!(changed.kind, ChangedObjectKind::Unclassified) {
            continue;
        }
        let owner = snapshot.interner.resolve(changed.owner.symbol());
        let name = snapshot.interner.resolve(changed.name.symbol());
        let anchors: Vec<_> = catalog
            .nodes
            .iter()
            .filter(|(key, _)| {
                Some(key.owner.as_str()) == owner
                    && Some(key.name.as_str()) == name
                    && change_matches_type(&changed.kind, &key.kind)
            })
            .map(|(_, id)| *id)
            .collect();
        if anchors.is_empty() {
            catalog.gaps.insert(format!(
                "changed object has no resolved live anchor: owner_symbol={}, name_symbol={}",
                changed.owner.symbol().get(),
                changed.name.symbol().get()
            ));
        }
        if owner.is_none_or(|owner| !report.schema_names.iter().any(|schema| schema == owner)) {
            catalog
                .gaps
                .insert("changed owner is outside the observed dependency scope".to_owned());
        }
        for id in anchors {
            impacts.push(plsql_lineage::impact(&catalog.graph, &id, None));
        }
    }
    let mut prediction = predict_with_lineage(changeset, mode, &impacts, |logical| {
        catalog.metadata.get(logical).cloned()
    });
    for gap in catalog.gaps {
        prediction.uncertainties.push(UncertaintyRecord {
            reason: UnknownReason::MissingCatalogObject,
            affected_owner: None,
            affected_name: None,
            description: gap,
        });
    }
    prediction.completeness.diagnostics_total = prediction.uncertainties.len();
    prediction.completeness.finalize_posture();
    prediction.attributes.insert(
        "catalog_dependency_rows".to_owned(),
        dependency_count.to_string(),
    );
    prediction.attributes.insert(
        "catalog_dependency_scope".to_owned(),
        report.schema_names.join(","),
    );
    Ok(prediction)
}

/// Approval projection of the same dictionary graph used by blast_radius.
/// The changed root is being applied, so only dependent objects belong in the
/// post-apply invalid set; the standalone tool's broader affected set is kept.
#[derive(Serialize)]
pub(super) struct PredictedInvalidSet {
    pub mode: PredictMode,
    pub objects: Vec<PredictedDependent>,
    /// Unknown, remote or truncated observations never become a zero total.
    pub count: Option<usize>,
    pub uncertainties: Vec<Value>,
}

#[derive(Serialize)]
pub(super) struct PredictedDependent {
    pub owner: String,
    pub name: String,
    pub object_type: String,
    pub depth: u32,
}

fn catalog_text_row(fields: Vec<(&str, Option<String>)>) -> OracleRow {
    OracleRow {
        columns: fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), OracleCell::new("VARCHAR2", value)))
            .collect(),
    }
}

pub(super) fn predict_invalid_set(
    closure: &DependentsClosure,
    mode: PredictMode,
) -> Result<PredictedInvalidSet, ErrorEnvelope> {
    let objects = closure
        .roots
        .iter()
        .chain(&closure.nodes)
        .map(|node| {
            catalog_text_row(vec![
                ("OWNER", Some(node.object.owner.clone())),
                ("OBJECT_NAME", Some(node.object.name.clone())),
                ("OBJECT_TYPE", Some(node.object.object_type.clone())),
                ("OBJECT_ID", node.object_id.map(|id| id.to_string())),
                ("STATUS", node.status.clone()),
            ])
        })
        .collect();
    // The snapshot normalizer requires non-null target identities. Preserve
    // incomplete rows in the public closure and its uncertainty list while
    // projecting only actual identities into the existing lineage graph.
    let dependencies = closure
        .edges
        .iter()
        .filter_map(|edge| {
            let target = edge.referenced.as_ref()?;
            Some(catalog_text_row(vec![
                ("OWNER", Some(edge.dependent.owner.clone())),
                ("NAME", Some(edge.dependent.name.clone())),
                ("TYPE", Some(edge.dependent.object_type.clone())),
                ("REFERENCED_OWNER", Some(target.owner.clone())),
                ("REFERENCED_NAME", Some(target.name.clone())),
                ("REFERENCED_TYPE", Some(target.object_type.clone())),
                ("REFERENCED_LINK_NAME", edge.referenced_link_name.clone()),
                ("DEPENDENCY_TYPE", edge.dependency_type.clone()),
            ]))
        })
        .collect();
    let report = CatalogExtractReport {
        schema_names: closure
            .requested_roots
            .iter()
            .chain(closure.nodes.iter().map(|node| &node.object))
            .map(|object| object.owner.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        batches: vec![
            CatalogRowBatch {
                row_set: CatalogRowSetName::Objects,
                rows: objects,
            },
            CatalogRowBatch {
                row_set: CatalogRowSetName::Dependencies,
                rows: dependencies,
            },
        ],
        ..CatalogExtractReport::default()
    };
    let mut snapshot = super::snapshot_from_report(&report)?;
    let mut changeset = ChangeSet::default();
    for object in &closure.requested_roots {
        let owner = snapshot.interner.intern(&object.owner).ok_or_else(|| {
            ErrorEnvelope::new(
                ErrorClass::Internal,
                "dependency owner could not be interned",
            )
        })?;
        let name = snapshot.interner.intern(&object.name).ok_or_else(|| {
            ErrorEnvelope::new(
                ErrorClass::Internal,
                "dependency name could not be interned",
            )
        })?;
        let kind = match object.object_type.as_str() {
            "PACKAGE" => ChangedObjectKind::PackageSpec,
            "PACKAGE BODY" => ChangedObjectKind::PackageBody,
            "PROCEDURE" | "FUNCTION" => ChangedObjectKind::StandaloneRoutineSignature,
            "TABLE" => ChangedObjectKind::TableDestructiveDdl,
            "VIEW" => ChangedObjectKind::ViewDefinitionChange,
            "TYPE" => ChangedObjectKind::TypeEvolution,
            "SYNONYM" => ChangedObjectKind::SynonymRetargeting,
            "MATERIALIZED VIEW" => ChangedObjectKind::MaterializedViewRefreshAffecting,
            "TRIGGER" => ChangedObjectKind::TriggerChange,
            "INDEX" => ChangedObjectKind::IndexChange,
            "SEQUENCE" => ChangedObjectKind::SequenceChange,
            kind => ChangedObjectKind::OtherKnownKind {
                object_type: kind.to_owned(),
            },
        };
        changeset.objects.push(plsql_cicd::ChangedObject {
            owner: SchemaName::from(owner),
            name: ObjectName::from(name),
            kind,
            new_hash: None,
            previous_hash: None,
            file_paths: Vec::new(),
            uncertainties: Vec::new(),
        });
    }
    // This is the sole dependency projection and lineage predictor. In
    // particular, no independent invalidatable-type heuristic lives here.
    let prediction = predict(&snapshot, &report, &changeset, mode)?;
    let requested: BTreeSet<_> = closure.requested_roots.iter().cloned().collect();
    let observed: BTreeSet<_> = closure
        .nodes
        .iter()
        .map(|node| node.object.clone())
        .collect();
    let mut invalid = BTreeMap::new();
    for item in &prediction.predicted_invalidations {
        let (Some(owner), Some(name)) = (
            snapshot.interner.resolve(item.owner.symbol()),
            snapshot.interner.resolve(item.name.symbol()),
        ) else {
            continue;
        };
        let key = DependentObject {
            owner: owner.to_owned(),
            name: name.to_owned(),
            object_type: item.object_type.clone(),
        };
        if requested.contains(&key) || !observed.contains(&key) {
            continue;
        }
        invalid
            .entry(key)
            .and_modify(|depth: &mut u32| *depth = (*depth).min(item.distance))
            .or_insert(item.distance);
    }
    let mut uncertainties = closure
        .uncertainties
        .iter()
        .map(|item| {
            serde_json::json!({
                "source":"catalog", "reason":item.reason, "object":item.object
            })
        })
        .collect::<Vec<_>>();
    uncertainties.extend(closure.edges.iter().filter(|edge|edge.referenced.is_none()).map(|edge|
        serde_json::json!({"source":"catalog","reason":"unresolved_target","object":edge.dependent})));
    uncertainties.extend(prediction.uncertainties.iter().map(|item| {
        serde_json::json!({
            "source":"lineage", "reason":item.reason, "description":item.description,
            "owner":item.affected_owner.and_then(|owner| snapshot.interner.resolve(owner.symbol())),
            "name":item.affected_name.and_then(|name| snapshot.interner.resolve(name.symbol())),
        })
    }));
    let count = (!closure.truncated && uncertainties.is_empty()).then_some(invalid.len());
    Ok(PredictedInvalidSet {
        mode,
        objects: invalid
            .into_iter()
            .map(|(object, depth)| PredictedDependent {
                owner: object.owner,
                name: object.name,
                object_type: object.object_type,
                depth,
            })
            .collect(),
        count,
        uncertainties,
    })
}

#[cfg(test)]
mod approval_prediction_tests {
    use super::*;
    use serde_json::json;

    fn fixture_closure() -> DependentsClosure {
        let object = |name: &str, kind: &str| json!({"owner":"APP","name":name,"object_type":kind});
        let node = |name: &str, kind: &str, id: u64, depth: usize| {
            json!({
                "object":object(name,kind),"object_id":id,"depth":depth,"status":"VALID",
                "last_ddl_time":"2026-10-31T00:00:00",
                "source_hash":{"status":"computed","sha256":vec![0_u8;32]},
            })
        };
        let edge = |from: &str, from_type: &str, to: &str, to_type: &str, id: u64| {
            json!({
                "dependent":object(from,from_type),"referenced":object(to,to_type),
                "referenced_object_id":id,"referenced_link_name":null,"dependency_type":"HARD",
            })
        };
        serde_json::from_value(json!({
            "requested_roots":[object("PKG","PACKAGE")],
            "roots":[node("PKG","PACKAGE",1,0)],
            "nodes":[node("PKG","PACKAGE BODY",2,1),node("P_DEP","PROCEDURE",3,1),node("P_DEP2","PROCEDURE",4,2)],
            "edges":[edge("PKG","PACKAGE BODY","PKG","PACKAGE",1),
                edge("P_DEP","PROCEDURE","PKG","PACKAGE",1),edge("P_DEP2","PROCEDURE","P_DEP","PROCEDURE",3)],
            "caps":{"max_depth":10,"max_count":1000},"truncated":false,"truncation":[],
            "uncertainties":[],"dependency_hash":vec![0_u8;32],
        })).unwrap()
    }

    #[test]
    fn predict_invalid_set_package_spec_change() {
        let prediction =
            predict_invalid_set(&fixture_closure(), PredictMode::LiveSnapshot).unwrap();
        assert_eq!(prediction.count, Some(3));
        assert!(prediction.uncertainties.is_empty());
        let set = prediction
            .objects
            .iter()
            .map(|object| {
                (
                    object.name.as_str(),
                    object.object_type.as_str(),
                    object.depth,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            set,
            BTreeSet::from([
                ("PKG", "PACKAGE BODY", 1),
                ("P_DEP", "PROCEDURE", 1),
                ("P_DEP2", "PROCEDURE", 2)
            ])
        );
    }

    #[test]
    fn predict_invalid_set_remote_only_is_unknown_not_zero() {
        let mut closure = fixture_closure();
        closure.edges.truncate(1);
        closure.edges[0].referenced_link_name = Some("REMOTE_DB".into());
        let prediction = predict_invalid_set(&closure, PredictMode::LiveSnapshot).unwrap();
        assert!(prediction.objects.is_empty());
        assert_eq!(prediction.count, None);
        assert!(!prediction.uncertainties.is_empty());
    }

    #[test]
    fn predict_invalid_set_unresolved_and_truncated_totals_stay_unknown() {
        let mut closure = fixture_closure();
        closure.edges[0].referenced = None;
        let unresolved = predict_invalid_set(&closure, PredictMode::LiveSnapshot).unwrap();
        assert_eq!(unresolved.count, None);
        assert!(!unresolved.uncertainties.is_empty());
        let mut closure = fixture_closure();
        closure.truncated = true;
        closure
            .truncation
            .push(oraclemcp_db::DependencyTruncation::Depth);
        assert_eq!(
            predict_invalid_set(&closure, PredictMode::LiveSnapshot)
                .unwrap()
                .count,
            None
        );
    }
}

fn change_matches_type(change: &ChangedObjectKind, kind: &str) -> bool {
    match change {
        ChangedObjectKind::PackageSpec => kind == "PACKAGE",
        ChangedObjectKind::PackageBody => kind == "PACKAGE BODY",
        ChangedObjectKind::StandaloneRoutineSignature
        | ChangedObjectKind::StandaloneRoutineBody => matches!(kind, "PROCEDURE" | "FUNCTION"),
        ChangedObjectKind::TableAdditiveDdl | ChangedObjectKind::TableDestructiveDdl => {
            kind == "TABLE"
        }
        ChangedObjectKind::ViewDefinitionChange => matches!(kind, "VIEW" | "EDITIONING VIEW"),
        ChangedObjectKind::TypeEvolution => kind == "TYPE",
        ChangedObjectKind::SynonymRetargeting => kind == "SYNONYM",
        ChangedObjectKind::MaterializedViewRefreshAffecting => kind == "MATERIALIZED VIEW",
        ChangedObjectKind::TriggerChange => kind == "TRIGGER",
        ChangedObjectKind::IndexChange => kind == "INDEX",
        ChangedObjectKind::SequenceChange => kind == "SEQUENCE",
        ChangedObjectKind::OtherKnownKind { object_type } => kind == object_type,
        ChangedObjectKind::GrantOrRevoke | ChangedObjectKind::EditionedObjectChange => true,
        ChangedObjectKind::Unclassified => false,
    }
}
