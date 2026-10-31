#![cfg(feature = "plsql-intelligence")]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use asupersync::Cx;
use chrono::Utc;
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_db::{
    CatalogExtractReport, CatalogExtractRequest, CatalogQueryId, CatalogRowSetName,
    CatalogSchemaFilter, DbError, OracleBind, OracleConnection, OracleRow as DbOracleRow,
    extract_catalog_rowsets, run_catalog_query,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{
    Classifier, ClassifierConfig, ObjectRef, Purity, RoutineEffect, RoutineEffectsV1, RoutineRef,
    SideEffectOracle,
};
use plsql_catalog::{
    CatalogCapabilities, CatalogRowSet, CatalogSnapshot, CatalogSnapshotBuilder, CatalogSource,
    CatalogSourceKind, OracleRow as CatalogOracleRow,
};
use plsql_cicd::{ChangeSet, PredictMode, change_impact_envelope, predict};
use plsql_core::{
    AnalysisProfile, CompletenessPosture, Confidence, ConfidenceLevel, Diagnostic, FileId,
    Severity, Span,
};
use plsql_depgraph::{
    DepGraph, Edge, EdgeId, EdgeKind, LogicalObjectId, Node, NodeId, NodeIdentityKind,
    NodeSelector, ObjectRevisionId, Provenance, ResolutionStrategy,
};
use plsql_doc::{DocSet, extract_doc_comments};
use plsql_engine::{
    AnalysisRequest, InvocationIndexV1, InvocationShapeV1, analyze_project, engine_doctor_report,
    engine_full_doctor_report,
};
use plsql_ir::{FactPayload, lower_top_level};
use plsql_lineage::{LineageDirection, column_readers, column_writers, dependencies, impact};
use plsql_parser::{ParseOptions, parse_with_backend};
use plsql_parser_antlr::Antlr4RustBackend;
use plsql_sast::{CompletenessSnapshot, Rule};
use serde::Deserialize;
use serde_json::{Value, json};

mod catalog_impact;
mod sast_source;
mod source_limits;

/// Internal approval consumer of the same catalog projection as blast_radius.
pub(crate) fn predict_invalid_set(
    closure: &oraclemcp_db::DependentsClosure,
) -> Result<Value, ErrorEnvelope> {
    let prediction = catalog_impact::predict_invalid_set(closure, PredictMode::LiveSnapshot)?;
    serde_json::to_value(prediction).map_err(|_| {
        ErrorEnvelope::new(
            ErrorClass::Internal,
            "dependency prediction serialization failed",
        )
    })
}

pub const TOOL_NAMES: [&str; 9] = [
    "oracle_plsql_parse",
    "oracle_plsql_analyze",
    "oracle_plsql_what_breaks",
    "oracle_plsql_lineage",
    "oracle_lineage",
    "oracle_plsql_sast",
    "oracle_plsql_doc",
    "oracle_plsql_live_snapshot",
    "oracle_plsql_blast_radius",
];

const STATIC_TOOL_NAMES: [&str; 6] = [
    "oracle_plsql_parse",
    "oracle_plsql_analyze",
    "oracle_plsql_what_breaks",
    "oracle_plsql_lineage",
    "oracle_plsql_sast",
    "oracle_plsql_doc",
];

const IDE_LIST_LIMIT: usize = 200;

#[must_use]
pub fn is_static_tool(name: &str) -> bool {
    STATIC_TOOL_NAMES.contains(&name)
}

pub fn register_tools(registry: &mut ToolRegistry) {
    // The embedded policy is validated before tools can be served, even if
    // no analysis-backed classifier is constructed during this process.
    LazyLock::force(&SYS_EFFECTS);
    registry.register(
        ToolDescriptor::new(
            "oracle_plsql_parse",
            ToolTier::FoundationStatic,
            "Parse PL/SQL source offline with the grammar parser and return declarations and diagnostics. Syntax errors or recovered parses return INVALID_ARGUMENTS.",
        )
        .with_input_schema(object_schema(
            json!({
                "source": { "type": "string", "description": "PL/SQL source text." }
            }),
            &["source"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_plsql_analyze",
            ToolTier::FoundationStatic,
            "Run the offline plsql-intelligence engine over a local project root and return doctor summaries.",
        )
        .with_input_schema(object_schema(
            json!({
                "project_root": { "type": "string", "description": "Local filesystem path to analyze." }
            }),
            &["project_root"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_plsql_what_breaks",
            ToolTier::FoundationStatic,
            "Predict invalidation and recompilation impact for a PL/SQL ChangeSet without touching Oracle.",
        )
        .with_input_schema(object_schema(
            json!({
                "changeset": change_set_schema(),
                "mode": { "type": "string", "enum": ["source_only", "catalog_aware", "live_snapshot"], "description": "Prediction completeness mode. Defaults to catalog_aware." }
            }),
            &["changeset"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_plsql_lineage",
            ToolTier::FoundationStatic,
            "Run offline dependency-lineage traversal from a logical object id in a local PL/SQL project. Wrapped or obfuscated bodies are reported as a partial lineage gap.",
        )
        .with_input_schema(object_schema(
            json!({
                "project_root": { "type": "string", "description": "Local filesystem path to analyze." },
                "target": { "type": "string", "description": "Logical object id, for example SCHEMA.PACKAGE or package.procedure depending on source." },
                "direction": { "type": "string", "enum": ["upstream", "downstream", "bidirectional"], "description": "Traversal direction. Defaults to downstream." },
                "max_depth": { "type": "integer", "minimum": 0, "description": "Optional traversal depth cap." }
            }),
            &["project_root", "target"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_lineage",
            ToolTier::FoundationLiveDb,
            "Live-verified COLUMN lineage: cross-check source-derived owner.object.column edges against the guarded Oracle catalog and mark verified, missing, or type-mismatched drift.",
        )
        .with_input_schema(object_schema(
            json!({
                "project_root": { "type": "string", "description": "Local filesystem path to analyze for source (the object DDL, e.g. the view chain)." },
                "owner": { "type": "string", "description": "Optional schema/owner. When omitted the object is matched by object.column across owners." },
                "object": { "type": "string", "description": "The view/table/object that owns the column." },
                "column": { "type": "string", "description": "The column whose source-derived edges to compute." }
            }),
            &["project_root", "object", "column"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_plsql_sast",
            ToolTier::FoundationStatic,
            "Run the offline plsql-sast rule harness over a local PL/SQL project and return findings plus skipped-rule evidence.",
        )
        .with_input_schema(object_schema(
            json!({
                "project_root": { "type": "string", "description": "Local filesystem path to analyze." },
                "format": { "type": "string", "enum": ["json", "sarif", "junit", "histogram"], "description": "Response artifact. Defaults to json." },
                "tool_name": { "type": "string", "description": "SARIF tool name. Defaults to plsql-sast." },
                "tool_version": { "type": "string", "description": "SARIF tool version. Defaults to 0.1.0." },
                "suite_name": { "type": "string", "description": "JUnit suite name. Defaults to plsql-sast." }
            }),
            &["project_root"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_plsql_doc",
            ToolTier::FoundationStatic,
            "Extract doc comments from source or render an existing plsql-doc DocSet.",
        )
        .with_input_schema(object_schema(
            json!({
                "source": { "type": "string", "description": "Optional PL/SQL source text to scan for doc comments." },
                "docset": {
                    "type": "object",
                    "description": "Optional plsql-doc DocSet JSON to render.",
                    "properties": { "objects": { "type": "array" } },
                    "required": ["objects"],
                    "additionalProperties": false
                },
                "query": { "type": "string", "description": "Case-insensitive doc-comment filter." },
                "format": { "type": "string", "enum": ["json", "markdown", "html", "doctor"], "description": "DocSet render format. Defaults to json." },
                "project_label": { "type": "string", "description": "Label used by bundle/index renderers." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_plsql_live_snapshot",
            ToolTier::FoundationLiveDb,
            "Extract live Oracle dictionary rowsets and normalize them through plsql-intelligence CatalogSnapshotBuilder.",
        )
        .with_input_schema(live_schema(false)),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_plsql_blast_radius",
            ToolTier::FoundationLiveDb,
            "Extract a live catalog snapshot, then run the plsql-cicd change-impact predictor for a proposed ChangeSet.",
        )
        .with_input_schema(live_schema(true)),
    );
}

pub fn dispatch_static(tool: &str, args: Value) -> Result<Value, ErrorEnvelope> {
    validate_advertised_enum_arguments(tool, &args)?;
    match tool {
        "oracle_plsql_parse" => run_parse(parse_args(tool, args)?),
        "oracle_plsql_analyze" => run_analyze(parse_args(tool, args)?),
        "oracle_plsql_what_breaks" => run_what_breaks(parse_args(tool, args)?),
        "oracle_plsql_lineage" => run_lineage(parse_args(tool, args)?),
        "oracle_plsql_sast" => run_sast(parse_args(tool, args)?),
        "oracle_plsql_doc" => run_doc(parse_args(tool, args)?),
        _ => Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("unknown PL/SQL intelligence tool: {tool}"),
        )),
    }
}

/// Reject a value outside an advertised string enum before the handler can
/// read the filesystem, access Oracle, or construct an analysis run. The registry
/// schema is the public contract, so this deliberately derives the accepted
/// values from that schema rather than maintaining a second enum list here.
pub(crate) fn validate_advertised_enum_arguments(
    tool: &str,
    args: &Value,
) -> Result<(), ErrorEnvelope> {
    let schema = crate::registry::tool_registry()
        .tools
        .into_iter()
        .find(|descriptor| descriptor.name == tool)
        .and_then(|descriptor| descriptor.input_schema);
    let Some(properties) = schema
        .as_ref()
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    for (field, rule) in properties {
        let Some(allowed) = rule.get("enum").and_then(Value::as_array) else {
            continue;
        };
        let Some(value) = args.get(field) else {
            continue;
        };
        let Some(value) = value.as_str() else {
            return Err(ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                format!("invalid arguments for {tool}: {field} must be a string"),
            ));
        };
        if allowed
            .iter()
            .any(|candidate| candidate.as_str() == Some(value))
        {
            continue;
        }
        let expected = allowed
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("invalid arguments for {tool}: {field} must be one of: {expected}"),
        ));
    }
    Ok(())
}

pub async fn dispatch_live(
    cx: &Cx,
    conn: &dyn OracleConnection,
    tool: &str,
    args: Value,
) -> Result<Value, ErrorEnvelope> {
    match tool {
        "oracle_lineage" => run_column_lineage_live(cx, conn, parse_args(tool, args)?).await,
        "oracle_plsql_live_snapshot" => run_live_snapshot(cx, conn, parse_args(tool, args)?).await,
        "oracle_plsql_blast_radius" => run_blast_radius(cx, conn, parse_args(tool, args)?).await,
        _ => Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("unknown live PL/SQL intelligence tool: {tool}"),
        )),
    }
}

fn object_schema(props: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": false,
    })
}

fn change_set_schema() -> Value {
    json!({
        "type": "object",
        "description": "plsql-cicd ChangeSet JSON.",
        "properties": {
            "objects": { "type": "array", "description": "Changed objects; an empty array is valid." },
            "unclassified_files": { "type": "array", "description": "Project-relative files not classified as objects." }
        },
        "required": ["objects", "unclassified_files"],
        "additionalProperties": true
    })
}

fn live_schema(include_changeset: bool) -> Value {
    let mut props = json!({
        "schemas": { "type": "array", "items": { "type": "string" }, "description": "Schema owners to extract. Omit to use the current schema." },
        "include_plscope": { "type": "boolean", "description": "Include PL/Scope rowsets when available. Defaults to true." },
        "include_snapshot": { "type": "boolean", "description": "Include the normalized catalog with an explicit bounded PUBLIC synonym page. Inspect snapshot_export.status and counts. Defaults to false." },
        "public_synonym_offset": { "type": "integer", "minimum": 0, "description": "Offset into the PUBLIC synonym page when include_snapshot=true. Follow snapshot_export.public_synonyms.next_offset. Defaults to 0." }
    });
    let mut required = Vec::new();
    if include_changeset {
        if let Value::Object(map) = &mut props {
            map.insert("changeset".to_owned(), change_set_schema());
            map.insert(
                "mode".to_owned(),
                json!({ "type": "string", "enum": ["source_only", "catalog_aware", "live_snapshot"], "description": "Prediction completeness mode. Defaults to live_snapshot." }),
            );
        }
        required.push("changeset");
    }
    object_schema(props, &required)
}

/// Build the feature-gated, engine-backed classifier. The guard crate owns the
/// port; this consumer binds the PL/SQL analysis graph. The library baseline is
/// already strict, and the explicit call below documents that this served path
/// must stay fail-closed.
#[must_use]
pub fn classifier_from_analysis_run(run: &plsql_engine::AnalysisRun) -> Classifier {
    Classifier::new(ClassifierConfig::new())
        .with_oracle(Arc::new(PlsqlSideEffectOracle::from_analysis_run(run)))
        .with_statement_unknown_guarded()
}

/// The PL/SQL-intelligence implementation of `oraclemcp-guard`'s purity port.
///
/// Routine effects require an exact, Clean engine invocation closure. Graph
/// edges can only tighten that proof. Statement purity starts from SELECT base objects,
/// checks VPD/catalog policy functions, then walks incoming trigger-like
/// dependents and view dependencies. Anything not strongly proven read-only
/// stays `Unknown`.
#[derive(Clone)]
pub struct PlsqlSideEffectOracle {
    graph: Arc<DepGraph>,
    invocations: Arc<InvocationIndexV1>,
    catalog: Option<Arc<CatalogSnapshot>>,
    catalog_complete: bool,
    source_trustworthy: bool,
}

impl PlsqlSideEffectOracle {
    #[must_use]
    pub fn from_analysis_run(run: &plsql_engine::AnalysisRun) -> Self {
        let source_trustworthy = run.completeness.posture == CompletenessPosture::Clean;
        Self {
            graph: Arc::new(run.dep_graph.clone()),
            invocations: Arc::new(run.invocation_index.clone()),
            catalog: run.catalog.clone().map(Arc::new),
            catalog_complete: run.catalog.is_some(),
            source_trustworthy,
        }
    }

    fn routine_purity_by_candidates(&self, candidates: &[String]) -> Purity {
        let Some(node) = self.resolve_candidates(candidates) else {
            return Purity::Unknown;
        };
        effects_purity(&self.effects_for_exact_id(node.logical_id.as_str(), None))
    }

    fn routine_node_purity(&self, node_id: NodeId) -> Purity {
        match self.graph.nodes.get(&node_id) {
            Some(node) => {
                effects_purity(&self.effects_for_exact_id(node.logical_id.as_str(), None))
            }
            None => Purity::Unknown,
        }
    }

    fn effects_for_exact_id(&self, id: &str, overload: Option<u32>) -> RoutineEffectsV1 {
        if !self.source_trustworthy || !self.catalog_complete {
            return unknown_effects();
        }
        // The engine supports lexical package fallback for calls *inside*
        // source units. An adapter lookup must already identify one exact
        // unit; never let that fallback resolve an external caller's name.
        let candidates: Vec<_> = self
            .invocations
            .units
            .values()
            .filter(|unit| {
                let (base, suffix) = unit.id.split_once('#').unwrap_or((&unit.id, ""));
                base == id
                    && match overload {
                        Some(number) => {
                            suffix.parse::<u32>().ok() == Some(number)
                                || (suffix.is_empty() && number == 1 && unit.kind.is_none())
                        }
                        None => suffix.is_empty() || suffix.parse::<u32>().is_ok(),
                    }
            })
            .collect();
        let [unit] = candidates.as_slice() else {
            return unknown_effects();
        };
        let closure = self.invocations.closure(&InvocationShapeV1 {
            routine_id: unit.id.clone(),
            // Include every optional default's effects. The identity-only
            // port cannot prove that a caller supplied a particular default.
            named_arguments: unit
                .params
                .iter()
                .filter(|p| !p.has_default)
                .map(|p| p.name.clone())
                .collect(),
            ..InvocationShapeV1::default()
        });
        if !closure.clean
            || !closure.unknown_reasons.is_empty()
            || closure.root != unit.id
            || !closure.units.contains(&unit.id)
        {
            return unknown_effects();
        }
        let mut effects = map_engine_effects(&closure.effects);
        // A clean source closure independently proves these effects can never
        // be admitted. Graph uncertainty cannot turn that definite refusal
        // into an unknown result. This does not reconcile any edge for an
        // otherwise admissible closure: it still needs the full High proof.
        let source_refuses = effects.iter().any(|effect| {
            matches!(
                effect,
                RoutineEffect::Autonomous | RoutineEffect::TxnControl
            )
        });
        for member in &closure.units {
            if self.catalog_unit_invalid(member) {
                return unknown_effects();
            }
            if source_refuses {
                continue;
            }
            let Some(node) = self.resolve_candidates(std::slice::from_ref(member)) else {
                return unknown_effects();
            };
            if self
                .outgoing_edges(node.id)
                .iter()
                .any(|edge| !is_high_confidence(edge))
            {
                return unknown_effects();
            }
            // Graph evidence may tighten a source closure, never stand in for
            // a missing one. In particular, a source/index disagreement about
            // a call or a catalog callback is not read-only proof.
            for edge in self.outgoing_edges(node.id) {
                let effect = match edge.kind {
                    EdgeKind::Calls => {
                        if !self.graph.nodes.get(&edge.to).is_some_and(|target| {
                            closure.units.contains(target.logical_id.as_str())
                        }) {
                            return unknown_effects();
                        }
                        None
                    }
                    EdgeKind::Reads
                    | EdgeKind::ReadsColumn
                    | EdgeKind::ReadsUnknownColumnOfTable => {
                        if self.read_relation_has_callbacks(edge.to) {
                            return unknown_effects();
                        }
                        Some(RoutineEffect::ReadDb)
                    }
                    EdgeKind::References | EdgeKind::DependsOnType => None,
                    EdgeKind::Writes
                    | EdgeKind::WritesColumn
                    | EdgeKind::WritesUnknownColumnOfTable
                    | EdgeKind::DerivesColumn => Some(RoutineEffect::Dml),
                    EdgeKind::TransactionControl => Some(RoutineEffect::TxnControl),
                    EdgeKind::Autonomous => Some(RoutineEffect::Autonomous),
                    EdgeKind::SequenceAdvance => Some(RoutineEffect::SequenceAdvance),
                    EdgeKind::RowLock => Some(RoutineEffect::RowLock),
                    EdgeKind::SessionState => Some(RoutineEffect::SessionState),
                    EdgeKind::Ddl => Some(RoutineEffect::Ddl),
                    EdgeKind::Admin => Some(RoutineEffect::Admin),
                    EdgeKind::OperatorOnly => Some(RoutineEffect::OperatorOnly(
                        oraclemcp_guard::OperatorStatementClass::DefaultEditionFlip,
                    )),
                    EdgeKind::ExternalIo => Some(RoutineEffect::ExternalIo),
                    EdgeKind::UnresolvedDynamicSql
                    | EdgeKind::OpaqueDynamic
                    | EdgeKind::Unknown
                    | EdgeKind::TriggersOn
                    | EdgeKind::Constrains
                    | EdgeKind::DbLink
                    | EdgeKind::UnresolvedCallee => return unknown_effects(),
                };
                if let Some(effect) = effect {
                    effects = effects.union(&RoutineEffectsV1::new([effect]));
                }
            }
            if matches!(member.split('.').next(), Some("SYS" | "SYSTEM")) {
                let name = member.split('#').next().unwrap_or(member);
                let Some(reviewed) = SYS_EFFECTS.get(name) else {
                    return unknown_effects();
                };
                // The allowlist can add conservative effects; it cannot erase
                // anything reported by the source-backed engine closure.
                effects = effects.union(reviewed);
            }
        }
        effects
    }

    fn read_relation_has_callbacks(&self, node_id: NodeId) -> bool {
        let Some(node) = self.graph.nodes.get(&node_id) else {
            return true;
        };
        self.incoming_edges(node_id)
            .iter()
            .any(|edge| edge.kind == EdgeKind::TriggersOn)
            || self.catalog.iter().any(|catalog| {
                catalog.schemas.values().any(|schema| {
                    schema.vpd_policies.iter().any(|policy| {
                        policy.enabled
                            && policy.on_select
                            && catalog_object_matches(
                                catalog,
                                policy.object_owner,
                                policy.object_name,
                                node,
                            )
                    })
                })
            })
    }

    fn catalog_unit_invalid(&self, id: &str) -> bool {
        use plsql_catalog::{CatalogObject, ObjectStatus};
        self.catalog
            .iter()
            .flat_map(|catalog| {
                catalog
                    .schemas
                    .values()
                    .flat_map(|schema| schema.objects.values())
                    .map(move |object| (catalog, object))
            })
            .any(|(catalog, object)| {
                let common = match object {
                    CatalogObject::Table(value) => &value.common,
                    CatalogObject::View(value) => &value.common,
                    CatalogObject::MaterializedView(value) => &value.common,
                    CatalogObject::Sequence(value) => &value.common,
                    CatalogObject::Type(value) => &value.common,
                    CatalogObject::Package(value) => &value.common,
                    CatalogObject::Procedure(value) => &value.common,
                    CatalogObject::Function(value) => &value.common,
                    CatalogObject::Trigger(value) => &value.common,
                    CatalogObject::SchedulerJob(value) => &value.common,
                    CatalogObject::EditioningView(value) => &value.common,
                };
                let Some(owner) = catalog.interner.resolve(common.owner.symbol()) else {
                    return true;
                };
                let Some(name) = catalog.interner.resolve(common.name.symbol()) else {
                    return true;
                };
                let qualified = format!("{owner}.{name}");
                (id == qualified
                    || id
                        .strip_prefix(&qualified)
                        .is_some_and(|rest| rest.starts_with(['.', '#'])))
                    && common.status != ObjectStatus::Valid
            })
    }

    fn statement_node_purity(&self, node_id: NodeId, stack: &mut HashSet<NodeId>) -> Purity {
        let key = node_id;
        if !stack.insert(key) {
            return Purity::Unknown;
        };

        let verdict = if !self.source_trustworthy || !self.catalog_complete {
            Purity::Unknown
        } else {
            let mut verdict = self.catalog_vpd_purity_for_node(node_id);

            for edge in self.incoming_edges(node_id) {
                if !matches!(edge.kind, EdgeKind::TriggersOn) {
                    continue;
                }
                let edge_purity = if is_high_confidence(&edge) {
                    self.routine_node_purity(edge.from)
                } else {
                    Purity::Unknown
                };
                verdict = combine_purity(verdict, edge_purity);
                if matches!(verdict, Purity::ProvenSideEffecting) {
                    break;
                }
            }

            if !matches!(verdict, Purity::ProvenSideEffecting) {
                for edge in self.outgoing_edges(node_id) {
                    verdict = combine_purity(verdict, self.statement_edge_purity(&edge, stack));
                    if matches!(verdict, Purity::ProvenSideEffecting) {
                        break;
                    }
                }
            }

            verdict
        };

        stack.remove(&key);
        verdict
    }

    fn statement_edge_purity(&self, edge: &Edge, stack: &mut HashSet<NodeId>) -> Purity {
        if is_proven_side_effect_edge(edge.kind) {
            return Purity::ProvenSideEffecting;
        }
        if !is_high_confidence(edge) {
            return Purity::Unknown;
        }
        match edge.kind {
            EdgeKind::Calls => self.routine_node_purity(edge.to),
            EdgeKind::Reads | EdgeKind::ReadsColumn | EdgeKind::ReadsUnknownColumnOfTable => {
                self.statement_node_purity(edge.to, stack)
            }
            EdgeKind::References | EdgeKind::DependsOnType => Purity::ProvenReadOnly,
            EdgeKind::Unknown
            | EdgeKind::TriggersOn
            | EdgeKind::Constrains
            | EdgeKind::OpaqueDynamic
            | EdgeKind::DbLink => Purity::Unknown,
            EdgeKind::UnresolvedDynamicSql | EdgeKind::UnresolvedCallee => Purity::Unknown,
            EdgeKind::Writes
            | EdgeKind::WritesColumn
            | EdgeKind::WritesUnknownColumnOfTable
            | EdgeKind::DerivesColumn
            | EdgeKind::TransactionControl
            | EdgeKind::Autonomous
            | EdgeKind::SequenceAdvance
            | EdgeKind::RowLock
            | EdgeKind::SessionState
            | EdgeKind::Ddl
            | EdgeKind::Admin
            | EdgeKind::OperatorOnly
            | EdgeKind::ExternalIo => Purity::ProvenSideEffecting,
        }
    }

    fn catalog_vpd_purity_for_node(&self, node_id: NodeId) -> Purity {
        let Some(catalog) = &self.catalog else {
            return Purity::Unknown;
        };
        let Some(node) = self.graph.nodes.get(&node_id) else {
            return Purity::Unknown;
        };
        let mut verdict = Purity::ProvenReadOnly;
        for schema_catalog in catalog.schemas.values() {
            for policy in &schema_catalog.vpd_policies {
                if !policy.enabled || !policy.on_select {
                    continue;
                }
                if !catalog_object_matches(catalog, policy.object_owner, policy.object_name, node) {
                    continue;
                }
                let candidates = vpd_function_candidates(catalog, policy);
                let policy_purity = if candidates.is_empty() {
                    Purity::Unknown
                } else {
                    self.routine_purity_by_candidates(&candidates)
                };
                verdict = combine_purity(verdict, policy_purity);
                if matches!(verdict, Purity::ProvenSideEffecting) {
                    break;
                }
            }
            if matches!(verdict, Purity::ProvenSideEffecting) {
                break;
            }
        }
        verdict
    }

    fn resolve_candidates(&self, candidates: &[String]) -> Option<&Node> {
        let mut resolved = None;
        for candidate in candidates {
            for node in self
                .graph
                .nodes
                .values()
                .filter(|node| node.logical_id.as_str() == candidate)
            {
                if resolved.is_some_and(|prior: &Node| prior.id != node.id) {
                    return None;
                }
                resolved = Some(node);
            }
        }
        resolved
    }

    fn outgoing_edges(&self, node_id: NodeId) -> Vec<Edge> {
        self.graph
            .edges
            .iter()
            .filter(|edge| edge.from == node_id)
            .cloned()
            .collect()
    }

    fn incoming_edges(&self, node_id: NodeId) -> Vec<Edge> {
        self.graph
            .edges
            .iter()
            .filter(|edge| edge.to == node_id)
            .cloned()
            .collect()
    }
}

impl SideEffectOracle for PlsqlSideEffectOracle {
    fn routine_effects(&self, routine: &RoutineRef) -> RoutineEffectsV1 {
        let Some(id) = exact_routine_id(routine) else {
            return unknown_effects();
        };
        self.effects_for_exact_id(&id, routine.overload)
    }

    fn routine_purity(&self, routine: &ObjectRef) -> Purity {
        self.routine_purity_by_candidates(&object_ref_candidates(routine))
    }

    fn statement_purity(&self, base_objects: &[ObjectRef]) -> Purity {
        if base_objects.is_empty() {
            return Purity::Unknown;
        }
        let mut verdict = Purity::ProvenReadOnly;
        for base in base_objects {
            let Some(node_id) = self
                .resolve_candidates(&object_ref_candidates(base))
                .map(|node| node.id)
            else {
                return Purity::Unknown;
            };
            verdict = combine_purity(
                verdict,
                self.statement_node_purity(node_id, &mut HashSet::new()),
            );
            if matches!(verdict, Purity::ProvenSideEffecting) {
                break;
            }
        }
        verdict
    }
}

fn unknown_effects() -> RoutineEffectsV1 {
    RoutineEffectsV1::new([RoutineEffect::Unknown])
}

fn effects_purity(effects: &RoutineEffectsV1) -> Purity {
    if effects
        .iter()
        .any(|effect| effect == RoutineEffect::Unknown)
    {
        Purity::Unknown
    } else if effects.iter().all(|effect| effect == RoutineEffect::ReadDb) {
        Purity::ProvenReadOnly
    } else {
        Purity::ProvenSideEffecting
    }
}

fn exact_routine_id(routine: &RoutineRef) -> Option<String> {
    let parts = routine
        .schema
        .iter()
        .chain(routine.package.iter())
        .chain(std::iter::once(&routine.member));
    let mut names = Vec::new();
    for part in parts {
        // The engine's flattened identity format cannot represent separators
        // inside a component without ambiguity. Refuse those identities.
        if part.text.is_empty()
            || part
                .text
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, '.' | '#' | '@' | '(' | ')' | '"'))
        {
            return None;
        }
        names.push(if part.quoted {
            part.text.clone()
        } else {
            part.text.to_ascii_uppercase()
        });
    }
    Some(names.join("."))
}

pub(crate) fn map_engine_effects(effects: &plsql_engine::RoutineEffectsV1) -> RoutineEffectsV1 {
    use plsql_engine::{OperatorStatementClass as EngineOperator, RoutineEffect as EngineEffect};
    RoutineEffectsV1::new(effects.iter().map(|effect| match effect {
        EngineEffect::ReadDb => RoutineEffect::ReadDb,
        EngineEffect::RowLock => RoutineEffect::RowLock,
        EngineEffect::SessionState => RoutineEffect::SessionState,
        EngineEffect::Dml => RoutineEffect::Dml,
        EngineEffect::Ddl => RoutineEffect::Ddl,
        EngineEffect::Admin => RoutineEffect::Admin,
        EngineEffect::SequenceAdvance => RoutineEffect::SequenceAdvance,
        EngineEffect::OperatorOnly(class) => RoutineEffect::OperatorOnly(match class {
            EngineOperator::DefaultEditionFlip => {
                oraclemcp_guard::OperatorStatementClass::DefaultEditionFlip
            }
        }),
        EngineEffect::TxnControl => RoutineEffect::TxnControl,
        EngineEffect::Autonomous => RoutineEffect::Autonomous,
        EngineEffect::DynamicSql => RoutineEffect::DynamicSql,
        EngineEffect::ExternalIo => RoutineEffect::ExternalIo,
        EngineEffect::Unknown => RoutineEffect::Unknown,
    }))
}

const SYS_EFFECTS_SOURCE: &str = oraclemcp_guard::SYS_EFFECTS_TOML;
static SYS_EFFECTS: LazyLock<BTreeMap<String, RoutineEffectsV1>> = LazyLock::new(|| {
    parse_sys_effects(SYS_EFFECTS_SOURCE).expect("invalid reviewed sys_effects.toml policy")
});

fn sys_effects_marker(effects: &BTreeMap<String, RoutineEffectsV1>) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let digest = Sha256::digest(serde_json::to_vec(effects).expect("effect map serializes"));
    let mut marker = String::from("sha256:");
    for byte in digest {
        write!(marker, "{byte:02x}").expect("writing to String");
    }
    marker
}

fn parse_sys_effects(source: &str) -> Result<BTreeMap<String, RoutineEffectsV1>, String> {
    let document = source
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| error.to_string())?;
    if document
        .iter()
        .any(|(key, _)| !matches!(key, "schema_version" | "reviewed_marker" | "routine"))
        || document
            .get("schema_version")
            .and_then(toml_edit::Item::as_integer)
            != Some(1)
    {
        return Err("unsupported SYS effects policy schema".into());
    }
    let entries = document
        .get("routine")
        .and_then(toml_edit::Item::as_array_of_tables)
        .ok_or("SYS effects entries are missing")?;
    let mut effects = BTreeMap::new();
    for entry in entries {
        if entry
            .iter()
            .any(|(key, _)| !matches!(key, "identity" | "effects"))
        {
            return Err("unknown SYS effects entry field".into());
        }
        let name = entry
            .get("identity")
            .and_then(toml_edit::Item::as_str)
            .ok_or("SYS effects identity is missing")?;
        let parts: Vec<_> = name.split('.').collect();
        if parts.len() != 3
            || !matches!(parts[0], "SYS" | "SYSTEM")
            || parts.iter().any(|part| {
                part.is_empty()
                    || !part.bytes().all(|b| {
                        b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'_' | b'$')
                    })
            })
        {
            return Err("SYS effects identity must be exact OWNER.PACKAGE.MEMBER".into());
        }
        let values = entry
            .get("effects")
            .and_then(toml_edit::Item::as_array)
            .ok_or("SYS effect set is missing")?;
        let values = values
            .iter()
            .map(|value| {
                let text = value.as_str().ok_or("SYS effect must be a named variant")?;
                serde_json::from_value::<RoutineEffect>(json!(text))
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, String>>()?;
        if values.is_empty()
            || values.iter().collect::<BTreeSet<_>>().len() != values.len()
            || effects
                .insert(name.to_owned(), RoutineEffectsV1::new(values))
                .is_some()
        {
            return Err("empty, duplicate or ambiguous SYS effects entry".into());
        }
    }
    if document
        .get("reviewed_marker")
        .and_then(toml_edit::Item::as_str)
        != Some(sys_effects_marker(&effects).as_str())
    {
        return Err("SYS effects changed without updating the reviewed marker".into());
    }
    Ok(effects)
}

fn combine_purity(left: Purity, right: Purity) -> Purity {
    match (left, right) {
        (Purity::ProvenSideEffecting, _) | (_, Purity::ProvenSideEffecting) => {
            Purity::ProvenSideEffecting
        }
        (Purity::Unknown, _) | (_, Purity::Unknown) => Purity::Unknown,
        (Purity::ProvenReadOnly, Purity::ProvenReadOnly) => Purity::ProvenReadOnly,
        _ => Purity::Unknown,
    }
}

fn is_proven_side_effect_edge(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::Writes
            | EdgeKind::WritesColumn
            | EdgeKind::WritesUnknownColumnOfTable
            | EdgeKind::DerivesColumn
            | EdgeKind::TransactionControl
            | EdgeKind::Autonomous
            | EdgeKind::SequenceAdvance
            | EdgeKind::RowLock
            | EdgeKind::SessionState
            | EdgeKind::Ddl
            | EdgeKind::Admin
            | EdgeKind::OperatorOnly
            | EdgeKind::ExternalIo
    )
}

fn is_high_confidence(edge: &Edge) -> bool {
    matches!(edge.confidence.level, ConfidenceLevel::High)
}

fn object_ref_candidates(reference: &ObjectRef) -> Vec<String> {
    for component in reference
        .schema
        .iter()
        .chain(std::iter::once(&reference.name))
    {
        if let Some(quoted) = component
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
        {
            if quoted
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, '.' | '#' | '@' | '(' | ')' | '"'))
            {
                // A quoted separator is part of one identifier, not one of
                // the engine's flattened multipart identity separators.
                return Vec::new();
            }
        } else if component.contains('"') {
            return Vec::new();
        }
    }
    let name = normalize_identifier(&reference.name);
    if let Some(schema) = &reference.schema {
        // A qualified reference must never inherit proof from an unrelated
        // bare node. If the graph cannot resolve the exact two-part identity,
        // purity is Unknown; Oracle name resolution is not a suffix match.
        vec![format!("{}.{}", normalize_identifier(schema), name)]
    } else {
        vec![name]
    }
}

fn normalize_identifier(value: &str) -> String {
    match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        Some(quoted) => quoted.replace("\"\"", "\""),
        None => value.to_ascii_uppercase(),
    }
}

fn catalog_object_matches(
    catalog: &CatalogSnapshot,
    owner: plsql_core::SchemaName,
    object: plsql_core::ObjectName,
    node: &Node,
) -> bool {
    let Some(owner) = catalog.interner.resolve(owner.symbol()) else {
        return false;
    };
    let Some(object) = catalog.interner.resolve(object.symbol()) else {
        return false;
    };
    // Catalog identifiers are already Oracle's canonical spelling.
    let qualified = format!("{owner}.{object}");
    node.logical_id.as_str() == qualified
}

fn vpd_function_candidates(
    catalog: &CatalogSnapshot,
    policy: &plsql_catalog::VpdPolicy,
) -> Vec<String> {
    let Some(owner) = catalog
        .interner
        .resolve(policy.function_owner.symbol())
        .map(str::to_owned)
    else {
        return Vec::new();
    };
    let function = &policy.function_name;
    if let Some(package) = &policy.function_package {
        vec![format!("{owner}.{package}.{function}")]
    } else {
        vec![format!("{owner}.{function}")]
    }
}

fn parse_args<T: for<'de> Deserialize<'de>>(tool: &str, args: Value) -> Result<T, ErrorEnvelope> {
    let args = match args {
        Value::Null => Value::Object(serde_json::Map::new()),
        other => other,
    };
    if let Some((unknown, accepted)) = crate::registry::undeclared_arguments(tool, &args) {
        return Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!(
                "invalid arguments for {tool}: unknown argument(s) {}; accepted arguments: {}",
                unknown.join(", "),
                accepted.join(", ")
            ),
        )
        .with_next_step("call tools/list and inspect this tool's inputSchema.properties"));
    }
    serde_json::from_value(args).map_err(|error| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("invalid arguments for {tool}: {error}"),
        )
        .with_next_step("call tools/list and inspect this tool's inputSchema.properties")
    })
}

#[cfg(test)]
pub(crate) fn decode_args_for_contract(tool: &str, args: Value) -> Result<(), ErrorEnvelope> {
    macro_rules! typed {
        ($ty:ty) => {
            parse_args::<$ty>(tool, args).map(|_| ())
        };
    }
    match tool {
        "oracle_plsql_parse" => typed!(ParseArgs),
        "oracle_plsql_analyze" => typed!(AnalyzeArgs),
        "oracle_plsql_what_breaks" => typed!(WhatBreaksArgs),
        "oracle_plsql_lineage" => typed!(LineageArgs),
        "oracle_lineage" => typed!(ColumnLineageArgs),
        "oracle_plsql_sast" => typed!(SastArgs),
        "oracle_plsql_doc" => typed!(DocArgs),
        "oracle_plsql_live_snapshot" => typed!(LiveSnapshotArgs),
        "oracle_plsql_blast_radius" => typed!(BlastRadiusArgs),
        other => panic!("registered PL/SQL tool {other} has no decoder contract"),
    }
}

#[cfg(test)]
pub(crate) fn runtime_fields_for_contract(tool: &str) -> Vec<String> {
    fn fields<T: serde::de::DeserializeOwned>() -> Vec<String> {
        let error = serde_json::from_value::<T>(json!({"__bogus__": 1}))
            .err()
            .expect("PL/SQL DTO must reject unknown probe");
        let message = error.to_string();
        assert!(message.contains("unknown field `__bogus__`"), "{message}");
        message
            .split('`')
            .skip(3)
            .step_by(2)
            .map(str::to_owned)
            .collect()
    }
    match tool {
        "oracle_plsql_parse" => fields::<ParseArgs>(),
        "oracle_plsql_analyze" => fields::<AnalyzeArgs>(),
        "oracle_plsql_what_breaks" => fields::<WhatBreaksArgs>(),
        "oracle_plsql_lineage" => fields::<LineageArgs>(),
        "oracle_lineage" => fields::<ColumnLineageArgs>(),
        "oracle_plsql_sast" => fields::<SastArgs>(),
        "oracle_plsql_doc" => fields::<DocArgs>(),
        "oracle_plsql_live_snapshot" => fields::<LiveSnapshotArgs>(),
        "oracle_plsql_blast_radius" => fields::<BlastRadiusArgs>(),
        other => panic!("registered PL/SQL tool {other} has no decoder contract"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParseArgs {
    source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyzeArgs {
    project_root: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WhatBreaksArgs {
    changeset: ChangeSet,
    mode: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LineageArgs {
    project_root: String,
    target: String,
    direction: Option<String>,
    max_depth: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ColumnLineageArgs {
    project_root: String,
    owner: Option<String>,
    object: String,
    column: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SastArgs {
    project_root: String,
    format: Option<String>,
    tool_name: Option<String>,
    tool_version: Option<String>,
    suite_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocArgs {
    source: Option<String>,
    docset: Option<DocSet>,
    query: Option<String>,
    format: Option<String>,
    project_label: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveSnapshotArgs {
    schemas: Option<Vec<String>>,
    include_plscope: Option<bool>,
    include_snapshot: Option<bool>,
    public_synonym_offset: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlastRadiusArgs {
    schemas: Option<Vec<String>>,
    include_plscope: Option<bool>,
    include_snapshot: Option<bool>,
    public_synonym_offset: Option<u32>,
    changeset: ChangeSet,
    mode: Option<String>,
}

fn run_parse(args: ParseArgs) -> Result<Value, ErrorEnvelope> {
    validate_engine_source(&args.source)?;
    // Header scanning alone does not validate a routine's body. Use the same
    // grammar backend as project analysis, and never lower a recovered parse
    // into a successful declaration report.
    let parsed = parse_with_backend(
        &args.source,
        FileId::new(1),
        &Antlr4RustBackend::new(),
        &ParseOptions::default(),
    );
    if !parsed.is_clean() || parsed.was_recovered() {
        let error_count = parsed
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity >= Severity::Error)
            .count();
        let mut error = ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!(
                "invalid PL/SQL source: {error_count} parser error(s); recovered={}",
                parsed.was_recovered()
            ),
        );
        // Report diagnostic codes and locations without echoing source literals
        // from parser messages into the error envelope.
        for diagnostic in parsed.diagnostics.iter().take(8) {
            let location = diagnostic.primary_span.map_or_else(String::new, |span| {
                format!(" at line {}, column {}", span.start.line, span.start.column)
            });
            error = error.with_next_step(format!(
                "correct PL/SQL syntax: {}{location}, then retry oracle_plsql_parse",
                diagnostic.code
            ));
        }
        return Err(error
            .with_next_step("submit source that parses without syntax errors or parser recovery"));
    }
    let mut interner = plsql_core::SymbolInterner::new();
    let lowered = lower_top_level(&parsed.ast, &mut interner);
    let all_diagnostics: Vec<_> = parsed
        .diagnostics
        .iter()
        .chain(&lowered.diagnostics)
        .collect();
    let diagnostics: Vec<Value> = all_diagnostics
        .iter()
        .map(|d| diagnostic_summary(d))
        .collect();
    let declaration_kinds: Vec<String> = lowered
        .declarations
        .iter()
        .map(|decl| format!("{:?}", decl.kind()))
        .collect();
    let declarations: Vec<Value> = lowered
        .declarations
        .iter()
        .map(|decl| declaration_summary(decl, &interner))
        .collect();

    Ok(json!({
        "declaration_count": declaration_kinds.len(),
        "declaration_kinds": declaration_kinds,
        "declarations": declarations,
        "recovered": parsed.was_recovered(),
        "error_count": all_diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity >= Severity::Error)
            .count(),
        "warning_count": all_diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Warn)
            .count(),
        "diagnostics": diagnostics,
    }))
}

fn run_analyze(args: AnalyzeArgs) -> Result<Value, ErrorEnvelope> {
    let run = analyze_local_project(&args.project_root)?;
    Ok(json!({
        "project_root": args.project_root,
        "file_count": run.project.file_count,
        "summary": engine_doctor_report(&run),
        "full_doctor": engine_full_doctor_report(&run),
        "completeness": run.completeness,
        "graph": {
            "node_count": run.dep_graph.node_count(),
            "edge_count": run.dep_graph.edge_count(),
        },
        "ide": ide_project_summary(&run),
        "diagnostic_count": run.diagnostics.len(),
    }))
}

fn declaration_summary(
    decl: &plsql_ir::Declaration,
    interner: &plsql_core::SymbolInterner,
) -> Value {
    json!({
        "name": interner.resolve(decl.common().name).unwrap_or(""),
        "kind": format!("{:?}", decl.kind()),
        "span": span_summary(decl.span()),
        "schema": decl.common().schema.map(|schema| interner.resolve(schema.symbol()).unwrap_or("")),
        "parent": decl.common().parent.map(|parent| parent.get()),
        "callable": decl.is_callable(),
        "schema_object": decl.is_schema_object(),
    })
}

fn diagnostic_summary(diagnostic: &Diagnostic) -> Value {
    json!({
        "code": diagnostic.code.as_str(),
        "severity": format!("{:?}", diagnostic.severity),
        "message": diagnostic.message.as_str(),
        "primary_span": diagnostic.primary_span.map(span_summary),
        "related_spans": diagnostic
            .related_spans
            .iter()
            .map(|span| json!({ "label": span.label.as_str(), "span": span_summary(span.span) }))
            .collect::<Vec<_>>(),
        "help": diagnostic.help.as_deref(),
        "unknown_reasons": &diagnostic.unknown_reasons,
    })
}

fn span_summary(span: Span) -> Value {
    json!({
        "file_id": span.file_id,
        "start": {
            "line": span.start.line,
            "column": span.start.column,
            "offset": span.start.offset,
        },
        "end": {
            "line": span.end.line,
            "column": span.end.column,
            "offset": span.end.offset,
        },
    })
}

fn ide_project_summary(run: &plsql_engine::AnalysisRun) -> Value {
    let mut nodes: Vec<_> = run.dep_graph.nodes.values().collect();
    nodes.sort_by(|a, b| a.logical_id.as_str().cmp(b.logical_id.as_str()));
    let definitions: Vec<Value> = nodes
        .iter()
        .take(IDE_LIST_LIMIT)
        .map(|node| {
            json!({
                "node_id": node.id.get(),
                "logical_id": node.logical_id.as_str(),
                "kind": node.identity_kind.as_str(),
                "revision_id": node.revision_id.as_str(),
            })
        })
        .collect();

    let mut edges: Vec<_> = run.dep_graph.edges.iter().collect();
    edges.sort_by_key(|edge| edge.id.get());
    let dependencies: Vec<Value> = edges
        .iter()
        .take(IDE_LIST_LIMIT)
        .map(|edge| {
            let provenance = run.dep_graph.provenance.get(&edge.id);
            json!({
                "edge_id": edge.id.get(),
                "from": graph_node_name(run, edge.from),
                "to": graph_node_name(run, edge.to),
                "kind": edge.kind.as_str(),
                "confidence": &edge.confidence,
                "resolution_strategy": provenance.map(|p| p.resolution_strategy.as_str()),
                "span": provenance.map(|p| span_summary(p.span)),
                "notes": provenance.map(|p| p.notes.clone()).unwrap_or_default(),
                "has_evidence": run.dep_graph.evidence.contains_key(&edge.id),
            })
        })
        .collect();

    let mut declaration_facts = Vec::new();
    let mut reference_facts = Vec::new();
    let mut dependency_facts = Vec::new();
    for fact in &run.fact_store.facts {
        match &fact.payload {
            FactPayload::Declaration { decl, logical_id } => {
                if declaration_facts.len() < IDE_LIST_LIMIT {
                    declaration_facts.push(json!({
                        "fact_id": fact.id.0.as_str(),
                        "decl_id": decl.get(),
                        "logical_id": logical_id,
                        "source_file": fact.provenance.source_file.as_deref(),
                        "source_logical_id": fact.provenance.source_logical_id.as_deref(),
                    }));
                }
            }
            FactPayload::Reference {
                from_decl,
                to_logical_id,
            } => {
                if reference_facts.len() < IDE_LIST_LIMIT {
                    reference_facts.push(json!({
                        "fact_id": fact.id.0.as_str(),
                        "from_decl": from_decl.get(),
                        "to_logical_id": to_logical_id,
                        "source_file": fact.provenance.source_file.as_deref(),
                        "source_logical_id": fact.provenance.source_logical_id.as_deref(),
                    }));
                }
            }
            // The length-guard is the match arm's guard (clippy::collapsible_match):
            // when the sample is full the guard fails and a DependencyEdge — matching
            // no other arm — falls through to `_ => {}`, exactly the no-op the inner
            // `if` produced before. Behavior-preserving.
            FactPayload::DependencyEdge {
                from_logical_id,
                to_logical_id,
                edge_kind,
            } if dependency_facts.len() < IDE_LIST_LIMIT => {
                dependency_facts.push(json!({
                    "fact_id": fact.id.0.as_str(),
                    "from": from_logical_id,
                    "to": to_logical_id,
                    "kind": edge_kind,
                    "source_file": fact.provenance.source_file.as_deref(),
                    "source_logical_id": fact.provenance.source_logical_id.as_deref(),
                }));
            }
            _ => {}
        }
    }

    json!({
        "definition_count": run.dep_graph.node_count(),
        "dependency_count": run.dep_graph.edge_count(),
        "definition_sample": definitions,
        "dependency_sample": dependencies,
        "fact_sample": {
            "declarations": declaration_facts,
            "references": reference_facts,
            "dependency_edges": dependency_facts,
        },
        "truncated": run.dep_graph.node_count() > IDE_LIST_LIMIT
            || run.dep_graph.edge_count() > IDE_LIST_LIMIT
            || run.fact_store.facts.len() > IDE_LIST_LIMIT,
    })
}

fn graph_node_name(run: &plsql_engine::AnalysisRun, node_id: NodeId) -> String {
    run.dep_graph
        .nodes
        .get(&node_id)
        .map(|node| node.logical_id.to_string())
        .unwrap_or_else(|| format!("node:{}", node_id.get()))
}

fn run_what_breaks(args: WhatBreaksArgs) -> Result<Value, ErrorEnvelope> {
    let mode = parse_predict_mode(args.mode.as_deref(), PredictMode::CatalogAware)?;
    let prediction = predict(&args.changeset, mode);
    serde_json::to_value(change_impact_envelope(&prediction, Vec::new())).map_err(json_error)
}

fn run_lineage(args: LineageArgs) -> Result<Value, ErrorEnvelope> {
    let run = analyze_local_project(&args.project_root)?;
    let wrapped_source = target_has_wrapped_source(&args.project_root, &args.target);
    let selector = NodeSelector::LogicalObjectId(args.target.clone());
    let Ok(node) = run.dep_graph.resolve_node(&selector) else {
        let mut available_nodes: Vec<String> = run
            .dep_graph
            .nodes
            .values()
            .map(|node| node.logical_id.to_string())
            .collect();
        available_nodes.sort();
        available_nodes.truncate(25);
        let mut value = json!({
            "target": args.target,
            "found": false,
            "available_node_sample": available_nodes,
            "graph": {
                "node_count": run.dep_graph.node_count(),
                "edge_count": run.dep_graph.edge_count(),
            },
        });
        if wrapped_source {
            mark_wrapped_source_partial(&mut value, &args.target);
        }
        return Ok(value);
    };

    let direction = parse_lineage_direction(args.direction.as_deref())?;
    let mut value = match direction {
        LineageDirection::Downstream => {
            json!({ "target": args.target, "found": true, "direction": "downstream", "result": impact(&run.dep_graph, &node.id, args.max_depth) })
        }
        LineageDirection::Upstream => {
            json!({ "target": args.target, "found": true, "direction": "upstream", "result": dependencies(&run.dep_graph, &node.id, args.max_depth) })
        }
        LineageDirection::Bidirectional => {
            json!({
                "target": args.target,
                "found": true,
                "direction": "bidirectional",
                "downstream": impact(&run.dep_graph, &node.id, args.max_depth),
                "upstream": dependencies(&run.dep_graph, &node.id, args.max_depth),
            })
        }
    };
    if wrapped_source {
        mark_wrapped_source_partial(&mut value, &args.target);
    }
    Ok(value)
}

const WRAPPED_SOURCE_UNKNOWN_REASON: &str = "WrappedSource";
const WRAPPED_SOURCE_DETAIL: &str =
    "Wrapped or obfuscated PL/SQL source prevents complete source-only lineage.";

/// Return whether a wrapped body in the project belongs to the requested target.
///
/// This deliberately uses the engine family's header-shaped detector rather than
/// parsing the opaque body. A wrapped body proves only that a gap exists; it
/// cannot prove any dependency edge.
fn target_has_wrapped_source(project_root: &str, target: &str) -> bool {
    let project_root = Path::new(project_root);
    let Ok(manifest) = plsql_project::ProjectManifest::load(project_root) else {
        return false;
    };
    let Ok(source_files) = plsql_project::discover_files(project_root, &manifest) else {
        return false;
    };
    source_files.into_iter().any(|source_file| {
        std::fs::read_to_string(project_root.join(source_file.relative_path))
            .ok()
            .is_some_and(|source| {
                plsql_project::looks_wrapped(&source)
                    && wrapped_source_declares_target(&source, target)
            })
    })
}

fn wrapped_source_declares_target(source: &str, target: &str) -> bool {
    let scan_window = source.get(..4096).unwrap_or(source);
    scan_window.lines().take(64).any(|line| {
        let tokens: Vec<&str> = line
            .trim()
            .trim_end_matches(';')
            .split_whitespace()
            .collect();
        let Some(last) = tokens.last() else {
            return false;
        };
        if !last.eq_ignore_ascii_case("wrapped") {
            return false;
        }

        let object_position = tokens.iter().position(|token| {
            matches!(
                token.to_ascii_uppercase().as_str(),
                "PACKAGE" | "FUNCTION" | "PROCEDURE" | "TRIGGER" | "TYPE" | "LIBRARY"
            )
        });
        let Some(object_position) = object_position else {
            return false;
        };
        let object_name_position = if tokens[object_position].eq_ignore_ascii_case("package")
            || tokens[object_position].eq_ignore_ascii_case("type")
        {
            if tokens
                .get(object_position + 1)
                .is_some_and(|token| token.eq_ignore_ascii_case("body"))
            {
                object_position + 2
            } else {
                object_position + 1
            }
        } else {
            object_position + 1
        };
        let Some(object_name) = tokens.get(object_name_position) else {
            return false;
        };
        lineage_object_name_matches(object_name, target)
    })
}

fn lineage_object_name_matches(header_name: &str, target: &str) -> bool {
    let header_name = header_name
        .split('(')
        .next()
        .unwrap_or(header_name)
        .trim_matches('"');
    let target = target.trim().trim_matches('"');
    if header_name.eq_ignore_ascii_case(target) {
        return true;
    }
    // A source header that explicitly names an owner is evidence only for that
    // owner. Falling back to the last segment is useful for callers who ask
    // for an unqualified local object, but must not turn APP.PKG into a marker
    // for OTHER.PKG.
    if header_name.contains('.') && target.contains('.') {
        return false;
    }
    header_name.rsplit('.').next().is_some_and(|header| {
        target
            .rsplit('.')
            .next()
            .is_some_and(|target| header.trim_matches('"').eq_ignore_ascii_case(target))
    })
}

fn mark_wrapped_source_partial(value: &mut Value, target: &str) {
    let marker = json!({
        "source": target,
        "unknown_reason": WRAPPED_SOURCE_UNKNOWN_REASON,
        "detail": WRAPPED_SOURCE_DETAIL,
    });
    let Some(root) = value.as_object_mut() else {
        return;
    };
    root.insert("lineage_completeness".to_owned(), json!("partial"));
    root.insert(
        "partial_lineage_marker".to_owned(),
        json!({
            "reason": WRAPPED_SOURCE_UNKNOWN_REASON,
            "detail": WRAPPED_SOURCE_DETAIL,
        }),
    );
    if let Some(result) = root.get_mut("result") {
        append_wrapped_source_unknown_edge(result, marker.clone());
    }
    for direction in ["upstream", "downstream"] {
        if let Some(result) = root.get_mut(direction) {
            append_wrapped_source_unknown_edge(result, marker.clone());
        }
    }
    if !root.contains_key("result") && !root.contains_key("upstream") {
        root.insert("unknown_edges".to_owned(), json!([marker]));
    }
}

fn append_wrapped_source_unknown_edge(result: &mut Value, marker: Value) {
    let Some(result) = result.as_object_mut() else {
        return;
    };
    let Some(unknown_edges) = result
        .entry("unknown_edges".to_owned())
        .or_insert_with(|| json!([]))
        .as_array_mut()
    else {
        return;
    };
    unknown_edges.push(marker);
    result.insert("partial".to_owned(), json!(true));
}

/// The logical id a column node carries, as `owner.object.column` (the depgraph
/// lowercases these). Built from the requested arguments so a caller-supplied
/// name is compared against the graph in the graph's own canonical form.
fn column_logical_id(owner: Option<&str>, object: &str, column: &str) -> String {
    match owner {
        Some(owner) => format!("{owner}.{object}.{column}"),
        None => format!("{object}.{column}"),
    }
}

/// Find the column node whose logical id matches the requested column.
///
/// An exact `owner.object.column` match wins. With no owner supplied, any column
/// whose logical id ends in `.object.column` (or equals `object.column`) matches,
/// so a project without schema-qualified names still resolves. The comparison is
/// case-insensitive because the depgraph canonicalizes identifiers to lowercase
/// while an operator may type them in any case.
fn resolve_column_node<'a>(
    graph: &'a DepGraph,
    owner: Option<&str>,
    object: &str,
    column: &str,
) -> Option<&'a Node> {
    let exact = column_logical_id(owner, object, column).to_ascii_lowercase();
    let suffix = format!(
        ".{}",
        column_logical_id(None, object, column).to_ascii_lowercase()
    );
    graph
        .nodes
        .values()
        .filter(|node| matches!(node.identity_kind, NodeIdentityKind::Column))
        .find(|node| {
            let logical = node.logical_id.as_str().to_ascii_lowercase();
            logical == exact
                || (owner.is_none() && (logical == exact || logical.ends_with(&suffix)))
        })
}

/// Render one column-access result (readers or writers) as the redacted,
/// source-derived edge list the tool returns. Each edge is the accessing object,
/// how it touches the column, and the depgraph's confidence — never any literal
/// value or bind, only object/column identifiers already present in the source.
#[cfg(test)]
fn column_edges_json(result: &plsql_lineage::ColumnAccessResult) -> Value {
    let edges: Vec<Value> = result
        .accessors
        .iter()
        .map(|accessor| {
            json!({
                "object": accessor.accessor_logical_id,
                "edge_kind": accessor.edge_kind,
                "accessor_kind": accessor.accessor_kind,
                "confidence": format!("{:?}", accessor.confidence),
                "is_unknown_column_of_table": accessor.is_unknown_column_of_table,
            })
        })
        .collect();
    json!({
        "column_logical_id": result.column_logical_id,
        "edges": edges,
        "resolution_error": result.resolution_error,
    })
}

/// `oracle_lineage` — source-derived column lineage.
///
/// Builds the analysis run for the project source, resolves the requested
/// column node, and returns the upstream columns it derives from
/// (`column_writers`: `DerivesColumn`/`WritesColumn`) and the downstream objects
/// that read it (`column_readers`: `ReadsColumn`). Traces a column through a view
/// chain. Purely source-derived — no database round-trip, no literals or binds.
#[cfg(test)]
fn run_column_lineage(args: ColumnLineageArgs) -> Result<Value, ErrorEnvelope> {
    let source_graph = source_derived_column_graph(Path::new(&args.project_root))?;
    let Some(node) = resolve_column_node(
        &source_graph.graph,
        args.owner.as_deref(),
        &args.object,
        &args.column,
    ) else {
        let mut available: Vec<String> = source_graph
            .graph
            .nodes
            .values()
            .filter(|node| matches!(node.identity_kind, NodeIdentityKind::Column))
            .map(|node| node.logical_id.to_string())
            .collect();
        available.sort();
        available.truncate(25);
        return Ok(json!({
            "owner": args.owner,
            "object": args.object,
            "column": args.column,
            "found": false,
            "available_column_sample": available,
            "source_files_scanned": source_graph.source_files_scanned,
            "unsupported_projection_count": source_graph.unsupported_projection_count,
        }));
    };

    // Upstream = what this column is derived from / written by (the view chain
    // above it). Downstream = who reads it. Both are column-level edges.
    let upstream = column_writers(&source_graph.graph, &NodeSelector::NodeId(node.id));
    let downstream = column_readers(&source_graph.graph, &NodeSelector::NodeId(node.id));
    Ok(json!({
        "owner": args.owner,
        "object": args.object,
        "column": args.column,
        "found": true,
        "column_logical_id": node.logical_id.to_string(),
        "upstream": column_edges_json(&upstream),
        "downstream": column_edges_json(&downstream),
        "source_files_scanned": source_graph.source_files_scanned,
        "unsupported_projection_count": source_graph.unsupported_projection_count,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceLineageColumnRef {
    logical_id: String,
    expected_data_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CatalogColumnRef {
    data_type: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LiveCatalogSnapshot {
    columns: BTreeMap<String, CatalogColumnRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CatalogDriftMarker {
    Verified,
    Missing,
    TypeMismatch,
}

impl CatalogDriftMarker {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Missing => "drift:missing",
            Self::TypeMismatch => "drift:type_mismatch",
        }
    }
}

fn classify_catalog_drift(
    source: &SourceLineageColumnRef,
    catalog: &LiveCatalogSnapshot,
) -> CatalogDriftMarker {
    let key = normalize_source_name(&source.logical_id);
    let Some(live) = catalog.columns.get(&key) else {
        return CatalogDriftMarker::Missing;
    };
    if source
        .expected_data_type
        .as_deref()
        .is_some_and(|expected| normalize_data_type(expected) != live.data_type)
    {
        CatalogDriftMarker::TypeMismatch
    } else {
        CatalogDriftMarker::Verified
    }
}

fn catalog_marker_json(source: &SourceLineageColumnRef, catalog: &LiveCatalogSnapshot) -> Value {
    let key = normalize_source_name(&source.logical_id);
    let live = catalog.columns.get(&key);
    json!({
        "status": classify_catalog_drift(source, catalog).as_str(),
        "column_logical_id": source.logical_id,
        "source_data_type": source.expected_data_type,
        "catalog_data_type": live.map(|column| column.data_type.as_str()),
    })
}

fn column_edges_json_with_catalog_markers(
    result: &plsql_lineage::ColumnAccessResult,
    source_graph: &SourceDerivedColumnGraph,
    catalog: &LiveCatalogSnapshot,
) -> Value {
    let edges: Vec<Value> = result
        .accessors
        .iter()
        .map(|accessor| {
            let source = source_graph.column_ref(&accessor.accessor_logical_id);
            json!({
                "object": accessor.accessor_logical_id,
                "edge_kind": accessor.edge_kind,
                "accessor_kind": accessor.accessor_kind,
                "confidence": format!("{:?}", accessor.confidence),
                "is_unknown_column_of_table": accessor.is_unknown_column_of_table,
                "catalog_marker": catalog_marker_json(&source, catalog),
            })
        })
        .collect();
    json!({
        "column_logical_id": result.column_logical_id,
        "edges": edges,
        "resolution_error": result.resolution_error,
    })
}

async fn run_column_lineage_live(
    cx: &Cx,
    conn: &dyn OracleConnection,
    args: ColumnLineageArgs,
) -> Result<Value, ErrorEnvelope> {
    let source_graph = source_derived_column_graph(Path::new(&args.project_root))?;
    let Some(node) = resolve_column_node(
        &source_graph.graph,
        args.owner.as_deref(),
        &args.object,
        &args.column,
    ) else {
        let mut available: Vec<String> = source_graph
            .graph
            .nodes
            .values()
            .filter(|node| matches!(node.identity_kind, NodeIdentityKind::Column))
            .map(|node| node.logical_id.to_string())
            .collect();
        available.sort();
        available.truncate(25);
        return Ok(json!({
            "owner": args.owner,
            "object": args.object,
            "column": args.column,
            "found": false,
            "available_column_sample": available,
            "source_files_scanned": source_graph.source_files_scanned,
            "unsupported_projection_count": source_graph.unsupported_projection_count,
            "catalog_cross_check": { "enabled": true, "catalog_columns_loaded": 0 },
        }));
    };

    let upstream = column_writers(&source_graph.graph, &NodeSelector::NodeId(node.id));
    let downstream = column_readers(&source_graph.graph, &NodeSelector::NodeId(node.id));
    let catalog = live_catalog_snapshot_for_lineage(
        cx,
        conn,
        args.owner.as_deref(),
        Some(node.logical_id.as_str()),
        [&upstream, &downstream],
    )
    .await?;
    let target_ref = source_graph.column_ref(node.logical_id.as_str());
    Ok(json!({
        "owner": args.owner,
        "object": args.object,
        "column": args.column,
        "found": true,
        "column_logical_id": node.logical_id.to_string(),
        "catalog_marker": catalog_marker_json(&target_ref, &catalog),
        "upstream": column_edges_json_with_catalog_markers(&upstream, &source_graph, &catalog),
        "downstream": column_edges_json_with_catalog_markers(&downstream, &source_graph, &catalog),
        "source_files_scanned": source_graph.source_files_scanned,
        "unsupported_projection_count": source_graph.unsupported_projection_count,
        "catalog_cross_check": {
            "enabled": true,
            "catalog_columns_loaded": catalog.columns.len(),
        },
    }))
}

async fn live_catalog_snapshot_for_lineage(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner_hint: Option<&str>,
    target_column: Option<&str>,
    results: [&plsql_lineage::ColumnAccessResult; 2],
) -> Result<LiveCatalogSnapshot, ErrorEnvelope> {
    let mut objects = BTreeSet::new();
    if let Some(target_column) = target_column
        && let Some((owner, object, _)) = split_lineage_column_id(target_column, owner_hint)
    {
        objects.insert((owner, object));
    }
    for result in results {
        for accessor in &result.accessors {
            if let Some((owner, object, _)) =
                split_lineage_column_id(&accessor.accessor_logical_id, owner_hint)
            {
                objects.insert((owner, object));
            }
        }
    }

    let mut snapshot = LiveCatalogSnapshot::default();
    for (owner, object) in objects {
        for row in run_catalog_query(
            cx,
            conn,
            CatalogQueryId::LineageColumns,
            &[
                OracleBind::from(owner.clone()),
                OracleBind::from(object.clone()),
            ],
        )
        .await
        .map_err(DbError::into_envelope)?
        {
            let Some(column_name) = row.text("COLUMN_NAME") else {
                continue;
            };
            let Some(data_type) = row.text("DATA_TYPE") else {
                continue;
            };
            let logical_id = column_logical_id(Some(&owner), &object, column_name);
            snapshot.columns.insert(
                normalize_source_name(&logical_id),
                CatalogColumnRef {
                    data_type: normalize_data_type(data_type),
                },
            );
        }
    }
    Ok(snapshot)
}

fn split_lineage_column_id(
    logical_id: &str,
    owner_hint: Option<&str>,
) -> Option<(String, String, String)> {
    let parts: Vec<&str> = logical_id
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    match parts.as_slice() {
        [owner, object, column] => Some((
            owner.to_ascii_uppercase(),
            object.to_ascii_uppercase(),
            column.to_ascii_uppercase(),
        )),
        [object, column] => owner_hint.map(|owner| {
            (
                owner.to_ascii_uppercase(),
                object.to_ascii_uppercase(),
                column.to_ascii_uppercase(),
            )
        }),
        _ => None,
    }
}

const MAX_SOURCE_LINEAGE_FILES: usize = 2_048;
const MAX_SOURCE_LINEAGE_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// A small, deliberately conservative source overlay for the column edge kinds
/// the engine's object graph does not yet emit. The graph contains no database
/// facts: every node and edge comes from a `CREATE TABLE` or `CREATE VIEW`
/// declaration under the requested local project root.
#[derive(Default)]
struct SourceDerivedColumnGraph {
    graph: DepGraph,
    column_nodes: BTreeMap<String, NodeId>,
    object_columns: BTreeMap<String, BTreeSet<String>>,
    column_types: BTreeMap<String, String>,
    edge_keys: BTreeSet<(String, String, &'static str)>,
    next_node_id: u64,
    next_edge_id: u64,
    source_files_scanned: usize,
    unsupported_projection_count: usize,
}

impl SourceDerivedColumnGraph {
    fn ensure_column(&mut self, logical_id: String) -> NodeId {
        let logical_id = normalize_source_name(&logical_id);
        if let Some(node_id) = self.column_nodes.get(&logical_id) {
            return *node_id;
        }

        self.next_node_id += 1;
        let node_id = NodeId::new(self.next_node_id);
        self.graph.insert_node(Node::new(
            node_id,
            LogicalObjectId::new(logical_id.clone()),
            ObjectRevisionId::new("source-derived"),
            Default::default(),
            NodeIdentityKind::Column,
        ));
        if let Some((object, column)) = logical_id.rsplit_once('.') {
            self.object_columns
                .entry(object.to_owned())
                .or_default()
                .insert(column.to_owned());
        }
        self.column_nodes.insert(logical_id, node_id);
        node_id
    }

    fn insert_projection_edge(&mut self, source: &str, target: &str, kind: EdgeKind) {
        let kind_name = kind.as_str();
        let key = (source.to_owned(), target.to_owned(), kind_name);
        if !self.edge_keys.insert(key) {
            return;
        }

        let source = self.ensure_column(source.to_owned());
        let target = self.ensure_column(target.to_owned());
        self.next_edge_id += 1;
        self.graph.insert_edge(
            Edge::new(
                EdgeId::new(self.next_edge_id),
                source,
                target,
                kind,
                Confidence::new(
                    ConfidenceLevel::High,
                    Some("exact source-derived view projection".to_owned()),
                ),
            ),
            Provenance::new(
                FileId::new(0),
                Span::default(),
                ResolutionStrategy::LocalLexical,
            )
            .with_note("source-derived column lineage"),
            None,
        );
    }

    fn add_table(&mut self, table: &SourceTable) {
        for column in &table.columns {
            let logical_id = format!("{}.{}", table.object, column.name);
            self.ensure_column(logical_id.clone());
            if let Some(data_type) = &column.data_type {
                self.column_types
                    .insert(normalize_source_name(&logical_id), data_type.clone());
            }
        }
    }

    fn add_view_columns(&mut self, view: &SourceView) {
        for (index, projection) in view.projections.iter().enumerate() {
            if let Some((column, _)) = projection_output_column(
                projection,
                view.declared_columns.get(index).map(String::as_str),
            ) {
                self.ensure_column(format!("{}.{}", view.object, column));
            } else {
                self.unsupported_projection_count += 1;
            }
        }
    }

    fn add_view_edges(&mut self, view: &SourceView) {
        for (index, projection) in view.projections.iter().enumerate() {
            let Some((output_column, expression)) = projection_output_column(
                projection,
                view.declared_columns.get(index).map(String::as_str),
            ) else {
                continue;
            };
            let target = format!("{}.{}", view.object, output_column);
            for source in self.projection_sources(expression, &view.sources) {
                // The lineage helpers use incoming edges: source -> target is
                // the upstream derivation, while the inverse `ReadsColumn`
                // edge makes the consumer visible from the source column.
                self.insert_projection_edge(&source, &target, EdgeKind::DerivesColumn);
                self.insert_projection_edge(&target, &source, EdgeKind::ReadsColumn);
                if let Some(data_type) = self
                    .column_types
                    .get(&normalize_source_name(&source))
                    .cloned()
                {
                    self.column_types
                        .insert(normalize_source_name(&target), data_type);
                }
            }
        }
    }

    fn projection_sources(
        &mut self,
        expression: &[SourceToken],
        sources: &[SourceRelation],
    ) -> Vec<String> {
        let Some(parts) = source_identifier_parts(expression) else {
            return source_identifiers_in_expression(expression, sources, self);
        };
        if parts.last().is_some_and(|part| part == "*") {
            return self.expand_star(&parts, sources);
        }
        self.resolve_column_reference(&parts, sources)
            .into_iter()
            .collect()
    }

    fn expand_star(&self, parts: &[String], sources: &[SourceRelation]) -> Vec<String> {
        let relations: Vec<&SourceRelation> = if parts.len() == 1 {
            sources.iter().collect()
        } else {
            self.relation_for_reference(&parts[..parts.len() - 1], sources)
                .into_iter()
                .collect()
        };
        let mut columns = BTreeSet::new();
        for relation in relations {
            if let Some(known_columns) = self.object_columns.get(&relation.object) {
                columns.extend(
                    known_columns
                        .iter()
                        .map(|column| format!("{}.{}", relation.object, column)),
                );
            }
        }
        columns.into_iter().collect()
    }

    fn resolve_column_reference(
        &self,
        parts: &[String],
        sources: &[SourceRelation],
    ) -> Option<String> {
        let column = parts.last()?.clone();
        if parts.len() > 1 {
            let relation = self.relation_for_reference(&parts[..parts.len() - 1], sources)?;
            return Some(format!("{}.{}", relation.object, column));
        }

        let matching_relations: Vec<&SourceRelation> = sources
            .iter()
            .filter(|relation| {
                self.object_columns
                    .get(&relation.object)
                    .is_some_and(|columns| columns.contains(&column))
            })
            .collect();
        if matching_relations.len() == 1 {
            return Some(format!("{}.{}", matching_relations[0].object, column));
        }
        (sources.len() == 1).then(|| format!("{}.{}", sources[0].object, column))
    }

    fn relation_for_reference<'a>(
        &self,
        reference: &[String],
        sources: &'a [SourceRelation],
    ) -> Option<&'a SourceRelation> {
        let reference = reference.join(".");
        sources.iter().find(|relation| {
            relation
                .alias
                .as_deref()
                .is_some_and(|alias| alias == reference)
                || relation.object == reference
                || relation
                    .object
                    .rsplit_once('.')
                    .is_some_and(|(_, object)| object == reference)
        })
    }

    fn column_ref(&self, logical_id: &str) -> SourceLineageColumnRef {
        let logical_id = normalize_source_name(logical_id);
        SourceLineageColumnRef {
            expected_data_type: self.column_types.get(&logical_id).cloned(),
            logical_id,
        }
    }
}

#[derive(Clone, Debug)]
struct SourceTable {
    object: String,
    columns: Vec<SourceColumn>,
}

#[derive(Clone, Debug)]
struct SourceColumn {
    name: String,
    data_type: Option<String>,
}

#[derive(Clone, Debug)]
struct SourceView {
    object: String,
    declared_columns: Vec<String>,
    projections: Vec<Vec<SourceToken>>,
    sources: Vec<SourceRelation>,
}

#[derive(Clone, Debug)]
struct SourceRelation {
    object: String,
    alias: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SourceToken {
    Word(String),
    Punctuation(char),
}

fn source_derived_column_graph(
    project_root: &Path,
) -> Result<SourceDerivedColumnGraph, ErrorEnvelope> {
    let source_files = source_lineage_files(project_root)?;
    let mut graph = SourceDerivedColumnGraph::default();
    let mut tables = Vec::new();
    let mut views = Vec::new();

    for source_file in source_files {
        let size = std::fs::metadata(&source_file)
            .map_err(|_| source_lineage_error("could not inspect a source file"))?
            .len();
        if size > MAX_SOURCE_LINEAGE_FILE_BYTES {
            return Err(source_lineage_error(
                "a source file exceeds the safe source-lineage size limit",
            ));
        }
        let source = std::fs::read_to_string(&source_file)
            .map_err(|_| source_lineage_error("could not read a source file as UTF-8"))?;
        let (file_tables, file_views) = parse_source_declarations(&source_tokens(&source));
        tables.extend(file_tables);
        views.extend(file_views);
        graph.source_files_scanned += 1;
    }

    for table in &tables {
        graph.add_table(table);
    }
    // Declare every view output before resolving a projection. This permits a
    // deterministic view chain even if the source files are not ordered.
    for view in &views {
        graph.add_view_columns(view);
    }
    for view in &views {
        graph.add_view_edges(view);
    }
    Ok(graph)
}

fn source_lineage_files(project_root: &Path) -> Result<Vec<PathBuf>, ErrorEnvelope> {
    if !project_root.exists() {
        return Err(source_lineage_error("project_root does not exist"));
    }
    let mut files = Vec::new();
    if project_root.is_file() {
        if is_source_lineage_file(project_root) {
            files.push(project_root.to_owned());
        }
    } else {
        collect_source_lineage_files(project_root, &mut files)?;
    }
    files.sort();
    Ok(files)
}

fn collect_source_lineage_files(
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), ErrorEnvelope> {
    for entry in std::fs::read_dir(directory)
        .map_err(|_| source_lineage_error("could not enumerate the project source tree"))?
    {
        let entry = entry.map_err(|_| source_lineage_error("could not inspect a source entry"))?;
        let file_type = entry
            .file_type()
            .map_err(|_| source_lineage_error("could not inspect a source entry type"))?;
        if file_type.is_dir() {
            collect_source_lineage_files(&entry.path(), files)?;
        } else if file_type.is_file() && is_source_lineage_file(&entry.path()) {
            files.push(entry.path());
            if files.len() > MAX_SOURCE_LINEAGE_FILES {
                return Err(source_lineage_error(
                    "project exceeds the safe source-lineage file-count limit",
                ));
            }
        }
    }
    Ok(())
}

fn is_source_lineage_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "sql" | "pls" | "plsql" | "pkb" | "pks"
            )
        })
}

fn source_lineage_error(message: &str) -> ErrorEnvelope {
    ErrorEnvelope::new(ErrorClass::RuntimeStateRequired, message)
}

fn source_tokens(source: &str) -> Vec<SourceToken> {
    let mut tokens = Vec::new();
    let mut chars = source.chars().peekable();
    while let Some(character) = chars.next() {
        if character.is_whitespace() {
            continue;
        }
        if character == '-' && chars.peek() == Some(&'-') {
            chars.next();
            while chars.next().is_some_and(|next| next != '\n') {}
            continue;
        }
        if character == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut previous = '\0';
            for next in chars.by_ref() {
                if previous == '*' && next == '/' {
                    break;
                }
                previous = next;
            }
            continue;
        }
        if character == '\'' {
            while let Some(next) = chars.next() {
                if next == '\'' && chars.peek() != Some(&'\'') {
                    break;
                }
                if next == '\'' {
                    chars.next();
                }
            }
            continue;
        }
        if character == '"' {
            let mut quoted = String::new();
            while let Some(next) = chars.next() {
                if next == '"' && chars.peek() != Some(&'"') {
                    break;
                }
                if next == '"' {
                    chars.next();
                }
                quoted.push(next);
            }
            if !quoted.is_empty() {
                tokens.push(SourceToken::Word(normalize_source_name(&quoted)));
            }
            continue;
        }
        if matches!(character, '(' | ')' | ',' | '.' | ';' | '*') {
            tokens.push(SourceToken::Punctuation(character));
            continue;
        }
        if is_source_identifier_character(character) {
            let mut word = String::from(character);
            while chars
                .peek()
                .is_some_and(|next| is_source_identifier_character(*next))
            {
                word.push(chars.next().expect("peeked source identifier character"));
            }
            tokens.push(SourceToken::Word(normalize_source_name(&word)));
        }
    }
    tokens
}

fn is_source_identifier_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '$' | '#')
}

fn parse_source_declarations(tokens: &[SourceToken]) -> (Vec<SourceTable>, Vec<SourceView>) {
    let mut tables = Vec::new();
    let mut views = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if !token_is_word(tokens.get(index), "create") {
            index += 1;
            continue;
        }
        let mut declaration = index + 1;
        if token_is_word(tokens.get(declaration), "or")
            && token_is_word(tokens.get(declaration + 1), "replace")
        {
            declaration += 2;
        }
        while matches!(
            token_word(tokens.get(declaration)),
            Some("force" | "noforce" | "editioning" | "global" | "temporary")
        ) {
            declaration += 1;
        }
        if token_is_word(tokens.get(declaration), "table") {
            if let Some((table, end)) = parse_source_table(tokens, declaration + 1) {
                tables.push(table);
                index = end;
                continue;
            }
        } else if token_is_word(tokens.get(declaration), "view")
            && let Some((view, end)) = parse_source_view(tokens, declaration + 1)
        {
            views.push(view);
            index = end;
            continue;
        }
        index += 1;
    }
    (tables, views)
}

fn parse_source_table(tokens: &[SourceToken], mut index: usize) -> Option<(SourceTable, usize)> {
    let object = take_source_qualified_name(tokens, &mut index)?;
    while !token_is_punctuation(tokens.get(index), '(')
        && !token_is_punctuation(tokens.get(index), ';')
    {
        index += 1;
    }
    if !token_is_punctuation(tokens.get(index), '(') {
        return None;
    }
    let end = matching_source_parenthesis(tokens, index)?;
    let columns = split_source_top_level(&tokens[index + 1..end], ',')
        .into_iter()
        .filter_map(|definition| match definition.first() {
            Some(SourceToken::Word(column)) if !is_table_constraint_keyword(column) => {
                Some(SourceColumn {
                    name: column.clone(),
                    data_type: token_word(definition.get(1)).map(normalize_data_type),
                })
            }
            _ => None,
        })
        .collect();
    Some((SourceTable { object, columns }, end + 1))
}

fn parse_source_view(tokens: &[SourceToken], mut index: usize) -> Option<(SourceView, usize)> {
    let object = take_source_qualified_name(tokens, &mut index)?;
    let mut declared_columns = Vec::new();
    if token_is_punctuation(tokens.get(index), '(') {
        let end = matching_source_parenthesis(tokens, index)?;
        declared_columns = split_source_top_level(&tokens[index + 1..end], ',')
            .into_iter()
            .filter_map(|column| match column.first() {
                Some(SourceToken::Word(column)) => Some(column.clone()),
                _ => None,
            })
            .collect();
        index = end + 1;
    }
    while !token_is_word(tokens.get(index), "as") && !token_is_punctuation(tokens.get(index), ';') {
        index += 1;
    }
    if !token_is_word(tokens.get(index), "as") {
        return None;
    }
    index += 1;
    while !token_is_word(tokens.get(index), "select")
        && !token_is_punctuation(tokens.get(index), ';')
    {
        index += 1;
    }
    if !token_is_word(tokens.get(index), "select") {
        return None;
    }
    let select_start = index + 1;
    let from_index = find_source_top_level_word(tokens, select_start, "from")?;
    let statement_end = find_source_statement_end(tokens, from_index + 1);
    let projections = split_source_top_level(&tokens[select_start..from_index], ',');
    let sources = parse_source_relations(&tokens[from_index + 1..statement_end]);
    Some((
        SourceView {
            object,
            declared_columns,
            projections,
            sources,
        },
        statement_end + 1,
    ))
}

fn take_source_qualified_name(tokens: &[SourceToken], index: &mut usize) -> Option<String> {
    let mut parts = vec![token_word(tokens.get(*index))?.to_owned()];
    *index += 1;
    while token_is_punctuation(tokens.get(*index), '.') {
        *index += 1;
        parts.push(token_word(tokens.get(*index))?.to_owned());
        *index += 1;
    }
    Some(parts.join("."))
}

fn matching_source_parenthesis(tokens: &[SourceToken], open: usize) -> Option<usize> {
    let mut depth = 0_u32;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token {
            SourceToken::Punctuation('(') => depth += 1,
            SourceToken::Punctuation(')') => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn find_source_top_level_word(tokens: &[SourceToken], start: usize, wanted: &str) -> Option<usize> {
    let mut depth = 0_u32;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token {
            SourceToken::Punctuation('(') => depth += 1,
            SourceToken::Punctuation(')') => depth = depth.saturating_sub(1),
            _ if depth == 0 && token_is_word(Some(token), wanted) => return Some(index),
            _ => {}
        }
    }
    None
}

fn find_source_statement_end(tokens: &[SourceToken], start: usize) -> usize {
    let mut depth = 0_u32;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token {
            SourceToken::Punctuation('(') => depth += 1,
            SourceToken::Punctuation(')') => depth = depth.saturating_sub(1),
            SourceToken::Punctuation(';') if depth == 0 => return index,
            _ => {}
        }
    }
    tokens.len()
}

fn split_source_top_level(tokens: &[SourceToken], separator: char) -> Vec<Vec<SourceToken>> {
    let mut pieces = Vec::new();
    let mut current = Vec::new();
    let mut depth = 0_u32;
    for token in tokens {
        match token {
            SourceToken::Punctuation('(') => depth += 1,
            SourceToken::Punctuation(')') => depth = depth.saturating_sub(1),
            SourceToken::Punctuation(character) if *character == separator && depth == 0 => {
                if !current.is_empty() {
                    pieces.push(std::mem::take(&mut current));
                }
                continue;
            }
            _ => {}
        }
        current.push(token.clone());
    }
    if !current.is_empty() {
        pieces.push(current);
    }
    pieces
}

fn parse_source_relations(tokens: &[SourceToken]) -> Vec<SourceRelation> {
    let mut relations = Vec::new();
    let mut index = 0;
    let mut expect_relation = true;
    while index < tokens.len() {
        if token_is_source_clause_boundary(tokens.get(index)) {
            break;
        }
        if expect_relation {
            if token_is_punctuation(tokens.get(index), '(') {
                if let Some(end) = matching_source_parenthesis(tokens, index) {
                    index = end + 1;
                } else {
                    break;
                }
                expect_relation = false;
                continue;
            }
            let mut relation_index = index;
            let Some(object) = take_source_qualified_name(tokens, &mut relation_index) else {
                index += 1;
                continue;
            };
            let mut alias = None;
            if token_is_word(tokens.get(relation_index), "as") {
                relation_index += 1;
                alias = token_word(tokens.get(relation_index)).map(str::to_owned);
                relation_index += usize::from(alias.is_some());
            } else if let Some(candidate) = token_word(tokens.get(relation_index))
                && !is_source_relation_keyword(candidate)
            {
                alias = Some(candidate.to_owned());
                relation_index += 1;
            }
            relations.push(SourceRelation { object, alias });
            index = relation_index;
            expect_relation = false;
            continue;
        }
        if token_is_punctuation(tokens.get(index), ',') || token_is_word(tokens.get(index), "join")
        {
            expect_relation = true;
        }
        index += 1;
    }
    relations
}

fn projection_output_column<'a>(
    projection: &'a [SourceToken],
    declared_column: Option<&str>,
) -> Option<(String, &'a [SourceToken])> {
    if let Some(declared_column) = declared_column {
        return Some((normalize_source_name(declared_column), projection));
    }
    let as_index = projection
        .iter()
        .rposition(|token| token_is_word(Some(token), "as"));
    if let Some(as_index) = as_index
        && let Some(alias) = token_word(projection.get(as_index + 1))
    {
        return Some((alias.to_owned(), &projection[..as_index]));
    }
    let parts = source_identifier_parts(projection)?;
    (parts.last() != Some(&"*".to_owned())).then(|| {
        let column = parts.last().cloned().expect("non-empty source identifier");
        (column, projection)
    })
}

fn source_identifier_parts(tokens: &[SourceToken]) -> Option<Vec<String>> {
    if tokens.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    let mut needs_word = true;
    for token in tokens {
        match (needs_word, token) {
            (true, SourceToken::Word(word)) => {
                parts.push(word.clone());
                needs_word = false;
            }
            (true, SourceToken::Punctuation('*')) => {
                parts.push("*".to_owned());
                needs_word = false;
            }
            (false, SourceToken::Punctuation('.')) => needs_word = true,
            (false, SourceToken::Punctuation('*')) if !parts.is_empty() => {
                parts.push("*".to_owned());
                needs_word = false;
            }
            _ => return None,
        }
    }
    (!needs_word).then_some(parts)
}

fn source_identifiers_in_expression(
    tokens: &[SourceToken],
    sources: &[SourceRelation],
    graph: &SourceDerivedColumnGraph,
) -> Vec<String> {
    let mut columns = BTreeSet::new();
    let mut index = 0;
    while index < tokens.len() {
        let Some(word) = token_word(tokens.get(index)) else {
            index += 1;
            continue;
        };
        if is_source_expression_keyword(word) || token_is_punctuation(tokens.get(index + 1), '(') {
            index += 1;
            continue;
        }
        let mut end = index + 1;
        let mut parts = vec![word.to_owned()];
        while token_is_punctuation(tokens.get(end), '.') {
            let Some(next) = token_word(tokens.get(end + 1)) else {
                break;
            };
            parts.push(next.to_owned());
            end += 2;
        }
        if let Some(column) = graph.resolve_column_reference(&parts, sources) {
            columns.insert(column);
        }
        index = end;
    }
    columns.into_iter().collect()
}

fn token_word(token: Option<&SourceToken>) -> Option<&str> {
    match token {
        Some(SourceToken::Word(word)) => Some(word),
        _ => None,
    }
}

fn token_is_word(token: Option<&SourceToken>, wanted: &str) -> bool {
    token_word(token).is_some_and(|word| word == wanted)
}

fn token_is_punctuation(token: Option<&SourceToken>, wanted: char) -> bool {
    matches!(token, Some(SourceToken::Punctuation(character)) if *character == wanted)
}

fn normalize_source_name(value: &str) -> String {
    value.trim().trim_matches('"').to_ascii_lowercase()
}

fn normalize_data_type(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn is_table_constraint_keyword(word: &str) -> bool {
    matches!(
        word,
        "constraint" | "primary" | "foreign" | "unique" | "check" | "supplemental" | "period"
    )
}

fn token_is_source_clause_boundary(token: Option<&SourceToken>) -> bool {
    matches!(
        token_word(token),
        Some(
            "where"
                | "group"
                | "having"
                | "order"
                | "connect"
                | "start"
                | "union"
                | "minus"
                | "intersect"
                | "fetch"
                | "offset"
                | "for"
                | "model"
        )
    )
}

fn is_source_relation_keyword(word: &str) -> bool {
    matches!(
        word,
        "on" | "join"
            | "inner"
            | "left"
            | "right"
            | "full"
            | "cross"
            | "outer"
            | "where"
            | "group"
            | "having"
            | "order"
            | "connect"
            | "start"
            | "union"
            | "minus"
            | "intersect"
            | "fetch"
            | "offset"
            | "for"
            | "model"
    )
}

fn is_source_expression_keyword(word: &str) -> bool {
    matches!(
        word,
        "as" | "case"
            | "when"
            | "then"
            | "else"
            | "end"
            | "distinct"
            | "null"
            | "true"
            | "false"
            | "and"
            | "or"
            | "not"
            | "over"
            | "partition"
            | "by"
            | "asc"
            | "desc"
    ) || word.chars().all(|character| character.is_ascii_digit())
}

fn run_sast(args: SastArgs) -> Result<Value, ErrorEnvelope> {
    let run = analyze_local_project(&args.project_root)?;
    let completeness = CompletenessSnapshot {
        catalog_available: run.completeness.catalog_available || run.catalog.is_some(),
        plscope_available: run.completeness.plscope_available,
        files_total: run.completeness.files_total,
        files_recovered: run.completeness.files_recovered,
    };
    let scan = sast_source::scan(&run, &sast_rules(), &completeness)?;
    let report = scan.report;
    match args.format.as_deref().unwrap_or("json") {
        "json" => Ok(json!({
            "project_root": args.project_root,
            "report": report,
            "histogram": plsql_sast::rule_firing_histogram(&report),
            "completeness": completeness,
            "unit_count": scan.unit_count,
            "rule_evaluation_count": scan.rule_evaluation_count,
        })),
        "sarif" => Ok(json!(plsql_sast::to_sarif(
            &report,
            args.tool_name.as_deref().unwrap_or("plsql-sast"),
            args.tool_version.as_deref().unwrap_or("0.1.0"),
        ))),
        "junit" => Ok(json!({
            "junit_xml": plsql_sast::to_junit_xml(
                &report,
                args.suite_name.as_deref().unwrap_or("plsql-sast"),
            )
        })),
        "histogram" => Ok(json!(plsql_sast::rule_firing_histogram(&report))),
        other => Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("format must be one of json, sarif, junit, histogram; got {other}"),
        )),
    }
}

fn run_doc(args: DocArgs) -> Result<Value, ErrorEnvelope> {
    let query = args.query.unwrap_or_default().to_ascii_lowercase();
    if let Some(source) = args.source {
        let matches: Vec<_> = extract_doc_comments(&source)
            .into_iter()
            .filter(|comment| {
                query.is_empty()
                    || comment.text.to_ascii_lowercase().contains(&query)
                    || comment
                        .tag
                        .as_deref()
                        .is_some_and(|tag| tag.to_ascii_lowercase().contains(&query))
            })
            .collect();
        return Ok(json!({ "matches": matches }));
    }

    let docset = args.docset.unwrap_or_default();
    let label = args.project_label.as_deref().unwrap_or("PL/SQL Project");
    match args.format.as_deref().unwrap_or("json") {
        "json" => Ok(json!({ "docset": docset })),
        "markdown" => {
            Ok(json!({ "markdown": plsql_doc::render_full_markdown_bundle(&docset, label) }))
        }
        "html" => Ok(json!({ "html": plsql_doc::render_full_html_bundle(&docset, label) })),
        "doctor" => Ok(json!(plsql_doc::doctor_report(&docset))),
        other => Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("format must be one of json, markdown, html, doctor; got {other}"),
        )),
    }
}

async fn run_live_snapshot(
    cx: &Cx,
    conn: &dyn OracleConnection,
    args: LiveSnapshotArgs,
) -> Result<Value, ErrorEnvelope> {
    let report = extract_live_report(cx, conn, &args.schemas, args.include_plscope).await?;
    let snapshot = snapshot_from_report(&report)?;
    snapshot_response(
        &report,
        snapshot,
        args.include_snapshot.unwrap_or(false),
        args.public_synonym_offset.unwrap_or(0),
    )
}

async fn run_blast_radius(
    cx: &Cx,
    conn: &dyn OracleConnection,
    args: BlastRadiusArgs,
) -> Result<Value, ErrorEnvelope> {
    let report = extract_live_report(cx, conn, &args.schemas, args.include_plscope).await?;
    let snapshot = snapshot_from_report(&report)?;
    let mode = parse_predict_mode(args.mode.as_deref(), PredictMode::LiveSnapshot)?;
    let prediction = catalog_impact::predict(&snapshot, &report, &args.changeset, mode)?;
    let object_count = snapshot
        .schemas
        .values()
        .map(|schema| schema.objects.len())
        .sum();
    let symbol_count = snapshot.interner.len();
    let response = json!({
        "snapshot": snapshot_response(&report, snapshot, args.include_snapshot.unwrap_or(false), args.public_synonym_offset.unwrap_or(0))?,
        "prediction": change_impact_envelope(&prediction, Vec::new()),
    });
    Ok(catalog_impact::bound_response(
        response,
        object_count,
        symbol_count,
    ))
}

async fn extract_live_report(
    cx: &Cx,
    conn: &dyn OracleConnection,
    schemas: &Option<Vec<String>>,
    include_plscope: Option<bool>,
) -> Result<CatalogExtractReport, ErrorEnvelope> {
    let request = match schemas {
        Some(schemas) if !schemas.is_empty() => CatalogExtractRequest {
            schema_filters: schemas
                .iter()
                .map(|schema| CatalogSchemaFilter::Named(schema.clone()))
                .collect(),
            include_plscope: include_plscope.unwrap_or(true),
        },
        _ => CatalogExtractRequest::for_current_schema()
            .with_plscope(include_plscope.unwrap_or(true)),
    };
    extract_catalog_rowsets(cx, conn, &request)
        .await
        .map_err(db_error_to_envelope)
}

fn snapshot_response(
    report: &CatalogExtractReport,
    snapshot: CatalogSnapshot,
    include_snapshot: bool,
    public_synonym_offset: u32,
) -> Result<Value, ErrorEnvelope> {
    let object_count = snapshot
        .schemas
        .values()
        .map(|schema| schema.objects.len())
        .sum();
    let symbol_count = snapshot.interner.len();
    let row_counts: Vec<Value> = report
        .batches
        .iter()
        .map(|batch| {
            json!({
                "row_set": batch.row_set.as_str(),
                "row_count": batch.rows.len(),
            })
        })
        .collect();
    let doctor = snapshot.doctor_report();
    let mut value = json!({
        "schemas": report.schema_names,
        "row_counts": row_counts,
        "warnings": report.warnings,
        "doctor": doctor,
    });
    if include_snapshot && let Value::Object(map) = &mut value {
        let exported = catalog_impact::export(snapshot, public_synonym_offset)?;
        map.insert("snapshot_export".to_owned(), json!(exported.status));
        if let Some(body) = exported.body {
            map.insert("catalog_snapshot".to_owned(), body);
        }
    }
    Ok(catalog_impact::bound_response(
        value,
        object_count,
        symbol_count,
    ))
}

fn snapshot_from_report(report: &CatalogExtractReport) -> Result<CatalogSnapshot, ErrorEnvelope> {
    let mut builder = CatalogSnapshotBuilder::new(
        AnalysisProfile::default(),
        CatalogCapabilities::default(),
        CatalogSource {
            kind: CatalogSourceKind::LiveConnection,
            description: Some("oraclemcp live catalog extraction".to_owned()),
            ..CatalogSource::default()
        },
        Utc::now(),
    );
    for batch in &report.batches {
        let row_set = catalog_row_set(batch.row_set);
        let rows: Vec<CatalogOracleRow> = batch.rows.iter().map(catalog_row).collect();
        builder.apply_rows(row_set, rows.iter()).map_err(|error| {
            ErrorEnvelope::new(
                ErrorClass::Internal,
                format!(
                    "catalog snapshot normalization failed for {}: {error}",
                    row_set.as_str()
                ),
            )
        })?;
    }
    builder.finish().map_err(|error| {
        ErrorEnvelope::new(
            ErrorClass::Internal,
            format!("catalog snapshot finalization failed: {error}"),
        )
    })
}

fn catalog_row(row: &DbOracleRow) -> CatalogOracleRow {
    let mut out = CatalogOracleRow::default();
    for (name, cell) in &row.columns {
        out.insert(name.as_str(), cell.oracle_type.as_str(), cell.value.clone());
    }
    out
}

fn catalog_row_set(row_set: CatalogRowSetName) -> CatalogRowSet {
    match row_set {
        CatalogRowSetName::Objects => CatalogRowSet::Objects,
        CatalogRowSetName::Columns => CatalogRowSet::Columns,
        CatalogRowSetName::Constraints => CatalogRowSet::Constraints,
        CatalogRowSetName::Indexes => CatalogRowSet::Indexes,
        CatalogRowSetName::Triggers => CatalogRowSet::Triggers,
        CatalogRowSetName::Synonyms => CatalogRowSet::Synonyms,
        CatalogRowSetName::Routines => CatalogRowSet::Routines,
        CatalogRowSetName::RoutineArguments => CatalogRowSet::RoutineArguments,
        CatalogRowSetName::Views => CatalogRowSet::Views,
        CatalogRowSetName::MaterializedViews => CatalogRowSet::MaterializedViews,
        CatalogRowSetName::Sequences => CatalogRowSet::Sequences,
        CatalogRowSetName::TypeAttributes => CatalogRowSet::TypeAttributes,
        CatalogRowSetName::Users => CatalogRowSet::Users,
        CatalogRowSetName::Grants => CatalogRowSet::Grants,
        CatalogRowSetName::DatabaseLinks => CatalogRowSet::DatabaseLinks,
        CatalogRowSetName::TableComments => CatalogRowSet::TableComments,
        CatalogRowSetName::ColumnComments => CatalogRowSet::ColumnComments,
        CatalogRowSetName::Editions => CatalogRowSet::Editions,
        CatalogRowSetName::EditioningViews => CatalogRowSet::EditioningViews,
        CatalogRowSetName::VpdPolicies => CatalogRowSet::VpdPolicies,
        CatalogRowSetName::Dependencies => CatalogRowSet::Dependencies,
        CatalogRowSetName::PlScopeAvailability => CatalogRowSet::PlScopeAvailability,
        CatalogRowSetName::PlScopeIdentifiers => CatalogRowSet::PlScopeIdentifiers,
    }
}

fn analyze_local_project(project_root: &str) -> Result<plsql_engine::AnalysisRun, ErrorEnvelope> {
    source_limits::validate_project(Path::new(project_root))?;
    analyze_project(AnalysisRequest {
        project_root: PathBuf::from(project_root),
        ..AnalysisRequest::default()
    })
    .map_err(|error| {
        ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            format!("PL/SQL analysis failed: {error}"),
        )
    })
}

pub(crate) fn validate_engine_source(source: &str) -> Result<(), ErrorEnvelope> {
    source_limits::validate_source(source)
}

/// The pinned PL/SQL engine release behind every served analysis fact.
pub(crate) const ENGINE_VERSION: &str = env!("OMCP_BUILD_PLSQL_ENGINE_VERSION");

/// Engine facts for one exact unit source, as an approval preview shows them.
pub(crate) struct SourceImpactAnalysis {
    pub effects: RoutineEffectsV1,
    pub unknown_reasons: Vec<String>,
    /// SAST refuses source with syntax errors; effects are still reported.
    pub sast: Result<SourceSast, ErrorEnvelope>,
}

pub(crate) struct SourceSast {
    pub findings: Vec<plsql_sast::Finding>,
    pub skipped: Vec<plsql_sast::RuleSkippedDiagnostic>,
}

/// Analyze one stored or candidate unit with the pinned engine, without a
/// database. The effect set is the union of every declared routine's
/// invocation closure. A non-clean run or closure, or a source in which the
/// engine finds no routine, adds Unknown; it is never reported as no effect.
pub(crate) fn analyze_source_impact(source: &str) -> Result<SourceImpactAnalysis, ErrorEnvelope> {
    validate_engine_source(source)?;
    // Grammar-backed analysis recurses deeply. Previews reach this from
    // callers on default-sized stacks, so it gets the lane thread's stack
    // (oraclemcp-core lane.rs) regardless of where it is called from.
    on_engine_stack(|| analyze_source_impact_on_stack(source))?
}

/// Share the existing parser stack boundary across source-proof consumers.
pub(crate) fn on_engine_stack<T: Send>(
    analyze: impl FnOnce() -> T + Send,
) -> Result<T, ErrorEnvelope> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("omcp-source-impact".to_owned())
            .stack_size(8 * 1024 * 1024)
            .spawn_scoped(scope, analyze)
            .map_err(|_| {
                ErrorEnvelope::new(ErrorClass::Internal, "PL/SQL analysis thread unavailable")
            })?
            .join()
            .map_err(|_| ErrorEnvelope::new(ErrorClass::Internal, "PL/SQL analysis panicked"))
    })
}

fn analyze_source_impact_on_stack(source: &str) -> Result<SourceImpactAnalysis, ErrorEnvelope> {
    let workspace_error = |_| {
        ErrorEnvelope::new(
            ErrorClass::Internal,
            "PL/SQL analysis workspace unavailable",
        )
    };
    let project = tempfile::tempdir().map_err(workspace_error)?;
    std::fs::write(project.path().join("unit.sql"), source).map_err(workspace_error)?;
    let run = analyze_project(AnalysisRequest {
        project_root: project.path().to_owned(),
        cache: plsql_engine::CacheConfig {
            enabled: false,
            ..Default::default()
        },
        ..AnalysisRequest::default()
    })
    .map_err(|error| {
        ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            format!("PL/SQL analysis failed: {error}"),
        )
    })?;
    let mut effects = RoutineEffectsV1::default();
    let mut unknown_reasons = BTreeSet::new();
    if run.completeness.posture != CompletenessPosture::Clean {
        unknown_reasons.insert(format!(
            "analysis posture is {:?}",
            run.completeness.posture
        ));
    }
    if run.invocation_index.units.is_empty() {
        unknown_reasons.insert("the engine found no routine in this source".to_owned());
    }
    for (id, unit) in &run.invocation_index.units {
        let closure = run.invocation_index.closure(&InvocationShapeV1 {
            routine_id: id.clone(),
            named_arguments: unit
                .params
                .iter()
                .filter(|param| !param.has_default)
                .map(|param| param.name.clone())
                .collect(),
            ..InvocationShapeV1::default()
        });
        effects = effects.union(&map_engine_effects(&closure.effects));
        if !closure.clean && closure.unknown_reasons.is_empty() {
            unknown_reasons.insert(format!("{id}: invocation closure is not clean"));
        }
        unknown_reasons.extend(
            closure
                .unknown_reasons
                .iter()
                .map(|reason| format!("{id}: {reason}")),
        );
    }
    if !unknown_reasons.is_empty() {
        effects = effects.union(&unknown_effects());
    }
    let completeness = CompletenessSnapshot {
        catalog_available: false,
        plscope_available: run.completeness.plscope_available,
        files_total: run.completeness.files_total,
        files_recovered: run.completeness.files_recovered,
    };
    let sast = sast_source::scan(&run, &sast_rules(), &completeness).map(|scan| SourceSast {
        findings: scan.report.findings,
        skipped: scan.report.skipped,
    });
    Ok(SourceImpactAnalysis {
        effects,
        unknown_reasons: unknown_reasons.into_iter().collect(),
        sast,
    })
}

/// Digest of the enabled SAST rule set under the pinned engine release.
pub(crate) fn sast_ruleset_digest() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut rules: Vec<_> = sast_rules()
        .iter()
        .map(|rule| (rule.id(), format!("{:?}", rule.default_severity())))
        .collect();
    rules.sort();
    let mut hash = Sha256::new();
    hash.update(b"omcp/impact/sast-ruleset/v1\0");
    hash.update(ENGINE_VERSION.as_bytes());
    for (id, severity) in rules {
        hash.update([0]);
        hash.update(id.as_bytes());
        hash.update([0]);
        hash.update(severity.as_bytes());
    }
    hash.finalize().into()
}

fn parse_predict_mode(
    raw: Option<&str>,
    default_mode: PredictMode,
) -> Result<PredictMode, ErrorEnvelope> {
    match raw.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "" => Ok(default_mode),
        "source_only" | "source-only" => Ok(PredictMode::SourceOnly),
        "catalog_aware" | "catalog-aware" => Ok(PredictMode::CatalogAware),
        "live_snapshot" | "live-snapshot" => Ok(PredictMode::LiveSnapshot),
        other => Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("mode must be source_only, catalog_aware, or live_snapshot; got {other}"),
        )),
    }
}

fn parse_lineage_direction(raw: Option<&str>) -> Result<LineageDirection, ErrorEnvelope> {
    match raw
        .unwrap_or("downstream")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "downstream" => Ok(LineageDirection::Downstream),
        "upstream" => Ok(LineageDirection::Upstream),
        "bidirectional" | "both" => Ok(LineageDirection::Bidirectional),
        other => Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("direction must be upstream, downstream, or bidirectional; got {other}"),
        )),
    }
}

fn db_error_to_envelope(error: DbError) -> ErrorEnvelope {
    error.into_envelope()
}

fn json_error(error: serde_json::Error) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::Internal,
        format!("failed to serialize PL/SQL intelligence response: {error}"),
    )
}

fn sast_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(plsql_sast::Sec001ExecuteImmediateInjection),
        Box::new(plsql_sast::Sec002DbmsSqlParse),
        Box::new(plsql_sast::Sec003HardcodedCredentials),
        Box::new(plsql_sast::Sec004InvokerRights),
        Box::new(plsql_sast::Sec005SensitivePublicSynonym),
        Box::new(plsql_sast::Sec006GrantToPublic),
        Box::new(plsql_sast::Sec007RefCursorReturn),
        Box::new(plsql_sast::Dep001CrossSchemaWrite),
        Box::new(plsql_sast::Perf001CursorForLoopBulkCollect),
        Box::new(plsql_sast::Perf002CursorForLoopForall),
        Box::new(plsql_sast::Perf003IsNullOnIndexedColumn),
        Box::new(plsql_sast::Qual001WhenOthersThenNull),
        Box::new(plsql_sast::Qual002LogWithoutReraise),
        Box::new(plsql_sast::Qual003UnboundedBulkCollect),
        Box::new(plsql_sast::Qual004TxnControlInHandler),
        Box::new(plsql_sast::Qual005DeprecatedFeature),
        Box::new(plsql_sast::Qual006MutatingTableTrigger),
        Box::new(plsql_sast::Qual007DmlInFunction),
        Box::new(plsql_sast::Qual008DeterministicMisuse),
        Box::new(plsql_sast::Style001MissingInstrumentation),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_guard::{DangerLevel, OperatingLevel};

    #[test]
    fn advertised_static_enums_are_refused_before_tool_execution() {
        for (tool, arguments) in [
            (
                "oracle_plsql_what_breaks",
                json!({"mode": "__w4_wrong_enum__"}),
            ),
            (
                "oracle_plsql_lineage",
                json!({
                    "project_root": "/must-not-be-read",
                    "target": "APP.P",
                    "direction": "__w4_wrong_enum__",
                }),
            ),
            (
                "oracle_plsql_sast",
                json!({"project_root": "/must-not-be-read", "format": "__w4_wrong_enum__"}),
            ),
            ("oracle_plsql_doc", json!({"format": "__w4_wrong_enum__"})),
        ] {
            let error = dispatch_static(tool, arguments)
                .expect_err("an advertised enum value must be rejected before execution");
            assert_eq!(error.error_class, ErrorClass::InvalidArguments, "{tool}");
            assert!(
                error.message.contains("must be one of"),
                "{tool}: {error:?}"
            );
        }
    }

    #[test]
    fn parse_reports_declarations_without_live_db() {
        let value = run_parse(ParseArgs {
            source: "CREATE OR REPLACE PACKAGE p AS PROCEDURE q; END;".to_owned(),
        })
        .expect("parse succeeds");
        assert_eq!(value["declaration_count"].as_u64(), Some(1));
        assert_eq!(value["recovered"].as_bool(), Some(false));
        // The grammar AST resolves unquoted Oracle identifiers canonically.
        assert_eq!(value["declarations"][0]["name"].as_str(), Some("P"));
        assert_eq!(value["declarations"][0]["kind"].as_str(), Some("Package"));
        assert_eq!(
            value["declarations"][0]["span"]["start"]["offset"].as_u64(),
            Some(0)
        );
    }

    #[test]
    fn parse_refuses_malformed_source_instead_of_returning_header_declarations() {
        for source in [
            "CREATE OR REPLACE PROCEDURE w4_broken AS BEGIN SELECT FROM ; END;",
            "CREATE OR REPLACE PROCEDURE w4_broken AS BEGIN IF THEN NULL; END IF; END;",
            "CREATE OR REPLACE PROCEDURE w4_broken AS BEGIN NULL;",
            "CREATE OR REPLACE PACKAGE w4_broken AS PROCEDURE ; END;",
            "this is not valid PL/SQL @@@",
        ] {
            let error = dispatch_static("oracle_plsql_parse", json!({"source": source}))
                .expect_err("malformed source must not return a successful declaration report");
            assert_eq!(error.error_class, ErrorClass::InvalidArguments, "{source}");
            assert!(error.message.contains("parser error"), "{error:?}");
            assert!(error.next_steps.iter().any(|step| step.contains("syntax")));
        }
    }

    #[test]
    fn parse_accepts_a_valid_routine_body_after_grammar_validation() {
        let value = dispatch_static(
            "oracle_plsql_parse",
            json!({"source": "CREATE OR REPLACE PROCEDURE w4_valid AS n NUMBER; BEGIN SELECT 1 INTO n FROM dual; IF n = 1 THEN NULL; END IF; END;"}),
        )
        .expect("valid routine body parses without a database");
        assert_eq!(value["declaration_count"], 1);
        assert_eq!(value["error_count"], 0);
        assert_eq!(value["recovered"], false);
        assert_eq!(value["declarations"][0]["name"], "W4_VALID");
    }

    fn scan_synthetic_sast(source: &str) -> Value {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("routine.sql"), source).unwrap();
        dispatch_static(
            "oracle_plsql_sast",
            json!({
                "project_root": project.path().to_str().unwrap(),
            }),
        )
        .expect("real source analysis and rule scan succeed")
    }

    #[test]
    fn sast_reports_the_original_standalone_formal_to_dynamic_sql_flow() {
        for source in [
            "CREATE OR REPLACE PROCEDURE w4_unsafe(p_name VARCHAR2) AUTHID DEFINER AS BEGIN EXECUTE IMMEDIATE 'DELETE FROM ' || p_name; END;",
            "CREATE OR REPLACE PROCEDURE w4_unsafe(p_name VARCHAR2) AUTHID DEFINER AS v_sql VARCHAR2(4000); BEGIN v_sql := 'DELETE FROM ' || p_name; EXECUTE IMMEDIATE v_sql; END;",
            "CREATE OR REPLACE PROCEDURE w4_unsafe(p_name VARCHAR2) AS v_sql VARCHAR2(4000); BEGIN v_sql := p_name; EXECUTE IMMEDIATE v_sql; v_sql := 'SELECT 1 FROM dual'; END;",
            "CREATE OR REPLACE PROCEDURE w4_unsafe(p_name VARCHAR2) AUTHID DEFINER AS BEGIN EXECUTE IMMEDIATE DBMS_ASSERT.ENQUOTE_LITERAL('x') || p_name; END;",
            "CREATE OR REPLACE PROCEDURE w4_unsafe(p_name VARCHAR2) AUTHID DEFINER AS BEGIN EXECUTE IMMEDIATE 'DELETE FROM ' || DBMS_ASSERT.NOOP(p_name); END;",
            "CREATE OR REPLACE FUNCTION w4_unsafe(p_name VARCHAR2) RETURN NUMBER AUTHID DEFINER AS BEGIN EXECUTE IMMEDIATE 'DELETE FROM ' || p_name; RETURN 1; END;",
        ] {
            let value = scan_synthetic_sast(source);
            let finding = value["report"]["findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|finding| finding["rule_id"] == "SEC001")
                .expect("actual formal input reaches the SQL sink");
            assert_eq!(finding["severity"], "critical");
            assert_eq!(finding["location"]["file"], "routine.sql");
            assert_eq!(finding["location"]["line"], 1);
            assert!(finding["location"]["byte_span"][1].as_u64().unwrap() > 0);
            assert_eq!(value["unit_count"], 1);
            assert_eq!(
                value["rule_evaluation_count"],
                value["report"]["rules_run"].as_u64().unwrap()
                    + value["report"]["rules_gated"].as_u64().unwrap()
            );
            assert!(
                value["report"]["rules_gated"].as_u64().unwrap() > 0,
                "missing unrelated fact families remain gated"
            );
        }
    }

    #[test]
    fn sast_preserves_clean_literal_and_sanitized_controls() {
        for source in [
            "CREATE OR REPLACE PROCEDURE w4_clean AS BEGIN NULL; END;",
            "CREATE OR REPLACE PROCEDURE w4_clean(p_name VARCHAR2) AS BEGIN EXECUTE IMMEDIATE 'DELETE FROM fixed_table'; END;",
            "CREATE OR REPLACE PROCEDURE w4_clean(p_name VARCHAR2) AS v_sql VARCHAR2(4000); BEGIN v_sql := 'SELECT 1 FROM dual'; EXECUTE IMMEDIATE v_sql; v_sql := p_name; END;",
            "CREATE OR REPLACE PROCEDURE w4_clean(p_name VARCHAR2) AS BEGIN EXECUTE IMMEDIATE 'DELETE FROM ' || SYS.DBMS_ASSERT.SIMPLE_SQL_NAME(p_name); END;",
        ] {
            let value = scan_synthetic_sast(source);
            assert_eq!(value["report"]["findings"], json!([]), "{value}");
            assert!(
                value["report"]["rules_gated"].as_u64().unwrap() > 0,
                "zero findings does not claim the missing fact families passed"
            );
        }
    }

    #[test]
    fn sast_uses_real_package_member_formals_and_body() {
        let value = scan_synthetic_sast(
            "CREATE OR REPLACE PACKAGE w4_sast AS PROCEDURE q(p_name VARCHAR2); END;\n/\nCREATE OR REPLACE PACKAGE BODY w4_sast AS PROCEDURE q(p_name VARCHAR2) AS BEGIN EXECUTE IMMEDIATE 'DELETE FROM ' || p_name; END; END;\n/",
        );
        assert!(
            value["report"]["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["rule_id"] == "SEC001"),
            "{value}"
        );
    }

    #[test]
    fn sast_reports_an_unmodeled_block_as_a_flow_gap() {
        for source in [
            "CREATE OR REPLACE PROCEDURE w4_nested(p_name VARCHAR2) AS BEGIN BEGIN EXECUTE IMMEDIATE p_name; END; END;",
            "CREATE OR REPLACE PROCEDURE w4_nested(p_name VARCHAR2) AS BEGIN IF p_name IS NOT NULL THEN EXECUTE IMMEDIATE p_name; END IF; END;",
            "CREATE OR REPLACE PROCEDURE w4_nested(p_name VARCHAR2) AS BEGIN LOOP EXECUTE IMMEDIATE p_name; EXIT; END LOOP; END;",
        ] {
            let value = scan_synthetic_sast(source);
            assert!(
                value["report"]["skipped"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|skip| {
                        skip["rule_id"] == "SEC001"
                            && skip["reason"] == "missing_flow_facts"
                            && skip["detail"]
                                .as_str()
                                .is_some_and(|detail| detail.contains("traversal is incomplete"))
                    }),
                "{value}"
            );
        }
    }

    fn write_view_chain_project() -> tempfile::TempDir {
        // A three-level view chain over a base table. `amount` is carried column
        // for column from the base table up through v_orders into v_paid, so its
        // source-derived lineage must trace back down the chain.
        let dir = tempfile::tempdir().expect("temp project dir");
        std::fs::write(
            dir.path().join("orders.sql"),
            "CREATE TABLE app.orders (\n  id NUMBER,\n  amount NUMBER,\n  status VARCHAR2(20)\n);\n",
        )
        .expect("write base table");
        std::fs::write(
            dir.path().join("v_orders.sql"),
            "CREATE VIEW app.v_orders AS\n  SELECT id, amount, status FROM app.orders;\n",
        )
        .expect("write v_orders");
        std::fs::write(
            dir.path().join("v_paid.sql"),
            "CREATE VIEW app.v_paid AS\n  SELECT id, amount FROM app.v_orders WHERE status = 'PAID';\n",
        )
        .expect("write v_paid");
        std::fs::write(
            dir.path().join("v_report.sql"),
            "CREATE VIEW app.v_report AS\n  SELECT amount FROM app.v_paid;\n",
        )
        .expect("write v_report");
        dir
    }

    #[test]
    fn column_lineage_returns_source_derived_edges_for_a_view_chain() {
        let project = write_view_chain_project();
        let value = run_column_lineage(ColumnLineageArgs {
            project_root: project.path().display().to_string(),
            owner: Some("app".to_owned()),
            object: "v_paid".to_owned(),
            column: "amount".to_owned(),
        })
        .expect("column lineage succeeds over source");

        // The column resolves to its canonical logical id, and the tool reports
        // it found the node rather than an empty available-sample fallback.
        assert_eq!(value["found"].as_bool(), Some(true), "value={value}");
        assert_eq!(
            value["column_logical_id"].as_str(),
            Some("app.v_paid.amount")
        );

        // The upstream side is source-derived: v_paid.amount derives from the
        // view chain below it (v_orders / orders), never from thin air. Every
        // edge names an object and a column edge kind, and nothing else.
        let upstream = &value["upstream"];
        assert_eq!(
            upstream["column_logical_id"].as_str(),
            Some("app.v_paid.amount")
        );
        let edges = upstream["edges"].as_array().expect("upstream edges array");
        assert!(
            !edges.is_empty(),
            "a carried view column must have at least one source-derived upstream edge: {value}"
        );
        let upstream_objects: Vec<String> = edges
            .iter()
            .map(|edge| {
                edge["object"]
                    .as_str()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
            })
            .collect();
        assert!(
            upstream_objects
                .iter()
                .any(|object| object.contains("v_orders") || object.contains("orders")),
            "upstream should trace into the view chain (v_orders/orders); got {upstream_objects:?}"
        );
        for edge in edges {
            let kind = edge["edge_kind"].as_str().unwrap_or_default();
            assert!(
                kind.contains("Column"),
                "every upstream edge is a column-level edge; got {kind}"
            );
            // Redaction: an edge names only objects and column-edge metadata, no
            // literal value (the WHERE 'PAID' literal must never appear).
            assert!(
                !edge.to_string().contains("PAID"),
                "an edge leaked a literal: {edge}"
            );
        }

        let downstream = value["downstream"]["edges"]
            .as_array()
            .expect("downstream edges array");
        assert!(
            downstream.iter().any(|edge| {
                edge["object"]
                    .as_str()
                    .is_some_and(|object| object.eq_ignore_ascii_case("app.v_report.amount"))
                    && edge["edge_kind"] == "ReadsColumn"
            }),
            "the next view must be a direct reader of v_paid.amount: {downstream:?}"
        );
    }

    #[test]
    fn column_lineage_reports_a_missing_column_without_inventing_edges() {
        let project = write_view_chain_project();
        let value = run_column_lineage(ColumnLineageArgs {
            project_root: project.path().display().to_string(),
            owner: Some("app".to_owned()),
            object: "v_paid".to_owned(),
            column: "does_not_exist".to_owned(),
        })
        .expect("column lineage runs even when the column is absent");
        assert_eq!(value["found"].as_bool(), Some(false));
        assert!(
            value.get("upstream").is_none(),
            "no edges for a missing column"
        );
        assert!(value["available_column_sample"].is_array());
    }

    #[test]
    fn lineage_marks_wrapped_body_as_partial_without_inventing_dependencies() {
        let project = tempfile::tempdir().expect("wrapped lineage project");
        std::fs::write(
            project.path().join("secure_pkg.pks"),
            "CREATE OR REPLACE PACKAGE secure_pkg AS\n\
             PROCEDURE public_api;\n\
             END secure_pkg;\n",
        )
        .expect("write package spec");
        std::fs::write(
            project.path().join("secure_pkg.pkb"),
            "CREATE OR REPLACE PACKAGE BODY secure_pkg WRAPPED\n\
             a000000\n\
             1\n\
             abcd\n",
        )
        .expect("write wrapped package body");

        let value = run_lineage(LineageArgs {
            project_root: project.path().display().to_string(),
            target: "SECURE_PKG".to_owned(),
            direction: Some("bidirectional".to_owned()),
            max_depth: None,
        })
        .expect("wrapped source must not fail lineage");

        assert_eq!(value["found"], json!(true), "value={value}");
        assert_eq!(value["lineage_completeness"], json!("partial"));
        assert_eq!(
            value["partial_lineage_marker"]["reason"],
            json!(WRAPPED_SOURCE_UNKNOWN_REASON)
        );
        for direction in ["upstream", "downstream"] {
            let result = &value[direction];
            assert_eq!(result["partial"], json!(true), "value={value}");
            let unknown_edges = result["unknown_edges"]
                .as_array()
                .expect("partial lineage has typed unknown edges");
            assert!(unknown_edges.iter().any(|edge| {
                edge["source"] == "SECURE_PKG"
                    && edge["unknown_reason"] == WRAPPED_SOURCE_UNKNOWN_REASON
            }));
            assert!(
                result["edges"]
                    .as_array()
                    .expect("lineage result has an edge set")
                    .is_empty(),
                "wrapped source must not fabricate dependency edges: {result}"
            );
        }
    }

    #[test]
    fn wrapped_source_marker_is_scoped_to_its_declared_object() {
        let source = "PACKAGE BODY app.secure_pkg WRAPPED\na000000\n1\nabcd\n";
        assert!(wrapped_source_declares_target(source, "APP.SECURE_PKG"));
        assert!(wrapped_source_declares_target(source, "secure_pkg"));
        assert!(!wrapped_source_declares_target(source, "APP.OTHER_PKG"));
        assert!(
            !wrapped_source_declares_target(source, "OTHER.SECURE_PKG"),
            "an explicitly qualified wrapped header must not affect a same-named object in another schema"
        );
    }

    fn test_source_column(
        logical_id: &str,
        expected_data_type: Option<&str>,
    ) -> SourceLineageColumnRef {
        SourceLineageColumnRef {
            logical_id: normalize_source_name(logical_id),
            expected_data_type: expected_data_type.map(normalize_data_type),
        }
    }

    fn test_catalog(columns: &[(&str, &str)]) -> LiveCatalogSnapshot {
        let mut catalog = LiveCatalogSnapshot::default();
        for (logical_id, data_type) in columns {
            catalog.columns.insert(
                normalize_source_name(logical_id),
                CatalogColumnRef {
                    data_type: normalize_data_type(data_type),
                },
            );
        }
        catalog
    }

    #[test]
    fn catalog_drift_markers_distinguish_verified_missing_and_type_mismatch() {
        let source = test_source_column("APP.V_PAID.AMOUNT", Some("NUMBER"));
        let verified = test_catalog(&[("APP.V_PAID.AMOUNT", "NUMBER")]);
        assert_eq!(
            classify_catalog_drift(&source, &verified),
            CatalogDriftMarker::Verified
        );
        assert_eq!(
            catalog_marker_json(&source, &verified)["status"],
            "verified"
        );

        let missing = test_catalog(&[("APP.V_PAID.ID", "NUMBER")]);
        assert_eq!(
            classify_catalog_drift(&source, &missing),
            CatalogDriftMarker::Missing
        );
        assert_eq!(
            catalog_marker_json(&source, &missing)["status"],
            "drift:missing"
        );

        let mismatch = test_catalog(&[("APP.V_PAID.AMOUNT", "VARCHAR2")]);
        assert_eq!(
            classify_catalog_drift(&source, &mismatch),
            CatalogDriftMarker::TypeMismatch
        );
        let marker = catalog_marker_json(&source, &mismatch);
        assert_eq!(marker["status"], "drift:type_mismatch");
        assert_eq!(marker["source_data_type"], "NUMBER");
        assert_eq!(marker["catalog_data_type"], "VARCHAR2");
    }

    #[test]
    fn oracle_lineage_is_registered_as_a_live_catalog_tool_under_the_feature() {
        assert!(TOOL_NAMES.contains(&"oracle_lineage"));
        assert!(!is_static_tool("oracle_lineage"));
        let mut registry = ToolRegistry::default();
        register_tools(&mut registry);
        let descriptor = registry
            .tools
            .iter()
            .find(|tool| tool.name == "oracle_lineage")
            .expect("oracle_lineage must be registered under the feature");
        assert_eq!(descriptor.tier, ToolTier::FoundationLiveDb);
    }

    #[test]
    fn ambiguous_multi_source_projection_stays_edge_free() {
        let project = tempfile::tempdir().expect("temp project dir");
        std::fs::write(
            project.path().join("sources.sql"),
            "CREATE TABLE app.left_orders (id NUMBER);\n\
             CREATE TABLE app.right_orders (id NUMBER);\n\
             CREATE VIEW app.ambiguous_orders AS\n\
             SELECT id FROM app.left_orders l JOIN app.right_orders r ON l.id = r.id;\n",
        )
        .expect("write ambiguous source project");
        let value = run_column_lineage(ColumnLineageArgs {
            project_root: project.path().display().to_string(),
            owner: Some("app".to_owned()),
            object: "ambiguous_orders".to_owned(),
            column: "id".to_owned(),
        })
        .expect("ambiguous lineage still returns a truthful column node");
        assert_eq!(value["found"], json!(true));
        assert!(
            value["upstream"]["edges"]
                .as_array()
                .expect("upstream edge array")
                .is_empty(),
            "an ambiguous unqualified source column must not be guessed: {value}"
        );
    }

    #[test]
    fn what_breaks_empty_changeset_is_a_real_prediction() {
        let value = run_what_breaks(WhatBreaksArgs {
            changeset: ChangeSet::default(),
            mode: None,
        })
        .expect("predict succeeds");
        assert_eq!(
            value["schema_id"].as_str(),
            Some("plsql.cicd.change_impact")
        );
    }

    #[test]
    fn doc_source_filter_reuses_doc_extractor() {
        let value = run_doc(DocArgs {
            source: Some("/** hello billing */\nCREATE PROCEDURE p IS BEGIN NULL; END;".into()),
            docset: None,
            query: Some("billing".into()),
            format: None,
            project_label: None,
        })
        .expect("doc succeeds");
        assert_eq!(value["matches"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn adapter_gap3_no_edges_is_unknown() {
        let mut graph = DepGraph::new();
        add_node(
            &mut graph,
            1,
            "APP.EMPTY",
            NodeIdentityKind::StandaloneFunction,
        );
        let oracle =
            PlsqlSideEffectOracle::from_analysis_run(&analysis_run(graph, Some(empty_catalog())));
        assert_eq!(
            oracle.routine_purity(&ObjectRef::parse("APP.EMPTY")),
            Purity::Unknown
        );
        assert_eq!(
            oracle.routine_effects(&adapter_reference("EMPTY")),
            unknown_effects()
        );
    }

    fn adapter_reference(member: &str) -> RoutineRef {
        RoutineRef {
            schema: Some(oraclemcp_guard::RoutineIdentifier::new("APP", false)),
            package: None,
            member: oraclemcp_guard::RoutineIdentifier::new(member, false),
            overload: None,
        }
    }

    fn add_source_unit(run: &mut plsql_engine::AnalysisRun, id: &str, body: &str) {
        run.invocation_index
            .insert_unit(plsql_engine::effects::EffectUnit {
                id: id.to_owned(),
                package: None,
                kind: None,
                statements: plsql_ir::stmt::lower_statement_body(body),
                params: Vec::new(),
                source_complete: true,
                source_reasons: BTreeSet::new(),
            });
    }

    fn adapter_read_run() -> plsql_engine::AnalysisRun {
        let mut graph = DepGraph::new();
        add_node(
            &mut graph,
            1,
            "APP.LOOKUP",
            NodeIdentityKind::StandaloneFunction,
        );
        add_node(&mut graph, 2, "APP.ORDERS", NodeIdentityKind::Table);
        add_edge(&mut graph, 1, 1, 2, EdgeKind::Reads);
        let mut run = analysis_run(graph, Some(empty_catalog()));
        add_source_unit(
            &mut run,
            "APP.LOOKUP",
            "BEGIN SELECT ID INTO n FROM APP.ORDERS; END;",
        );
        run
    }

    #[test]
    fn adapter_source_refusal_dominates_medium_writes_and_transaction_control() {
        let project = tempfile::tempdir().unwrap();
        for (declaration, expected) in [
            (
                "PRAGMA AUTONOMOUS_TRANSACTION;",
                vec![
                    RoutineEffect::Dml,
                    RoutineEffect::TxnControl,
                    RoutineEffect::Autonomous,
                ],
            ),
            ("", vec![RoutineEffect::Dml, RoutineEffect::TxnControl]),
        ] {
            std::fs::write(project.path().join("change.sql"), format!(
                "CREATE OR REPLACE TRIGGER APP.CHANGE BEFORE UPDATE ON APP.T FOR EACH ROW DECLARE {declaration} BEGIN INSERT INTO APP.CANARY (ID) VALUES (7); COMMIT; END;\n"
            )).unwrap();
            let mut run = analyze_project(AnalysisRequest {
                project_root: project.path().to_owned(),
                cache: plsql_engine::CacheConfig {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
            assert_eq!(
                run.completeness.posture,
                CompletenessPosture::Clean,
                "{:?}",
                run.completeness
            );
            run.catalog = Some(empty_catalog());
            for kind in [EdgeKind::Writes, EdgeKind::TransactionControl] {
                let edges: Vec<_> = run
                    .dep_graph
                    .edges
                    .iter_mut()
                    .filter(|edge| edge.kind == kind)
                    .collect();
                assert!(!edges.is_empty(), "real source must produce {kind:?}");
                for edge in edges {
                    edge.confidence.level = ConfidenceLevel::Medium;
                }
            }
            let closure = run.invocation_index.closure(&InvocationShapeV1 {
                routine_id: "APP.CHANGE".into(),
                ..Default::default()
            });
            assert!(
                closure.clean && closure.unknown_reasons.is_empty(),
                "{closure:?}"
            );
            assert_eq!(
                map_engine_effects(&closure.effects),
                RoutineEffectsV1::new(expected.clone())
            );
            let effects = PlsqlSideEffectOracle::from_analysis_run(&run)
                .routine_effects(&adapter_reference("CHANGE"));
            assert_eq!(effects, RoutineEffectsV1::new(expected));
            assert_eq!(
                oraclemcp_guard::admit(
                    &effects,
                    oraclemcp_guard::AdmissionContext::DmlMutationClosure
                ),
                Err(oraclemcp_guard::EffectRefusal::AlwaysRefused(
                    RoutineEffect::TxnControl
                ))
            );

            run.invocation_index
                .units
                .get_mut("APP.CHANGE")
                .unwrap()
                .source_complete = false;
            assert_eq!(
                PlsqlSideEffectOracle::from_analysis_run(&run)
                    .routine_effects(&adapter_reference("CHANGE")),
                unknown_effects(),
                "a refusal must still have a clean source proof"
            );
        }
    }

    #[test]
    fn adapter_call_specs_are_unknown_for_effects() {
        let project = tempfile::tempdir().unwrap();
        for separator in [" ", "\n", " /* call spec */ "] {
            for (language, tail) in [
                ("JAVA", "NAME 'X.f()'"),
                ("C", "NAME \"employee_label\" LIBRARY employee_lib"),
            ] {
                let source = format!(
                    "CREATE OR REPLACE PROCEDURE APP.OPAQUE_CALL AS LANGUAGE{separator}{language} {tail};\n/\n"
                );
                std::fs::write(project.path().join("call_spec.sql"), &source).unwrap();
                let mut run = analyze_project(AnalysisRequest {
                    project_root: project.path().to_owned(),
                    cache: plsql_engine::CacheConfig {
                        enabled: false,
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .unwrap();
                assert!(
                    run.dep_graph
                        .nodes
                        .values()
                        .any(|node| node.logical_id.as_str() == "APP.OPAQUE_CALL"),
                    "the real parser must recognize {language} call spec with separator {separator:?}"
                );
                run.catalog = Some(empty_catalog());
                for clean_outer_report in [false, true] {
                    let mut oracle = PlsqlSideEffectOracle::from_analysis_run(&run);
                    assert!(oracle.catalog_complete);
                    if clean_outer_report {
                        // An optimistic surrounding report cannot provide the
                        // opaque body's missing invocation/effect proof.
                        oracle.source_trustworthy = true;
                    }
                    let effects = oracle.routine_effects(&adapter_reference("OPAQUE_CALL"));
                    assert_eq!(
                        effects,
                        unknown_effects(),
                        "{language}, separator {separator:?}, clean outer {clean_outer_report}"
                    );
                    assert_eq!(effects_purity(&effects), Purity::Unknown);
                }
            }
        }
    }

    #[test]
    fn adapter_medium_writes_cannot_promote_source_read_db() {
        let mut run = adapter_read_run();
        add_edge(&mut run.dep_graph, 2, 1, 2, EdgeKind::Writes);
        run.dep_graph.edges.last_mut().unwrap().confidence.level = ConfidenceLevel::Medium;
        assert_eq!(
            PlsqlSideEffectOracle::from_analysis_run(&run)
                .routine_effects(&adapter_reference("LOOKUP")),
            unknown_effects()
        );
    }

    #[test]
    fn adapter_source_proven_autonomous_effect_survives_its_medium_effect_edge() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("trigger.sql"),
            "CREATE OR REPLACE TRIGGER APP.TR_AUTO BEFORE UPDATE OF C2 ON APP.T FOR EACH ROW DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN NULL; END;\n").unwrap();
        let mut run = analyze_project(AnalysisRequest {
            project_root: project.path().to_owned(),
            cache: plsql_engine::CacheConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        // Explicit unit catalog fixture; the native mutation fixture separately
        // proves the same binding against fresh Oracle metadata and sources.
        run.catalog = Some(empty_catalog());
        let edge = run
            .dep_graph
            .edges
            .iter()
            .find(|edge| edge.kind == EdgeKind::Autonomous)
            .unwrap();
        assert_eq!(edge.confidence.level, ConfidenceLevel::Medium);
        let target = edge.to;
        let reference = adapter_reference("TR_AUTO");
        let effects = PlsqlSideEffectOracle::from_analysis_run(&run).routine_effects(&reference);
        assert_eq!(effects, RoutineEffectsV1::new([RoutineEffect::Autonomous]));
        assert_eq!(
            oraclemcp_guard::admit(
                &effects,
                oraclemcp_guard::AdmissionContext::DmlMutationClosure
            ),
            Err(oraclemcp_guard::EffectRefusal::AlwaysRefused(
                RoutineEffect::Autonomous
            ))
        );

        let mut edge_only = run.clone();
        edge_only
            .invocation_index
            .units
            .get_mut("APP.TR_AUTO")
            .unwrap()
            .statements
            .clear();
        assert_eq!(
            PlsqlSideEffectOracle::from_analysis_run(&edge_only).routine_effects(&reference),
            unknown_effects(),
            "a Medium graph edge alone cannot supply source authority"
        );

        let mut wrong_target = run.clone();
        wrong_target
            .dep_graph
            .nodes
            .get_mut(&target)
            .unwrap()
            .logical_id = LogicalObjectId::new("EFFECT::OTHER");
        assert_eq!(
            PlsqlSideEffectOracle::from_analysis_run(&wrong_target).routine_effects(&reference),
            effects,
            "graph target uncertainty cannot erase a source-proven refusal"
        );

        let mut low_confidence = run;
        low_confidence
            .dep_graph
            .edges
            .iter_mut()
            .find(|edge| edge.kind == EdgeKind::Autonomous)
            .unwrap()
            .confidence
            .level = ConfidenceLevel::Low;
        assert_eq!(
            PlsqlSideEffectOracle::from_analysis_run(&low_confidence).routine_effects(&reference),
            effects,
            "graph confidence cannot erase a source-proven refusal"
        );
    }

    #[test]
    fn adapter_clean_read_effects_are_admitted_at_read_only() {
        let run = adapter_read_run();
        let oracle = PlsqlSideEffectOracle::from_analysis_run(&run);
        let effects = oracle.routine_effects(&adapter_reference("LOOKUP"));
        assert_eq!(effects, RoutineEffectsV1::new([RoutineEffect::ReadDb]));
        assert_eq!(
            oraclemcp_guard::admit(&effects, oraclemcp_guard::AdmissionContext::CustomToolCall),
            Ok(OperatingLevel::ReadOnly)
        );
        assert_eq!(
            oracle.routine_purity(&ObjectRef::parse("APP.LOOKUP")),
            Purity::ProvenReadOnly
        );
    }

    #[test]
    fn adapter_gap3_unloaded_sys_call_is_unknown() {
        for name in [
            "SYS.UTL_HTTP.REQUEST",
            "SYS.DBMS_SCHEDULER.RUN_JOB",
            "SYSTEM.UTL_HTTP.REQUEST",
        ] {
            let mut run = adapter_read_run();
            let parts: Vec<_> = name.split('.').collect();
            add_node(
                &mut run.dep_graph,
                3,
                name,
                NodeIdentityKind::StandaloneFunction,
            );
            // Even a loaded, Clean body does not substitute for a reviewed SYS identity.
            add_source_unit(&mut run, name, "BEGIN NULL; END;");
            let oracle = PlsqlSideEffectOracle::from_analysis_run(&run);
            let reference = RoutineRef {
                schema: Some(oraclemcp_guard::RoutineIdentifier::new(parts[0], false)),
                package: Some(oraclemcp_guard::RoutineIdentifier::new(parts[1], false)),
                member: oraclemcp_guard::RoutineIdentifier::new(parts[2], false),
                overload: None,
            };
            assert_eq!(
                oracle.routine_effects(&reference),
                unknown_effects(),
                "{name}"
            );
            let mut unloaded = run.clone();
            unloaded.invocation_index.units.remove(name);
            assert_eq!(
                PlsqlSideEffectOracle::from_analysis_run(&unloaded).routine_effects(&reference),
                unknown_effects()
            );
        }
        // Nor may an allowlisted identity synthesize an unavailable source closure.
        let mut reference = adapter_reference("SUBSTR");
        reference.schema = Some(oraclemcp_guard::RoutineIdentifier::new("SYS", false));
        reference.package = Some(oraclemcp_guard::RoutineIdentifier::new("DBMS_LOB", false));
        assert_eq!(
            PlsqlSideEffectOracle::from_analysis_run(&adapter_read_run())
                .routine_effects(&reference),
            unknown_effects()
        );

        let mut transitive = adapter_read_run();
        let callee = "SYS.DBMS_UNREVIEWED.READ";
        add_node(
            &mut transitive.dep_graph,
            3,
            callee,
            NodeIdentityKind::StandaloneFunction,
        );
        add_edge(&mut transitive.dep_graph, 2, 1, 3, EdgeKind::Calls);
        transitive.invocation_index.units.remove("APP.LOOKUP");
        add_source_unit(
            &mut transitive,
            "APP.LOOKUP",
            "BEGIN RETURN SYS.DBMS_UNREVIEWED.READ(); END;",
        );
        add_source_unit(&mut transitive, callee, "BEGIN NULL; END;");
        let closure = transitive.invocation_closure(&InvocationShapeV1 {
            routine_id: "APP.LOOKUP".into(),
            ..InvocationShapeV1::default()
        });
        assert!(
            closure.clean && closure.units.contains(callee),
            "exercise a loaded transitive SYS callee: {closure:?}"
        );
        assert_eq!(
            PlsqlSideEffectOracle::from_analysis_run(&transitive)
                .routine_effects(&adapter_reference("LOOKUP")),
            unknown_effects()
        );
    }

    #[test]
    fn adapter_sys_policy_never_erases_engine_effects() {
        let mut run = adapter_read_run();
        let id = "SYS.DBMS_LOB.SUBSTR";
        add_node(
            &mut run.dep_graph,
            3,
            id,
            NodeIdentityKind::StandaloneFunction,
        );
        add_source_unit(&mut run, id, "BEGIN UPDATE t SET n=1; END;");
        let mut reference = adapter_reference("SUBSTR");
        reference.schema = Some(oraclemcp_guard::RoutineIdentifier::new("SYS", false));
        reference.package = Some(oraclemcp_guard::RoutineIdentifier::new("DBMS_LOB", false));
        assert_eq!(
            PlsqlSideEffectOracle::from_analysis_run(&run).routine_effects(&reference),
            RoutineEffectsV1::new([
                RoutineEffect::ReadDb,
                RoutineEffect::Dml,
                RoutineEffect::ExternalIo
            ])
        );
    }

    #[test]
    fn adapter_gap4_no_case_insensitive_fallback() {
        let mut run = adapter_read_run();
        add_node(
            &mut run.dep_graph,
            3,
            "APP.MixedCase",
            NodeIdentityKind::StandaloneFunction,
        );
        add_source_unit(&mut run, "APP.MixedCase", "BEGIN NULL; END;");
        let oracle = PlsqlSideEffectOracle::from_analysis_run(&run);
        assert_eq!(
            oracle.routine_purity(&ObjectRef::parse("APP.mixedcase")),
            Purity::Unknown
        );
        assert_eq!(
            oracle.routine_effects(&adapter_reference("mixedcase")),
            unknown_effects()
        );
        let mut exact = adapter_reference("unused");
        exact.member = oraclemcp_guard::RoutineIdentifier::new("MixedCase", true);
        assert_eq!(oracle.routine_effects(&exact), RoutineEffectsV1::default());
        exact.member.text = "Mixed.Case".into();
        assert_eq!(
            oracle.routine_effects(&exact),
            unknown_effects(),
            "flattened separators cannot identify one unit"
        );
    }

    #[test]
    fn adapter_quoted_and_owner_chain_calls_cannot_inherit_bare_proof() {
        let mut run = adapter_read_run();
        add_node(
            &mut run.dep_graph,
            3,
            "LOOKUP",
            NodeIdentityKind::StandaloneFunction,
        );
        add_source_unit(&mut run, "LOOKUP", "BEGIN NULL; END;");
        add_node(
            &mut run.dep_graph,
            4,
            "A.B",
            NodeIdentityKind::StandaloneFunction,
        );
        add_source_unit(&mut run, "A.B", "BEGIN NULL; END;");
        let classifier = classifier_from_analysis_run(&run);
        assert_eq!(
            classifier
                .classify("SELECT LOOKUP(id) FROM APP.ORDERS")
                .danger,
            DangerLevel::Safe
        );
        for sql in [
            "SELECT \"EVIL\".\"LOOKUP\"(id) FROM APP.ORDERS",
            "SELECT EVIL.PKG.LOOKUP(id) FROM APP.ORDERS",
            "SELECT \"lookup\"(id) FROM APP.ORDERS",
            "SELECT \"A.B\"(id) FROM APP.ORDERS",
        ] {
            assert_eq!(
                classifier.classify(sql).danger,
                DangerLevel::Guarded,
                "a richer or quoted identity must not collapse to the loaded bare LOOKUP: {sql}"
            );
        }
    }

    #[test]
    fn adapter_gap5_partial_is_untrusted() {
        let mut run = adapter_read_run();
        run.completeness.posture = CompletenessPosture::Partial;
        let oracle = PlsqlSideEffectOracle::from_analysis_run(&run);
        assert_eq!(
            oracle.routine_effects(&adapter_reference("LOOKUP")),
            unknown_effects()
        );
        assert_eq!(
            oracle.routine_purity(&ObjectRef::parse("APP.LOOKUP")),
            Purity::Unknown
        );
        assert_eq!(
            oracle.statement_purity(&[ObjectRef::parse("APP.ORDERS")]),
            Purity::Unknown
        );
    }

    #[test]
    fn adapter_low_confidence_is_untrusted() {
        let mut run = adapter_read_run();
        run.completeness.posture = CompletenessPosture::LowConfidence;
        assert_eq!(
            PlsqlSideEffectOracle::from_analysis_run(&run)
                .routine_effects(&adapter_reference("LOOKUP")),
            unknown_effects()
        );
        run.completeness.posture = CompletenessPosture::Clean;
        for confidence in [ConfidenceLevel::Low, ConfidenceLevel::Medium] {
            run.dep_graph.edges[0].confidence.level = confidence;
            assert_eq!(
                PlsqlSideEffectOracle::from_analysis_run(&run)
                    .routine_effects(&adapter_reference("LOOKUP")),
                unknown_effects(),
                "non-Autonomous {confidence:?} edges remain untrusted"
            );
        }
        run.dep_graph.edges[0].confidence.level = ConfidenceLevel::High;
        run.invocation_index
            .units
            .get_mut("APP.LOOKUP")
            .unwrap()
            .source_complete = false;
        assert_eq!(
            PlsqlSideEffectOracle::from_analysis_run(&run)
                .routine_effects(&adapter_reference("LOOKUP")),
            unknown_effects(),
            "a Clean run cannot repair a non-Clean closure"
        );
    }

    #[test]
    fn adapter_missing_catalog_is_unknown() {
        let mut run = adapter_read_run();
        run.catalog = None;
        let oracle = PlsqlSideEffectOracle::from_analysis_run(&run);
        assert_eq!(
            oracle.routine_effects(&adapter_reference("LOOKUP")),
            unknown_effects()
        );
        assert_eq!(
            oracle.statement_purity(&[ObjectRef::parse("APP.ORDERS")]),
            Purity::Unknown
        );
        assert_eq!(oracle.statement_purity(&[]), Purity::Unknown);
        assert_eq!(
            oracle.catalog_vpd_purity_for_node(NodeId::new(2)),
            Purity::Unknown
        );
    }

    #[test]
    fn adapter_ambiguous_overload_is_unknown() {
        let mut run = adapter_read_run();
        run.invocation_index.units.remove("APP.LOOKUP");
        for (id, node) in [("APP.LOOKUP#1", 3), ("APP.LOOKUP#2", 4)] {
            add_node(
                &mut run.dep_graph,
                node,
                id,
                NodeIdentityKind::StandaloneFunction,
            );
            add_source_unit(&mut run, id, "BEGIN NULL; END;");
        }
        let oracle = PlsqlSideEffectOracle::from_analysis_run(&run);
        assert_eq!(
            oracle.routine_effects(&adapter_reference("LOOKUP")),
            unknown_effects()
        );
        let mut exact = adapter_reference("LOOKUP");
        exact.overload = Some(1);
        assert_eq!(oracle.routine_effects(&exact), RoutineEffectsV1::default());
        exact.overload = Some(3);
        assert_eq!(oracle.routine_effects(&exact), unknown_effects());
    }

    #[test]
    fn adapter_invalid_catalog_member_is_unknown() {
        let mut run = adapter_read_run();
        let catalog = run.catalog.as_mut().unwrap();
        let owner = catalog.interner.intern_schema_name("APP").unwrap();
        let name = plsql_core::ObjectName::from(catalog.interner.intern("LOOKUP").unwrap());
        let mut function = plsql_catalog::FunctionMetadata::default();
        function.common.owner = owner;
        function.common.name = name;
        function.common.status = plsql_catalog::ObjectStatus::Invalid;
        catalog
            .schemas
            .entry(owner)
            .or_default()
            .objects
            .insert(name, plsql_catalog::CatalogObject::Function(function));
        assert_eq!(
            PlsqlSideEffectOracle::from_analysis_run(&run)
                .routine_effects(&adapter_reference("LOOKUP")),
            unknown_effects()
        );
    }

    #[test]
    fn effects_contract_parity() {
        use plsql_engine::{OperatorStatementClass as O, RoutineEffect as E};
        let engine = plsql_engine::RoutineEffectsV1::new([
            E::ReadDb,
            E::RowLock,
            E::SessionState,
            E::Dml,
            E::Ddl,
            E::Admin,
            E::SequenceAdvance,
            E::OperatorOnly(O::DefaultEditionFlip),
            E::TxnControl,
            E::Autonomous,
            E::DynamicSql,
            E::ExternalIo,
            E::Unknown,
        ]);
        let mapped = map_engine_effects(&engine);
        assert_eq!(
            serde_json::to_value(&engine).unwrap(),
            serde_json::to_value(&mapped).unwrap()
        );
        // A new guard variant also makes this reverse contract check fail to
        // compile, rather than disappearing from a manually counted list.
        let reverse =
            plsql_engine::RoutineEffectsV1::new(mapped.iter().map(|effect| match effect {
                RoutineEffect::ReadDb => E::ReadDb,
                RoutineEffect::RowLock => E::RowLock,
                RoutineEffect::SessionState => E::SessionState,
                RoutineEffect::Dml => E::Dml,
                RoutineEffect::Ddl => E::Ddl,
                RoutineEffect::Admin => E::Admin,
                RoutineEffect::SequenceAdvance => E::SequenceAdvance,
                RoutineEffect::OperatorOnly(class) => E::OperatorOnly(match class {
                    oraclemcp_guard::OperatorStatementClass::DefaultEditionFlip => {
                        O::DefaultEditionFlip
                    }
                }),
                RoutineEffect::TxnControl => E::TxnControl,
                RoutineEffect::Autonomous => E::Autonomous,
                RoutineEffect::DynamicSql => E::DynamicSql,
                RoutineEffect::ExternalIo => E::ExternalIo,
                RoutineEffect::Unknown => E::Unknown,
            }));
        assert_eq!(reverse, engine);
        assert_eq!(
            map_engine_effects(&plsql_engine::RoutineEffectsV1::new([E::OperatorOnly(
                O::DefaultEditionFlip
            )])),
            RoutineEffectsV1::new([RoutineEffect::OperatorOnly(
                oraclemcp_guard::OperatorStatementClass::DefaultEditionFlip
            )])
        );
    }

    #[test]
    fn sys_effects_toml_parses_and_is_tighten_only() {
        let effects = parse_sys_effects(SYS_EFFECTS_SOURCE).unwrap();
        assert_eq!(effects.len(), 3);
        for (name, effect) in [
            ("SYS.DBMS_LOB.SUBSTR", RoutineEffect::ExternalIo),
            ("SYS.DBMS_XPLAN.DISPLAY", RoutineEffect::DynamicSql),
        ] {
            assert!(effects[name].iter().any(|actual| actual == effect));
            assert!(
                oraclemcp_guard::admit(
                    &effects[name],
                    oraclemcp_guard::AdmissionContext::CustomToolCall
                )
                .is_err(),
                "an identity-wide policy cannot prove a safe overload or arbitrary filter: {name}"
            );
        }
        for mutation in [
            SYS_EFFECTS_SOURCE.replace("schema_version = 1", "schema_version = 2"),
            SYS_EFFECTS_SOURCE.replace("effects = [\"ReadDb\"]", "effects = []"),
            SYS_EFFECTS_SOURCE.replace(
                "effects = [\"ReadDb\", \"ExternalIo\"]",
                "effects = [\"ReadDb\"]",
            ),
            SYS_EFFECTS_SOURCE.replace(
                "effects = [\"ReadDb\", \"DynamicSql\"]",
                "effects = [\"ReadDb\"]",
            ),
            SYS_EFFECTS_SOURCE.replace("SYS.DBMS_LOB.SUBSTR", "SYS.DBMS_LOB.WRITE"),
            format!(
                "{SYS_EFFECTS_SOURCE}\n[[routine]]\nidentity=\"SYS.UTL_HTTP.REQUEST\"\neffects=[\"ReadDb\"]\n"
            ),
            format!(
                "{SYS_EFFECTS_SOURCE}\n[[routine]]\nidentity=\"SYS.DBMS_LOB.SUBSTR\"\neffects=[\"ReadDb\"]\n"
            ),
            SYS_EFFECTS_SOURCE.replace(
                "effects = [\"ReadDb\"]",
                "effects = [\"ReadDb\",\"ReadDb\"]",
            ),
            SYS_EFFECTS_SOURCE.replace("effects = [\"ReadDb\"]", "effects = [\"FutureEffect\"]"),
        ] {
            assert!(
                parse_sys_effects(&mutation).is_err(),
                "unreviewed or malformed policy was accepted"
            );
        }
        assert_eq!(
            sys_effects_marker(&effects),
            "sha256:a70072bc57f365ae33b9a2607f4b94791561a02b14c59e74037d4ed90bc1c58e"
        );
    }

    fn assert_engine_adapter_unknown(source: &str) {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("fixture.sql"), source).unwrap();
        let mut run = analyze_project(AnalysisRequest {
            project_root: project.path().to_owned(),
            ..AnalysisRequest::default()
        })
        .unwrap();
        let closure = run.invocation_closure(&InvocationShapeV1 {
            routine_id: "FX".into(),
            ..InvocationShapeV1::default()
        });
        assert!(
            !closure.clean
                && closure
                    .effects
                    .effects
                    .contains(&plsql_engine::RoutineEffect::Unknown),
            "engine must retain this source uncertainty: {closure:?}"
        );
        run.catalog = Some(empty_catalog());
        let oracle = PlsqlSideEffectOracle::from_analysis_run(&run);
        let mut reference = adapter_reference("FX");
        reference.schema = None;
        assert_eq!(oracle.routine_effects(&reference), unknown_effects());
        assert_eq!(
            oracle.routine_purity(&ObjectRef::parse("FX")),
            Purity::Unknown
        );
    }

    #[test]
    fn wrapped_body_refused() {
        assert_engine_adapter_unknown("CREATE OR REPLACE PROCEDURE fx WRAPPED\na000000\n/");
    }

    #[test]
    fn dynamic_execute_immediate_refused() {
        for body in [
            "EXECUTE IMMEDIATE query_text;",
            "EXECUTE IMMEDIATE 'UPDATE t SET n=' || input_value;",
        ] {
            assert_engine_adapter_unknown(&format!(
                "CREATE OR REPLACE PROCEDURE fx IS BEGIN {body} END fx; /"
            ));
        }
    }

    #[test]
    fn dbms_sql_refused() {
        for call in [
            "DBMS_SQL.PARSE(c,query_text,1);",
            "DBMS_SCHEDULER.RUN_JOB('J');",
            "DBMS_PIPE.SEND_MESSAGE('P');",
            "DBMS_AQ.LISTEN(NULL,NULL,NULL);",
            "UTL_HTTP.REQUEST('http://example.invalid/');",
        ] {
            assert_engine_adapter_unknown(&format!(
                "CREATE OR REPLACE PROCEDURE fx IS BEGIN {call} END fx; /"
            ));
        }
    }

    #[test]
    fn authid_current_user_refused() {
        assert_engine_adapter_unknown(
            "CREATE OR REPLACE PROCEDURE fx AUTHID CURRENT_USER IS BEGIN NULL; END fx; /",
        );
    }

    #[test]
    fn java_and_external_procedure_refused() {
        for source in [
            "CREATE OR REPLACE PROCEDURE fx AS LANGUAGE JAVA NAME 'X.f()'; /",
            "CREATE OR REPLACE PROCEDURE fx AS EXTERNAL NAME 'f' LIBRARY l; /",
        ] {
            assert_engine_adapter_unknown(source);
        }
    }

    #[test]
    fn plsql_side_effect_oracle_proves_clean_routine_and_statement() {
        let mut graph = DepGraph::new();
        add_node(&mut graph, 1, "APP.ORDERS", NodeIdentityKind::Table);
        add_node(
            &mut graph,
            2,
            "APP.LOOKUP",
            NodeIdentityKind::StandaloneFunction,
        );

        let mut run = analysis_run(graph, Some(empty_catalog()));
        add_source_unit(&mut run, "APP.LOOKUP", "BEGIN NULL; END;");
        let classifier = classifier_from_analysis_run(&run);
        let d = classifier.classify("SELECT APP.LOOKUP(id) FROM APP.ORDERS");

        assert_eq!(
            d.danger,
            DangerLevel::Safe,
            "the engine binding may clear a refusal only when routine and base object are proven read-only"
        );
        assert_eq!(d.required_level, Some(OperatingLevel::ReadOnly));
    }

    #[test]
    fn sideeffect_oracle_binding_never_loosens_without_readonly_proof() {
        let mut graph = DepGraph::new();
        add_node(&mut graph, 1, "APP.ORDERS", NodeIdentityKind::Table);
        add_node(
            &mut graph,
            2,
            "APP.PURGE",
            NodeIdentityKind::StandaloneFunction,
        );
        add_node(&mut graph, 3, "APP.AUDIT_LOG", NodeIdentityKind::Table);
        add_edge(&mut graph, 1, 2, 3, EdgeKind::Writes);

        let mut run = analysis_run(graph, Some(empty_catalog()));
        add_source_unit(
            &mut run,
            "APP.PURGE",
            "BEGIN UPDATE APP.AUDIT_LOG SET ID=1; END;",
        );
        let classifier = classifier_from_analysis_run(&run);

        assert_eq!(
            Classifier::default()
                .classify("SELECT APP.PURGE(id) FROM APP.ORDERS")
                .danger,
            DangerLevel::Guarded,
            "default UnknownOracle refuses the UDF"
        );
        assert_eq!(
            classifier
                .classify("SELECT APP.PURGE(id) FROM APP.ORDERS")
                .danger,
            DangerLevel::Guarded,
            "a real write edge must not be loosened"
        );
        assert_eq!(
            classifier
                .classify("SELECT APP.MISSING(id) FROM APP.ORDERS")
                .danger,
            DangerLevel::Guarded,
            "an unresolved routine remains Unknown and guarded"
        );
    }

    #[test]
    fn new_engine_effect_edges_never_prove_a_routine_read_only() {
        let side_effecting = [
            EdgeKind::TransactionControl,
            EdgeKind::Autonomous,
            EdgeKind::SequenceAdvance,
            EdgeKind::RowLock,
            EdgeKind::SessionState,
            EdgeKind::Ddl,
            EdgeKind::Admin,
            EdgeKind::OperatorOnly,
            EdgeKind::ExternalIo,
        ];
        for (index, kind) in side_effecting.into_iter().enumerate() {
            let mut graph = DepGraph::new();
            add_node(
                &mut graph,
                1,
                "APP.CALLER",
                NodeIdentityKind::StandaloneFunction,
            );
            add_node(&mut graph, 2, "APP.DEPENDENCY", NodeIdentityKind::Table);
            add_edge(&mut graph, 1, 1, 2, kind);

            let mut run = analysis_run(graph, Some(empty_catalog()));
            add_source_unit(&mut run, "APP.CALLER", "BEGIN NULL; END;");
            let oracle = PlsqlSideEffectOracle::from_analysis_run(&run);
            assert_eq!(
                oracle.routine_purity(&ObjectRef::parse("APP.CALLER")),
                Purity::ProvenSideEffecting,
                "{kind:?} must tighten routine purity (case {index})"
            );
        }

        for (index, kind) in [EdgeKind::UnresolvedDynamicSql, EdgeKind::UnresolvedCallee]
            .into_iter()
            .enumerate()
        {
            let mut graph = DepGraph::new();
            add_node(
                &mut graph,
                1,
                "APP.CALLER",
                NodeIdentityKind::StandaloneFunction,
            );
            add_node(&mut graph, 2, "APP.DEPENDENCY", NodeIdentityKind::Table);
            add_edge(&mut graph, 1, 1, 2, kind);

            let oracle = PlsqlSideEffectOracle::from_analysis_run(&analysis_run(
                graph,
                Some(empty_catalog()),
            ));
            assert_eq!(
                oracle.routine_purity(&ObjectRef::parse("APP.CALLER")),
                Purity::Unknown,
                "{kind:?} must remain unknown (case {index})"
            );
        }
    }

    #[test]
    fn qualified_routine_proof_never_falls_back_to_an_unrelated_bare_node() {
        let mut graph = DepGraph::new();
        add_node(
            &mut graph,
            1,
            "LOOKUP",
            NodeIdentityKind::StandaloneFunction,
        );
        let mut run = analysis_run(graph, Some(empty_catalog()));
        add_source_unit(&mut run, "LOOKUP", "BEGIN NULL; END;");
        let oracle = PlsqlSideEffectOracle::from_analysis_run(&run);

        assert_eq!(
            oracle.routine_purity(&ObjectRef::parse("EVIL.LOOKUP")),
            Purity::Unknown,
            "a missing qualified identity must not inherit bare LOOKUP proof"
        );
        assert_eq!(
            oracle.routine_purity(&ObjectRef::parse("LOOKUP")),
            Purity::ProvenReadOnly,
            "the exact bare identity remains resolvable"
        );
    }

    #[test]
    fn select_side_effecting_trigger_tightens_plain_select() {
        let mut graph = DepGraph::new();
        add_node(&mut graph, 1, "APP.ORDERS", NodeIdentityKind::Table);
        add_node(
            &mut graph,
            2,
            "APP.ORDERS_READ_TRG",
            NodeIdentityKind::Trigger,
        );
        add_node(&mut graph, 3, "APP.AUDIT_LOG", NodeIdentityKind::Table);
        add_edge(&mut graph, 1, 2, 1, EdgeKind::TriggersOn);
        add_edge(&mut graph, 2, 2, 3, EdgeKind::Writes);

        let run = analysis_run(graph, Some(empty_catalog()));
        let classifier = classifier_from_analysis_run(&run);

        assert_eq!(
            Classifier::engine_free_baseline(ClassifierConfig::new())
                .classify("SELECT * FROM APP.ORDERS")
                .danger,
            DangerLevel::Safe,
            "the explicit engine-free baseline remains available for offline analysis"
        );
        assert_eq!(
            classifier.classify("SELECT * FROM APP.ORDERS").danger,
            DangerLevel::Guarded,
            "the engine binding must tighten SELECT when graph evidence reaches side effects"
        );
    }

    #[test]
    fn select_vpd_policy_function_is_part_of_statement_purity() {
        let mut graph = DepGraph::new();
        add_node(&mut graph, 1, "APP.ORDERS", NodeIdentityKind::Table);
        add_node(
            &mut graph,
            2,
            "APP.POLICY_FN",
            NodeIdentityKind::StandaloneFunction,
        );
        add_node(&mut graph, 3, "APP.AUDIT_LOG", NodeIdentityKind::Table);
        add_edge(&mut graph, 1, 2, 3, EdgeKind::Writes);

        let run = analysis_run(graph, Some(catalog_with_select_vpd_policy()));
        let classifier = classifier_from_analysis_run(&run);

        assert_eq!(
            classifier.classify("SELECT * FROM APP.ORDERS").danger,
            DangerLevel::Guarded,
            "a SELECT VPD policy function is resolved through the catalog and walked for side effects"
        );
    }

    fn analysis_run(
        dep_graph: DepGraph,
        catalog: Option<CatalogSnapshot>,
    ) -> plsql_engine::AnalysisRun {
        let mut completeness = plsql_core::CompletenessReport {
            posture: CompletenessPosture::Clean,
            catalog_available: catalog.is_some(),
            ..plsql_core::CompletenessReport::default()
        };
        completeness.finalize_posture();
        completeness.posture = CompletenessPosture::Clean;
        plsql_engine::AnalysisRun {
            dep_graph,
            catalog,
            completeness,
            ..plsql_engine::AnalysisRun::default()
        }
    }

    fn add_node(graph: &mut DepGraph, id: u64, logical_id: &str, kind: NodeIdentityKind) {
        graph.insert_node(Node::new(
            NodeId::new(id),
            plsql_depgraph::LogicalObjectId::new(logical_id),
            plsql_depgraph::ObjectRevisionId::new("test"),
            plsql_depgraph::QualifiedName::default(),
            kind,
        ));
    }

    fn add_edge(graph: &mut DepGraph, id: u64, from: u64, to: u64, kind: EdgeKind) {
        graph.insert_edge(
            Edge::new(
                plsql_depgraph::EdgeId::new(id),
                NodeId::new(from),
                NodeId::new(to),
                kind,
                plsql_core::Confidence::new(ConfidenceLevel::High, None::<String>),
            ),
            plsql_depgraph::Provenance::new(
                FileId::new(0),
                plsql_core::Span::default(),
                plsql_depgraph::ResolutionStrategy::LocalLexical,
            ),
            None,
        );
    }

    fn empty_catalog() -> CatalogSnapshot {
        CatalogSnapshot::new(
            AnalysisProfile::default(),
            CatalogCapabilities::default(),
            CatalogSource::default(),
            Utc::now(),
        )
    }

    fn catalog_with_select_vpd_policy() -> CatalogSnapshot {
        let mut catalog = empty_catalog();
        let owner = catalog
            .interner
            .intern_schema_name("APP")
            .expect("schema interned");
        let object = catalog
            .interner
            .intern("ORDERS")
            .map(plsql_core::ObjectName::from)
            .expect("object interned");
        catalog
            .schemas
            .entry(owner)
            .or_default()
            .vpd_policies
            .push(plsql_catalog::VpdPolicy {
                object_owner: owner,
                object_name: object,
                policy_group: None,
                policy_name: "ORDERS_SELECT_POLICY".to_owned(),
                function_owner: owner,
                function_package: None,
                function_name: "POLICY_FN".to_owned(),
                on_select: true,
                on_insert: false,
                on_update: false,
                on_delete: false,
                enabled: true,
            });
        catalog
    }
}
