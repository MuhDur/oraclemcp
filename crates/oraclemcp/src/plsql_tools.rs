#![cfg(feature = "plsql-intelligence")]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use asupersync::Cx;
use chrono::Utc;
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_db::{
    CatalogExtractReport, CatalogExtractRequest, CatalogRowSetName, CatalogSchemaFilter, DbError,
    OracleConnection, OracleRow as DbOracleRow, extract_catalog_rowsets,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{Classifier, ClassifierConfig, ObjectRef, Purity, SideEffectOracle};
use plsql_catalog::{
    CatalogCapabilities, CatalogRowSet, CatalogSnapshot, CatalogSnapshotBuilder, CatalogSource,
    CatalogSourceKind, OracleRow as CatalogOracleRow,
};
use plsql_cicd::{ChangeSet, PredictMode, change_impact_envelope, predict};
use plsql_core::{
    AnalysisProfile, CompletenessPosture, ConfidenceLevel, Diagnostic, FileId, Severity, Span,
};
use plsql_depgraph::{DepGraph, Edge, EdgeKind, Node, NodeId, NodeIdentityKind, NodeSelector};
use plsql_doc::{DocSet, extract_doc_comments};
use plsql_engine::{
    AnalysisRequest, analyze_project, engine_doctor_report, engine_full_doctor_report,
};
use plsql_ir::{FactPayload, FactStore, FlowEnv, lower_top_level};
use plsql_lineage::{LineageDirection, column_writers, dependencies, impact};
use plsql_parser_antlr::lower::lower_source;
use plsql_sast::{CompletenessSnapshot, Rule, ScanUnit, run_scan};
use serde::Deserialize;
use serde_json::{Value, json};

pub const TOOL_NAMES: [&str; 8] = [
    "oracle_plsql_parse",
    "oracle_plsql_analyze",
    "oracle_plsql_what_breaks",
    "oracle_plsql_lineage",
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
    registry.register(
        ToolDescriptor::new(
            "oracle_plsql_parse",
            ToolTier::FoundationStatic,
            "Parse PL/SQL source with the offline plsql-intelligence lowerer and return declaration and diagnostic counts.",
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
                "changeset": { "type": "object", "description": "plsql-cicd ChangeSet JSON." },
                "mode": { "type": "string", "enum": ["source_only", "catalog_aware", "live_snapshot"], "description": "Prediction completeness mode. Defaults to catalog_aware." }
            }),
            &["changeset"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_plsql_lineage",
            ToolTier::FoundationStatic,
            "Run offline dependency-lineage traversal from a logical object id in a local PL/SQL project.",
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
                "docset": { "type": "object", "description": "Optional plsql-doc DocSet JSON to render." },
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

pub async fn dispatch_live(
    cx: &Cx,
    conn: &dyn OracleConnection,
    tool: &str,
    args: Value,
) -> Result<Value, ErrorEnvelope> {
    match tool {
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

fn live_schema(include_changeset: bool) -> Value {
    let mut props = json!({
        "schemas": { "type": "array", "items": { "type": "string" }, "description": "Schema owners to extract. Omit to use the current schema." },
        "include_plscope": { "type": "boolean", "description": "Include PL/Scope rowsets when available. Defaults to true." },
        "include_snapshot": { "type": "boolean", "description": "Include the full normalized CatalogSnapshot in the response. Defaults to false." }
    });
    let mut required = Vec::new();
    if include_changeset {
        if let Value::Object(map) = &mut props {
            map.insert(
                "changeset".to_owned(),
                json!({ "type": "object", "description": "plsql-cicd ChangeSet JSON." }),
            );
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
/// port; this consumer binds the PL/SQL analysis graph to it and opts in to the
/// Gap-2 statement-Unknown tightening.
#[must_use]
pub fn classifier_from_analysis_run(run: &plsql_engine::AnalysisRun) -> Classifier {
    Classifier::new(ClassifierConfig::new())
        .with_oracle(Arc::new(PlsqlSideEffectOracle::from_analysis_run(run)))
        .with_statement_unknown_guarded()
}

/// The PL/SQL-intelligence implementation of `oraclemcp-guard`'s purity port.
///
/// `plsql-depgraph` edges point `dependent -> dependency`. Routine purity walks
/// outgoing dependencies. Statement purity starts from SELECT base objects,
/// checks VPD/catalog policy functions, then walks incoming trigger-like
/// dependents and view dependencies. Anything not strongly proven read-only
/// stays `Unknown`.
#[derive(Clone)]
pub struct PlsqlSideEffectOracle {
    graph: Arc<DepGraph>,
    catalog: Option<Arc<CatalogSnapshot>>,
    catalog_complete: bool,
    source_trustworthy: bool,
}

impl PlsqlSideEffectOracle {
    #[must_use]
    pub fn from_analysis_run(run: &plsql_engine::AnalysisRun) -> Self {
        let source_trustworthy = matches!(
            run.completeness.posture,
            CompletenessPosture::Clean | CompletenessPosture::Partial
        );
        Self {
            graph: Arc::new(run.dep_graph.clone()),
            catalog: run.catalog.clone().map(Arc::new),
            catalog_complete: run.catalog.is_some(),
            source_trustworthy,
        }
    }

    fn routine_purity_by_candidates(&self, candidates: &[String]) -> Purity {
        let Some(node_id) = self.resolve_candidates(candidates).map(|node| node.id) else {
            return Purity::Unknown;
        };
        self.routine_node_purity(node_id, &mut HashSet::new())
    }

    fn routine_node_purity(&self, node_id: NodeId, stack: &mut HashSet<WalkKey>) -> Purity {
        let key = WalkKey::routine(node_id);
        if !stack.insert(key) {
            return Purity::Unknown;
        }

        let verdict = if !self.source_trustworthy {
            Purity::Unknown
        } else if self
            .graph
            .nodes
            .get(&node_id)
            .is_some_and(|node| self.node_writes_columns_via_lineage(node))
        {
            Purity::ProvenSideEffecting
        } else {
            let mut verdict = Purity::ProvenReadOnly;
            for edge in self.outgoing_edges(node_id) {
                verdict = combine_purity(verdict, self.routine_edge_purity(&edge, stack));
                if matches!(verdict, Purity::ProvenSideEffecting) {
                    break;
                }
            }
            verdict
        };

        stack.remove(&key);
        verdict
    }

    fn statement_node_purity(&self, node_id: NodeId, stack: &mut HashSet<WalkKey>) -> Purity {
        let key = WalkKey::statement(node_id);
        if !stack.insert(key) {
            return Purity::Unknown;
        }

        let verdict = if !self.catalog_complete {
            Purity::Unknown
        } else {
            let mut verdict = self.catalog_vpd_purity_for_node(node_id);

            for edge in self.incoming_edges(node_id) {
                if !matches!(edge.kind, EdgeKind::TriggersOn) {
                    continue;
                }
                let edge_purity = if is_high_confidence(&edge) {
                    self.routine_node_purity(edge.from, stack)
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

    fn routine_edge_purity(&self, edge: &Edge, stack: &mut HashSet<WalkKey>) -> Purity {
        if is_write_edge(edge.kind) {
            return Purity::ProvenSideEffecting;
        }
        if !is_high_confidence(edge) {
            return Purity::Unknown;
        }
        match edge.kind {
            EdgeKind::Calls => self.routine_node_purity(edge.to, stack),
            EdgeKind::Reads | EdgeKind::ReadsColumn | EdgeKind::ReadsUnknownColumnOfTable => {
                if self
                    .graph
                    .nodes
                    .get(&edge.to)
                    .is_some_and(|node| is_statement_object_kind(node.identity_kind))
                {
                    self.statement_node_purity(edge.to, stack)
                } else {
                    Purity::ProvenReadOnly
                }
            }
            EdgeKind::References | EdgeKind::DependsOnType => Purity::ProvenReadOnly,
            EdgeKind::Unknown
            | EdgeKind::TriggersOn
            | EdgeKind::Constrains
            | EdgeKind::OpaqueDynamic
            | EdgeKind::DbLink => Purity::Unknown,
            EdgeKind::Writes
            | EdgeKind::WritesColumn
            | EdgeKind::WritesUnknownColumnOfTable
            | EdgeKind::DerivesColumn => Purity::ProvenSideEffecting,
        }
    }

    fn statement_edge_purity(&self, edge: &Edge, stack: &mut HashSet<WalkKey>) -> Purity {
        if is_write_edge(edge.kind) {
            return Purity::ProvenSideEffecting;
        }
        if !is_high_confidence(edge) {
            return Purity::Unknown;
        }
        match edge.kind {
            EdgeKind::Calls => self.routine_node_purity(edge.to, stack),
            EdgeKind::Reads | EdgeKind::ReadsColumn | EdgeKind::ReadsUnknownColumnOfTable => {
                self.statement_node_purity(edge.to, stack)
            }
            EdgeKind::References | EdgeKind::DependsOnType => Purity::ProvenReadOnly,
            EdgeKind::Unknown
            | EdgeKind::TriggersOn
            | EdgeKind::Constrains
            | EdgeKind::OpaqueDynamic
            | EdgeKind::DbLink => Purity::Unknown,
            EdgeKind::Writes
            | EdgeKind::WritesColumn
            | EdgeKind::WritesUnknownColumnOfTable
            | EdgeKind::DerivesColumn => Purity::ProvenSideEffecting,
        }
    }

    fn catalog_vpd_purity_for_node(&self, node_id: NodeId) -> Purity {
        let Some(catalog) = &self.catalog else {
            return Purity::ProvenReadOnly;
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

    fn node_writes_columns_via_lineage(&self, source: &Node) -> bool {
        self.graph
            .nodes
            .values()
            .filter(|node| matches!(node.identity_kind, NodeIdentityKind::Column))
            .any(|column| {
                let writers = column_writers(&self.graph, &NodeSelector::NodeId(column.id));
                writers.accessors.iter().any(|accessor| {
                    accessor
                        .accessor_logical_id
                        .eq_ignore_ascii_case(source.logical_id.as_str())
                })
            })
    }

    fn resolve_candidates(&self, candidates: &[String]) -> Option<&Node> {
        for candidate in candidates {
            if let Ok(node) = self
                .graph
                .resolve_node(&NodeSelector::LogicalObjectId(candidate.clone()))
            {
                return Some(node);
            }
        }
        self.graph.nodes.values().find(|node| {
            candidates
                .iter()
                .any(|candidate| node.logical_id.as_str().eq_ignore_ascii_case(candidate))
        })
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
    fn routine_purity(&self, routine: &ObjectRef) -> Purity {
        self.routine_purity_by_candidates(&object_ref_candidates(routine))
    }

    fn statement_purity(&self, base_objects: &[ObjectRef]) -> Purity {
        if base_objects.is_empty() {
            return Purity::ProvenReadOnly;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum WalkKind {
    Routine,
    Statement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct WalkKey {
    kind: WalkKind,
    node: NodeId,
}

impl WalkKey {
    fn routine(node: NodeId) -> Self {
        Self {
            kind: WalkKind::Routine,
            node,
        }
    }

    fn statement(node: NodeId) -> Self {
        Self {
            kind: WalkKind::Statement,
            node,
        }
    }
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

fn is_write_edge(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::Writes
            | EdgeKind::WritesColumn
            | EdgeKind::WritesUnknownColumnOfTable
            | EdgeKind::DerivesColumn
    )
}

fn is_high_confidence(edge: &Edge) -> bool {
    matches!(edge.confidence.level, ConfidenceLevel::High)
}

fn is_statement_object_kind(kind: NodeIdentityKind) -> bool {
    matches!(
        kind,
        NodeIdentityKind::Table
            | NodeIdentityKind::View
            | NodeIdentityKind::MaterializedView
            | NodeIdentityKind::EditioningView
    )
}

fn object_ref_candidates(reference: &ObjectRef) -> Vec<String> {
    let name = normalize_identifier(&reference.name);
    let mut out = Vec::new();
    if let Some(schema) = &reference.schema {
        out.push(format!("{}.{}", normalize_identifier(schema), name));
    }
    out.push(name);
    out
}

fn normalize_identifier(value: &str) -> String {
    value.trim_matches('"').to_ascii_uppercase()
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
    let bare = normalize_identifier(object);
    let qualified = format!("{}.{}", normalize_identifier(owner), bare);
    node.logical_id.as_str().eq_ignore_ascii_case(&bare)
        || node.logical_id.as_str().eq_ignore_ascii_case(&qualified)
}

fn vpd_function_candidates(
    catalog: &CatalogSnapshot,
    policy: &plsql_catalog::VpdPolicy,
) -> Vec<String> {
    let Some(owner) = catalog
        .interner
        .resolve(policy.function_owner.symbol())
        .map(normalize_identifier)
    else {
        return Vec::new();
    };
    let function = normalize_identifier(&policy.function_name);
    let mut out = Vec::new();
    if let Some(package) = &policy.function_package {
        let package = normalize_identifier(package);
        out.push(format!("{owner}.{package}.{function}"));
        out.push(format!("{package}.{function}"));
    }
    out.push(format!("{owner}.{function}"));
    out.push(function);
    out
}

fn parse_args<T: for<'de> Deserialize<'de>>(tool: &str, args: Value) -> Result<T, ErrorEnvelope> {
    let args = match args {
        Value::Null => Value::Object(serde_json::Map::new()),
        other => other,
    };
    serde_json::from_value(args).map_err(|error| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("invalid arguments for {tool}: {error}"),
        )
    })
}

#[derive(Deserialize)]
struct ParseArgs {
    source: String,
}

#[derive(Deserialize)]
struct AnalyzeArgs {
    project_root: String,
}

#[derive(Deserialize)]
struct WhatBreaksArgs {
    changeset: ChangeSet,
    mode: Option<String>,
}

#[derive(Deserialize)]
struct LineageArgs {
    project_root: String,
    target: String,
    direction: Option<String>,
    max_depth: Option<u32>,
}

#[derive(Deserialize)]
struct SastArgs {
    project_root: String,
    format: Option<String>,
    tool_name: Option<String>,
    tool_version: Option<String>,
    suite_name: Option<String>,
}

#[derive(Deserialize)]
struct DocArgs {
    source: Option<String>,
    docset: Option<DocSet>,
    query: Option<String>,
    format: Option<String>,
    project_label: Option<String>,
}

#[derive(Deserialize)]
struct LiveSnapshotArgs {
    schemas: Option<Vec<String>>,
    include_plscope: Option<bool>,
    include_snapshot: Option<bool>,
}

#[derive(Deserialize)]
struct BlastRadiusArgs {
    schemas: Option<Vec<String>>,
    include_plscope: Option<bool>,
    include_snapshot: Option<bool>,
    changeset: ChangeSet,
    mode: Option<String>,
}

fn run_parse(args: ParseArgs) -> Result<Value, ErrorEnvelope> {
    let ast = lower_source(&args.source, FileId::new(1));
    let mut interner = plsql_core::SymbolInterner::new();
    let lowered = lower_top_level(&ast, &mut interner);
    let diagnostics: Vec<Value> = lowered.diagnostics.iter().map(diagnostic_summary).collect();
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
        "recovered": false,
        "error_count": lowered
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity >= Severity::Error)
            .count(),
        "warning_count": lowered
            .diagnostics
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
        return Ok(json!({
            "target": args.target,
            "found": false,
            "available_node_sample": available_nodes,
            "graph": {
                "node_count": run.dep_graph.node_count(),
                "edge_count": run.dep_graph.edge_count(),
            },
        }));
    };

    let direction = parse_lineage_direction(args.direction.as_deref())?;
    let value = match direction {
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
    Ok(value)
}

fn run_sast(args: SastArgs) -> Result<Value, ErrorEnvelope> {
    let run = analyze_local_project(&args.project_root)?;
    let facts = FactStore {
        facts: run.fact_store.facts.clone(),
    };
    let mut nodes: Vec<_> = run.dep_graph.nodes.values().collect();
    nodes.sort_by(|a, b| a.logical_id.as_str().cmp(b.logical_id.as_str()));
    let flows: Vec<FlowEnv> = nodes.iter().map(|_| FlowEnv::default()).collect();
    let units: Vec<ScanUnit<'_>> = nodes
        .iter()
        .zip(flows.iter())
        .map(|(node, flow)| ScanUnit {
            unit_logical_id: node.logical_id.as_str(),
            source_file: node.logical_id.as_str(),
            flow,
        })
        .collect();
    let completeness = CompletenessSnapshot {
        catalog_available: run.completeness.catalog_available || run.catalog.is_some(),
        plscope_available: run.completeness.plscope_available,
        files_total: run.completeness.files_total,
        files_recovered: run.completeness.files_recovered,
    };
    let report = run_scan(&sast_rules(), &units, &facts, &completeness);
    match args.format.as_deref().unwrap_or("json") {
        "json" => Ok(json!({
            "project_root": args.project_root,
            "report": report,
            "histogram": plsql_sast::rule_firing_histogram(&report),
            "completeness": completeness,
            "unit_count": units.len(),
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
    Ok(snapshot_response(
        &report,
        snapshot,
        args.include_snapshot.unwrap_or(false),
    ))
}

async fn run_blast_radius(
    cx: &Cx,
    conn: &dyn OracleConnection,
    args: BlastRadiusArgs,
) -> Result<Value, ErrorEnvelope> {
    let report = extract_live_report(cx, conn, &args.schemas, args.include_plscope).await?;
    let snapshot = snapshot_from_report(&report)?;
    let mode = parse_predict_mode(args.mode.as_deref(), PredictMode::LiveSnapshot)?;
    let prediction = predict(&args.changeset, mode);
    Ok(json!({
        "snapshot": snapshot_response(&report, snapshot, args.include_snapshot.unwrap_or(false)),
        "prediction": change_impact_envelope(&prediction, Vec::new()),
    }))
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
) -> Value {
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
        map.insert("catalog_snapshot".to_owned(), json!(snapshot));
    }
    value
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
    fn parse_reports_declarations_without_live_db() {
        let value = run_parse(ParseArgs {
            source: "CREATE OR REPLACE PACKAGE p AS PROCEDURE q; END;".to_owned(),
        })
        .expect("parse succeeds");
        assert_eq!(value["declaration_count"].as_u64(), Some(1));
        assert_eq!(value["recovered"].as_bool(), Some(false));
        assert_eq!(value["declarations"][0]["name"].as_str(), Some("p"));
        assert_eq!(value["declarations"][0]["kind"].as_str(), Some("Package"));
        assert_eq!(
            value["declarations"][0]["span"]["start"]["offset"].as_u64(),
            Some(0)
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
    fn plsql_side_effect_oracle_proves_clean_routine_and_statement() {
        let mut graph = DepGraph::new();
        add_node(&mut graph, 1, "APP.ORDERS", NodeIdentityKind::Table);
        add_node(
            &mut graph,
            2,
            "APP.LOOKUP",
            NodeIdentityKind::StandaloneFunction,
        );

        let run = analysis_run(graph, Some(empty_catalog()));
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

        let run = analysis_run(graph, Some(empty_catalog()));
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
            Classifier::default()
                .classify("SELECT * FROM APP.ORDERS")
                .danger,
            DangerLevel::Safe,
            "the no-engine baseline stays permissive for UDF-free SELECT"
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
