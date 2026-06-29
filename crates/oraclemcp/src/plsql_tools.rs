#![cfg(feature = "plsql-intelligence")]

use std::path::PathBuf;

use asupersync::Cx;
use chrono::Utc;
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_db::{
    CatalogExtractReport, CatalogExtractRequest, CatalogRowSetName, CatalogSchemaFilter, DbError,
    OracleConnection, OracleRow as DbOracleRow, extract_catalog_rowsets,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use plsql_catalog::{
    CatalogCapabilities, CatalogRowSet, CatalogSnapshot, CatalogSnapshotBuilder, CatalogSource,
    CatalogSourceKind, OracleRow as CatalogOracleRow,
};
use plsql_cicd::{ChangeSet, PredictMode, change_impact_envelope, predict};
use plsql_core::{AnalysisProfile, FileId, Severity};
use plsql_depgraph::NodeSelector;
use plsql_doc::{DocSet, extract_doc_comments};
use plsql_engine::{
    AnalysisRequest, analyze_project, engine_doctor_report, engine_full_doctor_report,
};
use plsql_ir::{FactStore, FlowEnv, lower_top_level};
use plsql_lineage::{LineageDirection, dependencies, impact};
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
    let diagnostics: Vec<Value> = lowered
        .diagnostics
        .iter()
        .map(|diagnostic| {
            json!({
                "code": diagnostic.code,
                "severity": format!("{:?}", diagnostic.severity),
                "message": diagnostic.message,
                "unknown_reasons": diagnostic.unknown_reasons,
            })
        })
        .collect();
    let declaration_kinds: Vec<String> = lowered
        .declarations
        .iter()
        .map(|decl| format!("{:?}", decl.kind()))
        .collect();

    Ok(json!({
        "declaration_count": declaration_kinds.len(),
        "declaration_kinds": declaration_kinds,
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
        "diagnostic_count": run.diagnostics.len(),
    }))
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

    #[test]
    fn parse_reports_declarations_without_live_db() {
        let value = run_parse(ParseArgs {
            source: "CREATE OR REPLACE PACKAGE p AS PROCEDURE q; END;".to_owned(),
        })
        .expect("parse succeeds");
        assert_eq!(value["declaration_count"].as_u64(), Some(1));
        assert_eq!(value["recovered"].as_bool(), Some(false));
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
}
