//! Source metadata omitted by the pinned engine's standalone EffectUnit.
//!
//! This projection consumes only grammar-validated public parser tokens and
//! real IR. Remove the formal-header projection when the engine retains exact
//! standalone formal modes and source provenance in its invocation units.

use std::collections::BTreeMap;

use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use plsql_core::{FileId, Span, SymbolInterner};
use plsql_engine::AnalysisRun;
use plsql_ir::{
    Declaration, FactProvenance, FactStore, ParamMode, Statement, TaintSources,
    analyze_flow_bounded, emit_dynamic_sql_facts, emit_flow_facts, lower_ast_statements,
    lower_statement_body, lower_top_level,
};
use plsql_parser::ast::Spanned;
use plsql_parser::{ParseOptions, Token, TokenKind, parse_with_backend};
use plsql_parser_antlr::Antlr4RustBackend;
use plsql_sast::{
    CompletenessSnapshot, Rule, RuleSkippedDiagnostic, ScanReport, ScanUnit, SkipReason, run_scan,
};

pub(super) struct SourceScan {
    pub report: ScanReport,
    pub unit_count: usize,
    /// Denominator for rules_run/rules_gated: one evaluation per source unit.
    pub rule_evaluation_count: usize,
}

pub(super) fn scan(
    run: &AnalysisRun,
    rules: &[Box<dyn Rule>],
    completeness: &CompletenessSnapshot,
) -> Result<SourceScan, ErrorEnvelope> {
    let projected = project_sources(run)?;
    let mut report = ScanReport::default();
    for (id, unit) in &run.invocation_index.units {
        // The rule's flow-fact lookup folds case. Isolate exact source units
        // so quoted routines cannot borrow one another's taint evidence.
        let mut facts = FactStore {
            facts: run
                .fact_store
                .facts
                .iter()
                .filter(|fact| {
                    fact.provenance
                        .source_logical_id
                        .as_deref()
                        .is_none_or(|source| source == id)
                })
                .cloned()
                .collect(),
        };
        let source = projected.get(id);
        let source_file = source.map_or("<unknown source>", |source| source.file.as_str());
        let mut flow = plsql_ir::FlowEnv::default();
        let mut gap = "exact source/formal identity is unavailable";
        let inputs = source.and_then(|source| source.input_names.as_ref());
        if let Some(inputs) = inputs {
            let taint_sources = TaintSources {
                user_input_names: inputs.clone(),
                bind_names: Vec::new(),
            };
            if let Ok(site_flows) = sink_flows(id, &unit.statements, &taint_sources) {
                let (computed, outcome) = analyze_flow_bounded(&unit.statements, &taint_sources);
                if !outcome.limit_hit {
                    let provenance = FactProvenance {
                        component: "oraclemcp-sast-source".to_owned(),
                        component_version: env!("CARGO_PKG_VERSION").to_owned(),
                        run_id: String::new(),
                        source_logical_id: Some(id.clone()),
                        source_file: Some(source_file.to_owned()),
                    };
                    emit_dynamic_sql_facts(
                        &mut facts,
                        &provenance,
                        site_flows.iter().map(|(site, _)| site.clone()),
                    );
                    emit_flow_facts(&mut facts, &provenance, id, site_flows);
                    flow = computed;
                    gap = "";
                } else {
                    gap = "bounded source-flow analysis reached its recursion limit";
                }
            } else {
                gap = "dynamic SQL body traversal is incomplete or reached its recursion limit";
            }
        }
        let mut unit_report = run_scan(
            rules,
            &[ScanUnit {
                unit_logical_id: id,
                source_file,
                flow: &flow,
            }],
            &facts,
            completeness,
        );
        for skipped in &mut unit_report.skipped {
            if skipped.unit == "<analysis-run>" {
                skipped.unit.clone_from(id);
            }
        }
        if !gap.is_empty() {
            unit_report.skipped.push(RuleSkippedDiagnostic {
                rule_id: "SEC001".to_owned(),
                unit: id.clone(),
                reason: SkipReason::MissingFlowFacts,
                detail: gap.to_owned(),
            });
        }
        if let Some(source) = source {
            // The pinned rule emits zero positions. Point at the enclosing
            // real declaration and retain precise engine locations if present.
            for finding in &mut unit_report.findings {
                if finding.location.file == source.file && finding.location.line == 0 {
                    finding.location.line = source.line;
                    finding.location.byte_span = (source.start, source.end);
                }
            }
        }
        report.rules_run += unit_report.rules_run;
        report.rules_gated += unit_report.rules_gated;
        report.findings.extend(unit_report.findings);
        report.skipped.extend(unit_report.skipped);
    }
    report.findings.sort_by(|a, b| {
        (
            &a.rule_id,
            &a.location.file,
            a.location.byte_span,
            &a.message,
        )
            .cmp(&(
                &b.rule_id,
                &b.location.file,
                b.location.byte_span,
                &b.message,
            ))
    });
    report
        .skipped
        .sort_by(|a, b| (&a.rule_id, &a.unit, &a.detail).cmp(&(&b.rule_id, &b.unit, &b.detail)));
    let unit_count = run.invocation_index.units.len();
    Ok(SourceScan {
        report,
        unit_count,
        rule_evaluation_count: rules.len() * unit_count,
    })
}

fn sink_flows(
    id: &str,
    statements: &[Statement],
    taint_sources: &TaintSources,
) -> Result<Vec<(String, plsql_ir::ValueFlow)>, ()> {
    let mut sinks = Vec::new();
    collect_sinks(statements, 0, &mut sinks)?;
    if sinks.len() > 64 {
        return Err(());
    }
    let mut flows = Vec::new();
    for (index, statement) in statements.iter().enumerate() {
        if let Statement::ExecuteImmediate { sql_literal, .. } = statement {
            // The solver iterates its input to a fixpoint. Analyze only the
            // real prefix ending at this sink so later writes cannot taint an
            // earlier SQL expression. This target cannot collide with a local.
            let site = format!("@SAST:{id}:{}", flows.len());
            let mut prefix = statements[..index].to_vec();
            prefix.push(Statement::Assignment {
                target: site.clone(),
                rhs_text: sql_literal.clone(),
            });
            let (flow, outcome) = analyze_flow_bounded(&prefix, taint_sources);
            if outcome.limit_hit {
                return Err(());
            }
            let value = flow.get(&site).ok_or(())?.clone();
            flows.push((site, value));
        }
    }
    // Nested control bodies are retained as source text by this IR. Their
    // sinks cannot be instrumented at an exact program point through its
    // public API; report a gap instead of evaluating them at routine exit.
    if flows.len() != sinks.len() {
        return Err(());
    }
    Ok(flows)
}

fn collect_sinks(
    statements: &[Statement],
    depth: usize,
    sinks: &mut Vec<String>,
) -> Result<(), ()> {
    if depth >= plsql_ir::MAX_RELOWER_DEPTH {
        return Err(());
    }
    for statement in statements {
        match statement {
            Statement::ExecuteImmediate { sql_literal, .. } => sinks.push(sql_literal.clone()),
            Statement::If {
                arms,
                else_body_text,
            } => {
                for arm in arms {
                    collect_sinks(&lower_statement_body(&arm.body_text), depth + 1, sinks)?;
                }
                if let Some(body) = else_body_text {
                    collect_sinks(&lower_statement_body(body), depth + 1, sinks)?;
                }
            }
            Statement::BareLoop { body_text }
            | Statement::ForLoop { body_text, .. }
            | Statement::WhileLoop { body_text, .. } => {
                collect_sinks(&lower_statement_body(body_text), depth + 1, sinks)?
            }
            // The IR block-wrapper helper is private. Preserve the gap rather
            // than create another parser or silently drop a possible sink.
            Statement::NestedBlock { .. } | Statement::Unrecognized { .. } => return Err(()),
            _ => {}
        }
    }
    Ok(())
}

struct UnitSource {
    pub file: String,
    pub line: u32,
    pub start: u32,
    pub end: u32,
    /// None is unknown, distinct from a proven empty formal-input list.
    pub input_names: Option<Vec<String>>,
}

impl UnitSource {
    fn new(file: &str, span: Span, input_names: Option<Vec<String>>) -> Self {
        Self {
            file: file.to_owned(),
            line: span.start.line,
            start: span.start.offset,
            end: span.end.offset,
            input_names,
        }
    }
}

fn project_sources(run: &AnalysisRun) -> Result<BTreeMap<String, UnitSource>, ErrorEnvelope> {
    let mut sources = BTreeMap::new();
    for (index, file) in run.parse_results.iter().enumerate() {
        let source = std::fs::read_to_string(&file.file).map_err(|_| {
            ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                "SAST could not read a source file selected by project analysis",
            )
        })?;
        super::validate_engine_source(&source)?;
        let parsed = parse_with_backend(
            &source,
            FileId::new(u32::try_from(index + 1).map_err(|_| {
                ErrorEnvelope::new(ErrorClass::InvalidArguments, "too many SAST source files")
            })?),
            &Antlr4RustBackend::new(),
            &ParseOptions::default(),
        );
        if !parsed.is_clean() || parsed.was_recovered() {
            return Err(ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                "SAST requires source without syntax errors or parser recovery",
            ));
        }
        let relative = file.file.strip_prefix(&run.project.root).map_err(|_| {
            ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                "SAST source is outside the analyzed project",
            )
        })?;
        let file_name = relative.to_string_lossy().into_owned();
        let mut interner = SymbolInterner::new();
        let lowered = lower_top_level(&parsed.ast, &mut interner);
        for declaration in &lowered.declarations {
            let Some(id) = interner.resolve(declaration.common().name) else {
                continue;
            };
            if let Declaration::Package(package) = declaration {
                for unit in package.units.addressable_units(id) {
                    let inputs = package
                        .units
                        .members
                        .iter()
                        .find(|member| member.unit_id(id) == unit.id)
                        .map(|member| {
                            if matches!(
                                member.overload,
                                plsql_ir::OverloadIdentity::Ambiguous { .. }
                            ) {
                                return None;
                            }
                            Some(
                                member
                                    .params
                                    .iter()
                                    .filter(|param| param.mode != ParamMode::Out)
                                    .map(|param| param.name.clone())
                                    .collect::<Vec<_>>(),
                            )
                        })
                        .unwrap_or_else(|| Some(Vec::new()))
                        .filter(|inputs| {
                            inputs_are_exact(&parsed.cst.token_tape.tokens, unit.span, inputs)
                        });
                    put_source(
                        &mut sources,
                        run,
                        &unit.id,
                        &unit.statements,
                        UnitSource::new(&file_name, unit.span, inputs),
                    );
                }
            } else if matches!(
                declaration,
                Declaration::Procedure(_) | Declaration::Function(_)
            ) {
                let span = declaration.common().span;
                // Match spans, not declaration positions: the lowerer may omit
                // an unsupported declaration before this routine.
                let body = parsed
                    .ast
                    .root
                    .declarations
                    .iter()
                    .zip(&parsed.ast.body_statements)
                    .find(|(decl, _)| decl.span() == span)
                    .map(|(_, statements)| lower_ast_statements(statements));
                if let Some(body) = body {
                    put_source(
                        &mut sources,
                        run,
                        id,
                        &body,
                        UnitSource::new(
                            &file_name,
                            span,
                            standalone_inputs(&parsed.cst.token_tape.tokens, span, id),
                        ),
                    );
                }
            }
        }
    }
    Ok(sources)
}

fn put_source(
    sources: &mut BTreeMap<String, UnitSource>,
    run: &AnalysisRun,
    id: &str,
    statements: &[Statement],
    mut source: UnitSource,
) {
    // A changed source, engine identity drift, or merged/ambiguous body cannot
    // authorize a guessed formal-to-sink flow.
    if !run
        .invocation_index
        .units
        .get(id)
        .is_some_and(|unit| unit.source_complete && unit.statements == statements)
    {
        source.input_names = None;
    }
    if let Some(previous) = sources.get_mut(id) {
        if previous.input_names.is_some() && source.input_names.is_none() {
            return;
        }
        if previous.input_names.is_some() && source.input_names.is_some() {
            previous.input_names = None;
            return;
        }
    }
    sources.insert(id.to_owned(), source);
}

fn standalone_inputs(tokens: &[Token], span: Span, expected_id: &str) -> Option<Vec<String>> {
    let tokens: Vec<_> = tokens
        .iter()
        .filter(|token| {
            token.span.start.offset >= span.start.offset && token.span.end.offset <= span.end.offset
        })
        .take(8193)
        .collect();
    let mut cursor = tokens.iter().position(|token| {
        token.kind == TokenKind::Keyword
            && (token.text.eq_ignore_ascii_case("PROCEDURE")
                || token.text.eq_ignore_ascii_case("FUNCTION"))
    })? + 1;
    let mut names = vec![identifier(tokens.get(cursor)?)?];
    cursor += 1;
    while tokens
        .get(cursor)
        .is_some_and(|token| token.kind == TokenKind::Dot)
    {
        names.push(identifier(tokens.get(cursor + 1)?)?);
        cursor += 2;
    }
    if names.join(".") != expected_id {
        return None;
    }
    if tokens.get(cursor)?.kind != TokenKind::LParen {
        return ["AS", "IS", "RETURN", "AUTHID"]
            .iter()
            .any(|word| {
                tokens[cursor].kind == TokenKind::Keyword
                    && tokens[cursor].text.eq_ignore_ascii_case(word)
            })
            .then(Vec::new);
    }
    cursor += 1;
    let mut depth = 1usize;
    let mut begin = cursor;
    let mut inputs = Vec::new();
    while cursor < tokens.len() && cursor < 8192 {
        match tokens[cursor].kind {
            TokenKind::LParen => {
                depth += 1;
                if depth > 64 {
                    return None;
                }
            }
            TokenKind::RParen => {
                depth -= 1;
                if depth == 0 {
                    add_input(&tokens[begin..cursor], &mut inputs)?;
                    return inputs_are_exact(tokens.iter().copied(), span, &inputs)
                        .then_some(inputs);
                }
            }
            TokenKind::Comma if depth == 1 => {
                add_input(&tokens[begin..cursor], &mut inputs)?;
                if inputs.len() > 1024 {
                    return None;
                }
                begin = cursor + 1;
            }
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn identifier(token: &Token) -> Option<String> {
    let name = match token.kind {
        // Oracle allows contextual keywords in these grammar-validated name
        // positions (for example the routine name `p`).
        TokenKind::Identifier | TokenKind::Keyword | TokenKind::BuiltIn => {
            token.text.to_ascii_uppercase()
        }
        TokenKind::QuotedIdentifier => token
            .text
            .strip_prefix('"')?
            .strip_suffix('"')?
            .replace("\"\"", "\""),
        _ => return None,
    };
    (!name.contains(['.', '#', '(', ')', '@'])).then_some(name)
}

fn inputs_are_exact<'a>(
    tokens: impl IntoIterator<Item = &'a Token>,
    span: Span,
    inputs: &[String],
) -> bool {
    let mut count = 0;
    for token in tokens.into_iter().filter(|token| {
        token.span.start.offset >= span.start.offset && token.span.end.offset <= span.end.offset
    }) {
        count += 1;
        if count > 8192 {
            return false;
        }
        if let Some(name) = identifier(token)
            && inputs
                .iter()
                .any(|input| name.eq_ignore_ascii_case(input) && name != *input)
        {
            return false;
        }
    }
    true
}

fn add_input(tokens: &[&Token], inputs: &mut Vec<String>) -> Option<()> {
    let name = identifier(tokens.first()?)?;
    let mode = tokens.get(1)?;
    if !(mode.kind == TokenKind::Keyword && mode.text.eq_ignore_ascii_case("OUT")) {
        inputs.push(name);
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_routine_name_retains_its_formal_identity() {
        let project = tempfile::tempdir().unwrap();
        let source = "CREATE OR REPLACE PROCEDURE p(p_name VARCHAR2) AS BEGIN EXECUTE IMMEDIATE 'DELETE FROM ' || DBMS_ASSERT.NOOP(p_name); END;";
        std::fs::write(project.path().join("routine.sql"), source).unwrap();
        let run = super::super::analyze_local_project(project.path().to_str().unwrap()).unwrap();
        let projected = project_sources(&run).unwrap();
        assert_eq!(
            projected
                .get("P")
                .and_then(|unit| unit.input_names.as_ref()),
            Some(&vec!["P_NAME".to_owned()]),
            "units={:?}",
            run.invocation_index.units
        );
    }

    #[test]
    fn standalone_projection_matches_the_real_engine_identity_and_formal_modes() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("unsafe.sql"),
            "CREATE OR REPLACE PROCEDURE w4_unsafe(p_name VARCHAR2, p_out OUT VARCHAR2, p_both IN OUT VARCHAR2, \"pQuoted\" VARCHAR2 DEFAULT substr('a,b',1,2)) AUTHID DEFINER AS BEGIN EXECUTE IMMEDIATE 'DELETE FROM ' || p_name; END;\n"
        ).unwrap();
        let run = super::super::analyze_local_project(project.path().to_str().unwrap()).unwrap();
        // Pin the public parser projection to the actual engine's exact unit
        // identity. A dependency bump that changes either side must fail here.
        assert!(run.invocation_index.units.contains_key("W4_UNSAFE"));
        let projected = project_sources(&run).unwrap();
        let source = projected
            .get("W4_UNSAFE")
            .expect("exact engine unit projected");
        assert_eq!(
            source.input_names.as_deref(),
            Some(
                [
                    "P_NAME".to_owned(),
                    "P_BOTH".to_owned(),
                    "pQuoted".to_owned()
                ]
                .as_slice()
            )
        );
        assert_eq!(source.file, "unsafe.sql");
        assert_eq!(source.line, 1);
        assert_eq!(source.start, 0);
        assert!(source.end > source.start);
    }

    #[test]
    fn a_source_body_that_no_longer_matches_the_engine_keeps_taint_unknown() {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().join("routine.sql");
        std::fs::write(
            &path,
            "CREATE OR REPLACE PROCEDURE p(x VARCHAR2) AS BEGIN NULL; END;",
        )
        .unwrap();
        let run = super::super::analyze_local_project(project.path().to_str().unwrap()).unwrap();
        std::fs::write(
            &path,
            "CREATE OR REPLACE PROCEDURE p(x VARCHAR2) AS BEGIN EXECUTE IMMEDIATE x; END;",
        )
        .unwrap();
        let projected = project_sources(&run).unwrap();
        assert!(projected.get("P").unwrap().input_names.is_none());
    }

    #[test]
    fn quoted_formals_that_the_flow_lookup_would_merge_stay_unknown() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("quoted.sql"), "CREATE OR REPLACE PROCEDURE p(\"x\" VARCHAR2, \"X\" OUT VARCHAR2) AS BEGIN EXECUTE IMMEDIATE \"x\"; END;").unwrap();
        let run = super::super::analyze_local_project(project.path().to_str().unwrap()).unwrap();
        let projected = project_sources(&run).unwrap();
        assert!(projected.get("P").unwrap().input_names.is_none());
    }
}
