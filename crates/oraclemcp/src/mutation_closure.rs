//! Real engine binding for the database mutation collector's source-proof port.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write;

use asupersync::Cx;
use oraclemcp_db::mutation_closure::{
    MAX_MUTATION_SCOPES, MAX_MUTATION_SOURCE_BYTES, MutationEffectOracle, MutationRequest,
    MutationRoutineProof, MutationRoutineSource, MutationRoutineUse, read_mutation_routine_source,
};
use oraclemcp_db::{
    CatalogQueryId, FgaClosure, FgaStatementKind, OracleConnection, OracleRow, fga_closure,
    observe_relation_security, read_closure_database_identity, resolved_relations_read_purity,
    run_catalog_query,
};
use oraclemcp_guard::mutation_closure::{
    MutationColumns, MutationStatementKind, MutationUnavailableReason,
};
use oraclemcp_guard::{
    CatalogObjectKind, Purity, ResolvedIdentity, ResolvedObject, RoutineEffect, RoutineIdentifier,
    RoutineRef, SideEffectOracle,
};
use plsql_catalog::{
    CatalogCapabilities, CatalogRowSet, CatalogSnapshotBuilder, CatalogSource, CatalogSourceKind,
};
use plsql_core::{AnalysisProfile, CompletenessPosture, FileId, SymbolInterner};
use plsql_parser::{ParseOptions, TokenKind, parse_with_backend};
use plsql_parser_antlr::Antlr4RustBackend;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Analyze fresh collector sources with the actual PL/SQL engine. There is no
/// source-text purity fallback; incomplete or unsupported analysis is Unknown.
pub struct EngineMutationEffects;

type Unknown = MutationUnavailableReason;

fn digest(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn encoded<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("mutation proof contains serializable values")
}

fn required<'a>(row: &'a OracleRow, name: &str) -> Result<&'a str, Unknown> {
    row.text(name)
        .filter(|text| !text.is_empty())
        .ok_or(Unknown::CatalogIncomplete)
}

fn simple(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_uppercase()
        && name.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"_$#".contains(&byte)
        })
}

fn header_identifier(text: &str) -> String {
    if let Some(quoted) = text
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
    {
        quoted.replace("\"\"", "\"")
    } else {
        text.to_ascii_uppercase()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Dependency {
    from_owner: String,
    from_name: String,
    from_type: String,
    owner: String,
    name: String,
    object_type: String,
    object_id: u64,
    last_ddl_time: String,
    dependency_type: String,
}

struct Sources {
    root: MutationRoutineSource,
    members: Vec<MutationRoutineSource>,
    dependencies: Vec<Dependency>,
    synthetic: bool,
}

async fn dependencies(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    kind: &str,
) -> Result<Vec<Dependency>, Unknown> {
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::ClosureDependencies,
        &[owner.into(), name.into(), kind.into(), 513_i64.into()],
    )
    .await
    .map_err(|_| Unknown::CatalogUnreadable)?;
    if rows.len() >= 513 {
        return Err(Unknown::RowCapExhausted);
    }
    rows.iter()
        .map(|row| {
            // An unobserved link column is not proof of a local dependency.
            if row
                .cell("REFERENCED_LINK_NAME")
                .is_none_or(|cell| cell.value.is_some())
            {
                return Err(Unknown::UnsupportedMechanism);
            }
            if required(row, "TARGET_STATUS")? != "VALID" {
                return Err(Unknown::SourceUnavailable);
            }
            Ok(Dependency {
                from_owner: owner.into(),
                from_name: name.into(),
                from_type: kind.into(),
                owner: required(row, "REFERENCED_OWNER")?.into(),
                name: required(row, "REFERENCED_NAME")?.into(),
                object_type: required(row, "REFERENCED_TYPE")?.into(),
                object_id: row
                    .parse_i64("TARGET_OBJECT_ID")
                    .and_then(|id| u64::try_from(id).ok())
                    .filter(|id| *id != 0)
                    .ok_or(Unknown::CatalogIncomplete)?,
                last_ddl_time: required(row, "TARGET_LAST_DDL_TIME")?.into(),
                dependency_type: required(row, "DEPENDENCY_TYPE")?.into(),
            })
        })
        .collect()
}

fn expression_source(source: &MutationRoutineSource) -> Result<MutationRoutineSource, Unknown> {
    let mut parameters = Vec::new();
    for (name, kind) in &source.expression_columns {
        if !simple(name) {
            return Err(Unknown::UnsupportedMechanism);
        }
        let kind = match kind.as_str() {
            "NUMBER" | "FLOAT" | "BINARY_FLOAT" | "BINARY_DOUBLE" | "VARCHAR2" | "NVARCHAR2"
            | "CHAR" | "NCHAR" | "DATE" | "CLOB" | "NCLOB" | "RAW" => kind.as_str(),
            kind if kind.starts_with("TIMESTAMP") => "TIMESTAMP",
            _ => return Err(Unknown::UnsupportedMechanism),
        };
        parameters.push(format!("\"{name}\" {kind}"));
    }
    let name = format!("OMCP_MUT_{}", &source.source_sha256[..20]);
    if source.name == name {
        return Err(Unknown::IdentityMismatch);
    }
    let parameters = if parameters.is_empty() {
        String::new()
    } else {
        format!("({})", parameters.join(", "))
    };
    let text = format!(
        "FUNCTION {name}{parameters} RETURN NUMBER AUTHID DEFINER IS BEGIN RETURN ({}); END;\n",
        source.source
    );
    let mut root = source.clone();
    root.name = name;
    root.member = None;
    root.subprogram_id = Some(1);
    root.object_type = "FUNCTION".into();
    root.expression_storage_type = None;
    root.source_sha256 = digest(text.as_bytes());
    root.source = text;
    Ok(root)
}

async fn load_sources(
    cx: &Cx,
    conn: &dyn OracleConnection,
    input: &MutationRoutineSource,
) -> Result<Sources, Unknown> {
    crate::plsql_tools::validate_engine_source(&input.source)
        .map_err(|_| Unknown::SourceUnavailable)?;
    if !simple(&input.owner)
        || !simple(&input.name)
        || digest(input.source.as_bytes()) != input.source_sha256
    {
        return Err(Unknown::EffectSourceMismatch);
    }
    let synthetic = input.object_type == "EXPRESSION";
    let root = if synthetic {
        expression_source(input)?
    } else {
        let mut fresh = read_mutation_routine_source(
            cx,
            conn,
            &input.owner,
            &input.name,
            &input.object_type,
            input.member.as_deref(),
        )
        .await?;
        fresh.use_context = input.use_context;
        if fresh != *input {
            return Err(Unknown::EffectSourceMismatch);
        }
        fresh
    };
    let mut members = vec![root.clone()];
    let mut queue = VecDeque::from([(
        input.owner.clone(),
        input.name.clone(),
        if synthetic {
            match input.expression_storage_type.as_deref() {
                Some("TABLE") => "TABLE".into(),
                Some("INDEX") => "INDEX".into(),
                _ => return Err(Unknown::InvalidInput),
            }
        } else {
            input.object_type.clone()
        },
    )]);
    let mut visited = BTreeSet::new();
    let mut loaded = BTreeSet::from([(
        root.owner.clone(),
        root.name.clone(),
        root.object_type.clone(),
    )]);
    let mut captured = Vec::new();
    let mut bytes = root.source.len();
    let mut rows = input.source_line_count;
    while let Some((owner, name, kind)) = queue.pop_front() {
        if !visited.insert((owner.clone(), name.clone(), kind.clone())) {
            continue;
        }
        if visited.len() > MAX_MUTATION_SCOPES {
            return Err(Unknown::ClosureCapExhausted);
        }
        let current = dependencies(cx, conn, &owner, &name, &kind).await?;
        rows = rows.saturating_add(current.len());
        if rows > 16_384 {
            return Err(Unknown::ClosureCapExhausted);
        }
        for dependency in current {
            if !simple(&dependency.owner) || !simple(&dependency.name) {
                return Err(Unknown::UnsupportedMechanism);
            }
            if synthetic && dependency.owner == root.owner && dependency.name == root.name {
                return Err(Unknown::IdentityMismatch);
            }
            let source_kind = match dependency.object_type.as_str() {
                "FUNCTION" => Some("FUNCTION"),
                "PROCEDURE" => Some("PROCEDURE"),
                "PACKAGE"
                    if dependency.owner == "SYS"
                        && matches!(dependency.name.as_str(), "STANDARD" | "DBMS_STANDARD") =>
                {
                    None
                }
                "PACKAGE" | "PACKAGE BODY" => Some("PACKAGE BODY"),
                "TABLE" | "VIEW" | "SEQUENCE" => None,
                _ => return Err(Unknown::UnsupportedMechanism),
            };
            if let Some(kind) = source_kind
                && loaded.insert((
                    dependency.owner.clone(),
                    dependency.name.clone(),
                    kind.to_owned(),
                ))
            {
                let source = read_mutation_routine_source(
                    cx,
                    conn,
                    &dependency.owner,
                    &dependency.name,
                    kind,
                    None,
                )
                .await?;
                bytes = bytes.saturating_add(source.source.len());
                rows = rows.saturating_add(source.source_line_count);
                if bytes > MAX_MUTATION_SOURCE_BYTES || rows > 16_384 {
                    return Err(Unknown::ClosureCapExhausted);
                }
                queue.push_back((
                    dependency.owner.clone(),
                    dependency.name.clone(),
                    kind.to_owned(),
                ));
                members.push(source);
            }
            captured.push(dependency);
        }
    }
    members.sort_by_key(|source| {
        (
            source.owner.clone(),
            source.name.clone(),
            source.object_type.clone(),
        )
    });
    captured.sort_by_key(encoded);
    Ok(Sources {
        root,
        members,
        dependencies: captured,
        synthetic,
    })
}

fn qualified_source(source: &MutationRoutineSource) -> Result<String, Unknown> {
    if !simple(&source.owner)
        || !simple(&source.name)
        || !matches!(
            source.object_type.as_str(),
            "FUNCTION" | "PROCEDURE" | "TRIGGER" | "PACKAGE BODY"
        )
    {
        return Err(Unknown::UnsupportedMechanism);
    }
    crate::plsql_tools::validate_engine_source(&source.source)
        .map_err(|_| Unknown::SourceUnavailable)?;
    let text = format!("CREATE OR REPLACE {}", source.source);
    crate::plsql_tools::validate_engine_source(&text).map_err(|_| Unknown::SourceUnavailable)?;
    let parsed = parse_with_backend(
        &text,
        FileId::new(1),
        &Antlr4RustBackend::new(),
        &ParseOptions::default(),
    );
    if !parsed.is_clean() || parsed.was_recovered() {
        return Err(Unknown::SourceUnavailable);
    }
    let tokens = &parsed.cst.token_tape.tokens;
    if tokens.iter().any(|token| {
        token.kind != TokenKind::StringLiteral
            && (token.text.contains('@')
                || token.text.contains("$$")
                || token.text.eq_ignore_ascii_case("$IF"))
    }) {
        return Err(Unknown::UnsupportedMechanism);
    }
    let header: Vec<_> = ["CREATE", "OR", "REPLACE"]
        .into_iter()
        .chain(source.object_type.split_ascii_whitespace())
        .collect();
    if tokens.len() <= header.len()
        || !tokens
            .iter()
            .take(header.len())
            .map(|token| token.text.to_ascii_uppercase())
            .eq(header.into_iter().map(str::to_owned))
    {
        return Err(Unknown::IdentityMismatch);
    }
    let cursor = 3 + source.object_type.split_ascii_whitespace().count();
    let first = tokens.get(cursor).ok_or(Unknown::SourceUnavailable)?;
    let last = if tokens
        .get(cursor + 1)
        .is_some_and(|token| token.kind == TokenKind::Dot)
    {
        if header_identifier(&first.text) != source.owner {
            return Err(Unknown::IdentityMismatch);
        }
        tokens.get(cursor + 2).ok_or(Unknown::SourceUnavailable)?
    } else {
        first
    };
    if header_identifier(&last.text) != source.name {
        return Err(Unknown::IdentityMismatch);
    }
    let mut interner = SymbolInterner::new();
    let lowered = plsql_ir::lower_top_level(&parsed.ast, &mut interner);
    let [declaration] = lowered.declarations.as_slice() else {
        return Err(Unknown::SourceUnavailable);
    };
    let correct_kind = match source.object_type.as_str() {
        "FUNCTION" => matches!(declaration, plsql_ir::Declaration::Function(_)),
        "PROCEDURE" => matches!(declaration, plsql_ir::Declaration::Procedure(_)),
        "TRIGGER" => matches!(declaration, plsql_ir::Declaration::Trigger(_)),
        "PACKAGE BODY" => matches!(declaration, plsql_ir::Declaration::Package(_)),
        _ => false,
    };
    if !correct_kind {
        return Err(Unknown::SourceUnavailable);
    }
    let end = declaration.common().span.end.offset;
    if tokens
        .iter()
        .any(|token| token.span.start.offset >= end && token.text != ";" && token.text != "/")
    {
        return Err(Unknown::SourceUnavailable);
    }
    let start = usize::try_from(first.span.start.offset).map_err(|_| Unknown::SourceUnavailable)?;
    let end = usize::try_from(last.span.end.offset).map_err(|_| Unknown::SourceUnavailable)?;
    if text.get(start..end).is_none() {
        return Err(Unknown::SourceUnavailable);
    }
    let mut qualified = text;
    qualified.replace_range(
        start..end,
        &format!("\"{}\".\"{}\"", source.owner, source.name),
    );
    crate::plsql_tools::validate_engine_source(&qualified)
        .map_err(|_| Unknown::SourceUnavailable)?;
    Ok(qualified)
}

fn catalog(sources: &Sources) -> Result<plsql_catalog::CatalogSnapshot, Unknown> {
    let mut builder = CatalogSnapshotBuilder::new(
        AnalysisProfile::default(),
        CatalogCapabilities::default(),
        CatalogSource {
            kind: CatalogSourceKind::LiveConnection,
            description: Some("hash-bound mutation callback closure".into()),
            ..Default::default()
        },
        chrono::Utc::now(),
    );
    for (owner, name, kind) in sources
        .members
        .iter()
        .map(|source| (&source.owner, &source.name, &source.object_type))
        .chain(
            sources
                .dependencies
                .iter()
                .map(|dependency| (&dependency.owner, &dependency.name, &dependency.object_type)),
        )
    {
        let mut row = plsql_catalog::OracleRow::default();
        for (column, value) in [
            ("OWNER", owner.as_str()),
            ("OBJECT_NAME", name.as_str()),
            ("OBJECT_TYPE", kind.as_str()),
            ("STATUS", "VALID"),
        ] {
            row.insert(column, "VARCHAR2", Some(value.to_owned()));
        }
        builder
            .apply_row(CatalogRowSet::Objects, &row)
            .map_err(|_| Unknown::CatalogIncomplete)?;
    }
    for dependency in &sources.dependencies {
        let mut row = plsql_catalog::OracleRow::default();
        for (column, value) in [
            ("OWNER", dependency.from_owner.as_str()),
            ("NAME", dependency.from_name.as_str()),
            ("TYPE", dependency.from_type.as_str()),
            ("REFERENCED_OWNER", dependency.owner.as_str()),
            ("REFERENCED_NAME", dependency.name.as_str()),
            ("REFERENCED_TYPE", dependency.object_type.as_str()),
            ("DEPENDENCY_TYPE", dependency.dependency_type.as_str()),
        ] {
            row.insert(column, "VARCHAR2", Some(value.to_owned()));
        }
        builder
            .apply_row(CatalogRowSet::Dependencies, &row)
            .map_err(|_| Unknown::CatalogIncomplete)?;
    }
    builder.finish().map_err(|_| Unknown::CatalogIncomplete)
}

fn routine(source: &MutationRoutineSource) -> RoutineRef {
    RoutineRef {
        schema: Some(RoutineIdentifier::new(&source.owner, true)),
        package: source
            .member
            .as_ref()
            .map(|_| RoutineIdentifier::new(&source.name, true)),
        member: RoutineIdentifier::new(source.member.as_deref().unwrap_or(&source.name), true),
        overload: source.subprogram_id,
    }
}

fn qualified_id(source: &MutationRoutineSource) -> String {
    match &source.member {
        Some(member) => format!("{}.{}.{member}", source.owner, source.name),
        None => format!("{}.{}", source.owner, source.name),
    }
}

fn constant_policy_returns(
    source: &str,
    statements: &[plsql_ir::Statement],
) -> Result<usize, Unknown> {
    use plsql_ir::Statement;
    let mut returns = 0;
    for statement in statements {
        match statement {
            Statement::Return { value_text } => {
                let text = value_text
                    .as_deref()
                    .map(str::trim)
                    .ok_or(Unknown::EffectProofUnavailable)?;
                if !text.eq_ignore_ascii_case("NULL") && !matches!(text, "'1=1'" | "'1 = 1'") {
                    // Other predicates need their own SQL/name/effect proof;
                    // a pure PL/SQL string builder does not supply that proof.
                    return Err(Unknown::EffectProofUnavailable);
                }
                returns += 1;
            }
            Statement::If { .. }
            | Statement::BareLoop { .. }
            | Statement::ForLoop { .. }
            | Statement::WhileLoop { .. }
            | Statement::NestedBlock { .. }
            | Statement::Null
            | Statement::Assignment { .. }
            | Statement::Raise { .. }
            | Statement::Exit { .. }
            | Statement::ExecuteImmediate { .. }
            | Statement::Sql { .. }
            | Statement::TransactionControl { .. }
            | Statement::Unrecognized { .. } => {}
        }
    }
    let parsed = parse_with_backend(
        source,
        FileId::new(1),
        &Antlr4RustBackend::new(),
        &ParseOptions::default(),
    );
    if !parsed.is_clean() || parsed.was_recovered() {
        return Err(Unknown::EffectProofUnavailable);
    }
    let keywords = parsed
        .cst
        .token_tape
        .tokens
        .iter()
        .filter(|token| {
            !matches!(
                token.kind,
                TokenKind::StringLiteral | TokenKind::QuotedIdentifier
            ) && token.text.eq_ignore_ascii_case("RETURN")
        })
        .count();
    // One RETURN belongs to the function result type. Any other keyword must
    // have a top-level IR Return with an admitted constant predicate. Extra
    // declarations, nested bodies and exception handlers fail closed.
    if returns == 0 || keywords != returns + 1 {
        return Err(Unknown::EffectProofUnavailable);
    }
    Ok(returns)
}

fn analyze(
    sources: &Sources,
) -> Result<(plsql_engine::AnalysisRun, plsql_engine::InvocationClosureV1), Unknown> {
    let project = tempfile::tempdir().map_err(|_| Unknown::EffectProofUnavailable)?;
    for (index, source) in sources.members.iter().enumerate() {
        std::fs::write(
            project.path().join(format!("unit_{index}.sql")),
            qualified_source(source)?,
        )
        .map_err(|_| Unknown::EffectProofUnavailable)?;
    }
    let snapshot = project.path().join("catalog.json");
    plsql_catalog::export_snapshot_to_json(&catalog(sources)?, &snapshot)
        .map_err(|_| Unknown::EffectProofUnavailable)?;
    let run = plsql_engine::analyze_project(plsql_engine::AnalysisRequest {
        project_root: project.path().to_owned(),
        catalog_source: plsql_engine::CatalogSourceConfig::Snapshot(snapshot),
        cache: plsql_engine::CacheConfig {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    })
    .map_err(|_| Unknown::EffectProofUnavailable)?;
    if run.completeness.posture != CompletenessPosture::Clean
        || run.catalog.is_none()
        || !run.completeness.catalog_available
    {
        return Err(Unknown::EffectProofUnavailable);
    }
    let id = qualified_id(&sources.root);
    let units: Vec<_> = run
        .invocation_index
        .units
        .values()
        .filter(|unit| {
            unit.id
                .split_once('#')
                .map_or(unit.id.as_str(), |(base, _)| base)
                == id
        })
        .collect();
    let [unit] = units.as_slice() else {
        return Err(Unknown::EffectProofUnavailable);
    };
    let closure = run
        .invocation_index
        .closure(&plsql_engine::InvocationShapeV1 {
            routine_id: unit.id.clone(),
            named_arguments: unit
                .params
                .iter()
                .filter(|param| !param.has_default)
                .map(|param| param.name.clone())
                .collect(),
            ..Default::default()
        });
    if !closure.clean || !closure.unknown_reasons.is_empty() || !closure.units.contains(&unit.id) {
        return Err(Unknown::EffectProofUnavailable);
    }
    if sources.root.use_context == MutationRoutineUse::VpdPolicy
        && constant_policy_returns(&qualified_source(&sources.root)?, &unit.statements)? == 0
    {
        return Err(Unknown::EffectProofUnavailable);
    }
    Ok((run, closure))
}

fn relation(dependency: &Dependency) -> Result<ResolvedObject, Unknown> {
    let kind = match dependency.object_type.as_str() {
        "TABLE" => CatalogObjectKind::Table,
        "VIEW" => CatalogObjectKind::View,
        _ => return Err(Unknown::UnsupportedMechanism),
    };
    Ok(ResolvedObject {
        owner: dependency.owner.clone(),
        name: dependency.name.clone(),
        kind,
        container: None,
        member: None,
        overloads: Vec::new(),
        quote_exact: true,
        synonym_chain: Vec::new(),
        db_link: None,
        identity: ResolvedIdentity {
            object_id: dependency.object_id,
            edition: None,
        },
    })
}

async fn prove_read_dependencies(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sources: &Sources,
) -> Result<(), Unknown> {
    let mut seen = BTreeSet::new();
    for dependency in &sources.dependencies {
        if !matches!(dependency.object_type.as_str(), "TABLE" | "VIEW")
            || !seen.insert((dependency.owner.clone(), dependency.name.clone()))
        {
            continue;
        }
        let relation = relation(dependency)?;
        let relations = std::slice::from_ref(&relation);
        if resolved_relations_read_purity(cx, conn, relations, &[])
            .await
            .map_err(|_| Unknown::CatalogUnreadable)?
            != Purity::ProvenReadOnly
            || !matches!(
                fga_closure(cx, conn, relations, FgaStatementKind::Select).await,
                FgaClosure::ProvenReadOnly
            )
        {
            return Err(Unknown::EffectProofUnavailable);
        }
        observe_relation_security(cx, conn, relations)
            .await
            .map_err(|_| Unknown::EffectProofUnavailable)?;
    }
    Ok(())
}

fn mutations(
    sources: &Sources,
    run: &plsql_engine::AnalysisRun,
    closure: &plsql_engine::InvocationClosureV1,
) -> Result<Vec<MutationRequest>, Unknown> {
    let mut mutations = BTreeMap::new();
    for edge in &run.dep_graph.edges {
        if edge.kind != plsql_depgraph::EdgeKind::Writes {
            continue;
        }
        let from = run
            .dep_graph
            .nodes
            .get(&edge.from)
            .ok_or(Unknown::EffectProofUnavailable)?;
        if !closure.units.contains(from.logical_id.as_str()) {
            continue;
        }
        let to = run
            .dep_graph
            .nodes
            .get(&edge.to)
            .ok_or(Unknown::EffectProofUnavailable)?;
        let target = to.logical_id.as_str();
        let caller_owner = from
            .logical_id
            .as_str()
            .split('.')
            .next()
            .ok_or(Unknown::IdentityMismatch)?;
        let candidates: Vec<_> = sources
            .dependencies
            .iter()
            .filter(|dependency| {
                if !matches!(dependency.object_type.as_str(), "TABLE" | "VIEW") {
                    return false;
                }
                if target.contains('.') {
                    format!("{}.{}", dependency.owner, dependency.name) == target
                } else {
                    dependency.name == target
                }
            })
            .collect();
        let preferred: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|dependency| dependency.owner == caller_owner)
            .collect();
        let candidate_set = if preferred.is_empty() {
            &candidates
        } else {
            &preferred
        };
        let identities: BTreeSet<_> = candidate_set
            .iter()
            .map(|dependency| (&dependency.owner, &dependency.name, dependency.object_id))
            .collect();
        if identities.len() != 1 {
            return Err(Unknown::EffectProofUnavailable);
        }
        let dependency = candidate_set[0];
        if dependency.object_type != "TABLE" {
            return Err(Unknown::UnsupportedMechanism);
        }
        mutations.insert(
            (dependency.owner.clone(), dependency.name.clone()),
            MutationRequest {
                target: relation(dependency)?,
                statement_kind: MutationStatementKind::Merge,
                columns: MutationColumns::All,
            },
        );
    }
    if mutations.len() > MAX_MUTATION_SCOPES {
        return Err(Unknown::ClosureCapExhausted);
    }
    Ok(mutations.into_values().collect())
}

#[async_trait::async_trait(?Send)]
impl MutationEffectOracle for EngineMutationEffects {
    async fn prove_source(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
        source: &MutationRoutineSource,
    ) -> Result<MutationRoutineProof, Unknown> {
        let identity = read_closure_database_identity(cx, conn)
            .await
            .map_err(|_| Unknown::CatalogUnreadable)?;
        let sources = load_sources(cx, conn, source).await?;
        let (run, closure) = analyze(&sources)?;
        let mut reference = routine(&sources.root);
        if sources.root.object_type == "PACKAGE BODY" {
            // Source fetching required exactly one catalog member with this name;
            // the engine must independently have exactly one source unit too.
            reference.overload = None;
        }
        let effects = crate::plsql_tools::PlsqlSideEffectOracle::from_analysis_run(&run)
            .routine_effects(&reference);
        if effects
            .iter()
            .any(|effect| effect == RoutineEffect::Unknown)
        {
            return Err(Unknown::EffectProofUnavailable);
        }
        if effects
            .iter()
            .any(|effect| matches!(effect, RoutineEffect::ReadDb | RoutineEffect::Dml))
        {
            prove_read_dependencies(cx, conn, &sources).await?;
        }
        let mutations = mutations(&sources, &run, &closure)?;
        if effects.iter().any(|effect| effect == RoutineEffect::Dml) && mutations.is_empty() {
            return Err(Unknown::EffectProofUnavailable);
        }
        let current = load_sources(cx, conn, source).await?;
        if encoded(&sources.members) != encoded(&current.members)
            || sources.dependencies != current.dependencies
            || read_closure_database_identity(cx, conn)
                .await
                .map_err(|_| Unknown::CatalogUnreadable)?
                != identity
        {
            return Err(Unknown::EffectSourceMismatch);
        }
        let fingerprint = digest(&encoded(&(
            "mutation-engine/v1",
            identity,
            source,
            sources.synthetic,
            &sources.members,
            &sources.dependencies,
            &effects,
            oraclemcp_guard::SYS_EFFECTS_TOML,
        )));
        Ok(MutationRoutineProof {
            use_context: source.use_context,
            source_sha256: source.source_sha256.clone(),
            closure_fingerprint: fingerprint,
            effects,
            mutations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statements(source: &str) -> Vec<plsql_ir::Statement> {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("policy.sql"), source).unwrap();
        let run = plsql_engine::analyze_project(plsql_engine::AnalysisRequest {
            project_root: project.path().to_owned(),
            cache: plsql_engine::CacheConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        run.invocation_index
            .units
            .get("APP.PF")
            .unwrap()
            .statements
            .clone()
    }

    #[test]
    fn policy_predicate_returns_require_complete_top_level_coverage() {
        for body in [
            "BEGIN RETURN NULL; END;",
            "BEGIN RETURN '1=1'; END;",
            "BEGIN RETURN '1 = 1'; END;",
        ] {
            let source = format!(
                "CREATE OR REPLACE FUNCTION APP.PF(S VARCHAR2, O VARCHAR2) RETURN VARCHAR2 IS {body}"
            );
            let statements = statements(&source);
            assert_eq!(constant_policy_returns(&source, &statements), Ok(1));
        }
        for body in [
            "BEGIN RETURN 'APP.LOG_HIT() = 1'; END;",
            "BEGIN IF S = 'X' THEN RETURN NULL; END IF; RETURN '1=1'; END;",
            "BEGIN IF S = 'X' THEN RETURN 'APP.LOG_HIT() = 1'; END IF; RETURN NULL; END;",
            "BEGIN RETURN NULL; EXCEPTION WHEN OTHERS THEN RETURN 'APP.LOG_HIT() = 1'; END;",
            "BEGIN RETURN ''; END;",
        ] {
            let source = format!(
                "CREATE OR REPLACE FUNCTION APP.PF(S VARCHAR2, O VARCHAR2) RETURN VARCHAR2 IS {body}"
            );
            let statements = statements(&source);
            assert_eq!(
                constant_policy_returns(&source, &statements),
                Err(Unknown::EffectProofUnavailable),
                "{body}"
            );
        }
    }
}
