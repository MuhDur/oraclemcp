//! The served engine port and prepared boundary for compile-time SQL callbacks.
//! The database collector owns catalog proof; this module supplies the existing
//! grammar frontend and mutation effect oracle, never a second effect analyzer.

use asupersync::Cx;
use oraclemcp_db::{
    CatalogQueryId, CompileParseCallbackClass, CompileParseEffectClosureV1, CompileParseUnproven,
    OracleBind, OracleConnection, run_catalog_query,
};
use oraclemcp_error::{
    ErrorClass, ErrorEnvelope, ReasonCategory, StatementOutcome, StructuredReason,
};
use oraclemcp_guard::mutation_closure::MutationUnavailableReason;
use sha2::{Digest, Sha256};
use sqlparser::{
    dialect::OracleDialect,
    tokenizer::{Token, Tokenizer},
};

/// A stable refusal names only the ordinal and callback family, not code.
pub fn unproven(reason: CompileParseUnproven) -> ErrorEnvelope {
    let error = ErrorEnvelope::new(
        ErrorClass::ForbiddenStatement,
        format!(
            "compile-time callback proof is unavailable for static SQL statement {} ({:?})",
            reason.statement_ordinal, reason.callback_class
        ),
    )
    .with_structured_reason(
        StructuredReason::new(ReasonCategory::ParseCallbackUnproven).with_offending_construct(
            format!(
                "statement={} callback={:?}",
                reason.statement_ordinal, reason.callback_class
            ),
        ),
    )
    .with_statement_outcome(StatementOutcome::NotStarted);
    if reason.callback_class == CompileParseCallbackClass::Resolution {
        error.with_next_step(
            "this compile did not start; use oracle_compile_errors for the existing unit's \
             diagnostics, then resolve its references before compiling again",
        )
    } else {
        error
    }
}

fn unavailable(
    class: CompileParseCallbackClass,
    reason: MutationUnavailableReason,
) -> ErrorEnvelope {
    unproven(CompileParseUnproven {
        statement_ordinal: 0,
        callback_class: class,
        reason,
    })
}

#[cfg(feature = "plsql-intelligence")]
impl oraclemcp_db::CompileParseEffectOracle for crate::mutation_closure::EngineMutationEffects {
    fn static_sql(&self, source: &str) -> Result<Vec<String>, MutationUnavailableReason> {
        use plsql_parser::ast::StaticSqlProjection;
        crate::plsql_tools::validate_engine_source(source)
            .map_err(|_| MutationUnavailableReason::SourceUnavailable)?;
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("omcp-compile-sql".into())
                .stack_size(8 * 1024 * 1024)
                .spawn_scoped(scope, || {
                    let parsed = plsql_parser::parse_with_backend(
                        source,
                        plsql_core::FileId::new(1),
                        &plsql_parser_antlr::Antlr4RustBackend::new(),
                        &plsql_parser::ParseOptions::default(),
                    );
                    if !parsed.is_clean()
                        || parsed.was_recovered()
                        || parsed.ast.root.declarations.is_empty()
                    {
                        return Err(MutationUnavailableReason::SourceUnavailable);
                    }
                    let StaticSqlProjection::Computed { statements } = parsed.ast.static_sql else {
                        return Err(MutationUnavailableReason::SourceUnavailable);
                    };
                    if statements.iter().any(|statement| {
                        source.get(
                            statement.span.start.offset as usize
                                ..statement.span.end.offset as usize,
                        ) != Some(statement.sql.as_str())
                    }) {
                        return Err(MutationUnavailableReason::SourceUnavailable);
                    }
                    Ok(statements
                        .into_iter()
                        .map(|statement| statement.sql)
                        .collect())
                })
                .map_err(|_| MutationUnavailableReason::EffectProofUnavailable)?
                .join()
                .map_err(|_| MutationUnavailableReason::EffectProofUnavailable)?
        })
    }
}

/// Collect on the authenticated target lane. W12 supplies its child-edition
/// connection and the same explicit resolution schema through this boundary.
pub async fn collect_compile_parse_effect_closure(
    cx: &Cx,
    conn: &dyn OracleConnection,
    source: &str,
    resolution_schema: &str,
    require_security_feature_evidence: bool,
) -> Result<CompileParseEffectClosureV1, ErrorEnvelope> {
    #[cfg(feature = "plsql-intelligence")]
    let effects = crate::mutation_closure::EngineMutationEffects;
    #[cfg(not(feature = "plsql-intelligence"))]
    let effects = oraclemcp_db::mutation_closure::UnknownMutationEffects;
    let closure = oraclemcp_db::collect_compile_parse_effect_closure(
        cx,
        conn,
        source,
        resolution_schema,
        None,
        &effects,
        require_security_feature_evidence,
    )
    .await;
    closure.admit().map_err(unproven)?;
    Ok(closure)
}

#[derive(Clone)]
struct CompileHeader {
    owner: Option<String>,
    name: String,
    kind: String,
    recompile: bool,
    spec_only: bool,
}

fn keyword(token: &Token, word: &str) -> bool {
    matches!(token,Token::Word(value) if value.quote_style.is_none() && value.value.eq_ignore_ascii_case(word))
}

fn identifier(token: &Token) -> Result<String, ErrorEnvelope> {
    let Token::Word(word) = token else {
        return Err(unavailable(
            CompileParseCallbackClass::Source,
            MutationUnavailableReason::InvalidInput,
        ));
    };
    if word.value.is_empty() || word.value.len() > 128 || word.value.chars().any(char::is_control) {
        return Err(unavailable(
            CompileParseCallbackClass::Source,
            MutationUnavailableReason::InvalidInput,
        ));
    }
    match word.quote_style {
        Some('"') => Ok(word.value.clone()),
        None if word.value.as_bytes()[0].is_ascii_alphabetic()
            && word
                .value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_$#".contains(&byte)) =>
        {
            Ok(word.value.to_ascii_uppercase())
        }
        _ => Err(unavailable(
            CompileParseCallbackClass::Source,
            MutationUnavailableReason::InvalidInput,
        )),
    }
}

// Selection only; ordinary classification remains mandatory for authority.
fn header(sql: &str) -> Result<Option<CompileHeader>, ErrorEnvelope> {
    let tokens = Tokenizer::new(&OracleDialect {}, sql)
        .tokenize()
        .map_err(|_| {
            unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::InvalidInput,
            )
        })?;
    let tokens = tokens
        .into_iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .collect::<Vec<_>>();
    let Some(first) = tokens.first() else {
        return Ok(None);
    };
    let recompile = keyword(first, "ALTER");
    if !recompile && !keyword(first, "CREATE") {
        return Ok(None);
    }
    let mut index = 1;
    if tokens.get(index).is_some_and(|token| keyword(token, "OR")) {
        if !tokens
            .get(index + 1)
            .is_some_and(|token| keyword(token, "REPLACE"))
        {
            return Err(unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::InvalidInput,
            ));
        }
        index += 2;
    }
    while tokens.get(index).is_some_and(|token| {
        ["EDITIONABLE", "NONEDITIONABLE", "FORCE", "NOFORCE"]
            .iter()
            .any(|word| keyword(token, word))
    }) {
        index += 1;
    }
    if tokens
        .get(index)
        .is_some_and(|token| keyword(token, "JAVA") || keyword(token, "AND"))
    {
        return Err(unavailable(
            CompileParseCallbackClass::Source,
            MutationUnavailableReason::UnsupportedMechanism,
        ));
    }
    let Some(kind) = tokens.get(index).and_then(|token| {
        [
            "FUNCTION",
            "PROCEDURE",
            "PACKAGE",
            "TYPE",
            "TRIGGER",
            "VIEW",
        ]
        .into_iter()
        .find(|word| keyword(token, word))
    }) else {
        return Ok(None);
    };
    let mut kind = kind.to_owned();
    index += 1;
    if matches!(kind.as_str(), "PACKAGE" | "TYPE")
        && tokens
            .get(index)
            .is_some_and(|token| keyword(token, "BODY"))
    {
        kind.push_str(" BODY");
        index += 1;
    }
    let name = identifier(tokens.get(index).ok_or_else(|| {
        unavailable(
            CompileParseCallbackClass::Source,
            MutationUnavailableReason::InvalidInput,
        )
    })?)?;
    index += 1;
    let (owner, name) = if tokens.get(index) == Some(&Token::Period) {
        index += 1;
        let object = identifier(tokens.get(index).ok_or_else(|| {
            unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::InvalidInput,
            )
        })?)?;
        index += 1;
        if tokens.get(index) == Some(&Token::Period) {
            return Err(unavailable(
                CompileParseCallbackClass::Resolution,
                MutationUnavailableReason::UnsupportedMechanism,
            ));
        }
        (Some(name), object)
    } else {
        (None, name)
    };
    if recompile {
        if !tokens
            .get(index)
            .is_some_and(|token| keyword(token, "COMPILE"))
        {
            return Err(unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::UnsupportedMechanism,
            ));
        }
        if matches!(kind.as_str(), "PACKAGE" | "TYPE")
            && tokens[index + 1..]
                .iter()
                .any(|token| keyword(token, "BODY"))
        {
            kind.push_str(" BODY");
        }
    }
    let spec_only = recompile
        && tokens[index..]
            .iter()
            .any(|token| keyword(token, "SPECIFICATION"));
    Ok(Some(CompileHeader {
        owner,
        name,
        kind,
        recompile,
        spec_only,
    }))
}

pub(crate) fn is_compile_ddl(sql: &str) -> Result<bool, ErrorEnvelope> {
    header(sql).map(|header| header.is_some())
}

async fn current_schema(cx: &Cx, conn: &dyn OracleConnection) -> Result<String, ErrorEnvelope> {
    let rows = run_catalog_query(cx, conn, CatalogQueryId::SessionContext, &[])
        .await
        .map_err(|_| {
            unavailable(
                CompileParseCallbackClass::Resolution,
                MutationUnavailableReason::CatalogUnreadable,
            )
        })?;
    let [row] = rows.as_slice() else {
        return Err(unavailable(
            CompileParseCallbackClass::Resolution,
            MutationUnavailableReason::CatalogIncomplete,
        ));
    };
    row.text("CURRENT_SCHEMA")
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            unavailable(
                CompileParseCallbackClass::Resolution,
                MutationUnavailableReason::CatalogIncomplete,
            )
        })
}

async fn stored_source(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    kind: &str,
) -> Result<String, ErrorEnvelope> {
    if kind == "VIEW" {
        // The identifiers are already dictionary-exact, including quoted case.
        let rows = run_catalog_query(
            cx,
            conn,
            CatalogQueryId::GetDdl,
            &[OracleBind::from("VIEW"), name.into(), owner.into()],
        )
        .await
        .map_err(|_| {
            unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::SourceUnavailable,
            )
        })?;
        let [row] = rows.as_slice() else {
            return Err(unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::SourceUnavailable,
            ));
        };
        let source = row.text("DDL").ok_or_else(|| {
            unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::SourceUnavailable,
            )
        })?;
        if row
            .parse_i64("DDL_LENGTH")
            .and_then(|value| usize::try_from(value).ok())
            != Some(source.chars().count())
        {
            return Err(unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::SourceUnavailable,
            ));
        }
        return Ok(source.to_owned());
    }
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::ClosureSource,
        &[owner.into(), name.into(), kind.into(), 16_385_i64.into()],
    )
    .await
    .map_err(|_| {
        unavailable(
            CompileParseCallbackClass::Source,
            MutationUnavailableReason::SourceUnavailable,
        )
    })?;
    if rows.is_empty() || rows.len() >= 16_385 {
        return Err(unavailable(
            CompileParseCallbackClass::Source,
            MutationUnavailableReason::SourceUnavailable,
        ));
    }
    let mut source = String::from("CREATE OR REPLACE ");
    for (index, row) in rows.iter().enumerate() {
        if row.parse_i64("LINE") != i64::try_from(index + 1).ok() {
            return Err(unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::SourceUnavailable,
            ));
        }
        let cell = row.cell("TEXT").ok_or_else(|| {
            unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::SourceUnavailable,
            )
        })?;
        let text = cell.value.as_deref().unwrap_or("");
        if cell.bytes.is_some()
            || cell.structured.is_some()
            || cell.nested_result.is_some()
            || cell
                .source_length
                .is_some_and(|length| length > text.chars().count())
        {
            return Err(unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::SourceUnavailable,
            ));
        }
        source.push_str(text);
        if !text.ends_with('\n') {
            source.push('\n');
        }
        if source.len() > 16 * 1024 * 1024 {
            return Err(unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::ClosureCapExhausted,
            ));
        }
    }
    Ok(source)
}

/// Preview state contains original SQL, never an execution grant. Revalidation
/// reloads stored source and every catalog/callback proof on the target lane.
pub(crate) struct PreparedCompileParse {
    sql: String,
    resolution_schema: Option<String>,
    require_security_feature_evidence: bool,
    target_commitments: Vec<[u8; 32]>,
    pub(crate) closures: Vec<CompileParseEffectClosureV1>,
}

impl PreparedCompileParse {
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"omcp/compile-parse/prepared/v1\0");
        for commitment in &self.target_commitments {
            hash.update(commitment);
        }
        for closure in &self.closures {
            hash.update(closure.digest());
        }
        hash.finalize().into()
    }
    pub(crate) async fn revalidate(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
    ) -> Result<(), ErrorEnvelope> {
        let fresh = prepare_compile_for_schema(
            cx,
            conn,
            &self.sql,
            self.resolution_schema.as_deref(),
            self.require_security_feature_evidence,
        )
        .await
        .map_err(|_| stale())?
        .ok_or_else(stale)?;
        if fresh.digest() != self.digest() {
            return Err(stale());
        }
        Ok(())
    }
}

pub(crate) fn stale() -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::RepreviewRequired,
        "compile-time callback closure changed; preview this candidate again",
    )
    .with_structured_reason(StructuredReason::new(ReasonCategory::ParseCallbackUnproven))
    .with_statement_outcome(StatementOutcome::NotStarted)
}

async fn prepare_compile(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    require_security_feature_evidence: bool,
) -> Result<Option<PreparedCompileParse>, ErrorEnvelope> {
    prepare_compile_for_schema(cx, conn, sql, None, require_security_feature_evidence).await
}

/// A definer-rights routine resolves its literal DDL in its own schema. Keep
/// that explicit identity in the same compile proof and its fresh recheck.
pub(crate) async fn prepare_compile_for_schema(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    resolution_schema: Option<&str>,
    require_security_feature_evidence: bool,
) -> Result<Option<PreparedCompileParse>, ErrorEnvelope> {
    let Some(header) = header(sql)? else {
        return Ok(None);
    };
    let owner = match header.owner {
        Some(owner) => owner,
        None => match resolution_schema {
            Some(owner) => owner.to_owned(),
            None => current_schema(cx, conn).await?,
        },
    };
    let mut sources = Vec::new();
    let mut target_commitments = Vec::new();
    if !header.recompile {
        sources.push(sql.to_owned());
    } else {
        sources.push(stored_source(cx, conn, &owner, &header.name, &header.kind).await?);
        if !header.spec_only && matches!(header.kind.as_str(), "PACKAGE" | "TYPE") {
            sources.push(
                stored_source(
                    cx,
                    conn,
                    &owner,
                    &header.name,
                    &format!("{} BODY", header.kind),
                )
                .await?,
            );
        }
    }
    if header.recompile {
        let kinds = if !header.spec_only && matches!(header.kind.as_str(), "PACKAGE" | "TYPE") {
            vec![header.kind.clone(), format!("{} BODY", header.kind)]
        } else {
            vec![header.kind.clone()]
        };
        for kind in kinds {
            let binds = [
                owner.as_str().into(),
                header.name.as_str().into(),
                kind.as_str().into(),
                2_i64.into(),
            ];
            let rows = run_catalog_query(cx, conn, CatalogQueryId::ClosureMemberObject, &binds)
                .await
                .map_err(|_| {
                    unavailable(
                        CompileParseCallbackClass::Source,
                        MutationUnavailableReason::CatalogUnreadable,
                    )
                })?;
            let [row] = rows.as_slice() else {
                return Err(unavailable(
                    CompileParseCallbackClass::Source,
                    MutationUnavailableReason::CatalogIncomplete,
                ));
            };
            if row.parse_i64("OBJECT_ID").is_none_or(|id| id <= 0)
                || row.text("LAST_DDL_TIME").is_none()
                || row.text("STATUS").is_none()
            {
                return Err(unavailable(
                    CompileParseCallbackClass::Source,
                    MutationUnavailableReason::CatalogIncomplete,
                ));
            }
            target_commitments.push(
                Sha256::digest(
                    serde_json::to_vec(&(kind.as_str(), rows)).expect("target identity serializes"),
                )
                .into(),
            );
            if kind != "VIEW" {
                let rows =
                    run_catalog_query(cx, conn, CatalogQueryId::ClosureCompilerSettings, &binds)
                        .await
                        .map_err(|_| {
                            unavailable(
                                CompileParseCallbackClass::Source,
                                MutationUnavailableReason::CatalogUnreadable,
                            )
                        })?;
                let [row] = rows.as_slice() else {
                    return Err(unavailable(
                        CompileParseCallbackClass::Source,
                        MutationUnavailableReason::CatalogIncomplete,
                    ));
                };
                if [
                    "PLSQL_OPTIMIZE_LEVEL",
                    "PLSQL_CODE_TYPE",
                    "PLSQL_DEBUG",
                    "PLSQL_WARNINGS",
                    "PLSQL_CCFLAGS",
                    "NLS_LENGTH_SEMANTICS",
                    "PLSCOPE_SETTINGS",
                ]
                .iter()
                .any(|column| row.cell(column).is_none())
                    || row
                        .text("PLSQL_CCFLAGS")
                        .is_some_and(|flags| !flags.trim().is_empty())
                {
                    return Err(unavailable(
                        CompileParseCallbackClass::Source,
                        MutationUnavailableReason::CatalogIncomplete,
                    ));
                }
                target_commitments.push(
                    Sha256::digest(
                        serde_json::to_vec(&(kind.as_str(), rows))
                            .expect("compiler facts serialize"),
                    )
                    .into(),
                );
            }
        }
    }
    let mut closures = Vec::new();
    for source in &sources {
        closures.push(
            collect_compile_parse_effect_closure(
                cx,
                conn,
                source,
                &owner,
                require_security_feature_evidence,
            )
            .await?,
        );
    }
    Ok(Some(PreparedCompileParse {
        sql: sql.to_owned(),
        resolution_schema: resolution_schema.map(str::to_owned),
        require_security_feature_evidence,
        target_commitments,
        closures,
    }))
}

/// Combine independent proof families while retaining the single served
/// classifier and its existing routine-effect oracle.
pub(super) struct PreparedSqlProof {
    runtime: super::served_classifier::PreparedClassifier,
    compile_authorized: bool,
    compile: Result<Option<PreparedCompileParse>, ErrorEnvelope>,
}

impl std::ops::Deref for PreparedSqlProof {
    type Target = super::served_classifier::PreparedClassifier;
    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}

impl PreparedSqlProof {
    pub(super) fn attach_compile_parse_observations(&self, response: &mut serde_json::Value) {
        let Ok(Some(compile)) = &self.compile else {
            return;
        };
        let mut observations = Vec::new();
        for closure in &compile.closures {
            for statement in &closure.statements {
                observations.extend(statement.security_feature_evidence.iter().filter(|fact| {
                    [fact.ols, fact.ras, fact.redaction].contains(&oraclemcp_db::RelationSecurityState::Unavailable)
                }).map(|fact| serde_json::json!({"statement_ordinal":statement.ordinal,"security_feature_evidence":fact})));
                if !statement.unresolved_local_names.is_empty() {
                    observations.push(serde_json::json!({
                        "statement_ordinal": statement.ordinal,
                        "resolution_schema": closure.resolution_schema,
                        "unresolved_local_names": statement.unresolved_local_names,
                        "visibility_scope": "compiling_identity",
                    }));
                }
            }
        }
        if !observations.is_empty() {
            response["compile_parse_observations"] = serde_json::json!({
                "status":"admitted_with_observation", "statements":observations,
            });
        }
    }
    pub(super) fn require_compile_parse_closure(&self, sql: &str) -> Result<(), ErrorEnvelope> {
        // An already forbidden statement has no execution grant; retain the
        // existing inspectable refusal preview and its stronger guard verdict.
        if self.runtime.precheck.classify(sql).danger == oraclemcp_guard::DangerLevel::Forbidden {
            return Ok(());
        }
        if !self.compile_authorized {
            return Ok(());
        }
        let proof = self.compile.as_ref().map_err(Clone::clone)?;
        if proof.is_none() && is_compile_ddl(sql)? {
            return Err(unavailable(
                CompileParseCallbackClass::Source,
                MutationUnavailableReason::EffectProofUnavailable,
            ));
        }
        Ok(())
    }
    pub(super) fn attach_compile_parse_binding(&self, response: &mut serde_json::Value) {
        self.attach_compile_parse_observations(response);
        let Ok(Some(compile)) = &self.compile else {
            return;
        };
        if response.get("impact").is_none() {
            response["impact"] =
                serde_json::to_value(oraclemcp_guard::impact_binding::ImpactV1::default())
                    .expect("typed impact serializes");
        }
        if response["impact"].get("binding").is_none() {
            response["impact"]["binding"] =
                serde_json::to_value(oraclemcp_guard::impact_binding::ImpactBindingV1::default())
                    .expect("typed binding serializes");
        }
        response["impact"]["binding"]["decisive"]["compile_parse_closure_digest"] =
            serde_json::to_value(oraclemcp_guard::impact_binding::FieldStatus::Computed {
                value: compile.digest(),
            })
            .expect("compile binding serializes");
    }
    pub(super) fn bind_material(&self, material: String) -> String {
        let mut material = self.runtime.bind_material(material);
        if let Ok(Some(compile)) = &self.compile {
            material.push_str(";compile-parse-closure/v1:");
            for byte in compile.digest() {
                use std::fmt::Write;
                write!(material, "{byte:02x}").expect("String formatting");
            }
        }
        material
    }

    pub(super) fn compile_parse_digest(&self) -> Option<[u8; 32]> {
        self.compile
            .as_ref()
            .ok()?
            .as_ref()
            .map(|proof| proof.digest())
    }
    pub(super) async fn revalidate_compile_parse_closure(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
    ) -> Result<(), ErrorEnvelope> {
        match &self.compile {
            Ok(Some(compile)) => compile.revalidate(cx, conn).await,
            Ok(None) => Ok(()),
            Err(_) => Err(stale()),
        }
    }
}

pub(super) async fn prepare(
    classifier: &super::served_classifier::ProfileClassifier,
    cx: &Cx,
    conn: &dyn OracleConnection,
    cache: &oraclemcp_db::OracleCatalogResolverCache,
    session: &oraclemcp_guard::SessionLevelState,
    sql: &str,
) -> PreparedSqlProof {
    let runtime = classifier.prepare(cx, conn, cache, sql).await;
    let compile_authorized = matches!(
        session.evaluate(Some(oraclemcp_guard::OperatingLevel::Ddl)),
        oraclemcp_guard::LevelDecision::Allow
    );
    let compile = if !compile_authorized
        || runtime.precheck.classify(sql).danger == oraclemcp_guard::DangerLevel::Forbidden
    {
        Ok(None)
    } else {
        prepare_compile(
            cx,
            conn,
            sql,
            classifier.requires_security_feature_evidence(),
        )
        .await
    };
    PreparedSqlProof {
        runtime,
        compile_authorized,
        compile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_parse_closure_headers_preserve_quoted_case_and_cover_recompile() {
        for sql in [
            "CREATE OR REPLACE EDITIONABLE PACKAGE BODY \"App\".\"Api\" AS END;",
            "ALTER PACKAGE \"App\".\"Api\" COMPILE BODY REUSE SETTINGS",
        ] {
            let value = header(sql).unwrap().unwrap();
            assert_eq!(value.owner.as_deref(), Some("App"));
            assert_eq!(value.name, "Api");
            assert_eq!(value.kind, "PACKAGE BODY");
        }
        assert!(header("CREATE TABLE app.t(id NUMBER)").unwrap().is_none());
        assert!(
            header("ALTER TABLE app.t ADD (x NUMBER)")
                .unwrap()
                .is_none()
        );
        assert!(header("CREATE OR REPLACE JAVA SOURCE NAMED app.x AS hi").is_err());
    }

    #[cfg(feature = "plsql-intelligence")]
    #[test]
    fn compile_parse_closure_empty_call_spec_never_proves_runtime_purity() {
        use oraclemcp_db::CompileParseEffectOracle;
        for source in [
            "CREATE OR REPLACE FUNCTION APP.J_CALL RETURN NUMBER AS LANGUAGE JAVA NAME 'X.f() return int';",
            "CREATE OR REPLACE FUNCTION APP.C_CALL RETURN NUMBER AS LANGUAGE C NAME \"f\" LIBRARY lib;",
        ] {
            assert!(
                crate::mutation_closure::EngineMutationEffects
                    .static_sql(source)
                    .unwrap()
                    .is_empty()
            );
            let runtime = crate::plsql_tools::analyze_source_impact(source).unwrap();
            assert!(
                runtime
                    .effects
                    .iter()
                    .any(|effect| effect == oraclemcp_guard::RoutineEffect::Unknown)
            );
            assert_eq!(
                oraclemcp_guard::admit(
                    &runtime.effects,
                    oraclemcp_guard::AdmissionContext::CustomToolCall
                ),
                Err(oraclemcp_guard::EffectRefusal::AlwaysRefused(
                    oraclemcp_guard::RoutineEffect::Unknown
                ))
            );
        }
    }

    #[cfg(feature = "plsql-intelligence")]
    #[test]
    fn compile_parse_closure_type_body_projection() {
        use oraclemcp_db::CompileParseEffectOracle;
        for source in [
            "CREATE OR REPLACE TYPE BODY employee_t AS MEMBER FUNCTION label RETURN VARCHAR2 IS BEGIN RETURN 'ok'; END label; END employee_t;",
            "CREATE OR REPLACE TYPE BODY APP.EMPLOYEE_T AS MEMBER PROCEDURE P IS BEGIN SELF.id := SELF.id; END P; END EMPLOYEE_T;",
        ] {
            let parsed = plsql_parser::parse_with_backend(
                source,
                plsql_core::FileId::new(1),
                &plsql_parser_antlr::Antlr4RustBackend::new(),
                &plsql_parser::ParseOptions::default(),
            );
            assert!(parsed.is_clean(), "{:?}", parsed.diagnostics);
            assert!(
                crate::mutation_closure::EngineMutationEffects
                    .static_sql(source)
                    .is_ok()
            );
        }
    }

    #[cfg(feature = "plsql-intelligence")]
    #[test]
    fn compile_parse_closure_incomplete_parse_refuses() {
        use oraclemcp_db::CompileParseEffectOracle;
        let oracle = crate::mutation_closure::EngineMutationEffects;
        for source in [
            "CREATE OR REPLACE PROCEDURE p AS BEGIN SELECT",
            "CREATE OR REPLACE PROCEDURE p AS BEGIN $IF $$flag $THEN NULL; $END END;",
            "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE j AS LANGUAGE JAVA NAME 'X.y()'; PROCEDURE q IS BEGIN NULL; END; END;",
        ] {
            assert!(oracle.static_sql(source).is_err(), "{source}");
        }
    }

    #[cfg(feature = "plsql-intelligence")]
    #[test]
    fn compile_parse_closure_recovered_lexer_with_computed_sql_refuses() {
        use oraclemcp_db::CompileParseEffectOracle;
        use plsql_parser::ast::StaticSqlProjection;
        // The lexer reports the stray euro symbol, while the independent
        // grammar-tree pass can recover by skipping it between two valid SQL
        // statements. A computed projection alone is therefore insufficient.
        let source = "CREATE OR REPLACE PROCEDURE p AS n NUMBER; BEGIN SELECT COUNT(*) INTO n FROM app.a; \u{20ac} SELECT COUNT(*) INTO n FROM app.b; END;";
        let parsed = plsql_parser::parse_with_backend(
            source,
            plsql_core::FileId::new(1),
            &plsql_parser_antlr::Antlr4RustBackend::new(),
            &plsql_parser::ParseOptions::default(),
        );
        assert!(!parsed.is_clean(), "the real lexer must report its error");
        assert!(
            parsed.was_recovered(),
            "the real backend must mark recovery"
        );
        let StaticSqlProjection::Computed { statements } = &parsed.ast.static_sql else {
            panic!("fixture must independently retain a computed projection");
        };
        assert_eq!(statements.len(), 2);
        assert!(
            crate::mutation_closure::EngineMutationEffects
                .static_sql(source)
                .is_err(),
            "recovered/unclean source must refuse even when SQL projection is computed"
        );
    }

    #[cfg(feature = "plsql-intelligence")]
    #[test]
    fn compile_parse_closure_extracts_every_static_statement() {
        use oraclemcp_db::CompileParseEffectOracle;
        let oracle = crate::mutation_closure::EngineMutationEffects;
        let sql=oracle.static_sql("CREATE OR REPLACE PROCEDURE p AS CURSOR c IS SELECT id FROM app.a; n NUMBER; BEGIN SELECT COUNT(*) INTO n FROM app.b; INSERT INTO app.c(id) VALUES (n); FOR r IN (SELECT id FROM app.d) LOOP UPDATE app.e SET id=r.id; END LOOP; BEGIN NULL; EXCEPTION WHEN OTHERS THEN DELETE FROM app.f; END; EXECUTE IMMEDIATE 'DELETE FROM app.dynamic_t'; END;").unwrap();
        assert_eq!(sql.len(), 6, "{sql:?}");
        for name in ["app.a", "app.b", "app.c", "app.d", "app.e", "app.f"] {
            assert!(sql.iter().any(|sql| sql.contains(name)), "{name}");
        }
        assert!(!sql.iter().any(|sql| sql.contains("dynamic_t")));
    }

    #[cfg(feature = "plsql-intelligence")]
    #[test]
    fn compile_parse_closure_no_static_sql_projection_is_computed_empty() {
        use oraclemcp_db::CompileParseEffectOracle;
        assert!(crate::mutation_closure::EngineMutationEffects.static_sql("CREATE OR REPLACE PROCEDURE p AS BEGIN EXECUTE IMMEDIATE 'SELECT 1 FROM dual'; END;").unwrap().is_empty());
    }
}

#[cfg(all(test, feature = "plsql-intelligence"))]
mod native {
    use super::super::{ActiveCustomCatalog, DispatchContext, OracleDispatcher};
    use super::*;
    use oraclemcp_core::CustomToolCatalog;
    use oraclemcp_db::{OracleConnectOptions, RustOracleConnection};
    use oraclemcp_guard::{Classifier, ClassifierConfig, OperatingLevel, SessionLevelState};
    use serde_json::{Value, json};
    use std::time::Duration;

    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    // This observer forwards every tested operation to the real thin driver.
    // It counts candidate DDL at the wire-adapter boundary; it supplies no rows,
    // effects, policies, execution outcomes or success paths of its own.
    struct NativeCompileObserver {
        inner: RustOracleConnection,
        compiles: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for NativeCompileObserver {
        fn backend(&self) -> oraclemcp_db::OracleBackend {
            self.inner.backend()
        }
        async fn close(&self, cx: &Cx) -> Result<(), oraclemcp_db::DbError> {
            self.inner.close(cx).await
        }
        async fn ping(&self, cx: &Cx) -> Result<(), oraclemcp_db::DbError> {
            self.inner.ping(cx).await
        }
        async fn describe(
            &self,
            cx: &Cx,
        ) -> Result<oraclemcp_db::OracleConnectionInfo, oraclemcp_db::DbError> {
            self.inner.describe(cx).await
        }
        async fn query_rows(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<oraclemcp_db::OracleRow>, oraclemcp_db::DbError> {
            self.inner.query_rows(cx, sql, binds).await
        }
        async fn query_rows_with_provenance(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
            origin: oraclemcp_db::ReadQueryProvenance,
            options: Option<&oraclemcp_db::SerializeOptions>,
        ) -> Result<Vec<oraclemcp_db::OracleRow>, oraclemcp_db::DbError> {
            self.inner
                .query_rows_with_provenance(cx, sql, binds, origin, options)
                .await
        }
        async fn execute(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<u64, oraclemcp_db::DbError> {
            if matches!(header(sql), Ok(Some(_))) {
                self.compiles.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.execute(cx, sql, binds).await
        }
        async fn commit(&self, cx: &Cx) -> Result<(), oraclemcp_db::DbError> {
            self.inner.commit(cx).await
        }
        async fn rollback(&self, cx: &Cx) -> Result<(), oraclemcp_db::DbError> {
            self.inner.rollback(cx).await
        }
        fn call_timeout(&self) -> Result<Option<Duration>, oraclemcp_db::DbError> {
            self.inner.call_timeout()
        }
        fn set_call_timeout(&self, value: Option<Duration>) -> Result<(), oraclemcp_db::DbError> {
            self.inner.set_call_timeout(value)
        }
        fn request_deadline(
            &self,
            cx: &Cx,
        ) -> Result<Option<asupersync::Time>, oraclemcp_db::DbError> {
            self.inner.request_deadline(cx)
        }
        fn set_request_deadline(
            &self,
            cx: &Cx,
            value: Option<asupersync::Time>,
        ) -> Result<(), oraclemcp_db::DbError> {
            self.inner.set_request_deadline(cx, value)
        }
        fn request_quota(
            &self,
            cx: &Cx,
        ) -> Result<Option<oraclemcp_db::DbRequestQuota>, oraclemcp_db::DbError> {
            self.inner.request_quota(cx)
        }
        fn set_request_quota(
            &self,
            cx: &Cx,
            value: Option<oraclemcp_db::DbRequestQuota>,
        ) -> Result<(), oraclemcp_db::DbError> {
            self.inner.set_request_quota(cx, value)
        }
    }

    async fn call(
        cx: &Cx,
        dispatcher: &OracleDispatcher,
        tool: &str,
        args: Value,
    ) -> Result<Value, ErrorEnvelope> {
        let recorded = std::cell::Cell::new(false);
        Box::pin(dispatcher.dispatch_with_cx_inner(
            cx,
            DispatchContext::default(),
            tool,
            args,
            &recorded,
        ))
        .await
    }
    async fn ddl(cx: &Cx, conn: &RustOracleConnection, sql: &str) -> Result<(), String> {
        conn.execute(cx, sql, &[])
            .await
            .map(|_| ())
            .map_err(|error| format!("fixture DDL: {error}"))
    }
    async fn count(cx: &Cx, conn: &RustOracleConnection, sql: &str) -> Result<i64, String> {
        let rows = conn
            .query_rows(cx, sql, &[])
            .await
            .map_err(|error| error.to_string())?;
        rows.first()
            .and_then(|row| row.parse_i64("N"))
            .ok_or_else(|| "missing count".into())
    }
    fn grant_catalog(schema: &str) -> Result<(), String> {
        let status=std::process::Command::new("python3").args(["-c",r#"
import os,re,oracledb
schema=os.environ['ORACLEMCP_COMPILE_SCHEMA']
assert re.fullmatch(r'OM_CP_[A-Z0-9_]+',schema)
with oracledb.connect(user='sys',password=os.environ['ORACLEMCP_TEST_PASSWORD'],dsn=os.environ['ORACLEMCP_TEST_DSN'],mode=oracledb.AUTH_MODE_SYSDBA,tcp_connect_timeout=10,retry_count=0) as conn:
    conn.call_timeout=10000
    c=conn.cursor()
    for view in ['V_$OPTION','ALL_AUDIT_POLICIES','ALL_XS_APPLIED_POLICIES','REDACTION_POLICIES']:
        c.execute(f'GRANT SELECT ON SYS.{view} TO {schema}')
"#]).env("ORACLEMCP_COMPILE_SCHEMA",schema).status().map_err(|error|error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err("SYS catalog setup failed".into())
        }
    }
    fn envelope(error: ErrorEnvelope) -> String {
        format!(
            "{:?}: {} {:?}",
            error.error_class, error.message, error.structured_reason
        )
    }
    fn confirmed(value: &Value) -> Result<String, String> {
        value
            .pointer("/confirmation/confirm")
            .or_else(|| value.pointer("/execute_confirmation/confirm"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("missing grant: {value}"))
    }
    fn bound(value: &Value) -> Result<(), String> {
        if value
            .pointer("/impact/binding/decisive/compile_parse_closure_digest/status")
            .and_then(Value::as_str)
            != Some("computed")
        {
            return Err(format!("missing computed closure binding: {value}"));
        }
        Ok(())
    }
    async fn refuse(
        cx: &Cx,
        dispatcher: &OracleDispatcher,
        tool: &str,
        args: Value,
        compiles: &AtomicUsize,
    ) -> Result<(), String> {
        let before = compiles.load(Ordering::SeqCst);
        let original_args = args.clone();
        let result = call(cx, dispatcher, tool, args).await;
        if let Ok(preview) = &result
            && matches!(
                tool,
                "oracle_create_or_replace" | "oracle_patch_source" | "oracle_compile_object"
            )
            && let Ok(token) = confirmed(preview)
        {
            let mut apply = original_args;
            apply["execute"] = json!(true);
            apply["confirm"] = json!(token);
            let _ = call(cx, dispatcher, tool, apply).await;
        }
        if compiles.load(Ordering::SeqCst) != before {
            return Err(format!("{tool} reached the real candidate DDL adapter"));
        }
        match result {
            Err(error)
                if error.structured_reason.as_ref().is_some_and(|reason| {
                    reason.category == ReasonCategory::ParseCallbackUnproven
                }) =>
            {
                Ok(())
            }
            result => Err(format!(
                "{tool} must refuse parse callback before DDL: {result:?}"
            )),
        }
    }

    // The live proof is ignored in ordinary offline runs and explicitly invoked
    // with --ignored on the local lab. It never substitutes a pure policy for
    // the autonomous INSERT + COMMIT canary.
    struct NativeFixtureHarness {
        options: OracleConnectOptions,
        security_visibility: bool,
    }
    impl oraclemcp_core::ToolDispatch for NativeFixtureHarness {
        fn request_timeout_ceiling(&self) -> Result<Duration, ErrorEnvelope> {
            Ok(Duration::from_secs(90))
        }
        fn dispatch<'a>(
            &'a self,
            cx: &'a Cx,
            _: DispatchContext<'a>,
            _: &'a str,
            _: Value,
        ) -> oraclemcp_core::DispatchFuture<'a> {
            Box::pin(async move {
                let result = if self.security_visibility {
                    native_security_visibility(cx, self.options.clone()).await
                } else {
                    native_fixture(cx, self.options.clone()).await
                };
                match result {
                    Ok(()) => asupersync::Outcome::Ok(json!({"fixture":"passed"})),
                    Err(error) => {
                        asupersync::Outcome::Err(ErrorEnvelope::new(ErrorClass::Internal, error))
                    }
                }
            })
        }
    }

    #[test]
    #[ignore = "requires administrative local FREE23 fixture setup"]
    fn compile_parse_closure_native_free23_paths_canary_and_drift() {
        run_native_fixture(false);
    }

    #[test]
    #[ignore = "requires CI-equivalent E2E_ORACLE on local FREE23"]
    fn compile_parse_closure_native_free23_security_visibility() {
        run_native_fixture(true);
    }

    fn run_native_fixture(security_visibility: bool) {
        let options = OracleConnectOptions {
            connect_string: std::env::var("ORACLEMCP_TEST_DSN").expect("FREE23 DSN"),
            username: Some(std::env::var("ORACLEMCP_TEST_USER").expect("admin user")),
            password: Some(std::env::var("ORACLEMCP_TEST_PASSWORD").expect("admin password")),
            call_timeout: Some(Duration::from_secs(20)),
            ..Default::default()
        };
        assert!(options.connect_string.starts_with("localhost:1523/"));
        // Use the actual production lane/runtime/stack, not a test-only stack override.
        use oraclemcp_core::ToolDispatch;
        let lane = oraclemcp_core::LaneRuntime::spawn_default(
            "compile-fixture",
            Arc::new(NativeFixtureHarness {
                options,
                security_visibility,
            }),
        );
        let outcome = oraclemcp_core::block_on_lane_bridge(async {
            let cx = Cx::current().unwrap();
            let outcome = lane
                .dispatch(
                    &cx,
                    DispatchContext::default(),
                    "compile-fixture",
                    json!({}),
                )
                .await;
            oraclemcp_core::ToolDispatch::close(
                &lane,
                &cx,
                oraclemcp_core::DispatchCloseReason::ServerShutdown,
            )
            .await
            .unwrap();
            outcome
        });
        assert!(matches!(outcome, asupersync::Outcome::Ok(_)), "{outcome:?}");
    }

    fn observed_security(value: &Value) -> Result<(), String> {
        let observation = &value["compile_parse_observations"];
        if observation["status"] != "admitted_with_observation"
            || !observation["statements"]
                .as_array()
                .is_some_and(|statements| {
                    statements.iter().any(|statement| {
                        let fact = &statement["security_feature_evidence"];
                        fact["key"]["owner"] == "SYS"
                            && fact["key"]["name"] == "DUAL"
                            && fact["redaction"] == "unavailable"
                            && fact["key"]["object_id"].as_u64().is_some()
                    })
                })
        {
            return Err(format!(
                "unreadable redaction must remain an identity-bound observation: {value}"
            ));
        }
        Ok(())
    }

    async fn native_security_visibility(
        cx: &Cx,
        options: OracleConnectOptions,
    ) -> Result<(), String> {
        if options.username.as_deref() != Some("E2E_ORACLE") {
            return Err(
                "security-visibility fixture requires the unchanged CI E2E_ORACLE user".into(),
            );
        }
        let admin = RustOracleConnection::connect(cx, options.clone())
            .await
            .map_err(|error| error.to_string())?;
        let nonce = oraclemcp_db::PlanStatementId::generate().map_err(|error| error.to_string())?;
        let view = format!("OM_CV_{}", &nonce.as_str()[5..]);
        let source = format!("CREATE OR REPLACE VIEW {view} AS SELECT 1 AS id FROM dual");
        let compiles = Arc::new(AtomicUsize::new(0));
        let result = Box::pin(async {
            for strict in [false, true] {
                let conn = RustOracleConnection::connect(cx, options.clone()).await.map_err(|error|error.to_string())?;
                let mut level = SessionLevelState::new(OperatingLevel::Ddl, false);
                level.set_current_level(OperatingLevel::Ddl).unwrap();
                let dispatcher = OracleDispatcher::new_with_profile_level(
                    Box::new(NativeCompileObserver { inner: conn, compiles: Arc::clone(&compiles) }),
                    Some("compile-security-native".into()), level,
                ).with_security_feature_evidence_requirement(strict);
                let outcome = Box::pin(async {
                    let args = json!({"source_code":source});
                    if strict {
                        refuse(cx, &dispatcher, "oracle_create_or_replace", args, &compiles).await?;
                        let error = call(cx, &dispatcher, "oracle_create_or_replace", json!({"source_code":source,"execute":true,"confirm":"unissued"})).await.expect_err("strict direct apply must refuse");
                        if error.structured_reason.as_ref().is_none_or(|reason| reason.category != ReasonCategory::ParseCallbackUnproven) {
                            return Err(envelope(error));
                        }
                    } else {
                        let preview = call(cx, &dispatcher, "oracle_create_or_replace", args).await.map_err(envelope)?;
                        bound(&preview)?;
                        observed_security(&preview)?;
                        let applied = call(cx, &dispatcher, "oracle_create_or_replace", json!({"source_code":source,"execute":true,"confirm":confirmed(&preview)?})).await.map_err(envelope)?;
                        if applied["applied"] != true {return Err(format!("view was not applied: {applied}"));}
                        observed_security(&applied)?;
                        if count(cx, &admin, &format!("SELECT COUNT(*) N FROM {view} WHERE id=1")).await? != 1 {return Err("admitted view is not usable".into());}
                    }
                    if compiles.load(Ordering::SeqCst) != 1 {return Err("only the default observed apply may reach candidate DDL".into());}
                    Ok::<_,String>(())
                }).await;
                let close = dispatcher.state.lock(cx).await.unwrap().conn.close(cx).await.map_err(|error|error.to_string());
                outcome?;
                close?;
            }
            eprintln!("compile security visibility: unchanged CI account, observed preview/apply, strict preview/direct-apply refusal, one real candidate compile PASS");
            Ok::<_,String>(())
        }).await;
        let cleanup = admin.execute(cx, &format!("DROP VIEW {view}"), &[]).await;
        let close = admin.close(cx).await.map_err(|error| error.to_string());
        result?;
        cleanup.map_err(|error| error.to_string())?;
        close
    }

    async fn native_fixture(cx: &Cx, options: OracleConnectOptions) -> Result<(), String> {
        let cx = cx.clone();
        let admin = RustOracleConnection::connect(&cx, options.clone())
            .await
            .map_err(|error| error.to_string())?;
        let version = admin
            .query_rows(
                &cx,
                "SELECT version_full AS version FROM SYS.product_component_version WHERE ROWNUM=1",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
        eprintln!(
            "compile native Oracle version {}",
            version
                .first()
                .and_then(|row| row.text("VERSION"))
                .unwrap_or("unknown")
        );
        let nonce = oraclemcp_db::PlanStatementId::generate().map_err(|error| error.to_string())?;
        let schema = format!("OM_CP_{}", &nonce.as_str()[5..]);
        let password = format!("Compile{}A", &nonce.as_str()[5..25]);
        // Do not print the password-bearing CREATE USER statement.
        ddl(&cx,&admin,&format!("CREATE USER {schema} IDENTIFIED BY \"{password}\" DEFAULT TABLESPACE USERS QUOTA 8M ON USERS")).await?;
        eprintln!("compile native fixture {schema}");
        let outcome=Box::pin(async {
                ddl(&cx,&admin,&format!("GRANT CREATE SESSION, CREATE PROCEDURE, CREATE TYPE, CREATE VIEW, SELECT_CATALOG_ROLE TO {schema}")).await?;
                grant_catalog(&schema)?;
                for table in ["CLEAN_DATA","PROTECTED_DATA","CANARY"] {ddl(&cx,&admin,&format!("CREATE TABLE {schema}.{table}(ID NUMBER)")).await?;}
                ddl(&cx,&admin,&format!("INSERT INTO {schema}.PROTECTED_DATA VALUES(1)")).await?;
                admin.commit(&cx).await.map_err(|error|error.to_string())?;
                let clean=format!("CREATE OR REPLACE PROCEDURE {schema}.PATCH_ME AS n NUMBER; BEGIN SELECT COUNT(*) INTO n FROM {schema}.CLEAN_DATA; END;");
                ddl(&cx,&admin,&format!("CREATE TYPE {schema}.CLEAN_T AS OBJECT(id NUMBER,MEMBER FUNCTION label RETURN VARCHAR2)")).await?;
                let harmful=format!("CREATE OR REPLACE PROCEDURE {schema}.COMPILE_ME AS n NUMBER; BEGIN SELECT COUNT(*) INTO n FROM {schema}.PROTECTED_DATA; END;");
                ddl(&cx,&admin,&clean).await?;ddl(&cx,&admin,&harmful).await?;
                let original_patch=stored_source(&cx,&admin,&schema,"PATCH_ME","PROCEDURE").await.map_err(envelope)?;
                ddl(&cx,&admin,&format!("CREATE OR REPLACE FUNCTION {schema}.POLICY_FN(s VARCHAR2,o VARCHAR2) RETURN VARCHAR2 AUTHID DEFINER IS PRAGMA AUTONOMOUS_TRANSACTION; BEGIN INSERT INTO {schema}.CANARY(ID) VALUES(1); COMMIT; RETURN '1=1'; END;")).await?;
                let cross_source=format!("CREATE OR REPLACE PROCEDURE {schema}.CROSS_PROOF AS n NUMBER; BEGIN SELECT COUNT(*) INTO n FROM CLEAN_DATA; SELECT COUNT(*) INTO n FROM dual; END;");
                let cross=collect_compile_parse_effect_closure(&cx,&admin,&cross_source,&schema,false).await.map_err(envelope)?;
                if !cross.statements.iter().flat_map(|statement|&statement.objects).any(|object|object.owner==schema && object.name=="CLEAN_DATA") || !cross.statements.iter().flat_map(|statement|&statement.objects).any(|object|object.owner=="SYS" && object.name=="DUAL") {return Err("explicit owner resolution must retain local tables and PUBLIC synonyms".into());}
                let mut user=options.clone();user.username=Some(schema.clone());user.password=Some(password);
                let conn=RustOracleConnection::connect(&cx,user).await.map_err(|error|error.to_string())?;
                if count(&cx,&conn,"SELECT COUNT(*) N FROM SESSION_PRIVS WHERE PRIVILEGE='EXEMPT ACCESS POLICY'").await?!=0{return Err("canary reader must be subject to VPD".into());}
                let mut level=SessionLevelState::new(OperatingLevel::Ddl,false);level.set_current_level(OperatingLevel::Ddl).unwrap();
                let compiles=Arc::new(AtomicUsize::new(0));
                let dispatcher=OracleDispatcher::new_with_profile_level(Box::new(NativeCompileObserver{inner:conn,compiles:Arc::clone(&compiles)}),Some("compile-native".into()),level);
                let outcome=Box::pin(async {
                    let source=format!("CREATE OR REPLACE PACKAGE {schema}.CLEAN_API AS PROCEDURE p; END;");
                    let preview=call(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":source})).await.map_err(envelope)?;bound(&preview)?;
                    call(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":source,"execute":true,"confirm":confirmed(&preview)?})).await.map_err(envelope)?;
                    let body=format!("CREATE OR REPLACE PACKAGE BODY {schema}.CLEAN_API AS PROCEDURE p IS n NUMBER; BEGIN SELECT COUNT(*) INTO n FROM CLEAN_DATA; SELECT COUNT(*) INTO n FROM dual; END; END;");
                    let preview=call(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":body})).await.map_err(envelope)?;bound(&preview)?;
                    call(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":body,"execute":true,"confirm":confirmed(&preview)?})).await.map_err(envelope)?;
                    let compile=json!({"owner":schema,"name":"CLEAN_API","object_type":"PACKAGE BODY"});
                    let preview=call(&cx,&dispatcher,"oracle_compile_object",compile.clone()).await.map_err(envelope)?;bound(&preview)?;
                    let mut apply=compile;apply["execute"]=json!(true);apply["confirm"]=json!(confirmed(&preview)?);
                    call(&cx,&dispatcher,"oracle_compile_object",apply).await.map_err(envelope)?;
                    let type_body=format!("CREATE OR REPLACE TYPE BODY {schema}.CLEAN_T AS MEMBER FUNCTION label RETURN VARCHAR2 IS n NUMBER; BEGIN SELECT COUNT(*) INTO n FROM {schema}.CLEAN_DATA; RETURN 'ok'; END label; END CLEAN_T;");
                    let preview=call(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":type_body})).await.map_err(envelope)?;bound(&preview)?;
                    call(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":type_body,"execute":true,"confirm":confirmed(&preview)?})).await.map_err(envelope)?;
                    if compiles.load(Ordering::SeqCst)!=4{return Err("real observer must see exactly4 clean candidate DDL calls".into());}
                    // A safe metadata change must also invalidate its old grant;
                    // this proves digest binding independently of unsafe-policy refusal.
                    let clean_drift=format!("CREATE OR REPLACE PROCEDURE {schema}.CLEAN_DRIFT AS n NUMBER; BEGIN SELECT COUNT(*) INTO n FROM {schema}.CLEAN_DATA; END;");
                    let clean_preview=call(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":clean_drift})).await.map_err(envelope)?;
                    ddl(&cx,&admin,&format!("CREATE INDEX {schema}.CLEAN_I ON {schema}.CLEAN_DATA(ID)")).await?;
                    {
                        let state=dispatcher.state.lock(&cx).await.unwrap();
                        collect_compile_parse_effect_closure(&cx,state.conn.as_ref(),&clean_drift,&schema,false).await.map_err(envelope)?;
                    }
                    match call(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":clean_drift,"execute":true,"confirm":confirmed(&clean_preview)?})).await {
                        Err(error) if error.error_class==ErrorClass::RepreviewRequired=>(),
                        result=>return Err(format!("admissible catalog drift must invalidate the exact old grant: {result:?}")),
                    }
                    let drift=format!("CREATE OR REPLACE PROCEDURE {schema}.DRIFT_ME AS n NUMBER; BEGIN SELECT COUNT(*) INTO n FROM {schema}.PROTECTED_DATA; END;");
                    let drift_preview=call(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":drift})).await.map_err(envelope)?;
                    ddl(&cx,&admin,&format!("BEGIN SYS.DBMS_RLS.ADD_POLICY(object_schema=>'{schema}',object_name=>'PROTECTED_DATA',policy_name=>'AUTONOMOUS_CANARY',function_schema=>'{schema}',policy_function=>'POLICY_FN',statement_types=>'SELECT,INSERT,UPDATE,DELETE',update_check=>TRUE); END;")).await?;
                    {
                        let state=dispatcher.state.lock(&cx).await.unwrap();
                        state.conn.query_rows(&cx,&format!("SELECT COUNT(*) N FROM {schema}.PROTECTED_DATA"),&[]).await.map_err(|error|error.to_string())?;
                    }
                    let select_count=count(&cx,&admin,&format!("SELECT COUNT(*) N FROM {schema}.CANARY")).await?;
                    if select_count==0{return Err("VPD query control did not commit the autonomous canary".into());}
                    let mut observations=vec![("select",select_count)];
                    // These exact raw controls characterize this Oracle version.
                    // Their canary counts are observations, not an exploit claim.
                    for (path,sql) in [
                        ("fresh_procedure",format!("CREATE PROCEDURE {schema}.CONTROL_PROC AS n NUMBER; BEGIN SELECT /* fresh-control */ COUNT(*) INTO n FROM {schema}.PROTECTED_DATA; END;")),
                        ("alter_procedure",format!("ALTER PROCEDURE {schema}.COMPILE_ME COMPILE")),
                        ("fresh_view",format!("CREATE VIEW {schema}.CONTROL_VIEW AS SELECT /* fresh-control */ ID FROM {schema}.PROTECTED_DATA")),
                        ("alter_view",format!("ALTER VIEW {schema}.CONTROL_VIEW COMPILE")),
                    ] {
                        ddl(&cx,&admin,&format!("DELETE FROM {schema}.CANARY")).await?;admin.commit(&cx).await.map_err(|error|error.to_string())?;
                        {
                            let state=dispatcher.state.lock(&cx).await.unwrap();
                            state.conn.execute(&cx,&sql,&[]).await.map_err(|error|error.to_string())?;
                        }
                        observations.push((path,count(&cx,&admin,&format!("SELECT COUNT(*) N FROM {schema}.CANARY")).await?));
                    }
                    eprintln!("{}",json!({"case":"compile_parse_closure_native_free23","raw_control_canary_counts":observations}));
                    ddl(&cx,&admin,&format!("DELETE FROM {schema}.CANARY")).await?;admin.commit(&cx).await.map_err(|error|error.to_string())?;
                    let bad=drift.replace("DRIFT_ME","NEW_BAD");
                    refuse(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":bad}),&compiles).await?;
                    let bad_view=format!("CREATE OR REPLACE VIEW {schema}.BAD_VIEW AS SELECT id FROM {schema}.PROTECTED_DATA");
                    refuse(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":bad_view}),&compiles).await?;
                    refuse(&cx,&dispatcher,"oracle_patch_source",json!({"owner":schema,"name":"PATCH_ME","object_type":"PROCEDURE","old_text":"CLEAN_DATA","new_text":"PROTECTED_DATA"}),&compiles).await?;
                    refuse(&cx,&dispatcher,"oracle_compile_object",json!({"owner":schema,"name":"COMPILE_ME","object_type":"PROCEDURE"}),&compiles).await?;
                    refuse(&cx,&dispatcher,"oracle_preview_sql",json!({"sql":bad,"commit":true}),&compiles).await?;
                    let changed=call(&cx,&dispatcher,"oracle_create_or_replace",json!({"source_code":drift,"execute":true,"confirm":confirmed(&drift_preview)?})).await.expect_err("metadata drift must invalidate preview");
                    if changed.error_class!=ErrorClass::RepreviewRequired{return Err(envelope(changed));}
                    // Custom SQL DDL uses the same generic execute boundary.
                    let custom_sql=format!("CREATE OR REPLACE PROCEDURE {schema}.CUSTOM_OK AS n NUMBER; BEGIN SELECT COUNT(*) INTO n FROM {schema}.CLEAN_DATA; END;");
                    let defs=oraclemcp_core::parse_tools_file(&format!("[[tool]]\nname='app_compile_clean'\ndescription='Compile synthetic clean procedure'\nsql={custom_sql:?}\noutput_mode='rows'\n\n[[tool]]\nname='app_compile_bad'\ndescription='Compile synthetic guarded procedure'\nsql={bad:?}\noutput_mode='rows'\n")).map_err(|error|error.to_string())?;
                    let loaded=oraclemcp_core::load_tools(&defs,&Classifier::engine_free_baseline(ClassifierConfig::new()),OperatingLevel::Ddl).map_err(|error|error.to_string())?;
                    dispatcher.state.lock(&cx).await.unwrap().custom_catalog=ActiveCustomCatalog::new(2,CustomToolCatalog::new(loaded));
                    let preview=call(&cx,&dispatcher,"oracle_preview_sql",json!({"sql":custom_sql,"commit":true})).await.map_err(envelope)?;bound(&preview)?;
                    call(&cx,&dispatcher,"app_compile_clean",json!({"commit":true,"confirm":confirmed(&preview)?})).await.map_err(envelope)?;
                    refuse(&cx,&dispatcher,"app_compile_bad",json!({"commit":true}),&compiles).await?;
                    if compiles.load(Ordering::SeqCst)!=9{return Err("real observer must see exactly9 positive/control candidate DDL calls".into());}
                    if stored_source(&cx,&admin,&schema,"PATCH_ME","PROCEDURE").await.map_err(envelope)?!=original_patch{return Err("refused patch changed complete stored source".into());}
                    if count(&cx,&admin,&format!("SELECT COUNT(*) N FROM {schema}.CANARY")).await?!=0{return Err("refused compilation executed the autonomous canary".into());}
                    if count(&cx,&admin,&format!("SELECT COUNT(*) N FROM SYS.ALL_OBJECTS WHERE OWNER='{schema}' AND OBJECT_NAME IN ('NEW_BAD','BAD_VIEW','DRIFT_ME','CLEAN_DRIFT')")).await?!=0{return Err("refused candidate DDL reached Oracle".into());}
                    if count(&cx,&admin,&format!("SELECT COUNT(*) N FROM SYS.ALL_OBJECTS WHERE OWNER='{schema}' AND OBJECT_NAME='CLEAN_API' AND STATUS='VALID'")).await?!=2{return Err("clean package did not compile both units".into());}
                    if count(&cx,&admin,&format!("SELECT COUNT(*) N FROM SYS.ALL_OBJECTS WHERE OWNER='{schema}' AND OBJECT_NAME='CLEAN_T' AND OBJECT_TYPE='TYPE BODY' AND STATUS='VALID'")).await?!=1{return Err("clean named TYPE BODY did not compile".into());}
                    eprintln!("compile_parse_closure_native_free23: clean package/create/compile/custom PASS; VPD autonomous INSERT+COMMIT control and create/patch/compile/generic/custom refusals PASS; drift PASS");
                    Ok::<_,String>(())
                }).await;
                dispatcher.state.lock(&cx).await.unwrap().conn.close(&cx).await.map_err(|error|error.to_string())?;
                outcome
            }).await;
        let cleanup = ddl(&cx, &admin, &format!("DROP USER {schema} CASCADE")).await;
        admin.close(&cx).await.map_err(|error| error.to_string())?;
        outcome?;
        cleanup
    }
}
