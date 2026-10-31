//! Impact facts that can be computed without changing the guarded statement
//! path.  Every database observation is advisory; it never admits caller SQL.

use asupersync::Cx;
use oraclemcp_db::{
    CatalogQueryId, DbError, DependentObject, HardParseEffectClosureV1, OracleBind,
    OracleCatalogResolverCache, OracleConnection, PlanStatementId, QuarantineOutcome, explain_plan,
    plan_cost_estimate, prove_hard_parse_effect_closure, resolve_plan_table, run_catalog_query,
};
#[cfg(feature = "plsql-intelligence")]
use oraclemcp_db::{DepCaps, DependentsError, probe_dependents_transitive};
use oraclemcp_guard::{
    CatalogObjectKind, CatalogResolver, FieldStatus, ImpactV1, NotApplicableReason, OperatingLevel,
    RawName, RawNamePart, Resolution, ResolvedObject, StatementScope, SyntacticRole,
    UnavailableReason,
};
use serde_json::{Value, json};

const MAX_IMPACT_SQL_BYTES: usize = 64 * 1024;

fn preview_dependency_root(response: &Value) -> Option<DependentObject> {
    let fields = response
        .get("detected_object")
        .filter(|value| value.is_object())
        .unwrap_or(response);
    Some(DependentObject {
        owner: fields.get("owner")?.as_str()?.to_owned(),
        name: fields.get("name")?.as_str()?.to_owned(),
        object_type: fields.get("object_type")?.as_str()?.to_owned(),
    })
}

fn dependency_target_prefix(sql: &str) -> Option<(Option<String>, String, String)> {
    use sqlparser::{
        dialect::OracleDialect,
        tokenizer::{Token, Tokenizer},
    };
    if sql.is_empty() || sql.len() > MAX_IMPACT_SQL_BYTES {
        return None;
    }
    let tokens = Tokenizer::new(&OracleDialect {}, sql).tokenize().ok()?;
    // A second DDL verb cannot be silently reduced to the first target. String
    // literals and quoted identifiers never count as statement verbs.
    let ddl_verbs = tokens.iter().filter(|token| matches!(token, Token::Word(word)
        if word.quote_style.is_none() && ["CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME", "GRANT", "REVOKE"]
            .iter().any(|verb| word.value.eq_ignore_ascii_case(verb)))).count();
    if ddl_verbs != 1 {
        return None;
    }
    let mut cursor = SqlPrefix::new(sql);
    let verb = cursor.word().ok()??.to_ascii_uppercase();
    if !matches!(verb.as_str(), "CREATE" | "ALTER" | "DROP" | "TRUNCATE") {
        return None;
    }
    if verb == "CREATE"
        && cursor.consume_word("OR").ok()?
        && !cursor.consume_word("REPLACE").ok()?
    {
        return None;
    }
    while cursor.consume_word("EDITIONABLE").ok()?
        || cursor.consume_word("NONEDITIONABLE").ok()?
        || cursor.consume_word("FORCE").ok()?
        || cursor.consume_word("NOFORCE").ok()?
    {}
    let mut kind = cursor.word().ok()??.to_ascii_uppercase();
    if matches!(kind.as_str(), "PACKAGE" | "TYPE") && cursor.consume_word("BODY").ok()? {
        kind.push_str(" BODY");
    }
    if kind == "MATERIALIZED" {
        if !cursor.consume_word("VIEW").ok()? {
            return None;
        }
        kind.push_str(" VIEW");
    }
    if !matches!(
        kind.as_str(),
        "TABLE"
            | "VIEW"
            | "PACKAGE"
            | "PACKAGE BODY"
            | "TYPE"
            | "TYPE BODY"
            | "PROCEDURE"
            | "FUNCTION"
            | "TRIGGER"
            | "SEQUENCE"
            | "SYNONYM"
            | "MATERIALIZED VIEW"
            | "INDEX"
    ) {
        return None;
    }
    let canonical = |part: RawNamePart| match part.quoting {
        oraclemcp_guard::QuoteSemantics::Quoted => part.text,
        oraclemcp_guard::QuoteSemantics::Unquoted => part.text.to_ascii_uppercase(),
    };
    let first = canonical(cursor.identifier().ok()?);
    let (owner, name) = if cursor.consume_punct(b'.').ok()? {
        (Some(first), canonical(cursor.identifier().ok()?))
    } else {
        (None, first)
    };
    if cursor.consume_punct(b'.').ok()? || cursor.consume_punct(b'@').ok()? {
        return None;
    }
    Some((owner, name, kind))
}

pub(super) async fn compute_dependents_impact(
    cx: &Cx,
    conn: &dyn OracleConnection,
    quarantine: &std::sync::Mutex<Option<super::ConnectionQuarantine>>,
    roots: &[DependentObject],
) -> FieldStatus<Value> {
    #[cfg(not(feature = "plsql-intelligence"))]
    {
        let _ = (cx, conn, quarantine, roots);
        FieldStatus::Unavailable {
            reason: UnavailableReason::EngineNotWired,
        }
    }
    #[cfg(feature = "plsql-intelligence")]
    {
        let closure = match probe_dependents_transitive(cx, conn, roots, DepCaps::default()).await {
            Ok(closure) => closure,
            Err(DependentsError::NoPrivilege) => {
                return FieldStatus::Unavailable {
                    reason: UnavailableReason::NoPrivilege,
                };
            }
            Err(DependentsError::Database(error)) => {
                quarantine_dependency_observation(quarantine, &error);
                return FieldStatus::Unavailable {
                    reason: UnavailableReason::CatalogUnavailable,
                };
            }
            Err(_) => {
                return FieldStatus::Unavailable {
                    reason: UnavailableReason::CatalogUnavailable,
                };
            }
        };
        let prediction = match crate::plsql_tools::predict_invalid_set(&closure) {
            Ok(prediction) => prediction,
            Err(_) => {
                return FieldStatus::Unavailable {
                    reason: UnavailableReason::CatalogUnavailable,
                };
            }
        };
        let Ok(mut value) = serde_json::to_value(&closure) else {
            return FieldStatus::Unavailable {
                reason: UnavailableReason::CatalogUnavailable,
            };
        };
        if let Some(fields) = value.as_object_mut() {
            fields.insert("prediction_mode".into(), prediction["mode"].clone());
            fields.insert(
                "predicted_invalid_set".into(),
                prediction["objects"].clone(),
            );
            fields.insert(
                "predicted_invalid_count".into(),
                prediction["count"].clone(),
            );
            fields.insert("uncertainties".into(), prediction["uncertainties"].clone());
        }
        FieldStatus::Estimated { value }
    }
}

fn quarantine_dependency_observation(
    quarantine: &std::sync::Mutex<Option<super::ConnectionQuarantine>>,
    error: &DbError,
) {
    if error.is_uncertain_session_state() {
        // R36 preserves the advisory preview, but a failed observation must
        // not silently put an unsynchronized wire back into circulation.
        let _ = super::mark_connection_quarantined(
            quarantine,
            oraclemcp_audit::AuditOutcome::UnknownDiscarded,
            "dependency observation lost a synchronized Oracle session".to_owned(),
        );
    }
}

/// Dependency observations never alter a preview's admission or confirmation.
pub(super) async fn enrich_dependents_preview(
    response: &mut Value,
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    required_level: Option<OperatingLevel>,
    quarantine: &std::sync::Mutex<Option<super::ConnectionQuarantine>>,
) {
    if !is_confirmation_preview(response) {
        return;
    }
    let dependents = if !required_level.is_some_and(|level| level >= OperatingLevel::Ddl) {
        FieldStatus::NotApplicable {
            reason: NotApplicableReason::NoEffect,
        }
    } else if !response
        .as_object()
        .is_some_and(|fields| preview_admits_effect_probes(fields, required_level))
    {
        FieldStatus::Unavailable {
            reason: UnavailableReason::LevelBelowRequired,
        }
    } else {
        let root = if response.get("detected_object").is_none()
            && preview_dependency_root(response).is_some()
        {
            preview_dependency_root(response)
        } else if let Some((owner, name, kind)) = dependency_target_prefix(sql) {
            let owner = match owner {
                Some(owner) => Some(owner),
                None => match conn.describe(cx).await {
                    Ok(info) => info.current_schema.or(info.session_user),
                    Err(error) => {
                        quarantine_dependency_observation(quarantine, &error);
                        None
                    }
                },
            };
            owner.map(|owner| DependentObject {
                owner,
                name,
                object_type: kind,
            })
        } else {
            None
        };
        match root {
            Some(root) => compute_dependents_impact(cx, conn, quarantine, &[root]).await,
            None => FieldStatus::Unavailable {
                reason: UnavailableReason::UnresolvedDependency,
            },
        }
    };
    if let Some(fields) = response.as_object_mut() {
        let mut impact = fields
            .get("impact")
            .and_then(|value| serde_json::from_value::<ImpactV1>(value.clone()).ok())
            .unwrap_or_default();
        impact.dependents = dependents;
        if let Ok(value) = serde_json::to_value(impact) {
            fields.insert("impact".into(), value);
        }
    }
}

/// Resolve the one local DML target for which this impact slice can make a
/// closed optimizer claim. Complex/multi-source DML remains explicitly
/// unavailable rather than guessing from a partial name.
pub(super) async fn resolve_dml_relations(
    cx: &Cx,
    conn: &dyn OracleConnection,
    cache: &OracleCatalogResolverCache,
    sql: &str,
) -> Result<Vec<ResolvedObject>, UnavailableReason> {
    let name = parse_single_local_dml_target(sql)?;
    let context = cache
        .preload(
            cx,
            conn,
            std::slice::from_ref(&name),
            StatementScope::default(),
        )
        .await
        .map_err(|_| UnavailableReason::HardParseCallbacks)?;
    match cache.resolve(&name, &context) {
        Resolution::Resolved(object)
            if object.kind == CatalogObjectKind::Table && object.db_link.is_none() =>
        {
            Ok(vec![*object])
        }
        Resolution::Remote { .. }
        | Resolution::Ambiguous { .. }
        | Resolution::Unresolved
        | Resolution::Resolved(_) => Err(UnavailableReason::HardParseCallbacks),
    }
}

pub(super) async fn resolve_ddl_lock_targets(
    cx: &Cx,
    conn: &dyn OracleConnection,
    cache: &OracleCatalogResolverCache,
    sql: &str,
) -> Result<Vec<ResolvedObject>, UnavailableReason> {
    let name = parse_single_ddl_target(sql)?;
    let context = cache
        .preload(
            cx,
            conn,
            std::slice::from_ref(&name),
            StatementScope::default(),
        )
        .await
        .map_err(|_| UnavailableReason::Truncated)?;
    match cache.resolve(&name, &context) {
        Resolution::Resolved(object) if object.db_link.is_none() => Ok(vec![*object]),
        Resolution::Remote { .. }
        | Resolution::Ambiguous { .. }
        | Resolution::Unresolved
        | Resolution::Resolved(_) => Err(UnavailableReason::Truncated),
    }
}

fn parse_single_ddl_target(sql: &str) -> Result<RawName, UnavailableReason> {
    if sql.is_empty()
        || sql.len() > MAX_IMPACT_SQL_BYTES
        || sql.contains(';')
        || sql.contains('@')
        || sql.to_ascii_uppercase().contains("WITH")
    {
        return Err(UnavailableReason::Truncated);
    }
    let mut cursor = SqlPrefix::new(sql);
    let statement = cursor
        .word()
        .map_err(|_| UnavailableReason::Truncated)?
        .ok_or(UnavailableReason::Truncated)?;
    let object_type = if statement.eq_ignore_ascii_case("TRUNCATE") {
        let _ = cursor
            .consume_word("TABLE")
            .map_err(|_| UnavailableReason::Truncated)?;
        "TABLE".to_owned()
    } else if statement.eq_ignore_ascii_case("ALTER") || statement.eq_ignore_ascii_case("DROP") {
        cursor
            .word()
            .map_err(|_| UnavailableReason::Truncated)?
            .ok_or(UnavailableReason::Truncated)?
    } else {
        return Err(UnavailableReason::Truncated);
    };
    if !matches!(
        object_type.to_ascii_uppercase().as_str(),
        "TABLE" | "VIEW" | "INDEX" | "MATERIALIZED" | "SEQUENCE" | "TRIGGER"
    ) {
        return Err(UnavailableReason::Truncated);
    }
    if object_type.eq_ignore_ascii_case("MATERIALIZED")
        && !cursor
            .consume_word("VIEW")
            .map_err(|_| UnavailableReason::Truncated)?
    {
        return Err(UnavailableReason::Truncated);
    }
    let first = cursor
        .identifier()
        .map_err(|_| UnavailableReason::Truncated)?;
    let mut parts = vec![first];
    if cursor
        .consume_punct(b'.')
        .map_err(|_| UnavailableReason::Truncated)?
    {
        parts.push(
            cursor
                .identifier()
                .map_err(|_| UnavailableReason::Truncated)?,
        );
        if cursor
            .consume_punct(b'.')
            .map_err(|_| UnavailableReason::Truncated)?
        {
            return Err(UnavailableReason::Truncated);
        }
    }
    Ok(RawName::new(parts, SyntacticRole::FromFactor))
}

fn parse_single_local_dml_target(sql: &str) -> Result<RawName, UnavailableReason> {
    if sql.is_empty() || sql.len() > MAX_IMPACT_SQL_BYTES || sql.contains(';') || sql.contains('@')
    {
        return Err(UnavailableReason::UnsupportedDmlShape);
    }
    // The closure currently accepts only a DML statement with one target and
    // no query blocks. This conservative marker rejection may refuse a string
    // literal containing these words; it cannot mistake one for proof.
    let uppercase = sql.to_ascii_uppercase();
    if uppercase.contains("SELECT") || uppercase.contains("WITH") {
        return Err(UnavailableReason::UnsupportedDmlShape);
    }

    let mut cursor = SqlPrefix::new(sql);
    let statement = cursor
        .word()?
        .ok_or(UnavailableReason::UnsupportedDmlShape)?;
    let delete = if statement.eq_ignore_ascii_case("UPDATE") {
        false
    } else if statement.eq_ignore_ascii_case("DELETE") {
        if !cursor.consume_word("FROM")? {
            return Err(UnavailableReason::UnsupportedDmlShape);
        }
        true
    } else {
        return Err(UnavailableReason::UnsupportedDmlShape);
    };

    let first = cursor.identifier()?;
    let mut parts = vec![first];
    if cursor.consume_punct(b'.')? {
        parts.push(cursor.identifier()?);
        if cursor.consume_punct(b'.')? {
            return Err(UnavailableReason::UnsupportedDmlShape);
        }
    }
    let next = cursor
        .word()?
        .ok_or(UnavailableReason::UnsupportedDmlShape)?;
    let expected = if delete { "WHERE" } else { "SET" };
    if !next.eq_ignore_ascii_case(expected) {
        return Err(UnavailableReason::UnsupportedDmlShape);
    }
    Ok(RawName::new(parts, SyntacticRole::FromFactor))
}

pub(super) fn is_dml_statement(sql: &str) -> bool {
    let mut cursor = SqlPrefix::new(sql);
    cursor.word().ok().flatten().is_some_and(|word| {
        ["UPDATE", "DELETE", "INSERT", "MERGE"]
            .iter()
            .any(|verb| word.eq_ignore_ascii_case(verb))
    })
}

/// Tiny fail-closed lexer for the DML target prefix. It does not parse or
/// rewrite the statement body; Oracle/classifier remain authoritative there.
struct SqlPrefix<'a> {
    source: &'a [u8],
    position: usize,
}

impl<'a> SqlPrefix<'a> {
    const fn new(source: &'a str) -> Self {
        Self {
            source: source.as_bytes(),
            position: 0,
        }
    }

    fn skip_trivia(&mut self) -> Result<(), UnavailableReason> {
        loop {
            while self
                .source
                .get(self.position)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.position += 1;
            }
            if self.source.get(self.position..self.position + 2) == Some(b"--") {
                self.position += 2;
                while self
                    .source
                    .get(self.position)
                    .is_some_and(|byte| *byte != b'\n')
                {
                    self.position += 1;
                }
                continue;
            }
            if self.source.get(self.position..self.position + 2) == Some(b"/*") {
                self.position += 2;
                let Some(relative_end) = self.source[self.position..]
                    .windows(2)
                    .position(|window| window == b"*/")
                else {
                    return Err(UnavailableReason::UnsupportedDmlShape);
                };
                self.position += relative_end + 2;
                continue;
            }
            return Ok(());
        }
    }

    fn word(&mut self) -> Result<Option<String>, UnavailableReason> {
        self.skip_trivia()?;
        let start = self.position;
        let Some(first) = self.source.get(self.position).copied() else {
            return Ok(None);
        };
        if !first.is_ascii_alphabetic() {
            return Ok(None);
        }
        self.position += 1;
        while self
            .source
            .get(self.position)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'$' | b'#'))
        {
            self.position += 1;
        }
        let text = std::str::from_utf8(&self.source[start..self.position])
            .map_err(|_| UnavailableReason::UnsupportedDmlShape)?;
        Ok(Some(text.to_owned()))
    }

    fn consume_word(&mut self, expected: &str) -> Result<bool, UnavailableReason> {
        let saved = self.position;
        match self.word()? {
            Some(word) if word.eq_ignore_ascii_case(expected) => Ok(true),
            _ => {
                self.position = saved;
                Ok(false)
            }
        }
    }

    fn consume_punct(&mut self, expected: u8) -> Result<bool, UnavailableReason> {
        self.skip_trivia()?;
        if self.source.get(self.position) == Some(&expected) {
            self.position += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn identifier(&mut self) -> Result<RawNamePart, UnavailableReason> {
        self.skip_trivia()?;
        match self.source.get(self.position).copied() {
            Some(b'"') => self.quoted_identifier(),
            Some(first) if first.is_ascii_alphabetic() => {
                let word = self.word()?.ok_or(UnavailableReason::UnsupportedDmlShape)?;
                Ok(RawNamePart::unquoted(word))
            }
            _ => Err(UnavailableReason::UnsupportedDmlShape),
        }
    }

    fn quoted_identifier(&mut self) -> Result<RawNamePart, UnavailableReason> {
        self.position += 1;
        let mut value = String::new();
        loop {
            let Some(byte) = self.source.get(self.position).copied() else {
                return Err(UnavailableReason::UnsupportedDmlShape);
            };
            self.position += 1;
            match byte {
                b'"' if self.source.get(self.position) == Some(&b'"') => {
                    value.push('"');
                    self.position += 1;
                }
                b'"' => return Ok(RawNamePart::quoted(value)),
                byte if byte.is_ascii() => value.push(char::from(byte)),
                _ => return Err(UnavailableReason::UnsupportedDmlShape),
            }
        }
    }
}

/// Project the execution envelope onto a stable reversibility classification.
/// This is pure: it does not alter the classification or authorization result.
pub(super) fn compute_reversibility(
    required_level: Option<OperatingLevel>,
    is_dml: bool,
    commit: bool,
    hold: bool,
    non_transactional_effect: bool,
) -> FieldStatus<Value> {
    let status = if commit
        || required_level.is_some_and(|level| level >= OperatingLevel::Ddl)
        || non_transactional_effect
    {
        "irreversible"
    } else if hold {
        "needs_checkpoint"
    } else if is_dml {
        "rolled_back_by_default"
    } else {
        return FieldStatus::NotApplicable {
            reason: NotApplicableReason::NoEffect,
        };
    };
    FieldStatus::Computed {
        value: json!(status),
    }
}

/// Compute optimizer estimates only after the caller has already classified
/// the statement and supplied exact resolved relation identities.  The
/// generated plan is isolated by statement id and its write is always rolled
/// back to this function's savepoint.
#[allow(clippy::too_many_arguments)]
pub(super) async fn compute_cost_impact(
    cx: &Cx,
    conn: &dyn OracleConnection,
    read_only_backstop: &super::ReadOnlyBackstop,
    quarantine: &std::sync::Mutex<Option<super::ConnectionQuarantine>>,
    sql: &str,
    relations: &[ResolvedObject],
    level: OperatingLevel,
    configured_plan_table: Option<&str>,
    max_query_cost: Option<u64>,
    read_only_standby: bool,
) -> Result<FieldStatus<Value>, DbError> {
    let unavailable = |reason| FieldStatus::Unavailable { reason };
    // The preview carries an explicit unavailable cost at READ_ONLY. Do not
    // probe catalogs or issue SAVEPOINT/ROLLBACK against the still-armed
    // database-side transaction backstop.
    if level == OperatingLevel::ReadOnly || read_only_backstop.is_armed() {
        return Ok(unavailable(UnavailableReason::ReadOnlyTxn));
    }
    if relations.is_empty()
        || relations
            .iter()
            .any(|relation| relation.kind != CatalogObjectKind::Table || relation.db_link.is_some())
    {
        return Ok(unavailable(UnavailableReason::HardParseCallbacks));
    }

    // A cost preview cannot write into a caller-controlled table. The resolver
    // rejects local objects/private synonyms and verifies the public SYS GTT.
    let table = match resolve_plan_table(cx, conn, configured_plan_table).await {
        Ok(table) if table.verification_observation().is_none() => table,
        Ok(_) | Err(_) => return Ok(unavailable(UnavailableReason::PlanTableUnverified)),
    };

    // Impact cost is stricter than the read-path's observed-admission mode:
    // any unreadable or truncated proof makes the estimate unavailable.
    let closure = prove_hard_parse_effect_closure(cx, conn, sql, relations).await;
    match closure {
        HardParseEffectClosureV1::Proven => {}
        HardParseEffectClosureV1::Refused { reason }
        | HardParseEffectClosureV1::Unavailable { reason }
        | HardParseEffectClosureV1::AdmittedWithObservation { reason } => {
            if reason == "policy_code"
                && has_visible_vpd_policy(cx, conn, relations)
                    .await
                    .unwrap_or(false)
            {
                return Ok(unavailable(UnavailableReason::Vpd));
            }
            return Ok(unavailable(UnavailableReason::HardParseCallbacks));
        }
    }

    let statement_id = PlanStatementId::generate()?;
    let savepoint_name = impact_savepoint_name(&statement_id);
    let savepoint_sql = format!("SAVEPOINT {savepoint_name}");
    let rollback_sql = format!("ROLLBACK TO {savepoint_name}");

    if let Err(error) = conn.execute(cx, &savepoint_sql, &[]).await {
        return if super::is_read_only_transaction_error(&error) {
            Ok(unavailable(UnavailableReason::ReadOnlyTxn))
        } else if error.is_uncertain_session_state() {
            Err(quarantined_impact_error(
                quarantine,
                format!("impact EXPLAIN savepoint outcome is uncertain: {error}"),
            ))
        } else {
            Ok(unavailable(UnavailableReason::PlanTableUnverified))
        };
    }

    let estimate = async {
        explain_plan(cx, conn, sql, &table, &statement_id, read_only_standby).await?;
        plan_cost_estimate(cx, conn, &table, &statement_id).await
    }
    .await;

    // Cleanup is mandatory on success and on every failed EXPLAIN/read path.
    // A failed rollback quarantines the session rather than reporting a clean
    // advisory result.
    if let Err(error) = conn.execute(cx, &rollback_sql, &[]).await {
        return Err(quarantined_impact_error(
            quarantine,
            format!("impact EXPLAIN savepoint rollback failed: {error}"),
        ));
    }

    let estimate = match estimate {
        Ok(Some(estimate)) => estimate,
        Ok(None) => return Ok(unavailable(UnavailableReason::PlanTableUnverified)),
        Err(error) if super::is_read_only_transaction_error(&error) => {
            return Ok(unavailable(UnavailableReason::ReadOnlyTxn));
        }
        Err(error) if error.is_uncertain_session_state() => {
            return Err(quarantined_impact_error(
                quarantine,
                format!("impact EXPLAIN result is uncertain: {error}"),
            ));
        }
        Err(_) => return Ok(unavailable(UnavailableReason::PlanTableUnverified)),
    };

    let remaining =
        super::read_executor::verified_plan_table_row_count(cx, conn, &table, &statement_id).await;
    let remaining = match remaining {
        Ok(rows) => rows,
        Err(error) if error.is_uncertain_session_state() => {
            return Err(quarantined_impact_error(
                quarantine,
                format!("impact PLAN_TABLE cleanup verification is uncertain: {error}"),
            ));
        }
        Err(_) => return Ok(unavailable(UnavailableReason::PlanTableUnverified)),
    };
    if remaining != Some(0) {
        return Ok(unavailable(UnavailableReason::PlanTableUnverified));
    }

    let total_cost = estimate
        .summary
        .total_cost
        .and_then(|cost| u64::try_from(cost).ok());
    let within_limit = total_cost
        .zip(max_query_cost)
        .map(|(cost, limit)| cost <= limit);
    Ok(FieldStatus::Estimated {
        value: json!({
            "statement_id": statement_id.as_str(),
            "total_cost": total_cost,
            "cardinality": estimate.summary.total_cardinality,
            "bytes": estimate.summary.total_bytes,
            "max_query_cost": max_query_cost,
            "within_max_query_cost": within_limit,
            "note": estimate.note,
        }),
    })
}

fn quarantined_impact_error(
    quarantine: &std::sync::Mutex<Option<super::ConnectionQuarantine>>,
    message: String,
) -> DbError {
    if let Err(error) = super::mark_connection_quarantined(
        quarantine,
        super::AuditOutcome::UnknownDiscarded,
        message.clone(),
    ) {
        return DbError::Refused(Box::new(error));
    }
    DbError::Quarantined {
        outcome: QuarantineOutcome::UnknownDiscarded,
        message,
    }
}

/// Predict the table locks a DML statement requests, or inspect current lock
/// and access holders for DDL when the caller can read both diagnostic views.
/// Lack of either privilege is reported explicitly; it is never rendered as
/// an empty lock list.
pub(super) async fn compute_locks_impact(
    cx: &Cx,
    conn: &dyn OracleConnection,
    required_level: Option<OperatingLevel>,
    is_dml: bool,
    relations: &[ResolvedObject],
) -> FieldStatus<Value> {
    let unavailable = |reason| FieldStatus::Unavailable { reason };
    let Some(required_level) = required_level else {
        return unavailable(UnavailableReason::HardParseCallbacks);
    };
    if relations.is_empty() {
        if !is_dml && required_level < OperatingLevel::Ddl {
            return FieldStatus::NotApplicable {
                reason: NotApplicableReason::NoEffect,
            };
        }
        return unavailable(UnavailableReason::HardParseCallbacks);
    }

    if is_dml {
        return FieldStatus::Estimated {
            value: json!({
                "kind": "dml_target_tables",
                "locks": relations.iter().map(|relation| json!({
                    "owner": relation.owner,
                    "object": relation.name,
                    "mode": "row_exclusive",
                })).collect::<Vec<_>>(),
            }),
        };
    }
    if required_level < OperatingLevel::Ddl {
        return FieldStatus::NotApplicable {
            reason: NotApplicableReason::NoEffect,
        };
    }

    let mut locks = Vec::new();
    for relation in relations {
        let binds = || {
            [
                OracleBind::String(relation.owner.clone()),
                OracleBind::String(relation.name.clone()),
                OracleBind::I64(65),
            ]
        };
        let ddl_locks = match run_catalog_query(
            cx,
            conn,
            CatalogQueryId::ImpactDbaDdlLocksForObject,
            &binds(),
        )
        .await
        {
            Ok(rows) if rows.len() <= 64 => rows,
            Ok(_) => return unavailable(UnavailableReason::Truncated),
            Err(error) if is_no_privilege(&error) => {
                return unavailable(UnavailableReason::NoPrivilege);
            }
            Err(_) => return unavailable(UnavailableReason::Truncated),
        };
        let accesses =
            match run_catalog_query(cx, conn, CatalogQueryId::ImpactVAccessForObject, &binds())
                .await
            {
                Ok(rows) if rows.len() <= 64 => rows,
                Ok(_) => return unavailable(UnavailableReason::Truncated),
                Err(error) if is_no_privilege(&error) => {
                    return unavailable(UnavailableReason::NoPrivilege);
                }
                Err(_) => return unavailable(UnavailableReason::Truncated),
            };
        locks.extend(ddl_locks.into_iter().map(|row| {
            json!({
                "source": "dba_ddl_locks",
                "owner": row.text("OWNER"),
                "object": row.text("NAME"),
                "object_type": row.text("TYPE"),
                "mode_held": row.text("MODE_HELD"),
            })
        }));
        locks.extend(accesses.into_iter().map(|row| {
            json!({
                "source": "v$access",
                "sid": row.parse_i64("SID"),
                "owner": row.text("OWNER"),
                "object": row.text("OBJECT"),
                "object_type": row.text("TYPE"),
            })
        }));
    }
    FieldStatus::Computed {
        value: json!({ "kind": "current_ddl_locks_and_access", "locks": locks }),
    }
}

/// Enrich a status-complete confirmation preview without changing its gate or
/// confirmation material. The caller must pass the exact decision already
/// used to construct the preview, plus the current connection/backstop state.
#[allow(clippy::too_many_arguments)]
pub(super) async fn enrich_preview_impact(
    response: &mut Value,
    cx: &Cx,
    conn: &dyn OracleConnection,
    read_only_backstop: &super::ReadOnlyBackstop,
    quarantine: &std::sync::Mutex<Option<super::ConnectionQuarantine>>,
    catalog_cache: &OracleCatalogResolverCache,
    sql: &str,
    required_level: Option<OperatingLevel>,
    is_dml: bool,
    commit: bool,
    hold: bool,
    non_transactional_effect: bool,
    current_level: OperatingLevel,
    configured_plan_table: Option<&str>,
    max_query_cost: Option<u64>,
    read_only_standby: bool,
) -> Result<(), DbError> {
    if !is_confirmation_preview(response) {
        return Ok(());
    }
    enrich_dependents_preview(response, cx, conn, sql, required_level, quarantine).await;
    let Some(fields) = response.as_object_mut() else {
        return Ok(());
    };

    let mut impact = fields
        .get("impact")
        .and_then(|value| serde_json::from_value::<ImpactV1>(value.clone()).ok())
        .unwrap_or_default();
    impact.reversibility = compute_reversibility(
        required_level,
        is_dml,
        commit,
        hold,
        non_transactional_effect,
    );

    if !preview_admits_effect_probes(fields, required_level) {
        impact.cost = FieldStatus::Unavailable {
            reason: if current_level == OperatingLevel::ReadOnly
                && required_level.is_some_and(|level| level > OperatingLevel::ReadOnly)
            {
                UnavailableReason::ReadOnlyTxn
            } else {
                UnavailableReason::LevelBelowRequired
            },
        };
        impact.locks = FieldStatus::Unavailable {
            reason: UnavailableReason::LevelBelowRequired,
        };
        fields.insert(
            "impact".to_owned(),
            serde_json::to_value(impact).map_err(|error| {
                DbError::Internal(format!("impact serialization failed: {error}"))
            })?,
        );
        return Ok(());
    }

    if is_dml {
        match resolve_dml_relations(cx, conn, catalog_cache, sql).await {
            Ok(relations) => {
                impact.locks =
                    compute_locks_impact(cx, conn, required_level, true, &relations).await;
                impact.cost = compute_cost_impact(
                    cx,
                    conn,
                    read_only_backstop,
                    quarantine,
                    sql,
                    &relations,
                    current_level,
                    configured_plan_table,
                    max_query_cost,
                    read_only_standby,
                )
                .await?;
            }
            Err(reason) => {
                impact.cost = FieldStatus::Unavailable { reason };
                impact.locks = FieldStatus::Unavailable { reason };
            }
        }
    } else {
        impact.cost = FieldStatus::NotApplicable {
            reason: NotApplicableReason::NoEffect,
        };
        if required_level.is_some_and(|level| level >= OperatingLevel::Ddl) {
            match resolve_ddl_lock_targets(cx, conn, catalog_cache, sql).await {
                Ok(relations) => {
                    impact.locks =
                        compute_locks_impact(cx, conn, required_level, false, &relations).await;
                }
                Err(reason) => impact.locks = FieldStatus::Unavailable { reason },
            }
        } else {
            impact.locks = FieldStatus::NotApplicable {
                reason: NotApplicableReason::NoEffect,
            };
        }
    }

    fields.insert(
        "impact".to_owned(),
        serde_json::to_value(impact)
            .map_err(|error| DbError::Internal(format!("impact serialization failed: {error}")))?,
    );
    Ok(())
}

pub(super) fn is_confirmation_preview(response: &Value) -> bool {
    response.as_object().is_some_and(|fields| {
        fields.contains_key("execute_confirmation")
            || (fields.get("preview").and_then(Value::as_bool) == Some(true)
                && fields.contains_key("confirmation"))
    })
}

fn preview_admits_effect_probes(
    fields: &serde_json::Map<String, Value>,
    required_level: Option<OperatingLevel>,
) -> bool {
    required_level.is_some() && fields.get("gate_decision").and_then(Value::as_str) == Some("allow")
}

async fn has_visible_vpd_policy(
    cx: &Cx,
    conn: &dyn OracleConnection,
    relations: &[ResolvedObject],
) -> Result<bool, DbError> {
    for relation in relations {
        let rows = run_catalog_query(
            cx,
            conn,
            CatalogQueryId::HardParseVpdPolicies,
            &[
                OracleBind::String(relation.owner.clone()),
                OracleBind::String(relation.name.clone()),
                OracleBind::I64(2),
            ],
        )
        .await?;
        if !rows.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
fn is_plan_table_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"_$#".contains(&byte)
        })
}

fn impact_savepoint_name(statement_id: &PlanStatementId) -> String {
    // Oracle limits savepoint identifiers to 30 bytes. The random 24-byte
    // statement-id suffix plus the fixed two-byte prefix stays within that
    // limit and prevents concurrent previews from replacing each other's
    // rollback marker on a shared connection.
    format!("I_{}", &statement_id.as_str()[5..])
}

fn is_no_privilege(error: &DbError) -> bool {
    let text = error.to_string();
    text.contains("ORA-00942") || text.contains("ORA-01031")
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::RuntimeBuilder;
    use oraclemcp_db::{OracleBackend, OracleConnectionInfo, OracleRow};
    use std::sync::Mutex;

    #[derive(Default)]
    struct CountingConnection {
        calls: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for CountingConnection {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
            self.calls.lock().expect("calls").push("close".to_owned());
            Ok(())
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            self.calls.lock().expect("calls").push("ping".to_owned());
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            self.calls
                .lock()
                .expect("calls")
                .push("describe".to_owned());
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.calls.lock().expect("calls").push("query".to_owned());
            Ok(Vec::new())
        }

        async fn execute(
            &self,
            _cx: &Cx,
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            self.calls.lock().expect("calls").push(sql.to_owned());
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            self.calls.lock().expect("calls").push("commit".to_owned());
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            self.calls
                .lock()
                .expect("calls")
                .push("rollback".to_owned());
            Ok(())
        }
    }

    fn run_with_cx<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(Cx) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async move {
            let cx = Cx::current().expect("block_on installs a current Cx");
            body(cx).await
        })
    }

    #[test]
    fn dependents_target_prefix_preserves_exact_quoted_identity() {
        assert_eq!(
            dependency_target_prefix(
                "/* CREATE */ CREATE OR REPLACE EDITIONABLE PACKAGE BODY \"MiX\".\"P.K\"\"G\" AS PROCEDURE p IS BEGIN NULL; END; END;"
            ),
            Some((Some("MiX".into()), "P.K\"G".into(), "PACKAGE BODY".into()))
        );
        assert_eq!(
            dependency_target_prefix(
                "CREATE OR REPLACE VIEW app.v AS SELECT 'CREATE TABLE' txt FROM dual"
            ),
            Some((Some("APP".into()), "V".into(), "VIEW".into()))
        );
        assert_eq!(
            dependency_target_prefix("ALTER TABLE t ADD x NUMBER"),
            Some((None, "T".into(), "TABLE".into()))
        );
    }

    #[test]
    fn dependents_target_prefix_refuses_batches_remote_and_unknown_targets() {
        for sql in [
            "CREATE TABLE a(x NUMBER); DROP TABLE b",
            "ALTER TABLE app.t@remote ADD x NUMBER",
            "ALTER TABLE pdb.app.t ADD x NUMBER",
            "GRANT SELECT ON app.t TO other",
            "BEGIN NULL; END;",
            "CREATE OR REPLACE PACKAGE \"unterminated AS END;",
        ] {
            assert!(
                dependency_target_prefix(sql).is_none(),
                "partial target for {sql}"
            );
        }
    }

    #[test]
    fn impact_reversibility_matrix() {
        assert_eq!(
            compute_reversibility(Some(OperatingLevel::ReadWrite), true, false, false, false),
            FieldStatus::Computed {
                value: json!("rolled_back_by_default")
            }
        );
        assert_eq!(
            compute_reversibility(Some(OperatingLevel::ReadWrite), true, false, true, false),
            FieldStatus::Computed {
                value: json!("needs_checkpoint")
            }
        );
        for (level, commit, non_transactional) in [
            (OperatingLevel::Ddl, false, false),
            (OperatingLevel::ReadWrite, true, false),
            (OperatingLevel::ReadWrite, false, true),
        ] {
            assert_eq!(
                compute_reversibility(Some(level), true, commit, false, non_transactional),
                FieldStatus::Computed {
                    value: json!("irreversible")
                }
            );
        }
        assert_eq!(
            compute_reversibility(Some(OperatingLevel::ReadWrite), false, false, false, true,),
            FieldStatus::Computed {
                value: json!("irreversible")
            }
        );
    }

    #[test]
    fn impact_target_parser_preserves_quoted_identity_and_rejects_complex_dml() {
        let target = parse_single_local_dml_target(
            "/* preview */ UPDATE \"Mixed.Schema\".accounts SET active = 0 WHERE id = 1",
        )
        .expect("simple quoted target");
        assert_eq!(target.parts[0], RawNamePart::quoted("Mixed.Schema"));
        assert_eq!(target.parts[1], RawNamePart::unquoted("accounts"));

        for unsupported in [
            "UPDATE accounts a SET active = 0 WHERE id = 1",
            "UPDATE accounts SET active = (SELECT 0 FROM dual) WHERE id = 1",
            "DELETE FROM accounts@remote WHERE id = 1",
            "UPDATE accounts SET active = 0 WHERE id = 1; DELETE FROM accounts WHERE id = 2",
        ] {
            assert_eq!(
                parse_single_local_dml_target(unsupported),
                Err(UnavailableReason::UnsupportedDmlShape),
                "{unsupported}"
            );
        }
        assert!(is_dml_statement(
            "/* preview */ UPDATE accounts SET active = 0"
        ));
        assert!(is_dml_statement(
            "-- preview\nDELETE FROM accounts WHERE id = 1"
        ));
        assert!(is_dml_statement("INSERT INTO accounts (id) VALUES (1)"));
        assert!(is_dml_statement(
            "MERGE INTO accounts a USING source s ON (a.id=s.id)"
        ));
        assert!(!is_dml_statement("SELECT * FROM accounts"));
    }

    #[test]
    fn impact_cost_statement_id_alphabet_validated() {
        let id = PlanStatementId::generate().expect("OS random source");
        assert_eq!(id.as_str().len(), 29);
        assert!(id.as_str().starts_with("OMCP_"));
        assert!(
            id.as_str()[5..]
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        );
        let savepoint = impact_savepoint_name(&id);
        assert_eq!(savepoint.len(), 26);
        assert!(savepoint.starts_with("I_"));
        assert!(
            savepoint[2..]
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        );
        let other_id = PlanStatementId::generate().expect("independent OS random source");
        assert_ne!(savepoint, impact_savepoint_name(&other_id));
    }

    #[test]
    fn impact_cleanup_uncertainty_quarantines_the_dispatcher_connection() {
        let quarantine = Mutex::new(None);
        let error = quarantined_impact_error(&quarantine, "synthetic cleanup failure".to_owned());
        assert!(matches!(
            error,
            DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                ..
            }
        ));
        assert!(matches!(
            quarantine.lock().expect("quarantine").as_ref(),
            Some(super::super::ConnectionQuarantine {
                outcome: super::super::AuditOutcome::UnknownDiscarded,
                ..
            })
        ));
    }

    #[test]
    fn impact_plan_table_count_sql_accepts_only_verified_identifier_grammar() {
        assert!(is_plan_table_identifier("SYS"));
        assert!(is_plan_table_identifier("PLAN_TABLE$"));
        assert!(is_plan_table_identifier("OMCP_PLAN_01"));
        for invalid in [
            "",
            "sys",
            "SYS.PLAN_TABLE$",
            "PLAN\"TABLE",
            "PLAN TABLE",
            "X;DROP",
        ] {
            assert!(!is_plan_table_identifier(invalid), "{invalid}");
        }
    }

    #[test]
    fn impact_effect_probes_require_known_level_and_allow_gate() {
        for response in [
            json!({"gate_decision": "blocked"}),
            json!({"gate_decision": "require_step_up"}),
            json!({"gate_decision": "unknown"}),
            json!({}),
        ] {
            assert!(!preview_admits_effect_probes(
                response.as_object().expect("object"),
                Some(OperatingLevel::ReadWrite),
            ));
        }
        assert!(!preview_admits_effect_probes(
            json!({"gate_decision": "allow"})
                .as_object()
                .expect("object"),
            None,
        ));
        assert!(preview_admits_effect_probes(
            json!({"gate_decision": "allow"})
                .as_object()
                .expect("object"),
            Some(OperatingLevel::ReadWrite),
        ));
    }

    #[test]
    fn impact_blocked_preview_does_not_probe_oracle() {
        let conn = CountingConnection::default();
        let cache = OracleCatalogResolverCache::new();
        let backstop = super::super::ReadOnlyBackstop::new();
        let quarantine = Mutex::new(None);
        let mut response = json!({
            "execute_confirmation": null,
            "gate_decision": "require_step_up",
        });
        let conn_ref = &conn;
        let cache_ref = &cache;
        let backstop_ref = &backstop;
        let quarantine_ref = &quarantine;
        let response_ref = &mut response;
        run_with_cx(|cx| async move {
            enrich_preview_impact(
                response_ref,
                &cx,
                conn_ref,
                backstop_ref,
                quarantine_ref,
                cache_ref,
                "UPDATE ACCOUNTS SET ACTIVE = 0 WHERE ID = 1",
                Some(OperatingLevel::ReadWrite),
                true,
                false,
                false,
                false,
                OperatingLevel::ReadWrite,
                None,
                Some(100),
                false,
            )
            .await
            .expect("blocked preview impact is advisory");
        });
        assert!(
            conn.calls.lock().expect("calls").is_empty(),
            "a step-up preview must not run EXPLAIN or any catalog probe"
        );
        assert_eq!(
            response
                .pointer("/impact/cost/reason")
                .and_then(Value::as_str),
            Some("level_below_required")
        );
        assert_eq!(
            response
                .pointer("/impact/locks/reason")
                .and_then(Value::as_str),
            Some("level_below_required")
        );
    }

    #[test]
    fn impact_read_only_preview_reports_transaction_backstop_without_clearing_it() {
        let conn = CountingConnection::default();
        let cache = OracleCatalogResolverCache::new();
        let mut backstop = super::super::ReadOnlyBackstop::new();
        let quarantine = Mutex::new(None);
        let conn_ref = &conn;
        let backstop_ref = &mut backstop;
        run_with_cx(|cx| async move {
            backstop_ref
                .ensure_armed(
                    &cx,
                    conn_ref,
                    &oraclemcp_guard::SessionLevelState::new(OperatingLevel::ReadOnly, false),
                )
                .await
                .expect("read-only backstop arms");
        });
        conn.calls.lock().expect("calls").clear();
        let mut response = json!({
            "execute_confirmation": null,
            "gate_decision": "require_step_up",
        });
        let conn_ref = &conn;
        let cache_ref = &cache;
        let backstop_ref = &mut backstop;
        let quarantine_ref = &quarantine;
        let response_ref = &mut response;
        run_with_cx(|cx| async move {
            enrich_preview_impact(
                response_ref,
                &cx,
                conn_ref,
                backstop_ref,
                quarantine_ref,
                cache_ref,
                "UPDATE ACCOUNTS SET ACTIVE = 0 WHERE ID = 1",
                Some(OperatingLevel::ReadWrite),
                true,
                false,
                false,
                false,
                OperatingLevel::ReadOnly,
                None,
                Some(100),
                false,
            )
            .await
            .expect("READ_ONLY impact is advisory");
        });
        assert!(conn.calls.lock().expect("calls").is_empty());
        assert!(backstop.is_armed());
        assert_eq!(
            response
                .pointer("/impact/cost/reason")
                .and_then(Value::as_str),
            Some("read_only_txn")
        );
        assert_eq!(
            response
                .pointer("/impact/locks/reason")
                .and_then(Value::as_str),
            Some("level_below_required")
        );
    }

    #[test]
    fn impact_cost_read_only_unavailable_backstop_untouched() {
        let conn = CountingConnection::default();
        let mut backstop = super::super::ReadOnlyBackstop::new();
        let quarantine = Mutex::new(None);
        let conn_ref = &conn;
        let backstop_ref = &mut backstop;
        run_with_cx(|cx| async move {
            backstop_ref
                .ensure_armed(
                    &cx,
                    conn_ref,
                    &oraclemcp_guard::SessionLevelState::new(OperatingLevel::ReadOnly, false),
                )
                .await
                .expect("read-only backstop arms");
        });
        conn.calls.lock().expect("calls").clear();
        let conn_ref = &conn;
        let backstop_ref = &backstop;
        let quarantine_ref = &quarantine;
        let status = run_with_cx(|cx| async move {
            compute_cost_impact(
                &cx,
                conn_ref,
                backstop_ref,
                quarantine_ref,
                "UPDATE accounts SET active = 0 WHERE id = 1",
                &[],
                OperatingLevel::ReadOnly,
                None,
                Some(100),
                false,
            )
            .await
            .expect("advisory cost returns a field status")
        });
        assert_eq!(
            status,
            FieldStatus::Unavailable {
                reason: UnavailableReason::ReadOnlyTxn
            }
        );
        assert!(
            conn.calls.lock().expect("calls").is_empty(),
            "READ_ONLY impact cost must not read or clear the DB backstop"
        );
        assert!(
            backstop.is_armed(),
            "READ_ONLY impact cost preserves the backstop"
        );
    }
    #[test]
    fn impact_cost_armed_read_write_preview_does_not_touch_connection() {
        let conn = CountingConnection::default();
        let mut backstop = super::super::ReadOnlyBackstop::new();
        let quarantine = Mutex::new(None);
        let conn_ref = &conn;
        let backstop_ref = &mut backstop;
        run_with_cx(|cx| async move {
            backstop_ref
                .ensure_armed(
                    &cx,
                    conn_ref,
                    &oraclemcp_guard::SessionLevelState::new(OperatingLevel::ReadOnly, false),
                )
                .await
                .expect("read-only backstop arms");
        });
        conn.calls.lock().expect("calls").clear();
        let conn_ref = &conn;
        let backstop_ref = &backstop;
        let quarantine_ref = &quarantine;
        let status = run_with_cx(|cx| async move {
            compute_cost_impact(
                &cx,
                conn_ref,
                backstop_ref,
                quarantine_ref,
                "UPDATE accounts SET active=0 WHERE id=1",
                &[],
                OperatingLevel::ReadWrite,
                None,
                Some(100),
                false,
            )
            .await
            .expect("advisory cost")
        });
        assert_eq!(
            status,
            FieldStatus::Unavailable {
                reason: UnavailableReason::ReadOnlyTxn
            }
        );
        assert!(
            conn.calls.lock().expect("calls").is_empty(),
            "an elevated cost preview must not touch an armed connection"
        );
        assert!(
            backstop.is_armed(),
            "elevation does not disarm the preview backstop"
        );
    }

    #[cfg(feature = "live-xe")]
    mod live_tests {
        use super::*;
        use asupersync::runtime::RuntimeBuilder;
        use oraclemcp_db::{OracleConnectOptions, RustOracleConnection};
        use std::time::Duration;

        fn run_with_cx<F, Fut, T>(body: F) -> T
        where
            F: FnOnce(Cx) -> Fut,
            Fut: std::future::Future<Output = T>,
        {
            let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(reactor)
                .build()
                .expect("live-impact runtime");
            runtime.block_on(async move {
                body(Cx::current().expect("live-impact runtime installs Cx")).await
            })
        }

        fn options(lane: &str) -> OracleConnectOptions {
            let key = lane.to_ascii_uppercase();
            let lane_name = lane.to_ascii_lowercase();
            let env = |suffix: &str| std::env::var(format!("ORACLE_MATRIX_{key}_{suffix}"));
            OracleConnectOptions {
                connect_string: env("DSN").unwrap_or_else(|_| match lane_name.as_str() {
                    "xe18" => "localhost:1518/XEPDB1".to_owned(),
                    "xe21" => "localhost:1520/XEPDB1".to_owned(),
                    _ => "localhost:1522/FREEPDB1".to_owned(),
                }),
                username: Some(env("USER").expect("lane-specific least-privilege user configured")),
                password: Some(env("PASSWORD").expect("lane-specific password configured")),
                call_timeout: Some(Duration::from_secs(30)),
                ..Default::default()
            }
        }

        fn test_name(lane: &str) -> String {
            format!("impact_cost_live_{lane}")
        }

        #[cfg(feature = "plsql-intelligence")]
        async fn live_dependency_preview(
            cx: &Cx,
            connect: OracleConnectOptions,
            source: &str,
        ) -> Result<Value, String> {
            use super::super::super::{DispatchContext, OracleDispatcher};
            let conn = RustOracleConnection::connect(cx, connect)
                .await
                .map_err(|error| format!("dependency preview connection: {error}"))?;
            let mut level = oraclemcp_guard::SessionLevelState::new(OperatingLevel::Ddl, false);
            level
                .set_current_level(OperatingLevel::Ddl)
                .map_err(|error| error.to_string())?;
            let dispatcher = OracleDispatcher::new_with_profile_level(
                Box::new(conn),
                Some("live-dependents".into()),
                level,
            );
            let refusal_recorded = std::cell::Cell::new(false);
            let result = dispatcher
                .dispatch_with_cx_inner(
                    cx,
                    DispatchContext::default(),
                    "oracle_create_or_replace",
                    json!({"source_code":source}),
                    &refusal_recorded,
                )
                .await
                .map_err(|error| format!("dependency preview: {}", error.message));
            let state = dispatcher
                .state
                .lock(cx)
                .await
                .map_err(|_| "dependency state lock".to_owned())?;
            state
                .conn
                .close(cx)
                .await
                .map_err(|error| format!("preview connection close: {error}"))?;
            result
        }

        /// A native Oracle observation, not a mocked invalidation oracle. The
        /// three expected dependents are declared before the spec is changed.
        #[cfg(feature = "plsql-intelligence")]
        #[test]
        fn impact_dependents_live_three_dependents_predicted_equals_observed() {
            if std::env::var("ORACLEMCP_LIVE_XE").as_deref() != Ok("1") {
                eprintln!("live FREE23 dependents disabled; set ORACLEMCP_LIVE_XE=1");
                return;
            }
            run_with_cx(|cx| async move {
                let connect = options("FREE23");
                let conn = RustOracleConnection::connect(&cx, connect.clone()).await
                    .map_err(|error| format!("fixture connection: {error}"))?;
                let rows = conn.query_rows(&cx, "SELECT USER AS OWNER FROM DUAL", &[]).await
                    .map_err(|error| error.to_string())?;
                let owner = rows.first().and_then(|row| row.text("OWNER"))
                    .filter(|owner| is_plan_table_identifier(owner)).ok_or("fixture owner missing")?.to_owned();
                let id = PlanStatementId::generate().map_err(|error| error.to_string())?;
                let suffix = &id.as_str()[5..13];
                let package = format!("OMCPI_{suffix}_PKG");
                let p1 = format!("OMCPI_{suffix}_P1");
                let p2 = format!("OMCPI_{suffix}_P2");
                let qualified = |name: &str| format!("\"{owner}\".\"{name}\"");
                let spec = format!("CREATE OR REPLACE PACKAGE {} AS PROCEDURE p(x NUMBER); END;",qualified(&package));
                let replacement = format!("CREATE OR REPLACE PACKAGE {} AS PROCEDURE p(x VARCHAR2); END;",qualified(&package));
                conn.execute(&cx,&spec,&[]).await.map_err(|error| error.to_string())?;
                let outcome = async {
                    let fixtures = [
                        format!("CREATE OR REPLACE PACKAGE BODY {} AS PROCEDURE p(x NUMBER) IS BEGIN NULL; END; END;",qualified(&package)),
                        format!("CREATE OR REPLACE PROCEDURE {} AS BEGIN {}.p(1); END;",qualified(&p1),qualified(&package)),
                        // Both direct and transitive edges are present by
                        // design. Unit tests separately prove a pure chain.
                        format!("CREATE OR REPLACE PROCEDURE {} AS BEGIN {}; {}.p(2); END;",qualified(&p2),qualified(&p1),qualified(&package)),
                    ];
                    for sql in fixtures { conn.execute(&cx,&sql,&[]).await.map_err(|error| error.to_string())?; }
                    let status_sql = "SELECT OBJECT_NAME, OBJECT_TYPE, STATUS FROM SYS.ALL_OBJECTS WHERE OWNER=:1 AND OBJECT_NAME IN (:2,:3,:4) AND SUBOBJECT_NAME IS NULL";
                    let binds = [OracleBind::String(owner.clone()),OracleBind::String(package.clone()),
                        OracleBind::String(p1.clone()),OracleBind::String(p2.clone())];
                    let initial = conn.query_rows(&cx,status_sql,&binds).await.map_err(|error| error.to_string())?;
                    if initial.len()!=4 || initial.iter().any(|row| row.text("STATUS")!=Some("VALID")) {
                        return Err(format!("fixture was not four VALID objects: {initial:?}"));
                    }
                    let expected = std::collections::BTreeSet::from([
                        (owner.clone(),package.clone(),"PACKAGE BODY".to_owned()),
                        (owner.clone(),p1.clone(),"PROCEDURE".to_owned()),
                        (owner.clone(),p2.clone(),"PROCEDURE".to_owned()),
                    ]);
                    let preview = live_dependency_preview(&cx,connect,&replacement).await?;
                    let value = &preview["impact"]["dependents"]["value"];
                    if preview["impact"]["dependents"]["status"]!="estimated" {
                        return Err(format!("privileged closure unavailable: {}",preview["impact"]["dependents"]));
                    }
                    if value["truncated"]!=false || value["prediction_mode"]!="LiveSnapshot"
                        || !preview["confirmation"]["confirm"].is_string() {
                        return Err(format!("incomplete native dependency preview: {value}"));
                    }
                    let gaps=value["uncertainties"].as_array().ok_or("uncertainties absent")?;
                    // FREE23 can expose SYS_STUB_FOR_PURITY_ANALYSIS edges
                    // without a local object ID, even to SYSTEM. Keep that
                    // observation unknown; it must never turn into a total.
                    if gaps.is_empty() {
                        if value["predicted_invalid_count"]!=3 { return Err("complete native prediction omitted its exact total".into()); }
                    } else if !value["predicted_invalid_count"].is_null() {
                        return Err("unresolved native dependency became a numeric total".into());
                    }
                    let predicted = value["predicted_invalid_set"].as_array().ok_or("predicted set absent")?
                        .iter().map(|item| Ok((item["owner"].as_str().ok_or("predicted owner")?.to_owned(),
                            item["name"].as_str().ok_or("predicted name")?.to_owned(),
                            item["object_type"].as_str().ok_or("predicted type")?.to_owned())))
                        .collect::<Result<std::collections::BTreeSet<_>,String>>()?;
                    if predicted!=expected { return Err(format!("prediction differs from predeclared set: {predicted:?}")); }
                    // Applying through the fixture connection tests Oracle's
                    // invalidation, not token drift/revalidation (.16.7).
                    conn.execute(&cx,&replacement,&[]).await.map_err(|error| error.to_string())?;
                    let after = conn.query_rows(&cx,status_sql,&binds).await.map_err(|error| error.to_string())?;
                    let observed = after.iter().filter(|row| row.text("STATUS")==Some("INVALID"))
                        .map(|row| Ok((owner.clone(),row.text("OBJECT_NAME").ok_or("observed name")?.to_owned(),
                            row.text("OBJECT_TYPE").ok_or("observed type")?.to_owned())))
                        .collect::<Result<std::collections::BTreeSet<_>,String>>()?;
                    if predicted!=observed { return Err(format!("predicted {predicted:?}, Oracle INVALID {observed:?}")); }
                    println!("FREE23 native prediction equals observed INVALID set: 3 dependents; bounded closure; LiveSnapshot; {} explicit uncertainties",gaps.len());
                    Ok::<(),String>(())
                }.await;
                let cleanup = async {
                    for (kind,name) in [("PROCEDURE",&p2),("PROCEDURE",&p1),("PACKAGE",&package)] {
                        let result = conn.execute(&cx,&format!("DROP {kind} {}",qualified(name)),&[]).await;
                        if let Err(error)=result && !error.to_string().contains("ORA-04043") { return Err(format!("fixture cleanup: {error}")); }
                    }
                    conn.close(&cx).await.map_err(|error| error.to_string())
                }.await;
                cleanup?;
                outcome
            }).unwrap();
        }

        #[cfg(feature = "plsql-intelligence")]
        #[test]
        fn impact_dependents_live_no_privilege_preserves_confirmation() {
            if std::env::var("ORACLEMCP_LIVE_XE").as_deref() != Ok("1") {
                eprintln!("live FREE23 privilege boundary disabled; set ORACLEMCP_LIVE_XE=1");
                return;
            }
            run_with_cx(|cx| async move {
                let admin_options=options("FREE23");
                let admin=RustOracleConnection::connect(&cx,admin_options.clone()).await.map_err(|error|error.to_string())?;
                let id=PlanStatementId::generate().map_err(|error|error.to_string())?;
                let suffix=&id.as_str()[5..13];
                let user=format!("OMCPI_{suffix}");
                let password=format!("D{suffix}a9Zq");
                admin.execute(&cx,&format!("CREATE USER {user} IDENTIFIED BY \"{password}\""),&[]).await.map_err(|error|error.to_string())?;
                let outcome=async {
                    // These are fixture-only grants. The product performs no
                    // privilege provisioning for its observation query.
                    admin.execute(&cx,&format!("GRANT CREATE SESSION, CREATE PROCEDURE TO {user}"),&[]).await.map_err(|error|error.to_string())?;
                    let connect=OracleConnectOptions{username:Some(user.clone()),password:Some(password),..admin_options};
                    let conn=RustOracleConnection::connect(&cx,connect.clone()).await.map_err(|error|error.to_string())?;
                    let source=format!("CREATE OR REPLACE PACKAGE {user}.PKG AS PROCEDURE p; END;");
                    conn.execute(&cx,&source,&[]).await.map_err(|error|error.to_string())?;
                    conn.close(&cx).await.map_err(|error|error.to_string())?;
                    let preview=live_dependency_preview(&cx,connect,&source).await?;
                    if preview["impact"]["dependents"]["status"]!="unavailable"
                        || preview["impact"]["dependents"]["reason"]!="no_privilege"
                        || preview["gate_decision"]!="allow" || !preview["confirmation"]["confirm"].is_string() {
                        return Err(format!("R36 visibility observation suppressed working preview: {preview}"));
                    }
                    println!("FREE23 native low-privilege preview: unavailable(no_privilege), confirmation preserved");
                    Ok::<(),String>(())
                }.await;
                admin.execute(&cx,&format!("DROP USER {user} CASCADE"),&[]).await.map_err(|error|format!("fixture user cleanup: {error}"))?;
                admin.close(&cx).await.map_err(|error|error.to_string())?;
                outcome
            }).unwrap();
        }

        async fn assert_live_cost(lane: &str) -> Result<(), String> {
            let name = test_name(lane);
            let cx = Cx::current().ok_or_else(|| "live test Cx missing".to_owned())?;
            let conn = RustOracleConnection::connect(&cx, options(lane))
                .await
                .map_err(|error| format!("{name}: live connection failed: {error}"))?;
            let owner_rows = conn
                .query_rows(&cx, "SELECT USER AS CURRENT_USER FROM DUAL", &[])
                .await
                .map_err(|error| format!("{name}: current-user query failed: {error}"))?;
            let owner = owner_rows
                .first()
                .and_then(|row| row.text("CURRENT_USER"))
                .ok_or_else(|| format!("{name}: current schema was not returned"))?;
            if !is_plan_table_identifier(owner) {
                return Err(format!(
                    "{name}: current schema has invalid identifier grammar"
                ));
            }
            let statement_id = PlanStatementId::generate()
                .map_err(|error| format!("{name}: OS randomness failed: {error}"))?;
            let suffix = &statement_id.as_str()[5..13];
            let table = format!("OMCP_IMPACT_{suffix}");
            let qualified = format!("\"{owner}\".\"{table}\"");
            conn.execute(
                &cx,
                &format!("CREATE TABLE {qualified} (ID NUMBER PRIMARY KEY)"),
                &[],
            )
            .await
            .map_err(|error| format!("{name}: fixture create failed: {error}"))?;
            let outcome = async {
                conn.execute(
                    &cx,
                    &format!("INSERT INTO {qualified} (ID) VALUES (1)"),
                    &[],
                )
                .await
                .map_err(|error| format!("{name}: fixture insert failed: {error}"))?;
                conn.commit(&cx)
                    .await
                    .map_err(|error| format!("{name}: fixture commit failed: {error}"))?;

                let cache = OracleCatalogResolverCache::new();
                let mut backstop = super::super::super::ReadOnlyBackstop::new();
                let quarantine = std::sync::Mutex::new(None);
                let mut response = json!({
                    "execute_confirmation": {},
                    "gate_decision": "allow",
                    "required_level": "read_write",
                });
                enrich_preview_impact(
                    &mut response,
                    &cx,
                    &conn,
                    &backstop,
                    &quarantine,
                    &cache,
                    &format!("UPDATE {qualified} SET ID = ID WHERE ID = 1"),
                    Some(OperatingLevel::ReadWrite),
                    true,
                    false,
                    false,
                    false,
                    OperatingLevel::ReadWrite,
                    None,
                    Some(u64::MAX),
                    false,
                )
                .await
                .map_err(|error| format!("{name}: impact preview failed: {error}"))?;
                let cost = response
                    .pointer("/impact/cost")
                    .ok_or_else(|| format!("{name}: preview omitted impact.cost"))?;
                if cost.get("status").and_then(Value::as_str) != Some("estimated") {
                    return Err(format!("{name}: impact.cost was not estimated: {cost}"));
                }
                let value = cost
                    .get("value")
                    .ok_or_else(|| format!("{name}: estimated cost omitted its value"))?;
                if !value.get("total_cost").is_some_and(Value::is_number)
                    || !value.get("cardinality").is_some_and(Value::is_number)
                    || !value.get("max_query_cost").is_some_and(Value::is_number)
                    || value.get("within_max_query_cost").and_then(Value::as_bool) != Some(true)
                    || value
                        .get("statement_id")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                {
                    return Err(format!(
                        "{name}: cost/cardinality/budget/id incomplete: {value}"
                    ));
                }
                let rows = conn
                    .query_rows(
                        &cx,
                        &format!("SELECT COUNT(*) AS ROW_COUNT FROM {qualified} WHERE ID = 1"),
                        &[],
                    )
                    .await
                    .map_err(|error| format!("{name}: fixture reread failed: {error}"))?;
                let count = rows.first().and_then(|row| row.parse_i64("ROW_COUNT"));
                if count != Some(1) {
                    return Err(format!("{name}: preview changed the DML target: {count:?}"));
                }
                let mut limited = json!({"execute_confirmation": {}, "gate_decision": "allow"});
                enrich_preview_impact(&mut limited, &cx, &conn, &backstop,
                    &quarantine, &cache, &format!("UPDATE {qualified} SET ID=ID WHERE ID=1"),
                    Some(OperatingLevel::ReadWrite), true, false, false, false,
                    OperatingLevel::ReadWrite, None, Some(0), false)
                    .await.map_err(|error| format!("{name}: zero-budget preview: {error}"))?;
                let limited_value = &limited["impact"]["cost"]["value"];
                let cost = limited_value["total_cost"].as_u64()
                    .ok_or_else(|| format!("{name}: zero-budget cost missing"))?;
                if limited_value["max_query_cost"] != json!(0)
                    || limited_value["within_max_query_cost"] != json!(cost == 0) {
                    return Err(format!("{name}: cost was not compared with zero budget: {limited_value}"));
                }
                // Elevation does not authorize a preview to end an existing
                // Oracle READ ONLY transaction merely to obtain an estimate.
                backstop.ensure_armed(&cx, &conn,
                    &oraclemcp_guard::SessionLevelState::new(OperatingLevel::ReadOnly, false))
                    .await.map_err(|error| format!("{name}: arm backstop: {}", error.message))?;
                let mut armed = json!({"execute_confirmation": {}, "gate_decision": "allow"});
                enrich_preview_impact(&mut armed, &cx, &conn, &backstop,
                    &quarantine, &cache, &format!("UPDATE {qualified} SET ID = ID WHERE ID = 1"),
                    Some(OperatingLevel::ReadWrite), true, false, false, false,
                    OperatingLevel::ReadWrite, None, Some(u64::MAX), false)
                    .await.map_err(|error| format!("{name}: armed preview: {error}"))?;
                // Check Oracle itself before the client flag: a rollback that
                // accidentally leaves the flag set must also fail this test.
                let refused = conn.execute(&cx,
                    &format!("UPDATE {qualified} SET ID=ID WHERE ID=1"), &[]).await
                    .err().ok_or_else(|| format!("{name}: Oracle accepted UPDATE after armed elevated preview"))?;
                if !super::super::super::is_read_only_transaction_error(&refused) {
                    return Err(format!("{name}: armed UPDATE failed without ORA-01456: {refused}"));
                }
                if armed.pointer("/impact/cost/reason").and_then(Value::as_str) != Some("read_only_txn")
                    || !backstop.is_armed() {
                    return Err(format!("{name}: elevated preview disarmed backstop or wrote PLAN_TABLE: {} armed={}",
                        armed["impact"]["cost"], backstop.is_armed()));
                }
                Ok::<(), String>(())
            }
            .await;
            conn.rollback(&cx)
                .await
                .map_err(|error| format!("{name}: fixture rollback: {error}"))?;
            let cleanup = conn
                .execute(&cx, &format!("DROP TABLE {qualified} PURGE"), &[])
                .await
                .map_err(|error| format!("{name}: fixture cleanup failed: {error}"));
            cleanup?;
            outcome
        }

        async fn assert_live_ddl_lock_no_privilege(lane: &str) -> Result<(), String> {
            let name = format!("impact_locks_live_ddl_no_privilege_unavailable_{lane}");
            let cx = Cx::current().ok_or_else(|| "live test Cx missing".to_owned())?;
            let conn = RustOracleConnection::connect(&cx, options(lane))
                .await
                .map_err(|error| format!("{name}: live connection failed: {error}"))?;
            let cache = OracleCatalogResolverCache::new();
            let dual = RawName::new([RawNamePart::unquoted("DUAL")], SyntacticRole::FromFactor);
            let context = cache
                .preload(
                    &cx,
                    &conn,
                    std::slice::from_ref(&dual),
                    StatementScope::default(),
                )
                .await
                .map_err(|error| {
                    format!("{name}: could not resolve the live lock target: {error}")
                })?;
            let Resolution::Resolved(target) = cache.resolve(&dual, &context) else {
                return Err(format!("{name}: DUAL did not resolve to a live object"));
            };
            let locks = compute_locks_impact(
                &cx,
                &conn,
                Some(OperatingLevel::Ddl),
                false,
                std::slice::from_ref(target.as_ref()),
            )
            .await;
            match locks {
                FieldStatus::Unavailable {
                    reason: UnavailableReason::NoPrivilege,
                } => Ok(()),
                other => Err(format!(
                    "{name}: expected unavailable(no_privilege) for the live account, got {other:?}"
                )),
            }
        }

        async fn live_preview_cost(
            cx: &Cx,
            conn: &dyn OracleConnection,
            sql: &str,
        ) -> Result<Value, DbError> {
            let decision = super::super::super::DEFAULT_CLASSIFIER.classify(sql);
            let mut session =
                oraclemcp_guard::SessionLevelState::new(OperatingLevel::ReadWrite, false);
            session
                .set_current_level(OperatingLevel::ReadWrite)
                .unwrap();
            let (gate, _, _) = super::super::super::gate_decision_json(&decision.gate(&session));
            assert_eq!(
                gate,
                json!("allow"),
                "fixture SQL must be admitted before impact probes"
            );
            let mut response = json!({"execute_confirmation": {}, "gate_decision": gate});
            enrich_preview_impact(
                &mut response,
                cx,
                conn,
                &super::super::super::ReadOnlyBackstop::new(),
                &std::sync::Mutex::new(None),
                &OracleCatalogResolverCache::new(),
                sql,
                decision.required_level,
                true,
                false,
                false,
                false,
                OperatingLevel::ReadWrite,
                None,
                Some(u64::MAX),
                false,
            )
            .await?;
            Ok(response["impact"]["cost"].clone())
        }

        async fn live_count(
            cx: &Cx,
            conn: &dyn OracleConnection,
            table: &str,
        ) -> Result<i64, DbError> {
            let rows = conn
                .query_rows(cx, &format!("SELECT COUNT(*) AS N FROM {table}"), &[])
                .await?;
            rows.first()
                .and_then(|row| row.parse_i64("N"))
                .ok_or_else(|| DbError::Internal("live canary count missing".to_owned()))
        }

        async fn assert_live_impact_safety(lane: &str) -> Result<(), DbError> {
            let schema = std::env::var(format!("ORACLE_MATRIX_{lane}_SCHEMA"))
                .expect("run-owned fixture schema required; outer fixture owns teardown");
            assert!(is_plan_table_identifier(&schema));
            let cx = Cx::current().unwrap();
            let conn = RustOracleConnection::connect(&cx, options(lane)).await?;
            conn.execute(
                &cx,
                &format!("ALTER SESSION SET CURRENT_SCHEMA={schema}"),
                &[],
            )
            .await?;
            let id = PlanStatementId::generate()?;
            let suffix = &id.as_str()[5..13];
            let a = format!("{schema}.T16A_{suffix}");
            let b = format!("{schema}.T16B_{suffix}");
            let canary = format!("{schema}.C16_{suffix}");
            for table in [&a, &b, &canary] {
                conn.execute(&cx, &format!("CREATE TABLE {table} (ID NUMBER)"), &[])
                    .await?;
            }
            conn.execute(&cx, &format!("INSERT INTO {a} VALUES (1)"), &[])
                .await?;
            conn.execute(&cx, &format!("INSERT INTO {b} VALUES (2)"), &[])
                .await?;
            conn.commit(&cx).await?;
            let sql_a = format!("UPDATE {a} SET ID=ID WHERE ID=1");
            let sql_b = format!("UPDATE {b} SET ID=ID WHERE ID=2");

            // Copy the real plan-column types, including LONG, rather than an
            // ID-only fake that would reject EXPLAIN before its trigger fires.
            let columns = conn.query_rows(&cx, "SELECT COLUMN_NAME, DATA_TYPE, DATA_LENGTH FROM SYS.ALL_TAB_COLUMNS WHERE OWNER='SYS' AND TABLE_NAME='PLAN_TABLE$' ORDER BY COLUMN_ID", &[]).await?;
            assert!(!columns.is_empty());
            let definitions: Vec<String> = columns
                .iter()
                .map(|row| {
                    let name = row.text("COLUMN_NAME").unwrap();
                    assert!(is_plan_table_identifier(name));
                    let kind = match row.text("DATA_TYPE").unwrap() {
                        "VARCHAR2" => {
                            format!("VARCHAR2({} BYTE)", row.parse_i64("DATA_LENGTH").unwrap())
                        }
                        "NUMBER" | "DATE" | "LONG" | "CLOB" => {
                            row.text("DATA_TYPE").unwrap().to_owned()
                        }
                        other => panic!("unsupported real PLAN_TABLE fixture column type {other}"),
                    };
                    format!("\"{name}\" {kind}")
                })
                .collect();
            conn.execute(
                &cx,
                &format!(
                    "CREATE TABLE {schema}.PLAN_TABLE ({})",
                    definitions.join(",")
                ),
                &[],
            )
            .await?;
            conn.execute(&cx, &format!("CREATE OR REPLACE TRIGGER {schema}.TR16_{suffix} BEFORE INSERT ON {schema}.PLAN_TABLE FOR EACH ROW DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN INSERT INTO {canary} VALUES (1); COMMIT; END;"), &[]).await?;
            conn.execute(
                &cx,
                &format!("INSERT INTO {schema}.PLAN_TABLE (STATEMENT_ID) VALUES ('CONTROL')"),
                &[],
            )
            .await?;
            conn.rollback(&cx).await?;
            assert_eq!(
                live_count(&cx, &conn, &canary).await?,
                1,
                "autonomous trigger positive control"
            );
            conn.execute(&cx, &format!("DELETE FROM {canary}"), &[])
                .await?;
            conn.commit(&cx).await?;
            assert_eq!(
                live_preview_cost(&cx, &conn, &sql_a).await?,
                json!({"status":"unavailable","reason":"plan_table_unverified"})
            );
            assert_eq!(
                live_count(&cx, &conn, &canary).await?,
                0,
                "preview fired local PLAN_TABLE trigger"
            );
            conn.execute(&cx, &format!("DROP TABLE {schema}.PLAN_TABLE PURGE"), &[])
                .await?;
            eprintln!(
                "{lane}: impact_cost_live_local_plan_table_autonomous_trigger_never_fires PASS"
            );

            conn.execute(
                &cx,
                &format!("CREATE SYNONYM {schema}.PLAN_TABLE FOR {a}"),
                &[],
            )
            .await?;
            assert_eq!(
                live_preview_cost(&cx, &conn, &sql_a).await?,
                json!({"status":"unavailable","reason":"plan_table_unverified"})
            );
            conn.execute(&cx, &format!("DROP SYNONYM {schema}.PLAN_TABLE"), &[])
                .await?;
            eprintln!("{lane}: impact_cost_live_private_synonym_plan_table_refused PASS");

            let table = resolve_plan_table(&cx, &conn, None)
                .await
                .expect("verified standard plan table");
            let cache = OracleCatalogResolverCache::new();
            for sql in [&sql_a, &sql_b] {
                let relations = resolve_dml_relations(&cx, &conn, &cache, sql)
                    .await
                    .unwrap();
                assert!(
                    prove_hard_parse_effect_closure(&cx, &conn, sql, &relations)
                        .await
                        .is_proven()
                );
            }
            let id_a = PlanStatementId::generate()?;
            let id_b = PlanStatementId::generate()?;
            conn.execute(&cx, "SAVEPOINT I166_INTERLEAVED", &[]).await?;
            explain_plan(&cx, &conn, &sql_a, &table, &id_a, false).await?;
            explain_plan(&cx, &conn, &sql_b, &table, &id_b, false).await?;
            // A is read again AFTER B was inserted on the same physical session.
            // A MAX(plan_id) implementation now returns the wrong object.
            for (id, own, other) in [
                (&id_a, format!("T16A_{suffix}"), format!("T16B_{suffix}")),
                (&id_b, format!("T16B_{suffix}"), format!("T16A_{suffix}")),
            ] {
                let plan = plan_cost_estimate(&cx, &conn, &table, id).await?.unwrap();
                assert!(
                    plan.rows
                        .iter()
                        .any(|row| row.object_name.as_deref() == Some(&own))
                );
                assert!(
                    !plan
                        .rows
                        .iter()
                        .any(|row| row.object_name.as_deref() == Some(&other))
                );
            }
            conn.execute(&cx, "ROLLBACK TO I166_INTERLEAVED", &[])
                .await?;
            for id in [&id_a, &id_b] {
                assert!(plan_cost_estimate(&cx, &conn, &table, id).await?.is_none());
            }
            eprintln!("{lane}: impact_cost_live_interleaved_statement_ids_isolated PASS");

            conn.execute(&cx, &format!("CREATE OR REPLACE FUNCTION {schema}.VP16_{suffix}(s VARCHAR2,o VARCHAR2) RETURN VARCHAR2 AS PRAGMA AUTONOMOUS_TRANSACTION; BEGIN INSERT INTO {canary} VALUES (1); COMMIT; RETURN '1=1'; END;"), &[]).await?;
            conn.execute(&cx, &format!("BEGIN DBMS_RLS.ADD_POLICY(object_schema=>'{schema}',object_name=>'T16A_{suffix}',policy_name=>'VP16_{suffix}',function_schema=>'{schema}',policy_function=>'VP16_{suffix}',statement_types=>'SELECT,UPDATE'); END;"), &[]).await?;
            conn.execute(&cx, &format!("DELETE FROM {canary}"), &[])
                .await?;
            conn.commit(&cx).await?;
            assert_eq!(
                live_preview_cost(&cx, &conn, &sql_a).await?,
                json!({"status":"unavailable","reason":"vpd"})
            );
            assert_eq!(
                live_count(&cx, &conn, &canary).await?,
                0,
                "preview invoked VPD policy code"
            );
            conn.execute(
                &cx,
                &format!(
                    "DECLARE p VARCHAR2(4000); BEGIN p := {schema}.VP16_{suffix}(NULL,NULL); END;"
                ),
                &[],
            )
            .await?;
            assert_eq!(
                live_count(&cx, &conn, &canary).await?,
                1,
                "VPD callback positive control did not fire"
            );
            conn.execute(
                &cx,
                &format!(
                    "BEGIN DBMS_RLS.DROP_POLICY('{schema}','T16A_{suffix}','VP16_{suffix}'); END;"
                ),
                &[],
            )
            .await?;
            eprintln!("{lane}: impact_cost_live_vpd_unavailable PASS");

            // Reuse the live W4 optimizer callback fixture, including its real
            // compilation check, rather than manufacturing catalog rows.
            let cases: Value = serde_json::from_str(include_str!(
                "../../../../scripts/e2e/w4/cases/explain-plan.json"
            ))
            .unwrap();
            let case = cases
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["case_id"] == "w4_explain_plan_odci_canary_not_invoked")
                .unwrap();
            for step in case["setup"].as_array().unwrap() {
                let sql = step["sql"].as_str().unwrap();
                if sql.starts_with("GRANT ") {
                    continue;
                }
                let sql = sql
                    .replace("${owner}", &schema)
                    .replace("${run_id}", suffix);
                conn.execute(&cx, &sql, &[]).await?;
            }
            let odci_canary = format!("{schema}.T_ODCI_CANARY_{suffix}");
            let odci_sql = format!("UPDATE {a} SET ID=ID WHERE {schema}.FN_ODCI_{suffix}(ID)=1");
            assert_eq!(
                live_preview_cost(&cx, &conn, &odci_sql).await?,
                json!({"status":"unavailable","reason":"hard_parse_callbacks"})
            );
            assert_eq!(
                live_count(&cx, &conn, &odci_canary).await?,
                0,
                "preview invoked ODCIStatsSelectivity"
            );
            conn.execute(&cx, &format!("DECLARE s NUMBER; r NUMBER; BEGIN r := {schema}.TY_ODCI_{suffix}.ODCIStatsSelectivity(NULL,s,NULL,NULL,NULL,1,NULL); END;"), &[]).await?;
            assert_eq!(
                live_count(&cx, &conn, &odci_canary).await?,
                1,
                "ODCI callback positive control did not fire"
            );
            eprintln!("{lane}: impact_cost_live_odci_canary_never_invoked PASS");
            conn.rollback(&cx).await?;
            conn.close(&cx).await?;
            Ok(())
        }

        macro_rules! live_safety_test {
            ($test:ident, $lane:literal) => {
                #[test]
                #[ignore = "requires a run-owned fixture schema and live matrix credentials"]
                fn $test() {
                    run_with_cx(|_| async { assert_live_impact_safety($lane).await }).unwrap();
                }
            };
        }
        live_safety_test!(impact_cost_live_safety_free23, "FREE23");
        live_safety_test!(impact_cost_live_safety_xe21, "XE21");
        live_safety_test!(impact_cost_live_safety_xe18, "XE18");

        macro_rules! live_lane_test {
        ($test:ident, $lane:literal) => {
            #[test]
            #[ignore = "requires an explicitly configured live Oracle lane"]
            fn $test() {
                assert!(
                    std::env::var("ORACLEMCP_LIVE_XE").is_ok_and(|value| value == "1"),
                    "set ORACLEMCP_LIVE_XE=1 and lane credentials before running ignored live tests"
                );
                let result = run_with_cx(|_| async { assert_live_cost($lane).await });
                result.unwrap_or_else(|error| panic!("{error}"));
            }
        };
    }

        live_lane_test!(impact_cost_live_free23, "FREE23");
        live_lane_test!(impact_cost_live_xe21, "XE21");
        live_lane_test!(impact_cost_live_xe18, "XE18");

        macro_rules! live_lock_lane_test {
            ($test:ident, $lane:literal) => {
                #[test]
                #[ignore = "requires an explicitly configured least-privilege live Oracle lane"]
                fn $test() {
                    assert!(
                        std::env::var("ORACLEMCP_LIVE_XE").is_ok_and(|value| value == "1"),
                        "set ORACLEMCP_LIVE_XE=1 and lane credentials before running ignored live tests"
                    );
                    let result = run_with_cx(|_| async {
                        assert_live_ddl_lock_no_privilege($lane).await
                    });
                    result.unwrap_or_else(|error| panic!("{error}"));
                }
            };
        }

        live_lock_lane_test!(
            impact_locks_live_ddl_no_privilege_unavailable_free23,
            "FREE23"
        );
        live_lock_lane_test!(impact_locks_live_ddl_no_privilege_unavailable_xe21, "XE21");
        live_lock_lane_test!(impact_locks_live_ddl_no_privilege_unavailable_xe18, "XE18");
    }
}
