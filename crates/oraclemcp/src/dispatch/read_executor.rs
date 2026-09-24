//! The single served caller-read entry for the current proof pipeline.
//!
//! Admission deliberately calls the existing semantic and catalog proof in
//! its existing order. Later guard work can strengthen that proof here without
//! giving a served tool a raw query capability.

use super::*;
use oraclemcp_db::{ReadPlanProofError, prove_semantic_read_plan};
use oraclemcp_guard::semantic_read_plan_checked;

mod read_only_backstop;
pub(super) use read_only_backstop::ReadOnlyBackstop;

/// Resolve each lexical read block under its own live catalog scope. The
/// classifier receives the exact per-object proof, so an inner view or VPD
/// table cannot borrow a clean outer table's verdict.
pub(super) async fn resolve_query_block_read(
    cx: &Cx,
    conn: &dyn OracleConnection,
    cache: &OracleCatalogResolverCache,
    sql: &str,
    verified_local_vector_embedding: bool,
) -> Result<(Vec<ResolvedObject>, GuardDecision), ErrorEnvelope> {
    let initial = if verified_local_vector_embedding {
        SEMANTIC_READ_PRECHECK_CLASSIFIER.classify_verified_local_vector_embedding(sql)
    } else {
        SEMANTIC_READ_PRECHECK_CLASSIFIER.classify(sql)
    };
    ensure_read_only_decision(initial).map_err(|error| attach_parameterization_hint(error, sql))?;
    let plan = semantic_read_plan_checked(sql)
        .map_err(|error| unresolved_semantic_read(error.as_str()))?;
    let proof = prove_semantic_read_plan(cx, conn, cache, &plan)
        .await
        .map_err(|error| match error {
            ReadPlanProofError::Database(error) => error.into_envelope(),
            ReadPlanProofError::MissingRelation(name) => missing_semantic_relation(&name),
            ReadPlanProofError::MissingColumn(name) => missing_semantic_column(&name),
            ReadPlanProofError::Unproven(reason) => unresolved_semantic_read(reason),
            ReadPlanProofError::FgaHandlerAutonomous => fga_refusal("fga_handler_autonomous"),
            ReadPlanProofError::FgaEvidenceUnknown => fga_refusal("fga_evidence_unknown"),
        })?;
    let relations = proof.relations.clone();
    let classifier =
        Classifier::new(ClassifierConfig::new().with_unresolved_qualified_calls_guarded())
            .with_oracle(Arc::new(proof))
            .with_statement_unknown_guarded();
    let decision = if verified_local_vector_embedding {
        classifier.classify_verified_local_vector_embedding(sql)
    } else {
        classifier.classify(sql)
    };
    ensure_read_only_decision(decision.clone())
        .map_err(|error| attach_parameterization_hint(error, sql))?;
    Ok((relations, decision))
}

fn fga_refusal(code: &'static str) -> ErrorEnvelope {
    // An autonomous handler is a property of the table; unknown evidence is
    // most often an account that cannot read ALL_AUDIT_POLICIES, which doctor
    // reports as fga_catalog_unreadable (.6.11). The refusal itself is the
    // same either way: the admission rule does not change.
    let next_step = match code {
        "fga_evidence_unknown" => format!(
            "FGA evidence could not be proven. If `oraclemcp doctor --online` reports \
             fga_catalog_unreadable, the account cannot read ALL_AUDIT_POLICIES: {}",
            oraclemcp_core::doctor::FGA_CATALOG_REMEDIATION
        ),
        _ => "remove the FGA handler or use a different ordinary table without user-code \
              audit conditions"
            .to_owned(),
    };
    ErrorEnvelope::new(
        ErrorClass::ForbiddenStatement,
        format!("read-only server refused FGA read dependency: {code}"),
    )
    .with_structured_reason(
        StructuredReason::new(ReasonCategory::UnprovenSideEffect).with_offending_construct(code),
    )
    .with_next_step(next_step)
}

/// `oracle_query` request, parsed and classified ONCE up front (A3/perf).
///
/// The dispatcher previously parsed `QueryArgs` twice and ran the
/// mark+classify pipeline on each of the read-only backstop path and the read
/// handler path — six classifier runs per call, all under the held
/// per-connection lock. This carries the single parse, the single marked
/// `executed_sql` (classified == executed), and the single read-only gate
/// result so both paths reuse them. Behavior is identical to the prior code.
pub(super) struct ReadExecutionPlan {
    pub(super) args: QueryArgs,
    /// The served tool that owns this query's audit record.
    pub(super) audit_tool: String,
    /// The audit-marked SQL actually executed (== the text that was classified).
    pub(super) executed_sql: String,
    /// The read-only gate verdict for `executed_sql`, computed once.
    pub(super) gate: Result<(), ErrorEnvelope>,
    /// The exact semantic classification that produced `gate`. It becomes
    /// audit evidence only after a signed record exists; it never comes from a
    /// client request and never authorizes execution.
    pub(super) verdict_certificate: Option<VerdictCertificate>,
    /// K9: the validated flashback target (if any). It is NOT part of the
    /// classifier input or the executed SQL text — the proven `executed_sql`
    /// runs unchanged inside a `DBMS_FLASHBACK` session window when this is set.
    pub(super) as_of: Option<AsOf>,
    /// Resolved relation evidence from the same semantic gate that admitted the
    /// read. Used only to attach VPD/RLS observation metadata to the result.
    pub(super) rls_vpd_relations: Vec<ResolvedObject>,
    /// Arc N: the proof of what the profile's policy took away, attached to the
    /// response so a client (and the operator console) can see that it applied.
    pub(super) policy: Option<Value>,
}

/// A read admitted by the current semantic and catalog proof.
///
/// No caller outside this module can construct the token or reach the
/// execution step without a successful verdict.
///
/// ```compile_fail
/// use oraclemcp::dispatch::AdmittedRead;
/// fn inspect(read: AdmittedRead) {
///     let AdmittedRead { plan: _ } = read;
/// }
/// ```
pub struct AdmittedRead {
    plan: ReadExecutionPlan,
}

impl AdmittedRead {
    fn new(plan: ReadExecutionPlan) -> Result<Self, ErrorEnvelope> {
        plan.gate.as_ref().map_err(Clone::clone)?;
        Ok(Self { plan })
    }

    pub(super) fn into_plan(self) -> ReadExecutionPlan {
        self.plan
    }
}

/// SQL assembled by the server over named application objects.
///
/// The SQL and object identities are evidence inputs, not a grant: this type
/// must pass the same semantic proof as caller SQL before it can execute.
pub struct ServerSql {
    sql: String,
    objects: Vec<ResolvedObject>,
}

impl ServerSql {
    /// Carry server-built text and the objects from which it was constructed.
    pub fn new(sql: String, objects: Vec<ResolvedObject>) -> Self {
        Self { sql, objects }
    }

    /// SQL text to submit to the normal read admission pipeline.
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// The object identities supplied by the builder, never trusted alone.
    pub fn objects(&self) -> &[ResolvedObject] {
        &self.objects
    }
}

/// E3/E3b: materialize the bounded full result of a read query as an
/// `oracle-export://{id}` resource and return a `resource_link` result (no
/// inlined rows). Fetches up to [`MAX_QUERY_EXPORT_ROWS`] at `offset`; rows
/// beyond that are dropped and the export is flagged truncated with a next hint.
#[allow(clippy::too_many_arguments)]
async fn export_query_to_resource(
    cx: &Cx,
    conn: &dyn OracleConnection,
    executed_sql: &str,
    a: &QueryArgs,
    binds: &[OracleBind],
    offset: usize,
    active_profile: Option<&str>,
    export_access: &QueryExportAccess,
    exports: Option<&oraclemcp_core::ExportRegistry>,
    as_of: Option<&AsOf>,
    result_masking: Option<&ResultMaskingPolicy>,
    auditor: Option<&Auditor>,
    audit_subject: &AuditSubject,
) -> Result<Value, ErrorEnvelope> {
    let format = oraclemcp_core::ExportFormat::parse(a.export_format.as_deref())
        .ok_or_else(|| invalid_args("export_format must be \"csv\" or \"json\""))?;
    let Some(exports) = exports else {
        return Err(ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "result export is not enabled in this server instance",
        )
        .with_next_step("retry without export=true to page the result inline"));
    };

    // Fetch up to the export ceiling in one window. The byte cap is raised to
    // the export ceiling so the row cap (not the inline byte cap) governs.
    let caps = QueryCaps {
        max_rows: MAX_QUERY_EXPORT_ROWS,
        max_result_bytes: oraclemcp_core::export::MAX_EXPORT_BYTES,
    };
    let serialize_opts = query_serialize_options_from_args_with_policy(a, result_masking);
    // K9: an export honors the flashback target too — the SAME proven SQL is
    // materialized as of the requested snapshot.
    let mut response = match as_of {
        Some(as_of) => {
            read_query_as_of(
                cx,
                conn,
                executed_sql,
                binds,
                caps,
                offset,
                &serialize_opts,
                as_of,
            )
            .await
        }
        None => read_query(cx, conn, executed_sql, binds, caps, offset, &serialize_opts).await,
    }
    .map_err(DbError::into_envelope)?;
    bind_result_masking_audit(
        cx,
        conn,
        auditor,
        audit_subject,
        "oracle_query",
        executed_sql,
        &mut response,
    )
    .await?;
    let response_value = serde_json::to_value(&response).unwrap_or(Value::Null);
    let more_rows = response.truncated;
    let next_cursor = response.next_cursor.as_deref().map(|offset| {
        let binding = query_cursor_binding(&a.sql, active_profile);
        oraclemcp_core::sign_token(QUERY_CURSOR_SCOPE, offset, &[&binding])
    });

    let (columns, rows) = query_value_to_export_rows(&response_value);
    let access = oraclemcp_core::ExportAccess::new(
        active_profile,
        &export_access.principal_key,
        export_access.scopes.as_deref(),
    );
    let handle = exports
        .create(
            &columns,
            &rows,
            format,
            access,
            oraclemcp_core::export::DEFAULT_EXPORT_TTL,
        )
        .map_err(|_| {
            ErrorEnvelope::new(
                ErrorClass::Internal,
                "query result could not be materialized within export limits",
            )
            .with_next_step("retry with export=false and page the result inline")
        })?;

    tracing::info!(
        export_uri = %handle.uri,
        format = ?handle.format,
        rows = handle.row_count,
        bytes = handle.byte_size,
        truncated = handle.truncated || more_rows,
        profile = active_profile.unwrap_or(""),
        "oracle_query materialized a large result as an export resource"
    );

    Ok(json!({
        "export": {
            "uri": handle.uri,
            "mime_type": handle.mime_type,
            "format": match handle.format {
                oraclemcp_core::ExportFormat::Csv => "csv",
                oraclemcp_core::ExportFormat::Json => "json",
            },
            "byte_size": handle.byte_size,
            "row_count": handle.row_count,
            "truncated": handle.truncated || more_rows,
        },
        "resource_link": {
            "type": "resource_link",
            "uri": handle.uri,
            "name": "oracle_query export",
            "mimeType": handle.mime_type,
            "description": "Materialized query result. Fetch with resources/read; bound to the originating principal and exact scope grant, and expires.",
        },
        "columns": columns,
        "row_count": handle.row_count,
        "inlined": false,
        "next_cursor": next_cursor,
        "next_step": if handle.truncated || more_rows {
            "The export was capped; re-run with the returned next_cursor to export the next window."
        } else {
            "Fetch the full result via resources/read on the export uri."
        },
    }))
}

pub(super) struct GuardedReadExecutor<'a> {
    dispatcher: &'a OracleDispatcher,
}

impl std::ops::Deref for GuardedReadExecutor<'_> {
    type Target = OracleDispatcher;

    fn deref(&self) -> &Self::Target {
        self.dispatcher
    }
}

impl<'a> GuardedReadExecutor<'a> {
    pub(super) fn new(dispatcher: &'a OracleDispatcher) -> Self {
        Self { dispatcher }
    }

    /// Admit server-generated application SQL through the same proof as a
    /// caller query, retaining the generated tool's audit identity.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run_server_read(
        &self,
        cx: &Cx,
        state: &mut DispatcherState,
        context: DispatchContext<'_>,
        audit_tool: &str,
        mut args: Value,
        server_sql: ServerSql,
        request_budget: RequestBudget,
        request_subject: &AuditSubject,
        sql_policy: Option<SqlPolicyConfig>,
        current_schema: Option<String>,
        scoped_level: &SessionLevelState,
    ) -> Result<Value, ErrorEnvelope> {
        let Value::Object(ref mut fields) = args else {
            return Err(invalid_args("server read arguments must be an object"));
        };
        fields.insert("sql".to_owned(), Value::String(server_sql.sql));
        self.run_caller_read(
            cx,
            state,
            context,
            "oracle_query",
            args,
            request_budget,
            request_subject,
            sql_policy,
            current_schema,
            scoped_level,
            audit_tool,
        )
        .await
    }

    /// Run a closed catalog query after checking its bind schema.
    #[expect(dead_code, reason = "T1.2b migrates the remaining dictionary tools")]
    pub(super) async fn run_catalog(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
        id: oraclemcp_db::CatalogQueryId,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        oraclemcp_db::run_catalog_query(cx, conn, id, binds).await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run_caller_read(
        &self,
        cx: &Cx,
        state: &mut DispatcherState,
        context: DispatchContext<'_>,
        name: &str,
        args: Value,
        mut request_budget: RequestBudget,
        request_subject: &AuditSubject,
        sql_policy: Option<SqlPolicyConfig>,
        current_schema: Option<String>,
        scoped_level: &SessionLevelState,
        tool: &str,
    ) -> Result<Value, ErrorEnvelope> {
        let (prepared, semantic_metadata) = {
            let audit_tool = tool.to_owned();
            let (parsed, semantic_metadata) = if tool == "oracle_semantic_search" {
                let result_masking = self.result_masking_policy()?;
                let (parsed, metadata) = semantic_search_as_query_args(
                    cx,
                    state.conn.as_ref(),
                    result_masking.as_ref(),
                    name,
                    args,
                )
                .await?;
                (parsed, Some(metadata))
            } else {
                (parse_args::<QueryArgs>(name, args)?, None)
            };
            let verified_local_vector_embedding = semantic_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.verified_local_vector_embedding);
            // K9: validate the STRUCTURED as_of one-of and build the
            // flashback target BEFORE any classification or I/O (both-set /
            // empty -> typed refusal). The base SELECT below is classified
            // UNCHANGED — as_of never enters the classifier input, it only
            // selects WHICH committed snapshot the proven read observes.
            let as_of = query_as_of_from_args(parsed.as_of.as_ref())?;
            let _ = parsed
                .binds
                .iter()
                .map(json_to_bind)
                .collect::<Result<Vec<_>, _>>()?;
            if parsed.streaming && parsed.export {
                return Err(invalid_args(
                    "streaming and export are mutually exclusive: choose incremental delivery OR a single export resource",
                ));
            }
            if parsed.streaming && as_of.is_some() {
                return Err(invalid_args(
                    "streaming and as_of are mutually exclusive: page the flashback read with its cursor",
                ));
            }
            if as_of.is_some() {
                // Arc I: DBMS_FLASHBACK cannot be enabled inside a
                // transaction, so the flashback read resets the pinned
                // session — erasing the reversible workspace's savepoints and
                // every statement held above them.
                ensure_workspace_closed(
                    &state.checkpoints,
                    "an as_of (flashback) read (it resets the session transaction)",
                )?;
            }
            // Arc N on the read path. A deny refuses the read here; a
            // predicate narrowing REWRITES it — that is what row-level policy
            // IS — and the rewritten candidate has already re-entered the
            // classifier (SEC-1). The candidate is then re-marked and put
            // through the SAME semantic read gate as any other statement, so a
            // rewrite can never widen what the read path admits.
            let base_decision = if verified_local_vector_embedding {
                SEMANTIC_READ_PRECHECK_CLASSIFIER
                    .classify_verified_local_vector_embedding(&parsed.sql)
            } else {
                SEMANTIC_READ_PRECHECK_CLASSIFIER.classify(&parsed.sql)
            };
            let policy = apply_sql_policy(
                sql_policy.as_ref(),
                current_schema.as_deref(),
                context.principal_key(),
                &SEMANTIC_READ_PRECHECK_CLASSIFIER,
                &base_decision,
                &parsed.sql,
            )?;
            let policy_sql = policy
                .effective_sql
                .clone()
                .unwrap_or_else(|| parsed.sql.clone());
            let executed_sql =
                with_audit_marker(&policy_sql, state.active_profile.as_deref(), &audit_tool);
            let classified = if verified_local_vector_embedding {
                resolve_read_only_relations_with_verified_local_vector_embedding(
                    cx,
                    state.conn.as_ref(),
                    &state.catalog_cache,
                    &executed_sql,
                )
                .await
            } else {
                resolve_read_only_relations(
                    cx,
                    state.conn.as_ref(),
                    &state.catalog_cache,
                    &executed_sql,
                )
                .await
            };
            let (gate, verdict_certificate, rls_vpd_relations) = match classified {
                Ok((relations, decision)) => (
                    Ok(()),
                    Some(decision.verdict_certificate().clone()),
                    relations,
                ),
                Err(error) => (Err(error), None, Vec::new()),
            };
            (
                ReadExecutionPlan {
                    args: parsed,
                    audit_tool,
                    executed_sql,
                    gate,
                    verdict_certificate,
                    as_of,
                    rls_vpd_relations,
                    policy: policy.attachment.clone(),
                },
                semantic_metadata,
            )
        };
        request_budget = query_budget_with_cost_limit(
            request_budget,
            self.max_query_cost()?,
            prepared.args.max_query_cost,
        );
        request_budget.enforce(cx).map_err(DbError::into_envelope)?;

        // A1: lazily ensure SET TRANSACTION READ ONLY is in force so a
        // MISCLASSIFIED write would still hit ORA-01456 from the engine.
        // `ensure_armed` is a no-op when the effective level is above
        // READ_ONLY (a write may be authorized) or when already armed (no
        // per-read round trip), and it fails closed if the statement cannot
        // apply.
        //
        // Guard-before-I/O: consult the single read-only gate computed above
        // and only arm when it passes. A refused statement therefore never
        // issues the backstop round trip (or any DB I/O); the read below
        // reuses the same verdict to surface the identical structured
        // refusal. The arm uses a disjoint &mut split of the guard's fields.
        if prepared.gate.is_ok() {
            let cost_limit =
                effective_query_cost_limit(self.max_query_cost()?, prepared.args.max_query_cost);
            let cumulative_policy = self.cumulative_query_cost_budget()?;
            let budget_profile = state
                .active_profile
                .clone()
                .unwrap_or_else(|| "standalone".to_owned());
            let budget_principal = context
                .principal_key()
                .unwrap_or(oraclemcp_core::STDIO_EXPORT_PRINCIPAL)
                .to_owned();
            let DispatcherState {
                conn,
                read_only_backstop,
                checkpoints,
                ..
            } = &mut *state;
            enforce_query_cost_gate(
                QueryCostGateCtx {
                    cx,
                    conn: conn.as_ref(),
                    read_only_backstop,
                    checkpoints,
                    session: scoped_level,
                    request_budget: &request_budget,
                    quarantine: &self.quarantine,
                },
                &prepared.args,
                &prepared.executed_sql,
                cost_limit,
                CumulativeQueryCostGate {
                    profile: &budget_profile,
                    principal: &budget_principal,
                    policy: cumulative_policy.as_ref(),
                    store: self.query_cost_budget_store.as_deref(),
                },
            )
            .await?;
            if prepared.as_of.is_some() {
                // K9: a flashback read cannot coexist with the SET
                // TRANSACTION READ ONLY backstop — Oracle refuses
                // DBMS_FLASHBACK.ENABLE inside a transaction (ORA-08183,
                // verified live). The flashback wrapper (`read_query_as_of`)
                // owns the session snapshot, and Oracle itself refuses DML
                // while flashback is enabled, so layer B is preserved by a
                // different DB mechanism. Reset the belief so the NEXT
                // non-flashback read re-arms SET TRANSACTION READ ONLY on a
                // fresh transaction (the wrapper rolls back the session, so
                // any previously-armed read-only transaction is gone).
                read_only_backstop.disarm();
                // Arc I: the flashback wrapper rolls the session back, so
                // Oracle erased every savepoint with it.
                checkpoints.clear();
            } else {
                // Consult the effective level that governs THIS request
                // (scoped_level folds in any OAuth scope, which can only
                // LOWER the level — so this arms at least as often as the
                // unscoped level, never less).
                ensure_read_only_backstop_bounded(
                    cx,
                    conn.as_ref(),
                    read_only_backstop,
                    checkpoints,
                    scoped_level,
                    &request_budget,
                    &self.quarantine,
                )
                .await?;
            }
        }

        let active_profile = state.active_profile.clone();
        // E3/E3b: resolve immutable export ownership before the conn borrow
        // / read closure. HTTP supplies a canonical transport principal;
        // missing means the one-process stdio identity.
        let export_access = QueryExportAccess {
            principal_key: context
                .principal_key()
                .unwrap_or(oraclemcp_core::STDIO_EXPORT_PRINCIPAL)
                .to_owned(),
            scopes: context.scope_grant().map(|grant| grant.0.clone()),
        };
        let conn: &dyn OracleConnection = state.conn.as_ref();
        let policy_attachment = prepared.policy.clone();
        let admitted = AdmittedRead::new(prepared)?;
        let mut response = self
            .run_prepared_query(
                cx,
                PreparedQueryRuntime {
                    conn,
                    request_budget,
                    active_profile,
                    export_access,
                    request_subject: request_subject.clone(),
                },
                admitted,
            )
            .await?;
        // The proof of what the policy took away rides on the read it governed.
        if let (Some(tightening), Value::Object(map)) = (policy_attachment, &mut response) {
            map.insert("policy".to_owned(), tightening);
        }
        if let (Some(metadata), Value::Object(map)) = (semantic_metadata, &mut response) {
            map.insert(
                "metric".to_owned(),
                Value::String(metadata.metric.to_owned()),
            );
            map.insert("k".to_owned(), json!(metadata.k));
            // F2 does not inspect an execution plan: reporting a boolean
            // here would claim an index decision that this read did not
            // prove. The later capability/index slice can populate it.
            map.insert("used_index".to_owned(), Value::Null);
        }
        Ok(response)
    }

    pub(super) async fn dispatch_query_stream_with_cx(
        &self,
        cx: &Cx,
        context: DispatchContext<'_>,
        name: &str,
        args: Value,
        frames: ToolStreamSender,
    ) -> Result<Value, ErrorEnvelope> {
        let mut request_budget = self.dispatch_request_budget(cx, context)?;
        if let Some(timeout) = explicit_timeout_duration(&args)? {
            request_budget = request_budget.tighten_timeout(timeout);
            request_budget.enforce(cx).map_err(DbError::into_envelope)?;
        }
        self.recycle_pinned_session_if_needed(cx, &request_budget)
            .await?;
        if let Some(quarantine) = self.connection_quarantine()? {
            return Err(self.quarantined_connection_error(&quarantine));
        }

        let delivery = {
            let mut state = self.state.lock(cx).await.map_err(|_| {
                ErrorEnvelope::new(ErrorClass::Internal, "connection mutex lock failed")
            })?;
            // Arc N: the streaming read is governed by the same policy as the
            // buffered one. A read that escaped the policy just by asking for SSE
            // delivery would be a hole the size of the whole feature.
            let sql_policy = self.sql_policy()?;
            if sql_policy.is_some() && state.current_schema.is_none() {
                let described = describe_conn(cx, state.conn.as_ref())
                    .await
                    .ok()
                    .and_then(|info| info.current_schema);
                state.current_schema = described.map(|schema| schema.to_ascii_uppercase());
            }
            let current_schema = state.current_schema.clone();
            let scoped_level = scoped_session_level(&state.level, context);
            if let Some(active_profile) = state.active_profile.as_deref() {
                match state.profile_generation.as_ref() {
                    None => return Err(profile_generation_inactive_error(active_profile)),
                    Some(generation) if generation.is_draining() => {
                        return Err(profile_draining_error(active_profile));
                    }
                    Some(_) => {}
                }
            }
            let prepared = {
                let parsed = parse_args::<QueryArgs>(name, args)?;
                if !parsed.streaming {
                    return Err(invalid_args(
                        "streaming dispatch requires oracle_query streaming=true",
                    ));
                }
                let as_of = query_as_of_from_args(parsed.as_of.as_ref())?;
                let _ = parsed
                    .binds
                    .iter()
                    .map(json_to_bind)
                    .collect::<Result<Vec<_>, _>>()?;
                if parsed.export {
                    return Err(invalid_args(
                        "streaming and export are mutually exclusive: choose incremental delivery OR a single export resource",
                    ));
                }
                if as_of.is_some() {
                    return Err(invalid_args(
                        "streaming and as_of are mutually exclusive: page the flashback read with its cursor",
                    ));
                }
                // Arc N on the read path. A deny refuses the read here; a
                // predicate narrowing REWRITES it — that is what row-level policy
                // IS — and the rewritten candidate has already re-entered the
                // classifier (SEC-1). The candidate is then re-marked and put
                // through the SAME semantic read gate as any other statement, so a
                // rewrite can never widen what the read path admits.
                let policy = apply_sql_policy(
                    sql_policy.as_ref(),
                    current_schema.as_deref(),
                    context.principal_key(),
                    &SEMANTIC_READ_PRECHECK_CLASSIFIER,
                    &SEMANTIC_READ_PRECHECK_CLASSIFIER.classify(&parsed.sql),
                    &parsed.sql,
                )?;
                let policy_sql = policy
                    .effective_sql
                    .clone()
                    .unwrap_or_else(|| parsed.sql.clone());
                let executed_sql =
                    with_audit_marker(&policy_sql, state.active_profile.as_deref(), "oracle_query");
                let classified = ensure_resolved_read_only(
                    cx,
                    state.conn.as_ref(),
                    &state.catalog_cache,
                    &executed_sql,
                )
                .await;
                let (gate, verdict_certificate) = match classified {
                    Ok(decision) => (Ok(()), Some(decision.verdict_certificate().clone())),
                    Err(error) => (Err(error), None),
                };
                ReadExecutionPlan {
                    args: parsed,
                    audit_tool: "oracle_query".to_owned(),
                    executed_sql,
                    gate,
                    verdict_certificate,
                    as_of,
                    rls_vpd_relations: Vec::new(),
                    policy: policy.attachment.clone(),
                }
            };
            request_budget = query_budget_with_cost_limit(
                request_budget,
                self.max_query_cost()?,
                prepared.args.max_query_cost,
            );
            request_budget.enforce(cx).map_err(DbError::into_envelope)?;

            if prepared.gate.is_ok() {
                let cost_limit = effective_query_cost_limit(
                    self.max_query_cost()?,
                    prepared.args.max_query_cost,
                );
                let cumulative_policy = self.cumulative_query_cost_budget()?;
                let budget_profile = state
                    .active_profile
                    .clone()
                    .unwrap_or_else(|| "standalone".to_owned());
                let budget_principal = context
                    .principal_key()
                    .unwrap_or(oraclemcp_core::STDIO_EXPORT_PRINCIPAL)
                    .to_owned();
                let DispatcherState {
                    conn,
                    read_only_backstop,
                    checkpoints,
                    ..
                } = &mut *state;
                enforce_query_cost_gate(
                    QueryCostGateCtx {
                        cx,
                        conn: conn.as_ref(),
                        read_only_backstop,
                        checkpoints,
                        session: &scoped_level,
                        request_budget: &request_budget,
                        quarantine: &self.quarantine,
                    },
                    &prepared.args,
                    &prepared.executed_sql,
                    cost_limit,
                    CumulativeQueryCostGate {
                        profile: &budget_profile,
                        principal: &budget_principal,
                        policy: cumulative_policy.as_ref(),
                        store: self.query_cost_budget_store.as_deref(),
                    },
                )
                .await?;
                if prepared.as_of.is_some() {
                    read_only_backstop.disarm();
                    // Arc I: the flashback wrapper rolls the session back, so
                    // Oracle erased every savepoint with it.
                    checkpoints.clear();
                } else {
                    ensure_read_only_backstop_bounded(
                        cx,
                        conn.as_ref(),
                        read_only_backstop,
                        checkpoints,
                        &scoped_level,
                        &request_budget,
                        &self.quarantine,
                    )
                    .await?;
                }
            }

            let active_profile = state.active_profile.clone();
            let conn: &dyn OracleConnection = state.conn.as_ref();
            let policy_attachment = prepared.policy.clone();
            let admitted = AdmittedRead::new(prepared)?;
            let delivery = self
                .prepare_query_stream_delivery(cx, conn, request_budget, active_profile, admitted)
                .await?;
            (delivery, policy_attachment)
        };
        let (delivery, policy_attachment) = delivery;

        let mut response = match delivery {
            QueryStreamDelivery::Rows(plan) => self.drive_query_row_stream(cx, *plan, frames).await,
            QueryStreamDelivery::Chunked(response) => {
                OracleDispatcher::emit_chunked_stream_frames(cx, response, frames).await
            }
        }?;
        if let (Some(tightening), Value::Object(map)) = (policy_attachment, &mut response) {
            map.insert("policy".to_owned(), tightening);
        }
        Ok(response)
    }

    /// Run an oracle_query whose args were parsed and whose SQL was marked +
    /// classified ONCE up front (see `ReadExecutionPlan`). Reuses the prepared
    /// `executed_sql` and `gate` instead of re-parsing/re-marking/re-classifying
    /// — behavior is identical to the prior inline arm, with one classify run.
    async fn run_prepared_query(
        &self,
        cx: &Cx,
        runtime: PreparedQueryRuntime<'_>,
        admitted: AdmittedRead,
    ) -> Result<Value, ErrorEnvelope> {
        let prepared = admitted.into_plan();
        let PreparedQueryRuntime {
            conn,
            request_budget,
            active_profile,
            export_access,
            request_subject,
        } = runtime;
        let ReadExecutionPlan {
            args: a,
            audit_tool,
            executed_sql,
            gate,
            verdict_certificate,
            as_of,
            rls_vpd_relations,
            policy: _,
        } = prepared;
        let timeout_seconds = a.timeout_seconds;
        let exports = self.exports.clone();
        let body_budget = request_budget.clone();
        let read_conn = ReadUncertaintyConn {
            inner: conn,
            quarantine: Some(&self.quarantine),
        };
        // A9: narrow the handler context to the read-path capability row
        // (TIME + IO; no SPAWN / REMOTE / RANDOM). The pure handler work below —
        // gate, bind conversion, cursor decode, serialization — runs under this
        // narrowed row; only the locked DB round trip (`OracleConnection` is
        // object-safe and takes the full `&Cx`) is handed the full `cx`, the one
        // documented IO exception.
        let read_cx = narrow_to_read_path(cx);
        with_call_timeout(
            cx,
            conn,
            &self.quarantine,
            request_budget,
            timeout_seconds,
            CompletionPolicy::EnforceDeadlineAfterBody,
            || async {
                dispatch_checkpoint(&read_cx, "oraclemcp.dispatch.query.before")?;
                // The read-only gate was computed ONCE up front (classified ==
                // executed); reuse the same verdict here. `executed_sql` is the
                // marked text that gate was computed against.
                gate?;
                let binds = a
                    .binds
                    .iter()
                    .map(json_to_bind)
                    .collect::<Result<Vec<_>, _>>()?;
                // E2: the page cursor is an opaque, tamper-evident token bound to
                // THIS statement + active profile, decoded to a raw offset here (a
                // forged/cross-statement cursor fails closed).
                let offset =
                    decode_query_cursor(a.cursor.as_deref(), &a.sql, active_profile.as_deref())?;
                if a.format == QueryFormat::Arrow && (a.export || a.streaming) {
                    return Err(invalid_args(
                        "format=arrow is an inline result format and is mutually exclusive with \
                         export and streaming",
                    )
                    .with_next_step(
                        "use format=json with export/streaming, or remove export/streaming for an Arrow page",
                    ));
                }
                // K10: streaming delivery. The classifier already proved this read
                // (`gate?` above); streaming only changes how the SAME rows are
                // DELIVERED — as an ordered, resumable `chunks` array driven by
                // successive cursor pages, byte-identical to a manual cursor resume.
                if a.streaming {
                    if a.export {
                        return Err(invalid_args(
                            "streaming and export are mutually exclusive: choose incremental \
                         chunks (streaming=true) OR a single export resource (export=true)",
                        )
                        .with_next_step("re-run with exactly one of streaming / export"));
                    }
                    if as_of.is_some() {
                        return Err(invalid_args(
                            "streaming and as_of are mutually exclusive: a flashback read is \
                         delivered as a single page — resume it with the returned cursor",
                        )
                        .with_next_step("drop streaming, or page the as_of read with cursor"));
                    }
                    let caps = query_caps_from_args(&a);
                    let result_masking = self.result_masking_policy()?;
                    if result_masking.is_some() {
                        return Err(invalid_args(
                            "streaming masked query results is temporarily unavailable because \
                             mask-decision certificates must be audit-bound before rows leave the \
                             server",
                        )
                        .with_next_step(
                            "retry without streaming=true so the masked page can carry an audit-bound certificate",
                        ));
                    }
                    let serialize_opts =
                        query_serialize_options_from_args_with_policy(&a, result_masking.as_ref());
                    return stream_query_response(
                        cx,
                        &read_conn,
                        &body_budget,
                        &executed_sql,
                        &a.sql,
                        &binds,
                        caps,
                        offset,
                        &serialize_opts,
                        active_profile.as_deref(),
                    )
                    .await;
                }
                // E3b: when the caller opts into export, materialize the bounded full
                // result as an oracle-export://{id} resource and return a
                // resource_link instead of inlining the rows.
                if a.export {
                    let result_masking = self.result_masking_policy()?;
                    return export_query_to_resource(
                        cx,
                        &read_conn,
                        &executed_sql,
                        &a,
                        &binds,
                        offset,
                        active_profile.as_deref(),
                        &export_access,
                        exports.as_deref(),
                        as_of.as_ref(),
                        result_masking.as_ref(),
                        self.auditor.as_deref(),
                        &request_subject,
                    )
                    .await;
                }
                // K9: when a flashback target is set, run the SAME proven SQL inside
                // a bounded DBMS_FLASHBACK window (`read_query_as_of`); otherwise the
                // plain read path. Both take the identical proven `executed_sql`.
                let caps = query_caps_from_args(&a);
                let result_masking = self.result_masking_policy()?;
                let serialize_opts =
                    query_serialize_options_from_args_with_policy(&a, result_masking.as_ref());
                let auditor = self.auditor.as_deref();
                if result_masking.is_some() && auditor.is_none() {
                    return Err(ErrorEnvelope::new(
                        ErrorClass::RuntimeStateRequired,
                        "result masking is active but no audit sink is configured; refusing to return a \
                         masked result without hash-chain binding",
                    )
                    .with_next_step(
                        "configure audit logging, or disable result masking for this profile",
                    ));
                }

                let read_audit_evidence =
                    collect_read_audit_db_evidence(cx, auditor, &read_conn).await?;
                let read_audit = AuditEntryCtx {
                    auditor,
                    subject: &request_subject,
                    db_evidence: read_audit_evidence.as_ref(),
                };

                // Resolve every structured flashback target before execution,
                // regardless of whether audit is configured. Timestamp input
                // becomes the exact SCN Oracle selected, which the response
                // echoes as a replay handle; the guard still sees only the
                // unchanged base SQL. A missing DBMS_FLASHBACK grant here
                // still typed-refuses (K9's replay contract genuinely needs
                // the capability — there is no snapshot-less AS-OF read).
                let replay_target = match as_of.as_ref() {
                    Some(as_of) => Some(AsOf::Scn(
                        as_of
                            .resolve_to_scn(cx, &read_conn)
                            .await
                            .map_err(DbError::into_envelope)?,
                    )),
                    None => None,
                };
                // F-S1 (SEC-4: self-heal DOWN, never silently UP): an ordinary
                // (non-AS-OF) audited read only probes the SCN for audit
                // provenance, so a missing DBMS_FLASHBACK grant degrades this
                // read explicitly via `observed_scn_for_audit` (which audits
                // the degradation itself) rather than blocking every audited
                // profile that has not separately granted the capability.
                let observed_scn = match (auditor, replay_target.as_ref()) {
                    (Some(_), Some(AsOf::Scn(scn))) => Some(*scn),
                    (Some(_), Some(AsOf::Timestamp(_))) => unreachable!(
                        "audited timestamp flashback targets are resolved to SCNs before execution"
                    ),
                    (Some(_), None) => observed_scn_for_audit(cx, &read_conn, read_audit)
                        .await
                        .map_err(DbError::into_envelope)?,
                    (None, _) => None,
                };
                // The certificate is built whenever an auditor is configured,
                // even when `observed_scn` degraded to `None` above: the read
                // stays durably audited, just without a captured snapshot
                // (`VerdictCertificate::with_observed_scn` already accepts
                // `Option<u64>`, so this needs no new API).
                let audit_certificate = auditor
                    .map(|_| {
                        verdict_certificate
                            .as_ref()
                            .expect("a successful prepared read gate always retains its certificate")
                            .clone()
                            .with_observed_scn(observed_scn)
                            .audit_certificate()
                    })
                    .transpose()
                    .map_err(|error| {
                        ErrorEnvelope::new(
                            ErrorClass::Internal,
                            format!("cannot persist registered verdict certificate: {error}"),
                        )
                    })?;
                if let Some(audit_certificate) = audit_certificate.as_ref() {
                    append_query_read_audit(
                        read_audit,
                        &audit_tool,
                        &executed_sql,
                        observed_scn,
                        audit_certificate,
                        AuditOutcome::Pending,
                        None,
                    )?;
                }

                let read = match replay_target.as_ref() {
                    Some(as_of) => {
                        read_query_as_of(
                            cx,
                            &read_conn,
                            &executed_sql,
                            &binds,
                            caps,
                            offset,
                            &serialize_opts,
                            as_of,
                        )
                        .await
                    }
                    None => {
                        read_query(
                            cx,
                            &read_conn,
                            &executed_sql,
                            &binds,
                            caps,
                            offset,
                            &serialize_opts,
                        )
                        .await
                    }
                };
                let mut response = match read {
                    Ok(response) => response,
                    Err(error) => {
                        if let Some(audit_certificate) = audit_certificate.as_ref() {
                            append_query_read_audit(
                                read_audit,
                                &audit_tool,
                                &executed_sql,
                                observed_scn,
                                audit_certificate,
                                AuditOutcome::Failed,
                                None,
                            )?;
                        }
                        return Err(DbError::into_envelope(error));
                    }
                };
                if !rls_vpd_relations.is_empty() {
                    response.rls_vpd = Some(
                        observe_vpd_rls_for_relations(cx, &read_conn, &rls_vpd_relations).await,
                    );
                }
                if let Some(audit_certificate) = audit_certificate.as_ref() {
                    append_query_read_audit(
                        read_audit,
                        &audit_tool,
                        &executed_sql,
                        observed_scn,
                        audit_certificate,
                        AuditOutcome::Succeeded,
                        Some(&mut response),
                    )?;
                }
                let response = match a.format {
                    QueryFormat::Json => serde_json::to_value(response).unwrap_or(Value::Null),
                    QueryFormat::Arrow => query_response_as_arrow(response)?,
                };
                Ok(reseal_query_cursor(
                    response,
                    &a.sql,
                    active_profile.as_deref(),
                ))
            },
        )
        .await
    }
}

pub(super) async fn ensure_read_only_backstop_bounded(
    cx: &Cx,
    conn: &dyn OracleConnection,
    backstop: &mut ReadOnlyBackstop,
    checkpoints: &CheckpointWorkspace,
    level: &SessionLevelState,
    request_budget: &RequestBudget,
    quarantine: &SyncMutex<Option<ConnectionQuarantine>>,
) -> Result<(), ErrorEnvelope> {
    request_budget.enforce(cx).map_err(DbError::into_envelope)?;
    let limits = ConnectionLimitGuard::install(
        cx,
        conn,
        Some(quarantine),
        None,
        request_budget.deadline(),
        Some(request_budget.db_quota()),
    )
    .map_err(DbError::into_envelope)?;
    let result = backstop.ensure_armed(cx, conn, level).await;
    // Arc I: re-arming rolled the transaction back, so Oracle erased every
    // savepoint and every held statement with it. Drop the workspace belief
    // before anything can read it back as still-live.
    if matches!(result, Ok(true)) {
        checkpoints.clear();
    }
    let budget_after = request_budget.enforce(cx).map_err(DbError::into_envelope);
    let restore_error = limits.restore().err();
    if let Err(primary) = result {
        if let Some(restore_err) = restore_error {
            let _ = mark_connection_quarantined(
                quarantine,
                AuditOutcome::UnknownDiscarded,
                format!(
                    "read-only transaction backstop failed and request-limit restoration also failed: {restore_err}"
                ),
            );
        }
        return Err(primary);
    }
    if let Some(restore_err) = restore_error {
        return Err(limit_restore_failure(quarantine, false, restore_err));
    }
    budget_after
}

/// K10: deliver a proven read as an ordered, resumable `chunks` array —
/// streaming delivery of `oracle_query`. Each chunk is one [`read_query`]
/// cursor page, so a chunk's rows are BYTE-IDENTICAL to the page a caller
/// would get by resuming with the previous chunk's `next_cursor`; streaming
/// changes DELIVERY, never the proven-read bytes, and the classifier is
/// untouched (the read was already gated in `run_prepared_query`).
///
/// Backpressure / budget: every chunk boundary re-checkpoints `cx`, so the
/// request deadline + cancellation (the asupersync budget carried on `cx`)
/// stop the walk between pages — a cancelled or expired stream never keeps
/// fetching. Bounded by [`MAX_QUERY_STREAM_ROWS`]: at the cap the final chunk
/// carries a resume cursor and the response is flagged `truncated`.
///
/// Over the HTTP/SSE transport the assembled `chunks` are re-emitted as
/// individual `event: chunk` SSE frames by the transport layer
/// (`oraclemcp_core::http`); over stdio/JSON the same `chunks` array is the
/// inline incremental-delivery contract.
#[allow(clippy::too_many_arguments)]
pub(super) async fn stream_query_response(
    cx: &Cx,
    conn: &dyn OracleConnection,
    request_budget: &RequestBudget,
    executed_sql: &str,
    cursor_sql: &str,
    binds: &[OracleBind],
    caps: QueryCaps,
    start_offset: usize,
    serialize_opts: &SerializeOptions,
    active_profile: Option<&str>,
) -> Result<Value, ErrorEnvelope> {
    let page_rows = caps.max_rows.max(1);
    let max_chunks = MAX_QUERY_STREAM_ROWS.div_ceil(page_rows).max(1);
    let mut offset = start_offset;
    let mut chunks: Vec<Value> = Vec::new();
    let mut columns: Vec<String> = Vec::new();
    let mut total_rows = 0usize;
    let mut truncated = false;
    let mut final_cursor = Value::Null;
    for seq in 0..max_chunks {
        // Budget/cancellation checkpoint at every chunk boundary — the
        // backpressure signal for the walk (A9-narrowed cx is sufficient;
        // only the DB round trip inside read_query needs the full row).
        dispatch_checkpoint(cx, "oraclemcp.dispatch.query.stream.chunk")?;
        request_budget.enforce(cx).map_err(DbError::into_envelope)?;
        let page = read_query(cx, conn, executed_sql, binds, caps, offset, serialize_opts)
            .await
            .map_err(DbError::into_envelope)?;
        request_budget.enforce(cx).map_err(DbError::into_envelope)?;
        if seq == 0 {
            columns = page.columns.clone();
        }
        let more = page.truncated;
        let reached_cap = seq + 1 >= max_chunks;
        let last = !more || reached_cap;
        total_rows += page.row_count;
        // Re-seal the raw next offset as the tamper-evident cursor a
        // paginated caller would receive (E2); present only when more rows
        // remain. On the final chunk this doubles as the resume cursor.
        let sealed_next = page
            .next_cursor
            .as_deref()
            .map(|raw| Value::String(seal_raw_query_cursor(raw, cursor_sql, active_profile)))
            .unwrap_or(Value::Null);
        let next_offset = offset + page.row_count;
        chunks.push(json!({
            "seq": seq,
            "rows": page.rows,
            "row_count": page.row_count,
            "total_bytes": page.total_bytes,
            "next_cursor": sealed_next.clone(),
            "last": last,
        }));
        if last {
            truncated = more;
            final_cursor = sealed_next;
            break;
        }
        offset = next_offset;
    }
    let chunk_count = chunks.len();
    Ok(json!({
        "streaming": true,
        "columns": columns,
        "chunks": chunks,
        "chunk_count": chunk_count,
        "row_count": total_rows,
        "truncated": truncated,
        "next_cursor": final_cursor,
    }))
}

impl OracleDispatcher {
    /// Read one side of a cross-database `oracle_diff` from a named profile, on
    /// a connection opened and closed inside this call.
    ///
    /// Arc H adds *reach*, never admission surface. Every guard the caller would
    /// meet on the way to this database through `oracle_switch_profile` is met
    /// here, in the same order:
    ///
    /// 1. **Exposure (E5).** The profile is admitted through
    ///    [`ProfileDrainState::admit_mcp_profile`] before its credentials are
    ///    resolved, so a diff can never reach a profile the caller could not
    ///    switch to, and a hidden name is refused without revealing that it
    ///    exists.
    /// 2. **Its own catalog.** The statement is re-resolved and re-classified
    ///    against *this* database with a fresh
    ///    [`OracleCatalogResolverCache`]. The cache key carries no database
    ///    identity, so reusing the pinned session's cache would resolve this
    ///    database's SQL against the other one's objects — the same text can name
    ///    different objects here.
    /// 3. **Its own egress policy.** Rows are masked under this profile's
    ///    masking policy, not the active session's.
    ///
    /// The connection is transient: it is never installed in `DispatcherState`,
    /// so the pinned session, its transaction, and its quarantine are untouched.
    /// It is deliberately *not* wired to `self.quarantine` — a failure on the
    /// database being compared against must not poison the caller's own session.
    pub(super) async fn read_diff_side_from_profile(
        &self,
        cx: &Cx,
        request: DiffSideRequest<'_>,
    ) -> Result<DiffSideRead, ErrorEnvelope> {
        let DiffSideRequest {
            side,
            profile,
            sql,
            binds,
            caps,
            scn,
            serialize_defaults,
            subject,
            budget,
            infer_key,
        } = request;

        let lease = match self
            .profile_drain
            .admit_mcp_profile(profile, self.mcp_exposure.is_exposed(profile))
        {
            ProfileGenerationAdmission::Ready(lease) => lease,
            ProfileGenerationAdmission::NotExposed => {
                return Err(diff_side_failure(
                    side,
                    profile,
                    profile_not_available(profile),
                ));
            }
            ProfileGenerationAdmission::Draining => {
                return Err(diff_side_failure(
                    side,
                    profile,
                    profile_draining_error(profile),
                ));
            }
        };
        let Some(connector) = &self.connector else {
            return Err(diff_side_failure(
                side,
                profile,
                ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "cross-database diff is unavailable in this server instance",
                )
                .with_next_step("restart the server with `oraclemcp serve --profile <name>`"),
            ));
        };
        let policy = profile_dispatch_policy(&lease)
            .map_err(|error| diff_side_failure(side, profile, error))?;
        let (conn, _stateless) = connector(cx, &lease)
            .await
            .map_err(|error| diff_side_failure(side, profile, DbError::into_envelope(error)))?
            .into_parts();

        let limits = ConnectionLimitGuard::install(
            cx,
            conn.as_ref(),
            None,
            None,
            budget.deadline(),
            Some(budget.db_quota()),
        )
        .map_err(|error| diff_side_failure(side, profile, DbError::into_envelope(error)))?;

        // Everything fallible below runs inside this block so the connection's
        // request limits are always restored, whatever the outcome.
        let read = async {
            let observed = ReadUncertaintyConn {
                inner: conn.as_ref(),
                quarantine: None,
            };
            let executed_sql = with_audit_marker(sql, Some(profile), "oracle_diff");
            let catalog_cache = OracleCatalogResolverCache::new();
            let (relations, _) =
                resolve_read_only_relations(cx, &observed, &catalog_cache, &executed_sql).await?;
            let inferred_key = if infer_key {
                inferred_diff_key_columns(cx, &observed, &relations).await?
            } else {
                Vec::new()
            };
            let serialize_opts = SerializeOptions {
                result_masking: policy.result_masking.clone(),
                ..serialize_defaults
            };
            let mut response = match scn {
                Some(scn) => {
                    read_query_as_of(
                        cx,
                        &observed,
                        &executed_sql,
                        binds,
                        caps,
                        0,
                        &serialize_opts,
                        &AsOf::Scn(scn),
                    )
                    .await
                }
                None => {
                    read_query(
                        cx,
                        &observed,
                        &executed_sql,
                        binds,
                        caps,
                        0,
                        &serialize_opts,
                    )
                    .await
                }
            }
            .map_err(DbError::into_envelope)?;
            bind_result_masking_audit(
                cx,
                &observed,
                self.auditor.as_deref(),
                subject,
                "oracle_diff",
                &executed_sql,
                &mut response,
            )
            .await?;
            Ok(DiffSideRead {
                response,
                inferred_key,
            })
        }
        .await
        .map_err(|error| diff_side_failure(side, profile, error));

        // Restore before surfacing the read outcome: a restore failure on a
        // connection we are about to drop must not mask the real error.
        let restore = limits
            .restore()
            .map_err(|error| diff_side_failure(side, profile, DbError::into_envelope(error)));
        let read = read?;
        restore?;
        Ok(read)
    }
}

#[cfg(test)]
mod fga_shape_tests {
    use super::*;

    #[test]
    fn fga_evidence_unknown_refusal_points_to_doctor_and_the_grant() {
        let unknown = fga_refusal("fga_evidence_unknown");
        // Still the same fail-closed refusal (.6.9); only the hint is new.
        assert_eq!(unknown.error_class, ErrorClass::ForbiddenStatement);
        assert!(unknown.message.ends_with("fga_evidence_unknown"));
        let hint = unknown.next_steps.join(" ");
        assert!(hint.contains("fga_catalog_unreadable"), "{hint}");
        assert!(hint.contains("oraclemcp doctor --online"), "{hint}");
        assert!(hint.contains("GRANT SELECT ANY DICTIONARY"), "{hint}");
        assert!(hint.contains("docs/operations.md §3.1"), "{hint}");

        let handler = fga_refusal("fga_handler_autonomous");
        assert_eq!(handler.error_class, ErrorClass::ForbiddenStatement);
        let hint = handler.next_steps.join(" ");
        assert!(hint.contains("remove the FGA handler"), "{hint}");
        assert!(!hint.contains("SELECT ANY DICTIONARY"), "{hint}");
    }

    #[test]
    fn generated_sample_shape_is_eligible_for_semantic_read_proof() {
        let sql = "SELECT * FROM (SELECT * FROM APP.ORDERS) WHERE ROWNUM <= :1";
        let preliminary = READ_PRECHECK_CLASSIFIER.classify(sql);
        ensure_read_only_decision(preliminary).expect("sample shape must pass read precheck");
        semantic_read_plan_checked(sql).expect("sample shape must have a semantic read plan");
    }

    #[test]
    fn generated_lob_shape_is_eligible_for_semantic_read_proof() {
        let sql = oraclemcp_db::read_lob_sql("APP", "ORDERS", "NOTE", "ID")
            .expect("fixed identifiers form a read query");
        let preliminary = READ_PRECHECK_CLASSIFIER.classify(&sql);
        ensure_read_only_decision(preliminary).expect("LOB shape must pass read precheck");
        semantic_read_plan_checked(&sql).expect("LOB shape must have a semantic read plan");
    }
}
