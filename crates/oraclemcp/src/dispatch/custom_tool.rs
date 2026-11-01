//! Operator-defined SQL and signed package tools. Package activation and each
//! call share the source-backed plan, typed wrapper and confirmation binding.

use std::collections::HashMap;

use oraclemcp_core::ToolBody;
use oraclemcp_db::OracleBind;
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{FieldStatus, named_bind_placeholders};
use serde_json::{Value, json};

use super::*;
use oraclemcp_core::{PackageArgDirection, PackageCallWrapper, SignedPackageDefinition};
#[cfg(any(feature = "plsql-intelligence", test))]
use oraclemcp_db::{CatalogQueryId, run_catalog_query};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub(super) struct PackageCallPlan {
    pub(super) approval_action: oraclemcp_core::tools::ApprovalAction,
    pub(super) signed: SignedPackageDefinition,
    pub(super) wrapper: PackageCallWrapper,
    pub(super) required_level: OperatingLevel,
    pub(super) effects: oraclemcp_guard::RoutineEffectsV1,
    pub(super) literal_sql: Vec<String>,
    pub(super) facts_digest: [u8; 32],
    pub(super) callback_digests: Vec<String>,
    pub(super) ddl_closures: Vec<[u8; 32]>,
    pub(super) compile_observation: bool,
}

pub(super) fn package_unavailable(message: impl Into<String>) -> ErrorEnvelope {
    ErrorEnvelope::new(ErrorClass::RuntimeStateRequired, message)
        .with_statement_outcome(StatementOutcome::NotStarted)
}

fn package_unknown(reason: impl std::fmt::Debug) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::ForbiddenStatement,
        format!("CUSTOM_TOOL_CLOSURE_UNPROVEN: {reason:?}"),
    )
    .with_statement_outcome(StatementOutcome::NotStarted)
}

#[cfg(any(feature = "plsql-intelligence", test))]
async fn check_package_name_capture(
    cx: &Cx,
    conn: &dyn OracleConnection,
    schema: &str,
    owner: &str,
) -> Result<(), ErrorEnvelope> {
    for (query, namespace) in [
        (CatalogQueryId::Objects, schema),
        (CatalogQueryId::Synonyms, schema),
        (CatalogQueryId::Synonyms, "PUBLIC"),
    ] {
        let rows = run_catalog_query(
            cx,
            conn,
            query,
            &[namespace.into(), owner.into(), 2_i64.into()],
        )
        .await
        .map_err(|_| package_unknown("name-capture evidence unreadable"))?;
        if !rows.is_empty() {
            return Err(ErrorEnvelope::new(ErrorClass::PolicyDenied, "CUSTOM_TOOL_NAME_CAPTURE: an object or synonym captures the routine's schema qualifier")
                .with_statement_outcome(StatementOutcome::NotStarted));
        }
    }
    Ok(())
}

fn package_digest(value: &impl serde::Serialize) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(value).expect("typed package facts serialize")).into()
}

impl OracleDispatcher {
    /// Pending definitions never enter a registry. This transition belongs to
    /// one pinned profile generation and publishes only completed live proofs.
    pub(super) async fn activate_package_catalog(
        &self,
        cx: &Cx,
        state: &mut DispatcherState,
        budget: &RequestBudget,
    ) -> Result<(), ErrorEnvelope> {
        if state.custom_catalog.activation_complete {
            return Ok(());
        }
        if let Some(profile) = state.active_profile.as_deref() {
            let lease = state
                .profile_generation
                .as_ref()
                .ok_or_else(|| profile_generation_inactive_error(profile))?;
            if lease.is_draining() {
                return Err(profile_draining_error(profile));
            }
        }
        let masked = self
            .result_masking
            .lock()
            .map_err(|_| package_unavailable("masking state is unavailable"))?
            .is_some();
        let pending = state.custom_catalog.catalog.pending().to_vec();
        let limits = ConnectionLimitGuard::install(
            cx,
            state.conn.as_ref(),
            Some(&self.quarantine),
            None,
            budget.deadline(),
            Some(budget.db_quota()),
        )
        .map_err(DbError::into_envelope)?;
        let mut packages = Vec::new();
        let mut plans = HashMap::new();
        for signed in pending {
            budget.enforce(cx).map_err(DbError::into_envelope)?;
            let plan = Box::pin(collect_package_plan(
                cx,
                state.conn.as_ref(),
                &signed,
                state.level.effective_ceiling(),
                masked,
                state
                    .profile_classifier
                    .requires_security_feature_evidence(),
            ))
            .await;
            if let Ok(plan) = &plan {
                packages.push(oraclemcp_core::LoadedTool {
                    def: signed.definition().clone(),
                    required_level: plan.required_level,
                });
            }
            plans.insert(signed.definition().name.clone(), plan);
        }
        limits.restore().map_err(DbError::into_envelope)?;
        let catalog = state.custom_catalog.catalog.activated(packages);
        let mut registry = ToolRegistry::new();
        catalog.register_first_class(&mut registry);
        state.custom_catalog.catalog = Arc::new(catalog);
        for descriptor in &mut registry.tools {
            descriptor.approval_action = Some(
                plans
                    .get(&descriptor.name)
                    .and_then(|plan| plan.as_ref().ok())
                    .map_or(
                        oraclemcp_core::tools::ApprovalAction::ExecuteStatement,
                        |plan| plan.approval_action,
                    ),
            );
        }
        state.custom_catalog.descriptors = registry.tools.into();
        state.custom_catalog.package_plans = plans;
        state.custom_catalog.activation_complete = true;
        Ok(())
    }
}

async fn collect_package_plan(
    cx: &Cx,
    conn: &dyn OracleConnection,
    signed: &SignedPackageDefinition,
    max_level: OperatingLevel,
    masked: bool,
    strict_security: bool,
) -> Result<PackageCallPlan, ErrorEnvelope> {
    let def = signed.definition();
    let output = def.implicit_results
        || def.capture_dbms_output
        || def
            .args
            .iter()
            .any(|arg| arg.direction != PackageArgDirection::In);
    if masked && output {
        return Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "CUSTOM_TOOL_MASKED_OUTPUT: package output cannot be proven masked",
        )
        .with_statement_outcome(StatementOutcome::NotStarted));
    }
    #[cfg(not(feature = "plsql-intelligence"))]
    {
        let _ = (cx, conn, max_level, strict_security);
        Err(package_unavailable(
            "package-call activation requires the PL/SQL engine",
        ))
    }
    #[cfg(feature = "plsql-intelligence")]
    {
        use oraclemcp_db::mutation_closure::{
            MutationRoutineUse, read_pinned_mutation_routine_source,
        };
        let routine = def
            .routine
            .as_ref()
            .ok_or_else(|| package_unknown("structured routine missing"))?;
        let context = oraclemcp_db::read_catalog_resolve_context(
            cx,
            conn,
            Default::default(),
            Default::default(),
        )
        .await
        .map_err(|_| package_unknown("session visibility unreadable"))?;
        check_package_name_capture(cx, conn, &context.current_schema, &routine.owner).await?;
        if def.args.iter().any(|arg| {
            matches!(
                arg.oracle_type,
                oraclemcp_core::PackageOracleType::Date
                    | oraclemcp_core::PackageOracleType::Timestamp
                    | oraclemcp_core::PackageOracleType::Raw
            )
        }) {
            check_package_name_capture(cx, conn, &context.current_schema, "SYS").await?;
        }
        let identities = run_catalog_query(
            cx,
            conn,
            CatalogQueryId::ClosureRoutineAuthid,
            &[
                routine.owner.as_str().into(),
                routine.package.as_str().into(),
                routine.member.as_str().into(),
                routine.member.as_str().into(),
                33_i64.into(),
            ],
        )
        .await
        .map_err(|_| package_unknown("routine identity unreadable"))?;
        if identities.len() >= 33 {
            return Err(package_unknown("routine identity projection truncated"));
        }
        let selected: Vec<_> = identities
            .iter()
            .filter(|row| row.parse_i64("SUBPROGRAM_ID") == Some(i64::from(routine.subprogram_id)))
            .collect();
        let [identity] = selected.as_slice() else {
            return Err(package_unknown("pinned subprogram is absent or ambiguous"));
        };
        if identity.text("OVERLOAD") != routine.overload.as_deref()
            || identity.text("AUTHID") != Some("DEFINER")
        {
            return Err(package_unknown(
                "overload or definer-rights identity differs",
            ));
        }
        let rows = run_catalog_query(
            cx,
            conn,
            CatalogQueryId::MemberArguments,
            &[
                routine.owner.as_str().into(),
                routine.package.as_str().into(),
                routine.member.as_str().into(),
                257_i64.into(),
            ],
        )
        .await
        .map_err(|_| package_unknown("argument metadata unreadable"))?;
        let wrapper = oraclemcp_core::package_call_wrapper(def, &rows).map_err(|error| match error {
            oraclemcp_core::LoadError::OutputUnavailable { channel, .. } => package_unavailable(format!("CUSTOM_TOOL_OUTPUT_UNAVAILABLE: {channel} requires pvlqq.10.15"))
                .with_next_step("pvlqq.10.15 must provide bounded output execution before this definition can be advertised"),
            other => package_unknown(other),
        })?;
        let mut source = read_pinned_mutation_routine_source(
            cx,
            conn,
            &routine.owner,
            &routine.package,
            "PACKAGE BODY",
            Some(&routine.member),
            Some(routine.subprogram_id),
        )
        .await
        .map_err(package_unknown)?;
        source.use_context = MutationRoutineUse::CustomToolCall;
        let proof = crate::mutation_closure::EngineMutationEffects
            .prove_package_call(cx, conn, &source, &def.args)
            .await
            .map_err(package_unknown)?;
        if def.closure_sha256.as_deref() != Some(proof.proof.closure_fingerprint.as_str()) {
            return Err(ErrorEnvelope::new(
                ErrorClass::ForbiddenStatement,
                format!(
                    "CUSTOM_TOOL_CLOSURE_PIN_MISMATCH: observed closure_sha256={}",
                    proof.proof.closure_fingerprint
                ),
            )
            .with_statement_outcome(StatementOutcome::NotStarted));
        }
        let derived = oraclemcp_guard::admit(
            &proof.proof.effects,
            oraclemcp_guard::AdmissionContext::CustomToolCall,
        )
        .map_err(package_unknown)?;
        let required_level = def
            .declared_level
            .as_deref()
            .and_then(OperatingLevel::parse)
            .map_or(derived, |floor| floor.max(derived));
        if required_level > max_level {
            return Err(ErrorEnvelope::new(
                ErrorClass::PolicyDenied,
                "custom routine exceeds the profile ceiling",
            )
            .with_statement_outcome(StatementOutcome::NotStarted));
        }
        let fresh = oraclemcp_db::read_catalog_resolve_context(
            cx,
            conn,
            Default::default(),
            Default::default(),
        )
        .await
        .map_err(|_| package_unknown("session visibility unreadable"))?;
        if fresh != context {
            return Err(package_unknown(
                "session visibility changed during activation",
            ));
        }
        check_package_name_capture(cx, conn, &context.current_schema, &routine.owner).await?;
        let database = oraclemcp_db::read_closure_database_identity(cx, conn)
            .await
            .map_err(|_| package_unknown("database identity unreadable"))?;
        let mut callback_digests = Vec::new();
        let mut ddl_closures = Vec::new();
        let mut compile_observation = false;
        let mut effects = proof.proof.effects.clone();
        for request in &proof.proof.mutations {
            let closure = oraclemcp_db::mutation_closure::collect_mutation_effect_closure(
                cx,
                conn,
                request.clone(),
                &crate::mutation_closure::EngineMutationEffects,
            )
            .await;
            let callback_level = closure.admit().map_err(package_unknown)?;
            if callback_level >= OperatingLevel::Ddl {
                return Err(package_unknown(
                    "implicit mutation introduces DDL/Admin into a DML call",
                ));
            }
            for mechanism in &closure.mechanisms {
                effects = effects.union(&mechanism.effects);
            }
            callback_digests.push(closure.fingerprint());
        }
        if proof
            .proof
            .effects
            .iter()
            .any(|effect| effect == oraclemcp_guard::RoutineEffect::Ddl)
        {
            // The DDL collector models the executing identity. A different
            // definer cannot be substituted for that identity by an assertion.
            if context.connected_schema != routine.owner {
                return Err(package_unknown(
                    "DDL definer differs from the connected trigger context",
                ));
            }
            for sql in &proof.literal_sql {
                let event = oraclemcp_guard::ddl_closure::ddl_event_for_statement(sql)
                    .map_err(package_unknown)?
                    .ok_or_else(|| package_unknown("literal DDL event is unavailable"))?;
                let (owner, name, object_type) = super::impact::dependency_target_prefix(sql)
                    .ok_or_else(|| package_unknown("literal DDL target is unavailable"))?;
                if owner.as_deref().is_some_and(|owner| owner != routine.owner) {
                    return Err(package_unknown(
                        "DDL target schema differs from the proven trigger context",
                    ));
                }
                let closure = crate::ddl_closure::collect_ddl_effect_closure(
                    cx,
                    conn,
                    event,
                    oraclemcp_guard::ddl_closure::DdlObject {
                        owner: owner.unwrap_or_else(|| routine.owner.clone()),
                        name,
                        object_type,
                    },
                    &database.container,
                )
                .await;
                closure.admit().map_err(package_unknown)?;
                for trigger in &closure.triggers {
                    effects = effects.union(&trigger.effects);
                }
                ddl_closures.push(decode_package_digest(&closure.fingerprint())?);
                callback_digests.push(closure.fingerprint());
                let compile = super::compile_parse_closure::prepare_compile_for_schema(
                    cx,
                    conn,
                    sql,
                    Some(&routine.owner),
                    strict_security,
                )
                .await?;
                if let Some(compile) = compile {
                    compile_observation |= compile.closures.iter().any(compile_has_observations);
                    callback_digests.push(hex_bytes(&compile.digest()));
                } else {
                    // CTAS and other non-unit DDL can still hard-parse SQL
                    // with policy/optimizer callbacks. Use the same complete
                    // static-SQL projection and callback collector.
                    let compile =
                        super::compile_parse_closure::collect_compile_parse_effect_closure(
                            cx,
                            conn,
                            sql,
                            &routine.owner,
                            strict_security,
                        )
                        .await?;
                    compile_observation |= compile_has_observations(&compile);
                    callback_digests.push(hex_bytes(&compile.digest()));
                    // Statements outside the compile family still need a
                    // complete SQL expression projection. Any callback remains
                    // unknown rather than being hidden inside literal DDL.
                    let calls = oraclemcp_guard::classifier::hard_parse_sql_routine_calls(sql)
                        .map_err(package_unknown)?;
                    if !calls.is_empty() {
                        return Err(package_unknown(
                            "literal DDL contains an unproven runtime callback",
                        ));
                    }
                }
            }
        }
        if !proof
            .proof
            .effects
            .iter()
            .any(|effect| effect == oraclemcp_guard::RoutineEffect::Ddl)
        {
            for sql in &proof.literal_sql {
                oraclemcp_guard::semantic_read_plan_checked(sql).map_err(package_unknown)?;
                // Parse-only carrier for the existing SQL/callback collector;
                // no synthetic view or candidate SQL is executed.
                let carrier = format!(
                    "CREATE VIEW \"{}\".\"OMCP_LITERAL_PROOF\" AS {sql}",
                    routine.owner
                );
                let compile = super::compile_parse_closure::collect_compile_parse_effect_closure(
                    cx,
                    conn,
                    &carrier,
                    &routine.owner,
                    strict_security,
                )
                .await?;
                compile_observation |= compile_has_observations(&compile);
                callback_digests.push(hex_bytes(&compile.digest()));
            }
        }
        let signature: Vec<_> = rows
            .iter()
            .map(|row| {
                [
                    "SUBPROGRAM_ID",
                    "OVERLOAD",
                    "POSITION",
                    "DATA_LEVEL",
                    "ARGUMENT_NAME",
                    "IN_OUT",
                    "DATA_TYPE",
                    "DEFAULTED",
                ]
                .map(|column| row.text(column).map(str::to_owned))
            })
            .collect();
        let required_level = required_level.max(
            oraclemcp_guard::admit(&effects, oraclemcp_guard::AdmissionContext::CustomToolCall)
                .map_err(package_unknown)?,
        );
        // Source Admin effects refuse; DML callbacks at DDL or above refuse;
        // DDL triggers admit only ReadDb/SessionState. Implicit additions cannot
        // currently exceed a passing source's ceiling. Retain this final check
        // for future effect-port expansion.
        if required_level > max_level {
            return Err(package_unknown(
                "implicit effects exceed the profile ceiling",
            ));
        }
        let facts_digest = package_digest(&(
            "custom-package-activation/v1",
            &proof.fact_key,
            signature,
            &context.connected_schema,
            &context.current_schema,
            &context.edition,
            &context.enabled_roles,
            &callback_digests,
        ));
        Ok(PackageCallPlan {
            approval_action: oraclemcp_core::tools::ApprovalAction::CustomToolCall,
            signed: signed.clone(),
            wrapper,
            required_level,
            effects,
            literal_sql: proof.literal_sql,
            facts_digest,
            callback_digests,
            ddl_closures,
            compile_observation,
        })
    }
}

#[cfg(feature = "plsql-intelligence")]
fn compile_has_observations(closure: &oraclemcp_db::CompileParseEffectClosureV1) -> bool {
    !closure.is_complete()
        || closure
            .statements
            .iter()
            .any(|statement| !statement.unresolved_local_names.is_empty())
}

fn attach_package_observation(value: &mut Value, plan: &PackageCallPlan) {
    if plan.compile_observation {
        value["compile_parse_observations"] = json!({"status":"admitted_with_observation","reason":"optional security evidence is unavailable or local compile references are unresolved"});
    }
}

struct PackageCallArgs {
    inputs: Vec<OracleBind>,
    wire: Vec<oraclemcp_db::OracleRoutineArg>,
    commit: bool,
    confirm: Option<String>,
}

fn package_call_args(
    plan: &PackageCallPlan,
    args: &Value,
) -> Result<PackageCallArgs, ErrorEnvelope> {
    use oraclemcp_core::PackageOracleType as Ty;
    use oraclemcp_db::OracleRoutineArg;
    let def = plan.signed.definition();
    let mut object = args
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_args("package arguments must be an object"))?;
    if object.contains_key("scoped_grant") {
        return Err(write_auth_error(
            WriteAuthRefusal::GrantEnforcementUnavailable,
        ));
    }
    let commit = consume_custom_tool_control_bool(&mut object, &def.name, &["commit"])?;
    let confirm = consume_custom_tool_control_string(
        &mut object,
        &def.name,
        &["confirm", "token", "confirmation_token"],
    )?;
    if confirm
        .as_deref()
        .is_some_and(|token| token.starts_with("sgr1."))
    {
        return Err(write_auth_error(
            WriteAuthRefusal::GrantEnforcementUnavailable,
        ));
    }
    let values: HashMap<_, _> = bind_params(def, &Value::Object(object))?
        .into_iter()
        .collect();
    let mut inputs = Vec::new();
    let mut wire = Vec::new();
    for slot in &plan.wrapper.bindings {
        if slot.direction == PackageArgDirection::In {
            let value = values
                .get(&slot.bind_name)
                .cloned()
                .ok_or_else(|| invalid_args("package input bind is missing"))?;
            if let OracleBind::String(value) = &value {
                let byte_length = if slot.oracle_type == Ty::Raw {
                    value.len() / 2
                } else {
                    value.len()
                };
                if byte_length > slot.max_bytes as usize {
                    return Err(invalid_args(format!(
                        "package argument {} exceeds its signed byte limit",
                        slot.bind_name
                    )));
                }
                if slot.oracle_type == Ty::Raw
                    && (value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()))
                {
                    return Err(invalid_args(
                        "RAW package input must be an even-length hexadecimal string",
                    ));
                }
            }
            wire.push(OracleRoutineArg::input(value.clone()).map_err(DbError::into_envelope)?);
            inputs.push(value);
        } else {
            let (kind, charset, bytes) = match slot.oracle_type {
                Ty::Number => (2, 1, 22),
                Ty::Varchar2 => (1, 1, slot.max_bytes),
                Ty::Nvarchar2 => (1, 2, slot.max_bytes),
                Ty::Boolean => (252, 1, 1),
                Ty::BinaryFloat => (100, 1, 4),
                Ty::BinaryDouble => (101, 1, 8),
                Ty::Date => (12, 1, 7),
                Ty::Timestamp => (180, 1, 11),
                Ty::Raw => (23, 1, slot.max_bytes),
                Ty::RefCursor => {
                    return Err(package_unavailable("REF_CURSOR requires pvlqq.10.15"));
                }
            };
            wire.push(OracleRoutineArg::output(kind, charset, bytes));
        }
    }
    Ok(PackageCallArgs {
        inputs,
        wire,
        commit,
        confirm,
    })
}

fn package_result(
    plan: &PackageCallPlan,
    result: &oraclemcp_db::ExecuteOutcome,
) -> Result<Value, ErrorEnvelope> {
    let slots: Vec<_> = plan
        .wrapper
        .bindings
        .iter()
        .filter(|slot| slot.direction != PackageArgDirection::In)
        .collect();
    if slots.len() != result.out_binds().len() {
        return Err(package_unavailable(
            "native package output does not match the signed scalar slots",
        ));
    }
    let mut row = serde_json::Map::new();
    for (slot, cell) in slots.iter().zip(result.out_binds()) {
        let bytes = cell.bytes.as_ref().map_or_else(
            || {
                cell.value.as_ref().map_or(0, |value| {
                    if slot.oracle_type == oraclemcp_core::PackageOracleType::Raw {
                        value.len() / 2
                    } else {
                        value.len()
                    }
                })
            },
            Vec::len,
        );
        if bytes > slot.max_bytes as usize
            || cell.source_length.is_some_and(|length| {
                length > cell.value.as_ref().map_or(0, |value| value.chars().count())
            })
        {
            return Err(package_unavailable(
                "native package output exceeds its signed byte limit or is truncated",
            ));
        }
        row.insert(
            slot.bind_name.clone(),
            oraclemcp_db::serialize_cell(cell, &SerializeOptions::default()),
        );
    }
    match plan.signed.definition().output_mode {
        oraclemcp_core::OutputMode::Rows => {
            let rows = if row.is_empty() {
                Vec::new()
            } else {
                vec![Value::Object(row)]
            };
            Ok(json!({"rows":rows}))
        }
        oraclemcp_core::OutputMode::Scalar if row.len() == 1 => {
            Ok(json!({"value": row.into_values().next().expect("one scalar")}))
        }
        _ => Err(package_unavailable(
            "scalar output requires exactly one signed output slot",
        )),
    }
}

fn package_approval(
    plan: &PackageCallPlan,
    args: &PackageCallArgs,
    generations: ImpactGenerations,
    masked: bool,
) -> Result<
    (
        oraclemcp_guard::ImpactBindingV1,
        oraclemcp_guard::GrantMaterial,
    ),
    ErrorEnvelope,
> {
    use oraclemcp_guard::impact_binding::DecisiveField;
    let def = plan.signed.definition();
    let envelope = action_envelope_material(ActionEnvelopeInput {
        sql: &plan.wrapper.sql,
        binds: &args.inputs,
        kind: plan.approval_action.resolve(plan.required_level, 0),
        commit: args.commit,
        hold: false,
        capture_dbms_output: false,
        max_lines: None,
        max_chars: None,
        timeout_seconds: None,
        scoped_grant: None,
    });
    let envelope = format!(
        "{envelope}:package-definition:{}",
        hex_bytes(&package_digest(&(&def.name, &def.signature)))
    );
    let mut binding = local_impact(&envelope, generations);
    binding.decisive.statement_digest = FieldStatus::Computed {
        value: ActionEnvelopeV1::statement_digest(&plan.wrapper.sql),
    };
    let bind_views: Vec<_> = args.inputs.iter().map(canonical_bind_view).collect();
    binding.decisive.bind_hmac = FieldStatus::Computed {
        value: BindEnvelope::from_binds(&ACTION_BIND_HMAC_KEY, &bind_views).value_hmac,
    };
    for (field, value) in [
        (
            DecisiveField::ClosureFactKey,
            package_digest(&(&plan.facts_digest, &plan.callback_digests)),
        ),
        (DecisiveField::RoutineEffects, package_digest(&plan.effects)),
        (
            DecisiveField::MaskingProfileOutput,
            package_digest(&(masked, &def.signature)),
        ),
    ] {
        binding
            .decisive
            .action_fields
            .insert(field, FieldStatus::Computed { value });
    }
    if plan
        .effects
        .iter()
        .any(|effect| effect == oraclemcp_guard::RoutineEffect::Ddl)
    {
        let value = match plan.ddl_closures.as_slice() {
            [] => return Err(package_unknown("DDL closure commitment is missing")),
            [value] => *value,
            values => {
                let mut hash = Sha256::new();
                hash.update(b"omcp/custom-package/ddl-closures/v1\0");
                hash.update((values.len() as u64).to_be_bytes());
                for value in values {
                    hash.update((value.len() as u64).to_be_bytes());
                    hash.update(value);
                }
                hash.finalize().into()
            }
        };
        binding.decisive.action_fields.insert(
            DecisiveField::DdlEffectClosure,
            FieldStatus::Computed { value },
        );
    }
    let material = oraclemcp_guard::GrantMaterial::new(&envelope, &binding)
        .map_err(|_| package_unknown("impact binding version is unsupported"))?;
    Ok((binding, material))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(any(feature = "plsql-intelligence", test))]
fn decode_package_digest(value: &str) -> Result<[u8; 32], ErrorEnvelope> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(package_unknown("producer fingerprint is invalid"));
    }
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| package_unknown("producer fingerprint is invalid"))?;
    }
    Ok(output)
}

impl OracleDispatcher {
    pub(super) async fn execute_package_call(
        &self,
        ctx: DbToolCtx<'_>,
        plan: &PackageCallPlan,
        args: &Value,
        profile: Option<&ProfileGenerationLease>,
    ) -> Result<Value, ErrorEnvelope> {
        let parsed = package_call_args(plan, args)?;
        if let Some(profile) = profile
            && profile.is_draining()
        {
            return Err(profile_draining_error(profile.profile()));
        }
        if !matches!(
            ctx.session.evaluate(Some(plan.required_level)),
            LevelDecision::Allow
        ) {
            return Err(write_not_started(session_level_gate_error(
                ctx.session,
                plan.required_level,
            )));
        }
        if ctx.sql_policy.is_some() {
            return Err(ErrorEnvelope::new(
                ErrorClass::PolicyDenied,
                "custom routine SQL policy narrowing is unavailable; the package is not executed",
            )
            .with_statement_outcome(StatementOutcome::NotStarted));
        }
        let ddl = plan
            .effects
            .iter()
            .any(|effect| effect == oraclemcp_guard::RoutineEffect::Ddl);
        let isolated = ddl
            || plan.effects.iter().any(|effect| {
                matches!(
                    effect,
                    oraclemcp_guard::RoutineEffect::SessionState
                        | oraclemcp_guard::RoutineEffect::Admin
                )
            });
        if profile.is_some_and(ProfileGenerationLease::edition_change_requests_enabled)
            && plan
                .literal_sql
                .iter()
                .any(|sql| oraclemcp_guard::requires_change_request(sql, true))
        {
            return Err(ErrorEnvelope::new(
                ErrorClass::ForbiddenStatement,
                "editionable package DDL requires oracle_change_request on this profile",
            )
            .with_structured_reason(StructuredReason::new(ReasonCategory::UseChangeRequest))
            .with_statement_outcome(StatementOutcome::NotStarted));
        }
        let write = plan.required_level > OperatingLevel::ReadOnly;
        if ddl && !parsed.commit {
            return Err(invalid_args(
                "package DDL is irreversible and requires commit=true for both preview and apply",
            )
            .with_statement_outcome(StatementOutcome::NotStarted));
        }
        if write && ctx.audit.auditor.is_none() {
            return Err(package_unavailable(
                "write-capable package calls require the durable audit sink",
            ));
        }
        if write {
            ensure_workspace_closed(ctx.checkpoints, "package call transaction boundary")?;
        }
        let masked = self
            .result_masking
            .lock()
            .map_err(|_| package_unavailable("masking state is unavailable"))?
            .is_some();
        let strict = ctx.profile_classifier.requires_security_feature_evidence();
        let fresh = Box::pin(collect_package_plan(
            ctx.cx,
            ctx.conn,
            &plan.signed,
            ctx.session.max_level(),
            masked,
            strict,
        ))
        .await?;
        if fresh.facts_digest != plan.facts_digest {
            return Err(repreview_required());
        }
        let (binding, mut material) =
            package_approval(&fresh, &parsed, ctx.impact_generations, masked)?;
        let approval = DecisiveApproval::check(
            &material,
            &binding,
            &fresh.approval_action.resolve(fresh.required_level, 0),
            DecisiveMatrixContext {
                dml_rows_supported: false,
                has_ddl_event: ddl,
                ..Default::default()
            },
        )?;
        if write && parsed.confirm.is_none() {
            let token = issue_confirmation_grant(
                ctx.execute_grants,
                ctx.grant_binding,
                ctx.active_profile,
                &approval,
                fresh.required_level,
            );
            let mut preview = json!({"status":"confirmation_required", "tool":plan.signed.definition().name,
                "required_level":fresh.required_level.as_str(), "confirmation_token":token,
                "commit":parsed.commit, "irreversible":ddl, "impact":{"binding":binding}});
            attach_package_observation(&mut preview, &fresh);
            return Ok(preview);
        }
        let confirmation = if write {
            let consumed=consume_confirmation_grant(ConfirmationGrantRequest {
                approval:&approval, required_level:fresh.required_level, active_profile:ctx.active_profile,
                grants:ctx.execute_grants, binding:ctx.grant_binding, confirm:parsed.confirm.as_deref(),
                challenge_message:"package call needs the exact preview confirmation", suggested_tool:&plan.signed.definition().name,
                next_step:"preview this package call again, then submit its single-use confirmation token",
            }).map_err(write_not_started)?;
            material = consumed.material;
            Some(consumed.confirmation)
        } else {
            None
        };
        if isolated {
            let connector = self.connector.as_ref().ok_or_else(|| {
                package_unavailable("literal package DDL requires a fresh-connection factory")
            })?;
            let profile = profile.ok_or_else(|| {
                package_unavailable("literal package DDL requires an active profile generation")
            })?;
            if profile.is_draining() {
                return Err(profile_draining_error(profile.profile()));
            }
            let (connection, stateless) = connector(ctx.cx, profile)
                .await
                .map_err(DbError::into_envelope)?
                .into_parts();
            // Keep the one-shot connection/proof/call state off the dispatch
            // poll stack, including while the native connector is polled.
            let result = Box::pin(async {
                let limits = ConnectionLimitGuard::install(
                    ctx.cx,
                    connection.as_ref(),
                    None,
                    None,
                    ctx.request_budget.deadline(),
                    Some(ctx.request_budget.db_quota()),
                )
                .map_err(DbError::into_envelope)?;
                let primary = describe_conn(ctx.cx, ctx.conn)
                    .await
                    .map_err(DbError::into_envelope)?;
                let isolated = describe_conn(ctx.cx, connection.as_ref())
                    .await
                    .map_err(DbError::into_envelope)?;
                match (
                    &primary.sid,
                    &primary.serial_number,
                    &isolated.sid,
                    &isolated.serial_number,
                ) {
                    (Some(a), Some(b), Some(c), Some(d))
                        if !a.is_empty()
                            && !b.is_empty()
                            && !c.is_empty()
                            && !d.is_empty()
                            && (a, b) != (c, d) => {}
                    _ => return Err(package_unknown("fresh DDL session identity is unproven")),
                }
                // Discard any prior pool transaction before the one-shot call;
                // the dispatch workspace is never transplanted onto this wire.
                rollback_conn_cleanup(ctx.cx, connection.as_ref())
                    .await
                    .map_err(DbError::into_envelope)?;
                let checked = Box::pin(collect_package_plan(
                    ctx.cx,
                    connection.as_ref(),
                    &plan.signed,
                    ctx.session.max_level(),
                    masked,
                    strict,
                ))
                .await?;
                if checked.facts_digest != fresh.facts_digest {
                    return Err(repreview_required());
                }
                if profile.is_draining() {
                    return Err(profile_draining_error(profile.profile()));
                }
                let outcome = Box::pin(run_package_wire(
                    &ctx,
                    connection.as_ref(),
                    &checked,
                    &parsed,
                    &material,
                    confirmation.as_deref(),
                    ddl,
                ))
                .await;
                let restored = limits.restore().map_err(DbError::into_envelope);
                match (outcome, restored) {
                    (Err(error), _) => Err(error),
                    (Ok(_), Err(error)) => {
                        Err(error.with_statement_outcome(if ddl || parsed.commit {
                            StatementOutcome::Committed
                        } else {
                            StatementOutcome::RolledBack
                        }))
                    }
                    (Ok(value), Ok(())) => Ok(value),
                }
            })
            .await;
            let close = close_conn_cleanup(ctx.cx, connection.as_ref()).await;
            let other_close = match stateless {
                Some(stateless) => close_conn_cleanup(ctx.cx, stateless.as_ref()).await,
                None => Ok(()),
            };
            let close = close.and(other_close);
            match (result, close) {
                (Err(error), _) => Err(error),
                (Ok(_), Err(error)) => {
                    Err(error
                        .into_envelope()
                        .with_statement_outcome(if ddl || parsed.commit {
                            StatementOutcome::Committed
                        } else {
                            StatementOutcome::RolledBack
                        }))
                }
                (Ok(mut value), Ok(())) => {
                    value["session_discarded"] = json!(true);
                    Ok(value)
                }
            }
        } else {
            if write {
                clear_read_only_transaction_before_write(&ctx).await?;
            }
            // A consumed token is never enough on its own: reread the complete
            // producer after token consumption and before candidate execution.
            let checked = Box::pin(collect_package_plan(
                ctx.cx,
                ctx.conn,
                &plan.signed,
                ctx.session.max_level(),
                masked,
                strict,
            ))
            .await?;
            if checked.facts_digest != fresh.facts_digest {
                return Err(repreview_required());
            }
            if let Some(profile) = profile
                && profile.is_draining()
            {
                return Err(profile_draining_error(profile.profile()));
            }
            Box::pin(run_package_wire(
                &ctx,
                ctx.conn,
                &checked,
                &parsed,
                &material,
                confirmation.as_deref(),
                false,
            ))
            .await
        }
    }
}

async fn run_package_wire(
    ctx: &DbToolCtx<'_>,
    conn: &dyn OracleConnection,
    plan: &PackageCallPlan,
    args: &PackageCallArgs,
    material: &oraclemcp_guard::GrantMaterial,
    confirmation: Option<&str>,
    ddl: bool,
) -> Result<Value, ErrorEnvelope> {
    let tool = &plan.signed.definition().name;
    let sql = &plan.wrapper.sql;
    let write = plan.required_level > OperatingLevel::ReadOnly;
    let danger = if ddl {
        "DESTRUCTIVE"
    } else if write {
        "GUARDED"
    } else {
        "SAFE"
    };
    let evidence = collect_effect_audit_db_evidence_bounded(
        ctx.cx,
        ctx.audit.auditor,
        conn,
        &ctx.request_budget,
        ctx.quarantine,
    )
    .await?;
    let impact = oraclemcp_audit::AuditImpactBinding {
        statement_digest: format!(
            "sha256:{}",
            hex_bytes(&ActionEnvelopeV1::statement_digest(sql))
        ),
        decisive_digest: format!("sha256:{}", hex_bytes(&material.decisive_digest)),
        revalidated_at: oraclemcp_audit::AuditRevalidationStage::BeforeExecute,
    };
    let entry = AuditEntryCtx {
        auditor: ctx.audit.auditor,
        subject: ctx.audit.subject,
        db_evidence: evidence.as_ref(),
        impact: Some(&impact),
    };
    let intent = match confirmation {
        Some(key) => append_write_intent(ctx, tool, sql, plan.required_level, key)?,
        None => None,
    };
    if let Err(error) = append_audit(entry, tool, sql, danger, None, AuditOutcome::Pending) {
        resolve_write_intent(
            ctx,
            intent.as_deref(),
            WriteIntentOutcome::AbortedBeforeExecute,
        )?;
        return Err(write_not_started(error));
    }
    let preflight = ctx
        .request_budget
        .enforce(ctx.cx)
        .map_err(DbError::into_envelope)
        .and_then(|()| {
            if matches!(
                ctx.session.evaluate(Some(plan.required_level)),
                LevelDecision::Allow
            ) {
                Ok(())
            } else {
                Err(session_level_gate_error(ctx.session, plan.required_level))
            }
        });
    if let Err(error) = preflight {
        append_terminal_audit(ctx, entry, tool, sql, danger, None, AuditOutcome::Failed)?;
        resolve_write_intent(
            ctx,
            intent.as_deref(),
            WriteIntentOutcome::AbortedBeforeExecute,
        )?;
        return Err(write_not_started(error));
    }
    let executed = conn.call_routine(ctx.cx, sql, &args.wire).await;
    let mut output = None;
    let (outcome, terminal, failure) = match executed {
        Ok(result) => {
            output = Some(package_result(plan, &result));
            if ddl {
                (
                    AuditOutcome::Succeeded,
                    Some(WriteIntentOutcome::Succeeded),
                    None,
                )
            } else if write && args.commit {
                match commit_conn(ctx.cx, conn).await {
                    Ok(()) => (
                        AuditOutcome::Succeeded,
                        Some(WriteIntentOutcome::Succeeded),
                        None,
                    ),
                    Err(error) => (
                        AuditOutcome::CommitInDoubt,
                        None,
                        Some(
                            error
                                .into_envelope()
                                .with_statement_outcome(StatementOutcome::CommitUnknown),
                        ),
                    ),
                }
            } else if write {
                match rollback_conn_cleanup(ctx.cx, conn).await {
                    Ok(()) => (
                        AuditOutcome::RolledBack,
                        Some(WriteIntentOutcome::RolledBack),
                        None,
                    ),
                    Err(error) => (
                        AuditOutcome::UnknownDiscarded,
                        None,
                        Some(
                            error
                                .into_envelope()
                                .with_statement_outcome(StatementOutcome::ProtocolUnsynchronized),
                        ),
                    ),
                }
            } else {
                (AuditOutcome::Succeeded, None, None)
            }
        }
        Err(error) => {
            let rollback = rollback_conn_cleanup(ctx.cx, conn).await;
            if ddl || rollback.is_err() || error.is_uncertain_session_state() {
                (
                    AuditOutcome::UnknownDiscarded,
                    None,
                    Some(error.into_envelope().with_statement_outcome(if ddl {
                        StatementOutcome::DdlOutcomeUnknown
                    } else {
                        StatementOutcome::ProtocolUnsynchronized
                    })),
                )
            } else {
                (
                    AuditOutcome::RolledBack,
                    Some(WriteIntentOutcome::RolledBack),
                    Some(
                        error
                            .into_envelope()
                            .with_statement_outcome(StatementOutcome::RolledBack),
                    ),
                )
            }
        }
    };
    if write && !ddl {
        ctx.checkpoints.clear();
    }
    if matches!(
        outcome,
        AuditOutcome::CommitInDoubt | AuditOutcome::UnknownDiscarded
    ) {
        mark_connection_quarantined(
            ctx.quarantine,
            outcome,
            "package call crossed an uncertain execution boundary",
        )?;
    }
    append_terminal_audit(ctx, entry, tool, sql, danger, None, outcome)?;
    if let Some(terminal) = terminal {
        resolve_write_intent_after_db(
            ctx,
            intent.as_deref(),
            terminal,
            outcome,
            "native package call completed",
        )?;
    }
    if let Some(error) = failure {
        return Err(error);
    }
    let mut value = output
        .expect("successful call has outputs")
        .map_err(|error| {
            error.with_statement_outcome(if ddl || (write && args.commit) {
                StatementOutcome::Committed
            } else if write {
                StatementOutcome::RolledBack
            } else {
                StatementOutcome::CompletedRead
            })
        })?;
    value["status"] = json!(audit_outcome_label(outcome));
    value["package_call"] = json!(true);
    value["executed"] = json!(true);
    value["committed"] = json!(ddl || (write && args.commit));
    value["non_transactional_effect"] = json!(ddl);
    value["required_level"] = json!(plan.required_level.as_str());
    value["irreversible"] = json!(ddl);
    attach_package_observation(&mut value, plan);
    Ok(value)
}

fn consume_custom_tool_control_string(
    args: &mut serde_json::Map<String, Value>,
    canonical: &str,
    keys: &[&str],
) -> Result<Option<String>, ErrorEnvelope> {
    let mut raw = None;
    for key in keys {
        if let Some(value) = args.remove(*key) {
            if raw.is_some() {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} and its aliases are mutually exclusive"
                )));
            }
            let Some(value) = value.as_str().map(str::to_owned) else {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} must be a string"
                )));
            };
            raw = Some(value);
        }
    }
    Ok(raw)
}

fn consume_custom_tool_control_bool(
    args: &mut serde_json::Map<String, Value>,
    canonical: &str,
    keys: &[&str],
) -> Result<bool, ErrorEnvelope> {
    let mut value = None;
    for key in keys {
        if let Some(raw) = args.remove(*key) {
            if value.is_some() {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} and its aliases are mutually exclusive"
                )));
            }
            let Some(raw) = raw.as_bool() else {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} must be true/false"
                )));
            };
            value = Some(raw);
        }
    }
    Ok(value.unwrap_or(false))
}

fn consume_custom_tool_control_usize(
    args: &mut serde_json::Map<String, Value>,
    canonical: &str,
    keys: &[&str],
) -> Result<Option<usize>, ErrorEnvelope> {
    let mut value = None;
    for key in keys {
        if let Some(raw) = args.remove(*key) {
            if value.is_some() {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} and its aliases are mutually exclusive"
                )));
            }
            let Some(raw) = raw.as_u64() else {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} must be a non-negative integer"
                )));
            };
            let converted = usize::try_from(raw).map_err(|_| {
                invalid_args(format!(
                    "invalid arguments for {canonical}: {key} exceeds supported range"
                ))
            })?;
            value = Some(converted);
        }
    }
    Ok(value)
}

fn consume_custom_tool_control_u64(
    args: &mut serde_json::Map<String, Value>,
    canonical: &str,
    keys: &[&str],
) -> Result<Option<u64>, ErrorEnvelope> {
    let mut value = None;
    for key in keys {
        if let Some(raw) = args.remove(*key) {
            if value.is_some() {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} and its aliases are mutually exclusive"
                )));
            }
            let Some(raw) = raw.as_u64() else {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} must be a non-negative integer"
                )));
            };
            value = Some(raw);
        }
    }
    Ok(value)
}

pub(super) fn ordered_custom_tool_binds(
    sql: &str,
    bind_values: Vec<(String, OracleBind)>,
) -> Result<Vec<Value>, ErrorEnvelope> {
    let mut values = HashMap::new();
    for (name, value) in bind_values {
        values.insert(name.to_ascii_uppercase(), value);
    }
    named_bind_placeholders(sql)
        .into_iter()
        .map(|name| {
            values.remove(&name).map(bind_to_json).ok_or_else(|| {
                invalid_args(format!("custom tool body references missing bind :{name}"))
            })
        })
        .collect()
}

fn bind_to_json(bind: OracleBind) -> Value {
    match bind {
        OracleBind::Null => Value::Null,
        OracleBind::String(v) => Value::String(v),
        OracleBind::I64(v) => Value::Number(v.into()),
        OracleBind::F64(v) => serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number),
        OracleBind::Bool(v) => Value::Bool(v),
        OracleBind::TimestampTz {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
            offset_minutes,
        } => json!({
            "year": year,
            "month": month,
            "day": day,
            "hour": hour,
            "minute": minute,
            "second": second,
            "nanosecond": nanosecond,
            "offset_minutes": offset_minutes
        }),
    }
}

pub(super) fn custom_tool_execute_args(
    canonical: &str,
    tool: &oraclemcp_core::LoadedTool,
    args: &Value,
) -> Result<ExecuteArgs, ErrorEnvelope> {
    let Some(args) = args.as_object() else {
        return Err(invalid_args(format!(
            "invalid arguments for {canonical}: expected an object"
        )));
    };
    let mut args = args.clone();

    let commit = consume_custom_tool_control_bool(&mut args, canonical, &["commit"])?;
    let hold = consume_custom_tool_control_bool(&mut args, canonical, &["hold"])?;
    let capture_dbms_output = consume_custom_tool_control_bool(
        &mut args,
        canonical,
        &["capture_dbms_output", "dbms_output"],
    )?;
    let dbms_output_max_lines =
        consume_custom_tool_control_usize(&mut args, canonical, &["max_dbms_output_lines"])?;
    let dbms_output_max_chars =
        consume_custom_tool_control_usize(&mut args, canonical, &["max_dbms_output_chars"])?;
    let timeout_seconds =
        consume_custom_tool_control_u64(&mut args, canonical, &["timeout_seconds"])?;
    let confirm = consume_custom_tool_control_string(
        &mut args,
        canonical,
        &["confirm", "token", "confirmation_token"],
    )?;
    let ToolBody::InlineSql(sql) = tool.def.body().map_err(|error| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("invalid tool body: {error}"),
        )
    })?;
    let binds = oraclemcp_core::bind_params(&tool.def, &Value::Object(args))?;
    let ordered_binds = ordered_custom_tool_binds(sql, binds)?;
    Ok(ExecuteArgs {
        sql: sql.to_owned(),
        binds: ordered_binds,
        commit,
        hold,
        confirm,
        scoped_grant: None,
        capture_dbms_output,
        dbms_output_max_lines,
        dbms_output_max_chars,
        timeout_seconds,
    })
}

#[cfg(test)]
#[path = "tests/custom_tool/tests.rs"]
mod tests;
