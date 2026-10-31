//! Immutable approval material and bounded decisive-fact revalidation.

use super::*;
use oraclemcp_guard::{GrantMaterial, ImpactBindingV1};

pub(super) fn execute_grant_token_fields(
    binding: &ExecGrantBinding,
    active_profile: Option<&str>,
    required_level: OperatingLevel,
    material: &GrantMaterial,
) -> Vec<String> {
    vec![
        active_profile.unwrap_or("").to_owned(),
        binding.session_id.clone(),
        binding.lane_id.clone(),
        binding.subject_id.clone(),
        binding.generation.to_string(),
        required_level.as_str().to_owned(),
        hex_digest(&material.sql_digest),
        hex_digest(&material.decisive_digest),
    ]
}

pub(super) fn sign_execute_grant_reference(
    raw_grant_id: &str,
    binding: &ExecGrantBinding,
    active_profile: Option<&str>,
    required_level: OperatingLevel,
    material: &GrantMaterial,
) -> String {
    let fields = execute_grant_token_fields(binding, active_profile, required_level, material);
    let refs = fields.iter().map(String::as_str).collect::<Vec<_>>();
    let payload = format!(
        "{raw_grant_id}~{}~{}",
        hex_digest(&material.sql_digest),
        hex_digest(&material.decisive_digest)
    );
    sign_token(EXECUTE_GRANT_TOKEN_SCOPE, &payload, &refs)
}

pub(super) struct VerifiedGrantReference {
    pub(super) raw_id: String,
    pub(super) material: GrantMaterial,
}

pub(super) fn verify_execute_grant_reference(
    token: &str,
    binding: &ExecGrantBinding,
    active_profile: Option<&str>,
    required_level: OperatingLevel,
) -> Option<VerifiedGrantReference> {
    let (payload, _) = token.rsplit_once('.')?;
    let (raw_and_sql, decisive) = payload.rsplit_once('~')?;
    let (raw, sql) = raw_and_sql.rsplit_once('~')?;
    let material = GrantMaterial {
        sql_digest: parse_digest(sql)?,
        decisive_digest: parse_digest(decisive)?,
    };
    let fields = execute_grant_token_fields(binding, active_profile, required_level, &material);
    let refs = fields.iter().map(String::as_str).collect::<Vec<_>>();
    verify_token(EXECUTE_GRANT_TOKEN_SCOPE, token, &refs)?;
    Some(VerifiedGrantReference {
        raw_id: raw.to_owned(),
        material,
    })
}

pub(super) fn issue_confirmation_grant(
    grants: &ExecGrantStore,
    binding: &ExecGrantBinding,
    active_profile: Option<&str>,
    material: &GrantMaterial,
    required_level: OperatingLevel,
) -> String {
    let raw = grants.issue(
        material.clone(),
        binding.clone(),
        required_level,
        Duration::from_secs(EXECUTE_APPROVED_TOKEN_TTL_SECONDS),
    );
    sign_execute_grant_reference(&raw, binding, active_profile, required_level, material)
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_digest(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

pub(super) struct ConfirmationGrantRequest<'a> {
    pub(super) material: &'a GrantMaterial,
    pub(super) required_level: OperatingLevel,
    pub(super) active_profile: Option<&'a str>,
    pub(super) grants: &'a ExecGrantStore,
    pub(super) binding: &'a ExecGrantBinding,
    pub(super) confirm: Option<&'a str>,
    pub(super) challenge_message: &'static str,
    pub(super) suggested_tool: &'a str,
    pub(super) next_step: &'static str,
}

pub(super) fn consume_confirmation_grant(
    request: ConfirmationGrantRequest<'_>,
) -> Result<String, ErrorEnvelope> {
    let Some(confirm) = request
        .confirm
        .and_then(|value| non_empty_arg(Some(value.to_owned())))
    else {
        return Err(
            ErrorEnvelope::new(ErrorClass::ChallengeRequired, request.challenge_message)
                .with_suggested_tool(request.suggested_tool)
                .with_next_step(request.next_step),
        );
    };
    let reference = verify_execute_grant_reference(
        &confirm,
        request.binding,
        request.active_profile,
        request.required_level,
    )
    .ok_or_else(|| {
        ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "confirmation grant is invalid for this statement, lane, principal, generation, or active profile",
        )
        .with_suggested_tool(request.suggested_tool)
        .with_next_step(request.next_step)
    })?;
    // Raw counters can alias across dispatcher stores in one broker process.
    // The authenticated material in the reference must also match this request;
    // checking the signature and the store independently would allow a token
    // from another store to authorize that store's different impact.
    if reference.material != *request.material {
        return Err(confirmation_grant_error(
            if reference.material.sql_digest != request.material.sql_digest {
                ExecGrantError::DigestMismatch
            } else {
                ExecGrantError::DecisiveMismatch
            },
            request.suggested_tool,
            request.next_step,
        ));
    }
    request
        .grants
        .consume(
            &reference.raw_id,
            request.material,
            request.binding,
            request.required_level,
        )
        // Separate dispatcher stores share a broker PID and restart their
        // counters. The verified reference also binds the session/generation;
        // its stripped raw ID alone would alias in the shared durable ledger.
        .map(|_| confirm)
        .map_err(|e| confirmation_grant_error(e, request.suggested_tool, request.next_step))
}

pub(super) fn confirmation_grant_error(
    e: ExecGrantError,
    suggested_tool: &str,
    next_step: &'static str,
) -> ErrorEnvelope {
    match e {
        ExecGrantError::Unknown => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "confirmation grant is unknown or already used; preview again",
        )
        .with_suggested_tool(suggested_tool)
        .with_next_step(next_step),
        ExecGrantError::Expired => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "confirmation grant expired; preview again",
        )
        .with_suggested_tool(suggested_tool)
        .with_next_step(next_step),
        ExecGrantError::DigestMismatch | ExecGrantError::DecisiveMismatch => ErrorEnvelope::new(
            ErrorClass::RepreviewRequired,
            "REPREVIEW_REQUIRED: confirmation grant belongs to a different SQL or execution envelope, or decisive impact facts changed",
        )
        .with_suggested_tool(suggested_tool)
        .with_next_step(next_step),
        ExecGrantError::SessionMismatch => ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "confirmation grant belongs to a different MCP session",
        ),
        ExecGrantError::LaneMismatch => ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "confirmation grant belongs to a different dispatch lane",
        ),
        ExecGrantError::SubjectMismatch => ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "confirmation grant belongs to a different principal",
        ),
        ExecGrantError::GenerationMismatch { presented, granted } => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            format!(
                "confirmation grant was minted for generation {granted}, but current generation is {presented}"
            ),
        )
        .with_suggested_tool(suggested_tool)
        .with_next_step(next_step),
        ExecGrantError::LevelExceedsGrant { requested, granted } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "requested level {} exceeds the granted level {}",
                requested.as_str(),
                granted.as_str()
            ),
        ),
        _ => ErrorEnvelope::new(ErrorClass::ChallengeRequired, "confirmation grant rejected")
            .with_suggested_tool(suggested_tool)
            .with_next_step(next_step),
    }
}

use oraclemcp_db::{
    CatalogQueryId, DepCaps, DependencySourceHash, DependentObject, OracleRow,
    probe_dependents_transitive, run_catalog_query,
};
use oraclemcp_guard::{DbIdentity, DecisiveFacts, FieldStatus, ObjectFact, UnavailableReason};

/// Fact reads only: no optimizer, effect analysis, SAST or candidate execution.
/// Two context reads, one exact identity read, at most twelve dependency frontiers, one compiler read,
/// one trigger list and at most 64 trigger-source reads.
const MAX_REVALIDATION_QUERIES: usize = 81;
const MAX_TRIGGER_FACTS: usize = 64;

#[derive(Clone, Copy)]
pub(super) struct ImpactGenerations {
    pub(super) profile: u64,
    pub(super) lane: u64,
}

pub(super) fn impact_generations(
    state: &DispatcherState,
    context: DispatchContext<'_>,
) -> ImpactGenerations {
    ImpactGenerations {
        profile: state
            .profile_generation
            .as_ref()
            .map_or(state.grant_generation, |lease| lease.generation()),
        lane: context.lane_generation().unwrap_or(state.grant_generation),
    }
}

#[derive(Clone, Copy)]
pub(super) struct FactProbeContext<'a> {
    pub(super) cx: &'a Cx,
    pub(super) conn: &'a dyn OracleConnection,
    pub(super) binding: &'a ExecGrantBinding,
    pub(super) generations: ImpactGenerations,
    pub(super) policy: Option<&'a SqlPolicyConfig>,
    pub(super) policy_provider: Option<&'a SyncMutex<Option<SqlPolicyConfig>>>,
    pub(super) current_schema: Option<&'a str>,
    pub(super) scoped_grants: &'a ScopedGrantStore,
    pub(super) active_profile: Option<&'a str>,
    pub(super) is_preview: bool,
    pub(super) quarantine: &'a SyncMutex<Option<ConnectionQuarantine>>,
}

#[derive(Clone)]
struct DecisiveFactProbe {
    root: Option<DependentObject>,
    ddl: bool,
}

pub(super) struct BoundImpact {
    pub(super) binding: ImpactBindingV1,
    pub(super) material: GrantMaterial,
    probe: DecisiveFactProbe,
    pub(super) query_count: Option<usize>,
    scope_reference: Option<String>,
}

fn computed<T>(value: T) -> FieldStatus<T> {
    FieldStatus::Computed { value }
}

fn unknown<T>() -> FieldStatus<T> {
    FieldStatus::Unavailable {
        reason: UnavailableReason::CatalogUnavailable,
    }
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

fn digest_json(value: &impl serde::Serialize) -> [u8; 32] {
    digest_bytes(&serde_json::to_vec(value).expect("fact serialization is infallible"))
}

/// Local facts for an action that does not inspect Oracle (session elevation).
/// Database-dependent actions add their current catalog fingerprints below.
pub(super) fn local_impact(envelope: &str, generations: ImpactGenerations) -> ImpactBindingV1 {
    ImpactBindingV1 {
        decisive: DecisiveFacts {
            envelope_digest: computed(digest_bytes(envelope.as_bytes())),
            profile_generation: computed(generations.profile),
            lane_generation: computed(generations.lane),
            current_schema: unknown(),
            edition: unknown(),
            db_identity: unknown(),
            compiler_facts: unknown(),
            objects: unknown(),
            ..DecisiveFacts::default()
        },
        ..ImpactBindingV1::default()
    }
}

impl DecisiveFactProbe {
    fn query_bound(&self) -> usize {
        match self.root.as_ref() {
            None => 2,
            Some(root) if !self.ddl && root.object_type == "TABLE" => 4 + MAX_TRIGGER_FACTS,
            Some(_) => MAX_REVALIDATION_QUERIES,
        }
    }

    fn for_sql(sql: &str) -> Self {
        let ddl_target = impact::dependency_target_prefix(sql);
        let ddl =
            ddl_target.is_some() || sql.trim_start().to_ascii_uppercase().starts_with("ALTER ");
        let root = ddl_target
            .map(|(owner, name, object_type)| DependentObject {
                owner: owner.unwrap_or_default(),
                name,
                object_type,
            })
            .or_else(|| {
                let raw = impact::parse_single_local_dml_target(sql).ok()?;
                let names = raw
                    .parts
                    .into_iter()
                    .map(|part| match part.quoting {
                        oraclemcp_guard::QuoteSemantics::Quoted => part.text,
                        oraclemcp_guard::QuoteSemantics::Unquoted => part.text.to_ascii_uppercase(),
                    })
                    .collect::<Vec<_>>();
                let (owner, name) = match names.as_slice() {
                    [name] => (String::new(), name.clone()),
                    [owner, name] => (owner.clone(), name.clone()),
                    _ => return None,
                };
                Some(DependentObject {
                    owner,
                    name,
                    object_type: "TABLE".into(),
                })
            })
            .or_else(|| {
                use sqlparser::ast::{Statement, TableObject};
                let statements = sqlparser::parser::Parser::parse_sql(
                    &sqlparser::dialect::OracleDialect {},
                    sql,
                )
                .ok()?;
                let [Statement::Insert(insert)] = statements.as_slice() else {
                    return None;
                };
                let TableObject::TableName(table) = &insert.table else {
                    return None;
                };
                let names = table
                    .0
                    .iter()
                    .map(|part| {
                        let name = part.as_ident()?;
                        Some(if name.quote_style.is_some() {
                            name.value.clone()
                        } else {
                            name.value.to_ascii_uppercase()
                        })
                    })
                    .collect::<Option<Vec<_>>>()?;
                let (owner, name) = match names.as_slice() {
                    [name] => (String::new(), name.clone()),
                    [owner, name] => (owner.clone(), name.clone()),
                    _ => return None,
                };
                Some(DependentObject {
                    owner,
                    name,
                    object_type: "TABLE".into(),
                })
            });
        Self { root, ddl }
    }

    async fn read(
        &self,
        context: FactProbeContext<'_>,
        id: CatalogQueryId,
        binds: &[OracleBind],
        queries: &mut usize,
    ) -> Result<Option<Vec<OracleRow>>, ErrorEnvelope> {
        if *queries >= self.query_bound() {
            return Err(repreview_required());
        }
        *queries += 1;
        match run_catalog_query(context.cx, context.conn, id, binds).await {
            Ok(rows) => Ok(Some(rows)),
            Err(error) if error.is_uncertain_session_state() => {
                impact::quarantine_dependency_observation(context.quarantine, &error);
                Err(error.into_envelope())
            }
            Err(_) => Ok(None),
        }
    }

    async fn collect(
        &self,
        context: FactProbeContext<'_>,
        decisive: &mut DecisiveFacts,
    ) -> Result<Option<usize>, ErrorEnvelope> {
        let mut queries = 0;
        let mut exact_count = true;
        if let Some(rows) = self
            .read(context, CatalogQueryId::SessionContext, &[], &mut queries)
            .await?
            && let [row] = rows.as_slice()
        {
            decisive.current_schema = row
                .text("current_schema")
                .map_or_else(unknown, |value| computed(value.to_owned()));
            decisive.edition = row
                .text("edition_name")
                .map_or_else(unknown, |value| computed(value.to_owned()));
        }
        if let Some(rows) = self
            .read(context, CatalogQueryId::PdbIdentity, &[], &mut queries)
            .await?
            && let [row] = rows.as_slice()
        {
            decisive.db_identity = match (
                row.text("dbid").and_then(|v| v.trim().parse().ok()),
                row.text("con_uid").and_then(|v| v.trim().parse().ok()),
            ) {
                (Some(dbid), Some(con_uid)) => computed(DbIdentity { dbid, con_uid }),
                _ => unknown(),
            };
        }
        let Some(mut root) = self.root.clone() else {
            decisive.objects = unknown();
            return Ok(Some(queries));
        };
        if root.owner.is_empty() {
            let FieldStatus::Computed { value: schema } = &decisive.current_schema else {
                decisive.objects = unknown();
                return Ok(Some(queries));
            };
            root.owner.clone_from(schema);
        }
        let object_binds = [
            OracleBind::String(root.owner.clone()),
            OracleBind::String(root.name.clone()),
            OracleBind::String(root.object_type.clone()),
            OracleBind::I64(2),
        ];
        let metadata = self
            .read(
                context,
                CatalogQueryId::ClosureMemberObject,
                &object_binds,
                &mut queries,
            )
            .await?;
        // Row changes cannot invalidate stored dependent code. Bind the exact
        // target metadata (including LAST_DDL_TIME), and still re-read all row
        // trigger facts below. A missing target also has no visible source to
        // traverse: its absence/unknown identity remains in the fingerprint.
        let needs_dependencies = (self.ddl || root.object_type != "TABLE")
            && metadata.as_ref().is_none_or(|rows| !rows.is_empty());
        let mut objects = Vec::new();
        if needs_dependencies {
            let closure = probe_dependents_transitive(
                context.cx,
                context.conn,
                std::slice::from_ref(&root),
                DepCaps::default(),
            )
            .await;
            match closure {
                Ok(closure) => {
                    queries += closure.query_count();
                    objects = dependency_object_facts(&closure);
                }
                Err(oraclemcp_db::DependentsError::Database(error))
                    if error.is_uncertain_session_state() =>
                {
                    impact::quarantine_dependency_observation(context.quarantine, &error);
                    return Err(error.into_envelope());
                }
                Err(_) => {
                    // The collector owns a hard max_depth + 2 bound even on an error.
                    queries += 12;
                    exact_count = false;
                }
            }
        } else {
            let row = metadata.as_ref().and_then(|rows| match rows.as_slice() {
                [row] => Some(row),
                _ => None,
            });
            objects.push(ObjectFact {
                identity: row
                    .and_then(|row| row.text("object_id"))
                    .and_then(|id| id.parse::<u64>().ok())
                    .filter(|id| *id > 0)
                    .map_or_else(unknown, |id| {
                        computed(
                            serde_json::to_string(&(
                                &root.owner,
                                &root.name,
                                &root.object_type,
                                id,
                            ))
                            .expect("object identity serialization"),
                        )
                    }),
                status: row
                    .and_then(|row| row.text("status"))
                    .map_or_else(unknown, |status| computed(status.to_owned())),
                source_hash: if root.object_type == "TABLE" && row.is_some() {
                    FieldStatus::NotApplicable {
                        reason: oraclemcp_guard::NotApplicableReason::NoSource,
                    }
                } else {
                    unknown()
                },
                dependency_hash: metadata
                    .as_ref()
                    .map_or_else(unknown, |rows| computed(digest_json(&(&root, rows)))),
                trigger_hash: unknown(),
            });
        }
        let has_compiler_settings = matches!(
            root.object_type.as_str(),
            "PROCEDURE"
                | "FUNCTION"
                | "PACKAGE"
                | "PACKAGE BODY"
                | "TRIGGER"
                | "TYPE"
                | "TYPE BODY"
        );
        decisive.compiler_facts = if needs_dependencies && has_compiler_settings {
            self.read(
                context,
                CatalogQueryId::ClosureCompilerSettings,
                &object_binds,
                &mut queries,
            )
            .await?
            .map_or_else(unknown, |rows| computed(hex_digest(&digest_json(&rows))))
        } else {
            FieldStatus::NotApplicable {
                reason: oraclemcp_guard::NotApplicableReason::NoSource,
            }
        };
        let (trigger_query, trigger_binds) = if self.ddl {
            (
                CatalogQueryId::DdlTriggers,
                vec![OracleBind::I64((MAX_TRIGGER_FACTS + 1) as i64)],
            )
        } else {
            (
                CatalogQueryId::ClosureTriggers,
                vec![
                    OracleBind::String(root.owner.clone()),
                    OracleBind::String(root.name.clone()),
                    OracleBind::I64((MAX_TRIGGER_FACTS + 1) as i64),
                ],
            )
        };
        let trigger_hash = match self
            .read(context, trigger_query, &trigger_binds, &mut queries)
            .await?
        {
            Some(rows) if rows.len() <= MAX_TRIGGER_FACTS => {
                let mut facts = vec![digest_json(&rows)];
                let mut complete = true;
                for row in &rows {
                    let (Some(owner), Some(name)) = (row.text("owner"), row.text("trigger_name"))
                    else {
                        complete = false;
                        continue;
                    };
                    let binds = [
                        OracleBind::String(owner.to_owned()),
                        OracleBind::String(name.to_owned()),
                        OracleBind::String("TRIGGER".into()),
                        OracleBind::I64(4097),
                    ];
                    let source_hash = match self
                        .read(context, CatalogQueryId::ClosureSource, &binds, &mut queries)
                        .await?
                    {
                        Some(source) if !source.is_empty() && source.len() <= 4096 => {
                            Some(digest_json(&source))
                        }
                        _ => {
                            complete = false;
                            None
                        }
                    };
                    facts.push(digest_json(&(owner, name, source_hash)));
                }
                if complete {
                    computed(digest_json(&facts))
                } else {
                    FieldStatus::Estimated {
                        value: digest_json(&facts),
                    }
                }
            }
            _ => unknown(),
        };
        for object in &mut objects {
            object.trigger_hash = trigger_hash.clone();
        }
        decisive.objects = if objects.is_empty() {
            unknown()
        } else {
            computed(objects)
        };
        Ok(exact_count.then_some(queries))
    }
}

fn dependency_object_facts(closure: &oraclemcp_db::DependentsClosure) -> Vec<ObjectFact> {
    let mut objects = Vec::new();
    let dependency_hash = if closure.truncated || !closure.uncertainties.is_empty() {
        FieldStatus::Estimated {
            value: closure.dependency_hash,
        }
    } else {
        computed(closure.dependency_hash)
    };
    for node in closure.roots.iter().chain(&closure.nodes) {
        let source_hash = match node.source_hash {
            DependencySourceHash::Computed { sha256 } => computed(sha256),
            DependencySourceHash::NotApplicable => FieldStatus::NotApplicable {
                reason: oraclemcp_guard::NotApplicableReason::NoSource,
            },
            DependencySourceHash::Unavailable { .. } => unknown(),
        };
        objects.push(ObjectFact {
            identity: node.object_id.map_or_else(unknown, |id| {
                computed(
                    serde_json::to_string(&(
                        &node.object.owner,
                        &node.object.name,
                        &node.object.object_type,
                        id,
                    ))
                    .expect("object identity serialization"),
                )
            }),
            status: node
                .status
                .as_ref()
                .map_or_else(unknown, |status| computed(status.clone())),
            source_hash,
            dependency_hash: dependency_hash.clone(),
            trigger_hash: unknown(),
        });
    }
    // Missing roots/gaps are bound as well, rather than being treated as an empty closure.
    if objects.is_empty() {
        objects.push(ObjectFact {
            identity: unknown(),
            status: unknown(),
            source_hash: unknown(),
            dependency_hash,
            trigger_hash: unknown(),
        });
    }
    objects
}

pub(super) fn repreview_required() -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::RepreviewRequired,
        "REPREVIEW_REQUIRED: decisive impact facts changed; preview again",
    )
    .with_statement_outcome(StatementOutcome::NotStarted)
}

impl BoundImpact {
    pub(super) fn unobserved(sql: &str, envelope: &str, generations: ImpactGenerations) -> Self {
        let mut binding = local_impact(envelope, generations);
        binding.decisive.statement_digest = computed(ActionEnvelopeV1::statement_digest(sql));
        binding.decisive.objects = FieldStatus::Unavailable {
            reason: UnavailableReason::LevelBelowRequired,
        };
        let material = GrantMaterial::new(sql, &binding).expect("current impact binding version");
        Self {
            binding,
            material,
            probe: DecisiveFactProbe {
                root: None,
                ddl: false,
            },
            query_count: Some(0),
            scope_reference: None,
        }
    }

    pub(super) async fn capture(
        context: FactProbeContext<'_>,
        sql: &str,
        envelope: &str,
        binds: &[OracleBind],
        admission: Option<&PolicyGateAdmission>,
        scope_reference: Option<&str>,
        compile_parse_digest: Option<[u8; 32]>,
    ) -> Result<Self, ErrorEnvelope> {
        let mut binding = local_impact(envelope, context.generations);
        binding.decisive.statement_digest = computed(ActionEnvelopeV1::statement_digest(sql));
        if let Some(digest) = compile_parse_digest {
            binding.decisive.compile_parse_closure_digest = computed(digest);
        }
        let views = binds.iter().map(canonical_bind_view).collect::<Vec<_>>();
        let bind_hmac = BindEnvelope::from_binds(&ACTION_BIND_HMAC_KEY, &views).value_hmac;
        binding.decisive.bind_hmac = computed(bind_hmac);
        let probe = DecisiveFactProbe::for_sql(sql);
        let query_count = match probe.collect(context, &mut binding.decisive).await {
            Ok(count) => count,
            Err(error)
                if context.is_preview && error.error_class != ErrorClass::RequestCancelled =>
            {
                let reason = UnavailableReason::from_error_class(error.error_class);
                binding.decisive.current_schema = FieldStatus::Unavailable { reason };
                binding.decisive.edition = FieldStatus::Unavailable { reason };
                binding.decisive.db_identity = FieldStatus::Unavailable { reason };
                binding.decisive.compiler_facts = FieldStatus::Unavailable { reason };
                binding.decisive.objects = FieldStatus::Unavailable { reason };
                None
            }
            Err(error) => return Err(error),
        };
        if query_count.is_some_and(|count| count > probe.query_bound()) {
            return Err(repreview_required());
        }
        if current_policy(context)? != context.policy.cloned() {
            return Err(repreview_required());
        }
        binding.decisive.policy_schema_digest = computed(digest_bytes(
            &context
                .policy
                .map_or(1, |policy| policy.version)
                .to_be_bytes(),
        ));
        binding.decisive.policy_ruleset_digest = computed(digest_json(&context.policy));
        binding.decisive.matched_policy_rule_ids = match admission {
            Some(admission) if context.policy.is_some() => computed(
                admission
                    .attachment
                    .as_ref()
                    .and_then(|value| value.pointer("/Narrow/matched_rule_ids"))
                    .and_then(|value| serde_json::from_value::<Vec<String>>(value.clone()).ok())
                    .ok_or_else(repreview_required)?,
            ),
            _ if context.policy.is_none() => computed(Vec::new()),
            _ => FieldStatus::not_wired(),
        };
        binding.decisive.rewrite_algorithm_version =
            computed(oraclemcp_guard::DML_REWRITE_ALGORITHM_VERSION);
        binding.decisive.scope_digest = computed(
            scope_reference
                .map(|reference| {
                    resolve_scoped_grant_reference(
                        context.scoped_grants,
                        context.binding,
                        context.active_profile,
                        reference,
                    )
                    .map(|grant| grant.scope_digest())
                    .map_err(write_auth_error)
                })
                .transpose()?,
        );
        #[cfg(feature = "plsql-intelligence")]
        {
            binding.decisive.engine_version = computed(crate::plsql_tools::ENGINE_VERSION.into());
            binding.decisive.ruleset_digest = computed(crate::plsql_tools::sast_ruleset_digest());
        }
        let material = GrantMaterial::new(sql, &binding).map_err(|_| repreview_required())?;
        Ok(Self {
            binding,
            material,
            probe,
            query_count,
            scope_reference: scope_reference.map(str::to_owned),
        })
    }

    pub(super) async fn revalidate(
        &self,
        context: FactProbeContext<'_>,
    ) -> Result<(), ErrorEnvelope> {
        let mut current = self.binding.clone();
        // Never retain catalog facts from the previous snapshot on a failed read.
        current.decisive.current_schema = unknown();
        current.decisive.edition = unknown();
        current.decisive.db_identity = unknown();
        current.decisive.compiler_facts = unknown();
        current.decisive.objects = unknown();
        self.probe.collect(context, &mut current.decisive).await?;
        current.decisive.scope_digest = computed(
            self.scope_reference
                .as_deref()
                .map(|reference| {
                    resolve_scoped_grant_reference(
                        context.scoped_grants,
                        context.binding,
                        context.active_profile,
                        reference,
                    )
                    .map(|grant| grant.scope_digest())
                    .map_err(|_| repreview_required())
                })
                .transpose()?,
        );
        let policy = current_policy(context)?;
        current.decisive.policy_schema_digest = computed(digest_bytes(
            &policy
                .as_ref()
                .map_or(1, |policy| policy.version)
                .to_be_bytes(),
        ));
        current.decisive.policy_ruleset_digest = computed(digest_json(&policy));
        current.decisive.profile_generation = computed(context.generations.profile);
        current.decisive.lane_generation = computed(context.generations.lane);
        if current
            .decisive_digest()
            .map_err(|_| repreview_required())?
            != self.material.decisive_digest
        {
            return Err(repreview_required());
        }
        Ok(())
    }

    pub(super) fn attach(&self, response: &mut Value) {
        debug_assert!(
            self.query_count
                .is_none_or(|count| count <= self.probe.query_bound())
        );
        let mut impact = response
            .get("impact")
            .and_then(|value| serde_json::from_value::<ImpactV1>(value.clone()).ok())
            .unwrap_or_default();
        impact.binding = self.binding.clone();
        response["impact"] = serde_json::to_value(impact).expect("impact serialization");
    }
}

impl<'a> DbToolCtx<'a> {
    pub(super) fn fact_probe(&self) -> FactProbeContext<'a> {
        FactProbeContext {
            cx: self.cx,
            conn: self.conn,
            binding: self.grant_binding,
            generations: self.impact_generations,
            policy: self.sql_policy,
            current_schema: self.current_schema,
            quarantine: self.quarantine,
            policy_provider: self.sql_policy_provider,
            scoped_grants: self.scoped_grants,
            active_profile: self.active_profile,
            is_preview: false,
        }
    }
}

fn current_policy(context: FactProbeContext<'_>) -> Result<Option<SqlPolicyConfig>, ErrorEnvelope> {
    match context.policy_provider {
        Some(provider) => provider
            .lock()
            .map(|policy| policy.clone())
            .map_err(|_| repreview_required()),
        None => Ok(context.policy.cloned()),
    }
}

impl BoundImpact {
    /// Final bounded fact checkpoint before the first candidate call.
    /// A failure resolves the write intent as not started, retaining the normal
    /// audit failure handling used by compile-closure revalidation.
    pub(super) async fn before_execute(
        &self,
        ctx: &DbToolCtx<'_>,
        entry: AuditEntryCtx<'_>,
        tool: &str,
        sql: &str,
        danger: &str,
        intent: Option<&str>,
    ) -> Result<(), ErrorEnvelope> {
        let check = self.revalidate(ctx.fact_probe()).await;
        if let Err(failure) = check {
            append_terminal_audit_with_failure(
                ctx,
                entry,
                tool,
                sql,
                danger,
                None,
                AuditOutcome::Failed,
                &failure,
            )?;
            resolve_write_intent_after_db(
                ctx,
                intent,
                WriteIntentOutcome::AbortedBeforeExecute,
                AuditOutcome::Failed,
                "impact facts changed before candidate execution",
            )?;
            return Err(write_not_started(failure));
        }
        Ok(())
    }

    pub(super) fn audit_binding(
        &self,
        stage: oraclemcp_audit::AuditRevalidationStage,
    ) -> Result<oraclemcp_audit::AuditImpactBinding, ErrorEnvelope> {
        let FieldStatus::Computed {
            value: statement_digest,
        } = self.binding.decisive.statement_digest
        else {
            return Err(repreview_required());
        };
        Ok(oraclemcp_audit::AuditImpactBinding {
            statement_digest: format!("sha256:{}", hex_digest(&statement_digest)),
            decisive_digest: format!("sha256:{}", hex_digest(&self.material.decisive_digest)),
            revalidated_at: stage,
        })
    }
}

#[cfg(test)]
#[path = "tests/impact_grants.rs"]
mod tests;
