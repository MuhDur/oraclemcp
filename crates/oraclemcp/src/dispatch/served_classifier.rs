//! Profile-bound routine proofs. Engine output, live source commitments and
//! the ordinary relation proof have independent authority; none replaces another.

use super::*;
#[cfg(feature = "plsql-intelligence")]
use oraclemcp_db::ClosureFacts;
use oraclemcp_db::{ClosureFactKey, RoutineClosure};
#[cfg(feature = "plsql-intelligence")]
use oraclemcp_guard::OperatorPureFunctionAllowlist;
use oraclemcp_guard::{ObjectRef, SideEffectOracle};

pub(super) struct ProfileClassifier {
    profile: Option<String>,
    generation: u64,
    drain: Option<ProfileDrainState>,
    #[cfg(feature = "plsql-intelligence")]
    restriction: Option<OperatorPureFunctionAllowlist>,
    /// `profiles.trusted_policy_functions`: VPD functions eligible for proof.
    #[cfg(feature = "plsql-intelligence")]
    trusted_policy_functions: Arc<[String]>,
    read_policy: RoutineReadPolicy,
    finding: SyncMutex<Option<&'static str>>,
}

impl Default for ProfileClassifier {
    fn default() -> Self {
        Self {
            profile: None,
            generation: 0,
            drain: None,
            #[cfg(feature = "plsql-intelligence")]
            restriction: None,
            #[cfg(feature = "plsql-intelligence")]
            trusted_policy_functions: Arc::from([]),
            read_policy: RoutineReadPolicy::default(),
            finding: SyncMutex::new(None),
        }
    }
}

impl ProfileClassifier {
    pub(super) fn set_read_policy(
        &mut self,
        fga: FgaEvidencePolicy,
        security: bool,
        trusted_views: Arc<[String]>,
    ) {
        #[cfg(feature = "plsql-intelligence")]
        {
            self.read_policy = RoutineReadPolicy {
                fga,
                security,
                trusted_views,
            };
        }
        #[cfg(not(feature = "plsql-intelligence"))]
        let _ = (fga, security, trusted_views);
    }
    pub(super) fn activate(
        profile: Option<String>,
        lease: Option<&ProfileGenerationLease>,
    ) -> Self {
        Self {
            #[cfg(feature = "plsql-intelligence")]
            trusted_policy_functions: lease
                .and_then(|lease| lease.config()?.profile(lease.profile()))
                .and_then(|profile| profile.trusted_policy_functions.clone())
                .unwrap_or_default()
                .into(),
            profile,
            generation: lease.map_or(0, ProfileGenerationLease::generation),
            drain: lease.map(|lease| lease.state.clone()),
            ..Self::default()
        }
    }

    /// The VPD policy-function prover for one read on this profile
    /// generation. None when the profile trusts no policy function: the list
    /// only makes a function eligible for the served engine proof.
    pub(super) fn policy_function_prover<'a>(
        &'a self,
        cache: &'a OracleCatalogResolverCache,
    ) -> Option<Box<dyn oraclemcp_db::PolicyFunctionProver + 'a>> {
        #[cfg(feature = "plsql-intelligence")]
        {
            if self.trusted_policy_functions.is_empty() {
                return None;
            }
            let _ = cache;
            Some(Box::new(engine::PolicyFunctionProof {
                trusted: &self.trusted_policy_functions,
            }))
        }
        #[cfg(not(feature = "plsql-intelligence"))]
        {
            let _ = cache;
            None
        }
    }

    pub(super) fn finding(&self) -> Option<&'static str> {
        self.finding.lock().ok().and_then(|finding| *finding)
    }

    pub(super) fn fallback_decision(&self, sql: &str) -> GuardDecision {
        PreparedClassifier::unknown(self.profile.clone(), self.generation)
            .classifier
            .classify(sql)
    }

    pub(super) async fn prepare(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
        cache: &OracleCatalogResolverCache,
        sql: &str,
    ) -> PreparedClassifier {
        let mut prepared = PreparedClassifier::unknown(self.profile.clone(), self.generation);
        prepared.drain = self.drain.clone();
        prepared.read_policy = self.read_policy.clone();
        if prepared.precheck.classify(sql).danger == DangerLevel::Forbidden {
            return prepared;
        }
        let calls = match sql_routine_calls(sql) {
            Ok(calls) if calls.len() <= 32 => calls,
            _ => return prepared,
        };
        if calls.is_empty() {
            return prepared;
        }
        #[cfg(feature = "plsql-intelligence")]
        match engine::prepare(cx, conn, cache, sql, &calls, &self.read_policy).await {
            Ok((oracle, closures)) => {
                if let Ok(mut finding) = self.finding.lock() {
                    *finding = None;
                }
                prepared.bindings = closures;
                prepared.oracle = match &self.restriction {
                    Some(restriction) => {
                        Arc::new(oraclemcp_guard::OperatorPureFunctionRestriction::new(
                            oracle,
                            restriction.clone(),
                        ))
                    }
                    None => oracle,
                };
                prepared.classifier = Classifier::new(
                    ClassifierConfig::new().with_unresolved_qualified_calls_guarded(),
                )
                .with_oracle(Arc::clone(&prepared.oracle));
                prepared.precheck = Classifier::engine_free_baseline(ClassifierConfig::new())
                    .with_oracle(Arc::clone(&prepared.oracle));
            }
            Err(reason) => {
                prepared.reason = Some(reason);
                if let Ok(mut finding) = self.finding.lock() {
                    *finding = Some(reason);
                }
                tracing::debug!(
                    profile = self.profile.as_deref().unwrap_or(""),
                    reason,
                    "engine classifier retained Unknown routine admission"
                );
            }
        }
        #[cfg(not(feature = "plsql-intelligence"))]
        {
            let _ = (cx, conn, cache, calls);
            prepared.reason = Some("engine_not_built");
            if let Ok(mut finding) = self.finding.lock() {
                *finding = Some("engine_not_built");
            }
        }
        prepared
    }
}

#[derive(Clone)]
#[cfg_attr(not(feature = "plsql-intelligence"), derive(Default))]
struct RoutineReadPolicy {
    #[cfg(feature = "plsql-intelligence")]
    fga: FgaEvidencePolicy,
    #[cfg(feature = "plsql-intelligence")]
    security: bool,
    #[cfg(feature = "plsql-intelligence")]
    trusted_views: Arc<[String]>,
}
#[cfg(feature = "plsql-intelligence")]
impl Default for RoutineReadPolicy {
    fn default() -> Self {
        Self {
            fga: FgaEvidencePolicy::AdmitUnavailable,
            security: false,
            trusted_views: Arc::from([]),
        }
    }
}

#[derive(Clone)]
pub(super) struct ClosureBinding {
    closure: RoutineClosure,
    key: ClosureFactKey,
    calls: Vec<CallResolution>,
}

#[derive(Clone)]
struct CallResolution {
    candidate: oraclemcp_guard::RoutineRef,
    arguments: Vec<oraclemcp_guard::RoutineArgument>,
}

pub(super) struct PreparedClassifier {
    pub(super) classifier: Classifier,
    pub(super) precheck: Classifier,
    pub(super) oracle: Arc<dyn SideEffectOracle>,
    profile: Option<String>,
    generation: u64,
    drain: Option<ProfileDrainState>,
    bindings: Vec<ClosureBinding>,
    read_policy: RoutineReadPolicy,
    /// Why the engine could not prove this statement's routine closures.
    reason: Option<&'static str>,
}

/// The served effect sets of the routines one statement calls.
pub(super) struct CallEffects {
    /// Each called routine with its effects; Unknown when its closure is unproven.
    pub(super) calls: Vec<(String, oraclemcp_guard::RoutineEffectsV1)>,
    pub(super) unknown_reasons: Vec<String>,
}

impl PreparedClassifier {
    /// The effects of every routine `sql` calls, exactly as this profile
    /// generation's served engine proved them; None when it calls none. A
    /// statement that cannot be parsed, or a CALL statement, may call anything
    /// and reports no proven call.
    pub(super) fn call_effects(&self, sql: &str) -> Option<CallEffects> {
        use sqlparser::ast::Statement;
        let unknown = |reason: &str| CallEffects {
            calls: Vec::new(),
            unknown_reasons: vec![reason.to_owned()],
        };
        let Ok(statements) =
            sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::OracleDialect {}, sql)
        else {
            return Some(unknown(
                "statement could not be parsed; its routine calls are unknown",
            ));
        };
        if statements
            .iter()
            .any(|statement| matches!(statement, Statement::Call(_)))
        {
            return Some(unknown("a CALL statement's routine closure is not proven"));
        }
        let Ok(found) = sql_routine_calls(sql) else {
            return Some(unknown("routine call shape could not be proven"));
        };
        if found.is_empty() {
            return None;
        }
        let mut calls = Vec::new();
        let mut unknown_reasons = Vec::new();
        for call in &found {
            let effects = self.oracle.routine_call_effects(call).unwrap_or_else(|| {
                oraclemcp_guard::RoutineEffectsV1::new([oraclemcp_guard::RoutineEffect::Unknown])
            });
            let routine = routine_call_key(call);
            if effects
                .iter()
                .any(|effect| effect == oraclemcp_guard::RoutineEffect::Unknown)
            {
                unknown_reasons.push(format!(
                    "{routine}: {}",
                    self.reason.unwrap_or("routine closure not proven")
                ));
            }
            calls.push((routine, effects));
        }
        Some(CallEffects {
            calls,
            unknown_reasons,
        })
    }

    pub(super) fn active_profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    pub(super) fn require_readonly_routine_closures(&self, sql: &str) -> Result<(), ErrorEnvelope> {
        let Ok(statements) =
            sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::OracleDialect {}, sql)
        else {
            return Ok(());
        };
        if !statements.iter().any(|statement| {
            matches!(
                statement,
                sqlparser::ast::Statement::Query(_)
                    | sqlparser::ast::Statement::Insert(_)
                    | sqlparser::ast::Statement::Update(_)
                    | sqlparser::ast::Statement::Delete(_)
                    | sqlparser::ast::Statement::Merge { .. }
            )
        }) {
            return Ok(());
        }
        let calls = sql_routine_calls(sql).map_err(|_| {
            ErrorEnvelope::new(
                ErrorClass::ForbiddenStatement,
                "routine call shape could not be proven",
            )
        })?;
        if calls.iter().any(|call| {
            !self
                .oracle
                .routine_call_effects(call)
                .is_some_and(|effects| {
                    effects
                        .iter()
                        .all(|effect| effect == oraclemcp_guard::RoutineEffect::ReadDb)
                })
        }) {
            return Err(ErrorEnvelope::new(
                ErrorClass::ForbiddenStatement,
                "routine execution requires a proven read-only closure; mutating routine collectors are unavailable",
            ));
        }
        Ok(())
    }
    fn unknown(profile: Option<String>, generation: u64) -> Self {
        let oracle: Arc<dyn SideEffectOracle> = Arc::new(oraclemcp_guard::UnknownOracle);
        Self {
            classifier: Classifier::new(
                ClassifierConfig::new().with_unresolved_qualified_calls_guarded(),
            )
            .with_oracle(Arc::clone(&oracle)),
            precheck: Classifier::engine_free_baseline(ClassifierConfig::new())
                .with_oracle(Arc::clone(&oracle)),
            oracle,
            profile,
            generation,
            drain: None,
            bindings: Vec::new(),
            read_policy: RoutineReadPolicy::default(),
            reason: None,
        }
    }

    pub(super) fn bind_material(&self, mut material: String) -> String {
        if !self.bindings.is_empty() {
            use sha2::{Digest, Sha256};
            let keys: Vec<_> = self.bindings.iter().map(|binding| &binding.key).collect();
            let bytes = serde_json::to_vec(&(&self.profile, self.generation, keys))
                .expect("closure keys serialize");
            material.push_str(";engine-closure/v1:");
            for byte in Sha256::digest(bytes) {
                use std::fmt::Write;
                write!(material, "{byte:02x}").expect("String formatting");
            }
        }
        material
    }

    pub(super) async fn revalidate(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
    ) -> Result<(), ErrorEnvelope> {
        self.require_current_generation()?;
        let cache = OracleCatalogResolverCache::new();
        let context = if self.bindings.is_empty() {
            None
        } else {
            Some(
                cache
                    .preload(cx, conn, &[], oraclemcp_guard::StatementScope::default())
                    .await
                    .map_err(|_| stale())?,
            )
        };
        for binding in &self.bindings {
            for call in &binding.calls {
                let resolved = oraclemcp_db::OracleCatalogResolver::resolve_routine_call(
                    cx,
                    conn,
                    &call.candidate,
                    &call.arguments,
                    context.as_ref().ok_or_else(stale)?,
                )
                .await
                .map_err(|_| stale())?;
                if resolved.as_ref() != Some(&binding.closure.root) {
                    return Err(stale());
                }
            }
            let current = oraclemcp_db::extract_closure_facts(
                cx,
                conn,
                &binding.closure,
                Some(cache.generation().0),
            )
            .await
            .map_err(|_| stale())?;
            if current.key != binding.key {
                return Err(stale());
            }
            #[cfg(feature = "plsql-intelligence")]
            engine::prove_read_dependencies(cx, conn, &cache, &current, &self.read_policy)
                .await
                .map_err(|_| stale())?;
        }
        self.require_current_generation()
    }

    fn require_current_generation(&self) -> Result<(), ErrorEnvelope> {
        if self
            .drain
            .as_ref()
            .zip(self.profile.as_deref())
            .is_some_and(|(drain, profile)| drain.generation_is_draining(profile, self.generation))
        {
            return Err(stale());
        }
        Ok(())
    }
}

fn sql_routine_calls(sql: &str) -> Result<Vec<ObjectRef>, ()> {
    oraclemcp_guard::classifier::hard_parse_sql_routine_calls(sql).map_err(|_| ())
}

fn routine_call_key(source: &ObjectRef) -> String {
    match &source.schema {
        Some(schema) => format!("{schema}.{}", source.name).to_ascii_uppercase(),
        None => source.name.to_ascii_uppercase(),
    }
}

fn stale() -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::RepreviewRequired,
        "REPREVIEW_REQUIRED: profile or routine closure changed or could not be revalidated",
    )
}

pub(super) struct ReadAndRoutineOracle {
    pub(super) read: oraclemcp_db::ReadPlanProof,
    pub(super) routines: Arc<dyn SideEffectOracle>,
}

impl SideEffectOracle for ReadAndRoutineOracle {
    fn routine_call_effects(
        &self,
        routine: &ObjectRef,
    ) -> Option<oraclemcp_guard::RoutineEffectsV1> {
        self.routines.routine_call_effects(routine)
    }
    fn routine_purity(&self, routine: &ObjectRef) -> oraclemcp_guard::Purity {
        self.routines.routine_purity(routine)
    }
    fn statement_purity(&self, objects: &[ObjectRef]) -> oraclemcp_guard::Purity {
        self.read.statement_purity(objects)
    }
    fn proves_value_column(&self, name: &RawName) -> bool {
        self.read.proves_value_column(name)
    }
}

#[cfg(feature = "plsql-intelligence")]
mod engine {
    use super::*;
    use oraclemcp_db::{
        CatalogQueryId, ClosureMember, MemberFact, OracleCatalogResolver, extract_closure_facts,
        read_verified_closure_source, run_catalog_query,
    };
    use oraclemcp_guard::StatementScope;
    use oraclemcp_guard::{
        Purity, RoutineArgument, RoutineArgumentValue, RoutineEffect, RoutineIdentifier, RoutineRef,
    };
    use plsql_catalog::{
        CatalogCapabilities, CatalogRowSet, CatalogSnapshotBuilder, CatalogSource,
        CatalogSourceKind,
    };
    use plsql_core::{AnalysisProfile, CompletenessPosture, FileId, SymbolInterner};
    use plsql_parser::{ParseOptions, TokenKind, parse_with_backend};
    use plsql_parser_antlr::Antlr4RustBackend;
    use sqlparser::ast::{Expr, FunctionArg, FunctionArguments, ObjectNamePart, Visit, Visitor};
    use sqlparser::dialect::OracleDialect;
    use sqlparser::parser::Parser;
    use std::collections::{BTreeMap, HashSet};
    use std::ops::ControlFlow;

    struct Invocation {
        source: ObjectRef,
        candidate: RoutineRef,
        arguments: Vec<RoutineArgument>,
    }
    struct Calls(Vec<Invocation>);
    impl Visitor for Calls {
        type Break = ();
        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            if let Expr::Function(function) = expr {
                let Some(parts) = function
                    .name
                    .0
                    .iter()
                    .map(|part| match part {
                        ObjectNamePart::Identifier(id) if id.quote_style.is_none() => {
                            Some(id.value.to_ascii_uppercase())
                        }
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()
                else {
                    return ControlFlow::Continue(());
                };
                let (source, candidate) = match parts.as_slice() {
                    [name] => (
                        ObjectRef::new(None, name.clone()),
                        RoutineRef {
                            schema: None,
                            package: None,
                            member: RoutineIdentifier::new(name, false),
                            overload: None,
                        },
                    ),
                    [first, name] => (
                        ObjectRef::new(Some(first.clone()), name.clone()),
                        RoutineRef {
                            schema: None,
                            package: Some(RoutineIdentifier::new(first, false)),
                            member: RoutineIdentifier::new(name, false),
                            overload: None,
                        },
                    ),
                    _ => return ControlFlow::Continue(()),
                };
                let FunctionArguments::List(args) = &function.args else {
                    return ControlFlow::Continue(());
                };
                if args.args.len() > 128
                    || args
                        .args
                        .iter()
                        .any(|arg| !matches!(arg, FunctionArg::Unnamed(_)))
                {
                    return ControlFlow::Continue(());
                }
                self.0.push(Invocation {
                    source,
                    candidate,
                    arguments: args
                        .args
                        .iter()
                        .map(|_| RoutineArgument {
                            name: None,
                            value: RoutineArgumentValue::Bind,
                        })
                        .collect(),
                });
            }
            ControlFlow::Continue(())
        }
    }

    struct Oracle {
        effects: BTreeMap<String, oraclemcp_guard::RoutineEffectsV1>,
    }
    fn source_key(source: &ObjectRef) -> String {
        format!("{}.{}", source.schema.as_deref().unwrap_or(""), source.name).to_ascii_uppercase()
    }
    impl SideEffectOracle for Oracle {
        fn routine_call_effects(
            &self,
            source: &ObjectRef,
        ) -> Option<oraclemcp_guard::RoutineEffectsV1> {
            Some(
                self.effects
                    .get(&source_key(source))
                    .cloned()
                    .unwrap_or_else(|| {
                        oraclemcp_guard::RoutineEffectsV1::new([RoutineEffect::Unknown])
                    }),
            )
        }
        fn routine_purity(&self, source: &ObjectRef) -> Purity {
            let Some(effects) = self.effects.get(&source_key(source)) else {
                return Purity::Unknown;
            };
            if effects.iter().all(|effect| effect == RoutineEffect::ReadDb) {
                Purity::ProvenReadOnly
            } else if effects
                .iter()
                .any(|effect| effect == RoutineEffect::Unknown)
            {
                Purity::Unknown
            } else {
                Purity::ProvenSideEffecting
            }
        }
    }

    pub(super) async fn prepare(
        cx: &Cx,
        conn: &dyn OracleConnection,
        cache: &OracleCatalogResolverCache,
        sql: &str,
        wanted: &[ObjectRef],
        policy: &RoutineReadPolicy,
    ) -> Result<(Arc<dyn SideEffectOracle>, Vec<ClosureBinding>), &'static str> {
        let statements =
            Parser::parse_sql(&OracleDialect {}, sql).map_err(|_| "statement_parse_incomplete")?;
        if statements.len() != 1 {
            return Err("statement_parse_incomplete");
        }
        let mut calls = Calls(Vec::new());
        let _ = statements.visit(&mut calls);
        let context = cache
            .preload(cx, conn, &[], StatementScope::default())
            .await
            .map_err(|_| "catalog_unreadable")?;
        let mut oracle = Oracle {
            effects: BTreeMap::new(),
        };
        let mut bindings = Vec::new();
        let mut seen = HashSet::new();
        for source in wanted {
            let key = source_key(source);
            if !seen.insert(key.clone()) {
                continue;
            }
            let matching: Vec<_> = calls
                .0
                .iter()
                .filter(|call| source_key(&call.source) == key)
                .collect();
            if matching.is_empty() {
                return Err("routine_identity_unrepresented");
            }
            let resolutions = matching
                .iter()
                .map(|call| CallResolution {
                    candidate: call.candidate.clone(),
                    arguments: call.arguments.clone(),
                })
                .collect();
            let mut root = None;
            for call in matching {
                let exact = OracleCatalogResolver::resolve_routine_call(
                    cx,
                    conn,
                    &call.candidate,
                    &call.arguments,
                    &context,
                )
                .await
                .map_err(|_| "catalog_unreadable")?
                .ok_or("routine_identity_unresolved")?;
                if root.as_ref().is_some_and(|prior| prior != &exact) {
                    return Err("routine_identity_ambiguous");
                }
                root = Some(exact);
            }
            let root = root.ok_or("routine_identity_unresolved")?;
            let (closure, facts, sources) =
                load_closure(cx, conn, cache, root.clone(), policy).await?;
            let effects = analyze(&facts, &sources, &root)?;
            oracle.effects.insert(key, effects);
            bindings.push(ClosureBinding {
                closure,
                key: facts.key,
                calls: resolutions,
            });
        }
        Ok((Arc::new(oracle), bindings))
    }

    fn name(routine: &RoutineRef) -> Result<(&str, &str), &'static str> {
        let owner = routine.schema.as_ref().ok_or("routine_owner_missing")?;
        if routine.package.is_some() || !simple(&owner.text) || !simple(&routine.member.text) {
            return Err("routine_identity_unsupported");
        }
        Ok((&owner.text, &routine.member.text))
    }
    fn simple(name: &str) -> bool {
        name.len() <= 128
            && name.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
            && name.bytes().all(|byte| {
                byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"_$#".contains(&byte)
            })
    }

    async fn signature(
        cx: &Cx,
        conn: &dyn OracleConnection,
        routine: &RoutineRef,
    ) -> Result<(), &'static str> {
        let (owner, name) = name(routine)?;
        let rows = run_catalog_query(
            cx,
            conn,
            CatalogQueryId::StandaloneArguments,
            &[owner.into(), name.into(), 130_i64.into()],
        )
        .await
        .map_err(|_| "catalog_unreadable")?;
        if rows.len() >= 130 || rows.is_empty() {
            return Err("signature_incomplete");
        }
        for row in rows {
            if !matches!(row.text("DEFAULTED"), Some("N" | "Y"))
                || row.parse_i64("DATA_LEVEL") != Some(0)
                || !matches!(
                    row.text("DATA_TYPE"),
                    Some(
                        "NUMBER"
                            | "VARCHAR2"
                            | "CHAR"
                            | "BINARY_INTEGER"
                            | "PLS_INTEGER"
                            | "FLOAT"
                            | "BINARY_FLOAT"
                            | "BINARY_DOUBLE"
                    )
                )
                || row
                    .parse_i64("SUBPROGRAM_ID")
                    .and_then(|id| u32::try_from(id).ok())
                    != routine.overload
                || (row.parse_i64("POSITION") != Some(0) && row.text("IN_OUT") != Some("IN"))
            {
                return Err("unsupported_signature");
            }
        }
        Ok(())
    }

    async fn load_closure(
        cx: &Cx,
        conn: &dyn OracleConnection,
        cache: &OracleCatalogResolverCache,
        root: RoutineRef,
        policy: &RoutineReadPolicy,
    ) -> Result<(RoutineClosure, ClosureFacts, Vec<(MemberFact, String)>), &'static str> {
        let mut closure = RoutineClosure {
            root: root.clone(),
            members: Vec::new(),
            dml_targets: Vec::new(),
        };
        let mut queue = vec![root];
        let mut seen = HashSet::new();
        while let Some(routine) = queue.pop() {
            let (owner, object) = name(&routine)?;
            if !seen.insert((owner.to_owned(), object.to_owned())) {
                continue;
            }
            if seen.len() > 32 {
                return Err("closure_cap");
            }
            signature(cx, conn, &routine).await?;
            closure.members.push(ClosureMember {
                routine: routine.clone(),
                owner: owner.to_owned(),
                object_name: object.to_owned(),
                object_type: "FUNCTION".into(),
                source_types: vec!["FUNCTION".into()],
            });
            let current = extract_closure_facts(cx, conn, &closure, Some(cache.generation().0))
                .await
                .map_err(|_| "catalog_incomplete")?;
            for dependency in &current.dependencies {
                if dependency.status != "VALID" {
                    return Err("dependency_invalid");
                }
                match dependency.object_type.as_str() {
                    "FUNCTION" => {
                        let rows = run_catalog_query(
                            cx,
                            conn,
                            CatalogQueryId::StandaloneProcedures,
                            &[
                                dependency.owner.as_str().into(),
                                dependency.name.as_str().into(),
                                3_i64.into(),
                            ],
                        )
                        .await
                        .map_err(|_| "catalog_unreadable")?;
                        let [row] = rows.as_slice() else {
                            return Err("dependency_signature_ambiguous");
                        };
                        let overload = row
                            .parse_i64("SUBPROGRAM_ID")
                            .and_then(|id| u32::try_from(id).ok())
                            .ok_or("dependency_signature_missing")?;
                        queue.push(RoutineRef {
                            schema: Some(RoutineIdentifier::new(&dependency.owner, true)),
                            package: None,
                            member: RoutineIdentifier::new(&dependency.name, true),
                            overload: Some(overload),
                        });
                    }
                    "TABLE" | "VIEW" | "SEQUENCE" => {}
                    "PACKAGE"
                        if dependency.owner == "SYS"
                            && matches!(dependency.name.as_str(), "STANDARD" | "DBMS_STANDARD") => {
                    }
                    _ => return Err("dependency_kind_unproven"),
                }
            }
        }
        let facts = extract_closure_facts(cx, conn, &closure, Some(cache.generation().0))
            .await
            .map_err(|_| "catalog_incomplete")?;
        prove_read_dependencies(cx, conn, cache, &facts, policy).await?;
        let mut sources = Vec::new();
        for member in &facts.members {
            if member
                .compiler_settings
                .get("PLSQL_CCFLAGS")
                .and_then(|value| value.as_deref())
                .is_some_and(|flags| !flags.trim().is_empty())
            {
                return Err("conditional_compilation_unproven");
            }
            let source = read_verified_closure_source(cx, conn, member)
                .await
                .map_err(|_| "source_unbound")?;
            sources.push((member.clone(), source));
        }
        Ok((closure, facts, sources))
    }

    pub(super) async fn prove_read_dependencies(
        cx: &Cx,
        conn: &dyn OracleConnection,
        cache: &OracleCatalogResolverCache,
        facts: &ClosureFacts,
        policy: &RoutineReadPolicy,
    ) -> Result<(), &'static str> {
        for dependency in &facts.dependencies {
            if matches!(dependency.object_type.as_str(), "TABLE" | "VIEW") {
                if !simple(&dependency.owner) || !simple(&dependency.name) {
                    return Err("dependency_identity_unsupported");
                }
                let sql = format!(
                    "SELECT * FROM \"{}\".\"{}\"",
                    dependency.owner, dependency.name
                );
                read_executor::resolve_query_block_read_with_security_policy(
                    cx,
                    conn,
                    cache,
                    &sql,
                    false,
                    read_proof_policy(policy.fga, policy.security, &policy.trusted_views, None),
                )
                .await
                .map_err(|_| "dependency_read_effects_unproven")?;
            }
        }
        Ok(())
    }

    fn qualified_source(member: &MemberFact, source: &str) -> Result<String, &'static str> {
        crate::plsql_tools::validate_engine_source(source).map_err(|_| "source_limit")?;
        let source = format!("CREATE OR REPLACE {source}");
        crate::plsql_tools::validate_engine_source(&source).map_err(|_| "source_limit")?;
        let parsed = parse_with_backend(
            &source,
            FileId::new(1),
            &Antlr4RustBackend::new(),
            &ParseOptions::default(),
        );
        if !parsed.is_clean() || parsed.was_recovered() {
            return Err("source_parse_incomplete");
        }
        let tokens = &parsed.cst.token_tape.tokens;
        if tokens.iter().any(|token| {
            token.kind != TokenKind::StringLiteral
                && (token.text.contains('@')
                    || token.text.contains("$$")
                    || token.text.eq_ignore_ascii_case("$IF"))
        }) {
            return Err("source_resolution_context_unsupported");
        }
        let cursor = tokens
            .iter()
            .position(|token| {
                token.kind == TokenKind::Keyword && token.text.eq_ignore_ascii_case("FUNCTION")
            })
            .ok_or("source_header_missing")?
            + 1;
        if cursor != 4
            || !tokens[..3]
                .iter()
                .map(|token| token.text.to_ascii_uppercase())
                .eq(["CREATE", "OR", "REPLACE"].into_iter().map(str::to_owned))
        {
            return Err("source_header_mismatch");
        }
        let first = tokens.get(cursor).ok_or("source_header_missing")?;
        let (owner, expected) = name(&member.routine)?;
        let last = if tokens
            .get(cursor + 1)
            .is_some_and(|token| token.kind == TokenKind::Dot)
        {
            if first.text.to_ascii_uppercase() != owner {
                return Err("source_owner_mismatch");
            }
            tokens.get(cursor + 2).ok_or("source_header_missing")?
        } else {
            first
        };
        if last.text.to_ascii_uppercase() != expected
            || first.kind == TokenKind::QuotedIdentifier
            || last.kind == TokenKind::QuotedIdentifier
        {
            return Err("source_header_mismatch");
        }
        let mut result = source.clone();
        if source
            .get(first.span.start.offset as usize..last.span.end.offset as usize)
            .is_none()
        {
            return Err("source_header_span_invalid");
        }
        result.replace_range(
            first.span.start.offset as usize..last.span.end.offset as usize,
            &format!("{owner}.{expected}"),
        );
        crate::plsql_tools::validate_engine_source(&result).map_err(|_| "source_limit")?;
        let mut interner = SymbolInterner::new();
        let lowered = plsql_ir::lower_top_level(&parsed.ast, &mut interner);
        if !matches!(
            lowered.declarations.as_slice(),
            [plsql_ir::Declaration::Function(_)]
        ) {
            return Err("source_declarations_ambiguous");
        }
        Ok(result)
    }

    fn catalog(facts: &ClosureFacts) -> Result<plsql_catalog::CatalogSnapshot, &'static str> {
        let mut builder = CatalogSnapshotBuilder::new(
            AnalysisProfile::default(),
            CatalogCapabilities::default(),
            CatalogSource {
                kind: CatalogSourceKind::LiveConnection,
                description: Some("hash-bound whole routine closure".into()),
                ..CatalogSource::default()
            },
            chrono::Utc::now(),
        );
        for member in &facts.members {
            let (owner, name) = name(&member.routine)?;
            let mut row = plsql_catalog::OracleRow::default();
            for (key, value) in [
                ("OWNER", owner),
                ("OBJECT_NAME", name),
                ("OBJECT_TYPE", member.object_type.as_str()),
                ("STATUS", member.status.as_str()),
            ] {
                row.insert(key, "VARCHAR2", Some(value.to_owned()));
            }
            builder
                .apply_row(CatalogRowSet::Objects, &row)
                .map_err(|_| "catalog_normalization_failed")?;
        }
        for dependency in &facts.dependencies {
            let mut object = plsql_catalog::OracleRow::default();
            for (key, value) in [
                ("OWNER", dependency.owner.as_str()),
                ("OBJECT_NAME", dependency.name.as_str()),
                ("OBJECT_TYPE", dependency.object_type.as_str()),
                ("STATUS", dependency.status.as_str()),
            ] {
                object.insert(key, "VARCHAR2", Some(value.to_owned()));
            }
            builder
                .apply_row(CatalogRowSet::Objects, &object)
                .map_err(|_| "catalog_normalization_failed")?;
            let (owner, name) = name(&dependency.member)?;
            let mut row = plsql_catalog::OracleRow::default();
            for (key, value) in [
                ("OWNER", owner),
                ("NAME", name),
                ("TYPE", "FUNCTION"),
                ("REFERENCED_OWNER", dependency.owner.as_str()),
                ("REFERENCED_NAME", dependency.name.as_str()),
                ("REFERENCED_TYPE", dependency.object_type.as_str()),
                ("DEPENDENCY_TYPE", dependency.dependency_type.as_str()),
            ] {
                row.insert(key, "VARCHAR2", Some(value.to_owned()));
            }
            builder
                .apply_row(CatalogRowSet::Dependencies, &row)
                .map_err(|_| "catalog_normalization_failed")?;
        }
        builder.finish().map_err(|_| "catalog_normalization_failed")
    }

    fn analyze(
        facts: &ClosureFacts,
        sources: &[(MemberFact, String)],
        root: &RoutineRef,
    ) -> Result<oraclemcp_guard::RoutineEffectsV1, &'static str> {
        let project = tempfile::tempdir().map_err(|_| "engine_init_failed")?;
        for (index, (member, source)) in sources.iter().enumerate() {
            let source = qualified_source(member, source)?;
            std::fs::write(project.path().join(format!("unit_{index}.sql")), source)
                .map_err(|_| "engine_init_failed")?;
        }
        let catalog_path = project.path().join("catalog.json");
        plsql_catalog::export_snapshot_to_json(&catalog(facts)?, &catalog_path)
            .map_err(|_| "engine_init_failed")?;
        let run = plsql_engine::analyze_project(plsql_engine::AnalysisRequest {
            project_root: project.path().to_owned(),
            catalog_source: plsql_engine::CatalogSourceConfig::Snapshot(catalog_path),
            cache: plsql_engine::CacheConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        });
        effects_from_engine_result(run, facts, root)
    }

    /// Proves one trusted VPD policy function for a read on the executing
    /// connection through the shared mutation-effect port in its VpdPolicy
    /// context: fresh hash-bound source, Clean engine closure, re-read source
    /// and dependencies, and every returned predicate proven constant. This
    /// read admission adds what the port leaves to its consumer: the function
    /// must be listed, standalone, and do nothing but read.
    pub(super) struct PolicyFunctionProof<'a> {
        pub(super) trusted: &'a [String],
    }

    #[async_trait::async_trait(?Send)]
    impl oraclemcp_db::PolicyFunctionProver for PolicyFunctionProof<'_> {
        async fn proves_policy_function(
            &self,
            cx: &Cx,
            conn: &dyn OracleConnection,
            function: &oraclemcp_db::PolicyFunctionRef,
        ) -> Result<bool, DbError> {
            match self.prove(cx, conn, function).await {
                Ok(()) => Ok(true),
                Err(reason) => {
                    tracing::debug!(
                        owner = function.owner,
                        function = function.function,
                        reason,
                        "VPD policy function stays unproven"
                    );
                    Ok(false)
                }
            }
        }
    }

    impl PolicyFunctionProof<'_> {
        async fn prove(
            &self,
            cx: &Cx,
            conn: &dyn OracleConnection,
            function: &oraclemcp_db::PolicyFunctionRef,
        ) -> Result<(), &'static str> {
            use oraclemcp_db::mutation_closure::{
                MutationEffectOracle, MutationRoutineUse, read_mutation_routine_source,
            };
            if function.package.is_some() {
                return Err("policy_function_package_member_unsupported");
            }
            if !policy_function_is_trusted(self.trusted, function) {
                return Err("policy_function_untrusted");
            }
            let mut source = read_mutation_routine_source(
                cx,
                conn,
                &function.owner,
                &function.function,
                "FUNCTION",
                None,
            )
            .await
            .map_err(|_| "policy_function_source_unavailable")?;
            source.use_context = MutationRoutineUse::VpdPolicy;
            let proof = crate::mutation_closure::EngineMutationEffects
                .prove_source(cx, conn, &source)
                .await
                .map_err(|_| "policy_function_unproven")?;
            policy_proof_admits_read(&proof, &source)
        }
    }

    /// A read may run a policy function only when the port proved exactly the
    /// submitted source in its VPD context and it does nothing but read.
    fn policy_proof_admits_read(
        proof: &oraclemcp_db::mutation_closure::MutationRoutineProof,
        source: &oraclemcp_db::mutation_closure::MutationRoutineSource,
    ) -> Result<(), &'static str> {
        if proof.use_context != oraclemcp_db::mutation_closure::MutationRoutineUse::VpdPolicy
            || proof.source_sha256 != source.source_sha256
        {
            return Err("policy_function_proof_mismatch");
        }
        if !proof.mutations.is_empty()
            || proof
                .effects
                .iter()
                .any(|effect| effect != RoutineEffect::ReadDb)
        {
            return Err("policy_function_has_effects");
        }
        Ok(())
    }

    fn policy_function_is_trusted(
        trusted: &[String],
        function: &oraclemcp_db::PolicyFunctionRef,
    ) -> bool {
        function.package.is_none()
            && trusted.iter().any(|candidate| {
                matches!(
                    oraclemcp_guard::parse_trusted_proof_target(candidate).as_deref(),
                    Some([owner, name]) if owner == &function.owner && name == &function.function
                )
            })
    }

    fn effects_from_engine_result(
        run: Result<plsql_engine::AnalysisRun, plsql_engine::EngineError>,
        facts: &ClosureFacts,
        root: &RoutineRef,
    ) -> Result<oraclemcp_guard::RoutineEffectsV1, &'static str> {
        let run = run.map_err(|_| "engine_init_failed")?;
        if run.completeness.posture != CompletenessPosture::Clean {
            return Err("engine_run_not_clean");
        }
        let (owner, object) = name(root)?;
        let expected: HashSet<_> = facts
            .members
            .iter()
            .map(|member| name(&member.routine).map(|(owner, object)| format!("{owner}.{object}")))
            .collect::<Result<_, _>>()?;
        let root_unit = run
            .invocation_index
            .units
            .get(&format!("{owner}.{object}"))
            .ok_or("engine_closure_catalog_mismatch")?;
        let closure = run
            .invocation_index
            .closure(&plsql_engine::InvocationShapeV1 {
                routine_id: format!("{owner}.{object}"),
                named_arguments: root_unit
                    .params
                    .iter()
                    .filter(|param| !param.has_default)
                    .map(|param| param.name.clone())
                    .collect(),
                ..Default::default()
            });
        if !closure.clean
            || !closure.unknown_reasons.is_empty()
            || !expected.iter().all(|id| closure.units.contains(id))
            || !closure.units.iter().all(|id| expected.contains(id))
        {
            return Err("engine_closure_catalog_mismatch");
        }
        if run.catalog.is_none() || !run.completeness.catalog_available {
            return Err("engine_catalog_missing");
        }
        let oracle = crate::plsql_tools::PlsqlSideEffectOracle::from_analysis_run(&run);
        let effects = oracle.routine_effects(root);
        if effects
            .iter()
            .any(|effect| effect == RoutineEffect::Unknown)
        {
            return Err("engine_closure_unknown");
        }
        Ok(effects)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn member() -> MemberFact {
            MemberFact {
                routine: RoutineRef {
                    schema: Some(RoutineIdentifier::new("APP", true)),
                    package: None,
                    member: RoutineIdentifier::new("FX", true),
                    overload: Some(1),
                },
                object_type: "FUNCTION".into(),
                object_id: 1,
                last_ddl_time: "unit fixture".into(),
                status: "VALID".into(),
                authid: "DEFINER".into(),
                compiler_settings: BTreeMap::new(),
                source_sha256: BTreeMap::new(),
            }
        }

        fn facts(member: &MemberFact) -> ClosureFacts {
            ClosureFacts {
                schema_version: 1,
                key: ClosureFactKey {
                    dbid: "synthetic".into(),
                    container: "synthetic".into(),
                    edition: "ORA$BASE".into(),
                    root: member.routine.clone(),
                    fingerprint: "unit source binding".into(),
                },
                members: vec![member.clone()],
                dependencies: Vec::new(),
                triggers: Vec::new(),
                catalog_revision: None,
            }
        }

        fn classifier_for(
            source: &str,
            restriction: Option<OperatorPureFunctionAllowlist>,
        ) -> Classifier {
            let member = member();
            let mut effects = BTreeMap::new();
            if let Ok(proven) = analyze(
                &facts(&member),
                &[(member.clone(), source.into())],
                &member.routine,
            ) {
                effects.insert("APP.FX".into(), proven);
            }
            let oracle: Arc<dyn SideEffectOracle> = Arc::new(Oracle { effects });
            let oracle = restriction.map_or_else(
                || Arc::clone(&oracle),
                |restriction| {
                    Arc::new(oraclemcp_guard::OperatorPureFunctionRestriction::new(
                        Arc::clone(&oracle),
                        restriction,
                    ))
                },
            );
            Classifier::engine_free_baseline(ClassifierConfig::new()).with_oracle(oracle)
        }

        /// A prepared statement whose APP.FX closure the real engine analyzed.
        fn prepared_for(source: &str) -> PreparedClassifier {
            let member = member();
            let mut effects = BTreeMap::new();
            if let Ok(proven) = analyze(
                &facts(&member),
                &[(member.clone(), source.into())],
                &member.routine,
            ) {
                effects.insert("APP.FX".into(), proven);
            }
            let mut prepared = PreparedClassifier::unknown(Some("dev".into()), 1);
            prepared.oracle = Arc::new(Oracle { effects });
            prepared
        }

        fn names(effects: &oraclemcp_guard::RoutineEffectsV1) -> Vec<RoutineEffect> {
            effects.iter().collect()
        }

        #[test]
        fn impact_effects_routine_call_reports_the_served_closure() {
            let read =
                prepared_for("FUNCTION FX(n NUMBER) RETURN NUMBER IS BEGIN RETURN n+1; END;");
            let calls = read
                .call_effects("SELECT APP.FX(1) FROM DUAL")
                .expect("a routine call has effects");
            assert_eq!(calls.calls.len(), 1);
            assert_eq!(calls.calls[0].0, "APP.FX");
            // A pure closure is proven to have no effect at all: an empty
            // set, distinct from Unknown.
            assert!(names(&calls.calls[0].1).is_empty());
            assert!(calls.unknown_reasons.is_empty());
            // Source-proven transaction control and autonomous work stay
            // definite refusals even when their graph edges are Medium.
            let writes = prepared_for(
                "FUNCTION FX(n NUMBER) RETURN NUMBER IS PRAGMA AUTONOMOUS_TRANSACTION; BEGIN COMMIT; RETURN n; END;",
            );
            let calls = writes.call_effects("SELECT APP.FX(1) FROM DUAL").unwrap();
            assert_eq!(
                names(&calls.calls[0].1),
                [RoutineEffect::TxnControl, RoutineEffect::Autonomous]
            );
            assert!(calls.unknown_reasons.is_empty());
            assert_eq!(
                oraclemcp_guard::admit(
                    &calls.calls[0].1,
                    oraclemcp_guard::AdmissionContext::CustomToolCall
                ),
                Err(oraclemcp_guard::EffectRefusal::AlwaysRefused(
                    RoutineEffect::TxnControl
                ))
            );
        }

        #[test]
        fn impact_effects_unproven_routine_call_is_unknown() {
            let mut prepared =
                prepared_for("FUNCTION FX(n NUMBER) RETURN NUMBER IS BEGIN RETURN n+1; END;");
            prepared.reason = Some("routine_identity_unresolved");
            let calls = prepared
                .call_effects("SELECT OTHER.FX(1) FROM DUAL")
                .unwrap();
            assert_eq!(names(&calls.calls[0].1), [RoutineEffect::Unknown]);
            assert_eq!(
                calls.unknown_reasons,
                ["OTHER.FX: routine_identity_unresolved"]
            );
            // Text the parser cannot read, or a CALL, may call anything.
            for sql in ["BEGIN APP.P; END;", "CALL APP.P()"] {
                let calls = prepared.call_effects(sql).expect(sql);
                assert!(
                    calls.calls.is_empty() && !calls.unknown_reasons.is_empty(),
                    "{sql}"
                );
            }
            // With no engine proof at all (the Unknown oracle answers nothing),
            // a call is Unknown, never an empty effect set.
            let unproven = PreparedClassifier::unknown(None, 0);
            let calls = unproven.call_effects("SELECT APP.FX(1) FROM DUAL").unwrap();
            assert_eq!(names(&calls.calls[0].1), [RoutineEffect::Unknown]);
            assert_eq!(
                calls.unknown_reasons,
                ["APP.FX: routine closure not proven"]
            );
            // A statement that calls no routine has no effect field to compute.
            assert!(
                prepared
                    .call_effects("UPDATE APP.T SET N = 1 WHERE ID = 1")
                    .is_none()
            );
        }

        #[test]
        fn policy_function_read_admission_requires_a_read_only_vpd_proof() {
            use oraclemcp_db::mutation_closure::{
                MutationRequest, MutationRoutineProof, MutationRoutineSource, MutationRoutineUse,
            };
            let source = MutationRoutineSource {
                use_context: MutationRoutineUse::VpdPolicy,
                owner: "APP".into(),
                name: "POLICY_FN".into(),
                object_type: "FUNCTION".into(),
                member: None,
                subprogram_id: Some(1),
                object_id: 7,
                last_ddl_time: "unit fixture".into(),
                compiler_settings: BTreeMap::new(),
                expression_columns: BTreeMap::new(),
                expression_storage_type: None,
                source: "FUNCTION POLICY_FN RETURN VARCHAR2 IS BEGIN RETURN '1=1'; END;".into(),
                source_sha256: "a".repeat(64),
                source_line_count: 1,
            };
            let proof = |effects: &[RoutineEffect]| MutationRoutineProof {
                use_context: MutationRoutineUse::VpdPolicy,
                source_sha256: source.source_sha256.clone(),
                closure_fingerprint: "b".repeat(64),
                effects: oraclemcp_guard::RoutineEffectsV1::new(effects.iter().copied()),
                mutations: Vec::new(),
            };
            assert_eq!(policy_proof_admits_read(&proof(&[]), &source), Ok(()));
            assert_eq!(
                policy_proof_admits_read(&proof(&[RoutineEffect::ReadDb]), &source),
                Ok(())
            );
            for effects in [
                vec![RoutineEffect::Dml],
                vec![RoutineEffect::ReadDb, RoutineEffect::RowLock],
                vec![RoutineEffect::SessionState],
            ] {
                assert_eq!(
                    policy_proof_admits_read(&proof(&effects), &source),
                    Err("policy_function_has_effects"),
                    "{effects:?}"
                );
            }
            let mut writes = proof(&[RoutineEffect::ReadDb]);
            writes.mutations.push(MutationRequest {
                target: oraclemcp_guard::ResolvedObject {
                    owner: "APP".into(),
                    name: "LOG".into(),
                    kind: oraclemcp_guard::CatalogObjectKind::Table,
                    container: None,
                    member: None,
                    overloads: Vec::new(),
                    quote_exact: false,
                    synonym_chain: Vec::new(),
                    db_link: None,
                    identity: oraclemcp_guard::ResolvedIdentity {
                        object_id: 9,
                        edition: None,
                    },
                },
                statement_kind: oraclemcp_guard::mutation_closure::MutationStatementKind::Insert,
                columns: oraclemcp_guard::mutation_closure::MutationColumns::All,
            });
            assert_eq!(
                policy_proof_admits_read(&writes, &source),
                Err("policy_function_has_effects")
            );
            let mut other_context = proof(&[]);
            other_context.use_context = MutationRoutineUse::DmlTrigger;
            let mut other_bytes = proof(&[]);
            other_bytes.source_sha256 = "c".repeat(64);
            for mismatch in [other_context, other_bytes] {
                assert_eq!(
                    policy_proof_admits_read(&mismatch, &source),
                    Err("policy_function_proof_mismatch")
                );
            }
        }

        #[test]
        fn policy_function_trust_is_exact_and_standalone_only() {
            let function = |package: Option<&str>, name: &str| oraclemcp_db::PolicyFunctionRef {
                owner: "APP".into(),
                package: package.map(str::to_owned),
                function: name.into(),
            };
            let trusted = ["APP.POLICY_FN".to_owned(), "APP.PKG.MEMBER_FN".to_owned()];
            assert!(policy_function_is_trusted(
                &trusted,
                &function(None, "POLICY_FN")
            ));
            assert!(!policy_function_is_trusted(
                &trusted,
                &function(None, "OTHER_FN")
            ));
            // A trusted package member stays outside the served proof.
            assert!(!policy_function_is_trusted(
                &trusted,
                &function(Some("PKG"), "MEMBER_FN")
            ));
            assert!(!policy_function_is_trusted(
                &[],
                &function(None, "POLICY_FN")
            ));
        }

        #[test]
        fn served_proven_readonly_udf_clears_at_read_only() {
            let classifier = classifier_for(
                "FUNCTION FX(n NUMBER) RETURN NUMBER IS BEGIN RETURN n+1; END;",
                None,
            );
            assert_eq!(
                classifier
                    .classify("SELECT APP.FX(1) FROM DUAL")
                    .required_level,
                Some(OperatingLevel::ReadOnly)
            );
            assert_eq!(
                classifier
                    .classify("SELECT OTHER.FX(1) FROM DUAL")
                    .required_level,
                None,
                "another owner cannot borrow the source proof"
            );
        }

        #[test]
        fn served_side_effecting_udf_refused() {
            for body in [
                "INSERT INTO APP.T(N) VALUES(n); RETURN n;",
                "COMMIT; RETURN n;",
                "RETURN APP.S.NEXTVAL;",
            ] {
                let classifier = classifier_for(
                    &format!("FUNCTION FX(n NUMBER) RETURN NUMBER IS BEGIN {body} END;"),
                    None,
                );
                assert_eq!(
                    classifier
                        .classify("SELECT APP.FX(1) FROM DUAL")
                        .required_level,
                    None,
                    "{body}"
                );
            }
        }

        #[test]
        fn served_unknown_udf_refused() {
            let classifier = classifier_for(
                "FUNCTION FX(n NUMBER) RETURN NUMBER IS BEGIN RETURN missing_fn(n); END;",
                None,
            );
            assert_eq!(
                classifier
                    .classify("SELECT APP.FX(1) FROM DUAL")
                    .required_level,
                None
            );
        }

        #[test]
        fn served_mutating_udf_execute_requires_its_collector() {
            // This unit exercises the collector boundary with an admitted
            // effect-set input; real engine production is covered separately.
            let effects = oraclemcp_guard::RoutineEffectsV1::new([RoutineEffect::Ddl]);
            let mut proof = PreparedClassifier::unknown(Some("synthetic".into()), 1);
            proof.oracle = Arc::new(Oracle {
                effects: BTreeMap::from([("APP.FX".into(), effects)]),
            });
            assert_eq!(
                proof
                    .require_readonly_routine_closures("UPDATE APP.T SET N=APP.FX(1) WHERE ID=1")
                    .unwrap_err()
                    .error_class,
                ErrorClass::ForbiddenStatement
            );
            let unknown = PreparedClassifier::unknown(None, 0);
            for sql in [
                "SELECT APP.FX(1) FROM DUAL",
                "INSERT INTO APP.T(N) VALUES(APP.FX(1))",
                "UPDATE APP.T SET N=APP.FX(1) WHERE ID=1; DELETE FROM APP.T WHERE ID=2",
            ] {
                assert_eq!(
                    unknown
                        .require_readonly_routine_closures(sql)
                        .unwrap_err()
                        .error_class,
                    ErrorClass::ForbiddenStatement
                );
            }
        }

        #[test]
        fn served_catalog_incomplete_is_unknown() {
            let member = member();
            let mut incomplete = facts(&member);
            incomplete.members.clear();
            assert!(
                analyze(
                    &incomplete,
                    &[(
                        member.clone(),
                        "FUNCTION FX(n NUMBER) RETURN NUMBER IS BEGIN RETURN n; END;".into()
                    )],
                    &member.routine
                )
                .is_err()
            );
        }

        #[test]
        fn served_b12a_only_narrows() {
            let restriction =
                OperatorPureFunctionAllowlist::new([oraclemcp_guard::OperatorPureFunction::parse(
                    "APP.FX",
                )
                .unwrap()]);
            let source = "FUNCTION FX(n NUMBER) RETURN NUMBER IS BEGIN RETURN n; END;";
            assert_eq!(
                classifier_for(source, Some(restriction.clone()))
                    .classify("SELECT APP.FX(1) FROM DUAL")
                    .required_level,
                Some(OperatingLevel::ReadOnly)
            );
            assert_eq!(
                classifier_for(source, Some(OperatorPureFunctionAllowlist::default()))
                    .classify("SELECT APP.FX(1) FROM DUAL")
                    .required_level,
                None
            );
            assert_eq!(
                classifier_for(
                    "FUNCTION FX(n NUMBER) RETURN NUMBER IS BEGIN COMMIT; RETURN n; END;",
                    Some(restriction)
                )
                .classify("SELECT APP.FX(1) FROM DUAL")
                .required_level,
                None
            );
        }

        #[test]
        fn served_engine_init_failure_falls_back_to_unknown_oracle() {
            let member = member();
            let project = tempfile::tempdir().unwrap();
            let run = plsql_engine::analyze_project(plsql_engine::AnalysisRequest {
                project_root: project.path().into(),
                catalog_source: plsql_engine::CatalogSourceConfig::Snapshot(
                    project.path().join("unavailable-catalog.json"),
                ),
                ..Default::default()
            });
            assert_eq!(
                effects_from_engine_result(run, &facts(&member), &member.routine),
                Err("engine_init_failed")
            );
            let fallback = PreparedClassifier::unknown(Some("synthetic".into()), 1);
            assert!(!matches!(
                fallback
                    .precheck
                    .classify("SELECT APP.FX(1) FROM DUAL")
                    .gate(&default_read_only_level()),
                LevelDecision::Allow
            ));
        }

        #[test]
        fn served_real_partial_engine_run_is_unknown() {
            let member = member();
            let project = tempfile::tempdir().unwrap();
            let source = "CREATE FUNCTION APP.FX(n NUMBER) RETURN NUMBER IS BEGIN RETURN n; END; /\nCREATE FUNCTION APP.FYA RETURN NUMBER IS BEGIN RETURN 1; END; /\nCREATE FUNCTION APP.FYB RETURN NUMBER IS BEGIN RETURN 1; END; /\nCREATE FUNCTION APP.FYC RETURN NUMBER IS BEGIN RETURN 1; END; /\nCREATE TABLE APP.PARTIAL_MARKER(N NUMBER);";
            crate::plsql_tools::validate_engine_source(source).unwrap();
            std::fs::write(project.path().join("partial.sql"), source).unwrap();
            let catalog_path = project.path().join("catalog.json");
            plsql_catalog::export_snapshot_to_json(
                &catalog(&facts(&member)).unwrap(),
                &catalog_path,
            )
            .unwrap();
            let run = plsql_engine::analyze_project(plsql_engine::AnalysisRequest {
                project_root: project.path().into(),
                catalog_source: plsql_engine::CatalogSourceConfig::Snapshot(catalog_path),
                cache: plsql_engine::CacheConfig {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
            assert_eq!(
                run.completeness.posture,
                CompletenessPosture::Partial,
                "{:?}",
                run.diagnostics
            );
            assert_eq!(
                effects_from_engine_result(Ok(run), &facts(&member), &member.routine),
                Err("engine_run_not_clean")
            );
        }
        #[test]
        fn served_real_engine_keeps_exact_catalog_header_identity() {
            let member = member();
            let source = qualified_source(
                &member,
                "FUNCTION FX(n NUMBER) RETURN NUMBER IS BEGIN RETURN n+1; END;",
            )
            .unwrap();
            let project = tempfile::tempdir().unwrap();
            std::fs::write(project.path().join("fx.sql"), source).unwrap();
            let run = plsql_engine::analyze_project(plsql_engine::AnalysisRequest {
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
                run.diagnostics
            );
            assert!(
                run.invocation_index.units.contains_key("APP.FX"),
                "{:?}",
                run.invocation_index.units.keys()
            );
            let closure = run
                .invocation_index
                .closure(&plsql_engine::InvocationShapeV1 {
                    routine_id: "APP.FX".into(),
                    positional_count: 1,
                    ..Default::default()
                });
            assert!(closure.clean, "{closure:?}");
            assert!(
                closure
                    .effects
                    .iter()
                    .all(|effect| effect == plsql_engine::RoutineEffect::ReadDb)
            );
        }
        #[test]
        fn served_default_effects_are_analyzed_and_wrong_headers_refuse() {
            let member = member();
            for source in [
                "FUNCTION OTHER RETURN NUMBER IS BEGIN RETURN 1; END;",
                "FUNCTION OTHER.FX RETURN NUMBER IS BEGIN RETURN 1; END;",
            ] {
                assert!(qualified_source(&member, source).is_err(), "{source}");
            }
            for default in ["DEFAULT evil()", ":= evil()", "DEFAULT evil"] {
                let source = format!(
                    "FUNCTION FX(n NUMBER {default}) RETURN NUMBER IS BEGIN RETURN n; END;"
                );
                assert!(qualified_source(&member, &source).is_ok());
                assert_eq!(
                    classifier_for(&source, None)
                        .classify("SELECT APP.FX() FROM DUAL")
                        .required_level,
                    None
                );
            }
            let pure = classifier_for(
                "FUNCTION FX(n NUMBER DEFAULT 1) RETURN NUMBER IS BEGIN RETURN n; END;",
                None,
            );
            assert_eq!(
                pure.classify("SELECT APP.FX() FROM DUAL").required_level,
                Some(OperatingLevel::ReadOnly)
            );
        }
    }
}

#[cfg(test)]
mod generation_tests {
    use super::*;
    use oraclemcp_db::{
        CatalogQueryId, ClosureMember, OracleBackend, OracleCell, OracleRow, extract_closure_facts,
    };
    use oraclemcp_guard::{RoutineIdentifier, RoutineRef, StatementScope};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct RevalidationCatalog {
        changed_schema: AtomicBool,
        executions: AtomicUsize,
    }

    fn catalog_row(values: &[(&str, Option<&str>)]) -> OracleRow {
        OracleRow {
            columns: values
                .iter()
                .map(|(name, value)| {
                    (
                        (*name).to_owned(),
                        OracleCell::new("VARCHAR2", value.map(str::to_owned)),
                    )
                })
                .collect(),
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for RevalidationCatalog {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            let row = if sql == CatalogQueryId::SessionContext.spec().sql {
                catalog_row(&[
                    ("SESSION_USER", Some("APP")),
                    (
                        "CURRENT_SCHEMA",
                        Some(if self.changed_schema.load(Ordering::SeqCst) {
                            "OTHER"
                        } else {
                            "APP"
                        }),
                    ),
                    ("EDITION_NAME", Some("ORA$BASE")),
                ])
            } else if sql == CatalogQueryId::SessionRoles.spec().sql
                || sql == CatalogQueryId::ClosureDependencies.spec().sql
            {
                return Ok(Vec::new());
            } else if sql == CatalogQueryId::ClosureIdentity.spec().sql {
                catalog_row(&[
                    ("DBID", Some("42")),
                    ("CONTAINER_NAME", Some("FREEPDB1")),
                    ("EDITION_NAME", Some("ORA$BASE")),
                ])
            } else if sql == CatalogQueryId::Objects.spec().sql
                || sql == CatalogQueryId::ClosureMemberObject.spec().sql
            {
                let Some(OracleBind::String(owner)) = binds.first() else {
                    panic!("object lookup must bind its owner");
                };
                assert_eq!(binds.get(1), Some(&OracleBind::from("FX")));
                catalog_row(&[
                    ("OWNER", Some(owner)),
                    ("OBJECT_NAME", Some("FX")),
                    ("OBJECT_TYPE", Some("FUNCTION")),
                    ("OBJECT_ID", Some(if owner == "APP" { "1" } else { "2" })),
                    ("LAST_DDL_TIME", Some("2026-10-31T00:00:00")),
                    ("STATUS", Some("VALID")),
                    ("EDITION_NAME", None),
                ])
            } else if sql == CatalogQueryId::StandaloneProcedures.spec().sql
                || sql == CatalogQueryId::ClosureRoutineAuthid.spec().sql
            {
                catalog_row(&[
                    ("SUBPROGRAM_ID", Some("1")),
                    ("OVERLOAD", None),
                    ("AUTHID", Some("DEFINER")),
                ])
            } else if sql == CatalogQueryId::StandaloneArguments.spec().sql {
                catalog_row(&[
                    ("SUBPROGRAM_ID", Some("1")),
                    ("OVERLOAD", None),
                    ("POSITION", Some("0")),
                    ("DATA_LEVEL", Some("0")),
                    ("IN_OUT", Some("OUT")),
                    ("DEFAULTED", Some("N")),
                    ("ARGUMENT_NAME", None),
                    ("DATA_TYPE", Some("NUMBER")),
                ])
            } else if sql == CatalogQueryId::ClosureCompilerSettings.spec().sql {
                catalog_row(&[
                    ("PLSQL_OPTIMIZE_LEVEL", Some("2")),
                    ("PLSQL_CODE_TYPE", Some("INTERPRETED")),
                    ("PLSQL_DEBUG", Some("FALSE")),
                    ("PLSQL_WARNINGS", Some("DISABLE:ALL")),
                    ("PLSQL_CCFLAGS", None),
                    ("NLS_LENGTH_SEMANTICS", Some("BYTE")),
                    ("PLSCOPE_SETTINGS", Some("IDENTIFIERS:NONE")),
                ])
            } else if sql == CatalogQueryId::ClosureSource.spec().sql {
                catalog_row(&[
                    ("LINE", Some("1")),
                    (
                        "TEXT",
                        Some("FUNCTION FX RETURN NUMBER IS BEGIN RETURN 1; END;\n"),
                    ),
                ])
            } else {
                panic!("unexpected revalidation catalog query: {sql}");
            };
            Ok(vec![row])
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            self.executions.fetch_add(1, Ordering::SeqCst);
            Ok(1)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            panic!("revalidation must not commit");
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            panic!("revalidation must not roll back");
        }
    }

    #[test]
    fn served_revalidation_identity_drift_refuses_before_execution() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let conn = RevalidationCatalog::default();
            let cache = OracleCatalogResolverCache::new();
            let candidate = RoutineRef {
                schema: None,
                package: None,
                member: RoutineIdentifier::new("FX", false),
                overload: None,
            };
            let context = cache
                .preload(&cx, &conn, &[], StatementScope::default())
                .await
                .unwrap();
            let root = oraclemcp_db::OracleCatalogResolver::resolve_routine_call(
                &cx,
                &conn,
                &candidate,
                &[],
                &context,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(root.schema.as_ref().unwrap().text, "APP");
            let closure = RoutineClosure {
                root: root.clone(),
                members: vec![ClosureMember {
                    routine: root.clone(),
                    owner: "APP".into(),
                    object_name: "FX".into(),
                    object_type: "FUNCTION".into(),
                    source_types: vec!["FUNCTION".into()],
                }],
                dml_targets: Vec::new(),
            };
            let key = extract_closure_facts(&cx, &conn, &closure, Some(cache.generation().0))
                .await
                .unwrap()
                .key;
            let mut proof = PreparedClassifier::unknown(Some("dev".into()), 0);
            proof.bindings.push(ClosureBinding {
                closure: closure.clone(),
                key: key.clone(),
                calls: vec![CallResolution {
                    candidate: candidate.clone(),
                    arguments: Vec::new(),
                }],
            });

            // Positive control: complete unchanged facts allow the caller past
            // the real revalidation gate and into the recording connection.
            proof.revalidate(&cx, &conn).await.unwrap();
            conn.execute(&cx, "SELECT FX() FROM SYS.DUAL", &[])
                .await
                .unwrap();
            assert_eq!(conn.executions.swap(0, Ordering::SeqCst), 1);

            conn.changed_schema.store(true, Ordering::SeqCst);
            let context = cache
                .preload(&cx, &conn, &[], StatementScope::default())
                .await
                .unwrap();
            let resolved = oraclemcp_db::OracleCatalogResolver::resolve_routine_call(
                &cx,
                &conn,
                &candidate,
                &[],
                &context,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(resolved.schema.as_ref().unwrap().text, "OTHER");
            assert_ne!(resolved, root);
            // The old routine still exists unchanged: a closure-key comparison
            // alone cannot detect that the caller would now invoke OTHER.FX.
            assert_eq!(
                extract_closure_facts(&cx, &conn, &closure, Some(cache.generation().0))
                    .await
                    .unwrap()
                    .key,
                key
            );
            let result = async {
                proof.revalidate(&cx, &conn).await?;
                conn.execute(&cx, "SELECT FX() FROM SYS.DUAL", &[])
                    .await
                    .map_err(DbError::into_envelope)
            }
            .await;
            assert_eq!(conn.executions.load(Ordering::SeqCst), 0);
            let error = result.expect_err("a different resolved routine must require repreview");
            assert_eq!(error.error_class, ErrorClass::RepreviewRequired);
            assert!(error.message.starts_with("REPREVIEW_REQUIRED:"));
        });
    }

    #[test]
    fn served_generation_change_between_preview_and_apply_refuses() {
        let before = OracleMcpConfig::from_toml_str(
            "[[profiles]]\nname='dev'\nconnect_string='old:1521/svc'\n",
        )
        .unwrap();
        let after = OracleMcpConfig::from_toml_str(
            "[[profiles]]\nname='dev'\nconnect_string='new:1521/svc'\n",
        )
        .unwrap();
        let drain = ProfileDrainState::from_config(before.clone());
        let lease = match drain.admit_mcp_profile("dev", true) {
            ProfileGenerationAdmission::Ready(lease) => lease,
            _ => panic!("profile not admitted"),
        };
        let profile = ProfileClassifier::activate(Some("dev".into()), Some(&lease));
        let mut preview = PreparedClassifier::unknown(profile.profile.clone(), profile.generation);
        preview.drain = profile.drain.clone();
        assert!(preview.require_current_generation().is_ok());
        drain
            .apply_config_reload_plan(&ConfigReloadPlan::between(&before, &after), &before, &after)
            .unwrap();
        assert_eq!(
            preview
                .require_current_generation()
                .unwrap_err()
                .error_class,
            ErrorClass::RepreviewRequired
        );
    }
}
