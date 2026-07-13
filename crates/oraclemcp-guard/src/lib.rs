#![forbid(unsafe_code)]

//! The safety guard for the `oraclemcp` server: the fail-closed, engine-aware
//! statement classifier (§5.3), the ordered operating-level model (§6.6), the
//! `SideEffectOracle` purity port (default `Unknown` = fail-closed), per-schema
//! policy (§6.2), and the monotonic-deadline approval/elevation tokens
//! (§5.5, §5.10) — beads P0-7, P0-CLK, P1-1, P1-10, P1-POLICY.
//!
//! Phase-A skeleton. The guard ships fully functional with **no** engine
//! dependency: the `SideEffectOracle` port's default impl returns `Unknown`, so
//! a statement is cleared to `Safe` only on an explicit `ProvenReadOnly`
//! verdict the engine binds from the consumer side (keeps the one-way boundary
//! intact — §0 hard rule 1).

pub mod classifier;
pub mod clock;
pub mod enforcement;
pub mod exec_grant;
pub mod levels;
pub mod policy;
pub mod purity;
pub mod resolver;
pub mod rewrite;
pub mod stepup;
pub mod token;

pub use enforcement::{
    SET_TRANSACTION_READ_ONLY, is_allowed_alter_session, read_only_setup_statements,
};

pub use classifier::{
    BatchShape, Classifier, ClassifierConfig, GuardDecision, StageA,
    VERDICT_CERTIFICATE_CLASSIFIER_VERSION, VERDICT_CERTIFICATE_REGISTRY_GENERATION,
    VerdictCertificate, VerdictCertificateBindingError, VerdictDerivationStep, analyze_batch,
    named_bind_placeholders, semantic_read_plan, stage_a,
};
pub use clock::MonotonicDeadline;
pub use exec_grant::{ExecGrantBinding, ExecGrantError, ExecGrantStore};
pub use levels::{
    BlockReason, DangerLevel, EscalationError, LevelDecision, OperatingLevel, SessionLevelState,
};
pub use policy::{
    DefaultMode, PolicyDecision, SQL_POLICY_VERSION, SchemaPolicy, SchemaPolicyRaw,
    SchemaPolicySet, SqlPolicyConfig, SqlPolicyEffectConfig, SqlPolicyMatchConfig,
    SqlPolicyRuleConfig, SqlPolicyValidationError, SqlPolicyVerb,
};
pub use purity::{ObjectRef, Purity, SideEffectOracle, UnknownOracle};
pub use resolver::{
    CatalogGeneration, CatalogObjectKind, CatalogResolver, QuoteSemantics, RawName, RawNamePart,
    Resolution, ResolveCtx, ResolvedContainer, ResolvedIdentity, ResolvedObject, ResolvedOverload,
    SemanticReadPlan, StatementRelation, StatementScope, SynonymHop, SyntacticRole,
    UnresolvedCatalogResolver,
};
pub use rewrite::suggest_parameterized_form;
pub use stepup::{
    ChallengeStatus, CiToken, StepUpChallenge, StepUpOption, StepUpRegistry, StepUpResolution,
};
pub use token::{ALLOW_ONCE_TTL, AllowOnceError, AllowOnceStore, sql_digest};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
