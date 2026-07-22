//! MCP resource subscriptions (plan §8.5; bead P3-6 / oracle-qmwz.4.6,
//! sub-feature 2; WP-E E1). `resources/subscribe` lets a client watch an
//! `oracle://` resource; the server emits `resources/updated` to its
//! subscribers when the resource changes.
//!
//! **The change-detection fork (E1).** Oracle can push DDL/data changes via
//! `DBMS_CHANGE_NOTIFICATION` (DCN), but that requires the `CHANGE NOTIFICATION`
//! privilege and an open callback port. The Rust thin driver already supports
//! CQN registration; this module makes that registration an explicitly-gated
//! privileged operation. A CQN callback is reduced in the DB adapter to its
//! registration identity, then this module fans it out as a coalesced URI-only
//! update. Clients must re-read through the ordinary guarded path for data.
//!
//! **Capability gating (E1, hard requirement).** `resources.subscribe` is
//! advertised in the `initialize` capabilities **only** when a working change
//! source has been confirmed ([`SubscriptionHub::with_source`]). With no source
//! ([`SubscriptionHub::unsupported`], the default), `subscribe` is NOT
//! advertised and a `resources/subscribe` call fails — we never advertise a
//! subscription we cannot honor.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use asupersync::Cx;
use oraclemcp_audit::{
    AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, Auditor, sha256_hex,
};
use oraclemcp_config::{ConnectionProfile, DEFAULT_MAX_SUBSCRIPTIONS};
use oraclemcp_db::{
    CatalogInvalidation, CqnDriverNotification, CqnNotificationOutcome, CqnNotificationReceiver,
    CqnQueryRegistration, OracleBind, OracleCatalogResolverCache, OracleConnection,
    resolved_relations_read_purity,
};
use oraclemcp_guard::{
    CatalogObjectKind, CatalogResolver, Classifier, ClassifierConfig, DangerLevel, LevelDecision,
    ObjectRef, OperatingLevel, Purity, Resolution, SessionLevelState, SideEffectOracle,
    semantic_read_plan,
};
use parking_lot::Mutex;

/// The CQN registration form requested from Oracle.
///
/// Object-level registration is deliberately represented so the gate can
/// refuse it explicitly instead of accidentally gaining a permissive fallback
/// when driver wiring arrives. Object notifications reveal base-table activity
/// beyond a query predicate's read scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CqnRegistrationScope {
    /// Register one classifier-proven query with Oracle.
    Query,
    /// Register an object-wide notification. Always refused.
    Object,
}

/// Fail-closed errors from CQN registration admission.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CqnRegistrationError {
    /// The profile did not explicitly opt into this standing information channel.
    #[error("CQN registration is disabled for this profile")]
    ProfileNotPermitted,
    /// Object-wide notifications can reveal rows outside the proven query scope.
    #[error("OBJECT-level CQN registration is refused; only QUERY-level registration is supported")]
    ObjectLevelRefused,
    /// The requested SQL is not a classifier-proven `READ_ONLY` query.
    #[error("CQN registration requires a classifier-proven READ_ONLY query")]
    QueryNotReadOnly,
    /// The query scope cannot be represented exactly enough for a future
    /// callback to be bound safely.
    #[error("CQN registration requires a query with an exactly representable semantic read scope")]
    QueryScopeNotRepresentable,
    /// The exact live session could not prove every query dependency is a
    /// locally resolved, ordinary read-only relation.
    #[error("CQN registration requires live proof that every query dependency is read-only-safe")]
    LiveReadProofUnavailable,
    /// The registration cannot be linked to a server-derived MCP resource URI,
    /// so its receiver and callback fan-out cannot be cap-governed.
    #[error("CQN registration requires a server-derived resource URI")]
    ResourceUriRequired,
    /// The operation needs a confirmed, active `READ_WRITE` elevation.
    #[error("CQN registration requires an active confirmed READ_WRITE step-up")]
    StepUpRequired,
    /// The profile/OAuth ceiling makes the required step-up impossible.
    #[error(
        "CQN registration is blocked because READ_WRITE is outside the effective operating-level ceiling"
    )]
    OperatingLevelBlocked,
    /// Registration cannot proceed without the required durable audit evidence.
    #[error("CQN registration is refused because no audit sink is configured")]
    AuditUnavailable,
    /// The audit append failed, so no registration permit was issued.
    #[error("CQN registration is refused because its audit append failed")]
    AuditAppendFailed,
    /// Oracle rejected the query registration after the fail-closed admission
    /// proof was recorded, so no CQN source became available.
    #[error("CQN QUERY registration was not accepted by the Oracle backend")]
    DriverRegistrationFailed,
}

/// Fail-closed errors from opening CQN's separately authenticated EMON
/// receiver.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CqnEmonOpenError {
    /// The server-derived owner does not currently hold the registered URI's
    /// subscription reservation.
    #[error(
        "CQN EMON receiver requires an admitted subscription for its server-derived owner and URI"
    )]
    SubscriptionNotAdmitted,
    /// A receiver is already open for this owner/URI reservation.
    #[error("CQN EMON receiver is already open for this server-derived owner and URI")]
    ReceiverAlreadyOpen,
    /// The database adapter refused the authenticated EMON connection after
    /// the registry reservation was acquired. The reservation is released
    /// before this error is returned.
    #[error("CQN EMON receiver could not be opened: {0}")]
    Driver(#[from] oraclemcp_db::DbError),
}

/// Opaque proof that one CQN registration crossed the profile, classifier,
/// active-step-up, and audit gates.
///
/// The fields are private and the type has no public constructor. The later
/// driver call must still re-run [`CqnRegistrationGate::authorize`] immediately
/// before `register_query`: this permit is evidence of the gate, never an
/// authorization input that can widen admission after a profile/session change.
#[derive(Debug)]
pub struct CqnRegistrationPermit {
    profile_name: String,
    query_sha256: String,
}

/// A live, QUERY-level CQN registration bound to the exact audited query.
///
/// The private permit prevents a caller from constructing a notification
/// source from a raw driver handle. The handle contains only Oracle registration
/// metadata; neither it nor any future callback carries result rows, values, or
/// rowids across this boundary.
#[derive(Debug)]
pub struct CqnRegisteredQuery {
    permit: CqnRegistrationPermit,
    registration: CqnQueryRegistration,
    resource_uri: String,
}

impl CqnRegisteredQuery {
    /// Whether the underlying admission evidence is bound to this profile and
    /// exact query text. This is evidence, never a future authorization input.
    #[must_use]
    pub fn is_bound_to(&self, profile_name: &str, query: &str) -> bool {
        self.permit.is_bound_to(profile_name, query)
    }

    /// The opaque driver registration id for callback ownership and eventual
    /// adapter cleanup. It contains no query result data.
    #[must_use]
    pub const fn registration_id(&self) -> u64 {
        self.registration.registration_id()
    }

    /// The opaque registered-query id. It is metadata only, not a row value.
    #[must_use]
    pub const fn query_id(&self) -> u64 {
        self.registration.query_id()
    }

    /// Bind this actual QUERY-level registration to one server-derived MCP
    /// resource for URI-only callback fan-out.
    ///
    /// This proves only that the fan-out originates from a registration that
    /// already passed the privileged gate. It is not reusable authorization:
    /// registration admission still happened at the driver effect point, and a
    /// later client re-read remains classifier/masking/egress governed.
    #[must_use]
    pub fn callback_fanout(&self) -> CqnCallbackFanout {
        CqnCallbackFanout {
            registration_id: self.registration.registration_id(),
            resource_uri: self.resource_uri.clone(),
        }
    }

    /// Open the separately authenticated EMON receiver for this existing
    /// QUERY-level registration.
    ///
    /// `owner` MUST be the server-derived principal. The registry atomically
    /// re-checks its admission and returns a non-reusable receiver reservation
    /// before the database effect. The returned receiver owns that reservation,
    /// releasing it exactly once when it is dropped; a driver-open failure
    /// releases it before this method returns the error. This method has no
    /// registry-free path.
    pub async fn open_emon_receiver(
        &self,
        cx: &Cx,
        connection: &dyn OracleConnection,
        registry: &SubscriptionRegistry,
        owner: &str,
    ) -> Result<Box<dyn CqnNotificationReceiver>, CqnEmonOpenError> {
        let reservation = registry.reserve_emon_receiver(
            owner,
            &self.resource_uri,
            self.registration.registration_id(),
        )?;
        let receiver = connection
            .open_cqn_notification_receiver(cx, self.registration)
            .await?;
        Ok(Box::new(ReservedCqnNotificationReceiver {
            receiver,
            _reservation: reservation,
        }))
    }
}

/// All server-derived inputs required to admit one QUERY-level CQN
/// registration at its effect point.
///
/// This request has no certificate or permit field by design: the gate creates
/// new admission evidence from these current inputs immediately before asking
/// Oracle to register the query.
pub struct CqnQueryRegistrationRequest<'a> {
    scope: CqnRegistrationScope,
    query: &'a str,
    resource_uri: Option<&'a str>,
    binds: &'a [OracleBind],
    classifier: &'a Classifier,
    session: &'a SessionLevelState,
    catalog_cache: Option<&'a OracleCatalogResolverCache>,
    auditor: Option<&'a Auditor>,
    subject: AuditSubject,
}

impl<'a> CqnQueryRegistrationRequest<'a> {
    /// Build the current, server-derived CQN registration inputs.
    ///
    /// `resource_uri` is bound to the successful registration and cannot be
    /// swapped when opening its EMON receiver or projecting callbacks.
    #[must_use]
    pub fn new(
        scope: CqnRegistrationScope,
        query: &'a str,
        binds: &'a [OracleBind],
        classifier: &'a Classifier,
        session: &'a SessionLevelState,
        auditor: Option<&'a Auditor>,
        subject: AuditSubject,
    ) -> Self {
        CqnQueryRegistrationRequest {
            scope,
            query,
            resource_uri: None,
            binds,
            classifier,
            session,
            catalog_cache: None,
            auditor,
            subject,
        }
    }

    /// Bind the request to the server-derived MCP resource URI before the
    /// registration effect point. Omitting this binding is refused rather than
    /// leaving an EMON receiver or callback fan-out without a cap-governed URI.
    #[must_use]
    pub fn with_resource_uri(mut self, resource_uri: &'a str) -> Self {
        self.resource_uri = Some(resource_uri);
        self
    }

    /// Supply the exact live-session catalog cache required to prove the CQN
    /// query remains no broader than an ordinary guarded read. Omitting this
    /// binding is refused at the driver effect point.
    #[must_use]
    pub fn with_catalog_cache(mut self, catalog_cache: &'a OracleCatalogResolverCache) -> Self {
        self.catalog_cache = Some(catalog_cache);
        self
    }
}

impl CqnRegistrationPermit {
    /// Whether this evidence is bound to exactly `profile_name` and `query`.
    ///
    /// This check is deliberately not an authorization decision. Consumers must
    /// call the gate again at their point of effect (SEC-1).
    #[must_use]
    pub fn is_bound_to(&self, profile_name: &str, query: &str) -> bool {
        self.profile_name == profile_name && self.query_sha256 == sha256_hex(query.as_bytes())
    }
}

/// First-class CQN-registration gate for a single connection profile.
///
/// CQN registration is not SQL text and therefore cannot be admitted solely by
/// the SQL classifier. This gate layers a fail-closed profile capability,
/// classifier proof for the query being registered, a confirmed active
/// `READ_WRITE` elevation, and durable audit-before-effect into one permit.
#[derive(Debug)]
pub struct CqnRegistrationGate {
    profile_name: String,
    profile_permits_cqn: bool,
}

impl CqnRegistrationGate {
    /// Construct the gate from a profile's effective CQN capability.
    #[must_use]
    pub fn from_profile(profile: &ConnectionProfile) -> Self {
        CqnRegistrationGate {
            profile_name: profile.name.clone(),
            profile_permits_cqn: profile.allows_change_notification(),
        }
    }

    /// Admit and audit static CQN-registration evidence.
    ///
    /// This evidence is deliberately not sufficient for the driver effect:
    /// [`Self::register_query`] independently obtains a fresh live
    /// relation-purity proof immediately before registration. A stored permit
    /// can therefore never bypass a later catalog, policy, or virtual-column
    /// change.
    pub fn authorize(
        &self,
        scope: CqnRegistrationScope,
        query: &str,
        classifier: &Classifier,
        session: &SessionLevelState,
        auditor: Option<&Auditor>,
        subject: AuditSubject,
    ) -> Result<CqnRegistrationPermit, CqnRegistrationError> {
        self.validate_static_admission(scope, query, classifier, session)?;
        self.audit_permit(query, auditor, subject)
    }

    fn validate_static_admission(
        &self,
        scope: CqnRegistrationScope,
        query: &str,
        classifier: &Classifier,
        session: &SessionLevelState,
    ) -> Result<(), CqnRegistrationError> {
        if scope == CqnRegistrationScope::Object {
            return Err(CqnRegistrationError::ObjectLevelRefused);
        }
        if !self.profile_permits_cqn {
            return Err(CqnRegistrationError::ProfileNotPermitted);
        }

        let decision = classifier.classify(query);
        if decision.danger != DangerLevel::Safe
            || decision.required_level != Some(OperatingLevel::ReadOnly)
        {
            return Err(CqnRegistrationError::QueryNotReadOnly);
        }
        if semantic_read_plan(query).is_none() {
            return Err(CqnRegistrationError::QueryScopeNotRepresentable);
        }

        match session.evaluate(Some(OperatingLevel::ReadWrite)) {
            LevelDecision::Allow if session.has_active_elevation() => {}
            LevelDecision::Allow | LevelDecision::RequireStepUp { .. } => {
                return Err(CqnRegistrationError::StepUpRequired);
            }
            LevelDecision::Blocked { .. } => {
                return Err(CqnRegistrationError::OperatingLevelBlocked);
            }
            _ => return Err(CqnRegistrationError::OperatingLevelBlocked),
        }

        Ok(())
    }

    fn audit_permit(
        &self,
        query: &str,
        auditor: Option<&Auditor>,
        subject: AuditSubject,
    ) -> Result<CqnRegistrationPermit, CqnRegistrationError> {
        let auditor = auditor.ok_or(CqnRegistrationError::AuditUnavailable)?;
        let draft = AuditEntryDraft {
            subject,
            db_evidence: None,
            cancel: None,
            result_masking: None,
            tool: "oracle_cqn_register_query".to_owned(),
            sql: format!("CQN REGISTER QUERY: {query}"),
            danger_level: OperatingLevel::ReadWrite.as_str().to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: None,
            outcome: AuditOutcome::Succeeded,
        };
        auditor
            .append(&draft, cqn_audit_timestamp(), true)
            .map_err(|_| CqnRegistrationError::AuditAppendFailed)?;

        Ok(CqnRegistrationPermit {
            profile_name: self.profile_name.clone(),
            query_sha256: sha256_hex(query.as_bytes()),
        })
    }

    /// Re-classify, prove every live relation is read-only-safe, step-up-check,
    /// and durably audit the exact query before issuing Oracle's QUERY-level
    /// registration at that effect point.
    ///
    /// The permit is intentionally created and consumed inside this method;
    /// callers cannot replay an earlier certificate or stored verdict to widen
    /// registration after configuration or session state changed (SEC-1).
    pub async fn register_query(
        &self,
        cx: &Cx,
        connection: &dyn OracleConnection,
        request: CqnQueryRegistrationRequest<'_>,
    ) -> Result<CqnRegisteredQuery, CqnRegistrationError> {
        let CqnQueryRegistrationRequest {
            scope,
            query,
            resource_uri,
            binds,
            classifier,
            session,
            catalog_cache,
            auditor,
            subject,
        } = request;
        let resource_uri = resource_uri.ok_or(CqnRegistrationError::ResourceUriRequired)?;
        let catalog_cache = catalog_cache.ok_or(CqnRegistrationError::LiveReadProofUnavailable)?;
        self.validate_static_admission(scope, query, classifier, session)?;
        prove_cqn_live_read_only(cx, connection, catalog_cache, query).await?;
        let permit = self.audit_permit(query, auditor, subject)?;
        let registration = connection
            .register_cqn_query(cx, query, binds)
            .await
            .map_err(|_| CqnRegistrationError::DriverRegistrationFailed)?;
        Ok(CqnRegisteredQuery {
            permit,
            registration,
            resource_uri: resource_uri.to_owned(),
        })
    }
}

/// Bind the strict classifier's statement-purity question to the fresh live
/// relation proof obtained immediately before a CQN driver registration.
///
/// CQN is a standing side channel: it must meet the same bar as a one-shot
/// guarded read rather than relying on earlier syntactic admission evidence.
struct CqnResolvedStatementPurity(Purity);

impl SideEffectOracle for CqnResolvedStatementPurity {
    fn statement_purity(&self, _base_objects: &[ObjectRef]) -> Purity {
        self.0
    }
}

/// Re-run the guarded read path's live semantic proof for a CQN target.
///
/// Every dependency is resolved through the exact driver session, then the
/// relation set is checked for views, VPD policy functions, virtual columns,
/// remote objects, and unknown object kinds. Any resolver or purity failure is
/// intentionally collapsed to one fail-closed refusal before CQN audit or
/// driver effects occur.
async fn prove_cqn_live_read_only(
    cx: &Cx,
    connection: &dyn OracleConnection,
    cache: &OracleCatalogResolverCache,
    query: &str,
) -> Result<(), CqnRegistrationError> {
    let plan = semantic_read_plan(query).ok_or(CqnRegistrationError::QueryScopeNotRepresentable)?;
    cache.invalidate(CatalogInvalidation::SemanticProofRefresh);
    let mut names = plan.relations.clone();
    names.extend(plan.values.iter().cloned());
    let context = cache
        .preload(cx, connection, &names, plan.statement_scope)
        .await
        .map_err(|_| CqnRegistrationError::LiveReadProofUnavailable)?;

    let mut relations = Vec::with_capacity(plan.relations.len());
    for name in &plan.relations {
        let Resolution::Resolved(object) = cache.resolve(name, &context) else {
            return Err(CqnRegistrationError::LiveReadProofUnavailable);
        };
        relations.push(*object);
    }
    for name in &plan.values {
        let Resolution::Resolved(object) = cache.resolve(name, &context) else {
            return Err(CqnRegistrationError::LiveReadProofUnavailable);
        };
        if object.kind != CatalogObjectKind::Column {
            return Err(CqnRegistrationError::LiveReadProofUnavailable);
        }
    }

    let purity = resolved_relations_read_purity(cx, connection, &relations)
        .await
        .map_err(|_| CqnRegistrationError::LiveReadProofUnavailable)?;
    if !purity.permits_safe() {
        return Err(CqnRegistrationError::LiveReadProofUnavailable);
    }

    let strict_classifier =
        Classifier::new(ClassifierConfig::new().with_unresolved_qualified_calls_guarded())
            .with_oracle(Arc::new(CqnResolvedStatementPurity(purity)))
            .with_statement_unknown_guarded();
    let decision = strict_classifier.classify(query);
    if decision.danger != DangerLevel::Safe
        || decision.required_level != Some(OperatingLevel::ReadOnly)
    {
        return Err(CqnRegistrationError::LiveReadProofUnavailable);
    }
    Ok(())
}

fn cqn_audit_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format!("unix:{seconds}")
}

/// URI-only binding for one actual QUERY-level CQN registration.
///
/// It has no public constructor: a callback can be routed only through
/// [`CqnRegisteredQuery::callback_fanout`], which consumes registration
/// evidence rather than a client-supplied certificate or raw registration id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CqnCallbackFanout {
    registration_id: u64,
    resource_uri: String,
}

impl CqnCallbackFanout {
    /// Project a driver callback to the bound URI only when its opaque
    /// registration identity matches. The driver record itself was already
    /// reduced to an identity in the DB adapter, so no row, rowid, table, or
    /// query metadata can cross this seam.
    fn project(&self, notification: CqnDriverNotification) -> Option<CqnChangeEvent> {
        (notification.registration_id() == self.registration_id)
            .then(|| CqnChangeEvent::from_bound_resource(self.resource_uri.clone()))
    }
}

/// An event emitted from a CQN callback after it was matched to a registered
/// MCP resource. Its only payload is the bound resource URI: CQN callbacks
/// must never forward row data, column values, rowids, or driver metadata to
/// clients.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CqnChangeEvent {
    resource_uri: String,
}

impl CqnChangeEvent {
    /// The changed MCP resource URI; clients re-read it through the normal
    /// guarded, masked, and egress-controlled read path.
    #[must_use]
    pub fn resource_uri(&self) -> &str {
        &self.resource_uri
    }
}

/// Result of relaying one bounded EMON receive through a subscription hub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CqnFanoutOutcome {
    /// A matching CQN callback was coalesced into its bound resource update.
    Delivered,
    /// A callback for an unknown registration was ignored fail-closed.
    Ignored,
    /// No callback arrived during the bounded receive window.
    TimedOut,
    /// The EMON stream closed; no update was fabricated.
    Closed,
}

impl CqnChangeEvent {
    /// Build a bound event internally after registration-id matching.
    fn from_bound_resource(resource_uri: String) -> Self {
        CqnChangeEvent { resource_uri }
    }
}

/// The reserved subscription-owner key for the single stdio client.
///
/// Stdio has no per-request principal (its `DispatchContext` carries none), so
/// every stdio `resources/subscribe` / `resources/unsubscribe` / drain uses this
/// one stable, server-derived key. It is intentionally distinct from any HTTP
/// principal key (those are mTLS/OAuth-derived or `anonymous-http`), so a future
/// multi-client transport that keys owners off its own principals can never
/// collide with — or drain — the stdio client's subscriptions.
pub const STDIO_SUBSCRIPTION_OWNER: &str = "stdio-local";

/// Per-URI subscriber registry. Cheap, in-process; one per server. Subscribers
/// are keyed by the SERVER-DERIVED owner (principal), never a client-supplied
/// id, so one caller can never enumerate, cancel, or impersonate another.
pub struct SubscriptionRegistry {
    /// Per-principal subscription cap from the active connection profile.
    max_subscriptions_per_principal: u32,
    /// One admitted subscription needs one dedicated EMON notification
    /// connection, so the total active count must never exceed this per-DB
    /// ceiling.
    emon_connection_ceiling: u32,
    state: Arc<Mutex<SubscriptionState>>,
}

#[derive(Default)]
struct SubscriptionState {
    by_uri: HashMap<String, HashSet<String>>,
    active_emon_receivers: HashSet<EmonReceiverKey>,
}

/// A single active receiver is bound to the server-derived owner, registered
/// resource URI, and opaque CQN registration identity. The registry never
/// exposes or accepts this key from clients.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct EmonReceiverKey {
    owner: String,
    resource_uri: String,
    registration_id: u64,
}

/// Non-cloneable ownership of one active EMON receiver slot. Dropping this
/// reservation releases precisely the slot acquired before the driver effect.
struct EmonReceiverReservation {
    state: Arc<Mutex<SubscriptionState>>,
    key: EmonReceiverKey,
}

impl Drop for EmonReceiverReservation {
    fn drop(&mut self) {
        self.state.lock().active_emon_receivers.remove(&self.key);
    }
}

/// Receiver wrapper that retains the registry reservation for exactly the
/// driver's receiver lifetime. There is no caller-controlled release path.
struct ReservedCqnNotificationReceiver {
    receiver: Box<dyn CqnNotificationReceiver>,
    _reservation: EmonReceiverReservation,
}

#[async_trait::async_trait(?Send)]
impl CqnNotificationReceiver for ReservedCqnNotificationReceiver {
    async fn next_notification(
        &mut self,
        cx: &Cx,
    ) -> Result<CqnNotificationOutcome, oraclemcp_db::DbError> {
        self.receiver.next_notification(cx).await
    }
}

/// Result of one atomic subscription admission attempt.
///
/// An idempotent re-subscribe is [`Self::Accepted`]: it neither opens another
/// EMON connection nor consumes another per-principal slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionAdmission {
    /// The subscription was admitted (or it already existed).
    Accepted,
    /// The server-derived principal has reached the profile cap.
    PerPrincipalCapReached,
    /// A further EMON notification connection would exceed the database cap.
    EmonConnectionCeilingReached,
}

impl SubscriptionAdmission {
    /// Whether this attempt leaves the owner subscribed to the URI.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

impl Default for SubscriptionRegistry {
    fn default() -> Self {
        // A registry without a resolved runtime profile must remain bounded.
        // C1.4 wiring supplies the actual database ceiling through
        // `for_profile`; until then the conservative profile default is safer
        // than treating the ceiling as unbounded.
        Self::with_limits(DEFAULT_MAX_SUBSCRIPTIONS, DEFAULT_MAX_SUBSCRIPTIONS)
    }
}

impl SubscriptionRegistry {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry bounded by `profile` and the already-resolved runtime
    /// database connection ceiling.
    ///
    /// The ceiling must be the effective pool ceiling after any runtime clamp,
    /// rather than a client value. Every admitted `owner`/`uri` pair reserves
    /// one EMON notification connection against it.
    #[must_use]
    pub fn for_profile(profile: &ConnectionProfile, emon_connection_ceiling: u32) -> Self {
        Self::with_limits(profile.max_subscriptions(), emon_connection_ceiling)
    }

    /// A registry with explicit, server-derived resource limits. This is the
    /// narrow integration seam used after database pool sizing is resolved.
    #[must_use]
    pub fn with_limits(max_subscriptions_per_principal: u32, emon_connection_ceiling: u32) -> Self {
        SubscriptionRegistry {
            max_subscriptions_per_principal,
            emon_connection_ceiling,
            state: Arc::new(Mutex::new(SubscriptionState::default())),
        }
    }

    /// Subscribe `client` to `uri` atomically with its per-principal and EMON
    /// resource accounting. `client` must be the server-derived principal.
    ///
    /// The rejection happens before the registry changes, so it cannot leave a
    /// subscription visible without an accounted EMON connection.
    pub fn subscribe(&self, client: &str, uri: &str) -> SubscriptionAdmission {
        let mut state = self.state.lock();
        if state
            .by_uri
            .get(uri)
            .is_some_and(|subscribers| subscribers.contains(client))
        {
            return SubscriptionAdmission::Accepted;
        }

        let active_for_client = state
            .by_uri
            .values()
            .filter(|subscribers| subscribers.contains(client))
            .count();
        if active_for_client >= self.max_subscriptions_per_principal as usize {
            return SubscriptionAdmission::PerPrincipalCapReached;
        }
        let receiver_already_owns_pair = state
            .active_emon_receivers
            .iter()
            .any(|receiver| receiver.owner == client && receiver.resource_uri == uri);
        if !receiver_already_owns_pair
            && Self::emon_connection_count_locked(&state) >= self.emon_connection_ceiling as usize
        {
            return SubscriptionAdmission::EmonConnectionCeilingReached;
        }

        state
            .by_uri
            .entry(uri.to_owned())
            .or_default()
            .insert(client.to_owned());
        SubscriptionAdmission::Accepted
    }

    /// Unsubscribe `client` from `uri`. Idempotent; drops the URI entry when its
    /// last subscriber leaves.
    pub fn unsubscribe(&self, client: &str, uri: &str) {
        let mut state = self.state.lock();
        if let Some(set) = state.by_uri.get_mut(uri) {
            set.remove(client);
            if set.is_empty() {
                state.by_uri.remove(uri);
            }
        }
    }

    /// Drop all of `client`'s subscriptions (on disconnect).
    pub fn unsubscribe_all(&self, client: &str) {
        let mut state = self.state.lock();
        state.by_uri.retain(|_, set| {
            set.remove(client);
            !set.is_empty()
        });
    }

    /// Every URI with at least one subscriber (sorted). Used by the polling
    /// hub to know which resources to fingerprint.
    #[must_use]
    pub fn subscribed_uris(&self) -> Vec<String> {
        let state = self.state.lock();
        let mut out: Vec<String> = state.by_uri.keys().cloned().collect();
        out.sort();
        out
    }

    /// The clients to notify for `uri` (sorted, deduped).
    #[must_use]
    pub fn subscribers_of(&self, uri: &str) -> Vec<String> {
        let state = self.state.lock();
        let mut out: Vec<String> = state
            .by_uri
            .get(uri)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        out.sort();
        out
    }

    /// Whether `client` is subscribed to `uri`.
    #[must_use]
    pub fn is_subscribed(&self, client: &str, uri: &str) -> bool {
        self.state
            .lock()
            .by_uri
            .get(uri)
            .is_some_and(|s| s.contains(client))
    }

    /// Active client/URI subscriptions plus receiver slots which outlived an
    /// unsubscribe. Every item has one accounted EMON notification connection.
    #[must_use]
    pub fn emon_connection_count(&self) -> usize {
        Self::emon_connection_count_locked(&self.state.lock())
    }

    /// The server-derived ceiling that caps [`Self::emon_connection_count`].
    #[must_use]
    pub const fn emon_connection_ceiling(&self) -> u32 {
        self.emon_connection_ceiling
    }

    /// Atomically reserve the receiver slot at the actual EMON effect point.
    ///
    /// This is intentionally private: only [`CqnRegisteredQuery`] can present
    /// the registered query id, and its public receiver-opening method always
    /// supplies the registry and server-derived owner.
    fn reserve_emon_receiver(
        &self,
        owner: &str,
        resource_uri: &str,
        registration_id: u64,
    ) -> Result<EmonReceiverReservation, CqnEmonOpenError> {
        let mut state = self.state.lock();
        if !Self::is_subscribed_locked(&state.by_uri, owner, resource_uri) {
            return Err(CqnEmonOpenError::SubscriptionNotAdmitted);
        }
        if state
            .active_emon_receivers
            .iter()
            .any(|receiver| receiver.owner == owner && receiver.resource_uri == resource_uri)
        {
            return Err(CqnEmonOpenError::ReceiverAlreadyOpen);
        }

        let key = EmonReceiverKey {
            owner: owner.to_owned(),
            resource_uri: resource_uri.to_owned(),
            registration_id,
        };
        let inserted = state.active_emon_receivers.insert(key.clone());
        debug_assert!(inserted, "receiver reservation was already present");
        Ok(EmonReceiverReservation {
            state: Arc::clone(&self.state),
            key,
        })
    }

    fn is_subscribed_locked(
        by_uri: &HashMap<String, HashSet<String>>,
        owner: &str,
        resource_uri: &str,
    ) -> bool {
        by_uri
            .get(resource_uri)
            .is_some_and(|subscribers| subscribers.contains(owner))
    }

    fn emon_connection_count_locked(state: &SubscriptionState) -> usize {
        let admitted = state.by_uri.values().map(HashSet::len).sum::<usize>();
        let receivers_without_admission = state
            .active_emon_receivers
            .iter()
            .filter(|receiver| {
                !Self::is_subscribed_locked(&state.by_uri, &receiver.owner, &receiver.resource_uri)
            })
            .count();
        admitted + receivers_without_admission
    }
}

/// A polling change source (E1 fallback). The hub calls [`PollingSource::poll`]
/// for each subscribed URI to learn its current fingerprint; when the
/// fingerprint differs from the last one the hub saw, the resource is reported
/// changed and a `resources/updated` is emitted to its subscribers. The
/// fingerprint is opaque (e.g. a `LAST_DDL_TIME` hash, a row-count + checksum);
/// the hub only compares for inequality.
///
/// `poll` returns `None` when the source cannot fingerprint a URI (e.g. an
/// ephemeral resource), in which case the hub reports no change.
pub trait PollingSource: Send + Sync {
    /// The current opaque fingerprint of `uri`, or `None` if not pollable.
    fn poll(&self, uri: &str) -> Option<String>;
}

/// The confirmed change-detection source backing `resources/subscribe` (E1).
/// The capability is advertised iff this is not [`SubscribeSource::Unsupported`].
pub enum SubscribeSource {
    /// No working source — `resources/subscribe` is unsupported and unadvertised.
    Unsupported,
    /// The polling fallback: re-read resource fingerprints on a cadence.
    Polling(Box<dyn PollingSource>),
    /// Oracle CQN source. Constructing its URI-bound callback fan-out requires
    /// an actual QUERY-level registration from
    /// [`CqnRegistrationGate::register_query`], so a caller cannot enable the
    /// standing channel with a replayed certificate or without profile opt-in,
    /// classifier proof, active step-up, durable audit, and the driver
    /// accepting the exact query.
    ChangeNotification(CqnCallbackFanout),
}

impl SubscribeSource {
    /// Whether this source supports subscriptions (and so the capability may be
    /// advertised).
    #[must_use]
    pub fn is_supported(&self) -> bool {
        !matches!(self, SubscribeSource::Unsupported)
    }
}

/// The subscription hub: the per-URI subscriber [`SubscriptionRegistry`], the
/// confirmed change source (the capability gate), the last-seen fingerprints
/// for the polling fallback, and the pending `resources/updated` notifications
/// the transport drains.
///
/// `pending` is keyed by the SERVER-DERIVED owner (principal). A change to a
/// watched URI enqueues one copy for each subscriber (owner) of that URI, and a
/// drain returns only the CALLING owner's queue — so on a multi-client transport
/// one client can never drain another's updates. There is no shared global
/// queue.
pub struct SubscriptionHub {
    registry: SubscriptionRegistry,
    source: SubscribeSource,
    fingerprints: Mutex<HashMap<String, String>>,
    pending: Mutex<HashMap<String, VecDeque<String>>>,
}

impl Default for SubscriptionHub {
    fn default() -> Self {
        Self::unsupported()
    }
}

impl SubscriptionHub {
    /// A hub with NO change source: `resources/subscribe` is unsupported and the
    /// capability is not advertised (E1 fail-closed default).
    #[must_use]
    pub fn unsupported() -> Self {
        SubscriptionHub {
            registry: SubscriptionRegistry::new(),
            source: SubscribeSource::Unsupported,
            fingerprints: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// A hub backed by a confirmed change `source`. When the source supports
    /// subscriptions, the capability is advertised and `resources/subscribe`
    /// works.
    #[must_use]
    pub fn with_source(source: SubscribeSource) -> Self {
        SubscriptionHub {
            registry: SubscriptionRegistry::new(),
            source,
            fingerprints: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// A hub bounded by the active profile and actual database connection
    /// ceiling. The profile cap constrains each server-derived principal; the
    /// resolved database ceiling constrains all EMON connections together.
    #[must_use]
    pub fn with_source_for_profile(
        source: SubscribeSource,
        profile: &ConnectionProfile,
        emon_connection_ceiling: u32,
    ) -> Self {
        SubscriptionHub {
            registry: SubscriptionRegistry::for_profile(profile, emon_connection_ceiling),
            source,
            fingerprints: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Whether subscriptions are supported (the capability gate).
    #[must_use]
    pub fn supports_subscriptions(&self) -> bool {
        self.source.is_supported()
    }

    /// Subscribe `owner` to `uri`. `owner` MUST be the server-derived principal
    /// (never a client-supplied id). Seeds the baseline fingerprint from the
    /// polling source so the first change (not the first poll) fires an update.
    /// Returns `false` when subscriptions are unsupported (the caller maps that
    /// to a method/feature error).
    pub fn subscribe(&self, owner: &str, uri: &str) -> bool {
        if !self.supports_subscriptions() {
            return false;
        }
        if !self.registry.subscribe(owner, uri).is_accepted() {
            return false;
        }
        if let SubscribeSource::Polling(source) = &self.source
            && let Some(fp) = source.poll(uri)
        {
            self.fingerprints.lock().insert(uri.to_owned(), fp);
        }
        true
    }

    /// Unsubscribe `owner` from `uri`. Scoped to `owner`: one principal can only
    /// drop its own subscription, never another's.
    pub fn unsubscribe(&self, owner: &str, uri: &str) {
        self.registry.unsubscribe(owner, uri);
    }

    /// Drop all of `owner`'s subscriptions AND its pending updates (on
    /// disconnect). Touches only `owner`; other principals are unaffected.
    pub fn unsubscribe_all(&self, owner: &str) {
        self.registry.unsubscribe_all(owner);
        self.pending.lock().remove(owner);
    }

    /// Poll every subscribed URI through the polling source; for each whose
    /// fingerprint changed, enqueue a `resources/updated` for each of that URI's
    /// subscribers and return the changed URIs. A no-op (returns empty) when the
    /// source is not polling.
    pub fn poll_for_changes(&self) -> Vec<String> {
        let SubscribeSource::Polling(source) = &self.source else {
            return Vec::new();
        };
        let uris = self.registry.subscribed_uris();
        let mut changed = Vec::new();
        let mut fingerprints = self.fingerprints.lock();
        for uri in uris {
            let Some(current) = source.poll(&uri) else {
                continue;
            };
            let prior = fingerprints.get(&uri).cloned();
            if prior.as_ref() != Some(&current) {
                fingerprints.insert(uri.clone(), current);
                // Only an actual change (we had a prior fingerprint that
                // differs) fires; the very first observation just seeds.
                if prior.is_some() {
                    changed.push(uri);
                }
            }
        }
        drop(fingerprints);
        self.enqueue_updates(&changed);
        changed
    }

    /// Directly mark `uri` changed (used when an out-of-band signal — e.g. a
    /// DDL the server itself just applied — is known without polling). Enqueues
    /// a `resources/updated` for each of its subscribers.
    pub fn mark_changed(&self, uri: &str) {
        self.enqueue_updates(std::slice::from_ref(&uri.to_owned()));
    }

    /// Relay one bounded EMON receive as an event-only MCP resource update.
    ///
    /// No callback payload can cross this seam: the database adapter emits
    /// only an opaque registration identity, and the CQN source maps a matching
    /// identity to its already-bound URI. A client must re-read through the
    /// ordinary classifier, masking, and egress path to see any data.
    pub async fn relay_cqn_callback(
        &self,
        cx: &Cx,
        receiver: &mut dyn CqnNotificationReceiver,
    ) -> Result<CqnFanoutOutcome, oraclemcp_db::DbError> {
        match receiver.next_notification(cx).await? {
            CqnNotificationOutcome::Event(notification) => {
                Ok(if self.forward_cqn_notification(notification) {
                    CqnFanoutOutcome::Delivered
                } else {
                    CqnFanoutOutcome::Ignored
                })
            }
            CqnNotificationOutcome::TimedOut => Ok(CqnFanoutOutcome::TimedOut),
            CqnNotificationOutcome::Closed => Ok(CqnFanoutOutcome::Closed),
        }
    }

    /// Deliver one driver-reduced callback to the matching CQN source.
    ///
    /// Returns `false` when CQN is not the active source or the opaque
    /// registration id does not match. Either case is ignored rather than
    /// generating a client-visible event.
    pub fn forward_cqn_notification(&self, notification: CqnDriverNotification) -> bool {
        let SubscribeSource::ChangeNotification(fanout) = &self.source else {
            return false;
        };
        let Some(event) = fanout.project(notification) else {
            return false;
        };
        self.mark_changed(event.resource_uri());
        true
    }

    /// Fan a set of changed URIs out to their subscribers, coalescing duplicate
    /// pending `resources/updated` entries per owner and URI. Subscribers are
    /// resolved through the registry BEFORE the `pending` lock is taken, so the
    /// lock order is always registry→pending and never inverts. A URI with no
    /// subscribers enqueues nothing.
    fn enqueue_updates(&self, changed: &[String]) {
        if changed.is_empty() {
            return;
        }
        let fanned: Vec<(String, Vec<String>)> = changed
            .iter()
            .map(|uri| (uri.clone(), self.registry.subscribers_of(uri)))
            .collect();
        let mut pending = self.pending.lock();
        for (uri, owners) in fanned {
            for owner in owners {
                let queue = pending.entry(owner).or_default();
                if !queue.iter().any(|queued_uri| queued_uri == &uri) {
                    queue.push_back(uri.clone());
                }
            }
        }
    }

    /// Drain `owner`'s queued `resources/updated` URIs (the transport turns each
    /// into a `notifications/resources/updated` JSON-RPC notification). Returns
    /// ONLY `owner`'s pending updates; another principal's queue is untouched.
    pub fn drain_pending(&self, owner: &str) -> Vec<String> {
        let mut pending = self.pending.lock();
        let Some(queue) = pending.get_mut(owner) else {
            return Vec::new();
        };
        let drained: Vec<String> = queue.drain(..).collect();
        if queue.is_empty() {
            pending.remove(owner);
        }
        drained
    }

    /// The subscriber registry (for introspection/tests).
    #[must_use]
    pub fn registry(&self) -> &SubscriptionRegistry {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use oraclemcp_audit::{AuditError, AuditRecord, AuditSink, MemoryAuditSink, SigningKey};
    use oraclemcp_config::OracleMcpConfig;
    use oraclemcp_db::{DbError, OracleBackend, OracleCell, OracleConnectionInfo, OracleRow};

    const URI: &str = "oracle://object/HR/PACKAGE/EMP_API";

    struct SharedMemoryAuditSink(Arc<MemoryAuditSink>);

    impl AuditSink for SharedMemoryAuditSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }

        fn append_with_verdict_certificate(
            &self,
            record: &AuditRecord,
            certificate: &oraclemcp_audit::BoundAuditVerdictCertificate,
        ) -> Result<(), AuditError> {
            self.0.append_with_verdict_certificate(record, certificate)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    struct RefusingAuditSink;

    impl AuditSink for RefusingAuditSink {
        fn append(&self, _record: &AuditRecord) -> Result<(), AuditError> {
            Err(AuditError::Io("synthetic audit failure".to_owned()))
        }

        fn append_with_verdict_certificate(
            &self,
            _record: &AuditRecord,
            _certificate: &oraclemcp_audit::BoundAuditVerdictCertificate,
        ) -> Result<(), AuditError> {
            Err(AuditError::Io("synthetic audit failure".to_owned()))
        }

        fn flush(&self) -> Result<(), AuditError> {
            Err(AuditError::Io("synthetic audit failure".to_owned()))
        }
    }

    fn cqn_profile(enabled: bool) -> ConnectionProfile {
        let enabled_line = if enabled {
            "allow_change_notification = true"
        } else {
            ""
        };
        OracleMcpConfig::from_toml_str(&format!(
            r#"
            [[profiles]]
            name = "cqn"
            connect_string = "synthetic:1521/service"
            max_level = "READ_WRITE"
            {enabled_line}
            "#
        ))
        .expect("synthetic CQN profile parses")
        .profiles
        .into_iter()
        .next()
        .expect("one profile")
    }

    fn cqn_auditor() -> (Auditor, Arc<MemoryAuditSink>) {
        let sink = Arc::new(MemoryAuditSink::new());
        let key = SigningKey::new("cqn-test", vec![7; 32]).expect("test signing key");
        (
            Auditor::new(Box::new(SharedMemoryAuditSink(Arc::clone(&sink))), key),
            sink,
        )
    }

    fn stepped_up_session() -> SessionLevelState {
        let mut session = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        session
            .escalate_window(OperatingLevel::ReadWrite, Duration::from_secs(60))
            .expect("READ_WRITE fits the synthetic ceiling");
        session
    }

    fn subject() -> AuditSubject {
        AuditSubject::new("test", "cqn-client")
    }

    const PROVEN_QUERY: &str = "SELECT id FROM app.cqn_target";
    const UNPROVEN_VIEW_QUERY: &str = "SELECT id FROM app.unproven_view";

    #[derive(Clone, Copy, Default)]
    enum CqnCatalogFixture {
        #[default]
        CleanTable,
        UnprovenView,
        SelectVpdPolicy,
        VirtualColumn,
    }

    impl CqnCatalogFixture {
        fn object_type(self) -> &'static str {
            match self {
                Self::CleanTable | Self::SelectVpdPolicy | Self::VirtualColumn => "TABLE",
                Self::UnprovenView => "VIEW",
            }
        }

        fn object_name(self) -> &'static str {
            match self {
                Self::UnprovenView => "UNPROVEN_VIEW",
                Self::CleanTable | Self::SelectVpdPolicy | Self::VirtualColumn => "CQN_TARGET",
            }
        }

        fn has_select_vpd_policy(self) -> bool {
            matches!(self, Self::SelectVpdPolicy)
        }

        fn has_virtual_column(self) -> bool {
            matches!(self, Self::VirtualColumn)
        }
    }

    #[derive(Default)]
    struct RecordingCqnConnection {
        registrations: Mutex<Vec<(String, Vec<OracleBind>)>>,
        emon_open_attempts: Mutex<Vec<CqnQueryRegistration>>,
        reject_emon_open: AtomicBool,
        catalog_fixture: CqnCatalogFixture,
    }

    impl RecordingCqnConnection {
        fn with_catalog_fixture(catalog_fixture: CqnCatalogFixture) -> Self {
            Self {
                catalog_fixture,
                ..Self::default()
            }
        }
    }

    fn catalog_row(columns: &[(&str, Option<&str>)]) -> OracleRow {
        OracleRow {
            columns: columns
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

    /// A deterministic EMON seam that exposes only the DB adapter's reduced
    /// notification outcome. It cannot carry table names, rowids, or values.
    struct ScriptedCqnReceiver {
        outcome: CqnNotificationOutcome,
    }

    #[async_trait::async_trait(?Send)]
    impl CqnNotificationReceiver for ScriptedCqnReceiver {
        async fn next_notification(&mut self, _cx: &Cx) -> Result<CqnNotificationOutcome, DbError> {
            Ok(self.outcome)
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for RecordingCqnConnection {
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
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            if sql.contains("SYS_CONTEXT('USERENV', 'SESSION_USER')") {
                return Ok(vec![catalog_row(&[
                    ("SESSION_USER", Some("TEST")),
                    ("CURRENT_SCHEMA", Some("APP")),
                    ("EDITION_NAME", Some("ORA$BASE")),
                ])]);
            }
            if sql.contains("FROM session_roles") {
                return Ok(Vec::new());
            }
            if sql.contains("FROM all_objects WHERE") {
                return Ok(vec![catalog_row(&[
                    ("OWNER", Some("APP")),
                    ("OBJECT_NAME", Some(self.catalog_fixture.object_name())),
                    ("OBJECT_TYPE", Some(self.catalog_fixture.object_type())),
                    ("OBJECT_ID", Some("42")),
                    ("STATUS", Some("VALID")),
                    ("EDITION_NAME", Some("ORA$BASE")),
                ])]);
            }
            if sql.contains("FROM all_tab_columns") && sql.contains("column_name = :3") {
                return Ok(vec![catalog_row(&[
                    ("COLUMN_NAME", Some("ID")),
                    ("COLUMN_ID", Some("1")),
                ])]);
            }
            if sql.contains("FROM all_policies") {
                return Ok(if self.catalog_fixture.has_select_vpd_policy() {
                    vec![catalog_row(&[("POLICY_NAME", Some("CQN_POLICY"))])]
                } else {
                    Vec::new()
                });
            }
            if sql.contains("FROM all_tab_cols") && sql.contains("virtual_column = 'YES'") {
                return Ok(if self.catalog_fixture.has_virtual_column() {
                    vec![catalog_row(&[("COLUMN_NAME", Some("COMPUTED"))])]
                } else {
                    Vec::new()
                });
            }
            Err(DbError::Query("unexpected catalog query".to_owned()))
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn register_cqn_query(
            &self,
            _cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<CqnQueryRegistration, DbError> {
            let mut registrations = self.registrations.lock();
            let sequence = registrations.len() as u64 + 1;
            registrations.push((sql.to_owned(), binds.to_vec()));
            Ok(CqnQueryRegistration::new(100 + sequence, 201 + sequence))
        }

        async fn open_cqn_notification_receiver(
            &self,
            _cx: &Cx,
            registration: CqnQueryRegistration,
        ) -> Result<Box<dyn CqnNotificationReceiver>, DbError> {
            self.emon_open_attempts.lock().push(registration);
            if self.reject_emon_open.load(Ordering::Relaxed) {
                return Err(DbError::Query("synthetic EMON open failure".to_owned()));
            }
            Ok(Box::new(ScriptedCqnReceiver {
                outcome: CqnNotificationOutcome::Closed,
            }))
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    async fn register_cqn_for_uri(
        cx: &Cx,
        gate: &CqnRegistrationGate,
        connection: &dyn OracleConnection,
        catalog_cache: &OracleCatalogResolverCache,
        auditor: &Auditor,
        resource_uri: &str,
    ) -> CqnRegisteredQuery {
        gate.register_query(
            cx,
            connection,
            CqnQueryRegistrationRequest::new(
                CqnRegistrationScope::Query,
                PROVEN_QUERY,
                &[],
                &Classifier::default(),
                &stepped_up_session(),
                Some(auditor),
                subject(),
            )
            .with_catalog_cache(catalog_cache)
            .with_resource_uri(resource_uri),
        )
        .await
        .expect("the exact classifier-proven query is registered")
    }

    #[test]
    fn cqn_is_disabled_until_the_profile_explicitly_permits_it() {
        let profile = cqn_profile(false);
        let gate = CqnRegistrationGate::from_profile(&profile);
        let (auditor, sink) = cqn_auditor();

        let result = gate.authorize(
            CqnRegistrationScope::Query,
            PROVEN_QUERY,
            &Classifier::default(),
            &stepped_up_session(),
            Some(&auditor),
            subject(),
        );

        assert!(matches!(
            result,
            Err(CqnRegistrationError::ProfileNotPermitted)
        ));
        assert!(
            sink.records().is_empty(),
            "a refused registration is not audited as allowed"
        );
    }

    #[test]
    fn cqn_refuses_object_scope_before_any_driver_or_audit_effect() {
        let profile = cqn_profile(true);
        let gate = CqnRegistrationGate::from_profile(&profile);
        let (auditor, sink) = cqn_auditor();

        let result = gate.authorize(
            CqnRegistrationScope::Object,
            PROVEN_QUERY,
            &Classifier::default(),
            &stepped_up_session(),
            Some(&auditor),
            subject(),
        );

        assert!(matches!(
            result,
            Err(CqnRegistrationError::ObjectLevelRefused)
        ));
        assert!(sink.records().is_empty());
    }

    #[test]
    fn cqn_effect_point_refuses_object_scope_before_the_db_adapter() {
        let profile = cqn_profile(true);
        let gate = CqnRegistrationGate::from_profile(&profile);
        let (auditor, sink) = cqn_auditor();
        let connection = RecordingCqnConnection::default();
        let catalog_cache = OracleCatalogResolverCache::new();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");

        let result = runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a current Cx");
            gate.register_query(
                &cx,
                &connection,
                CqnQueryRegistrationRequest::new(
                    CqnRegistrationScope::Object,
                    PROVEN_QUERY,
                    &[],
                    &Classifier::default(),
                    &stepped_up_session(),
                    Some(&auditor),
                    subject(),
                )
                .with_catalog_cache(&catalog_cache)
                .with_resource_uri(URI),
            )
            .await
        });

        assert!(matches!(
            result,
            Err(CqnRegistrationError::ObjectLevelRefused)
        ));
        assert!(connection.registrations.lock().is_empty());
        assert!(sink.records().is_empty());
    }

    #[test]
    fn cqn_effect_point_refuses_without_a_live_catalog_proof() {
        let profile = cqn_profile(true);
        let gate = CqnRegistrationGate::from_profile(&profile);
        let (auditor, sink) = cqn_auditor();
        let connection = RecordingCqnConnection::default();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");

        let result = runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a current Cx");
            gate.register_query(
                &cx,
                &connection,
                CqnQueryRegistrationRequest::new(
                    CqnRegistrationScope::Query,
                    PROVEN_QUERY,
                    &[],
                    &Classifier::default(),
                    &stepped_up_session(),
                    Some(&auditor),
                    subject(),
                )
                .with_resource_uri(URI),
            )
            .await
        });

        assert!(matches!(
            result,
            Err(CqnRegistrationError::LiveReadProofUnavailable)
        ));
        assert!(connection.registrations.lock().is_empty());
        assert!(sink.records().is_empty());
    }

    #[test]
    fn cqn_effect_point_refuses_an_unbound_resource_uri_before_the_db_adapter() {
        let profile = cqn_profile(true);
        let gate = CqnRegistrationGate::from_profile(&profile);
        let (auditor, sink) = cqn_auditor();
        let connection = RecordingCqnConnection::default();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");

        let result = runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a current Cx");
            gate.register_query(
                &cx,
                &connection,
                CqnQueryRegistrationRequest::new(
                    CqnRegistrationScope::Query,
                    PROVEN_QUERY,
                    &[],
                    &Classifier::default(),
                    &stepped_up_session(),
                    Some(&auditor),
                    subject(),
                ),
            )
            .await
        });

        assert!(matches!(
            result,
            Err(CqnRegistrationError::ResourceUriRequired)
        ));
        assert!(connection.registrations.lock().is_empty());
        assert!(sink.records().is_empty());
    }

    #[test]
    fn cqn_refuses_unproven_live_relations_before_audit_or_driver_effect() {
        for (fixture, query, label) in [
            (CqnCatalogFixture::UnprovenView, UNPROVEN_VIEW_QUERY, "view"),
            (
                CqnCatalogFixture::SelectVpdPolicy,
                PROVEN_QUERY,
                "SELECT VPD policy",
            ),
            (
                CqnCatalogFixture::VirtualColumn,
                PROVEN_QUERY,
                "virtual column",
            ),
        ] {
            let profile = cqn_profile(true);
            let gate = CqnRegistrationGate::from_profile(&profile);
            let (auditor, sink) = cqn_auditor();
            let connection = RecordingCqnConnection::with_catalog_fixture(fixture);
            let catalog_cache = OracleCatalogResolverCache::new();
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .build()
                .expect("current-thread runtime");

            let result = runtime.block_on(async {
                let cx = Cx::current().expect("runtime installs a current Cx");
                gate.register_query(
                    &cx,
                    &connection,
                    CqnQueryRegistrationRequest::new(
                        CqnRegistrationScope::Query,
                        query,
                        &[],
                        &Classifier::default(),
                        &stepped_up_session(),
                        Some(&auditor),
                        subject(),
                    )
                    .with_catalog_cache(&catalog_cache)
                    .with_resource_uri(URI),
                )
                .await
            });

            assert!(
                matches!(result, Err(CqnRegistrationError::LiveReadProofUnavailable)),
                "{label} must be refused without a live relation-purity proof"
            );
            assert!(
                connection.registrations.lock().is_empty(),
                "{label} must not reach register_cqn_query"
            );
            assert!(
                sink.records().is_empty(),
                "{label} refusal must occur before an allowed audit record"
            );
        }
    }

    #[test]
    fn cqn_demands_an_active_confirmed_step_up_not_only_a_writable_baseline() {
        let profile = cqn_profile(true);
        let gate = CqnRegistrationGate::from_profile(&profile);
        let (auditor, sink) = cqn_auditor();
        let baseline_writable = SessionLevelState::new(OperatingLevel::ReadWrite, false);

        let result = gate.authorize(
            CqnRegistrationScope::Query,
            PROVEN_QUERY,
            &Classifier::default(),
            &baseline_writable,
            Some(&auditor),
            subject(),
        );

        assert!(matches!(result, Err(CqnRegistrationError::StepUpRequired)));
        assert!(sink.records().is_empty());
    }

    #[test]
    fn cqn_refuses_a_query_the_classifier_cannot_prove_read_only() {
        let profile = cqn_profile(true);
        let gate = CqnRegistrationGate::from_profile(&profile);
        let (auditor, sink) = cqn_auditor();

        let result = gate.authorize(
            CqnRegistrationScope::Query,
            "SELECT employee_id FROM hr.employees FOR UPDATE",
            &Classifier::default(),
            &stepped_up_session(),
            Some(&auditor),
            subject(),
        );

        assert!(matches!(
            result,
            Err(CqnRegistrationError::QueryNotReadOnly)
        ));
        assert!(sink.records().is_empty());
    }

    #[test]
    fn cqn_permit_is_audited_before_return_and_bound_to_one_query_and_profile() {
        let profile = cqn_profile(true);
        let gate = CqnRegistrationGate::from_profile(&profile);
        let (auditor, sink) = cqn_auditor();

        let permit = gate
            .authorize(
                CqnRegistrationScope::Query,
                PROVEN_QUERY,
                &Classifier::default(),
                &stepped_up_session(),
                Some(&auditor),
                subject(),
            )
            .expect("the explicit, stepped-up, proven query is admitted");

        assert!(permit.is_bound_to("cqn", PROVEN_QUERY));
        assert!(!permit.is_bound_to("other-profile", PROVEN_QUERY));
        assert!(!permit.is_bound_to("cqn", "SELECT * FROM hr.employees"));
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tool, "oracle_cqn_register_query");
        assert_eq!(records[0].danger_level, "READ_WRITE");
        assert_eq!(
            sink.flush_count(),
            1,
            "CQN audit evidence is durable before permit return"
        );
    }

    #[test]
    fn cqn_refuses_to_issue_a_permit_when_the_audit_append_fails() {
        let profile = cqn_profile(true);
        let gate = CqnRegistrationGate::from_profile(&profile);
        let key = SigningKey::new("cqn-test", vec![7; 32]).expect("test signing key");
        let auditor = Auditor::new(Box::new(RefusingAuditSink), key);

        let result = gate.authorize(
            CqnRegistrationScope::Query,
            PROVEN_QUERY,
            &Classifier::default(),
            &stepped_up_session(),
            Some(&auditor),
            subject(),
        );

        assert!(matches!(
            result,
            Err(CqnRegistrationError::AuditAppendFailed)
        ));
    }

    #[test]
    fn cqn_emon_open_requires_an_owner_bound_reservation_for_every_receiver() {
        const SECOND_URI: &str = "oracle://object/HR/PACKAGE/SECOND_API";
        const THIRD_URI: &str = "oracle://object/HR/PACKAGE/THIRD_API";

        let profile = cqn_profile(true);
        let gate = CqnRegistrationGate::from_profile(&profile);
        let (auditor, _sink) = cqn_auditor();
        let connection = RecordingCqnConnection::default();
        let catalog_cache = OracleCatalogResolverCache::new();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        let (registered, principal_capped, database_capped) = runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a current Cx");
            (
                register_cqn_for_uri(&cx, &gate, &connection, &catalog_cache, &auditor, URI).await,
                register_cqn_for_uri(
                    &cx,
                    &gate,
                    &connection,
                    &catalog_cache,
                    &auditor,
                    SECOND_URI,
                )
                .await,
                register_cqn_for_uri(&cx, &gate, &connection, &catalog_cache, &auditor, THIRD_URI)
                    .await,
            )
        });
        let registry = SubscriptionRegistry::with_limits(1, 1);

        let unadmitted = runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a current Cx");
            registered
                .open_emon_receiver(&cx, &connection, &registry, "principal-a")
                .await
        });
        assert!(matches!(
            unadmitted,
            Err(CqnEmonOpenError::SubscriptionNotAdmitted)
        ));
        assert!(
            connection.emon_open_attempts.lock().is_empty(),
            "opening without registry admission must not reach the driver"
        );

        assert_eq!(
            registry.subscribe("principal-a", URI),
            SubscriptionAdmission::Accepted
        );
        assert_eq!(
            registry.subscribe("principal-a", SECOND_URI),
            SubscriptionAdmission::PerPrincipalCapReached
        );
        let principal_cap = runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a current Cx");
            principal_capped
                .open_emon_receiver(&cx, &connection, &registry, "principal-a")
                .await
        });
        assert!(matches!(
            principal_cap,
            Err(CqnEmonOpenError::SubscriptionNotAdmitted)
        ));

        assert_eq!(
            registry.subscribe("principal-b", THIRD_URI),
            SubscriptionAdmission::EmonConnectionCeilingReached
        );
        let database_cap = runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a current Cx");
            database_capped
                .open_emon_receiver(&cx, &connection, &registry, "principal-b")
                .await
        });
        assert!(matches!(
            database_cap,
            Err(CqnEmonOpenError::SubscriptionNotAdmitted)
        ));
        assert!(
            connection.emon_open_attempts.lock().is_empty(),
            "cap-refused admissions must not create a driver receiver"
        );

        let receiver = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime installs a current Cx");
                registered
                    .open_emon_receiver(&cx, &connection, &registry, "principal-a")
                    .await
            })
            .expect("the admitted owner may open exactly one receiver");
        assert_eq!(connection.emon_open_attempts.lock().len(), 1);

        let repeated = runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a current Cx");
            registered
                .open_emon_receiver(&cx, &connection, &registry, "principal-a")
                .await
        });
        assert!(matches!(
            repeated,
            Err(CqnEmonOpenError::ReceiverAlreadyOpen)
        ));
        assert_eq!(
            connection.emon_open_attempts.lock().len(),
            1,
            "the N+1th open is refused before it reaches the driver"
        );

        registry.unsubscribe("principal-a", URI);
        assert_eq!(
            registry.emon_connection_count(),
            1,
            "an active receiver remains accounted after its subscription is removed"
        );
        drop(receiver);
        assert_eq!(
            registry.emon_connection_count(),
            0,
            "receiver teardown releases its reservation exactly once"
        );

        assert_eq!(
            registry.subscribe("principal-a", URI),
            SubscriptionAdmission::Accepted
        );
        connection.reject_emon_open.store(true, Ordering::Relaxed);
        let driver_failure = runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a current Cx");
            registered
                .open_emon_receiver(&cx, &connection, &registry, "principal-a")
                .await
        });
        assert!(matches!(driver_failure, Err(CqnEmonOpenError::Driver(_))));
        connection.reject_emon_open.store(false, Ordering::Relaxed);
        let retry_after_failure = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime installs a current Cx");
                registered
                    .open_emon_receiver(&cx, &connection, &registry, "principal-a")
                    .await
            })
            .expect("a failed driver open releases the reservation for one retry");
        assert_eq!(connection.emon_open_attempts.lock().len(), 3);
        drop(retry_after_failure);
    }

    #[test]
    fn cqn_emon_callback_relay_is_uri_only_and_coalesced() {
        let profile = cqn_profile(true);
        let gate = CqnRegistrationGate::from_profile(&profile);
        let (auditor, _sink) = cqn_auditor();
        let connection = RecordingCqnConnection::default();
        let catalog_cache = OracleCatalogResolverCache::new();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        let registered = runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a current Cx");
            gate.register_query(
                &cx,
                &connection,
                CqnQueryRegistrationRequest::new(
                    CqnRegistrationScope::Query,
                    PROVEN_QUERY,
                    &[],
                    &Classifier::default(),
                    &stepped_up_session(),
                    Some(&auditor),
                    subject(),
                )
                .with_catalog_cache(&catalog_cache)
                .with_resource_uri(URI),
            )
            .await
            .expect("the exact classifier-proven query is registered")
        });
        assert!(registered.is_bound_to("cqn", PROVEN_QUERY));
        assert_eq!(registered.registration_id(), 101);
        assert_eq!(registered.query_id(), 202);
        assert_eq!(
            connection.registrations.lock().as_slice(),
            [(PROVEN_QUERY.to_owned(), Vec::new())],
            "the DB adapter receives exactly the predicate-bearing query, not an object scope"
        );

        let hub = SubscriptionHub::with_source(SubscribeSource::ChangeNotification(
            registered.callback_fanout(),
        ));
        assert!(hub.subscribe("principal-a", URI));

        // The database adapter already removed tables, rowids, and all row
        // data. The matching opaque registration id maps only to this bound
        // URI, and duplicate callbacks coalesce before an MCP client drains.
        let mut receiver = ScriptedCqnReceiver {
            outcome: CqnNotificationOutcome::Event(CqnDriverNotification::for_registration(101)),
        };
        let relay = runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a current Cx");
            hub.relay_cqn_callback(&cx, &mut receiver).await
        });
        assert_eq!(
            relay.expect("reduced callback relays"),
            CqnFanoutOutcome::Delivered
        );

        assert!(hub.forward_cqn_notification(CqnDriverNotification::for_registration(101)));
        assert!(
            !hub.forward_cqn_notification(CqnDriverNotification::for_registration(999)),
            "a callback for another registration cannot wake this resource"
        );

        assert_eq!(hub.drain_pending("principal-a"), vec![URI.to_owned()]);
    }

    #[test]
    fn subscribe_then_notify_lists_subscribers() {
        let r = SubscriptionRegistry::new();
        r.subscribe("agent-a", URI);
        r.subscribe("agent-b", URI);
        r.subscribe("agent-a", URI); // idempotent
        assert_eq!(
            r.subscribers_of(URI),
            vec!["agent-a".to_owned(), "agent-b".to_owned()]
        );
        assert!(r.is_subscribed("agent-a", URI));
    }

    #[test]
    fn registry_refuses_subscriptions_beyond_the_principal_and_emon_connection_caps() {
        let mut profile = cqn_profile(true);
        profile.max_subscriptions = Some(2);

        let per_principal = SubscriptionRegistry::for_profile(&profile, 8);
        assert_eq!(
            per_principal.subscribe("principal-a", "oracle://resource/one"),
            SubscriptionAdmission::Accepted
        );
        assert_eq!(
            per_principal.subscribe("principal-a", "oracle://resource/two"),
            SubscriptionAdmission::Accepted
        );
        assert_eq!(
            per_principal.subscribe("principal-a", "oracle://resource/three"),
            SubscriptionAdmission::PerPrincipalCapReached,
            "the profile cap applies to the server-derived principal"
        );
        assert!(!per_principal.is_subscribed("principal-a", "oracle://resource/three"));

        let emon = SubscriptionRegistry::for_profile(&profile, 2);
        assert_eq!(emon.emon_connection_ceiling(), 2);
        assert_eq!(
            emon.subscribe("principal-a", "oracle://resource/one"),
            SubscriptionAdmission::Accepted
        );
        assert_eq!(
            emon.subscribe("principal-b", "oracle://resource/two"),
            SubscriptionAdmission::Accepted,
            "each active owner/URI pair consumes one EMON connection"
        );
        assert_eq!(emon.emon_connection_count(), 2);
        assert_eq!(
            emon.subscribe("principal-c", "oracle://resource/three"),
            SubscriptionAdmission::EmonConnectionCeilingReached,
            "the third EMON connection is refused before the subscription exists"
        );
        assert_eq!(emon.emon_connection_count(), 2);
        assert!(!emon.is_subscribed("principal-c", "oracle://resource/three"));

        emon.unsubscribe("principal-a", "oracle://resource/one");
        assert_eq!(emon.emon_connection_count(), 1);
        assert_eq!(
            emon.subscribe("principal-c", "oracle://resource/three"),
            SubscriptionAdmission::Accepted,
            "unsubscribing releases exactly one accounted EMON connection"
        );
        assert_eq!(emon.emon_connection_count(), 2);
    }

    #[test]
    fn unsubscribe_removes_the_client_and_prunes_empty_uris() {
        let r = SubscriptionRegistry::new();
        r.subscribe("agent-a", URI);
        r.unsubscribe("agent-a", URI);
        assert!(!r.is_subscribed("agent-a", URI));
        assert!(r.subscribers_of(URI).is_empty());
    }

    #[test]
    fn unsubscribe_all_clears_a_disconnected_client() {
        let r = SubscriptionRegistry::new();
        r.subscribe("agent-a", URI);
        r.subscribe("agent-a", "oracle://capabilities");
        r.subscribe("agent-b", URI);
        r.unsubscribe_all("agent-a");
        assert_eq!(r.subscribers_of(URI), vec!["agent-b".to_owned()]);
        assert!(r.subscribers_of("oracle://capabilities").is_empty());
    }

    #[test]
    fn unknown_uri_has_no_subscribers() {
        let r = SubscriptionRegistry::new();
        assert!(r.subscribers_of("oracle://nope").is_empty());
    }

    /// A scripted polling source whose fingerprint advances on demand, so a
    /// test can model "the watched resource changed" without a database.
    struct ScriptedSource {
        fingerprints: Mutex<HashMap<String, String>>,
    }
    impl ScriptedSource {
        fn new() -> Self {
            Self {
                fingerprints: Mutex::new(HashMap::new()),
            }
        }
        fn set(&self, uri: &str, fp: &str) {
            self.fingerprints
                .lock()
                .insert(uri.to_owned(), fp.to_owned());
        }
    }
    impl PollingSource for ScriptedSource {
        fn poll(&self, uri: &str) -> Option<String> {
            self.fingerprints.lock().get(uri).cloned()
        }
    }

    #[test]
    fn an_unsupported_hub_does_not_advertise_or_accept_subscriptions() {
        // E1 hard requirement: with no confirmed source, the capability is off
        // and subscribe is refused.
        let hub = SubscriptionHub::unsupported();
        assert!(!hub.supports_subscriptions());
        assert!(
            !hub.subscribe("agent-a", URI),
            "subscribe refused with no source"
        );
        assert!(hub.registry().subscribers_of(URI).is_empty());
    }

    #[test]
    fn the_polling_fallback_fires_updates_only_on_an_actual_change() {
        // E1: the polling-fallback path (no DBMS_CHANGE_NOTIFICATION).
        let source = std::sync::Arc::new(ScriptedSource::new());
        source.set(URI, "fp-v1");
        let hub = SubscriptionHub::with_source(SubscribeSource::Polling(Box::new(
            PollingSourceArc(source.clone()),
        )));
        assert!(hub.supports_subscriptions());
        assert!(hub.subscribe("agent-a", URI));

        // No change yet: a poll fires nothing (the baseline was seeded on
        // subscribe).
        assert!(hub.poll_for_changes().is_empty());
        assert!(hub.drain_pending("agent-a").is_empty());

        // The resource changes: the next poll detects it and enqueues an update.
        source.set(URI, "fp-v2");
        assert_eq!(hub.poll_for_changes(), vec![URI.to_owned()]);
        assert_eq!(hub.drain_pending("agent-a"), vec![URI.to_owned()]);

        // Draining is one-shot.
        assert!(hub.drain_pending("agent-a").is_empty());

        // A second change fires again.
        source.set(URI, "fp-v3");
        assert_eq!(hub.poll_for_changes(), vec![URI.to_owned()]);
    }

    #[test]
    fn mark_changed_only_enqueues_for_subscribed_uris() {
        let source = std::sync::Arc::new(ScriptedSource::new());
        source.set(URI, "fp");
        let hub = SubscriptionHub::with_source(SubscribeSource::Polling(Box::new(
            PollingSourceArc(source),
        )));
        // No subscriber yet: mark is a no-op.
        hub.mark_changed(URI);
        assert!(hub.drain_pending("agent-a").is_empty());
        // After subscribing, an out-of-band mark enqueues an update.
        hub.subscribe("agent-a", URI);
        hub.mark_changed(URI);
        assert_eq!(hub.drain_pending("agent-a"), vec![URI.to_owned()]);
    }

    /// Build a polling hub over a scripted source seeded so `subscribe` seeds a
    /// baseline for `uri`. Returns the hub and the shared source handle.
    fn polling_hub(uri: &str) -> (SubscriptionHub, std::sync::Arc<ScriptedSource>) {
        let source = std::sync::Arc::new(ScriptedSource::new());
        source.set(uri, "fp-v1");
        let hub = SubscriptionHub::with_source(SubscribeSource::Polling(Box::new(
            PollingSourceArc(source.clone()),
        )));
        (hub, source)
    }

    #[test]
    fn one_owner_cannot_unsubscribe_another_from_the_same_uri() {
        // .77 owner-spoof: two principals watch the SAME uri. Even with an
        // identical (untrusted) clientId, the server keys off the principal, so
        // B's unsubscribe removes only B — A stays subscribed and keeps its
        // baseline/queue.
        let (hub, _source) = polling_hub(URI);
        assert!(hub.subscribe("principal-a", URI));
        assert!(hub.subscribe("principal-b", URI));

        hub.unsubscribe("principal-b", URI);

        assert!(
            hub.registry().is_subscribed("principal-a", URI),
            "A must remain subscribed after B unsubscribes"
        );
        assert!(
            !hub.registry().is_subscribed("principal-b", URI),
            "B unsubscribes only itself"
        );
    }

    #[test]
    fn a_change_delivers_one_update_per_owner_with_no_cross_drain() {
        // .77 per-owner drain isolation: one change to a shared uri enqueues
        // exactly one update for EACH owner, and each owner drains only its own.
        let (hub, source) = polling_hub(URI);
        assert!(hub.subscribe("principal-a", URI));
        assert!(hub.subscribe("principal-b", URI));

        source.set(URI, "fp-v2");
        assert_eq!(hub.poll_for_changes(), vec![URI.to_owned()]);

        // A drains its own queue; B's is untouched by A's drain.
        assert_eq!(hub.drain_pending("principal-a"), vec![URI.to_owned()]);
        assert!(
            hub.drain_pending("principal-a").is_empty(),
            "A's drain is one-shot"
        );
        // B still has exactly one update — A never consumed it.
        assert_eq!(hub.drain_pending("principal-b"), vec![URI.to_owned()]);
        assert!(hub.drain_pending("principal-b").is_empty());

        // An unrelated principal that never subscribed has nothing to drain.
        assert!(hub.drain_pending("principal-c").is_empty());
    }

    #[test]
    fn unsubscribe_all_clears_only_that_owners_subscriptions_and_pending() {
        // .77 disconnect scoping: dropping one principal on disconnect wipes its
        // subscriptions and pending queue, but never another principal's.
        let (hub, source) = polling_hub(URI);
        assert!(hub.subscribe("principal-a", URI));
        assert!(hub.subscribe("principal-b", URI));
        source.set(URI, "fp-v2");
        assert_eq!(hub.poll_for_changes(), vec![URI.to_owned()]);

        // A disconnects before draining: its subscription and queued update go.
        hub.unsubscribe_all("principal-a");
        assert!(
            hub.drain_pending("principal-a").is_empty(),
            "A's pending is cleared on disconnect"
        );
        assert!(!hub.registry().is_subscribed("principal-a", URI));

        // B is untouched: still subscribed, still holds its update.
        assert!(hub.registry().is_subscribed("principal-b", URI));
        assert_eq!(hub.drain_pending("principal-b"), vec![URI.to_owned()]);
    }

    /// Adapter so a test can share one `ScriptedSource` between the hub and the
    /// test body (the hub takes ownership of a `Box<dyn PollingSource>`).
    struct PollingSourceArc(std::sync::Arc<ScriptedSource>);
    impl PollingSource for PollingSourceArc {
        fn poll(&self, uri: &str) -> Option<String> {
            self.0.poll(uri)
        }
    }
}
