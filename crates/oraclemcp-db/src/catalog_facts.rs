//! Whole-closure catalog facts used to decide whether an engine resolution is
//! still bound to the current visible Oracle catalog state.

use std::collections::BTreeMap;

use asupersync::Cx;
use oraclemcp_guard::purity::{RoutineIdentifier, RoutineRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::DbError;
use crate::{CatalogQueryId, OracleBind, OracleConnection, OracleRow, run_catalog_query};

/// Maximum number of executable members accepted in one closure.
pub const MAX_CLOSURE_MEMBERS: usize = 64;
/// Maximum dependency rows accepted per member.
pub const MAX_CLOSURE_DEPENDENCIES: usize = 512;
/// Maximum triggers accepted per DML target.
pub const MAX_CLOSURE_TRIGGERS: usize = 128;
/// Maximum source rows accepted for one object.
pub const MAX_CLOSURE_SOURCE_ROWS: usize = 16_384;
/// Maximum canonical source bytes accepted per catalog object.
pub const MAX_CLOSURE_SOURCE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum DML targets accepted in one closure.
pub const MAX_CLOSURE_DML_TARGETS: usize = 64;
/// Maximum combined dependency rows accepted in one closure.
pub const MAX_CLOSURE_TOTAL_DEPENDENCIES: usize = 4_096;
/// Maximum combined trigger rows accepted in one closure.
pub const MAX_CLOSURE_TOTAL_TRIGGERS: usize = 512;
/// Maximum combined source rows accepted in one closure.
pub const MAX_CLOSURE_TOTAL_SOURCE_ROWS: usize = 65_536;
const FACT_SCHEMA_VERSION: u8 = 1;
/// Supported schema version of persisted catalog fact records.
pub const CLOSURE_FACT_SCHEMA_VERSION: u8 = FACT_SCHEMA_VERSION;

/// An exact DML target supplied by the engine's routine closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DmlTarget {
    /// Exact owning schema spelling.
    pub owner: String,
    /// Exact table name spelling.
    pub table: String,
}

/// One catalog object in the resolved routine closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClosureMember {
    /// Engine-resolved exact routine identity.
    pub routine: RoutineRef,
    /// Exact owner used to query ALL_* views.
    pub owner: String,
    /// Exact object name used to query ALL_* views.
    pub object_name: String,
    /// Oracle object type, for example PACKAGE or PROCEDURE.
    pub object_type: String,
    /// Source types whose bytes make up this member, ordered by source type.
    pub source_types: Vec<String>,
}

/// Whole-closure input from the engine. It carries no resolver generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoutineClosure {
    /// Exact root routine identity.
    pub root: RoutineRef,
    /// Every executable closure member, including the root.
    pub members: Vec<ClosureMember>,
    /// Tables changed by the closure whose triggers can affect its behavior.
    pub dml_targets: Vec<DmlTarget>,
}

/// Persisted identity and fingerprint for a complete routine closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClosureFactKey {
    /// Database DBID read from USERENV.
    pub dbid: String,
    /// PDB/container name read from USERENV.
    pub container: String,
    /// Current edition read from USERENV.
    pub edition: String,
    /// Exact engine-resolved root.
    pub root: RoutineRef,
    /// SHA-256 of the canonical whole-closure facts.
    pub fingerprint: String,
}

/// Live database identity shared by whole-closure and relation-security facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClosureDatabaseIdentity {
    /// Database DBID read from USERENV.
    pub dbid: String,
    /// PDB/container name read from USERENV.
    pub container: String,
    /// Current edition read from USERENV.
    pub edition: String,
}

/// Stable Oracle PDB identity usable as a service-state-store coordination key.
///
/// `DBID` identifies the database and `CON_ID` identifies its current container
/// within that database. CON_UID comes from the exact current V$CONTAINERS row;
/// an unreadable catalog gives local-only coordination rather than substituting
/// the reusable container slot CON_ID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PdbIdentity {
    /// Database DBID read from USERENV.
    pub dbid: String,
    /// Actual V$CONTAINERS.CON_UID, never the container slot CON_ID.
    pub con_uid: String,
}

/// Why stable PDB identity could not be read for a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdbIdentityObservation {
    /// The closed session-identity query failed or returned an incomplete row.
    Unreadable,
    /// An older persisted request recorded a container slot without a stable UID.
    LegacyContainerIdentity,
}

/// Coordination scope available to one request.
///
/// A service must continue an otherwise admissible request when identity
/// evidence is unavailable (R36). In that case it records a local-only scope,
/// which deliberately makes no claim about PDB-wide coordination.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "coordination_scope", rename_all = "snake_case")]
pub enum PdbIdentityScope {
    /// Stable identity permits coordination within this service state store.
    ServiceStateStore {
        /// The DBID/CON_UID identity the store keys requests by.
        identity: PdbIdentity,
    },
    /// Stable identity is unavailable; only local request observation is safe.
    LocalOnly {
        /// Why stable identity could not be established.
        observation: PdbIdentityObservation,
    },
}

/// Catalog identity for one closure object and its compiler state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemberFact {
    /// Exact engine-resolved routine identity.
    pub routine: RoutineRef,
    /// Oracle catalog object type (package spec/body are distinct facts).
    pub object_type: String,
    /// Object id in ALL_OBJECTS.
    pub object_id: i64,
    /// Canonical LAST_DDL_TIME value.
    pub last_ddl_time: String,
    /// Object status; only VALID is accepted.
    pub status: String,
    /// AUTHID value from ALL_PROCEDURES.
    pub authid: String,
    /// Compiler settings, including PLSQL_CCFLAGS.
    pub compiler_settings: BTreeMap<String, Option<String>>,
    /// SHA-256 source hashes, keyed by Oracle source type.
    pub source_sha256: BTreeMap<String, String>,
}

/// A dependency target and its current object identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DependencyFact {
    /// Source member identity.
    pub member: RoutineRef,
    /// Referenced owner.
    pub owner: String,
    /// Referenced name.
    pub name: String,
    /// Referenced Oracle object type.
    pub object_type: String,
    /// Oracle dependency type.
    pub dependency_type: String,
    /// Current target object id.
    pub object_id: i64,
    /// Current target LAST_DDL_TIME.
    pub last_ddl_time: String,
    /// Current target status; only VALID is accepted.
    pub status: String,
}

/// Trigger metadata and source hash for one DML target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TriggerFact {
    /// Target table owner.
    pub table_owner: String,
    /// Target table name.
    pub table_name: String,
    /// Trigger owner.
    pub owner: String,
    /// Trigger name.
    pub name: String,
    /// Oracle trigger timing/type.
    pub trigger_type: String,
    /// Triggering events.
    pub triggering_event: String,
    /// Trigger status; only ENABLED is accepted.
    pub status: String,
    /// Trigger action type.
    pub action_type: String,
    /// WHEN clause, normalized to empty when absent.
    pub when_clause: String,
    /// SHA-256 of the trigger's ordered source.
    pub source_sha256: String,
}

/// Schema-versioned fact record for one complete routine closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClosureFacts {
    /// Persisted record schema version.
    pub schema_version: u8,
    /// Whole-closure stable identity and fingerprint.
    pub key: ClosureFactKey,
    /// Current closure member facts.
    pub members: Vec<MemberFact>,
    /// Current dependency target facts.
    pub dependencies: Vec<DependencyFact>,
    /// Current DML trigger facts.
    pub triggers: Vec<TriggerFact>,
    /// In-memory invalidation hint. Deliberately excluded from persisted key.
    #[serde(skip)]
    pub catalog_revision: Option<u64>,
}

/// Result of comparing a stored fact with the current catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Revalidation {
    /// Every bounded fact re-read matches the stored closure.
    Fresh,
    /// A readable catalog value changed.
    Stale(String),
    /// The catalog or store could not provide a complete trusted fact.
    Unknown(String),
}

/// Durable persistence boundary implemented by `oraclemcp-core` over FileStore.
pub trait ClosureFactStore {
    /// Load one profile/root record; malformed or unsupported records are absent.
    fn load(&self, profile: &str, key: &ClosureFactKey) -> Result<Option<ClosureFacts>, String>;
    /// Atomically persist a complete schema-versioned fact record.
    fn save(&self, profile: &str, facts: &ClosureFacts) -> Result<(), String>;
}

/// Read the exact source bytes committed by one previously captured member.
///
/// The caller must still revalidate the whole closure before execution. This
/// check binds the engine's input to that closure and rejects a source change
/// between fact capture and analysis instead of analyzing unbound bytes.
pub async fn read_verified_closure_source(
    cx: &Cx,
    conn: &dyn OracleConnection,
    member: &MemberFact,
) -> Result<String, Revalidation> {
    validate_member_status(&member.status)?;
    if member.authid != "DEFINER" {
        return Err(Revalidation::Unknown(
            "routine source needs definer-rights binding".into(),
        ));
    }
    let owner = member
        .routine
        .schema
        .as_ref()
        .filter(|owner| !owner.text.is_empty())
        .ok_or_else(|| Revalidation::Unknown("routine source owner is unresolved".into()))?;
    let object = routine_object_name(&member.routine)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| Revalidation::Unknown("routine source object is unresolved".into()))?;
    if !matches!(
        member.object_type.as_str(),
        "FUNCTION" | "PROCEDURE" | "PACKAGE" | "PACKAGE BODY"
    ) {
        return Err(Revalidation::Unknown(
            "unsupported routine source type".into(),
        ));
    }
    let rows = query(
        cx,
        conn,
        CatalogQueryId::ClosureSource,
        &[
            text(&owner.text),
            text(&object),
            text(&member.object_type),
            integer((MAX_CLOSURE_SOURCE_ROWS + 1) as i64),
        ],
    )
    .await?;
    verified_closure_source_text(member, &rows)
}

fn verified_closure_source_text(
    member: &MemberFact,
    rows: &[OracleRow],
) -> Result<String, Revalidation> {
    check_cap(rows.len(), MAX_CLOSURE_SOURCE_ROWS, "routine source")?;
    let expected = member
        .source_sha256
        .get(&member.object_type)
        .filter(|_| member.source_sha256.len() == 1)
        .ok_or_else(|| {
            Revalidation::Unknown("routine source hash is absent or ambiguous".into())
        })?;
    if hash_source(rows)? != *expected {
        return Err(Revalidation::Stale(
            "routine source changed before analysis".into(),
        ));
    }
    // The fact hash commits to line numbers and exact payload bytes. Preserve
    // every payload, and retain its physical line boundary even when TEXT
    // omits the trailing newline: otherwise a line comment can hide the next
    // executable statement from the engine.
    let mut source = String::new();
    for row in rows {
        let text = row.text("TEXT").expect("validated source text");
        source.push_str(text);
        if !text.ends_with('\n') {
            source.push('\n');
        }
    }
    Ok(source)
}

/// Read a bounded live closure snapshot from ALL_* catalogs.
pub async fn extract_closure_facts(
    cx: &Cx,
    conn: &dyn OracleConnection,
    closure: &RoutineClosure,
    catalog_revision: Option<u64>,
) -> Result<ClosureFacts, Revalidation> {
    if closure.members.is_empty() || closure.members.len() > MAX_CLOSURE_MEMBERS {
        return Err(Revalidation::Unknown(
            "closure member cap or empty closure".into(),
        ));
    }
    if closure.dml_targets.len() > MAX_CLOSURE_DML_TARGETS {
        return Err(Revalidation::Unknown(
            "closure DML target cap exhausted".into(),
        ));
    }
    let identity = read_closure_database_identity(cx, conn).await?;

    let mut members = Vec::with_capacity(closure.members.len());
    let mut dependencies = Vec::new();
    let mut triggers = Vec::new();
    let mut total_source_rows = 0;
    for input in &closure.members {
        if input.owner.is_empty()
            || input.object_name.is_empty()
            || input.source_types.len() != 1
            || input.source_types[0] != input.object_type
            || input
                .routine
                .schema
                .as_ref()
                .is_none_or(|schema| schema.text != input.owner)
            || routine_object_name(&input.routine).as_deref() != Some(input.object_name.as_str())
        {
            return Err(Revalidation::Unknown(
                "incomplete closure member identity".into(),
            ));
        }
        let object_rows = query(
            cx,
            conn,
            CatalogQueryId::ClosureMemberObject,
            &[
                text(&input.owner),
                text(&input.object_name),
                text(&input.object_type),
                integer(2),
            ],
        )
        .await?;
        let object = exactly_one(&object_rows, "closure member object")?;
        let object_id = required_i64(object, "OBJECT_ID", "closure member object")?;
        let last_ddl_time = required_text(object, "LAST_DDL_TIME", "closure member object")?;
        let status = required_text(object, "STATUS", "closure member object")?;
        validate_member_status(&status)?;

        let procedure_name = input
            .routine
            .package
            .as_ref()
            .map(|_| input.routine.member.text.as_str());
        let authid_rows = query(
            cx,
            conn,
            CatalogQueryId::ClosureRoutineAuthid,
            &[
                text(&input.owner),
                text(&input.object_name),
                procedure_name.map_or(OracleBind::Null, text),
                procedure_name.map_or(OracleBind::Null, text),
                integer(33),
            ],
        )
        .await?;
        if authid_rows.len() >= 33 {
            return Err(Revalidation::Unknown(
                "routine AUTHID row cap exhausted".into(),
            ));
        }
        let authid_matches = authid_rows
            .iter()
            .filter(|row| subprogram_matches(row, input.routine.overload))
            .collect::<Vec<_>>();
        if authid_matches.len() != 1 {
            return Err(Revalidation::Unknown(
                "expected one routine AUTHID row".into(),
            ));
        }
        let authid_row = authid_matches[0];
        let authid = required_text(authid_row, "AUTHID", "routine AUTHID")?;

        let settings_rows = query(
            cx,
            conn,
            CatalogQueryId::ClosureCompilerSettings,
            &[
                text(&input.owner),
                text(&input.object_name),
                text(&input.object_type),
                integer(2),
            ],
        )
        .await?;
        let settings_row = exactly_one(&settings_rows, "compiler settings")?;
        let compiler_settings = collect_text_fields(
            settings_row,
            &[
                "PLSQL_OPTIMIZE_LEVEL",
                "PLSQL_CODE_TYPE",
                "PLSQL_DEBUG",
                "PLSQL_WARNINGS",
                "PLSQL_CCFLAGS",
                "NLS_LENGTH_SEMANTICS",
                "PLSCOPE_SETTINGS",
            ],
        )?;

        let mut source_sha256 = BTreeMap::new();
        for source_type in &input.source_types {
            let source_rows = query(
                cx,
                conn,
                CatalogQueryId::ClosureSource,
                &[
                    text(&input.owner),
                    text(&input.object_name),
                    text(source_type),
                    integer((MAX_CLOSURE_SOURCE_ROWS + 1) as i64),
                ],
            )
            .await?;
            if source_rows.len() > MAX_CLOSURE_SOURCE_ROWS {
                return Err(Revalidation::Unknown("source row cap exhausted".into()));
            }
            total_source_rows += source_rows.len();
            check_cap(
                total_source_rows,
                MAX_CLOSURE_TOTAL_SOURCE_ROWS,
                "closure source",
            )?;
            let source_hash = hash_source(&source_rows)?;
            source_sha256.insert(source_type.clone(), source_hash);
        }
        members.push(MemberFact {
            routine: input.routine.clone(),
            object_type: input.object_type.clone(),
            object_id,
            last_ddl_time,
            status,
            authid,
            compiler_settings,
            source_sha256,
        });

        let dependency_rows = query(
            cx,
            conn,
            CatalogQueryId::ClosureDependencies,
            &[
                text(&input.owner),
                text(&input.object_name),
                text(&input.object_type),
                integer((MAX_CLOSURE_DEPENDENCIES + 1) as i64),
            ],
        )
        .await?;
        check_cap(
            dependency_rows.len(),
            MAX_CLOSURE_DEPENDENCIES,
            "dependency",
        )?;
        check_cap(
            dependencies.len() + dependency_rows.len(),
            MAX_CLOSURE_TOTAL_DEPENDENCIES,
            "closure dependency",
        )?;
        for row in dependency_rows {
            require_local_dependency(&row)?;
            dependencies.push(DependencyFact {
                member: input.routine.clone(),
                owner: required_text(&row, "REFERENCED_OWNER", "dependency")?,
                name: required_text(&row, "REFERENCED_NAME", "dependency")?,
                object_type: required_text(&row, "REFERENCED_TYPE", "dependency")?,
                dependency_type: required_text(&row, "DEPENDENCY_TYPE", "dependency")?,
                object_id: required_i64(&row, "TARGET_OBJECT_ID", "dependency target")?,
                last_ddl_time: required_text(&row, "TARGET_LAST_DDL_TIME", "dependency target")?,
                status: required_text(&row, "TARGET_STATUS", "dependency target")?,
            });
        }
    }

    for target in &closure.dml_targets {
        let trigger_rows = query(
            cx,
            conn,
            CatalogQueryId::ClosureTriggers,
            &[
                text(&target.owner),
                text(&target.table),
                integer((MAX_CLOSURE_TRIGGERS + 1) as i64),
            ],
        )
        .await?;
        check_cap(trigger_rows.len(), MAX_CLOSURE_TRIGGERS, "trigger")?;
        check_cap(
            triggers.len() + trigger_rows.len(),
            MAX_CLOSURE_TOTAL_TRIGGERS,
            "closure trigger",
        )?;
        for row in trigger_rows {
            let owner = required_text(&row, "OWNER", "trigger")?;
            let name = required_text(&row, "TRIGGER_NAME", "trigger")?;
            let trigger_source = query(
                cx,
                conn,
                CatalogQueryId::ClosureSource,
                &[
                    text(&owner),
                    text(&name),
                    text("TRIGGER"),
                    integer((MAX_CLOSURE_SOURCE_ROWS + 1) as i64),
                ],
            )
            .await?;
            if trigger_source.len() > MAX_CLOSURE_SOURCE_ROWS {
                return Err(Revalidation::Unknown(
                    "trigger source row cap exhausted".into(),
                ));
            }
            total_source_rows += trigger_source.len();
            check_cap(
                total_source_rows,
                MAX_CLOSURE_TOTAL_SOURCE_ROWS,
                "closure source",
            )?;
            let status = required_text(&row, "STATUS", "trigger")?;
            validate_trigger_status(&status)?;
            triggers.push(TriggerFact {
                table_owner: target.owner.clone(),
                table_name: target.table.clone(),
                owner,
                name,
                trigger_type: required_text(&row, "TRIGGER_TYPE", "trigger")?,
                triggering_event: required_text(&row, "TRIGGERING_EVENT", "trigger")?,
                status,
                action_type: required_text(&row, "ACTION_TYPE", "trigger")?,
                when_clause: row.text("WHEN_CLAUSE").unwrap_or_default().to_owned(),
                source_sha256: hash_source(&trigger_source)?,
            });
        }
    }

    members.sort_by(|a, b| {
        (&a.routine.member.text, &a.object_type).cmp(&(&b.routine.member.text, &b.object_type))
    });
    dependencies.sort_by(|a, b| {
        (&a.owner, &a.name, &a.object_type, &a.member.member.text).cmp(&(
            &b.owner,
            &b.name,
            &b.object_type,
            &b.member.member.text,
        ))
    });
    triggers.sort_by(|a, b| {
        (&a.table_owner, &a.table_name, &a.owner, &a.name).cmp(&(
            &b.table_owner,
            &b.table_name,
            &b.owner,
            &b.name,
        ))
    });
    let mut facts = ClosureFacts {
        schema_version: FACT_SCHEMA_VERSION,
        key: ClosureFactKey {
            dbid: identity.dbid,
            container: identity.container,
            edition: identity.edition,
            root: closure.root.clone(),
            fingerprint: String::new(),
        },
        members,
        dependencies,
        triggers,
        catalog_revision,
    };
    facts.key.fingerprint = fingerprint(&facts)?;
    Ok(facts)
}

fn require_local_dependency(row: &OracleRow) -> Result<(), Revalidation> {
    if !row
        .cell("REFERENCED_LINK_NAME")
        .is_some_and(|cell| cell.value.is_none())
    {
        return Err(Revalidation::Unknown(
            "dependency database-link observation is missing or remote".into(),
        ));
    }
    Ok(())
}

/// Read the same strict DBID/container/edition identity used by persisted
/// whole-closure keys, for callers that bind another live fact to that scope.
pub async fn read_closure_database_identity(
    cx: &Cx,
    conn: &dyn OracleConnection,
) -> Result<ClosureDatabaseIdentity, Revalidation> {
    let identity_rows = query(cx, conn, CatalogQueryId::ClosureIdentity, &[]).await?;
    let identity = exactly_one(&identity_rows, "database identity")?;
    Ok(ClosureDatabaseIdentity {
        dbid: required_text(identity, "DBID", "database identity")?,
        container: required_text(identity, "CONTAINER_NAME", "database identity")?,
        edition: required_text(identity, "EDITION_NAME", "database identity")?,
    })
}

/// Read the least-privilege PDB identity for service-local coordination.
///
/// This helper never turns missing identity evidence into a request refusal:
/// callers receive [`PdbIdentityScope::LocalOnly`] with an observation they can
/// persist or expose in diagnostics.
pub async fn read_pdb_identity_scope(cx: &Cx, conn: &dyn OracleConnection) -> PdbIdentityScope {
    let rows = match query(cx, conn, CatalogQueryId::PdbIdentity, &[]).await {
        Ok(rows) => rows,
        Err(_) => {
            return PdbIdentityScope::LocalOnly {
                observation: PdbIdentityObservation::Unreadable,
            };
        }
    };
    pdb_identity_scope_from_rows(&rows)
}

fn pdb_identity_scope_from_rows(rows: &[OracleRow]) -> PdbIdentityScope {
    let Some(row) = rows.first().filter(|_| rows.len() == 1) else {
        return PdbIdentityScope::LocalOnly {
            observation: PdbIdentityObservation::Unreadable,
        };
    };
    let (Some(dbid), Some(con_uid)) = (
        pdb_identity_number(row, "DBID"),
        pdb_identity_number(row, "CON_UID"),
    ) else {
        return PdbIdentityScope::LocalOnly {
            observation: PdbIdentityObservation::Unreadable,
        };
    };
    PdbIdentityScope::ServiceStateStore {
        identity: PdbIdentity { dbid, con_uid },
    }
}

fn pdb_identity_number(row: &OracleRow, column: &str) -> Option<String> {
    let value = required_text(row, column, "PDB identity").ok()?;
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .map(|value| value.to_string())
}

/// Compare stored facts with a new live extraction, mapping all incomplete reads to Unknown.
pub async fn revalidate(
    cx: &Cx,
    conn: &dyn OracleConnection,
    store: &dyn ClosureFactStore,
    profile: &str,
    closure: &RoutineClosure,
    key: &ClosureFactKey,
    catalog_revision: Option<u64>,
) -> Revalidation {
    let stored = match store.load(profile, key) {
        Ok(Some(facts)) if facts.schema_version == FACT_SCHEMA_VERSION => facts,
        Ok(_) => return Revalidation::Unknown("no supported persisted closure facts".into()),
        Err(_) => return Revalidation::Unknown("persisted closure facts unreadable".into()),
    };
    let current = match extract_closure_facts(cx, conn, closure, catalog_revision).await {
        Ok(facts) => facts,
        Err(result) => return result,
    };
    if current.key == *key && stored.key == *key {
        Revalidation::Fresh
    } else {
        Revalidation::Stale("whole-closure fingerprint changed".into())
    }
}

async fn query(
    cx: &Cx,
    conn: &dyn OracleConnection,
    id: CatalogQueryId,
    binds: &[OracleBind],
) -> Result<Vec<OracleRow>, Revalidation> {
    map_catalog_read(run_catalog_query(cx, conn, id, binds).await)
}

fn map_catalog_read<T>(result: Result<T, DbError>) -> Result<T, Revalidation> {
    result.map_err(|_| Revalidation::Unknown("required ALL_* catalog data is not readable".into()))
}

fn text(value: &str) -> OracleBind {
    OracleBind::String(value.to_owned())
}
fn integer(value: i64) -> OracleBind {
    OracleBind::I64(value)
}

fn exactly_one<'a>(rows: &'a [OracleRow], what: &str) -> Result<&'a OracleRow, Revalidation> {
    if rows.len() == 1 {
        Ok(&rows[0])
    } else {
        Err(Revalidation::Unknown(format!("expected one {what} row")))
    }
}

fn validate_member_status(status: &str) -> Result<(), Revalidation> {
    if status == "VALID" {
        Ok(())
    } else {
        Err(Revalidation::Unknown("closure member is not VALID".into()))
    }
}

fn validate_trigger_status(status: &str) -> Result<(), Revalidation> {
    if status == "ENABLED" {
        Ok(())
    } else {
        Err(Revalidation::Unknown(
            "DML target has a disabled trigger".into(),
        ))
    }
}

fn check_cap(count: usize, cap: usize, kind: &str) -> Result<(), Revalidation> {
    if count > cap {
        Err(Revalidation::Unknown(format!("{kind} row cap exhausted")))
    } else {
        Ok(())
    }
}

fn required_text(row: &OracleRow, column: &str, what: &str) -> Result<String, Revalidation> {
    row.text(column)
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Revalidation::Unknown(format!("missing {column} in {what}")))
}

fn required_i64(row: &OracleRow, column: &str, what: &str) -> Result<i64, Revalidation> {
    row.parse_i64(column)
        .ok_or_else(|| Revalidation::Unknown(format!("invalid {column} in {what}")))
}

fn collect_text_fields(
    row: &OracleRow,
    columns: &[&str],
) -> Result<BTreeMap<String, Option<String>>, Revalidation> {
    columns
        .iter()
        .map(|column| {
            row.cell(column)
                .map(|cell| ((*column).to_owned(), cell.text().map(str::to_owned)))
                .ok_or_else(|| Revalidation::Unknown(format!("missing compiler setting {column}")))
        })
        .collect()
}

fn subprogram_matches(row: &OracleRow, identity: Option<u32>) -> bool {
    // OracleCatalogResolver binds RoutineRef.overload to SUBPROGRAM_ID.
    // OVERLOAD is nullable (including every standalone function) and is a
    // different ordinal for package members; it cannot substitute for that ID.
    match identity {
        Some(expected) => row.parse_i64("SUBPROGRAM_ID") == Some(i64::from(expected)),
        None => row
            .cell("OVERLOAD")
            .is_some_and(|cell| cell.value.is_none()),
    }
}

fn hash_source(rows: &[OracleRow]) -> Result<String, Revalidation> {
    if rows.is_empty() {
        return Err(Revalidation::Unknown(
            "source is absent or unreadable".into(),
        ));
    }
    let mut hasher = Sha256::new();
    let mut total_bytes = 0usize;
    let mut first_code_line = None;
    let mut last_line = 0_i64;
    for row in rows {
        let line = required_i64(row, "LINE", "source")?;
        let text = row
            .text("TEXT")
            .ok_or_else(|| Revalidation::Unknown("source text is unreadable".into()))?;
        if line != last_line + 1 {
            return Err(Revalidation::Unknown(
                "source lines are missing or not strictly ordered".into(),
            ));
        }
        last_line = line;
        let bytes = text.as_bytes();
        total_bytes = total_bytes.saturating_add(bytes.len());
        check_cap(total_bytes, MAX_CLOSURE_SOURCE_BYTES, "source byte")?;
        hasher.update(line.to_be_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        if first_code_line.is_none() {
            first_code_line = text.lines().map(str::trim).find(|line| !line.is_empty());
        }
    }
    if first_code_line.is_some_and(|line| {
        line.eq_ignore_ascii_case("wrapped") || line.to_ascii_lowercase().starts_with("wrapped ")
    }) {
        return Err(Revalidation::Unknown(
            "wrapped source cannot be hashed".into(),
        ));
    }
    Ok(hex_hasher(hasher.finalize()))
}

fn fingerprint(facts: &ClosureFacts) -> Result<String, Revalidation> {
    let mut canonical = facts.clone();
    canonical.key.fingerprint.clear();
    canonical.catalog_revision = None;
    let encoded = serde_json::to_vec(&canonical)
        .map_err(|_| Revalidation::Unknown("closure facts could not be canonicalized".into()))?;
    Ok(hex_digest(&encoded))
}

/// Check that a decoded record's fingerprint covers its complete stored facts.
#[must_use]
pub fn fact_record_valid(facts: &ClosureFacts) -> bool {
    facts.schema_version == FACT_SCHEMA_VERSION
        && fingerprint(facts).is_ok_and(|fingerprint| fingerprint == facts.key.fingerprint)
}

fn hex_digest(bytes: &[u8]) -> String {
    hex_hasher(Sha256::digest(bytes))
}

fn hex_hasher(digest: impl AsRef<[u8]>) -> String {
    let mut output = String::with_capacity(64);
    for &byte in digest.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Build an exact dictionary member identity from a resolved routine.
pub fn routine_object_name(routine: &RoutineRef) -> Option<String> {
    routine
        .package
        .as_ref()
        .map(|package| package.text.clone())
        .or_else(|| Some(routine.member.text.clone()))
}

/// Make an unquoted Oracle identifier using the same normalization as RoutineRef.
pub fn unquoted_identifier(value: impl Into<String>) -> RoutineIdentifier {
    RoutineIdentifier::new(value, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closure_authid_matches_the_resolved_subprogram_not_the_overload_ordinal() {
        let mut row = OracleRow {
            columns: vec![
                (
                    "SUBPROGRAM_ID".into(),
                    crate::OracleCell::new("NUMBER", Some("1".into())),
                ),
                ("OVERLOAD".into(), crate::OracleCell::new("VARCHAR2", None)),
            ],
        };
        assert!(subprogram_matches(&row, Some(1)));
        assert!(!subprogram_matches(&row, Some(2)));
        row.columns[0].1.value = Some("7".into());
        row.columns[1].1.value = Some("2".into());
        assert!(subprogram_matches(&row, Some(7)));
        assert!(!subprogram_matches(&row, Some(2)));
        assert!(!subprogram_matches(&row, None));
        row.columns[0].1.value = None;
        assert!(!subprogram_matches(&row, Some(7)));
    }

    fn source_line(line: i64, text: &str) -> OracleRow {
        OracleRow {
            columns: vec![
                (
                    "LINE".into(),
                    crate::OracleCell::new("NUMBER", Some(line.to_string())),
                ),
                (
                    "TEXT".into(),
                    crate::OracleCell::new("VARCHAR2", Some(text.to_owned())),
                ),
            ],
        }
    }

    #[test]
    fn verified_source_loader_binds_exact_analyzed_bytes() {
        let rows = vec![
            source_line(1, "FUNCTION FX RETURN NUMBER IS\n"),
            source_line(2, "BEGIN RETURN 2; END;\n"),
        ];
        let mut member = fixture().members.remove(0);
        member.routine.package = None;
        member.routine.member = unquoted_identifier("FX");
        member.object_type = "FUNCTION".into();
        member.source_sha256 = BTreeMap::from([("FUNCTION".into(), hash_source(&rows).unwrap())]);
        assert_eq!(
            verified_closure_source_text(&member, &rows).unwrap(),
            "FUNCTION FX RETURN NUMBER IS\nBEGIN RETURN 2; END;\n"
        );
        let changed = vec![
            rows[0].clone(),
            source_line(2, "BEGIN COMMIT; RETURN 2; END;\n"),
        ];
        assert!(matches!(
            verified_closure_source_text(&member, &changed),
            Err(Revalidation::Stale(_))
        ));
        assert!(matches!(
            verified_closure_source_text(&member, &[rows[1].clone(), rows[0].clone()]),
            Err(Revalidation::Unknown(_))
        ));
        let no_newlines = vec![
            source_line(1, "FUNCTION FX RETURN NUMBER IS BEGIN -- comment"),
            source_line(2, "UPDATE APP.T SET N=1; RETURN 2; END;"),
        ];
        member.source_sha256 =
            BTreeMap::from([("FUNCTION".into(), hash_source(&no_newlines).unwrap())]);
        assert!(
            verified_closure_source_text(&member, &no_newlines)
                .unwrap()
                .contains("-- comment\nUPDATE APP.T"),
            "a physical source row must end a line comment"
        );
        member.source_sha256.clear();
        assert!(matches!(
            verified_closure_source_text(&member, &rows),
            Err(Revalidation::Unknown(_))
        ));
    }

    fn fixture() -> ClosureFacts {
        let root = RoutineRef {
            schema: Some(unquoted_identifier("app")),
            package: Some(unquoted_identifier("pkg")),
            member: unquoted_identifier("run"),
            overload: Some(1),
        };
        let mut settings = BTreeMap::new();
        settings.insert("PLSQL_CCFLAGS".into(), Some("FLAG:TRUE".into()));
        let mut hashes = BTreeMap::new();
        hashes.insert("PACKAGE".into(), "spec-a".into());
        ClosureFacts {
            schema_version: FACT_SCHEMA_VERSION,
            key: ClosureFactKey {
                dbid: "db".into(),
                container: "pdb".into(),
                edition: "ora$base".into(),
                root: root.clone(),
                fingerprint: "".into(),
            },
            members: vec![MemberFact {
                routine: root.clone(),
                object_type: "PACKAGE".into(),
                object_id: 11,
                last_ddl_time: "t1".into(),
                status: "VALID".into(),
                authid: "DEFINER".into(),
                compiler_settings: settings,
                source_sha256: hashes,
            }],
            dependencies: vec![DependencyFact {
                member: root.clone(),
                owner: "APP".into(),
                name: "T".into(),
                object_type: "TABLE".into(),
                dependency_type: "HARD".into(),
                object_id: 13,
                last_ddl_time: "t2".into(),
                status: "VALID".into(),
            }],
            triggers: vec![TriggerFact {
                table_owner: "APP".into(),
                table_name: "T".into(),
                owner: "APP".into(),
                name: "TRG".into(),
                trigger_type: "BEFORE EACH ROW".into(),
                triggering_event: "INSERT".into(),
                status: "ENABLED".into(),
                action_type: "PL/SQL".into(),
                when_clause: String::new(),
                source_sha256: "trigger-a".into(),
            }],
            catalog_revision: None,
        }
    }

    fn key(facts: &ClosureFacts) -> String {
        fingerprint(facts).expect("fingerprint")
    }

    #[test]
    fn fact_key_changes_on_spec_source() {
        let mut f = fixture();
        let a = key(&f);
        f.members[0]
            .source_sha256
            .insert("PACKAGE".into(), "spec-b".into());
        assert_ne!(a, key(&f));
    }
    #[test]
    fn fact_key_changes_on_body_source() {
        let mut f = fixture();
        let a = key(&f);
        f.members[0]
            .source_sha256
            .insert("PACKAGE BODY".into(), "body-b".into());
        assert_ne!(a, key(&f));
    }
    #[test]
    fn fact_key_changes_on_authid() {
        let mut f = fixture();
        let a = key(&f);
        f.members[0].authid = "CURRENT_USER".into();
        assert_ne!(a, key(&f));
    }
    #[test]
    fn fact_key_changes_on_ccflags() {
        let mut f = fixture();
        let a = key(&f);
        f.members[0]
            .compiler_settings
            .insert("PLSQL_CCFLAGS".into(), Some("FLAG:FALSE".into()));
        assert_ne!(a, key(&f));
    }
    #[test]
    fn fact_key_changes_on_last_ddl_time() {
        let mut f = fixture();
        let a = key(&f);
        f.members[0].last_ddl_time = "t3".into();
        assert_ne!(a, key(&f));
    }
    #[test]
    fn fact_key_changes_on_object_id() {
        let mut f = fixture();
        let a = key(&f);
        f.members[0].object_id += 1;
        assert_ne!(a, key(&f));
    }
    #[test]
    fn fact_key_changes_on_dependency_target() {
        let mut f = fixture();
        let a = key(&f);
        f.dependencies[0].object_id += 1;
        assert_ne!(a, key(&f));
        let b = key(&f);
        f.dependencies[0].last_ddl_time = "t9".into();
        assert_ne!(b, key(&f));
    }
    #[test]
    fn fact_key_changes_on_trigger_source() {
        let mut f = fixture();
        let a = key(&f);
        f.triggers[0].source_sha256 = "trigger-b".into();
        assert_ne!(a, key(&f));
    }
    #[test]
    fn fact_key_changes_on_edition() {
        let mut f = fixture();
        let a = key(&f);
        f.key.edition = "edition_two".into();
        assert_ne!(a, key(&f));
    }
    #[test]
    fn fact_key_changes_on_dbid() {
        let mut f = fixture();
        let a = key(&f);
        f.key.dbid = "db_two".into();
        assert_ne!(a, key(&f));
    }
    #[test]
    fn fact_key_changes_on_container() {
        let mut f = fixture();
        let a = key(&f);
        f.key.container = "PDB2".into();
        assert_ne!(a, key(&f));
    }
    #[test]
    fn fact_store_ignores_in_memory_catalog_revision() {
        let mut f = fixture();
        let a = key(&f);
        f.catalog_revision = Some(99);
        assert_eq!(a, key(&f));
    }
    #[test]
    fn fact_missing_privilege_is_unknown() {
        let result: Result<Vec<OracleRow>, DbError> = Err(DbError::Internal("ORA-00942".into()));
        let mapped = map_catalog_read(result);
        assert!(matches!(mapped, Err(Revalidation::Unknown(_))));
    }

    #[test]
    fn closure_dependency_needs_an_observed_null_database_link() {
        let mut row = OracleRow::default();
        assert!(require_local_dependency(&row).is_err());
        row.columns.push((
            "REFERENCED_LINK_NAME".into(),
            crate::OracleCell::new("VARCHAR2", None),
        ));
        assert!(require_local_dependency(&row).is_ok());
        row.columns[0].1.value = Some("REMOTE_LAB".into());
        assert!(require_local_dependency(&row).is_err());
    }

    fn pdb_identity_row(dbid: Option<&str>, con_uid: Option<&str>) -> OracleRow {
        OracleRow {
            columns: vec![
                (
                    "DBID".into(),
                    crate::OracleCell::new("VARCHAR2", dbid.map(str::to_owned)),
                ),
                (
                    "CON_UID".into(),
                    crate::OracleCell::new("VARCHAR2", con_uid.map(str::to_owned)),
                ),
                (
                    "CON_ID".into(),
                    crate::OracleCell::new("VARCHAR2", Some("3".to_owned())),
                ),
            ],
        }
    }

    #[test]
    fn pdb_identity_scope_uses_dbid_and_con_uid_not_container_slot_or_name() {
        assert_eq!(
            pdb_identity_scope_from_rows(&[pdb_identity_row(Some("424242"), Some("9001"))]),
            PdbIdentityScope::ServiceStateStore {
                identity: PdbIdentity {
                    dbid: "424242".into(),
                    con_uid: "9001".into(),
                },
            }
        );
    }

    #[test]
    fn pdb_identity_scope_does_not_substitute_a_reusable_container_slot() {
        let row = OracleRow {
            columns: vec![
                (
                    "DBID".into(),
                    crate::OracleCell::new("VARCHAR2", Some("424242".into())),
                ),
                (
                    "CON_ID".into(),
                    crate::OracleCell::new("VARCHAR2", Some("3".into())),
                ),
            ],
        };
        assert!(matches!(
            pdb_identity_scope_from_rows(&[row]),
            PdbIdentityScope::LocalOnly {
                observation: PdbIdentityObservation::Unreadable
            }
        ));
        for invalid in ["0", "not-an-id", "-1", "18446744073709551616"] {
            assert!(
                matches!(
                    pdb_identity_scope_from_rows(&[pdb_identity_row(
                        Some("424242"),
                        Some(invalid)
                    )]),
                    PdbIdentityScope::LocalOnly { .. }
                ),
                "{invalid}"
            );
        }
    }

    #[test]
    fn live_pdb_identity_matches_uid_or_explicitly_reports_local_only() {
        if std::env::var("ORACLEMCP_PDB_IDENTITY_LIVE").as_deref() != Ok("1") {
            eprintln!("set ORACLEMCP_PDB_IDENTITY_LIVE=1 for the real lab identity check");
            return;
        }
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            use crate::{AuthAdapter, OracleConnectOptions, RustOracleConnection};
            let cx = Cx::current().expect("runtime Cx");
            let dsn = std::env::var("ORACLEMCP_TEST_DSN").expect("lab DSN");
            assert!(dsn.starts_with("localhost:") || dsn.starts_with("127.0.0.1:"));
            let conn = RustOracleConnection::connect(&cx, OracleConnectOptions {
                connect_string: dsn,
                username: Some(std::env::var("ORACLEMCP_TEST_USER").expect("lab user")),
                password: Some(std::env::var("ORACLEMCP_TEST_PASSWORD").expect("lab password")),
                auth_adapter: AuthAdapter::Password,
                ..Default::default()
            }).await.expect("real lab connection");
            let observed = read_pdb_identity_scope(&cx, &conn).await;
            if std::env::var("ORACLEMCP_PDB_IDENTITY_EXPECT_LOCAL").as_deref() == Ok("1") {
                assert_eq!(observed, PdbIdentityScope::LocalOnly { observation: PdbIdentityObservation::Unreadable });
            } else {
                let reference = conn.query_rows(&cx,
                    "SELECT SYS_CONTEXT('USERENV','DBID') AS expected_dbid, con_uid AS expected_uid, con_id AS container_slot FROM v$containers WHERE con_id=TO_NUMBER(SYS_CONTEXT('USERENV','CON_ID'))",
                    &[]).await.expect("independent UID census");
                assert_eq!(reference.len(), 1);
                let expected_dbid = required_text(&reference[0], "EXPECTED_DBID", "live identity").unwrap();
                let expected_uid = required_text(&reference[0], "EXPECTED_UID", "live identity").unwrap();
                assert_ne!(expected_uid, required_text(&reference[0], "CONTAINER_SLOT", "live identity").unwrap(), "the fixture must distinguish UID from slot");
                assert_eq!(observed, PdbIdentityScope::ServiceStateStore { identity: PdbIdentity { dbid: expected_dbid, con_uid: expected_uid } });
            }
            // An unavailable identity is an observation, never a refusal or a
            // poisoned connection: the principal can still perform its read.
            let rows = conn.query_rows(&cx, "SELECT 1 AS continued_read FROM dual", &[]).await.expect("ordinary read continues");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].parse_i64("CONTINUED_READ"), Some(1));
            conn.close(&cx).await.expect("close lab connection");
        });
    }

    #[test]
    fn pdb_identity_scope_is_local_only_when_identity_is_incomplete() {
        assert_eq!(
            pdb_identity_scope_from_rows(&[pdb_identity_row(Some("424242"), None)]),
            PdbIdentityScope::LocalOnly {
                observation: PdbIdentityObservation::Unreadable,
            }
        );
    }

    #[test]
    fn pdb_identity_scope_is_local_only_when_identity_row_is_not_exactly_one() {
        assert_eq!(
            pdb_identity_scope_from_rows(&[]),
            PdbIdentityScope::LocalOnly {
                observation: PdbIdentityObservation::Unreadable,
            }
        );
    }

    #[test]
    fn fact_wrapped_source_is_unknown() {
        let row = OracleRow {
            columns: vec![
                (
                    "LINE".into(),
                    crate::OracleCell::new("NUMBER", Some("1".into())),
                ),
                (
                    "TEXT".into(),
                    crate::OracleCell::new("VARCHAR2", Some("wrapped\n".into())),
                ),
            ],
        };
        assert!(matches!(hash_source(&[row]), Err(Revalidation::Unknown(_))));
    }
    #[test]
    fn fact_invalid_member_is_unknown() {
        assert!(matches!(
            validate_member_status("INVALID"),
            Err(Revalidation::Unknown(_))
        ));
    }
    #[test]
    fn fact_cap_exhaustion_is_unknown() {
        assert!(matches!(
            check_cap(2, 1, "member"),
            Err(Revalidation::Unknown(_))
        ));
    }
    #[test]
    fn fact_store_corrupt_record_is_unknown() {
        assert!(serde_json::from_slice::<ClosureFacts>(b"{broken").is_err());
    }
}
