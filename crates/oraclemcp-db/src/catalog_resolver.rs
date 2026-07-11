//! Live Oracle dictionary-backed semantic name resolution.
//!
//! The resolver is loaded asynchronously from the connection and then exposed
//! through the synchronous, engine-free [`CatalogResolver`] port.  A loaded
//! snapshot is usable only with the exact session, statement-scope, and catalog
//! generation context that produced it; a cache miss or context mismatch is
//! deliberately unresolved.

use std::collections::{BTreeSet, HashMap, HashSet};

use asupersync::Cx;
use oraclemcp_guard::{
    CatalogObjectKind, CatalogResolver, QuoteSemantics, RawName, RawNamePart, Resolution,
    ResolveCtx, ResolvedContainer, ResolvedIdentity, ResolvedObject, ResolvedOverload,
    StatementScope, SynonymHop, SyntacticRole,
};

use crate::{DbError, OracleBind, OracleConnection, OracleRow};

/// Maximum number of syntactic names loaded into one immutable resolver.
pub const MAX_CATALOG_NAMES: usize = 64;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_CANDIDATES: usize = 32;
const MAX_SYNONYM_HOPS: usize = 16;
const MAX_ARGUMENT_ROWS: usize = 512;
const MAX_SESSION_ROLES: usize = 256;

const SESSION_CONTEXT_SQL: &str = "SELECT SYS_CONTEXT('USERENV', 'SESSION_USER') AS session_user, \
    SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') AS current_schema, \
    SYS_CONTEXT('USERENV', 'CURRENT_EDITION_NAME') AS edition_name FROM dual";

const SESSION_ROLES_SQL: &str = "SELECT role FROM (SELECT role FROM session_roles ORDER BY role) \
    WHERE ROWNUM <= :1";

const OBJECTS_SQL: &str = "SELECT owner, object_name, object_type, object_id, status, edition_name \
    FROM (SELECT owner, object_name, object_type, object_id, status, edition_name \
          FROM all_objects WHERE owner = :1 AND object_name = :2 ORDER BY object_id) \
    WHERE ROWNUM <= :3";

const SYNONYMS_SQL: &str = "SELECT s.owner, s.synonym_name, s.table_owner, s.table_name, s.db_link, \
    o.object_id, o.status, o.edition_name \
    FROM all_synonyms s LEFT JOIN all_objects o \
      ON o.owner = s.owner AND o.object_name = s.synonym_name AND o.object_type = 'SYNONYM' \
    WHERE s.owner = :1 AND s.synonym_name = :2 AND ROWNUM <= :3";

const STANDALONE_ARGUMENTS_SQL: &str = "SELECT subprogram_id, overload, position, data_level, in_out, defaulted \
    FROM (SELECT subprogram_id, overload, position, data_level, in_out, defaulted, sequence \
          FROM all_arguments WHERE owner = :1 AND package_name IS NULL AND object_name = :2 \
          ORDER BY subprogram_id, sequence) WHERE ROWNUM <= :3";

const MEMBER_ARGUMENTS_SQL: &str = "SELECT subprogram_id, overload, position, data_level, in_out, defaulted \
    FROM (SELECT subprogram_id, overload, position, data_level, in_out, defaulted, sequence \
          FROM all_arguments WHERE owner = :1 AND package_name = :2 AND object_name = :3 \
          ORDER BY subprogram_id, sequence) WHERE ROWNUM <= :4";

const COLUMN_CONFLICT_SQL: &str = "SELECT owner, table_name, column_name, column_id \
    FROM all_tab_columns WHERE column_name = :1 AND ROWNUM <= :2";

/// Immutable set of live dictionary answers for one exact resolution context.
#[derive(Debug, Clone)]
pub struct OracleCatalogResolver {
    context: ResolveCtx,
    entries: HashMap<RawName, Resolution>,
}

impl OracleCatalogResolver {
    /// Load bounded dictionary evidence for `names` using `conn`.
    ///
    /// The connection's session user, current schema, edition, and enabled
    /// roles must exactly match `context`. A mismatch produces an empty,
    /// fail-closed snapshot rather than attaching evidence from another
    /// session context. Dictionary query failures are returned to the caller;
    /// incomplete individual answers are stored as [`Resolution::Unresolved`].
    pub async fn load(
        cx: &Cx,
        conn: &dyn OracleConnection,
        names: &[RawName],
        context: &ResolveCtx,
    ) -> Result<Self, DbError> {
        if names.len() > MAX_CATALOG_NAMES {
            return Err(DbError::Query(format!(
                "catalog resolver name cap exceeded: {} > {MAX_CATALOG_NAMES}",
                names.len()
            )));
        }

        let live = read_catalog_resolve_context(
            cx,
            conn,
            context.generation,
            context.statement_scope.clone(),
        )
        .await?;
        if live != *context {
            return Ok(Self {
                context: context.clone(),
                entries: HashMap::new(),
            });
        }

        let lookup = DictionaryLookup { cx, conn, context };
        let mut entries = HashMap::with_capacity(names.len());
        for name in names {
            if entries.contains_key(name) {
                continue;
            }
            let resolution = lookup.resolve_name(name).await?;
            entries.insert(name.clone(), resolution);
        }
        Ok(Self {
            context: context.clone(),
            entries,
        })
    }

    /// Number of distinct syntactic names loaded into this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether this resolver contains no dictionary answers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl CatalogResolver for OracleCatalogResolver {
    fn resolve(&self, name: &RawName, context: &ResolveCtx) -> Resolution {
        if context != &self.context {
            return Resolution::Unresolved;
        }
        self.entries
            .get(name)
            .cloned()
            .unwrap_or(Resolution::Unresolved)
    }
}

/// Read the live session inputs needed to construct a truthful resolver
/// context. `generation` remains consumer-owned and `statement_scope` remains
/// parser-owned; every other field is obtained from the Oracle session.
pub async fn read_catalog_resolve_context(
    cx: &Cx,
    conn: &dyn OracleConnection,
    generation: oraclemcp_guard::CatalogGeneration,
    statement_scope: StatementScope,
) -> Result<ResolveCtx, DbError> {
    let rows = conn.query_rows(cx, SESSION_CONTEXT_SQL, &[]).await?;
    let [row] = rows.as_slice() else {
        return Err(DbError::Query(
            "catalog resolver session context query returned an incomplete answer".to_owned(),
        ));
    };
    let Some(connected_schema) = required_text(row, "SESSION_USER") else {
        return Err(DbError::Query(
            "catalog resolver session user was missing".to_owned(),
        ));
    };
    let Some(current_schema) = required_text(row, "CURRENT_SCHEMA") else {
        return Err(DbError::Query(
            "catalog resolver current schema was missing".to_owned(),
        ));
    };
    let Some(edition) = required_text(row, "EDITION_NAME") else {
        return Err(DbError::Query(
            "catalog resolver current edition was missing".to_owned(),
        ));
    };

    let role_rows = conn
        .query_rows(
            cx,
            SESSION_ROLES_SQL,
            &[OracleBind::from((MAX_SESSION_ROLES + 1) as i64)],
        )
        .await?;
    if role_rows.len() > MAX_SESSION_ROLES {
        return Err(DbError::Query(format!(
            "catalog resolver enabled-role cap exceeded: more than {MAX_SESSION_ROLES}"
        )));
    }
    let mut enabled_roles = BTreeSet::new();
    for row in &role_rows {
        let Some(role) = required_text(row, "ROLE") else {
            return Err(DbError::Query(
                "catalog resolver enabled-role row was incomplete".to_owned(),
            ));
        };
        enabled_roles.insert(role);
    }

    Ok(ResolveCtx {
        connected_schema,
        current_schema,
        edition: Some(edition),
        enabled_roles,
        statement_scope,
        generation,
    })
}

struct DictionaryLookup<'a> {
    cx: &'a Cx,
    conn: &'a dyn OracleConnection,
    context: &'a ResolveCtx,
}

impl DictionaryLookup<'_> {
    async fn resolve_name(&self, raw: &RawName) -> Result<Resolution, DbError> {
        if let Some(db_link) = &raw.db_link {
            return Ok(Resolution::Remote {
                db_link: db_link.clone(),
            });
        }
        let Some(parts) = normalize_parts(&raw.parts) else {
            return Ok(Resolution::Unresolved);
        };
        if parts.is_empty() || self.references_statement_scope(raw) {
            return Ok(Resolution::Unresolved);
        }

        match raw.role {
            SyntacticRole::FromFactor => self.resolve_from(raw, &parts).await,
            SyntacticRole::CallWithArgs => self.resolve_callable(raw, &parts, false).await,
            SyntacticRole::ValuePosition => {
                if parts.len() == 1 && self.has_column_conflict(&parts[0]).await? {
                    return Ok(Resolution::Unresolved);
                }
                self.resolve_callable(raw, &parts, true).await
            }
        }
    }

    fn references_statement_scope(&self, raw: &RawName) -> bool {
        let Some(first) = raw.parts.first() else {
            return false;
        };
        self.context
            .statement_scope
            .aliases
            .iter()
            .chain(self.context.statement_scope.common_table_expressions.iter())
            .any(|local| parts_equal(first, local))
    }

    async fn resolve_from(&self, raw: &RawName, parts: &[String]) -> Result<Resolution, DbError> {
        let (owner, name, allow_public) = match parts {
            [name] => (self.context.current_schema.as_str(), name.as_str(), true),
            [owner, name] => (owner.as_str(), name.as_str(), false),
            _ => return Ok(Resolution::Unresolved),
        };
        self.resolve_object(owner, name, raw, allow_public, ObjectPurpose::From)
            .await
    }

    async fn resolve_callable(
        &self,
        raw: &RawName,
        parts: &[String],
        zero_arg_only: bool,
    ) -> Result<Resolution, DbError> {
        match parts {
            [name] => {
                self.resolve_object(
                    &self.context.current_schema,
                    name,
                    raw,
                    true,
                    ObjectPurpose::Callable { zero_arg_only },
                )
                .await
            }
            [first, second] => {
                let standalone = self
                    .resolve_object(
                        first,
                        second,
                        raw,
                        false,
                        ObjectPurpose::Callable { zero_arg_only },
                    )
                    .await?;
                let member = self
                    .resolve_member(
                        &self.context.current_schema,
                        first,
                        second,
                        raw,
                        true,
                        zero_arg_only,
                    )
                    .await?;
                Ok(merge_alternatives(standalone, member))
            }
            [owner, container, member] => {
                self.resolve_member(owner, container, member, raw, false, zero_arg_only)
                    .await
            }
            _ => Ok(Resolution::Unresolved),
        }
    }

    async fn resolve_object(
        &self,
        owner: &str,
        name: &str,
        raw: &RawName,
        allow_public: bool,
        purpose: ObjectPurpose,
    ) -> Result<Resolution, DbError> {
        let walked = self
            .walk_synonyms(owner, name, allow_public, |kind| purpose.accepts(kind))
            .await?;
        let WalkResult::Objects {
            objects,
            synonym_chain,
        } = walked
        else {
            return Ok(walked.into_resolution());
        };
        self.finish_objects(objects, synonym_chain, raw, purpose)
            .await
    }

    async fn resolve_member(
        &self,
        owner: &str,
        container: &str,
        member: &str,
        raw: &RawName,
        allow_public: bool,
        zero_arg_only: bool,
    ) -> Result<Resolution, DbError> {
        let walked = self
            .walk_synonyms(owner, container, allow_public, |kind| {
                matches!(kind, CatalogObjectKind::Package | CatalogObjectKind::Type)
            })
            .await?;
        let WalkResult::Objects {
            objects,
            synonym_chain,
        } = walked
        else {
            return Ok(walked.into_resolution());
        };
        if objects.len() != 1 {
            return Ok(ambiguous_objects(&objects));
        }
        let object = &objects[0];
        let Some(arguments) = self
            .argument_rows(&object.owner, Some(&object.name), member)
            .await?
        else {
            return Ok(Resolution::Unresolved);
        };
        let Some(callable) = callable_overloads(&arguments, zero_arg_only) else {
            return Ok(Resolution::Unresolved);
        };
        if callable.overloads.is_empty() {
            return Ok(Resolution::Unresolved);
        }
        Ok(Resolution::Resolved(Box::new(ResolvedObject {
            owner: object.owner.clone(),
            name: member.to_owned(),
            kind: callable.kind,
            container: Some(ResolvedContainer {
                name: object.name.clone(),
                kind: object.kind.clone(),
            }),
            member: Some(member.to_owned()),
            overloads: callable.overloads,
            quote_exact: raw
                .parts
                .iter()
                .any(|part| part.quoting == QuoteSemantics::Quoted),
            synonym_chain,
            db_link: None,
            identity: object.identity.clone(),
        })))
    }

    async fn finish_objects(
        &self,
        objects: Vec<ObjectFact>,
        synonym_chain: Vec<SynonymHop>,
        raw: &RawName,
        purpose: ObjectPurpose,
    ) -> Result<Resolution, DbError> {
        if objects.len() != 1 {
            return Ok(ambiguous_objects(&objects));
        }
        let object = &objects[0];
        let overloads = if let ObjectPurpose::Callable { zero_arg_only } = purpose {
            let Some(arguments) = self
                .argument_rows(&object.owner, None, &object.name)
                .await?
            else {
                return Ok(Resolution::Unresolved);
            };
            let Some(callable) = callable_overloads(&arguments, zero_arg_only) else {
                return Ok(Resolution::Unresolved);
            };
            if callable.kind != object.kind || (zero_arg_only && callable.overloads.is_empty()) {
                return Ok(Resolution::Unresolved);
            }
            callable.overloads
        } else {
            Vec::new()
        };
        Ok(Resolution::Resolved(Box::new(ResolvedObject {
            owner: object.owner.clone(),
            name: object.name.clone(),
            kind: object.kind.clone(),
            container: None,
            member: None,
            overloads,
            quote_exact: raw
                .parts
                .iter()
                .any(|part| part.quoting == QuoteSemantics::Quoted),
            synonym_chain,
            db_link: None,
            identity: object.identity.clone(),
        })))
    }

    async fn walk_synonyms<F>(
        &self,
        owner: &str,
        name: &str,
        allow_public: bool,
        accepts: F,
    ) -> Result<WalkResult, DbError>
    where
        F: Fn(&CatalogObjectKind) -> bool,
    {
        let mut owner = owner.to_owned();
        let mut name = name.to_owned();
        let mut permit_public = allow_public;
        let mut chain = Vec::new();
        let mut visited = HashSet::new();

        loop {
            if !record_synonym_visit(&mut visited, &owner, &name, chain.len()) {
                return Ok(WalkResult::Unresolved);
            }
            let facts = self.object_rows(&owner, &name).await?;
            if facts.incomplete {
                return Ok(WalkResult::Unresolved);
            }
            if !facts.objects.is_empty() {
                let accepted: Vec<_> = facts
                    .objects
                    .into_iter()
                    .filter(|object| accepts(&object.kind))
                    .collect();
                if accepted.is_empty() {
                    return Ok(WalkResult::Unresolved);
                }
                return Ok(WalkResult::Objects {
                    objects: accepted,
                    synonym_chain: chain,
                });
            }

            let mut synonym = self.synonym_row(&owner, &name).await?;
            if synonym.is_none() && permit_public && owner != "PUBLIC" {
                synonym = self.synonym_row("PUBLIC", &name).await?;
            }
            permit_public = false;
            let Some(synonym) = synonym else {
                return Ok(WalkResult::Unresolved);
            };
            let Some(identity) = synonym.identity else {
                return Ok(WalkResult::Unresolved);
            };
            chain.push(SynonymHop {
                owner: synonym.owner,
                name: synonym.name,
                identity,
            });
            if let Some(db_link) = synonym.db_link {
                return Ok(WalkResult::Remote {
                    db_link: RawNamePart::quoted(db_link),
                });
            }
            owner = synonym.target_owner;
            name = synonym.target_name;
        }
    }

    async fn object_rows(&self, owner: &str, name: &str) -> Result<ObjectFacts, DbError> {
        let rows = self
            .conn
            .query_rows(
                self.cx,
                OBJECTS_SQL,
                &[
                    OracleBind::from(owner),
                    OracleBind::from(name),
                    OracleBind::from((MAX_CANDIDATES + 1) as i64),
                ],
            )
            .await?;
        if rows.len() > MAX_CANDIDATES {
            return Ok(ObjectFacts {
                objects: Vec::new(),
                incomplete: true,
            });
        }
        let mut objects = Vec::new();
        for row in &rows {
            let Some(object) = ObjectFact::from_row(row, self.context) else {
                return Ok(ObjectFacts {
                    objects: Vec::new(),
                    incomplete: true,
                });
            };
            if object.kind != CatalogObjectKind::Synonym {
                objects.push(object);
            }
        }
        Ok(ObjectFacts {
            objects,
            incomplete: false,
        })
    }

    async fn synonym_row(&self, owner: &str, name: &str) -> Result<Option<SynonymFact>, DbError> {
        let rows = self
            .conn
            .query_rows(
                self.cx,
                SYNONYMS_SQL,
                &[
                    OracleBind::from(owner),
                    OracleBind::from(name),
                    OracleBind::from(2_i64),
                ],
            )
            .await?;
        if rows.len() != 1 {
            return Ok(None);
        }
        Ok(SynonymFact::from_row(&rows[0], self.context))
    }

    async fn argument_rows(
        &self,
        owner: &str,
        package: Option<&str>,
        name: &str,
    ) -> Result<Option<Vec<ArgumentFact>>, DbError> {
        let (sql, binds) = if let Some(package) = package {
            (
                MEMBER_ARGUMENTS_SQL,
                vec![
                    OracleBind::from(owner),
                    OracleBind::from(package),
                    OracleBind::from(name),
                    OracleBind::from((MAX_ARGUMENT_ROWS + 1) as i64),
                ],
            )
        } else {
            (
                STANDALONE_ARGUMENTS_SQL,
                vec![
                    OracleBind::from(owner),
                    OracleBind::from(name),
                    OracleBind::from((MAX_ARGUMENT_ROWS + 1) as i64),
                ],
            )
        };
        let rows = self.conn.query_rows(self.cx, sql, &binds).await?;
        if rows.len() > MAX_ARGUMENT_ROWS {
            return Ok(None);
        }
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let Some(argument) = ArgumentFact::from_row(row) else {
                return Ok(None);
            };
            out.push(argument);
        }
        Ok(Some(out))
    }

    async fn has_column_conflict(&self, name: &str) -> Result<bool, DbError> {
        let rows = self
            .conn
            .query_rows(
                self.cx,
                COLUMN_CONFLICT_SQL,
                &[
                    OracleBind::from(name),
                    OracleBind::from((MAX_CANDIDATES + 1) as i64),
                ],
            )
            .await?;
        Ok(!rows.is_empty())
    }
}

#[derive(Clone, Copy)]
enum ObjectPurpose {
    From,
    Callable { zero_arg_only: bool },
}

impl ObjectPurpose {
    fn accepts(self, kind: &CatalogObjectKind) -> bool {
        match self {
            Self::From => matches!(
                kind,
                CatalogObjectKind::Table
                    | CatalogObjectKind::View
                    | CatalogObjectKind::MaterializedView
            ),
            Self::Callable {
                zero_arg_only: true,
            } => matches!(kind, CatalogObjectKind::Function),
            Self::Callable {
                zero_arg_only: false,
            } => matches!(
                kind,
                CatalogObjectKind::Function | CatalogObjectKind::Procedure
            ),
        }
    }
}

struct ObjectFacts {
    objects: Vec<ObjectFact>,
    incomplete: bool,
}

#[derive(Clone)]
struct ObjectFact {
    owner: String,
    name: String,
    kind: CatalogObjectKind,
    identity: ResolvedIdentity,
}

impl ObjectFact {
    fn from_row(row: &OracleRow, context: &ResolveCtx) -> Option<Self> {
        let owner = required_text(row, "OWNER")?;
        let name = required_text(row, "OBJECT_NAME")?;
        let object_type = required_text(row, "OBJECT_TYPE")?;
        let object_id = u64::try_from(row.parse_i64("OBJECT_ID")?).ok()?;
        if row.text("STATUS")? != "VALID" {
            return None;
        }
        let edition = optional_text(row, "EDITION_NAME");
        if edition.is_some() && edition != context.edition {
            return None;
        }
        Some(Self {
            owner,
            name,
            kind: object_kind(&object_type),
            identity: ResolvedIdentity { object_id, edition },
        })
    }
}

struct SynonymFact {
    owner: String,
    name: String,
    target_owner: String,
    target_name: String,
    db_link: Option<String>,
    identity: Option<ResolvedIdentity>,
}

impl SynonymFact {
    fn from_row(row: &OracleRow, context: &ResolveCtx) -> Option<Self> {
        let status = row.text("STATUS")?;
        if status != "VALID" {
            return None;
        }
        let edition = optional_text(row, "EDITION_NAME");
        if edition.is_some() && edition != context.edition {
            return None;
        }
        Some(Self {
            owner: required_text(row, "OWNER")?,
            name: required_text(row, "SYNONYM_NAME")?,
            target_owner: required_text(row, "TABLE_OWNER")?,
            target_name: required_text(row, "TABLE_NAME")?,
            db_link: optional_text(row, "DB_LINK"),
            identity: Some(ResolvedIdentity {
                object_id: u64::try_from(row.parse_i64("OBJECT_ID")?).ok()?,
                edition,
            }),
        })
    }
}

#[derive(Clone)]
struct ArgumentFact {
    subprogram_id: u32,
    overload: Option<String>,
    position: u32,
    data_level: u32,
    in_out: String,
    defaulted: bool,
}

impl ArgumentFact {
    fn from_row(row: &OracleRow) -> Option<Self> {
        Some(Self {
            subprogram_id: u32::try_from(row.parse_i64("SUBPROGRAM_ID")?).ok()?,
            overload: optional_text(row, "OVERLOAD"),
            position: u32::try_from(row.parse_i64("POSITION")?).ok()?,
            data_level: u32::try_from(row.parse_i64("DATA_LEVEL")?).ok()?,
            in_out: required_text(row, "IN_OUT")?,
            defaulted: row.text("DEFAULTED")? == "Y",
        })
    }
}

enum WalkResult {
    Objects {
        objects: Vec<ObjectFact>,
        synonym_chain: Vec<SynonymHop>,
    },
    Remote {
        db_link: RawNamePart,
    },
    Unresolved,
}

impl WalkResult {
    fn into_resolution(self) -> Resolution {
        match self {
            Self::Remote { db_link } => Resolution::Remote { db_link },
            Self::Objects { objects, .. } => ambiguous_objects(&objects),
            Self::Unresolved => Resolution::Unresolved,
        }
    }
}

struct CallableFacts {
    kind: CatalogObjectKind,
    overloads: Vec<ResolvedOverload>,
}

fn callable_overloads(rows: &[ArgumentFact], zero_arg_only: bool) -> Option<CallableFacts> {
    if rows.is_empty() {
        return Some(CallableFacts {
            kind: CatalogObjectKind::Procedure,
            overloads: Vec::new(),
        });
    }
    let mut grouped: HashMap<(u32, Option<String>), (bool, bool)> = HashMap::new();
    for row in rows {
        let required_input =
            row.data_level == 0 && row.position > 0 && row.in_out.contains("IN") && !row.defaulted;
        let is_function = row.data_level == 0 && row.position == 0;
        grouped
            .entry((row.subprogram_id, row.overload.clone()))
            .and_modify(|(has_required, has_return)| {
                *has_required |= required_input;
                *has_return |= is_function;
            })
            .or_insert((required_input, is_function));
    }
    if grouped.len() > MAX_CANDIDATES {
        return None;
    }
    let has_function = grouped.values().any(|(_, has_return)| *has_return);
    let has_procedure = grouped.values().any(|(_, has_return)| !*has_return);
    if has_function && has_procedure {
        return None;
    }
    let mut out: Vec<_> = grouped
        .into_iter()
        .filter(|(_, (has_required, has_return))| !zero_arg_only || (!*has_required && *has_return))
        .map(|((subprogram_id, overload), _)| ResolvedOverload {
            subprogram_id,
            overload,
        })
        .collect();
    out.sort_by(|left, right| {
        left.subprogram_id
            .cmp(&right.subprogram_id)
            .then_with(|| left.overload.cmp(&right.overload))
    });
    Some(CallableFacts {
        kind: if has_function {
            CatalogObjectKind::Function
        } else {
            CatalogObjectKind::Procedure
        },
        overloads: out,
    })
}

fn merge_alternatives(left: Resolution, right: Resolution) -> Resolution {
    match (left, right) {
        (Resolution::Unresolved, resolution) | (resolution, Resolution::Unresolved) => resolution,
        (Resolution::Resolved(left), Resolution::Resolved(right)) => Resolution::Ambiguous {
            candidates: vec![left.identity.clone(), right.identity.clone()],
        },
        (Resolution::Ambiguous { candidates }, _) | (_, Resolution::Ambiguous { candidates }) => {
            Resolution::Ambiguous { candidates }
        }
        (Resolution::Remote { .. }, Resolution::Resolved(_))
        | (Resolution::Resolved(_), Resolution::Remote { .. })
        | (Resolution::Remote { .. }, Resolution::Remote { .. }) => Resolution::Unresolved,
    }
}

fn record_synonym_visit(
    visited: &mut HashSet<(String, String)>,
    owner: &str,
    name: &str,
    completed_hops: usize,
) -> bool {
    completed_hops < MAX_SYNONYM_HOPS && visited.insert((owner.to_owned(), name.to_owned()))
}

fn ambiguous_objects(objects: &[ObjectFact]) -> Resolution {
    if objects.is_empty() {
        Resolution::Unresolved
    } else if objects.len() == 1 {
        Resolution::Ambiguous {
            candidates: vec![objects[0].identity.clone()],
        }
    } else {
        Resolution::Ambiguous {
            candidates: objects
                .iter()
                .take(MAX_CANDIDATES)
                .map(|object| object.identity.clone())
                .collect(),
        }
    }
}

fn normalize_parts(parts: &[RawNamePart]) -> Option<Vec<String>> {
    parts
        .iter()
        .map(|part| {
            if part.text.is_empty()
                || part.text.len() > MAX_IDENTIFIER_BYTES
                || part.text.chars().any(char::is_control)
            {
                return None;
            }
            Some(match part.quoting {
                QuoteSemantics::Unquoted => part.text.to_ascii_uppercase(),
                QuoteSemantics::Quoted => part.text.clone(),
            })
        })
        .collect()
}

fn parts_equal(left: &RawNamePart, right: &RawNamePart) -> bool {
    match (left.quoting, right.quoting) {
        (QuoteSemantics::Quoted, QuoteSemantics::Quoted) => left.text == right.text,
        (QuoteSemantics::Quoted, QuoteSemantics::Unquoted) => {
            left.text == right.text.to_ascii_uppercase()
        }
        (QuoteSemantics::Unquoted, QuoteSemantics::Quoted) => {
            left.text.to_ascii_uppercase() == right.text
        }
        (QuoteSemantics::Unquoted, QuoteSemantics::Unquoted) => {
            left.text.eq_ignore_ascii_case(&right.text)
        }
    }
}

fn object_kind(value: &str) -> CatalogObjectKind {
    match value {
        "TABLE" => CatalogObjectKind::Table,
        "VIEW" | "EDITIONING VIEW" => CatalogObjectKind::View,
        "MATERIALIZED VIEW" => CatalogObjectKind::MaterializedView,
        "SEQUENCE" => CatalogObjectKind::Sequence,
        "FUNCTION" => CatalogObjectKind::Function,
        "PROCEDURE" => CatalogObjectKind::Procedure,
        "PACKAGE" => CatalogObjectKind::Package,
        "TYPE" => CatalogObjectKind::Type,
        "SYNONYM" => CatalogObjectKind::Synonym,
        other => CatalogObjectKind::Other(other.to_owned()),
    }
}

fn required_text(row: &OracleRow, name: &str) -> Option<String> {
    let value = row.text(name)?;
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn optional_text(row: &OracleRow, name: &str) -> Option<String> {
    row.text(name)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OracleCell;

    fn row(columns: &[(&str, Option<&str>)]) -> OracleRow {
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

    #[test]
    fn dictionary_queries_bind_every_dynamic_identifier_and_bound_every_result() {
        assert!(OBJECTS_SQL.contains("owner = :1 AND object_name = :2"));
        assert!(OBJECTS_SQL.contains("ROWNUM <= :3"));
        assert!(SYNONYMS_SQL.contains("s.owner = :1 AND s.synonym_name = :2"));
        assert!(SYNONYMS_SQL.contains("ROWNUM <= :3"));
        assert!(STANDALONE_ARGUMENTS_SQL.contains("owner = :1"));
        assert!(STANDALONE_ARGUMENTS_SQL.contains("object_name = :2"));
        assert!(MEMBER_ARGUMENTS_SQL.contains("package_name = :2 AND object_name = :3"));
        assert!(MEMBER_ARGUMENTS_SQL.contains("ROWNUM <= :4"));
        assert!(COLUMN_CONFLICT_SQL.contains("column_name = :1"));
        assert!(COLUMN_CONFLICT_SQL.contains("ROWNUM <= :2"));
        for sql in [
            OBJECTS_SQL,
            SYNONYMS_SQL,
            STANDALONE_ARGUMENTS_SQL,
            MEMBER_ARGUMENTS_SQL,
            COLUMN_CONFLICT_SQL,
        ] {
            assert!(!sql.contains("{}"));
        }
    }

    #[test]
    fn quote_normalization_and_scope_matching_follow_oracle_rules() {
        let normalized = normalize_parts(&[
            RawNamePart::unquoted("mixed_case"),
            RawNamePart::quoted("MixedCase"),
        ])
        .expect("valid names");
        assert_eq!(normalized, ["MIXED_CASE", "MixedCase"]);
        assert!(parts_equal(
            &RawNamePart::unquoted("orders"),
            &RawNamePart::quoted("ORDERS")
        ));
        assert!(!parts_equal(
            &RawNamePart::unquoted("orders"),
            &RawNamePart::quoted("orders")
        ));
    }

    #[test]
    fn object_rows_reject_invalid_and_wrong_edition_evidence() {
        let mut context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(7));
        context.edition = Some("BLUE".to_owned());
        let valid = row(&[
            ("OWNER", Some("APP")),
            ("OBJECT_NAME", Some("ORDERS")),
            ("OBJECT_TYPE", Some("TABLE")),
            ("OBJECT_ID", Some("42")),
            ("STATUS", Some("VALID")),
            ("EDITION_NAME", None),
        ]);
        assert!(ObjectFact::from_row(&valid, &context).is_some());
        let wrong_edition = row(&[
            ("OWNER", Some("APP")),
            ("OBJECT_NAME", Some("F")),
            ("OBJECT_TYPE", Some("FUNCTION")),
            ("OBJECT_ID", Some("43")),
            ("STATUS", Some("VALID")),
            ("EDITION_NAME", Some("GREEN")),
        ]);
        assert!(ObjectFact::from_row(&wrong_edition, &context).is_none());
    }

    #[test]
    fn zero_arg_filter_keeps_only_overloads_without_required_inputs() {
        let rows = vec![
            ArgumentFact {
                subprogram_id: 1,
                overload: Some("1".to_owned()),
                position: 0,
                data_level: 0,
                in_out: "OUT".to_owned(),
                defaulted: false,
            },
            ArgumentFact {
                subprogram_id: 2,
                overload: Some("2".to_owned()),
                position: 0,
                data_level: 0,
                in_out: "OUT".to_owned(),
                defaulted: false,
            },
            ArgumentFact {
                subprogram_id: 2,
                overload: Some("2".to_owned()),
                position: 1,
                data_level: 0,
                in_out: "IN".to_owned(),
                defaulted: false,
            },
            ArgumentFact {
                subprogram_id: 3,
                overload: Some("3".to_owned()),
                position: 0,
                data_level: 0,
                in_out: "OUT".to_owned(),
                defaulted: false,
            },
            ArgumentFact {
                subprogram_id: 3,
                overload: Some("3".to_owned()),
                position: 1,
                data_level: 0,
                in_out: "IN".to_owned(),
                defaulted: true,
            },
        ];
        let overloads = callable_overloads(&rows, true).expect("bounded overload set");
        assert_eq!(
            overloads
                .overloads
                .iter()
                .map(|item| item.subprogram_id)
                .collect::<Vec<_>>(),
            [1, 3]
        );
    }

    #[test]
    fn snapshot_rejects_generation_role_scope_or_name_misses() {
        let context = ResolveCtx::new("APP", "APP", oraclemcp_guard::CatalogGeneration(4));
        let loaded = RawName::new([RawNamePart::unquoted("orders")], SyntacticRole::FromFactor);
        let mut entries = HashMap::new();
        entries.insert(
            loaded.clone(),
            Resolution::Resolved(Box::new(ResolvedObject {
                owner: "APP".to_owned(),
                name: "ORDERS".to_owned(),
                kind: CatalogObjectKind::Table,
                container: None,
                member: None,
                overloads: Vec::new(),
                quote_exact: false,
                synonym_chain: Vec::new(),
                db_link: None,
                identity: ResolvedIdentity {
                    object_id: 44,
                    edition: None,
                },
            })),
        );
        let resolver = OracleCatalogResolver {
            context: context.clone(),
            entries,
        };
        assert!(matches!(
            resolver.resolve(&loaded, &context),
            Resolution::Resolved(_)
        ));
        let mut stale = context.clone();
        stale.generation = oraclemcp_guard::CatalogGeneration(5);
        assert_eq!(resolver.resolve(&loaded, &stale), Resolution::Unresolved);
        let mut role_drift = context.clone();
        role_drift.enabled_roles.insert("REPORTER".to_owned());
        assert_eq!(
            resolver.resolve(&loaded, &role_drift),
            Resolution::Unresolved
        );
        let mut scope_drift = context.clone();
        scope_drift
            .statement_scope
            .aliases
            .push(RawNamePart::unquoted("o"));
        assert_eq!(
            resolver.resolve(&loaded, &scope_drift),
            Resolution::Unresolved
        );
        let missing = RawName::new(
            [RawNamePart::unquoted("customers")],
            SyntacticRole::FromFactor,
        );
        assert_eq!(resolver.resolve(&missing, &context), Resolution::Unresolved);
    }

    #[test]
    fn synonym_walk_rejects_cycles_and_overlong_chains() {
        let mut visited = HashSet::new();
        assert!(record_synonym_visit(&mut visited, "APP", "A", 0));
        assert!(record_synonym_visit(&mut visited, "APP", "B", 1));
        assert!(!record_synonym_visit(&mut visited, "APP", "A", 2));

        let mut fresh = HashSet::new();
        assert!(!record_synonym_visit(
            &mut fresh,
            "APP",
            "TOO_DEEP",
            MAX_SYNONYM_HOPS
        ));
    }

    #[test]
    fn remote_alternative_never_becomes_a_resolved_identity() {
        let local = Resolution::Resolved(Box::new(ResolvedObject {
            owner: "APP".to_owned(),
            name: "P".to_owned(),
            kind: CatalogObjectKind::Procedure,
            container: None,
            member: None,
            overloads: Vec::new(),
            quote_exact: false,
            synonym_chain: Vec::new(),
            db_link: None,
            identity: ResolvedIdentity {
                object_id: 9,
                edition: None,
            },
        }));
        let remote = Resolution::Remote {
            db_link: RawNamePart::unquoted("REMOTE_DB"),
        };
        assert_eq!(
            merge_alternatives(local.clone(), remote.clone()),
            Resolution::Unresolved
        );
        assert_eq!(merge_alternatives(remote, local), Resolution::Unresolved);
    }
}
