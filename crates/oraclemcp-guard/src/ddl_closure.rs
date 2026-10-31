//! Canonical evidence for the system triggers reachable from one DDL event.
//! This seam supplies evidence, never authority to execute the DDL.

use std::collections::BTreeSet;
use std::fmt::Write;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlparser::dialect::OracleDialect;
use sqlparser::tokenizer::{Token, Tokenizer};

use crate::OperatingLevel;
use crate::mutation_closure::{
    MutationComputation, MutationDatabaseIdentity, MutationUnavailableReason,
};
use crate::purity::{
    AdmissionContext, EffectRefusal, OperatorStatementClass, RoutineEffect, RoutineEffectsV1, admit,
};

/// Oracle events relevant to a DDL closure. `Ddl` and `ServerError` are
/// trigger subscriptions, not exact DDL events for a collection request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DdlEvent {
    Create,
    Alter,
    Drop,
    Truncate,
    Rename,
    Grant,
    Revoke,
    Comment,
    Analyze,
    Audit,
    Noaudit,
    #[serde(rename = "ASSOCIATE STATISTICS")]
    AssociateStatistics,
    #[serde(rename = "DISASSOCIATE STATISTICS")]
    DisassociateStatistics,
    Ddl,
    #[serde(rename = "SERVERERROR")]
    ServerError,
}

impl DdlEvent {
    /// Parse a dictionary event spelling, including Oracle's trailing spaces.
    #[must_use]
    pub fn from_catalog(value: &str) -> Option<Self> {
        Some(match value.trim() {
            "CREATE" => Self::Create,
            "ALTER" => Self::Alter,
            "DROP" => Self::Drop,
            "TRUNCATE" => Self::Truncate,
            "RENAME" => Self::Rename,
            "GRANT" => Self::Grant,
            "REVOKE" => Self::Revoke,
            "COMMENT" => Self::Comment,
            "ANALYZE" => Self::Analyze,
            "AUDIT" => Self::Audit,
            "NOAUDIT" => Self::Noaudit,
            "ASSOCIATE STATISTICS" => Self::AssociateStatistics,
            "DISASSOCIATE STATISTICS" => Self::DisassociateStatistics,
            "DDL" => Self::Ddl,
            // DBA_TRIGGERS uses ERROR; CREATE TRIGGER uses SERVERERROR.
            "ERROR" | "SERVERERROR" => Self::ServerError,
            _ => return None,
        })
    }
}

/// Classifies the event of already guarded literal DDL; it does not validate or
/// admit SQL. Only the operator's exact rendering gets the no-trigger exception.
/// Oracle documents ALTER DATABASE as not firing ALTER/DDL triggers:
/// <https://docs.oracle.com/en/database/oracle/oracle-database/21/lnpls/CREATE-TRIGGER-statement.html>
pub fn ddl_event_for_statement(sql: &str) -> Result<Option<DdlEvent>, MutationUnavailableReason> {
    if OperatorStatementClass::from_exact_rendered_sql(sql).is_some() {
        return Ok(None);
    }
    let mut tokens = Tokenizer::new(&OracleDialect {}, sql)
        .tokenize()
        .map_err(|_| MutationUnavailableReason::InvalidInput)?;
    tokens.retain(|token| !matches!(token, Token::Whitespace(_)));
    if matches!(tokens.last(), Some(Token::SemiColon)) {
        tokens.pop();
    }
    if tokens.iter().any(|token| matches!(token, Token::SemiColon)) {
        return Err(MutationUnavailableReason::InvalidInput);
    }
    let word = |i| match tokens.get(i) {
        Some(Token::Word(word)) if word.quote_style.is_none() => {
            Some(word.value.to_ascii_uppercase())
        }
        _ => None,
    };
    let first = word(0).ok_or(MutationUnavailableReason::InvalidInput)?;
    if tokens.len() < 2
        || (matches!(first.as_str(), "ALTER" | "CREATE")
            && matches!(word(1).as_deref(), Some("DATABASE" | "CONTROLFILE")))
    {
        return Err(MutationUnavailableReason::UnsupportedMechanism);
    }
    let event = if matches!(first.as_str(), "ASSOCIATE" | "DISASSOCIATE") {
        if word(1).as_deref() != Some("STATISTICS") {
            return Err(MutationUnavailableReason::UnsupportedMechanism);
        }
        DdlEvent::from_catalog(&format!("{first} STATISTICS"))
    } else {
        DdlEvent::from_catalog(&first)
    };
    event
        .filter(|event| !matches!(event, DdlEvent::Ddl | DdlEvent::ServerError))
        .map(Some)
        .ok_or(MutationUnavailableReason::UnsupportedMechanism)
}

/// Dictionary spellings of the object affected by the statement. CREATE does
/// not yet have an object id; the collector never invents one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DdlObject {
    pub owner: String,
    pub name: String,
    pub object_type: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdlTriggerScope {
    Schema,
    Database,
}

/// A supported predicate is retained even when statically false. Collection
/// never drops a trigger based on a heuristic about its body or WHEN clause.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DdlPredicate {
    Unconditional,
    DictionaryGuard { text: String, value: bool },
    Unknown { text: String },
}

impl DdlPredicate {
    /// Only bounded Boolean combinations of exact dictionary-attribute/string
    /// comparisons are understood. Other expressions retain Unknown. Even a
    /// false result is descriptive: it never removes a source from collection.
    #[must_use]
    pub fn from_catalog(text: Option<&str>, object: &DdlObject) -> Self {
        let Some(text) = text.filter(|text| !text.trim().is_empty()) else {
            return Self::Unconditional;
        };
        let parsed = (|| {
            if text.len() > 4096 {
                return None;
            }
            let tokens = Tokenizer::new(&OracleDialect {}, text).tokenize().ok()?;
            let tokens: Vec<_> = tokens
                .into_iter()
                .filter(|token| !matches!(token, Token::Whitespace(_)))
                .collect();
            if tokens.len() > 256 {
                return None;
            }
            let mut parser = PredicateParser {
                tokens: &tokens,
                position: 0,
                depth: 0,
                object,
            };
            let value = parser.disjunction()?;
            (parser.position == tokens.len()).then_some(value)
        })();
        match parsed {
            Some(value) => Self::DictionaryGuard {
                text: text.into(),
                value,
            },
            None => Self::Unknown { text: text.into() },
        }
    }
}

struct PredicateParser<'a> {
    tokens: &'a [Token],
    position: usize,
    depth: u8,
    object: &'a DdlObject,
}

impl PredicateParser<'_> {
    fn keyword(&mut self, expected: &str) -> bool {
        if matches!(self.tokens.get(self.position), Some(Token::Word(word)) if word.quote_style.is_none() && word.value.eq_ignore_ascii_case(expected))
        {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn disjunction(&mut self) -> Option<bool> {
        let mut value = self.conjunction()?;
        while self.keyword("OR") {
            let right = self.conjunction()?;
            value |= right;
        }
        Some(value)
    }

    fn conjunction(&mut self) -> Option<bool> {
        let mut value = self.atom()?;
        while self.keyword("AND") {
            let right = self.atom()?;
            value &= right;
        }
        Some(value)
    }

    fn atom(&mut self) -> Option<bool> {
        if self.depth >= 16 {
            return None;
        }
        self.depth += 1;
        let value = if self.keyword("NOT") {
            !self.atom()?
        } else if self.tokens.get(self.position) == Some(&Token::LParen) {
            self.position += 1;
            let value = self.disjunction()?;
            if self.tokens.get(self.position) != Some(&Token::RParen) {
                return None;
            }
            self.position += 1;
            value
        } else {
            let actual = if self.keyword("ORA_DICT_OBJ_OWNER") {
                &self.object.owner
            } else if self.keyword("ORA_DICT_OBJ_NAME") {
                &self.object.name
            } else if self.keyword("ORA_DICT_OBJ_TYPE") {
                &self.object.object_type
            } else {
                return None;
            };
            if self.tokens.get(self.position) == Some(&Token::LParen) {
                if self.tokens.get(self.position + 1) != Some(&Token::RParen) {
                    return None;
                }
                self.position += 2;
            }
            let equal = match self.tokens.get(self.position)? {
                Token::Eq => true,
                Token::Neq => false,
                _ => return None,
            };
            self.position += 1;
            let Token::SingleQuotedString(expected) = self.tokens.get(self.position)? else {
                return None;
            };
            if expected.is_empty() {
                return None;
            }
            self.position += 1;
            (actual == expected) == equal
        };
        self.depth -= 1;
        Some(value)
    }
}

/// Exact trigger metadata plus a source-bound whole-call-closure effect proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DdlTriggerFact {
    pub owner: String,
    pub name: String,
    pub object_id: u64,
    pub last_ddl_time: String,
    pub scope: DdlTriggerScope,
    pub schema: Option<String>,
    pub timing: String,
    pub events: BTreeSet<DdlEvent>,
    pub status: String,
    pub predicate: DdlPredicate,
    pub metadata_sha256: String,
    pub source_sha256: Option<String>,
    pub routine_closure_fingerprint: Option<String>,
    pub effects: RoutineEffectsV1,
    pub computation: MutationComputation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DdlClosureContract {
    #[serde(rename = "DdlEffectClosureV1")]
    V1,
}

/// A complete result needs positive DBA-level trigger visibility in the current
/// container, fresh session context, complete source and engine proofs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DdlEffectClosureV1 {
    contract: DdlClosureContract,
    pub database: Option<MutationDatabaseIdentity>,
    pub event: DdlEvent,
    pub object: DdlObject,
    pub session_user: Option<String>,
    pub current_schema: Option<String>,
    pub catalog_sha256: Option<String>,
    pub catalog_row_count: u32,
    pub database_triggers_visible: bool,
    pub triggers: Vec<DdlTriggerFact>,
    pub unavailable: BTreeSet<MutationUnavailableReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DdlClosureRefusal {
    Unknown,
    Effect(EffectRefusal),
}

fn hash_is_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl DdlEffectClosureV1 {
    #[must_use]
    pub fn new(event: DdlEvent, object: DdlObject) -> Self {
        Self {
            contract: DdlClosureContract::V1,
            database: None,
            event,
            object,
            session_user: None,
            current_schema: None,
            catalog_sha256: None,
            catalog_row_count: 0,
            database_triggers_visible: false,
            triggers: Vec::new(),
            unavailable: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unavailable.is_empty()
            && !matches!(self.event, DdlEvent::Ddl | DdlEvent::ServerError)
            && !self.object.owner.is_empty()
            && !self.object.name.is_empty()
            && !self.object.object_type.is_empty()
            && self.database.as_ref().is_some_and(|db| {
                !db.dbid.is_empty() && !db.container.is_empty() && !db.edition.is_empty()
            })
            && self
                .session_user
                .as_deref()
                .is_some_and(|name| !name.is_empty())
            && self
                .current_schema
                .as_deref()
                .is_some_and(|name| !name.is_empty())
            && self.database_triggers_visible
            && self.catalog_sha256.as_deref().is_some_and(hash_is_valid)
            && self.triggers.iter().all(|trigger| {
                trigger.computation == MutationComputation::Computed
                    && trigger.status == "ENABLED"
                    && !trigger.owner.is_empty()
                    && !trigger.name.is_empty()
                    && trigger.object_id > 0
                    && !trigger.last_ddl_time.is_empty()
                    && matches!(trigger.timing.as_str(), "BEFORE EVENT" | "AFTER EVENT")
                    && (trigger.events.contains(&self.event)
                        || trigger.events.contains(&DdlEvent::Ddl)
                        || trigger.events.contains(&DdlEvent::ServerError))
                    && (!trigger.events.contains(&DdlEvent::ServerError)
                        || trigger.timing == "AFTER EVENT")
                    && (trigger.scope != DdlTriggerScope::Schema
                        || trigger.schema.as_ref() == self.session_user.as_ref())
                    && !matches!(trigger.predicate, DdlPredicate::Unknown { .. })
                    && hash_is_valid(&trigger.metadata_sha256)
                    && trigger.source_sha256.as_deref().is_some_and(hash_is_valid)
                    && trigger
                        .routine_closure_fingerprint
                        .as_deref()
                        .is_some_and(hash_is_valid)
                    && !trigger
                        .effects
                        .iter()
                        .any(|effect| effect == RoutineEffect::Unknown)
            })
    }

    /// Every trigger goes through the shared W7 DDL-trigger admission rule.
    pub fn admit(&self) -> Result<OperatingLevel, DdlClosureRefusal> {
        if !self.is_complete() {
            return Err(DdlClosureRefusal::Unknown);
        }
        self.triggers
            .iter()
            .try_fold(OperatingLevel::ReadOnly, |level, trigger| {
                admit(&trigger.effects, AdmissionContext::DdlTrigger)
                    .map(|required| level.max(required))
                    .map_err(DdlClosureRefusal::Effect)
            })
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut closure = self.clone();
        closure.triggers.sort_by_key(|trigger| {
            serde_json::to_vec(trigger).expect("serializable trigger evidence")
        });
        serde_json::to_vec(&closure).expect("serializable DDL evidence")
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"omcp/ddl-effect-closure/v1\0");
        hash.update(self.canonical_bytes());
        let mut encoded = String::with_capacity(64);
        for byte in hash.finalize() {
            write!(&mut encoded, "{byte:02x}").expect("String write");
        }
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddl_closure_alter_database_default_edition_has_no_ddl_trigger_event() {
        assert_eq!(
            ddl_event_for_statement("ALTER DATABASE DEFAULT EDITION = \"NEXT_STAGE\""),
            Ok(None)
        );
        assert!(
            ddl_event_for_statement(
                "ALTER DATABASE DEFAULT EDITION = \"NEXT_STAGE\"; DROP TABLE T"
            )
            .is_err()
        );
        assert!(ddl_event_for_statement("ALTER DATABASE OPEN").is_err());
    }

    #[test]
    fn ddl_event_create_or_replace_is_create_and_unknown_statements_refuse() {
        assert_eq!(
            ddl_event_for_statement("CREATE OR REPLACE VIEW V AS SELECT 1 FROM SYS.DUAL"),
            Ok(Some(DdlEvent::Create))
        );
        for sql in [
            "CREATE DATABASE X",
            "CREATE CONTROLFILE X",
            "SELECT 1 FROM SYS.DUAL",
            "DDL X",
            "DROP TABLE X; DROP TABLE Y",
        ] {
            assert!(ddl_event_for_statement(sql).is_err(), "{sql}");
        }
    }

    fn complete(effects: RoutineEffectsV1) -> DdlEffectClosureV1 {
        let mut closure = DdlEffectClosureV1::new(
            DdlEvent::Create,
            DdlObject {
                owner: "APP".into(),
                name: "T".into(),
                object_type: "TABLE".into(),
            },
        );
        closure.database = Some(MutationDatabaseIdentity {
            dbid: "1".into(),
            container: "FREEPDB1".into(),
            edition: "ORA$BASE".into(),
        });
        closure.session_user = Some("APP".into());
        closure.current_schema = Some("OTHER".into());
        closure.catalog_sha256 = Some("a".repeat(64));
        closure.database_triggers_visible = true;
        closure.catalog_row_count = 1;
        closure.triggers.push(DdlTriggerFact {
            owner: "APP".into(),
            name: "AUDIT_DDL".into(),
            object_id: 42,
            last_ddl_time: "2026-10-31T00:00:00".into(),
            scope: DdlTriggerScope::Schema,
            schema: Some("APP".into()),
            timing: "AFTER EVENT".into(),
            events: BTreeSet::from([DdlEvent::Create]),
            status: "ENABLED".into(),
            predicate: DdlPredicate::Unconditional,
            metadata_sha256: "b".repeat(64),
            source_sha256: Some("c".repeat(64)),
            routine_closure_fingerprint: Some("d".repeat(64)),
            effects,
            computation: MutationComputation::Computed,
        });
        closure
    }

    fn refused(effect: RoutineEffect) {
        let closure = complete(RoutineEffectsV1::new([effect]));
        assert!(closure.is_complete());
        assert_eq!(
            closure.admit(),
            Err(DdlClosureRefusal::Effect(
                admit(&closure.triggers[0].effects, AdmissionContext::DdlTrigger).unwrap_err()
            ))
        );
    }

    #[test]
    fn ddl_closure_trigger_with_nextval_refused() {
        refused(RoutineEffect::SequenceAdvance);
    }
    #[test]
    fn ddl_closure_trigger_with_dynamic_sql_refused() {
        refused(RoutineEffect::DynamicSql);
    }
    #[test]
    fn ddl_closure_trigger_with_operator_only_refused() {
        refused(RoutineEffect::OperatorOnly(
            OperatorStatementClass::DefaultEditionFlip,
        ));
    }
    #[test]
    fn ddl_closure_trigger_with_dml_refused() {
        refused(RoutineEffect::Dml);
    }
    #[test]
    fn ddl_closure_trigger_with_autonomous_refused() {
        refused(RoutineEffect::Autonomous);
    }

    #[test]
    fn ddl_closure_readonly_trigger_admitted() {
        let closure = complete(RoutineEffectsV1::new([RoutineEffect::ReadDb]));
        assert_eq!(closure.admit(), Ok(OperatingLevel::ReadOnly));
        let session = complete(RoutineEffectsV1::new([
            RoutineEffect::ReadDb,
            RoutineEffect::SessionState,
        ]));
        assert_eq!(session.admit(), Ok(OperatingLevel::ReadWrite));
    }

    #[test]
    fn ddl_closure_when_clause_unsupported_is_unknown() {
        let mut closure = complete(RoutineEffectsV1::default());
        closure.triggers[0].predicate =
            DdlPredicate::from_catalog(Some("APP.CALLBACK() = 1"), &closure.object);
        assert!(matches!(
            closure.triggers[0].predicate,
            DdlPredicate::Unknown { .. }
        ));
        assert_eq!(closure.admit(), Err(DdlClosureRefusal::Unknown));
    }

    #[test]
    fn ddl_closure_predicate_is_bounded_and_never_erases_trigger_effects() {
        let mut closure = complete(RoutineEffectsV1::new([RoutineEffect::Dml]));
        for (text, value) in [
            (
                "ora_dict_obj_owner = 'APP' AND (ora_dict_obj_type() = 'TABLE' OR ora_dict_obj_name = 'X')",
                true,
            ),
            ("NOT ora_dict_obj_name = 'T'", false),
        ] {
            closure.triggers[0].predicate = DdlPredicate::from_catalog(Some(text), &closure.object);
            assert_eq!(
                closure.triggers[0].predicate,
                DdlPredicate::DictionaryGuard {
                    text: text.into(),
                    value
                }
            );
            assert!(matches!(closure.admit(), Err(DdlClosureRefusal::Effect(_))));
        }
        for text in [
            "ora_dict_obj_name = ''",
            "ora_dict_obj_name = 'T' OR app.f() = 'x'",
            "ora_dict_obj_name = 'T';",
            "ora_dict_obj_name LIKE '%'",
            "ora_dict_obj_name = 'T' garbage",
        ] {
            assert!(
                matches!(
                    DdlPredicate::from_catalog(Some(text), &closure.object),
                    DdlPredicate::Unknown { .. }
                ),
                "{text}"
            );
        }
        let deep = format!(
            "{}ora_dict_obj_name = 'T'{}",
            "(".repeat(100),
            ")".repeat(100)
        );
        assert!(matches!(
            DdlPredicate::from_catalog(Some(&deep), &closure.object),
            DdlPredicate::Unknown { .. }
        ));
    }

    #[test]
    fn ddl_closure_servererror_effects_use_ddl_admission_for_every_event() {
        let mut closure = complete(RoutineEffectsV1::new([RoutineEffect::Dml]));
        closure.triggers[0].events = BTreeSet::from([DdlEvent::ServerError]);
        closure.triggers[0].timing = "AFTER EVENT".into();
        for event in [
            DdlEvent::Create,
            DdlEvent::Alter,
            DdlEvent::Drop,
            DdlEvent::Truncate,
            DdlEvent::Rename,
            DdlEvent::Grant,
            DdlEvent::Revoke,
            DdlEvent::Comment,
            DdlEvent::Analyze,
            DdlEvent::Audit,
            DdlEvent::Noaudit,
            DdlEvent::AssociateStatistics,
            DdlEvent::DisassociateStatistics,
        ] {
            closure.event = event;
            assert!(closure.is_complete());
            assert_eq!(
                closure.admit(),
                Err(DdlClosureRefusal::Effect(EffectRefusal::DdlTriggerEffect(
                    RoutineEffect::Dml
                )))
            );
        }
        for subscription in [DdlEvent::Ddl, DdlEvent::ServerError] {
            closure.event = subscription;
            assert!(
                !closure.is_complete(),
                "subscriptions are not exact requests"
            );
        }
        assert_eq!(
            DdlEvent::from_catalog("SERVERERROR   "),
            Some(DdlEvent::ServerError)
        );
        assert_eq!(
            DdlEvent::from_catalog("ERROR   "),
            Some(DdlEvent::ServerError)
        );
        assert_eq!(
            serde_json::to_string(&DdlEvent::ServerError).unwrap(),
            "\"SERVERERROR\""
        );
        assert!(ddl_event_for_statement("SERVERERROR anything").is_err());
    }

    #[test]
    fn ddl_closure_hash_changes_on_trigger_recompile() {
        let closure = complete(RoutineEffectsV1::default());
        for field in [
            "source",
            "ddl_time",
            "effects",
            "metadata",
            "closure",
            "status",
            "event",
            "container",
            "schema",
        ] {
            let mut changed = closure.clone();
            match field {
                "source" => changed.triggers[0].source_sha256 = Some("e".repeat(64)),
                "ddl_time" => changed.triggers[0].last_ddl_time.push('1'),
                "effects" => {
                    changed.triggers[0].effects = RoutineEffectsV1::new([RoutineEffect::Dml])
                }
                "metadata" => changed.triggers[0].metadata_sha256 = "e".repeat(64),
                "closure" => changed.triggers[0].routine_closure_fingerprint = Some("e".repeat(64)),
                "status" => changed.triggers[0].status = "DISABLED".into(),
                "event" => changed.event = DdlEvent::Drop,
                "container" => changed.database.as_mut().unwrap().container.push('2'),
                "schema" => changed.current_schema = Some("APP".into()),
                _ => unreachable!(),
            }
            assert_ne!(changed.fingerprint(), closure.fingerprint(), "{field}");
        }
        let mut reordered = closure.clone();
        reordered.triggers.push(closure.triggers[0].clone());
        reordered.triggers[1].name = "B".into();
        let mut reverse = reordered.clone();
        reverse.triggers.reverse();
        assert_eq!(reverse.canonical_bytes(), reordered.canonical_bytes());
        assert_eq!(
            serde_json::from_slice::<DdlEffectClosureV1>(&closure.canonical_bytes()).unwrap(),
            closure
        );
    }
}
