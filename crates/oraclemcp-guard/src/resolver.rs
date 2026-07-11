//! Engine-free semantic catalog resolution port.
//!
//! The guard cannot infer Oracle object identity from syntax alone.  This port
//! lets the database-facing consumer bind a catalog implementation while the
//! guard crate keeps a fail-closed default.

use std::collections::BTreeSet;

/// How an identifier component appeared in the SQL source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuoteSemantics {
    /// Oracle folds the component to uppercase before lookup.
    Unquoted,
    /// Oracle preserves the component exactly, including case.
    Quoted,
}

/// One component of a syntactic Oracle name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawNamePart {
    pub text: String,
    pub quoting: QuoteSemantics,
}

impl RawNamePart {
    #[must_use]
    pub fn unquoted(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            quoting: QuoteSemantics::Unquoted,
        }
    }

    #[must_use]
    pub fn quoted(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            quoting: QuoteSemantics::Quoted,
        }
    }
}

/// The grammar position in which a name was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyntacticRole {
    FromFactor,
    ValuePosition,
    CallWithArgs,
}

/// A multipart name exactly as the parser observed it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawName {
    pub parts: Vec<RawNamePart>,
    pub role: SyntacticRole,
    pub db_link: Option<RawNamePart>,
}

impl RawName {
    #[must_use]
    pub fn new(parts: impl IntoIterator<Item = RawNamePart>, role: SyntacticRole) -> Self {
        Self {
            parts: parts.into_iter().collect(),
            role,
            db_link: None,
        }
    }

    #[must_use]
    pub fn with_db_link(mut self, db_link: RawNamePart) -> Self {
        self.db_link = Some(db_link);
        self
    }
}

/// Names introduced by the statement itself and therefore resolved before the
/// database catalog is consulted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatementScope {
    pub aliases: Vec<RawNamePart>,
    pub common_table_expressions: Vec<RawNamePart>,
}

/// Monotonic catalog-cache generation owned by the database-facing consumer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CatalogGeneration(pub u64);

/// All session and statement state that can change Oracle name resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveCtx {
    pub connected_schema: String,
    pub current_schema: String,
    pub edition: Option<String>,
    pub enabled_roles: BTreeSet<String>,
    pub statement_scope: StatementScope,
    pub generation: CatalogGeneration,
}

impl ResolveCtx {
    #[must_use]
    pub fn new(
        connected_schema: impl Into<String>,
        current_schema: impl Into<String>,
        generation: CatalogGeneration,
    ) -> Self {
        Self {
            connected_schema: connected_schema.into(),
            current_schema: current_schema.into(),
            edition: None,
            enabled_roles: BTreeSet::new(),
            statement_scope: StatementScope::default(),
            generation,
        }
    }
}

/// Semantic kind returned by the live Oracle catalog.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CatalogObjectKind {
    Table,
    View,
    MaterializedView,
    Sequence,
    Function,
    Procedure,
    Package,
    Type,
    Synonym,
    Other(String),
}

/// A package or SQL type that owns the resolved member.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedContainer {
    pub name: String,
    pub kind: CatalogObjectKind,
}

/// Stable dictionary identity used to reject stale or substituted catalog
/// answers. `object_id` is Oracle's OBJECT_ID; member overloads are separate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedIdentity {
    pub object_id: u64,
    pub edition: Option<String>,
}

/// One callable overload reported by the catalog.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedOverload {
    pub subprogram_id: u32,
    pub overload: Option<String>,
}

/// A synonym hop retained as evidence instead of silently flattening the
/// lookup path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SynonymHop {
    pub owner: String,
    pub name: String,
    pub identity: ResolvedIdentity,
}

/// A catalog object whose identity was proven for the supplied context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedObject {
    pub owner: String,
    pub name: String,
    pub kind: CatalogObjectKind,
    pub container: Option<ResolvedContainer>,
    pub member: Option<String>,
    pub overloads: Vec<ResolvedOverload>,
    pub quote_exact: bool,
    pub synonym_chain: Vec<SynonymHop>,
    pub db_link: Option<String>,
    pub identity: ResolvedIdentity,
}

/// Result of semantic lookup. Every non-`Resolved` variant is deliberately
/// unusable as safety proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    Resolved(Box<ResolvedObject>),
    Ambiguous { candidates: Vec<ResolvedIdentity> },
    Remote { db_link: RawNamePart },
    Unresolved,
}

/// Consumer-side semantic name resolver.
///
/// The default method is intentional: an implementation that has not wired a
/// real dictionary lookup remains fail-closed instead of inheriting a
/// syntactic guess.
pub trait CatalogResolver: Send + Sync {
    fn resolve(&self, _name: &RawName, _ctx: &ResolveCtx) -> Resolution {
        Resolution::Unresolved
    }
}

/// Engine-free default binding.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnresolvedCatalogResolver;

impl CatalogResolver for UnresolvedCatalogResolver {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_name_preserves_quote_role_and_remote_syntax() {
        let name = RawName::new(
            [
                RawNamePart::unquoted("hr"),
                RawNamePart::quoted("MixedCase"),
            ],
            SyntacticRole::CallWithArgs,
        )
        .with_db_link(RawNamePart::quoted("Remote.Db"));

        assert_eq!(name.parts[0].quoting, QuoteSemantics::Unquoted);
        assert_eq!(name.parts[1].text, "MixedCase");
        assert_eq!(name.parts[1].quoting, QuoteSemantics::Quoted);
        assert_eq!(name.role, SyntacticRole::CallWithArgs);
        assert_eq!(
            name.db_link.as_ref().map(|part| part.text.as_str()),
            Some("Remote.Db")
        );
    }

    #[test]
    fn context_retains_every_resolution_input_and_generation() {
        let mut ctx = ResolveCtx::new("LOGIN_USER", "APP_SCHEMA", CatalogGeneration(41));
        ctx.edition = Some("BLUE".to_owned());
        ctx.enabled_roles.insert("REPORTING".to_owned());
        ctx.statement_scope.aliases.push(RawNamePart::unquoted("o"));
        ctx.statement_scope
            .common_table_expressions
            .push(RawNamePart::quoted("Recent"));

        assert_eq!(ctx.connected_schema, "LOGIN_USER");
        assert_eq!(ctx.current_schema, "APP_SCHEMA");
        assert_eq!(ctx.edition.as_deref(), Some("BLUE"));
        assert!(ctx.enabled_roles.contains("REPORTING"));
        assert_eq!(ctx.statement_scope.aliases[0].text, "o");
        assert_eq!(
            ctx.statement_scope.common_table_expressions[0].text,
            "Recent"
        );
        assert_eq!(ctx.generation, CatalogGeneration(41));
    }

    #[test]
    fn default_resolver_is_fail_closed_for_local_and_remote_names() {
        let resolver = UnresolvedCatalogResolver;
        let ctx = ResolveCtx::new("APP", "APP", CatalogGeneration(0));
        let local = RawName::new([RawNamePart::unquoted("orders")], SyntacticRole::FromFactor);
        let remote = local
            .clone()
            .with_db_link(RawNamePart::unquoted("warehouse"));

        assert_eq!(resolver.resolve(&local, &ctx), Resolution::Unresolved);
        assert_eq!(resolver.resolve(&remote, &ctx), Resolution::Unresolved);
    }

    #[test]
    fn consumer_can_return_exact_identity_without_an_engine_dependency() {
        struct TestResolver;

        impl CatalogResolver for TestResolver {
            fn resolve(&self, name: &RawName, ctx: &ResolveCtx) -> Resolution {
                assert_eq!(name.role, SyntacticRole::FromFactor);
                assert_eq!(ctx.generation, CatalogGeneration(7));
                Resolution::Resolved(Box::new(ResolvedObject {
                    owner: "APP".to_owned(),
                    name: "ORDERS".to_owned(),
                    kind: CatalogObjectKind::Table,
                    container: None,
                    member: None,
                    overloads: Vec::new(),
                    quote_exact: true,
                    synonym_chain: Vec::new(),
                    db_link: None,
                    identity: ResolvedIdentity {
                        object_id: 42,
                        edition: None,
                    },
                }))
            }
        }

        let resolution = TestResolver.resolve(
            &RawName::new([RawNamePart::unquoted("orders")], SyntacticRole::FromFactor),
            &ResolveCtx::new("APP", "APP", CatalogGeneration(7)),
        );
        let Resolution::Resolved(object) = resolution else {
            panic!("test resolver must resolve the object");
        };
        assert_eq!(object.identity.object_id, 42);
        assert!(object.quote_exact);
    }
}
