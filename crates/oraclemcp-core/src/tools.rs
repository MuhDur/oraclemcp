//! The generic tool-registry contract for the `oraclemcp` MCP core.
//!
//! Every tool the server advertises over MCP is a [`ToolDescriptor`] held in a
//! [`ToolRegistry`]. The engine-side (or operator-defined) code contributes
//! its slice of tools by registering descriptors — the core never reaches into
//! a tool's implementation. Relocated from `plsql-mcp`'s `tools.rs` (bead
//! P0-0); native transports render descriptors from this registry.

use serde::{Deserialize, Serialize};

/// Tier of a registered tool — informs the safety / operating-level gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ToolTier {
    /// Static-analysis tool — operates on source, dependency graphs, and
    /// catalog snapshots only. Available regardless of profile; never touches
    /// a live database.
    FoundationStatic,
    /// Live-DB tool — gated by an operating level / safety profile that allows
    /// the operation.
    FoundationLiveDb,
}

/// Stable, machine-readable descriptor for a registered tool.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolDescriptor {
    /// The tool's stable name (e.g. `oracle_query`).
    pub name: String,
    /// Human-readable title for MCP clients that render tool catalogs.
    pub title: String,
    /// The tool's tier.
    pub tier: ToolTier,
    /// A one-line agent-facing summary.
    pub summary: String,
    /// The tool's JSON-Schema for its arguments, advertised to agents in
    /// `tools/list` so a call can be constructed correctly first-try. `None`
    /// falls back to the permissive `{type:object, additionalProperties:true}`
    /// (oracle-da9j.1). A `Value` so engine modules can hand-write or
    /// schemars-derive it without this crate depending on either.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
    /// Optional JSON-Schema for the tool's `structuredContent`, advertised to
    /// MCP clients as `outputSchema`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// Whether the tool performs a destructive / irreversible write (DDL,
    /// deploy, drop). Surfaced over the wire so an agent (and a gating layer)
    /// can isolate the destructive cluster from read-only tools
    /// (oracle-da9j.9). Defaults to `false`.
    #[serde(default)]
    pub destructive: bool,
    /// Explicit MCP tool annotations. These are advisory hints for clients; the
    /// SQL classifier and operating-level gate remain the enforcement path.
    pub annotations: ToolAnnotations,
}

/// Advisory MCP tool annotations, emitted with every advertised tool so
/// clients do not fall back to unsafe defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    /// Whether the tool is read-only.
    pub read_only_hint: bool,
    /// Whether the tool may perform destructive or irreversible writes.
    pub destructive_hint: bool,
    /// Whether repeating the same call is expected to be safe.
    pub idempotent_hint: bool,
    /// Whether the tool interacts with open-world external systems.
    pub open_world_hint: bool,
}

impl ToolAnnotations {
    /// Conservative hints for the read-only Oracle tool surface.
    pub const fn read_only() -> Self {
        Self {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        }
    }

    /// Conservative hints for gated session elevation, DML, DDL, and deploy
    /// tools. They remain fail-closed at runtime; these hints only guide MCP
    /// clients.
    pub const fn destructive() -> Self {
        Self {
            read_only_hint: false,
            destructive_hint: true,
            idempotent_hint: false,
            open_world_hint: false,
        }
    }
}

impl Default for ToolAnnotations {
    fn default() -> Self {
        Self::read_only()
    }
}

impl ToolDescriptor {
    /// A read-only, non-destructive descriptor with no advertised arg schema
    /// (the permissive default). Chain [`Self::with_input_schema`] /
    /// [`Self::destructive`] to enrich it.
    #[must_use]
    pub fn new(name: impl Into<String>, tier: ToolTier, summary: impl Into<String>) -> Self {
        let name = name.into();
        let title = title_from_name(&name);
        Self {
            name,
            title,
            tier,
            summary: summary.into(),
            input_schema: None,
            output_schema: None,
            destructive: false,
            annotations: ToolAnnotations::read_only(),
        }
    }

    /// Attach the tool's argument JSON-Schema (advertised in `tools/list`).
    #[must_use]
    pub fn with_input_schema(mut self, schema: serde_json::Value) -> Self {
        self.input_schema = Some(schema);
        self
    }

    /// Attach the tool's structured-content JSON-Schema.
    #[must_use]
    pub fn with_output_schema(mut self, schema: serde_json::Value) -> Self {
        self.output_schema = Some(schema);
        self
    }

    /// Override the generated human-readable MCP title.
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Mark the tool as performing a destructive / irreversible write.
    #[must_use]
    pub fn destructive(mut self) -> Self {
        self.destructive = true;
        self.annotations = ToolAnnotations::destructive();
        self
    }
}

fn title_from_name(name: &str) -> String {
    name.split('_')
        .filter(|part| !part.is_empty())
        .map(title_part)
        .collect::<Vec<_>>()
        .join(" ")
}

fn title_part(part: &str) -> String {
    match part.to_ascii_lowercase().as_str() {
        "clob" => "CLOB".to_owned(),
        "ddl" => "DDL".to_owned(),
        "dml" => "DML".to_owned(),
        "sql" => "SQL".to_owned(),
        "dbms" => "DBMS".to_owned(),
        "http" => "HTTP".to_owned(),
        "mcp" => "MCP".to_owned(),
        "oauth" => "OAuth".to_owned(),
        "plscope" => "PL/Scope".to_owned(),
        _ => {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect(),
                None => String::new(),
            }
        }
    }
}

/// Minimal registry that per-tool modules populate; dedups by name.
// `Eq`/`Hash` were dropped from `ToolDescriptor` when it gained an
// `input_schema: Option<serde_json::Value>` (Value is not Eq/Hash); the
// registry only ever needs structural `PartialEq` for tests.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolRegistry {
    /// The registered tool descriptors, in registration order.
    pub tools: Vec<ToolDescriptor>,
}

impl ToolRegistry {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a descriptor. Idempotent — re-registering a name is a no-op, so
    /// registration order is irrelevant and re-calling is safe.
    pub fn register(&mut self, descriptor: ToolDescriptor) {
        if !self.tools.iter().any(|t| t.name == descriptor.name) {
            self.tools.push(descriptor);
        }
    }

    /// Number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_starts_empty() {
        let registry = ToolRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn registry_deduplicates_by_name() {
        let mut registry = ToolRegistry::new();
        let tool = ToolDescriptor::new(
            "describe_table",
            ToolTier::FoundationLiveDb,
            "Describe a table's columns and constraints",
        );
        registry.register(tool.clone());
        registry.register(tool);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn descriptors_generate_titles_and_explicit_read_only_annotations() {
        let tool = ToolDescriptor::new("oracle_query", ToolTier::FoundationLiveDb, "Run a query");
        assert_eq!(tool.title, "Oracle Query");
        assert_eq!(tool.annotations, ToolAnnotations::read_only());
        assert!(!tool.destructive);
    }

    #[test]
    fn generated_titles_preserve_common_database_acronyms() {
        assert_eq!(title_from_name("oracle_preview_sql"), "Oracle Preview SQL");
        assert_eq!(title_from_name("deploy_ddl"), "Deploy DDL");
        assert_eq!(title_from_name("oracle_read_clob"), "Oracle Read CLOB");
        assert_eq!(
            title_from_name("oracle_plscope_inspect"),
            "Oracle PL/Scope Inspect"
        );
    }

    #[test]
    fn destructive_descriptor_flips_advisory_annotations() {
        let tool = ToolDescriptor::new("oracle_execute", ToolTier::FoundationLiveDb, "Execute SQL")
            .destructive();
        assert_eq!(tool.annotations, ToolAnnotations::destructive());
        assert!(tool.destructive);
    }
}
