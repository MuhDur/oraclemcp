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
    /// Whether the tool performs a destructive / irreversible write (DDL,
    /// deploy, drop). Surfaced over the wire so an agent (and a gating layer)
    /// can isolate the destructive cluster from read-only tools
    /// (oracle-da9j.9). Defaults to `false`.
    #[serde(default)]
    pub destructive: bool,
}

impl ToolDescriptor {
    /// A read-only, non-destructive descriptor with no advertised arg schema
    /// (the permissive default). Chain [`Self::with_input_schema`] /
    /// [`Self::destructive`] to enrich it.
    #[must_use]
    pub fn new(name: impl Into<String>, tier: ToolTier, summary: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tier,
            summary: summary.into(),
            input_schema: None,
            destructive: false,
        }
    }

    /// Attach the tool's argument JSON-Schema (advertised in `tools/list`).
    #[must_use]
    pub fn with_input_schema(mut self, schema: serde_json::Value) -> Self {
        self.input_schema = Some(schema);
        self
    }

    /// Mark the tool as performing a destructive / irreversible write.
    #[must_use]
    pub fn destructive(mut self) -> Self {
        self.destructive = true;
        self
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
}
