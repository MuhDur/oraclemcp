//! The generic tool-registry contract for the `oraclemcp` MCP core.
//!
//! Every tool the server advertises over MCP is a [`ToolDescriptor`] held in a
//! [`ToolRegistry`]. The engine-side (or operator-defined) code contributes
//! its slice of tools by registering descriptors — the core never reaches into
//! a tool's implementation. Relocated from `plsql-mcp`'s `tools.rs` (bead
//! P0-0); P0-6 builds the `rmcp` `ServerHandler` over this registry.

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
    /// Live-DB tool — gated by the `live-db` build feature and an operating
    /// level / safety profile that allows the operation.
    FoundationLiveDb,
}

/// Stable, machine-readable descriptor for a registered tool.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ToolDescriptor {
    /// The tool's stable name (e.g. `oracle_query`).
    pub name: String,
    /// The tool's tier.
    pub tier: ToolTier,
    /// A one-line agent-facing summary.
    pub summary: String,
}

/// Minimal registry that per-tool modules populate; dedups by name.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
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
        let tool = ToolDescriptor {
            name: String::from("describe_table"),
            tier: ToolTier::FoundationLiveDb,
            summary: String::from("Describe a table's columns and constraints"),
        };
        registry.register(tool.clone());
        registry.register(tool);
        assert_eq!(registry.len(), 1);
    }
}
