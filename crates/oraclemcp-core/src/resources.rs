//! MCP Resources + Prompts (plan §8.5; bead P2-RES / oracle-qmwz.3.10).
//!
//! Tools alone are a gap (the "tools-only" completeness finding). **Resources**
//! make the server browsable under a coherent `oracle://` scheme; **Prompts**
//! ship discoverable expert playbooks any harness can list. Both are a bonus
//! where the client supports them — tools never depend on them.
//!
//! This module owns the engine-free parts: the `oracle://` URI model + routing,
//! the `resources/list` template surface, and the parameterized prompt catalog
//! (pure recipe templates). Live resource *content* (object DDL, session state,
//! schema listings) is produced by an injected [`ResourceProvider`] so the
//! one-way boundary holds; `oracle://capabilities` and `oracle://tools` render
//! from in-core documents.

use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use serde_json::Value;

/// A parsed `oracle://` resource URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceUri {
    /// `oracle://schema/{owner}` — object listing for a schema.
    Schema {
        /// The schema owner.
        owner: String,
    },
    /// `oracle://object/{owner}/{type}/{name}` — DDL / source of an object.
    Object {
        /// The schema owner.
        owner: String,
        /// The object type (e.g. `TABLE`, `PACKAGE`).
        object_type: String,
        /// The object name.
        name: String,
    },
    /// `oracle://session/{lease_id}` — live session state for a lease.
    Session {
        /// The lease id.
        lease_id: String,
    },
    /// `oracle://capabilities` — the capability report.
    Capabilities,
    /// `oracle://tools` — the operator virtual-tool catalog (P1-13).
    Tools,
}

impl ResourceUri {
    /// Parse an `oracle://…` URI.
    pub fn parse(uri: &str) -> Result<Self, ErrorEnvelope> {
        let rest = uri.strip_prefix("oracle://").ok_or_else(|| {
            ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                "resource URI must start with oracle://",
            )
        })?;
        let parts: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
        let bad = || {
            ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                format!("unrecognized resource URI: {uri}"),
            )
        };
        match parts.as_slice() {
            ["capabilities"] => Ok(ResourceUri::Capabilities),
            ["tools"] => Ok(ResourceUri::Tools),
            ["schema", owner] => Ok(ResourceUri::Schema {
                owner: (*owner).to_owned(),
            }),
            ["object", owner, ty, name] => Ok(ResourceUri::Object {
                owner: (*owner).to_owned(),
                object_type: (*ty).to_owned(),
                name: (*name).to_owned(),
            }),
            ["session", lease] => Ok(ResourceUri::Session {
                lease_id: (*lease).to_owned(),
            }),
            _ => Err(bad()),
        }
    }

    /// Render back to the canonical URI string.
    #[must_use]
    pub fn to_uri(&self) -> String {
        match self {
            ResourceUri::Schema { owner } => format!("oracle://schema/{owner}"),
            ResourceUri::Object {
                owner,
                object_type,
                name,
            } => {
                format!("oracle://object/{owner}/{object_type}/{name}")
            }
            ResourceUri::Session { lease_id } => format!("oracle://session/{lease_id}"),
            ResourceUri::Capabilities => "oracle://capabilities".to_owned(),
            ResourceUri::Tools => "oracle://tools".to_owned(),
        }
    }
}

/// A `resources/list` template entry (the browsable surface).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTemplate {
    /// The URI template (`oracle://object/{owner}/{type}/{name}`).
    pub uri_template: String,
    /// Human name.
    pub name: String,
    /// What it returns.
    pub description: String,
    /// MIME type of the content.
    pub mime_type: String,
}

/// The static resource-template surface advertised by `resources/list`.
#[must_use]
pub fn resource_templates() -> Vec<ResourceTemplate> {
    let t = |uri: &str, name: &str, desc: &str, mime: &str| ResourceTemplate {
        uri_template: uri.to_owned(),
        name: name.to_owned(),
        description: desc.to_owned(),
        mime_type: mime.to_owned(),
    };
    vec![
        t(
            "oracle://capabilities",
            "capabilities",
            "Server capability report",
            "application/json",
        ),
        t(
            "oracle://tools",
            "tools",
            "Operator virtual-tool catalog",
            "application/json",
        ),
        t(
            "oracle://schema/{owner}",
            "schema",
            "Object listing for a schema",
            "application/json",
        ),
        t(
            "oracle://object/{owner}/{type}/{name}",
            "object",
            "DDL / source of a database object",
            "text/plain",
        ),
        t(
            "oracle://session/{lease_id}",
            "session",
            "Live session state for a lease",
            "application/json",
        ),
    ]
}

/// The content of a read resource.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContents {
    /// The resolved URI.
    pub uri: String,
    /// MIME type.
    pub mime_type: String,
    /// The text payload (JSON or source).
    pub text: String,
}

/// Produces content for the live resources (schema/object/session). Injected so
/// this module stays engine-free; `capabilities`/`tools` render in-core.
pub trait ResourceProvider: Send + Sync {
    /// Read a live resource.
    fn read(&self, uri: &ResourceUri) -> Result<ResourceContents, ErrorEnvelope>;
}

/// Read a resource: `capabilities`/`tools` render from the supplied in-core
/// documents; the rest route to the provider.
pub fn read_resource(
    uri: &ResourceUri,
    provider: &dyn ResourceProvider,
    capabilities: &Value,
    tools_catalog: &Value,
) -> Result<ResourceContents, ErrorEnvelope> {
    match uri {
        ResourceUri::Capabilities => Ok(ResourceContents {
            uri: uri.to_uri(),
            mime_type: "application/json".to_owned(),
            text: capabilities.to_string(),
        }),
        ResourceUri::Tools => Ok(ResourceContents {
            uri: uri.to_uri(),
            mime_type: "application/json".to_owned(),
            text: tools_catalog.to_string(),
        }),
        _ => provider.read(uri),
    }
}

// ── Prompts: discoverable expert playbooks ────────────────────────────────────

/// A prompt argument.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PromptArg {
    /// Argument name.
    pub name: String,
    /// What it is.
    pub description: String,
    /// Whether it is required.
    pub required: bool,
}

/// A parameterized prompt (recipe) definition.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PromptDef {
    /// Prompt name.
    pub name: String,
    /// What the recipe does.
    pub description: String,
    /// The arguments it takes.
    pub arguments: Vec<PromptArg>,
}

/// A rendered prompt message.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PromptMessage {
    /// `user` / `assistant`.
    pub role: String,
    /// The text content.
    pub text: String,
}

fn arg(name: &str, description: &str, required: bool) -> PromptArg {
    PromptArg {
        name: name.to_owned(),
        description: description.to_owned(),
        required,
    }
}

/// The expert-playbook catalog advertised by `prompts/list`.
#[must_use]
pub fn prompt_catalog() -> Vec<PromptDef> {
    vec![
        PromptDef {
            name: "investigate_slow_query".to_owned(),
            description: "Diagnose a slow SQL statement using the plan + stats tools".to_owned(),
            arguments: vec![arg("sql", "The SQL to investigate", true)],
        },
        PromptDef {
            name: "safe_column_rename".to_owned(),
            description: "Rename a column safely (dependency-aware, staged)".to_owned(),
            arguments: vec![
                arg("owner", "Schema owner", true),
                arg("table", "Table name", true),
                arg("column", "Current column name", true),
                arg("new_name", "New column name", true),
            ],
        },
        PromptDef {
            name: "explain_this_package".to_owned(),
            description: "Summarize a PL/SQL package: signatures, calls, complexity".to_owned(),
            arguments: vec![
                arg("owner", "Schema owner", true),
                arg("package", "Package name", true),
            ],
        },
        PromptDef {
            name: "find_callers_of".to_owned(),
            description: "Find everything that calls/references an object".to_owned(),
            arguments: vec![
                arg("owner", "Schema owner", true),
                arg("object", "Object name", true),
            ],
        },
        PromptDef {
            name: "generate_migration".to_owned(),
            description: "Draft a reversible migration for a schema change".to_owned(),
            arguments: vec![arg("description", "What to change", true)],
        },
    ]
}

/// Render a prompt by name with arguments into a usable recipe (messages).
pub fn render_prompt(name: &str, args: &Value) -> Result<Vec<PromptMessage>, ErrorEnvelope> {
    let def = prompt_catalog()
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| {
            ErrorEnvelope::new(
                ErrorClass::ObjectNotFound,
                format!("no prompt named '{name}'"),
            )
        })?;
    // Required-argument check.
    for a in def.arguments.iter().filter(|a| a.required) {
        if args
            .get(&a.name)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                format!("prompt '{name}' requires argument '{}'", a.name),
            ));
        }
    }
    let s = |k: &str| args.get(k).and_then(Value::as_str).unwrap_or("");
    let body = match name {
        "investigate_slow_query" => format!(
            "Investigate this slow query. Steps:\n\
             1. Call oracle_preview_sql for the statement. Use EXPLAIN PLAN via oracle_explain_plan only when a READ_WRITE diagnostic PLAN_TABLE write is acceptable.\n\
             2. Look for FULL TABLE SCAN / NESTED LOOPS over large row sources.\n\
             3. Check predicate selectivity and missing indexes via oracle_schema_inspect.\n\
             4. Propose an index or rewrite; never run DDL without confirmation.\n\n\
             SQL:\n{}",
            s("sql")
        ),
        "safe_column_rename" => format!(
            "Plan a safe rename of {0}.{1}.{2} -> {3}:\n\
             1. find_callers_of {0}.{1} to size the blast radius.\n\
             2. Stage: add {3}, backfill, dual-write, switch reads, drop {2}.\n\
             3. Each DDL step is DDL-level (step-up confirmed); provide rollback.",
            s("owner"),
            s("table"),
            s("column"),
            s("new_name")
        ),
        "explain_this_package" => format!(
            "Explain package {}.{}: call oracle_plsql_analyze for signatures, the \
             call/ref graph, lint findings, and cyclomatic complexity; summarize the \
             public API and any side-effecting routines.",
            s("owner"),
            s("package")
        ),
        "find_callers_of" => format!(
            "Find all callers/references of {}.{} using the dependency graph \
             (oracle_schema_inspect + dep graph). List direct and transitive callers.",
            s("owner"),
            s("object")
        ),
        "generate_migration" => format!(
            "Draft a reversible migration for: {}\n\
             Produce forward + reverse DDL, a rehearsal plan, and a data-integrity check. \
             Mark it DDL-level (step-up required).",
            s("description")
        ),
        // Unreachable today (the name was validated against the catalog above),
        // but degrade gracefully rather than panic if the catalog and this match
        // ever drift (e.g. a 6th playbook added to the catalog but not here).
        _ => {
            return Err(ErrorEnvelope::new(
                ErrorClass::Internal,
                format!("prompt '{name}' is in the catalog but has no template"),
            ));
        }
    };
    Ok(vec![PromptMessage {
        role: "user".to_owned(),
        text: body,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn uri_roundtrips_all_schemes() {
        for uri in [
            "oracle://capabilities",
            "oracle://tools",
            "oracle://schema/HR",
            "oracle://object/HR/PACKAGE/EMP_API",
            "oracle://session/lease-1-7",
        ] {
            let parsed = ResourceUri::parse(uri).expect(uri);
            assert_eq!(parsed.to_uri(), uri);
        }
    }

    #[test]
    fn bad_uris_are_rejected() {
        assert!(ResourceUri::parse("https://evil/x").is_err());
        assert!(ResourceUri::parse("oracle://object/only/two").is_err());
        assert!(ResourceUri::parse("oracle://nonsense").is_err());
    }

    #[test]
    fn templates_cover_all_five_schemes() {
        let t = resource_templates();
        assert_eq!(t.len(), 5);
        assert!(
            t.iter()
                .any(|r| r.uri_template == "oracle://object/{owner}/{type}/{name}")
        );
    }

    struct DdlProvider;
    impl ResourceProvider for DdlProvider {
        fn read(&self, uri: &ResourceUri) -> Result<ResourceContents, ErrorEnvelope> {
            match uri {
                ResourceUri::Object { name, .. } => Ok(ResourceContents {
                    uri: uri.to_uri(),
                    mime_type: "text/plain".to_owned(),
                    text: format!("CREATE OR REPLACE PACKAGE {name} AS END;"),
                }),
                _ => Err(ErrorEnvelope::new(
                    ErrorClass::ObjectNotFound,
                    "unsupported in mock",
                )),
            }
        }
    }

    #[test]
    fn read_resource_routes_static_and_live() {
        let caps = json!({"server_name": "oraclemcp"});
        let tools = json!({"tools": []});
        // Static: capabilities renders in-core.
        let c = read_resource(&ResourceUri::Capabilities, &DdlProvider, &caps, &tools).unwrap();
        assert_eq!(c.mime_type, "application/json");
        assert!(c.text.contains("oraclemcp"));
        // Live: object DDL via the provider.
        let obj = ResourceUri::parse("oracle://object/HR/PACKAGE/EMP_API").unwrap();
        let c = read_resource(&obj, &DdlProvider, &caps, &tools).unwrap();
        assert!(c.text.contains("CREATE OR REPLACE PACKAGE EMP_API"));
    }

    #[test]
    fn prompt_catalog_lists_five_playbooks() {
        let p = prompt_catalog();
        assert_eq!(p.len(), 5);
        assert!(p.iter().any(|d| d.name == "investigate_slow_query"));
    }

    #[test]
    fn render_prompt_produces_a_recipe() {
        let msgs = render_prompt(
            "investigate_slow_query",
            &json!({"sql": "SELECT * FROM big_table"}),
        )
        .expect("renders");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, "user");
        assert!(msgs[0].text.contains("EXPLAIN PLAN"));
        assert!(msgs[0].text.contains("SELECT * FROM big_table"));
    }

    #[test]
    fn render_prompt_validates_args_and_name() {
        // Missing required arg.
        assert_eq!(
            render_prompt("explain_this_package", &json!({"owner": "HR"}))
                .unwrap_err()
                .error_class,
            ErrorClass::InvalidArguments
        );
        // Unknown prompt.
        assert_eq!(
            render_prompt("nope", &json!({})).unwrap_err().error_class,
            ErrorClass::ObjectNotFound
        );
    }
}
