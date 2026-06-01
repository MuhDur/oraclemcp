//! Operator-defined custom / virtual tools (plan §8.6; bead P1-13 /
//! oracle-qmwz.2.12 and subtasks). Companies expose their OWN proprietary
//! operations as MCP tools **without forking** — a config-driven instantiation
//! of the Phase-1 spine (classifier, bind-first exec, audit, registry), not a
//! new subsystem.
//!
//! Definitions live in operator-controlled `~/.config/oraclemcp/tools.d/*.toml`
//! (NEVER in the repo, like login scripts), are loaded at startup, and register
//! into the same [`ToolRegistry`] so every MCP client discovers them via
//! `tools/list`. A definition is **Form A** (inline SQL / multi-statement /
//! full PL/SQL block) or **Form B** (wrap an existing DB package call). Both
//! bind agent values as bind variables only — never interpolated (injection
//! defense).
//!
//! Submodule coverage: this file is the **loader + schema + registration**
//! (P1-13a / 2.12.1); classify-at-load (2.12.2), Form A/B execution (2.12.3/4),
//! HMAC signing (2.12.5), and meta-dispatch registration (2.12.6) layer on here.

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::tools::{ToolDescriptor, ToolRegistry, ToolTier};

/// A custom-tool parameter type (maps to a JSON-Schema type + a bind kind).
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    /// Text.
    String,
    /// Fractional number.
    Number,
    /// Whole number.
    Integer,
    /// Boolean.
    Boolean,
}

impl ParamType {
    fn json_type(self) -> &'static str {
        match self {
            ParamType::String => "string",
            ParamType::Number => "number",
            ParamType::Integer => "integer",
            ParamType::Boolean => "boolean",
        }
    }
}

/// A typed, named parameter — bound as a bind variable (`:name`), never interpolated.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ParamDef {
    /// Bind name (without the leading `:`).
    pub name: String,
    /// JSON/bind type.
    #[serde(rename = "type")]
    pub ty: ParamType,
    /// Whether the agent must supply it.
    #[serde(default)]
    pub required: bool,
    /// Agent-facing description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Output shaping for a custom tool.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    /// A row set (default).
    #[default]
    Rows,
    /// A single scalar value.
    Scalar,
}

/// A parsed operator tool definition.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CustomToolDef {
    /// The stable tool name (MUST be operator-namespaced; see [`Self::validate`]).
    pub name: String,
    /// Agent-facing one-line description.
    pub description: String,
    /// Form A body: inline SQL / multi-statement / full PL/SQL block.
    #[serde(default)]
    pub sql: Option<String>,
    /// Form B body: an existing package call, e.g. `billing_api.get(:id)`.
    #[serde(default)]
    pub call: Option<String>,
    /// Typed parameters (bind-only).
    #[serde(default)]
    pub params: Vec<ParamDef>,
    /// Output shaping.
    #[serde(default)]
    pub output_mode: OutputMode,
    /// The author's declared operating level — may only make the tool STRICTER
    /// than the classifier-derived level (enforced at classify-at-load, 2.12.2).
    #[serde(default)]
    pub declared_level: Option<String>,
    /// HMAC signature (hex), required on `protected` profiles (2.12.5).
    #[serde(default)]
    pub signature: Option<String>,
}

/// The body form of a custom tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolBody<'a> {
    /// Form A: inline SQL / PL/SQL.
    InlineSql(&'a str),
    /// Form B: an existing package call.
    PackageCall(&'a str),
}

/// Why loading a custom-tool definition failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The TOML did not parse.
    #[error("tools.d parse error: {0}")]
    Parse(String),
    /// A definition is structurally invalid.
    #[error("invalid tool '{name}': {reason}")]
    Invalid {
        /// The offending tool name.
        name: String,
        /// Why.
        reason: String,
    },
}

/// The on-disk file shape: `[[tool]]` array-of-tables.
#[derive(Debug, Deserialize)]
struct ToolFile {
    #[serde(default, rename = "tool")]
    tool: Vec<CustomToolDef>,
}

/// Parse + validate a `tools.d/*.toml` file's worth of definitions.
pub fn parse_tools_file(toml_src: &str) -> Result<Vec<CustomToolDef>, LoadError> {
    let file: ToolFile = toml::from_str(toml_src).map_err(|e| LoadError::Parse(e.to_string()))?;
    for def in &file.tool {
        def.validate()?;
    }
    Ok(file.tool)
}

fn is_bind_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl CustomToolDef {
    /// The tool body, or an error if neither/both of `sql`/`call` were given.
    pub fn body(&self) -> Result<ToolBody<'_>, LoadError> {
        match (&self.sql, &self.call) {
            (Some(s), None) => Ok(ToolBody::InlineSql(s)),
            (None, Some(c)) => Ok(ToolBody::PackageCall(c)),
            _ => Err(LoadError::Invalid {
                name: self.name.clone(),
                reason: "exactly one of `sql` (Form A) or `call` (Form B) is required".to_owned(),
            }),
        }
    }

    /// Structural validation (independent of classification / signing).
    pub fn validate(&self) -> Result<(), LoadError> {
        let invalid = |reason: &str| LoadError::Invalid {
            name: self.name.clone(),
            reason: reason.to_owned(),
        };
        // Operator tools must be namespaced to avoid colliding with built-ins
        // (which are `oracle_*`); require a `custom_`/operator prefix is too
        // strict, so we only forbid the reserved `oracle_` built-in prefix.
        if self.name.is_empty() || !is_bind_ident(&self.name) {
            return Err(invalid(
                "name must be a non-empty identifier ([A-Za-z][A-Za-z0-9_]*)",
            ));
        }
        if self.name.starts_with("oracle_") {
            return Err(invalid(
                "name must not use the reserved `oracle_` built-in prefix",
            ));
        }
        if self.description.trim().is_empty() {
            return Err(invalid("description is required"));
        }
        self.body()?; // exactly one body form
        // Parameter names: unique, valid bind identifiers.
        let mut seen = std::collections::HashSet::new();
        for p in &self.params {
            if !is_bind_ident(&p.name) {
                return Err(invalid(&format!(
                    "parameter '{}' is not a valid bind identifier",
                    p.name
                )));
            }
            if !seen.insert(p.name.as_str()) {
                return Err(invalid(&format!("duplicate parameter '{}'", p.name)));
            }
        }
        Ok(())
    }

    /// Generate the MCP `inputSchema` (JSON Schema object) from the params.
    #[must_use]
    pub fn input_schema(&self) -> Value {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for p in &self.params {
            let mut prop = Map::new();
            prop.insert("type".to_owned(), json!(p.ty.json_type()));
            if let Some(d) = &p.description {
                prop.insert("description".to_owned(), json!(d));
            }
            properties.insert(p.name.clone(), Value::Object(prop));
            if p.required {
                required.push(json!(p.name));
            }
        }
        json!({
            "type": "object",
            "properties": Value::Object(properties),
            "required": required,
            "additionalProperties": false,
        })
    }

    /// The registry descriptor for this tool (live-DB tier).
    #[must_use]
    pub fn to_descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name.clone(),
            tier: ToolTier::FoundationLiveDb,
            summary: self.description.clone(),
        }
    }
}

/// Register a set of validated custom tools into the registry (first-class mode).
pub fn register_custom_tools(registry: &mut ToolRegistry, defs: &[CustomToolDef]) {
    for d in defs {
        registry.register(d.to_descriptor());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORM_A: &str = r#"
        [[tool]]
        name = "customer_360"
        description = "Read a customer 360 view"
        sql = "SELECT * FROM customer_360_v WHERE id = :id"
        output_mode = "rows"
        [[tool.params]]
        name = "id"
        type = "integer"
        required = true
        description = "Customer id"
    "#;

    const FORM_B: &str = r#"
        [[tool]]
        name = "billing_summary"
        description = "Wrap the billing package"
        call = "billing_api.get_summary(:acct)"
        [[tool.params]]
        name = "acct"
        type = "string"
        required = true
    "#;

    #[test]
    fn parses_form_a_and_form_b() {
        let a = parse_tools_file(FORM_A).expect("form A parses");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].name, "customer_360");
        assert_eq!(
            a[0].body().unwrap(),
            ToolBody::InlineSql("SELECT * FROM customer_360_v WHERE id = :id")
        );
        let b = parse_tools_file(FORM_B).expect("form B parses");
        assert_eq!(
            b[0].body().unwrap(),
            ToolBody::PackageCall("billing_api.get_summary(:acct)")
        );
    }

    #[test]
    fn input_schema_reflects_params() {
        let defs = parse_tools_file(FORM_A).unwrap();
        let schema = defs[0].input_schema();
        assert_eq!(schema["type"], json!("object"));
        assert_eq!(schema["properties"]["id"]["type"], json!("integer"));
        assert_eq!(schema["required"], json!(["id"]));
        assert_eq!(schema["additionalProperties"], json!(false));
    }

    #[test]
    fn registration_makes_tools_discoverable() {
        let defs = parse_tools_file(FORM_A).unwrap();
        let mut reg = ToolRegistry::new();
        register_custom_tools(&mut reg, &defs);
        assert!(reg.tools.iter().any(|t| t.name == "customer_360"));
        // Idempotent.
        register_custom_tools(&mut reg, &defs);
        assert_eq!(
            reg.tools
                .iter()
                .filter(|t| t.name == "customer_360")
                .count(),
            1
        );
    }

    #[test]
    fn both_bodies_is_invalid() {
        let src = r#"
            [[tool]]
            name = "bad"
            description = "two bodies"
            sql = "SELECT 1 FROM dual"
            call = "pkg.proc(:x)"
        "#;
        assert!(matches!(
            parse_tools_file(src),
            Err(LoadError::Invalid { .. })
        ));
    }

    #[test]
    fn neither_body_is_invalid() {
        let src = r#"
            [[tool]]
            name = "bad"
            description = "no body"
        "#;
        assert!(matches!(
            parse_tools_file(src),
            Err(LoadError::Invalid { .. })
        ));
    }

    #[test]
    fn reserved_prefix_and_bad_names_rejected() {
        let reserved = r#"
            [[tool]]
            name = "oracle_query"
            description = "shadow a built-in"
            sql = "SELECT 1 FROM dual"
        "#;
        assert!(matches!(
            parse_tools_file(reserved),
            Err(LoadError::Invalid { .. })
        ));
        let bad = r#"
            [[tool]]
            name = "9bad-name"
            description = "bad ident"
            sql = "SELECT 1 FROM dual"
        "#;
        assert!(matches!(
            parse_tools_file(bad),
            Err(LoadError::Invalid { .. })
        ));
    }

    #[test]
    fn duplicate_and_bad_params_rejected() {
        let dup = r#"
            [[tool]]
            name = "t"
            description = "dup params"
            sql = "SELECT :a FROM dual"
            [[tool.params]]
            name = "a"
            type = "string"
            [[tool.params]]
            name = "a"
            type = "integer"
        "#;
        assert!(matches!(
            parse_tools_file(dup),
            Err(LoadError::Invalid { .. })
        ));
    }

    #[test]
    fn malformed_toml_is_a_parse_error() {
        assert!(matches!(
            parse_tools_file("this is not = = toml"),
            Err(LoadError::Parse(_))
        ));
    }
}
