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

use oraclemcp_db::OracleBind;
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{Classifier, OperatingLevel};
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
    /// The body classified `Forbidden` — refuses to load (2.12.2).
    #[error("tool '{name}' refuses to load: forbidden body ({reason})")]
    Forbidden {
        /// The offending tool name.
        name: String,
        /// The classifier's reason.
        reason: String,
    },
    /// The body's required level exceeds the profile ceiling — refuses to load.
    #[error("tool '{name}' requires {required} but the profile ceiling is {max}; refuses to load")]
    OverCeiling {
        /// The offending tool name.
        name: String,
        /// The level the body requires.
        required: OperatingLevel,
        /// The profile ceiling.
        max: OperatingLevel,
    },
    /// A `protected` profile requires every definition to be HMAC-signed (2.12.5).
    #[error("tool '{name}' is unsigned; protected profiles require an HMAC signature")]
    SignatureRequired {
        /// The offending tool name.
        name: String,
    },
    /// The HMAC signature did not verify (tampered definition).
    #[error("tool '{name}' has an invalid HMAC signature (tampered?)")]
    SignatureInvalid {
        /// The offending tool name.
        name: String,
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
        // An operator-pinned `declared_level` must be a recognized operating
        // level. Otherwise `classify_at_load` would silently drop the typo'd
        // floor (`.and_then(OperatingLevel::parse)` → `None => derived`) and the
        // tool would load at the looser classifier-derived level — discarding
        // the operator's intended safety pin without any error. Reject the typo
        // at load time (fail-fast: a misconfigured tool must never silently
        // appear).
        match self.declared_level.as_deref() {
            Some(lvl) if OperatingLevel::parse(lvl).is_none() => {
                return Err(invalid(&format!(
                    "declared_level '{lvl}' is not a known operating level \
                     (READ_ONLY | READ_WRITE | DDL | ADMIN)"
                )));
            }
            _ => {}
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
        ToolDescriptor::new(
            self.name.clone(),
            ToolTier::FoundationLiveDb,
            self.description.clone(),
        )
    }
}

/// Register a set of validated custom tools into the registry (first-class mode).
pub fn register_custom_tools(registry: &mut ToolRegistry, defs: &[CustomToolDef]) {
    for d in defs {
        registry.register(d.to_descriptor());
    }
}

// ── Classify-at-load (P1-13b / 2.12.2): the safety gate ───────────────────────

/// A custom tool that passed classify-at-load, with its derived required level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedTool {
    /// The definition.
    pub def: CustomToolDef,
    /// The operating level the body actually requires (≥ the author's declared
    /// level — the author may only make it stricter).
    pub required_level: OperatingLevel,
}

impl CustomToolDef {
    /// The string the classifier sees: Form A is the SQL/PLSQL as-is; Form B is
    /// the package call wrapped in an anonymous block.
    fn classify_input(&self) -> Result<String, LoadError> {
        Ok(match self.body()? {
            ToolBody::InlineSql(s) => s.to_owned(),
            // Form B wraps the call in a SELECT so the classifier consults the
            // SideEffectOracle on the routine (P1-13d): the engine can PROVE the
            // package read-only → Safe/auto-approved, or flag writes → ≥ Guarded.
            // With the default Unknown oracle (no engine) it is fail-closed to
            // Guarded — never silently Safe.
            ToolBody::PackageCall(c) => format!("SELECT {c} FROM dual"),
        })
    }
}

/// Classify a definition at load and enforce the zero-new-privilege rules
/// (2.12.2): a `Forbidden` body refuses to load; the required level is derived
/// from behavior (the author's `declared_level` can only make it STRICTER); a
/// tool whose required level exceeds `max_level` refuses to load (fail-fast).
pub fn classify_at_load(
    def: &CustomToolDef,
    classifier: &Classifier,
    max_level: OperatingLevel,
) -> Result<LoadedTool, LoadError> {
    def.validate()?;
    let decision = classifier.classify(&def.classify_input()?);
    // `required_level == None` ⇒ Forbidden (fail-closed): refuse to load.
    let derived = decision
        .required_level
        .ok_or_else(|| LoadError::Forbidden {
            name: def.name.clone(),
            reason: decision.reason.clone(),
        })?;
    // The author may only raise the floor, never lower the derived level.
    let effective = match def
        .declared_level
        .as_deref()
        .and_then(OperatingLevel::parse)
    {
        Some(declared) => derived.max(declared),
        None => derived,
    };
    if effective > max_level {
        return Err(LoadError::OverCeiling {
            name: def.name.clone(),
            required: effective,
            max: max_level,
        });
    }
    Ok(LoadedTool {
        def: def.clone(),
        required_level: effective,
    })
}

/// Classify + gate a whole `tools.d` set. Fail-fast: the first refusal aborts
/// the load (a misconfigured tool must never silently appear).
pub fn load_tools(
    defs: &[CustomToolDef],
    classifier: &Classifier,
    max_level: OperatingLevel,
) -> Result<Vec<LoadedTool>, LoadError> {
    defs.iter()
        .map(|d| classify_at_load(d, classifier, max_level))
        .collect()
}

// ── HMAC signing on protected profiles (P1-13e / 2.12.5) ──────────────────────

/// The canonical byte sequence a tool's HMAC signs: the security-relevant
/// fields, in a fixed order, length-prefixed so no field can absorb another's
/// content. The `signature` field itself is excluded.
fn canonical_bytes(def: &CustomToolDef) -> Vec<u8> {
    let mut out = Vec::new();
    let field = |label: &str, value: &str, out: &mut Vec<u8>| {
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(&(value.len() as u64).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    };
    field("name", &def.name, &mut out);
    field("description", &def.description, &mut out);
    field("sql", def.sql.as_deref().unwrap_or(""), &mut out);
    field("call", def.call.as_deref().unwrap_or(""), &mut out);
    field(
        "declared_level",
        def.declared_level.as_deref().unwrap_or(""),
        &mut out,
    );
    out.extend_from_slice(&(def.params.len() as u64).to_le_bytes());
    for p in &def.params {
        field("param.name", &p.name, &mut out);
        field("param.type", p.ty.json_type(), &mut out);
        out.push(u8::from(p.required));
    }
    out
}

/// HMAC-SHA256 (RFC 2104) over `sha2`.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute the hex HMAC signature for a definition (operator-side signing).
#[must_use]
pub fn sign(def: &CustomToolDef, hmac_key: &[u8]) -> String {
    hex(&hmac_sha256(hmac_key, &canonical_bytes(def)))
}

/// Whether `def.signature` is present and a valid HMAC over its canonical bytes.
#[must_use]
pub fn verify_signature(def: &CustomToolDef, hmac_key: &[u8]) -> bool {
    let Some(sig) = &def.signature else {
        return false;
    };
    // Constant-time-ish compare on the hex strings (equal length expected).
    let expected = sign(def, hmac_key);
    sig.len() == expected.len()
        && sig
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Enforce signing policy: on a `protected` profile every definition MUST carry
/// a valid HMAC signature (a tampered/unsigned `tools.toml` is rejected). On an
/// unprotected profile signing is optional (verified if present).
pub fn enforce_signature(
    def: &CustomToolDef,
    hmac_key: &[u8],
    protected: bool,
) -> Result<(), LoadError> {
    if protected {
        if def.signature.is_none() {
            return Err(LoadError::SignatureRequired {
                name: def.name.clone(),
            });
        }
        if !verify_signature(def, hmac_key) {
            return Err(LoadError::SignatureInvalid {
                name: def.name.clone(),
            });
        }
    } else if def.signature.is_some() && !verify_signature(def, hmac_key) {
        return Err(LoadError::SignatureInvalid {
            name: def.name.clone(),
        });
    }
    Ok(())
}

/// Classify-at-load + signing enforcement for a profile. Use this in production:
/// `protected` profiles require a valid HMAC on every definition.
pub fn load_tools_for_profile(
    defs: &[CustomToolDef],
    classifier: &Classifier,
    max_level: OperatingLevel,
    hmac_key: &[u8],
    protected: bool,
) -> Result<Vec<LoadedTool>, LoadError> {
    defs.iter()
        .map(|d| {
            enforce_signature(d, hmac_key, protected)?;
            classify_at_load(d, classifier, max_level)
        })
        .collect()
}

// ── Form A / Form B execution: bind-only param binding (P1-13c / 2.12.3) ──────

/// Bind the agent's JSON arguments to typed Oracle bind variables — the
/// injection defense. Values are **bound, never interpolated** into the SQL.
/// Returns `(name, bind)` pairs (the body references `:name`). Enforces required
/// params, type-checks each value, and rejects unknown args (`additionalProperties:false`).
pub fn bind_params(
    def: &CustomToolDef,
    args: &Value,
) -> Result<Vec<(String, OracleBind)>, ErrorEnvelope> {
    let empty = Map::new();
    let obj = match args {
        Value::Object(m) => m,
        Value::Null => &empty,
        _ => {
            return Err(ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                "arguments must be a JSON object",
            ));
        }
    };
    let invalid = |msg: String| ErrorEnvelope::new(ErrorClass::InvalidArguments, msg);

    // Reject unknown args (no silent drop — additionalProperties:false).
    for key in obj.keys() {
        if !def.params.iter().any(|p| &p.name == key) {
            return Err(invalid(format!("unknown argument '{key}'")));
        }
    }

    let mut binds = Vec::with_capacity(def.params.len());
    for p in &def.params {
        let bind = match obj.get(&p.name) {
            None | Some(Value::Null) => {
                if p.required {
                    return Err(invalid(format!("missing required argument '{}'", p.name)));
                }
                OracleBind::Null
            }
            Some(v) => coerce_bind(p, v).ok_or_else(|| {
                invalid(format!("argument '{}' is not a valid {:?}", p.name, p.ty))
            })?,
        };
        binds.push((p.name.clone(), bind));
    }
    Ok(binds)
}

fn coerce_bind(p: &ParamDef, v: &Value) -> Option<OracleBind> {
    match p.ty {
        ParamType::String => v.as_str().map(|s| OracleBind::String(s.to_owned())),
        ParamType::Integer => v.as_i64().map(OracleBind::I64),
        // A number accepts integers too.
        ParamType::Number => v.as_f64().map(OracleBind::F64),
        ParamType::Boolean => v.as_bool().map(OracleBind::Bool),
    }
}

/// Runs a custom tool's body with bound params at the granted level (engine/DB
/// side). Injected so this module stays engine-free and unit-testable; the
/// implementation reuses the Phase-1 read/exec path + type/NLS serializer.
pub trait CustomToolExecutor: Send + Sync {
    /// Execute `body` at `level` with the bound params; return structured JSON.
    fn run(
        &self,
        body: ToolBody<'_>,
        level: OperatingLevel,
        binds: &[(String, OracleBind)],
    ) -> Result<Value, ErrorEnvelope>;
}

/// Execute a loaded custom tool: bind the agent args (bind-only) and run the
/// body at its classify-derived level. PL/SQL blocks are ≥ Guarded, so the
/// caller's level gate / step-up applies before the executor runs them.
pub fn execute_custom_tool(
    loaded: &LoadedTool,
    args: &Value,
    executor: &dyn CustomToolExecutor,
) -> Result<Value, ErrorEnvelope> {
    let binds = bind_params(&loaded.def, args)?;
    let body = loaded.def.body().map_err(|e| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("invalid tool body: {e}"),
        )
    })?;
    executor.run(body, loaded.required_level, &binds)
}

// ── Catalog: first-class vs meta-dispatch registration (P1-13f / 2.12.6) ──────

/// The single meta-dispatch tool name (large-catalog mode).
pub const RUN_NAMED_TOOL: &str = "oracle_run_named";

/// A loaded, gated catalog of operator tools. Operators choose per profile
/// between **first-class** registration (small catalog → each tool is its own
/// MCP tool with a proper `inputSchema`) and **meta-dispatch** (large catalog →
/// a single [`RUN_NAMED_TOOL`] keeps the top-level surface tiny; the full
/// catalog is discoverable via `oracle_capabilities` and the `oracle://tools`
/// resource). This keeps the ≤12 core-tool ergonomic budget intact — operator
/// tools are additive.
#[derive(Clone, Debug, Default)]
pub struct CustomToolCatalog {
    tools: Vec<LoadedTool>,
}

impl CustomToolCatalog {
    /// Build a catalog from the loaded (classified + gated) tools.
    #[must_use]
    pub fn new(tools: Vec<LoadedTool>) -> Self {
        CustomToolCatalog { tools }
    }

    /// Number of tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether the catalog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Look up a tool by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&LoadedTool> {
        self.tools.iter().find(|t| t.def.name == name)
    }

    /// Register each tool as a first-class MCP tool (small-catalog mode).
    pub fn register_first_class(&self, registry: &mut ToolRegistry) {
        for t in &self.tools {
            registry.register(t.def.to_descriptor());
        }
    }

    /// Register a single [`RUN_NAMED_TOOL`] meta-dispatch tool (large-catalog
    /// mode) — the catalog stays discoverable via [`Self::catalog_json`].
    pub fn register_meta_dispatch(&self, registry: &mut ToolRegistry) {
        registry.register(ToolDescriptor::new(
            RUN_NAMED_TOOL.to_owned(),
            ToolTier::FoundationLiveDb,
            format!(
                "Run one of {} operator-defined tools by name: {{ name, params }}. \
                 Discover the catalog via oracle_capabilities or the oracle://tools resource.",
                self.tools.len()
            ),
        ));
    }

    /// Meta-dispatch: run the named tool with `params`. `args` is the
    /// `oracle_run_named` payload `{ "name": "...", "params": { … } }`.
    pub fn run_named(
        &self,
        args: &Value,
        executor: &dyn CustomToolExecutor,
    ) -> Result<Value, ErrorEnvelope> {
        let name = args["name"].as_str().ok_or_else(|| {
            ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                "oracle_run_named requires a 'name'",
            )
        })?;
        let loaded = self.get(name).ok_or_else(|| {
            ErrorEnvelope::new(
                ErrorClass::ObjectNotFound,
                format!("no custom tool named '{name}'"),
            )
        })?;
        let params = args.get("params").cloned().unwrap_or(Value::Null);
        execute_custom_tool(loaded, &params, executor)
    }

    /// The catalog document for `oracle_capabilities` and the `oracle://tools`
    /// resource (P2-RES / 3.10): name, description, required level, inputSchema.
    #[must_use]
    pub fn catalog_json(&self) -> Value {
        let entries: Vec<Value> = self
            .tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.def.name,
                    "description": t.def.description,
                    "required_level": t.required_level.as_str(),
                    "input_schema": t.def.input_schema(),
                })
            })
            .collect();
        json!({ "tools": entries })
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

    // ── classify-at-load (2.12.2) ─────────────────────────────────────────────

    fn def_sql(name: &str, sql: &str, declared: Option<&str>) -> CustomToolDef {
        CustomToolDef {
            name: name.to_owned(),
            description: "t".to_owned(),
            sql: Some(sql.to_owned()),
            call: None,
            params: vec![],
            output_mode: OutputMode::Rows,
            declared_level: declared.map(str::to_owned),
            signature: None,
        }
    }

    #[test]
    fn read_only_tool_loads_at_read_only() {
        let c = Classifier::new(oraclemcp_guard::ClassifierConfig::new());
        let d = def_sql("cust", "SELECT * FROM t WHERE id = :id", None);
        let loaded = classify_at_load(&d, &c, OperatingLevel::ReadOnly).expect("loads");
        assert_eq!(loaded.required_level, OperatingLevel::ReadOnly);
    }

    #[test]
    fn write_block_refuses_on_a_read_only_profile() {
        let c = Classifier::new(oraclemcp_guard::ClassifierConfig::new());
        // A PL/SQL block is >= Guarded (ReadWrite); on a READ_ONLY ceiling it
        // refuses to load (fail-fast).
        let d = def_sql(
            "bump",
            "BEGIN UPDATE t SET x = 1 WHERE id = :id; END;",
            None,
        );
        let err = classify_at_load(&d, &c, OperatingLevel::ReadOnly).unwrap_err();
        assert!(
            matches!(err, LoadError::OverCeiling { required, .. } if required >= OperatingLevel::ReadWrite)
        );
        // But it loads on a READ_WRITE profile.
        let loaded = classify_at_load(&d, &c, OperatingLevel::ReadWrite).expect("loads at RW");
        assert!(loaded.required_level >= OperatingLevel::ReadWrite);
    }

    #[test]
    fn forbidden_body_refuses_to_load() {
        let c = Classifier::new(oraclemcp_guard::ClassifierConfig::new());
        // Dynamic SQL in a PL/SQL block is Forbidden (fail-closed).
        let d = def_sql("evil", "BEGIN EXECUTE IMMEDIATE 'DROP TABLE x'; END;", None);
        let err = classify_at_load(&d, &c, OperatingLevel::Admin).unwrap_err();
        assert!(matches!(err, LoadError::Forbidden { .. }));
    }

    #[test]
    fn declared_level_can_only_make_stricter() {
        let c = Classifier::new(oraclemcp_guard::ClassifierConfig::new());
        // A read-only SELECT the author declares DDL: the floor is raised to DDL,
        // so it refuses on a READ_ONLY ceiling.
        let d = def_sql("sel", "SELECT 1 FROM dual", Some("DDL"));
        let err = classify_at_load(&d, &c, OperatingLevel::ReadOnly).unwrap_err();
        assert!(
            matches!(err, LoadError::OverCeiling { required, .. } if required == OperatingLevel::Ddl)
        );
        // The author CANNOT loosen: declaring READ_ONLY on a write block keeps
        // the derived (write) level.
        let w = def_sql("w", "BEGIN UPDATE t SET x=1; END;", Some("READ_ONLY"));
        let loaded = classify_at_load(&w, &c, OperatingLevel::Admin).expect("loads");
        assert!(loaded.required_level >= OperatingLevel::ReadWrite);
    }

    #[test]
    fn unparseable_declared_level_is_rejected_not_silently_dropped() {
        let c = Classifier::new(oraclemcp_guard::ClassifierConfig::new());
        // A typo'd declared_level ("DLL" for "DDL") must NOT be silently dropped
        // and loaded at the looser classifier-derived level (ReadOnly). It is a
        // structural error surfaced as `LoadError::Invalid` at load time — never
        // a silent load below the operator's intended pin.
        let d = def_sql("sel", "SELECT 1 FROM dual", Some("DLL"));
        let err = classify_at_load(&d, &c, OperatingLevel::ReadOnly).unwrap_err();
        assert!(
            matches!(&err, LoadError::Invalid { reason, .. } if reason.contains("declared_level")),
            "expected LoadError::Invalid mentioning declared_level, got {err:?}"
        );
        // Other unrecognized spellings are also rejected (case/format variants).
        for typo in ["read only", "rw", "readonly", ""] {
            let d = def_sql("x", "SELECT 1 FROM dual", Some(typo));
            assert!(
                matches!(d.validate(), Err(LoadError::Invalid { .. })),
                "declared_level {typo:?} should be rejected"
            );
        }
        // The recognized tokens (incl. lowercase / surrounding whitespace, which
        // `OperatingLevel::parse` normalizes) still validate.
        for ok in ["READ_ONLY", "read_write", " DDL ", "Admin"] {
            let d = def_sql("x", "SELECT 1 FROM dual", Some(ok));
            assert!(
                d.validate().is_ok(),
                "declared_level {ok:?} should validate"
            );
        }
    }

    #[test]
    fn load_tools_is_fail_fast() {
        let c = Classifier::new(oraclemcp_guard::ClassifierConfig::new());
        let defs = vec![
            def_sql("ok", "SELECT 1 FROM dual", None),
            def_sql("evil", "BEGIN EXECUTE IMMEDIATE 'x'; END;", None),
        ];
        assert!(load_tools(&defs, &c, OperatingLevel::Admin).is_err());
    }

    // ── HMAC signing (2.12.5) ─────────────────────────────────────────────────

    const KEY: &[u8] = b"operator-hmac-key";

    #[test]
    fn sign_then_verify_roundtrips() {
        let mut d = def_sql("rep", "SELECT 1 FROM dual", None);
        d.params = vec![ParamDef {
            name: "x".to_owned(),
            ty: ParamType::Integer,
            required: true,
            description: None,
        }];
        d.signature = Some(sign(&d, KEY));
        assert!(verify_signature(&d, KEY));
        // Wrong key fails.
        assert!(!verify_signature(&d, b"other-key"));
    }

    #[test]
    fn tampering_invalidates_the_signature() {
        let mut d = def_sql("rep", "SELECT 1 FROM dual", None);
        d.signature = Some(sign(&d, KEY));
        // Tamper the body after signing.
        d.sql = Some("SELECT secret FROM admin_only".to_owned());
        assert!(!verify_signature(&d, KEY));
    }

    #[test]
    fn protected_profile_requires_a_valid_signature() {
        let d = def_sql("rep", "SELECT 1 FROM dual", None);
        // Unsigned on protected -> SignatureRequired.
        assert!(matches!(
            enforce_signature(&d, KEY, true),
            Err(LoadError::SignatureRequired { .. })
        ));
        // Tampered/forged signature on protected -> SignatureInvalid.
        let mut forged = d.clone();
        forged.signature = Some("deadbeef".to_owned());
        assert!(matches!(
            enforce_signature(&forged, KEY, true),
            Err(LoadError::SignatureInvalid { .. })
        ));
        // Correctly signed -> ok.
        let mut signed = d.clone();
        signed.signature = Some(sign(&signed, KEY));
        assert!(enforce_signature(&signed, KEY, true).is_ok());
    }

    #[test]
    fn unprotected_profile_allows_unsigned_but_rejects_bad_signature() {
        let d = def_sql("rep", "SELECT 1 FROM dual", None);
        // Unsigned on an unprotected profile is fine.
        assert!(enforce_signature(&d, KEY, false).is_ok());
        // But a present-yet-invalid signature is still rejected.
        let mut bad = d.clone();
        bad.signature = Some("00".to_owned());
        assert!(matches!(
            enforce_signature(&bad, KEY, false),
            Err(LoadError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn load_tools_for_profile_enforces_signing_then_classifies() {
        let c = Classifier::new(oraclemcp_guard::ClassifierConfig::new());
        let mut d = def_sql("rep", "SELECT 1 FROM dual", None);
        d.signature = Some(sign(&d, KEY));
        // Protected: signed + read-only -> loads.
        let loaded = load_tools_for_profile(&[d.clone()], &c, OperatingLevel::ReadOnly, KEY, true)
            .expect("loads");
        assert_eq!(loaded[0].required_level, OperatingLevel::ReadOnly);
        // Protected + unsigned -> refuses before classification.
        let unsigned = def_sql("rep2", "SELECT 1 FROM dual", None);
        assert!(matches!(
            load_tools_for_profile(&[unsigned], &c, OperatingLevel::ReadOnly, KEY, true),
            Err(LoadError::SignatureRequired { .. })
        ));
    }

    // ── Form A bind-only execution (2.12.3) ───────────────────────────────────

    fn def_with_params(sql: &str, params: Vec<ParamDef>) -> CustomToolDef {
        CustomToolDef {
            name: "t".to_owned(),
            description: "t".to_owned(),
            sql: Some(sql.to_owned()),
            call: None,
            params,
            output_mode: OutputMode::Rows,
            declared_level: None,
            signature: None,
        }
    }

    fn p(name: &str, ty: ParamType, required: bool) -> ParamDef {
        ParamDef {
            name: name.to_owned(),
            ty,
            required,
            description: None,
        }
    }

    #[test]
    fn bind_params_typechecks_and_binds() {
        let d = def_with_params(
            "SELECT * FROM t WHERE id = :id AND name = :name AND ratio = :r AND flag = :f",
            vec![
                p("id", ParamType::Integer, true),
                p("name", ParamType::String, true),
                p("r", ParamType::Number, false),
                p("f", ParamType::Boolean, false),
            ],
        );
        let binds = bind_params(&d, &json!({"id": 42, "name": "acme", "r": 1.5, "f": true}))
            .expect("binds");
        assert_eq!(binds.len(), 4);
        assert_eq!(binds[0], ("id".to_owned(), OracleBind::I64(42)));
        assert_eq!(
            binds[1],
            ("name".to_owned(), OracleBind::String("acme".to_owned()))
        );
        assert_eq!(binds[2], ("r".to_owned(), OracleBind::F64(1.5)));
        assert_eq!(binds[3], ("f".to_owned(), OracleBind::Bool(true)));
    }

    #[test]
    fn bind_params_enforces_required_and_types_and_unknown() {
        let d = def_with_params(
            "SELECT :id FROM dual",
            vec![p("id", ParamType::Integer, true)],
        );
        assert_eq!(
            bind_params(&d, &json!({})).unwrap_err().error_class,
            ErrorClass::InvalidArguments
        );
        assert_eq!(
            bind_params(&d, &json!({"id": "not-a-number"}))
                .unwrap_err()
                .error_class,
            ErrorClass::InvalidArguments
        );
        assert_eq!(
            bind_params(&d, &json!({"id": 1, "extra": 2}))
                .unwrap_err()
                .error_class,
            ErrorClass::InvalidArguments
        );
    }

    #[test]
    fn optional_missing_param_binds_null() {
        let d = def_with_params(
            "SELECT :a FROM dual",
            vec![p("a", ParamType::String, false)],
        );
        let binds = bind_params(&d, &json!({})).expect("ok");
        assert_eq!(binds[0], ("a".to_owned(), OracleBind::Null));
    }

    struct EchoExecutor;
    impl CustomToolExecutor for EchoExecutor {
        fn run(
            &self,
            body: ToolBody<'_>,
            level: OperatingLevel,
            binds: &[(String, OracleBind)],
        ) -> Result<Value, ErrorEnvelope> {
            // Bind-only: the executor receives the body + typed binds, never an
            // interpolated SQL string.
            let body_str = match body {
                ToolBody::InlineSql(s) => s.to_owned(),
                ToolBody::PackageCall(c) => c.to_owned(),
            };
            Ok(json!({
                "body": body_str,
                "level": level.as_str(),
                "bind_count": binds.len(),
            }))
        }
    }

    #[test]
    fn execute_custom_tool_binds_and_runs_at_derived_level() {
        let c = Classifier::new(oraclemcp_guard::ClassifierConfig::new());
        let d = def_with_params(
            "SELECT * FROM t WHERE id = :id",
            vec![p("id", ParamType::Integer, true)],
        );
        let loaded = classify_at_load(&d, &c, OperatingLevel::ReadOnly).expect("loads");
        let out = execute_custom_tool(&loaded, &json!({"id": 7}), &EchoExecutor).expect("runs");
        assert_eq!(out["level"], json!("READ_ONLY"));
        assert_eq!(out["bind_count"], json!(1));
        assert_eq!(out["body"], json!("SELECT * FROM t WHERE id = :id"));
    }

    // ── Form B package wrapper (2.12.4) ───────────────────────────────────────

    fn def_call(name: &str, call: &str) -> CustomToolDef {
        CustomToolDef {
            name: name.to_owned(),
            description: "wrap a package".to_owned(),
            sql: None,
            call: Some(call.to_owned()),
            params: vec![p("id", ParamType::Integer, true)],
            output_mode: OutputMode::Rows,
            declared_level: None,
            signature: None,
        }
    }

    #[test]
    fn form_b_proven_readonly_package_classifies_safe() {
        use oraclemcp_guard::{ObjectRef, Purity, SideEffectOracle};
        use std::sync::Arc;
        struct ProvenOracle;
        impl SideEffectOracle for ProvenOracle {
            fn routine_purity(&self, _r: &ObjectRef) -> Purity {
                Purity::ProvenReadOnly
            }
        }
        let c = oraclemcp_guard::Classifier::default().with_oracle(Arc::new(ProvenOracle));
        let d = def_call("cust360", "billing_api.get_360(:id)");
        // The engine proves the package read-only -> Safe -> loads at READ_ONLY
        // (auto-approved) even on a READ_ONLY profile.
        let loaded =
            classify_at_load(&d, &c, OperatingLevel::ReadOnly).expect("proven read-only loads");
        assert_eq!(loaded.required_level, OperatingLevel::ReadOnly);
    }

    #[test]
    fn form_b_unproven_package_is_fail_closed_to_guarded() {
        // The default classifier has no engine oracle -> the package call cannot
        // be proven read-only -> Guarded (>= ReadWrite), so it refuses on a
        // READ_ONLY profile and only loads with write headroom.
        let c = Classifier::new(oraclemcp_guard::ClassifierConfig::new());
        let d = def_call("cust360", "billing_api.get_360(:id)");
        let err = classify_at_load(&d, &c, OperatingLevel::ReadOnly).unwrap_err();
        assert!(
            matches!(err, LoadError::OverCeiling { required, .. } if required >= OperatingLevel::ReadWrite)
        );
        let loaded = classify_at_load(&d, &c, OperatingLevel::ReadWrite).expect("loads at RW");
        assert!(loaded.required_level >= OperatingLevel::ReadWrite);
    }

    // ── Catalog: first-class + meta-dispatch (2.12.6) ─────────────────────────

    fn catalog() -> CustomToolCatalog {
        let c = Classifier::new(oraclemcp_guard::ClassifierConfig::new());
        let defs = vec![
            def_with_params(
                "SELECT * FROM v WHERE id = :id",
                vec![p("id", ParamType::Integer, true)],
            ),
            {
                let mut d = def_with_params(
                    "SELECT name FROM t WHERE k = :k",
                    vec![p("k", ParamType::String, true)],
                );
                d.name = "lookup".to_owned();
                d
            },
        ];
        let loaded = load_tools(&defs, &c, OperatingLevel::ReadOnly).expect("load");
        CustomToolCatalog::new(loaded)
    }

    #[test]
    fn first_class_registers_each_tool() {
        let cat = catalog();
        let mut reg = ToolRegistry::new();
        cat.register_first_class(&mut reg);
        assert!(reg.tools.iter().any(|t| t.name == "t"));
        assert!(reg.tools.iter().any(|t| t.name == "lookup"));
        assert!(!reg.tools.iter().any(|t| t.name == RUN_NAMED_TOOL));
    }

    #[test]
    fn meta_dispatch_registers_a_single_tool() {
        let cat = catalog();
        let mut reg = ToolRegistry::new();
        cat.register_meta_dispatch(&mut reg);
        assert_eq!(reg.tools.len(), 1);
        assert_eq!(reg.tools[0].name, RUN_NAMED_TOOL);
    }

    #[test]
    fn run_named_dispatches_and_rejects_unknown() {
        let cat = catalog();
        let out = cat
            .run_named(
                &json!({"name": "lookup", "params": {"k": "x"}}),
                &EchoExecutor,
            )
            .expect("dispatches");
        assert_eq!(out["bind_count"], json!(1));
        let err = cat
            .run_named(&json!({"name": "nope", "params": {}}), &EchoExecutor)
            .unwrap_err();
        assert_eq!(err.error_class, ErrorClass::ObjectNotFound);
        let err = cat
            .run_named(&json!({"params": {}}), &EchoExecutor)
            .unwrap_err();
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    }

    #[test]
    fn catalog_json_lists_the_tools() {
        let cat = catalog();
        let doc = cat.catalog_json();
        let tools = doc["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert!(
            tools
                .iter()
                .all(|t| t["required_level"] == json!("READ_ONLY"))
        );
        assert!(tools.iter().any(|t| t["name"] == json!("lookup")));
        assert_eq!(tools[0]["input_schema"]["type"], json!("object"));
    }
}
