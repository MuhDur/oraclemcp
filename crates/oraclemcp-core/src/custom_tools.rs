//! Operator-defined custom / virtual tools (plan §8.6; bead P1-13 /
//! oracle-qmwz.2.12 and subtasks). Companies expose their OWN proprietary
//! operations as MCP tools **without forking** — a config-driven instantiation
//! of the Phase-1 spine (classifier, bind-first exec, audit, registry), not a
//! new subsystem.
//!
//! Definitions live in operator-controlled `~/.config/oraclemcp/tools.d/*.toml`
//! (NEVER in the repo, like login scripts), are loaded at startup, and register
//! into the same [`ToolRegistry`] so every MCP client discovers them via
//! `tools/list`. A definition is **Form A**: inline SQL / multi-statement /
//! full PL/SQL block. Agent values bind as bind variables only — never
//! interpolated (injection defense).
//!
//! Structured package definitions retain dictionary identities and typed scalar
//! slots. A verified signature only makes them pending: the server must prove
//! their complete live closure for the active profile before advertising them.
//! SQL-text `call` definitions and meta-dispatch remain unsupported.
//!
//! Submodule coverage: this file is the **loader + schema + registration**
//! (P1-13a / 2.12.1); classify-at-load (2.12.2), Form A execution (2.12.3), and
//! HMAC signing (2.12.5) layer on here.

use oraclemcp_audit::HmacSha256Key;
use oraclemcp_db::OracleBind;
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{Classifier, OperatingLevel, named_bind_placeholders};
use serde::{Deserialize, Serialize};
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
#[serde(deny_unknown_fields)]
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
    /// One structured return/OUT value. Inline SQL scalar shaping remains
    /// unsupported and is rejected during validation.
    Scalar,
}

/// Dictionary-exact identity of one packaged overload; never executable text.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageRoutineDef {
    /// Dictionary owner.
    pub owner: String,
    /// Package containing the member.
    pub package: String,
    /// Member name.
    pub member: String,
    /// ALL_PROCEDURES subprogram identity.
    pub subprogram_id: u32,
    /// Exact Oracle overload label, including absence.
    #[serde(default)]
    pub overload: Option<String>,
}

/// Closed Oracle type vocabulary for structured routine arguments.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PackageOracleType {
    /// Oracle NUMBER.
    Number,
    /// Database character text.
    Varchar2,
    /// National character text.
    Nvarchar2,
    /// PL/SQL BOOLEAN.
    Boolean,
    /// Single precision IEEE value.
    BinaryFloat,
    /// Double precision IEEE value.
    BinaryDouble,
    /// Oracle DATE.
    Date,
    /// Oracle TIMESTAMP.
    Timestamp,
    /// Binary scalar.
    Raw,
    /// Cursor output; unavailable until the bounded output executor is wired.
    RefCursor,
}

/// A routine argument's direction, including its function return slot.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PackageArgDirection {
    /// Input bind.
    In,
    /// Output bind.
    Out,
    /// Input/output bind; requires the later output adapter.
    InOut,
    /// Function return, at dictionary position zero.
    Return,
}

/// One typed bind matched against the pinned ALL_ARGUMENTS projection.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageArgDef {
    /// Dictionary argument name; absent only for the function return.
    #[serde(default)]
    pub oracle_name: Option<String>,
    /// Exact scalar type; arbitrary type expressions are refused.
    pub oracle_type: PackageOracleType,
    /// Input, output or function return.
    pub direction: PackageArgDirection,
    /// Server bind name and output result key.
    pub bind_name: String,
    /// Maximum scalar output bytes, bounded to 32767.
    #[serde(default = "default_package_output_bytes")]
    pub max_bytes: u32,
}

fn default_package_output_bytes() -> u32 {
    4096
}

impl PackageOracleType {
    fn catalog_name(self) -> &'static str {
        match self {
            Self::Number => "NUMBER",
            Self::Varchar2 => "VARCHAR2",
            Self::Nvarchar2 => "NVARCHAR2",
            Self::Boolean => "PL/SQL BOOLEAN",
            Self::BinaryFloat => "BINARY_FLOAT",
            Self::BinaryDouble => "BINARY_DOUBLE",
            Self::Date => "DATE",
            Self::Timestamp => "TIMESTAMP",
            Self::Raw => "RAW",
            Self::RefCursor => "REF CURSOR",
        }
    }

    fn declaration(self, bytes: u32) -> String {
        match self {
            Self::Varchar2 => format!("VARCHAR2({bytes})"),
            Self::Nvarchar2 => format!("NVARCHAR2({})", bytes.min(16_383)),
            Self::Raw => format!("RAW({bytes})"),
            Self::Timestamp => "TIMESTAMP(9)".into(),
            Self::Boolean => "BOOLEAN".into(),
            Self::RefCursor => "SYS_REFCURSOR".into(),
            other => other.catalog_name().to_owned(),
        }
    }
}

/// A fixed server-generated block and its positional wire slots. Agent values
/// are supplied separately; their bytes cannot influence the block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageCallWrapper {
    /// Typed locals force overload resolution to use the pinned argument types.
    pub sql: String,
    /// Positional input slots followed by return/OUT slots, in wire order.
    pub bindings: Vec<PackageArgDef>,
}

/// Build only from the exact, complete ALL_ARGUMENTS rows for the member.
/// All overloads are retained until their subprogram id is checked here.
pub fn package_call_wrapper(
    def: &CustomToolDef,
    rows: &[oraclemcp_db::OracleRow],
) -> Result<PackageCallWrapper, LoadError> {
    def.validate()?;
    let invalid = |reason: &str| LoadError::Invalid {
        name: def.name.clone(),
        reason: reason.into(),
    };
    let routine = def
        .routine
        .as_ref()
        .ok_or_else(|| invalid("structured routine is required"))?;
    if rows.len() >= 257 {
        return Err(invalid("ALL_ARGUMENTS projection was truncated"));
    }
    let mut selected = Vec::new();
    for row in rows {
        let id = row
            .parse_i64("SUBPROGRAM_ID")
            .ok_or_else(|| invalid("argument subprogram identity is unreadable"))?;
        if id == i64::from(routine.subprogram_id) {
            selected.push(row);
        }
    }
    // The closed projection orders by dictionary sequence but does not expose
    // SEQUENCE. POSITION is exact for the flat scalar signatures admitted here.
    selected.sort_by_key(|row| row.parse_i64("POSITION"));
    if selected.len() != def.args.len() {
        return Err(invalid("pinned overload argument count differs"));
    }
    let returns = def
        .args
        .first()
        .is_some_and(|arg| arg.direction == PackageArgDirection::Return);
    for (index, (arg, row)) in def.args.iter().zip(selected).enumerate() {
        let position = if returns { index } else { index + 1 };
        let direction = match arg.direction {
            PackageArgDirection::In => "IN",
            PackageArgDirection::Out | PackageArgDirection::Return => "OUT",
            PackageArgDirection::InOut => "IN/OUT",
        };
        if row.parse_i64("POSITION") != Some(position as i64)
            || row.parse_i64("DATA_LEVEL") != Some(0)
            || row.text("OVERLOAD") != routine.overload.as_deref()
            || row.text("ARGUMENT_NAME") != arg.oracle_name.as_deref()
            || row.text("IN_OUT") != Some(direction)
            || row.text("DATA_TYPE") != Some(arg.oracle_type.catalog_name())
        {
            return Err(invalid(
                "pinned overload name, type, direction or scalar position differs",
            ));
        }
    }
    if let Some(channel) = def.deferred_package_output() {
        return Err(LoadError::OutputUnavailable {
            name: def.name.clone(),
            channel: channel.into(),
        });
    }
    let mut sql = String::new();
    if !def.args.is_empty() {
        sql.push_str("DECLARE\n");
        for (index, arg) in def.args.iter().enumerate() {
            sql.push_str(&format!(
                "  omcp_p{index} {};\n",
                arg.oracle_type.declaration(arg.max_bytes)
            ));
        }
    }
    sql.push_str("BEGIN\n");
    let mut bindings = Vec::new();
    for (index, arg) in def.args.iter().enumerate() {
        if matches!(
            arg.direction,
            PackageArgDirection::In | PackageArgDirection::InOut
        ) {
            let bind = format!(":{}", arg.bind_name);
            let expression = match arg.oracle_type {
                PackageOracleType::Date => format!(
                    "SYS.STANDARD.TO_DATE({bind}, 'FXYYYY-MM-DD\"T\"HH24:MI:SS', 'NLS_DATE_LANGUAGE=American')"
                ),
                PackageOracleType::Timestamp => format!(
                    "SYS.STANDARD.TO_TIMESTAMP({bind}, 'FXYYYY-MM-DD\"T\"HH24:MI:SS.FF9', 'NLS_DATE_LANGUAGE=American')"
                ),
                PackageOracleType::Raw => format!("SYS.STANDARD.HEXTORAW({bind})"),
                _ => bind,
            };
            sql.push_str(&format!("  omcp_p{index} := {expression};\n"));
            bindings.push(arg.clone());
        }
    }
    sql.push_str("  ");
    if returns {
        sql.push_str("omcp_p0 := ");
    }
    sql.push_str(&format!(
        "\"{}\".\"{}\".\"{}\"(",
        routine.owner, routine.package, routine.member
    ));
    let mut comma = false;
    for (index, arg) in def.args.iter().enumerate() {
        if arg.direction != PackageArgDirection::Return {
            if comma {
                sql.push_str(", ");
            }
            comma = true;
            sql.push_str(&format!(
                "\"{}\" => omcp_p{index}",
                arg.oracle_name.as_deref().expect("validated argument name")
            ));
        }
    }
    sql.push_str(");\n");
    for (index, arg) in def.args.iter().enumerate() {
        if arg.direction != PackageArgDirection::In {
            sql.push_str(&format!("  :{} := omcp_p{index};\n", arg.bind_name));
            bindings.push(arg.clone());
        }
    }
    sql.push_str("END;");
    Ok(PackageCallWrapper { sql, bindings })
}

/// A parsed operator tool definition.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustomToolDef {
    /// The stable tool name (MUST be operator-namespaced; see [`Self::validate`]).
    pub name: String,
    /// Agent-facing one-line description.
    pub description: String,
    /// Form A body: inline SQL / multi-statement / full PL/SQL block.
    #[serde(default)]
    pub sql: Option<String>,
    /// Form B body: an existing package call, e.g. `billing_api.get(:id)`.
    /// **Not a supported execution mode** — rejected at load ([`Self::body`])
    /// because the fail-closed classifier can never clear a package call without
    /// a `SideEffectOracle` proof the server does not inject, so an accepted
    /// `call` definition would never execute. Kept as a field so its presence is
    /// detected and reported with actionable guidance (and stays authenticated
    /// by the HMAC signature). Rewrite the wrapper as inline `sql`.
    #[serde(default)]
    pub call: Option<String>,
    /// Structured package identity, requiring profile-specific live activation.
    #[serde(default)]
    pub routine: Option<PackageRoutineDef>,
    /// Typed named-notation argument projection.
    #[serde(default)]
    pub args: Vec<PackageArgDef>,
    /// Pinned complete call-closure fingerprint, inside the HMAC bytes.
    #[serde(default)]
    pub closure_sha256: Option<String>,
    /// Request implicit results; unavailable until output shaping is wired.
    #[serde(default)]
    pub implicit_results: bool,
    /// Request captured DBMS_OUTPUT; unavailable until output shaping is wired.
    #[serde(default)]
    pub capture_dbms_output: bool,
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
    /// Versioned HMAC signature, required on `protected` profiles (2.12.5).
    #[serde(default)]
    pub signature: Option<String>,
}

/// The body form of a custom tool. Only Form A (inline SQL / PL/SQL) is a
/// supported execution mode; Form B (`call = ...` package wrappers) is rejected
/// at load ([`CustomToolDef::body`]), so this enum carries only Form A.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolBody<'a> {
    /// Form A: inline SQL / PL/SQL.
    InlineSql(&'a str),
}

/// Why loading a custom-tool definition failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The TOML did not parse.
    #[error("tools.d parse error: {0}")]
    Parse(String),
    /// A valid structured definition still needs live profile activation.
    #[error("tool '{name}' requires live package-call activation before registration")]
    ActivationRequired {
        /// Pending definition name.
        name: String,
    },
    /// Valid output definition whose bounded execution is supplied by .10.15.
    #[error("tool '{name}' output channel {channel} is unavailable until pvlqq.10.15")]
    OutputUnavailable {
        /// Definition name.
        name: String,
        /// Unsupported output mechanism.
        channel: String,
    },
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
    #[error(
        "tool '{name}' is unsigned; protected profiles and write/package definitions require an HMAC signature"
    )]
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
    /// The signature uses an older canonical format.
    #[error(
        "tool '{name}' uses an unsupported legacy custom-tool signature; re-sign the definition with `oraclemcp sign-tool <tools.toml> --tool {name}`"
    )]
    SignatureVersionUnsupported {
        /// The offending tool name.
        name: String,
    },
}

/// The on-disk file shape: `[[tool]]` array-of-tables.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

fn is_oracle_ident(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_$#".contains(&byte))
}

fn validate_package_definition(def: &CustomToolDef) -> Result<(), LoadError> {
    let invalid = |reason: &str| LoadError::Invalid {
        name: def.name.clone(),
        reason: reason.to_owned(),
    };
    let routine = def
        .routine
        .as_ref()
        .expect("structured definition selected");
    if def.sql.is_some() || def.call.is_some() {
        return Err(invalid(
            "routine cannot be combined with sql or the unsupported call string",
        ));
    }
    if ![&routine.owner, &routine.package, &routine.member]
        .into_iter()
        .all(|name| is_oracle_ident(name))
        || routine.subprogram_id == 0
        || routine.overload.as_deref().is_some_and(|value| {
            value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(invalid(
            "routine requires exact identifiers and a positive subprogram_id; SQL, comments and database links are forbidden",
        ));
    }
    if !def.closure_sha256.as_deref().is_some_and(|pin| {
        pin.len() == 64
            && pin
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(invalid(
            "closure_sha256 must be a lowercase SHA-256 fingerprint",
        ));
    }
    if def.args.len() > 64 {
        return Err(invalid(
            "package calls support at most 64 scalar argument slots",
        ));
    }
    let mut binds = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    let mut inputs = std::collections::BTreeSet::new();
    let mut output_bytes = 0_u64;
    for (index, arg) in def.args.iter().enumerate() {
        if !is_bind_ident(&arg.bind_name)
            || arg.bind_name.len() > 128
            || !binds.insert(arg.bind_name.to_ascii_uppercase())
            || matches!(
                arg.bind_name.to_ascii_lowercase().as_str(),
                "commit"
                    | "hold"
                    | "confirm"
                    | "token"
                    | "confirmation_token"
                    | "scoped_grant"
                    | "timeout_seconds"
                    | "capture_dbms_output"
                    | "dbms_output"
                    | "max_dbms_output_lines"
                    | "max_dbms_output_chars"
            )
            || !(1..=32_767).contains(&arg.max_bytes)
        {
            return Err(invalid(
                "argument binds must be unique identifiers distinct from execution controls, with max_bytes in 1..32767",
            ));
        }
        if arg.direction == PackageArgDirection::Return {
            if index != 0 || arg.oracle_name.is_some() {
                return Err(invalid(
                    "the return slot must be first and have no oracle_name",
                ));
            }
        } else if !arg
            .oracle_name
            .as_deref()
            .is_some_and(|name| is_oracle_ident(name) && names.insert(name.to_owned()))
        {
            return Err(invalid(
                "every non-return argument requires a unique exact oracle_name",
            ));
        }
        if matches!(
            arg.direction,
            PackageArgDirection::In | PackageArgDirection::InOut
        ) {
            inputs.insert(arg.bind_name.as_str());
        }
        if arg.direction != PackageArgDirection::In {
            output_bytes += u64::from(arg.max_bytes);
        }
    }
    if output_bytes > 65_536 {
        return Err(invalid(
            "scalar output buffers exceed the aggregate 65536-byte bound",
        ));
    }
    if def.output_mode == OutputMode::Scalar
        && def
            .args
            .iter()
            .filter(|arg| arg.direction != PackageArgDirection::In)
            .count()
            != 1
    {
        return Err(invalid(
            "scalar package output requires exactly one return/OUT slot",
        ));
    }
    let mut params = std::collections::BTreeSet::new();
    for param in &def.params {
        if !is_bind_ident(&param.name)
            || !params.insert(param.name.as_str())
            || !inputs.contains(param.name.as_str())
        {
            return Err(invalid(
                "params must declare each input bind exactly once and must not declare output-only binds",
            ));
        }
        let arg = def
            .args
            .iter()
            .find(|arg| arg.bind_name == param.name)
            .expect("input name checked");
        let compatible = match arg.oracle_type {
            PackageOracleType::Number
            | PackageOracleType::BinaryFloat
            | PackageOracleType::BinaryDouble => {
                matches!(param.ty, ParamType::Number | ParamType::Integer)
            }
            PackageOracleType::Boolean => param.ty == ParamType::Boolean,
            PackageOracleType::Varchar2
            | PackageOracleType::Nvarchar2
            | PackageOracleType::Date
            | PackageOracleType::Timestamp
            | PackageOracleType::Raw => param.ty == ParamType::String,
            PackageOracleType::RefCursor => false,
        };
        if !compatible {
            return Err(invalid(
                "input JSON type does not match the declared Oracle scalar type",
            ));
        }
    }
    if params != inputs {
        return Err(invalid(
            "every package input bind requires a matching params entry",
        ));
    }
    if def
        .declared_level
        .as_deref()
        .is_some_and(|level| OperatingLevel::parse(level).is_none())
    {
        return Err(invalid(
            "declared_level must be READ_ONLY, READ_WRITE, DDL or ADMIN",
        ));
    }
    Ok(())
}

impl CustomToolDef {
    /// Unsupported package output remains unadvertised until .10.15.
    #[must_use]
    pub fn deferred_package_output(&self) -> Option<&'static str> {
        if self.implicit_results {
            Some("implicit results")
        } else if self.capture_dbms_output {
            Some("DBMS_OUTPUT")
        } else if self
            .args
            .iter()
            .any(|arg| arg.oracle_type == PackageOracleType::RefCursor)
        {
            Some("REF_CURSOR")
        } else if self
            .args
            .iter()
            .any(|arg| arg.direction == PackageArgDirection::InOut)
        {
            Some("IN OUT")
        } else {
            None
        }
    }

    /// The Form A inline-SQL body. `call = ...` (Form B package wrappers) is not
    /// a supported execution mode and is rejected here at load with actionable
    /// guidance; a definition with neither body is likewise rejected.
    pub fn body(&self) -> Result<ToolBody<'_>, LoadError> {
        if self.routine.is_some() {
            return Err(LoadError::ActivationRequired {
                name: self.name.clone(),
            });
        }
        match (&self.sql, &self.call) {
            (Some(s), None) => Ok(ToolBody::InlineSql(s)),
            // Form B needs a per-generation SideEffectOracle purity proof to
            // clear the fail-closed classifier, which this server never wires; an
            // accepted `call` definition could therefore never execute. Reject it
            // at load so accepted configuration equals behavior (QA100 .65). This
            // also covers a definition that set both `sql` and `call`.
            (_, Some(_)) => Err(LoadError::Invalid {
                name: self.name.clone(),
                reason: "`call` (Form B package wrappers) is not a supported execution mode; \
                         rewrite it as inline SQL, e.g. `sql = \"SELECT pkg.fn(:x) FROM dual\"`"
                    .to_owned(),
            }),
            (None, None) => Err(LoadError::Invalid {
                name: self.name.clone(),
                reason: "a `sql` (Form A inline SQL) body is required".to_owned(),
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
        if self.routine.is_some() {
            return validate_package_definition(self);
        }
        if !self.args.is_empty()
            || self.closure_sha256.is_some()
            || self.implicit_results
            || self.capture_dbms_output
        {
            return Err(invalid(
                "package argument, closure and output-channel fields require a routine",
            ));
        }
        // `output_mode = "scalar"` parses and is documented, but production
        // execution never shapes the result — it silently returns the row set.
        // Accepting it advertises a contract that does nothing, so reject it at
        // load until strict scalar shaping is implemented: accepted configuration
        // must equal behavior (QA100 .44).
        if self.output_mode == OutputMode::Scalar {
            return Err(invalid(
                "output_mode = \"scalar\" is not yet supported; use output_mode = \"rows\"",
            ));
        }
        let body = self.body()?; // exactly one body form
        // Parameter names: valid bind identifiers, unique both exactly AND
        // (because Oracle bind names are case-insensitive — `:Id` and `:ID` are
        // the same bind) case-insensitively. `seen_ci` maps the uppercased name
        // to the operator's original spelling for a legible error.
        let mut seen = std::collections::HashSet::new();
        let mut seen_ci: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
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
            if let Some(prev) = seen_ci.insert(p.name.to_ascii_uppercase(), p.name.clone()) {
                return Err(invalid(&format!(
                    "parameter '{}' duplicates parameter '{prev}' case-insensitively \
                     (Oracle bind names are case-insensitive)",
                    p.name
                )));
            }
        }
        // Declared parameters MUST match the named bind placeholders the body
        // actually references, case-insensitively. A `:bind` with no parameter
        // reaches ORA-01008 (not all variables bound) on every call; a parameter
        // with no matching `:bind` is bound-but-unreferenced and reaches ORA-01036
        // (illegal variable name) or is a silent no-op. Rejecting either at load
        // time turns a permanently-advertised-but-unusable tool into a clear
        // config error. Binds are extracted with the guard's SQL-aware tokenizer
        // (`named_bind_placeholders`), so colons inside string/`q'`/`n'` literals,
        // quoted identifiers, `--`/`/* */` comments, PL/SQL `:=`, and `::` casts
        // never count. This is a TIGHTENING (refuse a broken definition); it never
        // relaxes any query-path guard verdict.
        let ToolBody::InlineSql(body_sql) = body;
        let binds = named_bind_placeholders(body_sql); // uppercased, distinct
        for b in &binds {
            if !seen_ci.contains_key(b) {
                return Err(invalid(&format!(
                    "body references bind ':{}' but no matching parameter is declared",
                    b.to_ascii_lowercase()
                )));
            }
        }
        for p in &self.params {
            if !binds.contains(&p.name.to_ascii_uppercase()) {
                return Err(invalid(&format!(
                    "parameter '{}' is declared but the body references no ':{}' bind",
                    p.name, p.name
                )));
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
        .with_input_schema(self.input_schema())
    }
}

/// Register a set of validated custom tools into the registry (first-class mode).
pub fn register_custom_tools(registry: &mut ToolRegistry, defs: &[CustomToolDef]) {
    for d in defs {
        if d.routine.is_none() {
            registry.register(d.to_descriptor());
        }
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

/// A structured definition whose complete canonical HMAC was verified. It is
/// still pending live activation and carries no execution authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPackageDefinition {
    def: CustomToolDef,
}

impl SignedPackageDefinition {
    /// Immutable signature-bound definition.
    #[must_use]
    pub fn definition(&self) -> &CustomToolDef {
        &self.def
    }
}

/// Verify structure and signing before a package definition enters a catalogue.
pub fn prepare_package_definition(
    def: &CustomToolDef,
    key: &HmacSha256Key,
) -> Result<SignedPackageDefinition, LoadError> {
    def.validate()?;
    if def.routine.is_none() {
        return Err(LoadError::Invalid {
            name: def.name.clone(),
            reason: "structured routine is required".into(),
        });
    }
    enforce_signature(def, key, true)?;
    Ok(SignedPackageDefinition { def: def.clone() })
}

impl CustomToolDef {
    /// The string the classifier sees: the Form A SQL/PL-SQL as-is.
    fn classify_input(&self) -> Result<String, LoadError> {
        // Only Form A reaches here; `body` rejects Form B (`call = ...`) at load.
        let ToolBody::InlineSql(s) = self.body()?;
        Ok(s.to_owned())
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

const SIGNATURE_DOMAIN: &str = "oraclemcp.custom-tool.definition";
const SIGNATURE_VERSION: &str = "v3";
const SIGNATURE_PREFIX: &str = "oraclemcp-custom-tool:v3:hmac-sha256:";

fn push_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    let len = u64::try_from(value.len()).expect("custom-tool field length fits in u64");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

fn push_field(out: &mut Vec<u8>, label: &str, value: &str) {
    push_len_prefixed(out, label.as_bytes());
    push_len_prefixed(out, value.as_bytes());
}

fn push_optional_field(out: &mut Vec<u8>, label: &str, value: Option<&str>) {
    push_len_prefixed(out, label.as_bytes());
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            push_len_prefixed(out, value.as_bytes());
        }
    }
}

/// The v3 canonical byte sequence, including structured routine identity and pin.
///
/// The domain and version are explicit, every semantic or agent-visible field
/// is encoded in a fixed order, optional-field presence is unambiguous, and
/// each variable-width component is length-framed. The TOML `signature`
/// envelope itself is intentionally excluded so a definition can be re-signed.
fn canonical_bytes(def: &CustomToolDef) -> Vec<u8> {
    // Exhaustive destructuring is deliberate: adding a definition field must
    // make this signer fail to compile until the new field is either encoded
    // or explicitly judged to be part of the signature envelope.
    let CustomToolDef {
        name,
        description,
        sql,
        call,
        routine,
        args,
        closure_sha256,
        implicit_results,
        capture_dbms_output,
        params,
        output_mode,
        declared_level,
        signature: _,
    } = def;
    let mut out = Vec::new();
    push_field(&mut out, "domain", SIGNATURE_DOMAIN);
    push_field(&mut out, "version", SIGNATURE_VERSION);
    push_field(&mut out, "name", name);
    push_field(&mut out, "description", description);
    push_optional_field(&mut out, "sql", sql.as_deref());
    push_optional_field(&mut out, "call", call.as_deref());
    push_len_prefixed(&mut out, b"routine");
    push_len_prefixed(
        &mut out,
        &serde_json::to_vec(routine).expect("typed routine serializes"),
    );
    push_len_prefixed(&mut out, b"args");
    push_len_prefixed(
        &mut out,
        &serde_json::to_vec(args).expect("typed arguments serialize"),
    );
    push_optional_field(&mut out, "closure_sha256", closure_sha256.as_deref());
    push_len_prefixed(&mut out, b"implicit_results");
    out.push(u8::from(*implicit_results));
    push_len_prefixed(&mut out, b"capture_dbms_output");
    out.push(u8::from(*capture_dbms_output));
    push_field(
        &mut out,
        "output_mode",
        match output_mode {
            OutputMode::Rows => "rows",
            OutputMode::Scalar => "scalar",
        },
    );
    push_optional_field(&mut out, "declared_level", declared_level.as_deref());
    push_len_prefixed(&mut out, b"params");
    let params_len = u64::try_from(params.len()).expect("parameter count fits in u64");
    out.extend_from_slice(&params_len.to_be_bytes());
    for param in params {
        let ParamDef {
            name,
            ty,
            required,
            description,
        } = param;
        push_field(&mut out, "param.name", name);
        push_field(&mut out, "param.type", ty.json_type());
        push_len_prefixed(&mut out, b"param.required");
        out.push(u8::from(*required));
        push_optional_field(&mut out, "param.description", description.as_deref());
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute the versioned HMAC signature for a definition (operator-side signing).
#[must_use]
pub fn sign(def: &CustomToolDef, hmac_key: &HmacSha256Key) -> String {
    format!(
        "{SIGNATURE_PREFIX}{}",
        hex(&hmac_key.authenticate(&canonical_bytes(def)))
    )
}

/// Whether `def.signature` is a current-version HMAC over its canonical bytes.
#[must_use]
pub fn verify_signature(def: &CustomToolDef, hmac_key: &HmacSha256Key) -> bool {
    let Some(sig) = &def.signature else {
        return false;
    };
    if !sig.starts_with(SIGNATURE_PREFIX) {
        return false;
    }
    // Compare the complete, versioned envelope so alternate/legacy formats can
    // never be treated as an implicit downgrade.
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
    hmac_key: &HmacSha256Key,
    protected: bool,
) -> Result<(), LoadError> {
    if protected {
        if def.signature.is_none() {
            return Err(LoadError::SignatureRequired {
                name: def.name.clone(),
            });
        }
        if !verify_signature(def, hmac_key) {
            if def.signature.as_deref().is_some_and(is_legacy_signature) {
                return Err(LoadError::SignatureVersionUnsupported {
                    name: def.name.clone(),
                });
            }
            return Err(LoadError::SignatureInvalid {
                name: def.name.clone(),
            });
        }
    } else if def.signature.is_some() && !verify_signature(def, hmac_key) {
        if def.signature.as_deref().is_some_and(is_legacy_signature) {
            return Err(LoadError::SignatureVersionUnsupported {
                name: def.name.clone(),
            });
        }
        return Err(LoadError::SignatureInvalid {
            name: def.name.clone(),
        });
    }
    Ok(())
}

fn is_legacy_signature(signature: &str) -> bool {
    signature.starts_with("oraclemcp-custom-tool:v2:")
        || signature.len() == 64
            && signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Classify-at-load + signing enforcement for a profile. Use this in production:
/// `protected` profiles require a valid HMAC on every definition.
pub fn load_tools_for_profile(
    defs: &[CustomToolDef],
    classifier: &Classifier,
    max_level: OperatingLevel,
    hmac_key: &HmacSha256Key,
    protected: bool,
) -> Result<Vec<LoadedTool>, LoadError> {
    defs.iter()
        .map(|d| {
            enforce_signature(d, hmac_key, protected || d.routine.is_some())?;
            let loaded = classify_at_load(d, classifier, max_level)?;
            if loaded.required_level > OperatingLevel::ReadOnly {
                enforce_signature(d, hmac_key, true)?;
            }
            Ok(loaded)
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
#[async_trait::async_trait(?Send)]
pub trait CustomToolExecutor {
    /// Execute `body` at `level` with the bound params; return structured JSON.
    /// `Cx`-first and `async` (B1): the body runs a real DB round trip.
    async fn run(
        &self,
        body: ToolBody<'_>,
        level: OperatingLevel,
        binds: &[(String, OracleBind)],
    ) -> Result<Value, ErrorEnvelope>;
}

/// Execute a loaded custom tool: bind the agent args (bind-only) and run the
/// body at its classify-derived level. PL/SQL blocks are ≥ Guarded, so the
/// caller's level gate / step-up applies before the executor runs them.
pub async fn execute_custom_tool(
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
    executor.run(body, loaded.required_level, &binds).await
}

// ── Catalog: first-class registration (P1-13f) ────────────────────────────────

/// A loaded, gated catalog of operator tools. Each tool is registered as its own
/// **first-class** MCP tool (with a proper `inputSchema`) via
/// [`Self::register_first_class`], so every MCP client discovers it through
/// `tools/list`. Operator tools are additive to the ≤12 core-tool budget.
///
/// A large-catalog **meta-dispatch** mode (a single `oracle_run_named` fan-out
/// keeping the top-level surface tiny) was specified but never wired into
/// production — no registration threshold, no dispatch route. It is
/// intentionally omitted rather than shipped dormant: keeping it would advertise
/// an execution surface nothing reaches (QA100 .65). A bounded large-catalog
/// surface, if ever needed, must be added with end-to-end registration + dispatch
/// routing, not as dead API.
#[derive(Clone, Debug, Default)]
pub struct CustomToolCatalog {
    tools: Vec<LoadedTool>,
    pending: Vec<SignedPackageDefinition>,
}

impl CustomToolCatalog {
    /// Build a catalog from the loaded (classified + gated) tools.
    #[must_use]
    pub fn new(tools: Vec<LoadedTool>) -> Self {
        CustomToolCatalog {
            tools,
            pending: Vec::new(),
        }
    }

    /// Retain signature-checked structured definitions without registering them.
    #[must_use]
    pub fn with_pending(tools: Vec<LoadedTool>, pending: Vec<SignedPackageDefinition>) -> Self {
        Self { tools, pending }
    }

    /// Definitions awaiting the active profile's live resolution and proof.
    #[must_use]
    pub fn pending(&self) -> &[SignedPackageDefinition] {
        &self.pending
    }

    /// Publish only the members whose caller completed profile-specific proof.
    /// Unsupported/rejected members stay outside the advertised catalogue.
    #[must_use]
    pub fn activated(&self, packages: Vec<LoadedTool>) -> Self {
        let mut tools = self.tools.clone();
        tools.extend(packages);
        Self {
            tools,
            pending: Vec::new(),
        }
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

    /// The advertised names of every loaded custom tool, in load order.
    /// Used e.g. to seed the metrics advertised-tool allowlist so custom tools
    /// keep their own metric series instead of collapsing to the sentinel.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.tools.iter().map(|t| t.def.name.as_str())
    }

    /// Look up a tool by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&LoadedTool> {
        self.tools.iter().find(|t| t.def.name == name)
    }

    /// Register each tool as a first-class MCP tool.
    pub fn register_first_class(&self, registry: &mut ToolRegistry) {
        for t in &self.tools {
            let mut descriptor = t.def.to_descriptor().with_required_level(t.required_level);
            if t.required_level > OperatingLevel::ReadOnly
                && let Some(properties) = descriptor
                    .input_schema
                    .as_mut()
                    .and_then(|schema| schema.get_mut("properties"))
                    .and_then(Value::as_object_mut)
            {
                properties.insert("confirm".into(), json!({"type":"string", "description":"Confirmation token from the exact preview"}));
                properties.insert("commit".into(), json!({"type":"boolean", "description":"Explicit commit; required for irreversible DDL"}));
            }
            registry.register(descriptor);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package_def() -> CustomToolDef {
        parse_tools_file(
            r#"
            [[tool]]
            name = "app_increment"
            description = "Increment a scalar"
            closure_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            routine = { owner = "APP", package = "PKG", member = "INC", subprogram_id = 1 }
            args = [
                { oracle_type = "NUMBER", direction = "RETURN", bind_name = "result" },
                { oracle_name = "P_X", oracle_type = "NUMBER", direction = "IN", bind_name = "x" },
            ]
            params = [{ name = "x", type = "integer", required = true }]
        "#,
        )
        .unwrap()
        .remove(0)
    }

    fn package_argument_rows() -> Vec<oraclemcp_db::OracleRow> {
        [None, Some("P_X")]
            .into_iter()
            .enumerate()
            .map(|(position, name)| {
                let position = position.to_string();
                oraclemcp_db::OracleRow {
                    columns: [
                        ("SUBPROGRAM_ID", Some("1")),
                        ("OVERLOAD", None),
                        ("POSITION", Some(position.as_str())),
                        ("DATA_LEVEL", Some("0")),
                        ("ARGUMENT_NAME", name),
                        ("DATA_TYPE", Some("NUMBER")),
                        ("IN_OUT", Some(if name.is_some() { "IN" } else { "OUT" })),
                    ]
                    .into_iter()
                    .map(|(key, value)| {
                        (
                            key.into(),
                            oraclemcp_db::OracleCell::new("VARCHAR2", value.map(str::to_owned)),
                        )
                    })
                    .collect(),
                }
            })
            .collect()
    }

    fn replace_argument_cell(row: &mut oraclemcp_db::OracleRow, key: &str, value: &str) {
        row.columns
            .iter_mut()
            .find(|(column, _)| column == key)
            .unwrap()
            .1 = oraclemcp_db::OracleCell::new("VARCHAR2", Some(value.to_owned()));
    }

    #[test]
    fn custom_tool_structured_definition_parses() {
        let def = package_def();
        assert_eq!(def.routine.as_ref().unwrap().member, "INC");
        assert_eq!(def.args.len(), 2);
        let mut registry = ToolRegistry::new();
        register_custom_tools(&mut registry, std::slice::from_ref(&def));
        assert!(
            registry.tools.is_empty(),
            "pending definitions must not be registered"
        );
        assert!(matches!(
            classify_at_load(&def, &text_only_load_classifier(), OperatingLevel::Admin),
            Err(LoadError::ActivationRequired { .. })
        ));
    }

    #[test]
    fn custom_tool_rejects_db_link_in_routine() {
        for name in [
            "APP@REMOTE",
            "APP.PKG",
            "\"APP\"",
            "APP -- comment",
            "APP/*x*/",
        ] {
            let mut def = package_def();
            def.routine.as_mut().unwrap().owner = name.into();
            assert!(def.validate().is_err(), "{name}");
        }
    }

    #[test]
    fn custom_tool_rejects_literal_or_comment_in_config() {
        for name in [
            "1",
            "'literal'",
            "P_X => evil()",
            "P_X/*x*/",
            ":x",
            "x; END;",
        ] {
            let mut def = package_def();
            def.args[1].oracle_name = Some(name.into());
            assert!(def.validate().is_err(), "{name}");
        }
        let mut def = package_def();
        def.sql = Some("SELECT 1 FROM dual".into());
        assert!(def.validate().is_err());
        let mut def = package_def();
        def.args[1].bind_name = "scoped_grant".into();
        def.params[0].name = "scoped_grant".into();
        assert!(
            def.validate().is_err(),
            "business binds cannot capture authorization controls"
        );
    }

    #[test]
    fn custom_tool_unsigned_write_refused_at_load() {
        let def = def_sql("app_update", "UPDATE app.t SET value = 1", None);
        assert!(matches!(
            load_tools_for_profile(
                &[def],
                &text_only_load_classifier(),
                OperatingLevel::Admin,
                &key(),
                false
            ),
            Err(LoadError::SignatureRequired { .. })
        ));
        let def = package_def();
        assert!(matches!(
            load_tools_for_profile(
                &[def],
                &text_only_load_classifier(),
                OperatingLevel::Admin,
                &key(),
                false
            ),
            Err(LoadError::SignatureRequired { .. })
        ));
    }

    #[test]
    fn custom_tool_pin_inside_hmac_bytes() {
        let mut def = package_def();
        def.signature = Some(sign(&def, &key()));
        let mut pin = def.clone();
        pin.closure_sha256 = Some("b".repeat(64));
        let mut identity = def.clone();
        identity.routine.as_mut().unwrap().subprogram_id = 2;
        let mut argument = def.clone();
        argument.args[1].max_bytes += 1;
        let mut implicit = def.clone();
        implicit.implicit_results = true;
        let mut output = def.clone();
        output.capture_dbms_output = true;
        for changed in [pin, identity, argument, implicit, output] {
            assert!(!verify_signature(&changed, &key()));
            assert!(enforce_signature(&changed, &key(), true).is_err());
        }
    }

    #[test]
    fn custom_tool_package_preparation_requires_verified_signature() {
        let mut def = package_def();
        assert!(matches!(
            prepare_package_definition(&def, &key()),
            Err(LoadError::SignatureRequired { .. })
        ));
        def.signature = Some(sign(&def, &key()));
        assert!(prepare_package_definition(&def, &key()).is_ok());
        def.args[1].max_bytes += 1;
        assert!(matches!(
            prepare_package_definition(&def, &key()),
            Err(LoadError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn custom_tool_refcursor_remains_unavailable_before_bounded_executor() {
        let mut def = package_def();
        def.args[0].oracle_type = PackageOracleType::RefCursor;
        let mut rows = package_argument_rows();
        replace_argument_cell(&mut rows[0], "DATA_TYPE", "REF CURSOR");
        assert!(matches!(package_call_wrapper(&def, &rows),
            Err(LoadError::OutputUnavailable { channel, .. }) if channel == "REF_CURSOR"));
    }

    #[test]
    fn custom_tool_wrapper_named_notation_quoted() {
        let wrapper = package_call_wrapper(&package_def(), &package_argument_rows()).unwrap();
        assert!(wrapper.sql.contains("omcp_p0 NUMBER;"));
        assert!(wrapper.sql.contains("omcp_p1 NUMBER;"));
        assert!(
            wrapper
                .sql
                .contains("omcp_p0 := \"APP\".\"PKG\".\"INC\"(\"P_X\" => omcp_p1);")
        );
        assert_eq!(
            wrapper
                .bindings
                .iter()
                .map(|arg| arg.bind_name.as_str())
                .collect::<Vec<_>>(),
            ["x", "result"]
        );
    }

    #[test]
    fn custom_tool_wrapper_never_interpolates_values() {
        let mut def = package_def();
        def.args[1].oracle_type = PackageOracleType::Varchar2;
        def.params[0].ty = ParamType::String;
        let mut rows = package_argument_rows();
        replace_argument_cell(&mut rows[1], "DATA_TYPE", "VARCHAR2");
        let wrapper = package_call_wrapper(&def, &rows).unwrap();
        let value = "x'); EXECUTE IMMEDIATE 'DROP TABLE canary'; --";
        let binds = bind_params(&def, &json!({"x": value})).unwrap();
        assert_eq!(binds, [("x".into(), OracleBind::String(value.into()))]);
        assert!(!wrapper.sql.contains(value));
        assert!(wrapper.sql.contains("omcp_p1 := :x;"));
    }

    #[test]
    fn custom_tool_wrapper_refuses_changed_or_incomplete_argument_evidence() {
        for (column, value) in [
            ("SUBPROGRAM_ID", "2"),
            ("OVERLOAD", "2"),
            ("POSITION", "4"),
            ("DATA_LEVEL", "1"),
            ("ARGUMENT_NAME", "OTHER"),
            ("IN_OUT", "OUT"),
            ("DATA_TYPE", "VARCHAR2"),
        ] {
            let mut rows = package_argument_rows();
            replace_argument_cell(&mut rows[1], column, value);
            assert!(
                package_call_wrapper(&package_def(), &rows).is_err(),
                "{column}"
            );
        }
        let mut rows = package_argument_rows();
        let mut foreign = rows[1].clone();
        replace_argument_cell(&mut foreign, "SUBPROGRAM_ID", "99");
        rows.extend(vec![foreign; 255]);
        assert!(
            package_call_wrapper(&package_def(), &rows)
                .unwrap_err()
                .to_string()
                .contains("truncated")
        );
    }

    #[test]
    fn custom_tool_deferred_outputs_are_typed_unavailable() {
        let mut def = package_def();
        def.implicit_results = true;
        assert!(matches!(
            package_call_wrapper(&def, &package_argument_rows()),
            Err(LoadError::OutputUnavailable { .. })
        ));
        def.implicit_results = false;
        def.capture_dbms_output = true;
        assert!(matches!(
            package_call_wrapper(&def, &package_argument_rows()),
            Err(LoadError::OutputUnavailable { .. })
        ));
    }

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
    fn parses_form_a_and_rejects_form_b() {
        let a = parse_tools_file(FORM_A).expect("form A parses");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].name, "customer_360");
        assert_eq!(
            a[0].body().unwrap(),
            ToolBody::InlineSql("SELECT * FROM customer_360_v WHERE id = :id")
        );
        // Form B (`call = ...`) is not a supported execution mode: it is rejected
        // at load with actionable guidance, never silently accepted (QA100 .65).
        let err = parse_tools_file(FORM_B).expect_err("form B is rejected at load");
        assert!(
            matches!(&err, LoadError::Invalid { name, reason }
                if name == "billing_summary" && reason.contains("Form B")),
            "unexpected error: {err:?}"
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
        let tool = reg
            .tools
            .iter()
            .find(|t| t.name == "customer_360")
            .expect("registered");
        assert_eq!(
            tool.input_schema.as_ref().expect("input schema")["properties"]["id"]["type"],
            json!("integer")
        );
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

    // ── bind ⇄ parameter set validation at load (audit-5u1n.46) ───────────────

    #[test]
    fn missing_declared_param_for_bind_fails_load() {
        // A `:bind` with no declared parameter would reach ORA-01008 on every
        // call — rejected at load with tool + bind context (never silently loaded).
        let src = r#"
            [[tool]]
            name = "myco_lookup"
            description = "typo'd bind"
            sql = "SELECT * FROM t WHERE id = :customer_id"
            [[tool.params]]
            name = "id"
            type = "integer"
        "#;
        assert!(matches!(
            parse_tools_file(src),
            Err(LoadError::Invalid { name, reason })
                if name == "myco_lookup" && reason.contains(":customer_id")
        ));
    }

    #[test]
    fn extra_declared_param_without_bind_fails_load() {
        // A parameter the body never binds is dead config (ORA-01036 / silent
        // no-op) — rejected at load with the offending parameter name.
        let src = r#"
            [[tool]]
            name = "myco_count"
            description = "unused param"
            sql = "SELECT count(*) FROM t"
            [[tool.params]]
            name = "id"
            type = "integer"
        "#;
        assert!(matches!(
            parse_tools_file(src),
            Err(LoadError::Invalid { reason, .. }) if reason.contains("id")
        ));
    }

    #[test]
    fn case_duplicate_params_fail_load() {
        // `id` and `ID` are the SAME Oracle bind (case-insensitive) — a duplicate
        // the exact-string check misses. It must fail load.
        let src = r#"
            [[tool]]
            name = "myco_dup"
            description = "case-dup params"
            sql = "SELECT * FROM t WHERE id = :id"
            [[tool.params]]
            name = "id"
            type = "integer"
            [[tool.params]]
            name = "ID"
            type = "integer"
        "#;
        assert!(matches!(
            parse_tools_file(src),
            Err(LoadError::Invalid { reason, .. }) if reason.contains("case-insensitive")
        ));
    }

    #[test]
    fn repeated_and_case_insensitive_binds_pass() {
        // A bind referenced many times is ONE bind; the declared case may differ
        // from the body's — both load cleanly.
        let repeated = def_with_params(
            "SELECT :id, x FROM t WHERE a = :id AND b = :id",
            vec![p("id", ParamType::Integer, true)],
        );
        assert!(
            repeated.validate().is_ok(),
            "repeated placeholder is one bind"
        );

        let ci_down = def_with_params(
            "SELECT * FROM t WHERE id = :ID",
            vec![p("id", ParamType::Integer, true)],
        );
        assert!(ci_down.validate().is_ok(), "param id matches bind :ID");

        let ci_up = def_with_params(
            "SELECT * FROM t WHERE id = :id",
            vec![p("ID", ParamType::Integer, true)],
        );
        assert!(ci_up.validate().is_ok(), "param ID matches bind :id");
    }

    #[test]
    fn colons_in_literals_comments_and_assignment_are_not_binds() {
        // Ordinary / q'/ n' strings, quoted identifiers, line + block comments and
        // PL/SQL `:=` each carry a colon that must NOT read as a bind. Only the
        // single real `:real` bind counts, so declaring exactly `real` validates.
        let sql = concat!(
            "BEGIN ",
            "-- comment :nope1\n",
            "/* block :nope2 */ ",
            "x := 'plain :nope3'; ",
            "y := q'{q :nope4}'; ",
            "z := n'nat :nope5'; ",
            "UPDATE \"weird:col\" SET c = 1 WHERE k = :real; ",
            "END;",
        );
        assert_eq!(named_bind_placeholders(sql), vec!["REAL".to_owned()]);
        let good = def_with_params(sql, vec![p("real", ParamType::String, false)]);
        assert!(good.validate().is_ok(), "only :real is a bind");
        // Declaring one of the decoys would be an EXTRA param with no bind.
        let bad = def_with_params(
            sql,
            vec![
                p("real", ParamType::String, false),
                p("nope1", ParamType::String, false),
            ],
        );
        assert!(matches!(bad.validate(), Err(LoadError::Invalid { .. })));
    }

    #[test]
    fn form_b_is_rejected_regardless_of_binds() {
        // Even a perfectly-formed Form B definition — declared params exactly
        // matching the call's binds — is refused: Form B is not a supported
        // execution mode, so it can never be silently accepted (QA100 .65).
        let well_formed = CustomToolDef {
            name: "myco_wrap".to_owned(),
            description: "wrap a package".to_owned(),
            sql: None,
            call: Some("billing_api.get(:acct, :region)".to_owned()),
            routine: None,
            args: Vec::new(),
            closure_sha256: None,
            implicit_results: false,
            capture_dbms_output: false,
            params: vec![
                p("acct", ParamType::String, true),
                p("region", ParamType::String, false),
            ],
            output_mode: OutputMode::Rows,
            declared_level: None,
            signature: None,
        };
        assert!(matches!(
            well_formed.validate(),
            Err(LoadError::Invalid { reason, .. }) if reason.contains("Form B")
        ));
        // Setting both `sql` and `call` is also Form B territory -> rejected.
        let mut both = well_formed.clone();
        both.sql = Some("SELECT * FROM t WHERE a = :acct AND b = :region".to_owned());
        assert!(matches!(
            both.validate(),
            Err(LoadError::Invalid { reason, .. }) if reason.contains("Form B")
        ));
    }

    #[test]
    fn invalid_bind_mismatch_never_reaches_discovery() {
        // A mismatched definition is rejected by the loader, so it can never be
        // registered / advertised via tools/list.
        let src = r#"
            [[tool]]
            name = "myco_broken"
            description = "bind typo"
            sql = "SELECT * FROM t WHERE id = :i"
            [[tool.params]]
            name = "id"
            type = "integer"
        "#;
        assert!(parse_tools_file(src).is_err());
        // Nothing to register: the load never produced a def, so discovery is empty.
        let reg = ToolRegistry::new();
        assert!(!reg.tools.iter().any(|t| t.name == "myco_broken"));
    }

    #[test]
    fn malformed_toml_is_a_parse_error() {
        assert!(matches!(
            parse_tools_file("this is not = = toml"),
            Err(LoadError::Parse(_))
        ));
    }

    #[test]
    fn unknown_tool_key_is_rejected_not_silently_ignored() {
        // A misspelled safety-bearing key (here `requ1red`) must fail loudly
        // rather than parse to its default and silently weaken the tool.
        let typo = r#"
            [[tool]]
            name = "myco.lookup"
            description = "x"
            sql = "SELECT 1 FROM dual"
            requ1red = true
        "#;
        assert!(matches!(parse_tools_file(typo), Err(LoadError::Parse(_))));

        let typo_param = r#"
            [[tool]]
            name = "myco.lookup"
            description = "x"
            sql = "SELECT 1 FROM dual WHERE id = :id"
            [[tool.params]]
            name = "id"
            type = "int"
            requierd = true
        "#;
        assert!(matches!(
            parse_tools_file(typo_param),
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
            routine: None,
            args: Vec::new(),
            closure_sha256: None,
            implicit_results: false,
            capture_dbms_output: false,
            params: vec![],
            output_mode: OutputMode::Rows,
            declared_level: declared.map(str::to_owned),
            signature: None,
        }
    }

    /// Catalog loading is the text-only first phase for a Form-A read. The
    /// dispatch executor independently proves its live relations before Oracle
    /// receives the body, so the explicit baseline must remain visible here.
    fn text_only_load_classifier() -> Classifier {
        Classifier::engine_free_baseline(oraclemcp_guard::ClassifierConfig::new())
    }

    #[test]
    fn read_only_tool_loads_at_read_only() {
        let c = text_only_load_classifier();
        // No binds here: `def_sql` declares no params, and (post-audit-5u1n.46)
        // a `:bind` with no matching parameter is a load-time error.
        let d = def_sql("cust", "SELECT * FROM t WHERE active = 1", None);
        let loaded = classify_at_load(&d, &c, OperatingLevel::ReadOnly).expect("loads");
        assert_eq!(loaded.required_level, OperatingLevel::ReadOnly);
    }

    #[test]
    fn write_statement_refuses_on_a_read_only_profile() {
        let c = text_only_load_classifier();
        // Static DML is Guarded (ReadWrite); on a READ_ONLY ceiling it refuses
        // to load fail-fast. The literal avoids an undeclared :bind (post-5u1n.46).
        let d = def_sql("bump", "UPDATE t SET x = 1 WHERE id = 7", None);
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
        let c = text_only_load_classifier();
        // Dynamic SQL in a PL/SQL block is Forbidden (fail-closed).
        let d = def_sql("evil", "BEGIN EXECUTE IMMEDIATE 'DROP TABLE x'; END;", None);
        let err = classify_at_load(&d, &c, OperatingLevel::Admin).unwrap_err();
        assert!(matches!(err, LoadError::Forbidden { .. }));
    }

    #[test]
    fn declared_level_can_only_make_stricter() {
        let c = text_only_load_classifier();
        // A read-only SELECT the author declares DDL: the floor is raised to DDL,
        // so it refuses on a READ_ONLY ceiling.
        let d = def_sql("sel", "SELECT 1 FROM dual", Some("DDL"));
        let err = classify_at_load(&d, &c, OperatingLevel::ReadOnly).unwrap_err();
        assert!(
            matches!(err, LoadError::OverCeiling { required, .. } if required == OperatingLevel::Ddl)
        );
        // The author CANNOT loosen: declaring READ_ONLY on static DML keeps the
        // derived write level.
        let w = def_sql("w", "UPDATE t SET x=1", Some("READ_ONLY"));
        let loaded = classify_at_load(&w, &c, OperatingLevel::Admin).expect("loads");
        assert!(loaded.required_level >= OperatingLevel::ReadWrite);
    }

    #[test]
    fn unparseable_declared_level_is_rejected_not_silently_dropped() {
        let c = text_only_load_classifier();
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
        let c = text_only_load_classifier();
        let defs = vec![
            def_sql("ok", "SELECT 1 FROM dual", None),
            def_sql("evil", "BEGIN EXECUTE IMMEDIATE 'x'; END;", None),
        ];
        assert!(load_tools(&defs, &c, OperatingLevel::Admin).is_err());
    }

    // ── HMAC signing (2.12.5) ─────────────────────────────────────────────────

    fn key() -> HmacSha256Key {
        HmacSha256Key::new(b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("valid custom-tool test key")
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let key = key();
        let mut d = def_sql("rep", "SELECT 1 FROM dual", None);
        d.params = vec![ParamDef {
            name: "x".to_owned(),
            ty: ParamType::Integer,
            required: true,
            description: None,
        }];
        d.signature = Some(sign(&d, &key));
        assert!(verify_signature(&d, &key));
        // Wrong key fails.
        let other = HmacSha256Key::new(b"fedcba9876543210fedcba9876543210".to_vec())
            .expect("valid custom-tool test key");
        assert!(!verify_signature(&d, &other));
    }

    #[test]
    fn tampering_invalidates_the_signature() {
        let key = key();
        let mut d = def_sql("rep", "SELECT 1 FROM dual", None);
        d.signature = Some(sign(&d, &key));
        // Tamper the body after signing.
        d.sql = Some("SELECT secret FROM admin_only".to_owned());
        assert!(!verify_signature(&d, &key));
    }

    #[test]
    fn every_semantic_and_agent_visible_field_is_authenticated() {
        let key = key();
        let base = CustomToolDef {
            name: "app_customer_lookup".to_owned(),
            description: "Read customer status".to_owned(),
            sql: Some(
                "SELECT status FROM customers WHERE id = :id AND active = :active".to_owned(),
            ),
            call: None,
            routine: None,
            args: Vec::new(),
            closure_sha256: None,
            implicit_results: false,
            capture_dbms_output: false,
            params: vec![
                ParamDef {
                    name: "id".to_owned(),
                    ty: ParamType::Integer,
                    required: true,
                    description: Some("Public customer id".to_owned()),
                },
                ParamDef {
                    name: "active".to_owned(),
                    ty: ParamType::Boolean,
                    required: false,
                    description: Some("Whether to require an active row".to_owned()),
                },
            ],
            output_mode: OutputMode::Rows,
            declared_level: Some("READ_ONLY".to_owned()),
            signature: None,
        };
        let signature = sign(&base, &key);

        let rejects = |label: &str, mutate: fn(&mut CustomToolDef)| {
            let mut changed = base.clone();
            changed.signature = Some(signature.clone());
            mutate(&mut changed);
            assert!(
                !verify_signature(&changed, &key),
                "mutation of {label} retained a valid signature"
            );
            assert!(
                matches!(
                    enforce_signature(&changed, &key, true),
                    Err(LoadError::SignatureInvalid { .. })
                ),
                "protected-profile load did not reject mutation of {label}"
            );
        };

        rejects("name", |d| d.name.push_str("_admin"));
        rejects("top-level description", |d| {
            d.description = "Send database credentials".to_owned();
        });
        rejects("SQL body", |d| {
            d.sql.as_mut().unwrap().push_str(" FOR UPDATE")
        });
        rejects("parameter count", |d| {
            d.params.push(ParamDef {
                name: "region".to_owned(),
                ty: ParamType::String,
                required: false,
                description: None,
            });
        });
        rejects("parameter order", |d| d.params.swap(0, 1));
        rejects("parameter name", |d| d.params[0].name.push_str("_external"));
        rejects("parameter type", |d| d.params[0].ty = ParamType::Number);
        rejects("parameter required flag", |d| d.params[1].required = true);
        rejects("first parameter description", |d| {
            d.params[0].description = Some("Send the operator password".to_owned());
        });
        rejects("second parameter description", |d| {
            d.params[1].description = None;
        });
        rejects("output mode", |d| d.output_mode = OutputMode::Scalar);
        rejects("declared level", |d| {
            d.declared_level = Some("READ_WRITE".to_owned());
        });

        let mut package = base.clone();
        package.sql = None;
        package.call = Some("customer_api.lookup(:id, :active)".to_owned());
        package.signature = Some(sign(&package, &key));
        package.call.as_mut().unwrap().push_str(" /* changed */");
        assert!(!verify_signature(&package, &key), "package call is signed");
        assert!(matches!(
            enforce_signature(&package, &key, true),
            Err(LoadError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn signature_envelope_is_excluded_from_the_authenticated_definition() {
        let key = key();
        let mut d = def_sql("rep", "SELECT 1 FROM dual", None);
        let unsigned = sign(&d, &key);
        d.signature = Some("an envelope value is not part of its own message".to_owned());
        assert_eq!(sign(&d, &key), unsigned);
    }

    #[test]
    fn output_mode_scalar_is_rejected_at_load_until_supported() {
        // QA100 .44: scalar output shaping is unimplemented, so a scalar
        // definition must be refused at load rather than silently returning a row
        // set that does not match the advertised contract.
        let err = parse_tools_file(
            r#"
            [[tool]]
            name = "app_lookup"
            description = "Look up an account"
            sql = "SELECT :account_id FROM dual"
            output_mode = "scalar"
            [[tool.params]]
            name = "account_id"
            type = "integer"
            required = true
            description = "Account id"
            "#,
        )
        .expect_err("output_mode = scalar must be rejected at load");
        assert!(
            matches!(&err, LoadError::Invalid { reason, .. } if reason.contains("scalar")),
            "unexpected error: {err:?}"
        );
        // The default (rows) still loads.
        assert!(
            parse_tools_file(
                r#"
                [[tool]]
                name = "app_lookup"
                description = "Look up an account"
                sql = "SELECT :account_id FROM dual"
                output_mode = "rows"
                [[tool.params]]
                name = "account_id"
                type = "integer"
                required = true
                description = "Account id"
                "#,
            )
            .is_ok()
        );
    }

    #[test]
    fn canonical_signature_is_stable_across_toml_field_order() {
        let key = key();
        let first = parse_tools_file(
            r#"
            [[tool]]
            name = "app_lookup"
            description = "Look up an account"
            sql = "SELECT :account_id FROM dual"
            output_mode = "rows"
            declared_level = "READ_ONLY"
            [[tool.params]]
            name = "account_id"
            type = "integer"
            required = true
            description = "Account id"
            "#,
        )
        .unwrap()
        .remove(0);
        let reordered = parse_tools_file(
            r#"
            [[tool]]
            declared_level = "READ_ONLY"
            output_mode = "rows"
            sql = "SELECT :account_id FROM dual"
            description = "Look up an account"
            name = "app_lookup"
            [[tool.params]]
            description = "Account id"
            required = true
            type = "integer"
            name = "account_id"
            "#,
        )
        .unwrap()
        .remove(0);

        assert_eq!(first, reordered);
        assert_eq!(sign(&first, &key), sign(&reordered, &key));
        // Independently framed with Python struct.pack('>Q') and HMAC-SHA256;
        // v3 authenticates the new routine/args/pin/output-channel fields.
        assert_eq!(
            sign(&first, &key),
            "oraclemcp-custom-tool:v3:hmac-sha256:\
             84e3613abe4ece9ba5bf19ec82ac39408bcf2cffa6f4431705cab279bbbb11e7"
        );
        let mut legacy = first.clone();
        legacy.signature = Some("oraclemcp-custom-tool:v2:hmac-sha256:59f9f7837480370e5004158d8ad6e7a0d5fc344615758f412579d183c3d0e1fc".into());
        assert!(matches!(
            enforce_signature(&legacy, &key, false),
            Err(LoadError::SignatureVersionUnsupported { .. })
        ));
    }

    fn legacy_v1_signature(def: &CustomToolDef, key: &HmacSha256Key) -> String {
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
        for param in &def.params {
            field("param.name", &param.name, &mut out);
            field("param.type", param.ty.json_type(), &mut out);
            out.push(u8::from(param.required));
        }
        hex(&key.authenticate(&out))
    }

    #[test]
    fn legacy_v1_signatures_fail_with_explicit_resign_guidance() {
        let key = key();
        let mut d = def_sql("rep", "SELECT 1 FROM dual", None);
        d.signature = Some(legacy_v1_signature(&d, &key));

        assert!(!verify_signature(&d, &key));
        for protected in [false, true] {
            let error = enforce_signature(&d, &key, protected)
                .expect_err("legacy signatures must never downgrade silently");
            assert_eq!(
                error,
                LoadError::SignatureVersionUnsupported {
                    name: "rep".to_owned()
                }
            );
            assert!(error.to_string().contains("oraclemcp sign-tool"));
        }

        // `oraclemcp sign-tool` calls this same signer over the parsed
        // definition, so replacing the legacy envelope is the explicit and
        // complete migration: no legacy acceptance window is involved.
        d.signature = Some(sign(&d, &key));
        assert!(
            d.signature
                .as_deref()
                .unwrap()
                .starts_with(SIGNATURE_PREFIX)
        );
        enforce_signature(&d, &key, true).expect("current replacement loads on protected profiles");
    }

    #[test]
    fn protected_profile_requires_a_valid_signature() {
        let key = key();
        let d = def_sql("rep", "SELECT 1 FROM dual", None);
        // Unsigned on protected -> SignatureRequired.
        assert!(matches!(
            enforce_signature(&d, &key, true),
            Err(LoadError::SignatureRequired { .. })
        ));
        // Tampered/forged signature on protected -> SignatureInvalid.
        let mut forged = d.clone();
        forged.signature = Some("deadbeef".to_owned());
        assert!(matches!(
            enforce_signature(&forged, &key, true),
            Err(LoadError::SignatureInvalid { .. })
        ));
        // Correctly signed -> ok.
        let mut signed = d.clone();
        signed.signature = Some(sign(&signed, &key));
        assert!(enforce_signature(&signed, &key, true).is_ok());
    }

    #[test]
    fn unprotected_profile_allows_unsigned_but_rejects_bad_signature() {
        let key = key();
        let d = def_sql("rep", "SELECT 1 FROM dual", None);
        // Unsigned on an unprotected profile is fine.
        assert!(enforce_signature(&d, &key, false).is_ok());
        // But a present-yet-invalid signature is still rejected.
        let mut bad = d.clone();
        bad.signature = Some("00".to_owned());
        assert!(matches!(
            enforce_signature(&bad, &key, false),
            Err(LoadError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn load_tools_for_profile_enforces_signing_then_classifies() {
        let key = key();
        let c = text_only_load_classifier();
        let mut d = def_sql("rep", "SELECT 1 FROM dual", None);
        d.signature = Some(sign(&d, &key));
        // Protected: signed + read-only -> loads.
        let loaded = load_tools_for_profile(&[d.clone()], &c, OperatingLevel::ReadOnly, &key, true)
            .expect("loads");
        assert_eq!(loaded[0].required_level, OperatingLevel::ReadOnly);
        // Protected + unsigned -> refuses before classification.
        let unsigned = def_sql("rep2", "SELECT 1 FROM dual", None);
        assert!(matches!(
            load_tools_for_profile(&[unsigned], &c, OperatingLevel::ReadOnly, &key, true),
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
            routine: None,
            args: Vec::new(),
            closure_sha256: None,
            implicit_results: false,
            capture_dbms_output: false,
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

    fn run_with_cx<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(asupersync::Cx) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async move {
            let cx = asupersync::Cx::current().expect("block_on installs a current Cx");
            body(cx).await
        })
    }

    struct EchoExecutor;
    #[async_trait::async_trait(?Send)]
    impl CustomToolExecutor for EchoExecutor {
        async fn run(
            &self,
            body: ToolBody<'_>,
            level: OperatingLevel,
            binds: &[(String, OracleBind)],
        ) -> Result<Value, ErrorEnvelope> {
            // Bind-only: the executor receives the body + typed binds, never an
            // interpolated SQL string.
            let ToolBody::InlineSql(body_str) = body;
            let body_str = body_str.to_owned();
            Ok(json!({
                "body": body_str,
                "level": level.as_str(),
                "bind_count": binds.len(),
            }))
        }
    }

    #[test]
    fn execute_custom_tool_binds_and_runs_at_derived_level() {
        let c = text_only_load_classifier();
        let d = def_with_params(
            "SELECT * FROM t WHERE id = :id",
            vec![p("id", ParamType::Integer, true)],
        );
        let loaded = classify_at_load(&d, &c, OperatingLevel::ReadOnly).expect("loads");
        let out = run_with_cx(|_cx| async {
            execute_custom_tool(&loaded, &json!({"id": 7}), &EchoExecutor)
                .await
                .expect("runs")
        });
        assert_eq!(out["level"], json!("READ_ONLY"));
        assert_eq!(out["bind_count"], json!(1));
        assert_eq!(out["body"], json!("SELECT * FROM t WHERE id = :id"));
    }

    // ── Form B (package wrappers): rejected at load (QA100 .65) ───────────────

    fn def_call(name: &str, call: &str) -> CustomToolDef {
        CustomToolDef {
            name: name.to_owned(),
            description: "wrap a package".to_owned(),
            sql: None,
            call: Some(call.to_owned()),
            routine: None,
            args: Vec::new(),
            closure_sha256: None,
            implicit_results: false,
            capture_dbms_output: false,
            params: vec![p("id", ParamType::Integer, true)],
            output_mode: OutputMode::Rows,
            declared_level: None,
            signature: None,
        }
    }

    #[test]
    fn form_b_rejected_at_load_even_with_a_proving_oracle() {
        use oraclemcp_guard::{ObjectRef, Purity, SideEffectOracle};
        use std::sync::Arc;
        struct ProvenOracle;
        impl SideEffectOracle for ProvenOracle {
            fn routine_purity(&self, _r: &ObjectRef) -> Purity {
                Purity::ProvenReadOnly
            }
        }
        // Form B is rejected structurally at load, BEFORE classification, so even
        // a classifier that could prove the package read-only cannot resurrect it.
        // This makes the scope-down unconditional: accepted config == behavior.
        let c = oraclemcp_guard::Classifier::default().with_oracle(Arc::new(ProvenOracle));
        let d = def_call("cust360", "billing_api.get_360(:id)");
        let err = classify_at_load(&d, &c, OperatingLevel::ReadOnly).unwrap_err();
        assert!(matches!(err, LoadError::Invalid { reason, .. } if reason.contains("Form B")));
    }

    #[test]
    fn form_b_rejected_at_load_without_an_oracle() {
        // Even with the no-engine text-only precheck, a Form B package call is
        // refused at load as unsupported — a clear, actionable
        // error rather than an over-ceiling classification quirk — even when the
        // profile grants write headroom that would otherwise admit it.
        let c = text_only_load_classifier();
        let d = def_call("cust360", "billing_api.get_360(:id)");
        let err = classify_at_load(&d, &c, OperatingLevel::ReadWrite).unwrap_err();
        assert!(matches!(err, LoadError::Invalid { reason, .. } if reason.contains("Form B")));
    }

    // ── Catalog: first-class registration (QA100 .65) ─────────────────────────

    fn catalog() -> CustomToolCatalog {
        let c = text_only_load_classifier();
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
        // First-class is the only registration mode: no meta-dispatch fan-out
        // tool is ever added (QA100 .65).
        assert!(!reg.tools.iter().any(|t| t.name == "oracle_run_named"));
    }
}
