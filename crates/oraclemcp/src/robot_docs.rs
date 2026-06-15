//! Static onboarding payloads for the `oraclemcp` binary: the agent-facing
//! `robot-docs guide` (JSON + text) and the generic `setup` templates.
//!
//! Pure data, no I/O. Split out of `main.rs` so the CLI flow there stays small;
//! the `json!` macros are compile-time checked exactly as before.

pub(crate) fn setup_profiles_template(profile: &str, credential_env: &str) -> String {
    format!(
        r#"schema_version = 1
default_profile = "{profile}"

[[profiles]]
name = "{profile}"
description = "Read-only database profile"
connect_string = "dbhost.example.com:1521/service_name"
username = "APP_READONLY"
credential_ref = "env:{credential_env}"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
protected = true
require_signed_tools = true
call_timeout_seconds = 30
login_statements = [
  "ALTER SESSION SET NLS_LANGUAGE = english",
]

[profiles.session_identity]
module = "oraclemcp"
action = "inspect"
client_identifier = "agent"
client_info = "local-agent"
driver_name = "oraclemcp"

[[profiles]]
name = "db_ddl"
description = "DDL-capable sandbox; never point this at production"
base = "{profile}"
protected = false
max_level = "DDL"
default_level = "READ_ONLY"
require_signed_tools = true
"#
    )
}

pub(crate) fn setup_wrapper_template() -> &'static str {
    r#"#!/usr/bin/env sh
set -eu

ORACLE_NET_HOME="${ORACLE_NET_HOME:-$HOME/.config/oraclemcp/network}"

if [ -d "$ORACLE_NET_HOME" ]; then
  export TNS_ADMIN="${TNS_ADMIN:-$ORACLE_NET_HOME}"
fi

exec oraclemcp "$@"
"#
}

pub(crate) fn setup_custom_tool_template() -> &'static str {
    r#"[[tool]]
name = "app_customer_lookup"
description = "Lookup customer rows by id"
sql = "SELECT id, name, status FROM app_customers WHERE id = :id"
output_mode = "rows"
# signature = "add with: oraclemcp sign-tool ~/.config/oraclemcp/tools.d/customer.toml --tool app_customer_lookup"

[[tool.params]]
name = "id"
type = "integer"
required = true
description = "Customer id"
"#
}

pub(crate) fn robot_docs_guide_json() -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "guide_version": 1,
        "binary": "oraclemcp",
        "structured_output": {
            "flag": "--robot-json",
            "alias": "--json",
            "contract": "stdout is compact JSON; diagnostics go to stderr"
        },
        "tool_schema_contract": {
            "top_level": "every advertised MCP tool input schema is a JSON object",
            "strict_client_safe": "tool parameter schemas avoid top-level oneOf, anyOf, allOf, enum, and not"
        },
        "client_setup": {
            "principle": "install or build one oraclemcp binary, then configure each MCP client to call the same command, args, config file, and environment",
            "stdio": {
                "command": "oraclemcp",
                "args": ["serve", "--profile", "<profile>", "--allow-no-auth"],
                "argv": ["oraclemcp", "serve", "--profile", "<profile>", "--allow-no-auth"],
                "notes": [
                    "Use --allow-no-auth only for local stdio clients you already trust.",
                    "The thin driver does not need Oracle Instant Client; if Oracle Net files need TNS_ADMIN, point every MCP client at the same small wrapper script."
                ]
            },
            "secure_stdio": {
                "command": "oraclemcp",
                "args": ["serve", "--profile", "<profile>"],
                "env": {
                    "ORACLEMCP_STDIO_TOKEN": "<shared-init-token>"
                },
                "notes": [
                    "Use this when the MCP client can send the init token in initialize _meta.",
                    "If the client cannot send an init token, keep the server local and use --allow-no-auth intentionally."
                ]
            },
            "smoke_tests": [
                {
                    "intent": "generate generic local setup templates without reading private config",
                    "command": "oraclemcp --json setup --profile <profile>",
                    "argv": ["oraclemcp", "--json", "setup", "--profile", "<profile>"]
                },
                {
                    "intent": "verify the installed binary and local config without MCP",
                    "command": "oraclemcp --json doctor --profile <profile>",
                    "argv": ["oraclemcp", "--json", "doctor", "--profile", "<profile>"]
                },
                {
                    "intent": "verify the MCP client can import the tool list",
                    "mcp_method": "tools/list",
                    "expected": "the client discovers oracle_capabilities plus the advertised Oracle tools without schema import errors"
                },
                {
                    "intent": "verify a zero-arg MCP call works",
                    "mcp_tool": "oracle_capabilities",
                    "arguments": {}
                }
            ],
            "restart_rule": "after replacing the binary or wrapper, restart or reconnect each MCP client so it imports the fresh tool schema"
        },
        "first_commands": [
            {
                "intent": "print generic onboarding templates for profiles, wrappers, and MCP clients",
                "command": "oraclemcp --json setup --profile <profile>",
                "argv": ["oraclemcp", "--json", "setup", "--profile", "<profile>"]
            },
            {
                "intent": "discover configured profiles without opening a database connection",
                "command": "oraclemcp --json profiles",
                "argv": ["oraclemcp", "--json", "profiles"]
            },
            {
                "intent": "run offline diagnostics",
                "command": "oraclemcp --json doctor",
                "argv": ["oraclemcp", "--json", "doctor"]
            },
            {
                "intent": "run profile-backed diagnostics",
                "command": "oraclemcp --json doctor --profile <profile>",
                "argv": ["oraclemcp", "--json", "doctor", "--profile", "<profile>"]
            },
            {
                "intent": "inspect the MCP tool surface",
                "command": "oraclemcp --json capabilities",
                "argv": ["oraclemcp", "--json", "capabilities"]
            },
            {
                "intent": "start stdio MCP for a local agent",
                "command": "oraclemcp serve --profile <profile> --allow-no-auth",
                "argv": ["oraclemcp", "serve", "--profile", "<profile>", "--allow-no-auth"]
            }
        ],
        "mcp_workflows": [
            {
                "intent": "read data safely",
                "steps": [
                    "oracle_list_profiles",
                    "oracle_switch_profile if needed",
                    "oracle_preview_sql",
                    "oracle_query"
                ]
            },
            {
                "intent": "commit DML deliberately",
                "steps": [
                    "oracle_preview_sql",
                    "oracle_set_session_level when the preview asks for step-up",
                    "oracle_execute with commit=false for rollback preview",
                    "oracle_execute with commit=true and execute_confirmation.confirm only when committing"
                ]
            },
            {
                "intent": "apply DDL deliberately",
                "steps": [
                    "oracle_preview_sql or oracle_create_or_replace without execute=true",
                    "oracle_set_session_level with level=DDL when permitted",
                    "oracle_create_or_replace or oracle_execute with commit=true and the preview confirmation token"
                ]
            },
            {
                "intent": "patch stored source deliberately",
                "steps": [
                    "oracle_get_source or oracle_get_ddl to inspect the current object",
                    "oracle_patch_source with exact old_text/new_text and execute omitted",
                    "read_patch_preview when a compatibility client needs to re-read the last in-process patch preview",
                    "oracle_set_session_level with level=DDL when permitted",
                    "oracle_patch_source with execute=true and the preview confirmation token"
                ]
            }
        ],
        "safety_model": {
            "levels": ["READ_ONLY", "READ_WRITE", "DDL", "ADMIN"],
            "default_level": "READ_ONLY",
            "ceiling": "profile max_level is immutable for the running profile",
            "writes": "DML rolls back by default; commit requires a preview-derived confirmation token",
            "ddl_admin": "DDL and ADMIN statements require commit=true plus a confirmation token because Oracle cannot rollback-preview them"
        },
        "config": {
            "profiles": "~/.config/oraclemcp/profiles.toml or ORACLEMCP_CONFIG",
            "custom_tools": "~/.config/oraclemcp/tools.d/*.toml or ORACLEMCP_TOOLS_DIR",
            "custom_tool_signing": "protected profiles and profiles with require_signed_tools=true require ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY plus per-tool signatures from oraclemcp sign-tool",
            "secret_refs": "prefer credential_ref over literal passwords",
            "environment_specifics": "database aliases, session identity, client module/program labels, and custom workflow tools belong in profiles or tools.d config, not in the general core"
        },
        "thin_diagnostics": {
            "driver": "pure-Rust oracledb thin driver; no Oracle Instant Client, ODPI-C, libclntsh, or C toolchain required",
            "offline": "oraclemcp --json doctor checks thin-driver posture, TNS/wallet directory presence, NLS setup, classifier self-test, and custom-tool availability without opening a database",
            "profile": "oraclemcp --json doctor --profile <profile> adds live connectivity, authentication, role/open-mode, standby, and privilege-tier checks",
            "secret_handling": "doctor and profiles output omit connect strings, usernames, credential_ref values, passwords, IAM tokens, and wallet paths",
            "unsupported_auth": "published thin driver gaps such as external wallet auth, OCI IAM token auth, and edition selection are returned as structured unsupported diagnostics rather than falling back silently"
        },
        "diagnostic_flow": [
            {
                "intent": "binary and build posture",
                "argv": ["oraclemcp", "--json", "info"]
            },
            {
                "intent": "generic onboarding templates",
                "argv": ["oraclemcp", "--json", "setup", "--profile", "<profile>"]
            },
            {
                "intent": "profile inventory without connecting",
                "argv": ["oraclemcp", "--json", "profiles"]
            },
            {
                "intent": "offline checks",
                "argv": ["oraclemcp", "--json", "doctor"]
            },
            {
                "intent": "profile-backed checks",
                "argv": ["oraclemcp", "--json", "doctor", "--profile", "<profile>"]
            },
            {
                "intent": "MCP tool surface and schema inspection",
                "argv": ["oraclemcp", "--json", "capabilities"]
            }
        ],
        "agent_rules": [
            "Prefer oracle_query for SELECT/WITH statements.",
            "Use oracle_preview_sql before oracle_execute or DDL helpers.",
            "Use oracle_patch_source for exact stored-source edits instead of hand-building full replacement DDL when possible.",
            "Use read_patch_preview only for in-process compatibility reads of the last source-patch preview.",
            "deploy_ddl accepts name and wait_seconds for compatibility; the generic core executes synchronously and returns those fields.",
            "Treat confirmation tokens as process-local preview tokens; regenerate them after restarting the server.",
            "Never assume DDL can be rollback-previewed.",
            "Treat profile max_level as the hard ceiling for the running server.",
            "Keep environment-specific tools, names, identities, and connection details in config."
        ],
        "exit_codes": [
            { "code": 0, "meaning": "success" },
            { "code": 2, "meaning": "invalid arguments, config error, failed diagnostics, or startup safety block" }
        ]
    })
}

pub(crate) fn robot_docs_guide_text() -> &'static str {
    r#"oraclemcp robot-docs guide

Output contract
- Use --robot-json or --json for compact machine-readable stdout.
- Diagnostics and serve startup status are written to stderr.
- Read-only commands do not open a database unless their command explicitly says so.
- MCP tool parameter schemas are top-level JSON objects and avoid top-level oneOf, anyOf, allOf, enum, and not for strict client adapters.

Client setup
- Install or build one oraclemcp binary, then configure every MCP client to call the same command, args, config file, and environment.
- Generate generic setup templates with: oraclemcp --json setup --profile <profile>
- Local stdio command: oraclemcp serve --profile <profile> --allow-no-auth
- Secure stdio command: ORACLEMCP_STDIO_TOKEN=<token> oraclemcp serve --profile <profile>
- The thin driver does not need Oracle Instant Client, ODPI-C, libclntsh, or a C toolchain.
- If Oracle Net files need TNS_ADMIN, point every MCP client at the same small wrapper script.
- After replacing the binary or wrapper, restart or reconnect each MCP client so it imports the fresh tool schema.

Client smoke tests
1. oraclemcp --json setup --profile <profile>
2. oraclemcp --json doctor --profile <profile>
3. MCP tools/list discovers oracle_capabilities plus the advertised Oracle tools without schema import errors
4. MCP tools/call oracle_capabilities with empty arguments succeeds

First commands
- oraclemcp --json setup --profile <profile>
- oraclemcp --json profiles
- oraclemcp --json doctor
- oraclemcp --json doctor --profile <profile>
- oraclemcp --json capabilities
- oraclemcp serve --profile <profile> --allow-no-auth

MCP read workflow
1. oracle_list_profiles
2. oracle_switch_profile if the active profile is not the target profile
3. oracle_preview_sql to classify raw SQL before running it
4. oracle_query for proven read-only SELECT/WITH statements

MCP write workflow
1. oracle_preview_sql
2. oracle_set_session_level if the preview requires step-up and the profile ceiling permits it
3. oracle_execute with commit=false for rollback preview of DML
4. oracle_execute with commit=true and execute_confirmation.confirm only when committing

MCP DDL workflow
1. oracle_preview_sql or oracle_create_or_replace without execute=true
2. oracle_set_session_level with level=DDL when permitted by the profile ceiling
3. oracle_create_or_replace or oracle_execute with commit=true and the preview confirmation token

MCP source patch workflow
1. oracle_get_source or oracle_get_ddl to inspect the current object
2. oracle_patch_source with exact old_text/new_text and execute omitted
3. read_patch_preview when a compatibility client needs to re-read the last in-process patch preview
4. oracle_set_session_level with level=DDL when permitted by the profile ceiling
5. oracle_patch_source with execute=true and the preview confirmation token

Safety model
- Levels are ordered READ_ONLY < READ_WRITE < DDL < ADMIN.
- Profiles default to READ_ONLY and cannot be raised above max_level at runtime.
- DML rolls back by default.
- DDL and ADMIN require commit=true plus confirmation because Oracle cannot rollback-preview them.
- Confirmation tokens are process-local preview tokens; regenerate them after restarting the server.

Configuration
- Profiles: ~/.config/oraclemcp/profiles.toml or ORACLEMCP_CONFIG.
- Custom tools: ~/.config/oraclemcp/tools.d/*.toml or ORACLEMCP_TOOLS_DIR.
- Custom tool signing: protected profiles and profiles with require_signed_tools=true require ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY and signatures from oraclemcp sign-tool.
- Prefer credential_ref over literal passwords.
- Database aliases, session identity, client module/program labels, and custom workflow tools belong in profiles or tools.d config, not in the general core.

Diagnostic flow
1. oraclemcp --json info
2. oraclemcp --json setup --profile <profile>
3. oraclemcp --json profiles
4. oraclemcp --json doctor
5. oraclemcp --json doctor --profile <profile>
6. oraclemcp --json capabilities

Thin diagnostics
- Offline doctor checks the thin driver posture, optional TNS/wallet directories, canonical NLS setup, classifier self-test, and custom-tool availability without opening a database.
- Profile doctor adds live connectivity, authentication, role/open-mode, standby, and privilege-tier checks.
- Doctor output omits connect strings, usernames, credential_ref values, passwords, IAM tokens, and wallet paths.
- Unsupported thin auth/features are explicit diagnostics; the binary never silently falls back to thick mode.

Agent rules
- Prefer oracle_query for SELECT/WITH statements.
- Use oracle_preview_sql before oracle_execute or DDL helpers.
- Use oracle_patch_source for exact stored-source edits instead of hand-building full replacement DDL when possible.
- Use read_patch_preview only for in-process compatibility reads of the last source-patch preview.
- deploy_ddl accepts name and wait_seconds for compatibility; the generic core executes synchronously and returns those fields.
- Never assume DDL can be rollback-previewed.
- Treat profile max_level as the hard ceiling for the running server.
- Keep environment-specific tools, names, identities, and connection details in config.
"#
}
