//! Static onboarding payloads for the `oraclemcp` binary: the agent-facing
//! `robot-docs guide` (JSON + text) and the generic `setup` templates.
//!
//! Pure data, no I/O. Split out of `main.rs` so the CLI flow there stays small;
//! the `json!` macros are compile-time checked exactly as before.

pub(crate) fn setup_profiles_template(profile: &str, credential_env: &str) -> String {
    format!(
        r#"schema_version = 2
default_profile = "{profile}"

[[profiles]]
name = "{profile}"
description = "Read-only database profile"
connect_string = "dbhost.example.com:1521/service_name"
username = "APP_READONLY"
credential_ref = "env:{credential_env}"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
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

pub(crate) fn cli_exit_codes_json() -> serde_json::Value {
    serde_json::json!([
        {
            "code": 0,
            "name": "success",
            "meaning": "command completed successfully"
        },
        {
            "code": 1,
            "name": "process_or_transport_failure",
            "meaning": "stdout write failure or serve transport/runtime failure after startup"
        },
        {
            "code": 2,
            "name": "usage_config_or_safety_block",
            "meaning": "invalid invocation, config/auth/custom-tool/audit/client-credential error, failed doctor check, or startup safety block"
        },
        {
            "code": 3,
            "name": "service_manager_failure",
            "meaning": "local service is inactive, service logs/status are unavailable, or the service manager rejected a requested operation"
        },
        {
            "code": 4,
            "name": "doctor_fix_refused",
            "meaning": "doctor --fix refused an unsafe or out-of-scope repair target such as Oracle state, audit-chain rewrite/merge, classifier, or profile ceiling"
        }
    ])
}

pub(crate) fn cli_contract_json() -> serde_json::Value {
    serde_json::json!({
        "contract_version": 1,
        "binary_names": ["oraclemcp", "om"],
        "structured_output": {
            "flag": "--robot-json",
            "alias": "--json",
            "stdout": "data only: compact JSON for robot-readable commands, human reports otherwise",
            "stderr": "diagnostics only: startup notices, refusals, and operator hints"
        },
        "read_side_json_commands": [
            ["oraclemcp", "--json", "info"],
            ["oraclemcp", "--json", "setup", "--profile", "<profile>"],
            ["oraclemcp", "--json", "profiles"],
            ["oraclemcp", "--json", "doctor"],
            ["oraclemcp", "--json", "doctor", "--online", "--profile", "<profile>"],
            ["oraclemcp", "--json", "capabilities"],
            ["oraclemcp", "--json", "robot-docs", "guide"],
            ["oraclemcp", "--json", "service", "status"],
            ["oraclemcp", "--json", "service", "logs"]
        ],
        "dangerous_operations": [
            {
                "command": "oraclemcp setup --discover",
                "safe_preview": ["oraclemcp", "--json", "setup", "--discover", "--dry-run", "--discover-tns"],
                "execute_gate": "--discover-tns or --yes (explicit scan+write consent); a non-TTY caller without a consent flag refuses to scan/write and exits 2"
            },
            {
                "command": "oraclemcp service install",
                "safe_preview": ["oraclemcp", "--json", "service", "install", "--dry-run", "--profile", "<profile>"],
                "execute_gate": "--yes"
            },
            {
                "command": "oraclemcp service restart",
                "safe_preview": ["oraclemcp", "--json", "service", "restart", "--dry-run"],
                "execute_gate": "--yes"
            },
            {
                "command": "oraclemcp service uninstall",
                "safe_preview": ["oraclemcp", "--json", "service", "uninstall", "--dry-run"],
                "execute_gate": "--yes"
            },
            {
                "command": "MCP guarded writes: oracle_execute, oracle_create_or_replace, oracle_patch_source",
                "safe_preview": ["oracle_preview_sql", "oracle_execute with commit=false", "oracle_create_or_replace without execute=true", "oracle_patch_source without execute=true"],
                "execute_gate": "preview-derived confirmation token plus profile/session operating-level gate"
            }
        ],
        "error_pedagogy": {
            "bare_invocation_hint": "no subcommand exits 2 and names serve, doctor, and capabilities",
            "service_mutation_hint": "missing --yes names --dry-run as the safe alternative",
            "profiles_config_hint": "config load failures name ORACLEMCP_CONFIG and the default profiles path"
        },
        "determinism": {
            "ordering": "tool names, custom tool files, and profile metadata are emitted in stable order",
            "non_tty": "no interactive prompts are used; destructive host changes require flags instead",
            "secrets": "profile and doctor outputs redact credential refs, resolved secrets, wallet paths, and connect strings"
        },
        "exit_codes": cli_exit_codes_json()
    })
}

pub(crate) fn mcp_cli_dashboard_parity_json() -> serde_json::Value {
    serde_json::json!({
        "contract_version": 1,
        "status": "aligned",
        "matrix": [
            {
                "id": "discovery",
                "capability": "tool and server capability discovery",
                "cli": ["oraclemcp --json capabilities", "oraclemcp --json robot-docs guide"],
                "mcp": ["tools/list", "tools/call oracle_capabilities", "resources/read oracle://capabilities"],
                "dashboard": ["/operator/v1/actions/execute oracle_capabilities", "overview capability posture"],
                "status": "aligned"
            },
            {
                "id": "profile_inventory",
                "capability": "profile inventory and profile switching",
                "cli": ["oraclemcp --json profiles", "oraclemcp --json doctor --profile <profile>"],
                "mcp": ["oracle_list_profiles", "oracle_switch_profile", "oracle_connection_info"],
                "dashboard": ["config profiles view", "session lane profile controls", "connection health"],
                "status": "aligned"
            },
            {
                "id": "diagnostics",
                "capability": "offline and live diagnostics",
                "cli": ["oraclemcp --json doctor", "oraclemcp --json doctor --online --profile <profile>"],
                "mcp": ["oracle_connection_info", "oracle_capabilities"],
                "dashboard": ["doctor probes", "health and capacity pages"],
                "status": "aligned"
            },
            {
                "id": "guarded_sql",
                "capability": "read, preview, DML, DDL, and source patch workflow",
                "cli": ["oraclemcp robot-docs guide documents the guarded SQL flow"],
                "mcp": ["oracle_preview_sql", "oracle_query", "oracle_execute", "oracle_create_or_replace", "oracle_patch_source", "oracle_set_session_level"],
                "dashboard": ["SQL workbench read mode", "SQL workbench execute mode", "SQL workbench DDL mode"],
                "status": "aligned"
            },
            {
                "id": "schema_explorer",
                "capability": "schema/object metadata and source inspection",
                "cli": ["oraclemcp --json capabilities lists dictionary/source tools"],
                "mcp": ["oracle_list_schemas", "oracle_schema_inspect", "oracle_search_objects", "oracle_get_ddl", "oracle_get_source"],
                "dashboard": ["explorer schemas", "explorer objects", "source/DDL detail"],
                "status": "aligned"
            },
            {
                "id": "service_and_auth",
                "capability": "local service lifecycle and HTTP client credentials",
                "cli": ["oraclemcp --json service install --dry-run", "oraclemcp --json service status", "oraclemcp --json clients issue"],
                "mcp": ["serve stdio init token", "serve HTTP OAuth", "serve HTTP mTLS", "serve HTTP client credentials"],
                "dashboard": ["pairing ticket", "operator service health", "active lanes"],
                "status": "aligned"
            },
            {
                "id": "audit",
                "capability": "audit-chain visibility and verification",
                "cli": ["oraclemcp audit verify <file>", "oraclemcp audit verify <file> --with-db-evidence"],
                "mcp": ["audit hash-chain records every privileged action out of band"],
                "dashboard": ["audit timeline", "audit filters", "proof export"],
                "status": "aligned"
            }
        ]
    })
}

pub(crate) fn robot_docs_guide_json() -> serde_json::Value {
    let cli_contract = cli_contract_json();
    let parity = mcp_cli_dashboard_parity_json();
    serde_json::json!({
        "ok": true,
        "guide_version": 1,
        "binary": "oraclemcp",
        "structured_output": {
            "flag": "--robot-json",
            "alias": "--json",
            "contract": "stdout is compact JSON; diagnostics go to stderr"
        },
        "cli_contract": cli_contract,
        "mcp_cli_dashboard_parity": parity,
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
            "service": {
                "dry_run": {
                    "command": "oraclemcp --json service install --dry-run --profile <profile>",
                    "argv": ["oraclemcp", "--json", "service", "install", "--dry-run", "--profile", "<profile>"]
                },
                "install": {
                    "command": "oraclemcp service install --yes --client-credentials --profile <profile>",
                    "argv": ["oraclemcp", "service", "install", "--yes", "--client-credentials", "--profile", "<profile>"]
                },
                "status": {
                    "command": "oraclemcp --json service status",
                    "argv": ["oraclemcp", "--json", "service", "status"]
                },
                "logs": {
                    "command": "oraclemcp --json service logs",
                    "argv": ["oraclemcp", "--json", "service", "logs"]
                },
                "notes": [
                    "Use service install --dry-run before --yes; install/uninstall/restart deliberately require --yes.",
                    "The service command writes the platform user service definition for systemd --user, launchd, or Windows services.",
                    "Dry-run JSON includes service hardening: systemd notify readiness plus file/task/memory caps, launchd file/process caps, and Windows restart-on-failure.",
                    "Streamable HTTP auth rules are unchanged: configure per-client credentials, OAuth, or mTLS with registered client leaf fingerprints; use --allow-no-auth only for intentional local development."
                ]
            },
            "http_client_credentials": {
                "issue": {
                    "command": "oraclemcp --json clients issue --label <client-label> --scope oracle:read",
                    "argv": ["oraclemcp", "--json", "clients", "issue", "--label", "<client-label>", "--scope", "oracle:read"]
                },
                "serve": {
                    "command": "oraclemcp serve --listen 127.0.0.1:7070 --client-credentials --profile <profile>",
                    "argv": ["oraclemcp", "serve", "--listen", "127.0.0.1:7070", "--client-credentials", "--profile", "<profile>"]
                },
                "rotate": {
                    "command": "oraclemcp --json clients rotate <client_id>",
                    "argv": ["oraclemcp", "--json", "clients", "rotate", "<client_id>"]
                },
                "revoke": {
                    "command": "oraclemcp --json clients revoke <client_id>",
                    "argv": ["oraclemcp", "--json", "clients", "revoke", "<client_id>"]
                },
                "notes": [
                    "Issue one bearer per MCP client; the bearer is printed once and clients.json stores only salted hashes.",
                    "Do not put the bearer in profiles.toml, audit data, logs, or committed client config."
                ]
            },
            "smoke_tests": [
                {
                    "intent": "generate generic local setup templates without reading private config",
                    "command": "oraclemcp --json setup --profile <profile>",
                    "argv": ["oraclemcp", "--json", "setup", "--profile", "<profile>"]
                },
                {
                    "intent": "verify the live database profile without MCP",
                    "command": "oraclemcp --json doctor --online --profile <profile>",
                    "argv": ["oraclemcp", "--json", "doctor", "--online", "--profile", "<profile>"]
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
                "intent": "run live profile-backed diagnostics",
                "command": "oraclemcp --json doctor --online --profile <profile>",
                "argv": ["oraclemcp", "--json", "doctor", "--online", "--profile", "<profile>"]
            },
            {
                "intent": "inspect the MCP tool surface",
                "command": "oraclemcp --json capabilities",
                "argv": ["oraclemcp", "--json", "capabilities"]
            },
            {
                "intent": "preview the always-on service manager changes without mutating the host",
                "command": "oraclemcp --json service install --dry-run --profile <profile>",
                "argv": ["oraclemcp", "--json", "service", "install", "--dry-run", "--profile", "<profile>"]
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
            "custom_tool_signing": "protected profiles and profiles with require_signed_tools=true require ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY plus per-tool signatures from oraclemcp sign-tool; the HMAC key must contain at least 32 bytes",
            "hmac_key_size": "resolved OAuth HS256, audit-signing, and custom-tool HMAC keys must contain at least 32 bytes of randomly generated key material",
            "secret_refs": "prefer credential_ref and wallet_password_ref over literal passwords",
            "http_transport": "use --client-credentials for service-owned per-client bearers, or top-level http config / serve --oauth-* / --http-* / --tls-* flags for Streamable HTTP; native rustls TLS and optional mTLS are served directly, mTLS identities require registered leaf fingerprints, and server-only TLS still needs per-client credentials, OAuth, or explicit --allow-no-auth",
            "proxy_auth": "use profiles.proxy_auth for thin proxy auth; credential_ref belongs to proxy_user and target_schema is the CONNECT THROUGH client",
            "network_routing": "use top-level sdu and profiles.drcp for validated thin SDU and DRCP server routing instead of raw connect_string query parameters",
            "local_pool": "profiles.pool enables hybrid_pool where pool-backed reads are used: stateless catalog/metadata reads can use bounded local read connections, while user SQL, LOB/sample reads, transactions, DBMS_OUTPUT, login setup, and session identity remain on the pinned main session; served stateless HTTP uses bounded per-subject/profile read-worker lanes instead of sharing one pool across lane runtimes; statement_cache_size reaches the thin driver for pool-backed reads",
            "app_context": "use repeated profiles.app_context entries for typed thin logon application-context triples; values are sensitive and redacted from profile output",
            "environment_specifics": "database aliases, session identity, client module/program labels, and custom workflow tools belong in profiles or tools.d config, not in the general core"
        },
        "thin_diagnostics": {
            "driver": "pure-Rust oracledb thin driver; no Oracle Instant Client, ODPI-C, libclntsh, or C toolchain required",
            "offline": "oraclemcp --json doctor checks thin-driver posture, TNS/wallet directory presence, NLS setup, classifier self-test, and custom-tool availability without opening a database",
            "profile": "oraclemcp --json doctor --profile <profile> inspects non-secret profile metadata offline; add --online to open the live connection for authentication, role/open-mode, standby, and privilege-tier checks",
            "secret_handling": "doctor and profiles output omit connect strings, usernames, credential_ref values, passwords, proxy identities, wallet passwords, IAM tokens, wallet paths, and server DNs",
            "unsupported_auth": "username/password over TCPS wallet is supported; passwordless external wallet auth, profile-driven OCI IAM token retrieval, and Kerberos/RADIUS auth are returned as structured unsupported diagnostics rather than falling back silently"
        },
        "result_materialization": {
            "lobs": "CLOB/BLOB/BFILE locators are materialized with bounded reads before JSON serialization.",
            "ref_cursors": "Valid REF CURSOR values and implicit resultsets serialize as nested result objects with child columns, rows, row_count, fetched_count, and truncation metadata.",
            "caps": "Nested cursor materialization is bounded by row, cell, byte, and depth caps; unsupported shapes remain explicit."
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
                "intent": "live profile-backed checks",
                "argv": ["oraclemcp", "--json", "doctor", "--online", "--profile", "<profile>"]
            },
            {
                "intent": "MCP tool surface and schema inspection",
                "argv": ["oraclemcp", "--json", "capabilities"]
            },
            {
                "intent": "always-on service status",
                "argv": ["oraclemcp", "--json", "service", "status"]
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
            "Preview service lifecycle changes with oraclemcp --json service install --dry-run before using --yes.",
            "Keep environment-specific tools, names, identities, and connection details in config."
        ],
        "exit_codes": cli_exit_codes_json()
    })
}

pub(crate) fn robot_docs_guide_text() -> &'static str {
    r#"oraclemcp robot-docs guide

Output contract
- Use --robot-json or --json for compact machine-readable stdout.
- Diagnostics and serve startup status are written to stderr.
- Read-only commands do not open a database unless their command explicitly says so.
- MCP tool parameter schemas are top-level JSON objects and avoid top-level oneOf, anyOf, allOf, enum, and not for strict client adapters.

CLI contract
- Binary names: oraclemcp and the short argv0-aware alias om.
- Exit codes: 0 success; 1 process/transport failure after startup; 2 invalid invocation, config/auth error, failed doctor check, or startup safety block; 3 service-manager state/failure; 4 doctor --fix refused an unsafe/out-of-scope repair.
- Dangerous host operations are flag-gated: service install/restart/uninstall require --dry-run for preview or --yes to execute.
- No command prompts interactively; missing consent exits non-zero and names the safe preview command.

Client setup
- Install or build one oraclemcp binary, then configure every MCP client to call the same command, args, config file, and environment.
- Generate generic setup templates with: oraclemcp --json setup --profile <profile>
- Local stdio command: oraclemcp serve --profile <profile> --allow-no-auth
- Secure stdio command: ORACLEMCP_STDIO_TOKEN=<token> oraclemcp serve --profile <profile>
- Streamable HTTP starts only with per-client credentials, configured OAuth, mTLS client-certificate verification, or explicit --allow-no-auth; issue per-client bearers with oraclemcp clients issue and enable them with --client-credentials. mTLS identities require registered leaf fingerprints via --mtls-client-fingerprint or [http.mtls].client_fingerprints; use --oauth-* / --http-* / --tls-* flags or top-level [http] config, and keep non-loopback binds behind ORACLEMCP_HTTP_ALLOW_REMOTE=1.
- The thin driver does not need Oracle Instant Client, ODPI-C, libclntsh, or a C toolchain.
- If Oracle Net files need TNS_ADMIN, point every MCP client at the same small wrapper script.
- After replacing the binary or wrapper, restart or reconnect each MCP client so it imports the fresh tool schema.

Always-on service
- Preview host changes first: oraclemcp --json service install --dry-run --profile <profile>
- Install only with explicit consent: oraclemcp service install --yes --client-credentials --profile <profile>
- Check state: oraclemcp --json service status
- Read logs: oraclemcp --json service logs
- Restart: oraclemcp service restart --yes
- Uninstall: oraclemcp service uninstall --yes
- The service command targets the platform user service manager: systemd --user on Linux, launchd on macOS, and Windows services on Windows.
- Dry-run JSON includes service hardening: systemd notify readiness plus file/task/memory caps, launchd file/process caps, and Windows restart-on-failure.
- Streamable HTTP auth rules are unchanged: configure per-client credentials, OAuth, or mTLS with registered client leaf fingerprints; use --allow-no-auth only for intentional local development.

Client smoke tests
1. oraclemcp --json setup --profile <profile>
2. oraclemcp --json doctor --online --profile <profile>
3. MCP tools/list discovers oracle_capabilities plus the advertised Oracle tools without schema import errors
4. MCP tools/call oracle_capabilities with empty arguments succeeds

First commands
- oraclemcp --json setup --profile <profile>
- oraclemcp --json profiles
- oraclemcp --json doctor
- oraclemcp --json doctor --online --profile <profile>
- oraclemcp --json capabilities
- oraclemcp --json service install --dry-run --profile <profile>
- oraclemcp --json clients issue --label <client-label> --scope oracle:read
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

MCP / CLI / dashboard parity
- Discovery: CLI capabilities and robot-docs, MCP tools/list and oracle_capabilities, dashboard overview capability posture.
- Profiles: CLI profiles/doctor, MCP oracle_list_profiles/oracle_switch_profile/oracle_connection_info, dashboard config and lane controls.
- Diagnostics: CLI doctor, MCP connection_info/capabilities, dashboard doctor probes and health pages.
- Guarded SQL: MCP preview/query/execute/DDL/source patch tools and dashboard SQL workbench share the classifier, operating-level, confirmation, and audit path documented by robot-docs.
- Schema explorer: MCP dictionary/source tools back the dashboard explorer; CLI capabilities advertises the same tool names.
- Service/auth: CLI service and clients commands configure the service that serves MCP HTTP and the dashboard pairing flow.
- Audit: CLI audit verify checks the same hash-chain the dashboard audit timeline renders.

Configuration
- Profiles: ~/.config/oraclemcp/profiles.toml or ORACLEMCP_CONFIG.
- Custom tools: ~/.config/oraclemcp/tools.d/*.toml or ORACLEMCP_TOOLS_DIR.
- Custom tool signing: protected profiles and profiles with require_signed_tools=true require ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY and signatures from oraclemcp sign-tool.
- HMAC key size: resolved OAuth HS256, audit-signing, and custom-tool HMAC keys must contain at least 32 bytes of randomly generated key material.
- Prefer credential_ref and wallet_password_ref over literal passwords.
- Use profiles.proxy_auth for thin proxy authentication: credential_ref belongs to proxy_user and target_schema is the CONNECT THROUGH client.
- Use top-level sdu and profiles.drcp for validated thin SDU and DRCP server routing instead of raw connect_string query parameters.
- Use profiles.pool for hybrid_pool where pool-backed reads are used: stateless catalog/metadata reads can use bounded local read connections, while user SQL, LOB/sample reads, transactions, DBMS_OUTPUT, login setup, and session identity remain on the pinned main session. Served stateless HTTP uses bounded per-subject/profile read-worker lanes instead of sharing one pool across lane runtimes.
- Use repeated profiles.app_context entries for thin logon application-context triples; values are redacted from profile output.
- Database aliases, session identity, client module/program labels, and custom workflow tools belong in profiles or tools.d config, not in the general core.

Diagnostic flow
1. oraclemcp --json info
2. oraclemcp --json setup --profile <profile>
3. oraclemcp --json profiles
4. oraclemcp --json doctor
5. oraclemcp --json doctor --online --profile <profile>
6. oraclemcp --json capabilities
7. oraclemcp --json service status

Thin diagnostics
- Offline doctor checks the thin driver posture, optional TNS/wallet directories, canonical NLS setup, classifier self-test, and custom-tool availability without opening a database.
- Profile doctor inspects non-secret metadata offline; add --online for live connectivity, authentication, role/open-mode, standby, and privilege-tier checks.
- Doctor output omits connect strings, usernames, credential_ref values, passwords, proxy identities, wallet passwords, IAM tokens, wallet paths, and server DNs.
- Unsupported thin auth/features are explicit diagnostics; the binary never silently falls back to thick mode.

Result materialization
- CLOB/BLOB/BFILE locators are materialized with bounded reads before JSON serialization.
- Valid REF CURSOR values and implicit resultsets serialize as nested result objects with child columns, rows, row_count, fetched_count, and truncation metadata.
- Nested cursor materialization is bounded by row, cell, byte, and depth caps; unsupported shapes remain explicit.

Agent rules
- Prefer oracle_query for SELECT/WITH statements.
- Use oracle_preview_sql before oracle_execute or DDL helpers.
- Use oracle_patch_source for exact stored-source edits instead of hand-building full replacement DDL when possible.
- Use read_patch_preview only for in-process compatibility reads of the last source-patch preview.
- deploy_ddl accepts name and wait_seconds for compatibility; the generic core executes synchronously and returns those fields.
- Never assume DDL can be rollback-previewed.
- Treat profile max_level as the hard ceiling for the running server.
- Preview service lifecycle changes with oraclemcp --json service install --dry-run before using --yes.
- Keep environment-specific tools, names, identities, and connection details in config.
"#
}
