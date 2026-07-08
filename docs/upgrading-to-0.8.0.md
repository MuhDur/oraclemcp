# Upgrading to 0.8.0

This guide covers operator-visible changes in the 0.8.0 line. It does not
change the safety invariant: profiles still start at `READ_ONLY` unless
configured otherwise, every statement is classified before Oracle sees it, and
temporary elevation remains capped by the profile `max_level`.

## Before upgrading

1. Back up the active config file and audit log.
2. Run the old binary's `doctor` against the active profile and save the output.
3. Install 0.8.0 with the normal release installer or image pin.
4. Run `oraclemcp doctor --profile <profile>` before exposing the server to an
   MCP client.

For rollback-specific config cleanup, use
[`downgrading-0.8.0-to-0.7.2.md`](downgrading-0.8.0-to-0.7.2.md).

## Profile timeout and keepalive fields

0.8.0 adds profile-local connection liveness controls:

```toml
[[profiles]]
name = "prod_ro"
connect_string = "PRODDB"
credential_ref = "env:ORACLE_PROD_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"

# Per Oracle call and dispatcher request-budget ceiling. Default: 30 seconds.
call_timeout_seconds = 30

# Oracle Net transport connect/auth timeout before a session exists.
# Omit for the thin driver's 20 second default.
connect_timeout_seconds = 20

# Per-read idle deadline on an established session. Omit to keep driver default.
inactivity_timeout_seconds = 300

# Oracle dead-connection-detection probe interval, in minutes. Omit to disable.
keepalive_minutes = 10
```

`0` is not a useful liveness value for the new fields: the driver treats it as
unset, and `doctor` warns so the profile owner can remove it or set a positive
value.

## HTTP remote bind gate

Native Streamable HTTP remains loopback-oriented by default. A non-loopback
bind such as `0.0.0.0:7070` now requires an explicit operator opt-in:

```toml
[http]
allow_remote = true
allowed_hosts = ["mcp.example.internal:7070"]
allowed_origins = ["https://mcp.example.internal"]
```

You can also opt in for one process with `ORACLEMCP_HTTP_ALLOW_REMOTE=1`.
Remote binding does not authenticate clients by itself. `/mcp` still needs
OAuth, mTLS, per-client credentials, or an explicit development
`--allow-no-auth` posture, and the dashboard still requires its loopback pairing
flow.

## OCI IAM token sources

OCI IAM database-token auth is opt-in per profile and TCPS-only. The token value
is resolved transiently and is never stored or rendered in profile metadata.

```toml
[[profiles]]
name = "adb_iam"
connect_string = "tcps://adb.example.oraclecloud.com:1522/service"
username = "ADMIN"

[profiles.oci]
wallet_location = "/etc/oracle/wallet"
use_iam_token = true

# Pick at most one explicit source:
token_env = "ORACLE_ADB_IAM_TOKEN"
# token_file = "/run/secrets/oracle-adb.jwt"
# token_exec = ["/usr/local/bin/fetch-adb-token", "--profile", "prod"]
```

If no explicit source is set, `ORACLEMCP_IAM_TOKEN` is read. `token_file` is
re-read on every connect so token rotation does not require a restart.
`token_exec` is an argument array, not a shell string; the server runs it
directly, caps stdout, enforces a timeout, and refuses to run it for a non-TCPS
connect string. `iam_config_profile` still only parses and is reserved for a
future autonomous OCI-SDK token source.

## TNS alias resolution

`connect_string` may now be a bare `tnsnames.ora` alias. Use
`oraclemcp setup --discover` to generate read-only profiles from discovered TNS
services, or write the alias directly:

```toml
[[profiles]]
name = "sales_ro"
connect_string = "SALESDB"
credential_ref = "env:ORACLE_SALES_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
```

Generated profiles keep secrets out of the config and write explicit
`READ_ONLY` ceilings. The field reference and discovery contract live in
[`configuration.md`](configuration.md) and
[`tns-discovery-onboarding.md`](tns-discovery-onboarding.md).

## Streaming query delivery

Cursor pagination remains the default for large `oracle_query` results. To opt
into streaming delivery for one read, set `streaming = true` on that tool call:

```json
{
  "sql": "select * from app.events order by event_id",
  "max_rows": 200,
  "streaming": true
}
```

The classifier and row caps are unchanged. Streaming cannot be combined with
`export` or `as_of`; use normal cursor pagination for those paths. Over HTTP,
streamed chunks are additionally emitted as SSE `event: chunk` frames. Over
stdio, the same ordered `chunks` array is returned inline.

See [`feature-rollout-0.8.0.md`](feature-rollout-0.8.0.md) for all new default
postures and opt-in paths.
