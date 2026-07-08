# Downgrading 0.8.0 to 0.7.2

Use this runbook when you need to run a 0.7.2 binary against a host that has
already been configured or operated with 0.8.0. The important rule is to scrub
new config keys before starting the older binary: 0.7.2 rejects unknown TOML
fields.

## 1. Preserve state first

Stop the service or MCP client, then copy the active config and audit files to a
timestamped location. Do not edit the only copy in place.

```sh
install -m 600 "$ORACLEMCP_CONFIG" "$ORACLEMCP_CONFIG.before-0.7.2"
cp -p "$HOME/.local/state/oraclemcp/audit/audit.jsonl" \
  "$HOME/.local/state/oraclemcp/audit/audit.jsonl.before-0.7.2"
```

Adjust the paths if your config or audit sink lives elsewhere.

## 2. Remove 0.8.0-only config keys

From every affected profile, remove these fields before launching 0.7.2:

| Location | Remove | 0.7.2 replacement |
|---|---|---|
| `[[profiles]]` | `connect_timeout_seconds` | Use the older driver's default connect timeout. |
| `[[profiles]]` | `inactivity_timeout_seconds` | No exact 0.7.2 equivalent. Use external service supervision if needed. |
| `[[profiles]]` | `keepalive_minutes` | No exact 0.7.2 equivalent. Remove the key. |
| `[http]` | `allow_remote` | Bind loopback only, or use a 0.8.0 binary for remote HTTP. |
| `[profiles.oci]` | `token_env` | No 0.7.2 token-source field. |
| `[profiles.oci]` | `token_file` | No 0.7.2 token-source field. |
| `[profiles.oci]` | `token_exec` | No 0.7.2 token-source field. |

OCI wallet fields such as `wallet_location`, `wallet_password_ref`,
`ssl_server_dn_match`, `ssl_server_cert_dn`, and `use_sni` are additive and can
stay when the 0.7.2 binary already accepts them. If the older binary reports an
additional unknown key, remove that key too before allowing database traffic.

Use a scrubbed copy:

```sh
cp "$ORACLEMCP_CONFIG" /tmp/oraclemcp-0.7.2.toml
${EDITOR:-vi} /tmp/oraclemcp-0.7.2.toml
ORACLEMCP_CONFIG=/tmp/oraclemcp-0.7.2.toml oraclemcp doctor
```

The `doctor` command must parse cleanly before you install or restart 0.7.2.

## 3. Audit-chain compatibility

0.8.0 audit records use hash-chain format v4. A 0.7.2 binary cannot verify v4
records. Keep the v4 audit file as append-only evidence, but do not use the
0.7.2 verifier as proof that the v4 segment is valid.

For a downgrade that may perform privileged actions, point 0.7.2 at a fresh
audit file so older records are not mixed into a chain the old verifier cannot
understand:

```toml
[audit]
path = "/var/log/oraclemcp/audit-0.7.2.jsonl"
key_ref = "env:ORACLEMCP_AUDIT_KEY"
```

Keep the 0.8.0 v4 file beside the incident or release evidence. Verification of
that file must be done by a 0.8.0-or-newer binary.

## 4. Install and validate 0.7.2

Use an explicit downgrade operation and point it at the scrubbed config:

```sh
bash install.sh --version 0.7.2 --force
ORACLEMCP_CONFIG=/tmp/oraclemcp-0.7.2.toml oraclemcp doctor --profile <profile>
ORACLEMCP_CONFIG=/tmp/oraclemcp-0.7.2.toml oraclemcp capabilities
```

Before serving clients, confirm:

- The profile still has the intended `max_level` and `default_level`.
- Protected profiles are still pinned to `READ_ONLY`.
- The selected audit file is writable when any profile can exceed `READ_ONLY`.
- HTTP is bound only where the older binary can protect it.

If validation fails, restore the backed-up 0.8.0 binary and config rather than
editing the production config in place.
