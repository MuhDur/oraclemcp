# Downgrading 0.9.0 to 0.8.0

Use this runbook only when a host already configured or operated with 0.9.0
must run 0.8.0. Preserve the 0.9.0 audit chain as immutable evidence, and scrub
0.9.0-only configuration before starting the older binary: configuration is
deny-unknown-fields and must fail closed rather than ignore an unsupported key.

## 1. Preserve state first

Stop the service or MCP client. Copy the active config, audit files, service
definition, and the 0.9.0 `doctor` output to a timestamped location. Do not edit
the only copy in place.

```sh
install -m 600 "$ORACLEMCP_CONFIG" "$ORACLEMCP_CONFIG.before-0.8.0"
cp -p "$HOME/.local/state/oraclemcp/audit/audit.jsonl" \
  "$HOME/.local/state/oraclemcp/audit/audit.jsonl.before-0.8.0"
```

Adjust the paths when config or audit state lives elsewhere.

## 2. Remove the 0.9.0 control-listener table

0.8.0 does not understand `[http.control]`. Remove that complete table from a
scrubbed config copy before launching 0.8.0. Keep `[http.tls]`, `[http.mtls]`,
and `[http.operator]` only where the older binary already accepts and needs
them; removing the second listener must not weaken authentication on the
ordinary HTTP listener.

```sh
cp "$ORACLEMCP_CONFIG" /tmp/oraclemcp-0.8.0.toml
${EDITOR:-vi} /tmp/oraclemcp-0.8.0.toml
ORACLEMCP_CONFIG=/tmp/oraclemcp-0.8.0.toml oraclemcp doctor
```

The old `doctor` must parse the scrubbed file cleanly before the service starts.

## 3. Audit-chain compatibility

The 0.8.0 release writes and understands audit schema v4; 0.9.0 can append
newer schema records that a 0.8.0 verifier cannot authenticate. Retain the
0.9.0 chain byte-for-byte and verify it with 0.9.0-or-newer. Do not treat a
0.8.0 parse or rejection as evidence that the newer segment is valid.

When the downgraded server may perform privileged actions, point 0.8.0 at a
fresh audit file so it cannot mix new v4 records into the preserved 0.9.0
evidence:

```toml
[audit]
path = "/var/log/oraclemcp/audit-0.8.0.jsonl"
key_ref = "env:ORACLEMCP_AUDIT_KEY"
```

Keep the signing material needed to verify both chains according to your key
retention policy.

## 4. Client and lease expectations

Discard outstanding 0.9.0 lease handles before downgrade. They are ephemeral,
owner-bound capabilities and are not migration state. Reconnect MCP clients,
initialize a new session, reacquire any needed lease through the supported tool
flow, and refresh the catalog rather than replaying a retained 0.9.0 SSE cursor.

Rust clients that directly construct the 0.9.0 `GuardDecision` struct must
compile against the 0.8.0 API separately; do not hide the version difference
behind deserialization defaults in safety-sensitive code.

## 5. Install and validate 0.8.0

Use an explicit downgrade and the scrubbed config:

```sh
bash install.sh --version 0.8.0 --force
ORACLEMCP_CONFIG=/tmp/oraclemcp-0.8.0.toml oraclemcp doctor --profile <profile>
ORACLEMCP_CONFIG=/tmp/oraclemcp-0.8.0.toml oraclemcp capabilities
```

Before serving clients, confirm that profile ceilings, protected-profile
`READ_ONLY` pinning, HTTP authentication, and the fresh audit sink all match
the intended posture. Restore the backed-up 0.9.0 binary and config if any of
those checks fails.
