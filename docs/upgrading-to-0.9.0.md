# Upgrading to 0.9.0

This guide covers operator-visible changes in the shipped 0.9.0 line. It does
not change the fail-closed safety invariant: profiles still start at
`READ_ONLY` unless configured otherwise, every statement is classified before
Oracle sees it, and temporary elevation remains capped by profile `max_level`.

## Before upgrading

1. Back up the active config, audit chain, and service definition.
2. Run the old binary's `doctor` against every served profile and save the
   secret-free output.
3. Install the immutable 0.9.0 release or pin the 0.9.0 container image.
4. Run `oraclemcp doctor --profile <profile>` before exposing the server to an
   MCP client.

For rollback-specific cleanup, use
[`downgrading-0.9.0-to-0.8.0.md`](downgrading-0.9.0-to-0.8.0.md).

## Shipped driver and build toolchain

The 0.9.0 server ships with the pure-Rust thin `oracledb` driver pinned exactly
to **0.8.4** and asupersync pinned to **0.3.9**. Runtime installations still do
not need Oracle Instant Client, ODPI-C, a C toolchain, or Rust. Source builds use
the repository's pinned `nightly-2026-05-11`; the complete reason is documented
in [`TOOLCHAIN.md`](TOOLCHAIN.md).

## Optional dedicated control listener

0.9.0 can place remote readiness and operator traffic on a second, separately
bounded listener. It is disabled by default. Enabling it requires native TLS,
a client CA, a registered client-certificate fingerprint, and the same
fingerprint in the operator allowlist:

```toml
[http.tls]
cert_chain_path = "/path/to/server-chain.pem"
private_key_path = "/path/to/server-key.pem"
client_ca_path = "/path/to/client-ca.pem"

[http.mtls]
client_fingerprints = ["sha256:<client-leaf-der-sha256>"]

[http.control]
listen = "0.0.0.0:7071"
preauth_workers = 4
operator_workers = 1
doctor_workers = 1

[http.operator]
allowed_subjects = ["mtls:sha256:<client-leaf-der-sha256>"]
```

Each worker setting must be between 1 and 64. TLS and registered-certificate
identity complete before HTTP parsing; the control listener never serves the
ordinary MCP or dashboard routes. Do not copy the placeholder fingerprint or
paths into a live config.

## Stateful HTTP notifications and replay

Stateful HTTP notifications are now bound to the owning MCP session and exact
outbound stream. Progress tokens and replay buffers are isolated between
sessions. Reconnect with the exact `Last-Event-ID`; a foreign cursor is refused,
and retention loss is reported as an explicit gap instead of silently replaying
another session's events. Elevation, de-escalation, and TTL expiry can emit
catalog-refresh notifications, so clients should handle `tools/list_changed`
rather than caching the tool surface forever.

## Session leases and guarded effects

Lease handles are now opaque random values bound to the authenticated owner.
Treat a lease ID as an indivisible capability: never parse it, synthesize it,
or transfer it between principals. Revocation is linearized, and an uncertain
database call quarantines the Oracle session before reuse.

For Rust library consumers, `GuardDecision` adds
`non_transactional_effect` and `query_effect_requires_fetch`. Code that
constructs the public struct must initialize both fields. The fields keep
sequence consumption and query-shaped effects behind explicit confirmation;
they do not create a bypass around the classifier or operating-level gate.

## Audit-chain transition

0.9.0 verifies historical audit schemas without rewriting them and writes its
new records without retaining raw SQL text. Keep the entire pre-upgrade chain
and signing-key history. After the first privileged 0.9.0 operation, verify the
chain with the 0.9.0 binary and archive that result with the upgrade evidence.

See [`feature-rollout-0.9.0.md`](feature-rollout-0.9.0.md) for the default
posture and opt-in path of each new surface.
