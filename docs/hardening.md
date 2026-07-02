# Hardening oraclemcp

A security checklist for deploying `oraclemcp`. It is the controls-oriented
companion to [`operations.md`](operations.md), which has the full deployment and
runbook detail. Cross-references point there rather than repeating procedure.

`oraclemcp` is **governed and least-privilege**, not read-only-only: a
fail-closed SQL classifier gates an explicit operating-level ladder
`READ_ONLY < READ_WRITE < DDL < ADMIN`. It is read-only by default and
escalation-capable up to `ADMIN` only through a single-use confirmation-grant
step-up that is TTL-bounded and capped by each profile's `max_level`. Hardening
is about configuring those bounds tightly and adding a database account that
cannot write on its own — defense in depth.

---

## Threat model in one paragraph

The agent is *semi-trusted*: it may emit a `SELECT` that it intends as a read
but which, through injection or its own error, expresses a write or a privilege
escalation. The classifier's job is to refuse anything it cannot **prove** is
permitted at the current operating level, before the statement reaches Oracle. A
statement the classifier cannot prove safe is treated as dangerous, never the
reverse. The remaining controls below reduce blast radius if any single layer is
misconfigured.

The full asset/threat/mitigation model — with the committed test suite that
holds each mitigation honest — is in [`threat-model.md`](threat-model.md); the
vulnerability-reporting policy and supported versions are in the repo-root
[`SECURITY.md`](../SECURITY.md).

---

## Checklist

### Database account

- [ ] Connect as a dedicated least-privilege user, **not** a schema owner or DBA.
- [ ] Grant only `CREATE SESSION`, `SELECT ANY DICTIONARY`, and object-level
      `SELECT` on the data the agent should read. See
      [`operations.md` §3](operations.md#3-a-least-privilege-read-only-oracle-account)
      for the exact `GRANT` set.
- [ ] Grant **no** write-implying system privilege (`CREATE TABLE`,
      `INSERT/UPDATE/DELETE ANY TABLE`, `CREATE/ALTER ANY PROCEDURE`,
      `ALTER SYSTEM`, `UNLIMITED TABLESPACE`, the `DBA`/`RESOURCE` roles).
- [ ] Prefer **proxy authentication** so each agent's identity is preserved in
      the audit trail (`ALTER USER target GRANT CONNECT THROUGH proxy`).
- [ ] Run `oraclemcp --json doctor --online --profile <p>` and confirm the
      **Write posture** check (11) reports a clean read-only posture. Treat any
      warning (it names the offending privileges) as a finding to fix.

### Profile / operating-level configuration

- [ ] Pin `max_level` to the lowest level the workload needs. For read-only
      work, `max_level = "READ_ONLY"` makes escalation impossible regardless of
      client request or OAuth scope.
- [ ] Keep `default_level` at `READ_ONLY`; require explicit, confirmation-gated
      step-up for anything higher.
- [ ] Mark physical standbys with `read_only_standby = true` so they cannot be
      elevated even if `max_level` is higher.
- [ ] Mark sensitive profiles `protected = true`. Protected profiles are pinned
      at `READ_ONLY` with an immutable ceiling and reject literal credentials.
- [ ] Set `require_signed_tools = true` so operator-defined custom tools must
      carry a valid HMAC signature (implied by `protected = true`). The
      classifier only loads custom tools it proves are `READ_ONLY`, even on a
      higher-ceiling profile.
- [ ] Store credentials via external refs such as `credential_ref = "env:VAR"`,
      `file:/path`, or `keyring:service/account`; keep `literal:` for local
      development only. Literal credentials are rejected on protected profiles.

### Network / transport

- [ ] Use **stdio** for single-client, local agent integrations — it has no
      network surface; the parent process is the trust boundary.
- [ ] For the **HTTP** transport, require OAuth bearer enforcement or mTLS with
      registered client leaf fingerprints. The listener fails closed: it will
      not bind without OAuth, mTLS client-certificate verification, or an
      explicit `--allow-no-auth` dev opt-in.
- [ ] Reserve `--allow-no-auth` for local development only.
- [ ] Keep the bind on loopback unless you have a deliberate network boundary; a
      non-loopback bind requires `ORACLEMCP_HTTP_ALLOW_REMOTE=1`.
- [ ] Set `Host` and `Origin` allowlists (`--http-allowed-host` /
      `--http-allowed-origin`).
- [ ] Grant each client the **narrowest OAuth scope** it needs; scopes can only
      *lower* the effective ceiling (`oracle:read` → `READ_ONLY`).
- [ ] Enable native rustls **TLS**, and **mTLS** (`[http.tls.client_ca_path]` /
      `--mtls-client-ca`) for service-to-service callers, and register each
      client leaf DER SHA-256 fingerprint with `[http.mtls].client_fingerprints`
      or `--mtls-client-fingerprint`. Remember server-only TLS is encryption,
      not authentication — `/mcp` still needs OAuth or registered mTLS.
- [ ] See [`operations.md` §4](operations.md#4-network-posture) for the full
      posture and example flags.

### Audit

- [ ] Configure `[audit]` with a signing key (`key_ref` as a secret-ref) and a
      labeled `key_id` for rotation. Privileged actions write to a hash-chained,
      HMAC-SHA256-signed log.
- [ ] Protect and back up the audit log; treat it as a security record.
- [ ] For any profile that can reach `READ_WRITE` or above, mount a persistent,
      private state directory and set `XDG_STATE_HOME` so the durable
      write-intent log survives restarts. An unresolved intent must be treated
      as in-doubt and verified before a writable server is restarted.
- [ ] Periodically and after any incident, run `oraclemcp audit verify <file>`
      — it recomputes every hash link and re-checks the keyed MAC, exiting
      non-zero on tampering. See
      [`operations.md` §5.4](operations.md#54-verify-the-audit-trail).
- [ ] For defense in depth, ship the signed log to an external WORM store / SIEM
      via `[audit.shipping]` (off by default). The mirror is tamper-evident end
      to end — `audit verify` accepts the forwarded JSONL — and a forwarding
      failure never loses the local durable record. See
      [`operations.md` §5.6](operations.md#56-ship-the-audit-log-to-a-worm-store--siem).

### Container / runtime

- [ ] Pin the image to an immutable tag (`ghcr.io/muhdur/oraclemcp:0.6.3`), not
      `:latest`, and verify the digest.
- [ ] Run as non-root with `readOnlyRootFilesystem`,
      `allowPrivilegeEscalation: false`, and all capabilities dropped (see the
      Kubernetes sketch in
      [`operations.md` §2](operations.md#kubernetes-sketch)).
- [ ] Mount the profiles config **read-only**.
- [ ] Set `terminationGracePeriodSeconds` longer than your slowest in-flight
      tool call so the `SIGTERM` drain (rollback → lease-revoke → pool-drain)
      completes before `SIGKILL`.
- [ ] Wire readiness/liveness probes to `/readyz` and `/healthz` once those HTTP
      endpoints are mounted. The health state ships today; the HTTP mounting is
      bead D1 and may be **planned** in your build — verify the endpoints
      respond before relying on the probes.

### Supply chain / build

- [ ] Build (or pull) with the pinned toolchain. The pinned **nightly** is
      **build-time-only** and invisible at runtime — running the shipped binary
      or image needs no Rust toolchain. See
      [`operations.md` §1](operations.md#1-the-pinned-nightly-toolchain-is-build-time-only),
      and [`TOOLCHAIN.md`](TOOLCHAIN.md) for the re-pin runbook.
- [ ] Every crate is `#![forbid(unsafe_code)]` and the workspace builds with
      `panic = "unwind"` so lane-level panic containment can quarantine failed
      DB lanes and audit `unknown_discarded`; the fail-closed classifier carries
      a differential cargo-fuzz target. Keep `cargo deny check` green on the
      pinned toolchain.

---

## What oraclemcp does *not* do for you

Hardening is a shared responsibility. oraclemcp enforces the classifier and the
operating-level ceiling and signs its audit trail, but it does not:

- Manage the lifecycle of your DB credentials, OAuth secrets, or audit key — you
  rotate those (see [`operations.md` §5.5](operations.md#55-rotate-credentials-and-keys)).
- Provide a hosted authorization server — bring your own OAuth issuer.
- Replace database-side controls — a least-privilege account is the backstop the
  classifier is paired with, not a substitute for it.
- Protect against a misconfigured `max_level`. If you set a profile's ceiling to
  `ADMIN`, confirmation-gated escalation to `ADMIN` becomes possible by design.
  Set the ceiling to match the work.
