# Operating oraclemcp

Operator-facing deployment and hardening guide for the `oraclemcp` server. It
covers containerized deployment, a least-privilege read-only Oracle account, the
network posture, and a start/stop/drain runbook.

`oraclemcp` is **governed and least-privilege**: a fail-closed SQL classifier in
front of an explicit operating-level ladder
`READ_ONLY < READ_WRITE < DDL < ADMIN`. It is **read-only by default**, but it
is *escalation-capable* up to `ADMIN` through a single-use confirmation-grant
step-up that is TTL-bounded and capped by each profile's `max_level`. Every
privileged action lands in a hash-chained, HMAC-signed audit log. Plan your
deployment around that model: the guarantees below come from how you configure
the profile ceiling and the database account, not from the binary being
incapable of writing.

> See also: [`hardening.md`](hardening.md) for the security-checklist view of
> the same controls, and the project [`README.md`](../README.md) for the full
> tool surface and profile schema.

---

## 1. The pinned nightly toolchain is build-time-only

`oraclemcp` builds on a pinned Rust toolchain (`nightly-2026-05-11`, recorded in
`rust-toolchain.toml`). The thin-native line has no stable MSRV because
**asupersync 0.3.4** uses nightly-only language features (`try_trait_v2` +
`try_trait_v2_residual`); the pinned `oracledb` 0.5.1 driver is stable-clean.

**This is invisible at runtime.** Once compiled, `oraclemcp` is an ordinary
native binary. The toolchain pin matters only when you build the binary or image
yourself; it does **not** affect operators who run the shipped binary or the
published container image:

- You do **not** install a Rust toolchain to *run* `oraclemcp`.
- The shipped binary has no dependency on `rustc`, `cargo`, or any nightly
  feature flag; nightly features are a compile-time concern that the optimizer
  has already resolved.
- The published image at `ghcr.io/muhdur/oraclemcp` ships only the compiled
  binary in its runtime stage — no Rust toolchain, no build tools.
- `cargo install oraclemcp` is the one path where the toolchain pin reaches an
  operator, because that path compiles from source. Use the pinned toolchain for
  it (`cargo +nightly-2026-05-11 install oraclemcp`). Prefer the released binary
  or container image to avoid building at all.

In short: nightly is a property of *building* oraclemcp, not of *running* it.

---

## 2. Containerized deployment

### Docker

The published image is `ghcr.io/muhdur/oraclemcp`. It is a two-stage build: an
`oraclelinux:9` builder compiles the binary with the pinned nightly toolchain,
and the runtime stage is a clean `oraclelinux:9` carrying only
`/usr/local/bin/oraclemcp`. The pure-Rust thin `oracledb` driver is compiled in,
so the image does **not** redistribute or require Oracle Instant Client, ODPI-C,
`libclntsh`, or a C toolchain at runtime.

The default entrypoint serves MCP over stdio:

```sh
# Tool surface only — no database. Safe to inspect anywhere.
docker run -i --rm ghcr.io/muhdur/oraclemcp:0.4.1

# Against a configured profile. Mount a read-only profiles config and pass the
# credential the profile's credential_ref expects.
docker run -i --rm \
  -v "$HOME/.config/oraclemcp:/root/.config/oraclemcp:ro" \
  -e ORACLE_APP_PASSWORD \
  ghcr.io/muhdur/oraclemcp:0.4.1
```

`--allow-no-auth` is baked into the default `CMD` because, over stdio, the
trusted peer is the parent process that launched the container. Do **not** carry
that assumption over to the HTTP transport (see §4).

To verify what you are about to run before wiring it into a client:

```sh
docker run -i --rm ghcr.io/muhdur/oraclemcp:0.4.1 info       # version, tools, transports
docker run -i --rm ghcr.io/muhdur/oraclemcp:0.4.1 --json doctor
```

The optional PL/SQL intelligence image uses the same runtime contract, but the
binary is compiled with `--features plsql-intelligence`. It does not need a
database connection to start, list capabilities, or expose the offline
`oracle_plsql_parse`, `oracle_plsql_analyze`, `oracle_plsql_lineage`,
`oracle_plsql_sast`, and `oracle_plsql_doc` tools. Live snapshot and blast
radius tools still need a configured profile.

```sh
# Published by the manual Docker workflow with variant=plsql-intelligence.
docker run -i --rm ghcr.io/muhdur/oraclemcp:<version>-plsql-intelligence --json info

# Local feature build; PL/SQL engine crates resolve from crates.io.
docker buildx build \
  --target runtime-plsql-intelligence \
  -t oraclemcp:plsql-intelligence .
docker run -i --rm oraclemcp:plsql-intelligence --json info
```

Pin to an immutable tag (`:0.4.1`), not `:latest`, in any non-interactive
deployment, and verify the image digest against the release. The exact
verification commands — SBOM, provenance, and signatures for both the binaries
and the image — are in [§6](#6-verifying-release-artifacts-sbom-provenance-signatures).

### Kubernetes (sketch)

The HTTP transport (`serve --listen`) is what you deploy under Kubernetes. A
minimal Deployment, with credentials and the profiles config supplied as a
Secret and a ConfigMap:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oraclemcp
spec:
  replicas: 2
  selector:
    matchLabels: { app: oraclemcp }
  template:
    metadata:
      labels: { app: oraclemcp }
    spec:
      terminationGracePeriodSeconds: 45   # allow the drain in §5 to complete
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        fsGroup: 65532
      containers:
        - name: oraclemcp
          image: ghcr.io/muhdur/oraclemcp:0.4.1
          args:
            - serve
            - --listen
            - 0.0.0.0:7070
            # OAuth flags or an [http.oauth] block in the mounted config make
            # this fail-closed listener start; otherwise it refuses to bind.
            - --oauth-resource
            - https://oraclemcp.internal/mcp
            - --oauth-issuer
            - https://issuer.example.com
            - --oauth-required-scope
            - oracle:read
            - --oauth-hs256-secret-ref
            - env:ORACLEMCP_OAUTH_HS256_SECRET
            - --http-allowed-host
            - oraclemcp.internal
          env:
            # Durable write intents live under $XDG_STATE_HOME/oraclemcp.
            # Use a persistent volume for write-capable profiles so in-doubt
            # recovery survives process restarts and pod replacement.
            - { name: XDG_STATE_HOME, value: /var/lib/oraclemcp-state }
            # A non-loopback bind (0.0.0.0) requires this opt-in.
            - { name: ORACLEMCP_HTTP_ALLOW_REMOTE, value: "1" }
            - name: ORACLE_APP_PASSWORD
              valueFrom: { secretKeyRef: { name: oraclemcp-db, key: password } }
            - name: ORACLEMCP_OAUTH_HS256_SECRET
              valueFrom: { secretKeyRef: { name: oraclemcp-oauth, key: hs256 } }
            - name: ORACLEMCP_AUDIT_KEY
              valueFrom: { secretKeyRef: { name: oraclemcp-audit, key: hmac } }
          ports:
            - { name: mcp, containerPort: 7070 }
          volumeMounts:
            - name: config
              mountPath: /home/nonroot/.config/oraclemcp
              readOnly: true
            - name: state
              mountPath: /var/lib/oraclemcp-state
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          # readiness/liveness probes target /readyz and /healthz. The health
          # STATE and report shape ship today in oraclemcp-telemetry; mounting
          # them as HTTP endpoints on the listener is bead D1
          # (oraclemcp-040-epic-wp-d-1il.4) and may be PLANNED in your build —
          # confirm `curl http://127.0.0.1:7070/healthz` returns 200 before
          # relying on these probes.
          readinessProbe:
            httpGet: { path: /readyz, port: mcp }
            periodSeconds: 5
          livenessProbe:
            httpGet: { path: /healthz, port: mcp }
            periodSeconds: 10
      volumes:
        - name: config
          configMap: { name: oraclemcp-profiles }
        - name: state
          persistentVolumeClaim: { claimName: oraclemcp-state }
```

Probe semantics, once the endpoints are mounted:

- `/healthz` (**liveness**) is 200 while the process is up, 503 only when the
  process is down. A failed Oracle round trip does **not** flip liveness — that
  would cause needless restarts on transient DB blips.
- `/readyz` (**readiness**) is 200 only when a pool connection pings *and* the
  server is not shutting down. On `SIGTERM` it flips to 503 immediately so the
  load balancer drains in-flight traffic before the pod exits.

---

## 3. A least-privilege read-only Oracle account

The classifier and the per-profile operating-level ceiling are the *enforced*
control. Pair them with a database account that simply **cannot** write — that
is defense in depth, not redundancy. A fresh operator can stand up the read-only
user from this section alone.

### 3.1 Create the account and grant only what the read tools need

Connect as a DBA (or a user with the needed admin rights) and run:

```sql
-- 1. The read-only login.
CREATE USER mcp_ro IDENTIFIED BY "<choose-a-strong-secret>";

-- 2. Connect only. No CREATE TABLE / RESOURCE / unlimited tablespace.
GRANT CREATE SESSION TO mcp_ro;

-- 3. Read the data dictionary the introspection tools rely on. This powers
--    oracle_schema_inspect / oracle_get_ddl / oracle_describe* / search_source.
GRANT SELECT ANY DICTIONARY TO mcp_ro;

-- 4. Read ONLY the specific application objects the agent should see. Grant
--    object-level SELECT, never a write-implying ANY privilege.
GRANT SELECT ON app.customers TO mcp_ro;
GRANT SELECT ON app.orders    TO mcp_ro;
-- ...one GRANT SELECT per object (or use a read-only role, §3.3).
```

Grant **no** write-implying system privileges. Specifically avoid:
`CREATE TABLE`, `CREATE ANY TABLE`, `INSERT/UPDATE/DELETE ANY TABLE`,
`CREATE/ALTER ANY PROCEDURE`, `CREATE/DROP ANY ...`, `ALTER SYSTEM`,
`ALTER DATABASE`, `UNLIMITED TABLESPACE`, and the `DBA`/`RESOURCE` roles.

### 3.2 Prefer proxy authentication (preserves identity in the audit trail)

A proxy user lets several agents share one connecting account while each agent's
individual identity is preserved end to end. Connect as a low-privilege proxy
that authenticates, then proxies through to the read-only target:

```sql
CREATE USER mcp_proxy IDENTIFIED BY "<proxy-secret>";
GRANT CREATE SESSION TO mcp_proxy;

-- Let the proxy connect AS the read-only target, but only via proxy auth.
ALTER USER mcp_ro GRANT CONNECT THROUGH mcp_proxy;
```

Then in the profile, set `[profiles.proxy_auth]` with `proxy_user = "mcp_proxy"`
and `target_schema = "mcp_ro"` (see the README profile schema). The
`credential_ref` then belongs to the proxy.

### 3.3 Optional: a reusable read-only role

If you read many objects, bundle the object grants into a role instead of
listing each grant on the user:

```sql
CREATE ROLE mcp_read_only;
GRANT SELECT ON app.customers TO mcp_read_only;
GRANT SELECT ON app.orders    TO mcp_read_only;
-- ...
GRANT mcp_read_only TO mcp_ro;
```

Keep the role free of any write-implying privilege; it should contain only
`SELECT` object grants (and optionally `SELECT ANY DICTIONARY` if you centralize
dictionary access there). Roles are not active under some `SET ROLE`/definer's
rights paths, so `SELECT ANY DICTIONARY` is often cleaner as a direct grant.

### 3.4 Pin the profile to the account's true capability

In `~/.config/oraclemcp/profiles.toml`, the profile for this account should
keep both the ceiling and the starting level at `READ_ONLY`:

```toml
[[profiles]]
name = "db_ro"
description = "Read-only production database"
connect_string = "db.internal:1521/APPPDB"
username = "MCP_RO"
credential_ref = "env:ORACLE_APP_PASSWORD"
max_level = "READ_ONLY"       # immutable ceiling — escalation can never exceed this
default_level = "READ_ONLY"   # starting session level
require_signed_tools = true   # operator-defined custom tools must be HMAC-signed
```

With `max_level = "READ_ONLY"`, `oracle_set_session_level`/`enable_writes` can
never elevate this profile, and write/DDL/admin work stays blocked regardless of
any client request or OAuth scope. Mark a physical standby with
`read_only_standby = true` to pin it the same way regardless of `max_level`.

### 3.5 Verify the posture from the database's own view

```sh
oraclemcp --json doctor --online --profile db_ro
```

Doctor's **Write posture** check (check 11) reads the session's own
`SESSION_PRIVS` over a live connection and reports a read-only posture when the
principal holds no write-implying system privilege — or **warns**, naming the
offending privileges, if the account can in fact write. Treat any warning here
as a finding: tighten the grants until doctor reports a clean read-only posture.
Doctor output is redaction-safe (it omits connect strings, usernames,
credential refs, passwords, wallet paths, and server DNs) and safe to paste into
an agent session.

---

## 4. Network posture

The stdio transport talks to a single trusted parent process and has no network
surface. Everything below concerns the HTTP transport (`serve --listen`).

- **Fail-closed start.** The HTTP listener starts **only** when service-owned
  per-client credentials, OAuth bearer enforcement, mTLS client-certificate
  verification, or `--allow-no-auth` is explicitly supplied. With none of
  those, it refuses to bind. `--allow-no-auth` is for local development only.
- **Loopback by default.** A non-loopback bind (anything other than
  `127.0.0.1`/`::1`) is refused unless `ORACLEMCP_HTTP_ALLOW_REMOTE=1` is set.
  This is a deliberate guard against accidentally exposing the server; set it
  consciously, behind a network boundary.
- **Single service instance.** After binding but before accepting work, the HTTP
  service creates a private runtime `service-instance.json` lock containing
  pid/listen/start metadata. A second `serve --listen` process fails closed with
  `ORACLEMCP_SERVICE_ALREADY_RUNNING` and reports that metadata instead of
  silently taking over another port or socket.
- **Host / Origin allowlists.** `--http-allowed-host` and
  `--http-allowed-origin` (or `[http] allowed_hosts`/`allowed_origins`) gate the
  `Host` authority and browser `Origin`. Loopback authorities are allowed
  implicitly; everything else must be listed.
- **OAuth 2.1 bearer.** When OAuth is enabled,
  `/.well-known/oauth-protected-resource` stays public, `/mcp` requires a valid
  bearer token, and granted `oracle:*` scopes can only **lower** the effective
  operating ceiling: `oracle:read` caps the request at `READ_ONLY`,
  `oracle:write`/`oracle:execute` at `READ_WRITE`, `oracle:ddl` at `DDL`,
  `oracle:admin` at `ADMIN`. No scope can raise a profile above its `max_level`,
  and protected profiles stay `READ_ONLY`.
- **Per-client HTTP bearer.** `oraclemcp clients issue --label <client>
  --scope oracle:read` creates one opaque bearer for one MCP client and stores
  only a salted hash under `$XDG_STATE_HOME/oraclemcp/clients.json`. Enable this
  mode with `serve --client-credentials` or `service install
  --client-credentials`. Rotate or revoke one `client_id` without changing the
  others; issue/rotate print the new bearer once.
- **TLS / mTLS.** Native rustls TLS is enabled with `[http.tls]` or
  `--tls-cert`/`--tls-key`. Adding `[http.tls.client_ca_path]` or
  `--mtls-client-ca` requires client certificates (mTLS) verified against that
  CA. Register each allowed client leaf DER SHA-256 fingerprint in
  `[http.mtls].client_fingerprints` or with `--mtls-client-fingerprint`; only
  then does the request get an `mtls:sha256:<hex>` principal. Server-only TLS
  encrypts the transport but is **not** application authentication — `/mcp`
  still needs per-client credentials, OAuth, or an explicit `--allow-no-auth`
  dev opt-in, and a non-loopback bind still needs `ORACLEMCP_HTTP_ALLOW_REMOTE=1`
  even with TLS.

Recommended production posture: bind behind a reverse proxy or service mesh,
use one scoped credential per MCP client or require OAuth with the narrowest
scope each client needs (`oracle:read` for read-only agents), enable mTLS with
registered leaf fingerprints for service-to-service callers, and keep
`max_level` pinned at the lowest level the workload requires.

---

## 5. Runbook

### 5.1 Preflight (before serving)

```sh
# Offline checks: thin driver, TNS/wallet resolution, classifier, NLS.
oraclemcp --json doctor

# Add live connectivity, auth, role/open-mode, standby, and the write-posture
# check (§3.5) for the profile you will serve.
oraclemcp --json doctor --online --profile db_ro
```

Both emit a single JSON object on stdout (`--json` is the alias for
`--robot-json`) and are redaction-safe to paste into an agent session. Do not
start serving until doctor is clean for the target profile.

### 5.2 Start

```sh
export ORACLE_APP_PASSWORD='...'          # the profile's credential_ref source
# stdio (an MCP client launches this; --allow-no-auth because the peer is trusted)
oraclemcp serve --profile db_ro --allow-no-auth

# HTTP (fail-closed; needs per-client credentials, OAuth, or --allow-no-auth)
oraclemcp --json clients issue --label claude --scope oracle:read
oraclemcp serve --profile db_ro --listen 127.0.0.1:7070 --client-credentials

# HTTP with OAuth (remote binds also need ORACLEMCP_HTTP_ALLOW_REMOTE=1)
export ORACLEMCP_OAUTH_HS256_SECRET='...'
export ORACLEMCP_HTTP_ALLOW_REMOTE=1      # only for a non-loopback bind
oraclemcp serve --profile db_ro --listen 0.0.0.0:7070 \
  --oauth-resource https://oraclemcp.internal/mcp \
  --oauth-issuer https://issuer.example.com \
  --oauth-required-scope oracle:read \
  --oauth-hs256-secret-ref env:ORACLEMCP_OAUTH_HS256_SECRET \
  --http-allowed-host oraclemcp.internal
```

Logs go to **stderr** (stdout stays pure JSON-RPC over stdio). Startup keeps the
tool surface and discovery available even when the live connection cannot open;
live tool calls then return structured error envelopes instead of crashing the
server.
Only one HTTP service instance is allowed per runtime directory. If a second
`serve --listen` process finds `service-instance.json`, it exits with
`ORACLEMCP_SERVICE_ALREADY_RUNNING`; `oraclemcp --json service status` includes
the same runtime instance discovery block for operator inspection.

### 5.3 Drain and stop (SIGTERM)

`oraclemcp` shuts down gracefully on `SIGTERM`. The coordinator
(`oraclemcp-core` shutdown path):

1. Flips `/readyz` to 503 immediately so load balancers stop sending new work
   (in-flight requests continue).
2. Stops accepting new work.
3. Rolls back in-flight transactions.
4. Revokes outstanding session leases.
5. Drains the connection pool and flushes telemetry/audit exporters.
6. Exits.

Send `SIGTERM` (Kubernetes does this on pod termination) and allow the drain to
finish. Give it headroom: set `terminationGracePeriodSeconds` (≈45s in the §2
sketch) longer than your slowest in-flight tool call so the rollback/lease-revoke
sequence completes before `SIGKILL`. `/healthz` stays 200 while draining; the
process stays live until step 6.

If rollback, cancellation, network loss, or shutdown prevents the server from
proving the final database outcome, that physical session is quarantined and
never returned to reuse. Error/audit outcomes distinguish `rolled_back`,
`discarded_uncommitted`, `commit_in_doubt`, and `unknown_discarded`; a
`commit_in_doubt` record means the operator must verify the Oracle transaction
state before retrying non-idempotent work. For writable deployments, committing
tools also append durable write intents under
`$XDG_STATE_HOME/oraclemcp/write-intents/intents.jsonl` (or
`$HOME/.local/state/oraclemcp/...`). `commit_in_doubt` and unknown outcomes keep
the intent unresolved, so restart refuses writable service with
`ORACLEMCP_WRITE_INTENT_IN_DOUBT` until the database outcome is verified. Safe
terminal outcomes are recovered as a durable idempotency index and reject exact
confirmation-grant plus SQL replay after restart.
Stateful lane close records use tool `lane_lifecycle`, SQL preview `LANE_CLOSE`,
and hash-covered `cancel.kind` / `cancel.reason` fields such as
`User/session_delete` for HTTP `DELETE /mcp` or `Shutdown/server_shutdown` for
listener drain.

### 5.3.1 Config reload and profile drain

Reload is validated as a config-to-config diff before any live state changes.
The hot-reloadable surface is deliberately narrow: profile additions and
compatible profile metadata changes can apply in place; HTTP transport, audit,
or `default_profile` changes require a process restart. A profile is retained
only when its connection, credentials, session setup, pool, exposure, and
operating-level fields are unchanged. Removed profiles and incompatible profile
changes are marked **draining**.

Draining is fail-closed and profile-scoped. Drained profiles are omitted from
the served `oracle_list_profiles` result, `oracle_switch_profile` refuses to
connect to them before resolving secrets or opening Oracle, and lanes already
pinned to a drained profile refuse further non-diagnostic work until the MCP
session is deleted or expires by the stateful idle TTL.

### 5.3.2 Connection pool and failover posture

The local stateless-read pool (`oraclemcp-db`, `[profiles.pool]`) is a bounded,
pure-Rust async pool — no Tokio/r2d2 boundary — for stdio/direct dispatch and
lane-local metadata reads where pool-backed reads are used. Served stateless
HTTP does not share that pool across lane runtimes; generated catalog/metadata
reads route through bounded per-subject/profile read-worker lanes, each with its
own reactor and Oracle connection. The local pool's operating posture:

- **Sizing.** `max_size` from the profile is a *ceiling*; the effective ceiling
  applied at construction is `min(max_size, cpu*2+1)` (plan §10), so a large
  configured ceiling never over-provisions sessions on a small host. `min_idle`
  connections are opened eagerly so a bad profile fails fast. `min_idle` is
  clamped to the resolved `max_size`.
- **Acquire timeout.** A checkout waits up to `acquire_timeout_secs` (default
  5s) for a free or newly-openable connection. If none is available within the
  window — the pool is at `max_size` and all connections are in use — the
  checkout returns a `Pool` (BUSY) error rather than blocking forever. The
  per-DB session ceiling (admission layer) caps concurrent leases at the same
  `max_size`, so a flood sheds load deterministically instead of opening
  unbounded sessions.
- **Dead / torn connections (dirty-discard).** A connection whose call errored
  or was cancelled mid-flight is discarded **dirty**: it is dropped, never
  returned to the idle set, and the freed slot is decremented so a fresh session
  can replace it. A torn round trip can therefore never be reused. An idle
  connection that fails its pre-checkout liveness ping is likewise forgotten and
  a replacement is opened. This composes with the lease layer, which drops any
  session whose rollback/savepoint cleanup cannot be proven and records the
  safest known quarantine outcome.
- **Failover.** Transient connection errors (ORA-03113/03114/12170/12541/…) are
  the only retryable class and reads only — DML is never auto-retried
  (double-execute risk). RAC/ADB failover is handled by the driver/connect
  string; on a dead connection the pool discards dirty and the next checkout
  opens a fresh session against the (failed-over) listener. A read-only standby
  forces the session ceiling to `READ_ONLY` (§3.5, §5.8).
- **Upstream `EXPIRE_TIME` status.** The pinned `oracledb` 0.5.1 stack parses
  `EXPIRE_TIME` into `Description::expire_time`, and `TRANSPORT_CONNECT_TIMEOUT`
  is honored for bounded connect handshakes, but rust-oracledb#14 still tracks
  applying `EXPIRE_TIME` as TCP keepalive on established sockets. `oraclemcp`
  does not fake that driver-owned socket option in the adapter; it relies on the
  profile call timeout, request budget, liveness ping, and dirty-discard rules
  above until the upstream keepalive hook lands.

Checkout accounting is observable via `PoolMetrics` (`acquired`, `released`,
`discarded`, `in_use`, `open`); `is_balanced()` asserts every acquire was
returned clean or discarded dirty (zero leaked sessions) and `is_bounded()`
asserts `open ≤ max_size`. These are the invariants the B3 load/soak harness
checks (see `docs/performance-footprint.md`).

Served stateful HTTP lanes have a separate N4 admission gate before the lane
thread or lane-owned Oracle connection can be opened. The HTTP listener also
admits accepted connection workers before spawning the per-connection thread,
and long-lived Streamable HTTP GET/SSE subscribers have their own transport cap
because they are not Oracle lanes. The current served defaults are upper
bounds: 8 stateful lanes or SSE subscribers per principal bucket, 64 total host
slots, with 1 operator slot and 1 doctor/readiness slot held out of regular
agent admission; accepted connection workers share the same 64-slot host budget
with the same reserve. N4b finalized those shipped upper bounds from the CX-I6
Phase-0 measurement recorded in
`tests/artifacts/perf/20260630-cx-i6-phase0-capacity/RESULTS.md`, which observed
2.00 OS threads and 4.00 file descriptors per warmed stateful lane and enough
finite fd/task headroom for the 64-slot host candidate on the measured dev host.
When regular capacity is exhausted, HTTP paths that can speak HTTP return the
typed `AT_CAPACITY` error with `retry_after_ms`, HTTP 429, `Retry-After`, and a
redacted capacity snapshot; HTTPS sockets rejected before the TLS handshake are
closed at the transport boundary. The snapshot reports capacities and redacted
subject length only; it does not echo bearer tokens, raw principals, profiles,
connect strings, or credentials. Runtime effective-cap surfaces still clamp the
configured caps by the service context's visible DB/session, fd, task, and
memory budgets when those values are available.

`oraclemcp --json service install --dry-run` includes the generated service-unit
hardening. On Linux systemd user units are `Type=notify`/`NotifyAccess=main`,
restart on failure, and set `LimitNOFILE=65536`, `TasksMax=512`,
`MemoryMax=2G`, and `OOMScoreAdjust=100`. launchd agents get `KeepAlive` plus
file/process `SoftResourceLimits`; Windows services get automatic start plus an
SCM restart-on-failure policy. `oraclemcp --json doctor` reports those
configured caps alongside the effective limits visible to the current process
and cgroup. Run doctor from the installed service context when you need the
service-inherited effective values rather than the invoking shell's limits.

### 5.3.2 Persistent service file store

Service-owned state uses the shared `oraclemcp-core` file-store primitives under
the XDG state directory (`$XDG_STATE_HOME/oraclemcp`, or
`$HOME/.local/state/oraclemcp`). The contract is files-first and does not use
SQLite: every mutation requires the service lock token, writes a private temp
file, fsyncs it, renames it into place, and fsyncs the parent directory.

Future service features must not interpolate profile, principal, author, or
proposal names into paths. Use the file-store `StoreId::content_hashed` helper
for untrusted names and keep collection names as fixed code-owned segments.
JSONL-style prunable stores recover by truncating a torn tail and rebuilding an
offset index from complete lines. Retention is only for prunable data such as
metrics snapshots; audit data is explicitly non-prunable.

### 5.4 Verify the audit trail

Privileged actions are written to a hash-chained, HMAC-SHA256-signed audit log
(out-of-band of the Oracle session). Verify the chain offline at any time:

```sh
oraclemcp audit verify /path/to/audit.jsonl
# Override the key id to verify against a rotated key:
oraclemcp audit verify /path/to/audit.jsonl --key_id 2026-q2
```

`verify` re-walks the file, recomputes every hash link, and re-checks the keyed
MAC with the configured key(s); it exits non-zero on a broken link or a
recompute-without-key forgery. Configure the log under `[audit]` in your config
(`path`, `key_ref` as a secret-ref like `env:ORACLEMCP_AUDIT_KEY`, and `key_id`
to label the active key for rotation; the default key id is `default`). When
`[audit].path` is unset, the binary writes to
`$XDG_STATE_HOME/oraclemcp/audit/audit.jsonl`, or
`$HOME/.local/state/oraclemcp/audit/audit.jsonl` when `XDG_STATE_HOME` is unset.
Back up and rotate this log like any other security record, and verify it after
incident review.

Audit records are additive and format-versioned. Current records carry
`schema_version = 3`, a structured server-derived `subject`, and optional
database-evidence fields. `audit verify` still accepts signed v1/v2 records, so
existing logs do not need to be rewritten.

For a 0.4.x layout that still has the default audit log at
`~/.config/oraclemcp/audit.jsonl`, `oraclemcp doctor` reports the legacy layout.
`oraclemcp doctor --fix` copies that JSONL byte-for-byte into the XDG state
audit path when the current target is absent, writes a backup artifact first,
and leaves the legacy source untouched. If both legacy and current audit chains
exist with different bytes, doctor refuses to merge them; verify the chains
manually and set `[audit].path` explicitly if you need a non-default location.

The `/operator/v1` API is gated above ordinary MCP subjects. An OAuth/mTLS
principal is an operator only when its server-derived subject key, such as
`mtls:sha256:<hex>`, appears in `[http.operator].allowed_subjects`; otherwise
only the unauthenticated loopback local-owner path is accepted by default.
Authorized operator API actions append to the same signed audit chain before
routing, and fail closed if no audit sink is configured.

Operator v1 is versioned and schema-first. `GET /operator/v1/schema` serves the
generated schema bundle (`schemas/operator.schema.json`), while the captured UI
fixtures in `tests/fixtures/ui/operator-v1/` are validated by
`scripts/ui_fixtures_validate_against_rust_schema.sh`. REST routes expose
health, metrics, audit-tail summaries, active lane summaries, and unavailable
`v$session` status until a monitor profile is configured. `GET
/operator/v1/audit-tail` accepts `limit`, `subject_id_hash` (or `subject`),
`tool`, `level`/`danger_level`, `decision`, and `outcome` filters. Its timeline
and `export=proof-bundle` response are allow-list-first: raw subject ids, SQL
text/previews, bind values, and secrets are not exported. Records include
`sql_sha256`, DB-evidence columns, chain hashes/signature metadata, and a
structural hash-chain status for the full file. Keyed MAC verification still
requires the audit signing key and remains the offline
`oraclemcp audit verify` path. `GET
/operator/v1/events` streams redacted SSE event envelopes with `event_seq`,
`event_id`, `lane_id`, `subject_id_hash`, `redaction_level`, and
`schema_version`. It accepts `cursor` or `Last-Event-ID` to resume from a
bounded in-memory ring keyed by server-derived subject hash and `lane_id`; stale
query cursors return typed `410 operator_stream_cursor_expired`, while stale
`Last-Event-ID` resumes include an `operator.stream_gap` marker. A cursor from
another lane is rejected before replay. Gated-action routes forward to the
existing MCP `tools/call` dispatcher so all SQL guards and confirmation-token
checks remain in one place. The browser Workbench uses this surface directly:
`oracle_preview_sql` for classify/preview, `oracle_query` for read execution,
and `oracle_execute` for guarded DML. Browser-originated DDL/Admin apply is
release-gated and rejected before MCP dispatch; DDL preview remains available,
and non-browser operator API callers keep the normal profile-ceiling path. They
also carry an in-memory idempotency ledger:
send `Idempotency-Key`, `idempotency_key`, or `request_id` for explicit retry
identity, or let the server derive a key from the
route/tool/subject/lane generation/arguments. Same-key retries replay the
original redacted response; concurrent duplicates return
`operator_idempotency_in_progress`; same-key request drift returns
`operator_idempotency_key_conflict`. Durable crash safety for committing SQL is
still the write-intent/audit path, not this HTTP-edge cache.

### 5.5 Rotate credentials and keys

- **DB credential:** update the secret behind `credential_ref` and restart (or
  re-point the `env:` / `file:` / `keyring:` reference and restart). For proxy auth, rotate the *proxy*
  credential.
- **OAuth HS256 secret:** rotate the value behind `--oauth-hs256-secret-ref` and
  restart; tokens signed with the old secret stop verifying.
- **Per-client HTTP access credential:** service-owned client credentials live
  in `$XDG_STATE_HOME/oraclemcp/clients.json` (or
  `$HOME/.local/state/oraclemcp/clients.json`) as salted hashes only. Issued
  bearer values are shown once:
  `oraclemcp --json clients rotate <client_id>` prints the replacement bearer
  once, and `oraclemcp --json clients revoke <client_id>` revokes that client.
  Close that client's active lanes or restart the service so in-memory grants
  are revoked.
- **Audit signing key:** add the new key under `[audit].key_ref` with a new
  `key_id`, restart, and keep the old `key_id` available to `audit verify` so
  historical records still verify.

### 5.6 Ship the audit log to a WORM store / SIEM

The signed local audit log (§5.4) is the authoritative security record. For
defense in depth — so a tamper attempt at the *local* file is also detectable at
an independent destination — you can mirror every signed record to an external
**write-once-read-many (WORM)** store and/or a SIEM. Shipping is **off by
default**: nothing is forwarded unless you configure `[audit.shipping]` with at
least one destination.

```toml
[audit]
key_ref = "env:ORACLEMCP_AUDIT_KEY"
key_id  = "2026-q2"

[audit.shipping]
# A WORM mirror: a byte-identical JSONL copy, written O_APPEND. Point it at a
# WORM-mounted volume or an object-lock bucket's sync directory.
worm_path = "/mnt/worm/oraclemcp-audit.jsonl"

# And/or a SIEM HTTP(S) endpoint that receives one signed record per POST.
siem_endpoint        = "https://siem.example.com/services/collector/raw"
siem_format          = "json"            # json (default) | cef | syslog
siem_auth_header_ref = "env:SIEM_TOKEN"  # secret-ref for the auth header value
siem_auth_header_name = "Authorization"  # defaults to Authorization
```

How it behaves — the load-bearing properties:

- **Fail-safe ordering.** Each record is written and **fsynced to the local log
  first**; only then is it mirrored to the WORM file / SIEM. A forwarding
  failure (an unreachable SIEM, a full WORM volume) is logged and counted, never
  fatal — the audited call still succeeds and the local signed chain stays
  complete. The local log is the record of record; shipping is a mirror.
- **Tamper-evidence end to end.** The forwarded stream is the *same* signed
  records, in `seq` order. The `json` format and the WORM mirror are
  byte-identical JSONL, so you verify the destination copy with the same tool:
  `oraclemcp audit verify /mnt/worm/oraclemcp-audit.jsonl`. The keyed MAC means a
  forger who lacks the signing key cannot mint a record `verify` will accept,
  even with write access to the destination.
- **SIEM-native formats.** `cef` emits ArcSight CEF v0 and `syslog` emits
  RFC-5424, each carrying the chain-integrity fields (`seq`, `prevHash`,
  `entryHash`, `keyId`, `signature`) in the extension / structured-data element
  so a SIEM rule can alert on a gap or a re-signed record. Records never carry
  bind values or secrets (only the SQL SHA-256 + a truncated preview), so
  nothing sensitive crosses the wire.
- **No new network stack.** The SIEM forwarder POSTs over the same Tokio-free
  asupersync HTTP/1 client the OTLP exporter uses; there is no reqwest/hyper/tokio
  in the production graph.

Operator setup for the destination:

- **WORM bucket / volume.** Enable object-lock / WORM retention on the bucket or
  mount (e.g. S3 Object Lock in compliance mode, or an append-only filesystem).
  oraclemcp writes `O_APPEND` and never seeks or truncates; the write-once
  guarantee is enforced by the destination. Size retention to your compliance
  window and back the volume up like any security record.
- **SIEM endpoint.** Use a raw/HEC-style ingest endpoint that accepts a POST body
  per event. Provision the ingest token as the secret behind
  `siem_auth_header_ref` (for example `env:`, `file:`, or `keyring:`; `literal:`
  is rejected on `protected` profiles). Set a retention policy on the SIEM index to match the
  WORM window.
- **Verify the mirror after incident review**, exactly as for the local log
  (§5.4): a `BROKEN` result names the first divergent `seq`.

### 5.7 Live verification against a test database

The offline suite needs no database. To exercise the live thin paths
(connectivity, auth, the profile/config matrix, and the load/soak), point the
unified `ORACLEMCP_TEST_*` env at a real Oracle 23ai. A throwaway Oracle FREE
instance is enough — it provides `FREEPDB1` on `:1521`:

```sh
docker run -d --name oracle-free -p 1521:1521 \
  -e ORACLE_PASSWORD=<pw> gvenzl/oracle-free:23-slim
```

The live tests read these env vars (unified across the suite):

```sh
# Required for any live test.
export ORACLEMCP_TEST_DSN=localhost:1521/FREEPDB1
export ORACLEMCP_TEST_USER=...
export ORACLEMCP_TEST_PASSWORD=...

# Optional, per scenario:
#   ORACLEMCP_TEST_WALLET_LOCATION, ORACLEMCP_TEST_WALLET_PASSWORD  (TCPS/wallet)
#   ORACLEMCP_TEST_SSL_SERVER_DN_MATCH, ORACLEMCP_TEST_SSL_SERVER_CERT_DN, ORACLEMCP_TEST_USE_SNI
#   ORACLEMCP_TEST_PROXY_USER, ORACLEMCP_TEST_PROXY_TARGET_SCHEMA  (proxy auth)
#   ORACLEMCP_TEST_DRCP=1, ORACLEMCP_TEST_DRCP_CLASS               (DRCP routing)
#   ORACLEMCP_TEST_EDITION, ORACLEMCP_TEST_APP_CONTEXT            (edition / app context)

# Live profile/config matrix.
cargo test -p oraclemcp-db --features live-xe --test live_oracle -- --nocapture

# Heavy load/soak — additionally opt-in via ORACLEMCP_LIVE_XE=1.
ORACLEMCP_LIVE_XE=1 cargo test -p oraclemcp-db --test load_soak -- --ignored --nocapture
```

The structured e2e harness wraps the same suites and is the standard entrypoint
for acceptance beads:

```sh
# Validate harness wiring without running cargo subcommands.
bash scripts/e2e/run_all.sh --log --dry-run

# Run all offline e2e scenarios; live Oracle scenarios skip unless explicitly gated.
bash scripts/e2e/run_all.sh --log
```

Every script under `scripts/e2e/` accepts `--log` and emits JSON-line events to
stderr with `event`, `phase`, `ts`, `duration_ms`, `lane`, `subject`, `sid`,
`profile`, `level`, `grant`, and `outcome`. Command output stays on stdout. On
failure the harness emits a `CRASHPACK=... SEED=...` replay pointer and stores
artifacts under `target/e2e/`. Live scripts require the `ORACLEMCP_TEST_*`
database env plus `ORACLEMCP_LIVE_XE=1`, and they refuse production-looking DSNs
or users before cargo starts.

The load/soak is gated behind `ORACLEMCP_LIVE_XE=1` (a second, explicit opt-in
on top of the connection env) and skips with a clear message when it is unset.
Latency thresholds and the run-recording table are in
[`performance-footprint.md`](performance-footprint.md).

---

## 6. Verifying release artifacts (SBOM, provenance, signatures)

Every tagged release is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml)
and carries supply-chain evidence so a third party can prove *what* an artifact
is and *where it came from* before trusting it. The release produces, for each
platform archive (`.tar.gz` / `.zip`):

- a SHA-256 checksum (`*.sha256`),
- a keyless [cosign](https://docs.sigstore.dev/) signature + certificate
  (`*.sig` / `*.crt`), bound to the release workflow's OIDC identity, and
- a [SLSA-style build provenance attestation](https://slsa.dev/) recorded in the
  repository's attestation store, plus a downloadable cosign blob-attestation
  bundle (`*.attestation.sigstore.json`) for archive-first installers.

The binary archive matrix is:

- `oraclemcp-x86_64-unknown-linux-gnu.tar.gz`
- `oraclemcp-x86_64-unknown-linux-musl.tar.gz`
- `oraclemcp-aarch64-unknown-linux-gnu.tar.gz`
- `oraclemcp-aarch64-unknown-linux-musl.tar.gz`
- `oraclemcp-x86_64-apple-darwin.tar.gz`
- `oraclemcp-aarch64-apple-darwin.tar.gz`
- `oraclemcp-x86_64-pc-windows-msvc.zip`

A CycloneDX 1.5 SBOM for the binary crate
(`oraclemcp-<version>.cdx.json`, plus its own `.sig`/`.crt`) is attached to the
release. The GHCR image is built with SLSA `provenance: mode=max` and an
embedded SBOM, signed with cosign by digest, and carries a pushed provenance
attestation.

Set these once; every command below uses them:

```sh
VERSION=<version>                               # the release you are verifying
IDENTITY="https://github.com/MuhDur/oraclemcp/.github/workflows/release.yml@refs/tags/v${VERSION}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
```

`IDENTITY` is the exact release workflow ref that signed the artifacts; cosign
refuses a signature minted by any other identity. (For images rebuilt via the
manual [`docker.yml`](../.github/workflows/docker.yml) path, the identity ends
in `docker.yml@refs/heads/main` instead — match it to the workflow that built
what you hold.)

### 6.1 Checksum (integrity only — not authenticity)

```sh
sha256sum -c "oraclemcp-x86_64-unknown-linux-gnu.tar.gz.sha256"
```

A checksum proves the bytes are intact, not who produced them. The signature
below is what proves authenticity.

### 6.2 Verify a binary archive signature (cosign keyless)

```sh
cosign verify-blob \
  --certificate "oraclemcp-x86_64-unknown-linux-gnu.tar.gz.crt" \
  --signature   "oraclemcp-x86_64-unknown-linux-gnu.tar.gz.sig" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  "oraclemcp-x86_64-unknown-linux-gnu.tar.gz"
```

`Verified OK` means the archive was signed by the oraclemcp release workflow at
that tag and has not changed since. The same command verifies the SBOM
(`oraclemcp-${VERSION}.cdx.json` with its `.sig`/`.crt`).

### 6.3 Verify binary build provenance (cosign blob attestation)

```sh
cosign verify-blob-attestation \
  --bundle "oraclemcp-x86_64-unknown-linux-gnu.tar.gz.attestation.sigstore.json" \
  --type slsaprovenance1 \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  "oraclemcp-x86_64-unknown-linux-gnu.tar.gz"
```

This checks the signed provenance bundle attached to the archive itself. The
installer runs this after the checksum and `cosign verify-blob` checks and
before extracting the binary.

### 6.4 Verify binary build provenance (GitHub attestation)

```sh
gh attestation verify "oraclemcp-x86_64-unknown-linux-gnu.tar.gz" \
  --repo MuhDur/oraclemcp
```

This checks the SLSA provenance predicate that records the source repo, commit,
and workflow that built the archive. It works offline against a downloaded
bundle with `--bundle <file>` once you have fetched it.

### 6.5 Verify the container image (signature + provenance)

```sh
IMAGE="ghcr.io/muhdur/oraclemcp:${VERSION}"

# Keyless signature, bound to the release workflow identity.
cosign verify "$IMAGE" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER"

# SLSA build provenance attestation for the image.
gh attestation verify "oci://${IMAGE}" --repo MuhDur/oraclemcp
```

Then resolve and pin the digest you just verified, and run that digest (not the
mutable tag) in production:

```sh
docker buildx imagetools inspect "$IMAGE" --format '{{json .Manifest.Digest}}'
```

### 6.6 Inspect the SBOM

The attached CycloneDX SBOM enumerates every crate (and version) compiled into
the binary, so you can cross-check it against your own advisory feed:

```sh
jq -r '.components[] | "\(.name) \(.version)"' "oraclemcp-${VERSION}.cdx.json"
```

The image additionally carries an SBOM attestation you can pull directly:

```sh
cosign download sbom "ghcr.io/muhdur/oraclemcp:${VERSION}"
```

> A release is "verifiable" only when 6.2–6.4 succeed against the **release**
> OIDC identity above. A signature that verifies under any other identity, or a
> provenance that names a different repo/workflow, is not this project's release
> — treat it as untrusted.
