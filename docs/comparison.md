# oraclemcp vs. Oracle SQLcl MCP and genai-toolbox

An honest positioning of `oraclemcp` against the two most common ways an AI agent
talks to an Oracle database today: **Oracle SQLcl's MCP server** and the
**genai-toolbox** (MCP Toolbox for Databases) Oracle path. The goal is to be
accurate about what each does well and where oraclemcp's design differs — not to
claim oraclemcp is universally better.

`oraclemcp` is an **independent, unofficial** project, not affiliated with
Oracle. Oracle's own tools are first-party and integrate with the broader Oracle
ecosystem in ways an independent project does not. Treat the comparison below as
a description of design trade-offs, and verify the current behavior of the other
tools against their own documentation before relying on these specifics — their
releases move independently of this document.

---

## What oraclemcp is (so the comparison is grounded)

`oraclemcp` is a **governed, least-privilege** Oracle Database MCP server in pure
Rust. It puts a **fail-closed SQL classifier** in front of an explicit operating
-level ladder `READ_ONLY < READ_WRITE < DDL < ADMIN`. It is **read-only by
default** and **escalation-capable** up to `ADMIN` — but only through a
preview → confirmation-token step-up that is **TTL-bounded** and capped by each
profile's `max_level`. Every privileged action is written to a hash-chained,
HMAC-SHA256-signed audit log. The whole thing ships as a single self-contained
binary with the thin `oracledb` driver compiled in — no Oracle Instant Client,
no ODPI-C, no JVM, no Python.

In privileged-access-management terms, oraclemcp applies PAM-style discipline to
agent DB access — least privilege by default, just-in-time elevation, bounded
windows, and an audited trail. (That is an analogy to the access-control
*pattern*, not a claim that oraclemcp is a drop-in for an enterprise PAM product;
it does not broker OS logins, manage credential vaults, or do session recording
beyond its own audit log.)

---

## The three approaches at a glance

| Dimension | **oraclemcp** | **Oracle SQLcl MCP** | **genai-toolbox (Oracle)** |
| --- | --- | --- | --- |
| Origin | Independent, unofficial | Oracle, first-party | Google-led OSS; Oracle source supported |
| Pre-execution SQL classification | **Fail-closed classifier**, proves the minimum level per statement before it reaches Oracle | Privilege-delegated to the DB session; SQLcl runs what the connected user can run | No classifier; tool author decides Query vs. Exec at config time |
| Default posture | **Read-only by default** | Depends on the connected account's privileges | Depends on which tools the author exposes |
| Escalation model | **Per-profile `max_level` ceiling**, JIT confirmation-token step-up, TTL-bounded window | Whatever the DB user is granted; no in-server ceiling | Flag/config-level: change the tool set or connection to widen capability |
| Audit | **Hash-chained, HMAC-SHA256-signed** log + offline `audit verify` | Relies on DB-side auditing | Relies on DB-side auditing |
| `NUMBER` fidelity | **`NUMBER` cells as strings by default** (no float coercion) | Tooling-dependent | Risk of float/JSON-number coercion |
| Deploy footprint | **Single static binary**, thin driver, no Instant Client / JVM / Python | JVM + SQLcl distribution | Go binary + an Oracle client/driver per its requirements |
| Transports | stdio + Streamable HTTP (rustls TLS/mTLS, OAuth bearer) | Primarily stdio in current releases | HTTP/stdio per Toolbox |

Read the table as "where the design weight is placed." None of these are
absolutes about quality — they are different answers to "how should an agent be
allowed to touch a production database."

---

## oraclemcp's real differentiators

These are the claims oraclemcp stands behind. Each is a property of the design,
verifiable in the source and tests, and stated with its caveats.

### 1. Provable read-only classification at the current level

oraclemcp does not infer safety from the tool name or trust the DB session to
reject a write. Every raw statement runs through the classifier, which derives
the **minimum operating level** the statement needs and admits it only when the
active session already permits that level. A statement it **cannot prove** safe
for the active level is refused fail-closed, before it reaches Oracle — the
inverse of "allow unless known-bad." The classifier is whitespace-, comment-,
quote-, and batch-aware, fails closed on desynchronized multi-statement input,
and is exercised by a differential adversarial corpus and a cargo-fuzz target.

*Caveat:* the classifier is the enforced control, but it is strongest paired with
a least-privilege DB account (defense in depth). It governs *SQL the server
admits*; it does not replace database-side privilege controls.

### 2. Per-profile ceiling-bounded escalation

Each connection profile carries an immutable `max_level` ceiling and a
`default_level` starting level. Escalation can **never** exceed `max_level`,
regardless of client request or OAuth scope; `protected` profiles and read-only
standbys are pinned at `READ_ONLY`. This is the in-server control that SQLcl's
"run as the DB user" model leaves entirely to database grants, and that
genai-toolbox leaves to which tools the author wires up.

### 3. JIT, confirmation-gated step-up

Elevating above the current level is **just-in-time**: a preview returns the
target level, a gate decision, and a confirmation token; a second call with that
token opens a **TTL-bounded** window (default 900s, max 3600s). DML rolls back by
default; commits and DDL/Admin require the preview's execution grant. There is
no persistent "writes enabled" mode — capability is granted for a bounded window
and a confirmed statement, then it lapses. Committing tools also append a
durable write-ahead intent before DB execution; unresolved in-doubt intents
refuse writable restart instead of silently allowing re-execution.

### 4. Audited and tamper-evident (A8)

Privileged actions land in a **hash-chained, HMAC-SHA256-signed** audit log,
written out-of-band of the Oracle session, fsync-before-execute. `oraclemcp audit
verify <file>` re-walks the chain, recomputes every hash link, and re-checks the
keyed MAC, exiting non-zero on a broken link or a recompute-without-key forgery.
Because the chain is keyed, it is tamper-evident against a writer who controls
the file but not the signing key — not merely against accidental corruption.

*Caveat:* this is oraclemcp's *own* application-level audit trail, complementary
to (not a replacement for) Oracle's database auditing. The signing key is an
operator responsibility to protect and rotate.

### 5. `NUMBER` → string fidelity

Oracle `NUMBER` has higher precision than an IEEE-754 double and than a JSON
number in many parsers. oraclemcp returns `NUMBER` cells **as strings by
default**, so a 38-digit value or a precise monetary amount survives the trip to
the agent without silent float coercion. A caller can explicitly opt into
`numbers_as_float=true` when it genuinely wants floats. Tools that coerce
`NUMBER` into JSON numbers risk losing precision invisibly.

### 6. Single-binary deploy (no Instant Client, no JVM, no Python)

The thin `oracledb` driver is pure Rust and compiled in. There is no Oracle
Instant Client, ODPI-C, `libclntsh`, JVM, or Python runtime to install or
redistribute. The published `ghcr.io/muhdur/oraclemcp` image carries only the
compiled binary in its runtime stage. SQLcl is a JVM application; genai-toolbox's
Oracle path brings its own driver/client requirements.

---

## Where the others fit better

Honesty cuts both ways. Reach for the alternatives when:

- **You want Oracle's first-party tool.** SQLcl is Oracle's own, integrates with
  the broader SQLcl/SQL Developer ecosystem, and is the natural choice if you are
  already standardized on Oracle tooling and want vendor support.
- **You want one toolbox across many database engines.** genai-toolbox targets
  many databases behind one interface. If you run a polyglot fleet and want a
  single MCP toolbox for Postgres, MySQL, Oracle, and more, that breadth is its
  point; oraclemcp is Oracle-only by design.
- **You need a capability oraclemcp does not ship.** oraclemcp's thin adapter
  fails explicitly (structured diagnostics) for auth/features it cannot serve
  end-to-end safely today — for example, a complete OCI IAM token source/refresh
  flow, external-wallet-only auth, and Kerberos/RADIUS. If those are
  load-bearing for you, check the README's current support matrix first.

---

## Summary

oraclemcp's bet is that an agent touching a production Oracle database should be
**governed by default and provably bounded** — classification before execution,
a per-profile ceiling, just-in-time confirmation-gated escalation, a signed audit
trail, precise `NUMBER` handling, and a deploy with no native client to manage.
SQLcl delegates trust to the database session as Oracle's first-party tool;
genai-toolbox trades a classifier for multi-engine breadth and config-time tool
selection. Pick the one whose trust model matches how much you are willing to let
an agent do.

> This document supersedes the earlier deferred positioning draft. Verify the
> current behavior of SQLcl MCP and genai-toolbox against their own
> documentation before relying on version-specific claims here.
