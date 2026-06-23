# Security Policy

`oraclemcp` is a **governed, least-privilege** Oracle Database MCP server. It is
read-only by default and escalation-capable up to `ADMIN` only through an
explicit, confirmation-gated operating-level ladder bounded by each profile's
ceiling. The model is *governed*, not write-incapable: a fail-closed SQL
classifier refuses anything it cannot prove is permitted at the current
operating level, before the statement reaches Oracle. This document states what
we protect, how to report a vulnerability, and which versions receive fixes.

## Supported versions

Security fixes land on the latest released minor line. There is no long-term
support branch.

| Version | Supported          |
|---------|--------------------|
| 0.4.x   | ✅ (current line)  |
| 0.3.x   | ⚠️ critical fixes only |
| < 0.3   | ❌                 |

The `0.3.0 → 0.4.0` transition is the production-hardening line; deploy the
latest `0.4.x`.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately through GitHub's coordinated disclosure channel:

- Use **[Private vulnerability reporting](https://github.com/MuhDur/oraclemcp/security/advisories/new)**
  ("Security" tab → "Report a vulnerability") on the repository. This opens a
  private advisory only the maintainer can see.

Please include:

- the affected version / commit,
- a description of the issue and its impact (which guarantee below it breaks),
- a minimal reproduction (a SQL string, a config, or a request sequence), and
- any suggested remediation.

What to expect:

- **Acknowledgement** within 7 days.
- An initial **severity assessment** against the
  [severity policy](docs/severity-policy.md) (P0/P1 are release-blocking).
- Coordinated disclosure: we agree a timeline, ship a fix on the supported line,
  and credit the reporter unless they prefer to remain anonymous.

This is a single-maintainer project that does not accept outside code
contributions (see the README); a focused security report with a clear
reproduction is the most useful thing you can send.

## What we protect (the security model in brief)

The assets are the **Oracle database and its data**, the **connection
credentials and signing/auth secrets**, and the **integrity of the audit
chain**. The agent driving the server is treated as *semi-trusted*: it may emit
a statement it intends as a read which, through injection or its own error,
expresses a write or a privilege escalation. The controls are layered so no
single misconfiguration is catastrophic:

- **Fail-closed SQL classifier** — every statement is classified before it
  reaches Oracle; anything not provably permitted at the current operating level
  is treated as dangerous, never the reverse
  ([ADR 0004](docs/adr/0004-governed-operating-level-ladder.md)).
- **Governed operating-level ladder** — `READ_ONLY < READ_WRITE < DDL < ADMIN`,
  read-only by default, escalation only via a TTL-bounded, confirmation-token
  step-up capped by each profile's `max_level` (no out-of-band device 2FA).
- **Least-privilege database account** — a dedicated read-scoped Oracle user is
  the backstop the classifier is paired with (see
  [`docs/operations.md` §3](docs/operations.md#3-a-least-privilege-read-only-oracle-account)).
- **Signed, hash-chained audit** — privileged actions are logged out-of-band to
  an append-only, HMAC-SHA256-signed, hash-chained JSONL log, fsynced *before*
  the statement executes, and verifiable with `oraclemcp audit verify`
  ([ADR 0003](docs/adr/0003-keyed-mac-audit-chain.md)). The log can be shipped to
  an external WORM store / SIEM for tamper-evidence at an independent
  destination.
- **Output fencing + telemetry redaction** — row data and logs are fenced and
  redacted so untrusted database content cannot smuggle instructions back to the
  agent, and bind values / secrets never reach logs or exporters.
- **Driver-adapter seam** — all Oracle driver access is isolated behind one seam
  ([ADR 0002](docs/adr/0002-driver-adapter-seam.md)), and every crate is
  `#![forbid(unsafe_code)]`.

The full threat model — assets, threats (classifier bypass, privilege
escalation, injection, cancellation-torn commit, audit forgery, secret leak,
prompt-injection via row data), mitigations, and the evidence suites that hold
each mitigation honest — is in [`docs/threat-model.md`](docs/threat-model.md).
The deployment-time hardening checklist is in
[`docs/hardening.md`](docs/hardening.md).

## Scope and shared responsibility

Hardening is a shared responsibility. `oraclemcp` enforces the classifier, the
operating-level ceiling, and the signed audit trail, but it does **not** manage
the lifecycle of your DB credentials / OAuth secrets / audit key, host an
authorization server, or substitute for database-side controls. A misconfigured
profile ceiling (`max_level = "ADMIN"`) makes confirmation-gated escalation to
`ADMIN` possible *by design* — set the ceiling to match the work. See
[`docs/hardening.md`](docs/hardening.md) for the controls you own.
