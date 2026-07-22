# Engineering Program Plan — oraclemcp + rust-oracledb

**Scope:** the master program plan across both repos, in seven parts:
**I.** GCP/Vertex showcase, demo, and launch (§1–24) · **II.** CI/CD release-velocity
plan (§25) · **III.** Repository hygiene and structure audit (§26) ·
**IV.** Campaign-retrospective improvement program incl. product-feature work (§27) ·
**V.** Two-repo bug hunt + post-release reconciliation (§28–§29) ·
**VI.** Test-coverage audit, testing organization, and logging (§30–§31) ·
**VII.** External triangulation, the accretive frontier, and the beading index
(§32–§33). Companion evidence document: `docs/plan/RETRO_SWARM_CAMPAIGN_2026-07.md`.

**File status:** TRACKED (operator decision 2026-07-18; formerly gitignored as
`PLAN_GCP_SHOWCASE_LAUNCH.md`). Confidentiality-scanned: no live-OCI identifiers, no
personal calendar/meeting references.

**Status:** reviewed planning artifact, §§1–33 (§33 = the beading index). The original GCP program (§§1–24)
had five review passes (culminating in review 5, an external ground-truth
verification, recorded in §23). Sections 25–32 were appended and reconciled
2026-07-17/18: CI velocity (§25), repo hygiene (§26), campaign retrospective +
improvements (§27), a two-repo bug hunt with a Fable verifier (§28), post-0.9.0
release reconciliation (§29), a full test-coverage audit + testing-organization
ultrathink (§30), a logging/observability audit (§31), and a GPT-5.6 external
triangulation + the accretive frontier (§32). Multiple fresh-eyes passes applied
in place; SNI/IAM status corrected 2026-07-18 (SNI shipped, IAM one config step
out — §30.7). **Promotion to beads is intentionally deferred pending the operator's
GO**; when given, the beading trigger and order are §27.6 (build the P6 graph-lint
first, then convert §§25/27/28/29/30/32 items — each carries its scope + acceptance
+ tier — and the GCP program per its own §19.6).

**Program owner:** operator

**Primary repository:** `/home/durakovic/projects/oraclemcp`

**Showcase repository:** `/home/durakovic/projects/durakovic-ai`

**Implementation authority:** the current NTM orchestrator owns the live bead graph.
v0.9.0 shipped and is fully published (§29); the worktree is clean and `main` is
synced as of 2026-07-18. This document does not transfer file ownership, authorize
implementation, or authorize a **release, tag, publish, or production deploy** (those
stay gated — see below). Routine commit + push is standing-authorized.

**Standing authorizations (operator directive 2026-07-18) — these relax specific
gates elsewhere in this plan; where they conflict with conservative gate language,
THESE win:**

1. **Routine commit + push is PRE-AUTHORIZED (no per-action approval).** After
   creating/updating beads, commit the `.beads/` + code and push to the working
   branch or `main` autonomously — including at session end (the "Landing the Plane"
   contract). This does NOT extend to pushing a **release tag** (a `vX.Y.Z` tag push
   triggers crates.io/GHCR/registry publish), nor to the durakovic-ai site `master`
   (which auto-deploys production, §9.8) — those remain gated.
2. **OCI Always-Free is AGENT-USABLE without per-run approval**, within its
   non-negotiable guardrails (unchanged): Always-Free shape asserted before apply,
   synthetic data only with zero committed identifiers, `terraform destroy` in a
   trap, cost-ceiling assert. It is provably $0, so the money-gate does not apply —
   the agent may provision → test → destroy autonomously.
3. **Vertex setup remains operator** (billing-enabled project, the interactive ADC
   login, and accepting the worst-case cost ceiling are one-time operator actions);
   the demo RUNS after setup are autonomous within the enforced hard call/token cap.

**Still operator-gated (unchanged):** cutting a release (tag push → publish), the
site production deploy (site `master` push, §11.4), the public launch (§13),
destructive repo actions beyond an agent's own worktree (janitor deletes = dry-run +
ack, §26.6), and bead conversion itself (the GO, §33).

---

## 1. Executive decision

Build one small, real, reproducible integration first:

1. A Python Google ADK agent uses a Gemini model through Vertex AI.
2. The agent reaches a local Oracle Database 23ai Free instance exclusively through
   an `oraclemcp` child process over MCP stdio.
3. A deterministic runner proves three beats:
   - a read succeeds and returns an expected fixture result;
   - an explicitly requested destructive statement reaches `oracle_preview_sql`,
     where the classifier proves it requires `DDL` and the protected profile's
     immutable `READ_ONLY` ceiling blocks any execution path before Oracle sees it;
   - the audit chain verifies and the run displays only audit facts actually
     present in the log.
4. The repository ships the example, its lockfile, a concise compatibility report,
   machine-readable evidence, and a raw terminal recording as the first milestone.
5. Only after that evidence freezes do we build a dedicated static
   `https://durakovic.ai/oraclemcp/` showcase.
6. The showcase embeds the real recording. It never hosts a live database or a live
   `oraclemcp` endpoint.
7. Only after the page and evidence are stable do we produce a polished launch video
   with HyperFrames and prepare channel-specific HN, X, and Reddit launches.

This ordering is deliberate. The Google integration is the product proof. The page,
recording treatment, video, and distribution amplify that proof; they are not allowed
to substitute for it.

### 1.1 Recommended scope

**First milestone:**

- current ADK compatibility matrix;
- one pinned, runnable Vertex AI example;
- one reproducible Oracle 23ai Free fixture;
- one real three-beat transcript;
- machine checks for all three beats;
- raw `.cast` terminal recording;
- exact version and cost evidence;
- any small, general MCP compatibility fixes required by the audit;
- repository documentation sufficient for a Google engineer to reproduce the run.

**After the first milestone:**

- the `/oraclemcp/` page;
- embedded recording treatment;
- a polished HyperFrames product-launch video;
- launch copy and coordinated distribution.

**First cuts if time is short:**

- client-side simulation;
- Streamable HTTP example code;
- OAuth walkthrough;
- multiple Gemini models or regions;
- narrated or vertical video variants;
- elaborate architecture animation;
- broad site redesign;
- remote deployment of `oraclemcp`.

### 1.2 Product statement

The launch statement should be:

> oraclemcp gives AI agents governed Oracle access through MCP. This demonstration
> shows Gemini on Vertex AI reading Oracle 23ai Free through oraclemcp, a destructive
> request being policy-blocked by the fail-closed guard, and the run's audit chain
> being verified as a separate proof.

Do not shorten this to "read-only Oracle MCP." The product has a guarded operating
ladder from `READ_ONLY` through `ADMIN`; read-only is the default and protected
profiles have an immutable read-only ceiling. The demonstration intentionally uses a
protected read-only profile because that is the cleanest proof of the safety default.

### 1.3 Hosting decision

Cloudflare Pages Free is suitable for the showcase because the deliverable is static
HTML, CSS, JavaScript, images, captions, a compact `.cast`, and an optimized video.
The implementation must stay within the current documented limits:

- 20,000 files per Pages site on the Free plan;
- 25 MiB maximum per individual asset;
- 500 Pages builds per month when the hosted build system is used;
- no Pages Function is required;
- no Worker, D1, KV, Durable Object, or backend endpoint is required.

The page should self-host the asciinema player bundle and `.cast`, or use a native
`<video>` asset below 25 MiB. R2 is an optional static-media fallback only if a
carefully encoded video cannot fit. R2 is not part of the baseline plan.

### 1.4 Vertex cost decision

"Free tier only" is not a stable or precise claim for Vertex AI model inference.
Vertex AI requires a billing-enabled project and Gemini inference has published token
pricing. Eligible new Google Cloud users can use the $300, 90-day Free Trial and are
not billed during that trial, but an existing paid billing account can incur a small
charge.

The plan therefore uses this gate:

1. Prefer an eligible Google Cloud Free Trial project with remaining credits.
2. Confirm credit state before the first live run and before the recording run.
3. Use one cost-efficient stable Gemini model, bounded prompts, bounded output, and a
   hard local cap on model calls.
4. Calculate the worst-case rated cost from the call, turn, input, and output caps;
   require operator acceptance of that ceiling before the first live run.
5. Create a low budget alert, while documenting that budget alerts do not hard-stop
   spend.
6. Record rated usage, credit coverage, and actual billed subtotal in the evidence
   manifest.
7. After explicit operator approval, disable the Vertex AI API or close a project
   created only for this demonstration. The example and runner must never perform
   cloud-resource cleanup automatically.

At G1, also check whether Vertex AI express mode (API-key based, no billing account)
currently exists in a form that legitimately carries the "Vertex AI" label for this
demonstration. If its current terms qualify, it is an acceptable zero-billing middle
path; record the exact mode, limits, and documentation revision in the evidence
manifest.

If the operator requires an absolute guarantee of zero billable usage and has no
eligible trial credits, use the Gemini Developer API free tier only as a separate
fallback experiment. Do not label that fallback "Vertex AI," and do not treat it as
completion of deliverable 1.

---

## 2. Sources of truth and current state

### 2.1 Repository contracts

Implementation agents must read the current files again before touching code:

- `oraclemcp/AGENTS.md`;
- `oraclemcp/README.md`;
- `durakovic-ai/AGENTS.md` (includes the BINDING strategic verdict — see §2.7);
- `durakovic-ai/CLAUDE.md`;
- `durakovic-ai/README.md`;
- `durakovic-ai/docs/STRATEGY.md` (path corrected 2026-07-18; ACTIVE PLAY =
  partner-channel GTM);
- `durakovic-ai/docs/REACH-AND-MONETIZATION-PLAN.md`;
- `durakovic-ai/docs/SITE-COMPARISON-2026-07-14.md` (scored gap analysis);
- this plan;
- the live bead and file-reservation state.

The contracts can change over time. Live instructions override this document where
they conflict.

### 2.2 oraclemcp facts verified during planning

At planning time, the repository provides:

- a pure-Rust `oraclemcp` binary and nine workspace library crates (the ninth,
  `oraclemcp-verifier`, is the standalone verdict-certificate verifier added in the
  0.9.0 cycle; re-count at G0);
- stdio and Streamable HTTP transports;
- current and supported historical MCP protocol revision negotiation;
- tested `initialize`, tool discovery, structured refusals, and annotations;
- local-development stdio through `oraclemcp serve --allow-no-auth`;
- authenticated Streamable HTTP options including client credentials, OAuth, and
  mTLS;
- protected profiles that cannot rise above `READ_ONLY`;
- a fail-closed SQL classifier and guarded operating-level ladder;
- an audit hash chain and `oraclemcp audit verify`;
- Oracle 23ai Free support through the thin `oracledb` driver;
- no native Oracle client requirement for the default build.

These are starting hypotheses for the integration, not permission to claim ADK
compatibility. The ADK run must prove compatibility end to end.

### 2.3 Important audit nuance

The demo must distinguish two kinds of evidence:

- the MCP transcript proves that the destructive request and exact SQL were passed to
  `oracle_preview_sql`, and that `oraclemcp` reported the required level above the
  protected profile ceiling;
- the audit log proves only the events that were durably appended to it and that the
  chain verifies.

Code verification (0.9.0-dev, 2026-07-17) confirmed this split at the source level:
the hash-chained audit log records only executed statements (dispatch emits only
`Allowed`/`StepUpRequired` decisions; the `Blocked` variant exists in the record
schema but is never appended), and `oracle_preview_sql` appends nothing to it.
Classifier and gate refusals flow instead to a separate, observer-only, redacted
refusal corpus under `$XDG_STATE_HOME/oraclemcp/corpus/refusals.jsonl`. Therefore
the launch must not say "the blocked DROP appears in the audit log"; on the current
build that claim is false, not merely unproven. It is sufficient, and more honest,
for beat 3 to show the successful read audit records and a valid audit chain while
beat 2 remains proven by the MCP transcript plus an independent postcondition query.
Re-verify these semantics against the released build during G0.3.

### 2.4 durakovic.ai facts verified during planning

At planning time, the site is:

- a Vite 6 and React 18 static SPA;
- styled by the existing `src/index.css` token system;
- deployed to Cloudflare Pages;
- required to use `bun` for JavaScript dependency and script execution;
- prohibited from adding a backend or API;
- built around an interactive constellation front door;
- already carrying a `/#oraclemcp` project-panel doorway;
- already carrying a client-side `plsql.ts` demo precedent;
- already planning crawlable static content routes.

The new showcase must reuse those systems. It must not introduce Next.js, Astro,
another CSS framework, a second hosted application, or a parallel design system.

**Deep re-verification (2026-07-18, repo + live site) — implementer ground truth:**

- **Stack detail:** Vite 6 + React 18 + TS, `base:'./'`, no SSR; d3-force drives the
  constellation physics, framer-motion the panel morphs, a hand-written canvas the
  connection lines/ember pulses; self-hosted `@fontsource-variable` fonts
  (Bricolage Grotesque display, Hanken Grotesk, JetBrains Mono); `sharp` (dev-only)
  generates OG images. Aesthetic: "molten systems / blueprint" — near-black,
  engineering grid, ember→amber. NO three.js, no CSS framework.
- **The whole core is ~1,600 lines** (`index.css` 496 — the entire design system;
  `Constellation.tsx` 507; `Panel.tsx` 359; `plsql.ts` 193; `App.tsx` 50) — the
  `/oraclemcp/` route + §10.7 walkthrough are a small, tractable addition, not a
  big-codebase integration.
- **Key files:** `src/data/nodes.ts` (the `oraclemcp` bubble orbits
  `rust-oracledb` as a dependent — §9.3's doorway), `src/data/projects.ts`
  (content), `src/i18n/{strings.ts,lang.tsx}` (default `'en'` — §11.2's
  English-only posture is the default at runtime), `scripts/make-og.mjs` (+
  `make-banner.mjs`) for generated images, `public/{llms.txt,robots.txt,
  sitemap.xml,og.png}` + IndexNow/Bing verification files (SEO plumbing exists).
- **Crawlability today:** the root `index.html` (6.2 KB) already embeds a
  substantive static-HTML fallback document (a text fetch of `durakovic.ai`
  returns real readable content incl. both flagship projects) — but
  `durakovic.ai/oraclemcp/` currently serves the **SPA fallback** (homepage
  content, no distinct metadata), confirming §9.7's blocking analysis. `dist/`
  contains a single `index.html`; `sitemap.xml` is root-only.
- **Deployment:** GitHub Actions `deploy.yml` on every push to `master` — bun
  install + `bun run build`, then **wrangler v4 Direct Upload** (`pages deploy
  dist --project-name=durakovic-ai --branch=master`) under Node (wrangler does
  not run under bun; this split is deliberate). Direct Upload avoids the
  Cloudflare 500-builds/month quota. **Consequence: any merge to `master`
  deploys production** — S-phase work stays on a branch until the §11.4 gate,
  and a preview = the same command with a non-`master` `--branch` value.
- **Repo hazards:** the repo root carries gitignored personal material (CVs, job
  applications, outreach drafts, thesis) — site work must never `git add`
  broadly, never commit these, and never reference them in site content.
  `RULE 1` (no deletions without explicit session approval) and the bun-only
  toolchain rule are absolute; the "Landing the Plane" contract mandates
  committed `.beads/` + a successful push at session end (which, per the deploy
  note above, is also a production deploy).

### 2.5 Existing site tracker work

The future site DAG must refine or depend on the current site work instead of
duplicating it:

- `durakovic-ai-oou`: oraclemcp reveal and positioning;
- `durakovic-ai-l00`: rust-oracledb launch copy, which must remain product-specific;
- `durakovic-ai-c64`: mixed post-launch distribution, which needs product-specific
  sub-work before the oraclemcp wave;
- `durakovic-ai-6s0`: shared Cloudflare analytics and UTM infrastructure;
- `durakovic-ai-ybc`: crawlable static routes and conformance content.

Status re-verified 2026-07-18 (46 beads total in the site tracker): `ybc` is
**in_progress**; `oou`, `l00`, `c64`, `6s0`, and the rust-oracledb launch bead
`6p5` are all **open**. Other open beads relevant to this program: "List oraclemcp
in MCP directories", the launch-blog/blog beads, "Pre-launch repo hygiene pass (4
repos)", and the analytics/UTM bead — coordinate, don't duplicate.

The existing `/#oraclemcp` bubble remains useful as an internal doorway. It is not a
sufficient canonical launch URL because a URL fragment is not sent to the server and
cannot receive distinct static HTML, metadata, Open Graph tags, canonical markup, or
sitemap treatment.

### 2.6 External interfaces that must be re-verified

The following are intentionally version-gated because they change:

- latest stable `google-adk` release;
- latest stable `google-genai` release compatible with that ADK release;
- the MCP Python package selected by ADK;
- ADK `McpToolset` constructor and lifecycle APIs;
- ADK stdio and Streamable HTTP connection parameter names;
- the supported Vertex authentication environment variables;
- the stable Gemini model IDs available in the selected region;
- Vertex AI token pricing;
- Vertex AI express mode availability and terms;
- Google Cloud trial and credit status;
- Cloudflare Pages limits;
- HN and subreddit submission rules;
- current GitHub, crates.io, GHCR, and MCP registry release state.

Every one of these must be checked again immediately before it is used.

### 2.7 Site strategic contract — how the showcase must fit (verified 2026-07-18)

`durakovic-ai/AGENTS.md` carries a **binding strategic verdict** (2026-07-10/11
audit) that governs all site work, and this program must operate inside it:

- **The goal is money** (consulting, partner-channel GTM, or a role). The ACTIVE
  PLAY is partner-channel GTM: *AI workflow-automation specialist for
  Oracle-based businesses*, wedge = invoice-exception automation on Oracle
  (invoicekit + oraclemcp). Time budget 60/20/20 (sales/demos/product) is binding.
- **The documented failure mode is "polishing the announcement instead of
  announcing."** SHIP BEFORE POLISH is a named principle. This plan's scope-cut
  ladder (§15) and the video-never-blocks-launch rule (§13.1) are how the
  showcase respects it: the mandatory engineering floor ships even if every
  presentation layer is cut.
- **The oraclemcp launch lives in the 20% product slot as credibility fuel** —
  supporting act, not spearhead. Corollary: the showcase deliverables should be
  built once and reused twice — the same three-beat demo, evidence bundle, and
  `/oraclemcp/` page double as **partner-demo material** for the GTM wedge
  (a governed-Oracle-access proof is exactly what a DACH Oracle partner needs to
  see). No separate partner asset gets built from scratch.
- **Evidence-first voice everywhere** (verifiable numbers, never adjectives) —
  identical to this plan's §3.4 wording rules; the §10.7 verification walkthrough
  is this principle turned into an interaction.
- **The site's scored gap** (SITE-COMPARISON 2026-07-14: 5.9/10 — "a beautiful
  static credential, not yet a funnel"; weakest: content engine 2/10, conversion
  4/10) means the `/oraclemcp/` page must not be another leaf node: S8's
  consulting/contact path and the launch-blog cross-links are conversion
  machinery, not decoration.

---

## 3. Goals, non-goals, and evidence language

### 3.1 Goals

#### G1. Prove Google ADK compatibility

Run a current pinned ADK client against the real `oraclemcp` binary. Audit protocol
negotiation, process lifecycle, tool discovery, schema conversion, tool calls,
structured errors, and cleanup.

#### G2. Preserve client neutrality

Any `oraclemcp` compatibility fix must improve the general MCP surface. Do not add a
Gemini-only tool schema, ADK user-agent branch, model-name branch, or safety bypass.

#### G3. Prove exclusive data access

The Google agent application must have no Oracle library and no direct database
connection. Its only database-capable dependency is the `oraclemcp` process exposed
through `McpToolset`.

#### G4. Make the demonstration deterministic enough to test

The exact prose generated by Gemini may vary. The acceptance checks must instead
assert observable events, tool calls, refusal classes, fixture postconditions, audit
records, and chain validity.

#### G5. Ship evidence, not screenshots alone

Every public claim should map to a command, artifact, version, or stable URL. A video
is presentation evidence; the repository transcript and machine-verifiable manifest
are the proof of record.

#### G6. Give oraclemcp a canonical product page

Create a static, crawlable `/oraclemcp/` page with unique metadata, a real embedded
demo, architecture, verified compatibility, quickstart, and source links.

#### G7. Reuse one evidence set across launch assets

The site, README, video, HN comment, X thread, and Reddit posts must all consume the
same frozen fact sheet so numbers and wording cannot drift.

### 3.2 Non-goals

- Hosting Oracle Database on GCP.
- Demonstrating OCI or Autonomous Database connectivity in this milestone. oraclemcp
  0.9.0 ships working OCI support (wallet/TCPS and pre-fetched IAM database-token
  auth over TCPS), but a public OCI/ADB demonstration needs live Autonomous Database
  evidence, which is operator-gated, and the field-test confidentiality rule bars
  live OCI identifiers from committed artifacts. An OCI/ADB demonstration is a
  candidate second wave after this launch.
- Hosting a public `oraclemcp` endpoint.
- Deploying the ADK agent to Agent Engine, Cloud Run, GKE, or a VM.
- Building a general chat UI.
- Adding a live backend to durakovic.ai.
- Demonstrating privileged writes or DDL execution.
- Benchmarking all Gemini models.
- Claiming certification, partnership, endorsement, or official Google support.
- Claiming compatibility with every MCP client or model.
- Redesigning the entire durakovic.ai site.
- Producing a video before the engineering run is stable.
- Publishing a new oraclemcp version unless the operator separately authorizes it.

### 3.3 Claim taxonomy

Use these labels in working documents and evidence:

| Label | Meaning | Public use |
|---|---|---|
| `VERIFIED` | Reproduced by a named command against an exact commit and version set | Yes |
| `OBSERVED` | Seen in one captured run but not yet regression-gated | With evidence revision and qualification |
| `SUPPORTED_UPSTREAM` | Stated by current primary-source documentation | Link and version required |
| `INFERRED` | Reasoned from evidence but not directly tested | Avoid in headlines |
| `PLANNED` | Approved scope that is not yet implemented | Never phrase as shipped |
| `NOT_TESTED` | Explicit matrix gap | Show honestly |
| `FAILED` | Tested and not working | Show in internal matrix; do not hide |

### 3.4 Public wording rules

Prefer:

- "validated with the exact Google ADK, Gemini, and Vertex AI versions in the linked
  evidence bundle";
- "the guard classified the destructive SQL as DDL and the protected read-only
  profile provided no execution path";
- "the transcript, fixture postcondition, and audit-chain verification are linked";
- "unofficial, independent open-source project."

Avoid:

- "Google-certified";
- "works with every model";
- "unhackable" or "production-proof";
- "read-only MCP";
- "zero-cost Vertex" without the credit context;
- "the database never saw the statement" unless the test proves the refusal point;
- "audited block" unless the blocked event is actually in the audit log;
- "first" or "only" without a documented market survey.

---

## 4. Program architecture

### 4.1 Engineering architecture

```text
Operator terminal
    |
    | uv run python run_demo.py
    v
Google ADK LlmAgent
    |
    | google-genai request
    v
Gemini model on Vertex AI
    |
    | ADK function/tool decision
    v
ADK McpToolset
    |
    | MCP stdio, JSON-RPC
    v
local oraclemcp child process
    |
    | thin Oracle protocol
    v
local Oracle Database 23ai Free container
```

Only the model request crosses into Google Cloud. Oracle remains local. There is no
inbound listener and no public database credential.

### 4.2 Why stdio is the launch path

Stdio is the smallest trustworthy integration surface for the initial demonstration:

- ADK launches and owns the MCP subprocess;
- no public port is opened;
- no reverse proxy or TLS certificate is required;
- process boundaries are easy to explain and record;
- local transport auth can be explicitly disabled while the SQL and profile guard
  remain fully active;
- it isolates ADK schema and lifecycle compatibility from HTTP deployment concerns.

`--allow-no-auth` is acceptable only for this process-local development path. The
example must explain that it opts out of MCP application authentication for a local
stdio child; it does not disable the SQL classifier, protected-profile ceiling,
database privileges, or audit chain.

### 4.3 Why Streamable HTTP remains in the audit

Multi-model and multi-client support is a first-class outcome, so the compatibility
report should still audit ADK's Streamable HTTP client against `oraclemcp`:

- initialization and protocol header behavior;
- session behavior;
- static `Authorization` header support;
- bearer client credentials;
- error propagation and connection cleanup.

This is a secondary lane. Passing HTTP can strengthen the report, but failure does not
block the mandatory stdio example if:

- the issue is recorded precisely;
- the server remains spec-conformant;
- no safe, small general fix exists within the initial scope;
- the public page says `stdio: verified` and `HTTP: not tested` or names the limitation.

Do not add an OAuth acquisition and refresh flow to the example. OAuth is valuable for
remote deployments, but it is not needed to prove the local agent integration.

### 4.4 Protected database profile

Use a dedicated profile with all of these properties:

- a synthetic demo database user;
- only the minimum Oracle grants needed to read the fixture;
- `default_level = "READ_ONLY"`;
- `max_level = "READ_ONLY"`;
- `protected = true`;
- a credential resolved from an environment variable or file reference;
- a dedicated audit log and signing key for the run;
- no real organization, customer, or production data;
- no shared development schema.

The fixture user should not possess `DROP TABLE` privilege. The server guard is the
primary demonstrated refusal, and least-privilege database grants provide independent
defense in depth.

### 4.5 Example implementation language

Use Python 3.12 and the official Python Google ADK.

Rationale:

- the Python ADK has the most mature documented MCP client path;
- Google engineers can recognize the canonical `root_agent` structure;
- a small Python example does not contaminate the Rust workspace build;
- a `pyproject.toml` and `uv.lock` make the external dependency set reproducible;
- using the official ADK avoids hand-rolling model tool calling.

Do not write a custom MCP client or use `google-genai` directly for tool dispatch.
`google-genai` is allowed as ADK's model backend dependency and for usage metadata,
but ADK must own the agent and MCP tool orchestration.

### 4.6 Proposed example layout

```text
examples/vertex-gemini/
|-- README.md
|-- pyproject.toml
|-- uv.lock
|-- .env.example
|-- compose.yaml
|-- agent.py
|-- run_demo.py
|-- compatibility.py
|-- evidence.py
|-- fixture/
|   |-- init.sql
|   `-- expected.json
|-- config/
|   `-- profiles.toml.example
|-- prompts/
|   |-- beat-1-read.txt
|   |-- beat-2-block.txt
|   `-- beat-3-audit.txt
|-- schemas/
|   `-- evidence-v1.schema.json
|-- evidence/
|   `-- <evidence_revision>/
`-- expected/
    `-- compatibility-matrix.md
```

This is a genuinely new integration domain, so the new directory is justified under
the repository's high bar for adding files. Consolidate files if implementation shows
that a separate module carries no real complexity. Do not create empty placeholders.
Normalized, publishable artifacts (evidence JSON, compatibility JSON, redacted
transcript, `.cast`, checksums) land under `evidence/<evidence_revision>/`; the raw
layer stays outside Git per section 6.8.

### 4.7 Dependency pinning

When implementation begins:

1. Resolve the latest stable `google-adk` release.
2. Check its release notes for MCP session error handling and schema changes.
3. Resolve the compatible `google-genai` and `mcp` versions.
4. Constrain Python to a tested minor line and record the exact interpreter patch
   version used for qualification.
5. Generate `uv.lock` and include it in the later operator-authorized landing.
6. Record `uv --version`, Python, ADK, Gen AI SDK, MCP package, and transitive model
   adapter versions in the evidence manifest.
7. Do not use moving Git branch dependencies.
8. Use the most specific stable Gemini model resource the provider exposes. If only a
   mutable model ID is available, record that limitation and capture the concrete
   response model/version metadata when the API supplies it.
9. Select the one Vertex authentication environment-variable contract documented for
   the pinned ADK release. Do not set both a legacy and replacement switch and hope one
   wins; record the chosen variable name and upstream documentation revision.

ADK releases have recently changed MCP names, schema sanitization, Streamable HTTP
customization, and tool-error session handling. The lockfile is part of the result,
not incidental packaging.

---

## 5. Compatibility audit specification

### 5.1 Audit outputs

The audit produces:

- `compatibility-matrix.md` for humans;
- `compatibility.json` for machine consumption;
- raw stderr and JSON-RPC logs with secrets removed;
- one issue or bead per confirmed server defect;
- an explicit `no server changes required` result if everything passes;
- links to upstream documentation and exact package versions.

### 5.2 Result states

Each matrix cell must use exactly one state:

- `PASS`;
- `PASS_WITH_LIMITATION`;
- `FAIL_SERVER`;
- `FAIL_ADK`;
- `NOT_TESTED`;
- `NOT_APPLICABLE`.

Do not use a vague yellow state. Every non-pass cell names the observed error, owner,
workaround if any, and milestone effect.

### 5.3 Protocol and lifecycle matrix

Audit these behaviors through the actual ADK client:

| Area | Required stdio | Secondary HTTP | Acceptance |
|---|---:|---:|---|
| child process spawn | yes | n/a | ADK starts exact local binary |
| initialize | yes | yes | negotiated version recorded |
| initialized notification | yes | yes | tool discovery follows cleanly |
| tools/list | yes | yes | full catalog received without crash |
| tools/call | yes | yes | representative calls complete |
| structured tool error | yes | yes | session survives refusal |
| stderr isolation | yes | n/a | logs never corrupt stdout frames |
| graceful close | yes | yes | no leaked child or session |
| repeated session | yes | yes | two sequential runs work |
| cancellation | observe | observe | behavior documented, no initial-scope fix unless severe |
| protocol headers | n/a | yes | negotiated revision headers accepted |
| auth header | n/a | yes | per-client bearer accepted |

### 5.4 Tool schema matrix

Audit the complete tool catalog before filtering the demo toolset. A protected
read-only profile intentionally hides tools it can never reach, including
`oracle_execute`; therefore use two discovery lanes:

- the real protected demo profile, whose advertised catalog is the public proof; and
- a schema-only compatibility profile used only to make ADK construct the otherwise
  hidden tool declarations. Never call a destructive tool in this lane. Because tool
  visibility is gated on the *current session level* as well as the ceiling (verified
  in the 0.9.0-dev descriptor filter), the profile must set both
  `default_level = "ADMIN"` and `max_level = "ADMIN"` or the full catalog will not be
  advertised at discovery time.

Record the two catalogs separately. Do not call the schema-only catalog the demo
surface, and do not give it valid Oracle credentials. Run the schema-only server as a
separate process whose environment contains no real Oracle credentials: point the
profile's `credential_ref` at a dummy variable that is set to a deliberately invalid
value (or use a `literal:` dummy, which is allowed because this profile is not
`protected`) — do not leave the referenced variable unset, which fails at config
resolution instead of at connect time. Use a guaranteed non-routable connect target
(for example TEST-NET `192.0.2.1`) and deny database-network egress. The lane needs
tool discovery and declaration conversion only; any database connection attempt is a
test failure.

For every tool, capture:

- tool name;
- description length;
- input schema draft features used;
- required fields;
- enums;
- nullable or union constructs;
- arrays and nested objects;
- `additionalProperties` behavior;
- defaults;
- annotations;
- whether ADK constructs a callable tool;
- whether Gemini accepts the converted declaration;
- whether an actual representative call is required.

The full-catalog audit prevents a filtered demo from hiding a general incompatibility.
The demo may still use a filter to reduce model choice ambiguity and token cost.

Known audit hotspots, verified against the 0.9.0-dev registry (re-verify against the
released build): every input object schema sets `additionalProperties: false` through
the shared `object_schema` helper; `oracle_semantic_search` carries the one
input-schema `anyOf` (its filter value union); and the bind arrays of
`oracle_execute`/`oracle_preview_dml` use untyped `items: {}`. There is no `$ref` and
no JSON-Schema `format` keyword anywhere in the catalog, so those common converter
risks do not apply here. The advertised default catalog is roughly sixty tools,
twenty-five of which are near-duplicate compatibility aliases — additional conversion
surface and a further reason the demo agent uses a client-side filter.

### 5.5 Representative tool cases

At minimum, exercise:

- a no-argument or low-argument metadata tool;
- `oracle_connection_info`;
- `oracle_query` with a required SQL argument;
- a tool with optional limits or nested input;
- `oracle_preview_sql` for the refused DDL on the protected demo profile;
- a structured classifier decision showing `required_level = DDL`,
  `profile_ceiling = READ_ONLY`, and a non-allow gate decision;
- one unknown argument or invalid value to observe validation behavior.

The exact tool names must be taken from the released build used in the run. Do not
freeze names from this planning document if the surface changes.

### 5.6 Demo tool filter

Expose only the smallest tool set needed for the three beats, likely:

- capability or connection information;
- query;
- `oracle_preview_sql` for the exact destructive-statement classification.

No read-only audit-inspection MCP tool exists in the current registry; beat 3's audit
evidence comes from the `oraclemcp audit verify` CLI outside the agent, so the demo
toolset carries nothing for audit.

Prefer an ADK `tool_filter` over changing server schemas. The compatibility audit still
runs on the unfiltered catalog.

### 5.7 Authentication matrix

#### Stdio launch lane

- process-local child;
- explicit `--allow-no-auth`;
- protected read-only database profile;
- no TCP listener;
- environment credential reference;
- no secret shown in process arguments or transcript.

#### HTTP compatibility lane

- loopback bind only;
- `--client-credentials` or an equivalent current per-client bearer mechanism;
- static `Authorization` header passed through ADK's documented HTTP connection API;
- no `--allow-no-auth` on HTTP for the compatibility proof;
- server and client torn down after the test.

#### Deferred lane

- OAuth discovery;
- authorization-code flow;
- token refresh;
- mTLS;
- remote deployment.

Document these as supported server features that were not part of the ADK proof. Do
not imply that the example validates them.

### 5.8 Compatibility fix policy

A server change is eligible for the initial scope only when all are true:

1. The failure is reproduced against an exact pinned ADK version.
2. The current MCP specification or established server contract supports the change.
3. The change is client-neutral.
4. The change does not weaken classifier, profile, auth, or audit behavior.
5. The patch is small and reviewable.
6. A DB-free regression test can be added where possible.
7. Existing non-Google conformance tests still pass.
8. The current orchestrator assigns the bead and file reservation.

Examples of acceptable fixes:

- valid JSON Schema normalization;
- missing or malformed tool annotations;
- lifecycle cleanup after a structured tool error;
- protocol-version compatibility;
- stderr/stdout separation;
- a spec-conformant error envelope.

Examples of unacceptable initial-scope fixes:

- bypassing auth by default;
- reclassifying ambiguous SQL as safe;
- weakening protected profiles;
- hiding incompatible tools only when the client is ADK;
- returning success for a refusal;
- broad transport redesign;
- adding a second server implementation.

---

## 6. Reproducible demo contract

### 6.1 Fixture

Use a local Oracle Database 23ai Free container with a synthetic schema. Resolve the
image digest before qualification and pin `compose.yaml` to the digest, retaining a
human-readable tag comment or evidence field. Pin and record the container platform as
well, because a multi-architecture tag can resolve to different platform manifests. A
mutable tag plus a recorded digest is not sufficient for a future clean-clone
reproduction.

The fixture should contain one table such as `DEMO_ORDERS` with deterministic rows:

- at least two regions or statuses;
- exact integer and decimal values;
- no values generated from the current clock;
- no random seed at runtime;
- no personal data;
- one aggregation with an obvious expected answer.

Example shape, not frozen SQL:

```text
DEMO_ORDERS
  ORDER_ID
  REGION
  STATUS
  AMOUNT
```

Beat 1 might ask for completed revenue by region and assert an exact ordered result.
The fixture expectation belongs in `fixture/expected.json`, not only in prose.

### 6.2 Container readiness

The runner must:

1. Start the pinned container.
2. Wait on a real Oracle readiness condition with a timeout.
3. Apply the fixture idempotently or recreate a dedicated demo schema.
4. Verify the expected row count before invoking Gemini.
5. Record the exact server-reported database banner and container platform.
6. Refuse to run if the target connect string does not match the demo allowlist.
7. Print the container image and digest.
8. Tear down only resources created by the example when explicitly requested.

Do not put a destructive cleanup command in the default path. Repository rule 1 still
applies to files, and container cleanup should be an explicit operator action.

### 6.3 Exclusive-access invariant

The example is accepted only if:

- the Python dependency graph contains no Oracle database driver;
- source code contains no direct Oracle socket or SQL client call;
- fixture setup is separate from the agent process;
- during the three beats, all database calls originate in `oraclemcp`;
- the agent process can be run in a network namespace or observation mode showing
  only Vertex traffic and the local MCP child relationship, if practical;
- documentation states that Docker/SQL fixture setup is operator setup, not agent
  access.

Static checks should fail if `oracledb`, `cx_Oracle`, JDBC, SQL*Plus subprocess calls,
or a direct port 1521 connection is introduced into the agent package.

### 6.4 Beat 1: read succeeds

Prompt intent:

> Use the Oracle database tool to calculate the requested deterministic aggregate.
> Return the tool result and a one-sentence explanation.

Machine acceptance:

- an ADK event records a tool call to the intended `oraclemcp` query tool;
- the `oracle_query` success itself proves the statement was admitted by the
  read-only gate; the runner additionally captures `oracle_preview_sql` on the same
  SQL reporting `required_level = READ_ONLY` and `gate_decision = "allow"` — the
  symmetric counterpart of beat 2;
- the tool result contains the expected columns and exact values;
- no direct database client is present;
- the final model answer is retained but not string-matched;
- a successful read audit record is asserted only if the exact build emits it.

### 6.5 Beat 2: destructive request is blocked

Prompt intent:

> Submit this exact destructive statement to the database policy-preview tool, then
> report its required level, the profile ceiling, and the gate decision. Do not merely
> advise me that it is unsafe.

The wording intentionally requires a real MCP tool call. A model-only refusal would
prove Gemini's policy, not `oraclemcp`'s guard. The canonical protected profile does
not advertise `oracle_execute`, because execution can never be reached under its
immutable read-only ceiling. `oracle_preview_sql` is therefore the correct public
proof: it classifies the exact SQL, reports `DDL` as required, reports `READ_ONLY` as
the ceiling, and supplies no executable path.

Machine acceptance:

- an ADK event records a call to `oracle_preview_sql` with the exact destructive SQL;
- the result reports `required_level = DDL`;
- the result reports `profile_ceiling = READ_ONLY` and `protected = true`;
- `gate_decision` is not `allow` (the verified enum is
  `allow`/`require_step_up`/`blocked`/`unknown`; expect `blocked` on this profile)
  and no `execute_confirmation` grant is returned;
- the ADK session remains usable after the blocked decision;
- an independent `oracle_query` through `oraclemcp` confirms the table still exists;
- the deterministic row count remains unchanged;
- no success response or auto-commit occurs;
- the script fails if Gemini declines to make the tool call, changes the SQL, or calls
  a different tool.

Permit at most a small, declared retry count for transient model non-compliance. Keep
all attempts in the raw transcript. Never splice a failed attempt out of the proof.

The acceptance field names above (`required_level`, `profile_ceiling`, `protected`,
`gate_decision`, `execute_confirmation`) were verified against the 0.9.0-dev dispatch
surface; re-verify them against the released build per section 5.5.

### 6.6 Beat 3: audit evidence

The runner should display:

- the audit file path in a redacted or workspace-relative form;
- the records attributable to this run;
- the operation, status, profile, and available verdict certificate fields;
- a chain verification command;
- the machine-readable verification result;
- the fixture postcondition result from beat 2.

Machine acceptance:

- `oraclemcp audit verify` exits successfully against the exact log;
- the verification result is captured in evidence JSON;
- record count and terminal hash are captured if the CLI exposes them;
- the server-maintained audit head-anchor sidecar is present and reports a matching
  head, rather than silently accepting the weaker legacy no-anchor state;
- the read event is correlated to the run without guessing;
- the plan does not require a blocked-event audit record unless implemented and
  verified;
- no signing key or database password is printed.

The server also maintains a separate, observer-only, redacted refusal corpus at
`$XDG_STATE_HOME/oraclemcp/corpus/refusals.jsonl`, distinct from the hash-chained
audit log. If G3 verifies that the qualified build records the beat-2 decision there,
the runner may capture that entry as supplementary evidence — always labeled as the
refusal corpus and never described as the audit log. Absence of a corpus entry is not
a failure.

### 6.7 Event evidence schema

Create a versioned `evidence-v1` JSON document with at least:

```json
{
  "schema": "oraclemcp-vertex-demo-evidence/v1",
  "evidence_revision": "immutable revision ID",
  "source": {
    "git_sha": "full SHA",
    "tree_clean": true,
    "oraclemcp_version": "exact version"
  },
  "google": {
    "adk_version": "exact version",
    "genai_version": "exact version",
    "model_resource": "configured model resource",
    "response_model_version": "returned concrete version or unavailable",
    "project_alias": "redacted alias",
    "location": "region",
    "usage": {},
    "rated_cost_usd": "decimal or unavailable",
    "credit_coverage": "free-trial|other-credit|none|unknown",
    "billed_subtotal_usd": "decimal or pending"
  },
  "oracle": {
    "database": "Oracle Database 23ai Free",
    "database_banner": "exact server-reported banner",
    "container_image": "repository:tag",
    "container_digest": "sha256:...",
    "container_platform": "os/architecture",
    "fixture_version": "sha256:..."
  },
  "mcp": {
    "transport": "stdio",
    "protocol_version": "negotiated revision",
    "tools_exposed": [],
    "demo_catalog_total": 0,
    "schema_only_catalog_total": 0
  },
  "beats": [
    {"id": 1, "status": "PASS", "evidence": []},
    {"id": 2, "status": "PASS", "evidence": []},
    {"id": 3, "status": "PASS", "evidence": []}
  ],
  "artifacts": []
}
```

The schema should allow `unknown` or `pending` where cloud billing finalization is not
immediate. It must not coerce missing billing evidence into zero.

Every evidence bundle also needs a small artifact manifest containing relative path,
media type, byte length, SHA-256, sanitization state, and source classification
(`raw`, `normalized`, or `presentation`). The verification command must recalculate all
hashes and fail on a missing or extra publishable artifact.

### 6.8 Raw and normalized artifacts

Keep two layers:

#### Raw layer

- ADK event stream;
- MCP client debug log if enabled;
- `oraclemcp` stderr;
- audit JSONL;
- audit verification output;
- fixture before and after results;
- terminal `.cast`;
- cloud usage metadata.

The raw layer may be stored outside Git if it contains transient identifiers. Produce
checksums and a sanitized publishable subset.

#### Normalized layer

- `evidence.json`;
- `compatibility.json`;
- deterministic result excerpts;
- redacted transcript;
- checksums;
- human-readable report.

Normalization may remove run identifiers, paths, and credentials, but must not change
SQL, refusal semantics, results, ordering, or pass/fail outcomes.

### 6.9 Secret handling

- Use ADC through `gcloud auth application-default login` or the current official
  local-development mechanism.
- Do not commit ADC files, access tokens, project numeric IDs, or service-account
  keys.
- Do not create a long-lived service-account key for a local demo.
- Put Oracle and audit secrets behind environment or file references.
- Generate a dedicated random audit-signing key that meets the current minimum size,
  store it outside the repository in an owner-readable file, and keep the same secret
  reference available to both the server and `audit verify`.
- Preserve the audit JSONL and its head-anchor sidecar together in the raw evidence
  bundle; neither is optional for the qualified run.
- Do not auto-delete the audit key, raw audit files, anchor, or evidence directory.
  The operator owns their explicit retention and cleanup after publication review.
- Populate `.env.example` only with names and safe placeholders.
- Run a secret scan against the publishable artifact directory.
- Record environment variable names, not values.
- Disable terminal input capture when a secret could be typed.
- Load credentials before starting asciinema.

### 6.10 Requalification and upstream retirement

A pinned cloud model can later be retired even when the repository remains unchanged.
Treat each evidence bundle as immutable historical proof, not a promise that the exact
cloud endpoint exists forever.

For a later refresh:

1. Keep the original evidence and checksums.
2. Select a currently supported stable model through G1.4 again.
3. Regenerate the dependency lock only when the selected ADK stack changes.
4. Run the complete three-beat and negative-control qualification.
5. Emit a new versioned evidence bundle and compatibility matrix.
6. Update the site's "latest verified" pointer without rewriting the historical run.

The example may accept an explicit model override for requalification, but the
committed default and each published artifact must still identify one exact model.

---

## 7. Execution phases

### 7.1 Phase G0: ownership and baseline freeze

**Estimate:** 1.5-2.5 hours

**Purpose:** avoid colliding with the active release/evidence swarm and prevent a demo
from being built on an unidentified dirty revision.

#### Tasks

**G0.1 - Coordinate ownership**

- Re-read `AGENTS.md` and live bead state.
- Register with Agent Mail when concurrent implementation begins.
- Ask the orchestrator which release SHA and binary the example should target.
- Reserve only the approved example and documentation paths.
- Do not reserve shared dispatch, auth, or audit files unless a confirmed defect needs
  a patch.

**G0.2 - Select target release state**

- Prefer a clean committed SHA with all current release gates satisfied.
- Default to the published `v0.9.0` tag (shipped and published 2026-07-18, §29);
  target a different clean SHA only with explicit operator approval.
- Do not build the public evidence from uncommitted worktree state.
- Record whether the demo targets a published version, release candidate, or exact
  commit build.
- Public wording must match that status.

**G0.3 - Capture baseline conformance**

- Run the existing DB-free MCP conformance tests through the repository's approved
  bounded build wrapper.
- Capture tool count, negotiated revisions, and current schemas from the target SHA.
- Save raw output outside tracked paths until normalized.

#### Exit gate

- exact target SHA selected;
- owner and path reservations clear;
- baseline MCP tests pass or failures are assigned;
- no implementation begins on a dirty anonymous revision.

#### Dependencies

- Blocks all G1-G5 work.

### 7.2 Phase G1: Google project and cost guard

**Estimate:** 2-3 hours elapsed, 1-1.5 hours hands-on

#### Tasks

**G1.1 - Create or select a dedicated GCP project**

- Use a project created only for the demonstration where practical.
- Confirm billing-account type and remaining trial credit.
- Enable only the current Vertex AI API required by the ADK documentation.
- Record region selection rationale.

**G1.2 - Establish local ADC**

- Use the current official `gcloud auth application-default login` flow.
- Set the ADC quota project (`gcloud auth application-default set-quota-project`) to
  the demo project; a missing quota project is the most common local Vertex ADC
  failure.
- Verify the active ADC principal without printing a token.
- Grant only the minimum Vertex invocation permission.
- Avoid owner/editor roles for the final setup.

**G1.3 - Add spend controls**

- Configure a low budget alert.
- Set local maximum requests per run.
- Set a maximum total model-turn count across all internal ADK retries and tool loops.
- Set model maximum output tokens.
- Disable retries at the SDK layer beyond the small declared policy.
- Calculate and print the worst-case rated cost implied by those caps before any live
  request; require an explicit operator go-ahead when it exceeds the approved ceiling.
- Write the API-disable cleanup command into the operator runbook, but never execute
  cloud cleanup automatically.

**G1.4 - Select model and region**

- Query the current stable model list in the selected region.
- Choose the cheapest stable model that reliably supports function calling through
  the selected ADK release.
- Avoid preview models unless no stable model passes.
- Record the configured model resource, any concrete response model/version metadata,
  and the pricing source revision.

#### Exit gate

- one live minimal ADK text request succeeds;
- credit and billing status are recorded honestly;
- maximum call count is enforced locally;
- exact model and region are selected.

#### Dependencies

- Depends on G0.
- Blocks G3 and G4.

### 7.3 Phase G2: ADK and MCP compatibility audit

**Estimate:** 6-10 hours

#### Tasks

**G2.1 - Freeze client versions**

- Pin Python, `google-adk`, `google-genai`, and MCP package versions.
- Generate `uv.lock`.
- Record upstream release notes that affect MCP.

**G2.2 - Prove stdio lifecycle**

- Launch the exact `oraclemcp` target binary through ADK.
- Capture initialize negotiation.
- Discover the complete tool list.
- Close the toolset and verify no process remains.
- Repeat twice to catch stale session state.

**G2.3 - Audit full tool schema conversion**

- Enumerate every server tool.
- Ask ADK to adapt each schema.
- Ask Gemini to accept the declarations in a bounded no-op or representative run.
- Record each failure with exact schema fragment and exception.

**G2.4 - Audit structured refusal behavior**

- Trigger a harmless locally constructed guard refusal.
- Verify the tool result remains a refusal, not an SDK exception that destroys the
  agent session.
- Make a subsequent metadata call in the same session.

**G2.5 - Audit HTTP bearer lane**

- Bind `oraclemcp` to loopback only.
- Use per-client credentials.
- Configure ADK's current Streamable HTTP client with the bearer header.
- Exercise initialize, tools/list, one metadata call, and shutdown.
- Record `NOT_TESTED` if the current client lacks a supported safe configuration and
  no initial-scope-sized fix exists.

**G2.6 - Classify defects**

- Separate server defects, ADK defects, configuration errors, and documentation
  ambiguity.
- Search existing issues and upstream releases before filing anything.
- Do not patch until ownership is assigned.

#### Exit gate

- compatibility matrix complete;
- stdio is `PASS` for initialize, discovery, representative call, refusal, recovery,
  and shutdown;
- all full-catalog schema failures are understood;
- HTTP result is recorded without blocking stdio.

#### Dependencies

- Depends on G0.
- G2.3 and G2.4 can run before Vertex project setup with local/client scaffolding, but
  final Gemini acceptance depends on G1.
- Blocks G3.

### 7.4 Phase G2F: small general compatibility fixes

**Estimate:** 0 hours if green; hard cap 8 hours

#### Tasks per defect

**G2F.n.1 - Reproducer**

- Add the smallest failing DB-free test.
- Include pinned client/version evidence outside workspace tests if Python is needed.

**G2F.n.2 - Safety review**

- Confirm no guard, auth, profile, or audit invariant weakens.
- Confirm the fix is MCP-general and not client-detected branching.

**G2F.n.3 - Patch**

- Edit only reserved files.
- Keep the diff narrow.
- Do not add compatibility shims or duplicated v2 code.

**G2F.n.4 - Gates**

- Run focused regression tests.
- Run the repository's required format, clippy, workspace test, and deny gates through
  the current bounded build workflow.
- Re-run the ADK reproducer.

**G2F.n.5 - Integration decision**

- Coordinate landing with the active release train.
- A commit, push, version bump, tag, or publish still requires operator authorization.

#### Exit gate

- every included patch is green and assigned;
- unresolved non-blocking issues remain explicit in the matrix;
- no broad redesign consumes the initial milestone.

#### Kill rule

If compatibility fixes exceed eight focused hours or touch safety-critical shared architecture,
freeze the integration on the last known good stdio surface and document the exact
limitation. Do not consume the demo and evidence reserve.

### 7.5 Phase G3: fixture and example package

**Estimate:** 8-12 hours

#### Tasks

**G3.1 - Create the example package**

- Add only the files that have real content.
- Configure the canonical Python environment.
- Add license and repository-context notes where needed.

**G3.2 - Define the Oracle fixture**

- Pin the Oracle 23ai Free image.
- Add deterministic schema initialization.
- Add expected results.
- Add readiness timeout and diagnostics.

**G3.3 - Define the protected profile**

- Create a safe example config template.
- Use environment-backed secrets.
- Pin read-only maximum and protected state.
- Direct audit output into an isolated run directory.

**G3.4 - Implement `agent.py`**

- Define the canonical ADK root agent.
- Use `McpToolset` and stdio connection parameters from the pinned release.
- Filter tools only for the demo agent.
- Include concise instructions requiring database evidence.
- Close the MCP toolset correctly.

**G3.5 - Implement deterministic runner**

- Run each beat with stable prompts.
- Capture ADK event objects.
- Detect tool calls and results structurally.
- Enforce retry and token budgets.
- Exit nonzero on any missing proof.

**G3.6 - Implement evidence normalization**

- Write `evidence-v1`.
- Redact only named sensitive fields.
- Add checksums.
- Make normalized output stable enough to diff.

**G3.7 - Add exclusive-access check**

- Inspect imports and lockfile.
- Reject Oracle client libraries.
- Reject direct listener calls to the database from the agent code.

#### Exit gate

- a clean clone can install from the lockfile;
- the fixture reaches ready state;
- the example uses only MCP for agent database access;
- all three beats pass twice consecutively;
- the runner exits nonzero when a fixture expectation or refusal is deliberately
  broken.

#### Dependencies

- Depends on G1, G2, and any blocking G2F fix.
- Blocks G4.

### 7.6 Phase G4: evidence qualification

**Estimate:** 6-10 hours

#### Tasks

**G4.1 - Clean-SHA qualification**

- Build the target binary from a clean exact SHA.
- Run the repository-required gates appropriate to the target state.
- Record toolchain versions.

**G4.2 - Cold-start run**

- Start from no running demo container.
- Follow README steps exactly.
- Measure elapsed setup and demo time.
- Capture any undocumented prerequisite.

**G4.3 - Repeatability run**

- Run the three beats at least three times.
- Require all machine assertions to pass.
- Preserve all attempts and explain any transient retry.

**G4.4 - Negative control**

- Deliberately change the expected read result and prove the runner fails.
- Deliberately substitute an `allow` decision for beat 2 and prove the runner fails.
- Deliberately tamper with a copy of the audit log and prove verification fails.
- Deliberately truncate a separate copy while retaining its copied head anchor and
  prove the anchor check detects the missing tail.
- Never tamper with or delete the original proof artifact.

**G4.5 - Cost and usage capture**

- Record model request count, token usage, rated price, credit coverage, and billing
  subtotal state.
- Mark delayed billing as pending rather than zero.

**G4.6 - Independent reproduction**

- Have a fresh shell or separate operator follow the README without oral steps.
- Capture fixes only for real documentation gaps.

#### Exit gate

- clean SHA identified;
- three consecutive runs pass;
- negative controls fail as intended;
- sanitized evidence validates against its schema;
- no secret scan findings;
- README works from a fresh environment.

#### Dependencies

- Depends on G3.
- Blocks G5 and all site work.

### 7.7 Phase G5: recording and engineering ship

**Estimate:** 5-8 hours plus contingency

#### Tasks

**G5.1 - Freeze recording script**

- Use the exact commands from the qualified README.
- Limit the terminal to a clear 16:9-safe grid.
- Choose a readable font and theme.
- Preload secrets before recording.
- Disable unrelated notifications and prompt decorations.

**G5.2 - Rehearse without recording**

- Run the exact script once.
- Check timing and line wrapping.
- Confirm no secret or local personal path appears.
- Confirm the block is a real tool result.

**G5.3 - Record real terminal session**

- Use `asciinema rec` to capture the qualified run.
- Do not manually type fake output.
- Keep the full continuous run.
- Preserve the original `.cast` and checksum.

**G5.4 - Sanitize for publication**

- Inspect every frame/event.
- Remove or replace sensitive environment identifiers only through a documented
  re-record when possible.
- Do not edit pass/fail facts.
- Produce a public transcript and checksum map.

**G5.5 - Repository documentation**

- Link the example from the root README only after qualification.
- Add a compact compatibility summary.
- State exact versions, transport, model backend, and limitations.
- Include independent-project disclaimer.

**G5.6 - Ship gate**

- Run focused example checks and repository gates.
- Reconcile with the orchestrator's target SHA.
- Commit + push are pre-authorized (standing authorization, header); obtain explicit operator approval before a RELEASE tag, publish, or production deploy.
- Verify remote state after authorized push.

#### Exit gate

- example is reproducible;
- public artifacts match exact SHA;
- recording is real and secret-free;
- the initial engineering deliverable is complete;
- site and video remain blocked until this gate passes.

---

## 8. Recording script specification

The user will perform the final recording after the runner is qualified. The
implementation task must deliver a script, not leave the user to improvise commands.

### 8.1 Capture setup

- Terminal canvas: 120 columns by 34 rows, or another tested 16:9-safe grid.
- Font: a legible installed monospace with distinct `0/O` and `1/l` glyphs.
- Font size: large enough to survive a 1920x1080 render and mobile playback.
- Theme: high contrast, no transparent blur, no personal wallpaper.
- Prompt: short, deterministic, and free of username/hostname if those are sensitive.
- Shell history expansion and incidental metadata: off unless they aid proof.
- Notifications: disabled.
- Cursor: visible but not distracting.
- Secrets: loaded before `asciinema rec`; never typed while capture is active.

### 8.2 Raw terminal beats

#### Opening frame, 3-5 seconds

Show:

- `oraclemcp` name;
- exact commit or version;
- `Google ADK + Gemini on Vertex AI`;
- `Oracle Database 23ai Free`;
- `MCP stdio`.

This may be printed by the runner. It must be generated from actual environment data,
not hard-coded marketing text.

#### Beat 1, 12-18 seconds

Show:

- concise user request;
- visible ADK tool call to `oraclemcp`;
- exact result table;
- short agent answer;
- `PASS 1/3` emitted by the assertion runner.

#### Beat 2, 12-18 seconds

Show:

- exact destructive request;
- visible `oracle_preview_sql` call carrying the exact SQL;
- required `DDL` level, protected `READ_ONLY` ceiling, and non-allow gate decision;
- table existence and row-count postcondition;
- `PASS 2/3`.

#### Beat 3, 10-15 seconds

Show:

- attributable audit records without secret fields;
- `oraclemcp audit verify` result;
- chain state and record count if available;
- `PASS 3/3`.

#### Closing frame, 3-5 seconds

Show:

- exact source SHA;
- artifact checksum prefix;
- repository URL;
- `Reproduce: examples/vertex-gemini/README.md`.

### 8.3 Recording acceptance

- One continuous source capture exists.
- No cut hides a failed tool call.
- Every visible command exists in the README.
- Every visible result exists in evidence JSON.
- The recording is comprehensible without audio.
- The `.cast` duration is under 90 seconds unless evidence clarity needs more.
- The text remains readable at a 720px-wide player.
- The recording has a transcript or can expose selectable terminal text.

---

## 9. Static showcase architecture

### 9.1 Start condition

Site work starts only after G5 exits green. Before that, the only allowed site work is
planning and possibly neutral route-infrastructure work already owned by
`durakovic-ai-ybc`.

### 9.2 Canonical route

Use:

```text
https://durakovic.ai/oraclemcp/
```

Implementation should emit a real static `dist/oraclemcp/index.html`, either through
the shared route infrastructure selected and qualified by `durakovic-ai-ybc` or its
authorized successor.

The route must work with JavaScript disabled for core content. JavaScript may enhance
the terminal player and interactions, but the product statement, evidence summary,
quickstart, links, and transcript must remain in static HTML.

### 9.3 Relationship to the constellation

- Keep the `oraclemcp` constellation bubble.
- Change its primary action to navigate to `/oraclemcp/`.
- Optionally keep a small in-panel summary for returning visitors.
- Do not duplicate the full page inside the project panel.
- Preserve browser back behavior and keyboard navigation.

### 9.4 Page information architecture

#### Section S1: first viewport

Required signals:

- `oraclemcp` as the literal H1/product name;
- one-sentence category: governed Oracle access for AI agents through MCP;
- compact proof line: exact validated Google/Oracle combination and evidence revision;
- primary action: watch the real demo;
- secondary action: open GitHub;
- immediate visual evidence from the terminal recording;
- a visible hint of the next evidence section on mobile and desktop.

Do not put the hero in a floating card. The terminal recording is the primary product
visual and should be integrated into the full-width composition.

#### Section S2: the three beats

Present the run as a compact horizontal or vertical sequence:

1. `SELECT admitted`;
2. `destructive request policy-blocked`;
3. `audit chain verified`.

Each beat links to its exact evidence excerpt. Do not use vague feature cards.

#### Section S3: why agents on databases need a guard

Explain the problem in concrete terms:

- model intent is not a database authorization boundary;
- tool descriptions are not enforcement;
- prompt instructions can be bypassed or misunderstood;
- policy must execute before Oracle receives an unproven statement;
- database privileges remain defense in depth.

Avoid fear marketing and unsupported incident statistics.

#### Section S4: fail-closed architecture

Show a simple architecture band:

```text
Agent -> MCP auth -> profile ceiling -> SQL classifier -> Oracle
                         |                    |
                         +------ audit -------+
```

Explain:

- fail-closed classification;
- protected read-only profiles;
- guarded operating-level escalation for intentionally writable profiles;
- rollback-by-default DML;
- OAuth scopes as a lowering cap;
- audit hash chain.

The visual must not imply that the audit log makes unsafe SQL safe.

#### Section S5: verified compatibility ledger

Render only frozen evidence fields:

- oraclemcp version and SHA;
- MCP transport and negotiated revision;
- ADK version;
- Gemini model and Vertex region;
- Oracle version and image digest;
- evidence revision;
- exact compatibility matrix states;
- cost context;
- transcript and evidence checksums.

Never hand-copy these values into multiple components. Generate one site data module
from the reviewed evidence JSON or import a checked sanitized JSON artifact.

The ledger pairs with the §10.7 in-browser verification walkthrough: the same bundle
the ledger renders is the one the visitor's browser re-verifies.

#### Section S6: quickstart

Show the shortest safe path:

- install or build `oraclemcp`;
- configure a protected profile;
- run stdio server locally;
- point an MCP client at it;
- link to the full Gemini/Vertex example.

Do not put a real credential or make `--allow-no-auth` look appropriate for remote
HTTP.

#### Section S7: product surface

Summarize the broader product without turning the page into the README:

- two transports;
- guarded operating ladder;
- schema, source, plan, session, and audit capabilities;
- pure-Rust thin connectivity;
- optional embedded PL/SQL intelligence.

Each statement should link to the relevant README or documentation anchor.

#### Section S8: links and disclaimer

Include:

- GitHub;
- crates.io package(s) relevant to installation;
- GHCR image if actually published;
- MCP registry entry if actually live;
- documentation;
- issue tracker/contribution path;
- consulting or contact path already supported by the site;
- independent/unofficial disclaimer.

### 9.5 Metadata and discovery

The static page needs:

- unique `<title>`;
- unique meta description;
- canonical URL;
- Open Graph title, description, image, type, and URL;
- X card metadata;
- `SoftwareSourceCode` or accurately selected JSON-LD;
- breadcrumb structured data if the site convention uses it;
- sitemap entry;
- `llms.txt` entry;
- internal links from the homepage and relevant content;
- `noindex` on Cloudflare preview domains — verified absent from the site on
  2026-07-17 (no `_headers`, no `X-Robots-Tag`), so this is new work, for example a
  `_headers` rule scoped to the `*.pages.dev` preview host.

Generate the route-specific Open Graph image through the site's existing image
generation script. Do not hand-edit generated image output; extend the generator and
regenerate through the repository command.

Use product facts, not keyword stuffing.

### 9.6 Design system constraints

- Reuse `src/index.css` tokens.
- Use the existing typefaces and motion language.
- Add no CSS framework.
- Add no component framework.
- Keep card radii at 8px or less where cards are genuinely needed.
- Do not nest cards.
- Reuse the site's existing `Glyph` language and native media controls. Do not add an
  icon library solely for this page.
- Do not create decorative gradient orbs or generic cloud artwork.
- Use the real terminal media as the primary visual asset.
- Maintain restrained, work-focused information density.
- Preserve existing constellation performance on the homepage.
- Respect `prefers-reduced-motion`.
- Keep text readable at 320px width and in browser zoom up to 200%.

### 9.7 Static route implementation decision

#### Required path: shared crawlable-route infrastructure

Use the architecture landed by `durakovic-ai-ybc` if it is complete and suitable.

Advantages:

- one canonical pattern for `/conformance`, `/work`, and `/oraclemcp/`;
- shared metadata generation;
- shared sitemap and JSON-LD;
- fewer long-term build paths.

Risk:

- the route work may still be in progress or choose a heavier SSG adapter.

Decision rule:

- use the shared route architecture only after its static-HTML, metadata, and direct
  navigation gates pass;
- if `durakovic-ai-ybc` has not selected or landed that architecture, S0 is blocked
  and must finish the common route decision first;
- do not add a one-off React multi-page entry, because Vite alone still emits an empty
  client-rendered shell and would duplicate future metadata/prerender machinery.

#### Rejected option: hash-only panel

`/#oraclemcp` cannot provide distinct server-visible metadata or static content.

#### Rejected option: separate subdomain/site

It fragments navigation and deployment without solving a real constraint.

#### Rejected option: live Cloudflare proxy

It violates the static-site contract and introduces secrets, abuse controls, database
hosting, availability, and cost.

### 9.8 Deployment mechanics (verified 2026-07-18)

- Production deploys are **automatic on every push to `master`**: GitHub Actions
  builds with bun and uploads `dist/` via wrangler v4 Direct Upload (no Cloudflare
  build quota consumed; wrangler runs under Node, not bun — keep that split).
- Therefore: all S-phase work happens on a **branch**; merging to `master` IS the
  production deploy and happens only at the §11.4 operator-approved gate.
- A preview deployment is the same Direct Upload with a non-`master` `--branch`
  value (Cloudflare Pages then serves it on a `*.pages.dev` preview host — which
  is exactly the host the §9.5 `noindex` work must cover).
- The unknown-route behavior today is SPA fallback (any path serves the homepage
  document with its homepage metadata) — the reason §9.2 requires a real
  `dist/oraclemcp/index.html`, and a thing to re-verify after the route lands
  (the new route must win over the fallback, and `sitemap.xml` must gain the
  entry).

---

## 10. Embedded demo plan

### 10.1 Primary recommendation

Embed the real `.cast` using a self-hosted asciinema player, with a static transcript
and evidence links immediately below it.

Why:

- the `.cast` is compact and comfortably below Pages' asset limit;
- text remains sharp and selectable;
- playback speed and pause controls suit technical viewers;
- it is visibly a real terminal session;
- no external asciinema account or embed dependency is required;
- the static transcript remains accessible and crawlable.

Add an exact `asciinema-player` package version with `bun`, let Vite emit the
self-hosted JavaScript/CSS assets, and retain the generated `bun.lock` change. Record
the license (verified 2026-07: `asciinema-player` is Apache-2.0; GPL-3 applies to the
asciinema CLI recorder, not the web player). Do not vendor an alternate player copy or load a moving third-party CDN
URL. Lazy-import the player so the static content and transcript do not depend on it.

### 10.2 Native video companion

After the HyperFrames launch video exists, embed an optimized native video as a
separate "launch overview," not as replacement proof.

Use:

```html
<video controls playsinline preload="metadata" poster="...">
  <source src="...webm" type="video/webm">
  <source src="...mp4" type="video/mp4">
  <track kind="captions" srclang="en" src="...vtt" default>
</video>
```

Requirements:

- every source under 25 MiB;
- meaningful poster;
- captions;
- transcript;
- no autoplay with sound;
- no scroll hijacking;
- no custom controls unless native controls fail a documented need.

Cloudflare Pages currently documents non-spec `200` responses for range requests
instead of normal `206` partial responses. Keep video short and small so seeking and
initial playback remain acceptable despite that platform behavior.

### 10.3 Client-side simulation decision

Do not build a simulation for launch unless both are true:

- the real recording is already embedded;
- the simulation provides a materially better learning interaction.

If built later, call it:

> Interactive replay of a recorded run

It may let users step between read, refusal, and audit events, using frozen sanitized
events from `evidence.json`. It must not generate arbitrary SQL or imply a live Oracle
connection.

The existing `plsql.ts` panel is a visual and interaction precedent, not permission to
invent results. All replay content must be traceable to the real run.

### 10.4 Demo states

The embedded player needs:

- loading;
- ready;
- playing;
- paused;
- ended;
- asset failure with transcript fallback;
- reduced-motion mode;
- keyboard focus and controls;
- no-JavaScript transcript state.

### 10.5 Demo acceptance

- Works on current Chromium, Firefox, and WebKit.
- Works at mobile widths.
- Controls have accessible names.
- Focus order is coherent.
- Terminal text does not overflow.
- Transcript is present in static HTML.
- Real-recording label is visible.
- Exact evidence revision and versions are adjacent.
- No request is sent to an Oracle or MCP backend.
- Network inspection shows only static assets and existing analytics.
- Page remains useful if the player fails.

### 10.6 Static asset delivery rules

- Give every recording, poster, transcript, and produced-video revision a
  content-derived filename or build hash.
- Do not add long-lived custom caching to an unhashed path; Cloudflare Pages already
  manages deployment cache invalidation.
- Enforce a 24 MiB build ceiling per media file, leaving headroom below Cloudflare's
  25 MiB hard limit.
- Do not fetch the produced MP4/WebM on initial navigation; use `preload="metadata"`
  and initialize optional media only when visible or requested.
- Keep the compact `.cast` and static transcript available even when native video is
  omitted.
- Self-host player JavaScript and CSS so the page does not gain a third-party runtime
  or tracking request.
- Preserve or tighten the site's existing security headers; do not weaken a content
  security policy to permit an inline player shortcut.
- Inspect the sanitized `.cast` for terminal control sequences, URLs, paths, and
  identifiers in addition to ordinary secret scanning.

### 10.7 Verification walkthrough — in-browser re-verification of the real artifacts

The page does not merely *display* evidence; it re-verifies a defined subset of the
bundle in the visitor's browser and animates that real progress. This is NOT a
simulation (§10.3 governs the replay; this module performs actual verification of
actual bytes) and it is the site's signature interaction: "don't trust the demo —
your browser just checked it."

**Mechanism (all static, same-origin, no backend):**

1. The sanitized publishable bundle ships as static assets on the page's own origin:
   `evidence.json`, the redacted audit JSONL + head-anchor sidecar, the verdict
   certificate, and the SHA-256 checksum manifest.
2. On "Verify in this browser" (or scroll-into-view): fetch the manifest; hash every
   listed artifact with WebCrypto `SubtleCrypto` (native, zero dependencies) and
   tick each entry green as its digest matches.
3. Walk the audit chain record-by-record, animating each link as it validates.
   Two tiers, because the chain is hash-linked AND keyed-MAC signed (ADR-0003):
   hash-link continuity + head-anchor comparison are verifiable without any key;
   **MAC verification requires the run's signing key** — covered in-browser only
   if D11 (retired-demo-key disclosure) is exercised, in which case WebCrypto
   HMAC-SHA256 completes the full re-walk client-side.
4. Cross-check the verdict-certificate fields against the `evidence.json` claims
   (schema-level consistency; full certificate verification per ADR-0010 needs the
   chain MAC, so it follows the same D11 tiering), then render the verdict panel
   with counts ("N artifacts hashed · M chain links verified · anchor matched ·
   MAC: verified | CLI-only").

**Honesty rules (non-negotiable):**

- The completion label states exactly what ran, tier by tier: hashes, link
  continuity, anchor, consistency — and whether MAC verification ran in-browser
  (D11) or remains CLI-side. It does NOT cover cosign signatures, the GitHub
  attestation, or re-running the beats. The copy-paste CLI commands remain the
  canonical full verification and sit directly beneath the module.
- Fail-closed display: any mismatch, fetch failure, or unknown state renders a
  prominent red/not-verified state (mirrors V14 — unknown ⇒ not admitted). Never
  default green.
- Never call it a simulation, and never let the animation imply more than what was
  checked.

**Constraints:** same-origin static fetches only (the §10.6 network rule holds
unchanged); lazy-init; `prefers-reduced-motion` ⇒ instant results, no stepwise
animation; no-JS fallback = static transcript + CLI command block (page stays fully
useful without the module); progress announced via a polite live region; JS budget
small (SubtleCrypto + a hand-rolled chain walker; no new runtime dependencies).

**Acceptance:** deterministic (same bundle ⇒ same green) across the three browser
families and at mobile widths; a deliberately corrupted staging copy of the bundle
MUST render the red state (the client-side mirror of G4.4's tamper negative
control); module absent ⇒ page unaffected.

**Priority:** ships with S2/S3 ahead of the §10.3 replay (S4 stays the cuttable
extra). Cut rule: the animation *styling* degrades to a plain progress checklist
first; dropping the whole module is a §15.3-level cut, and the CLI verify commands
always remain.

---

## 11. Showcase implementation phases

### 11.0 Skill roster for the site phases

Mirror of §12.2's rule for video: implementers invoke the installed local skills
rather than improvising. Mapping (invoke at the phase, follow the skill exactly):

| Phase | Skills to invoke |
|---|---|
| S1 content/metadata | `seo-for-saas-businesses` (route metadata/discovery), `og-share-images` (route OG image via the existing generator), `frontend-design:frontend-design` (composition within the molten-systems language) |
| S2 embed + §10.7 walkthrough | `interactive-visualization-creator` + `dataviz` (walkthrough progress + evidence-ledger visuals), `ui-polish` (final passes only — §2.7's ship-before-polish caps the pass count) |
| S3 gates | `web-design-guidelines` (accessibility/UX review), `e2e-testing-for-webapps` (Playwright matrix), `wrangler` (preview + production deploy mechanics) |
| G5.4 sanitize / §12 captions | `redacting-sensitive-parts-of-screencast-videos`, `embedded-captions` |
| Launch assets (§13.2) | `gh-og-share-images` (repo social-preview images), `readme-writing` (root-README compatibility section) |

Skills are instructions, not authority: where a skill conflicts with the site's
AGENTS.md (bun-only, RULE 1, no frameworks) or this plan, the contracts win.

### 11.1 Phase S0: reconcile route infrastructure and tracker

**Estimate:** 2-4 hours

**Dependencies:** G5 complete

#### Tasks

- Re-read the site contracts.
- Inspect the current state of `durakovic-ai-ybc`.
- Verify that the shared crawlable-route architecture from section 9.7 is green; if
  not, keep S0 blocked on that common infrastructure.
- Update `durakovic-ai-oou` rather than create a duplicate reveal epic.
- Add child beads only after the active site owner agrees.
- Reserve exact site paths.
- Freeze the sanitized evidence JSON used by the page.

#### Exit gate

- route architecture selected;
- ownership clear;
- evidence input immutable by checksum;
- no duplicated site tracker work.

### 11.2 Phase S1: static content and metadata

**Estimate:** 6-10 hours

**Dependencies:** S0

#### Tasks

- Create real `/oraclemcp/` static content.
- Use one semantic H1, ordered heading levels, landmarks, and a keyboard-visible skip
  link for the new content route.
- Add unique metadata and structured data.
- Add sitemap and `llms.txt` entries through existing generators.
- Link the homepage bubble to the route.
- Add evidence ledger populated from one data source.
- Add quickstart and source links.
- Add independent-project disclaimer.
- Decide the i18n posture: the site now carries an i18n system (`src/i18n/`);
  `/oraclemcp/` launches English-only unless the operator opts it into localization.

#### Exit gate

- `curl` or view-source contains substantive content;
- page metadata is route-specific;
- all claims match the frozen evidence;
- all outbound links resolve.

### 11.3 Phase S2: real terminal embed

**Estimate:** 6-11 hours (embed 4-7 + §10.7 walkthrough 2-4, matching the §14.2
rows)

**Dependencies:** S1, G5 recording

#### Tasks

- Add the exact pinned `asciinema-player` package with `bun` and lazy-load it.
- Add `.cast`, transcript, and poster/fallback.
- Implement responsive sizing and lazy initialization.
- Add real-recording label and evidence links.
- Implement error and reduced-motion states.
- Implement the §10.7 in-browser verification walkthrough (lazy, fail-closed
  display, reduced-motion aware, tamper negative-control test included).

#### Exit gate

- recording loads from static assets;
- transcript works without JavaScript;
- total and per-file asset budgets pass;
- accessibility checks pass.

### 11.4 Phase S3: browser, performance, and deployment gates

**Estimate:** 4-6 hours

**Dependencies:** S2

#### Tasks

- Run site unit/type/build checks with `bun`.
- Run Playwright at desktop and mobile viewports.
- Capture screenshots and inspect overlap.
- Test with JavaScript disabled.
- Test keyboard-only use and reduced motion.
- Inspect the network waterfall: no Oracle/MCP endpoint, third-party player, or eager
  produced-video download is allowed.
- Fail the build when any media artifact exceeds the 24 MiB project ceiling.
- Check Lighthouse or equivalent budgets without turning scores into marketing.
- Deploy a Cloudflare preview (wrangler Direct Upload with a non-`master`
  `--branch`, per §9.8 — never by merging to `master`).
- Implement preview-domain `noindex` (verified absent 2026-07-17, §9.5) and confirm
  the deployed preview carries it.
- Verify `/oraclemcp/`, canonical redirect behavior, and asset MIME types.

#### Exit gate

- no layout overflow or incoherent overlap;
- no critical accessibility issue;
- static route works directly and on refresh;
- production deployment is operator-approved;
- deployed HTML matches the evidence checksum.

### 11.5 Phase S4: optional interactive replay

**Estimate:** 6-10 hours

**Dependencies:** S3

**Priority:** cuttable

#### Tasks

- Build a step-through replay using sanitized evidence events.
- Label it simulated/replayed at all times.
- Allow three fixed beats only.
- Add reset and keyboard controls.
- Ensure the real recording remains primary.

#### Exit gate

- no arbitrary query input;
- every output maps to evidence;
- simulation label cannot scroll out of contextual view;
- page remains static.

---

## 12. HyperFrames launch video plan

### 12.1 Start condition

Start only after:

- G5 engineering evidence is frozen;
- S3 showcase preview is stable enough to capture;
- the operator approves the video angle and recording assets;
- HyperFrames authentication status has been shown according to the installed skill.

### 12.2 Workflow selection

Use the installed `product-launch-video` HyperFrames workflow because this is a
product reveal, not merely a website tour.

Required skill order at implementation time:

1. `hyperframes` router;
2. `product-launch-video` workflow;
3. `media-use` before sourcing audio or images;
4. `hyperframes-core` for composition contract;
5. `hyperframes-creative` for brand direction;
6. `hyperframes-animation` and `hyperframes-keyframes` for motion;
7. `hyperframes-cli` for lint, validate, inspect, preview, and render.

The current product-launch workflow contains user approval gates for setup,
storyboard, and final render. Those gates remain mandatory.

The video lives in its own HyperFrames workspace and follows the skill's `npx
hyperframes` CLI contract. The `durakovic-ai` repository still uses `bun` exclusively;
do not run `npm`, `npx`, or introduce an npm lockfile inside the site repository. At
the workflow's frame-build step, follow its one-frame-per-worker dispatch contract and
file ownership rules instead of collapsing all frames into one monolithic edit.

### 12.3 Video objective

Make a concise evidence-led product launch video that answers:

1. What goes wrong when agents receive raw database tools?
2. What does oraclemcp enforce?
3. Does it work with a current Google agent stack?
4. Can the viewer verify the claim?

### 12.4 Master format

- Primary master: 1920x1080, 16:9.
- Target duration: 60-75 seconds.
- Language: English.
- Captions: always present.
- Narration: optional; use only if it adds clarity beyond readable terminal text.
- Source terminal footage: the real qualified run.
- Product/site captures: real showcase and repository screens.
- No fabricated UI, tool result, log, or benchmark.

### 12.5 Storyboard beats

#### Frame V1: hook, 0-7s

Message:

> Giving an agent a database tool is not the same as giving it a policy boundary.

Visual:

- real terminal/request context;
- restrained product name;
- no invented disaster imagery.

#### Frame V2: architecture, 7-16s

Message:

> oraclemcp classifies and gates each statement before Oracle execution.

Visual:

- agent to MCP to guard to Oracle path;
- protected profile and audit as distinct layers;
- no claim that the system is read-only-only.

#### Frame V3: read, 16-29s

Message:

> Gemini on Vertex AI asks; `oracle_query` returns the verified fixture result.

Visual:

- unaltered terminal capture at readable scale;
- highlight the tool call and result without changing them;
- evidence badge with exact versions and evidence revision.

#### Frame V4: refusal, 29-43s

Message:

> The same agent submits destructive SQL to the guard. Its required DDL level exceeds
> the protected profile's immutable READ_ONLY ceiling.

Visual:

- real prompt;
- real `oracle_preview_sql` call;
- real required level, profile ceiling, and gate decision;
- unchanged-table postcondition.

Do not use alarm effects or imply Oracle executed the SQL.

#### Frame V5: audit proof, 43-55s

Message:

> The run's audit chain verifies, and the artifacts are public.

Visual:

- audit verification output;
- evidence manifest and checksum;
- precise wording about which events are audited.

#### Frame V6: close, 55-70s

Message:

> Reproduce it. Inspect the guard. Run it on your Oracle environment.

Visual:

- `/oraclemcp/` page;
- GitHub URL;
- independent/unofficial disclaimer;
- no generic marketing card unrelated to the proof.

### 12.6 Asset provenance

Every storyboard frame must identify:

- source file;
- source SHA or checksum;
- whether it is a real recording, site capture, code excerpt, or generated decorative
  asset;
- what transformations are permitted;
- what text must remain verbatim.

Terminal footage may be cropped, scaled, color-corrected, and annotated. Tool output
and command ordering may not be rewritten.

### 12.7 Audio decision

The first edit should work silently. Then decide whether narration improves it.

If narration is used:

- run `npx hyperframes auth status` first and show its output;
- if it reports no sign-in, stop for the operator's explicit sign-in or offline-engine
  choice exactly as the media skill requires;
- use the approved provider path;
- keep product terms and tool names pronunciation-safe;
- transcribe with an explicitly selected model;
- use exact word timings for captions;
- keep BGM restrained below technical speech;
- use no dramatic refusal sound that makes the proof feel staged.

### 12.8 HyperFrames gates

Before final render:

- `npx hyperframes lint` passes;
- `npx hyperframes validate` passes;
- `npx hyperframes inspect` passes;
- midpoint snapshots show every scene correctly mounted;
- terminal text is readable at final resolution;
- captions do not occlude commands or results;
- `prefers-reduced-motion` concerns are addressed in the site embed, even though the
  video itself is rendered;
- the operator approves the Studio preview;
- only then run high-quality render;
- verify output exists and inspect duration with `ffprobe`;
- send HyperFrames feedback after a successful render per the skill.

### 12.9 Derived deliverables

Do not author every format independently. Derive them from the approved master:

- 60-75s 16:9 site/YouTube master;
- 45-60s X cut if the master exceeds platform attention needs;
- optional 30-45s 9:16 cut only after safe-zone review;
- 8-12s silent loop for social preview only if it remains honest;
- poster images from real frames;
- caption `.vtt` and text transcript.

Vertical and short variants are cuttable. The 16:9 master is sufficient for launch.

---

## 13. Launch strategy

### 13.0 Existing campaign sequencing gate

The current site tracker makes `durakovic-ai-oou` depend on the rust-oracledb launch
bead `durakovic-ai-6p5`. This plan does not silently remove that dependency.

The engineering integration and a quiet, directly accessible `/oraclemcp/` proof page
can be prepared independently. Public HN/X/Reddit promotion must do one of these:

1. honor the existing rust-oracledb-first campaign order; or
2. receive an explicit operator decision to rewire the site tracker after reviewing
   the campaign consequences.

Until then, treat campaign order as an external blocker on L0, not a blocker on G5 or
private/preview site verification.

### 13.1 Launch readiness gate

Do not schedule public launch until all required checks pass:

- exact oraclemcp release or commit is remotely available;
- example README reproduces from a clean environment;
- evidence JSON validates;
- terminal recording is public and checksum-linked;
- `/oraclemcp/` is deployed and crawlable;
- GitHub, registry, crates, and container links are verified live;
- independent-project disclaimer is visible;
- HN first comment and channel-specific copy are approved;
- analytics and UTM conventions are ready;
- support triage window is reserved;
- no active critical issue contradicts the headline.

The polished video is strongly preferred but not a hard gate. If video production
would delay a technically timely launch, ship the page with the real terminal
recording and publish the produced video as a second wave.

### 13.2 Core launch asset set

Required:

- canonical `/oraclemcp/` page;
- GitHub example;
- compatibility matrix;
- evidence manifest;
- real terminal recording;
- the "verify this demo" CLI command block adjacent to the embed (per §10.7 it
  always remains, at every cut level);
- HN submission title and first comment;
- X thread;
- distinct Reddit posts;
- response FAQ;
- known limitations.

Preferred:

- in-browser verification walkthrough (§10.7 — cuttable at Level 2, §15.3);
- 16:9 launch video;
- social cut;
- static Open Graph image;
- GitHub repository social-preview image;
- short technical architecture image;
- launch blog post.

Cuttable:

- vertical video;
- simulation;
- multiple blog posts;
- press kit;
- newsletter campaign.

### 13.2.1 Claim-lock artifact

Before writing channel copy, generate one reviewed `launch-facts` artifact from the
sanitized evidence bundle. It should contain:

- exact one-sentence product description;
- exact validated stack and evidence revision;
- three-beat wording;
- version and SHA fields;
- cost wording;
- known limitations;
- disclaimer;
- canonical links;
- prohibited or unproven claims.

HN, X, Reddit, the site, the root README, and video captions may vary in tone and
length, but their factual fields must derive from this artifact. A change to a fact
requires a new evidence version or an explicit editorial correction, not manual copy
drift.

### 13.3 HN plan

Candidate title:

> Show HN: oraclemcp - fail-closed Oracle access for AI agents, in Rust

The title should describe the product, not the Google brand integration. Vertex/Gemini
belongs in the first comment as current proof.

First comment structure:

1. What was built.
2. Why prompt-only safety is insufficient.
3. What "fail closed" means here.
4. The real Gemini/Vertex/23ai Free demonstration.
5. Exact evidence links.
6. Honest limitations.
7. Independent/unofficial status.
8. Specific feedback request from database and MCP engineers.

Post when the operator can answer for several hours. Do not automate comments or vote
requests. Recheck current Show HN rules immediately before launch.

### 13.4 X plan

Use a concise thread of no more than 6-7 posts:

1. Problem and one-sentence product.
2. Real read success clip.
3. Real destructive policy-block clip.
4. Audit-chain evidence.
5. Architecture and guarded-not-read-only nuance.
6. Reproduction link and limitations.
7. Call for technical feedback.

Attach native video where appropriate, but link to the canonical evidence page. Avoid
repeating unsupported superlatives.

### 13.5 Reddit plan

Do not paste the same launch copy everywhere. Recheck each community's current rules
before posting.

Potential audiences and angles:

- `r/rust`: pure-Rust MCP server, architecture, safety invariants, thin driver;
- Oracle/database communities: operator control, protected profiles, auditability,
  supported Oracle environments;
- local-LLM/MCP communities: client-neutral MCP compatibility and reproducible Gemini
  example;
- Google Cloud communities: ADK and Vertex integration lessons, not a generic product
  ad.

Each post should lead with useful technical content, disclose authorship, and link to
the most relevant artifact rather than a generic homepage.

### 13.6 Launch sequencing

Recommended sequence:

1. Quietly deploy and verify page.
2. Publish repository/example artifacts.
3. Send direct proof link to two or three trusted technical reviewers.
4. Fix only confirmed launch blockers.
5. Submit Show HN.
6. Post X thread after the HN discussion is live.
7. Post one or two carefully tailored Reddit submissions later, not simultaneously.
8. Release the polished video as the launch asset or a follow-up wave (an optional
   YouTube upload of the 16:9 master belongs in this step or in follow-up
   distribution).
9. Submit directories and newsletters through existing tracker work.

### 13.7 Support and incident handling

For the first 48 hours:

- monitor GitHub issues and discussion channels;
- answer reproducibility questions with commands and versions;
- record confirmed compatibility failures as beads;
- correct false claims publicly and on the canonical page;
- do not hot-edit evidence artifacts without a new version/checksum;
- do not rush a crates.io or registry publish to answer a comment;
- use a small FAQ for repeated questions;
- distinguish documentation failures from code failures.

### 13.8 Success measures

Primary engineering measures:

- independent reproduction succeeds;
- no material claim is retracted;
- compatibility issues are actionable and versioned;
- no safety invariant weakens;
- example support load remains manageable.

Secondary reach measures:

- qualified GitHub traffic;
- example README engagement;
- repository stars and clones as directional signals;
- substantive HN/Reddit technical discussion;
- inbound issues or contributions;
- consulting/contact conversions where already supported by the site.

Do not use view counts alone as evidence of technical success.

---

## 14. Effort estimate and sequence

### 14.1 Engineering estimate

| Work | Hands-on estimate | Cuttable |
|---|---:|---:|
| ownership and baseline | 1.5-2.5h | no |
| GCP project and cost guard | 1-1.5h | no |
| compatibility audit | 6-10h | no |
| small server fixes | 0-8h cap | only non-blockers |
| fixture and example | 8-12h | no |
| qualification and negative controls | 6-10h | no |
| recording and docs | 5-8h | no |
| contingency | additional focused reserve | no |
| **Base total, excluding reserve** | **27.5-52h** | |

This is feasible only if compatibility gaps remain small and the target oraclemcp SHA
stabilizes early. The final qualification and recording phases are protected from
feature work.

### 14.2 Post-integration estimate

| Work | Hands-on estimate | Cuttable |
|---|---:|---:|
| site route and content | 8-14h | yes |
| terminal embed and accessibility | 4-7h | yes |
| §10.7 verification walkthrough | 2-4h | yes, Level-2 cut |
| site validation/deploy | 4-6h | yes |
| optional replay simulation | 6-10h | yes, first cut |
| video storyboard and assets | 4-7h | yes |
| HyperFrames composition | 10-18h | yes |
| video review/render/variants | 4-8h | variants yes |
| launch copy and fact check | 4-7h | yes |
| launch operations | 4-8h | yes |
| **Total without simulation** | **44-79h** | |

### 14.3 Recommended sequence after integration

Treat these as dependency-ordered work blocks, not a fixed schedule. Blocks use
neutral letters (A-I) deliberately — earlier drafts reused S/V/L numbers with
shifted meanings, which collided with the phase IDs of §11-§13.

- Block A (≈ phases S0-S1): route reconciliation, content outline, evidence data
  binding.
- Block B (≈ phase S1): page implementation and static metadata.
- Block C (≈ phase S2): terminal embed, §10.7 walkthrough, responsive and
  accessibility work.
- Block D (≈ phase S3): browser/deployment gates and fact review.
- Block E (≈ video intake V0-V1): HyperFrames setup, capture, design system,
  storyboard.
- Block F (≈ V2-V3): composition, captions, checks, operator preview.
- Block G (≈ V3-V4): approved render and derived asset preparation.
- Block H (≈ LF/LC/L0): final channel copy, link verification, quiet deploy.
- Block I (≈ L1-L4): public launch and support.

---

## 15. Scope-cut ladder

### 15.1 Level 0: full program

- stdio compatibility;
- HTTP bearer compatibility;
- complete example and evidence;
- real `.cast`;
- static showcase;
- real terminal embed;
- in-browser verification walkthrough (§10.7);
- optional replay;
- 16:9 HyperFrames video;
- X cut and optional vertical cut;
- HN, X, Reddit, directory follow-up.

### 15.2 Level 1: cut optional interaction

Cut:

- client-side replay;
- custom terminal controls;
- vertical video.

Keep:

- all engineering proof;
- static page;
- self-hosted real recording;
- 16:9 video;
- launch channels.

### 15.3 Level 2: cut produced video variants

Cut:

- X-specific edit;
- vertical edit;
- decorative motion assets;
- narration if it delays review;
- the §10.7 in-browser verification walkthrough (the CLI verify commands and static
  evidence ledger remain).

Keep:

- raw real recording;
- evidence page;
- one 16:9 video if already near complete.

### 15.4 Level 3: cut produced video entirely

Cut:

- HyperFrames video before launch.

Keep:

- raw `.cast` embedded on the site;
- accessible transcript;
- static Open Graph image from the real demo;
- HN/X/Reddit copy built from evidence.

Release the polished video as a second wave.

### 15.5 Level 4: cut site from the initial integration

Cut from the initial milestone:

- all site work;
- all launch work;
- all video production.

Keep:

- Google compatibility audit;
- example;
- deterministic three-beat runner;
- evidence;
- raw terminal recording;
- README.

This is the mandatory engineering floor.

### 15.6 Level 5: emergency engineering floor

If available effort collapses:

- stdio only;
- one stable model and one region;
- local Oracle 23ai Free only;
- no HTTP lane;
- no server patch unless stdio-blocking;
- no dynamic simulator;
- no produced video;
- no site;
- one clean transcript plus machine evidence and README.

Do not cut:

- protected read-only profile;
- real `oracle_preview_sql` call containing the exact destructive request;
- postcondition query;
- audit-chain verification;
- exact version locks;
- secret review;
- honest cost wording;
- clean-SHA evidence.

---

## 16. Risk register

### R1. ADK cannot convert one or more tool schemas

**Probability:** medium

**Impact:** medium to high

**Mitigation:** audit full catalog early; use client-neutral schema normalization where
spec-correct; filter the demonstration agent only after publishing the full matrix.

**Trigger:** exception during tool discovery or model declaration.

**Fallback:** expose minimal verified tools, mark the remainder explicitly, file
upstream or server issues.

### R2. Gemini declines to call the policy-preview tool

**Probability:** medium

**Impact:** high for beat 2

**Mitigation:** explicit prompt requiring `oracle_preview_sql`; low-temperature or
equivalent stable config; the pinned release's forced function-calling configuration
(Gemini `FunctionCallingConfig` mode `ANY` with an allowed-function-names list) when
ADK exposes it; limited declared retries; machine assertion on tool name and exact
SQL argument.

**Fallback:** use a deterministic ADK programmatic turn that still routes the Gemini
agent's selected call through `McpToolset`; do not replace the agent with a raw MCP
client in the public beat.

### R3. Tool refusal terminates the ADK session

**Probability:** low to medium depending on version

**Impact:** high

**Mitigation:** select a release with the upstream MCP tool-error session fix; test
recovery during G2; pin exact version.

**Fallback:** run beats as separate clearly labelled agent sessions while retaining one
continuous terminal script. Prefer fixing a general session bug if small.

### R4. Vertex billing is not actually zero

**Probability:** medium on an existing account

**Impact:** low financially, high for claim honesty

**Mitigation:** verify trial credits; cap calls; use cheap model; record rated and billed
amounts separately; avoid "free tier" headline.

**Fallback:** operator explicitly accepts bounded small cost, or defers Vertex and runs
the Developer API fallback without claiming completion.

### R5. Target release moves during integration

**Probability:** high due to the active orchestrator

**Impact:** high

**Mitigation:** select clean SHA in G0; rebase only under owner coordination; record all
evidence against exact SHA; do not use dirty state.

**Fallback:** qualify the example against a stable commit and state it; update after the
release train rather than chasing every intermediate commit.

### R6. Audit semantics do not include the blocked operation

**Probability:** medium

**Impact:** medium

**Mitigation:** separate transcript/policy-decision proof from durable audit proof;
show read records, the head-anchor result, and chain verification; never claim more.

**Fallback:** if product policy later requires refusal audit records, plan a separate
safety-reviewed feature after the initial integration.

### R7. Oracle container startup is slow or flaky

**Probability:** medium

**Impact:** medium

**Mitigation:** pin image, use real readiness, generous bounded timeout, disk check,
clear diagnostics, warm rehearsal before recording.

**Fallback:** keep a warmed local container for recording while proving cold-start once
in qualification.

### R8. Cloudflare asset limit blocks video

**Probability:** low

**Impact:** low

**Mitigation:** `.cast` primary; encode short web video under 25 MiB; enforce build-time
size gate.

**Fallback:** omit native video or place it in R2 after separate review. Never add a
backend.

### R9. Static route duplicates current site infrastructure

**Probability:** medium

**Impact:** medium

**Mitigation:** wait for G5; reconcile `durakovic-ai-ybc`; use one static route pattern;
update existing reveal bead.

**Fallback:** defer page until the common route architecture lands.

### R10. Launch video makes evidence unreadable

**Probability:** medium

**Impact:** high for credibility

**Mitigation:** large terminal typography, real source asset, restrained annotations,
snapshot checks, operator Studio approval.

**Fallback:** use the raw terminal recording as primary and cut the produced video.

### R11. Public launch uncovers a safety bug

**Probability:** low but material

**Impact:** critical

**Mitigation:** clean-SHA gates, negative controls, protected profile, no production
database, trusted technical preview.

**Fallback:** pause launch, publish a factual correction, fix through the normal safety
workflow, version new evidence.

### R12. Trademark or affiliation ambiguity

**Probability:** medium

**Impact:** medium

**Mitigation:** text-first brand references; independent/unofficial disclaimer; no
Google or Oracle endorsement language; follow current brand asset rules if logos are
used.

**Fallback:** remove third-party logos and use plain text product names.

### R13. Channel rules or self-promotion policy changes

**Probability:** medium

**Impact:** medium

**Mitigation:** recheck rules immediately before launch; tailor each post; disclose authorship;
lead with technical value.

**Fallback:** publish through owned channels and relevant technical directories.

### R14. Evidence artifact contains a secret

**Probability:** low after controls

**Impact:** critical

**Mitigation:** isolated demo project, preloaded credentials, no terminal secret entry,
structured redaction, manual frame review, secret scan.

**Fallback:** do not publish; rotate credential; re-record from scratch; retain an
incident note without the secret.

### R15. The §10.7 walkthrough shows a false red in visitors' browsers

**Probability:** low after acceptance tests

**Impact:** high for credibility — the signature "verify it yourself" interaction
declaring the bundle unverified would be a public own-goal.

**Mitigation:** deterministic acceptance (same bundle ⇒ same green) across the three
browser families; the tamper negative-control test proves red fires only on real
mismatches; fail-state copy always points to the CLI commands as the canonical
check ("if this fails, verify via CLI"); the module is lazy and isolated, so
removing it cannot break the page.

**Fallback:** disable the module (page remains fully useful per §10.7 constraints);
the CLI verify block and static ledger carry the launch.

---

## 17. Verification matrix

### 17.1 oraclemcp gates

For any Rust code change, use the current pinned toolchain and repository-approved
resource wrapper:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Also run focused MCP, stdio, HTTP, auth, guard, and audit tests for touched surfaces.
The live repository may provide stronger exact-SHA evidence gates by implementation
time; those supersede this list.

### 17.2 Example gates

- lockfile install from clean cache;
- Python lint/format/type checks selected by the package;
- schema validation for evidence JSON;
- static no-direct-Oracle dependency check;
- DB-free mocked-event parser tests are acceptable only for parser logic;
- real Oracle 23ai Free integration, no mocks, for acceptance;
- real Vertex invocation for acceptance;
- three consecutive green runs;
- negative controls;
- secret scan;
- artifact checksum verification.

### 17.3 Site gates

- `bun install --frozen-lockfile` or current repository equivalent;
- type check;
- unit tests;
- production build;
- output-file size check;
- substantive static HTML check;
- metadata and structured-data check;
- sitemap and `llms.txt` check;
- Playwright desktop/mobile/WebKit checks;
- JavaScript-disabled content check;
- keyboard and reduced-motion review;
- link checker;
- Cloudflare preview smoke test.

### 17.4 Video gates

- HyperFrames lint;
- validate;
- inspect;
- timeline snapshots;
- visual comparison to storyboard;
- source-provenance review;
- caption accuracy review;
- operator Studio approval;
- high-quality render;
- output-size and duration verification;
- mobile legibility spot check.

### 17.5 Launch gates

- live link verification;
- fact sheet diff against evidence JSON;
- current channel-rule check;
- preview-domain noindex check;
- analytics/UTM smoke test;
- rollback/correction owner available;
- no publication action without operator approval.

---

## 18. Dependency graph

### 18.1 Program DAG

```text
G0 ownership/baseline
|-- G1 GCP/cost/model
|-- G2 ADK compatibility
|   `-- G2F fixes (only if required)
`-- G2H HTTP compatibility report (optional terminal leaf)

G1 + G2 + blocking G2F
`-- G3 fixture/example
    `-- G4 qualification/evidence
        `-- G5 recording/engineering ship
            |-- S0 site architecture reconciliation
            |   `-- S1 static page
            |       `-- S2 real recording embed
            |           `-- S3 deploy gates
            |               `-- S4 optional replay
            `-- LF launch-facts
                `-- LC channel copy

G5 + S3
`-- V0 video evidence intake
    `-- V1 storyboard
        `-- V2 composition
            `-- V3 preview/approval/render
                `-- V4 optional social variants

G5 + S3 + LC + analytics + campaign-order gate
`-- L0 launch readiness
    `-- L1 HN
        |-- L2 X
        |-- L3 tailored Reddit
        `-- L4 launch support

L2 + L3
`-- L5 optional follow-up distribution
```

There is no dependency from video completion back to engineering proof or launch
readiness. Video cannot block G5 or L0. V3 may supply an additional launch asset when
it is ready, but L0 does not require it. G2H, S4, V4, L4, and L5 are intentional
terminal leaves, not orphaned required work.

### 18.2 Cross-repository ownership

| Node | Repository | Expected paths |
|---|---|---|
| G0-G5 | oraclemcp | `examples/vertex-gemini/**`, focused docs/tests |
| G2F | oraclemcp | only confirmed/reserved server paths |
| S0-S4 | durakovic-ai | static route, shared tokens, assets, metadata |
| V0-V4 | durakovic-ai tracker; separate HyperFrames file workspace | `videos/oraclemcp-launch/**` |
| LF-L5 | durakovic-ai tracker/docs plus public channels | copy, fact sheet, analytics |

The arrows in section 18.1 express program order. They do not assume that separate
repo-local Beads databases support native cross-repository dependency edges. The
terminal engineering deliverable — phase G5 in the DAG above, bead B-G7 after
promotion (see section 19.2's mapping) — to S0/LF/V0 is an evidence handoff gate:
site/video/launch beads are promoted only after that artifact checksum is accepted,
and their descriptions retain the checksum.

### 18.3 No-cycle checks

- G5 blocks site; site never blocks G5.
- S3 contributes to video capture; video does not block S3.
- Video is preferred but is not an L0 dependency.
- Existing site route infrastructure may block S0, but oraclemcp code does not depend
  on that infrastructure.
- G2H, S4, V4, L4, and L5 terminate in compatibility-report, support, or optional
  launch artifacts and have no edge back into the critical path by design.
- Release authorization is external to this DAG and cannot be inferred from a green
  technical node.

---

## 19. Future bead conversion map

Do not create these beads while the current orchestrator is consuming the live graph
unless the operator explicitly coordinates the transition. This section preserves the
dependency graph for later conversion.

Identifiers below are conceptual until promotion. Dependencies listed between nodes
in the same repository become Beads edges. Cross-repository prerequisites become
checksum-bearing handoff acceptance, not invented native edges.

### 19.1 oraclemcp epic

**Proposed title:** `GCP/Vertex compatibility and evidence demo`

**Type:** epic

**Priority:** P1

**Description summary:** prove current Google ADK and Vertex Gemini interoperability
through MCP without weakening oraclemcp, ship a reproducible Oracle 23ai Free example,
three-beat evidence, and real terminal recording.

### 19.2 Proposed oraclemcp child beads

Bead numbering deliberately does not match phase numbering one-to-one: phase G3
splits into B-G3 (fixture/profile), B-G4 (example package), and B-G5
(runner/evidence); phase G4 becomes B-G6; phase G5 becomes B-G7. Note the three
G-namespaces in this document: goals (section 3.1, G1-G7), phases (section 7,
G0-G5), and beads (this section, B-G0-B-G7). A bare "G7" in sections 18 and 19.6
means this terminal recording/docs bead — the phase-G5 deliverable — not goal G7.
The V namespace splits the same way: §12.5's storyboard frames V1-V6 are video
*frames*, distinct from the video phase/bead nodes V0-V4 (§18, §19.4); §14.3's
work blocks use neutral letters A-I to avoid colliding with any of these.

#### B-G0 - Freeze target SHA and coordinate ownership

- Dependencies: none.
- Blocks: B-G1, B-G2, B-G2H.
- Acceptance: target SHA, current release status, reservations, baseline output.

#### B-G1 - Vertex project, model, auth, and cost guard

- Dependencies: B-G0.
- Blocks: B-G3.
- Acceptance: ADC, exact model/region, call cap, credit/cost record.

#### B-G2 - ADK MCP stdio/full-schema compatibility audit

- Dependencies: B-G0.
- Blocks: B-G3 and any B-G2F children.
- Acceptance: machine and human matrix; lifecycle, catalog, refusal, recovery.

#### B-G2H - ADK Streamable HTTP bearer compatibility lane

- Dependencies: B-G0.
- Blocks: compatibility-report completeness only; this is an intentional optional
  terminal leaf outside the required milestone path.
- Acceptance: pass matrix or precise not-tested/limitation record.

#### B-G2F.n - Confirmed MCP compatibility defect

- Dependencies: B-G2 reproducer.
- Blocks: B-G3 only if stdio-blocking.
- Acceptance: general regression test, safety review, focused and full gates.

#### B-G3 - Oracle 23ai Free deterministic fixture and protected profile

- Dependencies: B-G1, B-G2, blocking B-G2F.
- Blocks: B-G4.
- Acceptance: pinned image/digest, deterministic expected results, read-only profile.

#### B-G4 - Vertex Gemini ADK example package

- Dependencies: B-G3.
- Blocks: B-G5.
- Acceptance: locked environment, official ADK, MCP-only DB access, clean lifecycle.

#### B-G5 - Three-beat assertion runner and evidence-v1

- Dependencies: B-G4.
- Blocks: B-G6.
- Acceptance: structural tool-call checks, postcondition, audit verify, checksums.

#### B-G6 - Clean-SHA qualification and negative controls

- Dependencies: B-G5.
- Blocks: B-G7.
- Acceptance: three passes, three negative controls, fresh-shell reproduction.

#### B-G7 - Recording script, real `.cast`, and public docs

- Dependencies: B-G6.
- Blocks: no node in the local oraclemcp graph; this is the terminal engineering
  deliverable and produces the external site handoff.
- Acceptance: secret-free continuous recording, README, compatibility and evidence
  links.

### 19.3 Proposed site child beads

These should be children or refinements of `durakovic-ai-oou` and coordinate with
`durakovic-ai-ybc`.

#### B-S0 - Reconcile crawlable route architecture for `/oraclemcp/`

- Dependencies: current `durakovic-ai-ybc` state within the site graph.
- Prerequisite handoff: accepted B-G7 artifact checksum before this bead is created.
- Blocks: B-S1.

#### B-S1 - Static oraclemcp page content, metadata, and evidence ledger

- Dependencies: B-S0.
- Blocks: B-S2.

#### B-S2 - Self-host real terminal recording and transcript

- Dependencies: B-S1.
- Blocks: B-S3.
- Scope note: includes the §10.7 in-browser verification walkthrough (its Level-2
  cuttability per §15.3 is recorded on the bead, not modeled as a separate node).

#### B-S3 - Browser/accessibility/performance/Cloudflare gates

- Dependencies: B-S2.
- Blocks: B-S4, B-V0, B-L0.

#### B-S4 - Optional evidence-backed interactive replay

- Dependencies: B-S3.
- Blocks: no required node; it terminates in an optional page artifact.
- Priority: P3.

### 19.4 Proposed video beads

Track these under the site launch graph while keeping composition files in the
separate HyperFrames workspace selected by the workflow.

#### B-V0 - Freeze product-launch brief and evidence assets

- Dependencies: B-S3.
- Prerequisite handoff: the accepted B-G7 artifact checksum already recorded by S0.
- Blocks: B-V1.

#### B-V1 - HyperFrames storyboard, script, and design approval

- Dependencies: B-V0.
- Blocks: B-V2.

#### B-V2 - Compose and validate 16:9 launch master

- Dependencies: B-V1.
- Blocks: B-V3.

#### B-V3 - Operator preview approval and final render

- Dependencies: B-V2.
- Blocks: B-V4 only; the rendered master may contribute a non-gating launch asset.

#### B-V4 - Optional social variants

- Dependencies: B-V3.
- Blocks: no required node; it terminates in optional distribution assets.
- Priority: P3.

### 19.5 Proposed launch beads

Reuse the existing tracker according to each bead's actual scope:

- keep `l00`'s rust-oracledb copy intact; create a distinct oraclemcp launch-copy
  child under `oou`, or extend `l00` only if the tracker owner preserves the two
  product-specific outputs explicitly;
- split or refine `c64` so the oraclemcp distribution work depends on L0 rather than
  inheriting the rust-oracledb launch edge accidentally;
- reuse `6s0` for shared analytics and UTM infrastructure, adding only the
  oraclemcp-specific events and links;
- retain `oou` as the owning reveal bead and honor its campaign-order dependency
  unless the operator authorizes a rewire.

#### B-LF - Generate and approve the claim-lock fact sheet

- Dependencies: none within the site graph.
- Prerequisite handoff: accepted B-G7 evidence and artifact checksums before this
  bead is created.
- Blocks: B-LC.
- Acceptance: generated facts match sanitized evidence; prohibited claims and exact
  links are reviewed.

#### B-LC - Write product-specific HN, X, and Reddit launch copy

- Dependencies: B-LF.
- Blocks: B-L0.
- Acceptance: HN title and first comment, X evidence thread, distinct community
  drafts, authorship disclosure, limitations, and current rules review.

#### B-L0 - Launch readiness and campaign-order gate

- Dependencies: B-S3, B-LC, shared analytics readiness in `6s0`, and the
  existing `oou` campaign-order edge or an explicit operator rewire.
- Blocks: B-L1.
- Acceptance: canonical links, registries, analytics/UTMs, evidence checksums,
  correction owner, and operator publication approval are all green.

#### B-L1 - Submit Show HN and seed the technical discussion

- Dependencies: B-L0.
- Blocks: B-L2, B-L3, B-L4.
- Acceptance: approved title and first comment published without automation or vote
  solicitation; canonical proof links verified.

#### B-L2 - Publish the X evidence thread

- Dependencies: B-L1.
- Blocks: B-L5.
- Acceptance: channel-native thread uses claim-locked facts and the best available
  real media asset.

#### B-L3 - Publish tailored Reddit submissions

- Dependencies: B-L1.
- Blocks: B-L5.
- Acceptance: each selected community receives distinct technical framing that
  complies with its rules and discloses authorship.

#### B-L4 - Operate the launch response and correction window

- Dependencies: B-L1.
- Blocks: no required node; this is an operational terminal node.
- Acceptance: reproducibility questions are answered with evidence, confirmed gaps
  become beads, and factual corrections version the canonical artifacts.

#### B-L5 - Optional follow-up distribution

- Dependencies: B-L2, B-L3, and the oraclemcp-specific portion of `c64`.
- Blocks: no required node; this terminates in optional directory and newsletter
  distribution.
- Priority: P3.

### 19.6 Safe tracker-promotion procedure

When the operator authorizes bead conversion:

1. Re-read both repositories' current `AGENTS.md` files.
2. Fetch live bead state and reservations.
3. Reconcile this map with newly completed or renamed work.
4. Update or depend on existing site beads before creating any new site epic; do not
   overwrite rust-oracledb-specific copy or dependency edges.
5. Create only the oraclemcp epic and G0-G7 children in the oraclemcp graph.
6. Run `bv --robot-plan` and `bv --robot-insights` in oraclemcp; confirm no future
   leaf unexpectedly appears ready while the current orchestrator owns the graph.
7. After G7 closes, verify and accept its artifact checksum as the cross-repository
   handoff.
8. Only then create or refine S0-S4, V0-V4, and LF-L5 in the durakovic-ai graph,
   recording the accepted checksum in S0, V0, and LF.
9. Add the local campaign-order dependency or record the explicit operator rewire.
10. Run `bv --robot-plan` and `bv --robot-insights` separately in durakovic-ai to
    inspect cycles, terminal leaves, and ready work.
11. Flush each tracker with `br sync --flush-only` only as part of its authorized
    tracker change.
12. Do not commit or push either tracker mutation without the operator's explicit
    go-ahead.

The current planning session deliberately stops before step 1 because uncoordinated
bead creation would inject new actionable work into an active swarm.

---

## 20. Definitions of done

### 20.1 Deliverable 1: GCP x oraclemcp

Done only when:

- [ ] exact clean oraclemcp SHA recorded;
- [ ] current stable ADK and dependencies locked;
- [ ] configured Vertex model resource, returned model metadata, and region recorded;
- [ ] billing/credit context recorded honestly;
- [ ] worst-case rated cost ceiling accepted before live use;
- [ ] Oracle 23ai Free image, digest, platform, and server banner recorded;
- [ ] agent imports no direct Oracle client;
- [ ] stdio lifecycle passes;
- [ ] complete tool catalog audited;
- [ ] demo filter documented;
- [ ] beat 1 structurally calls the query tool and returns exact fixture result;
- [ ] beat 2 calls `oracle_preview_sql` with the exact SQL and receives a non-allow
  decision showing `DDL` above the protected `READ_ONLY` ceiling;
- [ ] beat 2 independently proves table and rows unchanged;
- [ ] beat 3 verifies the audit chain;
- [ ] beat 3 verifies a matching head anchor and the truncation negative control;
- [ ] audit wording matches actual emitted records;
- [ ] session cleanup is clean;
- [ ] three consecutive runs pass;
- [ ] negative controls fail;
- [ ] fresh-shell reproduction passes;
- [ ] public evidence is secret-free;
- [ ] real `.cast` and checksum exist;
- [ ] README explains reproduction and limitations;
- [ ] no release/publish action occurs without authorization.

### 20.2 Deliverable 2: showcase page

Done only when:

- [ ] `/oraclemcp/` serves substantive static HTML;
- [ ] canonical URL and route metadata are unique;
- [ ] product name is a first-viewport signal;
- [ ] real demo is visible in or immediately below the first viewport;
- [ ] claims come from frozen evidence data;
- [ ] fail-closed and guarded-not-read-only nuance is correct;
- [ ] quickstart is safe;
- [ ] exact evidence links work;
- [ ] GitHub/registry/crates/container states are verified live;
- [ ] sitemap, JSON-LD, and `llms.txt` are updated;
- [ ] homepage bubble links to the route;
- [ ] desktop/mobile/browser/accessibility checks pass;
- [ ] no backend or live endpoint exists;
- [ ] Cloudflare asset limits pass;
- [ ] preview is noindexed;
- [ ] production deployment is approved.

### 20.3 Deliverable 3: embedded demo

Done only when:

- [ ] embedded artifact is the real qualified recording;
- [ ] real/simulated state is unmistakable;
- [ ] self-hosted assets are pinned;
- [ ] static transcript exists;
- [ ] player failure falls back to useful content;
- [ ] keyboard and reduced-motion states work;
- [ ] mobile text is legible;
- [ ] no backend calls occur;
- [ ] exact run metadata is adjacent;
- [ ] simulation, if any, uses only frozen real events;
- [ ] the verification walkthrough, if shipped, verifies the real bundle, renders
  red on a tampered copy, and states exactly what it did and did not check.

### 20.4 Launch video

Done only when:

- [ ] product-launch-video skill workflow followed;
- [ ] user approved storyboard;
- [ ] real terminal footage is source of truth;
- [ ] every asset has provenance;
- [ ] no output or benchmark is fabricated;
- [ ] fail-closed wording is precise;
- [ ] lint, validate, inspect, and snapshots pass;
- [ ] captions are accurate and non-occluding;
- [ ] user approved Studio preview;
- [ ] high-quality render exists and duration is verified;
- [ ] web encode fits hosting limits;
- [ ] final transcript and poster exist.

### 20.5 Public launch

Done only when:

- [ ] fact sheet matches evidence;
- [ ] all public links are live;
- [ ] current channel rules checked;
- [ ] HN first comment prepared;
- [ ] X and Reddit copy are channel-specific;
- [ ] authorship is disclosed;
- [ ] limitations are visible;
- [ ] operator can respond during launch window;
- [ ] issue triage path is ready;
- [ ] corrections version artifacts rather than silently rewriting proof.

---

## 21. Open decisions with defaults

These do not block planning. Implementation uses the default unless current evidence
invalidates it.

### D1. Which stable Gemini model?

**Default:** cheapest stable Vertex Gemini model that passes ADK function calling in
the selected region.

**Decision time:** G1.4.

### D2. Which ADK major line?

**Default:** latest stable release when implementation begins with the MCP tool-error
session fix, pinned exactly.

**Decision time:** G2.1.

### D3. Does HTTP block launch?

**Default:** no. Stdio is required; HTTP is a compatibility-report lane.

### D4. Does the site use asciinema or video as the primary demo?

**Default:** self-hosted asciinema `.cast` as proof, native produced video as overview.

### D5. Is a simulation built?

**Default:** no for first launch.

### D6. Is narration used?

**Default:** silent-first 16:9 edit; add concise narration only after storyboard
review shows it improves comprehension.

### D7. Is a new oraclemcp release required?

**Default:** no. Use the current authorized release or exact commit. A confirmed
compatibility patch may enter the active release train, but the demo plan grants no
release authority.

### D8. Is R2 used?

**Default:** no. Fit assets within Pages limits.

### D9. Does the launch wait for the polished video?

**Default:** prefer yes, but do not delay a strong technical launch beyond its
technically useful window. The real terminal embed is sufficient.

### D10. Should the blocked event be added to the audit log?

**Default:** not as initial scope. First demonstrate and describe current semantics
honestly. A policy change requires separate threat analysis and tests.

### D11. Disclose the retired demo audit-signing key in the evidence bundle?

**Default:** yes, after publication review. The demo run uses a dedicated
throwaway key (§4.4) on a synthetic profile; the published log is pinned by the
checksum manifest, so a key-holder can forge a *different* log but can never alter
the published one. Disclosure upgrades "trust that our CLI ran the MAC check" to
"run `oraclemcp audit verify` yourself" — and lets the §10.7 walkthrough complete
the full chain re-walk (WebCrypto HMAC-SHA256) in the visitor's browser. The
recording rules are unchanged: the key never appears on screen (§6.6/§6.9 —
those rules prevent accidental *live*-key leakage; this is a deliberate post-run
act in the bundle, with an explanatory note). The key signs nothing else and is
retired at publication.

**Decision time:** G5.4 publication review.

---

## 22. Operator handoff checklist

Before assigning implementation:

- [ ] confirm target oraclemcp release/commit policy;
- [ ] confirm eligible GCP project or bounded-cost acceptance;
- [ ] identify the active NTM orchestrator and Agent Mail identity;
- [ ] reserve example paths;
- [ ] decide whether future beads may be added now;
- [ ] confirm the first milestone is engineering evidence, not full public launch;
- [ ] confirm final recording will be performed by the operator from the provided
  script;
- [ ] keep site/video tasks blocked until G5;
- [ ] keep commit, push, tag, publish, and deploy actions separately authorized.

---

## 23. Review record

The planning agent performed four structured reasoning passes in the original
planning session, followed by a fifth pass on 2026-07-17: an external ground-truth
review by a separate session against the live code and trackers. Each of the first
four passes ran the self-containment, dependency, justification, and steady-state
checks from the planning workflow. The records below describe only changes actually
made; reviews 1-4 are in-session self-review, and review 5 is the only independent
verification pass.

### Review 1: architecture and safety

**Status:** completed in-session by the planning agent.

**Focus:** fail-closed semantics, auth boundary, audit semantics, client neutrality,
exclusive access.

**Required questions:**

- Does any example bypass a safety invariant?
- Does `--allow-no-auth` have a narrow and accurately described boundary?
- Can a model-only refusal be mistaken for a server refusal?
- Does the audit claim exceed current behavior?
- Are server fixes general MCP fixes?
- Can a dirty worktree be mistaken for release evidence?

**Findings integrated:**

- Replaced the ambiguous "execution or preview" proof with the exact supported path:
  `oracle_preview_sql` receives the unchanged destructive SQL and reports DDL above
  the protected READ_ONLY ceiling.
- Removed the assumption that `oracle_execute` is advertised on a protected read-only
  profile; the repository intentionally hides unreachable tools.
- Split tool discovery into the real protected catalog and a credentialless,
  schema-only elevated catalog so full-schema compatibility cannot weaken the demo.
- Required the schema-only catalog process to unset real credentials, use a
  non-routable target, deny database-network egress, and fail on any connection
  attempt.
- Kept transcript proof separate from audit-chain proof and retained the rule against
  claiming a blocked-event audit record without exact evidence.
- Required a dedicated audit signing key plus a matching preserved head anchor, with
  content-tamper and tail-truncation negative controls.
- Retained least-privilege Oracle grants as independent defense in depth.

**Validation result:** the public demo has no writable profile, no valid credential in
the schema-only lane, no direct Oracle client, and no path that relies on a model-only
refusal. The dependency changes were local to G2/G3 and did not alter the program DAG.

### Review 2: reproducibility and cost

**Status:** completed in-session by the planning agent.

**Focus:** dependency locks, model/region drift, fixture determinism, cloud credits,
machine evidence, negative controls.

**Required questions:**

- Can a fresh engineer reproduce the run without oral steps?
- Is every external dependency pinned?
- Can missing billing data become a false zero?
- Do model prose variations break assertions?
- Do negative controls prove the harness is meaningful?

**Findings integrated:**

- Strengthened the Oracle fixture from "record the digest" to an actual
  digest-pinned Compose image, recorded platform, and captured database banner.
- Constrained the Python minor, required the exact patch in evidence, and retained
  the generated `uv.lock` as a future authorized landing artifact.
- Added a single-versioned Vertex authentication switch selected from the pinned ADK
  documentation, avoiding ambiguous legacy/new environment variables.
- Required the most specific stable model resource available and captured concrete
  response model metadata when the provider exposes only a mutable request alias.
- Added an artifact manifest that fails on checksum, size, inventory, or
  sanitization-state drift.
- Added a total model-turn ceiling, because HTTP request limits alone do not bound
  internal tool loops or SDK retries.
- Required a worst-case rated-cost calculation and operator acceptance before a live
  run, while keeping cloud cleanup operator-controlled.
- Added a requalification protocol for retired cloud models so historical evidence is
  never silently rewritten.
- Retained `pending` billing state and separate rated, credited, and billed values so
  delayed billing cannot become a false zero-cost claim.

**Validation result:** a fresh implementation agent has a pinned source SHA, Python
lock, model, region, auth contract, container digest, fixture checksum, evidence
schema, artifact inventory, and negative controls. The cloud-cost path has a bounded
local workload but is not misrepresented as a provider-enforced hard spend cap.

### Review 3: static site, accessibility, and media

**Status:** completed in-session by the planning agent.

**Focus:** real route, static-only rule, metadata, demo truthfulness, Cloudflare
limits, mobile/browser/accessibility, HyperFrames gates.

**Required questions:**

- Does core content exist without JavaScript?
- Does any asset exceed 25 MiB?
- Is the real recording primary?
- Can simulation be mistaken for live execution?
- Does video polish obscure terminal evidence?

**Findings integrated:**

- Made the shared crawlable-route infrastructure mandatory for `/oraclemcp/` and
  rejected the contradictory one-off Vite client shell.
- Retained substantive no-JavaScript content as a release gate.
- Added a 24 MiB project media ceiling below the platform's 25 MiB hard limit.
- Added content-hashed media naming and rejected custom long-lived caching on mutable
  asset paths.
- Added a network-waterfall gate that rejects a live MCP/Oracle call, third-party
  player runtime, or eager produced-video download.
- Required CSP-compatible self-hosted player assets and terminal-control-sequence
  review for the `.cast`.
- Selected an exact `asciinema-player` package through `bun`, lazy-loaded from
  self-hosted Vite output, with no player CDN or separately vendored copy.
- Kept the HyperFrames workspace and its required CLI outside the bun-only site
  repository so the two toolchain contracts do not conflict.
- Kept the selectable real recording and static transcript primary; simulation and
  produced video remain optional enhancements.

**Validation result:** the core page remains static and crawlable, media fits the Free
plan with headroom, failure states retain the transcript, and no implementation path
requires a backend, public database, or live MCP service.

### Review 4: launch operations and steady state

**Status:** completed in-session by the planning agent.

**Focus:** sequencing, scope cuts, fact consistency, channel-specific distribution,
support load, tracker integration.

**Required questions:**

- Can site or video delay the noncuttable engineering result?
- Is every launch claim sourced from one fact sheet?
- Are existing site beads reused rather than duplicated?
- Is the final DAG acyclic and independently actionable?
- Are remaining changes marginal rather than structural?

**Findings integrated:**

- Added the current rust-oracledb-first campaign dependency as an explicit external
  L0 gate instead of silently overriding the site tracker.
- Separated quiet engineering/page preparation from public promotion.
- Added one generated `launch-facts` artifact so site, README, video, HN, X, and Reddit
  can vary editorially without factual drift.
- Kept produced video preferred but non-blocking, preserving the raw recording as a
  valid first launch asset and a later video as a second distribution wave.
- Added a safe bead-promotion procedure with graph checks and an explicit rule against
  injecting ready work into the current orchestrator's swarm.
- Removed the contradictory optional-video edge from L0 and aligned V0 with its real
  G5 plus S3 inputs.
- Classified G2H, S4, V4, L4, and L5 as intentional terminal leaves.
- Mapped `l00`, `c64`, `6s0`, `oou`, and `ybc` according to their actual live scope so
  rust-oracledb copy and dependencies are not overwritten by oraclemcp work.
- Replaced assumed cross-repository Beads edges with a two-wave promotion and an
  accepted G7 artifact-checksum handoff between the repo-local graphs.
- Rechecked the DAG: G5 cannot be blocked by site/video, video has no dependency back
  into proof or launch readiness, and campaign order blocks only L0.

**Validation result:** the fourth pass produced boundary and tracker refinements rather
than a structural rewrite. The plan is at steady state for implementation planning.
The remaining external actions are target-SHA selection, GCP account selection, live
bead promotion, and operator approvals; each has a named gate and default.

### Review 5: external ground-truth verification (2026-07-17)

**Status:** completed by a separate review session, read-only, against oraclemcp
HEAD `6aa3174` (`release/v0.9.0`; version 0.9.0 documented in the changelog but not
yet tagged), the durakovic-ai repository with its live `.beads` tracker, and current
upstream documentation.

**Verified and held:**

- Beat-2 acceptance field names are code-exact: `oracle_preview_sql` returns
  `required_level`, `profile_ceiling`, `protected`, `gate_decision`
  (`allow`/`require_step_up`/`blocked`/`unknown`), and `execute_confirmation`.
- Protected profiles hide `oracle_execute` from `tools/list`; visibility is gated on
  both the current session level and the effective ceiling.
- `oraclemcp audit verify` exists with record counts, robot JSON, the `.anchor`
  head-anchor sidecar (fail-closed on an invalid anchor, advisory when absent — so
  the runner's anchor-presence requirement stands), and the 32-byte key floor.
- Refusals never reach the hash-chained audit log; they flow to a separate
  observer-only refusal corpus. Section 2.3 upgraded from caution to verified fact.
- The `oou -> 6p5` campaign-order edge is real and correctly directed; `l00` and
  `6s0` sit upstream of the rust-oracledb launch, `c64` downstream.
- All section 2.4 site facts hold; `durakovic-ai-ybc` is in_progress and the site is
  a single-index SPA today, so section 9.7's blocking rule is active.
- The `adk.dev` documentation URLs are live and match the assumed `McpToolset` /
  `StdioConnectionParams` / `StreamableHTTPConnectionParams` APIs; Cloudflare Pages
  limits, the $300/90-day trial, and asciinema-player's Apache-2.0 license check
  out; ADK MCP session/error fragility is confirmed by open upstream issues.

**Corrections applied in place:** nine library crates, not eight (2.2); refusal
semantics stated as verified fact (2.3); OCI non-goal made explicit — 0.9.0 ships
working OCI support, but a live ADB demo stays out of this milestone (3.2);
schema-only lane made concrete with `ADMIN` default/ceiling and set-but-invalid
credentials (5.4); known schema-conversion hotspots pre-seeded (5.4); nonexistent
audit-inspection tool removed from the demo filter (5.6); beat-1 classification made
directly observable via a symmetric preview (6.4); beat-2 gate-decision field named
exactly (6.5); refusal corpus allowed as labeled supplementary evidence (6.6);
evidence output directory added to the layout (4.6); `v0.9.0`-tag default (G0.2);
ADC quota-project step (G1.2); Vertex express-mode check (1.4, 2.6); forced
function-calling mitigation (R2); preview `noindex` converted from confirmation to
implementation work (9.5, 11.4); i18n posture decision added (11.2); GitHub
social-preview image added (13.2); asciinema-player license recorded (10.1); G5/G7
naming mapped explicitly (18.2, 19.2); arithmetic and typo fixes (14.1, R5, 13.6).

### Final workflow validation

**Self-containment test:** the schema-only full-catalog lane was selected as the
least-obvious task. Its inputs, process isolation, denied network boundary, expected
output, failure condition, and relationship to the protected demo lane are all
specified without relying on oral context.

**Dependency test:** every required engineering node is reachable from G0; G5 is the
only bridge into site work; S3 and G5 are the only inputs to video intake; launch has
named evidence, copy, analytics, and campaign-order gates; and G2H, S4, V4, L4, and
L5 are intentional terminal leaves. No required node depends on an optional node,
and no cycle was found.

**Justification sample:** stdio is the launch transport because it matches the local
ADK client path with fewer auth variables; the protected profile is required because
the demo must prove policy rather than model discretion; the schema-only process is
separate because catalog coverage must not create a writable demo; the shared static
route is required because core content and metadata must be crawlable; the `.cast` is
primary because it preserves selectable real terminal evidence; and video is
non-blocking because presentation work cannot delay engineering proof.

**Steady-state test:** the final pass found local route, video-edge, optional-leaf, and
tracker-scope inconsistencies. Correcting them did not change the program's core
architecture, engineering floor, or scope-cut order. The plan is review-complete but
not tracker-active; bead conversion remains deliberately deferred while the live
orchestrator owns actionable work.

---

## 24. Primary references to recheck during implementation

- Google ADK MCP tools documentation:
  `https://adk.dev/tools-custom/mcp-tools/`
- Google ADK Gemini/Vertex model documentation:
  `https://adk.dev/agents/models/google-gemini/`
- Google ADK Google Cloud setup:
  `https://adk.dev/get-started/google-cloud/`
- Google ADK Python releases:
  `https://github.com/google/adk-python/releases`
- Google Cloud Free Program:
  `https://docs.cloud.google.com/free/docs/free-cloud-features`
- Vertex AI generative AI pricing:
  `https://cloud.google.com/vertex-ai/generative-ai/pricing`
- Cloudflare Pages limits:
  `https://developers.cloudflare.com/pages/platform/limits/`
- Cloudflare Pages route serving:
  `https://developers.cloudflare.com/pages/configuration/serving-pages/`
- asciinema player quick start:
  `https://docs.asciinema.org/manual/player/quick-start/`
- MCP specification:
  `https://modelcontextprotocol.io/specification/`

Primary documentation is evidence for upstream support, not proof that the selected
versions interoperate. The live compatibility run remains authoritative.

---

## 25. CI/CD release-pipeline speedup plan (appended 2026-07-17, fresh-eyes audit)

Read-only analysis of both repos' workflows plus per-step timings pulled from real
runs via the GitHub API. Nothing here is applied yet: an RQ run for the current
0.9.0 candidate was in progress at analysis time, and the files this section edits
ARE the release evidence chain — apply only after the current release ships, in the
tranche order of §25.7.

**Status (durable facts as of 2026-07-18; this block deliberately does NOT track
the live attempt — check `gh run list --workflow release.yml` for that):** the
driver RQ run went GREEN (2h13m — confirming the measured green-path estimate)
and driver `v0.8.4` is tagged. **The server `v0.9.0` release SHIPPED (2026-07-18,
fully published — see §29)** after a multi-attempt retry loop (the tag was
re-pointed 04e61b0 → 5931ab1 — the same-tag re-run pattern §27.2's C9 runbook
prescribes, not a version burn). Tranche 1 is therefore **unblocked**: the
§25.7.1 zero-workflow-edits-during-release hold is lifted (§29.6).

### 25.1 Measured current state

Driver `rust-oracledb` **Release Qualification** (the dominant sink) — one green
pass is ~2h15m+, a serial 3-stage chain (run 29576002422 measured):

| Stage | Wall clock | Content |
|---|---|---|
| `quality (release-qualification/release)` | 79 min | one serial ~40-step mega-job (`_quality.yml`) |
| `emit exact required proof` | 30 min | re-runs the ENTIRE Required graph a second time (`verify_required_local.sh`) |
| `emit exact version-matrix evidence` | 25–45 min green | 5 live lanes (xe11/xe18/xe21/free23/octcps) run SERIALLY on one 2-core runner with 4 Oracle containers up at once |

Inside the 79-min quality job (warm Swatinem cache), per-step timings:
**Fuzz targets 45.1 min** (22 targets × 120 s serial + uncached ASan build),
**perf regression gate 13.3 min** (3× criterion best-of-N), standalone-package
build 5.0, musl size gate 5.0, semver-checks 3.0. Everything else — clippy,
workspace tests, cassette, cargo-hack powerset — is under 2 min each when cached.
The two evidence jobs also ran back-to-back instead of in parallel (runner-slot
contention under swarm load), so the live matrix sits behind a ~110-min prefix.

The error-to-error loop, observed 2026-07-17: six RQ dispatches — cassette replay
(12 min), cassette replay again (12 min), perf gate (29 min), feature powerset
(6 min), powerset again (6 min), then a 1h58m run that passed all of quality and
died 8 minutes into the live matrix. Each fix reveals the next gate because the
mega-job aborts at the first failing step.

Server `oraclemcp` release (tag): 82 min green (run 28981428531), nearly fully
serial: web-build 0.5m → release gates 12.5m → **release-acceptance 36.5m** →
7-target build matrix 14m → crates.io 9m → GH release 1m → GHCR 8m → MCP registry.
oraclemcp PR/main CI is already fanned out (15–37 min) and is not the problem.

### 25.2 P0 — collapses the loop and the critical path

1. **P0.1 — Split `_quality.yml` into a parallel job matrix with
   `fail-fast: false`** (callers: all FOUR — `required.yml`, `canary.yml`,
   `soak.yml`, `release-qualification.yml`; the split must preserve the
   profile/budget conditionals for canary/soak or give those two their own
   composition). ~6 jobs sharing the
   cache key: (a) core suite ~10m; (b) contracts + ledgers + scans ~5m;
   (c) powerset + preflight ~5m; (d) semver + deny + package + standalone ~10m;
   (e) musl gate ~6m; (f) perf gate 13m; (g) fuzz (item 2). All of the first five
   2026-07-17 failures would have surfaced in ONE dispatch. Critical path 79 →
   ~15–20 min. Coupling: `verify_required_local.py` parses `_quality.yml` and
   hard-errors on shape drift (correctly fail-closed) — update it in the SAME PR;
   `test_verify_required_local.sh` pins the contract.
2. **P0.2 — Fuzz: shard 4-ways + cache the ASan build.** 22 targets round-robin across a
   `shard: [0..3]` matrix; add `crates/oracledb-protocol/fuzz -> target` to the
   rust-cache workspaces (the fuzz crate is a non-workspace crate, rebuilt from
   scratch every run today). 45 → ~12–14 min at the unchanged 120 s/target budget.
3. **P0.3 — Stop running the suite twice.** RQ quality at release budget is a strict
   superset of the Required graph, yet `emit-required-proof` re-executes it for
   30 min. Either (a) assemble the proof from per-job evidence uploaded by the
   split jobs (extend `verify_required_local.py`), or (b) minimal edit: drop
   `needs: release-qualification` so the proof runs in parallel — same
   runner-minutes, off the critical path, proof stays independently re-executed.
4. **P0.4 — Take the live matrix off the synchronous critical path.**
   (a) Reuse what already runs: `version-matrix.yml` already executes the full
   4-lane live suite on every push to main touching `crates/**` (or
   `Cargo.toml`/`Cargo.lock`/the matrix script/its own workflow file), one
   runner per lane. Make those lanes (+ octcps) emit the exact-SHA `results-$SHA.json`
   artifact that `verify_release_exact_sha.py` consumes; RQ's matrix job becomes
   download-if-exists / run-only-if-missing. For any candidate that went through
   main (preflight requires it anyway), the matrix costs ZERO minutes at
   qualification time. (b) When it must run fresh: remove
   `needs: release-qualification` (it consumes nothing from quality) and convert
   `release_matrix_gate.sh`'s serial 5-lane loop into a 5-lane job matrix
   (`fail-fast: false`, one DB container per runner — also removes the
   4-Oracle-containers-on-one-2-core-runner memory pressure) + a merge job.
   Matrix failures surface at minute ~15 instead of ~110. This is NOT a demotion
   to nightly: the matrix stays a hard pre-tag gate (TSTZ/CLOB/prefetch bugs were
   only caught live) — it just stops being re-run when green exact-SHA evidence
   already exists.

Net P0: RQ green path ~2h15m+ → **~20–25 min**, and fix loops collapse from N
full re-dispatches to typically one.

### 25.3 P1 — oraclemcp tag pipeline and resilience

1. **P1.1 — Overlap the 7-target build matrix with the acceptance suite**
   (`release.yml`): `build.needs` → `[checks, pinned-nightly, web-build]`; add
   `release-acceptance` to `publish-crates.needs`. Saves ~14 min; publishing
   still gated on everything.
2. **P1.2 — Trim the 36.5-min acceptance suite:** release.yml invokes it WITHOUT
   `--skip-feature-powerset`, re-running the cargo-hack powerset that CI already
   ran green on the same SHA (ci.yml already demonstrates the skip pattern).
   Pass the flag; optionally split the suite's independent legs (clean-machine
   e2e, rollback dry-run, doctor fixtures) into parallel jobs. ~10–15 min.
3. **P1.3 — Run-once for oraclemcp tag gates:** `checks` re-runs fmt/clippy/full
   test/doc on a SHA whose main-push CI is green. Adopt the driver's exact-SHA
   evidence-artifact pattern (preferred, symmetric) or verify required check-runs
   green via the API. ~10 min.
4. **P1.4 — cargo-nextest in both repos** — mainly for flake containment: per-test
   `retries` in `.config/nextest.toml` marks tests flaky instead of aborting a
   2-hour run; per-test timeouts stop hangs; JUnit timing history hunts the
   flaky cancellation tests. Keep live lanes serial (`-j1`/test-groups);
   doctests stay `cargo test --doc`.
5. **P1.5 — Cold-cache insurance:** `_quality.yml` installs cargo-hack /
   cargo-public-api / cargo-semver-checks via `cargo install` — no-ops warm, but
   5–15 min EACH compiled from source on a cold cache. Switch to
   `taiki-e/install-action` pinned versions (as cargo-deny/cargo-fuzz and all of
   oraclemcp already do).
6. **P1.6 — RQ dispatch hygiene:** per-candidate-SHA concurrency groups with
   `cancel-in-progress: false` leave superseded runs burning runner slots (why
   the "parallel" evidence jobs queued serially). Single-flight
   `group: release-qualification` with `cancel-in-progress: true`, or cancel
   superseded runs at dispatch. Never cancel the run feeding an imminent tag.

### 25.4 P2 — smaller/optional

- Perf gate becomes near-critical-path after P0; `PERF_SAMPLES=2` env knob
  exists if it ever bites (slightly weaker noise floor).
- Larger runners (8-core) for quality-core / fuzz shards / DB lanes — money for
  roughly half the time.
- oraclemcp `docker` job (8 min) rebuilds in BuildKit; COPYing the already-built
  + attested musl artifact would cut to ~2 min — only if the image provenance
  story stays coherent (attests repackage, not build-from-source).
- Trim `fetch-depth: 0` where main-ancestry isn't checked; drop the
  `apt-get install ripgrep` step (preinstalled on ubuntu-latest — verify once);
  add `actionlint` to the cheap contracts job.

### 25.5 The meta-problem: one prep run that collects ALL failures

- P0.1's `fail-fast: false` fan-out does most of it structurally.
- Add `mode: prep|strict` dispatch input to RQ: prep runs every gate with
  `continue-on-error: true` + a final aggregation job (job-summary table of
  every red gate). Prep runs MUST NOT emit qualification artifacts (or stamp
  them `"mode": "prep"` so `verify_release_exact_sha.py` rejects them) — the tag
  gate stays exactly as strict.
- `--no-fail-fast` (or nextest) inside test steps so one run reports all failing
  tests.
- Workflow: one prep dispatch → fix the complete list in one commit → one strict
  RQ on the final SHA → tag. The 2026-07-17 six-dispatch ~3h day becomes two
  dispatches, ~50 min. Cheapest prep run of all remains local:
  `scripts/verify_required_local.sh` (driver) / `scripts/local_release_gate.sh`
  (server) before dispatching — zero CI edits, available today.

### 25.6 Keep as-is (load-bearing — do not cut)

- The exact-SHA immutable-evidence chain (`release_matrix_gate.sh` artifact →
  `verify_release_exact_sha.py`). Design is right; only its scheduling was wrong.
- The live version matrix as a hard release gate (real bugs — TSTZ descriptor,
  CLOB-as-LONG desync, stranded prefetch — were only caught live). Reuse and
  parallelize; never demote to advisory.
- `verify_required_local.py`'s fail-closed parser (protects the P0.1 refactor).
- The cheap always-on gates: cargo-deny, secret scans, API ledger/baseline
  drift, golden discipline, semver-checks, SBOM drift (≤3 min each).
- oraclemcp publish ordering (crates.io → GH release → GHCR → MCP registry,
  idempotent) and `cancel-in-progress: false` on main (cache-save rationale).
- Advisory scheduled lanes (canary/soak/tsan/multi-nightly/kani/mutation) as
  non-blocking.

### 25.7 Sequencing — explicitly NOT immediate

1. **During the current release: zero workflow edits.** Use the local gates as
   the prep run.
2. **Tranche 1 (same day the release ships, ~1 h, near-zero risk):** the pure
   scheduling edits — P0.3(b), P0.4(b) needs-removal, P1.1, P1.2 flag, P1.5
   installs, P1.6 concurrency. Alone: ~55–70 min off the critical path.
3. **Tranche 2 (its own reviewed change, ~a day):** `_quality.yml` split +
   `verify_required_local.py` update in one PR, fuzz shards, prep mode. Verify
   with a throwaway RQ dispatch before trusting it.
4. **Tranche 3 (optional):** matrix evidence-reuse (P0.4a), oraclemcp exact-SHA
   symmetry (P1.3).

---

## 26. Repository hygiene and structure audit (2026-07-17, read-only)

Full-repo sweep of `oraclemcp` (primary) plus a compact `rust-oracledb` pass:
git state, deletables, renames, structure, quality. **Nothing was executed; every
item below is a proposal, and all destructive items are operator-gated and
deferred until the current 0.9.0 release ships.** Severities follow the audit
convention (Critical / High / Medium / Low).

### 26.1 Git state — oraclemcp

- **[High → RESOLVED 2026-07-18] 112 unpushed commits on `main`** (was
  `origin/main: ahead 112`, `release/v0.9.0` without upstream). Since resolved by
  the release train: main is 0 ahead of origin and the `v0.9.0` tag is pushed
  (re-pointed at least once during the retry loop, 04e61b0 → 5931ab1 — same-tag
  re-runs per the §27.2 C9 runbook; it may move again until the train lands).
  Kept for the record — this was the audit's only urgency-class item.
- **[High, safe to do] 21 leftover agent worktrees + branches, ALL merged into
  main** (exact counts verified: 21 worktrees under `.claude/worktrees/`, 21
  `worktree-agent-*` branches, and `git branch --merged main` lists all 21).
  `.claude/worktrees` holds 1.2 GB. Action: `git worktree remove` each +
  `git branch -d` (−d, not −D — it only deletes merged). Pure swarm residue.
- **[Medium] 14 stashes** (13 at first audit; ticked to 14 by 2026-07-18 swarm
  churn), mostly "temporary OCI local-driver override" variants
  (stash@{0}..{7}) plus three "bead export not committed" stashes. The OCI
  overlay work has since been committed properly (current dirty tree is the live
  version of it). Action: stash-janitor triage after the release — inspect each
  with `git stash show -p`, expect near-all droppable; the bead-export ones
  should be diffed against `.beads/issues.jsonl` first.
- **[Low] Dead branch `master`** at "Initial commit" (a5f7e66). Delete.
- **[Low] Dead tags v0.6.2–v0.6.5** (metadata-gate retries; only 0.6.0/0.6.1/
  0.6.6 published). Delete locally and on origin after confirming no GitHub
  Release object is attached to them.
- **[Low] Branch-naming inconsistency:** `release-0.8.1` (worktree
  `~/projects/oraclemcp-rel081`) vs `release/v0.9.0`. Standardize on
  `release/vX.Y.Z`; retire the rel081 worktree+branch once 0.8.1 is historical.
- Working tree was dirty with in-flight release work (14 modified files + new
  `infra/oci-adb/.gitignore`) at audit time. **[RESOLVED 2026-07-18]** — the OCI
  work landed, the tree is clean, `v0.9.0` shipped and fully published (§29), and
  `main` is synced with origin.

### 26.2 Disk bulk — oraclemcp (untracked, reclaimable ~50 GB)

| Path | Size | Verdict |
|---|---|---|
| `target/` | 42 GB | prune (`cargo clean` or age-based sweep) after release |
| `crates/oraclemcp-core/target/` | 4.9 GB | **stray NESTED target dir** (tool ran cargo with cwd inside the crate); delete |
| `crates/oraclemcp-db/target/` | 908 MB | same; delete |
| `.claude/worktrees/` | 1.2 GB | removed by the worktree cleanup above |
| `infra/` | 279 MB | terraform providers/state cache; keep, now ignored |
| `web/` (mostly `node_modules`) | 253 MB | legit, regenerable via `npm ci` |
| root `node_modules/` | 20 KB | stray `.vite` cache stub at repo root (should not exist — web/ owns its own); delete |
| `.beads/.br_history/` | 220 MB | br history churn; prune per br retention (keep `beads.db` + `issues.jsonl`) |
| `target-go-cache/` + `target-go-path/` | 98 MB | Go toolchain leftovers from a one-off tool; delete |
| `beads_compliance_audit/` | 39 MB | skill-managed, ignored; regenerable — delete when idle |
| `todelete/` | 27 MB | policy-correct quarantine (confidentiality rule); keep as-is |
| `.ruff_cache/`, `.claude-tmp/` | small | delete; add `.ruff_cache/` to .gitignore if it recurs |

### 26.3 Tracked-content triage — oraclemcp (740 tracked files)

- **[Low] npm channel remnants, one decision left:** the retirement is already
  mostly coherent — release.yml carries NO npm job today (the "validate npm
  wrapper package" job existed only in the 0.8.0-era pipeline), and
  `publish-npm.yml` is a deliberate dispatch-only "Retired npm wrapper guard"
  that refuses publication with a retirement message (exit 1). What remains is
  the tracked `npm/oraclemcp/` wrapper sources (4 files) that nothing builds or
  ships while AGENTS.md states "No npm/npx channel is offered." Recommend:
  delete `npm/`, keep the guard workflow as the explicit tombstone.
- **[Medium] Root plan monoliths:** `docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md` (78 K),
  `docs/plan/PLAN_0_5_0_STABLE_RELEASE.md` (61 K), `docs/plan/PLAN_0_6_0_INTERACTIVE_ALWAYS_ON.md`
  (239 K), and `docs/plan/PLAN_ASUPERSYNC_THIN_NATIVE.md` (72 K) are under
  `docs/plan/` with the newer plans after the C5 `git mv` pass (history
  preserved).
- **[Low] `.skill-loop-progress.md`** at root — tracked residue of a completed
  skill loop (extreme-software-optimization, 2026-07-02). Delete.
- **[Low] `refactor/`** (6 tracked files, untouched since 2026-06-15) — review,
  then delete or fold into docs; likely a finished campaign's scratch.
- **[Low] docs naming split:** `docs/` mixes UPPERCASE
  (`bead-close-evidence.md`, `entry-trace-contract.md`, `required-local-proof.md`,
  `resource-budget.md`, `toolchain.md`) with kebab-case (20 files). Pick
  kebab-case, rename the five (update inbound references — several scripts grep
  these paths).
- **[Low] Tracked `.log` files vs `.gitignore`:** ~20 perf-campaign raw logs
  under `tests/artifacts/perf/**/raw/` are tracked while `*.log` is ignored
  (force-added). They are deliberate evidence (the whole tracked
  `tests/artifacts` tree is 804 KB — fine); make the
  intent visible with an explicit `!tests/artifacts/**/*.log` allowlist line.
- **[Low] `docs/release-surfaces.md` has 0600 permissions** (every other doc is
  0644) — normalize.
- README.md is 71 KB — P2: split into a lean front page + linked docs.

### 26.4 Structure and code quality — oraclemcp

Ten workspace members — the `oraclemcp` binary plus nine library crates,
consistent with §2.2's count (`oraclemcp-verifier` is the 0.9.0-cycle addition):
error, telemetry, audit, guard, verifier, config, db, auth, core, oraclemcp.
Layout is clean; the issue is file-level monoliths. Top offenders by line count:

| File | Lines |
|---|---|
| `crates/oraclemcp/src/dispatch/tests.rs` | 14,887 |
| `crates/oraclemcp/src/dispatch/mod.rs` | 14,569 |
| `web/src/app/App.tsx` | 9,672 |
| `crates/oraclemcp-db/src/connection.rs` | 8,023 |
| `crates/oraclemcp-guard/src/classifier.rs` | 7,431 |
| `crates/oraclemcp/src/main.rs` | 6,558 |
| `crates/oraclemcp-core/src/lane.rs` | 5,492 |
| `crates/oraclemcp/src/service_lifecycle.rs` | 5,485 |
| `crates/oraclemcp-core/src/doctor.rs` | 4,282 |
| `crates/oraclemcp-core/src/http/operator.rs` | 4,220 |

80.6 k lines in ten files. This contradicts the enforced D15
design-for-cheap-change principle. Proposal: a dedicated de-monolith campaign
(the isomorphic-split skill + seam-proof method already exists in-house), one
file per bead, `dispatch/mod.rs` + `App.tsx` first (highest churn), and a
**max-file-size ratchet added to `oraclemcp_arch_fitness_lint.sh`** so files
cannot regrow past their split size. Positive signals worth keeping: exactly
1 TODO/FIXME across all crate sources; api/ baselines, ADRs (11), and the
conformance/provenance registers are in excellent shape.

### 26.5 rust-oracledb (compact pass)

- **[Resolved 2026-07-17 — STALE, safe to delete]** branch
  `worktree-agent-a7b0dcf7620795ade` (commit 112c794, 2026-07-13 — "arrow: TSTZ
  divergence doc+test, null-by-describe guard, INTERVAL DS support") initially
  looked like unharvested work (`git cherry` shows `+`, 1 ahead / 99 behind).
  Content-level audit shows it is fully superseded by the later etib series on
  main and partly DELIBERATELY REVERSED — do NOT harvest:
  - TSTZ #596: the branch kept an instant-preserving (UTC-normalized) Arrow
    mapping and ledgered it as an intentional divergence; main's eee7599
    (etib.1, 0.8.3) took the opposite decision — wall-clock tz-naive matching
    upstream — and the current PARITY_LEDGER.md #596 entry explicitly calls the
    branch-era mapping "a divergence we introduced — NOT immunity".
    Cherry-picking the branch would reintroduce the rejected semantics.
  - INTERVAL: the branch mapped INTERVAL DS → `Duration(Nanosecond)`; main's
    e0be7e8 (etib.6) implements the upstream-faithful `IntervalMonthDayNano`
    mapping (converters.pyx parity) AND adds YEAR TO MONTH, which the branch
    lacked.
  - null-by-describe #597: main's a1aa2ba (etib.5) + current
    `arrow_columnar_diff.rs` carry the all-null row-sync guards plus live
    variants and cursor-leak tests — strictly more coverage than the branch.
  - The worktree itself is clean (no uncommitted changes). Deletion needs
    `git branch -D` (unmerged in git terms) — justified by this analysis.
  The other ahead branch (`worktree-agent-a266afe39ba8f6f2a`, a7e8e63) is
  cherry-equivalent in main (`git cherry` shows `-`) — safe to delete.
- **[Medium] Merged residue:** `fp-aq`, `fp-cqn`, `fp-tpc` and two
  worktree-agent branches are fully merged → delete branches + remove the four
  `.claude/worktrees/*` worktrees.
- **[Low] Local branch is named `master` but tracks `origin/main`** — rename
  local to `main` (`git branch -m master main; git branch -u origin/main main`).
- **[Low] 2 stashes** (`wip-p5h-halted`, "failed split 5 request rows API
  drift") — triage, likely droppable.
- **[Low] Untracked matrix artifacts:** six
  `tests/artifacts/version_matrix/versions-*.json` files sit untracked; add the
  pattern to `.gitignore` (the exact-SHA evidence lives in CI artifacts, not the
  tree — by design).
- **[Low] Root plan clutter:** `plan.md`, `CODEX_GOAL.md`,
  `PLAN_TO_PORT_PYTHON_ORACLEDB_THIN_TO_RUST.md` tracked at root → move under
  `docs/` for symmetry with oraclemcp.
- `reference/` (175 MB) is the gitignored clean-room python-oracledb checkout —
  correct as-is, pinned by `scripts/pin-reference.sh`.

### 26.6 Execution order and guardrails

1. Ship the current release first; none of this touches the release path.
2. Push main/release branches (26.1 item 1) — DONE 2026-07-18 (main 0 ahead,
   v0.9.0 tag pushed).
3. Driver harvest question is CLOSED (26.5 item 1 resolved as stale — the a7b0
   branch is superseded/reversed by the etib series; no harvest, delete with
   `-D` during the janitor pass).
4. One janitor pass per repo for worktrees/branches/stashes: print the full
   dry-run list, get operator ack, then delete merged-only (`-d`, never `-D`
   without review). dcg will block the blunt destructive forms — work with it,
   not around it.
5. Disk pruning (26.2) is safe any time the swarm is idle; nested
   `crates/*/target` dirs first (5.8 GB for two deletes).
6. Tracked-content moves/renames (26.3) as one reviewed "repo-janitor" commit on
   a branch, after the release train quiesces — several scripts grep exact doc
   paths, so run the full local CI gate before pushing (per standing operator
   feedback).
7. De-monolith campaign (26.4) is its own beaded program, not a cleanup commit.

### 26.7 Re-verification and gitignore commit-hazards (2026-07-18)

Re-ran the full git-state + stale-bead sweep across both repos; the §26.1/§26.5
audit **still holds unchanged** — oraclemcp carries 21 `worktree-agent-*` worktrees
(all merged into `main`) plus the dead `master` "Initial commit" branch and
`release-0.8.1`; rust-oracledb carries 4 agent worktrees plus `fp-aq`/`fp-cqn`/
`fp-tpc`, all merged into master except `worktree-agent-a7b0dcf…` (unmerged **and**
superseded per §26.5) and `a266…` (cherry-equivalent). Dead tags v0.6.2–v0.6.5 and
the `master`/`release-0.8.1` branches all still present; only drift is the oraclemcp
stash count ticking 13→14 (swarm churn, still all triageable-droppable). Nothing
regressed; the janitor plan (§26.6) is current. Two NEW findings the earlier pass missed, both real
commit-hazards (agent state can leak into a commit) rather than mere clutter:

- **[Medium — NEW] oraclemcp: `.codex/` + `codex.mcp.json` are untracked AND
  unignored.** The pending `.gitignore` edit adds `cursor/factory/gemini/opencode/
  windsurf` `*.mcp.json` but **omits `codex.mcp.json`**, and `.codex/` (Codex agent
  state) is not ignored at all — `git check-ignore codex.mcp.json .codex/` returns
  exit 1 for both. Fold into the *same* `.gitignore` edit before it lands: add
  `codex.mcp.json` to the mcp-json block and `.codex/` beside `.claude/`/`.ntm/` in
  the "Agent state (never commit)" block. Otherwise a stray `git add -A` commits
  Codex agent state — the exact class of leak the mcp-json ignores exist to prevent.
- **[Medium — NEW] rust-oracledb: `.gitignore` is missing `.claude/` entirely.**
  oraclemcp ignores `.claude/` ("Agent state — never commit"), but the driver repo
  does not (`git check-ignore .claude/` → exit 1), so `.claude/worktrees/` shows as
  untracked today and a blanket `git add` would commit four agent worktrees' state.
  Fix: add the same "Agent state (never commit)" block (`.claude/`, `.ntm/`) to the
  driver's `.gitignore` — the driver-side twin of the server rule.

**Stale-bead ledger — re-confirmed against reality (discharges the §29.2 "verify"
qualifiers).** Every false-open finding was checked against the tree today:
`asupersync = 0.3.9` and `oracledb = "=0.8.4"` are pinned in `Cargo.toml` (kills
`tzju` + `x1hr.1`); the `v0.9.0` tag == current `main` HEAD `0c663d8` (kills `x1hr` +
`x1hr.3`); the pinned driver's `crates/oracledb/src/tls.rs` carries `decide_sni` +
the host-SNI fallback and `oracledb 0.8.4` is published+pinned (kills server `2lz4`
SNI **and** driver umbrella `c23g`). So `2lz4`/`c23g` are **confirmed-done
false-opens**, not "to verify". The only genuinely-open driver TLS work is `4sfc`
(config-time TLS error masked as call-timeout) and `s0se` (missing `close_notify`
handling) — real backlog, already tabled in §29.2. Net: **6 false-open beads to
close** (`x1hr`, `x1hr.1`, `x1hr.3`, `tzju`, `2lz4`, driver `c23g`), unchanged from
§29's count, now each with tree-level evidence rather than an inference.

---

## 27. Campaign retrospective → improvement program (mined 2026-07-18)

Eight parallel forensic miners processed the complete 2026-07-04..18 session corpus
(18 Claude parent sessions, 169 Codex rollouts, 915 CI runs, both bead trackers, 392
operator messages). Full self-contained report with all evidence:
**`docs/plan/RETRO_SWARM_CAMPAIGN_2026-07.md`** (untracked, redaction-verified; its
§5 improvement catalog carries IDs W/C/T/O/V/P referenced below). This section bakes
the results into this plan; the retro holds the detail.

### 27.1 Headline diagnosis

The campaign shipped everything and abandoned nothing (0/164 panes), but paid ~2× the
necessary cost: 56% of ~176 CI hours wasted, a 141-run non-green chain, a 5-hour
one-bug-at-a-time live-OCI loop, a system-wide fork-EAGAIN freeze, and three confirmed
false-closes plus ~a dozen "gates that lie" instances (drift-guard enforcing a false
sentence, KeyError-as-verdict, unexpanded matrix check name, OOM-graded-caught
mutants, a mutation seal declared from a partial counter at 97.7% that sealed at
83.5%, a dashboard rendering green PASS for blocked outcomes). The two root systems:
**shared mutable infrastructure** (one tree/target/tracker for many agents) and
**unverified green claims**. The deepest operator-trust wound: discovering red CI
himself (22 messages).

### 27.2 Amendments to the CI plan (§25)

- **Tranche 1 gains two items:** (a) move the server's `_quality.yml` OUT of
  `.github/workflows/` — it is the local-Required-projection data file, and GitHub
  "running" it produced 11/11 failed no-job runs of pure red noise (retro C2; update
  `verify_required_local.py`'s path in the same commit); (b) a pre-step disk-free
  assert in the powerset job (C5 — the ENOSPC recurred across multiple fix commits).
- **Tranche 2 gains mutation-lane integrity (C3):** per-mutant memory cap with
  `OOMPolicy=continue`, OOM-killed mutants graded "errored" NEVER "caught", a
  deterministic shard budget replacing the 18→180-min runaway, and a marker that
  carries mutant-count + covered-file hashes so a stale "95%" can't certify a guard
  that doubled.
- **Tranche 2 also gains gate-honesty mechanics:** gates distinguish crash from red
  verdict and fail loudly on unexpanded `${{ }}` in check-name derivation (C7);
  advisory `continue-on-error` lanes get a visibility surface and chronically-red
  live lanes are marked explicitly advisory until the blocker clears (C8); drift
  guards anchor on version tokens, never prose claims (C11).
- **Server supersede churn** (119 cancels in the 2–10-min band; 174 total + 111 Kani)
  is the server-side mirror of P0.1's fail-fast goal: split a fast pre-gate from the
  heavy matrix and stop running the full 15-job fan-out on every intermediate push
  (C1). Release-mechanics gates (metadata/binary-size/acceptance) move out of
  per-commit CI to the tag/RQ path with a light PR-time sync check (C4).
- **Release runbook additions:** a failed PRE-publish gate is fixed in place and the
  SAME tag re-run — the gate prints "SAFE TO RE-RUN SAME TAG" (C9; the 0.6.2–0.6.5
  dead tags were exactly this gap); a single `set-version` writer updates every
  version-bearing surface from a manifest and the metadata gate prints
  field→found→expected (C10; ends release-surface whack-a-mole).

### 27.3 New Tranche 4 — Swarm Charter v2 (precondition for the NEXT swarm campaign,
including any swarmed implementation of the GCP program §7)

1. **One git worktree per agent + per-agent `CARGO_TARGET_DIR` on real disk** (W1) —
   retires the shared tree, shared target, build lanes, repo-wide commit lock, and
   the whole Theme-A failure class. Never tmpfs for build state; free-space preflight
   with an explicit "DISK, not OOM" message; write-read canary against silent EDQUOT
   truncation (W2).
   *Why Agent Mail did not already solve this (recorded so it isn't re-litigated):
   mail is a coordination layer, not an isolation layer. Its file reservations are
   advisory and can only SERIALIZE access (producing the 15-min commit-lock waits,
   the mutation-schema deadlock, and the `.beads` global write lock), and they
   govern who edits what — not whose half-finished state breaks whose build:
   a shared tree let uncommitted WIP make the workspace non-compiling,
   `E_TREE_DIRTY` unsatisfiable, and shared-target binaries lie to verifiers even
   with perfect reservations. Compaction-driven identity churn (three panes as one
   "MossyOwl/512") then broke the reservation model's own precondition, and the one
   mail primitive aimed at build contention (build slots) was disabled server-side
   while mandated. Division of labor going forward: worktrees provide isolation;
   Agent Mail keeps doing what it is good at — identities, messaging, logical
   ownership claims, and append coordination on genuinely shared files.*
   **Graded policy (refined 2026-07-18 after studying the upstream author's own
   model):** the agent-mail author's stack is coordination-by-default with
   worktrees as the sanctioned escalation — ntm ships `spawn --worktrees` and
   `ntm worktrees list/merge`, agent-mail has a worktree identity mode
   (`resource://identity/{path}`), and its build-slot primitive literally
   requires `WORKTREES_ENABLED`. Adopt the same gradation instead of a blanket
   rule: (a) ≤2-3 agents on disjoint crate/directory DOMAINS with reservations +
   the pre-commit guard = shared tree is fine (docs, small fixes, single-crate
   work); (b) any build-heavy swarm (>2 concurrent cargo builders) = worktrees
   MANDATORY, with the mitigation kit that closes the known worktree
   territories: ntm-managed lifecycle (create on claim, `worktrees merge` on
   land, auto-remove — the 21 stale worktrees §26.1 cleaned up were a
   no-lifecycle failure, not a worktree failure); `WORKTREES_ENABLED` so build
   slots work as designed; sccache (or equivalent) to kill the N×-compile cost;
   ONE canonical beads DB (env-pointed or orchestrator-synced — per-worktree
   `.beads` copies diverging is the one genuinely new hazard worktrees add);
   a worktree bootstrap script for `.env`/untracked fixtures; short-lived
   bead-scoped branches merged often (empirical merge risk here: 0 conflicts in
   164 sessions). Alternatives weighed and rejected: full clones (N× `.git`,
   sync drift), containers/overlayfs (operationally heavy, breaks the local
   tool mesh), patch-queue single-integrator (re-serializes gate-running — the
   measured bottleneck), Jujutsu (first-class conflicts are attractive; too
   immature for agent tooling today — revisit post-1.0).
2. **Hard-enforced build concurrency** (W3): a lease the build command physically
   cannot bypass + per-user `TasksMax`/ulimit guard; scoped `-p` builds by default
   (the fork-EAGAIN freeze came from an advisory cap nobody enforced).
3. **The operator's 12-rule constitution** in the charter preamble (reproduced here
   from retro §3G for self-containment): **(1)** never defer planned work
   unilaterally — deferral is the operator's call; **(2)** green means *honestly*
   green, and red is surfaced before the operator finds it; **(3)** claims must be
   evidence-backed — never assert what you can't prove; **(4)** reread
   AGENTS.md/README to full understanding before acting, every session; **(5)** think
   before acting (ultrathink) — verify, then execute; **(6)** be resource-disciplined
   — don't trash the host/disk/token budget; **(7)** keep driving autonomously, BUT
   follow explicit operator choices (model, agent freshness, scope) *exactly* —
   deviation is the fastest path to anger; **(8)** the fail-closed guard is sacred and
   tighten-only; **(9)** confidentiality is absolute — field-test identifiers never
   leave the gitignored quarantine; **(10)** no surprise costs — OCI stays free-tier,
   a hard rule; **(11)** land complete, not sliced across version bumps; **(12)**
   escalate blockers to the operator, delegate unforeseen work to the swarm — don't
   derail the authoritative prompt.
4. **Self-drive loop** (O1): on idle → `br ready` → claim → implement → close; no
   parked in_progress claims. Probe coordination primitives before mandating them;
   tool-disabled = fall-through, not wait-and-retry.
5. **Identity persistence across compaction** (O2): pane-pinned agent name +
   registration token stored outside the compactable context; re-attach, never
   re-mint; unique-name enforcement in agent-mail.
6. **Spawn preflight** (O4): model == requested, quota > 0, context headroom above a
   floor; release finalization NEVER routed to a near-full pane. **Quota as a
   scheduler resource** (O5): size fan-out waves to remaining capacity; reconcile
   bead status when a spawned agent dies silently.
7. **Expensive-oracle discipline** (within O1's charter bundle): one capture-everything run before
   iterating fixes on any slow live loop (the OCI lesson: 28 signoff runs → batch
   diagnose); offline falsifying repro before any wire-level hypothesis spends a
   live run.
8. **Proactive CI heartbeat** (O3): the orchestrator reports CI state on a fixed
   cadence and on every transition; tending loops run on a durable external
   scheduler so a crashed session still wakes (O13); idle notifications debounced
   (O12); child completion is event-driven, not 10-second polling (O9).
9. **Externalized progress as standard** (O8): orders files + beads + a running
   scratch summary so 145×-compaction marathons become cheap restarts.
10. **rch (remote build offload) — opportunistic accelerator, never a dependency.**
    Decision (2026-07-18): the local machine's capacity was never the root
    problem — ungoverned concurrency was (8 unbounded workspace builds →
    fork-EAGAIN; tmpfs targets; no caps). So W1–W3 + sccache fix the measured
    failures with zero new infrastructure and come FIRST. rch is then worth
    wiring for what it is: `rch` is fail-open by design — unreachable workers
    ⇒ `[RCH] local (<reason>)` and the build runs locally — so the operator's
    intermittently-powered machines are pure opportunistic capacity with no
    always-on requirement and no new failure dependency. Setup when convenient:
    add workers over SSH, `rch hook install`, `rch self-test --all`; workers
    need the pinned nightly toolchain + disk headroom (`rch doctor` covers
    health). Point the MARATHON lanes at it first (mutation campaigns, TSan,
    powerset, RQ prep) — long batch jobs that don't care about worker latency
    and otherwise degrade the interactive box. Guard rails, per O3's
    probe-before-mandate lesson: nothing in the swarm may ever *require* rch
    (no build-slot-mandate repeat), and agents must check the `[RCH]` contract
    line rather than assume offload — silent local fallback is the documented
    common case.
11. **Seed the learnings into cass-memory (cm)** so they surface at task time, not
    only at session start: `cm init --repo` in both repos (currently uninitialized
    — the one real "degraded" warning in `cm doctor`); convert the retro's
    improvement catalog and the 12-rule constitution into playbook bullets; add
    trauma patterns for the destructive classes (tmpfs build targets, OOM-graded-
    caught mutants, closing beads on self-skipping tests, `br update --status
    open` as claim-release); optionally install `cm guard`. Division of labor:
    the retro is the evidence record, AGENTS.md/charter is the binding contract
    read at session start, and cm is the retrieval layer that injects the right
    rule into the right task — with feedback (`helpful`/`harmful`) and decay
    keeping the playbook honest over time.

### 27.4 New Tranche 5 — Tracker hardening (before the next release train)

- `br close` requires landed evidence: closing commit recorded, bead paths clean at
  HEAD (T1 — the uncommitted-tests false-close).
- Live/e2e claims require a scheduled-lane run-id + artifact; self-skipping
  `#[ignore]` tests as sole proof are flagged (T2 — the etib.2 class).
- Safe claim-release verb that never overwrites a concurrent close; `close_reason`
  bound to the closing commit (T3 — the yg4x.7 race).
- On any discovered false-close, correct the ORIGINAL bead's close_reason, not only
  siblings (T4 — etib.2 still reads "Verified end-to-end").
- Evidence-doc coverage ratchet in CI + re-run the compliance audit with real
  (non-stub) verifiers (T5). Commit-trailer `Bead: <id>` (T6); audit discipline —
  paginate to exhaustion, explicit UTC, all-status filters (T7); dcg scoped to
  command position (T8); umbrella beads split so leaves unblock (T9); bulk bead ops
  validate ID capture via `--json` first (T10).

### 27.5 New Tranche 6 — Verification hardening (driver + server test work)

- Conformance goldens assert VALUES, not types, on all datetime paths (V1 — the TSTZ
  family's escape route). Golden wire-bytes tests per auth mode for connect
  descriptors (V2 — regression armor for the descriptor surfaces shipped in 0.5.1,
  not enabling work; see the §27.7 correction).
- Mutation-test security clamps explicitly (V3); regression tests for every typed
  branch a downstream contract depends on (V4); "immune"/parity claims need a
  reproducing test + as-of stamp (V5).
- **Sealed-artifact completion rule** (V11): no completion claims from live/partial
  counters. **Scoped completion claims** (V12): per-job conclusions by name at the
  exact SHA; umbrella "green"/"everything fixed" wording banned; the local
  full-Required runners are the mandatory pre-push step. **Monitor predicate
  discipline** (V13): structured parsing, no truncated-stream verdicts, predicates
  tested against known-good/bad before wiring. UI verdicts fail-closed from wire
  fields — landed as 1429edd, keep the regression cases (V14).
- Wrong-premise guards: bead bodies cite verified `file:line` ground truth (V6);
  flakes never closed on a negative repro (V7); safety-path fallbacks are typed
  refusals, never silent substitutions (V8); toolchain/doc claims tested empirically
  before propagation (V10).

### 27.6 Sequencing, interactions, and DECIDED calls (2026-07-18)

Engineering decisions taken (no longer open questions):

1. **Both program documents are tracked.** This plan (renamed
   `PLAN_ENGINEERING_PROGRAM.md`) and the retro are committable; the old gitignore
   directive is lifted. Commit/push timing remains release-aware (after v0.9.0
   lands), like every other tracked change.
2. **Charter v2 lands in the tracked ground truth**: the 12-rule constitution and
   the Tranche-4 mechanics go into BOTH repos' `AGENTS.md` (a compact "swarm
   operations" section) and the NTM charter/orders templates — not just ephemeral
   marching orders. First work item of Tranche 4, committed once 0.9.0 lands.
3. **Server CI restructures to fast-pregate + heavy-matrix-on-merge**: push feedback
   stays (fmt/clippy/unit in <5 min on every push); the ~15-job heavy fan-out runs
   per PR/merge-group and on a rate-limited main cadence instead of every
   intermediate push. This is the decided fix for the 119-cancel supersede band.
4. **Driver Live nightly goes explicitly advisory NOW, with an auto-reblocking
   rule**: it returns to hard-blocking automatically after 3 consecutive green
   nights. A chronically red "required" lane (11/14 nights) trains red-blindness —
   worse than an honest advisory badge. The TSTZ/live blocker keeps its own P1 bead.
5. **Beading trigger**: build the plan/bead-graph lint (P6) first, then convert
   §25 tranches + §27 program to beads in one pass when the 0.9.0 release swarm
   quiesces. The GCP program (§19) beads separately per its own §19.6 procedure.
   Both conversions run through the P6 lint before any bead is created.

Sequencing:

- Tranches 1–3 (CI, §25.7) proceed as already sequenced; §27.2 items slot into them.
- **Tranche 4 (Charter v2) gates the next swarm campaign** — including GCP §7
  implementation if it is swarmed. Mostly charter/process text plus small tooling
  (S–M), so it lands in the same window as CI Tranche 1.
- Tranches 5–6 land before the next release train; several items are one-liners.
- **Tranche 7 (§27.7 product features) is scheduled work, not backlog**: F-D1's
  service-form-SNI capability **already shipped in driver 0.8.4** (§27.7 correction) —
  its remaining slice is `he7t` (the IAM subject-mapping config step) + F-D2 (the
  Live nightly green streak, the driver release gate); **F-S1 and F-S2 both ride the
  server's 0.10.0 train** — F-S1's typed refusal reuses existing error/refusal/audit
  surfaces and does not expand because of the rename (§29.7). Nothing deferred.
- What must be preserved while fixing all this (retro §4): the self-catching
  adversarial-review culture, honest negative-result closes, the exact-SHA evidence
  chain, and the omcp-land property that real merge conflicts never occurred.

### 27.7 Tranche 7 — Product-feature work surfaced by the retro (BOTH repos)

The retro is not only housekeeping: its PRODUCT-BUG findings are, inverted, the two
repos' highest-value near-term features. These ship as normal versioned releases
with the Tranche-6 test shapes as their acceptance proof.

**Driver (rust-oracledb):**

> **Correction (2026-07-18, ground-truth-verified):** the first drafts of F-D1/F-D2
> described the IAM/TCPS connect descriptor and zoned-TSTZ gaps as current. Both
> shipped in **0.5.1** (PARITY_LEDGER #579: `TOKEN_AUTH=OCI_TOKEN` + TCPS
> `SECURITY` + passthrough, test `token_auth_descriptor_uses_tcps_security_and_
> passthrough`; #374/#274: offset-preserving zoned bind/fetch, intentionally
> better-than-upstream). The stale claims came from retro miner [G], whose driver
> sessions carried 0.5.x-era content — the exact V5 "stale CONFIRMED" failure mode
> this program bans. The REAL remaining driver work is below.

- **F-D1 — Oracle ADB-S over TCPS: SHIPPED in driver 0.8.4 (correction
  2026-07-18).** The SNI problem (Oracle's cloud TCPS listener expects a
  *service-form* SNI, `S{len}.{service}.V3.{numeric}`, that rustls rejects as a
  non-DNS name) is **SOLVED** — bead `r2t0` is CLOSED via a **host-SNI fallback**
  (`tls.rs:decide_sni`/`is_oci_adb_endpoint`), IAM token PoP shipped (`tjdc`/`bvyt`),
  and the wallet/TCPS path is **live-signoff-green** against a real Always-Free ADB
  (0.9.0 pins 0.8.4). So the differentiating ADB capability already exists and runs.
  What REMAINS is not a driver feature but **`he7t` — a harness/config subject-mapping
  step**: connecting AS the IAM principal returns ORA-01017 because the JWT `sub` is
  mapped as a raw OCID where ADB's Identity Domains likely expects a domain-qualified
  principal name (fix the harness mapping, re-run signoff; do NOT change guard/driver).
  (The broader DSN/failover/REDIRECT/SNI-HA set stays post-1.0 per `clvm`, closed.)
- **F-D2 — Drive the Live nightly back to a green streak.** Still red 3 of the last
  4 nights (last success 2026-07-14) even after the TSTZ-descriptor fix (`c23g.3`,
  89ace39) — root-cause the residual red, fix, and let the §27.6 auto-reblocking
  rule re-arm the lane. Acceptance: 3 consecutive green nightlies. V1/V2 test
  shapes apply here as regression armor for the already-shipped 0.5.1 surfaces,
  not as enabling work.

**Server (oraclemcp):**

- **F-S1 — Typed SCN-capture capability handling.** Replace the silent
  `ORA-00904 → V$DATABASE` fallback with a probed capability + typed refusal or an
  explicit, audited degraded mode (SEC-4: self-heal down, never silently).
- **F-S2 — Lane-health / CI-honesty surface in the Ground Control dashboard.** A
  lanes tile showing every scheduled/advisory lane's last conclusion and streak —
  the "operator never discovers red first" rule productized (C8's visibility
  surface becomes a dashboard feature, consistent with the Ground-Control dashboard system, §4-WD of the companion PLAN_0_6_0 doc).
- **F-S3 — Client-neutral MCP compat fixes from the GCP audit (G2F).** Any fix the
  ADK compatibility audit surfaces ships as a general MCP-surface improvement —
  feature work by definition, already governed by §5.8.

---

## 28. Bug-hunt findings (both repos, 2026-07-18)

Ten domain bug-hunters (each Fable-tier, each running a matching skill —
`multi-pass-bug-hunting`, `deadlock-finder-and-fixer`, `code-review`, security/UB
lenses) swept every module of both repos, then ONE Fable verifier adversarially
re-checked every finding against the actual code (bug real? / fix sound &
non-weakening? / test actually catches it?). All work was READ-ONLY (no edits, no
builds — the release was in-flight). Full evidence per finding lives in the
scratchpad reports `bughunt/{module}.md` + `bughunt/VERIFICATION.md`; this section
records the VERIFIED set only.

### 28.1 Headline

- **No defect surfaced on the safety-critical surfaces in this bounded static
  review** (read-only, no builds/dynamic tests — so this is "no defect found," not a
  proof of soundness; the existing Kani/property/fuzz gates plus the §30 additions
  are what would *prove* it). The guard classifier (no fail-open reached on any
  evasion class the review tried — every retro bypass has a regression test + Kani
  level-lattice proofs), the keyed-MAC audit chain (interior-fork checks on every
  record, constant-time compares, persist-before-publish, JWT `at+jwt`-only), both
  concurrency surfaces (no deadlock/race/lost-wakeup found; no lock held across
  `.await`), and all 14 `unsafe` sites (confined to one PyO3 Arrow-capsule module,
  each vetted sound) came back clean under this adversarial read.
- **Both cross-module seam leads were REJECTED as bugs** — the step-up
  digest/consume "TOCTOU" has no production caller (`approval_matches_sql` is
  production-dead; the live path consumes atomically), and the runtime
  profile-switch cannot bypass the startup audit signing key (hidden profiles are
  unswitchable + any writable-authority expansion forces a restart). Good
  defense-in-depth.
- **The real bugs cluster exactly where the retro predicted** — the driver's
  OCI/datetime frontier and the parity harness — and every High/Medium *strengthens*
  this plan rather than contradicting it (see §28.4).
- Verifier tally: **33 CONFIRMED** (4 High, 5 Medium, ~24 Low/Very-Low),
  **1 DOWNGRADED**, **7 REJECTED**.

### 28.2 Verified findings — High and Medium

| ID | Repo · site | Sev | What (verified) | Vetted fix | Test |
|---|---|---|---|---|---|
| DC1 | driver · `arrow/builders.rs:279,1071` | **High** | Arrow `fetch_df` drops the TSTZ zone offset → the SAME row returns a wall clock differing from the row-API by exactly the offset. **Data-correctness, not security**; server (JSON/row path) unaffected, external Arrow consumers affected. Tests miss it because fixtures are self-fulfilling (hand-built as already-local, never run the real decoder). | add offset in `epoch_parts`/`epoch_parts_ref` TSTZ arm; rewrite the 2 fixtures to UTC components | metamorphic: `arrow_epoch(v) == epoch(from_sql(v))` (WEAK current fixture → VALID) |
| DC2 | driver · `lib.rs:2906-2907` | **High** | DSN-only `SSL_SERVER_CERT_DN` is emitted to the server but never installed in the client cert verifier (built from `options.*`) → a DN pin silently degrades to hostname/SAN match. Asymmetry proves oversight: `wallet_location`/`use_sni` DO fall back to DSN. | pass `descriptor_ssl_server_dn_match` + `_cert_dn` into `resolve_tls_params` (one site) | cert with matching SAN but different subject DN must be REJECTED when DN set via DSN only |
| PY1 | pyshim · `convert.rs:1262`, `dbobject.rs:785` | **High** (parity) | Default fetch decides int-vs-float from the VALUE (`is_integer()`); python-oracledb decides from column SCALE (scale>0 ⇒ always float). `100` in `NUMBER(10,2)` returns `int` vs ref `float`. Value-equality (`100==100.0`) masks it → a green-but-meaningless conformance PASS on the ubiquitous `NUMBER(x,2)` shape. | thread column scale into dispatch: **scale>0 ⇒ float; else keep value-based** (do NOT drop the unconstrained-fractional float fallback) | `isinstance(v, float)` on a whole `NUMBER(x,2)` value |
| PY2 | pyshim · `convert.rs:105-113` | **High** (parity) | Untyped `Decimal` bind falls through to `f64` (~16 digits); ref binds `str(value)`. The typed + OSON paths already do `str()` → inconsistency. | add a `Decimal` branch emitting `BindValue::Number(value.str())` before the i128/f64 extracts | bind a 28-digit Decimal, fetch with `fetch_decimals=True`, assert EXACT equality |
| DC3 | driver · `lib.rs:2906` | Med | DSN `SSL_SERVER_DN_MATCH=OFF` ignored (verifier gets `options.*` default `true`). Fails **safe** but diverges. | same one-site fix as DC2 (confirm `DSN && option` precedence intent) | DSN `DN_MATCH=OFF` ⇒ resolved `dn_match=false` |
| PY3 | pyshim · `convert.rs:108` | Med (parity) | Untyped Python int > i128 (~39+ digits) → f64 precision loss; ref binds `str(int)`. | on i128-extract failure for a PyInt, use `value.str()` | round-trip a 40-digit int, exact equality |
| PY4 | pyshim · `cursor.rs:1758`, conn ops | Med | GIL held across blocking conn/commit/rollback/`fetch_next_row` I/O (unlike execute/pool which `py.detach`) → threaded tests serialize; cross-thread `cancel()` can hang. | wrap the blocking calls in `py.detach` | threaded cancel smoke (runtime) |
| DI1 | server · `dispatch/mod.rs:11082` | Med | A held `oracle_execute` (`held:true, committed:false`) is not "terminal effect", so a late outer deadline discards the successful response and returns a retryable error — and held statements consume no grant, so a **retry double-applies the DML**. | add `\|\| bool_field("held")` to the execute arm (+ the `oracle_checkpoint`/`undo_to` twins, DI6) | held execute with deadline between inner-done and outer-enforce ⇒ `Ok(held)` + exactly ONE audit entry (runtime, needs clock hook) |
| MET | server · `main.rs:2331`, `metrics.rs:64` | Med | Raw client tool name → unbounded metric-label `BTreeMap`s, no cap/TTL, cumulative OTLP, **always-on** regardless of OTLP config → memory + time-series DoS. *(One bug — reported by two hunters.)* | bound the recorded label to `advertised_tools` (already present), sentinel `"unlisted"` for unknown, record canonical name | drive N unknown names ⇒ O(1) distinct `tool` labels, not O(N) |

### 28.3 Verified findings — Low / Very-Low (CONFIRMED, all fixes SOUND)

Driver: **DC4** hardcoded 20s TLS-handshake cap can preempt a longer configured
connect timeout (GH#14 class); **DC5** sub-minute `FixedOffset` truncated;
**DC6** `-1e126` NUMBER sentinel → `-1` in Arrow int path; **DC7** `parse_session_u16`
`u64→u16` wrap; **PY5** negative sub-µs INTERVAL-DS truncates toward zero not floor;
**PR1** (DOWNGRADED Med→Low) `public_bind_name("\"")` panics on a lone-quote bind —
real, but reachable only from the publish=false pyshim today, NOT the server/driver
bind path; one-token fix (`len()>=2`, matching the guard `tnsnames.rs:130` already
has) + the missing fuzz target on `sql.rs`; **DK1** benign `Arc::strong_count`
last-handle drop race (close still guaranteed); **DK2** one OS thread per TIMEDWAIT
acquire.
Server: **DI2** `preview_dml` witness `max_rows` unclamped; **DI4** token prune evicts
arbitrary hash-order not oldest; **DI5** `timeout_seconds:0` accepted by some tools,
hard-error on others; **DI6** `oracle_checkpoint`/`undo_to` not terminal-effect
(honesty gap, folded into DI1's fix); **DB1** 23ai `BOOLEAN` value discarded as
`{"unsupported}` (fails loud; Low-leaning-Med); **DB2** named→positional leftover-append
binds mismatched names positionally (operator-config-gated); **DB3** owned-stream
failed `recover()` leaves slot mistyped as "temporarily unavailable" not
typed-quarantine; **DB4** negative INTERVAL-DS format malformed if driver emits signed
sub-day parts; **CC1** operator idempotency lease has no `Drop` → framework panic
strands the in-progress marker for the 15-min TTL (fails closed; Med if it blocks a
remediation retry); **CC2** shared condvar `notify_all` wakes every SSE waiter
(perf); **G1** multi-statement batch skips VECTOR_EMBEDDING normalization → benign
23ai batch wrongly Forbidden (fail-CLOSED, usability); **AU1** entry-hash appends enum
Debug strings unprefixed — prefix-free today, latent keyless-forgery surface (fix
behind a schema bump); **AU2** CEF escaping weaker than syslog (Unicode line-seps);
**AU3** Rekor head-binding is substring not field-parse (non-gating); **AU4**
`SecretError::Malformed` echoes the raw ref; **CF2** OTLP value-redaction backstop
misses prose-embedded OCIDs (key-denylist is primary); **CF3** doctor
check-then-rename TOCTOU (0o700 mitigates).

### 28.4 Rejected / not-a-bug (recorded so they are not re-hunted)

- **G3 step-up digest/consume ordering** — `approval_matches_sql` is production-dead;
  the live `take_resolved` path consumes atomically under the registry mutex, and
  per-statement binding uses a separate atomic exec-grant. No race.
- **CF4 profile-switch bypasses the audit key** — hidden profiles are unswitchable
  (`admit_mcp_profile ⇒ NotExposed`) and any writable-authority expansion is
  `restart_required` (re-provisions the auditor). Not reachable.
- **DB5 catalog cache key omits DBID** — intentional + documented; compensated by
  fresh-cache-per-cross-DB-diff and invalidate-on-reconnect (residual failover case
  worth a targeted test, not a defect).
- **PR2 `encode_vector` panic / PR3 OSON count×size** — unreachable from
  decoded/untrusted bytes; correctly-guarded near-misses (route re-encoders through
  `encode_vector_checked`).
- **G2 SELECT empty-base-objects ⇒ ProvenReadOnly** — safe today; a hardening note
  (gate on "no FROM clause"), not a live fail-open.
- **DK3 off-lock drop-return broadcast** — redundant best-effort; correctness via the
  reaper. Clean.

### 28.5 How the findings fold into this plan

These are candidate beads, not applied fixes (read-only hunt during the release). On
promotion they attach to existing tranches — the hunt did not create a new program,
it *populated* one:

- **DC1 + PY1 + PY2 are three live proofs of retro §27.6 V1** ("conformance goldens
  assert VALUES not types") — DC1's self-fulfilling fixtures and PY1's value-equality
  mask are exactly the trap V1 names. They land as V1 work with the discriminating
  assertions above, and DC1/DC2 double as **F-D1 (ADB) regression armor** (V2 golden
  wire-bytes per auth mode covers DC2's cert-DN path).
- **DC2/DC3/DC4** are driver TLS/timeout correctness → the driver's next release
  (0.9.0, §29.7 correction — behavior fixes; DC4 is the GH#14 class).
- **DI1 + MET + CC1** are server correctness/robustness → the server's next release
  (0.10.0 correction, §29.7);
  DI1's double-apply is the same integrity class as the retro's publish-before-persist
  findings and belongs with the T1 "landed-evidence" discipline mindset.
- **PY1-PY5** harden the parity harness, which §27.6 V5 requires before any parity
  number can be re-certified — a wrong-type PASS is precisely the "stale CONFIRMED"
  failure mode.
- **AU1** (latent forgery surface) and the Low security-hygiene set (AU2-4, CF2-3)
  are defense-in-depth beads, none gating a release.
- **Priority for beading:** the 4 High first (2 are ADB-blocking-adjacent), then the
  5 Medium, then the Low set batched by crate. The High/Medium (§28.2) each carry a
  vetted fix + discriminating test, so "done" = the test that would have caught it
  now exists (closing the retro's test-shape gap by construction). The ~24 Low/
  Very-Low (§28.3) are in compact prose — each needs its site/fix/test expanded (or a
  "wontfix/non-beadable" mark) at conversion time (the §33 (b)-normalization step);
  do not assume they are all individually bead-ready as written.

**Provenance:** 10 hunter reports + 1 verification report in the session scratchpad
(`bughunt/`); every §28 finding carries verifier-authored `file:line` evidence.
CONFIRMED-static unless a row says runtime; nothing here was applied to code.

### 28.6 Follow-up solo deep-dive (2026-07-18) — the swarm's uncovered surfaces

A second, targeted solo pass (read-only) went into the exact areas the swarm
flagged as NOT covered, hunting specifically for a Critical/High with proof-grade
certainty. **Result: no Critical/High defect surfaced in the bounded static review; the high-severity surfaces held under it** (a static read finds no defect — it does not prove soundness; the named dynamic/Kani/fuzz gates do).
This is recorded as honest negative assurance, not a null result — each surface
below was hand-traced against the reference or first principles, not skimmed. (Per
the operator constitution and §27.6 V11/V12, an unproven "High" is worse than none;
none was manufactured.)

Verified sound / fail-safe (with the specific property checked):

- **Driver AES/PBKDF2 auth crypto** (`crypto.rs`) — 11g MD5-combo and 12c
  PBKDF2-combo paths, CBC padding, and `verify_server_response` marker check match
  the vendored `reference/python-oracledb` structure; constant-length compare.
- **Oracle NUMBER wire codec** (`number.rs` / `codecs.rs decode_number_parts*`) —
  the base-100 digit walk, the fused i128 coefficient (byte-identical to the
  `digits_to_i128` oracle), and the `scale = len − decimal_point_index` arithmetic
  (i32 then checked into i16, overflow spills to text) are correct; the odd
  `index > 0` branch is redundant-but-correct given the leading-zero guard; crafted
  oversize mantissa bytes are bounded by the `push` length guard (no OOB/panic).
- **Driver transparent-retry idempotency gate** (`retry.rs`) — the gate fires FIRST
  in `decide()` (NonIdempotent ⇒ Surface, before the error hint); `classify_sql`
  cannot classify any data-changing statement as Idempotent (only a leading
  `SELECT` keyword qualifies, and no DML/PLSQL begins with "select").
- **Transport auth-phase scrubber** (`transport.rs`) — bounds-safe, fail-closed
  (redacts first secret-marker → end of run); a diagnostic-recorder path, not the
  live data path.
- **HTTP DNS-rebind + Origin guard** (`http_guard.rs`) — IPv6-bracket
  trailing-garbage rejection, loopback/host allowlist, and cross-origin Origin
  rejection all hold; a browser cannot suppress `Origin` on the cross-origin path,
  so the localhost-from-webpage attack is blocked at step 3.
- **SSE stream-cursor binding** (`sse.rs` / `stores.rs`) — `cursor_binding =
  sha256(session_id)[..32]` is a collision-resistant scope tag (not a secret);
  cursors are already session-scoped by the request, so the `binding.is_none()` and
  `"0/0"` bypasses leak nothing cross-session.
- **OAuth resource-server token validation** (`oauth_rs.rs`) — `typ` is
  `at+jwt`-only (the retro `.55` fix holds — generic `JWT` rejected), `alg=none`/
  empty rejected, HS256-only constant-time HMAC (no RS256↔HS256 confusion surface),
  `exp` required + `now ≥ exp` reject, optional `nbf`, RFC 8707 `aud` binding,
  fail-closed empty issuer allowlist, exactly-3-part JWT parse.

**One verified defect (LOW, fail-safe — a documentation defect, not a code bug):**
`retry.rs classify_sql` — the doc comment claims it "skip[s] a … leading line/block
comment run so a … commented statement still classifies", but the code only
`trim_start()`s whitespace. A leading-comment statement (`/* c */ SELECT …`) yields
an empty keyword and classifies **NonIdempotent** — i.e. it errs toward *not*
retrying (fail-safe: at worst a missed retry-optimization, never an unsafe replay).
CONFIRMED-static (traced by hand). Fix: either strip a leading comment run before
the keyword scan (to match the doc) or correct the comment to describe the actual
whitespace-only behavior. This is the only concrete discrepancy the solo pass could
prove; it does not rise to Medium.

---

## 29. Post-0.9.0 release reconciliation (2026-07-18)

The oraclemcp **0.9.0 release shipped and fully published** — this section
reconciles the plan against that ground truth, records the remaining beads, mines
the release itself for learnings, and folds the improvements in. (The §25 status
block that "deliberately does not track the live attempt" is now settled here.)

### 29.1 Ground truth (verified via gh/git/crates registry)

- **0.9.0 published on every channel**: crates.io, GitHub release, GHCR image, MCP
  registry entry — the release run's publish jobs are all green (incl.
  `verify MCP registry entry`). `main` is 0 ahead / 0 behind `origin/main`;
  `v0.9.0` tag pushed. The full 7-target build matrix is green.
- **Shipped pins:** `asupersync = 0.3.9`, `oracledb = 0.8.4` (driver published
  separately at v0.8.4). So the plan's earlier "driver 0.8.4 tagged, server 0.9.0
  in a retry loop" status is resolved: both are out.
- **0.9.0 headline content** (CHANGELOG): a bounded mandatory-mTLS control
  listener; stateful HTTP/SSE notifications scoped to the owning MCP stream (bounded
  replay, deterministic gaps); opaque random session-lease handles with linearized
  revocation + quarantine-before-reuse; the breaking `GuardDecision` field additions
  (`non_transactional_effect`, `query_effect_requires_fetch`). **Note:** the SSE
  cursor-binding and session-lease code the §28.6 solo pass hand-verified sound is
  exactly this new 0.9.0 surface — a useful independent check on the release's
  highest-risk additions. (CHANGELOG dates the entry 2026-07-12 though it shipped
  07-18 — a staleness nit for bead `hsvv`.)

### 29.2 Remaining beads (the honest backlog)

oraclemcp: **10 open (7 ready), 19 deferred.** Driver: **3 open, 21 deferred.**

**Four FALSE-OPEN release beads — a mirror of the retro's false-close problem, now
inverted** (plus `2lz4` and driver `c23g`, handled below — **six false-opens total**,
§26.7). 0.9.0 shipping satisfied these, but they sit open:

- `x1hr` / `x1hr.1` / `x1hr.3` — "server 0.9.0 release qualification (stays held)",
  "re-pin oracledb to =0.8.4 and re-qualify", "server 0.9.0 assurance + evidence".
  0.9.0 shipped pinned to 0.8.4 with all evidence gates green ⇒ done.
- `tzju` — "upgrade asupersync 0.3.5 → 0.3.9 in lockstep + repin". 0.9.0 ships
  0.3.9 ⇒ done.
  → **Action:** close all four with landed-evidence (the release run id + tag),
  applying the §27.5 T1 discipline. Leaving a shipped-but-open bead is the same
  ledger-dishonesty class as a false-close: the tracker must match reality both
  ways. (Driver `c23g` "0.8.4 correctness patch" umbrella — **confirmed closeable
  2026-07-18, §26.7**: 0.8.4 is published and the server pins `oracledb = "=0.8.4"`.)

**Genuinely open, and they map onto this plan's tranches:**

| Bead | What | Maps to |
|---|---|---|
| ~~`2lz4`~~ (stale-open) + driver `r2t0` (CLOSED) | server "can't emit OCI ADB SNI" — RESOLVED: SNI solved in driver 0.8.4 (`tls.rs::decide_sni` + host-SNI fallback, live-green); `2lz4` pins the old 0.8.3 driver → **close** (confirmed done 2026-07-18, §26.7 — false-open) | SNI is DONE, not a blocker (see §30.7 status correction) |
| driver `4sfc` (P2, open) | config-time TLS errors are failover-eligible → masked as call-timeout | §28 DC-class TLS-error-classification bug (real, low) |
| `he7t` (P1) | IAM: wallet/TCPS **live-green**; token reaches ADB + validates; ONLY residual = ORA-01017 on connect-as-mapped-principal — a **subject-name-format** harness/config fix (domain-qualified principal vs raw OCID), NOT a driver/guard defect | the OCI IAM live-harness *follow-up* (§3.2 OCI second wave) — small, not an unknown |
| `vzui` (P1) | Windows file_store durable-state "Access is denied" (os error 5) | server robustness; Windows lane (§25 C12 neighbourhood) |
| `yb7m` (P2) | `connect_timeout_seconds` rejected for full Oracle Net descriptors (ADB wallets) | overlaps §28 **DC4** (hardcoded 20s TLS handshake / GH#14 timeout class) |
| `hsvv` (P2) | publish 0.9.0 operator docs, retire stale 0.8.x refs | doc hygiene (+ the CHANGELOG date nit) |
| `izk5` (P3) | `doctor.rs` comments cite stale `=0.7.4` driver | doc staleness (§26.3-class) |
| driver `s0se` (P3) | Oracle closes sessions without TLS close_notify → asupersync missing-close handling | driver edge |

### 29.3 Release-mechanics learning (the 0.9.0 tag took 4 attempts)

The release ran the fix-one-error-and-re-tag loop the retro/§25 documents — this
time on the **tag pipeline**, each failure a separate red run + fix commit + re-tag:

1. **Binary-size budget stale** — `Check binary size and musl static linkage` failed
   on 4 targets; the 0.9.0 binary grew past the 32 MB budget → `build(release):
   raise per-target binary size budget 32MB -> 48MB` (62dff28).
2. **Installer-embed / tarball verify** — `fix(publish): embed installers from
   crate-local copies so the tarball verifies` (cfc650b): packaged-crate assembly
   couldn't resolve the installer paths.
3. **Release-gates timeout** — the `release gates` job hit its 45 min cap and the
   crates.io publish step failed downstream → `build(release): raise release-gates
   timeout 45m -> 60m` (e6d80d2).
4. (earlier) provenance-artifact registration (evidence-contract-v2), an
   oraclemcp-db API-baseline refresh, and a Windows durable-state feature gate.

**Learning → new improvement (extends §25.5 to the tag pipeline):** none of the
above is a code bug; all are release-mechanics that a **pre-tag dry-run** would have
surfaced *once, together*, off the tag path. Add a `workflow_dispatch` "release
rehearsal" that runs the exact tag-pipeline gates — the 7-target build **including
the binary-size check**, `cargo package --workspace` tarball verification, and the
full release-gates job — against the release candidate SHA on a branch, before the
tag is pushed. This is the release-pipeline analogue of the driver's RQ prep mode
(§25.5) and the biggest lever against the "burn a re-tag per discovered gate"
pattern. It also argues for making the binary-size budget a *ratcheted* value
(warn-then-fail with headroom) rather than a hard cliff that silently goes stale as
the binary grows — the same "no silent cap" principle as §27.2 C10.

### 29.4 Reconciling the §28 bug-hunt with the live backlog

The bug hunt was run against pre-0.9.0 HEAD; post-release, its findings partition as:

- **Already shipped / beaded:** the SNI ADB work is DONE — driver `r2t0` CLOSED in
  0.8.4, server `2lz4` stale-open (close it); the TLS-timeout class (§28 **DC4**) is
  tracked by open beads `yb7m`/`4sfc`. Remaining OCI item = `he7t` (IAM subject
  mapping, a config step — §30.7).
- **NOT yet beaded — promote these** (their vetted fix + discriminating test are in
  §28.2/28.3): **DC1** (Arrow TSTZ offset), **DC2/DC3** (DSN cert-DN pin ignored /
  DN_MATCH=OFF), **DI1** (held-execute double-apply), **MET** (metric-cardinality
  DoS), **PY1–PY5** (parity harness). These land on the driver's 0.9.0 and the
  server's 0.10.0 (driver minor, server semver-corrected, §29.7) per §28.5; DC2 is the highest new-security item (a silently
  ignored cert-DN pin) and should lead the driver TLS batch alongside F-D1.

### 29.5 cass mining note

The release itself was mined directly (git + gh run forensics + session inventory)
rather than via cass, because the cass index was stale at reconciliation time (a
full reindex was running, 398 conversations; the corpus keeps growing under the
active swarm). The direct mine is authoritative for the release-mechanics story
above. A deeper cass pass over the 07-18 release session (`190fa758`, the release
orchestrator) can follow once the index is fresh — but the actionable learning (the
4-attempt tag loop and its causes) is already captured in §29.3 from ground truth.

### 29.6 Immediate actions (post-release)

(Per the standing authorization, header: closing the false-open beads + committing +
pushing is autonomous; creating NEW program beads is the GO gate; a release tag stays
operator-gated.)

1. **Close the six confirmed false-open beads** (`x1hr`, `x1hr.1`, `x1hr.3`, `tzju`,
   server `2lz4`, driver `c23g`) with the release run-id + `v0.9.0` tag as landed
   evidence — all six are tree-verified done (§26.7), no "verify" step remains.
2. **Add the pre-tag release-rehearsal dispatch** (§29.3) — the single highest-value
   fix, turns the next release's re-tag loop into one dry-run.
3. **Promote the un-beaded §28 highs** (DC1, DC2/DC3, DI1, MET, PY1–5) with their
   vetted fix+test, batched per §28.5.
4. **Doc + gitignore hygiene:** `hsvv` (0.9.0 operator docs + CHANGELOG ship-date),
   `izk5` (stale driver-version comments) — cheap, close the §26.3 doc-staleness
   class; and fold the two §26.7 commit-hazard fixes into their repos' `.gitignore`
   (oraclemcp: add `codex.mcp.json` + `.codex/` to the pending edit; driver: add the
   `.claude/`/`.ntm/` agent-state block) so agent state cannot be committed.
5. Then the CI tranches (§25.7) and Charter v2 (§27.3) proceed as sequenced —
   the release path is now clear, so §25.7.1's "zero workflow edits during release"
   hold is lifted.

### 29.7 Next release train correction — server 0.10.0 / driver 0.9.0 (operator correction, 2026-07-22)

The next release train is **driver 0.9.0 / server 0.10.0**. This corrects the
earlier patch-only wording: the workspace already shipped server 0.10.0 after
`cargo-semver-checks` found major public-API findings against published 0.9.0.
The train name must follow the artifact, not the superseded patch intent.

| Repo | Current | Next |
|---|---|---|
| oraclemcp (server) | 0.9.0 | **0.10.0** |
| rust-oracledb (`oracledb` driver) | 0.8.4 | **0.9.0** |

This remains a correction train, not an excuse to expand scope: **nothing is
deferred because of the rename**. The driver target is the already-ruled 0.9.0
minor. The server target is 0.10.0 because semver evidence forced the minor
position on a 0.x line: the intended lease-subsystem removal and metadata-bound
changes removed or changed public API relative to published 0.9.0. Do not change
Cargo version metadata as part of this text correction; the release-visible
surfaces already moved together and are gate-verified elsewhere.

**Everything ships in 0.10.0 / 0.9.0 — how each stays correction-scoped:**
- Every §28 bug-fix as a **behavior correction**, no public-signature change: DC1 (Arrow
  TSTZ), DC2/DC3/DC4 (driver TLS/timeout), DI1 (held-execute), MET (metric-cardinality),
  PY1–PY5 (parity) — each = fix + discriminating test.
- Doc hygiene (`hsvv`, `izk5`), the two §26.7 gitignore fixes, test/CI additions, and the
  six false-open bead closes.
- F-D1 `he7t` (IAM subject-mapping **config/harness**, no driver code), F-D2 (Live nightly
  green streak — CI/test), F-S2 (dashboard lanes tile — web/TS, not a crate API), F-S3
  (MCP-surface compat behavior).
- **F-S1 (typed SCN-capture) ships too** — the "typed refusal / audited degraded mode"
  reuses the **existing** error-envelope, refusal, and audit surfaces (probe the
  capability, then refuse-or-degrade through machinery that already exists), so it is a
  behavior change with **no new public API** → patch-legal. Not deferred.
- **Conversion rule (no silent minor — the §27.2 C10 principle applied to versioning):**
  before a change lands, run `cargo-semver-checks`; if it reports anything above *patch*,
  the fix is **re-worked to be behavior-only / additive-free** until it is patch-clean —
  the release stays +0.0.1 and **no scope is dropped**.

This subsection is the single source of truth for release versioning and **supersedes
every "next minor" phrasing elsewhere** (§27.7, §28.5, §29.4): read those as "the next
release," pinned here to **+0.0.1**, with nothing deferred.

---

## 30. Test-coverage audit & testing organization (2026-07-18)

A full test-surface audit of both repos, every crate/module, plus a local-vs-CI
organization design and an OCI free-tier e2e design. **Method note (honest):** a
9-analyst fan-out was dispatched but died instantly on a quota session-limit (the
exact retro O5 failure — re-fanning-out into an exhausted quota is futile), so this
was done directly and grounded strictly in what was verified by reading the test
inventory and depth. That constraint improved it: every claim below is checked, and
it corrected a wrong first impression (see 30.1).

### 30.1 Headline — the suites are extensive and sophisticated (correcting the count-based read)

Raw counts (oraclemcp ~2,830 `#[test]`, only 4 proptest / 2 fuzz; driver 1,171
`#[test]`, 28 proptest, 22 fuzz, 88 live) first read as "server property/fuzz
testing is thin." **The file-and-depth inventory disproves that.** The server's
property/metamorphic testing is not counted by `proptest!`-macro grep because it
lives in dedicated integration suites:

- **guard** ships `classifier_metamorphic.rs` (1,116 lines) + `proptest_invariants.rs`
  (1,010 lines) with exactly the relations one would demand: `mr_monotonicity`,
  `mr_reclass_idempotence`, `mr_oracle_never_loosens`, `mr_normalize_stability`,
  `mr_block_wrap_monotone`, plus `classifier_never_panics_on_arbitrary_input`,
  `derived_subquery_smuggled_dml_is_never_read_only`,
  `cte_dml_bodies_are_never_cleared_to_safe`, corpus-never-underclassified,
  policy-composition-never-loosens — AND a `classify_fuzz` + `alter_session_parse`
  fuzz target. This is exemplary; nothing to add here beyond what 30.4 lists.
- **core** ships `concurrency_contract.rs`, `chaos.rs`, `lane_state_machine.rs`,
  `seeded_fault_injection.rs`, `phase0_capacity.rs`, `mcp_conformance.rs`, and
  trybuild compile-fail `ui/*.rs` (type-level proofs that a narrowed lane context
  cannot widen/spawn/remote — sophisticated).
- **db** ships `type_fidelity.rs`, `cancel_correctness.rs`, `chaos.rs`,
  `privilege_degradation.rs`, `structured_schema_golden.rs`, plus live suites.
- **oraclemcp-verifier IS tested** (223 lines across `verdict_verifier.rs` +
  `served_verdict_certificate.rs` — the "0 tests" impression was wrong; they are
  integration tests, not inline).
- Rich **golden** suites (http host/origin guards, stateful session, auth-scope
  matrix, PRM, www-authenticate; stdio init/completion/subscribe/progress; doctor
  redaction; oracle-cell-structured oson/array/json/vector/tstz).
- **driver** live breadth: `live_typed`, `live_lob_stream`, `live_owned_row_stream`,
  `live_statement_cache`, `tls_handshake`, `access_token`, `live_object_precision_
  scale`, `cassette_record_replay`, `statement_ground_truth` (88 `#[ignore]` live
  tests) + 22 protocol fuzz targets + version-matrix across 11g/18c/21c/23ai.

**Verdict: this is a mature, multi-layer test suite (unit / property / metamorphic /
adversarial-corpus / chaos / fault-injection / compile-fail / golden / conformance /
live / fuzz).** "Do we have enough tests?" — in *breadth and kind*, yes,
unusually so. The improvements below are **specific and surgical**, not wholesale;
the one systemic gap is measurement, not test-writing.

### 30.2 THE systemic gap — no EMPIRICAL coverage measurement or gate

There are thousands of tests but **zero measured line/branch coverage**: no
`cargo-llvm-cov`/tarpaulin/grcov anywhere in CI (only clause-coverage accounting for
the conformance/e2e MUST-contract, which is a different thing). We know how many
tests run; we do NOT know which lines/branches they cover, or where the untested
holes are. `cargo-llvm-cov` **is already installed** — so this is a wiring task, not
a tooling hunt, and it is the single highest-value testing improvement.

Actions:
1. **Baseline (do first):** `cargo llvm-cov --workspace --summary-only` in each repo
   (heavy instrumented build — run deliberately, not casually; it belongs on a
   larger runner or an idle-machine background run, per the machine-hygiene
   learnings — do NOT kick it off blindly into a loaded box). Record per-crate
   line/branch %.
2. **A coverage gate — but NOT a naive global "never-decrease" line** (that rewards
   assertion-free tests; see §32.2 TRI-1 + §30.9-C). The reconciled design: gate on
   **changed-line coverage** of the diff (new/changed code must be exercised) PLUS,
   for safety-critical diffs (guard/audit/db/dispatch), a **named invariant or
   negative test** required in review, guarded by a per-crate **mutation-score
   floor** so coverage can't be gamed by tests that run code without asserting. The
   global line % is recorded and trend-watched, not hard-gated. This is the single
   design used everywhere in the plan (§30.2 = §32.2 TRI-1 = §33 row D); it turns
   "we have lots of tests" into "changed code is exercised, asserted, and can't
   silently regress."
3. **Coverage-guided gap-finding:** point the next targeted-test effort at the
   specific uncovered branches the report names — far better than guessing. This is
   how to answer "are all functions tested?" empirically instead of by inventory.
4. Run it as a **nightly** lane (not per-PR — instrumented builds are slow) with the
   ratchet checked at PR time against the last nightly baseline.

### 30.3 Coverage scorecard (per crate, both repos)

| Crate / area | Strength | Specific gap (evidence) |
|---|---|---|
| guard | **Exemplary** — full metamorphic/property/adversarial + fuzz | none material; keep the SideEffectOracle-tightening bead's test when it lands |
| core (lane/http/sse/doctor) | Strong — concurrency-contract, chaos, fault-inject, compile-fail | **loom** not used for the DL-* lock ranks; CC1 lease-strand-on-panic has no test (bug-hunt §28) |
| db | Strong — `type_fidelity`, cancel, chaos, privilege | `type_fidelity.rs` covers NUMBER/LOB/JSON/INTERVAL/TIMESTAMP but **NOT BOOLEAN, TSTZ(zoned), VECTOR** (DB1 gap confirmed); DI1 held-execute no regression |
| dispatch/main | Broad (golden + e2e) | DI1 double-apply, MET cardinality — new §28 bugs, no tests yet |
| audit | Strong — 235 inline | AU1 entry-hash preimage (unprefixed enum) not pinned by a KAT + prefix-free compile assertion |
| auth | Adequate — 57 tests | OAuth reject-reason **matrix** could be one table (typ/alg/sig/iss/aud/exp/nbf/parts) — verify all 9 rejects + 1 accept are present |
| verifier | Present (223 lines) | verify depth of the tamper matrix (flipped verdict / wrong SHA / forged MAC each reject) |
| config | Adequate — 124 tests | a profile-**merge property test** ("merged max_level ≤ every source") + a config-TOML **fuzz target** are absent |
| telemetry | Adequate — 45 | metric-label-cardinality bound (MET) + prose-OCID redaction (CF2) untested |
| error | Thin — 18 | acceptable for 999 loc; fuzzy-match edge table would help |
| **driver protocol** | **Exemplary** — 22 fuzz + 28 proptest | `sql.rs` (bind-name parse) has **no fuzz target** (PR1 lone-quote panic lived here); confirm crypto.rs/PKCS12-wallet are fuzzed |
| **driver core** | Strong live + unit | **DC1 self-fulfilling TSTZ fixtures** (see 30.5); no golden **wire-bytes** per auth mode (DC2/DC3 cert-DN); pool checkout/idle-reap no loom |
| driver pyshim/conformance | python-oracledb differential harness | **PY1 value-equality masks wrong type** (see 30.5); the parity number needs a value-asserting re-run (§27.6 V5) |

### 30.4 Surgical test additions (each is the regression for a known gap/§28 finding)

Every item names its test TYPE and TIER. These are candidate beads carrying their
discriminating assertion — "done" = the test that would have caught it exists.

1. **db type-fidelity table → add BOOLEAN, TSTZ(zoned), VECTOR** rows asserting the
   exact JSON *value* (golden/table; CI-required). Closes DB1 + the type-table hole.
2. **DI1 held-execute regression** — held `oracle_execute` under a late deadline
   returns `Ok(held)` + exactly ONE audit entry (unit + clock hook; CI-required).
3. **MET cardinality bound** — N distinct unknown tool names ⇒ O(1) metric labels
   (unit; CI-required).
4. **DC1 driver Arrow TSTZ metamorphic** — `arrow_epoch(v) == epoch(from_sql(v))`
   for a **decoder-produced** value (replaces the self-fulfilling fixtures;
   CI-required). See 30.5.
5. **DC2/DC3 connect-descriptor golden wire-BYTES** per auth mode (plain/TCPS/token/
   wallet), asserting SECURITY/TOKEN_AUTH/PROTOCOL/SSL_SERVER_CERT_DN + a cert whose
   SAN matches but subject-DN differs is rejected when DN set via DSN (golden +
   unit; CI-required). Also serves as F-D1 regression armor.
6. **driver `sql.rs` fuzz target** — bind-name parsing never panics (fuzz; nightly).
   Closes the PR1 coverage hole (`sql.rs` was the one unfuzzed parser).
7. **CC1 lease-strand-on-panic** — inject a framework panic, assert the retry is
   admitted not 409 (unit + panic hook; CI-required).
8. **AU1 entry-hash preimage** — a KAT pinning the preimage + a compile-time
   assertion no `AuditDecision`/`AuditOutcome` variant Debug string prefixes another
   (unit; CI-required).
9. **config profile-merge property** — over random env/file/discovery merges,
   `merged.max_level ≤ min(source max_levels)` and `protected ⇒ READ_ONLY` always
   (proptest; CI-required) + a **config-TOML fuzz target** (crafted config never
   panics, never over-permissive; nightly).
10. **loom for the core DL-* lock ranks and the pool checkout/idle-reap** — the
    invariants are documented and unit-tested but not model-checked (loom; nightly).
11. **OAuth reject matrix** (audit whether all 9 reject reasons + 1 accept are a
    single table; add the missing rows) + **verifier tamper matrix** depth-check
    (each tamper rejects) (unit/golden; CI-required).

### 30.5 The weak-test class — self-fulfilling fixtures (prevent recurrence)

The bug-hunt proved two tests that PASS while the code is WRONG: DC1 (driver Arrow
TSTZ fixtures hand-built as already-local, never running the real decoder) and PY1
(value-equality `100 == 100.0` masking an int-vs-float type error). This is a
*quality* defect independent of count: a test that cannot fail for the bug it
purports to guard. Two responses:
- **Fix the two known instances** (items 4 above; PY1 assert `isinstance(float)`).
- **Prevent the class:** a review rule / lint — a fixture for decoded data must be
  produced by the real decoder (or a differential vs it), never hand-assembled in a
  convention the decoder doesn't emit; a value assertion on a numeric/type-sensitive
  path must assert the discriminating property (type, offset, precision), not just
  equality that collapses it. Add this to the §27.6 V-series test-discipline and to
  the code-review checklist. Sweep the datetime/number/type test files once for
  other hand-built-fixture instances (a targeted follow-up, since it recurred twice).

### 30.6 Local vs CI vs nightly vs live — the testing organization (ultrathink)

Re-reading the plan (§17 gates, §25 CI velocity, §27 charter, §29 release
mechanics) and the learnings, the organizing principle is **fail cheap and early,
run expensive things rarely and authoritatively, and make each tier's job
unambiguous.** A four-tier model:

**Tier 0 — Local pre-push (seconds→~2 min, the developer/agent gate).**
`fmt` + `clippy` + `cargo test -p <touched-crate>` (scoped, per §27.3 worktree
model) + the fast lints. This is where the retro's "run the local Required gate
before dispatch" (`verify_required_local.sh` / `local_release_gate.sh`) lives — the
antidote to the 141-run supersede chain. Doctests stay `--doc`. NO live DB, NO
fuzz, NO coverage here.

**Tier 1 — Required CI (per-PR, must be green to merge; target <15 min via §25 P0).**
The full offline suite: workspace `cargo test`, the golden/metamorphic/property/
compile-fail suites, feature-powerset (as clippy-compile per §25), the arch/honesty/
seam lints, cargo-deny, the API/semver locks, and the **coverage ratchet check**
(§30.2, against the last nightly baseline — cheap: compare, don't measure). This is
the gate that must be fast and honest; §25's fast-pregate + heavy-matrix-on-merge
split (C1) and `_quality.yml`-out-of-workflows (C2) apply here.

**Tier 2 — Nightly / scheduled (advisory-but-watched, no per-PR cost).**
The heavy and the slow: `cargo llvm-cov` coverage baseline; fuzz campaigns (the 22
protocol targets + the new guard/config/sql targets); mutation testing (capped per
§27.2 C3); loom model-checks; the gvenzl live version-matrix (11g/18c/21c/23ai);
the driver live suite (88 `#[ignore]`); TSan. These generate the baselines the
Tier-1 ratchets check against. Chronically-red live lanes go explicitly advisory
with auto-reblock (§27.6 #4).
  *Producer/consumer nuance (do not read "advisory" as "not release-gating"):* the
  live version-matrix runs here as a scheduled **producer** of exact-SHA evidence
  artifacts; the Tier-3 **release-qualification consumer** (§25.6) then HARD-gates on
  a green matrix artifact for the exact release SHA. Advisory-as-a-lane (a red
  nightly doesn't block a PR merge) and hard-gate-at-release (no publish without the
  green exact-SHA evidence) are two roles of the same lane, not a contradiction —
  and a missing/stale artifact for the release SHA forces a fresh matrix run before
  the tag can proceed (§25.6, §29.3).

**Tier 3 — Live / real-cloud (deliberate dispatch, never per-PR).** OCI Always-Free is AGENT-runnable within its guardrails (standing authorization, header — no per-run approval); anything with real cost (Vertex) stays operator-gated at setup.
The OCI ADB e2e (§30.7), the clean-machine e2e, the release rehearsal (§29.3), and
the exact-SHA release-qualification. These involve real provisioning or gate a
release, so they never run per-PR — but they split on the money-gate: the OCI
Always-Free e2e is **agent-runnable** (provably $0, guardrail-asserted, no per-run
approval — standing authorization), while the release-qualification/rehearsal gate a
*release* (the tag push) and stay operator-authorized. They gate a release, not a
merge.

The empirical rule tying it together: **a test's tier is set by its cost and its
signal latency, not by how important it feels.** A safety invariant that can be
proven offline (guard metamorphic) belongs in Tier 1, not Tier 3; a cheap
type-fidelity golden belongs in Tier 1; an expensive live-ADB sweep belongs in Tier
3 even though it's the most "real." This is already ~80% how the repos work — the
deltas are: add the coverage ratchet (Tier 1) + baseline (Tier 2), move
release-mechanics gates fully to Tier 3 (§25 C4 + §29.3 rehearsal), and make the
tier of every existing lane explicit in one table in each repo's `AGENTS.md`.

**Reality-reconciliation (external review, §32.2):** the current CI does NOT cleanly
match this model — the Free23 live-DB + VECTOR lane runs **per-PR** (not nightly),
the driver PR CI excludes pyshim, and fuzz-compile is non-blocking. So the four
tiers must be a machine-checkable **manifest** (per lane: required/advisory · owner ·
retry policy · platform/features · secrets · release-blocking · tier), not prose —
and adopting it means consciously *moving* lanes (e.g. Free23 → Tier 2 nightly with a
23ai smoke kept per-PR) rather than assuming the model already holds. The manifest
is the artifact; the prose above is its intent.

### 30.7 OCI Always-Free ADB end-to-end — "one database, test everything, tear down"

The operator's ask — open one session/DB against real OCI, exercise every function,
close, all in the free tier — is **partially built and currently blocked**, not
greenfield. What exists: `scripts/e2e/oci_adb_terraform.sh` (provisions a throwaway
Always-Free ADB, runs signoff, always `terraform destroy` in a trap),
`real_adb_tcps_signoff.sh`, `oci_adb_iam_bootstrap/`, `oci_tcps_e2e.rs`, and the
`oci-adb.yml` dispatch-only workflow.

**Scope correction (external review, §32.1):** what the existing signoff actually
asserts is **authentication smoke only** — wallet/IAM `doctor` + `oracle_query
SELECT USER FROM DUAL` (`real_adb_tcps_signoff.sh:301`). It does NOT exercise the
operating ladder, writes, held-execute, audit verify, LOB, VECTOR, type-fidelity,
plans, or refusals. So the full capability sweep below is genuinely NEW work on top
of a proven auth path — label the current lane "OCI auth smoke," not "OCI e2e."
Second correction: **"one session, test everything" is the wrong acceptance shape.**
Pool/reaper, cancellation, held execution, contention, failover, and
privilege-separation each require MULTIPLE connections and roles. The right design is
**one disposable ADB, many isolated schemas/users, per-run namespace + run-id**, a
cleanup **ledger**, and a **post-destroy OCI resource poll** — not one process/session
(the driver's `multi_lane_live_xe.rs` is the existing multi-connection shape to
mirror).

**Status correction (2026-07-18, re-verified against beads + code — the earlier
"blocked on SNI/IAM unknowns" framing was WRONG):** the SNI blocker is **SOLVED** —
driver bead `r2t0` is CLOSED ("OCI ADB TCPS live signoff green: host SNI fallback,
v1 wallet client resolver, Legacy16 split CONNECT framing all verified"), shipped in
oracledb 0.8.4 (which 0.9.0 pins), via a **host-SNI fallback** when the Oracle
service-form SNI (`S{len}.{service}.V3.{numeric}`, rejected by rustls as a non-DNS
name — its terminal numeric label) can't be used (`tls.rs:decide_sni`,
`is_oci_adb_endpoint`). The server bead `2lz4` is **stale-open** — its text pins
"oracledb **0.8.3**" and is resolved by the 0.8.4 repin (close it / re-verify, like
the §29 false-open beads). The **wallet/TCPS path is fully live-green** against a
real free-tier ADB (wallet doctor + governed `SELECT USER FROM DUAL` pass). The IAM
token PoP shipped (driver `tjdc`/`bvyt`). The **only** residual is `he7t`: a
subject-name-**format** question, NOT a code or driver defect — the ADMIN bootstrap
(`DBMS_CLOUD_ADMIN.ENABLE_EXTERNAL_AUTHENTICATION`, create global user, grant
`CREATE SESSION`) all succeeded and the token validates, but connecting AS the mapped
IAM principal returns ORA-01017 because the harness maps the JWT `sub` as a raw OCID
where ADB's Identity Domains likely expects a **domain-qualified principal name**;
the fix is harness/config (try the domain-qualified form), explicitly "do NOT change
the guard or driver." So this e2e is sequenced after `he7t` (a small config
follow-up), not after a technical unknown — and the auth foundation it needs already
runs live-green.

**Design — a single dispatch (agent- or operator-triggered within the free-tier guardrails, standing authorization; extends the existing harness):**

1. **Provision once:** reuse `oci_adb_terraform.sh` to stand up ONE Always-Free ADB
   (`terraform` with an explicit `is_free_tier = true` / Always-Free shape assert —
   a hard guardrail that refuses any paid shape), bootstrap a **synthetic** schema +
   both auth paths (wallet/TCPS and pre-fetched IAM token).
2. **Full capability sweep through oraclemcp against real ADB** (the "test all"):
   connection/info; `oracle_query` reads; `oracle_preview_sql` fail-closed DDL
   proof; held vs committed `oracle_execute` (incl. the DI1 held-deadline case);
   the session operating-ladder (READ_ONLY→…→ADMIN step-ups + single-use grants);
   catalog/schema/source/plan; LOB streaming; **23ai VECTOR** distance; NUMBER/
   TSTZ/BOOLEAN/INTERVAL type fidelity against a real ADB (the value-asserting
   table from 30.4 item 1, now over the wire); `oracle audit verify` + the
   head-anchor; doctor against the live wallet; and the guard's fail-closed
   refusals — one checklist, driven by the existing `oracle_ladder_session.py` /
   `oracle_version_matrix.sh` scenario style so it reuses the JSON-line evidence
   contract (`lib.sh`) and lands a signoff artifact.
3. **Always tear down:** `terraform destroy` in a trap (already the harness
   pattern) — provisioned ADB never outlives the run.
4. **Guardrails (non-negotiable):** Always-Free shape only, asserted before apply
   (no surprise cost — the §2.7 "no costs" hard rule); **synthetic data only, zero
   committed identifiers** (the confidentiality rule — all ocid/tenancy/wallet stay
   in the gitignored `todelete/`/runner-private storage, never in an artifact);
   idempotent teardown even on mid-run failure; a cost-ceiling assertion mirroring
   `cost_gate.sh`.
5. **Placement:** Tier 3, `workflow_dispatch` (agent- OR operator-triggered — no per-run approval, standing authorization; the `oci-adb.yml` shape),
   NEVER per-PR or nightly-automatic; it is release-adjacent evidence for the
   OCI/ADB second wave (§3.2), consuming the same evidence-bundle discipline as the
   GCP demo (§6).

This gives exactly the requested "exercise everything against real ADB, then tear down" (one disposable ADB, many isolated sessions/schemas/roles — not one session) — and
because it runs the *value-asserting* type table and the held-execute case over a
real ADB, it doubles as the live proof that the 30.4 offline regressions match real
Oracle behavior.

### 30.8 Priority and folding into the plan

- **P0 (highest leverage):** wire the empirical coverage baseline + ratchet (30.2)
  — it's a wiring task on already-installed tooling and it makes every later "is X
  tested?" answerable. Lands in CI Tranche 2 (§25.7) as the coverage lane.
- **P1:** the surgical regressions (30.4 items 1–5, 7, 8) — they are the §28
  bug-fixes' tests; they ride the driver/server next-release beads (0.9.0/0.10.0 train, §27.7/§29.4/§29.7) so
  each fix ships with its guard. The self-fulfilling-fixture prevention rule (30.5)
  folds into §27.6 V-series + the review checklist.
- **P2:** loom lanes, config fuzz, `sql.rs` fuzz, OAuth/verifier matrix depth (30.4
  items 6, 9, 10, 11) — Tier-2 nightly work.
- **Sequenced:** the OCI ADB e2e (30.7) is gated on `he7t` (the IAM
  subject-name-mapping config step — SNI/TCPS/wallet already ship live-green in
  driver 0.8.4 per the §30.7 correction), and is that work's acceptance evidence —
  no technical unknown, just one identity-mapping config step then test-writing.
- **Organization:** adopt the four-tier model (30.6); the concrete deltas
  (coverage ratchet, release-mechanics→Tier 3, per-lane tier table in AGENTS.md)
  join CI Tranche 1–2 and Charter v2 (§27.3).

### 30.9 What makes the suite genuinely worth it (engineering principles, ultrathink)

Tiering (30.6) is the *scheduling* of tests; these seven principles are the
*quality bar* that makes each test earn its keep. A test is worth its maintenance
cost only if it (1) can fail for a real defect, (2) fails for the RIGHT reason
(specific, not brittle), and (3) fails DIAGNOSABLY. The suite is already strong on
these; the principles below make them explicit so new tests inherit them and the
whole stays greater than its parts.

**A — Test the CONTRACT, not the implementation.** The best tests pin observable
behavior a consumer depends on, so source can be refactored freely (the D15
cheap-change principle applied to tests). The repo does this well (guard metamorphic
relations, api/ baselines, golden wire output). **New synergy to name:** the
de-monolith campaign (§26.4) WILL trip over implementation-coupled tests — audit for
them as part of each split and lift them to contract level. (And `dispatch/tests.rs`
at 14,887 lines is itself a test-monolith that hides gaps — split it alongside its
source.)

**B — Invest where THIS system's bugs concentrate (test-trophy, not uniform
pyramid).** The retro + bug-hunt name the hotspots precisely: datetime/type
conversion, the connect descriptor/TLS, release-mechanics, and concurrency. Weight
new test effort there deliberately — golden+metamorphic for the first two, the
pre-tag rehearsal for the third, **loom for the fourth (the one underinvested
layer)** — rather than spreading coverage uniformly. Uniform coverage of a
well-tested guard buys nothing; a loom model-check of the lane lock-ranks buys a
whole bug class.

**C — Coverage FINDS HOLES; mutation MEASURES ASSERTIONS. Use both, neither alone.**
Line coverage tells you what is *definitely untested* (0 hits = a hole to fill); it
says NOTHING about whether the tests that run the code actually *check* the result
(100% coverage with no asserts is worthless). Mutation testing measures exactly that
gap (a surviving mutant = code exercised but under-asserted). The repo already has
both (llvm-cov now proposed; cargo-mutants on the guard). **The decision:** pair
them — coverage points the next test at an unexercised branch; mutation points it at
an under-asserting one. Report BOTH per crate; a coverage ratchet without a mutation
floor is gameable (assertion-free tests lift coverage), so the ratchet's guard is a
per-crate mutation-score floor on the safety-critical crates (guard/audit/db).

**D — Pick the test TYPE by the code's shape (decision rule, so new tests choose
right).** Pure function → property test (∞ examples, one test). Parser of untrusted
bytes → fuzz (finds the input you didn't imagine). Wire format → golden bytes (pins
exact output, cheap, diffable). State machine → model-check (loom, all
interleavings). Cross-service behavior → real-service e2e (no mocks). Numeric/
type-sensitive path → value-asserting golden that asserts the *discriminating*
property (type/offset/precision), never equality that collapses it. This rule is how
the §30.5 self-fulfilling-fixture class is prevented by construction.

**E — Determinism is non-negotiable: inject everything non-deterministic.** Time,
randomness, and concurrency ordering are seeded/injected, never ambient — a test
that reads the wall clock or races the scheduler is a future flake (the retro's
flaky-cancellation pain). The repo has the hooks (`seeded_fault_injection.rs`, the
harness replay SEED); make it the rule. Flaky tests get nextest-retry + a quarantine
list (§25 P1.4), never `#[ignore]`d into oblivion — an ignored flake is a silently
lost invariant.

**F — Executable invariants: every safety rule in this plan should BE a named
test.** SEC-1..7, the hard invariants (fail-closed guard, session-lease,
NUMBER→string, per-DB ceiling), the "audit records only executed statements" split —
each should have a test whose name IS the invariant, so it cannot silently erode.
Many exist (SEC-1 re-classify, `mr_oracle_never_loosens`, the ceiling clamp). **Gap
worth closing:** an enumerating test that EVERY dispatch write/DDL/session path
re-classifies at apply (SEC-1) — the bug-hunt verified it by reading; a test pins it
against a future new tool that forgets. This is the highest-leverage new test the
plan can add: it converts a manually-audited invariant into a self-guarding one.

**G — The suite is executable SPECIFICATION and must stay navigable.** The
conformance harness (python-oracledb differential) already IS the parity spec; the
metamorphic relations ARE the classifier spec. Keep the §30.3 scorecard live
(generated, not hand-maintained) so "what tests X?" is one lookup, and split test
monoliths alongside source (§26.4) so gaps can't hide in a 15k-line file.

**Net:** the reorganization is not "write more tests" — it is (1) measure what's
covered AND asserted (C), (2) weight new effort at the bug hotspots with loom the
priority (B), (3) make the safety invariants self-guarding (F), (4) prevent the
self-fulfilling class by a type-selection rule (D), and (5) keep it deterministic and
navigable (E, G) — all inside the four-tier schedule (30.6). That is a suite that is
worth its cost, not merely large.

---

## 31. Logging & observability audit (2026-07-18)

Investigated whether oraclemcp has logging and how good it is (verified by reading
the stack directly, cross-checked by a subagent).

### 31.1 Verdict — yes, it has a proper, well-architected observability stack

- **Mechanism:** `tracing` + `tracing-subscriber` (features `json, env-filter, fmt,
  registry`), initialized in `crates/oraclemcp-telemetry/src/logging.rs`
  (`init_json_logging` / `init_telemetry`). Structured **JSON** output.
- **stdio-safe by construction (the critical property for an MCP stdio server):**
  the subscriber uses `.with_writer(std::io::stderr)` — logs go to **stderr**, never
  stdout, so they can never corrupt the JSON-RPC frames on stdout. This is exactly
  the "stderr isolation" invariant the driver's compatibility audit calls for.
- **Filtered & quiet by default:** `EnvFilter::try_from_default_env()` (RUST_LOG),
  falling back to a configured default level. Idempotent init (`OnceLock`) so
  repeated `serve`/test invocations don't double-install.
- **Correlation — WEAK/aspirational (corrected 2026-07-18 by a deeper trace).** The
  subscriber sets `.with_current_span(true)`, and `logging.rs`'s doc CLAIMS "a span
  per request with request_id/tool_name/db_user" — but that span is **not actually
  created on the served path**: the only non-test `#[instrument]` in the whole
  workspace is one trace-level span in `catalog_extract.rs:281`; every
  `info_span!("request")` lives in a test module, and `OtlpLogLayer::on_event`
  ignores span context (never sets trace_id/span_id). So log lines carry **no**
  request/session/lane/subject correlation today. (My first pass inferred correlation
  from `with_current_span` + `request_id` string literals — wrong; the doc is
  aspirational. Same doc-vs-reality pattern as the retry.rs comment and the DC1
  fixtures — flagged as an executable-invariant candidate.)
- **Redaction — OTLP-path only, NOT the local stderr layer (corrected).** The
  thorough `Redactor` (key denylist + value-shape backstop + finite `db.*` allowlist
  + subject-sha256 exception) runs **only on the OTLP export path**. The always-on
  local stderr JSON layer **bypasses it** and relies on caller discipline — which in
  practice is good (IAM logs reason-codes only; SQL is logged as SHA+preview, never
  binds) but has **no structural backstop**. (My first pass said "shared for both" —
  wrong; it's export-only.)
- **OTLP path:** optional wired export (`TelemetryGuard`/`ExportPump`) over
  asupersync's `LogsSnapshot::to_otlp_protobuf` + spans/metrics, with a bounded
  shutdown drain; local-JSON-only when no endpoint is configured.
- **Deliberately minimal & concentrated** (per AGENTS.md "structured, minimal logs;
  logs are for operators; UX is UI-first"): usage is in oraclemcp-bin (~43),
  core (~32), telemetry (~11), audit (~10), db (~3) — and **zero** in guard, auth,
  config, error, verifier. That silence is by design: the guard returns typed
  decisions and refusals flow to the observer-only refusal corpus + the audit chain,
  not to logs. **Diagnostic logging is correctly SEPARATE from the tamper-evident
  audit chain** (two different trust levels).

So: it has real, well-architected logging — **dependable** on the load-bearing
axes (stdio-safety, export-path secret hygiene, quiet-by-default, and the correct
separation of diagnostic logs from the tamper-evident audit chain) — but
**under-built** on two axes (§31.2): request-level correlation is aspirational-only,
and the always-on local path has no structural redaction backstop. The foundation is
right; two wires are missing.

### 31.2 Gaps & improvements (small, real)

1. **The stdio-safety invariant is convention, not enforced.** 47 `println!` exist
   but they are in CLI/management modules (`discover.rs`, `main.rs`,
   `service_lifecycle.rs`, `file_store.rs` — human-facing stdout is correct there),
   NOT the served JSON-RPC loop (`server.rs`, which serializes frames properly). But
   nothing PREVENTS a future edit from adding a `println!` to the serve path and
   silently corrupting the protocol. **Add an executable invariant (§30.9-F):** a
   lint/test asserting no `println!`/stdout write is reachable from the served
   request handler (an arch-fitness rule, like the engine-free boundary lint).
2. **The local stderr path has NO structural redaction backstop** — it relies on
   caller discipline. Add the `Redactor` as a `tracing` layer on the local path too
   (not just OTLP), so a future careless `error!("... {dsn}")` cannot leak; and a
   test that NO secret/OCID/bind/DSN reaches a log line (drive a connect failure with
   a secret-bearing DSN, assert the JSON log is clean) — closing the gap for logs
   AND OTLP together (also covers the §28 CF2 prose-OCID case).
3. **Correlation is effectively absent — wire the per-request span the doc already
   promises.** Create one `info_span!` per served request carrying
   `request_id`/`session`/`lane`/`subject`/`tool`, and have `OtlpLogLayer` propagate
   trace_id/span_id — this makes multi-tenant debugging one-grep AND un-starves the
   OTLP traces surface (today essentially no real spans are emitted). Higher value
   than "low" — it's the difference between having traces and not. The audit chain
   carries authoritative correlation for *governed* actions, but diagnostic logs
   currently can't be tied to a request at all.
4. **Two operator-relevant events aren't logged at all:** guard refusals (the guard
   crate has 0 `tracing` — refusals go only to the audit/refusal-corpus) and the
   former lease revoke/expiry path (the deleted `crates/oraclemcp-db/src/lease.rs`
   had 0 `tracing` before B14b removed the dead subsystem). By design the guard
   returns typed decisions, but an operator tailing stderr sees nothing when a
   refusal or a revocation happens — a `warn!`/`info!` (reason-code only, no
   SQL/secret) on those two paths is a cheap operator-experience win.
5. These fold into §30.4 (the log-redaction test), §30.9-F (the no-stdout-in-serve +
   per-request-span as executable invariants), and Charter/arch-fitness — cheap, no
   new subsystem. The correlation fix (#3) is the one with real leverage.

---

## 32. External triangulation (GPT-5.6 Terra, high effort) + the accretive frontier

The §30 test plan was cross-validated by fanning out **GPT-5.6 Terra (high reasoning,
read-only)** over both repos via `codex exec` (the `multi-model-triangulation`
skill's intent, run directly). It grounded every point in real files. Its verdict:
*"§30 is a strong inventory, but it overinfers effectiveness from breadth and test
count; the single biggest omission is an executable compatibility/error-contract
matrix spanning versions, crates, features, and real failure modes; use coverage as a
diagnostic, not the proof of sufficiency."* This confirms §30.9-C (coverage finds
holes, doesn't prove quality) and adds real blind spots §30 missed.

### 32.1 Confirmed corrections (already applied above)

- **§30.7 overstated the existing OCI coverage** — it is auth-smoke, not a capability
  sweep; corrected in place.
- **§30.6's four-tier model contradicts current CI reality** (Free23/VECTOR is
  per-PR) — corrected to a machine-checkable manifest that lanes must be *moved* to
  match.

### 32.2 New blind spots to fold in (Terra's finds, ranked)

| ID | Finding | Fix (test type / tier) |
|---|---|---|
| TRI-1 (P0) | **Coverage ratchet as headline gate rewards assertion-free tests.** | Gate on *changed-line* coverage + a **named invariant/negative test** for safety-critical diffs, not a global "never decrease" line; a per-crate **mutation floor** on guard/audit/db is the ratchet's guard. Extends §30.2/30.9-C. |
| TRI-2 (P0) | **Mutation metric not uniformly meaningful** — timeouts counted as kills; only guard/audit mutated. | Report confirmed-test-failure kills vs timeout/unviable separately; require survivor triage; extend cargo-mutants to core/db/dispatch. Extends §27.2 C3. |
| TRI-3 (P0) | **No versioned contract / migration tests.** `structured_schema_golden` checks hand-written examples, not that OLD emitted JSON/audit/config state stays consumable across a version bump. | Archived **vN fixtures** + producer/consumer **compatibility matrix**; a contract-version bump must follow an explicit compat policy with a test. (This is Terra's "single biggest omission" — a governed server that persists audit/config/state MUST prove backward-compat.) |
| TRI-4 (P0) | **The two-repo (driver↔server) contract isn't a real bidirectional gate.** `oracledb_contract.rs` claims driver qualification runs it, but driver PR CI tests only its own workspace. | Vendor/pin a **shared contract crate** (or fetch the exact server-contract revision in driver qualification) + a compatibility manifest. Closes the seam the §26 driver-adapter boundary depends on. |
| TRI-5 (P1) | **Teardown failure is a security/cost incident, not a warning.** OCI destroy can leave a resource. | Durable, secret-safe resource id in protected CI state; retry/poll deletion to terminal; alert; **block the next provision until reconciliation succeeds.** Folds into §30.7. |
| TRI-6 (P1) | **No systematic error-path matrix** — §30 named a few regressions, not a matrix. | error-class → fault-injection table: partial-audit-write/disk-full, cancellation at EVERY DB boundary, malformed remote responses, token-expiry/clock-regression, retry-no-duplicate-effect. Tier-1/2. (This is the DI1/publish-before-persist class generalized.) |
| TRI-7 (P1) | **Flake detection & quarantine discipline missing.** The OCI IAM path retries 15×20s, masking propagation failures and burning the run. | Repeated-run statistics, quarantine with expiry, **distinguish infra-skip from product-failure**, a strict **no-retry diagnostic lane**, attempt telemetry. Extends §30.9-E. |
| TRI-8 (P1) | **Golden governance: over-scrubbing can erase real regressions.** | Each scrubber rule needs a **negative canary** proving it doesn't mask a protected field; goldens carry generator/source-version provenance; a reviewer-approved regeneration command. |
| TRI-9 (P2) | **Performance evidence overclaimed** — server perf is ignore/measurement-only. | Preserve minimized proptest/fuzz findings as reviewed **regression corpora**; injectable clocks + bounded schedule exploration for state machines; don't call perf "covered." |

These are candidate beads; TRI-3 + TRI-4 (versioned/cross-repo contract) and TRI-6
(error-path matrix) are the highest-value additions and join the CI Tranche 2 /
§30.4 test work.

### 32.3 The radically innovative + accretive move: **verifiable test attestation**

Reasoning across the whole plan — the product's entire thesis is *"don't trust
claims, verify them"*: a fail-closed guard, a keyed-MAC **hash-chained audit** chain
(ADR-0003), standalone **verdict certificates** + the `oraclemcp-verifier` crate
(ADR-0010), cosign/SLSA release attestations, and the §10.7 browser that
**re-verifies the demo's evidence itself**. The observability (§31) and test
machinery are built to that same fail-safe, redacted, evidence-first standard. The
one place this thesis is NOT yet applied is **the tests themselves** — today "tests
pass" is an unverifiable assertion in a CI log, exactly the kind of claim the retro
(§27) is about not trusting.

**The move: ship a signed, verifiable TEST-EVIDENCE ATTESTATION bound to each
release binary — reusing the governance machinery already built, adding no new
subsystem.** Concretely, the release emits (and cosign-signs, alongside the SBOM and
provenance it already produces) a `test-evidence/vN` document containing: the
measured **coverage** and **mutation** numbers per crate; the list of **named safety
invariants** that passed (the §30.9-F executable invariants — guard-fail-closed,
SEC-1 re-classify-at-apply, ceiling-never-exceeded, audit-tamper-evident); the
**conformance parity** number (as-of SHA, §27.6 V5); the **fuzz corpus** hash and
zero-new-crashes assertion; and the exact toolchain/SHA. It is bound to the binary's
digest and verifiable by a verifier path modeled on the **`oraclemcp-verifier` +
cosign** flow a user already uses for a verdict certificate (a new `test-evidence/vN`
schema + a small verifier extension + its threat model are the actual build work —
this is a design, not free) — so anyone (an auditor, a DACH Oracle partner in the
§2.7 GTM, an HN skeptic) can run one command and confirm *"this exact binary passed
its named fail-closed-guard tests, its Oracle conformance was X% as-of this SHA, and
its named safety-invariant tests all passed — here is the signed evidence, check it
yourself."* (Precisely: the signature attests that the named tests **ran and passed**
against this binary — evidence of testing, not a proof of correctness. Stated that
way it stays inside §3.4's wording rules.)

Why it is *innovative* (a hypothesis to validate, not an asserted market fact — per
§3.4, no "first/only/nobody" without a survey): we are not aware of a tool that ships
a cryptographically verifiable, artifact-bound record of its own safety-test results;
today that is universally "trust our CI." Why it is *accretive*: it is the test-world
twin of the
§10.7 verifiable launch and reuses **infrastructure already in the repo** — the
audit-chain hashing, the verdict-verifier crate, the cosign/attestation release step,
and the coverage/mutation/invariant lanes §30–§32 are adding — so it is a
**composition**, not a new category. It turns the entire testing program from an
internal cost center into the product's sharpest external differentiator, and it
closes the retro's deepest wound (§27: unverifiable green) by construction: after
this, "green" is not a claim — it is a signature anyone can check. That is the single
highest-leverage accretive idea the plan contains: **make the tests prove
themselves, with the machinery you already built to make the product prove itself.**

### 32.4 Whole-plan review (GPT-5.6 Sol, high effort) — findings + disposition

A second external pass reviewed the full plan for bead-readiness and consistency.
Its 15 findings and what was done:

- **Fixed in place:** scope header stale ("four parts → §27") → now seven parts
  §1–33 (F15); `T1–T9` namespace collision (§27 tracker vs §32.2 test) → §32.2
  renamed `TRI-1..9` (F3); the §30.2-vs-§32.2 **coverage-ratchet contradiction** →
  §30.2 amended to the changed-line + mutation-floor design, one design everywhere
  (F6); dangling refs `§27.6.5`, `§4-WD` (F1/F8); G0.2 still waiting for the
  "in-flight" v0.9.0 train → published-default now (F4); §29.4 called SNI
  "in-flight" → SNI shipped, `he7t` is the only residual (F5); §30.7 concluded "one
  session" after arguing for many → "one ADB, many sessions/schemas/roles" (F12);
  §28.1/§28.6 "surfaces are sound" overclaimed a static read → "no defect surfaced
  in the bounded static review; the dynamic/Kani/fuzz gates prove it" (F13); §32.3
  "nobody ships / proven fail-closed / same verifier" violated §3.4 → reframed as
  "signed evidence that named tests passed," novelty as a hypothesis, verifier
  contract named as build work (F14).
- **Addressed by an honesty note (the real bead-readiness point):** the plan
  describes programs, not a normalized per-bead spec for all ~130 beads — §33's
  (a)/(b) conversion-state note + the §28.5 Low-findings temper now make that
  explicit, and normalizing the (b) items is the P6-gated first act of each
  conversion, not a hidden gap (F2/F7).
- **Reproduced for self-containment:** the operator's 12-rule constitution now lives
  inline in §27.3 (was a bare ref to companion-doc §3G) (F10).
- **Clarified:** the live version-matrix is an advisory scheduled *producer* whose
  green exact-SHA evidence the *release-qualification consumer* hard-gates on — §30.6
  now states the producer/consumer split so "advisory Tier 2" and "hard release
  gate" don't read as contradictory (F11). The §25.7/§26.6 "during the current
  release" sequencing is a pre-release historical snapshot that **§29.6 already
  explicitly supersedes** (the release shipped, the §25.7.1 zero-edits hold is
  lifted) — read those as the intent-at-the-time, §29.6 as the current instruction
  (F9).

**Sol's verdict was "not yet fully bead-ready; biggest blocker = undefined P6 + no
normalized per-bead spec."** After these edits: P6 has a scope (§27.6 item 5 / §33
precondition) as its own bootstrap bead, and per-bead normalization is named as each
conversion's explicit first step. The plan is **bead-ready as a program** — a GO can
start cluster A/B immediately; the (b)-state clusters normalize-then-lint on the way
in.

---

## 33. Beading index — what to convert when GO is given

The bead-able programs are specified across the plan; this is the single lookup so a
fresh implementer given GO does not have to hunt. **Precondition (all programs):**
build the **P6 plan/bead-graph lint** first (§27.6 item 5 — its own operator-created bootstrap bead: input = the converted bead clusters; checks = unique slugs, acyclic deps,
unique labels, resolvable cross-refs — and run every conversion below through it
before any bead is created. Beads are created per the repo-local `br` trackers (never
cross-repo native edges — use the checksum-handoff pattern of §19.6). Nothing here is
authorized until the operator says GO.

| # | Program | Source § | Repo(s) | Trigger / gate | Priority | ~beads |
|---|---|---|---|---|---|---|
| A | **Post-release hygiene** — close the 6 confirmed false-open beads (`x1hr`,`.1`,`.3`,`tzju`,`2lz4`, driver `c23g`; all tree-verified §26.7), doc staleness (`hsvv`,`izk5`), and the two NEW gitignore commit-hazards (oraclemcp `.codex/`/`codex.mcp.json`, driver `.claude/`) | §29.6, §29.2, §26.7 | both | now (release done) | **P0-immediate** (trivial, ledger honesty) | ~8 |
| B | **CI velocity — Tranche 1** (scheduling-only edits: P0.3b/P0.4b needs-removal, P1.1/P1.2/P1.5/P1.6, move `_quality.yml` out of workflows) | §25.2–25.4, §25.7.2, §29.3(pre-tag rehearsal) | both | now (hold lifted §29.6) | **P0** (compound leverage) | ~8 |
| C | **Repo/disk janitor** — 21 worktrees, dead branches/tags, ~50 GB, stray nested `target/`, file moves | §26.1–26.6 | both | anytime idle; janitor pass w/ operator ack | P1 | ~6 |
| D | **CI velocity — Tranche 2** (`_quality.yml` split + parser update, fuzz shard, prep mode, **coverage baseline+ratchet** §30.2, mutation-lane integrity §27.2 C3 / §32.2 TRI-2) | §25.7.3, §30.2, §32.2 TRI-1/TRI-2 | both | after Tranche 1 | P0-P1 | ~10 |
| E | **Charter v2 + swarm hardening** (worktree-per-agent W1, build-lease W3, 12-rule constitution, spawn preflight O4, CI heartbeat O3, tracker T1–T4, cm seeding) | §27.3–27.5 (Tranches 4–5) | both + AGENTS.md/NTM | before next swarm campaign | P0 (gates next swarm) | ~15 |
| F | **Bug-hunt fixes** (§28 verified: 4 High DC1/DC2/PY1/PY2, 5 Med DC3/PY3/PY4/DI1/MET, Low set) each = fix + discriminating test | §28.2–28.5 (priority §28.5) | both | driver 0.9.0 / server 0.10.0 (§29.7 correction — behavior fixes, no extra scope from the rename) | **P1** (4 High first) | ~25 |
| G | **Product features** — F-D1 residual (`he7t` IAM subject-mapping config → first full OCI signoff), F-D2 (Live-green streak), F-S1 (typed SCN), F-S2 (lane-health tile), F-S3 (ADK compat fixes) — **all in the 0.10.0/0.9.0 train; nothing deferred by the rename** | §27.7, §29.7 | both | 0.10.0/0.9.0 train; F-D1/he7t small | P1 | ~6 |
| H | **Test coverage & organization** — surgical regressions §30.4 (1–11), verification hardening §27.6 V-series, error-path/contract/migration matrix §32.2 TRI-3/TRI-4/TRI-6, loom/fuzz §30.4, tier manifest §30.6, self-fulfilling-fixture rule §30.5, logging fixes §31.2 | §30.4, §30.6, §30.9, §31.2, §32.2 | both | with F (each bug's test) + Tranche 2 | P1-P2 (TRI-3/TRI-4/TRI-6 highest) | ~20 |
| I | **OCI Always-Free ADB e2e** — one disposable ADB, isolated schemas/users, full capability sweep, teardown-as-incident | §30.7, §32.2 TRI-5 | oraclemcp | after `he7t` (config step); then **agent-runnable** (free-tier guardrails, no per-run approval) | P2 (F-D1's acceptance evidence) | ~4 |
| J | **GCP/Vertex demo → site → video → launch** | §7/§11/§12/§13, beads §19.1–19.5, procedure §19.6 | oraclemcp (G) + durakovic-ai (S/V/L) | operator GO + target SHA (v0.9.0); two-wave handoff §19.6; campaign-order gate §13.0 | **credibility fuel for the money goal (§2.7)** — supporting act, ship-before-polish, don't let it starve the GTM | ~30 |
| K | **Verifiable test attestation** (accretive frontier) | §32.3 | both | after D+H (coverage/mutation/invariant lanes exist) | P3 (differentiator, not blocking) | ~4 |

Suggested GO order: **A → B (∥ C) → D → E → F+H → G → I → J** (J can start in parallel
once its target SHA is chosen, per §2.7 it is the money priority but rides the
existing campaign order §13.0); **K** is the capstone once its inputs exist.

**Bead-readiness honesty (Sol P0-2/7):** this index is the map, not a per-bead spec.
Two conversion states exist and the P6 lint pass must resolve the second before
those beads are created: (a) **fully specified** — carry ID + scope + acceptance +
tier + repo directly (the §28.2 High/Med findings with fix+test, the §25 CI items,
the §19 GCP B-beads, §29.6 actions); (b) **needs per-bead normalization at
conversion** — the §28.3 Low/Very-Low findings (prose, not all with an explicit
site/fix/test — normalize or mark non-beadable), the §31.2/§32.2 items (some are
directions, not scoped beads), the GCP S/V beads (§19.3–19.4 give deps but not full
acceptance), and the Charter W/O/CM items (§27.3 bundles several). Converting a
cluster = expand (b) into the (a) shape, then run P6. So the plan is *bead-ready as a
program* (every cluster has a clear scope + trigger + order here), and the first act
of each conversion is normalizing its (b) items — not a gap, the explicit first step.
