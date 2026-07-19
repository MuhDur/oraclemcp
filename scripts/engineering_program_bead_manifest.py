#!/usr/bin/env python3
"""Emit the immutable PLAN_ENGINEERING_PROGRAM.md to-Beads import specification.

This file is conversion provenance, not a status tracker. Runtime state belongs
only in each repository's local Beads database. ``promotion`` says how a plan
item is imported: create a Bead, reuse an existing Bead, defer the strict GCP
second wave, or retain a non-actionable decision as a record-only mapping.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


PLAN = "docs/plan/PLAN_ENGINEERING_PROGRAM.md"
PROGRAM = "engineering-program-2026-07-18"
tasks: list[dict[str, Any]] = []


def plan_label(slug: str) -> str:
    digest = hashlib.sha256(slug.encode("ascii")).hexdigest()[:8]
    return f"plan:ep260718:{slug[:27]}-{digest}"


def patch_acceptance(specific: str) -> list[str]:
    return [
        specific,
        "The change remains behavior-only for server 0.9.1 or driver 0.8.5, introduces no new public API, and passes cargo-semver-checks.",
    ]


def patch_evidence(specific: str) -> list[str]:
    return [
        specific,
        "Focused regression, repository fmt/clippy/tests/deny gates, SemVer report, and exact landed paths.",
    ]


def handoff(task_slug: str, artifact: str | None = None) -> dict[str, str]:
    return {
        "task": task_slug,
        "artifact": artifact or f"Checksum-bound completion evidence for {task_slug}",
        "checksum": "required",
    }


def add(
    slug: str,
    repo: str,
    title: str,
    source: str,
    scope: str,
    acceptance: list[str],
    evidence: list[str],
    *,
    cluster: str,
    issue_type: str = "task",
    priority: int = 1,
    tier: str = "tier-1",
    depends_on: list[str] | None = None,
    handoffs: list[dict[str, str]] | None = None,
    parent: str | None = None,
    operator_gate: str = "none",
    promotion: str = "create",
    existing_id: str | None = None,
    condition: str | None = None,
    lineage: list[dict[str, str]] | None = None,
    reuse_action: str | None = None,
) -> None:
    tracking_label = plan_label(slug)
    task: dict[str, Any] = {
        "slug": slug,
        "tracking_label": tracking_label,
        "repo": repo,
        "title": title,
        "type": issue_type,
        "priority": priority,
        "labels": ["engineering-program", f"cluster-{cluster.lower()}", tracking_label],
        "source_refs": [f"{PLAN}:{source}"],
        "scope": scope,
        "description": (
            f"Normalized from PLAN_ENGINEERING_PROGRAM.md cluster {cluster}. {scope} "
            "Preserve repository safety, exact-SHA evidence, and fail-closed behavior."
        ),
        "acceptance_criteria": acceptance,
        "evidence": evidence,
        "tier": tier,
        "depends_on": depends_on or [],
        "handoffs": handoffs or [],
        "operator_gate": operator_gate,
        "promotion": promotion,
    }
    if lineage:
        task["lineage"] = lineage
    if parent is not None:
        task["parent"] = parent
    if existing_id is not None:
        task["existing_id"] = existing_id
    if promotion == "reuse":
        task["reuse_action"] = reuse_action or "continue"
    if condition is not None:
        task["condition"] = condition
    tasks.append(task)


# P6 — sole bootstrap exception.
add(
    "p6-plan-bead-graph-lint",
    "server",
    "P6: validate the normalized plan-to-Beads graph",
    "4447-4450",
    "Validate the complete two-repository program before any non-bootstrap plan Bead is promoted.",
    [
        "Unique slugs and plan labels, complete task fields, source anchors, exact SemVer targets, repo-local dependencies, checksum handoffs, and acyclic graphs all fail closed.",
        "The full live import manifest passes the validator before promotion.",
    ],
    ["Unit and CLI test transcript plus the successful full-manifest lint summary."],
    cluster="P6",
    issue_type="task",
    priority=0,
    tier="process",
    promotion="reuse",
    existing_id="oraclemcp-plan-bead-graph-lint-eshv",
)


# A — post-release ledger and commit hygiene.
add(
    "a-close-driver-084-release",
    "driver",
    "Close the shipped driver 0.8.4 release epic",
    "4213-4224",
    "Reconcile the false-open driver release umbrella without changing code or publishing anything.",
    ["All children are closed and v0.8.4 is published from the exact tagged SHA with a successful release run."],
    ["v0.8.4 tag SHA, run 29596141970, crates.io version, and server pin evidence."],
    cluster="A",
    issue_type="epic",
    priority=0,
    tier="process",
    promotion="reuse",
    existing_id="rust-oracledb-driver-next-release-c23g",
)
add(
    "a-close-server-090-release",
    "server",
    "Close the shipped server 0.9.0 release epic",
    "4716-4752",
    "Reconcile the false-open server release umbrella against the published tag and its children.",
    ["Every release child is closed and the close reason cites the published exact tag rather than current-main tests."],
    ["v0.9.0 tag 0c663d8d19ffd4a16c5cdb19c5c7d547531bb8cc and run 29638451182."],
    cluster="A",
    issue_type="epic",
    priority=0,
    tier="process",
    handoffs=[handoff("a-close-driver-084-release", "Published v0.8.4 tag and release-run checksum evidence")],
    promotion="reuse",
    existing_id="oraclemcp-server-next-release-x1hr",
)
add(
    "a-close-server-084-repin",
    "server",
    "Close the completed server repin to driver 0.8.4",
    "4743-4752",
    "Record that the shipped server tag pins both driver crates exactly at 0.8.4 and was requalified.",
    ["The v0.9.0 manifest and lock prove both exact pins and the exact-SHA release run succeeded."],
    ["Tagged Cargo manifests, lockfile, tag SHA, and release run URL."],
    cluster="A",
    priority=0,
    tier="process",
    parent="a-close-server-090-release",
    handoffs=[handoff("a-close-driver-084-release", "Published driver 0.8.4 release checksum")],
    promotion="reuse",
    existing_id="oraclemcp-server-next-release-x1hr.1",
)
add(
    "a-close-server-090-qualification",
    "server",
    "Close the completed server 0.9.0 qualification",
    "4716-4749",
    "Reconcile the exact-SHA release-qualification leaf after the successful tag pipeline.",
    ["The published v0.9.0 tag has a green exact-SHA Release workflow and immutable evidence."],
    ["Release run 29638451182 and exact tag SHA 0c663d8d19ffd4a16c5cdb19c5c7d547531bb8cc."],
    cluster="A",
    priority=0,
    tier="process",
    parent="a-close-server-090-release",
    depends_on=["a-close-server-084-repin"],
    promotion="reuse",
    existing_id="oraclemcp-server-next-release-x1hr.3",
)
add(
    "a-close-server-asupersync-039",
    "server",
    "Close the completed asupersync 0.3.9 upgrade",
    "4213-4224",
    "Record the shipped 0.3.9 pin without restating the nightly-feature attribution incorrectly.",
    ["The v0.9.0 tag pins 0.3.9 and its exact-SHA release gates passed."],
    ["Tagged Cargo manifest lines, lockfile, and release-run evidence."],
    cluster="A",
    priority=0,
    tier="process",
    depends_on=["a-close-server-084-repin"],
    promotion="reuse",
    existing_id="oraclemcp-tzju",
)
add(
    "a-close-server-adb-sni",
    "server",
    "Close the stale OCI ADB SNI blocker",
    "4754-4759",
    "Record that driver 0.8.4 shipped the Oracle service SNI solution and the old 0.8.3 blocker is obsolete.",
    ["Published driver source and the server pin prove the SNI capability; only IAM subject mapping remains."],
    ["Driver v0.8.4 tag, server v0.9.0 pin, and prior live ADB signoff."],
    cluster="A",
    issue_type="bug",
    priority=0,
    tier="process",
    handoffs=[handoff("a-close-driver-084-release", "Driver v0.8.4 SNI implementation checksum")],
    promotion="reuse",
    existing_id="oraclemcp-2lz4",
)
add(
    "a-server-090-doc-hygiene",
    "server",
    "Publish truthful 0.9.0 operator documentation",
    "4725-4764",
    "Update active operator documentation to 0.9.0 and driver 0.8.4 truth, correct the ship date, and preserve historical release records as historical.",
    ["Current-state docs agree on 0.9.0 and 0.8.4, historical 0.8.x records remain labelled, and links resolve."],
    ["Targeted stale-version scan, documentation link checks, and reviewed diff."],
    cluster="A",
    priority=2,
    tier="tier-1",
    promotion="reuse",
    existing_id="oraclemcp-hsvv",
)
add(
    "a-driver-084-doc-hygiene",
    "driver",
    "Publish truthful driver 0.8.4 release documentation",
    "4716-4764",
    "Update the active driver README, CHANGELOG, CURRENT_ROADMAP, PUBLISHING, GROUND_TRUTH, and ROADMAP from prepared-candidate wording to published v0.8.4 truth and the exact v0.8.5 patch target, including the release date and canonical tag links, while preserving historical qualification results as historical.",
    [
        "Current driver documentation identifies v0.8.4 as published, names exactly v0.8.5 as the active patch target, links the immutable release, retains honest historical-versus-fresh qualification wording, and contains no active prepared-candidate claim."
    ],
    [
        "Targeted stale-release scan, canonical v0.8.4 tag and crates.io evidence, documentation link checks, and reviewed diff."
    ],
    cluster="A",
    priority=2,
    tier="tier-1",
)
add(
    "a-server-doctor-driver-comment",
    "server",
    "Correct stale doctor driver-version comments",
    "4754-4765",
    "Verify the pinned 0.8.4 wallet error variants, then correct the stale doctor comments without blind substitution.",
    ["Every 0.8.4 wallet variant is reviewed explicitly and the focused typed mapping test passes."],
    ["Pinned-driver source inspection, focused test output, and exact diff."],
    cluster="A",
    priority=3,
    tier="tier-1",
    promotion="reuse",
    existing_id="oraclemcp-izk5",
)
add(
    "a-server-ignore-agent-state",
    "server",
    "Ignore Codex state without hiding evidence logs",
    "4054-4059",
    "Ignore .codex and codex.mcp.json while retaining an explicit allowlist for tracked test artifact logs and avoiding broad evidence-hiding patterns.",
    ["git check-ignore proves local agent state is ignored and intended tracked evidence logs remain visible."],
    ["Positive and negative git check-ignore transcript plus clean status."],
    cluster="A",
    issue_type="chore",
    priority=0,
    tier="tier-0",
)
add(
    "a-driver-ignore-agent-state",
    "driver",
    "Ignore driver agent state and local matrix artifacts",
    "4155-4158",
    "Ignore .claude, .ntm, and local version-matrix JSON artifacts without masking committed exact-SHA evidence.",
    ["Current local agent-worktree and matrix artifacts are ignored while tracked qualification evidence stays visible."],
    ["git check-ignore transcript for every class and a clean tracked status."],
    cluster="A",
    issue_type="chore",
    priority=0,
    tier="tier-0",
)


# B — CI velocity tranche 1 and release rehearsal.
add(
    "b-driver-required-proof-parallel",
    "driver",
    "Parallelize independently executed Required proof",
    "3887-3892",
    "Remove Required-proof's unnecessary qualification dependency while preserving independent exact-SHA execution and strict consumption rules.",
    ["Proof starts in parallel and cannot consume incomplete, stale, or different-SHA qualification output."],
    ["Workflow contract tests and a release-qualification run graph."],
    cluster="B",
    priority=0,
    tier="tier-0",
)
add(
    "b-driver-live-matrix-parallel-start",
    "driver",
    "Start the fresh live matrix before quality completes",
    "3893-3909",
    "Remove the fresh live matrix's scheduling dependency on quality while retaining it as a hard pre-tag gate.",
    ["The matrix starts in parallel, remains exact-SHA, and is still required before release qualification can pass."],
    ["Workflow-DAG assertion and one strict release-qualification run."],
    cluster="B",
    priority=0,
    tier="tier-0",
)
add(
    "b-server-release-build-overlap",
    "server",
    "Overlap seven-target release builds with acceptance",
    "3914-3919",
    "Run the server release build matrix alongside acceptance, then require both at publication without removing existing prerequisites.",
    ["Build needs only its real prerequisites and publish waits for acceptance plus every existing release gate."],
    ["Workflow contract test, actionlint result, and rehearsal DAG."],
    cluster="B",
    priority=1,
)
add(
    "b-server-acceptance-dedupe",
    "server",
    "Skip duplicate feature powerset work in release acceptance",
    "3920-3924",
    "Pass --skip-feature-powerset only where same-SHA CI already proves it; split other legs only when isolation and artifact semantics remain equivalent.",
    ["No mandatory test is lost and the acceptance invocation demonstrably avoids duplicate powerset work."],
    ["Argument contract test, same-SHA prerequisite proof, and timing comparison."],
    cluster="B",
    priority=1,
)
add(
    "b-driver-pinned-tool-installs",
    "driver",
    "Replace cold Cargo tool installs with pinned actions",
    "3934-3938",
    "Install cargo-hack, public-api, and semver-checks through reviewed pinned install actions without changing tool versions or policy.",
    ["Cold-cache workflows report the expected exact tool versions and retain existing supply-chain checks."],
    ["Cold-cache workflow run and captured tool-version output."],
    cluster="B",
    priority=1,
)
add(
    "b-driver-rq-single-flight",
    "driver",
    "Cancel superseded release qualification runs safely",
    "3939-3943",
    "Single-flight release qualification per candidate while protecting the run selected for an imminent tag from cancellation.",
    ["A newer candidate cancels an older one, but tag-selected qualification cannot be canceled accidentally."],
    ["Concurrency-expression tests and a two-dispatch demonstration."],
    cluster="B",
    priority=1,
)
add(
    "b-server-quality-projection-relocation",
    "server",
    "Move local quality projection outside workflow discovery",
    "4250-4256",
    "Move the server quality data projection out of .github/workflows and update the fail-closed parser and tests atomically.",
    ["GitHub no longer discovers a zero-job workflow and required-local parsing still fails closed on drift."],
    ["Parser tests, workflow listing, and local Required-proof result."],
    cluster="B",
    priority=0,
    tier="tier-0",
)
add(
    "b-driver-powerset-disk-assert",
    "driver",
    "Fail feature powerset early when disk is unsafe",
    "4250-4256",
    "Add real-free-space and write/read-canary checks to powerset and build-heavy jobs before compilation begins.",
    ["Insufficient or unwritable disk fails with a specific diagnosis before build work; healthy runners continue."],
    ["Low-space and canary-failure fixtures plus a healthy workflow run."],
    cluster="B",
    priority=0,
    tier="tier-0",
)
add(
    "b-driver-live-advisory-autoreblock",
    "driver",
    "Make Live nightly advisory with automatic reblocking",
    "4439-4446",
    "Expose the currently red Live nightly as honestly advisory and automatically restore blocking after exactly three consecutive green nights.",
    ["Red, infrastructure skip, and green streaks are distinct; the third consecutive green re-arms the gate."],
    ["State-machine tests and three immutable run IDs showing the transition."],
    cluster="B",
    priority=0,
    tier="tier-0",
)
add(
    "b-server-release-surface-runbook",
    "server",
    "Make version surfaces and release retry guidance deterministic",
    "4767-4794",
    "Provide one manifest-driven set-version writer, field/found/expected diagnostics, same-tag pre-publish retry guidance, and a warning-plus-headroom binary-size ratchet.",
    ["The writer is idempotent, stale fields fail specifically, and post-publish immutability remains explicit."],
    ["Stale-surface fixtures, writer idempotence test, and binary-budget boundary tests."],
    cluster="B",
    priority=0,
    tier="tier-0",
)
add(
    "b-server-pretag-release-rehearsal",
    "server",
    "Rehearse every server tag gate against a branch SHA",
    "4784-4794",
    "Add a non-publishing workflow_dispatch that runs seven target builds with size checks, package and tarball verification, and the full release gates against a candidate SHA.",
    ["A green rehearsal cannot tag or publish and cannot be mistaken for publish-valid tag evidence."],
    ["One green rehearsal run, complete artifact set, and negative permission test."],
    cluster="B",
    priority=0,
    tier="tier-0",
    depends_on=[
        "b-server-release-build-overlap",
        "b-server-acceptance-dedupe",
        "b-server-release-surface-runbook",
    ],
)


# C — repository/disk janitor and de-monolith work.
add(
    "c-server-git-state-janitor",
    "server",
    "Reconcile server worktrees, branches, tags, and stashes",
    "4012-4042",
    "Reverify and dry-run the merged worktrees and branches, fourteen stashes, dead master, dead retry tags, and historical release-0.8.1 state before any removal.",
    ["Every target and exact command is operator-approved first; branches use safe deletion where possible and stashes are reviewed individually."],
    ["Before and after inventories, release-object checks, stash diffs, exact-command approval, and clean status."],
    cluster="C",
    issue_type="chore",
    priority=1,
    tier="operator-gated",
    operator_gate="destructive",
)
add(
    "c-driver-git-state-janitor",
    "driver",
    "Reconcile driver worktrees, branches, and stashes",
    "4123-4154",
    "Review the a7b and a266 histories, stale worktrees and merged fp branches, local master tracking, and two stashes before exact approved cleanup.",
    ["No reversed a7b work is harvested, force deletion is target-specific, and upstream main tracking is correct afterward."],
    ["Content comparison, git cherry, before and after inventory, and exact-command approval."],
    cluster="C",
    issue_type="chore",
    priority=1,
    tier="operator-gated",
    operator_gate="destructive",
)
add(
    "c-server-disk-prune",
    "server",
    "Reclaim verified regenerable server disk bulk",
    "4044-4060",
    "Prune verified build targets, Vite stub, eligible Beads history, Go caches, compliance output, and temporary caches only while builds and swarms are idle.",
    ["Exact targets and commands are approved; infra, web node_modules, todelete, tracker state, and required evidence survive."],
    ["Process-idle proof, du inventory, exact-command approval, after-size report, and repository health checks."],
    cluster="C",
    issue_type="chore",
    priority=1,
    tier="operator-gated",
    operator_gate="destructive",
)
add(
    "c-server-doc-layout-normalization",
    "server",
    "Normalize server plan and documentation layout",
    "4061-4091",
    "Move the four root plans under docs/plan, normalize five document names and inbound references, and normalize release-surfaces permissions using history-preserving moves.",
    ["All path-sensitive references and scripts are updated and the full applicable local gates pass."],
    ["Rename-aware diff, inbound-reference scan, link checks, and gate transcript."],
    cluster="C",
    issue_type="chore",
    priority=2,
)
add(
    "c-server-tracked-residue-retirement",
    "server",
    "Retire dormant npm and completed campaign residue",
    "4061-4079",
    "Review and retire dormant npm sources while retaining the refusal workflow, remove completed skill-loop residue, and disposition every refactor file without losing useful content.",
    ["The operator approves exact removals, no release surface references removed npm, and useful refactor material is folded into docs."],
    ["Per-file disposition, reference/build scan, exact-command approval, and full gate."],
    cluster="C",
    issue_type="chore",
    priority=2,
    tier="operator-gated",
    operator_gate="destructive",
)
add(
    "c-server-readme-split",
    "server",
    "Split the oversized server README into focused documentation",
    "4090-4092",
    "Keep positioning, installation, quickstart, safety invariant, and support links on the front page while moving detail into discoverable linked documents.",
    ["No operator instruction or capability is dropped, anchors resolve, and the front page remains a complete safe starting point."],
    ["Section-coverage ledger, rendered review, and link-check output."],
    cluster="C",
    priority=2,
)
add(
    "c-driver-doc-layout-normalization",
    "driver",
    "Move driver planning files under docs",
    "4155-4163",
    "History-preservingly move plan.md, CODEX_GOAL.md, and the thin-port plan under docs, update references, and leave the clean-room reference checkout untouched.",
    ["All references resolve, repository gates pass, and reference remains ignored and unchanged."],
    ["Rename-aware diff, reference scan, and documentation/build checks."],
    cluster="C",
    issue_type="chore",
    priority=2,
)
add(
    "c-demono-epic",
    "server",
    "Isomorphically split the server monolith files",
    "4094-4121",
    "Run the one-file-per-Bead de-monolith campaign without compatibility clones, public-API drift, or weakened contract tests.",
    ["Every named large file has a child, implementation-coupled tests are lifted where appropriate, and final architecture gates pass."],
    ["Child coverage ledger, before and after line counts, module ownership map, and full gate report."],
    cluster="C",
    issue_type="epic",
    priority=1,
)

for slug, title, priority, dependencies, proof in [
    (
        "c-demono-dispatch-mod",
        "Split dispatch/mod.rs along proven seams",
        1,
        [],
        "dispatch API, guard, integration, and end-to-end tests",
    ),
    (
        "c-demono-web-app",
        "Split the Ground Control App.tsx monolith",
        1,
        [],
        "web tests, build, route replay, and fail-closed verdict cases",
    ),
    (
        "c-demono-dispatch-tests",
        "Split the dispatch test monolith with its source",
        2,
        ["c-demono-dispatch-mod", "c-demono-web-app"],
        "test discovery and count, fixtures, and contract-level assertions",
    ),
    (
        "c-demono-db-connection",
        "Split the database connection monolith",
        2,
        ["c-demono-dispatch-mod"],
        "connection, cancellation, recovery, and live-seam tests",
    ),
    (
        "c-demono-guard-classifier",
        "Split the fail-closed guard classifier",
        1,
        ["c-demono-dispatch-mod"],
        "classifier outcomes, safety invariants, and mutation proof",
    ),
    (
        "c-demono-main",
        "Split the binary main.rs orchestration monolith",
        2,
        ["c-demono-dispatch-mod"],
        "CLI, service startup, signal, and shutdown behavior",
    ),
    (
        "c-demono-core-lane",
        "Split the core lane orchestration monolith",
        2,
        ["c-demono-dispatch-mod"],
        "lane state, concurrency, and verdict contracts",
    ),
    (
        "c-demono-service-lifecycle",
        "Split service lifecycle orchestration",
        2,
        ["c-demono-dispatch-mod"],
        "restart, recovery, cancellation, and shutdown tests",
    ),
    (
        "c-demono-core-doctor",
        "Split doctor.rs into diagnostic domains",
        2,
        ["c-demono-dispatch-mod"],
        "stable diagnostic codes, JSON shapes, wallet posture, and secret tests",
    ),
    (
        "c-demono-http-operator",
        "Split the HTTP operator surface monolith",
        2,
        ["c-demono-dispatch-mod"],
        "HTTP authentication, operator, streaming, and refusal contracts",
    ),
]:
    add(
        slug,
        "server",
        title,
        "4094-4121",
        f"Extract cohesive modules from the named file, migrate callers, and preserve isomorphic observable behavior; prove with {proof}.",
        ["Public behavior and APIs remain unchanged, no v2 clone or compatibility shim is introduced, and focused plus applicable full gates pass."],
        [f"Before and after line counts, module map, reviewable diff, and {proof}."],
        cluster="C",
        priority=priority,
        parent="c-demono-epic",
        depends_on=dependencies,
    )


# K — signed test-evidence attestations bound to release binaries.
add(
    "k-server-test-attestation",
    "server",
    "Bind server release binaries to verifiable test evidence",
    "5408-5453",
    "Extend existing exact-SHA evidence, SBOM, provenance, cosign, and verifier machinery with a versioned statement that named tests ran and passed for the exact server binary.",
    ["The wording never claims proof of correctness and every child is downstream of measured D and H inputs."],
    ["Schema, producer, verifier, threat-model, and tamper-matrix closure ledger."],
    cluster="K",
    issue_type="epic",
    priority=3,
    tier="tier-3",
    depends_on=[
        "d-server-coverage-ratchet",
        "d-server-mutation-integrity",
        "h-server-tier-manifest",
        "h-server-monitor-predicate-delta",
    ],
)
add(
    "k-driver-test-attestation",
    "driver",
    "Bind driver release binaries to verifiable test evidence",
    "5408-5453",
    "Extend the driver exact-SHA evidence, SBOM, provenance, and release attestations under the shared test-evidence schema without changing published crate API.",
    ["Every input is sealed, exact-SHA, and binary-bound and the statement is limited to named tests having run and passed."],
    ["Driver producer closure ledger, shared-schema checksum, and signed dry-run evidence."],
    cluster="K",
    issue_type="epic",
    priority=3,
    tier="tier-3",
    depends_on=[
        "d-driver-coverage-ratchet",
        "d-driver-mutation-integrity",
        "h-driver-tier-manifest",
        "h-driver-monitor-predicate-delta",
    ],
)
add(
    "k-server-test-evidence-schema-threat-model",
    "server",
    "Design test-evidence vN and its threat model",
    "5420-5438",
    "Define the versioned schema, exact binary-digest binding, compatibility policy, and threat model using the existing evidence-validator layout.",
    ["Fields cover per-crate line and branch coverage, mutation witnesses, named invariants, parity as-of SHA, fuzz corpus hash and no-new-crashes, toolchain, and source SHA."],
    ["Schema fixtures, threat-model review, migration tests, and valid and invalid binding examples."],
    cluster="K",
    priority=3,
    tier="tier-3",
    parent="k-server-test-attestation",
    depends_on=["h-server-versioned-contract-migrations"],
)
add(
    "k-server-test-evidence-producer",
    "server",
    "Emit signed server test evidence beside provenance",
    "5420-5453",
    "Assemble sealed exact-SHA coverage, mutation, invariant, parity, fuzz, toolchain, and binary inputs; emit and cosign the artifact beside SBOM and provenance through existing release machinery.",
    ["Missing, stale, partial, or unsealed input and binary digest mismatch all fail; a non-publishing dry-run artifact verifies."],
    ["Deterministic dry-run artifact, signature, provenance, input checksums, and negative fixtures."],
    cluster="K",
    priority=3,
    tier="tier-3",
    parent="k-server-test-attestation",
    depends_on=[
        "k-server-test-evidence-schema-threat-model",
        "h-server-apply-path-invariants",
        "h-server-regression-corpora-schedules",
        "h-server-request-span-correlation",
    ],
)
add(
    "k-driver-test-evidence-producer",
    "driver",
    "Emit signed driver test evidence under the shared schema",
    "5420-5453",
    "Consume the shared schema checksum and assemble the exact 0.8.5 driver evidence through existing SBOM and provenance machinery without a new public API.",
    ["The exact artifact, SHA, and sealed inputs are bound; a stale schema or binary digest mismatch is rejected."],
    ["Signed dry-run artifact, SBOM and provenance linkage, schema checksum, and mismatch fixtures."],
    cluster="K",
    priority=3,
    tier="tier-3",
    parent="k-driver-test-attestation",
    depends_on=[
        "h-driver-conformance-value-wire-parity",
        "h-driver-regression-corpora-schedules",
    ],
    handoffs=[handoff("k-server-test-evidence-schema-threat-model", "test-evidence schema and threat-model checksum")],
)
add(
    "k-server-test-evidence-verifier",
    "server",
    "Verify test evidence against server and driver binaries",
    "5429-5453",
    "Extend the existing verifier path for test-evidence vN and provide one command that verifies signature, schema, exact source SHA, and binary digest for server and driver artifacts.",
    ["Valid artifacts pass; forged signature, wrong digest, altered metric or invariant, stale SHA, and wrong schema version each reject specifically."],
    ["One-command transcript and complete tamper matrix for both repository producers."],
    cluster="K",
    issue_type="feature",
    priority=3,
    tier="tier-3",
    parent="k-server-test-attestation",
    depends_on=["k-server-test-evidence-schema-threat-model", "k-server-test-evidence-producer"],
    handoffs=[handoff("k-driver-test-evidence-producer", "Signed driver test-evidence artifact checksum")],
)


def manifest() -> dict[str, Any]:
    return {
        "schema": "oraclemcp-plan-bead-graph/v1",
        "program": PROGRAM,
        "source_document": {
            "path": PLAN,
            "sha256": "4b9c4aa8b30ed78e2953947bb6104523bca1dac4c51939e2a3f818b0cbf47d0d",
        },
        "repositories": ["server", "driver", "site"],
        "trackers": {
            "server": {"path": ".beads/issues.jsonl", "source_repo": "oraclemcp"},
            "driver": {
                "path": "../rust-oracledb/.beads/issues.jsonl",
                "source_repo": "rust-oracledb",
            },
            "site": {
                "path": "../durakovic-ai/.beads/issues.jsonl",
                "source_repo": "durakovic-ai",
            },
        },
        "release_targets": [
            {"repo": "server", "current": "0.9.0", "next": "0.9.1", "bump": "patch"},
            {"repo": "driver", "current": "0.8.4", "next": "0.8.5", "bump": "patch"},
        ],
        "tasks": tasks,
    }


# J — GCP/Vertex engineering wave, then checksum-gated site/video/launch specs.
add(
    "j-gcp-vertex-demo",
    "server",
    "Prove Vertex Gemini and Google ADK through oraclemcp",
    "3105-3115",
    "Own Wave 1 from exact target freeze through official ADK integration, deterministic Oracle evidence, negative controls, and a real sanitized terminal recording.",
    ["The current official ADK reaches the published v0.9.0 server through MCP only and the three-beat evidence bundle is reproducible and checksum-bound."],
    ["G7 accepted checksum plus exact target, compatibility, qualification, cost, and recording artifacts."],
    cluster="J",
    issue_type="epic",
    priority=1,
)
add(
    "j-g0-freeze-target",
    "server",
    "Freeze the published target SHA and DB-free baseline",
    "1132-1178",
    "Select the published v0.9.0 exact SHA, coordinate ownership and reservations, and capture protocol, catalog, schema, tool-count, refusal, and shutdown baselines without a database.",
    ["The tree is clean at the selected tag, baseline output is raw and reproducible, and every failure has an owner rather than being hidden."],
    ["Exact SHA, release status, tree state, raw baseline logs, and compatibility baseline."],
    cluster="J",
    priority=1,
    parent="j-gcp-vertex-demo",
)
add(
    "j-g1-vertex-project-cost-guard",
    "server",
    "Configure the operator-owned Vertex project and cost guard",
    "1180-1234",
    "After operator setup, pin project, model, region, ADC role, request, turn, and token caps; calculate worst-case rated cost, create the agreed budget alert, and document cleanup without assuming credits mean zero cost.",
    ["One minimal request succeeds only after operator approval and usage, rated cost, credits, subtotal, and pending state are recorded honestly."],
    ["Redacted project and auth configuration, exact model and region, minimal-call result, usage and cost record, and cleanup command."],
    cluster="J",
    priority=1,
    tier="operator-gated",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g0-freeze-target"],
    operator_gate="cost",
)
add(
    "j-g2-stdio-schema-audit",
    "server",
    "Audit official ADK MCP stdio and full schemas",
    "1236-1299",
    "Pin the official ADK stack, exercise stdio lifecycle twice, convert the complete tool catalog, prove structured refusal and recovery, and classify every row as pass, fail, not tested, or blocking defect.",
    ["Lifecycle, catalog, schema conversion, refusal, recovery, and shutdown are machine and human auditable; no custom client or direct Oracle path is used."],
    ["Locked dependency set, raw JSON-RPC and stderr logs, compatibility JSON and Markdown, and refusal artifacts."],
    cluster="J",
    priority=1,
    parent="j-gcp-vertex-demo",
    depends_on=["j-g0-freeze-target"],
)
add(
    "j-g2h-http-bearer-lane",
    "server",
    "Audit optional loopback HTTP bearer compatibility",
    "1270-1277",
    "Exercise initialize, list, metadata, and shutdown through loopback Streamable HTTP with a per-client bearer while keeping stdio as the launch path.",
    ["The lane is PASS or a precise NOT_TESTED limitation and never blocks the stdio milestone."],
    ["HTTP compatibility row, redacted request log, and authentication result."],
    cluster="J",
    priority=2,
    tier="tier-2",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g0-freeze-target"],
)
add(
    "j-g2f-compat-defect-template",
    "server",
    "Create one narrow G2F Bead per confirmed MCP defect",
    "1301-1345",
    "For each confirmed general MCP defect, require the smallest DB-free reproducer, safety review, client-neutral patch, focused and full gates, and ADK rerun; never branch on ADK or Gemini identity.",
    ["No G2F Bead exists without a confirmed reproducer and every fix preserves guard, authentication, profile, and audit invariants."],
    ["Defect compatibility row, reproducer, safety review, focused tests, full gates, and ADK rerun."],
    cluster="J",
    issue_type="bug",
    priority=1,
    tier="process",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g2-stdio-schema-audit"],
    promotion="defer",
    condition="Create a defect-specific child only if G2 proves a general MCP compatibility defect.",
)
add(
    "j-g3-oracle-fixture-profile",
    "server",
    "Build the pinned Oracle fixture and protected profile",
    "1347-1372",
    "Pin the Oracle 23ai Free image and digest, deterministic fixture and expected values, readiness diagnostics, protected READ_ONLY profile, and isolated audit output.",
    ["Fixture values are exact and repeatable, the profile ceiling is immutable, and all confirmed blocking G2 defects are closed."],
    ["Image digest and banner, fixture checksum, expected JSON, readiness log, and config invariant test."],
    cluster="J",
    issue_type="feature",
    priority=1,
    tier="operator-gated",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g1-vertex-project-cost-guard", "j-g2-stdio-schema-audit"],
    operator_gate="operator-input",
)
add(
    "j-g4-adk-example-package",
    "server",
    "Build the locked official-ADK example package",
    "1353-1379",
    "Create the locked Python package using the official ADK agent and McpToolset, a demo-only tool filter, clean lifecycle shutdown, and a static ban on direct Oracle clients or listener calls.",
    ["Clean-clone install works, lifecycle runs twice, and MCP is the exclusive database access path."],
    ["pyproject, uv lock checksum, environment example, lifecycle logs, and exclusive-access static-check output."],
    cluster="J",
    issue_type="feature",
    priority=1,
    tier="operator-gated",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g3-oracle-fixture-profile"],
    operator_gate="operator-input",
)
add(
    "j-g5-three-beat-evidence-runner",
    "server",
    "Implement the assertion-driven three-beat evidence runner",
    "918-1109",
    "Run deterministic read, exact destructive preview refusal with postcondition, and audit verify plus head anchor; assert structure, normalize evidence-v1, seal raw and derived artifacts, and enforce call and token budgets.",
    ["The beats pass twice and changed expected read, false allow, model-only refusal, or missing audit proof causes nonzero exit."],
    ["Raw logs, ADK events, audit and anchor, evidence JSON and schema, artifact manifest, checksums, and budget metadata."],
    cluster="J",
    issue_type="feature",
    priority=1,
    tier="operator-gated",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g4-adk-example-package"],
    operator_gate="cost",
)
add(
    "j-g6-clean-sha-qualification",
    "server",
    "Qualify the demo from a clean SHA with negative controls",
    "1416-1473",
    "Perform cold-start exact-SHA qualification three times, run wrong-read, false-allow, audit-tamper, and truncation controls, capture actual cost, secret-scan everything, and reproduce independently from the README.",
    ["Three consecutive passes, every negative control fails, the secret scan is clean, and fresh-shell reproduction succeeds."],
    ["Exact-SHA qualification bundle, three run records, negative artifacts, usage and cost data, and fresh-shell transcript."],
    cluster="J",
    priority=1,
    tier="operator-gated",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g5-three-beat-evidence-runner"],
    operator_gate="cost",
)
add(
    "j-g7-recording-public-docs",
    "server",
    "Produce the real terminal recording and public engineering docs",
    "1475-1531",
    "Freeze and rehearse the recording script, let the operator capture one continuous real cast, sanitize frame by frame, publish transcript and checksum, and link compatibility and evidence documentation to the exact target.",
    ["No output is fabricated, no secret or personal path appears, and the accepted cast and public docs bind the exact v0.9.0 SHA."],
    ["Frozen script, real cast, transcript, sanitization review, public docs, and accepted G7 checksum."],
    cluster="J",
    priority=1,
    tier="operator-gated",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g6-clean-sha-qualification"],
    operator_gate="operator-input",
)

wave2_condition = (
    "Do not create or refine this site-tracker Bead until the operator accepts the checksum from j-g7-recording-public-docs."
)
add(
    "j-site-wave2-owner",
    "site",
    "Map the checksum-gated showcase wave to durakovic-ai-oou",
    "3331-3353",
    "After the G7 checksum, reuse the existing reveal owner durakovic-ai-oou, reconcile active route ownership, and promote the normalized site, video, and launch children in the site tracker.",
    ["No Wave-2 Bead is created early and the existing campaign DAG remains acyclic and rust-oracledb launch work stays independent."],
    ["Accepted G7 checksum, site tracker audit, active-owner acknowledgement, and zero-cycle graph result."],
    cluster="J",
    issue_type="epic",
    priority=1,
    tier="operator-gated",
    handoffs=[handoff("j-g7-recording-public-docs", "Accepted G7 public artifact manifest checksum")],
    promotion="defer",
    condition=wave2_condition,
)

site_rows = [
    (
        "j-s0-route-reconcile",
        "Reconcile the crawlable oraclemcp route and tracker",
        "2059-2081",
        "Reuse the active ybc route infrastructure under oou, coordinate its current owner, reserve exact paths, and freeze the immutable evidence input.",
        "The architecture yields a real crawlable route, one owner, no duplicate epic, and immutable input checksum.",
        "Route proof, ownership acknowledgement, reservations, and accepted checksum.",
        1,
        [],
    ),
    (
        "j-s1-static-content-metadata",
        "Build static page content, metadata, and evidence ledger",
        "1626-1846",
        "Implement substantive static /oraclemcp/ HTML with semantic S1-S8 content, route metadata, JSON-LD, sitemap, llms, preview noindex, OG generation, and one evidence-backed data source.",
        "View-source is substantive, claims equal evidence, route metadata is specific, and all links and ledgers resolve.",
        "Build output, metadata tests, evidence ledger, and rendered browser review.",
        1,
        ["j-s0-route-reconcile"],
    ),
    (
        "j-s2-real-terminal-verification",
        "Embed the real cast, transcript, and browser verifier",
        "1866-2037",
        "Self-host the pinned asciinema player, cast, transcript, poster and fallback, and implement in-browser checksum, chain, anchor, and certificate consistency verification with fail-closed tamper state.",
        "No-JS content works, reduced motion and keyboard access work, corrupted evidence renders red, and no backend request is introduced.",
        "Browser matrix, corrupted-bundle test, asset sizes, accessibility report, and verifier output.",
        1,
        ["j-s1-static-content-metadata"],
    ),
    (
        "j-s3-browser-deployment-gates",
        "Run browser, accessibility, performance, and deployment gates",
        "2134-2163",
        "Run Bun gates and Playwright across browsers, viewports, no-JS, keyboard, and reduced motion; verify waterfall, budgets, preview noindex, direct route, MIME, canonical, and deployed checksum.",
        "No critical accessibility or layout issue remains, direct refresh works, and preview and production claims remain separately gated.",
        "Preview URL, screenshots, reports, waterfall, route checks, and checksum comparison.",
        1,
        ["j-s2-real-terminal-verification"],
    ),
    (
        "j-s4-optional-replay",
        "Add the optional evidence-backed fixed replay",
        "2165-2186",
        "If still valuable, implement only the three fixed evidence-backed beats with explicit replay labeling and no arbitrary query or backend path.",
        "Every displayed output maps to immutable evidence and the page remains static and honest when replay is omitted.",
        "Beat mapping table, replay UI tests, and static-network assertion.",
        3,
        ["j-s3-browser-deployment-gates"],
    ),
]
for slug, title, source, scope, criterion, proof, priority, dependencies in site_rows:
    add(
        slug,
        "site",
        title,
        source,
        scope,
        [criterion],
        [proof],
        cluster="J",
        issue_type="feature" if slug in {"j-s1-static-content-metadata", "j-s2-real-terminal-verification", "j-s4-optional-replay"} else "task",
        priority=priority,
        tier="operator-gated",
        parent="j-site-wave2-owner",
        depends_on=dependencies,
        promotion="defer",
        condition=wave2_condition,
    )

video_rows = [
    ("j-v0-freeze-video-brief", "Freeze the evidence-led video brief", "2192-2223", "Freeze the product-launch workflow, angle, asset provenance, and accepted evidence inputs before storyboard work.", "The operator approves the brief and every source asset has provenance and checksum.", "Approved brief and asset checksum inventory.", 2, ["j-s3-browser-deployment-gates"]),
    ("j-v1-storyboard-design", "Approve the six-frame storyboard and design", "2225-2336", "Design six evidence-led frames without fabricated UI, results, or benchmarks and preserve terminal facts verbatim.", "The operator approves message, footage, design, provenance, and transform rules.", "Approved storyboard, script, provenance, and source-to-frame map.", 2, ["j-v0-freeze-video-brief"]),
    ("j-v2-compose-master", "Compose and validate the 16:9 launch master", "2234-2382", "Build the 1920 by 1080, sixty-to-seventy-five-second silent-first HyperFrames composition with readable real terminal footage and captions.", "HyperFrames lint, validation, inspection, and midpoint snapshots pass and all factual content traces to evidence.", "Preview artifact, lint and validation logs, snapshots, and caption review.", 2, ["j-v1-storyboard-design"]),
    ("j-v3-preview-final-render", "Approve preview and render the final video", "2354-2369", "Obtain operator Studio preview approval, then render and verify the final duration, readability, captions, and checksum.", "The approved final exists, ffprobe matches the format contract, and captions obscure no evidence.", "Preview approval, final checksum, ffprobe output, and render validation.", 2, ["j-v2-compose-master"]),
    ("j-v4-social-variants", "Derive optional social video variants", "2371-2382", "Only if requested, derive X, vertical, loop, poster, caption, and transcript assets from the approved master without changing facts.", "Safe zones and factual fidelity pass and the master remains sufficient if variants are skipped.", "Variant checksums, safe-zone review, captions, and source-master linkage.", 3, ["j-v3-preview-final-render"]),
]
for slug, title, source, scope, criterion, proof, priority, dependencies in video_rows:
    add(
        slug,
        "site",
        title,
        source,
        scope,
        [criterion],
        [proof],
        cluster="J",
        priority=priority,
        tier="operator-gated",
        parent="j-site-wave2-owner",
        depends_on=dependencies,
        operator_gate="operator-input" if slug in {"j-v0-freeze-video-brief", "j-v1-storyboard-design", "j-v3-preview-final-render", "j-v4-social-variants"} else "none",
        promotion="defer",
        condition=wave2_condition,
    )

launch_rows = [
    ("j-lf-claim-lock", "Generate the oraclemcp claim-lock fact sheet", "2458-2476", "Generate the product sentence, stack and revision, beats, versions, actual cost, limitations, disclaimer, proof links, and prohibited claims from evidence.", "Every factual field matches the accepted evidence and public wording taxonomy.", "Reviewed fact artifact and checksum.", 1, [], "none"),
    ("j-lc-channel-copy", "Write distinct HN, X, and Reddit launch copy", "2478-2532", "Write product-specific HN title and comment, X thread, and tailored Reddit drafts with disclosure, limitations, and a current channel-rules review; do not reuse the rust-oracledb l00 copy wholesale.", "Every fact derives from the claim lock and each community receives distinct rule-compliant copy.", "Approved drafts and dated channel-rules review.", 1, ["j-lf-claim-lock"], "operator-input"),
    ("j-l0-launch-readiness", "Pass campaign-order and launch-readiness gates", "2388-2421", "Under oou, preserve 6s0 analytics and 6p5 campaign ordering and verify links, registries, evidence, correction ownership, and support availability before any publication.", "The operator approves publication or an explicit campaign rewire and every readiness item is green.", "Signed readiness checklist, analytics proof, graph audit, and operator decision.", 1, ["j-s3-browser-deployment-gates", "j-lc-channel-copy"], "public-launch"),
    ("j-l1-show-hn", "Submit the approved Show HN launch", "2478-2499", "Manually publish the approved Show HN title and technical comment without vote solicitation and verify all proof links.", "The canonical post is live with approved facts and no automated engagement.", "Canonical post URL and final text checksum.", 1, ["j-l0-launch-readiness"], "public-launch"),
    ("j-l2-x-thread", "Publish the approved X evidence thread", "2501-2514", "Manually publish the claim-locked short thread with the best real media and canonical proof link.", "Every post matches the fact sheet and the complete canonical thread URLs are recorded.", "Thread URLs and final copy checksum.", 1, ["j-l1-show-hn"], "public-launch"),
    ("j-l3-reddit", "Publish tailored technical Reddit submissions", "2516-2532", "Manually publish distinct rule-compliant technical submissions with authorship disclosure in approved communities.", "Each submission follows current community rules and does not copy generic launch text.", "Post URLs, final texts, and dated rules review.", 1, ["j-l1-show-hn"], "public-launch"),
    ("j-l4-response-correction-window", "Operate the launch response and correction window", "2550-2561", "For the agreed window, answer only from evidence, convert confirmed gaps into Beads, and version corrections in canonical artifacts.", "Responses remain evidence-backed and every confirmed error receives a visible correction and tracker record.", "Forty-eight-hour response, FAQ, incident, and correction log.", 1, ["j-l1-show-hn"], "public-launch"),
    ("j-l5-follow-up-distribution", "Perform optional follow-up distribution", "2534-2548", "After the primary launch, reuse or split existing c64 and 2e9 directory work so MCP directories have one owner; add only approved newsletters, directories, or optional video distribution.", "No directory task is duplicated and every destination uses the canonical claim lock.", "Destination URLs, existing-Bead reconciliation, and final fact checksum.", 3, ["j-l2-x-thread", "j-l3-reddit"], "public-launch"),
]
for slug, title, source, scope, criterion, proof, priority, dependencies, gate in launch_rows:
    add(
        slug,
        "site",
        title,
        source,
        scope,
        [criterion],
        [proof],
        cluster="J",
        priority=priority,
        tier="operator-gated",
        parent="j-site-wave2-owner",
        depends_on=dependencies,
        operator_gate=gate,
        promotion="defer",
        condition=wave2_condition,
    )


# I — one disposable OCI Always-Free ADB full capability run.
add(
    "i-oci-adb-e2e",
    "server",
    "Extend the OCI ADB auth harness into full capability E2E",
    "5103-5181",
    "Use exactly one disposable Always-Free ADB with synthetic isolated schemas, roles, and sessions to prove the full server surface and terminal teardown.",
    ["All child guards and capability checks pass with zero paid shape, no committed identifiers, and confirmed terminal resource deletion."],
    ["Exact run ID, sanitized signoff bundle, cost and shape assertion, cleanup ledger, and terminal delete poll."],
    cluster="I",
    issue_type="epic",
    priority=2,
    tier="tier-3",
)
add(
    "i-oci-auth-smoke-foundation",
    "server",
    "Reuse the completed OCI ADB auth-smoke harness",
    "5103-5146",
    "Map the existing Always-Free provisioning, wallet, TCPS, token, and basic JSON-line signoff harness as the foundation; do not claim it already proves the full capability sweep.",
    ["The new program extends rather than duplicates the closed harness and labels prior evidence honestly as auth smoke."],
    ["Closed y1x7 evidence, harness paths, and capability-gap checklist."],
    cluster="I",
    priority=2,
    tier="process",
    promotion="reuse",
    existing_id="oraclemcp-oci-live-adb-harness-y1x7",
)
add(
    "i-oci-free-tier-provision-guard",
    "server",
    "Refuse any OCI plan that is not provably Always-Free",
    "5148-5153",
    "Before apply, assert is_free_tier, the approved Always-Free shape, a machine-readable zero cost ceiling, synthetic namespace, and exactly one database; stop on unknown or nonzero cost.",
    ["Paid, unknown, non-free, or multi-database plans exit before apply while the approved free fixture passes."],
    ["Accepted-plan fixture, paid and unknown negative fixtures, cost JSON, and no-apply assertion."],
    cluster="I",
    priority=0,
    tier="tier-3",
    parent="i-oci-adb-e2e",
    depends_on=["i-oci-auth-smoke-foundation"],
)
add(
    "i-oci-durable-teardown-reconcile",
    "server",
    "Make OCI teardown durable and block residue reuse",
    "5165-5176",
    "Persist a protected secret-safe resource identifier, destroy in a trap, retry and poll to terminal deletion, alert on residue, and block the next provision until reconciliation.",
    ["Injected destroy failure leaves durable recovery state and a subsequent run refuses provisioning until deletion is confirmed."],
    ["Destroy-failure fixture, protected-state proof, retry log, terminal poll, and redacted incident artifact."],
    cluster="I",
    priority=1,
    tier="tier-3",
    parent="i-oci-adb-e2e",
    depends_on=["i-oci-free-tier-provision-guard"],
)
add(
    "i-oci-capability-sweep",
    "server",
    "Exercise the complete server capability ladder on ADB",
    "5154-5164",
    "Across multiple synthetic roles and connections test info, query, DDL preview refusal, held and committed execute including DI1, level grants, catalog, schema, source, plan, LOB, VECTOR, NUMBER, TSTZ, BOOLEAN, INTERVAL, audit verify and anchor, doctor, and refusals.",
    ["Every capability has an exact value or postcondition and no current auth-smoke result is relabelled as full proof."],
    ["JSONL per-capability result map, exact values, role matrix, audit artifacts, and run ID."],
    cluster="I",
    priority=2,
    tier="tier-3",
    parent="i-oci-adb-e2e",
    depends_on=[
        "i-oci-free-tier-provision-guard",
        "i-oci-durable-teardown-reconcile",
        "g-server-he7t-iam-subject-mapping",
        "f-server-di1-terminal-held-effects",
        "f-server-db1-db4-value-fidelity",
    ],
)
add(
    "i-oci-evidence-and-cleanup-ledger",
    "server",
    "Seal OCI evidence and cleanup without identifier leakage",
    "5118-5124",
    "Emit a per-run namespace, cleanup ledger, sanitized artifact manifest, secret scan, and post-destroy resource query while keeping every OCI identifier out of git and public artifacts.",
    ["The cleanup ledger becomes empty only after terminal polling and no OCID, wallet, tenancy, or principal value enters committed output."],
    ["Secret scan, checksums, sanitized artifact manifest, cleanup ledger, and terminal resource query."],
    cluster="I",
    priority=2,
    tier="tier-3",
    parent="i-oci-adb-e2e",
    depends_on=["i-oci-capability-sweep", "i-oci-durable-teardown-reconcile"],
)

add(
    "c-demono-size-ratchet",
    "server",
    "Prevent split monolith files from regrowing",
    "4114-4121",
    "Add reviewed post-split per-file ceilings to architecture fitness without penalizing generated files or legitimate evidence artifacts.",
    ["The lint passes at reviewed ceilings and a seeded growth fixture fails with the exact offending file and limit."],
    ["Boundary fixtures, final line-count ledger, and architecture-gate output."],
    cluster="C",
    priority=1,
    parent="c-demono-epic",
    depends_on=[
        "c-demono-dispatch-mod",
        "c-demono-web-app",
        "c-demono-dispatch-tests",
        "c-demono-db-connection",
        "c-demono-guard-classifier",
        "c-demono-main",
        "c-demono-core-lane",
        "c-demono-service-lifecycle",
        "c-demono-core-doctor",
        "c-demono-http-operator",
    ],
)
add(
    "c-explicit-preservation-decisions",
    "server",
    "Record repository artifacts that must be preserved",
    "4052-4058",
    "Record that infra, web node_modules, todelete, the driver reference checkout, and reversed a7b content are intentional keep or do-not-harvest decisions.",
    ["No janitor task treats these paths or reversed commits as reclaimable without a new explicit operator decision."],
    ["Plan source anchors and janitor task scopes demonstrating the exclusions."],
    cluster="C",
    issue_type="chore",
    priority=4,
    tier="process",
    promotion="record-only",
    condition="These are explicit preservation decisions rather than actionable tracker work.",
)


# D — CI tranche 2/3, coverage, mutation, and gate honesty.
add(
    "d-driver-quality-fanout",
    "driver",
    "Split reusable quality into fail-all parallel jobs",
    "3871-3882",
    "Fan the driver reusable quality workflow across all four callers with fail-fast false while preserving every profile, budget, parser, and caller contract.",
    ["Independent failures surface in one run and the fail-closed parser and contract fixtures change atomically."],
    ["Parser fixtures, actionlint, four-caller graph proof, and throwaway release-qualification dispatch."],
    cluster="D",
    priority=0,
    tier="tier-0",
    depends_on=["b-driver-pinned-tool-installs", "b-driver-powerset-disk-assert"],
)
add(
    "d-driver-fuzz-shards",
    "driver",
    "Shard every driver fuzz target and cache ASan builds",
    "3883-3886",
    "Assign all twenty-two fuzz targets deterministically across four shards and cache the non-workspace sanitizer target without reducing budgets.",
    ["A manifest test proves no duplicate or omitted target and cold and warm runs retain identical target budgets."],
    ["Shard manifest test, cold and warm timing, and fuzz compile artifact."],
    cluster="D",
    priority=0,
    tier="tier-0",
    depends_on=["d-driver-quality-fanout"],
)
add(
    "d-driver-fresh-live-matrix",
    "driver",
    "Fan fresh release live proof into isolated lanes",
    "3901-3909",
    "Run five fail-all live lane jobs with one Oracle database per runner and merge deterministic exact-SHA evidence.",
    ["All lanes remain hard blocking, isolated, complete, and represented exactly once in the merge result."],
    ["Matrix completeness test and strict fresh release-qualification run."],
    cluster="D",
    priority=0,
    tier="tier-0",
    depends_on=["b-driver-live-matrix-parallel-start"],
)
add(
    "d-driver-rq-prep-mode",
    "driver",
    "Collect every release qualification failure in prep mode",
    "3958-3972",
    "Run every prep gate and aggregate failures, while marking prep artifacts non-qualifying and preserving a strict final verification mode.",
    ["Strict verification rejects prep artifacts and a prep run reports every independent failure in one summary."],
    ["Prep and strict fixtures plus one throwaway prep dispatch and aggregate artifact."],
    cluster="D",
    priority=0,
    tier="tier-0",
    depends_on=[
        "d-driver-quality-fanout",
        "d-driver-fuzz-shards",
        "d-driver-fresh-live-matrix",
        "b-driver-required-proof-parallel",
    ],
)
add(
    "d-driver-main-matrix-evidence-reuse",
    "driver",
    "Reuse exact-SHA main live evidence in release qualification",
    "3893-3909",
    "Implement download-if-complete-and-exact, otherwise run-fresh behavior for main live-matrix evidence including the TCPS lane.",
    ["Matching sealed evidence is reused; missing, partial, or different-SHA evidence forces a fresh run."],
    ["Hit, miss, partial, and SHA-mismatch fixtures plus a strict qualification run."],
    cluster="D",
    priority=0,
    tier="tier-0",
    depends_on=["d-driver-fresh-live-matrix"],
)
add(
    "d-server-exact-sha-tag-gate-reuse",
    "server",
    "Reuse same-SHA server CI evidence at tag gates",
    "3925-3928",
    "Accept only immutable complete same-SHA CI evidence or verified required checks when validating a tag candidate.",
    ["Missing, stale, incomplete, or mismatched evidence reruns or fails closed rather than being assumed green."],
    ["Good, missing, stale, and mismatch fixtures plus a rehearsal run."],
    cluster="D",
    priority=1,
    depends_on=["b-server-pretag-release-rehearsal"],
)
for repo in ("server", "driver"):
    add(
        f"d-{repo}-nextest",
        repo,
        f"Adopt nextest for bounded {repo} tests",
        "3929-3933",
        "Configure retries, timeouts, JUnit history, and serial live groups while retaining doctests under cargo test and exposing every retry as a flake.",
        ["No doctest or live serialization is lost, retries remain visible, and timeout behavior is deterministic."],
        ["Nextest configuration tests, JUnit artifact, and retry and timeout fixtures."],
        cluster="D",
        priority=1,
        depends_on=["b-server-quality-projection-relocation"] if repo == "server" else ["d-driver-quality-fanout"],
    )
add(
    "d-server-fast-pregate",
    "server",
    "Separate fast push feedback from heavy merge fanout",
    "4267-4271",
    "Keep fmt, clippy, and unit feedback under five minutes on every push; move heavy fanout to pull requests, merge groups, and rate-limited main, with release mechanics at rehearsal or tag time.",
    ["Event and path filters preserve every required gate and a lightweight sync check catches release-surface drift."],
    ["Workflow contract tests and representative push, pull-request, and merge-group graphs."],
    cluster="D",
    priority=0,
    tier="tier-0",
    depends_on=[
        "b-server-release-build-overlap",
        "b-server-acceptance-dedupe",
        "b-server-quality-projection-relocation",
    ],
)
for repo, dependencies in [
    ("server", ["d-server-fast-pregate"]),
    ("driver", ["d-driver-quality-fanout", "b-driver-live-advisory-autoreblock"]),
]:
    add(
        f"d-{repo}-gate-honesty",
        repo,
        f"Make {repo} CI verdict derivation fail closed",
        "4262-4271",
        "Distinguish infrastructure crash from a red verdict, reject unexpanded expression names, expose advisory status, and anchor drift guards on version tokens rather than prose.",
        ["Known-good, red, crash, unknown, advisory, and unexpanded-expression fixtures all produce distinct correct outcomes."],
        ["Verdict fixture suite and machine-readable lane status artifact."],
        cluster="D",
        priority=0,
        tier="tier-0",
        depends_on=dependencies,
    )
for repo in ("server", "driver"):
    scope = (
        "Cap each mutant, continue after OOM while classifying it as errored, seal deterministic shards by count and file hash, distinguish witnessed test-failure kills from timeout or unviable outcomes, and require survivor triage."
    )
    if repo == "server":
        scope += " Extend the measured campaign to core, database, and dispatch alongside guard and audit."
    add(
        f"d-{repo}-mutation-integrity",
        repo,
        f"Make {repo} mutation evidence resource-safe and honest",
        "4257-4261",
        scope,
        ["OOM, timeout, unviable, witnessed kill, and survivor are never conflated; partial or unsealed campaigns cannot qualify."],
        ["Synthetic outcome fixtures, survivor ledger, seal verification, and a targeted exact-SHA campaign."],
        cluster="D",
        priority=0,
        tier="tier-0",
    )
for repo in ("server", "driver"):
    add(
        f"d-{repo}-coverage-ratchet",
        repo,
        f"Establish measured {repo} coverage and a non-gameable ratchet",
        "4938-4967",
        "Baseline per-crate line and branch coverage deliberately, publish nightly trends, gate changed-line coverage, and require named negative invariants plus safety-crate mutation floors without gaming a global percentage.",
        ["Coverage is empirical and per-crate, changed lines are checked, and safety-critical diffs cannot pass without a named discriminating test."],
        ["Baseline report, uncovered-branch backlog, positive and negative PR fixtures, and nightly run."],
        cluster="D",
        priority=0,
        tier="tier-0",
        depends_on=[f"d-{repo}-mutation-integrity"],
    )
add(
    "d-server-optional-ci-efficiency",
    "server",
    "Apply only provenance-safe optional server CI optimizations",
    "3945-3956",
    "Conditionally repackage the attested musl binary, trim fetch depth only where ancestry is unused, verify preinstalled ripgrep before removing setup, and add actionlint.",
    ["Every adopted optimization preserves provenance and correctness and has a measured positive timing result."],
    ["Provenance comparison, workflow tests, runner package check, and timing delta."],
    cluster="D",
    issue_type="chore",
    priority=2,
    tier="tier-2",
)
add(
    "d-driver-optional-ci-efficiency",
    "driver",
    "Apply measured low-risk driver CI optimizations",
    "3945-3956",
    "Reduce performance samples only after a noise-floor study, safely trim fetch depth or ripgrep setup, and add actionlint without hiding variability.",
    ["Only empirically safe changes land and performance wording reports measured variance honestly."],
    ["Variance study, runner package check, workflow tests, and timing delta."],
    cluster="D",
    issue_type="chore",
    priority=2,
    tier="tier-2",
)
for repo in ("server", "driver"):
    add(
        f"d-{repo}-larger-runner-option",
        repo,
        f"Evaluate paid larger runners for {repo} critical jobs",
        "3947-3953",
        "Estimate measured benefit and a hard cost ceiling without changing any runner configuration or incurring spend.",
        ["No paid runner is enabled until the operator explicitly accepts the documented cost ceiling and benefit."],
        ["Runner-minute benchmark, cost estimate, and explicit operator decision if ever promoted."],
        cluster="D",
        priority=2,
        tier="operator-gated",
        operator_gate="cost",
        promotion="defer",
        condition="Paid runners can create recurring cost and require explicit operator approval.",
    )
add(
    "d-p03a-alternative-record",
    "driver",
    "Record the rejected P0.3a evidence assembly alternative",
    "3887-3892",
    "Retain P0.3a as the documented alternative to the selected P0.3b parallel Required-proof design, not a second implementation task.",
    ["The graph contains only the chosen P0.3b implementation and future readers can see why P0.3a was not duplicated."],
    ["Plan source and the selected b-driver-required-proof-parallel mapping."],
    cluster="D",
    issue_type="chore",
    priority=4,
    tier="process",
    promotion="record-only",
    condition="P0.3a is an alternative design superseded by the selected P0.3b implementation.",
)


# E — Charter v2, swarm mechanics, tracker hardening, and procedural memory.
add(
    "e-server-charter-v2",
    "server",
    "Land Swarm Charter v2 in the server contract",
    "4278-4353",
    "Encode all twelve binding operator rules, graded shared-tree versus worktree isolation, self-driving ready-to-close work, coordination fallthrough, offline falsifiers, and externalized progress in AGENTS.md.",
    ["Every one of the twelve rules is explicit and no existing safety, tracker, build, or deletion contract is weakened."],
    ["Rule-by-rule coverage matrix, contract diff, and repository policy lint."],
    cluster="E",
    priority=0,
    tier="process",
)
add(
    "e-driver-charter-v2",
    "driver",
    "Land Swarm Charter v2 in the driver contract",
    "4278-4353",
    "Adapt every Charter v2 rule to driver build slots, live qualification, tracker ownership, and clean-room boundaries without copy drift.",
    ["All twelve rules are represented and driver-specific resource, live-evidence, and safety rules remain stronger where applicable."],
    ["Rule-by-rule coverage matrix, checksum handoff from server wording, and contract lint."],
    cluster="E",
    priority=0,
    tier="process",
    handoffs=[handoff("e-server-charter-v2", "Reviewed Charter v2 rule matrix checksum")],
)
add(
    "e-orchestration-controls",
    "server",
    "Extend the existing multi-agent orchestration controls",
    "4340-4359",
    "Reuse the deferred capacity, worker-contract, clean-HEAD, hot-file, watchdog, and orders umbrella as the parent for the remaining Charter v2 orchestration deltas.",
    ["The existing umbrella is un-deferred when implementation starts and no parallel orchestration epic duplicates its controls."],
    ["Existing Bead scope audit and child mapping for every remaining delta."],
    cluster="E",
    issue_type="epic",
    priority=0,
    tier="process",
    promotion="reuse",
    existing_id="oraclemcp-multiagent-orchestration-controls-3748",
)
add(
    "e-ntm-charter-orders-templates",
    "server",
    "Encode Charter v2 in NTM orders templates",
    "4340-4359",
    "Generate orders that carry ownership, self-drive, identity, resource, evidence, progress, blocker, and fallthrough rules without assuming unavailable coordination services.",
    ["Rendered orders cover every Charter rule and disabled coordination primitives degrade explicitly instead of blocking work."],
    ["Rendered-template golden, disabled-service fixture, and template validation tests."],
    cluster="E",
    priority=0,
    tier="process",
    parent="e-orchestration-controls",
    depends_on=["e-server-charter-v2"],
)
add(
    "e-server-worktree-lifecycle",
    "server",
    "Manage build-heavy server worktrees end to end",
    "4281-4321",
    "Implement NTM create, merge, and automatic removal with real-disk per-agent targets, disk canaries, sccache, one Beads DB, ignored env and fixture bootstrap, and short-lived Bead branches.",
    ["Build-heavy fanout cannot share one tree, lifecycle leaves no stale worktree, and tracker state never forks."],
    ["Temporary-repository integration test, disk and EDQUOT fixtures, and lifecycle log."],
    cluster="E",
    priority=0,
    tier="tier-0",
    parent="e-orchestration-controls",
    depends_on=["e-ntm-charter-orders-templates"],
)
add(
    "e-driver-worktree-lifecycle",
    "driver",
    "Adopt managed worktree lifecycle for driver swarms",
    "4281-4321",
    "Apply the managed lifecycle to the driver with pinned toolchain, isolated real-disk targets, canonical tracker, and safe local fixture bootstrap.",
    ["A driver worktree can build, land, sync Beads, and be removed without stale state or touching the clean-room reference checkout."],
    ["Driver integration run, canonical-tracker proof, and no-stale-worktree assertion."],
    cluster="E",
    priority=0,
    tier="tier-0",
    handoffs=[handoff("e-server-worktree-lifecycle", "Managed worktree lifecycle contract checksum")],
)
add(
    "e-server-build-lease",
    "server",
    "Physically enforce server build concurrency limits",
    "4322-4324",
    "Make the build entrypoint require a held lease, enable WORKTREES_ENABLED, apply TasksMax and ulimit safeguards, and default agents to scoped package builds.",
    ["Competing builds prove the lease cannot be bypassed and workspace-wide work refuses to start without a slot."],
    ["Competing-build integration test, lease audit log, and kernel-limit report."],
    cluster="E",
    priority=0,
    tier="tier-0",
    parent="e-orchestration-controls",
    depends_on=["e-server-worktree-lifecycle"],
)
add(
    "e-driver-build-lease",
    "driver",
    "Physically enforce driver build concurrency limits",
    "4322-4324",
    "Enforce at most two Agent Mail build slots, four-job Cargo limits, TasksMax and ulimit safeguards, and scoped iteration through an unbypassable entrypoint.",
    ["Workspace builds cannot run without a slot and competing workers remain within the documented resource ceiling."],
    ["Driver competing-build test, slot audit log, and resource-limit report."],
    cluster="E",
    priority=0,
    tier="tier-0",
    depends_on=["e-driver-worktree-lifecycle"],
    handoffs=[handoff("e-server-build-lease", "Build-lease conformance fixture checksum")],
)
add(
    "e-orchestrator-identity-spawn-quota",
    "server",
    "Persist identities and preflight every worker spawn",
    "4343-4349",
    "Persist pane identity and token outside compactable context, reattach rather than remint, validate requested model, quota, and context headroom, size fanout to quota, and reconcile silently dead claims.",
    ["Restart retains identity; duplicate name, wrong model, zero quota, or low context fails before claim; dead workers release or reconcile safely."],
    ["Restart, duplicate-name, model, quota, context, and dead-worker fixtures."],
    cluster="E",
    priority=0,
    tier="process",
    parent="e-orchestration-controls",
    depends_on=["e-ntm-charter-orders-templates"],
)
add(
    "e-orchestrator-ci-tending",
    "server",
    "Make CI tending durable and event driven",
    "4354-4359",
    "Provide fixed-cadence and transition heartbeats, a crash-resistant external scheduler, debounced idle notifications, event-driven child completion, and reconstructable orders, Beads, and scratch progress.",
    ["Tending survives orchestrator exit, each conclusion transition emits once, and restart reconstructs state without a polling storm."],
    ["Scheduler status, crash and restart test, debounce fixture, and progress recovery log."],
    cluster="E",
    priority=0,
    tier="process",
    parent="e-orchestration-controls",
    depends_on=["e-ntm-charter-orders-templates"],
)
add(
    "e-rch-opportunistic-offload",
    "server",
    "Use rch only as a fail-open marathon accelerator",
    "4360-4377",
    "Configure and self-test reachable rch workers for mutation, sanitizers, powerset, and prep lanes while always inspecting the RCH fallback contract and retaining local execution.",
    ["Unavailable workers fall back locally and no required gate depends on remote capacity or an unverified toolchain."],
    ["rch doctor, all-worker self-test, one remote run, and one unreachable-worker fallback run."],
    cluster="E",
    priority=3,
    tier="operator-gated",
    operator_gate="operator-input",
)
for repo in ("server", "driver"):
    add(
        f"e-{repo}-cm-seed",
        repo,
        f"Seed {repo} cass-memory with campaign learnings",
        "4378-4388",
        "Initialize repository memory, encode the Charter and improvement playbook plus destructive-trauma patterns, and verify representative tasks retrieve the right rules; add a guard only after measured usefulness.",
        ["cm doctor is clean and context queries surface repository-specific safety, build, tracker, and evidence rules."],
        ["cm doctor output, representative context query results, and feedback or decay configuration."],
        cluster="E",
        priority=1,
        tier="process",
        handoffs=[handoff("e-server-cm-seed", "Server memory playbook checksum")] if repo == "driver" else [],
    )
add(
    "e-tracker-close-integrity",
    "server",
    "Enforce honest and race-safe Beads closure",
    "4390-4399",
    "Implement T1 landed-commit and clean-path proof, T2 live run or artifact proof, T3 concurrency-safe claim release and close-reason binding, and T4 correction of the original false close.",
    ["Unlanded or self-skipping proof cannot close and concurrent close or release preserves the terminal state and correct evidence."],
    ["T1 through T4 regression fixtures, concurrent race test, and corrected historical record."],
    cluster="E",
    priority=0,
    tier="process",
)
add(
    "e-tracker-audit-integrity",
    "server",
    "Harden tracker compliance and bulk operations",
    "4400-4404",
    "Implement T5 evidence-doc ratchets and real verifiers, T6 Bead trailers, T7 exhaustive pagination and UTC all-status audits, T8 command-position dcg matching, T9 leaf-unblocking umbrellas, and T10 JSON distinct-ID validation.",
    ["Every T5 through T10 failure class has a discriminating fixture and the real compliance audit runs to exhaustion."],
    ["Compliance report, CI run, trailer and audit fixtures, dcg tests, and graph and bulk-ID tests."],
    cluster="E",
    priority=1,
    tier="process",
    depends_on=["e-tracker-close-integrity"],
)
add(
    "e-driver-tracker-adoption",
    "driver",
    "Apply T1 through T10 tracker integrity to the driver",
    "4390-4404",
    "Adopt the same close, evidence, audit, trailer, pagination, dcg, graph, and bulk-operation contracts in the driver without forking tracker schemas.",
    ["The driver passes shared T1 through T10 conformance fixtures and a live repo compliance audit."],
    ["Shared conformance checksum, driver-side run, schema comparison, and compliance report."],
    cluster="E",
    priority=0,
    tier="process",
    handoffs=[
        handoff("e-tracker-close-integrity", "T1-T4 tracker conformance checksum"),
        handoff("e-tracker-audit-integrity", "T5-T10 tracker conformance checksum"),
    ],
)


# F — every confirmed bug-hunt finding, patch-safe for 0.8.5/0.9.1.
for repo in ("driver", "server"):
    add(
        f"f-{repo}-bughunt-fixes",
        repo,
        f"Ship every confirmed {repo} bug-hunt fix in the patch release",
        "4520-4652",
        f"Own the complete confirmed {repo} High, Medium, Low, and Very-Low finding set, including each discriminating regression and explicit rejected-finding ledger.",
        ["Every confirmed child is fixed or explicitly adjudicated against stronger prior evidence, and the exact patch release remains SemVer-compatible."],
        [f"Child closure ledger and exact-SHA {repo} patch-release qualification artifact."],
        cluster="F",
        issue_type="epic",
        priority=1,
    )

driver_findings = [
    (
        "f-driver-dc1-arrow-tstz-offset",
        "Correct Arrow TSTZ instant conversion",
        "4555-4560",
        "Add the decoded offset in both Arrow epoch paths and update the prior intentional-divergence ledger rather than silently overriding closed etib.1 history.",
        "Decoder-produced Arrow epochs equal row-API instants across positive and negative zoned offsets, with wall-clock compatibility disposition documented.",
        "Metamorphic decoder-produced test and explicit prior-etib.1 reconciliation.",
        1,
        [],
    ),
    (
        "f-driver-dc2-dsn-cert-dn-pin",
        "Honor DSN certificate-DN pinning",
        "4555-4563",
        "Thread DSN-derived certificate-DN matching and the exact DN into TLS resolution without weakening SAN or chain verification.",
        "A SAN-matching but subject-DN-mismatching certificate is rejected when the pin exists only in the DSN.",
        "Descriptor golden and TLS verifier regression.",
        1,
        [],
    ),
    (
        "f-driver-py1-number-scale-type",
        "Preserve NUMBER scale in default Python fetch",
        "4561-4561",
        "Thread column scale into default fetch so constrained fractional NUMBER values retain the reference Python type and unconstrained fallbacks stay correct.",
        "NUMBER(10,2) returns float with an explicit type assertion rather than merely a numerically equal integer-like value.",
        "Differential value-and-isinstance regression.",
        1,
        [],
    ),
    (
        "f-driver-py2-decimal-exact-bind",
        "Bind Python Decimal without precision loss",
        "4562-4562",
        "Bind untyped Decimal through its exact decimal string before any i128 or f64 extraction can lose precision.",
        "A twenty-eight-digit Decimal round-trips exactly with fetch_decimals enabled.",
        "Differential exact-value Decimal regression.",
        1,
        [],
    ),
    (
        "f-driver-dc3-dsn-dn-match-off",
        "Honor DSN SSL_SERVER_DN_MATCH OFF",
        "4563-4563",
        "Honor DSN SSL_SERVER_DN_MATCH=OFF with an explicitly tested DSN versus options precedence rule.",
        "DSN-only OFF resolves dn_match false and explicit option precedence is stable and documented.",
        "TLS-resolution precedence table test.",
        1,
        ["f-driver-dc2-dsn-cert-dn-pin"],
    ),
    (
        "f-driver-py3-bigint-exact-bind",
        "Bind Python integers beyond i128 exactly",
        "4564-4564",
        "On PyInt i128 extraction failure, bind the exact decimal string rather than converting through f64.",
        "A forty-digit Python integer round-trips exactly with its intended numeric type semantics.",
        "Differential exact-value and type regression.",
        1,
        [],
    ),
    (
        "f-driver-py4-detach-blocking-io",
        "Release the GIL around all blocking driver I/O",
        "4565-4565",
        "Detach the GIL consistently around blocking connect, commit, rollback, and row fetch, matching execute and pool behavior.",
        "Concurrent cancellation completes without serialization or hang and Python exception mapping remains correct.",
        "Bounded threaded runtime and cancellation test.",
        1,
        [],
    ),
    (
        "f-driver-dc4-configured-tls-timeout",
        "Derive TLS handshake timeout from configured budgets",
        "4571-4572",
        "Use the configured connect and deadline budget for TLS handshake rather than a hidden fixed twenty-second cap.",
        "Configured budgets above and below twenty seconds govern predictably and cancellation remains bounded.",
        "Paused-clock handshake budget table.",
        2,
        [],
    ),
    (
        "f-driver-dc5-py5-subsecond-offsets",
        "Preserve sub-minute offsets and negative interval fractions",
        "4571-4575",
        "Retain FixedOffset seconds below one minute and use Euclidean normalization for negative sub-microsecond INTERVAL DAY TO SECOND values.",
        "Positive and negative thirty-second offsets survive and -1ns through -999ns normalize to the correct signed second and fraction pair.",
        "Boundary and metamorphic offset and interval table.",
        2,
        [],
    ),
    (
        "f-driver-dc6-arrow-number-sentinel",
        "Preserve the Oracle NUMBER sentinel in Arrow",
        "4572-4574",
        "Keep Oracle's negative 1e126 NUMBER sentinel semantics in Arrow instead of collapsing the value to negative one.",
        "Arrow and row APIs agree on the sentinel and neighboring exponent cases from decoder-produced values.",
        "Cross-API decoder golden for sentinel boundaries.",
        2,
        [],
    ),
    (
        "f-driver-pr1-bind-name-lone-quote",
        "Make lone-quote bind parsing panic-free",
        "4575-4578",
        "Require both quoted bind-name delimiters before slicing while preserving all valid quoted and unquoted behavior.",
        "A lone quote and arbitrary short input never panic and valid public bind names remain byte-identical.",
        "Focused lone-quote regression and future fuzz seed.",
        2,
        [],
    ),
    (
        "f-driver-dk1-dk2-pool-lifecycle",
        "Remove pool close races and per-waiter OS threads",
        "4578-4580",
        "Remove correctness dependence on Arc strong_count during last-handle close and replace one OS thread per timed waiter with a bounded cancellation-aware timer mechanism.",
        "Racing drops close exactly once and N timed waiters do not create N OS threads while preserving timeout and cancellation behavior.",
        "Stress race, thread-count bound, and deterministic lifecycle schedules.",
        2,
        [],
    ),
    (
        "f-driver-retry-leading-comment-contract",
        "Align retry classification comments and behavior",
        "4696-4705",
        "Keep the fail-safe whitespace-only classifier, correct contradictory documentation, and pin leading-comment SELECT as NonIdempotent rather than silently widening retry eligibility.",
        "Documentation and executable classification agree and no data-changing statement gains retry eligibility.",
        "Leading-comment classification regression and reviewed documentation diff.",
        3,
        [],
    ),
]

for slug, title, source, scope, criterion, proof, priority, dependencies in driver_findings:
    add(
        slug,
        "driver",
        title,
        source,
        scope,
        patch_acceptance(criterion),
        patch_evidence(proof),
        cluster="F",
        issue_type="bug",
        priority=priority,
        tier="tier-1" if priority == 1 else "tier-2",
        parent="f-driver-bughunt-fixes",
        depends_on=dependencies,
    )

add(
    "f-driver-dc7-session-u16-adjudication",
    "driver",
    "Adjudicate the session u16 truncation finding against parity",
    "4573-4574",
    "Reconcile DC7 with closed a7a8 evidence that low-sixteen-bit truncation intentionally matches python-oracledb; do not reintroduce strict rejection without proving a distinct parser contract.",
    ["The exact code site and reference behavior are compared; a fix Bead is created only for a genuinely different overflow contract."],
    ["Closed a7a8 test evidence, current file and line inspection, and written adjudication."],
    cluster="F",
    issue_type="bug",
    priority=2,
    tier="process",
    promotion="reuse",
    existing_id="rust-oracledb-a7a8",
)

server_findings = [
    (
        "f-server-di1-terminal-held-effects",
        "Prevent late-deadline retry of terminal held effects",
        "4566-4566",
        "Treat held execute, checkpoint, and undo-to success as terminal effects at the outer deadline boundary so DI1 and DI6 cannot double-apply.",
        "A late deadline returns the successful held response with exactly one effect and one audit record across all three operation twins.",
        "Injected-clock terminal-effect regression for execute, checkpoint, and undo.",
        1,
        [],
    ),
    (
        "f-server-met-bounded-tool-labels",
        "Bound tool metric label cardinality",
        "4567-4567",
        "Canonicalize advertised tool labels and map every unadvertised client name to one bounded sentinel.",
        "N distinct unknown tool names create constant metric cardinality while known labels remain individually useful.",
        "Cardinality property test and OTLP snapshot.",
        1,
        [],
    ),
    (
        "f-server-di2-di5-dispatch-input-consistency",
        "Clamp preview rows and normalize zero timeout policy",
        "4581-4583",
        "Clamp preview witness max_rows to the server cap and enforce one typed timeout_seconds=0 policy across every tool.",
        "Oversized witnesses cannot bypass caps and an enumerated tool table proves zero timeout is handled identically everywhere.",
        "All-tools generated table and boundary tests.",
        2,
        [],
    ),
    (
        "f-server-di4-token-prune-oldest",
        "Prune the oldest token deterministically",
        "4581-4582",
        "Replace arbitrary hash-iteration token pruning with oldest-first eviction and deterministic tie breaking.",
        "Fixed timestamps always evict the oldest token regardless of insertion or hash order.",
        "Seeded insertion-order and tie-break regression.",
        2,
        [],
    ),
    (
        "f-server-db1-db4-value-fidelity",
        "Preserve BOOLEAN and signed interval values",
        "4584-4589",
        "Serialize 23ai BOOLEAN as its exact value and canonicalize positive and negative sub-day INTERVAL DAY TO SECOND output.",
        "Exact JSON goldens cover true, false, null, and signed sub-day interval boundaries.",
        "Offline value-fidelity table and live-acceptance handoff checklist.",
        2,
        [],
    ),
    (
        "f-server-db2-db3-bind-recovery",
        "Prevent bind-slot mismatch and type failed recovery",
        "4585-4588",
        "Never append unmatched named binds into positional slots and place stream slots in typed quarantine after failed recovery.",
        "Reordered or unmatched names cannot bind incorrectly and failed recovery reports quarantine rather than transient unavailability.",
        "Bind permutation table and injected recovery-failure test.",
        2,
        [],
    ),
    (
        "f-server-cc1-cc2-core-concurrency",
        "Make idempotency leases panic-safe and SSE wakes targeted",
        "4589-4592",
        "Use RAII cleanup for idempotency leases after framework panic and replace broad SSE notify-all behavior with bounded targeted wakeups.",
        "Injected panic permits immediate retry and unrelated SSE waiters do not all wake.",
        "Panic-hook lease regression and waiter-count test.",
        2,
        [],
    ),
    (
        "f-server-g1-vector-batch-normalization",
        "Normalize VECTOR_EMBEDDING in every batch statement",
        "4592-4593",
        "Apply the existing VECTOR_EMBEDDING normalization independently to each statement in a multi-statement batch.",
        "A benign statement is classified identically alone and in a batch while any unsafe batch statement remains refused.",
        "Single-versus-batch metamorphic guard test.",
        2,
        [],
    ),
    (
        "f-server-au1-au4-audit-hardening",
        "Harden audit preimages, CEF, Rekor, and secret errors",
        "4593-4597",
        "Domain-separate and length-prefix audit fields under an explicit version and migration policy, escape Unicode line separators, parse exact Rekor head fields, and remove raw secret references from malformed errors.",
        "Old fixtures follow the declared compatibility policy and all four adversarial ambiguity or disclosure cases fail safely.",
        "Prefix-free KAT, migration fixture, Unicode, Rekor-substring, and secret-ref negative tests.",
        2,
        [],
    ),
    (
        "f-server-cf2-prose-ocid-redaction",
        "Redact OCIDs embedded in prose",
        "4597-4599",
        "Extend value-shape redaction to prose-embedded tenancy, user, and compartment OCIDs without masking approved hashes or ordinary text.",
        "Embedded OCIDs never survive and negative canaries prove ordinary text and approved non-secrets remain visible.",
        "Redactor positive and negative canary table.",
        2,
        [],
    ),
    (
        "f-server-cf3-doctor-atomic-replace",
        "Eliminate doctor destination rename races",
        "4598-4599",
        "Replace check-then-rename with a securely opened and validated atomic destination operation while retaining containment and permissions.",
        "Concurrent replacement or symlink attempts cannot redirect or overwrite an unvalidated target.",
        "Adversarial filesystem race test and platform gate.",
        3,
        [],
    ),
]

for slug, title, source, scope, criterion, proof, priority, dependencies in server_findings:
    add(
        slug,
        "server",
        title,
        source,
        scope,
        patch_acceptance(criterion),
        patch_evidence(proof),
        cluster="F",
        issue_type="bug",
        priority=priority,
        tier="tier-1" if priority == 1 else "tier-2",
        parent="f-server-bughunt-fixes",
        depends_on=dependencies,
    )

for slug, repo, title, existing_id, source, scope, criterion, proof, priority in [
    (
        "f-driver-4sfc-tls-error-classification",
        "driver",
        "Preserve configuration-time TLS error classification",
        "rust-oracledb-4sfc",
        "4759-4759",
        "Keep configuration-time TLS failures as their real typed error instead of converting them into failover-eligible call timeouts.",
        "TLS configuration errors cannot trigger inappropriate failover and configured timeout behavior remains deterministic.",
        "Existing Bead evidence plus fault-class regression.",
        2,
    ),
    (
        "f-driver-s0se-tls-close-notify",
        "driver",
        "Classify Oracle TLS EOF without close_notify correctly",
        "rust-oracledb-s0se",
        "4765-4765",
        "Accept Oracle's clean session close without TLS close_notify while still rejecting truncated application data.",
        "Clean EOF succeeds and truncated application data remains a typed failure.",
        "Existing Bead evidence and TLS fixture matrix.",
        3,
    ),
    (
        "f-server-yb7m-descriptor-timeout",
        "server",
        "Honor connect timeout for full Oracle Net descriptors",
        "oraclemcp-yb7m",
        "4762-4762",
        "Accept connect_timeout_seconds for full descriptors and ADB wallets and preserve it through driver setup.",
        "Descriptor profiles carry the configured timeout into the driver without weakening validation.",
        "Existing Bead tests plus driver timeout handoff checksum.",
        2,
    ),
    (
        "f-server-vzui-windows-durable-state",
        "server",
        "Fix Windows durable state access denied behavior",
        "oraclemcp-vzui",
        "4761-4761",
        "Restore Windows file-store persistence and reopening without weakening hard-link lock or file-identity defenses.",
        "Windows persists and reopens state while unsafe linked lock state is still refused.",
        "Existing Bead criteria and real Windows CI artifact.",
        1,
    ),
]:
    add(
        slug,
        repo,
        title,
        source,
        scope,
        patch_acceptance(criterion),
        patch_evidence(proof),
        cluster="F",
        issue_type="bug",
        priority=priority,
        tier="tier-1" if priority == 1 else "tier-2",
        parent=f"f-{repo}-bughunt-fixes",
        handoffs=[handoff("f-driver-dc4-configured-tls-timeout", "Driver TLS budget regression checksum")]
        if slug == "f-server-yb7m-descriptor-timeout"
        else [],
        promotion="reuse",
        existing_id=existing_id,
    )

add(
    "f-rejected-findings-ledger",
    "server",
    "Record rejected bug-hunt findings so they are not re-hunted",
    "4601-4618",
    "Preserve G3, CF4, DB5, PR2, PR3, G2, and DK3 as reviewed not-a-bug decisions; DB5 or G2 may receive a separate hardening test only if independently selected.",
    ["No implementation Bead is generated for a rejected finding and each rejection remains source-addressable."],
    ["Rejected-finding table and mapping audit showing zero promoted fixes."],
    cluster="F",
    issue_type="chore",
    priority=4,
    tier="process",
    promotion="record-only",
    condition="These findings were explicitly rejected after review and must not become fix tasks.",
)


# G — scheduled product features for the patch releases.
for repo in ("driver", "server"):
    add(
        f"g-{repo}-product-features",
        repo,
        f"Ship the scheduled {repo} patch-line product features",
        "4469-4516",
        f"Own every scheduled {repo} Tranche 7 feature without deferring scope, adding public API, or weakening safety.",
        ["Every child lands in exactly 0.8.5 or 0.9.1 as applicable and cargo-semver-checks confirms patch legality."],
        ["Child closure ledger and exact patch-release qualification artifact."],
        cluster="G",
        issue_type="epic",
        priority=1,
    )
add(
    "g-driver-adb-sni-shipped",
    "driver",
    "Record that ADB TCPS SNI support already shipped",
    "4477-4497",
    "Record token auth, TCPS security and passthrough, host-SNI fallback, wallet handling, and live signoff as shipped driver 0.8.4 capabilities rather than pending work.",
    ["No future task recreates the SNI feature and the only residual acceptance item is server IAM subject mapping."],
    ["Closed driver Beads, v0.8.4 tag, server pin, and live signoff."],
    cluster="G",
    issue_type="feature",
    priority=1,
    tier="process",
    promotion="record-only",
    condition="The complete driver capability shipped in v0.8.4 and must not be recreated.",
)
add(
    "g-driver-zoned-tstz-shipped",
    "driver",
    "Record shipped zoned timestamp bind and fetch support",
    "4477-4484",
    "Preserve the parity-ledger evidence that offset-preserving zoned bind and fetch shipped before this program and avoid stale missing-feature claims.",
    ["The product feature is not duplicated; DC1 remains a narrower Arrow conversion correction with explicit prior-decision reconciliation."],
    ["Parity ledger entries, release history, and the DC1 task mapping."],
    cluster="G",
    issue_type="feature",
    priority=4,
    tier="process",
    promotion="record-only",
    condition="The feature is completed prior art; only its distinct Arrow conversion bug remains actionable.",
)
add(
    "g-server-he7t-iam-subject-mapping",
    "server",
    "Correct the ADB IAM subject-name mapping",
    "4486-4497",
    "Change only harness and configuration to use the domain-qualified IAM subject form expected by ADB; do not alter driver, guard, or authorization semantics.",
    patch_acceptance("The mapped synthetic IAM principal connects after bootstrap and token validation using the already-shipped TCPS path."),
    patch_evidence("Secret-safe live signoff, exact configuration diff, and terminal cleanup result."),
    cluster="G",
    priority=1,
    parent="g-server-product-features",
    promotion="reuse",
    existing_id="oraclemcp-he7t",
)
add(
    "g-driver-live-nightly-green-streak",
    "driver",
    "Root-cause Live nightly red and restore blocking",
    "4498-4503",
    "Diagnose the remaining Live-nightly product or infrastructure failures, add a regression for the real cause, and obtain the required three-green streak before automatic reblocking.",
    patch_acceptance("Three consecutive exact-SHA nightlies are green and the advisory-to-required state transition is automatic and visible."),
    patch_evidence("Root-cause regression, three immutable run IDs and artifacts, and gate transition log."),
    cluster="G",
    priority=1,
    parent="g-driver-product-features",
    depends_on=["b-driver-live-advisory-autoreblock"],
)
add(
    "g-server-typed-scn-capability",
    "server",
    "Probe SCN capability with typed fallback behavior",
    "4505-4510",
    "Probe SCN capture and use existing typed refusal or explicitly audited degraded-mode surfaces; never silently substitute V$DATABASE or add a public field.",
    patch_acceptance("Supported SCN remains exact and unsupported capability refuses or degrades observably with an audit-visible reason."),
    patch_evidence("Capability matrix and focused refusal or degraded-mode audit test."),
    cluster="G",
    issue_type="feature",
    priority=1,
    parent="g-server-product-features",
)
add(
    "g-server-lane-health-dashboard",
    "server",
    "Expose lane conclusion and streak health in Ground Control",
    "4510-4513",
    "Render every scheduled and advisory lane's last conclusion, source run, and streak from the machine lane manifest, with fail-closed unknown, stale, and crash states.",
    patch_acceptance("No unknown, crashed, or stale lane renders green and every visible state cites its source run."),
    patch_evidence("Lane JSON fixture, UI golden, stale and crash negative cases, and web gate."),
    cluster="G",
    issue_type="feature",
    priority=1,
    parent="g-server-product-features",
    depends_on=["h-server-tier-manifest"],
)
add(
    "g-server-adk-compat-fixes",
    "server",
    "Map conditional ADK compatibility fixes to G2F",
    "4514-4516",
    "Represent F-S3 only through one defect-specific G2F child after the ADK audit proves a general MCP compatibility defect; never create an empty or client-specific fix program.",
    ["Every promoted defect has a minimal DB-free reproducer, safety review, narrow client-neutral patch, and focused plus full gates."],
    ["The G2 compatibility row and its defect-specific patch evidence if a defect is confirmed."],
    cluster="G",
    issue_type="feature",
    priority=1,
    tier="process",
    depends_on=["j-g2-stdio-schema-audit"],
    promotion="record-only",
    condition="F-S3 is the same conditional work as J G2F and must not create a duplicate Bead.",
)


# H — test organization, verification discipline, contracts, faults, and logs.
for repo in ("driver", "server"):
    add(
        f"h-{repo}-quality-system",
        repo,
        f"Close the remaining {repo} test and verification blind spots",
        "4889-5101",
        f"Own the remaining {repo} surgical regressions, organization, contract migration, fault, flake, corpus, and evidence-verdict work without duplicating closed evidence-control foundations.",
        ["Every child adds a discriminating contract or an explicit completed mapping and no test claim exceeds its evidence."],
        ["Child closure ledger, lane manifest, scorecard, and exact-SHA quality artifact."],
        cluster="H",
        issue_type="epic",
        priority=1,
    )
    foundation_id = (
        "rust-oracledb-evidence-controls-f1cl"
        if repo == "driver"
        else "oraclemcp-evidence-controls-yg4x"
    )
    add(
        f"h-{repo}-evidence-controls-foundation",
        repo,
        f"Reuse the completed {repo} evidence-control foundation",
        "4406-4425",
        "Map already-shipped versioned schemas, sealed exact-SHA proofs, tri-state verdicts, close-evidence audit, mutation schema, and CI taxonomy to V11 and V12 rather than recreating them.",
        ["New verification tasks are scoped only to proven deltas and retain every fail-closed foundation test."],
        ["Closed evidence-control epic and children, exact IDs, and delta coverage matrix."],
        cluster="H",
        issue_type="epic",
        priority=1,
        tier="process",
        promotion="reuse",
        existing_id=foundation_id,
    )

add(
    "h-surgical-regressions-absorbed",
    "server",
    "Map surgical regressions into their owning bug fixes",
    "4987-5020",
    "Record that value fidelity, DI1, metric cardinality, DC1, DC2/DC3, CC1, and AU1 surgical tests are acceptance criteria of their F fixes rather than duplicate H tasks.",
    ["All eleven surgical additions map to an owning F or concrete H task and none disappears or is duplicated."],
    ["One-to-one section 30.4 mapping ledger and owner task slugs."],
    cluster="H",
    priority=1,
    tier="process",
    promotion="record-only",
    condition="These regressions are implemented with their owning fixes or concrete H harness tasks.",
)
add(
    "h-v6-v7-v10-charter-mapping",
    "server",
    "Map ground-truth verification rules into Charter and tracker work",
    "4406-4425",
    "Map V6 file-and-line premises, V7 no flake closure from negative repro, and V10 empirical toolchain and documentation checks into E Charter and tracker enforcement.",
    ["The relevant E acceptance criteria explicitly enforce all three rules in both repositories."],
    ["Rule-to-E-task mapping and Charter coverage matrix."],
    cluster="H",
    priority=1,
    tier="process",
    depends_on=["e-server-charter-v2", "e-tracker-close-integrity"],
    promotion="record-only",
    condition="The binding implementation belongs to cluster E rather than duplicate H Beads.",
)
add(
    "h-v9-absent-record",
    "server",
    "Record that the plan defines no V9 requirement",
    "4406-4425",
    "Preserve the V-series namespace exactly as written and do not invent an unreviewed V9 requirement during conversion.",
    ["The coverage ledger calls out the gap explicitly and every defined V item is mapped."],
    ["V-series source range and conversion coverage ledger."],
    cluster="H",
    priority=4,
    tier="process",
    promotion="record-only",
    condition="No V9 requirement exists in the governing plan or companion retro.",
)
add(
    "h-v14-ui-completed-record",
    "server",
    "Preserve the completed fail-closed UI verdict work",
    "4415-4421",
    "Record V14 as already landed through the wire-field fail-closed UI and QA regressions; retain those tests without creating a replacement implementation.",
    ["Partial, unknown, crashed, and malformed verdict fixtures remain red or unknown and cannot render green."],
    ["Closed tmmi and QA100 evidence plus existing regression paths."],
    cluster="H",
    priority=1,
    tier="process",
    promotion="record-only",
    condition="The V14 implementation and regressions are already landed and only preservation is required.",
)

for slug, repo, title, source, scope, criterion, proof, priority, dependencies in [
    (
        "h-driver-sql-bind-fuzz",
        "driver",
        "Fuzz SQL bind-name parsing",
        "5005-5006",
        "Add the missing sql.rs target to existing fuzz infrastructure and preserve minimized lone-quote and delimiter corpus cases.",
        "Arbitrary bytes never panic or overrun and the target compiles in CI and runs in the resource-capped nightly tier.",
        "Target manifest entry, seed corpus, compile artifact, and bounded zero-crash run.",
        2,
        ["f-driver-pr1-bind-name-lone-quote"],
    ),
    (
        "h-server-config-merge-fuzz",
        "server",
        "Fuzz config parsing and prove ceiling merges",
        "5012-5015",
        "Property-test merged privilege ceilings and protected profiles, and fuzz TOML parsing so malformed input never panics or widens authority.",
        "Merged max_level never exceeds any source and protected profiles always remain READ_ONLY.",
        "Proptest seeds, minimized counterexamples, fuzz corpus, and nightly artifact.",
        2,
        [],
    ),
    (
        "h-server-concurrency-models",
        "server",
        "Model core lock, lease, and SSE schedules",
        "5016-5017",
        "Use an Asupersync-compatible deterministic model for lock ranks, panic-safe leases, and targeted SSE wakeups after auditing whether loom or the native scheduler is the correct mechanism.",
        "Bounded interleavings preserve no-deadlock, no-lost-wakeup, single-owner, and immediate panic cleanup properties.",
        "Model-selection audit, deterministic schedules, and minimized failure traces.",
        2,
        ["f-server-cc1-cc2-core-concurrency"],
    ),
    (
        "h-driver-pool-model-gap-audit",
        "driver",
        "Extend pool DPOR only for proven lifecycle gaps",
        "5016-5017",
        "Audit current pool synchronization against closed llv.4.4; add loom only for a remaining std sync or atomic island, otherwise extend DPOR with missing checkout, idle-reap, close, and timed-wait schedules.",
        "The selected model covers every remaining concurrency primitive without reintroducing a rejected parallel framework.",
        "llv.4.4 reconciliation, synchronization inventory, schedule count, and deterministic result.",
        2,
        ["f-driver-dk1-dk2-pool-lifecycle"],
    ),
    (
        "h-server-oauth-verifier-matrices",
        "server",
        "Unify OAuth rejection and verifier tamper matrices",
        "5018-5020",
        "Audit and consolidate nine OAuth rejection classes plus one accept case and verdict-verifier tampering for flipped verdict, wrong SHA, and forged MAC using existing fixtures.",
        "Every invalid row returns a specific typed refusal and the valid row passes without weakening scopes or signature binding.",
        "Matrix output, fixture reuse ledger, and exact golden results.",
        2,
        [],
    ),
]:
    add(
        slug,
        repo,
        title,
        source,
        scope,
        [criterion],
        [proof],
        cluster="H",
        priority=priority,
        tier="tier-2",
        parent=f"h-{repo}-quality-system",
        depends_on=dependencies,
    )

add(
    "h-driver-conformance-value-wire-parity",
    "driver",
    "Recertify value, type, and authentication wire parity",
    "4408-4414",
    "Implement V1 exact datetime and numeric values, V2 wire bytes for plain, TCPS, token, and wallet modes, V4 every downstream typed branch, and V5 reproducer plus as-of SHA for parity claims.",
    ["No audited test collapses type, offset, precision, or wire distinctions and exact-SHA differential qualification passes."],
    ["Differential report, decoder-produced goldens, raw wire bytes, reproducer, and as-of SHA."],
    cluster="H",
    priority=1,
    parent="h-driver-quality-system",
    depends_on=[
        "f-driver-dc1-arrow-tstz-offset",
        "f-driver-dc2-dsn-cert-dn-pin",
        "f-driver-dc3-dsn-dn-match-off",
        "f-driver-py1-number-scale-type",
        "f-driver-py2-decimal-exact-bind",
        "f-driver-py3-bigint-exact-bind",
        "f-driver-dc5-py5-subsecond-offsets",
        "f-driver-dc6-arrow-number-sentinel",
    ],
)
add(
    "h-server-apply-path-invariants",
    "server",
    "Make privileged apply-path coverage self-enumerating",
    "5257-5265",
    "Audit the five existing SEC-1 tests, then add only the missing registry or architecture fitness layer that fails when a new write, DDL, or session dispatch path lacks apply-time reclassification; retain V3, V4, and V8 typed clamps.",
    ["Adding a synthetic privileged path without reclassification coverage fails and no safety fallback silently substitutes success."],
    ["Existing-test audit, seeded missing-path fixture, named invariant tests, and mutation witness."],
    cluster="H",
    priority=1,
    parent="h-server-quality-system",
)

for repo in ("server", "driver"):
    add(
        f"h-{repo}-monitor-predicate-delta",
        repo,
        f"Audit and close V13 monitor predicate gaps for {repo}",
        "4415-4421",
        "Build on completed sealed exact-SHA and tri-state evidence controls; test structured monitor predicates against known good, bad, truncated, crashed, stale, and unknown producer streams.",
        ["Only sealed terminal exact-SHA per-job evidence can qualify and every malformed or incomplete predicate fails closed."],
        ["Foundation audit, known-good and bad fixtures, and monitor parser results."],
        cluster="H",
        priority=1,
        parent=f"h-{repo}-quality-system",
        depends_on=[f"h-{repo}-evidence-controls-foundation"],
    )

for repo in ("server", "driver"):
    scope = (
        "Extend the existing ci-taxonomy data with required or advisory state, owner, retries, platform, features, secrets, release-blocking, and tier; make CI and documentation validate against one manifest."
    )
    if repo == "driver":
        scope += " Represent pyshim and fuzz compile explicitly, move full Free23 live work to Tier 2, and retain a narrow defined 23ai pull-request smoke."
    add(
        f"h-{repo}-tier-manifest",
        repo,
        f"Extend the {repo} lane taxonomy into a complete tier manifest",
        "5038-5101",
        scope,
        ["No lane is assumed covered; manifest drift fails, advisory versus required is machine-distinct, and release consumers remain exact-SHA."],
        ["Extended manifest, lint fixtures, generated documentation, and before and after schedule graph."],
        cluster="H",
        priority=1,
        parent=f"h-{repo}-quality-system",
        depends_on=[f"h-{repo}-evidence-controls-foundation", f"d-{repo}-coverage-ratchet"],
    )

for repo in ("server", "driver"):
    add(
        f"h-{repo}-fixture-scorecard-discipline",
        repo,
        f"Maintain a per-crate scorecard and non-self-fulfilling fixtures for {repo}",
        "4969-5036",
        "Generate the per-crate test and lane scorecard, audit datetime, number, and type fixtures for decoder bypass or collapsed assertions, and require fixture-shape review with deterministic clocks, seeds, and schedules.",
        ["Every crate and non-Cargo surface has an honest lane entry and type-sensitive tests preserve the discriminant under test."],
        ["Scorecard, audited-file ledger, corrected fixtures, deterministic seed policy, and review-rule diff."],
        cluster="H",
        priority=1,
        parent=f"h-{repo}-quality-system",
    )

add(
    "h-server-versioned-contract-migrations",
    "server",
    "Archive versioned contracts and test migrations",
    "5396-5396",
    "Archive vN emitted audit, evidence, configuration, and state fixtures and define producer-to-consumer migration or typed-refusal policy for every persisted contract.",
    ["Each old fixture remains consumable or fails through its declared version policy and version bumps have positive and negative tests."],
    ["Archived fixtures, compatibility matrix, migration results, and bump-negative test."],
    cluster="H",
    priority=0,
    tier="tier-0",
    parent="h-server-quality-system",
)
add(
    "h-server-driver-contract-provider",
    "server",
    "Publish the exact server-driver contract input",
    "5397-5397",
    "Package the existing oracledb contract suite and an exact revision, schema, feature, and expected-result manifest without adding a public crate API.",
    ["The immutable provider artifact identifies server SHA, driver revision, schemas, features, and expected results and its own tests pass."],
    ["Provider artifact, checksum, suite inventory, and focused test result."],
    cluster="H",
    priority=0,
    tier="tier-0",
    parent="h-server-quality-system",
    depends_on=["h-server-versioned-contract-migrations"],
)
add(
    "h-driver-server-contract-qualification",
    "driver",
    "Run the shared server contract in driver qualification",
    "5397-5397",
    "Consume the exact checksum-bound server contract in driver pull-request and release qualification so workspace-only tests cannot hide a server seam regression.",
    ["Wrong or stale provider checksum fails and a driver change that breaks the server contract cannot qualify."],
    ["Provider checksum, exact run ID, result artifact, and stale-input negative case."],
    cluster="H",
    priority=0,
    tier="tier-0",
    parent="h-driver-quality-system",
    handoffs=[handoff("h-server-driver-contract-provider", "Server-driver contract provider checksum")],
)
add(
    "h-server-contract-consumer-gate",
    "server",
    "Fail closed on driver contract qualification results",
    "5397-5397",
    "Consume the checksum-bound driver qualification result as the final server compatibility seam in the one-way provider-to-driver-to-server DAG.",
    ["Missing, stale, partial, or mismatched results fail closed and no reciprocal dependency cycle exists."],
    ["Good, stale, missing, and mismatch fixtures plus the complete checksum chain."],
    cluster="H",
    priority=0,
    tier="tier-0",
    parent="h-server-quality-system",
    depends_on=["h-server-driver-contract-provider"],
    handoffs=[handoff("h-driver-server-contract-qualification", "Driver qualification result checksum")],
)

for repo, dependencies in [
    ("server", ["f-server-di1-terminal-held-effects", "f-server-db2-db3-bind-recovery"]),
    ("driver", ["f-driver-py4-detach-blocking-io", "f-driver-4sfc-tls-error-classification"]),
]:
    add(
        f"h-{repo}-error-path-matrix",
        repo,
        f"Systematize {repo} fault and error-path coverage",
        "5399-5399",
        "Build on existing fault-injection harnesses to enumerate disk or partial writes, cancellation boundaries, malformed responses, token or TLS expiry, clock regression, recovery, and retry-no-duplicate-effect postconditions.",
        ["Every matrix row names the injected fault, typed outcome, cleanup state, and duplicate-effect assertion."],
        ["Generated matrix report, harness reuse ledger, and exact failing or passing row output."],
        cluster="H",
        priority=1,
        parent=f"h-{repo}-quality-system",
        depends_on=dependencies,
    )
for repo in ("server", "driver"):
    add(
        f"h-{repo}-flake-discipline",
        repo,
        f"Make {repo} flakes measurable and expiring",
        "5400-5400",
        "Add repeated-run statistics, owner and expiry for quarantine, infrastructure-skip versus product-failure distinction, no-retry diagnostic lanes, and attempt telemetry that exposes first-attempt failure.",
        ["Retries cannot hide a first-attempt failure and every expired quarantine fails until removed or renewed with evidence."],
        ["Repeated-run report, quarantine expiry fixture, no-retry artifact, and attempt telemetry."],
        cluster="H",
        priority=1,
        parent=f"h-{repo}-quality-system",
        depends_on=[f"h-{repo}-tier-manifest"],
    )
    add(
        f"h-{repo}-golden-governance",
        repo,
        f"Govern {repo} goldens with provenance and scrubber canaries",
        "5401-5401",
        "Give every scrubber a protected-field negative canary and every golden a generator, source-version provenance, and reviewer-approved deterministic regeneration command.",
        ["Over-broad scrubbing fails and regenerated output is deterministic and reviewable."],
        ["Canary suite, provenance manifest, approved command, and deterministic regeneration diff."],
        cluster="H",
        priority=1,
        parent=f"h-{repo}-quality-system",
    )
    add(
        f"h-{repo}-regression-corpora-schedules",
        repo,
        f"Govern {repo} regression corpora and schedules",
        "5402-5402",
        "Retain minimized property and fuzz failures with reviewable provenance, inject clocks, extend only missing deterministic schedules, and label performance evidence as measured rather than covered.",
        ["Every corpus entry replays, every schedule has a stable seed, and measurement-only tests cannot satisfy coverage claims."],
        ["Corpus manifest, schedule replay, provenance review, and wording audit."],
        cluster="H",
        priority=2,
        tier="tier-2",
        parent=f"h-{repo}-quality-system",
        depends_on=["h-server-concurrency-models"] if repo == "server" else ["h-driver-pool-model-gap-audit"],
    )

for slug, title, source, scope, criterion, proof, priority, dependencies in [
    (
        "h-server-stdio-arch-fitness",
        "Prevent stdout writes on served JSON-RPC paths",
        "5337-5344",
        "Add executable architecture fitness proving served JSON-RPC request paths cannot reach println or stdout writes while explicit CLI output remains allowed.",
        "A seeded served-path stdout violation fails with a call path and legitimate CLI output continues.",
        "Architecture fixture, seeded violation, and normal-path pass result.",
        1,
        [],
    ),
    (
        "h-server-local-log-redaction",
        "Apply structural redaction to local stderr",
        "5345-5350",
        "Run the existing Redactor over local structured stderr as well as OTLP and exercise secret-bearing DSN, bind, OCID, and reference failures.",
        "No secret, OCID, bind, or DSN survives either sink and negative canaries prevent destructive over-redaction.",
        "Captured stderr and OTLP payloads plus positive and negative canaries.",
        1,
        ["f-server-cf2-prose-ocid-redaction"],
    ),
    (
        "h-server-request-span-correlation",
        "Correlate request spans through local logs and OTLP",
        "5351-5358",
        "Create one request span carrying request, session, lane, subject, and tool identifiers and propagate matching trace and span IDs to OTLP without raw secrets.",
        "Concurrent requests are separable by one query and local and remote events carry matching correlation IDs.",
        "Concurrent multi-request integration capture and OTLP trace fixture.",
        1,
        [],
    ),
    (
        "h-server-operator-event-logging",
        "Emit bounded refusal and lease lifecycle events",
        "5359-5364",
        "Add reason-code-only guard-refusal warnings and lease revoke or expiry info events while preserving the diagnostic-log versus audit-chain separation.",
        "Events appear exactly once, contain no SQL or secret, and never replace the authoritative audit record.",
        "Captured event tests, duplicate check, and audit separation assertion.",
        2,
        ["h-server-local-log-redaction"],
    ),
]:
    add(
        slug,
        "server",
        title,
        source,
        scope,
        [criterion],
        [proof],
        cluster="H",
        priority=priority,
        parent="h-server-quality-system",
        depends_on=dependencies,
    )


# Semantic reconciliation tasks discovered by comparing the governing plan with
# the live repo-local trackers. These make prior decisions, tranche gates, and
# swarm activation order machine-visible instead of burying them in prose.
add(
    "b-server-tranche-1-complete",
    "server",
    "Prove server CI Tranche 1 complete",
    "3993-4000",
    "Close the server's first CI tranche only after its same-SHA scheduling, projection, release-surface, and rehearsal deltas are all proven without weakening the load-bearing release invariants.",
    [
        "Every server Tranche-1 child is closed at the same exact SHA and the release rehearsal proves the retained hard gates and publish ordering."
    ],
    ["Same-SHA child ledger, Required proof, rehearsal artifact, and invariant checklist."],
    cluster="B",
    priority=0,
    tier="process",
    depends_on=[
        "b-server-release-build-overlap",
        "b-server-acceptance-dedupe",
        "b-server-quality-projection-relocation",
        "b-server-release-surface-runbook",
        "b-server-pretag-release-rehearsal",
    ],
)
add(
    "b-driver-tranche-1-complete",
    "driver",
    "Prove driver CI Tranche 1 complete",
    "3993-4000",
    "Close the driver's first CI tranche only after proof parallelism, live-matrix scheduling, pinned tools, single-flight qualification, disk preflight, and advisory-state mechanics are proven together.",
    [
        "Every driver Tranche-1 child is closed at one exact SHA and the state-machine proof does not falsely require three future live-nightly runs."
    ],
    ["Same-SHA child ledger, workflow proof, state-machine fixtures, and invariant checklist."],
    cluster="B",
    priority=0,
    tier="process",
    depends_on=[
        "b-driver-required-proof-parallel",
        "b-driver-live-matrix-parallel-start",
        "b-driver-pinned-tool-installs",
        "b-driver-rq-single-flight",
        "b-driver-powerset-disk-assert",
        "b-driver-live-advisory-autoreblock",
    ],
)
add(
    "c-demono-db-connection-seam-decision",
    "server",
    "Re-adjudicate the connection.rs single-file seam",
    "4094-4121",
    "Reconcile the new de-monolith proposal against the closed single-file driver-seam decision before any split, including the exact-path allowlist, pin test, driver-value boundary, and embedded test modules.",
    [
        "The decision explicitly upholds or supersedes oraclemcp-demonolith-connection-leave-alone-jwh1 with current file evidence and names every lock that a safe split must migrate."
    ],
    ["Current seam-lint output, source ownership map, test placement audit, and signed decision record."],
    cluster="C",
    priority=0,
    tier="process",
    parent="c-demono-epic",
    depends_on=["c-demono-dispatch-mod", "c-demono-web-app"],
    lineage=[
        {
            "id": "oraclemcp-demonolith-connection-leave-alone-jwh1",
            "relation": "supersedes",
        }
    ],
)
add(
    "d-load-bearing-ci-invariants",
    "server",
    "Preserve the load-bearing CI and release invariants",
    "3974-3987",
    "Record the exact-SHA evidence chain, hard live release gate, fail-closed Required parser, cheap always-on safety gates, server publish ordering and main cancellation policy, and advisory scheduled-lane taxonomy as non-regression constraints.",
    ["Every B and D implementation task cites the applicable invariant and no optimization weakens one."],
    ["Plan source range and invariant-to-task coverage ledger."],
    cluster="D",
    priority=0,
    tier="process",
    promotion="record-only",
    condition="These are preserved constraints on other tasks, not an independently actionable Bead.",
)
add(
    "e-server-swarm-ready",
    "server",
    "Prove the server Charter v2 swarm controls",
    "4453-4457",
    "Gate every later server swarm on the tracked Charter, durable orders and acknowledgements, graded worktree lifecycle, physical build lease, identity and spawn quota, CI tending, and seeded procedural memory.",
    [
        "A bounded dry-run swarm proves acknowledgement hashes, first-deliverable deadlines, PID/log/result capture, clean-HEAD landing, hot-file ownership, watchdog behavior, and resource ceilings."
    ],
    ["Dry-run transcript, worker artifacts, resource report, and exact Charter checksum."],
    cluster="E",
    priority=0,
    tier="process",
    depends_on=[
        "e-server-charter-v2",
        "e-orchestration-controls",
        "e-ntm-charter-orders-templates",
        "e-server-worktree-lifecycle",
        "e-server-build-lease",
        "e-orchestrator-identity-spawn-quota",
        "e-orchestrator-ci-tending",
        "e-server-cm-seed",
    ],
)
add(
    "e-driver-swarm-ready",
    "driver",
    "Prove the driver Charter v2 swarm controls",
    "4453-4457",
    "Gate every later driver swarm on its tracked Charter, graded worktree lifecycle, configured physical build lease, seeded procedural memory, canonical repo-local tracker, and untouched clean-room reference boundary.",
    ["A bounded driver dry-run conforms to the server Charter checksum and all driver-specific resource and repository boundaries."],
    ["Driver dry-run transcript, resource report, tracker proof, reference-tree proof, and Charter checksum."],
    cluster="E",
    priority=0,
    tier="process",
    depends_on=[
        "e-driver-charter-v2",
        "e-driver-worktree-lifecycle",
        "e-driver-build-lease",
        "e-driver-cm-seed",
    ],
    handoffs=[handoff("e-server-swarm-ready", "Accepted server Charter-v2 swarm proof checksum")],
)
add(
    "f-driver-dc1-prior-arrow-contract",
    "driver",
    "Map the prior Arrow TSTZ wall-clock decision",
    "4559-4559",
    "Treat the closed etib.1 wall-clock parity decision as required adjudication context before changing Arrow TIMESTAMP WITH TIME ZONE epoch behavior.",
    [
        "The later instant-preserving proposal is compared with the prior upstream-parity contract and the owning fix may close with the prior decision upheld if evidence rejects the proposal."
    ],
    ["Closed decision record, upstream behavior evidence, and explicit chosen-contract ledger."],
    cluster="F",
    priority=0,
    tier="process",
    promotion="reuse",
    existing_id="rust-oracledb-upstream-sync-2026-07-13-etib.1",
    reuse_action="record-complete",
)
add(
    "h-server-db-type-fidelity-tstz-vector",
    "server",
    "Complete zoned TSTZ and VECTOR value-fidelity coverage",
    "4992-4994",
    "Extend the exact-JSON database type-fidelity table with decoder or real-row-produced TIMESTAMP WITH TIME ZONE and VECTOR values while preserving offset, element type, shape, and value distinctions.",
    [
        "The TSTZ and VECTOR rows fail when offset, type, shape, precision, or value changes and complement the BOOLEAN regression owned by the F fix."
    ],
    ["Focused exact-value table output, seeded discriminant failures, and fixture provenance."],
    cluster="H",
    priority=1,
    tier="tier-1",
    parent="h-server-quality-system",
    depends_on=["f-server-db1-db4-value-fidelity"],
)
add(
    "h-driver-security-clamp-fallback-matrix",
    "driver",
    "Mutation-test driver security clamps and typed fallbacks",
    "4412-4425",
    "Exercise V3 mutation resistance on descriptor and TLS security clamps and V8 typed-error behavior for every safety fallback; no failure path may silently substitute a permissive value or success.",
    [
        "Security-clamp mutants are witnessed or explicitly errored, and each fallback branch returns its exact typed refusal under a discriminating regression."
    ],
    ["Mutation witnesses, typed-error matrix, downstream contract tests, and exact-SHA report."],
    cluster="H",
    priority=1,
    tier="tier-2",
    parent="h-driver-quality-system",
    depends_on=[
        "d-driver-mutation-integrity",
        "f-driver-dc2-dsn-cert-dn-pin",
        "f-driver-dc3-dsn-dn-match-off",
        "f-driver-4sfc-tls-error-classification",
    ],
)
add(
    "h-driver-v6-v7-v10-charter-mapping",
    "driver",
    "Map driver ground-truth verification rules into Charter work",
    "4406-4425",
    "Prove the driver Charter and tracker implementation carries V6 verified file-and-line premises, V7 no flake closure from a negative reproduction, and V10 empirical toolchain and documentation checks.",
    ["The driver binding implementation and tracker enforcement explicitly cover all three rules."],
    ["Driver rule-to-task matrix, Charter diff, and tracker enforcement fixtures."],
    cluster="H",
    priority=1,
    tier="process",
    depends_on=["e-driver-charter-v2", "e-driver-tracker-adoption"],
    promotion="record-only",
    condition="The binding implementation belongs to driver cluster E rather than a duplicate H Bead.",
)
add(
    "j-g2-gemini-final-acceptance",
    "server",
    "Run bounded Gemini declaration acceptance",
    "1288-1299",
    "After the local ADK schema audit and Vertex cost guard, run the bounded real Gemini initialize, catalog, representative call, structured refusal, recovery, and shutdown acceptance and close the final G2 matrix.",
    ["Every final Gemini matrix row is PASS, FAIL, or typed NOT_TESTED with actual model, region, usage, and cost evidence."],
    ["Bounded live transcript, final compatibility matrix, model metadata, usage, and cost record."],
    cluster="J",
    priority=1,
    tier="operator-gated",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g1-vertex-project-cost-guard", "j-g2-stdio-schema-audit"],
    operator_gate="cost",
)
add(
    "j-g2-blocking-defect-gate",
    "server",
    "Clear all stdio-blocking compatibility defects",
    "1301-1345",
    "Close only after the final Gemini matrix exists and every confirmed stdio-blocking G2F child is closed with its checksum; nonblocking limitations stay explicit without blocking the demo.",
    ["The gate enumerates zero unresolved blocking defects and every dynamic child has a reproducer, safety review, landed patch evidence, or explicit nonblocking disposition."],
    ["Final matrix, dynamic-child ledger, close evidence, and accepted checksums."],
    cluster="J",
    priority=1,
    tier="process",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g2-gemini-final-acceptance"],
)
add(
    "j-g5-live-three-beat-qualification",
    "server",
    "Qualify the three evidence beats on Vertex Gemini",
    "918-1109",
    "Run the already-built assertion runner against bounded Vertex Gemini twice, proving the exact read value, destructive preview refusal and postcondition, and audit verify plus head anchor without model-only evidence.",
    ["Both live runs pass structurally within the accepted call and cost ceiling and every seeded false proof exits nonzero."],
    ["Two live evidence bundles, usage and cost records, postcondition, audit anchor, and negative controls."],
    cluster="J",
    priority=1,
    tier="operator-gated",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g5-three-beat-evidence-runner", "j-g2-gemini-final-acceptance"],
    operator_gate="cost",
)
add(
    "j-g7-recording-kit",
    "server",
    "Build the deterministic recording and sanitization kit",
    "1475-1531",
    "Prepare the frozen recording commands, deterministic transcript generator, frame-by-frame sanitizer, secret canaries, checksum manifest, and public-document scaffolding before the operator records a real cast.",
    ["The kit is reproducible from the qualified bundle and seeded secrets are detected without fabricating or altering evidence."],
    ["Frozen script, sanitizer tests, transcript fixture, canary results, and kit checksum."],
    cluster="J",
    priority=1,
    tier="tier-2",
    parent="j-gcp-vertex-demo",
    depends_on=["j-g6-clean-sha-qualification"],
)
for slug, title, existing_id, scope in [
    (
        "j-site-ybc-route-foundation",
        "Reuse the live crawlable-route foundation",
        "durakovic-ai-ybc",
        "Map the in-progress ybc crawlable-route architecture as the prerequisite for S0 without duplicating or stealing its active ownership.",
    ),
    (
        "j-site-shared-analytics-foundation",
        "Reuse shared analytics and UTM readiness",
        "durakovic-ai-6s0",
        "Map the shared free Cloudflare analytics and UTM infrastructure as a required L0 readiness input, adding only oraclemcp-specific events later.",
    ),
    (
        "j-site-campaign-order-foundation",
        "Preserve the existing rust-oracledb campaign order",
        "durakovic-ai-6p5",
        "Map the current rust-oracledb launch gate so the oraclemcp reveal retains its established campaign order unless the operator records an explicit rewire.",
    ),
    (
        "j-site-distribution-foundation",
        "Reconcile the shared post-launch distribution task",
        "durakovic-ai-c64",
        "Map c64 so its rust-oracledb distribution edge is preserved while any overlapping oraclemcp directory scope is reconciled before L5.",
    ),
    (
        "j-site-directory-foundation",
        "Reuse the sole oraclemcp MCP-directory task",
        "durakovic-ai-2e9",
        "Map 2e9 as the sole oraclemcp MCP-directory owner and prevent L5 from creating a third overlapping directory campaign.",
    ),
]:
    add(
        slug,
        "site",
        title,
        "3331-3353",
        scope,
        ["The live site Bead is re-read after G7, remains owned in place, and its existing product-specific dependencies are preserved."],
        ["Accepted G7 checksum, live Bead JSON, owner acknowledgement, and zero-cycle site graph."],
        cluster="J",
        priority=1,
        tier="process",
        parent="j-site-wave2-owner",
        promotion="defer",
        existing_id=existing_id,
        condition=wave2_condition,
    )

add(
    "j-s3-production-deploy",
    "site",
    "Approve and verify the production oraclemcp route",
    "2134-2163",
    "After local and Cloudflare preview gates, obtain explicit production-deploy approval and verify the live route, canonical behavior, asset MIME types, preview noindex separation, and accepted evidence checksum.",
    ["Production is not mutated before approval and deployed HTML matches the accepted G7 evidence checksum."],
    ["Approval record, production URL, route and MIME checks, HTML checksum, and noindex comparison."],
    cluster="J",
    priority=1,
    tier="operator-gated",
    parent="j-site-wave2-owner",
    depends_on=["j-s3-browser-deployment-gates"],
    operator_gate="production-deploy",
    promotion="defer",
    condition=wave2_condition,
)
add(
    "g-driver-085-release-finalization",
    "driver",
    "Tag and publish exactly driver 0.8.5",
    "4843-4885",
    "Aggregate the patch-safe driver fixes and their discriminating verification, consume a fresh exact-SHA live matrix, run every required local and release qualification gate, and stop for operator authorization before the immutable v0.8.5 tag or crates.io publish.",
    [
        "The candidate is exactly 0.8.5, every declared patch child and hard release gate is green at one SHA, cargo-semver-checks reports no forbidden API change, and tag/publish occur only after explicit operator approval."
    ],
    ["Exact-SHA qualification bundle, fresh live matrix, SemVer report, operator approval, release run, tag, and crates.io evidence."],
    cluster="G",
    issue_type="epic",
    priority=0,
    tier="operator-gated",
    depends_on=[
        "d-driver-rq-prep-mode",
        "d-driver-fresh-live-matrix",
        "d-driver-main-matrix-evidence-reuse",
        "d-driver-gate-honesty",
        "f-driver-bughunt-fixes",
        "f-driver-dc1-arrow-tstz-offset",
        "f-driver-dc2-dsn-cert-dn-pin",
        "f-driver-py1-number-scale-type",
        "f-driver-py2-decimal-exact-bind",
        "f-driver-dc3-dsn-dn-match-off",
        "f-driver-py3-bigint-exact-bind",
        "f-driver-py4-detach-blocking-io",
        "f-driver-dc4-configured-tls-timeout",
        "f-driver-dc5-py5-subsecond-offsets",
        "f-driver-dc6-arrow-number-sentinel",
        "f-driver-pr1-bind-name-lone-quote",
        "f-driver-dk1-dk2-pool-lifecycle",
        "f-driver-retry-leading-comment-contract",
        "f-driver-4sfc-tls-error-classification",
        "f-driver-s0se-tls-close-notify",
        "g-driver-live-nightly-green-streak",
        "h-driver-conformance-value-wire-parity",
        "h-driver-security-clamp-fallback-matrix",
        "h-driver-error-path-matrix",
    ],
    operator_gate="release",
)
add(
    "g-driver-085-release-qualification",
    "driver",
    "Qualify the complete driver 0.8.5 patch scope",
    "4843-4885",
    "Autonomously assemble and verify the complete non-GCP engineering-program scope for rust-oracledb at one exact 0.8.5 candidate SHA, including all code, docs, CI, tracker, testing, and cross-repository evidence inputs, without tagging or publishing.",
    [
        "Every promoted non-GCP driver task is terminal, every deferred specification has its explicit disposition, all required local/live/SemVer gates are green at one SHA, and the candidate is exactly patch-legal 0.8.5."
    ],
    ["Complete task closure ledger, exact-SHA Required and live evidence, cargo-semver-checks report, and non-publishing release dry run."],
    cluster="G",
    priority=0,
    tier="tier-3",
)
add(
    "g-server-091-release-finalization",
    "server",
    "Tag and publish exactly server 0.9.1",
    "4843-4885",
    "Aggregate the patch-safe server fixes and verification, consume the published driver 0.8.5 checksum and exact-SHA release rehearsal, run required local and release gates, and stop for operator authorization before the immutable v0.9.1 tag, registries, images, or release assets.",
    [
        "The candidate is exactly 0.9.1, every declared patch child and hard release gate is green at one SHA, cargo-semver-checks reports no forbidden API change, and tag/publish occur only after explicit operator approval."
    ],
    ["Exact-SHA qualification bundle, driver handoff, rehearsal, SemVer report, operator approval, release run, tag, registry, image, and asset evidence."],
    cluster="G",
    issue_type="epic",
    priority=0,
    tier="operator-gated",
    depends_on=[
        "b-server-pretag-release-rehearsal",
        "d-server-exact-sha-tag-gate-reuse",
        "d-server-gate-honesty",
        "f-server-bughunt-fixes",
        "f-server-di1-terminal-held-effects",
        "f-server-met-bounded-tool-labels",
        "f-server-di2-di5-dispatch-input-consistency",
        "f-server-di4-token-prune-oldest",
        "f-server-db1-db4-value-fidelity",
        "f-server-db2-db3-bind-recovery",
        "f-server-cc1-cc2-core-concurrency",
        "f-server-g1-vector-batch-normalization",
        "f-server-au1-au4-audit-hardening",
        "f-server-cf2-prose-ocid-redaction",
        "f-server-cf3-doctor-atomic-replace",
        "f-server-yb7m-descriptor-timeout",
        "f-server-vzui-windows-durable-state",
        "g-server-he7t-iam-subject-mapping",
        "g-server-typed-scn-capability",
        "g-server-lane-health-dashboard",
        "h-server-db-type-fidelity-tstz-vector",
        "h-server-apply-path-invariants",
        "h-server-error-path-matrix",
        "h-server-local-log-redaction",
    ],
    handoffs=[
        handoff(
            "g-driver-085-release-finalization",
            "Published driver 0.8.5 exact-tag and crates.io checksum",
        )
    ],
    operator_gate="release",
)
add(
    "g-server-091-release-qualification",
    "server",
    "Qualify the complete server 0.9.1 patch scope",
    "4843-4885",
    "Autonomously assemble and verify the complete non-GCP engineering-program scope for oraclemcp at one exact 0.9.1 candidate SHA, including OCI Always-Free acceptance, code, docs, CI, tracker, testing, and cross-repository evidence inputs, without tagging or publishing.",
    [
        "Every promoted non-GCP server task is terminal, every deferred specification has its explicit disposition, all required local/live/OCI/SemVer gates are green at one SHA, and the candidate is exactly patch-legal 0.9.1."
    ],
    ["Complete task closure ledger, exact-SHA Required/live/OCI evidence, cargo-semver-checks report, and non-publishing release dry run."],
    cluster="G",
    priority=0,
    tier="tier-3",
    handoffs=[
        handoff(
            "g-driver-085-release-qualification",
            "Accepted complete driver 0.8.5 qualification checksum",
        )
    ],
)


def task_by_slug(slug: str) -> dict[str, Any]:
    matches = [task for task in tasks if task["slug"] == slug]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one normalized task for {slug!r}, found {len(matches)}")
    return matches[0]


def amend(
    slug: str,
    *,
    sources: list[str] | None = None,
    scope: str | None = None,
    scope_addition: str | None = None,
    acceptance: list[str] | None = None,
    acceptance_additions: list[str] | None = None,
    evidence: list[str] | None = None,
    evidence_additions: list[str] | None = None,
    dependencies: list[str] | None = None,
    remove_dependencies: list[str] | None = None,
    handoff_additions: list[dict[str, str]] | None = None,
    lineage_additions: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    task = task_by_slug(slug)
    for source in sources or []:
        source_ref = f"{PLAN}:{source}"
        if source_ref not in task["source_refs"]:
            task["source_refs"].append(source_ref)
    if scope is not None:
        task["scope"] = scope
        task["description"] = (
            f"Reconciled normalized scope for {slug}. {scope} Preserve repository safety, "
            "exact-SHA evidence, and fail-closed behavior."
        )
    if scope_addition is not None:
        task["scope"] = f"{task['scope']} {scope_addition}"
        task["description"] = f"{task['description']} Reconciliation: {scope_addition}"
    if acceptance is not None:
        task["acceptance_criteria"] = acceptance
    for item in acceptance_additions or []:
        if item not in task["acceptance_criteria"]:
            task["acceptance_criteria"].append(item)
    if evidence is not None:
        task["evidence"] = evidence
    for item in evidence_additions or []:
        if item not in task["evidence"]:
            task["evidence"].append(item)
    for dependency in remove_dependencies or []:
        task["depends_on"] = [item for item in task["depends_on"] if item != dependency]
    for dependency in dependencies or []:
        if dependency not in task["depends_on"]:
            task["depends_on"].append(dependency)
    for item in handoff_additions or []:
        if item["task"] not in {existing["task"] for existing in task["handoffs"]}:
            task["handoffs"].append(item)
    if lineage_additions:
        task.setdefault("lineage", [])
        for item in lineage_additions:
            if item not in task["lineage"]:
                task["lineage"].append(item)
    return task


# A — exact source ownership and completed-versus-continuing reuse semantics.
amend(
    "a-server-ignore-agent-state",
    sources=["4085-4089", "4198-4205"],
    scope=(
        "Ignore .codex/ and codex.mcp.json, expose deliberate tracked performance logs with an explicit tests/artifacts log allowlist, and add .ruff_cache only if recurrence is verified; never hide committed evidence broadly."
    ),
    acceptance=[
        "Agent-local state is ignored, intended evidence logs remain visible, .ruff_cache has a recorded recur-or-not decision, and no broad evidence-hiding pattern is introduced."
    ],
)
amend(
    "a-driver-ignore-agent-state",
    sources=["4206-4211"],
    scope=(
        "Ignore driver-local .claude/ and .ntm/ state plus generated tests/artifacts/version_matrix/versions-*.json evidence while preserving committed exact-SHA evidence and the clean-room reference boundary."
    ),
    acceptance=[
        "Positive ignore probes cover all generated agent and matrix paths while negative probes prove committed exact-SHA evidence remains visible."
    ],
)
for slug in [
    "a-close-driver-084-release",
    "a-close-server-090-release",
    "a-close-server-084-repin",
    "a-close-server-090-qualification",
    "a-close-server-asupersync-039",
    "a-close-server-adb-sni",
]:
    task_by_slug(slug)["reuse_action"] = "record-complete"

# B — reconcile shipped foundations, the superseded projection decision, and
# the live-nightly mechanism/evidence split.
amend(
    "b-driver-required-proof-parallel",
    scope_addition="Modify scheduling around the shipped required-proof/v1 producer rather than replacing its exact-SHA, independently executed contract.",
    lineage_additions=[
        {"id": "rust-oracledb-evidence-controls-f1cl.2", "relation": "extends"}
    ],
)
amend(
    "b-driver-live-matrix-parallel-start",
    scope_addition="Extend the exact-SHA Free23 and live evidence already shipped by c23g.4; do not recreate its qualification semantics.",
    lineage_additions=[
        {"id": "rust-oracledb-driver-next-release-c23g.4", "relation": "extends"}
    ],
)
quality_projection = amend(
    "b-server-quality-projection-relocation",
    scope=(
        "Correct and supersede the prior triggerless-retention close after the retro observed eleven no-job failures, then move _quality.yml outside .github/workflows and update the fail-closed parser and tests atomically."
    ),
    acceptance=[
        "The original close is explicitly corrected, GitHub workflow discovery no longer sees the projection, and required-local parsing still fails closed on missing or drifted data."
    ],
)
quality_projection.update(
    promotion="reuse",
    existing_id="oraclemcp-bqna",
    reuse_action="reopen-correct",
)
amend(
    "b-driver-powerset-disk-assert",
    sources=["4281-4285"],
    scope=(
        "Extend the shipped resource harness with one reusable real-disk free-space and write/read canary invoked by powerset and build-heavy jobs before compilation, covering EDQUOT, low-space, unwritable, and healthy cases."
    ),
    lineage_additions=[
        {"id": "rust-oracledb-evidence-controls-f1cl.9", "relation": "extends"},
        {"id": "rust-oracledb-56rf", "relation": "extends"},
    ],
)
amend(
    "b-driver-live-advisory-autoreblock",
    acceptance=[
        "Red, infrastructure skip, and green streak are machine-distinct; state-machine fixtures prove that the third consecutive green re-arms the gate and any interruption resets the streak."
    ],
    evidence=["State-machine fixtures, visible advisory-state output, and deterministic third-green re-arm proof."],
)
amend(
    "b-server-release-surface-runbook",
    sources=["4784-4794"],
    scope=(
        "Retain the shipped manifest-driven version writer and candidate verifier; add only the C9 same-tag pre-publish retry message, field-to-found-to-expected diagnostics, and binary warning/headroom ratchet without a second schema or writer."
    ),
    lineage_additions=[
        {"id": "oraclemcp-evidence-controls-yg4x.4", "relation": "extends"},
        {"id": "oraclemcp-evidence-controls-yg4x.3", "relation": "extends"},
    ],
)
amend("b-server-pretag-release-rehearsal", dependencies=["b-server-quality-projection-relocation"])

# C — preserve destructive gates while making safe moves and stale architectural
# decisions explicit.
amend(
    "c-server-git-state-janitor",
    sources=["4165-4176", "4185-4195"],
    dependencies=["a-close-server-090-release"],
)
amend(
    "c-driver-git-state-janitor",
    sources=["4165-4176", "4185-4195"],
    dependencies=["a-close-driver-084-release"],
)
amend(
    "c-server-disk-prune",
    sources=["4165-4178"],
    acceptance_additions=[
        "Idle-process proof precedes any approved deletion, and infra, web dependencies, todelete, tracker truth, and non-regenerable evidence are preserved."
    ],
)
amend(
    "c-server-doc-layout-normalization",
    sources=["4179-4182"],
    dependencies=["a-server-ignore-agent-state"],
)
task_by_slug("c-server-doc-layout-normalization")["operator_gate"] = "destructive"
task_by_slug("c-server-doc-layout-normalization")["tier"] = "operator-gated"
amend(
    "c-server-tracked-residue-retirement",
    scope_addition="This is residual tracked npm/ source cleanup after 6p3t; the deliberate refusal workflow and already-retired release validation remain intact.",
    lineage_additions=[{"id": "oraclemcp-6p3t", "relation": "extends"}],
)
amend(
    "c-driver-doc-layout-normalization",
    sources=["4179-4182"],
    dependencies=["a-driver-ignore-agent-state"],
)
task_by_slug("c-driver-doc-layout-normalization")["operator_gate"] = "destructive"
task_by_slug("c-driver-doc-layout-normalization")["tier"] = "operator-gated"
amend(
    "c-demono-epic",
    sources=["4165-4183"],
    dependencies=["c-server-doc-layout-normalization"],
    lineage_additions=[{"id": "oraclemcp-8fc.4", "relation": "supersedes"}],
)
for slug in [
    "c-demono-db-connection",
    "c-demono-guard-classifier",
    "c-demono-main",
    "c-demono-core-lane",
    "c-demono-service-lifecycle",
    "c-demono-core-doctor",
    "c-demono-http-operator",
]:
    amend(slug, dependencies=["c-demono-dispatch-mod", "c-demono-web-app"])
amend(
    "c-demono-db-connection",
    scope=(
        "Split connection.rs only after the prerequisite seam decision explicitly supersedes the single-file contract, atomically migrating the driver-seam allowlist, pin test, driver-value boundary, and embedded connection, cancellation, recovery, and live tests."
    ),
    dependencies=["c-demono-db-connection-seam-decision"],
    acceptance=[
        "The prior decision is explicitly superseded, no adapter path escapes the reviewed allowlist, public behavior and API remain unchanged, and every migrated test still exercises the real seam."
    ],
)
task_by_slug("c-demono-db-connection")["operator_gate"] = "operator-input"
task_by_slug("c-demono-db-connection")["tier"] = "operator-gated"
amend(
    "c-demono-http-operator",
    scope_addition="Keep every new HTTP source visible to the nonrecursive dashboard scanner through flat modules or an atomic scanner migration, preserving tests.rs include contracts and all pinned security text.",
    lineage_additions=[
        {"id": "oraclemcp-demonolith-http-qyqs.4", "relation": "extends"},
        {"id": "oraclemcp-w8sp", "relation": "extends"},
        {"id": "oraclemcp-kfd8", "relation": "extends"},
    ],
)
amend(
    "c-explicit-preservation-decisions",
    sources=["4119-4121", "4125-4147", "4162-4163"],
    scope_addition="Also preserve API baselines, ADRs, conformance and provenance registers, the ignored clean-room reference checkout, and the deliberately reversed a7b semantics.",
)

# D — every Tranche-2/3 task is downstream of its complete first tranche, and
# shipped evidence-control foundations are extended rather than rebuilt.
for task in tasks:
    if "cluster-d" not in task["labels"] or task["promotion"] == "record-only":
        continue
    sentinel = (
        "b-server-tranche-1-complete"
        if task["repo"] == "server"
        else "b-driver-tranche-1-complete"
    )
    if sentinel not in task["depends_on"]:
        task["depends_on"].append(sentinel)

amend(
    "d-driver-quality-fanout",
    scope_addition="Extend the shipped required-proof/v1 producer and preserve all caller profile, budget, exact-SHA, and fail-closed parser contracts.",
    lineage_additions=[
        {"id": "rust-oracledb-evidence-controls-f1cl.2", "relation": "extends"}
    ],
)
amend(
    "d-driver-fresh-live-matrix",
    acceptance_additions=[
        "The scheduled producer may be advisory, but release qualification remains a hard consumer of a fresh green exact-SHA matrix artifact."
    ],
)
amend(
    "d-server-fast-pregate",
    sources=["4439-4442"],
    acceptance_additions=[
        "Server publish ordering and main-branch cancel-in-progress false remain unchanged while push feedback stays under the target."
    ],
)
for repo in ("server", "driver"):
    foundation = (
        "oraclemcp-evidence-controls-yg4x"
        if repo == "server"
        else "rust-oracledb-evidence-controls-f1cl"
    )
    amend(
        f"d-{repo}-mutation-integrity",
        sources=["5395-5395"],
        scope=(
            "Extend the shipped mutation-result schema and bounded resource harness with per-mutant caps, OOM-continue classification, witnessed-kill versus timeout or unviable outcomes, survivor triage, and a deterministic exact-SHA seal; do not recreate shipped schema work."
            + (" Expand governed scope to core, db, and dispatch after the guard." if repo == "server" else "")
        ),
        dependencies=[f"h-{repo}-evidence-controls-foundation"],
        lineage_additions=[
            {"id": f"{foundation}.7", "relation": "extends"},
            {"id": f"{foundation}.9", "relation": "extends"},
        ],
    )
    amend(
        f"d-{repo}-coverage-ratchet",
        sources=["5394-5394"],
        scope_addition="Generate a baseline only through the enforced resource wrapper on an idle host or larger runner; never start blindly on a loaded machine. Gate changed-line coverage plus a named negative invariant and per-crate mutation floor, while global percentage remains trend-only.",
        dependencies=[f"h-{repo}-evidence-controls-foundation"],
        lineage_additions=[
            {"id": f"{foundation}.7", "relation": "extends"},
            {"id": f"{foundation}.9", "relation": "extends"},
        ],
    )
amend(
    "d-server-optional-ci-efficiency",
    scope=(
        "Conditionally repackage the attested musl binary, trim fetch depth only where ancestry is unused, and add actionlint; retain provenance and adopt only measured positive timing changes."
    ),
    lineage_additions=[{"id": "oraclemcp-h3xz", "relation": "extends"}],
)
amend(
    "d-driver-optional-ci-efficiency",
    lineage_additions=[{"id": "rust-oracledb-56rf", "relation": "extends"}],
)

# E — binding Charter ground truth and reusable orchestration mechanics.
for slug in ("e-server-charter-v2", "e-driver-charter-v2"):
    amend(
        slug,
        sources=["4358-4359", "4435-4438"],
        scope_addition="Land the complete twelve-rule constitution, O1/O8 safeguards, externalized-progress rule, and graded isolation policy in tracked AGENTS.md ground truth.",
    )
orchestration = amend(
    "e-orchestration-controls",
    scope=(
        "Reactivate the existing orchestration-control task and close its full durable contract: capacity admission, acknowledgement hash, first-deliverable deadline, PID/log/result capture, clean-HEAD landing gate, hot-file ownership ledger, watchdog, and durable orders."
    ),
    acceptance=[
        "Every original 3748 requirement has executable proof and no parallel orchestration umbrella duplicates or weakens it."
    ],
)
orchestration["type"] = "task"
orchestration["reuse_action"] = "reactivate"
amend(
    "e-ntm-charter-orders-templates",
    sources=["4435-4438"],
    scope_addition="Own durable acknowledgement hash, deadline, PID, log, result, hot-file ownership, clean-HEAD landing, watchdog, and disabled-tool fallthrough fields in the tracked templates.",
)
amend(
    "e-server-worktree-lifecycle",
    acceptance=[
        "Shared-tree work remains allowed for at most two or three agents on disjoint reserved domains, build-heavy swarms with more than two Cargo builders require isolated worktrees, and lifecycle leaves no stale worktree or forked tracker."
    ],
    lineage_additions=[
        {"id": "oraclemcp-gctl", "relation": "extends"},
        {"id": "oraclemcp-evidence-controls-yg4x.9", "relation": "extends"},
    ],
)
amend(
    "e-driver-worktree-lifecycle",
    scope_addition="Preserve the same graded shared-tree policy, keep the clean-room reference untouched, and reuse the driver's resource harness and disk preflight.",
    dependencies=["b-driver-powerset-disk-assert"],
    lineage_additions=[
        {"id": "rust-oracledb-56rf", "relation": "extends"},
        {"id": "rust-oracledb-evidence-controls-f1cl.9", "relation": "extends"},
    ],
)
amend(
    "e-server-build-lease",
    lineage_additions=[
        {"id": "oraclemcp-gctl", "relation": "extends"},
        {"id": "oraclemcp-evidence-controls-yg4x.9", "relation": "extends"},
    ],
)
amend(
    "e-driver-build-lease",
    scope=(
        "Enforce the configured Agent Mail build-slot ceiling, currently two and contract-tested, plus four-job Cargo limits, TasksMax, ulimit safeguards, and scoped iteration through an unbypassable entrypoint."
    ),
    lineage_additions=[
        {"id": "rust-oracledb-56rf", "relation": "extends"},
        {"id": "rust-oracledb-evidence-controls-f1cl.9", "relation": "extends"},
    ],
)
amend(
    "e-tracker-close-integrity",
    scope_addition="Extend the shipped close-evidence audit and mutation-race foundations rather than rebuilding them.",
    lineage_additions=[
        {"id": "oraclemcp-evidence-controls-yg4x.5", "relation": "extends"},
        {"id": "oraclemcp-evidence-controls-yg4x.7", "relation": "extends"},
    ],
)
amend(
    "e-tracker-audit-integrity",
    scope_addition="Extend the historical real close-evidence audit with pagination, UTC, all-status, command-position, umbrella, and JSON ID-capture rules.",
    lineage_additions=[
        {"id": "oraclemcp-evidence-controls-yg4x.5", "relation": "extends"}
    ],
)
amend(
    "e-driver-tracker-adoption",
    lineage_additions=[
        {"id": "rust-oracledb-evidence-controls-f1cl.5", "relation": "extends"},
        {"id": "rust-oracledb-evidence-controls-f1cl.7", "relation": "extends"},
    ],
)

# F/G — reconcile live predecessor decisions and keep patch work behind the
# Charter-v2 swarm gate.
amend(
    "f-driver-dc1-arrow-tstz-offset",
    scope=(
        "Adjudicate the later instant-preserving Arrow TSTZ claim against etib.1's intentional upstream wall-clock parity contract, then implement only the evidence-selected behavior with decoder-produced metamorphic coverage and a parity-ledger update."
    ),
    acceptance=[
        "The chosen contract is explicit and tested; the task may close with the prior decision upheld when evidence rejects the proposed offset addition."
    ],
    dependencies=["f-driver-dc1-prior-arrow-contract"],
)
amend(
    "f-server-au1-au4-audit-hardening",
    dependencies=["h-server-versioned-contract-migrations"],
)
amend(
    "g-server-adk-compat-fixes",
    scope_addition="Map any real patch-safe compatibility fix through j-g2-blocking-defect-gate and a confirmed defect-specific G2F child; never close an empty feature shell.",
)

# H — complete the V-series and surgical-test mapping without claiming coverage
# that belongs to the other repository.
amend(
    "h-surgical-regressions-absorbed",
    scope=(
        "Map every section 30.4 addition exactly once: F owns BOOLEAN, DI1, metric cardinality, DC1, DC2/DC3, CC1, and AU1; h-server-db-type-fidelity-tstz-vector owns zoned TSTZ and VECTOR; concrete H fuzz, model, config, OAuth, and verifier tasks own the remaining items."
    ),
    acceptance=[
        "All eleven surgical additions have an exact owning slug and discriminating assertion, with no disappearance or duplicate implementation."
    ],
)
amend(
    "h-v6-v7-v10-charter-mapping",
    scope=(
        "Prove the server Charter and tracker work carries V6 verified file-and-line premises, V7 no flake closure from a negative reproduction, and V10 empirical toolchain and documentation checks."
    ),
    dependencies=["e-tracker-audit-integrity"],
)
amend(
    "h-server-tier-manifest",
    scope_addition="Move the full Free23 live-database and VECTOR lane to Tier 2 while retaining a narrow, explicitly defined 23ai pull-request smoke.",
)
driver_tier = task_by_slug("h-driver-tier-manifest")
driver_tier["scope"] = (
    "Extend the existing ci-taxonomy data with required or advisory state, owner, retries, platform, features, secrets, release-blocking, and tier; represent and correct pyshim pull-request coverage and fuzz-compile status explicitly without assigning the server's Free23 lane to this repository."
)
driver_tier["description"] = (
    "Reconciled driver tier-manifest scope. " + driver_tier["scope"]
)

# Completed foundations are context-only; active product fixes continue in place.
for slug in [
    "f-driver-dc7-session-u16-adjudication",
    "h-driver-evidence-controls-foundation",
    "h-server-evidence-controls-foundation",
    "i-oci-auth-smoke-foundation",
]:
    task_by_slug(slug)["reuse_action"] = "record-complete"

amend(
    "i-oci-capability-sweep",
    scope=(
        "Across isolated synthetic roles and connections, prove the exact READ_ONLY to READ_WRITE to DDL to ADMIN ladder, preview and confirmation token, TTL and profile ceiling, single-use grants, held execution, default rollback, explicit commit postconditions, dictionary and source tools, LOB, VECTOR, NUMBER, zoned TSTZ, BOOLEAN, INTERVAL, audit verify and anchor, doctor, and typed refusals."
    ),
    acceptance=[
        "Every capability has an exact value or postcondition; grants are single-use and ceiling-bounded, rollback and commit are distinct, and no auth-smoke result is relabelled as full proof."
    ],
    dependencies=["h-server-db-type-fidelity-tstz-vector"],
)

# J Wave 1 — keep local scaffolding autonomous, isolate paid Gemini calls, and
# preserve a separate operator recording acceptance.
amend(
    "j-g2-stdio-schema-audit",
    scope=(
        "Pin the official ADK stack and complete the local client scaffolding, stdio lifecycle, full-catalog schema conversion, locally constructed structured-refusal and recovery fixtures, and machine and human matrix before any paid Gemini call."
    ),
    acceptance=[
        "Local lifecycle, catalog, schema conversion, refusal, recovery, and shutdown are auditable without Vertex, a custom client, or direct Oracle access."
    ],
)
g3 = amend(
    "j-g3-oracle-fixture-profile",
    dependencies=["j-g2-blocking-defect-gate"],
)
g3["operator_gate"] = "none"
g3["tier"] = "tier-2"
g4 = task_by_slug("j-g4-adk-example-package")
g4["operator_gate"] = "none"
g4["tier"] = "tier-2"
g5 = amend(
    "j-g5-three-beat-evidence-runner",
    scope=(
        "Implement the deterministic three-beat assertion runner, evidence-v1 normalization, structural tool-call checks, postconditions, audit verification, checksums, budgets, and seeded negative fixtures entirely offline before live qualification."
    ),
    acceptance=[
        "Changed expected read, false allow, model-only refusal, missing audit proof, or malformed event fixtures cause nonzero exit without making a paid call."
    ],
)
g5["operator_gate"] = "none"
g5["tier"] = "tier-2"
amend(
    "j-g6-clean-sha-qualification",
    dependencies=["j-g5-live-three-beat-qualification"],
    remove_dependencies=["j-g5-three-beat-evidence-runner"],
)
amend(
    "j-g7-recording-public-docs",
    dependencies=["j-g7-recording-kit"],
    remove_dependencies=["j-g6-clean-sha-qualification"],
)

# J Wave 2 — remain checksum-deferred and map every existing site owner without
# mutating the site tracker before G7 acceptance.
wave2_owner = task_by_slug("j-site-wave2-owner")
wave2_owner["existing_id"] = "durakovic-ai-oou"
for slug in [
    "j-site-ybc-route-foundation",
    "j-site-shared-analytics-foundation",
    "j-site-campaign-order-foundation",
    "j-site-distribution-foundation",
    "j-site-directory-foundation",
]:
    task_by_slug(slug).pop("parent", None)
amend(
    "j-s0-route-reconcile",
    dependencies=["j-site-ybc-route-foundation"],
    handoff_additions=[
        handoff("j-g7-recording-public-docs", "Accepted G7 site-input artifact checksum")
    ],
)
amend(
    "j-v0-freeze-video-brief",
    handoff_additions=[
        handoff("j-g7-recording-public-docs", "Accepted G7 video-input artifact checksum")
    ],
)
amend(
    "j-lf-claim-lock",
    handoff_additions=[
        handoff("j-g7-recording-public-docs", "Accepted G7 fact-sheet evidence checksum")
    ],
)
s3 = amend(
    "j-s3-browser-deployment-gates",
    scope=(
        "Run Bun and Playwright gates across browsers, viewports, no-JS, keyboard, and reduced motion; verify waterfall, asset budgets, a non-master Cloudflare preview, preview noindex, direct route, MIME, canonical behavior, and preview checksum without production mutation."
    ),
    acceptance=[
        "No critical accessibility or layout issue remains, direct preview refresh works, preview noindex is present, and no production deployment occurs in this task."
    ],
)
s3["operator_gate"] = "none"
s3["tier"] = "tier-2"
amend(
    "j-l0-launch-readiness",
    dependencies=[
        "j-s3-production-deploy",
        "j-site-shared-analytics-foundation",
        "j-site-campaign-order-foundation",
    ],
    remove_dependencies=["j-s3-browser-deployment-gates"],
)
amend(
    "j-l5-follow-up-distribution",
    scope=(
        "After primary launch, reconcile through the mapped c64 and sole 2e9 directory owners, preserve c64's rust-oracledb edge, and add only nonduplicative approved newsletters or optional media distribution."
    ),
    dependencies=["j-site-distribution-foundation", "j-site-directory-foundation"],
)
for slug, tier in {
    "j-s0-route-reconcile": "tier-2",
    "j-s1-static-content-metadata": "tier-2",
    "j-s2-real-terminal-verification": "tier-2",
    "j-s4-optional-replay": "tier-3",
    "j-v2-compose-master": "tier-2",
    "j-lf-claim-lock": "tier-2",
}.items():
    task_by_slug(slug)["tier"] = tier

# K — parent epics do not confer blockers, so every child carries its measured
# D/H prerequisites directly.
amend(
    "k-server-test-evidence-schema-threat-model",
    dependencies=[
        "d-server-coverage-ratchet",
        "d-server-mutation-integrity",
        "h-server-tier-manifest",
        "h-server-monitor-predicate-delta",
    ],
)
amend(
    "k-server-test-evidence-producer",
    dependencies=[
        "d-server-coverage-ratchet",
        "d-server-mutation-integrity",
        "h-server-tier-manifest",
        "h-server-monitor-predicate-delta",
        "h-server-db-type-fidelity-tstz-vector",
    ],
    remove_dependencies=["h-server-request-span-correlation"],
    handoff_additions=[
        handoff(
            "h-driver-conformance-value-wire-parity",
            "Accepted driver parity-as-of-SHA evidence checksum",
        )
    ],
)
amend(
    "k-driver-test-evidence-producer",
    dependencies=[
        "d-driver-coverage-ratchet",
        "d-driver-mutation-integrity",
        "h-driver-tier-manifest",
        "h-driver-monitor-predicate-delta",
    ],
)
amend(
    "k-server-test-evidence-verifier",
    dependencies=[
        "d-server-coverage-ratchet",
        "d-server-mutation-integrity",
        "h-server-tier-manifest",
        "h-server-monitor-predicate-delta",
    ],
)

amend(
    "g-driver-085-release-finalization",
    scope=(
        "After the complete autonomous 0.8.5 qualification checksum is accepted, stop for operator approval, then create the immutable tag and publish through the normal driver release pipeline; perform no qualification work inside this gated step."
    ),
    acceptance=[
        "The accepted candidate is unchanged, explicit operator approval precedes the v0.8.5 tag and crates.io publish, and immutable release evidence binds the qualified SHA."
    ],
    evidence=[
        "Accepted qualification checksum, operator approval, immutable v0.8.5 tag, release run, and crates.io evidence."
    ],
    dependencies=["g-driver-085-release-qualification"],
)
task_by_slug("g-driver-085-release-finalization")["depends_on"] = [
    "g-driver-085-release-qualification"
]
amend(
    "g-server-091-release-finalization",
    scope=(
        "After the complete autonomous 0.9.1 qualification and published driver 0.8.5 checksums are accepted, stop for operator approval, then create the immutable tag and run the normal server release pipeline; perform no qualification work inside this gated step."
    ),
    acceptance=[
        "The accepted candidate is unchanged, explicit operator approval precedes the v0.9.1 tag and all registry, image, and asset publication, and immutable release evidence binds the qualified SHA."
    ],
    evidence=[
        "Accepted server and published-driver qualification checksums, operator approval, immutable v0.9.1 tag, release run, registries, image, and asset evidence."
    ],
    dependencies=["g-server-091-release-qualification"],
)
task_by_slug("g-server-091-release-finalization")["depends_on"] = [
    "g-server-091-release-qualification"
]

# Tranche 4 is a hard prerequisite for later swarm campaigns. Apply the edge to
# each actionable child because Beads parent-child relationships do not inherit
# blockers. Completed reused foundations remain historical context only.
for task in tasks:
    cluster_labels = {
        label for label in task["labels"] if label in {"cluster-f", "cluster-g", "cluster-h", "cluster-i", "cluster-j", "cluster-k"}
    }
    if not cluster_labels or task["repo"] not in {"server", "driver"}:
        continue
    if task["promotion"] not in {"create", "reuse"}:
        continue
    if task.get("reuse_action") == "record-complete":
        continue
    swarm_gate = "e-server-swarm-ready" if task["repo"] == "server" else "e-driver-swarm-ready"
    if swarm_gate not in task["depends_on"]:
        task["depends_on"].append(swarm_gate)

# The qualification gates cover every actionable non-GCP task in their own
# repository. Operator/cost/destructive tasks may block the closure, but their
# existence never causes autonomous qualification logic to be skipped.
release_slugs = {
    "g-driver-085-release-qualification",
    "g-driver-085-release-finalization",
    "g-server-091-release-qualification",
    "g-server-091-release-finalization",
}
for repo, qualification_slug in (
    ("driver", "g-driver-085-release-qualification"),
    ("server", "g-server-091-release-qualification"),
):
    qualification = task_by_slug(qualification_slug)
    qualification["depends_on"] = sorted(
        task["slug"]
        for task in tasks
        if task["repo"] == repo
        and task["promotion"] in {"create", "reuse"}
        and "cluster-j" not in task["labels"]
        and task["slug"] not in release_slugs
    )


if __name__ == "__main__":
    print(json.dumps(manifest(), indent=2, sort_keys=True))
