# Swarm recap and fix plan (2026-10-05)

A plain recap of the 2026-10-04/05 oraclemcp swarm: what stalled, where we deviate from the Agent Mail author's tooling, why our agents don't follow it, and the smallest set of changes that fixes it for every project.
**Anti-ceremony rule for this plan:** no new dashboards, ledgers, certificates or checklists. Use the author's tools as he uses them, and delete our substitutes.

## 1. What happened
- About 20 h, 2→3 Codex panes, 13 beads closed (each independently verified), about 85 commits.
- 81 gate runs: 34 full passes, 10 failures, **37 aborted or superseded**.
- About 1 in 3 "done" claims failed independent verification.
- About 3–4 h lost to environment stalls.
- The operator's verdict: too slow. About half the Codex budget was burned on overhead.

## 2. Bottlenecks, stalls and foot-guns (each with its cause)

| # | What | Root cause |
|---|---|---|
| 1 | Half of all gate runs thrown away | Every agent gated its own commit, then main moved and it re-gated. No coordinated commit or landing phase |
| 2 | Parallel commit histories, stale files reverting landed work, 3 manual reconciliations | **Worktrees**: per-agent checkouts and private rebases |
| 3 | Agents idle-waiting on each other's files (3×) | AGENTS.md said "**wait for expiry**", and nobody messaged anybody |
| 4 | Commits colliding on `.git/index.lock`; one stale lock blocked all commits for 1.5 h | No serialized commit; a killed git process left the lock |
| 5 | Codex input failures: `/goal` injection, queued messages not delivered, false "goal achieved", Ctrl-C quitting Codex | **Orchestrator instructions were typed into tmux** instead of sent as Agent Mail messages |
| 6 | The content filter stalled a pane for about 1 h | Security-flavoured wording (fuzzing, DoS) in goals |
| 7 | CI red after green local gates (fuzz lockfiles, W4 lane) | The local gate didn't match CI |
| 8 | Masked CI job hid real failures for days | `continue-on-error` on a job that covers required behaviour |
| 9 | About 1 in 3 "done" claims weren't done (tests that couldn't fail, a fix with no effect) | READY didn't require a planted-fault proof or a compliance-skill pass |
| 10 | Disk climbed to 79% | sbh installed but its daemon off; manual janitor runs instead |
| 11 | Poison in memories and docs | Codex `memory_summary.md` said "use dedicated worktrees". Past orders were stored as "follow by default". AGENTS.md rule 14 said "clean worktree". Proof scripts print `git worktree add`. My own Claude memory prescribed worktrees |

## 3. Where we deviate from the Agent Mail author's tooling

| Author's way | What we did | Effect |
|---|---|---|
| One shared checkout, interchangeable agents | Worktrees per agent and per gate | Divergence, reconciliation, half the budget |
| Agents **introduce themselves**, check mail, **respond promptly**, announce on the bead thread, hand off by message | Agent Mail used only as a file lock; our own 60-line ORDERS.md replaced his short marching-orders prompt | No conversation, so no coordination |
| On a reservation conflict, message the holder and split the file or take turns | "wait for expiry" (in **28 project AGENTS.md files**) | Idle agents |
| **Pre-commit guard** enforces reservations | Not installed in **any** project | The shared checkout was unprotected, so agents fled to worktrees |
| Commit phase: "complete current bead, commit, then stop"; commit in logical groups and push | Every agent pushes through its own 40-minute gate | Gate races, re-gates, aborted runs |
| Builds via **rch** and Agent Mail **build slots** | Home-made `build_lease.sh`, claiming "Agent Mail slots are disabled server-side" (the server is healthy, v0.3.35) | Not checked; our own lock |
| Disk via the **sbh** daemon | Daemon off; manual janitor runs | Disk pressure, manual cleanup |
| Orchestrator talks via Agent Mail (the overseer channel marks messages high priority) | tmux keystrokes | Codex input failures |
| ntm conflict negotiation / inbox nudges | `Conflict negotiate: disabled`; no inbox nudge | Nobody gets reminded to read mail |

## 4. Why our agents don't follow the author
1. **Agents follow whatever they read at session start**: AGENTS.md, Codex `memory_summary.md`, and our orders. All three pointed away from the author's model: wait for expiry, use worktrees, a long custom protocol.
2. **Codex memory turns our past orders into permanent defaults** ("follow this swarm protocol by default"). One bad orchestrator order outlives the run.
3. **Tools contradicted the docs.** Proof scripts refused a shared, dirty tree and printed `git worktree add`, so agents obeyed the tool.
4. **Without the guard, the shared checkout feels unsafe**, which makes private checkouts look rational.
5. **Too much of our own process.** Long ORDERS.md files, custom gates and locks, ledger-like evidence rules. Agents spent effort on our ceremony instead of on the author's simple loop.

## 5. The fix, for every current and future project (minimal)

**A. One machine-wide block in `~/AGENTS.md`.** Codex reads it as a parent of every project, so it reaches all repos at once. About 12 lines:
- no git worktrees, ever;
- on joining: `macro_start_session`, introduce yourself, check and answer mail every turn;
- reserve before editing; on a conflict, message the holder and split the file or take turns, never wait for expiry;
- announce, update and hand off on the bead-id thread;
- commit only your reserved paths; the pre-commit guard enforces it;
- commit and land only when the orchestrator calls a commit phase.

**B. Per repo: one-line fix plus guard.**
- Replace the copied "wait for expiry" line in the 28 project AGENTS.md files.
- Install the Agent Mail pre-commit guard in each repo that runs swarms. **Not yet**: the operator decides when.

**C. Orders = the author's marching-orders prompt, verbatim**, plus only the project specifics: bead, test lab, and "done = planted-fault proof + compliance-skill pass". No 60-line ORDERS.md.

**D. Orchestrator talks via Agent Mail.** Assignments, freezes and rulings go as messages. tmux is only a nudge ("check your inbox"). Turn on ntm conflict negotiation and inbox nudges if the installed ntm supports them.

**E. Commit and land like the author.**
- Commit phase: agents finish, commit their paths, then stop.
- One gate on the tip, in the shared checkout, under an Agent Mail build slot, then push.
- Agents never gate or push individually. This matches the agreed landing queue.

**F. Tools on, homemade substitutes off:**
- start the **sbh** daemon;
- check Agent Mail build slots, and retire `build_lease.sh` if they work;
- enable **rch** if remote workers exist.

**G. Memory hygiene.**
- Codex memories must not store orchestrator orders as defaults.
- After each swarm, grep `~/.codex/memories` and the Claude memory for "worktree" and "wait for expiry".
- Keep the hard rules in AGENTS.md, since Codex can regenerate its own memory files.

**H. Keep what worked:**
- independent verification, plus the beads-compliance-and-completion-verification skill as the close test;
- the guarded close;
- the 4-minute polling ticks (operator decision).

## 6. Leftovers found outside oraclemcp (not yet touched)
- **Linked worktrees still exist:**
  - plsql-intelligence: 4 (`-orch-verify`, `-t102`, `-t103`, `-wt-CreamLeopard`, ~10 GB total)
  - invoices: 7
  - oracle: 1
  - bend: 1 (`bend-verify`)
- The swarm-created one in rust-oracledb was removed (it was clean).
- **Decision needed:** may I remove these (after checking each is clean and its commits are reachable)?

## 7. Needed to establish this (in order)
1. Operator approves the `~/AGENTS.md` block (A) and the 28-repo one-line fix (B).
2. Operator says when to install the pre-commit guard (B).
3. Replace our orders template with the author's prompt (C).
4. Start the sbh daemon; check build slots; check rch (F).
5. Remove the leftover worktrees in other repos (§6), once approved.
6. Land bead oraclemcp-cjv4j: proof tooling without worktrees.
