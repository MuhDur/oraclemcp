# Running the swarm without git worktrees

**Status:** design draft (2026-10-05), at the operator's request. Based on the Agent Mail author's own tooling and swarm doctrine (the `agent-mail`, `multi-agent-swarm-workflow`, `rch` and `sbh` skills and tools).
**Rule:** no git worktrees of any kind in this repo. They were tried repeatedly and failed every time; in the 2026-10-04 run they cost about half of the Codex budget.

## 1. Why worktrees kept coming back

| # | The need | Where it was written down | Why it pointed to a worktree |
|---|---|---|---|
| A | The gate must test an exact commit with nobody's half-finished edits | the swarm `prepush.sh`/`gate.sh`, which refused a tree with uncommitted changes | A shared checkout always has someone's dirty files |
| B | Close evidence must bind to HEAD without other agents' work (constitution rule 14) | AGENTS.md rule 14 (fixed); `swarm_discipline.sh`; `verify_required_local.py`; docs/required-local-proof.md | These tools refuse a dirty tree and print `git worktree add …` (bead **oraclemcp-cjv4j**) |
| C | Land independently: a commit gated on an old base can't fast-forward | the swarm ORDERS "Throughput rules" (removed) | Agents rebased in private checkouts, which created parallel histories |
| D | Build isolation | build policy | Not a worktree need: per-agent `CARGO_TARGET_DIR` plus the build lease already handle it |
| E | One git index: concurrent commits collide on `index.lock` | observed twice | Separate checkouts have separate indexes |
| F | Reservation conflicts | AGENTS.md "wait for expiry" (fixed) | Private checkouts let agents ignore each other instead of talking |
| G | Planted-fault proofs need a temporarily broken file | verifier practice | They were done in separate copies to keep the shared tree clean |

**Root cause:** the tooling assumed "clean tree" means "a tree only I use". And nothing protected the shared checkout. Agent Mail was used only as an advisory lock, never as a conversation, and its pre-commit guard was never installed.

## 2. What the Agent Mail author does

1. **One shared checkout, no worktrees.** The swarm workflow never uses them; ntm's `--worktrees` is optional and unused. Every agent is interchangeable and works in the same repo.
2. **Agent Mail is a conversation.** The author's marching orders to every agent:
   - register with Agent Mail and **introduce yourself to the other agents**;
   - **check mail and respond promptly**, acknowledging every request;
   - announce each bead on its thread (`[bead] Starting…`, with acknowledgement required) and post progress there;
   - on a conflict, **message the holder and split the file or take turns**;
   - hand off explicitly: a handoff message, then the receiver joins the thread (`macro_prepare_thread`), reserves the files and acknowledges;
   - avoid "communication purgatory": tell the others, then start.
3. **Reservations are enforced by the Agent Mail pre-commit guard** ("Pre-commit guard enforces exclusivity"). `git commit` refuses files that another agent holds exclusively. This is what makes one shared checkout safe.
4. **Committing is its own coordinated phase.** The orchestrator sends "complete current bead, commit, then stop"; then the changes are committed in logical groups and pushed once. Agents review each other's code in review rounds instead of each racing through a private gate.
5. **Build contention is handled by tools:**
   - **rch** offloads cargo builds to remote workers, with locks that keep parallel builds from colliding;
   - **Agent Mail build slots** (`acquire_build_slot`, or `am am-run <slot> -- <cmd>`) serialize long jobs through the same coordination system.
6. **Disk is managed by the sbh daemon** (storage ballast helper), which watches pressure and reclaims build output automatically.

## 3. The design for oraclemcp (no worktrees, no copies)

**3.1 Agent Mail guard (REQUIRED; NOT YET INSTALLED).** The Agent Mail pre-commit guard **must be installed** in `/home/durakovic/projects/oraclemcp` before the next swarm:
- `install_precommit_guard(project_key="/home/durakovic/projects/oraclemcp", code_repo_path="/home/durakovic/projects/oraclemcp")`;
- every agent pane sets `AGENT_NAME=<its Agent Mail name>`;
- verify that a planted commit of a file reserved by another agent is refused.

Operator decision 2026-10-05: write this down, **do not install yet**.

**3.2 Orders.** Use the author's marching-orders block alongside AGENTS.md:
- introduce yourself;
- check and answer mail every turn;
- announce, update and hand off on the bead-id thread;
- on a conflict, message and split instead of waiting.

The orchestrator sends assignments, freezes and rulings as Agent Mail messages (the human-overseer channel gives them high importance). Tmux typing is only a nudge to read the inbox.

**3.3 Commits.**
- Agents commit only their own reserved paths (`git commit -- <paths>`), and the guard enforces it.
- Concurrent commits are serialized by a flock wrapper, so `index.lock` never collides.
- All commits go onto the one local `main`, so history is linear by construction. Nobody rebases.

**3.4 Landing and gate (replaces per-agent gating).**
- Agents post `READY <bead> <sha>` on the Agent Mail `landing` thread.
- On each landing cycle the orchestrator announces a short **landing window** on Agent Mail. Agents finish or commit their in-scope edits, or hold them, and acknowledge.
- The gate runs **in the shared checkout on HEAD**, under the Agent Mail build slot `gate`, then `main` is pushed and the window is released. One gate per batch; agents never re-gate.
- On a failure, bisect the batch and message the owner on the bead thread.

**3.5 Evidence (B).** Bind to HEAD with the scoped clean check (`audit_bead_closes.py --scope` is the model): refuse only if the bead's *own* paths are dirty. Make `swarm_discipline.sh` and `verify_required_local.py` do the same (bead **oraclemcp-cjv4j**).

**3.6 Planted-fault proofs (G).** Run them inside the landing window, or under a reservation on the touched file, in the shared checkout. Plant, run, revert, and verify `git diff` is empty. The author of the bead or the verifier holds the reservation while doing it.

**3.7 Builds and disk.**
- Keep per-agent `CARGO_TARGET_DIR` and the build lease.
- Re-check Agent Mail build slots: `build_lease.sh` says the slot primitive was "disabled server-side", but the server is healthy (v0.3.35). If slots work, use them for the gate.
- Enable rch if remote workers are available.
- Run the **sbh daemon** for disk instead of manual janitor runs. It is installed, but its daemon is not running.

## 4. Done so far (2026-10-05)
- AGENTS.md (uncommitted): rule 14 no longer uses a worktree; new section "No git worktrees"; the Agent Mail section says to message the holder instead of waiting, and to check the inbox every turn.
- Claude memory: hard rule `feedback-no-worktrees-ever`; old worktree guidance deleted.
- Codex memories: worktree prescriptions removed; the no-worktree and Agent Mail-as-conversation rule added (backups in `~/.cache/codex-*.bak-20261005`).
- Bead oraclemcp-cjv4j: remove the worktree mandates from the proof tooling.

## 5. Still to do before the next swarm
1. Install the Agent Mail pre-commit guard (3.1) and verify it.
2. Land bead oraclemcp-cjv4j (proof tooling without worktrees).
3. Write the landing-window and commit-wrapper scripts into `scripts/swarm/`, committed to the repo.
4. Check whether Agent Mail build slots work; start the sbh daemon.
5. Put the author's marching-orders block into the swarm orders template.
