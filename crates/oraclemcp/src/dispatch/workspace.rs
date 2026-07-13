//! The reversible workspace on the pinned session (Arc I / bead
//! `oraclemcp-epic-09x-alien-6sj8.11.1`).
//!
//! A **checkpoint** is a native Oracle `SAVEPOINT <name>` issued by the server
//! on its own pinned session; **undo** is `ROLLBACK TO SAVEPOINT <name>`. Held
//! statements are ordinary classifier-gated DML run through `oracle_execute`
//! with `hold=true`: instead of the default rollback-preview, the effect stays
//! *pending inside the current transaction* so a later checkpoint/undo can walk
//! it back. The result is a labeled-linear undo stack, not a DAG — Oracle
//! savepoints nest linearly and `ROLLBACK TO SAVEPOINT x` erases every savepoint
//! established after `x`.
//!
//! ## Why the server owns the statement text
//!
//! The classifier **forbids caller-supplied** `COMMIT` / `ROLLBACK` / `SAVEPOINT`
//! ("the server owns commit, rollback, and transaction audit outcomes"), so an
//! agent can never reach these statements through `oracle_execute`. This module
//! is the *governed* way to exercise that ownership: the statement text is a
//! fixed template and the only caller-controlled part is a name validated by
//! [`validated_checkpoint_name`] down to `[A-Za-z][A-Za-z0-9_]{0,29}`. Oracle
//! has no bind placeholder for a savepoint identifier, so that allowlist — not a
//! bind — is the injection boundary, and it is exhaustively tested over the byte
//! space.
//!
//! ## What holds this fail-closed
//!
//! Held DML is uncommitted, and in this increment it can **only** ever be rolled
//! back: while the workspace is open the dispatcher refuses every operation that
//! would end the pinned transaction — an explicit `commit=true`, an implicitly
//! committing DDL/Admin statement, and the diagnostic paths whose cleanup rolls
//! the transaction back (EXPLAIN PLAN / `PLAN_TABLE` cost estimation, flashback
//! reads). Without that rule a held statement could ride a *different*
//! statement's `COMMIT` into permanence without ever passing the single-use
//! grant — the transaction-wide nature of `COMMIT` is exactly the hole the guard
//! must not open. Committing held work needs its own re-classifying gate; that
//! is bead `.11.3`, not this one.
//!
//! The in-memory stack here is the dispatcher's *belief*. Oracle is the ground
//! truth: a `ROLLBACK TO SAVEPOINT` for a savepoint erased by an intervening
//! transaction boundary raises `ORA-01086`, so a stale belief can only ever
//! produce a refusal, never a false "restored". The belief is cleared at every
//! transaction boundary the dispatcher issues.

use std::cell::RefCell;

use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use serde_json::{Value, json};

/// Maximum live checkpoints on one session. Oracle imposes no small limit, but
/// an unbounded agent-driven stack is a memory and legibility hazard; a linear
/// undo stack this deep is already past what an agent can reason about.
pub(crate) const MAX_CHECKPOINTS: usize = 16;

/// Oracle identifiers are limited to 30 bytes on every supported release
/// (11g..23ai); the 128-byte extension does not apply to savepoint names.
const MAX_NAME_BYTES: usize = 30;

/// Savepoint names the *server* reserves for its own sandboxes. An agent that
/// could name a checkpoint `OMCP_PREVIEW` would be able to move or erase the
/// savepoint `oracle_preview_dml` rolls its dry run back to, so the prefix is
/// refused at the door.
const RESERVED_PREFIX: &str = "OMCP_";

/// The savepoint `oracle_preview_dml` brackets its dry run with. It is nested
/// *inside* whatever transaction is running, so rolling back to it restores the
/// exact pre-preview state — including any work the agent is holding above its
/// own checkpoints, which are older and therefore untouched.
pub(crate) const PREVIEW_SANDBOX: &str = "OMCP_PREVIEW_DML";

/// One live checkpoint: a savepoint name plus the number of held statements
/// executed *after* it was established (the work an undo to this checkpoint
/// discards, excluding anything discarded by the checkpoints stacked above it).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Checkpoint {
    name: String,
    held_after: usize,
}

/// What an [`CheckpointWorkspace::undo_to`] would discard, so the dispatch arm
/// can report it truthfully after Oracle accepts the rollback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UndoSummary {
    /// Held statements whose effects the `ROLLBACK TO SAVEPOINT` discards.
    pub(crate) discarded_statements: usize,
    /// Checkpoints Oracle erases because they were established after the target.
    pub(crate) released_checkpoints: Vec<String>,
}

/// The pinned session's reversible workspace: a labeled-linear savepoint stack.
///
/// Interior mutability mirrors [`super::ReadOnlyBackstop`]: the dispatcher
/// serializes every call on this session behind one async mutex and the dispatch
/// future is `!Send`, so `&self` methods need no further synchronization.
#[derive(Debug, Default)]
pub(crate) struct CheckpointWorkspace {
    stack: RefCell<Vec<Checkpoint>>,
}

impl CheckpointWorkspace {
    pub(crate) fn new() -> Self {
        Self {
            stack: RefCell::new(Vec::new()),
        }
    }

    /// Whether any checkpoint is live — i.e. whether the pinned transaction is
    /// carrying an agent-visible undo stack that a transaction boundary would
    /// destroy (and whose held work a `COMMIT` would persist ungranted).
    pub(crate) fn is_open(&self) -> bool {
        !self.stack.borrow().is_empty()
    }

    /// Uncommitted statements currently held across the whole workspace.
    pub(crate) fn held_statements(&self) -> usize {
        self.stack
            .borrow()
            .iter()
            .map(|checkpoint| checkpoint.held_after)
            .sum()
    }

    /// Whether a checkpoint may be established — checked *before* the `SAVEPOINT`
    /// round trip so a refusal never touches the database, and so a failed round
    /// trip cannot leave a phantom checkpoint behind ([`Self::commit_open`]
    /// records it only once Oracle has accepted).
    ///
    /// Duplicate names are refused: re-establishing a name in Oracle silently
    /// *moves* it past the savepoints stacked above it, which would make this
    /// stack — and the agent's mental model of what an undo restores — wrong.
    pub(crate) fn check_can_open(&self, name: &str) -> Result<(), ErrorEnvelope> {
        let stack = self.stack.borrow();
        if stack.iter().any(|checkpoint| checkpoint.name == name) {
            return Err(ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                format!(
                    "checkpoint {name} is already live on this session; re-establishing a savepoint name would move it above the work it is supposed to protect"
                ),
            )
            .with_next_step("choose an unused checkpoint name, or undo to this one first"));
        }
        if stack.len() >= MAX_CHECKPOINTS {
            return Err(ErrorEnvelope::new(
                ErrorClass::PolicyDenied,
                format!("the reversible workspace is capped at {MAX_CHECKPOINTS} live checkpoints"),
            )
            .with_next_step(
                "undo to an earlier checkpoint to release the ones stacked above it, or discard the workspace with oracle_undo_to and no name",
            ));
        }
        Ok(())
    }

    /// Record the checkpoint Oracle just established.
    pub(crate) fn commit_open(&self, name: &str) {
        self.stack.borrow_mut().push(Checkpoint {
            name: name.to_owned(),
            held_after: 0,
        });
    }

    /// Record that one statement's effect is now held (uncommitted) above the
    /// newest checkpoint. Callers must have proven [`Self::is_open`] first; a
    /// closed workspace cannot hold work and silently drops the note.
    pub(crate) fn note_held_statement(&self) {
        if let Some(top) = self.stack.borrow_mut().last_mut() {
            top.held_after += 1;
        }
    }

    /// Plan an undo to `name` *without* mutating: the dispatch arm only commits
    /// the stack truncation once Oracle has accepted the `ROLLBACK TO SAVEPOINT`.
    pub(crate) fn plan_undo_to(&self, name: &str) -> Result<UndoSummary, ErrorEnvelope> {
        let stack = self.stack.borrow();
        let Some(index) = stack.iter().position(|checkpoint| checkpoint.name == name) else {
            return Err(ErrorEnvelope::new(
                    ErrorClass::InvalidArguments,
                    format!("no live checkpoint named {name} on this session"),
                )
                .with_next_step(if stack.is_empty() {
                    "the reversible workspace is closed: establish one with oracle_checkpoint before undoing"
                } else {
                    "call oracle_undo_to with a checkpoint reported by oracle_checkpoint"
                }));
        };
        Ok(UndoSummary {
            discarded_statements: stack[index..]
                .iter()
                .map(|checkpoint| checkpoint.held_after)
                .sum(),
            released_checkpoints: stack[index + 1..]
                .iter()
                .map(|checkpoint| checkpoint.name.clone())
                .collect(),
        })
    }

    /// Apply the undo Oracle just accepted: every checkpoint above `name` is
    /// erased and the work held above `name` is gone. `name` itself survives —
    /// Oracle keeps the savepoint it rolled back to.
    pub(crate) fn commit_undo_to(&self, name: &str) {
        let mut stack = self.stack.borrow_mut();
        if let Some(index) = stack.iter().position(|checkpoint| checkpoint.name == name) {
            stack.truncate(index + 1);
            stack[index].held_after = 0;
        }
    }

    /// Forget every checkpoint. Called at each transaction boundary the
    /// dispatcher issues on the pinned session (commit, rollback, the read-only
    /// backstop re-arming, a workspace discard): Oracle erases all savepoints
    /// there, so keeping them would be a lie.
    pub(crate) fn clear(&self) {
        self.stack.borrow_mut().clear();
    }

    /// The agent-facing view of the workspace, embedded in every tool response
    /// that opens, holds into, or unwinds it.
    pub(crate) fn view(&self) -> Value {
        let stack = self.stack.borrow();
        json!({
            "open": !stack.is_empty(),
            "checkpoints": stack
                .iter()
                .map(|checkpoint| checkpoint.name.as_str())
                .collect::<Vec<_>>(),
            "held_statements": stack
                .iter()
                .map(|checkpoint| checkpoint.held_after)
                .sum::<usize>(),
        })
    }
}

/// Validate an agent-supplied checkpoint name down to a bare Oracle identifier.
///
/// Oracle has no bind placeholder for a savepoint name, so this allowlist is the
/// injection boundary for [`savepoint_statement`] / [`undo_statement`]: a leading
/// ASCII letter followed by ASCII alphanumerics and `_`, at most 30 bytes, folded
/// to upper case (Oracle folds unquoted identifiers anyway, so `sp1` and `SP1`
/// must not be two different checkpoints). Everything else — quotes, whitespace,
/// `;`, `$`, `#`, non-ASCII — is refused.
pub(crate) fn validated_checkpoint_name(raw: &str) -> Result<String, ErrorEnvelope> {
    let name = raw.trim();
    let refuse = |reason: &str| {
        Err(ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("invalid checkpoint name {raw:?}: {reason}"),
        )
        .with_next_step(
            "use a bare Oracle identifier: a letter followed by letters, digits, or underscores, at most 30 characters",
        ))
    };
    if name.is_empty() {
        return refuse("it is empty");
    }
    if name.len() > MAX_NAME_BYTES {
        return refuse("Oracle savepoint names are limited to 30 characters");
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap_or_default();
    if !first.is_ascii_alphabetic() {
        return refuse("it must start with an ASCII letter");
    }
    if let Some(bad) = chars.find(|c| !(c.is_ascii_alphanumeric() || *c == '_')) {
        return refuse(&format!(
            "{bad:?} is not allowed; only ASCII letters, digits, and underscores are"
        ));
    }
    let name = name.to_ascii_uppercase();
    if name.starts_with(RESERVED_PREFIX) {
        return refuse(&format!(
            "the {RESERVED_PREFIX} prefix is reserved for the server's own sandbox savepoints"
        ));
    }
    Ok(name)
}

/// `SAVEPOINT <name>` for a name already through [`validated_checkpoint_name`].
pub(crate) fn savepoint_statement(name: &str) -> String {
    format!("SAVEPOINT {name}")
}

/// `ROLLBACK TO SAVEPOINT <name>` for a validated name.
pub(crate) fn undo_statement(name: &str) -> String {
    format!("ROLLBACK TO SAVEPOINT {name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dispatch arm's two-step sequence: check, issue `SAVEPOINT`, record.
    fn open(workspace: &CheckpointWorkspace, name: &str) -> Result<(), ErrorEnvelope> {
        workspace.check_can_open(name)?;
        workspace.commit_open(name);
        Ok(())
    }

    fn workspace_with(names: &[&str]) -> CheckpointWorkspace {
        let workspace = CheckpointWorkspace::new();
        for name in names {
            open(&workspace, name).expect("checkpoint opens");
        }
        workspace
    }

    #[test]
    fn name_validation_folds_case_and_accepts_bare_identifiers() {
        for (raw, expected) in [
            ("sp1", "SP1"),
            ("  before_patch  ", "BEFORE_PATCH"),
            ("A", "A"),
            ("x9_y", "X9_Y"),
            (&"a".repeat(30), &"A".repeat(30)),
        ] {
            assert_eq!(
                validated_checkpoint_name(raw).expect("valid name"),
                expected,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn name_validation_refuses_every_injection_shaped_name() {
        for raw in [
            "",
            "   ",
            "1sp",
            "_sp",
            "$sp",
            "sp;DROP TABLE t",
            "sp 1",
            "sp'--",
            "\"sp\"",
            "sp\nCOMMIT",
            "sp\tx",
            "sp/*x*/",
            "sp#1",
            "sp$1",
            "spé",
            "sp.x",
            "sp-x",
            // The server's own sandbox savepoints are off limits: an agent that
            // could name this could move or erase the one a dry run rolls back to.
            "omcp_preview_dml",
            "OMCP_anything",
            &"a".repeat(31),
        ] {
            let error = validated_checkpoint_name(raw)
                .expect_err(&format!("{raw:?} must be refused, never interpolated"));
            assert_eq!(error.error_class, ErrorClass::InvalidArguments, "{raw:?}");
        }
    }

    /// The allowlist is the injection boundary, so prove it over the whole byte
    /// space rather than over a hand-picked sample: no accepted name can carry a
    /// character that could terminate or extend the generated statement.
    #[test]
    fn no_accepted_name_can_escape_the_statement_template() {
        for byte in 0..=u8::MAX {
            let candidate = format!("A{}", byte as char);
            let Ok(name) = validated_checkpoint_name(&candidate) else {
                continue;
            };
            // Surrounding whitespace is trimmed, never interpolated, so the
            // invariant is over the *accepted identifier*, not the raw input.
            assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "accepted {candidate:?} and produced {name:?}, which is outside the allowlist"
            );
            for statement in [savepoint_statement(&name), undo_statement(&name)] {
                assert!(
                    statement
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ' '),
                    "generated statement {statement:?} must contain nothing but the template and the identifier"
                );
                assert!(!statement.contains("  "), "{statement:?}");
            }
        }
    }

    #[test]
    fn statements_are_fixed_templates() {
        assert_eq!(savepoint_statement("SP1"), "SAVEPOINT SP1");
        assert_eq!(undo_statement("SP1"), "ROLLBACK TO SAVEPOINT SP1");
    }

    #[test]
    fn a_fresh_workspace_is_closed() {
        let workspace = CheckpointWorkspace::new();
        assert!(!workspace.is_open());
        assert_eq!(workspace.held_statements(), 0);
        assert_eq!(workspace.view()["open"], json!(false));
    }

    #[test]
    fn opening_a_checkpoint_opens_the_workspace() {
        let workspace = workspace_with(&["SP1"]);
        assert!(workspace.is_open());
        assert_eq!(workspace.view()["checkpoints"], json!(["SP1"]));
    }

    #[test]
    fn duplicate_checkpoint_names_are_refused() {
        let workspace = workspace_with(&["SP1", "SP2"]);
        let error = open(&workspace, "SP1").expect_err("duplicate is refused");
        assert_eq!(error.error_class, ErrorClass::InvalidArguments);
        assert_eq!(workspace.view()["checkpoints"], json!(["SP1", "SP2"]));
    }

    #[test]
    fn the_checkpoint_stack_is_capped() {
        let workspace = CheckpointWorkspace::new();
        for index in 0..MAX_CHECKPOINTS {
            open(&workspace, &format!("SP{index}")).expect("within cap");
        }
        let error = open(&workspace, "OVERFLOW").expect_err("cap is enforced");
        assert_eq!(error.error_class, ErrorClass::PolicyDenied);
    }

    #[test]
    fn held_statements_accrue_above_the_newest_checkpoint() {
        let workspace = workspace_with(&["SP1"]);
        workspace.note_held_statement();
        open(&workspace, "SP2").expect("second checkpoint");
        workspace.note_held_statement();
        workspace.note_held_statement();
        assert_eq!(workspace.held_statements(), 3);

        let summary = workspace.plan_undo_to("SP2").expect("SP2 is live");
        assert_eq!(
            summary,
            UndoSummary {
                discarded_statements: 2,
                released_checkpoints: Vec::new(),
            }
        );
        workspace.commit_undo_to("SP2");
        assert_eq!(workspace.held_statements(), 1, "SP1's held work survives");
        assert_eq!(workspace.view()["checkpoints"], json!(["SP1", "SP2"]));
    }

    #[test]
    fn undo_releases_every_checkpoint_stacked_above_the_target() {
        let workspace = workspace_with(&["SP1", "SP2", "SP3"]);
        workspace.note_held_statement(); // above SP3
        let summary = workspace.plan_undo_to("SP1").expect("SP1 is live");
        assert_eq!(
            summary,
            UndoSummary {
                discarded_statements: 1,
                released_checkpoints: vec!["SP2".to_owned(), "SP3".to_owned()],
            }
        );
        workspace.commit_undo_to("SP1");
        assert_eq!(workspace.view()["checkpoints"], json!(["SP1"]));
        assert_eq!(workspace.held_statements(), 0);
        assert!(
            workspace.is_open(),
            "Oracle keeps the savepoint it rolled back to, so the workspace stays open"
        );
    }

    #[test]
    fn planning_an_undo_never_mutates_the_stack() {
        let workspace = workspace_with(&["SP1", "SP2"]);
        workspace.note_held_statement();
        let error = workspace
            .plan_undo_to("MISSING")
            .expect_err("unknown checkpoint");
        assert_eq!(error.error_class, ErrorClass::InvalidArguments);
        workspace.plan_undo_to("SP1").expect("SP1 is live");
        assert_eq!(workspace.view()["checkpoints"], json!(["SP1", "SP2"]));
        assert_eq!(workspace.held_statements(), 1);
    }

    #[test]
    fn a_transaction_boundary_closes_the_workspace() {
        let workspace = workspace_with(&["SP1"]);
        workspace.note_held_statement();
        workspace.clear();
        assert!(!workspace.is_open());
        assert_eq!(workspace.held_statements(), 0);
        let error = workspace
            .plan_undo_to("SP1")
            .expect_err("savepoint is gone");
        assert!(
            error.next_steps.iter().any(|step| step.contains("closed")),
            "the refusal must say the workspace closed: {:?}",
            error.next_steps
        );
    }
}
