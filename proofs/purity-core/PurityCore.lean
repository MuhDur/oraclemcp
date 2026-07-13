/-
  Arc B3.1: the formally specified *routine-purity core* of the SQL guard.

  This file deliberately models neither SQL parsing nor the full Rust
  classifier.  It proves the small security-critical law at the oracle seam:
  a SELECT that contains user-defined routine calls is Safe only when every
  consulted routine is ProvenReadOnly.  Unknown is not evidence of purity.

  The deployed Rust classifier is not extracted from this model.  Its
  conformance is pinned by
  crates/oraclemcp-guard/tests/purity_core_conformance.rs.  Consequently this
  is a verified specification plus a tested implementation, not a verified
  binary.  To our knowledge, it is the first formally specified SQL-safety
  purity core; that is a research claim, not a claim of full SQL verification.

  Check with the pinned standalone toolchain:
    lean PurityCore.lean
-/

namespace OracleMcp.PurityCore

/-- The only three oracle answers the routine-purity gate may consume. -/
inductive Purity where
  | provenReadOnly
  | provenSideEffecting
  | unknown
  deriving DecidableEq, Repr

/-- The two outcomes of the routine-purity core, before other classifier floors. -/
inductive RoutineVerdict where
  | safe
  | guarded
  deriving DecidableEq, Repr

/--
The exact fail-closed core used for a SELECT's user-defined calls.  The empty
list is safe because no routine-purity obligation exists; an unproven or
side-effecting call forces Guarded.
-/
def routineCore : List Purity → RoutineVerdict
  | [] => .safe
  | .provenReadOnly :: tail => routineCore tail
  | .provenSideEffecting :: _ => .guarded
  | .unknown :: _ => .guarded

/-- Key purity-core lemma: Safe is equivalent to a proof for every routine. -/
theorem safe_iff_all_proven_read_only (calls : List Purity) :
    routineCore calls = .safe ↔
      ∀ purity ∈ calls, purity = .provenReadOnly := by
  induction calls with
  | nil => simp [routineCore]
  | cons head tail inductionHypothesis =>
    cases head <;> simp [routineCore, inductionHypothesis]

/-- Unknown is never sufficient evidence for Safe, regardless of position. -/
theorem unknown_blocks_safe (before after : List Purity) :
    routineCore (before ++ .unknown :: after) ≠ .safe := by
  intro safe
  have allProven := (safe_iff_all_proven_read_only _).mp safe
  have impossible : Purity.unknown = Purity.provenReadOnly :=
    allProven .unknown (by simp)
  cases impossible

/-- A known side effect also blocks Safe, regardless of position. -/
theorem side_effect_blocks_safe (before after : List Purity) :
    routineCore (before ++ .provenSideEffecting :: after) ≠ .safe := by
  intro safe
  have allProven := (safe_iff_all_proven_read_only _).mp safe
  have impossible : Purity.provenSideEffecting = Purity.provenReadOnly :=
    allProven .provenSideEffecting (by simp)
  cases impossible

end OracleMcp.PurityCore
