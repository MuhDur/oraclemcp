# Purity-core Lean research proof

`PurityCore.lean` proves the routine-purity core only: a `Safe` result requires
every user-defined routine call to be `ProvenReadOnly`; `Unknown` and
`ProvenSideEffecting` force `Guarded`. It deliberately does not model SQL
parsing, DML recognition, statement-level trigger/VPD analysis, operating-level
gates, or certificate/audit binding.

This is a verified specification plus a tested implementation, not verified
Rust extraction. The matching Rust conformance fixture is
`crates/oraclemcp-guard/tests/purity_core_conformance.rs`.

The repository pins Lean 4.30.0 in `lean-toolchain`. From this directory:

```text
lean PurityCore.lean
```
