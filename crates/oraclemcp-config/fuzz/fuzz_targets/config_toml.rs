#![no_main]
//! Fuzz `OracleMcpConfig::from_toml_str` (bead H10 /
//! oraclemcp-eng-program-bp8ia.9.10). Operator-supplied `profiles.toml` is an
//! untrusted-input parse surface: arbitrary bytes must never panic the parser,
//! whether the TOML is well-formed, malformed, or degenerate (e.g. deep
//! `base` inheritance chains, oversized strings, or profile shapes designed to
//! exercise validation edge cases).
//!
//! This target is engine-free like the rest of oraclemcp-config: it only
//! proves `from_toml_str` returns `Ok`/`Err` cleanly, never panics or
//! aborts. It does not assert anything about which inputs are accepted —
//! that behavior is covered by `oraclemcp-config`'s own unit/integration
//! tests.
//!
//! Run: `cargo +nightly-2026-05-11 fuzz run config_toml` (from
//! crates/oraclemcp-config).

use libfuzzer_sys::fuzz_target;
use oraclemcp_config::OracleMcpConfig;

fuzz_target!(|data: &[u8]| {
    let toml = String::from_utf8_lossy(data);
    let _ = OracleMcpConfig::from_toml_str(&toml);
});
