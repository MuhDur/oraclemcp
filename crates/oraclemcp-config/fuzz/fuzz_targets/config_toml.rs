#![no_main]
//! Fuzz the narrow, deterministic configuration boundary. Arbitrary TOML must
//! never panic. Every accepted profile graph must keep the validation and
//! security-lattice invariants: defaults stay below ceilings, a child ceiling
//! never exceeds any base-chain ceiling, and inherited protection is monotone
//! and READ_ONLY-pinned.
//!
//! The target checks both raw bytes (lossily decoded to exercise all byte
//! inputs) and a compact structure-aware profile grammar so valid inheritance
//! graphs remain common in the corpus.
//!
//! Run from `crates/oraclemcp-config`:
//! `cargo +nightly-2026-05-11 fuzz run config_toml fuzz/corpus/config_toml -- \
//!  -dict=fuzz/dictionaries/toml.dict -max_len=65536`.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use oraclemcp_config::{OperatingLevel, OracleMcpConfig};

const MAX_RAW_TOML_BYTES: usize = 64 * 1024;
const STRUCTURED_PROFILE_SLOTS: usize = 8;

#[derive(Clone, Copy, Debug, Arbitrary)]
struct ProfileSpec {
    level: u8,
    protected: bool,
    has_base: bool,
    base_selector: u8,
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    profiles: [ProfileSpec; STRUCTURED_PROFILE_SLOTS],
    profile_count: u8,
}

fn level_name(selector: u8) -> &'static str {
    match selector % 4 {
        0 => "READ_ONLY",
        1 => "READ_WRITE",
        2 => "DDL",
        _ => "ADMIN",
    }
}

fn render_structured(input: &FuzzInput) -> String {
    let count = usize::from(input.profile_count) % STRUCTURED_PROFILE_SLOTS + 1;
    let mut toml = String::with_capacity(count * 160);
    for (index, spec) in input.profiles[..count].iter().enumerate() {
        toml.push_str("[[profiles]]\n");
        toml.push_str(&format!("name = \"profile_{index}\"\n"));
        toml.push_str("connect_string = \"synthetic:1521/service\"\n");
        // Keep every protected source valid in isolation so the fuzzer reaches
        // descendant attempts to clear protection or raise the inherited cap.
        let level = if spec.protected {
            "READ_ONLY"
        } else {
            level_name(spec.level)
        };
        toml.push_str(&format!("max_level = \"{level}\"\n"));
        toml.push_str(&format!("protected = {}\n", spec.protected));
        if spec.has_base && index > 0 {
            let base = usize::from(spec.base_selector) % index;
            toml.push_str(&format!("base = \"profile_{base}\"\n"));
        }
        toml.push('\n');
    }
    toml
}

fn assert_accepted_invariants(config: &OracleMcpConfig) {
    for profile in &config.profiles {
        assert!(
            profile.default_level() <= profile.max_level(),
            "accepted profile default exceeded its ceiling"
        );
        if profile.protected() {
            assert_eq!(
                profile.max_level(),
                OperatingLevel::ReadOnly,
                "accepted protected profile was not READ_ONLY-pinned"
            );
        }

        let merged_ceiling = profile.max_level();
        let merged_protected = profile.protected();
        let mut base = profile.base.as_deref();
        let mut hops = 0usize;
        while let Some(base_name) = base {
            hops += 1;
            assert!(
                hops <= config.profiles.len(),
                "accepted profile graph contained an inheritance cycle"
            );
            let parent = config
                .profile(base_name)
                .expect("accepted profile graph referenced an unknown base");
            // An omitted max_level is not an authored ceiling: the child may
            // supply one through ordinary inheritance. Once a source has an
            // explicit or inherited ceiling, however, descendants may only
            // tighten it.
            if let Some(parent_ceiling) = parent.max_level {
                assert!(
                    merged_ceiling <= parent_ceiling,
                    "merged child ceiling exceeded a contributing base ceiling"
                );
            }
            assert!(
                !parent.protected() || merged_protected,
                "merged child cleared inherited protection"
            );
            base = parent.base.as_deref();
        }
    }
}

fn check_toml(toml: &str) {
    let first = OracleMcpConfig::from_toml_str(toml);
    let second = OracleMcpConfig::from_toml_str(toml);
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "config acceptance must be deterministic"
    );
    if let (Ok(first), Ok(second)) = (first, second) {
        assert_eq!(
            first, second,
            "accepted config must parse deterministically"
        );
        assert_accepted_invariants(&first);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_RAW_TOML_BYTES {
        return;
    }
    check_toml(&String::from_utf8_lossy(data));

    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = FuzzInput::arbitrary(&mut unstructured) {
        check_toml(&render_structured(&input));
    }
});
