//! Profile-merge safety properties (bead H11, plan §30.4 item 9, property half).
//!
//! The plan states the invariant as "merged.max_level <= min(source max_levels)".
//! That is NOT the contract this system has, and asserting it would pin a
//! property the code deliberately does not provide: `base` is configuration
//! reuse, not a fleet safety ceiling, and a child may raise `max_level` above
//! its base (README "Connection profiles"; docs/threat-model.md). The ceiling a
//! profile cannot escape is `protected`, which is checked here, and
//! `base_cannot_be_used_as_a_safety_ceiling` pins the surprising-but-documented
//! direction so a silent change to it fails.
//!
//! What load actually guarantees, for every profile after inheritance resolves:
//!   1. `protected` implies `max_level == READ_ONLY`
//!   2. `default_level <= max_level`
//!   3. parsing is total: a generated config either loads or returns a typed
//!      `ConfigError`; it never panics and an inheritance cycle never hangs.
//!
//! Fail-closed matters more than repair: a config violating 1 or 2 must be
//! REJECTED, never silently corrected into something weaker than the operator
//! wrote.

use oraclemcp_config::{OperatingLevel, OracleMcpConfig};
use proptest::prelude::*;

const LEVELS: [&str; 4] = ["READ_ONLY", "READ_WRITE", "DDL", "ADMIN"];

/// One generated profile. `base` is an index, so the generator can produce
/// self-references, forward references, and cycles — all of which the loader
/// must survive with a typed error rather than a panic or a hang.
#[derive(Debug, Clone)]
struct ProfileSpec {
    max_level: Option<usize>,
    default_level: Option<usize>,
    protected: bool,
    base: Option<usize>,
    connect_string: bool,
}

fn profile_spec() -> impl Strategy<Value = ProfileSpec> {
    (
        proptest::option::of(0usize..LEVELS.len()),
        proptest::option::of(0usize..LEVELS.len()),
        any::<bool>(),
        proptest::option::of(0usize..4),
        any::<bool>(),
    )
        .prop_map(
            |(max_level, default_level, protected, base, connect_string)| ProfileSpec {
                max_level,
                default_level,
                protected,
                base,
                connect_string,
            },
        )
}

fn render(specs: &[ProfileSpec]) -> String {
    let mut toml = String::from("schema_version = 2\n");
    for (index, spec) in specs.iter().enumerate() {
        toml.push_str("\n[[profiles]]\n");
        toml.push_str(&format!("name = \"p{index}\"\n"));
        if spec.connect_string {
            toml.push_str("connect_string = \"localhost:1521/FREEPDB1\"\n");
        }
        if let Some(level) = spec.max_level {
            toml.push_str(&format!("max_level = \"{}\"\n", LEVELS[level]));
        }
        if let Some(level) = spec.default_level {
            toml.push_str(&format!("default_level = \"{}\"\n", LEVELS[level]));
        }
        if spec.protected {
            toml.push_str("protected = true\n");
        }
        if let Some(base) = spec.base {
            toml.push_str(&format!("base = \"p{base}\"\n"));
        }
    }
    toml
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The load path is total, and everything it admits satisfies the two
    /// invariants. A cycle, a dangling base, or a contradictory level pair must
    /// come back as an error, never as an accepted-but-weakened profile.
    #[test]
    fn loaded_profiles_satisfy_the_level_invariants(
        specs in proptest::collection::vec(profile_spec(), 1..5)
    ) {
        let toml = render(&specs);
        let Ok(config) = OracleMcpConfig::from_toml_str(&toml) else {
            // A rejected config is a valid outcome: fail closed.
            return Ok(());
        };
        for profile in config.list_profiles() {
            let resolved = config
                .profile(&profile.name)
                .expect("a listed profile must resolve by name");
            prop_assert!(
                !resolved.protected() || resolved.max_level() == OperatingLevel::ReadOnly,
                "protected profile {} loaded with max_level {:?}",
                profile.name,
                resolved.max_level()
            );
            // OperatingLevel is the ordered ladder itself; compare it directly
            // rather than re-encoding the ranks (it is #[non_exhaustive], so a
            // local rank table would silently mis-rank a future level).
            prop_assert!(
                resolved.default_level() <= resolved.max_level(),
                "profile {} loaded with default_level {:?} above max_level {:?}",
                profile.name,
                resolved.default_level(),
                resolved.max_level()
            );
        }
    }
}

/// Anti-vacuity (plan §30.5): a property that never reaches an interesting
/// state is a test that cannot fail for the bug it guards. This enumerates the
/// generator's own space deterministically and asserts the property body is
/// actually exercised on loaded profiles — including the two states that carry
/// the invariants: a `protected` profile and a profile that inherited via
/// `base`. If a future change makes the loader reject nearly everything, this
/// fails instead of leaving the property quietly green.
#[test]
fn the_generated_space_reaches_the_states_the_property_asserts_over() {
    let mut loaded = 0usize;
    let mut protected_seen = 0usize;
    let mut inherited_seen = 0usize;

    for max_level in 0..LEVELS.len() {
        for default_level in 0..LEVELS.len() {
            for protected in [false, true] {
                for with_base in [false, true] {
                    let specs = vec![
                        ProfileSpec {
                            max_level: Some(0),
                            default_level: None,
                            protected: false,
                            base: None,
                            connect_string: true,
                        },
                        ProfileSpec {
                            max_level: Some(max_level),
                            default_level: Some(default_level),
                            protected,
                            base: with_base.then_some(0),
                            connect_string: !with_base,
                        },
                    ];
                    let Ok(config) = OracleMcpConfig::from_toml_str(&render(&specs)) else {
                        continue;
                    };
                    loaded += 1;
                    let child = config.profile("p1").expect("child profile");
                    if child.protected() {
                        protected_seen += 1;
                    }
                    if with_base {
                        inherited_seen += 1;
                    }
                }
            }
        }
    }

    assert!(
        loaded >= 16,
        "the generator space is too narrow to exercise the property: {loaded} configs loaded"
    );
    assert!(
        protected_seen > 0,
        "no loaded profile was protected; the protected invariant is never checked"
    );
    assert!(
        inherited_seen > 0,
        "no loaded profile inherited via base; merging is never checked"
    );
}

/// `base` is configuration reuse, not a ceiling: a child may raise `max_level`
/// above its base. Pinned deliberately — the plan assumed the opposite, and a
/// reader who assumes a READ_ONLY base constrains its children is wrong in a
/// way that matters. `protected = true` is the mechanism that does constrain.
#[test]
fn base_cannot_be_used_as_a_safety_ceiling() {
    let config = OracleMcpConfig::from_toml_str(
        r#"
schema_version = 2

[[profiles]]
name = "locked_base"
connect_string = "localhost:1521/FREEPDB1"
max_level = "READ_ONLY"

[[profiles]]
name = "child"
base = "locked_base"
max_level = "DDL"
"#,
    )
    .expect("a child raising max_level above its base is accepted by design");
    assert_eq!(
        config.profile("child").expect("child profile").max_level(),
        OperatingLevel::Ddl,
        "base inheritance must not be mistaken for a fleet safety ceiling"
    );
}

/// The ceiling that does hold: a protected profile is refused outright when it
/// declares anything above READ_ONLY, rather than being silently clamped.
#[test]
fn protected_profile_above_read_only_is_refused_not_clamped() {
    let error = OracleMcpConfig::from_toml_str(
        r#"
schema_version = 2

[[profiles]]
name = "prod"
connect_string = "localhost:1521/FREEPDB1"
protected = true
max_level = "READ_WRITE"
"#,
    )
    .expect_err("a protected profile above READ_ONLY must be refused");
    assert!(
        error.to_string().contains("protected"),
        "the refusal must name the protected rule, got: {error}"
    );
}

/// A `base` cycle terminates with a typed error. The loader walks inheritance
/// edges, so this is the difference between a config error and a hang.
#[test]
fn inheritance_cycle_is_a_typed_error() {
    let error = OracleMcpConfig::from_toml_str(
        r#"
schema_version = 2

[[profiles]]
name = "a"
base = "b"

[[profiles]]
name = "b"
base = "a"
"#,
    )
    .expect_err("an inheritance cycle must be refused");
    assert!(
        error.to_string().contains("cycle"),
        "the refusal must name the cycle, got: {error}"
    );
}
