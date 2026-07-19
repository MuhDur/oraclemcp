//! Property checks for the profile-inheritance security lattice.
//!
//! A base chain is a merge of independently authored profile sources. Ordinary
//! fields use child-wins inheritance, but an operating ceiling is a constraint,
//! not a grant: every explicit source ceiling must still bound the merged
//! profile. Likewise, no descendant may clear `protected = true` inherited from
//! any source.

use oraclemcp_config::OracleMcpConfig;
use oraclemcp_guard::OperatingLevel;
use proptest::prelude::*;
use std::path::Path;

#[derive(Clone, Debug)]
struct ProfileSource {
    max_level: OperatingLevel,
    protected: bool,
    base: Option<usize>,
}

fn operating_level(selector: u8) -> OperatingLevel {
    match selector % 4 {
        0 => OperatingLevel::ReadOnly,
        1 => OperatingLevel::ReadWrite,
        2 => OperatingLevel::Ddl,
        _ => OperatingLevel::Admin,
    }
}

fn sources_from(selectors: &[(u8, bool, u8)]) -> Vec<ProfileSource> {
    selectors
        .iter()
        .enumerate()
        .map(|(index, &(level, protected, base_selector))| {
            // Keep each authored source valid in isolation. The interesting
            // cases are descendants that try to raise a lower ancestor or
            // explicitly clear an ancestor's protection.
            let max_level = if protected {
                OperatingLevel::ReadOnly
            } else {
                operating_level(level)
            };
            let candidate = usize::from(base_selector) % (index + 1);
            let base = (candidate < index).then_some(candidate);
            ProfileSource {
                max_level,
                protected,
                base,
            }
        })
        .collect()
}

fn render_config(sources: &[ProfileSource]) -> String {
    let mut toml = String::new();
    for (index, source) in sources.iter().enumerate() {
        toml.push_str("[[profiles]]\n");
        toml.push_str(&format!("name = \"profile_{index}\"\n"));
        toml.push_str("connect_string = \"synthetic:1521/service\"\n");
        toml.push_str(&format!("max_level = \"{}\"\n", source.max_level.as_str()));
        toml.push_str(&format!("protected = {}\n", source.protected));
        if let Some(base) = source.base {
            toml.push_str(&format!("base = \"profile_{base}\"\n"));
        }
        toml.push('\n');
    }
    toml
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn merged_profile_never_exceeds_any_source_ceiling_and_protection_is_monotone(
        selectors in prop::collection::vec((0u8..4, any::<bool>(), any::<u8>()), 1..16),
    ) {
        let sources = sources_from(&selectors);
        let config = OracleMcpConfig::from_toml_str(&render_config(&sources))
            .expect("generated acyclic profile sources are valid");

        for (index, source) in sources.iter().enumerate() {
            let merged = config
                .profile(&format!("profile_{index}"))
                .expect("generated profile remains present after merge");
            let mut expected_ceiling = source.max_level;
            let mut expected_protected = source.protected;
            let mut cursor = source.base;

            while let Some(source_index) = cursor {
                let contributing = &sources[source_index];
                expected_ceiling = expected_ceiling.min(contributing.max_level);
                expected_protected |= contributing.protected;
                prop_assert!(
                    merged.max_level() <= contributing.max_level,
                    "profile_{index} exceeded contributing profile_{source_index}"
                );
                cursor = contributing.base;
            }

            if expected_protected {
                expected_ceiling = OperatingLevel::ReadOnly;
            }
            prop_assert_eq!(merged.max_level(), expected_ceiling);
            prop_assert_eq!(merged.protected(), expected_protected);
            prop_assert!(merged.default_level() <= merged.max_level());
            if merged.protected() {
                prop_assert_eq!(merged.max_level(), OperatingLevel::ReadOnly);
            }
        }
    }
}

#[test]
#[allow(clippy::result_large_err)]
fn real_file_and_env_load_path_preserves_profile_security_merge() {
    // Config discovery selects one file; it does not combine multiple files.
    // Figment then layers environment/CLI values over that selected document,
    // and a profiles vector supplied by a later provider replaces the earlier
    // vector. The randomized test above therefore proves the source-ceiling
    // meet inside the retained profile graph, while this regression exercises
    // that graph through the real file + environment provider path.
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "profiles.toml",
            r#"
            [[profiles]]
            name = "protected_base"
            connect_string = "synthetic:1521/service"
            max_level = "READ_ONLY"
            protected = true

            [[profiles]]
            name = "child"
            base = "protected_base"
            max_level = "ADMIN"
            protected = false
            "#,
        )?;
        jail.set_env("ORACLEMCP_DEFAULT_PROFILE", "child");

        let config = OracleMcpConfig::load(Some(Path::new("profiles.toml")))
            .expect("real file + environment load path remains valid");
        let child = config.profile("child").expect("child profile");

        assert_eq!(config.default_profile.as_deref(), Some("child"));
        assert!(child.protected());
        assert_eq!(child.max_level(), OperatingLevel::ReadOnly);
        Ok(())
    });
}
