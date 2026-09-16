use super::*;

const VALID_PROFILE_TOML: &str = r#"
[[profiles]]
name = "descriptor-bound-profile"
connect_string = "localhost:1521/FREEPDB1"
"#;

#[test]
#[allow(clippy::result_large_err)]
fn startup_config_descriptor_read_preserves_valid_cli_config_loading() {
    figment::Jail::expect_with(|jail| {
        let path = jail.directory().join("operator.toml");
        jail.create_file(&path, VALID_PROFILE_TOML)?;

        let config = OracleMcpConfig::load(Some(&path))
            .expect("a descriptor-bound regular config must keep loading");
        assert!(config.profile("descriptor-bound-profile").is_some());
        Ok(())
    });
}

#[test]
#[allow(clippy::result_large_err)]
fn startup_config_refuses_regular_file_replaced_after_cli_validation() {
    figment::Jail::expect_with(|jail| {
        let path = jail.directory().join("operator.toml");
        let displaced = jail.directory().join("operator-before-swap.toml");
        jail.create_file(&path, VALID_PROFILE_TOML)?;

        let replacement_path = path.clone();
        set_startup_config_open_hook(move || {
            std::fs::rename(&replacement_path, &displaced)
                .expect("move observed config away before descriptor open");
            std::fs::write(
                &replacement_path,
                "[[profiles]]\nname = \"replacement-profile\"\nconnect_string = \"replacement:1521/FREEPDB1\"\n",
            )
            .expect("replace the config pathname");
        });

        let error = OracleMcpConfig::load(Some(&path))
            .expect_err("a source swap must not change the config that starts the server");
        assert!(
            matches!(error, ConfigError::StartupConfigSourceUnusable { .. }),
            "expected descriptor-bound source refusal, got {error:?}"
        );
        assert!(error.to_string().contains("changed while it was opened"));
        Ok(())
    });
}

#[test]
#[allow(clippy::result_large_err)]
fn startup_config_refuses_a_file_larger_than_the_bounded_read_limit() {
    figment::Jail::expect_with(|jail| {
        let path = jail.directory().join("oversized.toml");
        let file = std::fs::File::create(&path).expect("create oversized sparse config");
        file.set_len((MAX_CONFIG_SOURCE_BYTES + 1) as u64)
            .expect("extend oversized sparse config");

        let error = OracleMcpConfig::load(Some(&path))
            .expect_err("an oversized source must be refused before parsing");
        assert!(
            matches!(error, ConfigError::StartupConfigSourceUnusable { .. }),
            "expected bounded-read refusal, got {error:?}"
        );
        assert!(error.to_string().contains("16 MiB"));
        Ok(())
    });
}

#[cfg(unix)]
#[test]
#[allow(clippy::result_large_err)]
fn startup_config_refuses_a_fifo_swapped_in_after_validation_without_blocking() {
    use std::time::{Duration, Instant};

    figment::Jail::expect_with(|jail| {
        let path = jail.directory().join("operator.toml");
        let displaced = jail.directory().join("operator-before-fifo.toml");
        jail.create_file(&path, VALID_PROFILE_TOML)?;

        let fifo_path = path.clone();
        set_startup_config_open_hook(move || {
            std::fs::rename(&fifo_path, &displaced)
                .expect("move observed config away before descriptor open");
            let status = std::process::Command::new("mkfifo")
                .arg(&fifo_path)
                .status()
                .expect("run mkfifo");
            assert!(status.success(), "mkfifo must create the replacement FIFO");
        });

        let started = Instant::now();
        let error = OracleMcpConfig::load(Some(&path))
            .expect_err("a FIFO swapped in after validation must be refused");
        assert!(
            matches!(error, ConfigError::StartupConfigSourceUnusable { .. }),
            "expected descriptor-bound source refusal, got {error:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a swapped FIFO must not stall startup; took {:?}",
            started.elapsed()
        );
        Ok(())
    });
}
