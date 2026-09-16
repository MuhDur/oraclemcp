use super::*;

#[test]
#[allow(clippy::result_large_err)]
fn cli_config_path_is_validated_fail_closed() {
    figment::Jail::expect_with(|jail| {
        let missing = jail.directory().join("does-not-exist.toml");
        let err = OracleMcpConfig::load(Some(&missing))
            .expect_err("a missing --config file must not silently load defaults");
        assert!(
            matches!(err, ConfigError::CliConfigPathUnusable { .. }),
            "expected CLI-path refusal, got {err:?}"
        );
        assert!(
            err.to_string().contains("no such regular file"),
            "got {err}"
        );
        Ok(())
    });

    figment::Jail::expect_with(|jail| {
        let directory = jail.directory().join("a-directory");
        jail.create_dir(&directory)?;
        let err = OracleMcpConfig::load(Some(&directory))
            .expect_err("a directory passed to --config must be refused");
        assert!(
            matches!(err, ConfigError::CliConfigPathUnusable { .. }),
            "expected CLI-path refusal, got {err:?}"
        );
        assert!(err.to_string().contains("is a directory"), "got {err}");
        Ok(())
    });
}

#[cfg(unix)]
#[test]
#[allow(clippy::result_large_err)]
fn cli_config_path_refuses_fifo_without_opening_it() {
    figment::Jail::expect_with(|jail| {
        let fifo = jail.directory().join("config.fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if made {
            let err = OracleMcpConfig::load(Some(&fifo))
                .expect_err("a FIFO must be refused before it can block Figment");
            assert!(
                matches!(err, ConfigError::CliConfigPathUnusable { .. }),
                "expected CLI-path refusal, got {err:?}"
            );
            assert!(
                err.to_string().contains("no such regular file"),
                "got {err}"
            );
        }
        Ok(())
    });
}

#[test]
#[allow(clippy::result_large_err)]
fn cli_config_path_loads_a_valid_regular_file() {
    figment::Jail::expect_with(|jail| {
        let path = jail.directory().join("operator.toml");
        jail.create_file(
            &path,
            "[[profiles]]\nname = \"cli-profile\"\nconnect_string = \"localhost:1521/FREEPDB1\"\n",
        )?;

        let config = OracleMcpConfig::load(Some(&path))
            .expect("a valid regular --config file must keep loading");
        assert!(config.profile("cli-profile").is_some());
        Ok(())
    });
}

#[test]
#[allow(clippy::result_large_err)]
fn cli_config_path_preserves_relative_path_support() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "relative.toml",
            "[[profiles]]\nname = \"relative-cli-profile\"\nconnect_string = \"localhost:1521/FREEPDB1\"\n",
        )?;

        let config = OracleMcpConfig::load(Some(Path::new("relative.toml")))
            .expect("relative CLI --config paths remain supported");
        assert!(config.profile("relative-cli-profile").is_some());
        Ok(())
    });
}
