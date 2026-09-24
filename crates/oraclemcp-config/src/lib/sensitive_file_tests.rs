use super::*;

#[test]
#[allow(clippy::result_large_err)]
fn sensitive_reader_preserves_regular_file_contents() {
    figment::Jail::expect_with(|jail| {
        let path = jail.directory().join("material.pem");
        jail.create_file(&path, "descriptor-bound bytes")?;
        assert_eq!(
            read_sensitive_file(&path, 64).expect("regular file is readable"),
            b"descriptor-bound bytes"
        );
        Ok(())
    });
}

#[test]
#[allow(clippy::result_large_err)]
fn sensitive_reader_refuses_a_regular_file_over_its_limit() {
    figment::Jail::expect_with(|jail| {
        let path = jail.directory().join("oversized.pem");
        let file = std::fs::File::create(&path).expect("create oversized sparse fixture");
        file.set_len(33).expect("extend fixture");
        assert_eq!(
            read_sensitive_file(&path, 32),
            Err(SensitiveFileReadError::TooLarge)
        );
        Ok(())
    });
}

#[cfg(unix)]
#[test]
#[allow(clippy::result_large_err)]
fn sensitive_reader_refuses_a_fifo_without_blocking() {
    use std::time::{Duration, Instant};

    figment::Jail::expect_with(|jail| {
        let path = jail.directory().join("material.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo must create the FIFO fixture");

        let started = Instant::now();
        assert!(matches!(
            read_sensitive_file(&path, 64),
            Err(SensitiveFileReadError::Unusable(
                "file is not a regular file"
            ))
        ));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a configured FIFO must be refused before it can block; took {:?}",
            started.elapsed()
        );
        Ok(())
    });
}

#[test]
#[allow(clippy::result_large_err)]
fn sensitive_reader_refuses_a_regular_file_swapped_after_inspection() {
    figment::Jail::expect_with(|jail| {
        let path = jail.directory().join("material.pem");
        let displaced = jail.directory().join("material-before-swap.pem");
        jail.create_file(&path, "before")?;

        let replacement_path = path.clone();
        set_startup_config_open_hook(move || {
            std::fs::rename(&replacement_path, &displaced)
                .expect("move observed source before descriptor open");
            std::fs::write(&replacement_path, "replacement").expect("replace configured pathname");
        });

        assert_eq!(
            read_sensitive_file(&path, 64),
            Err(SensitiveFileReadError::Unusable(
                "file changed while it was opened"
            ))
        );
        Ok(())
    });
}

#[cfg(unix)]
#[test]
#[allow(clippy::result_large_err)]
fn sensitive_reader_refuses_a_parent_replaced_after_the_descriptor_read() {
    figment::Jail::expect_with(|jail| {
        let parent = jail.directory().join("material-parent");
        let parked = jail.directory().join("material-parent-parked");
        std::fs::create_dir(&parent).expect("create configured parent");
        let path = parent.join("material.pem");
        std::fs::write(&path, "bound material").expect("write configured material");

        let replacement_parent = parent.clone();
        set_sensitive_file_post_read_hook(move || {
            std::fs::rename(&replacement_parent, &parked)
                .expect("park original parent after the descriptor read");
            std::fs::create_dir(&replacement_parent).expect("install normal replacement parent");
        });

        assert_eq!(
            read_sensitive_file(&path, 64),
            Err(SensitiveFileReadError::Unusable(
                "parent directory changed while the file was read"
            ))
        );
        Ok(())
    });
}

#[cfg(windows)]
#[test]
#[allow(clippy::result_large_err)]
fn sensitive_reader_refuses_a_parent_replaced_after_the_descriptor_read() {
    use std::{cell::Cell, rc::Rc};

    figment::Jail::expect_with(|jail| {
        let parent = jail.directory().join("material-parent");
        let parked = jail.directory().join("material-parent-parked");
        std::fs::create_dir(&parent).expect("create configured parent");
        let path = parent.join("material.pem");
        std::fs::write(&path, "bound material").expect("write configured material");

        let swap_blocked = Rc::new(Cell::new(false));
        let hook_blocked = Rc::clone(&swap_blocked);
        let replacement_parent = parent.clone();
        let attempted_parked = parked.clone();
        set_sensitive_file_post_read_hook(move || {
            let error = std::fs::rename(&replacement_parent, &attempted_parked)
                .expect_err("Windows must refuse a parent swap while its descriptor is held");
            assert_eq!(error.raw_os_error(), Some(32), "expected sharing violation");
            assert!(
                replacement_parent.is_dir(),
                "original parent remains in place"
            );
            assert!(
                !attempted_parked.exists(),
                "attacker did not park the parent"
            );
            hook_blocked.set(true);
        });

        assert_eq!(
            read_sensitive_file(&path, 64).expect("the unchanged descriptor remains readable"),
            b"bound material"
        );
        assert!(
            swap_blocked.get(),
            "the attempted parent swap was exercised"
        );

        // This control proves that the held reader descriptor, rather than an
        // unusable fixture path, prevented the same rename during the read.
        std::fs::rename(&parent, &parked)
            .expect("parent can be moved once the sensitive reader has returned");
        assert!(parked.join("material.pem").is_file());
        Ok(())
    });
}
