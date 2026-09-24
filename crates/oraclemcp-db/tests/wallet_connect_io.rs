//! Wallet filesystem inputs are opened as bounded regular files before a
//! connection attempt can block on a FIFO or follow a symlink.

#[cfg(unix)]
mod unix {
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::Duration;

    use asupersync::Cx;
    use asupersync::runtime::RuntimeBuilder;
    use oraclemcp_db::RustOracleConnection;
    use oraclemcp_db::{
        OracleConnectOptions, WalletFileChoice, WalletFileReadError, wallet_certificate_validity,
    };
    use tempfile::tempdir;

    fn create_fifo(path: &std::path::Path) {
        let status = Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("run mkfifo for wallet fixture");
        assert!(status.success(), "mkfifo must create {}", path.display());
    }

    fn assert_not_regular(result: Result<(), WalletFileReadError>, filename: &str) {
        assert!(
            matches!(result, Err(WalletFileReadError::NotRegularFile { .. })),
            "{filename}: expected typed NotRegularFile, got {result:?}"
        );
    }

    #[test]
    fn wallet_certificate_validity_refuses_fifo_pem() {
        for (filename, password) in [
            ("ewallet.pem", None),
            ("ewallet.p12", Some("synthetic-password")),
            ("cwallet.sso", None),
        ] {
            let started = std::time::Instant::now();
            let dir = tempdir().expect("temporary wallet directory");
            let path = dir.path().join(filename);
            create_fifo(&path);
            let (sender, receiver) = mpsc::sync_channel(1);
            let wallet_dir = dir.path().to_owned();
            let worker = std::thread::spawn(move || {
                let result = wallet_certificate_validity(&wallet_dir, password).map(|_| ());
                sender.send(result).expect("receiver remains available");
            });
            let result = match receiver.recv_timeout(Duration::from_secs(2)) {
                Ok(result) => result,
                Err(timeout) => {
                    drop(
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(&path)
                            .expect("open FIFO writer to release blocked reader"),
                    );
                    let _ = receiver.recv_timeout(Duration::from_secs(2));
                    worker.join().expect("reader exits after watchdog release");
                    panic!("wallet_certificate_validity blocked on {filename}: {timeout}");
                }
            };
            worker.join().expect("certificate probe exits");
            assert_not_regular(result, filename);
            println!(
                "{{\"case_id\":\"wallet_certificate_validity_refuses_fifo\",\"wallet_file\":\"{filename}\",\"file_kind\":\"fifo\",\"expected\":\"refused\",\"actual\":\"NotRegularFile\",\"elapsed_ms\":{}}}",
                started.elapsed().as_millis()
            );
        }
    }

    #[test]
    fn connect_refuses_fifo_wallet_before_blocking() {
        let started = std::time::Instant::now();
        let dir = tempdir().expect("temporary wallet directory");
        let pem = dir.path().join(WalletFileChoice::Pem.file_name());
        create_fifo(&pem);

        let mut options = OracleConnectOptions::default();
        options.connect_string = "tcps://127.0.0.1:1/XEPDB1".to_owned();
        options.wallet_location = Some(dir.path().to_owned());
        options.connect_timeout = Some(Duration::from_millis(250));

        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = RuntimeBuilder::current_thread()
                .build()
                .expect("test runtime")
                .block_on(async {
                    let cx = Cx::current().expect("block_on installs a current Cx");
                    let error = RustOracleConnection::connect(&cx, options).await;
                    match error {
                        Ok(_) => "unexpected successful direct connect".to_owned(),
                        Err(error) => error.to_string(),
                    }
                });
            sender.send(result).expect("receiver remains available");
        });
        let error = match receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(error) => error,
            Err(timeout) => {
                drop(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&pem)
                        .expect("open FIFO writer to release blocked reader"),
                );
                let _ = receiver.recv_timeout(Duration::from_secs(2));
                worker.join().expect("connect exits after watchdog release");
                panic!("connect blocked on wallet FIFO: {timeout}");
            }
        };
        worker.join().expect("connect worker exits");
        assert!(
            error
                .to_ascii_lowercase()
                .contains("wallet file is not a regular file"),
            "connect must fail with the wallet-file refusal before socket I/O: {error}"
        );
        println!(
            "{{\"case_id\":\"connect_refuses_fifo_wallet_before_blocking\",\"wallet_file\":\"ewallet.pem\",\"file_kind\":\"fifo\",\"expected\":\"refused\",\"actual\":\"NotRegularFile\",\"elapsed_ms\":{}}}",
            started.elapsed().as_millis()
        );
    }
}
