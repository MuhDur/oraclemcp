//! Descriptor-bound loading for configured server TLS material.

use std::path::Path;

use oraclemcp_config::{HttpTlsConfig, read_sensitive_file};
use oraclemcp_core::TlsMaterial;

/// Certificate and key PEMs are normally kilobytes; this leaves ample room for
/// long certificate chains without allowing a configured path to consume memory
/// without a limit during server startup.
const MAX_TLS_PEM_BYTES: usize = 4 * 1024 * 1024;

pub(super) fn tls_material_from_config(
    tls: &HttpTlsConfig,
) -> Result<Option<TlsMaterial>, (&'static str, String)> {
    let Some(cert_path) = tls.cert_chain_path.as_deref() else {
        return Ok(None);
    };
    let key_path = tls
        .private_key_path
        .as_deref()
        .expect("validated TLS private_key_path");
    let cert_chain_pem = read_tls_pem("server certificate chain", cert_path)?;
    let private_key_pem = read_tls_pem("server private key", key_path)?;
    let client_ca_pem = tls
        .client_ca_path
        .as_deref()
        .map(|path| read_tls_pem("client CA", path))
        .transpose()?;
    Ok(Some(TlsMaterial {
        cert_chain_pem,
        private_key_pem,
        client_ca_pem,
    }))
}

fn read_tls_pem(role: &'static str, path: &Path) -> Result<Vec<u8>, (&'static str, String)> {
    read_sensitive_file(path, MAX_TLS_PEM_BYTES).map_err(|error| {
        (
            "ORACLEMCP_HTTP_TLS_INVALID",
            format!("failed safely to read HTTP TLS {role}: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    #[test]
    fn tls_pem_fifo_is_refused_without_blocking_or_rendering_its_path() {
        let path = std::env::temp_dir().join(format!(
            "oraclemcp-tls-fifo-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo must create the FIFO fixture");

        let started = Instant::now();
        let (_, error) = read_tls_pem("server private key", &path)
            .expect_err("a configured TLS FIFO must be refused before it can block");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a configured TLS FIFO must not stall startup; took {:?}",
            started.elapsed()
        );
        assert!(error.contains("failed safely to read HTTP TLS server private key"));
        assert!(
            !error.contains(&path.display().to_string()),
            "the configured TLS path leaked: {error}"
        );
        std::fs::remove_file(&path).expect("remove FIFO fixture");
    }
}
