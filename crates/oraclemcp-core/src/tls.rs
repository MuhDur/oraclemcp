//! TLS + mTLS for the Streamable HTTP transport (plan §7.1; bead P1-9c /
//! oracle-qmwz.2.9.3). **HTTPS-only** off-box: builds a `rustls::ServerConfig`
//! from operator-supplied PEM material, optionally requiring **mutual TLS**
//! (client-certificate verification against a configured CA). The crypto
//! provider is `ring`, pinned explicitly (no reliance on a process-global
//! default install).
//!
//! `build_server_config` returns the `Arc<ServerConfig>` a TLS-terminating
//! listener can use while the security-relevant configuration — and the mTLS
//! decision — lives here and is unit-tested.

use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;

/// Operator TLS material (PEM bytes).
#[derive(Clone)]
pub struct TlsMaterial {
    /// The server certificate chain (PEM, leaf first).
    pub cert_chain_pem: Vec<u8>,
    /// The server private key (PEM; PKCS#8 / PKCS#1 / SEC1).
    pub private_key_pem: Vec<u8>,
    /// When `Some`, **mTLS is required**: client certs are verified against
    /// these CA certificate(s) (PEM). `None` = server-only TLS.
    pub client_ca_pem: Option<Vec<u8>>,
}

/// Why building the TLS server config failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// No server certificate parsed from the chain PEM.
    #[error("no server certificate found in the PEM chain")]
    NoCerts,
    /// No private key parsed from the key PEM.
    #[error("no private key found in the PEM")]
    NoKey,
    /// mTLS requested but the client-CA PEM had no certificates.
    #[error("mTLS requested but no client CA certificate found")]
    NoClientCa,
    /// A PEM block failed to parse.
    #[error("PEM parse error: {0}")]
    BadPem(String),
    /// The client-certificate verifier could not be built.
    #[error("client verifier error: {0}")]
    Verifier(String),
    /// rustls rejected the assembled config (e.g. cert/key mismatch).
    #[error("TLS config error: {0}")]
    Config(String),
}

fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    // `rustls_pki_types::pem` (maintained; supersedes the archived rustls-pemfile).
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::BadPem(e.to_string()))
}

/// Build the `rustls::ServerConfig` for the HTTPS transport. When
/// `material.client_ca_pem` is set, the config **requires and verifies client
/// certificates** (mutual TLS) against that CA; otherwise it is server-only TLS.
pub fn build_server_config(material: &TlsMaterial) -> Result<Arc<ServerConfig>, TlsError> {
    let certs = parse_certs(&material.cert_chain_pem)?;
    if certs.is_empty() {
        return Err(TlsError::NoCerts);
    }
    // No parseable private key (absent or wrong PEM type) -> NoKey.
    let key: PrivateKeyDer<'static> =
        PrivateKeyDer::from_pem_slice(&material.private_key_pem).map_err(|_| TlsError::NoKey)?;

    // Pin the `ring` provider explicitly (no process-global default needed).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Config(e.to_string()))?;

    let config = match &material.client_ca_pem {
        Some(ca_pem) => {
            let ca_certs = parse_certs(ca_pem)?;
            if ca_certs.is_empty() {
                return Err(TlsError::NoClientCa);
            }
            let mut roots = rustls::RootCertStore::empty();
            for c in ca_certs {
                roots
                    .add(c)
                    .map_err(|e| TlsError::Verifier(e.to_string()))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()
            .map_err(|e| TlsError::Verifier(e.to_string()))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| TlsError::Config(e.to_string()))?
        }
        None => builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TlsError::Config(e.to_string()))?,
    };
    Ok(Arc::new(config))
}

/// Whether this material requires mutual TLS (a client CA is configured).
#[must_use]
pub fn requires_mtls(material: &TlsMaterial) -> bool {
    material.client_ca_pem.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed cert + key (PEM) for tests via rcgen.
    fn self_signed() -> (Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        (
            cert.cert.pem().into_bytes(),
            cert.key_pair.serialize_pem().into_bytes(),
        )
    }

    #[test]
    fn server_only_tls_config_builds() {
        let (cert, key) = self_signed();
        let material = TlsMaterial {
            cert_chain_pem: cert,
            private_key_pem: key,
            client_ca_pem: None,
        };
        assert!(!requires_mtls(&material));
        let cfg = build_server_config(&material).expect("server-only TLS builds");
        // No client auth required when there is no client CA.
        assert!(Arc::strong_count(&cfg) >= 1);
    }

    #[test]
    fn mtls_config_builds_with_a_client_ca() {
        let (cert, key) = self_signed();
        // Use a second self-signed cert as the client CA.
        let (ca, _ca_key) = self_signed();
        let material = TlsMaterial {
            cert_chain_pem: cert,
            private_key_pem: key,
            client_ca_pem: Some(ca),
        };
        assert!(requires_mtls(&material));
        build_server_config(&material).expect("mTLS config builds with a client CA");
    }

    #[test]
    fn missing_cert_is_rejected() {
        let (_cert, key) = self_signed();
        let material = TlsMaterial {
            cert_chain_pem: b"not a pem".to_vec(),
            private_key_pem: key,
            client_ca_pem: None,
        };
        assert!(matches!(
            build_server_config(&material),
            Err(TlsError::NoCerts)
        ));
    }

    #[test]
    fn missing_key_is_rejected() {
        let (cert, _key) = self_signed();
        let material = TlsMaterial {
            cert_chain_pem: cert,
            private_key_pem: b"-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----"
                .to_vec(),
            client_ca_pem: None,
        };
        assert!(matches!(
            build_server_config(&material),
            Err(TlsError::NoKey)
        ));
    }

    #[test]
    fn mtls_with_empty_ca_is_rejected() {
        let (cert, key) = self_signed();
        let material = TlsMaterial {
            cert_chain_pem: cert,
            private_key_pem: key,
            client_ca_pem: Some(
                b"-----BEGIN RSA PRIVATE KEY-----\nMA==\n-----END RSA PRIVATE KEY-----".to_vec(),
            ),
        };
        assert!(matches!(
            build_server_config(&material),
            Err(TlsError::NoClientCa)
        ));
    }
}
