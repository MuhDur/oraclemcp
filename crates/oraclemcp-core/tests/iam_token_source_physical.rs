//! B16a: server IAM token sources are invoked per physical TCPS connection.
//!
//! The terminator is a rustls server, not an Oracle protocol server. A successful
//! proof is therefore: profile load configures a refreshable source without
//! running it, each real driver connect attempt reaches TCPS, and the configured
//! `token_exec` counter advances once per physical attempt.

use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::{
    DoctorContext, DoctorIamTokenSourceKind, DoctorIamTokenSourceObservation,
    build_session_context, inject_iam_token, run_doctor,
};
use oraclemcp_db::RustOracleConnection;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection};

const SYNTHETIC_CN: &str = "oracle-test.invalid";
const SYNTHETIC_DN: &str = "CN=oracle-test.invalid,O=Oracle Synthetic Test,C=US";

#[derive(Clone)]
struct B16aSyntheticMaterial {
    cert_chain_pem: Vec<u8>,
    leaf_key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
}

#[derive(Debug)]
struct B16aTerminatorObservation {
    peer_cert_count: usize,
    post_tls_bytes: usize,
}

type B16aTerminatorHandle = (
    u16,
    mpsc::Receiver<Result<Vec<B16aTerminatorObservation>, String>>,
    std::thread::JoinHandle<()>,
);

fn synthetic_dn() -> rcgen::DistinguishedName {
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, SYNTHETIC_CN);
    dn.push(rcgen::DnType::OrganizationName, "Oracle Synthetic Test");
    dn.push(rcgen::DnType::CountryName, "US");
    dn
}

fn synthetic_material() -> B16aSyntheticMaterial {
    let mut ca_params =
        rcgen::CertificateParams::new(vec!["oraclemcp-test-ca".to_owned()]).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name = synthetic_dn();
    let ca_key = rcgen::KeyPair::generate().expect("CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");

    let mut leaf_params =
        rcgen::CertificateParams::new(vec![SYNTHETIC_CN.to_owned()]).expect("leaf params");
    leaf_params.distinguished_name = synthetic_dn();
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf signed by synthetic CA");
    let leaf_pem = leaf_cert.pem();
    let ca_pem = ca_cert.pem();
    let cert_chain_pem = format!("{leaf_pem}{ca_pem}").into_bytes();
    B16aSyntheticMaterial {
        cert_chain_pem,
        leaf_key_pem: leaf_key.serialize_pem().into_bytes(),
        ca_pem: ca_pem.into_bytes(),
    }
}

fn parse_certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .expect("certificate PEM parses")
}

fn parse_key(pem: &[u8]) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(pem).expect("private key PEM parses")
}

fn server_config(material: &B16aSyntheticMaterial) -> Arc<ServerConfig> {
    let mut roots = RootCertStore::empty();
    for cert in parse_certs(&material.ca_pem) {
        roots.add(cert).expect("add synthetic CA root");
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .expect("client verifier");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            parse_certs(&material.cert_chain_pem),
            parse_key(&material.leaf_key_pem),
        )
        .expect("synthetic TCPS server config")
        .into()
}

fn spawn_tcps_terminator(
    material: B16aSyntheticMaterial,
    expected_connections: usize,
) -> B16aTerminatorHandle {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback TCPS terminator");
    let port = listener.local_addr().expect("listener address").port();
    let config = server_config(&material);
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let outcome = (|| -> Result<Vec<B16aTerminatorObservation>, String> {
            let mut observations = Vec::with_capacity(expected_connections);
            for _ in 0..expected_connections {
                let (mut sock, peer) = listener.accept().map_err(|e| format!("accept: {e}"))?;
                if !peer.ip().is_loopback() {
                    return Err(format!("refusing non-loopback peer: {peer}"));
                }
                sock.set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|e| format!("set read timeout: {e}"))?;
                sock.set_write_timeout(Some(Duration::from_secs(5)))
                    .map_err(|e| format!("set write timeout: {e}"))?;
                let mut conn = ServerConnection::new(Arc::clone(&config))
                    .map_err(|e| format!("server connection: {e}"))?;
                conn.complete_io(&mut sock)
                    .map_err(|e| format!("TLS handshake: {e}"))?;
                if conn.is_handshaking() {
                    return Err("TLS handshake did not complete".to_owned());
                }
                let peer_cert_count = conn.peer_certificates().map_or(0, <[CertificateDer]>::len);
                let mut tls = rustls::Stream::new(&mut conn, &mut sock);
                let mut buf = [0u8; 512];
                let post_tls_bytes = tls.read(&mut buf).unwrap_or(0);
                observations.push(B16aTerminatorObservation {
                    peer_cert_count,
                    post_tls_bytes,
                });
            }
            Ok(observations)
        })();
        let _ = tx.send(outcome);
    });
    (port, rx, handle)
}

fn unique_lab_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "oraclemcp-b16a-token-source-{}-{nanos}",
        std::process::id()
    ))
}

fn write_lab_wallet(root: &Path, port: u16, material: &B16aSyntheticMaterial) -> PathBuf {
    let wallet = root.join("wallet");
    std::fs::create_dir_all(&wallet).expect("create synthetic wallet dir");
    let ewallet = [
        material.cert_chain_pem.as_slice(),
        material.leaf_key_pem.as_slice(),
    ]
    .concat();
    std::fs::write(wallet.join("ewallet.pem"), ewallet).expect("write ewallet.pem");
    std::fs::write(
        wallet.join("tnsnames.ora"),
        format!(
            "LOCAL_TCPS =\n  (DESCRIPTION =\n    (ADDRESS = (PROTOCOL = TCPS)(HOST = 127.0.0.1)(PORT = {port}))\n    (CONNECT_DATA = (SERVICE_NAME = FREEPDB1))\n    (SECURITY = (SSL_SERVER_CERT_DN = \"{SYNTHETIC_DN}\"))\n  )\n"
        ),
    )
    .expect("write tnsnames.ora");
    wallet
}

fn toml_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn coreutil(name: &str) -> String {
    #[cfg(windows)]
    let (dirs, suffix): (&[&str], &str) = (
        &[r"C:\Program Files\Git\usr\bin", r"C:\Program Files\Git\bin"],
        ".exe",
    );
    #[cfg(not(windows))]
    let (dirs, suffix): (&[&str], &str) = (&["/usr/bin", "/bin"], "");
    for dir in dirs {
        let candidate = std::path::Path::new(dir).join(format!("{name}{suffix}"));
        if candidate.exists() {
            return candidate.to_string_lossy().replace('\\', "/");
        }
    }
    panic!("hermetic test requires `{name}` (looked in {dirs:?})");
}

fn profile_with_token_exec(
    wallet: &Path,
    token_exec: &[String],
) -> oraclemcp_config::ConnectionProfile {
    let token_exec = token_exec
        .iter()
        .map(|arg| toml_string(arg))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        r#"
        [[profiles]]
        name = "local-oci"
        connect_string = "LOCAL_TCPS"
        username = "OCITESTUSER"
        default_level = "READ_ONLY"
        max_level = "READ_ONLY"

        [profiles.oci]
        wallet_location = "{}"
        ssl_server_cert_dn = "{}"
        use_sni = false
        use_iam_token = true
        token_exec = [{token_exec}]
        "#,
        wallet.display(),
        SYNTHETIC_DN,
    );
    OracleMcpConfig::from_toml_str(&toml)
        .expect("synthetic OCI token_exec profile parses")
        .profiles
        .into_iter()
        .next()
        .expect("profile present")
}

fn run_with_cx<T>(f: impl Future<Output = T>) -> T {
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("runtime")
        .block_on(f)
}

#[test]
fn token_exec_runs_once_per_physical_tcps_connect_attempt() {
    let material = synthetic_material();
    let (port, rx, server) = spawn_tcps_terminator(material.clone(), 2);
    let lab_dir = unique_lab_dir();
    let wallet = write_lab_wallet(&lab_dir, port, &material);
    let counter = lab_dir.join("token-exec-count.txt");
    let counter_arg = counter.display().to_string().replace('\\', "/");
    let sh = coreutil("sh");
    let script = "count=$(cat \"$1\" 2>/dev/null || printf 0); count=$((count + 1)); printf '%s' \"$count\" > \"$1\"; printf 'header.payload.%s' \"$count\"";
    let profile = profile_with_token_exec(
        &wallet,
        &[
            sh,
            "-c".to_owned(),
            script.to_owned(),
            "oraclemcp-token-counter".to_owned(),
            counter_arg,
        ],
    );

    let mut ctx =
        build_session_context(&profile, None, None, false).expect("profile maps to options");
    inject_iam_token(&profile, &mut ctx.options)
        .expect("token_exec configures a refreshable source over wallet TCPS");
    assert!(ctx.options.iam_token.is_none());
    assert!(ctx.options.iam_token_source.is_some());
    assert!(
        !counter.exists(),
        "config load must not run token_exec before a physical connect"
    );
    let doctor_report = run_with_cx(async {
        let cx = Cx::current().expect("block_on installs a Cx");
        run_doctor(
            &cx,
            &DoctorContext {
                iam_token_source: Some(DoctorIamTokenSourceObservation {
                    source_kind: DoctorIamTokenSourceKind::Exec,
                    last_successful_invocation_unix: None,
                }),
                ..DoctorContext::default()
            },
        )
        .await
    });
    let iam_check = doctor_report
        .checks
        .iter()
        .find(|check| check.id == 14)
        .expect("IAM token check");
    assert!(
        iam_check.detail.contains("source_kind=exec"),
        "{}",
        iam_check.detail
    );
    assert!(
        iam_check
            .detail
            .contains("last_successful_invocation=not_observed_by_doctor"),
        "{}",
        iam_check.detail
    );
    assert!(
        !iam_check.detail.contains("re-read on every connect"),
        "{}",
        iam_check.detail
    );
    assert!(
        !counter.exists(),
        "doctor must report the source observation without invoking token_exec"
    );

    for attempt in 1..=2 {
        let rendered = run_with_cx({
            let options = ctx.options.clone();
            async move {
                let cx = Cx::current().expect("block_on installs a Cx");
                match RustOracleConnection::connect(&cx, options).await {
                    Ok(_) => panic!("terminator is not an Oracle protocol server"),
                    Err(err) => err.to_string(),
                }
            }
        });
        assert!(
            !rendered.contains("header.payload.")
                && !rendered.contains(&wallet.display().to_string()),
            "attempt {attempt} leaked token or wallet material: {rendered}"
        );
        assert_eq!(
            std::fs::read_to_string(&counter).expect("counter written"),
            attempt.to_string(),
            "token_exec must run exactly once for physical connect attempt {attempt}"
        );
    }

    let observations = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("terminator reports observations")
        .expect("terminator completed TLS twice");
    server.join().expect("terminator thread joins");
    assert_eq!(observations.len(), 2);
    for observed in observations {
        assert!(observed.peer_cert_count > 0, "{observed:?}");
        assert!(observed.post_tls_bytes > 0, "{observed:?}");
    }
}
