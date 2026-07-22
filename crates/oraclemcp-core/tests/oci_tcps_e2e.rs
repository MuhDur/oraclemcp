//! B2.4 server OCI/TCPS lane: prove a profile-backed, wallet-backed OCI path
//! reaches a local TCPS terminator through the real driver adapter.
//!
//! The terminator is a rustls server, not an Oracle protocol server. The expected
//! database outcome is therefore a connect failure after TLS. The acceptance
//! signal is the local listener's evidence: completed mutual TLS, a verified
//! client certificate from the generated synthetic wallet, and post-handshake
//! Oracle Net bytes from the thin driver.

use std::io::{ErrorKind, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::{build_session_context, inject_iam_token};
use oraclemcp_db::RustOracleConnection;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection};

const SYNTHETIC_CN: &str = "oracle-test.invalid";
const SYNTHETIC_DN: &str = "CN=oracle-test.invalid,O=Oracle Synthetic Test,C=US";
const TOKEN: &str =
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJvcmFjbGVtY3Atc3ludGhldGljIiwiZXhwIjoyNTM0MDIzMDB9.sig";

#[derive(Clone)]
struct SyntheticMaterial {
    cert_chain_pem: Vec<u8>,
    leaf_key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
}

#[derive(Debug)]
struct TerminatorObservation {
    peer_cert_count: usize,
    post_tls_bytes: usize,
}

fn synthetic_dn() -> rcgen::DistinguishedName {
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, SYNTHETIC_CN);
    dn.push(rcgen::DnType::OrganizationName, "Oracle Synthetic Test");
    dn.push(rcgen::DnType::CountryName, "US");
    dn
}

fn ca_cert() -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params =
        rcgen::CertificateParams::new(vec!["oraclemcp-test-ca".to_owned()]).expect("CA params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = synthetic_dn();
    let key = rcgen::KeyPair::generate().expect("CA key");
    let cert = params.self_signed(&key).expect("self-signed CA");
    (cert, key)
}

fn synthetic_material() -> SyntheticMaterial {
    let (ca_cert, ca_key) = ca_cert();
    let mut params =
        rcgen::CertificateParams::new(vec![SYNTHETIC_CN.to_owned()]).expect("leaf params");
    params.distinguished_name = synthetic_dn();
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf_cert = params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf signed by synthetic CA");
    let leaf_pem = leaf_cert.pem();
    let ca_pem = ca_cert.pem();
    let cert_chain_pem = format!("{leaf_pem}{ca_pem}").into_bytes();
    SyntheticMaterial {
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

fn server_config_trusting_client_ca(
    material: &SyntheticMaterial,
    client_ca_pem: &[u8],
) -> Arc<ServerConfig> {
    let mut roots = RootCertStore::empty();
    for cert in parse_certs(client_ca_pem) {
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

fn server_config(material: &SyntheticMaterial) -> Arc<ServerConfig> {
    server_config_trusting_client_ca(material, &material.ca_pem)
}

fn server_config_without_client_auth(material: &SyntheticMaterial) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            parse_certs(&material.cert_chain_pem),
            parse_key(&material.leaf_key_pem),
        )
        .expect("synthetic TCPS server config")
        .into()
}

fn observe_tcps_connection(
    mut sock: std::net::TcpStream,
    peer: std::net::SocketAddr,
    config: Arc<ServerConfig>,
) -> Result<TerminatorObservation, String> {
    if !peer.ip().is_loopback() {
        return Err(format!("refusing non-loopback peer: {peer}"));
    }
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    sock.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set write timeout: {e}"))?;
    let mut conn = ServerConnection::new(config).map_err(|e| format!("server connection: {e}"))?;
    conn.complete_io(&mut sock)
        .map_err(|e| format!("TLS handshake: {e}"))?;
    if conn.is_handshaking() {
        return Err("TLS handshake did not complete".to_owned());
    }
    let peer_cert_count = conn.peer_certificates().map_or(0, <[CertificateDer]>::len);
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let mut buf = [0u8; 512];
    let post_tls_bytes = tls.read(&mut buf).unwrap_or(0);
    Ok(TerminatorObservation {
        peer_cert_count,
        post_tls_bytes,
    })
}

fn spawn_tcps_terminator_with_config(
    config: Arc<ServerConfig>,
) -> (
    u16,
    mpsc::Receiver<Result<TerminatorObservation, String>>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback TCPS terminator");
    let port = listener.local_addr().expect("listener address").port();
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let outcome = (|| -> Result<TerminatorObservation, String> {
            let (sock, peer) = listener.accept().map_err(|e| format!("accept: {e}"))?;
            observe_tcps_connection(sock, peer, config)
        })();
        let _ = tx.send(outcome);
    });
    (port, rx, handle)
}

fn spawn_tcps_terminator(
    material: SyntheticMaterial,
) -> (
    u16,
    mpsc::Receiver<Result<TerminatorObservation, String>>,
    std::thread::JoinHandle<()>,
) {
    spawn_tcps_terminator_with_config(server_config(&material))
}

fn spawn_tcps_terminator_without_client_auth(
    material: SyntheticMaterial,
) -> (
    u16,
    mpsc::Receiver<Result<TerminatorObservation, String>>,
    std::thread::JoinHandle<()>,
) {
    spawn_tcps_terminator_with_config(server_config_without_client_auth(&material))
}

fn spawn_optional_tcps_terminator(
    material: SyntheticMaterial,
    wait_for_dial: Duration,
) -> (
    u16,
    mpsc::Receiver<Result<Option<TerminatorObservation>, String>>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback TCPS terminator");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let port = listener.local_addr().expect("listener address").port();
    let config = server_config(&material);
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let outcome = (|| -> Result<Option<TerminatorObservation>, String> {
            let deadline = Instant::now() + wait_for_dial;
            loop {
                match listener.accept() {
                    Ok((sock, peer)) => {
                        return observe_tcps_connection(sock, peer, config).map(Some);
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Ok(None);
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => return Err(format!("accept: {err}")),
                }
            }
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
        "oraclemcp-synthetic-tcps-{}-{nanos}",
        std::process::id()
    ))
}

fn descriptor(port: u16, description_prefix: &str) -> String {
    format!(
        "LOCAL_TCPS =\n  (DESCRIPTION =\n    {description_prefix}(ADDRESS = (PROTOCOL = TCPS)(HOST = 127.0.0.1)(PORT = {port}))\n    (CONNECT_DATA = (SERVICE_NAME = FREEPDB1))\n    (SECURITY = (SSL_SERVER_CERT_DN = \"{SYNTHETIC_DN}\"))\n  )\n"
    )
}

fn write_lab_wallet_with_descriptor(
    root: &Path,
    material: &SyntheticMaterial,
    tnsnames: &str,
) -> (PathBuf, PathBuf) {
    let wallet = root.join("wallet");
    std::fs::create_dir_all(&wallet).expect("create synthetic wallet dir");
    let ewallet = [
        material.cert_chain_pem.as_slice(),
        material.leaf_key_pem.as_slice(),
    ]
    .concat();
    std::fs::write(wallet.join("ewallet.pem"), ewallet).expect("write ewallet.pem");
    std::fs::write(wallet.join("tnsnames.ora"), tnsnames).expect("write tnsnames.ora");
    let token_file = root.join("iam-token.jwt");
    std::fs::write(&token_file, TOKEN).expect("write synthetic token file");
    (wallet, token_file)
}

fn write_lab_wallet(root: &Path, port: u16, material: &SyntheticMaterial) -> (PathBuf, PathBuf) {
    write_lab_wallet_with_descriptor(root, material, &descriptor(port, ""))
}

fn profile_with_sni(
    wallet: &Path,
    token_file: &Path,
    use_sni: Option<bool>,
) -> oraclemcp_config::ConnectionProfile {
    let use_sni_toml = use_sni
        .map(|value| format!("        use_sni = {value}\n"))
        .unwrap_or_default();
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
{}        use_iam_token = true
        token_file = "{}"
        "#,
        wallet.display(),
        SYNTHETIC_DN,
        use_sni_toml,
        token_file.display(),
    );
    OracleMcpConfig::from_toml_str(&toml)
        .expect("synthetic OCI profile parses")
        .profiles
        .into_iter()
        .next()
        .expect("profile present")
}

fn profile(wallet: &Path, token_file: &Path) -> oraclemcp_config::ConnectionProfile {
    profile_with_sni(wallet, token_file, Some(false))
}

fn child_env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} must be set")))
}

fn child_profile() -> oraclemcp_config::ConnectionProfile {
    profile_with_sni(
        &child_env_path("ORACLEMCP_D6_WALLET"),
        &child_env_path("ORACLEMCP_D6_TOKEN_FILE"),
        Some(false),
    )
}

fn connect_with_profile(profile: &oraclemcp_config::ConnectionProfile) -> String {
    let mut ctx =
        build_session_context(profile, None, None, false).expect("profile maps to options");
    inject_iam_token(profile, &mut ctx.options)
        .expect("token file configures a refreshable source over wallet TCPS");
    run_with_cx(async move {
        let cx = Cx::current().expect("block_on installs a Cx");
        match RustOracleConnection::connect(&cx, ctx.options).await {
            Ok(_) => panic!("terminator is not an Oracle protocol server"),
            Err(err) => err.to_string(),
        }
    })
}

fn run_ignored_child_with_root_override(
    test_name: &str,
    wallet: &Path,
    token_file: &Path,
    root_override: Option<(&str, &Path)>,
) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().expect("current test binary"));
    command
        .arg("--exact")
        .arg(test_name)
        .arg("--ignored")
        .arg("--nocapture")
        .env("ORACLEMCP_D6_WALLET", wallet)
        .env("ORACLEMCP_D6_TOKEN_FILE", token_file)
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR");
    if let Some((name, path)) = root_override {
        command.env(name, path);
    }
    command.output().expect("spawn ignored child test")
}

fn run_ignored_child(test_name: &str, wallet: &Path, token_file: &Path) -> std::process::Output {
    run_ignored_child_with_root_override(test_name, wallet, token_file, None)
}

fn assert_child_passed(label: &str, output: std::process::Output) {
    assert!(
        output.status.success(),
        "{label} child failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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
fn profile_wallet_and_iam_token_reach_local_tcps_terminator() {
    let material = synthetic_material();
    let (port, rx, server) = spawn_tcps_terminator(material.clone());
    let lab_dir = unique_lab_dir();
    let (wallet, token_file) = write_lab_wallet(&lab_dir, port, &material);
    let profile = profile(&wallet, &token_file);

    let mut ctx =
        build_session_context(&profile, None, None, false).expect("profile maps to options");
    inject_iam_token(&profile, &mut ctx.options)
        .expect("token file configures a refreshable source over wallet TCPS");
    assert_eq!(ctx.options.connect_string, "LOCAL_TCPS");
    assert!(
        ctx.options.iam_token.is_none(),
        "a server profile never stores the JWT"
    );
    assert!(ctx.options.iam_token_source.is_some());
    assert_eq!(
        ctx.options.wallet_location.as_deref(),
        Some(wallet.as_path())
    );
    assert_eq!(
        ctx.options.ssl_server_cert_dn.as_deref(),
        Some(SYNTHETIC_DN)
    );

    let connect_err = run_with_cx(async move {
        let cx = Cx::current().expect("block_on installs a Cx");
        match RustOracleConnection::connect(&cx, ctx.options).await {
            Ok(_) => panic!("terminator is not an Oracle protocol server"),
            Err(err) => err,
        }
    });
    let rendered = connect_err.to_string();
    assert!(
        !rendered.contains(TOKEN) && !rendered.contains(&wallet.display().to_string()),
        "connect error leaked secret material: {rendered}"
    );

    let observed = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("terminator reports observation")
        .expect("terminator completed TLS");
    server.join().expect("terminator thread joins");
    assert!(
        observed.peer_cert_count > 0,
        "mTLS terminator must verify a client certificate: {observed:?}"
    );
    assert!(
        observed.post_tls_bytes > 0,
        "driver must send Oracle Net bytes after TCPS: {observed:?}"
    );
    eprintln!(
        "{{\"suite\":\"oci_tcps_e2e\",\"phase\":\"assert\",\"event\":\"tcps_observed\",\"peer_cert_count\":{},\"post_tls_bytes\":{}}}",
        observed.peer_cert_count, observed.post_tls_bytes
    );
}

#[test]
#[ignore]
fn b5_unknown_issuer_with_retry_count_20_fails_inside_fast_budget() {
    let client_material = synthetic_material();
    let server_material = synthetic_material();
    let (port, rx, server) = spawn_tcps_terminator_without_client_auth(server_material);
    let lab_dir = unique_lab_dir();
    let retry_prefix = "    (RETRY_COUNT = 20)\n    (RETRY_DELAY = 1)\n    ";
    let (wallet, token_file) = write_lab_wallet_with_descriptor(
        &lab_dir,
        &client_material,
        &descriptor(port, retry_prefix),
    );

    let output = run_ignored_child(
        "b5_unknown_issuer_child_probe",
        wallet.as_path(),
        token_file.as_path(),
    );
    assert_child_passed("B5 UnknownIssuer timing", output);

    let _ = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("terminator saw the rejected TLS attempt");
    server.join().expect("terminator thread joins");
}

#[test]
#[ignore]
fn b5_unknown_issuer_child_probe() {
    let profile = child_profile();
    let started = Instant::now();
    let rendered = connect_with_profile(&profile);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "B5 UnknownIssuer should not burn retry_count=20/retry_delay=1 budget; elapsed={elapsed:?}; error={rendered}"
    );
    let lower = rendered.to_lowercase();
    assert!(
        lower.contains("unknownissuer") || lower.contains("unknown issuer"),
        "B5 expected UnknownIssuer, got: {rendered}"
    );
    assert!(
        !rendered.contains(TOKEN)
            && !rendered.contains(&child_env_path("ORACLEMCP_D6_WALLET").display().to_string()),
        "B5 connect error leaked secret material: {rendered}"
    );
}

#[test]
fn b6_ssl_cert_file_public_root_reaches_local_tcps_terminator() {
    let client_material = synthetic_material();
    let server_material = synthetic_material();
    let (port, rx, server) = spawn_tcps_terminator_without_client_auth(server_material.clone());
    let lab_dir = unique_lab_dir();
    std::fs::create_dir_all(&lab_dir).expect("create synthetic TCPS lab");
    let public_root = lab_dir.join("synthetic-public-root.pem");
    std::fs::write(&public_root, &server_material.ca_pem).expect("write synthetic public root");
    let (wallet, token_file) = write_lab_wallet(&lab_dir, port, &client_material);

    let output = run_ignored_child_with_root_override(
        "b6_ssl_cert_file_child_probe",
        wallet.as_path(),
        token_file.as_path(),
        Some(("SSL_CERT_FILE", public_root.as_path())),
    );
    assert_child_passed("B6 SSL_CERT_FILE root override", output);

    let observed = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("terminator reports B6 observation")
        .expect("B6 TLS terminator completed TLS");
    server.join().expect("terminator thread joins");
    assert!(
        observed.post_tls_bytes > 0,
        "B6 SSL_CERT_FILE root override must allow TCPS before Oracle Net failure: {observed:?}"
    );
}

#[test]
#[ignore]
fn b6_ssl_cert_file_child_probe() {
    let profile = child_profile();
    let rendered = connect_with_profile(&profile);
    let lower = rendered.to_lowercase();
    assert!(
        !lower.contains("unknownissuer") && !lower.contains("unknown issuer"),
        "B6 SSL_CERT_FILE root override did not trust the synthetic public root: {rendered}"
    );
    assert!(
        !rendered.contains(TOKEN)
            && !rendered.contains(&child_env_path("ORACLEMCP_D6_WALLET").display().to_string()),
        "B6 connect error leaked secret material: {rendered}"
    );
}

#[test]
fn b6_ssl_cert_dir_public_root_reaches_local_tcps_terminator() {
    let client_material = synthetic_material();
    let server_material = synthetic_material();
    let (port, rx, server) = spawn_tcps_terminator_without_client_auth(server_material.clone());
    let lab_dir = unique_lab_dir();
    let public_root_dir = lab_dir.join("synthetic-public-roots");
    std::fs::create_dir_all(&public_root_dir).expect("create synthetic public root directory");
    std::fs::write(
        public_root_dir.join("synthetic-public-root.pem"),
        &server_material.ca_pem,
    )
    .expect("write synthetic public root in directory");
    let (wallet, token_file) = write_lab_wallet(&lab_dir, port, &client_material);

    let output = run_ignored_child_with_root_override(
        "b6_ssl_cert_file_child_probe",
        wallet.as_path(),
        token_file.as_path(),
        Some(("SSL_CERT_DIR", public_root_dir.as_path())),
    );
    assert_child_passed("B6 SSL_CERT_DIR root override", output);

    let observed = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("terminator reports B6 directory observation")
        .expect("B6 directory TLS terminator completed TLS");
    server.join().expect("terminator thread joins");
    assert!(
        observed.post_tls_bytes > 0,
        "B6 SSL_CERT_DIR root override must allow TCPS before Oracle Net failure: {observed:?}"
    );
}

#[test]
fn p2_4_wallet_profile_without_explicit_sni_records_current_default_red() {
    let material = synthetic_material();
    let (port, rx, server) =
        spawn_optional_tcps_terminator(material.clone(), Duration::from_millis(1500));
    let lab_dir = unique_lab_dir();
    let (wallet, token_file) = write_lab_wallet(&lab_dir, port, &material);
    let profile = profile_with_sni(&wallet, &token_file, None);
    let mut ctx =
        build_session_context(&profile, None, None, false).expect("profile maps to options");
    inject_iam_token(&profile, &mut ctx.options)
        .expect("token file configures a refreshable source over wallet TCPS");
    assert_eq!(
        ctx.options.use_sni, None,
        "the server profile must leave SNI unset for this P2-4 lane probe"
    );

    let rendered = run_with_cx(async move {
        let cx = Cx::current().expect("block_on installs a Cx");
        match RustOracleConnection::connect(&cx, ctx.options).await {
            Ok(_) => panic!("terminator is not an Oracle protocol server"),
            Err(err) => err.to_string(),
        }
    });
    assert!(
        rendered.contains("use_sni=true cannot be honored"),
        "P2-4 current-red probe expected adapter-forced SNI failure, got: {rendered}"
    );
    let observed = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("terminator reports whether the driver dialed")
        .expect("terminator probe did not fail");
    server.join().expect("terminator thread joins");
    assert!(
        observed.is_none(),
        "current P2-4 red condition should fail before dialing the local TCPS terminator: {observed:?}"
    );
}
