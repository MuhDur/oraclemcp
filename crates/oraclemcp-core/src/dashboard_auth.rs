//! Browser dashboard local pairing and CSRF protection.
//!
//! The dashboard is same-origin HTTP, but loopback is not a browser security
//! boundary. This module owns the local bootstrap ticket, the HttpOnly session
//! cookie, and per-route action tickets used by `/operator/v1` POST routes.
//!
//! The bootstrap code is a **body-only** credential (bead oraclemcp-l6xn). It is
//! never placed in a URL — not in the query and not in the fragment — because a
//! URL is readable from browser history and from any extension holding `tabs` or
//! `webNavigation` permission, which observe a navigation before page script can
//! scrub it. The operator pastes the code into a script-free same-origin form,
//! and the server accepts it only from that `POST` body.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use asupersync::http::h1::http_client::{HttpClient, ParsedUrl, Scheme};
use asupersync::http::h1::types::Method;
#[cfg(test)]
use asupersync::runtime::RuntimeBuilder;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use oraclemcp_audit::{ct_eq, hmac_sha256};

use crate::operator_protocol::OPERATOR_ROUTE_SPECS;

/// One-time local bootstrap route used by `oraclemcp dashboard`. `GET` serves
/// the script-free pairing form; `POST` exchanges the code in the request body.
pub const DASHBOARD_PAIR_PATH: &str = "/dashboard/pair";
/// Form field the pairing page returns the one-time bootstrap code in. The code
/// is only ever accepted from a `POST` body, never from the request target.
pub const DASHBOARD_PAIRING_CODE_FIELD: &str = "pairing_code";
/// Same-origin session-info route used by the SPA to get CSRF/action tickets.
pub const DASHBOARD_SESSION_PATH: &str = "/dashboard/session";
/// Liveness path probed before minting a dashboard pairing ticket (B3.1 / D1).
pub const DASHBOARD_HTTP_PROBE_PATH: &str = "/healthz";
/// Request challenge used to bind pairing to one live listener instance.
pub const DASHBOARD_PROBE_CHALLENGE_HEADER: &str = "x-oraclemcp-dashboard-challenge";
/// Hash of the not-yet-released pairing secret covered by the listener proof.
pub const DASHBOARD_PROBE_TOKEN_HASH_HEADER: &str = "x-oraclemcp-dashboard-token-sha256";
/// Listener instance identity returned only for a well-formed pairing probe.
pub const DASHBOARD_INSTANCE_HEADER: &str = "x-oraclemcp-dashboard-instance";
/// Listener-configured audience returned with the pairing proof.
pub const DASHBOARD_AUDIENCE_HEADER: &str = "x-oraclemcp-dashboard-audience";
/// HMAC capability proof binding the challenge, token hash, and audience.
pub const DASHBOARD_PROOF_HEADER: &str = "x-oraclemcp-dashboard-proof";
/// Short timeout for the pre-mint dashboard HTTP probe.
pub const DASHBOARD_HTTP_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Dashboard session cookie. It is deliberately distinct from the MCP cookie.
pub const DASHBOARD_SESSION_COOKIE: &str = "oraclemcp_dashboard_session";
/// Header carrying the session CSRF token for dashboard POST requests.
pub const DASHBOARD_CSRF_HEADER: &str = "x-oraclemcp-csrf";
/// Header carrying the route-scoped dashboard action ticket.
pub const DASHBOARD_ACTION_TICKET_HEADER: &str = "x-oraclemcp-action-ticket";

/// Lifetime of a one-time pairing code, from mint to exchange.
pub const DASHBOARD_PAIRING_TTL_SECONDS: u64 = 60;
const DASHBOARD_SESSION_TTL_SECONDS: u64 = 12 * 60 * 60;
const TOKEN_BYTES: usize = 32;

/// A freshly minted local pairing ticket.
pub struct DashboardPairingTicket {
    /// URL to open in the browser. Deliberately carries **no** secret, so it is
    /// safe in browser history, extension `tabs`/`webNavigation` events, and
    /// `Referer` (bead oraclemcp-l6xn).
    pub url: String,
    /// The one-time bootstrap code, pasted into the pairing form and returned
    /// to the server in a POST body. Never place this in a URL.
    pub code: String,
    /// Expiration as a Unix timestamp.
    pub expires_unix: u64,
    /// The 0600 ticket file consumed by the running service.
    pub ticket_file: PathBuf,
}

/// Opaque preflight state. The raw token remains in the CLI process until a
/// listener answers the instance-bound probe.
pub struct DashboardPairingRequest {
    audience: String,
    token: String,
    token_sha256: String,
    challenge: String,
}

impl fmt::Debug for DashboardPairingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DashboardPairingRequest")
            .field("audience", &self.audience)
            .field("token", &"<redacted>")
            .field("token_sha256", &self.token_sha256)
            .field("challenge", &self.challenge)
            .finish()
    }
}

/// Capability proof returned by the probed listener. It is useful only with
/// the still-private pairing token whose hash it covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DashboardListenerProof {
    instance_id: String,
    audience: String,
    proof: String,
}

impl fmt::Debug for DashboardPairingTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DashboardPairingTicket")
            .field("url", &self.url)
            .field("code", &"<redacted>")
            .field("expires_unix", &self.expires_unix)
            .field("ticket_file", &self.ticket_file)
            .finish()
    }
}

/// Session cookie minted after a successful ticket exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DashboardLogin {
    pub session_cookie: String,
    pub expires_unix: u64,
}

/// A route-scoped action ticket visible to the same-origin SPA.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DashboardActionTicket {
    pub method: String,
    pub path: String,
    pub ticket: String,
}

/// Same-origin session info returned to the SPA after cookie auth succeeds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DashboardSessionView {
    pub csrf_token: String,
    pub csrf_header: &'static str,
    pub action_ticket_header: &'static str,
    pub expires_unix: u64,
    pub action_tickets: Vec<DashboardActionTicket>,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DashboardAuthError {
    #[error("dashboard pairing ticket is missing")]
    MissingTicket,
    #[error("dashboard pairing ticket is invalid")]
    InvalidTicket,
    #[error("dashboard pairing ticket expired")]
    ExpiredTicket,
    #[error("dashboard pairing ticket is bound to a different listener or audience")]
    ListenerBindingMismatch,
    #[error("dashboard session cookie is missing")]
    MissingSession,
    #[error("dashboard session is invalid or expired")]
    InvalidSession,
    #[error("dashboard CSRF token is missing")]
    MissingCsrf,
    #[error("dashboard CSRF token is invalid")]
    InvalidCsrf,
    #[error("dashboard action ticket is missing")]
    MissingActionTicket,
    #[error("dashboard action ticket is invalid")]
    InvalidActionTicket,
    #[error("{operation} failed: {message}")]
    Io {
        operation: &'static str,
        message: String,
    },
    #[error(
        "no oraclemcp HTTP service at {base_url} — start it with `oraclemcp service install` or `oraclemcp serve --listen …` ({detail})"
    )]
    ServiceUnreachable { base_url: String, detail: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TicketFile {
    schema_version: u8,
    token_sha256: String,
    challenge: String,
    listener_instance_id: String,
    listener_proof: String,
    audience: String,
    issued_unix: u64,
    expires_unix: u64,
    purpose: String,
}

#[derive(Clone, Debug)]
struct DashboardSession {
    id: String,
    csrf_token: String,
    expires_at: Instant,
    expires_unix: u64,
}

/// In-memory dashboard session store plus the runtime-dir ticket reader.
pub struct DashboardAuth {
    ticket_dir: PathBuf,
    instance_id: String,
    instance_secret: [u8; TOKEN_BYTES],
    audience: String,
    sessions: Mutex<HashMap<String, DashboardSession>>,
    session_ttl: Duration,
}

impl DashboardAuth {
    /// Build dashboard auth against the shared runtime ticket directory.
    pub fn new(ticket_dir: PathBuf, audience: &str) -> Result<Self, DashboardAuthError> {
        let audience = canonical_dashboard_audience(audience)?;
        let mut instance_secret = [0_u8; TOKEN_BYTES];
        getrandom::getrandom(&mut instance_secret).map_err(|error| DashboardAuthError::Io {
            operation: "read OS randomness",
            message: error.to_string(),
        })?;
        Ok(Self {
            ticket_dir,
            instance_id: sha256_hex(&instance_secret),
            instance_secret,
            audience,
            sessions: Mutex::new(HashMap::new()),
            session_ttl: Duration::from_secs(DASHBOARD_SESSION_TTL_SECONDS),
        })
    }

    /// Runtime directory this instance consumes one-time tickets from.
    #[must_use]
    pub fn ticket_dir(&self) -> &Path {
        &self.ticket_dir
    }

    /// Stable, non-secret identity for this process-local listener instance.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Canonical scheme/host/port audience this listener accepts pairing for.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Produce an instance capability proof for a pre-release token hash.
    pub fn pairing_probe_proof(&self, challenge: &str, token_sha256: &str) -> Option<String> {
        if !is_lower_hex_64(challenge) || !is_lower_hex_64(token_sha256) {
            return None;
        }
        Some(self.proof_for(challenge, token_sha256))
    }

    /// Consume one local pairing ticket and mint an HttpOnly dashboard cookie.
    pub fn exchange_ticket(
        &self,
        token: &str,
        audience: &str,
        secure_cookie: bool,
    ) -> Result<DashboardLogin, DashboardAuthError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(DashboardAuthError::MissingTicket);
        }
        let token_hash = sha256_hex(token.as_bytes());
        let path = ticket_path(&self.ticket_dir, &token_hash);
        let raw = fs::read_to_string(&path).map_err(|_| DashboardAuthError::InvalidTicket)?;
        let ticket: TicketFile =
            serde_json::from_str(&raw).map_err(|_| DashboardAuthError::InvalidTicket)?;
        if ticket.schema_version != 2
            || ticket.purpose != "oraclemcp-dashboard-pairing"
            || ticket.token_sha256 != token_hash
        {
            return Err(DashboardAuthError::InvalidTicket);
        }
        let audience = canonical_dashboard_audience(audience)?;
        let expected_proof = self.proof_for(&ticket.challenge, &ticket.token_sha256);
        if ticket.listener_instance_id != self.instance_id
            || ticket.audience != self.audience
            || audience != self.audience
            || !ct_eq(ticket.listener_proof.as_bytes(), expected_proof.as_bytes())
        {
            return Err(DashboardAuthError::ListenerBindingMismatch);
        }
        if unix_now() > ticket.expires_unix {
            let _ = fs::remove_file(&path);
            return Err(DashboardAuthError::ExpiredTicket);
        }
        fs::remove_file(&path).map_err(|_| DashboardAuthError::InvalidTicket)?;

        let id = random_hex(TOKEN_BYTES)?;
        let csrf_token = format!("csrf-{}", random_hex(TOKEN_BYTES)?);
        let expires_unix = unix_now().saturating_add(self.session_ttl.as_secs());
        let session = DashboardSession {
            id: id.clone(),
            csrf_token,
            expires_at: Instant::now() + self.session_ttl,
            expires_unix,
        };
        self.sessions.lock().insert(id.clone(), session);
        Ok(DashboardLogin {
            session_cookie: dashboard_session_cookie_header(
                &id,
                self.session_ttl.as_secs(),
                secure_cookie,
            ),
            expires_unix,
        })
    }

    fn proof_for(&self, challenge: &str, token_sha256: &str) -> String {
        let message =
            dashboard_probe_message(challenge, token_sha256, &self.audience, &self.instance_id);
        hex_bytes(&hmac_sha256(&self.instance_secret, &message))
    }

    /// Return same-origin session info for a valid dashboard session cookie.
    pub fn session_view(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<DashboardSessionView, DashboardAuthError> {
        let session = self.valid_session(cookie_header)?;
        Ok(session_view(&session))
    }

    /// Return a non-secret binding for server-side authorities scoped to this
    /// exact browser session. The raw cookie/session id never leaves this type.
    pub(crate) fn session_binding(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<String, DashboardAuthError> {
        let session = self.valid_session(cookie_header)?;
        let mut hasher = Sha256::new();
        hasher.update(b"oraclemcp.dashboard.session-binding.v1\0");
        hasher.update(session.id.as_bytes());
        Ok(format!(
            "dashboard-session-sha256:{}",
            hex_bytes(&hasher.finalize())
        ))
    }

    /// Validate a dashboard POST against the cookie, CSRF token, and scoped
    /// action ticket for the requested route.
    pub fn validate_action(
        &self,
        cookie_header: Option<&str>,
        csrf_header: Option<&str>,
        action_ticket_header: Option<&str>,
        method: &str,
        path: &str,
    ) -> Result<(), DashboardAuthError> {
        let session = self.valid_session(cookie_header)?;
        let csrf = csrf_header
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(DashboardAuthError::MissingCsrf)?;
        if !constant_time_eq(csrf.as_bytes(), session.csrf_token.as_bytes()) {
            return Err(DashboardAuthError::InvalidCsrf);
        }
        let action_ticket = action_ticket_header
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(DashboardAuthError::MissingActionTicket)?;
        if !is_dashboard_action_route(method, path) {
            return Err(DashboardAuthError::InvalidActionTicket);
        }
        let expected = action_ticket_for(&session, method, path);
        if !constant_time_eq(action_ticket.as_bytes(), expected.as_bytes()) {
            return Err(DashboardAuthError::InvalidActionTicket);
        }
        Ok(())
    }

    fn valid_session(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<DashboardSession, DashboardAuthError> {
        let session_id = cookie_header
            .and_then(|cookie| cookie_value(cookie, DASHBOARD_SESSION_COOKIE))
            .ok_or(DashboardAuthError::MissingSession)?;
        let now = Instant::now();
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, session| session.expires_at > now);
        sessions
            .get(session_id)
            .cloned()
            .ok_or(DashboardAuthError::InvalidSession)
    }
}

impl fmt::Debug for DashboardAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DashboardAuth")
            .field("ticket_dir", &self.ticket_dir)
            .field("instance_id", &self.instance_id)
            .field("instance_secret", &"<redacted>")
            .field("audience", &self.audience)
            .field("session_ttl", &self.session_ttl)
            .finish_non_exhaustive()
    }
}

/// Directory shared by the CLI shell and the running service for one-time
/// dashboard pairing tickets.
#[must_use]
pub fn default_dashboard_ticket_dir() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("oraclemcp");
    }
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_owned());
    std::env::temp_dir().join(format!("oraclemcp-dashboard-{user}"))
}

/// Prepare a pairing request without releasing its raw bearer to any listener.
pub fn prepare_dashboard_pairing(
    base_url: &str,
) -> Result<DashboardPairingRequest, DashboardAuthError> {
    let audience = canonical_dashboard_audience(base_url)?;
    let token = random_hex(TOKEN_BYTES)?;
    Ok(DashboardPairingRequest {
        audience,
        token_sha256: sha256_hex(token.as_bytes()),
        token,
        challenge: random_hex(TOKEN_BYTES)?,
    })
}

/// Probe the requested listener for a capability proof bound to the still
/// private pairing token. Uses `/healthz` (liveness even when the DB is down).
pub async fn probe_dashboard_http_service(
    cx: &Cx,
    request: &DashboardPairingRequest,
) -> Result<DashboardListenerProof, DashboardAuthError> {
    let base = &request.audience;
    let probe_url = format!(
        "{}{}",
        base.trim_end_matches('/'),
        DASHBOARD_HTTP_PROBE_PATH
    );
    let timeout = DASHBOARD_HTTP_PROBE_TIMEOUT;
    let base_owned = base.to_owned();
    // Pure async: the caller owns the runtime/reactor. The single sync->async
    // boundary for this CLI path lives in `main::block_on_connect` (a library
    // must not build its own runtime — asupersync idiom: `&Cx` first, block_on
    // only at the outermost process edge).
    let client = HttpClient::new();
    let response = asupersync::time::timeout(cx.now(), timeout, async {
        client
            .request(
                cx,
                Method::Get,
                &probe_url,
                vec![
                    (
                        DASHBOARD_PROBE_CHALLENGE_HEADER.to_owned(),
                        request.challenge.clone(),
                    ),
                    (
                        DASHBOARD_PROBE_TOKEN_HASH_HEADER.to_owned(),
                        request.token_sha256.clone(),
                    ),
                ],
                Vec::new(),
            )
            .await
    })
    .await
    .map_err(|_| DashboardAuthError::ServiceUnreachable {
        base_url: base_owned.clone(),
        detail: "probe timed out".to_owned(),
    })?
    .map_err(|e| DashboardAuthError::ServiceUnreachable {
        base_url: base_owned.clone(),
        detail: e.to_string(),
    })?;
    if !(200..300).contains(&response.status) {
        return Err(DashboardAuthError::ServiceUnreachable {
            base_url: base_owned,
            detail: format!("HTTP {}", response.status),
        });
    }
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim().to_owned())
    };
    let instance_id = header(DASHBOARD_INSTANCE_HEADER);
    let audience = header(DASHBOARD_AUDIENCE_HEADER);
    let proof = header(DASHBOARD_PROOF_HEADER);
    let (Some(instance_id), Some(audience), Some(proof)) = (instance_id, audience, proof) else {
        return Err(DashboardAuthError::ServiceUnreachable {
            base_url: base_owned,
            detail: "listener did not return an oraclemcp pairing proof".to_owned(),
        });
    };
    if !is_lower_hex_64(&instance_id)
        || !is_lower_hex_64(&proof)
        || canonical_dashboard_audience(&audience).ok().as_deref()
            != Some(request.audience.as_str())
    {
        return Err(DashboardAuthError::ServiceUnreachable {
            base_url: base_owned,
            detail: "listener returned an invalid or mismatched pairing proof".to_owned(),
        });
    }
    Ok(DashboardListenerProof {
        instance_id,
        audience,
        proof,
    })
}

/// Create a 0600, short-lived local pairing ticket and return the browser URL.
pub fn mint_dashboard_pairing_ticket(
    ticket_dir: &Path,
    request: DashboardPairingRequest,
    listener: DashboardListenerProof,
) -> Result<DashboardPairingTicket, DashboardAuthError> {
    if listener.audience != request.audience
        || !is_lower_hex_64(&listener.instance_id)
        || !is_lower_hex_64(&listener.proof)
    {
        return Err(DashboardAuthError::ListenerBindingMismatch);
    }
    prepare_ticket_dir(ticket_dir)?;
    let issued_unix = unix_now();
    let expires_unix = issued_unix.saturating_add(DASHBOARD_PAIRING_TTL_SECONDS);
    let ticket = TicketFile {
        schema_version: 2,
        token_sha256: request.token_sha256.clone(),
        challenge: request.challenge,
        listener_instance_id: listener.instance_id,
        listener_proof: listener.proof,
        audience: listener.audience,
        issued_unix,
        expires_unix,
        purpose: "oraclemcp-dashboard-pairing".to_owned(),
    };
    let ticket_file = ticket_path(ticket_dir, &request.token_sha256);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&ticket_file)
        .map_err(|e| DashboardAuthError::Io {
            operation: "create dashboard pairing ticket",
            message: e.to_string(),
        })?;
    let body = serde_json::to_vec(&ticket).map_err(|e| DashboardAuthError::Io {
        operation: "serialize dashboard pairing ticket",
        message: e.to_string(),
    })?;
    file.write_all(&body).map_err(|e| DashboardAuthError::Io {
        operation: "write dashboard pairing ticket",
        message: e.to_string(),
    })?;
    file.sync_all().map_err(|e| DashboardAuthError::Io {
        operation: "sync dashboard pairing ticket",
        message: e.to_string(),
    })?;
    // The bootstrap secret is NOT in this URL. It travels only in the pairing
    // form's POST body, so it never reaches the request target, an access log,
    // `Referer`, browser history, or an extension's tab/navigation events.
    let url = format!(
        "{}{}",
        request.audience.trim_end_matches('/'),
        DASHBOARD_PAIR_PATH,
    );
    Ok(DashboardPairingTicket {
        url,
        code: request.token,
        expires_unix,
        ticket_file,
    })
}

#[cfg(test)]
pub(crate) fn mint_dashboard_pairing_ticket_for_test(
    auth: &DashboardAuth,
) -> Result<DashboardPairingTicket, DashboardAuthError> {
    let request = prepare_dashboard_pairing(auth.audience())?;
    let proof = DashboardListenerProof {
        instance_id: auth.instance_id().to_owned(),
        audience: auth.audience().to_owned(),
        proof: auth
            .pairing_probe_proof(&request.challenge, &request.token_sha256)
            .ok_or(DashboardAuthError::InvalidTicket)?,
    };
    mint_dashboard_pairing_ticket(auth.ticket_dir(), request, proof)
}

fn prepare_ticket_dir(ticket_dir: &Path) -> Result<(), DashboardAuthError> {
    fs::create_dir_all(ticket_dir).map_err(|e| DashboardAuthError::Io {
        operation: "create dashboard ticket directory",
        message: e.to_string(),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(ticket_dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            DashboardAuthError::Io {
                operation: "secure dashboard ticket directory",
                message: e.to_string(),
            }
        })?;
    }
    Ok(())
}

fn ticket_path(ticket_dir: &Path, token_sha256: &str) -> PathBuf {
    ticket_dir.join(format!("dashboard-ticket-{token_sha256}.json"))
}

/// Normalize and restrict dashboard bootstrap to an exact loopback audience.
/// The canonical form always includes the effective port so scheme/port drift
/// cannot silently retarget a ticket.
pub fn canonical_dashboard_audience(base_url: &str) -> Result<String, DashboardAuthError> {
    let parsed = ParsedUrl::parse(base_url.trim()).map_err(|error| {
        DashboardAuthError::ServiceUnreachable {
            base_url: base_url.to_owned(),
            detail: error.to_string(),
        }
    })?;
    if parsed.path != "/" {
        return Err(DashboardAuthError::ServiceUnreachable {
            base_url: base_url.to_owned(),
            detail: "dashboard base URL must not contain a path, query, or fragment".to_owned(),
        });
    }
    let host = parsed.host.to_ascii_lowercase();
    let ip_host = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host == "localhost"
        || ip_host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !loopback {
        return Err(DashboardAuthError::ServiceUnreachable {
            base_url: base_url.to_owned(),
            detail: "dashboard pairing is restricted to an exact loopback listener".to_owned(),
        });
    }
    let scheme = match parsed.scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    Ok(format!("{scheme}://{host}:{}", parsed.port))
}

fn dashboard_probe_message(
    challenge: &str,
    token_sha256: &str,
    audience: &str,
    instance_id: &str,
) -> Vec<u8> {
    [
        b"oraclemcp.dashboard.listener-proof.v1\0".as_slice(),
        challenge.as_bytes(),
        b"\0",
        token_sha256.as_bytes(),
        b"\0",
        audience.as_bytes(),
        b"\0",
        instance_id.as_bytes(),
    ]
    .concat()
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn session_view(session: &DashboardSession) -> DashboardSessionView {
    DashboardSessionView {
        csrf_token: session.csrf_token.clone(),
        csrf_header: DASHBOARD_CSRF_HEADER,
        action_ticket_header: DASHBOARD_ACTION_TICKET_HEADER,
        expires_unix: session.expires_unix,
        action_tickets: OPERATOR_ROUTE_SPECS
            .iter()
            .filter(|spec| spec.browser_post)
            .map(|spec| DashboardActionTicket {
                method: spec.method.to_owned(),
                path: spec.path.to_owned(),
                ticket: action_ticket_for(session, spec.method, spec.path),
            })
            .collect(),
    }
}

fn is_dashboard_action_route(method: &str, path: &str) -> bool {
    OPERATOR_ROUTE_SPECS
        .iter()
        .any(|spec| spec.browser_post && spec.method == method && spec.path == path)
}

fn dashboard_session_cookie_header(session_id: &str, max_age_seconds: u64, secure: bool) -> String {
    let mut header = format!(
        "{DASHBOARD_SESSION_COOKIE}={session_id}; Path=/; Max-Age={max_age_seconds}; HttpOnly; SameSite=Strict"
    );
    if secure {
        header.push_str("; Secure");
    }
    header
}

fn action_ticket_for(session: &DashboardSession, method: &str, path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"oraclemcp.dashboard.action.v1\0");
    hasher.update(session.id.as_bytes());
    hasher.update(b"\0");
    hasher.update(session.csrf_token.as_bytes());
    hasher.update(b"\0");
    hasher.update(method.to_ascii_uppercase().as_bytes());
    hasher.update(b"\0");
    hasher.update(path.as_bytes());
    format!("dashboard-action-sha256:{}", hex_bytes(&hasher.finalize()))
}

fn cookie_value<'a>(cookie: &'a str, name: &str) -> Option<&'a str> {
    cookie.split(';').find_map(|part| {
        let (candidate, value) = part.trim().split_once('=')?;
        (candidate == name && !value.is_empty()).then_some(value)
    })
}

fn random_hex(bytes: usize) -> Result<String, DashboardAuthError> {
    let mut raw = vec![0u8; bytes];
    getrandom::getrandom(&mut raw).map_err(|e| DashboardAuthError::Io {
        operation: "read OS randomness",
        message: e.to_string(),
    })?;
    Ok(hex_bytes(&raw))
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    hex_bytes(&digest)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let max = a.len().max(b.len());
    for index in 0..max {
        diff |=
            usize::from(a.get(index).copied().unwrap_or(0) ^ b.get(index).copied().unwrap_or(0));
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.push("../../target/tmp/dashboard-auth-tests");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        dir.push(format!("{}-{nanos}-{name}", std::process::id()));
        dir
    }

    fn auth_and_ticket(dir: PathBuf, base_url: &str) -> (DashboardAuth, DashboardPairingTicket) {
        let auth = DashboardAuth::new(dir.clone(), base_url).expect("dashboard auth builds");
        let request = prepare_dashboard_pairing(base_url).expect("pairing prepares");
        let proof = DashboardListenerProof {
            instance_id: auth.instance_id().to_owned(),
            audience: auth.audience().to_owned(),
            proof: auth
                .pairing_probe_proof(&request.challenge, &request.token_sha256)
                .expect("well-formed probe proof"),
        };
        let ticket =
            mint_dashboard_pairing_ticket(&dir, request, proof).expect("pairing ticket mints");
        (auth, ticket)
    }

    fn listener_proof(
        auth: &DashboardAuth,
        request: &DashboardPairingRequest,
    ) -> DashboardListenerProof {
        DashboardListenerProof {
            instance_id: auth.instance_id().to_owned(),
            audience: auth.audience().to_owned(),
            proof: auth
                .pairing_probe_proof(&request.challenge, &request.token_sha256)
                .expect("well-formed probe proof"),
        }
    }

    #[test]
    fn pairing_ticket_is_single_use_and_hash_only() {
        let dir = test_dir("single-use");
        let (auth, ticket) = auth_and_ticket(dir, "http://127.0.0.1:7070");
        let token = &ticket.code;
        let file = fs::read_to_string(&ticket.ticket_file).expect("ticket file is readable");
        assert!(
            !file.contains(token),
            "ticket file stores only a hash, not the bootstrap secret"
        );

        let login = auth
            .exchange_ticket(token, auth.audience(), false)
            .expect("first exchange works");
        assert!(
            login.session_cookie.contains("HttpOnly")
                && login.session_cookie.contains("SameSite=Strict")
        );
        assert!(matches!(
            auth.exchange_ticket(token, auth.audience(), false),
            Err(DashboardAuthError::InvalidTicket)
        ));
    }

    #[test]
    fn csrf_and_action_ticket_are_route_scoped() {
        let dir = test_dir("scoped");
        let (auth, ticket) = auth_and_ticket(dir, "http://127.0.0.1:7070");
        let token = &ticket.code;
        let login = auth
            .exchange_ticket(token, auth.audience(), false)
            .expect("login works");
        let cookie_pair = login.session_cookie.split(';').next().expect("cookie pair");
        let view = auth
            .session_view(Some(cookie_pair))
            .expect("session view works");
        let preview = view
            .action_tickets
            .iter()
            .find(|ticket| ticket.path == "/operator/v1/actions/preview")
            .expect("preview ticket");
        let lane_cancel = view
            .action_tickets
            .iter()
            .filter(|ticket| ticket.path == "/operator/v1/lanes/cancel")
            .collect::<Vec<_>>();
        assert_eq!(lane_cancel.len(), 1, "lane cancel has exactly one ticket");
        assert_eq!(lane_cancel[0].method, "POST");

        auth.validate_action(
            Some(cookie_pair),
            Some(&view.csrf_token),
            Some(&preview.ticket),
            "POST",
            "/operator/v1/actions/preview",
        )
        .expect("matching route validates");
        auth.validate_action(
            Some(cookie_pair),
            Some(&view.csrf_token),
            Some(&lane_cancel[0].ticket),
            "POST",
            "/operator/v1/lanes/cancel",
        )
        .expect("lane-cancel ticket validates for its route");
        assert!(matches!(
            auth.validate_action(
                Some(cookie_pair),
                Some(&view.csrf_token),
                Some(&preview.ticket),
                "POST",
                "/operator/v1/actions/execute",
            ),
            Err(DashboardAuthError::InvalidActionTicket)
        ));
        assert!(matches!(
            auth.validate_action(
                Some(cookie_pair),
                Some("csrf-wrong"),
                Some(&preview.ticket),
                "POST",
                "/operator/v1/actions/preview",
            ),
            Err(DashboardAuthError::InvalidCsrf)
        ));
        let unissued_get_ticket = action_ticket_for(
            &auth
                .valid_session(Some(cookie_pair))
                .expect("session remains valid"),
            "GET",
            "/operator/v1/health",
        );
        assert!(matches!(
            auth.validate_action(
                Some(cookie_pair),
                Some(&view.csrf_token),
                Some(&unissued_get_ticket),
                "GET",
                "/operator/v1/health",
            ),
            Err(DashboardAuthError::InvalidActionTicket)
        ));
    }

    #[test]
    fn pairing_ticket_is_bound_to_exact_listener_instance_and_audience() {
        let dir = test_dir("listener-binding");
        let base = "http://127.0.0.1:7070";
        let intended = DashboardAuth::new(dir.clone(), base).expect("intended listener builds");
        let other_instance = DashboardAuth::new(dir.clone(), base).expect("other listener builds");
        let request = prepare_dashboard_pairing(base).expect("pairing prepares");
        let proof = listener_proof(&intended, &request);
        let ticket = mint_dashboard_pairing_ticket(&dir, request, proof).expect("ticket mints");
        let token = &ticket.code;

        assert!(matches!(
            other_instance.exchange_ticket(token, other_instance.audience(), false),
            Err(DashboardAuthError::ListenerBindingMismatch)
        ));
        intended
            .exchange_ticket(token, intended.audience(), false)
            .expect("binding failure does not consume intended ticket");

        let drifted =
            DashboardAuth::new(dir, "http://127.0.0.1:7071").expect("drifted listener builds");
        assert_ne!(drifted.audience(), intended.audience());
    }

    #[test]
    fn listener_proof_cannot_be_replayed_for_a_substituted_pairing_token() {
        let dir = test_dir("proof-substitution");
        let base = "http://127.0.0.1:7070";
        let auth = DashboardAuth::new(dir.clone(), base).expect("listener builds");
        let mut request = prepare_dashboard_pairing(base).expect("pairing prepares");
        let proof = listener_proof(&auth, &request);
        request.token = random_hex(TOKEN_BYTES).expect("replacement token");
        request.token_sha256 = sha256_hex(request.token.as_bytes());
        let ticket = mint_dashboard_pairing_ticket(&dir, request, proof)
            .expect("structurally valid proof persists for server verification");
        assert!(matches!(
            auth.exchange_ticket(&ticket.code, auth.audience(), false),
            Err(DashboardAuthError::ListenerBindingMismatch)
        ));
    }

    #[test]
    fn expired_pairing_ticket_fails_closed_and_is_swept() {
        let dir = test_dir("expiry");
        let (auth, ticket) = auth_and_ticket(dir, "http://127.0.0.1:7070");
        // Age the persisted ticket rather than the clock: the TTL is enforced
        // from the ticket's own recorded expiry.
        let raw = fs::read_to_string(&ticket.ticket_file).expect("ticket file is readable");
        let mut stored: serde_json::Value = serde_json::from_str(&raw).expect("ticket json");
        stored["expires_unix"] = serde_json::json!(unix_now().saturating_sub(1));
        fs::write(
            &ticket.ticket_file,
            serde_json::to_vec(&stored).expect("ticket re-serializes"),
        )
        .expect("rewrite ticket");

        assert!(matches!(
            auth.exchange_ticket(&ticket.code, auth.audience(), false),
            Err(DashboardAuthError::ExpiredTicket)
        ));
        assert!(
            !ticket.ticket_file.exists(),
            "an expired ticket is swept, not left replayable"
        );
    }

    #[test]
    fn dashboard_pairing_rejects_remote_and_non_base_urls() {
        for invalid in [
            "http://192.0.2.1:7070",
            "http://127.0.0.1:7070/path",
            "http://127.0.0.1:7070/?query=1",
            "ftp://127.0.0.1:7070",
        ] {
            assert!(
                prepare_dashboard_pairing(invalid).is_err(),
                "invalid dashboard audience must fail: {invalid}"
            );
        }
    }

    fn spawn_healthz_stub() -> (
        u16,
        std::thread::JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind healthz stub");
        let port = listener.local_addr().expect("stub addr").port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_flag = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("nonblocking stub listener");
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            while !shutdown_flag.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(response.as_bytes());
                }
                thread::sleep(Duration::from_millis(5));
            }
        });
        (port, handle, shutdown)
    }

    // Drives the async probe on a dedicated test runtime. `block_on` is allowed
    // here because the concurrency-lint scans production code only (#[cfg(test)]
    // is skipped) — this mirrors the real CLI boundary (`main::block_on_connect`).
    fn probe_blocking(
        request: &DashboardPairingRequest,
    ) -> Result<DashboardListenerProof, DashboardAuthError> {
        let reactor =
            asupersync::runtime::reactor::create_reactor().expect("test probe reactor builds");
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("test probe runtime builds");
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            probe_dashboard_http_service(&cx, request).await
        })
    }

    #[test]
    fn probe_dashboard_http_service_refuses_unreachable_base_url() {
        let request = prepare_dashboard_pairing("http://127.0.0.1:1").expect("pairing prepares");
        let err = probe_blocking(&request).expect_err("closed port");
        assert!(matches!(err, DashboardAuthError::ServiceUnreachable { .. }));
        assert!(err.to_string().contains("no oraclemcp HTTP service at"));
    }

    #[test]
    fn probe_dashboard_http_service_refuses_generic_healthz_liveness() {
        let (port, handle, shutdown) = spawn_healthz_stub();
        let base = format!("http://127.0.0.1:{port}");
        let request = prepare_dashboard_pairing(&base).expect("pairing prepares");
        let error = probe_blocking(&request).expect_err("generic healthz stub is unauthenticated");
        assert!(error.to_string().contains("pairing proof"));
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = handle.join();
    }
}
