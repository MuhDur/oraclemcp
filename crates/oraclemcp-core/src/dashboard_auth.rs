//! Browser dashboard local pairing and CSRF protection.
//!
//! The dashboard is same-origin HTTP, but loopback is not a browser security
//! boundary. This module owns the local bootstrap ticket, the HttpOnly session
//! cookie, and per-route action tickets used by `/operator/v1` POST routes.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// One-time local bootstrap route used by `oraclemcp dashboard`.
pub const DASHBOARD_PAIR_PATH: &str = "/dashboard/pair";
/// Same-origin session-info route used by the SPA to get CSRF/action tickets.
pub const DASHBOARD_SESSION_PATH: &str = "/dashboard/session";
/// Dashboard session cookie. It is deliberately distinct from the MCP cookie.
pub const DASHBOARD_SESSION_COOKIE: &str = "oraclemcp_dashboard_session";
/// Header carrying the session CSRF token for dashboard POST requests.
pub const DASHBOARD_CSRF_HEADER: &str = "x-oraclemcp-csrf";
/// Header carrying the route-scoped dashboard action ticket.
pub const DASHBOARD_ACTION_TICKET_HEADER: &str = "x-oraclemcp-action-ticket";

const DASHBOARD_PAIRING_TTL_SECONDS: u64 = 60;
const DASHBOARD_SESSION_TTL_SECONDS: u64 = 12 * 60 * 60;
const TOKEN_BYTES: usize = 32;

/// Operator routes that accept dashboard-originated POSTs.
pub const DASHBOARD_ACTION_ROUTES: &[(&str, &str)] = &[
    ("POST", "/operator/v1/actions/preview"),
    ("POST", "/operator/v1/actions/confirm"),
    ("POST", "/operator/v1/actions/execute"),
    ("POST", "/operator/v1/config/draft"),
    ("POST", "/operator/v1/config/apply"),
    ("POST", "/operator/v1/config/rollback"),
    ("POST", "/operator/v1/session/set-level"),
    ("POST", "/operator/v1/session/switch-profile"),
];

/// A freshly minted local pairing ticket.
pub struct DashboardPairingTicket {
    /// URL to open in the browser. Contains the one-time bootstrap secret.
    pub url: String,
    /// Expiration as a Unix timestamp.
    pub expires_unix: u64,
    /// The 0600 ticket file consumed by the running service.
    pub ticket_file: PathBuf,
}

impl fmt::Debug for DashboardPairingTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DashboardPairingTicket")
            .field("url", &"<redacted-bootstrap-url>")
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TicketFile {
    schema_version: u8,
    token_sha256: String,
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
#[derive(Debug)]
pub struct DashboardAuth {
    ticket_dir: PathBuf,
    sessions: Mutex<HashMap<String, DashboardSession>>,
    session_ttl: Duration,
}

impl DashboardAuth {
    /// Build dashboard auth against the shared runtime ticket directory.
    #[must_use]
    pub fn new(ticket_dir: PathBuf) -> Self {
        Self {
            ticket_dir,
            sessions: Mutex::new(HashMap::new()),
            session_ttl: Duration::from_secs(DASHBOARD_SESSION_TTL_SECONDS),
        }
    }

    /// Runtime directory this instance consumes one-time tickets from.
    #[must_use]
    pub fn ticket_dir(&self) -> &Path {
        &self.ticket_dir
    }

    /// Consume one local pairing ticket and mint an HttpOnly dashboard cookie.
    pub fn exchange_ticket(&self, token: &str) -> Result<DashboardLogin, DashboardAuthError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(DashboardAuthError::MissingTicket);
        }
        let token_hash = sha256_hex(token.as_bytes());
        let path = ticket_path(&self.ticket_dir, &token_hash);
        let raw = fs::read_to_string(&path).map_err(|_| DashboardAuthError::InvalidTicket)?;
        let ticket: TicketFile =
            serde_json::from_str(&raw).map_err(|_| DashboardAuthError::InvalidTicket)?;
        if ticket.schema_version != 1
            || ticket.purpose != "oraclemcp-dashboard-pairing"
            || ticket.token_sha256 != token_hash
        {
            return Err(DashboardAuthError::InvalidTicket);
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
            session_cookie: dashboard_session_cookie_header(&id, self.session_ttl.as_secs()),
            expires_unix,
        })
    }

    /// Return same-origin session info for a valid dashboard session cookie.
    pub fn session_view(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<DashboardSessionView, DashboardAuthError> {
        let session = self.valid_session(cookie_header)?;
        Ok(session_view(&session))
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

/// Create a 0600, short-lived local pairing ticket and return the browser URL.
pub fn mint_dashboard_pairing_ticket(
    ticket_dir: &Path,
    base_url: &str,
) -> Result<DashboardPairingTicket, DashboardAuthError> {
    prepare_ticket_dir(ticket_dir)?;
    let token = random_hex(TOKEN_BYTES)?;
    let token_sha256 = sha256_hex(token.as_bytes());
    let issued_unix = unix_now();
    let expires_unix = issued_unix.saturating_add(DASHBOARD_PAIRING_TTL_SECONDS);
    let ticket = TicketFile {
        schema_version: 1,
        token_sha256: token_sha256.clone(),
        issued_unix,
        expires_unix,
        purpose: "oraclemcp-dashboard-pairing".to_owned(),
    };
    let ticket_file = ticket_path(ticket_dir, &token_sha256);
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
    let url = format!(
        "{}{}?ticket={token}",
        base_url.trim_end_matches('/'),
        DASHBOARD_PAIR_PATH
    );
    Ok(DashboardPairingTicket {
        url,
        expires_unix,
        ticket_file,
    })
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

fn session_view(session: &DashboardSession) -> DashboardSessionView {
    DashboardSessionView {
        csrf_token: session.csrf_token.clone(),
        csrf_header: DASHBOARD_CSRF_HEADER,
        action_ticket_header: DASHBOARD_ACTION_TICKET_HEADER,
        expires_unix: session.expires_unix,
        action_tickets: DASHBOARD_ACTION_ROUTES
            .iter()
            .map(|(method, path)| DashboardActionTicket {
                method: (*method).to_owned(),
                path: (*path).to_owned(),
                ticket: action_ticket_for(session, method, path),
            })
            .collect(),
    }
}

fn dashboard_session_cookie_header(session_id: &str, max_age_seconds: u64) -> String {
    format!(
        "{DASHBOARD_SESSION_COOKIE}={session_id}; Path=/; Max-Age={max_age_seconds}; HttpOnly; SameSite=Strict"
    )
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

    fn token_from_url(url: &str) -> &str {
        url.split_once("ticket=")
            .map(|(_, token)| token)
            .expect("pairing URL has ticket")
    }

    #[test]
    fn pairing_ticket_is_single_use_and_hash_only() {
        let dir = test_dir("single-use");
        let ticket =
            mint_dashboard_pairing_ticket(&dir, "http://127.0.0.1:7070").expect("ticket mints");
        let token = token_from_url(&ticket.url);
        let file = fs::read_to_string(&ticket.ticket_file).expect("ticket file is readable");
        assert!(
            !file.contains(token),
            "ticket file stores only a hash, not the bootstrap secret"
        );

        let auth = DashboardAuth::new(dir);
        let login = auth.exchange_ticket(token).expect("first exchange works");
        assert!(
            login.session_cookie.contains("HttpOnly")
                && login.session_cookie.contains("SameSite=Strict")
        );
        assert!(matches!(
            auth.exchange_ticket(token),
            Err(DashboardAuthError::InvalidTicket)
        ));
    }

    #[test]
    fn csrf_and_action_ticket_are_route_scoped() {
        let dir = test_dir("scoped");
        let ticket =
            mint_dashboard_pairing_ticket(&dir, "http://127.0.0.1:7070").expect("ticket mints");
        let token = token_from_url(&ticket.url);
        let auth = DashboardAuth::new(dir);
        let login = auth.exchange_ticket(token).expect("login works");
        let cookie_pair = login.session_cookie.split(';').next().expect("cookie pair");
        let view = auth
            .session_view(Some(cookie_pair))
            .expect("session view works");
        let preview = view
            .action_tickets
            .iter()
            .find(|ticket| ticket.path == "/operator/v1/actions/preview")
            .expect("preview ticket");

        auth.validate_action(
            Some(cookie_pair),
            Some(&view.csrf_token),
            Some(&preview.ticket),
            "POST",
            "/operator/v1/actions/preview",
        )
        .expect("matching route validates");
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
    }
}
