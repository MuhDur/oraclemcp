//! Optional embedded operator dashboard bundle.
//!
//! The bundle is deliberately feature-gated so normal source installs remain a
//! Rust-only build. Release binaries and OCI images enable `dashboard-bundle`
//! after CI has produced `web/dist`.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DashboardAsset {
    pub(crate) content_type: &'static str,
    pub(crate) cache_control: &'static str,
    pub(crate) body: Vec<u8>,
}

#[cfg(feature = "dashboard-bundle")]
use rust_embed::RustEmbed;

#[cfg(feature = "dashboard-bundle")]
#[derive(RustEmbed)]
#[folder = "../../web/dist/"]
struct DashboardBundle;

#[cfg(feature = "dashboard-bundle")]
pub(crate) fn dashboard_asset_for(path: &str) -> Option<DashboardAsset> {
    let asset_path = asset_path_for_request(path)?;
    let file = DashboardBundle::get(asset_path)?;
    Some(DashboardAsset {
        content_type: content_type(asset_path),
        cache_control: cache_control(asset_path),
        body: file.data.into_owned(),
    })
}

#[cfg(not(feature = "dashboard-bundle"))]
pub(crate) fn dashboard_asset_for(_path: &str) -> Option<DashboardAsset> {
    None
}

#[cfg(feature = "dashboard-bundle")]
fn asset_path_for_request(path: &str) -> Option<&str> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return Some("index.html");
    }
    if path.contains("..") || path.contains('\\') {
        return None;
    }
    if path == "index.html" || path.starts_with("assets/") {
        return Some(path);
    }
    if path
        .rsplit('/')
        .next()
        .is_some_and(|name| name.contains('.'))
    {
        return Some(path);
    }
    Some("index.html")
}

#[cfg(feature = "dashboard-bundle")]
fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or_default() {
        "css" => "text/css; charset=utf-8",
        "gif" => "image/gif",
        "html" => "text/html; charset=utf-8",
        "ico" => "image/x-icon",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

#[cfg(feature = "dashboard-bundle")]
fn cache_control(path: &str) -> &'static str {
    if path == "index.html" {
        "no-store"
    } else {
        "public, max-age=31536000, immutable"
    }
}
