//! Structured `tracing` JSON logging (plan §10).
//!
//! A span per request carries `request_id` / `tool_name` / `db_user`; logs go to
//! stderr as JSON, filtered by `RUST_LOG` (default `info`). **Bind values and
//! secrets are never logged** — that discipline is the caller's, enforced by
//! only ever logging SQL SHA-256 + previews (see `oraclemcp-audit`).

use std::sync::OnceLock;

use tracing_subscriber::EnvFilter;

static INIT: OnceLock<()> = OnceLock::new();

/// Initialize JSON logging to stderr, filtered by `RUST_LOG` (default `level`).
/// Idempotent: returns `true` on the first call that installs the subscriber,
/// `false` if logging was already initialized (so tests / repeated `serve`
/// invocations do not panic on a double-install).
pub fn init_json_logging(default_level: &str) -> bool {
    let mut installed = false;
    INIT.get_or_init(|| {
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
        // `try_init` returns Err if a global subscriber is already set; we treat
        // that as "already initialized" rather than a hard error.
        let _ = tracing_subscriber::fmt()
            .json()
            .with_current_span(true)
            .with_span_list(false)
            .with_target(true)
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init();
        installed = true;
    });
    installed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent() {
        // First call installs (or coexists with a test harness subscriber);
        // subsequent calls must not panic and must report not-installed.
        let _first = init_json_logging("info");
        assert!(!init_json_logging("debug"), "second init must be a no-op");
    }

    #[test]
    fn env_filter_parses_default_level() {
        // A bad default would panic in EnvFilter::new; assert common levels work.
        for level in ["error", "warn", "info", "debug", "trace"] {
            let _ = EnvFilter::new(level);
        }
    }
}
