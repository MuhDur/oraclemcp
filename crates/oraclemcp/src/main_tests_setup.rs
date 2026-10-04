//! Client configuration assertions for `oraclemcp setup`.

use super::*;

#[test]
fn setup_payload_emits_cursor_gemini_and_vscode_snippets() {
    let command = "/opt/oraclemcp-wrapper";
    let args = ["serve", "--profile", "tenant_ro", "--allow-no-auth"];
    let out = setup_payload(
        "tenant_ro",
        "APP_PASSWORD",
        command,
        Some(command),
        "/etc/oraclemcp/profiles.toml",
        "/etc/oraclemcp/tools.d",
    );
    for key in ["cursor_mcp_json", "gemini_settings_json"] {
        assert_eq!(out[key]["mcpServers"]["oracle"]["command"], command);
        assert_eq!(
            out[key]["mcpServers"]["oracle"]["args"],
            serde_json::json!(args)
        );
    }
    assert_eq!(out["vscode_mcp_json"]["servers"]["oracle"]["type"], "stdio");
    assert_eq!(
        out["vscode_mcp_json"]["servers"]["oracle"]["command"],
        command
    );
}

#[test]
fn setup_payload_resolves_new_snippets_to_the_binary() {
    let binary = setup_snippet_command();
    let out = setup_payload(
        "tenant_ro",
        "APP_PASSWORD",
        &binary,
        None,
        "/etc/oraclemcp/profiles.toml",
        "/etc/oraclemcp/tools.d",
    );
    for key in ["cursor_mcp_json", "gemini_settings_json"] {
        assert_eq!(out[key]["mcpServers"]["oracle"]["command"], binary);
    }
    assert_eq!(
        out["vscode_mcp_json"]["servers"]["oracle"]["command"],
        binary
    );
}

#[test]
fn configured_connection_ceiling_includes_pinned_and_observation_sessions() {
    for max_size in [1, 2, 3, 7, 16] {
        let configured = PoolSettings {
            max_size,
            min_idle: max_size,
            ..PoolSettings::default()
        };
        let effective = configured.resolved().max_size;
        match stateless_pool_settings(configured) {
            Some(shared) => {
                assert_eq!(shared.max_size + 1, effective);
                assert!(shared.min_idle <= shared.max_size);
                assert_eq!(shared.acquire_timeout_secs, configured.acquire_timeout_secs);
            }
            None => assert_eq!(effective, 1, "no spare slot means no isolated logon"),
        }
    }
}
