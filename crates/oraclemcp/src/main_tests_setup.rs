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
