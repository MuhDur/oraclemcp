use super::*;
use crate::capabilities::FeatureTiers;

struct ContextEchoDispatcher;
impl ToolDispatch for ContextEchoDispatcher {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        let scopes = context
            .scope_grant()
            .map(|grant| grant.0.clone())
            .unwrap_or_default();
        let session_id = context.http_session_id().map(str::to_owned);
        let principal_key = context.principal_key().map(str::to_owned);
        Box::pin(async move {
            Outcome::Ok(serde_json::json!({
                "tool": name,
                "args": args,
                "scopes": scopes,
                "session_id": session_id,
                "principal_key": principal_key,
            }))
        })
    }
}

fn context_echo_server() -> OracleMcpServer {
    let caps = CapabilitiesReport::new(
        "0.1.0",
        Vec::new(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: true,
            engine: true,
            http_transport: true,
        },
    );
    OracleMcpServer::new(
        "0.1.0",
        ToolRegistry::new(),
        caps,
        Arc::new(ContextEchoDispatcher),
    )
}

#[test]
fn resource_template_reads_route_through_dispatch_with_transport_context() {
    let s = context_echo_server();
    let grant = crate::http::ScopeGrant(vec!["oracle:read".to_owned()]);
    let context = DispatchContext::with_scope_grant(&grant)
        .with_principal_key("principal-a")
        .with_http_session_id("session-a")
        .with_local_transport(false);

    let read = |uri: &str| -> Value {
        let reply = s
            .handle_jsonrpc_request_with_context(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": uri,
                    "method": "resources/read",
                    "params": { "uri": uri },
                }),
                None,
                context,
            )
            .expect("resource read reply");
        let text = reply["result"]["contents"][0]["text"]
            .as_str()
            .expect("resource text");
        serde_json::from_str(text).expect("resource text is dispatcher JSON")
    };

    let schema = read("oracle://schema/HR");
    assert_eq!(schema["tool"], serde_json::json!("oracle_schema_inspect"));
    assert_eq!(schema["args"], serde_json::json!({ "owner": "HR" }));
    assert_eq!(schema["scopes"], serde_json::json!(["oracle:read"]));
    assert_eq!(schema["principal_key"], serde_json::json!("principal-a"));
    assert_eq!(schema["session_id"], serde_json::json!("session-a"));

    let object = read("oracle://object/HR/PACKAGE/EMP_API");
    assert_eq!(object["tool"], serde_json::json!("oracle_get_source"));
    assert_eq!(
        object["args"],
        serde_json::json!({
            "owner": "HR",
            "object_type": "PACKAGE",
            "name": "EMP_API",
        })
    );
    assert_eq!(object["scopes"], serde_json::json!(["oracle:read"]));
    assert_eq!(object["principal_key"], serde_json::json!("principal-a"));
    assert_eq!(object["session_id"], serde_json::json!("session-a"));
}
