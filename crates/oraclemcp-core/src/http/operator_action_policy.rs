use serde_json::{Value, json};

use super::operator::OperatorRouteKind;

const ACTION_PREVIEW_POLICY: u8 = 1;
const ACTION_CONFIRM_POLICY: u8 = 2;
const ACTION_EXECUTE_POLICY: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BrowserApplyPolicy {
    Allow,
    ClassifySql,
    DdlMutation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OperatorActionToolPolicy {
    pub(super) tool: &'static str,
    pub(super) routes: u8,
    pub(super) browser_apply: BrowserApplyPolicy,
}

impl OperatorActionToolPolicy {
    pub(super) fn allows(self, route: OperatorRouteKind) -> bool {
        let flag = match route {
            OperatorRouteKind::ActionPreview => ACTION_PREVIEW_POLICY,
            OperatorRouteKind::ActionConfirm => ACTION_CONFIRM_POLICY,
            OperatorRouteKind::ActionExecute => ACTION_EXECUTE_POLICY,
            _ => return false,
        };
        self.routes & flag != 0
    }
}

pub(super) const OPERATOR_ACTION_TOOL_POLICIES: &[OperatorActionToolPolicy] = &[
    OperatorActionToolPolicy {
        tool: "oracle_preview_sql",
        routes: ACTION_PREVIEW_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_execute",
        routes: ACTION_CONFIRM_POLICY | ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::ClassifySql,
    },
    OperatorActionToolPolicy {
        tool: "oracle_set_session_level",
        routes: ACTION_PREVIEW_POLICY | ACTION_CONFIRM_POLICY | ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_compile_object",
        routes: ACTION_PREVIEW_POLICY | ACTION_CONFIRM_POLICY | ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::DdlMutation,
    },
    OperatorActionToolPolicy {
        tool: "oracle_create_or_replace",
        routes: ACTION_PREVIEW_POLICY | ACTION_CONFIRM_POLICY | ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::DdlMutation,
    },
    OperatorActionToolPolicy {
        tool: "oracle_patch_source",
        routes: ACTION_PREVIEW_POLICY | ACTION_CONFIRM_POLICY | ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::DdlMutation,
    },
    OperatorActionToolPolicy {
        tool: "oracle_connection_info",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_list_schemas",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_search_objects",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_search_source",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_capabilities",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_get_ddl",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_get_source",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_query",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_parse",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_analyze",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_what_breaks",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_lineage",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_sast",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_doc",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
];

pub(super) fn operator_action_tool_policy(tool: &str) -> Option<OperatorActionToolPolicy> {
    OPERATOR_ACTION_TOOL_POLICIES
        .iter()
        .copied()
        .find(|policy| policy.tool == tool)
}

pub(super) fn allowed_operator_action_tool(
    route: OperatorRouteKind,
    tool: &str,
) -> Option<&'static str> {
    operator_action_tool_policy(tool)
        .filter(|policy| policy.allows(route))
        .map(|policy| policy.tool)
}

pub(super) fn force_preview_mode(tool: &str, arguments: &mut Value) {
    if tool == "oracle_preview_sql" {
        return;
    }
    if let Value::Object(args) = arguments {
        args.insert("execute".to_owned(), Value::Bool(false));
    }
}

pub(super) fn dashboard_workbench_release_gate(
    route: OperatorRouteKind,
    tool: &str,
    arguments: &Value,
) -> Option<Value> {
    if !matches!(
        route,
        OperatorRouteKind::ActionConfirm | OperatorRouteKind::ActionExecute
    ) {
        return None;
    }
    let Some(policy) = operator_action_tool_policy(tool) else {
        return Some(json!({
            "error": "dashboard_action_policy_missing",
            "message": "browser action has no explicit release policy and was refused before dispatch",
            "tool": tool,
        }));
    };
    let required_level = match policy.browser_apply {
        BrowserApplyPolicy::Allow => return None,
        BrowserApplyPolicy::DdlMutation => Some(oraclemcp_guard::OperatingLevel::Ddl),
        BrowserApplyPolicy::ClassifySql => {
            let Some(sql) = ["sql", "ddl", "source_code"]
                .into_iter()
                .find_map(|key| arguments.get(key).and_then(Value::as_str))
            else {
                return Some(json!({
                    "error": "dashboard_action_policy_unresolved",
                    "message": "browser SQL action could not be classified and was refused before dispatch",
                    "tool": tool,
                }));
            };
            oraclemcp_guard::Classifier::default()
                .classify(sql)
                .required_level
        }
    };
    if required_level.is_some_and(|level| level >= oraclemcp_guard::OperatingLevel::Ddl) {
        Some(json!({
            "error": "dashboard_ddl_workbench_disabled",
            "message": "browser dashboard DDL/Admin apply is release-gated; preview remains available",
            "tool": tool,
            "required_level": required_level,
            "next_step": "use /operator/v1/actions/preview to inspect the action, or use a non-browser operator path with the normal profile ceiling",
        }))
    } else {
        None
    }
}
