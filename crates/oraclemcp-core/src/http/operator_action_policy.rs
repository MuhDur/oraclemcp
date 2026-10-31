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
    OperatorOnlyEditionFlip,
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

/// This class belongs only to the fixed no-SQL edition routes. Tool names
/// supplied to the general workbench can never select it.
pub(super) fn browser_apply_policy(
    route: OperatorRouteKind,
    tool: &str,
) -> Option<BrowserApplyPolicy> {
    match route {
        OperatorRouteKind::EditionProposalsMerge | OperatorRouteKind::EditionProposalsRollback => {
            Some(BrowserApplyPolicy::OperatorOnlyEditionFlip)
        }
        OperatorRouteKind::ActionPreview
        | OperatorRouteKind::ActionConfirm
        | OperatorRouteKind::ActionExecute => {
            operator_action_tool_policy(tool).map(|p| p.browser_apply)
        }
        _ => None,
    }
}

pub(super) fn dashboard_workbench_release_gate(
    dashboard_workbench_enabled: bool,
    route: OperatorRouteKind,
    tool: &str,
    arguments: &Value,
) -> Option<Value> {
    if !matches!(
        route,
        OperatorRouteKind::ActionPreview
            | OperatorRouteKind::ActionConfirm
            | OperatorRouteKind::ActionExecute
            | OperatorRouteKind::EditionProposalsMerge
            | OperatorRouteKind::EditionProposalsRollback
    ) {
        return None;
    }
    let Some(policy) = browser_apply_policy(route, tool) else {
        return Some(json!({
            "error": "dashboard_action_policy_missing",
            "message": "browser action has no explicit release policy and was refused before dispatch",
            "tool": tool,
        }));
    };
    let required_level = match policy {
        // Authentication, current profile opt-in, review revision and one-use
        // ADMIN confirmation are checked by the dedicated handler/executor.
        BrowserApplyPolicy::OperatorOnlyEditionFlip => return None,
        BrowserApplyPolicy::Allow => None,
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
            // Browser policy is an early text-only check. The dispatched tool
            // remains the admission authority and binds live purity evidence
            // before a read can execute, so preserve the intentional baseline
            // rather than treating this UI precheck as a standalone grant.
            let decision = oraclemcp_guard::Classifier::engine_free_baseline(
                oraclemcp_guard::ClassifierConfig::new(),
            )
            .classify(sql);
            if decision.reason_category
                == Some(oraclemcp_guard::corpus::ReasonCategory::OperatorOnlyStatement)
            {
                return Some(json!({
                    "error": "dashboard_operator_only_statement",
                    "message": "default-edition changes require the dedicated no-SQL operator route",
                    "tool": tool,
                }));
            }
            decision.required_level
        }
    };
    if matches!(
        route,
        OperatorRouteKind::ActionConfirm
            | OperatorRouteKind::ActionExecute
            | OperatorRouteKind::EditionProposalsMerge
            | OperatorRouteKind::EditionProposalsRollback
    ) && required_level.is_some_and(|level| level >= oraclemcp_guard::OperatingLevel::Ddl)
    {
        Some(json!({
            "error": "dashboard_ddl_workbench_disabled",
            "message": "browser dashboard DDL/Admin apply is release-gated; preview remains available",
            "tool": tool,
            "required_level": required_level,
            "next_step": "use /operator/v1/actions/preview to inspect the action, or use a non-browser operator path with the normal profile ceiling",
        }))
    } else if !dashboard_workbench_enabled
        && matches!(
            tool,
            "oracle_preview_sql" | "oracle_query" | "oracle_execute"
        )
    {
        Some(json!({
            "source": "dashboard_workbench",
            "error": "dashboard_workbench_disabled",
            "message": "browser SQL Workbench actions are disabled by server configuration",
            "tool": tool,
            "enabled": false,
            "configuration": "http.dashboard_workbench",
            "next_step": "ask the service operator to set [http].dashboard_workbench = true after reviewing the browser SQL access policy",
        }))
    } else {
        None
    }
}
