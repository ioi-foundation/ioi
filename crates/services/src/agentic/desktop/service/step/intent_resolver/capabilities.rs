use super::*;

pub(super) fn capability(id: &str) -> CapabilityId {
    CapabilityId::from(id)
}

pub(super) fn tool_capability_bindings() -> Vec<ToolCapabilityBinding> {
    vec![
        ToolCapabilityBinding {
            tool_name: "agent__complete".to_string(),
            action_target: ActionTarget::Custom("agent__complete".to_string()),
            capabilities: vec![capability("agent.lifecycle")],
        },
        ToolCapabilityBinding {
            tool_name: "agent__pause".to_string(),
            action_target: ActionTarget::Custom("agent__pause".to_string()),
            capabilities: vec![capability("agent.lifecycle")],
        },
        ToolCapabilityBinding {
            tool_name: "agent__await_result".to_string(),
            action_target: ActionTarget::Custom("agent__await_result".to_string()),
            capabilities: vec![
                capability("agent.lifecycle"),
                capability("delegation.manage"),
            ],
        },
        ToolCapabilityBinding {
            tool_name: "chat__reply".to_string(),
            action_target: ActionTarget::Custom("chat__reply".to_string()),
            capabilities: vec![capability("conversation.reply")],
        },
        ToolCapabilityBinding {
            tool_name: "math__eval".to_string(),
            action_target: ActionTarget::Custom("math::eval".to_string()),
            capabilities: vec![capability("conversation.reply")],
        },
        ToolCapabilityBinding {
            tool_name: "system__fail".to_string(),
            action_target: ActionTarget::Custom("system__fail".to_string()),
            capabilities: vec![capability("system.failure")],
        },
        ToolCapabilityBinding {
            tool_name: "memory__search".to_string(),
            action_target: ActionTarget::Custom("memory::search".to_string()),
            capabilities: vec![capability("memory.access")],
        },
        ToolCapabilityBinding {
            tool_name: "memory__inspect".to_string(),
            action_target: ActionTarget::Custom("memory::inspect".to_string()),
            capabilities: vec![capability("memory.access")],
        },
        ToolCapabilityBinding {
            tool_name: "agent__delegate".to_string(),
            action_target: ActionTarget::Custom("agent__delegate".to_string()),
            capabilities: vec![capability("delegation.manage")],
        },
        ToolCapabilityBinding {
            tool_name: "computer".to_string(),
            action_target: ActionTarget::GuiClick,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "gui__click".to_string(),
            action_target: ActionTarget::GuiClick,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "gui__type".to_string(),
            action_target: ActionTarget::GuiType,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "gui__scroll".to_string(),
            action_target: ActionTarget::GuiScroll,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "gui__snapshot".to_string(),
            action_target: ActionTarget::GuiInspect,
            capabilities: vec![capability("ui.inspect")],
        },
        ToolCapabilityBinding {
            tool_name: "gui__click_element".to_string(),
            action_target: ActionTarget::GuiClick,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "ui__find".to_string(),
            action_target: ActionTarget::Custom("ui::find".to_string()),
            capabilities: vec![capability("ui.inspect")],
        },
        ToolCapabilityBinding {
            tool_name: "os__focus_window".to_string(),
            action_target: ActionTarget::WindowFocus,
            capabilities: vec![capability("ui.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "os__copy".to_string(),
            action_target: ActionTarget::ClipboardWrite,
            capabilities: vec![capability("clipboard.write")],
        },
        ToolCapabilityBinding {
            tool_name: "os__paste".to_string(),
            action_target: ActionTarget::ClipboardRead,
            capabilities: vec![capability("clipboard.read")],
        },
        ToolCapabilityBinding {
            tool_name: "os__launch_app".to_string(),
            action_target: ActionTarget::Custom("os::launch_app".to_string()),
            capabilities: vec![capability("app.launch")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__read_file".to_string(),
            action_target: ActionTarget::FsRead,
            capabilities: vec![capability("filesystem.read")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__list_directory".to_string(),
            action_target: ActionTarget::FsRead,
            capabilities: vec![capability("filesystem.read")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__search".to_string(),
            action_target: ActionTarget::FsRead,
            capabilities: vec![capability("filesystem.read")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__write_file".to_string(),
            action_target: ActionTarget::FsWrite,
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__patch".to_string(),
            action_target: ActionTarget::FsWrite,
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__delete_path".to_string(),
            action_target: ActionTarget::FsWrite,
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__create_directory".to_string(),
            action_target: ActionTarget::Custom("filesystem__create_directory".to_string()),
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__move_path".to_string(),
            action_target: ActionTarget::Custom("filesystem__move_path".to_string()),
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "filesystem__copy_path".to_string(),
            action_target: ActionTarget::Custom("filesystem__copy_path".to_string()),
            capabilities: vec![capability("filesystem.write")],
        },
        ToolCapabilityBinding {
            tool_name: "sys__exec".to_string(),
            action_target: ActionTarget::SysExec,
            capabilities: vec![capability("command.exec"), capability("command.probe")],
        },
        ToolCapabilityBinding {
            tool_name: "sys__exec_session".to_string(),
            action_target: ActionTarget::SysExec,
            capabilities: vec![capability("command.exec"), capability("command.probe")],
        },
        ToolCapabilityBinding {
            tool_name: "sys__exec_session_reset".to_string(),
            action_target: ActionTarget::SysExec,
            capabilities: vec![capability("command.exec")],
        },
        ToolCapabilityBinding {
            tool_name: "sys__change_directory".to_string(),
            action_target: ActionTarget::SysExec,
            capabilities: vec![capability("command.exec")],
        },
        ToolCapabilityBinding {
            tool_name: "sys__install_package".to_string(),
            action_target: ActionTarget::SysInstallPackage,
            capabilities: vec![capability("system.install_package")],
        },
        ToolCapabilityBinding {
            tool_name: "web__search".to_string(),
            action_target: ActionTarget::WebRetrieve,
            capabilities: vec![capability("web.retrieve"), capability("sys.time.read")],
        },
        ToolCapabilityBinding {
            tool_name: "web__read".to_string(),
            action_target: ActionTarget::WebRetrieve,
            capabilities: vec![capability("web.retrieve"), capability("sys.time.read")],
        },
        ToolCapabilityBinding {
            tool_name: "net__fetch".to_string(),
            action_target: ActionTarget::NetFetch,
            capabilities: vec![capability("net.fetch")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__navigate".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__snapshot".to_string(),
            action_target: ActionTarget::BrowserInspect,
            capabilities: vec![capability("browser.inspect")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__click".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__click_element".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__synthetic_click".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__scroll".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__type".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__key".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
    ]
}

pub(super) fn is_mail_connector_tool(tool_name: &str) -> bool {
    tool_name.starts_with("wallet_network__mail_")
        || tool_name.starts_with("wallet_mail_")
        || tool_name.starts_with("mail__")
}

pub(super) fn tool_capabilities(tool_name: &str) -> Vec<CapabilityId> {
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return vec![];
    }

    for binding in tool_capability_bindings() {
        if binding.tool_name == normalized {
            return binding.capabilities;
        }
    }

    if matches!(
        normalized.as_str(),
        "agent__complete" | "agent__pause" | "agent__await_result" | "agent__await"
    ) {
        return vec![capability("agent.lifecycle")];
    }
    if normalized == "chat__reply" {
        return vec![capability("conversation.reply")];
    }
    if normalized == "system__fail" {
        return vec![capability("system.failure")];
    }
    if normalized.starts_with("memory__") {
        return vec![capability("memory.access")];
    }
    if normalized.starts_with("agent__delegate") {
        return vec![capability("delegation.manage")];
    }
    if is_mail_connector_tool(&normalized) {
        return vec![capability("conversation.reply")];
    }
    vec![]
}

pub(super) fn policy_explicitly_blocks_target(rules: &ActionRules, target: &ActionTarget) -> bool {
    let canonical = target.canonical_label();
    rules.rules.iter().any(|rule| {
        rule.action == Verdict::Block && (rule.target == "*" || rule.target == canonical)
    })
}

pub(super) fn policy_blocks_tool(rules: &ActionRules, binding: &ToolCapabilityBinding) -> bool {
    policy_explicitly_blocks_target(rules, &binding.action_target)
}

pub(super) fn capability_satisfiable(
    capability: &CapabilityId,
    bindings: &[ToolCapabilityBinding],
    rules: &ActionRules,
) -> bool {
    bindings.iter().any(|binding| {
        !policy_blocks_tool(rules, binding) && binding.capabilities.iter().any(|c| c == capability)
    })
}

pub(super) fn capability_known(
    capability: &CapabilityId,
    bindings: &[ToolCapabilityBinding],
) -> bool {
    bindings
        .iter()
        .any(|binding| binding.capabilities.iter().any(|c| c == capability))
}

pub(super) fn intent_feasible_without_policy(
    entry: &IntentMatrixEntry,
    bindings: &[ToolCapabilityBinding],
    query: &str,
    query_facets: &QueryFacetProfile,
) -> bool {
    if !query_binding_satisfied(entry, query, query_facets) {
        return false;
    }
    if entry.required_capabilities.is_empty() {
        return true;
    }
    entry
        .required_capabilities
        .iter()
        .all(|required| capability_known(required, bindings))
}

pub(super) fn intent_feasible_for_execution(
    entry: &IntentMatrixEntry,
    bindings: &[ToolCapabilityBinding],
    rules: &ActionRules,
    query: &str,
    query_facets: &QueryFacetProfile,
) -> bool {
    if !query_binding_satisfied(entry, query, query_facets) {
        return false;
    }
    if entry.required_capabilities.is_empty() {
        return true;
    }
    entry
        .required_capabilities
        .iter()
        .all(|required| capability_satisfiable(required, bindings, rules))
}

pub(super) fn infer_unclassified_error_class(
    ranked_candidates: &[IntentCandidateScore],
    matrix: &[IntentMatrixEntry],
    bindings: &[ToolCapabilityBinding],
    rules: &ActionRules,
    query: &str,
    query_facets: &QueryFacetProfile,
) -> String {
    if ranked_candidates.is_empty() || all_candidate_scores_zero(ranked_candidates) {
        return "IntentUnclassified".to_string();
    }

    let ranked_entries = ranked_candidates
        .iter()
        .filter_map(|candidate| {
            matrix
                .iter()
                .find(|entry| entry.intent_id == candidate.intent_id)
        })
        .collect::<Vec<_>>();

    if ranked_entries.is_empty() {
        return "ResolverContractViolation".to_string();
    }

    let has_policy_block = ranked_entries.iter().any(|entry| {
        intent_feasible_without_policy(entry, bindings, query, query_facets)
            && !intent_feasible_for_execution(entry, bindings, rules, query, query_facets)
    });
    if has_policy_block {
        return "PolicyBlocked".to_string();
    }

    "IntentInfeasible".to_string()
}

pub fn is_tool_allowed_for_resolution(
    resolved: Option<&ResolvedIntentState>,
    tool_name: &str,
) -> bool {
    let Some(resolved) = resolved else {
        return false;
    };
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized == "system__fail" {
        return true;
    }
    let tool_caps = tool_capabilities(tool_name);
    if tool_caps.is_empty() {
        return false;
    }
    if resolved.required_capabilities.is_empty() {
        return false;
    }
    tool_caps.iter().any(|tool_cap| {
        resolved
            .required_capabilities
            .iter()
            .any(|required| required == tool_cap)
    })
}
