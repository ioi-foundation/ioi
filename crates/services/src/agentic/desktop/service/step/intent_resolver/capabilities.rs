use super::*;
use crate::agentic::desktop::connectors::{connector_tool_route_bindings, google_workspace};

pub(super) fn capability(id: &str) -> CapabilityId {
    CapabilityId::from(id)
}

pub(super) fn tool_capability_bindings() -> Vec<ToolCapabilityBinding> {
    let mut bindings = vec![
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
            tool_name: "automation__create_monitor".to_string(),
            action_target: ActionTarget::Custom("automation__create_monitor".to_string()),
            capabilities: vec![capability("automation.monitor.install")],
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
            tool_name: "filesystem__stat".to_string(),
            action_target: ActionTarget::FsRead,
            capabilities: vec![
                capability("filesystem.read"),
                capability("filesystem.metadata"),
            ],
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
            tool_name: "filesystem__create_zip".to_string(),
            action_target: ActionTarget::Custom("filesystem__create_zip".to_string()),
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
            tool_name: "wallet_network__mail_read_latest".to_string(),
            action_target: ActionTarget::Custom("wallet_network__mail_read_latest".to_string()),
            capabilities: vec![capability("mail.read.latest")],
        },
        ToolCapabilityBinding {
            tool_name: "wallet_mail_read_latest".to_string(),
            action_target: ActionTarget::Custom("wallet_mail_read_latest".to_string()),
            capabilities: vec![capability("mail.read.latest")],
        },
        ToolCapabilityBinding {
            tool_name: "mail__read_latest".to_string(),
            action_target: ActionTarget::Custom("mail__read_latest".to_string()),
            capabilities: vec![capability("mail.read.latest")],
        },
        ToolCapabilityBinding {
            tool_name: "wallet_network__mail_list_recent".to_string(),
            action_target: ActionTarget::Custom("wallet_network__mail_list_recent".to_string()),
            capabilities: vec![
                capability("mail.list.recent"),
                capability("mail.read.latest"),
            ],
        },
        ToolCapabilityBinding {
            tool_name: "wallet_mail_list_recent".to_string(),
            action_target: ActionTarget::Custom("wallet_mail_list_recent".to_string()),
            capabilities: vec![
                capability("mail.list.recent"),
                capability("mail.read.latest"),
            ],
        },
        ToolCapabilityBinding {
            tool_name: "mail__list_recent".to_string(),
            action_target: ActionTarget::Custom("mail__list_recent".to_string()),
            capabilities: vec![
                capability("mail.list.recent"),
                capability("mail.read.latest"),
            ],
        },
        ToolCapabilityBinding {
            tool_name: "wallet_network__mail_delete_spam".to_string(),
            action_target: ActionTarget::Custom("wallet_network__mail_delete_spam".to_string()),
            capabilities: vec![capability("mail.delete.spam")],
        },
        ToolCapabilityBinding {
            tool_name: "wallet_mail_delete_spam".to_string(),
            action_target: ActionTarget::Custom("wallet_mail_delete_spam".to_string()),
            capabilities: vec![capability("mail.delete.spam")],
        },
        ToolCapabilityBinding {
            tool_name: "mail__delete_spam".to_string(),
            action_target: ActionTarget::Custom("mail__delete_spam".to_string()),
            capabilities: vec![capability("mail.delete.spam")],
        },
        ToolCapabilityBinding {
            tool_name: "wallet_network__mail_reply".to_string(),
            action_target: ActionTarget::Custom("wallet_network__mail_reply".to_string()),
            capabilities: vec![
                capability("mail.reply"),
                capability("mail.send"),
                capability("conversation.reply"),
            ],
        },
        ToolCapabilityBinding {
            tool_name: "wallet_mail_reply".to_string(),
            action_target: ActionTarget::Custom("wallet_mail_reply".to_string()),
            capabilities: vec![
                capability("mail.reply"),
                capability("mail.send"),
                capability("conversation.reply"),
            ],
        },
        ToolCapabilityBinding {
            tool_name: "mail__reply".to_string(),
            action_target: ActionTarget::Custom("mail__reply".to_string()),
            capabilities: vec![
                capability("mail.reply"),
                capability("mail.send"),
                capability("conversation.reply"),
            ],
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
            tool_name: "media__extract_transcript".to_string(),
            action_target: ActionTarget::WebRetrieve,
            capabilities: vec![capability("web.retrieve"), capability("sys.time.read")],
        },
        ToolCapabilityBinding {
            tool_name: "media__extract_multimodal_evidence".to_string(),
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
        ToolCapabilityBinding {
            tool_name: "browser__find_text".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__screenshot".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__wait".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact"), capability("sys.time.read")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__upload_file".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![
                capability("browser.interact"),
                capability("filesystem.read"),
            ],
        },
        ToolCapabilityBinding {
            tool_name: "browser__dropdown_options".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__select_dropdown".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__go_back".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__tab_list".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__tab_switch".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
        ToolCapabilityBinding {
            tool_name: "browser__tab_close".to_string(),
            action_target: ActionTarget::BrowserInteract,
            capabilities: vec![capability("browser.interact")],
        },
    ];
    bindings.extend(google_workspace::google_connector_tool_bindings());
    bindings
}

pub(crate) fn tool_provider_family(tool_name: &str) -> Option<&'static str> {
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    connector_tool_route_bindings()
        .into_iter()
        .find(|binding| binding.tool_name == normalized)
        .map(|binding| binding.provider_family)
}

pub(crate) fn tool_provider_route_label(tool_name: &str) -> Option<&'static str> {
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    connector_tool_route_bindings()
        .into_iter()
        .find(|binding| binding.tool_name == normalized)
        .map(|binding| binding.route_label)
}

pub(crate) fn tool_has_capability(tool_name: &str, capability_id: &str) -> bool {
    let normalized = capability_id.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    tool_capabilities(tool_name)
        .iter()
        .any(|capability| capability.as_str() == normalized)
}

pub(crate) fn is_mail_reply_provider_tool(tool_name: &str) -> bool {
    tool_has_capability(tool_name, "mail.reply") || tool_has_capability(tool_name, "mail.send")
}

pub(super) fn is_mail_connector_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "wallet_network__mail_read_latest"
            | "wallet_mail_read_latest"
            | "mail__read_latest"
            | "wallet_network__mail_list_recent"
            | "wallet_mail_list_recent"
            | "mail__list_recent"
            | "wallet_network__mail_delete_spam"
            | "wallet_mail_delete_spam"
            | "mail__delete_spam"
            | "wallet_network__mail_reply"
            | "wallet_mail_reply"
            | "mail__reply"
    )
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

fn workspace_temporal_filter_known(
    entry: &IntentMatrixEntry,
    bindings: &[ToolCapabilityBinding],
    query_binding_profile: &QueryBindingProfile,
) -> bool {
    if !matches!(entry.scope, IntentScopeProfile::WorkspaceOps)
        || !query_binding_profile.temporal_filesystem_filter
    {
        return true;
    }
    capability_known(&capability("filesystem.metadata"), bindings)
}

fn workspace_temporal_filter_satisfiable(
    entry: &IntentMatrixEntry,
    bindings: &[ToolCapabilityBinding],
    rules: &ActionRules,
    query_binding_profile: &QueryBindingProfile,
) -> bool {
    if !matches!(entry.scope, IntentScopeProfile::WorkspaceOps)
        || !query_binding_profile.temporal_filesystem_filter
    {
        return true;
    }
    capability_satisfiable(&capability("filesystem.metadata"), bindings, rules)
}

pub(super) fn intent_feasible_without_policy(
    entry: &IntentMatrixEntry,
    bindings: &[ToolCapabilityBinding],
    query_binding_profile: &QueryBindingProfile,
) -> bool {
    if !query_binding_satisfied(entry, query_binding_profile) {
        return false;
    }
    if !workspace_temporal_filter_known(entry, bindings, query_binding_profile) {
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
    query_binding_profile: &QueryBindingProfile,
) -> bool {
    if !query_binding_satisfied(entry, query_binding_profile) {
        return false;
    }
    if !workspace_temporal_filter_satisfiable(entry, bindings, rules, query_binding_profile) {
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
    query_binding_profile: &QueryBindingProfile,
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
        intent_feasible_without_policy(entry, bindings, query_binding_profile)
            && !intent_feasible_for_execution(entry, bindings, rules, query_binding_profile)
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

pub fn is_tool_allowed_for_selected_provider(
    resolved: Option<&ResolvedIntentState>,
    tool_name: &str,
) -> bool {
    let Some(resolved) = resolved else {
        return true;
    };
    let Some(provider_selection) = resolved.provider_selection.as_ref() else {
        return true;
    };
    if provider_selection.candidates.is_empty() {
        return tool_provider_family(tool_name).is_none();
    }

    let tool_family = tool_provider_family(tool_name);
    let Some(tool_family) = tool_family else {
        return true;
    };

    if let Some(selected_family) = provider_selection.selected_provider_family.as_deref() {
        return tool_family == selected_family;
    }

    provider_selection
        .candidates
        .iter()
        .any(|candidate| candidate.provider_family == tool_family)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::agentic::{
        IntentQueryBindingClass, ProviderSelectionMode, VerificationMode,
    };

    fn workspace_ops_entry() -> IntentMatrixEntry {
        IntentMatrixEntry {
            intent_id: "workspace.ops".to_string(),
            semantic_descriptor: "inspect and modify files in the local workspace".to_string(),
            query_binding: IntentQueryBindingClass::None,
            required_capabilities: vec![capability("filesystem.read")],
            risk_class: "low".to_string(),
            scope: IntentScopeProfile::WorkspaceOps,
            preferred_tier: "tool_first".to_string(),
            applicability_class: ExecutionApplicabilityClass::TopologyDependent,
            requires_host_discovery: Some(false),
            provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
            required_receipts: vec![],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DynamicSynthesis),
            aliases: vec![],
            exemplars: vec![],
        }
    }

    fn command_exec_entry() -> IntentMatrixEntry {
        IntentMatrixEntry {
            intent_id: "command.exec".to_string(),
            semantic_descriptor: "execute local shell or terminal commands".to_string(),
            query_binding: IntentQueryBindingClass::CommandDirected,
            required_capabilities: vec![capability("command.exec")],
            risk_class: "low".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            preferred_tier: "tool_first".to_string(),
            applicability_class: ExecutionApplicabilityClass::TopologyDependent,
            requires_host_discovery: Some(true),
            provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
            required_receipts: vec![],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DynamicSynthesis),
            aliases: vec![],
            exemplars: vec![],
        }
    }

    fn automation_monitor_entry() -> IntentMatrixEntry {
        IntentMatrixEntry {
            intent_id: "automation.monitor".to_string(),
            semantic_descriptor:
                "install a durable local automation monitor that watches a source on a schedule"
                    .to_string(),
            query_binding: IntentQueryBindingClass::DurableAutomation,
            required_capabilities: vec![capability("automation.monitor.install")],
            risk_class: "medium".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            preferred_tier: "tool_first".to_string(),
            applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
            requires_host_discovery: Some(false),
            provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
            required_receipts: vec![],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DeterministicCheck),
            aliases: vec![],
            exemplars: vec![],
        }
    }

    fn temporal_files_profile() -> QueryBindingProfile {
        QueryBindingProfile {
            available: true,
            command_directed: true,
            temporal_filesystem_filter: true,
            ..Default::default()
        }
    }

    fn durable_remote_monitor_profile() -> QueryBindingProfile {
        QueryBindingProfile {
            available: true,
            remote_public_fact_required: true,
            command_directed: true,
            durable_automation_requested: true,
            ..Default::default()
        }
    }

    #[test]
    fn workspace_ops_temporal_file_queries_are_feasible_with_metadata_tooling() {
        let entry = workspace_ops_entry();
        let profile = temporal_files_profile();
        let bindings = tool_capability_bindings();
        let rules = ActionRules::default();

        assert!(intent_feasible_without_policy(&entry, &bindings, &profile));
        assert!(intent_feasible_for_execution(
            &entry, &bindings, &rules, &profile
        ));
    }

    #[test]
    fn command_exec_remains_feasible_for_temporal_file_queries() {
        let entry = command_exec_entry();
        let profile = temporal_files_profile();
        let bindings = tool_capability_bindings();
        let rules = ActionRules::default();

        assert!(intent_feasible_without_policy(&entry, &bindings, &profile));
        assert!(intent_feasible_for_execution(
            &entry, &bindings, &rules, &profile
        ));
    }

    #[test]
    fn durable_automation_remains_feasible_when_monitoring_public_sources() {
        let entry = automation_monitor_entry();
        let profile = durable_remote_monitor_profile();
        let bindings = tool_capability_bindings();
        let rules = ActionRules::default();

        assert!(intent_feasible_without_policy(&entry, &bindings, &profile));
        assert!(intent_feasible_for_execution(
            &entry, &bindings, &rules, &profile
        ));
    }
}
