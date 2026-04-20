use super::cognition::{filter_cognition_tools, reply_safe_browser_semantics_enabled};
use super::intent_resolver::{tool_has_capability, tool_provider_family};
use super::signals::is_browser_surface;
use super::worker::{filter_tools_for_worker_recovery, worker_recovery_failure_class};
use crate::agentic::runtime::agent_playbooks::playbook_route_contract;
use crate::agentic::runtime::service::lifecycle::load_worker_assignment;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::tools::discover_tools;
use crate::agentic::runtime::types::{AgentState, ExecutionTier};
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::{
    CapabilityId, IntentScopeProfile, LlmToolDefinition, ResolvedIntentState,
};
use ioi_types::app::{RoutingEffectiveToolSurface, RoutingRouteDecision};
use std::collections::BTreeSet;
use std::time::Duration;

const ROUTE_ACTIVE_WINDOW_TIMEOUT: Duration = Duration::from_millis(300);
const BROAD_FALLBACK_TOOLS: &[&str] = &[
    "chat__reply",
    "agent__delegate",
    "shell__run",
    "browser__navigate",
    "web__search",
    "web__read",
    "memory__search",
    "memory__read",
    "model__responses",
];

fn playbook_slot_value<'a>(resolved: &'a ResolvedIntentState, slot_name: &str) -> Option<&'a str> {
    resolved
        .instruction_contract
        .as_ref()?
        .slot_bindings
        .iter()
        .find(|binding| binding.slot.trim().eq_ignore_ascii_case(slot_name))
        .and_then(|binding| binding.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn route_family_for_resolved_intent(resolved_intent: Option<&ResolvedIntentState>) -> String {
    let Some(resolved) = resolved_intent else {
        return "general".to_string();
    };

    if let Some(playbook_id) = playbook_slot_value(resolved, "playbook_id") {
        let contract = playbook_route_contract(playbook_id);
        if !contract.route_family.trim().is_empty() {
            return contract.route_family.to_string();
        }
    }

    match resolved.scope {
        IntentScopeProfile::WebResearch => "research",
        IntentScopeProfile::WorkspaceOps | IntentScopeProfile::CommandExecution => "coding",
        IntentScopeProfile::UiInteraction | IntentScopeProfile::AppLaunch => "computer_use",
        IntentScopeProfile::Delegation => "general",
        IntentScopeProfile::Conversation | IntentScopeProfile::Unknown => "general",
    }
    .to_string()
}

fn currentness_override_for_resolved_intent(resolved_intent: Option<&ResolvedIntentState>) -> bool {
    let Some(resolved) = resolved_intent else {
        return false;
    };

    if matches!(resolved.scope, IntentScopeProfile::WebResearch) {
        return true;
    }

    let normalized_intent_id = resolved.intent_id.trim().to_ascii_lowercase();
    if normalized_intent_id.contains("latest")
        || normalized_intent_id.contains("clock")
        || normalized_intent_id.contains("current")
    {
        return true;
    }

    resolved.required_capabilities.iter().any(|capability| {
        matches!(
            capability.as_str(),
            "web.retrieve" | "sys.time.read" | "mail.read.latest" | "mail.list.recent"
        )
    })
}

fn tool_name_has_prefix(tool_name: &str, prefixes: &[&str]) -> bool {
    let normalized = tool_name.trim().to_ascii_lowercase();
    prefixes
        .iter()
        .any(|prefix| normalized.starts_with(prefix.trim().to_ascii_lowercase().as_str()))
}

fn file_mutation_tool(current_tool_name: &str) -> bool {
    matches!(
        current_tool_name.trim().to_ascii_lowercase().as_str(),
        "file__write"
            | "file__edit"
            | "file__replace_line"
            | "file__multi_edit"
            | "file__move"
            | "file__copy"
    )
}

fn file_output_intent(route_family: &str, current_tool_name: &str) -> bool {
    route_family.eq_ignore_ascii_case("artifacts")
        || file_mutation_tool(current_tool_name)
        || tool_name_has_prefix(current_tool_name, &["clipboard__write"])
}

fn artifact_output_intent(
    resolved_intent: Option<&ResolvedIntentState>,
    route_family: &str,
    current_tool_name: &str,
) -> bool {
    route_family.eq_ignore_ascii_case("artifacts")
        || playbook_slot_value_opt(resolved_intent, "playbook_id").is_some_and(|playbook_id| {
            playbook_id.eq_ignore_ascii_case("artifact_generation_gate")
                || playbook_id.eq_ignore_ascii_case("research_backed_artifact_gate")
        })
        || tool_name_has_prefix(current_tool_name, &["media__", "visualize__"])
}

fn playbook_slot_value_opt<'a>(
    resolved_intent: Option<&'a ResolvedIntentState>,
    slot_name: &str,
) -> Option<&'a str> {
    playbook_slot_value(resolved_intent?, slot_name)
}

fn inline_visual_intent(
    resolved_intent: Option<&ResolvedIntentState>,
    current_tool_name: &str,
) -> bool {
    matches!(
        resolved_intent.map(|intent| intent.scope),
        Some(IntentScopeProfile::UiInteraction | IntentScopeProfile::AppLaunch)
    ) || tool_name_has_prefix(current_tool_name, &["browser__", "screen__", "window__"])
}

fn skill_prep_required(route_family: &str, current_tool_name: &str) -> bool {
    matches!(route_family, "computer_use" | "artifacts")
        || file_mutation_tool(current_tool_name)
        || tool_name_has_prefix(
            current_tool_name,
            &["browser__", "screen__", "window__", "app__", "media__"],
        )
}

fn broad_fallback_tool(tool_name: &str) -> bool {
    BROAD_FALLBACK_TOOLS
        .iter()
        .any(|fallback| tool_name.eq_ignore_ascii_case(fallback))
}

fn ordered_union<'a, I>(groups: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a [String]>,
{
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    for group in groups {
        for value in group {
            let normalized = value.trim();
            if normalized.is_empty() {
                continue;
            }
            let owned = normalized.to_string();
            if seen.insert(owned.clone()) {
                ordered.push(owned);
            }
        }
    }
    ordered
}

fn capability_matches_required(tool_name: &str, required_capabilities: &[CapabilityId]) -> bool {
    required_capabilities
        .iter()
        .any(|capability| tool_has_capability(tool_name, capability.as_str()))
}

fn route_primary_tool(
    tool_name: &str,
    current_tool_name: &str,
    selected_provider_family: Option<&str>,
    required_capabilities: &[CapabilityId],
) -> bool {
    if tool_name.eq_ignore_ascii_case(current_tool_name) {
        return true;
    }

    if selected_provider_family.is_some_and(|family| {
        tool_provider_family(tool_name)
            .map(|tool_family| tool_family.eq_ignore_ascii_case(family))
            .unwrap_or(false)
    }) {
        return true;
    }

    if capability_matches_required(tool_name, required_capabilities) {
        return true;
    }

    !broad_fallback_tool(tool_name)
        && (tool_has_capability(tool_name, "conversation.reply")
            || tool_has_capability(tool_name, "agent.lifecycle"))
}

fn build_effective_tool_surface(
    tools: &[LlmToolDefinition],
    resolved_intent: Option<&ResolvedIntentState>,
    current_tool_name: &str,
) -> RoutingEffectiveToolSurface {
    let selected_provider_family = resolved_intent
        .and_then(|intent| intent.provider_selection.as_ref())
        .and_then(|selection| selection.selected_provider_family.as_deref());
    let required_capabilities = resolved_intent
        .map(|intent| intent.required_capabilities.as_slice())
        .unwrap_or(&[]);

    let mut primary_tools = Vec::new();
    let mut broad_fallback_tools = Vec::new();
    let mut diagnostic_tools = Vec::new();

    for tool in tools {
        let tool_name = tool.name.trim();
        if tool_name.is_empty() {
            continue;
        }
        if route_primary_tool(
            tool_name,
            current_tool_name,
            selected_provider_family,
            required_capabilities,
        ) {
            primary_tools.push(tool_name.to_string());
            continue;
        }
        if broad_fallback_tool(tool_name) {
            broad_fallback_tools.push(tool_name.to_string());
            continue;
        }
        diagnostic_tools.push(tool_name.to_string());
    }

    let projected_tools =
        ordered_union([primary_tools.as_slice(), broad_fallback_tools.as_slice()]);

    RoutingEffectiveToolSurface {
        projected_tools,
        primary_tools,
        broad_fallback_tools,
        diagnostic_tools,
    }
}

fn output_intent(
    current_tool_name: &str,
    direct_answer_allowed: bool,
    file_output_intent: bool,
    artifact_output_intent: bool,
    inline_visual_intent: bool,
) -> &'static str {
    if current_tool_name.eq_ignore_ascii_case("agent__delegate") {
        return "delegated";
    }
    if current_tool_name.eq_ignore_ascii_case("chat__reply")
        || current_tool_name.eq_ignore_ascii_case("model__responses")
    {
        return "direct_inline";
    }
    if artifact_output_intent {
        return "artifact";
    }
    if file_output_intent {
        return "file";
    }
    if inline_visual_intent {
        return "inline_visual";
    }
    if direct_answer_allowed && current_tool_name.trim().is_empty() {
        return "direct_inline";
    }
    "tool_execution"
}

fn direct_answer_blockers(
    currentness_override: bool,
    connector_first_preference: bool,
    file_output_intent: bool,
    artifact_output_intent: bool,
    inline_visual_intent: bool,
    skill_prep_required: bool,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if currentness_override {
        blockers.push("currentness_override".to_string());
    }
    if connector_first_preference {
        blockers.push("connector_preferred".to_string());
    }
    if file_output_intent {
        blockers.push("file_output_intent".to_string());
    }
    if artifact_output_intent {
        blockers.push("artifact_output_intent".to_string());
    }
    if inline_visual_intent {
        blockers.push("inline_visual_intent".to_string());
    }
    if skill_prep_required {
        blockers.push("skill_prep_required".to_string());
    }
    blockers
}

async fn active_window_title_for_projection(
    service: &RuntimeAgentService,
    _session_id: [u8; 32],
) -> String {
    let Some(os_driver) = service.os_driver.as_ref() else {
        return "Unknown".to_string();
    };

    match tokio::time::timeout(
        ROUTE_ACTIVE_WINDOW_TIMEOUT,
        os_driver.get_active_window_info(),
    )
    .await
    {
        Ok(Ok(Some(win))) => format!("{} ({})", win.title, win.app_name),
        Ok(Ok(None)) | Ok(Err(_)) | Err(_) => "Unknown".to_string(),
    }
}

pub(crate) async fn project_route_decision(
    service: &RuntimeAgentService,
    state: &dyn StateAccess,
    agent_state: &AgentState,
    current_tool_name: &str,
    tier: ExecutionTier,
) -> RoutingRouteDecision {
    let active_window_title =
        active_window_title_for_projection(service, agent_state.session_id).await;
    let discovered_tools = discover_tools(
        state,
        service.memory_runtime.as_deref(),
        service.mcp.as_deref(),
        &agent_state.goal,
        service.fast_inference.clone(),
        tier,
        &active_window_title,
        agent_state.resolved_intent.as_ref(),
    )
    .await;

    let worker_assignment = match load_worker_assignment(state, agent_state.session_id) {
        Ok(assignment) => assignment,
        Err(error) => {
            log::warn!(
                "Failed to load worker assignment while projecting route decision session={}: {}",
                hex::encode(agent_state.session_id),
                error
            );
            None
        }
    };

    let worker_filtered_tools = filter_tools_for_worker_recovery(
        &discovered_tools,
        agent_state,
        worker_assignment.as_ref(),
        worker_recovery_failure_class(agent_state, worker_assignment.as_ref()),
    );
    let prefer_browser_semantics = reply_safe_browser_semantics_enabled(
        is_browser_surface("", &active_window_title),
        &worker_filtered_tools,
        agent_state.resolved_intent.as_ref(),
    );
    let cognition_tools = filter_cognition_tools(
        &worker_filtered_tools,
        agent_state.resolved_intent.as_ref(),
        prefer_browser_semantics,
        &agent_state.goal,
        "",
        "",
    );

    let route_family = route_family_for_resolved_intent(agent_state.resolved_intent.as_ref());
    let currentness_override =
        currentness_override_for_resolved_intent(agent_state.resolved_intent.as_ref());
    let effective_tool_surface = build_effective_tool_surface(
        &cognition_tools,
        agent_state.resolved_intent.as_ref(),
        current_tool_name,
    );
    let provider_selection = agent_state
        .resolved_intent
        .as_ref()
        .and_then(|intent| intent.provider_selection.as_ref());
    let selected_provider_family =
        provider_selection.and_then(|selection| selection.selected_provider_family.clone());
    let selected_provider_route_label =
        provider_selection.and_then(|selection| selection.selected_route_label.clone());
    let connector_candidate_count = provider_selection
        .map(|selection| selection.candidates.len() as u32)
        .unwrap_or_default();
    let connector_first_preference =
        selected_provider_family
            .as_deref()
            .is_some_and(|provider_family| {
                !effective_tool_surface.primary_tools.is_empty()
                    && effective_tool_surface
                        .primary_tools
                        .iter()
                        .any(|tool_name| {
                            tool_provider_family(tool_name)
                                .map(|tool_family| {
                                    tool_family.eq_ignore_ascii_case(provider_family)
                                })
                                .unwrap_or(false)
                        })
            });
    let narrow_tool_preference = !effective_tool_surface.broad_fallback_tools.is_empty()
        && effective_tool_surface
            .primary_tools
            .iter()
            .any(|tool_name| !broad_fallback_tool(tool_name));
    let file_output_intent = file_output_intent(&route_family, current_tool_name);
    let artifact_output_intent = artifact_output_intent(
        agent_state.resolved_intent.as_ref(),
        &route_family,
        current_tool_name,
    );
    let inline_visual_intent =
        inline_visual_intent(agent_state.resolved_intent.as_ref(), current_tool_name);
    let skill_prep_required = skill_prep_required(&route_family, current_tool_name);
    let direct_answer_blockers = direct_answer_blockers(
        currentness_override,
        connector_first_preference,
        file_output_intent,
        artifact_output_intent,
        inline_visual_intent,
        skill_prep_required,
    );
    let direct_answer_allowed = direct_answer_blockers.is_empty();

    RoutingRouteDecision {
        route_family,
        direct_answer_allowed,
        direct_answer_blockers,
        currentness_override,
        connector_candidate_count,
        selected_provider_family,
        selected_provider_route_label,
        connector_first_preference,
        narrow_tool_preference,
        file_output_intent,
        artifact_output_intent,
        inline_visual_intent,
        skill_prep_required,
        output_intent: output_intent(
            current_tool_name,
            direct_answer_allowed,
            file_output_intent,
            artifact_output_intent,
            inline_visual_intent,
        )
        .to_string(),
        effective_tool_surface,
    }
}

#[cfg(test)]
#[path = "route_projection/tests.rs"]
mod tests;
