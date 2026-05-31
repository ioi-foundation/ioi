use super::*;

fn is_browser_step_tool(name: &str) -> bool {
    name.starts_with("browser__")
        || matches!(
            name,
            "agent__await"
                | "agent__complete"
                | "agent__pause"
                | "window__focus"
                | "agent__escalate"
        )
}

fn is_pure_conversation_reply_tool(name: &str) -> bool {
    matches!(
        name,
        "chat__reply" | "agent__complete" | "agent__pause" | "agent__escalate" | "math__eval"
    )
}

fn is_general_compact_tool(name: &str) -> bool {
    matches!(
        name,
        "chat__reply"
            | "agent__complete"
            | "agent__pause"
            | "agent__escalate"
            | "math__eval"
            | "web__search"
            | "web__read"
            | "memory__search"
            | "memory__read"
            | "agent__delegate"
            | "shell__run"
    )
}

fn is_web_research_compact_tool(name: &str) -> bool {
    matches!(
        name,
        "chat__reply"
            | "agent__complete"
            | "agent__pause"
            | "agent__escalate"
            | "web__search"
            | "web__read"
            | "memory__search"
            | "memory__read"
            | "agent__delegate"
    )
}

fn is_workspace_compact_tool(name: &str) -> bool {
    matches!(
        name,
        "chat__reply"
            | "agent__complete"
            | "agent__pause"
            | "agent__escalate"
            | "agent__delegate"
            | "file__read"
            | "file__view"
            | "file__list"
            | "file__search"
            | "file__info"
            | "file__edit"
            | "file__write"
            | "shell__run"
            | "shell__start"
    )
}

fn truncate_tool_description(description: &str, max_chars: usize) -> String {
    let trimmed = description.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }

    let mut truncated = trimmed.chars().take(max_chars).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn compact_non_browser_cognition_tool(tool: &LlmToolDefinition) -> LlmToolDefinition {
    let parameters = serde_json::from_str::<Value>(&tool.parameters)
        .map(|mut schema| {
            strip_tool_schema_prompt_metadata(&mut schema, true);
            serde_json::to_string(&schema).unwrap_or_else(|_| tool.parameters.clone())
        })
        .unwrap_or_else(|_| tool.parameters.clone());

    LlmToolDefinition {
        name: tool.name.clone(),
        description: truncate_tool_description(&tool.description, 180),
        parameters,
    }
}

fn compact_tool_subset<F>(tools: &[LlmToolDefinition], keep: F) -> Vec<LlmToolDefinition>
where
    F: Fn(&str) -> bool,
{
    let mut seen_tool_names = std::collections::BTreeSet::<String>::new();
    tools
        .iter()
        .filter(|tool| keep(&tool.name))
        .filter(|tool| seen_tool_names.insert(tool.name.clone()))
        .map(compact_non_browser_cognition_tool)
        .collect()
}

fn pending_state_has_visible_start_gate(pending_browser_state_context: &str) -> bool {
    pending_browser_state_context
        .to_ascii_lowercase()
        .contains("visible start gate")
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CognitionToolRecovery<'a> {
    pub consecutive_failures: u32,
    pub last_failure_reason: Option<&'a str>,
    pub workspace_context_ready_for_reply: bool,
    pub web_context_ready_for_reply: bool,
}

pub(crate) fn filter_cognition_tools(
    tools: &[LlmToolDefinition],
    resolved_intent: Option<&ResolvedIntentState>,
    prefer_browser_semantics: bool,
    goal: &str,
    browser_observation_context: &str,
    pending_browser_state_context: &str,
) -> Vec<LlmToolDefinition> {
    filter_cognition_tools_with_recovery(
        tools,
        resolved_intent,
        prefer_browser_semantics,
        goal,
        browser_observation_context,
        pending_browser_state_context,
        CognitionToolRecovery::default(),
    )
}

pub(crate) fn filter_cognition_tools_with_recovery(
    tools: &[LlmToolDefinition],
    resolved_intent: Option<&ResolvedIntentState>,
    prefer_browser_semantics: bool,
    goal: &str,
    browser_observation_context: &str,
    pending_browser_state_context: &str,
    recovery: CognitionToolRecovery<'_>,
) -> Vec<LlmToolDefinition> {
    let resolved_scope = resolved_intent
        .map(|intent| intent.scope)
        .unwrap_or(IntentScopeProfile::Unknown);
    if !prefer_browser_semantics && recovery.web_context_ready_for_reply {
        return compact_tool_subset(tools, |name| name == "chat__reply");
    }
    if resolved_intent
        .map(|intent| intent.intent_id == "conversation.reply")
        .unwrap_or(false)
        || (matches!(resolved_scope, IntentScopeProfile::Conversation) && !prefer_browser_semantics)
    {
        return tools
            .iter()
            .filter(|tool| is_pure_conversation_reply_tool(&tool.name))
            .cloned()
            .collect();
    }

    if !prefer_browser_semantics {
        if matches!(resolved_scope, IntentScopeProfile::Unknown) {
            return compact_tool_subset(tools, is_general_compact_tool);
        }
        if matches!(resolved_scope, IntentScopeProfile::WebResearch) {
            if web_research_no_effect_recovery_requires_reply_only(recovery) {
                return compact_tool_subset(tools, |name| name == "chat__reply");
            }
            return compact_tool_subset(tools, is_web_research_compact_tool);
        }
        if matches!(resolved_scope, IntentScopeProfile::WorkspaceOps) {
            if recovery.workspace_context_ready_for_reply
                || workspace_no_effect_recovery_requires_reply_only(recovery)
            {
                return compact_tool_subset(tools, |name| name == "chat__reply");
            }
            return compact_tool_subset(tools, is_workspace_compact_tool);
        }
        return tools.to_vec();
    }

    let hide_synthetic_click = pending_state_has_visible_start_gate(pending_browser_state_context)
        || browser_observation_has_grounded_shape_targets(browser_observation_context)
            && !browser_observation_has_grounded_geometry_targets(browser_observation_context);
    let prefer_sustained_hover_surface = goal_prefers_sustained_hover_browser_surface(goal);

    let mut seen_tool_names = std::collections::BTreeSet::<String>::new();
    tools
        .iter()
        .filter(|tool| {
            is_browser_step_tool(&tool.name)
                && (!prefer_sustained_hover_surface
                    || matches!(
                        tool.name.as_str(),
                        "browser__hover"
                            | "browser__inspect"
                            | "browser__click"
                            | "browser__move_pointer"
                            | "browser__wait"
                            | "agent__complete"
                            | "agent__escalate"
                    ))
                && (!hide_synthetic_click || tool.name != "browser__click_at")
        })
        .filter(|tool| seen_tool_names.insert(tool.name.clone()))
        .map(|tool| compact_cognition_tool(tool, prefer_browser_semantics))
        .collect()
}

fn workspace_no_effect_recovery_requires_reply_only(recovery: CognitionToolRecovery<'_>) -> bool {
    if recovery.consecutive_failures == 0 {
        return false;
    }
    let Some(reason) = recovery.last_failure_reason else {
        return false;
    };
    reason.contains("NoEffectAfterAction")
}

fn web_research_no_effect_recovery_requires_reply_only(
    recovery: CognitionToolRecovery<'_>,
) -> bool {
    if recovery.consecutive_failures == 0 {
        return false;
    }
    let Some(reason) = recovery.last_failure_reason else {
        return false;
    };
    reason.contains("NoEffectAfterAction")
}

fn workspace_capability_requires_more_than_reply(capability: &str) -> bool {
    let capability = capability.to_ascii_lowercase();
    [
        "write", "edit", "patch", "delete", "create", "move", "rename", "shell", "command",
        "browser", "computer", "delegate", "subagent",
    ]
    .iter()
    .any(|needle| capability.contains(needle))
}

pub(super) fn workspace_context_ready_for_reply(
    agent_state: &AgentState,
    resolved_scope: IntentScopeProfile,
) -> bool {
    if !matches!(resolved_scope, IntentScopeProfile::WorkspaceOps) {
        return false;
    }
    if !has_execution_evidence(&agent_state.tool_execution_log, "workspace_read")
        || !has_execution_evidence(&agent_state.tool_execution_log, "file_context")
    {
        return false;
    }

    agent_state
        .resolved_intent
        .as_ref()
        .map(|intent| {
            !intent.required_capabilities.iter().any(|capability| {
                workspace_capability_requires_more_than_reply(capability.as_str())
            })
        })
        .unwrap_or(true)
}

fn compact_cognition_tool(
    tool: &LlmToolDefinition,
    prefer_browser_semantics: bool,
) -> LlmToolDefinition {
    if !prefer_browser_semantics {
        return tool.clone();
    }

    let parameters = serde_json::from_str::<Value>(&tool.parameters)
        .map(|mut schema| {
            strip_tool_schema_prompt_metadata(&mut schema, false);
            serde_json::to_string(&schema).unwrap_or_else(|_| tool.parameters.clone())
        })
        .unwrap_or_else(|_| tool.parameters.clone());

    LlmToolDefinition {
        name: tool.name.clone(),
        description: tool.description.clone(),
        parameters,
    }
}

pub(super) fn compact_browser_action_prompt_tools(
    tools: &[LlmToolDefinition],
) -> Vec<LlmToolDefinition> {
    tools
        .iter()
        .map(|tool| {
            let parameters = serde_json::from_str::<Value>(&tool.parameters)
                .map(|mut schema| {
                    strip_tool_schema_prompt_metadata(&mut schema, true);
                    serde_json::to_string(&schema).unwrap_or_else(|_| tool.parameters.clone())
                })
                .unwrap_or_else(|_| tool.parameters.clone());

            LlmToolDefinition {
                name: tool.name.clone(),
                description: tool.description.clone(),
                parameters,
            }
        })
        .collect()
}

fn preserve_compact_tool_property_description(property_name: &str) -> bool {
    matches!(property_name, "id" | "ids" | "selector")
}

fn strip_tool_schema_prompt_metadata(value: &mut Value, strip_descriptions: bool) {
    match value {
        Value::Object(map) => {
            map.remove("title");
            map.remove("examples");
            map.remove("$comment");
            if strip_descriptions {
                map.remove("description");
            }
            if let Some(Value::Object(properties)) = map.get_mut("properties") {
                for (property_name, child) in properties.iter_mut() {
                    strip_tool_schema_prompt_metadata(
                        child,
                        strip_descriptions
                            && !preserve_compact_tool_property_description(property_name),
                    );
                }
            }
            for (key, child) in map.iter_mut() {
                if key == "properties" {
                    continue;
                }
                strip_tool_schema_prompt_metadata(child, strip_descriptions);
            }
        }
        Value::Array(items) => {
            for item in items {
                strip_tool_schema_prompt_metadata(item, strip_descriptions);
            }
        }
        _ => {}
    }
}

pub(super) fn format_tool_desc(
    tools: &[LlmToolDefinition],
    prefer_browser_semantics: bool,
    goal: &str,
    resolved_intent: Option<&ResolvedIntentState>,
) -> String {
    if prefer_browser_semantics {
        return tools
            .iter()
            .map(|tool| format!("- {}", tool.name))
            .collect::<Vec<_>>()
            .join("\n");
    }

    let mut sections = vec![tools
        .iter()
        .map(|tool| format!("- {}: {}", tool.name, tool.description))
        .collect::<Vec<_>>()
        .join("\n")];

    if let Some(worker_catalog) = render_worker_template_catalog(tools) {
        sections.push(worker_catalog);
    }
    if let Some(agent_playbook_catalog) =
        render_agent_playbook_catalog(tools, goal, resolved_intent)
    {
        sections.push(agent_playbook_catalog);
    }

    sections.join("\n")
}

pub(super) fn instruction_contract_slot_value<'a>(
    resolved_intent: Option<&'a ResolvedIntentState>,
    slot_name: &str,
) -> Option<&'a str> {
    resolved_intent?
        .instruction_contract
        .as_ref()?
        .slot_bindings
        .iter()
        .find(|binding| binding.slot.trim().eq_ignore_ascii_case(slot_name))
        .and_then(|binding| binding.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(super) fn render_selected_parent_playbook_instruction(
    resolved_intent: Option<&ResolvedIntentState>,
) -> Option<String> {
    let resolved = resolved_intent?;
    if resolved
        .intent_id
        .trim()
        .eq_ignore_ascii_case("delegation.task")
    {
        return None;
    }

    let playbook_id = instruction_contract_slot_value(resolved_intent, "playbook_id")?;
    let decision_record = playbook_decision_record(playbook_id);
    let template_id = instruction_contract_slot_value(resolved_intent, "template_id")
        .unwrap_or("runtime-selected");
    let workflow_id = instruction_contract_slot_value(resolved_intent, "workflow_id")
        .unwrap_or("runtime-selected");
    let route_specific_rule = match playbook_id {
        "evidence_audited_patch" => {
            "Do not spend the root session on repeated repo stat/list loops. The context worker owns initial repo inspection, the coder owns the patch, the verifier owns targeted checks, and the synthesizer owns the final handoff."
        }
        "citation_grounded_brief" => {
            "Do not perform raw web retrieval from the root session. The research worker owns source gathering, and the verifier owns citation/freshness auditing before the final brief is accepted."
        }
        "artifact_generation_gate" => {
            "Do not materialize the artifact directly from the root session. The context worker shapes the brief, the builder produces the candidate, and the verifier validates whether it is launch-ready."
        }
        "research_backed_artifact_gate" => {
            "Do not materialize the researched artifact directly from the root session. The context worker shapes the brief, the research worker gathers current source material, the builder writes from that retained evidence, and the verifier validates whether the retained artifact is launch-ready."
        }
        "browser_postcondition_gate" => {
            "Do not run the entire UI action loop from the root session. The perception worker captures state, the operator executes the route, and the verifier confirms the postcondition or recovery need."
        }
        _ => "Keep the root session orchestration-only until the delegated worker returns.",
    };

    Some(format!(
        "SELECTED EXECUTION ROUTE:\n\
         - Parent playbook: `{}` (route_family={} topology={} planner_authority={} verifier_role={} verifier_required={}).\n\
         - Root-session kickoff must be `agent__delegate`; the runtime will carry the grounded slots automatically.\n\
         - Grounded kickoff slots: playbook_id=`{}` template_id=`{}` workflow_id=`{}`.\n\
         - {}",
        playbook_id,
        decision_record.route_family,
        decision_record.topology,
        decision_record.planner_authority,
        decision_record.verifier_role.unwrap_or("not_engaged"),
        decision_record.requires_verifier,
        playbook_id,
        template_id,
        workflow_id,
        route_specific_rule
    ))
}

pub(super) fn compact_allowed_tool_list(tools: &[String], max_visible: usize) -> String {
    if tools.is_empty() {
        return "runtime-discovered tool surface".to_string();
    }
    if tools.len() <= max_visible {
        return tools.join(", ");
    }
    let preview = tools
        .iter()
        .take(max_visible)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    format!("{preview}, +{} more", tools.len() - max_visible)
}
