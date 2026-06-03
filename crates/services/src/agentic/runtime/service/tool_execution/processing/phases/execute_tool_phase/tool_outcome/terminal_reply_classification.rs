use super::*;

pub(super) fn goal_requires_fresh_retrieval_before_chat_reply(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    let explicitly_requests_public_sources = [
        "use sources",
        "with sources",
        "cite",
        "citation",
        "citations",
        "research",
        "web search",
        "web read",
        "search the web",
        "search online",
    ]
    .iter()
    .any(|hint| lower.contains(hint))
        || (lower.contains("sources") && !lower.contains("source code"));
    if explicitly_requests_public_sources {
        return true;
    }
    let has_temporal_hint = [
        "right now",
        "today",
        "latest",
        "current",
        "currently",
        "recent",
    ]
    .iter()
    .any(|hint| lower.contains(hint));
    let has_retrieval_subject = [
        "source",
        "cite",
        "citation",
        "research",
        "news",
        "price",
        "market",
        "stock",
        "crypto",
        "investment",
        "filecoin",
        "akash",
        "akt",
        "runtime issue",
        "ai model",
    ]
    .iter()
    .any(|hint| lower.contains(hint));
    has_temporal_hint && has_retrieval_subject
}

pub(super) fn workspace_contextual_answer_candidate(
    agent_state: &AgentState,
    message: &str,
) -> bool {
    if !agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::WorkspaceOps)
        .unwrap_or(false)
    {
        return false;
    }
    if !has_execution_evidence(&agent_state.tool_execution_log, "workspace_read")
        || !has_execution_evidence(&agent_state.tool_execution_log, "file_context")
    {
        return false;
    }
    workspace_chat_reply_looks_terminal(message)
}

pub(super) fn file_mutation_policy_action_report_candidate(
    agent_state: &AgentState,
    message: &str,
) -> bool {
    if !agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| {
            resolved.scope == IntentScopeProfile::WorkspaceOps
                && resolved.intent_id.eq_ignore_ascii_case("workspace.mutate")
        })
        .unwrap_or(false)
    {
        return false;
    }
    if !file_mutation_policy_result_available(agent_state) {
        return false;
    }
    if !workspace_chat_reply_looks_terminal(message) {
        return false;
    }
    let lower = message.to_ascii_lowercase();
    [
        "blocked",
        "denied",
        "refused",
        "prevented",
        "rejected",
        "not allowed",
        "outside workspace",
        "workspace boundary",
        "policy",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn file_mutation_policy_result_available(agent_state: &AgentState) -> bool {
    let file_write_dispatched = agent_state
        .recent_actions
        .iter()
        .any(|action| action.starts_with("runtime_route_frame_dispatch:file__write"));
    let failed_write = agent_state.tool_execution_log.iter().any(|(key, status)| {
        key.contains("file__write")
            && matches!(status, ToolCallStatus::Failed(reason) if policy_block_reason(reason))
    });
    let policy_failure_after_dispatch = file_write_dispatched
        && agent_state
            .tool_execution_log
            .values()
            .any(|status| matches!(status, ToolCallStatus::Failed(reason) if policy_block_reason(reason)));
    failed_write || policy_failure_after_dispatch
}

fn policy_block_reason(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("policyblocked")
        || lower.contains("policy blocked")
        || lower.contains("policy block")
        || lower.contains("intent_scope_block")
        || lower.contains("outside workspace")
        || lower.contains("workspace boundary")
        || lower.contains("outside the workspace")
}

pub(super) fn workspace_chat_reply_looks_terminal(message: &str) -> bool {
    let compact = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.split_whitespace().count() < 8 {
        return false;
    }
    let lower = compact.to_ascii_lowercase();
    const NON_TERMINAL_PREFIXES: &[&str] = &[
        "i need to ",
        "i need ",
        "i'm analyzing",
        "i am analyzing",
        "i'm going to ",
        "i am going to ",
        "let me ",
        "i should ",
    ];
    !NON_TERMINAL_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

pub(super) fn chat_reply_looks_like_source_candidate_list(message: &str) -> bool {
    let compact = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.is_empty() {
        return false;
    }
    let lower = compact.to_ascii_lowercase();
    let names_candidate_list = [
        "current source candidate",
        "current source candidates",
        "source candidate",
        "source candidates",
        "candidate sources",
        "retrieved current sources",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    if !names_candidate_list {
        return false;
    }
    let has_external_reference =
        lower.contains("http://") || lower.contains("https://") || lower.contains("www.");
    let has_list_shape = lower.matches(" | ").count() >= 2
        || lower.matches("\n- ").count() >= 1
        || lower.matches(" • ").count() >= 1
        || lower.matches("source ").count() >= 2;
    has_external_reference || has_list_shape
}

pub(super) fn source_candidate_chat_reply_blocker(message: &str) -> Option<String> {
    if chat_reply_looks_like_tool_plan(message) {
        return Some(
            concat!(
                "ERROR_CLASS=NoEffectAfterAction Planning notes are intermediate work, ",
                "not a final answer. Continue the model -> tool -> result loop, then call ",
                "chat__reply with the completed answer."
            )
            .to_string(),
        );
    }
    if !chat_reply_looks_like_source_candidate_list(message) {
        return None;
    }
    Some(
        concat!(
            "ERROR_CLASS=NoEffectAfterAction Source candidate lists are intermediate evidence, ",
            "not a final answer. Read the most relevant sources, then call chat__reply with a ",
            "concise model-authored answer grounded in the gathered evidence."
        )
        .to_string(),
    )
}

pub(super) fn chat_reply_looks_like_tool_plan(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    let names_tool = lower.contains("web__search")
        || lower.contains("web__read")
        || lower.contains("file__")
        || lower.contains("shell__")
        || lower.contains("chat__reply");
    if !names_tool {
        return false;
    }
    [
        "i need to",
        "let me start",
        "i will",
        "i should",
        "next i",
        "then call",
        "need to call",
        "call web__",
    ]
    .iter()
    .any(|hint| lower.contains(hint))
}
