use crate::agentic::runtime::service::decision_loop::route_projection;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{AgentState, ExecutionTier};
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::{
    ChatMessage as AgentChatMessage, InferenceOptions, IntentScopeProfile,
};
use ioi_types::app::RoutingRouteDecision;
use ioi_types::error::TransactionError;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

const DIRECT_INLINE_AUTHOR_TIMEOUT_SECS: u64 = 12;
const DIRECT_INLINE_AUTHOR_LOCAL_GPU_TIMEOUT_SECS: u64 = 60;

fn env_var_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn direct_inline_author_timeout() -> Duration {
    let default_timeout_secs = if env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV") {
        DIRECT_INLINE_AUTHOR_LOCAL_GPU_TIMEOUT_SECS
    } else {
        DIRECT_INLINE_AUTHOR_TIMEOUT_SECS
    };

    std::env::var("IOI_DIRECT_INLINE_AUTHOR_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(default_timeout_secs))
}

fn truncate_direct_inline_prompt(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut truncated = text.chars().take(max_chars).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn recent_direct_inline_conversation_excerpt(messages: &[AgentChatMessage]) -> String {
    messages
        .iter()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|message| {
            format!(
                "{}: {}",
                message.role,
                truncate_direct_inline_prompt(message.content.trim(), 500)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn latest_user_message_for_direct_inline_authoring(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    agent_state: &AgentState,
) -> (String, Option<String>) {
    let history = service.hydrate_session_history(session_id).ok();
    let latest_user = history
        .as_ref()
        .and_then(|messages| {
            messages
                .iter()
                .rev()
                .find(|message| message.role.trim().eq_ignore_ascii_case("user"))
                .map(|message| message.content.trim().to_string())
        })
        .filter(|content| !content.is_empty())
        .unwrap_or_else(|| agent_state.goal.trim().to_string());
    let recent_excerpt = history
        .as_ref()
        .map(|messages| recent_direct_inline_conversation_excerpt(messages))
        .filter(|excerpt| !excerpt.trim().is_empty());

    (latest_user, recent_excerpt)
}

fn build_direct_inline_author_prompt(
    latest_user_message: &str,
    recent_conversation: Option<&str>,
) -> String {
    let mut prompt = String::from(
        "You are the direct-inline authoring path for the IOI desktop agent.\n\
Return ONLY the final user-facing answer text.\n\
Rules:\n\
1. Do not output JSON, tool names, markdown fences, or process narration.\n\
2. Do not mention routing, internal tools, repairs, or system state.\n\
3. Answer the user's latest request directly and concisely.\n\
4. If the request requires fresh current data, exact live state, or unavailable private data, say that fresh retrieval is required and do not guess.\n\
5. Keep the answer useful on its own.\n",
    );
    if let Some(recent_conversation) = recent_conversation {
        prompt.push_str("\nRecent conversation:\n");
        prompt.push_str(&truncate_direct_inline_prompt(
            recent_conversation.trim(),
            1800,
        ));
    }
    prompt.push_str("\nLatest user request:\n");
    prompt.push_str(&truncate_direct_inline_prompt(
        latest_user_message.trim(),
        1500,
    ));
    prompt.push_str("\nFinal answer text:");
    prompt
}

fn normalize_direct_inline_author_output(raw_output: &str) -> Option<String> {
    let trimmed = raw_output.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let extracted = value
            .as_str()
            .map(str::trim)
            .or_else(|| {
                value
                    .get("message")
                    .and_then(|value| value.as_str())
                    .map(str::trim)
            })
            .or_else(|| {
                value
                    .get("arguments")
                    .and_then(|arguments| arguments.get("message"))
                    .and_then(|value| value.as_str())
                    .map(str::trim)
            })
            .filter(|value| !value.is_empty());
        if let Some(message) = extracted {
            return Some(message.to_string());
        }
    }

    Some(trimmed.to_string())
}

async fn run_direct_inline_author_inference(
    service: &RuntimeAgentService,
    runtime: Arc<dyn InferenceRuntime>,
    runtime_label: &str,
    session_id: [u8; 32],
    prompt: &str,
) -> Result<Option<String>, TransactionError> {
    let messages = json!([
        { "role": "system", "content": prompt },
        { "role": "user", "content": "Answer the latest user request now." }
    ]);
    let input = serde_json::to_vec(&messages)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    let inference_input = service
        .prepare_cloud_inference_input(
            Some(session_id),
            "desktop_agent",
            "model_hash:direct_inline_author",
            &input,
        )
        .await?;
    let timeout = direct_inline_author_timeout();
    let output = match tokio::time::timeout(
        timeout,
        runtime.execute_inference(
            [0u8; 32],
            &inference_input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: false,
                max_tokens: 768,
                ..Default::default()
            },
        ),
    )
    .await
    {
        Err(_) => {
            log::warn!(
                "Direct inline authoring timed out session={} runtime={} timeout_ms={}",
                hex::encode(&session_id[..4]),
                runtime_label,
                timeout.as_millis()
            );
            return Ok(None);
        }
        Ok(Err(error)) => {
            log::warn!(
                "Direct inline authoring failed session={} runtime={} error={}",
                hex::encode(&session_id[..4]),
                runtime_label,
                error
            );
            return Ok(None);
        }
        Ok(Ok(bytes)) => String::from_utf8_lossy(&bytes).to_string(),
    };

    Ok(normalize_direct_inline_author_output(&output))
}

fn direct_inline_authoring_eligible(route_decision: &RoutingRouteDecision) -> bool {
    route_decision.direct_answer_allowed
        && route_decision
            .output_intent
            .eq_ignore_ascii_case("direct_inline")
        && route_decision.route_family.eq_ignore_ascii_case("general")
        && route_decision
            .effective_tool_surface
            .projected_tools
            .iter()
            .any(|tool_name: &String| tool_name.eq_ignore_ascii_case("chat__reply"))
}

pub(crate) async fn maybe_direct_inline_author_tool_call(
    service: &RuntimeAgentService,
    state: &dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    target_tier: ExecutionTier,
) -> Result<Option<String>, TransactionError> {
    if !matches!(
        agent_state
            .resolved_intent
            .as_ref()
            .map(|resolved| resolved.scope),
        Some(IntentScopeProfile::Conversation)
    ) {
        return Ok(None);
    }

    let route_decision = route_projection::project_route_decision(
        service,
        state,
        agent_state,
        "chat__reply",
        target_tier,
    )
    .await;
    if !direct_inline_authoring_eligible(&route_decision) {
        return Ok(None);
    }

    let (latest_user_message, recent_conversation) =
        latest_user_message_for_direct_inline_authoring(service, session_id, agent_state);
    if latest_user_message.trim().is_empty() {
        return Ok(None);
    }

    let prompt =
        build_direct_inline_author_prompt(&latest_user_message, recent_conversation.as_deref());
    let mut authored_message = run_direct_inline_author_inference(
        service,
        service.fast_inference.clone(),
        "fast",
        session_id,
        &prompt,
    )
    .await?;

    if authored_message.is_none()
        && !Arc::ptr_eq(&service.fast_inference, &service.reasoning_inference)
    {
        authored_message = run_direct_inline_author_inference(
            service,
            service.reasoning_inference.clone(),
            "reasoning",
            session_id,
            &prompt,
        )
        .await?;
    }

    let Some(message) = authored_message else {
        return Ok(None);
    };

    serde_json::to_string(&json!({
        "name": "chat__reply",
        "arguments": {
            "message": message,
        }
    }))
    .map(Some)
    .map_err(|error| TransactionError::Serialization(error.to_string()))
}
