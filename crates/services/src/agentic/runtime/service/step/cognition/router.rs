use crate::agentic::runtime::service::RuntimeAgentService;
use ioi_types::app::agentic::{InferenceOptions, IntentScopeProfile};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, Copy, PartialEq)]
pub(super) enum AttentionMode {
    Chat,
    BlindAction,
    VisualAction,
}

pub(super) async fn determine_attention_mode(
    service: &RuntimeAgentService,
    latest_input: &str,
    goal: &str,
    _step: u32,
    last_output: Option<&str>,
    resolved_scope: Option<IntentScopeProfile>,
) -> AttentionMode {
    if let Some(scope) = resolved_scope {
        match scope {
            IntentScopeProfile::Conversation => return AttentionMode::Chat,
            IntentScopeProfile::WebResearch | IntentScopeProfile::UiInteraction => {
                return AttentionMode::VisualAction;
            }
            IntentScopeProfile::WorkspaceOps
            | IntentScopeProfile::AppLaunch
            | IntentScopeProfile::CommandExecution
            | IntentScopeProfile::Delegation => return AttentionMode::BlindAction,
            IntentScopeProfile::Unknown => {}
        }
    }
    if let Some(out) = last_output {
        if out.contains("I need to see") || out.contains("screenshot") {
            return AttentionMode::VisualAction;
        }
    }

    let prompt = format!(
        "GOAL: \"{}\"\n\
        LATEST USER MESSAGE: \"{}\"\n\
        Classify the immediate next execution mode and respond with strict JSON:\n\
        {{ \"mode\": \"Chat\" | \"Blind\" | \"Visual\" }}.\n\
        Choose Visual when perception/browser/UI state is needed, Blind for deterministic non-visual actions, Chat for conversational-only responses.\n\
        Respond JSON: {{ \"mode\": \"Chat\" | \"Blind\" | \"Visual\" }}",
        goal, latest_input
    );

    let options = InferenceOptions {
        temperature: 0.0,
        json_mode: true,
        ..Default::default()
    };

    match service
        .fast_inference
        .execute_inference(
            [0u8; 32],
            &match service
                .prepare_cloud_inference_input(
                    None,
                    "desktop_agent",
                    "model_hash:0000000000000000000000000000000000000000000000000000000000000000",
                    prompt.as_bytes(),
                )
                .await
            {
                Ok(v) => v,
                Err(_) => return AttentionMode::VisualAction,
            },
            options,
        )
        .await
    {
        Ok(bytes) => {
            let s = String::from_utf8_lossy(&bytes);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&s) {
                return match val["mode"].as_str() {
                    Some("Chat") => AttentionMode::Chat,
                    Some("Blind") => AttentionMode::BlindAction,
                    Some("Visual") => AttentionMode::VisualAction,
                    _ => AttentionMode::VisualAction,
                };
            }
            AttentionMode::VisualAction
        }
        Err(_) => AttentionMode::VisualAction,
    }
}
