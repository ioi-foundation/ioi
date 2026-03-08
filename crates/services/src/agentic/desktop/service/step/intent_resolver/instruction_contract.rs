use super::*;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct InstructionContractPayload {
    #[serde(default)]
    operation: String,
    #[serde(default)]
    side_effect_mode: ioi_types::app::agentic::InstructionSideEffectMode,
    #[serde(default)]
    slot_bindings: Vec<ioi_types::app::agentic::InstructionSlotBinding>,
    #[serde(default)]
    negative_constraints: Vec<String>,
    #[serde(default)]
    success_criteria: Vec<String>,
}

fn extract_first_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in raw[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '{' {
            brace_depth = brace_depth.saturating_add(1);
            continue;
        }
        if ch == '}' {
            brace_depth = brace_depth.saturating_sub(1);
            if brace_depth == 0 {
                let end = start + idx + 1;
                return Some(raw[start..end].to_string());
            }
        }
    }
    None
}

fn parse_instruction_contract_payload(raw: &str) -> Result<InstructionContract, TransactionError> {
    let payload = serde_json::from_str::<InstructionContractPayload>(raw).or_else(|_| {
        let extracted = extract_first_json_object(raw).ok_or_else(|| {
            TransactionError::Invalid(
                "ERROR_CLASS=ResolverContractViolation instruction contract output missing JSON"
                    .to_string(),
            )
        })?;
        serde_json::from_str::<InstructionContractPayload>(&extracted).map_err(|error| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=ResolverContractViolation instruction contract output parse failed: {}",
                error
            ))
        })
    })?;

    Ok(InstructionContract {
        operation: payload.operation,
        side_effect_mode: payload.side_effect_mode,
        slot_bindings: payload.slot_bindings,
        negative_constraints: payload.negative_constraints,
        success_criteria: payload.success_criteria,
    })
}

pub(super) async fn synthesize_instruction_contract(
    service: &DesktopAgentService,
    runtime: &Arc<dyn InferenceRuntime>,
    session_id: [u8; 32],
    query: &str,
    intent_id: &str,
    required_capabilities: &[CapabilityId],
    provider_selection: Option<&ProviderSelectionState>,
) -> Option<InstructionContract> {
    let payload = json!([
        {
            "role": "system",
            "content": "Extract a connector-agnostic instruction contract from the user's request. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "User request:\n{}\n\nResolved intent:\n{}\n\nRequired capabilities:\n{}\n\nProvider selection state:\n{}\n\nReturn exactly one JSON object with this schema:\n{{\"operation\":<string>,\"sideEffectMode\":<\"none\"|\"read_only\"|\"draft_only\"|\"send\"|\"create\"|\"update\"|\"delete\"|\"unknown\">,\"slotBindings\":[{{\"slot\":<string>,\"bindingKind\":<\"symbolic_ref\"|\"user_literal\"|\"unresolved\">,\"value\":<string|null>,\"origin\":<\"user_span\"|\"state_ref\"|\"evidence_ref\"|\"tool_default\"|\"model_inferred\">,\"protectedSlotKind\":<\"email_address\"|\"account_email\"|\"calendar_id\"|\"resource_id\"|\"project_id\"|\"file_id\"|\"unknown\">}}],\"negativeConstraints\":[<string>],\"successCriteria\":[<string>]}}\nRules:\n1) Preserve the user's requested end state and prohibitions.\n2) Never invent concrete email addresses, calendar ids, project ids, file ids, or resource ids.\n3) If the user refers to the connected/current/default account or resource instead of an explicit literal, bind the slot to a symbolic reference such as `connected_account.email`, `primary_calendar.id`, `default_project.id`, or `default_task_list.id`.\n4) Use `user_literal` only for values explicitly provided by the user.\n5) Mark protected destination/resource slots with the appropriate protectedSlotKind.\n6) For draft-only email requests, include a success criterion of `mail.reply.completed` and a negative constraint that preserves draft-only behavior.\n7) Keep extraction generic and connector-agnostic; do not rely on brittle keyword heuristics.",
                query,
                intent_id,
                serde_json::to_string(required_capabilities).unwrap_or_default(),
                serde_json::to_string(&provider_selection).unwrap_or_default(),
            )
        }
    ]);
    let input_bytes = match serde_json::to_vec(&payload) {
        Ok(encoded) => encoded,
        Err(error) => {
            log::warn!(
                "IntentResolver instruction contract payload encode failed error={}",
                error
            );
            return None;
        }
    };
    let airlocked_input = match service
        .prepare_cloud_inference_input(
            Some(session_id),
            "intent_resolver",
            INTENT_INSTRUCTION_CONTRACT_MODEL_ID,
            &input_bytes,
        )
        .await
    {
        Ok(encoded) => encoded,
        Err(error) => {
            log::warn!(
                "IntentResolver instruction contract airlock failed session={} error={}",
                hex::encode(&session_id[..4]),
                error
            );
            return None;
        }
    };
    let output = match runtime
        .execute_inference(
            [0u8; 32],
            &airlocked_input,
            ioi_types::app::agentic::InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: 384,
                ..Default::default()
            },
        )
        .await
    {
        Ok(bytes) => bytes,
        Err(error) => {
            log::warn!(
                "IntentResolver instruction contract inference failed error={}",
                vm_error_to_tx(error)
            );
            return None;
        }
    };
    let raw = String::from_utf8_lossy(&output).to_string();
    match parse_instruction_contract_payload(&raw) {
        Ok(parsed) => Some(parsed),
        Err(error) => {
            log::warn!(
                "IntentResolver instruction contract parse failed error={}",
                error
            );
            None
        }
    }
}
