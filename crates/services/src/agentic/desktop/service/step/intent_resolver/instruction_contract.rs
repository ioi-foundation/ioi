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

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueryTerminalStateTarget {
    subject_token: String,
    target_token: String,
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

fn normalize_contract_token(raw: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = true;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }
    normalized.trim_matches('_').to_string()
}

fn trim_known_prefixes(raw: &str) -> &str {
    let mut value = raw.trim();
    loop {
        let lower = value.to_ascii_lowercase();
        let next = if let Some(rest) = value.strip_prefix("the ") {
            rest
        } else if let Some(rest) = value.strip_prefix("a ") {
            rest
        } else if let Some(rest) = value.strip_prefix("an ") {
            rest
        } else if let Some(rest) = value.strip_prefix("this ") {
            rest
        } else if let Some(rest) = value.strip_prefix("that ") {
            rest
        } else if let Some(rest) = value.strip_prefix("these ") {
            rest
        } else if let Some(rest) = value.strip_prefix("those ") {
            rest
        } else if lower.starts_with("the '") || lower.starts_with("the \"") {
            &value[4..]
        } else {
            value
        };
        if next == value {
            return value;
        }
        value = next.trim();
    }
}

fn trim_wrapping_quotes(raw: &str) -> &str {
    raw.trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`' | ' ' | '\t' | '\n' | '\r'))
}

fn tail_clause_subject(prefix: &str) -> &str {
    let lower = prefix.to_ascii_lowercase();
    let boundaries = [" so ", " until ", " when ", " once ", " after ", " then "];
    let mut start = 0usize;
    for boundary in boundaries {
        if let Some(idx) = lower.rfind(boundary) {
            start = start.max(idx + boundary.len());
        }
    }
    prefix[start..].trim()
}

fn head_clause_target(suffix: &str) -> &str {
    let lower = suffix.to_ascii_lowercase();
    let mut end = suffix.len();

    for marker in [".", ",", ";", "!", "?"] {
        if let Some(idx) = suffix.find(marker) {
            end = end.min(idx);
        }
    }
    for marker in [" and ", " but ", " without ", " do not ", " don't ", " then "] {
        if let Some(idx) = lower.find(marker) {
            end = end.min(idx);
        }
    }

    suffix[..end].trim()
}

fn extract_query_terminal_state_targets(query: &str) -> Vec<QueryTerminalStateTarget> {
    let lower = query.to_ascii_lowercase();
    let patterns = [
        " updated to ",
        " changed to ",
        " changes to ",
        " set to ",
        " becomes ",
        " become ",
        " equals ",
        " is ",
    ];
    let mut targets = Vec::new();

    for pattern in patterns {
        let mut search_start = 0usize;
        while let Some(relative_idx) = lower[search_start..].find(pattern) {
            let idx = search_start + relative_idx;
            let subject_raw = tail_clause_subject(&query[..idx]);
            let target_raw = head_clause_target(&query[idx + pattern.len()..]);
            let subject_token =
                normalize_contract_token(trim_wrapping_quotes(trim_known_prefixes(subject_raw)));
            let target_token =
                normalize_contract_token(trim_wrapping_quotes(trim_known_prefixes(target_raw)));
            if !subject_token.is_empty() && !target_token.is_empty() {
                targets.push(QueryTerminalStateTarget {
                    subject_token,
                    target_token,
                });
            }
            search_start = idx + pattern.len();
        }
    }

    targets
}

fn criterion_has_terminal_value(criterion: &str) -> bool {
    let lower = criterion.to_ascii_lowercase();
    [
        ".updated_to_",
        ".changed_to_",
        ".set_to_",
        ".becomes_",
        ".equals_",
        ".is_",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn subject_matches_criterion(subject_token: &str, criterion_root_token: &str) -> bool {
    subject_token == criterion_root_token
        || criterion_root_token.ends_with(&format!("_{}", subject_token))
        || subject_token.ends_with(&format!("_{}", criterion_root_token))
}

fn enrich_success_criterion_from_query(
    criterion: &str,
    query_targets: &[QueryTerminalStateTarget],
) -> String {
    let trimmed = criterion.trim();
    if trimmed.is_empty() || criterion_has_terminal_value(trimmed) {
        return trimmed.to_string();
    }

    let variants = [
        (".updated", ".updated_to_"),
        (".changed", ".changed_to_"),
        (".becomes", ".becomes_"),
        (".equals", ".equals_"),
        (".is", ".is_"),
    ];
    let lower = trimmed.to_ascii_lowercase();
    for (generic_suffix, enriched_suffix) in variants {
        if let Some(root) = lower.strip_suffix(generic_suffix) {
            let criterion_root_token = normalize_contract_token(root);
            if let Some(target) = query_targets
                .iter()
                .find(|target| subject_matches_criterion(&target.subject_token, &criterion_root_token))
            {
                let trimmed_root = &trimmed[..trimmed.len() - generic_suffix.len()];
                return format!("{trimmed_root}{enriched_suffix}{}", target.target_token);
            }
        }
    }

    trimmed.to_string()
}

fn enrich_instruction_contract_from_query(query: &str, contract: &mut InstructionContract) {
    let query_targets = extract_query_terminal_state_targets(query);
    if query_targets.is_empty() {
        return;
    }
    contract.success_criteria = contract
        .success_criteria
        .iter()
        .map(|criterion| enrich_success_criterion_from_query(criterion, &query_targets))
        .collect();
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
                "User request:\n{}\n\nResolved intent:\n{}\n\nRequired capabilities:\n{}\n\nProvider selection state:\n{}\n\nReturn exactly one JSON object with this schema:\n{{\"operation\":<string>,\"sideEffectMode\":<\"none\"|\"read_only\"|\"draft_only\"|\"send\"|\"create\"|\"update\"|\"delete\"|\"unknown\">,\"slotBindings\":[{{\"slot\":<string>,\"bindingKind\":<\"symbolic_ref\"|\"user_literal\"|\"unresolved\">,\"value\":<string|null>,\"origin\":<\"user_span\"|\"state_ref\"|\"evidence_ref\"|\"tool_default\"|\"model_inferred\">,\"protectedSlotKind\":<\"email_address\"|\"account_email\"|\"calendar_id\"|\"resource_id\"|\"project_id\"|\"file_id\"|\"unknown\">}}],\"negativeConstraints\":[<string>],\"successCriteria\":[<string>]}}\nRules:\n1) Preserve the user's requested end state and prohibitions.\n2) Never invent concrete email addresses, calendar ids, project ids, file ids, or resource ids.\n3) If the user refers to the connected/current/default account or resource instead of an explicit literal, bind the slot to a symbolic reference such as `connected_account.email`, `primary_calendar.id`, `default_project.id`, or `default_task_list.id`.\n4) Use `user_literal` only for values explicitly provided by the user.\n5) Mark protected destination/resource slots with the appropriate protectedSlotKind.\n6) For draft-only email requests, include a success criterion of `mail.reply.completed` and a negative constraint that preserves draft-only behavior.\n7) Keep extraction generic and connector-agnostic; do not rely on brittle keyword heuristics.\n8) When the user specifies a terminal value or label, encode it directly in `successCriteria` with a stable snake_case marker such as `status_text.updated_to_done`, `toggle.is_on`, or `toast.equals_saved` instead of a vague criterion like `status_text.updated`.",
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
        Ok(mut parsed) => {
            enrich_instruction_contract_from_query(query, &mut parsed);
            Some(parsed)
        }
        Err(error) => {
            log::warn!(
                "IntentResolver instruction contract parse failed error={}",
                error
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::agentic::InstructionSideEffectMode;

    fn contract_with_success_criteria(criteria: &[&str]) -> InstructionContract {
        InstructionContract {
            operation: "click".to_string(),
            side_effect_mode: InstructionSideEffectMode::Update,
            slot_bindings: vec![],
            negative_constraints: vec![],
            success_criteria: criteria.iter().map(|value| value.to_string()).collect(),
        }
    }

    #[test]
    fn enriches_generic_updated_success_criterion_from_query_end_state() {
        let mut contract = contract_with_success_criteria(&["status_text.updated"]);

        enrich_instruction_contract_from_query(
            "Click the button so the status text becomes done.",
            &mut contract,
        );

        assert_eq!(contract.success_criteria, vec!["status_text.updated_to_done"]);
    }

    #[test]
    fn keeps_specific_success_criterion_unchanged() {
        let mut contract = contract_with_success_criteria(&["status_text.updated_to_done"]);

        enrich_instruction_contract_from_query(
            "Click the button so the status text becomes done.",
            &mut contract,
        );

        assert_eq!(contract.success_criteria, vec!["status_text.updated_to_done"]);
    }

    #[test]
    fn does_not_enrich_unrelated_success_criterion() {
        let mut contract = contract_with_success_criteria(&["button_label.updated"]);

        enrich_instruction_contract_from_query(
            "Click the button so the status text becomes done.",
            &mut contract,
        );

        assert_eq!(contract.success_criteria, vec!["button_label.updated"]);
    }

    #[test]
    fn extracts_quoted_terminal_values_from_query() {
        let mut contract = contract_with_success_criteria(&["toast.equals"]);

        enrich_instruction_contract_from_query(
            "Save the form so the toast equals 'Saved successfully'.",
            &mut contract,
        );

        assert_eq!(
            contract.success_criteria,
            vec!["toast.equals_saved_successfully"]
        );
    }
}
