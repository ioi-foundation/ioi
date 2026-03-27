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
    for marker in [
        " and ",
        " but ",
        " without ",
        " do not ",
        " don't ",
        " then ",
    ] {
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
            if let Some(target) = query_targets.iter().find(|target| {
                subject_matches_criterion(&target.subject_token, &criterion_root_token)
            }) {
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

fn normalized_query_text(query: &str) -> String {
    let normalized_chars = query
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>();
    format!(
        " {} ",
        normalized_chars
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn query_contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn query_requests_code_change_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    let code_action = query_contains_any(
        &normalized,
        &[
            " fix ",
            " patch ",
            " implement ",
            " refactor ",
            " port ",
            " bug ",
            " regression ",
            " code ",
            " write ",
            " add ",
            " update ",
            " modify ",
            " edit ",
            " failing test ",
            " failing tests ",
            " broken test ",
            " broken tests ",
            " compile error ",
        ],
    );
    let code_context = query_contains_any(
        &normalized,
        &[
            " repo ",
            " repository ",
            " codebase ",
            " function ",
            " module ",
            " component ",
            " class ",
            " method ",
            " crate ",
            " rust ",
            " typescript ",
            " javascript ",
            " python ",
            " test ",
            " tests ",
            " file ",
            " source ",
            " workspace ",
        ],
    );
    code_action && code_context
}

fn query_requests_verification_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    query_contains_any(
        &normalized,
        &[
            " verify ",
            " verification ",
            " validate ",
            " validation ",
            " check ",
            " double-check ",
            " audit ",
            " review ",
            " confirm ",
            " inspect ",
        ],
    )
}

fn query_requests_research_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    query_contains_any(
        &normalized,
        &[
            " research ",
            " investigate ",
            " look up ",
            " find sources ",
            " gather evidence ",
            " latest ",
            " current ",
            " compare sources ",
            " fact-check ",
        ],
    )
}

fn query_requests_port_or_parity_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    query_contains_any(&normalized, &[" port ", " parity ", " clone ", " absorb "])
}

fn preferred_agent_playbook_for_intent(query: &str, intent_id: &str) -> Option<&'static str> {
    match intent_id.trim() {
        "workspace.ops" | "delegation.task"
            if query_requests_code_change_work(query)
                && (query_requests_research_work(query)
                    || query_requests_verification_work(query)
                    || query_requests_port_or_parity_work(query)) =>
        {
            Some("evidence_audited_patch")
        }
        _ => None,
    }
}

fn preferred_delegation_template_for_intent(query: &str, intent_id: &str) -> Option<&'static str> {
    if matches!(
        preferred_agent_playbook_for_intent(query, intent_id),
        Some("evidence_audited_patch")
    ) {
        return Some("researcher");
    }

    match intent_id.trim() {
        "web.research" | "memory.recall" => Some("researcher"),
        "workspace.ops" if query_requests_code_change_work(query) => Some("coder"),
        "delegation.task" if query_requests_verification_work(query) => Some("verifier"),
        "delegation.task" if query_requests_code_change_work(query) => Some("coder"),
        "delegation.task" if query_requests_research_work(query) => Some("researcher"),
        _ => None,
    }
}

fn preferred_delegation_workflow_for_intent(
    query: &str,
    intent_id: &str,
    template_id: &str,
) -> Option<&'static str> {
    if matches!(
        preferred_agent_playbook_for_intent(query, intent_id),
        Some("evidence_audited_patch")
    ) && template_id.trim() == "researcher"
    {
        return Some("live_research_brief");
    }

    match (intent_id.trim(), template_id.trim()) {
        ("web.research", "researcher") | ("memory.recall", "researcher") => {
            Some("live_research_brief")
        }
        ("workspace.ops", "coder") if query_requests_code_change_work(query) => {
            Some("patch_build_verify")
        }
        ("delegation.task", "researcher") if query_requests_research_work(query) => {
            Some("live_research_brief")
        }
        ("delegation.task", "verifier") if query_requests_verification_work(query) => {
            Some("postcondition_audit")
        }
        ("delegation.task", "coder") if query_requests_code_change_work(query) => {
            Some("patch_build_verify")
        }
        _ => None,
    }
}

fn ensure_preferred_agent_playbook_slot(
    query: &str,
    intent_id: &str,
    contract: &mut InstructionContract,
) {
    let Some(playbook_id) = preferred_agent_playbook_for_intent(query, intent_id) else {
        return;
    };

    if let Some(binding) = contract
        .slot_bindings
        .iter_mut()
        .find(|binding| binding.slot.trim().eq_ignore_ascii_case("playbook_id"))
    {
        let has_explicit_value = binding
            .value
            .as_deref()
            .map(str::trim)
            .map(|value| !value.is_empty())
            .unwrap_or(false);
        if has_explicit_value {
            return;
        }
        binding.binding_kind = ioi_types::app::agentic::InstructionBindingKind::UserLiteral;
        binding.value = Some(playbook_id.to_string());
        binding.origin = ioi_types::app::agentic::ArgumentOrigin::ModelInferred;
        binding.protected_slot_kind = ioi_types::app::agentic::ProtectedSlotKind::Unknown;
        return;
    }

    contract
        .slot_bindings
        .push(ioi_types::app::agentic::InstructionSlotBinding {
            slot: "playbook_id".to_string(),
            binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
            value: Some(playbook_id.to_string()),
            origin: ioi_types::app::agentic::ArgumentOrigin::ModelInferred,
            protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
        });
}

fn ensure_preferred_delegation_template_slot(
    query: &str,
    intent_id: &str,
    contract: &mut InstructionContract,
) {
    let Some(template_id) = preferred_delegation_template_for_intent(query, intent_id) else {
        return;
    };

    if let Some(binding) = contract
        .slot_bindings
        .iter_mut()
        .find(|binding| binding.slot.trim().eq_ignore_ascii_case("template_id"))
    {
        let has_explicit_value = binding
            .value
            .as_deref()
            .map(str::trim)
            .map(|value| !value.is_empty())
            .unwrap_or(false);
        if has_explicit_value {
            return;
        }
        binding.binding_kind = ioi_types::app::agentic::InstructionBindingKind::UserLiteral;
        binding.value = Some(template_id.to_string());
        binding.origin = ioi_types::app::agentic::ArgumentOrigin::ModelInferred;
        binding.protected_slot_kind = ioi_types::app::agentic::ProtectedSlotKind::Unknown;
        return;
    }

    contract
        .slot_bindings
        .push(ioi_types::app::agentic::InstructionSlotBinding {
            slot: "template_id".to_string(),
            binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
            value: Some(template_id.to_string()),
            origin: ioi_types::app::agentic::ArgumentOrigin::ModelInferred,
            protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
        });
}

fn template_binding_value(contract: &InstructionContract) -> Option<&str> {
    contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot.trim().eq_ignore_ascii_case("template_id"))
        .and_then(|binding| binding.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn ensure_preferred_delegation_workflow_slot(
    query: &str,
    intent_id: &str,
    contract: &mut InstructionContract,
) {
    let Some(template_id) = template_binding_value(contract)
        .or_else(|| preferred_delegation_template_for_intent(query, intent_id))
    else {
        return;
    };
    let Some(workflow_id) = preferred_delegation_workflow_for_intent(query, intent_id, template_id)
    else {
        return;
    };

    if let Some(binding) = contract
        .slot_bindings
        .iter_mut()
        .find(|binding| binding.slot.trim().eq_ignore_ascii_case("workflow_id"))
    {
        let has_explicit_value = binding
            .value
            .as_deref()
            .map(str::trim)
            .map(|value| !value.is_empty())
            .unwrap_or(false);
        if has_explicit_value {
            return;
        }
        binding.binding_kind = ioi_types::app::agentic::InstructionBindingKind::UserLiteral;
        binding.value = Some(workflow_id.to_string());
        binding.origin = ioi_types::app::agentic::ArgumentOrigin::ModelInferred;
        binding.protected_slot_kind = ioi_types::app::agentic::ProtectedSlotKind::Unknown;
        return;
    }

    contract
        .slot_bindings
        .push(ioi_types::app::agentic::InstructionSlotBinding {
            slot: "workflow_id".to_string(),
            binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
            value: Some(workflow_id.to_string()),
            origin: ioi_types::app::agentic::ArgumentOrigin::ModelInferred,
            protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
        });
}

fn finalize_instruction_contract(query: &str, intent_id: &str, contract: &mut InstructionContract) {
    enrich_instruction_contract_from_query(query, contract);
    ensure_preferred_agent_playbook_slot(query, intent_id, contract);
    ensure_preferred_delegation_template_slot(query, intent_id, contract);
    ensure_preferred_delegation_workflow_slot(query, intent_id, contract);
}

fn fallback_instruction_contract(query: &str, intent_id: &str) -> Option<InstructionContract> {
    preferred_delegation_template_for_intent(query, intent_id)?;
    let mut contract = InstructionContract::default();
    finalize_instruction_contract(query, intent_id, &mut contract);
    Some(contract)
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
            return fallback_instruction_contract(query, intent_id);
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
            return fallback_instruction_contract(query, intent_id);
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
            return fallback_instruction_contract(query, intent_id);
        }
    };
    let raw = String::from_utf8_lossy(&output).to_string();
    match parse_instruction_contract_payload(&raw) {
        Ok(mut parsed) => {
            finalize_instruction_contract(query, intent_id, &mut parsed);
            Some(parsed)
        }
        Err(error) => {
            log::warn!(
                "IntentResolver instruction contract parse failed error={}",
                error
            );
            fallback_instruction_contract(query, intent_id)
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

        assert_eq!(
            contract.success_criteria,
            vec!["status_text.updated_to_done"]
        );
    }

    #[test]
    fn keeps_specific_success_criterion_unchanged() {
        let mut contract = contract_with_success_criteria(&["status_text.updated_to_done"]);

        enrich_instruction_contract_from_query(
            "Click the button so the status text becomes done.",
            &mut contract,
        );

        assert_eq!(
            contract.success_criteria,
            vec!["status_text.updated_to_done"]
        );
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

    #[test]
    fn seeds_researcher_template_for_web_research_intent() {
        let mut contract = InstructionContract::default();

        finalize_instruction_contract(
            "Find the latest kernel scheduling benchmarks.",
            "web.research",
            &mut contract,
        );

        let template_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "template_id")
            .expect("template binding should be added");
        assert_eq!(
            template_binding.binding_kind,
            ioi_types::app::agentic::InstructionBindingKind::UserLiteral
        );
        assert_eq!(template_binding.value.as_deref(), Some("researcher"));
        let workflow_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "workflow_id")
            .expect("workflow binding should be added");
        assert_eq!(
            workflow_binding.value.as_deref(),
            Some("live_research_brief")
        );
    }

    #[test]
    fn preserves_existing_template_binding_when_present() {
        let mut contract = InstructionContract {
            operation: "delegate".to_string(),
            side_effect_mode: InstructionSideEffectMode::ReadOnly,
            slot_bindings: vec![ioi_types::app::agentic::InstructionSlotBinding {
                slot: "template_id".to_string(),
                binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
                value: Some("verifier".to_string()),
                origin: ioi_types::app::agentic::ArgumentOrigin::UserSpan,
                protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
            }],
            negative_constraints: vec![],
            success_criteria: vec![],
        };

        finalize_instruction_contract(
            "Research and verify the latest kernel scheduling benchmarks.",
            "web.research",
            &mut contract,
        );

        let template_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "template_id")
            .expect("template binding should exist");
        assert_eq!(template_binding.value.as_deref(), Some("verifier"));
    }

    #[test]
    fn seeds_coder_template_for_workspace_code_change_intent() {
        let mut contract = InstructionContract::default();

        finalize_instruction_contract(
            "Implement a patch in the Rust workspace to fix the failing test.",
            "workspace.ops",
            &mut contract,
        );

        let template_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "template_id")
            .expect("coder template binding should be added");
        assert_eq!(template_binding.value.as_deref(), Some("coder"));
        let workflow_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "workflow_id")
            .expect("coder workflow binding should be added");
        assert_eq!(
            workflow_binding.value.as_deref(),
            Some("patch_build_verify")
        );
    }

    #[test]
    fn seeds_evidence_audited_parent_playbook_for_workspace_port_task() {
        let mut contract = InstructionContract::default();

        finalize_instruction_contract(
            "Port LocalAI parity into the Rust workspace, research the current behavior first, and verify the final postcondition.",
            "workspace.ops",
            &mut contract,
        );

        let playbook_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "playbook_id")
            .expect("parent playbook binding should be added");
        assert_eq!(
            playbook_binding.value.as_deref(),
            Some("evidence_audited_patch")
        );
        let template_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "template_id")
            .expect("researcher template binding should be added");
        assert_eq!(template_binding.value.as_deref(), Some("researcher"));
        let workflow_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "workflow_id")
            .expect("researcher workflow binding should be added");
        assert_eq!(
            workflow_binding.value.as_deref(),
            Some("live_research_brief")
        );
    }

    #[test]
    fn does_not_seed_coder_template_for_generic_workspace_file_task() {
        let mut contract = InstructionContract::default();

        finalize_instruction_contract(
            "Rename every file in my Downloads folder to lowercase.",
            "workspace.ops",
            &mut contract,
        );

        assert!(
            contract
                .slot_bindings
                .iter()
                .all(|binding| binding.slot != "template_id"),
            "generic file-management tasks should not default to coder"
        );
    }

    #[test]
    fn seeds_verifier_template_for_explicit_verification_delegation() {
        let mut contract = InstructionContract::default();

        finalize_instruction_contract(
            "Delegate a worker to verify whether the evidence bundle supports the claim.",
            "delegation.task",
            &mut contract,
        );

        let template_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "template_id")
            .expect("verifier template binding should be added");
        assert_eq!(template_binding.value.as_deref(), Some("verifier"));
        let workflow_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "workflow_id")
            .expect("verifier workflow binding should be added");
        assert_eq!(
            workflow_binding.value.as_deref(),
            Some("postcondition_audit")
        );
    }

    #[test]
    fn seeds_coder_workflow_for_explicit_code_change_delegation() {
        let mut contract = InstructionContract::default();

        finalize_instruction_contract(
            "Delegate a worker to patch the parser bug, run the focused tests, and report what changed.",
            "delegation.task",
            &mut contract,
        );

        let template_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "template_id")
            .expect("coder template binding should be added");
        assert_eq!(template_binding.value.as_deref(), Some("coder"));
        let workflow_binding = contract
            .slot_bindings
            .iter()
            .find(|binding| binding.slot == "workflow_id")
            .expect("coder workflow binding should be added");
        assert_eq!(
            workflow_binding.value.as_deref(),
            Some("patch_build_verify")
        );
    }
}
