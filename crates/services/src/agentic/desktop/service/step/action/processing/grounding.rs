use super::*;
use crate::agentic::desktop::connectors::{
    connector_id_for_tool_name, connector_protected_slot_bindings,
    connector_symbolic_reference_bindings, connector_symbolic_reference_inference_bindings,
    ConnectorProtectedSlotBinding, ConnectorSymbolicReferenceBinding,
    ConnectorSymbolicReferenceInferenceBinding, ResolvedSymbolicReference,
};
use crate::agentic::desktop::service::step::action::command_contract::contract_requires_receipt_with_rules;
use crate::agentic::desktop::service::step::action::support::{
    mark_execution_receipt_with_value, receipt_marker,
};
use crate::agentic::pii_substrate;
use ioi_types::app::agentic::{
    ArgumentOrigin, InstructionBindingKind, InstructionSlotBinding, PiiClass, ProtectedSlotKind,
    ResolvedIntentState,
};
use lettre::message::Mailbox;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn selected_connector_id(
    resolved: &ResolvedIntentState,
    tool_name: Option<&str>,
) -> Option<String> {
    resolved
        .provider_selection
        .as_ref()
        .and_then(|selection| selection.selected_connector_id.as_deref())
        .map(str::to_string)
        .or_else(|| {
            tool_name
                .and_then(connector_id_for_tool_name)
                .map(str::to_string)
        })
}

fn lookup_symbolic_reference_binding(
    connector_id: &str,
) -> Option<ConnectorSymbolicReferenceBinding> {
    connector_symbolic_reference_bindings()
        .into_iter()
        .find(|binding| binding.connector_id == connector_id)
}

fn lookup_symbolic_reference_inference_binding(
    connector_id: &str,
) -> Option<ConnectorSymbolicReferenceInferenceBinding> {
    connector_symbolic_reference_inference_bindings()
        .into_iter()
        .find(|binding| binding.connector_id == connector_id)
}

fn validate_protected_literal(
    slot: &InstructionSlotBinding,
    raw: &str,
) -> Result<Value, TransactionError> {
    match slot.protected_slot_kind {
        ProtectedSlotKind::EmailAddress | ProtectedSlotKind::AccountEmail => {
            let mailbox = raw.trim().parse::<Mailbox>().map_err(|error| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=GroundingMissing Protected slot '{}' requires a valid email literal: {}",
                    slot.slot, error
                ))
            })?;
            Ok(Value::String(mailbox.to_string()))
        }
        _ => Ok(Value::String(raw.trim().to_string())),
    }
}

fn normalize_grounding_phrase(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn query_attests_email_literal(query: &str, raw: &str) -> bool {
    let query_lower = query.to_ascii_lowercase();
    let candidate = raw.trim().to_ascii_lowercase();
    !candidate.is_empty() && query_lower.contains(&candidate)
}

fn is_redacted_email_placeholder(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.contains("<redacted:email>")
        || normalized == "redacted:email"
        || normalized == "redacted_email"
}

fn recover_single_explicit_email_literal(query: &str) -> Option<String> {
    let evidence = pii_substrate::build_evidence_graph(query).ok()?;
    let mut emails = evidence
        .spans
        .iter()
        .filter(|span| span.pii_class == PiiClass::Email)
        .filter_map(|span| {
            let start = usize::try_from(span.start_index).ok()?;
            let end = usize::try_from(span.end_index).ok()?;
            if start >= end
                || end > query.len()
                || !query.is_char_boundary(start)
                || !query.is_char_boundary(end)
            {
                return None;
            }
            query[start..end].trim().parse::<Mailbox>().ok()
        })
        .map(|mailbox| mailbox.to_string())
        .collect::<Vec<_>>();
    emails.sort_by_key(|value| value.to_ascii_lowercase());
    emails.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    if emails.len() == 1 {
        emails.into_iter().next()
    } else {
        None
    }
}

fn recover_redacted_protected_literal_from_query(
    query: &str,
    binding: &InstructionSlotBinding,
    raw: &str,
) -> Option<String> {
    if !is_redacted_email_placeholder(raw) {
        return None;
    }
    match binding.protected_slot_kind {
        ProtectedSlotKind::EmailAddress | ProtectedSlotKind::AccountEmail => {
            recover_single_explicit_email_literal(query)
        }
        _ => None,
    }
}

fn query_attests_phrase_literal(query: &str, raw: &str) -> bool {
    let normalized_query = format!(" {} ", normalize_grounding_phrase(query));
    let normalized_candidate = normalize_grounding_phrase(raw);
    !normalized_candidate.is_empty()
        && normalized_query.contains(&format!(" {} ", normalized_candidate))
}

fn query_attests_protected_literal(query: &str, slot: &InstructionSlotBinding, raw: &str) -> bool {
    match slot.protected_slot_kind {
        ProtectedSlotKind::EmailAddress | ProtectedSlotKind::AccountEmail => {
            query_attests_email_literal(query, raw) || query_attests_phrase_literal(query, raw)
        }
        ProtectedSlotKind::CalendarId
        | ProtectedSlotKind::ResourceId
        | ProtectedSlotKind::ProjectId
        | ProtectedSlotKind::FileId => query_attests_phrase_literal(query, raw),
        ProtectedSlotKind::Unknown => true,
    }
}

fn current_argument_literal<'a>(arguments: &'a Map<String, Value>, slot: &str) -> Option<&'a str> {
    arguments.get(slot).and_then(Value::as_str)
}

fn slot_bindings_by_name(
    resolved: &ResolvedIntentState,
) -> BTreeMap<String, InstructionSlotBinding> {
    resolved
        .instruction_contract
        .as_ref()
        .map(|contract| {
            contract
                .slot_bindings
                .iter()
                .cloned()
                .filter(|binding| !binding.slot.trim().is_empty())
                .map(|binding| (binding.slot.clone(), binding))
                .collect()
        })
        .unwrap_or_default()
}

fn tool_name_for_grounding(tool_value: &Value) -> Option<&str> {
    tool_value.get("name").and_then(Value::as_str)
}

fn merge_slot_binding_with_protected_slot_metadata(
    mut existing: InstructionSlotBinding,
    protected_slot: &ConnectorProtectedSlotBinding,
    arguments: &Map<String, Value>,
) -> InstructionSlotBinding {
    if existing.protected_slot_kind == ProtectedSlotKind::Unknown {
        existing.protected_slot_kind = protected_slot.protected_slot_kind;
    }
    if existing.value.is_none() {
        existing.value =
            current_argument_literal(arguments, &protected_slot.slot).map(str::to_string);
    }
    if matches!(existing.origin, ArgumentOrigin::ToolDefault) {
        existing.origin = ArgumentOrigin::ModelInferred;
    }
    existing
}

fn protected_slot_bindings_by_name(
    resolved: &ResolvedIntentState,
    tool_name: Option<&str>,
    arguments: &Map<String, Value>,
) -> BTreeMap<String, InstructionSlotBinding> {
    let mut bindings = slot_bindings_by_name(resolved);
    let Some(tool_name) = tool_name else {
        return bindings;
    };

    for protected_slot in connector_protected_slot_bindings()
        .into_iter()
        .filter(|binding| binding.tool_name == tool_name)
    {
        let synthetic = InstructionSlotBinding {
            slot: protected_slot.slot.clone(),
            binding_kind: if current_argument_literal(arguments, &protected_slot.slot).is_some() {
                InstructionBindingKind::UserLiteral
            } else {
                InstructionBindingKind::Unresolved
            },
            value: current_argument_literal(arguments, &protected_slot.slot).map(str::to_string),
            origin: ArgumentOrigin::ModelInferred,
            protected_slot_kind: protected_slot.protected_slot_kind,
        };
        match bindings.remove(&protected_slot.slot) {
            Some(existing) => {
                bindings.insert(
                    protected_slot.slot.clone(),
                    merge_slot_binding_with_protected_slot_metadata(
                        existing,
                        &protected_slot,
                        arguments,
                    ),
                );
            }
            None => {
                bindings.insert(protected_slot.slot.clone(), synthetic);
            }
        }
    }

    bindings
}

async fn resolve_symbolic_reference(
    resolver_binding: ConnectorSymbolicReferenceBinding,
    agent_state: &AgentState,
    slot: &InstructionSlotBinding,
    reference: &str,
) -> Result<ResolvedSymbolicReference, TransactionError> {
    let Some(resolved_reference) = (resolver_binding.resolve)(agent_state, reference)
        .await
        .map_err(|error| {
            TransactionError::Invalid(format!("ERROR_CLASS=GroundingMissing {}", error))
        })?
    else {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=GroundingMissing Symbolic reference '{}' for slot '{}' could not be resolved.",
            reference, slot.slot
        )));
    };
    Ok(resolved_reference)
}

async fn infer_symbolic_reference_from_query(
    inference_binding: Option<ConnectorSymbolicReferenceInferenceBinding>,
    agent_state: &AgentState,
    slot: &InstructionSlotBinding,
    query: &str,
) -> Result<Option<String>, TransactionError> {
    let Some(inference_binding) = inference_binding else {
        return Ok(None);
    };
    (inference_binding.infer)(agent_state, &slot.slot, query, slot.protected_slot_kind)
        .await
        .map_err(|error| {
            TransactionError::Invalid(format!("ERROR_CLASS=GroundingMissing {}", error))
        })
}

fn record_grounded_symbolic_reference(
    service: &DesktopAgentService,
    arguments: &mut Map<String, Value>,
    grounded_slots: &mut Vec<Value>,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    slot: &InstructionSlotBinding,
    reference: &str,
    resolved_reference: ResolvedSymbolicReference,
) {
    let provider_id = resolved_reference.provider_id.clone();
    arguments.insert(slot.slot.clone(), resolved_reference.value.clone());
    grounded_slots.push(json!({
        "slot": slot.slot,
        "bindingKind": "symbolic_ref",
        "reference": reference,
        "resolvedValue": resolved_reference.value,
        "origin": resolved_reference.origin,
        "protectedSlotKind": slot.protected_slot_kind,
        "providerId": provider_id,
    }));
    verification_checks.push(format!(
        "grounding_slot={}::symbolic_ref::{}",
        slot.slot, reference
    ));
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "execution",
        "grounding",
        true,
        &resolved_reference.evidence,
        Some("instruction_contract"),
        Some(reference),
        Some("symbolic_ref"),
        None,
        resolved_reference.provider_id,
        synthesized_payload_hash,
    );
}

pub(super) async fn apply_instruction_contract_grounding(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    tool: AgentTool,
    rules: &ActionRules,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<AgentTool, TransactionError> {
    let Some(resolved) = agent_state.resolved_intent.as_ref() else {
        return Ok(tool);
    };
    let requires_grounding = contract_requires_receipt_with_rules(agent_state, rules, "grounding");
    if !requires_grounding {
        return Ok(tool);
    }

    let mut tool_value =
        serde_json::to_value(&tool).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let tool_name = tool_name_for_grounding(&tool_value).map(str::to_string);
    let Some(arguments) = tool_value
        .get_mut("arguments")
        .and_then(Value::as_object_mut)
    else {
        return Err(TransactionError::Invalid(
            "ERROR_CLASS=GroundingMissing Tool arguments were unavailable for grounding."
                .to_string(),
        ));
    };

    let connector_id = selected_connector_id(resolved, tool_name.as_deref()).ok_or_else(|| {
        TransactionError::Invalid(
            "ERROR_CLASS=GroundingMissing Connector selection missing for grounded intent."
                .to_string(),
        )
    })?;
    let resolver_binding = lookup_symbolic_reference_binding(&connector_id).ok_or_else(|| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=GroundingMissing No symbolic reference resolver registered for connector '{}'.",
            connector_id
        ))
    })?;
    let inference_binding = lookup_symbolic_reference_inference_binding(&connector_id);
    let user_query = agent_state.goal.clone();

    let mut grounded_slots = Vec::<Value>::new();
    for binding in
        protected_slot_bindings_by_name(resolved, tool_name.as_deref(), arguments).into_values()
    {
        match binding.binding_kind {
            InstructionBindingKind::SymbolicRef => {
                let reference = binding.value.as_deref().ok_or_else(|| {
                    TransactionError::Invalid(format!(
                        "ERROR_CLASS=GroundingMissing Symbolic slot '{}' was missing a reference.",
                        binding.slot
                    ))
                })?;
                let resolved_reference =
                    resolve_symbolic_reference(resolver_binding, agent_state, &binding, reference)
                        .await?;
                record_grounded_symbolic_reference(
                    service,
                    arguments,
                    &mut grounded_slots,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash.clone(),
                    &binding,
                    reference,
                    resolved_reference,
                );
            }
            InstructionBindingKind::UserLiteral => {
                let literal = current_argument_literal(arguments, &binding.slot)
                    .or_else(|| binding.value.as_deref())
                    .ok_or_else(|| {
                        TransactionError::Invalid(format!(
                        "ERROR_CLASS=GroundingMissing User literal slot '{}' was missing a value.",
                        binding.slot
                    ))
                    })?;
                let literal =
                    recover_redacted_protected_literal_from_query(&user_query, &binding, literal)
                        .unwrap_or_else(|| literal.trim().to_string());
                let attested = query_attests_protected_literal(&user_query, &binding, &literal);
                let validated_literal = validate_protected_literal(&binding, &literal).ok();
                if matches!(binding.protected_slot_kind, ProtectedSlotKind::Unknown) {
                    let grounded_value =
                        validated_literal.unwrap_or(Value::String(literal.clone()));
                    arguments.insert(binding.slot.clone(), grounded_value.clone());
                    grounded_slots.push(json!({
                        "slot": binding.slot,
                        "bindingKind": "user_literal",
                        "value": grounded_value,
                        "origin": binding.origin,
                        "protectedSlotKind": binding.protected_slot_kind,
                    }));
                    verification_checks
                        .push(format!("grounding_slot={}::user_literal", binding.slot));
                    continue;
                }

                if attested {
                    if let Some(grounded_value) = validated_literal {
                        arguments.insert(binding.slot.clone(), grounded_value.clone());
                        grounded_slots.push(json!({
                            "slot": binding.slot,
                            "bindingKind": "user_literal",
                            "value": grounded_value,
                            "origin": binding.origin,
                            "protectedSlotKind": binding.protected_slot_kind,
                        }));
                        verification_checks.push(format!(
                            "grounding_slot={}::user_literal_attested",
                            binding.slot
                        ));
                        continue;
                    }
                }

                if let Some(reference) = infer_symbolic_reference_from_query(
                    inference_binding,
                    agent_state,
                    &binding,
                    &user_query,
                )
                .await?
                {
                    let resolved_reference = resolve_symbolic_reference(
                        resolver_binding,
                        agent_state,
                        &binding,
                        &reference,
                    )
                    .await?;
                    record_grounded_symbolic_reference(
                        service,
                        arguments,
                        &mut grounded_slots,
                        verification_checks,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        synthesized_payload_hash.clone(),
                        &binding,
                        &reference,
                        resolved_reference,
                    );
                    verification_checks.push(format!(
                        "grounding_slot={}::query_inferred_symbolic_ref",
                        binding.slot
                    ));
                    continue;
                }

                if attested {
                    return Err(TransactionError::Invalid(format!(
                        "ERROR_CLASS=GroundingMissing Protected slot '{}' was attested by the user request but could not be validated as a canonical literal or resolved from connector state.",
                        binding.slot
                    )));
                }

                return Err(TransactionError::Invalid(format!(
                    "ERROR_CLASS=GroundingMissing Protected slot '{}' literal was not directly attested by the user request and could not be resolved from connector state.",
                    binding.slot
                )));
            }
            InstructionBindingKind::Unresolved => {
                if !matches!(binding.protected_slot_kind, ProtectedSlotKind::Unknown) {
                    if let Some(reference) = infer_symbolic_reference_from_query(
                        inference_binding,
                        agent_state,
                        &binding,
                        &user_query,
                    )
                    .await?
                    {
                        let resolved_reference = resolve_symbolic_reference(
                            resolver_binding,
                            agent_state,
                            &binding,
                            &reference,
                        )
                        .await?;
                        record_grounded_symbolic_reference(
                            service,
                            arguments,
                            &mut grounded_slots,
                            verification_checks,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            synthesized_payload_hash.clone(),
                            &binding,
                            &reference,
                            resolved_reference,
                        );
                        verification_checks.push(format!(
                            "grounding_slot={}::unresolved_query_inferred_symbolic_ref",
                            binding.slot
                        ));
                        continue;
                    }
                    return Err(TransactionError::Invalid(format!(
                        "ERROR_CLASS=GroundingMissing Protected slot '{}' remained unresolved.",
                        binding.slot
                    )));
                }
            }
        }
    }

    let grounding_commit = serde_jcs::to_vec(&grounded_slots)
        .ok()
        .and_then(|bytes| sha256(&bytes).ok())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|| "sha256:unavailable".to_string());
    mark_execution_receipt_with_value(
        &mut agent_state.tool_execution_log,
        "grounding",
        grounding_commit.clone(),
    );
    verification_checks.push(receipt_marker("grounding"));
    verification_checks.push(format!("grounding_commit={}", grounding_commit));

    serde_json::from_value::<AgentTool>(Value::Object(
        tool_value.as_object().cloned().unwrap_or_else(Map::new),
    ))
    .map_err(|error| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=GroundingMissing Failed to rebuild grounded tool payload: {}",
            error
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn slot(slot: &str, protected_slot_kind: ProtectedSlotKind) -> InstructionSlotBinding {
        InstructionSlotBinding {
            slot: slot.to_string(),
            binding_kind: InstructionBindingKind::UserLiteral,
            value: None,
            origin: ioi_types::app::agentic::ArgumentOrigin::UserSpan,
            protected_slot_kind,
        }
    }

    fn resolved_without_contract() -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "mail.reply".to_string(),
            scope: IntentScopeProfile::Conversation,
            band: IntentConfidenceBand::High,
            score: 0.99,
            top_k: vec![],
            required_capabilities: vec![],
            risk_class: "medium".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "test".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "test".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            provider_selection: None,
            constrained: false,
            required_receipts: vec!["grounding".to_string()],
            required_postconditions: vec!["mail.reply.completed".to_string()],
            instruction_contract: None,
        }
    }

    #[test]
    fn query_attests_explicit_email_literals_only_when_present() {
        let binding = slot("to", ProtectedSlotKind::EmailAddress);
        assert!(query_attests_protected_literal(
            "Draft an email to ioifoundationhl@gmail.com and do not send it.",
            &binding,
            "ioifoundationhl@gmail.com"
        ));
        assert!(!query_attests_protected_literal(
            "Draft an email to my connected Google address and do not send it.",
            &binding,
            "your-connected-email@example.com"
        ));
    }

    #[test]
    fn query_attests_symbolic_alias_phrases_for_protected_email_slots() {
        let binding = slot("to", ProtectedSlotKind::EmailAddress);
        assert!(query_attests_protected_literal(
            "Draft an email to my connected Google address with the subject hello.",
            &binding,
            "my connected Google address"
        ));
    }

    #[test]
    fn redacted_email_placeholder_recovers_single_explicit_query_email() {
        let binding = slot("to", ProtectedSlotKind::EmailAddress);
        assert_eq!(
            recover_redacted_protected_literal_from_query(
                "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM.",
                &binding,
                "<REDACTED:email>"
            )
            .as_deref(),
            Some("team@ioi.network")
        );
    }

    #[test]
    fn protected_slot_metadata_synthesizes_missing_bindings_for_google_tools() {
        let resolved = resolved_without_contract();
        let arguments = json!({
            "to": "your-connected-email@example.com",
            "subject": "hello",
            "body": "world"
        });
        let bindings = protected_slot_bindings_by_name(
            &resolved,
            Some("connector__google__gmail_draft_email"),
            arguments.as_object().expect("arguments object"),
        );
        let to = bindings.get("to").expect("protected slot binding");
        assert_eq!(to.binding_kind, InstructionBindingKind::UserLiteral);
        assert_eq!(to.origin, ArgumentOrigin::ModelInferred);
        assert_eq!(to.protected_slot_kind, ProtectedSlotKind::EmailAddress);
        assert_eq!(
            to.value.as_deref(),
            Some("your-connected-email@example.com")
        );
    }
}
