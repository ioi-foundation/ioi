use super::*;

pub(super) fn effective_intent_catalog(
    policy: &IntentRoutingPolicy,
) -> Result<Vec<IntentCatalogEntry>, TransactionError> {
    let mut merged = BTreeMap::<String, IntentCatalogEntry>::new();
    for entry in &policy.intent_catalog {
        let intent_id = entry.intent_id.trim();
        if intent_id.is_empty() {
            return Err(TransactionError::Invalid(
                "ERROR_CLASS=OntologyViolation Intent catalog contains empty intent_id".to_string(),
            ));
        }
        let preferred_tier = entry.preferred_tier.trim();
        if !valid_preferred_tier_label(preferred_tier) {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=OntologyViolation Intent '{}' has unsupported preferred_tier '{}'",
                intent_id, entry.preferred_tier
            )));
        }
        let semantic_descriptor = entry.semantic_descriptor.trim();
        if semantic_descriptor.is_empty() {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=OntologyViolation Intent '{}' has empty semantic_descriptor",
                intent_id
            )));
        }
        let risk_class = entry.risk_class.trim();
        if risk_class.is_empty() {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=OntologyViolation Intent '{}' has empty risk_class",
                intent_id
            )));
        }
        let mut normalized = entry.clone();
        normalized.intent_id = intent_id.to_string();
        normalized.semantic_descriptor = semantic_descriptor.to_string();
        normalized.risk_class = risk_class.to_string();
        normalized.preferred_tier = preferred_tier.to_string();
        normalized.required_capabilities = normalized
            .required_capabilities
            .iter()
            .filter_map(|capability| {
                let value = capability.0.trim();
                (!value.is_empty()).then_some(CapabilityId::from(value))
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if merged
            .insert(normalized.intent_id.clone(), normalized)
            .is_some()
        {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=OntologyViolation Intent catalog contains duplicate intent_id '{}'",
                intent_id
            )));
        }
    }
    Ok(merged.into_values().collect())
}

pub(super) fn intent_catalog_source_hash(
    policy: &IntentRoutingPolicy,
    intent_catalog: &[IntentCatalogEntry],
) -> Result<[u8; 32], TransactionError> {
    let payload = json!({
        "intent_catalog_version": policy.intent_catalog_version,
        "intent_catalog": intent_catalog,
        "score_quantization_bps": quantization_step_bps(policy),
        "tie_region_eps_bps": tie_region_eps_bps(policy),
        "ambiguity_margin_bps": ambiguity_margin_bps(policy),
        "ambiguity_abstain_exempt_intents": policy.ambiguity_abstain_exempt_intents,
    });
    let canonical =
        serde_jcs::to_vec(&payload).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = sha256(&canonical).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

pub(super) fn hash_payload(payload: &serde_json::Value) -> Result<[u8; 32], TransactionError> {
    let canonical =
        serde_jcs::to_vec(payload).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = sha256(&canonical).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

pub(super) fn intent_set_hash(
    intent_catalog: &[IntentCatalogEntry],
) -> Result<[u8; 32], TransactionError> {
    let payload = json!({
        "intents": intent_catalog.iter().map(|entry| json!({
            "intent_id": entry.intent_id,
            "semantic_descriptor": entry.semantic_descriptor,
            "query_binding": entry.query_binding,
            "required_capabilities": entry.required_capabilities,
            "risk_class": entry.risk_class,
        })).collect::<Vec<_>>(),
    });
    hash_payload(&payload)
}

pub(super) fn tool_registry_hash(
    bindings: &[ToolCapabilityBinding],
) -> Result<[u8; 32], TransactionError> {
    let payload = json!({
        "bindings": bindings.iter().map(|binding| json!({
            "tool_name": binding.tool_name,
            "action_target": binding.action_target.canonical_label(),
            "capabilities": binding.capabilities,
        })).collect::<Vec<_>>(),
    });
    hash_payload(&payload)
}

pub(super) fn capability_ontology_hash(
    bindings: &[ToolCapabilityBinding],
) -> Result<[u8; 32], TransactionError> {
    let mut capability_ids = BTreeSet::<String>::new();
    for binding in bindings {
        for capability in &binding.capabilities {
            capability_ids.insert(capability.0.clone());
        }
    }
    let payload = json!({
        "capabilities": capability_ids.into_iter().collect::<Vec<_>>(),
    });
    hash_payload(&payload)
}

pub(super) fn evidence_requirements_hash(
    query: &str,
    normalized_query: &str,
    resolved: &ResolvedIntentState,
    policy: &IntentRoutingPolicy,
    session_id: Option<[u8; 32]>,
    active_window_title: &str,
) -> Result<[u8; 32], TransactionError> {
    let query_hash =
        sha256(query.as_bytes()).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let normalized_query_hash = sha256(normalized_query.as_bytes())
        .map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let payload = json!({
        "contract_version": CIRC_CONTRACT_VERSION,
        "query": query,
        "query_hash": hex::encode(query_hash.as_ref()),
        "normalized_query": normalized_query,
        "normalized_query_hash": hex::encode(normalized_query_hash.as_ref()),
        "query_normalization_version": resolved.query_normalization_version,
        "session_id": session_id.map(hex::encode),
        "active_window_title": active_window_title,
        "intent_id": resolved.intent_id,
        "scope": resolved.scope,
        "band": resolved.band,
        "score": resolved.score,
        "top_k": resolved.top_k,
        "required_capabilities": resolved.required_capabilities,
        "required_evidence": resolved.required_evidence,
        "success_conditions": resolved.success_conditions,
        "risk_class": resolved.risk_class,
        "preferred_tier": resolved.preferred_tier,
        "intent_catalog_version": resolved.intent_catalog_version,
        "embedding_model_id": resolved.embedding_model_id,
        "embedding_model_version": resolved.embedding_model_version,
        "similarity_function_id": resolved.similarity_function_id,
        "intent_set_hash": hex::encode(resolved.intent_set_hash),
        "tool_registry_hash": hex::encode(resolved.tool_registry_hash),
        "capability_ontology_hash": hex::encode(resolved.capability_ontology_hash),
        "intent_catalog_source_hash": hex::encode(resolved.intent_catalog_source_hash),
        "provider_selection": resolved.provider_selection,
        "instruction_contract": resolved.instruction_contract,
        "score_quantization_bps": quantization_step_bps(policy),
        "tie_region_eps_bps": tie_region_eps_bps(policy),
        "ambiguity_margin_bps": ambiguity_margin_bps(policy),
        "selected_intent_id": resolved.intent_id,
        "selected_score_quantized": resolved.score,
        "ambiguity_abstain_exempt_intents": policy.ambiguity_abstain_exempt_intents,
        "constrained": resolved.constrained,
    });
    let canonical =
        serde_jcs::to_vec(&payload).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = sha256(&canonical).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

pub(super) fn emit_intent_resolution_receipt(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    resolved: &ResolvedIntentState,
    error_class: Option<String>,
) {
    if let Some(tx) = service.event_sender.as_ref() {
        let _ = tx.send(KernelEvent::IntentResolutionReceipt(
            IntentResolutionReceiptEvent {
                contract_version: CIRC_CONTRACT_VERSION.to_string(),
                session_id: Some(session_id),
                intent_id: resolved.intent_id.clone(),
                selected_intent_id: resolved.intent_id.clone(),
                scope: resolved.scope,
                band: resolved.band,
                score: resolved.score,
                selected_score_quantized: resolved.score,
                top_k: resolved.top_k.clone(),
                preferred_tier: resolved.preferred_tier.clone(),
                intent_catalog_version: resolved.intent_catalog_version.clone(),
                embedding_model_id: resolved.embedding_model_id.clone(),
                embedding_model_version: resolved.embedding_model_version.clone(),
                similarity_function_id: resolved.similarity_function_id.clone(),
                intent_set_hash: resolved.intent_set_hash,
                tool_registry_hash: resolved.tool_registry_hash,
                capability_ontology_hash: resolved.capability_ontology_hash,
                query_normalization_version: resolved.query_normalization_version.clone(),
                intent_catalog_source_hash: resolved.intent_catalog_source_hash,
                evidence_requirements_hash: resolved.evidence_requirements_hash,
                provider_selection: resolved.provider_selection.clone(),
                error_class,
                constrained: resolved.constrained,
            },
        ));
    }
}
