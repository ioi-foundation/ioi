#[derive(Default)]
struct ExecutionReceiptMetadata {
    verifier_command_commit_hash: Option<String>,
    probe_source: Option<String>,
    observed_value: Option<String>,
    evidence_type: Option<String>,
    provider_id: Option<String>,
    synthesized_payload_hash: Option<String>,
    timestamp_ms: Option<u64>,
}

fn emit_execution_contract_receipt_event_with_metadata(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    stage: &str,
    key: &str,
    satisfied: bool,
    evidence_material: &str,
    metadata: ExecutionReceiptMetadata,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };

    let ExecutionReceiptMetadata {
        verifier_command_commit_hash,
        probe_source,
        observed_value,
        evidence_type,
        provider_id,
        synthesized_payload_hash,
        timestamp_ms,
    } = metadata;

    let timestamp_ms = timestamp_ms.unwrap_or_else(unix_timestamp_ms_now);
    let evidence_payload = format!(
        "intent_id={};stage={};key={};satisfied={};evidence={};probe_source={};observed_value={};evidence_type={};provider_id={};synthesized_payload_hash={};verifier_command_commit_hash={};timestamp_ms={}",
        intent_id,
        stage,
        key,
        satisfied,
        evidence_material,
        probe_source.as_deref().unwrap_or("none"),
        observed_value.as_deref().unwrap_or("none"),
        evidence_type.as_deref().unwrap_or("none"),
        provider_id.as_deref().unwrap_or("none"),
        synthesized_payload_hash.as_deref().unwrap_or("none"),
        verifier_command_commit_hash.as_deref().unwrap_or("none"),
        timestamp_ms,
    );
    let evidence_commit_hash = sha256(evidence_payload.as_bytes())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string());

    let _ = tx.send(KernelEvent::ExecutionContractReceipt(
        ExecutionContractReceiptEvent {
            contract_version: CEC_CONTRACT_VERSION.to_string(),
            session_id,
            step_index,
            intent_id: intent_id.to_string(),
            stage: stage.to_string(),
            key: key.to_string(),
            satisfied,
            timestamp_ms,
            evidence_commit_hash,
            verifier_command_commit_hash,
            probe_source,
            observed_value,
            evidence_type,
            provider_id,
            synthesized_payload_hash,
            authoritative: false,
        },
    ));
}

fn emit_execution_contract_receipt_event(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    stage: &str,
    key: &str,
    satisfied: bool,
    evidence_material: &str,
) {
    emit_execution_contract_receipt_event_with_metadata(
        service,
        session_id,
        step_index,
        intent_id,
        stage,
        key,
        satisfied,
        evidence_material,
        ExecutionReceiptMetadata::default(),
    );
}

fn emit_execution_phase_timing_receipt(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    key: &str,
    phase_started: Instant,
    satisfied: bool,
    status: &str,
    detail: serde_json::Value,
) {
    let finished_at_ms = unix_timestamp_ms_now();
    let elapsed_ms = phase_started.elapsed().as_millis() as u64;
    let started_at_ms = finished_at_ms.saturating_sub(elapsed_ms);
    let mut observed = json!({
        "status": status,
        "elapsed_ms": elapsed_ms,
        "started_at_ms": started_at_ms,
        "finished_at_ms": finished_at_ms,
    });
    if let Some(observed_map) = observed.as_object_mut() {
        match detail {
            serde_json::Value::Object(extra) => {
                for (key, value) in extra {
                    observed_map.insert(key, value);
                }
            }
            value => {
                observed_map.insert("detail".to_string(), value);
            }
        }
    }
    let observed_value = serde_json::to_string(&observed)
        .unwrap_or_else(|_| "{\"status\":\"serialization_error\"}".to_string());
    emit_execution_contract_receipt_event_with_metadata(
        service,
        session_id,
        step_index,
        intent_id,
        "execution",
        key,
        satisfied,
        &format!(
            "status={};elapsed_ms={};started_at_ms={};finished_at_ms={}",
            status, elapsed_ms, started_at_ms, finished_at_ms
        ),
        ExecutionReceiptMetadata {
            probe_source: Some("service_action_execution".to_string()),
            observed_value: Some(observed_value),
            evidence_type: Some("json".to_string()),
            timestamp_ms: Some(finished_at_ms),
            ..ExecutionReceiptMetadata::default()
        },
    );
}

fn persist_committed_action(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    committed_action: &CommittedAction,
) -> Result<(), TransactionError> {
    let key = determinism_commit_state_key(session_id, step_index);
    let bytes = ioi_types::codec::to_bytes_canonical(committed_action)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&key, &bytes)?;
    Ok(())
}

fn persist_determinism_evidence(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    request: &ActionRequest,
    committed_action: &CommittedAction,
    recovery_retry: bool,
    recovery_reason: Option<String>,
) -> Result<(), TransactionError> {
    let key = determinism_evidence_state_key(session_id, step_index);
    let evidence = DeterminismEvidence {
        schema_version: DeterminismEvidence::schema_version(),
        request: request.clone(),
        committed_action: committed_action.clone(),
        recovery_retry,
        recovery_reason,
    };
    let bytes = ioi_types::codec::to_bytes_canonical(&evidence)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&key, &bytes)?;
    Ok(())
}

fn persist_firewall_decision_receipt(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    verdict: PolicyVerdict,
    signing_context: Option<(ChainId, AccountId)>,
) -> Result<[u8; 32], TransactionError> {
    let (seq, prev_receipt_hash) = if step_index == 0 {
        (0u64, [0u8; 32])
    } else {
        let prev_key = firewall_decision_state_key(session_id, step_index.saturating_sub(1));
        let prev = state
            .get(&prev_key)?
            .and_then(|bytes| codec::from_bytes_canonical::<FirewallDecisionReceipt>(&bytes).ok());
        if let Some(prev) = prev {
            let prev_hash = firewall_decision_receipt_hash(&prev)?;
            (prev.seq.saturating_add(1), prev_hash)
        } else {
            (step_index as u64, [0u8; 32])
        }
    };

    let attestation_payload = json!({
        "request_hash": request_hash,
        "policy_hash": policy_hash,
        "verdict": verdict,
        "seq": seq,
        "prev_receipt_hash": prev_receipt_hash,
    });
    let attestation_bytes = serde_jcs::to_vec(&attestation_payload)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let guardian_sig = sign_firewall_attestation(state, signing_context, &attestation_bytes)?;

    let receipt = FirewallDecisionReceipt {
        request_hash,
        policy_hash,
        verdict,
        seq,
        prev_receipt_hash,
        guardian_sig,
    };
    let key = firewall_decision_state_key(session_id, step_index);
    let bytes = codec::to_bytes_canonical(&receipt)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&key, &bytes)?;
    firewall_decision_receipt_hash(&receipt)
}

fn persist_policy_decision_record(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    policy_decision: &PolicyDecisionRecord,
) -> Result<(), TransactionError> {
    policy_decision.verify().map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Policy decision verification failed: {}",
            e
        ))
    })?;
    let key = policy_decision_state_key(session_id, step_index);
    let bytes = codec::to_bytes_canonical(policy_decision)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&key, &bytes)?;
    Ok(())
}

fn persist_settlement_receipt_bundle(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    bundle: &SettlementReceiptBundle,
) -> Result<(), TransactionError> {
    bundle.verify().map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Settlement bundle verification failed: {}",
            e
        ))
    })?;
    let key = settlement_receipt_bundle_state_key(session_id, step_index);
    let bytes = codec::to_bytes_canonical(bundle)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&key, &bytes)?;
    Ok(())
}

fn persist_execution_observation_receipt(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    receipt_index: u16,
    receipt: &ExecutionObservationReceipt,
) -> Result<(), TransactionError> {
    receipt.verify().map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Execution observation verification failed: {}",
            e
        ))
    })?;
    let key = execution_observation_receipt_state_key(session_id, step_index, receipt_index);
    let bytes = codec::to_bytes_canonical(receipt)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&key, &bytes)?;
    Ok(())
}

fn persist_postcondition_proof(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    proof_index: u16,
    proof: &PostconditionProof,
) -> Result<(), TransactionError> {
    proof.verify().map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Postcondition proof verification failed: {}",
            e
        ))
    })?;
    let key = postcondition_proof_state_key(session_id, step_index, proof_index);
    let bytes = codec::to_bytes_canonical(proof)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&key, &bytes)?;
    Ok(())
}

fn persist_required_receipt_manifest(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    manifest: &RequiredReceiptManifest,
) -> Result<(), TransactionError> {
    manifest.verify().map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Required receipt manifest verification failed: {}",
            e
        ))
    })?;
    let key = required_receipt_manifest_state_key(session_id, step_index);
    let bytes = codec::to_bytes_canonical(manifest)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&key, &bytes)?;
    Ok(())
}

fn load_persisted_committed_action(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
) -> Result<CommittedAction, TransactionError> {
    let key = determinism_commit_state_key(session_id, step_index);
    let bytes = state.get(&key)?.ok_or_else(|| {
        TransactionError::Invalid(
            "Missing committed action while finalizing settlement".to_string(),
        )
    })?;
    codec::from_bytes_canonical(&bytes)
        .map_err(|e| TransactionError::Serialization(e.to_string()))
}

fn load_persisted_policy_decision(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
) -> Result<PolicyDecisionRecord, TransactionError> {
    let key = policy_decision_state_key(session_id, step_index);
    let bytes = state.get(&key)?.ok_or_else(|| {
        TransactionError::Invalid(
            "Missing policy decision while finalizing settlement".to_string(),
        )
    })?;
    codec::from_bytes_canonical(&bytes)
        .map_err(|e| TransactionError::Serialization(e.to_string()))
}

fn load_existing_settlement_bundle_hash(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
) -> Result<Option<[u8; 32]>, TransactionError> {
    let key = settlement_receipt_bundle_state_key(session_id, step_index);
    match state.get(&key)? {
        Some(bytes) => {
            let bundle: SettlementReceiptBundle = codec::from_bytes_canonical(&bytes)
                .map_err(|e| TransactionError::Serialization(e.to_string()))?;
            Ok(Some(bundle.artifact_root_hash))
        }
        None => Ok(None),
    }
}

fn default_required_receipt_manifest_for_target(
    target: &ActionTarget,
) -> Result<RequiredReceiptManifest, TransactionError> {
    RequiredReceiptManifest::build(
        target.canonical_label(),
        vec!["execution.outcome".to_string()],
        vec!["execution.terminal_outcome".to_string()],
    )
    .map_err(|e| TransactionError::Invalid(e.to_string()))
}

fn persist_terminal_settlement(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    determinism: &DeterminismContext,
    success: bool,
    history_entry: Option<&str>,
    error: Option<&str>,
    visual_artifact_hash: Option<[u8; 32]>,
    started_at_ms: u64,
    finished_at_ms: u64,
) -> Result<(), TransactionError> {
    let committed_action = load_persisted_committed_action(state, session_id, step_index)?;
    let policy_decision = load_persisted_policy_decision(state, session_id, step_index)?;
    let prior_bundle_hash = load_existing_settlement_bundle_hash(state, session_id, step_index)?;

    let manifest = default_required_receipt_manifest_for_target(&determinism.request.target)?;
    persist_required_receipt_manifest(state, session_id, step_index, &manifest)?;

    let execution_receipt = ExecutionObservationReceipt::build(
        determinism.request_hash,
        determinism.request.target.canonical_label(),
        "execution.outcome".to_string(),
        success,
        started_at_ms,
        finished_at_ms,
        history_entry.map(str::to_string),
        error.map(str::to_string),
        None,
        visual_artifact_hash,
    )
    .map_err(|e| TransactionError::Invalid(e.to_string()))?;
    persist_execution_observation_receipt(state, session_id, step_index, 0, &execution_receipt)?;

    let terminal_state = if success { "succeeded" } else { "failed" };
    let terminal_observed_value = match (history_entry, error) {
        (Some(entry), _) => Some(entry.to_string()),
        (_, Some(reason)) => Some(reason.to_string()),
        _ => Some(terminal_state.to_string()),
    };
    let postcondition_proof = PostconditionProof::build(
        determinism.request_hash,
        "execution.terminal_outcome".to_string(),
        success,
        terminal_observed_value,
        Some("terminal_outcome".to_string()),
        None,
        finished_at_ms,
    )
    .map_err(|e| TransactionError::Invalid(e.to_string()))?;
    persist_postcondition_proof(state, session_id, step_index, 0, &postcondition_proof)?;

    let bundle = SettlementReceiptBundle::build(
        determinism.request_hash,
        committed_action.commitment_hash,
        policy_decision.decision_hash,
        committed_action.approval_ref,
        vec![execution_receipt.receipt_hash],
        vec![postcondition_proof.proof_hash],
        Some(manifest.manifest_hash),
        prior_bundle_hash,
        terminal_state.to_string(),
    )
    .map_err(|e| TransactionError::Invalid(e.to_string()))?;
    persist_settlement_receipt_bundle(state, session_id, step_index, &bundle)?;
    Ok(())
}
