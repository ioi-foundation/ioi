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
    service: &DesktopAgentService,
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
        },
    ));
}

fn emit_execution_contract_receipt_event(
    service: &DesktopAgentService,
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
    service: &DesktopAgentService,
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
