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
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let evidence_payload = format!(
        "intent_id={};stage={};key={};satisfied={};evidence={}",
        intent_id, stage, key, satisfied, evidence_material
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
            verifier_command_commit_hash: None,
            probe_source: None,
            observed_value: None,
            evidence_type: None,
            provider_id: None,
            synthesized_payload_hash: None,
        },
    ));
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
