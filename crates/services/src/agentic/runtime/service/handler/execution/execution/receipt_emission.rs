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

/// Find where the next firewall decision receipt of `session_id` links: its `seq` and the hash of
/// the receipt before it.
///
/// The chain never restarts silently. A session with a chain head must still hold the receipt the
/// head names, unaltered and signed by a key this host holds; anything else is a hard error. A
/// session without a head is either new (genesis) or was written before heads existed, in which
/// case the chain continues from its latest legacy receipt instead of starting over beside it.
fn resolve_firewall_chain_link(
    state: &dyn StateAccess,
    key_store: &FirewallReceiptKeyStore,
    session_id: [u8; 32],
) -> Result<(u64, [u8; 32]), TransactionError> {
    let broken = |detail: String| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=ReceiptChainBroken Firewall receipt chain for session {}: {}; refusing to start a new chain",
            hex::encode(&session_id[..8]),
            detail
        ))
    };

    if let Some(head_bytes) = state.get(&firewall_chain_head_state_key(session_id))? {
        let head: FirewallChainHead = codec::from_bytes_canonical(&head_bytes)
            .map_err(|e| broken(format!("the chain head is unreadable ({e})")))?;
        let prev_bytes = state
            .get(&firewall_decision_seq_state_key(session_id, head.seq))?
            .ok_or_else(|| {
                broken(format!(
                    "the previous receipt (seq {}, step {}) is missing",
                    head.seq, head.step_index
                ))
            })?;
        let prev: FirewallDecisionReceipt =
            codec::from_bytes_canonical(&prev_bytes).map_err(|e| {
                broken(format!(
                    "the previous receipt (seq {}) is unreadable ({e})",
                    head.seq
                ))
            })?;
        let prev_hash = firewall_decision_receipt_hash(&prev)?;
        if prev.seq != head.seq || prev_hash != head.receipt_hash {
            return Err(broken(format!(
                "the previous receipt (seq {}) does not match the chain head",
                head.seq
            )));
        }
        verify_firewall_decision_receipt(&prev, key_store).map_err(|e| {
            broken(format!(
                "the previous receipt (seq {}) does not verify ({e})",
                head.seq
            ))
        })?;
        let seq = head
            .seq
            .checked_add(1)
            .ok_or_else(|| broken("the sequence is exhausted".to_string()))?;
        return Ok((seq, prev_hash));
    }

    let mut seq_prefix = FIREWALL_DECISION_SEQ_STATE_PREFIX.to_vec();
    seq_prefix.extend_from_slice(&session_id);
    if state.prefix_scan(&seq_prefix)?.next().is_some() {
        return Err(broken(
            "the chain head is missing while sequenced receipts exist".to_string(),
        ));
    }

    // Receipts written before chain heads existed are keyed only by step. Continue from the
    // latest of them. Keys are matched from the end, since a namespaced state returns them
    // qualified.
    let mut step_prefix = FIREWALL_DECISION_STATE_PREFIX.to_vec();
    step_prefix.extend_from_slice(&session_id);
    let mut latest: Option<(u32, Vec<u8>)> = None;
    for entry in state.prefix_scan(&step_prefix)? {
        let (key, value) = entry?;
        let Some(split) = key.len().checked_sub(std::mem::size_of::<u32>()) else {
            continue;
        };
        if !key[..split].ends_with(&step_prefix) {
            continue;
        }
        let mut step_bytes = [0u8; 4];
        step_bytes.copy_from_slice(&key[split..]);
        let step = u32::from_be_bytes(step_bytes);
        if latest
            .as_ref()
            .map_or(true, |(latest_step, _)| step > *latest_step)
        {
            latest = Some((step, value.to_vec()));
        }
    }
    let Some((step, prev_bytes)) = latest else {
        return Ok((0, [0u8; 32]));
    };
    let prev: FirewallDecisionReceipt = codec::from_bytes_canonical(&prev_bytes).map_err(|e| {
        broken(format!(
            "the legacy receipt at step {step} is unreadable ({e})"
        ))
    })?;
    if decode_firewall_signature(&prev.guardian_sig)
        .map_err(|e| broken(format!("the receipt at step {step} is unreadable ({e})")))?
        .key_id
        .is_some()
    {
        // Only a writer that also writes the head names a host key, so the head was lost.
        return Err(broken(format!(
            "the chain head is missing while the receipt at step {step} names a host key"
        )));
    }
    log::warn!(
        "Firewall receipt chain for session {} continues from legacy receipt seq {} (step {}); receipts up to it were signed with a key derived from public values",
        hex::encode(&session_id[..8]),
        prev.seq,
        step
    );
    let prev_hash = firewall_decision_receipt_hash(&prev)?;
    let seq = prev
        .seq
        .checked_add(1)
        .ok_or_else(|| broken("the sequence is exhausted".to_string()))?;
    Ok((seq, prev_hash))
}

fn persist_firewall_decision_receipt(
    state: &mut dyn StateAccess,
    key_store: Option<&FirewallReceiptKeyStore>,
    session_id: [u8; 32],
    step_index: u32,
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    verdict: PolicyVerdict,
    signing_context: Option<(ChainId, AccountId)>,
) -> Result<[u8; 32], TransactionError> {
    let key_store = key_store.ok_or_else(missing_firewall_receipt_key_error)?;
    let (seq, prev_receipt_hash) = resolve_firewall_chain_link(&*state, key_store, session_id)?;

    let attestation_bytes =
        firewall_attestation_bytes(request_hash, policy_hash, &verdict, seq, prev_receipt_hash)?;
    let guardian_sig = sign_firewall_attestation(key_store, signing_context, &attestation_bytes)?;

    let receipt = FirewallDecisionReceipt {
        request_hash,
        policy_hash,
        verdict,
        seq,
        prev_receipt_hash,
        guardian_sig,
    };
    let bytes = codec::to_bytes_canonical(&receipt)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let receipt_hash = firewall_decision_receipt_hash(&receipt)?;
    // The sequenced copy first and the head last: a head is only ever written over a receipt
    // that is already in place.
    state.insert(&firewall_decision_seq_state_key(session_id, seq), &bytes)?;
    state.insert(&firewall_decision_state_key(session_id, step_index), &bytes)?;
    let head = FirewallChainHead {
        seq,
        step_index,
        receipt_hash,
    };
    let head_bytes = codec::to_bytes_canonical(&head)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&firewall_chain_head_state_key(session_id), &head_bytes)?;
    Ok(receipt_hash)
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
