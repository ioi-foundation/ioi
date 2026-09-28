fn firewall_decision_state_key(session_id: [u8; 32], step_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        FIREWALL_DECISION_STATE_PREFIX.len() + session_id.len() + std::mem::size_of::<u32>(),
    );
    key.extend_from_slice(FIREWALL_DECISION_STATE_PREFIX);
    key.extend_from_slice(&session_id);
    key.extend_from_slice(&step_index.to_be_bytes());
    key
}

fn firewall_decision_seq_state_key(session_id: [u8; 32], seq: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        FIREWALL_DECISION_SEQ_STATE_PREFIX.len() + session_id.len() + std::mem::size_of::<u64>(),
    );
    key.extend_from_slice(FIREWALL_DECISION_SEQ_STATE_PREFIX);
    key.extend_from_slice(&session_id);
    key.extend_from_slice(&seq.to_be_bytes());
    key
}

fn firewall_chain_head_state_key(session_id: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(FIREWALL_CHAIN_HEAD_STATE_PREFIX.len() + session_id.len());
    key.extend_from_slice(FIREWALL_CHAIN_HEAD_STATE_PREFIX);
    key.extend_from_slice(&session_id);
    key
}

fn firewall_decision_receipt_hash(
    receipt: &FirewallDecisionReceipt,
) -> Result<[u8; 32], TransactionError> {
    let canonical =
        serde_jcs::to_vec(receipt).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = sha256(&canonical).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Firewall receipt hash failed: {}",
            e
        ))
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

/// The bytes a firewall decision receipt's signature covers.
fn firewall_attestation_bytes(
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    verdict: &PolicyVerdict,
    seq: u64,
    prev_receipt_hash: [u8; 32],
) -> Result<Vec<u8>, TransactionError> {
    let attestation_payload = json!({
        "request_hash": request_hash,
        "policy_hash": policy_hash,
        "verdict": verdict,
        "seq": seq,
        "prev_receipt_hash": prev_receipt_hash,
    });
    serde_jcs::to_vec(&attestation_payload)
        .map_err(|e| TransactionError::Serialization(e.to_string()))
}

/// A decoded `guardian_sig`. `key_id` is `None` for a legacy receipt, whose seed was derived from
/// public values.
struct DecodedFirewallSignature {
    suite: SignatureSuite,
    key_id: Option<String>,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

fn decode_firewall_signature(
    encoded_envelope: &[u8],
) -> Result<DecodedFirewallSignature, TransactionError> {
    let decode_error = |e: String| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Firewall signature envelope decode failed: {}",
            e
        ))
    };
    if let Some(body) = encoded_envelope.strip_prefix(FIREWALL_SIGNATURE_ENVELOPE_V2_MAGIC) {
        let envelope: FirewallSignatureEnvelope =
            codec::from_bytes_canonical(body).map_err(decode_error)?;
        // The key id is the digest of the public key, so an envelope cannot name one key and
        // carry another.
        if crate::agentic::runtime::firewall_receipt_keys::firewall_receipt_key_id(
            &envelope.public_key,
        ) != envelope.key_id
        {
            return Err(TransactionError::Invalid(format!(
                "ERROR_CLASS=DeterminismBoundary Firewall signature names key {} but carries a different public key",
                envelope.key_id
            )));
        }
        return Ok(DecodedFirewallSignature {
            suite: envelope.suite,
            key_id: Some(envelope.key_id),
            public_key: envelope.public_key,
            signature: envelope.signature,
        });
    }
    let legacy: LegacyFirewallSignatureEnvelope =
        codec::from_bytes_canonical(encoded_envelope).map_err(decode_error)?;
    Ok(DecodedFirewallSignature {
        suite: legacy.suite,
        key_id: None,
        public_key: legacy.public_key,
        signature: legacy.signature,
    })
}

fn verify_firewall_attestation_signature(
    attestation_bytes: &[u8],
    encoded_envelope: &[u8],
) -> Result<DecodedFirewallSignature, TransactionError> {
    let envelope = decode_firewall_signature(encoded_envelope)?;
    if envelope.suite != SignatureSuite::ED25519 {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Unsupported firewall signature suite: {}",
            envelope.suite.0
        )));
    }

    let public_key = Ed25519PublicKey::from_bytes(&envelope.public_key).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Firewall public key decode failed: {}",
            e
        ))
    })?;
    let signature = Ed25519Signature::from_bytes(&envelope.signature).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Firewall signature decode failed: {}",
            e
        ))
    })?;
    public_key
        .verify(attestation_bytes, &signature)
        .map_err(|e| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=DeterminismBoundary Firewall signature verification failed: {}",
                e
            ))
        })?;
    Ok(envelope)
}

fn missing_firewall_receipt_key_error() -> TransactionError {
    TransactionError::Invalid(
        "ERROR_CLASS=DeterminismBoundary Firewall receipt signing key is not configured: the host must hold its own key (FirewallReceiptKeyStore); a key derived from public values is never used.".to_string(),
    )
}

fn sign_firewall_attestation(
    key_store: &FirewallReceiptKeyStore,
    signing_context: Option<(ChainId, AccountId)>,
    attestation_bytes: &[u8],
) -> Result<Vec<u8>, TransactionError> {
    let (_chain_id, signer_account_id) = signing_context.ok_or_else(|| {
        TransactionError::Invalid(
            "ERROR_CLASS=DeterminismBoundary Missing firewall signing context.".to_string(),
        )
    })?;
    let signed = key_store.sign(attestation_bytes).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Firewall attestation sign failed: {}",
            e
        ))
    })?;
    let envelope = FirewallSignatureEnvelope {
        suite: SignatureSuite::ED25519,
        signer_account_id: signer_account_id.0,
        key_id: signed.key_id,
        public_key: signed.public_key,
        signature: signed.signature,
    };
    let mut encoded = FIREWALL_SIGNATURE_ENVELOPE_V2_MAGIC.to_vec();
    encoded.extend(
        codec::to_bytes_canonical(&envelope)
            .map_err(|e| TransactionError::Serialization(e.to_string()))?,
    );
    verify_firewall_attestation_signature(attestation_bytes, &encoded)?;
    Ok(encoded)
}

/// Verify one receipt against the key this host holds for the key id it names, and return that
/// key id. A legacy receipt is refused: its key was derivable, so its signature vouches for nothing.
fn verify_firewall_decision_receipt(
    receipt: &FirewallDecisionReceipt,
    key_store: &FirewallReceiptKeyStore,
) -> Result<String, TransactionError> {
    let attestation_bytes = firewall_attestation_bytes(
        receipt.request_hash,
        receipt.policy_hash,
        &receipt.verdict,
        receipt.seq,
        receipt.prev_receipt_hash,
    )?;
    let envelope =
        verify_firewall_attestation_signature(&attestation_bytes, &receipt.guardian_sig)?;
    let key_id = envelope.key_id.ok_or_else(|| {
        TransactionError::Invalid(
            "ERROR_CLASS=DeterminismBoundary Firewall receipt is signed with a legacy key derived from public values; it cannot be verified as this host's".to_string(),
        )
    })?;
    let held = key_store
        .public_key_for(&key_id)
        .map_err(|e| TransactionError::Invalid(format!("ERROR_CLASS=DeterminismBoundary {e}")))?
        .ok_or_else(|| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=DeterminismBoundary Firewall receipt names key {key_id}, which this host has never held"
            ))
        })?;
    if held != envelope.public_key {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Firewall receipt key {key_id} does not match the key this host holds"
        )));
    }
    Ok(key_id)
}

fn compute_policy_hash(rules: &ActionRules) -> Result<[u8; 32], TransactionError> {
    let canonical =
        serde_jcs::to_vec(rules).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = ioi_crypto::algorithms::hash::sha256(&canonical).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Policy hash failed: {}",
            e
        ))
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn compute_approval_grant_ref(grant: &ApprovalGrant) -> Result<[u8; 32], TransactionError> {
    grant
        .artifact_hash()
        .map_err(|e| TransactionError::Invalid(format!("Invalid approval grant hash: {}", e)))
}

fn default_policy_label(rules: &ActionRules) -> &'static str {
    match rules.defaults {
        crate::agentic::rules::DefaultPolicy::AllowAll => "allow_all",
        crate::agentic::rules::DefaultPolicy::DenyAll => "deny_all",
        crate::agentic::rules::DefaultPolicy::RequireApproval => "require_approval",
    }
}

fn emit_policy_decision_and_exit(
    service: &RuntimeAgentService,
    rules: &ActionRules,
    policy_record: Option<&PolicyEvaluationRecord>,
    execution_state: &mut Option<&mut dyn StateAccess>,
    session_id: [u8; 32],
    step_index: u32,
    target_str: &str,
    determinism: &DeterminismContext,
    verdict: &str,
    firewall_verdict: PolicyVerdict,
    exit_error: TransactionError,
) -> Result<TransactionError, TransactionError> {
    let firewall_receipt_hash = if let Some(state) = execution_state.as_deref_mut() {
        if verdict == "REQUIRE_APPROVAL" {
            state.insert(
                &crate::agentic::runtime::keys::get_approval_policy_hash_key(
                    &session_id,
                    &determinism.request_hash,
                ),
                &determinism.policy_hash,
            )?;
        }
        let matched_rules = policy_record
            .map(PolicyEvaluationRecord::matched_rules_for_decision)
            .unwrap_or_else(|| vec![format!("default:{}", default_policy_label(rules))]);
        let policy_decision = PolicyDecisionRecord::build(
            determinism.request_hash,
            determinism.policy_hash,
            matched_rules,
            default_policy_label(rules).to_string(),
            None,
            verdict == "REQUIRE_APPROVAL" || matches!(firewall_verdict, PolicyVerdict::Approved(_)),
            firewall_verdict.clone(),
        )
        .map_err(|e| TransactionError::Invalid(e.to_string()))?;
        persist_policy_decision_record(state, session_id, step_index, &policy_decision)?;
        Some(persist_firewall_decision_receipt(
            state,
            service.firewall_receipt_keys.as_deref(),
            session_id,
            step_index,
            determinism.request_hash,
            determinism.policy_hash,
            firewall_verdict,
            determinism.signing_context,
        )?)
    } else {
        None
    };
    emit_execution_contract_receipt_event_with_metadata(
        service,
        session_id,
        step_index,
        &determinism.intent_id,
        "execution",
        "policy_decision",
        false,
        &format!(
            "decision={};policy_hash={};request_hash={};firewall_receipt_hash={}",
            verdict,
            hex::encode(determinism.policy_hash),
            hex::encode(determinism.request_hash),
            firewall_receipt_hash
                .map(hex::encode)
                .unwrap_or_else(|| "unavailable".to_string())
        ),
        ExecutionReceiptMetadata::default(),
    );
    if let Some(tx) = &service.event_sender {
        let _ = tx.send(KernelEvent::FirewallInterception {
            verdict: verdict.to_string(),
            target: target_str.to_string(),
            request_hash: determinism.request_hash,
            session_id: Some(session_id),
        });
    }
    Ok(exit_error)
}

async fn enforce_policy_and_record(
    service: &RuntimeAgentService,
    tool: &AgentTool,
    rules: &ActionRules,
    agent_state: &AgentState,
    os_driver: &Arc<dyn OsDriver>,
    session_id: [u8; 32],
    step_index: u32,
    execution_state: &mut Option<&mut dyn StateAccess>,
    determinism: &DeterminismContext,
) -> Result<(), TransactionError> {
    // 3. Policy Check
    let skip_policy = matches!(tool, AgentTool::SystemFail { .. });
    if skip_policy {
        return Ok(());
    }

    emit_execution_contract_receipt_event_with_metadata(
        service,
        session_id,
        step_index,
        &determinism.intent_id,
        "execution",
        "policy_hash_binding",
        true,
        &format!(
            "policy_hash={};request_hash={};target={}",
            hex::encode(determinism.policy_hash),
            hex::encode(determinism.request_hash),
            determinism.target_str
        ),
        ExecutionReceiptMetadata::default(),
    );

    let workload_lease_check = determinism.workload_spec.evaluate_lease(
        &determinism.request.target,
        determinism.observed_domain.as_deref(),
        unix_timestamp_ms_now(),
    );
    let workload_lease_reason = workload_lease_check
        .reason
        .as_deref()
        .unwrap_or("none")
        .to_string();
    emit_execution_contract_receipt_event_with_metadata(
        service,
        session_id,
        step_index,
        &determinism.intent_id,
        "execution",
        "capability_lease",
        workload_lease_check.satisfied,
        &format!(
            "observed_value={};probe_source={};timestamp_ms={};satisfied={};reason={};runtime_target={};net_mode={}",
            workload_lease_check.observed_value,
            workload_lease_check.probe_source,
            workload_lease_check.timestamp_ms,
            workload_lease_check.satisfied,
            workload_lease_reason,
            determinism.workload_spec.runtime_target.as_label(),
            determinism.workload_spec.net_mode.as_label()
        ),
        ExecutionReceiptMetadata {
            probe_source: Some(workload_lease_check.probe_source.clone()),
            observed_value: Some(workload_lease_check.observed_value.clone()),
            evidence_type: Some("scalar".to_string()),
            timestamp_ms: Some(workload_lease_check.timestamp_ms),
            ..ExecutionReceiptMetadata::default()
        },
    );
    if !workload_lease_check.satisfied {
        let exit = emit_policy_decision_and_exit(
            service,
            rules,
            None,
            execution_state,
            session_id,
            step_index,
            &determinism.target_str,
            determinism,
            "REQUIRE_APPROVAL",
            PolicyVerdict::Block(format!("out_of_lease:{}", workload_lease_reason)),
            TransactionError::PendingApproval(hex::encode(determinism.request_hash)),
        )?;
        return Err(exit);
    }

    if let Some(false) = crate::agentic::policy::filesystem_request_stays_within_workspace(
        &determinism.request.target,
        &determinism.request.params,
        Some(agent_state.working_directory.as_str()),
    ) {
        let exit = emit_policy_decision_and_exit(
            service,
            rules,
            None,
            execution_state,
            session_id,
            step_index,
            &determinism.target_str,
            determinism,
            "BLOCK",
            PolicyVerdict::Block("workspace_filesystem_boundary".to_string()),
            TransactionError::Invalid(
                "Blocked by Policy: filesystem path is outside workspace authority.".to_string(),
            ),
        )?;
        return Err(exit);
    }

    let matched_approval_grant = execution_state
        .as_deref_mut()
        .map(|state| {
            let key = get_approval_grant_key(&session_id);
            match state.get(&key) {
                Ok(Some(bytes)) => {
                    let grant: ApprovalGrant = codec::from_bytes_canonical(&bytes).map_err(|e| {
                        TransactionError::Invalid(format!("Invalid approval grant: {}", e))
                    })?;
                    let scope_context =
                        crate::agentic::runtime::kernel::approval::ApprovalScopeContext::from_action_request(
                            &determinism.request,
                        )
                        .with_operation_label("desktop_agent.resume");
                    crate::agentic::runtime::service::actions::resume::validate_registered_approval_grant(
                        state,
                        &grant,
                        None,
                        Some(determinism.policy_hash),
                        Some(&scope_context),
                    )?;
                    if grant.request_hash == determinism.request_hash
                        && grant.policy_hash == determinism.policy_hash
                    {
                        Ok(Some(grant))
                    } else {
                        Ok(None)
                    }
                }
                Ok(None) => Ok(None),
                Err(err) => Err(TransactionError::State(err)),
            }
        })
        .transpose()?
        .flatten();
    let approved_by_runtime_secret = approvals::is_runtime_secret_install_retry_approved(
        tool,
        determinism.tool_hash,
        session_id,
        agent_state,
    );
    let is_approved = matched_approval_grant.is_some() || approved_by_runtime_secret;
    use crate::agentic::policy::PolicyEngine;
    use crate::agentic::rules::Verdict;
    let policy_record = PolicyEngine::evaluate_record_with_working_directory(
        rules,
        &determinism.request,
        Some(agent_state.working_directory.as_str()),
        &service.scrubber.model,
        os_driver,
    )
    .await;

    if matches!(
        determinism.request.target,
        ActionTarget::SoftwareInstallExecute
    ) && !is_approved
    {
        let mut install_gate_record = policy_record.clone();
        install_gate_record
            .matched_rule_ids
            .push("cec:install_requires_explicit_approval".to_string());
        log::info!(
            "Policy Gate: CEC install approval invariant requires approval for hash: {}",
            hex::encode(determinism.request_hash)
        );
        let exit = emit_policy_decision_and_exit(
            service,
            rules,
            Some(&install_gate_record),
            execution_state,
            session_id,
            step_index,
            &determinism.target_str,
            determinism,
            "REQUIRE_APPROVAL",
            PolicyVerdict::Block("install_requires_explicit_approval".to_string()),
            TransactionError::PendingApproval(hex::encode(determinism.request_hash)),
        )?;
        return Err(exit);
    }

    let firewall_verdict = match policy_record.verdict {
        Verdict::Allow => {
            if let Some(grant) = matched_approval_grant.as_ref() {
                log::info!(
                    "Policy Gate: ApprovalGrant present for allowed hash {}",
                    hex::encode(determinism.request_hash)
                );
                let approval_ref = compute_approval_grant_ref(grant)?;
                PolicyVerdict::Approved(approval_ref)
            } else {
                PolicyVerdict::Allow
            }
        }
        Verdict::Block => {
            let exit = emit_policy_decision_and_exit(
                service,
                rules,
                Some(&policy_record),
                execution_state,
                session_id,
                step_index,
                &determinism.target_str,
                determinism,
                "BLOCK",
                PolicyVerdict::Block("blocked_by_policy".to_string()),
                TransactionError::Invalid("Blocked by Policy".into()),
            )?;
            return Err(exit);
        }
        Verdict::RequireApproval => {
            if is_approved {
                if let Some(grant) = matched_approval_grant.as_ref() {
                    log::info!(
                        "Policy Gate: Pre-approved via ApprovalGrant for hash {}",
                        hex::encode(determinism.request_hash)
                    );
                    let approval_ref = compute_approval_grant_ref(grant)?;
                    PolicyVerdict::Approved(approval_ref)
                } else {
                    log::info!(
                        "Policy Gate: Pre-approved via runtime secret retry for hash {}",
                        hex::encode(determinism.request_hash)
                    );
                    PolicyVerdict::Allow
                }
            } else {
                log::info!(
                    "Policy Gate: RequireApproval for hash: {}",
                    hex::encode(determinism.request_hash)
                );
                let exit = emit_policy_decision_and_exit(
                    service,
                    rules,
                    Some(&policy_record),
                    execution_state,
                    session_id,
                    step_index,
                    &determinism.target_str,
                    determinism,
                    "REQUIRE_APPROVAL",
                    PolicyVerdict::Block("require_approval".to_string()),
                    TransactionError::PendingApproval(hex::encode(determinism.request_hash)),
                )?;
                return Err(exit);
            }
        }
    };

    let policy_decision = PolicyDecisionRecord::build(
        determinism.request_hash,
        determinism.policy_hash,
        policy_record.matched_rules_for_decision(),
        default_policy_label(rules).to_string(),
        workload_lease_check
            .reason
            .as_ref()
            .filter(|_| !workload_lease_check.satisfied)
            .cloned(),
        matches!(firewall_verdict, PolicyVerdict::Approved(_)),
        firewall_verdict.clone(),
    )
    .map_err(|e| TransactionError::Invalid(e.to_string()))?;

    let firewall_receipt_hash = if let Some(state) = execution_state.as_deref_mut() {
        persist_policy_decision_record(state, session_id, step_index, &policy_decision)?;
        Some(persist_firewall_decision_receipt(
            state,
            service.firewall_receipt_keys.as_deref(),
            session_id,
            step_index,
            determinism.request_hash,
            determinism.policy_hash,
            firewall_verdict,
            determinism.signing_context,
        )?)
    } else {
        None
    };
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        &determinism.intent_id,
        "execution",
        "firewall_decision_receipt",
        true,
        &format!(
            "request_hash={};policy_hash={};firewall_receipt_hash={}",
            hex::encode(determinism.request_hash),
            hex::encode(determinism.policy_hash),
            firewall_receipt_hash
                .map(hex::encode)
                .unwrap_or_else(|| "unavailable".to_string())
        ),
    );

    let approval_ref = if let Some(grant) = matched_approval_grant.as_ref() {
        Some(compute_approval_grant_ref(grant)?)
    } else {
        None
    };
    let recovery_retry = agent_state.consecutive_failures > 0;
    let recovery_reason = recovery_retry
        .then(|| format!("consecutive_failures={}", agent_state.consecutive_failures));

    let committed_action =
        CommittedAction::commit(&determinism.request, determinism.policy_hash, approval_ref)
            .map_err(|e| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=DeterminismBoundary Unable to commit action: {}",
                    e
                ))
            })?;

    committed_action
        .verify(&determinism.request, determinism.policy_hash, approval_ref)
        .map_err(|e| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=DeterminismBoundary Commit verification failed: {}",
                e
            ))
        })?;

    if let Some(state) = execution_state.as_deref_mut() {
        persist_committed_action(state, session_id, step_index, &committed_action)?;
        persist_determinism_evidence(
            state,
            session_id,
            step_index,
            &determinism.request,
            &committed_action,
            recovery_retry,
            recovery_reason.clone(),
        )?;
    }

    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        &determinism.intent_id,
        "execution",
        "determinism_commit",
        true,
        &format!(
            "commitment_hash={};request_hash={};policy_hash={};recovery_retry={}",
            hex::encode(committed_action.commitment_hash),
            hex::encode(committed_action.request_hash),
            hex::encode(committed_action.policy_hash),
            recovery_retry
        ),
    );

    Ok(())
}
