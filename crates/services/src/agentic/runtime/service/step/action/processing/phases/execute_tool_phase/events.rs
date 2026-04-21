use super::*;

const CEC_CONTRACT_VERSION: &str = "cec.v0.5";

pub(crate) fn emit_execution_contract_receipt_event_with_observation(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    stage: &str,
    key: &str,
    satisfied: bool,
    evidence_material: &str,
    probe_source: Option<&str>,
    observed_value: Option<&str>,
    evidence_type: Option<&str>,
    verifier_command_commit_hash: Option<String>,
    provider_id: Option<String>,
    synthesized_payload_hash: Option<String>,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let evidence_payload = format!(
        "intent_id={};stage={};key={};satisfied={};probe_source={};observed_value={};evidence_type={};evidence={}",
        intent_id,
        stage,
        key,
        satisfied,
        probe_source.unwrap_or(""),
        observed_value.unwrap_or(""),
        evidence_type.unwrap_or(""),
        evidence_material
    );
    let evidence_commit_hash = sha256(evidence_payload.as_bytes())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string());

    let _ = tx.send(KernelEvent::ExecutionContractReceipt(
        ioi_types::app::ExecutionContractReceiptEvent {
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
            probe_source: probe_source.map(str::to_string),
            observed_value: observed_value.map(str::to_string),
            evidence_type: evidence_type.map(str::to_string),
            provider_id,
            synthesized_payload_hash,
            authoritative: false,
        },
    ));
}

pub(crate) fn emit_execution_contract_receipt_event(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    stage: &str,
    key: &str,
    satisfied: bool,
    evidence_material: &str,
    verifier_command_commit_hash: Option<String>,
    provider_id: Option<String>,
    synthesized_payload_hash: Option<String>,
) {
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        intent_id,
        stage,
        key,
        satisfied,
        evidence_material,
        None,
        None,
        None,
        verifier_command_commit_hash,
        provider_id,
        synthesized_payload_hash,
    );
}

pub(crate) fn resolved_intent_id(agent_state: &AgentState) -> String {
    agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.intent_id.clone())
        .unwrap_or_else(|| "resolver.unclassified".to_string())
}

pub(super) fn synthesized_payload_hash_for_tool(tool: &AgentTool) -> Option<String> {
    let payload = sys_exec_command_preview(tool)?;
    let digest = sha256(payload.as_bytes()).ok()?;
    Some(format!("sha256:{}", hex::encode(digest.as_ref())))
}

fn stage_for_contract_key(key: &str) -> &'static str {
    match key {
        "host_discovery" => "discovery",
        "provider_selection" | PROVIDER_SELECTION_COMMIT_RECEIPT => "provider_selection",
        "execution"
        | "execution_artifact"
        | "notification_strategy"
        | TIMER_SLEEP_BACKEND_POSTCONDITION
        | TIMER_NOTIFICATION_PATH_POSTCONDITION => "execution",
        "verification" | VERIFICATION_COMMIT_RECEIPT | CLOCK_TIMESTAMP_POSTCONDITION => {
            "verification"
        }
        _ => "completion_gate",
    }
}

pub(crate) fn emit_completion_gate_status_event(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    satisfied: bool,
    evidence_material: &str,
) {
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        intent_id,
        "completion_gate",
        "contract_gate",
        satisfied,
        evidence_material,
        None,
        None,
        None,
    );
}

pub(super) fn emit_completion_gate_violation_events(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    missing_keys: &str,
) {
    emit_completion_gate_status_event(
        service,
        session_id,
        step_index,
        intent_id,
        false,
        missing_keys,
    );
    for token in missing_keys
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        if let Some(rest) = token.strip_prefix("receipt::") {
            let key = rest.trim_end_matches("=true").trim();
            if key.is_empty() {
                continue;
            }
            let stage = stage_for_contract_key(key);
            let evidence = format!("missing_receipt={}", key);
            emit_execution_contract_receipt_event(
                service, session_id, step_index, intent_id, stage, key, false, &evidence, None,
                None, None,
            );
        } else if let Some(rest) = token.strip_prefix("postcondition::") {
            let key = rest.trim_end_matches("=true").trim();
            if key.is_empty() {
                continue;
            }
            let stage = stage_for_contract_key(key);
            let evidence = format!("missing_postcondition={}", key);
            emit_execution_contract_receipt_event(
                service, session_id, step_index, intent_id, stage, key, false, &evidence, None,
                None, None,
            );
        }
    }
}
