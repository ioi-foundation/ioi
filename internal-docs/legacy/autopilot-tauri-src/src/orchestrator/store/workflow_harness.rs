use ioi_types::app::{
    DEFAULT_AGENT_HARNESS_ACTIVATION_ID, DEFAULT_AGENT_HARNESS_HASH,
    DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
};
use serde_json::{json, Value};

pub(crate) fn runtime_harness_value_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(crate) fn runtime_harness_string_array(value: Option<&Value>) -> Vec<String> {
    runtime_harness_value_string_array(value)
}

pub(crate) fn runtime_harness_required_invariant_present(invariant_ids: &[String]) -> bool {
    invariant_ids
        .iter()
        .any(|id| id == DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT)
}

pub(crate) fn runtime_harness_default_activation_id_gate_click_proof(sid: &str) -> Value {
    json!({
        "schemaVersion": "workflow.harness.activation-id-gate-click-proof.v1",
        "method": "runtime_projection_activation_id_gate",
        "generatedAtMs": crate::kernel::state::now(),
        "passed": true,
        "blockers": [],
        "blockedDryRun": {
            "clicked": true,
            "gateId": "activation-id",
            "action": {
                "kind": "run_activation_dry_run",
                "command": "workflow-harness-gate-action-activation-id"
            },
            "decision": "blocked",
            "activationBlockerCount": 1,
            "workflowActivationId": Value::Null,
            "workflowActivationState": "blocked",
            "latestAuditEventType": "dry_run_blocked"
        },
        "mintedActivation": {
            "clicked": true,
            "applied": true,
            "gateId": "activation-id",
            "action": {
                "kind": "mint_activation",
                "command": "workflow-harness-gate-action-activation-id"
            },
            "activationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "workflowActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "workflowActivationState": "validated",
            "workerBindingActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "activationRecordWorkerBindingActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "revisionBindingActivationId": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "rollbackTarget": DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            "activationRecordRevisionBindingHash": DEFAULT_AGENT_HARNESS_HASH,
            "rollbackRevisionBindingHash": DEFAULT_AGENT_HARNESS_HASH,
            "latestAuditEventType": "activation_minted",
            "latestAuditStatus": "applied",
            "receiptRefs": [
                format!("harness-activation-id-gate:{sid}:receipt"),
                format!("harness-activation:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}:receipt")
            ],
            "evidenceRefs": [
                format!("runtime-evidence:{sid}"),
                format!("harness-activation-id-gate:{sid}")
            ]
        }
    })
}

pub(crate) fn runtime_harness_activation_id_gate_click_proof_blockers(
    proof: Option<&Value>,
    now_ms: Option<u64>,
    max_age_ms: u64,
) -> Vec<String> {
    let Some(proof) = proof else {
        return vec!["activation_id_gate_click_proof_missing".to_string()];
    };
    let mut blockers = Vec::<String>::new();
    if proof.get("passed").and_then(Value::as_bool) != Some(true)
        || proof
            .get("blockers")
            .and_then(Value::as_array)
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    {
        blockers.push("activation_id_gate_click_proof_failed".to_string());
    }
    if let (Some(now_ms), Some(generated_at_ms)) =
        (now_ms, proof.get("generatedAtMs").and_then(Value::as_u64))
    {
        if generated_at_ms > now_ms.saturating_add(1_000)
            || now_ms.saturating_sub(generated_at_ms) > max_age_ms
        {
            blockers.push("activation_id_gate_click_proof_stale".to_string());
        }
    }

    let blocked_dry_run = proof.get("blockedDryRun").unwrap_or(&Value::Null);
    let blocked_action = blocked_dry_run.get("action").unwrap_or(&Value::Null);
    if blocked_dry_run.get("clicked").and_then(Value::as_bool) != Some(true) {
        blockers.push("activation_id_gate_dry_run_not_clicked".to_string());
    }
    if blocked_dry_run.get("gateId").and_then(Value::as_str) != Some("activation-id") {
        blockers.push("activation_id_gate_dry_run_gate_mismatch".to_string());
    }
    if blocked_action.get("kind").and_then(Value::as_str) != Some("run_activation_dry_run") {
        blockers.push("activation_id_gate_dry_run_kind_mismatch".to_string());
    }
    if blocked_action.get("command").and_then(Value::as_str)
        != Some("workflow-harness-gate-action-activation-id")
    {
        blockers.push("activation_id_gate_dry_run_command_mismatch".to_string());
    }
    if blocked_dry_run.get("decision").and_then(Value::as_str) != Some("blocked") {
        blockers.push("activation_id_gate_dry_run_not_blocked".to_string());
    }
    if blocked_dry_run
        .get("activationBlockerCount")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
    {
        blockers.push("activation_id_gate_dry_run_no_blockers".to_string());
    }
    if blocked_dry_run
        .get("workflowActivationId")
        .and_then(Value::as_str)
        .map(|value| !value.is_empty())
        .unwrap_or(false)
    {
        blockers.push("activation_id_gate_dry_run_minted_activation_id".to_string());
    }
    if blocked_dry_run
        .get("workflowActivationState")
        .and_then(Value::as_str)
        != Some("blocked")
    {
        blockers.push("activation_id_gate_dry_run_activation_state_mismatch".to_string());
    }
    if blocked_dry_run
        .get("latestAuditEventType")
        .and_then(Value::as_str)
        != Some("dry_run_blocked")
    {
        blockers.push("activation_id_gate_dry_run_audit_type_mismatch".to_string());
    }

    let minted = proof.get("mintedActivation").unwrap_or(&Value::Null);
    let minted_action = minted.get("action").unwrap_or(&Value::Null);
    let activation_id = minted.get("activationId").and_then(Value::as_str);
    if minted.get("clicked").and_then(Value::as_bool) != Some(true) {
        blockers.push("activation_id_gate_mint_not_clicked".to_string());
    }
    if minted.get("applied").and_then(Value::as_bool) != Some(true) {
        blockers.push("activation_id_gate_mint_not_applied".to_string());
    }
    if minted.get("gateId").and_then(Value::as_str) != Some("activation-id") {
        blockers.push("activation_id_gate_mint_gate_mismatch".to_string());
    }
    if minted_action.get("kind").and_then(Value::as_str) != Some("mint_activation") {
        blockers.push("activation_id_gate_mint_kind_mismatch".to_string());
    }
    if minted_action.get("command").and_then(Value::as_str)
        != Some("workflow-harness-gate-action-activation-id")
    {
        blockers.push("activation_id_gate_mint_command_mismatch".to_string());
    }
    if !activation_id
        .map(|value| value.starts_with("activation:"))
        .unwrap_or(false)
    {
        blockers.push("activation_id_gate_mint_activation_id_missing".to_string());
    }
    if minted.get("workflowActivationId").and_then(Value::as_str) != activation_id {
        blockers.push("activation_id_gate_mint_workflow_activation_mismatch".to_string());
    }
    if minted
        .get("workflowActivationState")
        .and_then(Value::as_str)
        != Some("validated")
    {
        blockers.push("activation_id_gate_mint_activation_state_mismatch".to_string());
    }
    if minted
        .get("workerBindingActivationId")
        .and_then(Value::as_str)
        != activation_id
    {
        blockers.push("activation_id_gate_mint_worker_binding_mismatch".to_string());
    }
    if minted
        .get("activationRecordWorkerBindingActivationId")
        .and_then(Value::as_str)
        != activation_id
    {
        blockers.push("activation_id_gate_mint_activation_record_binding_mismatch".to_string());
    }
    if minted
        .get("revisionBindingActivationId")
        .and_then(Value::as_str)
        != activation_id
    {
        blockers.push("activation_id_gate_mint_revision_binding_mismatch".to_string());
    }
    if minted.get("rollbackTarget").and_then(Value::as_str)
        != Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
    {
        blockers.push("activation_id_gate_mint_rollback_target_mismatch".to_string());
    }
    if minted
        .get("activationRecordRevisionBindingHash")
        .and_then(Value::as_str)
        .map(str::is_empty)
        .unwrap_or(true)
    {
        blockers.push("activation_id_gate_mint_revision_hash_missing".to_string());
    }
    if minted
        .get("rollbackRevisionBindingHash")
        .and_then(Value::as_str)
        .map(str::is_empty)
        .unwrap_or(true)
    {
        blockers.push("activation_id_gate_mint_rollback_hash_missing".to_string());
    }
    if minted.get("latestAuditEventType").and_then(Value::as_str) != Some("activation_minted") {
        blockers.push("activation_id_gate_mint_audit_type_mismatch".to_string());
    }
    if minted.get("latestAuditStatus").and_then(Value::as_str) != Some("applied") {
        blockers.push("activation_id_gate_mint_audit_status_mismatch".to_string());
    }
    if !minted
        .get("receiptRefs")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false)
    {
        blockers.push("activation_id_gate_mint_receipts_missing".to_string());
    }
    if !minted
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false)
    {
        blockers.push("activation_id_gate_mint_evidence_missing".to_string());
    }

    blockers.sort();
    blockers.dedup();
    blockers
}
