use super::*;
use ioi_crypto::algorithms::hash::sha256;
use ioi_ipc::public::RoutingReceipt;
use ioi_types::app::{RoutingFailureClass, RoutingReceiptEvent};

fn routing_policy_binding_hash(intent_hash: &str, policy_decision: &str) -> String {
    let payload = format!(
        "ioi::routing-policy-binding::v1::{}::{}",
        intent_hash, policy_decision
    );
    sha256(payload.as_bytes())
        .map(hex::encode)
        .unwrap_or_else(|_| String::new())
}

pub(super) fn parse_session_id_hex(session_id_hex: &str) -> Result<[u8; 32], Status> {
    let normalized = session_id_hex
        .trim()
        .trim_start_matches("0x")
        .replace('-', "");
    let bytes = hex::decode(normalized)
        .map_err(|_| Status::invalid_argument("Invalid session_id_hex encoding"))?;
    let mut session_id = [0u8; 32];
    match bytes.len() {
        32 => {
            session_id.copy_from_slice(&bytes);
            Ok(session_id)
        }
        16 => {
            session_id[..16].copy_from_slice(&bytes);
            Ok(session_id)
        }
        _ => Err(Status::invalid_argument(
            "Invalid session_id_hex length (expected 16 or 32 bytes)",
        )),
    }
}

pub(super) fn map_routing_receipt(
    receipt: RoutingReceiptEvent,
    signer: Option<(&libp2p::identity::Keypair, &str)>,
) -> RoutingReceipt {
    let failure_class_name = if !receipt.failure_class_name.is_empty() {
        receipt.failure_class_name.clone()
    } else if let Some(class) = receipt.failure_class.as_ref() {
        format!("{:?}", class)
    } else {
        String::new()
    };

    let (failure_class, has_failure_class) = if let Some(class) = receipt.failure_class.as_ref() {
        let code = match class {
            RoutingFailureClass::FocusMismatch => 1,
            RoutingFailureClass::TargetNotFound => 2,
            RoutingFailureClass::PermissionOrApprovalRequired => 3,
            RoutingFailureClass::ToolUnavailable => 4,
            RoutingFailureClass::NonDeterministicUI => 5,
            RoutingFailureClass::UnexpectedState => 6,
            RoutingFailureClass::TimeoutOrHang => 7,
            RoutingFailureClass::UserInterventionNeeded => 8,
            RoutingFailureClass::VisionTargetNotFound => 9,
            RoutingFailureClass::NoEffectAfterAction => 10,
            RoutingFailureClass::TierViolation => 11,
            RoutingFailureClass::MissingDependency => 12,
            RoutingFailureClass::ContextDrift => 13,
        };
        (code, true)
    } else {
        (0, false)
    };

    let policy_binding_hash = if receipt.policy_binding_hash.is_empty() {
        routing_policy_binding_hash(&receipt.intent_hash, &receipt.policy_decision)
    } else {
        receipt.policy_binding_hash.clone()
    };

    let (policy_binding_sig, policy_binding_signer) = if let Some((keypair, signer_pk_hex)) = signer
    {
        match keypair.sign(policy_binding_hash.as_bytes()) {
            Ok(sig) => (hex::encode(sig), signer_pk_hex.to_string()),
            Err(_) => (
                receipt.policy_binding_sig.clone().unwrap_or_default(),
                receipt.policy_binding_signer.clone().unwrap_or_default(),
            ),
        }
    } else {
        (
            receipt.policy_binding_sig.clone().unwrap_or_default(),
            receipt.policy_binding_signer.clone().unwrap_or_default(),
        )
    };

    RoutingReceipt {
        session_id: hex::encode(receipt.session_id),
        step_index: receipt.step_index,
        intent_hash: receipt.intent_hash,
        policy_decision: receipt.policy_decision,
        tool_name: receipt.tool_name,
        tool_version: receipt.tool_version,
        pre_state: Some(ioi_ipc::public::RoutingStateSummary {
            agent_status: receipt.pre_state.agent_status,
            tier: receipt.pre_state.tier,
            step_index: receipt.pre_state.step_index,
            consecutive_failures: receipt.pre_state.consecutive_failures as u32,
            target_hint: receipt.pre_state.target_hint.unwrap_or_default(),
        }),
        action_json: receipt.action_json,
        post_state: Some(ioi_ipc::public::RoutingPostStateSummary {
            agent_status: receipt.post_state.agent_status,
            tier: receipt.post_state.tier,
            step_index: receipt.post_state.step_index,
            consecutive_failures: receipt.post_state.consecutive_failures as u32,
            success: receipt.post_state.success,
            verification_checks: receipt.post_state.verification_checks,
        }),
        artifacts: receipt.artifacts,
        failure_class,
        has_failure_class,
        stop_condition_hit: receipt.stop_condition_hit,
        escalation_path: receipt.escalation_path.unwrap_or_default(),
        scs_lineage_ptr: receipt.scs_lineage_ptr.unwrap_or_default(),
        mutation_receipt_ptr: receipt.mutation_receipt_ptr.unwrap_or_default(),
        policy_binding_hash,
        policy_binding_sig,
        policy_binding_signer,
        failure_class_name,
        intent_class: receipt.intent_class,
        incident_id: receipt.incident_id,
        incident_stage: receipt.incident_stage,
        strategy_name: receipt.strategy_name,
        strategy_node: receipt.strategy_node,
        gate_state: receipt.gate_state,
        resolution_action: receipt.resolution_action,
    }
}
