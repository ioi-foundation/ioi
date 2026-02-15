use crate::agentic::desktop::keys::get_mutation_receipt_ptr_key;
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{KernelEvent, RoutingReceiptEvent};
use tokio::sync::broadcast::Sender;

pub fn lineage_pointer(active_skill_hash: Option<[u8; 32]>) -> Option<String> {
    active_skill_hash.map(|hash| format!("scs://skill/{}", hex::encode(hash)))
}

pub fn policy_binding_hash(intent_hash: &str, policy_decision: &str) -> String {
    // Domain-separated canonical payload for routing policy attestation.
    let payload = format!(
        "ioi::routing-policy-binding::v1::{}::{}",
        intent_hash, policy_decision
    );
    sha256(payload.as_bytes())
        .map(hex::encode)
        .unwrap_or_else(|_| String::new())
}

pub fn mutation_receipt_pointer(state: &dyn StateAccess, session_id: &[u8; 32]) -> Option<String> {
    let key = get_mutation_receipt_ptr_key(session_id);
    let bytes = state.get(&key).ok()??;
    String::from_utf8(bytes).ok().filter(|v| !v.is_empty())
}

pub fn emit_routing_receipt(
    event_sender: Option<&Sender<KernelEvent>>,
    receipt: RoutingReceiptEvent,
) {
    if let Some(tx) = event_sender {
        let _ = tx.send(KernelEvent::RoutingReceipt(receipt));
    }
}

pub fn extract_artifacts(error: Option<&str>, history_entry: Option<&str>) -> Vec<String> {
    let mut artifacts = Vec::new();

    if let Some(err) = error {
        if let Some(path) = extract_grounding_path(err) {
            artifacts.push(path);
        }
    }

    if let Some(entry) = history_entry {
        if let Some(path) = extract_grounding_path(entry) {
            if !artifacts.iter().any(|p| p == &path) {
                artifacts.push(path);
            }
        }
    }

    artifacts
}

fn extract_grounding_path(input: &str) -> Option<String> {
    let marker = "grounding_debug=";
    let start = input.find(marker)?;
    let after = &input[start + marker.len()..];
    let end = after.find(']').unwrap_or(after.len());
    let candidate = after[..end].trim();
    if candidate.is_empty() {
        None
    } else {
        Some(candidate.to_string())
    }
}
