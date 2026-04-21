use super::super::{RuntimeAgentService, ServiceCallContext};
use super::approvals;
use super::focus;
use super::pii;
use super::{normalize_web_research_tool_call, reconcile_pending_web_research_tool_call};
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::keys::get_approval_grant_key;
use crate::agentic::runtime::adapters;
use crate::agentic::runtime::execution::ToolExecutor;
use crate::agentic::runtime::types::AgentState;
use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::eddsa::{
    Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
};
use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{
    determinism_commit_state_key, determinism_evidence_state_key, policy_decision_state_key,
    execution_observation_receipt_state_key, postcondition_proof_state_key,
    required_receipt_manifest_state_key, settlement_receipt_bundle_state_key, AccountId,
    ActionRequest, ActionTarget, ApprovalGrant, CapabilityLease, CapabilityLeaseMode, ChainId,
    CommittedAction, DeterminismEvidence, ExecutionContractReceiptEvent,
    ExecutionObservationReceipt, FirewallDecisionReceipt, KernelEvent, NetMode,
    PolicyDecisionRecord, PolicyVerdict, PostconditionProof, RequiredReceiptManifest,
    RuntimeTarget, SettlementReceiptBundle, SignatureSuite, UiSurfaceSpec, WorkloadSpec,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;

mod handlers;

const ACTIVE_WINDOW_QUERY_TIMEOUT: Duration = Duration::from_millis(300);
const CEC_CONTRACT_VERSION: &str = "cec.v0.4";
const FIREWALL_DECISION_STATE_PREFIX: &[u8] = b"agentic:firewall:decision:v1:";
const FIREWALL_SIGNING_KEY_STATE_PREFIX: &[u8] = b"agentic:firewall:signing_key:v1:";

type ActionExecutionOutcome = (bool, Option<String>, Option<String>, Option<[u8; 32]>);

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
struct FirewallSignatureEnvelope {
    suite: SignatureSuite,
    signer_account_id: [u8; 32],
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

struct DeterminismContext {
    request: ActionRequest,
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    target_str: String,
    tool_hash: [u8; 32],
    intent_id: String,
    workload_spec: WorkloadSpec,
    observed_domain: Option<String>,
    signing_context: Option<(ChainId, AccountId)>,
}

fn execution_request_nonce(agent_state: &AgentState, step_index: u32) -> u64 {
    agent_state
        .pending_request_nonce
        .unwrap_or(step_index as u64)
}

include!("execution/determinism.rs");

include!("execution/workload_spec.rs");

include!("execution/receipt_emission.rs");

include!("execution/firewall_policy.rs");

include!("execution/window_binding.rs");

include!("execution/action_execution.rs");

#[cfg(test)]
mod tests;
