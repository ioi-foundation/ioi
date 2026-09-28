use super::super::{RuntimeAgentService, ServiceCallContext};
use super::approvals;
use super::focus;
use super::pii;
use super::{normalize_web_research_tool_call, reconcile_pending_web_research_tool_call};
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::adapters;
use crate::agentic::runtime::execution::ToolExecutor;
use crate::agentic::runtime::firewall_receipt_keys::FirewallReceiptKeyStore;
use crate::agentic::runtime::kernel::policy::PolicyEvaluationRecord;
use crate::agentic::runtime::keys::get_approval_grant_key;
use crate::agentic::runtime::types::AgentState;
use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{
    determinism_commit_state_key, determinism_evidence_state_key,
    execution_observation_receipt_state_key, policy_decision_state_key,
    postcondition_proof_state_key, required_receipt_manifest_state_key,
    settlement_receipt_bundle_state_key, AccountId, ActionRequest, ActionTarget, ApprovalGrant,
    CapabilityLease, CapabilityLeaseMode, ChainId, CommittedAction, DeterminismEvidence,
    ExecutionContractReceiptEvent, ExecutionObservationReceipt, FirewallDecisionReceipt,
    KernelEvent, NetMode, PolicyDecisionRecord, PolicyVerdict, PostconditionProof,
    RequiredReceiptManifest, RuntimeTarget, SettlementReceiptBundle, SignatureSuite, UiSurfaceSpec,
    WorkloadSpec,
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
mod runtime_tool_admission;

const ACTIVE_WINDOW_QUERY_TIMEOUT: Duration = Duration::from_millis(300);
const CEC_CONTRACT_VERSION: &str = "cec.v0.4";
/// The latest firewall decision receipt at a step (a re-decision at the same step replaces it).
const FIREWALL_DECISION_STATE_PREFIX: &[u8] = b"agentic:firewall:decision:v1:";
/// Every firewall decision receipt, keyed by its chain sequence number, so the chain can be walked
/// even when a step is decided more than once.
const FIREWALL_DECISION_SEQ_STATE_PREFIX: &[u8] = b"agentic:firewall:decision_seq:v1:";
/// The head of a session's firewall receipt chain: the last receipt's seq and hash.
const FIREWALL_CHAIN_HEAD_STATE_PREFIX: &[u8] = b"agentic:firewall:chain_head:v1:";
/// Marks a `guardian_sig` that carries a [`FirewallSignatureEnvelope`] (the v2 envelope, which
/// names the host key that signed). Legacy receipts carry a bare [`LegacyFirewallSignatureEnvelope`].
const FIREWALL_SIGNATURE_ENVELOPE_V2_MAGIC: &[u8] = b"ioi.firewall.sig.v2\0";

type ActionExecutionOutcome = (bool, Option<String>, Option<String>, Option<[u8; 32]>);

/// The signature over a firewall decision receipt, made by the host-held key named by `key_id`.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
struct FirewallSignatureEnvelope {
    suite: SignatureSuite,
    signer_account_id: [u8; 32],
    key_id: String,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

/// The pre-G7 envelope, signed with a seed derived from public values. Decoded only so receipts
/// written before the fix can still be read and linked; never produced.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
struct LegacyFirewallSignatureEnvelope {
    suite: SignatureSuite,
    signer_account_id: [u8; 32],
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

/// The head of one session's firewall receipt chain.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct FirewallChainHead {
    seq: u64,
    step_index: u32,
    receipt_hash: [u8; 32],
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
