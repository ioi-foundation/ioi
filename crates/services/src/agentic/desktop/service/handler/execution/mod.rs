use super::super::{DesktopAgentService, ServiceCallContext};
use super::approvals;
use super::focus;
use super::pii;
use super::wallet_mail::try_execute_wallet_mail_dynamic_tool;
use super::web_research::normalize_web_research_tool_call;
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::types::AgentState;
use crate::agentic::rules::ActionRules;
use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::eddsa::{
    Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
};
use ioi_drivers::mcp::McpManager;
use ioi_scs::{FrameType, RetentionClass};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{
    determinism_commit_state_key, determinism_evidence_state_key, AccountId, ActionRequest,
    ActionTarget, ApprovalToken, CapabilityLease, CapabilityLeaseMode, ChainId, CommittedAction,
    DeterminismEvidence, ExecutionContractReceiptEvent, FirewallDecisionReceipt, KernelEvent,
    NetMode, PolicyVerdict, RuntimeTarget, SignatureSuite, UiSurfaceSpec, WorkloadSpec,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
