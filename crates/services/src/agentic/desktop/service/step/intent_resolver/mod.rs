use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, ExecutionTier};
use crate::agentic::rules::{ActionRules, Verdict};
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{
    CapabilityId, ExecutionApplicabilityClass, InstructionContract, IntentAmbiguityAction,
    IntentCandidateScore, IntentConfidenceBand, IntentMatrixEntry, IntentQueryBindingClass,
    IntentRoutingPolicy, IntentScopeProfile, ProviderRouteCandidate, ProviderSelectionState,
    ResolvedIntentState, ToolCapabilityBinding,
};
use ioi_types::app::{ActionTarget, IntentResolutionReceiptEvent, KernelEvent};
use ioi_types::error::{TransactionError, VmError};
use serde_json::json;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock, RwLock};
use tokio::time::{timeout, Duration};

const INTENT_EMBED_RANK_TIMEOUT: Duration = Duration::from_secs(15);
const INTENT_QUERY_NORMALIZATION_VERSION: &str = "intent_query_norm_v1";
const INTENT_EMBEDDING_MODEL_ID: &str = "inference.embed_text";
const INTENT_EMBEDDING_MODEL_VERSION: &str = "v1";
const INTENT_SIMILARITY_FUNCTION_ID: &str = "cosine_similarity_v1";
const INTENT_MODEL_RANK_MODEL_ID: &str = "inference.execute_inference";
const INTENT_MODEL_RANK_MODEL_VERSION: &str = "v1";
const INTENT_MODEL_RANK_SIMILARITY_FUNCTION_ID: &str = "llm_descriptor_rank_v1";
const INTENT_QUERY_BINDING_MODEL_ID: &str = "inference.execute_inference";
const INTENT_QUERY_BINDING_MODEL_VERSION: &str = "v1";
const INTENT_QUERY_BINDING_SCHEMA_ID: &str = "query_binding_profile_v1";
const INTENT_PROVIDER_SELECTION_MODEL_ID: &str = "inference.execute_inference";
const INTENT_PROVIDER_SELECTION_MODEL_VERSION: &str = "v1";
const INTENT_PROVIDER_SELECTION_SCHEMA_ID: &str = "provider_selection_state_v1";
const INTENT_INSTRUCTION_CONTRACT_MODEL_ID: &str = "inference.execute_inference";
const INTENT_INSTRUCTION_CONTRACT_MODEL_VERSION: &str = "v1";
const INTENT_INSTRUCTION_CONTRACT_SCHEMA_ID: &str = "instruction_contract_v1";
const CIRC_CONTRACT_VERSION: &str = "circ.v0.5";

#[derive(Debug, Clone, Copy, Default)]
struct QueryBindingProfile {
    available: bool,
    remote_public_fact_required: bool,
    host_local_clock_targeted: bool,
    command_directed: bool,
    app_launch_directed: bool,
    direct_ui_input: bool,
    desktop_screenshot_requested: bool,
    temporal_filesystem_filter: bool,
}

mod capabilities;
mod contract_hash;
mod instruction_contract;
mod policy;
mod providers;
mod ranking;
mod resolve;

use capabilities::*;
use contract_hash::*;
use instruction_contract::*;
use policy::*;
use providers::*;
use ranking::*;

pub(crate) use capabilities::tool_provider_route_label;
pub(crate) use capabilities::{
    is_mail_reply_provider_tool, is_tool_allowed_for_resolution,
    is_tool_allowed_for_selected_provider, tool_has_capability,
};
pub use ranking::{preferred_tier, should_pause_for_clarification};
pub use resolve::{resolve_step_intent, resolve_step_intent_with_state};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
