use crate::agentic::desktop::service::step::signals::{analyze_query_facets, QueryFacetProfile};
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, ExecutionTier};
use crate::agentic::rules::{ActionRules, Verdict};
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{
    CapabilityId, ExecutionApplicabilityClass, IntentAmbiguityAction, IntentCandidateScore,
    IntentConfidenceBand, IntentMatrixEntry, IntentRoutingPolicy, IntentScopeProfile,
    ResolvedIntentState, ToolCapabilityBinding,
};
use ioi_types::app::{ActionTarget, IntentResolutionReceiptEvent, KernelEvent};
use ioi_types::error::{TransactionError, VmError};
use serde_json::json;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock, RwLock};
use tokio::time::{timeout, Duration};

const INTENT_EMBED_RANK_TIMEOUT: Duration = Duration::from_secs(5);
const INTENT_PROTOTYPE_BUILD_TIMEOUT: Duration = Duration::from_secs(30);
const INTENT_QUERY_NORMALIZATION_VERSION: &str = "intent_query_norm_v1";
const INTENT_EMBEDDING_MODEL_ID: &str = "inference.embed_text";
const INTENT_EMBEDDING_MODEL_VERSION: &str = "v1";
const INTENT_SIMILARITY_FUNCTION_ID: &str = "cosine_similarity_v1";
const CIRC_CONTRACT_VERSION: &str = "circ.v0.5";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntentQueryBindingClass {
    None,
    HostLocal,
    RemotePublicFact,
    CommandDirected,
    DirectUiInput,
    DesktopScreenshot,
}

mod capabilities;
mod contract_hash;
mod policy;
mod ranking;
mod resolve;

use capabilities::*;
use contract_hash::*;
use policy::*;
use ranking::*;

pub use capabilities::is_tool_allowed_for_resolution;
pub use ranking::{preferred_tier, should_pause_for_clarification};
pub use resolve::resolve_step_intent;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
