//! Shared route/topology/policy semantics for the Chat harness.
//!
//! The functions in this module should stay provenance-free and product-shell
//! agnostic. They compute reusable runtime semantics such as lane/topology
//! projections, route decisions, source decision, verification state, and
//! non-artifact execution policy.
//!
//! UI-specific presentation, session lifecycle mutation, and shell-only render
//! surfaces should remain in the Autopilot Chat kernel.

use super::intent_signals::ChatIntentContext;
use super::runtime_locality::runtime_locality_scope_hint;
use super::specialized_policy::{
    chat_normalized_request_clarification_slots, chat_normalized_request_missing_slots,
    chat_specialized_domain_kind, chat_specialized_domain_policy,
};
use super::types::{
    ArtifactConnectorGrounding, ArtifactOperatorPhase, ArtifactOperatorRunStatus,
    ArtifactOperatorStep,
};
use crate::execution::{
    block_swarm_work_item_on, spawn_follow_up_swarm_work_item, ExecutionCompletionInvariant,
    ExecutionCompletionInvariantStatus, ExecutionGraphMutationReceipt, ExecutionReplanReceipt,
    SwarmPlan, SwarmVerificationPolicy, SwarmVerificationReceipt, SwarmWorkItem,
    SwarmWorkItemStatus, SwarmWorkerReceipt, SwarmWorkerResultKind, SwarmWorkerRole,
};
use ioi_types::app::{
    ChatArtifactClass, ChatArtifactLifecycleState, ChatArtifactManifest,
    ChatArtifactManifestVerification, ChatArtifactVerificationStatus, ChatCheckpointState,
    ChatClarificationMode, ChatClarificationPolicy, ChatCompletionInvariant,
    ChatDomainPolicyBundle, ChatExecutionModeDecision, ChatExecutionStrategy,
    ChatExecutionSubstrate, ChatFallbackMode, ChatFallbackPolicy, ChatLaneFamily, ChatLaneRequest,
    ChatLaneTransition, ChatLaneTransitionKind, ChatMessageComposeRequestFrame,
    ChatNormalizedRequest, ChatObjectiveState, ChatOrchestrationState, ChatOutcomeArtifactRequest,
    ChatOutcomeKind, ChatOutcomeRequest, ChatPlacesRequestFrame, ChatPolicyContractSummary,
    ChatPresentationPolicy, ChatRecipeRequestFrame, ChatRendererKind, ChatRetainedLaneState,
    ChatRetainedWidgetState, ChatRiskProfile, ChatRiskSensitivity, ChatRuntimeProvenance,
    ChatSourceDecision, ChatSourceFamily, ChatSourceRankingEntry, ChatSportsRequestFrame,
    ChatTaskUnitState, ChatTransformationPolicy, ChatUserInputRequestFrame,
    ChatVerificationContract, ChatWeatherRequestFrame, ChatWidgetStateBinding, ChatWorkStatus,
    RoutingEffectiveToolSurface, RoutingRouteDecision,
};
use serde_json::json;

include!("projection.rs");
include!("decision_policy.rs");
