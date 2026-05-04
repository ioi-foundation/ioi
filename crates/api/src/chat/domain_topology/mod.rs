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
    block_work_graph_work_item_on, spawn_follow_up_work_graph_work_item,
    ExecutionCompletionInvariant, ExecutionCompletionInvariantStatus,
    ExecutionGraphMutationReceipt, ExecutionReplanReceipt, WorkGraphPlan,
    WorkGraphVerificationPolicy, WorkGraphVerificationReceipt, WorkGraphWorkItem,
    WorkGraphWorkItemStatus, WorkGraphWorkerReceipt, WorkGraphWorkerResultKind,
    WorkGraphWorkerRole,
};
use ioi_types::app::agentic::{
    BrowserActionPlanRef, CommandExecutionPlanRef, HostMutationScope, RequiredCapability,
    RuntimeActionFrame, RuntimeIntentEvidence, RuntimeRouteFrame, SoftwareInstallRequestFrame,
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
use sha2::Digest;

fn command_plan_ref_for_literal(command: &str) -> String {
    let digest = sha2::Sha256::digest(command.as_bytes());
    format!("command.exec:{}", hex::encode(digest))
}

fn command_plan_for_literal(command: &str) -> CommandExecutionPlanRef {
    CommandExecutionPlanRef {
        plan_ref: command_plan_ref_for_literal(command),
        argv: vec!["bash".to_string(), "-lc".to_string(), command.to_string()],
        shell_policy: "bounded".to_string(),
        cwd: Some(".".to_string()),
        env: Vec::new(),
        approval_scope: None,
        expected_receipt: Some("command_receipt".to_string()),
    }
}

include!("projection.rs");
include!("decision_policy.rs");

fn derive_source_decision(
    context: &ChatIntentContext,
    primary_lane: ChatLaneFamily,
    normalized_request: Option<&ChatNormalizedRequest>,
    decision_evidence: &[String],
    active_artifact_id: Option<&str>,
) -> ChatSourceDecision {
    let specialized_policy =
        chat_specialized_domain_kind(normalized_request).map(chat_specialized_domain_policy);
    let mut candidate_sources = Vec::new();
    let mut push_unique = |source: ChatSourceFamily| {
        if !candidate_sources.contains(&source) {
            candidate_sources.push(source);
        }
    };

    if active_artifact_id.is_some() {
        push_unique(ChatSourceFamily::ArtifactContext);
    }
    if context.references_previous_conversation() {
        push_unique(ChatSourceFamily::ConversationRetrieval);
    }
    if context.references_memory_context() {
        push_unique(ChatSourceFamily::Memory);
    }
    push_unique(ChatSourceFamily::ConversationContext);

    let specialized_tool_required = matches!(
        normalized_request,
        Some(
            ChatNormalizedRequest::Weather(_)
                | ChatNormalizedRequest::Sports(_)
                | ChatNormalizedRequest::Places(_)
                | ChatNormalizedRequest::Recipe(_)
                | ChatNormalizedRequest::UserInput(_)
        )
    );

    let selected_source = if specialized_tool_required {
        push_unique(ChatSourceFamily::SpecializedTool);
        if !matches!(
            normalized_request,
            Some(ChatNormalizedRequest::UserInput(_))
        ) {
            push_unique(ChatSourceFamily::WebSearch);
        }
        ChatSourceFamily::SpecializedTool
    } else if active_artifact_id.is_some() {
        ChatSourceFamily::ArtifactContext
    } else if matches!(
        normalized_request,
        Some(ChatNormalizedRequest::SoftwareInstall(_))
            | Some(ChatNormalizedRequest::RuntimeAction(_))
    ) {
        push_unique(ChatSourceFamily::UserDirected);
        ChatSourceFamily::UserDirected
    } else if decision_evidence_item_flag(decision_evidence, "connector_intent_detected") {
        push_unique(ChatSourceFamily::Connector);
        ChatSourceFamily::Connector
    } else if decision_evidence_item_flag(decision_evidence, "workspace_grounding_required") {
        push_unique(ChatSourceFamily::Workspace);
        ChatSourceFamily::Workspace
    } else if decision_evidence_item_flag(decision_evidence, "currentness_override")
        || primary_lane == ChatLaneFamily::Research
        || matches!(
            normalized_request,
            Some(
                ChatNormalizedRequest::Weather(_)
                    | ChatNormalizedRequest::Sports(_)
                    | ChatNormalizedRequest::Places(_)
                    | ChatNormalizedRequest::Recipe(_)
            )
        )
    {
        push_unique(ChatSourceFamily::WebSearch);
        ChatSourceFamily::WebSearch
    } else if matches!(
        normalized_request,
        Some(ChatNormalizedRequest::MessageCompose(_))
    ) {
        if decision_evidence_item_flag(decision_evidence, "connector_intent_detected") {
            push_unique(ChatSourceFamily::Connector);
            ChatSourceFamily::Connector
        } else {
            ChatSourceFamily::DirectAnswer
        }
    } else if context.references_memory_context() {
        ChatSourceFamily::Memory
    } else if context.references_previous_conversation() {
        ChatSourceFamily::ConversationRetrieval
    } else {
        ChatSourceFamily::DirectAnswer
    };

    push_unique(selected_source);

    let explicit_user_source = active_artifact_id.is_some()
        || decision_evidence_item_flag(decision_evidence, "connector_intent_detected")
        || decision_evidence_item_flag(decision_evidence, "workspace_grounding_required")
        || matches!(
            normalized_request,
            Some(ChatNormalizedRequest::SoftwareInstall(_))
                | Some(ChatNormalizedRequest::RuntimeAction(_))
        )
        || decision_evidence_item_flag(decision_evidence, "currentness_override")
        || tool_widget_family_hint(decision_evidence).is_some()
        || context.references_previous_conversation()
        || context.references_memory_context();

    let degradation_reason = if decision_evidence_item_flag(decision_evidence, "connector_missing")
    {
        Some("connector route is preferred but unavailable in this runtime".to_string())
    } else if decision_evidence_item_flag(decision_evidence, "connector_auth_required") {
        Some("connector route is preferred but still needs authentication".to_string())
    } else if normalized_request
        .is_some_and(|frame| !chat_normalized_request_missing_slots(frame).is_empty())
    {
        Some(
            specialized_policy
                .map(|policy| policy.missing_slot_degradation_reason.to_string())
                .unwrap_or_else(|| {
                    "required lane slots are still missing, so execution is blocked on clarification"
                        .to_string()
                }),
        )
    } else {
        None
    };

    ChatSourceDecision {
        candidate_sources,
        selected_source,
        explicit_user_source,
        degradation_reason,
    }
}
