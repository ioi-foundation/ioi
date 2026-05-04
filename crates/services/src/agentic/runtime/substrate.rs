use crate::agentic::runtime::tools::contracts::runtime_tool_contract_for_definition;
use crate::agentic::runtime::types::{
    AgentPauseReason, AgentState, AgentStatus, ExecutionAttemptStatus, ExecutionTier,
    ToolCallStatus,
};
use ioi_api::vm::inference::{ModelRouterInput, RuntimeModelRouter};
use ioi_types::app::agentic::LlmToolDefinition;
use ioi_types::app::{
    AgentDecisionLoop, AgentDecisionStage, AgentDecisionStageRecord, AgentQualityLedger,
    AgentRuntimeEvent, AgentTurnPhase, AgentTurnState, BoundedSelfImprovementGate,
    CapabilityDiscovery, CapabilityRetirement, CapabilitySelection, CapabilitySequence,
    CapabilitySequencing, ClarificationContract, CognitiveBudget, ConfidenceBand, DriftSignal,
    DryRunCapability, ErrorRecoveryContract, EvidenceRef, FileObservationState, FileReadStatus,
    HandoffQuality, HarnessTraceAdapter, MemoryQualityGate, ModelRoutingDecision,
    NegativeLearningRecord, OperatorCollaborationContract, OperatorInterruptionContract,
    OperatorInterruptionEvent, OperatorPreference, PostconditionCheck, PostconditionSynthesis,
    PostconditionSynthesizer, Probe, ProbeResultStatus, PromptAssemblyContract, PromptLayerKind,
    PromptPrivacyClass, PromptSectionMutability, PromptSectionRecord, RuntimeCheckStatus,
    RuntimeDecisionAction, RuntimeErrorClass, RuntimeExecutionEnvelope, RuntimeStrategyDecision,
    RuntimeStrategyRouter, RuntimeSubstratePortContract, RuntimeSurface, RuntimeToolContract,
    SemanticImpactAnalysis, SessionTraceBundle, StopConditionRecord, StopReason,
    TaskFamilyPlaybook, TaskStateClaim, TaskStateModel, ToolSelectionQualityModel,
    UncertaintyAssessment, UncertaintyLevel, VerifierIndependencePolicy, WorkflowEnvelopeAdapter,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSubstrateSnapshot {
    pub envelope: RuntimeExecutionEnvelope,
    pub port_contract: RuntimeSubstratePortContract,
    pub events: Vec<AgentRuntimeEvent>,
    pub tool_contracts: Vec<RuntimeToolContract>,
    pub prompt_assembly: PromptAssemblyContract,
    pub turn_state: AgentTurnState,
    pub decision_loop: AgentDecisionLoop,
    pub file_observations: Vec<FileObservationState>,
    pub session_trace_bundle: SessionTraceBundle,
    pub task_state: TaskStateModel,
    pub uncertainty: UncertaintyAssessment,
    pub strategy_router: RuntimeStrategyRouter,
    pub strategy_decision: RuntimeStrategyDecision,
    pub model_routing: ModelRoutingDecision,
    pub capability_discovery: CapabilityDiscovery,
    pub capability_selection: CapabilitySelection,
    pub capability_sequencing: CapabilitySequencing,
    pub capability_retirement: CapabilityRetirement,
    pub capability_sequence: CapabilitySequence,
    pub tool_selection_quality: Vec<ToolSelectionQualityModel>,
    pub probes: Vec<Probe>,
    pub postcondition_synthesizer: PostconditionSynthesizer,
    pub postconditions: PostconditionSynthesis,
    pub semantic_impact: SemanticImpactAnalysis,
    pub cognitive_budget: CognitiveBudget,
    pub drift_signal: DriftSignal,
    pub verifier_independence_policy: VerifierIndependencePolicy,
    pub dry_run_capabilities: Vec<DryRunCapability>,
    pub handoff_quality: Option<HandoffQuality>,
    pub task_family_playbook: TaskFamilyPlaybook,
    pub negative_learning: Vec<NegativeLearningRecord>,
    pub memory_quality_gates: Vec<MemoryQualityGate>,
    pub operator_preference: Option<OperatorPreference>,
    pub bounded_self_improvement_gate: Option<BoundedSelfImprovementGate>,
    pub operator_collaboration: OperatorCollaborationContract,
    pub workflow_envelope_adapter: WorkflowEnvelopeAdapter,
    pub harness_trace_adapter: HarnessTraceAdapter,
    pub operator_interruption: OperatorInterruptionContract,
    pub operator_interruption_events: Vec<OperatorInterruptionEvent>,
    pub clarification: Option<ClarificationContract>,
    pub error_recovery: Vec<ErrorRecoveryContract>,
    pub quality_ledger: AgentQualityLedger,
    pub stop_condition: StopConditionRecord,
}

pub fn runtime_substrate_snapshot_for_state(
    state: &AgentState,
    surface: RuntimeSurface,
) -> RuntimeSubstrateSnapshot {
    let session_id = hex::encode(state.session_id);
    let stop_condition = stop_condition_for_state(state);
    let semantic_impact = semantic_impact_for_state(state);
    let postconditions = postconditions_for_state(state, &semantic_impact);
    let task_state = task_state_for_state(state, &stop_condition);
    let uncertainty = uncertainty_for_state(state, &stop_condition, &postconditions);
    let cognitive_budget = cognitive_budget_for_state(state);
    let strategy_decision =
        strategy_decision_for_state(state, &uncertainty, &cognitive_budget, &session_id);
    let strategy_router = strategy_router_for_state(
        state,
        &task_state,
        &uncertainty,
        &cognitive_budget,
        &strategy_decision,
    );
    let capability_sequence = capability_sequence_for_state(state, &session_id);
    let capability_discovery = capability_discovery_for_state(state, &capability_sequence);
    let capability_selection = capability_selection_for_state(state, &capability_sequence);
    let capability_sequencing = capability_sequencing_for_state(state, &capability_sequence);
    let capability_retirement = capability_retirement_for_state(state, &capability_sequence);
    let probes = probes_for_state(state, &uncertainty);
    let postcondition_synthesizer =
        postcondition_synthesizer_for_state(state, &postconditions, &session_id);
    let drift_signal = drift_signal_for_state(state);
    let handoff_quality = handoff_quality_for_state(state);
    let tool_contracts = tool_contracts_for_state(state);
    let prompt_assembly = prompt_assembly_for_state(state, &tool_contracts);
    let turn_state = turn_state_for_state(state, &session_id);
    let decision_loop = decision_loop_for_state(
        state,
        &task_state,
        &uncertainty,
        &strategy_decision,
        &postconditions,
        &stop_condition,
    );
    let file_observations = file_observations_for_state(state, &session_id);
    let tool_selection_quality = tool_selection_quality_for_state(state);
    let model_routing = model_routing_for_state(
        state,
        &session_id,
        &strategy_decision.task_family,
        &semantic_impact.risk_class,
    );
    let clarification = clarification_contract_for_state(state);
    let operator_interruption_events = operator_interruption_events_for_state(state, &session_id);
    let error_recovery = error_recovery_for_state(state);
    let bounded_self_improvement_gate = bounded_self_improvement_gate_for_state(state);
    let verifier_independence_policy =
        verifier_independence_policy_for_state(state, &semantic_impact, &postconditions);
    let quality_ledger = quality_ledger_for_state(
        state,
        &stop_condition,
        &semantic_impact,
        bounded_self_improvement_gate.clone(),
    );
    let envelope = RuntimeExecutionEnvelope {
        envelope_id: format!("runtime-envelope:{}", session_id),
        session_id,
        turn_id: format!("step:{}", state.step_count),
        surface,
        objective: state.goal.clone(),
        policy_hash: state
            .resolved_intent
            .as_ref()
            .map(|intent| hex::encode(intent.evidence_requirements_hash))
            .unwrap_or_else(|| "unresolved".to_string()),
        tool_contract_ids: tool_contracts
            .iter()
            .map(|contract| contract.stable_tool_id.clone())
            .collect(),
        event_stream_id: format!("agent-events:{}", hex::encode(state.session_id)),
        trace_bundle_id: format!("agent-trace:{}", hex::encode(state.session_id)),
        quality_ledger_id: format!("agent-quality:{}", hex::encode(state.session_id)),
        ..RuntimeExecutionEnvelope::default()
    };
    let session_trace_bundle = session_trace_bundle_for_state(
        state,
        &envelope,
        &prompt_assembly,
        &postconditions,
        &stop_condition,
    );
    let events = runtime_events_for_snapshot(
        state,
        &envelope,
        &turn_state,
        &session_trace_bundle,
        &decision_loop,
        &task_state,
        &prompt_assembly,
        &uncertainty,
        &strategy_decision,
        &stop_condition,
    );

    RuntimeSubstrateSnapshot {
        envelope,
        port_contract: RuntimeSubstratePortContract::default(),
        events,
        tool_contracts,
        prompt_assembly,
        turn_state,
        decision_loop,
        file_observations,
        session_trace_bundle,
        task_state,
        uncertainty,
        strategy_router,
        strategy_decision,
        model_routing,
        capability_discovery,
        capability_selection,
        capability_sequencing,
        capability_retirement,
        capability_sequence,
        tool_selection_quality,
        probes,
        postcondition_synthesizer,
        postconditions,
        semantic_impact,
        cognitive_budget,
        drift_signal,
        verifier_independence_policy,
        dry_run_capabilities: default_dry_run_capabilities(),
        handoff_quality,
        task_family_playbook: task_family_playbook_for_state(state),
        negative_learning: negative_learning_for_state(state),
        memory_quality_gates: memory_quality_gates_for_state(state),
        operator_preference: operator_preference_for_state(state),
        bounded_self_improvement_gate,
        operator_collaboration: OperatorCollaborationContract {
            ask_only_when_uncertainty_or_policy_requires: true,
            choices_include_consequences: true,
            resume_preserves_plan_state: true,
            blocked_state_explained: true,
            intervention_success_measured: true,
            operator_decisions_preserved_in_trace: true,
        },
        workflow_envelope_adapter: workflow_envelope_adapter_for_surface(surface),
        harness_trace_adapter: harness_trace_adapter_for_surface(surface),
        operator_interruption: operator_interruption_contract_for_state(state),
        operator_interruption_events,
        clarification,
        error_recovery,
        quality_ledger,
        stop_condition,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn runtime_event(
    envelope: &RuntimeExecutionEnvelope,
    step_index: u32,
    event_kind: &str,
    pointer: Option<String>,
    payload_summary: BTreeMap<String, String>,
) -> AgentRuntimeEvent {
    AgentRuntimeEvent {
        event_id: format!("{}:{}:{}", envelope.event_stream_id, step_index, event_kind),
        session_id: envelope.session_id.clone(),
        turn_id: envelope.turn_id.clone(),
        step_index,
        event_kind: event_kind.to_string(),
        timestamp_ms: now_ms(),
        actor: "agent_runtime".to_string(),
        receipt_or_state_pointer: pointer,
        payload_summary,
        ..AgentRuntimeEvent::default()
    }
}

fn runtime_events_for_snapshot(
    state: &AgentState,
    envelope: &RuntimeExecutionEnvelope,
    turn_state: &AgentTurnState,
    trace_bundle: &SessionTraceBundle,
    decision_loop: &AgentDecisionLoop,
    task_state: &TaskStateModel,
    prompt_assembly: &PromptAssemblyContract,
    uncertainty: &UncertaintyAssessment,
    strategy_decision: &RuntimeStrategyDecision,
    stop_condition: &StopConditionRecord,
) -> Vec<AgentRuntimeEvent> {
    let mut task_payload = BTreeMap::new();
    task_payload.insert(
        "objective".to_string(),
        task_state.current_objective.clone(),
    );
    task_payload.insert(
        "known_fact_count".to_string(),
        task_state.known_facts.len().to_string(),
    );

    let mut prompt_payload = BTreeMap::new();
    prompt_payload.insert(
        "section_count".to_string(),
        prompt_assembly.included_section_count().to_string(),
    );
    prompt_payload.insert(
        "final_prompt_hash".to_string(),
        prompt_assembly.final_prompt_hash.clone(),
    );

    let mut uncertainty_payload = BTreeMap::new();
    uncertainty_payload.insert(
        "selected_action".to_string(),
        format!("{:?}", uncertainty.selected_action),
    );
    uncertainty_payload.insert("rationale".to_string(), uncertainty.rationale.clone());

    let mut strategy_payload = BTreeMap::new();
    strategy_payload.insert(
        "selected_strategy".to_string(),
        strategy_decision.selected_strategy.clone(),
    );
    strategy_payload.insert(
        "task_family".to_string(),
        strategy_decision.task_family.clone(),
    );

    let mut stop_payload = BTreeMap::new();
    stop_payload.insert("reason".to_string(), format!("{:?}", stop_condition.reason));
    stop_payload.insert(
        "evidence_sufficient".to_string(),
        stop_condition.evidence_sufficient.to_string(),
    );

    let mut turn_payload = BTreeMap::new();
    turn_payload.insert("phase".to_string(), format!("{:?}", turn_state.phase));
    turn_payload.insert(
        "persisted_before_irreversible_boundary".to_string(),
        turn_state
            .persisted_before_irreversible_boundary
            .to_string(),
    );

    let mut trace_payload = BTreeMap::new();
    trace_payload.insert("bundle_id".to_string(), trace_bundle.bundle_id.clone());
    trace_payload.insert(
        "reconstructs_final_state".to_string(),
        trace_bundle.reconstructs_final_state.to_string(),
    );

    let mut decision_payload = BTreeMap::new();
    decision_payload.insert(
        "stage_count".to_string(),
        decision_loop.stages.len().to_string(),
    );
    decision_payload.insert(
        "all_required_stages_recorded".to_string(),
        decision_loop.all_required_stages_recorded.to_string(),
    );

    vec![
        runtime_event(
            envelope,
            state.step_count,
            "turn_state_recorded",
            Some("AgentTurnState".to_string()),
            turn_payload,
        ),
        runtime_event(
            envelope,
            state.step_count,
            "task_state_projected",
            Some("TaskStateModel".to_string()),
            task_payload,
        ),
        runtime_event(
            envelope,
            state.step_count,
            "prompt_assembly_recorded",
            Some("PromptAssemblyContract".to_string()),
            prompt_payload,
        ),
        runtime_event(
            envelope,
            state.step_count,
            "decision_loop_recorded",
            Some("AgentDecisionLoop".to_string()),
            decision_payload,
        ),
        runtime_event(
            envelope,
            state.step_count,
            "uncertainty_assessed",
            Some("UncertaintyAssessment".to_string()),
            uncertainty_payload,
        ),
        runtime_event(
            envelope,
            state.step_count,
            "strategy_decision_recorded",
            Some("RuntimeStrategyDecision".to_string()),
            strategy_payload,
        ),
        runtime_event(
            envelope,
            state.step_count,
            "stop_condition_recorded",
            Some("StopConditionRecord".to_string()),
            stop_payload,
        ),
        runtime_event(
            envelope,
            state.step_count,
            "session_trace_bundle_recorded",
            Some("SessionTraceBundle".to_string()),
            trace_payload,
        ),
    ]
}

fn turn_state_for_state(state: &AgentState, session_id: &str) -> AgentTurnState {
    let phase = match &state.status {
        AgentStatus::Completed(_) => AgentTurnPhase::Completed,
        AgentStatus::Failed(_) => AgentTurnPhase::Failed,
        AgentStatus::Terminated => AgentTurnPhase::Cancelled,
        AgentStatus::Paused(_) => match state.pause_reason() {
            Some(
                AgentPauseReason::WaitingForApproval | AgentPauseReason::WaitingForHumanApproval,
            ) => AgentTurnPhase::AwaitingApproval,
            Some(
                AgentPauseReason::WaitingForIntentClarification
                | AgentPauseReason::WaitingForTargetClarification
                | AgentPauseReason::WaitingForSudoPassword,
            ) => AgentTurnPhase::ContextPrepared,
            _ => AgentTurnPhase::Failed,
        },
        AgentStatus::Running => {
            if state.pending_tool_hash.is_some() {
                AgentTurnPhase::PolicyEvaluated
            } else if state.pending_tool_call.is_some() {
                AgentTurnPhase::ToolProposed
            } else if !state.execution_queue.is_empty() {
                AgentTurnPhase::ToolValidated
            } else {
                AgentTurnPhase::ContextPrepared
            }
        }
        AgentStatus::Idle => AgentTurnPhase::Accepted,
    };

    let mut pending_authority_refs = Vec::new();
    if let Some(hash) = state.pending_tool_hash {
        pending_authority_refs.push(EvidenceRef {
            kind: "pending_tool_hash".to_string(),
            reference: hex::encode(hash),
            summary: "pending action hash persisted before approval or execution".to_string(),
        });
    }
    if state.pending_approval.is_some() {
        pending_authority_refs.push(EvidenceRef {
            kind: "approval_grant".to_string(),
            reference: "pending_approval".to_string(),
            summary: "approval state is part of the canonical pending action".to_string(),
        });
    }

    AgentTurnState {
        turn_id: format!("step:{}", state.step_count),
        phase,
        persisted_before_irreversible_boundary: state.pending_tool_jcs.is_some()
            || state.pending_tool_hash.is_some()
            || state.pending_approval.is_some()
            || matches!(
                state.status,
                AgentStatus::Paused(_) | AgentStatus::Completed(_) | AgentStatus::Failed(_)
            ),
        cancellation_boundaries: vec![
            "model_request".to_string(),
            "stream_decode".to_string(),
            "tool_execution".to_string(),
            "approval_wait".to_string(),
            "child_wait".to_string(),
        ],
        crash_recovery_pointer: format!("agent_state:{session_id}:{}", state.step_count),
        pending_authority_refs,
        evidence_refs: vec![EvidenceRef {
            kind: "runtime_state".to_string(),
            reference: format!("agent_state:{session_id}"),
            summary: format!("status:{:?};step:{}", state.status, state.step_count),
        }],
        ..AgentTurnState::default()
    }
}

fn decision_loop_for_state(
    state: &AgentState,
    task_state: &TaskStateModel,
    uncertainty: &UncertaintyAssessment,
    strategy_decision: &RuntimeStrategyDecision,
    postconditions: &PostconditionSynthesis,
    stop_condition: &StopConditionRecord,
) -> AgentDecisionLoop {
    let stages = [
        (
            AgentDecisionStage::Perceive,
            RuntimeCheckStatus::Passed,
            "runtime state checkpoint loaded",
        ),
        (
            AgentDecisionStage::ClassifyIntent,
            if state.resolved_intent.is_some() {
                RuntimeCheckStatus::Passed
            } else {
                RuntimeCheckStatus::Unknown
            },
            "intent classification is present when the resolver has produced it",
        ),
        (
            AgentDecisionStage::UpdateTaskState,
            RuntimeCheckStatus::Passed,
            "TaskStateModel projected from the persisted agent state",
        ),
        (
            AgentDecisionStage::AssessUncertainty,
            RuntimeCheckStatus::Passed,
            "UncertaintyAssessment selected the next bounded action",
        ),
        (
            AgentDecisionStage::DecideStrategy,
            RuntimeCheckStatus::Passed,
            "RuntimeStrategyDecision records the selected strategy",
        ),
        (
            AgentDecisionStage::RetrieveContext,
            if task_state.known_resources.is_empty() {
                RuntimeCheckStatus::Skipped
            } else {
                RuntimeCheckStatus::Passed
            },
            "retrieved resources are attached as evidence refs when present",
        ),
        (
            AgentDecisionStage::Plan,
            if state.planner_state.is_some() {
                RuntimeCheckStatus::Passed
            } else {
                RuntimeCheckStatus::Skipped
            },
            "planner state is preserved when the strategy uses planning",
        ),
        (
            AgentDecisionStage::ChooseCapabilities,
            RuntimeCheckStatus::Passed,
            "capabilities are projected from tool log and recent actions",
        ),
        (
            AgentDecisionStage::Execute,
            if state.recent_actions.is_empty() {
                RuntimeCheckStatus::Skipped
            } else {
                RuntimeCheckStatus::Passed
            },
            "recent runtime actions are part of the substrate snapshot",
        ),
        (
            AgentDecisionStage::Verify,
            if postconditions.checks.is_empty() {
                RuntimeCheckStatus::Unknown
            } else if postconditions.all_required_checks_proven() {
                RuntimeCheckStatus::Passed
            } else {
                RuntimeCheckStatus::Required
            },
            "postconditions drive verification state",
        ),
        (
            AgentDecisionStage::RecoverOrAsk,
            if uncertainty.should_ask() || uncertainty.should_probe() || state.consecutive_failures > 0
            {
                RuntimeCheckStatus::Required
            } else {
                RuntimeCheckStatus::Skipped
            },
            "recovery or operator intervention is required only when uncertainty or failure demands it",
        ),
        (
            AgentDecisionStage::Summarize,
            RuntimeCheckStatus::Passed,
            "snapshot summarizes state without exposing raw receipts in chat",
        ),
        (
            AgentDecisionStage::UpdateMemory,
            RuntimeCheckStatus::Skipped,
            "memory writeback is separately quality-gated",
        ),
        (
            AgentDecisionStage::RecordStopReason,
            if stop_condition.rationale.trim().is_empty() {
                RuntimeCheckStatus::Unknown
            } else {
                RuntimeCheckStatus::Passed
            },
            "stop reason is recorded for terminal or current non-terminal state",
        ),
        (
            AgentDecisionStage::EmitQualitySignals,
            RuntimeCheckStatus::Passed,
            "quality ledger and scorecard signals are emitted from the same substrate",
        ),
    ]
    .into_iter()
    .map(|(stage, status, rationale)| AgentDecisionStageRecord {
        stage,
        status,
        rationale: rationale.to_string(),
        evidence_refs: vec![EvidenceRef::new(
            "runtime_state",
            format!("step:{}", state.step_count),
        )],
    })
    .collect::<Vec<_>>();

    AgentDecisionLoop {
        loop_id: format!(
            "decision-loop:{}:{}",
            hex::encode(state.session_id),
            state.step_count
        ),
        current_stage: AgentDecisionStage::EmitQualitySignals,
        all_required_stages_recorded: stages.len() >= AgentDecisionLoop::required_stage_count(),
        stages,
        evidence_refs: vec![
            EvidenceRef::new("task_state", task_state.current_objective.clone()),
            EvidenceRef::new("strategy", strategy_decision.selected_strategy.clone()),
        ],
    }
}

fn file_observations_for_state(state: &AgentState, session_id: &str) -> Vec<FileObservationState> {
    let mut observations = structured_file_observations_from_log(state, session_id);
    let read_evidence = execution_evidence_value_from_log(state, "workspace_read_observed");
    let edit_evidence = execution_evidence_value_from_log(state, "workspace_edit_applied");
    let read_step = read_evidence.as_deref().and_then(parse_receipt_step);
    let read_path = read_evidence.as_deref().and_then(parse_receipt_path);
    let edit_step = edit_evidence.as_deref().and_then(parse_receipt_step);
    let edit_path = edit_evidence.as_deref().and_then(parse_receipt_path);

    if observations.is_empty() {
        if let Some(path) = read_path.as_deref() {
            observations.push(file_observation_from_receipt(
                state,
                session_id,
                path,
                read_evidence.as_deref().unwrap_or_default(),
                read_step.unwrap_or(state.step_count),
                false,
            ));
        }
    }

    if let Some(path) = edit_path {
        let matching_prior_read = read_path
            .as_deref()
            .map(|read_path| read_path == path)
            .unwrap_or(false)
            && read_step
                .zip(edit_step)
                .is_some_and(|(read, edit)| read <= edit);
        observations.push(file_observation_from_receipt(
            state,
            session_id,
            &path,
            edit_evidence.as_deref().unwrap_or_default(),
            edit_step.unwrap_or(state.step_count),
            matching_prior_read,
        ));
    }

    if observations.is_empty() {
        observations.extend(
            state
                .tool_execution_log
                .keys()
                .filter(|name| name.starts_with("file__"))
                .map(|tool| FileObservationState {
                    requested_path: "unavailable:tool_log_lacks_object_level_arguments".to_string(),
                    canonical_path: "unknown".to_string(),
                    symlink_status: "unknown".to_string(),
                    workspace_root: state.working_directory.clone(),
                    content_hash: "unknown".to_string(),
                    mtime_ms: 0,
                    size_bytes: 0,
                    encoding: "unknown".to_string(),
                    line_endings: "unknown".to_string(),
                    read_status: FileReadStatus::Unknown,
                    observing_tool: tool.clone(),
                    observing_turn: format!("step:{}", state.step_count),
                    stale_write_guard_enforced: false,
                    evidence_refs: vec![EvidenceRef {
                        kind: "tool_execution_log".to_string(),
                        reference: format!("{session_id}:{tool}"),
                        summary:
                            "file tool was observed, but object-level path/hash metadata is not yet attached"
                                .to_string(),
                    }],
                    ..FileObservationState::default()
                }),
        );
    }

    observations
}

#[derive(Debug, Deserialize)]
struct StructuredWorkspaceFileObservation {
    step_index: u32,
    tool_name: String,
    requested_path: String,
    canonical_path: String,
    content_hash: String,
    mtime_ms: u128,
    size: u64,
}

fn structured_file_observations_from_log(
    state: &AgentState,
    session_id: &str,
) -> Vec<FileObservationState> {
    state
        .tool_execution_log
        .iter()
        .filter_map(|(key, status)| {
            if !key.starts_with("evidence::workspace_read_observed:") {
                return None;
            }
            let ToolCallStatus::Executed(value) = status else {
                return None;
            };
            let receipt: StructuredWorkspaceFileObservation = serde_json::from_str(value).ok()?;
            Some(FileObservationState {
                requested_path: receipt.requested_path.clone(),
                canonical_path: receipt.canonical_path.clone(),
                symlink_status: "not_symlink".to_string(),
                workspace_root: state.working_directory.clone(),
                content_hash: receipt.content_hash.clone(),
                mtime_ms: receipt.mtime_ms.min(u64::MAX as u128) as u64,
                size_bytes: receipt.size,
                encoding: "unknown".to_string(),
                line_endings: "unknown".to_string(),
                read_status: FileReadStatus::Full,
                observing_tool: receipt.tool_name.clone(),
                observing_turn: format!("step:{}", receipt.step_index),
                stale_write_guard_enforced: false,
                evidence_refs: vec![EvidenceRef {
                    kind: "workspace_file_observation".to_string(),
                    reference: format!("{session_id}:{key}"),
                    summary: "object-level file observation with canonical path and content hash"
                        .to_string(),
                }],
                ..FileObservationState::default()
            })
        })
        .collect()
}

fn execution_evidence_value_from_log(state: &AgentState, name: &str) -> Option<String> {
    let key = format!("evidence::{name}=true");
    match state.tool_execution_log.get(&key) {
        Some(ToolCallStatus::Executed(value)) => Some(value.clone()),
        _ => None,
    }
}

fn parse_receipt_step(value: &str) -> Option<u32> {
    parse_receipt_field(value, "step")?.parse().ok()
}

fn parse_receipt_path(value: &str) -> Option<String> {
    parse_receipt_field(value, "path").map(str::to_string)
}

fn parse_receipt_tool(value: &str) -> Option<String> {
    parse_receipt_field(value, "tool").map(str::to_string)
}

fn parse_receipt_field<'a>(value: &'a str, field: &str) -> Option<&'a str> {
    value.split(';').find_map(|part| {
        let (key, rest) = part.split_once('=')?;
        (key.trim() == field).then_some(rest.trim())
    })
}

fn file_observation_from_receipt(
    state: &AgentState,
    session_id: &str,
    path: &str,
    receipt: &str,
    observed_step: u32,
    stale_write_guard_enforced: bool,
) -> FileObservationState {
    let metadata = std::fs::symlink_metadata(path).ok();
    let bytes = std::fs::read(path).ok();
    let content_hash = bytes
        .as_deref()
        .map(stable_bytes_hash)
        .unwrap_or_else(|| "unknown".to_string());
    let (encoding, line_endings, read_status) = match bytes.as_deref() {
        Some(bytes) if std::str::from_utf8(bytes).is_ok() => (
            "utf-8".to_string(),
            detected_line_endings(bytes),
            FileReadStatus::Full,
        ),
        Some(_) => (
            "binary".to_string(),
            "not_applicable".to_string(),
            FileReadStatus::MetadataOnly,
        ),
        None => (
            "unknown".to_string(),
            "unknown".to_string(),
            FileReadStatus::Unknown,
        ),
    };
    let symlink_status = metadata
        .as_ref()
        .map(|metadata| {
            if metadata.file_type().is_symlink() {
                "symlink"
            } else {
                "not_symlink"
            }
        })
        .unwrap_or("unknown")
        .to_string();
    let canonical_path = std::fs::canonicalize(path)
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_else(|_| path.to_string());
    let mtime_ms = metadata
        .as_ref()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    FileObservationState {
        requested_path: path.to_string(),
        canonical_path,
        symlink_status,
        workspace_root: state.working_directory.clone(),
        content_hash,
        mtime_ms,
        size_bytes: metadata
            .as_ref()
            .map(|metadata| metadata.len())
            .unwrap_or(0),
        encoding,
        line_endings,
        read_status,
        observing_tool: parse_receipt_tool(receipt).unwrap_or_else(|| "file__read".to_string()),
        observing_turn: format!("step:{observed_step}"),
        stale_write_guard_enforced,
        evidence_refs: vec![EvidenceRef {
            kind: "workspace_file_receipt".to_string(),
            reference: format!("{session_id}:{receipt}"),
            summary: "object-level file observation derived from workspace read/edit receipt"
                .to_string(),
        }],
        ..FileObservationState::default()
    }
}

fn stable_bytes_hash(bytes: &[u8]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("stable64:{hash:016x}")
}

fn detected_line_endings(bytes: &[u8]) -> String {
    if bytes.windows(2).any(|window| window == b"\r\n") {
        "crlf".to_string()
    } else if bytes.contains(&b'\n') {
        "lf".to_string()
    } else {
        "none".to_string()
    }
}

fn session_trace_bundle_for_state(
    state: &AgentState,
    envelope: &RuntimeExecutionEnvelope,
    prompt_assembly: &PromptAssemblyContract,
    postconditions: &PostconditionSynthesis,
    stop_condition: &StopConditionRecord,
) -> SessionTraceBundle {
    SessionTraceBundle {
        bundle_id: envelope.trace_bundle_id.clone(),
        config_snapshot_ref: "EffectiveAgentConfig:default".to_string(),
        prompt_section_hashes: prompt_assembly
            .sections
            .iter()
            .map(|section| section.content_hash.clone())
            .collect(),
        model_call_refs: state
            .command_history
            .iter()
            .map(|command| format!("command:{}:{}", command.step_index, command.timestamp_ms))
            .collect(),
        model_output_refs: Vec::new(),
        tool_proposal_refs: state.recent_actions.clone(),
        policy_decision_refs: state
            .pending_tool_hash
            .map(|hash| vec![format!("pending_tool_hash:{}", hex::encode(hash))])
            .unwrap_or_default(),
        approval_refs: if state.pending_approval.is_some() {
            vec!["pending_approval".to_string()]
        } else {
            Vec::new()
        },
        execution_receipt_refs: state
            .execution_ledger
            .attempts
            .iter()
            .map(|attempt| format!("execution_attempt:{}", attempt.attempt_id))
            .collect(),
        memory_retrieval_refs: state
            .resolved_intent
            .as_ref()
            .map(|intent| vec![format!("intent:{}", intent.intent_id)])
            .unwrap_or_default(),
        child_agent_state_refs: state
            .child_session_ids
            .iter()
            .map(hex::encode)
            .map(|sid| format!("child_agent:{sid}"))
            .collect(),
        final_outcome_ref: format!("{:?}:{}", stop_condition.reason, stop_condition.rationale),
        redaction_manifest_ref: "runtime_redaction:default".to_string(),
        verification_result_ref: if postconditions.all_required_checks_proven() {
            "postconditions:passed".to_string()
        } else {
            "postconditions:unknown_or_pending".to_string()
        },
        reconstructs_final_state: !envelope.envelope_id.trim().is_empty()
            && !prompt_assembly.final_prompt_hash.trim().is_empty()
            && !stop_condition.rationale.trim().is_empty(),
        evidence_refs: vec![EvidenceRef::new(
            "runtime_snapshot",
            format!("{}:{}", envelope.session_id, state.step_count),
        )],
    }
}

fn tool_selection_quality_for_state(state: &AgentState) -> Vec<ToolSelectionQualityModel> {
    state
        .tool_execution_log
        .iter()
        .map(|(tool_id, status)| {
            let failed = matches!(status, ToolCallStatus::Failed(_));
            let policy_denied = match status {
                ToolCallStatus::Failed(detail) => detail.to_ascii_lowercase().contains("policy"),
                _ => false,
            };
            ToolSelectionQualityModel {
                model_id: "runtime-observed-tool-prior:v1".to_string(),
                tool_id: tool_id.clone(),
                task_family: state
                    .resolved_intent
                    .as_ref()
                    .map(|intent| intent.intent_id.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                schema_validation_failures: match status {
                    ToolCallStatus::Failed(detail)
                        if detail.to_ascii_lowercase().contains("schema")
                            || detail.to_ascii_lowercase().contains("invalid") =>
                    {
                        1
                    }
                    _ => 0,
                },
                policy_denials: u32::from(policy_denied),
                postcondition_pass_rate_bps: if failed { 0 } else { 10_000 },
                retry_rate_bps: if state.consecutive_failures > 0 {
                    5_000
                } else {
                    0
                },
                average_latency_ms: 0,
                operator_override_rate_bps: if state.pending_approval.is_some() {
                    10_000
                } else {
                    0
                },
                failure_classes: match status {
                    ToolCallStatus::Failed(detail) => vec![detail.clone()],
                    _ => Vec::new(),
                },
                helpful_task_families: if failed {
                    Vec::new()
                } else {
                    vec!["observed_success_or_pending".to_string()]
                },
                harmful_task_families: if failed {
                    vec!["observed_failure".to_string()]
                } else {
                    Vec::new()
                },
                evidence_refs: vec![EvidenceRef::new(
                    "tool_execution_log",
                    format!("{}:{tool_id}", hex::encode(state.session_id)),
                )],
            }
        })
        .collect()
}

fn model_routing_for_state(
    state: &AgentState,
    session_id: &str,
    task_family: &str,
    risk_class: &str,
) -> ModelRoutingDecision {
    let privacy_class = if state.working_directory.starts_with("/tmp") {
        PromptPrivacyClass::Public
    } else {
        PromptPrivacyClass::Internal
    };
    let required_modality = if matches!(
        state.current_tier,
        ExecutionTier::VisualBackground | ExecutionTier::VisualForeground
    ) {
        "vision+text".to_string()
    } else {
        "text".to_string()
    };
    let route = RuntimeModelRouter::route_from_env(ModelRouterInput {
        task_class: task_family.to_string(),
        risk_class: risk_class.to_string(),
        privacy_class,
        required_modality,
        requested_model: std::env::var("IOI_RUNTIME_MODEL")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        policy_allows_egress: env_truthy("IOI_AGENT_ALLOW_MODEL_EGRESS")
            || env_truthy("AUTOPILOT_ALLOW_MODEL_EGRESS"),
        allow_sensitive_remote: env_truthy("IOI_AGENT_ALLOW_SENSITIVE_MODEL_EGRESS")
            || env_truthy("AUTOPILOT_ALLOW_SENSITIVE_MODEL_EGRESS"),
        latency_budget_ms: 30_000,
        token_estimate: state.tokens_used,
    });
    let mut decision = match route {
        Ok(route) => route.decision,
        Err(decision) => decision,
    };

    decision.routing_id = format!("model-routing:{session_id}:{}", state.step_count);
    decision.required_modality = if matches!(
        state.current_tier,
        ExecutionTier::VisualBackground | ExecutionTier::VisualForeground
    ) {
        "vision+text".to_string()
    } else {
        "text".to_string()
    };
    decision.token_estimate = state.tokens_used;
    decision.cost_estimate_units = decision
        .cost_estimate_units
        .max(state.budget.saturating_sub(state.tokens_used));
    if state.consecutive_failures > 0 && decision.fallback_reason.is_empty() {
        decision.fallback_reason =
            "fallback considered after runtime failure under configured model policy".to_string();
    }
    if decision.error_class.is_empty() {
        decision.error_class = state
            .execution_ledger
            .attempts
            .iter()
            .rev()
            .find_map(|attempt| attempt.error_class.clone())
            .unwrap_or_default();
    }
    decision.evidence_refs.push(EvidenceRef::new(
        "runtime_state",
        format!("agent_state:{session_id}:{}", state.step_count),
    ));
    decision
}

fn env_truthy(key: &str) -> bool {
    std::env::var(key).is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn runtime_error_class_from_label(label: &str) -> RuntimeErrorClass {
    let normalized = label.to_ascii_lowercase();
    if normalized.contains("policy") {
        RuntimeErrorClass::PolicyBlocked
    } else if normalized.contains("approval") {
        RuntimeErrorClass::PendingApproval
    } else if normalized.contains("schema") || normalized.contains("invalid") {
        RuntimeErrorClass::InvalidToolInput
    } else if normalized.contains("provider") || normalized.contains("model") {
        RuntimeErrorClass::ProviderError
    } else if normalized.contains("timeout") || normalized.contains("hang") {
        RuntimeErrorClass::TimeoutOrHang
    } else if normalized.contains("external") {
        RuntimeErrorClass::ExternalDependency
    } else {
        RuntimeErrorClass::UnexpectedState
    }
}

fn error_recovery_for_state(state: &AgentState) -> Vec<ErrorRecoveryContract> {
    let mut contracts = state
        .execution_ledger
        .attempts
        .iter()
        .filter_map(|attempt| attempt.error_class.as_deref())
        .map(runtime_error_class_from_label)
        .map(ErrorRecoveryContract::for_error_class)
        .collect::<Vec<_>>();

    if contracts.is_empty() && state.consecutive_failures > 0 {
        contracts.push(ErrorRecoveryContract::for_error_class(
            RuntimeErrorClass::UnexpectedState,
        ));
    }
    if contracts.is_empty()
        && matches!(
            state.pause_reason(),
            Some(AgentPauseReason::WaitingForApproval | AgentPauseReason::WaitingForHumanApproval)
        )
    {
        contracts.push(ErrorRecoveryContract::for_error_class(
            RuntimeErrorClass::PendingApproval,
        ));
    }
    contracts
}

fn clarification_contract_for_state(state: &AgentState) -> Option<ClarificationContract> {
    let is_clarification = state.awaiting_intent_clarification
        || matches!(
            state.pause_reason(),
            Some(
                AgentPauseReason::WaitingForIntentClarification
                    | AgentPauseReason::WaitingForTargetClarification
            )
        );
    if !is_clarification {
        return None;
    }
    Some(ClarificationContract {
        clarification_id: format!(
            "clarification:{}:{}",
            hex::encode(state.session_id),
            state.step_count
        ),
        question: "operator clarification required before safe continuation".to_string(),
        missing_input: "intent_or_target".to_string(),
        consequences: vec![
            "answer updates TaskStateModel open questions".to_string(),
            "runtime resumes through the same authority-preserving substrate".to_string(),
        ],
        answer_updates_task_state: true,
        replayable: true,
        evidence_refs: vec![EvidenceRef::new(
            "agent_status",
            format!("paused:{:?}", state.pause_reason()),
        )],
    })
}

fn operator_interruption_events_for_state(
    state: &AgentState,
    session_id: &str,
) -> Vec<OperatorInterruptionEvent> {
    let Some(reason) = state.pause_reason() else {
        return Vec::new();
    };
    let action = match reason {
        AgentPauseReason::WaitingForApproval | AgentPauseReason::WaitingForHumanApproval => {
            "approval_wait"
        }
        AgentPauseReason::WaitingForIntentClarification
        | AgentPauseReason::WaitingForTargetClarification => "clarification_wait",
        AgentPauseReason::WaitingForSudoPassword => "credential_wait",
        AgentPauseReason::ApprovalLoopDetected => "approval_loop_detected",
        AgentPauseReason::RetryBlocked(_)
        | AgentPauseReason::ModelRefusal(_)
        | AgentPauseReason::Other(_) => "operator_intervention",
    };
    vec![OperatorInterruptionEvent {
        event_id: format!("operator-interruption:{session_id}:{}", state.step_count),
        action: action.to_string(),
        preserves_objective: !state.goal.trim().is_empty(),
        preserves_task_state: true,
        preserves_authority: true,
        trace_event_required: true,
        evidence_refs: vec![EvidenceRef::new(
            "agent_status",
            format!("paused:{reason:?}"),
        )],
    }]
}

fn task_state_for_state(
    state: &AgentState,
    stop_condition: &StopConditionRecord,
) -> TaskStateModel {
    let mut task_state = TaskStateModel::for_objective(state.goal.clone());
    task_state.evidence_refs.push(EvidenceRef {
        kind: "runtime_state".to_string(),
        reference: format!("agent_state:{}", hex::encode(state.session_id)),
        summary: format!("status:{:?};step:{}", state.status, state.step_count),
    });

    if let Some(resolved_intent) = &state.resolved_intent {
        task_state.known_facts.push(TaskStateClaim {
            id: "resolved_intent".to_string(),
            text: format!("resolved intent id: {}", resolved_intent.intent_id),
            confidence: ioi_types::app::ConfidenceBand::High,
            evidence_refs: vec![EvidenceRef {
                kind: "intent_hash".to_string(),
                reference: hex::encode(resolved_intent.evidence_requirements_hash),
                summary: "intent resolver output".to_string(),
            }],
            stale: false,
        });
    }

    if state.awaiting_intent_clarification {
        task_state
            .open_questions
            .push("intent clarification required".to_string());
    }

    match state.pause_reason() {
        Some(AgentPauseReason::WaitingForIntentClarification)
        | Some(AgentPauseReason::WaitingForTargetClarification) => {
            task_state
                .open_questions
                .push("operator clarification pending".to_string());
        }
        Some(AgentPauseReason::WaitingForApproval)
        | Some(AgentPauseReason::WaitingForHumanApproval) => {
            task_state
                .blockers
                .push("approval required before execution can continue".to_string());
        }
        Some(AgentPauseReason::WaitingForSudoPassword) => {
            task_state
                .blockers
                .push("human credential required before execution can continue".to_string());
        }
        Some(AgentPauseReason::ApprovalLoopDetected) => {
            task_state
                .blockers
                .push("approval loop detected".to_string());
        }
        Some(AgentPauseReason::RetryBlocked(detail))
        | Some(AgentPauseReason::ModelRefusal(detail))
        | Some(AgentPauseReason::Other(detail)) => {
            if !detail.trim().is_empty() {
                task_state.blockers.push(detail);
            }
        }
        None => {}
    }

    if !stop_condition.evidence_sufficient {
        task_state.uncertain_facts.push(TaskStateClaim {
            id: "evidence_sufficiency".to_string(),
            text: "evidence is not yet sufficient for completion".to_string(),
            confidence: ioi_types::app::ConfidenceBand::Medium,
            evidence_refs: stop_condition.evidence_refs.clone(),
            stale: false,
        });
    }

    task_state
}

fn tool_contracts_for_state(state: &AgentState) -> Vec<RuntimeToolContract> {
    let mut tool_names: Vec<String> = state.tool_execution_log.keys().cloned().collect();
    tool_names.sort();
    tool_names
        .into_iter()
        .map(|name| {
            runtime_tool_contract_for_definition(&LlmToolDefinition {
                name,
                description: "Runtime-observed tool projected into the shared substrate"
                    .to_string(),
                parameters: r#"{"type":"object"}"#.to_string(),
            })
        })
        .collect()
}

fn prompt_assembly_for_state(
    state: &AgentState,
    tool_contracts: &[RuntimeToolContract],
) -> PromptAssemblyContract {
    let mut sections = Vec::new();
    let session_id = hex::encode(state.session_id);
    sections.push(PromptSectionRecord::new(
        "runtime_root_safety_policy",
        PromptLayerKind::RuntimeRootSafetyPolicy,
        "RuntimeSubstratePortContract",
        "Authority, policy, receipts, replay, trace export, and quality ledgers are mandatory for consequential execution.",
        PromptSectionMutability::ImmutablePolicy,
        PromptPrivacyClass::Internal,
    ));
    sections.push(PromptSectionRecord::new(
        "user_goal",
        PromptLayerKind::UserGoal,
        "AgentState.goal",
        &state.goal,
        PromptSectionMutability::OperatorMutable,
        PromptPrivacyClass::Public,
    ));

    if let Some(planner) = &state.planner_state {
        sections.push(PromptSectionRecord::new(
            "active_plan",
            PromptLayerKind::ActivePlan,
            "AgentState.planner_state",
            &format!("planner_status={:?}", planner.status),
            PromptSectionMutability::RuntimeMutable,
            PromptPrivacyClass::Internal,
        ));
    }

    let tool_material = if tool_contracts.is_empty() {
        "no runtime tool contracts observed for this snapshot".to_string()
    } else {
        tool_contracts
            .iter()
            .map(|contract| {
                format!(
                    "{}:{}:{}",
                    contract.stable_tool_id, contract.effect_class, contract.policy_target
                )
            })
            .collect::<Vec<_>>()
            .join("|")
    };
    sections.push(PromptSectionRecord::new(
        "tool_contracts",
        PromptLayerKind::ToolContract,
        "RuntimeToolContract",
        &tool_material,
        PromptSectionMutability::RuntimeMutable,
        PromptPrivacyClass::Internal,
    ));

    if let Some(intent) = &state.resolved_intent {
        sections.push(PromptSectionRecord::new(
            "memory_context",
            PromptLayerKind::MemoryContext,
            "intent_resolver",
            &format!("resolved_intent={}", intent.intent_id),
            PromptSectionMutability::RuntimeMutable,
            PromptPrivacyClass::Internal,
        ));
    }

    let mut assembly = PromptAssemblyContract::new(
        format!("prompt-assembly:{}:{}", session_id, state.step_count),
        sections,
    );
    assembly.evidence_refs.push(EvidenceRef {
        kind: "runtime_state".to_string(),
        reference: format!("agent_state:{session_id}"),
        summary: "prompt assembly projected from shared runtime state".to_string(),
    });
    assembly
}

fn uncertainty_for_state(
    state: &AgentState,
    stop_condition: &StopConditionRecord,
    postconditions: &PostconditionSynthesis,
) -> UncertaintyAssessment {
    let evidence_refs = vec![EvidenceRef::new(
        "agent_status",
        format!("{:?}:{}", state.status, hex::encode(state.session_id)),
    )];
    let assessment_id = format!(
        "uncertainty:{}:{}",
        hex::encode(state.session_id),
        state.step_count
    );

    if matches!(state.status, AgentStatus::Completed(_)) && stop_condition.evidence_sufficient {
        return UncertaintyAssessment {
            assessment_id,
            ambiguity_level: UncertaintyLevel::Low,
            missing_input_severity: UncertaintyLevel::None,
            reversibility: ConfidenceBand::High,
            cost_of_being_wrong: UncertaintyLevel::Low,
            value_of_asking_human: UncertaintyLevel::Low,
            value_of_retrieval: UncertaintyLevel::Low,
            value_of_probe: UncertaintyLevel::Low,
            confidence_threshold: ConfidenceBand::Medium,
            selected_action: RuntimeDecisionAction::Stop,
            rationale: "objective is complete with sufficient evidence".to_string(),
            evidence_refs,
        };
    }

    if state.awaiting_intent_clarification
        || matches!(
            state.pause_reason(),
            Some(
                AgentPauseReason::WaitingForIntentClarification
                    | AgentPauseReason::WaitingForTargetClarification
                    | AgentPauseReason::WaitingForSudoPassword
            )
        )
    {
        return UncertaintyAssessment {
            assessment_id,
            ambiguity_level: UncertaintyLevel::High,
            missing_input_severity: UncertaintyLevel::High,
            reversibility: ConfidenceBand::Low,
            cost_of_being_wrong: UncertaintyLevel::High,
            value_of_asking_human: UncertaintyLevel::High,
            value_of_retrieval: UncertaintyLevel::Low,
            value_of_probe: UncertaintyLevel::Low,
            confidence_threshold: ConfidenceBand::High,
            selected_action: RuntimeDecisionAction::AskHuman,
            rationale: "runtime is waiting on operator input that changes the safe next action"
                .to_string(),
            evidence_refs,
        };
    }

    if matches!(
        state.pause_reason(),
        Some(AgentPauseReason::WaitingForApproval | AgentPauseReason::WaitingForHumanApproval)
    ) {
        return UncertaintyAssessment {
            assessment_id,
            ambiguity_level: UncertaintyLevel::Medium,
            missing_input_severity: UncertaintyLevel::High,
            reversibility: ConfidenceBand::Low,
            cost_of_being_wrong: UncertaintyLevel::High,
            value_of_asking_human: UncertaintyLevel::High,
            value_of_retrieval: UncertaintyLevel::Low,
            value_of_probe: UncertaintyLevel::Low,
            confidence_threshold: ConfidenceBand::High,
            selected_action: RuntimeDecisionAction::AskHuman,
            rationale: "policy requires explicit approval before continuing".to_string(),
            evidence_refs,
        };
    }

    if state.consecutive_failures > 0
        || postconditions
            .checks
            .iter()
            .any(|check| check.status == RuntimeCheckStatus::Unknown)
    {
        return UncertaintyAssessment {
            assessment_id,
            ambiguity_level: UncertaintyLevel::Medium,
            missing_input_severity: UncertaintyLevel::Medium,
            reversibility: ConfidenceBand::Medium,
            cost_of_being_wrong: UncertaintyLevel::Medium,
            value_of_asking_human: UncertaintyLevel::Low,
            value_of_retrieval: UncertaintyLevel::Medium,
            value_of_probe: UncertaintyLevel::High,
            confidence_threshold: ConfidenceBand::High,
            selected_action: RuntimeDecisionAction::Probe,
            rationale: "a cheap probe can reduce uncertainty before another execution attempt"
                .to_string(),
            evidence_refs,
        };
    }

    UncertaintyAssessment {
        assessment_id,
        ambiguity_level: UncertaintyLevel::Low,
        missing_input_severity: UncertaintyLevel::Low,
        reversibility: ConfidenceBand::Medium,
        cost_of_being_wrong: UncertaintyLevel::Low,
        value_of_asking_human: UncertaintyLevel::Low,
        value_of_retrieval: UncertaintyLevel::Low,
        value_of_probe: UncertaintyLevel::Medium,
        confidence_threshold: ConfidenceBand::Medium,
        selected_action: RuntimeDecisionAction::Execute,
        rationale: "next action is bounded by the runtime envelope and remains reversible enough"
            .to_string(),
        evidence_refs,
    }
}

fn cognitive_budget_for_state(state: &AgentState) -> CognitiveBudget {
    let remaining_steps = state.max_steps.saturating_sub(state.step_count).max(1);
    CognitiveBudget {
        max_reasoning_tokens: state.budget.saturating_sub(state.tokens_used),
        max_tool_calls: remaining_steps,
        max_verification_spend: remaining_steps.min(3) as u64,
        max_retries: 2u32.saturating_sub(state.consecutive_failures as u32),
        max_wall_time_ms: u64::from(remaining_steps) * 30_000,
        escalation_threshold: ConfidenceBand::Low,
        stop_threshold: if state.step_count >= state.max_steps {
            ConfidenceBand::High
        } else {
            ConfidenceBand::Low
        },
    }
}

fn strategy_decision_for_state(
    state: &AgentState,
    uncertainty: &UncertaintyAssessment,
    budget: &CognitiveBudget,
    session_id: &str,
) -> RuntimeStrategyDecision {
    let selected_strategy = match uncertainty.selected_action {
        RuntimeDecisionAction::AskHuman => "operator_intervention",
        RuntimeDecisionAction::Probe => "probe_then_repair_or_execute",
        RuntimeDecisionAction::Verify => "verify_before_completion",
        RuntimeDecisionAction::Stop => "stop_with_reason",
        RuntimeDecisionAction::DryRun => "dry_run_preview",
        RuntimeDecisionAction::Retrieve => "retrieve_then_synthesize",
        RuntimeDecisionAction::Escalate => "escalate_with_evidence",
        RuntimeDecisionAction::Execute => state
            .planner_state
            .as_ref()
            .map(|planner| match planner.status {
                crate::agentic::runtime::types::PlannerStatus::Draft
                | crate::agentic::runtime::types::PlannerStatus::Ready
                | crate::agentic::runtime::types::PlannerStatus::Running => "planned_execution",
                crate::agentic::runtime::types::PlannerStatus::Completed => "post_plan_completion",
                crate::agentic::runtime::types::PlannerStatus::Failed => "repair_failed_plan",
                crate::agentic::runtime::types::PlannerStatus::Blocked => "blocked_plan",
            })
            .unwrap_or("direct_execution"),
    };
    RuntimeStrategyDecision {
        decision_id: format!("strategy:{}:{}", session_id, state.step_count),
        task_family: state
            .resolved_intent
            .as_ref()
            .map(|intent| intent.intent_id.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        selected_strategy: selected_strategy.to_string(),
        rejected_strategies: if uncertainty.should_ask() {
            vec!["unsafe_autonomous_execution".to_string()]
        } else {
            Vec::new()
        },
        rationale: uncertainty.rationale.clone(),
        budget: budget.clone(),
        uncertainty: Some(uncertainty.clone()),
        evidence_refs: uncertainty.evidence_refs.clone(),
    }
}

fn strategy_router_for_state(
    state: &AgentState,
    task_state: &TaskStateModel,
    uncertainty: &UncertaintyAssessment,
    budget: &CognitiveBudget,
    selected_decision: &RuntimeStrategyDecision,
) -> RuntimeStrategyRouter {
    let mut candidate_strategies = vec![
        "direct_execution".to_string(),
        "planned_execution".to_string(),
        "retrieve_then_synthesize".to_string(),
        "probe_then_repair_or_execute".to_string(),
        "verify_before_completion".to_string(),
        "operator_intervention".to_string(),
        "stop_with_reason".to_string(),
    ];
    candidate_strategies.sort();
    candidate_strategies.dedup();

    RuntimeStrategyRouter {
        router_id: format!(
            "strategy-router:{}:{}",
            hex::encode(state.session_id),
            state.step_count
        ),
        task_family: selected_decision.task_family.clone(),
        candidate_strategies,
        selected_decision: selected_decision.clone(),
        decision_inputs: vec![
            format!(
                "objective_present={}",
                !task_state.current_objective.is_empty()
            ),
            format!("selected_action={:?}", uncertainty.selected_action),
            format!("remaining_tool_calls={}", budget.max_tool_calls),
            format!("consecutive_failures={}", state.consecutive_failures),
        ],
        used_task_state: true,
        used_uncertainty: true,
        used_cognitive_budget: true,
        used_drift_signal: state.pending_tool_hash.is_some()
            || state.pending_approval.is_some()
            || state.awaiting_intent_clarification,
        evidence_refs: selected_decision.evidence_refs.clone(),
    }
}

fn capability_sequence_for_state(state: &AgentState, session_id: &str) -> CapabilitySequence {
    let mut discovered: Vec<String> = state.tool_execution_log.keys().cloned().collect();
    discovered.sort();
    CapabilitySequence {
        sequence_id: format!("capability-sequence:{}:{}", session_id, state.step_count),
        discovered,
        selected: state.recent_actions.clone(),
        ordered_steps: state.recent_actions.clone(),
        retired_or_deprioritized: state
            .execution_ledger
            .attempts
            .iter()
            .filter_map(|attempt| attempt.error_class.clone())
            .collect(),
        rationale: "projected from runtime tool log and recent action order".to_string(),
        evidence_refs: vec![EvidenceRef::new(
            "tool_execution_log",
            format!("{} entries", state.tool_execution_log.len()),
        )],
    }
}

fn capability_discovery_for_state(
    state: &AgentState,
    sequence: &CapabilitySequence,
) -> CapabilityDiscovery {
    CapabilityDiscovery {
        discovery_id: format!(
            "capability-discovery:{}:{}",
            hex::encode(state.session_id),
            state.step_count
        ),
        discovered_capabilities: sequence.discovered.clone(),
        unavailable_capabilities: Vec::new(),
        evidence_refs: sequence.evidence_refs.clone(),
    }
}

fn capability_selection_for_state(
    state: &AgentState,
    sequence: &CapabilitySequence,
) -> CapabilitySelection {
    CapabilitySelection {
        selection_id: format!(
            "capability-selection:{}:{}",
            hex::encode(state.session_id),
            state.step_count
        ),
        selected_capabilities: sequence.selected.clone(),
        rejected_capabilities: Vec::new(),
        rationale: if sequence.selected.is_empty() {
            "no tool capability has been selected for the current step yet".to_string()
        } else {
            "selected from recent runtime actions under the current strategy".to_string()
        },
        evidence_refs: sequence.evidence_refs.clone(),
    }
}

fn capability_sequencing_for_state(
    state: &AgentState,
    sequence: &CapabilitySequence,
) -> CapabilitySequencing {
    CapabilitySequencing {
        sequencing_id: format!(
            "capability-sequencing:{}:{}",
            hex::encode(state.session_id),
            state.step_count
        ),
        ordered_steps: sequence.ordered_steps.clone(),
        dependency_notes: state
            .planner_state
            .as_ref()
            .map(|planner| vec![format!("planner_status={:?}", planner.status)])
            .unwrap_or_default(),
        evidence_refs: sequence.evidence_refs.clone(),
    }
}

fn capability_retirement_for_state(
    state: &AgentState,
    sequence: &CapabilitySequence,
) -> CapabilityRetirement {
    CapabilityRetirement {
        retirement_id: format!(
            "capability-retirement:{}:{}",
            hex::encode(state.session_id),
            state.step_count
        ),
        retired_or_deprioritized: sequence.retired_or_deprioritized.clone(),
        retry_conditions: if state.consecutive_failures > 0 {
            vec!["retry only after a narrower probe or verifier updates confidence".to_string()]
        } else {
            Vec::new()
        },
        evidence_refs: sequence.evidence_refs.clone(),
    }
}

fn probes_for_state(state: &AgentState, uncertainty: &UncertaintyAssessment) -> Vec<Probe> {
    if !uncertainty.should_probe() {
        return Vec::new();
    }

    vec![Probe {
        probe_id: format!(
            "probe:{}:{}",
            hex::encode(state.session_id),
            state.step_count
        ),
        hypothesis: if state.consecutive_failures > 0 {
            "previous failure is recoverable with a narrower validation step".to_string()
        } else {
            "postcondition status can be resolved with cheap verification".to_string()
        },
        cheapest_validation_action:
            "inspect the execution ledger and run the smallest mapped verification".to_string(),
        expected_observation: "a passed, failed, or still-unknown postcondition receipt"
            .to_string(),
        cost_bound: "one read-only inspection or one targeted verifier".to_string(),
        result: ProbeResultStatus::Pending,
        confidence_update: "pending".to_string(),
        next_action: RuntimeDecisionAction::Verify,
        evidence_refs: uncertainty.evidence_refs.clone(),
    }]
}

fn postcondition_synthesizer_for_state(
    state: &AgentState,
    postconditions: &PostconditionSynthesis,
    session_id: &str,
) -> PostconditionSynthesizer {
    PostconditionSynthesizer {
        synthesizer_id: format!(
            "postcondition-synthesizer:{}:{}",
            session_id, state.step_count
        ),
        objective: state.goal.clone(),
        inferred_task_family: postconditions.task_family.clone(),
        synthesized: postconditions.clone(),
        rationale:
            "derived minimum evidence from execution ledger success conditions and terminal status"
                .to_string(),
        evidence_refs: vec![EvidenceRef::new(
            "execution_ledger",
            format!("{} attempts", state.execution_ledger.attempts.len()),
        )],
    }
}

fn semantic_impact_for_state(state: &AgentState) -> SemanticImpactAnalysis {
    let mut impact = SemanticImpactAnalysis::default();
    let mut changed_symbols = BTreeSet::new();
    let mut changed_apis = BTreeSet::new();
    let mut changed_schemas = BTreeSet::new();
    let mut changed_policies = BTreeSet::new();
    let mut affected_call_sites = BTreeSet::new();
    let mut affected_tests = BTreeSet::new();
    let mut affected_docs = BTreeSet::new();
    let mut generated_files_needing_refresh = BTreeSet::new();
    let mut migration_implications = BTreeSet::new();
    let mut unknowns = BTreeSet::new();

    let path_impacts = semantic_impact_paths_from_log(state);
    for observed in &path_impacts {
        if !observed.mutating {
            continue;
        }
        classify_changed_path_for_semantic_impact(
            &observed.path,
            &mut changed_symbols,
            &mut changed_apis,
            &mut changed_schemas,
            &mut changed_policies,
            &mut affected_call_sites,
            &mut affected_tests,
            &mut affected_docs,
            &mut generated_files_needing_refresh,
            &mut migration_implications,
            &mut unknowns,
        );
        impact.evidence_refs.push(EvidenceRef::new(
            "semantic_impact_path",
            format!(
                "{}:{}:{}",
                observed.evidence_key, observed.tool_name, observed.path
            ),
        ));
    }

    for (tool_name, status) in &state.tool_execution_log {
        let effective_tool_name = match status {
            ToolCallStatus::Executed(value) => {
                parse_receipt_tool(value).unwrap_or_else(|| normalize_tool_log_key(tool_name))
            }
            _ => normalize_tool_log_key(tool_name),
        };

        if is_mutating_file_tool(&effective_tool_name)
            && !path_impacts
                .iter()
                .any(|impact| impact.evidence_key == *tool_name && impact.mutating)
        {
            changed_symbols.insert("filesystem_object".to_string());
            affected_tests.insert(
                "targeted tests should be selected after recovering changed path metadata"
                    .to_string(),
            );
            unknowns.insert(format!(
                "mutating file tool lacks changed-path metadata: {effective_tool_name}"
            ));
        }

        if effective_tool_name.starts_with("connector__")
            || effective_tool_name.starts_with("memory__")
        {
            changed_schemas.insert("external_or_memory_state".to_string());
            affected_tests.insert(format!(
                "verify connector or memory contract touched by {effective_tool_name}"
            ));
        }

        if effective_tool_name.starts_with("shell__")
            || effective_tool_name == "software_install__execute_plan"
        {
            migration_implications
                .insert("host command may have changed local environment".to_string());
            if matches!(status, ToolCallStatus::Executed(_)) {
                affected_tests
                    .insert("rerun command-specific verification from shell receipt".to_string());
            } else {
                unknowns.insert(format!(
                    "shell/software install tool lacks execution receipt details: {effective_tool_name}"
                ));
            }
        }
    }

    impact.changed_symbols = changed_symbols.into_iter().collect();
    impact.changed_apis = changed_apis.into_iter().collect();
    impact.changed_schemas = changed_schemas.into_iter().collect();
    impact.changed_policies = changed_policies.into_iter().collect();
    impact.affected_call_sites = affected_call_sites.into_iter().collect();
    impact.affected_tests = affected_tests.into_iter().collect();
    impact.affected_docs = affected_docs.into_iter().collect();
    impact.generated_files_needing_refresh = generated_files_needing_refresh.into_iter().collect();
    impact.migration_implications = migration_implications.into_iter().collect();
    impact.unknowns = unknowns.into_iter().collect();

    impact.risk_class = if impact.changed_symbols.is_empty()
        && impact.changed_apis.is_empty()
        && impact.changed_schemas.is_empty()
        && impact.changed_policies.is_empty()
        && impact.affected_call_sites.is_empty()
        && impact.affected_docs.is_empty()
        && impact.generated_files_needing_refresh.is_empty()
        && impact.migration_implications.is_empty()
    {
        "none_observed".to_string()
    } else if !impact.changed_policies.is_empty() {
        "requires_independent_verification".to_string()
    } else {
        "requires_targeted_verification".to_string()
    };
    impact.evidence_refs.push(EvidenceRef::new(
        "tool_execution_log",
        format!("{} entries", state.tool_execution_log.len()),
    ));
    if impact.risk_class == "none_observed" && !state.tool_execution_log.is_empty() {
        impact
            .unknowns
            .push("tool log lacks object-level diff metadata".to_string());
    }
    impact
}

#[derive(Debug, Clone)]
struct SemanticImpactPathObservation {
    path: String,
    tool_name: String,
    evidence_key: String,
    mutating: bool,
}

fn semantic_impact_paths_from_log(state: &AgentState) -> Vec<SemanticImpactPathObservation> {
    let mut observed = Vec::new();
    let mut seen = BTreeSet::new();

    for (key, status) in &state.tool_execution_log {
        let ToolCallStatus::Executed(value) = status else {
            continue;
        };

        if let Ok(receipt) = serde_json::from_str::<StructuredWorkspaceFileObservation>(value) {
            push_semantic_impact_path(
                &mut observed,
                &mut seen,
                key,
                &receipt.tool_name,
                &receipt.requested_path,
            );
            continue;
        }

        if let Some(path) = parse_receipt_path(value) {
            let tool_name =
                parse_receipt_tool(value).unwrap_or_else(|| normalize_tool_log_key(key));
            push_semantic_impact_path(&mut observed, &mut seen, key, &tool_name, &path);
        }
    }

    observed
}

fn push_semantic_impact_path(
    observed: &mut Vec<SemanticImpactPathObservation>,
    seen: &mut BTreeSet<(String, String, String)>,
    evidence_key: &str,
    tool_name: &str,
    path: &str,
) {
    let path = path.trim();
    if path.is_empty() {
        return;
    }
    let tool_name = normalize_tool_log_key(tool_name);
    let mutating = is_mutating_file_tool(&tool_name)
        || evidence_key == "evidence::workspace_edit_applied=true"
        || evidence_key.starts_with("evidence::workspace_write")
        || evidence_key.starts_with("evidence::workspace_patch");
    let dedupe_key = (
        evidence_key.to_string(),
        tool_name.clone(),
        path.to_string(),
    );
    if !seen.insert(dedupe_key) {
        return;
    }
    observed.push(SemanticImpactPathObservation {
        path: path.to_string(),
        tool_name,
        evidence_key: evidence_key.to_string(),
        mutating,
    });
}

#[allow(clippy::too_many_arguments)]
fn classify_changed_path_for_semantic_impact(
    path: &str,
    changed_symbols: &mut BTreeSet<String>,
    changed_apis: &mut BTreeSet<String>,
    changed_schemas: &mut BTreeSet<String>,
    changed_policies: &mut BTreeSet<String>,
    affected_call_sites: &mut BTreeSet<String>,
    affected_tests: &mut BTreeSet<String>,
    affected_docs: &mut BTreeSet<String>,
    generated_files_needing_refresh: &mut BTreeSet<String>,
    migration_implications: &mut BTreeSet<String>,
    unknowns: &mut BTreeSet<String>,
) {
    let normalized = path.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let file_name = std::path::Path::new(&normalized)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&normalized);
    let stem = std::path::Path::new(file_name)
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or(file_name)
        .trim();
    let extension = std::path::Path::new(file_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if is_source_path(&lower, &extension) {
        if !stem.is_empty() {
            changed_symbols.insert(stem.to_string());
            affected_call_sites.insert(format!("call sites importing or invoking {stem}"));
        }
        affected_tests.insert(test_selection_hint_for_path(&normalized, &extension));
        if is_public_api_path(&lower, file_name) {
            changed_apis.insert(normalized.clone());
        }
    }

    if is_test_path(&lower) {
        affected_tests.insert(format!("direct changed test file: {normalized}"));
    }

    if is_schema_or_manifest_path(&lower, file_name, &extension) {
        changed_schemas.insert(normalized.clone());
        affected_tests.insert(format!(
            "contract/schema validation for changed manifest or schema: {normalized}"
        ));
    }

    if is_policy_path(&lower) {
        changed_policies.insert(normalized.clone());
        affected_tests.insert(format!("policy/security regression tests for {normalized}"));
    }

    if is_docs_path(&lower, &extension) {
        affected_docs.insert(normalized.clone());
    }

    if is_generated_path(&lower, file_name) {
        generated_files_needing_refresh.insert(normalized.clone());
        migration_implications.insert(format!(
            "generated or lock artifact changed; verify producer command for {normalized}"
        ));
    }

    if is_migration_path(&lower, file_name, &extension) {
        migration_implications.insert(format!("migration/dependency implication: {normalized}"));
    }

    let categorized = is_source_path(&lower, &extension)
        || is_test_path(&lower)
        || is_schema_or_manifest_path(&lower, file_name, &extension)
        || is_policy_path(&lower)
        || is_docs_path(&lower, &extension)
        || is_generated_path(&lower, file_name)
        || is_migration_path(&lower, file_name, &extension);
    if !categorized {
        changed_symbols.insert("filesystem_object".to_string());
        unknowns.insert(format!(
            "changed path has no semantic category; inspect manually: {normalized}"
        ));
    }
}

fn normalize_tool_log_key(value: &str) -> String {
    value
        .split_once(':')
        .map(|(head, _)| head)
        .unwrap_or(value)
        .trim()
        .to_string()
}

fn is_mutating_file_tool(tool_name: &str) -> bool {
    tool_name.starts_with("file__")
        && !matches!(
            tool_name,
            "file__read"
                | "file__view"
                | "file__list"
                | "file__search"
                | "file__info"
                | "file__stat"
                | "file__diff"
                | "file__history"
                | "file__validate_observation"
        )
}

fn is_source_path(lower: &str, extension: &str) -> bool {
    matches!(
        extension,
        "rs" | "ts"
            | "tsx"
            | "js"
            | "jsx"
            | "py"
            | "go"
            | "java"
            | "kt"
            | "swift"
            | "c"
            | "cc"
            | "cpp"
            | "h"
            | "hpp"
    ) && !is_test_path(lower)
}

fn is_test_path(lower: &str) -> bool {
    lower.starts_with("tests/")
        || lower.contains("/tests/")
        || lower.ends_with("_test.py")
        || lower.ends_with("_test.rs")
        || lower.ends_with(".spec.ts")
        || lower.ends_with(".spec.tsx")
        || lower.ends_with(".test.ts")
        || lower.ends_with(".test.tsx")
        || lower.ends_with(".test.js")
        || lower.ends_with(".test.jsx")
}

fn is_public_api_path(lower: &str, file_name: &str) -> bool {
    matches!(file_name, "lib.rs" | "mod.rs" | "main.rs")
        || lower.contains("/api/")
        || lower.contains("/types/")
        || lower.contains("/contracts/")
        || lower.contains("/runtime_contracts")
        || lower.contains("/workflow")
        || lower.contains("/connector")
}

fn is_schema_or_manifest_path(lower: &str, file_name: &str, extension: &str) -> bool {
    matches!(
        file_name,
        "Cargo.toml"
            | "Cargo.lock"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "tsconfig.json"
    ) || matches!(
        extension,
        "json" | "toml" | "yaml" | "yml" | "proto" | "graphql" | "sql"
    ) || lower.contains("/schema/")
        || lower.contains("/schemas/")
        || lower.contains("schema.")
}

fn is_policy_path(lower: &str) -> bool {
    lower.contains("policy")
        || lower.contains("permission")
        || lower.contains("approval")
        || lower.contains("firewall")
        || lower.contains("security")
        || lower.contains("sandbox")
        || lower.contains("authority")
}

fn is_docs_path(lower: &str, extension: &str) -> bool {
    matches!(extension, "md" | "mdx" | "rst" | "adoc") || lower.starts_with("docs/")
}

fn is_generated_path(lower: &str, file_name: &str) -> bool {
    matches!(
        file_name,
        "Cargo.lock" | "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock"
    ) || lower.contains("/generated/")
        || lower.contains("/gen/")
        || lower.contains("/dist/")
        || lower.contains("/target/")
        || lower.ends_with(".tsbuildinfo")
}

fn is_migration_path(lower: &str, file_name: &str, extension: &str) -> bool {
    matches!(
        file_name,
        "Cargo.toml" | "package.json" | "Dockerfile" | "docker-compose.yml"
    ) || lower.contains("/migrations/")
        || extension == "sql"
}

fn test_selection_hint_for_path(path: &str, extension: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if extension == "rs" {
        if let Some(crate_name) = path
            .strip_prefix("crates/")
            .and_then(|rest| rest.split('/').next())
        {
            return format!("targeted Rust tests for crate path crates/{crate_name}");
        }
        return "targeted Rust tests for changed module".to_string();
    }
    if matches!(extension, "ts" | "tsx" | "js" | "jsx") {
        if lower.starts_with("apps/") || lower.starts_with("packages/") {
            return format!("targeted TypeScript tests for package path {path}");
        }
        return "targeted TypeScript/JavaScript tests for changed module".to_string();
    }
    if extension == "py" {
        return "targeted Python tests for changed module".to_string();
    }
    format!("targeted tests for changed source path {path}")
}

fn drift_signal_for_state(state: &AgentState) -> DriftSignal {
    DriftSignal {
        plan_drift: state
            .planner_state
            .as_ref()
            .map(|planner| {
                planner.status == crate::agentic::runtime::types::PlannerStatus::Failed
                    || planner.status == crate::agentic::runtime::types::PlannerStatus::Blocked
            })
            .unwrap_or(false),
        file_drift: state.pending_tool_hash.is_some() && state.pending_approval.is_none(),
        branch_drift: false,
        connector_auth_drift: state
            .tool_execution_log
            .keys()
            .any(|tool| tool.starts_with("connector__"))
            && state.consecutive_failures > 0,
        external_conversation_drift: state.awaiting_intent_clarification,
        requirement_drift: state.pending_search_completion.is_some(),
        policy_drift: state.pending_approval.is_some(),
        model_availability_drift: false,
        projection_state_drift: state.pending_tool_call.is_some()
            && state.pending_tool_jcs.is_none(),
        evidence_refs: vec![EvidenceRef::new(
            "runtime_state",
            format!("step:{}", state.step_count),
        )],
    }
}

fn handoff_quality_for_state(state: &AgentState) -> Option<HandoffQuality> {
    if state.child_session_ids.is_empty() && state.parent_session_id.is_none() {
        return None;
    }

    Some(HandoffQuality {
        objective_preserved: !state.goal.trim().is_empty(),
        current_state_included: true,
        blockers_included: state.pause_reason().is_none()
            || matches!(
                state.pause_reason(),
                Some(
                    AgentPauseReason::WaitingForApproval
                        | AgentPauseReason::WaitingForHumanApproval
                        | AgentPauseReason::WaitingForIntentClarification
                        | AgentPauseReason::WaitingForTargetClarification
                        | AgentPauseReason::WaitingForSudoPassword
                )
            ),
        evidence_refs_included: !state.tool_execution_log.is_empty()
            || state.execution_ledger.has_verification_evidence(),
        receiver_succeeded: matches!(state.status, AgentStatus::Completed(_)),
        human_reconstruction_required: false,
    })
}

fn verifier_independence_policy_for_state(
    state: &AgentState,
    semantic_impact: &SemanticImpactAnalysis,
    postconditions: &PostconditionSynthesis,
) -> VerifierIndependencePolicy {
    let high_risk = semantic_impact.risk_class == "requires_independent_verification"
        || !semantic_impact.changed_policies.is_empty()
        || state.pending_approval.is_some()
        || matches!(
            state.pause_reason(),
            Some(
                AgentPauseReason::WaitingForApproval
                    | AgentPauseReason::WaitingForHumanApproval
                    | AgentPauseReason::WaitingForSudoPassword
            )
        );
    let has_unproven_required_checks = postconditions.checks.iter().any(|check| {
        matches!(
            check.status,
            RuntimeCheckStatus::Required | RuntimeCheckStatus::Unknown | RuntimeCheckStatus::Failed
        )
    });
    let verifier_may_need_probe = high_risk
        || has_unproven_required_checks
        || !semantic_impact.unknowns.is_empty()
        || state.consecutive_failures > 0;

    VerifierIndependencePolicy {
        same_model_allowed: !high_risk,
        same_context_allowed: !high_risk && semantic_impact.unknowns.is_empty(),
        evidence_only_mode: true,
        adversarial_review_required: high_risk || !semantic_impact.changed_policies.is_empty(),
        human_review_threshold: if high_risk {
            "policy_or_destructive_or_sensitive_change".to_string()
        } else if has_unproven_required_checks {
            "unproven_postconditions".to_string()
        } else {
            "high_risk".to_string()
        },
        verifier_can_request_probes: verifier_may_need_probe,
        failure_creates_repair_task: true,
    }
}

fn default_dry_run_capabilities() -> Vec<DryRunCapability> {
    vec![
        DryRunCapability {
            capability_id: "dry_run:file_patch".to_string(),
            supported_tool_classes: vec![
                "file__write".to_string(),
                "file__edit".to_string(),
                "file__multi_edit".to_string(),
            ],
            side_effect_preview: true,
            policy_preview: true,
            output_artifact: Some("diff_preview".to_string()),
            limitations: vec!["does not prove generated code behavior".to_string()],
        },
        DryRunCapability {
            capability_id: "dry_run:shell_command".to_string(),
            supported_tool_classes: vec![
                "shell__run".to_string(),
                "shell__start".to_string(),
                "software_install__execute_plan".to_string(),
            ],
            side_effect_preview: true,
            policy_preview: true,
            output_artifact: Some("risk_preview".to_string()),
            limitations: vec!["cannot simulate every command side effect".to_string()],
        },
        DryRunCapability {
            capability_id: "dry_run:connector_action".to_string(),
            supported_tool_classes: vec![
                "connector__*".to_string(),
                "commerce__checkout".to_string(),
            ],
            side_effect_preview: true,
            policy_preview: true,
            output_artifact: Some("connector_preview_receipt".to_string()),
            limitations: vec!["live provider state can drift after preview".to_string()],
        },
        DryRunCapability {
            capability_id: "dry_run:policy_decision".to_string(),
            supported_tool_classes: vec![
                "policy__evaluate".to_string(),
                "approval__request".to_string(),
                "firewall__decide".to_string(),
            ],
            side_effect_preview: false,
            policy_preview: true,
            output_artifact: Some("policy_preview_receipt".to_string()),
            limitations: vec!["preview does not grant approval or persist authority".to_string()],
        },
        DryRunCapability {
            capability_id: "dry_run:workflow_side_effect".to_string(),
            supported_tool_classes: vec![
                "workflow.node.dry_run".to_string(),
                "workflow.function.dry_run".to_string(),
                "workflow__execute".to_string(),
            ],
            side_effect_preview: true,
            policy_preview: true,
            output_artifact: Some("workflow_dry_run_bundle".to_string()),
            limitations: vec!["mocked connectors can differ from live provider state".to_string()],
        },
        DryRunCapability {
            capability_id: "dry_run:external_order_or_cart".to_string(),
            supported_tool_classes: vec![
                "commerce__cart".to_string(),
                "commerce__checkout".to_string(),
                "order__submit".to_string(),
            ],
            side_effect_preview: true,
            policy_preview: true,
            output_artifact: Some("external_action_preview_receipt".to_string()),
            limitations: vec!["provider pricing and inventory can drift after preview".to_string()],
        },
    ]
}

fn workflow_envelope_adapter_for_surface(surface: RuntimeSurface) -> WorkflowEnvelopeAdapter {
    WorkflowEnvelopeAdapter {
        workflow_surface: RuntimeSurface::Workflow,
        target_surface: surface,
        evidence_refs: vec![EvidenceRef {
            kind: "runtime_substrate_port".to_string(),
            reference: "RuntimeSubstratePortContract".to_string(),
            summary: "workflow execution maps into the public runtime envelope".to_string(),
        }],
        ..WorkflowEnvelopeAdapter::default()
    }
}

fn harness_trace_adapter_for_surface(surface: RuntimeSurface) -> HarnessTraceAdapter {
    HarnessTraceAdapter {
        fixture_scope: match surface {
            RuntimeSurface::Harness | RuntimeSurface::Benchmark => {
                "validation_trace_and_scorecard".to_string()
            }
            _ => "runtime_trace_projection".to_string(),
        },
        evidence_refs: vec![EvidenceRef {
            kind: "runtime_trace".to_string(),
            reference: "exported_trace_bundle".to_string(),
            summary: "harness validation consumes exported substrate evidence".to_string(),
        }],
        ..HarnessTraceAdapter::default()
    }
}

fn operator_interruption_contract_for_state(state: &AgentState) -> OperatorInterruptionContract {
    OperatorInterruptionContract {
        evidence_refs: vec![EvidenceRef {
            kind: "agent_status".to_string(),
            reference: format!("agent_state:{}", hex::encode(state.session_id)),
            summary: format!("status:{:?};pause:{:?}", state.status, state.pause_reason()),
        }],
        ..OperatorInterruptionContract::default()
    }
}

fn postconditions_for_state(
    state: &AgentState,
    semantic_impact: &SemanticImpactAnalysis,
) -> PostconditionSynthesis {
    let mut checks = Vec::new();
    let mut minimum_evidence = Vec::new();
    let mut unknowns = Vec::new();
    for attempt in &state.execution_ledger.attempts {
        for (key, value) in &attempt.success_conditions {
            minimum_evidence.push(key.clone());
            let passed = !value.trim().is_empty()
                && attempt.status == ExecutionAttemptStatus::Succeeded
                && attempt.completion_gate_missing.is_empty();
            checks.push(PostconditionCheck {
                check_id: format!("attempt:{}:{}", attempt.attempt_id, key),
                description: value.clone(),
                required_evidence: vec![key.clone()],
                mapped_tools: Vec::new(),
                receipt_refs: vec![EvidenceRef {
                    kind: "execution_attempt".to_string(),
                    reference: attempt.attempt_id.to_string(),
                    summary: format!("stage:{:?};status:{:?}", attempt.stage, attempt.status),
                }],
                status: if passed {
                    RuntimeCheckStatus::Passed
                } else {
                    RuntimeCheckStatus::Unknown
                },
            });
        }
    }

    add_semantic_impact_postconditions(
        state,
        semantic_impact,
        &mut checks,
        &mut minimum_evidence,
        &mut unknowns,
    );

    PostconditionSynthesis {
        objective: state.goal.clone(),
        task_family: state
            .resolved_intent
            .as_ref()
            .map(|intent| intent.intent_id.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        risk_class: "runtime_state_projection".to_string(),
        checks,
        minimum_evidence,
        unknowns,
        ..PostconditionSynthesis::default()
    }
}

fn add_semantic_impact_postconditions(
    state: &AgentState,
    semantic_impact: &SemanticImpactAnalysis,
    checks: &mut Vec<PostconditionCheck>,
    minimum_evidence: &mut Vec<String>,
    unknowns: &mut Vec<String>,
) {
    let has_verification = state.execution_ledger.has_verification_evidence();
    let mut push_check = |check_id: &str,
                          description: String,
                          required_evidence: Vec<String>,
                          mapped_tools: Vec<String>,
                          status: RuntimeCheckStatus| {
        for evidence in &required_evidence {
            if !minimum_evidence.contains(evidence) {
                minimum_evidence.push(evidence.clone());
            }
        }
        checks.push(PostconditionCheck {
            check_id: check_id.to_string(),
            description,
            required_evidence,
            mapped_tools,
            receipt_refs: semantic_impact.evidence_refs.clone(),
            status,
        });
    };

    if !semantic_impact.changed_symbols.is_empty() || !semantic_impact.changed_apis.is_empty() {
        push_check(
            "semantic_impact:code_api",
            format!(
                "Verify changed code/API impact: symbols={:?}; apis={:?}",
                semantic_impact.changed_symbols, semantic_impact.changed_apis
            ),
            vec![
                "SemanticImpactAnalysis.changed_symbols".to_string(),
                "targeted_test_or_verifier_receipt".to_string(),
            ],
            semantic_impact.affected_tests.clone(),
            if has_verification {
                RuntimeCheckStatus::Passed
            } else {
                RuntimeCheckStatus::Unknown
            },
        );
    }

    if !semantic_impact.changed_schemas.is_empty() {
        push_check(
            "semantic_impact:schema",
            format!(
                "Verify schema/manifest compatibility for {:?}",
                semantic_impact.changed_schemas
            ),
            vec![
                "SemanticImpactAnalysis.changed_schemas".to_string(),
                "schema_or_contract_validation_receipt".to_string(),
            ],
            semantic_impact.affected_tests.clone(),
            if has_verification {
                RuntimeCheckStatus::Passed
            } else {
                RuntimeCheckStatus::Unknown
            },
        );
    }

    if !semantic_impact.changed_policies.is_empty() {
        push_check(
            "semantic_impact:policy",
            format!(
                "Run independent policy/security verification for {:?}",
                semantic_impact.changed_policies
            ),
            vec![
                "SemanticImpactAnalysis.changed_policies".to_string(),
                "independent_policy_verifier_receipt".to_string(),
            ],
            semantic_impact.affected_tests.clone(),
            if has_verification {
                RuntimeCheckStatus::Passed
            } else {
                RuntimeCheckStatus::Unknown
            },
        );
    }

    if !semantic_impact.affected_docs.is_empty() {
        push_check(
            "semantic_impact:docs",
            format!(
                "Confirm documentation impact is intentional for {:?}",
                semantic_impact.affected_docs
            ),
            vec!["SemanticImpactAnalysis.affected_docs".to_string()],
            Vec::new(),
            RuntimeCheckStatus::Required,
        );
    }

    if !semantic_impact.generated_files_needing_refresh.is_empty() {
        push_check(
            "semantic_impact:generated",
            format!(
                "Verify generated artifacts were refreshed by their producer: {:?}",
                semantic_impact.generated_files_needing_refresh
            ),
            vec![
                "SemanticImpactAnalysis.generated_files_needing_refresh".to_string(),
                "producer_command_receipt".to_string(),
            ],
            semantic_impact.affected_tests.clone(),
            if has_verification {
                RuntimeCheckStatus::Passed
            } else {
                RuntimeCheckStatus::Unknown
            },
        );
    }

    if !semantic_impact.migration_implications.is_empty()
        && (!semantic_impact.changed_schemas.is_empty()
            || !semantic_impact.generated_files_needing_refresh.is_empty())
    {
        push_check(
            "semantic_impact:migration",
            format!(
                "Review migration/dependency implications: {:?}",
                semantic_impact.migration_implications
            ),
            vec!["SemanticImpactAnalysis.migration_implications".to_string()],
            semantic_impact.affected_tests.clone(),
            if has_verification {
                RuntimeCheckStatus::Passed
            } else {
                RuntimeCheckStatus::Unknown
            },
        );
    }

    for unknown in &semantic_impact.unknowns {
        unknowns.push(unknown.clone());
    }
    if !semantic_impact.unknowns.is_empty() {
        push_check(
            "semantic_impact:unknowns",
            "Resolve semantic-impact unknowns before claiming broad safety".to_string(),
            vec!["SemanticImpactAnalysis.unknowns".to_string()],
            Vec::new(),
            RuntimeCheckStatus::Unknown,
        );
    }
}

fn quality_ledger_for_state(
    state: &AgentState,
    stop_condition: &StopConditionRecord,
    semantic_impact: &SemanticImpactAnalysis,
    promotion_decision: Option<BoundedSelfImprovementGate>,
) -> AgentQualityLedger {
    let mut scorecard_metrics = BTreeMap::new();
    scorecard_metrics.insert("step_count".to_string(), state.step_count);
    scorecard_metrics.insert(
        "consecutive_failures".to_string(),
        state.consecutive_failures as u32,
    );
    scorecard_metrics.insert(
        "tool_count".to_string(),
        state.tool_execution_log.len() as u32,
    );
    scorecard_metrics.insert(
        "semantic_changed_symbols".to_string(),
        semantic_impact.changed_symbols.len() as u32,
    );
    scorecard_metrics.insert(
        "semantic_changed_apis".to_string(),
        semantic_impact.changed_apis.len() as u32,
    );
    scorecard_metrics.insert(
        "semantic_changed_schemas".to_string(),
        semantic_impact.changed_schemas.len() as u32,
    );
    scorecard_metrics.insert(
        "semantic_changed_policies".to_string(),
        semantic_impact.changed_policies.len() as u32,
    );
    scorecard_metrics.insert(
        "semantic_unknowns".to_string(),
        semantic_impact.unknowns.len() as u32,
    );
    AgentQualityLedger {
        ledger_id: format!("agent-quality:{}", hex::encode(state.session_id)),
        session_id: hex::encode(state.session_id),
        task_family: state
            .resolved_intent
            .as_ref()
            .map(|intent| intent.intent_id.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        selected_strategy: state
            .planner_state
            .as_ref()
            .map(|plan| format!("{:?}", plan.status))
            .unwrap_or_else(|| "direct_or_unplanned".to_string()),
        model_roles: Vec::new(),
        tool_sequence: state.recent_actions.clone(),
        scorecard_metrics,
        failure_ontology_labels: state
            .execution_ledger
            .attempts
            .iter()
            .filter_map(|attempt| attempt.error_class.clone())
            .collect(),
        cost_units: state.budget.saturating_sub(state.tokens_used),
        latency_ms: 0,
        stop_condition: Some(stop_condition.clone()),
        promotion_decision,
    }
}

fn task_family_playbook_for_state(state: &AgentState) -> TaskFamilyPlaybook {
    let task_class = state
        .resolved_intent
        .as_ref()
        .map(|intent| intent.intent_id.clone())
        .unwrap_or_else(|| "unknown".to_string());
    TaskFamilyPlaybook {
        task_class,
        recommended_strategy: state
            .planner_state
            .as_ref()
            .map(|_| "planned_execution_with_verification".to_string())
            .unwrap_or_else(|| "direct_execution_with_postcondition_check".to_string()),
        required_context: vec!["objective".to_string(), "policy".to_string()],
        typical_tools: state.tool_execution_log.keys().cloned().collect(),
        usual_failure_modes: state
            .execution_ledger
            .attempts
            .iter()
            .filter_map(|attempt| attempt.error_class.clone())
            .collect(),
        verification_checklist: vec![
            "stop_condition_recorded".to_string(),
            "postconditions_synthesized".to_string(),
            "quality_ledger_recorded".to_string(),
        ],
        escalation_triggers: vec![
            "policy_requires_approval".to_string(),
            "uncertainty_requires_human".to_string(),
            "repeated_failure".to_string(),
        ],
        cost_latency_profile: "bounded_by_cognitive_budget".to_string(),
        success_history: Vec::new(),
        last_validated_version: ioi_types::app::RUNTIME_CONTRACT_SCHEMA_VERSION_V1.to_string(),
    }
}

fn negative_learning_for_state(state: &AgentState) -> Vec<NegativeLearningRecord> {
    state
        .execution_ledger
        .attempts
        .iter()
        .filter_map(|attempt| {
            let failure = attempt.error_class.as_ref()?;
            Some(NegativeLearningRecord {
                task_family: attempt
                    .intent_id
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                failed_strategy_tool_or_model: failure.clone(),
                failure_evidence: vec![EvidenceRef::new(
                    "execution_attempt",
                    attempt.attempt_id.to_string(),
                )],
                decay_policy: "decay after successful retry or version change".to_string(),
                retry_conditions: vec!["probe or verifier must change confidence".to_string()],
                override_conditions: vec![
                    "operator explicitly overrides with policy approval".to_string()
                ],
            })
        })
        .collect()
}

fn memory_quality_gates_for_state(state: &AgentState) -> Vec<MemoryQualityGate> {
    let Some(intent) = &state.resolved_intent else {
        return Vec::new();
    };
    vec![MemoryQualityGate {
        memory_id: format!("intent-memory:{}", intent.intent_id),
        relevance: ConfidenceBand::High,
        freshness: ConfidenceBand::Medium,
        contradiction_status: "not_checked_in_snapshot".to_string(),
        outcome_impact: "intent resolver context".to_string(),
        writeback_eligible: false,
        prompt_eligible: true,
        expiry_policy: "session_scoped".to_string(),
        evidence_refs: vec![EvidenceRef::new(
            "intent_hash",
            hex::encode(intent.evidence_requirements_hash),
        )],
    }]
}

fn operator_preference_for_state(state: &AgentState) -> Option<OperatorPreference> {
    if state.goal.trim().is_empty() {
        return None;
    }
    Some(OperatorPreference {
        preference_id: format!("operator-preference:{}", hex::encode(state.session_id)),
        preferred_autonomy_level: if state.pending_approval.is_some() {
            "approval_required_for_current_action".to_string()
        } else {
            "bounded_autonomy".to_string()
        },
        preferred_verbosity: "concise_with_optional_evidence".to_string(),
        preferred_approval_style: "ask_when_policy_or_uncertainty_requires".to_string(),
        preferred_risk_tolerance: "low_for_destructive_actions".to_string(),
        preferred_code_style: "repo_local_patterns".to_string(),
        preferred_testing_depth: "risk_scaled".to_string(),
        preferred_connector_behavior: "least_privilege".to_string(),
        confidence: ConfidenceBand::Medium,
        source: "runtime_default_policy".to_string(),
        last_confirmed_ms: 0,
    })
}

fn bounded_self_improvement_gate_for_state(
    state: &AgentState,
) -> Option<BoundedSelfImprovementGate> {
    let has_recovery_or_skill_mutation = state.active_skill_hash.is_some()
        && state
            .execution_ledger
            .attempts
            .iter()
            .any(|attempt| attempt.error_class.is_some());
    if !has_recovery_or_skill_mutation {
        return None;
    }
    Some(BoundedSelfImprovementGate {
        source_trace_hash: "runtime_trace_required_before_promotion".to_string(),
        mutation_type: "recovery_skill_candidate".to_string(),
        allowed_surface: "runtime_optimizer".to_string(),
        validation_slice: "targeted_recovery_regression".to_string(),
        protected_holdout_summary: "required_before_promotion".to_string(),
        cross_model_or_profile_regression_check: "required_before_promotion".to_string(),
        complexity_budget: "bounded".to_string(),
        rollback_ref: "skill_previous_version".to_string(),
        policy_decision: "review_required".to_string(),
    })
}

fn stop_condition_for_state(state: &AgentState) -> StopConditionRecord {
    match &state.status {
        AgentStatus::Completed(_) => StopConditionRecord {
            reason: StopReason::ObjectiveSatisfied,
            evidence_sufficient: state.execution_ledger.has_verification_evidence()
                || state
                    .execution_ledger
                    .attempts
                    .iter()
                    .any(|attempt| attempt.status == ExecutionAttemptStatus::Succeeded),
            rationale: "runtime session completed".to_string(),
            evidence_refs: vec![EvidenceRef::new(
                "agent_status",
                format!("completed:{}", hex::encode(state.session_id)),
            )],
        },
        AgentStatus::Failed(reason) => StopConditionRecord {
            reason: StopReason::RepeatedFailure,
            evidence_sufficient: false,
            rationale: reason.clone(),
            evidence_refs: vec![EvidenceRef::new(
                "agent_status",
                format!("failed:{}", hex::encode(state.session_id)),
            )],
        },
        AgentStatus::Paused(reason) => StopConditionRecord {
            reason: match state.pause_reason() {
                Some(
                    AgentPauseReason::WaitingForApproval
                    | AgentPauseReason::WaitingForHumanApproval,
                ) => StopReason::PolicyPreventsProgress,
                Some(
                    AgentPauseReason::WaitingForIntentClarification
                    | AgentPauseReason::WaitingForTargetClarification
                    | AgentPauseReason::WaitingForSudoPassword,
                ) => StopReason::UncertaintyRequiresHuman,
                _ => StopReason::ExternalDependencyBlocked,
            },
            evidence_sufficient: false,
            rationale: reason.clone(),
            evidence_refs: vec![EvidenceRef::new(
                "agent_status",
                format!("paused:{}", hex::encode(state.session_id)),
            )],
        },
        AgentStatus::Running | AgentStatus::Idle => StopConditionRecord {
            reason: StopReason::Unknown,
            evidence_sufficient: false,
            rationale: "runtime session is not terminal".to_string(),
            evidence_refs: Vec::new(),
        },
        AgentStatus::Terminated => StopConditionRecord {
            reason: StopReason::ExternalDependencyBlocked,
            evidence_sufficient: false,
            rationale: "runtime session terminated".to_string(),
            evidence_refs: vec![EvidenceRef::new(
                "agent_status",
                format!("terminated:{}", hex::encode(state.session_id)),
            )],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::types::{
        AgentMode, ExecutionLedger, ExecutionStage, ExecutionTier, ToolCallStatus,
    };
    use std::collections::{BTreeMap, VecDeque};

    fn test_agent_state(status: AgentStatus) -> AgentState {
        AgentState {
            session_id: [4; 32],
            goal: "Validate runtime substrate".to_string(),
            runtime_route_frame: None,
            transcript_root: [0; 32],
            status,
            step_count: 3,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: Vec::new(),
            budget: 100,
            tokens_used: 10,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec!["read".to_string(), "verify".to_string()],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: Vec::new(),
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::from([(
                "shell__run".to_string(),
                ToolCallStatus::Executed("ok".to_string()),
            )]),
            execution_ledger: ExecutionLedger::default(),
            visual_som_map: None,
            visual_semantic_map: None,
            work_graph_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    #[test]
    fn substrate_snapshot_projects_running_state_without_terminal_success() {
        let state = test_agent_state(AgentStatus::Running);
        let snapshot = runtime_substrate_snapshot_for_state(&state, RuntimeSurface::Cli);
        assert_eq!(snapshot.envelope.surface, RuntimeSurface::Cli);
        assert_eq!(snapshot.task_state.current_objective, state.goal);
        assert_eq!(snapshot.stop_condition.reason, StopReason::Unknown);
        assert!(!snapshot.stop_condition.evidence_sufficient);
        assert!(snapshot.port_contract.forbids_privileged_dogfood_bypass);
        assert_eq!(snapshot.tool_contracts.len(), 1);
        assert!(snapshot
            .tool_contracts
            .iter()
            .any(|contract| contract.display_name == "shell__run"));
        assert_eq!(snapshot.envelope.tool_contract_ids.len(), 1);
        assert!(!snapshot.prompt_assembly.final_prompt_hash.trim().is_empty());
        assert!(snapshot
            .prompt_assembly
            .sections
            .iter()
            .any(|section| section.layer == PromptLayerKind::RuntimeRootSafetyPolicy));
        assert!(snapshot
            .events
            .iter()
            .any(|event| event.event_kind == "prompt_assembly_recorded"));
        assert_eq!(
            snapshot.uncertainty.selected_action,
            RuntimeDecisionAction::Execute
        );
        assert_eq!(snapshot.cognitive_budget.max_tool_calls, 5);
        assert!(snapshot
            .dry_run_capabilities
            .iter()
            .any(|capability| capability.capability_id == "dry_run:file_patch"));
        assert!(snapshot.operator_collaboration.resume_preserves_plan_state);
        assert!(
            snapshot
                .workflow_envelope_adapter
                .uses_public_substrate_contract
        );
        assert!(
            snapshot
                .workflow_envelope_adapter
                .forbids_compositor_runtime_truth
        );
        assert!(
            snapshot
                .harness_trace_adapter
                .consumes_exported_runtime_trace
        );
        assert!(!snapshot.harness_trace_adapter.imports_compositor_ui_state);
        assert!(snapshot.operator_interruption.replayable);
        assert!(
            snapshot
                .operator_interruption
                .preserves_objective_task_state_and_authority
        );
    }

    #[test]
    fn substrate_snapshot_maps_paused_approval_to_policy_stop_reason() {
        let state = test_agent_state(AgentStatus::Paused(
            AgentPauseReason::WaitingForApproval.message(),
        ));
        let snapshot = runtime_substrate_snapshot_for_state(&state, RuntimeSurface::Gui);
        assert_eq!(
            snapshot.stop_condition.reason,
            StopReason::PolicyPreventsProgress
        );
        assert!(snapshot
            .task_state
            .blockers
            .iter()
            .any(|blocker| blocker.contains("approval required")));
        assert_eq!(snapshot.quality_ledger.tool_sequence, state.recent_actions);
        assert_eq!(
            snapshot.uncertainty.selected_action,
            RuntimeDecisionAction::AskHuman
        );
        assert!(snapshot
            .strategy_decision
            .rejected_strategies
            .iter()
            .any(|strategy| strategy == "unsafe_autonomous_execution"));
    }

    #[test]
    fn substrate_snapshot_maps_execution_ledger_success_to_postcondition() {
        let mut state = test_agent_state(AgentStatus::Completed(Some("done".to_string())));
        state.execution_ledger.record_success_condition(
            Some("intent".to_string()),
            "targeted_test",
            "targeted test passed",
        );
        state.execution_ledger.record_verification_evidence(
            Some("intent".to_string()),
            "test",
            "pass",
        );
        state
            .execution_ledger
            .record_terminal_success(Some("intent".to_string()));

        let snapshot = runtime_substrate_snapshot_for_state(&state, RuntimeSurface::Harness);
        assert_eq!(
            snapshot.stop_condition.reason,
            StopReason::ObjectiveSatisfied
        );
        assert!(snapshot.stop_condition.evidence_sufficient);
        assert!(snapshot.postconditions.all_required_checks_proven());
        assert_eq!(
            snapshot.uncertainty.selected_action,
            RuntimeDecisionAction::Stop
        );
    }

    #[test]
    fn substrate_snapshot_projects_probe_and_semantic_impact_when_evidence_is_unknown() {
        let mut state = test_agent_state(AgentStatus::Running);
        state.consecutive_failures = 1;
        state.tool_execution_log.insert(
            "file__edit".to_string(),
            ToolCallStatus::Failed("search block missing".to_string()),
        );
        state.execution_ledger.record_success_condition(
            Some("intent".to_string()),
            "targeted_test",
            "targeted test passed",
        );

        let snapshot = runtime_substrate_snapshot_for_state(&state, RuntimeSurface::Harness);
        assert_eq!(
            snapshot.uncertainty.selected_action,
            RuntimeDecisionAction::Probe
        );
        assert_eq!(snapshot.probes.len(), 1);
        assert_eq!(snapshot.probes[0].result, ProbeResultStatus::Pending);
        assert_eq!(
            snapshot.semantic_impact.risk_class,
            "requires_targeted_verification"
        );
        assert!(snapshot
            .semantic_impact
            .affected_tests
            .iter()
            .any(|test| test.contains("targeted tests")));
    }

    #[test]
    fn semantic_impact_classifies_paths_from_runtime_receipts() {
        let mut state = test_agent_state(AgentStatus::Running);
        state.tool_execution_log.clear();
        state.tool_execution_log.insert(
            "file__write:source".to_string(),
            ToolCallStatus::Executed(
                "step=3;tool=file__write;path=crates/services/src/agentic/runtime/substrate.rs"
                    .to_string(),
            ),
        );
        state.tool_execution_log.insert(
            "file__write:policy".to_string(),
            ToolCallStatus::Executed(
                "step=4;tool=file__write;path=crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs"
                    .to_string(),
            ),
        );
        state.tool_execution_log.insert(
            "file__write:schema".to_string(),
            ToolCallStatus::Executed("step=5;tool=file__write;path=package.json".to_string()),
        );
        state.tool_execution_log.insert(
            "file__write:docs".to_string(),
            ToolCallStatus::Executed(
                "step=6;tool=file__write;path=docs/specs/runtime/agent-runtime-parity-plus-master-guide.md"
                    .to_string(),
            ),
        );
        state.tool_execution_log.insert(
            "file__write:generated".to_string(),
            ToolCallStatus::Executed("step=7;tool=file__write;path=pnpm-lock.yaml".to_string()),
        );

        let snapshot = runtime_substrate_snapshot_for_state(&state, RuntimeSurface::Harness);
        let impact = &snapshot.semantic_impact;

        assert_eq!(impact.risk_class, "requires_independent_verification");
        assert!(impact
            .changed_symbols
            .iter()
            .any(|symbol| symbol == "substrate"));
        assert!(impact
            .changed_symbols
            .iter()
            .any(|symbol| symbol == "firewall_policy"));
        assert!(impact
            .changed_policies
            .iter()
            .any(|path| path.contains("firewall_policy.rs")));
        assert!(impact
            .changed_schemas
            .iter()
            .any(|path| path == "package.json"));
        assert!(impact
            .affected_docs
            .iter()
            .any(|path| path.contains("agent-runtime-parity-plus-master-guide.md")));
        assert!(impact
            .generated_files_needing_refresh
            .iter()
            .any(|path| path == "pnpm-lock.yaml"));
        assert!(impact
            .migration_implications
            .iter()
            .any(|item| item.contains("package.json")));
        assert!(impact
            .affected_call_sites
            .iter()
            .any(|item| item.contains("substrate")));
        assert!(impact
            .affected_tests
            .iter()
            .any(|item| item.contains("crates/services")));
        assert!(impact.unknowns.is_empty());
        assert!(snapshot
            .postconditions
            .checks
            .iter()
            .any(|check| check.check_id == "semantic_impact:policy"
                && check
                    .required_evidence
                    .iter()
                    .any(|evidence| evidence == "independent_policy_verifier_receipt")));
        assert!(snapshot
            .postconditions
            .checks
            .iter()
            .any(|check| check.check_id == "semantic_impact:schema"));
        assert!(snapshot
            .postconditions
            .minimum_evidence
            .iter()
            .any(|evidence| evidence == "producer_command_receipt"));
        assert_eq!(
            snapshot
                .quality_ledger
                .scorecard_metrics
                .get("semantic_changed_policies"),
            Some(&1)
        );
        assert_eq!(
            snapshot
                .quality_ledger
                .scorecard_metrics
                .get("semantic_unknowns"),
            Some(&0)
        );
        assert!(
            snapshot
                .verifier_independence_policy
                .adversarial_review_required
        );
        assert!(!snapshot.verifier_independence_policy.same_model_allowed);
        assert!(!snapshot.verifier_independence_policy.same_context_allowed);
        assert_eq!(
            snapshot.verifier_independence_policy.human_review_threshold,
            "policy_or_destructive_or_sensitive_change"
        );
        assert!(
            snapshot
                .verifier_independence_policy
                .verifier_can_request_probes
        );
    }

    #[test]
    fn semantic_impact_marks_uncategorized_changed_paths_unknown() {
        let mut state = test_agent_state(AgentStatus::Running);
        state.tool_execution_log.clear();
        state.tool_execution_log.insert(
            "file__write:asset".to_string(),
            ToolCallStatus::Executed("step=3;tool=file__write;path=fixtures/blob.bin".to_string()),
        );

        let snapshot = runtime_substrate_snapshot_for_state(&state, RuntimeSurface::Harness);

        assert_eq!(
            snapshot.semantic_impact.risk_class,
            "requires_targeted_verification"
        );
        assert!(snapshot
            .semantic_impact
            .changed_symbols
            .iter()
            .any(|symbol| symbol == "filesystem_object"));
        assert!(snapshot
            .semantic_impact
            .unknowns
            .iter()
            .any(|unknown| unknown.contains("fixtures/blob.bin")));
    }

    #[test]
    fn quality_ledger_records_bounded_self_improvement_gate() {
        let mut state = test_agent_state(AgentStatus::Failed("recovery needed".to_string()));
        state.active_skill_hash = Some([3; 32]);
        state.execution_ledger.record_execution_failure(
            Some("intent".to_string()),
            ExecutionStage::Execution,
            "ToolUnavailable",
        );

        let snapshot = runtime_substrate_snapshot_for_state(&state, RuntimeSurface::Harness);

        let gate = snapshot
            .quality_ledger
            .promotion_decision
            .as_ref()
            .expect("bounded learning decision should be recorded");
        assert_eq!(gate.policy_decision, "review_required");
        assert!(gate
            .protected_holdout_summary
            .contains("required_before_promotion"));
        assert!(snapshot.bounded_self_improvement_gate.is_some());
    }

    #[test]
    fn dry_run_capabilities_cover_policy_workflow_and_external_side_effects() {
        let state = test_agent_state(AgentStatus::Running);
        let snapshot = runtime_substrate_snapshot_for_state(&state, RuntimeSurface::Workflow);
        let ids = snapshot
            .dry_run_capabilities
            .iter()
            .map(|capability| capability.capability_id.as_str())
            .collect::<BTreeSet<_>>();

        assert!(ids.contains("dry_run:file_patch"));
        assert!(ids.contains("dry_run:shell_command"));
        assert!(ids.contains("dry_run:connector_action"));
        assert!(ids.contains("dry_run:policy_decision"));
        assert!(ids.contains("dry_run:workflow_side_effect"));
        assert!(ids.contains("dry_run:external_order_or_cart"));
        assert!(snapshot.dry_run_capabilities.iter().any(|capability| {
            capability.capability_id == "dry_run:policy_decision"
                && capability.policy_preview
                && !capability.side_effect_preview
                && capability.output_artifact.as_deref() == Some("policy_preview_receipt")
        }));
        assert!(snapshot.dry_run_capabilities.iter().any(|capability| {
            capability.capability_id == "dry_run:workflow_side_effect"
                && capability
                    .supported_tool_classes
                    .iter()
                    .any(|tool_class| tool_class == "workflow__execute")
        }));
        assert!(snapshot.dry_run_capabilities.iter().any(|capability| {
            capability.capability_id == "dry_run:external_order_or_cart"
                && capability
                    .supported_tool_classes
                    .iter()
                    .any(|tool_class| tool_class == "order__submit")
        }));
    }

    #[test]
    fn substrate_snapshot_projects_object_level_file_observation_from_receipts() {
        let dir = std::env::temp_dir().join(format!(
            "ioi-substrate-file-observation-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should exist");
        let path = dir.join("observed.txt");
        std::fs::write(&path, "alpha\nbeta\n").expect("observed file should be written");

        let mut state = test_agent_state(AgentStatus::Running);
        state.working_directory = dir.to_string_lossy().to_string();
        state.tool_execution_log.insert(
            "evidence::workspace_read_observed=true".to_string(),
            ToolCallStatus::Executed(format!("step=2;tool=file__read;path={}", path.display())),
        );
        state.tool_execution_log.insert(
            "evidence::workspace_edit_applied=true".to_string(),
            ToolCallStatus::Executed(format!("step=3;tool=file__write;path={}", path.display())),
        );

        let snapshot = runtime_substrate_snapshot_for_state(&state, RuntimeSurface::Cli);
        assert!(snapshot.file_observations.iter().any(|observation| {
            observation.requested_path == path.to_string_lossy()
                && observation.read_status == FileReadStatus::Full
                && observation.line_endings == "lf"
                && observation.stale_write_guard_enforced
                && !observation.content_hash.trim().is_empty()
                && observation.content_hash != "unknown"
        }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn substrate_snapshot_scores_handoff_when_child_sessions_exist() {
        let mut state = test_agent_state(AgentStatus::Completed(Some("done".to_string())));
        state.child_session_ids.push([9; 32]);
        state.execution_ledger.record_verification_evidence(
            Some("intent".to_string()),
            "handoff",
            "child merged",
        );

        let snapshot = runtime_substrate_snapshot_for_state(&state, RuntimeSurface::Workflow);
        let handoff = snapshot
            .handoff_quality
            .as_ref()
            .expect("child session should create handoff quality");
        assert!(handoff.objective_preserved);
        assert!(handoff.evidence_refs_included);
        assert!(handoff.passes());
    }
}
