use super::revisions::persist_studio_artifact_exemplar;
use super::*;
use crate::models::StudioVerifiedReply;
use ioi_api::execution::{
    annotate_execution_envelope, block_swarm_work_item_on, build_execution_envelope_from_swarm,
    build_execution_envelope_from_swarm_with_receipts, completion_invariant_for_direct_execution,
    derive_execution_mode_decision, execution_domain_kind_for_outcome,
    execution_strategy_for_outcome, plan_swarm_dispatch_batches, spawn_follow_up_swarm_work_item,
    ExecutionBudgetSummary, ExecutionCompletionInvariantStatus, ExecutionDomainKind,
    ExecutionEnvelope, ExecutionGraphMutationReceipt, ExecutionReplanReceipt, ExecutionStage,
    SwarmChangeReceipt, SwarmExecutionSummary, SwarmMergeReceipt, SwarmPlan,
    SwarmVerificationReceipt, SwarmWorkItem, SwarmWorkItemStatus, SwarmWorkerReceipt,
    SwarmWorkerResultKind, SwarmWorkerRole,
};
use ioi_api::studio::{
    StudioArtifactBlueprint, StudioArtifactExemplar, StudioArtifactIR,
    StudioArtifactPreparationNeeds, StudioArtifactPreparedContextResolution,
    StudioArtifactRenderEvaluation, StudioArtifactRuntimeNarrationEvent,
    StudioArtifactSelectedSkill, StudioArtifactSkillDiscoveryResolution,
};
use ioi_types::app::{StudioExecutionModeDecision, StudioExecutionStrategy};
use std::time::Duration;

pub(super) fn studio_routing_timeout_for_runtime(runtime: &Arc<dyn InferenceRuntime>) -> Duration {
    let seconds = [
        "AUTOPILOT_STUDIO_ROUTING_TIMEOUT_SECS",
        "IOI_STUDIO_ROUTING_TIMEOUT_SECS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
    })
    .unwrap_or_else(|| match runtime.studio_runtime_provenance().kind {
        crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime => 45,
        _ => 20,
    });

    Duration::from_secs(seconds)
}

pub(super) struct MaterializedContentArtifact {
    pub(super) artifacts: Vec<Artifact>,
    pub(super) files: Vec<StudioArtifactManifestFile>,
    pub(super) file_writes: Vec<StudioArtifactMaterializationFileWrite>,
    pub(super) notes: Vec<String>,
    pub(super) brief: StudioArtifactBrief,
    pub(super) preparation_needs: Option<StudioArtifactPreparationNeeds>,
    pub(super) prepared_context_resolution: Option<StudioArtifactPreparedContextResolution>,
    pub(super) skill_discovery_resolution: Option<StudioArtifactSkillDiscoveryResolution>,
    pub(super) blueprint: Option<StudioArtifactBlueprint>,
    pub(super) artifact_ir: Option<StudioArtifactIR>,
    pub(super) selected_skills: Vec<StudioArtifactSelectedSkill>,
    pub(super) retrieved_exemplars: Vec<StudioArtifactExemplar>,
    pub(super) edit_intent: Option<StudioArtifactEditIntent>,
    pub(super) candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    pub(super) winning_candidate_id: Option<String>,
    pub(super) winning_candidate_rationale: Option<String>,
    pub(super) execution_envelope: Option<ExecutionEnvelope>,
    pub(super) swarm_plan: Option<SwarmPlan>,
    pub(super) swarm_execution: Option<SwarmExecutionSummary>,
    pub(super) swarm_worker_receipts: Vec<SwarmWorkerReceipt>,
    pub(super) swarm_change_receipts: Vec<SwarmChangeReceipt>,
    pub(super) swarm_merge_receipts: Vec<SwarmMergeReceipt>,
    pub(super) swarm_verification_receipts: Vec<SwarmVerificationReceipt>,
    pub(super) render_evaluation: Option<StudioArtifactRenderEvaluation>,
    pub(super) judge: Option<StudioArtifactJudgeResult>,
    pub(super) output_origin: StudioArtifactOutputOrigin,
    pub(super) production_provenance: Option<crate::models::StudioRuntimeProvenance>,
    pub(super) acceptance_provenance: Option<crate::models::StudioRuntimeProvenance>,
    pub(super) fallback_used: bool,
    pub(super) ux_lifecycle: StudioArtifactUxLifecycle,
    pub(super) failure: Option<crate::models::StudioArtifactFailure>,
    pub(super) taste_memory: Option<StudioArtifactTasteMemory>,
    pub(super) selected_targets: Vec<StudioArtifactSelectionTarget>,
    pub(super) lifecycle_state: StudioArtifactLifecycleState,
    pub(super) verification_summary: String,
    pub(super) runtime_narration_events: Vec<StudioArtifactRuntimeNarrationEvent>,
}

fn default_studio_outcome_request(
    raw_prompt: &str,
    active_artifact_id: Option<String>,
) -> StudioOutcomeRequest {
    StudioOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: raw_prompt.trim().to_string(),
        active_artifact_id,
        outcome_kind: StudioOutcomeKind::Conversation,
        execution_strategy: execution_strategy_for_outcome(StudioOutcomeKind::Conversation, None),
        execution_mode_decision: None,
        confidence: 0.0,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        artifact: None,
    }
}

fn outcome_kind_id(kind: StudioOutcomeKind) -> &'static str {
    match kind {
        StudioOutcomeKind::Conversation => "conversation",
        StudioOutcomeKind::ToolWidget => "tool_widget",
        StudioOutcomeKind::Visualizer => "visualizer",
        StudioOutcomeKind::Artifact => "artifact",
    }
}

fn execution_strategy_id(strategy: StudioExecutionStrategy) -> &'static str {
    match strategy {
        StudioExecutionStrategy::SinglePass => "single_pass",
        StudioExecutionStrategy::DirectAuthor => "direct_author",
        StudioExecutionStrategy::PlanExecute => "plan_execute",
        StudioExecutionStrategy::MicroSwarm => "micro_swarm",
        StudioExecutionStrategy::AdaptiveWorkGraph => "adaptive_work_graph",
    }
}

pub(super) fn artifact_execution_envelope_for_contract(
    execution_mode_decision: Option<StudioExecutionModeDecision>,
    execution_strategy: StudioExecutionStrategy,
    materialization: &StudioArtifactMaterializationContract,
) -> Option<ExecutionEnvelope> {
    let mut envelope = build_execution_envelope_from_swarm(
        Some(execution_strategy),
        Some("studio_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        materialization.swarm_plan.as_ref(),
        materialization.swarm_execution.as_ref(),
        &materialization.swarm_worker_receipts,
        &materialization.swarm_change_receipts,
        &materialization.swarm_merge_receipts,
        &materialization.swarm_verification_receipts,
    );
    annotate_execution_envelope(
        &mut envelope,
        execution_mode_decision,
        materialization
            .execution_envelope
            .as_ref()
            .and_then(|entry| entry.completion_invariant.clone()),
    );
    envelope
}

fn non_artifact_execution_domain(kind: StudioOutcomeKind) -> String {
    format!("studio_{}", outcome_kind_id(kind))
}

fn non_artifact_adapter_label(
    kind: StudioOutcomeKind,
    strategy: StudioExecutionStrategy,
) -> String {
    format!(
        "{}_{}_v1",
        outcome_kind_id(kind),
        execution_strategy_id(strategy)
    )
}

fn non_artifact_route_summary(outcome_request: &StudioOutcomeRequest) -> String {
    if outcome_request.needs_clarification {
        let question = outcome_request
            .clarification_questions
            .first()
            .cloned()
            .unwrap_or_else(|| {
                "Studio needs clarification before it can choose the correct outcome surface."
                    .to_string()
            });
        return format!(
            "Studio paused before selecting the outcome surface because it needs clarification: {}",
            question
        );
    }

    match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => {
            "Studio routed this request to conversation and kept it on the shared execution lane. No artifact renderer was invoked."
                .to_string()
        }
        StudioOutcomeKind::ToolWidget => {
            "Studio routed this request to a tool-widget outcome and kept it on the shared execution lane. No artifact renderer was invoked."
                .to_string()
        }
        StudioOutcomeKind::Visualizer => {
            "Studio routed this request to a visualizer outcome and kept it on the shared execution lane. No artifact renderer was invoked."
                .to_string()
        }
        StudioOutcomeKind::Artifact => {
            "Studio routed this request to artifact materialization.".to_string()
        }
    }
}

fn non_artifact_route_title(intent: &str, outcome_request: &StudioOutcomeRequest) -> String {
    let base = derive_artifact_title(intent);
    match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => format!("Conversation route · {base}"),
        StudioOutcomeKind::ToolWidget => format!("Tool widget route · {base}"),
        StudioOutcomeKind::Visualizer => format!("Visualizer route · {base}"),
        StudioOutcomeKind::Artifact => base,
    }
}

fn non_artifact_swarm_plan(outcome_request: &StudioOutcomeRequest) -> SwarmPlan {
    let execution_domain = non_artifact_execution_domain(outcome_request.outcome_kind);
    let adapter_label = non_artifact_adapter_label(
        outcome_request.outcome_kind,
        outcome_request.execution_strategy,
    );
    let strategy = execution_strategy_id(outcome_request.execution_strategy).to_string();
    let responder_title = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => "Conversation handoff",
        StudioOutcomeKind::ToolWidget => "Tool-widget handoff",
        StudioOutcomeKind::Visualizer => "Visualizer handoff",
        StudioOutcomeKind::Artifact => "Artifact handoff",
    };
    let responder_summary = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => {
            "Keep the request on the conversation surface and preserve the shared execution evidence."
        }
        StudioOutcomeKind::ToolWidget => {
            "Keep the request on the tool-widget surface and preserve the shared execution evidence."
        }
        StudioOutcomeKind::Visualizer => {
            "Keep the request on the visualizer surface and preserve the shared execution evidence."
        }
        StudioOutcomeKind::Artifact => {
            "Keep the request on the artifact surface and preserve the shared execution evidence."
        }
    };

    SwarmPlan {
        version: 1,
        strategy,
        execution_domain,
        adapter_label,
        parallelism_mode: "sequential_by_default".to_string(),
        top_level_objective: Some(format!(
            "Route the request onto the {} surface and preserve truthful execution evidence.",
            outcome_kind_id(outcome_request.outcome_kind)
        )),
        decomposition_hypothesis: Some(
            "The request can be satisfied with a small known non-artifact work graph."
                .to_string(),
        ),
        decomposition_type: Some("small_graph_functional_decomposition".to_string()),
        first_frontier_ids: vec!["handoff".to_string()],
        spawn_conditions: vec![
            "Spawn a clarification gate only when the router discovers unresolved ambiguity."
                .to_string(),
        ],
        prune_conditions: vec![
            "Prune clarification work once the reply handoff is already unblocked.".to_string(),
        ],
        merge_strategy: Some("deterministic_reply_surface_projection".to_string()),
        verification_strategy: Some("route_truth_before_reply".to_string()),
        fallback_collapse_strategy: Some(
            "Collapse to the reply handoff once clarification obligations are satisfied."
                .to_string(),
        ),
        completion_invariant: Some(ioi_api::execution::ExecutionCompletionInvariant {
            summary:
                "Complete once the mandatory non-artifact handoff is satisfied and route truth is preserved."
                    .to_string(),
            status: ExecutionCompletionInvariantStatus::Satisfied,
            required_work_item_ids: vec!["planner".to_string(), "handoff".to_string()],
            satisfied_work_item_ids: vec!["planner".to_string(), "handoff".to_string()],
            speculative_work_item_ids: if outcome_request.needs_clarification {
                vec!["clarification_gate".to_string()]
            } else {
                Vec::new()
            },
            pruned_work_item_ids: Vec::new(),
            required_verification_ids: vec!["route_truth".to_string()],
            satisfied_verification_ids: vec!["route_truth".to_string()],
            required_artifact_paths: Vec::new(),
            remaining_obligations: Vec::new(),
            allows_early_exit: true,
        }),
        work_items: vec![
            SwarmWorkItem {
                id: "planner".to_string(),
                title: "Outcome planner".to_string(),
                role: SwarmWorkerRole::Planner,
                summary:
                    "Lock the correct non-artifact route and execution strategy before any downstream handoff."
                        .to_string(),
                spawned_from_id: None,
                read_paths: vec!["request".to_string(), "route_context".to_string()],
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: vec![
                    "Outcome route is explicit.".to_string(),
                    "Execution strategy is explicit.".to_string(),
                ],
                dependency_ids: Vec::new(),
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: SwarmWorkItemStatus::Succeeded,
            },
            SwarmWorkItem {
                id: "handoff".to_string(),
                title: responder_title.to_string(),
                role: SwarmWorkerRole::Responder,
                summary: responder_summary.to_string(),
                spawned_from_id: None,
                read_paths: vec!["request".to_string(), "execution_plan".to_string()],
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: vec![
                    "Studio reply remains truthful about the chosen surface.".to_string(),
                    "No artifact renderer is implied when none was invoked.".to_string(),
                ],
                dependency_ids: vec!["planner".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: SwarmWorkItemStatus::Succeeded,
            },
        ],
    }
}

fn non_artifact_swarm_worker_receipts(
    outcome_request: &StudioOutcomeRequest,
    provenance: &crate::models::StudioRuntimeProvenance,
    swarm_plan: &SwarmPlan,
) -> Vec<SwarmWorkerReceipt> {
    let now = now_iso();
    let handoff_summary = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => {
            "Conversation stayed primary and no artifact renderer was launched."
        }
        StudioOutcomeKind::ToolWidget => {
            "Tool-widget stayed primary and no artifact renderer was launched."
        }
        StudioOutcomeKind::Visualizer => {
            "Visualizer stayed primary and no artifact renderer was launched."
        }
        StudioOutcomeKind::Artifact => "Artifact stayed primary.",
    };

    let clarification_questions = outcome_request.clarification_questions.clone();
    let planner_spawned_items = if outcome_request.needs_clarification {
        vec!["clarification_gate".to_string()]
    } else {
        Vec::new()
    };
    let handoff_status = swarm_plan
        .work_items
        .iter()
        .find(|item| item.id == "handoff")
        .map(|item| item.status)
        .unwrap_or(SwarmWorkItemStatus::Succeeded);

    let mut receipts = vec![SwarmWorkerReceipt {
        work_item_id: "planner".to_string(),
        role: SwarmWorkerRole::Planner,
        status: SwarmWorkItemStatus::Succeeded,
        result_kind: Some(if outcome_request.needs_clarification {
            ioi_api::execution::SwarmWorkerResultKind::DependencyDiscovered
        } else {
            ioi_api::execution::SwarmWorkerResultKind::Completed
        }),
        summary: format!(
            "Selected the {} route with the {} strategy.",
            outcome_kind_id(outcome_request.outcome_kind),
            execution_strategy_id(outcome_request.execution_strategy)
        ),
        started_at: now.clone(),
        finished_at: Some(now.clone()),
        runtime: provenance.clone(),
        read_paths: vec!["request".to_string(), "route_context".to_string()],
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        spawned_work_item_ids: planner_spawned_items,
        blocked_on_ids: Vec::new(),
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: if outcome_request.needs_clarification {
            clarification_questions.clone()
        } else {
            vec!["No artifact files were requested on this route.".to_string()]
        },
        failure: None,
    }];
    if outcome_request.needs_clarification {
        receipts.push(SwarmWorkerReceipt {
            work_item_id: "clarification_gate".to_string(),
            role: SwarmWorkerRole::Coordinator,
            status: SwarmWorkItemStatus::Blocked,
            result_kind: Some(ioi_api::execution::SwarmWorkerResultKind::Blocked),
            summary:
                "Clarification is required before the shared responder can safely finalize the route."
                    .to_string(),
            started_at: now.clone(),
            finished_at: Some(now.clone()),
            runtime: provenance.clone(),
            read_paths: vec!["request".to_string(), "clarification_questions".to_string()],
            write_paths: Vec::new(),
            write_regions: Vec::new(),
            spawned_work_item_ids: Vec::new(),
            blocked_on_ids: Vec::new(),
            prompt_bytes: None,
            output_bytes: None,
            output_preview: None,
            preview_language: None,
            notes: clarification_questions.clone(),
            failure: None,
        });
    }
    receipts.push(SwarmWorkerReceipt {
        work_item_id: "handoff".to_string(),
        role: SwarmWorkerRole::Responder,
        status: handoff_status,
        result_kind: Some(if outcome_request.needs_clarification {
            ioi_api::execution::SwarmWorkerResultKind::Blocked
        } else {
            ioi_api::execution::SwarmWorkerResultKind::Completed
        }),
        summary: handoff_summary.to_string(),
        started_at: now.clone(),
        finished_at: Some(now),
        runtime: provenance.clone(),
        read_paths: vec!["request".to_string(), "execution_plan".to_string()],
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        spawned_work_item_ids: Vec::new(),
        blocked_on_ids: if outcome_request.needs_clarification {
            vec!["clarification_gate".to_string()]
        } else {
            Vec::new()
        },
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: vec![
            "Studio kept the shared execution evidence instead of surfacing a blocked artifact failure."
                .to_string(),
        ],
        failure: if outcome_request.needs_clarification {
            Some("Clarification is still required before reply handoff can complete.".to_string())
        } else {
            None
        },
    });
    receipts
}

fn non_artifact_swarm_verification_receipts(
    outcome_request: &StudioOutcomeRequest,
) -> Vec<SwarmVerificationReceipt> {
    let status = if outcome_request.needs_clarification {
        "blocked"
    } else {
        "ready"
    };
    let route_detail = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => "conversation surface",
        StudioOutcomeKind::ToolWidget => "tool-widget surface",
        StudioOutcomeKind::Visualizer => "visualizer surface",
        StudioOutcomeKind::Artifact => "artifact surface",
    };

    vec![
        SwarmVerificationReceipt {
            id: "route_verification".to_string(),
            kind: "route_verification".to_string(),
            status: status.to_string(),
            summary: if outcome_request.needs_clarification {
                "Studio blocked execution because clarification is still required.".to_string()
            } else {
                format!(
                    "Studio verified that this request belongs on the {}.",
                    route_detail
                )
            },
            details: outcome_request.clarification_questions.clone(),
        },
        SwarmVerificationReceipt {
            id: "reply_surface".to_string(),
            kind: "reply_surface".to_string(),
            status: status.to_string(),
            summary: if outcome_request.needs_clarification {
                "The shared reply lane is blocked until the user answers the clarification."
                    .to_string()
            } else {
                "The shared reply lane stays primary and no artifact renderer is required."
                    .to_string()
            },
            details: vec![format!(
                "strategy:{}",
                execution_strategy_id(outcome_request.execution_strategy)
            )],
        },
    ]
}

fn non_artifact_materialization_contract(
    intent: &str,
    outcome_request: &StudioOutcomeRequest,
    summary: &str,
    provenance: &crate::models::StudioRuntimeProvenance,
) -> StudioArtifactMaterializationContract {
    let mut swarm_plan = non_artifact_swarm_plan(outcome_request);
    let mut graph_mutation_receipts = Vec::<ExecutionGraphMutationReceipt>::new();
    let mut replan_receipts = Vec::<ExecutionReplanReceipt>::new();
    if outcome_request.needs_clarification {
        let clarification_gate = SwarmWorkItem {
            id: "clarification_gate".to_string(),
            title: "Clarification gate".to_string(),
            role: SwarmWorkerRole::Coordinator,
            summary:
                "Hold the response until the user answers the required clarification questions."
                    .to_string(),
            spawned_from_id: Some("planner".to_string()),
            read_paths: vec!["request".to_string(), "clarification_questions".to_string()],
            write_paths: Vec::new(),
            write_regions: Vec::new(),
            lease_requirements: Vec::new(),
            acceptance_criteria: vec![
                "Clarification questions stay visible.".to_string(),
                "Responder stays blocked until clarification arrives.".to_string(),
            ],
            dependency_ids: vec!["planner".to_string()],
            blocked_on_ids: Vec::new(),
            verification_policy: Some(ioi_api::execution::SwarmVerificationPolicy::Blocking),
            retry_budget: Some(0),
            status: SwarmWorkItemStatus::Blocked,
        };
        let clarification_gate_id = clarification_gate.id.clone();
        let clarification_details = outcome_request.clarification_questions.clone();
        let _ = spawn_follow_up_swarm_work_item(&mut swarm_plan, clarification_gate);
        let _ = block_swarm_work_item_on(
            &mut swarm_plan,
            "handoff",
            std::slice::from_ref(&clarification_gate_id),
        );
        graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
            id: "clarification-gate-spawned".to_string(),
            mutation_kind: "subtask_spawned".to_string(),
            status: "applied".to_string(),
            summary:
                "The planner discovered a clarification dependency and spawned a gate before reply handoff."
                    .to_string(),
            triggered_by_work_item_id: Some("planner".to_string()),
            affected_work_item_ids: vec![
                clarification_gate_id.clone(),
                "handoff".to_string(),
            ],
            details: clarification_details.clone(),
        });
        replan_receipts.push(ExecutionReplanReceipt {
            id: "clarification-replan".to_string(),
            status: "blocked".to_string(),
            summary:
                "Shared execution widened the plan with a clarification gate before the responder could finalize."
                    .to_string(),
            triggered_by_work_item_id: Some("planner".to_string()),
            spawned_work_item_ids: vec![clarification_gate_id],
            blocked_work_item_ids: vec!["handoff".to_string()],
            details: clarification_details,
        });
    }
    let swarm_worker_receipts =
        non_artifact_swarm_worker_receipts(outcome_request, provenance, &swarm_plan);
    let swarm_verification_receipts = non_artifact_swarm_verification_receipts(outcome_request);
    let verification_status = if outcome_request.needs_clarification {
        "blocked".to_string()
    } else {
        "ready".to_string()
    };
    let completed_work_items = swarm_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                SwarmWorkItemStatus::Succeeded | SwarmWorkItemStatus::Skipped
            )
        })
        .count();
    let failed_work_items = swarm_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                SwarmWorkItemStatus::Blocked
                    | SwarmWorkItemStatus::Failed
                    | SwarmWorkItemStatus::Rejected
            )
        })
        .count();
    let swarm_execution = SwarmExecutionSummary {
        enabled: true,
        current_stage: if outcome_request.needs_clarification {
            "routing".to_string()
        } else {
            "reply".to_string()
        },
        execution_stage: Some(if outcome_request.needs_clarification {
            ExecutionStage::Dispatch
        } else {
            ExecutionStage::Finalize
        }),
        active_worker_role: None,
        total_work_items: swarm_plan.work_items.len(),
        completed_work_items,
        failed_work_items,
        verification_status,
        strategy: swarm_plan.strategy.clone(),
        execution_domain: swarm_plan.execution_domain.clone(),
        adapter_label: swarm_plan.adapter_label.clone(),
        parallelism_mode: swarm_plan.parallelism_mode.clone(),
    };
    let dispatch_batches = plan_swarm_dispatch_batches(&swarm_plan);
    let execution_budget_summary = ExecutionBudgetSummary {
        planned_worker_count: Some(swarm_plan.work_items.len()),
        dispatched_worker_count: Some(
            swarm_worker_receipts
                .iter()
                .filter(|receipt| {
                    !matches!(receipt.result_kind, Some(SwarmWorkerResultKind::Blocked))
                })
                .count(),
        ),
        token_budget: None,
        token_usage: None,
        wall_clock_ms: None,
        coordination_overhead_ms: None,
        status: if outcome_request.needs_clarification {
            "blocked".to_string()
        } else {
            "completed".to_string()
        },
    };
    let mut execution_envelope = build_execution_envelope_from_swarm_with_receipts(
        Some(outcome_request.execution_strategy),
        Some(swarm_plan.execution_domain.clone()),
        Some(execution_domain_kind_for_outcome(
            outcome_request.outcome_kind,
        )),
        Some(&swarm_plan),
        Some(&swarm_execution),
        &swarm_worker_receipts,
        &[],
        &[],
        &swarm_verification_receipts,
        &graph_mutation_receipts,
        &dispatch_batches,
        &[],
        &replan_receipts,
        Some(execution_budget_summary),
        &[],
    );
    annotate_execution_envelope(
        &mut execution_envelope,
        outcome_request.execution_mode_decision.clone(),
        Some(ioi_api::execution::completion_invariant_for_plan(
            &swarm_plan,
            &swarm_verification_receipts,
            Vec::new(),
        )),
    );

    StudioArtifactMaterializationContract {
        version: 7,
        request_kind: outcome_kind_id(outcome_request.outcome_kind).to_string(),
        normalized_intent: intent.trim().to_string(),
        summary: summary.to_string(),
        artifact_brief: None,
        preparation_needs: None,
        prepared_context_resolution: None,
        skill_discovery_resolution: None,
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        retrieved_exemplars: Vec::new(),
        edit_intent: None,
        candidate_summaries: Vec::new(),
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        execution_envelope,
        swarm_execution: Some(swarm_execution),
        swarm_plan: Some(swarm_plan),
        swarm_worker_receipts,
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts,
        render_evaluation: None,
        judge: None,
        output_origin: Some(output_origin_from_runtime_provenance(provenance)),
        production_provenance: Some(provenance.clone()),
        acceptance_provenance: Some(provenance.clone()),
        fallback_used: false,
        ux_lifecycle: Some(StudioArtifactUxLifecycle::Judged),
        failure: None,
        navigator_nodes: Vec::new(),
        file_writes: Vec::new(),
        command_intents: Vec::new(),
        preview_intent: None,
        verification_steps: vec![
            verification_step("route", "Verify route", "success"),
            verification_step(
                "reply_surface",
                "Verify reply surface",
                if outcome_request.needs_clarification {
                    "blocked"
                } else {
                    "success"
                },
            ),
        ],
        pipeline_steps: Vec::new(),
        runtime_narration_events: Vec::new(),
        notes: vec![
            "Studio intentionally kept this request off the artifact materialization path."
                .to_string(),
            "The shared execution envelope still records plan, worker, and verification state."
                .to_string(),
            "No renderer-specific fallback artifact was injected for this route.".to_string(),
        ],
    }
}

fn verified_reply_for_non_artifact_route(
    title: &str,
    summary: &str,
    lifecycle_state: StudioArtifactLifecycleState,
    provenance: &crate::models::StudioRuntimeProvenance,
    outcome_request: &StudioOutcomeRequest,
) -> StudioVerifiedReply {
    let status = match lifecycle_state {
        StudioArtifactLifecycleState::Draft
        | StudioArtifactLifecycleState::Planned
        | StudioArtifactLifecycleState::Materializing
        | StudioArtifactLifecycleState::Rendering
        | StudioArtifactLifecycleState::Implementing
        | StudioArtifactLifecycleState::Verifying => StudioArtifactVerificationStatus::Pending,
        StudioArtifactLifecycleState::Ready => StudioArtifactVerificationStatus::Ready,
        StudioArtifactLifecycleState::Blocked => StudioArtifactVerificationStatus::Blocked,
        StudioArtifactLifecycleState::Failed => StudioArtifactVerificationStatus::Failed,
        StudioArtifactLifecycleState::Partial => StudioArtifactVerificationStatus::Partial,
    };

    StudioVerifiedReply {
        status,
        lifecycle_state,
        title: title.to_string(),
        summary: summary.to_string(),
        evidence: vec![
            format!("outcome:{}", outcome_kind_id(outcome_request.outcome_kind)),
            format!(
                "strategy:{}",
                execution_strategy_id(outcome_request.execution_strategy)
            ),
            format!("provenance:{}", provenance.label),
        ],
        production_provenance: Some(provenance.clone()),
        acceptance_provenance: Some(provenance.clone()),
        failure: None,
        updated_at: now_iso(),
    }
}

pub(super) fn attach_non_artifact_studio_session(
    task: &mut AgentTask,
    intent: &str,
    provenance: crate::models::StudioRuntimeProvenance,
    outcome_request: &StudioOutcomeRequest,
) {
    let lifecycle_state = if outcome_request.needs_clarification {
        StudioArtifactLifecycleState::Blocked
    } else {
        StudioArtifactLifecycleState::Ready
    };
    let title = non_artifact_route_title(intent, outcome_request);
    let summary = non_artifact_route_summary(outcome_request);
    let mut materialization =
        non_artifact_materialization_contract(intent, outcome_request, &summary, &provenance);
    let artifact_id = Uuid::new_v4().to_string();
    let manifest = StudioArtifactManifest {
        artifact_id: artifact_id.clone(),
        title: title.clone(),
        artifact_class: StudioArtifactClass::ReportBundle,
        renderer: StudioRendererKind::BundleManifest,
        primary_tab: "source".to_string(),
        tabs: vec![
            StudioArtifactManifestTab {
                id: "source".to_string(),
                label: "Source".to_string(),
                kind: StudioArtifactTabKind::Source,
                renderer: None,
                file_path: None,
                lens: Some("source".to_string()),
            },
            StudioArtifactManifestTab {
                id: "evidence".to_string(),
                label: "Evidence".to_string(),
                kind: StudioArtifactTabKind::Evidence,
                renderer: None,
                file_path: None,
                lens: Some("evidence".to_string()),
            },
        ],
        files: Vec::new(),
        verification: StudioArtifactManifestVerification {
            status: if outcome_request.needs_clarification {
                StudioArtifactVerificationStatus::Blocked
            } else {
                StudioArtifactVerificationStatus::Ready
            },
            lifecycle_state,
            summary: summary.clone(),
            production_provenance: Some(provenance.clone()),
            acceptance_provenance: Some(provenance.clone()),
            failure: None,
        },
        storage: None,
    };
    let navigator_nodes = navigator_nodes_for_manifest(&manifest);
    materialization.navigator_nodes = navigator_nodes.clone();
    let created_at = now_iso();
    let mut studio_session = StudioArtifactSession {
        session_id: Uuid::new_v4().to_string(),
        thread_id: task.session_id.clone().unwrap_or_else(|| task.id.clone()),
        artifact_id,
        title: title.clone(),
        summary: summary.clone(),
        current_lens: "source".to_string(),
        navigator_backing_mode: "logical".to_string(),
        navigator_nodes,
        attached_artifact_ids: Vec::new(),
        available_lenses: vec!["source".to_string(), "evidence".to_string()],
        materialization,
        outcome_request: outcome_request.clone(),
        artifact_manifest: manifest,
        verified_reply: verified_reply_for_non_artifact_route(
            &title,
            &summary,
            lifecycle_state,
            &provenance,
            outcome_request,
        ),
        lifecycle_state,
        status: lifecycle_state_label(lifecycle_state).to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory: None,
        retrieved_exemplars: Vec::new(),
        selected_targets: Vec::new(),
        ux_lifecycle: Some(StudioArtifactUxLifecycle::Judged),
        created_at: created_at.clone(),
        updated_at: created_at,
        build_session_id: None,
        workspace_root: None,
        renderer_session_id: None,
    };
    refresh_pipeline_steps(&mut studio_session, None);
    let initial_revision = initial_revision_for_session(&studio_session, intent);
    studio_session.active_revision_id = Some(initial_revision.revision_id.clone());
    studio_session.revisions = vec![initial_revision];
    task.studio_outcome = Some(outcome_request.clone());
    task.studio_session = Some(studio_session);
    task.renderer_session = None;
    task.build_session = None;
}

fn studio_failure_request() -> StudioOutcomeArtifactRequest {
    StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::ReportBundle,
        deliverable_shape: StudioArtifactDeliverableShape::FileSet,
        renderer: StudioRendererKind::BundleManifest,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::None,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: StudioOutcomeArtifactVerificationRequest {
            require_render: false,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    }
}

pub(super) fn attach_blocked_studio_failure_session(
    task: &mut AgentTask,
    intent: &str,
    active_artifact_id: Option<String>,
    provenance: crate::models::StudioRuntimeProvenance,
    failure: StudioArtifactFailure,
) {
    let request = studio_failure_request();
    let outcome_request = StudioOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: intent.trim().to_string(),
        active_artifact_id,
        outcome_kind: StudioOutcomeKind::Artifact,
        execution_strategy: execution_strategy_for_outcome(
            StudioOutcomeKind::Artifact,
            Some(&request),
        ),
        execution_mode_decision: None,
        confidence: 0.0,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        artifact: Some(request.clone()),
    };
    let title = derive_artifact_title(intent);
    let summary = failure.message.clone();
    let judge = StudioArtifactJudgeResult {
        classification: ioi_api::studio::StudioArtifactJudgeClassification::Blocked,
        request_faithfulness: 1,
        concept_coverage: 1,
        interaction_relevance: 1,
        layout_coherence: 1,
        visual_hierarchy: 1,
        completeness: 1,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: false,
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        issue_classes: vec!["failure_session".to_string()],
        repair_hints: vec![
            "Resolve the upstream studio failure and rerun materialization before surfacing the artifact."
                .to_string(),
        ],
        strengths: Vec::new(),
        blocked_reasons: vec![summary.clone()],
        file_findings: Vec::new(),
        aesthetic_verdict: "not_evaluated_due_to_failure_session".to_string(),
        interaction_verdict: "not_evaluated_due_to_failure_session".to_string(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some("generation_retry".to_string()),
        strongest_contradiction: Some(summary.clone()),
        rationale: summary.clone(),
    };
    let artifact_manifest = StudioArtifactManifest {
        artifact_id: Uuid::new_v4().to_string(),
        title: title.clone(),
        artifact_class: request.artifact_class,
        renderer: request.renderer,
        primary_tab: "evidence".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "evidence".to_string(),
            label: "Evidence".to_string(),
            kind: StudioArtifactTabKind::Evidence,
            renderer: None,
            file_path: None,
            lens: Some("evidence".to_string()),
        }],
        files: Vec::new(),
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Blocked,
            lifecycle_state: StudioArtifactLifecycleState::Blocked,
            summary: summary.clone(),
            production_provenance: Some(provenance.clone()),
            acceptance_provenance: Some(provenance.clone()),
            failure: Some(failure.clone()),
        },
        storage: None,
    };
    let mut materialization = materialization_contract_for_request(
        intent,
        &request,
        &summary,
        None,
        execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&request)),
    );
    materialization.artifact_brief = Some(blocked_failure_brief(
        &title,
        intent,
        request.renderer,
        &summary,
        Vec::new(),
    ));
    materialization.judge = Some(judge);
    materialization.output_origin = Some(output_origin_from_runtime_provenance(&provenance));
    materialization.production_provenance = Some(provenance.clone());
    materialization.acceptance_provenance = Some(provenance.clone());
    let failure_kind = failure.kind;
    materialization.failure = Some(failure);
    materialization.summary = summary.clone();
    materialization.ux_lifecycle = Some(StudioArtifactUxLifecycle::Draft);
    materialization.notes.push(match failure_kind {
        StudioArtifactFailureKind::InferenceUnavailable => {
            "Studio stopped before routing because inference was unavailable and no substitute artifact was allowed."
                .to_string()
        }
        StudioArtifactFailureKind::RoutingFailure => {
            "Studio stopped before opening the artifact because typed outcome routing did not complete successfully."
                .to_string()
        }
        _ => "Studio stopped before opening the artifact because verification could not authorize a usable primary artifact view."
            .to_string(),
    });
    let mut studio_session = StudioArtifactSession {
        session_id: Uuid::new_v4().to_string(),
        thread_id: task.session_id.clone().unwrap_or_else(|| task.id.clone()),
        artifact_id: artifact_manifest.artifact_id.clone(),
        title: title.clone(),
        summary: summary.clone(),
        current_lens: "evidence".to_string(),
        navigator_backing_mode: "logical".to_string(),
        navigator_nodes: Vec::new(),
        attached_artifact_ids: Vec::new(),
        available_lenses: vec!["evidence".to_string()],
        materialization,
        outcome_request: outcome_request.clone(),
        verified_reply: verified_reply_from_manifest(&title, &artifact_manifest),
        artifact_manifest,
        lifecycle_state: StudioArtifactLifecycleState::Blocked,
        status: lifecycle_state_label(StudioArtifactLifecycleState::Blocked).to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory: None,
        retrieved_exemplars: Vec::new(),
        selected_targets: Vec::new(),
        ux_lifecycle: Some(StudioArtifactUxLifecycle::Draft),
        created_at: now_iso(),
        updated_at: now_iso(),
        build_session_id: None,
        workspace_root: None,
        renderer_session_id: None,
    };
    refresh_pipeline_steps(&mut studio_session, None);
    let initial_revision = initial_revision_for_session(&studio_session, intent);
    studio_session.active_revision_id = Some(initial_revision.revision_id.clone());
    studio_session.revisions = vec![initial_revision];
    task.studio_outcome = Some(outcome_request);
    task.studio_session = Some(studio_session);
}

pub(super) fn studio_outcome_request(
    app: &AppHandle,
    intent: &str,
    active_artifact_id: Option<String>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioOutcomeRequest, String> {
    let trimmed_intent = intent.trim();
    if trimmed_intent.is_empty() {
        return Ok(default_studio_outcome_request(
            trimmed_intent,
            active_artifact_id,
        ));
    }

    let Some(runtime) = app_studio_routing_inference_runtime(app) else {
        return Ok(default_studio_outcome_request(
            trimmed_intent,
            active_artifact_id,
        ));
    };

    studio_outcome_request_with_runtime(
        runtime,
        trimmed_intent,
        active_artifact_id,
        active_artifact,
    )
}

pub(super) fn studio_outcome_request_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    active_artifact_id: Option<String>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioOutcomeRequest, String> {
    let timeout = studio_routing_timeout_for_runtime(&runtime);
    studio_outcome_request_with_runtime_timeout(
        runtime,
        intent,
        active_artifact_id,
        active_artifact,
        timeout,
    )
}

pub(super) fn studio_outcome_request_with_runtime_timeout(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    active_artifact_id: Option<String>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
    timeout: Duration,
) -> Result<StudioOutcomeRequest, String> {
    let trimmed_intent = intent.trim();
    if trimmed_intent.is_empty() {
        return Ok(default_studio_outcome_request(
            trimmed_intent,
            active_artifact_id,
        ));
    }

    let planning = match tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            timeout,
            plan_studio_outcome_with_runtime(
                runtime,
                trimmed_intent,
                active_artifact_id.as_deref(),
                active_artifact,
            ),
        )
        .await
    }) {
        Ok(Ok(payload)) => payload,
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            return Err(format!(
                "Studio outcome planning timed out after {}s while routing the request.",
                timeout.as_secs()
            ))
        }
    };

    let planner_execution_strategy = planning.execution_strategy;
    let mut outcome_kind = planning.outcome_kind;
    let mut needs_clarification = planning.needs_clarification;
    let mut clarification_questions = planning.clarification_questions;
    let artifact = planning.artifact;
    if outcome_kind == StudioOutcomeKind::Artifact && artifact.is_none() {
        outcome_kind = StudioOutcomeKind::Conversation;
        needs_clarification = true;
        clarification_questions.push(
            "What artifact should Studio create: document, visual, single-file interactive surface, downloadable file, or workspace project?"
                .to_string(),
        );
    }
    let requested_strategy = if outcome_kind != planning.outcome_kind
        || (outcome_kind == StudioOutcomeKind::Artifact && artifact.is_none())
    {
        execution_strategy_for_outcome(outcome_kind, artifact.as_ref())
    } else {
        planner_execution_strategy
    };
    let execution_mode_decision = derive_execution_mode_decision(
        outcome_kind,
        artifact.as_ref(),
        requested_strategy,
        planning.confidence.clamp(0.0, 1.0),
        needs_clarification,
        active_artifact_id.is_some(),
    );
    let execution_strategy = execution_mode_decision.resolved_strategy;

    Ok(StudioOutcomeRequest {
        request_id: Uuid::new_v4().to_string(),
        raw_prompt: trimmed_intent.to_string(),
        active_artifact_id,
        outcome_kind,
        execution_strategy,
        execution_mode_decision: Some(execution_mode_decision),
        confidence: planning.confidence.clamp(0.0, 1.0),
        needs_clarification,
        clarification_questions,
        artifact,
    })
}

pub(super) fn artifact_class_id_for_request(request: &StudioOutcomeArtifactRequest) -> String {
    match request.artifact_class {
        StudioArtifactClass::WorkspaceProject => "workspace_project".to_string(),
        StudioArtifactClass::CompoundBundle => "compound_bundle".to_string(),
        StudioArtifactClass::Document => "document".to_string(),
        StudioArtifactClass::Visual => "visual".to_string(),
        StudioArtifactClass::InteractiveSingleFile => "interactive_single_file".to_string(),
        StudioArtifactClass::DownloadableFile => "downloadable_file".to_string(),
        StudioArtifactClass::CodePatch => "code_patch".to_string(),
        StudioArtifactClass::ReportBundle => "report_bundle".to_string(),
    }
}

pub(super) fn renderer_kind_id(renderer: StudioRendererKind) -> &'static str {
    match renderer {
        StudioRendererKind::Markdown => "markdown",
        StudioRendererKind::HtmlIframe => "html_iframe",
        StudioRendererKind::JsxSandbox => "jsx_sandbox",
        StudioRendererKind::Svg => "svg",
        StudioRendererKind::Mermaid => "mermaid",
        StudioRendererKind::PdfEmbed => "pdf_embed",
        StudioRendererKind::DownloadCard => "download_card",
        StudioRendererKind::WorkspaceSurface => "workspace_surface",
        StudioRendererKind::BundleManifest => "bundle_manifest",
    }
}

pub(super) fn presentation_surface_id(surface: StudioPresentationSurface) -> &'static str {
    match surface {
        StudioPresentationSurface::Inline => "inline",
        StudioPresentationSurface::SidePanel => "side_panel",
        StudioPresentationSurface::Overlay => "overlay",
        StudioPresentationSurface::TabbedPanel => "tabbed_panel",
    }
}

pub(super) fn persistence_mode_id(mode: StudioArtifactPersistenceMode) -> &'static str {
    match mode {
        StudioArtifactPersistenceMode::Ephemeral => "ephemeral",
        StudioArtifactPersistenceMode::ArtifactScoped => "artifact_scoped",
        StudioArtifactPersistenceMode::SharedArtifactScoped => "shared_artifact_scoped",
        StudioArtifactPersistenceMode::WorkspaceFilesystem => "workspace_filesystem",
    }
}

pub(super) fn lifecycle_state_label(state: StudioArtifactLifecycleState) -> &'static str {
    match state {
        StudioArtifactLifecycleState::Draft => "draft",
        StudioArtifactLifecycleState::Planned => "planned",
        StudioArtifactLifecycleState::Materializing => "materializing",
        StudioArtifactLifecycleState::Rendering => "rendering",
        StudioArtifactLifecycleState::Implementing => "implementing",
        StudioArtifactLifecycleState::Verifying => "verifying",
        StudioArtifactLifecycleState::Ready => "ready",
        StudioArtifactLifecycleState::Partial => "partial",
        StudioArtifactLifecycleState::Blocked => "blocked",
        StudioArtifactLifecycleState::Failed => "failed",
    }
}

pub(super) fn summary_for_request(request: &StudioOutcomeArtifactRequest, title: &str) -> String {
    match request.renderer {
        StudioRendererKind::WorkspaceSurface => format!(
            "Studio provisioned '{}' as an artifact backed by the workspace_surface renderer and is supervising scaffold, verification, and preview under kernel authority.",
            title
        ),
        StudioRendererKind::Markdown => format!(
            "Studio created '{}' as a markdown artifact with a side-panel document surface.",
            title
        ),
        StudioRendererKind::HtmlIframe => format!(
            "Studio created '{}' as a single-file HTML artifact rendered in an isolated frame.",
            title
        ),
        StudioRendererKind::JsxSandbox => format!(
            "Studio created '{}' as a JSX sandbox artifact with source and render tabs.",
            title
        ),
        StudioRendererKind::Svg => format!(
            "Studio created '{}' as a vector artifact rendered inline.",
            title
        ),
        StudioRendererKind::Mermaid => format!(
            "Studio created '{}' as a mermaid diagram artifact with a renderable graph surface.",
            title
        ),
        StudioRendererKind::PdfEmbed => format!(
            "Studio created '{}' as a PDF artifact with inline preview and download support.",
            title
        ),
        StudioRendererKind::DownloadCard => format!(
            "Studio created '{}' as a downloadable artifact with explicit export handling.",
            title
        ),
        StudioRendererKind::BundleManifest => format!(
            "Studio created '{}' as a bundle-manifest artifact with structured source and evidence tabs.",
            title
        ),
    }
}

pub(super) fn materialization_contract_for_request(
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    summary: &str,
    execution_mode_decision: Option<StudioExecutionModeDecision>,
    execution_strategy: StudioExecutionStrategy,
) -> StudioArtifactMaterializationContract {
    let verification_steps = if request.renderer == StudioRendererKind::WorkspaceSurface {
        vec![
            verification_step("scaffold", "Scaffold workspace", "pending"),
            verification_step("install", "Install dependencies", "pending"),
            verification_step("validation", "Validate build", "pending"),
            verification_step("preview", "Verify preview", "pending"),
        ]
    } else {
        vec![
            verification_step("materialize", "Materialize artifact", "pending"),
            verification_step("verify", "Verify artifact contract", "pending"),
        ]
    };
    let mut execution_envelope = build_execution_envelope_from_swarm(
        Some(execution_strategy),
        Some("studio_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        None,
        None,
        &[],
        &[],
        &[],
        &[],
    );
    annotate_execution_envelope(
        &mut execution_envelope,
        execution_mode_decision.clone(),
        Some(completion_invariant_for_direct_execution(
            execution_strategy,
            Vec::new(),
            vec!["verify".to_string()],
            ExecutionCompletionInvariantStatus::Pending,
        )),
    );

    StudioArtifactMaterializationContract {
        version: 7,
        request_kind: artifact_class_id_for_request(request),
        normalized_intent: intent.trim().to_string(),
        summary: summary.to_string(),
        artifact_brief: None,
        preparation_needs: None,
        prepared_context_resolution: None,
        skill_discovery_resolution: None,
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        retrieved_exemplars: Vec::new(),
        edit_intent: None,
        candidate_summaries: Vec::new(),
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        execution_envelope,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        render_evaluation: None,
        judge: None,
        output_origin: None,
        production_provenance: None,
        acceptance_provenance: None,
        fallback_used: false,
        ux_lifecycle: None,
        failure: None,
        navigator_nodes: Vec::new(),
        file_writes: Vec::new(),
        command_intents: Vec::new(),
        preview_intent: None,
        verification_steps,
        pipeline_steps: Vec::new(),
        runtime_narration_events: Vec::new(),
        notes: vec![
            "Conversation remains the control plane; this artifact is the work product."
                .to_string(),
            "Renderer choice is explicit in the typed outcome request.".to_string(),
            "Verification state, not worker prose, authorizes the final Studio summary."
                .to_string(),
        ],
    }
}

pub(super) fn verification_steps_for_materialized_artifact(
    request: &StudioOutcomeArtifactRequest,
    materialized_artifact: &MaterializedContentArtifact,
) -> Vec<crate::models::StudioArtifactMaterializationVerificationStep> {
    if request.renderer == StudioRendererKind::WorkspaceSurface {
        return Vec::new();
    }

    let materialize_status = if !materialized_artifact.files.is_empty()
        || !materialized_artifact.file_writes.is_empty()
    {
        "success"
    } else if matches!(
        materialized_artifact.lifecycle_state,
        StudioArtifactLifecycleState::Failed | StudioArtifactLifecycleState::Blocked
    ) {
        "blocked"
    } else {
        "pending"
    };
    let verify_status = match materialized_artifact.lifecycle_state {
        StudioArtifactLifecycleState::Ready | StudioArtifactLifecycleState::Partial => "success",
        StudioArtifactLifecycleState::Failed | StudioArtifactLifecycleState::Blocked => "blocked",
        _ => "pending",
    };

    vec![
        verification_step("materialize", "Materialize artifact", materialize_status),
        verification_step("verify", "Verify artifact contract", verify_status),
    ]
}

pub(super) fn apply_materialized_artifact_to_contract(
    materialization: &mut StudioArtifactMaterializationContract,
    request: &StudioOutcomeArtifactRequest,
    materialized_artifact: &MaterializedContentArtifact,
    execution_mode_decision: Option<StudioExecutionModeDecision>,
    execution_strategy: StudioExecutionStrategy,
) {
    materialization.file_writes = materialized_artifact.file_writes.clone();
    materialization.notes = materialized_artifact.notes.clone();
    materialization.artifact_brief = Some(materialized_artifact.brief.clone());
    materialization.preparation_needs = materialized_artifact.preparation_needs.clone();
    materialization.prepared_context_resolution =
        materialized_artifact.prepared_context_resolution.clone();
    materialization.skill_discovery_resolution =
        materialized_artifact.skill_discovery_resolution.clone();
    materialization.blueprint = materialized_artifact.blueprint.clone();
    materialization.artifact_ir = materialized_artifact.artifact_ir.clone();
    materialization.selected_skills = materialized_artifact.selected_skills.clone();
    materialization.retrieved_exemplars = materialized_artifact.retrieved_exemplars.clone();
    materialization.edit_intent = materialized_artifact.edit_intent.clone();
    materialization.candidate_summaries = materialized_artifact.candidate_summaries.clone();
    materialization.winning_candidate_id = materialized_artifact.winning_candidate_id.clone();
    materialization.winning_candidate_rationale =
        materialized_artifact.winning_candidate_rationale.clone();
    materialization.swarm_plan = materialized_artifact.swarm_plan.clone();
    materialization.swarm_execution = materialized_artifact.swarm_execution.clone();
    materialization.swarm_worker_receipts = materialized_artifact.swarm_worker_receipts.clone();
    materialization.swarm_change_receipts = materialized_artifact.swarm_change_receipts.clone();
    materialization.swarm_merge_receipts = materialized_artifact.swarm_merge_receipts.clone();
    materialization.swarm_verification_receipts =
        materialized_artifact.swarm_verification_receipts.clone();
    materialization.verification_steps =
        verification_steps_for_materialized_artifact(request, materialized_artifact);
    materialization.execution_envelope =
        materialized_artifact
            .execution_envelope
            .clone()
            .or_else(|| {
                artifact_execution_envelope_for_contract(
                    execution_mode_decision,
                    execution_strategy,
                    materialization,
                )
            });
    materialization.render_evaluation = materialized_artifact.render_evaluation.clone();
    materialization.judge = materialized_artifact.judge.clone();
    materialization.output_origin = Some(materialized_artifact.output_origin);
    materialization.production_provenance = materialized_artifact.production_provenance.clone();
    materialization.acceptance_provenance = materialized_artifact.acceptance_provenance.clone();
    materialization.fallback_used = materialized_artifact.fallback_used;
    materialization.ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
    materialization.failure = materialized_artifact.failure.clone();
    materialization.runtime_narration_events =
        materialized_artifact.runtime_narration_events.clone();
}

pub(super) fn should_refine_current_non_workspace_artifact(
    task: &AgentTask,
    outcome_request: &StudioOutcomeRequest,
) -> bool {
    let Some(studio_session) = task.studio_session.as_ref() else {
        return false;
    };
    let Some(current_request) = studio_session.outcome_request.artifact.as_ref() else {
        return false;
    };
    let Some(next_request) = outcome_request.artifact.as_ref() else {
        return false;
    };

    current_request.renderer != StudioRendererKind::WorkspaceSurface
        && next_request.renderer != StudioRendererKind::WorkspaceSurface
        && current_request.renderer == next_request.renderer
}

pub(super) fn maybe_refine_current_non_workspace_artifact_turn(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
    outcome_request: StudioOutcomeRequest,
) -> Result<bool, String> {
    if !should_refine_current_non_workspace_artifact(task, &outcome_request) {
        return Ok(false);
    }

    let Some(mut studio_session) = task.studio_session.clone() else {
        return Ok(false);
    };
    let Some(request) = outcome_request.artifact.clone() else {
        return Ok(false);
    };
    let memory_runtime = app
        .state::<Mutex<AppState>>()
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime is unavailable for Studio refinement.".to_string())?;

    let refinement = studio_refinement_context_for_session(&memory_runtime, &studio_session);
    let thread_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
    let mut materialized_artifact = materialize_non_workspace_artifact(
        app,
        &thread_id,
        &studio_session.title,
        intent,
        &request,
        Some(&refinement),
    )?;
    let selected_targets = if materialized_artifact.selected_targets.is_empty() {
        materialized_artifact
            .edit_intent
            .as_ref()
            .map(|edit_intent| edit_intent.selected_targets.clone())
            .unwrap_or_default()
    } else {
        materialized_artifact.selected_targets.clone()
    };
    let taste_memory = derive_studio_taste_memory(
        refinement.taste_memory.as_ref(),
        &materialized_artifact.brief,
        materialized_artifact.blueprint.as_ref(),
        materialized_artifact.artifact_ir.as_ref(),
        materialized_artifact.edit_intent.as_ref(),
        materialized_artifact.judge.as_ref(),
    );
    materialized_artifact.selected_targets = selected_targets.clone();
    materialized_artifact.taste_memory = taste_memory.clone();

    let title = if matches!(
        materialized_artifact
            .edit_intent
            .as_ref()
            .map(|edit_intent| edit_intent.mode),
        Some(StudioArtifactEditMode::Replace | StudioArtifactEditMode::Create)
    ) {
        derive_artifact_title(intent)
    } else {
        studio_session.title.clone()
    };
    let summary = if materialized_artifact
        .edit_intent
        .as_ref()
        .is_some_and(|edit_intent| edit_intent.patch_existing_artifact)
    {
        format!(
            "Studio refined '{}' in place through the {} renderer and preserved revision continuity.",
            title,
            renderer_kind_id(request.renderer)
        )
    } else {
        summary_for_request(&request, &title)
    };

    task.artifacts
        .extend(materialized_artifact.artifacts.iter().cloned());

    studio_session.title = title.clone();
    studio_session.summary = summary.clone();
    studio_session.navigator_backing_mode = "logical".to_string();
    studio_session.attached_artifact_ids.extend(
        materialized_artifact
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.clone()),
    );
    studio_session.outcome_request = outcome_request.clone();
    studio_session.artifact_manifest.title = title.clone();
    studio_session.artifact_manifest.artifact_class = request.artifact_class;
    studio_session.artifact_manifest.renderer = request.renderer;
    studio_session.artifact_manifest.primary_tab =
        if request.renderer == StudioRendererKind::DownloadCard {
            "download".to_string()
        } else {
            "render".to_string()
        };
    studio_session.artifact_manifest.tabs = manifest_tabs_for_request(&request, None);
    studio_session.artifact_manifest.files = materialized_artifact.files.clone();
    studio_session.artifact_manifest.verification = StudioArtifactManifestVerification {
        status: verification_status_for_lifecycle(materialized_artifact.lifecycle_state),
        lifecycle_state: materialized_artifact.lifecycle_state,
        summary: materialized_artifact.verification_summary.clone(),
        production_provenance: materialized_artifact.production_provenance.clone(),
        acceptance_provenance: materialized_artifact.acceptance_provenance.clone(),
        failure: materialized_artifact.failure.clone(),
    };
    studio_session.available_lenses = studio_session
        .artifact_manifest
        .tabs
        .iter()
        .map(|tab| tab.id.clone())
        .collect();
    if !studio_session
        .available_lenses
        .iter()
        .any(|lens| lens == &studio_session.current_lens)
    {
        studio_session.current_lens = studio_session.artifact_manifest.primary_tab.clone();
    }

    let mut materialization = materialization_contract_for_request(
        intent,
        &request,
        &summary,
        outcome_request.execution_mode_decision.clone(),
        outcome_request.execution_strategy,
    );
    let resolved_verification_steps =
        verification_steps_for_materialized_artifact(&request, &materialized_artifact);
    materialization.file_writes = materialized_artifact.file_writes.clone();
    materialization.notes = materialized_artifact.notes.clone();
    materialization.artifact_brief = Some(materialized_artifact.brief.clone());
    materialization.preparation_needs = materialized_artifact.preparation_needs.clone();
    materialization.prepared_context_resolution =
        materialized_artifact.prepared_context_resolution.clone();
    materialization.skill_discovery_resolution =
        materialized_artifact.skill_discovery_resolution.clone();
    materialization.blueprint = materialized_artifact.blueprint.clone();
    materialization.artifact_ir = materialized_artifact.artifact_ir.clone();
    materialization.selected_skills = materialized_artifact.selected_skills.clone();
    materialization.retrieved_exemplars = materialized_artifact.retrieved_exemplars.clone();
    materialization.edit_intent = materialized_artifact.edit_intent.clone();
    materialization.candidate_summaries = materialized_artifact.candidate_summaries.clone();
    materialization.winning_candidate_id = materialized_artifact.winning_candidate_id.clone();
    materialization.winning_candidate_rationale =
        materialized_artifact.winning_candidate_rationale.clone();
    materialization.swarm_plan = materialized_artifact.swarm_plan.clone();
    materialization.swarm_execution = materialized_artifact.swarm_execution.clone();
    materialization.swarm_worker_receipts = materialized_artifact.swarm_worker_receipts.clone();
    materialization.swarm_change_receipts = materialized_artifact.swarm_change_receipts.clone();
    materialization.swarm_merge_receipts = materialized_artifact.swarm_merge_receipts.clone();
    materialization.swarm_verification_receipts =
        materialized_artifact.swarm_verification_receipts.clone();
    materialization.render_evaluation = materialized_artifact.render_evaluation.clone();
    materialization.judge = materialized_artifact.judge.clone();
    materialization.output_origin = Some(materialized_artifact.output_origin);
    materialization.production_provenance = materialized_artifact.production_provenance.clone();
    materialization.acceptance_provenance = materialized_artifact.acceptance_provenance.clone();
    materialization.fallback_used = materialized_artifact.fallback_used;
    materialization.ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
    materialization.failure = materialized_artifact.failure.clone();
    if !resolved_verification_steps.is_empty() {
        materialization.verification_steps = resolved_verification_steps;
    }
    materialization.execution_envelope =
        materialized_artifact
            .execution_envelope
            .clone()
            .or_else(|| {
                artifact_execution_envelope_for_contract(
                    outcome_request.execution_mode_decision.clone(),
                    outcome_request.execution_strategy,
                    &materialization,
                )
            });
    materialization.navigator_nodes =
        navigator_nodes_for_manifest(&studio_session.artifact_manifest);

    studio_session.materialization = materialization;
    studio_session.navigator_nodes =
        navigator_nodes_for_manifest(&studio_session.artifact_manifest);
    studio_session.verified_reply =
        verified_reply_from_manifest(&title, &studio_session.artifact_manifest);
    studio_session.lifecycle_state = materialized_artifact.lifecycle_state;
    studio_session.status =
        lifecycle_state_label(materialized_artifact.lifecycle_state).to_string();
    studio_session.taste_memory = taste_memory;
    studio_session.retrieved_exemplars = materialized_artifact.retrieved_exemplars.clone();
    studio_session.selected_targets = selected_targets;
    studio_session.ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
    studio_session.updated_at = now_iso();
    refresh_pipeline_steps(&mut studio_session, None);

    let (branch_id, branch_label, parent_revision_id) =
        revision_branch_identity(&studio_session, materialized_artifact.edit_intent.as_ref());
    let revision = revision_for_session(
        &studio_session,
        intent,
        branch_id,
        branch_label,
        parent_revision_id,
    );
    studio_session.active_revision_id = Some(revision.revision_id.clone());
    studio_session.revisions.push(revision.clone());
    match persist_studio_artifact_exemplar(
        &memory_runtime,
        app_inference_runtime(app),
        &studio_session,
        &revision,
    ) {
        Ok(Some(exemplar)) => studio_session.materialization.notes.push(format!(
            "Archived exemplar {} for {} / {}.",
            exemplar.record_id,
            renderer_kind_id(exemplar.renderer),
            exemplar.scaffold_family
        )),
        Ok(None) => {}
        Err(error) => studio_session
            .materialization
            .notes
            .push(format!("Exemplar archival skipped: {error}")),
    }

    let artifact_refs = task
        .artifacts
        .iter()
        .map(|artifact| ArtifactRef {
            artifact_id: artifact.artifact_id.clone(),
            artifact_type: artifact.artifact_type.clone(),
        })
        .collect::<Vec<_>>();
    task.events.push(build_event(
        &thread_id,
        task.progress,
        EventType::Receipt,
        format!("Studio refined {}", studio_session.title),
        json!({
            "artifact_class": artifact_class_id_for_request(&request),
            "mode": materialized_artifact
                .edit_intent
                .as_ref()
                .map(|edit_intent| format!("{:?}", edit_intent.mode).to_lowercase()),
            "revision_id": revision.revision_id,
            "branch_id": revision.branch_id,
        }),
        serde_json::to_value(&studio_session).unwrap_or_else(|_| json!({})),
        EventStatus::Success,
        artifact_refs,
        None,
        Vec::new(),
        Some(0),
    ));

    task.studio_session = Some(studio_session);
    task.renderer_session = None;
    task.build_session = None;
    Ok(true)
}
