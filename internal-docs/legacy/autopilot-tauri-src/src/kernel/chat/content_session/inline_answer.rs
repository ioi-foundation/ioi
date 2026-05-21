use super::clarification::clarification_request_for_outcome_request;
use super::decision_record::append_decision_record_event;
use super::inline_answer_surface::{
    inline_answer_domain_policy_bundle, inline_answer_manifest, refresh_inline_answer_chat_surface,
    verified_reply_for_inline_answer_route,
};
use super::*;
use ioi_api::runtime_harness::{
    apply_inline_answer_clarification_gate, inline_answer_operator_steps,
    inline_answer_route_notes, inline_answer_route_summary, inline_answer_route_title,
    inline_answer_verification_receipts, inline_answer_work_graph_plan,
    inline_answer_worker_receipts, route_decision_for_outcome_request,
};

fn outcome_kind_id(kind: ChatOutcomeKind) -> &'static str {
    match kind {
        ChatOutcomeKind::Conversation => "conversation",
        ChatOutcomeKind::ToolWidget => "tool_widget",
        ChatOutcomeKind::Visualizer => "visualizer",
        ChatOutcomeKind::Artifact => "artifact",
    }
}

fn inline_answer_work_graph_worker_receipts(
    outcome_request: &ChatOutcomeRequest,
    provenance: &crate::models::ChatRuntimeProvenance,
    work_graph_plan: &WorkGraphPlan,
) -> Vec<WorkGraphWorkerReceipt> {
    inline_answer_worker_receipts(outcome_request, provenance, work_graph_plan, &now_iso())
}

fn inline_answer_materialization_contract(
    intent: &str,
    outcome_request: &ChatOutcomeRequest,
    summary: &str,
    provenance: &crate::models::ChatRuntimeProvenance,
) -> ChatArtifactMaterializationContract {
    let route_decision = route_decision_for_outcome_request(outcome_request);
    let surface_synthetic_work_graph = outcome_request.needs_clarification
        || outcome_request.outcome_kind != ChatOutcomeKind::Conversation;
    let mut work_graph_plan = inline_answer_work_graph_plan(outcome_request);
    let (graph_mutation_receipts, replan_receipts) =
        apply_inline_answer_clarification_gate(&mut work_graph_plan, outcome_request);
    let work_graph_worker_receipts = if surface_synthetic_work_graph {
        inline_answer_work_graph_worker_receipts(outcome_request, provenance, &work_graph_plan)
    } else {
        Vec::new()
    };
    let work_graph_verification_receipts = if surface_synthetic_work_graph {
        inline_answer_verification_receipts(outcome_request)
    } else {
        Vec::new()
    };
    let verification_status = if outcome_request.needs_clarification {
        "blocked".to_string()
    } else {
        "ready".to_string()
    };
    let completed_work_items = work_graph_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                WorkGraphWorkItemStatus::Succeeded | WorkGraphWorkItemStatus::Skipped
            )
        })
        .count();
    let failed_work_items = work_graph_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                WorkGraphWorkItemStatus::Blocked
                    | WorkGraphWorkItemStatus::Failed
                    | WorkGraphWorkItemStatus::Rejected
            )
        })
        .count();
    let work_graph_execution = WorkGraphExecutionSummary {
        enabled: surface_synthetic_work_graph,
        current_stage: if outcome_request.needs_clarification {
            "routing".to_string()
        } else if route_decision.output_intent == "tool_execution" {
            "runtime_handoff".to_string()
        } else {
            "reply".to_string()
        },
        execution_stage: if surface_synthetic_work_graph {
            Some(if outcome_request.needs_clarification {
                ExecutionStage::Dispatch
            } else {
                ExecutionStage::Finalize
            })
        } else {
            None
        },
        active_worker_role: None,
        total_work_items: if surface_synthetic_work_graph {
            work_graph_plan.work_items.len()
        } else {
            0
        },
        completed_work_items: if surface_synthetic_work_graph {
            completed_work_items
        } else {
            0
        },
        failed_work_items,
        verification_status: if surface_synthetic_work_graph {
            verification_status
        } else {
            String::new()
        },
        strategy: work_graph_plan.strategy.clone(),
        execution_domain: work_graph_plan.execution_domain.clone(),
        adapter_label: work_graph_plan.adapter_label.clone(),
        parallelism_mode: work_graph_plan.parallelism_mode.clone(),
    };
    let dispatch_batches = plan_work_graph_dispatch_batches(&work_graph_plan);
    let execution_budget_summary = ExecutionBudgetSummary {
        planned_worker_count: Some(work_graph_plan.work_items.len()),
        dispatched_worker_count: Some(
            work_graph_worker_receipts
                .iter()
                .filter(|receipt| {
                    !matches!(
                        receipt.result_kind,
                        Some(WorkGraphWorkerResultKind::Blocked)
                    )
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
    let mut execution_envelope = build_execution_envelope_from_work_graph_with_receipts(
        Some(outcome_request.execution_strategy),
        Some(work_graph_plan.execution_domain.clone()),
        Some(execution_domain_kind_for_outcome(
            outcome_request.outcome_kind,
        )),
        Some(&work_graph_plan),
        Some(&work_graph_execution),
        &work_graph_worker_receipts,
        &[],
        &[],
        &work_graph_verification_receipts,
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
            &work_graph_plan,
            &work_graph_verification_receipts,
            Vec::new(),
        )),
    );

    ChatArtifactMaterializationContract {
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
        retrieved_sources: Vec::new(),
        edit_intent: None,
        candidate_summaries: Vec::new(),
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        execution_envelope,
        work_graph_execution: Some(work_graph_execution),
        work_graph_plan: Some(work_graph_plan),
        work_graph_worker_receipts,
        work_graph_change_receipts: Vec::new(),
        work_graph_merge_receipts: Vec::new(),
        work_graph_verification_receipts,
        render_evaluation: None,
        validation: None,
        output_origin: Some(output_origin_from_runtime_provenance(provenance)),
        production_provenance: Some(provenance.clone()),
        acceptance_provenance: Some(provenance.clone()),
        degraded_path_used: false,
        ux_lifecycle: Some(ChatArtifactUxLifecycle::Validated),
        failure: None,
        navigator_nodes: Vec::new(),
        file_writes: Vec::new(),
        command_intents: Vec::new(),
        preview_intent: None,
        operator_steps: inline_answer_operator_steps(outcome_request),
        pipeline_steps: Vec::new(),
        notes: vec![
            "Chat intentionally kept this request off the artifact materialization path."
                .to_string(),
            if surface_synthetic_work_graph {
                "The shared execution envelope still records plan, worker, and verification state."
                    .to_string()
            } else {
                "No synthetic work items or validation rows were projected for this conversation route."
                    .to_string()
            },
            "No renderer-specific fallback artifact was injected for this route.".to_string(),
            if outcome_request.decision_evidence.is_empty() {
                "decision_evidence:none".to_string()
            } else {
                format!(
                    "decision_evidence:{}",
                    outcome_request.decision_evidence.join(" | ")
                )
            },
        ],
    }
}

pub(in crate::kernel::chat) fn attach_inline_answer_chat_session(
    task: &mut AgentTask,
    intent: &str,
    provenance: crate::models::ChatRuntimeProvenance,
    outcome_request: &ChatOutcomeRequest,
) {
    let mut resolved_outcome_request = outcome_request.clone();
    let retained_widget_state = task
        .chat_session
        .as_ref()
        .and_then(|session| session.widget_state.as_ref());
    super::refresh_outcome_request_topology(&mut resolved_outcome_request, retained_widget_state);
    super::apply_retained_widget_state_resolution(
        &mut resolved_outcome_request,
        retained_widget_state,
    );

    let lifecycle_state = if resolved_outcome_request.needs_clarification {
        ChatArtifactLifecycleState::Blocked
    } else {
        ChatArtifactLifecycleState::Ready
    };
    let title = inline_answer_route_title(intent, &resolved_outcome_request);
    let summary = inline_answer_route_summary(&resolved_outcome_request);
    let mut materialization = inline_answer_materialization_contract(
        intent,
        &resolved_outcome_request,
        &summary,
        &provenance,
    );
    materialization
        .notes
        .extend(inline_answer_route_notes(&resolved_outcome_request));
    let domain_policy_bundle = inline_answer_domain_policy_bundle(&resolved_outcome_request, None);
    let manifest = inline_answer_manifest(
        &Uuid::new_v4().to_string(),
        &title,
        &summary,
        lifecycle_state,
        &provenance,
        &resolved_outcome_request,
        domain_policy_bundle.retained_widget_state.as_ref(),
    );
    let artifact_id = manifest.artifact_id.clone();
    let navigator_nodes = navigator_nodes_for_manifest(&manifest);
    materialization.navigator_nodes = navigator_nodes.clone();
    let created_at = now_iso();
    let mut chat_session = ChatArtifactSession {
        session_id: Uuid::new_v4().to_string(),
        thread_id: task.session_id.clone().unwrap_or_else(|| task.id.clone()),
        artifact_id,
        origin_prompt_event_id: None,
        title: title.clone(),
        summary: summary.clone(),
        current_lens: "source".to_string(),
        navigator_backing_mode: "logical".to_string(),
        navigator_nodes,
        attached_artifact_ids: Vec::new(),
        available_lenses: vec!["source".to_string(), "evidence".to_string()],
        materialization,
        outcome_request: resolved_outcome_request.clone(),
        artifact_manifest: manifest,
        verified_reply: verified_reply_for_inline_answer_route(
            &title,
            &summary,
            lifecycle_state,
            &provenance,
            &resolved_outcome_request,
        ),
        lifecycle_state,
        status: lifecycle_state_label(lifecycle_state).to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory: None,
        retrieved_exemplars: Vec::new(),
        retrieved_sources: Vec::new(),
        selected_targets: Vec::new(),
        widget_state: domain_policy_bundle.retained_widget_state.clone(),
        ux_lifecycle: Some(ChatArtifactUxLifecycle::Validated),
        active_operator_run: None,
        operator_run_history: Vec::new(),
        created_at: created_at.clone(),
        updated_at: created_at,
        build_session_id: None,
        workspace_root: None,
        renderer_session_id: None,
    };
    refresh_inline_answer_chat_surface(&mut chat_session);
    refresh_pipeline_steps(&mut chat_session, None);
    let initial_revision = initial_revision_for_session(&chat_session, intent);
    chat_session.active_revision_id = Some(initial_revision.revision_id.clone());
    chat_session.revisions = vec![initial_revision];
    task.chat_outcome = Some(resolved_outcome_request.clone());
    task.chat_session = Some(chat_session);
    task.renderer_session = None;
    task.build_session = None;
    task.gate_info = None;
    task.pending_request_hash = None;
    task.credential_request = None;
    task.clarification_request =
        clarification_request_for_outcome_request(&resolved_outcome_request);
    append_decision_record_event(
        task,
        &resolved_outcome_request,
        "Chat route decision",
        &summary,
        !resolved_outcome_request.needs_clarification,
    );
}
