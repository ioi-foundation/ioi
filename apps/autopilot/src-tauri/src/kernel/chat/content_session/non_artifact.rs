use super::clarification::clarification_request_for_outcome_request;
use super::non_artifact_surface::{
    non_artifact_domain_policy_bundle, non_artifact_manifest, refresh_non_artifact_chat_surface,
    verified_reply_for_non_artifact_route,
};
use super::route_contract::append_route_contract_event;
use super::*;
use ioi_api::runtime_harness::{
    apply_non_artifact_clarification_gate, non_artifact_operator_steps, non_artifact_route_notes,
    non_artifact_route_summary, non_artifact_route_title, non_artifact_swarm_plan,
    non_artifact_verification_receipts, non_artifact_worker_receipts,
};

fn outcome_kind_id(kind: ChatOutcomeKind) -> &'static str {
    match kind {
        ChatOutcomeKind::Conversation => "conversation",
        ChatOutcomeKind::ToolWidget => "tool_widget",
        ChatOutcomeKind::Visualizer => "visualizer",
        ChatOutcomeKind::Artifact => "artifact",
    }
}

fn non_artifact_swarm_worker_receipts(
    outcome_request: &ChatOutcomeRequest,
    provenance: &crate::models::ChatRuntimeProvenance,
    swarm_plan: &SwarmPlan,
) -> Vec<SwarmWorkerReceipt> {
    non_artifact_worker_receipts(outcome_request, provenance, swarm_plan, &now_iso())
}

fn non_artifact_materialization_contract(
    intent: &str,
    outcome_request: &ChatOutcomeRequest,
    summary: &str,
    provenance: &crate::models::ChatRuntimeProvenance,
) -> ChatArtifactMaterializationContract {
    let mut swarm_plan = non_artifact_swarm_plan(outcome_request);
    let (graph_mutation_receipts, replan_receipts) =
        apply_non_artifact_clarification_gate(&mut swarm_plan, outcome_request);
    let swarm_worker_receipts =
        non_artifact_swarm_worker_receipts(outcome_request, provenance, &swarm_plan);
    let swarm_verification_receipts = non_artifact_verification_receipts(outcome_request);
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
        swarm_execution: Some(swarm_execution),
        swarm_plan: Some(swarm_plan),
        swarm_worker_receipts,
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts,
        render_evaluation: None,
        validation: None,
        output_origin: Some(output_origin_from_runtime_provenance(provenance)),
        production_provenance: Some(provenance.clone()),
        acceptance_provenance: Some(provenance.clone()),
        fallback_used: false,
        ux_lifecycle: Some(ChatArtifactUxLifecycle::Validated),
        failure: None,
        navigator_nodes: Vec::new(),
        file_writes: Vec::new(),
        command_intents: Vec::new(),
        preview_intent: None,
        operator_steps: non_artifact_operator_steps(outcome_request),
        pipeline_steps: Vec::new(),
        notes: vec![
            "Chat intentionally kept this request off the artifact materialization path."
                .to_string(),
            "The shared execution envelope still records plan, worker, and verification state."
                .to_string(),
            "No renderer-specific fallback artifact was injected for this route.".to_string(),
            if outcome_request.routing_hints.is_empty() {
                "routing_hints:none".to_string()
            } else {
                format!(
                    "routing_hints:{}",
                    outcome_request.routing_hints.join(" | ")
                )
            },
        ],
    }
}

pub(in crate::kernel::chat) fn attach_non_artifact_chat_session(
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
    let title = non_artifact_route_title(intent, &resolved_outcome_request);
    let summary = non_artifact_route_summary(&resolved_outcome_request);
    let mut materialization = non_artifact_materialization_contract(
        intent,
        &resolved_outcome_request,
        &summary,
        &provenance,
    );
    materialization
        .notes
        .extend(non_artifact_route_notes(&resolved_outcome_request));
    let domain_policy_bundle = non_artifact_domain_policy_bundle(&resolved_outcome_request, None);
    let manifest = non_artifact_manifest(
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
        verified_reply: verified_reply_for_non_artifact_route(
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
    refresh_non_artifact_chat_surface(&mut chat_session);
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
    append_route_contract_event(
        task,
        &resolved_outcome_request,
        "Chat route decision",
        &summary,
        !resolved_outcome_request.needs_clarification,
    );
}
