use super::*;
use ioi_api::runtime_harness::{
    build_chat_decision_record_payload, build_chat_runtime_handoff_prompt_prefix,
    inline_answer_status_message as shared_inline_answer_status_message,
    runtime_route_frame_for_outcome_request,
};
use ioi_types::app::agentic::RuntimeRouteFrame;

pub(super) fn decision_evidence_item_flag(
    outcome_request: &ChatOutcomeRequest,
    needle: &str,
) -> bool {
    outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == needle || hint.starts_with(&format!("{needle}:")))
}

pub(super) fn decision_evidence_item_prefixed_value(
    outcome_request: &ChatOutcomeRequest,
    prefix: &str,
) -> Option<String> {
    outcome_request
        .decision_evidence
        .iter()
        .find_map(|hint| hint.strip_prefix(prefix))
        .map(str::to_string)
}

fn workspace_root_from_task(task: &AgentTask) -> Option<String> {
    task.build_session
        .as_ref()
        .map(|session| session.workspace_root.clone())
        .or_else(|| {
            task.renderer_session
                .as_ref()
                .map(|session| session.workspace_root.clone())
        })
        .or_else(|| {
            task.chat_session
                .as_ref()
                .and_then(|session| session.workspace_root.clone())
        })
}

pub(crate) fn runtime_handoff_prompt_prefix_for_task(task: &AgentTask) -> Option<String> {
    if super::task_state::task_requires_chat_primary_execution(task) {
        return None;
    }

    let outcome_request = task.chat_outcome.as_ref()?;
    Some(build_chat_runtime_handoff_prompt_prefix(
        outcome_request,
        workspace_root_from_task(task).as_deref(),
    ))
}

pub(crate) fn runtime_route_frame_for_task(task: &AgentTask) -> Option<RuntimeRouteFrame> {
    if super::task_state::task_requires_chat_primary_execution(task) {
        return None;
    }

    let outcome_request = task.chat_outcome.as_ref()?;
    runtime_route_frame_for_outcome_request(outcome_request)
}

fn build_decision_record_payload_with_widget_state(
    outcome_request: &ChatOutcomeRequest,
    completed: bool,
    retained_widget_state: Option<&ChatRetainedWidgetState>,
) -> serde_json::Value {
    let mut resolved_outcome_request = outcome_request.clone();
    super::refresh_outcome_request_topology(&mut resolved_outcome_request, retained_widget_state);
    build_chat_decision_record_payload(&resolved_outcome_request, completed, retained_widget_state)
}

pub(in crate::kernel::chat) fn build_decision_record_payload(
    outcome_request: &ChatOutcomeRequest,
    completed: bool,
) -> serde_json::Value {
    build_decision_record_payload_with_widget_state(outcome_request, completed, None)
}

pub(in crate::kernel::chat) fn append_decision_record_event(
    task: &mut AgentTask,
    outcome_request: &ChatOutcomeRequest,
    title: impl Into<String>,
    summary: impl Into<String>,
    completed: bool,
) -> String {
    let thread_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
    let title_text = title.into();
    let summary_text = summary.into();
    let step_index = task
        .events
        .iter()
        .map(|event| event.step_index)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let payload = build_decision_record_payload_with_widget_state(
        outcome_request,
        completed,
        task.chat_session
            .as_ref()
            .and_then(|session| session.widget_state.as_ref()),
    );
    let input_refs = task
        .events
        .last()
        .map(|event| vec![event.event_id.clone()])
        .unwrap_or_default();
    let event = build_event(
        &thread_id,
        step_index,
        EventType::Receipt,
        title_text,
        payload.clone(),
        json!({
            "summary": summary_text,
            "route_decision": payload.get("route_decision").cloned().unwrap_or_else(|| json!({})),
            "selected_route": payload.get("selected_route").cloned().unwrap_or_else(|| json!("")),
            "route_family": payload.get("route_family").cloned().unwrap_or_else(|| json!("")),
            "topology": payload.get("topology").cloned().unwrap_or_else(|| json!("single_agent")),
            "planner_authority": payload.get("planner_authority").cloned().unwrap_or_else(|| json!("kernel")),
            "verifier_state": payload.get("verifier_state").cloned().unwrap_or_else(|| json!("not_engaged")),
            "verifier_outcome": payload.get("verifier_outcome").cloned().unwrap_or(serde_json::Value::Null),
            "lane_request": payload.get("lane_request").cloned().unwrap_or(serde_json::Value::Null),
            "normalized_request": payload.get("normalized_request").cloned().unwrap_or(serde_json::Value::Null),
            "source_decision": payload.get("source_decision").cloned().unwrap_or(serde_json::Value::Null),
            "retained_lane_state": payload.get("retained_lane_state").cloned().unwrap_or(serde_json::Value::Null),
            "lane_transitions": payload.get("lane_transitions").cloned().unwrap_or_else(|| json!([])),
            "orchestration_state": payload.get("orchestration_state").cloned().unwrap_or(serde_json::Value::Null),
        }),
        EventStatus::Success,
        Vec::<ArtifactRef>::new(),
        None,
        input_refs,
        None,
    );
    let event_id = event.event_id.clone();
    task.events.push(event);
    event_id
}

pub(in crate::kernel::chat) fn inline_answer_status_message(
    outcome_request: &ChatOutcomeRequest,
) -> String {
    shared_inline_answer_status_message(outcome_request)
}

pub(in crate::kernel::chat) fn artifact_execution_envelope_for_contract(
    execution_mode_decision: Option<ChatExecutionModeDecision>,
    execution_strategy: ChatExecutionStrategy,
    materialization: &ChatArtifactMaterializationContract,
) -> Option<ExecutionEnvelope> {
    let mut envelope = build_execution_envelope_from_work_graph(
        Some(execution_strategy),
        Some("chat_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        materialization.work_graph_plan.as_ref(),
        materialization.work_graph_execution.as_ref(),
        &materialization.work_graph_worker_receipts,
        &materialization.work_graph_change_receipts,
        &materialization.work_graph_merge_receipts,
        &materialization.work_graph_verification_receipts,
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
