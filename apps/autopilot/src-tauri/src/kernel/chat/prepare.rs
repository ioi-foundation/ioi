use super::content_session::attach_non_artifact_chat_session;
use super::operator_run::{
    refresh_active_operator_run_from_session, start_operator_run_for_session,
};
use super::revisions::persist_chat_artifact_exemplar;
use super::*;
use crate::models::ChatMessage;
use ioi_api::execution::{ExecutionEnvelope, ExecutionStage};
use ioi_api::runtime_harness::{
    ArtifactOperatorRunMode, ChatArtifactExemplar as ChatArtifactExemplar,
    ChatArtifactGenerationProgress as ChatArtifactGenerationProgress,
    ChatArtifactMergeReceipt as ChatArtifactMergeReceipt,
    ChatArtifactPatchReceipt as ChatArtifactPatchReceipt,
    ChatArtifactSwarmExecutionSummary as ChatArtifactSwarmExecutionSummary,
    ChatArtifactSwarmPlan as ChatArtifactSwarmPlan,
    ChatArtifactVerificationReceipt as ChatArtifactVerificationReceipt,
    ChatArtifactWorkerReceipt as ChatArtifactWorkerReceipt,
};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::ChatExecutionStrategy as ChatExecutionStrategy;

#[path = "prepare/places.rs"]
mod places;
#[path = "prepare/sports.rs"]
mod sports;
#[path = "prepare/weather.rs"]
mod weather;

fn publish_current_task_progress(
    app: &AppHandle,
    task: &mut AgentTask,
    current_step: impl Into<String>,
) {
    task.phase = AgentPhase::Running;
    task.current_step = current_step.into();
    publish_current_task_snapshot(app, task);
}

pub(super) fn publish_current_task_snapshot(app: &AppHandle, task: &AgentTask) {
    let task_id = task.id.clone();
    let task_snapshot = task.clone();
    let state = app.state::<Mutex<AppState>>();
    let mut memory_runtime = None;
    let mut replaced_current_task = false;

    if let Ok(mut guard) = state.lock() {
        memory_runtime = guard.memory_runtime.clone();
        if let Some(current_task) = guard.current_task.as_mut() {
            if current_task.id == task_id {
                *current_task = task_snapshot.clone();
                replaced_current_task = true;
            }
        }
    }

    if !replaced_current_task {
        return;
    }

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        orchestrator::save_local_task_state(memory_runtime, &task_snapshot);
    }

    let _ = app.emit("task-updated", &task_snapshot);
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        crate::kernel::session::emit_session_projection_update(&app_clone, false).await;
    });
}

fn build_direct_inline_conversation_prompt(intent: &str) -> String {
    format!(
        "You are Autopilot Chat's direct inline reply path.\n\
Answer the user's request directly.\n\
Constraints:\n\
- Answer in plain prose with no preamble about tools, routing, or process.\n\
- Do not mention unavailable tools or system internals.\n\
- Avoid markdown headings unless the user explicitly asked for structure.\n\
- Keep the answer compact but complete for a normal chat turn.\n\
- If the request truly cannot be answered safely without fresh external information, say that briefly instead of inventing details.\n\
\n\
User request:\n{intent}\n"
    )
}

fn tool_widget_family_hint(outcome_request: &ChatOutcomeRequest) -> Option<&str> {
    outcome_request
        .routing_hints
        .iter()
        .find_map(|hint| hint.strip_prefix("tool_widget:"))
}

#[cfg(test)]
pub(super) fn extract_weather_scopes(intent: &str) -> Vec<String> {
    weather::extract_weather_scopes(intent)
}

#[cfg(test)]
pub(super) fn parse_weather_report_fallback(scope: &str, body: &str) -> Option<String> {
    weather::parse_weather_report_fallback(scope, body)
}

#[cfg(test)]
pub(super) fn weather_scopes_for_tool_widget(
    intent: &str,
    outcome_request: &ChatOutcomeRequest,
) -> Vec<String> {
    weather::weather_scopes_for_tool_widget(intent, outcome_request)
}


fn build_recipe_tool_widget_prompt(intent: &str) -> String {
    format!(
        "You are Autopilot Chat's recipe reply path.\n\
Answer the user's recipe request directly.\n\
Constraints:\n\
- Give a practical recipe sized to the user's request.\n\
- Include ingredients and concise numbered steps.\n\
- Keep the answer compact and kitchen-usable.\n\
- Do not mention tools, routing, or system internals.\n\
\n\
User request:\n{intent}\n"
    )
}

fn build_visualizer_reply_prompt(intent: &str) -> String {
    format!(
        "You are Autopilot Chat's inline visualizer reply path.\n\
Return only a mermaid fenced code block that satisfies the user's request.\n\
Constraints:\n\
- Start with ```mermaid and end with ```.\n\
- Keep the diagram compact, readable, and semantically correct.\n\
- Do not add prose before or after the fenced block.\n\
\n\
User request:\n{intent}\n"
    )
}

fn complete_recipe_tool_widget_reply(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
) -> Result<String, String> {
    let runtime = app_inference_runtime(app)
        .or_else(|| app_chat_routing_inference_runtime(app))
        .ok_or_else(|| {
            "Chat recipe reply is unavailable because inference is missing.".to_string()
        })?;

    publish_current_task_progress(app, task, "Drafting the recipe...");
    let prompt = build_recipe_tool_widget_prompt(intent);
    let options = InferenceOptions {
        temperature: 0.2,
        json_mode: false,
        max_tokens: 1024,
        ..Default::default()
    };

    let bytes = tauri::async_runtime::block_on(runtime.execute_inference(
        [0u8; 32],
        prompt.as_bytes(),
        options,
    ))
    .map_err(|error| format!("Chat recipe reply inference failed: {error}"))?;
    let reply = match String::from_utf8(bytes.clone()) {
        Ok(value) => value,
        Err(_) => String::from_utf8_lossy(&bytes).to_string(),
    };
    let cleaned = reply.trim().to_string();
    if cleaned.is_empty() {
        return Err("Chat recipe reply returned empty output.".to_string());
    }
    Ok(cleaned)
}

fn complete_visualizer_reply(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
) -> Result<String, String> {
    let runtime = app_inference_runtime(app)
        .or_else(|| app_chat_routing_inference_runtime(app))
        .ok_or_else(|| {
            "Chat visualizer reply is unavailable because inference is missing.".to_string()
        })?;

    publish_current_task_progress(app, task, "Drafting the inline visualizer...");
    let prompt = build_visualizer_reply_prompt(intent);
    let options = InferenceOptions {
        temperature: 0.1,
        json_mode: false,
        max_tokens: 768,
        ..Default::default()
    };

    let bytes = tauri::async_runtime::block_on(runtime.execute_inference(
        [0u8; 32],
        prompt.as_bytes(),
        options,
    ))
    .map_err(|error| format!("Chat visualizer inference failed: {error}"))?;
    let reply = match String::from_utf8(bytes.clone()) {
        Ok(value) => value,
        Err(_) => String::from_utf8_lossy(&bytes).to_string(),
    };
    let cleaned = reply.trim().to_string();
    if cleaned.is_empty() {
        return Err("Chat visualizer reply returned empty output.".to_string());
    }
    if cleaned.starts_with("```mermaid") {
        return Ok(cleaned);
    }
    Ok(format!("```mermaid\n{}\n```", cleaned))
}

fn finalize_chat_primary_non_artifact_reply(
    app: &AppHandle,
    task: &mut AgentTask,
    outcome_request: &ChatOutcomeRequest,
    reply: String,
    route_execution_evidence: &str,
    completion_summary: &str,
) {
    let timestamp = crate::kernel::state::now();

    if let Some(chat_session) = task.chat_session.as_mut() {
        chat_session.summary = reply.clone();
        chat_session.lifecycle_state = ChatArtifactLifecycleState::Ready;
        chat_session.status = "ready".to_string();
        chat_session.updated_at = now_iso();
        chat_session.verified_reply.status = ChatArtifactVerificationStatus::Ready;
        chat_session.verified_reply.lifecycle_state = ChatArtifactLifecycleState::Ready;
        chat_session.verified_reply.summary = reply.clone();
        if !chat_session
            .verified_reply
            .evidence
            .iter()
            .any(|entry| entry == route_execution_evidence)
        {
            chat_session
                .verified_reply
                .evidence
                .push(route_execution_evidence.to_string());
        }
        chat_session.verified_reply.updated_at = chat_session.updated_at.clone();
        super::content_session::refresh_non_artifact_chat_surface(chat_session);
    }

    task.phase = AgentPhase::Complete;
    task.progress = task.total_steps.max(1);
    task.total_steps = task.total_steps.max(1);
    task.current_step = "Ready for input".to_string();
    task.history.push(ChatMessage {
        role: "agent".to_string(),
        text: reply,
        timestamp,
    });
    super::content_session::append_route_contract_event(
        task,
        outcome_request,
        "Chat reply completed",
        completion_summary,
        true,
    );
    publish_current_task_snapshot(app, task);
}

fn complete_direct_inline_conversation_reply(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
) -> Result<String, String> {
    let runtime = app_inference_runtime(app)
        .or_else(|| app_chat_routing_inference_runtime(app))
        .ok_or_else(|| {
            "Chat direct inline reply is unavailable because inference is missing.".to_string()
        })?;

    publish_current_task_progress(app, task, "Drafting the direct answer...");
    let prompt = build_direct_inline_conversation_prompt(intent);
    let options = InferenceOptions {
        temperature: 0.2,
        json_mode: false,
        max_tokens: 1024,
        ..Default::default()
    };

    let bytes = tauri::async_runtime::block_on(runtime.execute_inference(
        [0u8; 32],
        prompt.as_bytes(),
        options,
    ))
    .map_err(|error| format!("Chat direct inline reply inference failed: {error}"))?;
    let reply = match String::from_utf8(bytes.clone()) {
        Ok(value) => value,
        Err(_) => String::from_utf8_lossy(&bytes).to_string(),
    };
    let cleaned = reply.trim().to_string();
    if cleaned.is_empty() {
        return Err("Chat direct inline reply returned empty output.".to_string());
    }
    Ok(cleaned)
}

pub(super) fn maybe_execute_chat_primary_non_artifact_reply(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
    outcome_request: &ChatOutcomeRequest,
) -> Result<bool, String> {
    let (reply, route_execution_evidence, completion_summary) =
        if super::task_state::non_artifact_single_pass_reply_stays_chat_primary(outcome_request) {
            (
                complete_direct_inline_conversation_reply(app, task, intent)?,
                "route_execution:chat_direct_inline",
                "Chat completed the direct inline route and preserved the final route contract.",
            )
        } else if super::task_state::tool_widget_route_stays_chat_primary(outcome_request) {
            match tool_widget_family_hint(outcome_request) {
                Some("weather") => {
                    publish_current_task_progress(app, task, "Fetching the current weather...");
                    (
                        weather::fetch_weather_tool_widget_reply(intent, outcome_request)?,
                        "route_execution:chat_tool_widget_weather",
                        "Chat completed the weather tool-widget route directly and preserved the final route contract.",
                    )
                }
                Some("recipe") => (
                    complete_recipe_tool_widget_reply(app, task, intent)?,
                    "route_execution:chat_tool_widget_recipe",
                    "Chat completed the recipe tool-widget route directly and preserved the final route contract.",
                ),
                Some("sports") => {
                    publish_current_task_progress(app, task, "Checking the latest team data...");
                    (
                        sports::fetch_sports_tool_widget_reply(intent)?,
                        "route_execution:chat_tool_widget_sports",
                        "Chat completed the sports tool-widget route directly and preserved the final route contract.",
                    )
                }
                Some("places") => {
                    publish_current_task_progress(app, task, "Finding nearby places...");
                    (
                        places::format_places_tool_widget_reply(intent, outcome_request)?,
                        "route_execution:chat_tool_widget_places",
                        "Chat completed the places tool-widget route directly and preserved the final route contract.",
                    )
                }
                _ => return Ok(false),
            }
        } else if super::task_state::visualizer_route_stays_chat_primary(outcome_request) {
            (
                complete_visualizer_reply(app, task, intent)?,
                "route_execution:chat_visualizer_inline",
                "Chat completed the inline visualizer route directly and preserved the final route contract.",
            )
        } else {
            return Ok(false);
        };

    finalize_chat_primary_non_artifact_reply(
        app,
        task,
        outcome_request,
        reply,
        route_execution_evidence,
        completion_summary,
    );
    Ok(true)
}

fn lifecycle_state_for_generation_progress(
    progress: &ChatArtifactGenerationProgress,
) -> ChatArtifactLifecycleState {
    let stage = progress
        .execution_envelope
        .as_ref()
        .and_then(|envelope| envelope.execution_summary.as_ref())
        .and_then(|summary| summary.execution_stage);
    match stage {
        Some(ExecutionStage::Plan) | Some(ExecutionStage::Dispatch) => {
            ChatArtifactLifecycleState::Materializing
        }
        Some(ExecutionStage::Work) | Some(ExecutionStage::Mutate) | Some(ExecutionStage::Merge) => {
            ChatArtifactLifecycleState::Implementing
        }
        Some(ExecutionStage::Verify) | Some(ExecutionStage::Finalize) => {
            ChatArtifactLifecycleState::Verifying
        }
        None => ChatArtifactLifecycleState::Materializing,
    }
}

fn latest_user_request_event_id(task: &AgentTask) -> Option<String> {
    task.events.iter().rev().find_map(|event| {
        let is_user_input = event
            .details
            .get("kind")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("user_input"));
        is_user_input.then(|| event.event_id.clone())
    })
}

pub(super) fn publish_current_task_generation_progress(
    app: &AppHandle,
    task_id: &str,
    progress: &ChatArtifactGenerationProgress,
) {
    let task_snapshot = {
        let state = app.state::<Mutex<AppState>>();
        let Ok(mut guard) = state.lock() else {
            return;
        };
        let Some(task) = guard.current_task.as_mut() else {
            return;
        };
        if task.id != task_id {
            return;
        }

        task.phase = AgentPhase::Running;
        task.current_step = progress.current_step.clone();
        if let Some(session) = task.chat_session.as_mut() {
            let session_origin_prompt_event_id = session.origin_prompt_event_id.clone();
            assign_chat_session_turn_ownership(session, session_origin_prompt_event_id.as_deref());
            if progress.artifact_brief.is_some()
                || progress.preparation_needs.is_some()
                || progress.prepared_context_resolution.is_some()
                || progress.skill_discovery_resolution.is_some()
                || progress.blueprint.is_some()
                || progress.artifact_ir.is_some()
                || !progress.selected_skills.is_empty()
                || !progress.retrieved_exemplars.is_empty()
                || !progress.retrieved_sources.is_empty()
            {
                session.materialization.artifact_brief = progress.artifact_brief.clone();
                session.materialization.preparation_needs = progress.preparation_needs.clone();
                session.materialization.prepared_context_resolution =
                    progress.prepared_context_resolution.clone();
                session.materialization.skill_discovery_resolution =
                    progress.skill_discovery_resolution.clone();
                session.materialization.blueprint = progress.blueprint.clone();
                session.materialization.artifact_ir = progress.artifact_ir.clone();
                session.materialization.selected_skills = progress.selected_skills.clone();
                session.materialization.retrieved_exemplars = progress.retrieved_exemplars.clone();
                session.materialization.retrieved_sources = progress.retrieved_sources.clone();
            }
            session.materialization.execution_envelope = progress.execution_envelope.clone();
            session.materialization.swarm_plan = progress.swarm_plan.clone();
            session.materialization.swarm_execution = progress.swarm_execution.clone();
            session.materialization.swarm_worker_receipts = progress.swarm_worker_receipts.clone();
            session.materialization.swarm_change_receipts = progress.swarm_change_receipts.clone();
            session.materialization.swarm_merge_receipts = progress.swarm_merge_receipts.clone();
            session.materialization.swarm_verification_receipts =
                progress.swarm_verification_receipts.clone();
            if progress.render_evaluation.is_some() {
                session.materialization.render_evaluation = progress.render_evaluation.clone();
            }
            if progress.validation.is_some() {
                session.materialization.validation = progress.validation.clone();
            }
            if !progress.operator_steps.is_empty() {
                let mut operator_steps = progress.operator_steps.clone();
                let origin_prompt_event_id =
                    session_origin_prompt_event_id.clone().unwrap_or_default();
                for step in &mut operator_steps {
                    if step.origin_prompt_event_id.trim().is_empty() {
                        step.origin_prompt_event_id = origin_prompt_event_id.clone();
                    }
                    if let Some(preview) = step.preview.as_mut() {
                        if preview.origin_prompt_event_id.trim().is_empty() {
                            preview.origin_prompt_event_id = origin_prompt_event_id.clone();
                        }
                    }
                }
                session.materialization.operator_steps = operator_steps;
            }
            session.lifecycle_state = lifecycle_state_for_generation_progress(progress);
            session.status = lifecycle_state_label(session.lifecycle_state).to_string();
            session.updated_at = now_iso();
            session.artifact_manifest.verification.summary = progress.current_step.clone();
            session.verified_reply.summary = progress.current_step.clone();
            refresh_active_operator_run_from_session(session, None);
            refresh_pipeline_steps(session, None);
        }
        if task_requires_chat_primary_execution(task) {
            apply_chat_authoritative_status(task, None);
        }

        task.clone()
    };

    publish_current_task_snapshot(app, &task_snapshot);
}

pub(super) fn provisional_non_workspace_chat_session(
    thread_id: &str,
    chat_session_id: &str,
    title: &str,
    summary: &str,
    created_at: &str,
    outcome_request: &ChatOutcomeRequest,
    origin_prompt_event_id: Option<&str>,
    materialization: ChatArtifactMaterializationContract,
) -> Result<ChatArtifactSession, String> {
    let artifact_request = outcome_request
        .artifact
        .as_ref()
        .ok_or_else(|| "Chat artifact outcome missing artifact request".to_string())?;
    let lifecycle_state = ChatArtifactLifecycleState::Materializing;
    let mut artifact_manifest =
        artifact_manifest_for_request(title, artifact_request, &[], None, None, lifecycle_state);
    artifact_manifest.verification.summary = materialization
        .blueprint
        .as_ref()
        .map(|blueprint| format!("Preparing the {} artifact plan.", blueprint.scaffold_family))
        .unwrap_or_else(|| "Preparing the artifact plan.".to_string());
    artifact_manifest.verification.production_provenance =
        materialization.production_provenance.clone();
    artifact_manifest.verification.acceptance_provenance =
        materialization.acceptance_provenance.clone();
    let retrieved_exemplars = materialization.retrieved_exemplars.clone();
    let retrieved_sources = materialization.retrieved_sources.clone();
    let mut chat_session = ChatArtifactSession {
        session_id: chat_session_id.to_string(),
        thread_id: thread_id.to_string(),
        artifact_id: artifact_manifest.artifact_id.clone(),
        origin_prompt_event_id: origin_prompt_event_id.map(ToOwned::to_owned),
        title: title.to_string(),
        summary: summary.to_string(),
        current_lens: artifact_manifest.primary_tab.clone(),
        navigator_backing_mode: "logical".to_string(),
        navigator_nodes: navigator_nodes_for_manifest(&artifact_manifest),
        attached_artifact_ids: Vec::new(),
        available_lenses: artifact_manifest
            .tabs
            .iter()
            .map(|tab| tab.id.clone())
            .collect(),
        materialization,
        outcome_request: outcome_request.clone(),
        artifact_manifest: artifact_manifest.clone(),
        verified_reply: verified_reply_from_manifest(title, &artifact_manifest),
        lifecycle_state,
        status: lifecycle_state_label(lifecycle_state).to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory: None,
        retrieved_exemplars,
        retrieved_sources,
        selected_targets: Vec::new(),
        widget_state: None,
        ux_lifecycle: None,
        active_operator_run: None,
        operator_run_history: Vec::new(),
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        build_session_id: None,
        workspace_root: None,
        renderer_session_id: None,
    };
    assign_chat_session_turn_ownership(&mut chat_session, origin_prompt_event_id);
    start_operator_run_for_session(
        &mut chat_session,
        origin_prompt_event_id,
        ArtifactOperatorRunMode::Create,
    );
    refresh_active_operator_run_from_session(&mut chat_session, None);
    refresh_pipeline_steps(&mut chat_session, None);
    Ok(chat_session)
}

pub(super) fn seed_provisional_artifact_route_state(
    task: &mut AgentTask,
    outcome_request: &ChatOutcomeRequest,
    summary: &str,
    chat_session: ChatArtifactSession,
    build_session: Option<BuildArtifactSession>,
    renderer_session: Option<ChatRendererSession>,
) {
    task.chat_outcome = Some(outcome_request.clone());
    task.chat_session = Some(chat_session);
    task.build_session = build_session;
    task.renderer_session = renderer_session;
    super::content_session::append_route_contract_event(
        task,
        outcome_request,
        "Chat route decision",
        summary,
        false,
    );
}

pub fn maybe_prepare_task_for_chat(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
) -> Result<(), String> {
    publish_current_task_progress(app, task, "Routing the request...");
    let active_artifact_id = task
        .chat_session
        .as_ref()
        .map(|session| session.artifact_id.clone());
    let active_refinement = task.chat_session.as_ref().and_then(|session| {
        app.state::<Mutex<AppState>>()
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .memory_runtime
                    .as_ref()
                    .map(|runtime| chat_refinement_context_for_session(runtime, session))
            })
    });
    let active_widget_state = task
        .chat_session
        .as_ref()
        .and_then(|session| session.widget_state.as_ref());
    if let Some(runtime) = app_chat_routing_inference_runtime(app) {
        if runtime.chat_runtime_provenance().kind
            == crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable
        {
            let failure = ChatArtifactFailure {
                kind: ChatArtifactFailureKind::InferenceUnavailable,
                code: "inference_unavailable".to_string(),
                message:
                    "Chat cannot route or materialize artifacts because inference is unavailable."
                        .to_string(),
            };
            attach_blocked_chat_failure_session(
                task,
                intent,
                active_artifact_id,
                runtime.chat_runtime_provenance(),
                failure,
            );
            return Ok(());
        }
    } else {
        attach_blocked_chat_failure_session(
            task,
            intent,
            active_artifact_id,
            crate::models::ChatRuntimeProvenance {
                kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            },
            ChatArtifactFailure {
                kind: ChatArtifactFailureKind::InferenceUnavailable,
                code: "inference_unavailable".to_string(),
                message: "Chat cannot route or materialize artifacts because inference runtime is unavailable."
                    .to_string(),
            },
        );
        return Ok(());
    }
    let outcome_request = match chat_outcome_request(
        app,
        intent,
        active_artifact_id.clone(),
        active_refinement.as_ref(),
        active_widget_state,
    ) {
        Ok(outcome_request) => outcome_request,
        Err(error) => {
            let provenance = app_chat_routing_inference_runtime(app)
                .map(|runtime| runtime.chat_runtime_provenance())
                .unwrap_or(crate::models::ChatRuntimeProvenance {
                    kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
                    label: "inference unavailable".to_string(),
                    model: None,
                    endpoint: None,
                });
            attach_blocked_chat_failure_session(
                task,
                intent,
                active_artifact_id,
                provenance,
                ChatArtifactFailure {
                    kind: ChatArtifactFailureKind::RoutingFailure,
                    code: "routing_failure".to_string(),
                    message: error,
                },
            );
            return Ok(());
        }
    };
    task.chat_outcome = Some(outcome_request.clone());

    if outcome_request.needs_clarification {
        let provenance = app_chat_routing_inference_runtime(app)
            .map(|runtime| runtime.chat_runtime_provenance())
            .unwrap_or(crate::models::ChatRuntimeProvenance {
                kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            });
        attach_non_artifact_chat_session(task, intent, provenance, &outcome_request);
        apply_non_artifact_route_state(task, &outcome_request);
        publish_current_task_snapshot(app, task);
        return Ok(());
    }

    if outcome_request.outcome_kind != ChatOutcomeKind::Artifact {
        let provenance = app_chat_routing_inference_runtime(app)
            .map(|runtime| runtime.chat_runtime_provenance())
            .unwrap_or(crate::models::ChatRuntimeProvenance {
                kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            });
        attach_non_artifact_chat_session(task, intent, provenance, &outcome_request);
        apply_non_artifact_route_state(task, &outcome_request);
        if maybe_execute_chat_primary_non_artifact_reply(app, task, intent, &outcome_request)? {
            return Ok(());
        }
        if task_requires_chat_primary_execution(task) {
            apply_chat_authoritative_status(task, None);
        }
        publish_current_task_snapshot(app, task);
        return Ok(());
    }

    maybe_prepare_task_for_chat_with_request(app, task, intent, outcome_request)
}

fn maybe_prepare_task_for_chat_with_request(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
    outcome_request: ChatOutcomeRequest,
) -> Result<(), String> {
    let origin_prompt_event_id = latest_user_request_event_id(task);
    let artifact_request = outcome_request
        .artifact
        .clone()
        .ok_or_else(|| "Chat artifact outcome missing artifact request".to_string())?;
    let renderer_kind = artifact_request.renderer;
    let thread_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
    let title = derive_artifact_title(intent);
    let summary = summary_for_request(&artifact_request, &title);
    let chat_session_id = Uuid::new_v4().to_string();
    let created_at = now_iso();
    let mut attached_artifact_ids = Vec::new();
    let mut manifest_files: Vec<ChatArtifactManifestFile> = Vec::new();
    let mut materialization = materialization_contract_for_request(
        intent,
        &artifact_request,
        &summary,
        outcome_request.execution_mode_decision.clone(),
        outcome_request.execution_strategy,
    );
    let workspace_root = if renderer_kind == ChatRendererKind::WorkspaceSurface {
        Some(workspace_root_for(app, &chat_session_id))
    } else {
        None
    };
    let mut initial_lifecycle_state = if renderer_kind == ChatRendererKind::WorkspaceSurface {
        ChatArtifactLifecycleState::Materializing
    } else {
        ChatArtifactLifecycleState::Ready
    };
    let mut non_workspace_verification_summary: Option<String> = None;
    let mut artifact_brief: Option<ChatArtifactBrief> = None;
    let mut edit_intent: Option<ChatArtifactEditIntent> = None;
    let mut candidate_summaries = Vec::<ChatArtifactCandidateSummary>::new();
    let mut winning_candidate_id: Option<String> = None;
    let mut winning_candidate_rationale: Option<String> = None;
    let mut execution_envelope: Option<ExecutionEnvelope> = None;
    let mut swarm_plan: Option<ChatArtifactSwarmPlan> = None;
    let mut swarm_execution: Option<ChatArtifactSwarmExecutionSummary> = None;
    let mut swarm_worker_receipts = Vec::<ChatArtifactWorkerReceipt>::new();
    let mut swarm_change_receipts = Vec::<ChatArtifactPatchReceipt>::new();
    let mut swarm_merge_receipts = Vec::<ChatArtifactMergeReceipt>::new();
    let mut swarm_verification_receipts = Vec::<ChatArtifactVerificationReceipt>::new();
    let mut render_evaluation: Option<ioi_api::runtime_harness::ArtifactRenderEvaluation> =
        None;
    let mut validation: Option<ChatArtifactValidationResult> = None;
    let mut output_origin: Option<ChatArtifactOutputOrigin> = None;
    let mut production_provenance: Option<crate::models::ChatRuntimeProvenance> = None;
    let mut acceptance_provenance: Option<crate::models::ChatRuntimeProvenance> = None;
    let mut fallback_used = false;
    let mut ux_lifecycle: Option<ChatArtifactUxLifecycle> = None;
    let mut failure: Option<crate::models::ChatArtifactFailure> = None;
    let mut taste_memory: Option<ChatArtifactTasteMemory> = None;
    let mut retrieved_exemplars = Vec::<ChatArtifactExemplar>::new();
    let mut selected_targets = Vec::<ChatArtifactSelectionTarget>::new();
    let mut final_materialized_artifact: Option<
        super::content_session::MaterializedContentArtifact,
    > = None;
    let connector_grounding =
        ioi_api::runtime_harness::artifact_connector_grounding_for_outcome_request(
            &outcome_request,
        );
    let app_runtime_provenance =
        app_inference_runtime(app).map(|runtime| runtime.chat_runtime_provenance());
    let app_acceptance_runtime_provenance =
        app_acceptance_inference_runtime(app).map(|runtime| runtime.chat_runtime_provenance());

    if renderer_kind == ChatRendererKind::WorkspaceSurface {
        production_provenance = Some(app_runtime_provenance.clone().unwrap_or(
            crate::models::ChatRuntimeProvenance {
                kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            },
        ));
        acceptance_provenance = Some(app_acceptance_runtime_provenance.clone().unwrap_or(
            crate::models::ChatRuntimeProvenance {
                kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            },
        ));
        output_origin = production_provenance
            .as_ref()
            .map(output_origin_from_runtime_provenance);
    }

    let mut build_session = if let Some(root) = workspace_root.as_ref() {
        let recipe = select_workspace_recipe(&artifact_request);
        let package_name = package_name_for_title(&title);
        let scaffold = scaffold_workspace(
            recipe,
            artifact_request
                .presentation_variant_id
                .as_deref()
                .and_then(parse_static_html_archetype_id),
            root,
            &title,
            &package_name,
        )?;
        materialization.file_writes = scaffold.file_writes.clone();
        materialization.command_intents = build_command_intents();
        materialization.preview_intent = Some(ChatArtifactMaterializationPreviewIntent {
            label: "Preview lane".to_string(),
            url: None,
            status: "pending".to_string(),
        });
        for step in &mut materialization.operator_steps {
            if step.step_id == "workspace_scaffold" {
                step.status = ioi_api::runtime_harness::ArtifactOperatorRunStatus::Complete;
                step.detail = "Scaffold workspace completed.".to_string();
                step.finished_at_ms = Some(step.finished_at_ms.unwrap_or(0));
            }
        }
        Some(BuildArtifactSession {
            session_id: Uuid::new_v4().to_string(),
            chat_session_id: chat_session_id.clone(),
            workspace_root: root.to_string_lossy().to_string(),
            entry_document: recipe.entry_document().to_string(),
            preview_url: None,
            preview_process_id: None,
            scaffold_recipe_id: recipe.id().to_string(),
            presentation_variant_id: artifact_request.presentation_variant_id.clone(),
            package_manager: "npm".to_string(),
            build_status: "scaffolded".to_string(),
            verification_status: "pending".to_string(),
            receipts: vec![ChatBuildReceipt {
                receipt_id: Uuid::new_v4().to_string(),
                kind: "scaffold".to_string(),
                title: format!("Scaffolded {} workspace", recipe.label()),
                status: "success".to_string(),
                summary: format!(
                    "Materialized {} starter files in {} using the {} recipe.",
                    scaffold.file_writes.len(),
                    root.display(),
                    recipe.label()
                ),
                started_at: created_at.clone(),
                finished_at: Some(now_iso()),
                artifact_ids: Vec::new(),
                command: None,
                exit_code: Some(0),
                duration_ms: Some(0),
                failure_class: None,
                replay_classification: Some("replay_safe".to_string()),
            }],
            current_worker_execution: ChatCodeWorkerLease {
                backend: "hosted-fallback".to_string(),
                planner_authority: "kernel".to_string(),
                allowed_mutation_scope: mutation_scope_for_recipe(root, recipe),
                allowed_command_classes: vec![
                    "install".to_string(),
                    "build".to_string(),
                    "preview".to_string(),
                    "repair".to_string(),
                ],
                execution_state: "preparing".to_string(),
                retry_classification: Some("retry_required".to_string()),
                last_summary: Some(format!(
                    "Kernel owns routing. Chat materialized a {} workspace so the artifact can open real code and preview lenses under bounded supervision.",
                    recipe.label()
                )),
            },
            current_lens: "code".to_string(),
            available_lenses: BUILD_LENSES_IN_PROGRESS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            ready_lenses: vec!["code".to_string()],
            retry_count: 0,
            last_failure_summary: None,
        })
    } else {
        None
    };

    let renderer_session = build_session
        .as_ref()
        .map(build_session_to_renderer_session);

    if build_session.is_some() {
        publish_current_task_progress(app, task, "Selecting workspace scaffold...");
        let mut provisional_session = provisional_non_workspace_chat_session(
            &thread_id,
            &chat_session_id,
            &title,
            &summary,
            &created_at,
            &outcome_request,
            origin_prompt_event_id.as_deref(),
            materialization.clone(),
        )?;
        provisional_session.navigator_backing_mode = "workspace".to_string();
        provisional_session.workspace_root = workspace_root
            .as_ref()
            .map(|root| root.to_string_lossy().to_string());
        provisional_session.build_session_id = build_session
            .as_ref()
            .map(|session| session.session_id.clone());
        seed_provisional_artifact_route_state(
            task,
            &outcome_request,
            &summary,
            provisional_session,
            build_session.clone(),
            renderer_session.clone(),
        );
        publish_current_task_snapshot(app, task);
    } else {
        publish_current_task_progress(
            app,
            task,
            if outcome_request.execution_strategy == ChatExecutionStrategy::DirectAuthor {
                "Understanding the artifact request..."
            } else {
                "Planning artifact blueprint..."
            },
        );
        materialization.production_provenance = app_runtime_provenance.clone();
        materialization.acceptance_provenance = app_acceptance_runtime_provenance
            .clone()
            .or_else(|| app_runtime_provenance.clone());
        task.chat_session = Some(provisional_non_workspace_chat_session(
            &thread_id,
            &chat_session_id,
            &title,
            &summary,
            &created_at,
            &outcome_request,
            origin_prompt_event_id.as_deref(),
            materialization.clone(),
        )?);
        super::content_session::append_route_contract_event(
            task,
            &outcome_request,
            "Chat route decision",
            &summary,
            false,
        );
        publish_current_task_snapshot(app, task);
        let progress_app = app.clone();
        let progress_task_id = task.id.clone();
        let progress_observer =
            std::sync::Arc::new(move |progress: ChatArtifactGenerationProgress| {
                publish_current_task_generation_progress(
                    &progress_app,
                    &progress_task_id,
                    &progress,
                );
            });
        let materialized_artifact =
            materialize_non_workspace_artifact_with_execution_strategy_and_progress_observer(
                app,
                &thread_id,
                &title,
                intent,
                &artifact_request,
                None,
                connector_grounding.as_ref(),
                outcome_request.execution_strategy,
                Some(progress_observer),
            )?;
        publish_current_task_progress(
            app,
            task,
            if outcome_request.execution_strategy == ChatExecutionStrategy::DirectAuthor {
                "Evaluating rendered artifact...".to_string()
            } else if let Some(blueprint) = materialized_artifact.blueprint.as_ref() {
                format!(
                    "Running static audits and render sanity for the {} scaffold...",
                    blueprint.scaffold_family
                )
            } else {
                "Running static audits and render sanity...".to_string()
            },
        );
        initial_lifecycle_state = materialized_artifact.lifecycle_state;
        non_workspace_verification_summary =
            Some(materialized_artifact.verification_summary.clone());
        artifact_brief = Some(materialized_artifact.brief.clone());
        edit_intent = materialized_artifact.edit_intent.clone();
        candidate_summaries = materialized_artifact.candidate_summaries.clone();
        winning_candidate_id = materialized_artifact.winning_candidate_id.clone();
        winning_candidate_rationale = materialized_artifact.winning_candidate_rationale.clone();
        execution_envelope = materialized_artifact.execution_envelope.clone();
        swarm_plan = materialized_artifact.swarm_plan.clone();
        swarm_execution = materialized_artifact.swarm_execution.clone();
        swarm_worker_receipts = materialized_artifact.swarm_worker_receipts.clone();
        swarm_change_receipts = materialized_artifact.swarm_change_receipts.clone();
        swarm_merge_receipts = materialized_artifact.swarm_merge_receipts.clone();
        swarm_verification_receipts = materialized_artifact.swarm_verification_receipts.clone();
        render_evaluation = materialized_artifact.render_evaluation.clone();
        validation = materialized_artifact.validation.clone();
        output_origin = Some(materialized_artifact.output_origin);
        production_provenance = materialized_artifact.production_provenance.clone();
        acceptance_provenance = materialized_artifact.acceptance_provenance.clone();
        fallback_used = materialized_artifact.fallback_used;
        ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
        failure = materialized_artifact.failure.clone();
        taste_memory = materialized_artifact.taste_memory.clone();
        retrieved_exemplars = materialized_artifact.retrieved_exemplars.clone();
        selected_targets = materialized_artifact.selected_targets.clone();
        attached_artifact_ids.extend(
            materialized_artifact
                .artifacts
                .iter()
                .map(|artifact| artifact.artifact_id.clone()),
        );
        task.artifacts
            .extend(materialized_artifact.artifacts.clone());
        manifest_files = materialized_artifact.files.clone();
        materialization
            .file_writes
            .extend(materialized_artifact.file_writes.clone());
        materialization
            .notes
            .extend(materialized_artifact.notes.clone());
        final_materialized_artifact = Some(materialized_artifact);
    }

    publish_current_task_progress(app, task, "Finalizing artifact session...");
    let mut artifact_manifest = artifact_manifest_for_request(
        &title,
        &artifact_request,
        &attached_artifact_ids,
        build_session.as_ref(),
        renderer_session.as_ref(),
        initial_lifecycle_state,
    );

    if let Some(build) = build_session.as_mut() {
        if let Some(receipt_artifact) =
            create_receipt_report_artifact(app, &thread_id, &title, &build.receipts[0])
        {
            build.receipts[0]
                .artifact_ids
                .push(receipt_artifact.artifact_id.clone());
            attached_artifact_ids.push(receipt_artifact.artifact_id.clone());
            task.artifacts.push(receipt_artifact);
        }
    }

    if let Some(materialized_artifact) = final_materialized_artifact.as_ref() {
        super::content_session::apply_materialized_artifact_to_contract(
            &mut materialization,
            &artifact_request,
            materialized_artifact,
            outcome_request.execution_mode_decision.clone(),
            outcome_request.execution_strategy,
        );
    } else {
        materialization.artifact_brief = artifact_brief.clone();
        materialization.edit_intent = edit_intent.clone();
        materialization.candidate_summaries = candidate_summaries.clone();
        materialization.winning_candidate_id = winning_candidate_id.clone();
        materialization.winning_candidate_rationale = winning_candidate_rationale.clone();
        materialization.swarm_plan = swarm_plan.clone();
        materialization.swarm_execution = swarm_execution.clone();
        materialization.swarm_worker_receipts = swarm_worker_receipts.clone();
        materialization.swarm_change_receipts = swarm_change_receipts.clone();
        materialization.swarm_merge_receipts = swarm_merge_receipts.clone();
        materialization.swarm_verification_receipts = swarm_verification_receipts.clone();
        materialization.execution_envelope = execution_envelope.clone().or_else(|| {
            super::content_session::artifact_execution_envelope_for_contract(
                outcome_request.execution_mode_decision.clone(),
                outcome_request.execution_strategy,
                &materialization,
            )
        });
        materialization.render_evaluation = render_evaluation;
        materialization.validation = validation.clone();
        materialization.output_origin = output_origin;
        materialization.production_provenance = production_provenance.clone();
        materialization.acceptance_provenance = acceptance_provenance.clone();
        materialization.fallback_used = fallback_used;
        materialization.ux_lifecycle = ux_lifecycle;
        materialization.failure = failure.clone();
        materialization.retrieved_exemplars = retrieved_exemplars.clone();
    }

    if let Some(artifact) = create_contract_artifact(app, &thread_id, &title, &materialization) {
        attached_artifact_ids.push(artifact.artifact_id.clone());
        task.artifacts.push(artifact);
    }

    artifact_manifest.artifact_id = attached_artifact_ids
        .first()
        .cloned()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    artifact_manifest.files = if manifest_files.is_empty() {
        manifest_files_for_request(&artifact_request, build_session.as_ref())
    } else {
        manifest_files
    };
    if let Some(summary) = non_workspace_verification_summary {
        artifact_manifest.verification = ChatArtifactManifestVerification {
            status: verification_status_for_lifecycle(initial_lifecycle_state),
            lifecycle_state: initial_lifecycle_state,
            summary,
            production_provenance: production_provenance.clone(),
            acceptance_provenance: acceptance_provenance.clone(),
            failure: failure.clone(),
        };
    }
    materialization.navigator_nodes = navigator_nodes_for_manifest(&artifact_manifest);
    let verified_reply = verified_reply_from_manifest(&title, &artifact_manifest);
    let prior_operator_run = task
        .chat_session
        .as_ref()
        .and_then(|session| session.active_operator_run.clone());
    let prior_operator_run_history = task
        .chat_session
        .as_ref()
        .map(|session| session.operator_run_history.clone())
        .unwrap_or_default();

    let retrieved_sources = materialization.retrieved_sources.clone();
    let mut chat_session = ChatArtifactSession {
        session_id: chat_session_id.clone(),
        thread_id: thread_id.clone(),
        artifact_id: attached_artifact_ids
            .first()
            .cloned()
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        origin_prompt_event_id: origin_prompt_event_id.clone(),
        title,
        summary,
        current_lens: artifact_manifest.primary_tab.clone(),
        navigator_backing_mode: if renderer_kind == ChatRendererKind::WorkspaceSurface {
            "workspace".to_string()
        } else {
            "logical".to_string()
        },
        navigator_nodes: navigator_nodes_for_manifest(&artifact_manifest),
        attached_artifact_ids,
        available_lenses: artifact_manifest
            .tabs
            .iter()
            .map(|tab| tab.id.clone())
            .collect(),
        materialization,
        outcome_request: outcome_request.clone(),
        artifact_manifest,
        verified_reply,
        lifecycle_state: initial_lifecycle_state,
        status: lifecycle_state_label(initial_lifecycle_state).to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory,
        retrieved_exemplars,
        retrieved_sources,
        selected_targets,
        widget_state: None,
        ux_lifecycle,
        active_operator_run: prior_operator_run,
        operator_run_history: prior_operator_run_history,
        created_at: created_at.clone(),
        updated_at: created_at,
        build_session_id: build_session
            .as_ref()
            .map(|session| session.session_id.clone()),
        workspace_root: workspace_root
            .as_ref()
            .map(|root| root.to_string_lossy().to_string()),
        renderer_session_id: renderer_session
            .as_ref()
            .map(|session| session.session_id.clone()),
    };
    assign_chat_session_turn_ownership(&mut chat_session, origin_prompt_event_id.as_deref());
    if chat_session.active_operator_run.is_some() {
        refresh_active_operator_run_from_session(&mut chat_session, build_session.as_ref());
    } else {
        start_operator_run_for_session(
            &mut chat_session,
            origin_prompt_event_id.as_deref(),
            ArtifactOperatorRunMode::Create,
        );
        refresh_active_operator_run_from_session(&mut chat_session, build_session.as_ref());
    }
    refresh_pipeline_steps(&mut chat_session, build_session.as_ref());
    let initial_revision = initial_revision_for_session(&chat_session, intent);
    chat_session.active_revision_id = Some(initial_revision.revision_id.clone());
    chat_session.revisions = vec![initial_revision];
    if let Some(initial_revision) = chat_session.revisions.first().cloned() {
        if let Some(memory_runtime) = app
            .state::<Mutex<AppState>>()
            .lock()
            .ok()
            .and_then(|state| state.memory_runtime.clone())
        {
            match persist_chat_artifact_exemplar(
                &memory_runtime,
                app_inference_runtime(app),
                &chat_session,
                &initial_revision,
            ) {
                Ok(Some(exemplar)) => chat_session.materialization.notes.push(format!(
                    "Archived exemplar {} for {} / {}.",
                    exemplar.record_id,
                    renderer_kind_id(exemplar.renderer),
                    exemplar.scaffold_family
                )),
                Ok(None) => {}
                Err(error) => chat_session
                    .materialization
                    .notes
                    .push(format!("Exemplar archival skipped: {error}")),
            }
        }
    }
    sync_workspace_manifest_file(&chat_session);

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
        format!("Chat created {}", chat_session.title),
        json!({
            "artifact_class": artifact_class_id_for_request(&artifact_request),
            "navigator_backing_mode": chat_session.navigator_backing_mode,
            "build_session_id": chat_session.build_session_id,
            "selected_route": super::content_session::build_route_contract_payload(
                &outcome_request,
                false,
            )
            .get("selected_route")
            .cloned()
            .unwrap_or_else(|| json!("artifact")),
            "route_family": super::content_session::build_route_contract_payload(
                &outcome_request,
                false,
            )
            .get("route_family")
            .cloned()
            .unwrap_or_else(|| json!("artifacts")),
            "topology": super::content_session::build_route_contract_payload(
                &outcome_request,
                false,
            )
            .get("topology")
            .cloned()
            .unwrap_or_else(|| json!("planner_specialist")),
            "planner_authority": "kernel",
            "verifier_state": super::content_session::build_route_contract_payload(
                &outcome_request,
                false,
            )
            .get("verifier_state")
            .cloned()
            .unwrap_or_else(|| json!("active")),
            "route_decision": super::content_session::build_route_contract_payload(
                &outcome_request,
                false,
            )
            .get("route_decision")
            .cloned()
            .unwrap_or_else(|| json!({})),
        }),
        {
            let mut details = serde_json::to_value(&chat_session).unwrap_or_else(|_| json!({}));
            if let Some(details_object) = details.as_object_mut() {
                let payload =
                    super::content_session::build_route_contract_payload(&outcome_request, false);
                details_object.insert(
                    "selected_route".to_string(),
                    payload["selected_route"].clone(),
                );
                details_object.insert("route_family".to_string(), payload["route_family"].clone());
                details_object.insert("topology".to_string(), payload["topology"].clone());
                details_object.insert(
                    "planner_authority".to_string(),
                    payload["planner_authority"].clone(),
                );
                details_object.insert(
                    "verifier_state".to_string(),
                    payload["verifier_state"].clone(),
                );
                details_object.insert(
                    "verifier_outcome".to_string(),
                    payload["verifier_outcome"].clone(),
                );
                details_object.insert(
                    "route_decision".to_string(),
                    payload["route_decision"].clone(),
                );
            }
            details
        },
        EventStatus::Success,
        artifact_refs,
        None,
        Vec::new(),
        Some(0),
    ));

    task.chat_session = Some(chat_session.clone());
    task.renderer_session = renderer_session.clone();
    task.build_session = build_session.clone();

    if let Some(build_session) = build_session {
        spawn_build_supervisor(app.clone(), chat_session, build_session);
    }

    Ok(())
}

pub fn maybe_prepare_current_task_for_chat_turn(
    app: &AppHandle,
    intent: &str,
) -> Result<(), String> {
    println!(
        "[Autopilot][ChatContinue] maybe_prepare_current_task_for_chat_turn intent={}",
        intent
    );
    let state = app.state::<Mutex<AppState>>();
    let (mut task, memory_runtime) = {
        let guard = state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        let Some(task) = guard.current_task.clone() else {
            return Ok(());
        };
        (task, guard.memory_runtime.clone())
    };
    let origin_prompt_event_id = latest_user_request_event_id(&task);
    let current_artifact_id = task
        .chat_session
        .as_ref()
        .map(|session| session.artifact_id.clone());
    let active_refinement = task.chat_session.as_ref().and_then(|session| {
        memory_runtime
            .as_ref()
            .map(|runtime| chat_refinement_context_for_session(runtime, session))
    });
    let active_widget_state = task
        .chat_session
        .as_ref()
        .and_then(|session| session.widget_state.as_ref());
    let outcome_request = chat_outcome_request(
        app,
        intent,
        current_artifact_id,
        active_refinement.as_ref(),
        active_widget_state,
    )?;
    println!(
        "[Autopilot][ChatContinue] routed follow-up outcome_kind={:?} hints={:?}",
        outcome_request.outcome_kind, outcome_request.routing_hints
    );

    task.chat_outcome = Some(outcome_request.clone());

    let previous_build_session_id = task
        .build_session
        .as_ref()
        .map(|session| session.session_id.clone());
    let previous_chat_session_id = task
        .chat_session
        .as_ref()
        .map(|session| session.session_id.clone());
    let previous_artifact_count = task.artifacts.len();
    let previous_phase = task.phase.clone();
    let previous_current_step = task.current_step.clone();
    let previous_outcome_request_id = task
        .chat_outcome
        .as_ref()
        .map(|request| request.request_id.clone());
    let previous_chat_lifecycle = task
        .chat_session
        .as_ref()
        .map(|session| session.lifecycle_state);
    let previous_revision_count = task
        .chat_session
        .as_ref()
        .map(|session| session.revisions.len());
    let previous_file_count = task
        .chat_session
        .as_ref()
        .map(|session| session.artifact_manifest.files.len());

    if outcome_request.outcome_kind == ChatOutcomeKind::Artifact
        && !outcome_request.needs_clarification
    {
        if !maybe_refine_current_non_workspace_artifact_turn(
            app,
            &mut task,
            intent,
            outcome_request.clone(),
        )? {
            maybe_prepare_task_for_chat_with_request(app, &mut task, intent, outcome_request)?;
        }
    } else {
        if outcome_request.outcome_kind != ChatOutcomeKind::Artifact {
            let provenance = app_chat_routing_inference_runtime(app)
                .map(|runtime| runtime.chat_runtime_provenance())
                .unwrap_or(crate::models::ChatRuntimeProvenance {
                    kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
                    label: "inference unavailable".to_string(),
                    model: None,
                    endpoint: None,
                });
            attach_non_artifact_chat_session(&mut task, intent, provenance, &outcome_request);
        }
        apply_non_artifact_route_state(&mut task, &outcome_request);
        maybe_execute_chat_primary_non_artifact_reply(app, &mut task, intent, &outcome_request)?;
    }

    if let Some(session) = task.chat_session.as_mut() {
        assign_chat_session_turn_ownership(session, origin_prompt_event_id.as_deref());
    }

    if task_requires_chat_primary_execution(&task) {
        apply_chat_authoritative_status(&mut task, None);
    }

    let chat_changed = previous_chat_session_id
        != task
            .chat_session
            .as_ref()
            .map(|session| session.session_id.clone());
    let build_changed = previous_build_session_id
        != task
            .build_session
            .as_ref()
            .map(|session| session.session_id.clone());
    let artifacts_changed = previous_artifact_count != task.artifacts.len();
    let phase_changed = previous_phase != task.phase;
    let current_step_changed = previous_current_step != task.current_step;
    let outcome_changed = previous_outcome_request_id
        != task
            .chat_outcome
            .as_ref()
            .map(|request| request.request_id.clone());
    let lifecycle_changed = previous_chat_lifecycle
        != task
            .chat_session
            .as_ref()
            .map(|session| session.lifecycle_state);
    let revision_count_changed = previous_revision_count
        != task
            .chat_session
            .as_ref()
            .map(|session| session.revisions.len());
    let file_count_changed = previous_file_count
        != task
            .chat_session
            .as_ref()
            .map(|session| session.artifact_manifest.files.len());

    if !chat_changed
        && !build_changed
        && !artifacts_changed
        && !phase_changed
        && !current_step_changed
        && !outcome_changed
        && !lifecycle_changed
        && !revision_count_changed
        && !file_count_changed
    {
        println!("[Autopilot][ChatContinue] follow-up produced no material task change");
        return Ok(());
    }

    if let Some(previous_build_session_id) = previous_build_session_id {
        if task
            .build_session
            .as_ref()
            .is_none_or(|session| session.session_id != previous_build_session_id)
        {
            kill_preview_process(&previous_build_session_id);
        }
    }

    {
        let mut guard = state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        if let Some(current_task) = guard.current_task.as_mut() {
            *current_task = task.clone();
        }
    }

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        orchestrator::save_local_task_state(memory_runtime, &task);
    }

    let _ = app.emit("task-updated", &task);
    println!(
        "[Autopilot][ChatContinue] follow-up task updated phase={:?} current_step={}",
        task.phase, task.current_step
    );
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        crate::kernel::session::emit_session_projection_update(&app_clone, false).await;
    });
    Ok(())
}

pub(super) fn apply_non_artifact_route_state(
    task: &mut AgentTask,
    outcome_request: &ChatOutcomeRequest,
) {
    task.current_step = if outcome_request.outcome_kind == ChatOutcomeKind::Artifact {
        task.current_step.clone()
    } else {
        super::content_session::non_artifact_route_status_message(outcome_request)
    };
}

#[cfg(test)]
#[path = "prepare/tests.rs"]
mod tests;
