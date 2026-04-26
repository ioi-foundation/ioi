use super::operator_run::refresh_active_operator_run_from_session;
use super::*;

pub(super) fn non_artifact_single_pass_reply_stays_chat_primary(
    outcome_request: &ChatOutcomeRequest,
) -> bool {
    outcome_request.outcome_kind == ChatOutcomeKind::Conversation
        && outcome_request.execution_strategy == ioi_types::app::ChatExecutionStrategy::SinglePass
        && !outcome_request.needs_clarification
        && !outcome_request
            .routing_hints
            .iter()
            .any(|hint| hint == "workspace_grounding_required")
        && !outcome_request
            .routing_hints
            .iter()
            .any(|hint| hint == "currentness_override")
}

pub(super) fn tool_widget_route_stays_chat_primary(outcome_request: &ChatOutcomeRequest) -> bool {
    outcome_request.outcome_kind == ChatOutcomeKind::ToolWidget
        && !outcome_request.needs_clarification
        && outcome_request.routing_hints.iter().any(|hint| {
            matches!(
                hint.as_str(),
                "tool_widget:weather"
                    | "tool_widget:recipe"
                    | "tool_widget:sports"
                    | "tool_widget:places"
            )
        })
}

pub(super) fn visualizer_route_stays_chat_primary(outcome_request: &ChatOutcomeRequest) -> bool {
    outcome_request.outcome_kind == ChatOutcomeKind::Visualizer
        && !outcome_request.needs_clarification
}

fn chat_repair_pass_count(chat_session: &ChatArtifactSession) -> usize {
    if let Some(run) = chat_session.active_operator_run.as_ref() {
        return run.repair_count as usize;
    }

    chat_session
        .materialization
        .candidate_summaries
        .iter()
        .filter_map(|candidate| candidate.convergence.as_ref())
        .filter(|trace| trace.pass_kind != "initial")
        .count()
}

fn chat_validation_obligation_counts(
    chat_session: &ChatArtifactSession,
) -> Option<(usize, usize, usize)> {
    let materialization = &chat_session.materialization;
    let evaluation = materialization.render_evaluation.as_ref().or_else(|| {
        materialization
            .candidate_summaries
            .iter()
            .find(|candidate| candidate.selected)
            .and_then(|candidate| candidate.render_evaluation.as_ref())
            .or_else(|| {
                materialization
                    .winning_candidate_id
                    .as_ref()
                    .and_then(|winner_id| {
                        materialization
                            .candidate_summaries
                            .iter()
                            .find(|candidate| &candidate.candidate_id == winner_id)
                            .and_then(|candidate| candidate.render_evaluation.as_ref())
                    })
            })
    })?;
    Some((
        evaluation.cleared_required_obligation_count(),
        evaluation.required_obligation_count(),
        evaluation.failed_required_obligation_count(),
    ))
}

fn operator_run_terminal_lifecycle(
    chat_session: &ChatArtifactSession,
) -> Option<ChatArtifactLifecycleState> {
    let active_run = chat_session.active_operator_run.as_ref()?;
    match active_run.status {
        ioi_api::runtime_harness::ArtifactOperatorRunStatus::Blocked => {
            Some(ChatArtifactLifecycleState::Blocked)
        }
        ioi_api::runtime_harness::ArtifactOperatorRunStatus::Failed => {
            Some(ChatArtifactLifecycleState::Failed)
        }
        ioi_api::runtime_harness::ArtifactOperatorRunStatus::Complete => {
            let present_step_complete = active_run.steps.iter().any(|step| {
                step.phase == ioi_api::runtime_harness::ArtifactOperatorPhase::PresentArtifact
                    && step.status == ioi_api::runtime_harness::ArtifactOperatorRunStatus::Complete
            });
            let verification_ready = chat_session.artifact_manifest.verification.lifecycle_state
                == ChatArtifactLifecycleState::Ready;
            if present_step_complete || verification_ready {
                Some(ChatArtifactLifecycleState::Ready)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn operator_run_active_step(
    chat_session: &ChatArtifactSession,
) -> Option<&ioi_api::runtime_harness::ArtifactOperatorStep> {
    let active_run = chat_session.active_operator_run.as_ref()?;
    active_run
        .steps
        .iter()
        .find(|step| step.status == ioi_api::runtime_harness::ArtifactOperatorRunStatus::Active)
        .or_else(|| {
            active_run.steps.iter().rev().find(|step| {
                matches!(
                    step.status,
                    ioi_api::runtime_harness::ArtifactOperatorRunStatus::Blocked
                        | ioi_api::runtime_harness::ArtifactOperatorRunStatus::Failed
                )
            })
        })
}

fn operator_run_active_lifecycle(
    chat_session: &ChatArtifactSession,
) -> Option<ChatArtifactLifecycleState> {
    let active_run = chat_session.active_operator_run.as_ref()?;
    if active_run.status != ioi_api::runtime_harness::ArtifactOperatorRunStatus::Active {
        return None;
    }

    let active_step = operator_run_active_step(chat_session)?;
    Some(match active_step.phase {
        ioi_api::runtime_harness::ArtifactOperatorPhase::UnderstandRequest
        | ioi_api::runtime_harness::ArtifactOperatorPhase::RouteArtifact
        | ioi_api::runtime_harness::ArtifactOperatorPhase::ReopenArtifactContext => {
            ChatArtifactLifecycleState::Planned
        }
        ioi_api::runtime_harness::ArtifactOperatorPhase::SearchSources
        | ioi_api::runtime_harness::ArtifactOperatorPhase::ReadSources => {
            ChatArtifactLifecycleState::Materializing
        }
        ioi_api::runtime_harness::ArtifactOperatorPhase::AuthorArtifact
        | ioi_api::runtime_harness::ArtifactOperatorPhase::RepairArtifact
        | ioi_api::runtime_harness::ArtifactOperatorPhase::InspectArtifact => {
            ChatArtifactLifecycleState::Implementing
        }
        ioi_api::runtime_harness::ArtifactOperatorPhase::VerifyArtifact => {
            ChatArtifactLifecycleState::Verifying
        }
        ioi_api::runtime_harness::ArtifactOperatorPhase::PresentArtifact => {
            ChatArtifactLifecycleState::Rendering
        }
        ioi_api::runtime_harness::ArtifactOperatorPhase::Other => {
            ChatArtifactLifecycleState::Implementing
        }
    })
}

fn operator_run_step_hint(chat_session: &ChatArtifactSession) -> Option<String> {
    let active_step = operator_run_active_step(chat_session)?;
    let detail = active_step.detail.trim();
    if !detail.is_empty() {
        return Some(detail.to_string());
    }
    let label = active_step.label.trim();
    if !label.is_empty() {
        return Some(label.to_string());
    }
    None
}

fn effective_chat_lifecycle_state(
    chat_session: &ChatArtifactSession,
) -> ChatArtifactLifecycleState {
    if let Some(state) = operator_run_terminal_lifecycle(chat_session) {
        return state;
    }
    let manifest_lifecycle_state = chat_session.artifact_manifest.verification.lifecycle_state;
    let manifest_terminal_state = match manifest_lifecycle_state {
        ChatArtifactLifecycleState::Ready => ChatArtifactLifecycleState::Ready,
        ChatArtifactLifecycleState::Partial => ChatArtifactLifecycleState::Partial,
        ChatArtifactLifecycleState::Blocked => ChatArtifactLifecycleState::Blocked,
        ChatArtifactLifecycleState::Failed => ChatArtifactLifecycleState::Failed,
        _ => ChatArtifactLifecycleState::Draft,
    };
    let manifest_is_terminal = matches!(
        manifest_terminal_state,
        ChatArtifactLifecycleState::Ready
            | ChatArtifactLifecycleState::Partial
            | ChatArtifactLifecycleState::Blocked
            | ChatArtifactLifecycleState::Failed
    );
    let manifest_blocked_is_final = manifest_lifecycle_state == ChatArtifactLifecycleState::Blocked
        && (chat_session
            .artifact_manifest
            .verification
            .failure
            .is_some()
            || chat_session
                .artifact_manifest
                .verification
                .summary
                .to_ascii_lowercase()
                .contains("acceptance validation blocked"));
    let manifest_should_override_active_verify = matches!(
        manifest_lifecycle_state,
        ChatArtifactLifecycleState::Ready
            | ChatArtifactLifecycleState::Partial
            | ChatArtifactLifecycleState::Failed
    ) || manifest_blocked_is_final;

    if let Some(active_step) = operator_run_active_step(chat_session) {
        if manifest_should_override_active_verify
            && active_step.phase == ioi_api::runtime_harness::ArtifactOperatorPhase::VerifyArtifact
        {
            return manifest_terminal_state;
        }
        if let Some(state) = operator_run_active_lifecycle(chat_session) {
            return state;
        }
    }

    if manifest_is_terminal {
        return manifest_terminal_state;
    }

    chat_session.lifecycle_state.clone()
}

fn chat_authoritative_step_hint(
    task: &AgentTask,
    chat_session: &ChatArtifactSession,
) -> Option<String> {
    let lifecycle_state = effective_chat_lifecycle_state(chat_session);
    if chat_session.outcome_request.outcome_kind != ChatOutcomeKind::Artifact {
        if lifecycle_state == ChatArtifactLifecycleState::Blocked
            && task.clarification_request.is_some()
        {
            return Some(
                "Chat is waiting for clarification before it can choose the right outcome surface."
                    .to_string(),
            );
        }
        return Some(if lifecycle_state == ChatArtifactLifecycleState::Blocked {
            chat_session
                .verified_reply
                .failure
                .as_ref()
                .map(|failure| failure.message.clone())
                .unwrap_or_else(|| chat_session.verified_reply.summary.clone())
        } else {
            chat_session.verified_reply.summary.clone()
        });
    }

    let candidate_count = chat_session.materialization.candidate_summaries.len();
    let repair_passes = chat_repair_pass_count(chat_session);
    let obligation_counts = chat_validation_obligation_counts(chat_session);
    let scaffold_family = chat_session
        .materialization
        .blueprint
        .as_ref()
        .map(|blueprint| blueprint.scaffold_family.as_str());

    if !matches!(
        lifecycle_state,
        ChatArtifactLifecycleState::Ready
            | ChatArtifactLifecycleState::Partial
            | ChatArtifactLifecycleState::Blocked
            | ChatArtifactLifecycleState::Failed
    ) {
        if let Some(step_hint) = operator_run_step_hint(chat_session) {
            return Some(step_hint);
        }
    }

    match lifecycle_state {
        ChatArtifactLifecycleState::Materializing => scaffold_family
            .map(|scaffold| format!("Preparing the {scaffold} artifact plan.")),
        ChatArtifactLifecycleState::Rendering | ChatArtifactLifecycleState::Implementing
            if candidate_count > 0 =>
        {
            Some(format!(
                "Drafted {candidate_count} candidate(s) and is finalizing the strongest artifact view."
            ))
        }
        ChatArtifactLifecycleState::Verifying => Some(
            scaffold_family
                .map(|scaffold| {
                    format!(
                        "Running static audits and render sanity for the {scaffold} artifact."
                    )
                })
                .unwrap_or_else(|| {
                    "Running static audits and render sanity for the artifact."
                        .to_string()
                }),
        ),
        ChatArtifactLifecycleState::Ready if candidate_count > 0 => {
            let winner = chat_session
                .materialization
                .winning_candidate_id
                .as_deref()
                .unwrap_or("winner");
            if let Some((cleared, required, failed)) = obligation_counts {
                let repair_suffix = if repair_passes > 0 {
                    format!(
                        " {repair_passes} bounded repair attempt(s) were recorded separately."
                    )
                } else {
                    String::new()
                };
                Some(format!(
                    "Chat verified {winner} after clearing {cleared}/{required} required obligations across {candidate_count} candidate(s).{}",
                    if failed > 0 {
                        format!(" {failed} required obligation(s) remained unresolved in prior attempts.")
                    } else {
                        repair_suffix
                    }
                ))
            } else {
                Some(format!(
                    "Chat verified {winner} after {candidate_count} candidate(s)."
                ))
            }
        }
        ChatArtifactLifecycleState::Partial if candidate_count > 0 => Some(format!(
            "Chat surfaced a provisional artifact after {candidate_count} candidate(s); {}",
            chat_session.artifact_manifest.verification.summary
        )),
        ChatArtifactLifecycleState::Blocked if task.clarification_request.is_none() => {
            obligation_counts.map(|(cleared, required, failed)| {
                let repair_suffix = if repair_passes > 0 {
                    format!(" after {repair_passes} bounded repair attempt(s)")
                } else {
                    String::new()
                };
                format!(
                    "Chat stopped with {failed} unresolved required obligation(s) after clearing {cleared}/{required}.{} {}",
                    repair_suffix,
                    chat_session.artifact_manifest.verification.summary
                )
            })
        }
        _ => None,
    }
}

pub(super) fn persist_current_task_update(
    state: &State<'_, Mutex<AppState>>,
    app: &AppHandle,
    task: AgentTask,
    memory_runtime: Option<Arc<MemoryRuntime>>,
) -> Result<(), String> {
    {
        let mut guard = state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        if let Some(current_task) = guard.current_task.as_mut() {
            *current_task = task.clone();
        } else {
            return Err("No active Chat task is loaded.".to_string());
        }
    }

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        orchestrator::save_local_task_state(memory_runtime, &task);
    }
    let _ = app.emit("task-updated", &task);
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        crate::kernel::session::emit_session_projection_update(&app_clone, false).await;
    });
    Ok(())
}

pub(super) fn current_task_and_memory_runtime(
    state: &State<'_, Mutex<AppState>>,
) -> Result<(AgentTask, Option<Arc<MemoryRuntime>>), String> {
    let guard = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?;
    let task = guard
        .current_task
        .clone()
        .ok_or_else(|| "No active Chat task is loaded.".to_string())?;
    Ok((task, guard.memory_runtime.clone()))
}

pub(super) fn app_inference_runtime(app: &AppHandle) -> Option<Arc<dyn InferenceRuntime>> {
    app.state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| state.inference_runtime.clone())
}

pub(super) fn app_chat_routing_inference_runtime(
    app: &AppHandle,
) -> Option<Arc<dyn InferenceRuntime>> {
    app.state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| {
            state
                .chat_routing_inference_runtime
                .clone()
                .or_else(|| state.inference_runtime.clone())
        })
}

pub(super) fn app_acceptance_inference_runtime(
    app: &AppHandle,
) -> Option<Arc<dyn InferenceRuntime>> {
    app.state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| state.acceptance_inference_runtime.clone())
}

pub fn verified_reply_summary_for_task(task: &AgentTask) -> Option<String> {
    task.chat_session
        .as_ref()
        .map(|session| session.verified_reply.summary.clone())
}

pub fn verified_reply_title_for_task(task: &AgentTask) -> Option<String> {
    task.chat_session
        .as_ref()
        .map(|session| session.verified_reply.title.clone())
}

pub fn task_requires_chat_primary_execution(task: &AgentTask) -> bool {
    let Some(chat_session) = task.chat_session.as_ref() else {
        return false;
    };
    if task.chat_outcome.is_none() {
        return false;
    }

    chat_session.outcome_request.needs_clarification
        || chat_session.outcome_request.outcome_kind == ChatOutcomeKind::Artifact
        || non_artifact_single_pass_reply_stays_chat_primary(&chat_session.outcome_request)
        || tool_widget_route_stays_chat_primary(&chat_session.outcome_request)
        || visualizer_route_stays_chat_primary(&chat_session.outcome_request)
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn task_is_chat_authoritative(task: &AgentTask) -> bool {
    task.chat_outcome.is_some() && task.chat_session.is_some()
}

pub fn apply_chat_authoritative_status(task: &mut AgentTask, current_step: Option<String>) {
    let Some(chat_session) = task.chat_session.as_ref() else {
        return;
    };
    let lifecycle_state = effective_chat_lifecycle_state(chat_session);

    if non_artifact_single_pass_reply_stays_chat_primary(&chat_session.outcome_request)
        && task.phase == AgentPhase::Complete
        && task.current_step.eq_ignore_ascii_case("ready for input")
        && task
            .history
            .iter()
            .rev()
            .any(|entry| entry.role == "agent" && !entry.text.trim().is_empty())
    {
        return;
    }

    let fallback_step = current_step.clone().unwrap_or_else(|| {
        if task.gate_info.is_some() || task.pending_request_hash.is_some() {
            let existing_step = task.current_step.trim();
            if !existing_step.is_empty() {
                return existing_step.to_string();
            }
            return "Waiting for approval".to_string();
        }
        if let Some(step) = chat_authoritative_step_hint(task, chat_session) {
            return step;
        }
        if chat_session.outcome_request.outcome_kind != ChatOutcomeKind::Artifact {
            return match lifecycle_state {
                ChatArtifactLifecycleState::Draft => {
                    "Chat captured the non-artifact route and is preparing the shared reply lane."
                        .to_string()
                }
                ChatArtifactLifecycleState::Planned
                | ChatArtifactLifecycleState::Materializing
                | ChatArtifactLifecycleState::Rendering
                | ChatArtifactLifecycleState::Implementing
                | ChatArtifactLifecycleState::Verifying => {
                    "Chat is executing the shared non-artifact route.".to_string()
                }
                ChatArtifactLifecycleState::Ready | ChatArtifactLifecycleState::Partial => {
                    "Chat completed the shared non-artifact route and is ready for the next request."
                        .to_string()
                }
                ChatArtifactLifecycleState::Blocked => {
                    "Chat could not continue the non-artifact route without clarification."
                        .to_string()
                }
                ChatArtifactLifecycleState::Failed => {
                    "Chat could not complete the non-artifact route.".to_string()
                }
            };
        }
        match lifecycle_state {
            ChatArtifactLifecycleState::Draft => {
                "Chat has created a draft artifact request.".to_string()
            }
            ChatArtifactLifecycleState::Planned => {
                "Chat planned the artifact and is preparing materialization.".to_string()
            }
            ChatArtifactLifecycleState::Materializing => {
                "Chat is materializing the requested renderer and verification pipeline."
                    .to_string()
            }
            ChatArtifactLifecycleState::Rendering => {
                "Chat is rendering the artifact surface for verification.".to_string()
            }
            ChatArtifactLifecycleState::Implementing => {
                "Chat is implementing and validating the artifact.".to_string()
            }
            ChatArtifactLifecycleState::Verifying => {
                "Chat is verifying the artifact before presenting it as ready."
                    .to_string()
            }
            ChatArtifactLifecycleState::Ready => {
                "Chat verified the artifact and is ready for the next request.".to_string()
            }
            ChatArtifactLifecycleState::Partial => {
                "Chat partially materialized the requested artifact and needs follow-up verification."
                    .to_string()
            }
            ChatArtifactLifecycleState::Blocked => {
                if task.clarification_request.is_some() {
                    "Chat is waiting for clarification before it can materialize a usable artifact."
                        .to_string()
                } else {
                    chat_session
                        .artifact_manifest
                        .verification
                        .failure
                        .as_ref()
                        .map(|failure| failure.message.clone())
                        .or_else(|| {
                            let summary = chat_session
                                .artifact_manifest
                                .verification
                                .summary
                                .trim();
                            if summary.is_empty() {
                                None
                            } else {
                                Some(summary.to_string())
                            }
                        })
                        .unwrap_or_else(|| {
                            "Chat could not verify a usable artifact surface and stopped before opening the artifact stage."
                                .to_string()
                        })
                }
            }
            ChatArtifactLifecycleState::Failed => {
                "Chat could not verify the requested artifact.".to_string()
            }
        }
    });

    if let Some(build_session) = task.build_session.as_ref() {
        if build_session.build_status.eq_ignore_ascii_case("failed")
            || build_session
                .verification_status
                .eq_ignore_ascii_case("failed")
            || chat_session.status.eq_ignore_ascii_case("failed")
        {
            task.phase = AgentPhase::Failed;
            task.current_step = build_session
                .last_failure_summary
                .clone()
                .unwrap_or(fallback_step);
            return;
        }

        if build_session
            .verification_status
            .eq_ignore_ascii_case("passed")
        {
            task.phase = AgentPhase::Complete;
            task.current_step =
                current_step.unwrap_or_else(|| "Chat workspace renderer verified.".to_string());
            return;
        }

        task.phase = AgentPhase::Running;
        task.current_step = fallback_step;
        return;
    }

    if task.gate_info.is_some() || task.pending_request_hash.is_some() {
        task.phase = AgentPhase::Gate;
        task.current_step = fallback_step;
        return;
    }

    match lifecycle_state {
        ChatArtifactLifecycleState::Ready => {
            task.phase = AgentPhase::Complete;
            task.current_step = fallback_step;
        }
        ChatArtifactLifecycleState::Partial => {
            task.phase = AgentPhase::Complete;
            task.current_step = fallback_step;
        }
        ChatArtifactLifecycleState::Blocked => {
            task.phase = if task.clarification_request.is_some() {
                AgentPhase::Gate
            } else {
                AgentPhase::Failed
            };
            task.current_step = fallback_step;
        }
        ChatArtifactLifecycleState::Draft
        | ChatArtifactLifecycleState::Planned
        | ChatArtifactLifecycleState::Materializing
        | ChatArtifactLifecycleState::Rendering
        | ChatArtifactLifecycleState::Implementing
        | ChatArtifactLifecycleState::Verifying => {
            task.phase = AgentPhase::Running;
            task.current_step = fallback_step;
        }
        ChatArtifactLifecycleState::Failed => {
            task.phase = AgentPhase::Failed;
            task.current_step = fallback_step;
        }
    }
}

pub(super) fn build_session_to_renderer_session(
    build_session: &BuildArtifactSession,
) -> ChatRendererSession {
    ChatRendererSession {
        session_id: build_session.session_id.clone(),
        chat_session_id: build_session.chat_session_id.clone(),
        renderer: ChatRendererKind::WorkspaceSurface,
        workspace_root: build_session.workspace_root.clone(),
        entry_document: build_session.entry_document.clone(),
        preview_url: build_session.preview_url.clone(),
        preview_process_id: build_session.preview_process_id,
        scaffold_recipe_id: Some(build_session.scaffold_recipe_id.clone()),
        presentation_variant_id: build_session.presentation_variant_id.clone(),
        package_manager: Some(build_session.package_manager.clone()),
        status: build_session.build_status.clone(),
        verification_status: build_session.verification_status.clone(),
        receipts: build_session.receipts.clone(),
        current_worker_execution: Some(build_session.current_worker_execution.clone()),
        current_tab: if build_session
            .ready_lenses
            .iter()
            .any(|lens| lens == "preview")
        {
            "preview".to_string()
        } else {
            "workspace".to_string()
        },
        available_tabs: vec![
            "preview".to_string(),
            "workspace".to_string(),
            "evidence".to_string(),
        ],
        ready_tabs: if build_session
            .ready_lenses
            .iter()
            .any(|lens| lens == "preview")
        {
            vec![
                "preview".to_string(),
                "workspace".to_string(),
                "evidence".to_string(),
            ]
        } else {
            vec!["workspace".to_string(), "evidence".to_string()]
        },
        retry_count: build_session.retry_count,
        last_failure_summary: build_session.last_failure_summary.clone(),
    }
}

pub(super) fn update_chat_session_from_build_session(
    chat_session: &mut ChatArtifactSession,
    build_session: Option<&BuildArtifactSession>,
) {
    if let Some(build_session) = build_session {
        let lifecycle_state = if build_session
            .verification_status
            .eq_ignore_ascii_case("passed")
        {
            ChatArtifactLifecycleState::Ready
        } else if build_session.build_status.eq_ignore_ascii_case("failed")
            || build_session
                .verification_status
                .eq_ignore_ascii_case("failed")
        {
            ChatArtifactLifecycleState::Failed
        } else if build_session
            .build_status
            .eq_ignore_ascii_case("preview-starting")
            || build_session
                .build_status
                .eq_ignore_ascii_case("preview-ready")
        {
            ChatArtifactLifecycleState::Verifying
        } else if build_session
            .build_status
            .eq_ignore_ascii_case("validating")
        {
            ChatArtifactLifecycleState::Implementing
        } else {
            ChatArtifactLifecycleState::Materializing
        };
        let status = verification_status_for_lifecycle(lifecycle_state);
        let summary = if lifecycle_state == ChatArtifactLifecycleState::Ready {
            "Preview verified and workspace lenses are ready.".to_string()
        } else if lifecycle_state == ChatArtifactLifecycleState::Failed {
            build_session
                .last_failure_summary
                .clone()
                .unwrap_or_else(|| "Workspace verification failed.".to_string())
        } else if lifecycle_state == ChatArtifactLifecycleState::Implementing {
            "Chat is implementing the workspace artifact and validating changes.".to_string()
        } else if lifecycle_state == ChatArtifactLifecycleState::Verifying {
            "Chat is verifying preview health for the workspace artifact.".to_string()
        } else {
            "Chat is still materializing the workspace renderer.".to_string()
        };

        chat_session.artifact_manifest.verification = ChatArtifactManifestVerification {
            status,
            lifecycle_state,
            summary,
            production_provenance: chat_session.materialization.production_provenance.clone(),
            acceptance_provenance: chat_session.materialization.acceptance_provenance.clone(),
            failure: chat_session.materialization.failure.clone(),
        };
        chat_session.artifact_manifest.primary_tab = if build_session
            .ready_lenses
            .iter()
            .any(|lens| lens == "preview")
        {
            "preview".to_string()
        } else {
            "workspace".to_string()
        };
        chat_session.current_lens = chat_session.artifact_manifest.primary_tab.clone();
        chat_session.available_lenses = chat_session
            .artifact_manifest
            .tabs
            .iter()
            .map(|tab| tab.id.clone())
            .collect();
        chat_session.verified_reply =
            verified_reply_from_manifest(&chat_session.title, &chat_session.artifact_manifest);
        chat_session.renderer_session_id = Some(build_session.session_id.clone());
        chat_session.lifecycle_state = lifecycle_state;
        chat_session.status = lifecycle_state_label(lifecycle_state).to_string();
        chat_session.updated_at = now_iso();
        refresh_active_operator_run_from_session(chat_session, Some(build_session));
        refresh_pipeline_steps(chat_session, Some(build_session));
        sync_workspace_manifest_file(chat_session);
    }
}
