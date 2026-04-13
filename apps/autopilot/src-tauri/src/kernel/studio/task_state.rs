use super::*;

fn studio_repair_pass_count(studio_session: &StudioArtifactSession) -> usize {
    studio_session
        .materialization
        .candidate_summaries
        .iter()
        .filter_map(|candidate| candidate.convergence.as_ref())
        .filter(|trace| trace.pass_kind != "initial")
        .count()
}

fn studio_validation_obligation_counts(
    studio_session: &StudioArtifactSession,
) -> Option<(usize, usize, usize)> {
    let materialization = &studio_session.materialization;
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

fn studio_authoritative_step_hint(
    task: &AgentTask,
    studio_session: &StudioArtifactSession,
) -> Option<String> {
    if studio_session.outcome_request.outcome_kind != StudioOutcomeKind::Artifact {
        return Some(
            if studio_session.lifecycle_state == StudioArtifactLifecycleState::Blocked {
                studio_session
                    .verified_reply
                    .failure
                    .as_ref()
                    .map(|failure| failure.message.clone())
                    .unwrap_or_else(|| studio_session.verified_reply.summary.clone())
            } else {
                studio_session.verified_reply.summary.clone()
            },
        );
    }

    let candidate_count = studio_session.materialization.candidate_summaries.len();
    let repair_passes = studio_repair_pass_count(studio_session);
    let obligation_counts = studio_validation_obligation_counts(studio_session);
    let scaffold_family = studio_session
        .materialization
        .blueprint
        .as_ref()
        .map(|blueprint| blueprint.scaffold_family.as_str());

    match studio_session.lifecycle_state {
        StudioArtifactLifecycleState::Materializing => scaffold_family
            .map(|scaffold| format!("Preparing the {scaffold} artifact plan.")),
        StudioArtifactLifecycleState::Rendering | StudioArtifactLifecycleState::Implementing
            if candidate_count > 0 =>
        {
            Some(format!(
                "Drafted {candidate_count} candidate(s) and is finalizing the strongest artifact view."
            ))
        }
        StudioArtifactLifecycleState::Verifying => Some(
            scaffold_family
                .map(|scaffold| {
                    format!(
                        "Running static audits and acceptance verification for the {scaffold} artifact."
                    )
                })
                .unwrap_or_else(|| {
                    "Running static audits and acceptance verification for the artifact."
                        .to_string()
                }),
        ),
        StudioArtifactLifecycleState::Ready if candidate_count > 0 => {
            let winner = studio_session
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
                    "Studio verified {winner} after clearing {cleared}/{required} required obligations across {candidate_count} candidate(s).{}",
                    if failed > 0 {
                        format!(" {failed} required obligation(s) remained unresolved in prior attempts.")
                    } else {
                        repair_suffix
                    }
                ))
            } else {
                Some(format!(
                    "Studio verified {winner} after {candidate_count} candidate(s)."
                ))
            }
        }
        StudioArtifactLifecycleState::Partial if candidate_count > 0 => Some(format!(
            "Studio surfaced a provisional artifact after {candidate_count} candidate(s); {}",
            studio_session.artifact_manifest.verification.summary
        )),
        StudioArtifactLifecycleState::Blocked if task.clarification_request.is_none() => {
            obligation_counts.map(|(cleared, required, failed)| {
                let repair_suffix = if repair_passes > 0 {
                    format!(" after {repair_passes} bounded repair attempt(s)")
                } else {
                    String::new()
                };
                format!(
                    "Studio stopped with {failed} unresolved required obligation(s) after clearing {cleared}/{required}.{} {}",
                    repair_suffix,
                    studio_session.artifact_manifest.verification.summary
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
            return Err("No active Studio task is loaded.".to_string());
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
        .ok_or_else(|| "No active Studio task is loaded.".to_string())?;
    Ok((task, guard.memory_runtime.clone()))
}

pub(super) fn app_inference_runtime(app: &AppHandle) -> Option<Arc<dyn InferenceRuntime>> {
    app.state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| state.inference_runtime.clone())
}

pub(super) fn app_studio_routing_inference_runtime(
    app: &AppHandle,
) -> Option<Arc<dyn InferenceRuntime>> {
    app.state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| {
            state
                .studio_routing_inference_runtime
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
    task.studio_session
        .as_ref()
        .map(|session| session.verified_reply.summary.clone())
}

pub fn verified_reply_title_for_task(task: &AgentTask) -> Option<String> {
    task.studio_session
        .as_ref()
        .map(|session| session.verified_reply.title.clone())
}

pub fn task_is_studio_authoritative(task: &AgentTask) -> bool {
    task.studio_outcome.is_some() && task.studio_session.is_some()
}

pub fn apply_studio_authoritative_status(task: &mut AgentTask, current_step: Option<String>) {
    let Some(studio_session) = task.studio_session.as_ref() else {
        return;
    };

    let fallback_step = current_step.clone().unwrap_or_else(|| {
        if let Some(step) = studio_authoritative_step_hint(task, studio_session) {
            return step;
        }
        if studio_session.outcome_request.outcome_kind != StudioOutcomeKind::Artifact {
            return match studio_session.lifecycle_state {
                StudioArtifactLifecycleState::Draft => {
                    "Studio captured the non-artifact route and is preparing the shared reply lane."
                        .to_string()
                }
                StudioArtifactLifecycleState::Planned
                | StudioArtifactLifecycleState::Materializing
                | StudioArtifactLifecycleState::Rendering
                | StudioArtifactLifecycleState::Implementing
                | StudioArtifactLifecycleState::Verifying => {
                    "Studio is executing the shared non-artifact route.".to_string()
                }
                StudioArtifactLifecycleState::Ready | StudioArtifactLifecycleState::Partial => {
                    "Studio completed the shared non-artifact route and is ready for the next request."
                        .to_string()
                }
                StudioArtifactLifecycleState::Blocked => {
                    "Studio could not continue the non-artifact route without clarification."
                        .to_string()
                }
                StudioArtifactLifecycleState::Failed => {
                    "Studio could not complete the non-artifact route.".to_string()
                }
            };
        }
        match studio_session.lifecycle_state {
            StudioArtifactLifecycleState::Draft => {
                "Studio has created a draft artifact request.".to_string()
            }
            StudioArtifactLifecycleState::Planned => {
                "Studio planned the artifact and is preparing materialization.".to_string()
            }
            StudioArtifactLifecycleState::Materializing => {
                "Studio is materializing the requested renderer and verification pipeline."
                    .to_string()
            }
            StudioArtifactLifecycleState::Rendering => {
                "Studio is rendering the artifact surface for verification.".to_string()
            }
            StudioArtifactLifecycleState::Implementing => {
                "Studio is implementing and validating the artifact.".to_string()
            }
            StudioArtifactLifecycleState::Verifying => {
                "Studio is verifying the artifact before presenting it as ready."
                    .to_string()
            }
            StudioArtifactLifecycleState::Ready => {
                "Studio verified the artifact and is ready for the next request.".to_string()
            }
            StudioArtifactLifecycleState::Partial => {
                "Studio partially materialized the requested artifact and needs follow-up verification."
                    .to_string()
            }
            StudioArtifactLifecycleState::Blocked => {
                if task.clarification_request.is_some() {
                    "Studio is waiting for clarification before it can materialize a usable artifact."
                        .to_string()
                } else {
                    studio_session
                        .artifact_manifest
                        .verification
                        .failure
                        .as_ref()
                        .map(|failure| failure.message.clone())
                        .or_else(|| {
                            let summary = studio_session
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
                            "Studio could not verify a usable artifact surface and stopped before opening the artifact stage."
                                .to_string()
                        })
                }
            }
            StudioArtifactLifecycleState::Failed => {
                "Studio could not verify the requested artifact.".to_string()
            }
        }
    });

    if let Some(build_session) = task.build_session.as_ref() {
        if build_session.build_status.eq_ignore_ascii_case("failed")
            || build_session
                .verification_status
                .eq_ignore_ascii_case("failed")
            || studio_session.status.eq_ignore_ascii_case("failed")
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
                current_step.unwrap_or_else(|| "Studio workspace renderer verified.".to_string());
            return;
        }

        task.phase = AgentPhase::Running;
        task.current_step = fallback_step;
        return;
    }

    match studio_session.lifecycle_state {
        StudioArtifactLifecycleState::Ready => {
            task.phase = AgentPhase::Complete;
            task.current_step = fallback_step;
        }
        StudioArtifactLifecycleState::Partial => {
            task.phase = AgentPhase::Complete;
            task.current_step = fallback_step;
        }
        StudioArtifactLifecycleState::Blocked => {
            task.phase = if task.clarification_request.is_some() {
                AgentPhase::Running
            } else {
                AgentPhase::Failed
            };
            task.current_step = fallback_step;
        }
        StudioArtifactLifecycleState::Draft
        | StudioArtifactLifecycleState::Planned
        | StudioArtifactLifecycleState::Materializing
        | StudioArtifactLifecycleState::Rendering
        | StudioArtifactLifecycleState::Implementing
        | StudioArtifactLifecycleState::Verifying => {
            task.phase = AgentPhase::Running;
            task.current_step = fallback_step;
        }
        StudioArtifactLifecycleState::Failed => {
            task.phase = AgentPhase::Failed;
            task.current_step = fallback_step;
        }
    }
}

pub(super) fn build_session_to_renderer_session(
    build_session: &BuildArtifactSession,
) -> StudioRendererSession {
    StudioRendererSession {
        session_id: build_session.session_id.clone(),
        studio_session_id: build_session.studio_session_id.clone(),
        renderer: StudioRendererKind::WorkspaceSurface,
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

pub(super) fn update_studio_session_from_build_session(
    studio_session: &mut StudioArtifactSession,
    build_session: Option<&BuildArtifactSession>,
) {
    if let Some(build_session) = build_session {
        let lifecycle_state = if build_session
            .verification_status
            .eq_ignore_ascii_case("passed")
        {
            StudioArtifactLifecycleState::Ready
        } else if build_session.build_status.eq_ignore_ascii_case("failed")
            || build_session
                .verification_status
                .eq_ignore_ascii_case("failed")
        {
            StudioArtifactLifecycleState::Failed
        } else if build_session
            .build_status
            .eq_ignore_ascii_case("preview-starting")
            || build_session
                .build_status
                .eq_ignore_ascii_case("preview-ready")
        {
            StudioArtifactLifecycleState::Verifying
        } else if build_session
            .build_status
            .eq_ignore_ascii_case("validating")
        {
            StudioArtifactLifecycleState::Implementing
        } else {
            StudioArtifactLifecycleState::Materializing
        };
        let status = verification_status_for_lifecycle(lifecycle_state);
        let summary = if lifecycle_state == StudioArtifactLifecycleState::Ready {
            "Preview verified and workspace lenses are ready.".to_string()
        } else if lifecycle_state == StudioArtifactLifecycleState::Failed {
            build_session
                .last_failure_summary
                .clone()
                .unwrap_or_else(|| "Workspace verification failed.".to_string())
        } else if lifecycle_state == StudioArtifactLifecycleState::Implementing {
            "Studio is implementing the workspace artifact and validating changes.".to_string()
        } else if lifecycle_state == StudioArtifactLifecycleState::Verifying {
            "Studio is verifying preview health for the workspace artifact.".to_string()
        } else {
            "Studio is still materializing the workspace renderer.".to_string()
        };

        studio_session.artifact_manifest.verification = StudioArtifactManifestVerification {
            status,
            lifecycle_state,
            summary,
            production_provenance: studio_session.materialization.production_provenance.clone(),
            acceptance_provenance: studio_session.materialization.acceptance_provenance.clone(),
            failure: studio_session.materialization.failure.clone(),
        };
        studio_session.artifact_manifest.primary_tab = if build_session
            .ready_lenses
            .iter()
            .any(|lens| lens == "preview")
        {
            "preview".to_string()
        } else {
            "workspace".to_string()
        };
        studio_session.current_lens = studio_session.artifact_manifest.primary_tab.clone();
        studio_session.available_lenses = studio_session
            .artifact_manifest
            .tabs
            .iter()
            .map(|tab| tab.id.clone())
            .collect();
        studio_session.verified_reply =
            verified_reply_from_manifest(&studio_session.title, &studio_session.artifact_manifest);
        studio_session.renderer_session_id = Some(build_session.session_id.clone());
        studio_session.lifecycle_state = lifecycle_state;
        studio_session.status = lifecycle_state_label(lifecycle_state).to_string();
        studio_session.updated_at = now_iso();
        refresh_pipeline_steps(studio_session, Some(build_session));
        sync_workspace_manifest_file(studio_session);
    }
}
