use crate::kernel::artifacts as artifact_store;
use crate::kernel::events::build_event;
mod content_session;
mod manifest;
mod materialization;
mod pipeline;
mod prepare;
mod presentation;
mod proof;
mod revisions;
mod selection;
mod skills;
mod task_state;
mod workspace_build;
mod workspace_scaffold;
use self::content_session::{
    artifact_class_id_for_request, attach_blocked_studio_failure_session, lifecycle_state_label,
    materialization_contract_for_request, maybe_refine_current_non_workspace_artifact_turn,
    persistence_mode_id, presentation_surface_id, renderer_kind_id,
    should_refine_current_non_workspace_artifact, studio_outcome_request, summary_for_request,
    MaterializedContentArtifact,
};
use self::manifest::{
    artifact_manifest_for_request, manifest_files_for_request, manifest_tabs_for_request,
    navigator_nodes_for_manifest, verification_status_for_lifecycle, verified_reply_from_manifest,
};
#[cfg(test)]
use self::materialization::blocked_materialized_artifact_from_error;
use self::materialization::*;
#[cfg(test)]
use self::pipeline::pipeline_steps_for_state;
use self::pipeline::{build_command_intents, refresh_pipeline_steps, verification_step};
pub use self::prepare::{
    maybe_prepare_current_task_for_studio_turn, maybe_prepare_task_for_studio,
};
use self::presentation::{
    assess_materialized_artifact_presentation, finalize_presentation_assessment, truncate_preview,
    MaterializedArtifactQualityFile,
};
pub(crate) use self::proof::run_studio_current_task_turn_for_proof;
pub(crate) use self::revisions::changed_paths_between_revisions;
use self::revisions::{
    branch_artifact_revision, compare_artifact_revisions, derive_studio_taste_memory,
    initial_revision_for_session, restore_artifact_revision, revision_branch_identity,
    revision_for_session, studio_refinement_context_for_session,
};
use self::selection::attach_artifact_selection;
use self::task_state::{
    app_acceptance_inference_runtime, app_inference_runtime, app_studio_routing_inference_runtime,
    build_session_to_renderer_session, current_task_and_memory_runtime,
    persist_current_task_update, update_studio_session_from_build_session,
};
pub use self::task_state::{
    apply_studio_authoritative_status, task_is_studio_authoritative,
    verified_reply_summary_for_task, verified_reply_title_for_task,
};
#[cfg(test)]
use self::workspace_build::preview_launch_command;
use self::workspace_build::{kill_preview_process, spawn_build_supervisor};
use self::workspace_scaffold::{
    mutation_scope_for_recipe, package_name_for_title, parse_static_html_archetype_id,
    scaffold_workspace, workspace_root_for, StudioScaffoldRecipe,
};
#[cfg(test)]
use self::workspace_scaffold::{static_html_template_files, StudioStaticHtmlArchetype};
use crate::models::{
    AgentPhase, AgentTask, AppState, Artifact, ArtifactRef, BuildArtifactSession, EventStatus,
    EventType, StudioArtifactClass, StudioArtifactDeliverableShape, StudioArtifactFailure,
    StudioArtifactFailureKind, StudioArtifactLifecycleState, StudioArtifactManifest,
    StudioArtifactManifestFile, StudioArtifactManifestTab, StudioArtifactManifestVerification,
    StudioArtifactMaterializationContract, StudioArtifactMaterializationFileWrite,
    StudioArtifactMaterializationPreviewIntent, StudioArtifactPersistenceMode,
    StudioArtifactRevision, StudioArtifactSession, StudioArtifactTabKind,
    StudioArtifactVerificationStatus, StudioBuildReceipt, StudioCodeWorkerLease,
    StudioExecutionSubstrate, StudioOutcomeArtifactRequest, StudioOutcomeArtifactScope,
    StudioOutcomeArtifactVerificationRequest, StudioOutcomeKind, StudioOutcomeRequest,
    StudioPresentationSurface, StudioRendererKind, StudioRendererSession,
};
use crate::orchestrator;
#[cfg(test)]
use ioi_api::studio::materialize_studio_artifact_with_runtime;
#[cfg(test)]
use ioi_api::studio::pdf_artifact_bytes;
use ioi_api::studio::{
    plan_studio_outcome_with_runtime, StudioArtifactBrief, StudioArtifactCandidateSummary,
    StudioArtifactEditIntent, StudioArtifactEditMode, StudioArtifactJudgeResult,
    StudioArtifactOutputOrigin, StudioArtifactRefinementContext,
    StudioArtifactRuntimeNarrationEvent, StudioArtifactSelectionTarget, StudioArtifactTasteMemory,
    StudioArtifactUxLifecycle,
};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_memory::MemoryRuntime;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;

const BUILD_LENSES_IN_PROGRESS: &[&str] = &[
    "code",
    "files",
    "search",
    "source-control",
    "terminal",
    "problems",
    "output",
];
const BUILD_LENSES_READY: &[&str] = &[
    "preview",
    "code",
    "files",
    "search",
    "source-control",
    "terminal",
    "problems",
    "output",
    "ports",
];

fn merge_runtime_narration_events(
    existing: &mut Vec<StudioArtifactRuntimeNarrationEvent>,
    incoming: &[StudioArtifactRuntimeNarrationEvent],
) {
    for event in incoming {
        if existing
            .iter()
            .any(|candidate| candidate.event_id == event.event_id)
        {
            continue;
        }
        existing.push(event.clone());
    }
    existing.sort_by(|left, right| {
        left.occurred_at_ms
            .cmp(&right.occurred_at_ms)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactRevisionComparison {
    base_revision_id: String,
    target_revision_id: String,
    base_branch_label: String,
    target_branch_label: String,
    changed_paths: Vec<String>,
    summary: String,
    same_renderer: bool,
    same_title: bool,
}

#[tauri::command]
pub fn studio_retry_renderer_session(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: String,
) -> Result<(), String> {
    let task = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .current_task
        .clone()
        .ok_or_else(|| "No active Studio task is loaded.".to_string())?;

    let studio_session = task
        .studio_session
        .clone()
        .ok_or_else(|| "No Studio artifact session is attached to the current task.".to_string())?;
    let build_session = task
        .build_session
        .clone()
        .ok_or_else(|| "No workspace renderer session is active for this artifact.".to_string())?;

    if build_session.session_id != session_id {
        return Err(
            "The requested renderer session does not match the active workspace renderer."
                .to_string(),
        );
    }

    spawn_build_supervisor(app, studio_session, build_session);
    Ok(())
}

#[tauri::command]
pub fn studio_attach_artifact_selection(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    selection: StudioArtifactSelectionTarget,
) -> Result<(), String> {
    attach_artifact_selection(state, app, selection)
}

#[tauri::command]
pub fn studio_compare_artifact_revisions(
    state: State<'_, Mutex<AppState>>,
    base_revision_id: String,
    target_revision_id: String,
) -> Result<StudioArtifactRevisionComparison, String> {
    compare_artifact_revisions(state, base_revision_id, target_revision_id)
}

#[tauri::command]
pub fn studio_restore_artifact_revision(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    revision_id: String,
) -> Result<(), String> {
    restore_artifact_revision(state, app, revision_id)
}

#[tauri::command]
pub fn studio_branch_artifact_revision(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    revision_id: String,
) -> Result<StudioArtifactRevision, String> {
    branch_artifact_revision(state, app, revision_id)
}

#[cfg(test)]
mod tests;
