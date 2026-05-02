use crate::kernel::artifacts as artifact_store;
use crate::kernel::events::build_event;
mod content_session;
mod manifest;
mod materialization;
mod operator_run;
mod pipeline;
mod prepare;
mod presentation;
mod proof;
mod revisions;
mod selection;
mod skills;
mod source_research;
mod task_state;
mod workspace_build;
mod workspace_scaffold;
pub(crate) use self::content_session::runtime_handoff_prompt_prefix_for_task;
pub(crate) use self::content_session::seed_task_route_from_intent_signals;
use self::content_session::{
    artifact_class_id_for_request, attach_blocked_chat_failure_session, chat_outcome_request,
    lifecycle_state_label, materialization_contract_for_request,
    maybe_refine_current_non_workspace_artifact_turn, persistence_mode_id, presentation_surface_id,
    renderer_kind_id, should_refine_current_non_workspace_artifact, summary_for_request,
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
use self::pipeline::{build_command_intents, refresh_pipeline_steps};
pub use self::prepare::{maybe_prepare_current_task_for_chat_turn, maybe_prepare_task_for_chat};
use self::presentation::{
    assess_materialized_artifact_presentation, finalize_presentation_assessment, truncate_preview,
    MaterializedArtifactQualityFile,
};
pub(crate) use self::proof::run_chat_current_task_turn_for_proof;
pub(crate) use self::revisions::changed_paths_between_revisions;
use self::revisions::{
    branch_artifact_revision, chat_refinement_context_for_session, compare_artifact_revisions,
    derive_chat_taste_memory, initial_revision_for_session, restore_artifact_revision,
    revision_branch_identity, revision_for_session,
};
use self::selection::{attach_artifact_selection, attach_widget_state};
use self::task_state::{
    app_acceptance_inference_runtime, app_chat_routing_inference_runtime, app_inference_runtime,
    build_session_to_renderer_session, current_task_and_memory_runtime,
    persist_current_task_update, update_chat_session_from_build_session,
};
#[allow(unused_imports)]
pub use self::task_state::{
    apply_chat_authoritative_status, task_is_chat_authoritative,
    task_requires_chat_primary_execution, verified_reply_summary_for_task,
    verified_reply_title_for_task,
};
#[cfg(test)]
use self::workspace_build::preview_launch_command;
use self::workspace_build::{kill_preview_process, spawn_build_supervisor};
use self::workspace_scaffold::{
    mutation_scope_for_recipe, package_name_for_title, parse_static_html_archetype_id,
    scaffold_workspace, workspace_root_for, ChatScaffoldRecipe,
};
#[cfg(test)]
use self::workspace_scaffold::{static_html_template_files, ChatStaticHtmlArchetype};
use crate::models::{
    AgentPhase, AgentTask, AppState, Artifact, ArtifactRef, BuildArtifactSession,
    ChatArtifactClass, ChatArtifactDeliverableShape, ChatArtifactFailure, ChatArtifactFailureKind,
    ChatArtifactLifecycleState, ChatArtifactManifest, ChatArtifactManifestFile,
    ChatArtifactManifestTab, ChatArtifactManifestVerification, ChatArtifactMaterializationContract,
    ChatArtifactMaterializationFileWrite, ChatArtifactMaterializationPreviewIntent,
    ChatArtifactPersistenceMode, ChatArtifactRevision, ChatArtifactSession, ChatArtifactTabKind,
    ChatArtifactVerificationStatus, ChatBuildReceipt, ChatCodeWorkerLease, ChatExecutionSubstrate,
    ChatOutcomeArtifactRequest, ChatOutcomeArtifactScope, ChatOutcomeArtifactVerificationRequest,
    ChatOutcomeKind, ChatOutcomeRequest, ChatPresentationSurface, ChatRendererKind,
    ChatRendererSession, ChatRetainedWidgetState, EventStatus, EventType,
};
use crate::orchestrator;
#[cfg(test)]
use ioi_api::chat::materialize_chat_artifact_with_runtime;
#[cfg(test)]
use ioi_api::chat::pdf_artifact_bytes;
use ioi_api::chat::{
    plan_chat_outcome_with_runtime, ChatArtifactBrief, ChatArtifactCandidateSummary,
    ChatArtifactEditIntent, ChatArtifactEditMode, ChatArtifactOutputOrigin,
    ChatArtifactRefinementContext, ChatArtifactSelectionTarget, ChatArtifactTasteMemory,
    ChatArtifactUxLifecycle, ChatArtifactValidationResult,
};
use ioi_api::runtime_harness::ArtifactOperatorStep;
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

fn assign_operator_step_origin(
    step: &mut ArtifactOperatorStep,
    origin_prompt_event_id: Option<&str>,
) {
    let Some(origin_prompt_event_id) = origin_prompt_event_id.map(str::trim) else {
        return;
    };
    if origin_prompt_event_id.is_empty() {
        return;
    }
    if step.origin_prompt_event_id.trim().is_empty() {
        step.origin_prompt_event_id = origin_prompt_event_id.to_string();
    }
    if let Some(preview) = step.preview.as_mut() {
        if preview.origin_prompt_event_id.trim().is_empty() {
            preview.origin_prompt_event_id = origin_prompt_event_id.to_string();
        }
    }
    for source_ref in &mut step.source_refs {
        if source_ref.origin_prompt_event_id.trim().is_empty() {
            source_ref.origin_prompt_event_id = origin_prompt_event_id.to_string();
        }
    }
    for file_ref in &mut step.file_refs {
        if file_ref.origin_prompt_event_id.trim().is_empty() {
            file_ref.origin_prompt_event_id = origin_prompt_event_id.to_string();
        }
    }
    for verification_ref in &mut step.verification_refs {
        if verification_ref.origin_prompt_event_id.trim().is_empty() {
            verification_ref.origin_prompt_event_id = origin_prompt_event_id.to_string();
        }
    }
}

fn assign_operator_steps_origin(
    steps: &mut [ArtifactOperatorStep],
    origin_prompt_event_id: Option<&str>,
) {
    for step in steps {
        assign_operator_step_origin(step, origin_prompt_event_id);
    }
}

fn assign_chat_session_turn_ownership(
    session: &mut ChatArtifactSession,
    origin_prompt_event_id: Option<&str>,
) {
    let Some(origin_prompt_event_id) = origin_prompt_event_id.map(str::trim) else {
        return;
    };
    if origin_prompt_event_id.is_empty() {
        return;
    }
    session.origin_prompt_event_id = Some(origin_prompt_event_id.to_string());
    assign_operator_steps_origin(
        &mut session.materialization.operator_steps,
        Some(origin_prompt_event_id),
    );
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactRevisionComparison {
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
pub fn chat_retry_renderer_session(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: String,
) -> Result<(), String> {
    let task = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .current_task
        .clone()
        .ok_or_else(|| "No active Chat task is loaded.".to_string())?;

    let chat_session = task
        .chat_session
        .clone()
        .ok_or_else(|| "No Chat artifact session is attached to the current task.".to_string())?;
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

    spawn_build_supervisor(app, chat_session, build_session);
    Ok(())
}

#[tauri::command]
pub fn chat_attach_artifact_selection(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    selection: ChatArtifactSelectionTarget,
) -> Result<(), String> {
    attach_artifact_selection(state, app, selection)
}

#[tauri::command]
pub fn chat_attach_widget_state(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    widget_state: ChatRetainedWidgetState,
) -> Result<(), String> {
    attach_widget_state(state, app, widget_state)
}

#[tauri::command]
pub fn chat_compare_artifact_revisions(
    state: State<'_, Mutex<AppState>>,
    base_revision_id: String,
    target_revision_id: String,
) -> Result<ChatArtifactRevisionComparison, String> {
    compare_artifact_revisions(state, base_revision_id, target_revision_id)
}

#[tauri::command]
pub fn chat_restore_artifact_revision(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    revision_id: String,
) -> Result<(), String> {
    restore_artifact_revision(state, app, revision_id)
}

#[tauri::command]
pub fn chat_branch_artifact_revision(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    revision_id: String,
) -> Result<ChatArtifactRevision, String> {
    branch_artifact_revision(state, app, revision_id)
}

#[cfg(test)]
mod tests;
