use super::*;
use crate::models::{StudioArtifactRevision, StudioArtifactSession};
use crate::orchestrator;
use ioi_api::studio::{
    StudioArtifactBrief, StudioArtifactEditIntent, StudioArtifactRefinementContext,
    StudioArtifactTasteMemory, StudioArtifactUxLifecycle, StudioGeneratedArtifactFile,
};
use ioi_memory::MemoryRuntime;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

use super::{
    lifecycle_state_label, navigator_nodes_for_manifest, now_iso, refresh_pipeline_steps,
    verified_reply_from_manifest,
};

pub(super) fn compare_artifact_revisions(
    state: State<'_, Mutex<AppState>>,
    base_revision_id: String,
    target_revision_id: String,
) -> Result<StudioArtifactRevisionComparison, String> {
    let (task, memory_runtime) = current_task_and_memory_runtime(&state)?;
    let studio_session = task
        .studio_session
        .as_ref()
        .ok_or_else(|| "No active Studio task is loaded.".to_string())?;
    let base = current_studio_revision(studio_session, &base_revision_id)?;
    let target = current_studio_revision(studio_session, &target_revision_id)?;
    let changed_paths = changed_paths_between_revisions(base, target, memory_runtime.as_ref());

    Ok(StudioArtifactRevisionComparison {
        base_revision_id,
        target_revision_id,
        base_branch_label: base.branch_label.clone(),
        target_branch_label: target.branch_label.clone(),
        summary: if changed_paths.is_empty() {
            "The selected revisions resolve to the same surfaced artifact files.".to_string()
        } else {
            format!(
                "{} path(s) changed between these revisions.",
                changed_paths.len()
            )
        },
        changed_paths,
        same_renderer: base.artifact_manifest.renderer == target.artifact_manifest.renderer,
        same_title: base.artifact_manifest.title == target.artifact_manifest.title,
    })
}

pub(crate) fn changed_paths_between_revisions(
    base: &StudioArtifactRevision,
    target: &StudioArtifactRevision,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
) -> Vec<String> {
    let base_files = base
        .artifact_manifest
        .files
        .iter()
        .map(|file| (file.path.clone(), file))
        .collect::<HashMap<_, _>>();
    let target_files = target
        .artifact_manifest
        .files
        .iter()
        .map(|file| (file.path.clone(), file))
        .collect::<HashMap<_, _>>();
    let relative_paths = base_files
        .keys()
        .chain(target_files.keys())
        .cloned()
        .collect::<HashSet<_>>();
    let base_previews = base
        .file_writes
        .iter()
        .filter_map(|write| {
            write
                .content_preview
                .as_ref()
                .map(|preview| (write.path.as_str(), preview.as_str()))
        })
        .collect::<HashMap<_, _>>();
    let target_previews = target
        .file_writes
        .iter()
        .filter_map(|write| {
            write
                .content_preview
                .as_ref()
                .map(|preview| (write.path.as_str(), preview.as_str()))
        })
        .collect::<HashMap<_, _>>();

    let mut changed_paths = relative_paths
        .into_iter()
        .filter(
            |path| match (base_files.get(path), target_files.get(path)) {
                (Some(left), Some(right)) => {
                    if left.mime != right.mime
                        || left.role != right.role
                        || left.renderable != right.renderable
                        || left.downloadable != right.downloadable
                    {
                        return true;
                    }

                    match (
                        revision_file_body(base, path, memory_runtime),
                        revision_file_body(target, path, memory_runtime),
                    ) {
                        (Some(left_body), Some(right_body)) => left_body != right_body,
                        _ => {
                            if let (Some(left_preview), Some(right_preview)) = (
                                base_previews.get(path.as_str()),
                                target_previews.get(path.as_str()),
                            ) {
                                if left_preview != right_preview {
                                    return true;
                                }
                            }

                            left.artifact_id != right.artifact_id
                        }
                    }
                }
                _ => true,
            },
        )
        .collect::<Vec<_>>();
    changed_paths.sort();
    changed_paths
}

fn revision_file_body(
    revision: &StudioArtifactRevision,
    path: &str,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
) -> Option<Vec<u8>> {
    let runtime = memory_runtime?;
    let artifact_id = revision
        .artifact_manifest
        .files
        .iter()
        .find(|file| file.path == path)
        .and_then(|file| file.artifact_id.as_deref())?;
    orchestrator::load_artifact_content(runtime, artifact_id)
}

pub(super) fn restore_artifact_revision(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    revision_id: String,
) -> Result<(), String> {
    let (mut task, memory_runtime) = current_task_and_memory_runtime(&state)?;
    let studio_session = task
        .studio_session
        .as_mut()
        .ok_or_else(|| "No Studio artifact session is attached to the current task.".to_string())?;
    let revision = current_studio_revision(studio_session, &revision_id)?.clone();
    apply_revision_to_studio_session(studio_session, &revision);
    persist_current_task_update(&state, &app, task, memory_runtime)
}

pub(super) fn branch_artifact_revision(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    revision_id: String,
) -> Result<StudioArtifactRevision, String> {
    let (mut task, memory_runtime) = current_task_and_memory_runtime(&state)?;
    let studio_session = task
        .studio_session
        .as_mut()
        .ok_or_else(|| "No Studio artifact session is attached to the current task.".to_string())?;
    let seed_revision = current_studio_revision(studio_session, &revision_id)?.clone();
    let branch_index = studio_session
        .revisions
        .iter()
        .filter(|revision| revision.branch_id != "main")
        .map(|revision| revision.branch_id.clone())
        .collect::<HashSet<_>>()
        .len()
        + 1;
    let mut branch_revision = seed_revision;
    branch_revision.revision_id = Uuid::new_v4().to_string();
    branch_revision.parent_revision_id = Some(revision_id);
    branch_revision.branch_id = format!("branch-{}", branch_index);
    branch_revision.branch_label = format!("Branch {}", branch_index);
    branch_revision.prompt = format!(
        "Branch from {} at {}",
        branch_revision.branch_label, branch_revision.created_at
    );
    branch_revision.created_at = now_iso();
    studio_session.revisions.push(branch_revision.clone());
    apply_revision_to_studio_session(studio_session, &branch_revision);
    persist_current_task_update(&state, &app, task, memory_runtime)?;
    Ok(branch_revision)
}

pub(super) fn current_studio_revision<'a>(
    studio_session: &'a StudioArtifactSession,
    revision_id: &str,
) -> Result<&'a StudioArtifactRevision, String> {
    studio_session
        .revisions
        .iter()
        .find(|revision| revision.revision_id == revision_id)
        .ok_or_else(|| format!("Studio revision '{}' was not found.", revision_id))
}

pub(super) fn apply_revision_to_studio_session(
    studio_session: &mut StudioArtifactSession,
    revision: &StudioArtifactRevision,
) {
    studio_session.title = revision.artifact_manifest.title.clone();
    studio_session.artifact_manifest = revision.artifact_manifest.clone();
    studio_session.navigator_nodes =
        navigator_nodes_for_manifest(&studio_session.artifact_manifest);
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
    studio_session.materialization.artifact_brief = revision.artifact_brief.clone();
    studio_session.materialization.edit_intent = revision.edit_intent.clone();
    studio_session.materialization.candidate_summaries = revision.candidate_summaries.clone();
    studio_session.materialization.winning_candidate_id = revision.winning_candidate_id.clone();
    studio_session.materialization.winning_candidate_rationale =
        revision.judge.as_ref().map(|judge| judge.rationale.clone());
    studio_session.materialization.judge = revision.judge.clone();
    studio_session.materialization.output_origin = revision.output_origin;
    studio_session.materialization.production_provenance = revision.production_provenance.clone();
    studio_session.materialization.acceptance_provenance = revision.acceptance_provenance.clone();
    studio_session.materialization.failure = revision.failure.clone();
    studio_session.materialization.file_writes = revision.file_writes.clone();
    studio_session.materialization.navigator_nodes =
        navigator_nodes_for_manifest(&studio_session.artifact_manifest);
    studio_session.materialization.summary =
        materialization_summary_for_revision(studio_session, revision);
    studio_session.materialization.ux_lifecycle = Some(revision.ux_lifecycle);
    studio_session.verified_reply =
        verified_reply_from_manifest(&studio_session.title, &studio_session.artifact_manifest);
    studio_session.lifecycle_state = studio_session
        .artifact_manifest
        .verification
        .lifecycle_state;
    studio_session.status = lifecycle_state_label(studio_session.lifecycle_state).to_string();
    studio_session.selected_targets = revision.selected_targets.clone();
    studio_session.ux_lifecycle = Some(revision.ux_lifecycle);
    studio_session.active_revision_id = Some(revision.revision_id.clone());
    studio_session.updated_at = now_iso();
    refresh_pipeline_steps(studio_session, None);
}

pub(super) fn initial_revision_for_session(
    studio_session: &StudioArtifactSession,
    prompt: &str,
) -> StudioArtifactRevision {
    build_revision_from_session(
        studio_session,
        prompt,
        "main".to_string(),
        "Main".to_string(),
        None,
    )
}

pub(super) fn studio_refinement_context_for_session(
    memory_runtime: &Arc<MemoryRuntime>,
    session: &StudioArtifactSession,
) -> StudioArtifactRefinementContext {
    let files = session
        .artifact_manifest
        .files
        .iter()
        .filter_map(|file| {
            let artifact_id = file.artifact_id.as_deref()?;
            let bytes = orchestrator::load_artifact_content(memory_runtime, artifact_id)?;
            let body = refinement_body_for_artifact_file(&file.path, &file.mime, &bytes)?;
            Some(StudioGeneratedArtifactFile {
                path: file.path.clone(),
                mime: file.mime.clone(),
                role: file.role,
                renderable: file.renderable,
                downloadable: file.downloadable,
                encoding: None,
                body,
            })
        })
        .collect();

    StudioArtifactRefinementContext {
        artifact_id: Some(session.artifact_id.clone()),
        revision_id: session.active_revision_id.clone(),
        title: session.title.clone(),
        summary: session.summary.clone(),
        renderer: session.artifact_manifest.renderer,
        files,
        selected_targets: session.selected_targets.clone(),
        taste_memory: session.taste_memory.clone(),
    }
}

pub(super) fn derive_studio_taste_memory(
    prior: Option<&StudioArtifactTasteMemory>,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
) -> Option<StudioArtifactTasteMemory> {
    let mut directives = Vec::new();
    if let Some(prior) = prior {
        merge_unique_directives(&mut directives, prior.directives.iter());
    }
    merge_unique_directives(&mut directives, brief.visual_tone.iter());
    merge_unique_directives(&mut directives, brief.style_directives.iter());
    if let Some(edit_intent) = edit_intent {
        merge_unique_directives(&mut directives, edit_intent.tone_directives.iter());
        merge_unique_directives(&mut directives, edit_intent.style_directives.iter());
    }

    if directives.is_empty() {
        return prior.cloned();
    }

    Some(StudioArtifactTasteMemory {
        summary: format!(
            "Session taste memory is steering this artifact toward {}.",
            directives
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ),
        directives,
    })
}

pub(super) fn revision_branch_identity(
    studio_session: &StudioArtifactSession,
    edit_intent: Option<&StudioArtifactEditIntent>,
) -> (String, String, Option<String>) {
    let active_revision = studio_session
        .active_revision_id
        .as_ref()
        .and_then(|revision_id| {
            studio_session
                .revisions
                .iter()
                .find(|revision| revision.revision_id == *revision_id)
        });
    let parent_revision_id = active_revision.map(|revision| revision.revision_id.clone());

    if edit_intent.is_some_and(|intent| intent.branch_requested) {
        let branch_index = studio_session
            .revisions
            .iter()
            .filter(|revision| revision.branch_id != "main")
            .map(|revision| revision.branch_id.clone())
            .collect::<HashSet<_>>()
            .len()
            + 1;
        return (
            format!("branch-{}", branch_index),
            format!("Branch {}", branch_index),
            parent_revision_id,
        );
    }

    (
        active_revision
            .map(|revision| revision.branch_id.clone())
            .unwrap_or_else(|| "main".to_string()),
        active_revision
            .map(|revision| revision.branch_label.clone())
            .unwrap_or_else(|| "Main".to_string()),
        parent_revision_id,
    )
}

pub(super) fn revision_for_session(
    studio_session: &StudioArtifactSession,
    prompt: &str,
    branch_id: String,
    branch_label: String,
    parent_revision_id: Option<String>,
) -> StudioArtifactRevision {
    build_revision_from_session(
        studio_session,
        prompt,
        branch_id,
        branch_label,
        parent_revision_id,
    )
}

fn materialization_summary_for_revision(
    studio_session: &StudioArtifactSession,
    revision: &StudioArtifactRevision,
) -> String {
    revision
        .judge
        .as_ref()
        .map(|judge| judge.rationale.clone())
        .unwrap_or_else(|| studio_session.materialization.summary.clone())
}

fn build_revision_from_session(
    studio_session: &StudioArtifactSession,
    prompt: &str,
    branch_id: String,
    branch_label: String,
    parent_revision_id: Option<String>,
) -> StudioArtifactRevision {
    StudioArtifactRevision {
        revision_id: Uuid::new_v4().to_string(),
        parent_revision_id,
        branch_id,
        branch_label,
        prompt: prompt.trim().to_string(),
        created_at: now_iso(),
        ux_lifecycle: studio_session
            .ux_lifecycle
            .unwrap_or(StudioArtifactUxLifecycle::Judged),
        artifact_manifest: studio_session.artifact_manifest.clone(),
        artifact_brief: studio_session.materialization.artifact_brief.clone(),
        edit_intent: studio_session.materialization.edit_intent.clone(),
        candidate_summaries: studio_session.materialization.candidate_summaries.clone(),
        winning_candidate_id: studio_session.materialization.winning_candidate_id.clone(),
        judge: studio_session.materialization.judge.clone(),
        output_origin: studio_session.materialization.output_origin,
        production_provenance: studio_session.materialization.production_provenance.clone(),
        acceptance_provenance: studio_session.materialization.acceptance_provenance.clone(),
        failure: studio_session.materialization.failure.clone(),
        file_writes: studio_session.materialization.file_writes.clone(),
        selected_targets: studio_session.selected_targets.clone(),
    }
}

fn studio_artifact_file_is_text(mime: &str) -> bool {
    let normalized = mime.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return true;
    }
    normalized.starts_with("text/")
        || normalized.contains("json")
        || normalized.contains("javascript")
        || normalized.contains("typescript")
        || normalized.contains("xml")
        || normalized.contains("yaml")
        || normalized.contains("svg")
        || normalized.contains("html")
        || normalized.contains("markdown")
        || normalized.contains("mermaid")
}

fn refinement_body_for_artifact_file(path: &str, mime: &str, bytes: &[u8]) -> Option<String> {
    if studio_artifact_file_is_text(mime) {
        return Some(String::from_utf8_lossy(bytes).into_owned());
    }

    if mime.trim().eq_ignore_ascii_case("application/pdf") {
        return Some(format!(
            "Binary PDF export present at {}. Preserve the current document structure unless the follow-up explicitly replaces it.",
            path
        ));
    }

    None
}

fn merge_unique_directives<'a>(
    target: &mut Vec<String>,
    values: impl IntoIterator<Item = &'a String>,
) {
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !target
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(trimmed))
        {
            target.push(trimmed.to_string());
        }
    }
}
