use super::*;
use crate::models::{ChatArtifactSession, StudioArtifactRevision};
use crate::orchestrator;
use ioi_api::runtime_harness::{
    StudioArtifactBlueprint, StudioArtifactBrief, StudioArtifactEditIntent, StudioArtifactExemplar,
    StudioArtifactIR, StudioArtifactRefinementContext, StudioArtifactTasteMemory,
    StudioArtifactUxLifecycle, StudioArtifactValidationResult, StudioArtifactValidationStatus,
    StudioGeneratedArtifactFile,
};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_memory::{ArchivalMemoryRecord, MemoryRuntime, NewArchivalMemoryRecord};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

use super::{
    lifecycle_state_label, navigator_nodes_for_manifest, now_iso, refresh_pipeline_steps,
    verified_reply_from_manifest,
};

pub(super) const STUDIO_ARTIFACT_EXEMPLAR_SCOPE: &str = "desktop.studio.artifact_exemplars";
const STUDIO_ARTIFACT_EXEMPLAR_KIND: &str = "studio.artifact_exemplar";
const STUDIO_ARTIFACT_EXEMPLAR_MIN_SCORE: i32 = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StudioArtifactExemplarArchivalMetadata {
    trust_level: String,
    artifact_id: String,
    revision_id: String,
    renderer: StudioRendererKind,
    scaffold_family: String,
    title: String,
    summary: String,
    thesis: String,
    quality_rationale: String,
    score_total: i32,
    #[serde(default)]
    design_cues: Vec<String>,
    #[serde(default)]
    component_patterns: Vec<String>,
    #[serde(default)]
    anti_patterns: Vec<String>,
}

fn merge_unique_text_values<'a>(
    target: &mut Vec<String>,
    values: impl IntoIterator<Item = &'a str>,
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

fn studio_artifact_validation_total_score(validation: &StudioArtifactValidationResult) -> i32 {
    i32::from(validation.request_faithfulness)
        + i32::from(validation.concept_coverage)
        + i32::from(validation.interaction_relevance)
        + i32::from(validation.layout_coherence)
        + i32::from(validation.visual_hierarchy)
        + i32::from(validation.completeness)
}

fn exemplar_quality_rationale(
    validation: &StudioArtifactValidationResult,
    winning_candidate_rationale: Option<&str>,
) -> String {
    winning_candidate_rationale
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| validation.rationale.trim().to_string())
}

fn exemplar_design_cues(
    brief: &StudioArtifactBrief,
    blueprint: &StudioArtifactBlueprint,
    artifact_ir: &StudioArtifactIR,
    taste_memory: Option<&StudioArtifactTasteMemory>,
) -> Vec<String> {
    let mut cues = Vec::new();
    merge_unique_text_values(&mut cues, brief.visual_tone.iter().map(String::as_str));
    merge_unique_text_values(
        &mut cues,
        std::iter::once(blueprint.design_system.typography_strategy.as_str())
            .chain(std::iter::once(blueprint.design_system.density.as_str()))
            .chain(std::iter::once(
                blueprint.design_system.motion_style.as_str(),
            ))
            .chain(
                blueprint
                    .design_system
                    .emphasis_modes
                    .iter()
                    .map(String::as_str),
            ),
    );
    merge_unique_text_values(
        &mut cues,
        artifact_ir
            .design_tokens
            .iter()
            .take(4)
            .map(|token| token.value.as_str()),
    );
    if let Some(memory) = taste_memory {
        merge_unique_text_values(
            &mut cues,
            memory.typography_preferences.iter().map(String::as_str),
        );
        merge_unique_text_values(&mut cues, memory.tone_family.iter().map(String::as_str));
    }
    cues
}

fn exemplar_component_patterns(
    blueprint: &StudioArtifactBlueprint,
    artifact_ir: &StudioArtifactIR,
    prior: Option<&StudioArtifactTasteMemory>,
) -> Vec<String> {
    let mut patterns = Vec::new();
    merge_unique_text_values(
        &mut patterns,
        blueprint
            .component_plan
            .iter()
            .map(|component| component.component_family.as_str()),
    );
    merge_unique_text_values(
        &mut patterns,
        artifact_ir.component_bindings.iter().map(String::as_str),
    );
    if let Some(prior) = prior {
        merge_unique_text_values(
            &mut patterns,
            prior
                .preferred_component_patterns
                .iter()
                .map(String::as_str),
        );
    }
    patterns
}

fn exemplar_anti_patterns(
    prior: Option<&StudioArtifactTasteMemory>,
    validation: Option<&StudioArtifactValidationResult>,
) -> Vec<String> {
    let mut patterns = Vec::new();
    if let Some(prior) = prior {
        merge_unique_text_values(
            &mut patterns,
            prior.anti_patterns.iter().map(String::as_str),
        );
    }
    if let Some(validation) = validation {
        if validation.generic_shell_detected {
            patterns.push("generic_shell".to_string());
        }
        if validation.trivial_shell_detected {
            patterns.push("trivial_shell".to_string());
        }
        merge_unique_text_values(
            &mut patterns,
            validation
                .issue_classes
                .iter()
                .filter(|issue| issue.as_str() != "generation_failure")
                .map(String::as_str),
        );
    }
    patterns
}

fn build_studio_artifact_exemplar_content(
    exemplar: &StudioArtifactExemplar,
    brief: &StudioArtifactBrief,
    blueprint: &StudioArtifactBlueprint,
    artifact_ir: &StudioArtifactIR,
) -> String {
    let required_interactions = brief.required_interaction_summaries().join(", ");

    format!(
        "Studio artifact exemplar.\nTitle: {}\nRenderer: {:?}\nScaffold family: {}\nAudience: {}\nJob to be done: {}\nSubject domain: {}\nArtifact thesis: {}\nSummary: {}\nQuality rationale: {}\nScore total: {}\nRequired concepts: {}\nRequired interactions: {}\nSection roles: {}\nInteraction families: {}\nEvidence kinds: {}\nComponent patterns: {}\nDesign cues: {}\nAnti patterns to avoid: {}\nRender evaluation checklist: {}",
        exemplar.title,
        exemplar.renderer,
        exemplar.scaffold_family,
        brief.audience,
        brief.job_to_be_done,
        brief.subject_domain,
        exemplar.thesis,
        exemplar.summary,
        exemplar.quality_rationale,
        exemplar.score_total,
        brief.required_concepts.join(", "),
        required_interactions,
        blueprint
            .section_plan
            .iter()
            .map(|section| section.role.clone())
            .collect::<Vec<_>>()
            .join(", "),
        blueprint
            .interaction_plan
            .iter()
            .map(|interaction| interaction.family.clone())
            .collect::<Vec<_>>()
            .join(", "),
        blueprint
            .evidence_plan
            .iter()
            .map(|entry| entry.kind.clone())
            .collect::<Vec<_>>()
            .join(", "),
        exemplar.component_patterns.join(", "),
        exemplar.design_cues.join(", "),
        exemplar.anti_patterns.join(", "),
        artifact_ir.render_eval_checklist.join(", "),
    )
}

fn studio_artifact_exemplar_from_metadata(
    record_id: i64,
    metadata: StudioArtifactExemplarArchivalMetadata,
) -> StudioArtifactExemplar {
    StudioArtifactExemplar {
        record_id,
        title: metadata.title,
        summary: metadata.summary,
        renderer: metadata.renderer,
        scaffold_family: metadata.scaffold_family,
        thesis: metadata.thesis,
        quality_rationale: metadata.quality_rationale,
        score_total: metadata.score_total,
        design_cues: metadata.design_cues,
        component_patterns: metadata.component_patterns,
        anti_patterns: metadata.anti_patterns,
        source_revision_id: Some(metadata.revision_id),
    }
}

pub(super) fn studio_artifact_exemplar_from_archival_record(
    record: &ArchivalMemoryRecord,
) -> Option<StudioArtifactExemplar> {
    if record.scope != STUDIO_ARTIFACT_EXEMPLAR_SCOPE
        || record.kind != STUDIO_ARTIFACT_EXEMPLAR_KIND
    {
        return None;
    }
    let metadata =
        serde_json::from_str::<StudioArtifactExemplarArchivalMetadata>(&record.metadata_json)
            .ok()?;
    Some(studio_artifact_exemplar_from_metadata(record.id, metadata))
}

pub(super) fn persist_studio_artifact_exemplar(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    chat_session: &ChatArtifactSession,
    revision: &StudioArtifactRevision,
) -> Result<Option<StudioArtifactExemplar>, String> {
    let Some(runtime) = inference_runtime else {
        return Ok(None);
    };
    let Some(brief) = revision.artifact_brief.as_ref() else {
        return Ok(None);
    };
    let Some(blueprint) = revision.blueprint.as_ref() else {
        return Ok(None);
    };
    let Some(artifact_ir) = revision.artifact_ir.as_ref() else {
        return Ok(None);
    };
    let Some(validation) = revision.validation.as_ref() else {
        return Ok(None);
    };
    if validation.classification != StudioArtifactValidationStatus::Pass
        || studio_artifact_validation_total_score(validation) < STUDIO_ARTIFACT_EXEMPLAR_MIN_SCORE
        || chat_session.materialization.fallback_used
    {
        return Ok(None);
    }

    let exemplar = StudioArtifactExemplar {
        record_id: 0,
        title: revision.artifact_manifest.title.clone(),
        summary: chat_session.summary.clone(),
        renderer: revision.artifact_manifest.renderer,
        scaffold_family: blueprint.scaffold_family.clone(),
        thesis: brief.artifact_thesis.clone(),
        quality_rationale: exemplar_quality_rationale(
            validation,
            chat_session
                .materialization
                .winning_candidate_rationale
                .as_deref(),
        ),
        score_total: studio_artifact_validation_total_score(validation),
        design_cues: exemplar_design_cues(
            brief,
            blueprint,
            artifact_ir,
            chat_session.taste_memory.as_ref(),
        ),
        component_patterns: exemplar_component_patterns(
            blueprint,
            artifact_ir,
            chat_session.taste_memory.as_ref(),
        ),
        anti_patterns: exemplar_anti_patterns(chat_session.taste_memory.as_ref(), Some(validation)),
        source_revision_id: Some(revision.revision_id.clone()),
    };
    let content = build_studio_artifact_exemplar_content(&exemplar, brief, blueprint, artifact_ir);
    let metadata = StudioArtifactExemplarArchivalMetadata {
        trust_level: "runtime_observed".to_string(),
        artifact_id: chat_session.artifact_id.clone(),
        revision_id: revision.revision_id.clone(),
        renderer: exemplar.renderer,
        scaffold_family: exemplar.scaffold_family.clone(),
        title: exemplar.title.clone(),
        summary: exemplar.summary.clone(),
        thesis: exemplar.thesis.clone(),
        quality_rationale: exemplar.quality_rationale.clone(),
        score_total: exemplar.score_total,
        design_cues: exemplar.design_cues.clone(),
        component_patterns: exemplar.component_patterns.clone(),
        anti_patterns: exemplar.anti_patterns.clone(),
    };
    let metadata_json = serde_json::to_string(&metadata)
        .map_err(|error| format!("Failed to serialize Studio exemplar metadata: {error}"))?;
    let Some(record_id) = memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: STUDIO_ARTIFACT_EXEMPLAR_SCOPE.to_string(),
            thread_id: None,
            kind: STUDIO_ARTIFACT_EXEMPLAR_KIND.to_string(),
            content: content.clone(),
            metadata_json,
        })
        .map_err(|error| format!("Failed to insert Studio exemplar record: {error}"))?
    else {
        return Ok(None);
    };
    let embedding = tauri::async_runtime::block_on(async { runtime.embed_text(&content).await })
        .map_err(|error| format!("Failed to embed Studio exemplar record: {error}"))?;
    memory_runtime
        .upsert_archival_embedding(record_id, &embedding)
        .map_err(|error| format!("Failed to index Studio exemplar record: {error}"))?;

    Ok(Some(StudioArtifactExemplar {
        record_id,
        ..exemplar
    }))
}

pub(super) fn compare_artifact_revisions(
    state: State<'_, Mutex<AppState>>,
    base_revision_id: String,
    target_revision_id: String,
) -> Result<StudioArtifactRevisionComparison, String> {
    let (task, memory_runtime) = current_task_and_memory_runtime(&state)?;
    let chat_session = task
        .chat_session
        .as_ref()
        .ok_or_else(|| "No active Studio task is loaded.".to_string())?;
    let base = current_studio_revision(chat_session, &base_revision_id)?;
    let target = current_studio_revision(chat_session, &target_revision_id)?;
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
    let chat_session = task
        .chat_session
        .as_mut()
        .ok_or_else(|| "No Studio artifact session is attached to the current task.".to_string())?;
    let revision = current_studio_revision(chat_session, &revision_id)?.clone();
    apply_revision_to_chat_session(chat_session, &revision);
    persist_current_task_update(&state, &app, task, memory_runtime)
}

pub(super) fn branch_artifact_revision(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    revision_id: String,
) -> Result<StudioArtifactRevision, String> {
    let (mut task, memory_runtime) = current_task_and_memory_runtime(&state)?;
    let chat_session = task
        .chat_session
        .as_mut()
        .ok_or_else(|| "No Studio artifact session is attached to the current task.".to_string())?;
    let seed_revision = current_studio_revision(chat_session, &revision_id)?.clone();
    let branch_index = chat_session
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
    chat_session.revisions.push(branch_revision.clone());
    apply_revision_to_chat_session(chat_session, &branch_revision);
    persist_current_task_update(&state, &app, task, memory_runtime)?;
    Ok(branch_revision)
}

pub(super) fn current_studio_revision<'a>(
    chat_session: &'a ChatArtifactSession,
    revision_id: &str,
) -> Result<&'a StudioArtifactRevision, String> {
    chat_session
        .revisions
        .iter()
        .find(|revision| revision.revision_id == revision_id)
        .ok_or_else(|| format!("Studio revision '{}' was not found.", revision_id))
}

pub(super) fn apply_revision_to_chat_session(
    chat_session: &mut ChatArtifactSession,
    revision: &StudioArtifactRevision,
) {
    chat_session.title = revision.artifact_manifest.title.clone();
    chat_session.artifact_manifest = revision.artifact_manifest.clone();
    chat_session.navigator_nodes = navigator_nodes_for_manifest(&chat_session.artifact_manifest);
    chat_session.available_lenses = chat_session
        .artifact_manifest
        .tabs
        .iter()
        .map(|tab| tab.id.clone())
        .collect();
    if !chat_session
        .available_lenses
        .iter()
        .any(|lens| lens == &chat_session.current_lens)
    {
        chat_session.current_lens = chat_session.artifact_manifest.primary_tab.clone();
    }
    chat_session.materialization.artifact_brief = revision.artifact_brief.clone();
    chat_session.materialization.blueprint = revision.blueprint.clone();
    chat_session.materialization.artifact_ir = revision.artifact_ir.clone();
    chat_session.materialization.edit_intent = revision.edit_intent.clone();
    chat_session.materialization.candidate_summaries = revision.candidate_summaries.clone();
    chat_session.materialization.winning_candidate_id = revision.winning_candidate_id.clone();
    chat_session.materialization.winning_candidate_rationale = revision
        .validation
        .as_ref()
        .map(|validation| validation.rationale.clone());
    chat_session.materialization.execution_envelope = revision.execution_envelope.clone();
    chat_session.materialization.swarm_plan = revision.swarm_plan.clone();
    chat_session.materialization.swarm_execution = revision.swarm_execution.clone();
    chat_session.materialization.swarm_worker_receipts = revision.swarm_worker_receipts.clone();
    chat_session.materialization.swarm_change_receipts = revision.swarm_change_receipts.clone();
    chat_session.materialization.swarm_merge_receipts = revision.swarm_merge_receipts.clone();
    chat_session.materialization.swarm_verification_receipts =
        revision.swarm_verification_receipts.clone();
    chat_session.materialization.render_evaluation = revision.render_evaluation.clone();
    chat_session.materialization.validation = revision.validation.clone();
    chat_session.materialization.output_origin = revision.output_origin;
    chat_session.materialization.production_provenance = revision.production_provenance.clone();
    chat_session.materialization.acceptance_provenance = revision.acceptance_provenance.clone();
    chat_session.materialization.failure = revision.failure.clone();
    chat_session.materialization.file_writes = revision.file_writes.clone();
    chat_session.materialization.navigator_nodes =
        navigator_nodes_for_manifest(&chat_session.artifact_manifest);
    chat_session.materialization.summary =
        materialization_summary_for_revision(chat_session, revision);
    chat_session.materialization.ux_lifecycle = Some(revision.ux_lifecycle);
    chat_session.materialization.preparation_needs = revision.preparation_needs.clone();
    chat_session.materialization.prepared_context_resolution =
        revision.prepared_context_resolution.clone();
    chat_session.materialization.skill_discovery_resolution =
        revision.skill_discovery_resolution.clone();
    chat_session.materialization.selected_skills = revision.selected_skills.clone();
    chat_session.materialization.retrieved_exemplars = revision.retrieved_exemplars.clone();
    chat_session.verified_reply =
        verified_reply_from_manifest(&chat_session.title, &chat_session.artifact_manifest);
    chat_session.lifecycle_state = chat_session.artifact_manifest.verification.lifecycle_state;
    chat_session.status = lifecycle_state_label(chat_session.lifecycle_state).to_string();
    chat_session.taste_memory = revision.taste_memory.clone();
    chat_session.retrieved_exemplars = revision.retrieved_exemplars.clone();
    chat_session.selected_targets = revision.selected_targets.clone();
    chat_session.ux_lifecycle = Some(revision.ux_lifecycle);
    chat_session.active_revision_id = Some(revision.revision_id.clone());
    chat_session.updated_at = now_iso();
    refresh_pipeline_steps(chat_session, None);
}

pub(super) fn initial_revision_for_session(
    chat_session: &ChatArtifactSession,
    prompt: &str,
) -> StudioArtifactRevision {
    build_revision_from_session(
        chat_session,
        prompt,
        "main".to_string(),
        "Main".to_string(),
        None,
    )
}

pub(super) fn studio_refinement_context_for_session(
    memory_runtime: &Arc<MemoryRuntime>,
    session: &ChatArtifactSession,
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
        retrieved_exemplars: session.retrieved_exemplars.clone(),
        blueprint: session.materialization.blueprint.clone(),
        artifact_ir: session.materialization.artifact_ir.clone(),
        selected_skills: session.materialization.selected_skills.clone(),
    }
}

pub(super) fn derive_studio_taste_memory(
    prior: Option<&StudioArtifactTasteMemory>,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    edit_intent: Option<&StudioArtifactEditIntent>,
    validation: Option<&StudioArtifactValidationResult>,
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

    let mut typography_preferences = Vec::new();
    if let Some(prior) = prior {
        merge_unique_text_values(
            &mut typography_preferences,
            prior.typography_preferences.iter().map(String::as_str),
        );
    }
    if let Some(blueprint) = blueprint {
        merge_unique_text_values(
            &mut typography_preferences,
            std::iter::once(blueprint.design_system.typography_strategy.as_str()),
        );
    }

    let mut tone_family = Vec::new();
    if let Some(prior) = prior {
        merge_unique_text_values(
            &mut tone_family,
            prior.tone_family.iter().map(String::as_str),
        );
    }
    merge_unique_text_values(
        &mut tone_family,
        brief.visual_tone.iter().map(String::as_str),
    );
    if let Some(edit_intent) = edit_intent {
        merge_unique_text_values(
            &mut tone_family,
            edit_intent.tone_directives.iter().map(String::as_str),
        );
    }

    let mut preferred_scaffold_families = Vec::new();
    if let Some(prior) = prior {
        merge_unique_text_values(
            &mut preferred_scaffold_families,
            prior.preferred_scaffold_families.iter().map(String::as_str),
        );
    }
    if let Some(blueprint) = blueprint {
        merge_unique_text_values(
            &mut preferred_scaffold_families,
            std::iter::once(blueprint.scaffold_family.as_str()),
        );
    }

    let mut preferred_component_patterns = Vec::new();
    if let Some(prior) = prior {
        merge_unique_text_values(
            &mut preferred_component_patterns,
            prior
                .preferred_component_patterns
                .iter()
                .map(String::as_str),
        );
    }
    if let Some(artifact_ir) = artifact_ir {
        merge_unique_text_values(
            &mut preferred_component_patterns,
            artifact_ir.component_bindings.iter().map(String::as_str),
        );
    }
    if let Some(blueprint) = blueprint {
        merge_unique_text_values(
            &mut preferred_component_patterns,
            blueprint
                .component_plan
                .iter()
                .map(|component| component.component_family.as_str()),
        );
    }

    let anti_patterns = exemplar_anti_patterns(prior, validation);
    let density_preference = prior
        .and_then(|memory| memory.density_preference.clone())
        .or_else(|| blueprint.map(|value| value.design_system.density.clone()));
    let motion_tolerance = prior
        .and_then(|memory| memory.motion_tolerance.clone())
        .or_else(|| blueprint.map(|value| value.design_system.motion_style.clone()));

    if directives.is_empty()
        && typography_preferences.is_empty()
        && tone_family.is_empty()
        && preferred_scaffold_families.is_empty()
        && preferred_component_patterns.is_empty()
        && anti_patterns.is_empty()
        && density_preference.is_none()
        && motion_tolerance.is_none()
    {
        return prior.cloned();
    }

    let scaffold_summary = preferred_scaffold_families
        .first()
        .cloned()
        .unwrap_or_else(|| "current".to_string());
    let density_summary = density_preference
        .clone()
        .unwrap_or_else(|| "balanced".to_string());
    let component_summary = preferred_component_patterns
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");

    Some(StudioArtifactTasteMemory {
        summary: format!(
            "Session taste memory is steering this artifact toward {} inside the {} scaffold with {} density{}.",
            directives
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            scaffold_summary,
            density_summary,
            if component_summary.is_empty() {
                String::new()
            } else {
                format!(" and {} patterns", component_summary)
            }
        ),
        directives,
        typography_preferences,
        density_preference,
        tone_family,
        motion_tolerance,
        preferred_scaffold_families,
        preferred_component_patterns,
        anti_patterns,
    })
}

pub(super) fn revision_branch_identity(
    chat_session: &ChatArtifactSession,
    edit_intent: Option<&StudioArtifactEditIntent>,
) -> (String, String, Option<String>) {
    let active_revision = chat_session
        .active_revision_id
        .as_ref()
        .and_then(|revision_id| {
            chat_session
                .revisions
                .iter()
                .find(|revision| revision.revision_id == *revision_id)
        });
    let parent_revision_id = active_revision.map(|revision| revision.revision_id.clone());

    if edit_intent.is_some_and(|intent| intent.branch_requested) {
        let branch_index = chat_session
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
    chat_session: &ChatArtifactSession,
    prompt: &str,
    branch_id: String,
    branch_label: String,
    parent_revision_id: Option<String>,
) -> StudioArtifactRevision {
    build_revision_from_session(
        chat_session,
        prompt,
        branch_id,
        branch_label,
        parent_revision_id,
    )
}

fn materialization_summary_for_revision(
    chat_session: &ChatArtifactSession,
    revision: &StudioArtifactRevision,
) -> String {
    revision
        .validation
        .as_ref()
        .map(|validation| validation.rationale.clone())
        .unwrap_or_else(|| chat_session.materialization.summary.clone())
}

fn build_revision_from_session(
    chat_session: &ChatArtifactSession,
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
        ux_lifecycle: chat_session
            .ux_lifecycle
            .unwrap_or(StudioArtifactUxLifecycle::Validated),
        artifact_manifest: chat_session.artifact_manifest.clone(),
        artifact_brief: chat_session.materialization.artifact_brief.clone(),
        preparation_needs: chat_session.materialization.preparation_needs.clone(),
        prepared_context_resolution: chat_session
            .materialization
            .prepared_context_resolution
            .clone(),
        skill_discovery_resolution: chat_session
            .materialization
            .skill_discovery_resolution
            .clone(),
        blueprint: chat_session.materialization.blueprint.clone(),
        artifact_ir: chat_session.materialization.artifact_ir.clone(),
        selected_skills: chat_session.materialization.selected_skills.clone(),
        edit_intent: chat_session.materialization.edit_intent.clone(),
        candidate_summaries: chat_session.materialization.candidate_summaries.clone(),
        winning_candidate_id: chat_session.materialization.winning_candidate_id.clone(),
        execution_envelope: chat_session.materialization.execution_envelope.clone(),
        swarm_plan: chat_session.materialization.swarm_plan.clone(),
        swarm_execution: chat_session.materialization.swarm_execution.clone(),
        swarm_worker_receipts: chat_session.materialization.swarm_worker_receipts.clone(),
        swarm_change_receipts: chat_session.materialization.swarm_change_receipts.clone(),
        swarm_merge_receipts: chat_session.materialization.swarm_merge_receipts.clone(),
        swarm_verification_receipts: chat_session
            .materialization
            .swarm_verification_receipts
            .clone(),
        render_evaluation: chat_session.materialization.render_evaluation.clone(),
        validation: chat_session.materialization.validation.clone(),
        output_origin: chat_session.materialization.output_origin,
        production_provenance: chat_session.materialization.production_provenance.clone(),
        acceptance_provenance: chat_session.materialization.acceptance_provenance.clone(),
        failure: chat_session.materialization.failure.clone(),
        file_writes: chat_session.materialization.file_writes.clone(),
        taste_memory: chat_session.taste_memory.clone(),
        retrieved_exemplars: chat_session.retrieved_exemplars.clone(),
        retrieved_sources: chat_session.retrieved_sources.clone(),
        selected_targets: chat_session.selected_targets.clone(),
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
