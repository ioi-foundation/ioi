use crate::kernel::chat::{
    changed_paths_between_revisions, run_chat_current_task_turn_for_proof,
};
use crate::models::{
    AgentPhase, AgentTask, ChatArtifactFailure, ChatArtifactRevision,
    ChatArtifactValidationResult, ChatArtifactValidationStatus,
};
use crate::orchestrator;
use ioi_api::chat::{
    ChatArtifactBlueprint as ChatArtifactBlueprint,
    ChatArtifactBrief as ChatArtifactBrief,
    ChatArtifactCandidateSummary as ChatArtifactCandidateSummary,
    ChatArtifactEditIntent as ChatArtifactEditIntent,
    ChatArtifactExemplar as ChatArtifactExemplar,
    ChatArtifactIR as ChatArtifactIR,
    ChatArtifactOutputOrigin as ChatArtifactOutputOrigin,
    ChatArtifactSelectedSkill as ChatArtifactSelectedSkill,
    ChatArtifactSelectionTarget as ChatArtifactSelectionTarget,
    ChatArtifactTasteMemory as ChatArtifactTasteMemory,
    ChatArtifactUxLifecycle as ChatArtifactUxLifecycle,
};
use ioi_memory::MemoryRuntime;
use serde::Serialize;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

fn chat_proof_trace(message: impl AsRef<str>) {
    if env::var_os("IOI_CHAT_PROOF_TRACE").is_some() {
        eprintln!("[chat-proof-trace] {}", message.as_ref());
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofGenerationEvidence {
    prompt: String,
    title: String,
    route: crate::models::ChatOutcomeRequest,
    artifact_brief: Option<ChatArtifactBrief>,
    blueprint: Option<ChatArtifactBlueprint>,
    artifact_ir: Option<ChatArtifactIR>,
    selected_skills: Vec<ChatArtifactSelectedSkill>,
    retrieved_exemplars: Vec<ChatArtifactExemplar>,
    edit_intent: Option<ChatArtifactEditIntent>,
    candidate_summaries: Vec<ChatArtifactCandidateSummary>,
    winning_candidate_id: Option<String>,
    winning_candidate_rationale: Option<String>,
    validation: Option<ChatArtifactValidationResult>,
    output_origin: Option<ChatArtifactOutputOrigin>,
    production_provenance: Option<crate::models::ChatRuntimeProvenance>,
    acceptance_provenance: Option<crate::models::ChatRuntimeProvenance>,
    fallback_used: bool,
    ux_lifecycle: Option<ChatArtifactUxLifecycle>,
    failure: Option<ChatArtifactFailure>,
    manifest: crate::models::ChatArtifactManifest,
    verified_reply: crate::models::ChatVerifiedReply,
    materialized_files: Vec<String>,
    renderable_files: Vec<String>,
    selected_targets: Vec<ChatArtifactSelectionTarget>,
    taste_memory: Option<ChatArtifactTasteMemory>,
    revisions: Vec<ChatArtifactRevision>,
    active_revision_id: Option<String>,
    full_chat_path: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofRevisionComparison {
    base_revision_id: String,
    target_revision_id: String,
    base_branch_label: String,
    target_branch_label: String,
    changed_paths: Vec<String>,
    summary: String,
    same_renderer: bool,
    same_title: bool,
    full_chat_path: bool,
}

pub fn run_cli() -> Result<(), String> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let command = take_positional(&mut args).ok_or_else(|| {
        "expected a subcommand: run-turn, compare, restore, or branch".to_string()
    })?;

    match command.as_str() {
        "run-turn" => {
            let state_root = required_path_flag(&mut args, "--state-root")?;
            let output = required_path_flag(&mut args, "--output")?;
            let selected_targets =
                parse_selected_targets(&take_flag_values(&mut args, "--selected-target-json"))?;
            let prompt = required_string_flag(&mut args, "--prompt")?;
            let json_output = has_flag(&mut args, "--json");
            ensure_no_extra_args(&args)?;
            run_turn(
                &state_root,
                &output,
                &prompt,
                selected_targets.as_slice(),
                json_output,
            )
        }
        "compare" => {
            let state_root = required_path_flag(&mut args, "--state-root")?;
            let base_revision_id = required_string_flag(&mut args, "--base-revision-id")?;
            let target_revision_id = required_string_flag(&mut args, "--target-revision-id")?;
            let json_output = has_flag(&mut args, "--json");
            ensure_no_extra_args(&args)?;
            compare_revisions(
                &state_root,
                &base_revision_id,
                &target_revision_id,
                json_output,
            )
        }
        "restore" => {
            let state_root = required_path_flag(&mut args, "--state-root")?;
            let output = required_path_flag(&mut args, "--output")?;
            let revision_id = required_string_flag(&mut args, "--revision-id")?;
            let json_output = has_flag(&mut args, "--json");
            ensure_no_extra_args(&args)?;
            restore_revision(&state_root, &output, &revision_id, json_output)
        }
        "branch" => {
            let state_root = required_path_flag(&mut args, "--state-root")?;
            let output = required_path_flag(&mut args, "--output")?;
            let revision_id = required_string_flag(&mut args, "--revision-id")?;
            let json_output = has_flag(&mut args, "--json");
            ensure_no_extra_args(&args)?;
            branch_revision(&state_root, &output, &revision_id, json_output)
        }
        _ => Err(format!(
            "unknown subcommand '{}'; expected run-turn, compare, restore, or branch",
            command
        )),
    }
}

fn run_turn(
    state_root: &Path,
    output: &Path,
    prompt: &str,
    selected_targets: &[ChatArtifactSelectionTarget],
    json_output: bool,
) -> Result<(), String> {
    chat_proof_trace("run_turn:start");
    let memory_runtime = memory_runtime_for(state_root)?;
    let mut task = load_or_create_task(state_root, prompt)?;
    apply_selected_targets_to_task(&mut task, selected_targets)?;
    let workspace_root_base = state_root.join("chat-workspaces");
    fs::create_dir_all(&workspace_root_base).map_err(|error| {
        format!(
            "failed to create proof workspace root '{}': {}",
            workspace_root_base.display(),
            error
        )
    })?;
    let inference_runtime = crate::create_inference_runtime();
    let acceptance_inference_runtime =
        crate::create_acceptance_inference_runtime(&inference_runtime);
    chat_proof_trace("run_turn:before_current_task_turn");
    run_chat_current_task_turn_for_proof(
        &mut task,
        prompt,
        memory_runtime.clone(),
        inference_runtime,
        acceptance_inference_runtime,
        &workspace_root_base,
    )?;
    chat_proof_trace("run_turn:after_current_task_turn");
    save_task(state_root, &task)?;
    chat_proof_trace("run_turn:after_save_task");
    let evidence = materialize_current_task_output(&task, &memory_runtime, output, prompt)?;
    chat_proof_trace("run_turn:after_materialize_output");
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&evidence).map_err(|error| error.to_string())?
        );
    }
    chat_proof_trace("run_turn:return");
    Ok(())
}

fn compare_revisions(
    state_root: &Path,
    base_revision_id: &str,
    target_revision_id: &str,
    json_output: bool,
) -> Result<(), String> {
    let memory_runtime = memory_runtime_for(state_root)?;
    let task = load_task(state_root)?;
    let chat_session = task
        .chat_session
        .as_ref()
        .ok_or_else(|| "no Chat session is available in proof state".to_string())?;
    let base = chat_session
        .revisions
        .iter()
        .find(|revision| revision.revision_id == base_revision_id)
        .ok_or_else(|| format!("revision '{}' was not found", base_revision_id))?;
    let target = chat_session
        .revisions
        .iter()
        .find(|revision| revision.revision_id == target_revision_id)
        .ok_or_else(|| format!("revision '{}' was not found", target_revision_id))?;
    let changed_paths = changed_paths_between_revisions(base, target, Some(&memory_runtime));

    let comparison = ProofRevisionComparison {
        base_revision_id: base_revision_id.to_string(),
        target_revision_id: target_revision_id.to_string(),
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
        full_chat_path: true,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&comparison).map_err(|error| error.to_string())?
        );
    }
    Ok(())
}

fn restore_revision(
    state_root: &Path,
    output: &Path,
    revision_id: &str,
    json_output: bool,
) -> Result<(), String> {
    let memory_runtime = memory_runtime_for(state_root)?;
    let mut task = load_task(state_root)?;
    let chat_session = task
        .chat_session
        .as_mut()
        .ok_or_else(|| "no Chat session is available in proof state".to_string())?;
    let revision = chat_session
        .revisions
        .iter()
        .find(|candidate| candidate.revision_id == revision_id)
        .cloned()
        .ok_or_else(|| format!("revision '{}' was not found", revision_id))?;
    apply_revision_to_session(chat_session, &revision);
    save_task(state_root, &task)?;
    let evidence =
        materialize_current_task_output(&task, &memory_runtime, output, revision.prompt.as_str())?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&evidence).map_err(|error| error.to_string())?
        );
    }
    Ok(())
}

fn branch_revision(
    state_root: &Path,
    output: &Path,
    revision_id: &str,
    json_output: bool,
) -> Result<(), String> {
    let memory_runtime = memory_runtime_for(state_root)?;
    let mut task = load_task(state_root)?;
    let chat_session = task
        .chat_session
        .as_mut()
        .ok_or_else(|| "no Chat session is available in proof state".to_string())?;
    let seed_revision = chat_session
        .revisions
        .iter()
        .find(|candidate| candidate.revision_id == revision_id)
        .cloned()
        .ok_or_else(|| format!("revision '{}' was not found", revision_id))?;
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
    branch_revision.parent_revision_id = Some(revision_id.to_string());
    branch_revision.branch_id = format!("branch-{}", branch_index);
    branch_revision.branch_label = format!("Branch {}", branch_index);
    branch_revision.prompt = format!(
        "Branch from {} at {}",
        branch_revision.branch_label, branch_revision.created_at
    );
    branch_revision.created_at = chrono::Utc::now().to_rfc3339();
    chat_session.revisions.push(branch_revision.clone());
    apply_revision_to_session(chat_session, &branch_revision);
    save_task(state_root, &task)?;
    let evidence = materialize_current_task_output(
        &task,
        &memory_runtime,
        output,
        branch_revision.prompt.as_str(),
    )?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&evidence).map_err(|error| error.to_string())?
        );
    }
    Ok(())
}

fn materialize_current_task_output(
    task: &AgentTask,
    memory_runtime: &Arc<MemoryRuntime>,
    output: &Path,
    prompt: &str,
) -> Result<ProofGenerationEvidence, String> {
    let chat_session = task
        .chat_session
        .as_ref()
        .ok_or_else(|| "no Chat session is attached to the current proof task".to_string())?;
    ensure_clean_directory(output)?;

    if chat_session.artifact_manifest.renderer
        == crate::models::ChatRendererKind::WorkspaceSurface
    {
        let workspace_root = chat_session
            .workspace_root
            .as_ref()
            .ok_or_else(|| "workspace Chat session is missing a workspace root".to_string())?;
        copy_workspace_source_tree(Path::new(workspace_root), output)?;
    } else {
        for file in &chat_session.artifact_manifest.files {
            let Some(artifact_id) = file.artifact_id.as_deref() else {
                continue;
            };
            let bytes = orchestrator::load_artifact_content(memory_runtime, artifact_id)
                .ok_or_else(|| {
                    format!(
                        "failed to load artifact blob '{}' for '{}'",
                        artifact_id, file.path
                    )
                })?;
            let target = output.join(&file.path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!("failed to create '{}': {}", parent.display(), error)
                })?;
            }
            fs::write(&target, bytes)
                .map_err(|error| format!("failed to write '{}': {}", target.display(), error))?;
        }
    }

    let manifest_path = output.join("artifact-manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&chat_session.artifact_manifest)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("failed to write '{}': {}", manifest_path.display(), error))?;

    let session_path = output.join("chat-session.json");
    fs::write(
        &session_path,
        serde_json::to_vec_pretty(chat_session).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("failed to write '{}': {}", session_path.display(), error))?;

    let revisions_path = output.join("revision-history.json");
    fs::write(
        &revisions_path,
        serde_json::to_vec_pretty(&chat_session.revisions).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("failed to write '{}': {}", revisions_path.display(), error))?;

    let validation = chat_session.materialization.validation.clone().or_else(|| {
        let contradiction = chat_session
            .artifact_manifest
            .verification
            .summary
            .clone();
        Some(ioi_api::chat::ChatArtifactValidationResult {
            classification: ChatArtifactValidationStatus::Blocked,
            request_faithfulness: 1,
            concept_coverage: 1,
            interaction_relevance: 1,
            layout_coherence: 1,
            visual_hierarchy: 1,
            completeness: 1,
            generic_shell_detected: false,
            trivial_shell_detected: false,
            deserves_primary_artifact_view: false,
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            score_total: 0,
            proof_kind: "verification_summary".to_string(),
            primary_view_cleared: false,
            validated_paths: Vec::new(),
            issue_codes: vec!["verification_summary_only".to_string()],
            issue_classes: vec!["verification_summary_only".to_string()],
            repair_hints: vec![
                "Re-run validation so the proof export can include a full structured acceptance verdict."
                    .to_string(),
            ],
            strengths: Vec::new(),
            blocked_reasons: vec![contradiction.clone()],
            file_findings: Vec::new(),
            aesthetic_verdict: "not_evaluated_due_to_missing_validation_record".to_string(),
            interaction_verdict: "not_evaluated_due_to_missing_validation_record".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: Some("acceptance_pass".to_string()),
            strongest_contradiction: Some(contradiction.clone()),
            summary: "Proof export only has verification summary evidence; structured validation is missing."
                .to_string(),
            rationale: contradiction,
        })
    });

    let evidence = ProofGenerationEvidence {
        prompt: prompt.to_string(),
        title: chat_session.title.clone(),
        route: task
            .chat_outcome
            .clone()
            .ok_or_else(|| "proof task is missing the Chat route outcome".to_string())?,
        artifact_brief: chat_session.materialization.artifact_brief.clone(),
        blueprint: chat_session.materialization.blueprint.clone(),
        artifact_ir: chat_session.materialization.artifact_ir.clone(),
        selected_skills: chat_session.materialization.selected_skills.clone(),
        retrieved_exemplars: chat_session.materialization.retrieved_exemplars.clone(),
        edit_intent: chat_session.materialization.edit_intent.clone(),
        candidate_summaries: chat_session.materialization.candidate_summaries.clone(),
        winning_candidate_id: chat_session.materialization.winning_candidate_id.clone(),
        winning_candidate_rationale: chat_session
            .materialization
            .winning_candidate_rationale
            .clone(),
        validation,
        output_origin: chat_session.materialization.output_origin.or_else(|| {
            chat_session
                .materialization
                .production_provenance
                .as_ref()
                .map(|provenance| match provenance.kind {
                    crate::models::ChatRuntimeProvenanceKind::RealRemoteModelRuntime
                    | crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime => {
                        ChatArtifactOutputOrigin::LiveInference
                    }
                    crate::models::ChatRuntimeProvenanceKind::FixtureRuntime => {
                        ChatArtifactOutputOrigin::FixtureRuntime
                    }
                    crate::models::ChatRuntimeProvenanceKind::MockRuntime => {
                        ChatArtifactOutputOrigin::MockInference
                    }
                    crate::models::ChatRuntimeProvenanceKind::DeterministicContinuityFallback => {
                        ChatArtifactOutputOrigin::DeterministicFallback
                    }
                    crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable => {
                        ChatArtifactOutputOrigin::InferenceUnavailable
                    }
                    crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime => {
                        ChatArtifactOutputOrigin::OpaqueRuntime
                    }
                })
        }),
        production_provenance: chat_session.materialization.production_provenance.clone(),
        acceptance_provenance: chat_session.materialization.acceptance_provenance.clone(),
        fallback_used: chat_session.materialization.fallback_used,
        ux_lifecycle: chat_session.materialization.ux_lifecycle,
        failure: chat_session.materialization.failure.clone(),
        manifest: chat_session.artifact_manifest.clone(),
        verified_reply: chat_session.verified_reply.clone(),
        materialized_files: chat_session
            .artifact_manifest
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect(),
        renderable_files: chat_session
            .artifact_manifest
            .files
            .iter()
            .filter(|file| file.renderable)
            .map(|file| file.path.clone())
            .collect(),
        selected_targets: chat_session.selected_targets.clone(),
        taste_memory: chat_session.taste_memory.clone(),
        revisions: chat_session.revisions.clone(),
        active_revision_id: chat_session.active_revision_id.clone(),
        full_chat_path: true,
    };

    let generation_path = output.join("generation.json");
    fs::write(
        &generation_path,
        serde_json::to_vec_pretty(&evidence).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("failed to write '{}': {}", generation_path.display(), error))?;

    Ok(evidence)
}

fn memory_runtime_for(state_root: &Path) -> Result<Arc<MemoryRuntime>, String> {
    crate::open_or_create_memory_runtime(state_root).map(Arc::new)
}

fn load_or_create_task(state_root: &Path, prompt: &str) -> Result<AgentTask, String> {
    match fs::read_to_string(state_file(state_root)) {
        Ok(raw) => serde_json::from_str(&raw)
            .map_err(|error| format!("failed to decode stored proof task: {}", error)),
        Err(_) => Ok(empty_task(prompt)),
    }
}

fn load_task(state_root: &Path) -> Result<AgentTask, String> {
    let raw = fs::read_to_string(state_file(state_root)).map_err(|error| {
        format!(
            "failed to read proof task state '{}': {}",
            state_file(state_root).display(),
            error
        )
    })?;
    serde_json::from_str(&raw).map_err(|error| format!("failed to decode proof task: {}", error))
}

fn save_task(state_root: &Path, task: &AgentTask) -> Result<(), String> {
    fs::create_dir_all(state_root)
        .map_err(|error| format!("failed to create '{}': {}", state_root.display(), error))?;
    fs::write(
        state_file(state_root),
        serde_json::to_vec_pretty(task).map_err(|error| error.to_string())?,
    )
    .map_err(|error| {
        format!(
            "failed to write proof task state '{}': {}",
            state_file(state_root).display(),
            error
        )
    })
}

fn state_file(state_root: &Path) -> PathBuf {
    state_root.join("current-task.json")
}

fn empty_task(intent: &str) -> AgentTask {
    let mut task = AgentTask {
        id: "chat-proof-task".to_string(),
        intent: intent.trim().to_string(),
        agent: "Autopilot".to_string(),
        phase: AgentPhase::Running,
        progress: 0,
        total_steps: 20,
        current_step: "Initializing...".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        session_id: Some("chat-proof-task".to_string()),
        credential_request: None,
        clarification_request: None,
        session_checklist: Vec::new(),
        background_tasks: Vec::new(),
        history: Vec::new(),
        events: Vec::new(),
        artifacts: Vec::new(),
        chat_session: None,
        chat_outcome: None,
        renderer_session: None,
        build_session: None,
        run_bundle_id: None,
        processed_steps: HashSet::new(),
        swarm_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    };
    task.sync_runtime_views();
    task
}

fn apply_revision_to_session(
    chat_session: &mut crate::models::ChatArtifactSession,
    revision: &ChatArtifactRevision,
) {
    chat_session.title = revision.artifact_manifest.title.clone();
    chat_session.artifact_manifest = revision.artifact_manifest.clone();
    chat_session.navigator_nodes = chat_session
        .artifact_manifest
        .files
        .iter()
        .map(|file| crate::models::ChatArtifactNavigatorNode {
            id: file.path.clone(),
            label: file.path.clone(),
            kind: "file".to_string(),
            description: None,
            badge: None,
            status: None,
            lens: None,
            path: Some(file.path.clone()),
            children: Vec::new(),
        })
        .collect();
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
    chat_session.materialization.edit_intent = revision.edit_intent.clone();
    chat_session.materialization.candidate_summaries = revision.candidate_summaries.clone();
    chat_session.materialization.winning_candidate_id = revision.winning_candidate_id.clone();
    chat_session.materialization.winning_candidate_rationale = revision
        .validation
        .as_ref()
        .map(|validation| validation.rationale.clone());
    chat_session.materialization.validation = revision.validation.clone();
    chat_session.materialization.output_origin = revision.output_origin;
    chat_session.materialization.production_provenance = revision.production_provenance.clone();
    chat_session.materialization.acceptance_provenance = revision.acceptance_provenance.clone();
    chat_session.materialization.failure = revision.failure.clone();
    chat_session.materialization.file_writes = revision.file_writes.clone();
    chat_session.materialization.summary = revision
        .validation
        .as_ref()
        .map(|validation| validation.rationale.clone())
        .unwrap_or_else(|| chat_session.materialization.summary.clone());
    chat_session.materialization.ux_lifecycle = Some(revision.ux_lifecycle);
    let mut evidence = revision
        .artifact_manifest
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    if let Some(provenance) = revision
        .artifact_manifest
        .verification
        .production_provenance
        .as_ref()
    {
        evidence.push(format!(
            "production provenance: {}{}",
            provenance.label,
            provenance
                .model
                .as_ref()
                .map(|model| format!(" ({model})"))
                .unwrap_or_default()
        ));
    }
    if let Some(provenance) = revision
        .artifact_manifest
        .verification
        .acceptance_provenance
        .as_ref()
    {
        evidence.push(format!(
            "acceptance provenance: {}{}",
            provenance.label,
            provenance
                .model
                .as_ref()
                .map(|model| format!(" ({model})"))
                .unwrap_or_default()
        ));
    }
    if let Some(failure) = revision.artifact_manifest.verification.failure.as_ref() {
        evidence.push(format!("failure: {} ({})", failure.message, failure.code));
    }
    chat_session.verified_reply = crate::models::ChatVerifiedReply {
        status: revision.artifact_manifest.verification.status,
        lifecycle_state: revision.artifact_manifest.verification.lifecycle_state,
        title: format!("Chat outcome: {}", revision.artifact_manifest.title),
        summary: format!(
            "{} {}",
            revision.artifact_manifest.title, revision.artifact_manifest.verification.summary
        ),
        evidence,
        production_provenance: revision
            .artifact_manifest
            .verification
            .production_provenance
            .clone(),
        acceptance_provenance: revision
            .artifact_manifest
            .verification
            .acceptance_provenance
            .clone(),
        failure: revision.artifact_manifest.verification.failure.clone(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    chat_session.lifecycle_state = revision.artifact_manifest.verification.lifecycle_state;
    chat_session.status = match chat_session.lifecycle_state {
        crate::models::ChatArtifactLifecycleState::Ready => "ready",
        crate::models::ChatArtifactLifecycleState::Partial => "partial",
        crate::models::ChatArtifactLifecycleState::Blocked => "blocked",
        crate::models::ChatArtifactLifecycleState::Failed => "failed",
        crate::models::ChatArtifactLifecycleState::Draft => "draft",
        crate::models::ChatArtifactLifecycleState::Planned => "planned",
        crate::models::ChatArtifactLifecycleState::Materializing => "materializing",
        crate::models::ChatArtifactLifecycleState::Rendering => "rendering",
        crate::models::ChatArtifactLifecycleState::Implementing => "implementing",
        crate::models::ChatArtifactLifecycleState::Verifying => "verifying",
    }
    .to_string();
    chat_session.selected_targets = revision.selected_targets.clone();
    chat_session.ux_lifecycle = Some(revision.ux_lifecycle);
    chat_session.active_revision_id = Some(revision.revision_id.clone());
    chat_session.updated_at = chrono::Utc::now().to_rfc3339();
}

fn ensure_clean_directory(target: &Path) -> Result<(), String> {
    if target.exists() {
        fs::remove_dir_all(target)
            .map_err(|error| format!("failed to remove '{}': {}", target.display(), error))?;
    }
    fs::create_dir_all(target)
        .map_err(|error| format!("failed to create '{}': {}", target.display(), error))
}

fn copy_workspace_source_tree(source: &Path, target: &Path) -> Result<(), String> {
    copy_directory_filtered(source, target, true)
}

fn copy_directory_filtered(
    source: &Path,
    target: &Path,
    exclude_workspace_runtime_dirs: bool,
) -> Result<(), String> {
    fs::create_dir_all(target)
        .map_err(|error| format!("failed to create '{}': {}", target.display(), error))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("failed to read '{}': {}", source.display(), error))?
    {
        let entry = entry.map_err(|error| error.to_string())?;
        let entry_name = entry.file_name();
        if exclude_workspace_runtime_dirs
            && entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_dir()
            && matches!(
                entry_name.to_str(),
                Some("node_modules" | "dist" | ".chat")
            )
        {
            continue;
        }
        let source_path = entry.path();
        let target_path = target.join(&entry_name);
        if entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            copy_directory_filtered(&source_path, &target_path, exclude_workspace_runtime_dirs)?;
        } else {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!("failed to create '{}': {}", parent.display(), error)
                })?;
            }
            fs::copy(&source_path, &target_path).map_err(|error| {
                format!(
                    "failed to copy '{}' to '{}': {}",
                    source_path.display(),
                    target_path.display(),
                    error
                )
            })?;
        }
    }
    Ok(())
}

fn take_positional(args: &mut Vec<String>) -> Option<String> {
    if args.is_empty() {
        None
    } else {
        Some(args.remove(0))
    }
}

fn required_string_flag(args: &mut Vec<String>, flag: &str) -> Result<String, String> {
    let value =
        take_flag_value(args, flag).ok_or_else(|| format!("missing required flag {}", flag))?;
    if value.trim().is_empty() {
        return Err(format!("flag {} must not be empty", flag));
    }
    Ok(value)
}

fn required_path_flag(args: &mut Vec<String>, flag: &str) -> Result<PathBuf, String> {
    required_string_flag(args, flag).map(PathBuf::from)
}

fn has_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(index) = args.iter().position(|arg| arg == flag) {
        args.remove(index);
        true
    } else {
        false
    }
}

fn take_flag_values(args: &mut Vec<String>, flag: &str) -> Vec<String> {
    let mut values = Vec::new();
    while let Some(index) = args.iter().position(|arg| arg == flag) {
        args.remove(index);
        if index >= args.len() {
            break;
        }
        values.push(args.remove(index));
    }
    values
}

fn take_flag_value(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let index = args.iter().position(|arg| arg == flag)?;
    args.remove(index);
    if index >= args.len() {
        return None;
    }
    Some(args.remove(index))
}

fn ensure_no_extra_args(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(format!("unexpected extra arguments: {}", args.join(" ")))
    }
}

fn parse_selected_targets(
    raw_targets: &[String],
) -> Result<Vec<ChatArtifactSelectionTarget>, String> {
    raw_targets
        .iter()
        .enumerate()
        .map(|(index, raw)| {
            serde_json::from_str::<ChatArtifactSelectionTarget>(raw).map_err(|error| {
                format!(
                    "failed to parse --selected-target-json value {}: {}",
                    index + 1,
                    error
                )
            })
        })
        .collect()
}

fn apply_selected_targets_to_task(
    task: &mut AgentTask,
    selected_targets: &[ChatArtifactSelectionTarget],
) -> Result<(), String> {
    if selected_targets.is_empty() {
        return Ok(());
    }

    let chat_session = task.chat_session.as_mut().ok_or_else(|| {
        "--selected-target-json requires an existing Chat artifact session in proof state."
            .to_string()
    })?;
    chat_session.selected_targets = selected_targets.to_vec();
    Ok(())
}
