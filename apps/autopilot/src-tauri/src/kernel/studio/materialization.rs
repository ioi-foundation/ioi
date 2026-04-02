use super::*;
use ioi_api::studio::{
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_render_evaluator,
    pdf_artifact_bytes, resolve_studio_artifact_runtime_plan, StudioArtifactBlueprint,
    StudioArtifactIR, StudioArtifactRuntimePolicyProfile, StudioArtifactSelectedSkill,
};
use ioi_drivers::studio_render::BrowserStudioArtifactRenderEvaluator;
use std::time::Duration;

fn studio_proof_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_STUDIO_PROOF_TRACE").is_some() {
        eprintln!("[studio-proof-trace] {}", message.as_ref());
    }
}

pub(super) fn sync_workspace_manifest_file(studio_session: &StudioArtifactSession) {
    let Some(workspace_root) = studio_session.workspace_root.as_deref() else {
        return;
    };
    let manifest_path = Path::new(workspace_root).join("artifact-manifest.json");
    let Ok(json) = serde_json::to_vec_pretty(&studio_session.artifact_manifest) else {
        return;
    };
    let _ = fs::write(manifest_path, json);
}

pub(super) fn mime_for_workspace_entry(path: &str) -> String {
    if path.ends_with(".tsx") || path.ends_with(".jsx") {
        "text/jsx".to_string()
    } else if path.ends_with(".html") {
        "text/html".to_string()
    } else if path.ends_with(".md") {
        "text/markdown".to_string()
    } else if path.ends_with(".css") {
        "text/css".to_string()
    } else if path.ends_with(".svg") {
        "image/svg+xml".to_string()
    } else {
        "text/plain".to_string()
    }
}

pub(super) fn select_workspace_recipe(
    request: &StudioOutcomeArtifactRequest,
) -> StudioScaffoldRecipe {
    match request.workspace_recipe_id.as_deref() {
        Some("vite-static-html") => StudioScaffoldRecipe::StaticHtmlVite,
        Some("react-vite") => StudioScaffoldRecipe::ReactVite,
        _ => StudioScaffoldRecipe::ReactVite,
    }
}

pub(super) fn materialize_non_workspace_artifact(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<MaterializedContentArtifact, String> {
    let runtime_profile = configured_studio_runtime_profile();
    let (memory_runtime, inference_runtime, acceptance_inference_runtime) = {
        let app_state = app.state::<Mutex<AppState>>();
        let state = app_state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        (
            state.memory_runtime.clone().ok_or_else(|| {
                "Memory runtime is unavailable for Studio artifact materialization.".to_string()
            })?,
            state.inference_runtime.clone(),
            state.acceptance_inference_runtime.clone(),
        )
    };
    let planning_context = inference_runtime.as_ref().and_then(|runtime| {
        let runtime_plan = resolve_studio_artifact_runtime_plan(
            request,
            runtime.clone(),
            acceptance_inference_runtime.clone(),
            runtime_profile,
        );
        super::skills::prepare_studio_artifact_planning_context(
            app,
            &memory_runtime,
            runtime_plan.planning_runtime,
            title,
            intent,
            request,
            refinement,
        )
    });

    materialize_non_workspace_artifact_with_dependencies(
        &memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        planning_context,
    )
}

pub(super) fn materialize_non_workspace_artifact_with_dependencies(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<StudioArtifactPlanningContext>,
) -> Result<MaterializedContentArtifact, String> {
    let generation_timeout = inference_runtime
        .as_ref()
        .map(studio_generation_timeout_for_runtime)
        .unwrap_or_else(|| Duration::from_secs(120));
    materialize_non_workspace_artifact_with_dependencies_and_timeout(
        memory_runtime,
        inference_runtime,
        acceptance_inference_runtime,
        thread_id,
        title,
        intent,
        request,
        refinement,
        generation_timeout,
        planning_context,
    )
}

pub(super) fn studio_generation_timeout_for_runtime(
    runtime: &Arc<dyn InferenceRuntime>,
) -> Duration {
    let seconds = [
        "AUTOPILOT_STUDIO_GENERATION_TIMEOUT_SECS",
        "IOI_STUDIO_GENERATION_TIMEOUT_SECS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
    })
    .unwrap_or_else(|| match runtime.studio_runtime_provenance().kind {
        crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime => 180,
        _ => 90,
    });

    Duration::from_secs(seconds)
}

fn configured_studio_runtime_profile() -> StudioArtifactRuntimePolicyProfile {
    [
        "AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE",
        "IOI_STUDIO_MODEL_ROUTING_PROFILE",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .as_deref()
            .and_then(StudioArtifactRuntimePolicyProfile::parse)
    })
    .unwrap_or(StudioArtifactRuntimePolicyProfile::Auto)
}

fn format_generation_timeout(timeout: Duration) -> String {
    if timeout.as_secs() > 0 {
        format!("{}s", timeout.as_secs())
    } else {
        format!("{}ms", timeout.as_millis())
    }
}

pub(super) fn materialize_non_workspace_artifact_with_dependencies_and_timeout(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,
    thread_id: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    generation_timeout: Duration,
    planning_context: Option<StudioArtifactPlanningContext>,
) -> Result<MaterializedContentArtifact, String> {
    studio_proof_trace(format!(
        "materialize_non_workspace:start renderer={} title={}",
        renderer_kind_id(request.renderer),
        title
    ));
    let runtime_profile = configured_studio_runtime_profile();
    let bundle = match inference_runtime {
        Some(runtime) => {
            let runtime_plan = resolve_studio_artifact_runtime_plan(
                request,
                runtime,
                acceptance_inference_runtime.clone(),
                runtime_profile,
            );
            let render_evaluator = BrowserStudioArtifactRenderEvaluator::default();
            let production_provenance = runtime_plan.generation_runtime.studio_runtime_provenance();
            let acceptance_provenance =
                runtime_plan.acceptance_runtime.studio_runtime_provenance();
            match tauri::async_runtime::block_on(async {
                tokio::time::timeout(
                    generation_timeout,
                    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_render_evaluator(
                        runtime_plan,
                        title,
                        intent,
                        request,
                        refinement,
                        planning_context.as_ref(),
                        Some(&render_evaluator),
                    ),
                )
                .await
            }) {
                Ok(Ok(bundle)) => {
                    studio_proof_trace(format!(
                        "materialize_non_workspace:bundle_ready winner={} lifecycle={:?} fallback_used={}",
                        bundle.winning_candidate_id,
                        bundle.ux_lifecycle,
                        bundle.fallback_used
                    ));
                    bundle
                }
                Ok(Err(error)) => {
                    studio_proof_trace(format!(
                        "materialize_non_workspace:bundle_blocked {}",
                        error.message
                    ));
                    return Ok(blocked_materialized_artifact_from_error(
                        title,
                        intent,
                        request,
                        refinement,
                        &error.message,
                        error.brief,
                        error.blueprint,
                        error.artifact_ir,
                        error.selected_skills,
                        error.edit_intent,
                        error.candidate_summaries,
                        Some(production_provenance),
                        Some(acceptance_provenance),
                    ));
                }
                Err(_) => {
                    let message = format!(
                        "Studio artifact generation timed out after {} while drafting artifact candidates.",
                        format_generation_timeout(generation_timeout)
                    );
                    studio_proof_trace(format!(
                        "materialize_non_workspace:bundle_timeout {}",
                        message
                    ));
                    return Ok(blocked_materialized_artifact_from_error(
                        title,
                        intent,
                        request,
                        refinement,
                        &message,
                        None,
                        planning_context.as_ref().and_then(|context| context.blueprint.clone()),
                        planning_context
                            .as_ref()
                            .and_then(|context| context.artifact_ir.clone()),
                        planning_context
                            .as_ref()
                            .map(|context| context.selected_skills.clone())
                            .unwrap_or_default(),
                        None,
                        Vec::new(),
                        Some(production_provenance),
                        Some(acceptance_provenance),
                    ));
                }
            }
        }
        None if acceptance_inference_runtime.is_some() => {
            let acceptance_provenance = acceptance_inference_runtime
                .as_ref()
                .map(|runtime| runtime.studio_runtime_provenance());
            return Ok(blocked_materialized_artifact_from_error(
                title,
                intent,
                request,
                refinement,
                "Inference runtime is unavailable for Studio artifact materialization.",
                None,
                planning_context.as_ref().and_then(|context| context.blueprint.clone()),
                planning_context
                    .as_ref()
                    .and_then(|context| context.artifact_ir.clone()),
                planning_context
                    .as_ref()
                    .map(|context| context.selected_skills.clone())
                    .unwrap_or_default(),
                None,
                Vec::new(),
                None,
                acceptance_provenance,
            ));
        }
        None => {
            return Ok(blocked_materialized_artifact_from_error(
                title,
                intent,
                request,
                refinement,
                "Inference and acceptance runtimes are unavailable for Studio artifact materialization.",
                None,
                planning_context.as_ref().and_then(|context| context.blueprint.clone()),
                planning_context
                    .as_ref()
                    .and_then(|context| context.artifact_ir.clone()),
                planning_context
                    .as_ref()
                    .map(|context| context.selected_skills.clone())
                    .unwrap_or_default(),
                None,
                Vec::new(),
                None,
                None,
            ))
        }
    };
    let bundle_edit_intent = bundle.edit_intent.clone();
    let derived_taste_memory = derive_studio_taste_memory(
        refinement.and_then(|context| context.taste_memory.as_ref()),
        &bundle.brief,
        bundle.blueprint.as_ref(),
        bundle.artifact_ir.as_ref(),
        bundle_edit_intent.as_ref(),
        Some(&bundle.judge),
    );
    let retrieved_exemplars = planning_context
        .as_ref()
        .map(|context| context.retrieved_exemplars.clone())
        .filter(|exemplars| !exemplars.is_empty())
        .or_else(|| refinement.map(|context| context.retrieved_exemplars.clone()))
        .unwrap_or_default();
    let selected_targets = bundle_edit_intent
        .as_ref()
        .map(|edit_intent| edit_intent.selected_targets.clone())
        .filter(|targets| !targets.is_empty())
        .or_else(|| refinement.map(|context| context.selected_targets.clone()))
        .unwrap_or_default();
    let generated = bundle.winner.clone();
    let output_origin = bundle.origin;
    let fallback_used = bundle.fallback_used;

    let mut artifacts = Vec::new();
    let mut files = Vec::new();
    let mut file_writes = Vec::new();
    let mut quality_files = Vec::new();

    for generated_file in generated.files.clone() {
        studio_proof_trace(format!(
            "materialize_non_workspace:file {} mime={} renderable={} bytes={}",
            generated_file.path,
            generated_file.mime,
            generated_file.renderable,
            generated_file.body.len()
        ));
        quality_files.push(MaterializedArtifactQualityFile {
            path: generated_file.path.clone(),
            mime: generated_file.mime.clone(),
            renderable: generated_file.renderable,
            downloadable: generated_file.downloadable,
            text_content: Some(generated_file.body.clone()),
        });
        let bytes = if request.renderer == StudioRendererKind::PdfEmbed
            && generated_file.path.ends_with(".pdf")
        {
            pdf_artifact_bytes(title, &generated_file.body)
        } else {
            generated_file.body.as_bytes().to_vec()
        };
        let artifact = artifact_store::create_named_file_artifact(
            memory_runtime,
            thread_id,
            &generated_file.path,
            Some(&generated_file.mime),
            None,
            &bytes,
        );
        file_writes.push(StudioArtifactMaterializationFileWrite {
            path: generated_file.path.clone(),
            kind: format!("{:?}", generated_file.role).to_lowercase(),
            content_preview: Some(truncate_preview(&generated_file.body)),
        });
        files.push(StudioArtifactManifestFile {
            path: generated_file.path.clone(),
            mime: generated_file.mime.clone(),
            role: generated_file.role,
            renderable: generated_file.renderable,
            downloadable: generated_file.downloadable,
            artifact_id: Some(artifact.artifact_id.clone()),
            external_url: None,
        });
        artifacts.push(artifact);
    }

    studio_proof_trace(format!(
        "materialize_non_workspace:files_persisted count={}",
        files.len()
    ));
    let quality_assessment = finalize_presentation_assessment(
        assess_materialized_artifact_presentation(request, &quality_files),
        &bundle.judge,
        bundle.render_evaluation.as_ref(),
        fallback_used,
        bundle.ux_lifecycle == StudioArtifactUxLifecycle::Draft,
    );
    studio_proof_trace(format!(
        "materialize_non_workspace:quality lifecycle={:?} summary={}",
        quality_assessment.lifecycle_state, quality_assessment.summary
    ));

    let mut notes = generated.notes.clone();
    notes.extend(quality_assessment.findings.iter().cloned());
    if !bundle.selected_skills.is_empty() {
        notes.push(format!(
            "Applied {} registry-backed skill guide(s) during artifact planning.",
            bundle.selected_skills.len()
        ));
    }
    if !retrieved_exemplars.is_empty() {
        notes.push(format!(
            "Grounded generation with {} high-scoring exemplar artifact(s).",
            retrieved_exemplars.len()
        ));
    }
    notes.push(format!(
        "Winning candidate {} selected via typed judging.",
        bundle.winning_candidate_id
    ));

    studio_proof_trace("materialize_non_workspace:return");
    Ok(MaterializedContentArtifact {
        artifacts,
        files,
        file_writes,
        notes,
        brief: bundle.brief,
        blueprint: bundle.blueprint,
        artifact_ir: bundle.artifact_ir,
        selected_skills: bundle.selected_skills,
        retrieved_exemplars,
        edit_intent: bundle_edit_intent.clone(),
        candidate_summaries: bundle.candidate_summaries,
        winning_candidate_id: Some(bundle.winning_candidate_id),
        winning_candidate_rationale: Some(bundle.winning_candidate_rationale),
        render_evaluation: bundle.render_evaluation,
        judge: Some(bundle.judge),
        output_origin,
        production_provenance: Some(bundle.production_provenance),
        acceptance_provenance: Some(bundle.acceptance_provenance),
        fallback_used,
        ux_lifecycle: if fallback_used {
            StudioArtifactUxLifecycle::Draft
        } else if bundle_edit_intent
            .as_ref()
            .is_some_and(|edit_intent| edit_intent.patch_existing_artifact)
        {
            StudioArtifactUxLifecycle::Locked
        } else {
            bundle.ux_lifecycle
        },
        failure: bundle.failure,
        taste_memory: derived_taste_memory.or(bundle.taste_memory),
        selected_targets,
        lifecycle_state: quality_assessment.lifecycle_state,
        verification_summary: quality_assessment.summary,
    })
}

pub(super) fn blocked_materialized_artifact_from_error(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    error: &str,
    artifact_brief: Option<StudioArtifactBrief>,
    blueprint: Option<StudioArtifactBlueprint>,
    artifact_ir: Option<StudioArtifactIR>,
    selected_skills: Vec<StudioArtifactSelectedSkill>,
    edit_intent: Option<StudioArtifactEditIntent>,
    candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    production_runtime_provenance: Option<crate::models::StudioRuntimeProvenance>,
    acceptance_runtime_provenance: Option<crate::models::StudioRuntimeProvenance>,
) -> MaterializedContentArtifact {
    let production_provenance =
        production_runtime_provenance.unwrap_or(crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        });
    let acceptance_provenance =
        acceptance_runtime_provenance.unwrap_or(crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        });
    let failure_kind = if production_provenance.kind
        == crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable
        || acceptance_provenance.kind
            == crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable
    {
        crate::models::StudioArtifactFailureKind::InferenceUnavailable
    } else {
        crate::models::StudioArtifactFailureKind::GenerationFailure
    };
    let failure = crate::models::StudioArtifactFailure {
        kind: failure_kind,
        code: match failure_kind {
            crate::models::StudioArtifactFailureKind::InferenceUnavailable => {
                "inference_unavailable"
            }
            crate::models::StudioArtifactFailureKind::RoutingFailure => "routing_failure",
            crate::models::StudioArtifactFailureKind::GenerationFailure => "generation_failure",
            crate::models::StudioArtifactFailureKind::VerificationFailure => "verification_failure",
        }
        .to_string(),
        message: error.to_string(),
    };
    let judge = StudioArtifactJudgeResult {
        classification: ioi_api::studio::StudioArtifactJudgeClassification::Blocked,
        request_faithfulness: 1,
        concept_coverage: 1,
        interaction_relevance: 1,
        layout_coherence: 1,
        visual_hierarchy: 1,
        completeness: 1,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: false,
        patched_existing_artifact: refinement.map(|_| false),
        continuity_revision_ux: refinement.map(|_| 1),
        issue_classes: vec![failure.code.clone()],
        repair_hints: vec![
            "Restore runtime availability or repair the failing generation path before retrying the artifact."
                .to_string(),
        ],
        strengths: Vec::new(),
        blocked_reasons: vec![error.to_string()],
        file_findings: Vec::new(),
        aesthetic_verdict: "not_evaluated_due_to_generation_failure".to_string(),
        interaction_verdict: "not_evaluated_due_to_generation_failure".to_string(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some("generation_retry".to_string()),
        strongest_contradiction: Some(error.to_string()),
        rationale: error.to_string(),
    };

    MaterializedContentArtifact {
        artifacts: Vec::new(),
        files: Vec::new(),
        file_writes: Vec::new(),
        notes: vec![
            "Studio refused to substitute mock or deterministic output for a failed non-workspace artifact generation."
                .to_string(),
            error.to_string(),
        ],
        brief: artifact_brief.unwrap_or_else(|| {
            blocked_failure_brief(
                title,
                intent,
                request.renderer,
                error,
                refinement
                    .and_then(|context| context.taste_memory.as_ref())
                    .map(|memory| memory.directives.clone())
                    .unwrap_or_default(),
            )
        }),
        blueprint,
        artifact_ir,
        selected_skills,
        retrieved_exemplars: refinement
            .map(|context| context.retrieved_exemplars.clone())
            .unwrap_or_default(),
        edit_intent,
        candidate_summaries,
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        render_evaluation: None,
        judge: Some(judge),
        output_origin: output_origin_from_runtime_provenance(&production_provenance),
        production_provenance: Some(production_provenance),
        acceptance_provenance: Some(acceptance_provenance),
        fallback_used: false,
        ux_lifecycle: StudioArtifactUxLifecycle::Draft,
        failure: Some(failure),
        taste_memory: refinement.and_then(|context| context.taste_memory.clone()),
        selected_targets: refinement
            .map(|context| context.selected_targets.clone())
            .unwrap_or_default(),
        lifecycle_state: StudioArtifactLifecycleState::Blocked,
        verification_summary: error.to_string(),
    }
}

pub(super) fn blocked_failure_brief(
    title: &str,
    intent: &str,
    renderer: StudioRendererKind,
    failure_message: &str,
    reference_hints: Vec<String>,
) -> StudioArtifactBrief {
    StudioArtifactBrief {
        audience: "artifact operators".to_string(),
        job_to_be_done: "surface the generation failure truthfully".to_string(),
        subject_domain: title.to_string(),
        artifact_thesis: intent.to_string(),
        required_concepts: vec![renderer_kind_id(renderer).to_string()],
        required_interactions: Vec::new(),
        visual_tone: vec!["truthful failure".to_string()],
        factual_anchors: vec![failure_message.to_string()],
        style_directives: Vec::new(),
        reference_hints,
    }
}

pub(super) fn output_origin_from_runtime_provenance(
    provenance: &crate::models::StudioRuntimeProvenance,
) -> StudioArtifactOutputOrigin {
    match provenance.kind {
        crate::models::StudioRuntimeProvenanceKind::RealRemoteModelRuntime
        | crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime => {
            StudioArtifactOutputOrigin::LiveInference
        }
        crate::models::StudioRuntimeProvenanceKind::FixtureRuntime => {
            StudioArtifactOutputOrigin::FixtureRuntime
        }
        crate::models::StudioRuntimeProvenanceKind::MockRuntime => {
            StudioArtifactOutputOrigin::MockInference
        }
        crate::models::StudioRuntimeProvenanceKind::DeterministicContinuityFallback => {
            StudioArtifactOutputOrigin::DeterministicFallback
        }
        crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable => {
            StudioArtifactOutputOrigin::InferenceUnavailable
        }
        crate::models::StudioRuntimeProvenanceKind::OpaqueRuntime => {
            StudioArtifactOutputOrigin::OpaqueRuntime
        }
    }
}

#[cfg(test)]
pub(super) fn generate_non_workspace_artifact_payload(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    inference_runtime: Option<Arc<dyn InferenceRuntime>>,
) -> Result<StudioGeneratedArtifactPayload, String> {
    let runtime = inference_runtime.ok_or_else(|| {
        "Inference runtime is unavailable for Studio artifact materialization.".to_string()
    })?;
    tauri::async_runtime::block_on(materialize_studio_artifact_with_runtime(
        runtime, title, intent, request,
    ))
}

#[cfg(test)]
pub(super) fn generated_quality_files(
    payload: &StudioGeneratedArtifactPayload,
) -> Vec<MaterializedArtifactQualityFile> {
    payload
        .files
        .iter()
        .map(|file| MaterializedArtifactQualityFile {
            path: file.path.clone(),
            mime: file.mime.clone(),
            renderable: file.renderable,
            downloadable: file.downloadable,
            text_content: Some(file.body.clone()),
        })
        .collect()
}

pub(super) fn derive_artifact_title(intent: &str) -> String {
    let trimmed = intent.trim();
    let primary = trimmed
        .split(['.', '\n', ':'])
        .next()
        .unwrap_or(trimmed)
        .trim();
    if primary.is_empty() {
        return "Studio artifact".to_string();
    }

    let title = primary;
    if title.len() <= 68 {
        title.to_string()
    } else {
        format!("{}...", &title[..65])
    }
}

pub(super) fn create_contract_artifact_for_memory_runtime(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    title: &str,
    contract: &StudioArtifactMaterializationContract,
) -> Artifact {
    artifact_store::create_report_artifact(
        memory_runtime,
        thread_id,
        &format!("Studio artifact: {}", title),
        "Machine-routable Studio artifact materialization contract",
        &serde_json::to_value(contract).unwrap_or_else(|_| json!({})),
    )
}

pub(super) fn create_contract_artifact(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    contract: &StudioArtifactMaterializationContract,
) -> Option<Artifact> {
    let memory_runtime = app
        .state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| state.memory_runtime.clone())?;
    Some(create_contract_artifact_for_memory_runtime(
        &memory_runtime,
        thread_id,
        title,
        contract,
    ))
}

pub(super) fn create_receipt_report_artifact_for_memory_runtime(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    title: &str,
    receipt: &StudioBuildReceipt,
) -> Artifact {
    artifact_store::create_report_artifact(
        memory_runtime,
        thread_id,
        &format!("{} · {}", title, receipt.title),
        "Studio build receipt",
        &serde_json::to_value(receipt).unwrap_or_else(|_| json!({})),
    )
}

pub(super) fn create_receipt_report_artifact(
    app: &AppHandle,
    thread_id: &str,
    title: &str,
    receipt: &StudioBuildReceipt,
) -> Option<Artifact> {
    let memory_runtime = app
        .state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| state.memory_runtime.clone())?;
    Some(create_receipt_report_artifact_for_memory_runtime(
        &memory_runtime,
        thread_id,
        title,
        receipt,
    ))
}

pub(super) fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}
