use super::*;
use ioi_api::studio::StudioArtifactSelectionTarget;

pub(super) async fn run_route(
    prompt: &str,
    active_artifact_id: Option<&str>,
    refinement_path: Option<&Path>,
    selected_target_json: &[String],
    fixture_path: Option<&Path>,
    use_local_runtime: bool,
    use_mock_runtime: bool,
    api_url: Option<&str>,
    api_key: Option<&str>,
    model_name: Option<&str>,
    json_output: bool,
) -> Result<()> {
    let runtime = build_inference_runtime(
        fixture_path,
        use_local_runtime,
        use_mock_runtime,
        api_url,
        api_key,
        model_name,
    )?;
    let provenance = runtime.studio_runtime_provenance();
    let selected_targets = parse_selected_targets(selected_target_json)?;
    let (_, refinement_context) =
        load_selected_refinement(refinement_path, selected_targets.as_slice())?;
    let route = match route_with_runtime(
        runtime,
        prompt,
        active_artifact_id,
        refinement_context.as_ref(),
    )
    .await
    {
        Ok(route) => route,
        Err(error) => {
            emit_json_failure(
                json_output,
                StudioArtifactFailure {
                    kind: StudioArtifactFailureKind::RoutingFailure,
                    code: if matches!(
                        provenance.kind,
                        StudioRuntimeProvenanceKind::InferenceUnavailable
                    ) {
                        "inference_unavailable"
                    } else {
                        "routing_failure"
                    }
                    .to_string(),
                    message: error.to_string(),
                },
                Some(provenance),
                None,
            )?;
            return Err(error);
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&route)?);
        return Ok(());
    }

    println!("Route: {}", outcome_kind_label(&route));
    println!("  confidence: {:.2}", route.confidence);
    println!(
        "  clarification: {}",
        if route.needs_clarification {
            "yes"
        } else {
            "no"
        }
    );
    if let Some(artifact) = &route.artifact {
        println!(
            "  artifact class: {}",
            artifact_class_label(artifact.artifact_class)
        );
        println!("  renderer: {}", renderer_label(artifact.renderer));
    }
    if !route.clarification_questions.is_empty() {
        for question in &route.clarification_questions {
            println!("  - {}", question);
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) async fn route_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    prompt: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioOutcomePlanningPayload> {
    plan_studio_outcome_with_runtime(runtime, prompt, active_artifact_id, active_artifact)
        .await
        .map_err(|error| {
            anyhow::anyhow!("Failed to route Studio prompt through local inference: {error}")
        })
}

#[cfg(not(test))]
async fn route_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    prompt: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioOutcomePlanningPayload> {
    plan_studio_outcome_with_runtime(runtime, prompt, active_artifact_id, active_artifact)
        .await
        .map_err(|error| {
            anyhow::anyhow!("Failed to route Studio prompt through local inference: {error}")
        })
}

pub(super) fn parse_selected_targets(
    selected_target_json: &[String],
) -> Result<Vec<StudioArtifactSelectionTarget>> {
    selected_target_json
        .iter()
        .enumerate()
        .map(|(index, raw)| {
            serde_json::from_str::<StudioArtifactSelectionTarget>(raw).with_context(|| {
                format!(
                    "Failed to parse --selected-target-json value {} as a StudioArtifactSelectionTarget.",
                    index + 1
                )
            })
        })
        .collect()
}

pub(super) fn apply_selected_targets_to_loaded_refinement(
    refinement: &mut Option<super::types::LoadedRefinementEvidence>,
    selected_targets: &[StudioArtifactSelectionTarget],
) -> Result<()> {
    if selected_targets.is_empty() {
        return Ok(());
    }

    let Some(loaded) = refinement.as_mut() else {
        return Err(anyhow::anyhow!(
            "--selected-target-json requires --refinement so the selection can be grounded in an active artifact."
        ));
    };
    loaded.selected_targets = selected_targets.to_vec();
    Ok(())
}

fn load_selected_refinement(
    refinement_path: Option<&Path>,
    selected_targets: &[StudioArtifactSelectionTarget],
) -> Result<(
    Option<super::types::LoadedRefinementEvidence>,
    Option<StudioArtifactRefinementContext>,
)> {
    let mut refinement = load_refinement_evidence(refinement_path)?;
    apply_selected_targets_to_loaded_refinement(&mut refinement, selected_targets)?;
    let refinement_context = refinement
        .as_ref()
        .map(refinement_context_from_loaded_evidence);
    Ok((refinement, refinement_context))
}

fn refinement_context_from_loaded_evidence(
    loaded: &super::types::LoadedRefinementEvidence,
) -> StudioArtifactRefinementContext {
    StudioArtifactRefinementContext {
        artifact_id: loaded.artifact_id.clone(),
        revision_id: loaded.revision_id.clone(),
        title: loaded.title.clone(),
        summary: loaded.summary.clone(),
        renderer: loaded.renderer,
        files: loaded.files.clone(),
        selected_targets: loaded.selected_targets.clone(),
        taste_memory: loaded.taste_memory.clone(),
    }
}

pub(super) async fn run_generate(
    prompt: &str,
    output: &Path,
    force: bool,
    active_artifact_id: Option<&str>,
    refinement_path: Option<&Path>,
    selected_target_json: &[String],
    fixture_path: Option<&Path>,
    use_local_runtime: bool,
    use_mock_runtime: bool,
    api_url: Option<&str>,
    api_key: Option<&str>,
    model_name: Option<&str>,
    acceptance_api_url: Option<&str>,
    acceptance_api_key: Option<&str>,
    acceptance_model_name: Option<&str>,
    json_output: bool,
) -> Result<()> {
    let runtime = build_inference_runtime(
        fixture_path,
        use_local_runtime,
        use_mock_runtime,
        api_url,
        api_key,
        model_name,
    )?;
    let provenance = runtime.studio_runtime_provenance();
    let acceptance_runtime = build_acceptance_inference_runtime(
        runtime.clone(),
        fixture_path,
        use_mock_runtime,
        acceptance_api_url,
        acceptance_api_key,
        acceptance_model_name,
    )?;
    let acceptance_provenance = acceptance_runtime.studio_runtime_provenance();
    let selected_targets = parse_selected_targets(selected_target_json)?;
    let (refinement, refinement_context) =
        load_selected_refinement(refinement_path, selected_targets.as_slice())?;
    let route = match route_with_runtime(
        runtime.clone(),
        prompt,
        active_artifact_id,
        refinement_context.as_ref(),
    )
    .await
    {
        Ok(route) => route,
        Err(error) => {
            emit_json_failure(
                json_output,
                StudioArtifactFailure {
                    kind: ioi_types::app::StudioArtifactFailureKind::RoutingFailure,
                    code: if matches!(
                        provenance.kind,
                        ioi_types::app::StudioRuntimeProvenanceKind::InferenceUnavailable
                    ) {
                        "inference_unavailable"
                    } else {
                        "routing_failure"
                    }
                    .to_string(),
                    message: error.to_string(),
                },
                Some(provenance),
                None,
            )?;
            return Err(error);
        }
    };
    let request = route
        .artifact
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Studio route did not produce an artifact request."))?;
    let title = derive_generated_artifact_title(prompt);
    let bundle: Result<_, anyhow::Error> =
        if request.renderer == StudioRendererKind::WorkspaceSurface {
            generate_workspace_artifact_bundle_with_runtimes(
                runtime,
                acceptance_runtime,
                &title,
                prompt,
                &request,
                refinement_context.as_ref(),
            )
            .await
            .map_err(anyhow::Error::msg)
        } else {
            generate_studio_artifact_bundle_with_runtimes(
                runtime,
                acceptance_runtime,
                &title,
                prompt,
                &request,
                refinement_context.as_ref(),
            )
            .await
            .map_err(anyhow::Error::new)
        }
        .map_err(|error| anyhow::anyhow!("Failed to generate Studio artifact bundle: {error}"));
    let bundle = match bundle {
        Ok(bundle) => bundle,
        Err(error) => {
            emit_json_failure(
                json_output,
                StudioArtifactFailure {
                    kind: StudioArtifactFailureKind::GenerationFailure,
                    code: if matches!(
                        provenance.kind,
                        StudioRuntimeProvenanceKind::InferenceUnavailable
                    ) || matches!(
                        acceptance_provenance.kind,
                        StudioRuntimeProvenanceKind::InferenceUnavailable
                    ) {
                        "inference_unavailable"
                    } else {
                        "generation_failure"
                    }
                    .to_string(),
                    message: error.to_string(),
                },
                Some(provenance),
                Some(acceptance_provenance),
            )?;
            return Err(error);
        }
    };

    prepare_output_directory(output, force)?;
    write_generated_payload(output, &title, &bundle.winner)?;

    let manifest = build_generated_manifest(
        &title,
        &request,
        &bundle.winner,
        &bundle.judge,
        &bundle.production_provenance,
        &bundle.acceptance_provenance,
        bundle.failure.as_ref(),
    );
    let manifest_path = output.join("artifact-manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).context("Failed to serialize generated manifest.")?,
    )
    .with_context(|| format!("Failed to write '{}'.", manifest_path.display()))?;
    let verified_reply = compose_verified_reply(&manifest);
    let evidence = GeneratedArtifactEvidence {
        prompt: prompt.to_string(),
        title: title.clone(),
        route,
        artifact_brief: Some(bundle.brief),
        edit_intent: bundle.edit_intent,
        candidate_summaries: bundle.candidate_summaries,
        winning_candidate_id: Some(bundle.winning_candidate_id),
        winning_candidate_rationale: Some(bundle.winning_candidate_rationale),
        judge: Some(bundle.judge),
        output_origin: Some(bundle.origin),
        production_provenance: Some(bundle.production_provenance),
        acceptance_provenance: Some(bundle.acceptance_provenance),
        fallback_used: bundle.fallback_used,
        ux_lifecycle: Some(bundle.ux_lifecycle),
        failure: bundle.failure,
        manifest,
        verified_reply,
        materialized_files: bundle
            .winner
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect(),
        renderable_files: bundle
            .winner
            .files
            .iter()
            .filter(|file| file.renderable)
            .map(|file| file.path.clone())
            .collect(),
        refinement,
    };
    let evidence_path = output.join("generation.json");
    fs::write(
        &evidence_path,
        serde_json::to_vec_pretty(&evidence).context("Failed to serialize generation evidence.")?,
    )
    .with_context(|| format!("Failed to write '{}'.", evidence_path.display()))?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&evidence)?);
        return Ok(());
    }

    println!("Generated: {}", evidence.title);
    println!("  renderer: {}", renderer_label(request.renderer));
    let judge_label = evidence
        .judge
        .as_ref()
        .map(format_judge_label)
        .unwrap_or("unavailable");
    println!("  judge: {}", judge_label);
    println!("  output: {}", output.display());
    println!("  evidence: {}", evidence_path.display());
    Ok(())
}

fn emit_json_failure(
    json_output: bool,
    error: StudioArtifactFailure,
    production_provenance: Option<StudioRuntimeProvenance>,
    acceptance_provenance: Option<StudioRuntimeProvenance>,
) -> Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&ArtifactCommandErrorEnvelope {
                error,
                production_provenance,
                acceptance_provenance,
            })?
        );
    }
    Ok(())
}
