use super::*;

pub fn build_studio_artifact_materialization_repair_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_materialization_repair_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        None,
        None,
        &[],
        &[],
        edit_intent,
        refinement,
        candidate_id,
        candidate_seed,
        raw_output,
        failure,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

pub(crate) fn build_studio_artifact_materialization_repair_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    raw_output: &str,
    failure: &str,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let resolved_blueprint = blueprint
        .cloned()
        .unwrap_or_else(|| derive_studio_artifact_blueprint(request, brief));
    let resolved_artifact_ir = artifact_ir
        .cloned()
        .unwrap_or_else(|| compile_studio_artifact_ir(request, brief, &resolved_blueprint));
    let request_json =
        serialize_materialization_prompt_json(request, "Studio artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Studio artifact brief", compact_prompt)?;
    let blueprint_json = serialize_materialization_prompt_json(
        &resolved_blueprint,
        "Studio artifact blueprint",
        compact_prompt,
    )?;
    let artifact_ir_json = serialize_materialization_prompt_json(
        &resolved_artifact_ir,
        "Studio artifact IR",
        compact_prompt,
    )?;
    let selected_skills_json = serialize_materialization_prompt_json(
        &studio_artifact_selected_skill_prompt_view(selected_skills),
        "Studio selected skill guidance",
        compact_prompt,
    )?;
    let retrieved_exemplars_json = serialize_materialization_prompt_json(
        &studio_artifact_exemplar_prompt_view(retrieved_exemplars),
        "Studio retrieved exemplars",
        compact_prompt,
    )?;
    let surface_contracts = studio_surface_contract_prompt_bundle(
        brief,
        &resolved_blueprint,
        &resolved_artifact_ir,
        selected_skills,
        candidate_seed,
    );
    let promoted_design_spine_json = serialize_materialization_prompt_json(
        &surface_contracts.design_spine,
        surface_contracts.design_label,
        compact_prompt,
    )?;
    let scaffold_contract_json = serialize_materialization_prompt_json(
        &surface_contracts.scaffold_contract,
        surface_contracts.scaffold_label,
        compact_prompt,
    )?;
    let component_pack_contract_json = serialize_materialization_prompt_json(
        &surface_contracts.component_packs,
        surface_contracts.component_label,
        compact_prompt,
    )?;
    let edit_intent_json = serialize_materialization_prompt_json(
        &edit_intent,
        "Studio artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &studio_artifact_refinement_context_view(refinement),
        "Studio refinement context",
        compact_prompt,
    )?;
    let renderer_guidance = studio_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let scaffold_execution_digest = surface_contracts.execution_digest;
    let scaffold_execution_block = if scaffold_execution_digest.is_empty() {
        String::new()
    } else {
        format!(
            "\n\nScaffold execution digest:\n{}",
            if compact_prompt {
                truncate_materialization_focus_text(&scaffold_execution_digest, 180)
            } else {
                scaffold_execution_digest
            }
        )
    };
    let failure_directives =
        super::studio_artifact_materialization_failure_directives(request, brief, failure);
    let schema_contract =
        studio_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind);
    if compact_prompt {
        let request_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_materialization_request_focus(request),
            "Studio artifact request focus",
            true,
        )?;
        let brief_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_materialization_brief_focus(brief),
            "Studio artifact brief focus",
            true,
        )?;
        let interaction_contract_json = serialize_materialization_prompt_json(
            &super::studio_artifact_interaction_contract(brief),
            "Studio interaction contract",
            true,
        )?;
        let edit_intent_focus_json = serialize_materialization_prompt_json(
            &edit_intent,
            "Studio artifact edit intent focus",
            true,
        )?;
        let refinement_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_refinement_context_focus(refinement),
            "Studio refinement context focus",
            true,
        )?;
        let previous_candidate_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_materialization_repair_candidate_focus(raw_output, request),
            "Studio artifact repair candidate focus",
            true,
        )?;
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact materialization repairer. Patch the previous candidate into a schema-valid JSON artifact payload. Preserve the strongest valid request-specific structure instead of restarting from a fresh shell. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nArtifact brief focus JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent focus JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nPrevious candidate focus JSON:\n{}\n\nThe previous artifact payload was rejected.\nFailure:\n{}\n\nFailure-specific repair directives:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\nRepair the payload so it is fully schema-valid, keeps the strongest working structure, and remains request-faithful. Return JSON only.\n\n{}",
                    title,
                    intent,
                    request_focus_json,
                    brief_focus_json,
                    interaction_contract_json,
                    edit_intent_focus_json,
                    refinement_focus_json,
                    candidate_id,
                    candidate_seed,
                    previous_candidate_focus_json,
                    compact_local_html_directives_text(failure),
                    compact_local_html_directives_text(&failure_directives),
                    scaffold_execution_block,
                    renderer_guidance,
                    schema_contract,
                )
            }
        ]));
    }
    let previous_candidate_json = serialize_materialization_prompt_json(
        &materialization_repair_candidate_view(raw_output, request),
        "Studio artifact repair candidate view",
        compact_prompt,
    )?;
    let raw_output_preview = truncate_candidate_failure_preview(raw_output, 3600)
        .unwrap_or_else(|| "(empty)".to_string());
    let design_label = format!("{} JSON", surface_contracts.design_label);
    let scaffold_label = format!("{} JSON", surface_contracts.scaffold_label);
    let component_label = format!("{} JSON", surface_contracts.component_label);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact materialization repairer. Repair the candidate into a schema-valid JSON artifact payload. If the previous output already contains a usable candidate shape, patch it instead of restarting from a fresh shell. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nArtifact blueprint JSON:\n{}\n\nArtifact IR JSON:\n{}\n\nSelected skill guidance JSON:\n{}\n\nRetrieved exemplar JSON:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nThe previous artifact payload was rejected.\nFailure:\n{}\n\nPrevious candidate view JSON:\n{}\n\nPrevious raw output excerpt:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\nFailure-specific repair directives:\n{}\n\nRepair the payload so it is fully schema-valid and request-faithful. Preserve the strongest valid content from the previous attempt when possible.\n\n{}",
                title,
                intent,
                request_json,
                brief_json,
                blueprint_json,
                artifact_ir_json,
                selected_skills_json,
                retrieved_exemplars_json,
                design_label,
                promoted_design_spine_json,
                scaffold_label,
                scaffold_contract_json,
                component_label,
                component_pack_contract_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                failure,
                previous_candidate_json,
                raw_output_preview,
                scaffold_execution_block,
                renderer_guidance,
                failure_directives,
                schema_contract,
            )
        }
    ]))
}
