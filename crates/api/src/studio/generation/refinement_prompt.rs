use super::*;

pub fn build_studio_artifact_candidate_refinement_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
    validation: &StudioArtifactValidationResult,
    candidate_id: &str,
    candidate_seed: u64,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_candidate_refinement_prompt_for_runtime(
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
        candidate,
        render_evaluation,
        validation,
        candidate_id,
        candidate_seed,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

pub(crate) fn build_studio_artifact_candidate_refinement_prompt_for_runtime(
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
    candidate: &StudioGeneratedArtifactPayload,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
    validation: &StudioArtifactValidationResult,
    candidate_id: &str,
    candidate_seed: u64,
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
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::studio_artifact_interaction_contract(brief),
        "Studio interaction contract",
        compact_prompt,
    )?;
    let edit_intent_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &edit_intent,
            "Studio artifact edit intent focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(&edit_intent, "Studio artifact edit intent", false)?
    };
    let refinement_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_context_focus(refinement),
            "Studio refinement context focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(
            &studio_artifact_refinement_context_view(refinement),
            "Studio refinement context",
            false,
        )?
    };
    let candidate_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_candidate_focus(candidate),
            "Studio artifact candidate focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(
            &studio_artifact_refinement_candidate_view(candidate),
            "Studio artifact candidate",
            false,
        )?
    };
    let validation_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_validation_focus(validation),
            "Studio artifact validation focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(
            validation,
            "Studio artifact validation result",
            false,
        )?
    };
    let render_eval_json = serialize_materialization_prompt_json(
        &super::super::validation::studio_artifact_validation_render_eval_focus(render_evaluation),
        if compact_prompt {
            "Studio artifact render evaluation focus"
        } else {
            "Studio artifact render evaluation"
        },
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
    let refinement_directives =
        super::studio_artifact_candidate_refinement_directives(request, brief, validation);
    let refinement_directives = if compact_prompt {
        compact_local_html_directives_text(&refinement_directives)
    } else {
        refinement_directives
    };
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
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact refiner. Patch the current candidate in place to resolve the validation's cited contradictions while preserving working structure and strong request-specific content. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nArtifact brief focus JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent focus JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nCurrent candidate focus JSON:\n{}\n\nAcceptance validation result focus JSON:\n{}\n\nRender evaluation focus JSON:\n{}\n\nPatch the current candidate so it keeps the strongest working structure, but fixes the cited request-faithfulness, interaction, hierarchy, completeness, and witnessed execution failures. Preserve file paths unless they are actively wrong.\n\nRefinement output contract:\nReturn the patched artifact inside the exact JSON schema below; do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object.\n\nRefinement directives:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                    title,
                    intent,
                    request_focus_json,
                    brief_focus_json,
                    interaction_contract_json,
                    edit_intent_json,
                    refinement_json,
                    candidate_id,
                    candidate_seed,
                    candidate_json,
                    validation_json,
                    render_eval_json,
                    refinement_directives,
                    scaffold_execution_block,
                    renderer_guidance,
                    schema_contract,
                )
            }
        ]));
    }
    let design_label = format!("{} JSON", surface_contracts.design_label);
    let scaffold_label = format!("{} JSON", surface_contracts.scaffold_label);
    let component_label = format!("{} JSON", surface_contracts.component_label);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact refiner. Patch the current candidate in place to resolve the validation's cited contradictions while preserving working structure and strong request-specific content. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nArtifact blueprint JSON:\n{}\n\nArtifact IR JSON:\n{}\n\nSelected skill guidance JSON:\n{}\n\nRetrieved exemplar JSON:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nCurrent candidate JSON:\n{}\n\nAcceptance validation result JSON:\n{}\n\nRender evaluation JSON:\n{}\n\nPatch the current candidate so it keeps the strongest working structure, but fixes the cited request-faithfulness, interaction, hierarchy, completeness, and witnessed execution failures. Preserve file paths unless they are actively wrong.\n\nRefinement output contract:\nReturn the patched artifact inside the exact JSON schema below; do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object.\n\nRefinement directives:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
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
                interaction_contract_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                candidate_json,
                validation_json,
                render_eval_json,
                refinement_directives,
                scaffold_execution_block,
                renderer_guidance,
                schema_contract,
            )
        }
    ]))
}

pub fn build_studio_artifact_candidate_refinement_repair_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    validation: &StudioArtifactValidationResult,
    candidate_id: &str,
    candidate_seed: u64,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_candidate_refinement_repair_prompt_for_runtime(
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
        candidate,
        validation,
        candidate_id,
        candidate_seed,
        raw_output,
        failure,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

pub(super) fn build_studio_artifact_candidate_refinement_repair_prompt_for_runtime(
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
    candidate: &StudioGeneratedArtifactPayload,
    validation: &StudioArtifactValidationResult,
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
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::studio_artifact_interaction_contract(brief),
        "Studio interaction contract",
        compact_prompt,
    )?;
    let edit_intent_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &edit_intent,
            "Studio artifact edit intent focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(&edit_intent, "Studio artifact edit intent", false)?
    };
    let refinement_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_context_focus(refinement),
            "Studio refinement context focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(
            &studio_artifact_refinement_context_view(refinement),
            "Studio refinement context",
            false,
        )?
    };
    let candidate_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_candidate_focus(candidate),
            "Studio artifact candidate focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(
            &studio_artifact_refinement_candidate_view(candidate),
            "Studio artifact candidate",
            false,
        )?
    };
    let validation_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_validation_focus(validation),
            "Studio artifact validation focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(
            validation,
            "Studio artifact validation result",
            false,
        )?
    };
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
                truncate_materialization_focus_text(&scaffold_execution_digest, 320)
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
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact refinement repairer. Repair the refined candidate into a schema-valid patch that resolves the cited contradictions while preserving the current artifact's strongest valid structure. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nArtifact brief focus JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent focus JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nCurrent candidate focus JSON:\n{}\n\nAcceptance validation result focus JSON:\n{}\n\nThe previous refinement payload was rejected.\nFailure:\n{}\n\nPrevious raw refinement output:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\nFailure-specific repair directives:\n{}\n\nRepair the refinement payload so it stays request-faithful, preserves working structure, and fully validates.\n\n{}",
                    title,
                    intent,
                    request_focus_json,
                    brief_focus_json,
                    interaction_contract_json,
                    edit_intent_json,
                    refinement_json,
                    candidate_id,
                    candidate_seed,
                    candidate_json,
                    validation_json,
                    failure,
                    truncate_candidate_failure_preview(raw_output, 1600)
                        .unwrap_or_else(|| "(empty)".to_string()),
                    scaffold_execution_block,
                    renderer_guidance,
                    failure_directives,
                    schema_contract,
                )
            }
        ]));
    }
    let design_label = format!("{} JSON", surface_contracts.design_label);
    let scaffold_label = format!("{} JSON", surface_contracts.scaffold_label);
    let component_label = format!("{} JSON", surface_contracts.component_label);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact refinement repairer. Repair the refined candidate into a schema-valid patch that resolves the cited contradictions while preserving the current artifact's strongest valid structure. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nArtifact blueprint JSON:\n{}\n\nArtifact IR JSON:\n{}\n\nSelected skill guidance JSON:\n{}\n\nRetrieved exemplar JSON:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nCurrent candidate JSON:\n{}\n\nAcceptance validation result JSON:\n{}\n\nThe previous refinement payload was rejected.\nFailure:\n{}\n\nPrevious raw refinement output:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\nFailure-specific repair directives:\n{}\n\nRepair the refinement payload so it stays request-faithful, preserves working structure, and fully validates.\n\n{}",
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
                interaction_contract_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                candidate_json,
                validation_json,
                failure,
                raw_output,
                scaffold_execution_block,
                renderer_guidance,
                failure_directives,
                schema_contract,
            )
        }
    ]))
}
