use super::*;

pub(super) struct StudioSurfaceContractPromptBundle {
    pub(super) design_label: &'static str,
    pub(super) design_spine: Option<StudioHtmlPromotedDesignSkillSpine>,
    pub(super) scaffold_label: &'static str,
    pub(super) scaffold_contract: Option<StudioHtmlScaffoldContract>,
    pub(super) component_label: &'static str,
    pub(super) component_packs: Vec<StudioHtmlComponentPackContract>,
    pub(super) execution_digest: String,
}

pub(super) fn studio_surface_contract_prompt_bundle(
    brief: &StudioArtifactBrief,
    blueprint: &StudioArtifactBlueprint,
    artifact_ir: &StudioArtifactIR,
    selected_skills: &[StudioArtifactSelectedSkill],
    candidate_seed: u64,
) -> StudioSurfaceContractPromptBundle {
    match blueprint.renderer {
        StudioRendererKind::HtmlIframe => StudioSurfaceContractPromptBundle {
            design_label: "Studio promoted design skill spine",
            design_spine: studio_html_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Studio HTML scaffold contract",
            scaffold_contract: studio_html_scaffold_contract(
                blueprint,
                artifact_ir,
                candidate_seed,
            ),
            component_label: "Studio HTML component pack contracts",
            component_packs: studio_html_component_pack_contracts(blueprint),
            execution_digest: studio_html_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        StudioRendererKind::JsxSandbox => StudioSurfaceContractPromptBundle {
            design_label: "Studio JSX design skill spine",
            design_spine: studio_jsx_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Studio JSX scaffold contract",
            scaffold_contract: studio_jsx_scaffold_contract(blueprint, artifact_ir, candidate_seed),
            component_label: "Studio JSX component pack contracts",
            component_packs: studio_jsx_component_pack_contracts(blueprint),
            execution_digest: studio_jsx_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        StudioRendererKind::Svg => StudioSurfaceContractPromptBundle {
            design_label: "Studio SVG design skill spine",
            design_spine: studio_svg_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Studio SVG scaffold contract",
            scaffold_contract: studio_svg_scaffold_contract(blueprint, artifact_ir, candidate_seed),
            component_label: "Studio SVG component pack contracts",
            component_packs: studio_svg_component_pack_contracts(blueprint),
            execution_digest: studio_svg_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        StudioRendererKind::PdfEmbed => StudioSurfaceContractPromptBundle {
            design_label: "Studio PDF design skill spine",
            design_spine: studio_pdf_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Studio PDF scaffold contract",
            scaffold_contract: studio_pdf_scaffold_contract(blueprint, artifact_ir, candidate_seed),
            component_label: "Studio PDF component pack contracts",
            component_packs: studio_pdf_component_pack_contracts(blueprint),
            execution_digest: studio_pdf_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        _ => StudioSurfaceContractPromptBundle {
            design_label: "Studio renderer design skill spine",
            design_spine: None,
            scaffold_label: "Studio renderer scaffold contract",
            scaffold_contract: None,
            component_label: "Studio renderer component pack contracts",
            component_packs: Vec::new(),
            execution_digest: String::new(),
        },
    }
}

pub(super) fn materialization_repair_candidate_view(
    raw_output: &str,
    request: &StudioOutcomeArtifactRequest,
) -> serde_json::Value {
    match super::parse_studio_generated_artifact_payload(raw_output) {
        Ok(mut candidate) => {
            super::normalize_generated_artifact_payload(&mut candidate, request);
            studio_artifact_refinement_candidate_view(&candidate)
        }
        Err(_) => json!({
            "rawOutputPreview": truncate_candidate_failure_preview(raw_output, 3600),
        }),
    }
}

pub(super) fn merged_candidate_summaries(
    current: &[StudioArtifactCandidateSummary],
    failed: &[StudioArtifactCandidateSummary],
) -> Vec<StudioArtifactCandidateSummary> {
    let mut combined = current.to_vec();
    combined.extend(failed.iter().cloned());
    combined
}

pub(super) fn derive_planning_context_for_request(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<StudioArtifactBlueprint>,
    artifact_ir: Option<StudioArtifactIR>,
    selected_skills: Vec<StudioArtifactSelectedSkill>,
) -> StudioArtifactPlanningContext {
    if request.renderer == StudioRendererKind::WorkspaceSurface {
        return StudioArtifactPlanningContext {
            brief: brief.clone(),
            blueprint: None,
            artifact_ir: None,
            selected_skills,
            retrieved_exemplars: Vec::new(),
        };
    }

    let resolved_blueprint =
        blueprint.unwrap_or_else(|| derive_studio_artifact_blueprint(request, brief));
    let resolved_artifact_ir = artifact_ir
        .unwrap_or_else(|| compile_studio_artifact_ir(request, brief, &resolved_blueprint));
    StudioArtifactPlanningContext {
        brief: brief.clone(),
        blueprint: Some(resolved_blueprint),
        artifact_ir: Some(resolved_artifact_ir),
        selected_skills,
        retrieved_exemplars: Vec::new(),
    }
}

pub(super) fn studio_artifact_selected_skill_prompt_view(
    selected_skills: &[StudioArtifactSelectedSkill],
) -> serde_json::Value {
    serde_json::Value::Array(
        selected_skills
            .iter()
            .map(|skill| {
                json!({
                    "name": skill.name,
                    "description": skill.description,
                    "lifecycleState": skill.lifecycle_state,
                    "sourceType": skill.source_type,
                    "matchedNeedKinds": skill.matched_need_kinds,
                    "matchedNeedIds": skill.matched_need_ids,
                    "matchRationale": skill.match_rationale,
                    "relativePath": skill.relative_path,
                    "guidanceMarkdown": skill.guidance_markdown.as_ref().map(|markdown| {
                        let trimmed = markdown.trim();
                        let mut clipped = trimmed.chars().take(1800).collect::<String>();
                        if trimmed.chars().count() > 1800 {
                            clipped.push_str("...");
                        }
                        clipped
                    }),
                })
            })
            .collect(),
    )
}

pub(super) fn studio_artifact_exemplar_prompt_view(
    exemplars: &[StudioArtifactExemplar],
) -> serde_json::Value {
    serde_json::Value::Array(
        exemplars
            .iter()
            .map(|exemplar| {
                json!({
                    "recordId": exemplar.record_id,
                    "title": exemplar.title,
                    "summary": exemplar.summary,
                    "renderer": exemplar.renderer,
                    "scaffoldFamily": exemplar.scaffold_family,
                    "thesis": exemplar.thesis,
                    "qualityRationale": exemplar.quality_rationale,
                    "scoreTotal": exemplar.score_total,
                    "designCues": exemplar.design_cues,
                    "componentPatterns": exemplar.component_patterns,
                    "antiPatterns": exemplar.anti_patterns,
                    "sourceRevisionId": exemplar.source_revision_id,
                })
            })
            .collect(),
    )
}

pub(super) fn blocked_candidate_generation_judge(message: &str) -> StudioArtifactJudgeResult {
    StudioArtifactJudgeResult {
        classification: StudioArtifactJudgeClassification::Blocked,
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
        issue_classes: vec!["generation_failure".to_string()],
        repair_hints: vec![
            "Regenerate a structurally valid candidate before acceptance judging.".to_string(),
        ],
        strengths: Vec::new(),
        blocked_reasons: vec![message.to_string()],
        file_findings: vec![format!("materialization: {}", message)],
        aesthetic_verdict: "No valid surfaced artifact exists yet.".to_string(),
        interaction_verdict: "Interaction quality cannot be judged until materialization succeeds."
            .to_string(),
        truthfulness_warnings: vec![
            "The candidate failed before producing a verifiable artifact.".to_string(),
        ],
        recommended_next_pass: Some("structural_repair".to_string()),
        strongest_contradiction: Some(message.to_string()),
        rationale: message.to_string(),
    }
}

pub(super) fn failed_render_evaluation(
    request: &StudioOutcomeArtifactRequest,
    message: &str,
) -> StudioArtifactRenderEvaluation {
    StudioArtifactRenderEvaluation {
        supported: render_evaluation_required(request),
        first_paint_captured: false,
        interaction_capture_attempted: false,
        captures: Vec::new(),
        layout_density_score: 1,
        spacing_alignment_score: 1,
        typography_contrast_score: 1,
        visual_hierarchy_score: 1,
        blueprint_consistency_score: 1,
        overall_score: 1,
        findings: vec![StudioArtifactRenderFinding {
            code: "render_eval_failure".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary: message.to_string(),
        }],
        summary: message.to_string(),
    }
}

pub(crate) fn render_evaluation_required(request: &StudioOutcomeArtifactRequest) -> bool {
    request.verification.require_render
        || matches!(
            request.renderer,
            StudioRendererKind::HtmlIframe | StudioRendererKind::Svg
        )
}

pub(crate) async fn evaluate_candidate_render_with_fallback(
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate: &StudioGeneratedArtifactPayload,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Option<StudioArtifactRenderEvaluation> {
    if !render_evaluation_required(request) {
        studio_generation_trace(format!(
            "artifact_generation:render_eval:skip renderer={:?} reason=not_required",
            request.renderer
        ));
        return None;
    }
    let timeout = render_eval_timeout_for_runtime(request.renderer, runtime_kind);
    studio_generation_trace(format!(
        "artifact_generation:render_eval:start renderer={:?} timeout_ms={}",
        request.renderer,
        timeout.map(|value| value.as_millis()).unwrap_or(0)
    ));
    let evaluation = match timeout {
        Some(limit) => match tokio::time::timeout(
            limit,
            evaluate_studio_artifact_render_if_configured(
                render_evaluator,
                request,
                brief,
                blueprint,
                artifact_ir,
                edit_intent,
                candidate,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(format!(
                "Render evaluation timed out after {} seconds.",
                limit.as_secs()
            )),
        },
        None => {
            evaluate_studio_artifact_render_if_configured(
                render_evaluator,
                request,
                brief,
                blueprint,
                artifact_ir,
                edit_intent,
                candidate,
            )
            .await
        }
    };

    match evaluation {
        Ok(render_evaluation) => {
            studio_generation_trace(format!(
                "artifact_generation:render_eval:ok renderer={:?} present={}",
                request.renderer,
                render_evaluation.is_some()
            ));
            render_evaluation
        }
        Err(error) => Some(failed_render_evaluation(
            request,
            &format!(
                "Render evaluation failed before Studio could verify the surfaced first paint: {}",
                error
            ),
        )),
    }
}

pub(super) async fn judge_candidate_with_runtime_and_render_eval(
    runtime: Arc<dyn InferenceRuntime>,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
    title: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate: &StudioGeneratedArtifactPayload,
) -> Result<StudioArtifactJudgeResult, String> {
    let judge = judge_studio_artifact_candidate_with_runtime_and_render_eval(
        runtime,
        title,
        request,
        brief,
        edit_intent,
        candidate,
        render_evaluation,
    )
    .await?;
    Ok(merge_studio_artifact_render_evaluation_into_judge(
        request,
        judge,
        render_evaluation,
    ))
}

pub(super) async fn judge_candidate_with_runtime_and_render_eval_with_timeout(
    runtime: Arc<dyn InferenceRuntime>,
    acceptance_timeout: Option<Duration>,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
    title: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate: &StudioGeneratedArtifactPayload,
) -> Result<StudioArtifactJudgeResult, String> {
    let judge = judge_candidate_with_runtime_and_render_eval(
        runtime,
        render_evaluation,
        title,
        request,
        brief,
        edit_intent,
        candidate,
    );
    match acceptance_timeout {
        Some(limit) => match tokio::time::timeout(limit, judge).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "Acceptance judging timed out after {}.",
                format_timeout_duration(limit)
            )),
        },
        None => judge.await,
    }
}
