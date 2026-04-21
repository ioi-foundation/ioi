use super::*;

pub(super) struct ChatSurfaceContractPromptBundle {
    pub(super) design_label: &'static str,
    pub(super) design_spine: Option<ChatHtmlPromotedDesignSkillSpine>,
    pub(super) scaffold_label: &'static str,
    pub(super) scaffold_contract: Option<ChatHtmlScaffoldContract>,
    pub(super) component_label: &'static str,
    pub(super) component_packs: Vec<ChatHtmlComponentPackContract>,
    pub(super) execution_digest: String,
}

pub(super) fn chat_surface_contract_prompt_bundle(
    brief: &ChatArtifactBrief,
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    selected_skills: &[ChatArtifactSelectedSkill],
    candidate_seed: u64,
) -> ChatSurfaceContractPromptBundle {
    match blueprint.renderer {
        ChatRendererKind::HtmlIframe if chat_modal_first_html_enabled() => {
            ChatSurfaceContractPromptBundle {
                design_label: "Chat HTML query profile guidance",
                design_spine: None,
                scaffold_label: "Chat HTML renderer policy",
                scaffold_contract: None,
                component_label: "Chat HTML renderer capability packs",
                component_packs: Vec::new(),
                execution_digest: String::new(),
            }
        }
        ChatRendererKind::HtmlIframe => ChatSurfaceContractPromptBundle {
            design_label: "Chat promoted design skill spine",
            design_spine: chat_html_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Chat HTML scaffold contract",
            scaffold_contract: chat_html_scaffold_contract(
                blueprint,
                artifact_ir,
                candidate_seed,
            ),
            component_label: "Chat HTML component pack contracts",
            component_packs: chat_html_component_pack_contracts(blueprint),
            execution_digest: chat_html_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        ChatRendererKind::JsxSandbox => ChatSurfaceContractPromptBundle {
            design_label: "Chat JSX design skill spine",
            design_spine: chat_jsx_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Chat JSX scaffold contract",
            scaffold_contract: chat_jsx_scaffold_contract(blueprint, artifact_ir, candidate_seed),
            component_label: "Chat JSX component pack contracts",
            component_packs: chat_jsx_component_pack_contracts(blueprint),
            execution_digest: chat_jsx_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        ChatRendererKind::Svg => ChatSurfaceContractPromptBundle {
            design_label: "Chat SVG design skill spine",
            design_spine: chat_svg_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Chat SVG scaffold contract",
            scaffold_contract: chat_svg_scaffold_contract(blueprint, artifact_ir, candidate_seed),
            component_label: "Chat SVG component pack contracts",
            component_packs: chat_svg_component_pack_contracts(blueprint),
            execution_digest: chat_svg_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        ChatRendererKind::PdfEmbed => ChatSurfaceContractPromptBundle {
            design_label: "Chat PDF design skill spine",
            design_spine: chat_pdf_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Chat PDF scaffold contract",
            scaffold_contract: chat_pdf_scaffold_contract(blueprint, artifact_ir, candidate_seed),
            component_label: "Chat PDF component pack contracts",
            component_packs: chat_pdf_component_pack_contracts(blueprint),
            execution_digest: chat_pdf_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        _ => ChatSurfaceContractPromptBundle {
            design_label: "Chat renderer design skill spine",
            design_spine: None,
            scaffold_label: "Chat renderer scaffold contract",
            scaffold_contract: None,
            component_label: "Chat renderer component pack contracts",
            component_packs: Vec::new(),
            execution_digest: String::new(),
        },
    }
}

pub(super) fn materialization_repair_candidate_view(
    raw_output: &str,
    request: &ChatOutcomeArtifactRequest,
) -> serde_json::Value {
    match super::parse_chat_generated_artifact_payload(raw_output) {
        Ok(mut candidate) => {
            super::normalize_generated_artifact_payload(&mut candidate, request);
            chat_artifact_refinement_candidate_view(&candidate)
        }
        Err(_) => json!({
            "rawOutputPreview": truncate_candidate_failure_preview(raw_output, 3600),
        }),
    }
}

pub(super) fn merged_candidate_summaries(
    current: &[ChatArtifactCandidateSummary],
    failed: &[ChatArtifactCandidateSummary],
) -> Vec<ChatArtifactCandidateSummary> {
    let mut combined = current.to_vec();
    combined.extend(failed.iter().cloned());
    combined
}

pub fn derive_chat_artifact_prepared_context(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    blueprint: Option<ChatArtifactBlueprint>,
    artifact_ir: Option<ChatArtifactIR>,
    selected_skills: Vec<ChatArtifactSelectedSkill>,
    retrieved_exemplars: Vec<ChatArtifactExemplar>,
    retrieved_sources: Vec<ChatArtifactSourceReference>,
) -> ChatArtifactPlanningContext {
    let derive_skill_discovery_resolution =
        |preparation_needs: &ChatArtifactPreparationNeeds,
         selected_skills: &[ChatArtifactSelectedSkill],
         status: &str| {
            let guidance_status = if preparation_needs.skill_needs.is_empty() {
                "not_needed"
            } else if !selected_skills.is_empty() {
                "attached"
            } else {
                "unavailable"
            };
            ChatArtifactSkillDiscoveryResolution {
                status: status.to_string(),
                guidance_status: guidance_status.to_string(),
                guidance_evaluated: true,
                guidance_recommended: !preparation_needs.skill_needs.is_empty(),
                guidance_found: !selected_skills.is_empty(),
                guidance_attached: !selected_skills.is_empty(),
                skill_need_count: preparation_needs.skill_needs.len() as u32,
                selected_skill_count: selected_skills.len() as u32,
                selected_skill_names: selected_skills
                    .iter()
                    .map(|skill| skill.name.clone())
                    .collect(),
                search_scope: "published_runtime_skills".to_string(),
                rationale: if let Some(first_skill) = selected_skills.first() {
                    if selected_skills.len() == 1 {
                        format!(
                            "The request benefits from {} guidance before authoring.",
                            first_skill.name
                        )
                    } else {
                        format!(
                            "The request benefits from {} selected skill guides before authoring.",
                            selected_skills.len()
                        )
                    }
                } else if preparation_needs.skill_needs.is_empty() {
                    "The request can be authored directly without extra skill guidance.".to_string()
                } else {
                    "Chat checked the published runtime guidance corpus for this request but did not find a qualifying skill to attach before authoring."
                        .to_string()
                },
                failure_reason: if selected_skills.is_empty()
                    && !preparation_needs.skill_needs.is_empty()
                {
                    Some(
                        "No qualifying published runtime guidance matched the request's current skill needs."
                            .to_string(),
                    )
                } else {
                    None
                },
            }
        };
    let derive_preparation_needs =
        |resolved_blueprint: Option<&ChatArtifactBlueprint>,
         resolved_artifact_ir: Option<&ChatArtifactIR>| ChatArtifactPreparationNeeds {
            renderer: request.renderer,
            required_concepts: brief.required_concepts.clone(),
            required_interactions: brief.required_interaction_summaries(),
            skill_needs: resolved_blueprint
                .map(|value| value.skill_needs.clone())
                .unwrap_or_default(),
            require_blueprint: request.renderer != ChatRendererKind::WorkspaceSurface,
            require_artifact_ir: request.renderer != ChatRendererKind::WorkspaceSurface,
            exemplar_discovery_enabled: request.renderer != ChatRendererKind::WorkspaceSurface
                && (resolved_blueprint.is_some()
                    || resolved_artifact_ir.is_some()
                    || !brief.reference_hints.is_empty()),
        };
    let derive_resolution = |preparation_needs: &ChatArtifactPreparationNeeds| {
        ChatArtifactPreparedContextResolution {
            status: "resolved".to_string(),
            renderer: request.renderer,
            require_blueprint: preparation_needs.require_blueprint,
            require_artifact_ir: preparation_needs.require_artifact_ir,
            skill_need_count: preparation_needs.skill_needs.len() as u32,
            selected_skill_count: selected_skills.len() as u32,
            exemplar_count: retrieved_exemplars.len() as u32,
            source_count: retrieved_sources.len() as u32,
            selected_skill_names: selected_skills
                .iter()
                .map(|skill| skill.name.clone())
                .collect(),
        }
    };
    if request.renderer == ChatRendererKind::WorkspaceSurface {
        let preparation_needs = derive_preparation_needs(None, None);
        let prepared_context_resolution = derive_resolution(&preparation_needs);
        let skill_discovery_resolution =
            derive_skill_discovery_resolution(&preparation_needs, &selected_skills, "resolved");
        return ChatArtifactPlanningContext {
            brief: brief.clone(),
            blueprint: None,
            artifact_ir: None,
            preparation_needs: Some(preparation_needs),
            prepared_context_resolution: Some(prepared_context_resolution),
            skill_discovery_resolution: Some(skill_discovery_resolution),
            selected_skills,
            retrieved_exemplars,
            retrieved_sources,
        };
    }

    let resolved_blueprint =
        blueprint.unwrap_or_else(|| derive_chat_artifact_blueprint(request, brief));
    let resolved_artifact_ir = artifact_ir
        .unwrap_or_else(|| compile_chat_artifact_ir(request, brief, &resolved_blueprint));
    let preparation_needs =
        derive_preparation_needs(Some(&resolved_blueprint), Some(&resolved_artifact_ir));
    let prepared_context_resolution = derive_resolution(&preparation_needs);
    let skill_discovery_resolution =
        derive_skill_discovery_resolution(&preparation_needs, &selected_skills, "resolved");
    ChatArtifactPlanningContext {
        brief: brief.clone(),
        blueprint: Some(resolved_blueprint),
        artifact_ir: Some(resolved_artifact_ir),
        preparation_needs: Some(preparation_needs),
        prepared_context_resolution: Some(prepared_context_resolution),
        skill_discovery_resolution: Some(skill_discovery_resolution),
        selected_skills,
        retrieved_exemplars,
        retrieved_sources,
    }
}

pub(super) fn chat_artifact_selected_skill_prompt_view(
    selected_skills: &[ChatArtifactSelectedSkill],
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

pub(super) fn chat_artifact_exemplar_prompt_view(
    exemplars: &[ChatArtifactExemplar],
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

pub(super) fn failed_render_evaluation(
    request: &ChatOutcomeArtifactRequest,
    message: &str,
) -> ChatArtifactRenderEvaluation {
    ChatArtifactRenderEvaluation {
        supported: render_evaluation_required(request),
        first_paint_captured: false,
        interaction_capture_attempted: false,
        captures: Vec::new(),
        observation: None,
        acceptance_policy: None,
        layout_density_score: 1,
        spacing_alignment_score: 1,
        typography_contrast_score: 1,
        visual_hierarchy_score: 1,
        blueprint_consistency_score: 1,
        overall_score: 1,
        findings: vec![ChatArtifactRenderFinding {
            code: "render_eval_failure".to_string(),
            severity: ChatArtifactRenderFindingSeverity::Blocked,
            summary: message.to_string(),
        }],
        acceptance_obligations: Vec::new(),
        execution_witnesses: Vec::new(),
        summary: message.to_string(),
    }
}

pub(crate) fn render_evaluation_required(request: &ChatOutcomeArtifactRequest) -> bool {
    request.verification.require_render
        || matches!(
            request.renderer,
            ChatRendererKind::HtmlIframe | ChatRendererKind::Svg
        )
}

pub(crate) async fn evaluate_candidate_render_with_fallback(
    render_evaluator: Option<&dyn ChatArtifactRenderEvaluator>,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    blueprint: Option<&ChatArtifactBlueprint>,
    artifact_ir: Option<&ChatArtifactIR>,
    edit_intent: Option<&ChatArtifactEditIntent>,
    candidate: &ChatGeneratedArtifactPayload,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<ChatArtifactRenderEvaluation> {
    if !render_evaluation_required(request) {
        chat_generation_trace(format!(
            "artifact_generation:render_eval:skip renderer={:?} reason=not_required",
            request.renderer
        ));
        return None;
    }
    if render_evaluator.is_none() {
        return Some(failed_render_evaluation(
            request,
            "Render evaluation is required for this artifact, but no render evaluator is configured.",
        ));
    }
    let timeout = render_eval_timeout_for_runtime(request.renderer, runtime_kind);
    chat_generation_trace(format!(
        "artifact_generation:render_eval:start renderer={:?} timeout_ms={}",
        request.renderer,
        timeout.map(|value| value.as_millis()).unwrap_or(0)
    ));
    let evaluation = match timeout {
        Some(limit) => match tokio::time::timeout(
            limit,
            evaluate_chat_artifact_render_if_configured(
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
            evaluate_chat_artifact_render_if_configured(
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
            chat_generation_trace(format!(
                "artifact_generation:render_eval:ok renderer={:?} present={}",
                request.renderer,
                render_evaluation.is_some()
            ));
            render_evaluation
        }
        Err(error) => Some(failed_render_evaluation(
            request,
            &format!(
                "Render evaluation failed before Chat could verify the surfaced first paint: {}",
                error
            ),
        )),
    }
}
