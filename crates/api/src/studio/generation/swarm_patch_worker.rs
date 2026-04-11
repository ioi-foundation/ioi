use super::*;

pub(super) fn studio_swarm_payload_prompt_view(
    payload: &StudioGeneratedArtifactPayload,
) -> serde_json::Value {
    json!({
        "summary": payload.summary,
        "notes": payload.notes,
        "files": payload
            .files
            .iter()
            .map(|file| {
                json!({
                    "path": file.path,
                    "mime": file.mime,
                    "role": file.role,
                    "renderable": file.renderable,
                    "downloadable": file.downloadable,
                    "encoding": file.encoding,
                    "body": file.body,
                })
            })
            .collect::<Vec<_>>(),
    })
}

pub(super) fn studio_swarm_work_item_context(
    work_item: &StudioArtifactWorkItem,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    judge: Option<&StudioArtifactJudgeResult>,
) -> serde_json::Value {
    match work_item.role {
        StudioArtifactWorkerRole::Skeleton => json!({
            "scaffoldFamily": blueprint.map(|value| value.scaffold_family.clone()),
            "narrativeArc": blueprint.map(|value| value.narrative_arc.clone()),
            "sectionPlan": blueprint.map(|value| value.section_plan.clone()).unwrap_or_default(),
        }),
        StudioArtifactWorkerRole::SectionContent => {
            let target_region = work_item.write_regions.first().cloned().unwrap_or_default();
            let target_id = target_region
                .strip_prefix("section:")
                .unwrap_or(target_region.as_str());
            let section = blueprint.and_then(|value| {
                value
                    .section_plan
                    .iter()
                    .find(|section| {
                        section_region_id(section, 0) == target_id || section.id == target_id
                    })
                    .cloned()
            });
            json!({
                "targetRegion": target_region,
                "section": section,
            })
        }
        StudioArtifactWorkerRole::StyleSystem => json!({
            "designTokens": artifact_ir.map(|value| value.design_tokens.clone()).unwrap_or_default(),
            "colorStrategy": blueprint
                .map(|value| value.design_system.color_strategy.clone())
                .unwrap_or_default(),
            "density": blueprint
                .map(|value| value.design_system.density.clone())
                .unwrap_or_default(),
            "judge": judge,
        }),
        StudioArtifactWorkerRole::Interaction => json!({
            "interactionPlan": blueprint.map(|value| value.interaction_plan.clone()).unwrap_or_default(),
            "interactionGraph": artifact_ir.map(|value| value.interaction_graph.clone()).unwrap_or_default(),
            "judge": judge,
        }),
        StudioArtifactWorkerRole::Integrator | StudioArtifactWorkerRole::Repair => json!({
            "sectionPlan": blueprint.map(|value| value.section_plan.clone()).unwrap_or_default(),
            "interactionPlan": blueprint.map(|value| value.interaction_plan.clone()).unwrap_or_default(),
            "judge": judge,
        }),
        _ => json!({}),
    }
}

pub(super) fn html_swarm_targeted_repair_template_ids(
    judge: &StudioArtifactJudgeResult,
) -> Vec<&'static str> {
    let has_any_issue = |needles: &[&str]| {
        judge
            .issue_classes
            .iter()
            .any(|issue| needles.iter().any(|needle| issue == needle))
    };

    let mut template_ids = Vec::new();
    if has_any_issue(&[
        "main_region_missing",
        "alignment_unstable",
        "low_layout_density",
        "evidence_density_low",
        "visual_hierarchy_sparse",
        "incomplete_artifact",
        "missing_visual_evidence",
        "render_timeout",
    ]) {
        template_ids.push("integrator");
    }
    if has_any_issue(&[
        "low_layout_density",
        "alignment_unstable",
        "visual_hierarchy_sparse",
        "missing_visual_evidence",
        "render_timeout",
    ]) {
        template_ids.push("style-system");
    }
    if has_any_issue(&[
        "missing_interactive_states",
        "interaction_change_weak",
        "interaction_missing",
        "interaction_relevance_low",
        "render_timeout",
        "incomplete_artifact",
    ]) {
        template_ids.push("interaction");
    }
    if template_ids.is_empty() {
        template_ids.push("repair");
    }
    template_ids
}

pub(super) fn studio_swarm_worker_role_directive(
    request: &StudioOutcomeArtifactRequest,
    work_item: &StudioArtifactWorkItem,
) -> String {
    match (request.renderer, work_item.role) {
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::Skeleton) => format!(
            "Create one self-contained index.html shell for the artifact. The shell must include <main> and these exact region markers once each: {}. Reserve the style-system region in <head> and the interaction region before </body>, but do not author real CSS rules or JavaScript logic in this step because later workers own those regions. Keep the STUDIO_REGION markers in place so later workers can patch them. Do not force a panel grammar unless the brief actually calls for it.",
            work_item
                .write_regions
                .iter()
                .map(|region| format!(
                    "{} ... {}",
                    html_swarm_region_marker_start(region),
                    html_swarm_region_marker_end(region)
                ))
                .collect::<Vec<_>>()
                .join(" | ")
        ),
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::SectionContent) => {
            let region = work_item.write_regions.first().cloned().unwrap_or_default();
            format!(
                "Replace only region '{region}' with a complete semantic block that fulfills the section purpose, first-paint utility, and request-specific content. Return exactly one replace_region operation for index.html and do not rewrite other regions."
            )
        }
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::StyleSystem) => {
            "Replace only the style-system region with one <style> block. Favor slate and graphite neutrals, crisp hierarchy, dense readability, and one restrained cool accent family. Do not change copy or structural HTML outside CSS.".to_string()
        }
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::Interaction) => {
            "Replace only the interaction region with one <script> block that binds authored controls to visible state changes already present in the DOM. Avoid alert(), external libraries, navigation-only controls, or invisible first paint.".to_string()
        }
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::Integrator) => {
            "Patch only the regions needed to reconcile visual hierarchy, copy seams, and interaction coherence across the merged artifact. Preserve strong sections; do not restart the artifact from scratch.".to_string()
        }
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::Repair) => {
            "Patch only the cited failures from judging or verification against the current canonical artifact. Preserve strong authored structure and avoid global rewrites when a narrower region patch will solve the problem.".to_string()
        }
        (_, StudioArtifactWorkerRole::Skeleton) => {
            "Produce the initial renderer-native file set once under a bounded patch envelope. Use create_file or replace_file operations only.".to_string()
        }
        (_, StudioArtifactWorkerRole::Repair) => {
            "Patch the current canonical artifact only where the judge or verification cited concrete failures. Preserve working files and strong request-specific content.".to_string()
        }
        (_, StudioArtifactWorkerRole::Integrator) => {
            "Only patch cross-file or cross-section seams that prevent coherence. Skip the work item instead of rewriting the artifact without need.".to_string()
        }
        _ => "Stay strictly inside the assigned scope and return a valid JSON patch envelope.".to_string(),
    }
}

pub(super) fn studio_patch_operation_kind_label(
    kind: StudioArtifactPatchOperationKind,
) -> &'static str {
    match kind {
        StudioArtifactPatchOperationKind::CreateFile => "create_file",
        StudioArtifactPatchOperationKind::ReplaceFile => "replace_file",
        StudioArtifactPatchOperationKind::ReplaceRegion => "replace_region",
        StudioArtifactPatchOperationKind::DeleteFile => "delete_file",
    }
}

pub(super) fn build_studio_swarm_patch_prompt_for_runtime(
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
    current_payload: &StudioGeneratedArtifactPayload,
    work_item: &StudioArtifactWorkItem,
    worker_context: serde_json::Value,
    runtime_kind: StudioRuntimeProvenanceKind,
    candidate_seed: u64,
) -> Result<serde_json::Value, String> {
    let compact_prompt = request.renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime;
    if compact_prompt {
        let request_focus_text = compact_local_html_materialization_request_text(request);
        let brief_focus_text = compact_local_html_materialization_brief_text(brief);
        let interaction_contract_text = compact_local_html_interaction_contract_text(brief);
        let selected_skills_json = serialize_materialization_prompt_json(
            &compact_local_html_swarm_skill_focus(selected_skills),
            "Selected skill guidance",
            true,
        )?;
        let retrieved_exemplars_json = serialize_materialization_prompt_json(
            &compact_local_html_swarm_exemplar_focus(retrieved_exemplars),
            "Retrieved exemplars",
            true,
        )?;
        let refinement_json = serialize_materialization_prompt_json(
            &compact_local_html_refinement_context_focus(refinement),
            "Refinement context",
            true,
        )?;
        let current_json = serialize_materialization_prompt_json(
            &compact_local_html_swarm_payload_focus(current_payload, work_item),
            "Current canonical artifact",
            true,
        )?;
        let work_item_json = serialize_materialization_prompt_json(
            &compact_local_html_swarm_work_item_focus(work_item),
            "Swarm work item",
            true,
        )?;
        let worker_context_json = serialize_materialization_prompt_json(
            &compact_local_html_swarm_worker_context_focus(work_item, &worker_context),
            "Worker context",
            true,
        )?;
        let renderer_guidance = compact_local_html_swarm_renderer_guidance(
            request,
            brief,
            work_item,
            candidate_seed,
            runtime_kind,
        );
        let role_directive = studio_swarm_worker_role_directive(request, work_item);
        return Ok(json!([
            {
                "role": "system",
                "content": format!(
                    "You are Studio's typed swarm {:?} worker. Return JSON only. You own only the explicit work item scope and must preserve authored structure outside it.",
                    work_item.role
                )
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus:\n{}\n\nArtifact brief focus:\n{}\n\nInteraction contract:\n{}\n\nSelected skill guidance JSON:\n{}\n\nRetrieved exemplars JSON:\n{}\n\nRefinement context JSON:\n{}\n\nCurrent artifact focus JSON:\n{}\n\nSwarm work item JSON:\n{}\n\nWorker context JSON:\n{}\n\nRole directive:\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                    title,
                    intent,
                    request_focus_text,
                    brief_focus_text,
                    interaction_contract_text,
                    if matches!(
                        work_item.role,
                        StudioArtifactWorkerRole::Skeleton
                            | StudioArtifactWorkerRole::SectionContent
                            | StudioArtifactWorkerRole::StyleSystem
                            | StudioArtifactWorkerRole::Interaction
                            | StudioArtifactWorkerRole::Repair
                    ) {
                        "[]".to_string()
                    } else {
                        selected_skills_json
                    },
                    if matches!(work_item.role, StudioArtifactWorkerRole::Integrator) {
                        retrieved_exemplars_json
                    } else {
                        "[]".to_string()
                    },
                    refinement_json,
                    current_json,
                    work_item_json,
                    worker_context_json,
                    role_directive,
                    renderer_guidance,
                    swarm_patch_schema_contract(),
                )
            }
        ]));
    }

    let request_json =
        serialize_materialization_prompt_json(request, "Studio artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Studio artifact brief", compact_prompt)?;
    let blueprint_json = serialize_materialization_prompt_json(
        &blueprint,
        "Studio artifact blueprint",
        compact_prompt,
    )?;
    let artifact_ir_json =
        serialize_materialization_prompt_json(&artifact_ir, "Studio artifact IR", compact_prompt)?;
    let selected_skills_json = serialize_materialization_prompt_json(
        &selected_skills,
        "Selected skill guidance",
        compact_prompt,
    )?;
    let retrieved_exemplars_json = serialize_materialization_prompt_json(
        &retrieved_exemplars,
        "Retrieved exemplars",
        compact_prompt,
    )?;
    let edit_intent_json = serialize_materialization_prompt_json(
        &edit_intent,
        "Studio artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &compact_local_html_refinement_context_focus(refinement),
        "Refinement context",
        compact_prompt,
    )?;
    let current_json = serialize_materialization_prompt_json(
        &studio_swarm_payload_prompt_view(current_payload),
        "Current canonical artifact",
        false,
    )?;
    let work_item_json =
        serialize_materialization_prompt_json(work_item, "Swarm work item", false)?;
    let worker_context_json =
        serialize_materialization_prompt_json(&worker_context, "Worker context", false)?;
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::studio_artifact_interaction_contract(brief),
        "Interaction contract",
        compact_prompt,
    )?;
    let renderer_guidance = studio_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let role_directive = studio_swarm_worker_role_directive(request, work_item);
    Ok(json!([
        {
            "role": "system",
            "content": format!(
                "You are Studio's typed swarm {:?} worker. Return JSON only. You do not own the full artifact. You own only the explicit work item scope and must preserve strong authored structure outside it.",
                work_item.role
            )
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\nRole directive:\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}\n",
                title,
                intent,
                request_json,
                brief_json,
                blueprint_json,
                artifact_ir_json,
                selected_skills_json,
                retrieved_exemplars_json,
                edit_intent_json,
                refinement_json,
                interaction_contract_json,
                current_json,
                role_directive,
                renderer_guidance,
                format!(
                    "{}\n\n{}\n\n{}",
                    work_item_json,
                    worker_context_json,
                    swarm_patch_schema_contract()
                ),
            )
        }
    ]))
}

pub(super) fn studio_swarm_worker_temperature(
    request: &StudioOutcomeArtifactRequest,
    role: StudioArtifactWorkerRole,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> f32 {
    let (_, configured_temperature, _) =
        candidate_generation_config(request.renderer, runtime_kind);
    let base = effective_candidate_generation_temperature(
        request.renderer,
        runtime_kind,
        configured_temperature,
    );
    match role {
        StudioArtifactWorkerRole::Skeleton | StudioArtifactWorkerRole::SectionContent => base,
        StudioArtifactWorkerRole::StyleSystem | StudioArtifactWorkerRole::Interaction => {
            base.min(0.32)
        }
        StudioArtifactWorkerRole::Integrator => base.min(0.26),
        StudioArtifactWorkerRole::Repair => 0.18,
        _ => 0.0,
    }
}

pub(super) fn studio_swarm_worker_max_tokens(
    request: &StudioOutcomeArtifactRequest,
    role: StudioArtifactWorkerRole,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    let base = materialization_max_tokens_for_runtime(request.renderer, runtime_kind);
    if request.renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return match role {
            StudioArtifactWorkerRole::Skeleton => base.min(850),
            StudioArtifactWorkerRole::SectionContent => base.min(1000),
            StudioArtifactWorkerRole::StyleSystem => base.min(1800),
            StudioArtifactWorkerRole::Interaction => base.min(1600),
            StudioArtifactWorkerRole::Integrator => base.min(1800),
            StudioArtifactWorkerRole::Repair => base.min(2200),
            _ => base.min(1200),
        };
    }
    base
}

pub(super) fn studio_swarm_worker_timeout(
    request: &StudioOutcomeArtifactRequest,
    role: StudioArtifactWorkerRole,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Option<Duration> {
    if request.renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return Some(match role {
            StudioArtifactWorkerRole::Skeleton => Duration::from_secs(120),
            StudioArtifactWorkerRole::SectionContent => Duration::from_secs(150),
            StudioArtifactWorkerRole::StyleSystem => Duration::from_secs(150),
            StudioArtifactWorkerRole::Interaction => Duration::from_secs(150),
            StudioArtifactWorkerRole::Integrator => Duration::from_secs(120),
            StudioArtifactWorkerRole::Repair => Duration::from_secs(180),
            _ => Duration::from_secs(60),
        });
    }
    None
}

pub(super) fn configured_local_html_swarm_parallelism_cap() -> Option<usize> {
    [
        "AUTOPILOT_STUDIO_SWARM_LOCAL_PARALLELISM_CAP",
        "IOI_STUDIO_SWARM_LOCAL_PARALLELISM_CAP",
        "OLLAMA_NUM_PARALLEL",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|value| *value > 0)
    })
    .map(|value| value.clamp(1, 2))
}

pub(super) fn studio_swarm_dispatch_parallelism_cap(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> usize {
    match (request.renderer, runtime_kind) {
        (StudioRendererKind::HtmlIframe, StudioRuntimeProvenanceKind::RealRemoteModelRuntime) => 3,
        (StudioRendererKind::HtmlIframe, StudioRuntimeProvenanceKind::RealLocalRuntime) => {
            configured_local_html_swarm_parallelism_cap().unwrap_or(2)
        }
        (StudioRendererKind::HtmlIframe, _) => 2,
        _ => 1,
    }
}

pub(super) fn studio_swarm_planned_token_budget(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    swarm_plan: &StudioArtifactSwarmPlan,
) -> u32 {
    swarm_plan
        .work_items
        .iter()
        .map(|item| studio_swarm_worker_max_tokens(request, item.role, runtime_kind))
        .sum()
}

pub(super) fn build_studio_swarm_patch_repair_prompt(
    work_item: &StudioArtifactWorkItem,
    raw_output: &str,
    parse_error: &str,
) -> serde_json::Value {
    json!([
        {
            "role": "system",
            "content": "You repair malformed Studio swarm worker output into valid JSON. Return JSON only. Preserve the worker's intent, stay inside the existing scope, and do not invent extra files or extra operations. Prefer complete, closed CSS/JS blocks over partial truncation, and preserve every scoped operation you can recover."
        },
        {
            "role": "user",
            "content": format!(
                "Worker id: {}\nWorker role: {:?}\nParse error: {}\n\nMalformed worker output:\n{}\n\nRepair it into one valid JSON object matching this schema exactly:\n{}",
                work_item.id,
                work_item.role,
                parse_error,
                truncate_materialization_focus_text(raw_output, 3200),
                swarm_patch_schema_contract(),
            )
        }
    ])
}

pub(super) async fn repair_studio_swarm_patch_envelope(
    runtime: Arc<dyn InferenceRuntime>,
    request: &StudioOutcomeArtifactRequest,
    work_item: &StudioArtifactWorkItem,
    raw_output: &str,
    parse_error: &str,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<StudioArtifactPatchEnvelope, String> {
    if let Some(envelope) = salvage_studio_swarm_patch_envelope(request, work_item, raw_output) {
        studio_generation_trace(format!(
            "artifact_generation:swarm_worker:repair_parse:salvage_ok id={} role={:?}",
            work_item.id, work_item.role
        ));
        return Ok(envelope);
    }

    let prompt = build_studio_swarm_patch_repair_prompt(work_item, raw_output, parse_error);
    let prompt_bytes = serde_json::to_vec(&prompt)
        .map_err(|error| format!("Failed to encode Studio swarm repair prompt: {error}"))?;
    let max_tokens =
        studio_swarm_worker_max_tokens(request, work_item.role, runtime_kind).min(1800);
    studio_generation_trace(format!(
        "artifact_generation:swarm_worker:repair_parse:start id={} role={:?} prompt_bytes={} max_tokens={}",
        work_item.id,
        work_item.role,
        prompt_bytes.len(),
        max_tokens
    ));
    let output = tokio::time::timeout(
        Duration::from_secs(150),
        runtime.execute_inference(
            [0u8; 32],
            &prompt_bytes,
            InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens,
                ..Default::default()
            },
        ),
    )
    .await
    .map_err(|_| {
        format!(
            "Studio swarm worker '{}' JSON repair timed out after 150s.",
            work_item.id
        )
    })?
    .map_err(|error| format!("Studio swarm worker JSON repair failed: {error}"))?;
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Studio swarm worker JSON repair utf8 decode failed: {error}"))?;
    let envelope = match parse_studio_artifact_patch_envelope(&raw) {
        Ok(envelope) => envelope,
        Err(error) => {
            studio_generation_trace(format!(
                "artifact_generation:swarm_worker:repair_parse:error id={} role={:?} error={} preview={}",
                work_item.id,
                work_item.role,
                error,
                truncate_materialization_focus_text(&raw.replace('\n', "\\n"), 900)
            ));
            salvage_studio_swarm_patch_envelope(request, work_item, &raw)
                .or_else(|| salvage_studio_swarm_patch_envelope(request, work_item, raw_output))
                .ok_or_else(|| format!("Studio swarm worker JSON repair parse failed: {error}"))?
        }
    };
    studio_generation_trace(format!(
        "artifact_generation:swarm_worker:repair_parse:ok id={} role={:?}",
        work_item.id, work_item.role
    ));
    Ok(envelope)
}

pub(super) async fn execute_studio_swarm_patch_worker(
    runtime: Arc<dyn InferenceRuntime>,
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
    current_payload: &StudioGeneratedArtifactPayload,
    work_item: &StudioArtifactWorkItem,
    worker_context: serde_json::Value,
    candidate_seed: u64,
    live_preview_observer: Option<StudioArtifactLivePreviewObserver>,
) -> Result<(StudioArtifactPatchEnvelope, StudioArtifactWorkerReceipt), String> {
    let started_at = studio_swarm_now_iso();
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    let prompt = build_studio_swarm_patch_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        retrieved_exemplars,
        edit_intent,
        refinement,
        current_payload,
        work_item,
        worker_context,
        runtime_kind,
        candidate_seed,
    )?;
    let prompt_bytes = serde_json::to_vec(&prompt)
        .map_err(|error| format!("Failed to encode Studio swarm worker prompt: {error}"))?;
    let max_tokens = studio_swarm_worker_max_tokens(request, work_item.role, runtime_kind);
    let timeout = studio_swarm_worker_timeout(request, work_item.role, runtime_kind);
    studio_generation_trace(format!(
        "artifact_generation:swarm_worker:start id={} role={:?} prompt_bytes={} max_tokens={} timeout_ms={}",
        work_item.id,
        work_item.role,
        prompt_bytes.len(),
        max_tokens,
        timeout.map(|value| value.as_millis()).unwrap_or(0)
    ));
    let inference_started_at = Instant::now();
    let inference_options = InferenceOptions {
        temperature: studio_swarm_worker_temperature(request, work_item.role, runtime_kind),
        json_mode: true,
        max_tokens,
        ..Default::default()
    };
    let preview_language = studio_swarm_preview_language(request);
    let preview_id = format!("{}-live-output", work_item.id);
    let preview_label = format!("{} output", work_item.title);
    let (token_stream, stream_collector) = match live_preview_observer.as_ref() {
        Some(observer) => {
            let (token_tx, collector) = spawn_token_stream_preview_collector(
                Some(observer.clone()),
                preview_id.clone(),
                preview_label.clone(),
                Some(work_item.id.clone()),
                Some(work_item.role),
                preview_language.clone(),
            );
            (Some(token_tx), Some(collector))
        }
        None => (None, None),
    };
    let inference = runtime.execute_inference_streaming(
        [0u8; 32],
        &prompt_bytes,
        inference_options,
        token_stream,
    );
    let output = match timeout {
        Some(limit) => match tokio::time::timeout(limit, inference).await {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                studio_generation_trace(format!(
                    "artifact_generation:swarm_worker:error id={} role={:?} error={}",
                    work_item.id, work_item.role, error
                ));
                return Err(format!("Studio swarm worker inference failed: {error}"));
            }
            Err(_) => {
                studio_generation_trace(format!(
                    "artifact_generation:swarm_worker:timeout id={} role={:?} timeout_ms={}",
                    work_item.id,
                    work_item.role,
                    limit.as_millis()
                ));
                return Err(format!(
                    "Studio swarm worker '{}' timed out after {}s.",
                    work_item.id,
                    limit.as_secs()
                ));
            }
        },
        None => inference
            .await
            .map_err(|error| format!("Studio swarm worker inference failed: {error}"))?,
    };
    studio_generation_trace(format!(
        "artifact_generation:swarm_worker:ok id={} role={:?} elapsed_ms={} output_bytes={}",
        work_item.id,
        work_item.role,
        inference_started_at.elapsed().as_millis(),
        output.len()
    ));
    let streamed_preview = finish_token_stream_preview_collector(stream_collector).await;
    let raw = String::from_utf8(output.clone())
        .map_err(|error| format!("Studio swarm worker utf8 decode failed: {error}"))?;
    let output_preview = truncate_candidate_failure_preview(&raw, 2200);
    if let Some(observer) = live_preview_observer.as_ref() {
        observer(studio_swarm_live_preview(
            preview_id,
            if streamed_preview.trim().is_empty() {
                ExecutionLivePreviewKind::WorkerOutput
            } else {
                ExecutionLivePreviewKind::TokenStream
            },
            preview_label,
            Some(work_item.id.clone()),
            Some(work_item.role),
            "completed",
            preview_language.clone(),
            output_preview.clone().unwrap_or_default(),
            true,
        ));
    }
    let envelope = match parse_studio_artifact_patch_envelope(&raw) {
        Ok(envelope) => envelope,
        Err(error) => {
            studio_generation_trace(format!(
                "artifact_generation:swarm_worker:parse_error id={} role={:?} error={} preview={}",
                work_item.id,
                work_item.role,
                error,
                truncate_materialization_focus_text(&raw.replace('\n', "\\n"), 900)
            ));
            if let Some(envelope) = salvage_studio_swarm_patch_envelope(request, work_item, &raw) {
                studio_generation_trace(format!(
                    "artifact_generation:swarm_worker:salvage_ok id={} role={:?}",
                    work_item.id, work_item.role
                ));
                envelope
            } else {
                repair_studio_swarm_patch_envelope(
                    runtime.clone(),
                    request,
                    work_item,
                    &raw,
                    &error,
                    runtime_kind,
                )
                .await?
            }
        }
    };
    let summary = envelope
        .summary
        .clone()
        .unwrap_or_else(|| work_item.summary.clone());
    Ok((
        envelope.clone(),
        StudioArtifactWorkerReceipt {
            work_item_id: work_item.id.clone(),
            role: work_item.role,
            status: StudioArtifactWorkItemStatus::Succeeded,
            result_kind: Some(SwarmWorkerResultKind::Completed),
            summary,
            started_at,
            finished_at: Some(studio_swarm_now_iso()),
            runtime: runtime.studio_runtime_provenance(),
            read_paths: work_item.read_paths.clone(),
            write_paths: work_item.write_paths.clone(),
            write_regions: work_item.write_regions.clone(),
            spawned_work_item_ids: Vec::new(),
            blocked_on_ids: work_item.blocked_on_ids.clone(),
            prompt_bytes: Some(prompt_bytes.len()),
            output_bytes: Some(output.len()),
            output_preview,
            preview_language,
            notes: envelope.notes.clone(),
            failure: None,
        },
    ))
}
