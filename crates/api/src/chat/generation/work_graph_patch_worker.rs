use super::*;

pub(super) fn chat_work_graph_payload_prompt_view(
    payload: &ChatGeneratedArtifactPayload,
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

pub(super) fn chat_work_graph_work_item_context(
    work_item: &ChatArtifactWorkItem,
    blueprint: Option<&ChatArtifactBlueprint>,
    artifact_ir: Option<&ChatArtifactIR>,
    validation: Option<&ChatArtifactValidationResult>,
) -> serde_json::Value {
    match work_item.role {
        ChatArtifactWorkerRole::Skeleton => json!({
            "scaffoldFamily": blueprint.map(|value| value.scaffold_family.clone()),
            "narrativeArc": blueprint.map(|value| value.narrative_arc.clone()),
            "sectionPlan": blueprint.map(|value| value.section_plan.clone()).unwrap_or_default(),
        }),
        ChatArtifactWorkerRole::SectionContent => {
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
        ChatArtifactWorkerRole::StyleSystem => json!({
            "designTokens": artifact_ir.map(|value| value.design_tokens.clone()).unwrap_or_default(),
            "colorStrategy": blueprint
                .map(|value| value.design_system.color_strategy.clone())
                .unwrap_or_default(),
            "density": blueprint
                .map(|value| value.design_system.density.clone())
                .unwrap_or_default(),
            "validation": validation,
        }),
        ChatArtifactWorkerRole::Interaction => json!({
            "interactionPlan": blueprint.map(|value| value.interaction_plan.clone()).unwrap_or_default(),
            "interactionGraph": artifact_ir.map(|value| value.interaction_graph.clone()).unwrap_or_default(),
            "validation": validation,
        }),
        ChatArtifactWorkerRole::Integrator | ChatArtifactWorkerRole::Repair => json!({
            "sectionPlan": blueprint.map(|value| value.section_plan.clone()).unwrap_or_default(),
            "interactionPlan": blueprint.map(|value| value.interaction_plan.clone()).unwrap_or_default(),
            "validation": validation,
        }),
        _ => json!({}),
    }
}

pub(super) fn html_work_graph_targeted_repair_template_ids(
    validation: &ChatArtifactValidationResult,
) -> Vec<&'static str> {
    let has_any_issue = |needles: &[&str]| {
        validation
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

pub(super) fn chat_work_graph_worker_role_directive(
    request: &ChatOutcomeArtifactRequest,
    work_item: &ChatArtifactWorkItem,
) -> String {
    match (request.renderer, work_item.role) {
        (ChatRendererKind::HtmlIframe, ChatArtifactWorkerRole::Skeleton) => format!(
            "Create one self-contained index.html shell for the artifact. The shell must include <main> and these exact region markers once each: {}. Reserve the style-system region in <head> and the interaction region before </body>, but do not author real CSS rules or JavaScript logic in this step because later workers own those regions. Keep the STUDIO_REGION markers in place so later workers can patch them. Do not force a panel grammar unless the brief actually calls for it.",
            work_item
                .write_regions
                .iter()
                .map(|region| format!(
                    "{} ... {}",
                    html_work_graph_region_marker_start(region),
                    html_work_graph_region_marker_end(region)
                ))
                .collect::<Vec<_>>()
                .join(" | ")
        ),
        (ChatRendererKind::HtmlIframe, ChatArtifactWorkerRole::SectionContent) => {
            let region = work_item.write_regions.first().cloned().unwrap_or_default();
            format!(
                "Replace only region '{region}' with a complete semantic block that fulfills the section purpose, first-paint utility, and request-specific content. Return exactly one replace_region operation for index.html and do not rewrite other regions."
            )
        }
        (ChatRendererKind::HtmlIframe, ChatArtifactWorkerRole::StyleSystem) => {
            "Replace only the style-system region with one <style> block. Favor slate and graphite neutrals, crisp hierarchy, dense readability, and one restrained cool accent family. Do not change copy or structural HTML outside CSS.".to_string()
        }
        (ChatRendererKind::HtmlIframe, ChatArtifactWorkerRole::Interaction) => {
            "Replace only the interaction region with one <script> block that binds authored controls to visible state changes already present in the DOM. Avoid alert(), external libraries, navigation-only controls, or invisible first paint.".to_string()
        }
        (ChatRendererKind::HtmlIframe, ChatArtifactWorkerRole::Integrator) => {
            "Patch only the regions needed to reconcile visual hierarchy, copy seams, and interaction coherence across the merged artifact. Preserve strong sections; do not restart the artifact from scratch.".to_string()
        }
        (ChatRendererKind::HtmlIframe, ChatArtifactWorkerRole::Repair) => {
            "Patch only the cited failures from validation or verification against the current canonical artifact. Preserve strong authored structure and avoid global rewrites when a narrower region patch will solve the problem.".to_string()
        }
        (_, ChatArtifactWorkerRole::Skeleton) => {
            "Produce the initial renderer-native file set once under a bounded patch envelope. Use create_file or replace_file operations only.".to_string()
        }
        (_, ChatArtifactWorkerRole::Repair) => {
            "Patch the current canonical artifact only where the validation or verification cited concrete failures. Preserve working files and strong request-specific content.".to_string()
        }
        (_, ChatArtifactWorkerRole::Integrator) => {
            "Only patch cross-file or cross-section seams that prevent coherence. Skip the work item instead of rewriting the artifact without need.".to_string()
        }
        _ => "Stay strictly inside the assigned scope and return a valid JSON patch envelope.".to_string(),
    }
}

pub(super) fn chat_patch_operation_kind_label(
    kind: ChatArtifactPatchOperationKind,
) -> &'static str {
    match kind {
        ChatArtifactPatchOperationKind::CreateFile => "create_file",
        ChatArtifactPatchOperationKind::ReplaceFile => "replace_file",
        ChatArtifactPatchOperationKind::ReplaceRegion => "replace_region",
        ChatArtifactPatchOperationKind::DeleteFile => "delete_file",
    }
}

pub(super) fn build_chat_work_graph_patch_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    blueprint: Option<&ChatArtifactBlueprint>,
    artifact_ir: Option<&ChatArtifactIR>,
    selected_skills: &[ChatArtifactSelectedSkill],
    retrieved_exemplars: &[ChatArtifactExemplar],
    edit_intent: Option<&ChatArtifactEditIntent>,
    refinement: Option<&ChatArtifactRefinementContext>,
    current_payload: &ChatGeneratedArtifactPayload,
    work_item: &ChatArtifactWorkItem,
    worker_context: serde_json::Value,
    runtime_kind: ChatRuntimeProvenanceKind,
    candidate_seed: u64,
) -> Result<serde_json::Value, String> {
    let compact_prompt = request.renderer == ChatRendererKind::HtmlIframe
        && runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime;
    if compact_prompt {
        let request_focus_text = compact_local_html_materialization_request_text(request);
        let brief_focus_text = compact_local_html_materialization_brief_text(brief);
        let interaction_contract_text = compact_local_html_interaction_contract_text(brief);
        let selected_skills_json = serialize_materialization_prompt_json(
            &compact_local_html_work_graph_skill_focus(selected_skills),
            "Selected skill guidance",
            true,
        )?;
        let retrieved_exemplars_json = serialize_materialization_prompt_json(
            &compact_local_html_work_graph_exemplar_focus(retrieved_exemplars),
            "Retrieved exemplars",
            true,
        )?;
        let refinement_json = serialize_materialization_prompt_json(
            &compact_local_html_refinement_context_focus(refinement),
            "Refinement context",
            true,
        )?;
        let current_json = serialize_materialization_prompt_json(
            &compact_local_html_work_graph_payload_focus(current_payload, work_item),
            "Current canonical artifact",
            true,
        )?;
        let work_item_json = serialize_materialization_prompt_json(
            &compact_local_html_work_graph_work_item_focus(work_item),
            "WorkGraph work item",
            true,
        )?;
        let worker_context_json = serialize_materialization_prompt_json(
            &compact_local_html_work_graph_worker_context_focus(work_item, &worker_context),
            "Worker context",
            true,
        )?;
        let renderer_guidance = compact_local_html_work_graph_renderer_guidance(
            request,
            brief,
            work_item,
            candidate_seed,
            runtime_kind,
        );
        let role_directive = chat_work_graph_worker_role_directive(request, work_item);
        return Ok(json!([
            {
                "role": "system",
                "content": format!(
                    "You are Chat's typed work_graph {:?} worker. Return JSON only. You own only the explicit work item scope and must preserve authored structure outside it.",
                    work_item.role
                )
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus:\n{}\n\nArtifact brief focus:\n{}\n\nInteraction contract:\n{}\n\nSelected skill guidance JSON:\n{}\n\nRetrieved exemplars JSON:\n{}\n\nRefinement context JSON:\n{}\n\nCurrent artifact focus JSON:\n{}\n\nWorkGraph work item JSON:\n{}\n\nWorker context JSON:\n{}\n\nRole directive:\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                    title,
                    intent,
                    request_focus_text,
                    brief_focus_text,
                    interaction_contract_text,
                    if matches!(
                        work_item.role,
                        ChatArtifactWorkerRole::Skeleton
                            | ChatArtifactWorkerRole::SectionContent
                            | ChatArtifactWorkerRole::StyleSystem
                            | ChatArtifactWorkerRole::Interaction
                            | ChatArtifactWorkerRole::Repair
                    ) {
                        "[]".to_string()
                    } else {
                        selected_skills_json
                    },
                    if matches!(work_item.role, ChatArtifactWorkerRole::Integrator) {
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
                    work_graph_patch_schema_contract(),
                )
            }
        ]));
    }

    let request_json =
        serialize_materialization_prompt_json(request, "Chat artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Chat artifact brief", compact_prompt)?;
    let blueprint_json = serialize_materialization_prompt_json(
        &blueprint,
        "Chat artifact blueprint",
        compact_prompt,
    )?;
    let artifact_ir_json =
        serialize_materialization_prompt_json(&artifact_ir, "Chat artifact IR", compact_prompt)?;
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
        "Chat artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &compact_local_html_refinement_context_focus(refinement),
        "Refinement context",
        compact_prompt,
    )?;
    let current_json = serialize_materialization_prompt_json(
        &chat_work_graph_payload_prompt_view(current_payload),
        "Current canonical artifact",
        false,
    )?;
    let work_item_json =
        serialize_materialization_prompt_json(work_item, "WorkGraph work item", false)?;
    let worker_context_json =
        serialize_materialization_prompt_json(&worker_context, "Worker context", false)?;
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::chat_artifact_interaction_contract(brief),
        "Interaction contract",
        compact_prompt,
    )?;
    let renderer_guidance = chat_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let role_directive = chat_work_graph_worker_role_directive(request, work_item);
    Ok(json!([
        {
            "role": "system",
            "content": format!(
                "You are Chat's typed work_graph {:?} worker. Return JSON only. You do not own the full artifact. You own only the explicit work item scope and must preserve strong authored structure outside it.",
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
                    work_graph_patch_schema_contract()
                ),
            )
        }
    ]))
}

pub(super) fn chat_work_graph_worker_temperature(
    request: &ChatOutcomeArtifactRequest,
    role: ChatArtifactWorkerRole,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> f32 {
    let (_, configured_temperature, _) =
        candidate_generation_config(request.renderer, runtime_kind);
    let base = effective_candidate_generation_temperature(
        request.renderer,
        runtime_kind,
        configured_temperature,
    );
    match role {
        ChatArtifactWorkerRole::Skeleton | ChatArtifactWorkerRole::SectionContent => base,
        ChatArtifactWorkerRole::StyleSystem | ChatArtifactWorkerRole::Interaction => base.min(0.32),
        ChatArtifactWorkerRole::Integrator => base.min(0.26),
        ChatArtifactWorkerRole::Repair => 0.18,
        _ => 0.0,
    }
}

pub(super) fn chat_work_graph_worker_max_tokens(
    request: &ChatOutcomeArtifactRequest,
    role: ChatArtifactWorkerRole,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> u32 {
    let base = materialization_max_tokens_for_runtime(request.renderer, runtime_kind);
    if request.renderer == ChatRendererKind::HtmlIframe
        && runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
    {
        return match role {
            ChatArtifactWorkerRole::Skeleton => base.min(850),
            ChatArtifactWorkerRole::SectionContent => base.min(1000),
            ChatArtifactWorkerRole::StyleSystem => base.min(1800),
            ChatArtifactWorkerRole::Interaction => base.min(1600),
            ChatArtifactWorkerRole::Integrator => base.min(1800),
            ChatArtifactWorkerRole::Repair => base.min(2200),
            _ => base.min(1200),
        };
    }
    base
}

pub(super) fn chat_work_graph_worker_timeout(
    request: &ChatOutcomeArtifactRequest,
    role: ChatArtifactWorkerRole,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<Duration> {
    if request.renderer == ChatRendererKind::HtmlIframe
        && runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
    {
        return Some(match role {
            ChatArtifactWorkerRole::Skeleton => Duration::from_secs(120),
            ChatArtifactWorkerRole::SectionContent => Duration::from_secs(150),
            ChatArtifactWorkerRole::StyleSystem => Duration::from_secs(150),
            ChatArtifactWorkerRole::Interaction => Duration::from_secs(150),
            ChatArtifactWorkerRole::Integrator => Duration::from_secs(120),
            ChatArtifactWorkerRole::Repair => Duration::from_secs(180),
            _ => Duration::from_secs(60),
        });
    }
    None
}

pub(super) fn configured_local_html_work_graph_parallelism_cap() -> Option<usize> {
    [
        "AUTOPILOT_CHAT_ARTIFACT_SWARM_LOCAL_PARALLELISM_CAP",
        "IOI_CHAT_SWARM_LOCAL_PARALLELISM_CAP",
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

pub(super) fn chat_work_graph_dispatch_parallelism_cap(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> usize {
    match (request.renderer, runtime_kind) {
        (ChatRendererKind::HtmlIframe, ChatRuntimeProvenanceKind::RealRemoteModelRuntime) => 3,
        (ChatRendererKind::HtmlIframe, ChatRuntimeProvenanceKind::RealLocalRuntime) => {
            configured_local_html_work_graph_parallelism_cap().unwrap_or(2)
        }
        (ChatRendererKind::HtmlIframe, _) => 2,
        _ => 1,
    }
}

pub(super) fn chat_work_graph_planned_token_budget(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    work_graph_plan: &ChatArtifactWorkGraphPlan,
) -> u32 {
    work_graph_plan
        .work_items
        .iter()
        .map(|item| chat_work_graph_worker_max_tokens(request, item.role, runtime_kind))
        .sum()
}

pub(super) fn build_chat_work_graph_patch_repair_prompt(
    work_item: &ChatArtifactWorkItem,
    raw_output: &str,
    parse_error: &str,
) -> serde_json::Value {
    json!([
        {
            "role": "system",
            "content": "You repair malformed Chat work_graph worker output into valid JSON. Return JSON only. Preserve the worker's intent, stay inside the existing scope, and do not invent extra files or extra operations. Prefer complete, closed CSS/JS blocks over partial truncation, and preserve every scoped operation you can recover."
        },
        {
            "role": "user",
            "content": format!(
                "Worker id: {}\nWorker role: {:?}\nParse error: {}\n\nMalformed worker output:\n{}\n\nRepair it into one valid JSON object matching this schema exactly:\n{}",
                work_item.id,
                work_item.role,
                parse_error,
                truncate_materialization_focus_text(raw_output, 3200),
                work_graph_patch_schema_contract(),
            )
        }
    ])
}

pub(super) async fn repair_chat_work_graph_patch_envelope(
    runtime: Arc<dyn InferenceRuntime>,
    request: &ChatOutcomeArtifactRequest,
    work_item: &ChatArtifactWorkItem,
    raw_output: &str,
    parse_error: &str,
    runtime_kind: ChatRuntimeProvenanceKind,
    activity_observer: Option<ChatArtifactActivityObserver>,
) -> Result<ChatArtifactPatchEnvelope, String> {
    if let Some(envelope) = salvage_chat_work_graph_patch_envelope(request, work_item, raw_output) {
        chat_generation_trace(format!(
            "artifact_generation:work_graph_worker:repair_parse:salvage_ok id={} role={:?}",
            work_item.id, work_item.role
        ));
        return Ok(envelope);
    }

    let prompt = build_chat_work_graph_patch_repair_prompt(work_item, raw_output, parse_error);
    let prompt_bytes = serde_json::to_vec(&prompt)
        .map_err(|error| format!("Failed to encode Chat work_graph repair prompt: {error}"))?;
    let max_tokens =
        chat_work_graph_worker_max_tokens(request, work_item.role, runtime_kind).min(1800);
    chat_generation_trace(format!(
        "artifact_generation:work_graph_worker:repair_parse:start id={} role={:?} prompt_bytes={} max_tokens={}",
        work_item.id,
        work_item.role,
        prompt_bytes.len(),
        max_tokens
    ));
    let repair_future = tokio::time::timeout(
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
    );
    let output =
        await_with_activity_heartbeat(repair_future, activity_observer, Duration::from_millis(125))
            .await
            .map_err(|_| {
                format!(
                    "Chat work_graph worker '{}' JSON repair timed out after 150s.",
                    work_item.id
                )
            })?
            .map_err(|error| format!("Chat work_graph worker JSON repair failed: {error}"))?;
    let raw = String::from_utf8(output).map_err(|error| {
        format!("Chat work_graph worker JSON repair utf8 decode failed: {error}")
    })?;
    let envelope = match parse_chat_artifact_patch_envelope(&raw) {
        Ok(envelope) => envelope,
        Err(error) => {
            chat_generation_trace(format!(
                "artifact_generation:work_graph_worker:repair_parse:error id={} role={:?} error={} preview={}",
                work_item.id,
                work_item.role,
                error,
                truncate_materialization_focus_text(&raw.replace('\n', "\\n"), 900)
            ));
            salvage_chat_work_graph_patch_envelope(request, work_item, &raw)
                .or_else(|| salvage_chat_work_graph_patch_envelope(request, work_item, raw_output))
                .ok_or_else(|| {
                    format!("Chat work_graph worker JSON repair parse failed: {error}")
                })?
        }
    };
    chat_generation_trace(format!(
        "artifact_generation:work_graph_worker:repair_parse:ok id={} role={:?}",
        work_item.id, work_item.role
    ));
    Ok(envelope)
}

pub(super) async fn execute_chat_work_graph_patch_worker(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    blueprint: Option<&ChatArtifactBlueprint>,
    artifact_ir: Option<&ChatArtifactIR>,
    selected_skills: &[ChatArtifactSelectedSkill],
    retrieved_exemplars: &[ChatArtifactExemplar],
    edit_intent: Option<&ChatArtifactEditIntent>,
    refinement: Option<&ChatArtifactRefinementContext>,
    current_payload: &ChatGeneratedArtifactPayload,
    work_item: &ChatArtifactWorkItem,
    worker_context: serde_json::Value,
    candidate_seed: u64,
    live_preview_observer: Option<ChatArtifactLivePreviewObserver>,
    activity_observer: Option<ChatArtifactActivityObserver>,
) -> Result<(ChatArtifactPatchEnvelope, ChatArtifactWorkerReceipt), String> {
    let started_at = chat_work_graph_now_iso();
    let runtime_kind = runtime.chat_runtime_provenance().kind;
    let prompt = build_chat_work_graph_patch_prompt_for_runtime(
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
        .map_err(|error| format!("Failed to encode Chat work_graph worker prompt: {error}"))?;
    let max_tokens = chat_work_graph_worker_max_tokens(request, work_item.role, runtime_kind);
    let timeout = chat_work_graph_worker_timeout(request, work_item.role, runtime_kind);
    chat_generation_trace(format!(
        "artifact_generation:work_graph_worker:start id={} role={:?} prompt_bytes={} max_tokens={} timeout_ms={}",
        work_item.id,
        work_item.role,
        prompt_bytes.len(),
        max_tokens,
        timeout.map(|value| value.as_millis()).unwrap_or(0)
    ));
    let inference_started_at = Instant::now();
    let inference_options = InferenceOptions {
        temperature: chat_work_graph_worker_temperature(request, work_item.role, runtime_kind),
        json_mode: true,
        max_tokens,
        ..Default::default()
    };
    let preview_language = chat_work_graph_preview_language(request);
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
        Some(limit) => match await_with_activity_heartbeat(
            tokio::time::timeout(limit, inference),
            activity_observer.clone(),
            Duration::from_millis(125),
        )
        .await
        {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                chat_generation_trace(format!(
                    "artifact_generation:work_graph_worker:error id={} role={:?} error={}",
                    work_item.id, work_item.role, error
                ));
                return Err(format!("Chat work_graph worker inference failed: {error}"));
            }
            Err(_) => {
                chat_generation_trace(format!(
                    "artifact_generation:work_graph_worker:timeout id={} role={:?} timeout_ms={}",
                    work_item.id,
                    work_item.role,
                    limit.as_millis()
                ));
                return Err(format!(
                    "Chat work_graph worker '{}' timed out after {}s.",
                    work_item.id,
                    limit.as_secs()
                ));
            }
        },
        None => await_with_activity_heartbeat(
            inference,
            activity_observer.clone(),
            Duration::from_millis(125),
        )
        .await
        .map_err(|error| format!("Chat work_graph worker inference failed: {error}"))?,
    };
    chat_generation_trace(format!(
        "artifact_generation:work_graph_worker:ok id={} role={:?} elapsed_ms={} output_bytes={}",
        work_item.id,
        work_item.role,
        inference_started_at.elapsed().as_millis(),
        output.len()
    ));
    let streamed_preview = finish_token_stream_preview_collector(stream_collector).await;
    let raw = String::from_utf8(output.clone())
        .map_err(|error| format!("Chat work_graph worker utf8 decode failed: {error}"))?;
    let output_preview = truncate_candidate_failure_preview(&raw, 2200);
    if let Some(observer) = live_preview_observer.as_ref() {
        observer(chat_work_graph_live_preview(
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
    let envelope = match parse_chat_artifact_patch_envelope(&raw) {
        Ok(envelope) => envelope,
        Err(error) => {
            chat_generation_trace(format!(
                "artifact_generation:work_graph_worker:parse_error id={} role={:?} error={} preview={}",
                work_item.id,
                work_item.role,
                error,
                truncate_materialization_focus_text(&raw.replace('\n', "\\n"), 900)
            ));
            if let Some(envelope) = salvage_chat_work_graph_patch_envelope(request, work_item, &raw)
            {
                chat_generation_trace(format!(
                    "artifact_generation:work_graph_worker:salvage_ok id={} role={:?}",
                    work_item.id, work_item.role
                ));
                envelope
            } else {
                repair_chat_work_graph_patch_envelope(
                    runtime.clone(),
                    request,
                    work_item,
                    &raw,
                    &error,
                    runtime_kind,
                    activity_observer,
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
        ChatArtifactWorkerReceipt {
            work_item_id: work_item.id.clone(),
            role: work_item.role,
            status: ChatArtifactWorkItemStatus::Succeeded,
            result_kind: Some(WorkGraphWorkerResultKind::Completed),
            summary,
            started_at,
            finished_at: Some(chat_work_graph_now_iso()),
            runtime: runtime.chat_runtime_provenance(),
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
