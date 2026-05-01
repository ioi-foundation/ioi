use super::*;

pub fn build_chat_artifact_materialization_prompt(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
    refinement: Option<&ChatArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
) -> Result<serde_json::Value, String> {
    build_chat_artifact_materialization_prompt_for_runtime(
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
        ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

pub(crate) fn build_chat_artifact_materialization_prompt_for_runtime(
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
    candidate_id: &str,
    candidate_seed: u64,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let resolved_blueprint = blueprint
        .cloned()
        .unwrap_or_else(|| derive_chat_artifact_blueprint(request, brief));
    let resolved_artifact_ir = artifact_ir
        .cloned()
        .unwrap_or_else(|| compile_chat_artifact_ir(request, brief, &resolved_blueprint));
    let surface_contracts = chat_surface_contract_prompt_bundle(
        brief,
        &resolved_blueprint,
        &resolved_artifact_ir,
        selected_skills,
        candidate_seed,
    );
    let edit_intent_json = serialize_materialization_prompt_json(
        &edit_intent,
        "Chat artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &chat_artifact_refinement_context_view(refinement),
        "Chat refinement context",
        compact_prompt,
    )?;
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::chat_artifact_interaction_contract(brief),
        "Chat interaction contract",
        compact_prompt,
    )?;
    let renderer_guidance = chat_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let scaffold_execution_digest = surface_contracts.execution_digest.clone();
    let scaffold_execution_block = if scaffold_execution_digest.is_empty() {
        String::new()
    } else {
        format!(
            "\n\nScaffold execution digest:\n{}",
            if compact_prompt {
                truncate_materialization_focus_text(&scaffold_execution_digest, 280)
            } else {
                scaffold_execution_digest
            }
        )
    };
    let refinement_wrapper_directive = if refinement.is_some() {
        "\n\nRefinement output contract:\nReturn the patched artifact inside the exact JSON schema below; do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object."
    } else {
        ""
    };
    let schema_contract =
        chat_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind);
    if compact_prompt {
        let request_focus_text = compact_local_html_materialization_request_text(request);
        let brief_focus_text = compact_local_html_materialization_brief_text(brief);
        let interaction_contract_text = compact_local_html_interaction_contract_text(brief);
        let refinement_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_refinement_context_focus(refinement),
            "Chat refinement context",
            true,
        )?;

        return Ok(json!([
            {
                "role": "system",
                "content": "You are Chat's typed artifact materializer. Produce exactly one JSON object. The typed brief, edit intent, and current artifact context are authoritative. Do not emit prose outside JSON."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus:\n{}\n\nArtifact brief focus:\n{}\n\nInteraction contract:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context JSON:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                    title,
                    intent,
                    request_focus_text,
                    brief_focus_text,
                    interaction_contract_text,
                    edit_intent_json,
                    refinement_focus_json,
                    candidate_id,
                    candidate_seed,
                    refinement_wrapper_directive,
                    renderer_guidance,
                    schema_contract,
                )
            }
        ]));
    }

    let request_json =
        serialize_materialization_prompt_json(request, "Chat artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Chat artifact brief", compact_prompt)?;
    let blueprint_json = serialize_materialization_prompt_json(
        &resolved_blueprint,
        "Chat artifact blueprint",
        compact_prompt,
    )?;
    let artifact_ir_json = serialize_materialization_prompt_json(
        &resolved_artifact_ir,
        "Chat artifact IR",
        compact_prompt,
    )?;
    let selected_skills_json = serialize_materialization_prompt_json(
        &chat_artifact_selected_skill_prompt_view(selected_skills),
        "Chat selected skill guidance",
        compact_prompt,
    )?;
    let retrieved_exemplars_json = serialize_materialization_prompt_json(
        &chat_artifact_exemplar_prompt_view(retrieved_exemplars),
        "Chat retrieved exemplars",
        compact_prompt,
    )?;
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
    let design_label = format!("{} JSON", surface_contracts.design_label);
    let scaffold_label = format!("{} JSON", surface_contracts.scaffold_label);
    let component_label = format!("{} JSON", surface_contracts.component_label);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Chat's typed artifact materializer. Produce exactly one JSON object. The typed brief, edit intent, and current artifact context are authoritative. Do not emit prose outside JSON."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nArtifact blueprint JSON:\n{}\n\nArtifact IR JSON:\n{}\n\nSelected skill guidance JSON:\n{}\n\nRetrieved exemplar JSON:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n{}{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
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
                refinement_wrapper_directive,
                scaffold_execution_block,
                renderer_guidance,
                schema_contract,
            )
        }
    ]))
}

pub(crate) fn build_chat_artifact_direct_author_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    selected_skills: &[ChatArtifactSelectedSkill],
    edit_intent: Option<&ChatArtifactEditIntent>,
    refinement: Option<&ChatArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    runtime_kind: ChatRuntimeProvenanceKind,
    returns_raw_document: bool,
) -> Result<serde_json::Value, String> {
    fn edit_mode_label(mode: ChatArtifactEditMode) -> &'static str {
        match mode {
            ChatArtifactEditMode::Create => "create",
            ChatArtifactEditMode::Patch => "patch",
            ChatArtifactEditMode::Replace => "replace",
            ChatArtifactEditMode::Branch => "branch",
        }
    }

    fn direct_author_edit_intent_focus_text(
        edit_intent: Option<&ChatArtifactEditIntent>,
    ) -> Option<String> {
        let edit_intent = edit_intent?;
        let target_paths = if edit_intent.target_paths.is_empty() {
            "none".to_string()
        } else {
            edit_intent
                .target_paths
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        };
        let requested_operations = if edit_intent.requested_operations.is_empty() {
            "none".to_string()
        } else {
            edit_intent
                .requested_operations
                .iter()
                .take(4)
                .map(|operation| truncate_materialization_focus_text(operation, 72))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let selected_targets = if edit_intent.selected_targets.is_empty() {
            "none".to_string()
        } else {
            edit_intent
                .selected_targets
                .iter()
                .take(3)
                .map(|target| {
                    format!(
                        "{} ({})",
                        truncate_materialization_focus_text(&target.label, 60),
                        truncate_materialization_focus_text(&target.snippet, 120)
                    )
                })
                .collect::<Vec<_>>()
                .join(" | ")
        };

        Some(format!(
            "Follow-up edit intent:\nmode: {}\npatch existing artifact: {}\npreserve structure: {}\ntarget scope: {}\ntarget paths: {}\nrequested operations: {}\nselected targets: {}",
            edit_mode_label(edit_intent.mode),
            edit_intent.patch_existing_artifact,
            edit_intent.preserve_structure,
            truncate_materialization_focus_text(&edit_intent.target_scope, 96),
            target_paths,
            requested_operations,
            selected_targets,
        ))
    }

    fn direct_author_refinement_document_context(
        refinement: Option<&ChatArtifactRefinementContext>,
    ) -> Option<String> {
        let refinement = refinement?;
        let file = refinement
            .files
            .iter()
            .find(|file| file.renderable)
            .or_else(|| refinement.files.first())?;
        let body = file.body.trim();
        if body.is_empty() {
            return None;
        }

        let body_chars = body.chars().count();
        let preview = if body_chars <= 4200 {
            body.to_string()
        } else {
            let head = body.chars().take(2200).collect::<String>();
            let tail = body
                .chars()
                .rev()
                .take(1400)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>();
            format!(
                "{head}\n\n...[truncated {} chars]...\n\n{tail}",
                body_chars - 3600
            )
        };

        Some(format!(
            "Current renderable artifact ({}):\n{}",
            file.path, preview
        ))
    }

    fn direct_author_refinement_focus_text(
        refinement: Option<&ChatArtifactRefinementContext>,
    ) -> Option<String> {
        let refinement = refinement?;
        let selected_targets = if refinement.selected_targets.is_empty() {
            "none".to_string()
        } else {
            refinement
                .selected_targets
                .iter()
                .take(3)
                .map(|target| {
                    format!(
                        "{} ({})",
                        truncate_materialization_focus_text(&target.label, 56),
                        truncate_materialization_focus_text(&target.snippet, 96)
                    )
                })
                .collect::<Vec<_>>()
                .join(" | ")
        };

        Some(format!(
            "Existing artifact continuity:\ntitle: {}\nsummary: {}\nselected targets: {}",
            truncate_materialization_focus_text(&refinement.title, 96),
            truncate_materialization_focus_text(&refinement.summary, 220),
            selected_targets,
        ))
    }

    let user_intent = extract_user_request_from_contextualized_intent(intent);
    let title_seed = if title.trim().starts_with("[Codebase context]") {
        user_intent.as_str()
    } else {
        title
    };

    let renderer_guidance =
        chat_direct_author_renderer_guidance(request, candidate_seed, runtime_kind);
    let compact_local_renderer_guidance = if runtime_kind
        == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
        && returns_raw_document
    {
        if request.artifact_class == ChatArtifactClass::InteractiveSingleFile {
            "Keep the page compact and finishable in one local-model pass.\n- Use one self-contained index.html with concise inline CSS and tiny inline JavaScript.\n- Put the first actionable controls, response/detail region, and at least two evidence sections near the top of <main> before long prose.\n- Keep visible markup first, keep CSS lean, and spend the response on the request-shaped surface rather than decorative scaffolding.\n- Realize the typed query goals through explicit authored states, evidence surfaces, or response regions instead of placeholder shells.\n- After the first complete interactive flow lands, stop instead of adding extra stages or trailing notes.\n- Use semantic HTML with <main>, ship a complete default state on first paint, and end with a fully closed </body></html>."
                .to_string()
        } else {
            "Keep the page compact and finishable in one local-model pass.\n- Use one self-contained index.html with concise inline CSS and only minimal inline JavaScript when it truly improves the document.\n- Put the main explanatory surface and supporting evidence near the top of <main> before long prose.\n- Keep visible markup first, keep CSS lean, and spend the response on the request-shaped explanation rather than decorative scaffolding or controls the request did not ask for.\n- Realize the typed query goals through authored explanation, evidence surfaces, and comparison copy instead of placeholder shells.\n- Stop once the first complete document experience lands instead of adding extra stages, fake interactivity, or trailing notes.\n- Use semantic HTML with <main>, ship a complete first paint, and end with a fully closed </body></html>."
                .to_string()
        }
    } else {
        renderer_guidance.clone()
    };
    let output_contract = if returns_raw_document {
        match request.renderer {
            ChatRendererKind::Markdown => {
                "Output contract:\n- Return only one complete markdown document.\n- Do not wrap the document in JSON.\n- Do not wrap the document in markdown fences.\n- Keep the document request-specific and complete on first pass."
            }
            ChatRendererKind::HtmlIframe => {
                "Output contract:\n- Return only one complete self-contained HTML document.\n- Start with <!doctype html> or <html> and end with </html>.\n- Do not wrap the document in JSON.\n- Do not wrap the document in markdown fences.\n- Keep the authored file request-specific, complete on first paint, and ready to save as index.html."
            }
            ChatRendererKind::Svg => {
                "Output contract:\n- Return only one complete standalone SVG document.\n- Start with <svg and end with </svg>.\n- Do not wrap the SVG in JSON or markdown fences.\n- Keep the artifact request-specific and complete on first pass."
            }
            ChatRendererKind::Mermaid => {
                "Output contract:\n- Return only Mermaid diagram source.\n- Do not wrap the diagram in JSON or markdown fences.\n- Keep the diagram request-specific and complete on first pass."
            }
            ChatRendererKind::PdfEmbed => {
                "Output contract:\n- Return only the complete document text that should be compiled into the PDF artifact.\n- Do not return binary data, LaTeX, JSON, or markdown fences.\n- Keep the document request-specific and complete on first pass."
            }
            _ => {
                "Output contract:\n- Return only the complete authored document.\n- Do not wrap it in JSON or markdown fences."
            }
        }
    } else {
        chat_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind)
    };
    let direct_author_contract = if returns_raw_document {
        "Direct authoring contract:\n- Preserve the raw user request as the primary instruction.\n- Author the requested single-document artifact directly instead of inventing a generic platform artifact.\n- Produce one complete, request-specific document for the typed renderer.\n- Do not introduce planner summaries, blueprint language, or generalized artifact boilerplate into visible copy unless the request asked for it."
    } else {
        "Direct authoring contract:\n- Preserve the raw user request as the primary instruction.\n- Author the requested artifact directly instead of inventing a generic platform artifact.\n- Return exactly one JSON object in the schema below.\n- Do not introduce planner summaries, blueprint language, or generalized artifact boilerplate into visible copy unless the request asked for it."
    };
    let system_contract = if returns_raw_document {
        if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
            "You are Chat's direct document author. The raw user request is the primary instruction. Return only the completed document body for the requested renderer. Do not emit JSON, summaries, notes, keys, prose, or markdown fences before the document. If the renderer is html_iframe, the very first non-whitespace characters must be <!doctype html> or <html>."
        } else {
            "You are Chat's direct document author. The raw user request is the primary instruction. Author the artifact directly and return only the completed document body for the requested renderer. Do not emit prose, markdown fences, or JSON."
        }
    } else {
        "You are Chat's typed artifact materializer. The raw user request is the primary instruction. Author the artifact directly and return exactly one JSON object. Do not emit prose outside JSON."
    };
    let query_profile_focus = brief
        .query_profile
        .as_ref()
        .map(|profile| {
            let interaction_goals = if profile.interaction_goals.is_empty() {
                "None specified".to_string()
            } else {
                profile
                    .interaction_goals
                    .iter()
                    .map(|goal| goal.summary.trim().to_string())
                    .take(4)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let presentation_constraints = if profile.presentation_constraints.is_empty() {
                "None specified".to_string()
            } else {
                profile
                    .presentation_constraints
                    .iter()
                    .filter(|constraint| constraint.required)
                    .map(|constraint| constraint.summary.trim().to_string())
                    .take(4)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            format!(
                "\nTyped query goals: {}\nPresentation constraints: {}",
                interaction_goals, presentation_constraints
            )
        })
        .unwrap_or_default();
    let required_interactions = brief.required_interaction_summaries();
    let brief_focus_text = format!(
        "Audience: {}\nJob to be done: {}\nArtifact thesis: {}\nRequired concepts: {}\nRequired interactions: {}{}",
        brief.audience.trim(),
        brief.job_to_be_done.trim(),
        brief.artifact_thesis.trim(),
        if brief.required_concepts.is_empty() {
            "None specified".to_string()
        } else {
            brief
                .required_concepts
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        },
        if required_interactions.is_empty() {
            "None specified".to_string()
        } else {
            required_interactions
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        },
        query_profile_focus,
    );

    let selected_skills_focus_text = if selected_skills.is_empty() {
        "No selected skill guidance was attached.".to_string()
    } else {
        selected_skills
            .iter()
            .take(3)
            .map(|skill| {
                let guidance = skill
                    .guidance_markdown
                    .as_ref()
                    .map(|markdown| truncate_materialization_focus_text(markdown, 220))
                    .filter(|markdown| !markdown.trim().is_empty())
                    .unwrap_or_else(|| {
                        truncate_materialization_focus_text(&skill.match_rationale, 220)
                    });
                format!("- {}: {}", skill.name.trim(), guidance)
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    if compact_local_direct_author_prompt(runtime_kind, returns_raw_document) {
        if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
            && request.renderer == ChatRendererKind::HtmlIframe
            && returns_raw_document
            && refinement.is_none()
            && edit_intent.is_none()
        {
            let html_document_requirements = if request.artifact_class
                == ChatArtifactClass::InteractiveSingleFile
            {
                "- Deliver one request-specific interactive HTML document.\n- Use semantic HTML with <main> and a coherent set of authored regions for the typed query goals.\n- Keep first paint useful before scripts run.\n- Include one or more real interaction seams that change visible evidence or response context.\n- Keep body text, headings, controls, and evidence labels high-contrast against the background on first paint; avoid muted gray-on-gray styling that weakens readability.\n- Keep CSS short enough to finish the full document in one pass.\n- End with a fully closed </main></body></html>."
                    .to_string()
            } else {
                "- Deliver one request-specific HTML document.\n- Use semantic HTML with <main> and a coherent set of authored explanatory and evidence regions for the typed query goals.\n- Keep first paint useful before scripts run.\n- Prefer authored explanation, comparison surfaces, and visible evidence over control chrome the request did not ask for.\n- Only introduce JavaScript when it materially improves the document; do not force interactivity for document-class requests.\n- Keep body copy, headings, supporting labels, and evidence text high-contrast against the background on first paint; default to readable light-on-dark or dark-on-light pairings instead of muted low-contrast combinations.\n- Keep CSS short enough to finish the full document in one pass.\n- End with a fully closed </main></body></html>."
                    .to_string()
            };
            return Ok(json!([
                {
                    "role": "system",
                    "content": "Return only one complete self-contained index.html. Start with <!doctype html> and end with </html>. Do not emit JSON, markdown fences, notes, or explanation. Keep inline CSS concise, keep inline JavaScript tiny, and spend the response on the actual document rather than wrapper boilerplate. Keep text contrast clearly readable on first paint."
                },
                {
                    "role": "user",
                    "content": format!(
                        "{}\n\nPrepared artifact brief:\n{}\n\nSelected skill guidance:\n{}\n\nRequirements:\n{}",
                        user_intent.trim(),
                        brief_focus_text,
                        selected_skills_focus_text,
                        html_document_requirements,
                    )
                }
            ]));
        }

        let mut sections = vec![
            Some(format!("Title: {}", title_seed.trim())),
            Some(format!("Raw user request:\n{}", user_intent.trim())),
            Some(format!("Prepared artifact brief:\n{}", brief_focus_text)),
            Some(format!(
                "Selected skill guidance:\n{}",
                selected_skills_focus_text
            )),
            direct_author_edit_intent_focus_text(edit_intent),
            direct_author_refinement_focus_text(refinement),
            refinement.map(|_| {
                "Follow-up continuity contract:\n- Treat the current artifact as the baseline.\n- Preserve layout and authored structure unless the request explicitly asks for a broader rewrite.\n- Apply only the requested edits, then return the full updated document."
                    .to_string()
            }),
            direct_author_refinement_document_context(refinement),
            Some(direct_author_contract.to_string()),
            Some(format!(
                "Renderer-native authoring guidance:\n{}",
                compact_local_renderer_guidance
            )),
            Some(output_contract.to_string()),
            if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
                && request.renderer == ChatRendererKind::HtmlIframe
            {
                Some(
                    "Return format hard requirement:\n- Start immediately with <!doctype html>.\n- Do not output JSON keys like summary, notes, or files.\n- Spend the response budget on the actual document body, not wrapper metadata."
                        .to_string(),
                )
            } else {
                None
            },
        ];
        sections.retain(|entry| entry.as_ref().is_some_and(|text| !text.trim().is_empty()));

        return Ok(json!([
            {
                "role": "system",
                "content": system_contract
            },
            {
                "role": "user",
                "content": sections
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("\n\n")
            }
        ]));
    }

    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let brief_json =
        serialize_materialization_prompt_json(brief, "Chat artifact brief", compact_prompt)?;
    let selected_skills_json = serialize_materialization_prompt_json(
        &chat_artifact_selected_skill_prompt_view(selected_skills),
        "Chat selected skill guidance",
        compact_prompt,
    )?;
    let request_focus_json = serialize_materialization_prompt_json(
        &compact_local_html_materialization_request_focus(request),
        "Chat artifact request focus",
        compact_prompt,
    )?;
    let edit_intent_json = serialize_materialization_prompt_json(
        &edit_intent,
        "Chat artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &chat_artifact_refinement_context_view(refinement),
        "Chat refinement context",
        compact_prompt,
    )?;

    Ok(json!([
        {
            "role": "system",
            "content": system_contract
        },
        {
            "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRaw user request:\n{}\n\nArtifact request focus JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nSelected skill guidance JSON:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context JSON:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                title_seed,
                user_intent,
                request_focus_json,
                brief_json,
                selected_skills_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                direct_author_contract,
                renderer_guidance,
                output_contract,
            )
        }
    ]))
}

pub(crate) fn build_chat_artifact_direct_author_continuation_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    selected_skills: &[ChatArtifactSelectedSkill],
    partial_document: &str,
    latest_error: &str,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> serde_json::Value {
    fn local_html_semantic_underbuild_failure(error_message: &str) -> bool {
        [
            "HTML sectioning regions are empty shells on first paint.",
            "Interactive HTML iframe artifacts must update on-page state or shared detail, not only surface inert controls.",
            "Interactive HTML iframe artifacts must update on-page state or shared detail, not only scroll, jump, or log.",
            "HTML state switching does not keep enough authored evidence surfaces available on first paint.",
            "HTML state switching does not wire controls to produce visible state changes.",
            "HTML multi-step interaction briefs must surface at least two actionable controls on first paint.",
            "HTML only surfaces sparse inspection affordances on first paint.",
            "HTML lacks hover, focus, or equivalent inspection behavior for the requested detail interactions.",
            "HTML required interactions do not surface a visible response region on first paint.",
        ]
        .iter()
        .any(|needle| error_message.contains(needle))
    }

    fn continuation_partial_document_context(
        partial_document: &str,
        runtime_kind: ChatRuntimeProvenanceKind,
    ) -> String {
        let trimmed = partial_document.trim();
        let chars = trimmed.chars().collect::<Vec<_>>();
        let (max_chars, head_chars, tail_chars) =
            if compact_local_direct_author_prompt(runtime_kind, true) {
                (3200usize, 1200usize, 1800usize)
            } else {
                (6000usize, 2200usize, 2800usize)
            };
        if chars.len() <= max_chars {
            return trimmed.to_string();
        }

        let head = chars.iter().take(head_chars).collect::<String>();
        let tail = chars[chars.len().saturating_sub(tail_chars)..]
            .iter()
            .collect::<String>();
        format!("[document start]\n{head}\n\n[document tail]\n{tail}")
    }

    let boundary = direct_author_completion_boundary(request).unwrap_or("</html>");
    let continuation_contract = match request.renderer {
        ChatRendererKind::HtmlIframe => {
            "If the existing document is valid up to the stopping point, return mode=\"suffix\" and only the missing HTML tail. If the document needs structural rewrites, return mode=\"full_document\" and the full corrected HTML document. A full document must start with <!doctype html> or <html> and end with </html>."
        }
        ChatRendererKind::Svg => {
            "If the existing document is valid up to the stopping point, return mode=\"suffix\" and only the missing SVG tail. If the document needs structural rewrites, return mode=\"full_document\" and the full corrected SVG document. A full document must start with <svg and end with </svg>."
        }
        _ => {
            "Return mode=\"suffix\" with only the missing document tail, or mode=\"full_document\" with the full corrected document when a rewrite is necessary."
        }
    };
    let partial_document_context =
        continuation_partial_document_context(partial_document, runtime_kind);
    let selected_skills_focus_text = if selected_skills.is_empty() {
        "No selected skill guidance was attached.".to_string()
    } else {
        selected_skills
            .iter()
            .take(3)
            .map(|skill| {
                format!(
                    "- {}: {}",
                    skill.name.trim(),
                    truncate_materialization_focus_text(&skill.match_rationale, 180)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let brief_focus_text = format!(
        "Audience: {}\nJob to be done: {}\nArtifact thesis: {}\nRequired concepts: {}\nRequired interactions: {}",
        brief.audience.trim(),
        brief.job_to_be_done.trim(),
        brief.artifact_thesis.trim(),
        if brief.required_concepts.is_empty() {
            "None specified".to_string()
        } else {
            brief
                .required_concepts
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        },
        {
            let required_interactions = brief.required_interaction_summaries();
            if required_interactions.is_empty() {
                "None specified".to_string()
            } else {
                required_interactions
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        },
    );
    let system_contract = if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
        "You are Chat's typed direct document continuation author. Return exactly one JSON object and nothing else."
    } else {
        "You are Chat's typed direct document continuation author. Return exactly one JSON object and nothing else."
    };
    if compact_local_direct_author_prompt(runtime_kind, true) {
        if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
            && request.renderer == ChatRendererKind::HtmlIframe
            && direct_author_uses_raw_document(request)
        {
            let renderer_guidance = chat_direct_author_renderer_guidance(
                request,
                candidate_seed_for(title, intent, 0),
                runtime_kind,
            );
            let requires_full_document =
                local_html_semantic_underbuild_failure(latest_error.trim());
            let continuation_contract = if requires_full_document {
                "Return one complete corrected self-contained HTML document that preserves the strongest authored structure while fixing the invalid interactive behavior."
            } else {
                "Keep the current authored direction and continue the in-progress HTML document instead of restarting from scratch."
            };
            let output_schema = if requires_full_document {
                "- One complete corrected self-contained HTML document."
            } else {
                "- Missing tail only, or one full corrected self-contained HTML document when a rewrite is necessary."
            };
            let preference_rule = if requires_full_document {
                "- Return one full corrected self-contained HTML document; do not return only a suffix."
            } else {
                "- Prefer returning only the missing tail when possible."
            };
            let suffix_rule = if requires_full_document {
                "- Start with <!doctype html> or <html> and end with </html>.".to_string()
            } else {
                format!(
                    "- If you return a tail, do not repeat the earlier portion and make sure the combined document ends with {}.\n- If you rewrite, start with <!doctype html> or <html> and end with </html>.",
                    boundary,
                )
            };
            return json!([
                {
                    "role": "system",
                    "content": "You are Chat's typed direct document continuation author. Return document text only."
                },
                {
                    "role": "user",
                    "content": format!(
                        "Title: {}\n\nRaw user request:\n{}\n\nPrepared artifact brief:\n{}\n\nSelected skill guidance:\n{}\n\nValidation failure:\n{}\n\nContinuation contract:\n- {}\n\nContinuation output schema:\n{}\n\nRules:\n- Return only document text with no JSON, markdown fences, notes, or explanations.\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\nThe current partial document is below.\n\nPartial document tail:\n{}",
                        title.trim(),
                        intent.trim(),
                        brief_focus_text,
                        selected_skills_focus_text,
                        truncate_materialization_focus_text(latest_error.trim(), 420),
                        continuation_contract,
                        output_schema,
                        preference_rule,
                        suffix_rule,
                        truncate_materialization_focus_text(&renderer_guidance, 260),
                        partial_document_context,
                    )
                }
            ]);
        }

        let renderer_guidance = chat_direct_author_renderer_guidance(
            request,
            candidate_seed_for(title, intent, 0),
            runtime_kind,
        );
        return json!([
            {
                "role": "system",
                "content": "You are Chat's typed direct document continuation author. Return exactly one JSON object and nothing else."
            },
            {
                "role": "user",
                "content": format!(
                    "Title: {}\n\nRaw user request:\n{}\n\nPrepared artifact brief:\n{}\n\nSelected skill guidance:\n{}\n\nValidation failure:\n{}\n\nContinuation contract:\n{}\n\nContinuation output schema:\n{{\n  \"mode\": \"suffix\" | \"full_document\",\n  \"content\": <string>\n}}\nRules:\n- Return JSON only, with no markdown fences or explanations.\n- content must contain only document text.\n- Prefer mode=\"suffix\" when the earlier bytes are still valid and only a tail is missing.\n- Use mode=\"full_document\" when the document needs a structural rewrite.\n- If mode=\"suffix\", do not repeat the earlier portion, and make sure the combined document ends with {}.\n- If mode=\"full_document\", return the entire corrected document in content.\n\nRenderer-native authoring guidance:\n{}\n\nThe current partial document is below.\n\nPartial document tail:\n{}",
                    title.trim(),
                    intent.trim(),
                    brief_focus_text,
                    selected_skills_focus_text,
                    truncate_materialization_focus_text(latest_error.trim(), 420),
                    continuation_contract,
                    boundary,
                    truncate_materialization_focus_text(&renderer_guidance, 260),
                    partial_document_context,
                )
            }
        ]);
    }
    json!([
        {
            "role": "system",
            "content": system_contract
        },
        {
            "role": "user",
            "content": format!(
                "Title: {}\n\nRaw user request:\n{}\n\nPrepared artifact brief:\nAudience: {}\nJob to be done: {}\nArtifact thesis: {}\n\nSelected skill guidance:\n{}\n\nValidation failure:\n{}\n\nContinuation contract:\n{}\n\nContinuation output schema:\n{{\n  \"mode\": \"suffix\" | \"full_document\",\n  \"content\": <string>\n}}\nRules:\n- Return JSON only, with no markdown fences or explanations.\n- content must contain only document text.\n- Prefer mode=\"suffix\" when the earlier bytes are still valid and only a tail is missing.\n- Use mode=\"full_document\" when the document needs a structural rewrite.\n- If mode=\"suffix\", do not repeat the earlier portion, and make sure the combined document ends with {}.\n- If mode=\"full_document\", return the entire corrected document in content.\n\nThe current partial document is below.\n\nPartial document tail:\n{}",
                title.trim(),
                intent.trim(),
                brief.audience.trim(),
                brief.job_to_be_done.trim(),
                brief.artifact_thesis.trim(),
                selected_skills_focus_text,
                latest_error.trim(),
                continuation_contract,
                boundary,
                partial_document_context,
            )
        }
    ])
}

pub(super) fn build_chat_artifact_direct_author_repair_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    selected_skills: &[ChatArtifactSelectedSkill],
    invalid_document: &str,
    latest_error: &str,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> serde_json::Value {
    fn repair_document_context(
        invalid_document: &str,
        runtime_kind: ChatRuntimeProvenanceKind,
    ) -> String {
        let trimmed = invalid_document.trim();
        let chars = trimmed.chars().collect::<Vec<_>>();
        let (max_chars, head_chars, tail_chars) =
            if compact_local_direct_author_prompt(runtime_kind, true) {
                (2800usize, 900usize, 1400usize)
            } else {
                (3600usize, 1400usize, 1800usize)
            };
        if chars.len() <= max_chars {
            return trimmed.to_string();
        }

        let head = chars.iter().take(head_chars).collect::<String>();
        let tail = chars[chars.len().saturating_sub(tail_chars)..]
            .iter()
            .collect::<String>();
        format!("[document start]\n{head}\n\n[document tail]\n{tail}")
    }

    let renderer_guidance = chat_direct_author_renderer_guidance(
        request,
        candidate_seed_for(title, intent, 0),
        runtime_kind,
    );
    let required_interactions = brief.required_interaction_summaries();
    let brief_focus_text = format!(
        "Audience: {}\nJob to be done: {}\nArtifact thesis: {}\nRequired concepts: {}\nRequired interactions: {}",
        brief.audience.trim(),
        brief.job_to_be_done.trim(),
        brief.artifact_thesis.trim(),
        if brief.required_concepts.is_empty() {
            "None specified".to_string()
        } else {
            brief
                .required_concepts
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        },
        if required_interactions.is_empty() {
            "None specified".to_string()
        } else {
            required_interactions
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        },
    );
    let output_contract = match request.renderer {
        ChatRendererKind::Markdown => {
            "Return mode=\"full_document\" with one complete corrected markdown document."
        }
        ChatRendererKind::HtmlIframe => {
            "Return mode=\"full_document\" with one complete corrected self-contained HTML document. The document must start with <!doctype html> or <html> and end with </html>."
        }
        ChatRendererKind::Svg => {
            "Return mode=\"full_document\" with one complete corrected standalone SVG document. The document must start with <svg and end with </svg>."
        }
        ChatRendererKind::Mermaid => {
            "Return mode=\"full_document\" with one complete corrected Mermaid document."
        }
        ChatRendererKind::PdfEmbed => {
            "Return mode=\"full_document\" with one complete corrected document text."
        }
        _ => "Return mode=\"full_document\" with one complete corrected document.",
    };
    let system_contract = if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
        "You are Chat's typed direct document repair author. Return exactly one JSON object and nothing else."
    } else {
        "You are Chat's typed direct document repair author. Return exactly one JSON object and nothing else."
    };
    let selected_skills_focus_text = if selected_skills.is_empty() {
        "No selected skill guidance was attached.".to_string()
    } else {
        selected_skills
            .iter()
            .take(3)
            .map(|skill| {
                format!(
                    "- {}: {}",
                    skill.name.trim(),
                    truncate_materialization_focus_text(&skill.match_rationale, 180)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    if compact_local_direct_author_prompt(runtime_kind, true) {
        if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
            && request.renderer == ChatRendererKind::HtmlIframe
            && direct_author_uses_raw_document(request)
        {
            return json!([
                {
                    "role": "system",
                    "content": "You are Chat's typed direct document repair author. Return document text only."
                },
                {
                    "role": "user",
                    "content": format!(
                        "Title: {}\n\nRaw user request:\n{}\n\nPrepared artifact brief:\n{}\n\nSelected skill guidance:\n{}\n\nRepair failure:\n{}\n\nRepair contract:\n- Preserve the strongest authored structure that already works.\n- Fix the structural/runtime failure without switching to a generic shell.\n- For JavaScript runtime failures, repair the actual executable code path; variables reassigned during calculations or loops must use let, not const.\n- {}\n\nRepair output schema:\n- One complete corrected self-contained HTML document.\n\nRules:\n- Return one complete corrected self-contained HTML document.\n- Return only document text with no JSON, markdown fences, notes, or explanations.\n- Start with <!doctype html> or <html> and end with </html>.\n- Keep number/range/select controls as real controls with default values when the artifact is an adjustable calculator or simulator.\n\nRenderer-native authoring guidance:\n{}\n\nCurrent invalid document context:\n{}",
                        title.trim(),
                        intent.trim(),
                        brief_focus_text,
                        selected_skills_focus_text,
                        truncate_materialization_focus_text(latest_error.trim(), 420),
                        output_contract,
                        truncate_materialization_focus_text(&renderer_guidance, 260),
                        repair_document_context(invalid_document, runtime_kind),
                    )
                }
            ]);
        }

        return json!([
            {
                "role": "system",
                "content": "You are Chat's typed direct document repair author. Return exactly one JSON object and nothing else."
            },
            {
                "role": "user",
                "content": format!(
                    "Title: {}\n\nRaw user request:\n{}\n\nPrepared artifact brief:\n{}\n\nSelected skill guidance:\n{}\n\nRepair failure:\n{}\n\nRepair contract:\n- Preserve the authored direction and strongest working structure.\n- Fix the structural/runtime failure without restarting from a generic shell.\n- For JavaScript runtime failures, repair the actual executable code path; variables reassigned during calculations or loops must use let, not const.\n- {}\n\nRepair output schema:\n{{\n  \"mode\": \"full_document\",\n  \"content\": <string>\n}}\nRules:\n- Return JSON only, with no markdown fences or explanations.\n- content must contain only the corrected document text.\n- mode must be \"full_document\" for repair.\n- Keep number/range/select controls as real controls with default values when the artifact is an adjustable calculator or simulator.\n\nRenderer-native authoring guidance:\n{}\n\nCurrent invalid document context:\n{}",
                    title.trim(),
                    intent.trim(),
                    brief_focus_text,
                    selected_skills_focus_text,
                    truncate_materialization_focus_text(latest_error.trim(), 420),
                    output_contract,
                    truncate_materialization_focus_text(&renderer_guidance, 260),
                    repair_document_context(invalid_document, runtime_kind),
                )
            }
        ]);
    }

    json!([
        {
            "role": "system",
            "content": system_contract
        },
        {
            "role": "user",
            "content": format!(
                "Title: {}\n\nRaw user request:\n{}\n\nPrepared artifact brief:\nAudience: {}\nJob to be done: {}\nArtifact thesis: {}\n\nSelected skill guidance:\n{}\n\nValidation failure:\n{}\n\nRepair contract:\n- Preserve the existing authored direction when possible.\n- Correct the structural failure without switching to a generic platform artifact.\n- {}\n\nRepair output schema:\n{{\n  \"mode\": \"full_document\",\n  \"content\": <string>\n}}\nRules:\n- Return JSON only, with no markdown fences or explanations.\n- content must contain only the corrected document text.\n- mode must be \"full_document\" for repair.\n\nRenderer-native guidance:\n{}\n\nCurrent invalid document:\n{}",
                title.trim(),
                intent.trim(),
                brief.audience.trim(),
                brief.job_to_be_done.trim(),
                brief.artifact_thesis.trim(),
                selected_skills_focus_text,
                latest_error.trim(),
                output_contract,
                renderer_guidance,
                invalid_document,
            )
        }
    ])
}

pub(super) fn chat_artifact_materialization_schema_contract() -> &'static str {
    "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string>,\n  \"notes\": [<string>],\n  \"files\": [\n    {\n      \"path\": <string>,\n      \"mime\": <string>,\n      \"role\": \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean>,\n      \"downloadable\": <boolean>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string>\n    }\n  ]\n}\nRules:\n1) Respect the typed renderer exactly.\n2) markdown => one renderable .md file.\n3) html_iframe => one renderable .html file with inline CSS/JS only.\n4) html_iframe must use semantic HTML structure: include <main> plus at least three sectioning elements drawn from <section>, <article>, <nav>, <aside>, or <footer>.\n5) html_iframe must ground requiredInteractions in real controls or interactive regions, not just static headings.\n6) html_iframe must realize required interactions as on-page state changes, revealed detail, filtering, comparison, tutorial stepping, or comparable DOM behavior.\n7) html_iframe must ship interactive regions with actual first-paint content and data; empty containers, comment-only handlers, or explanation-only scripts do not count as implementation.\n8) html_iframe must include a first-paint control set plus a shared detail, comparison, or explanation region when requiredInteractions are non-empty.\n9) html_iframe view-switching or navigation interactions must change inline content or shared detail state; anchor-only jump links do not count as sufficient implementation.\n10) html_iframe must render the default selected chart, label, and detail state directly in the markup before any script runs; scripts may enhance or switch it, but must not create the only visible first-paint content from empty shells.\n11) html_iframe must not use alert(), dead buttons, submit-to-nowhere forms, or navigation-only controls as the main interaction.\n12) html_iframe must not invent custom element tags like <toolbox> or <demo>; use standard HTML elements, classes, and data-* attributes.\n13) html_iframe must not depend on external libraries, undefined globals, or remote placeholder media; render charts and diagrams with inline SVG, canvas, or DOM/CSS.\n14) html_iframe must prefer inline SVG or DOM data marks over blank canvas shells; a canvas-only placeholder does not count as first-paint implementation.\n15) html_iframe chart or diagram regions rendered with SVG must contain real marks plus visible labels, legend text, or accessible labels on first paint; abstract geometry alone does not count.\n16) html_iframe chart or diagram controls should update a shared detail, comparison, or explanation region instead of acting as decorative navigation.\n17) html_iframe must not include HTML comments, placeholder comments, TODO markers, or script references to DOM ids that do not exist in the document.\n18) html_iframe must not emit the literal words placeholder, placeholders, TODO, or TBD anywhere in the final HTML, CSS, JavaScript, comments, ids, classes, or visible copy.\n19) jsx_sandbox => one renderable .jsx file with a default export.\n20) svg => one renderable .svg file.\n21) mermaid => one renderable .mermaid file.\n22) pdf_embed => one .pdf file whose body is the document text that Chat will compile into PDF bytes, and the document text must still be returned inside this JSON object as files[0].body rather than as raw prose outside JSON.\n23) download_card => downloadable export files only; do not mark them renderable.\n24) bundle_manifest => a .json manifest plus any supporting files required by the bundle.\n25) workspace_surface must not be used here.\n26) The visible composition must surface the differentiating request concepts from artifactThesis and requiredConcepts, not just the broad category.\n27) Do not use placeholder image URLs, placeholder copy, generic stock filler, or fake media placeholders. Prefer typographic, diagrammatic, or CSS-native composition over fake media placeholders.\n28) If the artifact could fit many unrelated prompts by only swapping the heading, it is not acceptable.\n29) Honor refinement continuity when editIntent.mode is patch or branch.\n30) Prefer truthful partial output over invented completion.\n31) html_iframe controls that iterate across multiple buttons, cards, or marks must target collections correctly; use querySelectorAll or an equivalent collection before calling forEach or similar methods, and keep every referenced view present in the markup.\n32) html_iframe clickable navigation should use explicit static control-to-panel mappings such as data-view plus data-view-panel, aria-controls, or data-target tied to pre-rendered views. Use the literal data-view-panel attribute on the panel element itself; a CSS class like class=\"data-view-panel\" does not satisfy this contract. Do not synthesize target ids by concatenating button ids or other runtime strings.\n33) html_iframe briefs that call for charts, diagrams, metrics, or comparisons must surface at least two distinct first-paint evidence views or chart families tied to different requiredConcepts or referenceHints; one chart plus generic prose is insufficient, and blank mount divs like <div id=\"usage-chart\"></div> do not count as evidence views.\n34) html_iframe briefs that require both clickable view switching and rollover detail must satisfy both in the same document: keep at least two pre-rendered panels plus visible data-detail marks that update one shared detail region on click and hover/focus. Do not repair one interaction by deleting the other.\n35) html_iframe marks that rely on focus handlers must be focusable, such as via tabindex=\"0\" or naturally focusable elements.\n36) html_iframe view-switching briefs must not point multiple controls only at one shared detail region; each switchable control needs its own pre-rendered panel container. If you emit controls like data-view=\"overview\", data-view=\"comparison\", and data-view=\"details\", emit matching containers like <section data-view-panel=\"overview\">...</section>, <section data-view-panel=\"comparison\" hidden>...</section>, and <section data-view-panel=\"details\" hidden>...</section>, keep the literal data-view-panel attribute on those panel elements, and then toggle them through a panels collection like querySelectorAll('[data-view-panel]').\n37) Keep visible markup first: place the script tag after the closing </main> or at the end of <body>, not as a long head script before the surfaced sections.\n38) Prefer dataset comparisons such as panel.dataset.viewPanel !== button.dataset.view instead of building a querySelector string with nested quoted fragments.\n39) Static data-view, aria-controls, or data-target attributes do not satisfy clickable navigation by themselves; wire click or change handlers that toggle hidden, aria-selected, aria-hidden, data-active, or comparable state on the mapped panel wrappers.\n40) Class names like class=\"overview-panel\" or class=\"data-view-panel\" do not establish a mapped panel; put the mapping on the wrapper itself with literal attributes such as id=\"overview-panel\" and data-view-panel=\"overview\".\n41) Apply sequence-browsing requirements only when interactionContract.sequenceBrowsingRequired is true. In that case, expose a visible progression control on first paint such as a stepper, previous/next controls, a scrubber, or a scroll-snap evidence rail. A static chart plus unrelated panel toggles does not satisfy sequence browsing."
}

pub(super) fn chat_artifact_materialization_schema_contract_for_runtime(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> &'static str {
    if renderer == ChatRendererKind::HtmlIframe
        && chat_modal_first_html_enabled()
        && !compact_local_html_materialization_prompt(renderer, runtime_kind)
    {
        return "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string>,\n  \"notes\": [<string>],\n  \"files\": [\n    {\n      \"path\": <string>,\n      \"mime\": <string>,\n      \"role\": \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean>,\n      \"downloadable\": <boolean>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string>\n    }\n  ]\n}\nRules:\n1) Respect the typed renderer exactly.\n2) html_iframe => one self-contained renderable .html file with inline CSS/JS only.\n3) Use standard HTML with <body><main>...</main></body> and meaningful surfaced content.\n4) First paint must already show a complete default state for the chosen interaction grammar.\n5) Choose the interaction model that best fits the request: tabs, toggles, inspectable marks, steppers, scrubbers, sceneboards, inline simulators, annotated diagrams, or another truthful inline state-change pattern.\n6) If view switching is required, switch between authored on-page states, scenes, or sections with a visible state change; mapped panels are allowed but not mandatory.\n7) If detail inspection is required, reveal deeper context inline through captions, annotations, callouts, overlays, drawers, or contextual text; no fixed shared detail panel is required.\n8) If sequence browsing is required, expose a visible progression control on first paint such as previous/next, a stepper, a scrubber, or an evidence rail.\n9) Keep visible content in the raw HTML before scripts run; scripts may change authored state but must not create the only meaningful first-paint content from nothing.\n10) Use inline SVG, canvas, or DOM/CSS with visible labels when the brief calls for diagrams, metrics, or visual evidence.\n11) Interactive explainers must realize each typed required interaction with a meaningful request-grounded state change; decorative toggles are insufficient.\n12) Controls only count when they update labeled evidence, simulation state, comparison state, or explanatory copy tied to the request concepts.\n13) For numeric calculators or simulators, keep number/range/select controls in the markup with truthful default values and update visible results on input/change.\n14) In JavaScript, declare reassigned calculation variables with let, not const; never reassign a const binding.\n15) Establish an intentional visual system with purposeful typography, spacing, contrast, and palette; default browser-body styling or plain white document layouts are not acceptable unless the request explicitly calls for them.\n16) Do not use alert(), dead buttons, submit-nowhere forms, navigation-only controls, placeholder copy, TODO markers, HTML comments, nonexistent DOM ids, or external libraries.\n17) Keep the artifact request-specific, refinement-faithful, and truthful rather than inventing completion.";
    }
    if compact_local_html_materialization_prompt(renderer, runtime_kind) {
        if chat_modal_first_html_enabled() {
            return "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string>,\n  \"notes\": [<string>],\n  \"files\": [\n    {\n      \"path\": <string>,\n      \"mime\": <string>,\n      \"role\": \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean>,\n      \"downloadable\": <boolean>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string>\n    }\n  ]\n}\nRules:\n1) Respect the typed renderer exactly.\n2) html_iframe => one self-contained renderable .html file with inline CSS/JS only.\n3) Use standard HTML with <body><main>...</main></body> and meaningful surfaced content.\n4) First paint must already show a complete default state with visible request-grounded evidence.\n5) Make each typed required interaction produce a meaningful request-grounded state change; one decorative control is not enough.\n6) Controls only count when they update labeled evidence, simulation state, comparison state, or explanatory copy tied to the request.\n7) For numeric calculators or simulators, keep number/range/select controls in the markup with truthful default values and update visible results on input/change.\n8) In JavaScript, declare reassigned calculation variables with let, not const; never reassign a const binding.\n9) Keep visible content in the raw HTML before scripts run; scripts may switch authored state but must not create the only meaningful first-paint content from nothing.\n10) Use inline SVG, canvas, or DOM/CSS with visible labels when the brief calls for diagrams, metrics, or visual evidence.\n11) Keep CSS and JS concise enough to finish the full document in one local-model pass.\n12) Do not use placeholder copy, dead controls, nonexistent DOM ids, HTML comments, or external libraries.";
        }
        return "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string>,\n  \"notes\": [<string>],\n  \"files\": [\n    {\n      \"path\": <string>,\n      \"mime\": <string>,\n      \"role\": \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean>,\n      \"downloadable\": <boolean>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string>\n    }\n  ]\n}\nRules:\n1) Respect the typed renderer exactly.\n2) html_iframe => one self-contained renderable .html file with inline CSS/JS only.\n3) Use standard HTML with <body><main>...</main></body> and at least three sectioning elements inside <main>.\n4) Start the visible composition immediately inside <main>; do not spend most of the response budget on a long style block before the first surfaced section.\n5) First paint must already show a real control set, two populated evidence surfaces, and one shared detail or comparison region.\n6) If the artifact uses buttons, tabs, or chips to switch views, emit at least two pre-rendered mapped panel containers in the raw HTML with literal attributes such as <button data-view=\"overview\" aria-controls=\"overview-panel\"> plus <section id=\"overview-panel\" data-view-panel=\"overview\">...</section> and a second hidden mapped panel.\n7) View-switching controls must toggle those pre-rendered mapped panels through literal attributes such as data-view plus data-view-panel or aria-controls; do not synthesize target ids at runtime, and do not point every control only at one shared detail region.\n8) If rollover detail is required, include visible [data-detail] marks that update the shared detail region on hover/focus, and make every such mark keyboard-focusable with tabindex=\"0\" or a naturally focusable element.\n9) If you include a shared detail, comparison, or explanation region, populate its default state directly in the HTML before any script runs; do not leave it empty on first paint.\n10) Render the default selected view and evidence directly in the HTML before any script runs, with exactly one mapped panel visible when view switching is present.\n11) Keep CSS concise and utility-first so the document can reach a complete closing </main></body></html> within the response budget.\n12) Use inline SVG or DOM/CSS evidence with visible labels; no blank shells, placeholders, HTML comments, TODOs, nonexistent ids, or external libraries.\n13) Do not emit the literal words placeholder, placeholders, TODO, or TBD anywhere in the final HTML, CSS, JavaScript, comments, ids, classes, or visible copy.\n14) Keep the artifact request-specific, refinement-faithful, and truthful rather than inventing completion.";
    }
    chat_artifact_materialization_schema_contract()
}

pub(super) fn chat_artifact_renderer_authoring_guidance_for_runtime(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    candidate_seed: u64,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> String {
    let required_interactions = brief.required_interaction_summaries();
    if request.renderer == ChatRendererKind::HtmlIframe
        && chat_modal_first_html_enabled()
        && !compact_local_html_materialization_prompt(request.renderer, runtime_kind)
    {
        return chat_artifact_renderer_authoring_guidance(request, brief, candidate_seed);
    }
    if compact_local_html_materialization_prompt(request.renderer, runtime_kind) {
        if chat_modal_first_html_enabled() {
            let layout_recipe = match candidate_seed % 3 {
                0 => {
                    "editorial explainer with layered annotations and one decisive interactive seam"
                }
                1 => "scenario-driven workspace with an inline simulator or sceneboard",
                _ => "graphic narrative with inspectable marks and progression cues",
            };
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the typed request concepts",
                4,
            );
            let mut interaction_focus =
                summarized_guidance_terms(&required_interactions, "the required interactions", 3);
            interaction_focus.push_str(
                "; one isolated button or slider does not satisfy an interactive artifact",
            );
            let sequence_browsing_directive = if super::brief_requires_sequence_browsing(brief) {
                " Include a visible progression mechanic such as previous/next, a stepper, a scrubber, or an evidence rail."
            } else {
                ""
            };
            let view_switching_directive = if super::brief_requires_view_switching(brief) {
                " If view switching is part of the brief, switch between authored scenes, states, or sections with a visible on-page change; mapped panels are one valid pattern, not a requirement."
            } else {
                ""
            };
            let rollover_directive = if super::brief_requires_rollover_detail(brief) {
                " If detail inspection is part of the brief, let marks, cards, or inline callouts reveal deeper context without forcing a detached detail aside."
            } else {
                ""
            };
            return format!(
                "- Use the candidate seed to vary this composition recipe: {layout_recipe}.\n- Keep the artifact visibly grounded in these request concepts: {concept_focus}.\n- Make these interaction families tangible on first paint: {interaction_focus}.{sequence_browsing_directive}{view_switching_directive}{rollover_directive}\n- Ship one self-contained .html file with inline CSS/JS, <main>, and meaningful surfaced structure.\n- Open the document body with <main> immediately after <body>, and keep every visible artifact region inside that <main>.\n- First paint should already feel complete and useful, with at least two request-grounded zones of information density.\n- Choose the interaction grammar that best fits the request instead of defaulting to the same layout every time: sceneboard, stepper, scrubber, inspectable diagram, inline simulator, tabset, comparison story, or another truthful pattern are all valid.\n- Do not default to a left sidebar, dashboard shell, or app-style chrome unless the brief explicitly needs navigation.\n- For educational or explanatory briefs, prefer a living model, scenario walkthrough, inspectable diagram, or guided comparison over stacked textbook sections with decorative blocks.\n- Avoid the default classroom explainer pattern of stacked concept cards, repeated paragraph-plus-empty-box sections, or one interchangeable box per concept.\n- If the request is educational, still give it one strong visual metaphor or working interaction seam that makes the page feel authored rather than generic.\n- Make each typed required interaction change visible evidence, result state, or explanation; decorative controls do not satisfy an interactive artifact.\n- Establish a clear visual system with purposeful typography, spacing, contrast, and palette; avoid default browser-white document styling unless the brief explicitly calls for a print-like minimal surface.\n- Render the default state directly in the HTML; scripts may switch, annotate, or simulate authored state but must not create the only meaningful first-paint content from empty shells.\n- Use inline SVG, canvas, or DOM/CSS evidence with visible labels when the brief calls for diagrams, metrics, or comparisons.\n- Keep CSS concise so the response reaches a complete closing </main></body></html> instead of collapsing inside styles.\n- Avoid ornamental scaffolding, decorative gradients, and repeated chrome when they do not help the explanation.\n- Do not emit the literal words placeholder, placeholders, TODO, or TBD anywhere in the final HTML, CSS, JavaScript, comments, ids, classes, or visible copy.\n- No jump-link-only navigation, placeholder media, HTML comments, nonexistent ids, or external libraries.",
            );
        }
        let layout_recipe = match candidate_seed % 3 {
            0 => "story-led hero with a control rail and detail aside",
            1 => "dashboard-led metrics rail with mapped evidence panels",
            _ => "editorial explainer with a stepper-style control row",
        };
        let concept_focus =
            summarized_guidance_terms(&brief.required_concepts, "the typed request concepts", 4);
        let interaction_focus =
            summarized_guidance_terms(&required_interactions, "the required interactions", 3);
        let exact_view_scaffold = super::html_prompt_exact_view_scaffold(brief);
        let two_view_example = super::html_prompt_two_view_example(brief);
        let sequence_browsing_directive = if super::brief_requires_sequence_browsing(brief) {
            " Include a visible previous/next control, stepper, scrubber, or evidence rail for sequence browsing."
        } else {
            ""
        };
        let view_switching_directive = if super::brief_requires_view_switching(brief) {
            format!(
                " If view switching is part of the brief, follow a mapped-panel scaffold such as {}. Pair it with a panels collection like querySelectorAll('[data-view-panel]') and toggle hidden plus aria-selected state on click instead of routing every control only to the shared detail region. A safe visible pairing is {} plus one populated <aside><p id=\"detail-copy\">...</p></aside>.",
                exact_view_scaffold,
                two_view_example
            )
        } else {
            String::new()
        };
        let rollover_directive = if super::brief_requires_rollover_detail(brief) {
            " Use focusable visible [data-detail] marks that update the shared detail panel on hover and focus."
        } else {
            ""
        };
        return format!(
            "- Use the candidate seed to vary this layout recipe: {layout_recipe}.\n- Keep the artifact visibly grounded in these request concepts: {concept_focus}.\n- Make these interaction families tangible on first paint: {interaction_focus}.{sequence_browsing_directive}{view_switching_directive}\n- Ship one self-contained .html file with inline CSS/JS, <main>, and at least three sectioning elements.\n- Open the document body with <main> immediately after <body>, and keep every visible artifact region inside that <main>.\n- Start from a safe minimal scaffold such as <!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>...</title><style>body{{margin:0;font-family:system-ui,sans-serif;background:#0f172a;color:#e5e7eb}}main{{max-width:960px;margin:0 auto;padding:24px}}</style></head><body><main><section>...</section><section>...</section><aside>...</aside></main><script>...</script></body></html>.\n- First paint must include a request-specific hero, a real control bar, two populated evidence surfaces, and one shared detail or comparison aside.\n- Any shared detail, comparison, or explanation region must contain request-grounded default content in the raw HTML before script runs; do not leave it empty until interaction.\n- Keep exactly one mapped panel visible in the raw HTML before script runs; controls should toggle pre-rendered panels or rewrite the shared detail region.\n- Render the default selected view and evidence directly in the HTML; scripts may switch or annotate existing content but must not create the only first-paint content.\n- Use inline SVG or DOM/CSS evidence with visible labels and multiple marks, rows, or items per evidence surface.\n- Keep CSS concise and layout-led so the response reaches a complete closing </main></body></html> instead of ending inside styles.\n- Avoid long decorative token lists, animation scaffolds, or gradient-heavy style systems unless they are essential to the request.\n- Every visible [data-detail] mark should be keyboard-focusable through tabindex=\"0\" or a naturally focusable element such as a button.\n- Do not emit the literal words placeholder, placeholders, TODO, or TBD anywhere in the final HTML, CSS, JavaScript, comments, ids, classes, or visible copy.\n- No jump-link navigation, placeholder media, HTML comments, TODOs, nonexistent ids, or external libraries.{rollover_directive}",
        );
    }

    chat_artifact_renderer_authoring_guidance(request, brief, candidate_seed)
}

pub(super) fn chat_artifact_renderer_authoring_guidance(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    candidate_seed: u64,
) -> String {
    let required_interactions = brief.required_interaction_summaries();
    match request.renderer {
        ChatRendererKind::HtmlIframe => {
            if chat_modal_first_html_enabled() {
                let layout_recipe = match candidate_seed % 3 {
                    0 => {
                        "editorial explainer with layered annotations, one active seam, and a compact evidence rhythm"
                    }
                    1 => {
                        "scenario-driven workspace with a visible simulator state and grounded comparison surfaces"
                    }
                    _ => {
                        "graphic narrative with inspectable marks, progression cues, and restrained utility chrome"
                    }
                };
                let concept_focus = summarized_guidance_terms(
                    &brief.required_concepts,
                    "the typed request concepts",
                    4,
                );
                let interaction_focus = summarized_guidance_terms(
                    &required_interactions,
                    "the required interactions",
                    3,
                );
                let section_blueprint = html_first_paint_section_blueprint(brief);
                let evidence_plan = html_candidate_evidence_plan(brief, candidate_seed);
                let anchor_surface_directive = html_factual_anchor_surface_directive(brief);
                let interaction_distribution_directive =
                    html_interaction_distribution_directive(brief);
                let sequence_browsing_directive = if super::brief_requires_sequence_browsing(brief) {
                    "\n- When the brief implies progression, expose a visible progression control on first paint such as previous/next, a stepper, a scrubber, or an evidence rail."
                        .to_string()
                } else {
                    String::new()
                };
                let rollover_directive = if super::brief_requires_rollover_detail(brief) {
                    "\n- When the brief calls for inspection or hover detail, reveal deeper context inline through annotations, captions, callouts, overlays, drawers, or contextual text. Do not force a detached shared-detail aside unless it genuinely serves the artifact."
                        .to_string()
                } else {
                    String::new()
                };
                let view_switching_directive = if super::brief_requires_view_switching(brief) {
                    "\n- When the brief calls for switching views, move between authored scenes, states, or sections with a visible on-page change. Mapped panels are allowed but not required."
                        .to_string()
                } else {
                    String::new()
                };
                return format!(
                    "- Use the candidate seed to vary composition. This candidate should follow the layout recipe: {layout_recipe}.\n- Build the first paint around this section blueprint: {section_blueprint}.\n{evidence_plan}\n{anchor_surface_directive}\n{interaction_distribution_directive}\n- Derive visible controls, marks, and response regions from these brief concepts: {concept_focus}.\n- Make these required interactions tangible on first paint: {interaction_focus}.\n- Choose the interaction model that best serves the request instead of defaulting to one scaffold: tabs, steppers, sceneboards, inline simulators, inspectable diagrams, annotated cards, timelines, and comparison stories are all valid when they produce a truthful visible state change.\n- Do not default to a left navigation rail, dashboard frame, or generic application shell unless the request explicitly asks for one.\n- For educational or explanatory briefs, prefer a living model, scenario walkthrough, inspectable diagram, or guided comparison over stacked textbook sections with decorative blocks.\n- Keep the hero and primary heading request-specific; synthesize the thesis in your own words instead of pasting artifactThesis verbatim as the headline.\n- Surface every requiredConcept in visible headings, labels, legends, captions, callouts, or evidence notes, not only in the title.\n- Make each sectioning region independently meaningful on first paint: every <section>, <article>, <aside>, or <footer> should contain request-grounded content rather than acting as an empty future mount.\n- Ship interactive regions with actual first-paint content and data. Empty containers or comment-only handlers are not acceptable.\n- Make each typed required interaction change visible evidence, result state, or explanation; decorative controls do not satisfy an interactive artifact.\n- Establish a clear visual system with purposeful typography, spacing, contrast, and palette; avoid default browser-white document styling unless the brief explicitly calls for a print-like minimal surface.\n- Render the default state directly in the HTML markup before the script tag. JavaScript should switch, annotate, scrub, or simulate authored state, not create the only meaningful first-paint content from nothing.\n- Keep visible markup first: place the script after the closing </main> or at the end of <body>, not as a long head script before the surfaced sections.\n- Build charts, diagrams, or explainers with inline SVG, canvas, or DOM/CSS. Do not rely on external libraries, undefined globals, or remote placeholder media.\n- Every chart or diagram must include visible labels, legend text, or accessible labels on first paint. Decorative geometry alone is not enough.{sequence_browsing_directive}{rollover_directive}{view_switching_directive}\n- If you need illustrative values, present them as labeled rollout scenarios or comparative examples rather than fake measured facts.\n- Keep the first visible artifact complete, request-specific, and visually intentional for {}.",
                    brief.audience,
                );
            }
            let requires_rollover_detail = super::brief_requires_rollover_detail(brief);
            let requires_view_switching = super::brief_requires_view_switching(brief);
            let layout_recipe = match candidate_seed % 3 {
                0 => {
                    "story-led hero, sticky section navigation, annotated timeline, and a detail drawer"
                }
                1 => {
                    "dashboard-led metrics rail, scenario controls, comparison cards, and an evidence panel"
                }
                _ => {
                    "editorial sections, guided tutorial stepper, interactive showcase cards, and a feedback summary"
                }
            };
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the typed request concepts",
                4,
            );
            let interaction_focus = summarized_guidance_terms(
                &required_interactions,
                "the required interactions",
                3,
            );
            let section_blueprint = html_first_paint_section_blueprint(brief);
            let evidence_plan = html_candidate_evidence_plan(brief, candidate_seed);
            let anchor_surface_directive = html_factual_anchor_surface_directive(brief);
            let interaction_distribution_directive =
                html_interaction_distribution_directive(brief);
            let sequence_browsing_directive = if super::brief_requires_sequence_browsing(brief) {
                "\n- When a requiredInteraction implies sequence browsing, timeline traversal, or scrolling through staged evidence, give it its own visible progression mechanism on first paint such as a stepper, previous/next controls, a scrubber, or a scroll-snap evidence rail. A static chart plus unrelated panel toggles does not satisfy sequence browsing."
                    .to_string()
            } else {
                String::new()
            };
            let rollover_mark_example = super::html_prompt_rollover_mark_example(brief);
            let exact_view_scaffold = super::html_prompt_exact_view_scaffold(brief);
            let two_view_example = super::html_prompt_two_view_example(brief);
            let rollover_directive = if requires_rollover_detail {
                format!(
                    "\n- When the brief calls for rollover or hover detail, include at least three visible SVG or DOM marks with data-detail text plus mouseenter/focus handlers that rewrite one shared detail panel inline. Give focusable marks tabindex=\"0\" when needed, and wire them with one collection pattern such as querySelectorAll('[data-detail]'). Buttons alone do not satisfy rollover.\n- A concrete rollover mark can look like {}; pair it with one shared detail node such as #detail-copy that the hover/focus handlers rewrite inline.",
                    rollover_mark_example
                )
            } else {
                String::new()
            };
            let combined_interaction_directive =
                if requires_view_switching && requires_rollover_detail {
                format!(
                    "\n- When the brief combines clickable view switching with rollover detail, keep both behaviors in the same artifact: render at least two pre-rendered view panels, keep one panel active on first paint, and also render visible data-detail marks inside the evidence views so the same shared detail panel updates on both button click and mark hover/focus.\n- A strong script shape here is querySelectorAll('button[data-view]') for controls, querySelectorAll('[data-view-panel]') for panels, querySelectorAll('[data-detail]') for marks, and one shared detail node such as #detail-copy that both handlers rewrite inline.\n- A safe exact scaffold is {} plus <aside><p id=\"detail-copy\">{} is selected by default.</p></aside>.\n- Keep data-view-panel as a literal HTML attribute on each panel element; a class token like class=\"data-view-panel\" does not count as a mapped panel.\n- If you use aria-controls, target the enclosing section/article/div panel rather than an inner SVG node or chart mark.\n- If you use Array methods such as find, map, or filter on queried controls or panels, wrap querySelectorAll results with Array.from first instead of calling array-only methods on a NodeList.\n- Keep exactly one mapped panel visible in the raw markup before any script runs; the remaining mapped panels may start hidden.\n- Do not trade one interaction family away while fixing the other.",
                    exact_view_scaffold,
                    brief
                        .factual_anchors
                        .first()
                        .map(|value| value.trim())
                        .filter(|value| !value.is_empty())
                        .unwrap_or("The first evidence view")
                )
                } else {
                    String::new()
                };
            format!(
                "- Use the candidate seed to vary composition. This candidate should follow the layout recipe: {layout_recipe}.\n- Build the first paint around this section blueprint: {section_blueprint}.\n- Build the first paint around a named control bar, a primary evidence region, and a shared detail or comparison panel.\n- A strong HTML pattern here is: request-specific hero section, control nav with real buttons, primary evidence article, secondary evidence article or comparison card, populated detail aside, and a short footer note.\n{evidence_plan}\n{anchor_surface_directive}\n{interaction_distribution_directive}\n- Derive visible controls and response regions from these brief concepts: {concept_focus}.\n- Make these required interactions tangible on first paint: {interaction_focus}.\n- Realize every requiredInteraction with visible controls that change content, result state, revealed detail, or comparison state inline.\n- Include the stateful controls required by the typed brief, and wire them to one visible detail, result, comparison, or explanation region.{sequence_browsing_directive}\n- Keep the hero and primary heading request-specific; synthesize the thesis in your own words instead of pasting artifactThesis verbatim as the headline.\n- Surface every requiredConcept in visible headings, labels, legends, captions, or callouts, not only in the title.\n- Turn factualAnchors and referenceHints into visible annotations, labels, legends, comparison rows, or evidence notes on first paint instead of burying them in generic prose.\n- Avoid the default textbook/tutorial shell of stacked sections that repeat the same copy-plus-box pattern for each concept.\n- Use one decisive visual metaphor, evidence rhythm, or interaction seam so the artifact feels specifically authored for this request rather than like a generic explainer page.\n- Make each sectioning region independently meaningful on first paint: every <section>, <article>, <aside>, or <footer> should contain a heading, body copy, data marks, or detail content rather than acting as an empty wrapper around future script output.\n- Ship interactive regions with actual first-paint content and data. Empty containers or comment-only handlers are not acceptable.\n- Render the default selected chart, label, detail state, and secondary evidence preview directly in the HTML markup before the script tag. JavaScript should switch, annotate, or toggle visible content, not create the only first-paint content from nothing.\n- Keep visible markup first: place the script after the closing </main> or at the end of <body>, not as a long head script before the surfaced sections.\n- Do not rely on DOMContentLoaded, innerHTML, appendChild, createElement, template-string HTML injection, or canvas drawing to create the first visible chart, scorecard, comparison panel, or alternate evidence view from an empty target. Those techniques may enhance an already-populated region, but they must not be the sole first-paint implementation.\n- Prefer pre-rendered evidence articles, comparison cards, legend tables, or detail blocks already present in the DOM. Controls should toggle hidden/data-active/aria-selected state or rewrite one shared detail panel rather than rebuilding the whole view with innerHTML.\n- When the artifact uses view-switching controls, pair them with matching pre-rendered panels already in the DOM, for example {} and a panels collection selected before toggling hidden state.\n- Keep data-view-panel as a literal HTML attribute on each panel element; a class token like class=\"data-view-panel\" does not satisfy the mapping.\n- Prefer dataset comparisons such as panel.dataset.viewPanel !== button.dataset.view instead of building a querySelector string with nested quoted fragments.\n- If you use aria-controls, target the enclosing section/article/div panel rather than an inner SVG node or chart mark.\n- If you use Array methods such as find, map, or filter on queried controls or panels, wrap querySelectorAll results with Array.from first instead of calling array-only methods on a NodeList.\n- Keep exactly one mapped panel visible in the raw markup before any script runs; the remaining mapped panels may start hidden.\n- Do not point every button only at the shared detail panel with aria-controls; the shared detail panel supports the per-view panels and does not replace them.\n- Buttons that only call alert(), submit nowhere, or navigate away do not satisfy requiredInteractions.\n- Do not use fragment-jump anchors as the primary interaction model. Prefer buttons, tabs, or clickable cards that rewrite one shared detail, comparison, or explanation region inline.\n- Build charts, diagrams, or explainers with inline SVG, canvas, or DOM/CSS. Do not rely on external libraries, undefined globals, or remote placeholder media.\n- Prefer inline SVG or DOM/CSS data marks over blank canvas placeholders. If you use canvas, the first paint still needs visible drawn content or an adjacent data fallback.\n- Every chart or diagram must include visible labels, legend text, or accessible labels on first paint. Decorative rings or unlabeled shapes are not enough.\n- When charts, metrics, or data visualizations are part of the brief, first paint must show at least two distinct evidence views or chart families tied to different request concepts. Use one primary visualization with at least three labeled marks plus a second populated evidence region tied to a different brief concept or factual anchor inline. One chart plus generic prose is insufficient.\n- Each visible chart or evidence family should carry multiple request-grounded marks, rows, or milestone steps with labels or captions; a single generic bar or rect does not satisfy a chart-driven brief.\n- A populated secondary evidence surface is not a single sentence paragraph. Use a second SVG, a comparison list or table, or a metric-card rail with at least three labeled items or rows.\n- If a wrapper is labeled or styled as a chart, metric, or evidence panel, populate it with structured evidence rather than overview prose alone.\n- Shared detail updates should surface the underlying metric, milestone, or evidence sentence from the current mark or control, not just echo a raw panel id or button label.{rollover_directive}{combined_interaction_directive}\n- A valid two-view first paint can pair {} Empty mount divs like <div id=\"usage-chart\"></div> do not count as the second evidence view.\n- Keep the non-selected or secondary evidence view visible as a preview, comparison card, secondary article, legend table, or score rail so the artifact reads as multi-view before any click.\n- Never include placeholder comments such as <!-- chart goes here -->, TODO markers, malformed button markup, or references to DOM ids that are not present in the markup.\n- Prefer controls that switch or annotate a shared detail panel, comparison rail, or evidence tray instead of a top-nav list that only scrolls.\n- Each control must map to a pre-rendered view, panel, or detail payload that already exists in the markup; do not wire buttons to nonexistent future containers.\n- If you attach handlers to multiple controls, marks, or cards, select them as a collection such as querySelectorAll before using forEach or similar iteration methods.\n- Make the default selected state complete on first paint so the artifact reads as usable before any click.\n- If the brief requires both view switching and rollover detail, preserve both interaction families through every repair pass instead of rewriting the artifact around only one of them.\n- If you need illustrative values, present them as labeled rollout scenarios or comparative examples rather than fake measured facts.\n- Replace filler testimonials or stock review copy with request-specific notes, observations, or rollout evidence summaries.\n- Include a short usage cue when interactions are not obvious on first paint.\n- Keep the first visible artifact complete and request-specific for {}.",
                exact_view_scaffold,
                two_view_example,
                brief.audience,
            )
        }
        ChatRendererKind::JsxSandbox => {
            let layout_recipe = match candidate_seed % 2 {
                0 => "control panel, primary visualization, and inspectable detail tray",
                _ => "guided flow, scenario switcher, and stateful summary rail",
            };
            format!(
                "- Use the candidate seed to vary component composition. This candidate should follow the layout recipe: {layout_recipe}.\n- Make requiredInteractions visible through real component state, not placeholder handlers.\n- Surface requiredConcepts in labels, headings, and summary copy so the artifact stays request-faithful on first paint."
            )
        }
        ChatRendererKind::Svg => {
            let composition_recipe = match candidate_seed % 2 {
                0 => "layered poster composition with a focal diagram and supporting labels",
                _ => "data-forward composition with a central motif, callout labels, and supporting legends",
            };
            format!(
                "- Use the candidate seed to vary the SVG composition. This candidate should follow the composition recipe: {composition_recipe}.\n- Surface the differentiating request concepts with labels, annotations, and hierarchy instead of a generic decorative shell.\n- Build a full composition, not a title card: use at least six visible SVG content elements drawn from text, path, rect, circle, line, polygon, or comparable marks.\n- Pair the focal motif with supporting labels, callouts, or legend rows that make multiple request concepts readable on first paint.\n- Do not stop at one background shape plus one headline; include layered supporting marks or diagrammatic structure that earns the primary visual view."
            )
        }
        ChatRendererKind::PdfEmbed => {
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the typed request concepts",
                5,
            );
            let anchor_focus = summarized_guidance_terms(
                &brief.factual_anchors,
                "the typed factual anchors",
                4,
            );
            format!(
                "- Treat the PDF body as polished plain document text that Chat will compile into a PDF.\n- Do not emit LaTeX, TeX commands, markdown fences, HTML tags, or any wrapper format; write plain document text only.\n- Write at least 120 words across at least five non-empty sections, separated by blank lines.\n- Use a compact briefing structure with a title, short executive summary, explicit section headings, bullet lists, and a final next-steps or risks block.\n- Include at minimum an executive summary plus three request-grounded body sections and one closing section for next steps, risks, or decisions.\n- Put every section heading on its own short line with no trailing colon, for example Executive Summary, Project Scope, Target Audience, Marketing Strategy, Timeline and Milestones, and Next Steps and Risks.\n- Separate each heading block with a blank line so the rendered PDF keeps visible section breaks.\n- Do not use square-bracket placeholder tokens such as [Detailed description] or [List of objectives]; every bullet and row must contain concrete request-grounded content.\n- Surface these request concepts as named sections, bullets, or metric callouts: {concept_focus}.\n- Turn these factual anchors into labeled bullets, milestone rows, or a compact text table instead of dense prose: {anchor_focus}.\n- Prefer concise bullets, milestone lists, and compact comparison rows over long paragraphs.\n- If the brief asks for charts or graphs, realize them as compact metric tables, milestone grids, or labeled score rows inside the document text instead of promising unavailable graphics."
            )
        }
        ChatRendererKind::DownloadCard => {
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the request-grounded deliverables",
                4,
            );
            format!(
                "- Produce a truthful downloadable bundle with non-empty export files only; do not mark any file renderable.\n- When the request implies a README or notes file, include a non-empty README.md that explains the bundle contents and how each file maps to the request.\n- When the bundle includes a CSV export, give it a header row plus at least two data rows with request-grounded values.\n- Prefer a small bundle with clear filenames, such as README.md plus one or more exports, over placeholder shells.\n- Keep the bundle contents visibly grounded in these request concepts: {concept_focus}."
            )
        }
        _ => "- Keep the artifact request-grounded, complete on first paint, and faithful to the typed brief.".to_string(),
    }
}

pub(super) fn html_candidate_evidence_plan(
    brief: &ChatArtifactBrief,
    candidate_seed: u64,
) -> String {
    let topics = html_brief_evidence_topics(brief);
    let rotated_topics = rotated_guidance_terms(&topics, candidate_seed as usize, 4);
    let primary_focus = rotated_topics
        .first()
        .cloned()
        .unwrap_or_else(|| "the primary rollout evidence".to_string());
    let secondary_focus = rotated_topics
        .get(1)
        .cloned()
        .unwrap_or_else(|| "a supporting comparison topic".to_string());
    let detail_focus = rotated_topics
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let detail_focus = if detail_focus.is_empty() {
        "the brief evidence topics".to_string()
    } else {
        detail_focus
    };
    let control_terms = rotated_guidance_terms(&topics, candidate_seed as usize + 1, 3);
    let control_focus = if control_terms.is_empty() {
        "the brief evidence topics".to_string()
    } else {
        control_terms.join(", ")
    };
    let secondary_surface = match candidate_seed % 3 {
        0 => "comparison article",
        1 => "metric-card rail",
        _ => "score table or evidence list",
    };
    let tertiary_focus = rotated_topics.get(2).cloned();
    let tertiary_control_directive = tertiary_focus
        .as_ref()
        .map(|focus| {
            format!(
                "- Use a third labeled control, tab, or clickable card for {focus} when the brief exposes three or more evidence topics, and keep that topic visible as a preview, secondary panel, or detail payload instead of dropping it entirely."
            )
        })
        .unwrap_or_default();
    let combined_interaction_directive = if super::brief_requires_view_switching(brief)
        && super::brief_requires_rollover_detail(brief)
    {
        if chat_modal_first_html_enabled() {
            "- Keep the interaction model combined on first paint: view-switching should move between authored scenes or states, and visible inspectable marks should reveal deeper context inline without collapsing the whole artifact into one repeated control row."
                .to_string()
        } else {
            "- Keep the interaction model combined on first paint: buttons or tabs should switch pre-rendered [data-view-panel] views, and visible [data-detail] marks inside those views should update the same shared detail panel on hover or focus."
                .to_string()
        }
    } else {
        String::new()
    };

    if chat_modal_first_html_enabled() {
        return format!(
            "- Ground this candidate in a concrete evidence plan: primary evidence on {primary_focus}; secondary evidence on {secondary_focus}; inline explanation anchored in {detail_focus}.\n- Use visible control labels, section headings, legends, or comparison labels derived from these brief topics: {control_focus}.\n- Keep both the primary evidence view and a populated {secondary_surface} visible on first paint so the artifact reads as multi-view before any click.\n- Make the primary evidence view an inline SVG or DOM data-mark visualization for {primary_focus}. Use a separate populated {secondary_surface} for {secondary_focus}; it may be a second SVG, annotated comparison list, metric card grid, or score table, but it must stay visible on first paint.\n- Do not satisfy the secondary evidence surface with a bare paragraph. Use structured evidence such as multiple labeled rows, comparison bullets, metric cards, or a second SVG tied to {secondary_focus}.\n- Let captions, callouts, overlays, or nearby contextual copy explain {detail_focus} when buttons, cards, marks, or progression controls are activated.\n- If clickable navigation helps, move between authored scenes, states, or sections already present in the markup; do not default to the same detached detail-panel scaffold unless the request truly benefits from it.\n{combined_interaction_directive}\n{tertiary_control_directive}",
        );
    }

    format!(
        "- Ground this candidate in a concrete evidence plan: primary evidence on {primary_focus}; secondary evidence on {secondary_focus}; shared detail anchored in {detail_focus}.\n- Use visible control labels, section headings, legends, or comparison labels derived from these brief topics: {control_focus}.\n- Keep both the primary evidence view and a populated {secondary_surface} visible on first paint so the artifact reads as multi-view before any click.\n- Make the primary evidence view an inline SVG or DOM data-mark visualization for {primary_focus}. Use a separate populated {secondary_surface} for {secondary_focus}; it may be a second SVG, annotated comparison list, metric card grid, or score table, but it must stay visible on first paint.\n- Do not satisfy the secondary evidence surface with a bare paragraph. Use structured evidence such as multiple labeled rows, comparison bullets, metric cards, or a second SVG tied to {secondary_focus}.\n- Let the shared detail panel compare or explain {detail_focus} and update inline when buttons, cards, or marks are activated.\n- For clickable navigation, use explicit static mappings that point at pre-rendered panel ids already present in the markup. A safe pattern is {}. Keep data-view-panel as a literal HTML attribute on the panel element itself; a class token like class=\"data-view-panel\" does not satisfy the mapping. Toggle hidden, data-active, or aria-selected state instead of synthesizing target ids with string concatenation at runtime.\n- Static data-view, aria-controls, or data-target attributes do not count on their own; wire click handlers that toggle hidden, aria-selected, aria-hidden, data-active, or comparable state on the mapped panel wrappers.\n- Do not use class names like class=\"overview-panel\" or class=\"data-view-panel\" as a substitute for literal id/data-view-panel attributes on the panel wrapper.\n{combined_interaction_directive}\n{tertiary_control_directive}",
        super::html_prompt_view_mapping_pattern(brief),
    )
}

pub(super) fn html_factual_anchor_surface_directive(brief: &ChatArtifactBrief) -> String {
    let anchors = brief
        .factual_anchors
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if anchors.is_empty() {
        return String::new();
    }

    let mut directives = vec![format!(
        "- Dedicate a first-paint evidence surface directly to this factual anchor: {}. Make that anchor inspectable through visible labels, marks, annotations, captions, or comparison rows instead of generic overview prose.",
        anchors[0]
    )];
    if let Some(second_anchor) = anchors.get(1) {
        directives.push(format!(
            "- Dedicate a second named evidence surface or comparison rail directly to this factual anchor: {}. Keep that surface visible on first paint as a preview, metric rail, comparison article, or secondary evidence panel rather than collapsing it into one generic summary block.",
            second_anchor
        ));
    }
    if let Some(reference_hint) = brief
        .reference_hints
        .iter()
        .map(|item| item.trim())
        .find(|item| !item.is_empty())
    {
        directives.push(format!(
            "- Use supporting reference context like {} as annotations, comparative callouts, or provenance notes, but do not let it replace the top factual anchors as the main evidence surfaces.",
            reference_hint
        ));
    }

    directives.join("\n")
}

pub(super) fn html_interaction_distribution_directive(brief: &ChatArtifactBrief) -> String {
    let required_interactions = brief.required_interaction_summaries();
    let interactions = required_interactions
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if interactions.len() < 2 {
        return String::new();
    }

    format!(
        "- This brief carries multiple interaction demands ({}) so distribute them across the artifact: keep one explicit control-bar interaction, plus at least one in-evidence inspection or input behavior on visible marks, cards, chips, form fields, or list items. Do not collapse every interaction into the same button row or a single generic panel toggle.",
        interactions.join(", ")
    )
}

pub(super) fn html_brief_evidence_topics(brief: &ChatArtifactBrief) -> Vec<String> {
    let mut topics = Vec::<String>::new();
    let mut seen = HashSet::<String>::new();

    for collection in [
        &brief.factual_anchors,
        &brief.required_concepts,
        &brief.reference_hints,
    ] {
        for item in collection {
            for fragment in item
                .split(|ch| matches!(ch, ',' | ';' | '\n'))
                .map(str::trim)
                .filter(|fragment| !fragment.is_empty())
            {
                let key = fragment.to_ascii_lowercase();
                if seen.insert(key) {
                    topics.push(fragment.to_string());
                }
            }
        }
    }

    topics
}

pub(super) fn rotated_guidance_terms(
    topics: &[String],
    offset: usize,
    count: usize,
) -> Vec<String> {
    if topics.is_empty() || count == 0 {
        return Vec::new();
    }

    let start = offset % topics.len();
    (0..topics.len())
        .map(|index| topics[(start + index) % topics.len()].clone())
        .take(count.min(topics.len()))
        .collect()
}
