use super::*;

pub(super) fn compact_local_html_refinement_context_focus(
    refinement: Option<&ChatArtifactRefinementContext>,
) -> serde_json::Value {
    let Some(refinement) = refinement else {
        return serde_json::Value::Null;
    };

    json!({
        "artifactId": refinement.artifact_id,
        "revisionId": refinement.revision_id,
        "title": truncate_materialization_focus_text(&refinement.title, 120),
        "summary": truncate_materialization_focus_text(&refinement.summary, 200),
        "renderer": refinement.renderer,
        "files": refinement
            .files
            .iter()
            .take(2)
            .map(|file| {
                json!({
                    "path": file.path,
                    "mime": file.mime,
                    "role": file.role,
                    "renderable": file.renderable,
                    "downloadable": file.downloadable,
                    "bodyChars": file.body.chars().count(),
                    "lineCount": file.body.lines().count(),
                })
            })
            .collect::<Vec<_>>(),
        "selectedTargets": refinement
            .selected_targets
            .iter()
            .take(3)
            .map(|target| {
                json!({
                    "sourceSurface": target.source_surface,
                    "path": target.path,
                    "label": truncate_materialization_focus_text(&target.label, 80),
                    "snippet": truncate_materialization_focus_text(&target.snippet, 160),
                })
            })
            .collect::<Vec<_>>(),
    })
}

pub(super) fn compact_local_html_refinement_candidate_focus(
    candidate: &ChatGeneratedArtifactPayload,
) -> serde_json::Value {
    json!({
        "summary": truncate_materialization_focus_text(&candidate.summary, 160),
        "notes": candidate
            .notes
            .iter()
            .take(2)
            .map(|note| truncate_materialization_focus_text(note, 160))
            .collect::<Vec<_>>(),
        "files": candidate
            .files
            .iter()
            .take(2)
            .map(|file| {
                json!({
                    "path": file.path,
                    "mime": file.mime,
                    "role": file.role,
                    "renderable": file.renderable,
                    "downloadable": file.downloadable,
                    "encoding": file.encoding,
                    "bodyChars": file.body.chars().count(),
                    "lineCount": file.body.lines().count(),
                    "bodyPreview": truncate_materialization_focus_text(&file.body, 1200),
                })
            })
            .collect::<Vec<_>>(),
    })
}

pub(super) fn compact_local_html_refinement_validation_focus(
    validation: &ChatArtifactValidationResult,
) -> serde_json::Value {
    json!({
        "classification": validation.classification,
        "requestFaithfulness": validation.request_faithfulness,
        "conceptCoverage": validation.concept_coverage,
        "interactionRelevance": validation.interaction_relevance,
        "layoutCoherence": validation.layout_coherence,
        "visualHierarchy": validation.visual_hierarchy,
        "completeness": validation.completeness,
        "issueClasses": validation
            .issue_classes
            .iter()
            .take(3)
            .map(|item| truncate_materialization_focus_text(item, 80))
            .collect::<Vec<_>>(),
        "repairHints": validation
            .repair_hints
            .iter()
            .take(3)
            .map(|item| truncate_materialization_focus_text(item, 120))
            .collect::<Vec<_>>(),
        "strengths": validation
            .strengths
            .iter()
            .take(2)
            .map(|item| truncate_materialization_focus_text(item, 120))
            .collect::<Vec<_>>(),
        "fileFindings": validation
            .file_findings
            .iter()
            .take(2)
            .map(|item| truncate_materialization_focus_text(item, 140))
            .collect::<Vec<_>>(),
        "recommendedNextPass": validation.recommended_next_pass,
        "strongestContradiction": validation
            .strongest_contradiction
            .as_ref()
            .map(|value| truncate_materialization_focus_text(value, 140)),
        "rationale": truncate_materialization_focus_text(&validation.rationale, 160),
    })
}

pub(super) fn extract_html_swarm_region_body(body: &str, region_id: &str) -> Option<String> {
    for candidate in html_swarm_region_id_variants(region_id) {
        let start_marker = html_swarm_region_marker_start(&candidate);
        let end_marker = html_swarm_region_marker_end(&candidate);
        let Some(start_index) = body.find(&start_marker) else {
            continue;
        };
        let content_start = start_index + start_marker.len();
        let relative_end_index = body[content_start..].find(&end_marker)?;
        let end_index = content_start + relative_end_index;
        return Some(body[content_start..end_index].trim().to_string());
    }
    None
}

pub(super) fn extract_html_attribute_values(
    raw: &str,
    attribute: &str,
    split_whitespace: bool,
    max_items: usize,
) -> Vec<String> {
    let needle = format!("{attribute}=\"");
    let mut values = Vec::new();
    let mut search_start = 0usize;
    while values.len() < max_items {
        let Some(relative_start) = raw[search_start..].find(&needle) else {
            break;
        };
        let value_start = search_start + relative_start + needle.len();
        let Some(relative_end) = raw[value_start..].find('"') else {
            break;
        };
        let value_end = value_start + relative_end;
        let value = raw[value_start..value_end].trim();
        if !value.is_empty() {
            if split_whitespace {
                for item in value.split_whitespace() {
                    let item = item.trim();
                    if item.is_empty() || values.iter().any(|existing| existing == item) {
                        continue;
                    }
                    values.push(item.to_string());
                    if values.len() >= max_items {
                        break;
                    }
                }
            } else if !values.iter().any(|existing| existing == value) {
                values.push(value.to_string());
            }
        }
        search_start = value_end.saturating_add(1);
    }
    values
}

pub(super) fn compact_local_html_dom_selector_hints(body: &str, max_items: usize) -> Vec<String> {
    let class_budget = max_items.min(8);
    let id_budget = max_items.min(6);
    let mut hints = Vec::<String>::new();

    for class_name in extract_html_attribute_values(body, "class", true, class_budget) {
        let selector = format!(".{class_name}");
        if !hints.iter().any(|existing| existing == &selector) {
            hints.push(selector);
        }
        if hints.len() >= max_items {
            return hints;
        }
    }
    for id in extract_html_attribute_values(body, "id", false, id_budget) {
        let selector = format!("#{id}");
        if !hints.iter().any(|existing| existing == &selector) {
            hints.push(selector);
        }
        if hints.len() >= max_items {
            return hints;
        }
    }
    let mut search_start = 0usize;
    while hints.len() < max_items {
        let Some(relative_attr_start) = body[search_start..].find("data-") else {
            break;
        };
        let attr_start = search_start + relative_attr_start;
        let Some(relative_equals) = body[attr_start..].find("=\"") else {
            break;
        };
        let attr_end = attr_start + relative_equals;
        let attr = body[attr_start..attr_end].trim();
        if attr.is_empty() || attr.contains(char::is_whitespace) {
            search_start = attr_end.saturating_add(1);
            continue;
        }
        let value_start = attr_end + 2;
        let Some(relative_value_end) = body[value_start..].find('"') else {
            break;
        };
        let value_end = value_start + relative_value_end;
        let value = body[value_start..value_end].trim();
        if !value.is_empty() {
            let selector = format!("[{attr}=\"{value}\"]");
            if !hints.iter().any(|existing| existing == &selector) {
                hints.push(selector);
            }
        }
        search_start = value_end.saturating_add(1);
    }

    hints
}

pub(super) fn compact_local_html_swarm_payload_focus(
    payload: &ChatGeneratedArtifactPayload,
    work_item: &ChatArtifactWorkItem,
) -> serde_json::Value {
    let body_preview_chars = match work_item.role {
        ChatArtifactWorkerRole::SectionContent => 0,
        ChatArtifactWorkerRole::StyleSystem | ChatArtifactWorkerRole::Interaction => 220,
        ChatArtifactWorkerRole::Integrator => 900,
        ChatArtifactWorkerRole::Repair => 280,
        _ => 520,
    };
    let owned_region_preview_chars = match work_item.role {
        ChatArtifactWorkerRole::SectionContent => 220,
        ChatArtifactWorkerRole::StyleSystem | ChatArtifactWorkerRole::Interaction => 420,
        ChatArtifactWorkerRole::Integrator => 1200,
        ChatArtifactWorkerRole::Repair => 360,
        _ => 520,
    };
    let owned_region_limit = match work_item.role {
        ChatArtifactWorkerRole::Repair => 3,
        _ => usize::MAX,
    };
    let owned_regions = payload
        .files
        .iter()
        .find(|file| file.path == "index.html")
        .map(|file| {
            work_item
                .write_regions
                .iter()
                .take(owned_region_limit)
                .map(|region_id| {
                    json!({
                        "regionId": region_id,
                        "bodyPreview": extract_html_swarm_region_body(&file.body, region_id)
                            .map(|body| truncate_materialization_focus_text(&body, owned_region_preview_chars))
                            .unwrap_or_default(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let dom_selector_hints = payload
        .files
        .iter()
        .find(|file| file.path == "index.html")
        .map(|file| {
            let selector_limit = match work_item.role {
                ChatArtifactWorkerRole::StyleSystem | ChatArtifactWorkerRole::Interaction => 14,
                ChatArtifactWorkerRole::Integrator => 18,
                ChatArtifactWorkerRole::Repair => 12,
                _ => 8,
            };
            compact_local_html_dom_selector_hints(&file.body, selector_limit)
        })
        .unwrap_or_default();

    json!({
        "summary": truncate_materialization_focus_text(&payload.summary, 160),
        "notes": payload
            .notes
            .iter()
            .take(3)
            .map(|note| truncate_materialization_focus_text(note, 120))
            .collect::<Vec<_>>(),
        "files": payload
            .files
            .iter()
            .take(2)
            .map(|file| {
                json!({
                    "path": file.path,
                    "mime": file.mime,
                    "role": file.role,
                    "renderable": file.renderable,
                    "downloadable": file.downloadable,
                    "encoding": file.encoding,
                    "bodyChars": file.body.chars().count(),
                    "lineCount": file.body.lines().count(),
                    "bodyPreview": if body_preview_chars == 0 {
                        String::new()
                    } else {
                        truncate_materialization_focus_text(&file.body, body_preview_chars)
                    },
                })
            })
            .collect::<Vec<_>>(),
        "ownedRegions": owned_regions,
        "domSelectorHints": dom_selector_hints,
    })
}

pub(super) fn compact_local_html_swarm_work_item_focus(
    work_item: &ChatArtifactWorkItem,
) -> serde_json::Value {
    json!({
        "id": work_item.id,
        "role": work_item.role,
        "summary": truncate_materialization_focus_text(&work_item.summary, 140),
        "spawnedFromId": work_item.spawned_from_id,
        "writePaths": work_item.write_paths.iter().take(2).collect::<Vec<_>>(),
        "writeRegions": work_item.write_regions.iter().take(4).collect::<Vec<_>>(),
        "leaseRequirements": work_item
            .lease_requirements
            .iter()
            .take(4)
            .map(|lease| {
                json!({
                    "target": lease.target,
                    "scopeKind": lease.scope_kind,
                    "mode": lease.mode,
                })
            })
            .collect::<Vec<_>>(),
        "acceptanceCriteria": work_item
            .acceptance_criteria
            .iter()
            .take(4)
            .map(|item| truncate_materialization_focus_text(item, 100))
            .collect::<Vec<_>>(),
        "dependencyIds": work_item.dependency_ids.iter().take(4).collect::<Vec<_>>(),
        "blockedOnIds": work_item.blocked_on_ids.iter().take(4).collect::<Vec<_>>(),
        "verificationPolicy": work_item.verification_policy,
        "retryBudget": work_item.retry_budget,
    })
}

pub(super) fn json_array_string_focus(
    value: Option<&serde_json::Value>,
    max_items: usize,
    max_chars: usize,
) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(max_items)
                .filter_map(serde_json::Value::as_str)
                .map(|item| truncate_materialization_focus_text(item, max_chars))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(super) fn compact_local_html_swarm_worker_context_focus(
    work_item: &ChatArtifactWorkItem,
    worker_context: &serde_json::Value,
) -> serde_json::Value {
    match work_item.role {
        ChatArtifactWorkerRole::SectionContent => {
            let section = worker_context.get("section");
            json!({
                "targetRegion": worker_context
                    .get("targetRegion")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
                "section": {
                    "id": section
                        .and_then(|value| value.get("id"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default(),
                    "role": section
                        .and_then(|value| value.get("role"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default(),
                    "visiblePurpose": section
                        .and_then(|value| value.get("visiblePurpose"))
                        .and_then(serde_json::Value::as_str)
                        .map(|value| truncate_materialization_focus_text(value, 160))
                        .unwrap_or_default(),
                    "contentRequirements": json_array_string_focus(
                        section.and_then(|value| value.get("contentRequirements")),
                        4,
                        100,
                    ),
                    "interactionHooks": json_array_string_focus(
                        section.and_then(|value| value.get("interactionHooks")),
                        3,
                        90,
                    ),
                    "firstPaintRequirements": json_array_string_focus(
                        section.and_then(|value| value.get("firstPaintRequirements")),
                        4,
                        100,
                    ),
                },
            })
        }
        ChatArtifactWorkerRole::StyleSystem => json!({
            "designTokens": json_array_string_focus(
                worker_context.get("designTokens"),
                5,
                72,
            ),
            "colorStrategy": worker_context
                .get("colorStrategy")
                .and_then(serde_json::Value::as_str)
                .map(|value| truncate_materialization_focus_text(value, 120))
                .unwrap_or_default(),
            "density": worker_context
                .get("density")
                .and_then(serde_json::Value::as_str)
                .map(|value| truncate_materialization_focus_text(value, 80))
                .unwrap_or_default(),
        }),
        ChatArtifactWorkerRole::Interaction => json!({
            "interactionPlan": json_array_string_focus(
                worker_context.get("interactionPlan"),
                4,
                120,
            ),
            "interactionGraph": worker_context
                .get("interactionGraph")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        }),
        ChatArtifactWorkerRole::Integrator => json!({
            "sectionPlan": worker_context
                .get("sectionPlan")
                .and_then(serde_json::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(4)
                        .map(|section| {
                            json!({
                                "id": section.get("id").and_then(serde_json::Value::as_str).unwrap_or_default(),
                                "role": section.get("role").and_then(serde_json::Value::as_str).unwrap_or_default(),
                                "visiblePurpose": section
                                    .get("visiblePurpose")
                                    .and_then(serde_json::Value::as_str)
                                    .map(|value| truncate_materialization_focus_text(value, 140))
                                    .unwrap_or_default(),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            "interactionPlan": json_array_string_focus(
                worker_context.get("interactionPlan"),
                4,
                120,
            ),
            "validation": worker_context.get("validation").cloned().unwrap_or(serde_json::Value::Null),
        }),
        ChatArtifactWorkerRole::Repair => json!({
            "sectionPlan": worker_context
                .get("sectionPlan")
                .and_then(serde_json::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(3)
                        .map(|section| {
                            json!({
                                "id": section.get("id").and_then(serde_json::Value::as_str).unwrap_or_default(),
                                "role": section.get("role").and_then(serde_json::Value::as_str).unwrap_or_default(),
                                "visiblePurpose": section
                                    .get("visiblePurpose")
                                    .and_then(serde_json::Value::as_str)
                                    .map(|value| truncate_materialization_focus_text(value, 96))
                                    .unwrap_or_default(),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            "interactionPlan": json_array_string_focus(
                worker_context.get("interactionPlan"),
                2,
                96,
            ),
            "validation": compact_local_html_refinement_validation_focus(
                &serde_json::from_value::<ChatArtifactValidationResult>(
                    worker_context.get("validation").cloned().unwrap_or(serde_json::Value::Null),
                )
                .unwrap_or_else(|_| blocked_candidate_generation_validation("Repair context validation summary unavailable.")),
            ),
        }),
        _ => worker_context.clone(),
    }
}

pub(super) fn compact_local_html_swarm_renderer_guidance(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    work_item: &ChatArtifactWorkItem,
    candidate_seed: u64,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> String {
    match work_item.role {
        ChatArtifactWorkerRole::Skeleton => {
            "- Emit only a compact semantic HTML shell with region markers.\n- Keep copy terse and structural so later workers can own the real explanation.\n- Keep the index.html body compact and mostly single-line inside the JSON string so the patch envelope stays easy to parse.\n- Reserve the style-system and interaction regions without authoring real CSS rules or script logic.\n- Use short section wrappers with headings or stub labels only; do not author the finished visual system, simulator, or long explanatory prose in this step.".to_string()
        }
        ChatArtifactWorkerRole::SectionContent => {
            let target_region = work_item.write_regions.first().cloned().unwrap_or_default();
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the request concepts",
                3,
            );
            let interaction_focus = summarized_guidance_terms(
                &brief.required_interaction_summaries(),
                "the required interactions",
                2,
            );
            format!(
                "- Author only the semantic block inside {target_region}.\n- Make the section immediately useful on first paint with request-grounded explanation, labels, and concrete content.\n- Keep this section faithful to {concept_focus}.\n- If this section needs interaction, make it visibly tied to {interaction_focus} without rewriting the whole page.\n- Do not emit <style>, <script>, a duplicate page shell, or another hero unless the section purpose explicitly requires it.\n- Prefer one strong visual metaphor, diagram, comparison, or explainer block over stacked filler cards."
            )
        }
        ChatArtifactWorkerRole::StyleSystem => {
            "- Author CSS only.\n- Favor slate and graphite neutrals, dense readability, subtle borders, and one restrained cool accent.\n- Ground every selector to classes, ids, or data-* hooks already present in the current canonical artifact focus.\n- Do not invent parallel wrapper selectors, generic utility shells, or styles for classes/ids that are absent from the current artifact.\n- Improve hierarchy and spacing without changing copy or DOM structure.".to_string()
        }
        ChatArtifactWorkerRole::Interaction => {
            "- Author one compact inline script only.\n- Bind existing controls to visible on-page state changes.\n- Reference only classes, ids, and data-* hooks that already exist in the current canonical artifact focus.\n- Verify every selector you use resolves against the authored DOM; do not invent dead panel mappings or nonexistent targets.\n- Do not create the first meaningful content from script or rely on hidden panels as the main artifact.".to_string()
        }
        ChatArtifactWorkerRole::Integrator => {
            "- Repair only cross-section seams in the current merged artifact.\n- Preserve strong authored sections and avoid global rewrites.\n- Reuse the selectors, ids, and section structure already present in the canonical artifact instead of inventing a parallel shell.\n- Make the page feel like one coherent artifact, not multiple stitched drafts.".to_string()
        }
        ChatArtifactWorkerRole::Repair => {
            "- Patch only the cited failures in the current artifact.\n- Preserve strong authored content and avoid restarting from scratch.\n- Reuse selectors and structure already present in the canonical artifact whenever possible.\n- Prefer the smallest truthful change that fixes the blocked outcome.".to_string()
        }
        _ => chat_artifact_renderer_authoring_guidance_for_runtime(
            request,
            brief,
            candidate_seed,
            runtime_kind,
        ),
    }
}

pub(super) fn compact_local_html_swarm_skill_focus(
    selected_skills: &[ChatArtifactSelectedSkill],
) -> serde_json::Value {
    json!(selected_skills
        .iter()
        .take(2)
        .map(|skill| {
            json!({
                "name": skill.name,
                "matchedNeedKinds": skill.matched_need_kinds,
                "matchRationale": truncate_materialization_focus_text(
                    &skill.match_rationale,
                    120,
                ),
            })
        })
        .collect::<Vec<_>>())
}

pub(super) fn compact_local_html_swarm_exemplar_focus(
    exemplars: &[ChatArtifactExemplar],
) -> serde_json::Value {
    json!(exemplars
        .iter()
        .take(2)
        .map(|exemplar| {
            json!({
                "title": exemplar.title,
                "summary": truncate_materialization_focus_text(&exemplar.summary, 120),
                "scaffoldFamily": exemplar.scaffold_family,
                "designCues": exemplar.design_cues.iter().take(3).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>())
}

pub(super) fn compact_local_html_directives_text(directives: &str) -> String {
    directives
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(10)
        .map(|line| truncate_materialization_focus_text(line, 200))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn compact_local_html_materialization_repair_candidate_focus(
    raw_output: &str,
    request: &ChatOutcomeArtifactRequest,
) -> serde_json::Value {
    match super::parse_chat_generated_artifact_payload(raw_output) {
        Ok(mut candidate) => {
            super::normalize_generated_artifact_payload(&mut candidate, request);
            compact_local_html_refinement_candidate_focus(&candidate)
        }
        Err(_) => json!({
            "rawOutputPreview": truncate_candidate_failure_preview(raw_output, 1600),
        }),
    }
}
