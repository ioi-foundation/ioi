use super::*;

fn studio_judge_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_STUDIO_PROOF_TRACE").is_some() {
        eprintln!("[studio-proof-trace] {}", message.as_ref());
    }
}

fn renderer_uses_document_judge_context(renderer: StudioRendererKind) -> bool {
    matches!(
        renderer,
        StudioRendererKind::Markdown
            | StudioRendererKind::Mermaid
            | StudioRendererKind::PdfEmbed
            | StudioRendererKind::DownloadCard
            | StudioRendererKind::BundleManifest
    )
}

fn compact_studio_judge_json<T: serde::Serialize>(
    value: &T,
    label: &str,
) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| format!("Failed to serialize {label}: {error}"))
}

fn studio_artifact_judge_request_focus(
    request: &StudioOutcomeArtifactRequest,
) -> serde_json::Value {
    json!({
        "artifactClass": request.artifact_class,
        "deliverableShape": request.deliverable_shape,
        "renderer": request.renderer,
        "presentationSurface": request.presentation_surface,
        "persistence": request.persistence,
        "executionSubstrate": request.execution_substrate,
        "scope": {
            "createNewWorkspace": request.scope.create_new_workspace,
            "mutationBoundary": request.scope.mutation_boundary,
        },
        "verification": {
            "requireRender": request.verification.require_render,
            "requireBuild": request.verification.require_build,
            "requirePreview": request.verification.require_preview,
            "requireExport": request.verification.require_export,
            "requireDiffReview": request.verification.require_diff_review,
        },
    })
}

fn studio_artifact_judge_brief_focus(brief: &StudioArtifactBrief) -> serde_json::Value {
    json!({
        "audience": brief.audience,
        "jobToBeDone": brief.job_to_be_done,
        "subjectDomain": brief.subject_domain,
        "artifactThesis": brief.artifact_thesis,
        "requiredConcepts": brief.required_concepts,
        "requiredInteractions": brief.required_interactions,
        "visualTone": brief.visual_tone,
        "factualAnchors": brief.factual_anchors,
        "styleDirectives": brief.style_directives,
        "referenceHints": brief.reference_hints,
    })
}

fn studio_artifact_judge_edit_focus(
    edit_intent: Option<&StudioArtifactEditIntent>,
) -> serde_json::Value {
    match edit_intent {
        Some(intent) => json!({
            "mode": intent.mode,
            "patchExistingArtifact": intent.patch_existing_artifact,
            "preserveStructure": intent.preserve_structure,
            "targetScope": intent.target_scope,
            "targetPaths": intent.target_paths,
            "requestedOperations": intent.requested_operations,
            "toneDirectives": intent.tone_directives,
            "styleDirectives": intent.style_directives,
            "selectedTargets": intent.selected_targets,
            "branchRequested": intent.branch_requested,
        }),
        None => serde_json::Value::Null,
    }
}

pub async fn judge_studio_artifact_candidate_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate: &StudioGeneratedArtifactPayload,
) -> Result<StudioArtifactJudgeResult, String> {
    let runtime_provenance = runtime.studio_runtime_provenance();
    studio_judge_trace(format!(
        "artifact_judge:start renderer={:?} runtime={} model={:?}",
        request.renderer, runtime_provenance.label, runtime_provenance.model
    ));
    let payload =
        build_studio_artifact_judge_prompt(title, request, brief, edit_intent, candidate)?;
    let input = serde_json::to_vec(&payload)
        .map_err(|error| format!("Failed to encode Studio artifact judge prompt: {error}"))?;
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: judge_max_tokens(request.renderer),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| format!("Studio artifact judge inference failed: {error}"))?;
    studio_judge_trace(format!(
        "artifact_judge:raw_ok runtime={} bytes={}",
        runtime_provenance.label,
        output.len()
    ));
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Studio artifact judge utf8 decode failed: {error}"))?;
    match parse_studio_artifact_judge_result(&raw) {
        Ok(result) => {
            studio_judge_trace(format!(
                "artifact_judge:parse_ok runtime={} classification={:?}",
                runtime_provenance.label, result.classification
            ));
            Ok(super::enforce_renderer_judge_contract(
                request, brief, candidate, result,
            ))
        }
        Err(first_error) => {
            studio_judge_trace(format!(
                "artifact_judge:repair:start runtime={} error={}",
                runtime_provenance.label, first_error
            ));
            let repair_payload = build_studio_artifact_judge_repair_prompt(
                title,
                request,
                brief,
                edit_intent,
                candidate,
                &raw,
                &first_error,
            )?;
            let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                format!("Failed to encode Studio artifact judge repair prompt: {error}")
            })?;
            let repair_output = runtime
                .execute_inference(
                    [0u8; 32],
                    &repair_input,
                    InferenceOptions {
                        temperature: 0.0,
                        json_mode: true,
                        max_tokens: judge_repair_max_tokens(request.renderer),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| {
                    format!("{first_error}; judge repair inference failed: {error}")
                })?;
            studio_judge_trace(format!(
                "artifact_judge:repair:raw_ok runtime={} bytes={}",
                runtime_provenance.label,
                repair_output.len()
            ));
            let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                format!("{first_error}; judge repair utf8 decode failed: {error}")
            })?;
            parse_studio_artifact_judge_result(&repair_raw)
                .map(|result| {
                    studio_judge_trace(format!(
                        "artifact_judge:repair:parse_ok runtime={} classification={:?}",
                        runtime_provenance.label, result.classification
                    ));
                    super::enforce_renderer_judge_contract(request, brief, candidate, result)
                })
                .map_err(|repair_error| {
                    format!("{first_error}; judge repair attempt also failed: {repair_error}")
                })
        }
    }
}

pub fn build_studio_artifact_judge_prompt(
    title: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate: &StudioGeneratedArtifactPayload,
) -> Result<serde_json::Value, String> {
    let candidate_json = compact_studio_judge_json(
        &studio_artifact_judge_candidate_view(candidate),
        "Studio artifact candidate",
    )?;
    let schema_contract = studio_artifact_judge_schema_contract(request.renderer);
    let brief_focus_json = compact_studio_judge_json(
        &studio_artifact_judge_brief_focus(brief),
        "Studio artifact brief focus",
    )?;
    if renderer_uses_document_judge_context(request.renderer) {
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact judge. Judge only the candidate files and the typed brief. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nBrief focus JSON:\n{}\n\nCandidate JSON:\n{}\n\n{}",
                    title,
                    brief_focus_json,
                    candidate_json,
                    schema_contract,
                )
            }
        ]));
    }

    let request_focus_json = compact_studio_judge_json(
        &studio_artifact_judge_request_focus(request),
        "Studio artifact request focus",
    )?;
    let interaction_contract_json = compact_studio_judge_json(
        &super::studio_artifact_interaction_contract(brief),
        "Studio interaction contract",
    )?;
    let edit_focus_json = compact_studio_judge_json(
        &studio_artifact_judge_edit_focus(edit_intent),
        "Studio artifact edit intent focus",
    )?;
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact judge. Judge only the candidate files and the typed brief. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest focus JSON:\n{}\n\nBrief focus JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent focus JSON:\n{}\n\nCandidate JSON:\n{}\n\n{}",
                title,
                request_focus_json,
                brief_focus_json,
                interaction_contract_json,
                edit_focus_json,
                candidate_json,
                schema_contract,
            )
        }
    ]))
}

fn studio_artifact_judge_schema_contract(renderer: StudioRendererKind) -> &'static str {
    match renderer {
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => {
            "Return exactly one JSON object with this camelCase schema:\n{\n  \"classification\": \"pass\" | \"repairable\" | \"blocked\",\n  \"requestFaithfulness\": <1_to_5_integer>,\n  \"conceptCoverage\": <1_to_5_integer>,\n  \"interactionRelevance\": <1_to_5_integer>,\n  \"layoutCoherence\": <1_to_5_integer>,\n  \"visualHierarchy\": <1_to_5_integer>,\n  \"completeness\": <1_to_5_integer>,\n  \"genericShellDetected\": <boolean>,\n  \"trivialShellDetected\": <boolean>,\n  \"deservesPrimaryArtifactView\": <boolean>,\n  \"patchedExistingArtifact\": null | <boolean>,\n  \"continuityRevisionUx\": null | <1_to_5_integer>,\n  \"strongestContradiction\": null | <string>,\n  \"rationale\": <string>\n}\nRules:\n1) Start with '{' and end with '}'. Do not emit markdown fences, prose prefaces, or trailing commentary.\n2) Every score field must be an integer from 1 through 5.\n3) Penalize generic shells, placeholder output, or request-thin artifacts.\n4) requestFaithfulness and conceptCoverage must drop sharply when the candidate omits or weakens differentiating request concepts from subjectDomain, artifactThesis, or requiredConcepts.\n5) A candidate that could fit many nearby prompts by only changing the headline should set genericShellDetected=true and deservesPrimaryArtifactView=false.\n6) Placeholder image URLs, placeholder media, lorem ipsum, fake stock filler, or empty chart regions should set trivialShellDetected=true and classification must not be pass.\n7) html_iframe candidates that rely on a thin div shell, omit semantic sectioning, use invented custom tags instead of standard HTML, fail to realize required interactions, or leave SVG/canvas chart regions empty on first paint must not be pass.\n8) When the brief calls for multiple charts, data visualizations, metrics, or comparisons, a single chart plus generic prose is insufficient and classification must not be pass.\n9) Broken control wiring that targets nonexistent views or uses collection-style iteration on a single selected element should reduce interactionRelevance and completeness.\n10) Apply sequence-browsing penalties only when interactionContract.sequenceBrowsingRequired is true. In that case, a static timeline illustration without a visible progression mechanism such as prev/next controls, a scrubber, or a scrollable evidence rail must reduce interactionRelevance and completeness.\n11) Judge requiredInteractions by the visible response behavior and interactionContract, not by literal widget nouns alone; equivalent truthful inline controls or state changes may satisfy the interaction.\n12) A refinement that restarts unnecessarily should fail patchedExistingArtifact.\n13) If the candidate should not lead the stage, classification must not be pass.\n14) Keep strongestContradiction and rationale terse: one sentence each, under 18 words when present."
        }
        _ => {
            "Return exactly one JSON object with this camelCase schema:\n{\n  \"classification\": \"pass\" | \"repairable\" | \"blocked\",\n  \"requestFaithfulness\": <1_to_5_integer>,\n  \"conceptCoverage\": <1_to_5_integer>,\n  \"interactionRelevance\": <1_to_5_integer>,\n  \"layoutCoherence\": <1_to_5_integer>,\n  \"visualHierarchy\": <1_to_5_integer>,\n  \"completeness\": <1_to_5_integer>,\n  \"genericShellDetected\": <boolean>,\n  \"trivialShellDetected\": <boolean>,\n  \"deservesPrimaryArtifactView\": <boolean>,\n  \"patchedExistingArtifact\": null | <boolean>,\n  \"continuityRevisionUx\": null | <1_to_5_integer>,\n  \"strongestContradiction\": null | <string>,\n  \"rationale\": <string>\n}\nRules:\n1) Start with '{' and end with '}'. Do not emit markdown fences, prose prefaces, or trailing commentary.\n2) Every score field must be an integer from 1 through 5.\n3) Penalize generic shells, placeholder output, or request-thin artifacts.\n4) requestFaithfulness and conceptCoverage must drop sharply when the candidate omits or weakens differentiating request concepts from subjectDomain, artifactThesis, or requiredConcepts.\n5) A candidate that could fit many nearby prompts by only changing the headline should set genericShellDetected=true and deservesPrimaryArtifactView=false.\n6) Empty deliverables, placeholder filler, or obviously incomplete artifacts should set trivialShellDetected=true and classification must not be pass.\n7) A refinement that restarts unnecessarily should fail patchedExistingArtifact.\n8) If the candidate should not lead the stage, classification must not be pass.\n9) Keep strongestContradiction and rationale terse: one sentence each, under 18 words when present."
        }
    }
}

pub fn build_studio_artifact_judge_repair_prompt(
    title: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate: &StudioGeneratedArtifactPayload,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    let candidate_json = compact_studio_judge_json(
        &studio_artifact_judge_candidate_view(candidate),
        "Studio artifact candidate",
    )?;
    let schema_contract = studio_artifact_judge_schema_contract(request.renderer);
    let brief_focus_json = compact_studio_judge_json(
        &studio_artifact_judge_brief_focus(brief),
        "Studio artifact brief focus",
    )?;
    if renderer_uses_document_judge_context(request.renderer) {
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact judge repairer. Repair the previous judge output into a schema-valid judgment. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nBrief focus JSON:\n{}\n\nCandidate JSON:\n{}\n\nThe previous judge output was rejected.\nFailure:\n{}\n\nPrevious raw output:\n{}\n\nRepair the judgment so it is schema-valid and faithful to the candidate.\n\n{}",
                    title,
                    brief_focus_json,
                    candidate_json,
                    failure,
                    raw_output,
                    schema_contract,
                )
            }
        ]));
    }

    let request_focus_json = compact_studio_judge_json(
        &studio_artifact_judge_request_focus(request),
        "Studio artifact request focus",
    )?;
    let interaction_contract_json = compact_studio_judge_json(
        &super::studio_artifact_interaction_contract(brief),
        "Studio interaction contract",
    )?;
    let edit_focus_json = compact_studio_judge_json(
        &studio_artifact_judge_edit_focus(edit_intent),
        "Studio artifact edit intent focus",
    )?;
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact judge repairer. Repair the previous judge output into a schema-valid judgment. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest focus JSON:\n{}\n\nBrief focus JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent focus JSON:\n{}\n\nCandidate JSON:\n{}\n\nThe previous judge output was rejected.\nFailure:\n{}\n\nPrevious raw output:\n{}\n\nRepair the judgment so it is schema-valid and faithful to the candidate.\n\n{}",
                title,
                request_focus_json,
                brief_focus_json,
                interaction_contract_json,
                edit_focus_json,
                candidate_json,
                failure,
                raw_output,
                schema_contract,
            )
        }
    ]))
}

fn coerce_judge_string_field(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(_) => {}
        serde_json::Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            *value = serde_json::Value::String(joined);
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::String(String::new());
        }
        _ => {}
    }
}

fn coerce_judge_bool_field(value: &mut serde_json::Value) {
    if let serde_json::Value::String(text) = value {
        let normalized = text.trim().to_ascii_lowercase();
        if normalized == "true" {
            *value = serde_json::Value::Bool(true);
        } else if normalized == "false" {
            *value = serde_json::Value::Bool(false);
        }
    }
}

fn clamp_judge_score_value(value: &mut serde_json::Value) {
    let numeric = match value {
        serde_json::Value::Number(number) => number
            .as_i64()
            .map(|score| score as f64)
            .or_else(|| number.as_u64().map(|score| score as f64))
            .or_else(|| number.as_f64()),
        serde_json::Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    };
    let Some(numeric) = numeric else {
        return;
    };

    let clamped = numeric.round().clamp(1.0, 5.0) as u64;
    *value = serde_json::Value::Number(serde_json::Number::from(clamped));
}

fn normalize_optional_judge_score_field(value: &mut serde_json::Value) {
    if value.is_null() {
        return;
    }
    clamp_judge_score_value(value);
}

fn normalize_studio_artifact_judge_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    for field in ["classification", "rationale", "strongestContradiction"] {
        if let Some(entry) = object.get_mut(field) {
            coerce_judge_string_field(entry);
        }
    }
    for field in [
        "genericShellDetected",
        "trivialShellDetected",
        "deservesPrimaryArtifactView",
        "patchedExistingArtifact",
    ] {
        if let Some(entry) = object.get_mut(field) {
            coerce_judge_bool_field(entry);
        }
    }
    for field in [
        "requestFaithfulness",
        "conceptCoverage",
        "interactionRelevance",
        "layoutCoherence",
        "visualHierarchy",
        "completeness",
    ] {
        if let Some(entry) = object.get_mut(field) {
            clamp_judge_score_value(entry);
        }
    }
    if let Some(entry) = object.get_mut("continuityRevisionUx") {
        normalize_optional_judge_score_field(entry);
    }
}

pub fn parse_studio_artifact_judge_result(raw: &str) -> Result<StudioArtifactJudgeResult, String> {
    let mut value = serde_json::from_str::<serde_json::Value>(raw)
        .or_else(|_| {
            let extracted = super::extract_first_json_object(raw)
                .ok_or_else(|| "Studio artifact judge output missing JSON payload".to_string())?;
            serde_json::from_str::<serde_json::Value>(&extracted).map_err(|error| error.to_string())
        })
        .map_err(|error| format!("Failed to parse Studio artifact judge result: {error}"))?;
    normalize_studio_artifact_judge_value(&mut value);
    let result = serde_json::from_value::<StudioArtifactJudgeResult>(value)
        .map_err(|error| format!("Failed to parse Studio artifact judge result: {error}"))?;

    for score in [
        result.request_faithfulness,
        result.concept_coverage,
        result.interaction_relevance,
        result.layout_coherence,
        result.visual_hierarchy,
        result.completeness,
    ] {
        if !(1..=5).contains(&score) {
            return Err("Studio artifact judge scores must stay within 1..=5.".to_string());
        }
    }

    if result.rationale.trim().is_empty() {
        return Err("Studio artifact judge rationale must not be empty.".to_string());
    }

    Ok(result)
}

pub(crate) fn candidate_generation_config(
    renderer: StudioRendererKind,
    production_kind: StudioRuntimeProvenanceKind,
) -> (usize, f32, &'static str) {
    match renderer {
        StudioRendererKind::HtmlIframe
            if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime =>
        {
            (2, 0.62, "request-grounded_html")
        }
        StudioRendererKind::HtmlIframe => (3, 0.6, "request-grounded_html"),
        StudioRendererKind::JsxSandbox => (2, 0.5, "interaction-first_jsx"),
        StudioRendererKind::Svg => (2, 0.48, "motif-first_svg"),
        StudioRendererKind::Markdown
            if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime =>
        {
            (1, 0.22, "outline-first_markdown")
        }
        StudioRendererKind::Markdown => (2, 0.22, "outline-first_markdown"),
        StudioRendererKind::Mermaid
            if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime =>
        {
            (1, 0.18, "pipeline-first_mermaid")
        }
        StudioRendererKind::Mermaid => (2, 0.18, "pipeline-first_mermaid"),
        StudioRendererKind::PdfEmbed
            if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime =>
        {
            (1, 0.2, "brief-first_pdf")
        }
        StudioRendererKind::PdfEmbed => (2, 0.2, "brief-first_pdf"),
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest
            if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime =>
        {
            (1, 0.12, "bundle-first_download")
        }
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => {
            (2, 0.12, "bundle-first_download")
        }
        StudioRendererKind::WorkspaceSurface => (1, 0.0, "workspace"),
    }
}

fn studio_artifact_judge_candidate_view(
    candidate: &StudioGeneratedArtifactPayload,
) -> serde_json::Value {
    json!({
        "summary": truncate_studio_judge_text(&candidate.summary, 320),
        "notes": candidate
            .notes
            .iter()
            .take(6)
            .map(|note| truncate_studio_judge_text(note, 220))
            .collect::<Vec<_>>(),
        "files": candidate
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
                    "bodyChars": file.body.chars().count(),
                    "lineCount": file.body.lines().count(),
                    "bodyPreview": truncate_studio_judge_text(&file.body, 1200),
                })
            })
            .collect::<Vec<_>>(),
    })
}

pub(crate) fn studio_artifact_refinement_candidate_view(
    candidate: &StudioGeneratedArtifactPayload,
) -> serde_json::Value {
    json!({
        "summary": truncate_studio_judge_text(&candidate.summary, 400),
        "notes": candidate
            .notes
            .iter()
            .take(8)
            .map(|note| truncate_studio_judge_text(note, 240))
            .collect::<Vec<_>>(),
        "files": candidate
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
                    "bodyChars": file.body.chars().count(),
                    "lineCount": file.body.lines().count(),
                    "bodyPreview": truncate_studio_judge_text(&file.body, 3200),
                })
            })
            .collect::<Vec<_>>(),
    })
}

pub(crate) fn studio_artifact_refinement_context_view(
    refinement: Option<&StudioArtifactRefinementContext>,
) -> serde_json::Value {
    let Some(refinement) = refinement else {
        return serde_json::Value::Null;
    };

    json!({
        "artifactId": refinement.artifact_id,
        "revisionId": refinement.revision_id,
        "title": truncate_studio_judge_text(&refinement.title, 240),
        "summary": truncate_studio_judge_text(&refinement.summary, 400),
        "renderer": refinement.renderer,
        "files": refinement
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
                    "bodyChars": file.body.chars().count(),
                    "lineCount": file.body.lines().count(),
                    "bodyPreview": truncate_studio_judge_text(&file.body, 1800),
                })
            })
            .collect::<Vec<_>>(),
        "selectedTargets": refinement
            .selected_targets
            .iter()
            .map(|target| {
                json!({
                    "sourceSurface": target.source_surface,
                    "path": target.path,
                    "label": truncate_studio_judge_text(&target.label, 120),
                    "snippet": truncate_studio_judge_text(&target.snippet, 400),
                })
            })
            .collect::<Vec<_>>(),
        "tasteMemory": refinement.taste_memory,
    })
}

fn truncate_studio_judge_text(text: &str, max_chars: usize) -> String {
    let total_chars = text.chars().count();
    if total_chars <= max_chars {
        return text.to_string();
    }

    let marker = format!("\n...[truncated {} chars]...\n", total_chars - max_chars);
    let marker_chars = marker.chars().count();
    if max_chars <= marker_chars + 2 {
        return text.chars().take(max_chars).collect();
    }

    let prefix_len = ((max_chars - marker_chars) * 2) / 3;
    let suffix_len = max_chars - marker_chars - prefix_len;
    let prefix = text.chars().take(prefix_len).collect::<String>();
    let suffix = text
        .chars()
        .rev()
        .take(suffix_len)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{prefix}{marker}{suffix}")
}

pub(crate) fn runtime_model_label(runtime: &Arc<dyn InferenceRuntime>) -> String {
    let provenance = runtime.studio_runtime_provenance();
    provenance
        .model
        .clone()
        .unwrap_or_else(|| provenance.label.clone())
}

pub(crate) fn output_origin_from_provenance(
    provenance: &StudioRuntimeProvenance,
) -> StudioArtifactOutputOrigin {
    match provenance.kind {
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime
        | StudioRuntimeProvenanceKind::RealLocalRuntime => {
            StudioArtifactOutputOrigin::LiveInference
        }
        StudioRuntimeProvenanceKind::FixtureRuntime => StudioArtifactOutputOrigin::FixtureRuntime,
        StudioRuntimeProvenanceKind::MockRuntime => StudioArtifactOutputOrigin::MockInference,
        StudioRuntimeProvenanceKind::DeterministicContinuityFallback => {
            StudioArtifactOutputOrigin::DeterministicFallback
        }
        StudioRuntimeProvenanceKind::InferenceUnavailable => {
            StudioArtifactOutputOrigin::InferenceUnavailable
        }
        StudioRuntimeProvenanceKind::OpaqueRuntime => StudioArtifactOutputOrigin::OpaqueRuntime,
    }
}

pub(crate) fn candidate_seed_for(title: &str, intent: &str, index: usize) -> u64 {
    title
        .bytes()
        .chain(intent.bytes())
        .fold((index as u64).saturating_add(1), |acc, byte| {
            acc.wrapping_mul(16777619).wrapping_add(byte as u64)
        })
}

pub(crate) fn materialization_max_tokens(renderer: StudioRendererKind) -> u32 {
    match renderer {
        StudioRendererKind::HtmlIframe => 2800,
        StudioRendererKind::JsxSandbox => 1800,
        StudioRendererKind::Svg => 1200,
        StudioRendererKind::Markdown => 900,
        StudioRendererKind::Mermaid => 700,
        StudioRendererKind::PdfEmbed => 1200,
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => 900,
        StudioRendererKind::WorkspaceSurface => 2000,
    }
}

fn judge_max_tokens(renderer: StudioRendererKind) -> u32 {
    match renderer {
        StudioRendererKind::HtmlIframe
        | StudioRendererKind::JsxSandbox
        | StudioRendererKind::Svg => 192,
        StudioRendererKind::Markdown
        | StudioRendererKind::Mermaid
        | StudioRendererKind::PdfEmbed
        | StudioRendererKind::DownloadCard
        | StudioRendererKind::BundleManifest
        | StudioRendererKind::WorkspaceSurface => 160,
    }
}

fn judge_repair_max_tokens(renderer: StudioRendererKind) -> u32 {
    match renderer {
        StudioRendererKind::HtmlIframe
        | StudioRendererKind::JsxSandbox
        | StudioRendererKind::Svg => 256,
        StudioRendererKind::Markdown
        | StudioRendererKind::Mermaid
        | StudioRendererKind::PdfEmbed
        | StudioRendererKind::DownloadCard
        | StudioRendererKind::BundleManifest
        | StudioRendererKind::WorkspaceSurface => 224,
    }
}

pub(crate) fn semantic_refinement_pass_limit(
    renderer: StudioRendererKind,
    production_kind: StudioRuntimeProvenanceKind,
) -> usize {
    match renderer {
        StudioRendererKind::HtmlIframe
            if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime =>
        {
            1
        }
        StudioRendererKind::HtmlIframe => 2,
        StudioRendererKind::JsxSandbox | StudioRendererKind::Svg => 1,
        _ => 0,
    }
}

pub(crate) fn refined_candidate_root(candidate_id: &str) -> &str {
    candidate_id
        .split("-refine-")
        .next()
        .unwrap_or(candidate_id)
}

pub(crate) fn summarized_guidance_terms(
    items: &[String],
    fallback: &str,
    max_items: usize,
) -> String {
    let visible = items
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .take(max_items)
        .collect::<Vec<_>>();
    if visible.is_empty() {
        fallback.to_string()
    } else {
        visible.join(", ")
    }
}

pub(crate) fn html_first_paint_section_blueprint(brief: &StudioArtifactBrief) -> String {
    let overview_focus = brief
        .artifact_thesis
        .trim()
        .strip_suffix('.')
        .unwrap_or(brief.artifact_thesis.trim());
    let primary_evidence = brief
        .factual_anchors
        .first()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .or_else(|| {
            brief
                .required_concepts
                .first()
                .map(|item| item.trim())
                .filter(|item| !item.is_empty())
        })
        .unwrap_or("the primary request concept");
    let secondary_evidence = brief
        .factual_anchors
        .iter()
        .skip(1)
        .chain(brief.reference_hints.iter())
        .chain(brief.required_concepts.iter().skip(1))
        .map(|item| item.trim())
        .find(|item| !item.is_empty())
        .unwrap_or("the supporting comparison evidence");
    let control_focus = brief
        .factual_anchors
        .iter()
        .chain(brief.required_concepts.iter())
        .map(|item| item.trim())
        .find(|item| !item.is_empty())
        .unwrap_or("the primary evidence topics");
    let detail_focus = brief
        .required_interactions
        .iter()
        .chain(brief.factual_anchors.iter().skip(2))
        .chain(brief.reference_hints.iter())
        .chain(brief.required_concepts.iter().skip(2))
        .map(|item| item.trim())
        .find(|item| !item.is_empty())
        .unwrap_or("the shared evidence and detail state");
    let anchor_focus = brief
        .reference_hints
        .first()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .or_else(|| {
            brief
                .factual_anchors
                .first()
                .map(|item| item.trim())
                .filter(|item| !item.is_empty())
        })
        .unwrap_or("the main rollout evidence");

    format!(
        "1) overview section that states {overview_focus}; 2) named control bar that lets the audience inspect {control_focus}; 3) primary evidence section that visualizes {primary_evidence} with visible marks, labels, or comparative values on first paint; 4) secondary evidence section or comparison article that surfaces {secondary_evidence}; 5) shared detail/comparison aside that reacts to controls and explains {detail_focus}; 6) supporting footer/aside callouts grounded in {anchor_focus}"
    )
}

fn judge_rank(classification: StudioArtifactJudgeClassification) -> u8 {
    match classification {
        StudioArtifactJudgeClassification::Pass => 3,
        StudioArtifactJudgeClassification::Repairable => 2,
        StudioArtifactJudgeClassification::Blocked => 1,
    }
}

pub(crate) fn judge_total_score(judge: &StudioArtifactJudgeResult) -> i32 {
    (judge_rank(judge.classification) as i32) * 100
        + (judge.request_faithfulness as i32) * 12
        + (judge.concept_coverage as i32) * 10
        + (judge.interaction_relevance as i32) * 8
        + (judge.layout_coherence as i32) * 7
        + (judge.visual_hierarchy as i32) * 7
        + (judge.completeness as i32) * 9
        + if judge.deserves_primary_artifact_view {
            12
        } else {
            -20
        }
        + if judge.generic_shell_detected { -28 } else { 0 }
        + if judge.trivial_shell_detected { -36 } else { 0 }
        + judge.continuity_revision_ux.unwrap_or(0) as i32
}

pub(crate) fn judge_clears_primary_view(judge: &StudioArtifactJudgeResult) -> bool {
    judge.classification == StudioArtifactJudgeClassification::Pass
        && judge.deserves_primary_artifact_view
        && !judge.generic_shell_detected
        && !judge.trivial_shell_detected
}

pub(crate) fn renderer_supports_semantic_refinement(renderer: StudioRendererKind) -> bool {
    matches!(
        renderer,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox | StudioRendererKind::Svg
    )
}
