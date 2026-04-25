use super::*;

fn chat_validation_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_CHAT_PROOF_TRACE").is_some() {
        eprintln!("[chat-proof-trace] {}", message.as_ref());
    }
}

fn chat_validation_trace_preview(stage: &str, runtime_label: &str, raw: &str) {
    chat_validation_trace(format!(
        "{stage} runtime={} preview={}",
        runtime_label,
        truncate_chat_validation_text(raw, 1200)
    ));
}

fn renderer_uses_document_validation_context(renderer: ChatRendererKind) -> bool {
    matches!(
        renderer,
        ChatRendererKind::Markdown
            | ChatRendererKind::Mermaid
            | ChatRendererKind::PdfEmbed
            | ChatRendererKind::DownloadCard
            | ChatRendererKind::BundleManifest
    )
}

fn compact_local_document_validation_prompt(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> bool {
    renderer_uses_document_validation_context(renderer)
        && runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
}

fn compact_local_html_validation_prompt(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> bool {
    renderer == ChatRendererKind::HtmlIframe
        && runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
}

fn ultra_compact_local_markdown_validation_prompt(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> bool {
    renderer == ChatRendererKind::Markdown
        && runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
}

fn compact_local_download_bundle_validation_prompt(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> bool {
    compact_local_document_validation_prompt(renderer, runtime_kind)
        && matches!(
            renderer,
            ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest
        )
}

fn compact_chat_validation_json<T: serde::Serialize>(
    value: &T,
    label: &str,
) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| format!("Failed to serialize {label}: {error}"))
}

fn chat_artifact_validation_request_focus(
    request: &ChatOutcomeArtifactRequest,
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

fn chat_artifact_validation_brief_focus(brief: &ChatArtifactBrief) -> serde_json::Value {
    json!({
        "audience": brief.audience,
        "jobToBeDone": brief.job_to_be_done,
        "subjectDomain": brief.subject_domain,
        "artifactThesis": brief.artifact_thesis,
        "requiredConcepts": brief.required_concepts,
        "requiredInteractions": brief.required_interaction_summaries(),
        "visualTone": brief.visual_tone,
        "factualAnchors": brief.factual_anchors,
        "styleDirectives": brief.style_directives,
        "referenceHints": brief.reference_hints,
    })
}

fn chat_artifact_compact_document_brief_focus(brief: &ChatArtifactBrief) -> serde_json::Value {
    json!({
        "jobToBeDone": truncate_chat_validation_text(&brief.job_to_be_done, 120),
        "subjectDomain": truncate_chat_validation_text(&brief.subject_domain, 80),
        "artifactThesis": truncate_chat_validation_text(&brief.artifact_thesis, 120),
        "requiredConcepts": brief
            .required_concepts
            .iter()
            .take(3)
            .map(|concept| truncate_chat_validation_text(concept, 36))
            .collect::<Vec<_>>(),
    })
}

fn chat_artifact_compact_document_brief_text(brief: &ChatArtifactBrief) -> String {
    let concepts = brief
        .required_concepts
        .iter()
        .take(3)
        .map(|concept| truncate_chat_validation_text(concept, 36))
        .collect::<Vec<_>>()
        .join(", ");
    [
        format!(
            "job: {}",
            truncate_chat_validation_text(&brief.job_to_be_done, 80)
        ),
        format!(
            "domain: {}",
            truncate_chat_validation_text(&brief.subject_domain, 64)
        ),
        format!(
            "thesis: {}",
            truncate_chat_validation_text(&brief.artifact_thesis, 96)
        ),
        format!("concepts: {}", concepts),
    ]
    .join("\n")
}

fn chat_artifact_compact_document_candidate_text(
    candidate: &ChatGeneratedArtifactPayload,
) -> String {
    let mut lines = Vec::new();
    if !candidate.summary.trim().is_empty() {
        lines.push(format!(
            "summary: {}",
            truncate_chat_validation_text(&candidate.summary, 120)
        ));
    }
    if let Some(note) = candidate.notes.first() {
        let note = truncate_chat_validation_text(note, 72);
        if !note.is_empty() {
            lines.push(format!("note: {note}"));
        }
    }
    for (index, file) in candidate.files.iter().take(3).enumerate() {
        lines.push(format!(
            "file{}: path={} mime={} role={:?} renderable={} downloadable={} chars={} lines={} preview={}",
            index + 1,
            file.path,
            file.mime,
            file.role,
            file.renderable,
            file.downloadable,
            file.body.chars().count(),
            file.body.lines().count(),
            truncate_chat_validation_text(&file.body, 80),
        ));
    }
    lines.join("\n")
}

fn chat_artifact_compact_html_candidate_text(candidate: &ChatGeneratedArtifactPayload) -> String {
    let mut lines = Vec::new();
    if !candidate.summary.trim().is_empty() {
        lines.push(format!(
            "summary: {}",
            truncate_chat_validation_text(&candidate.summary, 120)
        ));
    }
    if let Some(file) = candidate.files.iter().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
        )
    }) {
        let lower = file.body.to_ascii_lowercase();
        lines.push(format!(
            "file: path={} chars={} lines={} sections={} buttons={} inputs={} details={} scripts={} renderable={} preview={}",
            file.path,
            file.body.chars().count(),
            file.body.lines().count(),
            lower.matches("<section").count(),
            lower.matches("<button").count(),
            lower.matches("<input").count(),
            lower.matches("<details").count(),
            lower.matches("<script").count(),
            file.renderable,
            truncate_chat_validation_text(&file.body, 120),
        ));
    }
    lines.join("\n")
}

fn chat_artifact_ultra_compact_markdown_candidate_text(
    candidate: &ChatGeneratedArtifactPayload,
) -> String {
    let mut lines = Vec::new();
    if !candidate.summary.trim().is_empty() {
        lines.push(format!(
            "summary: {}",
            truncate_chat_validation_text(&candidate.summary, 96)
        ));
    }
    for (index, file) in candidate.files.iter().take(2).enumerate() {
        lines.push(format!(
            "file{}: {} lines={} preview={}",
            index + 1,
            file.path,
            file.body.lines().count(),
            truncate_chat_validation_text(&file.body, 56),
        ));
    }
    lines.join("\n")
}

fn chat_artifact_compact_download_bundle_candidate_text(
    candidate: &ChatGeneratedArtifactPayload,
) -> String {
    candidate
        .files
        .iter()
        .take(3)
        .enumerate()
        .map(|(index, file)| {
            format!(
                "file{}: path={} mime={} downloadable={} lines={} preview={}",
                index + 1,
                file.path,
                file.mime,
                file.downloadable,
                file.body.lines().count(),
                truncate_chat_validation_text(&file.body, 56),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn chat_artifact_validation_edit_focus(
    edit_intent: Option<&ChatArtifactEditIntent>,
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

pub async fn validate_chat_artifact_candidate_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
    candidate: &ChatGeneratedArtifactPayload,
) -> Result<ChatArtifactValidationResult, String> {
    validate_chat_artifact_candidate_with_runtime_and_render_eval(
        runtime,
        title,
        request,
        brief,
        edit_intent,
        candidate,
        None,
    )
    .await
}

pub(crate) async fn validate_chat_artifact_candidate_with_runtime_and_render_eval(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
    candidate: &ChatGeneratedArtifactPayload,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> Result<ChatArtifactValidationResult, String> {
    let runtime_provenance = runtime.chat_runtime_provenance();
    let compact_local_document_prompt =
        compact_local_document_validation_prompt(request.renderer, runtime_provenance.kind);
    let compact_local_html_prompt =
        compact_local_html_validation_prompt(request.renderer, runtime_provenance.kind);
    chat_validation_trace(format!(
        "artifact_validation:start renderer={:?} runtime={} model={:?}",
        request.renderer, runtime_provenance.label, runtime_provenance.model
    ));
    let payload = build_chat_artifact_validation_prompt_with_render_eval_for_runtime(
        title,
        request,
        brief,
        edit_intent,
        candidate,
        runtime_provenance.kind,
        render_evaluation,
    )?;
    let input = serde_json::to_vec(&payload)
        .map_err(|error| format!("Failed to encode Chat artifact validation prompt: {error}"))?;
    chat_validation_trace(format!(
        "artifact_validation:prompt_bytes runtime={} bytes={}",
        runtime_provenance.label,
        input.len()
    ));
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: !(compact_local_document_prompt || compact_local_html_prompt),
                max_tokens: validation_max_tokens_for_runtime(
                    request.renderer,
                    runtime_provenance.kind,
                ),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| format!("Chat artifact validation inference failed: {error}"))?;
    chat_validation_trace(format!(
        "artifact_validation:raw_ok runtime={} bytes={}",
        runtime_provenance.label,
        output.len()
    ));
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Chat artifact validation utf8 decode failed: {error}"))?;
    chat_validation_trace_preview(
        "artifact_validation:raw_preview",
        &runtime_provenance.label,
        &raw,
    );
    match parse_chat_artifact_validation_result(&raw) {
        Ok(result) => {
            chat_validation_trace(format!(
                "artifact_validation:parse_ok runtime={} classification={:?}",
                runtime_provenance.label, result.classification
            ));
            Ok(super::enforce_renderer_validation_contract(
                request, brief, candidate, result,
            ))
        }
        Err(first_error) => {
            chat_validation_trace(format!(
                "artifact_validation:repair:start runtime={} error={}",
                runtime_provenance.label, first_error
            ));
            let repair_payload = build_chat_artifact_validation_repair_prompt(
                title,
                request,
                brief,
                edit_intent,
                candidate,
                &raw,
                &first_error,
            )?;
            let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                format!("Failed to encode Chat artifact validation repair prompt: {error}")
            })?;
            let repair_output = runtime
                .execute_inference(
                    [0u8; 32],
                    &repair_input,
                    InferenceOptions {
                        temperature: 0.0,
                        json_mode: !(compact_local_document_prompt || compact_local_html_prompt),
                        max_tokens: validation_repair_max_tokens_for_runtime(
                            request.renderer,
                            runtime_provenance.kind,
                        ),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| {
                    format!("{first_error}; validation repair inference failed: {error}")
                })?;
            chat_validation_trace(format!(
                "artifact_validation:repair:raw_ok runtime={} bytes={}",
                runtime_provenance.label,
                repair_output.len()
            ));
            let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                format!("{first_error}; validation repair utf8 decode failed: {error}")
            })?;
            chat_validation_trace_preview(
                "artifact_validation:repair:raw_preview",
                &runtime_provenance.label,
                &repair_raw,
            );
            parse_chat_artifact_validation_result(&repair_raw)
                .map(|result| {
                    chat_validation_trace(format!(
                        "artifact_validation:repair:parse_ok runtime={} classification={:?}",
                        runtime_provenance.label, result.classification
                    ));
                    super::enforce_renderer_validation_contract(request, brief, candidate, result)
                })
                .map_err(|repair_error| {
                    format!("{first_error}; validation repair attempt also failed: {repair_error}")
                })
        }
    }
}

pub fn build_chat_artifact_validation_prompt(
    title: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
    candidate: &ChatGeneratedArtifactPayload,
) -> Result<serde_json::Value, String> {
    build_chat_artifact_validation_prompt_for_runtime(
        title,
        request,
        brief,
        edit_intent,
        candidate,
        ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

pub(crate) fn build_chat_artifact_validation_prompt_for_runtime(
    title: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
    candidate: &ChatGeneratedArtifactPayload,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    build_chat_artifact_validation_prompt_with_render_eval_for_runtime(
        title,
        request,
        brief,
        edit_intent,
        candidate,
        runtime_kind,
        None,
    )
}

pub(crate) fn build_chat_artifact_validation_prompt_with_render_eval_for_runtime(
    title: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
    candidate: &ChatGeneratedArtifactPayload,
    runtime_kind: ChatRuntimeProvenanceKind,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> Result<serde_json::Value, String> {
    let compact_document_prompt =
        compact_local_document_validation_prompt(request.renderer, runtime_kind);
    let compact_html_prompt = compact_local_html_validation_prompt(request.renderer, runtime_kind);
    let ultra_compact_markdown_prompt =
        ultra_compact_local_markdown_validation_prompt(request.renderer, runtime_kind);
    let schema_contract =
        chat_artifact_validation_schema_contract_for_runtime(request.renderer, runtime_kind);
    let render_eval_focus_json = compact_chat_validation_json(
        &chat_artifact_validation_render_eval_focus(render_evaluation),
        "Chat artifact render evaluation focus",
    )?;
    if compact_document_prompt && renderer_uses_document_validation_context(request.renderer) {
        let candidate_text =
            if compact_local_download_bundle_validation_prompt(request.renderer, runtime_kind) {
                chat_artifact_compact_download_bundle_candidate_text(candidate)
            } else if ultra_compact_markdown_prompt {
                chat_artifact_ultra_compact_markdown_candidate_text(candidate)
            } else {
                chat_artifact_compact_document_candidate_text(candidate)
            };
        let title_limit = if ultra_compact_markdown_prompt {
            72
        } else {
            96
        };
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Chat's typed artifact validation. Validation only the candidate files and the typed brief."
            },
            {
                "role": "user",
                "content": format!(
                    "Title: {}\n\nBrief:\n{}\n\nCandidate:\n{}\n\nRender evaluation JSON:\n{}\n\n{}",
                    truncate_chat_validation_text(title, title_limit),
                    chat_artifact_compact_document_brief_text(brief),
                    candidate_text,
                    render_eval_focus_json,
                    schema_contract,
                )
            }
        ]));
    }

    if compact_html_prompt {
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Chat's typed artifact validation. Validation only the candidate files and the typed brief."
            },
            {
                "role": "user",
                "content": format!(
                    "Title: {}\n\nBrief:\n{}\n\nCandidate:\n{}\n\nRender evaluation JSON:\n{}\n\nReturn exactly these plain-text lines:\nclassification: pass|repairable|blocked\nrequestFaithfulness: 1-5\nconceptCoverage: 1-5\ninteractionRelevance: 1-5\nlayoutCoherence: 1-5\nvisualHierarchy: 1-5\ncompleteness: 1-5\ngenericShellDetected: true|false\ntrivialShellDetected: true|false\ndeservesPrimaryArtifactView: true|false\nstrengths: item; item\nblockedReasons: item; item\nrecommendedNextPass: accept|structural_repair|polish_pass|hold_block\nrationale: short sentence\nRules:\n1) No JSON or markdown fences.\n2) Pass only if the artifact is request-specific, visibly interactive, materially complete, and strong enough to lead.\n3) Set genericShellDetected=true for nearby-prompt shells or generic dashboard chrome.\n4) Set trivialShellDetected=true for empty, placeholder, or barely interactive artifacts.\n5) Keep strengths and blockedReasons to 0-2 short items.\n6) If it should not lead the stage, classification must not be pass.",
                    truncate_chat_validation_text(title, 96),
                    chat_artifact_compact_document_brief_text(brief),
                    chat_artifact_compact_html_candidate_text(candidate),
                    render_eval_focus_json,
                )
            }
        ]));
    }

    let candidate_json = compact_chat_validation_json(
        &chat_artifact_validation_candidate_view_for_runtime(
            candidate,
            request.renderer,
            runtime_kind,
        ),
        "Chat artifact candidate",
    )?;
    let brief_focus = if compact_document_prompt {
        chat_artifact_compact_document_brief_focus(brief)
    } else {
        chat_artifact_validation_brief_focus(brief)
    };
    let brief_focus_json = compact_chat_validation_json(&brief_focus, "Chat artifact brief focus")?;
    if renderer_uses_document_validation_context(request.renderer) {
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Chat's typed artifact validation. Validation only the candidate files and the typed brief. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nBrief focus JSON:\n{}\n\nCandidate JSON:\n{}\n\nRender evaluation JSON:\n{}\n\n{}",
                    title,
                    brief_focus_json,
                    candidate_json,
                    render_eval_focus_json,
                    schema_contract,
                )
            }
        ]));
    }

    let request_focus_json = compact_chat_validation_json(
        &chat_artifact_validation_request_focus(request),
        "Chat artifact request focus",
    )?;
    let interaction_contract_json = compact_chat_validation_json(
        &super::chat_artifact_interaction_contract(brief),
        "Chat interaction contract",
    )?;
    let edit_focus_json = compact_chat_validation_json(
        &chat_artifact_validation_edit_focus(edit_intent),
        "Chat artifact edit intent focus",
    )?;
    Ok(json!([
        {
            "role": "system",
            "content": "You are Chat's typed artifact validation. Validation only the candidate files and the typed brief. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest focus JSON:\n{}\n\nBrief focus JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent focus JSON:\n{}\n\nCandidate JSON:\n{}\n\nRender evaluation JSON:\n{}\n\n{}",
                title,
                request_focus_json,
                brief_focus_json,
                interaction_contract_json,
                edit_focus_json,
                candidate_json,
                render_eval_focus_json,
                schema_contract,
            )
        }
    ]))
}

pub(crate) fn chat_artifact_validation_render_eval_focus(
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> serde_json::Value {
    match render_evaluation {
        Some(render_evaluation) => json!({
            "supported": render_evaluation.supported,
            "firstPaintCaptured": render_evaluation.first_paint_captured,
            "interactionCaptureAttempted": render_evaluation.interaction_capture_attempted,
            "layoutDensityScore": render_evaluation.layout_density_score,
            "spacingAlignmentScore": render_evaluation.spacing_alignment_score,
            "typographyContrastScore": render_evaluation.typography_contrast_score,
            "visualHierarchyScore": render_evaluation.visual_hierarchy_score,
            "blueprintConsistencyScore": render_evaluation.blueprint_consistency_score,
            "overallScore": render_evaluation.overall_score,
            "summary": truncate_chat_validation_text(&render_evaluation.summary, 220),
            "findings": render_evaluation.findings.iter().map(|finding| {
                json!({
                    "code": finding.code,
                    "severity": finding.severity,
                    "summary": truncate_chat_validation_text(&finding.summary, 180),
                })
            }).collect::<Vec<_>>(),
            "acceptanceObligations": render_evaluation.acceptance_obligations.iter().map(|obligation| {
                json!({
                    "id": obligation.obligation_id,
                    "family": obligation.family,
                    "required": obligation.required,
                    "status": obligation.status,
                    "summary": truncate_chat_validation_text(&obligation.summary, 180),
                })
            }).collect::<Vec<_>>(),
            "executionWitnesses": render_evaluation.execution_witnesses.iter().map(|witness| {
                json!({
                    "witnessId": witness.witness_id,
                    "obligationId": witness.obligation_id,
                    "status": witness.status,
                    "actionKind": witness.action_kind,
                    "summary": truncate_chat_validation_text(&witness.summary, 180),
                    "selector": witness.selector.as_ref().map(|selector| {
                        truncate_chat_validation_text(selector, 120)
                    }),
                })
            }).collect::<Vec<_>>(),
            "captures": render_evaluation.captures.iter().map(|capture| {
                json!({
                    "viewport": capture.viewport,
                    "visibleElementCount": capture.visible_element_count,
                    "visibleTextChars": capture.visible_text_chars,
                    "interactiveElementCount": capture.interactive_element_count,
                    "screenshotChangedFromPrevious": capture.screenshot_changed_from_previous,
                })
            }).collect::<Vec<_>>(),
        }),
        None => serde_json::Value::Null,
    }
}

fn chat_artifact_validation_schema_contract(renderer: ChatRendererKind) -> &'static str {
    chat_artifact_validation_schema_contract_for_runtime(
        renderer,
        ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn chat_artifact_validation_schema_contract_for_runtime(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> &'static str {
    if ultra_compact_local_markdown_validation_prompt(renderer, runtime_kind) {
        return "Return exactly these plain-text lines:\nverdict: pass|repairable|blocked\nfaithfulness: 1-5\ncoverage: 1-5\ncomplete: 1-5\ngeneric: true|false\ntrivial: true|false\nprimary: true|false\nnext: accept|repair|block\nwhy: short sentence\nRules:\n1) No JSON or fences.\n2) Pass only if the markdown is request-specific and materially usable.\n3) Use repairable for thin but fixable drafts.\n4) Use blocked for missing or unusable files.";
    }
    if compact_local_download_bundle_validation_prompt(renderer, runtime_kind) {
        return "Return exactly these plain-text lines:\nclassification: pass|repairable|blocked\nrecommendedNextPass: accept|structural_repair|hold_block\nstrengths: item; item\nblockedReasons: item; item\nrationale: short sentence\nRules:\n1) Validation only whether this is a usable downloadable bundle for the request.\n2) Pass only if the required files exist and their contents are non-placeholder and usable.\n3) Use repairable when the files exist but content is thin, generic, or partly incomplete.\n4) Use blocked when required files are missing or unusable.\n5) No JSON or markdown fences.";
    }
    if compact_local_document_validation_prompt(renderer, runtime_kind) {
        return "Return exactly these plain-text lines:\nclassification: pass|repairable|blocked\nrequestFaithfulness: 1-5\nconceptCoverage: 1-5\ncompleteness: 1-5\ngenericShellDetected: true|false\ntrivialShellDetected: true|false\ndeservesPrimaryArtifactView: true|false\nstrengths: item; item\nblockedReasons: item; item\nrecommendedNextPass: accept|structural_repair|polish_pass|hold_block\nrationale: short sentence\nRules:\n1) No JSON or markdown fences.\n2) Keep strengths and blockedReasons to 0-2 short items.\n3) Set genericShellDetected for nearby-prompt generic shells.\n4) Set trivialShellDetected for empty or placeholder artifacts.\n5) Set deservesPrimaryArtifactView=false unless classification is pass.";
    }
    match renderer {
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox => {
            if renderer == ChatRendererKind::HtmlIframe && chat_modal_first_html_enabled() {
                return "Return exactly one JSON object with this camelCase schema:\n{\n  \"classification\": \"pass\" | \"repairable\" | \"blocked\",\n  \"requestFaithfulness\": <1_to_5_integer>,\n  \"conceptCoverage\": <1_to_5_integer>,\n  \"interactionRelevance\": <1_to_5_integer>,\n  \"layoutCoherence\": <1_to_5_integer>,\n  \"visualHierarchy\": <1_to_5_integer>,\n  \"completeness\": <1_to_5_integer>,\n  \"genericShellDetected\": <boolean>,\n  \"trivialShellDetected\": <boolean>,\n  \"deservesPrimaryArtifactView\": <boolean>,\n  \"patchedExistingArtifact\": null | <boolean>,\n  \"continuityRevisionUx\": null | <1_to_5_integer>,\n  \"issueClasses\": [<string>],\n  \"repairHints\": [<string>],\n  \"strengths\": [<string>],\n  \"blockedReasons\": [<string>],\n  \"fileFindings\": [<string>],\n  \"aestheticVerdict\": <string>,\n  \"interactionVerdict\": <string>,\n  \"truthfulnessWarnings\": [<string>],\n  \"recommendedNextPass\": null | \"accept\" | \"structural_repair\" | \"polish_pass\" | \"hold_block\",\n  \"strongestContradiction\": null | <string>,\n  \"rationale\": <string>\n}\nRules:\n1) Start with '{' and end with '}'. Do not emit markdown fences, prose prefaces, or trailing commentary.\n2) Every score field must be an integer from 1 through 5.\n3) issueClasses, repairHints, strengths, blockedReasons, fileFindings, and truthfulnessWarnings should each contain 0 to 3 terse entries.\n4) Penalize generic shells, placeholder output, or request-thin artifacts.\n5) requestFaithfulness and conceptCoverage must drop sharply when the candidate omits or weakens differentiating request concepts from subjectDomain, artifactThesis, or requiredConcepts.\n6) A candidate that could fit many nearby prompts by only changing the headline should set genericShellDetected=true and deservesPrimaryArtifactView=false.\n7) Placeholder image URLs, placeholder media, lorem ipsum, fake stock filler, or obviously incomplete artifacts should set trivialShellDetected=true and classification must not be pass.\n8) Educational or explanatory html_iframe candidates that default to a generic document shell, stacked concept sections, repeated paragraph-plus-box rhythm, or default browser styling must not be pass.\n9) One isolated button, lone slider, or decorative toggle is insufficient for an interactive artifact; interactionRelevance and completeness must drop unless multiple linked state changes update visible evidence and explanation.\n10) html_iframe controls that only rewrite a label while leaving the surrounding evidence effectively static should not be pass.\n11) Validation requiredInteractions by the visible response behavior and interactionContract, not by literal widget nouns; equivalent truthful inline controls or state changes may satisfy the interaction.\n12) For html_iframe, do not require a shared detail panel or mapped panels unless the candidate itself chooses that pattern. Validation the chosen interaction grammar on whether it produces a truthful visible state change.\n13) Apply sequence-browsing penalties only when interactionContract.sequenceBrowsingRequired is true. In that case, a static illustration without a visible progression mechanic should reduce interactionRelevance and completeness.\n14) Explicitly critique typography, design intentionality, and evidence density in aestheticVerdict or repairHints, interaction truthfulness in interactionVerdict, and continuity with refinement context when patchedExistingArtifact is relevant.\n15) A refinement that restarts unnecessarily should fail patchedExistingArtifact.\n16) If the candidate should not lead the stage, classification must not be pass.\n17) Keep strongestContradiction, aestheticVerdict, interactionVerdict, and rationale terse: one sentence each.\n18) When Render evaluation JSON is present, treat it as surfaced evidence from the actual first paint. If it reports weak hierarchy, sparse density, low overallScore, or weak interaction change, classification must not be pass unless you can clearly justify why those findings are outweighed.\n19) Use recommendedNextPass to signal whether another stochastic repair or polish pass is worthwhile. Reserve hold_block for hard-stop cases such as missing essential content, broken rendering, placeholder output, or contradictions that should not be patched forward.";
            }
            "Return exactly one JSON object with this camelCase schema:\n{\n  \"classification\": \"pass\" | \"repairable\" | \"blocked\",\n  \"requestFaithfulness\": <1_to_5_integer>,\n  \"conceptCoverage\": <1_to_5_integer>,\n  \"interactionRelevance\": <1_to_5_integer>,\n  \"layoutCoherence\": <1_to_5_integer>,\n  \"visualHierarchy\": <1_to_5_integer>,\n  \"completeness\": <1_to_5_integer>,\n  \"genericShellDetected\": <boolean>,\n  \"trivialShellDetected\": <boolean>,\n  \"deservesPrimaryArtifactView\": <boolean>,\n  \"patchedExistingArtifact\": null | <boolean>,\n  \"continuityRevisionUx\": null | <1_to_5_integer>,\n  \"issueClasses\": [<string>],\n  \"repairHints\": [<string>],\n  \"strengths\": [<string>],\n  \"blockedReasons\": [<string>],\n  \"fileFindings\": [<string>],\n  \"aestheticVerdict\": <string>,\n  \"interactionVerdict\": <string>,\n  \"truthfulnessWarnings\": [<string>],\n  \"recommendedNextPass\": null | \"accept\" | \"structural_repair\" | \"polish_pass\" | \"hold_block\",\n  \"strongestContradiction\": null | <string>,\n  \"rationale\": <string>\n}\nRules:\n1) Start with '{' and end with '}'. Do not emit markdown fences, prose prefaces, or trailing commentary.\n2) Every score field must be an integer from 1 through 5.\n3) issueClasses, repairHints, strengths, blockedReasons, fileFindings, and truthfulnessWarnings should each contain 0 to 3 terse entries.\n4) Penalize generic shells, placeholder output, or request-thin artifacts.\n5) requestFaithfulness and conceptCoverage must drop sharply when the candidate omits or weakens differentiating request concepts from subjectDomain, artifactThesis, or requiredConcepts.\n6) A candidate that could fit many nearby prompts by only changing the headline should set genericShellDetected=true and deservesPrimaryArtifactView=false.\n7) Placeholder image URLs, placeholder media, lorem ipsum, fake stock filler, or empty chart regions should set trivialShellDetected=true and classification must not be pass.\n8) html_iframe candidates that rely on a thin div shell, omit semantic sectioning, use invented custom tags instead of standard HTML, fail to realize required interactions, or leave SVG/canvas chart regions empty on first paint must not be pass.\n9) When the brief calls for multiple charts, data visualizations, metrics, or comparisons, a single chart plus generic prose is insufficient and classification must not be pass.\n10) Broken control wiring that targets nonexistent views or uses collection-style iteration on a single selected element should reduce interactionRelevance and completeness.\n11) Apply sequence-browsing penalties only when interactionContract.sequenceBrowsingRequired is true. In that case, a static timeline illustration without a visible progression mechanism such as prev/next controls, a scrubber, or a scrollable evidence rail must reduce interactionRelevance and completeness.\n12) Validation requiredInteractions by the visible response behavior and interactionContract, not by literal widget nouns alone; equivalent truthful inline controls or state changes may satisfy the interaction.\n13) Explicitly critique typography and design intentionality in aestheticVerdict, first-paint evidence density in issueClasses or repairHints, interaction truthfulness in interactionVerdict, and continuity with refinement context when patchedExistingArtifact is relevant.\n14) A refinement that restarts unnecessarily should fail patchedExistingArtifact.\n15) If the candidate should not lead the stage, classification must not be pass.\n16) Keep strongestContradiction, aestheticVerdict, interactionVerdict, and rationale terse: one sentence each.\n17) Use recommendedNextPass to signal whether another stochastic repair or polish pass is worthwhile. Reserve hold_block for hard-stop cases such as missing essential content, broken rendering, placeholder output, or contradictions that should not be patched forward."
        }
        _ => {
            "Return exactly one JSON object with this camelCase schema:\n{\n  \"classification\": \"pass\" | \"repairable\" | \"blocked\",\n  \"requestFaithfulness\": <1_to_5_integer>,\n  \"conceptCoverage\": <1_to_5_integer>,\n  \"interactionRelevance\": <1_to_5_integer>,\n  \"layoutCoherence\": <1_to_5_integer>,\n  \"visualHierarchy\": <1_to_5_integer>,\n  \"completeness\": <1_to_5_integer>,\n  \"genericShellDetected\": <boolean>,\n  \"trivialShellDetected\": <boolean>,\n  \"deservesPrimaryArtifactView\": <boolean>,\n  \"patchedExistingArtifact\": null | <boolean>,\n  \"continuityRevisionUx\": null | <1_to_5_integer>,\n  \"issueClasses\": [<string>],\n  \"repairHints\": [<string>],\n  \"strengths\": [<string>],\n  \"blockedReasons\": [<string>],\n  \"fileFindings\": [<string>],\n  \"aestheticVerdict\": <string>,\n  \"interactionVerdict\": <string>,\n  \"truthfulnessWarnings\": [<string>],\n  \"recommendedNextPass\": null | \"accept\" | \"structural_repair\" | \"polish_pass\" | \"hold_block\",\n  \"strongestContradiction\": null | <string>,\n  \"rationale\": <string>\n}\nRules:\n1) Start with '{' and end with '}'. Do not emit markdown fences, prose prefaces, or trailing commentary.\n2) Every score field must be an integer from 1 through 5.\n3) issueClasses, repairHints, strengths, blockedReasons, fileFindings, and truthfulnessWarnings should each contain 0 to 3 terse entries.\n4) Penalize generic shells, placeholder output, or request-thin artifacts.\n5) requestFaithfulness and conceptCoverage must drop sharply when the candidate omits or weakens differentiating request concepts from subjectDomain, artifactThesis, or requiredConcepts.\n6) A candidate that could fit many nearby prompts by only changing the headline should set genericShellDetected=true and deservesPrimaryArtifactView=false.\n7) Empty deliverables, placeholder filler, or obviously incomplete artifacts should set trivialShellDetected=true and classification must not be pass.\n8) Explicitly record strengths, blockedReasons when blocked, and a recommendedNextPass that tells Chat whether to accept, repair, polish, or hold the block.\n9) A refinement that restarts unnecessarily should fail patchedExistingArtifact.\n10) If the candidate should not lead the stage, classification must not be pass.\n11) Keep strongestContradiction, aestheticVerdict, interactionVerdict, and rationale terse: one sentence each.\n12) Use recommendedNextPass to signal whether another stochastic repair or polish pass is worthwhile. Reserve hold_block for hard-stop cases such as missing essential content, broken rendering, placeholder output, or contradictions that should not be patched forward."
        }
    }
}

pub fn build_chat_artifact_validation_repair_prompt(
    title: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
    candidate: &ChatGeneratedArtifactPayload,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    let candidate_json = compact_chat_validation_json(
        &chat_artifact_validation_candidate_view(candidate),
        "Chat artifact candidate",
    )?;
    let schema_contract = chat_artifact_validation_schema_contract(request.renderer);
    let brief_focus_json = compact_chat_validation_json(
        &chat_artifact_validation_brief_focus(brief),
        "Chat artifact brief focus",
    )?;
    if renderer_uses_document_validation_context(request.renderer) {
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Chat's typed artifact validation repairer. Repair the previous validation output into a schema-valid validation result. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nBrief focus JSON:\n{}\n\nCandidate JSON:\n{}\n\nThe previous validation output was rejected.\nFailure:\n{}\n\nPrevious raw output:\n{}\n\nRepair the validation result so it is schema-valid and faithful to the candidate.\n\n{}",
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

    let request_focus_json = compact_chat_validation_json(
        &chat_artifact_validation_request_focus(request),
        "Chat artifact request focus",
    )?;
    let interaction_contract_json = compact_chat_validation_json(
        &super::chat_artifact_interaction_contract(brief),
        "Chat interaction contract",
    )?;
    let edit_focus_json = compact_chat_validation_json(
        &chat_artifact_validation_edit_focus(edit_intent),
        "Chat artifact edit intent focus",
    )?;
    Ok(json!([
        {
            "role": "system",
            "content": "You are Chat's typed artifact validation repairer. Repair the previous validation output into a schema-valid validation result. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest focus JSON:\n{}\n\nBrief focus JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent focus JSON:\n{}\n\nCandidate JSON:\n{}\n\nThe previous validation output was rejected.\nFailure:\n{}\n\nPrevious raw output:\n{}\n\nRepair the validation result so it is schema-valid and faithful to the candidate.\n\n{}",
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

fn coerce_validation_string_field(value: &mut serde_json::Value) {
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

fn coerce_optional_validation_string_field(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(_) | serde_json::Value::Null => {}
        serde_json::Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            *value = serde_json::Value::String(joined);
        }
        _ => {}
    }
}

fn coerce_validation_string_array_field(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                *value = serde_json::Value::Array(Vec::new());
            } else {
                *value =
                    serde_json::Value::Array(vec![serde_json::Value::String(trimmed.to_string())]);
            }
        }
        serde_json::Value::Array(items) => {
            let normalized = items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| serde_json::Value::String(value.to_string()))
                .collect::<Vec<_>>();
            *value = serde_json::Value::Array(normalized);
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::Array(Vec::new());
        }
        _ => {}
    }
}

fn coerce_validation_bool_field(value: &mut serde_json::Value) {
    if let serde_json::Value::String(text) = value {
        let normalized = text.trim().to_ascii_lowercase();
        if normalized == "true" {
            *value = serde_json::Value::Bool(true);
        } else if normalized == "false" {
            *value = serde_json::Value::Bool(false);
        }
    }
}

fn clamp_validation_score_value(value: &mut serde_json::Value) {
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

fn normalize_optional_validation_score_field(value: &mut serde_json::Value) {
    if value.is_null() {
        return;
    }
    clamp_validation_score_value(value);
}

fn normalize_chat_artifact_validation_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    for field in ["classification", "rationale"] {
        if let Some(entry) = object.get_mut(field) {
            coerce_validation_string_field(entry);
        }
    }
    for field in ["strongestContradiction", "recommendedNextPass"] {
        if let Some(entry) = object.get_mut(field) {
            coerce_optional_validation_string_field(entry);
        }
    }
    for field in ["aestheticVerdict", "interactionVerdict"] {
        if let Some(entry) = object.get_mut(field) {
            coerce_validation_string_field(entry);
        }
    }
    for field in [
        "issueClasses",
        "repairHints",
        "strengths",
        "blockedReasons",
        "fileFindings",
        "truthfulnessWarnings",
    ] {
        if let Some(entry) = object.get_mut(field) {
            coerce_validation_string_array_field(entry);
        }
    }
    for field in [
        "genericShellDetected",
        "trivialShellDetected",
        "deservesPrimaryArtifactView",
        "patchedExistingArtifact",
    ] {
        if let Some(entry) = object.get_mut(field) {
            coerce_validation_bool_field(entry);
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
            clamp_validation_score_value(entry);
        }
    }
    if let Some(entry) = object.get_mut("continuityRevisionUx") {
        normalize_optional_validation_score_field(entry);
    }

    let classification = object
        .get("classification")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let default_score = classification
        .as_deref()
        .map(default_plaintext_validation_score)
        .unwrap_or(3);
    for field in [
        "requestFaithfulness",
        "conceptCoverage",
        "interactionRelevance",
        "layoutCoherence",
        "visualHierarchy",
        "completeness",
    ] {
        object
            .entry(field.to_string())
            .or_insert_with(|| serde_json::Value::Number(default_score.into()));
    }
    object
        .entry("genericShellDetected".to_string())
        .or_insert(serde_json::Value::Bool(false));
    object
        .entry("trivialShellDetected".to_string())
        .or_insert(serde_json::Value::Bool(false));
    object
        .entry("deservesPrimaryArtifactView".to_string())
        .or_insert_with(|| serde_json::Value::Bool(classification.as_deref() == Some("pass")));
    if !object.contains_key("rationale") {
        let rationale = match classification.as_deref() {
            Some("pass") => {
                "Candidate satisfies the typed request well enough to lead.".to_string()
            }
            Some("blocked") => {
                "Candidate remains too incomplete or contradictory to lead.".to_string()
            }
            Some(_) => "Candidate needs repair before it should lead.".to_string(),
            None => "Validation returned a compact artifact verdict.".to_string(),
        };
        object.insert(
            "rationale".to_string(),
            serde_json::Value::String(rationale),
        );
    }
}

fn push_unique_string(values: &mut Vec<String>, value: impl Into<String>) {
    let normalized = value.into();
    let trimmed = normalized.trim();
    if trimmed.is_empty() || values.iter().any(|existing| existing == trimmed) {
        return;
    }
    values.push(trimmed.to_string());
}

fn hydrate_chat_artifact_validation_result(result: &mut ChatArtifactValidationResult) {
    if result.issue_classes.is_empty() {
        if result.generic_shell_detected {
            push_unique_string(&mut result.issue_classes, "generic_shell");
        }
        if result.trivial_shell_detected {
            push_unique_string(&mut result.issue_classes, "first_paint_incomplete");
        }
        if result.request_faithfulness <= 2 || result.concept_coverage <= 2 {
            push_unique_string(&mut result.issue_classes, "request_faithfulness");
        }
        if result.interaction_relevance <= 2 {
            push_unique_string(&mut result.issue_classes, "interaction_truthfulness");
        }
        if result.visual_hierarchy <= 2 {
            push_unique_string(&mut result.issue_classes, "art_direction");
        }
        if result.continuity_revision_ux.unwrap_or(5) <= 2 {
            push_unique_string(&mut result.issue_classes, "continuity");
        }
    }

    if result.strengths.is_empty() {
        if result.request_faithfulness >= 4 {
            push_unique_string(
                &mut result.strengths,
                "Request concepts stay visible and specific.",
            );
        }
        if result.visual_hierarchy >= 4 && !result.generic_shell_detected {
            push_unique_string(
                &mut result.strengths,
                "Hierarchy reads as deliberate instead of default scaffolding.",
            );
        }
        if result.interaction_relevance >= 4 {
            push_unique_string(
                &mut result.strengths,
                "Interactive affordances respond truthfully to the typed interaction contract.",
            );
        }
    }

    if result.repair_hints.is_empty() && result.classification != ChatArtifactValidationStatus::Pass
    {
        if result.request_faithfulness <= 3 || result.concept_coverage <= 3 {
            push_unique_string(
                &mut result.repair_hints,
                "Surface the differentiating request concepts in headings, labels, legends, and detail copy.",
            );
        }
        if result.visual_hierarchy <= 3 || result.generic_shell_detected {
            push_unique_string(
                &mut result.repair_hints,
                "Strengthen typography, spacing, and contrast so the page feels intentional rather than default.",
            );
        }
        if result.interaction_relevance <= 3 {
            push_unique_string(
                &mut result.repair_hints,
                if chat_modal_first_html_enabled() {
                    "Keep the chosen interaction grammar visibly responsive on first paint instead of falling back to decorative navigation."
                } else {
                    "Keep visible first-paint controls wired to pre-rendered panels or detail targets instead of decorative navigation."
                },
            );
        }
        if result.completeness <= 3 || result.trivial_shell_detected {
            push_unique_string(
                &mut result.repair_hints,
                "Increase first-paint evidence density with populated secondary evidence and default detail state.",
            );
        }
    }

    if result.blocked_reasons.is_empty()
        && result.classification == ChatArtifactValidationStatus::Blocked
    {
        if let Some(contradiction) = result.strongest_contradiction.clone() {
            push_unique_string(&mut result.blocked_reasons, contradiction);
        } else {
            push_unique_string(&mut result.blocked_reasons, result.rationale.clone());
        }
    }

    if result.file_findings.is_empty() {
        if let Some(contradiction) = result.strongest_contradiction.clone() {
            push_unique_string(
                &mut result.file_findings,
                format!("primary-surface: {}", contradiction),
            );
        }
    }

    if result.aesthetic_verdict.trim().is_empty() {
        result.aesthetic_verdict = if result.generic_shell_detected {
            "Visual hierarchy still reads as a generic shell.".to_string()
        } else if result.visual_hierarchy >= 4 {
            "Typography and layout feel deliberate enough to carry the artifact.".to_string()
        } else {
            "Hierarchy needs stronger typography, spacing, and emphasis cues.".to_string()
        };
    }

    if result.interaction_verdict.trim().is_empty() {
        result.interaction_verdict = if result.interaction_relevance >= 4 {
            "Interaction model is visible and materially changes the page state.".to_string()
        } else {
            "Interaction model needs clearer first-paint controls and truthful state changes."
                .to_string()
        };
    }

    if result.truthfulness_warnings.is_empty()
        && (result.request_faithfulness <= 2 || result.concept_coverage <= 2)
    {
        push_unique_string(
            &mut result.truthfulness_warnings,
            "Candidate may be substituting generic filler for the typed request concepts.",
        );
    }

    if result.recommended_next_pass.is_none() {
        result.recommended_next_pass = Some(
            match result.classification {
                ChatArtifactValidationStatus::Pass
                    if result.visual_hierarchy < 5 || result.layout_coherence < 5 =>
                {
                    "polish_pass"
                }
                ChatArtifactValidationStatus::Pass => "accept",
                ChatArtifactValidationStatus::Repairable => "structural_repair",
                ChatArtifactValidationStatus::Blocked => "hold_block",
            }
            .to_string(),
        );
    }
}

fn extract_json_value_prefix(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start();
    let first = trimmed.chars().next()?;
    match first {
        '"' => {
            let mut escaped = false;
            for (index, character) in trimmed.char_indices().skip(1) {
                if escaped {
                    escaped = false;
                    continue;
                }
                match character {
                    '\\' => escaped = true,
                    '"' => return Some(trimmed[..=index].to_string()),
                    _ => {}
                }
            }
            None
        }
        '[' | '{' => {
            let mut depth = 0usize;
            let mut in_string = false;
            let mut escaped = false;
            for (index, character) in trimmed.char_indices() {
                if in_string {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    match character {
                        '\\' => escaped = true,
                        '"' => in_string = false,
                        _ => {}
                    }
                    continue;
                }
                match character {
                    '"' => in_string = true,
                    '[' | '{' => depth += 1,
                    ']' | '}' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return Some(trimmed[..=index].to_string());
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        _ => {
            let end = trimmed.find([',', '}', ']']).unwrap_or(trimmed.len());
            let candidate = trimmed[..end].trim();
            if candidate.is_empty() {
                None
            } else {
                Some(candidate.to_string())
            }
        }
    }
}

fn extract_truncated_json_named_value(raw: &str, field: &str) -> Option<serde_json::Value> {
    let pattern = format!("\"{field}\"");
    let start = raw.find(&pattern)?;
    let remainder = &raw[start + pattern.len()..];
    let colon_index = remainder.find(':')?;
    let value = extract_json_value_prefix(&remainder[colon_index + 1..])?;
    serde_json::from_str::<serde_json::Value>(&value).ok()
}

fn recover_truncated_chat_artifact_validation_json_value(raw: &str) -> Option<serde_json::Value> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('{') {
        return None;
    }

    let mut object = serde_json::Map::new();
    for field in [
        "classification",
        "requestFaithfulness",
        "conceptCoverage",
        "interactionRelevance",
        "layoutCoherence",
        "visualHierarchy",
        "completeness",
        "genericShellDetected",
        "trivialShellDetected",
        "deservesPrimaryArtifactView",
        "patchedExistingArtifact",
        "continuityRevisionUx",
        "issueClasses",
        "repairHints",
        "strengths",
        "blockedReasons",
        "fileFindings",
        "aestheticVerdict",
        "interactionVerdict",
        "truthfulnessWarnings",
        "recommendedNextPass",
        "strongestContradiction",
        "rationale",
    ] {
        if let Some(value) = extract_truncated_json_named_value(trimmed, field) {
            object.insert(field.to_string(), value);
        }
    }

    let classification = object
        .get("classification")
        .and_then(serde_json::Value::as_str)?
        .to_string();
    let default_score = default_plaintext_validation_score(&classification);
    for field in [
        "requestFaithfulness",
        "conceptCoverage",
        "interactionRelevance",
        "layoutCoherence",
        "visualHierarchy",
        "completeness",
    ] {
        object
            .entry(field.to_string())
            .or_insert_with(|| serde_json::Value::Number(default_score.into()));
    }
    object
        .entry("genericShellDetected".to_string())
        .or_insert(serde_json::Value::Bool(false));
    object
        .entry("trivialShellDetected".to_string())
        .or_insert(serde_json::Value::Bool(false));
    object
        .entry("deservesPrimaryArtifactView".to_string())
        .or_insert(serde_json::Value::Bool(classification == "pass"));
    if !object.contains_key("rationale") {
        object.insert(
            "rationale".to_string(),
            serde_json::Value::String(fallback_plaintext_validation_rationale(
                &classification,
                &object,
                &[],
            )),
        );
    }

    Some(serde_json::Value::Object(object))
}

fn normalize_plaintext_validation_label(label: &str) -> String {
    label
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn strip_plaintext_validation_bullet_prefix(line: &str) -> &str {
    let trimmed = line.trim();
    for prefix in ["- ", "* ", "+ "] {
        if let Some(stripped) = trimmed.strip_prefix(prefix) {
            return stripped.trim_start();
        }
    }

    let bytes = trimmed.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index > 0
        && index < bytes.len()
        && (bytes[index] == b'.' || bytes[index] == b')')
        && index + 1 < bytes.len()
        && bytes[index + 1].is_ascii_whitespace()
    {
        return trimmed[index + 2..].trim_start();
    }

    trimmed
}

fn parse_plaintext_validation_score(value: &str) -> Option<u64> {
    let mut token = String::new();
    let mut started = false;
    for character in value.chars() {
        if !started {
            if character.is_ascii_digit() {
                started = true;
                token.push(character);
            }
            continue;
        }

        if character.is_ascii_digit() || character == '.' {
            token.push(character);
            continue;
        }
        break;
    }

    if token.is_empty() {
        return None;
    }

    token
        .parse::<f64>()
        .ok()
        .map(|numeric| numeric.round().clamp(1.0, 5.0) as u64)
}

fn parse_plaintext_validation_bool(value: &str) -> Option<bool> {
    let normalized = normalize_plaintext_validation_label(value);
    match normalized.as_str() {
        "true" | "yes" | "y" => Some(true),
        "false" | "no" | "n" => Some(false),
        _ => None,
    }
}

fn parse_plaintext_validation_classification(value: &str) -> Option<&'static str> {
    let trimmed = value.trim().trim_end_matches(',');
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end_index) = rest.find('"') {
            return parse_plaintext_validation_classification(&rest[..end_index]);
        }
    }

    let normalized = normalize_plaintext_validation_label(value);
    let leading = normalized
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    if matches!(leading.as_str(), "repairable" | "needs repair") {
        Some("repairable")
    } else if matches!(leading.as_str(), "blocked" | "block") {
        Some("blocked")
    } else if matches!(leading.as_str(), "pass" | "passed" | "accept" | "accepted")
        || normalized.starts_with("overall pass")
        || normalized.starts_with("classification pass")
        || normalized.starts_with("verdict pass")
    {
        Some("pass")
    } else {
        None
    }
}

fn parse_plaintext_validation_next_pass(value: &str) -> Option<&'static str> {
    let trimmed = value.trim().trim_end_matches(',');
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end_index) = rest.find('"') {
            return parse_plaintext_validation_next_pass(&rest[..end_index]);
        }
    }

    let normalized = normalize_plaintext_validation_label(trimmed);
    if normalized.contains("structural repair") || normalized == "repair" {
        Some("structural_repair")
    } else if normalized.contains("polish pass") || normalized == "polish" {
        Some("polish_pass")
    } else if normalized.contains("hold block") || normalized == "hold" || normalized == "block" {
        Some("hold_block")
    } else if normalized.contains("accept") {
        Some("accept")
    } else {
        None
    }
}

fn parse_plaintext_validation_list(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let normalized = normalize_plaintext_validation_label(trimmed);
    if matches!(normalized.as_str(), "none" | "n a" | "na" | "null") {
        return Vec::new();
    }
    if let Ok(parsed) = serde_json::from_str::<Vec<String>>(trimmed) {
        return parsed
            .into_iter()
            .map(|entry| entry.trim().to_string())
            .filter(|entry| !entry.is_empty())
            .collect();
    }
    trimmed
        .split([',', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

fn push_plaintext_validation_list_entry(
    object: &mut serde_json::Map<String, serde_json::Value>,
    field: &'static str,
    entry: impl Into<String>,
) {
    let entry = entry.into();
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return;
    }

    let values = object
        .entry(field.to_string())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    let Some(array) = values.as_array_mut() else {
        *values = serde_json::Value::Array(Vec::new());
        return push_plaintext_validation_list_entry(object, field, trimmed.to_string());
    };
    if array
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|existing| existing == trimmed)
    {
        return;
    }
    array.push(serde_json::Value::String(trimmed.to_string()));
}

fn map_plaintext_validation_field(label: &str) -> Option<(&'static str, bool)> {
    match normalize_plaintext_validation_label(label).as_str() {
        "classification" | "overall classification" | "overall verdict" | "verdict" => {
            Some(("classification", false))
        }
        "request faithfulness" | "faithfulness" => Some(("requestFaithfulness", false)),
        "concept coverage" | "coverage" => Some(("conceptCoverage", false)),
        "interaction relevance" => Some(("interactionRelevance", false)),
        "layout coherence" => Some(("layoutCoherence", false)),
        "visual hierarchy" => Some(("visualHierarchy", false)),
        "completeness" | "complete" => Some(("completeness", false)),
        "generic shell detected" | "generic shell" | "generic" => {
            Some(("genericShellDetected", false))
        }
        "trivial shell detected" | "trivial shell" | "trivial" => {
            Some(("trivialShellDetected", false))
        }
        "deserves primary artifact view" | "deserves primary view" | "primary artifact view" => {
            Some(("deservesPrimaryArtifactView", false))
        }
        "primary" => Some(("deservesPrimaryArtifactView", false)),
        "patched existing artifact" => Some(("patchedExistingArtifact", false)),
        "continuity revision ux" | "continuity ux" => Some(("continuityRevisionUx", false)),
        "issue classes" | "issues" => Some(("issueClasses", true)),
        "repair hints" | "repair suggestions" | "repairs" => Some(("repairHints", true)),
        "strengths" | "strength" => Some(("strengths", true)),
        "blocked reasons" | "blocked reason" | "blockers" | "reasons blocked" => {
            Some(("blockedReasons", true))
        }
        "file findings" | "file finding" | "findings" => Some(("fileFindings", true)),
        "aesthetic verdict" | "aesthetic" | "design verdict" => Some(("aestheticVerdict", false)),
        "interaction verdict" | "interaction assessment" => Some(("interactionVerdict", false)),
        "truthfulness warnings" | "truthfulness warning" | "warnings" => {
            Some(("truthfulnessWarnings", true))
        }
        "recommended next pass" | "next pass" | "recommended action" | "next" => {
            Some(("recommendedNextPass", false))
        }
        "strongest contradiction" | "contradiction" => Some(("strongestContradiction", false)),
        "rationale" | "reasoning" | "summary" | "why" => Some(("rationale", false)),
        _ => None,
    }
}

fn default_plaintext_validation_score(classification: &str) -> u64 {
    match classification {
        "pass" => 4,
        "blocked" => 1,
        _ => 3,
    }
}

fn fallback_plaintext_validation_rationale(
    classification: &str,
    object: &serde_json::Map<String, serde_json::Value>,
    free_text: &[String],
) -> String {
    if let Some(line) = free_text
        .first()
        .map(String::as_str)
        .filter(|line| !line.is_empty())
    {
        return truncate_chat_validation_text(line, 240);
    }
    for field in [
        "strongestContradiction",
        "aestheticVerdict",
        "interactionVerdict",
    ] {
        if let Some(text) = object.get(field).and_then(serde_json::Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return truncate_chat_validation_text(trimmed, 240);
            }
        }
    }
    for field in [
        "blockedReasons",
        "repairHints",
        "strengths",
        "fileFindings",
        "truthfulnessWarnings",
    ] {
        if let Some(text) = object
            .get(field)
            .and_then(serde_json::Value::as_array)
            .and_then(|values| values.first())
            .and_then(serde_json::Value::as_str)
        {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return truncate_chat_validation_text(trimmed, 240);
            }
        }
    }

    match classification {
        "pass" => "Recovered pass validation result from plaintext output.".to_string(),
        "blocked" => "Recovered blocked validation result from plaintext output.".to_string(),
        _ => "Recovered repairable validation result from plaintext output.".to_string(),
    }
}

fn recover_plaintext_chat_artifact_validation_value(raw: &str) -> Option<serde_json::Value> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut object = serde_json::Map::new();
    let mut current_list_field = None::<&'static str>;
    let mut free_text = Vec::new();
    let mut first_content_line = None::<String>;

    for line in trimmed.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() {
            current_list_field = None;
            continue;
        }
        if trimmed_line.starts_with("```") {
            continue;
        }

        let content = strip_plaintext_validation_bullet_prefix(trimmed_line);
        let line_is_list_entry = content.len() != trimmed_line.len();
        if first_content_line.is_none() && !content.is_empty() {
            first_content_line = Some(content.to_string());
        }

        if let Some((label, value)) = content.split_once(':') {
            if let Some((field, is_list)) = map_plaintext_validation_field(label) {
                let value = value.trim();
                current_list_field = if is_list { Some(field) } else { None };
                match field {
                    "classification" => {
                        if let Some(classification) =
                            parse_plaintext_validation_classification(value)
                        {
                            object.insert(
                                field.to_string(),
                                serde_json::Value::String(classification.to_string()),
                            );
                        }
                    }
                    "recommendedNextPass" => {
                        if let Some(next_pass) = parse_plaintext_validation_next_pass(value) {
                            object.insert(
                                field.to_string(),
                                serde_json::Value::String(next_pass.to_string()),
                            );
                        }
                    }
                    "requestFaithfulness"
                    | "conceptCoverage"
                    | "interactionRelevance"
                    | "layoutCoherence"
                    | "visualHierarchy"
                    | "completeness"
                    | "continuityRevisionUx" => {
                        if let Some(score) = parse_plaintext_validation_score(value) {
                            object
                                .insert(field.to_string(), serde_json::Value::Number(score.into()));
                        }
                    }
                    "genericShellDetected"
                    | "trivialShellDetected"
                    | "deservesPrimaryArtifactView"
                    | "patchedExistingArtifact" => {
                        if let Some(flag) = parse_plaintext_validation_bool(value) {
                            object.insert(field.to_string(), serde_json::Value::Bool(flag));
                        }
                    }
                    "issueClasses"
                    | "repairHints"
                    | "strengths"
                    | "blockedReasons"
                    | "fileFindings"
                    | "truthfulnessWarnings" => {
                        for entry in parse_plaintext_validation_list(value) {
                            push_plaintext_validation_list_entry(&mut object, field, entry);
                        }
                    }
                    _ => {
                        if !value.is_empty() {
                            object.insert(
                                field.to_string(),
                                serde_json::Value::String(value.to_string()),
                            );
                        }
                    }
                }
                continue;
            }
        }

        if let Some(field) = current_list_field.filter(|_| line_is_list_entry) {
            push_plaintext_validation_list_entry(&mut object, field, content.to_string());
            continue;
        }

        free_text.push(content.to_string());
    }

    if !object.contains_key("classification") {
        if let Some(line) = first_content_line
            .as_deref()
            .filter(|line| line.chars().count() <= 48)
        {
            if let Some(classification) = parse_plaintext_validation_classification(line) {
                if free_text.first().map(String::as_str) == Some(line) {
                    free_text.remove(0);
                }
                object.insert(
                    "classification".to_string(),
                    serde_json::Value::String(classification.to_string()),
                );
            }
        }
    }

    let classification = object
        .get("classification")
        .and_then(serde_json::Value::as_str)?
        .to_string();
    let default_score = default_plaintext_validation_score(&classification);
    for field in [
        "requestFaithfulness",
        "conceptCoverage",
        "interactionRelevance",
        "layoutCoherence",
        "visualHierarchy",
        "completeness",
    ] {
        object
            .entry(field.to_string())
            .or_insert_with(|| serde_json::Value::Number(default_score.into()));
    }
    object
        .entry("genericShellDetected".to_string())
        .or_insert(serde_json::Value::Bool(false));
    object
        .entry("trivialShellDetected".to_string())
        .or_insert(serde_json::Value::Bool(false));
    object
        .entry("deservesPrimaryArtifactView".to_string())
        .or_insert(serde_json::Value::Bool(classification == "pass"));

    if !object.contains_key("rationale") {
        object.insert(
            "rationale".to_string(),
            serde_json::Value::String(fallback_plaintext_validation_rationale(
                &classification,
                &object,
                &free_text,
            )),
        );
    }

    Some(serde_json::Value::Object(object))
}

pub fn parse_chat_artifact_validation_result(
    raw: &str,
) -> Result<ChatArtifactValidationResult, String> {
    let mut value = match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(value) => value,
        Err(initial_error) => {
            if let Some(extracted) = super::extract_first_json_object(raw) {
                serde_json::from_str::<serde_json::Value>(&extracted).map_err(|error| {
                    format!("Failed to parse Chat artifact validation result: {error}")
                })?
            } else if let Some(recovered) =
                recover_truncated_chat_artifact_validation_json_value(raw)
            {
                chat_validation_trace("artifact_validation:truncated_json_recovery");
                recovered
            } else if let Some(recovered) = recover_plaintext_chat_artifact_validation_value(raw) {
                chat_validation_trace("artifact_validation:plaintext_recovery");
                recovered
            } else {
                return Err(format!(
                    "Failed to parse Chat artifact validation result: {}",
                    if initial_error.is_eof() {
                        "Chat artifact validation output missing JSON payload".to_string()
                    } else {
                        initial_error.to_string()
                    }
                ));
            }
        }
    };
    normalize_chat_artifact_validation_value(&mut value);
    let mut result = serde_json::from_value::<ChatArtifactValidationResult>(value)
        .map_err(|error| format!("Failed to parse Chat artifact validation result: {error}"))?;
    hydrate_chat_artifact_validation_result(&mut result);

    for score in [
        result.request_faithfulness,
        result.concept_coverage,
        result.interaction_relevance,
        result.layout_coherence,
        result.visual_hierarchy,
        result.completeness,
    ] {
        if !(1..=5).contains(&score) {
            return Err("Chat artifact validation scores must stay within 1..=5.".to_string());
        }
    }

    if result.rationale.trim().is_empty() {
        return Err("Chat artifact validation rationale must not be empty.".to_string());
    }

    Ok(result)
}

pub(crate) fn candidate_generation_config(
    renderer: ChatRendererKind,
    production_kind: ChatRuntimeProvenanceKind,
) -> (usize, f32, &'static str) {
    match renderer {
        ChatRendererKind::HtmlIframe
            if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime =>
        {
            if chat_modal_first_html_enabled() {
                (1, 0.72, "request-grounded_html")
            } else {
                (2, 0.54, "request-grounded_html")
            }
        }
        ChatRendererKind::HtmlIframe => (3, 0.6, "request-grounded_html"),
        ChatRendererKind::JsxSandbox => (2, 0.5, "interaction-first_jsx"),
        ChatRendererKind::Svg => (2, 0.48, "motif-first_svg"),
        ChatRendererKind::Markdown
            if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime =>
        {
            (1, 0.22, "outline-first_markdown")
        }
        ChatRendererKind::Markdown => (2, 0.22, "outline-first_markdown"),
        ChatRendererKind::Mermaid
            if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime =>
        {
            (1, 0.18, "pipeline-first_mermaid")
        }
        ChatRendererKind::Mermaid => (2, 0.18, "pipeline-first_mermaid"),
        ChatRendererKind::PdfEmbed
            if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime =>
        {
            (1, 0.2, "brief-first_pdf")
        }
        ChatRendererKind::PdfEmbed => (2, 0.2, "brief-first_pdf"),
        ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest
            if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime =>
        {
            (1, 0.12, "bundle-first_download")
        }
        ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest => {
            (2, 0.12, "bundle-first_download")
        }
        ChatRendererKind::WorkspaceSurface => (1, 0.0, "workspace"),
    }
}

fn chat_artifact_validation_candidate_view(
    candidate: &ChatGeneratedArtifactPayload,
) -> serde_json::Value {
    chat_artifact_validation_candidate_view_for_runtime(
        candidate,
        ChatRendererKind::HtmlIframe,
        ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn chat_artifact_validation_candidate_view_for_runtime(
    candidate: &ChatGeneratedArtifactPayload,
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> serde_json::Value {
    let compact_document_prompt = compact_local_document_validation_prompt(renderer, runtime_kind);
    let note_limit = if compact_document_prompt { 1 } else { 6 };
    let summary_limit = if compact_document_prompt { 120 } else { 320 };
    let body_preview_limit = if compact_document_prompt { 80 } else { 1200 };
    json!({
        "summary": truncate_chat_validation_text(&candidate.summary, summary_limit),
        "notes": candidate
            .notes
            .iter()
            .take(note_limit)
            .map(|note| truncate_chat_validation_text(note, 220))
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
                    "bodyPreview": truncate_chat_validation_text(&file.body, body_preview_limit),
                })
            })
            .collect::<Vec<_>>(),
    })
}

pub(crate) fn chat_artifact_refinement_candidate_view(
    candidate: &ChatGeneratedArtifactPayload,
) -> serde_json::Value {
    json!({
        "summary": truncate_chat_validation_text(&candidate.summary, 400),
        "notes": candidate
            .notes
            .iter()
            .take(8)
            .map(|note| truncate_chat_validation_text(note, 240))
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
                    "bodyPreview": truncate_chat_validation_text(&file.body, 3200),
                })
            })
            .collect::<Vec<_>>(),
    })
}

pub(crate) fn chat_artifact_refinement_context_view(
    refinement: Option<&ChatArtifactRefinementContext>,
) -> serde_json::Value {
    let Some(refinement) = refinement else {
        return serde_json::Value::Null;
    };

    json!({
        "artifactId": refinement.artifact_id,
        "revisionId": refinement.revision_id,
        "title": truncate_chat_validation_text(&refinement.title, 240),
        "summary": truncate_chat_validation_text(&refinement.summary, 400),
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
                    "bodyPreview": truncate_chat_validation_text(&file.body, 1800),
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
                    "label": truncate_chat_validation_text(&target.label, 120),
                    "snippet": truncate_chat_validation_text(&target.snippet, 400),
                })
            })
            .collect::<Vec<_>>(),
        "tasteMemory": refinement.taste_memory,
        "retrievedExemplars": refinement
            .retrieved_exemplars
            .iter()
            .map(|exemplar| {
                json!({
                    "recordId": exemplar.record_id,
                    "title": truncate_chat_validation_text(&exemplar.title, 120),
                    "summary": truncate_chat_validation_text(&exemplar.summary, 200),
                    "renderer": exemplar.renderer,
                    "scaffoldFamily": exemplar.scaffold_family,
                    "scoreTotal": exemplar.score_total,
                    "designCues": exemplar.design_cues,
                    "componentPatterns": exemplar.component_patterns,
                    "antiPatterns": exemplar.anti_patterns,
                })
            })
            .collect::<Vec<_>>(),
        "blueprint": refinement.blueprint.as_ref().map(|blueprint| {
            json!({
                "renderer": blueprint.renderer,
                "scaffoldFamily": blueprint.scaffold_family,
                "narrativeArc": truncate_chat_validation_text(&blueprint.narrative_arc, 240),
                "sectionPlan": blueprint
                    .section_plan
                    .iter()
                    .map(|section| {
                        json!({
                            "id": section.id,
                            "role": section.role,
                            "visiblePurpose": truncate_chat_validation_text(&section.visible_purpose, 180),
                        })
                    })
                    .collect::<Vec<_>>(),
                "interactionPlan": blueprint
                    .interaction_plan
                    .iter()
                    .map(|interaction| {
                        json!({
                            "id": interaction.id,
                            "family": interaction.family,
                            "defaultState": interaction.default_state,
                        })
                    })
                    .collect::<Vec<_>>(),
                "skillNeeds": blueprint.skill_needs,
            })
        }),
        "artifactIr": refinement.artifact_ir.as_ref().map(|artifact_ir| {
            json!({
                "renderer": artifact_ir.renderer,
                "scaffoldFamily": artifact_ir.scaffold_family,
                "semanticNodeCount": artifact_ir.semantic_structure.len(),
                "interactionCount": artifact_ir.interaction_graph.len(),
                "evidenceSurfaceCount": artifact_ir.evidence_surfaces.len(),
                "renderEvalChecklist": artifact_ir.render_eval_checklist,
            })
        }),
        "selectedSkills": refinement
            .selected_skills
            .iter()
            .map(|skill| {
                json!({
                    "name": skill.name,
                    "matchedNeedKinds": skill.matched_need_kinds,
                    "matchRationale": truncate_chat_validation_text(&skill.match_rationale, 180),
                    "guidanceMarkdown": skill.guidance_markdown.as_ref().map(|markdown| truncate_chat_validation_text(markdown, 240)),
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn truncate_chat_validation_text(text: &str, max_chars: usize) -> String {
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
    let provenance = runtime.chat_runtime_provenance();
    provenance
        .model
        .clone()
        .unwrap_or_else(|| provenance.label.clone())
}

pub(crate) fn output_origin_from_provenance(
    provenance: &ChatRuntimeProvenance,
) -> ChatArtifactOutputOrigin {
    match provenance.kind {
        ChatRuntimeProvenanceKind::RealRemoteModelRuntime
        | ChatRuntimeProvenanceKind::RealLocalRuntime => ChatArtifactOutputOrigin::LiveInference,
        ChatRuntimeProvenanceKind::FixtureRuntime => ChatArtifactOutputOrigin::FixtureRuntime,
        ChatRuntimeProvenanceKind::MockRuntime => ChatArtifactOutputOrigin::MockInference,
        ChatRuntimeProvenanceKind::DeterministicContinuityFallback => {
            ChatArtifactOutputOrigin::DeterministicFallback
        }
        ChatRuntimeProvenanceKind::InferenceUnavailable => {
            ChatArtifactOutputOrigin::InferenceUnavailable
        }
        ChatRuntimeProvenanceKind::OpaqueRuntime => ChatArtifactOutputOrigin::OpaqueRuntime,
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

pub(crate) fn materialization_max_tokens(renderer: ChatRendererKind) -> u32 {
    match renderer {
        ChatRendererKind::HtmlIframe => 2800,
        ChatRendererKind::JsxSandbox => 1800,
        ChatRendererKind::Svg => 1200,
        ChatRendererKind::Markdown => 900,
        ChatRendererKind::Mermaid => 700,
        ChatRendererKind::PdfEmbed => 1200,
        ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest => 420,
        ChatRendererKind::WorkspaceSurface => 2000,
    }
}

fn validation_max_tokens(renderer: ChatRendererKind) -> u32 {
    match renderer {
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox | ChatRendererKind::Svg => 192,
        ChatRendererKind::Markdown
        | ChatRendererKind::Mermaid
        | ChatRendererKind::PdfEmbed
        | ChatRendererKind::DownloadCard
        | ChatRendererKind::BundleManifest
        | ChatRendererKind::WorkspaceSurface => 160,
    }
}

fn validation_max_tokens_for_runtime(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> u32 {
    if ultra_compact_local_markdown_validation_prompt(renderer, runtime_kind) {
        48
    } else if compact_local_html_validation_prompt(renderer, runtime_kind) {
        96
    } else if compact_local_download_bundle_validation_prompt(renderer, runtime_kind) {
        56
    } else if compact_local_document_validation_prompt(renderer, runtime_kind) {
        80
    } else {
        validation_max_tokens(renderer)
    }
}

fn validation_repair_max_tokens(renderer: ChatRendererKind) -> u32 {
    match renderer {
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox | ChatRendererKind::Svg => 256,
        ChatRendererKind::Markdown
        | ChatRendererKind::Mermaid
        | ChatRendererKind::PdfEmbed
        | ChatRendererKind::DownloadCard
        | ChatRendererKind::BundleManifest
        | ChatRendererKind::WorkspaceSurface => 224,
    }
}

fn validation_repair_max_tokens_for_runtime(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> u32 {
    if ultra_compact_local_markdown_validation_prompt(renderer, runtime_kind) {
        64
    } else if compact_local_html_validation_prompt(renderer, runtime_kind) {
        112
    } else if compact_local_download_bundle_validation_prompt(renderer, runtime_kind) {
        72
    } else if compact_local_document_validation_prompt(renderer, runtime_kind) {
        96
    } else {
        validation_repair_max_tokens(renderer)
    }
}

pub(crate) fn semantic_refinement_pass_limit(
    renderer: ChatRendererKind,
    production_kind: ChatRuntimeProvenanceKind,
) -> usize {
    match renderer {
        ChatRendererKind::HtmlIframe
            if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime =>
        {
            if chat_modal_first_html_enabled() {
                1
            } else {
                2
            }
        }
        ChatRendererKind::HtmlIframe => 2,
        ChatRendererKind::JsxSandbox | ChatRendererKind::Svg => 1,
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

pub(crate) fn html_first_paint_section_blueprint(brief: &ChatArtifactBrief) -> String {
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
    let required_interactions = brief.required_interaction_summaries();
    let detail_focus = required_interactions
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

    if chat_modal_first_html_enabled() {
        return format!(
            "1) overview section that states {overview_focus}; 2) one interaction seam that lets the audience inspect {control_focus}; 3) primary evidence section that visualizes {primary_evidence} with visible marks, labels, or comparative values on first paint; 4) secondary evidence section or comparison article that surfaces {secondary_evidence}; 5) contextual annotations, captions, callouts, or inline detail that explain {detail_focus}; 6) supporting footer/aside callouts grounded in {anchor_focus}"
        );
    }

    format!(
        "1) overview section that states {overview_focus}; 2) named control bar that lets the audience inspect {control_focus}; 3) primary evidence section that visualizes {primary_evidence} with visible marks, labels, or comparative values on first paint; 4) secondary evidence section or comparison article that surfaces {secondary_evidence}; 5) shared detail/comparison aside that reacts to controls and explains {detail_focus}; 6) supporting footer/aside callouts grounded in {anchor_focus}"
    )
}

fn validation_rank(classification: ChatArtifactValidationStatus) -> u8 {
    match classification {
        ChatArtifactValidationStatus::Pass => 3,
        ChatArtifactValidationStatus::Repairable => 2,
        ChatArtifactValidationStatus::Blocked => 1,
    }
}

pub(crate) fn validation_total_score(validation: &ChatArtifactValidationResult) -> i32 {
    (validation_rank(validation.classification) as i32) * 100
        + (validation.request_faithfulness as i32) * 12
        + (validation.concept_coverage as i32) * 10
        + (validation.interaction_relevance as i32) * 8
        + (validation.layout_coherence as i32) * 7
        + (validation.visual_hierarchy as i32) * 7
        + (validation.completeness as i32) * 9
        + if validation.deserves_primary_artifact_view {
            12
        } else {
            -20
        }
        + if validation.generic_shell_detected {
            -28
        } else {
            0
        }
        + if validation.trivial_shell_detected {
            -36
        } else {
            0
        }
        - (validation.issue_classes.len() as i32) * 4
        - (validation.truthfulness_warnings.len() as i32) * 6
        - (validation.blocked_reasons.len() as i32) * 8
        + (validation.strengths.len() as i32) * 3
        + validation.continuity_revision_ux.unwrap_or(0) as i32
}

pub(crate) fn validation_clears_primary_view(validation: &ChatArtifactValidationResult) -> bool {
    let strong_repairable_primary = validation.classification
        == ChatArtifactValidationStatus::Repairable
        && validation.deserves_primary_artifact_view
        && validation.request_faithfulness >= 4
        && validation.concept_coverage >= 4
        && validation.interaction_relevance >= 3
        && validation.layout_coherence >= 4
        && validation.visual_hierarchy >= 4
        && validation.completeness >= 4
        && !validation.issue_classes.is_empty()
        && validation
            .issue_classes
            .iter()
            .all(|issue| issue == "interaction_change_weak");

    (validation.classification == ChatArtifactValidationStatus::Pass || strong_repairable_primary)
        && validation.deserves_primary_artifact_view
        && !validation.generic_shell_detected
        && !validation.trivial_shell_detected
        && validation.truthfulness_warnings.is_empty()
}

pub(crate) fn renderer_supports_semantic_refinement(renderer: ChatRendererKind) -> bool {
    matches!(
        renderer,
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox | ChatRendererKind::Svg
    )
}
