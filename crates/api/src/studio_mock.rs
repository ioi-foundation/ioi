use crate::studio::{
    parse_studio_artifact_brief, parse_studio_artifact_edit_intent,
    parse_studio_generated_artifact_payload, StudioArtifactBrief, StudioArtifactEditIntent,
    StudioArtifactEditMode, StudioArtifactRefinementContext, StudioArtifactSelectionTarget,
    StudioArtifactTasteMemory, StudioArtifactValidationResult, StudioArtifactValidationStatus,
    StudioGeneratedArtifactFile, StudioGeneratedArtifactPayload,
};
use ioi_types::app::{
    StudioArtifactClass, StudioArtifactFileRole, StudioOutcomeArtifactRequest,
    StudioOutcomeArtifactScope, StudioOutcomeArtifactVerificationRequest, StudioRendererKind,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

const STOP_WORDS: &[&str] = &[
    "a",
    "an",
    "and",
    "artifact",
    "build",
    "bundle",
    "create",
    "diagram",
    "document",
    "edit",
    "explains",
    "for",
    "html",
    "interactive",
    "it",
    "jsx",
    "make",
    "markdown",
    "more",
    "of",
    "only",
    "page",
    "pdf",
    "project",
    "render",
    "replace",
    "section",
    "show",
    "source",
    "style",
    "summarizes",
    "svg",
    "that",
    "the",
    "this",
    "with",
    "workspace",
];

const REFINEMENT_OPERATION_WORDS: &[&str] = &[
    "branch",
    "discarding",
    "existing",
    "feel",
    "hero",
    "identity",
    "keep",
    "patch",
    "preserve",
    "same",
    "structure",
    "targeted",
    "tone",
];

#[derive(Debug, Clone)]
struct PromptAnalysis {
    subject_domain: String,
    short_subject: String,
    audience: String,
    tone_tags: Vec<String>,
    style_directives: Vec<String>,
    required_concepts: Vec<String>,
    required_interactions: Vec<String>,
    factual_anchors: Vec<String>,
}

pub(crate) fn maybe_handle_studio_prompt(input: &str) -> Option<String> {
    let normalized = normalize_prompt_input(input);
    if normalized.contains("Studio's typed outcome router") {
        return Some(mock_route_payload(&normalized).to_string());
    }
    if normalized.contains("Studio's typed artifact brief planner") {
        return Some(mock_brief_payload(&normalized).to_string());
    }
    if normalized.contains("Studio's typed artifact brief field repairer") {
        return Some(mock_brief_payload(&normalized).to_string());
    }
    if normalized.contains("Studio's typed artifact edit-intent planner") {
        return Some(mock_edit_intent_payload(&normalized).to_string());
    }
    if normalized.contains("Studio's typed artifact materialization repairer")
        || normalized.contains("Studio's typed artifact refiner")
    {
        return Some(mock_materialization_payload(&normalized).to_string());
    }
    if normalized.contains("Studio's typed artifact materializer") {
        return Some(mock_materialization_payload(&normalized).to_string());
    }
    if normalized.contains("Studio's typed artifact validation repairer") {
        return Some(mock_validation_payload(&normalized).to_string());
    }
    if normalized.contains("Studio's typed artifact validation") {
        return Some(mock_validation_payload(&normalized).to_string());
    }
    None
}

fn normalize_prompt_input(input: &str) -> String {
    let Some(value) = serde_json::from_str::<Value>(input).ok() else {
        return input.to_string();
    };
    let mut parts = Vec::new();
    collect_prompt_content(&value, &mut parts);
    if parts.is_empty() {
        input.to_string()
    } else {
        parts.join("\n\n")
    }
}

fn collect_prompt_content(value: &Value, parts: &mut Vec<String>) {
    match value {
        Value::Array(values) => {
            for entry in values {
                collect_prompt_content(entry, parts);
            }
        }
        Value::Object(map) => {
            if let Some(content) = map.get("content") {
                collect_prompt_content(content, parts);
            }
        }
        Value::String(text) => {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                parts.push(trimmed.to_string());
            }
        }
        _ => {}
    }
}

fn mock_route_payload(input: &str) -> Value {
    let prompt =
        extract_text_block(input, "Request:\n", "\n\nActive artifact id:").unwrap_or_default();
    let lower = prompt.to_ascii_lowercase();

    let artifact = if lower.contains("workspace") || lower.contains("billing settings surface") {
        Some(json!({
            "artifactClass": "workspace_project",
            "deliverableShape": "workspace_project",
            "renderer": "workspace_surface",
            "presentationSurface": "tabbed_panel",
            "persistence": "workspace_filesystem",
            "executionSubstrate": "workspace_runtime",
            "workspaceRecipeId": "vite-static-html",
            "presentationVariantId": null,
            "scope": {
                "targetProject": "studio-workspace",
                "createNewWorkspace": true,
                "mutationBoundary": ["workspace"]
            },
            "verification": {
                "requireRender": true,
                "requireBuild": true,
                "requirePreview": true,
                "requireExport": false,
                "requireDiffReview": true
            }
        }))
    } else if lower.contains("markdown") || lower.contains("checklist") {
        Some(json!({
            "artifactClass": "document",
            "deliverableShape": "single_file",
            "renderer": "markdown",
            "presentationSurface": "side_panel",
            "persistence": "artifact_scoped",
            "executionSubstrate": "none",
            "workspaceRecipeId": null,
            "presentationVariantId": null,
            "scope": {
                "targetProject": null,
                "createNewWorkspace": false,
                "mutationBoundary": ["artifact"]
            },
            "verification": {
                "requireRender": true,
                "requireBuild": false,
                "requirePreview": false,
                "requireExport": true,
                "requireDiffReview": false
            }
        }))
    } else if lower.contains("jsx") || lower.contains("configurator") {
        Some(json!({
            "artifactClass": "interactive_single_file",
            "deliverableShape": "single_file",
            "renderer": "jsx_sandbox",
            "presentationSurface": "inline",
            "persistence": "artifact_scoped",
            "executionSubstrate": "client_sandbox",
            "workspaceRecipeId": null,
            "presentationVariantId": null,
            "scope": {
                "targetProject": null,
                "createNewWorkspace": false,
                "mutationBoundary": ["artifact"]
            },
            "verification": {
                "requireRender": true,
                "requireBuild": false,
                "requirePreview": false,
                "requireExport": true,
                "requireDiffReview": false
            }
        }))
    } else if lower.contains("svg") || lower.contains("hero concept") {
        Some(json!({
            "artifactClass": "visual",
            "deliverableShape": "single_file",
            "renderer": "svg",
            "presentationSurface": "inline",
            "persistence": "artifact_scoped",
            "executionSubstrate": "none",
            "workspaceRecipeId": null,
            "presentationVariantId": null,
            "scope": {
                "targetProject": null,
                "createNewWorkspace": false,
                "mutationBoundary": ["artifact"]
            },
            "verification": {
                "requireRender": true,
                "requireBuild": false,
                "requirePreview": false,
                "requireExport": true,
                "requireDiffReview": false
            }
        }))
    } else if lower.contains("mermaid") || lower.contains("approval pipeline") {
        Some(json!({
            "artifactClass": "visual",
            "deliverableShape": "single_file",
            "renderer": "mermaid",
            "presentationSurface": "inline",
            "persistence": "artifact_scoped",
            "executionSubstrate": "none",
            "workspaceRecipeId": null,
            "presentationVariantId": null,
            "scope": {
                "targetProject": null,
                "createNewWorkspace": false,
                "mutationBoundary": ["artifact"]
            },
            "verification": {
                "requireRender": true,
                "requireBuild": false,
                "requirePreview": false,
                "requireExport": true,
                "requireDiffReview": false
            }
        }))
    } else if lower.contains("pdf") || lower.contains("launch brief") {
        Some(json!({
            "artifactClass": "document",
            "deliverableShape": "single_file",
            "renderer": "pdf_embed",
            "presentationSurface": "side_panel",
            "persistence": "artifact_scoped",
            "executionSubstrate": "binary_generator",
            "workspaceRecipeId": null,
            "presentationVariantId": null,
            "scope": {
                "targetProject": null,
                "createNewWorkspace": false,
                "mutationBoundary": ["artifact"]
            },
            "verification": {
                "requireRender": true,
                "requireBuild": false,
                "requirePreview": false,
                "requireExport": true,
                "requireDiffReview": false
            }
        }))
    } else if lower.contains("csv") || lower.contains("readme") || lower.contains("downloadable") {
        Some(json!({
            "artifactClass": "downloadable_file",
            "deliverableShape": "file_set",
            "renderer": "download_card",
            "presentationSurface": "side_panel",
            "persistence": "artifact_scoped",
            "executionSubstrate": "none",
            "workspaceRecipeId": null,
            "presentationVariantId": null,
            "scope": {
                "targetProject": null,
                "createNewWorkspace": false,
                "mutationBoundary": ["artifact"]
            },
            "verification": {
                "requireRender": true,
                "requireBuild": false,
                "requirePreview": false,
                "requireExport": true,
                "requireDiffReview": false
            }
        }))
    } else {
        Some(json!({
            "artifactClass": "interactive_single_file",
            "deliverableShape": "single_file",
            "renderer": "html_iframe",
            "presentationSurface": "inline",
            "persistence": "artifact_scoped",
            "executionSubstrate": "client_sandbox",
            "workspaceRecipeId": null,
            "presentationVariantId": null,
            "scope": {
                "targetProject": null,
                "createNewWorkspace": false,
                "mutationBoundary": ["artifact"]
            },
            "verification": {
                "requireRender": true,
                "requireBuild": false,
                "requirePreview": false,
                "requireExport": true,
                "requireDiffReview": false
            }
        }))
    };

    json!({
        "outcomeKind": "artifact",
        "confidence": 0.96,
        "needsClarification": false,
        "clarificationQuestions": [],
        "artifact": artifact
    })
}

fn mock_brief_payload(input: &str) -> Value {
    let intent =
        extract_text_block(input, "Request:\n", "\n\nArtifact request JSON:\n").unwrap_or_default();
    let request: StudioOutcomeArtifactRequest =
        extract_json_after(input, "Artifact request JSON:\n")
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_else(default_html_request);
    let refinement: Option<StudioArtifactRefinementContext> =
        extract_json_after(input, "Current artifact context:\n")
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or(None);
    let analysis = analyze_prompt(&intent, &request, refinement.as_ref());

    json!({
        "audience": analysis.audience,
        "jobToBeDone": job_to_be_done(&request, &analysis),
        "subjectDomain": analysis.subject_domain,
        "artifactThesis": format!("Make the primary artifact unmistakably about {} while keeping the structure coherent enough to lead the stage.", analysis.short_subject),
        "requiredConcepts": analysis.required_concepts,
        "requiredInteractions": analysis.required_interactions,
        "visualTone": analysis.tone_tags,
        "factualAnchors": analysis.factual_anchors,
        "styleDirectives": analysis.style_directives,
        "referenceHints": refinement
            .and_then(|context| context.taste_memory)
            .map(|memory| memory.directives)
            .unwrap_or_default(),
    })
}

fn mock_edit_intent_payload(input: &str) -> Value {
    let follow_up = extract_text_block(
        input,
        "Follow-up request:\n",
        "\n\nArtifact request JSON:\n",
    )
    .unwrap_or_default();
    let request: StudioOutcomeArtifactRequest =
        extract_json_after(input, "Artifact request JSON:\n")
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_else(default_html_request);
    let brief: StudioArtifactBrief = extract_json_after(input, "Current brief JSON:\n")
        .and_then(|json| parse_studio_artifact_brief(&json).ok())
        .unwrap_or_else(default_brief);
    let refinement: StudioArtifactRefinementContext =
        extract_json_after(input, "Current artifact context:\n")
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_else(default_refinement_context);
    let lower = follow_up.to_ascii_lowercase();
    let patch_existing = !(lower.contains("start over")
        || lower.contains("replace the whole thing")
        || lower.contains("from scratch"));
    let preserve_structure = lower.contains("keep the structure")
        || lower.contains("keep structure")
        || lower.contains("same structure")
        || lower.contains("more enterprise")
        || lower.contains("more technical");
    let branch_requested = lower.contains("branch");
    let target_scope = if lower.contains("chart") || !refinement.selected_targets.is_empty() {
        "selection".to_string()
    } else {
        "artifact".to_string()
    };
    let mut requested_operations = Vec::new();
    if lower.contains("enterprise") {
        requested_operations.push("tone_shift_enterprise".to_string());
    }
    if lower.contains("technical") {
        requested_operations.push("tone_shift_technical".to_string());
    }
    if lower.contains("hero") {
        requested_operations.push("replace_hero".to_string());
    }
    if lower.contains("chart") {
        requested_operations.push("update_chart".to_string());
    }
    if lower.contains("adoption by channel") {
        requested_operations.push("change_chart_metric_adoption_by_channel".to_string());
    }
    if requested_operations.is_empty() {
        requested_operations.push("refine_current_artifact".to_string());
    }

    let tone_directives = collect_tone_tags(&follow_up);
    let selected_targets = if refinement.selected_targets.is_empty() {
        if let Some(path) = extract_selection_path(&follow_up) {
            vec![StudioArtifactSelectionTarget {
                source_surface: "source".to_string(),
                path: Some(path.clone()),
                label: "Selected source excerpt".to_string(),
                snippet: extract_selection_snippet(&follow_up),
            }]
        } else {
            Vec::new()
        }
    } else {
        refinement.selected_targets
    };

    let summary = if patch_existing {
        format!(
            "Patch the current {} artifact without discarding its identity.",
            renderer_label(request.renderer)
        )
    } else {
        format!(
            "Replace the current {} artifact with a new pass.",
            renderer_label(request.renderer)
        )
    };

    json!({
        "mode": if branch_requested {
            "branch"
        } else if patch_existing {
            "patch"
        } else {
            "replace"
        },
        "summary": summary,
        "patchExistingArtifact": patch_existing,
        "preserveStructure": preserve_structure,
        "targetScope": target_scope,
        "targetPaths": selected_targets
            .iter()
            .filter_map(|target| target.path.clone())
            .collect::<Vec<_>>(),
        "requestedOperations": requested_operations,
        "toneDirectives": if tone_directives.is_empty() {
            brief.visual_tone
        } else {
            tone_directives
        },
        "selectedTargets": selected_targets,
        "styleDirectives": brief.style_directives,
        "branchRequested": branch_requested
    })
}

fn mock_materialization_payload(input: &str) -> Value {
    let title = extract_text_block(input, "Title:\n", "\n\nRequest:\n").unwrap_or_default();
    let intent =
        extract_text_block(input, "Request:\n", "\n\nArtifact request JSON:\n").unwrap_or_default();
    let request: StudioOutcomeArtifactRequest =
        extract_json_after(input, "Artifact request JSON:\n")
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_else(default_html_request);
    let brief: StudioArtifactBrief = extract_json_after(input, "Artifact brief JSON:\n")
        .and_then(|json| parse_studio_artifact_brief(&json).ok())
        .unwrap_or_else(default_brief);
    let edit_intent: Option<StudioArtifactEditIntent> =
        extract_json_after(input, "Edit intent JSON:\n")
            .and_then(|json| parse_studio_artifact_edit_intent(&json).ok())
            .or(None);
    let refinement: Option<StudioArtifactRefinementContext> =
        extract_json_after(input, "Current artifact context:\n")
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or(None);
    let metadata: Value = extract_json_after(input, "Candidate metadata:\n")
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_else(|| json!({"candidateId":"candidate-1","candidateSeed":1}));
    let candidate_seed = metadata
        .get("candidateSeed")
        .and_then(Value::as_u64)
        .unwrap_or(1);

    let payload = match request.renderer {
        StudioRendererKind::Markdown => {
            build_markdown_payload(&title, &brief, edit_intent.as_ref())
        }
        StudioRendererKind::HtmlIframe => build_html_payload(
            &title,
            &brief,
            edit_intent.as_ref(),
            refinement.as_ref(),
            candidate_seed,
        ),
        StudioRendererKind::JsxSandbox => build_jsx_payload(&title, &brief, candidate_seed),
        StudioRendererKind::Svg => build_svg_payload(&title, &brief, candidate_seed),
        StudioRendererKind::Mermaid => build_mermaid_payload(&title, &brief, &intent),
        StudioRendererKind::PdfEmbed => build_pdf_payload(&title, &brief),
        StudioRendererKind::DownloadCard => build_download_payload(&title, &brief),
        StudioRendererKind::BundleManifest => build_bundle_payload(&title, &brief),
        StudioRendererKind::WorkspaceSurface => build_html_payload(
            &title,
            &brief,
            edit_intent.as_ref(),
            refinement.as_ref(),
            candidate_seed,
        ),
    };

    serde_json::to_value(payload).unwrap_or_else(|_| json!({}))
}

fn mock_validation_payload(input: &str) -> Value {
    let request: StudioOutcomeArtifactRequest =
        extract_json_after(input, "Artifact request JSON:\n")
            .and_then(|json| serde_json::from_str(&json).ok())
            .or_else(|| {
                extract_json_after(input, "Request focus JSON:\n")
                    .and_then(|json| mock_request_from_focus_json(&json))
            })
            .unwrap_or_else(default_html_request);
    let brief: StudioArtifactBrief = extract_json_after(input, "Brief JSON:\n")
        .and_then(|json| parse_studio_artifact_brief(&json).ok())
        .or_else(|| {
            extract_json_after(input, "Brief focus JSON:\n")
                .and_then(|json| parse_studio_artifact_brief(&json).ok())
        })
        .unwrap_or_else(default_brief);
    let edit_intent: Option<StudioArtifactEditIntent> =
        extract_json_after(input, "Edit intent JSON:\n")
            .and_then(|json| parse_studio_artifact_edit_intent(&json).ok())
            .or_else(|| {
                extract_json_after(input, "Edit intent focus JSON:\n")
                    .and_then(|json| mock_edit_intent_from_focus_json(&json))
            })
            .or(None);
    let candidate: StudioGeneratedArtifactPayload = extract_json_after(input, "Candidate JSON:\n")
        .and_then(|json| {
            parse_studio_generated_artifact_payload(&json)
                .ok()
                .or_else(|| parse_mock_validation_candidate_view(&json).ok())
                .or_else(|| Some(mock_candidate_from_raw_validation_json(&json)))
        })
        .unwrap_or_else(default_payload);

    let validation = evaluate_candidate(&request, &brief, edit_intent.as_ref(), &candidate);
    serde_json::to_value(validation).unwrap_or_else(|_| json!({}))
}

fn parse_mock_validation_candidate_view(
    raw: &str,
) -> Result<StudioGeneratedArtifactPayload, String> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|error| format!("invalid validation candidate JSON: {error}"))?;
    let summary = value
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let notes = value
        .get("notes")
        .and_then(Value::as_array)
        .map(|notes| {
            notes
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let files = value
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| "validation candidate view is missing files".to_string())?
        .iter()
        .map(parse_mock_validation_candidate_file)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StudioGeneratedArtifactPayload {
        summary,
        notes,
        files,
    })
}

fn parse_mock_validation_candidate_file(
    value: &Value,
) -> Result<StudioGeneratedArtifactFile, String> {
    let path = value
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("artifact.txt")
        .to_string();
    let mime = value
        .get("mime")
        .and_then(Value::as_str)
        .unwrap_or("text/plain")
        .to_string();
    let role = value
        .get("role")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| format!("invalid validation candidate file role: {error}"))?
        .unwrap_or(StudioArtifactFileRole::Primary);
    let encoding = value
        .get("encoding")
        .filter(|encoding| !encoding.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| format!("invalid validation candidate file encoding: {error}"))?
        .or(Some(crate::studio::StudioGeneratedArtifactEncoding::Utf8));
    let body = value
        .get("bodyPreview")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(StudioGeneratedArtifactFile {
        path,
        mime,
        role,
        renderable: value
            .get("renderable")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        downloadable: value
            .get("downloadable")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        encoding,
        body,
    })
}

fn mock_candidate_from_raw_validation_json(raw: &str) -> StudioGeneratedArtifactPayload {
    StudioGeneratedArtifactPayload {
        summary: "Mock validation candidate".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "candidate.json".to_string(),
            mime: "application/json".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(crate::studio::StudioGeneratedArtifactEncoding::Utf8),
            body: raw.to_string(),
        }],
    }
}

fn default_html_request() -> StudioOutcomeArtifactRequest {
    StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: ioi_types::app::StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: ioi_types::app::StudioPresentationSurface::Inline,
        persistence: ioi_types::app::StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: ioi_types::app::StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    }
}

fn mock_request_from_focus_json(raw: &str) -> Option<StudioOutcomeArtifactRequest> {
    let value = serde_json::from_str::<Value>(raw).ok()?;
    let object = value.as_object()?;
    let renderer = object
        .get("renderer")
        .cloned()
        .and_then(|value| serde_json::from_value::<StudioRendererKind>(value).ok())?;
    let mut request = default_html_request();
    request.renderer = renderer;
    request.artifact_class = object
        .get("artifactClass")
        .cloned()
        .and_then(|value| serde_json::from_value::<StudioArtifactClass>(value).ok())
        .unwrap_or_else(|| match renderer {
            StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed => {
                StudioArtifactClass::Document
            }
            StudioRendererKind::Svg | StudioRendererKind::Mermaid => StudioArtifactClass::Visual,
            StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => {
                StudioArtifactClass::InteractiveSingleFile
            }
            StudioRendererKind::DownloadCard => StudioArtifactClass::DownloadableFile,
            StudioRendererKind::WorkspaceSurface => StudioArtifactClass::WorkspaceProject,
            StudioRendererKind::BundleManifest => StudioArtifactClass::CompoundBundle,
        });
    if let Some(shape) = object
        .get("deliverableShape")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
    {
        request.deliverable_shape = shape;
    }
    if let Some(surface) = object
        .get("presentationSurface")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
    {
        request.presentation_surface = surface;
    }
    if let Some(persistence) = object
        .get("persistence")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
    {
        request.persistence = persistence;
    }
    if let Some(substrate) = object
        .get("executionSubstrate")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
    {
        request.execution_substrate = substrate;
    }
    if let Some(scope) = object.get("scope").and_then(Value::as_object) {
        request.scope.create_new_workspace = scope
            .get("createNewWorkspace")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        request.scope.mutation_boundary = scope
            .get("mutationBoundary")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|entries| !entries.is_empty())
            .unwrap_or_else(|| vec!["artifact".to_string()]);
    }
    if let Some(verification) = object.get("verification").and_then(Value::as_object) {
        request.verification.require_render = verification
            .get("requireRender")
            .and_then(Value::as_bool)
            .unwrap_or(request.verification.require_render);
        request.verification.require_build = verification
            .get("requireBuild")
            .and_then(Value::as_bool)
            .unwrap_or(request.verification.require_build);
        request.verification.require_preview = verification
            .get("requirePreview")
            .and_then(Value::as_bool)
            .unwrap_or(request.verification.require_preview);
        request.verification.require_export = verification
            .get("requireExport")
            .and_then(Value::as_bool)
            .unwrap_or(request.verification.require_export);
        request.verification.require_diff_review = verification
            .get("requireDiffReview")
            .and_then(Value::as_bool)
            .unwrap_or(request.verification.require_diff_review);
    }
    Some(request)
}

fn mock_edit_intent_from_focus_json(raw: &str) -> Option<StudioArtifactEditIntent> {
    let value = serde_json::from_str::<Value>(raw).ok()?;
    let object = value.as_object()?;
    let mode = object
        .get("mode")
        .cloned()
        .and_then(|value| serde_json::from_value::<StudioArtifactEditMode>(value).ok())
        .unwrap_or(StudioArtifactEditMode::Patch);
    let target_scope = object
        .get("targetScope")
        .and_then(Value::as_str)
        .unwrap_or("artifact")
        .to_string();
    Some(StudioArtifactEditIntent {
        mode,
        summary: object
            .get("targetScope")
            .and_then(Value::as_str)
            .map(|scope| format!("Mock focused {scope} edit intent"))
            .unwrap_or_else(|| "Mock focused edit intent".to_string()),
        patch_existing_artifact: object
            .get("patchExistingArtifact")
            .and_then(Value::as_bool)
            .unwrap_or(matches!(mode, StudioArtifactEditMode::Patch)),
        preserve_structure: object
            .get("preserveStructure")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        target_scope,
        target_paths: object
            .get("targetPaths")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        requested_operations: object
            .get("requestedOperations")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        tone_directives: object
            .get("toneDirectives")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        selected_targets: object
            .get("selectedTargets")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default(),
        style_directives: object
            .get("styleDirectives")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        branch_requested: object
            .get("branchRequested")
            .and_then(Value::as_bool)
            .unwrap_or(matches!(mode, StudioArtifactEditMode::Branch)),
    })
}

fn default_brief() -> StudioArtifactBrief {
    StudioArtifactBrief {
        audience: "the requesting team".to_string(),
        job_to_be_done: "turn the request into a presentable artifact".to_string(),
        subject_domain: "artifact".to_string(),
        artifact_thesis: "Make the artifact request-faithful.".to_string(),
        required_concepts: vec!["artifact".to_string()],
        required_interactions: Vec::new(),
        visual_tone: Vec::new(),
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
        query_profile: None,
    }
}

fn default_refinement_context() -> StudioArtifactRefinementContext {
    StudioArtifactRefinementContext {
        artifact_id: Some("artifact-1".to_string()),
        revision_id: Some("revision-1".to_string()),
        title: "Artifact".to_string(),
        summary: "Current artifact".to_string(),
        renderer: StudioRendererKind::HtmlIframe,
        files: Vec::new(),
        selected_targets: Vec::new(),
        taste_memory: Some(StudioArtifactTasteMemory {
            directives: Vec::new(),
            summary: "No stored preferences.".to_string(),
            typography_preferences: Vec::new(),
            density_preference: None,
            tone_family: Vec::new(),
            motion_tolerance: None,
            preferred_scaffold_families: Vec::new(),
            preferred_component_patterns: Vec::new(),
            anti_patterns: Vec::new(),
        }),
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        retrieved_exemplars: Vec::new(),
    }
}

fn default_payload() -> StudioGeneratedArtifactPayload {
    StudioGeneratedArtifactPayload {
        summary: "Artifact".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body: "<!doctype html><html><body><main><section><h1>Artifact</h1></section></main></body></html>".to_string(),
        }],
    }
}

fn analyze_prompt(
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> PromptAnalysis {
    let lower = intent.to_ascii_lowercase();
    let phrases = extract_focus_phrases(intent);
    let continuity_subject = refinement.and_then(refinement_subject_domain);
    let subject_domain = continuity_subject
        .clone()
        .or_else(|| {
            phrases
                .first()
                .cloned()
                .filter(|phrase| !phrase.trim().is_empty())
        })
        .unwrap_or_else(|| collect_significant_tokens(intent).join(" "));
    let short_subject = if subject_domain.trim().is_empty() {
        "the request".to_string()
    } else {
        subject_domain.clone()
    };
    let audience =
        if lower.contains("launch") || lower.contains("rollout") || lower.contains("brief") {
            "product, operations, and leadership stakeholders".to_string()
        } else if matches!(
            request.renderer,
            StudioRendererKind::Svg | StudioRendererKind::HtmlIframe
        ) {
            "the audience encountering the artifact in render-first mode".to_string()
        } else if lower.contains("pricing") || lower.contains("billing") {
            "finance, commercial, and product operators".to_string()
        } else {
            "the requesting team".to_string()
        };
    let mut required_concepts = Vec::new();
    if let Some(subject) = continuity_subject {
        required_concepts.push(subject);
        merge_unique_strings(
            &mut required_concepts,
            collect_refinement_focus_terms(intent).into_iter(),
        );
    } else {
        required_concepts = phrases;
    }
    if required_concepts.is_empty() {
        required_concepts = collect_significant_tokens(intent)
            .into_iter()
            .take(5)
            .collect();
    }
    let mut factual_anchors = required_concepts.clone();
    if let Some(refinement) = refinement {
        factual_anchors.push(format!("continue {}", refinement.title));
    }

    PromptAnalysis {
        subject_domain,
        short_subject,
        audience,
        tone_tags: collect_tone_tags(intent),
        style_directives: collect_style_directives(intent, request.renderer),
        required_interactions: collect_interaction_tags(intent, request.renderer),
        required_concepts,
        factual_anchors,
    }
}

fn job_to_be_done(request: &StudioOutcomeArtifactRequest, analysis: &PromptAnalysis) -> String {
    match request.renderer {
        StudioRendererKind::Markdown => format!(
            "Produce a document that makes {} easy to review and circulate.",
            analysis.short_subject
        ),
        StudioRendererKind::HtmlIframe => format!(
            "Turn {} into an interactive render-first artifact with clear hierarchy and grounded charts or sections.",
            analysis.short_subject
        ),
        StudioRendererKind::JsxSandbox => format!(
            "Turn {} into an interactive product surface with controls and live calculations.",
            analysis.short_subject
        ),
        StudioRendererKind::Svg => format!(
            "Create a hero composition that makes {} feel branded and intentional at a glance.",
            analysis.short_subject
        ),
        StudioRendererKind::Mermaid => format!(
            "Explain {} through a diagram that can be understood in one pass.",
            analysis.short_subject
        ),
        StudioRendererKind::PdfEmbed => format!(
            "Produce a brief that makes {} presentable as a surfaced PDF export.",
            analysis.short_subject
        ),
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => {
            "Package the useful files with enough orientation to justify render-first download presentation."
                .to_string()
        }
        StudioRendererKind::WorkspaceSurface => {
            "Scaffold a workspace project with a previewable implementation surface.".to_string()
        }
    }
}

fn collect_significant_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '/')
        .filter_map(|part| {
            let trimmed = part.trim().to_ascii_lowercase();
            if trimmed.len() < 3 || STOP_WORDS.contains(&trimmed.as_str()) {
                None
            } else {
                Some(trimmed)
            }
        })
        .collect()
}

fn extract_focus_phrases(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut phrases = Vec::new();
    for marker in [
        "grounded in ",
        "anchored in ",
        "centered on ",
        "centers on ",
        "focused on ",
        "explainer for ",
        "about ",
        "for ",
        "of ",
        "that documents ",
        "that summarizes ",
        "explains ",
    ] {
        if let Some(index) = lower.find(marker) {
            let start = index + marker.len();
            let phrase = sanitize_focus_phrase(
                text[start..]
                    .split(['\n', '.', ';'])
                    .next()
                    .unwrap_or_default(),
            );
            if !phrase.is_empty() {
                phrases.push(phrase);
            }
        }
    }
    phrases.dedup();
    phrases
}

fn sanitize_focus_phrase(raw: &str) -> String {
    let mut phrase = raw.trim().trim_matches('"').trim().to_string();
    for marker in [
        " while ",
        " that ",
        " with ",
        " so ",
        " instead ",
        " because ",
        " into ",
        " rather than ",
        "<",
        ",",
    ] {
        if let Some((head, _)) = phrase.split_once(marker) {
            phrase = head.to_string();
        }
    }
    phrase.trim().trim_matches('"').trim().to_string()
}

fn refinement_subject_domain(refinement: &StudioArtifactRefinementContext) -> Option<String> {
    refinement
        .taste_memory
        .as_ref()
        .and_then(|memory| extract_focus_phrases(&memory.summary).into_iter().next())
        .or_else(|| {
            extract_focus_phrases(&refinement.summary)
                .into_iter()
                .next()
        })
        .or_else(|| extract_focus_phrases(&refinement.title).into_iter().next())
        .or_else(|| {
            refinement
                .files
                .iter()
                .find_map(|file| extract_focus_phrases(&file.body).into_iter().next())
        })
}

fn collect_refinement_focus_terms(text: &str) -> Vec<String> {
    collect_significant_tokens(text)
        .into_iter()
        .filter(|token| !REFINEMENT_OPERATION_WORDS.contains(&token.as_str()))
        .take(5)
        .collect()
}

fn merge_unique_strings(target: &mut Vec<String>, values: impl Iterator<Item = String>) {
    for value in values {
        if value.trim().is_empty() {
            continue;
        }
        if !target
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(value.trim()))
        {
            target.push(value);
        }
    }
}

fn collect_tone_tags(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut tags = Vec::new();
    if lower.contains("enterprise") {
        tags.push("enterprise".to_string());
    }
    if lower.contains("technical") {
        tags.push("technical".to_string());
    }
    if lower.contains("editorial") {
        tags.push("editorial".to_string());
    }
    if lower.contains("launch") {
        tags.push("launch".to_string());
    }
    if lower.contains("brand") {
        tags.push("brand-forward".to_string());
    }
    if tags.is_empty() {
        tags.push("grounded".to_string());
    }
    tags
}

fn collect_style_directives(text: &str, renderer: StudioRendererKind) -> Vec<String> {
    let mut directives = collect_tone_tags(text);
    if renderer == StudioRendererKind::HtmlIframe {
        directives.push("request-shaped hierarchy".to_string());
    }
    if renderer == StudioRendererKind::Svg {
        directives.push("graphic clarity".to_string());
    }
    directives
}

fn collect_interaction_tags(text: &str, renderer: StudioRendererKind) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut tags = Vec::new();
    if lower.contains("chart") {
        tags.push("chart toggles".to_string());
    }
    if lower.contains("configurator") || renderer == StudioRendererKind::JsxSandbox {
        tags.push("live controls".to_string());
        tags.push("computed summary".to_string());
    }
    if lower.contains("interactive") && renderer == StudioRendererKind::HtmlIframe {
        tags.push("section focus switching".to_string());
    }
    if tags.is_empty() && renderer == StudioRendererKind::HtmlIframe {
        tags.push("narrative section progression".to_string());
    }
    tags
}

fn renderer_label(renderer: StudioRendererKind) -> &'static str {
    match renderer {
        StudioRendererKind::Markdown => "markdown",
        StudioRendererKind::HtmlIframe => "html",
        StudioRendererKind::JsxSandbox => "jsx",
        StudioRendererKind::Svg => "svg",
        StudioRendererKind::Mermaid => "mermaid",
        StudioRendererKind::PdfEmbed => "pdf",
        StudioRendererKind::DownloadCard => "download",
        StudioRendererKind::WorkspaceSurface => "workspace",
        StudioRendererKind::BundleManifest => "bundle",
    }
}

fn build_markdown_payload(
    title: &str,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
) -> StudioGeneratedArtifactPayload {
    let mut sections = vec![
        "# ".to_string() + title,
        String::new(),
        "## Purpose".to_string(),
        format!(
            "This artifact helps {} {}.",
            brief.audience, brief.job_to_be_done
        ),
        String::new(),
        "## Core Concepts".to_string(),
    ];
    sections.extend(
        brief
            .required_concepts
            .iter()
            .map(|concept| format!("- {}", concept)),
    );
    sections.extend([
        String::new(),
        "## Execution Notes".to_string(),
        format!(
            "The document is grounded in {} and keeps the thesis focused on {}.",
            brief.subject_domain, brief.artifact_thesis
        ),
        String::new(),
        "## Verification".to_string(),
        "Render should remain primary only when the sections, owners, and follow-up actions are explicit in the artifact itself."
            .to_string(),
    ]);
    if let Some(edit_intent) = edit_intent {
        sections.extend([
            String::new(),
            "## Revision Notes".to_string(),
            format!("- {}", edit_intent.summary),
        ]);
    }
    StudioGeneratedArtifactPayload {
        summary: format!(
            "Prepared a request-grounded markdown artifact for {}.",
            brief.subject_domain
        ),
        notes: vec![
            "Mock Studio runtime generated the markdown directly from the typed brief.".to_string(),
        ],
        files: vec![StudioGeneratedArtifactFile {
            path: "artifact.md".to_string(),
            mime: "text/markdown".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body: sections.join("\n"),
        }],
    }
}

fn build_html_payload(
    title: &str,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_seed: u64,
) -> StudioGeneratedArtifactPayload {
    let variant = (candidate_seed % 3) as usize;
    let subject = brief.subject_domain.clone();
    let concept_a = brief
        .required_concepts
        .first()
        .cloned()
        .unwrap_or_else(|| subject.clone());
    let concept_b = brief
        .required_concepts
        .get(1)
        .cloned()
        .unwrap_or_else(|| "delivery cadence".to_string());
    let tone = brief
        .visual_tone
        .first()
        .cloned()
        .unwrap_or_else(|| "grounded".to_string());
    let enterprise = tone.contains("enterprise")
        || edit_intent
            .map(|intent| {
                intent
                    .tone_directives
                    .iter()
                    .any(|tag| tag.contains("enterprise"))
            })
            .unwrap_or(false);
    let technical = tone.contains("technical")
        || edit_intent
            .map(|intent| {
                intent
                    .requested_operations
                    .iter()
                    .any(|tag| tag.contains("technical"))
            })
            .unwrap_or(false);
    let palette = if enterprise {
        ("#071421", "#10273d", "#9bd6ff", "#59d5c6")
    } else if technical {
        ("#061017", "#0c202d", "#7bc1ff", "#8dffcb")
    } else {
        ("#f7f2ea", "#ffffff", "#b7652a", "#2f9d8f")
    };
    let chart_heading = if edit_intent
        .map(|intent| {
            intent
                .requested_operations
                .iter()
                .any(|operation| operation.contains("adoption_by_channel"))
        })
        .unwrap_or(false)
    {
        "Adoption by channel"
    } else {
        "Impact by rollout lane"
    };
    let hero_copy = if technical {
        format!(
            "A technical rollout artifact for {} with concrete lanes, instrumentation, and governed launch sequencing.",
            subject
        )
    } else {
        format!(
            "A render-first explainer for {} that keeps the thesis visible in every section instead of hiding it inside one card.",
            subject
        )
    };
    let existing_summary = refinement
        .map(|context| context.summary.clone())
        .unwrap_or_default();
    let interactive_hint = if chart_heading == "Adoption by channel" {
        "Toggle between rollout sequencing and channel adoption to keep the targeted chart edit grounded in the current artifact."
    } else {
        "Use the view switch to compare rollout sequencing with the supporting evidence panel."
    };
    let text_color = if enterprise || technical {
        "#eef5ff"
    } else {
        "#1b2431"
    };
    let muted_color = if enterprise || technical {
        "rgba(238,245,255,0.74)"
    } else {
        "rgba(27,36,49,0.72)"
    };
    let hero_columns = if variant == 1 {
        "minmax(0, 0.95fr) minmax(280px, 1.05fr)"
    } else {
        "minmax(0, 1.1fr) minmax(300px, 0.9fr)"
    };
    let kicker = if technical {
        "Technical rollout artifact"
    } else {
        "Interactive HTML artifact"
    };
    let headline = if variant == 2 {
        format!("{} without the generic launch shell.", subject)
    } else {
        format!(
            "{} explained through real lanes and visible metrics.",
            subject
        )
    };
    let stat_one = 36 + (candidate_seed % 18);
    let stat_two = 52 + (candidate_seed % 21);
    let stat_three = 68 + (candidate_seed % 14);
    let lane_one = format!("{} planning", concept_a);
    let lane_two = format!("{} execution", concept_b);
    let lane_three = "Feedback and continuity".to_string();
    let lane_one_copy = format!(
        "Anchor the opening pass in {} so the request is visible above the fold.",
        concept_a
    );
    let lane_two_copy = format!(
        "Translate {} into concrete sections, owners, and timing instead of leaving it as a label.",
        concept_b
    );
    let lane_three_copy =
        "Keep revisions inspectable so the artifact can be refined without losing the strongest previous pass."
            .to_string();
    let side_heading = if enterprise {
        "Enterprise continuity"
    } else {
        "Request-grounded structure"
    };
    let side_copy = format!(
        "The chart, headline, and proof lanes stay anchored in {} so the page does not collapse into a generic SaaS launch shell.",
        subject
    );
    let close_heading = if technical {
        "Keep the artifact patchable by section."
    } else {
        "Refine the artifact without losing its identity."
    };
    let close_copy = if edit_intent
        .map(|intent| intent.patch_existing_artifact)
        .unwrap_or(false)
    {
        "This pass preserves the artifact identity and leaves stable section anchors for the next targeted edit."
    } else {
        "Render leads with the actual work product while Source remains one click away for patch-first refinement."
    };
    let primary_chart = {
        let series = if chart_heading == "Adoption by channel" {
            vec![
                (
                    "Retail",
                    74_i32,
                    "Retail adoption leads the current rollout.",
                ),
                (
                    "Subscription",
                    62_i32,
                    "Subscription adoption shows the clearest retained demand.",
                ),
                (
                    "Vet",
                    58_i32,
                    "Vet adoption stays visible as a specialist lane.",
                ),
                (
                    "Direct",
                    69_i32,
                    "Direct demand remains strong in the current pass.",
                ),
            ]
        } else {
            vec![
                (
                    "Pilot",
                    76_i32,
                    "Pilot readiness leads the rollout evidence.",
                ),
                (
                    "Launch",
                    63_i32,
                    "Launch readiness remains visible on first paint.",
                ),
                (
                    "Retention",
                    57_i32,
                    "Retention follow-up stays in the surfaced chart evidence.",
                ),
                (
                    "Ops",
                    71_i32,
                    "Operational readiness stays visible beside the shared detail panel.",
                ),
            ]
        };
        let marks = series
            .iter()
            .enumerate()
            .map(|(index, (label, value, detail))| {
                let x = 28 + index as i32 * 72;
                let y = 136 - value;
                format!(
                    "<rect x=\"{x}\" y=\"{y}\" width=\"42\" height=\"{value}\" rx=\"10\" data-detail=\"{detail}\" tabindex=\"0\"></rect><text x=\"{x}\" y=\"152\">{label}</text><text x=\"{x}\" y=\"{value_y}\">{value}</text>",
                    x = x,
                    y = y,
                    value = value,
                    detail = detail,
                    label = label,
                    value_y = y - 6,
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<article class=\"comparison-card chart-card\"><h3>{chart_heading}</h3><svg class=\"chart-svg\" viewBox=\"0 0 320 170\" role=\"img\" aria-label=\"{subject} chart\"><line x1=\"20\" y1=\"136\" x2=\"300\" y2=\"136\" stroke=\"currentColor\" stroke-opacity=\"0.24\"></line>{marks}</svg><p class=\"note\">The leading chart stays visible on first paint with labeled values and focusable marks.</p></article>",
            chart_heading = chart_heading,
            subject = subject,
            marks = marks,
        )
    };
    let body = format!(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{title}</title>
    <style>
      :root {{ --bg: {bg}; --panel: {panel}; --accent: {accent}; --accent2: {accent2}; --text: {text}; --muted: {muted}; font-family: "IBM Plex Sans", "Inter", system-ui, sans-serif; }}
      * {{ box-sizing: border-box; }}
      body {{ margin: 0; min-width: 320px; background: radial-gradient(circle at top left, color-mix(in srgb, var(--accent) 18%, transparent), transparent 24%), var(--bg); color: var(--text); }}
      main {{ width: min(1180px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0 72px; }}
      .shell, .panel, nav, footer {{ background: color-mix(in srgb, var(--panel) 94%, transparent); border: 1px solid color-mix(in srgb, var(--accent) 18%, rgba(255,255,255,0.06)); border-radius: 24px; box-shadow: 0 24px 60px rgba(0,0,0,0.16); }}
      nav {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 18px 22px; }}
      nav a {{ color: var(--muted); text-decoration: none; margin-left: 18px; font-size: 0.92rem; }}
      .hero {{ display: grid; grid-template-columns: {hero_columns}; gap: 22px; margin-top: 22px; padding: 28px; }}
      .eyebrow {{ margin: 0 0 12px; letter-spacing: 0.24em; text-transform: uppercase; color: var(--accent); font-size: 0.75rem; }}
      h1, h2 {{ margin: 0; letter-spacing: -0.04em; }}
      h1 {{ font-family: "Iowan Old Style", Georgia, serif; font-size: clamp(3rem, 7vw, 5.8rem); line-height: 0.92; max-width: 11ch; }}
      p {{ line-height: 1.7; }}
      .lead {{ max-width: 58ch; color: var(--muted); font-size: 1.08rem; }}
      .stats, .grid {{ display: grid; gap: 18px; margin-top: 22px; }}
      .stats {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
      .stats article, .grid article, .panel, footer {{ padding: 20px; }}
      .stats strong {{ display: block; font-size: 2rem; color: var(--accent); }}
      .grid {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
      .chart-wrap {{ display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(260px, 0.75fr); gap: 18px; margin-top: 22px; align-items: start; }}
      .view-switch {{ display: inline-flex; gap: 10px; flex-wrap: wrap; margin-top: 18px; }}
      .view-switch button {{ border: 0; border-radius: 999px; padding: 10px 14px; background: color-mix(in srgb, var(--accent) 18%, transparent); color: var(--text); cursor: pointer; font: inherit; }}
      .view-switch button[data-active="true"] {{ background: linear-gradient(90deg, var(--accent), var(--accent2)); color: #061017; font-weight: 700; }}
      .chart-card {{ display: grid; gap: 14px; }}
      .chart-card h3 {{ margin: 0; font-size: 1.05rem; }}
      .chart-svg {{ width: 100%; height: auto; display: block; }}
      .chart-svg rect {{ fill: var(--accent); opacity: 0.92; }}
      .chart-svg text {{ fill: var(--text); font-family: "IBM Plex Sans", "Inter", system-ui, sans-serif; font-size: 12px; }}
      .evidence-grid {{ display: grid; gap: 16px; }}
      [data-view-panel] {{ display: none; gap: 16px; }}
      [data-view-panel][data-active="true"] {{ display: grid; }}
      .comparison-rail {{ display: grid; gap: 12px; margin-top: 18px; }}
      .comparison-card {{ border-radius: 18px; border: 1px solid color-mix(in srgb, var(--accent) 18%, rgba(255,255,255,0.08)); background: color-mix(in srgb, var(--panel) 90%, transparent); padding: 14px; }}
      .comparison-card button {{ width: 100%; text-align: left; border: 0; background: transparent; color: inherit; font: inherit; cursor: pointer; padding: 0; display: grid; gap: 6px; }}
      .comparison-card strong {{ font-size: 1rem; }}
      .detail-panel {{ display: grid; gap: 12px; }}
      .note {{ font-size: 0.95rem; color: var(--muted); }}
      footer {{ display: flex; justify-content: space-between; gap: 18px; align-items: center; margin-top: 24px; }}
      @media (max-width: 980px) {{ .hero, .stats, .grid, .chart-wrap, footer {{ grid-template-columns: 1fr; display: grid; }} }}
    </style>
  </head>
  <body>
    <main>
      <nav>
        <strong>{subject}</strong>
        <div>
          <a href="#overview">Overview</a>
          <a href="#lanes">Lanes</a>
          <a href="#chart">Chart</a>
          <a href="#close">Close</a>
        </div>
      </nav>
      <!-- studio-section:hero -->
      <section class="shell hero" id="overview">
        <div>
          <p class="eyebrow">{kicker}</p>
          <h1>{headline}</h1>
          <p class="lead">{hero_copy}</p>
          <p class="note">{existing_summary}</p>
        </div>
        <aside class="panel">
          <p class="eyebrow">Audience</p>
          <h2>{audience}</h2>
          <p class="note">{thesis}</p>
        </aside>
      </section>
      <section class="stats" id="lanes">
        <article class="panel"><strong>{stat_one}</strong><span>{concept_a}</span></article>
        <article class="panel"><strong>{stat_two}</strong><span>{concept_b}</span></article>
        <article class="panel"><strong>{stat_three}</strong><span>{tone}</span></article>
      </section>
      <section class="grid">
        <article class="panel"><p class="eyebrow">Lane 1</p><h2>{lane_one}</h2><p>{lane_one_copy}</p></article>
        <article class="panel"><p class="eyebrow">Lane 2</p><h2>{lane_two}</h2><p>{lane_two_copy}</p></article>
        <article class="panel"><p class="eyebrow">Lane 3</p><h2>{lane_three}</h2><p>{lane_three_copy}</p></article>
      </section>
      <!-- studio-section:chart -->
      <section class="chart-wrap" id="chart">
        <article class="panel">
          <p class="eyebrow">Chart focus</p>
          <h2>{chart_heading}</h2>
          <p class="note">{interactive_hint}</p>
          <div class="view-switch" role="tablist" aria-label="Evidence view switcher">
            <button type="button" data-view="satisfaction" aria-controls="satisfaction-panel" data-active="true" role="tab" aria-selected="true">Satisfaction</button>
            <button type="button" data-view="usage" aria-controls="usage-panel" data-active="false" role="tab" aria-selected="false">Usage</button>
            <button type="button" data-view="ingredients" aria-controls="ingredients-panel" data-active="false" role="tab" aria-selected="false">Ingredients</button>
          </div>
          <div class="evidence-grid">
            <section id="satisfaction-panel" data-view-panel="satisfaction" data-active="true">
              {primary_chart}
            </section>
            <section id="usage-panel" data-view-panel="usage" data-active="false" hidden>
              <article class="comparison-card chart-card">
                <h3>Usage evidence stays pre-rendered.</h3>
                <svg class="chart-svg" viewBox="0 0 320 170" role="img" aria-label="{subject} usage evidence">
                  <rect x="28" y="74" width="42" height="62" rx="10" data-detail="Channel readiness is steady at 62 for the current rollout." tabindex="0"></rect>
                  <rect x="102" y="54" width="42" height="82" rx="10" data-detail="Repeat use is the strongest usage signal in this pass." tabindex="0"></rect>
                  <rect x="176" y="66" width="42" height="70" rx="10" data-detail="Support load stays visible as a third usage signal." tabindex="0"></rect>
                  <text x="34" y="152">Readiness</text>
                  <text x="108" y="152">Repeat</text>
                  <text x="186" y="152">Support</text>
                  <text x="34" y="68">62</text>
                  <text x="108" y="48">82</text>
                  <text x="186" y="60">70</text>
                </svg>
                <p class="note">Channel readiness, repeat use, and support load stay visible here without rebuilding the document.</p>
              </article>
              <article class="comparison-card">
                <strong>Request-specific usage notes</strong>
                <p class="note">Adoption, satisfaction, and rollout continuity remain tied to {subject} in the patch flow.</p>
              </article>
            </section>
            <section id="ingredients-panel" data-view-panel="ingredients" data-active="false" hidden>
              <article class="comparison-card">
                <strong>Ingredient evidence</strong>
                <p class="note">Ingredient analysis, proof points, and messaging cues stay in a dedicated pre-rendered panel.</p>
              </article>
              <article class="comparison-card">
                <strong>Why it matters</strong>
                <p class="note">This panel keeps a second evidence family visible in the same artifact instead of collapsing into one generic chart.</p>
              </article>
            </section>
          </div>
          <section class="comparison-rail" aria-label="Visible comparison evidence">
            <article class="comparison-card">
              <button type="button" data-detail="Retail satisfaction lift keeps the rollout anchored in visible shopper proof.">
                <span class="eyebrow">Retail proof</span>
                <strong>Retail satisfaction lift</strong>
                <span class="note">Hover, focus, or click to update the shared detail panel.</span>
              </button>
            </article>
            <article class="comparison-card">
              <button type="button" data-detail="Usage retention stays visible as a second evidence track for the same request.">
                <span class="eyebrow">Usage proof</span>
                <strong>Usage retention track</strong>
                <span class="note">Pre-rendered evidence stays visible before any interaction occurs.</span>
              </button>
            </article>
            <article class="comparison-card">
              <button type="button" data-detail="Ingredient messaging explains why the artifact belongs to {subject}, not a generic launch shell.">
                <span class="eyebrow">Ingredient proof</span>
                <strong>Ingredient messaging</strong>
                <span class="note">Shared detail stays truthful across chart and narrative evidence.</span>
              </button>
            </article>
          </section>
        </article>
        <aside class="panel detail-panel">
          <p class="eyebrow">Shared detail</p>
          <h2>{side_heading}</h2>
          <p id="detail-copy" class="note">Retail satisfaction lift is selected by default for {subject}.</p>
          <p class="note">{side_copy}</p>
        </aside>
      </section>
      <footer id="close">
        <div>
          <p class="eyebrow">Next step</p>
          <h2>{close_heading}</h2>
        </div>
        <p class="lead">{close_copy}</p>
      </footer>
    </main>
    <script>
      const detailCopy = document.getElementById('detail-copy');
      const viewButtons = Array.from(document.querySelectorAll('button[data-view]'));
      const panels = Array.from(document.querySelectorAll('[data-view-panel]'));
      const detailMarks = Array.from(document.querySelectorAll('[data-detail]'));
      viewButtons.forEach((button) => {{
        button.addEventListener('click', () => {{
          const target = button.dataset.view;
          viewButtons.forEach((entry) => {{
            const active = entry === button;
            entry.setAttribute('data-active', String(active));
            entry.setAttribute('aria-selected', String(active));
          }});
          panels.forEach((panel) => {{
            const active = panel.dataset.viewPanel === target;
            panel.setAttribute('data-active', String(active));
            panel.hidden = !active;
          }});
          if (detailCopy) {{
            detailCopy.textContent = button.textContent + ' view selected for {subject}.';
          }}
        }});
      }});
      detailMarks.forEach((mark) => {{
        const updateDetail = () => {{
          if (detailCopy && mark.dataset.detail) {{
            detailCopy.textContent = mark.dataset.detail;
          }}
        }};
        mark.addEventListener('mouseenter', updateDetail);
        mark.addEventListener('focus', updateDetail);
        mark.addEventListener('click', updateDetail);
      }});
    </script>
  </body>
</html>"##,
        title = title,
        bg = palette.0,
        panel = palette.1,
        accent = palette.2,
        accent2 = palette.3,
        text = text_color,
        muted = muted_color,
        hero_columns = hero_columns,
        subject = subject,
        kicker = kicker,
        headline = headline,
        hero_copy = hero_copy,
        existing_summary = existing_summary,
        audience = brief.audience,
        thesis = brief.artifact_thesis,
        stat_one = stat_one,
        stat_two = stat_two,
        stat_three = stat_three,
        concept_a = concept_a,
        concept_b = concept_b,
        tone = tone,
        lane_one = lane_one,
        lane_two = lane_two,
        lane_three = lane_three,
        lane_one_copy = lane_one_copy,
        lane_two_copy = lane_two_copy,
        lane_three_copy = lane_three_copy,
        chart_heading = chart_heading,
        interactive_hint = interactive_hint,
        primary_chart = primary_chart,
        side_heading = side_heading,
        side_copy = side_copy,
        close_heading = close_heading,
        close_copy = close_copy,
    );

    StudioGeneratedArtifactPayload {
        summary: format!("Materialized an HTML artifact about {} with renderer-grounded sections and charted proof.", subject),
        notes: vec![
            "Mock Studio runtime used the typed brief and candidate seed to vary layout and tone.".to_string(),
            "Stable section anchors support patch-first refinements without full restart.".to_string(),
        ],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body,
        }],
    }
}

fn build_jsx_payload(
    title: &str,
    brief: &StudioArtifactBrief,
    candidate_seed: u64,
) -> StudioGeneratedArtifactPayload {
    let subject = brief.subject_domain.replace('"', "");
    let base = 1800 + (candidate_seed % 900) as i64;
    let body = r##"import React, { useMemo, useState } from "react";

const tiers = {
  starter: { base: __BASE__, seat: 18, usage: 0.12 },
  growth: { base: __GROWTH__, seat: 15, usage: 0.10 },
  scale: { base: __SCALE__, seat: 11, usage: 0.07 },
};

export default function Artifact() {
  const [tier, setTier] = useState("growth");
  const [seats, setSeats] = useState(96);
  const [usage, setUsage] = useState(18000);
  const [annual, setAnnual] = useState(true);
  const current = tiers[tier];
  const monthly = useMemo(() => current.base + seats * current.seat + usage * current.usage, [current, seats, usage]);
  const total = annual ? monthly * 0.9 : monthly;

  return (
    <main style={shell}>
      <section style={layout}>
        <article style={panel}>
          <p style={eyebrow}>JSX artifact</p>
          <h1 style={headline}>Configure __SUBJECT__ pricing before finance review.</h1>
          <p style={copy}>This interactive surface stays grounded in the request by exposing the variables a reviewer would actually adjust.</p>

          <label style={field}>
            <span>Tier</span>
            <select value={tier} onChange={(event) => setTier(event.target.value)} style={control}>
              <option value="starter">Starter</option>
              <option value="growth">Growth</option>
              <option value="scale">Scale</option>
            </select>
          </label>

          <label style={field}>
            <span>Seats: {seats}</span>
            <input type="range" min="20" max="400" step="5" value={seats} onChange={(event) => setSeats(Number(event.target.value))} />
          </label>

          <label style={field}>
            <span>Usage: {usage.toLocaleString()}</span>
            <input type="range" min="2000" max="52000" step="1000" value={usage} onChange={(event) => setUsage(Number(event.target.value))} />
          </label>

          <label style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <input type="checkbox" checked={annual} onChange={(event) => setAnnual(event.target.checked)} />
            <span>Apply annual commitment</span>
          </label>
        </article>

        <aside style={summaryPanel}>
          <p style={eyebrow}>Live summary</p>
          <h2 style={{ margin: 0, fontSize: 28 }}>Estimated monthly run rate</h2>
          <strong style={{ fontSize: 54, lineHeight: 1 }}>${Math.round(total).toLocaleString()}</strong>
          <Metric label="Base platform" value={current.base} />
          <Metric label="Seat extension" value={seats * current.seat} />
          <Metric label="Usage cost" value={usage * current.usage} />
          <button type="button" style={primaryButton}>Send for review</button>
          <button type="button" style={secondaryButton}>Export assumptions</button>
        </aside>
      </section>
    </main>
  );
}

function Metric({ label, value }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 12, color: "rgba(236,243,255,0.78)" }}>
      <span>{label}</span>
      <strong>${Math.round(value).toLocaleString()}</strong>
    </div>
  );
}

const shell = { minHeight: "100vh", padding: 32, background: "linear-gradient(180deg, #07111d, #0d1f35)", color: "#ecf3ff", fontFamily: "\"IBM Plex Sans\", \"Inter\", system-ui, sans-serif" };
const layout = { display: "grid", gridTemplateColumns: "minmax(0,1.08fr) minmax(320px,0.92fr)", gap: 24 };
const panel = { borderRadius: 24, padding: 28, background: "rgba(8, 18, 33, 0.82)", border: "1px solid rgba(139,219,255,0.14)", display: "grid", gap: 18 };
const summaryPanel = { ...panel, background: "linear-gradient(180deg, rgba(18,39,66,0.95), rgba(9,18,31,0.98))" };
const eyebrow = { margin: 0, letterSpacing: "0.22em", textTransform: "uppercase", color: "#8bdbff", fontSize: 12 };
const headline = { margin: 0, fontSize: 48, lineHeight: 0.96 };
const copy = { margin: 0, color: "rgba(236,243,255,0.72)", lineHeight: 1.7 };
const field = { display: "grid", gap: 8 };
const control = { borderRadius: 14, border: "1px solid rgba(139,219,255,0.16)", padding: "0.9rem 1rem", background: "rgba(7,15,27,0.94)", color: "#ecf3ff", font: "inherit" };
const primaryButton = { borderRadius: 999, border: 0, padding: "0.95rem 1.2rem", background: "linear-gradient(90deg, #8bdbff, #64f2c5)", color: "#07111d", fontWeight: 700, cursor: "pointer" };
const secondaryButton = { ...primaryButton, background: "transparent", border: "1px solid rgba(139,219,255,0.16)", color: "#ecf3ff" };
"##
    .replace("__BASE__", &base.to_string())
    .replace("__GROWTH__", &(base + 2400).to_string())
    .replace("__SCALE__", &(base + 5600).to_string())
    .replace("__SUBJECT__", &subject);

    StudioGeneratedArtifactPayload {
        summary: format!("Materialized a JSX configurator for {}.", subject),
        notes: vec![
            "Mock Studio runtime generated real controls and computed summary output.".to_string(),
        ],
        files: vec![StudioGeneratedArtifactFile {
            path: format!("{}.jsx", title.replace(' ', "")),
            mime: "text/jsx".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body,
        }],
    }
}

fn build_svg_payload(
    title: &str,
    brief: &StudioArtifactBrief,
    candidate_seed: u64,
) -> StudioGeneratedArtifactPayload {
    let subject = brief.subject_domain.to_uppercase();
    let accent = if candidate_seed % 2 == 0 {
        "#8BDBFF"
    } else {
        "#F9A24B"
    };
    let body = format!(
        "<svg width=\"1440\" height=\"900\" viewBox=\"0 0 1440 900\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n  <rect width=\"1440\" height=\"900\" fill=\"#07121F\"/>\n  <rect x=\"72\" y=\"68\" width=\"1296\" height=\"764\" rx=\"44\" fill=\"#0A1627\" stroke=\"rgba(255,255,255,0.12)\"/>\n  <circle cx=\"1086\" cy=\"226\" r=\"168\" fill=\"{accent}\" fill-opacity=\"0.28\"/>\n  <circle cx=\"1086\" cy=\"226\" r=\"252\" stroke=\"{accent}\" stroke-opacity=\"0.18\"/>\n  <path d=\"M160 688C332 492 516 388 724 348C936 308 1126 356 1280 476\" stroke=\"{accent}\" stroke-width=\"4\" stroke-linecap=\"round\"/>\n  <path d=\"M160 736C386 590 566 520 742 492C930 462 1108 502 1252 580\" stroke=\"#64F2C5\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-dasharray=\"12 14\"/>\n  <rect x=\"152\" y=\"172\" width=\"486\" height=\"294\" rx=\"30\" fill=\"#0D1F35\" stroke=\"rgba(139,219,255,0.18)\"/>\n  <text x=\"188\" y=\"232\" fill=\"{accent}\" font-family=\"IBM Plex Sans, Arial, sans-serif\" font-size=\"20\" letter-spacing=\"5\">{subject}</text>\n  <text x=\"188\" y=\"318\" fill=\"#F2F6FF\" font-family=\"Georgia, serif\" font-size=\"78\">Signal the brand</text>\n  <text x=\"188\" y=\"396\" fill=\"#F2F6FF\" font-family=\"Georgia, serif\" font-size=\"78\">before the demo.</text>\n  <text x=\"188\" y=\"456\" fill=\"rgba(242,246,255,0.72)\" font-family=\"IBM Plex Sans, Arial, sans-serif\" font-size=\"26\">A hero concept with orbital motion, product gravity, and a clean visual ladder.</text>\n  <rect x=\"188\" y=\"560\" width=\"236\" height=\"64\" rx=\"32\" fill=\"{accent}\"/>\n  <text x=\"250\" y=\"601\" fill=\"#07121F\" font-family=\"IBM Plex Sans, Arial, sans-serif\" font-size=\"24\" font-weight=\"700\">See the system</text>\n  <rect x=\"844\" y=\"510\" width=\"430\" height=\"208\" rx=\"28\" fill=\"#0D1F35\" stroke=\"rgba(100,242,197,0.18)\"/>\n  <text x=\"878\" y=\"566\" fill=\"rgba(242,246,255,0.64)\" font-family=\"IBM Plex Sans, Arial, sans-serif\" font-size=\"18\" letter-spacing=\"4\">PRIMARY PROOF</text>\n  <text x=\"878\" y=\"628\" fill=\"#F2F6FF\" font-family=\"Georgia, serif\" font-size=\"44\">{title}</text>\n  <text x=\"878\" y=\"676\" fill=\"rgba(242,246,255,0.72)\" font-family=\"IBM Plex Sans, Arial, sans-serif\" font-size=\"24\">{thesis}</text>\n</svg>",
        thesis = brief.artifact_thesis,
    );
    StudioGeneratedArtifactPayload {
        summary: format!(
            "Materialized a request-shaped SVG hero concept for {}.",
            brief.subject_domain
        ),
        notes: vec![
            "Mock Studio runtime used the brief to change copy and composition.".to_string(),
        ],
        files: vec![StudioGeneratedArtifactFile {
            path: "hero-concept.svg".to_string(),
            mime: "image/svg+xml".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body,
        }],
    }
}

fn build_mermaid_payload(
    title: &str,
    brief: &StudioArtifactBrief,
    intent: &str,
) -> StudioGeneratedArtifactPayload {
    let body = if intent.to_ascii_lowercase().contains("approval") {
        format!(
            "flowchart TD\n  Intake[Approval request enters pipeline] --> Route[Typed approval route]\n  Route --> Brief[Approval pipeline brief]\n  Brief --> Materialize[Candidate generation]\n  Materialize --> Validation[Request-faithfulness validation]\n  Validation -->|pass| Present[Approved artifact view]\n  Validation -->|repairable| Refine[Patch current approval revision]\n  Refine --> Materialize\n  Present --> History[Approval pipeline history compare / restore]\n  History --> Archive[Approved record for {subject}]\n",
            subject = brief.subject_domain
        )
    } else {
        format!(
            "flowchart TD\n  A[{}] --> B[{}]\n  B --> C[Presentation]\n  C --> D[Revision history]\n",
            brief.subject_domain, title
        )
    };
    StudioGeneratedArtifactPayload {
        summary: format!(
            "Materialized a Mermaid diagram for {}.",
            brief.subject_domain
        ),
        notes: vec![
            "Mock Studio runtime generated a complete graph instead of a stub diagram.".to_string(),
        ],
        files: vec![StudioGeneratedArtifactFile {
            path: "diagram.mermaid".to_string(),
            mime: "text/plain".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body,
        }],
    }
}

fn build_pdf_payload(title: &str, brief: &StudioArtifactBrief) -> StudioGeneratedArtifactPayload {
    let body = format!(
        "%PDF-1.4\n% Studio mock PDF\n1 0 obj << /Type /Catalog >> endobj\n% {title}\n# {title}\n\n## Executive summary\nThe brief centers on {subject} and keeps the artifact thesis explicit: {thesis}\n\n## Audience and operating context\nThis PDF is meant for {audience}, so the document explains the launch posture, owners, and review cadence instead of falling back to generic prose.\n\n## Coverage\nKey concepts include {concepts}. The document covers goals, milestone checkpoints, launch readiness, and the decision points required before release.\n\n## Risks and mitigations\n1. Readiness risk: connect staffing and approval checkpoints to the launch window.\n2. Messaging risk: keep the surfaced narrative specific to {subject} rather than a generic rollout shell.\n3. Continuity risk: preserve revision evidence so reviewers can compare drafts before export.\n\n## Verification\nThe artifact is complete only when the exported PDF still reads as a real brief with decisions, owners, and next actions.\n\n%%EOF\n",
        title = title,
        subject = brief.subject_domain,
        thesis = brief.artifact_thesis,
        audience = brief.audience,
        concepts = brief.required_concepts.join(", "),
    );
    StudioGeneratedArtifactPayload {
        summary: format!(
            "Materialized a PDF-ready brief for {}.",
            brief.subject_domain
        ),
        notes: vec![
            "Mock Studio runtime produced source text intended for PDF compilation.".to_string(),
        ],
        files: vec![StudioGeneratedArtifactFile {
            path: "brief.pdf".to_string(),
            mime: "application/pdf".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body,
        }],
    }
}

fn build_download_payload(
    title: &str,
    brief: &StudioArtifactBrief,
) -> StudioGeneratedArtifactPayload {
    let slug = brief
        .subject_domain
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-")
        .to_ascii_lowercase();
    let readme = format!(
        "# {title}\n\nThis bundle stays grounded in {subject} and includes a machine-friendly export plus a README so the download view is actually useful.\n\n## Files\n- `exports/{slug}.csv`\n- `README.md`\n",
        subject = brief.subject_domain,
    );
    let csv = format!(
        "lane,metric,value\npilot,engagement,64\nlaunch,coverage,72\nretention,continuity,58\nsubject,{slug},1\n"
    );
    StudioGeneratedArtifactPayload {
        summary: format!(
            "Materialized a download bundle for {}.",
            brief.subject_domain
        ),
        notes: vec![
            "Mock Studio runtime produced the actual bundle payload and README.".to_string(),
        ],
        files: vec![
            StudioGeneratedArtifactFile {
                path: "README.md".to_string(),
                mime: "text/markdown".to_string(),
                role: StudioArtifactFileRole::Supporting,
                renderable: false,
                downloadable: true,
                encoding: None,
                body: readme,
            },
            StudioGeneratedArtifactFile {
                path: format!("exports/{slug}.csv"),
                mime: "text/csv".to_string(),
                role: StudioArtifactFileRole::Export,
                renderable: false,
                downloadable: true,
                encoding: None,
                body: csv,
            },
        ],
    }
}

fn build_bundle_payload(
    title: &str,
    brief: &StudioArtifactBrief,
) -> StudioGeneratedArtifactPayload {
    StudioGeneratedArtifactPayload {
        summary: format!(
            "Materialized a bundle manifest for {}.",
            brief.subject_domain
        ),
        notes: vec![
            "Mock Studio runtime generated a bundle manifest with supporting README.".to_string(),
        ],
        files: vec![
            StudioGeneratedArtifactFile {
                path: "bundle.json".to_string(),
                mime: "application/json".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: None,
                body: json!({
                    "title": title,
                    "subject": brief.subject_domain,
                    "items": ["README.md"]
                })
                .to_string(),
            },
            StudioGeneratedArtifactFile {
                path: "README.md".to_string(),
                mime: "text/markdown".to_string(),
                role: StudioArtifactFileRole::Supporting,
                renderable: true,
                downloadable: true,
                encoding: None,
                body: format!(
                    "# {title}\n\nBundle supporting {subject}.",
                    subject = brief.subject_domain
                ),
            },
        ],
    }
}

fn evaluate_candidate(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate: &StudioGeneratedArtifactPayload,
) -> StudioArtifactValidationResult {
    let all_text = candidate
        .files
        .iter()
        .map(|file| file.body.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("\n");
    let concept_hits = brief
        .required_concepts
        .iter()
        .filter(|concept| all_text.contains(&concept.to_ascii_lowercase()))
        .count();
    let interaction_hits = brief
        .required_interactions
        .iter()
        .filter(|interaction| {
            let lowered = interaction.to_ascii_lowercase();
            all_text.contains(&lowered)
                || (lowered.contains("chart") && all_text.contains("chart"))
                || (lowered.contains("control")
                    && (all_text.contains("<button") || all_text.contains("<input")))
        })
        .count();
    let generic_shell_detected = matches!(request.renderer, StudioRendererKind::HtmlIframe)
        && !(all_text.contains(&brief.subject_domain.to_ascii_lowercase())
            || brief
                .required_concepts
                .iter()
                .any(|concept| all_text.contains(&concept.to_ascii_lowercase())));
    let trivial_shell_detected = all_text.contains("placeholder")
        || all_text.contains("coming soon")
        || candidate.files.iter().all(|file| file.body.len() < 180);
    let request_faithfulness = if generic_shell_detected { 2 } else { 5 };
    let concept_coverage =
        if concept_hits >= 3 || concept_hits >= brief.required_concepts.len().min(2) {
            5
        } else if concept_hits >= 1 {
            4
        } else {
            2
        };
    let interaction_relevance = if request.renderer == StudioRendererKind::HtmlIframe {
        if all_text.contains("chart") || all_text.contains("track") {
            5
        } else {
            3
        }
    } else if request.renderer == StudioRendererKind::JsxSandbox {
        if all_text.contains("<input") && all_text.contains("usememo") {
            5
        } else {
            3
        }
    } else if interaction_hits > 0 {
        4
    } else {
        3
    };
    let layout_coherence = if all_text.contains("<section") || all_text.contains("## ") {
        5
    } else {
        3
    };
    let visual_hierarchy = if all_text.contains("<h1") || all_text.contains("<text") {
        5
    } else {
        3
    };
    let completeness = if candidate.files.len() >= 1 && !trivial_shell_detected {
        5
    } else {
        2
    };
    let patched_existing_artifact = edit_intent.map(|intent| {
        let patch_like_intent =
            intent.patch_existing_artifact || intent.mode == StudioArtifactEditMode::Patch;
        if !patch_like_intent || candidate.files.is_empty() {
            return false;
        }

        if intent.target_paths.is_empty() {
            return true;
        }

        candidate.files.iter().any(|file| {
            intent
                .target_paths
                .iter()
                .any(|target_path| target_path.trim() == file.path.trim())
        })
    });
    let classification = if trivial_shell_detected {
        StudioArtifactValidationStatus::Blocked
    } else if generic_shell_detected {
        StudioArtifactValidationStatus::Repairable
    } else {
        StudioArtifactValidationStatus::Pass
    };
    let deserves_primary_artifact_view = classification == StudioArtifactValidationStatus::Pass;

    StudioArtifactValidationResult {
        classification,
        request_faithfulness,
        concept_coverage,
        interaction_relevance,
        layout_coherence,
        visual_hierarchy,
        completeness,
        generic_shell_detected,
        trivial_shell_detected,
        deserves_primary_artifact_view,
        patched_existing_artifact,
        continuity_revision_ux: edit_intent.map(|_| {
            if patched_existing_artifact.unwrap_or(false) {
                5
            } else {
                3
            }
        }),
        score_total: i32::from(request_faithfulness)
            + i32::from(concept_coverage)
            + i32::from(interaction_relevance)
            + i32::from(layout_coherence)
            + i32::from(visual_hierarchy)
            + i32::from(completeness),
        proof_kind: "mock_validation".to_string(),
        primary_view_cleared: deserves_primary_artifact_view,
        validated_paths: candidate
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect(),
        issue_codes: if generic_shell_detected {
            vec!["generic_shell".to_string()]
        } else if trivial_shell_detected {
            vec!["first_paint_incomplete".to_string()]
        } else {
            Vec::new()
        },
        issue_classes: if generic_shell_detected {
            vec!["generic_shell".to_string()]
        } else if trivial_shell_detected {
            vec!["first_paint_incomplete".to_string()]
        } else {
            Vec::new()
        },
        repair_hints: if deserves_primary_artifact_view {
            Vec::new()
        } else {
            vec![
                "Add more request-specific evidence and strengthen the interaction surface."
                    .to_string(),
            ]
        },
        strengths: if deserves_primary_artifact_view {
            vec!["Candidate is strong enough to lead the stage.".to_string()]
        } else {
            Vec::new()
        },
        blocked_reasons: if classification == StudioArtifactValidationStatus::Blocked {
            vec!["The candidate is too thin to serve as the primary artifact surface.".to_string()]
        } else {
            Vec::new()
        },
        file_findings: candidate
            .files
            .iter()
            .find(|file| file.renderable)
            .map(|file| {
                vec![format!(
                    "{}: {}",
                    file.path,
                    if deserves_primary_artifact_view {
                        "renderable primary surface looks acceptable"
                    } else {
                        "renderable primary surface needs another pass"
                    }
                )]
            })
            .unwrap_or_default(),
        aesthetic_verdict: if generic_shell_detected {
            "The artifact still looks like a generic shell.".to_string()
        } else if trivial_shell_detected {
            "The surface is too thin to feel intentional.".to_string()
        } else {
            "Visual hierarchy is strong enough for the current stage.".to_string()
        },
        interaction_verdict: if interaction_relevance >= 4 {
            "Interactions stay aligned with the typed brief.".to_string()
        } else {
            "Interactions need another pass before the artifact can lead.".to_string()
        },
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some(
            if deserves_primary_artifact_view {
                "accept"
            } else if classification == StudioArtifactValidationStatus::Blocked {
                "hold_block"
            } else {
                "structural_repair"
            }
            .to_string(),
        ),
        strongest_contradiction: if generic_shell_detected {
            Some(
                "The artifact does not foreground the actual subject domain strongly enough."
                    .to_string(),
            )
        } else if trivial_shell_detected {
            Some("The candidate is too thin to serve as the primary artifact surface.".to_string())
        } else {
            None
        },
        rationale: if deserves_primary_artifact_view {
            format!(
                "The candidate stays grounded in {}, covers the required concepts, and is strong enough to lead the stage.",
                brief.subject_domain
            )
        } else {
            "The candidate needs another pass before it deserves the primary artifact view."
                .to_string()
        },
        summary: if deserves_primary_artifact_view {
            "Mock validation cleared the candidate for the primary artifact view.".to_string()
        } else {
            "Mock validation kept the candidate below the primary artifact threshold.".to_string()
        },
    }
}

fn extract_selection_path(text: &str) -> Option<String> {
    let marker = "selection from ";
    let lower = text.to_ascii_lowercase();
    let index = lower.find(marker)?;
    let rest = &text[index + marker.len()..];
    Some(
        rest.split(['\n', ':'])
            .next()
            .unwrap_or_default()
            .trim()
            .to_string(),
    )
    .filter(|value| !value.is_empty())
}

fn extract_selection_snippet(text: &str) -> String {
    text.split("\n\n")
        .nth(1)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn extract_text_block(input: &str, start_marker: &str, end_marker: &str) -> Option<String> {
    let start = input.find(start_marker)? + start_marker.len();
    let end = input[start..]
        .find(end_marker)
        .map(|offset| start + offset)
        .unwrap_or_else(|| input.len());
    Some(input[start..end].trim().to_string())
}

fn extract_json_after(input: &str, marker: &str) -> Option<String> {
    let start = input.find(marker)? + marker.len();
    let remaining = input[start..].trim_start();
    if remaining.starts_with("null") {
        return Some("null".to_string());
    }
    extract_json_value(remaining)
}

fn extract_json_value(raw: &str) -> Option<String> {
    let start = raw.find(|ch| ['{', '['].contains(&ch))?;
    let mut stack = Vec::<char>::new();
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in raw[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match ch {
            '{' | '[' => stack.push(ch),
            '}' => {
                if stack.pop() != Some('{') {
                    return None;
                }
            }
            ']' => {
                if stack.pop() != Some('[') {
                    return None;
                }
            }
            _ => {}
        }
        if stack.is_empty() {
            return Some(raw[start..start + offset + 1].to_string());
        }
    }
    None
}

#[allow(dead_code)]
fn parse_json<T: DeserializeOwned>(raw: &str) -> Option<T> {
    serde_json::from_str(raw).ok()
}

#[cfg(test)]
#[path = "studio_mock/tests.rs"]
mod tests;
