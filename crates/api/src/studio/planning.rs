use super::judging::studio_artifact_refinement_context_view;
use super::*;

fn studio_planning_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_STUDIO_PROOF_TRACE").is_some() {
        eprintln!("[studio-proof-trace] {}", message.as_ref());
    }
}

fn truncate_planning_preview(raw: &str, max_chars: usize) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "<empty>".to_string();
    }
    let mut preview = trimmed.chars().take(max_chars).collect::<String>();
    if trimmed.chars().count() > max_chars {
        preview.push_str("...");
    }
    preview
}

pub async fn plan_studio_outcome_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioOutcomePlanningPayload, String> {
    let payload = build_studio_outcome_router_prompt(intent, active_artifact_id, active_artifact);
    let input = serde_json::to_vec(&payload).map_err(|error| {
        format!(
            "Failed to encode Studio outcome planning payload: {}",
            error
        )
    })?;
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: 768,
                ..Default::default()
            },
        )
        .await
        .map_err(|error| format!("Studio outcome planning inference failed: {}", error))?;
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Studio outcome planning utf8 decode failed: {}", error))?;
    let mut planning = parse_studio_outcome_planning_payload(&raw)?;
    planning.artifact = planning.artifact.map(canonicalize_artifact_request);
    Ok(planning)
}

pub fn build_studio_outcome_router_prompt(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> serde_json::Value {
    let active_artifact_context_json =
        studio_artifact_refinement_context_view(active_artifact).to_string();
    json!([
        {
            "role": "system",
            "content": "You are Studio's typed outcome router. Route a user request to exactly one outcome kind: conversation, tool_widget, visualizer, or artifact. Do not guess. If confidence is low, set needsClarification true. Workspace is only one artifact renderer, not the default. Artifact output must be chosen when the request should become a persistent work product. When an active artifact context is supplied, continue that artifact by default for under-specified follow-up edits instead of switching renderer families. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Request:\n{}\n\nActive artifact id: {}\n\nActive artifact context JSON:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"outcomeKind\": \"conversation\" | \"tool_widget\" | \"visualizer\" | \"artifact\",\n  \"confidence\": <0_to_1_float>,\n  \"needsClarification\": <boolean>,\n  \"clarificationQuestions\": [<string>],\n  \"artifact\": null | {{\n    \"artifactClass\": \"document\" | \"visual\" | \"interactive_single_file\" | \"downloadable_file\" | \"workspace_project\" | \"compound_bundle\" | \"code_patch\" | \"report_bundle\",\n    \"deliverableShape\": \"single_file\" | \"file_set\" | \"workspace_project\",\n    \"renderer\": \"markdown\" | \"html_iframe\" | \"jsx_sandbox\" | \"svg\" | \"mermaid\" | \"pdf_embed\" | \"download_card\" | \"workspace_surface\" | \"bundle_manifest\",\n    \"presentationSurface\": \"inline\" | \"side_panel\" | \"overlay\" | \"tabbed_panel\",\n    \"persistence\": \"ephemeral\" | \"artifact_scoped\" | \"shared_artifact_scoped\" | \"workspace_filesystem\",\n    \"executionSubstrate\": \"none\" | \"client_sandbox\" | \"binary_generator\" | \"workspace_runtime\",\n    \"workspaceRecipeId\": null | \"react-vite\" | \"vite-static-html\",\n    \"presentationVariantId\": null | \"sport-editorial\" | \"minimal-agency\" | \"hospitality-retreat\" | \"product-launch\",\n    \"scope\": {{\n      \"targetProject\": null | <string>,\n      \"createNewWorkspace\": <boolean>,\n      \"mutationBoundary\": [<string>]\n    }},\n    \"verification\": {{\n      \"requireRender\": <boolean>,\n      \"requireBuild\": <boolean>,\n      \"requirePreview\": <boolean>,\n      \"requireExport\": <boolean>,\n      \"requireDiffReview\": <boolean>\n    }}\n  }}\n}}\nRenderer contracts:\n- markdown = a single renderable .md document.\n- html_iframe = a single self-contained .html document for browser presentation. Choose this when the final artifact should be HTML itself, such as a landing page, explainer, launch page, editorial page, or browser-native interactive document.\n- jsx_sandbox = a single .jsx source module with a default export. Choose this only when the final artifact should be JSX/React source as the work product rather than a plain HTML document.\n- svg = a single .svg visual artifact.\n- mermaid = a single .mermaid diagram source artifact.\n- pdf_embed = a document artifact that will be compiled into PDF bytes.\n- download_card = downloadable files or exports, not a primary inline document surface.\n- workspace_surface = a real multi-file workspace with supervised build/preview.\nCoherence rules:\n- html_iframe and jsx_sandbox are interactive_single_file artifacts with single_file deliverableShape and client_sandbox executionSubstrate.\n- workspace_surface is the only renderer that may use workspace_project deliverableShape, workspace_runtime executionSubstrate, createNewWorkspace=true, requireBuild=true, or requirePreview=true.\n- Non-workspace artifact renderers should not request build or preview verification.\nRules:\n1) conversation is for plain reply only.\n2) tool_widget is for first-party tool display surfaces.\n3) visualizer is for ephemeral inline visuals.\n4) artifact is for persistent work products.\n5) Use workspace_surface only when a real multi-file workspace and preview runtime are required.\n6) Treat explicit medium-plus-deliverable requests as sufficiently specified artifact work. If the user already asked for an HTML artifact, landing page, launch page, editorial page, markdown document, SVG concept, Mermaid diagram, PDF artifact, downloadable bundle, or workspace project, do not ask clarification merely to restate that same deliverable form.\n7) For example, \"Create an interactive HTML artifact for an AI tools editorial launch page\" is already an artifact request for html_iframe, not a clarification request.\n8) When active artifact context JSON is not null and the request is a follow-up refinement, patch or branch the current artifact by default instead of switching renderer, artifactClass, or deliverableShape unless the user explicitly asks for a different deliverable form.\n9) Under-specified follow-up requests should continue the active artifact rather than restarting as a new artifact kind.\n10) Do not use lexical fallbacks or benchmark phrase maps.\n11) When uncertainty remains about a required missing constraint, keep confidence low and ask clarification.",
                intent,
                active_artifact_id.unwrap_or("<none>"),
                active_artifact_context_json,
            )
        }
    ])
}

fn canonicalize_artifact_request(
    request: StudioOutcomeArtifactRequest,
) -> StudioOutcomeArtifactRequest {
    let renderer = request.renderer;
    let artifact_class = match renderer {
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed => {
            StudioArtifactClass::Document
        }
        StudioRendererKind::Svg | StudioRendererKind::Mermaid => StudioArtifactClass::Visual,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => {
            StudioArtifactClass::InteractiveSingleFile
        }
        StudioRendererKind::DownloadCard => StudioArtifactClass::DownloadableFile,
        StudioRendererKind::WorkspaceSurface => StudioArtifactClass::WorkspaceProject,
        StudioRendererKind::BundleManifest => match request.artifact_class {
            StudioArtifactClass::CompoundBundle
            | StudioArtifactClass::ReportBundle
            | StudioArtifactClass::CodePatch => request.artifact_class,
            _ => StudioArtifactClass::CompoundBundle,
        },
    };
    let deliverable_shape = match renderer {
        StudioRendererKind::WorkspaceSurface => StudioArtifactDeliverableShape::WorkspaceProject,
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => {
            StudioArtifactDeliverableShape::FileSet
        }
        _ => StudioArtifactDeliverableShape::SingleFile,
    };
    let presentation_surface = match renderer {
        StudioRendererKind::WorkspaceSurface => StudioPresentationSurface::TabbedPanel,
        _ => StudioPresentationSurface::SidePanel,
    };
    let persistence = match renderer {
        StudioRendererKind::WorkspaceSurface => StudioArtifactPersistenceMode::WorkspaceFilesystem,
        StudioRendererKind::BundleManifest => StudioArtifactPersistenceMode::ArtifactScoped,
        _ => StudioArtifactPersistenceMode::SharedArtifactScoped,
    };
    let execution_substrate = match renderer {
        StudioRendererKind::WorkspaceSurface => StudioExecutionSubstrate::WorkspaceRuntime,
        StudioRendererKind::PdfEmbed => StudioExecutionSubstrate::BinaryGenerator,
        StudioRendererKind::HtmlIframe
        | StudioRendererKind::JsxSandbox
        | StudioRendererKind::Svg
        | StudioRendererKind::Mermaid => StudioExecutionSubstrate::ClientSandbox,
        _ => StudioExecutionSubstrate::None,
    };
    let scope = StudioOutcomeArtifactScope {
        target_project: request.scope.target_project,
        create_new_workspace: renderer == StudioRendererKind::WorkspaceSurface,
        mutation_boundary: if request.scope.mutation_boundary.is_empty() {
            vec!["artifact".to_string()]
        } else {
            request.scope.mutation_boundary
        },
    };
    let verification = StudioOutcomeArtifactVerificationRequest {
        require_render: request.verification.require_render,
        require_build: renderer == StudioRendererKind::WorkspaceSurface,
        require_preview: renderer == StudioRendererKind::WorkspaceSurface,
        require_export: request.verification.require_export,
        require_diff_review: if renderer == StudioRendererKind::WorkspaceSurface {
            request.verification.require_diff_review
        } else {
            false
        },
    };

    StudioOutcomeArtifactRequest {
        artifact_class,
        deliverable_shape,
        renderer,
        presentation_surface,
        persistence,
        execution_substrate,
        workspace_recipe_id: if renderer == StudioRendererKind::WorkspaceSurface {
            request.workspace_recipe_id
        } else {
            None
        },
        presentation_variant_id: if matches!(
            renderer,
            StudioRendererKind::HtmlIframe
                | StudioRendererKind::JsxSandbox
                | StudioRendererKind::WorkspaceSurface
        ) {
            request.presentation_variant_id
        } else {
            None
        },
        scope,
        verification,
    }
}

pub fn parse_studio_outcome_planning_payload(
    raw: &str,
) -> Result<StudioOutcomePlanningPayload, String> {
    let mut value = parse_studio_json_object_value(
        raw,
        "Studio outcome planning output missing JSON payload",
        "Failed to parse Studio outcome planning payload",
    )?;
    normalize_studio_outcome_planning_value(&mut value);
    serde_json::from_value::<StudioOutcomePlanningPayload>(value)
        .map_err(|error| format!("Failed to parse Studio outcome planning payload: {}", error))
}

pub async fn plan_studio_artifact_brief_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioArtifactBrief, String> {
    let parse_and_validate = |raw: &str| -> Result<StudioArtifactBrief, String> {
        let brief = canonicalize_studio_artifact_brief_for_request(
            parse_studio_artifact_brief(raw)?,
            request,
        );
        validate_studio_artifact_brief_against_request(&brief, request, refinement)?;
        Ok(brief)
    };
    let payload = build_studio_artifact_brief_prompt(title, intent, request, refinement)?;
    let input = serde_json::to_vec(&payload)
        .map_err(|error| format!("Failed to encode Studio artifact brief prompt: {error}"))?;
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: 448,
                ..Default::default()
            },
        )
        .await
        .map_err(|error| format!("Studio artifact brief inference failed: {error}"))?;
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Studio artifact brief utf8 decode failed: {error}"))?;
    studio_planning_trace(format!(
        "artifact_brief:planner_output {}",
        truncate_planning_preview(&raw, 1200)
    ));
    match parse_and_validate(&raw) {
        Ok(brief) => Ok(brief),
        Err(first_error) => {
            studio_planning_trace(format!("artifact_brief:planner_rejected {first_error}"));
            let repair_payload = build_studio_artifact_brief_repair_prompt(
                title,
                intent,
                request,
                refinement,
                &raw,
                &first_error,
            )?;
            let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                format!("Failed to encode Studio artifact brief repair prompt: {error}")
            })?;
            let repair_output = runtime
                .execute_inference(
                    [0u8; 32],
                    &repair_input,
                    InferenceOptions {
                        temperature: 0.0,
                        json_mode: true,
                        max_tokens: 448,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| {
                    format!("{first_error}; brief repair inference failed: {error}")
                })?;
            let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                format!("{first_error}; brief repair utf8 decode failed: {error}")
            })?;
            studio_planning_trace(format!(
                "artifact_brief:repair_output {}",
                truncate_planning_preview(&repair_raw, 1200)
            ));
            match parse_and_validate(&repair_raw) {
                Ok(brief) => Ok(brief),
                Err(repair_error) => {
                    studio_planning_trace(format!("artifact_brief:repair_rejected {repair_error}"));
                    let field_repair_payload = build_studio_artifact_brief_field_repair_prompt(
                        title,
                        intent,
                        request,
                        refinement,
                        &raw,
                        &repair_raw,
                        &repair_error,
                    )?;
                    let field_repair_input =
                        serde_json::to_vec(&field_repair_payload).map_err(|error| {
                            format!(
                                "Failed to encode Studio artifact brief field repair prompt: {error}"
                            )
                        })?;
                    let field_repair_output = runtime
                        .execute_inference(
                            [0u8; 32],
                            &field_repair_input,
                            InferenceOptions {
                                temperature: 0.0,
                                json_mode: true,
                                max_tokens: 320,
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(|error| {
                            format!(
                                "{first_error}; brief repair attempt failed: {repair_error}; brief field repair inference failed: {error}"
                            )
                        })?;
                    let field_repair_raw =
                        String::from_utf8(field_repair_output).map_err(|error| {
                            format!(
                                "{first_error}; brief repair attempt failed: {repair_error}; brief field repair utf8 decode failed: {error}"
                            )
                        })?;
                    studio_planning_trace(format!(
                        "artifact_brief:field_repair_output {}",
                        truncate_planning_preview(&field_repair_raw, 1200)
                    ));
                    parse_and_validate(&field_repair_raw).map_err(|field_repair_error| {
                        format!(
                            "{first_error}; brief repair attempt failed: {repair_error}; brief field repair attempt also failed: {field_repair_error}; planner output preview: {}; repair output preview: {}; field repair output preview: {}",
                            truncate_planning_preview(&raw, 600),
                            truncate_planning_preview(&repair_raw, 600),
                            truncate_planning_preview(&field_repair_raw, 600),
                        )
                    })
                }
            }
        }
    }
}

pub fn build_studio_artifact_brief_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<serde_json::Value, String> {
    let request_json = serde_json::to_string(request)
        .map_err(|error| format!("Failed to serialize Studio artifact request: {error}"))?;
    let refinement_json =
        serde_json::to_string(&studio_artifact_refinement_context_view(refinement))
            .map_err(|error| format!("Failed to serialize Studio refinement context: {error}"))?;
    let renderer_guidance = studio_artifact_brief_planning_guidance(request);
    let validation_contract = studio_artifact_brief_validation_contract(request);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact brief planner. Convert a request into a renderer-agnostic artifact brief before file generation begins. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nCurrent artifact context:\n{}\n\nRenderer-aware brief guidance:\n{}\n\nValidation contract:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"audience\": <string>,\n  \"jobToBeDone\": <string>,\n  \"subjectDomain\": <string>,\n  \"artifactThesis\": <string>,\n  \"requiredConcepts\": [<string>],\n  \"requiredInteractions\": [<string>],\n  \"visualTone\": [<string>],\n  \"factualAnchors\": [<string>],\n  \"styleDirectives\": [<string>],\n  \"referenceHints\": [<string>]\n}}\nRules:\n1) Keep the brief request-grounded, not renderer-template-grounded.\n2) Distinguish subject matter from presentation tone.\n3) Preserve the concrete differentiating nouns and framing words from the request instead of abstracting them away.\n4) audience, jobToBeDone, subjectDomain, and artifactThesis must be non-empty request-grounded strings.\n5) requiredConcepts must include the request-specific concepts that would make a nearby but wrong artifact fail, such as launch/editorial/domain nouns when they matter.\n6) If a refinement context exists, preserve useful continuity and call out what must remain stable.\n7) Use empty arrays instead of invented filler.",
                title,
                intent,
                request_json,
                refinement_json,
                renderer_guidance,
                validation_contract,
            )
        }
    ]))
}

fn parse_studio_json_object_value(
    raw: &str,
    missing_payload_error: &str,
    parse_error_prefix: &str,
) -> Result<serde_json::Value, String> {
    let value = serde_json::from_str::<serde_json::Value>(raw).or_else(|_| {
        let extracted = super::extract_first_json_object(raw)
            .ok_or_else(|| missing_payload_error.to_string())?;
        serde_json::from_str::<serde_json::Value>(&extracted).map_err(|error| error.to_string())
    });
    let value = value.map_err(|error| format!("{parse_error_prefix}: {error}"))?;
    if !value.is_object() {
        return Err(format!(
            "{parse_error_prefix}: output must be a JSON object."
        ));
    }
    Ok(value)
}

fn coerce_string_field(value: &mut serde_json::Value) {
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

fn coerce_bool_field(value: &mut serde_json::Value) {
    if let serde_json::Value::String(text) = value {
        let normalized = text.trim().to_ascii_lowercase();
        if normalized == "true" {
            *value = serde_json::Value::Bool(true);
        } else if normalized == "false" {
            *value = serde_json::Value::Bool(false);
        }
    }
}

fn coerce_string_array_field(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(_) => {}
        serde_json::Value::String(text) => {
            let entry = text.trim().to_string();
            *value = if entry.is_empty() {
                serde_json::Value::Array(Vec::new())
            } else {
                serde_json::Value::Array(vec![serde_json::Value::String(entry)])
            };
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::Array(Vec::new());
        }
        _ => {}
    }
}

fn coerce_object_array_field(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(_) => {}
        serde_json::Value::Object(object) => {
            *value = serde_json::Value::Array(vec![serde_json::Value::Object(object.clone())]);
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::Array(Vec::new());
        }
        _ => {}
    }
}

fn normalize_studio_artifact_brief_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    for field in ["audience", "jobToBeDone", "subjectDomain", "artifactThesis"] {
        if let Some(entry) = object.get_mut(field) {
            coerce_string_field(entry);
        }
    }
    for field in [
        "requiredConcepts",
        "requiredInteractions",
        "visualTone",
        "factualAnchors",
        "styleDirectives",
        "referenceHints",
    ] {
        if let Some(entry) = object.get_mut(field) {
            coerce_string_array_field(entry);
        }
    }
}

fn normalize_studio_outcome_artifact_request_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    let scope = object.entry("scope").or_insert_with(|| {
        json!({
            "targetProject": null,
            "createNewWorkspace": false,
            "mutationBoundary": []
        })
    });
    if let Some(scope_object) = scope.as_object_mut() {
        if !scope_object.contains_key("targetProject") {
            scope_object.insert("targetProject".to_string(), serde_json::Value::Null);
        }
        if let Some(entry) = scope_object.get_mut("createNewWorkspace") {
            coerce_bool_field(entry);
        } else {
            scope_object.insert(
                "createNewWorkspace".to_string(),
                serde_json::Value::Bool(false),
            );
        }
        if let Some(entry) = scope_object.get_mut("mutationBoundary") {
            coerce_string_array_field(entry);
        } else {
            scope_object.insert(
                "mutationBoundary".to_string(),
                serde_json::Value::Array(Vec::new()),
            );
        }
    }

    let verification = object.entry("verification").or_insert_with(|| {
        json!({
            "requireRender": false,
            "requireBuild": false,
            "requirePreview": false,
            "requireExport": false,
            "requireDiffReview": false
        })
    });
    if let Some(verification_object) = verification.as_object_mut() {
        for field in [
            "requireRender",
            "requireBuild",
            "requirePreview",
            "requireExport",
            "requireDiffReview",
        ] {
            if let Some(entry) = verification_object.get_mut(field) {
                coerce_bool_field(entry);
            } else {
                verification_object.insert(field.to_string(), serde_json::Value::Bool(false));
            }
        }
    }
}

fn normalize_studio_outcome_planning_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    if let Some(entry) = object.get_mut("needsClarification") {
        coerce_bool_field(entry);
    }
    if let Some(entry) = object.get_mut("clarificationQuestions") {
        coerce_string_array_field(entry);
    }
    if let Some(artifact) = object.get_mut("artifact") {
        normalize_studio_outcome_artifact_request_value(artifact);
    }
}

fn normalize_inline_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn split_interaction_identifier_terms(value: &str) -> Vec<String> {
    let mut terms = Vec::<String>::new();
    let mut current = String::new();
    let mut previous_was_lower_or_digit = false;

    for character in value.chars() {
        if !character.is_alphanumeric() {
            if !current.is_empty() {
                terms.push(std::mem::take(&mut current));
            }
            previous_was_lower_or_digit = false;
            continue;
        }

        if character.is_ascii_uppercase() && previous_was_lower_or_digit && !current.is_empty() {
            terms.push(std::mem::take(&mut current));
        }

        current.push(character.to_ascii_lowercase());
        previous_was_lower_or_digit = character.is_ascii_lowercase() || character.is_ascii_digit();
    }

    if !current.is_empty() {
        terms.push(current);
    }

    terms
}

fn canonical_interaction_response_clause(terms: &[String]) -> &'static str {
    if terms
        .iter()
        .any(|term| matches!(term.as_str(), "hover" | "rollover" | "focus"))
    {
        "to reveal shared detail in the visible detail panel"
    } else if terms.iter().any(|term| {
        matches!(
            term.as_str(),
            "click" | "switch" | "toggle" | "tab" | "navigation" | "navigate" | "jump" | "view"
        )
    }) {
        "to switch the visible evidence view"
    } else if terms
        .iter()
        .any(|term| matches!(term.as_str(), "compare" | "comparison"))
    {
        "to update the shared comparison panel"
    } else {
        "to update the visible chart and detail panel"
    }
}

fn canonicalize_identifier_interaction(value: &str) -> String {
    let normalized = normalize_inline_whitespace(value);
    if normalized.contains(' ') {
        return normalized;
    }

    let terms = split_interaction_identifier_terms(&normalized);
    if terms.len() < 2 {
        return normalized;
    }

    let phrase = terms.join(" ");
    if phrase.contains("update ")
        || phrase.contains("reveal ")
        || phrase.contains("show ")
        || phrase.contains("switch ")
    {
        phrase
    } else {
        format!("{phrase} {}", canonical_interaction_response_clause(&terms))
    }
}

fn canonicalize_brief_list(entries: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::<String>::new();
    for entry in entries {
        let entry = normalize_inline_whitespace(&entry);
        if entry.is_empty()
            || normalized
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&entry))
        {
            continue;
        }
        normalized.push(entry);
    }
    normalized
}

fn canonicalize_brief_interactions(
    interactions: Vec<String>,
    request: &StudioOutcomeArtifactRequest,
) -> Vec<String> {
    let requires_concrete_interactions = matches!(
        request.renderer,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
    );
    let mut normalized = Vec::<String>::new();

    for interaction in interactions {
        let entry = if requires_concrete_interactions {
            canonicalize_identifier_interaction(&interaction)
        } else {
            normalize_inline_whitespace(&interaction)
        };

        if entry.is_empty()
            || normalized
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&entry))
        {
            continue;
        }
        normalized.push(entry);
    }

    normalized
}

pub(crate) fn canonicalize_studio_artifact_brief_for_request(
    mut brief: StudioArtifactBrief,
    request: &StudioOutcomeArtifactRequest,
) -> StudioArtifactBrief {
    brief.audience = normalize_inline_whitespace(&brief.audience);
    brief.job_to_be_done = normalize_inline_whitespace(&brief.job_to_be_done);
    brief.subject_domain = normalize_inline_whitespace(&brief.subject_domain);
    brief.artifact_thesis = normalize_inline_whitespace(&brief.artifact_thesis);
    brief.required_concepts = canonicalize_brief_list(brief.required_concepts);
    brief.required_interactions =
        canonicalize_brief_interactions(brief.required_interactions, request);
    brief.visual_tone = canonicalize_brief_list(brief.visual_tone);
    brief.factual_anchors = canonicalize_brief_list(brief.factual_anchors);
    brief.style_directives = canonicalize_brief_list(brief.style_directives);
    brief.reference_hints = canonicalize_brief_list(brief.reference_hints);
    brief
}

fn normalize_studio_artifact_edit_intent_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    for field in ["mode", "summary", "targetScope"] {
        if let Some(entry) = object.get_mut(field) {
            coerce_string_field(entry);
        }
    }
    for field in [
        "patchExistingArtifact",
        "preserveStructure",
        "branchRequested",
    ] {
        if let Some(entry) = object.get_mut(field) {
            coerce_bool_field(entry);
        }
    }
    for field in [
        "targetPaths",
        "requestedOperations",
        "toneDirectives",
        "styleDirectives",
    ] {
        if let Some(entry) = object.get_mut(field) {
            coerce_string_array_field(entry);
        }
    }
    if let Some(entry) = object.get_mut("selectedTargets") {
        coerce_object_array_field(entry);
    }
}

pub fn parse_studio_artifact_brief(raw: &str) -> Result<StudioArtifactBrief, String> {
    let mut value = parse_studio_json_object_value(
        raw,
        "Studio artifact brief output missing JSON payload",
        "Failed to parse Studio artifact brief",
    )?;
    normalize_studio_artifact_brief_value(&mut value);
    let brief = serde_json::from_value::<StudioArtifactBrief>(value)
        .map_err(|error| format!("Failed to parse Studio artifact brief: {error}"))?;

    if brief.audience.trim().is_empty()
        || brief.job_to_be_done.trim().is_empty()
        || brief.subject_domain.trim().is_empty()
        || brief.artifact_thesis.trim().is_empty()
    {
        return Err("Studio artifact brief fields must not be empty.".to_string());
    }

    Ok(brief)
}

fn studio_artifact_brief_planning_guidance(request: &StudioOutcomeArtifactRequest) -> String {
    match request.renderer {
        StudioRendererKind::HtmlIframe => "- Name at least two concrete on-page interaction patterns in requiredInteractions.\n- Single-word labels like \"interactive\" or \"explains\" are not sufficient interaction plans.\n- Keep requiredConcepts tied to the visible evidence surfaces or sections.\n- Provide at least one concrete evidence anchor or reference hint.".to_string(),
        StudioRendererKind::JsxSandbox => "- Name at least one concrete stateful interaction.\n- requiredInteractions should describe user action plus visible response.".to_string(),
        _ => "- Keep the brief concrete, request-specific, and directly usable by the materializer.".to_string(),
    }
}

fn studio_artifact_brief_validation_contract(request: &StudioOutcomeArtifactRequest) -> String {
    match request.renderer {
        StudioRendererKind::HtmlIframe => "- requiredConcepts must include at least three concrete request-grounded concepts.\n- requiredInteractions must include at least two multi-word interaction descriptions.\n- At least one factualAnchors or referenceHints entry must be present.".to_string(),
        StudioRendererKind::JsxSandbox => "- requiredInteractions must include at least one multi-word interaction description.".to_string(),
        _ => "- Keep required fields non-empty and list fields schema-valid.".to_string(),
    }
}

fn interaction_phrase_term_count(value: &str) -> usize {
    value
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .count()
}

fn interaction_grounding_noise_term(term: &str) -> bool {
    matches!(
        term,
        "a" | "an"
            | "and"
            | "artifact"
            | "artifacts"
            | "experience"
            | "for"
            | "from"
            | "in"
            | "interactive"
            | "interaction"
            | "interactions"
            | "of"
            | "on"
            | "page"
            | "pages"
            | "surface"
            | "surfaces"
            | "the"
            | "to"
            | "ui"
            | "ux"
            | "with"
    )
}

fn interaction_behavior_term(term: &str) -> bool {
    [
        "browse",
        "click",
        "compare",
        "detail",
        "drill",
        "filter",
        "focus",
        "highlight",
        "hover",
        "inspect",
        "nav",
        "rollover",
        "scrub",
        "scroll",
        "select",
        "sequence",
        "step",
        "switch",
        "tab",
        "toggle",
        "view",
    ]
    .iter()
    .any(|prefix| term.starts_with(prefix))
}

fn interaction_grounding_terms(brief: &StudioArtifactBrief) -> Vec<String> {
    let mut terms = Vec::<String>::new();
    for value in std::iter::once(brief.subject_domain.as_str())
        .chain(std::iter::once(brief.artifact_thesis.as_str()))
        .chain(brief.required_concepts.iter().map(String::as_str))
        .chain(brief.factual_anchors.iter().map(String::as_str))
        .chain(brief.reference_hints.iter().map(String::as_str))
    {
        for term in split_interaction_identifier_terms(value) {
            if term.len() < 3
                || interaction_grounding_noise_term(&term)
                || terms.iter().any(|existing| existing == &term)
            {
                continue;
            }
            terms.push(term);
        }
    }
    terms
}

fn refinement_interaction_grounding_terms(
    refinement: &StudioArtifactRefinementContext,
) -> Vec<String> {
    let mut terms = Vec::<String>::new();
    for value in std::iter::once(refinement.title.as_str())
        .chain(std::iter::once(refinement.summary.as_str()))
        .chain(refinement.files.iter().map(|file| file.path.as_str()))
        .chain(refinement.files.iter().map(|file| file.body.as_str()))
        .chain(
            refinement
                .selected_targets
                .iter()
                .map(|target| target.label.as_str()),
        )
        .chain(
            refinement
                .selected_targets
                .iter()
                .map(|target| target.snippet.as_str()),
        )
    {
        for term in split_interaction_identifier_terms(value) {
            if term.len() < 3
                || interaction_grounding_noise_term(&term)
                || terms.iter().any(|existing| existing == &term)
            {
                continue;
            }
            terms.push(term);
        }
    }
    terms
}

fn interaction_grounding_terms_for_validation(
    brief: &StudioArtifactBrief,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Vec<String> {
    let mut terms = interaction_grounding_terms(brief);
    if let Some(refinement) = refinement {
        for term in refinement_interaction_grounding_terms(refinement) {
            if !terms.iter().any(|existing| existing == &term) {
                terms.push(term);
            }
        }
    }
    terms
}

fn interaction_has_grounded_terms(interaction: &str, grounding_terms: &[String]) -> bool {
    let terms = split_interaction_identifier_terms(interaction)
        .into_iter()
        .filter(|term| term.len() >= 3 && !interaction_grounding_noise_term(term))
        .collect::<Vec<_>>();
    if terms.is_empty() {
        return false;
    }

    terms.iter().any(|term| {
        interaction_behavior_term(term) || grounding_terms.iter().any(|grounding| grounding == term)
    })
}

pub(crate) fn validate_studio_artifact_brief_against_request(
    brief: &StudioArtifactBrief,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<(), String> {
    if brief.required_concepts.is_empty() {
        return Err(
            "Studio artifact briefs must include at least one required concept.".to_string(),
        );
    }

    match request.renderer {
        StudioRendererKind::HtmlIframe => {
            if brief.required_concepts.len() < 3 {
                return Err(
                    "Interactive HTML briefs must keep at least three concrete request concepts visible."
                        .to_string(),
                );
            }
            if brief.required_interactions.len() < 2 {
                return Err(
                    "Interactive HTML briefs must name at least two concrete interaction patterns."
                        .to_string(),
                );
            }
            if brief
                .required_interactions
                .iter()
                .any(|interaction| interaction_phrase_term_count(interaction) < 2)
            {
                return Err(
                    "Interactive HTML brief interactions must describe concrete user actions and visible on-page responses, not single-word labels."
                        .to_string(),
                );
            }
            if brief.factual_anchors.is_empty() && brief.reference_hints.is_empty() {
                return Err(
                    "Interactive HTML briefs must identify at least one concrete evidence anchor or reference hint."
                        .to_string(),
                );
            }
            let grounding_terms = interaction_grounding_terms_for_validation(brief, refinement);
            if brief
                .required_interactions
                .iter()
                .any(|interaction| !interaction_has_grounded_terms(interaction, &grounding_terms))
            {
                return Err(
                    "Interactive HTML briefs must keep requiredInteractions grounded in request concepts, evidence anchors, or concrete on-page behavior."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::JsxSandbox => {
            if brief.required_interactions.is_empty() {
                return Err(
                    "Interactive JSX briefs must name at least one concrete interaction pattern."
                        .to_string(),
                );
            }
            if brief
                .required_interactions
                .iter()
                .any(|interaction| interaction_phrase_term_count(interaction) < 2)
            {
                return Err(
                    "Interactive JSX brief interactions must describe concrete user actions and visible component responses."
                        .to_string(),
                );
            }
        }
        _ => {}
    }

    Ok(())
}

pub fn build_studio_artifact_brief_repair_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    let request_json = serde_json::to_string(request)
        .map_err(|error| format!("Failed to serialize Studio artifact request: {error}"))?;
    let refinement_json =
        serde_json::to_string(&studio_artifact_refinement_context_view(refinement))
            .map_err(|error| format!("Failed to serialize Studio refinement context: {error}"))?;
    let renderer_guidance = studio_artifact_brief_planning_guidance(request);
    let validation_contract = studio_artifact_brief_validation_contract(request);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact brief repairer. Repair the previous brief into a schema-valid renderer-agnostic artifact brief. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nCurrent artifact context:\n{}\n\nRenderer-aware brief guidance:\n{}\n\nValidation contract:\n{}\n\nThe previous brief output was rejected.\nFailure:\n{}\n\nPrevious raw output:\n{}\n\nRepair the brief so it is schema-valid, request-grounded, and preserves the concrete differentiating nouns from the request.\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"audience\": <string>,\n  \"jobToBeDone\": <string>,\n  \"subjectDomain\": <string>,\n  \"artifactThesis\": <string>,\n  \"requiredConcepts\": [<string>],\n  \"requiredInteractions\": [<string>],\n  \"visualTone\": [<string>],\n  \"factualAnchors\": [<string>],\n  \"styleDirectives\": [<string>],\n  \"referenceHints\": [<string>]\n}}\nRules:\n1) Use arrays for every list field, even when there is only one item.\n2) audience, jobToBeDone, subjectDomain, and artifactThesis must be non-empty request-grounded strings.\n3) Keep the brief request-grounded, not renderer-template-grounded.\n4) Use empty arrays instead of invented filler.",
                title,
                intent,
                request_json,
                refinement_json,
                renderer_guidance,
                validation_contract,
                failure,
                raw_output,
            )
        }
    ]))
}

pub fn build_studio_artifact_brief_field_repair_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    first_raw_output: &str,
    repair_raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    let request_json = serde_json::to_string(request)
        .map_err(|error| format!("Failed to serialize Studio artifact request: {error}"))?;
    let refinement_json =
        serde_json::to_string(&studio_artifact_refinement_context_view(refinement))
            .map_err(|error| format!("Failed to serialize Studio refinement context: {error}"))?;
    let renderer_guidance = studio_artifact_brief_planning_guidance(request);
    let validation_contract = studio_artifact_brief_validation_contract(request);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact brief field repairer. Replace invalid or empty brief fields with the shortest request-grounded values that satisfy the schema. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nCurrent artifact context:\n{}\n\nRenderer-aware brief guidance:\n{}\n\nValidation contract:\n{}\n\nThe planner and repair pass still failed.\nFailure:\n{}\n\nPlanner output preview:\n{}\n\nRepair output preview:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"audience\": <string>,\n  \"jobToBeDone\": <string>,\n  \"subjectDomain\": <string>,\n  \"artifactThesis\": <string>,\n  \"requiredConcepts\": [<string>],\n  \"requiredInteractions\": [<string>],\n  \"visualTone\": [<string>],\n  \"factualAnchors\": [<string>],\n  \"styleDirectives\": [<string>],\n  \"referenceHints\": [<string>]\n}}\nRules:\n1) Every string field must be non-empty and request-grounded.\n2) Use arrays for every list field.\n3) Keep list items concrete and short.\n4) Preserve the differentiating subject nouns from the request.\n5) Do not leave required strings blank.",
                title,
                intent,
                request_json,
                refinement_json,
                renderer_guidance,
                validation_contract,
                failure,
                truncate_planning_preview(first_raw_output, 700),
                truncate_planning_preview(repair_raw_output, 700),
            )
        }
    ]))
}

pub async fn plan_studio_artifact_edit_intent_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    refinement: &StudioArtifactRefinementContext,
) -> Result<StudioArtifactEditIntent, String> {
    let payload = build_studio_artifact_edit_intent_prompt(intent, request, brief, refinement)?;
    let input = serde_json::to_vec(&payload)
        .map_err(|error| format!("Failed to encode Studio artifact edit-intent prompt: {error}"))?;
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: 384,
                ..Default::default()
            },
        )
        .await
        .map_err(|error| format!("Studio artifact edit-intent inference failed: {error}"))?;
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Studio artifact edit-intent utf8 decode failed: {error}"))?;
    match parse_studio_artifact_edit_intent(&raw) {
        Ok(edit_intent) => Ok(edit_intent),
        Err(first_error) => {
            let repair_payload = build_studio_artifact_edit_intent_repair_prompt(
                intent,
                request,
                brief,
                refinement,
                &raw,
                &first_error,
            )?;
            let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                format!("Failed to encode Studio artifact edit-intent repair prompt: {error}")
            })?;
            let repair_output = runtime
                .execute_inference(
                    [0u8; 32],
                    &repair_input,
                    InferenceOptions {
                        temperature: 0.0,
                        json_mode: true,
                        max_tokens: 384,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| {
                    format!("{first_error}; edit-intent repair inference failed: {error}")
                })?;
            let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                format!("{first_error}; edit-intent repair utf8 decode failed: {error}")
            })?;
            parse_studio_artifact_edit_intent(&repair_raw).map_err(|repair_error| {
                format!("{first_error}; edit-intent repair attempt also failed: {repair_error}")
            })
        }
    }
}

pub fn build_studio_artifact_edit_intent_prompt(
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    refinement: &StudioArtifactRefinementContext,
) -> Result<serde_json::Value, String> {
    let request_json = serde_json::to_string_pretty(request)
        .map_err(|error| format!("Failed to serialize Studio artifact request: {error}"))?;
    let brief_json = serde_json::to_string_pretty(brief)
        .map_err(|error| format!("Failed to serialize Studio artifact brief: {error}"))?;
    let refinement_json =
        serde_json::to_string_pretty(&studio_artifact_refinement_context_view(Some(refinement)))
            .map_err(|error| format!("Failed to serialize Studio refinement context: {error}"))?;
    let output_contract =
        "Edit-intent output contract:\nReturn the decision inside the exact JSON schema below; do not answer with raw prose, bullet notes, or commentary outside the JSON object.";
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact edit-intent planner. Decide whether a follow-up should patch, replace, or branch the current artifact. Produce exactly one JSON object. Do not emit prose outside JSON."
        },
        {
            "role": "user",
            "content": format!(
                "Follow-up request:\n{}\n\nArtifact request JSON:\n{}\n\nCurrent brief JSON:\n{}\n\nCurrent artifact context:\n{}\n\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"mode\": \"create\" | \"patch\" | \"replace\" | \"branch\",\n  \"summary\": <string>,\n  \"patchExistingArtifact\": <boolean>,\n  \"preserveStructure\": <boolean>,\n  \"targetScope\": <string>,\n  \"targetPaths\": [<string>],\n  \"requestedOperations\": [<string>],\n  \"toneDirectives\": [<string>],\n  \"selectedTargets\": [{{\n    \"sourceSurface\": <string>,\n    \"path\": null | <string>,\n    \"label\": <string>,\n    \"snippet\": <string>\n  }}],\n  \"styleDirectives\": [<string>],\n  \"branchRequested\": <boolean>\n}}\nRules:\n1) Prefer patchExistingArtifact=true when the request sounds like refinement, not replacement.\n2) Preserve structure when the user explicitly asks to keep structure or continuity.\n3) Selected targets must stay grounded in the supplied context; do not invent paths.\n4) Preserve explicit user steering words in toneDirectives or styleDirectives instead of paraphrasing them into broader synonyms.\n5) If the request says \"more X\", \"less X\", or \"make it feel X\", keep X verbatim in toneDirectives or styleDirectives.",
                intent,
                request_json,
                brief_json,
                refinement_json,
                output_contract,
            )
        }
    ]))
}

pub fn parse_studio_artifact_edit_intent(raw: &str) -> Result<StudioArtifactEditIntent, String> {
    let mut value = parse_studio_json_object_value(
        raw,
        "Studio artifact edit-intent output missing JSON payload",
        "Failed to parse Studio artifact edit intent",
    )?;
    normalize_studio_artifact_edit_intent_value(&mut value);
    let intent = serde_json::from_value::<StudioArtifactEditIntent>(value)
        .map_err(|error| format!("Failed to parse Studio artifact edit intent: {error}"))?;

    if intent.summary.trim().is_empty() || intent.target_scope.trim().is_empty() {
        return Err("Studio artifact edit intent fields must not be empty.".to_string());
    }

    Ok(intent)
}

pub fn build_studio_artifact_edit_intent_repair_prompt(
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    refinement: &StudioArtifactRefinementContext,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    let request_json = serde_json::to_string_pretty(request)
        .map_err(|error| format!("Failed to serialize Studio artifact request: {error}"))?;
    let brief_json = serde_json::to_string_pretty(brief)
        .map_err(|error| format!("Failed to serialize Studio artifact brief: {error}"))?;
    let refinement_json =
        serde_json::to_string_pretty(&studio_artifact_refinement_context_view(Some(refinement)))
            .map_err(|error| format!("Failed to serialize Studio refinement context: {error}"))?;
    let repair_contract = if failure
        .to_ascii_lowercase()
        .contains("missing json payload")
    {
        "Edit-intent repair contract:\nReturn the repaired decision inside the exact JSON schema below; do not answer with raw prose, bullet notes, or commentary outside the JSON object."
    } else {
        "Edit-intent repair contract:\nReturn the repaired decision inside the exact JSON schema below."
    };
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact edit-intent repairer. Repair the previous edit intent into a schema-valid decision about patch, replace, or branch. Produce exactly one JSON object. Do not emit prose outside JSON."
        },
        {
            "role": "user",
            "content": format!(
                "Follow-up request:\n{}\n\nArtifact request JSON:\n{}\n\nCurrent brief JSON:\n{}\n\nCurrent artifact context:\n{}\n\nThe previous edit intent output was rejected.\nFailure:\n{}\n\nPrevious raw output:\n{}\n\nRepair the edit intent so it is schema-valid, continuity-aware, and grounded in the supplied artifact context.\n\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"mode\": \"create\" | \"patch\" | \"replace\" | \"branch\",\n  \"summary\": <string>,\n  \"patchExistingArtifact\": <boolean>,\n  \"preserveStructure\": <boolean>,\n  \"targetScope\": <string>,\n  \"targetPaths\": [<string>],\n  \"requestedOperations\": [<string>],\n  \"toneDirectives\": [<string>],\n  \"selectedTargets\": [{{\n    \"sourceSurface\": <string>,\n    \"path\": null | <string>,\n    \"label\": <string>,\n    \"snippet\": <string>\n  }}],\n  \"styleDirectives\": [<string>],\n  \"branchRequested\": <boolean>\n}}\nRules:\n1) Prefer patchExistingArtifact=true when the request sounds like refinement, not replacement.\n2) Use arrays for every list field, even when there is only one item.\n3) Selected targets must stay grounded in the supplied context; do not invent paths.\n4) Preserve explicit user steering words in toneDirectives or styleDirectives instead of paraphrasing them into broader synonyms.\n5) If the request says \"more X\", \"less X\", or \"make it feel X\", keep X verbatim in toneDirectives or styleDirectives.",
                intent,
                request_json,
                brief_json,
                refinement_json,
                failure,
                raw_output,
                repair_contract,
            )
        }
    ]))
}
