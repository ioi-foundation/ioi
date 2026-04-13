use super::judging::studio_artifact_refinement_context_view;
use super::*;
use std::collections::BTreeSet;

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

pub fn studio_execution_strategy_for_outcome(
    outcome_kind: StudioOutcomeKind,
    artifact: Option<&StudioOutcomeArtifactRequest>,
) -> StudioExecutionStrategy {
    crate::execution::execution_strategy_for_outcome(outcome_kind, artifact)
}

fn compact_local_html_brief_prompt(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> bool {
    renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
}

pub(crate) fn brief_planner_max_tokens_for_runtime(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    if compact_local_html_brief_prompt(renderer, runtime_kind) {
        return 320;
    }

    448
}

fn brief_repair_max_tokens_for_runtime(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    if compact_local_html_brief_prompt(renderer, runtime_kind) {
        return 320;
    }

    448
}

fn brief_field_repair_max_tokens_for_runtime(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    if compact_local_html_brief_prompt(renderer, runtime_kind) {
        return 256;
    }

    320
}

pub async fn plan_studio_outcome_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioOutcomePlanningPayload, String> {
    if let Some(deterministic) =
        deterministic_single_document_artifact_route(intent, active_artifact_id, active_artifact)
    {
        return Ok(deterministic);
    }

    let runtime_provenance = runtime.studio_runtime_provenance();
    let router_max_tokens =
        if runtime_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
            384
        } else {
            768
        };
    let payload = build_studio_outcome_router_prompt_for_runtime(
        intent,
        active_artifact_id,
        active_artifact,
        runtime_provenance.kind,
    );
    let input = serde_json::to_vec(&payload).map_err(|error| {
        format!(
            "Failed to encode Studio outcome planning payload: {}",
            error
        )
    })?;
    studio_planning_trace(format!(
        "outcome_route:start runtime_kind={:?} prompt_bytes={} max_tokens={}",
        runtime_provenance.kind,
        input.len(),
        router_max_tokens
    ));
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: router_max_tokens,
                ..Default::default()
            },
        )
        .await
        .map_err(|error| format!("Studio outcome planning inference failed: {}", error))?;
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Studio outcome planning utf8 decode failed: {}", error))?;
    studio_planning_trace(format!(
        "outcome_route:raw bytes={} preview={}",
        raw.len(),
        truncate_planning_preview(&raw, 240)
    ));
    let mut planning = parse_studio_outcome_planning_payload(&raw)?;
    planning.artifact = planning
        .artifact
        .map(|request| reconcile_outcome_artifact_request_with_intent(intent, request));
    studio_planning_trace(format!(
        "outcome_route:parsed outcome={:?} strategy={:?} confidence={} needs_clarification={} artifact_present={}",
        planning.outcome_kind,
        planning.execution_strategy,
        planning.confidence,
        planning.needs_clarification,
        planning.artifact.is_some()
    ));
    Ok(planning)
}

pub fn build_studio_outcome_router_prompt(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> serde_json::Value {
    build_studio_outcome_router_prompt_for_runtime(
        intent,
        active_artifact_id,
        active_artifact,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

pub(crate) fn build_studio_outcome_router_prompt_for_runtime(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> serde_json::Value {
    let active_artifact_context_json =
        studio_artifact_refinement_context_view(active_artifact).to_string();
    let compact_local_contract = runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime;
    let system_content = if compact_local_contract {
        "You are Studio's typed outcome router. Return exactly one JSON object choosing conversation, tool_widget, visualizer, or artifact. Artifact means a persistent work product. If confidence is low, set needsClarification true. Continue the active artifact for follow-up edits when context is supplied. Output JSON only."
    } else {
        "You are Studio's typed outcome router. Route a user request to exactly one outcome kind: conversation, tool_widget, visualizer, or artifact. Do not guess. If confidence is low, set needsClarification true. Workspace is only one artifact renderer, not the default. Artifact output must be chosen when the request should become a persistent work product. When an active artifact context is supplied, continue that artifact by default for under-specified follow-up edits instead of switching renderer families. Output JSON only."
    };
    let user_content = if compact_local_contract {
        format!(
            "Request:\n{}\n\nActive artifact id: {}\n\nActive artifact context JSON:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"outcomeKind\": \"conversation\" | \"tool_widget\" | \"visualizer\" | \"artifact\",\n  \"executionStrategy\": \"single_pass\" | \"direct_author\" | \"plan_execute\" | \"micro_swarm\" | \"adaptive_work_graph\",\n  \"confidence\": <0_to_1_float>,\n  \"needsClarification\": <boolean>,\n  \"clarificationQuestions\": [<string>],\n  \"artifact\": null | {{\n    \"artifactClass\": \"document\" | \"visual\" | \"interactive_single_file\" | \"downloadable_file\" | \"workspace_project\" | \"compound_bundle\" | \"code_patch\" | \"report_bundle\",\n    \"renderer\": \"markdown\" | \"html_iframe\" | \"jsx_sandbox\" | \"svg\" | \"mermaid\" | \"pdf_embed\" | \"download_card\" | \"workspace_surface\" | \"bundle_manifest\",\n    \"workspaceRecipeId\": null | \"react-vite\" | \"vite-static-html\",\n    \"presentationVariantId\": null | \"sport-editorial\" | \"minimal-agency\" | \"hospitality-retreat\" | \"product-launch\",\n    \"scope\": {{\n      \"targetProject\": null | <string>,\n      \"mutationBoundary\": [<string>]\n    }},\n    \"verification\": {{\n      \"requireExport\": <boolean>\n    }}\n  }}\n}}\nDerived automatically from renderer when omitted: deliverableShape, presentationSurface, persistence, executionSubstrate, createNewWorkspace, requireBuild, requirePreview, requireDiffReview.\nExecution strategy rules:\n- single_pass = one bounded draft with no candidate search.\n- direct_author = direct first-pass authoring for one coherent single-document artifact; preserve the raw request and skip planner scaffolding on the first generation.\n- plan_execute = default when one planned execution unit is sufficient.\n- micro_swarm = use when the work graph is small and known up front.\n- adaptive_work_graph = use only when the request clearly needs a mutable multi-node work graph.\nRenderer rules:\n- markdown = single renderable .md document.\n- html_iframe = single self-contained .html document.\n- jsx_sandbox = single .jsx source module with a default export.\n- svg = single .svg visual artifact.\n- mermaid = single .mermaid diagram source artifact.\n- pdf_embed = document artifact compiled into PDF bytes.\n- download_card = downloadable files or exports, not a primary inline document surface.\n- workspace_surface = the only multi-file workspace renderer.\nRules:\n1) artifact is for persistent work products.\n2) Use workspace_surface only when a real multi-file workspace and preview runtime are required.\n3) Build, preview, and diff review are only valid for workspace_surface.\n4) Explicit medium-plus-deliverable requests are sufficiently specified artifact work.\n5) Prefer direct_author for a fresh coherent single-file document ask that the model can author directly, such as markdown, html_iframe, svg, mermaid, or pdf_embed; otherwise prefer plan_execute unless the request is trivial enough for single_pass, small-graph enough for micro_swarm, or clearly mutable enough for adaptive_work_graph.\n6) If active artifact context exists and the request is a follow-up, continue that artifact by default instead of using direct_author.\n7) Do not use lexical fallbacks or benchmark phrase maps.\n8) If a required constraint is missing, keep confidence low and ask clarification.",
            intent,
            active_artifact_id.unwrap_or("<none>"),
            active_artifact_context_json,
        )
    } else {
        format!(
            "Request:\n{}\n\nActive artifact id: {}\n\nActive artifact context JSON:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"outcomeKind\": \"conversation\" | \"tool_widget\" | \"visualizer\" | \"artifact\",\n  \"executionStrategy\": \"single_pass\" | \"direct_author\" | \"plan_execute\" | \"micro_swarm\" | \"adaptive_work_graph\",\n  \"confidence\": <0_to_1_float>,\n  \"needsClarification\": <boolean>,\n  \"clarificationQuestions\": [<string>],\n  \"artifact\": null | {{\n    \"artifactClass\": \"document\" | \"visual\" | \"interactive_single_file\" | \"downloadable_file\" | \"workspace_project\" | \"compound_bundle\" | \"code_patch\" | \"report_bundle\",\n    \"deliverableShape\": \"single_file\" | \"file_set\" | \"workspace_project\",\n    \"renderer\": \"markdown\" | \"html_iframe\" | \"jsx_sandbox\" | \"svg\" | \"mermaid\" | \"pdf_embed\" | \"download_card\" | \"workspace_surface\" | \"bundle_manifest\",\n    \"presentationSurface\": \"inline\" | \"side_panel\" | \"overlay\" | \"tabbed_panel\",\n    \"persistence\": \"ephemeral\" | \"artifact_scoped\" | \"shared_artifact_scoped\" | \"workspace_filesystem\",\n    \"executionSubstrate\": \"none\" | \"client_sandbox\" | \"binary_generator\" | \"workspace_runtime\",\n    \"workspaceRecipeId\": null | \"react-vite\" | \"vite-static-html\",\n    \"presentationVariantId\": null | \"sport-editorial\" | \"minimal-agency\" | \"hospitality-retreat\" | \"product-launch\",\n    \"scope\": {{\n      \"targetProject\": null | <string>,\n      \"createNewWorkspace\": <boolean>,\n      \"mutationBoundary\": [<string>]\n    }},\n    \"verification\": {{\n      \"requireRender\": <boolean>,\n      \"requireBuild\": <boolean>,\n      \"requirePreview\": <boolean>,\n      \"requireExport\": <boolean>,\n      \"requireDiffReview\": <boolean>\n    }}\n  }}\n}}\nExecution strategy contracts:\n- single_pass = one bounded draft with no candidate search.\n- direct_author = direct first-pass authoring for one coherent single-document artifact; preserve the raw request and skip planner scaffolding on the first generation.\n- plan_execute = default when one planned execution unit is sufficient.\n- micro_swarm = use when the request implies a small known work graph.\n- adaptive_work_graph = use only when the request clearly needs a mutable multi-node work graph.\nRenderer contracts:\n- markdown = a single renderable .md document.\n- html_iframe = a single self-contained .html document for browser presentation. Choose this when the final artifact should be HTML itself, such as a landing page, explainer, launch page, editorial page, or browser-native interactive document.\n- jsx_sandbox = a single .jsx source module with a default export. Choose this only when the final artifact should be JSX/React source as the work product rather than a plain HTML document.\n- svg = a single .svg visual artifact.\n- mermaid = a single .mermaid diagram source artifact.\n- pdf_embed = a document artifact that will be compiled into PDF bytes.\n- download_card = downloadable files or exports, not a primary inline document surface.\n- workspace_surface = a real multi-file workspace with supervised build/preview.\nCoherence rules:\n- html_iframe and jsx_sandbox are interactive_single_file artifacts with single_file deliverableShape and client_sandbox executionSubstrate.\n- workspace_surface is the only renderer that may use workspace_project deliverableShape, workspace_runtime executionSubstrate, createNewWorkspace=true, requireBuild=true, or requirePreview=true.\n- Non-workspace artifact renderers should not request build or preview verification.\nRules:\n1) conversation is for plain reply only.\n2) tool_widget is for first-party tool display surfaces.\n3) visualizer is for ephemeral inline visuals.\n4) artifact is for persistent work products.\n5) Use workspace_surface only when a real multi-file workspace and preview runtime are required.\n6) Prefer direct_author for a fresh coherent single-file document ask that the model can author directly, such as markdown, html_iframe, svg, mermaid, or pdf_embed; otherwise prefer plan_execute unless the request is trivial enough for single_pass, small-graph enough for micro_swarm, or clearly mutable enough for adaptive_work_graph.\n7) Treat explicit medium-plus-deliverable requests as sufficiently specified artifact work. If the user already asked for an HTML artifact, landing page, launch page, editorial page, markdown document, SVG concept, Mermaid diagram, PDF artifact, downloadable bundle, or workspace project, do not ask clarification merely to restate that same deliverable form.\n8) For example, \"Create an interactive HTML artifact for an AI tools editorial launch page\" is already an artifact request for html_iframe, not a clarification request.\n9) When active artifact context JSON is not null and the request is a follow-up refinement, patch or branch the current artifact by default instead of switching renderer, artifactClass, or deliverableShape unless the user explicitly asks for a different deliverable form.\n10) Under-specified follow-up requests should continue the active artifact rather than restarting as a new artifact kind.\n11) Do not use lexical fallbacks or benchmark phrase maps.\n12) When uncertainty remains about a required missing constraint, keep confidence low and ask clarification.",
            intent,
            active_artifact_id.unwrap_or("<none>"),
            active_artifact_context_json,
        )
    };
    json!([
        {
            "role": "system",
            "content": system_content
        },
        {
            "role": "user",
            "content": user_content
        }
    ])
}

#[derive(Clone, Copy)]
struct StudioOutcomeArtifactRendererDefaults {
    artifact_class: &'static str,
    deliverable_shape: &'static str,
    presentation_surface: &'static str,
    persistence: &'static str,
    execution_substrate: &'static str,
}

fn outcome_artifact_renderer_defaults(
    renderer: &str,
) -> Option<StudioOutcomeArtifactRendererDefaults> {
    match renderer {
        "markdown" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "document",
            deliverable_shape: "single_file",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "none",
        }),
        "html_iframe" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "interactive_single_file",
            deliverable_shape: "single_file",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "client_sandbox",
        }),
        "jsx_sandbox" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "interactive_single_file",
            deliverable_shape: "single_file",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "client_sandbox",
        }),
        "svg" | "mermaid" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "visual",
            deliverable_shape: "single_file",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "client_sandbox",
        }),
        "pdf_embed" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "document",
            deliverable_shape: "single_file",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "binary_generator",
        }),
        "download_card" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "downloadable_file",
            deliverable_shape: "file_set",
            presentation_surface: "side_panel",
            persistence: "shared_artifact_scoped",
            execution_substrate: "none",
        }),
        "workspace_surface" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "workspace_project",
            deliverable_shape: "workspace_project",
            presentation_surface: "tabbed_panel",
            persistence: "workspace_filesystem",
            execution_substrate: "workspace_runtime",
        }),
        "bundle_manifest" => Some(StudioOutcomeArtifactRendererDefaults {
            artifact_class: "compound_bundle",
            deliverable_shape: "file_set",
            presentation_surface: "side_panel",
            persistence: "artifact_scoped",
            execution_substrate: "none",
        }),
        _ => None,
    }
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

fn intent_terms(intent: &str) -> Vec<String> {
    intent
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(|term| term.to_ascii_lowercase())
        .collect()
}

fn intent_requests_downloadable_fileset(intent: &str) -> bool {
    const FILE_TARGET_TERMS: &[&str] = &[
        "csv",
        "tsv",
        "xlsx",
        "json",
        "yaml",
        "yml",
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "svg",
        "txt",
        "md",
        "markdown",
        "readme",
        "license",
        "changelog",
    ];
    const TRANSPORT_TERMS: &[&str] = &[
        "download",
        "downloadable",
        "export",
        "exports",
        "bundle",
        "archive",
        "package",
        "pack",
    ];
    const BUNDLE_TERMS: &[&str] = &["bundle", "archive", "package", "pack"];

    let terms = intent_terms(intent);
    let normalized = normalize_inline_whitespace(&intent.to_ascii_lowercase());
    let referenced_files = terms
        .iter()
        .filter(|term| FILE_TARGET_TERMS.contains(&term.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    let requests_transport = terms
        .iter()
        .any(|term| TRANSPORT_TERMS.contains(&term.as_str()))
        || normalized.contains("file set")
        || normalized.contains("fileset");
    let requests_bundle = terms
        .iter()
        .any(|term| BUNDLE_TERMS.contains(&term.as_str()))
        || normalized.contains("file set")
        || normalized.contains("fileset");

    requests_transport
        && (referenced_files.len() >= 2 || (requests_bundle && !referenced_files.is_empty()))
}

fn intent_requests_created_deliverable(intent: &str) -> bool {
    const CREATION_TERMS: &[&str] = &[
        "create", "make", "build", "generate", "write", "draft", "produce", "craft", "design",
    ];

    let terms = intent_terms(intent);
    let normalized = normalize_inline_whitespace(&intent.to_ascii_lowercase());
    terms
        .iter()
        .any(|term| CREATION_TERMS.contains(&term.as_str()))
        || normalized.starts_with("new ")
}

fn explicit_single_document_renderer_from_intent(
    intent: &str,
) -> Option<(StudioRendererKind, &'static str)> {
    let normalized = normalize_inline_whitespace(&intent.to_ascii_lowercase());

    if normalized.contains("interactive html artifact")
        || normalized.contains("html artifact")
        || normalized.contains("html page")
        || normalized.contains("html document")
        || normalized.contains("landing page")
        || normalized.contains("launch page")
        || normalized.contains("microsite")
    {
        return Some((
            StudioRendererKind::HtmlIframe,
            "explicit_single_document_html_deliverable",
        ));
    }

    if normalized.contains("markdown artifact")
        || normalized.contains("markdown document")
        || normalized.contains("markdown doc")
        || normalized.contains("markdown file")
        || normalized.contains("md file")
    {
        return Some((
            StudioRendererKind::Markdown,
            "explicit_single_document_markdown_deliverable",
        ));
    }

    if normalized.contains("mermaid artifact")
        || normalized.contains("mermaid diagram")
        || normalized.contains("mermaid chart")
    {
        return Some((
            StudioRendererKind::Mermaid,
            "explicit_single_document_mermaid_deliverable",
        ));
    }

    if normalized.contains("svg artifact")
        || normalized.contains("svg diagram")
        || normalized.contains("svg illustration")
        || normalized.contains("svg graphic")
    {
        return Some((
            StudioRendererKind::Svg,
            "explicit_single_document_svg_deliverable",
        ));
    }

    if normalized.contains("pdf artifact")
        || normalized.contains("pdf document")
        || normalized.contains("pdf report")
        || normalized.contains("pdf file")
    {
        return Some((
            StudioRendererKind::PdfEmbed,
            "explicit_single_document_pdf_deliverable",
        ));
    }

    None
}

fn deterministic_single_document_artifact_route(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Option<StudioOutcomePlanningPayload> {
    if active_artifact_id.is_some() || active_artifact.is_some() {
        return None;
    }

    if !intent_requests_created_deliverable(intent) {
        return None;
    }

    let (renderer, reason) = explicit_single_document_renderer_from_intent(intent)?;
    let request = canonicalize_artifact_request(StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::Document,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::SharedArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::None,
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
            require_export: renderer == StudioRendererKind::PdfEmbed,
            require_diff_review: false,
        },
    });
    let execution_strategy =
        studio_execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&request));
    studio_planning_trace(format!(
        "outcome_route:deterministic renderer={renderer:?} strategy={execution_strategy:?} reason={reason}"
    ));
    Some(StudioOutcomePlanningPayload {
        outcome_kind: StudioOutcomeKind::Artifact,
        execution_strategy,
        execution_mode_decision: None,
        confidence: 0.99,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        artifact: Some(request),
    })
}

fn reconcile_outcome_artifact_request_with_intent(
    intent: &str,
    mut request: StudioOutcomeArtifactRequest,
) -> StudioOutcomeArtifactRequest {
    if intent_requests_downloadable_fileset(intent) {
        request.verification.require_export = true;
        if !matches!(
            request.renderer,
            StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest
        ) {
            let original_renderer = request.renderer;
            request.renderer = StudioRendererKind::DownloadCard;
            request.verification.require_build = false;
            request.verification.require_preview = false;
            request.verification.require_diff_review = false;
            let request = canonicalize_artifact_request(request);
            studio_planning_trace(format!(
                "outcome_route:renderer_reconciled from={original_renderer:?} to={:?} reason=explicit_downloadable_fileset_intent",
                request.renderer
            ));
            return request;
        }
    }

    canonicalize_artifact_request(request)
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
    let runtime_provenance = runtime.studio_runtime_provenance();
    let parse_and_validate = |raw: &str| -> Result<StudioArtifactBrief, String> {
        let brief = canonicalize_studio_artifact_brief_for_request(
            parse_studio_artifact_brief(raw)?,
            request,
        );
        validate_studio_artifact_brief_against_request(&brief, request, refinement)?;
        Ok(brief)
    };
    let empty_core_fields_error = "Studio artifact brief fields must not be empty.";
    let salvage_and_validate = |raw: &str| -> Result<StudioArtifactBrief, String> {
        let brief = salvage_studio_artifact_brief_core_fields(raw, title, intent, request)?;
        validate_studio_artifact_brief_against_request(&brief, request, refinement)?;
        Ok(brief)
    };
    let planner_max_tokens =
        brief_planner_max_tokens_for_runtime(request.renderer, runtime_provenance.kind);
    let payload = build_studio_artifact_brief_prompt_for_runtime(
        title,
        intent,
        request,
        refinement,
        runtime_provenance.kind,
    )?;
    let input = serde_json::to_vec(&payload)
        .map_err(|error| format!("Failed to encode Studio artifact brief prompt: {error}"))?;
    studio_planning_trace(format!(
        "artifact_brief:start renderer={:?} runtime={} model={:?} prompt_bytes={} max_tokens={}",
        request.renderer,
        runtime_provenance.label,
        runtime_provenance.model,
        input.len(),
        planner_max_tokens
    ));
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: planner_max_tokens,
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
            if first_error.contains(empty_core_fields_error) {
                if let Ok(brief) = salvage_and_validate(&raw) {
                    studio_planning_trace("artifact_brief:planner_salvaged");
                    return Ok(brief);
                }
            }
            let repair_payload = build_studio_artifact_brief_repair_prompt_for_runtime(
                title,
                intent,
                request,
                refinement,
                &raw,
                &first_error,
                runtime_provenance.kind,
            )?;
            let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                format!("Failed to encode Studio artifact brief repair prompt: {error}")
            })?;
            let repair_max_tokens =
                brief_repair_max_tokens_for_runtime(request.renderer, runtime_provenance.kind);
            studio_planning_trace(format!(
                "artifact_brief:repair_start renderer={:?} runtime={} model={:?} prompt_bytes={} max_tokens={} failure={}",
                request.renderer,
                runtime_provenance.label,
                runtime_provenance.model,
                repair_input.len(),
                repair_max_tokens,
                truncate_planning_preview(&first_error, 240)
            ));
            let repair_output = runtime
                .execute_inference(
                    [0u8; 32],
                    &repair_input,
                    InferenceOptions {
                        temperature: 0.0,
                        json_mode: true,
                        max_tokens: repair_max_tokens,
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
                    let field_repair_payload = if compact_local_html_brief_prompt(
                        request.renderer,
                        runtime_provenance.kind,
                    ) {
                        build_studio_artifact_brief_field_repair_prompt_for_runtime(
                            title,
                            intent,
                            request,
                            refinement,
                            &raw,
                            &repair_raw,
                            &repair_error,
                            runtime_provenance.kind,
                        )?
                    } else {
                        build_studio_artifact_brief_field_repair_prompt(
                            title,
                            intent,
                            request,
                            refinement,
                            &raw,
                            &repair_raw,
                            &repair_error,
                        )?
                    };
                    let field_repair_input =
                        serde_json::to_vec(&field_repair_payload).map_err(|error| {
                            format!(
                                "Failed to encode Studio artifact brief field repair prompt: {error}"
                            )
                        })?;
                    let field_repair_max_tokens = brief_field_repair_max_tokens_for_runtime(
                        request.renderer,
                        runtime_provenance.kind,
                    );
                    studio_planning_trace(format!(
                        "artifact_brief:field_repair_start renderer={:?} runtime={} model={:?} prompt_bytes={} max_tokens={} failure={}",
                        request.renderer,
                        runtime_provenance.label,
                        runtime_provenance.model,
                        field_repair_input.len(),
                        field_repair_max_tokens,
                        truncate_planning_preview(&repair_error, 240)
                    ));
                    let field_repair_output = runtime
                        .execute_inference(
                            [0u8; 32],
                            &field_repair_input,
                            InferenceOptions {
                                temperature: 0.0,
                                json_mode: true,
                                max_tokens: field_repair_max_tokens,
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
                    parse_and_validate(&field_repair_raw)
                        .or_else(|field_repair_error| {
                            salvage_and_validate(&field_repair_raw).map_err(|salvage_error| {
                                format!(
                                    "{first_error}; brief repair attempt failed: {repair_error}; brief field repair attempt also failed: {field_repair_error}; deterministic salvage also failed: {salvage_error}; planner output preview: {}; repair output preview: {}; field repair output preview: {}",
                                    truncate_planning_preview(&raw, 600),
                                    truncate_planning_preview(&repair_raw, 600),
                                    truncate_planning_preview(&field_repair_raw, 600),
                                )
                            })
                        })
                }
            }
        }
    }
}

fn request_grounded_subject_domain(title: &str, intent: &str) -> String {
    derive_brief_subject_domain(
        &StudioArtifactBrief {
            audience: String::new(),
            job_to_be_done: String::new(),
            subject_domain: String::new(),
            artifact_thesis: String::new(),
            required_concepts: Vec::new(),
            required_interactions: Vec::new(),
            visual_tone: Vec::new(),
            factual_anchors: Vec::new(),
            style_directives: Vec::new(),
            reference_hints: Vec::new(),
        },
        title,
        intent,
    )
    .unwrap_or_else(|| {
        let fallback = trim_sentence_terminal(intent);
        if fallback.is_empty() {
            "the requested artifact".to_string()
        } else {
            fallback
        }
    })
}

fn request_grounded_job_to_be_done(
    request: &StudioOutcomeArtifactRequest,
    subject_domain: &str,
    intent: &str,
) -> String {
    let normalized_intent = trim_sentence_terminal(intent);
    if !normalized_intent.is_empty() {
        return normalized_intent;
    }

    match request.renderer {
        StudioRendererKind::HtmlIframe => {
            format!("understand {subject_domain} through an interactive artifact")
        }
        StudioRendererKind::JsxSandbox => {
            format!("explore {subject_domain} through an interactive surface")
        }
        StudioRendererKind::Svg | StudioRendererKind::Mermaid => {
            format!("understand {subject_domain} at a glance")
        }
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed => {
            format!("review {subject_domain} clearly")
        }
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => {
            format!("download the useful {subject_domain} fileset")
        }
        StudioRendererKind::WorkspaceSurface => {
            "scaffold a working implementation surface".to_string()
        }
    }
}

fn request_grounded_required_concepts(
    request: &StudioOutcomeArtifactRequest,
    subject_domain: &str,
) -> Vec<String> {
    let mut concepts = vec![subject_domain.to_string()];
    match request.renderer {
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => {
            concepts.push(format!("{subject_domain} fundamentals"));
            concepts.push(format!("{subject_domain} examples"));
            concepts.push(format!("{subject_domain} comparisons"));
        }
        StudioRendererKind::Svg | StudioRendererKind::Mermaid => {
            concepts.push(format!("{subject_domain} overview"));
            concepts.push(format!("{subject_domain} relationships"));
        }
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed => {
            concepts.push(format!("{subject_domain} summary"));
            concepts.push(format!("{subject_domain} evidence"));
        }
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => {
            concepts.push(format!("{subject_domain} files"));
            concepts.push(format!("{subject_domain} usage"));
        }
        StudioRendererKind::WorkspaceSurface => {
            concepts.push(format!("{subject_domain} interface"));
            concepts.push(format!("{subject_domain} implementation"));
        }
    }
    canonicalize_brief_list(concepts)
}

fn request_grounded_required_interactions(
    request: &StudioOutcomeArtifactRequest,
    subject_domain: &str,
) -> Vec<String> {
    let interactions = match request.renderer {
        StudioRendererKind::HtmlIframe => vec![
            format!("switch between {subject_domain} views to compare how the explanation changes"),
            format!("inspect {subject_domain} callouts to reveal deeper context inline"),
            format!("step through {subject_domain} examples to see the explanation progress"),
        ],
        StudioRendererKind::JsxSandbox => vec![
            format!("adjust {subject_domain} controls to update the visible response"),
            format!("inspect {subject_domain} state details in the shared panel"),
        ],
        _ => Vec::new(),
    };

    canonicalize_brief_interactions(interactions, request)
}

fn request_grounded_visual_tone(request: &StudioOutcomeArtifactRequest) -> Vec<String> {
    canonicalize_brief_list(match request.renderer {
        StudioRendererKind::HtmlIframe => vec![
            "bold editorial contrast".to_string(),
            "technical explainer clarity".to_string(),
        ],
        StudioRendererKind::JsxSandbox => vec![
            "product-grade interface clarity".to_string(),
            "interaction-led hierarchy".to_string(),
        ],
        StudioRendererKind::Svg | StudioRendererKind::Mermaid => {
            vec!["diagram-led clarity".to_string()]
        }
        _ => vec!["grounded document clarity".to_string()],
    })
}

fn request_grounded_style_directives(request: &StudioOutcomeArtifactRequest) -> Vec<String> {
    canonicalize_brief_list(match request.renderer {
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => vec![
            "request-shaped hierarchy".to_string(),
            "clear interaction affordances".to_string(),
        ],
        StudioRendererKind::Svg | StudioRendererKind::Mermaid => {
            vec!["strong visual labeling".to_string()]
        }
        _ => vec!["clear hierarchy".to_string()],
    })
}

pub fn derive_request_grounded_studio_artifact_brief(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> StudioArtifactBrief {
    let subject_domain = request_grounded_subject_domain(title, intent);
    let mut factual_anchors = canonicalize_brief_list(vec![
        trim_sentence_terminal(title),
        format!("{subject_domain} examples"),
    ]);
    if let Some(refinement) = refinement {
        factual_anchors = canonicalize_brief_list({
            let mut anchors = factual_anchors;
            anchors.push(refinement.title.trim().to_string());
            anchors
        });
    }
    let reference_hints = canonicalize_brief_list(vec![
        format!("{subject_domain} comparisons"),
        format!("{subject_domain} evidence"),
    ]);

    let brief = StudioArtifactBrief {
        audience: derive_brief_audience(request, &subject_domain)
            .unwrap_or_else(|| "people exploring the request".to_string()),
        job_to_be_done: request_grounded_job_to_be_done(request, &subject_domain, intent),
        subject_domain: subject_domain.clone(),
        artifact_thesis: match request.renderer {
            StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => format!(
                "Explain {subject_domain} through visible evidence, grounded comparisons, and request-faithful interaction."
            ),
            StudioRendererKind::Svg | StudioRendererKind::Mermaid => format!(
                "Make {subject_domain} understandable at a glance through a clear visual spine."
            ),
            _ => derive_brief_artifact_thesis(request, &subject_domain)
                .unwrap_or_else(|| format!("A {subject_domain} artifact")),
        },
        required_concepts: request_grounded_required_concepts(request, &subject_domain),
        required_interactions: request_grounded_required_interactions(request, &subject_domain),
        visual_tone: request_grounded_visual_tone(request),
        factual_anchors,
        style_directives: request_grounded_style_directives(request),
        reference_hints,
    };
    let canonical = canonicalize_studio_artifact_brief_for_request(brief, request);
    debug_assert!(
        validate_studio_artifact_brief_against_request(&canonical, request, refinement).is_ok(),
        "request-grounded artifact brief must satisfy Studio validation"
    );
    canonical
}

pub async fn synthesize_studio_artifact_brief_for_execution_strategy_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    execution_strategy: StudioExecutionStrategy,
) -> Result<StudioArtifactBrief, String> {
    if execution_strategy == StudioExecutionStrategy::DirectAuthor {
        return Ok(derive_request_grounded_studio_artifact_brief(
            title, intent, request, refinement,
        ));
    }

    plan_studio_artifact_brief_with_runtime(runtime, title, intent, request, refinement).await
}

pub fn build_studio_artifact_brief_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_brief_prompt_for_runtime(
        title,
        intent,
        request,
        refinement,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn studio_artifact_brief_request_focus(
    request: &StudioOutcomeArtifactRequest,
) -> serde_json::Value {
    json!({
        "artifactClass": request.artifact_class,
        "deliverableShape": request.deliverable_shape,
        "renderer": request.renderer,
        "presentationSurface": request.presentation_surface,
        "persistence": request.persistence,
        "executionSubstrate": request.execution_substrate,
        "verification": {
            "requireRender": request.verification.require_render,
            "requireExport": request.verification.require_export,
        },
    })
}

pub(crate) fn build_studio_artifact_brief_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_brief_prompt(request.renderer, runtime_kind);
    let request_json = serde_json::to_string(request)
        .map_err(|error| format!("Failed to serialize Studio artifact request: {error}"))?;
    let refinement_json =
        serde_json::to_string(&studio_artifact_refinement_context_view(refinement))
            .map_err(|error| format!("Failed to serialize Studio refinement context: {error}"))?;
    if compact_prompt {
        let request_focus_json = serde_json::to_string(&studio_artifact_brief_request_focus(
            request,
        ))
        .map_err(|error| format!("Failed to serialize Studio artifact request focus: {error}"))?;
        let continuity_rule = if refinement.is_some() {
            "Preserve stable concepts, interactions, and structure from the current artifact context when they still fit the request."
        } else {
            "No current artifact context is available, so derive the brief directly from the request."
        };
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact brief planner. Return exactly one request-grounded artifact brief JSON object. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nCurrent artifact context JSON:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\"audience\":<string>,\"jobToBeDone\":<string>,\"subjectDomain\":<string>,\"artifactThesis\":<string>,\"requiredConcepts\":[<string>],\"requiredInteractions\":[<string>],\"visualTone\":[<string>],\"factualAnchors\":[<string>],\"styleDirectives\":[<string>],\"referenceHints\":[<string>]}}\nRules:\n1) audience, jobToBeDone, subjectDomain, and artifactThesis must be non-empty request-grounded strings.\n2) Preserve the differentiating nouns and framing words from the request.\n3) For html_iframe, requiredConcepts must include at least three concrete request-grounded concepts.\n4) For html_iframe, requiredInteractions must include at least two concrete multi-word on-page interactions with visible response.\n5) Provide at least one factualAnchors or referenceHints entry tied to visible evidence.\n6) For html_iframe, visualTone or styleDirectives must include at least one concrete multi-word design direction that can actually steer composition, not only generic words like clean, interactive, or minimalist.\n7) When the request leaves visual style open, use referenceHints or styleDirectives to name concrete visual devices, metaphors, or diagram families the artifact can stage.\n8) {}\n9) Use empty arrays instead of filler or generic synonyms.",
                    title,
                    intent,
                    request_focus_json,
                    refinement_json,
                    continuity_rule,
                )
            }
        ]));
    }
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
    let renderer_defaults = object
        .get("renderer")
        .and_then(serde_json::Value::as_str)
        .and_then(outcome_artifact_renderer_defaults);

    if let Some(defaults) = renderer_defaults {
        for (field, default) in [
            ("artifactClass", defaults.artifact_class),
            ("deliverableShape", defaults.deliverable_shape),
            ("presentationSurface", defaults.presentation_surface),
            ("persistence", defaults.persistence),
            ("executionSubstrate", defaults.execution_substrate),
        ] {
            object
                .entry(field.to_string())
                .or_insert_with(|| serde_json::Value::String(default.to_string()));
        }
    }
    if !object.contains_key("workspaceRecipeId") {
        object.insert("workspaceRecipeId".to_string(), serde_json::Value::Null);
    }
    if !object.contains_key("presentationVariantId") {
        object.insert("presentationVariantId".to_string(), serde_json::Value::Null);
    }

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
    if let Some(entry) = object.get_mut("executionStrategy") {
        if let Some(text) = entry.as_str() {
            *entry = serde_json::Value::String(text.trim().to_ascii_lowercase().replace('-', "_"));
        }
    }
    if let Some(artifact) = object.get_mut("artifact") {
        normalize_studio_outcome_artifact_request_value(artifact);
    }
}

fn normalize_inline_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_studio_artifact_brief_lenient(raw: &str) -> Result<StudioArtifactBrief, String> {
    let mut value = parse_studio_json_object_value(
        raw,
        "Studio artifact brief output missing JSON payload",
        "Failed to parse Studio artifact brief",
    )?;
    normalize_studio_artifact_brief_value(&mut value);
    serde_json::from_value::<StudioArtifactBrief>(value)
        .map_err(|error| format!("Failed to parse Studio artifact brief: {error}"))
}

fn trim_sentence_terminal(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(|ch: char| matches!(ch, '.' | ':' | ';'))
        .trim()
        .to_string()
}

fn trim_leading_article(value: &str) -> String {
    let trimmed = trim_sentence_terminal(value);
    let lowered = trimmed.to_ascii_lowercase();
    for prefix in ["a ", "an ", "the "] {
        if lowered.starts_with(prefix) {
            return trimmed[prefix.len()..].trim().to_string();
        }
    }
    trimmed
}

fn title_is_too_generic_for_subject_domain(title: &str) -> bool {
    let generic_terms = [
        "artifact",
        "artifacts",
        "bundle",
        "bundles",
        "card",
        "checklist",
        "document",
        "download",
        "downloads",
        "file",
        "files",
        "launch",
        "page",
        "report",
    ];
    let terms = title
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(|term| term.to_ascii_lowercase())
        .collect::<Vec<_>>();
    !terms.is_empty()
        && terms
            .iter()
            .all(|term| generic_terms.iter().any(|candidate| candidate == term))
}

fn derive_brief_subject_domain(
    brief: &StudioArtifactBrief,
    title: &str,
    intent: &str,
) -> Option<String> {
    let title_candidate = trim_sentence_terminal(title);
    if !title_candidate.is_empty() && !title_is_too_generic_for_subject_domain(&title_candidate) {
        return Some(title_candidate);
    }

    let thesis_candidate = trim_leading_article(&brief.artifact_thesis);
    if !thesis_candidate.is_empty() {
        return Some(thesis_candidate);
    }

    if !brief.required_concepts.is_empty() {
        let concepts = brief
            .required_concepts
            .iter()
            .map(|concept| trim_sentence_terminal(concept))
            .filter(|concept| !concept.is_empty())
            .take(2)
            .collect::<Vec<_>>();
        if !concepts.is_empty() {
            return Some(match concepts.as_slice() {
                [only] => only.clone(),
                [first, second] => format!("{first} and {second}"),
                _ => concepts.join(", "),
            });
        }
    }

    let intent_candidate = trim_sentence_terminal(intent);
    if intent_candidate.is_empty() {
        None
    } else {
        Some(intent_candidate)
    }
}

fn derive_brief_audience(
    request: &StudioOutcomeArtifactRequest,
    subject_domain: &str,
) -> Option<String> {
    if subject_domain.trim().is_empty() {
        return None;
    }

    let prefix = match request.renderer {
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed => "people reviewing the",
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => {
            "people downloading the"
        }
        StudioRendererKind::HtmlIframe
        | StudioRendererKind::JsxSandbox
        | StudioRendererKind::Svg
        | StudioRendererKind::Mermaid => "people exploring the",
        StudioRendererKind::WorkspaceSurface => "people implementing the",
    };
    Some(format!("{prefix} {subject_domain}"))
}

fn derive_brief_artifact_thesis(
    request: &StudioOutcomeArtifactRequest,
    subject_domain: &str,
) -> Option<String> {
    if subject_domain.trim().is_empty() {
        return None;
    }

    let thesis = match request.renderer {
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed => {
            format!("A {subject_domain} document")
        }
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => {
            format!("A downloadable {subject_domain} bundle")
        }
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => {
            format!("An interactive {subject_domain} artifact")
        }
        StudioRendererKind::Svg | StudioRendererKind::Mermaid => {
            format!("A {subject_domain} visual artifact")
        }
        StudioRendererKind::WorkspaceSurface => {
            format!("A workspace implementation for {subject_domain}")
        }
    };
    Some(thesis)
}

fn salvage_studio_artifact_brief_core_fields(
    raw: &str,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
) -> Result<StudioArtifactBrief, String> {
    let mut brief = parse_studio_artifact_brief_lenient(raw)?;
    let subject_domain = derive_brief_subject_domain(&brief, title, intent).unwrap_or_default();
    if brief.subject_domain.trim().is_empty() {
        brief.subject_domain = subject_domain.clone();
    }
    if brief.job_to_be_done.trim().is_empty() {
        brief.job_to_be_done = trim_sentence_terminal(intent);
    }
    if brief.audience.trim().is_empty() {
        brief.audience = derive_brief_audience(request, &brief.subject_domain).unwrap_or_default();
    }
    if brief.artifact_thesis.trim().is_empty() {
        brief.artifact_thesis =
            derive_brief_artifact_thesis(request, &brief.subject_domain).unwrap_or_default();
    }
    if brief.required_concepts.is_empty() && !brief.subject_domain.trim().is_empty() {
        brief.required_concepts = vec![brief.subject_domain.clone()];
    }

    Ok(canonicalize_studio_artifact_brief_for_request(
        brief, request,
    ))
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
    if studio_modal_first_html_enabled() {
        if terms
            .iter()
            .any(|term| matches!(term.as_str(), "hover" | "rollover" | "focus"))
        {
            return "to reveal deeper context inline";
        } else if terms.iter().any(|term| {
            matches!(
                term.as_str(),
                "click" | "switch" | "toggle" | "tab" | "navigation" | "navigate" | "jump" | "view"
            )
        }) {
            return "to switch between authored states or scenes";
        } else if terms
            .iter()
            .any(|term| matches!(term.as_str(), "compare" | "comparison"))
        {
            return "to compare grounded scenarios inline";
        } else {
            return "to make the explanation visibly change on interaction";
        }
    }
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

fn concise_interaction_focus_phrase(value: &str) -> Option<String> {
    let normalized = trim_sentence_terminal(&normalize_inline_whitespace(value));
    if normalized.is_empty() {
        return None;
    }

    let words = normalized.split_whitespace().collect::<Vec<_>>();
    let phrase = if words.len() > 6 {
        words[..6].join(" ")
    } else {
        normalized
    };
    Some(phrase)
}

fn html_brief_interaction_focus_phrases(brief: &StudioArtifactBrief) -> Vec<String> {
    let mut phrases = Vec::<String>::new();
    for value in brief
        .required_concepts
        .iter()
        .chain(brief.factual_anchors.iter())
        .chain(brief.reference_hints.iter())
        .map(String::as_str)
        .chain(std::iter::once(brief.subject_domain.as_str()))
    {
        let Some(phrase) = concise_interaction_focus_phrase(value) else {
            continue;
        };
        if phrases
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&phrase))
        {
            continue;
        }
        phrases.push(phrase);
        if phrases.len() >= 3 {
            break;
        }
    }
    phrases
}

fn derived_grounded_html_interaction(
    family: &str,
    primary_focus: &str,
    secondary_focus: &str,
) -> String {
    if studio_modal_first_html_enabled() {
        return match family {
            "view_switching" => {
                format!(
                    "switch between {primary_focus} views to compare how the explanation changes"
                )
            }
            "detail_inspection" => {
                format!("inspect {secondary_focus} callouts to reveal deeper context inline")
            }
            "sequence_browsing" => {
                format!("step through {primary_focus} examples to see the explanation progress")
            }
            _ => {
                format!("interact with {secondary_focus} examples to reveal deeper context inline")
            }
        };
    }
    match family {
        "view_switching" => {
            format!("switch {primary_focus} sections to update the visible comparison panel")
        }
        "detail_inspection" => {
            format!("inspect {secondary_focus} details in the shared detail panel")
        }
        "sequence_browsing" => {
            format!("step through {primary_focus} examples to update the visible detail panel")
        }
        _ => format!("compare {secondary_focus} callouts in the shared detail panel"),
    }
}

fn ground_html_brief_interactions(
    interactions: Vec<String>,
    brief: &StudioArtifactBrief,
) -> Vec<String> {
    let grounding_terms = interaction_grounding_terms_for_validation(brief, None);
    let focus_phrases = html_brief_interaction_focus_phrases(brief);
    let primary_focus = focus_phrases
        .first()
        .map(String::as_str)
        .unwrap_or("request");
    let secondary_focus = focus_phrases
        .get(1)
        .or_else(|| focus_phrases.first())
        .map(String::as_str)
        .unwrap_or(primary_focus);
    let mut grounded = Vec::<String>::new();

    for interaction in interactions {
        let entry = if interaction_has_grounded_terms(&interaction, &grounding_terms)
            && interaction_has_behavior_terms(&interaction)
        {
            interaction
        } else {
            derived_grounded_html_interaction(
                blueprint_interaction_family(&interaction),
                primary_focus,
                secondary_focus,
            )
        };
        if grounded
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&entry))
        {
            continue;
        }
        grounded.push(entry);
    }

    let defaults = if studio_modal_first_html_enabled() {
        [
            format!("switch between {primary_focus} views to compare how the explanation changes"),
            format!("inspect {secondary_focus} callouts to reveal deeper context inline"),
        ]
    } else {
        [
            format!("switch {primary_focus} sections to update the visible comparison panel"),
            format!("inspect {secondary_focus} details in the shared detail panel"),
        ]
    };
    for entry in defaults {
        if grounded.len() >= 2 {
            break;
        }
        if grounded
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&entry))
        {
            continue;
        }
        grounded.push(entry);
    }

    grounded
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
    brief.visual_tone = canonicalize_brief_list(brief.visual_tone);
    brief.factual_anchors = canonicalize_brief_list(brief.factual_anchors);
    brief.style_directives = canonicalize_brief_list(brief.style_directives);
    brief.reference_hints = canonicalize_brief_list(brief.reference_hints);
    brief.required_interactions =
        canonicalize_brief_interactions(std::mem::take(&mut brief.required_interactions), request);
    if request.renderer == StudioRendererKind::HtmlIframe {
        brief.required_interactions = ground_html_brief_interactions(
            std::mem::take(&mut brief.required_interactions),
            &brief,
        );
    }
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
        StudioRendererKind::HtmlIframe => "- Name at least two concrete on-page interaction patterns in requiredInteractions.\n- Single-word labels like \"interactive\" or \"explains\" are not sufficient interaction plans.\n- Keep requiredConcepts tied to the visible evidence surfaces or sections.\n- Provide at least one concrete evidence anchor or reference hint.\n- Give visualTone or styleDirectives at least one multi-word design direction that a materializer can actually stage, not just generic words like clean, modern, or interactive.".to_string(),
        StudioRendererKind::JsxSandbox => "- Name at least one concrete stateful interaction.\n- requiredInteractions should describe user action plus visible response.".to_string(),
        _ => "- Keep the brief concrete, request-specific, and directly usable by the materializer.".to_string(),
    }
}

fn studio_artifact_brief_validation_contract(request: &StudioOutcomeArtifactRequest) -> String {
    match request.renderer {
        StudioRendererKind::HtmlIframe => "- requiredConcepts must include at least three concrete request-grounded concepts.\n- requiredInteractions must include at least two multi-word interaction descriptions.\n- At least one factualAnchors or referenceHints entry must be present.\n- visualTone or styleDirectives must contribute at least one concrete multi-word design direction instead of only generic style adjectives.".to_string(),
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

fn interaction_has_behavior_terms(interaction: &str) -> bool {
    split_interaction_identifier_terms(interaction)
        .into_iter()
        .filter(|term| term.len() >= 3 && !interaction_grounding_noise_term(term))
        .any(|term| interaction_behavior_term(&term))
}

fn html_visual_direction_noise_term(term: &str) -> bool {
    matches!(
        term,
        "a" | "an"
            | "and"
            | "clean"
            | "cool"
            | "educational"
            | "friendly"
            | "interactive"
            | "minimal"
            | "minimalist"
            | "modern"
            | "of"
            | "polished"
            | "professional"
            | "simple"
            | "sleek"
            | "the"
            | "usable"
            | "visual"
    )
}

fn html_visual_direction_entry_is_specific(entry: &str) -> bool {
    let terms = split_interaction_identifier_terms(entry)
        .into_iter()
        .filter(|term| term.len() >= 3)
        .collect::<Vec<_>>();
    if terms.len() < 2 {
        return false;
    }

    terms
        .iter()
        .any(|term| !html_visual_direction_noise_term(term))
}

fn brief_has_specific_html_visual_direction(brief: &StudioArtifactBrief) -> bool {
    brief
        .visual_tone
        .iter()
        .chain(brief.style_directives.iter())
        .any(|entry| html_visual_direction_entry_is_specific(entry))
}

pub fn build_studio_artifact_exemplar_query(
    brief: &StudioArtifactBrief,
    blueprint: &StudioArtifactBlueprint,
    artifact_ir: &StudioArtifactIR,
    taste_memory: Option<&StudioArtifactTasteMemory>,
) -> String {
    let section_roles = blueprint
        .section_plan
        .iter()
        .map(|section| section.role.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let interaction_families = blueprint
        .interaction_plan
        .iter()
        .map(|interaction| interaction.family.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let evidence_kinds = blueprint
        .evidence_plan
        .iter()
        .map(|entry| entry.kind.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let component_patterns = blueprint
        .component_plan
        .iter()
        .map(|component| component.component_family.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let typography_preferences = taste_memory
        .map(|memory| memory.typography_preferences.join(", "))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| blueprint.design_system.typography_strategy.clone());
    let density_preference = taste_memory
        .and_then(|memory| memory.density_preference.clone())
        .unwrap_or_else(|| blueprint.design_system.density.clone());
    let tone_family = taste_memory
        .map(|memory| memory.tone_family.join(", "))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| brief.visual_tone.join(", "));
    let motion_tolerance = taste_memory
        .and_then(|memory| memory.motion_tolerance.clone())
        .unwrap_or_else(|| blueprint.design_system.motion_style.clone());
    let preferred_scaffolds = taste_memory
        .map(|memory| memory.preferred_scaffold_families.join(", "))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| blueprint.scaffold_family.clone());
    let preferred_components = taste_memory
        .map(|memory| memory.preferred_component_patterns.join(", "))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| component_patterns.clone());
    let anti_patterns = taste_memory
        .map(|memory| memory.anti_patterns.join(", "))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "none noted".to_string());

    format!(
        "Studio artifact exemplar retrieval.\nRenderer: {:?}\nScaffold family: {}\nAudience: {}\nJob to be done: {}\nSubject domain: {}\nArtifact thesis: {}\nSection roles: {}\nInteraction families: {}\nEvidence kinds: {}\nComponent patterns: {}\nRequired concepts: {}\nRequired interactions: {}\nTypography preferences: {}\nDensity preference: {}\nTone family: {}\nMotion tolerance: {}\nPreferred scaffold families: {}\nPreferred component patterns: {}\nAnti patterns: {}\nStatic audit expectations: {}\nRender evaluation checklist: {}\nRetrieve high-quality prior artifacts that match this structural shape and design intent. Use them as structural grounding only, never as text-copy templates.",
        blueprint.renderer,
        blueprint.scaffold_family,
        brief.audience,
        brief.job_to_be_done,
        brief.subject_domain,
        brief.artifact_thesis,
        section_roles,
        interaction_families,
        evidence_kinds,
        component_patterns,
        brief.required_concepts.join(", "),
        brief.required_interactions.join(", "),
        typography_preferences,
        density_preference,
        tone_family,
        motion_tolerance,
        preferred_scaffolds,
        preferred_components,
        anti_patterns,
        artifact_ir.static_audit_expectations.join(", "),
        artifact_ir.render_eval_checklist.join(", "),
    )
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
            if !brief_has_specific_html_visual_direction(brief) {
                return Err(
                    "Interactive HTML briefs must contribute at least one concrete multi-word visual direction, not only generic tone words."
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

fn concise_requirement_list(values: &[String], fallback: &str, max_items: usize) -> Vec<String> {
    let mut items = values
        .iter()
        .map(|value| normalize_inline_whitespace(value))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    items.truncate(max_items);
    if items.is_empty() {
        items.push(fallback.to_string());
    }
    items
}

fn blueprint_interaction_family(interaction: &str) -> &'static str {
    let terms = split_interaction_identifier_terms(interaction);
    if terms.iter().any(|term| {
        matches!(
            term.as_str(),
            "tab" | "tabs" | "toggle" | "switch" | "view" | "views" | "compare" | "comparison"
        )
    }) {
        "view_switching"
    } else if terms.iter().any(|term| {
        matches!(
            term.as_str(),
            "hover" | "rollover" | "detail" | "focus" | "inspect" | "highlight"
        )
    }) {
        "detail_inspection"
    } else if terms.iter().any(|term| {
        matches!(
            term.as_str(),
            "step" | "sequence" | "browse" | "scroll" | "tour" | "previous" | "next" | "scrub"
        )
    }) {
        "sequence_browsing"
    } else if terms.iter().any(|term| {
        matches!(
            term.as_str(),
            "drag" | "rotate" | "measure" | "simulate" | "manipulate" | "state"
        )
    }) {
        "state_manipulation"
    } else {
        "guided_response"
    }
}

fn blueprint_scaffold_family(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) -> String {
    match request.renderer {
        StudioRendererKind::HtmlIframe => {
            if super::brief_requires_sequence_browsing(brief) {
                "guided_tutorial".to_string()
            } else if brief
                .required_interactions
                .iter()
                .any(|interaction| blueprint_interaction_family(interaction) == "view_switching")
            {
                "comparison_story".to_string()
            } else if brief.factual_anchors.len() + brief.reference_hints.len() >= 2 {
                "data_forward_walkthrough".to_string()
            } else {
                "editorial_explainer".to_string()
            }
        }
        StudioRendererKind::JsxSandbox => "guided_tutorial".to_string(),
        StudioRendererKind::Svg => "single_visual_story".to_string(),
        StudioRendererKind::Mermaid => "diagram_flow".to_string(),
        StudioRendererKind::PdfEmbed | StudioRendererKind::Markdown => {
            "document_outline".to_string()
        }
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => {
            "export_bundle".to_string()
        }
        StudioRendererKind::WorkspaceSurface => "workspace_project".to_string(),
    }
}

fn blueprint_skill_needs(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) -> Vec<StudioArtifactSkillNeed> {
    let mut skill_needs = vec![StudioArtifactSkillNeed {
        kind: StudioArtifactSkillNeedKind::AccessibilityReview,
        priority: StudioArtifactSkillNeedPriority::Required,
        rationale: "Persistent artifacts must keep keyboard, labeling, and readable structure obligations explicit.".to_string(),
    }];

    if matches!(
        request.renderer,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
    ) {
        skill_needs.push(StudioArtifactSkillNeed {
            kind: StudioArtifactSkillNeedKind::VisualArtDirection,
            priority: StudioArtifactSkillNeedPriority::Required,
            rationale: "Interactive renderer paths need explicit visual direction instead of generic default layout choices.".to_string(),
        });
        skill_needs.push(StudioArtifactSkillNeed {
            kind: StudioArtifactSkillNeedKind::InteractionCopyDiscipline,
            priority: StudioArtifactSkillNeedPriority::Recommended,
            rationale: "Control labels, detail copy, and explanatory state changes should stay concise and request-faithful.".to_string(),
        });
    }

    if brief.required_concepts.len() >= 3 {
        skill_needs.push(StudioArtifactSkillNeed {
            kind: StudioArtifactSkillNeedKind::EditorialLayout,
            priority: StudioArtifactSkillNeedPriority::Recommended,
            rationale: "Dense concept coverage benefits from a stronger narrative and section hierarchy spine.".to_string(),
        });
    }

    if brief
        .required_interactions
        .iter()
        .any(|interaction| blueprint_interaction_family(interaction) == "sequence_browsing")
    {
        skill_needs.push(StudioArtifactSkillNeed {
            kind: StudioArtifactSkillNeedKind::MotionHierarchy,
            priority: StudioArtifactSkillNeedPriority::Recommended,
            rationale:
                "Sequence browsing benefits from restrained choreography and progression cues."
                    .to_string(),
        });
    }

    if brief.required_interactions.iter().any(|interaction| {
        matches!(
            blueprint_interaction_family(interaction),
            "view_switching" | "detail_inspection"
        )
    }) {
        skill_needs.push(StudioArtifactSkillNeed {
            kind: StudioArtifactSkillNeedKind::DataStorytelling,
            priority: StudioArtifactSkillNeedPriority::Recommended,
            rationale: "Multiple evidence views should stay legible and comparably narrated across shared detail surfaces.".to_string(),
        });
    }

    skill_needs
}

fn blueprint_section_plan(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) -> Vec<StudioArtifactSectionPlan> {
    let concept_requirements = concise_requirement_list(
        &brief.required_concepts,
        "Keep the main request concepts visible.",
        3,
    );
    let evidence_requirements = concise_requirement_list(
        if brief.factual_anchors.is_empty() {
            &brief.reference_hints
        } else {
            &brief.factual_anchors
        },
        "Show at least one concrete evidence surface.",
        3,
    );
    let mut sections = vec![
        StudioArtifactSectionPlan {
            id: "hero".to_string(),
            role: "hero".to_string(),
            visible_purpose: "Frame the artifact thesis and orient the user immediately."
                .to_string(),
            content_requirements: vec![brief.artifact_thesis.clone(), brief.job_to_be_done.clone()],
            interaction_hooks: vec!["primary_controls".to_string()],
            first_paint_requirements: vec![
                "Show the title, thesis, and active control state before script execution."
                    .to_string(),
            ],
        },
        StudioArtifactSectionPlan {
            id: "concept-foundation".to_string(),
            role: "concept_foundation".to_string(),
            visible_purpose: "Keep the differentiating concepts explicit and readable.".to_string(),
            content_requirements: concept_requirements,
            interaction_hooks: vec!["shared_detail_region".to_string()],
            first_paint_requirements: vec![
                "Render concrete concept labels rather than placeholder headings.".to_string(),
            ],
        },
        StudioArtifactSectionPlan {
            id: "evidence-surface".to_string(),
            role: "evidence_surface".to_string(),
            visible_purpose: "Surface the artifact's primary evidence view on first paint."
                .to_string(),
            content_requirements: evidence_requirements,
            interaction_hooks: vec!["evidence_marks".to_string(), "detail_panel".to_string()],
            first_paint_requirements: vec![
                "Show populated evidence marks with visible labels and a default selected state."
                    .to_string(),
            ],
        },
    ];

    if matches!(
        request.renderer,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
    ) {
        sections.push(StudioArtifactSectionPlan {
            id: "interaction-lab".to_string(),
            role: "interaction_lab".to_string(),
            visible_purpose: "Make the planned interaction families tangible.".to_string(),
            content_requirements: concise_requirement_list(
                &brief.required_interactions,
                "Expose at least one concrete interaction.",
                3,
            ),
            interaction_hooks: vec![
                "view_switching".to_string(),
                "detail_inspection".to_string(),
                "sequence_browsing".to_string(),
            ],
            first_paint_requirements: vec![
                "Controls and response surfaces must already exist in the static markup."
                    .to_string(),
            ],
        });
    }

    sections.push(StudioArtifactSectionPlan {
        id: "takeaways".to_string(),
        role: "takeaways".to_string(),
        visible_purpose: "Close with summary and next-step framing.".to_string(),
        content_requirements: vec![
            "Summarize what the artifact teaches or proves.".to_string(),
            "Leave the user with an accurate closing comparison or takeaway.".to_string(),
        ],
        interaction_hooks: Vec::new(),
        first_paint_requirements: vec![
            "End with a visible conclusion section or footer.".to_string()
        ],
    });

    sections
}

fn blueprint_interaction_plan(brief: &StudioArtifactBrief) -> Vec<StudioArtifactInteractionPlan> {
    let mut plans = brief
        .required_interactions
        .iter()
        .enumerate()
        .map(|(index, interaction)| {
            let family = blueprint_interaction_family(interaction).to_string();
            let (source_controls, target_surfaces, default_state, required_first_paint_affordances) =
                match family.as_str() {
                    "view_switching" => (
                        vec!["control_bar".to_string(), "mapped_view_buttons".to_string()],
                        if studio_modal_first_html_enabled() {
                            vec!["authored_state_surfaces".to_string()]
                        } else {
                            vec!["mapped_panels".to_string(), "shared_detail_region".to_string()]
                        },
                        "first_view_selected".to_string(),
                        if studio_modal_first_html_enabled() {
                            vec![
                                "At least two authored states, scenes, or comparison surfaces should be visible or directly reachable on first paint."
                                    .to_string(),
                                "Interaction must produce a visible on-page state change instead of decorative navigation."
                                    .to_string(),
                            ]
                        } else {
                            vec![
                                "At least two mapped panels must be present in the raw markup."
                                    .to_string(),
                                "Exactly one mapped panel is visible before script execution."
                                    .to_string(),
                            ]
                        },
                    ),
                    "detail_inspection" => (
                        vec!["focusable_data_marks".to_string()],
                        if studio_modal_first_html_enabled() {
                            vec!["inline_annotation_surface".to_string()]
                        } else {
                            vec!["shared_detail_region".to_string()]
                        },
                        "default_detail_visible".to_string(),
                        vec![
                            if studio_modal_first_html_enabled() {
                                "Visible explanatory context is rendered before interaction.".to_string()
                            } else {
                                "Visible detail text is rendered before interaction.".to_string()
                            },
                            "Focusable marks or buttons already exist on first paint.".to_string(),
                        ],
                    ),
                    "sequence_browsing" => (
                        vec!["stepper".to_string(), "previous_next_controls".to_string()],
                        if studio_modal_first_html_enabled() {
                            vec!["sequence_surface".to_string(), "inline_annotation_surface".to_string()]
                        } else {
                            vec!["sequence_panel".to_string(), "shared_detail_region".to_string()]
                        },
                        "step_one_active".to_string(),
                        vec![
                            "A progression control is visible before script execution.".to_string(),
                        ],
                    ),
                    "state_manipulation" => (
                        vec!["state_controls".to_string()],
                        vec!["primary_demo_surface".to_string(), "state_readout".to_string()],
                        "default_state_visible".to_string(),
                        vec![
                            "The current state readout and manipulated surface are visible on first paint."
                                .to_string(),
                        ],
                    ),
                    _ => (
                        vec!["primary_controls".to_string()],
                        vec!["response_surface".to_string()],
                        "default_response_visible".to_string(),
                        vec!["The response surface must already contain meaningful content.".to_string()],
                    ),
                };

            StudioArtifactInteractionPlan {
                id: format!("interaction-{}", index + 1),
                family,
                source_controls,
                target_surfaces,
                default_state,
                required_first_paint_affordances,
            }
        })
        .collect::<Vec<_>>();

    if plans.is_empty() {
        plans.push(StudioArtifactInteractionPlan {
            id: "interaction-1".to_string(),
            family: "guided_response".to_string(),
            source_controls: vec!["primary_controls".to_string()],
            target_surfaces: vec!["response_surface".to_string()],
            default_state: "default_response_visible".to_string(),
            required_first_paint_affordances: vec![
                "Render the primary response region with meaningful default content.".to_string(),
            ],
        });
    }

    plans
}

fn blueprint_evidence_plan(brief: &StudioArtifactBrief) -> Vec<StudioArtifactEvidencePlanEntry> {
    let seed_concepts =
        concise_requirement_list(&brief.required_concepts, "main request concepts", 3);
    let seed_evidence = concise_requirement_list(
        if brief.factual_anchors.is_empty() {
            &brief.reference_hints
        } else {
            &brief.factual_anchors
        },
        "request-grounded evidence",
        3,
    );

    vec![
        StudioArtifactEvidencePlanEntry {
            id: "primary-evidence".to_string(),
            kind: "primary_surface".to_string(),
            purpose: "Carry the default evidence view that anchors the artifact.".to_string(),
            concept_bindings: seed_concepts.clone(),
            first_paint_elements: vec![
                "labeled evidence marks".to_string(),
                "default selection".to_string(),
                "shared detail copy".to_string(),
            ],
            detail_targets: seed_evidence.clone(),
        },
        StudioArtifactEvidencePlanEntry {
            id: "secondary-evidence".to_string(),
            kind: "comparison_surface".to_string(),
            purpose: "Provide a second evidence family so the artifact is not a one-chart shell."
                .to_string(),
            concept_bindings: seed_concepts,
            first_paint_elements: vec![
                "secondary labels".to_string(),
                "comparison cues".to_string(),
            ],
            detail_targets: seed_evidence,
        },
    ]
}

fn blueprint_design_system(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) -> StudioArtifactDesignSystem {
    let mut emphasis_modes =
        concise_requirement_list(&brief.visual_tone, "request-grounded hierarchy", 3);
    let additional_emphasis_modes =
        concise_requirement_list(&brief.style_directives, "clear interaction affordances", 2)
            .into_iter()
            .filter(|entry| !emphasis_modes.iter().any(|existing| existing == entry))
            .collect::<Vec<_>>();
    emphasis_modes.extend(additional_emphasis_modes);

    StudioArtifactDesignSystem {
        color_strategy: match request.renderer {
            StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => {
                "contrast-led editorial palette".to_string()
            }
            StudioRendererKind::Svg | StudioRendererKind::Mermaid => {
                "diagram-safe contrast palette".to_string()
            }
            _ => "document-safe neutral palette".to_string(),
        },
        typography_strategy: match request.renderer {
            StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => {
                "display plus annotation pairing".to_string()
            }
            _ => "readable document pairing".to_string(),
        },
        density: if brief.required_concepts.len() >= 4 {
            "information-dense".to_string()
        } else {
            "balanced".to_string()
        },
        motion_style: if matches!(
            request.renderer,
            StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
        ) {
            "restrained staged reveal".to_string()
        } else {
            "minimal motion".to_string()
        },
        emphasis_modes,
    }
}

fn blueprint_component_plan(
    blueprint: &StudioArtifactBlueprint,
) -> Vec<StudioArtifactComponentPlanEntry> {
    fn push_component(
        plan: &mut Vec<StudioArtifactComponentPlanEntry>,
        component_family: &str,
        role: &str,
        section_ids: &[&str],
        interaction_ids: Vec<String>,
    ) {
        if plan
            .iter()
            .any(|entry| entry.component_family == component_family)
        {
            return;
        }
        plan.push(StudioArtifactComponentPlanEntry {
            id: format!("component-{}", component_family.replace('_', "-")),
            component_family: component_family.to_string(),
            role: role.to_string(),
            section_ids: section_ids
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            interaction_ids,
        });
    }

    let all_interaction_ids = blueprint
        .interaction_plan
        .iter()
        .map(|interaction| interaction.id.clone())
        .collect::<Vec<_>>();
    let view_switching_ids = blueprint
        .interaction_plan
        .iter()
        .filter(|interaction| interaction.family == "view_switching")
        .map(|interaction| interaction.id.clone())
        .collect::<Vec<_>>();
    let detail_inspection_ids = blueprint
        .interaction_plan
        .iter()
        .filter(|interaction| interaction.family == "detail_inspection")
        .map(|interaction| interaction.id.clone())
        .collect::<Vec<_>>();
    let sequence_ids = blueprint
        .interaction_plan
        .iter()
        .filter(|interaction| interaction.family == "sequence_browsing")
        .map(|interaction| interaction.id.clone())
        .collect::<Vec<_>>();
    let state_ids = blueprint
        .interaction_plan
        .iter()
        .filter(|interaction| interaction.family == "state_manipulation")
        .map(|interaction| interaction.id.clone())
        .collect::<Vec<_>>();
    let has_view_switching = !view_switching_ids.is_empty();
    let has_detail_inspection = !detail_inspection_ids.is_empty();
    let has_sequence_browsing = !sequence_ids.is_empty();
    let has_state_manipulation = !state_ids.is_empty();

    let mut plan = Vec::new();
    push_component(
        &mut plan,
        "hero_frame",
        "orientation",
        &["hero"],
        Vec::new(),
    );
    if !studio_modal_first_html_enabled() {
        push_component(
            &mut plan,
            "shared_detail_panel",
            "shared_explanation",
            &["evidence-surface"],
            all_interaction_ids.clone(),
        );
    }

    match blueprint.scaffold_family.as_str() {
        "comparison_story" => {
            push_component(
                &mut plan,
                "tabbed_evidence_rail",
                "evidence_navigation",
                &["hero", "evidence-surface"],
                view_switching_ids.clone(),
            );
            push_component(
                &mut plan,
                "comparison_table",
                "structured_comparison",
                &["evidence-surface", "takeaways"],
                view_switching_ids.clone(),
            );
            push_component(
                &mut plan,
                "metric_card_grid",
                "evidence_summary",
                &["concept-foundation", "evidence-surface"],
                detail_inspection_ids.clone(),
            );
        }
        "data_forward_walkthrough" => {
            push_component(
                &mut plan,
                "metric_card_grid",
                "evidence_summary",
                &["hero", "concept-foundation"],
                detail_inspection_ids.clone(),
            );
            push_component(
                &mut plan,
                "comparison_table",
                "structured_comparison",
                &["evidence-surface", "takeaways"],
                all_interaction_ids.clone(),
            );
            push_component(
                &mut plan,
                "labeled_svg_chart_shell",
                "data_visualization",
                &["evidence-surface"],
                all_interaction_ids.clone(),
            );
        }
        "guided_tutorial" => {
            push_component(
                &mut plan,
                "guided_stepper",
                "progression",
                &["interaction-lab", "takeaways"],
                sequence_ids.clone(),
            );
            push_component(
                &mut plan,
                "timeline",
                "chronology",
                &["concept-foundation", "takeaways"],
                sequence_ids.clone(),
            );
            push_component(
                &mut plan,
                "metric_card_grid",
                "evidence_summary",
                &["hero", "concept-foundation"],
                all_interaction_ids.clone(),
            );
        }
        "launch_page" => {
            push_component(
                &mut plan,
                "metric_card_grid",
                "evidence_summary",
                &["hero", "takeaways"],
                all_interaction_ids.clone(),
            );
            push_component(
                &mut plan,
                "comparison_table",
                "structured_comparison",
                &["evidence-surface"],
                all_interaction_ids.clone(),
            );
        }
        _ => {
            push_component(
                &mut plan,
                "metric_card_grid",
                "evidence_summary",
                &["concept-foundation", "evidence-surface"],
                detail_inspection_ids.clone(),
            );
            push_component(
                &mut plan,
                "labeled_svg_chart_shell",
                "data_visualization",
                &["evidence-surface"],
                all_interaction_ids.clone(),
            );
        }
    }

    if has_view_switching {
        push_component(
            &mut plan,
            "mapped_view_switcher",
            "panel_switching",
            &["interaction-lab", "evidence-surface"],
            view_switching_ids.clone(),
        );
        push_component(
            &mut plan,
            "tabbed_evidence_rail",
            "evidence_navigation",
            &["hero", "evidence-surface"],
            view_switching_ids.clone(),
        );
    }

    if has_sequence_browsing {
        push_component(
            &mut plan,
            "guided_stepper",
            "progression",
            &["interaction-lab"],
            sequence_ids.clone(),
        );
        push_component(
            &mut plan,
            "timeline",
            "chronology",
            &["takeaways"],
            sequence_ids.clone(),
        );
    }

    if has_state_manipulation {
        push_component(
            &mut plan,
            "state_space_visualizer",
            "state_demo",
            &["interaction-lab", "evidence-surface"],
            state_ids.clone(),
        );
        push_component(
            &mut plan,
            "distribution_comparator",
            "distribution",
            &["evidence-surface", "takeaways"],
            state_ids.clone(),
        );
        push_component(
            &mut plan,
            "transform_diagram_surface",
            "transformation",
            &["interaction-lab"],
            state_ids.clone(),
        );
    }

    if has_state_manipulation && has_detail_inspection {
        push_component(
            &mut plan,
            "paired_state_correlation_demo",
            "correlation",
            &["interaction-lab", "evidence-surface"],
            all_interaction_ids,
        );
    }

    plan
}

fn blueprint_accessibility_plan(
    blueprint: &StudioArtifactBlueprint,
) -> StudioArtifactAccessibilityPlan {
    let mut focus_order = vec![
        "hero".to_string(),
        "primary_controls".to_string(),
        "shared_detail_region".to_string(),
    ];
    let additional_focus_order = blueprint
        .section_plan
        .iter()
        .map(|section| section.id.clone())
        .filter(|section_id| !focus_order.iter().any(|existing| existing == section_id))
        .collect::<Vec<_>>();
    focus_order.extend(additional_focus_order);

    StudioArtifactAccessibilityPlan {
        obligations: vec![
            "Use semantic sections and preserve heading order.".to_string(),
            "Keep interactive controls keyboard reachable.".to_string(),
            if studio_modal_first_html_enabled() {
                "Ensure interaction feedback remains perceivable after every state change."
                    .to_string()
            } else {
                "Ensure shared detail updates remain perceivable after interaction.".to_string()
            },
        ],
        focus_order,
        aria_expectations: vec![
            "Mapped controls expose selected state when applicable.".to_string(),
            "Evidence marks or diagrams expose labels or accessible names.".to_string(),
        ],
    }
}

fn blueprint_acceptance_targets(
    request: &StudioOutcomeArtifactRequest,
    blueprint: &StudioArtifactBlueprint,
) -> StudioArtifactAcceptanceTargets {
    StudioArtifactAcceptanceTargets {
        minimum_section_count: blueprint.section_plan.len().min(u8::MAX as usize) as u8,
        minimum_interactive_regions: if matches!(
            request.renderer,
            StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
        ) {
            blueprint
                .interaction_plan
                .len()
                .max(1)
                .min(u8::MAX as usize) as u8
        } else {
            0
        },
        require_first_paint_evidence: true,
        require_persistent_detail_region: blueprint
            .interaction_plan
            .iter()
            .any(|interaction| interaction.family != "guided_response"),
        require_distinct_typography: matches!(
            request.renderer,
            StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
        ),
        require_keyboard_affordances: matches!(
            request.renderer,
            StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
        ),
    }
}

pub fn derive_studio_artifact_blueprint(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) -> StudioArtifactBlueprint {
    let scaffold_family = blueprint_scaffold_family(request, brief);
    let section_plan = blueprint_section_plan(request, brief);
    let interaction_plan = blueprint_interaction_plan(brief);
    let evidence_plan = blueprint_evidence_plan(brief);
    let design_system = blueprint_design_system(request, brief);
    let skill_needs = blueprint_skill_needs(request, brief);
    let mut blueprint = StudioArtifactBlueprint {
        version: 1,
        renderer: request.renderer,
        narrative_arc: format!(
            "Orient the user, stage the core concepts, surface evidence, and close with a request-faithful takeaway for {}.",
            brief.job_to_be_done
        ),
        section_plan,
        interaction_plan,
        evidence_plan,
        design_system,
        component_plan: Vec::new(),
        accessibility_plan: StudioArtifactAccessibilityPlan {
            obligations: Vec::new(),
            focus_order: Vec::new(),
            aria_expectations: Vec::new(),
        },
        acceptance_targets: StudioArtifactAcceptanceTargets {
            minimum_section_count: 0,
            minimum_interactive_regions: 0,
            require_first_paint_evidence: true,
            require_persistent_detail_region: false,
            require_distinct_typography: false,
            require_keyboard_affordances: false,
        },
        scaffold_family,
        variation_strategy: "Preserve the scaffold family while varying composition through concept emphasis, evidence ordering, and motion restraint.".to_string(),
        skill_needs,
    };
    blueprint.component_plan = blueprint_component_plan(&blueprint);
    blueprint.accessibility_plan = blueprint_accessibility_plan(&blueprint);
    blueprint.acceptance_targets = blueprint_acceptance_targets(request, &blueprint);
    blueprint
}

pub fn compile_studio_artifact_ir(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: &StudioArtifactBlueprint,
) -> StudioArtifactIR {
    let mut semantic_structure = blueprint
        .section_plan
        .iter()
        .map(|section| StudioArtifactIRNode {
            id: section.id.clone(),
            kind: section.role.clone(),
            parent_id: Some("main".to_string()),
            section_id: Some(section.id.clone()),
            label: section.visible_purpose.clone(),
            bindings: section.content_requirements.clone(),
        })
        .collect::<Vec<_>>();
    semantic_structure.insert(
        0,
        StudioArtifactIRNode {
            id: "main".to_string(),
            kind: "root".to_string(),
            parent_id: None,
            section_id: None,
            label: brief.artifact_thesis.clone(),
            bindings: vec![brief.job_to_be_done.clone()],
        },
    );

    let interaction_graph = blueprint
        .interaction_plan
        .iter()
        .map(|interaction| StudioArtifactIRInteractionEdge {
            id: interaction.id.clone(),
            family: interaction.family.clone(),
            control_node_ids: interaction.source_controls.clone(),
            target_node_ids: interaction.target_surfaces.clone(),
            default_state: interaction.default_state.clone(),
        })
        .collect::<Vec<_>>();

    let evidence_surfaces = blueprint
        .evidence_plan
        .iter()
        .map(|surface| StudioArtifactIREvidenceSurface {
            id: surface.id.clone(),
            kind: surface.kind.clone(),
            section_id: "evidence-surface".to_string(),
            bound_concepts: surface.concept_bindings.clone(),
            first_paint_expectations: surface.first_paint_elements.clone(),
        })
        .collect::<Vec<_>>();

    let design_tokens = vec![
        StudioArtifactDesignToken {
            name: "color.strategy".to_string(),
            category: "color".to_string(),
            value: blueprint.design_system.color_strategy.clone(),
        },
        StudioArtifactDesignToken {
            name: "type.strategy".to_string(),
            category: "typography".to_string(),
            value: blueprint.design_system.typography_strategy.clone(),
        },
        StudioArtifactDesignToken {
            name: "layout.density".to_string(),
            category: "layout".to_string(),
            value: blueprint.design_system.density.clone(),
        },
        StudioArtifactDesignToken {
            name: "motion.style".to_string(),
            category: "motion".to_string(),
            value: blueprint.design_system.motion_style.clone(),
        },
    ];

    let component_bindings = blueprint
        .component_plan
        .iter()
        .map(|component| format!("{} -> {}", component.component_family, component.role))
        .collect::<Vec<_>>();

    let mut static_audit_expectations = vec![
        format!(
            "Render at least {} sections with semantic wrappers.",
            blueprint.acceptance_targets.minimum_section_count
        ),
        "Keep first-paint evidence populated before scripts execute.".to_string(),
    ];
    if blueprint
        .acceptance_targets
        .require_persistent_detail_region
    {
        static_audit_expectations.push(
            "Keep one persistent detail or explanation region visible alongside interactions."
                .to_string(),
        );
    }
    if matches!(
        request.renderer,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
    ) {
        static_audit_expectations.push(
            "Interactive controls must expose keyboard-reachable affordances and visible selected state."
                .to_string(),
        );
    }

    StudioArtifactIR {
        version: 1,
        renderer: request.renderer,
        scaffold_family: blueprint.scaffold_family.clone(),
        semantic_structure,
        interaction_graph,
        evidence_surfaces,
        design_tokens,
        motion_plan: vec![
            blueprint.design_system.motion_style.clone(),
            "Reveal sections in narrative order instead of animating every element equally."
                .to_string(),
        ],
        accessibility_obligations: blueprint.accessibility_plan.obligations.clone(),
        responsive_layout_rules: vec![
            "Preserve one readable primary column on narrow viewports.".to_string(),
            "Collapse side-by-side evidence into stacked sections without dropping shared detail."
                .to_string(),
        ],
        component_bindings,
        static_audit_expectations,
        render_eval_checklist: vec![
            "Hero, primary evidence, and detail region remain readable at first paint."
                .to_string(),
            "Evidence surfaces show distinct visual families rather than duplicated shells."
                .to_string(),
            "Interactive affordances remain visible and coherent on both desktop and narrow widths."
                .to_string(),
        ],
    }
}

pub fn build_studio_artifact_brief_repair_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_brief_repair_prompt_for_runtime(
        title,
        intent,
        request,
        refinement,
        raw_output,
        failure,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn build_studio_artifact_brief_repair_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    raw_output: &str,
    failure: &str,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_brief_prompt(request.renderer, runtime_kind);
    let request_json = serde_json::to_string(request)
        .map_err(|error| format!("Failed to serialize Studio artifact request: {error}"))?;
    let refinement_json =
        serde_json::to_string(&studio_artifact_refinement_context_view(refinement))
            .map_err(|error| format!("Failed to serialize Studio refinement context: {error}"))?;
    if compact_prompt {
        let request_focus_json = serde_json::to_string(&studio_artifact_brief_request_focus(
            request,
        ))
        .map_err(|error| format!("Failed to serialize Studio artifact request focus: {error}"))?;
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact brief repairer. Repair the previous brief into one schema-valid request-grounded artifact brief JSON object. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nCurrent artifact context JSON:\n{}\n\nFailure:\n{}\n\nPrevious raw output excerpt:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\"audience\":<string>,\"jobToBeDone\":<string>,\"subjectDomain\":<string>,\"artifactThesis\":<string>,\"requiredConcepts\":[<string>],\"requiredInteractions\":[<string>],\"visualTone\":[<string>],\"factualAnchors\":[<string>],\"styleDirectives\":[<string>],\"referenceHints\":[<string>]}}\nRules:\n1) Use arrays for every list field, even for one item.\n2) The four core string fields must be non-empty and request-grounded.\n3) Preserve the differentiating nouns and framing words from the request.\n4) For html_iframe, keep at least three concrete concepts, at least two concrete multi-word interactions, and at least one evidence anchor or reference hint.\n5) For html_iframe, supply at least one concrete multi-word visual direction in visualTone or styleDirectives instead of generic style adjectives alone.\n6) Use empty arrays instead of filler.",
                    title,
                    intent,
                    request_focus_json,
                    refinement_json,
                    failure,
                    truncate_planning_preview(raw_output, 1600),
                )
            }
        ]));
    }
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
    build_studio_artifact_brief_field_repair_prompt_for_runtime(
        title,
        intent,
        request,
        refinement,
        first_raw_output,
        repair_raw_output,
        failure,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn build_studio_artifact_brief_field_repair_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    first_raw_output: &str,
    repair_raw_output: &str,
    failure: &str,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_brief_prompt(request.renderer, runtime_kind);
    let request_json = serde_json::to_string(request)
        .map_err(|error| format!("Failed to serialize Studio artifact request: {error}"))?;
    let refinement_json =
        serde_json::to_string(&studio_artifact_refinement_context_view(refinement))
            .map_err(|error| format!("Failed to serialize Studio refinement context: {error}"))?;
    if compact_prompt {
        let request_focus_json = serde_json::to_string(&studio_artifact_brief_request_focus(
            request,
        ))
        .map_err(|error| format!("Failed to serialize Studio artifact request focus: {error}"))?;
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact brief field repairer. Replace invalid or empty fields with the shortest request-grounded schema-valid brief JSON object. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nCurrent artifact context JSON:\n{}\n\nFailure:\n{}\n\nPlanner output preview:\n{}\n\nRepair output preview:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\"audience\":<string>,\"jobToBeDone\":<string>,\"subjectDomain\":<string>,\"artifactThesis\":<string>,\"requiredConcepts\":[<string>],\"requiredInteractions\":[<string>],\"visualTone\":[<string>],\"factualAnchors\":[<string>],\"styleDirectives\":[<string>],\"referenceHints\":[<string>]}}\nRules:\n1) Every string field must be non-empty and request-grounded.\n2) Preserve the differentiating subject nouns from the request.\n3) Keep list items short, concrete, and schema-valid arrays.\n4) For html_iframe, keep at least three concepts, at least two multi-word interactions, and at least one evidence anchor or reference hint.\n5) For html_iframe, keep at least one concrete multi-word visual direction in visualTone or styleDirectives.\n6) Do not leave required strings blank.",
                    title,
                    intent,
                    request_focus_json,
                    refinement_json,
                    failure,
                    truncate_planning_preview(first_raw_output, 420),
                    truncate_planning_preview(repair_raw_output, 420),
                )
            }
        ]));
    }
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
