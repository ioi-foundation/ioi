use super::brief::{normalize_studio_outcome_planning_value, parse_studio_json_object_value};
use super::shared::{studio_planning_trace, truncate_planning_preview};
use crate::studio::validation::studio_artifact_refinement_context_view;
use crate::studio::*;
use crate::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    StudioArtifactClass, StudioArtifactDeliverableShape, StudioArtifactPersistenceMode,
    StudioExecutionStrategy, StudioExecutionSubstrate, StudioOutcomeArtifactRequest,
    StudioOutcomeArtifactScope, StudioOutcomeArtifactVerificationRequest, StudioOutcomeKind,
    StudioOutcomePlanningPayload, StudioPresentationSurface, StudioRendererKind,
    StudioRuntimeProvenanceKind,
};
use serde_json::json;
use std::sync::Arc;

fn compact_local_outcome_router_refinement_context(
    refinement: Option<&StudioArtifactRefinementContext>,
) -> serde_json::Value {
    let Some(refinement) = refinement else {
        return serde_json::Value::Null;
    };

    json!({
        "artifactId": refinement.artifact_id,
        "revisionId": refinement.revision_id,
        "title": truncate_planning_preview(&refinement.title, 120),
        "summary": truncate_planning_preview(&refinement.summary, 220),
        "renderer": refinement.renderer,
        "files": refinement
            .files
            .iter()
            .take(4)
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
                })
            })
            .collect::<Vec<_>>(),
        "selectedTargets": refinement
            .selected_targets
            .iter()
            .take(4)
            .map(|target| {
                json!({
                    "sourceSurface": target.source_surface,
                    "path": target.path,
                    "label": truncate_planning_preview(&target.label, 80),
                })
            })
            .collect::<Vec<_>>(),
        "hasBlueprint": refinement.blueprint.is_some(),
        "hasArtifactIr": refinement.artifact_ir.is_some(),
        "selectedSkillCount": refinement.selected_skills.len(),
        "retrievedExemplarCount": refinement.retrieved_exemplars.len(),
    })
}

fn build_compact_local_outcome_router_prompt(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> serde_json::Value {
    let active_artifact_context_json =
        compact_local_outcome_router_refinement_context(active_artifact).to_string();
    let user_content = format!(
        "Request:\n{intent}\n\n\
         Active artifact id: {artifact_id}\n\
         Active artifact context summary JSON:\n{active_context}\n\n\
         Return exactly one JSON object with this minimal camelCase schema:\n\
         {{\n\
           \"outcomeKind\": \"conversation\" | \"tool_widget\" | \"visualizer\" | \"artifact\",\n\
           \"executionStrategy\": \"single_pass\" | \"direct_author\" | \"plan_execute\" | \"micro_swarm\" | \"adaptive_work_graph\",\n\
           \"confidence\": <0_to_1_float>,\n\
           \"needsClarification\": <boolean>,\n\
           \"clarificationQuestions\": [<string>],\n\
           \"routingHints\": [<string>],\n\
           \"artifact\": null | {{\n\
             \"renderer\": \"markdown\" | \"html_iframe\" | \"jsx_sandbox\" | \"svg\" | \"mermaid\" | \"pdf_embed\" | \"download_card\" | \"workspace_surface\" | \"bundle_manifest\",\n\
             \"artifactClass\": \"document\" | \"visual\" | \"interactive_single_file\" | \"downloadable_file\" | \"workspace_project\" | \"compound_bundle\" | \"code_patch\" | \"report_bundle\",\n\
             \"workspaceRecipeId\": null | \"react-vite\" | \"vite-static-html\",\n\
             \"presentationVariantId\": null | \"sport-editorial\" | \"minimal-agency\" | \"hospitality-retreat\" | \"product-launch\",\n\
             \"scope\": {{ \"targetProject\": null | <string>, \"mutationBoundary\": [<string>] }},\n\
             \"verification\": {{ \"requireExport\": <boolean> }}\n\
           }}\n\
         }}\n\
         Defaults are derived from renderer when omitted: deliverableShape, presentationSurface, persistence, executionSubstrate, scope.createNewWorkspace, verification.requireBuild, verification.requirePreview, verification.requireDiffReview.\n\
         Renderer meanings: markdown=.md document, html_iframe=self-contained .html document, jsx_sandbox=single .jsx source module, svg=.svg visual, mermaid=.mermaid diagram, pdf_embed=PDF artifact, download_card=file export surface, workspace_surface=real multi-file workspace.\n\
         Rules:\n\
         - artifact = persistent work product; conversation = plain reply; tool_widget = first-party widget; visualizer = ephemeral inline visual.\n\
         - workspace_surface only when a real multi-file workspace and supervised preview runtime are required.\n\
         - Explicit medium-plus-deliverable requests are sufficiently specified artifact work.\n\
         - direct_author only for a fresh coherent single-file artifact; follow-up edits should continue the active artifact.\n\
         - For tool_widget, include exactly one routingHints entry of tool_widget:weather | tool_widget:recipe | tool_widget:sports | tool_widget:places | tool_widget:user_input.\n\
         - Include currentness_override when the request requires fresh or up-to-date information.\n\
         - Include workspace_grounding_required and coding_workspace_context when the answer should come from the current repo or workspace.\n\
         - Include downloadable_export_requested for download_card or bundle_manifest artifacts, plus download_format:<ext> when the requested export format is explicit.\n\
         - Include shared_answer_surface for inline conversation answers and narrow_surface_preferred when you choose a tool_widget.\n\
         - If required constraints are missing, set needsClarification true and ask concise questions.\n\
         - Do not use lexical fallbacks or benchmark phrase maps.\n\
         - JSON only.",
        intent = intent,
        artifact_id = active_artifact_id.unwrap_or("<none>"),
        active_context = active_artifact_context_json,
    );

    json!([
        {
            "role": "system",
            "content": "You are Studio's typed outcome router for local runtimes. Return exactly one JSON object, rely on renderer-derived defaults when fields are omitted, continue the active artifact for follow-up edits, and never use lexical fallbacks."
        },
        {
            "role": "user",
            "content": user_content
        }
    ])
}

fn build_compact_local_follow_up_outcome_router_prompt(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: &StudioArtifactRefinementContext,
) -> serde_json::Value {
    let active_artifact_context_json =
        compact_local_outcome_router_refinement_context(Some(active_artifact)).to_string();
    let user_content = format!(
        "Request:\n{intent}\n\n\
         Active artifact id: {artifact_id}\n\
         Active artifact context summary JSON:\n{active_context}\n\n\
         Return exactly one JSON object with this minimal camelCase schema:\n\
         {{\n\
           \"outcomeKind\": \"artifact\" | \"conversation\",\n\
           \"executionStrategy\": \"single_pass\" | \"direct_author\" | \"plan_execute\" | \"micro_swarm\" | \"adaptive_work_graph\",\n\
           \"confidence\": <0_to_1_float>,\n\
           \"needsClarification\": <boolean>,\n\
           \"clarificationQuestions\": [<string>],\n\
           \"routingHints\": [<string>],\n\
           \"artifact\": null | {{\n\
             \"renderer\": \"markdown\" | \"html_iframe\" | \"jsx_sandbox\" | \"svg\" | \"mermaid\" | \"pdf_embed\" | \"download_card\" | \"workspace_surface\" | \"bundle_manifest\",\n\
             \"workspaceRecipeId\": null | \"react-vite\" | \"vite-static-html\",\n\
             \"presentationVariantId\": null | \"sport-editorial\" | \"minimal-agency\" | \"hospitality-retreat\" | \"product-launch\",\n\
             \"scope\": {{ \"targetProject\": null | <string>, \"mutationBoundary\": [<string>] }},\n\
             \"verification\": {{ \"requireExport\": <boolean> }}\n\
           }}\n\
         }}\n\
         Defaults are derived from the active artifact and renderer when omitted: artifactClass, deliverableShape, presentationSurface, persistence, executionSubstrate, createNewWorkspace, requireRender, requireBuild, requirePreview, requireDiffReview.\n\
         Rules:\n\
         - This is a follow-up turn for the active artifact, so continue that artifact by default.\n\
         - Use artifact for edits, refinements, copy changes, layout adjustments, or fixes to the active artifact.\n\
         - Keep the current renderer family unless the user explicitly asks for a different deliverable form.\n\
         - direct_author is preferred for bounded single-file follow-up edits; use plan_execute only when the requested change clearly needs a heavier pass.\n\
         - Use conversation only when the user is asking about the artifact without requesting a change.\n\
         - If required constraints are missing, set needsClarification true and ask concise questions.\n\
         - JSON only.",
        intent = intent,
        artifact_id = active_artifact_id.unwrap_or("<none>"),
        active_context = active_artifact_context_json,
    );

    json!([
        {
            "role": "system",
            "content": "You are Studio's typed outcome router for local follow-up edits. Return exactly one JSON object, continue the active artifact by default, and rely on renderer-derived defaults when fields are omitted."
        },
        {
            "role": "user",
            "content": user_content
        }
    ])
}

pub fn studio_execution_strategy_for_outcome(
    outcome_kind: StudioOutcomeKind,
    artifact: Option<&StudioOutcomeArtifactRequest>,
) -> StudioExecutionStrategy {
    crate::execution::execution_strategy_for_outcome(outcome_kind, artifact)
}

pub async fn plan_studio_outcome_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioOutcomePlanningPayload, String> {
    let runtime_provenance = runtime.studio_runtime_provenance();
    let compact_local_contract =
        runtime_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime;
    let router_max_tokens = if compact_local_contract { 224 } else { 768 };
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
        "outcome_route:start runtime_kind={:?} prompt_bytes={} max_tokens={} json_mode={}",
        runtime_provenance.kind,
        input.len(),
        router_max_tokens,
        !compact_local_contract
    ));
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: !compact_local_contract,
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
    planning.artifact = planning.artifact.map(canonicalize_artifact_request);
    let contract_hints = default_routing_hints_for_planning(&planning);
    merge_routing_hints(&mut planning.routing_hints, contract_hints);
    let planning_confidence = planning.confidence;
    apply_topology_projection_to_planning(
        &mut planning,
        intent,
        active_artifact_id,
        planning_confidence,
    );
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

fn apply_topology_projection_to_planning(
    planning: &mut StudioOutcomePlanningPayload,
    intent: &str,
    active_artifact_id: Option<&str>,
    confidence: f32,
) {
    let projection = derive_studio_topology_projection(
        intent,
        active_artifact_id,
        None,
        planning.outcome_kind,
        planning.execution_strategy,
        planning.execution_mode_decision.as_ref(),
        confidence,
        planning.needs_clarification,
        &planning.clarification_questions,
        &planning.routing_hints,
        planning.artifact.as_ref(),
    );
    planning.lane_frame = projection.lane_frame;
    planning.request_frame = projection.request_frame;
    planning.source_selection = projection.source_selection;
    planning.retained_lane_state = projection.retained_lane_state;
    planning.lane_transitions = projection.lane_transitions;
    planning.orchestration_state = projection.orchestration_state;
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
    if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
        if let Some(active_artifact) = active_artifact {
            return build_compact_local_follow_up_outcome_router_prompt(
                intent,
                active_artifact_id,
                active_artifact,
            );
        }
        return build_compact_local_outcome_router_prompt(
            intent,
            active_artifact_id,
            active_artifact,
        );
    }

    let active_artifact_context_json =
        studio_artifact_refinement_context_view(active_artifact).to_string();
    let system_content = "You are Studio's typed outcome router. Route a user request to exactly one outcome kind: conversation, tool_widget, visualizer, or artifact. Do not guess. If confidence is low, set needsClarification true. Workspace is only one artifact renderer, not the default. Artifact output must be chosen when the request should become a persistent work product. When an active artifact context is supplied, continue that artifact by default for under-specified follow-up edits instead of switching renderer families. Output JSON only.";
    let user_content = format!(
        "Request:\n{}\n\nActive artifact id: {}\n\nActive artifact context JSON:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"outcomeKind\": \"conversation\" | \"tool_widget\" | \"visualizer\" | \"artifact\",\n  \"executionStrategy\": \"single_pass\" | \"direct_author\" | \"plan_execute\" | \"micro_swarm\" | \"adaptive_work_graph\",\n  \"confidence\": <0_to_1_float>,\n  \"needsClarification\": <boolean>,\n  \"clarificationQuestions\": [<string>],\n  \"routingHints\": [<string>],\n  \"artifact\": null | {{\n    \"artifactClass\": \"document\" | \"visual\" | \"interactive_single_file\" | \"downloadable_file\" | \"workspace_project\" | \"compound_bundle\" | \"code_patch\" | \"report_bundle\",\n    \"deliverableShape\": \"single_file\" | \"file_set\" | \"workspace_project\",\n    \"renderer\": \"markdown\" | \"html_iframe\" | \"jsx_sandbox\" | \"svg\" | \"mermaid\" | \"pdf_embed\" | \"download_card\" | \"workspace_surface\" | \"bundle_manifest\",\n    \"presentationSurface\": \"inline\" | \"side_panel\" | \"overlay\" | \"tabbed_panel\",\n    \"persistence\": \"ephemeral\" | \"artifact_scoped\" | \"shared_artifact_scoped\" | \"workspace_filesystem\",\n    \"executionSubstrate\": \"none\" | \"client_sandbox\" | \"binary_generator\" | \"workspace_runtime\",\n    \"workspaceRecipeId\": null | \"react-vite\" | \"vite-static-html\",\n    \"presentationVariantId\": null | \"sport-editorial\" | \"minimal-agency\" | \"hospitality-retreat\" | \"product-launch\",\n    \"scope\": {{\n      \"targetProject\": null | <string>,\n      \"createNewWorkspace\": <boolean>,\n      \"mutationBoundary\": [<string>]\n    }},\n    \"verification\": {{\n      \"requireRender\": <boolean>,\n      \"requireBuild\": <boolean>,\n      \"requirePreview\": <boolean>,\n      \"requireExport\": <boolean>,\n      \"requireDiffReview\": <boolean>\n    }}\n  }}\n}}\nExecution strategy contracts:\n- single_pass = one bounded draft with no candidate search.\n- direct_author = direct first-pass authoring for one coherent single-document artifact; preserve the raw request and skip planner scaffolding on the first generation.\n- plan_execute = default when one planned execution unit is sufficient.\n- micro_swarm = use when the request implies a small known work graph.\n- adaptive_work_graph = use only when the request clearly needs a mutable multi-node work graph.\nRenderer contracts:\n- markdown = a single renderable .md document.\n- html_iframe = a single self-contained .html document for browser presentation. Choose this when the final artifact should be HTML itself, such as a landing page, explainer, launch page, editorial page, or browser-native interactive document.\n- jsx_sandbox = a single .jsx source module with a default export. Choose this only when the final artifact should be JSX/React source as the work product rather than a plain HTML document.\n- svg = a single .svg visual artifact.\n- mermaid = a single .mermaid diagram source artifact.\n- pdf_embed = a document artifact that will be compiled into PDF bytes.\n- download_card = downloadable files or exports, not a primary inline document surface.\n- workspace_surface = a real multi-file workspace with supervised build/preview.\nCoherence rules:\n- html_iframe and jsx_sandbox are interactive_single_file artifacts with single_file deliverableShape and client_sandbox executionSubstrate.\n- workspace_surface is the only renderer that may use workspace_project deliverableShape, workspace_runtime executionSubstrate, createNewWorkspace=true, requireBuild=true, or requirePreview=true.\n- Non-workspace artifact renderers should not request build or preview verification.\nRules:\n1) conversation is for plain reply only.\n2) tool_widget is for first-party tool display surfaces.\n3) visualizer is for ephemeral inline visuals.\n4) artifact is for persistent work products.\n5) Use workspace_surface only when a real multi-file workspace and preview runtime are required.\n6) Prefer direct_author for a fresh coherent single-file document ask that the model can author directly, such as markdown, html_iframe, svg, mermaid, or pdf_embed; otherwise prefer plan_execute unless the request is trivial enough for single_pass, small-graph enough for micro_swarm, or clearly mutable enough for adaptive_work_graph.\n7) Treat explicit medium-plus-deliverable requests as sufficiently specified artifact work. If the user already asked for an HTML artifact, landing page, launch page, editorial page, markdown document, SVG concept, Mermaid diagram, PDF artifact, downloadable bundle, or workspace project, do not ask clarification merely to restate that same deliverable form.\n8) For example, \"Create an interactive HTML artifact for an AI tools editorial launch page\" is already an artifact request for html_iframe, not a clarification request.\n9) When active artifact context JSON is not null and the request is a follow-up refinement, patch or branch the current artifact by default instead of switching renderer, artifactClass, or deliverableShape unless the user explicitly asks for a different deliverable form.\n10) Under-specified follow-up requests should continue the active artifact rather than restarting as a new artifact kind.\n11) For tool_widget, include exactly one routingHints entry of tool_widget:weather | tool_widget:recipe | tool_widget:sports | tool_widget:places | tool_widget:user_input.\n12) Include currentness_override when the request requires fresh or up-to-date information.\n13) Include workspace_grounding_required and coding_workspace_context when the answer should come from the current repo or workspace.\n14) Include downloadable_export_requested for download_card or bundle_manifest artifacts, plus download_format:<ext> when the requested export format is explicit.\n15) Include shared_answer_surface for inline conversation answers and narrow_surface_preferred when you choose a tool_widget.\n16) Do not use lexical fallbacks or benchmark phrase maps.\n17) When uncertainty remains about a required missing constraint, keep confidence low and ask clarification.",
        intent,
        active_artifact_id.unwrap_or("<none>"),
        active_artifact_context_json,
    );
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

fn merge_routing_hints(target: &mut Vec<String>, incoming: Vec<String>) {
    for hint in incoming {
        if target.iter().any(|existing| existing == &hint) {
            continue;
        }
        target.push(hint);
    }
}

fn default_routing_hints_for_planning(planning: &StudioOutcomePlanningPayload) -> Vec<String> {
    let mut hints = Vec::<String>::new();
    match planning.outcome_kind {
        StudioOutcomeKind::Artifact => {
            hints.push("persistent_artifact_requested".to_string());
            if let Some(artifact) = planning.artifact.as_ref() {
                if matches!(
                    artifact.renderer,
                    StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest
                ) {
                    hints.push("downloadable_export_requested".to_string());
                }
            }
        }
        _ => {
            hints.push("no_persistent_artifact_requested".to_string());
            if planning.outcome_kind == StudioOutcomeKind::Conversation {
                hints.push("shared_answer_surface".to_string());
            }
        }
    }

    if planning.outcome_kind == StudioOutcomeKind::ToolWidget
        && planning
            .routing_hints
            .iter()
            .any(|hint| hint.starts_with("tool_widget:"))
    {
        hints.push("narrow_surface_preferred".to_string());
    }

    hints
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
